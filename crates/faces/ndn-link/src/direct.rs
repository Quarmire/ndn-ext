//! Direct paths: punching a NAT hole to a device reached through a relay,
//! answering the punches of others, and the state each one is in.
//!
//! A device punches each peer it reaches through a relay and names by its
//! device name: it sends a signed punch Interest to the peer's device name
//! (through the relay) carrying its candidate addresses, and the peer
//! answers with its own in signed Data, once it has admitted the sender as
//! it would admit a link from it. Then both send probes from their link
//! sockets to every candidate the other signed, and the device whose key
//! fingerprint is smaller dials the other's candidates; the other accepts.
//! The connection is admitted like any link and becomes the link's direct
//! path; its routes cost 0, so it carries the traffic while the relay's
//! routes stay as the fallback.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use tokio::sync::oneshot;

use ndn_face_quic::{CloseReason, KeyFingerprint, LinkEndpoint, LinkHandle, LinkHello, PathSession, PeerKey};
use ndn_packet::{Data, Interest, Name};
use ndn_security::{ReplayCheck, ReplayGuard};

use crate::admission::Admitted;
use crate::candidates::{Candidate, CandidateKind, dial_order, interfaces, probe_targets};
use crate::links::{Links, Origin};
use crate::peer::PeerId;
use crate::policy::{
    Backoff, CANDIDATES_MAX, DIAL_STAGGER, PROBE_INTERVAL, PROBE_WINDOW, PUNCH_ANSWER_TIMEOUT, PUNCH_BURST,
    PUNCH_CHECKS, PUNCH_GRACE, PUNCH_REFILL, PUNCH_WINDOW, PUNCHES_MAX,
};
use crate::punch::{self, PunchMessage};
use crate::signal::Answer;
use crate::status::{DirectState, DirectStatus};

/// Whose direct-path state an entry is: a configured peer's, or a device
/// that punched this one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Whom {
    Peer(PeerId),
    Key(KeyFingerprint),
}

/// A direct-path state as kept.
#[derive(Clone, Debug)]
pub(crate) struct Entry {
    pub(crate) label: String,
    pub(crate) key: Option<KeyFingerprint>,
    pub(crate) device: Option<Name>,
    pub(crate) state: DirectState,
    pub(crate) text: String,
    pub(crate) retry_at: Option<Instant>,
}

impl Entry {
    pub(crate) fn status(&self) -> DirectStatus {
        DirectStatus {
            state: self.state,
            text: self.text.clone(),
            retry_in: self.retry_at.map(|at| at.saturating_duration_since(Instant::now())),
        }
    }
}

/// A punch that runs.
struct Session {
    /// The other device's key.
    peer: KeyFingerprint,
    /// Told when the direct path of the punch is admitted.
    up: Option<oneshot::Sender<LinkHandle>>,
    /// A path of the punch was admitted: further ones are closed.
    claimed: bool,
}

/// A token bucket.
struct Bucket {
    tokens: f64,
    at: Instant,
}

impl Bucket {
    fn full(burst: u32) -> Self {
        Self {
            tokens: f64::from(burst),
            at: Instant::now(),
        }
    }

    fn take(&mut self, burst: u32, per_sec: f64) -> bool {
        let now = Instant::now();
        self.tokens = (self.tokens + now.duration_since(self.at).as_secs_f64() * per_sec).min(f64::from(burst));
        self.at = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Keys whose punch-request buckets are kept at most.
const KEYS_MAX: usize = 1024;

/// The direct-path state of this device's links.
pub(crate) struct Direct {
    sessions: Mutex<HashMap<PathSession, Session>>,
    entries: Mutex<HashMap<Whom, Entry>>,
    replay: ReplayGuard,
    checks: Mutex<Bucket>,
    per_key: Mutex<HashMap<KeyFingerprint, Bucket>>,
    pub(crate) probes_sent: AtomicU64,
    pub(crate) refused: AtomicU64,
}

impl Default for Direct {
    fn default() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            entries: Mutex::new(HashMap::new()),
            replay: ReplayGuard::new(64, false),
            checks: Mutex::new(Bucket::full(PUNCH_CHECKS.burst)),
            per_key: Mutex::new(HashMap::new()),
            probes_sent: AtomicU64::new(0),
            refused: AtomicU64::new(0),
        }
    }
}

impl Direct {
    /// The session of the punch this device runs with `peer`, if any.
    pub(crate) fn session_with(&self, peer: KeyFingerprint) -> Option<PathSession> {
        self.sessions
            .lock()
            .iter()
            .find(|(_, s)| s.peer == peer)
            .map(|(id, _)| *id)
    }

    /// Claim `session` for a path of its punch from `peer`: `false` when it
    /// is not this device's punch with `peer`, or a path of it was admitted
    /// already.
    pub(crate) fn claim(&self, session: &PathSession, peer: KeyFingerprint) -> bool {
        let mut sessions = self.sessions.lock();
        match sessions.get_mut(session) {
            Some(s) if s.peer == peer && !s.claimed => {
                s.claimed = true;
                true
            }
            _ => false,
        }
    }

    /// The direct path of `session` is admitted.
    pub(crate) fn path_up(&self, session: &PathSession, handle: &LinkHandle) {
        if let Some(tx) = self.sessions.lock().get_mut(session).and_then(|s| s.up.take()) {
            let _ = tx.send(handle.clone());
        }
    }

    pub(crate) fn entries(&self) -> HashMap<Whom, Entry> {
        self.entries.lock().clone()
    }

    fn set(&self, whom: Whom, update: impl FnOnce(&mut Entry)) {
        let mut entries = self.entries.lock();
        let entry = entries.entry(whom).or_insert_with(|| Entry {
            label: String::new(),
            key: None,
            device: None,
            state: DirectState::None,
            text: String::new(),
            retry_at: None,
        });
        update(entry);
    }

    fn state(&self, whom: Whom, state: DirectState, text: String, retry: Option<Duration>) {
        self.set(whom, |e| {
            e.state = state;
            e.text = text;
            e.retry_at = retry.map(|d| Instant::now() + d);
        });
    }

    /// Whether another punch request from `key` may be answered now.
    fn admit_request(&self, key: KeyFingerprint) -> bool {
        let mut per_key = self.per_key.lock();
        if per_key.len() >= KEYS_MAX && !per_key.contains_key(&key) {
            per_key.retain(|_, b| b.tokens < f64::from(PUNCH_BURST) - 0.5);
        }
        per_key
            .entry(key)
            .or_insert_with(|| Bucket::full(PUNCH_BURST))
            .take(PUNCH_BURST, 1.0 / PUNCH_REFILL.as_secs_f64())
    }
}

/// Removes a punch's session when it ends.
struct SessionGuard<'a> {
    direct: &'a Direct,
    session: PathSession,
}

impl Drop for SessionGuard<'_> {
    fn drop(&mut self) {
        self.direct.sessions.lock().remove(&self.session);
    }
}

/// Why a punch made no direct path, and whether it was refused.
pub(crate) struct Failure {
    text: String,
    refused: bool,
}

impl Failure {
    fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            refused: false,
        }
    }

    fn refused(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            refused: true,
        }
    }
}

fn random_session() -> PathSession {
    let mut session = [0u8; 8];
    getrandom::getrandom(&mut session).expect("the system's random source");
    session
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl Links {
    /// This device's candidate addresses for its link socket `socket`:
    /// reflexive ones (what linked devices see), then the sources' (host,
    /// advertised, mapped), at most [`CANDIDATES_MAX`].
    fn gather(&self, socket: &LinkEndpoint) -> Vec<Candidate> {
        let Ok(local) = socket.local_addr() else {
            return Vec::new();
        };
        let mut out: Vec<Candidate> = self
            .table
            .observed(local)
            .into_iter()
            .map(|addr| Candidate {
                kind: CandidateKind::Reflexive,
                addr,
            })
            .collect();
        for source in &self.candidates {
            for c in source.candidates(local) {
                if !out.iter().any(|o| o.addr == c.addr) {
                    out.push(c);
                }
            }
        }
        out.truncate(CANDIDATES_MAX);
        out
    }

    /// Why direct paths with an admitted device are off, if they are: its
    /// peer entry says `direct = false`, or the link policy of its
    /// namespace turns them off.
    pub(crate) fn direct_off(&self, admitted: &Admitted) -> Option<String> {
        if let Some(p) = admitted.peer.map(|i| self.peers.get(i))
            && !p.direct
        {
            return Some(format!(
                "this device's {} for {} turns direct paths off (direct = false)",
                self.hints.peer_entry, p.label
            ));
        }
        let ns_of = admitted
            .identity
            .as_ref()
            .map(|id| id.device.clone())
            .or_else(|| admitted.peer.and_then(|i| self.peers.get(i).device.clone()))?;
        self.policy_off(&ns_of)
    }

    /// Why the link policy of `device`'s namespace turns direct paths off,
    /// if it does.
    fn policy_off(&self, device: &Name) -> Option<String> {
        let ctx = self.trust.keyring().context_for(device);
        if ctx.namespace().is_empty() || ctx.link_policy().allows_direct_paths() {
            return None;
        }
        Some(format!(
            "{}'s link policy (trust context v{}) turns direct paths off",
            ctx.namespace(),
            ctx.version()
        ))
    }

    /// One round of the direct-path loop of `id`: wait while a direct path
    /// is up, or punch one; how long to wait before the next round.
    async fn direct_round(self: &Arc<Self>, id: PeerId, backoff: &mut Backoff) -> Duration {
        let peer = self.peers.get(id);
        let whom = Whom::Peer(id);
        let (Some(relay), Some(device)) = (peer.relay, peer.device.clone()) else {
            return Duration::MAX;
        };
        let relay_label = self.peers.get(relay).label.clone();
        self.direct.set(whom, |e| {
            e.label = peer.label.clone();
            e.device = Some(device.clone());
            if e.key.is_none() {
                e.key = peer.key;
            }
        });
        let known_key = self.direct.entries.lock().get(&whom).and_then(|e| e.key);
        if let Some(path) = self.table.direct_to(known_key, Some(id)) {
            let remote = path.remote_address();
            self.direct
                .state(whom, DirectState::Up, format!("direct path to {remote}"), None);
            let why = tokio::select! {
                () = self.cancel.cancelled() => return Duration::ZERO,
                why = path.closed() => why,
            };
            let wait = backoff.after_drop();
            let text = format!(
                "the direct path to {remote} ended ({why}); traffic goes through {relay_label} until \
                 the next punch"
            );
            tracing::info!(target: "face.quic", peer = %peer.label, "{text}");
            self.direct.state(whom, DirectState::NotPossible, text, Some(wait));
            return wait;
        }
        if self.table.link_to(id).is_some() {
            self.direct.state(
                whom,
                DirectState::None,
                "linked over its configured endpoint; no punch needed".into(),
                None,
            );
            return Duration::from_secs(5);
        }
        if self.table.link_to(relay).is_none() {
            self.direct.state(
                whom,
                DirectState::None,
                format!("waiting for the link to {relay_label}, through which the punch goes"),
                None,
            );
            return Duration::from_secs(1);
        }
        if !peer.direct {
            self.direct.state(
                whom,
                DirectState::Off,
                format!("this device's {} for {} says direct = false", self.hints.peer_entry, peer.label),
                None,
            );
            return Duration::MAX;
        }
        if let Some(why) = self.policy_off(&device) {
            self.direct.state(whom, DirectState::Off, why, None);
            return Duration::from_secs(60);
        }
        self.direct
            .state(whom, DirectState::Trying, format!("punching through {relay_label}"), None);
        match self.punch(id).await {
            Ok(path) => {
                backoff.reset();
                tracing::info!(
                    target: "face.quic",
                    peer = %peer.label,
                    remote = %path.remote_address(),
                    "direct path to {} up; {relay_label} stays the fallback",
                    peer.label
                );
                Duration::ZERO
            }
            Err(failure) => {
                let wait = backoff.after_failure(failure.refused);
                let state = if failure.refused {
                    DirectState::Refused
                } else {
                    DirectState::NotPossible
                };
                tracing::info!(
                    target: "face.quic",
                    peer = %peer.label,
                    retry_in_secs = wait.as_secs(),
                    "no direct path to {}: {}; traffic goes through {relay_label}",
                    peer.label,
                    failure.text
                );
                self.direct.state(whom, state, failure.text, Some(wait));
                wait
            }
        }
    }

    /// Punch a direct path to peer `id`: ask it through the relay, then
    /// probe and dial (or accept).
    async fn punch(self: &Arc<Self>, id: PeerId) -> Result<LinkHandle, Failure> {
        let peer = self.peers.get(id);
        let label = peer.label.clone();
        let device = peer.device.clone().ok_or_else(|| Failure::new("its peer entry names no device"))?;
        let relay = peer.relay.ok_or_else(|| Failure::new("its peer entry names no relay"))?;
        let relay_link = self
            .table
            .link_to(relay)
            .ok_or_else(|| Failure::new("the relay's link is down"))?;
        let socket = self
            .endpoint_for(relay_link.remote_address())
            .map_err(|e| Failure::new(format!("no link socket to punch from: {e}")))?;
        let key = self
            .key
            .current()
            .map_err(|e| Failure::new(format!("this device has no usable link key: {e}")))?;
        let chain = self.trust.own_chain();
        let ours = self.gather(&socket);
        let session = random_session();
        let request = PunchMessage {
            key: key.spki().clone(),
            candidates: ours.clone(),
            refusal: None,
            certificates: chain.clone(),
        };
        tracing::info!(
            target: "face.quic",
            peer = %label,
            candidates = ?ours.iter().map(|c| format!("{} {}", c.kind.as_str(), c.addr)).collect::<Vec<_>>(),
            "punching a direct path to {label} ({device})"
        );
        let wire = punch::request(&device, &session, &request, &key, &punch::locator(&key, &chain));
        let data = match self.signal().express(wire, PUNCH_ANSWER_TIMEOUT).await {
            Ok(Answer::Data(data)) => data,
            Ok(Answer::Nack { why, refused: true }) => {
                return Err(Failure::refused(format!(
                    "this device's forwarder refused {device}'s answer to the punch ({why}): it cannot \
                     validate that device's Data, so it holds no trust context of its namespace or lacks \
                     its certificates; adopt the namespace's trust context to punch it"
                )));
            }
            Ok(Answer::Nack { why, refused: false }) => {
                return Err(Failure::new(format!(
                    "the punch request to {device} was answered with {why}: nothing routes it there now"
                )));
            }
            Err(why) => {
                return Err(Failure::new(format!(
                    "the punch request to {device} got {why} (is it running and linked to the relay?)"
                )));
            }
        };
        let (peer_key, theirs) = self.check_answer(&data, id).await?;
        self.direct.set(Whom::Peer(id), |e| e.key = Some(peer_key.fingerprint()));
        if let Some((code, text)) = theirs.refusal {
            let transient = CloseReason::from_code(code).is_none_or(|r| r.is_transient());
            let text = format!("{label} refused the direct path: {text}");
            return Err(if transient {
                Failure::new(text)
            } else {
                Failure::refused(text)
            });
        }
        self.run_punch(session, peer_key.fingerprint(), &theirs.candidates, socket, &label)
            .await
            .map_err(Failure::new)
    }

    /// The answer to this device's punch of `id`, verified: signed by the
    /// key it names, which the peer's certificate (or expected fingerprint)
    /// makes that peer's.
    async fn check_answer(&self, data: &Data, id: PeerId) -> Result<(PeerKey, PunchMessage), Failure> {
        let label = &self.peers.get(id).label;
        let bad = |why: String| Failure::refused(format!("{label}'s punch answer is not usable: {why}"));
        let content = data.content().ok_or_else(|| bad("it carries no content".into()))?;
        let theirs = PunchMessage::decode(content).map_err(bad)?;
        let key = PeerKey::from_spki(&theirs.key).map_err(|e| bad(e.to_string()))?;
        punch::verify_answer(data, &key).await.map_err(bad)?;
        let hello = LinkHello {
            certificates: theirs.certificates.clone(),
            direct_path: None,
        };
        match self.judge().decide(&key, &hello, Some(id)).await {
            Ok(admitted) if admitted.enrollment.is_none() => Ok((key, theirs)),
            Ok(_) => Err(bad(format!(
                "this device cannot confirm it is {label} yet (it holds no certificate in its namespace)"
            ))),
            Err(refusal) => Err(bad(refusal.text)),
        }
    }

    /// Answer a punch Interest another device sent this one: refuse it, or
    /// answer with this device's candidates and punch back.
    pub(crate) async fn answer_punch(self: Arc<Self>, interest: Interest) {
        let Some(own) = self.own_device() else { return };
        let Some(session) = punch::session_of(&own, &interest.name) else {
            return;
        };
        // Signature checks cost work before this device knows who asks:
        // bounded over all requesters, silently.
        if !self
            .direct
            .checks
            .lock()
            .take(PUNCH_CHECKS.burst, f64::from(PUNCH_CHECKS.per_sec))
        {
            return;
        }
        let Some(params) = interest.app_parameters().cloned() else {
            return;
        };
        let Ok(theirs) = PunchMessage::decode(&params) else {
            return;
        };
        let Ok(key) = PeerKey::from_spki(&theirs.key) else {
            return;
        };
        // An Interest whose signature does not verify under the key it names
        // could be anyone's: no answer.
        if punch::verify_request(&interest, &key).await.is_err() {
            return;
        }
        let fingerprint = key.fingerprint();
        let name = (*interest.name).clone();
        let who = |admitted: Option<&Admitted>| admitted.map_or_else(|| format!("key {fingerprint}"), Admitted::describe);
        let info = interest.sig_info().expect("verified");
        let signed_at = info.sig_time.unwrap_or(0);
        let now = now_ms();
        if now.abs_diff(signed_at) > PUNCH_GRACE.as_millis() as u64 {
            let text = format!(
                "your punch request was signed at {signed_at} ms, more than {} s from this device's clock \
                 ({now} ms): it is replayed, or a clock is off; check both devices' clocks",
                PUNCH_GRACE.as_secs()
            );
            return self.refuse_punch(&name, &who(None), CloseReason::Protocol, text).await;
        }
        if self.direct.replay.check(info) != ReplayCheck::Fresh {
            let text = "your punch request repeats an earlier one (same SignatureNonce and SignatureTime): a \
                        replay; sign a new one"
                .to_string();
            return self.refuse_punch(&name, &who(None), CloseReason::Protocol, text).await;
        }
        if !self.direct.admit_request(fingerprint) {
            let text = format!(
                "this device answers {PUNCH_BURST} punch requests from one key at once, then one per {} s; \
                 punch again later",
                PUNCH_REFILL.as_secs()
            );
            return self.refuse_punch(&name, &who(None), CloseReason::Busy, text).await;
        }
        let hello = LinkHello {
            certificates: theirs.certificates.clone(),
            direct_path: None,
        };
        let admitted = match self.judge().decide(&key, &hello, None).await {
            Ok(a) if a.enrollment.is_none() => a,
            Ok(a) => {
                let text = format!(
                    "this device would admit {} only on an enrollment link, which no direct path carries; \
                     enroll first ({})",
                    a.describe(),
                    self.hints.enroll
                );
                return self.refuse_punch(&name, &who(Some(&a)), CloseReason::Unrecognized, text).await;
            }
            Err(refusal) => return self.refuse_punch(&name, &who(None), refusal.reason, refusal.text).await,
        };
        if let Some(why) = self.direct_off(&admitted) {
            return self
                .refuse_punch(&name, &who(Some(&admitted)), CloseReason::DirectPathsOff, why)
                .await;
        }
        if self.direct.sessions.lock().len() >= PUNCHES_MAX {
            let text = format!("this device runs {PUNCHES_MAX} punches at once already; punch again later");
            return self
                .refuse_punch(&name, &who(Some(&admitted)), CloseReason::Busy, text)
                .await;
        }
        let Some(first) = theirs.candidates.first() else {
            let text = "your punch request offers no address to reach you at".to_string();
            return self
                .refuse_punch(&name, &who(Some(&admitted)), CloseReason::Protocol, text)
                .await;
        };
        let socket = match self.endpoint_for(first.addr) {
            Ok(s) => s,
            Err(e) => {
                let text = format!("this device has no link socket for {}: {e}", first.addr);
                return self
                    .refuse_punch(&name, &who(Some(&admitted)), CloseReason::Busy, text)
                    .await;
            }
        };
        let (Ok(own_key), chain) = (self.key.current(), self.trust.own_chain()) else {
            return;
        };
        let ours = self.gather(&socket);
        let answer = PunchMessage {
            key: own_key.spki().clone(),
            candidates: ours.clone(),
            refusal: None,
            certificates: chain.clone(),
        };
        self.signal()
            .send(punch::answer(&name, &answer, &own_key, &punch::locator(&own_key, &chain)))
            .await;
        let label = admitted
            .identity
            .as_ref()
            .map_or_else(|| format!("key {fingerprint}"), |id| id.device.to_string());
        let whom = Whom::Key(fingerprint);
        self.direct.set(whom, |e| {
            e.label = label.clone();
            e.key = Some(fingerprint);
            e.device = admitted.identity.as_ref().map(|id| id.device.clone());
        });
        self.direct
            .state(whom, DirectState::Trying, format!("{label} punches a direct path"), None);
        tracing::info!(
            target: "face.quic",
            peer = %label,
            candidates = ?ours.iter().map(|c| format!("{} {}", c.kind.as_str(), c.addr)).collect::<Vec<_>>(),
            "answered {label}'s punch; punching back"
        );
        match self
            .run_punch(session, fingerprint, &theirs.candidates, socket, &label)
            .await
        {
            Ok(path) => {
                let remote = path.remote_address();
                self.direct
                    .state(whom, DirectState::Up, format!("direct path to {remote}"), None);
                let why = tokio::select! {
                    () = self.cancel.cancelled() => return,
                    why = path.closed() => why,
                };
                self.direct.state(
                    whom,
                    DirectState::NotPossible,
                    format!("the direct path to {remote} ended ({why}); {label} punches again"),
                    None,
                );
            }
            Err(text) => {
                tracing::info!(target: "face.quic", peer = %label, "no direct path to {label}: {text}");
                self.direct.state(
                    whom,
                    DirectState::NotPossible,
                    format!("{text}; {label} punches again"),
                    None,
                );
            }
        }
    }

    /// Refuse the punch Interest `name`, with a signed answer saying why.
    async fn refuse_punch(&self, name: &Name, who: &str, reason: CloseReason, text: String) {
        self.direct.refused.fetch_add(1, Ordering::Relaxed);
        tracing::warn!(target: "face.quic", peer = %who, reason = ?reason, "refused a direct-path punch: {text}");
        let Ok(key) = self.key.current() else { return };
        let chain = self.trust.own_chain();
        let msg = PunchMessage {
            key: key.spki().clone(),
            candidates: Vec::new(),
            refusal: Some((u64::from(reason.code()), text)),
            certificates: chain.clone(),
        };
        self.signal()
            .send(punch::answer(name, &msg, &key, &punch::locator(&key, &chain)))
            .await;
    }

    /// Probe the other device's candidates `theirs` from `socket`, and dial
    /// them (when this device's key fingerprint is the smaller) or accept
    /// its dial, within [`PUNCH_WINDOW`].
    async fn run_punch(
        self: &Arc<Self>,
        session: PathSession,
        peer: KeyFingerprint,
        theirs: &[Candidate],
        socket: Arc<LinkEndpoint>,
        label: &str,
    ) -> Result<LinkHandle, String> {
        let local = socket
            .local_addr()
            .map_err(|e| format!("the link socket has no address: {e}"))?;
        let targets = probe_targets(theirs, local);
        if targets.is_empty() {
            return Err(format!(
                "{label} offered no address this device's link socket ({local}) can reach"
            ));
        }
        let (up_tx, up_rx) = oneshot::channel();
        {
            let mut sessions = self.direct.sessions.lock();
            if sessions.len() >= PUNCHES_MAX {
                return Err(format!("this device runs {PUNCHES_MAX} punches at once already"));
            }
            sessions.insert(
                session,
                Session {
                    peer,
                    up: Some(up_tx),
                    claimed: false,
                },
            );
        }
        let _session = SessionGuard {
            direct: &self.direct,
            session,
        };
        let _window = socket.allow_inbound(&targets);
        let heard: Arc<Mutex<Vec<SocketAddr>>> = Arc::default();
        let listen = {
            let mut watch = socket.watch_probes(session);
            let heard = Arc::clone(&heard);
            async move {
                while let Some(from) = watch.next().await {
                    let mut heard = heard.lock();
                    if !heard.contains(&from) {
                        heard.push(from);
                    }
                }
            }
        };
        let probe = async {
            let rounds = (PROBE_WINDOW.as_millis() / PROBE_INTERVAL.as_millis()).max(1);
            for _ in 0..rounds {
                for target in &targets {
                    if socket.send_probe(*target, &session).await.is_ok() {
                        self.direct.probes_sent.fetch_add(1, Ordering::Relaxed);
                    }
                }
                tokio::time::sleep(PROBE_INTERVAL).await;
            }
        };
        let dialer = self.my_fingerprint().is_some_and(|mine| mine < peer);
        let order = dial_order(theirs, local, &interfaces());
        let dial = async {
            if !dialer {
                return std::future::pending().await;
            }
            // Let the first probes open this side's NAT first.
            tokio::time::sleep(PROBE_INTERVAL).await;
            self.dial_direct(&socket, &order, peer, session, label).await
        };
        let outcome = tokio::time::timeout(PUNCH_WINDOW, async {
            tokio::pin!(probe, dial, listen, up_rx);
            let mut probing = true;
            let mut dialing = true;
            let mut last = None;
            loop {
                tokio::select! {
                    () = &mut probe, if probing => probing = false,
                    () = &mut listen => {}
                    up = &mut up_rx => match up {
                        Ok(path) => return Ok(path),
                        Err(_) => return Err(last.unwrap_or_else(|| "the punch ended".to_string())),
                    },
                    dialed = &mut dial, if dialing => match dialed {
                        Ok(path) => return Ok(path),
                        Err(e) => {
                            last = Some(e);
                            dialing = false;
                        }
                    },
                }
            }
        })
        .await;
        match outcome {
            Ok(result) => result,
            Err(_) => {
                let heard = heard.lock().clone();
                let probed = targets.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ");
                Err(if heard.is_empty() {
                    format!(
                        "no probe from {label} reached this device and no QUIC handshake completed within {} s \
                         (probed {probed}); both networks drop unsolicited UDP or map each destination to \
                         another port (symmetric NAT), so the relay carries the traffic",
                        PUNCH_WINDOW.as_secs()
                    )
                } else {
                    format!(
                        "probes from {label} arrived (from {}), but no QUIC handshake completed within {} s \
                         (probed {probed}): the way back to it stays closed",
                        heard.iter().map(ToString::to_string).collect::<Vec<_>>().join(", "),
                        PUNCH_WINDOW.as_secs()
                    )
                })
            }
        }
    }

    /// Dial the other device's candidates `order` from `socket`, each
    /// [`DIAL_STAGGER`] after the previous; the first admitted wins.
    async fn dial_direct(
        self: &Arc<Self>,
        socket: &Arc<LinkEndpoint>,
        order: &[SocketAddr],
        peer: KeyFingerprint,
        session: PathSession,
        label: &str,
    ) -> Result<LinkHandle, String> {
        if order.is_empty() {
            return Err(format!("{label} offered no address this device dials"));
        }
        let mut dials = tokio::task::JoinSet::new();
        for (i, addr) in order.iter().copied().enumerate() {
            let links = Arc::clone(self);
            let socket = Arc::clone(socket);
            dials.spawn(async move {
                tokio::time::sleep(DIAL_STAGGER * u32::try_from(i).unwrap_or(u32::MAX)).await;
                let hs = socket
                    .connect_direct(addr, peer)
                    .await
                    .map_err(|e| format!("{addr}: {e}"))?;
                links
                    .establish(hs, Origin::Direct(session))
                    .await
                    .map_err(|e| format!("{addr}: {e}"))
            });
        }
        let mut errors = Vec::new();
        while let Some(done) = dials.join_next().await {
            match done {
                Ok(Ok(path)) => {
                    dials.abort_all();
                    return Ok(path);
                }
                Ok(Err(e)) => errors.push(e),
                Err(_) => {}
            }
        }
        Err(format!("no dial to {label} came up ({})", errors.join("; ")))
    }
}

/// Keep peer `id`'s direct path: punch it while the peer is reached through
/// its relay, again after it ends, with backoff while punches fail.
pub(crate) async fn direct_loop(links: std::sync::Weak<Links>, id: PeerId) {
    let mut backoff = Backoff::direct();
    loop {
        let Some(this) = links.upgrade() else { return };
        let cancel = this.cancel.clone();
        let wait = this.direct_round(id, &mut backoff).await;
        drop(this);
        if wait == Duration::MAX {
            return;
        }
        tokio::select! {
            () = cancel.cancelled() => return,
            () = tokio::time::sleep(wait) => {}
        }
    }
}
