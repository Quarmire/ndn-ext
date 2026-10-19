//! Direct paths: punching a NAT hole to a device reached through a relay,
//! answering the punches of others, and the state each one is in.
//!
//! A device punches each peer it reaches through a relay and names by its
//! device name: it sends a signed punch Interest to the peer's device name
//! (through the relay) carrying its candidate addresses, and the peer
//! answers with its own in signed Data, once it has admitted the sender as
//! it would admit a link from it. Both show the membership of the
//! namespace the punch is in when their link key is not certified there,
//! bound to the punch. Then both send probes from their link sockets to
//! every candidate the other signed, and the device whose key fingerprint
//! is smaller dials the other's candidates; the other accepts. The
//! connection is admitted like any link and becomes the link's direct
//! path; its routes cost 0, so it carries the traffic while the relay's
//! routes stay as the fallback.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use tokio::sync::{Notify, oneshot, watch};
use tokio_util::sync::CancellationToken;

use ndn_face_quic::{CloseReason, KeyFingerprint, LinkEndpoint, LinkHandle, LinkHello, PathSession, PeerKey};
use ndn_packet::{Data, Interest, Name};
use ndn_security::{ReplayCheck, ReplayGuard};

use crate::admission::{Admitted, own_memberships};
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
use crate::table::DirectUp;

/// Whose direct-path state an entry is: a configured peer's, or a device
/// that punched this one (or that this one punches by membership).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Whom {
    Peer(PeerId),
    Key(KeyFingerprint),
}

/// A device this one punches a direct path to.
#[derive(Clone, Debug)]
pub(crate) struct Target {
    pub(crate) whom: Whom,
    pub(crate) label: String,
    pub(crate) device: Name,
    /// Its key, when known before the punch (membership: from presence).
    pub(crate) key: Option<KeyFingerprint>,
    /// Its peer entry, when it has one.
    pub(crate) peer: Option<PeerId>,
}

/// A punch Interest this device answers: its name and session, and the
/// namespace of the name of this device it was sent to.
struct Punched {
    name: Name,
    session: PathSession,
    namespace: Name,
}

/// How a punch again after a network change ended.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Repunched {
    Up,
    Failed { refused: bool },
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
    /// When this device began it.
    started: Instant,
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
    /// Punch again now (the network changed).
    kicked: Arc<Notify>,
    /// The punches again after a network change that run, by the other
    /// device's key: how each ended, once it did.
    repunches: Mutex<HashMap<KeyFingerprint, watch::Receiver<Option<Repunched>>>>,
    /// When a direct path to each device last carried traffic: the
    /// tie-breaker between members waiting for a direct path.
    traffic: Mutex<HashMap<KeyFingerprint, Instant>>,
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
            kicked: Arc::new(Notify::new()),
            repunches: Mutex::new(HashMap::new()),
            traffic: Mutex::new(HashMap::new()),
        }
    }
}

impl Direct {
    /// Punch again now, whatever the backoff.
    pub(crate) fn kick(&self) {
        self.kicked.notify_waiters();
    }

    /// A direct path to `key` carried traffic until now.
    pub(crate) fn carried(&self, key: KeyFingerprint) {
        self.traffic.lock().insert(key, Instant::now());
    }

    /// The punch again after a network change that runs for `key`, if one
    /// does: how it ended, once it does.
    fn repunch_of(&self, key: KeyFingerprint) -> Option<watch::Receiver<Option<Repunched>>> {
        self.repunches.lock().get(&key).cloned()
    }
}

impl Direct {
    /// The session of the punch this device runs with `peer`, if any: the
    /// newest, when an earlier punch with that key still runs (the other
    /// device restarted, or punched again): that one is what it dials now.
    pub(crate) fn session_with(&self, peer: KeyFingerprint) -> Option<PathSession> {
        self.sessions
            .lock()
            .iter()
            .filter(|(_, s)| s.peer == peer)
            .max_by_key(|(_, s)| s.started)
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
    /// peer entry says `direct = false`, or the link policy of each
    /// namespace it was admitted in turns them off or does not pair its role
    /// with this device's (one namespace that pairs them is enough).
    pub(crate) fn direct_off(&self, admitted: &Admitted) -> Option<String> {
        let peer = admitted.peer.and_then(|i| self.peers.get(i));
        if let Some(p) = &peer
            && !p.direct
        {
            return Some(format!(
                "this device's {} for {} turns direct paths off (direct = false)",
                self.hints.peer_entry, p.label
            ));
        }
        let mut devices: Vec<Name> = admitted.identities.iter().map(|id| id.device.clone()).collect();
        if devices.is_empty() {
            devices.extend(peer.and_then(|p| p.device.clone()));
        }
        let mut why = None;
        for device in &devices {
            match self.pair_off(device) {
                None => return None,
                Some(off) => {
                    why.get_or_insert(off);
                }
            }
        }
        why
    }

    /// Why the link policy of `device`'s namespace allows no direct path
    /// between it and this device, if it does not: direct paths are off, or
    /// its role matrix does not pair their roles.
    pub(crate) fn pair_off(&self, device: &Name) -> Option<String> {
        let ctx = self.trust.keyring().context_for(device);
        let ns = ctx.namespace();
        if ns.is_empty() {
            return None;
        }
        let policy = ctx.link_policy();
        if !policy.allows_direct_paths() {
            return Some(format!(
                "{ns}'s link policy (trust context v{}) turns direct paths off",
                ctx.version()
            ));
        }
        let theirs = device
            .components()
            .get(ns.len())
            .map(|c| String::from_utf8_lossy(&c.value).into_owned())?;
        let mine = self.judge().own_role_in(ns)?;
        if policy.allows_direct_path(mine.as_str(), &theirs) {
            return None;
        }
        Some(format!(
            "{ns}'s link policy (trust context v{}) allows no direct path between {mine} and {theirs} \
             devices (its direct-path role matrix); traffic goes through the relay",
            ctx.version()
        ))
    }

    /// Why this device makes no more direct paths now, if it does not: it
    /// has as many up as it may.
    pub(crate) fn direct_full(&self) -> Option<String> {
        let up = self.table.direct_count();
        let max = self.direct_options.max_paths;
        (up >= max).then(|| {
            format!("this device has {up} direct paths up, its limit (max_paths = {max}); traffic goes through the relay")
        })
    }

    /// Whether member `key` (punched by membership) may punch now: a direct
    /// path is free, and of the members waiting for one, it is among those
    /// whose direct paths carried traffic most recently (the tie-breaker),
    /// then by key.
    fn member_turn(&self, key: KeyFingerprint) -> bool {
        let free = self
            .direct_options
            .max_paths
            .saturating_sub(self.table.direct_count());
        if free == 0 {
            return false;
        }
        let traffic = self.direct.traffic.lock().clone();
        let mut waiting: Vec<KeyFingerprint> = self
            .members
            .lock()
            .keys()
            .copied()
            .filter(|fp| self.table.direct_to(Some(*fp), None).is_none())
            .collect();
        waiting.sort_by(|a, b| {
            traffic
                .get(b)
                .cmp(&traffic.get(a))
                .then_with(|| a.cmp(b))
        });
        waiting.iter().take(free).any(|fp| *fp == key)
    }

    /// One round of the direct-path loop of `target`, punched through
    /// `relay`: wait while a direct path is up, or punch one; how long to
    /// wait before the next round.
    async fn direct_round(self: &Arc<Self>, target: &Target, relay: PeerId, backoff: &mut Backoff) -> Duration {
        let whom = target.whom;
        let relay_label = self.peers.label(relay);
        if let Some(id) = target.peer {
            let Some(peer) = self.peers.get(id) else {
                return Duration::MAX;
            };
            self.direct.set(whom, |e| {
                e.label = peer.label.clone();
                e.device = Some(target.device.clone());
                if e.key.is_none() {
                    e.key = peer.key;
                }
            });
        } else {
            self.direct.set(whom, |e| {
                e.label = target.label.clone();
                e.device = Some(target.device.clone());
                e.key = target.key;
            });
        }
        let known_key = self.direct.entries.lock().get(&whom).and_then(|e| e.key);
        if let Some((key, path)) = self.table.direct_to(known_key, target.peer) {
            let remote = path.remote_address();
            self.direct
                .state(whom, DirectState::Up, format!("direct path to {remote}"), None);
            let why = tokio::select! {
                () = self.cancel.cancelled() => return Duration::ZERO,
                why = path.closed() => why,
            };
            if path.datagrams() > 0 {
                self.direct.carried(key);
            }
            // This device's network changed and it punches again now: this
            // loop goes on from how that ends.
            if let Some(mut repunch) = self.direct.repunch_of(key) {
                let ended = tokio::select! {
                    () = self.cancel.cancelled() => return Duration::ZERO,
                    ended = repunch.wait_for(Option::is_some) => ended.ok().and_then(|e| *e),
                };
                return match ended {
                    Some(Repunched::Failed { refused }) => {
                        let wait = backoff.after_failure(refused);
                        self.direct.set(whom, |e| e.retry_at = Some(Instant::now() + wait));
                        wait
                    }
                    Some(Repunched::Up) | None => {
                        backoff.reset();
                        Duration::ZERO
                    }
                };
            }
            // A newer direct path took this one's place.
            if self.table.direct_to(Some(key), target.peer).is_some() {
                return Duration::ZERO;
            }
            let wait = backoff.after_drop();
            let text = format!(
                "the direct path to {remote} ended ({why}); traffic goes through {relay_label} until \
                 the next punch"
            );
            tracing::info!(target: "face.quic", peer = %target.label, "{text}");
            self.direct.state(whom, DirectState::NotPossible, text, Some(wait));
            return wait;
        }
        if target.peer.is_some_and(|id| self.table.link_to(id).is_some()) {
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
        if let Some(peer) = target.peer.and_then(|id| self.peers.get(id))
            && !peer.direct
        {
            self.direct.state(
                whom,
                DirectState::Off,
                format!("this device's {} for {} says direct = false", self.hints.peer_entry, peer.label),
                None,
            );
            return Duration::MAX;
        }
        if let Some(why) = self.pair_off(&target.device) {
            self.direct.state(whom, DirectState::Off, why, None);
            return Duration::from_secs(60);
        }
        let full = match target.key {
            Some(key) if target.peer.is_none() => (!self.member_turn(key)).then(|| {
                self.direct_full().unwrap_or_else(|| {
                    "other members wait for the free direct paths first (their direct paths carried \
                     traffic more recently)"
                        .to_string()
                })
            }),
            _ => self.direct_full(),
        };
        if let Some(why) = full {
            self.direct.state(whom, DirectState::None, why, None);
            return Duration::from_secs(5);
        }
        self.direct
            .state(whom, DirectState::Trying, format!("punching through {relay_label}"), None);
        let punched = match self.punch_socket(relay) {
            Ok(socket) => self.punch(target, socket).await,
            Err(failure) => Err(failure),
        };
        match punched {
            Ok(path) => {
                backoff.reset();
                tracing::info!(
                    target: "face.quic",
                    peer = %target.label,
                    remote = %path.remote_address(),
                    "direct path to {} up; {relay_label} stays the fallback",
                    target.label
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
                    peer = %target.label,
                    retry_in_secs = wait.as_secs(),
                    "no direct path to {}: {}; traffic goes through {relay_label}",
                    target.label,
                    failure.text
                );
                self.direct.state(whom, state, failure.text, Some(wait));
                wait
            }
        }
    }

    /// The link socket a punch through `relay` goes from: its link's, so
    /// the reflexive candidate is the NAT mapping the relay saw.
    fn punch_socket(self: &Arc<Self>, relay: PeerId) -> Result<Arc<LinkEndpoint>, Failure> {
        let relay_link = self
            .table
            .link_to(relay)
            .ok_or_else(|| Failure::new("the relay's link is down"))?;
        self.endpoint_for(relay_link.remote_address())
            .map_err(|e| Failure::new(format!("no link socket to punch from: {e}")))
    }

    /// Punch a direct path to `target` from `socket`: ask it through the
    /// routes that reach it (normally its relay's), then probe and dial (or
    /// accept).
    async fn punch(self: &Arc<Self>, target: &Target, socket: Arc<LinkEndpoint>) -> Result<LinkHandle, Failure> {
        let label = target.label.clone();
        let device = target.device.clone();
        let key = self
            .key
            .current()
            .map_err(|e| Failure::new(format!("this device has no usable link key: {e}")))?;
        let chain = crate::admission::hello_chain(self.trust.as_ref());
        let ours = self.gather(&socket);
        let session = random_session();
        // Its device is of a namespace this device may be a member of with
        // another key than its link key: that membership, bound to this
        // punch, is how the other device knows it there.
        let namespace = self.judge().namespace_of(&device);
        let memberships = own_memberships(self.trust.as_ref(), &key, &punch::punch_binding(&session), Some(&namespace)).await;
        let request = PunchMessage {
            key: key.spki().clone(),
            candidates: ours.clone(),
            refusal: None,
            certificates: chain.clone(),
            memberships,
        };
        tracing::info!(
            target: "face.quic",
            peer = %label,
            candidates = ?ours.iter().map(|c| format!("{} {}", c.kind.as_str(), c.addr)).collect::<Vec<_>>(),
            "punching a direct path to {label} ({device})"
        );
        let wire = punch::request(&device, &session, &request, &key, &punch::locator(&key, &chain));
        let data = match self.signal().express(wire, PUNCH_ANSWER_TIMEOUT).await {
            Ok(Answer::Data(data)) => *data,
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
        let (peer_key, theirs) = self.check_answer(&data, target, &session).await?;
        self.direct.set(target.whom, |e| e.key = Some(peer_key.fingerprint()));
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

    /// The answer to this device's punch of `target` (of `session`),
    /// verified: signed by the key it names, which the device's certificate
    /// or membership (or its expected fingerprint) makes that device's.
    async fn check_answer(
        &self,
        data: &Data,
        target: &Target,
        session: &PathSession,
    ) -> Result<(PeerKey, PunchMessage), Failure> {
        let label = &target.label;
        let bad = |why: String| Failure::refused(format!("{label}'s punch answer is not usable: {why}"));
        let content = data.content().ok_or_else(|| bad("it carries no content".into()))?;
        let theirs = PunchMessage::decode(content).map_err(bad)?;
        let key = PeerKey::from_spki(&theirs.key).map_err(|e| bad(e.to_string()))?;
        punch::verify_answer(data, &key).await.map_err(bad)?;
        if target.key.is_some_and(|expected| expected != key.fingerprint()) {
            return Err(bad(format!(
                "it is signed by key {}, not the key {} its relay listed",
                key.fingerprint(),
                target.key.map(|k| k.to_string()).unwrap_or_default()
            )));
        }
        let hello = LinkHello {
            certificates: theirs.certificates.clone(),
            memberships: theirs.memberships.clone(),
            direct_path: None,
        };
        match self
            .judge()
            .decide(&key, &hello, &punch::punch_binding(session), target.peer)
            .await
        {
            Ok(admitted) if admitted.enrollment.is_some() => Err(bad(format!(
                "this device cannot confirm it is {label} yet (it holds no certificate in its namespace)"
            ))),
            Ok(admitted)
                if target.peer.is_none() && !admitted.identities.iter().any(|id| id.device == target.device) =>
            {
                Err(bad(format!(
                    "its certificate is not {}'s ({})",
                    target.device,
                    admitted.describe()
                )))
            }
            Ok(_) => Ok((key, theirs)),
            Err(refusal) => Err(bad(refusal.text)),
        }
    }

    /// Answer a punch Interest another device sent this one (to any of its
    /// names): refuse it, or answer with this device's candidates and punch
    /// back.
    pub(crate) async fn answer_punch(self: Arc<Self>, interest: Interest) {
        let Some((own, session)) = self
            .own_devices()
            .into_iter()
            .find_map(|own| punch::session_of(&own, &interest.name).map(|s| (own, s)))
        else {
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
        let to = Punched {
            name: (*interest.name).clone(),
            session,
            namespace: self.judge().namespace_of(&own),
        };
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
            return self.refuse_punch(&to, &who(None), CloseReason::Protocol, text).await;
        }
        if self.direct.replay.check(info) != ReplayCheck::Fresh {
            let text = "your punch request repeats an earlier one (same SignatureNonce and SignatureTime): a \
                        replay; sign a new one"
                .to_string();
            return self.refuse_punch(&to, &who(None), CloseReason::Protocol, text).await;
        }
        if !self.direct.admit_request(fingerprint) {
            let text = format!(
                "this device answers {PUNCH_BURST} punch requests from one key at once, then one per {} s; \
                 punch again later",
                PUNCH_REFILL.as_secs()
            );
            return self.refuse_punch(&to, &who(None), CloseReason::Busy, text).await;
        }
        let hello = LinkHello {
            certificates: theirs.certificates.clone(),
            memberships: theirs.memberships.clone(),
            direct_path: None,
        };
        let admitted = match self
            .judge()
            .decide(&key, &hello, &punch::punch_binding(&session), None)
            .await
        {
            Ok(a) if a.enrollment.is_none() => a,
            Ok(a) => {
                let text = format!(
                    "this device would admit {} only on an enrollment link, which no direct path carries; \
                     enroll first ({})",
                    a.describe(),
                    self.hints.enroll
                );
                return self.refuse_punch(&to, &who(Some(&a)), CloseReason::Unrecognized, text).await;
            }
            Err(refusal) => return self.refuse_punch(&to, &who(None), refusal.reason, refusal.text).await,
        };
        if let Some(why) = self.direct_off(&admitted) {
            return self
                .refuse_punch(&to, &who(Some(&admitted)), CloseReason::DirectPathsOff, why)
                .await;
        }
        if self.direct.sessions.lock().len() >= PUNCHES_MAX {
            let text = format!("this device runs {PUNCHES_MAX} punches at once already; punch again later");
            return self
                .refuse_punch(&to, &who(Some(&admitted)), CloseReason::Busy, text)
                .await;
        }
        if self.table.direct_to(Some(fingerprint), None).is_none()
            && let Some(text) = self.direct_full()
        {
            return self
                .refuse_punch(&to, &who(Some(&admitted)), CloseReason::Busy, text)
                .await;
        }
        let Some(first) = theirs.candidates.first() else {
            let text = "your punch request offers no address to reach you at".to_string();
            return self
                .refuse_punch(&to, &who(Some(&admitted)), CloseReason::Protocol, text)
                .await;
        };
        let socket = match self.endpoint_for(first.addr) {
            Ok(s) => s,
            Err(e) => {
                let text = format!("this device has no link socket for {}: {e}", first.addr);
                return self
                    .refuse_punch(&to, &who(Some(&admitted)), CloseReason::Busy, text)
                    .await;
            }
        };
        let (Ok(own_key), chain) = (self.key.current(), crate::admission::hello_chain(self.trust.as_ref())) else {
            return;
        };
        let ours = self.gather(&socket);
        let answer = PunchMessage {
            key: own_key.spki().clone(),
            candidates: ours.clone(),
            refusal: None,
            certificates: chain.clone(),
            memberships: own_memberships(
                self.trust.as_ref(),
                &own_key,
                &punch::punch_binding(&session),
                Some(&to.namespace),
            )
            .await,
        };
        // The other device punches only while it has no direct path up to
        // this one, or after its network changed: one this device still has
        // to it is stale (§14.7). Its routes go now, not at its idle timeout.
        if let Some((_, stale)) = self.table.direct_to(Some(fingerprint), None) {
            stale.close(
                CloseReason::Replaced,
                "your device punched again (it lost this direct path, or its network changed); the path of \
                 its new punch takes this one's place",
            );
        }
        self.signal()
            .send(punch::answer(&to.name, &answer, &own_key, &punch::locator(&own_key, &chain)))
            .await;
        // The device as known in the namespace it punched this one in.
        let device = admitted
            .identities
            .iter()
            .find(|id| id.namespace == to.namespace)
            .or(admitted.identity())
            .map(|id| id.device.clone());
        let label = device
            .as_ref()
            .map_or_else(|| format!("key {fingerprint}"), ToString::to_string);
        let whom = Whom::Key(fingerprint);
        self.direct.set(whom, |e| {
            e.label = label.clone();
            e.key = Some(fingerprint);
            e.device = device.clone();
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
            Ok(path) => self.follow(whom, fingerprint, &label, path).await,
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

    /// Keep the state of direct path `path` to `whom` (`label`, key `key`),
    /// which the other device punches: up until the path ends, then waiting
    /// for its next punch — unless this device punches again after a
    /// network change, or a newer path took this one's place: they say.
    async fn follow(&self, whom: Whom, key: KeyFingerprint, label: &str, path: LinkHandle) {
        let remote = path.remote_address();
        self.direct
            .state(whom, DirectState::Up, format!("direct path to {remote}"), None);
        let why = tokio::select! {
            () = self.cancel.cancelled() => return,
            why = path.closed() => why,
        };
        if self.direct.repunch_of(key).is_some() || self.table.direct_to(Some(key), None).is_some() {
            return;
        }
        self.direct.state(
            whom,
            DirectState::NotPossible,
            format!("the direct path to {remote} ended ({why}); {label} punches again"),
            None,
        );
    }

    /// This device's network changed: close each direct path it has and
    /// punch each of those devices again at once, whichever side punched
    /// before (§14.7). A path this device accepted cannot follow it to its
    /// new address (a QUIC server cannot migrate, RFC 9000 §9), and one it
    /// dialled may not get through the other side's NAT from there; the
    /// punch carries the new network's candidates.
    pub(crate) fn punch_again_all(self: &Arc<Self>) {
        for up in self.table.direct_paths() {
            let Some((target, owned)) = self.repunch_target(&up) else {
                // Nothing to send a punch to: the other device punches.
                continue;
            };
            let (done, ended) = watch::channel(None);
            self.direct.repunches.lock().insert(up.fingerprint, ended);
            tracing::info!(
                target: "face.quic",
                peer = %target.label,
                remote = %up.handle.remote_address(),
                "the network changed: closing the direct path to {} and punching again",
                target.label
            );
            up.handle.close(
                CloseReason::Replaced,
                "this device's network changed: it punches a direct path again from its new address, which \
                 takes this one's place",
            );
            tokio::spawn(repunch(
                Arc::downgrade(self),
                target,
                owned,
                up.fingerprint,
                up.handle.remote_address(),
                up.gone,
                done,
            ));
        }
    }

    /// Whom to punch again for direct path `up`, and whether a direct-path
    /// loop of this device keeps that device (it punches it: a peer entry
    /// reached through a relay, or a member a relay listed); `None` when
    /// this device does not know the device's name.
    fn repunch_target(&self, up: &DirectUp) -> Option<(Target, bool)> {
        let fp = up.fingerprint;
        let peer = up.peer.or_else(|| self.peers.find(fp, up.device.as_ref()));
        let spec = peer.and_then(|id| self.peers.get(id));
        if let (Some(id), Some(spec)) = (peer, &spec)
            && spec.relay.is_some()
            && let Some(device) = spec.device.clone()
        {
            let target = Target {
                whom: Whom::Peer(id),
                label: spec.label.clone(),
                device,
                key: Some(fp),
                peer: Some(id),
            };
            return Some((target, true));
        }
        let device = up.device.clone().or_else(|| spec.and_then(|s| s.device.clone()))?;
        let target = Target {
            whom: Whom::Key(fp),
            label: device.to_string(),
            device,
            key: Some(fp),
            peer,
        };
        Some((target, self.members.lock().contains_key(&fp)))
    }

    /// Punch `target` again after a network change, from the link socket
    /// that reaches `remote` (where its direct path went).
    async fn punch_again(self: &Arc<Self>, target: &Target, owned: bool, remote: SocketAddr) -> Result<LinkHandle, Failure> {
        let whom = target.whom;
        let label = &target.label;
        self.direct.state(
            whom,
            DirectState::Trying,
            "this device's network changed: punching again from its new address".into(),
            None,
        );
        let punched = match self.endpoint_for(remote) {
            Ok(socket) => self.punch(target, socket).await,
            Err(e) => Err(Failure::new(format!("no link socket to punch from: {e}"))),
        };
        match &punched {
            Ok(path) => {
                tracing::info!(
                    target: "face.quic",
                    peer = %label,
                    remote = %path.remote_address(),
                    "direct path to {label} up again after the network change"
                );
                self.direct.state(
                    whom,
                    DirectState::Up,
                    format!("direct path to {}", path.remote_address()),
                    None,
                );
            }
            Err(failure) => {
                tracing::info!(
                    target: "face.quic",
                    peer = %label,
                    "no direct path to {label} after the network change: {}",
                    failure.text
                );
                let state = if failure.refused {
                    DirectState::Refused
                } else {
                    DirectState::NotPossible
                };
                let text = if owned {
                    failure.text.clone()
                } else {
                    format!("{}; {label} punches again", failure.text)
                };
                self.direct.state(whom, state, text, None);
            }
        }
        punched
    }

    /// Refuse the punch Interest `to`, with a signed answer saying why,
    /// showing this device's membership of the namespace it was punched in.
    async fn refuse_punch(&self, to: &Punched, who: &str, reason: CloseReason, text: String) {
        self.direct.refused.fetch_add(1, Ordering::Relaxed);
        tracing::warn!(target: "face.quic", peer = %who, reason = ?reason, "refused a direct-path punch: {text}");
        let Ok(key) = self.key.current() else { return };
        let chain = crate::admission::hello_chain(self.trust.as_ref());
        let msg = PunchMessage {
            key: key.spki().clone(),
            candidates: Vec::new(),
            refusal: Some((u64::from(reason.code()), text)),
            certificates: chain.clone(),
            memberships: own_memberships(
                self.trust.as_ref(),
                &key,
                &punch::punch_binding(&to.session),
                Some(&to.namespace),
            )
            .await,
        };
        self.signal()
            .send(punch::answer(&to.name, &msg, &key, &punch::locator(&key, &chain)))
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
                    started: Instant::now(),
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
    let (target, relay) = {
        let Some(this) = links.upgrade() else { return };
        let Some(peer) = this.peers.get(id) else { return };
        let (Some(relay), Some(device)) = (peer.relay, peer.device.clone()) else {
            return;
        };
        let target = Target {
            whom: Whom::Peer(id),
            label: peer.label.clone(),
            device,
            key: peer.key,
            peer: Some(id),
        };
        (target, relay)
    };
    punch_loop(links, target, relay, CancellationToken::new()).await;
}

/// Keep a direct path to a member relay `relay` listed (presence) until it
/// no longer lists it (`stop`).
pub(crate) async fn member_loop(links: std::sync::Weak<Links>, target: Target, relay: PeerId, stop: CancellationToken) {
    let whom = target.whom;
    punch_loop(links.clone(), target, relay, stop).await;
    if let Some(links) = links.upgrade() {
        links.direct.entries.lock().remove(&whom);
    }
}

async fn punch_loop(links: std::sync::Weak<Links>, target: Target, relay: PeerId, stop: CancellationToken) {
    let mut backoff = Backoff::direct();
    loop {
        let Some(this) = links.upgrade() else { return };
        let cancel = this.cancel.clone();
        let wait = tokio::select! {
            () = stop.cancelled() => return,
            wait = this.direct_round(&target, relay, &mut backoff) => wait,
        };
        let kick = Arc::clone(&this.direct.kicked);
        let kicked = kick.notified();
        drop(this);
        if wait == Duration::MAX {
            return;
        }
        tokio::select! {
            () = cancel.cancelled() => return,
            () = stop.cancelled() => return,
            () = kicked => backoff.reset(),
            () = tokio::time::sleep(wait) => {}
        }
    }
}

/// Punch `target` (key `key`) again after this device's network changed,
/// once its closed direct path to `remote` is gone (its face and routes:
/// the punch then goes through the routes that reach the device without
/// it, normally its relay's); tell `done` how it ended. When no loop of
/// this device keeps that device (`owned`), follow the new path here.
async fn repunch(
    links: std::sync::Weak<Links>,
    target: Target,
    owned: bool,
    key: KeyFingerprint,
    remote: SocketAddr,
    gone: CancellationToken,
    done: watch::Sender<Option<Repunched>>,
) {
    gone.cancelled().await;
    let Some(this) = links.upgrade() else { return };
    let punched = tokio::select! {
        () = this.cancel.cancelled() => return,
        punched = this.punch_again(&target, owned, remote) => punched,
    };
    {
        let mut repunches = this.direct.repunches.lock();
        let mine = done.subscribe();
        if repunches.get(&key).is_some_and(|r| r.same_channel(&mine)) {
            repunches.remove(&key);
        }
    }
    done.send_replace(Some(match &punched {
        Ok(_) => Repunched::Up,
        Err(failure) => Repunched::Failed {
            refused: failure.refused,
        },
    }));
    if !owned && let Ok(path) = punched {
        this.follow(target.whom, key, &target.label, path).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_listener_names_its_newest_punch_with_a_key() {
        let direct = Direct::default();
        let (peer, other) = (KeyFingerprint([1; 32]), KeyFingerprint([2; 32]));
        let start = Instant::now();
        let session = |peer, started| Session { peer, up: None, claimed: false, started };
        // Inserted newest first, so map order cannot be what picks it.
        let (old, new, theirs) = ([1; 8], [2; 8], [3; 8]);
        let mut sessions = direct.sessions.lock();
        sessions.insert(new, session(peer, start + Duration::from_secs(2)));
        sessions.insert(theirs, session(other, start + Duration::from_secs(5)));
        sessions.insert(old, session(peer, start));
        drop(sessions);
        assert_eq!(direct.session_with(peer), Some(new));
        assert_eq!(direct.session_with(KeyFingerprint([9; 32])), None);
    }
}
