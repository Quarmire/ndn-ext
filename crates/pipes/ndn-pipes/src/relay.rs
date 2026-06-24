//! Relay side: a node *between* consumer and producer that participates in pipe
//! formation on the COMMON control band, while the engine forwards the data
//! plane toward the producer.
//!
//! Faithful to the thesis's coordinator-free addressing: the relay derives its
//! own hop index from `GHL − remaining HopLimit` — no configuration, no central
//! assignment — and answers CONTEXT/LINK/PIPE for its hop.
//!
//! **G3 slice 1 — relay pipe-key handoff.** A relay now obtains and holds the pipe
//! key (the teardown credential) via the PIPE exchange: [`learn_pipe_key`] fetches it
//! sealed from upstream into a [`RelayPipeStore`], and the relay's PIPE handler then
//! re-seals that stored key to *its* adjacent downstream node — propagating the key
//! down the path. Holding the key is the prerequisite for relay-side PUI teardown
//! (slices 2–3) and the PathControl migration (slice 4).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ndn_app::{AppError, Consumer, Producer};
use ndn_packet::Name;
use ndn_packet::encode::DataBuilder;

use crate::crypto::seal;
use crate::keyexchange::fetch_pipe_key;
use crate::message::{GHL, MessageKind, classify, encode_pipe_bundle, hop_index};
use crate::pathcontrol::{now_seq, pipe_teardown_interest};

/// A relay's table of pipe keys it has learned (id → key + PUI), the teardown
/// credential for pipes passing through it. Cheaply cloneable (`Arc`): the learn path
/// inserts, the serve loop reads to re-seal, and (slice 3) the teardown path checks +
/// reaps. Mirrors the producer's `PipeRegistry`.
#[derive(Clone, Default)]
pub struct RelayPipeStore {
    inner: Arc<Mutex<HashMap<Vec<u8>, RelayEntry>>>,
}

struct RelayEntry {
    /// The producer namespace this pipe transfers under — teardown is monitored
    /// **per namespace** (the thesis: pipes sharing a namespace can't be told apart
    /// by traffic alone), so activity for the namespace renews every pipe under it.
    namespace: Name,
    /// This relay's hop order for the pipe (GHL-derived); shapes the nonuniform
    /// inactivity threshold so on-path nodes don't all announce teardown at once.
    hop: u32,
    pipe_key: Vec<u8>,
    pui: Duration,
    /// Last time the namespace showed traffic (renewed by [`note_activity`]).
    last_activity: Instant,
    /// A teardown announcement for this pipe is already in flight / suppressed —
    /// don't re-announce (cleared when activity resumes).
    announced: bool,
}

/// One pipe the monitor has decided to tear down: its namespace (the PathControl
/// teardown walks this prefix), id, and the membership key the announcement carries.
pub(crate) struct DueTeardown {
    pub namespace: Name,
    pub id: Vec<u8>,
    pub pipe_key: Vec<u8>,
}

impl RelayPipeStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn insert(&self, id: Vec<u8>, namespace: Name, hop: u32, pipe_key: Vec<u8>, pui: Duration) {
        self.inner.lock().unwrap().insert(
            id,
            RelayEntry {
                namespace,
                hop,
                pipe_key,
                pui,
                last_activity: Instant::now(),
                announced: false,
            },
        );
    }

    /// The `(pipe_key, pui)` for a held pipe — for re-sealing it downstream.
    pub fn bundle(&self, id: &[u8]) -> Option<(Vec<u8>, Duration)> {
        let m = self.inner.lock().unwrap();
        m.get(id).map(|e| (e.pipe_key.clone(), e.pui))
    }

    /// The pipe key for a held pipe (membership credential).
    pub fn pipe_key(&self, id: &[u8]) -> Option<Vec<u8>> {
        self.bundle(id).map(|(k, _)| k)
    }

    /// The namespace a held pipe transfers under (for suppressing siblings on an
    /// inbound teardown). `None` if not held.
    pub fn namespace_of(&self, id: &[u8]) -> Option<Name> {
        self.inner.lock().unwrap().get(id).map(|e| e.namespace.clone())
    }

    /// Data-plane activity signal: renew every pipe whose namespace is a **prefix** of
    /// `name` (i.e. a packet was fetched under that namespace) and clear its pending
    /// teardown. This is what keeps an actively-used pipe alive under the monitor; the
    /// forwarder feeds it every interest name via a `NameActivityObserver`. Distinct from
    /// [`note_activity`](Self::note_activity), which renews by *exact* namespace.
    pub fn note_traffic(&self, name: &Name) {
        let now = Instant::now();
        let mut m = self.inner.lock().unwrap();
        for e in m.values_mut() {
            if name.has_prefix(&e.namespace) {
                e.last_activity = now;
                e.announced = false;
            }
        }
    }

    /// Record that `namespace` showed traffic: renew every pipe under it and clear any
    /// pending teardown (the contract — the consumer used the pipe within the PUI). The
    /// data-plane / NPD calls this on observing namespace activity.
    pub fn note_activity(&self, namespace: &Name) {
        let now = Instant::now();
        let mut m = self.inner.lock().unwrap();
        for e in m.values_mut() {
            if &e.namespace == namespace {
                e.last_activity = now;
                e.announced = false;
            }
        }
    }

    /// The pipes whose inactivity has exceeded their **per-hop threshold**
    /// (`PUI + hop · quantum` — closer-to-consumer hops fire first, so the nearest
    /// node announces and the rest suppress). Marks them `announced` so a subsequent
    /// poll won't re-emit. The monitor sends a teardown for each.
    pub(crate) fn due(&self, quantum: Duration) -> Vec<DueTeardown> {
        let now = Instant::now();
        let mut out = Vec::new();
        let mut m = self.inner.lock().unwrap();
        for (id, e) in m.iter_mut() {
            let threshold = e.pui + quantum * e.hop;
            if !e.announced && now.duration_since(e.last_activity) > threshold {
                e.announced = true;
                out.push(DueTeardown {
                    namespace: e.namespace.clone(),
                    id: id.clone(),
                    pipe_key: e.pipe_key.clone(),
                });
            }
        }
        out
    }

    /// **Suppression**: a peer announced teardown for `namespace` first — cancel our
    /// own pending announcement(s) for it (mark `announced` so the monitor won't emit).
    /// The actual state reap is [`teardown_authorized`](Self::teardown_authorized).
    pub fn suppress(&self, namespace: &Name) {
        let mut m = self.inner.lock().unwrap();
        for e in m.values_mut() {
            if &e.namespace == namespace {
                e.announced = true;
            }
        }
    }

    /// Authorize (and perform) a teardown of this relay's pipe state: the supplied
    /// secret must equal the stored pipe key (membership). An unknown/already-gone
    /// pipe is an idempotent success.
    pub fn teardown_authorized(&self, id: &[u8], secret: Option<&[u8]>) -> bool {
        let mut m = self.inner.lock().unwrap();
        match m.get(id) {
            Some(e) => {
                if secret == Some(e.pipe_key.as_slice()) {
                    m.remove(id);
                    true
                } else {
                    false
                }
            }
            None => true,
        }
    }
}

/// A pipe relay: serves the COMMON control channel for one node on the path.
/// Its [`Producer`] must be registered on the relay engine for [`COMMON_PREFIX`]
/// (`/COMMON`); non-control names are left to the engine to forward onward.
///
/// [`COMMON_PREFIX`]: crate::message::COMMON_PREFIX
pub struct PipeRelay {
    producer: Producer,
    store: RelayPipeStore,
}

impl PipeRelay {
    pub fn new(producer: Producer) -> Self {
        Self {
            producer,
            store: RelayPipeStore::new(),
        }
    }

    /// The shared pipe-key store (for tests / a PIPES introspection module).
    pub fn store(&self) -> RelayPipeStore {
        self.store.clone()
    }

    /// Learn the pipe key for `pipe_id` (under `namespace`, at this relay's `hop`) from
    /// the adjacent upstream node (`upstream_hop` = `hop + 1`) via the PIPE exchange,
    /// storing it with activity tracking. Call during pipe formation; returns whether a
    /// key was obtained.
    pub async fn learn_pipe_key(
        &self,
        upstream: &mut Consumer,
        namespace: &Name,
        pipe_id: &[u8],
        hop: u32,
        upstream_hop: u32,
        timeout: Duration,
    ) -> bool {
        match fetch_pipe_key(upstream, pipe_id, upstream_hop, timeout).await {
            Some((key, pui)) => {
                self.store
                    .insert(pipe_id.to_vec(), namespace.clone(), hop, key.to_vec(), pui);
                true
            }
            None => false,
        }
    }

    /// Serve the COMMON control band. On a PIPE request, if this relay holds the pipe
    /// key it re-seals it to the requester (propagating the credential downstream);
    /// otherwise — and for CONTEXT/LINK — it reports the locally-derived hop index
    /// (coordinator-free addressing). Anything else is left unanswered.
    pub async fn serve(self) -> Result<(), AppError> {
        let store = self.store.clone();
        self.producer
            .serve(move |interest, responder| {
                let store = store.clone();
                async move {
                    let name = (*interest.name).clone();
                    let remaining = interest.hop_limit().unwrap_or(GHL);
                    let hop = hop_index(GHL, remaining);
                    match classify(&name) {
                        Some(MessageKind::Pipe) => {
                            // Re-seal the stored pipe key to the downstream requester
                            // if we hold it (the key handoff); else fall back to the
                            // hop-index report used during formation.
                            let resealed = pid_at1(&name)
                                .and_then(|id| store.bundle(&id))
                                .zip(interest.app_parameters())
                                .and_then(|((key, pui), pubkey)| {
                                    seal(pubkey, &encode_pipe_bundle(&key, pui.as_millis() as u64))
                                });
                            let d = match resealed {
                                Some(sealed) => DataBuilder::new(name, &sealed).build(),
                                None => DataBuilder::new(name, &[hop]).build(),
                            };
                            responder.respond_bytes(d).await.ok();
                        }
                        Some(MessageKind::Context | MessageKind::Link) => {
                            let d = DataBuilder::new(name, &[hop]).build();
                            responder.respond_bytes(d).await.ok();
                        }
                        _ => drop(responder),
                    }
                }
            })
            .await
    }
}

/// Background **PUI-teardown monitor** (slice 2): periodically announce teardown for
/// any pipe whose namespace has been idle past its per-hop threshold. Spawn alongside
/// [`PipeRelay::serve`] (share its [`store`](PipeRelay::store)); the caller aborts the
/// task to stop it. `quantum` is the per-hop delay step (nonuniform suppression);
/// `tick` the poll cadence. Each announcement is a membership-authenticated PathControl
/// `Teardown` (slice 4): a single signed-by-membership path-walk that reaps this relay's
/// state (the emitter's own engine hook) and every downstream hop's, toward the producer.
pub async fn run_relay_monitor(
    store: RelayPipeStore,
    mut emitter: Consumer,
    quantum: Duration,
    tick: Duration,
) {
    loop {
        tokio::time::sleep(tick).await;
        for due in store.due(quantum) {
            // Fire-and-forget: a teardown path-walk returns no Data (the forwarder hook
            // consumes it), so the fetch is expected to time out.
            let wire = pipe_teardown_interest(&due.namespace, &due.id, &due.pipe_key, now_seq());
            let _ = emitter.fetch_wire(wire, tick).await;
        }
    }
}

/// The pipe-id bytes at component 1 of a `/COMMON/{pipe_id}/…` control name.
fn pid_at1(name: &Name) -> Option<Vec<u8>> {
    name.components().get(1).map(|c| c.value.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ns(s: &str) -> Name {
        s.parse().unwrap()
    }

    /// The inactivity monitor's core logic (no async / engine): nonuniform per-hop
    /// threshold, single-announce, activity reset, and suppression.
    #[test]
    fn monitor_threshold_hop_order_reset_and_suppression() {
        let store = RelayPipeStore::new();
        let n = ns("/sensors/temp");
        // Two pipes under one namespace at different hops; PUI = 0 so the threshold is
        // purely hop · quantum.
        store.insert(b"near".to_vec(), n.clone(), 0, vec![1], Duration::ZERO); // thr 0
        store.insert(b"far".to_vec(), n.clone(), 2, vec![2], Duration::ZERO); // thr 2·q
        let q = Duration::from_millis(40);

        std::thread::sleep(Duration::from_millis(12));
        // Only the nearer hop (threshold 0) is due; the far hop (80ms) waits — this is
        // the nonuniform delay that lets the nearest node announce first.
        let due: Vec<_> = store.due(q).into_iter().map(|d| d.id).collect();
        assert_eq!(due, vec![b"near".to_vec()]);
        // Already-announced is not re-emitted on the next poll.
        assert!(store.due(q).is_empty(), "single announcement per inactivity episode");

        // Namespace activity renews everything (the PUI contract honored).
        store.note_activity(&n);
        std::thread::sleep(Duration::from_millis(12));
        let due2: Vec<_> = store.due(q).into_iter().map(|d| d.id).collect();
        assert_eq!(due2, vec![b"near".to_vec()], "due again only after a fresh quiet window");

        // Suppression: a peer announced teardown for the namespace first — cancel our
        // own pending announcement, so even past the far hop's threshold we stay quiet.
        store.suppress(&n);
        std::thread::sleep(Duration::from_millis(100));
        assert!(store.due(q).is_empty(), "suppressed: no self-announcement after a peer's");
    }

    /// Receive side (slice 3): an authenticated inbound teardown for one pipe reaps it
    /// and suppresses its namespace siblings' pending announcements; a wrong key is
    /// rejected and changes nothing. (Mirrors the serve `Teardown` arm's composition.)
    #[test]
    fn inbound_teardown_reaps_and_suppresses_namespace() {
        let store = RelayPipeStore::new();
        let n = ns("/sensors/temp");
        store.insert(b"a".to_vec(), n.clone(), 0, vec![0xAA], Duration::ZERO);
        store.insert(b"b".to_vec(), n.clone(), 2, vec![0xBB], Duration::ZERO);

        // A wrong key for A is rejected — nothing reaped.
        assert!(!store.teardown_authorized(b"a", Some(&[0x00])));
        assert!(store.pipe_key(b"a").is_some(), "rejected teardown leaves A held");

        // A correct teardown for A: capture its namespace, reap it, suppress siblings.
        let ns_a = store.namespace_of(b"a").expect("A held");
        assert!(store.teardown_authorized(b"a", Some(&[0xAA])), "membership authorizes");
        store.suppress(&ns_a);
        assert!(store.pipe_key(b"a").is_none(), "A reaped");

        // B (sibling in the same namespace) is suppressed: even past its threshold it
        // does not self-announce — the peer's teardown beat it.
        std::thread::sleep(Duration::from_millis(100));
        assert!(store.due(Duration::from_millis(40)).is_empty(), "B's announcement suppressed");
    }
}
