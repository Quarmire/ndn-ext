//! **Signals**: ephemeral live data — presence, cursors, a drag at 60 Hz, live
//! unsigned edits — that never becomes a version and never enters a content store
//! (ndn-rs `docs/specs/signals.md`).
//!
//! One [`Signals::subscribe`] receives a scope's signals from every member: a
//! sender on this host over its run's shared-memory ring, a remote one pushed.
//!
//! - **Push, never pull.** A sender pushes each packet (one signal or a batch) as
//!   one unsigned Interest into the sync group of each member namespace,
//!   `<O>/32=sync/32=signal/<ParametersSha256Digest>`, the packet in its
//!   ApplicationParameters, InterestLifetime 1 s, HopLimit 8. Nothing answers it.
//!   The groups are already routed (multicast) by the libraries that route sync;
//!   the forwarder is unchanged.
//! - **Run keys.** [`Signals::open`] makes a fresh Ed25519 run key; the device key
//!   signs its run header (ndn-data's `Device::signal_header`); the run key signs
//!   each packet. A receiver admits a header through `Device::signal_admit` and
//!   checks the sender's membership on every packet (`Device::signal_member`).
//! - **Sealing.** In a sealed scope every packet is sealed under the scope's
//!   signal key (XChaCha20-Poly1305) after it is signed.
//! - **Latest per (sender, address).** A subscriber reads the newest signal per
//!   pair not yet read; an older one is stale; a slow reader never gets a backlog.
//! - **The local leg.** A run opens a lossy broadcast ring whose secret rides in
//!   its header. A receiver on the same host that admits the header attaches; the
//!   ring carries the same packet bytes, so one pipeline verifies both; whichever
//!   copy of a packet comes second (usually the forwarder's) is dropped by the
//!   run's replay window before verification.
//!
//! A process does not receive its own signals: the forwarder never returns an
//! Interest to the face it came from, and a hub never attaches to its own rings.
//! Two hubs in one process (two devices) receive each other's.
//!
//! **Hosting.** `Signals::start` takes a connection of its own to the forwarder and
//! registers this device's namespace group `<ns>/32=sync` on it. Over ndn-ipc that
//! registers the route; on an in-process engine the host routes the group to the
//! connection's face, as it does for the Device's sync face, and runs the group
//! with the multicast strategy (as for sync).

mod crypto;
mod queue;
mod state;
pub mod wire;

use std::collections::{HashMap, HashSet};
use std::ops::Range;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::Duration;

use bytes::Bytes;
use ed25519_dalek::VerifyingKey;
use ndn_app::Connection;
use ndn_data::{DataError, Device, NextStep, SignalKey, SignalRefusal, SignalScope};
use ndn_foundation_types::{Name, NameComponent};
use ndn_packet::{Data, Interest};
use tokio::task::JoinHandle;

use crate::{NamedPublisher, NamedSubscriber};
use crypto::RunKey;
use queue::Queue;
use state::{Bucket, Latest, ReplayWindow};
pub use wire::RunId;
use wire::{Body, Outgoing, PACKET_MAX, Packet, RunHeaderBody};

/// The longest `Expires` after now a signal may carry (§5).
pub const TTL_MAX: Duration = Duration::from_secs(60);
/// The longest a run lasts from its start (§5).
pub const RUN_LIFETIME_MAX: Duration = Duration::from_secs(24 * 3600);
/// A sender's packets per second per run (§5).
pub const SEND_RATE: u64 = 120;
/// A sender's burst per run (§5).
pub const SEND_BURST: u64 = 30;
/// A receiver's packets per second per run (§5).
pub const RECEIVE_RATE_RUN: u64 = 240;
/// A receiver's packets per second per scope (§5).
pub const RECEIVE_RATE_SCOPE: u64 = 2000;
/// Runs held per sender key per scope (§5).
pub const RUNS_PER_SENDER: usize = 4;
/// Runs held per scope (§5).
pub const RUNS_PER_SCOPE: usize = 64;
/// Run headers being admitted at once per process (§5).
pub const ADMITTING_MAX: usize = 8;
/// Packets of a run kept while its header is admitted; more are `unknown_run`.
pub const WAITING_MAX: usize = 32;
/// How often a header rides again in its run's packets.
pub const HEADER_EVERY: Duration = Duration::from_secs(1);

/// Slots of a run's local ring: two seconds at the sender's full rate.
const RING_SLOTS: u32 = 256;
/// Readers a run's local ring takes.
const RING_READERS: u32 = 32;
/// Least time between two refreshes of the signal keys on an unknown key id.
const KEY_REFRESH_EVERY_US: u64 = 1_000_000;

/// A clock: µs since the Unix epoch.
pub type SignalClock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// How a process signals.
#[derive(Clone)]
pub struct SignalOptions {
    /// The default `Expires` of a signal, from its send: 2 s (at most [`TTL_MAX`]).
    pub ttl: Duration,
    /// A run's `NotAfter` from its start: 1 h (at most [`RUN_LIFETIME_MAX`]); a run
    /// is renewed (a new run key, sequences continuing) at 90 % of it.
    pub run_lifetime: Duration,
    /// Open a local ring per run: true.
    pub local_ring: bool,
    /// How far another device's clock may run behind ours: 30 s.
    pub clock_skew: Duration,
    /// Where every time `Signals` reads comes from (run starts, `Expires`,
    /// `NotAfter`, expiry, header re-rides, rate buckets, renewal). `None`: the
    /// system clock. A host running on a virtual clock gives its own.
    pub clock: Option<SignalClock>,
}

impl Default for SignalOptions {
    fn default() -> Self {
        SignalOptions {
            ttl: Duration::from_secs(2),
            run_lifetime: Duration::from_secs(3600),
            local_ring: true,
            clock_skew: Duration::from_secs(30),
            clock: None,
        }
    }
}

impl std::fmt::Debug for SignalOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignalOptions")
            .field("ttl", &self.ttl)
            .field("run_lifetime", &self.run_lifetime)
            .field("local_ring", &self.local_ring)
            .field("clock_skew", &self.clock_skew)
            .field("clock", &self.clock.as_ref().map(|_| "host"))
            .finish()
    }
}

/// A verified signal. `address` and `payload` are slices of the received packet.
#[derive(Clone, Debug)]
pub struct Signal {
    /// The scope (folder or collection).
    pub scope: Name,
    /// The device key that signed the run header: `/<ns>/<device>/KEY/<id>`.
    pub sender: Name,
    /// The run.
    pub run: RunId,
    /// Its sequence: per sender, increasing.
    pub seq: u64,
    /// The app's address, e.g. `b"cursor"`, `b"presence"`, `b"drag/<element>"`.
    pub address: Bytes,
    /// The app's payload.
    pub payload: Bytes,
    /// ms since the Unix epoch, by the sender's clock.
    pub expires: u64,
    /// Came off a ring on this host.
    pub local: bool,
}

/// Counters since start. Drops before delivery count packets; `delivered`,
/// `local`, `stale` and `expired` count signals (`expired` also counts a packet of
/// a run past its `NotAfter`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SignalStats {
    /// Packets made by this process's runs.
    pub sent_packets: u64,
    /// Octets of the push Interests sent (every group's copy).
    pub sent_bytes: u64,
    /// Signals handed to subscribers.
    pub delivered: u64,
    /// Of those, signals that came off a ring on this host.
    pub local: u64,
    /// Signals older than the newest per (sender, address).
    pub stale: u64,
    /// A sequence the run's window has seen (a duplicate copy included).
    pub replayed: u64,
    /// Signals past `Expires + clock_skew`; packets past their run's `NotAfter + clock_skew`.
    pub expired: u64,
    /// Sender (or its header) not a member by the record in force.
    pub not_member: u64,
    /// Run signature, the header's device signature, or a header whose key is not its run's.
    pub bad_signature: u64,
    /// No header held for the run yet (dropped unverified).
    pub unknown_run: u64,
    /// Sealed under a key id no subscribed scope holds (dropped undecrypted).
    pub unknown_key: u64,
    /// Over a rate or count limit (§5).
    pub flood: u64,
    /// Not a packet of the wire, over a wire limit, not opening under its key, or
    /// unsealed in a sealed scope.
    pub malformed: u64,
    /// A packet of a scope no one subscribes to here.
    pub unsubscribed: u64,
}

/// Why a signal call is refused. Each says why, and [`SignalError::next`] what to do.
#[derive(Debug, thiserror::Error)]
pub enum SignalError {
    /// This device isn't a member of `scope` by the record in force. Next: ask its
    /// owner to share the folder with this person or device.
    #[error(
        "this device is no member of {scope} by the record in force ({why}); ask its owner to \
         share it with this person or device"
    )]
    NotMember {
        /// The scope.
        scope: Name,
        /// Why, from the data layer.
        why: String,
    },
    /// Nothing decided yet: no record held, or the epoch key isn't held yet (its
    /// ask has started). Next: retry later.
    #[error("{scope} is not ready for signals ({why}); retry later")]
    NotReady {
        /// The scope.
        scope: Name,
        /// What it waits for.
        why: String,
    },
    /// An address, payload, batch, ttl or packet over its limit (§5). Next: send
    /// less, or put a version.
    #[error("{what} of {size} is over its limit of {max}; send less, or put a version")]
    TooLarge {
        /// What is over.
        what: &'static str,
        /// Its size (octets; signals for a batch; ms for a ttl or lifetime).
        size: usize,
        /// The limit.
        max: usize,
    },
    /// Over the sender's rate (§5). Next: send after `retry_after`, or batch.
    #[error(
        "over the run's rate of {SEND_RATE} packets/s (burst {SEND_BURST}); send after \
         {retry_after:?}, or batch"
    )]
    RateLimited {
        /// When a send is let again.
        retry_after: Duration,
    },
    /// The run has ended (closed, Signals shut down). Next: open a new run.
    #[error("the run has ended (closed, or Signals shut down); open a new run")]
    Closed,
    /// From the forwarder connection or the local ring.
    #[error("the forwarder connection or the local ring failed: {0}")]
    Io(String),
}

impl SignalError {
    /// What to do about it.
    pub fn next(&self) -> NextStep {
        match self {
            SignalError::NotMember { .. } => NextStep::AskOwner,
            SignalError::NotReady { .. } | SignalError::RateLimited { .. } => NextStep::RetryLater,
            SignalError::TooLarge { .. } | SignalError::Closed => NextStep::FixRequest,
            SignalError::Io(_) => NextStep::FixLocal,
        }
    }
}

/// A data-layer refusal of a scope as a signal refusal.
fn scope_error(scope: &Name, e: DataError) -> SignalError {
    match e.next() {
        NextStep::RetryLater => SignalError::NotReady {
            scope: scope.clone(),
            why: e.to_string(),
        },
        _ => SignalError::NotMember {
            scope: scope.clone(),
            why: e.to_string(),
        },
    }
}

fn system_us() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_micros() as u64)
}

/// A run's local ring: `<scope>/32=signal/32=ring/<RunId>`.
pub fn ring_name(scope: &Name, run: &RunId) -> Name {
    scope
        .clone()
        .append_component(NameComponent::keyword(Bytes::from_static(
            wire::SIGNAL_KEYWORD,
        )))
        .append_component(NameComponent::keyword(Bytes::from_static(b"ring")))
        .append(run.0)
}

// ---- counters and reasons ---------------------------------------------------------------------

#[derive(Default)]
struct Counters {
    sent_packets: AtomicU64,
    sent_bytes: AtomicU64,
    delivered: AtomicU64,
    local: AtomicU64,
    stale: AtomicU64,
    replayed: AtomicU64,
    expired: AtomicU64,
    not_member: AtomicU64,
    bad_signature: AtomicU64,
    unknown_run: AtomicU64,
    unknown_key: AtomicU64,
    flood: AtomicU64,
    malformed: AtomicU64,
    unsubscribed: AtomicU64,
}

/// Why a packet or signal is dropped.
#[derive(Clone, Copy, Debug)]
enum Reason {
    Stale,
    Replayed,
    Expired,
    NotMember,
    BadSignature,
    UnknownRun,
    UnknownKey,
    Flood,
    Malformed,
    Unsubscribed,
}

impl Reason {
    fn name(self) -> &'static str {
        match self {
            Reason::Stale => "stale",
            Reason::Replayed => "replayed",
            Reason::Expired => "expired",
            Reason::NotMember => "not_member",
            Reason::BadSignature => "bad_signature",
            Reason::UnknownRun => "unknown_run",
            Reason::UnknownKey => "unknown_key",
            Reason::Flood => "flood",
            Reason::Malformed => "malformed",
            Reason::Unsubscribed => "unsubscribed",
        }
    }

    /// What to do about it.
    fn next(self) -> &'static str {
        match self {
            Reason::Stale => "nothing: a newer signal of its address was delivered",
            Reason::Replayed => "nothing: a copy of it was taken already",
            Reason::Expired => {
                "nothing here; if every signal of a sender expires, its clock or ours is off by \
                 more than clock_skew"
            }
            Reason::NotMember => {
                "nothing here: the record in force here admits no such sender; its owner shares \
                 the scope with it, or this device fetches the newer record"
            }
            Reason::BadSignature => "nothing: forged, altered on the way, or a revoked key",
            Reason::UnknownRun => "nothing: the run's header rides again within a second",
            Reason::UnknownKey => {
                "nothing: this device holds no signal key of that epoch yet and asks for it"
            }
            Reason::Flood => "nothing here: the sender is over the limits of §5",
            Reason::Malformed => {
                "nothing here: the sender's program writes what this one doesn't read"
            }
            Reason::Unsubscribed => "subscribe to the scope to receive its signals",
        }
    }

    fn counter(self, c: &Counters) -> &AtomicU64 {
        match self {
            Reason::Stale => &c.stale,
            Reason::Replayed => &c.replayed,
            Reason::Expired => &c.expired,
            Reason::NotMember => &c.not_member,
            Reason::BadSignature => &c.bad_signature,
            Reason::UnknownRun => &c.unknown_run,
            Reason::UnknownKey => &c.unknown_key,
            Reason::Flood => &c.flood,
            Reason::Malformed => &c.malformed,
            Reason::Unsubscribed => &c.unsubscribed,
        }
    }
}

// ---- the hub ----------------------------------------------------------------------------------

struct ScopeState {
    queues: Vec<Weak<Queue>>,
    latest: Latest,
    rate: Bucket,
    sealed: bool,
}

struct RunState {
    scope: Name,
    sender: Name,
    key: VerifyingKey,
    start: u64,
    not_after: u64,
    window: ReplayWindow,
    rate: Bucket,
}

/// A packet of a run whose header is being admitted, processed once it is.
struct Waiting {
    body: Body,
    sealed: bool,
    local: bool,
}

#[derive(Default)]
struct HubState {
    scopes: HashMap<Name, ScopeState>,
    keys: HashMap<[u8; wire::KEY_ID_LEN], (Name, SignalKey)>,
    keys_refreshed_us: Option<u64>,
    runs: HashMap<RunId, RunState>,
    /// Runs whose header is being admitted, with the packets that wait for it.
    admitting: HashMap<RunId, Vec<Waiting>>,
    /// This process's runs (never attached to), and the rings of those that opened one.
    own: HashSet<RunId>,
    rings: HashMap<RunId, NamedPublisher>,
}

struct Hub {
    device: Device,
    conn: Arc<dyn Connection>,
    options: SignalOptions,
    listen: Name,
    counters: Counters,
    state: Mutex<HubState>,
    closed: AtomicBool,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

/// A header admitted: the run it starts.
struct Admitted {
    sender: Name,
    key: VerifyingKey,
    body: RunHeaderBody,
}

type Dropped = (Reason, String);

impl Hub {
    fn now_us(&self) -> u64 {
        self.options.clock.as_ref().map_or_else(system_us, |c| c())
    }

    fn lock(&self) -> MutexGuard<'_, HubState> {
        self.state.lock().expect("signal hub lock")
    }

    fn skew_ms(&self) -> u64 {
        self.options.clock_skew.as_millis() as u64
    }

    fn drop_packet(&self, reason: Reason, run: Option<&RunId>, why: &str) {
        self.drop_n(reason, 1, run, why);
    }

    fn drop_n(&self, reason: Reason, n: u64, run: Option<&RunId>, why: &str) {
        reason
            .counter(&self.counters)
            .fetch_add(n, Ordering::Relaxed);
        tracing::debug!(
            target: "ndn_surface::signal",
            reason = reason.name(),
            run = run.map(ToString::to_string),
            why,
            next = reason.next(),
            "signal dropped"
        );
    }

    fn spawn(&self, task: JoinHandle<()>) {
        let mut tasks = self.tasks.lock().expect("signal tasks lock");
        tasks.retain(|t| !t.is_finished());
        tasks.push(task);
    }

    /// A packet, pushed or off a ring: unseal, decode, then [`process`](Self::process).
    fn receive(self: &Arc<Self>, packet: Bytes, local: bool, scratch: &mut Vec<u8>) {
        if self.closed.load(Ordering::Relaxed) {
            return;
        }
        let decoded = match wire::decode_packet(packet) {
            Ok(p) => p,
            Err(e) => return self.drop_packet(Reason::Malformed, None, &e.to_string()),
        };
        let (body, sealed) = match decoded {
            Packet::Body(b) => (b, false),
            Packet::Sealed(s) => {
                let Some((scope, key)) = self.key_for(&s.key_id) else {
                    return self.drop_packet(
                        Reason::UnknownKey,
                        None,
                        &format!("sealed under the key id {:02x?}", s.key_id),
                    );
                };
                let Some(plain) = crypto::open(key.expose(), &s) else {
                    return self.drop_packet(
                        Reason::Malformed,
                        None,
                        &format!(
                            "sealed under the key id of {scope}'s epoch key but does not open \
                             under it: altered on the way"
                        ),
                    );
                };
                let body = match wire::decode_body(Bytes::from(plain)) {
                    Ok(b) => b,
                    Err(e) => return self.drop_packet(Reason::Malformed, None, &e.to_string()),
                };
                if body.scope != scope {
                    return self.drop_packet(
                        Reason::Malformed,
                        Some(&body.run),
                        &format!(
                            "sealed under {scope}'s key but names the scope {}",
                            body.scope
                        ),
                    );
                }
                (body, true)
            }
        };
        self.process(body, sealed, local, false, scratch);
    }

    /// The signal key of `id`, among the subscribed scopes' keys; on an unknown id
    /// the keys are asked of the device again, at most once a second.
    fn key_for(&self, id: &[u8; wire::KEY_ID_LEN]) -> Option<(Name, SignalKey)> {
        let now = self.now_us();
        let scopes: Vec<Name> = {
            let mut st = self.lock();
            if let Some(k) = st.keys.get(id) {
                return Some(k.clone());
            }
            if st
                .keys_refreshed_us
                .is_some_and(|t| now.saturating_sub(t) < KEY_REFRESH_EVERY_US)
            {
                return None;
            }
            st.keys_refreshed_us = Some(now);
            st.scopes.keys().cloned().collect()
        };
        for scope in scopes {
            if let Ok(s) = self.device.signal_scope(&scope) {
                set_keys(&mut self.lock(), &scope, &s);
            }
        }
        self.lock().keys.get(id).cloned()
    }

    /// The checks of a decoded body: of its run before verification, then the
    /// run signature and the sender's membership, then per signal.
    ///
    /// While a run's header is admitted, and until the packets that waited for it
    /// are processed in their order, its packets wait behind them; `drained`
    /// marks one the admission hands back.
    fn process(
        self: &Arc<Self>,
        body: Body,
        sealed: bool,
        local: bool,
        drained: bool,
        scratch: &mut Vec<u8>,
    ) {
        let now = self.now_us();
        let now_ms = now / 1000;
        let skew = self.skew_ms();
        let run_id = body.run;
        let (key, sender) = {
            let mut guard = self.lock();
            let st = &mut *guard;
            let Some(scope) = st.scopes.get_mut(&body.scope) else {
                return self.drop_packet(
                    Reason::Unsubscribed,
                    Some(&run_id),
                    &format!(
                        "a packet of {}, which no one subscribes to here",
                        body.scope
                    ),
                );
            };
            if scope.sealed && !sealed {
                return self.drop_packet(
                    Reason::Malformed,
                    Some(&run_id),
                    &format!("unsealed, and {} is sealed", body.scope),
                );
            }
            if !drained && let Some(waiting) = st.admitting.get_mut(&run_id) {
                if waiting.len() < WAITING_MAX {
                    waiting.push(Waiting {
                        body,
                        sealed,
                        local,
                    });
                } else {
                    self.drop_packet(
                        Reason::UnknownRun,
                        Some(&run_id),
                        &format!("{WAITING_MAX} packets wait for its header being admitted"),
                    );
                }
                return;
            }
            let Some(run) = st.runs.get_mut(&run_id) else {
                match body.header.clone() {
                    Some(header) => self.admit(st, body, sealed, local, header),
                    None => self.drop_packet(
                        Reason::UnknownRun,
                        Some(&run_id),
                        "no header of the run is held here yet",
                    ),
                }
                return;
            };
            if run.scope != body.scope {
                return self.drop_packet(
                    Reason::Malformed,
                    Some(&run_id),
                    &format!(
                        "the run is of {}, the packet names {}",
                        run.scope, body.scope
                    ),
                );
            }
            if body.signals.is_empty() {
                // A header-only packet of a run held: nothing to deliver.
                return;
            }
            if now_ms > run.not_after.saturating_add(skew) {
                return self.drop_packet(
                    Reason::Expired,
                    Some(&run_id),
                    &format!(
                        "past its run's NotAfter {} (now {now_ms} ms)",
                        run.not_after
                    ),
                );
            }
            if body.signals.iter().any(|s| s.seq < run.start) {
                return self.drop_packet(
                    Reason::Malformed,
                    Some(&run_id),
                    &format!("a sequence below its run's start {}", run.start),
                );
            }
            if !run.window.all_fresh(body.signals.iter().map(|s| s.seq)) {
                return self.drop_packet(
                    Reason::Replayed,
                    Some(&run_id),
                    "a sequence the run's window has seen, or older than it",
                );
            }
            if run.rate.take(1, now).is_err() {
                return self.drop_packet(
                    Reason::Flood,
                    Some(&run_id),
                    &format!("over {RECEIVE_RATE_RUN} packets/s of one run"),
                );
            }
            if scope.rate.take(1, now).is_err() {
                return self.drop_packet(
                    Reason::Flood,
                    Some(&run_id),
                    &format!("over {RECEIVE_RATE_SCOPE} packets/s of {}", body.scope),
                );
            }
            (run.key, run.sender.clone())
        };
        if !crypto::verify(&key, &body.signed, &body.signature, scratch) {
            return self.drop_packet(
                Reason::BadSignature,
                Some(&run_id),
                "its run signature does not verify by the run's key",
            );
        }
        if !self.device.signal_member(&body.scope, &sender) {
            return self.drop_packet(
                Reason::NotMember,
                Some(&run_id),
                &format!(
                    "{sender} is no member of {} by the record in force",
                    body.scope
                ),
            );
        }
        let mut guard = self.lock();
        let st = &mut *guard;
        let Some(run) = st.runs.get_mut(&run_id) else {
            return;
        };
        if !run.window.all_fresh(body.signals.iter().map(|s| s.seq)) {
            return self.drop_packet(
                Reason::Replayed,
                Some(&run_id),
                "another copy was taken while this one was verified",
            );
        }
        for s in &body.signals {
            run.window.mark(s.seq);
        }
        let Some(scope) = st.scopes.get_mut(&body.scope) else {
            return;
        };
        scope.queues.retain(|q| q.strong_count() > 0);
        let ttl_max = TTL_MAX.as_millis() as u64;
        for s in body.signals {
            if s.expires.saturating_add(skew) < now_ms {
                self.drop_packet(
                    Reason::Expired,
                    Some(&run_id),
                    &format!("its Expires {} is past (now {now_ms} ms)", s.expires),
                );
                continue;
            }
            if s.expires > now_ms.saturating_add(ttl_max).saturating_add(skew) {
                self.drop_packet(
                    Reason::Malformed,
                    Some(&run_id),
                    &format!("its Expires {} is more than 60 s ahead", s.expires),
                );
                continue;
            }
            if !scope.latest.advance(&sender, &s.address, s.seq) {
                self.drop_packet(
                    Reason::Stale,
                    Some(&run_id),
                    "a newer signal of its sender and address was delivered",
                );
                continue;
            }
            let signal = Signal {
                scope: body.scope.clone(),
                sender: sender.clone(),
                run: run_id,
                seq: s.seq,
                address: s.address,
                payload: s.payload,
                expires: s.expires,
                local,
            };
            for q in &scope.queues {
                if let Some(q) = q.upgrade() {
                    q.push(signal.clone());
                }
            }
            self.counters.delivered.fetch_add(1, Ordering::Relaxed);
            if local {
                self.counters.local.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Admit the header a packet of an unknown run carries, then process the
    /// packet and those of the run that came meanwhile.
    fn admit(
        self: &Arc<Self>,
        st: &mut HubState,
        body: Body,
        sealed: bool,
        local: bool,
        header: Bytes,
    ) {
        let run = body.run;
        if st.admitting.len() >= ADMITTING_MAX {
            return self.drop_packet(
                Reason::Flood,
                Some(&run),
                &format!("{ADMITTING_MAX} run headers are being admitted already"),
            );
        }
        st.admitting.insert(run, Vec::new());
        let hub = Arc::clone(self);
        let task = tokio::spawn(async move {
            let outcome = hub.check_header(&body, header).await;
            let Some((attach, waiting)) = hub.admitted(&body, outcome) else {
                return;
            };
            if let Some((ring, secret)) = attach {
                hub.attach(ring, secret, run);
            }
            let mut scratch = Vec::with_capacity(PACKET_MAX + 16);
            hub.process(body, sealed, local, true, &mut scratch);
            let mut waiting = waiting;
            // Packets keep waiting behind those taken until none is left, so
            // the run's packets are processed in the order they came.
            loop {
                for w in waiting {
                    hub.process(w.body, w.sealed, w.local, true, &mut scratch);
                }
                let mut st = hub.lock();
                match st.admitting.get_mut(&run) {
                    Some(more) if !more.is_empty() => waiting = std::mem::take(more),
                    _ => {
                        st.admitting.remove(&run);
                        break;
                    }
                }
            }
        });
        self.spawn(task);
    }

    async fn check_header(&self, body: &Body, header: Bytes) -> Result<Admitted, Dropped> {
        let malformed = |why: String| (Reason::Malformed, why);
        let data = Data::decode(header)
            .map_err(|e| malformed(format!("its run header is no Data packet: {e}")))?;
        let content = data.content().map(|c| c.as_ref()).unwrap_or(&[]);
        let hb = wire::decode_run_header_body(content)
            .map_err(|e| malformed(format!("its run header's content: {e}")))?;
        if RunId::of_key(&hb.key) != body.run {
            return Err((
                Reason::BadSignature,
                "its run header binds a key whose id is another run's".into(),
            ));
        }
        match ndn_data::wire::parse_signal_run_name(&data.name) {
            Some(n) if n.run == body.run.0 && n.scope == body.scope => {}
            _ => {
                return Err(malformed(format!(
                    "its run header {} is not the header of run {} of {}",
                    data.name, body.run, body.scope
                )));
            }
        }
        let now_ms = self.now_us() / 1000;
        let skew = self.skew_ms();
        if now_ms > hb.not_after.saturating_add(skew) {
            return Err((
                Reason::Expired,
                format!("its run ended at {} (now {now_ms} ms)", hb.not_after),
            ));
        }
        let lifetime_max = RUN_LIFETIME_MAX.as_millis() as u64;
        if hb.not_after > now_ms.saturating_add(lifetime_max).saturating_add(skew) {
            return Err(malformed(format!(
                "its run's NotAfter {} is more than 24 h ahead",
                hb.not_after
            )));
        }
        let key = VerifyingKey::from_bytes(&hb.key)
            .map_err(|_| malformed("its run key is no Ed25519 public key".into()))?;
        let sender = self
            .device
            .signal_admit(&body.scope, &data)
            .await
            .map_err(|r| match r {
                SignalRefusal::Malformed { .. } => (Reason::Malformed, r.to_string()),
                SignalRefusal::BadSignature { .. } => (Reason::BadSignature, r.to_string()),
                SignalRefusal::NotMember { .. } => (Reason::NotMember, r.to_string()),
                SignalRefusal::NotReady { .. } => (Reason::UnknownRun, r.to_string()),
            })?;
        Ok(Admitted {
            sender,
            key,
            body: hb,
        })
    }

    /// Hold the run a header admitted, within the limits: the packets that
    /// waited for it, and its ring when this host serves it and the run isn't
    /// this process's. `None` when it is not held (each waiting packet counted).
    #[allow(clippy::type_complexity)]
    fn admitted(
        &self,
        body: &Body,
        outcome: Result<Admitted, Dropped>,
    ) -> Option<(Option<(Name, [u8; 32])>, Vec<Waiting>)> {
        let run = body.run;
        let mut guard = self.lock();
        let st = &mut *guard;
        let waiting = st.admitting.remove(&run).unwrap_or_default();
        let refuse = |reason: Reason, why: &str| {
            self.drop_n(reason, 1 + waiting.len() as u64, Some(&run), why);
        };
        let a = match outcome {
            Ok(a) => a,
            Err((reason, why)) => {
                refuse(reason, &why);
                return None;
            }
        };
        if !st.scopes.contains_key(&body.scope) {
            refuse(
                Reason::Unsubscribed,
                &format!(
                    "{} was unsubscribed while its header was admitted",
                    body.scope
                ),
            );
            return None;
        }
        let now = self.now_us();
        let skew = self.skew_ms();
        st.runs
            .retain(|_, r| now / 1000 <= r.not_after.saturating_add(skew));
        let of_sender: Vec<(RunId, u64)> = st
            .runs
            .iter()
            .filter(|(_, r)| r.scope == body.scope && r.sender == a.sender)
            .map(|(id, r)| (*id, r.start))
            .collect();
        if of_sender.len() >= RUNS_PER_SENDER {
            let (oldest, start) = of_sender
                .iter()
                .min_by_key(|(_, s)| *s)
                .copied()
                .expect("a sender at its limit holds runs");
            if a.body.start <= start {
                refuse(
                    Reason::Flood,
                    &format!(
                        "{} holds {RUNS_PER_SENDER} newer runs of {} here",
                        a.sender, body.scope
                    ),
                );
                return None;
            }
            st.runs.remove(&oldest);
        }
        if st.runs.values().filter(|r| r.scope == body.scope).count() >= RUNS_PER_SCOPE {
            refuse(
                Reason::Flood,
                &format!("{} holds {RUNS_PER_SCOPE} runs here", body.scope),
            );
            return None;
        }
        st.runs.insert(
            run,
            RunState {
                scope: body.scope.clone(),
                sender: a.sender,
                key: a.key,
                start: a.body.start,
                not_after: a.body.not_after,
                window: ReplayWindow::default(),
                rate: Bucket::new(RECEIVE_RATE_RUN, RECEIVE_RATE_RUN, now),
            },
        );
        let ring = a
            .body
            .ring
            .filter(|_| !st.own.contains(&run))
            .map(|secret| (ring_name(&body.scope, &run), secret))
            .filter(|(ring, _)| crate::served_here(ring));
        // The run's later packets keep waiting behind those taken here until
        // the admission has processed them (see `admit`).
        st.admitting.insert(run, Vec::new());
        Some((ring, waiting))
    }

    /// Read a run's ring on this host: its packets enter the same pipeline, local.
    fn attach(self: &Arc<Self>, ring: Name, secret: [u8; 32], run: RunId) {
        let weak = Arc::downgrade(self);
        let task = tokio::spawn(async move {
            let mut sub =
                match NamedSubscriber::connect_broadcast_gated(ring.clone(), &secret).await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::debug!(
                            target: "ndn_surface::signal",
                            %run,
                            %ring,
                            error = %e,
                            next = "nothing: the run's packets come over the forwarder",
                            "the run's ring on this host did not take this reader"
                        );
                        return;
                    }
                };
            tracing::debug!(target: "ndn_surface::signal", %run, %ring, "reading the run's ring on this host");
            let mut scratch = Vec::with_capacity(PACKET_MAX + 16);
            while let Some(packet) = sub.next_broadcast().await {
                let Some(hub) = weak.upgrade() else { return };
                hub.receive(packet, true, &mut scratch);
                drop(hub);
                // Subscribers on this runtime read between packets, not after a backlog.
                tokio::task::yield_now().await;
            }
        });
        self.spawn(task);
    }

    fn publish_ring(&self, run: &RunId, packet: &[u8]) -> Result<(), SignalError> {
        if let Some(ring) = self.lock().rings.get_mut(run) {
            ring.publish_broadcast(packet)
                .map_err(|e| SignalError::Io(format!("the run's local ring: {e}")))?;
        }
        Ok(())
    }

    fn end_run(&self, run: &RunId) {
        let ring = {
            let mut st = self.lock();
            st.own.remove(run);
            st.rings.remove(run)
        };
        if let Some(ring) = ring {
            ring.end_broadcast();
        }
    }

    fn shutdown(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        for t in self.tasks.lock().expect("signal tasks lock").drain(..) {
            t.abort();
        }
        let (scopes, rings) = {
            let mut st = self.lock();
            st.runs.clear();
            st.keys.clear();
            (
                std::mem::take(&mut st.scopes),
                std::mem::take(&mut st.rings),
            )
        };
        for q in scopes.values().flat_map(|s| s.queues.iter()) {
            if let Some(q) = q.upgrade() {
                q.close();
            }
        }
        for ring in rings.into_values() {
            ring.end_broadcast();
        }
    }
}

impl Drop for Hub {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn set_keys(st: &mut HubState, scope: &Name, s: &SignalScope) {
    st.keys.retain(|_, (sc, _)| sc != scope);
    for k in &s.keys {
        st.keys.insert(k.id, (scope.clone(), k.clone()));
    }
    if let Some(ss) = st.scopes.get_mut(scope) {
        ss.sealed = !s.keys.is_empty();
    }
}

/// The packet a pushed wire carries, if it is a push Interest (LP-wrapped or not).
fn pushed(wire: Bytes) -> Option<Bytes> {
    let wire = if wire.first() == Some(&0x64) {
        ndn_packet::lp::LpPacket::decode(wire).ok()?.fragment?
    } else {
        wire
    };
    wire::push_packet(&Interest::decode(wire).ok()?)
}

// ---- the public handles -----------------------------------------------------------------------

/// One process's signals: a dedicated connection to the forwarder (in-process
/// engine or ndn-ipc), a Device for gating, keys and run headers. Cheap to clone.
#[derive(Clone)]
pub struct Signals {
    hub: Arc<Hub>,
}

impl Signals {
    /// Registers this device's own namespace group `<ns>/32=sync` on `conn` and
    /// starts receiving. `conn` must be a connection of its own (not the Device's).
    /// On an in-process engine the host routes the group to this connection's face,
    /// as it routes the Device's sync face. Refused `TooLarge` for a ttl or run
    /// lifetime over its limit, `Io` when the group can't be registered.
    pub async fn start(
        device: Device,
        conn: Arc<dyn Connection>,
        options: SignalOptions,
    ) -> Result<Signals, SignalError> {
        if options.ttl > TTL_MAX {
            return Err(SignalError::TooLarge {
                what: "the default ttl (ms)",
                size: options.ttl.as_millis() as usize,
                max: TTL_MAX.as_millis() as usize,
            });
        }
        if options.run_lifetime > RUN_LIFETIME_MAX || options.run_lifetime.is_zero() {
            return Err(SignalError::TooLarge {
                what: "the run lifetime (ms; more than 0)",
                size: options.run_lifetime.as_millis() as usize,
                max: RUN_LIFETIME_MAX.as_millis() as usize,
            });
        }
        let listen = wire::sync_group(device.namespace());
        conn.register_prefix(&listen).await.map_err(|e| {
            SignalError::Io(format!("cannot register {listen} on the connection: {e}"))
        })?;
        let hub = Arc::new(Hub {
            device,
            conn: Arc::clone(&conn),
            options,
            listen,
            counters: Counters::default(),
            state: Mutex::new(HubState::default()),
            closed: AtomicBool::new(false),
            tasks: Mutex::new(Vec::new()),
        });
        let weak = Arc::downgrade(&hub);
        let task = tokio::spawn(async move {
            let mut scratch = Vec::with_capacity(PACKET_MAX + 16);
            while let Some(wire) = conn.recv().await {
                let Some(packet) = pushed(wire) else { continue };
                let Some(hub) = weak.upgrade() else { return };
                hub.receive(packet, false, &mut scratch);
                drop(hub);
                // Subscribers on this runtime read between packets, not after a backlog.
                tokio::task::yield_now().await;
            }
        });
        hub.spawn(task);
        Ok(Signals { hub })
    }

    /// The group this device listens in: its namespace's `<ns>/32=sync`.
    pub fn listen(&self) -> &Name {
        &self.hub.listen
    }

    fn open_check(&self) -> Result<(), SignalError> {
        if self.hub.closed.load(Ordering::Relaxed) {
            return Err(SignalError::Closed);
        }
        Ok(())
    }

    /// Signals of `scope` (a folder or a collection), from every member, local or
    /// remote. Refused with NotMember when this device isn't a member by the record
    /// in force, NotReady when no record is held yet (or, sealed, the epoch key
    /// isn't held yet: its ask has started; ask again).
    pub async fn subscribe(&self, scope: &Name) -> Result<SignalSubscriber, SignalError> {
        self.open_check()?;
        let s = self
            .hub
            .device
            .signal_scope(scope)
            .map_err(|e| scope_error(scope, e))?;
        let queue = Arc::new(Queue::default());
        let now = self.hub.now_us();
        let mut st = self.hub.lock();
        st.scopes
            .entry(scope.clone())
            .or_insert_with(|| ScopeState {
                queues: Vec::new(),
                latest: Latest::default(),
                rate: Bucket::new(RECEIVE_RATE_SCOPE, RECEIVE_RATE_SCOPE, now),
                sealed: false,
            })
            .queues
            .push(Arc::downgrade(&queue));
        set_keys(&mut st, scope, &s);
        Ok(SignalSubscriber {
            scope: scope.clone(),
            queue,
            hub: Arc::clone(&self.hub),
        })
    }

    /// Open a run: a fresh Ed25519 run key, its header signed by the device key, a
    /// local ring. Refused as subscribe is.
    pub async fn open(&self, scope: &Name) -> Result<SignalRun, SignalError> {
        self.open_check()?;
        self.hub
            .device
            .signal_scope(scope)
            .map_err(|e| scope_error(scope, e))?;
        let now = self.hub.now_us();
        let keyed = Keyed::new(&self.hub, scope, now, now).await?;
        Ok(SignalRun {
            hub: Arc::clone(&self.hub),
            scope: scope.clone(),
            next_seq: now,
            keyed: Some(keyed),
            bucket: Bucket::new(SEND_RATE, SEND_BURST, now),
            body: Vec::with_capacity(PACKET_MAX),
            scratch: Vec::with_capacity(PACKET_MAX + 16),
        })
    }

    /// Counters since start, by reason (what was refused and dropped, and why).
    pub fn stats(&self) -> SignalStats {
        let c = &self.hub.counters;
        let l = |a: &AtomicU64| a.load(Ordering::Relaxed);
        SignalStats {
            sent_packets: l(&c.sent_packets),
            sent_bytes: l(&c.sent_bytes),
            delivered: l(&c.delivered),
            local: l(&c.local),
            stale: l(&c.stale),
            replayed: l(&c.replayed),
            expired: l(&c.expired),
            not_member: l(&c.not_member),
            bad_signature: l(&c.bad_signature),
            unknown_run: l(&c.unknown_run),
            unknown_key: l(&c.unknown_key),
            flood: l(&c.flood),
            malformed: l(&c.malformed),
            unsubscribed: l(&c.unsubscribed),
        }
    }

    /// Stop: closes every run (their rings end) and subscriber.
    pub fn shutdown(&self) {
        self.hub.shutdown();
    }
}

/// A run's key material: its key, its signed header, when it opened.
struct Keyed {
    key: RunKey,
    header: Bytes,
    opened_us: u64,
    header_rode_us: Option<u64>,
}

impl Keyed {
    /// A new run of `scope` starting at sequence `start`: its key, its header
    /// signed by the device, and its local ring.
    async fn new(hub: &Arc<Hub>, scope: &Name, start: u64, now: u64) -> Result<Keyed, SignalError> {
        let key = RunKey::generate()
            .map_err(|e| SignalError::Io(format!("no randomness for a run key: {e}")))?;
        let ring =
            if hub.options.local_ring {
                Some(crypto::random::<32>().map_err(|e| {
                    SignalError::Io(format!("no randomness for a ring secret: {e}"))
                })?)
            } else {
                None
            };
        let body = RunHeaderBody {
            key: *key.public(),
            start,
            not_after: now / 1000 + hub.options.run_lifetime.as_millis() as u64,
            ring,
        };
        let header = hub
            .device
            .signal_header(scope, &key.id().0, &wire::encode_run_header_body(&body))
            .map_err(|e| scope_error(scope, e))?;
        let id = key.id();
        hub.lock().own.insert(id);
        if let Some(secret) = ring {
            let name = ring_name(scope, &id);
            let max_frame = PACKET_MAX + wire::name_size(&name) + 32;
            let opened = NamedPublisher::open_broadcast_gated_with(
                name,
                &secret,
                max_frame,
                RING_SLOTS,
                RING_READERS,
            )
            .await;
            match opened {
                Ok(ring) => {
                    hub.lock().rings.insert(id, ring);
                }
                Err(e) => {
                    hub.lock().own.remove(&id);
                    return Err(SignalError::Io(format!(
                        "the local ring of run {id} did not open: {e}"
                    )));
                }
            }
        }
        Ok(Keyed {
            key,
            header,
            opened_us: now,
            header_rode_us: None,
        })
    }
}

/// A run: one sender's signals in one scope, under one run key (renewed at 90 %
/// of its lifetime, sequences continuing).
pub struct SignalRun {
    hub: Arc<Hub>,
    scope: Name,
    next_seq: u64,
    /// `None` once closed.
    keyed: Option<Keyed>,
    bucket: Bucket,
    body: Vec<u8>,
    scratch: Vec<u8>,
}

/// One packet to push: its signals, and whether the header rides.
struct Planned {
    header: bool,
    signals: Range<usize>,
}

impl SignalRun {
    /// One signal, pushed now as its own packet. Returns its sequence.
    pub async fn send(&mut self, address: &[u8], payload: &[u8]) -> Result<u64, SignalError> {
        let ttl = self.hub.options.ttl;
        self.send_for(address, payload, ttl).await
    }

    /// Like send, with an Expires other than the default ttl.
    pub async fn send_for(
        &mut self,
        address: &[u8],
        payload: &[u8],
        ttl: Duration,
    ) -> Result<u64, SignalError> {
        Ok(self.push(&[(address, payload)], ttl).await?.start)
    }

    /// Several signals in one packet (fewer bytes and signatures), consecutive
    /// sequences. Each element is (address, payload). Refused TooLarge if they
    /// don't fit one packet.
    pub async fn send_batch(
        &mut self,
        signals: &[(&[u8], &[u8])],
    ) -> Result<Range<u64>, SignalError> {
        let ttl = self.hub.options.ttl;
        self.push(signals, ttl).await
    }

    /// The current run's id (a renewal makes a new one).
    pub fn id(&self) -> RunId {
        self.keyed.as_ref().map_or(RunId([0; 16]), |k| k.key.id())
    }

    /// The scope.
    pub fn scope(&self) -> &Name {
        &self.scope
    }

    /// Ends the run: its ring tells local readers it ended. Remote readers forget
    /// the run at NotAfter, or sooner when a newer run of the same sender replaces it.
    pub async fn close(mut self) {
        self.end();
    }

    fn end(&mut self) {
        if let Some(k) = self.keyed.take() {
            self.hub.end_run(&k.key.id());
        }
    }

    async fn push(
        &mut self,
        signals: &[(&[u8], &[u8])],
        ttl: Duration,
    ) -> Result<Range<u64>, SignalError> {
        if self.hub.closed.load(Ordering::Relaxed) || self.keyed.is_none() {
            return Err(SignalError::Closed);
        }
        if signals.len() > wire::SIGNALS_MAX {
            return Err(SignalError::TooLarge {
                what: "a batch (signals)",
                size: signals.len(),
                max: wire::SIGNALS_MAX,
            });
        }
        if ttl > TTL_MAX {
            return Err(SignalError::TooLarge {
                what: "a ttl (ms)",
                size: ttl.as_millis() as usize,
                max: TTL_MAX.as_millis() as usize,
            });
        }
        for (address, payload) in signals {
            if address.len() > wire::ADDRESS_MAX {
                return Err(SignalError::TooLarge {
                    what: "an address",
                    size: address.len(),
                    max: wire::ADDRESS_MAX,
                });
            }
            if payload.len() > wire::PAYLOAD_MAX {
                return Err(SignalError::TooLarge {
                    what: "a payload",
                    size: payload.len(),
                    max: wire::PAYLOAD_MAX,
                });
            }
        }
        let first = self.next_seq;
        if signals.is_empty() {
            return Ok(first..first);
        }
        // Membership, keys and groups by the record in force now: NotMember from
        // the moment this device holds a record that removes it.
        let scope = self
            .hub
            .device
            .signal_scope(&self.scope)
            .map_err(|e| scope_error(&self.scope, e))?;
        let mut now = self.hub.now_us();
        let lifetime = self.hub.options.run_lifetime.as_micros() as u64;
        let opened = self.keyed.as_ref().map_or(now, |k| k.opened_us);
        if now.saturating_sub(opened) >= lifetime / 10 * 9 {
            self.renew(now).await?;
            now = self.hub.now_us();
        }
        let keyed = self.keyed.as_mut().ok_or(SignalError::Closed)?;
        let expires = now / 1000 + ttl.as_millis() as u64;
        let outgoing: Vec<Outgoing<'_>> = signals
            .iter()
            .zip(first..)
            .map(|((a, p), seq)| (seq, *a, expires, *p))
            .collect();
        let sealed = scope.keys.first();
        let size = |header: bool, of: &[Outgoing<'_>]| {
            let body = wire::body_size(
                wire::name_size(&self.scope),
                header.then_some(keyed.header.len()),
                of,
            );
            if sealed.is_some() {
                wire::sealed_size(body)
            } else {
                body
            }
        };
        let header_due = keyed
            .header_rode_us
            .is_none_or(|t| now.saturating_sub(t) >= HEADER_EVERY.as_micros() as u64);
        let all = 0..outgoing.len();
        let plan: Vec<Planned> = if !header_due {
            vec![Planned {
                header: false,
                signals: all,
            }]
        } else if size(true, &outgoing) <= PACKET_MAX {
            vec![Planned {
                header: true,
                signals: all,
            }]
        } else if size(true, &[]) > PACKET_MAX {
            return Err(SignalError::TooLarge {
                what: "the run header in a packet",
                size: size(true, &[]),
                max: PACKET_MAX,
            });
        } else {
            vec![
                Planned {
                    header: true,
                    signals: 0..0,
                },
                Planned {
                    header: false,
                    signals: all,
                },
            ]
        };
        let without = size(false, &outgoing);
        if without > PACKET_MAX {
            return Err(SignalError::TooLarge {
                what: "the packet",
                size: without,
                max: PACKET_MAX,
            });
        }
        self.bucket
            .take(plan.len() as u64, now)
            .map_err(|retry_after| SignalError::RateLimited { retry_after })?;
        let run = keyed.key.id();
        for p in plan {
            let header = p.header.then_some(keyed.header.as_ref());
            let key = &keyed.key;
            let scratch = &mut self.scratch;
            wire::encode_body(
                &mut self.body,
                &self.scope,
                &run,
                header,
                &outgoing[p.signals],
                |region| key.sign(region, scratch),
            );
            let packet = match sealed {
                Some(k) => {
                    let nonce = crypto::random::<{ wire::NONCE_LEN }>()
                        .map_err(|e| SignalError::Io(format!("no randomness for a nonce: {e}")))?;
                    Bytes::from(crypto::seal(k.expose(), &k.id, &nonce, &self.body))
                }
                None => Bytes::copy_from_slice(&self.body),
            };
            // The ring first: a reader on this host takes that copy, and the
            // forwarder's comes second, dropped by its window unverified.
            self.hub.publish_ring(&run, &packet)?;
            let mut bytes = 0u64;
            for group in &scope.groups {
                let interest = wire::push_interest(group, &packet);
                bytes += interest.len() as u64;
                self.hub
                    .conn
                    .send(interest)
                    .await
                    .map_err(|e| SignalError::Io(format!("pushing into {group}: {e}")))?;
            }
            self.hub
                .counters
                .sent_packets
                .fetch_add(1, Ordering::Relaxed);
            self.hub
                .counters
                .sent_bytes
                .fetch_add(bytes, Ordering::Relaxed);
            if p.header {
                keyed.header_rode_us = Some(now);
            }
        }
        self.next_seq = first + signals.len() as u64;
        Ok(first..self.next_seq)
    }

    /// A new run key, header and ring; sequences continue; the old ring ends.
    async fn renew(&mut self, now: u64) -> Result<(), SignalError> {
        let keyed = Keyed::new(&self.hub, &self.scope, self.next_seq, now).await?;
        if let Some(old) = self.keyed.replace(keyed) {
            self.hub.end_run(&old.key.id());
        }
        Ok(())
    }
}

impl Drop for SignalRun {
    fn drop(&mut self) {
        self.end();
    }
}

/// A scope's signals, as they arrive: the newest per (sender, address) not yet read.
pub struct SignalSubscriber {
    scope: Name,
    queue: Arc<Queue>,
    hub: Arc<Hub>,
}

impl SignalSubscriber {
    /// The next signal: the newest per (sender, address) not yet read. None once
    /// Signals is shut down.
    pub async fn next(&mut self) -> Option<Signal> {
        self.queue.next().await
    }

    /// The scope.
    pub fn scope(&self) -> &Name {
        &self.scope
    }
}

impl Drop for SignalSubscriber {
    fn drop(&mut self) {
        let mut guard = self.hub.lock();
        let st = &mut *guard;
        let Some(s) = st.scopes.get_mut(&self.scope) else {
            return;
        };
        let mine = Arc::downgrade(&self.queue);
        s.queues
            .retain(|q| q.strong_count() > 0 && !q.ptr_eq(&mine));
        if s.queues.is_empty() {
            st.scopes.remove(&self.scope);
            st.keys.retain(|_, (sc, _)| *sc != self.scope);
            st.runs.retain(|_, r| r.scope != self.scope);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wire::{decode_packet, encode_body};

    #[test]
    fn a_run_signature_over_one_scope_fails_in_another() {
        let key = RunKey::from_secret(&[3; 32]);
        let public = VerifyingKey::from_bytes(key.public()).unwrap();
        let mut scratch = Vec::new();
        let signals: [Outgoing<'_>; 1] = [(1, b"cursor", 2, b"x")];
        let sign_in = |scope: &str, scratch: &mut Vec<u8>| {
            let mut out = Vec::new();
            encode_body(
                &mut out,
                &scope.parse().unwrap(),
                &key.id(),
                None,
                &signals,
                |r| key.sign(r, scratch),
            );
            out
        };
        let board = sign_in("/alice/32=data/board", &mut scratch);
        let Packet::Body(b) = decode_packet(Bytes::from(board)).unwrap() else {
            panic!("a body");
        };
        assert!(crypto::verify(
            &public,
            &b.signed,
            &b.signature,
            &mut scratch
        ));
        // The same signature carried over a packet naming another scope.
        let mut other = Vec::new();
        let sig = b.signature;
        encode_body(
            &mut other,
            &"/alice/32=data/notes".parse().unwrap(),
            &key.id(),
            None,
            &signals,
            |_| sig,
        );
        let Packet::Body(o) = decode_packet(Bytes::from(other)).unwrap() else {
            panic!("a body");
        };
        assert_eq!(o.signature, sig);
        assert!(
            !crypto::verify(&public, &o.signed, &o.signature, &mut scratch),
            "a run signature binds its scope"
        );
    }
}
