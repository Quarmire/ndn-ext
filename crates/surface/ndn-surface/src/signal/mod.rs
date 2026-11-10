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

mod clock;
mod crypto;
mod queue;
mod state;
pub mod wire;

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::num::NonZeroU32;
use std::ops::Range;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::Duration;

use bytes::Bytes;
use ed25519_dalek::VerifyingKey;
use ndn_app::Connection;
use ndn_data::{DataError, Device, NextStep, SignalKey, SignalRefusal, SignalScope, SignalSender};
use ndn_foundation_types::{Name, NameComponent};
use ndn_packet::{Data, Interest};
use tokio::task::JoinHandle;

use crate::{NamedPublisher, NamedSubscriber};
use clock::Clock;
use crypto::RunKey;
use queue::Queue;
use state::{Bucket, Latest, ReplayWindow};
use wire::{Body, Outgoing, PACKET_MAX, Packet, RunHeaderBody, ScopeDigest};
pub use wire::{RunId, SCOPE_MAX};

/// The longest `Expires` after now a signal may carry (§5).
pub const TTL_MAX: Duration = Duration::from_secs(60);
/// The longest a run lasts from its start (§5).
pub const RUN_LIFETIME_MAX: Duration = Duration::from_secs(24 * 3600);
/// A sender's packets per second per run (§5).
pub const SEND_RATE: u64 = 120;
/// A sender's burst per run (§5).
pub const SEND_BURST: u64 = 30;
/// A receiver's verified packets per second per run (§10), charged once a
/// packet's run signature verifies.
pub const RECEIVE_RATE_RUN: u64 = 240;
/// A receiver's verified packets per second per scope (§10), charged once a
/// packet's run signature verifies.
pub const RECEIVE_RATE_SCOPE: u64 = 2000;
/// Signature checks per second of a scope's packets not verified yet (§10):
/// four times its verified rate, so forgeries spend their own budget, never
/// the verified traffic's.
pub const CHECK_RATE_SCOPE: u64 = 4 * RECEIVE_RATE_SCOPE;
/// Signature checks per second of packets not verified yet, per process
/// (§10): about 0.8 s of one core's Ed25519 verification.
pub const CHECK_RATE_PROCESS: u64 = 16_000;
/// Runs held per sender key per scope (§8.4).
pub const RUNS_PER_SENDER: usize = 4;
/// Runs held per sender namespace per scope (§8.4).
pub const RUNS_PER_NAMESPACE: usize = 16;
/// Runs held per scope (§8.4).
pub const RUNS_PER_SCOPE: usize = 64;
/// A run none of whose packets verified for this long may be let go for
/// another at a cap (§8.4).
pub const RUN_IDLE: Duration = Duration::from_secs(60);
/// Run headers being admitted at once per scope (§8.1).
pub const ADMITTING_PER_SCOPE: usize = 8;
/// Run headers being admitted at once per sender namespace (§8.1).
pub const ADMITTING_PER_NAMESPACE: usize = 2;
/// Packets of a run kept while its header is admitted; more are `unknown_run`.
pub const WAITING_MAX: usize = 32;
/// How long after this process first sees an epoch superseded it still
/// opens packets sealed under that epoch's signal key (§4.2).
pub const EPOCH_GRACE: Duration = Duration::from_secs(60);
/// How often a header rides again in its run's packets.
pub const HEADER_EVERY: Duration = Duration::from_secs(1);
/// The default push budget of a process: push Interests per second, shared by
/// all its runs (§5). A packet costs one push Interest per group it goes into.
/// A relay serving under quotas counts every packet a device sends, 100/s per
/// key by default (ndn-link §15.3); 80 leaves a fifth of it to the device's
/// Data, sync and certificate traffic.
pub const PUSH_RATE: NonZeroU32 = NonZeroU32::new(80).unwrap();
/// The default push burst of a process, in push Interests: twice the rate, as a
/// relay's quota bursts (200 for 100/s).
pub const PUSH_BURST: NonZeroU32 = NonZeroU32::new(160).unwrap();

/// Slots of a run's local ring: two seconds at the sender's full rate.
const RING_SLOTS: u32 = 256;
/// Readers a run's local ring takes.
const RING_READERS: u32 = 32;
/// Least time between two refreshes of the signal keys on an unknown key id.
const KEY_REFRESH_EVERY_US: u64 = 1_000_000;
/// How often the signal keys are asked of the device again while known ids
/// arrive, so an epoch superseded is noticed and its grace starts (§4.2).
const KEY_CONFIRM_EVERY_US: u64 = 5_000_000;
/// When to ask the device for more clock floor: its reserve (ndn-data's `SIGNAL_CLOCK_RESERVE`, 5 s
/// ahead of the time asked) is asked for again once less than half of it is left.
const CLOCK_RESERVE_US: u64 = 5_000_000;

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
    /// The push Interests per second this process sends, shared by all its runs:
    /// [`PUSH_RATE`]. A packet costs one per group it goes into, so a run at
    /// 60 Hz fits into one group, and into more only batched
    /// ([`SignalRun::send_batch`]). Kept below a relay's quota per device
    /// (ndn-link §15.3); a host whose links carry no quota (its own relays, a
    /// forwarder with no serving quota) may raise it.
    pub push_rate: NonZeroU32,
    /// The push Interests this process may send at once: [`PUSH_BURST`]. One send
    /// over it (a packet into more groups) is let from a full budget.
    pub push_burst: NonZeroU32,
}

impl Default for SignalOptions {
    fn default() -> Self {
        SignalOptions {
            ttl: Duration::from_secs(2),
            run_lifetime: Duration::from_secs(3600),
            local_ring: true,
            clock_skew: Duration::from_secs(30),
            clock: None,
            push_rate: PUSH_RATE,
            push_burst: PUSH_BURST,
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
            .field("push_rate", &self.push_rate)
            .field("push_burst", &self.push_burst)
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
    /// The scope's name is too long for a run to be opened in it: a run's
    /// header carries the scope's Name and the device's key name, and must fit a
    /// packet of its own ([`SCOPE_MAX`] encoded octets of scope for a device
    /// key name up to 140). Next: name the folder or collection shorter.
    #[error(
        "the scope {scope} is {size} encoded octets long, over the {max} that a run's header \
         can name in one packet of {} octets (it carries the scope's name and this device's \
         key name, and a signal packet then names the scope only by a 16-octet digest); name \
         the folder or collection with a shorter name",
        wire::PACKET_MAX
    )]
    ScopeTooLong {
        /// The scope.
        scope: Name,
        /// Its encoded octets (its Name TLV).
        size: usize,
        /// The most this device's runs can name: at most [`SCOPE_MAX`].
        max: usize,
    },
    /// Two scopes this process subscribes to have one 16-octet scope digest, so
    /// their packets could not be told apart. Next: unsubscribe one, or name it
    /// otherwise.
    #[error(
        "the scope {scope} has the same 16-octet scope digest as {other}, which this process \
         subscribes to already, so their packets could not be told apart; drop the \
         subscription to {other} first, or name {scope} otherwise"
    )]
    ScopeDigestCollision {
        /// The scope refused.
        scope: Name,
        /// The scope subscribed already.
        other: Name,
    },
    /// Over the run's rate, or over the process's push budget, which counts each
    /// packet once per group it goes into (§5). Next: send after `retry_after`,
    /// batch with `send_batch`, or send less.
    #[error(
        "over the run's rate of {SEND_RATE} packets/s (burst {SEND_BURST}) or this process's \
         push budget (SignalOptions::push_rate), which counts each packet once per group of the \
         scope; send after {retry_after:?}, batch signals into one packet with send_batch, or \
         send less"
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
    /// Any other refusal of the scope by the data layer (a name that is no
    /// folder or collection, a local failure, …). Next: as the data error says.
    #[error(transparent)]
    Data(DataError),
}

impl SignalError {
    /// What to do about it.
    pub fn next(&self) -> NextStep {
        match self {
            SignalError::NotMember { .. } => NextStep::AskOwner,
            SignalError::NotReady { .. } | SignalError::RateLimited { .. } => NextStep::RetryLater,
            SignalError::TooLarge { .. } | SignalError::Closed => NextStep::FixRequest,
            SignalError::ScopeTooLong { .. } | SignalError::ScopeDigestCollision { .. } => {
                NextStep::FixName
            }
            SignalError::Io(_) => NextStep::FixLocal,
            SignalError::Data(e) => e.next(),
        }
    }
}

/// A data-layer refusal of a scope as a signal refusal, keeping its next step:
/// no member (or outside a sealed audience) is NotMember, anything that may
/// succeed later NotReady, every other refusal the data error itself.
fn scope_error(scope: &Name, e: DataError) -> SignalError {
    match e {
        DataError::NotAllowed { .. } | DataError::Sealed { .. } => SignalError::NotMember {
            scope: scope.clone(),
            why: e.to_string(),
        },
        e if e.next() == NextStep::RetryLater => SignalError::NotReady {
            scope: scope.clone(),
            why: e.to_string(),
        },
        e => SignalError::Data(e),
    }
}

/// A scope a run can be opened in: its name within [`SCOPE_MAX`] encoded octets.
fn scope_fits(scope: &Name) -> Result<(), SignalError> {
    let size = wire::name_size(scope);
    if size > SCOPE_MAX {
        return Err(SignalError::ScopeTooLong {
            scope: scope.clone(),
            size,
            max: SCOPE_MAX,
        });
    }
    Ok(())
}

/// Record `scope` as the one subscribed under `digest`, or refuse when another
/// scope holds that digest: unsealed packets name their scope by digest alone, so
/// two scopes of one digest could not be told apart (a collision of a 128-bit
/// truncated hash costs about 2^64 work to find, so only the owner of both
/// scopes could make one).
fn claim_digest(
    by_digest: &mut HashMap<ScopeDigest, Name>,
    digest: ScopeDigest,
    scope: &Name,
) -> Result<(), SignalError> {
    match by_digest.entry(digest) {
        Entry::Occupied(held) if held.get() != scope => Err(SignalError::ScopeDigestCollision {
            scope: scope.clone(),
            other: held.get().clone(),
        }),
        Entry::Occupied(_) => Ok(()),
        Entry::Vacant(free) => {
            free.insert(scope.clone());
            Ok(())
        }
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
            Reason::BadSignature => {
                "nothing: forged, altered on the way, a revoked key, or a device certificate \
                 expired (its device renews it)"
            }
            Reason::UnknownRun => "nothing: the run's header rides again within a second",
            Reason::UnknownKey => {
                "nothing: this device holds no signal key of that epoch yet and asks for it, or \
                 the epoch was superseded past its grace and its sender seals under the newer \
                 one once it holds that epoch's record"
            }
            Reason::Flood => {
                "nothing here: the sender, or whoever forges its packets, is over the limits of \
                 signals.md §10"
            }
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
    digest: ScopeDigest,
    queues: Vec<Weak<Queue>>,
    latest: Latest,
    /// The scope's verified packets ([`RECEIVE_RATE_SCOPE`]).
    rate: Bucket,
    /// Signature checks of its packets not verified yet ([`CHECK_RATE_SCOPE`]).
    checks: Bucket,
    sealed: bool,
}

struct RunState {
    scope: Name,
    sender: Name,
    /// The sender's namespace, which runs are capped by (§8.4).
    namespace: Name,
    key: VerifyingKey,
    start: u64,
    not_after: u64,
    window: ReplayWindow,
    /// The run's verified packets ([`RECEIVE_RATE_RUN`]).
    rate: Bucket,
    /// When a packet of the run last verified, or it was admitted (µs).
    verified_us: u64,
}

/// A decoded body placed in its scope: the scope is the Name the subscription
/// gave for its digest (unsealed) or the scope of the key it was sealed under;
/// `digest` is what the packet claims, which the run signature covers.
struct Inbound {
    scope: Name,
    digest: ScopeDigest,
    run: RunId,
    header: Option<Bytes>,
    signals: Vec<wire::WireSignal>,
    signature: [u8; wire::SIGNATURE_LEN],
    signed: Bytes,
}

impl Inbound {
    fn new(body: Body, scope: Name) -> Inbound {
        Inbound {
            scope,
            digest: body.digest,
            run: body.run,
            header: body.header,
            signals: body.signals,
            signature: body.signature,
            signed: body.signed,
        }
    }
}

/// A packet of a run whose header is being admitted, processed once it is.
struct Waiting {
    body: Inbound,
    sealed: bool,
    local: bool,
    /// Its run signature verified already (it carried a header, §8.1 step 4).
    verified: bool,
}

/// A run header being admitted (§8.1 step 4): the slots it takes, and the
/// run's packets waiting for it.
struct Admitting {
    scope: Name,
    namespace: Name,
    waiting: Vec<Waiting>,
}

#[derive(Default)]
struct HubState {
    scopes: HashMap<Name, ScopeState>,
    /// The subscribed scopes by their digest, which unsealed packets name them
    /// by (never two scopes of one digest, [`claim_digest`]).
    by_digest: HashMap<ScopeDigest, Name>,
    keys: HashMap<[u8; wire::KEY_ID_LEN], (Name, SignalKey)>,
    keys_refreshed_us: Option<u64>,
    /// When this process first saw each signal key superseded by a newer
    /// epoch's (µs, §4.2).
    superseded: HashMap<[u8; wire::KEY_ID_LEN], u64>,
    runs: HashMap<RunId, RunState>,
    /// Run headers being admitted.
    admitting: HashMap<RunId, Admitting>,
    /// The device's `signal_revocations` the runs held were admitted under.
    revocations: u64,
    /// Signature checks of packets not verified yet in this process
    /// ([`CHECK_RATE_PROCESS`]), from the first.
    checks: Option<Bucket>,
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
    /// The process's push budget, in push Interests (`SignalOptions::push_rate`).
    push: Mutex<Bucket>,
    /// The clock every date and judgement is read from ([`clock::Clock`]).
    clock: Clock,
    /// The clock floor the device made durable, as far as this process knows
    /// ([`Device::signal_clock_dated`]).
    reserved: AtomicU64,
    /// A background extension of the floor is running.
    extending: AtomicBool,
}

/// A run header checked before its admission (§8.1 step 4).
struct Checked {
    data: Data,
    body: RunHeaderBody,
    key: VerifyingKey,
}

type Dropped = (Reason, String);

impl Hub {
    fn now_us(&self) -> u64 {
        self.clock.now()
    }

    /// About to date a signal by `now`: the device's clock floor is durable at or above it
    /// (spec §3.5), asked first when `now` is past what was reserved, and, once `now`
    /// is within half a reserve of the end of it, asked for more in the background, so a send
    /// rarely waits. Refused with the data layer's reason when the floor can't be made durable:
    /// a signal dated beyond it could be re-dated below it by a restart.
    async fn dated(self: &Arc<Self>, now: u64) -> Result<(), SignalError> {
        let reserved = self.reserved.load(Ordering::Acquire);
        if now > reserved {
            let floor = self
                .device
                .signal_clock_dated(now)
                .await
                .map_err(SignalError::Data)?;
            self.reserved.fetch_max(floor, Ordering::AcqRel);
            return Ok(());
        }
        if now.saturating_add(CLOCK_RESERVE_US / 2) > reserved
            && !self.extending.swap(true, Ordering::AcqRel)
        {
            let hub = Arc::clone(self);
            let task = tokio::spawn(async move {
                if let Ok(floor) = hub
                    .device
                    .signal_clock_dated(reserved.saturating_add(1))
                    .await
                {
                    hub.reserved.fetch_max(floor, Ordering::AcqRel);
                }
                hub.extending.store(false, Ordering::Release);
            });
            self.spawn(task);
        }
        Ok(())
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
        let (body, scope, sealed) = match decoded {
            Packet::Body(b) => {
                // An unsealed packet names its scope by digest: the scope is the one
                // subscribed here whose digest it is, if any (§8.1 step 3).
                let Some(scope) = self.lock().by_digest.get(&b.digest).cloned() else {
                    return self.drop_packet(
                        Reason::Unsubscribed,
                        Some(&b.run),
                        &format!(
                            "a packet of the scope with digest {}, which no one subscribes to \
                             here",
                            b.digest
                        ),
                    );
                };
                (b, scope, false)
            }
            Packet::Sealed(s) => {
                let (scope, key) = match self.key_for(&s.key_id) {
                    Ok(k) => k,
                    Err(why) => return self.drop_packet(Reason::UnknownKey, None, &why),
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
                (body, scope, true)
            }
        };
        self.process(
            Inbound::new(body, scope),
            sealed,
            local,
            false,
            false,
            scratch,
        );
    }

    /// The signal key of `id`, among the subscribed scopes' keys, unless its
    /// epoch was superseded here more than [`EPOCH_GRACE`] ago (§4.2); else
    /// why not. The keys are asked of the device again on an unknown id at
    /// most once a second, and while known ids arrive every
    /// [`KEY_CONFIRM_EVERY_US`], so a superseded epoch is noticed.
    fn key_for(&self, id: &[u8; wire::KEY_ID_LEN]) -> Result<(Name, SignalKey), String> {
        let now = self.now_us();
        let scopes: Vec<Name> = {
            let mut st = self.lock();
            let every = match st.keys.contains_key(id) {
                true => KEY_CONFIRM_EVERY_US,
                false => KEY_REFRESH_EVERY_US,
            };
            if st
                .keys_refreshed_us
                .is_some_and(|t| now.saturating_sub(t) < every)
            {
                return key_in(&st, id, now);
            }
            st.keys_refreshed_us = Some(now);
            st.scopes.keys().cloned().collect()
        };
        for scope in scopes {
            if let Ok(s) = self.device.signal_scope(&scope) {
                set_keys(&mut self.lock(), &scope, &s, now);
            }
        }
        key_in(&self.lock(), id, now)
    }

    /// The checks of a decoded body: of its run before verification (a
    /// signature check taken from the budgets of packets not verified yet),
    /// then the run signature and the sender's membership, then the run's
    /// and scope's rates of verified packets, then per signal.
    ///
    /// While a run's header is admitted, and until the packets that waited for it
    /// are processed in their order, its packets wait behind them; `drained`
    /// marks one the admission hands back, `verified` one whose run signature
    /// verified already (it carried the header).
    fn process(
        self: &Arc<Self>,
        body: Inbound,
        sealed: bool,
        local: bool,
        drained: bool,
        verified: bool,
        scratch: &mut Vec<u8>,
    ) {
        let now = self.now_us();
        let now_ms = now / 1000;
        let skew = self.skew_ms();
        let run_id = body.run;
        let revocations = self.device.signal_revocations();
        let (key, sender) = {
            let mut guard = self.lock();
            let st = &mut *guard;
            walk_again(st, revocations);
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
            if scope.digest != body.digest {
                return self.drop_packet(
                    Reason::Malformed,
                    Some(&run_id),
                    &format!(
                        "it names the scope digest {}, which is not {}'s ({}): sealed under that \
                         scope's key but claiming another scope",
                        body.digest, body.scope, scope.digest
                    ),
                );
            }
            if scope.sealed && !sealed {
                return self.drop_packet(
                    Reason::Malformed,
                    Some(&run_id),
                    &format!("unsealed, and {} is sealed", body.scope),
                );
            }
            if !drained && let Some(admitting) = st.admitting.get_mut(&run_id) {
                if admitting.waiting.len() < WAITING_MAX {
                    admitting.waiting.push(Waiting {
                        body,
                        sealed,
                        local,
                        verified,
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
                    Some(header) => {
                        drop(guard);
                        self.admit(body, sealed, local, header, scratch);
                    }
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
            if !verified
                && let Err(why) = take_check(&mut st.checks, &mut scope.checks, &body.scope, now)
            {
                return self.drop_packet(Reason::Flood, Some(&run_id), &why);
            }
            (run.key, run.sender.clone())
        };
        if !verified && !crypto::verify(&key, &body.signed, &body.signature, scratch) {
            return self.drop_packet(
                Reason::BadSignature,
                Some(&run_id),
                "its run signature does not verify by the run's key",
            );
        }
        if !self.device.signal_member(&body.scope, &sender) {
            // Its slots are free for members at once (§8.4).
            self.lock().runs.remove(&run_id);
            return self.drop_packet(
                Reason::NotMember,
                Some(&run_id),
                &format!(
                    "{sender} is no member of {} by the record in force; its run is let go",
                    body.scope
                ),
            );
        }
        let mut guard = self.lock();
        let st = &mut *guard;
        let (Some(run), Some(scope)) = (st.runs.get_mut(&run_id), st.scopes.get_mut(&body.scope))
        else {
            return;
        };
        if !run.window.all_fresh(body.signals.iter().map(|s| s.seq)) {
            return self.drop_packet(
                Reason::Replayed,
                Some(&run_id),
                "another copy was taken while this one was verified",
            );
        }
        // The verified traffic's budgets, which forgeries never reach (§10).
        if run.rate.take(1, now).is_err() {
            return self.drop_packet(
                Reason::Flood,
                Some(&run_id),
                &format!("over {RECEIVE_RATE_RUN} verified packets/s of one run"),
            );
        }
        if scope.rate.take(1, now).is_err() {
            return self.drop_packet(
                Reason::Flood,
                Some(&run_id),
                &format!(
                    "over {RECEIVE_RATE_SCOPE} verified packets/s of {}",
                    body.scope
                ),
            );
        }
        for s in &body.signals {
            run.window.mark(s.seq);
        }
        run.verified_us = now;
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

    /// Admit the header a packet of an unknown run carries (§8.1 step 4):
    /// checked here first ([`Self::check_header`]: the packet's run signature
    /// under the run key the header binds, the signer a member); then, while
    /// fewer than [`ADMITTING_PER_SCOPE`] headers of the scope and
    /// [`ADMITTING_PER_NAMESPACE`] of the signer's namespace are, admitted by
    /// the device; then the packet and those of the run that came meanwhile
    /// are processed.
    fn admit(
        self: &Arc<Self>,
        body: Inbound,
        sealed: bool,
        local: bool,
        header: Bytes,
        scratch: &mut Vec<u8>,
    ) {
        let run = body.run;
        let (checked, sender) = match self.check_header(&body, header, scratch) {
            Ok(c) => c,
            Err((reason, why)) => return self.drop_packet(reason, Some(&run), &why),
        };
        let mut guard = self.lock();
        let st = &mut *guard;
        if st.runs.contains_key(&run) || st.admitting.contains_key(&run) {
            // Held, or being admitted, meanwhile: the packet is one of the
            // run's, its signature verified by the run's key.
            drop(guard);
            return self.process(body, sealed, local, false, true, scratch);
        }
        let of_scope = st
            .admitting
            .values()
            .filter(|a| a.scope == body.scope)
            .count();
        if of_scope >= ADMITTING_PER_SCOPE {
            return self.drop_packet(
                Reason::Flood,
                Some(&run),
                &format!(
                    "{ADMITTING_PER_SCOPE} run headers of {} are being admitted already",
                    body.scope
                ),
            );
        }
        let of_namespace = st
            .admitting
            .values()
            .filter(|a| a.namespace == sender.namespace)
            .count();
        if of_namespace >= ADMITTING_PER_NAMESPACE {
            return self.drop_packet(
                Reason::Flood,
                Some(&run),
                &format!(
                    "{ADMITTING_PER_NAMESPACE} run headers of senders of {} are being admitted \
                     already",
                    sender.namespace
                ),
            );
        }
        st.admitting.insert(
            run,
            Admitting {
                scope: body.scope.clone(),
                namespace: sender.namespace,
                waiting: Vec::new(),
            },
        );
        drop(guard);
        let revocations = self.device.signal_revocations();
        let hub = Arc::clone(self);
        let task = tokio::spawn(async move {
            let outcome = hub
                .device
                .signal_admit(&body.scope, &checked.data)
                .await
                .map_err(refused);
            let Some((attach, waiting)) = hub.admitted(&body, checked, outcome, revocations) else {
                return;
            };
            if let Some((ring, secret)) = attach {
                hub.attach(ring, secret, run);
            }
            let mut scratch = Vec::with_capacity(PACKET_MAX + 16);
            hub.process(body, sealed, local, true, true, &mut scratch);
            let mut waiting = waiting;
            // Packets keep waiting behind those taken until none is left, so
            // the run's packets are processed in the order they came.
            loop {
                for w in waiting {
                    hub.process(w.body, w.sealed, w.local, true, w.verified, &mut scratch);
                }
                let mut st = hub.lock();
                match st.admitting.get_mut(&run) {
                    Some(more) if !more.waiting.is_empty() => {
                        waiting = std::mem::take(&mut more.waiting)
                    }
                    _ => {
                        st.admitting.remove(&run);
                        break;
                    }
                }
            }
        });
        self.spawn(task);
    }

    /// The checks of a run header before anything is spent on admitting it
    /// (§8.1 step 4), cheapest first: its shape, its run id the hash of its
    /// run key, its name, its NotAfter; then one signature check from the
    /// budgets of packets not verified yet, and the packet's run signature
    /// under the run key the header binds — proof that whoever sent it holds
    /// that run's secret key, so no header binding another's run key claims
    /// that run; then the signer a member, asked of the device offline.
    fn check_header(
        &self,
        body: &Inbound,
        header: Bytes,
        scratch: &mut Vec<u8>,
    ) -> Result<(Checked, SignalSender), Dropped> {
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
        let now = self.now_us();
        let now_ms = now / 1000;
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
        {
            let mut guard = self.lock();
            let st = &mut *guard;
            let Some(scope) = st.scopes.get_mut(&body.scope) else {
                return Err((
                    Reason::Unsubscribed,
                    format!("{} was unsubscribed meanwhile", body.scope),
                ));
            };
            take_check(&mut st.checks, &mut scope.checks, &body.scope, now)
                .map_err(|why| (Reason::Flood, why))?;
        }
        if !crypto::verify(&key, &body.signed, &body.signature, scratch) {
            return Err((
                Reason::BadSignature,
                "the packet carrying its run header is not signed by the run key that header \
                 binds: whoever sent it does not hold that run's secret key (a header binding \
                 another's run key claims that run), so the header is not admitted"
                    .into(),
            ));
        }
        let sender = self
            .device
            .signal_sender(&body.scope, &data)
            .map_err(refused)?;
        Ok((
            Checked {
                data,
                body: hb,
                key,
            },
            sender,
        ))
    }

    /// Hold the run a header admitted, within the caps (§8.4): the packets
    /// that waited for it, and its ring when this host serves it and the run
    /// isn't this process's. `None` when it is not held (each waiting packet
    /// counted).
    #[allow(clippy::type_complexity)]
    fn admitted(
        &self,
        body: &Inbound,
        checked: Checked,
        outcome: Result<SignalSender, Dropped>,
        revocations: u64,
    ) -> Option<(Option<(Name, [u8; 32])>, Vec<Waiting>)> {
        let run = body.run;
        let now = self.now_us();
        let current = self.device.signal_revocations();
        let mut guard = self.lock();
        let st = &mut *guard;
        let waiting = st
            .admitting
            .remove(&run)
            .map(|a| a.waiting)
            .unwrap_or_default();
        let refuse = |reason: Reason, why: &str| {
            self.drop_n(reason, 1 + waiting.len() as u64, Some(&run), why);
        };
        let sender = match outcome {
            Ok(s) => s,
            Err((reason, why)) => {
                refuse(reason, &why);
                return None;
            }
        };
        if current != revocations {
            refuse(
                Reason::UnknownRun,
                "a trust context revoking keys was adopted while its header was admitted; its \
                 next header is admitted again, its chain walked again",
            );
            return None;
        }
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
        walk_again(st, current);
        let skew = self.skew_ms();
        st.runs
            .retain(|_, r| now / 1000 <= r.not_after.saturating_add(skew));
        let of_sender: Vec<(RunId, u64)> = st
            .runs
            .iter()
            .filter(|(_, r)| r.scope == body.scope && r.sender == sender.key)
            .map(|(id, r)| (*id, r.start))
            .collect();
        if let Some((oldest, start)) = of_sender.iter().min_by_key(|(_, s)| *s).copied()
            && of_sender.len() >= RUNS_PER_SENDER
        {
            if checked.body.start <= start {
                refuse(
                    Reason::Flood,
                    &format!(
                        "{} holds {RUNS_PER_SENDER} newer runs of {} here",
                        sender.key, body.scope
                    ),
                );
                return None;
            }
            st.runs.remove(&oldest);
        }
        let of_namespace = st
            .runs
            .values()
            .filter(|r| r.scope == body.scope && r.namespace == sender.namespace)
            .count();
        if of_namespace >= RUNS_PER_NAMESPACE
            && !self.make_room(st, &body.scope, Some(&sender.namespace), now)
        {
            refuse(
                Reason::Flood,
                &format!(
                    "{} holds {RUNS_PER_NAMESPACE} runs of senders of {} here, each a member's \
                     with a packet verified within {} s",
                    body.scope,
                    sender.namespace,
                    RUN_IDLE.as_secs()
                ),
            );
            return None;
        }
        let of_scope = st.runs.values().filter(|r| r.scope == body.scope).count();
        if of_scope >= RUNS_PER_SCOPE && !self.make_room(st, &body.scope, None, now) {
            refuse(
                Reason::Flood,
                &format!(
                    "{} holds {RUNS_PER_SCOPE} runs here, each a member's with a packet verified \
                     within {} s",
                    body.scope,
                    RUN_IDLE.as_secs()
                ),
            );
            return None;
        }
        let ring = checked
            .body
            .ring
            .filter(|_| !st.own.contains(&run))
            .map(|secret| (ring_name(&body.scope, &run), secret))
            .filter(|(ring, _)| crate::served_here(ring));
        st.runs.insert(
            run,
            RunState {
                scope: body.scope.clone(),
                sender: sender.key,
                namespace: sender.namespace.clone(),
                key: checked.key,
                start: checked.body.start,
                not_after: checked.body.not_after,
                window: ReplayWindow::default(),
                rate: Bucket::new(RECEIVE_RATE_RUN, RECEIVE_RATE_RUN, now),
                verified_us: now,
            },
        );
        // The run's later packets keep waiting behind those taken here until
        // the admission has processed them (see `admit`).
        st.admitting.insert(
            run,
            Admitting {
                scope: body.scope.clone(),
                namespace: sender.namespace,
                waiting: Vec::new(),
            },
        );
        Some((ring, waiting))
    }

    /// Make room for a run in `scope` (of the sender namespace `namespace`,
    /// when given) at a cap (§8.4): let go every run there whose sender is no
    /// member now — a removal frees its slots at once — else the run none of
    /// whose packets verified for longest, if for [`RUN_IDLE`]. False when
    /// none may go.
    fn make_room(
        &self,
        st: &mut HubState,
        scope: &Name,
        namespace: Option<&Name>,
        now: u64,
    ) -> bool {
        let idle = RUN_IDLE.as_micros() as u64;
        let mut gone = Vec::new();
        let mut idlest: Option<(RunId, u64)> = None;
        for (id, r) in st
            .runs
            .iter()
            .filter(|(_, r)| r.scope == *scope && namespace.is_none_or(|ns| r.namespace == *ns))
        {
            if !self.device.signal_member(scope, &r.sender) {
                gone.push(*id);
            } else if now.saturating_sub(r.verified_us) >= idle
                && idlest.is_none_or(|(_, t)| r.verified_us < t)
            {
                idlest = Some((*id, r.verified_us));
            }
        }
        if gone.is_empty() {
            gone.extend(idlest.map(|(id, _)| id));
        }
        for id in &gone {
            if let Some(r) = st.runs.remove(id) {
                tracing::debug!(
                    target: "ndn_surface::signal",
                    run = %id,
                    sender = %r.sender,
                    %scope,
                    "a run let go for another at a cap: its sender is no member now, or none of its packets verified for {} s",
                    RUN_IDLE.as_secs()
                );
            }
        }
        !gone.is_empty()
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

/// Take `s`, what the device answers for `scope` now: its keys, the first
/// that of the epoch in force; each other noted superseded from `now`, if
/// not before (§4.2).
fn set_keys(st: &mut HubState, scope: &Name, s: &SignalScope, now: u64) {
    st.keys.retain(|_, (sc, _)| sc != scope);
    for (i, k) in s.keys.iter().enumerate() {
        st.keys.insert(k.id, (scope.clone(), k.clone()));
        match i {
            0 => {
                st.superseded.remove(&k.id);
            }
            _ => {
                st.superseded.entry(k.id).or_insert(now);
            }
        }
    }
    let keys = &st.keys;
    st.superseded.retain(|id, _| keys.contains_key(id));
    if let Some(ss) = st.scopes.get_mut(scope) {
        ss.sealed = !s.keys.is_empty();
    }
}

/// The signal key of `id` held in `st`, unless its epoch was superseded here
/// more than [`EPOCH_GRACE`] before `now` (§4.2); else why not.
fn key_in(
    st: &HubState,
    id: &[u8; wire::KEY_ID_LEN],
    now: u64,
) -> Result<(Name, SignalKey), String> {
    let Some((scope, key)) = st.keys.get(id) else {
        return Err(format!(
            "sealed under the key id {id:02x?}, of no epoch whose key this device holds"
        ));
    };
    if let Some(since) = st.superseded.get(id) {
        let ago = now.saturating_sub(*since);
        if ago > EPOCH_GRACE.as_micros() as u64 {
            return Err(format!(
                "sealed under the key of an epoch of {scope} superseded here {} s ago, past the \
                 {} s grace: its sender doesn't hold the record that started the newer epoch yet, \
                 or reads the scope no more",
                ago / 1_000_000,
                EPOCH_GRACE.as_secs()
            ));
        }
    }
    Ok((scope.clone(), key.clone()))
}

/// One signature check of a packet not verified yet, from its scope's and the
/// process's budgets (§10); else why not.
fn take_check(
    process: &mut Option<Bucket>,
    of_scope: &mut Bucket,
    scope: &Name,
    now: u64,
) -> Result<(), String> {
    if of_scope.take(1, now).is_err() {
        return Err(format!(
            "over {CHECK_RATE_SCOPE} signature checks/s of packets of {scope} not verified yet"
        ));
    }
    let process =
        process.get_or_insert_with(|| Bucket::new(CHECK_RATE_PROCESS, CHECK_RATE_PROCESS, now));
    if process.take(1, now).is_err() {
        return Err(format!(
            "over {CHECK_RATE_PROCESS} signature checks/s of packets not verified yet in this \
             process"
        ));
    }
    Ok(())
}

/// Let every run held go when the device's `signal_revocations` moved since
/// they were admitted (§8.4): a trust context revoking keys was adopted, and
/// each run is admitted again from its next header, its chain walked again,
/// so a revoked issuer ends the runs of the keys it certified.
fn walk_again(st: &mut HubState, revocations: u64) {
    if st.revocations == revocations {
        return;
    }
    st.revocations = revocations;
    if !st.runs.is_empty() {
        tracing::debug!(
            target: "ndn_surface::signal",
            runs = st.runs.len(),
            next = "nothing: each run's header rides again within a second and is admitted again",
            "a trust context revoking keys was adopted: every run held is let go, its chain to be walked again"
        );
        st.runs.clear();
    }
}

/// The drop a data-layer refusal of a run header is counted as.
fn refused(r: SignalRefusal) -> Dropped {
    let reason = match r {
        SignalRefusal::Malformed { .. } => Reason::Malformed,
        SignalRefusal::BadSignature { .. } => Reason::BadSignature,
        SignalRefusal::NotMember { .. } => Reason::NotMember,
        SignalRefusal::NotReady { .. } | SignalRefusal::Unverified { .. } => Reason::UnknownRun,
    };
    (reason, r.to_string())
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
        let clock = Clock::new(options.clock.clone(), device.signal_clock_floor());
        let now = clock.now();
        let push = Bucket::new(
            u64::from(options.push_rate.get()),
            u64::from(options.push_burst.get()),
            now,
        );
        let reserved = AtomicU64::new(device.signal_clock_floor());
        let hub = Arc::new(Hub {
            device,
            conn: Arc::clone(&conn),
            options,
            listen,
            counters: Counters::default(),
            state: Mutex::new(HubState::default()),
            closed: AtomicBool::new(false),
            tasks: Mutex::new(Vec::new()),
            push: Mutex::new(push),
            clock,
            reserved,
            extending: AtomicBool::new(false),
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

    /// The octets of address plus payload that one signal always fits beside in a
    /// packet of `scope`, sealed or not: any signal with an address of at most
    /// [`wire::ADDRESS_MAX`] (64), a payload of at most [`wire::PAYLOAD_MAX`] (768)
    /// and address + payload within the room fits one packet, whatever the scope
    /// is called, because a packet names its scope by a 16-octet digest and not by
    /// its Name (signals.md §4.1, §4.3). A batch takes [`wire::SIGNAL_OVERHEAD`]
    /// more octets per signal, and the packet [`wire::PACKET_MAX`] in all.
    ///
    /// 0 when no run can be opened in `scope`: its name is over [`SCOPE_MAX`]
    /// encoded octets, so its run header would not fit a packet of its own
    /// ([`SignalError::ScopeTooLong`]). A device whose own key name is far longer
    /// than the wire tests hold to (140 octets) can have less scope to spend; its
    /// `open` says so.
    pub fn room(scope: &Name) -> usize {
        if wire::name_size(scope) > SCOPE_MAX {
            0
        } else {
            wire::ROOM
        }
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
        scope_fits(scope)?;
        let s = self
            .hub
            .device
            .signal_scope(scope)
            .map_err(|e| scope_error(scope, e))?;
        let queue = Arc::new(Queue::default());
        let now = self.hub.now_us();
        let digest = ScopeDigest::of(scope);
        let mut st = self.hub.lock();
        claim_digest(&mut st.by_digest, digest, scope)?;
        st.scopes
            .entry(scope.clone())
            .or_insert_with(|| ScopeState {
                digest,
                queues: Vec::new(),
                latest: Latest::default(),
                rate: Bucket::new(RECEIVE_RATE_SCOPE, RECEIVE_RATE_SCOPE, now),
                checks: Bucket::new(CHECK_RATE_SCOPE, CHECK_RATE_SCOPE, now),
                sealed: false,
            })
            .queues
            .push(Arc::downgrade(&queue));
        set_keys(&mut st, scope, &s, now);
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
        scope_fits(scope)?;
        self.hub
            .device
            .signal_scope(scope)
            .map_err(|e| scope_error(scope, e))?;
        let now = self.hub.now_us();
        self.hub.dated(now).await?;
        let keyed = Keyed::new(&self.hub, scope, now, now).await?;
        Ok(SignalRun {
            hub: Arc::clone(&self.hub),
            scope: scope.clone(),
            digest: ScopeDigest::of(scope),
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
        if header.len() > wire::HEADER_MAX {
            let size = wire::name_size(scope);
            return Err(SignalError::ScopeTooLong {
                scope: scope.clone(),
                size,
                max: size.saturating_sub(header.len() - wire::HEADER_MAX),
            });
        }
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
    digest: ScopeDigest,
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
        // Receivers refuse a sequence past the last one; sequences start at the
        // host's clock in µs, so only a clock far past now gets there.
        // Sequences first ..= SEQ_MAX are left: SEQ_MAX + 1 - first of them.
        let room = (wire::SEQ_MAX + 1).saturating_sub(first);
        if signals.len() as u64 > room {
            return Err(SignalError::TooLarge {
                what: "a batch past the run's last sequence (signals; the host's clock is far \
                       past now)",
                size: signals.len(),
                max: usize::try_from(room).unwrap_or(usize::MAX),
            });
        }
        // Membership, keys and groups by the record in force now: NotMember from
        // the moment this device holds a record that removes it.
        let scope = self
            .hub
            .device
            .signal_scope(&self.scope)
            .map_err(|e| scope_error(&self.scope, e))?;
        let mut now = self.hub.now_us();
        self.hub.dated(now).await?;
        let lifetime = self.hub.options.run_lifetime.as_micros() as u64;
        let opened = self.keyed.as_ref().map_or(now, |k| k.opened_us);
        if now.saturating_sub(opened) >= lifetime / 10 * 9 {
            self.renew(now).await?;
            now = self.hub.now_us();
            self.hub.dated(now).await?;
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
            let body = wire::body_size(header.then_some(keyed.header.len()), of);
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
        // The run's rate counts packets; the process's push budget counts push
        // Interests, one per packet per group, as a relay's quota counts them.
        // Both are spent, or neither.
        let packets = plan.len() as u64;
        let pushes = packets.saturating_mul(scope.groups.len() as u64);
        {
            let mut budget = self.hub.push.lock().expect("signal push budget lock");
            let run_wait = self.bucket.ready(packets, now).err();
            let push_wait = budget.ready(pushes, now).err();
            if let Some(retry_after) = run_wait.max(push_wait) {
                return Err(SignalError::RateLimited { retry_after });
            }
            self.bucket.spend(packets);
            budget.spend(pushes);
        }
        let run = keyed.key.id();
        for p in plan {
            let header = p.header.then_some(keyed.header.as_ref());
            let key = &keyed.key;
            let scratch = &mut self.scratch;
            wire::encode_body(
                &mut self.body,
                &self.digest,
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
            st.by_digest.remove(&s.digest);
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
                &ScopeDigest::of(&scope.parse().unwrap()),
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
        // The same signature carried over a packet claiming another scope: its digest.
        let mut other = Vec::new();
        let sig = b.signature;
        encode_body(
            &mut other,
            &ScopeDigest::of(&"/alice/32=data/notes".parse().unwrap()),
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
            "a run signature binds its scope's digest"
        );
    }

    /// Two scopes with one digest can't both be subscribed: the second is refused,
    /// saying which; the same scope again is not a collision.
    #[test]
    fn a_second_scope_with_a_subscribed_scopes_digest_is_refused() {
        let (a, b): (Name, Name) = (
            "/alice/32=data/board".parse().unwrap(),
            "/alice/32=data/notes".parse().unwrap(),
        );
        let mut by_digest = HashMap::new();
        let digest = ScopeDigest::of(&a);
        assert!(claim_digest(&mut by_digest, digest, &a).is_ok());
        assert!(claim_digest(&mut by_digest, digest, &a).is_ok());
        match claim_digest(&mut by_digest, digest, &b) {
            Err(e @ SignalError::ScopeDigestCollision { .. }) => {
                assert_eq!(e.next(), NextStep::FixName);
                assert!(e.to_string().contains("notes"), "{e}");
            }
            other => panic!("refused as a digest collision, not {other:?}"),
        }
        assert_eq!(by_digest.get(&digest), Some(&a));
    }

    /// A scope longer than `SCOPE_MAX` has no room, and one within it has the room
    /// of a packet.
    #[test]
    fn room_is_the_packets_for_any_scope_within_scope_max_and_none_beyond() {
        let within: Name = "/alice/32=data/board".parse().unwrap();
        assert_eq!(Signals::room(&within), wire::ROOM);
        let long = |octets: usize| -> Name {
            let mut n: Name = "/alice/32=data".parse().unwrap();
            // 2 octets of framing per component and 4 for the Name's.
            while wire::name_size(&n) + 102 <= octets {
                n = n.append("x".repeat(100));
            }
            let rest = octets - wire::name_size(&n);
            n.append("y".repeat(rest - 2))
        };
        let at_max = long(SCOPE_MAX);
        assert_eq!(wire::name_size(&at_max), SCOPE_MAX);
        assert_eq!(Signals::room(&at_max), wire::ROOM);
        assert_eq!(Signals::room(&long(SCOPE_MAX + 1)), 0);
    }
}
