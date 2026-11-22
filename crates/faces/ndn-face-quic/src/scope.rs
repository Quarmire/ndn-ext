//! A link that carries less than everything: an *enrollment link*, or a
//! link only rate-bounded (a relay serving another namespace's devices).
//!
//! A [`LinkScope`] says which kind of packet each direction carries
//! (Interests one way, their answers the other, or both) and which names;
//! the face of a scoped link drops everything else as it crosses, in both
//! directions, so the scope holds whatever the forwarder above does. It
//! judges each NDNLPv2 frame by the network packet it carries: a packet sent
//! whole, or the first fragment of a fragmented one (the name is at its
//! head) — the later fragments of a packet follow the first one's verdict,
//! and a later fragment whose first one was not seen is dropped. Frames
//! carrying no network packet (acknowledgements) pass.
//!
//! An Interest the scope drops for a name it does not carry is answered with a
//! Nack (NoRoute) at once, so the requester stops waiting: one arriving from
//! the peer is Nacked to the peer, one this side would send is Nacked back to
//! this side. An Interest it drops for a rate is answered with a Nack
//! (Congestion) at once: "dropped for rate, ask again soon", never "not
//! there". Received packets are rate-limited before they are judged — by the
//! link's own bucket of frames, then its bucket of bytes (a link bounded by
//! bandwidth), then by the bucket of the names a scope rates apart
//! ([`RatedInterests`]; those are dropped without a Nack: an exchange with a
//! gate of its own), then by a bucket it shares with other links
//! ([`SharedRate`]); acknowledgements are not. A Nack costs the link a frame
//! sent, so the Congestion Nacks of one link are bounded too
//! ([`CONGESTION_NACKS`]): past it a dropped Interest is dropped silently.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use bytes::Bytes;
use ndn_packet::Name;
use ndn_packet::lp::LpPacket;
use ndn_packet::nack::NackReason;

const LP_PACKET: u64 = 0x64;
const INTEREST: u64 = 0x05;
const DATA: u64 = 0x06;
const NAME: u64 = 0x07;

/// How many fragmented packets in flight a scope remembers the verdict of,
/// per direction.
const REMEMBERED_FRAGMENTED: usize = 32;
/// How often a scope logs what it dropped, at most.
const DROP_LOG_EVERY: Duration = Duration::from_secs(10);
/// The Congestion Nacks one link sends for the Interests its rates dropped:
/// `burst` at once, refilled at `per_sec`. A peer that floods gets a Nack for
/// each Interest it lost, until this bucket is empty and one per 8 ms after
/// that: its flood is never answered with a flood. An honest asker that meets
/// a rate loses a window of 32 or so, which the burst covers.
pub const CONGESTION_NACKS: RateLimit = RateLimit {
    burst: 256,
    per_sec: 128,
};
/// The frames a link receives that carry no network packet and no TxSequence
/// (acknowledgements, idle frames), together: 1,024 at once, then 1,024 a
/// second. An honest peer sends them from its idle-Ack pump, which ticks every
/// 5 ms (200 a second) and sends one frame, or a few when more acks are pending
/// than one frame holds, so at 100,000 packets a second received (a gigabit of
/// small packets: far past any scoped link) it sends about 600 a second. A
/// peer that floods them is held to this before the reliability layer reads
/// the acks in each (round 12, L1). They take no token of the link's frames.
pub const LINK_ONLY_FRAMES: RateLimit = RateLimit {
    burst: 1024,
    per_sec: 1024,
};
/// The frames a link receives that carry a TxSequence and no network packet:
/// 16 at once, then 4 a second. No honest peer sends one: a frame with a
/// TxSequence carries the fragment that sequence numbers
/// (`LpReliability::on_send`), and its acknowledgements carry none. Each one
/// would make this side remember the sequence for up to two RTOs and queue an
/// acknowledgement, so a flood of them is a table to fill (round 12, L1).
pub const STAMPED_LINK_ONLY_FRAMES: RateLimit = RateLimit {
    burst: 16,
    per_sec: 4,
};

/// Which packets one direction of a scoped link carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Carries {
    /// Interests, within the scope's names.
    Interests,
    /// Data and Nacks, within the scope's names.
    Answers,
    /// Interests and their answers, within the scope's names: with every
    /// name, a full link bounded only by its rates.
    Everything,
}

/// A rate: `burst` at once, refilled at `per_sec`. Frames, or bytes where a
/// bucket counts those ([`LinkScope::bandwidth`]).
#[derive(Clone, Copy, Debug)]
pub struct RateLimit {
    pub burst: u32,
    pub per_sec: u32,
}

/// Some of the Interests the peer sends, held to a bucket of their own beside
/// the link's: the names `names` take a token of `rate` each, and an Interest
/// that finds none is dropped silently (no Nack, unlike one over the link's
/// rate: an exchange with a gate of its own, whose flood is told nothing),
/// counted, and without taking a token of the shared bucket. What the link's
/// own rate would allow of other names is not reduced by them.
pub struct RatedInterests {
    /// Whether an Interest of that name is rated apart.
    pub names: NameFilter,
    /// What those Interests take together over this link.
    pub rate: RateLimit,
}

/// Buckets shared by several links (all the links of a namespace a relay
/// serves, say): together they take no more than their [`RateLimit`]s, of
/// frames and, when given, of bytes.
pub struct SharedRate {
    rate: RateLimit,
    bandwidth: Option<RateLimit>,
    buckets: Mutex<(Bucket, Bucket)>,
}

impl SharedRate {
    pub fn new(rate: RateLimit, bandwidth: Option<RateLimit>) -> Self {
        Self {
            buckets: Mutex::new((
                Bucket::full(rate),
                Bucket::full(bandwidth.unwrap_or(RateLimit {
                    burst: 0,
                    per_sec: 0,
                })),
            )),
            rate,
            bandwidth,
        }
    }

    /// A frame of `len` bytes: a token of the frames and `len` of the bytes.
    fn take(&self, len: f64) -> bool {
        let mut buckets = self.buckets.lock().unwrap_or_else(PoisonError::into_inner);
        buckets.0.take(self.rate, 1.0)
            && self
                .bandwidth
                .is_none_or(|bandwidth| buckets.1.take(bandwidth, len))
    }
}

/// Whether a packet of a name is within a scope's names.
pub type NameFilter = Box<dyn Fn(&Name) -> bool + Send + Sync>;

/// What a scoped link carries.
pub struct LinkScope {
    /// What the peer may send over the link.
    pub receives: Carries,
    /// What this side may send to the peer.
    pub sends: Carries,
    /// Whether a packet of that name is within the scope (both directions).
    pub names: Box<dyn Fn(&Name) -> bool + Send + Sync>,
    /// Bound on received packets.
    pub rate: RateLimit,
    /// A bound on the bytes received, checked after `rate`: a link bounded by
    /// bandwidth as well as by frames (`burst` must be at least the largest
    /// frame). `None`: frames only, which bounds bytes by the frame size.
    pub bandwidth: Option<RateLimit>,
    /// Interests of some names the peer sends, each class held to a bucket of
    /// its own after `rate`, before `shared` (an Interest takes a token of the
    /// first class that names it).
    pub rated: Vec<RatedInterests>,
    /// A bound on the Interests the peer sends, whatever their names,
    /// beside `rate` (which counts every frame, a Data fragment too): an
    /// Interest is a small frame that may cost this side a Data of kilobytes,
    /// so the Interests are bounded below the frames. An Interest over it is
    /// dropped, with a Congestion Nack as for any rate. `None`: only `rate`.
    pub interests: Option<RateLimit>,
    /// A bound on the bytes of answers (Data, Nacks and their fragments) this
    /// side sends the peer, counted in [`ScopeState::sending`] (`burst` must be
    /// at least the largest frame). An answer over it is dropped, so what a
    /// peer can make this side send is bounded by more than what it asks in
    /// Interests. `None`: no bound.
    pub answered: Option<RateLimit>,
    /// A bound on received packets shared with other links, checked after
    /// `rate`.
    pub shared: Option<Arc<SharedRate>>,
    /// For the log, when a packet is dropped: what the link carries and
    /// what to do to carry more.
    pub explain: String,
    /// When set, an answer (Data or Nack) the peer sends is carried only
    /// within it, besides being within `names`: a peer whose Interests go
    /// everywhere may answer for some names only. What this side sends is
    /// judged by `names` alone.
    pub answers_in: Option<NameFilter>,
    /// When set, an Interest the peer sends is carried only within it,
    /// besides being within `names`: a link whose names are wide (the names
    /// this side's own Interests go out under) may let the peer ask for some
    /// of them only. What this side sends is judged by `names` alone.
    pub interests_in: Option<NameFilter>,
    /// When set, the scope narrows in place while [`Narrowing::when`] holds
    /// (asked at every packet), with no reconnect.
    pub narrowing: Option<Narrowing>,
    /// Where this link counts what it drops for rate and Nacks, with the
    /// host's other links.
    pub counts: Option<Arc<ScopeCounts>>,
}

/// What the scopes of a host's links dropped for rate and answered with a
/// Nack, in total, so a host's status can show it.
#[derive(Debug, Default)]
pub struct ScopeCounts {
    over_rate: AtomicU64,
    nacked: AtomicU64,
}

impl ScopeCounts {
    /// Frames dropped for a rate (the link's, its bandwidth's, its names' or
    /// a shared one): Interests, Data and fragments.
    pub fn over_rate(&self) -> u64 {
        self.over_rate.load(Ordering::Relaxed)
    }

    /// Congestion Nacks sent for the Interests dropped for a rate: at most
    /// one each, and none past [`CONGESTION_NACKS`].
    pub fn congestion_nacks(&self) -> u64 {
        self.nacked.load(Ordering::Relaxed)
    }
}

/// What a scope carries while it is narrowed: the same names and rates, other
/// kinds of packet. A link whose reason to be broad ended (a grant's last
/// entry, ndn-link §8.8) narrows to what the person may still be told.
pub struct Narrowing {
    /// Whether the scope is narrowed now.
    pub when: Box<dyn Fn() -> bool + Send + Sync>,
    /// What the peer may send while narrowed.
    pub receives: Carries,
    /// What this side may send while narrowed.
    pub sends: Carries,
}

/// What a scope did with a frame.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Judged {
    Pass,
    /// Dropped; `Some` is the Nack to send and the Interest it answers.
    Drop(Option<(NackReason, Bytes)>),
}

/// The fragmented packets of one direction whose verdict is known, by the
/// sequence of their first fragment.
#[derive(Default)]
struct Fragmented {
    passed: VecDeque<u64>,
}

impl Fragmented {
    fn remember(&mut self, base: u64) {
        if self.passed.len() == REMEMBERED_FRAGMENTED {
            self.passed.pop_front();
        }
        self.passed.push_back(base);
    }

    fn passed(&self, base: u64) -> bool {
        self.passed.contains(&base)
    }
}

struct Bucket {
    tokens: f64,
    at: Instant,
}

impl Bucket {
    fn full(rate: RateLimit) -> Self {
        Self {
            tokens: f64::from(rate.burst),
            at: Instant::now(),
        }
    }

    /// Refill for the time since the last take, then take `cost` tokens if
    /// there are that many.
    fn take(&mut self, rate: RateLimit, cost: f64) -> bool {
        let now = Instant::now();
        let refill = now.duration_since(self.at).as_secs_f64() * f64::from(rate.per_sec);
        self.tokens = (self.tokens + refill).min(f64::from(rate.burst));
        self.at = now;
        if self.tokens >= cost {
            self.tokens -= cost;
            true
        } else {
            false
        }
    }
}

/// A scope at work on one link: its verdicts, rate buckets and activity.
pub(crate) struct ScopeState {
    scope: LinkScope,
    inbound: Mutex<Fragmented>,
    outbound: Mutex<Fragmented>,
    bucket: Mutex<Bucket>,
    bandwidth_bucket: Mutex<Bucket>,
    /// One bucket per class of [`LinkScope::rated`], in its order.
    rated_buckets: Vec<Mutex<Bucket>>,
    /// The Interests of [`LinkScope::interests`].
    interest_bucket: Mutex<Bucket>,
    /// The bytes of answers of [`LinkScope::answered`].
    answered_bucket: Mutex<Bucket>,
    /// The frames with no packet in them ([`LINK_ONLY_FRAMES`]).
    link_only_bucket: Mutex<Bucket>,
    /// The frames with no packet in them that carry a TxSequence
    /// ([`STAMPED_LINK_ONLY_FRAMES`]).
    stamped_bucket: Mutex<Bucket>,
    /// What the link may still send of Congestion Nacks.
    nack_bucket: Mutex<Bucket>,
    started: Instant,
    /// Milliseconds after `started` of the last packet the scope passed.
    last_passed_ms: AtomicU64,
    dropped: AtomicU64,
    last_log: Mutex<Option<Instant>>,
}

impl ScopeState {
    pub(crate) fn new(scope: LinkScope) -> Self {
        let now = Instant::now();
        let none = RateLimit {
            burst: 0,
            per_sec: 0,
        };
        Self {
            bucket: Mutex::new(Bucket::full(scope.rate)),
            bandwidth_bucket: Mutex::new(Bucket::full(scope.bandwidth.unwrap_or(none))),
            rated_buckets: scope
                .rated
                .iter()
                .map(|rated| Mutex::new(Bucket::full(rated.rate)))
                .collect(),
            interest_bucket: Mutex::new(Bucket::full(scope.interests.unwrap_or(none))),
            answered_bucket: Mutex::new(Bucket::full(scope.answered.unwrap_or(none))),
            link_only_bucket: Mutex::new(Bucket::full(LINK_ONLY_FRAMES)),
            stamped_bucket: Mutex::new(Bucket::full(STAMPED_LINK_ONLY_FRAMES)),
            nack_bucket: Mutex::new(Bucket::full(CONGESTION_NACKS)),
            scope,
            inbound: Mutex::default(),
            outbound: Mutex::default(),
            started: now,
            last_passed_ms: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            last_log: Mutex::new(None),
        }
    }

    /// How long the scope has passed no packet (either way).
    pub(crate) fn idle_for(&self) -> Duration {
        let last = Duration::from_millis(self.last_passed_ms.load(Ordering::Relaxed));
        self.started.elapsed().saturating_sub(last)
    }

    /// Judge a frame the peer sent. A frame carrying no network packet (an
    /// acknowledgement) takes no token of the link's frames, which the peer's
    /// packets use: acknowledgements of the fragments this side sends must not
    /// crowd them out. It takes one of a bucket of its own
    /// ([`LINK_ONLY_FRAMES`]), and when it carries a TxSequence one of a
    /// smaller one ([`STAMPED_LINK_ONLY_FRAMES`]).
    pub(crate) fn received(&self, frame: &Bytes) -> Judged {
        let packet = Packet::of(frame);
        if let Some(Packet::LinkOnly { stamped }) = packet {
            if !self.take_link_only(stamped) {
                self.note_over_rate(
                    if stamped {
                        "over the rate limit of frames that carry a TxSequence and no packet"
                    } else {
                        "over the rate limit of frames that carry no packet"
                    },
                    None,
                );
                return Judged::Drop(None);
            }
        } else {
            if !self.take_token() {
                return self.congested("over the rate limit", packet.as_ref());
            }
            if let (
                Some(rate),
                Some(Packet::Network {
                    kind: Kind::Interest,
                    ..
                }),
            ) = (self.scope.interests, &packet)
                && !self
                    .interest_bucket
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .take(rate, 1.0)
            {
                return self.congested("over the rate limit of Interests", packet.as_ref());
            }
            if let Some(bandwidth) = self.scope.bandwidth
                && !self
                    .bandwidth_bucket
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .take(bandwidth, bytes(frame))
            {
                return self.congested("over the bandwidth limit", packet.as_ref());
            }
            if let Some(Packet::Network {
                kind: Kind::Interest,
                name,
                ..
            }) = &packet
                && !self.take_rated(name)
            {
                self.note_over_rate("over the rate limit of its names", Some(name));
                return Judged::Drop(None);
            }
            if self
                .scope
                .shared
                .as_ref()
                .is_some_and(|shared| !shared.take(bytes(frame)))
            {
                return self.congested(
                    "over the rate limit shared with other links",
                    packet.as_ref(),
                );
            }
        }
        self.judge(
            packet,
            self.carries(|n| n.receives, self.scope.receives),
            &self.inbound,
            self.scope.interests_in.as_deref(),
            self.scope.answers_in.as_deref(),
        )
    }

    /// Whether an Interest of `name` is within the bucket of the first class
    /// of [`LinkScope::rated`] that names it (it takes a token), or is in none.
    fn take_rated(&self, name: &Name) -> bool {
        let Some((i, rated)) = self
            .scope
            .rated
            .iter()
            .enumerate()
            .find(|(_, rated)| (rated.names)(name))
        else {
            return true;
        };
        self.rated_buckets[i]
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take(rated.rate, 1.0)
    }

    /// A frame dropped for a rate: counted, and when it carries a whole
    /// Interest, answered with a Congestion Nack while the link's bound on
    /// those holds. Data and fragments are dropped without one (an asker of
    /// Data waits for its timer: there is nothing to say to a Data).
    fn congested(&self, what: &str, packet: Option<&Packet>) -> Judged {
        let name = match packet {
            Some(Packet::Network { name, .. }) => Some(name),
            _ => None,
        };
        self.note_over_rate(what, name);
        let Some(Packet::Network {
            kind: Kind::Interest,
            whole: Some(interest),
            ..
        }) = packet
        else {
            return Judged::Drop(None);
        };
        if !self
            .nack_bucket
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take(CONGESTION_NACKS, 1.0)
        {
            return Judged::Drop(None);
        }
        if let Some(counts) = &self.scope.counts {
            counts.nacked.fetch_add(1, Ordering::Relaxed);
        }
        Judged::Drop(Some((NackReason::Congestion, interest.clone())))
    }

    fn note_over_rate(&self, what: &str, name: Option<&Name>) {
        if let Some(counts) = &self.scope.counts {
            counts.over_rate.fetch_add(1, Ordering::Relaxed);
        }
        self.note_drop(what, name);
    }

    /// Judge a frame this side would send. An answer (a Data, a Nack, or a
    /// fragment of one) that passes takes its bytes of [`LinkScope::answered`]
    /// and is dropped, silently, when they are not there: a Data has no one to
    /// be Nacked to, and its asker's timer asks again.
    pub(crate) fn sending(&self, frame: &Bytes) -> Judged {
        let packet = Packet::of(frame);
        let answer = matches!(
            packet,
            Some(
                Packet::LaterFragment { .. }
                    | Packet::Network {
                        kind: Kind::Data | Kind::Nack,
                        ..
                    }
            )
        );
        let name = match &packet {
            Some(Packet::Network { name, .. }) if self.scope.answered.is_some() => {
                Some(name.clone())
            }
            _ => None,
        };
        let verdict = self.judge(
            packet,
            self.carries(|n| n.sends, self.scope.sends),
            &self.outbound,
            None,
            None,
        );
        if let (Judged::Pass, true, Some(budget)) = (&verdict, answer, self.scope.answered)
            && !self
                .answered_bucket
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take(budget, bytes(frame))
        {
            self.note_over_rate(
                "over the budget of bytes this side answers over the link",
                name.as_ref(),
            );
            return Judged::Drop(None);
        }
        verdict
    }

    /// A frame with no packet in it: a token of [`LINK_ONLY_FRAMES`], and
    /// one of [`STAMPED_LINK_ONLY_FRAMES`] too when it carries a TxSequence.
    fn take_link_only(&self, stamped: bool) -> bool {
        if stamped
            && !self
                .stamped_bucket
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take(STAMPED_LINK_ONLY_FRAMES, 1.0)
        {
            return false;
        }
        self.link_only_bucket
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take(LINK_ONLY_FRAMES, 1.0)
    }

    /// What one direction carries now: the narrowed kind while the scope is
    /// narrowed, else `plain`.
    fn carries(&self, narrowed: impl Fn(&Narrowing) -> Carries, plain: Carries) -> Carries {
        match &self.scope.narrowing {
            Some(n) if (n.when)() => narrowed(n),
            _ => plain,
        }
    }

    fn take_token(&self) -> bool {
        self.bucket
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take(self.scope.rate, 1.0)
    }

    fn judge(
        &self,
        packet: Option<Packet>,
        carries: Carries,
        fragmented: &Mutex<Fragmented>,
        interests: Option<&(dyn Fn(&Name) -> bool + Send + Sync)>,
        answers: Option<&(dyn Fn(&Name) -> bool + Send + Sync)>,
    ) -> Judged {
        let Some(packet) = packet else {
            self.note_drop("not a packet a link carries", None);
            return Judged::Drop(None);
        };
        let verdict = match packet {
            Packet::LinkOnly { .. } => return Judged::Pass,
            Packet::LaterFragment { base } => {
                if fragmented
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .passed(base)
                {
                    Judged::Pass
                } else {
                    self.note_drop("a fragment of a packet not carried", None);
                    Judged::Drop(None)
                }
            }
            Packet::Network {
                kind,
                name,
                whole,
                first_of,
            } => {
                let carried = match carries {
                    Carries::Interests => kind == Kind::Interest,
                    Carries::Answers => kind != Kind::Interest,
                    Carries::Everything => true,
                };
                let named = if kind == Kind::Interest {
                    interests.is_none_or(|named| named(&name))
                } else {
                    answers.is_none_or(|named| named(&name))
                };
                if carried && named && (self.scope.names)(&name) {
                    if let Some(base) = first_of {
                        fragmented
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .remember(base);
                    }
                    Judged::Pass
                } else {
                    let what = match kind {
                        Kind::Interest => "an Interest",
                        Kind::Data => "a Data",
                        Kind::Nack => "a Nack",
                    };
                    self.note_drop(what, Some(&name));
                    Judged::Drop(
                        whole
                            .filter(|_| kind == Kind::Interest)
                            .map(|interest| (NackReason::NoRoute, interest)),
                    )
                }
            }
        };
        if verdict == Judged::Pass {
            let ms = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
            self.last_passed_ms.store(ms, Ordering::Relaxed);
        }
        verdict
    }

    fn note_drop(&self, what: &str, name: Option<&Name>) {
        let dropped = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
        let mut last = self.last_log.lock().unwrap_or_else(PoisonError::into_inner);
        if last.is_some_and(|t| t.elapsed() < DROP_LOG_EVERY) {
            return;
        }
        *last = Some(Instant::now());
        let name = name.map(|n| format!(" for {n}")).unwrap_or_default();
        tracing::info!(
            target: "face.quic",
            dropped,
            "dropped {what}{name}: {}",
            self.scope.explain
        );
    }
}

/// A Nack for an Interest a scope dropped, as an NDNLPv2 frame.
pub(crate) fn nack_for(reason: NackReason, interest: &[u8]) -> Bytes {
    ndn_packet::lp::encode_lp_nack(reason, interest)
}

/// What a frame costs the bandwidth buckets: its length.
fn bytes(frame: &Bytes) -> f64 {
    f64::from(u32::try_from(frame.len()).unwrap_or(u32::MAX))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Interest,
    Data,
    Nack,
}

/// What a frame carries, as far as a scope cares.
enum Packet {
    /// No network packet (acknowledgements, idle frames); `stamped` when it
    /// carries a TxSequence, which no honest peer's does.
    LinkOnly { stamped: bool },
    /// A network packet whole, or the first fragment of one.
    Network {
        kind: Kind,
        name: Name,
        /// The whole packet, when the frame carries it whole.
        whole: Option<Bytes>,
        /// The sequence of the first fragment, when it is one.
        first_of: Option<u64>,
    },
    /// A fragment after the first, of the packet whose first fragment had
    /// sequence `base`.
    LaterFragment { base: u64 },
}

impl Packet {
    fn of(frame: &Bytes) -> Option<Self> {
        let (t, _) = ndn_tlv::read_varu64(frame).ok()?;
        if t != LP_PACKET {
            let (kind, name) = head(frame)?;
            return Some(Self::Network {
                kind,
                name,
                whole: Some(frame.clone()),
                first_of: None,
            });
        }
        let lp = LpPacket::decode(frame.clone()).ok()?;
        let Some(fragment) = lp.fragment else {
            return Some(Self::LinkOnly {
                stamped: lp.tx_sequence.is_some(),
            });
        };
        let count = lp.frag_count.unwrap_or(1);
        let index = lp.frag_index.unwrap_or(0);
        if count > 1 {
            let base = lp.sequence?.checked_sub(index)?;
            if index > 0 {
                return Some(Self::LaterFragment { base });
            }
            let (kind, name) = head(&fragment)?;
            return Some(Self::Network {
                kind: if lp.nack.is_some() { Kind::Nack } else { kind },
                name,
                whole: None,
                first_of: Some(base),
            });
        }
        let (kind, name) = head(&fragment)?;
        Some(Self::Network {
            kind: if lp.nack.is_some() { Kind::Nack } else { kind },
            name,
            whole: Some(fragment),
            first_of: None,
        })
    }
}

/// The kind and name at the head of a network packet (or of its first
/// fragment: the Name is its first element).
fn head(packet: &[u8]) -> Option<(Kind, Name)> {
    let (t, tn) = ndn_tlv::read_varu64(packet).ok()?;
    let kind = match t {
        INTEREST => Kind::Interest,
        DATA => Kind::Data,
        _ => return None,
    };
    let (_, ln) = ndn_tlv::read_varu64(packet.get(tn..)?).ok()?;
    let rest = packet.get(tn + ln..)?;
    let (nt, ntn) = ndn_tlv::read_varu64(rest).ok()?;
    if nt != NAME {
        return None;
    }
    let (nl, nln) = ndn_tlv::read_varu64(rest.get(ntn..)?).ok()?;
    let start = ntn + nln;
    let value = rest.get(start..start.checked_add(usize::try_from(nl).ok()?)?)?;
    Name::decode(Bytes::copy_from_slice(value))
        .ok()
        .map(|name| (kind, name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_packet::encode::{DataBuilder, InterestBuilder};

    fn scope(receives: Carries, sends: Carries) -> ScopeState {
        let allowed: Name = "/home/CA".parse().unwrap();
        ScopeState::new(LinkScope {
            receives,
            sends,
            names: Box::new(move |n: &Name| n.has_prefix(&allowed)),
            rate: RateLimit {
                burst: 4,
                per_sec: 1,
            },
            bandwidth: None,
            rated: Vec::new(),
            interests: None,
            answered: None,
            shared: None,
            explain: "test".into(),
            answers_in: None,
            interests_in: None,
            narrowing: None,
            counts: None,
        })
    }

    fn interest(name: &str) -> Bytes {
        InterestBuilder::new(name.parse::<Name>().unwrap()).build()
    }

    fn data(name: &str, len: usize) -> Bytes {
        DataBuilder::new(name.parse::<Name>().unwrap(), &vec![7u8; len]).build()
    }

    #[test]
    fn each_direction_carries_its_kind_within_the_names_only() {
        let s = scope(Carries::Interests, Carries::Answers);
        let inside = ndn_packet::lp::encode_lp_packet(&interest("/home/CA/NEW"));
        assert_eq!(s.received(&inside), Judged::Pass);
        let outside = interest("/home/member/phone/album");
        assert_eq!(
            s.received(&ndn_packet::lp::encode_lp_packet(&outside)),
            Judged::Drop(Some((NackReason::NoRoute, outside))),
            "an Interest outside the scope is dropped, to be Nacked"
        );
        // Data from the peer: the wrong kind for what it may send.
        assert_eq!(
            s.received(&ndn_packet::lp::encode_lp_packet(&data("/home/CA/NEW", 10))),
            Judged::Drop(None)
        );
        // This side sends answers within the names, never Interests.
        assert_eq!(
            s.sending(&ndn_packet::lp::encode_lp_packet(&data("/home/CA/NEW", 10))),
            Judged::Pass
        );
        assert!(matches!(
            s.sending(&ndn_packet::lp::encode_lp_packet(&interest("/home/CA/x"))),
            Judged::Drop(Some(_))
        ));
        assert_eq!(
            s.sending(&ndn_packet::lp::encode_lp_packet(&data(
                "/home/member/x",
                10
            ))),
            Judged::Drop(None)
        );
    }

    /// A scope with `answers_in` carries the peer's Interests anywhere in the
    /// names, but its answers only within it; what this side sends is judged
    /// by the names alone.
    #[test]
    fn answers_the_peer_sends_are_judged_by_answers_in() {
        let own: Name = "/bob/member/phone".parse().unwrap();
        let s = ScopeState::new(LinkScope {
            receives: Carries::Everything,
            sends: Carries::Everything,
            names: Box::new(|_: &Name| true),
            rate: RateLimit {
                burst: 100,
                per_sec: 100,
            },
            bandwidth: None,
            rated: Vec::new(),
            interests: None,
            answered: None,
            shared: None,
            explain: "test".into(),
            answers_in: Some(Box::new(move |n: &Name| n.has_prefix(&own))),
            interests_in: None,
            narrowing: None,
            counts: None,
        });
        let lp = |p: &Bytes| ndn_packet::lp::encode_lp_packet(p);
        assert_eq!(
            s.received(&lp(&interest("/alice/32=sync/probe"))),
            Judged::Pass,
            "the peer's Interests go everywhere"
        );
        assert_eq!(
            s.received(&lp(&data("/bob/member/phone/seal/1", 10))),
            Judged::Pass,
            "an answer under the peer's own name passes"
        );
        assert_eq!(
            s.received(&lp(&data("/bob/32=sync/probe/1", 10))),
            Judged::Drop(None),
            "an answer under another name is dropped"
        );
        assert_eq!(
            s.sending(&lp(&data("/alice/32=sync/probe/1", 10))),
            Judged::Pass,
            "what this side sends is not held to answers_in"
        );
    }

    /// A scope with `interests_in` carries the peer's Interests only within
    /// it, and still its answers within `answers_in`; what this side sends is
    /// judged by the names alone. An Interest dropped is Nacked back to the
    /// peer, never handed on.
    #[test]
    fn interests_the_peer_sends_are_judged_by_interests_in() {
        let own: Name = "/bob/member/phone".parse().unwrap();
        let asked: Name = "/alice/member/laptop/32=held".parse().unwrap();
        let (own_in, asked_in, asked_names) = (own.clone(), asked.clone(), asked.clone());
        let s = ScopeState::new(LinkScope {
            receives: Carries::Everything,
            sends: Carries::Everything,
            names: Box::new(move |n: &Name| n.has_prefix(&own) || n.has_prefix(&asked_names)),
            rate: RateLimit {
                burst: 100,
                per_sec: 100,
            },
            bandwidth: None,
            rated: Vec::new(),
            interests: None,
            answered: None,
            shared: None,
            explain: "test".into(),
            answers_in: Some(Box::new(move |n: &Name| n.has_prefix(&asked_in))),
            interests_in: Some(Box::new(move |n: &Name| n.has_prefix(&own_in))),
            narrowing: None,
            counts: None,
        });
        let lp = |p: &Bytes| ndn_packet::lp::encode_lp_packet(p);
        assert_eq!(
            s.received(&lp(&interest("/bob/member/phone/seal"))),
            Judged::Pass,
            "the peer may ask for the names under this side's own device"
        );
        let other = interest("/alice/member/laptop/32=held/x");
        assert_eq!(
            s.received(&lp(&other)),
            Judged::Drop(Some((NackReason::NoRoute, other))),
            "an Interest within the names but outside interests_in is dropped, to be Nacked"
        );
        let elsewhere = interest("/carol/private");
        assert_eq!(
            s.received(&lp(&elsewhere)),
            Judged::Drop(Some((NackReason::NoRoute, elsewhere))),
            "an Interest outside the names is dropped"
        );
        assert_eq!(
            s.received(&lp(&data("/alice/member/laptop/32=held/x", 10))),
            Judged::Pass,
            "an answer within answers_in passes: interests_in judges Interests only"
        );
        assert_eq!(
            s.sending(&lp(&interest("/alice/member/laptop/32=held/x"))),
            Judged::Pass,
            "what this side sends is not held to interests_in"
        );
    }

    /// A narrowing scope carries what it was admitted for until `when` holds,
    /// then, with no reconnect, only Interests from the peer and answers to
    /// it, within the same names; it widens again when `when` stops holding.
    #[test]
    fn a_narrowing_scope_narrows_in_place_and_widens_back() {
        let narrowed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = Arc::clone(&narrowed);
        let s = ScopeState::new(LinkScope {
            receives: Carries::Everything,
            sends: Carries::Everything,
            names: Box::new(|_: &Name| true),
            rate: RateLimit {
                burst: 100,
                per_sec: 100,
            },
            bandwidth: None,
            rated: Vec::new(),
            interests: None,
            answered: None,
            shared: None,
            explain: "test".into(),
            answers_in: None,
            interests_in: None,
            narrowing: Some(Narrowing {
                when: Box::new(move || flag.load(Ordering::SeqCst)),
                receives: Carries::Interests,
                sends: Carries::Answers,
            }),
            counts: None,
        });
        let lp = |p: &Bytes| ndn_packet::lp::encode_lp_packet(p);
        let pushed = lp(&data("/bob/x", 10));
        let asked = lp(&interest("/bob/x"));
        assert_eq!(s.received(&pushed), Judged::Pass, "a full link before");
        assert_eq!(s.sending(&asked), Judged::Pass);

        narrowed.store(true, Ordering::SeqCst);
        assert_eq!(
            s.received(&pushed),
            Judged::Drop(None),
            "no Data from the peer once narrowed"
        );
        assert_eq!(s.received(&asked), Judged::Pass, "its Interests still come");
        assert!(
            matches!(s.sending(&asked), Judged::Drop(Some(_))),
            "this side asks the peer nothing once narrowed"
        );
        assert_eq!(s.sending(&pushed), Judged::Pass, "it still answers");

        narrowed.store(false, Ordering::SeqCst);
        assert_eq!(s.received(&pushed), Judged::Pass, "widened again");
    }

    #[test]
    fn fragments_follow_their_first_fragment() {
        let s = scope(Carries::Answers, Carries::Interests);
        for (name, carried) in [("/home/CA/big", true), ("/elsewhere/big", false)] {
            let frames = ndn_packet::fragment::fragment_packet(
                &data(name, 5000),
                1200,
                if carried { 100 } else { 200 },
            );
            assert!(frames.len() > 1);
            for frame in &frames {
                let judged = s.received(&frame.clone());
                assert_eq!(judged == Judged::Pass, carried, "{name}");
                // Keep the rate bucket out of the way.
                s.bucket
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .tokens = 4.0;
            }
        }
        // A later fragment whose first fragment was never seen is dropped.
        let frames = ndn_packet::fragment::fragment_packet(&data("/home/CA/big", 5000), 1200, 300);
        assert_eq!(s.received(&frames[1].clone()), Judged::Drop(None));
    }

    #[test]
    fn acknowledgements_pass_without_using_the_rate_bucket() {
        let s = scope(Carries::Interests, Carries::Answers);
        let ack_only = Bytes::from_static(&[0x64, 0x05, 0xFD, 0x03, 0x44, 0x01, 0x05]);
        for _ in 0..100 {
            assert_eq!(s.received(&ack_only), Judged::Pass);
        }
        let inside = ndn_packet::lp::encode_lp_packet(&interest("/home/CA/STATUS"));
        let passed = (0..10)
            .filter(|_| s.received(&inside) == Judged::Pass)
            .count();
        assert_eq!(
            passed, 4,
            "the whole burst is still there for the peer's Interests"
        );
    }

    #[test]
    fn received_packets_are_rate_limited() {
        let s = scope(Carries::Interests, Carries::Answers);
        let inside = ndn_packet::lp::encode_lp_packet(&interest("/home/CA/STATUS"));
        let passed = (0..10)
            .filter(|_| s.received(&inside) == Judged::Pass)
            .count();
        assert_eq!(
            passed, 4,
            "the burst, then nothing until the bucket refills"
        );
    }

    fn limited(
        rate: RateLimit,
        bandwidth: Option<RateLimit>,
        shared: Option<Arc<SharedRate>>,
        counts: Option<Arc<ScopeCounts>>,
    ) -> ScopeState {
        ScopeState::new(LinkScope {
            receives: Carries::Everything,
            sends: Carries::Everything,
            names: Box::new(|_: &Name| true),
            rate,
            bandwidth,
            rated: Vec::new(),
            interests: None,
            answered: None,
            shared,
            explain: "test".into(),
            answers_in: None,
            interests_in: None,
            narrowing: None,
            counts,
        })
    }

    /// An Interest the link's rate refuses is Nacked at once with Congestion
    /// (dropped for rate: ask again soon, not "there is no route"), so its
    /// asker retries instead of waiting for its timer.
    #[test]
    fn an_interest_over_the_rate_is_dropped_to_be_nacked_congestion() {
        let s = scope(Carries::Interests, Carries::Answers);
        let asked = interest("/home/CA/STATUS");
        let inside = ndn_packet::lp::encode_lp_packet(&asked);
        for _ in 0..4 {
            assert_eq!(s.received(&inside), Judged::Pass);
        }
        assert_eq!(
            s.received(&inside),
            Judged::Drop(Some((NackReason::Congestion, asked))),
            "an Interest over the rate must be dropped with a Congestion Nack"
        );
    }

    /// Only an Interest is Nacked: a Data or a fragment over the rate has
    /// nobody to tell, and is dropped.
    #[test]
    fn data_over_the_rate_is_dropped_without_a_nack() {
        let s = limited(
            RateLimit {
                burst: 1,
                per_sec: 1,
            },
            None,
            None,
            None,
        );
        let wire = |p: &Bytes| ndn_packet::lp::encode_lp_packet(p);
        assert_eq!(s.received(&wire(&data("/any/a", 10))), Judged::Pass);
        assert_eq!(
            s.received(&wire(&data("/any/b", 10))),
            Judged::Drop(None),
            "a Data over the rate"
        );
    }

    /// A flood is not answered with a flood: a link sends Congestion Nacks
    /// for the Interests it drops up to `CONGESTION_NACKS`, then drops
    /// silently; every drop is counted, every Nack counted.
    #[test]
    fn the_nacks_of_a_flood_are_bounded_and_counted() {
        let counts = Arc::new(ScopeCounts::default());
        let s = limited(
            RateLimit {
                burst: 10,
                per_sec: 1,
            },
            None,
            None,
            Some(Arc::clone(&counts)),
        );
        let flood = u64::from(CONGESTION_NACKS.burst) + 200;
        let wire = ndn_packet::lp::encode_lp_packet(&interest("/any/x"));
        let mut nacked = 0;
        for _ in 0..(10 + flood) {
            if matches!(s.received(&wire), Judged::Drop(Some(_))) {
                nacked += 1;
            }
        }
        assert!(
            (u64::from(CONGESTION_NACKS.burst)..=u64::from(CONGESTION_NACKS.burst) + 2)
                .contains(&nacked),
            "{nacked} Nacks for a flood of {flood} dropped Interests: the bound is {}",
            CONGESTION_NACKS.burst
        );
        assert_eq!(counts.over_rate(), flood, "every drop is counted");
        assert_eq!(counts.congestion_nacks(), nacked, "every Nack is counted");
    }

    /// The Nack of a rate is the spec's vector (ndn-link.md §19, scope Nack,
    /// Congestion): the NoRoute one of the same Interest with reason 50.
    #[test]
    fn the_congestion_nack_is_the_specs_vector() {
        let hex = |s: &str| -> Vec<u8> {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect()
        };
        let interest = hex("051707 0f0804686f6d650802434108034e45570a0401020304"
            .replace(' ', "")
            .as_str());
        assert_eq!(
            nack_for(NackReason::Congestion, &interest).as_ref(),
            hex("6424fd032005fd0321013250190517070f0804686f6d650802434108034e45570a0401020304")
        );
        assert_eq!(
            nack_for(NackReason::NoRoute, &interest).as_ref(),
            hex("6424fd032005fd0321019650190517070f0804686f6d650802434108034e45570a0401020304")
        );
    }

    /// A link bounded by bandwidth counts bytes: frames of a size that fit
    /// the burst pass, the next is over the bandwidth, and what is over it
    /// is dropped (an Interest with a Congestion Nack, a Data without).
    #[test]
    fn a_bandwidth_bound_counts_bytes() {
        let piece = ndn_packet::lp::encode_lp_packet(&data("/any/piece", 1000));
        let len = u32::try_from(piece.len()).unwrap();
        let counts = Arc::new(ScopeCounts::default());
        let s = limited(
            RateLimit {
                burst: 1000,
                per_sec: 1000,
            },
            Some(RateLimit {
                burst: 2 * len + len / 2,
                per_sec: 1,
            }),
            None,
            Some(Arc::clone(&counts)),
        );
        assert_eq!(s.received(&piece), Judged::Pass);
        assert_eq!(s.received(&piece), Judged::Pass);
        assert_eq!(
            s.received(&piece),
            Judged::Drop(None),
            "a third piece is over the bandwidth: {} bytes left of {}",
            len / 2,
            2 * len + len / 2
        );
        let asked = interest("/any/ask");
        let ask = ndn_packet::lp::encode_lp_packet(&asked);
        assert!(u32::try_from(ask.len()).unwrap() < len / 2);
        assert_eq!(
            s.received(&ask),
            Judged::Pass,
            "an Interest is a few bytes and still fits"
        );
        // Acknowledgements take no byte of it.
        let ack_only = Bytes::from_static(&[0x64, 0x05, 0xFD, 0x03, 0x44, 0x01, 0x05]);
        for _ in 0..100 {
            assert_eq!(s.received(&ack_only), Judged::Pass);
        }
        assert_eq!(counts.over_rate(), 1);
    }

    /// The links of a namespace share a bound on bytes too.
    #[test]
    fn links_sharing_a_bandwidth_take_no_more_than_it_together() {
        let piece = ndn_packet::lp::encode_lp_packet(&data("/any/piece", 1000));
        let len = u32::try_from(piece.len()).unwrap();
        let shared = Arc::new(SharedRate::new(
            RateLimit {
                burst: 1000,
                per_sec: 1000,
            },
            Some(RateLimit {
                burst: 3 * len + len / 2,
                per_sec: 1,
            }),
        ));
        let link = || {
            limited(
                RateLimit {
                    burst: 1000,
                    per_sec: 1000,
                },
                None,
                Some(Arc::clone(&shared)),
                None,
            )
        };
        let (a, b) = (link(), link());
        let passed = (0..4)
            .filter(|_| a.received(&piece) == Judged::Pass)
            .count()
            + (0..4)
                .filter(|_| b.received(&piece) == Judged::Pass)
                .count();
        assert_eq!(
            passed, 3,
            "three pieces in all pass the namespace's burst of bytes"
        );
    }

    /// The Interests of the names a scope rates apart take a bucket of their
    /// own, are dropped without a Nack when it is empty, and leave the link's
    /// other names and the shared bucket as they were.
    #[test]
    fn rated_interests_take_a_bucket_of_their_own() {
        let shared = Arc::new(SharedRate::new(
            RateLimit {
                burst: 1000,
                per_sec: 1000,
            },
            None,
        ));
        let s = ScopeState::new(LinkScope {
            receives: Carries::Everything,
            sends: Carries::Everything,
            names: Box::new(|_: &Name| true),
            rate: RateLimit {
                burst: 1000,
                per_sec: 1000,
            },
            bandwidth: None,
            rated: vec![RatedInterests {
                names: Box::new(|n: &Name| n.has_prefix(&"/rated".parse::<Name>().unwrap())),
                rate: RateLimit {
                    burst: 3,
                    per_sec: 1,
                },
            }],
            interests: None,
            answered: None,
            shared: Some(Arc::clone(&shared)),
            explain: "test".into(),
            answers_in: None,
            interests_in: None,
            narrowing: None,
            counts: None,
        });
        let wire = |p: Bytes| ndn_packet::lp::encode_lp_packet(&p);
        let rated = wire(interest("/rated/x"));
        let plain = wire(interest("/plain/x"));
        let passed = (0..10)
            .filter(|_| s.received(&rated) == Judged::Pass)
            .count();
        assert_eq!(passed, 3, "the rated names' burst, then nothing");
        assert_eq!(
            s.received(&rated),
            Judged::Drop(None),
            "an Interest over the rate is dropped without a Nack"
        );
        // Other names, Data of the rated name, are not held to it.
        assert_eq!(s.received(&plain), Judged::Pass);
        assert_eq!(s.received(&wire(data("/rated/x", 10))), Judged::Pass);
        // The refused Interests took nothing of the shared bucket: 3 + 1 + 1.
        let left = shared.buckets.lock().unwrap().0.tokens;
        assert!(
            (994.0..996.0).contains(&left),
            "{left} tokens left of the shared bucket"
        );
    }

    #[test]
    fn links_sharing_a_rate_take_no_more_than_it_together() {
        let shared = Arc::new(SharedRate::new(
            RateLimit {
                burst: 6,
                per_sec: 1,
            },
            None,
        ));
        let link = || {
            ScopeState::new(LinkScope {
                receives: Carries::Everything,
                sends: Carries::Everything,
                names: Box::new(|_: &Name| true),
                rate: RateLimit {
                    burst: 4,
                    per_sec: 1,
                },
                bandwidth: None,
                rated: Vec::new(),
                interests: None,
                answered: None,
                shared: Some(Arc::clone(&shared)),
                explain: "test".into(),
                answers_in: None,
                interests_in: None,
                narrowing: None,
                counts: None,
            })
        };
        let (a, b) = (link(), link());
        let wire = |p: Bytes| ndn_packet::lp::encode_lp_packet(&p);
        // Both kinds pass both ways on a link that carries everything.
        assert_eq!(a.received(&wire(data("/any/x", 10))), Judged::Pass);
        assert_eq!(a.sending(&wire(interest("/any/y"))), Judged::Pass);
        assert_eq!(a.sending(&wire(data("/any/y", 10))), Judged::Pass);
        let inside = wire(interest("/any/z"));
        let passed = (0..10)
            .filter(|_| a.received(&inside) == Judged::Pass)
            .count()
            + (0..10)
                .filter(|_| b.received(&inside) == Judged::Pass)
                .count();
        assert_eq!(
            passed, 5,
            "each link within its own burst, both within the shared one"
        );
    }

    /// A scope of everything, with the buckets round 12 added.
    fn bounded(
        interests: Option<RateLimit>,
        answered: Option<RateLimit>,
        rated: Vec<RatedInterests>,
    ) -> ScopeState {
        ScopeState::new(LinkScope {
            receives: Carries::Everything,
            sends: Carries::Everything,
            names: Box::new(|_: &Name| true),
            rate: RateLimit {
                burst: 100_000,
                per_sec: 100_000,
            },
            bandwidth: None,
            rated,
            interests,
            answered,
            shared: None,
            explain: "test".into(),
            answers_in: None,
            interests_in: None,
            narrowing: None,
            counts: None,
        })
    }

    /// R12 M2(a): the Interests a peer sends have a bucket below the frames', and what is
    /// over it is Nacked Congestion like any Interest over a rate; Data and fragments take
    /// none of it.
    #[test]
    fn interests_take_a_bucket_of_their_own_below_the_frames() {
        let s = bounded(
            Some(RateLimit {
                burst: 3,
                per_sec: 1,
            }),
            None,
            Vec::new(),
        );
        let wire = |p: &Bytes| ndn_packet::lp::encode_lp_packet(p);
        let asked = interest("/any/x");
        let passed = (0..10)
            .filter(|_| s.received(&wire(&asked)) == Judged::Pass)
            .count();
        assert_eq!(passed, 3, "the Interests' burst, then nothing");
        assert_eq!(
            s.received(&wire(&asked)),
            Judged::Drop(Some((NackReason::Congestion, asked))),
            "an Interest over its bucket is Nacked Congestion"
        );
        for _ in 0..1000 {
            assert_eq!(
                s.received(&wire(&data("/any/x", 10))),
                Judged::Pass,
                "Data takes no token of the Interests' bucket"
            );
        }
    }

    /// R12 M2(b): the bytes of answers this side sends are bounded; Interests this side
    /// sends and the answers within the burst are not, and a later fragment is counted.
    #[test]
    fn the_bytes_of_answers_sent_are_bounded() {
        let piece = ndn_packet::lp::encode_lp_packet(&data("/any/piece", 1000));
        let len = u32::try_from(piece.len()).unwrap();
        let s = bounded(
            None,
            Some(RateLimit {
                burst: 2 * len + len / 2,
                per_sec: 1,
            }),
            Vec::new(),
        );
        assert_eq!(s.sending(&piece), Judged::Pass);
        assert_eq!(s.sending(&piece), Judged::Pass);
        assert_eq!(
            s.sending(&piece),
            Judged::Drop(None),
            "a third piece is over the budget"
        );
        let ask = ndn_packet::lp::encode_lp_packet(&interest("/any/ask"));
        for _ in 0..100 {
            assert_eq!(
                s.sending(&ask),
                Judged::Pass,
                "an Interest this side sends is no answer"
            );
        }
        // What the peer sends is not counted by it.
        assert_eq!(s.received(&piece), Judged::Pass);
        assert_eq!(s.received(&piece), Judged::Pass);
        assert_eq!(s.received(&piece), Judged::Pass);

        // Fragments are counted: a Data of 5000 bytes in 1200-byte frames is over a budget
        // of two frames' worth after its first two fragments.
        let frames = ndn_packet::fragment::fragment_packet(&data("/any/big", 5000), 1200, 7);
        assert!(frames.len() > 3);
        let flen = u32::try_from(frames[0].len()).unwrap();
        let s = bounded(
            None,
            Some(RateLimit {
                burst: 2 * flen + 10,
                per_sec: 1,
            }),
            Vec::new(),
        );
        let passed = frames
            .iter()
            .filter(|f| s.sending(&(*f).clone()) == Judged::Pass)
            .count();
        assert_eq!(passed, 2, "the budget holds two fragments");
    }

    /// R12 H1: each class of rated names has its own bucket; Interests of no class take
    /// none, and a class's flood does not use up another's.
    #[test]
    fn each_class_of_rated_names_has_a_bucket_of_its_own() {
        let class = |prefix: &'static str, burst| RatedInterests {
            names: Box::new(move |n: &Name| n.has_prefix(&prefix.parse::<Name>().unwrap())),
            rate: RateLimit { burst, per_sec: 1 },
        };
        let s = bounded(None, None, vec![class("/a", 2), class("/b", 5)]);
        let wire = |name: &str| ndn_packet::lp::encode_lp_packet(&interest(name));
        let count = |name: &str| {
            (0..20)
                .filter(|_| s.received(&wire(name)) == Judged::Pass)
                .count()
        };
        assert_eq!(count("/a/x"), 2);
        assert_eq!(count("/b/x"), 5, "the other class's bucket is its own");
        assert_eq!(count("/c/x"), 20, "names of no class are not rated");
    }

    /// An acknowledgement-only frame, with `acks` acks (and a TxSequence when `stamped`).
    fn link_only(acks: usize, stamped: Option<u8>) -> Bytes {
        // Headers ascend by type: the acks (0x0344), then the TxSequence (0x0348). A frame
        // with a TxSequence and no ack at all is no LpPacket (it has neither fragment nor
        // acks) and is dropped before any bucket.
        let mut inner = Vec::new();
        for i in 0..acks {
            inner.extend_from_slice(&[0xFD, 0x03, 0x44, 0x01, u8::try_from(i % 200).unwrap()]);
        }
        if let Some(seq) = stamped {
            inner.extend_from_slice(&[0xFD, 0x03, 0x48, 0x01, seq]);
        }
        let mut frame = vec![0x64, u8::try_from(inner.len()).unwrap()];
        frame.extend_from_slice(&inner);
        Bytes::from(frame)
    }

    /// R12 L1: a frame with no packet in it takes a token of a bucket of its own, never
    /// of the link's frames, and one carrying a TxSequence (no honest peer sends one) of a
    /// small one; the buckets stay clear of what an honest peer sends.
    #[test]
    fn frames_with_no_packet_are_rated_and_the_peers_packets_are_not_held_back() {
        let s = scope(Carries::Interests, Carries::Answers);
        // An honest peer's idle-Ack pump: 200 frames a second, many acks each, for a while.
        let acks = link_only(40, None);
        for _ in 0..u64::from(LINK_ONLY_FRAMES.burst) {
            assert_eq!(s.received(&acks), Judged::Pass);
        }
        let flooded = (0..100_000)
            .filter(|_| s.received(&acks) == Judged::Pass)
            .count();
        // Whatever time passes in the loop refills 1,024 a second.
        assert!(
            flooded < 20_000,
            "{flooded} of 100,000 ack-only frames past the burst passed"
        );
        // The link's own frames took none of it.
        let inside = ndn_packet::lp::encode_lp_packet(&interest("/home/CA/STATUS"));
        assert_eq!(
            (0..10)
                .filter(|_| s.received(&inside) == Judged::Pass)
                .count(),
            4,
            "the whole burst of the link's frames is still there"
        );

        let s = scope(Carries::Interests, Carries::Answers);
        let stamped = link_only(1, Some(9));
        let passed = (0..1000)
            .filter(|_| s.received(&stamped) == Judged::Pass)
            .count();
        assert!(
            passed <= STAMPED_LINK_ONLY_FRAMES.burst as usize + 2,
            "{passed} of 1000 frames with a TxSequence and no fragment passed: no honest peer \
             sends one, the bucket holds {}",
            STAMPED_LINK_ONLY_FRAMES.burst
        );
        assert!(passed >= STAMPED_LINK_ONLY_FRAMES.burst as usize);
    }
}
