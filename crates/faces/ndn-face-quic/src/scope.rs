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
//! An Interest the scope drops is answered with a Nack (NoRoute) at once,
//! so the requester stops waiting: one arriving from the peer is Nacked to
//! the peer, one this side would send is Nacked back to this side. Received
//! packets are rate-limited before they are judged — by the link's own
//! bucket, then by a bucket it shares with other links ([`SharedRate`]);
//! acknowledgements are not.

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

/// Received packets a scoped link takes: `burst` at once, refilled at
/// `per_sec`.
#[derive(Clone, Copy, Debug)]
pub struct RateLimit {
    pub burst: u32,
    pub per_sec: u32,
}

/// One rate bucket shared by several links (all the links of a namespace a
/// relay serves, say): together they take no more than its [`RateLimit`].
pub struct SharedRate {
    rate: RateLimit,
    bucket: Mutex<Bucket>,
}

impl SharedRate {
    pub fn new(rate: RateLimit) -> Self {
        Self {
            bucket: Mutex::new(Bucket::full(rate)),
            rate,
        }
    }

    fn take(&self) -> bool {
        self.bucket
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take(self.rate)
    }
}

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
    /// A bound on received packets shared with other links, checked after
    /// `rate`.
    pub shared: Option<Arc<SharedRate>>,
    /// For the log, when a packet is dropped: what the link carries and
    /// what to do to carry more.
    pub explain: String,
}

/// What a scope did with a frame.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Judged {
    Pass,
    /// Dropped; `Some` is the Interest to Nack.
    Drop(Option<Bytes>),
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

    /// Refill for the time since the last take, then take a token if there
    /// is one.
    fn take(&mut self, rate: RateLimit) -> bool {
        let now = Instant::now();
        let refill = now.duration_since(self.at).as_secs_f64() * f64::from(rate.per_sec);
        self.tokens = (self.tokens + refill).min(f64::from(rate.burst));
        self.at = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// A scope at work on one link: its verdicts, rate bucket and activity.
pub(crate) struct ScopeState {
    scope: LinkScope,
    inbound: Mutex<Fragmented>,
    outbound: Mutex<Fragmented>,
    bucket: Mutex<Bucket>,
    started: Instant,
    /// Milliseconds after `started` of the last packet the scope passed.
    last_passed_ms: AtomicU64,
    dropped: AtomicU64,
    last_log: Mutex<Option<Instant>>,
}

impl ScopeState {
    pub(crate) fn new(scope: LinkScope) -> Self {
        let now = Instant::now();
        Self {
            bucket: Mutex::new(Bucket::full(scope.rate)),
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
    /// acknowledgement) passes without a token: acknowledgements of the
    /// fragments this side sends must not crowd out the peer's packets.
    pub(crate) fn received(&self, frame: &Bytes) -> Judged {
        let packet = Packet::of(frame);
        if !matches!(packet, Some(Packet::LinkOnly)) {
            if !self.take_token() {
                self.note_drop("over the rate limit", None);
                return Judged::Drop(None);
            }
            if self
                .scope
                .shared
                .as_ref()
                .is_some_and(|shared| !shared.take())
            {
                self.note_drop("over the rate limit shared with other links", None);
                return Judged::Drop(None);
            }
        }
        self.judge(packet, self.scope.receives, &self.inbound)
    }

    /// Judge a frame this side would send.
    pub(crate) fn sending(&self, frame: &Bytes) -> Judged {
        self.judge(Packet::of(frame), self.scope.sends, &self.outbound)
    }

    fn take_token(&self) -> bool {
        self.bucket
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take(self.scope.rate)
    }

    fn judge(
        &self,
        packet: Option<Packet>,
        carries: Carries,
        fragmented: &Mutex<Fragmented>,
    ) -> Judged {
        let Some(packet) = packet else {
            self.note_drop("not a packet a link carries", None);
            return Judged::Drop(None);
        };
        let verdict = match packet {
            Packet::LinkOnly => return Judged::Pass,
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
                if carried && (self.scope.names)(&name) {
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
                    Judged::Drop(whole.filter(|_| kind == Kind::Interest))
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

/// A Nack (NoRoute) for an Interest a scope dropped, as an NDNLPv2 frame.
pub(crate) fn nack_for(interest: &[u8]) -> Bytes {
    ndn_packet::lp::encode_lp_nack(NackReason::NoRoute, interest)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Interest,
    Data,
    Nack,
}

/// What a frame carries, as far as a scope cares.
enum Packet {
    /// No network packet (acknowledgements, idle frames).
    LinkOnly,
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
            return Some(Self::LinkOnly);
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
            shared: None,
            explain: "test".into(),
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
            Judged::Drop(Some(outside)),
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

    #[test]
    fn links_sharing_a_rate_take_no_more_than_it_together() {
        let shared = Arc::new(SharedRate::new(RateLimit {
            burst: 6,
            per_sec: 1,
        }));
        let link = || {
            ScopeState::new(LinkScope {
                receives: Carries::Everything,
                sends: Carries::Everything,
                names: Box::new(|_: &Name| true),
                rate: RateLimit {
                    burst: 4,
                    per_sec: 1,
                },
                shared: Some(Arc::clone(&shared)),
                explain: "test".into(),
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
}
