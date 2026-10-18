//! A link that carries less than everything: an *enrollment link*.
//!
//! A [`LinkScope`] says which kind of packet each direction carries
//! (Interests one way, their answers the other) and which names; the face
//! of a scoped link drops everything else as it crosses, in both
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
//! packets are rate-limited before they are judged.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};
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
}

/// Received packets a scoped link takes: `burst` at once, refilled at
/// `per_sec`.
#[derive(Clone, Copy, Debug)]
pub struct RateLimit {
    pub burst: u32,
    pub per_sec: u32,
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
            bucket: Mutex::new(Bucket {
                tokens: f64::from(scope.rate.burst),
                at: now,
            }),
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

    /// Judge a frame the peer sent.
    pub(crate) fn received(&self, frame: &Bytes) -> Judged {
        if !self.take_token() {
            self.note_drop("over the rate limit", None);
            return Judged::Drop(None);
        }
        self.judge(frame, self.scope.receives, &self.inbound)
    }

    /// Judge a frame this side would send.
    pub(crate) fn sending(&self, frame: &Bytes) -> Judged {
        self.judge(frame, self.scope.sends, &self.outbound)
    }

    fn take_token(&self) -> bool {
        let mut bucket = self.bucket.lock().unwrap_or_else(PoisonError::into_inner);
        let now = Instant::now();
        let refill = now.duration_since(bucket.at).as_secs_f64() * f64::from(self.scope.rate.per_sec);
        bucket.tokens = (bucket.tokens + refill).min(f64::from(self.scope.rate.burst));
        bucket.at = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn judge(&self, frame: &Bytes, carries: Carries, fragmented: &Mutex<Fragmented>) -> Judged {
        let Some(packet) = Packet::of(frame) else {
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
    Name::decode(Bytes::copy_from_slice(value)).ok().map(|name| (kind, name))
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
        assert_eq!(s.sending(&ndn_packet::lp::encode_lp_packet(&data("/home/CA/NEW", 10))), Judged::Pass);
        assert!(matches!(s.sending(&ndn_packet::lp::encode_lp_packet(&interest("/home/CA/x"))), Judged::Drop(Some(_))));
        assert_eq!(
            s.sending(&ndn_packet::lp::encode_lp_packet(&data("/home/member/x", 10))),
            Judged::Drop(None)
        );
    }

    #[test]
    fn fragments_follow_their_first_fragment() {
        let s = scope(Carries::Answers, Carries::Interests);
        for (name, carried) in [("/home/CA/big", true), ("/elsewhere/big", false)] {
            let frames = ndn_packet::fragment::fragment_packet(&data(name, 5000), 1200, if carried { 100 } else { 200 });
            assert!(frames.len() > 1);
            for frame in &frames {
                let judged = s.received(&frame.clone());
                assert_eq!(judged == Judged::Pass, carried, "{name}");
                // Keep the rate bucket out of the way.
                s.bucket.lock().unwrap_or_else(PoisonError::into_inner).tokens = 4.0;
            }
        }
        // A later fragment whose first fragment was never seen is dropped.
        let frames = ndn_packet::fragment::fragment_packet(&data("/home/CA/big", 5000), 1200, 300);
        assert_eq!(s.received(&frames[1].clone()), Judged::Drop(None));
    }

    #[test]
    fn received_packets_are_rate_limited() {
        let s = scope(Carries::Interests, Carries::Answers);
        let inside = ndn_packet::lp::encode_lp_packet(&interest("/home/CA/STATUS"));
        let passed = (0..10).filter(|_| s.received(&inside) == Judged::Pass).count();
        assert_eq!(passed, 4, "the burst, then nothing until the bucket refills");
    }
}
