//! The fault layer: **for tests only**. Behind the cargo feature `fault-injection`
//! (off by default, never enabled by another crate's default features, loud at start
//! and in [`Links::report`](crate::Links::report)), every link's face meets a seeded
//! fault profile as packets *arrive* on it: each is dropped, duplicated, forged,
//! delayed or held back, or none of these, exactly as the conformance's `--faulty`
//! profile does it. The profile and its draws are the `ndn-faults` crate's, shared
//! with `ndn-sim`, so a profile and a seed give the same fates on a simulated link
//! and on a real one.
//!
//! What it does and does not touch (ndn-rs `docs/specs/ndn-link.md` §17B):
//!
//! - **Only what crosses links.** The wrapper sits on the link's face, between the
//!   QUIC datagram and the forwarder: the host's local faces are never faulted. The
//!   link's own handshake and control messages (they travel on QUIC streams, not
//!   through the face) are not faulted either.
//! - **On arrival, once.** Each packet a link's face yields meets the profile once;
//!   what this device sends is not faulted here (the other device's layer faults it
//!   when it arrives there, as it does in the simulator).
//! - **A forged packet is still refused.** The layer only flips a signature byte of
//!   a Data; the consumer's validation refuses it.
//! - **Deterministic.** Each link's arrivals draw from the profile's stream for the
//!   direction `peer key → this device's key`, so the same seed, the same devices
//!   and the same packets give the same fates. A packet the verdict drops or passes
//!   draws nothing, so the fates of the packets that meet the profile do not depend on
//!   how many others were dropped or passed.
//! - **Links already up.** A plan installed by [`Links::inject_faults`] applies to
//!   every link, those already up included, from the next packet that arrives.

use std::cmp::{Ordering as Cmp, Reverse};
use std::collections::BinaryHeap;
use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use ndn_face_quic::{Direction, KeyFingerprint};
use ndn_faults::{FaultStream, Faults};
use ndn_packet::Name;
use ndn_packet::lp::LpPacket;
use ndn_transport::{
    ErasedTransport, FaceAddr, FaceError, FaceId, FaceKind, FacePersistency, FaceTrust, LinkType,
    MtuError, PeerCredentials, PersistencyError, Transport,
};
use parking_lot::RwLock;
use tokio::sync::Mutex;
use tokio::time::Instant;

use crate::fault_report::FaultReport;
use crate::links::Links;

const LP_PACKET: u64 = 0x64;
const INTEREST: u64 = 0x05;
const DATA: u64 = 0x06;
const NAME: u64 = 0x07;

/// What a packet that arrived on a link is, as far as a plan's verdict cares.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultKind {
    /// An Interest.
    Interest,
    /// A Data (a whole one, or the first fragment of a larger one).
    Data,
    /// A Nack.
    Nack,
    /// Anything else: a link-service frame carrying no network packet (an
    /// acknowledgement), a later fragment, or bytes that are no packet.
    Other,
}

/// What a plan's verdict is asked about: one packet that has just arrived on a
/// link.
#[derive(Clone, Debug)]
pub struct FaultFrame {
    /// Which side of the link opened it: `Dialed` when this device did.
    pub direction: Direction,
    /// The key of the device the packet came from.
    pub peer: KeyFingerprint,
    /// What the packet is.
    pub kind: FaultKind,
    /// The packet's name, for an Interest, a Data or a Nack (of a fragmented packet,
    /// the first fragment's); `None` for [`FaultKind::Other`].
    pub name: Option<Name>,
    /// The frame's length in bytes, as it crossed the link.
    pub len: usize,
}

/// What a plan says of one packet that arrived on a link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultVerdict {
    /// The profile applies to the packet: it meets the seeded draws and may be dropped,
    /// duplicated, forged or delayed ([`FaultReport::met`]).
    Profile,
    /// The packet is discarded, as a lossy network would. It draws nothing from the
    /// profile's stream and is counted in [`FaultReport::dropped`], the counter the
    /// profile's own drops share.
    Drop,
    /// The packet is delivered at once and untouched ([`FaultReport::passed`]). It draws
    /// nothing from the profile's stream.
    Pass,
}

/// What a plan's verdict function looks like: it says what becomes of the packet. It
/// runs on the link's receive path: keep it short; it must not block.
pub type FaultJudge = Arc<dyn Fn(&FaultFrame) -> FaultVerdict + Send + Sync>;

/// A profile, and a verdict per packet.
#[derive(Clone)]
pub struct FaultPlan {
    /// What becomes of the packets the verdict hands to the profile.
    pub profile: Faults,
    /// The verdict per packet: `None` is [`FaultVerdict::Profile`] for every packet. A
    /// `Drop` or a `Pass` draws nothing from the profile's stream, so the fates of the
    /// packets that meet the profile do not depend on how many others were dropped or
    /// passed.
    pub verdict: Option<FaultJudge>,
}

impl FaultPlan {
    /// The profile on every packet that arrives.
    pub fn new(profile: Faults) -> FaultPlan {
        FaultPlan {
            profile,
            verdict: None,
        }
    }

    /// The verdict `f` gives on each packet: the profile on it, discard it, or let it
    /// pass.
    pub fn verdict(
        mut self,
        f: impl Fn(&FaultFrame) -> FaultVerdict + Send + Sync + 'static,
    ) -> FaultPlan {
        self.verdict = Some(Arc::new(f));
        self
    }
}

impl fmt::Debug for FaultPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FaultPlan")
            .field("profile", &self.profile.to_string())
            .field("verdict", &self.verdict.as_ref().map(|_| "<verdict>"))
            .finish()
    }
}

/// The notice every `Links::start` of a build with the layer logs.
pub(crate) fn notice() {
    tracing::warn!(
        target: "ndn_link::fault",
        "ndn-link was built with `fault-injection`: it can drop, duplicate, forge and delay \
         packets; this is for tests and must not be in a production build"
    );
}

/// What a plan has done, over every link.
#[derive(Default)]
struct Counts {
    met: AtomicU64,
    dropped: AtomicU64,
    duplicated: AtomicU64,
    forged: AtomicU64,
    delayed: AtomicU64,
    passed: AtomicU64,
    predicate_panics: AtomicU64,
}

impl Counts {
    fn bump(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

/// An installed plan, with its own counters.
struct Plan {
    profile: Faults,
    verdict: Option<FaultJudge>,
    counts: Counts,
}

/// The plan every link of one [`Links`] shares.
#[derive(Default)]
pub(crate) struct FaultLayer {
    plan: RwLock<Option<Arc<Plan>>>,
}

impl FaultLayer {
    fn install(&self, plan: FaultPlan) {
        tracing::warn!(
            target: "ndn_link::fault",
            profile = %plan.profile,
            filtered = plan.verdict.is_some(),
            "fault injection is ON: packets arriving on links will be dropped, duplicated, \
             forged and delayed (tests only)"
        );
        *self.plan.write() = Some(Arc::new(Plan {
            profile: plan.profile,
            verdict: plan.verdict,
            counts: Counts::default(),
        }));
    }

    fn clear(&self) {
        *self.plan.write() = None;
    }

    fn current(&self) -> Option<Arc<Plan>> {
        self.plan.read().clone()
    }

    /// `transport`, the face of a link to the device with key `peer`, meeting the
    /// plan as its packets arrive.
    pub(crate) fn wrap(
        self: &Arc<Self>,
        transport: Arc<dyn ErasedTransport>,
        peer: KeyFingerprint,
        me: Option<KeyFingerprint>,
        direction: Direction,
    ) -> Arc<dyn ErasedTransport> {
        Arc::new(Faulted {
            inner: transport,
            layer: Arc::clone(self),
            peer,
            direction,
            from: end(&peer),
            to: me.as_ref().map_or(0, end),
            rx: Mutex::new(Rx::default()),
        })
    }

    pub(crate) fn report(&self) -> FaultReport {
        let Some(plan) = self.current() else {
            return FaultReport::default();
        };
        let c = &plan.counts;
        let get = |n: &AtomicU64| n.load(Ordering::Relaxed);
        FaultReport {
            profile: Some(plan.profile.to_string()),
            met: get(&c.met),
            dropped: get(&c.dropped),
            duplicated: get(&c.duplicated),
            forged: get(&c.forged),
            delayed: get(&c.delayed),
            passed: get(&c.passed),
            predicate_panics: get(&c.predicate_panics),
        }
    }
}

/// A link end's identity for the draws: the first eight bytes of its key's
/// fingerprint.
pub(crate) fn end(key: &KeyFingerprint) -> u64 {
    let mut first = [0u8; 8];
    first.copy_from_slice(&key.0[..8]);
    u64::from_be_bytes(first)
}

impl Links {
    /// Applies `plan` to the packets arriving on every link of these links, those
    /// already up included (from the next packet that arrives), and on every link made
    /// afterwards. Replaces an earlier plan and starts its counters again
    /// ([`LinkReport::fault_injection`](crate::LinkReport)).
    ///
    /// **For tests only**: see the module's docs and ndn-rs `ndn-link.md` §17B.
    pub fn inject_faults(&self, plan: FaultPlan) {
        self.faults.install(plan);
    }

    /// Ends fault injection: packets arrive untouched again. Held packets are still
    /// delivered at their time.
    pub fn clear_faults(&self) {
        self.faults.clear();
    }

    pub(crate) fn fault_report(&self) -> Option<FaultReport> {
        Some(self.faults.report())
    }
}

/// A packet held until its time.
struct Held {
    due: Instant,
    seq: u64,
    frame: Bytes,
}

impl PartialEq for Held {
    fn eq(&self, other: &Self) -> bool {
        (self.due, self.seq) == (other.due, other.seq)
    }
}
impl Eq for Held {}
impl PartialOrd for Held {
    fn partial_cmp(&self, other: &Self) -> Option<Cmp> {
        Some(self.cmp(other))
    }
}
impl Ord for Held {
    fn cmp(&self, other: &Self) -> Cmp {
        (self.due, self.seq).cmp(&(other.due, other.seq))
    }
}

/// The receive side of one link's face: what it holds back, and the draws it makes.
#[derive(Default)]
struct Rx {
    held: BinaryHeap<Reverse<Held>>,
    seq: u64,
    /// The plan `stream` draws for, and its draws for this link's direction.
    drawing: Option<(Arc<Plan>, FaultStream)>,
    /// The link ended: what the face says once what it holds is delivered.
    ended: Option<FaceError>,
}

impl Rx {
    fn hold(&mut self, due: Instant, frame: Bytes) {
        self.seq += 1;
        self.held.push(Reverse(Held {
            due,
            seq: self.seq,
            frame,
        }));
    }

    fn take_due(&mut self, now: Instant) -> Option<Bytes> {
        if self.held.peek().is_some_and(|Reverse(h)| h.due <= now) {
            return self.held.pop().map(|Reverse(h)| h.frame);
        }
        None
    }
}

/// A link's face with the fault layer on its receive side. Sends, and everything the
/// forwarder asks of a transport, go straight through.
struct Faulted {
    inner: Arc<dyn ErasedTransport>,
    layer: Arc<FaultLayer>,
    peer: KeyFingerprint,
    direction: Direction,
    /// The ends of the arrival direction: the peer's key to this device's.
    from: u64,
    to: u64,
    rx: Mutex<Rx>,
}

impl Faulted {
    /// A packet has just arrived: deliver it, drop it, or hold it, as the plan says.
    fn arrived(&self, rx: &mut Rx, frame: Bytes) {
        let now = Instant::now();
        let Some(plan) = self.layer.current() else {
            rx.hold(now, frame);
            return;
        };
        let counts = &plan.counts;
        if let Some(judge) = &plan.verdict {
            let (kind, name) = frame_info(&frame);
            let seen = FaultFrame {
                direction: self.direction,
                peer: self.peer,
                kind,
                name,
                len: frame.len(),
            };
            match catch_unwind(AssertUnwindSafe(|| judge(&seen))) {
                Ok(FaultVerdict::Profile) => {}
                Ok(FaultVerdict::Pass) => {
                    Counts::bump(&counts.passed);
                    rx.hold(now, frame);
                    return;
                }
                Ok(FaultVerdict::Drop) => {
                    // What the network already does; the profile's stream is not asked.
                    Counts::bump(&counts.dropped);
                    return;
                }
                Err(_) => {
                    // A verdict that panics must not end the link's receive task: the
                    // packet is left alone, and the report says so.
                    Counts::bump(&counts.predicate_panics);
                    tracing::warn!(
                        target: "ndn_link::fault",
                        "the fault plan's verdict panicked; the packet was delivered untouched"
                    );
                    rx.hold(now, frame);
                    return;
                }
            }
        }
        if !rx
            .drawing
            .as_ref()
            .is_some_and(|(drawn, _)| Arc::ptr_eq(drawn, &plan))
        {
            let stream = plan.profile.stream(self.from, self.to);
            rx.drawing = Some((Arc::clone(&plan), stream));
        }
        let Some((_, stream)) = rx.drawing.as_mut() else {
            return;
        };
        let fate = stream.fate(frame.clone());
        Counts::bump(&counts.met);
        if fate.copies == 0 {
            Counts::bump(&counts.dropped);
            return;
        }
        if fate.copies > 1 {
            Counts::bump(&counts.duplicated);
        }
        if fate.frame != frame {
            Counts::bump(&counts.forged);
        }
        if !fate.delay.is_zero() {
            Counts::bump(&counts.delayed);
        }
        for _ in 0..fate.copies {
            rx.hold(now + fate.delay, fate.frame.clone());
        }
    }
}

impl Transport for Faulted {
    fn id(&self) -> FaceId {
        self.inner.id()
    }

    fn kind(&self) -> FaceKind {
        self.inner.kind()
    }

    fn remote_uri(&self) -> Option<String> {
        self.inner.remote_uri()
    }

    fn local_uri(&self) -> Option<String> {
        self.inner.local_uri()
    }

    fn link_type(&self) -> LinkType {
        self.inner.link_type()
    }

    fn trust(&self) -> FaceTrust {
        self.inner.trust()
    }

    fn send_mtu(&self) -> Option<usize> {
        self.inner.send_mtu()
    }

    async fn send_bytes(&self, wire: Bytes) -> Result<(), FaceError> {
        self.inner.send_bytes(wire).await
    }

    async fn send_batch(&self, wires: &[Bytes]) -> Result<(), FaceError> {
        self.inner.send_batch(wires).await
    }

    async fn send_bytes_with_source(&self, wire: Bytes, source: FaceId) -> Result<(), FaceError> {
        self.inner.send_bytes_with_source(wire, source).await
    }

    async fn send_bytes_to(&self, addr: FaceAddr, wire: Bytes) -> Result<(), FaceError> {
        self.inner.send_bytes_to(addr, wire).await
    }

    /// The side path is the link's own: like `send_bytes`, what this device sends
    /// is not faulted here (the peer's layer meets it on arrival), so it goes to
    /// the link's face as is.
    async fn send_side(
        &self,
        frame: Bytes,
        class: ndn_transport::SideClass,
    ) -> Result<(), ndn_transport::SideRefused> {
        self.inner.send_side(frame, class).await
    }

    fn forward_side(
        &self,
        frame: Bytes,
        class: ndn_transport::SideClass,
    ) -> Result<(), ndn_transport::SideRefused> {
        self.inner.forward_side(frame, class)
    }

    fn forward_side_from(
        &self,
        frame: Bytes,
        class: ndn_transport::SideClass,
        ingress: FaceId,
    ) -> Result<(), ndn_transport::SideRefused> {
        self.inner.forward_side_from(frame, class, ingress)
    }
    fn side_frame_max(&self) -> usize {
        self.inner.side_frame_max()
    }

    fn set_send_mtu(&self, mtu: Option<u64>) -> Result<Option<u64>, MtuError> {
        self.inner.set_send_mtu(mtu)
    }

    fn set_persistency(&self, persistency: FacePersistency) -> Result<(), PersistencyError> {
        self.inner.set_persistency(persistency)
    }

    fn peer_credentials(&self) -> Option<PeerCredentials> {
        self.inner.peer_credentials()
    }

    /// The next packet of the link, as the plan decides what becomes of each that
    /// arrives. A single consumer (the face's own task); cancelling the future loses
    /// nothing: what is held stays held.
    async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
        let mut rx = self.rx.lock().await;
        loop {
            if let Some(frame) = rx.take_due(Instant::now()) {
                return Ok(frame);
            }
            if rx.held.is_empty()
                && let Some(ended) = rx.ended.take()
            {
                return Err(ended);
            }
            let next = rx.held.peek().map(|Reverse(h)| h.due);
            let live = rx.ended.is_none();
            // `biased`: when a held packet falls due at the instant another arrives, the
            // order they are handled in is the same every run (an unseeded RNG chose it,
            // and the plan's draws and the link's packet order followed it). Due
            // packets first, then arrivals. Neither starves the other: a due packet is
            // returned by the next pass's `take_due`, and an arrival is only taken when
            // none is due.
            tokio::select! {
                biased;
                () = tokio::time::sleep_until(next.unwrap_or_else(Instant::now)), if next.is_some() => {}
                arrived = self.inner.recv_bytes(), if live => match arrived {
                    Ok(frame) => self.arrived(&mut rx, frame),
                    Err(ended) if rx.held.is_empty() => return Err(ended),
                    Err(ended) => rx.ended = Some(ended),
                },
            }
        }
    }
}

/// What a frame is, and the name it carries, as far as a verdict cares.
fn frame_info(frame: &Bytes) -> (FaultKind, Option<Name>) {
    let Ok((t, _)) = ndn_tlv::read_varu64(frame) else {
        return (FaultKind::Other, None);
    };
    if t != LP_PACKET {
        return head(frame)
            .map(|(kind, name)| (kind, Some(name)))
            .unwrap_or((FaultKind::Other, None));
    }
    let Ok(lp) = LpPacket::decode(frame.clone()) else {
        return (FaultKind::Other, None);
    };
    let Some(fragment) = lp.fragment else {
        return (FaultKind::Other, None);
    };
    if lp.frag_index.unwrap_or(0) > 0 {
        return (FaultKind::Other, None);
    }
    match head(&fragment) {
        Some((_, name)) if lp.nack.is_some() => (FaultKind::Nack, Some(name)),
        Some((kind, name)) => (kind, Some(name)),
        None => (FaultKind::Other, None),
    }
}

/// The kind and name at the head of a network packet (or of its first fragment: the
/// Name is its first element).
fn head(packet: &[u8]) -> Option<(FaultKind, Name)> {
    let (t, tn) = ndn_tlv::read_varu64(packet).ok()?;
    let kind = match t {
        INTEREST => FaultKind::Interest,
        DATA => FaultKind::Data,
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
    use std::time::Duration;

    use ndn_faults::{FAULTY, carries_data};
    use ndn_packet::encode::{DataBuilder, InterestBuilder};
    use ndn_packet::lp::{encode_lp_nack, encode_lp_packet};
    use ndn_packet::nack::NackReason;
    use tokio::sync::mpsc;

    use super::*;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    fn interest(name: &str) -> Bytes {
        InterestBuilder::new(n(name)).build()
    }

    fn data(name: &str) -> Bytes {
        DataBuilder::new(n(name), b"content").build()
    }

    /// A transport whose arrivals the test feeds; it ends when the feed is dropped.
    struct Pipe {
        rx: Mutex<mpsc::UnboundedReceiver<Bytes>>,
    }

    impl Transport for Pipe {
        fn id(&self) -> FaceId {
            FaceId(7)
        }
        fn kind(&self) -> FaceKind {
            FaceKind::Quic
        }
        async fn send_bytes(&self, _: Bytes) -> Result<(), FaceError> {
            Ok(())
        }
        async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
            self.rx.lock().await.recv().await.ok_or(FaceError::Closed)
        }
    }

    const PEER: KeyFingerprint = KeyFingerprint([1; 32]);
    const ME: KeyFingerprint = KeyFingerprint([2; 32]);

    fn link(layer: &Arc<FaultLayer>) -> (mpsc::UnboundedSender<Bytes>, Arc<dyn ErasedTransport>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let pipe: Arc<dyn ErasedTransport> = Arc::new(Pipe { rx: Mutex::new(rx) });
        (tx, layer.wrap(pipe, PEER, Some(ME), Direction::Accepted))
    }

    fn plan(spec: &str) -> FaultPlan {
        FaultPlan::new(Faults::parse(spec).unwrap())
    }

    /// Every frame until the link ends (the feed dropped), in arrival order.
    async fn all(face: &Arc<dyn ErasedTransport>) -> Vec<Bytes> {
        let mut got = Vec::new();
        let limit = Duration::from_secs(20);
        loop {
            match tokio::time::timeout(limit, face.recv_bytes()).await {
                Ok(Ok(frame)) => got.push(frame),
                Ok(Err(_)) => return got,
                Err(_) => panic!("the link did not end within {limit:?}; got {}", got.len()),
            }
        }
    }

    /// The frames a profile makes of `frames` on the direction PEER → ME, drawn by the
    /// shared stream alone, with the totals the layer must report.
    fn expected(profile: &Faults, frames: &[Bytes]) -> (Vec<Bytes>, FaultReport) {
        let mut stream = profile.stream(end(&PEER), end(&ME));
        let mut out = Vec::new();
        let mut r = FaultReport::default();
        for frame in frames {
            let fate = stream.fate(frame.clone());
            r.met += 1;
            if fate.copies == 0 {
                r.dropped += 1;
                continue;
            }
            r.duplicated += u64::from(fate.copies > 1);
            r.forged += u64::from(fate.frame != *frame);
            r.delayed += u64::from(!fate.delay.is_zero());
            out.extend(std::iter::repeat_n(fate.frame, usize::from(fate.copies)));
        }
        (out, r)
    }

    fn sorted(mut v: Vec<Bytes>) -> Vec<Bytes> {
        v.sort();
        v
    }

    /// The conformance profile on a link: what comes out, and what is counted, is what
    /// the shared stream draws for the same packets (delays shortened to keep the case
    /// quick; the draws are the same as the shared stream's whatever the delay).
    #[tokio::test]
    async fn the_fates_are_the_shared_streams() {
        let profile = Faults {
            delay_ms: 30,
            blocks_ms: 30,
            ..Faults::parse(FAULTY).unwrap().with_seed(11)
        };
        let layer = Arc::new(FaultLayer::default());
        let (tx, face) = link(&layer);
        layer.install(FaultPlan::new(profile));
        let frames: Vec<Bytes> = (0..300)
            .map(|i| {
                if i % 3 == 0 {
                    interest(&format!("/a/{i}"))
                } else {
                    data(&format!("/a/{i}"))
                }
            })
            .collect();
        for f in &frames {
            tx.send(f.clone()).unwrap();
        }
        drop(tx);
        let got = all(&face).await;
        let (want, mut want_report) = expected(&profile, &frames);
        assert_eq!(sorted(got), sorted(want), "the frames delivered");
        let report = layer.report();
        want_report.profile = Some(profile.to_string());
        assert_eq!(report, want_report);
        assert!(report.dropped > 0 && report.forged > 0 && report.duplicated > 0);
        assert!(frames.iter().any(|f| carries_data(f)));
    }

    /// The same seed and the same packets give the same fates; another seed, others.
    #[tokio::test]
    async fn the_same_seed_is_the_same_faults() {
        async fn run(seed: u64) -> (Vec<Bytes>, FaultReport) {
            let layer = Arc::new(FaultLayer::default());
            let (tx, face) = link(&layer);
            layer.install(FaultPlan::new(
                Faults::parse("drop=0.3,dup=0.2,forge=0.3,delay=10")
                    .unwrap()
                    .with_seed(seed),
            ));
            for i in 0..100 {
                tx.send(data(&format!("/b/{i}"))).unwrap();
            }
            drop(tx);
            (sorted(all(&face).await), layer.report())
        }
        let (a, ra) = run(5).await;
        let (b, rb) = run(5).await;
        let (c, _) = run(6).await;
        assert_eq!((&a, &ra), (&b, &rb), "same seed, same faults");
        assert_ne!(a, c, "another seed, other faults");
    }

    #[tokio::test]
    async fn a_verdict_picks_the_packets_and_is_told_what_they_are() {
        let layer = Arc::new(FaultLayer::default());
        let (tx, face) = link(&layer);
        let seen = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        layer.install(plan("drop=1").verdict(move |f| {
            log.lock()
                .push((f.kind, f.name.clone(), f.len, f.direction));
            if f.kind == FaultKind::Data
                && f.name.as_ref().is_some_and(|nm| nm.has_prefix(&n("/keep")))
            {
                FaultVerdict::Profile
            } else {
                FaultVerdict::Pass
            }
        }));
        let frames = [
            interest("/keep/i"),
            data("/keep/d"),
            data("/other/d"),
            encode_lp_packet(&data("/keep/lp")),
            encode_lp_nack(NackReason::NoRoute, &interest("/keep/n")),
            encode_lp_packet(&Bytes::new()),
            Bytes::from_static(b"\x00\x01"),
        ];
        for f in &frames {
            tx.send(f.clone()).unwrap();
        }
        drop(tx);
        let got = all(&face).await;
        // Only the two `/keep` Data (bare, and in an LP packet) were chosen, and
        // dropped (drop=1); every other frame came out untouched and in order.
        let kept: Vec<Bytes> = vec![
            frames[0].clone(),
            frames[2].clone(),
            frames[4].clone(),
            frames[5].clone(),
            frames[6].clone(),
        ];
        assert_eq!(got, kept);
        let report = layer.report();
        assert_eq!((report.met, report.dropped, report.passed), (2, 2, 5));
        let seen = seen.lock();
        let kinds: Vec<FaultKind> = seen.iter().map(|s| s.0).collect();
        assert_eq!(
            kinds,
            [
                FaultKind::Interest,
                FaultKind::Data,
                FaultKind::Data,
                FaultKind::Data,
                FaultKind::Nack,
                FaultKind::Other,
                FaultKind::Other
            ]
        );
        assert_eq!(seen[0].1, Some(n("/keep/i")));
        assert_eq!(seen[2].1, Some(n("/other/d")));
        assert_eq!(
            seen[4].1,
            Some(n("/keep/n")),
            "a Nack carries its Interest's name"
        );
        assert_eq!(seen[5].1, None);
        assert_eq!(seen[1].2, frames[1].len());
        assert!(seen.iter().all(|s| s.3 == Direction::Accepted));
    }

    #[tokio::test]
    async fn a_verdict_that_panics_leaves_the_packet_alone_and_is_counted() {
        let layer = Arc::new(FaultLayer::default());
        let (tx, face) = link(&layer);
        layer.install(plan("drop=1").verdict(|_| panic!("a host bug")));
        let f = data("/p");
        tx.send(f.clone()).unwrap();
        drop(tx);
        assert_eq!(all(&face).await, vec![f]);
        let r = layer.report();
        assert_eq!((r.predicate_panics, r.met, r.dropped), (1, 0, 0));
    }

    /// The verdict of the tests below: `/drop` is discarded, `/pass` delivered
    /// untouched, everything else meets the profile.
    fn by_prefix(f: &FaultFrame) -> FaultVerdict {
        match &f.name {
            Some(nm) if nm.has_prefix(&n("/drop")) => FaultVerdict::Drop,
            Some(nm) if nm.has_prefix(&n("/pass")) => FaultVerdict::Pass,
            _ => FaultVerdict::Profile,
        }
    }

    /// `Drop` discards, `Pass` delivers untouched, `Profile` applies the profile, and each is
    /// counted where the spec says: the verdict's drops share `dropped` with the profile's,
    /// and a frame the verdict dropped or passed never met the profile.
    #[tokio::test]
    async fn a_verdict_drops_passes_or_hands_to_the_profile() {
        let layer = Arc::new(FaultLayer::default());
        let (tx, face) = link(&layer);
        layer.install(plan("dup=1").verdict(by_prefix));
        let dropped = [data("/drop/1"), interest("/drop/2"), data("/drop/3")];
        let passed = [data("/pass/1"), interest("/pass/2")];
        let profiled = [data("/x/1"), data("/x/2"), data("/x/3"), data("/x/4")];
        for f in dropped.iter().chain(&passed).chain(&profiled) {
            tx.send(f.clone()).unwrap();
        }
        drop(tx);
        let got = all(&face).await;
        for f in &dropped {
            assert!(!got.contains(f), "a dropped frame was delivered");
        }
        for f in &passed {
            assert_eq!(
                got.iter().filter(|g| *g == f).count(),
                1,
                "pass: once, untouched"
            );
        }
        for f in &profiled {
            assert_eq!(got.iter().filter(|g| *g == f).count(), 2, "dup=1: twice");
        }
        let r = layer.report();
        assert_eq!(
            (r.met, r.dropped, r.duplicated, r.passed),
            (4, 3, 4, 2),
            "{r:?}"
        );
    }

    /// Same seed, same fates: a frame that is dropped or passed draws nothing from the
    /// stream, so what the profile does to the frames that meet it does not depend on how
    /// many others were dropped or passed between them.
    #[tokio::test]
    async fn dropped_and_passed_frames_draw_nothing() {
        let profile = Faults::parse("drop=0.3,dup=0.2,forge=0.3")
            .unwrap()
            .with_seed(77);
        let profiled: Vec<Bytes> = (0..120).map(|i| data(&format!("/x/{i}"))).collect();
        async fn run(profile: Faults, frames: Vec<Bytes>) -> (Vec<Bytes>, FaultReport) {
            let layer = Arc::new(FaultLayer::default());
            let (tx, face) = link(&layer);
            layer.install(FaultPlan::new(profile).verdict(by_prefix));
            for f in frames {
                tx.send(f).unwrap();
            }
            drop(tx);
            (all(&face).await, layer.report())
        }
        let (alone, alone_report) = run(profile, profiled.clone()).await;
        // The same profiled frames, with a run of dropped and passed ones before each.
        let mut between = Vec::new();
        let mut extra_dropped = 0u64;
        let mut extra_passed = 0u64;
        for (i, f) in profiled.iter().enumerate() {
            for j in 0..(i % 4) {
                between.push(data(&format!("/drop/{i}/{j}")));
                extra_dropped += 1;
            }
            if i % 3 == 0 {
                between.push(interest(&format!("/pass/{i}")));
                extra_passed += 1;
            }
            between.push(f.clone());
        }
        let (mixed, mixed_report) = run(profile, between).await;
        let passed: Vec<Bytes> = mixed
            .iter()
            .filter(|g| frame_info(g).1.is_some_and(|nm| nm.has_prefix(&n("/pass"))))
            .cloned()
            .collect();
        assert_eq!(passed.len() as u64, extra_passed);
        let at_profile: Vec<Bytes> = mixed
            .iter()
            .filter(|g| frame_info(g).1.is_some_and(|nm| nm.has_prefix(&n("/x"))))
            .cloned()
            .collect();
        assert_eq!(
            at_profile, alone,
            "the profile's fates, in order, are the same"
        );
        assert!(alone_report.dropped > 0 && alone_report.forged > 0 && alone_report.duplicated > 0);
        assert_eq!(
            FaultReport {
                dropped: mixed_report.dropped - extra_dropped,
                passed: mixed_report.passed - extra_passed,
                ..mixed_report.clone()
            },
            alone_report,
            "the same counters but for the frames dropped and passed"
        );
        assert_eq!(mixed_report.dropped, alone_report.dropped + extra_dropped);
        assert_eq!(mixed_report.passed, extra_passed);
    }

    /// A plan installed after a link is up applies to its next packets; clearing it
    /// ends that; a plan replaced starts its counters and draws again.
    #[tokio::test]
    async fn a_plan_applies_to_links_already_up() {
        let layer = Arc::new(FaultLayer::default());
        let (tx, face) = link(&layer);
        assert_eq!(layer.report(), FaultReport::default());
        let first = data("/first");
        tx.send(first.clone()).unwrap();
        assert_eq!(face.recv_bytes().await.unwrap(), first, "no plan, no fault");
        layer.install(plan("drop=1"));
        tx.send(data("/lost")).unwrap();
        // The packet is read at once (the first poll takes what has arrived) and met
        // the plan; nothing comes out.
        let nothing = tokio::time::timeout(Duration::from_millis(50), face.recv_bytes()).await;
        assert!(nothing.is_err(), "a dropped packet is not delivered");
        let r = layer.report();
        assert_eq!((r.met, r.dropped), (1, 1));
        layer.clear();
        assert_eq!(layer.report(), FaultReport::default());
        let second = data("/second");
        tx.send(second.clone()).unwrap();
        assert_eq!(face.recv_bytes().await.unwrap(), second);
        // A plan installed again starts its counters at zero.
        layer.install(plan("dup=1"));
        assert_eq!(layer.report().met, 0);
        drop(tx);
        assert!(all(&face).await.is_empty());
    }

    /// A link that ends delivers what it holds first, then says it ended.
    #[tokio::test]
    async fn held_packets_are_delivered_before_the_end_of_the_link() {
        let layer = Arc::new(FaultLayer::default());
        let (tx, face) = link(&layer);
        layer.install(plan("delay=40,reorder=1"));
        for i in 0..5 {
            tx.send(interest(&format!("/h/{i}"))).unwrap();
        }
        drop(tx);
        let got = all(&face).await;
        assert_eq!(got.len(), 5);
        assert!(matches!(face.recv_bytes().await, Err(FaceError::Closed)));
    }

    #[test]
    fn a_frame_is_told_apart_by_its_kind_and_name() {
        let (k, nm) = frame_info(&interest("/x/y"));
        assert_eq!((k, nm), (FaultKind::Interest, Some(n("/x/y"))));
        let (k, nm) = frame_info(&encode_lp_packet(&data("/x/z")));
        assert_eq!((k, nm), (FaultKind::Data, Some(n("/x/z"))));
        assert_eq!(frame_info(&Bytes::new()), (FaultKind::Other, None));
    }

    #[test]
    fn the_ends_of_a_direction_are_the_first_bytes_of_the_keys() {
        let mut a = [0u8; 32];
        a[7] = 9;
        assert_eq!(end(&KeyFingerprint(a)), 9);
    }

    /// What records the side path: what `send_side` and `forward_side` were given,
    /// what `side_frame_max` answers, and a feed of arrivals.
    struct SideSpy {
        rx: Mutex<mpsc::UnboundedReceiver<Bytes>>,
        sent: parking_lot::Mutex<Vec<(Bytes, ndn_transport::SideClass)>>,
        forwarded: parking_lot::Mutex<Vec<(Bytes, ndn_transport::SideClass)>>,
        ingressed: parking_lot::Mutex<Vec<(Bytes, FaceId)>>,
    }

    impl Transport for SideSpy {
        fn id(&self) -> FaceId {
            FaceId(8)
        }
        fn kind(&self) -> FaceKind {
            FaceKind::Quic
        }
        async fn send_bytes(&self, _: Bytes) -> Result<(), FaceError> {
            panic!("a side frame must not go through send_bytes of the wrapper");
        }
        async fn send_side(
            &self,
            frame: Bytes,
            class: ndn_transport::SideClass,
        ) -> Result<(), ndn_transport::SideRefused> {
            self.sent.lock().push((frame, class));
            Ok(())
        }
        fn forward_side(
            &self,
            frame: Bytes,
            class: ndn_transport::SideClass,
        ) -> Result<(), ndn_transport::SideRefused> {
            self.forwarded.lock().push((frame, class));
            Err(ndn_transport::SideRefused::Full)
        }
        fn forward_side_from(
            &self,
            frame: Bytes,
            _class: ndn_transport::SideClass,
            ingress: FaceId,
        ) -> Result<(), ndn_transport::SideRefused> {
            self.ingressed.lock().push((frame, ingress));
            Ok(())
        }
        fn side_frame_max(&self) -> usize {
            1234
        }
        async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
            self.rx.lock().await.recv().await.ok_or(FaceError::Closed)
        }
    }

    /// The fault layer leaves the side path of the link alone on send (as it leaves
    /// `send_bytes`: the peer's layer meets what arrives) and hands the inner
    /// face's answers through; a marked frame that ARRIVES meets the profile like
    /// every other frame, with the shared stream's fates.
    #[tokio::test]
    async fn the_side_path_is_the_links_and_arrivals_meet_the_profile() {
        use ndn_transport::{SIDE_MARKER, SideClass, SideRefused};

        let (feed, rx) = mpsc::unbounded_channel();
        let spy = Arc::new(SideSpy {
            rx: Mutex::new(rx),
            sent: parking_lot::Mutex::new(Vec::new()),
            forwarded: parking_lot::Mutex::new(Vec::new()),
            ingressed: parking_lot::Mutex::new(Vec::new()),
        });
        let layer = Arc::new(FaultLayer::default());
        let inner: Arc<dyn ErasedTransport> = spy.clone();
        let face = layer.wrap(inner, PEER, Some(ME), Direction::Accepted);
        let profile = Faults::parse("drop=0.5,dup=0.3,delay=5")
            .unwrap()
            .with_seed(3);
        layer.install(FaultPlan::new(profile));

        // Send: even a plan that drops half of what arrives touches nothing sent.
        let frame = |i: u8| Bytes::from(vec![SIDE_MARKER, 0x20, i, i, i]);
        for (i, class) in [SideClass::Datagram, SideClass::Stream]
            .into_iter()
            .enumerate()
        {
            face.send_side(frame(i as u8), class).await.unwrap();
        }
        assert_eq!(
            *spy.sent.lock(),
            vec![
                (frame(0), SideClass::Datagram),
                (frame(1), SideClass::Stream)
            ]
        );
        assert_eq!(
            face.forward_side(frame(2), SideClass::Datagram),
            Err(SideRefused::Full),
            "the inner face's refusal comes through"
        );
        assert_eq!(*spy.forwarded.lock(), vec![(frame(2), SideClass::Datagram)]);
        assert_eq!(face.side_frame_max(), 1234);
        // The forwarder says which face a frame came over: the layer passes that on.
        face.forward_side_from(frame(3), SideClass::Datagram, FaceId(5))
            .unwrap();
        assert_eq!(
            *spy.ingressed.lock(),
            vec![(frame(3), FaceId(5))],
            "the ingress face reaches the inner face"
        );
        assert_eq!(layer.report().met, 0, "nothing sent met the profile");

        // Arrivals: marked frames get the fates the shared stream draws.
        let frames: Vec<Bytes> = (0..200).map(|i| frame(i as u8)).collect();
        for f in &frames {
            feed.send(f.clone()).unwrap();
        }
        drop(feed);
        let got = all(&face).await;
        let (want, want_report) = expected(&profile, &frames);
        assert_eq!(sorted(got), sorted(want), "the marked frames delivered");
        assert_eq!(layer.report().met, want_report.met);
        assert!(want_report.dropped > 0 && want_report.duplicated > 0);
    }
}
