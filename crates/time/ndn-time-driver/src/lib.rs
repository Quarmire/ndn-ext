//! Live driver for named-time — the I/O layer that stands the sans-IO
//! [`Timekeeper`](ndn_timekeeper::Timekeeper) up on a real transport.
//!
//! The `ndn-time` core and [`ndn_timekeeper`] are pure state machines: they combine samples,
//! discipline a clock, and *say* what to publish, but touch no hardware. This crate is the driver
//! the [named-time status] called missing — it composes the Timekeeper with four pluggable I/O
//! seams so the whole pipeline runs for real:
//!
//! - [`BeaconTransport`] — send/receive opaque beacon bytes. A monitor-wifi face's
//!   `send_bytes`/`recv_bytes` implements it; [`Loopback`] implements it in-memory for tests.
//! - [`BeaconAuth`] — seal an outbound beacon into a signed wire object and, crucially, **only
//!   return verified inbound ones** (the `SafeData` discipline: unauthenticated time can never
//!   reach [`ingest_beacon`](ndn_timekeeper::Timekeeper::ingest_beacon)). A real impl wraps an NDN
//!   `Signer`/`Validator`; [`DevAuth`] is an unsigned stand-in for bring-up/tests.
//! - `TimeSource`s ([`ndn_time_sources`]) — the local clocks, polled each round.
//! - [`ClockSink`] — where the disciplined `clock_ms` estimate lands (a `NodeSignals` writer in
//!   production; [`RecordingClock`] captures it for tests).
//!
//! [`TimeService`] wires these and exposes both the composable steps ([`TimeService::ingest_once`],
//! [`TimeService::discipline_once`] — deterministic, unit-testable) and an async [`TimeService::run`]
//! loop for deployment. Swapping [`Loopback`] for a monitor-wifi transport is all it takes to run
//! on-air.
//!
//! [named-time status]: https://example.invalid/named-time#status

#![deny(missing_docs)]

use async_trait::async_trait;
use bytes::Bytes;
use ndn_time::{
    Authenticity, ClockCapability, Discipline, KeyId, MeasurementProvenance, PathId, TimePolicy,
};
use ndn_time_sources::TimeSource;
use ndn_timekeeper::{beacon_wire, Timekeeper};
use std::sync::Mutex;

/// A peer beacon that has passed [`BeaconAuth::open`] — only these reach the Timekeeper.
pub struct VerifiedBeacon {
    /// The peer's node id (the authority that signed it).
    pub peer_id: u64,
    /// The beacon-wire payload (feed to [`beacon_wire::decode`]).
    pub content: Bytes,
    /// What verification established about this reception (authenticity, replay, distance).
    pub prov: MeasurementProvenance,
}

/// Seals outbound beacons and verifies inbound ones. The gate that keeps unauthenticated time out
/// of the discipline loop — the driver only ever ingests what [`open`](Self::open) returns.
pub trait BeaconAuth: Send + Sync {
    /// Wrap a beacon `payload` (from [`beacon_wire::encode`]) into a signed wire object — an NDN
    /// Data under `/<scope>/time/<node_id>/<seq>` in production.
    fn seal(&self, node_id: u64, seq: u64, payload: &[u8]) -> Bytes;

    /// Verify a wire object and return the peer beacon inside, or `None` if it fails validation
    /// (bad signature, untrusted key, replay). Returning `None` is the `SafeData` floor.
    fn open(&self, wire: &[u8]) -> Option<VerifiedBeacon>;
}

/// A byte pipe for beacons — the driver is agnostic to whether it is a monitor-wifi broadcast, an
/// SVS group, or an in-memory [`Loopback`].
#[async_trait]
pub trait BeaconTransport: Send + Sync {
    /// Broadcast one sealed beacon. Returns whether it was accepted for transmission.
    async fn send(&self, wire: Bytes) -> bool;

    /// Receive the next beacon wire object, or `None` when the transport is closed.
    async fn recv(&self) -> Option<Bytes>;
}

/// Where the disciplined wall-clock estimate lands. A `NodeSignals` writer in production
/// (`set_node` with `clock_ms`); [`RecordingClock`] for tests.
pub trait ClockSink: Send + Sync {
    /// Publish the current disciplined wall-clock estimate in **milliseconds** since the Unix
    /// epoch (the `NodeSignals.clock_ms` currency).
    fn set_clock_ms(&self, ms: i64);
}

/// The live named-time service: a [`Timekeeper`] wired to sources, a transport, auth, and a clock
/// sink. Compose it, then either drive it a step at a time or [`run`](Self::run) it.
pub struct TimeService {
    node_id: u64,
    tk: Mutex<Timekeeper>,
    sources: Mutex<Vec<Box<dyn TimeSource + Send>>>,
    /// Latest local wall estimate (center ns) — the value being disciplined by `tick`.
    last_wall_ns: Mutex<i64>,
    transport: std::sync::Arc<dyn BeaconTransport>,
    auth: std::sync::Arc<dyn BeaconAuth>,
    clock: std::sync::Arc<dyn ClockSink>,
    /// This node's own clock capability, stamped into every outbound heartbeat beacon.
    local_cap: ClockCapability,
    /// Monotone sequence for outbound heartbeat beacons.
    beacon_seq: std::sync::atomic::AtomicU64,
    /// Count of inbound beacons that passed auth and were fed to the loop — lets a driver observe
    /// that peer time is actually crossing the link (e.g. on-air 2-node convergence).
    peer_ingests: std::sync::atomic::AtomicU64,
}

impl TimeService {
    /// How many inbound peer beacons have passed [`BeaconAuth::open`] and been ingested so far.
    pub fn peer_ingests(&self) -> u64 {
        self.peer_ingests.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Build a service for `node_id` with its `self_key`, local clock `cap`ability and `policy`,
    /// over the given `sources`, `transport`, `auth`, and `clock` sink.
    #[allow(clippy::too_many_arguments)] // a composition root: each seam is an explicit dependency
    pub fn new(
        node_id: u64,
        self_key: KeyId,
        cap: ClockCapability,
        policy: TimePolicy,
        sources: Vec<Box<dyn TimeSource + Send>>,
        transport: std::sync::Arc<dyn BeaconTransport>,
        auth: std::sync::Arc<dyn BeaconAuth>,
        clock: std::sync::Arc<dyn ClockSink>,
    ) -> Self {
        Self {
            node_id,
            tk: Mutex::new(Timekeeper::new(node_id, self_key, cap, policy)),
            sources: Mutex::new(sources),
            last_wall_ns: Mutex::new(0),
            transport,
            auth,
            clock,
            local_cap: cap,
            beacon_seq: std::sync::atomic::AtomicU64::new(0),
            peer_ingests: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Verify + decode + ingest one inbound beacon wire object, anchored to our reception
    /// monotonic time `now_mono_ns`. Returns `true` if it passed auth and was fed to the loop.
    pub fn ingest_once(&self, now_mono_ns: u64, wire: &[u8]) -> bool {
        let Some(vb) = self.auth.open(wire) else {
            return false; // failed validation — the SafeData floor
        };
        let Some(dec) = beacon_wire::decode(&vb.content) else {
            return false;
        };
        let beacon = dec.into_beacon(now_mono_ns, vb.prov);
        self.tk.lock().unwrap().ingest_beacon(vb.peer_id, &beacon);
        self.peer_ingests
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        true
    }

    /// Poll the local sources, run one discipline pass at monotonic time `now_mono_ns`, push any
    /// disciplined `clock_ms` to the sink, and return a **sealed** outbound beacon to broadcast if
    /// the fix tightened enough to be worth sharing.
    pub fn discipline_once(&self, now_mono_ns: u64) -> Option<Bytes> {
        // SENSE: fold in each local source; remember the latest wall being disciplined.
        {
            let mut srcs = self.sources.lock().unwrap();
            let mut tk = self.tk.lock().unwrap();
            let mut wall = self.last_wall_ns.lock().unwrap();
            for src in srcs.iter_mut() {
                if let Some(r) = src.poll() {
                    *wall = r.wall.center_ns;
                    tk.ingest_local_reading(&r);
                }
            }
        }
        let local_wall = *self.last_wall_ns.lock().unwrap();
        // DECIDE + ACT.
        let out = self.tk.lock().unwrap().tick(now_mono_ns, local_wall);
        if let Some(ms) = out.clock_ms {
            self.clock.set_clock_ms(ms);
        }
        let _ = discipline_label(&out.discipline); // hook for a real clock-steering call
        // Heartbeat: whenever we hold a usable fix, beacon the *current* estimate every tick — not
        // only when it tightens (`out.beacon`). A broadcast time source must be continuously
        // present, or a peer that joins late (or after a loss) never hears it.
        out.clock_ms.map(|_| {
            let seq = self
                .beacon_seq
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let wall = local_wall + out.correction.offset_ns;
            let payload =
                beacon_wire::encode(seq, wall, out.correction.uncertainty_ns, &self.local_cap);
            self.auth.seal(self.node_id, seq, &payload)
        })
    }

    /// Run the service until the transport closes: a receive loop feeding
    /// [`ingest_once`](Self::ingest_once), and a `cadence` loop driving
    /// [`discipline_once`](Self::discipline_once) and broadcasting beacons. Monotonic time is taken
    /// from a process-start [`Instant`](std::time::Instant).
    pub async fn run(self: std::sync::Arc<Self>, cadence: std::time::Duration) {
        let start = std::time::Instant::now();
        // Ingest task: verify + feed every inbound beacon as it arrives.
        let ingest = std::sync::Arc::clone(&self);
        tokio::spawn(async move {
            while let Some(wire) = ingest.transport.recv().await {
                let mono = start.elapsed().as_nanos() as u64;
                ingest.ingest_once(mono, &wire);
            }
        });
        // Discipline loop: poll sources, tick, and broadcast a beacon on the cadence.
        loop {
            tokio::time::sleep(cadence).await;
            let mono = start.elapsed().as_nanos() as u64;
            if let Some(wire) = self.discipline_once(mono) {
                self.transport.send(wire).await;
            }
        }
    }
}

/// A short label for a [`Discipline`] action — the seam where a real driver would call the host
/// clock-steering interface (adjtimex slew / step) instead of logging.
fn discipline_label(d: &Discipline) -> &'static str {
    match d {
        Discipline::Step { .. } => "step",
        Discipline::Slew { .. } => "slew",
        Discipline::Track { .. } => "track",
        Discipline::Withhold { .. } => "withhold",
    }
}

// ---------------------------------------------------------------------------
// Bring-up / test kit: an in-memory transport, an unsigned auth, and a recording clock sink.
// These make the wiring runnable and unit-testable without a radio or a keychain.
// ---------------------------------------------------------------------------

/// An unsigned [`BeaconAuth`] for bring-up and tests. It frames the payload with the node id and
/// marks receptions as authenticated-domain-peer so they are admitted — **not** for production
/// (there is no real signature; swap in an NDN `Signer`/`Validator`-backed impl on real links).
pub struct DevAuth;

impl BeaconAuth for DevAuth {
    fn seal(&self, node_id: u64, _seq: u64, payload: &[u8]) -> Bytes {
        let mut w = Vec::with_capacity(8 + payload.len());
        w.extend_from_slice(&node_id.to_be_bytes());
        w.extend_from_slice(payload);
        Bytes::from(w)
    }

    fn open(&self, wire: &[u8]) -> Option<VerifiedBeacon> {
        if wire.len() < 8 {
            return None;
        }
        let peer_id = u64::from_be_bytes(wire[..8].try_into().ok()?);
        Some(VerifiedBeacon {
            peer_id,
            content: Bytes::copy_from_slice(&wire[8..]),
            prov: MeasurementProvenance {
                distance_bounded: false,
                replay_protected: true,
                authenticity: Authenticity::AuthenticatedDomainPeer(KeyId(peer_id)),
                path: PathId(peer_id as u32 + 1),
            },
        })
    }
}

/// A [`ClockSink`] that records the latest `clock_ms` — proves the ACT path writes, and lets a test
/// read the disciplined estimate.
#[derive(Default)]
pub struct RecordingClock {
    last: Mutex<Option<i64>>,
}

impl RecordingClock {
    /// A fresh sink with no value yet.
    pub fn new() -> Self {
        Self::default()
    }
    /// The most recent `clock_ms` written, if any.
    pub fn last_ms(&self) -> Option<i64> {
        *self.last.lock().unwrap()
    }
}

impl ClockSink for RecordingClock {
    fn set_clock_ms(&self, ms: i64) {
        *self.last.lock().unwrap() = Some(ms);
    }
}

/// An in-memory [`BeaconTransport`] pair for tests: two endpoints where each [`send`](BeaconTransport::send)
/// is delivered to the *other* endpoint's [`recv`](BeaconTransport::recv) (broadcast between two peers).
pub struct Loopback {
    tx: tokio::sync::mpsc::UnboundedSender<Bytes>,
    rx: tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<Bytes>>,
}

impl Loopback {
    /// Create a connected pair of loopback endpoints (a's sends arrive at b's recv and vice-versa).
    pub fn pair() -> (Loopback, Loopback) {
        let (a_tx, b_rx) = tokio::sync::mpsc::unbounded_channel();
        let (b_tx, a_rx) = tokio::sync::mpsc::unbounded_channel();
        (
            Loopback {
                tx: a_tx,
                rx: tokio::sync::Mutex::new(a_rx),
            },
            Loopback {
                tx: b_tx,
                rx: tokio::sync::Mutex::new(b_rx),
            },
        )
    }
}

#[async_trait]
impl BeaconTransport for Loopback {
    async fn send(&self, wire: Bytes) -> bool {
        self.tx.send(wire).is_ok()
    }
    async fn recv(&self) -> Option<Bytes> {
        self.rx.lock().await.recv().await
    }
}

/// (feature `wifi`) The on-air bridge — a [`BeaconTransport`] over a monitor-wifi face's `FrameIo`.
#[cfg(feature = "wifi")]
pub mod wifi {
    use super::BeaconTransport;
    use async_trait::async_trait;
    use bytes::Bytes;
    use ndn_frame_io::{FrameIo, InjectFrame, BROADCAST, DEFAULT_SRC, TxIntent};
    use std::sync::Arc;

    /// A [`BeaconTransport`] over any [`FrameIo`] radio (e.g. a monitor-wifi face). Each beacon is a
    /// most-robust broadcast 802.11 frame carrying the sealed beacon as its payload; `recv` yields
    /// the next frame's payload (non-beacon traffic is dropped upstream by `BeaconAuth::open`).
    /// Swapping [`Loopback`](super::Loopback) for this is all it takes to run the service on-air.
    pub struct FrameIoTransport {
        radio: Arc<dyn FrameIo>,
    }

    impl FrameIoTransport {
        /// Wrap a radio backend (a `MonitorWifiFace` / `Rtl8733buBackend` / `LibUsbRtl88xxBackend`).
        pub fn new(radio: Arc<dyn FrameIo>) -> Self {
            Self { radio }
        }
    }

    #[async_trait]
    impl BeaconTransport for FrameIoTransport {
        async fn send(&self, wire: Bytes) -> bool {
            self.radio
                .inject(InjectFrame {
                    payload: wire,
                    tx: TxIntent::ROBUST,
                    dst: BROADCAST,
                    src: DEFAULT_SRC,
                })
                .await
                .is_ok()
        }
        async fn recv(&self) -> Option<Bytes> {
            self.radio.recv_frame().await.ok().map(|f| f.payload)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_time::TimeInterval;
    use ndn_time_sources::Reading;
    use std::sync::Arc;

    /// A clock source with a fixed wall + uncertainty and an incrementing monotonic capture — lets
    /// a test inject a known offset between two nodes.
    struct FixedSource {
        wall_ns: i64,
        unc_ns: u64,
        cap: ClockCapability,
        mono: u64,
    }
    impl TimeSource for FixedSource {
        fn poll(&mut self) -> Option<Reading> {
            self.mono += 1_000_000_000; // 1 s per poll, for the skew regression's x-axis
            Some(Reading {
                wall: TimeInterval::new(self.wall_ns, self.unc_ns),
                cap: self.cap,
                captured_mono_ns: self.mono,
            })
        }
        fn label(&self) -> &'static str {
            "fixed"
        }
    }

    fn service(
        id: u64,
        wall_ns: i64,
        unc_ns: u64,
        cap: ClockCapability,
        transport: Arc<dyn BeaconTransport>,
        clock: Arc<RecordingClock>,
    ) -> TimeService {
        TimeService::new(
            id,
            KeyId(id),
            cap,
            TimePolicy::default(),
            vec![Box::new(FixedSource {
                wall_ns,
                unc_ns,
                cap,
                mono: 0,
            })],
            transport,
            Arc::new(DevAuth),
            clock,
        )
    }

    // ~year-2001 Unix ns; B is offset +50 ms with a wide (200 ms) self-uncertainty that contains A.
    const T: i64 = 1_000_000_000_000_000_000;
    const OFFSET_NS: i64 = 50_000_000;

    #[test]
    fn beacon_flows_and_disciplines_toward_reference() {
        let (la, lb) = Loopback::pair();
        let (ca, cb) = (Arc::new(RecordingClock::new()), Arc::new(RecordingClock::new()));
        // A: reference — tight 1 ms clock at T. B: 200 ms-uncertain clock at T + 50 ms.
        let a = service(0, T, 1_000_000, ClockCapability::gnss_disciplined(), Arc::new(la), ca.clone());
        let b = service(1, T + OFFSET_NS, 200_000_000, ClockCapability::oscillator_tcxo(), Arc::new(lb), cb.clone());

        // Drive rounds directly (deterministic): A beacons, B ingests + disciplines.
        let mut mono = 0u64;
        let mut b_admitted = false;
        for _ in 0..12 {
            mono += 1_000_000_000;
            if let Some(wire) = a.discipline_once(mono) {
                // A's sealed beacon reaches B (the loopback delivers a->b; drive it directly here).
                b_admitted |= b.ingest_once(mono, &wire);
            }
            let _ = b.discipline_once(mono);
        }

        assert!(b_admitted, "B never admitted A's beacon (transport+auth+decode path)");
        let b_ms = cb.last_ms().expect("B never wrote clock_ms (ACT path)");
        let truth_ms = T / 1_000_000;
        let raw_ms = (T + OFFSET_NS) / 1_000_000;
        // B's disciplined estimate is far closer to A's truth than its own raw offset clock.
        let disc_err = (b_ms - truth_ms).abs();
        let raw_err = (raw_ms - truth_ms).abs();
        assert!(
            disc_err < raw_err / 2,
            "B did not converge: disciplined err {disc_err} ms vs raw {raw_err} ms"
        );
    }

    #[tokio::test]
    async fn run_loop_sends_and_receives_over_loopback() {
        // Smoke-test the async run() wiring: A runs, B ingests what arrives over the real Loopback.
        let (la, lb) = Loopback::pair();
        let ca = Arc::new(RecordingClock::new());
        let a = Arc::new(service(0, T, 1_000_000, ClockCapability::gnss_disciplined(), Arc::new(la), ca));
        let lb = Arc::new(lb);
        let a2 = a.clone();
        tokio::spawn(async move { a2.run(std::time::Duration::from_millis(20)).await });
        // B just listens on the raw transport and confirms a sealed beacon arrives + opens.
        let got = tokio::time::timeout(std::time::Duration::from_secs(2), lb.recv())
            .await
            .ok()
            .flatten();
        let wire = got.expect("no beacon arrived over the loopback");
        assert!(DevAuth.open(&wire).is_some(), "beacon did not verify");
    }
}
