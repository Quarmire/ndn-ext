//! **The medium is the face.** A single NDN [`Face`] over the *wireless medium*,
//! backed by one or more **radio capabilities** — not one face per radio.
//!
//! Wired connectivity is point-to-point: a UDP/TCP/serial face *is* a link to one
//! peer, so "one face per connection" is right. Wireless is not that. A broadcast
//! transmission reaches every neighbour in range at once, and a node may reach that
//! same neighbourhood through *several* radios (a 5 GHz Wi-Fi monitor NIC, a HaLow
//! sub-GHz NIC, a LoRa modem, …). The medium — the shared air — is the face; each
//! radio is an **added capability** the node has for reaching it, not a separate
//! network face with its own FIB entry and its own PIT.
//!
//! [`RadioMediumFace`] is that: it owns a set of [`RadioBearer`]s (each a
//! [`WifiRadio`] driver + its declared [`RadioCapability`] + the per-radio
//! [`TxParams`] cell the cognitive control plane actuates), and presents them to
//! the engine as **one** face:
//!
//! - **RX is a union.** A reader task per radio feeds one inbound stream, so a
//!   packet heard on *any* capability is delivered once to the engine. Per-frame
//!   RSSI/rate flow to the [`SignalStore`] keyed by the medium face id, closing the
//!   sense→decide loop exactly as the single-radio face does.
//! - **TX fans out.** Each outbound frame is injected on every bearer at that
//!   bearer's decided rate ([`TxParams`] from the control plane, robust default
//!   otherwise). On a broadcast medium, replicating one frame across radios *is*
//!   spatial/frequency diversity. With one bearer this collapses to exactly the
//!   [`MonitorWifiFace`](crate::MonitorWifiFace) behaviour.
//!
//! The cognitive plane ([`RadioControl`](crate::RadioControl)) is already
//! medium-shaped — it holds a `MediumState` of *N* registered radios and decides a
//! `RadioPlan` that allocates a transmission across them. This face is the data
//! plane that matches it. Adding LoRa/BLE/HaLow later is *"register another
//! capability,"* never *"stand up another face."*
//!
//! v1 scope: broadcast addressing and diversity fan-out (every allocated bearer
//! transmits). The plan-driven *primary-vs-replica* refinement (transmit on the
//! subset the `RadioPlan` selects, honouring per-radio channel) and the name-group
//! / link-FEC / A-MSDU features of [`MonitorWifiFace`] are follow-ups; the
//! abstraction (one face, N capabilities, union RX, fan-out TX) is complete here.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use ndn_coding::link_fec_bridge::{FrameIoSink, LinkFecBridge};
use tokio::sync::{Mutex as AsyncMutex, mpsc};
use tokio::task::JoinHandle;

use crate::RadioControl;
use ndn_radio_cognition::{NameContext, RadioActuators, RadioAllocation, RadioError};
use ndn_signals_core::{LinkSignals, NodeSignals, SignalStore, SignalView};
use ndn_transport::link_service::{LinkServiceFeature, LpLinkService};
use ndn_transport::{
    Face, FaceAddr, FaceKind, FacePersistency, LinkType, MtuError, PersistencyError, Transport,
};

use crate::{
    Bandwidth, BROADCAST, CapturedFrame, DbmRange, DEFAULT_SRC, FaceError, FaceId, FrameIo,
    InjectFrame,
    McsDescriptor, MONITOR_MTU, RadioCapability, RadioKnobs, Reliability, TxIntent, WifiRadio,
    mcs_phy_rate_bps,
};

/// `Arc<dyn FrameIo>` as a concrete `FrameIo` — the link-FEC [`FrameIoSink`] takes an
/// owned `R: FrameIo`, and a `dyn` handle needs this thin forwarder.
struct ArcRadio(Arc<dyn FrameIo>);

#[async_trait]
impl FrameIo for ArcRadio {
    async fn inject(&self, frame: InjectFrame) -> Result<(), FaceError> {
        self.0.inject(frame).await
    }
    async fn recv_frame(&self) -> Result<CapturedFrame, FaceError> {
        self.0.recv_frame().await
    }
    fn set_rate(&self, mcs: McsDescriptor) -> Result<(), FaceError> {
        self.0.set_rate(mcs)
    }
}

/// Measures **residual** frame loss on the delivered (post-FEC) stream via LP
/// sequence gaps — the signal cognition drives link-FEC redundancy from (raise R
/// until residual → 0, back it off when clean). Cumulative; [`ratio`](Self::ratio)
/// is `gaps / (gaps + delivered)`.
pub struct LossMeter {
    last_seq: AtomicU64, // u64::MAX = unset
    delivered: AtomicU64,
    gaps: AtomicU64,
}

impl Default for LossMeter {
    fn default() -> Self {
        Self {
            last_seq: AtomicU64::new(u64::MAX),
            delivered: AtomicU64::new(0),
            gaps: AtomicU64::new(0),
        }
    }
}

impl LossMeter {
    /// Fold one delivered (post-FEC) LP frame into the residual-loss estimate.
    fn observe(&self, payload: &Bytes) {
        self.delivered.fetch_add(1, Ordering::Relaxed);
        if let Some(h) = ndn_packet::lp::extract_fragment(payload) {
            let seq = h.sequence;
            let last = self.last_seq.swap(seq, Ordering::Relaxed);
            if last != u64::MAX && seq > last.wrapping_add(1) {
                self.gaps.fetch_add(seq - last - 1, Ordering::Relaxed);
            }
        }
    }

    /// Residual loss fraction (0.0–1.0) over all frames delivered so far.
    pub fn ratio(&self) -> f32 {
        let d = self.delivered.load(Ordering::Relaxed);
        let g = self.gaps.load(Ordering::Relaxed);
        if d + g == 0 {
            0.0
        } else {
            g as f32 / (d + g) as f32
        }
    }

    /// The residual loss fraction **since the last call**, resetting the counters —
    /// so the control plane sees *recent* loss (and backs redundancy off when it
    /// clears) rather than a long-run average. `last_seq` is kept so a gap across the
    /// window boundary is not miscounted.
    pub fn take_ratio(&self) -> f32 {
        let d = self.delivered.swap(0, Ordering::Relaxed);
        let g = self.gaps.swap(0, Ordering::Relaxed);
        if d + g == 0 {
            0.0
        } else {
            g as f32 / (d + g) as f32
        }
    }
}

// `RadioId` identifies a radio within the cognitive `MediumState`; re-used here so
// a bearer's id is the same one the control plane registers and actuates against.
pub use ndn_radio_cognition::RadioId;

/// One radio bound into the medium as a capability: its cognition [`RadioId`], the
/// bearer-agnostic data-plane handle, and its declared [`RadioCapability`].
///
/// The data plane is [`FrameIo`] — **any** radio (Wi-Fi, LoRa, BLE, HaLow, …) is a
/// capability, not just Wi-Fi, and the medium face never touches a Wi-Fi type. The
/// transmit **rate is bearer state**, held inside the driver: the control plane's
/// [`MediumActuator`] calls [`FrameIo::set_rate`] each tick, and every `inject` then
/// transmits at that rate — so per-frame TX carries only a [`TxIntent`] and there is
/// no per-bearer rate cell or wrapper.
///
/// `Clone` shares the same radio handle (an `Arc`) — cloning a bearer does not open a
/// second device.
#[derive(Clone)]
pub struct RadioBearer {
    pub id: RadioId,
    /// Bearer-agnostic data plane (inject/recv/set_rate). Every radio kind implements it.
    pub radio: Arc<dyn FrameIo>,
    pub cap: RadioCapability,
    /// Optional stateful control seam (channel / TX power / contention). `None` =
    /// a bearer with no reachable knobs, whose rate is still actuated as driver
    /// state. Attach with [`with_knobs`](Self::with_knobs) so the actuator built
    /// for this bearer can drive it.
    pub knobs: Option<Arc<dyn RadioKnobs>>,
}

impl RadioBearer {
    /// A bearer over **any** [`FrameIo`] radio (LoRa, BLE, …).
    pub fn new(id: RadioId, radio: Arc<dyn FrameIo>, cap: RadioCapability) -> Self {
        Self {
            id,
            radio,
            cap,
            knobs: None,
        }
    }

    /// A **Wi-Fi** bearer — the same thing, upcasting the (now marker) [`WifiRadio`]
    /// handle to the bearer-agnostic data-plane view. Kept as a convenience for
    /// callers holding an `Arc<dyn WifiRadio>` from a driver.
    pub fn wifi(id: RadioId, radio: Arc<dyn WifiRadio>, cap: RadioCapability) -> Self {
        Self {
            id,
            radio,
            cap,
            knobs: None,
        }
    }

    /// Attach the radio's control seam, and let it describe itself: a seam that
    /// reports an absolute dBm range publishes it on the capability, which is what
    /// tells cognition to decide power in dB rather than chip index units.
    pub fn with_knobs(mut self, knobs: Arc<dyn RadioKnobs>) -> Self {
        self.knobs = Some(knobs);
        self
    }

    /// Declare this bearer's absolute TX-power range (from whatever discovered it).
    pub fn with_tx_power_dbm(mut self, range: DbmRange) -> Self {
        self.cap = self.cap.with_tx_power_dbm(range);
        self
    }
}

/// A minimal in-process **link-signal store** keyed by [`FaceId`]: the medium
/// face's readers push each captured frame's RSSI/rate here (via [`SignalStore`]),
/// and the cognitive control plane reads it back (via [`SignalView`]) on every tick
/// to rank the medium by live link quality — the SENSE→DECIDE bridge. Hand the same
/// `Arc` to [`RadioMediumFace::with_signal_sink`] and
/// [`RadioControl::with_signals`](crate::RadioControl::with_signals).
///
/// (`ndn-signals-core` deliberately ships only the traits; concrete stores are
/// per-host adapters. This is the small native one the radio face needs.)
#[derive(Default)]
pub struct LinkSignalStore {
    links: Mutex<HashMap<FaceId, LinkSignals>>,
}

impl LinkSignalStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SignalView<FaceId> for LinkSignalStore {
    fn link(&self, face: FaceId) -> Option<LinkSignals> {
        self.links.lock().unwrap().get(&face).copied()
    }
    fn node(&self) -> NodeSignals {
        NodeSignals::default()
    }
    fn neighbor(&self, _face: FaceId) -> Option<NodeSignals> {
        None
    }
}

impl SignalStore<FaceId> for LinkSignalStore {
    fn set_link(&self, face: FaceId, signals: LinkSignals) {
        self.links.lock().unwrap().insert(face, signals);
    }
    fn set_node(&self, _signals: NodeSignals) {}
    fn set_neighbor(&self, _face: FaceId, _signals: NodeSignals) {}
}

/// The last knob values pushed to a radio, so an unchanged knob is not re-applied
/// every tick (a channel retune is ~16 ms — it would dominate the loop).
#[derive(Default)]
struct AppliedKnobs {
    channel: Option<(u8, u8)>, // (channel, bw_code)
    csd: Option<bool>,
    edcca: Option<bool>,
    power: Option<u8>,
    power_dbm: Option<i8>,
    sf: Option<u8>, // LoRa spreading factor
    cr: Option<u8>, // LoRa coding rate
}

/// The medium's **actuator**: applies one radio's slice of a [`RadioPlan`] each tick.
///
/// The transmit **rate is set as driver state** via [`FrameIo::set_rate`] — the
/// decided MCS reaches the air because the driver holds it and every `inject` uses it
/// (no planned cell, no wrapper). The stateful control knobs — channel retune, TX
/// power, CSD, EDCCA, LoRa SF/CR — go through an optional [`RadioKnobs`] handle, gated
/// so an unchanged knob is not re-pushed. A portable bearer (loopback / af-packet)
/// passes `knobs = None`, and only its rate is actuated. Register one per bearer on
/// [`RadioControl`](crate::RadioControl) via `add_actuator`.
pub struct MediumActuator {
    radio: RadioId,
    io: Arc<dyn FrameIo>,
    knobs: Option<Arc<dyn RadioKnobs>>,
    last: Mutex<AppliedKnobs>,
    /// Shared parity count the medium face's FEC bridge reads — written each tick
    /// from the decided `link_fec_redundancy` (the loss-recovery lever).
    fec_redundancy: Option<Arc<AtomicU16>>,
    /// A floor on the actuated parity count — the cognition-decided R is raised to at
    /// least this. Lets an operator pin a minimum redundancy on a known-lossy
    /// broadcast link where the face-level loss signal can't see single-frame loss.
    fec_floor: u16,
}

impl MediumActuator {
    /// Actuate `radio`: set its rate on `io`, and (if `knobs` is given) its
    /// channel/power/etc. `knobs` is `None` for a bearer without a control seam.
    pub fn new(
        radio: RadioId,
        io: Arc<dyn FrameIo>,
        knobs: Option<Arc<dyn RadioKnobs>>,
    ) -> Self {
        Self {
            radio,
            io,
            knobs,
            last: Mutex::new(AppliedKnobs::default()),
            fec_redundancy: None,
            fec_floor: 0,
        }
    }

    /// Also actuate **link-FEC redundancy**: on each tick, write the decided
    /// `link_fec_redundancy` (raised to at least `floor`) into `cell`, which the
    /// medium face reads to set the parity count on outbound generations. `floor = 0`
    /// leaves the parity fully cognition-driven.
    pub fn with_fec_redundancy(mut self, cell: Arc<AtomicU16>, floor: u16) -> Self {
        self.fec_redundancy = Some(cell);
        self.fec_floor = floor;
        self
    }
}

impl RadioActuators for MediumActuator {
    fn radio_id(&self) -> RadioId {
        self.radio
    }

    fn apply(&self, alloc: &RadioAllocation) -> Result<(), RadioError> {
        let to_err = |e: FaceError| RadioError(e.to_string());
        let p = &alloc.params;

        // Rate as driver state — the decided MCS every subsequent `inject` transmits at.
        if let Some(index) = p.mcs() {
            let mcs = McsDescriptor {
                index,
                short_gi: p.short_gi(),
                vht: p.vht(),
                nss: p.nss().unwrap_or(1),
                stbc: p.stbc(),
                ldpc: p.ldpc(),
            };
            self.io.set_rate(mcs).map_err(to_err)?;
        }

        // Link-FEC redundancy — the loss-recovery lever, actuated regardless of the
        // knobs seam (a fixed-rate bearer still recovers losses via FEC).
        if let Some(cell) = &self.fec_redundancy {
            cell.store(
                p.link_fec_redundancy.unwrap_or(0).max(self.fec_floor),
                Ordering::Relaxed,
            );
        }

        // The stateful control knobs — only pushed when changed.
        let Some(knobs) = &self.knobs else {
            return Ok(());
        };
        let mut last = self.last.lock().unwrap();
        if let Some(ch) = alloc.channel {
            let bw_code = p.bw().unwrap_or(0);
            if last.channel != Some((ch, bw_code)) {
                knobs
                    .set_channel(ch, Bandwidth::from_code(bw_code))
                    .map_err(to_err)?;
                last.channel = Some((ch, bw_code));
            }
        }
        if last.csd != Some(p.csd()) {
            knobs.set_tx_csd(p.csd()).map_err(to_err)?;
            last.csd = Some(p.csd());
        }
        if last.edcca != Some(p.edcca_ignore) {
            knobs.set_edcca_ignore(p.edcca_ignore).map_err(to_err)?;
            last.edcca = Some(p.edcca_ignore);
        }
        // TX power: prefer the absolute dBm scale when the radio has one, since
        // it is what the policy actually decided (the index is a lossy rendering
        // of the same back-off through a chip-independent dB-per-step constant).
        // A radio without dBm control falls back to the index; a radio with it
        // skips the index entirely, so the two can never fight over one knob.
        let dbm_applied = match p.tx_power_dbm {
            Some(dbm) if last.power_dbm != Some(dbm) => match knobs.set_tx_power_dbm(dbm) {
                Ok(_applied) => {
                    // Dedupe on the *request*, not on what the radio reported
                    // applying. A firmware/regulatory clamp (30 dBm -> 27) means
                    // the applied value never equals the request, so keying on it
                    // would make an unchanged decision look changed and re-push a
                    // write on every single tick, forever.
                    last.power_dbm = Some(dbm);
                    true
                }
                // Unsupported on this radio — fall through to the index scale.
                Err(_) => false,
            },
            Some(_) => true, // already applied
            None => false,
        };
        if !dbm_applied
            && let Some(idx) = p.tx_power
            && last.power != Some(idx)
        {
            knobs.set_tx_power(idx as u32).map_err(to_err)?;
            last.power = Some(idx);
        }
        if let Some(sf) = p.spreading_factor()
            && last.sf != Some(sf)
        {
            knobs.set_spreading_factor(sf).map_err(to_err)?;
            last.sf = Some(sf);
        }
        if let Some(cr) = p.coding_rate()
            && last.cr != Some(cr)
        {
            knobs.set_coding_rate(cr).map_err(to_err)?;
            last.cr = Some(cr);
        }
        Ok(())
    }
}

/// Where the cognition loop's active [`NameContext`]s come from on each refresh — the
/// injection point that lets an engine-aware host (with FIB access) feed name-derived
/// contexts while a bare face falls back to a static set. The
/// [`FaceFactory`](ndn_transport::FaceFactory) seam has no engine, so a factory-built
/// face uses [`StaticContexts`]; a forwarder that holds the engine implements this
/// over its FIB and gets the same loop.
pub trait ContextSource: Send + Sync + 'static {
    /// The names the medium is currently transmitting for (what to decide plans for).
    fn active(&self) -> Vec<NameContext>;
}

/// A fixed active set — the default when no engine/FIB is reachable.
pub struct StaticContexts(pub Vec<NameContext>);

impl ContextSource for StaticContexts {
    fn active(&self) -> Vec<NameContext> {
        self.0.clone()
    }
}

/// Spawn the cognition control loop over `control`: refresh the active contexts from
/// `source` every `refresh_every` ticks and decide (`tick_now`) every `tick`. Returns
/// the task handle — hang it on the face via [`RunningMedium::attach_task`] to tie its
/// lifetime to the face. This is the single loop both the factory (with
/// [`StaticContexts`]) and an engine-aware mount (with a FIB-backed source) share.
pub fn spawn_control_loop(
    control: Arc<RadioControl>,
    source: Arc<dyn ContextSource>,
    tick: Duration,
    refresh_every: u32,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let started = Instant::now();
        let mut ticker = tokio::time::interval(tick);
        let mut since = u32::MAX; // force a refresh on the first tick
        loop {
            ticker.tick().await;
            since = since.saturating_add(1);
            if since >= refresh_every.max(1) {
                control.set_active(source.active());
                since = 0;
            }
            control.tick_now(started.elapsed().as_millis() as u64);
        }
    })
}

/// Declarative medium face: a face id, the radio capabilities, and options. Build
/// the running face with [`into_face`](Self::into_face) (or [`build`](Self::build)).
pub struct RadioMediumFace {
    id: FaceId,
    mtu: usize,
    bearers: Vec<RadioBearer>,
    signal_sink: Option<Arc<dyn SignalStore<FaceId> + Send + Sync>>,
    fec: Option<FecConfig>,
    /// When set true (by cognition, on hearing a legacy-only-RX neighbour), the data
    /// path injects at the basic legacy rate ([`TxIntent::ROBUST`]) so it reaches that
    /// neighbour — the worst-overheard-receiver rate cap. `None`/false = decided rate.
    legacy_gate: Option<Arc<AtomicBool>>,
}

/// Predicate deciding whether an outbound wire is **FEC-eligible** — i.e. wants the
/// last-resort loss-recovery treatment. Given the framed NDN wire (so the host can
/// classify by name via its QoS `PrefixClassifier`/`TrafficClass`). `None` = every
/// frame is eligible (blanket FEC, the pre-gating behaviour).
pub type FecEligible = Arc<dyn Fn(&Bytes) -> bool + Send + Sync>;

/// Link-FEC settings for the medium face: `k` source frames per generation, a tail-
/// flush `window`, the shared parity count the cognition actuator writes, the
/// residual-loss meter the reader feeds, and an optional per-frame eligibility gate.
#[derive(Clone)]
struct FecConfig {
    k: usize,
    window: Duration,
    redundancy: Arc<AtomicU16>,
    loss: Arc<LossMeter>,
    /// Only these frames are coded; the rest bypass FEC even when R>0. `None` = all.
    /// "Retransmit is last resort and appropriate traffic only" — reliable-delivery
    /// names get parity; real-time/best-effort classes do not (a late-recovered frame
    /// is dead weight there).
    eligible: Option<FecEligible>,
}

impl RadioMediumFace {
    /// A medium face `id` reachable through `bearers` (≥1 radio capability).
    pub fn new(id: FaceId, bearers: Vec<RadioBearer>) -> Self {
        Self {
            id,
            mtu: MONITOR_MTU,
            bearers,
            signal_sink: None,
            fec: None,
            legacy_gate: None,
        }
    }

    /// Bind the shared **legacy-rate gate**: when cognition sets it true (a legacy-only-RX
    /// neighbour is present), every data frame injects at the basic legacy rate so it
    /// reaches that neighbour. Reports already go legacy via [`RunningMedium::send_robust`];
    /// this extends the same worst-receiver reach to the data plane.
    pub fn with_legacy_gate(mut self, gate: Arc<AtomicBool>) -> Self {
        self.legacy_gate = Some(gate);
        self
    }

    /// Enable **link-layer FEC** on every bearer: outbound frames are grouped into
    /// generations of `k` (or flushed after `window`), sent as `k + R` coded frames,
    /// and the receiver recovers up to `R` losses per generation with no ARQ — the
    /// loss-recovery lever for a broadcast medium. `redundancy` is the shared parity
    /// count the cognition [`MediumActuator`] writes (from the decided
    /// `link_fec_redundancy`); `loss` is the residual-loss meter the RX side feeds so
    /// the control plane can raise R until residual loss falls. Both ends must enable
    /// FEC with the same `k`.
    pub fn with_link_fec(
        mut self,
        k: usize,
        window: Duration,
        redundancy: Arc<AtomicU16>,
        loss: Arc<LossMeter>,
    ) -> Self {
        self.fec = Some(FecConfig {
            k: k.max(1),
            window,
            redundancy,
            loss,
            eligible: None,
        });
        self
    }

    /// Gate link-FEC to **appropriate traffic only**: `pred(wire)` decides per frame
    /// whether to add parity (the host classifies by name via its QoS
    /// `PrefixClassifier`). Frames the predicate rejects bypass FEC even when the
    /// cognition-decided redundancy is >0 — so real-time/best-effort classes keep the
    /// low-latency direct path while reliable-delivery names get loss recovery. No-op
    /// unless [`with_link_fec`](Self::with_link_fec) was set.
    pub fn with_fec_eligibility(mut self, pred: FecEligible) -> Self {
        if let Some(fec) = &mut self.fec {
            fec.eligible = Some(pred);
        }
        self
    }

    /// Publish each captured frame's RSSI/rate to `sink`, keyed by this face id, so
    /// the cognitive control loop's `SignalView` sees live per-radio link quality.
    pub fn with_signal_sink(mut self, sink: Arc<dyn SignalStore<FaceId> + Send + Sync>) -> Self {
        self.signal_sink = Some(sink);
        self
    }

    /// Override the injected-frame payload budget (defaults to [`MONITOR_MTU`]).
    pub fn with_mtu(mut self, mtu: usize) -> Self {
        self.mtu = mtu;
        self
    }

    /// The declared capabilities of every bearer — hand these to
    /// [`RadioControl::register_radio`](crate::RadioControl::register_radio) so the
    /// medium's decide plane knows what it is allocating across.
    pub fn capabilities(&self) -> Vec<(RadioId, RadioCapability)> {
        self.bearers.iter().map(|b| (b.id, b.cap.clone())).collect()
    }

    /// Spawn the per-radio reader tasks and return the running [`Transport`].
    pub fn build(self) -> RunningMedium {
        RunningMedium::spawn(self)
    }

    /// Build a [`Face`] pairing the running medium transport with the engine's
    /// `LpLinkService`, so NDN packets fragment/reassemble across injected frames —
    /// exactly as [`MonitorWifiFace::into_face`](crate::MonitorWifiFace::into_face).
    pub fn into_face(self) -> Face {
        Face::from_transport(self.build())
    }

    /// Build a [`Face`] whose LP link service also runs `feature`. Used to mount the
    /// cognition [`RadioControl`](crate::RadioControl) as a `LinkServiceFeature` so it
    /// observes this face's forwarding events (`on_egress`/`on_ingress`/`tick`) — the
    /// seam that feeds per-name demand into the control plane. Without it, cognition
    /// runs open-loop on demand (the consolidation dropped this). Otherwise identical
    /// to [`into_face`](Self::into_face).
    pub fn into_face_with_feature(self, feature: Arc<dyn LinkServiceFeature>) -> Face {
        let transport = self.build();
        let ls = LpLinkService::new().with_extra_feature(feature);
        Face::from_parts(Arc::new(transport), Arc::new(ls))
    }
}

/// The send half of one bearer: the bearer-agnostic data plane and, when link-FEC is
/// on, the generation bridge + the shared parity count. The transmit rate is bearer
/// state (held in the driver), so this carries no rate — only the frame.
struct TxBearer {
    radio: Arc<dyn FrameIo>,
    /// `(bridge, redundancy)` when FEC is enabled: the wire is enqueued into a
    /// generation and the bridge emits `k + R` coded frames on this bearer.
    fec: Option<(Arc<LinkFecBridge<()>>, Arc<AtomicU16>)>,
    /// Per-frame FEC eligibility (appropriate-traffic-only gate); `None` = all frames.
    eligible: Option<FecEligible>,
    /// Shared legacy-rate gate: when true, data injects at the basic legacy rate to reach
    /// a legacy-only-RX neighbour (worst-overheard-receiver cap). `None` = decided rate.
    legacy_gate: Option<Arc<AtomicBool>>,
}

impl TxBearer {
    /// Send one already-framed wire on the data plane. Normally at the decided broadcast
    /// rate; but when the shared legacy gate is set (cognition heard a legacy-only-RX
    /// neighbour), inject at the basic legacy rate ([`TxIntent::ROBUST`]) instead, so the
    /// data reaches that neighbour — the doctrine's worst-overheard-receiver rate.
    async fn inject(&self, wire: Bytes) -> Result<(), FaceError> {
        let legacy = self
            .legacy_gate
            .as_ref()
            .is_some_and(|g| g.load(Ordering::Relaxed));
        let intent = if legacy {
            TxIntent::ROBUST
        } else {
            TxIntent::CONSERVATIVE
        };
        self.inject_with_intent(wire, intent).await
    }

    /// Send one wire at an explicit [`TxIntent`]. A `MostRobust` frame (cooperative
    /// report / discovery / control) **bypasses FEC** — it is a standalone control frame,
    /// not part of a data generation — and the driver maps `MostRobust` to the basic
    /// legacy rate every neighbour can decode (the worst-overheard-receiver reach).
    async fn inject_with_intent(&self, wire: Bytes, intent: TxIntent) -> Result<(), FaceError> {
        let robust = intent.reliability == Reliability::MostRobust;
        // Only route through the FEC coder when there is parity to add AND this frame
        // is FEC-eligible (appropriate-traffic-only) AND it is not a robust control frame.
        // At R=0 the generation batching would cost the tail-flush latency for no recovery;
        // for an ineligible class (real-time/best-effort) a late-recovered frame is dead
        // weight — all bypass and inject directly. The peer's decoder passes an uncoded
        // frame straight through, so mixing coded/uncoded frames is safe.
        if !robust {
            if let Some((bridge, r)) = &self.fec {
                let parity = r.load(Ordering::Relaxed);
                let eligible = self.eligible.as_ref().is_none_or(|pred| pred(&wire));
                if parity > 0 && eligible {
                    return bridge.send(wire, (), Some(parity));
                }
            }
        }
        let frame = InjectFrame {
            payload: wire,
            tx: intent,
            dst: BROADCAST,
            src: DEFAULT_SRC,
        };
        self.radio.inject(frame).await
    }
}

/// The running medium transport: N send-bearers, a unioned inbound channel fed by
/// one reader task per radio, plus any attached background tasks (e.g. a cognition
/// control loop). All task handles are aborted when the transport is dropped — so a
/// face torn down (`engine.remove_face`) stops reading *and* deciding.
pub struct RunningMedium {
    id: FaceId,
    mtu: usize,
    tx: Vec<TxBearer>,
    rx: AsyncMutex<mpsc::UnboundedReceiver<(Bytes, Option<FaceAddr>, u16)>>,
    tasks: Vec<JoinHandle<()>>,
}

impl RunningMedium {
    /// Attach a background task whose lifetime is tied to this face — aborted when
    /// the transport is dropped. Used to bind a face-owned cognition control loop to
    /// the face (a [`FaceFactory`](ndn_transport::FaceFactory) has no separate
    /// lifetime handle, so it hangs the loop here).
    pub fn attach_task(&mut self, handle: JoinHandle<()>) {
        self.tasks.push(handle);
    }

    /// Inject a cooperative-broadcast wire (reception report / discovery / control) at
    /// `MostRobust` intent on every bearer — the basic legacy rate every neighbour can
    /// decode, FEC bypassed. Distinct from [`Transport::send_bytes`], which sends data at
    /// the cognition-decided rate: a report must reach the *worst* receiver (e.g. a
    /// legacy-only-RX 8812au), so it never rides the throughput-optimised data rate.
    pub async fn send_robust(&self, wire: Bytes) -> Result<(), FaceError> {
        let mut sent = false;
        let mut last_err = None;
        for b in &self.tx {
            match b.inject_with_intent(wire.clone(), TxIntent::ROBUST).await {
                Ok(()) => sent = true,
                Err(e) => last_err = Some(e),
            }
        }
        if sent {
            Ok(())
        } else {
            Err(last_err.unwrap_or(FaceError::Closed))
        }
    }
}

impl RunningMedium {
    fn spawn(cfg: RadioMediumFace) -> Self {
        let RadioMediumFace {
            id,
            mtu,
            bearers,
            signal_sink,
            fec,
            legacy_gate,
        } = cfg;

        let (tx_chan, rx_chan) = mpsc::unbounded_channel();
        let mut tx = Vec::with_capacity(bearers.len());
        let mut tasks = Vec::with_capacity(bearers.len());

        for b in bearers {
            // One link-FEC bridge per bearer (shared TX-encode / RX-decode) when
            // enabled: the sink injects each coded frame on this bearer, and the
            // reader feeds captured frames through the same bridge's decoder.
            let bridge = fec.as_ref().map(|fc| {
                Arc::new(LinkFecBridge::spawn(
                    FrameIoSink::new(
                        ArcRadio(b.radio.clone()),
                        BROADCAST,
                        DEFAULT_SRC,
                        TxIntent::CONSERVATIVE,
                    ),
                    fc.k,
                    0,
                    fc.window,
                ))
            });
            tx.push(TxBearer {
                radio: b.radio.clone(),
                fec: bridge
                    .clone()
                    .zip(fec.as_ref().map(|fc| fc.redundancy.clone())),
                eligible: fec.as_ref().and_then(|fc| fc.eligible.clone()),
                legacy_gate: legacy_gate.clone(),
            });

            // One reader per radio → the RX union. A frame heard on any capability is
            // forwarded once to the engine (after FEC decode when on); its RSSI/rate
            // is published for the sense→decide loop.
            let radio = b.radio.clone();
            let radio_id = b.id.0; // stamp each captured frame with its receiving radio
            let out = tx_chan.clone();
            let sink = signal_sink.clone();
            let rx_bridge = bridge;
            let loss = fec.as_ref().map(|fc| fc.loss.clone());
            tasks.push(tokio::spawn(async move {
                loop {
                    match radio.recv_frame().await {
                        Ok(f) => {
                            if (f.rssi_dbm.is_some() || f.mcs_index.is_some())
                                && let Some(sink) = sink.as_ref()
                            {
                                let mut ls = LinkSignals {
                                    rssi_dbm: f.rssi_dbm,
                                    observed_tput_bps: f.mcs_index.map(mcs_phy_rate_bps),
                                    updated_ms: super::now_ms(),
                                    ..LinkSignals::default()
                                };
                                if let Some(mcs) = f.mcs_index {
                                    ls.ext_set("mcs", mcs as f32);
                                }
                                sink.set_link(id, ls);
                            }
                            let addr = f.addr.map(FaceAddr::Ether);
                            match &rx_bridge {
                                // FEC: a captured frame yields 0 (parity, incomplete),
                                // 1 (a source), or several (parity completed a
                                // generation, recovering losses). Each is measured for
                                // residual loss and delivered.
                                Some(bridge) => {
                                    for p in bridge.decode(f.payload) {
                                        if let Some(m) = &loss {
                                            m.observe(&p);
                                        }
                                        if out.send((p, addr.clone(), radio_id)).is_err() {
                                            return;
                                        }
                                    }
                                }
                                None => {
                                    if out.send((f.payload, addr, radio_id)).is_err() {
                                        return; // face dropped — stop reading
                                    }
                                }
                            }
                        }
                        // A transient per-radio RX error must not kill the union.
                        Err(_) => tokio::task::yield_now().await,
                    }
                }
            }));
        }

        Self {
            id,
            mtu,
            tx,
            rx: AsyncMutex::new(rx_chan),
            tasks,
        }
    }
}

impl Drop for RunningMedium {
    fn drop(&mut self) {
        for h in &self.tasks {
            h.abort();
        }
    }
}

impl Transport for RunningMedium {
    fn id(&self) -> FaceId {
        self.id
    }

    fn kind(&self) -> FaceKind {
        // `Wfb` is the workspace's connectionless-radio-broadcast kind — despite the
        // Wi-Fi-legacy name it is already shared by non-Wi-Fi radios (ndn-face-lora
        // reports it too): LP framing on, NonLocal, `AdHoc` link. Renaming it to a
        // neutral `FaceKind::Radio` is a foundational-enum change tracked separately.
        FaceKind::Wfb
    }

    fn remote_uri(&self) -> Option<String> {
        Some("radio-medium://broadcast".to_string())
    }

    fn link_type(&self) -> LinkType {
        LinkType::AdHoc
    }

    fn send_mtu(&self) -> Option<usize> {
        Some(self.mtu)
    }

    async fn send_bytes(&self, wire: Bytes) -> Result<(), FaceError> {
        // Fan out: inject the (already LP-framed) frame on every bearer at its own
        // decided rate. On a broadcast medium this replication is diversity; one
        // bearer collapses to the single-radio path. Succeed if any radio accepted
        // the frame; surface the last error only if all failed.
        let mut sent = false;
        let mut last_err = None;
        for b in &self.tx {
            match b.inject(wire.clone()).await {
                Ok(()) => sent = true,
                Err(e) => last_err = Some(e),
            }
        }
        if sent {
            Ok(())
        } else {
            Err(last_err.unwrap_or(FaceError::Closed))
        }
    }

    async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
        self.recv_bytes_with_meta().await.map(|(b, _, _)| b)
    }

    async fn recv_bytes_with_addr(&self) -> Result<(Bytes, Option<FaceAddr>), FaceError> {
        self.recv_bytes_with_meta().await.map(|(b, a, _)| (b, a))
    }

    async fn recv_bytes_with_meta(
        &self,
    ) -> Result<(Bytes, Option<FaceAddr>, Option<u16>), FaceError> {
        let mut rx = self.rx.lock().await;
        rx.recv()
            .await
            .map(|(b, a, r)| (b, a, Some(r)))
            .ok_or(FaceError::Closed)
    }

    fn set_send_mtu(&self, _mtu: Option<u64>) -> Result<Option<u64>, MtuError> {
        Err(MtuError::Immutable)
    }

    fn set_persistency(&self, _persistency: FacePersistency) -> Result<(), PersistencyError> {
        Err(PersistencyError::Immutable)
    }
}

#[cfg(test)]
mod power_actuation_tests {
    use super::*;
    use crate::LoopbackMonitorBus;
    use ndn_radio_cognition::{RadioPlan, TxParams};
    use std::sync::Mutex as StdMutex;

    /// Records which power scale the actuator reached for.
    #[derive(Default)]
    struct SpyKnobs {
        dbm_calls: StdMutex<Vec<i8>>,
        idx_calls: StdMutex<Vec<u32>>,
        /// Simulate a radio with no absolute control.
        dbm_unsupported: bool,
    }

    impl RadioKnobs for SpyKnobs {
        fn set_channel(&self, _c: u8, _bw: Bandwidth) -> Result<(), FaceError> {
            Ok(())
        }
        fn set_tx_power(&self, idx: u32) -> Result<(), FaceError> {
            self.idx_calls.lock().unwrap().push(idx);
            Ok(())
        }
        fn set_tx_power_dbm(&self, dbm: i8) -> Result<i8, FaceError> {
            if self.dbm_unsupported {
                return Err(FaceError::Io(std::io::Error::from(
                    std::io::ErrorKind::Unsupported,
                )));
            }
            self.dbm_calls.lock().unwrap().push(dbm);
            // Report a clamp, as real firmware does.
            Ok(dbm.min(27))
        }
    }

    fn actuate(knobs: Arc<SpyKnobs>, params: TxParams) -> Arc<SpyKnobs> {
        let bus = LoopbackMonitorBus::new();
        let io: Arc<dyn FrameIo> = Arc::new(bus.endpoint(1, -55));
        let act = MediumActuator::new(RadioId(0), io, Some(knobs.clone()));
        let plan = RadioPlan::single(RadioId(0), None, params);
        act.apply(plan.allocation_for(RadioId(0)).unwrap()).unwrap();
        knobs
    }

    /// A radio with dBm control is driven in dBm — and the index knob is left
    /// alone, so the two never fight over one piece of hardware state.
    #[test]
    fn dbm_is_preferred_over_the_index_scale() {
        let k = actuate(
            Arc::new(SpyKnobs::default()),
            TxParams {
                tx_power_dbm: Some(14),
                tx_power: Some(40),
                ..Default::default()
            },
        );
        assert_eq!(*k.dbm_calls.lock().unwrap(), vec![14]);
        assert!(
            k.idx_calls.lock().unwrap().is_empty(),
            "index knob must not also be pushed"
        );
    }

    /// A radio without dBm control still gets actuated: the decision falls back
    /// to the index rather than being silently dropped.
    #[test]
    fn falls_back_to_the_index_when_dbm_is_unsupported() {
        let k = actuate(
            Arc::new(SpyKnobs {
                dbm_unsupported: true,
                ..Default::default()
            }),
            TxParams {
                tx_power_dbm: Some(14),
                tx_power: Some(40),
                ..Default::default()
            },
        );
        assert!(k.dbm_calls.lock().unwrap().is_empty());
        assert_eq!(*k.idx_calls.lock().unwrap(), vec![40]);
    }

    /// An unchanged decision is not re-pushed every tick.
    #[test]
    fn repeated_identical_power_is_pushed_once() {
        let knobs = Arc::new(SpyKnobs::default());
        let bus = LoopbackMonitorBus::new();
        let io: Arc<dyn FrameIo> = Arc::new(bus.endpoint(1, -55));
        let act = MediumActuator::new(RadioId(0), io, Some(knobs.clone()));
        let params = TxParams {
            tx_power_dbm: Some(20),
            ..Default::default()
        };
        let plan = RadioPlan::single(RadioId(0), None, params);
        let alloc = plan.allocation_for(RadioId(0)).unwrap();
        act.apply(alloc).unwrap();
        act.apply(alloc).unwrap();
        assert_eq!(*knobs.dbm_calls.lock().unwrap(), vec![20]);
    }

    /// A clamped write is remembered as *applied*, not as requested — otherwise a
    /// request the firmware will never grant is re-sent on every single tick.
    #[test]
    fn a_clamped_write_is_not_retried_forever() {
        let knobs = Arc::new(SpyKnobs::default()); // clamps at 27
        let bus = LoopbackMonitorBus::new();
        let io: Arc<dyn FrameIo> = Arc::new(bus.endpoint(1, -55));
        let act = MediumActuator::new(RadioId(0), io, Some(knobs.clone()));
        let params = TxParams {
            tx_power_dbm: Some(30), // will clamp to 27
            ..Default::default()
        };
        let plan = RadioPlan::single(RadioId(0), None, params);
        let alloc = plan.allocation_for(RadioId(0)).unwrap();
        act.apply(alloc).unwrap();
        act.apply(alloc).unwrap();
        act.apply(alloc).unwrap();
        let calls = knobs.dbm_calls.lock().unwrap();
        assert_eq!(
            calls.len(),
            1,
            "a firmware clamp must not cause a write every tick, got {calls:?}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LoopbackMonitorBus, WifiRadio};
    use ndn_transport::Transport;
    use std::time::Duration;

    fn cap() -> RadioCapability {
        RadioCapability::wifi_monitor_5ghz(vec![149])
    }

    /// Two radios on two disjoint media, one medium face spanning both: a frame put
    /// on *either* medium is delivered once by the union, and a frame the face
    /// *sends* fans out onto *both* media. This is the whole "one face, N
    /// capabilities" contract — RX union + TX fan-out — with no hardware.
    #[tokio::test]
    async fn medium_face_unions_rx_and_fans_out_tx() {
        let bus_a = LoopbackMonitorBus::new();
        let bus_b = LoopbackMonitorBus::new();

        // Peers: a lone radio on each bus that we inject from / listen on.
        let peer_a: Arc<dyn WifiRadio> = Arc::new(bus_a.endpoint(10, -50));
        let peer_b: Arc<dyn WifiRadio> = Arc::new(bus_b.endpoint(20, -50));

        // The medium face: capability 1 on bus A, capability 2 on bus B.
        let bearers = vec![
            RadioBearer::new(RadioId(1), Arc::new(bus_a.endpoint(1, -55)), cap()),
            RadioBearer::new(RadioId(2), Arc::new(bus_b.endpoint(2, -55)), cap()),
        ];
        let medium = RadioMediumFace::new(FaceId(7), bearers).build();

        // RX union: a frame on bus A and a frame on bus B both arrive at the face.
        let inject = |radio: Arc<dyn WifiRadio>, byte: u8| async move {
            let frame = InjectFrame {
                payload: Bytes::from(vec![byte; 16]),
                tx: TxIntent::CONSERVATIVE,
                dst: BROADCAST,
                src: DEFAULT_SRC,
            };
            radio.inject_at(frame, McsDescriptor::ht(0)).await.unwrap();
        };
        inject(peer_a.clone(), 0xAA).await;
        inject(peer_b.clone(), 0xBB).await;

        let mut got = Vec::new();
        for _ in 0..2 {
            let (b, _) = tokio::time::timeout(Duration::from_secs(2), medium.recv_bytes_with_addr())
                .await
                .expect("union should deliver frames from both media")
                .unwrap();
            got.push(b[0]);
        }
        got.sort();
        assert_eq!(got, vec![0xAA, 0xBB], "RX unions both radio capabilities");

        // TX fan-out: one send reaches a listener on *each* medium.
        medium.send_bytes(Bytes::from(vec![0xCC; 16])).await.unwrap();
        for peer in [peer_a, peer_b] {
            let f = tokio::time::timeout(Duration::from_secs(2), peer.recv_frame())
                .await
                .expect("send must fan out onto every medium")
                .unwrap();
            assert_eq!(f.payload[0], 0xCC);
        }
    }

    /// The cognition loop closes through the driver's native rate state: a
    /// `RadioControl` with a [`MediumActuator`] over a loopback radio, fed a strong
    /// link, decides on `tick` and calls [`FrameIo::set_rate`] on that radio — so a
    /// subsequent plain `inject` puts the decided MCS on the air, observed by a peer.
    /// No USB, no hardware, no planned cell; this is the ACT the `ndn-fwd` radio face
    /// runs (proving `RateBearer`'s retirement is sound).
    #[tokio::test]
    async fn cognition_tick_sets_the_driver_rate() {
        use crate::{FrameIo, RadioControl};
        use ndn_radio_cognition::{NameContext, RadioPolicy, prefix_hash};

        let bus = LoopbackMonitorBus::new();
        let radio: Arc<dyn FrameIo> = Arc::new(bus.endpoint(1, -50));
        let peer: Arc<dyn WifiRadio> = Arc::new(bus.endpoint(2, -50));
        let face_id = FaceId(5);
        let rid = RadioId(0);

        let signals = Arc::new(LinkSignalStore::new());
        let mut control = RadioControl::new(RadioPolicy::default()).with_signals(signals.clone());
        control.register_radio(rid, face_id, cap());
        control.add_actuator(Arc::new(MediumActuator::new(rid, radio.clone(), None)));
        control.set_active(vec![NameContext::new(prefix_hash(&[b"radio"]))]);

        // A strong link so the policy picks a real (non-suppressed) rate.
        signals.set_link(
            face_id,
            LinkSignals {
                rssi_dbm: Some(-50),
                updated_ms: crate::now_ms(),
                ..LinkSignals::default()
            },
        );

        let plans = control.tick_now(1_000);
        let decided = plans
            .first()
            .and_then(|p| p.allocations.first())
            .and_then(|a| a.params.mcs())
            .expect("the tick decided a concrete MCS");

        // The actuator set that rate on the driver → a plain inject transmits at it.
        radio
            .inject(InjectFrame {
                payload: Bytes::from_static(b"x"),
                tx: TxIntent::CONSERVATIVE,
                dst: BROADCAST,
                src: DEFAULT_SRC,
            })
            .await
            .unwrap();
        let got = tokio::time::timeout(Duration::from_secs(2), peer.recv_frame())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            got.mcs_index,
            Some(decided),
            "the decided MCS reached the air as driver rate state"
        );
    }

    /// Link-FEC on the medium face round-trips: frames sent through a FEC-enabled
    /// medium are generation-coded, cross the bus, and the peer's FEC-enabled medium
    /// decodes them back to the originals — proving the TX-encode / RX-decode plumbing
    /// end to end (erasure *recovery* is covered by `ndn_coding`'s own tests). This is
    /// the loss-recovery lever the cognition loop actuates.
    #[tokio::test]
    async fn link_fec_round_trips_through_the_medium() {
        let bus = LoopbackMonitorBus::new();
        let tx = RadioMediumFace::new(
            FaceId(1),
            vec![RadioBearer::wifi(RadioId(0), Arc::new(bus.endpoint(1, -50)), cap())],
        )
        .with_link_fec(
            3,
            Duration::from_millis(20),
            Arc::new(AtomicU16::new(2)),
            Arc::new(LossMeter::default()),
        )
        .build();
        let rx = RadioMediumFace::new(
            FaceId(2),
            vec![RadioBearer::wifi(RadioId(0), Arc::new(bus.endpoint(2, -50)), cap())],
        )
        .with_link_fec(
            3,
            Duration::from_millis(20),
            Arc::new(AtomicU16::new(0)),
            Arc::new(LossMeter::default()),
        )
        .build();

        let sent: Vec<Bytes> = (0..3u8).map(|i| Bytes::from(vec![i; 12])).collect();
        for w in &sent {
            tx.send_bytes(w.clone()).await.unwrap();
        }
        let mut got = Vec::new();
        for _ in 0..3 {
            let (b, _) = tokio::time::timeout(Duration::from_secs(2), rx.recv_bytes_with_addr())
                .await
                .expect("FEC medium delivers the generation")
                .unwrap();
            got.push(b);
        }
        got.sort();
        let mut want = sent;
        want.sort();
        assert_eq!(got, want, "link-FEC round-trips the generation through the medium face");
    }

    /// One bearer ⇒ the medium face is exactly the single-radio path: send on the
    /// bus, the peer hears it; peer sends, the face receives it.
    #[tokio::test]
    async fn single_bearer_is_the_degenerate_medium() {
        let bus = LoopbackMonitorBus::new();
        let peer: Arc<dyn WifiRadio> = Arc::new(bus.endpoint(9, -50));
        let medium = RadioMediumFace::new(
            FaceId(3),
            vec![RadioBearer::new(RadioId(1), Arc::new(bus.endpoint(1, -55)), cap())],
        )
        .build();

        medium.send_bytes(Bytes::from(vec![0x42; 16])).await.unwrap();
        let f = tokio::time::timeout(Duration::from_secs(2), peer.recv_frame())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(f.payload[0], 0x42);
    }
}
