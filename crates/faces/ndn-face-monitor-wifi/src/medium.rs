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
//! subset the `RadioPlan` selects, honouring per-radio channel) remains a follow-up; the
//! abstraction (one face, N capabilities, union RX, fan-out TX) is complete here.
//!
//! The feature gap versus [`MonitorWifiFace`] that this note used to describe is closed (#82):
//! name-group addressing and link-FEC arrived earlier, the shared [`NameGate`](crate::NameGate)
//! landed in part 1, and A-MSDU — the last genuinely one-sided feature — landed in part 2. What
//! remains of #82 is the structural half: `MonitorWifiFace` becoming a one-bearer construction of
//! this face rather than a parallel implementation of it.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use ndn_coding::link_fec_bridge::LinkFecBridge;
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
    Bandwidth, BROADCAST, DbmRange, EphemeralSource, FaceError, FaceId,
    FrameIo, InjectFrame,
    McsDescriptor, MONITOR_MTU, OpenRadio, RadioCapability, RadioKnobs, RadioProfile,
    RadioTime,
    Reliability, TxIntent, mcs_phy_rate_bps,
};

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
    /// Hardware timestamping / TSF common-view for **this bearer** (#78).
    ///
    /// Per-bearer, not per-face, because that is the shape the MAC needs: a multi-radio node has one
    /// clock per radio, and a slot gate that consults a face-level clock is deciding for the wrong
    /// medium (#89). Absent until now only because [`open_named_radio`] could not return it.
    pub time: Option<Arc<dyn RadioTime>>,
    /// The bearer's self-description — declared capability and calibration (#78).
    ///
    /// `cap` above is what the *caller* asserted; this is what the *radio* says. Keeping both makes a
    /// disagreement visible instead of letting a hand-written `RadioCapability` quietly outrank the
    /// hardware (#98 is that failure in miniature: `agile` is asserted and never measured).
    pub profile: Option<Arc<dyn RadioProfile>>,
}

impl RadioBearer {
    /// A bearer over **any** [`FrameIo`] radio (LoRa, BLE, …).
    pub fn new(id: RadioId, radio: Arc<dyn FrameIo>, cap: RadioCapability) -> Self {
        Self { id, radio, cap, knobs: None, time: None, profile: None }
    }

    /// **A bearer from the standardized opener** (#78) — the capability-complete path.
    ///
    /// `open_named_radio` returns everything the backend implements; this carries all of it onto the
    /// bearer in one call. Before this existed, a caller wanting knobs or timing had to bypass the
    /// standardized opener and name a concrete backend, which is precisely the leak the opener was
    /// created to close — it had fixed the on-air FORMAT leak and left the CAPABILITY leak open.
    pub fn from_open(id: RadioId, r: OpenRadio, cap: RadioCapability) -> Self {
        Self { id, radio: r.io, cap, knobs: r.knobs, time: r.time, profile: r.profile }
    }

    /// **The capability that governs** — the radio's own when it declares one, else the caller's
    /// assertion.
    ///
    /// The [`profile`](Self::profile) field's contract says keeping both "makes a disagreement
    /// visible instead of letting a hand-written `RadioCapability` quietly outrank the hardware".
    /// Nothing read it, so that contract was itself unactuated: every consumer saw the asserted
    /// `cap` and the radio's self-description sat unused on the struct. The hardware wins here, and
    /// [`RunningMedium::spawn`] logs the disagreement rather than resolving it silently.
    pub fn effective_cap(&self) -> RadioCapability {
        match &self.profile {
            Some(p) => p.capability(),
            None => self.cap.clone(),
        }
    }

    /// Attach this bearer's clock. See the [`time`](Self::time) field on why it is per-bearer.
    pub fn with_time(mut self, time: Arc<dyn RadioTime>) -> Self {
        self.time = Some(time);
        self
    }

    /// Attach the radio's self-description.
    pub fn with_profile(mut self, profile: Arc<dyn RadioProfile>) -> Self {
        self.profile = Some(profile);
        self
    }

    /// A **Wi-Fi** bearer — the same thing, upcasting the (now marker) [`WifiRadio`]
    /// handle to the bearer-agnostic data-plane view. Kept as a convenience for
    /// callers holding an `Arc<dyn FrameIo>` from a driver.
    pub fn wifi(id: RadioId, radio: Arc<dyn FrameIo>, cap: RadioCapability) -> Self {
        Self { id, radio, cap, knobs: None, time: None, profile: None }
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
    /// Per-**neighbour** link signals, keyed by the frame's ephemeral source tag (the rotating nonce
    /// in the 802.11 source field — mac-addressing-doctrine §2). This is the per-neighbour RSSI map
    /// the doctrine wants in place of the ambient per-face scalar `links` holds: two neighbours heard
    /// on one radio get distinct RSSI, which CCLF density and macro-diversity need.
    per_source: Mutex<HashMap<[u8; 6], LinkSignals>>,
}

impl LinkSignalStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Every neighbour currently known, by source nonce → its last link signals. The per-frame
    /// RSSI-per-neighbour map the doctrine's §2 nonce buys (density / macro-diversity input).
    pub fn neighbours(&self) -> Vec<([u8; 6], LinkSignals)> {
        self.per_source.lock().unwrap().iter().map(|(k, v)| (*k, *v)).collect()
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
    fn source_link(&self, src: [u8; 6]) -> Option<LinkSignals> {
        self.per_source.lock().unwrap().get(&src).copied()
    }
    fn neighbour_count(&self, fresh_within_ms: u64, now_ms: u64) -> usize {
        // Distinct source nonces heard recently — the per-frame density the doctrine's §2 map buys,
        // catching neighbours that transmit frames but never send a reception report.
        self.per_source
            .lock()
            .unwrap()
            .values()
            .filter(|ls| now_ms.saturating_sub(ls.updated_ms as u64) <= fresh_within_ms)
            .count()
    }
}

impl SignalStore<FaceId> for LinkSignalStore {
    fn set_link(&self, face: FaceId, signals: LinkSignals) {
        self.links.lock().unwrap().insert(face, signals);
    }
    fn set_node(&self, _signals: NodeSignals) {}
    fn set_neighbor(&self, _face: FaceId, _signals: NodeSignals) {}
    fn set_source_link(&self, src: [u8; 6], signals: LinkSignals) {
        self.per_source.lock().unwrap().insert(src, signals);
    }
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
    /// **TX** Tier-0 addressing (#91c): when set, outbound frames carry each object's prefix-set
    /// filter in `addr1 ‖ addr2`, with the ephemeral nonce displaced to `addr3`. `None` ⇒ broadcast
    /// `addr1` and the nonce in `addr2`.
    tx_bloom: Option<crate::GroupKey>,
    /// **RX** name filtering: the shared [`NameGate`](crate::NameGate)'s two halves — the Tier-0
    /// filter (or the NDN-NIC baseline) and an optional Tier-1.
    ///
    /// TX and RX are separate because they are separate capabilities: a relay filters on a family of
    /// prefixes it forwards while addressing by whatever object it is carrying, and a passive
    /// monitor filters without transmitting at all. `with_bloom` sets both at once for the common
    /// case; `with_tx_bloom` / `with_rx_gate` set one.
    rx_gate: Option<Arc<crate::NameGate>>,
    /// Registered-prefix table for the scheduler (P1), built by [`with_bloom`](Self::with_bloom)
    /// from the same key + prefixes as the RX gate.
    group_table: Option<Arc<crate::GroupTable>>,
    /// **Per-frame rate selection** (#82), when enabled: the cognition-decided [`TxParams`], else an
    /// adaptive/fixed [`McsPolicy`]. `None` ⇒ rate stays pure bearer state set out-of-band, the
    /// historical behaviour.
    rate: Option<Arc<crate::RatePolicy>>,
    /// **A-MSDU bundling** (#82 part 2), when enabled: outbound data frames are coalesced and handed
    /// to the bearer's [`FrameIo::inject_batch`], which the AF_PACKET and RTL/MT7612 backends
    /// override with real aggregation. This was the one genuinely one-sided feature in #82 —
    /// `MonitorWifiFace` had it and the medium did not.
    amsdu: Option<AmsduCfg>,
}

/// A-MSDU bundling parameters for the medium: flush after `max_msdus` frames or `window`, whichever
/// comes first.
#[derive(Clone, Copy)]
struct AmsduCfg {
    max_msdus: usize,
    window: Duration,
}

/// The medium's send-coalescer: one per bearer, submitting whole batches to that bearer's
/// [`FrameIo::inject_batch`].
///
/// It carries no MCS, unlike `MonitorWifiFace`'s batcher. The medium models rate as **bearer state**
/// (the driver holds it; the face sends [`TxIntent`]s), so there is no per-frame descriptor to
/// attach — which is exactly why `ndn-frame-io`'s AF_PACKET backend gained an `inject_batch` that
/// aggregates at the currently-set rate. Aggregating only through the rate-carrying spelling would
/// have made this move silently lose A-MSDU on the S1G path.
struct MediumBatcher {
    tx: mpsc::UnboundedSender<(InjectFrame, Option<McsDescriptor>)>,
}

impl MediumBatcher {
    fn spawn(
        radio: Arc<dyn FrameIo>,
        cfg: AmsduCfg,
        rate: Option<Arc<crate::RatePolicy>>,
    ) -> (Self, JoinHandle<()>) {
        let (tx, mut rx) = mpsc::unbounded_channel::<(InjectFrame, Option<McsDescriptor>)>();
        let handle = tokio::spawn(async move {
            while let Some(first) = rx.recv().await {
                // **The plan sizes the aggregate, per batch** (#83/`decided-but-unactuated`).
                // `Some(0)` = the plane asking for no aggregation, which is not the same as `None`
                // = no opinion; only the latter falls back to the face's configured cap. Read here
                // rather than at spawn so a re-decided target takes effect on the next flush, the
                // way redundancy already does.
                // `Some(0)` never reaches here — the submit site sends those straight down the
                // direct path, because a 1-frame `inject_batch` would still build a single-subframe
                // A-MSDU on AF_PACKET, i.e. aggregation framing for "do not aggregate".
                let cap = match rate.as_ref().and_then(|r| r.planned_amsdu_msdus()) {
                    Some(n) => (n as usize).max(1),
                    None => cfg.max_msdus,
                };
                let mut batch = vec![first];
                let deadline = tokio::time::Instant::now() + cfg.window;
                while batch.len() < cap {
                    match tokio::time::timeout_at(deadline, rx.recv()).await {
                        Ok(Some(f)) => batch.push(f),
                        _ => break, // window elapsed, or the face was torn down
                    }
                }
                // Two spellings, both aggregating, chosen by whether a rate was decided per frame.
                // Batching used to drop the rate on the floor: the coalescer sat before the rate
                // branch, so turning on A-MSDU turned off every decided MCS. Carrying the rate
                // through the batch is what lets the two features compose.
                let _ = if batch.iter().any(|(_, m)| m.is_some()) {
                    let last = batch
                        .iter()
                        .rev()
                        .find_map(|(_, m)| *m)
                        .unwrap_or(McsDescriptor::CONSERVATIVE);
                    radio
                        .inject_batch_at(
                            batch
                                .into_iter()
                                .map(|(f, m)| (f, m.unwrap_or(last)))
                                .collect(),
                        )
                        .await
                } else {
                    radio.inject_batch(batch.into_iter().map(|(f, _)| f).collect()).await
                };
            }
        });
        (MediumBatcher { tx }, handle)
    }

    fn submit(&self, frame: InjectFrame, mcs: Option<McsDescriptor>) -> Result<(), FaceError> {
        self.tx.send((frame, mcs)).map_err(|_| FaceError::Closed)
    }
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
            tx_bloom: None,
            rx_gate: None,
            group_table: None,
            amsdu: None,
            rate: None,
        }
    }

    /// Enable **Tier-0 name addressing** (#91c) on this medium: outbound frames are addressed by
    /// each object's prefix-set Bloom filter (`addr1 ‖ addr2`) under `key`, with the ephemeral
    /// source nonce moved to `addr3`; inbound frames are dropped before the engine unless their
    /// filter could be under one of `registered_prefixes` (given as `/`-strings). A relay passes
    /// several prefixes (its forwarding family); a leaf, one. Broadcast frames always pass.
    pub fn with_bloom(mut self, key: &crate::GroupKey, registered_prefixes: &[impl AsRef<[u8]>]) -> Self {
        let masks = crate::bloom_masks_for(key, registered_prefixes);
        // P1 ("one filter, one map"): the same (key, prefixes) that gate RX also key the slot map,
        // built HERE so the gate and the scheduler cannot disagree about what is registered.
        self.group_table = Some(Arc::new(crate::GroupTable::new(key, registered_prefixes)));
        self.with_tx_bloom(*key)
            .with_rx_gate(Arc::new(crate::NameGate::new(crate::RxFilter::Bloom(masks), None)))
    }

    /// [`with_bloom`](Self::with_bloom), with some registered prefixes marked **latency-class**
    /// (#93): those names are placed among the reserved lanes (`NDN_SCHED_RESERVE`), `L = 1`,
    /// never contending with bulk. Class rides the registration set because it is part of the
    /// SHARED slot map — every node must classify a prefix identically or their maps diverge.
    pub fn with_bloom_latency(
        mut self,
        key: &crate::GroupKey,
        registered_prefixes: &[impl AsRef<[u8]>],
        latency_prefixes: &[impl AsRef<[u8]>],
    ) -> Self {
        self = self.with_bloom(key, registered_prefixes);
        self.group_table = Some(Arc::new(
            crate::GroupTable::new(key, registered_prefixes).with_latency(latency_prefixes),
        ));
        self
    }

    /// Address outbound frames by name (Tier-0) without changing what this face accepts.
    pub fn with_tx_bloom(mut self, key: crate::GroupKey) -> Self {
        self.tx_bloom = Some(key);
        self
    }

    /// Set the inbound name gate — Tier-0 (or the #101 NDN-NIC baseline) plus an optional Tier-1 —
    /// without changing how this face addresses what it sends.
    pub fn with_rx_gate(mut self, gate: Arc<crate::NameGate>) -> Self {
        self.rx_gate = Some(gate);
        self
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

    /// Choose each data frame's **exact rate** rather than leaving it as bearer state: the
    /// cognitive control plane's decided [`TxParams`] when `planned` carries one, else `policy`
    /// (adaptive from observed RSSI, or fixed).
    ///
    /// This closes #82's last one-sided feature. `MonitorWifiFace` could act on a decided MCS and
    /// this face could not, so a `RadioPlan` mounted on a medium face decided a rate that nothing
    /// applied — the quietest kind of gap, because a plan whose rate is never actuated looks exactly
    /// like a plan that chose the rate you were already transmitting at.
    ///
    /// Robust control frames are unaffected: they keep `TxIntent::ROBUST` so the driver puts them on
    /// the basic legacy rate every neighbour can decode. So does anything sent while the legacy gate
    /// is up — the worst-overheard-receiver cap outranks a throughput-chosen rate by design.
    pub fn with_rate_policy(mut self, rate: Arc<crate::RatePolicy>) -> Self {
        self.rate = Some(rate);
        self
    }

    /// Enable **A-MSDU bundling** on every bearer's data path: outbound frames are coalesced into
    /// one batch per up-to-`max_msdus` frames or `window` elapsed, whichever comes first, and handed
    /// to that bearer's [`FrameIo::inject_batch`] — which AF_PACKET, RTL and MT7612 override with
    /// real aggregation (one MPDU carrying many MSDUs, one PHY preamble). Each MSDU stays an
    /// independent NDN packet the receiver de-aggregates, so PIT/FIB semantics are untouched.
    ///
    /// Robust control frames (reports, discovery, time beacons) **bypass** the batcher: they must
    /// reach the worst receiver now, not wait out a flush window. So does link-FEC — a coded
    /// generation already interleaves its own frames, and stacking the two would only add latency.
    ///
    /// How much this buys is the backend's business, not the face's: a driver that does not override
    /// `inject_batch` falls back to individual injection with no airtime change, no error and no
    /// log. Measure the backend before quoting a number.
    pub fn with_amsdu_batching(mut self, max_msdus: usize, window: Duration) -> Self {
        self.amsdu = Some(AmsduCfg {
            max_msdus: max_msdus.max(1),
            window,
        });
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
        self.bearers
            .iter()
            .map(|b| (b.id, b.effective_cap()))
            .collect()
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

/// How often the clock master broadcasts its time-beacon (#41 common-view). Frequent enough that a
/// slave's clock never drifts a slot between beacons, cheap enough to be negligible airtime.
const TIME_BEACON_MS: u64 = 100;

/// The send half of one bearer: the bearer-agnostic data plane and, when link-FEC is
/// on, the generation bridge + the shared parity count. The transmit rate is bearer
/// state (held in the driver), so this carries no rate — only the frame.
struct TxBearer {
    radio: Arc<dyn FrameIo>,
    /// `(bridge, redundancy)` when FEC is enabled: the wire is enqueued into a
    /// generation and the bridge emits `k + R` coded frames on this bearer.
    fec: Option<(Arc<LinkFecBridge<crate::RadioFecPin>>, Arc<AtomicU16>)>,
    /// Per-frame FEC eligibility (appropriate-traffic-only gate); `None` = all frames.
    eligible: Option<FecEligible>,
    /// Shared legacy-rate gate: when true, data injects at the basic legacy rate to reach
    /// a legacy-only-RX neighbour (worst-overheard-receiver cap). `None` = decided rate.
    legacy_gate: Option<Arc<AtomicBool>>,
    /// This node's ephemeral rotating source nonce (mac-addressing-doctrine §2) — stamped into the
    /// 802.11 source field of every frame, replacing the old fixed `DEFAULT_SRC` constant. Shared
    /// (one identity per node) across all bearers.
    source: Arc<EphemeralSource>,
    /// The data-centric time-slice (#61) + FHSS (#40) transmit scheduler, when configured
    /// (`NDN_SCHED_*`). `None` ⇒ no gating, the historical send path. Per-bearer so a hop retunes its
    /// own radio; the slot timing is identical on every bearer (one common-view clock per node).
    sched: Option<Arc<crate::FaceScheduler>>,
    /// Tier-0 addressing (#91c): when set, the frame's `addr1 ‖ addr2` carry the object's
    /// prefix-set filter and the nonce moves to `addr3`. `None` ⇒ broadcast `addr1`, nonce in
    /// `addr2`. Shared (`Arc`) across this face's bearers so one object's fragments resolve to the
    /// same filter whichever bearer each goes out on — the cache is per *object*, not per radio.
    tier0: Option<Arc<crate::Tier0Addresser>>,
    /// Per-frame rate selection (#82). `None` ⇒ the driver's current rate stands.
    rate: Option<Arc<crate::RatePolicy>>,
    /// A-MSDU coalescer for this bearer's data path (#82 part 2). `None` ⇒ inject each frame
    /// directly. Never used for robust control frames, and never combined with FEC.
    batcher: Option<MediumBatcher>,
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
        let legacy = self
            .legacy_gate
            .as_ref()
            .is_some_and(|g| g.load(Ordering::Relaxed));
        // Data-centric time-slice/FHSS gate (#61/#40): wait for this name-group's owned slot and/or
        // retune to its hop channel, from the name + the common-view clock. Robust control frames
        // (reports / discovery) bypass — they must reach the worst receiver now, not wait on a data
        // slot (they already ride the basic legacy rate). Off unless `NDN_SCHED_*` is set.
        if !robust && let Some(sched) = &self.sched {
            sched.gate(&wire).await;
        }
        // ── Address the frame FIRST, then decide how it goes out ─────────────────────────────
        //
        // Tier-0 (#91c): address by the object's prefix-set filter in addr1‖addr2, nonce → addr3.
        // A non-first fragment (no inner name) has no filter of its own, so it falls back to
        // broadcast — which every receiver's Bloom filter admits (safe over-accept; the object's
        // first fragment already carried the discriminating filter).
        //
        // This block used to sit *after* the FEC branch, so a coded frame never reached it: the FEC
        // path returned early and the sink supplied a fixed broadcast address and a nonce
        // snapshotted once at spawn. Enabling link-FEC therefore switched Tier-0 addressing and §2
        // nonce rotation off, silently. Computing the address before the branch is what makes the
        // two paths incapable of disagreeing (#82).
        let nonce = self.source.current(super::now_ms() as u64);
        let (dst, src, addr3) = match self.tier0.as_ref().and_then(|t| t.wire_for(&wire)) {
            // addr1 = filter hi, addr2 = filter lo, addr3 = the §2 per-frame RSSI key displaced
            // out of addr2 by the filter.
            Some(bf) => (
                bf[..6].try_into().unwrap(),
                bf[6..].try_into().unwrap(),
                Some(nonce),
            ),
            // Doctrine §2: the source field carries this node's ephemeral rotating nonce, not a
            // fixed host tag — inert to real networks, no routing meaning, per-frame RSSI key.
            None => (BROADCAST, nonce, None),
        };

        // The rate this frame should ride, if any is decided. Computed BEFORE the FEC branch so a
        // coded generation can pin it: see the comment at the pin below.
        let decided = (!robust && !legacy)
            .then(|| self.rate.as_ref().map(|r| r.select()))
            .flatten();

        // Only route through the FEC coder when there is parity to add AND this frame
        // is FEC-eligible (appropriate-traffic-only) AND it is not a robust control frame.
        // At R=0 the generation batching would cost the tail-flush latency for no recovery;
        // for an ineligible class (real-time/best-effort) a late-recovered frame is dead
        // weight — all bypass and inject directly. The peer's decoder passes an uncoded
        // frame straight through, so mixing coded/uncoded frames is safe.
        if !robust {
            if let Some((bridge, r)) = &self.fec {
                // The plan is the authority when one is bound; the shared `AtomicU16` is the
                // channel cognition's `MediumActuator` writes when it is not. Reading only the
                // atomic meant a `RadioPlan` could decide `link_fec_redundancy` and have nothing
                // apply it unless a separate actuator happened to be running — the defect this
                // crate is named for in `decided-but-unactuated`.
                let parity = self
                    .rate
                    .as_ref()
                    .and_then(|rp| rp.planned_redundancy())
                    .unwrap_or_else(|| r.load(Ordering::Relaxed));
                let eligible = self.eligible.as_ref().is_none_or(|pred| pred(&wire));
                if parity > 0 && eligible {
                    // The generation takes the opening frame's address, intent AND rate, so coded
                    // traffic keeps Tier-0 addressing, the legacy-rate cap, and the decided MCS.
                    //
                    // `mcs` was `None` here until an on-air run caught it. The reasoning was "this
                    // face holds rate as bearer state" — true before `with_rate_policy` existed,
                    // false after: with a policy bound and FEC on, EVERY data frame takes this
                    // branch, so `inject_at` was never reached and no frame ever carried a decided
                    // rate. The old `MonitorWifiFace` pinned `mcs: Some(..)` into its `WifiPin`;
                    // unifying the sink dropped that, and the loopback test missed it because it
                    // exercised rate and FEC separately, never together.
                    //
                    // MEASURED (a81a → 881a, ch149, 2684 coded frames): the receiver decoded every
                    // `new`-arm frame at the *previous* period's MCS — the rate some other caller
                    // had last left in the bearer — while the direct-inject control arm tracked its
                    // plan exactly. A decided rate that reaches no frame is this codebase's
                    // signature defect, reintroduced by a refactor and invisible to every test that
                    // did not put both features on at once.
                    return bridge.send(
                        wire,
                        crate::RadioFecPin {
                            dst,
                            src,
                            addr3,
                            intent,
                            mcs: decided,
                        },
                        Some(parity),
                    );
                }
            }
        }

        let frame = InjectFrame {
            payload: wire,
            tx: intent,
            dst,
            src,
            addr3,
        };
        // A-MSDU bundling (#82 part 2): a non-robust data frame is coalesced instead of injected
        // one at a time. Robust control frames fall through — a report or time beacon must reach the
        // worst receiver *now*, and holding one for a flush window would blunt exactly the
        // worst-overheard-receiver reach the ROBUST intent exists to guarantee.
        //
        // So does a frame the plan has asked not to aggregate (`amsdu_msdus = Some(0)`): the direct
        // path costs it no flush window and gives it a plain MPDU rather than a one-subframe
        // aggregate. `Some(0)` is the plane's way of saying "not this traffic" and is deliberately
        // distinct from `None` = "no opinion, keep the configured cap".
        let no_aggregate = self
            .rate
            .as_ref()
            .and_then(|r| r.planned_amsdu_msdus())
            .is_some_and(|n| n == 0);
        if !robust && !no_aggregate && let Some(bat) = &self.batcher {
            return bat.submit(frame, decided);
        }
        // Per-frame rate (#82), when a policy is bound. Skipped for robust frames and whenever the
        // legacy gate is up: both mean "reach the worst receiver", which outranks any
        // throughput-chosen rate — actuating a decided MCS there would undo the very cap that was
        // just applied.
        if let Some(mcs) = decided {
            return self.radio.inject_at(frame, mcs).await;
        }
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

    /// This face's transmit scheduler, when `NDN_SCHED_*` configured one. Exposed so an experiment
    /// can read what the gate saw — in particular
    /// [`ambient_frames`](crate::FaceScheduler::ambient_frames), which distinguishes "our slots were
    /// busy" from "the channel was busy". Every bearer shares one node clock and one slot map, so the
    /// first bearer's scheduler is the face's.
    pub fn scheduler(&self) -> Option<Arc<crate::FaceScheduler>> {
        self.tx.first().and_then(|b| b.sched.clone())
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
            group_table,
            bearers,
            signal_sink,
            fec,
            legacy_gate,
            tx_bloom,
            rx_gate,
            amsdu,
            rate,
        } = cfg;

        let (tx_chan, rx_chan) = mpsc::unbounded_channel();
        let mut tx = Vec::with_capacity(bearers.len());
        let mut tasks = Vec::with_capacity(bearers.len());

        // This node's ephemeral source identity (mac-addressing-doctrine §2): one per-boot random
        // nonce, shared across bearers, rotating every 5 minutes to bound linkability. Seeded from
        // wall-clock nanos ⊕ pid ⊕ face id — non-cryptographic per-boot entropy (a stronger RNG is a
        // drop-in replacement for `boot_seed` without touching anything downstream).
        const NONCE_ROTATION_MS: u64 = 5 * 60 * 1000;
        let boot_seed = {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);
            nanos ^ ((std::process::id() as u64) << 32) ^ (id.0 as u64).wrapping_mul(0x9E37_79B9)
        };
        let source = Arc::new(EphemeralSource::new(boot_seed, NONCE_ROTATION_MS));

        // One Tier-0 addresser for the whole face (not per bearer): its cache is keyed by LP base
        // sequence, i.e. by *object*, and an object's fragments may fan out across bearers.
        let tier0 = tx_bloom.map(|k| Arc::new(crate::Tier0Addresser::new(k)));

        for b in bearers {
            // #83: the radio's self-description outranks the caller's assertion, and a mismatch is
            // said out loud. A capability that is asserted and never checked against the hardware is
            // how `agile` became decorative (#98); this is the same failure caught one layer up.
            if let Some(p) = &b.profile {
                let declared = p.capability();
                if declared != b.cap {
                    tracing::warn!(
                        target: "monitor-wifi", face = id.0, radio = b.id.0,
                        "capability mismatch: caller asserted {:?}, radio declares {:?} — using the \
                         radio's",
                        b.cap, declared
                    );
                }
            }

            // One link-FEC bridge per bearer (shared TX-encode / RX-decode) when enabled: the sink
            // injects each coded frame on this bearer, and the reader feeds captured frames through
            // the same bridge's decoder.
            //
            // The sink is `crate::RadioFecSink`, shared with `MonitorWifiFace` (#82). It replaced
            // `ndn-coding`'s generic `FrameIoSink`, which took a fixed broadcast dst and **one nonce
            // snapshotted for the bridge's whole lifetime** — so turning link-FEC on turned Tier-0
            // addressing and §2 nonce rotation off. Address, nonce and intent now ride the
            // per-generation pin, resolved by the same code the direct send path uses.
            let bridge = fec
                .as_ref()
                .map(|fc| {
                    Arc::new(LinkFecBridge::spawn(
                        crate::RadioFecSink { radio: b.radio.clone() },
                        fc.k,
                        0,
                        fc.window,
                    ))
                });
            // The data-centric time-slice/FHSS scheduler (#61/#40), per bearer so a hop retunes its own
            // radio via that bearer's knobs. Constructed from `NDN_SCHED_*`; `None` ⇒ send path
            // unchanged. Shared (Arc) with this bearer's RX reader so inbound hardware stamps feed the
            // scheduler's disciplined clock (#41). Bandwidth defaults to 20 MHz for hops across
            // non-overlapping channels.
            let sched = crate::FaceScheduler::from_env(b.knobs.clone(), crate::Bandwidth::default(), mtu)
                .map(|s| {
                    // Give the scheduler this bearer's rate policy so the #84 guard band sizes its
                    // airtime estimate from the rate we will actually transmit at, not from the
                    // conservative worst case (which would defer frames that would have fitted).
                    let s = match &rate {
                        Some(r) => s.with_rate(r.clone()),
                        None => s,
                    };
                    // P1: slot key = longest registered prefix; RX attribution by mask AND.
                    match &group_table {
                        Some(t) => s.with_groups(t.clone()),
                        None => s,
                    }
                })
                // **Refuse a hop schedule this radio cannot serve** (#97/#98). `set_channel` on the
                // Wi-Fi monitor parts is a ~16 ms blocking call; against a short dwell the radio
                // spends most of its life retuning and the "schedule" is thrashing, not frequency
                // diversity. That was known and written in a comment; now the capability carries the
                // measured cost and the face acts on it instead of hopping anyway.
                .map(|s| s.vet_hop(&b.cap))
                .map(Arc::new);
            if let Some(s) = &sched {
                tracing::info!(target: "monitor-wifi", face = id.0, "{}", s.describe());
                // **What was this run actually configured with?** (#81) 129 NDN_* variables exist
                // and nothing recorded which were set, so a measurement could not be reproduced
                // from its own output and a misspelled name was indistinguishable from an unset
                // one. Printed once per scheduled face, alongside the schedule it produced.
                let env = ndn_env::describe();
                if !env.is_empty() {
                    tracing::info!(target: "monitor-wifi", face = id.0, "{env}");
                }
            }
            // A-MSDU coalescer for this bearer (#82 part 2). Mutually exclusive with link-FEC:
            // the FEC bridge already emits a generation's k+R frames back-to-back, and batching on
            // top of it would only add the flush window to every generation's latency.
            let batcher = match (&amsdu, &fec) {
                (Some(cfg), None) => {
                    let (bat, handle) =
                        MediumBatcher::spawn(b.radio.clone(), *cfg, rate.clone());
                    tasks.push(handle);
                    Some(bat)
                }
                (Some(_), Some(_)) => {
                    tracing::warn!(
                        target: "monitor-wifi", face = id.0, radio = b.id.0,
                        "A-MSDU batching ignored on this bearer: link-FEC is enabled and the two \
                         are mutually exclusive"
                    );
                    None
                }
                _ => None,
            };
            tx.push(TxBearer {
                radio: b.radio.clone(),
                batcher,
                fec: bridge
                    .clone()
                    .zip(fec.as_ref().map(|fc| fc.redundancy.clone())),
                eligible: fec.as_ref().and_then(|fc| fc.eligible.clone()),
                legacy_gate: legacy_gate.clone(),
                source: source.clone(),
                sched: sched.clone(),
                tier0: tier0.clone(),
                rate: rate.clone(),
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
            let sched_rx = sched.clone();
            let rate_rx = rate.clone();
            let rx_gate = rx_gate.clone();
            tasks.push(tokio::spawn(async move {
                let mut last_mesh_cv = 0u64; // last mesh common-view observation count ingested (#74)
                loop {
                    match radio.recv_frame().await {
                        Ok(f) => {
                            // #41: feed the frame's hardware RX timestamp into the scheduler's
                            // disciplined clock — this is the face consuming `.stamp`, the gap the
                            // shared RadioHwClock was built to close. Cheap; only when scheduling is on.
                            if let (Some(sched), Some(stamp)) = (sched_rx.as_ref(), f.stamp.as_ref()) {
                                sched.on_rx_stamp(stamp);
                            }
                            // #88: the busy mark + per-slot evidence, for EVERY captured frame. This
                            // used to ride on the stamp branch above, so a radio whose driver reports
                            // no TSFT never marked the medium busy at all and claimed every slot.
                            if let Some(sched) = sched_rx.as_ref() {
                                // P1: hand the scheduler the Tier-0 bytes so attribution is a mask
                                // AND, not a per-frame TLV parse (parse survives only for
                                // broadcast-addressed legacy frames + first-sighting cold paths).
                                sched.observe_rx(f.group.as_ref(), f.addr.as_ref(), f.addr3.as_ref(), &f.payload);
                            }
                            // #74: the MESH hardware common-view — discipline the scheduler's clock to a
                            // neighbour's HW-TSF-stamped timing beacon (pair (peer_tsf, our_rxtsfl), both
                            // hardware) → self-contained sub-µs `CommonView` epoch, no AP. This is the
                            // face consuming the µs hardware clock (upgrading `cv` mode from the ms
                            // software beacon). Poll the driver's mesh side channel; ingest fresh obs.
                            if let Some(sched) = sched_rx.as_ref()
                                && let Some(mcv) = radio.mesh_common_view()
                                && mcv.count != last_mesh_cv
                            {
                                last_mesh_cv = mcv.count;
                                // #75: if the neighbour advertised a belief, compose multi-hop through it;
                                // otherwise treat it as a direct stratum-0 reference (single-hop, #74).
                                match mcv.belief {
                                    Some(b) => sched.ingest_common_view(mcv.peer_tsf, mcv.our_rxtsfl, b),
                                    None => sched.ingest_mesh_beacon(mcv.peer_tsf, mcv.our_rxtsfl, mcv.bssid),
                                }
                            }
                            // Time-beacon (#41 common-view): discipline the common-view clock to the
                            // master's reference and SUPPRESS the frame — it is a clock signal, not NDN
                            // traffic, so it never reaches the engine.
                            if let Some(sched) = sched_rx.as_ref()
                                && let Some(ref_us) = crate::FaceScheduler::parse_beacon(&f.payload)
                            {
                                sched.ingest_time_ref(ref_us);
                                continue;
                            }
                            // Tier-0 name filter (#91c): drop frames not under any registered prefix
                            // before they reach signals or the engine. The frame's filter is
                            // addr1‖addr2 (f.group‖f.addr); broadcast (no group) always passes.
                            // #82: the SAME gate `MonitorWifiFace` uses, from the same code. This
                            // was an open-coded Tier-0-only copy — no Tier-1, no NDN-NIC baseline, no
                            // drop accounting — and every filtering feature added recently landed
                            // only on the other face. Sharing it is what stops the two diverging.
                            if let Some(gate) = rx_gate.as_ref()
                                && !gate.admits(f.group, f.addr, &f.payload)
                            {
                                continue;
                            }
                            // The sender's ephemeral nonce is in addr3 under the Tier-0 layout, else
                            // in addr2 (legacy). This one accessor keys per-neighbour signals and the
                            // reassembly stream correctly for both layouts.
                            // Feedback for `McsPolicy::Adaptive` (#82): the RX path is what makes
                            // the TX path adaptive, so the policy is shared across the two.
                            if let (Some(rate), Some(rssi)) = (rate_rx.as_ref(), f.rssi_dbm) {
                                rate.observe_rssi(rssi);
                            }
                            let nonce = f.addr3.or(f.addr);
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
                                // Doctrine §2: also attribute this RSSI to the *neighbour* by its
                                // ephemeral source nonce (addr3 under Tier-0, addr2 legacy), so the
                                // store is a per-neighbour map, not an ambient per-face scalar.
                                if let Some(src) = nonce {
                                    sink.set_source_link(src, ls);
                                }
                            }
                            let addr = nonce.map(FaceAddr::Ether);
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

        // The clock master broadcasts the time-beacon (#41 common-view) on its first bearer, so every
        // `cv` node disciplines its slot clock to one shared timeline — no NTP, no AP. Injected raw
        // (bypasses the slot gate: the clock signal must never wait on a data slot).
        if let Some(first) = tx.first()
            && let Some(sched) = first.sched.clone()
            && sched.is_master()
        {
            let radio = first.radio.clone();
            let src = source.clone();
            tasks.push(tokio::spawn(async move {
                let mut tick =
                    tokio::time::interval(std::time::Duration::from_millis(TIME_BEACON_MS));
                loop {
                    tick.tick().await;
                    // Time beacons are broadcast control, not name-addressed: they must reach every
                    // node regardless of its Tier-0 filter, so addr1 stays broadcast (which always
                    // passes) and the nonce rides addr2 as in the legacy layout.
                    let frame = InjectFrame {
                        payload: sched.build_beacon(),
                        tx: TxIntent::ROBUST,
                        dst: BROADCAST,
                        src: src.current(super::now_ms() as u64),
                        addr3: None,
                    };
                    let _ = radio.inject(frame).await; // transient errors: keep the clock alive
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
    use crate::{DEFAULT_SRC, LoopbackMonitorBus, McsPolicy, TxParams};
    use ndn_transport::Transport;
    use std::time::Duration;

    fn cap() -> RadioCapability {
        RadioCapability::wifi_monitor_5ghz(vec![149])
    }

    fn name_tlv(comps: &[&[u8]]) -> Vec<u8> {
        let mut inner = Vec::new();
        for c in comps {
            inner.push(0x08);
            inner.push(c.len() as u8);
            inner.extend_from_slice(c);
        }
        let mut t = vec![0x07, inner.len() as u8];
        t.extend_from_slice(&inner);
        t
    }
    fn data_pkt(name: &[u8]) -> Bytes {
        let mut d = vec![0x06, name.len() as u8];
        d.extend_from_slice(name);
        Bytes::from(d)
    }

    /// The multi-radio medium carries Tier-0 addressing end to end (#91c). A producer
    /// `with_bloom` addresses each object by its name's prefix-set filter (`addr1‖addr2`) with
    /// the ephemeral nonce in `addr3`; a relay registered on the coarse `/x` receives the whole
    /// family, an unrelated `/w` node receives none, and — the nonce check — two objects with
    /// *different* names arrive under the *same* neighbour address (the per-transmitter nonce
    /// from addr3), not the name-derived filter half that sits in addr2.
    #[tokio::test]
    async fn medium_bloom_filters_and_keys_nonce_from_addr3() {
        let key = crate::OPEN_GROUP_KEY;
        let bus = LoopbackMonitorBus::new();
        let producer = RadioMediumFace::new(
            FaceId(1),
            vec![RadioBearer::new(RadioId(1), Arc::new(bus.endpoint(1, -50)), cap())],
        )
        .with_bloom(&key, &["/x"])
        .build();
        let relay = RadioMediumFace::new(
            FaceId(2),
            vec![RadioBearer::new(RadioId(2), Arc::new(bus.endpoint(2, -50)), cap())],
        )
        .with_bloom(&key, &["/x"])
        .build();
        let other = RadioMediumFace::new(
            FaceId(3),
            vec![RadioBearer::new(RadioId(3), Arc::new(bus.endpoint(3, -50)), cap())],
        )
        .with_bloom(&key, &["/w"])
        .build();

        producer.send_bytes(data_pkt(&name_tlv(&[b"x", b"y"]))).await.unwrap();
        producer.send_bytes(data_pkt(&name_tlv(&[b"x", b"z"]))).await.unwrap();

        // The /x relay hears both names; capture their neighbour addresses (the ether bytes).
        let mut addrs = Vec::new();
        for _ in 0..2 {
            let (_, a) = tokio::time::timeout(Duration::from_secs(2), relay.recv_bytes_with_addr())
                .await
                .expect("relay hears the /x family")
                .unwrap();
            let Some(ndn_transport::FaceAddr::Ether(bytes)) = a else {
                panic!("expected an ether neighbour address, got {a:?}");
            };
            addrs.push(bytes);
        }
        assert_eq!(
            addrs[0], addrs[1],
            "two different-name objects from one producer share ONE neighbour address — the addr3 \
             nonce, not the name-derived addr2 filter half"
        );

        // The /w node hears neither (Tier-0 filter drops before the engine).
        let none = tokio::time::timeout(Duration::from_millis(200), other.recv_bytes_with_addr()).await;
        assert!(none.is_err(), "an unrelated prefix must not pass the medium's Bloom filter");
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
        let peer_a: Arc<dyn FrameIo> = Arc::new(bus_a.endpoint(10, -50));
        let peer_b: Arc<dyn FrameIo> = Arc::new(bus_b.endpoint(20, -50));

        // The medium face: capability 1 on bus A, capability 2 on bus B.
        let bearers = vec![
            RadioBearer::new(RadioId(1), Arc::new(bus_a.endpoint(1, -55)), cap()),
            RadioBearer::new(RadioId(2), Arc::new(bus_b.endpoint(2, -55)), cap()),
        ];
        let medium = RadioMediumFace::new(FaceId(7), bearers).build();

        // RX union: a frame on bus A and a frame on bus B both arrive at the face.
        let inject = |radio: Arc<dyn FrameIo>, byte: u8| async move {
            let frame = InjectFrame {
                payload: Bytes::from(vec![byte; 16]),
                tx: TxIntent::CONSERVATIVE,
                dst: BROADCAST,
                src: DEFAULT_SRC,
                addr3: None,
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
        let peer: Arc<dyn FrameIo> = Arc::new(bus.endpoint(2, -50));
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
                addr3: None,
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
        let peer: Arc<dyn FrameIo> = Arc::new(bus.endpoint(9, -50));
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

    /// **The medium's A-MSDU batcher must reach `FrameIo::inject_batch`, and robust frames must
    /// bypass it.**
    ///
    /// A-MSDU was the one feature #82 listed that `RadioMediumFace` genuinely lacked rather than
    /// duplicated. Moving it down is only worth anything if the batch arrives at the method the
    /// backends override — the medium sends `TxIntent`s and holds rate as bearer state, so it can
    /// only use the rate-free `inject_batch` spelling, and `AfPacketBackend` had to grow one.
    ///
    /// The bypass half matters just as much: a reception report or time beacon held for a flush
    /// window is a report that arrives late to the receiver it exists to reach.
    #[tokio::test]
    async fn medium_amsdu_batches_data_and_never_delays_robust_frames() {
        struct BatchSpy {
            batches: std::sync::Mutex<Vec<usize>>,
            singles: std::sync::Mutex<Vec<TxIntent>>,
        }

        #[async_trait::async_trait]
        impl FrameIo for BatchSpy {
            async fn inject(&self, frame: InjectFrame) -> Result<(), FaceError> {
                self.singles.lock().unwrap().push(frame.tx);
                Ok(())
            }
            async fn inject_batch(&self, frames: Vec<InjectFrame>) -> Result<(), FaceError> {
                self.batches.lock().unwrap().push(frames.len());
                Ok(())
            }
            async fn recv_frame(&self) -> Result<crate::CapturedFrame, FaceError> {
                std::future::pending().await
            }
        }

        let spy = Arc::new(BatchSpy {
            batches: std::sync::Mutex::new(Vec::new()),
            singles: std::sync::Mutex::new(Vec::new()),
        });
        let medium = RadioMediumFace::new(
            FaceId(7),
            vec![RadioBearer::new(RadioId(0), spy.clone(), cap())],
        )
        .with_amsdu_batching(8, Duration::from_millis(5))
        .build();

        for i in 0..4u8 {
            medium.send_bytes(data_pkt(&name_tlv(&[b"x", &[i]]))).await.unwrap();
        }
        // A cooperative report — must go out immediately, not into the batch.
        medium.send_robust(Bytes::from_static(b"report")).await.unwrap();

        tokio::time::sleep(Duration::from_millis(60)).await;

        let batches = spy.batches.lock().unwrap().clone();
        let singles = spy.singles.lock().unwrap().clone();
        assert_eq!(
            batches.iter().sum::<usize>(),
            4,
            "all four data frames must arrive via inject_batch (the backends' aggregation hook), \
             got batches={batches:?} singles={singles:?}"
        );
        assert_eq!(
            singles.len(),
            1,
            "exactly the robust frame bypasses the batcher: {singles:?}"
        );
        assert_eq!(
            singles[0].reliability,
            Reliability::MostRobust,
            "the frame that bypassed must be the robust one"
        );
    }
    /// **The medium's coded frames must carry Tier-0 addressing and a fresh §2 nonce too.**
    ///
    /// The medium's FEC path used `ndn-coding`'s generic `FrameIoSink`, constructed with a fixed
    /// `BROADCAST` dst and one nonce snapshotted for the bridge's whole lifetime — and the FEC
    /// branch returned *before* the block that computes Tier-0 addressing. So enabling link-FEC
    /// silently switched off both name addressing and nonce rotation on this face, the same defect
    /// `MonitorWifiFace` had in its own dialect (#82).
    ///
    /// Both faces now share `RadioFecSink` and pin the address the direct path resolves. This
    /// asserts the coded frames land under the registered prefix, and that addr3 carries a nonce
    /// rather than the sink's fixed source.
    #[tokio::test]
    async fn medium_tier0_addressing_survives_link_fec() {
        use crate::OPEN_GROUP_KEY;

        const K: usize = 2;
        let key = OPEN_GROUP_KEY;
        let masks = crate::bloom_masks_for(&key, &[b"/x".as_slice()]);

        let bus = LoopbackMonitorBus::new();
        let sniffer = Arc::new(bus.endpoint(99, -70));
        let medium = RadioMediumFace::new(
            FaceId(5),
            vec![RadioBearer::new(RadioId(0), Arc::new(bus.endpoint(5, -50)), cap())],
        )
        .with_bloom(&key, &[b"/x/y".as_slice()])
        .with_link_fec(
            K,
            Duration::from_millis(20),
            Arc::new(AtomicU16::new(1)),
            Arc::new(LossMeter::default()),
        )
        .build();

        let collector = tokio::spawn(async move {
            let mut seen = Vec::new();
            while let Ok(Ok(f)) =
                tokio::time::timeout(Duration::from_millis(150), sniffer.recv_frame()).await
            {
                seen.push((f.group, f.addr, f.addr3));
            }
            seen
        });
        tokio::time::sleep(Duration::from_millis(10)).await;

        let wire = data_pkt(&name_tlv(&[b"x", b"y"]));
        for _ in 0..K {
            medium.send_bytes(wire.clone()).await.unwrap();
        }
        let frames = collector.await.unwrap();

        assert!(!frames.is_empty(), "the coded generation must reach the bus");
        for (i, (a1, a2, a3)) in frames.iter().enumerate() {
            let (Some(a1), Some(a2)) = (a1, a2) else {
                panic!("coded frame {i} carries no address pair");
            };
            let mut w = [0u8; 12];
            w[..6].copy_from_slice(a1);
            w[6..].copy_from_slice(a2);
            assert!(
                masks
                    .iter()
                    .any(|m| crate::PrefixFilter::from_wire(w).may_match(m)),
                "coded frame {i} must stay addressed under /x (addr1={a1:02x?} addr2={a2:02x?})"
            );
            assert!(
                a3.is_some(),
                "coded frame {i} must carry the doctrine §2 nonce in addr3, displaced there by the \
                 filter — the old sink dropped it entirely"
            );
        }
    }

    /// Build one LP fragment: `LpPacket(0x64){ Sequence(0x51), FragIndex(0x52), FragCount(0x53),
    /// Fragment(0x50) }`. Only fragment 0 carries the Name, which is the whole point below.
    fn lp_frag(seq: u64, index: u64, count: u64, payload: &[u8]) -> Bytes {
        fn tlv(t: u8, v: &[u8]) -> Vec<u8> {
            let mut o = vec![t, v.len() as u8];
            o.extend_from_slice(v);
            o
        }
        let mut inner = Vec::new();
        inner.extend(tlv(0x51, &seq.to_be_bytes()));
        inner.extend(tlv(0x52, &index.to_be_bytes()));
        inner.extend(tlv(0x53, &count.to_be_bytes()));
        inner.extend(tlv(0x50, payload));
        let mut out = vec![0x64, inner.len() as u8];
        out.extend_from_slice(&inner);
        Bytes::from(out)
    }

    /// **Every fragment of one object must carry that object's Tier-0 filter, not just the first.**
    ///
    /// Only fragment 0 of an LP-fragmented object contains the Name TLV, so a filter derived
    /// per-frame can only be computed once. `MonitorWifiFace` handles this with a cache keyed by LP
    /// base sequence (`sequence - frag_index`), so fragments 1..n reuse the opening fragment's
    /// filter. The medium's `bloom_wire_for_wire` had no cache: it called `inner_name(wire)`, got
    /// `None` for every continuation fragment, and fell back to broadcast.
    ///
    /// That loses no data — broadcast is admitted by every receiver — but it silently surrenders the
    /// filtering for all but the first frame of every fragmented object, which on a fragmenting MTU
    /// is nearly all of the traffic. #106 measured 87.32% reject on air using the *caching* path, so
    /// collapsing the faces onto an uncached medium would have quietly invalidated that number.
    #[tokio::test]
    async fn medium_addresses_every_fragment_of_an_object_under_its_prefix() {
        use crate::OPEN_GROUP_KEY;

        let key = OPEN_GROUP_KEY;
        let masks = crate::bloom_masks_for(&key, &[b"/x".as_slice()]);

        let bus = LoopbackMonitorBus::new();
        let sniffer = Arc::new(bus.endpoint(99, -70));
        let medium = RadioMediumFace::new(
            FaceId(6),
            vec![RadioBearer::new(RadioId(0), Arc::new(bus.endpoint(6, -50)), cap())],
        )
        .with_bloom(&key, &[b"/x/y".as_slice()])
        .build();

        let collector = tokio::spawn(async move {
            let mut seen = Vec::new();
            while let Ok(Ok(f)) =
                tokio::time::timeout(Duration::from_millis(120), sniffer.recv_frame()).await
            {
                seen.push((f.group, f.addr));
            }
            seen
        });
        tokio::time::sleep(Duration::from_millis(10)).await;

        // One object /x/y split across three fragments; only fragment 0 carries the Name.
        let named = data_pkt(&name_tlv(&[b"x", b"y"]));
        medium.send_bytes(lp_frag(100, 0, 3, &named)).await.unwrap();
        medium.send_bytes(lp_frag(101, 1, 3, b"tail-a")).await.unwrap();
        medium.send_bytes(lp_frag(102, 2, 3, b"tail-b")).await.unwrap();

        let frames = collector.await.unwrap();
        assert_eq!(frames.len(), 3, "all three fragments must reach the bus");
        for (i, (a1, a2)) in frames.iter().enumerate() {
            let (Some(a1), Some(a2)) = (a1, a2) else {
                panic!("fragment {i} carries no address pair");
            };
            let mut w = [0u8; 12];
            w[..6].copy_from_slice(a1);
            w[6..].copy_from_slice(a2);
            assert!(
                masks
                    .iter()
                    .any(|m| crate::PrefixFilter::from_wire(w).may_match(m)),
                "fragment {i} must carry the object's /x filter, not fall back to broadcast \
                 (addr1={a1:02x?} addr2={a2:02x?})"
            );
        }
    }

    /// **A rate the plan decides must change what the medium transmits — and must still lose to the
    /// worst-receiver cap.**
    ///
    /// `MonitorWifiFace` could act on a decided MCS; this face could not, so a `RadioPlan` mounted
    /// on a medium face chose a rate that nothing applied (#82's last one-sided feature). That gap
    /// is invisible from the decision side, so this asserts on which call the backend received.
    ///
    /// The second half matters as much: when cognition raises the legacy gate because a
    /// legacy-only-RX neighbour is present, the frame must go out at the basic legacy rate. The
    /// medium expresses that as `TxIntent::ROBUST` on the plain `inject` path, which every driver
    /// maps to the basic rate — *not* by picking a low MCS itself.
    ///
    /// Recording `set_rate` state alone was not enough to see this: the rate a driver holds is
    /// sticky, so after one `inject_at(.., MCS7)` the spy reported MCS 7 for the *next* frame too,
    /// even though the medium never asked for it. Asserting on the call that was made, rather than
    /// on leftover state, is what makes the distinction visible.
    #[tokio::test]
    async fn medium_actuates_the_planned_rate_but_the_legacy_gate_outranks_it() {
        #[derive(Debug, PartialEq)]
        enum Call {
            /// `inject_at` — an exact rate was demanded for this frame.
            At(u8),
            /// Plain `inject` — the rate is whatever the bearer holds; the intent carries the
            /// robustness the driver maps to a rate.
            Plain(Reliability),
        }

        struct RateSpy {
            calls: std::sync::Mutex<Vec<Call>>,
        }

        #[async_trait::async_trait]
        impl FrameIo for RateSpy {
            async fn inject(&self, f: InjectFrame) -> Result<(), FaceError> {
                self.calls.lock().unwrap().push(Call::Plain(f.tx.reliability));
                Ok(())
            }
            async fn inject_at(
                &self,
                _f: InjectFrame,
                mcs: McsDescriptor,
            ) -> Result<(), FaceError> {
                self.calls.lock().unwrap().push(Call::At(mcs.index));
                Ok(())
            }
            async fn recv_frame(&self) -> Result<crate::CapturedFrame, FaceError> {
                std::future::pending().await
            }
        }

        let spy = Arc::new(RateSpy {
            calls: std::sync::Mutex::new(Vec::new()),
        });
        let gate = Arc::new(AtomicBool::new(false));
        let plan = Arc::new(std::sync::RwLock::new(Some(TxParams {
            rate: ndn_radio_cognition::RateParams::Wifi(ndn_radio_cognition::WifiRate {
                mcs: Some(7),
                ..Default::default()
            }),
            ..Default::default()
        })));

        let medium = RadioMediumFace::new(
            FaceId(8),
            vec![RadioBearer::new(RadioId(0), spy.clone(), cap())],
        )
        .with_legacy_gate(gate.clone())
        .with_rate_policy(Arc::new(
            crate::RatePolicy::new(McsPolicy::Fixed(McsDescriptor::CONSERVATIVE))
                .with_planned(plan),
        ))
        .build();

        medium.send_bytes(Bytes::from_static(b"planned")).await.unwrap();
        // A legacy-only-RX neighbour appears: reach beats throughput.
        gate.store(true, Ordering::Relaxed);
        medium.send_bytes(Bytes::from_static(b"capped")).await.unwrap();

        let calls = spy.calls.lock().unwrap();
        assert_eq!(
            calls[0],
            Call::At(7),
            "the plan's decided MCS must reach the radio, not just the decision plane: {calls:?}"
        );
        assert_eq!(
            calls[1],
            Call::Plain(Reliability::MostRobust),
            "with the legacy gate up the frame must go out MostRobust on the plain path, so the \
             driver drops it to the basic rate — never at the planned MCS: {calls:?}"
        );
    }

    /// **A decided rate must reach FEC-CODED frames too** — the combination, not each feature alone.
    ///
    /// Found on air, not here. `medium_actuates_the_planned_rate_but_the_legacy_gate_outranks_it`
    /// tests rate with FEC off; `medium_tier0_addressing_survives_link_fec` tests FEC with no rate
    /// policy. Both passed while the intersection was broken: with a policy bound *and* FEC on,
    /// every data frame takes the FEC branch, which pinned `mcs: None`, so `inject_at` was never
    /// reached and coded frames rode whatever rate happened to be left in the bearer.
    ///
    /// The on-air A/B (a81a → 881a, ch149) showed it plainly: 2684 coded frames all decoded at the
    /// *previous* period's MCS, while a direct-inject control arm on the same radio tracked its plan
    /// exactly. Two features that are individually correct can still be jointly wrong, and a suite
    /// that only tests them apart will report success.
    #[tokio::test]
    async fn medium_actuates_the_planned_rate_on_fec_coded_frames() {
        struct RateSpy {
            at: std::sync::Mutex<Vec<u8>>,
            plain: std::sync::Mutex<usize>,
        }

        #[async_trait::async_trait]
        impl FrameIo for RateSpy {
            async fn inject(&self, _f: InjectFrame) -> Result<(), FaceError> {
                *self.plain.lock().unwrap() += 1;
                Ok(())
            }
            async fn inject_at(&self, _f: InjectFrame, mcs: McsDescriptor) -> Result<(), FaceError> {
                self.at.lock().unwrap().push(mcs.index);
                Ok(())
            }
            async fn recv_frame(&self) -> Result<crate::CapturedFrame, FaceError> {
                std::future::pending().await
            }
        }

        const K: usize = 2;
        let spy = Arc::new(RateSpy {
            at: std::sync::Mutex::new(Vec::new()),
            plain: std::sync::Mutex::new(0),
        });
        let plan = Arc::new(std::sync::RwLock::new(Some(TxParams {
            rate: ndn_radio_cognition::RateParams::Wifi(ndn_radio_cognition::WifiRate {
                mcs: Some(7),
                ..Default::default()
            }),
            ..Default::default()
        })));

        let medium = RadioMediumFace::new(
            FaceId(9),
            vec![RadioBearer::new(RadioId(0), spy.clone(), cap())],
        )
        .with_rate_policy(Arc::new(
            crate::RatePolicy::new(McsPolicy::Fixed(McsDescriptor::CONSERVATIVE))
                .with_planned(plan),
        ))
        // Parity > 0, so every data frame goes through the coder.
        .with_link_fec(
            K,
            Duration::from_millis(20),
            Arc::new(AtomicU16::new(2)),
            Arc::new(LossMeter::default()),
        )
        .build();

        for i in 0..K as u8 {
            medium.send_bytes(Bytes::from(vec![i; 24])).await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(80)).await;

        let at = spy.at.lock().unwrap().clone();
        let plain = *spy.plain.lock().unwrap();
        assert!(
            !at.is_empty(),
            "coded frames must be injected AT the decided rate; {plain} went out on the plain \
             path, which rides whatever rate the bearer happens to hold"
        );
        assert!(
            at.iter().all(|m| *m == 7),
            "every coded frame must carry the plan's MCS 7, got {at:?}"
        );
        assert_eq!(plain, 0, "no coded frame may bypass the decided rate");
    }

    /// **The plan must size the aggregate.** `TxParams::amsdu_msdus` had an accessor and *zero*
    /// callers: cognition decided an A-MSDU target that reached no actuator. It survived even the
    /// session that built this batcher, because the batcher took a static bound from its builder
    /// and never asked the plan — the decided-but-unactuated defect, produced fresh while fixing
    /// two other instances of it.
    ///
    /// Three states, all distinct and all asserted on the frames the backend actually received:
    ///   * `None`    — no opinion: the face's configured cap stands.
    ///   * `Some(n)` — aggregate to n.
    ///   * `Some(0)` — do not aggregate: bypass the batcher entirely, so the frame takes the direct
    ///                 path (no flush window, plain MPDU) rather than a one-subframe A-MSDU.
    #[tokio::test]
    async fn medium_sizes_the_amsdu_from_the_plan() {
        struct Spy {
            batches: std::sync::Mutex<Vec<usize>>,
            singles: std::sync::Mutex<usize>,
        }

        #[async_trait::async_trait]
        impl FrameIo for Spy {
            async fn inject(&self, _f: InjectFrame) -> Result<(), FaceError> {
                *self.singles.lock().unwrap() += 1;
                Ok(())
            }
            async fn inject_at(&self, _f: InjectFrame, _m: McsDescriptor) -> Result<(), FaceError> {
                *self.singles.lock().unwrap() += 1;
                Ok(())
            }
            async fn inject_batch(&self, frames: Vec<InjectFrame>) -> Result<(), FaceError> {
                self.batches.lock().unwrap().push(frames.len());
                Ok(())
            }
            async fn inject_batch_at(
                &self,
                frames: Vec<(InjectFrame, McsDescriptor)>,
            ) -> Result<(), FaceError> {
                self.batches.lock().unwrap().push(frames.len());
                Ok(())
            }
            async fn recv_frame(&self) -> Result<crate::CapturedFrame, FaceError> {
                std::future::pending().await
            }
        }

        /// Send `n` frames through a medium whose plan carries `target`, and report
        /// `(batch sizes, direct injects)`.
        async fn run(target: Option<u16>, n: usize) -> (Vec<usize>, usize) {
            let spy = Arc::new(Spy {
                batches: std::sync::Mutex::new(Vec::new()),
                singles: std::sync::Mutex::new(0),
            });
            let plan = Arc::new(std::sync::RwLock::new(target.map(|t| TxParams {
                rate: ndn_radio_cognition::RateParams::Wifi(ndn_radio_cognition::WifiRate {
                    amsdu_msdus: Some(t),
                    ..Default::default()
                }),
                ..Default::default()
            })));
            let medium = RadioMediumFace::new(
                FaceId(11),
                vec![RadioBearer::new(RadioId(0), spy.clone(), cap())],
            )
            .with_rate_policy(Arc::new(
                crate::RatePolicy::new(McsPolicy::default()).with_planned(plan),
            ))
            // Configured cap of 8 — what `None` must fall back to.
            .with_amsdu_batching(8, Duration::from_millis(5))
            .build();

            for i in 0..n {
                medium.send_bytes(Bytes::from(vec![i as u8; 16])).await.unwrap();
            }
            tokio::time::sleep(Duration::from_millis(60)).await;
            let b = spy.batches.lock().unwrap().clone();
            let s = *spy.singles.lock().unwrap();
            (b, s)
        }

        // No opinion → the configured cap of 8 governs: 8 frames land in one batch.
        let (batches, singles) = run(None, 8).await;
        assert_eq!(batches, vec![8], "None must keep the configured cap (singles={singles})");

        // The plan asks for 2 → batches cap at 2, so 8 frames become four of them.
        let (batches, singles) = run(Some(2), 8).await;
        assert!(
            !batches.is_empty() && batches.iter().all(|n| *n <= 2),
            "the plan's target must bound every batch, got {batches:?} (singles={singles})"
        );
        assert_eq!(batches.iter().sum::<usize>(), 8, "and every frame still goes out");

        // The plan asks for no aggregation → nothing is batched at all.
        let (batches, singles) = run(Some(0), 4).await;
        assert!(
            batches.is_empty(),
            "amsdu_msdus=0 means do not aggregate; a one-subframe A-MSDU is not that: {batches:?}"
        );
        assert_eq!(singles, 4, "all four take the direct path");
    }

    /// **The radio's self-description must outrank the caller's assertion.** `RadioBearer::profile`
    /// documented exactly this — "keeping both makes a disagreement visible instead of letting a
    /// hand-written `RadioCapability` quietly outrank the hardware" — and then nothing read the
    /// field. #78 landed the plumbing; the contract it carried stayed unactuated, so every consumer
    /// saw the asserted `cap` while the radio's own capability sat unused on the struct. Same shape
    /// as `agile` (#98): a capability asserted and never checked against hardware.
    #[test]
    fn the_radios_own_capability_outranks_the_callers_assertion() {
        struct Truthful(RadioCapability);
        impl RadioProfile for Truthful {
            fn capability(&self) -> RadioCapability {
                self.0.clone()
            }
        }

        struct Dummy;
        #[async_trait::async_trait]
        impl FrameIo for Dummy {
            async fn inject(&self, _f: InjectFrame) -> Result<(), FaceError> {
                Ok(())
            }
            async fn recv_frame(&self) -> Result<crate::CapturedFrame, FaceError> {
                std::future::pending().await
            }
        }

        // The caller guesses 5 GHz ch149; the radio knows it is really S1G on ch1/2.
        let asserted = RadioCapability::wifi_monitor_5ghz(vec![149]);
        let real = RadioCapability::wifi_halow_s1g(vec![1, 2]);
        assert_ne!(real, asserted, "the two must actually differ or this proves nothing");

        let guessed = RadioBearer::new(RadioId(0), Arc::new(Dummy), asserted.clone());
        assert_eq!(
            guessed.effective_cap(),
            asserted,
            "with no profile the caller's assertion is all there is"
        );

        let known = RadioBearer::new(RadioId(0), Arc::new(Dummy), asserted.clone())
            .with_profile(Arc::new(Truthful(real.clone())));
        assert_eq!(
            known.effective_cap(),
            real,
            "the radio wins; believing the assertion is how a planner budgets for a band the \
             hardware does not have"
        );

        // And the medium reports the governing one, not the asserted one.
        let medium = RadioMediumFace::new(FaceId(12), vec![known]);
        assert_eq!(
            medium.capabilities(),
            vec![(RadioId(0), real)],
            "capabilities() is what a control plane registers — it must carry the radio's truth"
        );
    }
}
