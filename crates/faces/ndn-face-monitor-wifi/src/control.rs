//! The **`LinkServiceFeature` seam** — binds the pure cognitive control plane
//! ([`ndn_radio_cognition`]) to the radio face: it feeds the sense bus from the
//! signal store, runs `RadioPolicy::decide` on the engine's per-face tick, and
//! applies the resulting [`RadioPlan`] to the radio's actuators.
//!
//! Three planes wired here:
//! - **SENSE** — `tick` pulls per-face RSSI from the [`SignalView`] into
//!   [`MediumState`]; occupancy/demand/loss are fed in via the passthroughs.
//! - **DECIDE** — `tick` runs [`RadioPolicy::decide`] for each managed object.
//! - **ACT** — the plan's per-radio [`RadioAllocation`] is `apply`-ed: stateful
//!   knobs (channel/CSD/EDCCA) hit the backend directly; the per-frame [`TxParams`]
//!   land in a shared cell the face's `select_mcs` reads
//!   ([`MonitorWifiFace::with_planned_params`]). That shared cell is what makes a
//!   *decision* actually change the transmitted rate/coding — the closed loop.
//!
//! `RadioControl` is a [`LinkServiceFeature`], so once mounted via
//! [`LpLinkService::with_extra_feature`] the engine's existing per-face tick pump
//! drives the loop with no extra task management.
//!
//! [`MonitorWifiFace::with_planned_params`]: crate::MonitorWifiFace::with_planned_params
//! [`LpLinkService::with_extra_feature`]: ndn_transport::link_service::LpLinkService::with_extra_feature

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use ndn_radio_cognition::{
    ARMS, ChannelOccupancy, Context, ContextualBandit, Demand, DemandTracker, MediumState,
    MediumView, NameContext, NeighborReport, PolicyConfig, RadioActuators, RadioCapability, RadioId,
    RadioPlan, RadioPolicy, RadioStrategy, RateCalibrator, TxParams, apply_arm, decode_report,
    default_thresholds, encode_report, reward,
};
#[cfg(any(test, feature = "libusb-backend"))]
use ndn_radio_cognition::RadioAllocation;
use ndn_signals_core::SignalView;
use ndn_transport::link_service::{InboundLpFrame, IngressCtx, LinkServiceFeature, TickCtx};

use crate::FaceId;

// One face contributes one representative receiver (its aggregate per-face RSSI)
// to the sense bus, keyed by `FaceId.0`, until per-neighbour reception reports
// exist (honest aggregate, documented limitation).

/// What a radio last transmitted, kept until its delivery outcome arrives.
#[derive(Clone, Copy)]
struct TxRecord {
    mcs: u8,
    rssi: i8,
    params: TxParams,
}

/// The control-plane feature: sense → decide → act over a node's radio faces.
pub struct RadioControl {
    medium: Mutex<MediumState>,
    policy: RadioPolicy,
    actuators: Vec<Arc<dyn RadioActuators + Send + Sync>>,
    signals: Option<Arc<dyn SignalView<FaceId> + Send + Sync>>,
    /// Which radio each face's RSSI feeds.
    face_radio: HashMap<u64, RadioId>,
    /// PIT-shadow demand: forwarding events → per-prefix [`Demand`]. When it has
    /// live demand, the managed-object set is derived from it (the forwarder drives
    /// the plane); otherwise the manual `active` set is used.
    demand_tracker: Mutex<DemandTracker>,
    /// Manually-managed objects (app-set / tests), used when no PIT demand is live.
    active: Mutex<Vec<NameContext>>,
    /// Last plans produced, for telemetry / the airtime-per-Interest measurement.
    last_plans: Mutex<Vec<RadioPlan>>,
    /// Online rate self-calibration (None ⇒ static thresholds). Learns per-MCS RSSI
    /// cliffs from delivery feedback.
    calibrator: Option<RateCalibrator>,
    /// Joint-axis contextual bandit (None ⇒ off). Sits above the policy: learns the
    /// rate × power × FEC operating point per context from reward.
    bandit: Option<Mutex<ContextualBandit>>,
    /// Last applied transmission per radio, so a later delivery outcome can be
    /// attributed back to what it was sent at (calibrator + bandit feedback).
    last_tx: Mutex<HashMap<u16, TxRecord>>,
    /// Last bandit `(context, arm)` per radio, awaiting its delivery reward.
    last_arm: Mutex<HashMap<u16, (Context, usize)>>,
    /// Probe every Nth transmission at one MCS above the chosen rate (Minstrel-style)
    /// so calibration learns the *next* rung's cliff, not just rates already in use.
    /// 0 = no probing.
    probe_interval: u32,
    probe_count: Mutex<u32>,
    /// This node's id, stamped into outgoing reception reports and used to spot the
    /// entry where a neighbour reports hearing *us* (measured outbound link). 0 = no
    /// reports.
    node_id: u64,
    /// Reception-report broadcast cadence (ms); 0 = off.
    report_interval_ms: u64,
    last_report_ms: Mutex<Option<u64>>,
    report_seq: Mutex<u32>,
    tick_interval: Duration,
    started: Instant,
}

impl RadioControl {
    pub fn new(policy: RadioPolicy) -> Self {
        Self {
            medium: Mutex::new(MediumState::new()),
            policy,
            actuators: Vec::new(),
            signals: None,
            face_radio: HashMap::new(),
            demand_tracker: Mutex::new(DemandTracker::new(4_000)),
            active: Mutex::new(Vec::new()),
            last_plans: Mutex::new(Vec::new()),
            calibrator: None,
            bandit: None,
            last_tx: Mutex::new(HashMap::new()),
            last_arm: Mutex::new(HashMap::new()),
            probe_interval: 0,
            probe_count: Mutex::new(0),
            node_id: 0,
            report_interval_ms: 0,
            last_report_ms: Mutex::new(None),
            report_seq: Mutex::new(0),
            tick_interval: Duration::from_millis(500),
            started: Instant::now(),
        }
    }

    /// Set this node's id (enables reception reports + outbound-link learning).
    pub fn with_node_id(mut self, node_id: u64) -> Self {
        self.node_id = node_id;
        self
    }

    /// Broadcast a reception report every `ms` (pull via [`outgoing_report`]; 0 = off).
    ///
    /// [`outgoing_report`]: RadioControl::outgoing_report
    pub fn with_report_interval(mut self, ms: u64) -> Self {
        self.report_interval_ms = ms;
        self
    }

    /// Build a control plane with **online rate self-calibration**: the policy's
    /// per-MCS RSSI thresholds start at the preset and are learned from delivery
    /// feedback ([`on_data`] = delivered, re-Interest = miss) toward
    /// `target_delivery` (e.g. 0.9), `step` dB per update.
    ///
    /// [`on_data`]: RadioControl::on_data
    pub fn new_calibrated(cfg: PolicyConfig, target_delivery: f32, step: f32) -> Self {
        let cell = default_thresholds();
        let policy = RadioPolicy::new(cfg).with_learned_thresholds(cell.clone());
        let calibrator = RateCalibrator::new(cell, target_delivery, step);
        Self {
            calibrator: Some(calibrator),
            probe_interval: 10, // ~10% probe budget, Minstrel-style
            ..Self::new(policy)
        }
    }

    /// Override the probe budget (every Nth transmission probes the next MCS up;
    /// 0 disables). Only meaningful with calibration.
    pub fn with_probe_interval(mut self, interval: u32) -> Self {
        self.probe_interval = interval;
        self
    }

    /// Build a control plane with the **contextual bandit** (joint rate × power × FEC
    /// learning) layered on the policy. `explore_c` is the UCB exploration constant
    /// (≈0.3–1.0). This is the rung above single-axis calibration: it learns the
    /// joint operating point per context — e.g. discovering that holding the rate but
    /// trimming power wins on a strong link (spatial reuse) where a hand-rule
    /// wouldn't. The policy supplies the baseline plan; the bandit nudges + learns.
    pub fn new_bandit(cfg: PolicyConfig, explore_c: f32) -> Self {
        let policy = RadioPolicy::new(cfg);
        Self {
            bandit: Some(Mutex::new(ContextualBandit::new(explore_c))),
            ..Self::new(policy)
        }
    }

    /// Re-tick cadence (the per-RTT control loop; keep above per-frame churn).
    pub fn with_tick_interval(mut self, interval: Duration) -> Self {
        self.tick_interval = interval;
        self
    }

    /// Read per-face RSSI from this signal store (the engine's shared one).
    pub fn with_signals(mut self, signals: Arc<dyn SignalView<FaceId> + Send + Sync>) -> Self {
        self.signals = Some(signals);
        self
    }

    /// Declare a local radio + its capabilities, and which face feeds its RSSI.
    pub fn register_radio(&mut self, radio: RadioId, face: FaceId, cap: RadioCapability) {
        self.medium.lock().unwrap().register_radio(radio, cap);
        self.face_radio.insert(face.0, radio);
    }

    /// Add an actuator for one radio (the ACT binding).
    pub fn add_actuator(&mut self, actuator: Arc<dyn RadioActuators + Send + Sync>) {
        self.actuators.push(actuator);
    }

    /// Convenience: build a [`LibUsbActuator`] over any
    /// [`RadioKnobs`](crate::RadioKnobs) backend and return the shared
    /// [`TxParams`] cell to hand to [`MonitorWifiFace::with_planned_params`], so the
    /// decided params flow into transmitted frames. An `Arc<ConcreteBackend>`
    /// coerces to `Arc<dyn RadioKnobs>` at the call site, so existing RTL callers
    /// are unchanged while `Mt7612uBackend` now plugs in identically.
    ///
    /// [`MonitorWifiFace::with_planned_params`]: crate::MonitorWifiFace::with_planned_params
    #[cfg(feature = "libusb-backend")]
    pub fn libusb_actuator(
        &mut self,
        radio: RadioId,
        knobs: Arc<dyn crate::RadioKnobs>,
    ) -> Arc<std::sync::RwLock<Option<ndn_radio_cognition::TxParams>>> {
        let cell = Arc::new(std::sync::RwLock::new(None));
        self.actuators
            .push(Arc::new(LibUsbActuator::new(radio, knobs, cell.clone())));
        cell
    }

    /// Set the named objects the plane manages (used when no PIT demand is live).
    pub fn set_active(&self, active: Vec<NameContext>) {
        *self.active.lock().unwrap() = active;
    }

    // --- forwarding-plane demand feed (PIT → Demand) ---

    /// The forwarder saw an Interest for `prefix_hash` from `downstream_face` (an
    /// in-record). Use [`ndn_radio_cognition::prefix_hash`] to derive the key. A
    /// re-expression is fed to the rate calibrator as a delivery **miss**.
    pub fn on_interest(&self, prefix_hash: u64, downstream_face: FaceId, now_ms: u64) {
        let reexpressed = self
            .demand_tracker
            .lock()
            .unwrap()
            .on_interest(prefix_hash, downstream_face.0, now_ms);
        if reexpressed {
            self.observe_delivery(false);
        }
    }

    /// The forwarder returned Data for `prefix_hash` (satisfies the in-records, and
    /// is fed to the rate calibrator as a delivery **success**).
    pub fn on_data(&self, prefix_hash: u64, now_ms: u64) {
        self.demand_tracker.lock().unwrap().on_data(prefix_hash, now_ms);
        self.observe_delivery(true);
    }

    /// Feed a delivery outcome to the learners, attributed to what each radio last
    /// transmitted: the calibrator learns the per-MCS cliff, the bandit learns the
    /// joint operating point's reward. No-op without either.
    pub fn observe_delivery(&self, delivered: bool) {
        if let Some(cal) = &self.calibrator {
            for rec in self.last_tx.lock().unwrap().values() {
                cal.observe(rec.mcs, rec.rssi, delivered);
            }
        }
        if let Some(bandit) = &self.bandit {
            // Snapshot records, then precompute per-radio max power without nesting
            // locks, then update the bandit.
            let records: Vec<(u16, TxParams)> = self
                .last_tx
                .lock()
                .unwrap()
                .iter()
                .map(|(k, r)| (*k, r.params))
                .collect();
            let max_power: HashMap<u16, u8> = {
                let m = self.medium.lock().unwrap();
                records
                    .iter()
                    .map(|(r, _)| (*r, m.capability(RadioId(*r)).map(|c| c.max_tx_power).unwrap_or(63)))
                    .collect()
            };
            let arms = self.last_arm.lock().unwrap();
            let mut b = bandit.lock().unwrap();
            for (radio, params) in &records {
                if let Some((ctx, arm)) = arms.get(radio) {
                    let r = reward(delivered, params, *max_power.get(radio).unwrap_or(&63));
                    b.update(ctx, *arm, r);
                }
            }
        }
    }

    /// Current learned per-MCS RSSI thresholds, if calibrating (telemetry / tests).
    pub fn learned_thresholds(&self) -> Option<[f32; 10]> {
        self.calibrator.as_ref().map(|c| c.thresholds())
    }

    /// Current PIT-shadow demand (telemetry / tests).
    pub fn demand_snapshot(&self, now_ms: u64) -> Vec<(u64, Demand)> {
        self.demand_tracker.lock().unwrap().snapshot(now_ms)
    }

    // --- reception-report channel (cooperative sensing) ---

    /// Encoded reception report to broadcast, if one is due (cadence + node-id set).
    /// The host wraps it as named Data on `/localhop/radio/report/<node>` (or sends
    /// it as a raw control frame) and transmits it. Pull this on each tick.
    pub fn outgoing_report(&self, now_ms: u64) -> Option<Bytes> {
        if self.report_interval_ms == 0 || self.node_id == 0 {
            return None;
        }
        {
            let mut last = self.last_report_ms.lock().unwrap();
            if let Some(t) = *last
                && now_ms.saturating_sub(t) < self.report_interval_ms
            {
                return None;
            }
            *last = Some(now_ms);
        }
        let seq = {
            let mut s = self.report_seq.lock().unwrap();
            *s = s.wrapping_add(1);
            *s
        };
        let rep = self.medium.lock().unwrap().snapshot_report(self.node_id, seq, now_ms);
        Some(Bytes::from(encode_report(&rep)))
    }

    /// Ingest a neighbour's reception report heard on `radio`: record what they hold
    /// plus their spectrum view (cooperative sensing), and — when they reported
    /// hearing this node — feed that as our **measured outbound** link quality to
    /// them, closing the rate/power loop with real data instead of reciprocity.
    /// Returns false on undecodable bytes.
    pub fn ingest_report(&self, radio: RadioId, bytes: &[u8], now_ms: u64) -> bool {
        let Some(rep) = decode_report(bytes) else {
            return false;
        };
        {
            let mut m = self.medium.lock().unwrap();
            m.observe_report(
                rep.node_id,
                NeighborReport {
                    heard_prefixes: rep.heard_prefixes.clone(),
                    quality_dbm: None,
                    spectrum: rep.spectrum.clone(),
                    ts_ms: now_ms,
                },
            );
            if self.node_id != 0
                && let Some(&(_, rssi)) =
                    rep.heard_neighbors.iter().find(|(n, _)| *n == self.node_id)
            {
                // They hear us at `rssi` on this radio → measured outbound link.
                m.observe_rx(radio, rep.node_id, Some(rssi), now_ms);
            }
        }
        true
    }

    // --- sense passthroughs (fed by the engine/forwarder/CLM scans) ---
    pub fn observe_rx(&self, radio: RadioId, neighbour: u64, rssi_dbm: Option<i8>, now_ms: u64) {
        self.medium
            .lock()
            .unwrap()
            .observe_rx(radio, neighbour, rssi_dbm, now_ms);
    }
    pub fn observe_occupancy(&self, occ: ChannelOccupancy) {
        self.medium.lock().unwrap().observe_occupancy(occ);
    }
    pub fn observe_demand(&self, prefix_hash: u64, demand: Demand) {
        self.medium.lock().unwrap().observe_demand(prefix_hash, demand);
    }
    pub fn observe_reinterest(&self, prefix_hash: u64, rate: f32, now_ms: u64) {
        self.medium
            .lock()
            .unwrap()
            .observe_reinterest(prefix_hash, rate, now_ms);
    }
    pub fn observe_rank_deficit(&self, prefix_hash: u64, deficit: f32, now_ms: u64) {
        self.medium
            .lock()
            .unwrap()
            .observe_rank_deficit(prefix_hash, deficit, now_ms);
    }
    pub fn observe_phy_per(&self, radio: RadioId, per: f32) {
        self.medium.lock().unwrap().observe_phy_per(radio, per);
    }

    /// EWMA RSSI (dBm) we hear `neighbour` at on `radio` (telemetry).
    pub fn neighbor_rssi(&self, radio: RadioId, neighbour: u64) -> Option<i8> {
        self.medium.lock().unwrap().neighbor_rssi(radio, neighbour)
    }

    /// Plans produced on the last tick (telemetry).
    pub fn last_plans(&self) -> Vec<RadioPlan> {
        self.last_plans.lock().unwrap().clone()
    }

    /// Millis since this control plane started (monotonic; drives EWMA staleness).
    pub fn now_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    /// One iteration of the loop: SENSE (pull RSSI) → DECIDE → ACT. Returns the
    /// plans (also stored for telemetry). Public so tests / a manual driver can
    /// run it without the engine tick pump.
    pub fn tick_now(&self, now_ms: u64) -> Vec<RadioPlan> {
        let _span = tracing::debug_span!(target: "named_radio", "radio_tick", now_ms).entered();
        // SENSE: fold per-face RSSI from the signal store into the medium.
        if let Some(sig) = &self.signals {
            let mut m = self.medium.lock().unwrap();
            for (&face, &radio) in &self.face_radio {
                if let Some(ls) = sig.link(FaceId(face)) {
                    m.observe_rx(radio, face, ls.rssi_dbm, now_ms);
                }
            }
        }

        // SENSE: fold PIT-shadow demand into the medium, and derive the managed-
        // object set from live demand when the forwarder is driving the plane.
        let tracked = {
            let mut t = self.demand_tracker.lock().unwrap();
            t.prune(now_ms);
            let mut m = self.medium.lock().unwrap();
            for (ph, d) in t.snapshot(now_ms) {
                m.observe_demand(ph, d);
            }
            t.active_contexts(now_ms)
        };

        // DECIDE: PIT-driven objects if any, else the manual set.
        let active = if tracked.is_empty() {
            self.active.lock().unwrap().clone()
        } else {
            tracked
        };
        let mut plans: Vec<RadioPlan> = {
            let m = self.medium.lock().unwrap();
            active
                .iter()
                .map(|ctx| self.policy.decide(ctx, &*m, now_ms))
                .collect()
        };

        // REFINE the joint operating point. The bandit (if on) selects + applies an
        // arm per managed object and remembers it for reward; otherwise calibration
        // probing (if on) occasionally samples the next rung up.
        self.last_arm.lock().unwrap().clear();
        if let Some(bandit) = &self.bandit {
            for (name_ctx, plan) in active.iter().zip(plans.iter_mut()) {
                if let Some(alloc) = plan.allocations.first_mut() {
                    let (rssi, busy, recv, max_mcs, max_power) = {
                        let m = self.medium.lock().unwrap();
                        let cap = m.capability(alloc.radio);
                        (
                            m.weakest_rssi(alloc.radio, now_ms).unwrap_or(-90),
                            alloc.channel.and_then(|ch| m.busy_pct(alloc.radio, ch)).unwrap_or(0),
                            m.receiver_count(now_ms),
                            cap.as_ref().map(|c| c.max_mcs).unwrap_or(9),
                            cap.as_ref().map(|c| c.max_tx_power).unwrap_or(63),
                        )
                    };
                    let ctx = Context::new(rssi, busy, recv, name_ctx.priority.rank());
                    let arm = bandit.lock().unwrap().select(&ctx);
                    apply_arm(&ARMS[arm], &mut alloc.params, max_mcs, max_power);
                    self.last_arm.lock().unwrap().insert(alloc.radio.0, (ctx, arm));
                }
            }
        } else if self.calibrator.is_some() && self.probe_interval > 0 {
            let probe = {
                let mut pc = self.probe_count.lock().unwrap();
                *pc = pc.wrapping_add(1);
                pc.is_multiple_of(self.probe_interval)
            };
            if probe
                && let Some(alloc) = plans.first_mut().and_then(|p| p.allocations.first_mut())
                && let Some(mcs) = alloc.params.mcs
            {
                let max = self
                    .medium
                    .lock()
                    .unwrap()
                    .capability(alloc.radio)
                    .map(|c| c.max_mcs)
                    .unwrap_or(9);
                if mcs < max {
                    alloc.params.mcs = Some(mcs + 1);
                }
            }
        }

        // ACT: apply each radio's slice. (Last-writer-wins on a radio when several
        // managed objects target it — fine for the single-managed-prefix first cut;
        // a per-egress-name apply is the next refinement.)
        for plan in &plans {
            for alloc in &plan.allocations {
                // Remember what this radio sent at, so a later delivery outcome can
                // train the calibrator and/or the bandit.
                if (self.calibrator.is_some() || self.bandit.is_some())
                    && let Some(mcs) = alloc.params.mcs
                {
                    let rssi = self
                        .medium
                        .lock()
                        .unwrap()
                        .weakest_rssi(alloc.radio, now_ms)
                        .unwrap_or(-90);
                    self.last_tx.lock().unwrap().insert(
                        alloc.radio.0,
                        TxRecord {
                            mcs,
                            rssi,
                            params: alloc.params,
                        },
                    );
                }
                if let Some(a) = self.actuators.iter().find(|a| a.radio_id() == alloc.radio)
                    && let Err(e) = a.apply(alloc)
                {
                    tracing::warn!(target: "named-radio", radio = alloc.radio.0, error = %e, "actuator apply failed");
                }
            }
        }

        // OBSERVE: emit one structured event per decision. Zero-cost without a
        // subscriber; a `tracing` subscriber (incl. tracing-opentelemetry) turns
        // these fields into logs / metrics / spans — the hook for dashboards and
        // research numbers. Target `named_radio::decision`.
        for (name_ctx, plan) in active.iter().zip(plans.iter()) {
            if plan.suppress {
                tracing::debug!(
                    target: "named_radio::decision",
                    prefix = name_ctx.prefix_hash,
                    suppress = true,
                    consistency = plan.consistency,
                    "radio: suppress (no rank to add)"
                );
            } else if let Some(a) = plan.allocations.first() {
                tracing::debug!(
                    target: "named_radio::decision",
                    prefix = name_ctx.prefix_hash,
                    strategy = self.policy.name(),
                    radio = a.radio.0,
                    channel = ?a.channel,
                    mcs = ?a.params.mcs,
                    bw = ?a.params.bw,
                    nss = ?a.params.nss,
                    ldpc = a.params.ldpc,
                    stbc = a.params.stbc,
                    csd = a.params.csd,
                    tx_power = ?a.params.tx_power,
                    link_fec = ?a.params.link_fec_redundancy,
                    edcca_ignore = a.params.edcca_ignore,
                    radios = plan.allocations.len(),
                    relay = plan.relay,
                    objective = plan.objective,
                    consistency = plan.consistency,
                    "radio: decision"
                );
            }
        }

        *self.last_plans.lock().unwrap() = plans.clone();
        plans
    }

    /// A snapshot of the control plane's current state — for the dashboard, an
    /// OpenTelemetry exporter, or a benchmark/paper run. Cheap; call at any cadence.
    pub fn telemetry(&self) -> RadioTelemetry {
        let plans = self.last_plans();
        RadioTelemetry {
            strategy: self.policy.name(),
            managed_objects: plans.len(),
            objective: plans.iter().map(|p| p.objective).fold(0.0, f32::max),
            suppressed: plans.iter().filter(|p| p.suppress).count(),
            learned_thresholds: self.learned_thresholds(),
            plans,
        }
    }
}

/// A serialisable-shaped snapshot of the radio control plane (observability).
#[derive(Clone, Debug)]
pub struct RadioTelemetry {
    /// Active [`RadioStrategy`] name.
    pub strategy: &'static str,
    pub managed_objects: usize,
    pub suppressed: usize,
    /// Worst (highest) predicted airtime-per-satisfied-Interest across active plans.
    pub objective: f32,
    /// Learned per-MCS RSSI thresholds, if calibrating.
    pub learned_thresholds: Option<[f32; 10]>,
    /// The last decisions (per managed object).
    pub plans: Vec<RadioPlan>,
}

impl LinkServiceFeature for RadioControl {
    fn name(&self) -> &'static str {
        "named-radio-control"
    }

    fn on_ingress(&self, frame: &InboundLpFrame, _ctx: &IngressCtx) {
        // Liveness: note we heard a peer on this face (RSSI itself is read from the
        // signal store in `tick`). The address, when present, is the seed for
        // per-neighbour sensing once reception reports land.
        if let Some(addr) = &frame.addr {
            let _ = addr; // reserved for per-neighbour attribution
        }
    }

    fn tick(&self, _ctx: &TickCtx) -> Option<Duration> {
        let now = self.now_ms();
        self.tick_now(now);
        Some(self.tick_interval)
    }
}

/// ACT binding over any [`RadioKnobs`](crate::RadioKnobs) backend (RTL88xx,
/// MT7612U, …): stateful knobs (channel/CSD/EDCCA/power) hit the radio; the
/// per-frame [`TxParams`] are written into a shared cell the face's `select_mcs`
/// reads. Backends that don't support a knob inherit the trait's no-op default,
/// so a less-capable radio is driven by the same actuator without special-casing.
#[cfg(feature = "libusb-backend")]
#[derive(Default, Clone, Copy, PartialEq)]
struct AppliedKnobs {
    channel: Option<(u8, u8)>, // (channel, bw_code)
    csd: Option<bool>,
    edcca: Option<bool>,
    power: Option<u8>,
}

#[cfg(feature = "libusb-backend")]
pub struct LibUsbActuator {
    radio: RadioId,
    knobs: Arc<dyn crate::RadioKnobs>,
    planned: Arc<std::sync::RwLock<Option<ndn_radio_cognition::TxParams>>>,
    /// Last values actually pushed to the radio, so unchanged knobs are not
    /// re-applied every frame (a channel retune per frame is ~16 ms — it would
    /// dominate, as the on-air run showed).
    last: Mutex<AppliedKnobs>,
}

#[cfg(feature = "libusb-backend")]
impl LibUsbActuator {
    pub fn new(
        radio: RadioId,
        knobs: Arc<dyn crate::RadioKnobs>,
        planned: Arc<std::sync::RwLock<Option<ndn_radio_cognition::TxParams>>>,
    ) -> Self {
        Self {
            radio,
            knobs,
            planned,
            last: Mutex::new(AppliedKnobs::default()),
        }
    }
}

#[cfg(feature = "libusb-backend")]
impl RadioActuators for LibUsbActuator {
    fn radio_id(&self) -> RadioId {
        self.radio
    }

    fn apply(&self, alloc: &RadioAllocation) -> Result<(), ndn_radio_cognition::RadioError> {
        let to_err = |e: crate::FaceError| ndn_radio_cognition::RadioError(e.to_string());
        let p = &alloc.params;

        // Only push a stateful knob to the radio when it actually changed — a
        // channel retune costs ~16 ms, so re-applying per frame would dominate.
        let mut last = self.last.lock().unwrap();

        // Stateful: retune channel + bandwidth together.
        if let Some(ch) = alloc.channel {
            let bw_code = p.bw.unwrap_or(0);
            if last.channel != Some((ch, bw_code)) {
                let bw = crate::Bandwidth::from_code(bw_code);
                self.knobs.set_channel(ch, bw).map_err(to_err)?;
                last.channel = Some((ch, bw_code));
            }
        }
        // Stateful: CSD (the 1-stream cyclic-shift antenna path; no-op on radios
        // without a per-frame CSD knob, e.g. mt76x2).
        if last.csd != Some(p.csd) {
            self.knobs.set_tx_csd(p.csd).map_err(to_err)?;
            last.csd = Some(p.csd);
        }
        if last.edcca != Some(p.edcca_ignore) {
            self.knobs.set_edcca_ignore(p.edcca_ignore).map_err(to_err)?;
            last.edcca = Some(p.edcca_ignore);
        }
        // Power: only when the plane asks to back off — `None` preserves the
        // hard-won calibrated/regulatory/PA-backoff power.
        if let Some(idx) = p.tx_power
            && last.power != Some(idx)
        {
            self.knobs.set_tx_power(idx as u32).map_err(to_err)?;
            last.power = Some(idx);
        }
        drop(last);

        // Per-frame: hand the decided params to the face's send path.
        if let Ok(mut g) = self.planned.write() {
            *g = Some(*p);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_radio_cognition::{AllocRole, Priority, RadioError, TxParams};
    use std::sync::RwLock;

    const W: RadioId = RadioId(0);

    /// Records the last allocation it was asked to apply.
    struct MockActuator {
        radio: RadioId,
        last: RwLock<Option<RadioAllocation>>,
    }
    impl RadioActuators for MockActuator {
        fn radio_id(&self) -> RadioId {
            self.radio
        }
        fn apply(&self, alloc: &RadioAllocation) -> Result<(), RadioError> {
            *self.last.write().unwrap() = Some(*alloc);
            Ok(())
        }
    }

    fn control_with_mock() -> (RadioControl, Arc<MockActuator>) {
        let mut c = RadioControl::new(RadioPolicy::default());
        c.register_radio(
            W,
            FaceId(10),
            RadioCapability::wifi_monitor_5ghz(vec![149, 161, 165]),
        );
        let mock = Arc::new(MockActuator {
            radio: W,
            last: RwLock::new(None),
        });
        c.add_actuator(mock.clone());
        (c, mock)
    }

    #[test]
    fn closed_loop_applies_decided_params() {
        let (c, mock) = control_with_mock();
        // a strong, single receiver heard on the Wi-Fi radio ⇒ high MCS unicast
        c.observe_rx(W, 99, Some(-50), 1_000);
        c.set_active(vec![NameContext::new(0xABCD)]);

        let plans = c.tick_now(1_000);
        assert_eq!(plans.len(), 1);
        assert!(!plans[0].suppress);

        let applied = mock.last.read().unwrap().expect("actuator applied");
        assert_eq!(applied.radio, W);
        let mcs = applied.params.mcs.expect("mcs decided");
        assert!(mcs >= 7, "strong unicast link should pick a high MCS, got {mcs}");
        assert_eq!(applied.role, AllocRole::Replicate);
    }

    #[test]
    fn weak_link_lowers_rate_through_the_loop() {
        let (c, mock) = control_with_mock();
        c.observe_rx(W, 99, Some(-85), 1_000); // weak receiver
        c.set_active(vec![NameContext::new(0xABCD)]);
        c.tick_now(1_000);
        let weak_mcs = mock.last.read().unwrap().unwrap().params.mcs.unwrap();

        let (c2, mock2) = control_with_mock();
        c2.observe_rx(W, 99, Some(-50), 1_000); // strong receiver
        c2.set_active(vec![NameContext::new(0xABCD)]);
        c2.tick_now(1_000);
        let strong_mcs = mock2.last.read().unwrap().unwrap().params.mcs.unwrap();

        assert!(weak_mcs < strong_mcs, "weak {weak_mcs} should be < strong {strong_mcs}");
    }

    #[test]
    fn relay_with_no_rank_suppresses_no_apply() {
        let (c, mock) = control_with_mock();
        c.observe_rank_deficit(0xABCD, 0.0, 1_000); // downstream satisfied
        let ctx = NameContext {
            is_origin: false,
            ..NameContext::new(0xABCD)
        };
        c.set_active(vec![ctx]);
        let plans = c.tick_now(1_000);
        assert!(plans[0].suppress);
        assert!(mock.last.read().unwrap().is_none(), "suppressed ⇒ no actuator apply");
    }

    #[test]
    fn urgent_under_contention_sets_edcca_ignore() {
        let (c, mock) = control_with_mock();
        c.observe_rx(W, 99, Some(-55), 1_000);
        c.observe_occupancy(ChannelOccupancy {
            radio: W,
            channel: 149,
            busy_pct: 80,
            ts_ms: 1_000,
        });
        // make 149 the only/least-busy by leaving others unmeasured? others default 0,
        // so pick_channel would avoid 149. Mark all busy so 149 (busy) can be chosen:
        c.observe_occupancy(ChannelOccupancy { radio: W, channel: 161, busy_pct: 90, ts_ms: 1_000 });
        c.observe_occupancy(ChannelOccupancy { radio: W, channel: 165, busy_pct: 95, ts_ms: 1_000 });
        let ctx = NameContext {
            priority: Priority::Urgent,
            ..NameContext::new(0xABCD)
        };
        c.set_active(vec![ctx]);
        c.tick_now(1_000);
        let applied = mock.last.read().unwrap().unwrap();
        assert!(applied.params.edcca_ignore, "urgent + busy ⇒ ignore EDCCA");
    }

    #[test]
    fn pit_fanout_drives_broadcast_robustness() {
        // Many downstream in-records ⇒ broad broadcast ⇒ lower (robust) MCS than a
        // single in-record near-unicast, at the same link quality. This is PIT
        // demand flowing through to the rate decision.
        let (c_broad, mock_broad) = control_with_mock();
        c_broad.observe_rx(W, 50, Some(-50), 1_000); // strong link
        for face in 1..=4u64 {
            c_broad.on_interest(0xABCD, FaceId(face), 1_000); // 4 listeners
        }
        c_broad.tick_now(1_000);
        let broad_mcs = mock_broad.last.read().unwrap().unwrap().params.mcs.unwrap();

        let (c_uni, mock_uni) = control_with_mock();
        c_uni.observe_rx(W, 50, Some(-50), 1_000);
        c_uni.on_interest(0xABCD, FaceId(1), 1_000); // 1 listener
        c_uni.tick_now(1_000);
        let uni_mcs = mock_uni.last.read().unwrap().unwrap().params.mcs.unwrap();

        assert!(
            broad_mcs < uni_mcs,
            "4-listener broadcast {broad_mcs} should be more robust than 1-listener {uni_mcs}"
        );
    }

    #[test]
    fn satisfied_demand_stops_managing_the_object() {
        let (c, _mock) = control_with_mock();
        c.observe_rx(W, 50, Some(-50), 1_000);
        c.on_interest(0xABCD, FaceId(1), 1_000);
        let plans = c.tick_now(1_000);
        assert_eq!(plans.len(), 1, "demanded object is managed");

        c.on_data(0xABCD, 1_100); // Data returns → in-records cleared
        let plans = c.tick_now(1_100);
        assert!(plans.is_empty(), "satisfied object is no longer transmitted");
    }

    #[test]
    fn calibration_drops_rate_after_repeated_misses() {
        use ndn_radio_cognition::PolicyConfig;
        let mut c = RadioControl::new_calibrated(PolicyConfig::default(), 0.9, 2.0);
        c.register_radio(
            W,
            FaceId(10),
            RadioCapability::wifi_monitor_5ghz(vec![149]),
        );
        c.add_actuator(Arc::new(MockActuator {
            radio: W,
            last: RwLock::new(None),
        }));
        // A link at -60 dBm; the preset would pick a fairly high MCS here.
        c.observe_rx(W, 99, Some(-60), 1_000);
        c.set_active(vec![NameContext::new(0xABCD)]);
        let mcs_before = c.tick_now(1_000).pop().unwrap().allocations[0]
            .params
            .mcs
            .unwrap();

        // That rate keeps missing (downstream re-Interests) at this RSSI.
        for _ in 0..30 {
            c.tick_now(1_000); // records last_tx (mcs, -60)
            c.observe_delivery(false); // miss feedback
        }
        let mcs_after = c.tick_now(1_000).pop().unwrap().allocations[0]
            .params
            .mcs
            .unwrap();

        assert!(
            mcs_after < mcs_before,
            "online calibration should back off the rate after misses: {mcs_after} < {mcs_before}"
        );
    }

    #[test]
    fn no_calibrator_means_static_behavior() {
        let (c, _m) = control_with_mock();
        assert!(c.learned_thresholds().is_none(), "default control is static");
    }

    #[test]
    fn reception_report_closes_the_outbound_link_loop() {
        // Node B (id=2) hears node A (id=1) at -55. B broadcasts a report; A ingests
        // it and thereby learns its *outbound* link to B is -55 — measured, not guessed.
        let mut b = RadioControl::new(RadioPolicy::default())
            .with_node_id(2)
            .with_report_interval(1);
        b.register_radio(W, FaceId(20), RadioCapability::wifi_monitor_5ghz(vec![149]));
        b.observe_rx(W, 1, Some(-55), 1_000); // B hears A(1) at -55
        let report = b.outgoing_report(1_000).expect("report due");

        let mut a = RadioControl::new(RadioPolicy::default()).with_node_id(1);
        a.register_radio(W, FaceId(10), RadioCapability::wifi_monitor_5ghz(vec![149]));
        assert!(a.ingest_report(W, &report, 2_000));
        // A now hears node 2 (B) at -55 — the measured outbound link — so a unicast
        // for B's demand picks a high MCS.
        a.set_active(vec![NameContext::new(0xF00D)]);
        let plan = a.tick_now(2_000).pop().unwrap();
        let mcs = plan.allocations[0].params.mcs.unwrap();
        assert!(mcs >= 7, "measured -55 outbound link should yield a high MCS, got {mcs}");
    }

    #[test]
    fn outgoing_report_respects_cadence() {
        let mut c = RadioControl::new(RadioPolicy::default())
            .with_node_id(1)
            .with_report_interval(500);
        c.register_radio(W, FaceId(10), RadioCapability::wifi_monitor_5ghz(vec![149]));
        assert!(c.outgoing_report(1_000).is_some(), "first report due");
        assert!(c.outgoing_report(1_200).is_none(), "within interval ⇒ none");
        assert!(c.outgoing_report(1_600).is_some(), "after interval ⇒ due");
    }

    #[test]
    fn no_node_id_means_no_reports() {
        let mut c = RadioControl::new(RadioPolicy::default()).with_report_interval(500);
        c.register_radio(W, FaceId(10), RadioCapability::wifi_monitor_5ghz(vec![149]));
        assert!(c.outgoing_report(1_000).is_none(), "node_id 0 ⇒ no reports");
    }

    #[test]
    fn telemetry_snapshot_reflects_decisions() {
        let (c, _m) = control_with_mock();
        c.observe_rx(W, 99, Some(-55), 1_000);
        c.set_active(vec![NameContext::new(0xABCD)]);
        c.tick_now(1_000);
        let t = c.telemetry();
        assert_eq!(t.strategy, "rule-calibrated");
        assert_eq!(t.managed_objects, 1);
        assert_eq!(t.plans.len(), 1);
        assert!(t.objective.is_finite());
    }

    #[test]
    fn probing_occasionally_samples_the_next_rate_up() {
        use ndn_radio_cognition::PolicyConfig;
        let c = RadioControl::new_calibrated(PolicyConfig::default(), 0.9, 1.0)
            .with_probe_interval(2); // every 2nd tick is a probe
        let c = {
            let mut c = c;
            c.register_radio(W, FaceId(10), RadioCapability::wifi_monitor_5ghz(vec![149]));
            let mock = Arc::new(MockActuator {
                radio: W,
                last: RwLock::new(None),
            });
            c.add_actuator(mock.clone());
            (c, mock)
        };
        let (c, mock) = c;
        c.observe_rx(W, 99, Some(-60), 1_000); // mid link ⇒ chosen MCS < max
        c.set_active(vec![NameContext::new(0xABCD)]);

        c.tick_now(1_000); // probe_count=1 (no probe)
        let steady = mock.last.read().unwrap().unwrap().params.mcs.unwrap();
        c.tick_now(1_000); // probe_count=2 (probe)
        let probed = mock.last.read().unwrap().unwrap().params.mcs.unwrap();

        assert_eq!(probed, steady + 1, "probe should sample one rung up: {probed} vs {steady}");
    }

    #[test]
    fn power_backs_off_when_demand_set_has_margin() {
        // A very strong link (margin left even after the rate maxes out) ⇒ the plane
        // should trim TX power below the calibrated max for spatial reuse. A weak
        // link (rate consumed all the margin) ⇒ leave power at the calibrated max.
        let (c_strong, mock_strong) = control_with_mock();
        c_strong.observe_rx(W, 99, Some(-30), 1_000); // very strong, MCS caps out
        c_strong.set_active(vec![NameContext::new(0xABCD)]);
        c_strong.tick_now(1_000);
        let strong_pwr = mock_strong.last.read().unwrap().unwrap().params.tx_power;

        let (c_weak, mock_weak) = control_with_mock();
        c_weak.observe_rx(W, 99, Some(-88), 1_000); // near the edge
        c_weak.set_active(vec![NameContext::new(0xABCD)]);
        c_weak.tick_now(1_000);
        let weak_pwr = mock_weak.last.read().unwrap().unwrap().params.tx_power;

        assert!(strong_pwr.is_some(), "strong link should back off power");
        assert!(strong_pwr.unwrap() < 63, "backed-off power below calibrated max");
        assert!(weak_pwr.is_none(), "weak link keeps full calibrated power (None)");
    }

    #[test]
    fn bandit_discovers_the_spatial_reuse_win() {
        use ndn_radio_cognition::PolicyConfig;
        // A mid link where the baseline rate (MCS7) delivers but +1 misses. The
        // bandit should learn that *holding the rate and trimming power* (arm 3)
        // beats full power (same airtime, smaller footprint) — a win a fixed rule
        // that only "maxes rate then trims" wouldn't reach here (no leftover margin
        // for the policy's own power trim).
        let c = RadioControl::new_bandit(PolicyConfig::default(), 0.4);
        let (c, mock) = {
            let mut c = c;
            c.register_radio(W, FaceId(10), RadioCapability::wifi_monitor_5ghz(vec![149]));
            let mock = Arc::new(MockActuator {
                radio: W,
                last: RwLock::new(None),
            });
            c.add_actuator(mock.clone());
            (c, mock)
        };
        c.observe_rx(W, 99, Some(-65), 1_000); // baseline MCS7 at this link
        c.set_active(vec![NameContext::new(0xABCD)]);

        const CLIFF: u8 = 7; // the link supports up to MCS7
        for _ in 0..400 {
            c.tick_now(1_000);
            let p = mock.last.read().unwrap().unwrap().params;
            c.observe_delivery(p.mcs.unwrap() <= CLIFF);
        }

        // Sample the steady behavior over a window; UCB exploits the best arm most
        // of the time. The winning outcome delivers at MCS7 with power trimmed.
        let mut at_cliff_trimmed = 0;
        let mut at_cliff_full = 0;
        for _ in 0..60 {
            c.tick_now(1_000);
            let p = mock.last.read().unwrap().unwrap().params;
            c.observe_delivery(p.mcs.unwrap() <= CLIFF);
            if p.mcs == Some(CLIFF) {
                if p.tx_power.is_some() {
                    at_cliff_trimmed += 1;
                } else {
                    at_cliff_full += 1;
                }
            }
        }
        assert!(
            at_cliff_trimmed > at_cliff_full,
            "bandit should prefer rate-held + power-trimmed (trimmed {at_cliff_trimmed} vs full {at_cliff_full})"
        );
    }

    #[test]
    fn planned_cell_is_written_for_face_to_read() {
        // Mirrors what LibUsbActuator does: an actuator writing the shared cell.
        let cell: Arc<RwLock<Option<TxParams>>> = Arc::new(RwLock::new(None));
        struct CellActuator {
            radio: RadioId,
            cell: Arc<RwLock<Option<TxParams>>>,
        }
        impl RadioActuators for CellActuator {
            fn radio_id(&self) -> RadioId {
                self.radio
            }
            fn apply(&self, alloc: &RadioAllocation) -> Result<(), RadioError> {
                *self.cell.write().unwrap() = Some(alloc.params);
                Ok(())
            }
        }
        let mut c = RadioControl::new(RadioPolicy::default());
        c.register_radio(W, FaceId(10), RadioCapability::wifi_monitor_5ghz(vec![149]));
        c.add_actuator(Arc::new(CellActuator {
            radio: W,
            cell: cell.clone(),
        }));
        c.observe_rx(W, 99, Some(-50), 1_000);
        c.set_active(vec![NameContext::new(0xABCD)]);
        c.tick_now(1_000);
        assert!(cell.read().unwrap().is_some(), "face would now read decided params");
    }
}
