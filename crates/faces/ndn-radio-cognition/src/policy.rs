//! The **decide** plane — `RadioPolicy::decide(name_ctx, medium) -> RadioPlan`.
//!
//! Measured-adaptive (not a static knob table): the inputs are what the forwarder
//! already knows about a named object (PIT fan-out, CCLF score, measured
//! re-Interest rate, pooled rank deficit) crossed with MRMC medium state
//! (per-radio RSSI, occupancy, residual). The single optimand is **airtime per
//! satisfied Interest over the demand set** — every choice (radio selection, rate,
//! redundancy, suppress) trades against it.
//!
//! Three resolved design points baked in here:
//! - **One plane, not two.** Suppress/relay is the same CCLF-style election; the
//!   actuators are just its widened output vocabulary.
//! - **Innovation-aware suppression** unifies CCLF (drop duplicate) and
//!   stop-at-rank-N (transmit only if it adds rank to a rank-deficient downstream).
//! - **Redundancy is ONE budget** sized from the residual left below each layer,
//!   discounted by macrodiversity receiver multiplicity, biased by the measured
//!   re-Interest rate (the real ARQ signal), targeting post-pooling rank deficit.
//!
//! Timescale separation (anti-oscillation): callers run `decide` at the per-Interest
//! cadence for rate/aggregation, but the slow inputs (residual, neighbor set) are
//! EWMA-smoothed in the sense bus and the demand record carries its own `ts_ms`, so
//! a fast decision never reads a slow signal as fresh-per-frame.

use crate::calibrate::{RateThresholds, STATIC_REQ_RSSI};
use crate::plan::{AllocRole, RadioAllocation, RadioPlan, TxParams};
use crate::sense::{MediumView, RadioCapability, RadioId, RadioKind};
use crate::strategy::RadioStrategy;

/// Delivery priority derived from the name / Interest (urgency, freshness, trust).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Priority {
    /// Background bulk — favour throughput (high rate, aggregation).
    Bulk,
    #[default]
    Normal,
    /// Latency/robustness-critical — favour reach, may ignore EDCCA.
    Urgent,
}

impl Priority {
    /// Numeric rank (Bulk=0, Normal=1, Urgent=2) for context keying.
    pub fn rank(self) -> u8 {
        match self {
            Priority::Bulk => 0,
            Priority::Normal => 1,
            Priority::Urgent => 2,
        }
    }
}

/// Name-derived context for one transmission decision.
#[derive(Clone, Copy, Debug)]
pub struct NameContext {
    /// Hash of the object's name-prefix (keys demand + consistency).
    pub prefix_hash: u64,
    pub priority: Priority,
    /// Are we the producer/origin (always transmit) vs a relay (innovation-gated)?
    pub is_origin: bool,
    /// Coding generation this object belongs to, if any (enables Split allocation).
    pub generation: Option<u32>,
}

impl NameContext {
    /// We are the origin/producer of this object (always transmit).
    pub fn new(prefix_hash: u64) -> Self {
        Self {
            prefix_hash,
            priority: Priority::Normal,
            is_origin: true,
            generation: None,
        }
    }

    /// We are relaying this object for downstream demand (innovation-gated by the
    /// suppress predicate). This is what PIT-driven demand produces.
    pub fn relayed(prefix_hash: u64) -> Self {
        Self {
            prefix_hash,
            priority: Priority::Normal,
            is_origin: false,
            generation: None,
        }
    }
}

/// Tunables for the policy (all measured-adaptive thresholds, not per-feature knobs).
#[derive(Clone, Copy, Debug)]
pub struct PolicyConfig {
    /// Receiver count above which an object is treated as a broad broadcast
    /// (robust low-MCS) rather than near-unicast (high-MCS).
    pub broad_receivers: usize,
    /// Coding generation size `k` the budget sizes parity against.
    pub generation_k: u16,
    /// Replicate across a second radio when post-pooling rank deficit exceeds this.
    pub replicate_deficit: f32,
    /// Default channel busy% above which we prefer a clearer channel / narrow BW.
    pub busy_high: u8,
    /// Emit TX-diversity (CSD / STBC) on weak 1-stream links. **Default off**: on
    /// the RTL8812EU userspace TX path both antenna-B diversity paths are fragile —
    /// they stalled the USB transfer on-air when combined with live actuator
    /// reconfiguration — and their small diversity gain is dominated by LDPC (~2 dB,
    /// always on for robust frames) + rate reduction, which are reliable. Opt in
    /// only where the diversity path is proven.
    pub enable_tx_diversity: bool,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            broad_receivers: 3,
            generation_k: 8,
            replicate_deficit: 1.0,
            busy_high: 50,
            enable_tx_diversity: false,
        }
    }
}

pub struct RadioPolicy {
    cfg: PolicyConfig,
    /// Learned per-MCS RSSI thresholds (shared with a [`crate::RateCalibrator`]).
    /// `None` ⇒ use the static preset.
    learned: Option<RateThresholds>,
}

impl Default for RadioPolicy {
    fn default() -> Self {
        Self::new(PolicyConfig::default())
    }
}

impl RadioPolicy {
    pub fn new(cfg: PolicyConfig) -> Self {
        Self { cfg, learned: None }
    }

    /// Drive rate selection from a learned, online-calibrated threshold cell
    /// instead of the static preset.
    pub fn with_learned_thresholds(mut self, thresholds: RateThresholds) -> Self {
        self.learned = Some(thresholds);
        self
    }

    /// Highest MCS the current thresholds allow at `rssi` (learned if present).
    fn pick_mcs(&self, rssi: Option<i8>, max_mcs: u8) -> u8 {
        let r = rssi.unwrap_or(-90);
        let t = match &self.learned {
            Some(cell) => *cell.read().unwrap(),
            None => STATIC_REQ_RSSI,
        };
        crate::calibrate::pick_mcs(r, max_mcs, &t)
    }

    /// The closed loop. Reads demand + MRMC medium state, emits a multi-radio plan
    /// optimizing airtime-per-satisfied-Interest, made cross-node-consistent. This
    /// is the [`RadioStrategy::decide`] implementation; kept inherent too for direct
    /// (monomorphized) use in tests/harness.
    ///
    /// [`RadioStrategy::decide`]: crate::RadioStrategy::decide
    pub fn decide(&self, ctx: &NameContext, view: &dyn MediumView, now_ms: u64) -> RadioPlan {
        let demand = view.demand(ctx.prefix_hash);
        let receivers = self.effective_receivers(ctx, view, now_ms);
        let holders = view.neighbors_holding(ctx.prefix_hash, now_ms);
        let deficit = demand
            .map(|d| d.rank_deficit.get_or(receivers as f32))
            .unwrap_or(receivers as f32);

        // --- Innovation-aware suppression (CCLF ∪ stop-at-rank-N) ---
        // A relay stays quiet unless its transmission adds rank to a downstream
        // that still needs it: deficit must be positive AND not already covered by
        // neighbors holding it. The origin always transmits (it IS the rank).
        if !ctx.is_origin {
            let adds_rank = deficit > f32::EPSILON && holders < receivers.max(1);
            if !adds_rank {
                return RadioPlan::suppressed(self.consistency(ctx, &[], 0));
            }
        }

        // --- Radio selection (MRMC: by capability fit to the demand) ---
        let mut tx: Vec<(RadioId, RadioCapability)> = view
            .radios()
            .into_iter()
            .filter(|(_, c)| !c.rx_only && !c.channels.is_empty())
            .collect();
        if tx.is_empty() {
            return RadioPlan::suppressed(self.consistency(ctx, &[], 0));
        }
        let broad = receivers >= self.cfg.broad_receivers;
        tx.sort_by(|(_, a), (_, b)| {
            self.radio_score(b, ctx, broad)
                .total_cmp(&self.radio_score(a, ctx, broad))
        });

        // Primary radio always; a second radio replicates (diversity) when the
        // post-pooling deficit is high and a TX-capable alternative exists.
        let replicate = deficit >= self.cfg.replicate_deficit && tx.len() >= 2;
        let chosen = if replicate { 2 } else { 1 };

        let mut allocations = Vec::with_capacity(chosen);
        for (i, (radio, cap)) in tx.iter().take(chosen).enumerate() {
            let channel = self.pick_channel(*radio, cap, view);
            let params =
                self.tx_params(*radio, cap, ctx, view, receivers, broad, deficit, channel, now_ms);
            // Heterogeneous + coded ⇒ second radio carries a distinct generation
            // subset (Split); otherwise it replicates the same content.
            let role = if i > 0 && ctx.generation.is_some() && cap.band != tx[0].1.band {
                AllocRole::Split
            } else {
                AllocRole::Replicate
            };
            allocations.push(RadioAllocation {
                radio: *radio,
                channel,
                params,
                role,
            });
        }

        let objective = self.estimate_objective(&allocations, receivers.max(1));
        let consistency = self.consistency(ctx, &allocations, receivers);
        RadioPlan {
            relay: !ctx.is_origin,
            suppress: false,
            allocations,
            objective,
            consistency,
        }
    }

    // --- effective demand-set size ---
    fn effective_receivers(&self, ctx: &NameContext, view: &dyn MediumView, now_ms: u64) -> usize {
        let fanout = view.demand(ctx.prefix_hash).map(|d| d.fanout as usize).unwrap_or(0);
        fanout.max(view.receiver_count(now_ms))
    }

    // --- radio capability fit ---
    fn radio_score(&self, cap: &RadioCapability, ctx: &NameContext, broad: bool) -> f32 {
        // Normalized reach vs rate (both 0..1) so the weighting, not the raw scale,
        // decides. Bulk wants rate; urgent/broad wants reach. Sub-GHz scores high on
        // reach, Wi-Fi high on rate — the homogeneous/heterogeneous switch falls out
        // of the descriptor, no special-casing.
        let reach = cap.band.range_rank() as f32 / 4.0;
        let rate = (cap.max_mcs as f32 / 9.0 + (cap.max_nss.saturating_sub(1)) as f32 / 3.0) / 2.0;
        let (w_reach, w_rate) = match ctx.priority {
            Priority::Bulk => (0.2, 1.0),
            Priority::Urgent => (1.0, 0.2),
            Priority::Normal if broad => (0.7, 0.5),
            Priority::Normal => (0.5, 0.7),
        };
        w_reach * reach + w_rate * rate
    }

    fn pick_channel(
        &self,
        radio: RadioId,
        cap: &RadioCapability,
        view: &dyn MediumView,
    ) -> Option<u8> {
        // Cognitive channel selection inline: least-busy channel this radio offers
        // (evidence-based when fed by an SDR PSD scan; coarse CCA otherwise).
        cap.channels
            .iter()
            .min_by_key(|&&ch| view.busy_pct(radio, ch).unwrap_or(0))
            .copied()
    }

    #[allow(clippy::too_many_arguments)]
    fn tx_params(
        &self,
        radio: RadioId,
        cap: &RadioCapability,
        ctx: &NameContext,
        view: &dyn MediumView,
        receivers: usize,
        broad: bool,
        deficit: f32,
        channel: Option<u8>,
        now_ms: u64,
    ) -> TxParams {
        // LoRa-class radios have no Wi-Fi MCS/BW knobs — keep params minimal.
        if cap.kind == RadioKind::Lora {
            return TxParams {
                link_fec_redundancy: self.fec_redundancy(radio, ctx, view, receivers, deficit),
                ..Default::default()
            };
        }

        let busy = channel
            .and_then(|ch| view.busy_pct(radio, ch))
            .unwrap_or(0);

        // Rate from RSSI — but the broad/unicast intent is expressed as an RSSI
        // *margin* so it goes through the (learned) thresholds too, rather than a
        // raw ±MCS bump that would bypass calibration. Broad broadcast provisions
        // for weaker/more listeners (margin down); a single good link pushes the
        // rate (margin up).
        let rssi = self.demand_set_rssi(radio, view, now_ms);
        let base = rssi.unwrap_or(-90) as f32;
        let eff = if broad {
            base - BROAD_MARGIN_DB
        } else if receivers <= 1 {
            base + UNICAST_MARGIN_DB
        } else {
            base
        };
        let mcs = self.pick_mcs(Some(eff.round().clamp(-110.0, 0.0) as i8), cap.max_mcs);

        // Bandwidth: capability ceiling, narrowed under contention.
        let mut bw = cap.max_bw;
        if busy >= self.cfg.busy_high {
            bw = bw.saturating_sub(1);
        }

        let good_snr = rssi.unwrap_or(-90) >= -60;
        let nss = if ctx.priority == Priority::Bulk && good_snr {
            cap.max_nss
        } else {
            1
        };

        // Robustness knobs from the situation, not standalone toggles:
        //  - LDPC: better coding gain whenever robustness matters.
        //  - STBC: 2-chain transmit diversity for a 1-stream robust send.
        //  - CSD: 1-stream cyclic-shift diversity to both antennas on a weak link.
        let robust = broad || ctx.priority == Priority::Urgent || deficit >= 1.0;
        let ldpc = robust;
        let weak = rssi.unwrap_or(-90) < -70;
        let div = self.cfg.enable_tx_diversity;
        let stbc = div && robust && nss == 1 && cap.max_nss >= 2 && weak;
        let csd = div && nss == 1 && weak && !stbc;

        // A-MSDU: aggregate only for bulk on a clean link (and it interleaves with
        // FEC at MSDU granularity downstream — not mutually exclusive).
        let amsdu_msdus = if ctx.priority == Priority::Bulk && !robust {
            Some(7)
        } else {
            None
        };

        TxParams {
            mcs: Some(mcs),
            vht: cap.max_bw >= 2,
            nss: Some(nss),
            short_gi: good_snr,
            bw: Some(bw),
            stbc,
            csd,
            ldpc,
            amsdu_msdus,
            link_fec_redundancy: self.fec_redundancy(radio, ctx, view, receivers, deficit),
            edcca_ignore: ctx.priority == Priority::Urgent && busy >= self.cfg.busy_high,
            tx_power: self.decide_power(cap, mcs, rssi),
        }
    }

    /// **Data-centric, cooperative, safe TX-power back-off.** Minimize power to the
    /// least that still serves the named object's demand set — which *maximizes
    /// network spatial reuse* (a smaller footprint frees the medium for concurrent
    /// named-data exchanges elsewhere). It is the one knob with a true externality
    /// (your reach is others' noise), so "minimum sufficient" is the cooperative as
    /// well as the data-centric choice.
    ///
    /// Reciprocity makes this possible from passive overhearing (no handshake): on a
    /// symmetric medium, how weakly we hear the weakest wanted receiver (`rssi`) ≈
    /// how weakly it hears us, so its decode margin ≈ `rssi − required_rssi(mcs)`,
    /// and the learned threshold doubles as the peer's decode floor. We back off by
    /// the surplus margin, keeping a safety margin, and **never exceed the calibrated
    /// max** (returns `None` ⇒ leave the hard-won power alone when there's no margin
    /// to give back).
    fn decide_power(&self, cap: &RadioCapability, mcs: u8, rssi: Option<i8>) -> Option<u8> {
        let r = rssi? as f32;
        let req = self.threshold_for(mcs);
        let headroom = r - req; // dB of margin the weakest peer has (reciprocity)
        let backoff_db = (headroom - POWER_SAFETY_MARGIN_DB).clamp(0.0, MAX_BACKOFF_DB);
        let backoff_idx = (backoff_db / DB_PER_POWER_IDX).round() as u8;
        if backoff_idx == 0 {
            None // no surplus margin → keep calibrated full power
        } else {
            Some(cap.max_tx_power.saturating_sub(backoff_idx))
        }
    }

    /// The (learned-or-static) RSSI decode threshold for an MCS.
    fn threshold_for(&self, mcs: u8) -> f32 {
        let t = match &self.learned {
            Some(cell) => *cell.read().unwrap(),
            None => STATIC_REQ_RSSI,
        };
        t[mcs.min(9) as usize]
    }

    /// RSSI representative of the demand set on a radio: provision for the
    /// **weakest fresh receiver** when one is heard (fed from the signal store by
    /// the feature); otherwise fall back to a residual-derived proxy so the policy
    /// still degrades gracefully before any reception is observed.
    fn demand_set_rssi(&self, radio: RadioId, view: &dyn MediumView, now_ms: u64) -> Option<i8> {
        if let Some(weakest) = view.weakest_rssi(radio, now_ms) {
            return Some(weakest);
        }
        // No receiver heard yet: derive a conservative proxy from link residual
        // (high residual ⇒ treat the link as worse).
        let res = view.residual(radio).and_then(|r| r.phy_per.get()).unwrap_or(0.0);
        let base = -55.0 - res * 40.0; // 0% → -55 dBm, 50% → -75 dBm
        Some(base.round().clamp(-95.0, -40.0) as i8)
    }

    /// THE shared redundancy budget. One number across PHY-LDPC / link-FEC / F1F2:
    /// size parity from the residual left below, **discounted** by macrodiversity
    /// receiver multiplicity (any-of pooling), **biased** by the measured
    /// re-Interest rate (drive ARQ down), targeting post-pooling rank deficit.
    fn fec_redundancy(
        &self,
        radio: RadioId,
        ctx: &NameContext,
        view: &dyn MediumView,
        receivers: usize,
        deficit: f32,
    ) -> Option<u16> {
        let phy = view
            .residual(radio)
            .and_then(|r| r.phy_per.get())
            .unwrap_or(0.0)
            .clamp(0.0, 0.95);
        let reinterest = view
            .demand(ctx.prefix_hash)
            .and_then(|d| d.reinterest_rate.get())
            .unwrap_or(0.0)
            .max(0.0);

        // Pooling: with `n` decorrelated receivers, the chance every one misses a
        // given frame is ~phy^n (any-of). The budget covers that residual, not the
        // single-link PER.
        let n = receivers.max(1) as i32;
        let mut eff = phy.powi(n);
        eff = (eff * (1.0 + reinterest)).min(0.95);
        // If diversity already drives the deficit to ~0, don't spend redundancy.
        if eff < 1e-3 || deficit < f32::EPSILON {
            return None;
        }
        let k = self.cfg.generation_k as f32;
        let parity = (k * eff / (1.0 - eff)).ceil().clamp(0.0, k);
        if parity < 1.0 {
            None
        } else {
            Some(parity as u16)
        }
    }

    /// Relative airtime per satisfied Interest (lower = better) — the optimand,
    /// for A/B comparison against a fixed-MCS blast. Approximate but monotone.
    fn estimate_objective(&self, allocations: &[RadioAllocation], satisfied: usize) -> f32 {
        if allocations.is_empty() {
            return f32::INFINITY;
        }
        let mut airtime = 0.0f32;
        for a in allocations {
            let rate = phy_rate_proxy(&a.params); // Mbps proxy
            let redundancy = 1.0
                + a.params.link_fec_redundancy.unwrap_or(0) as f32 / self.cfg.generation_k as f32;
            airtime += redundancy / rate;
        }
        airtime / satisfied as f32
    }

    /// Deterministic digest of the salient choices so independent nodes converge
    /// and contradictory re-transmits can be detected/suppressed on the wire.
    fn consistency(&self, ctx: &NameContext, allocations: &[RadioAllocation], receivers: usize) -> u64 {
        let mut h = Fnv::new();
        h.add(ctx.prefix_hash);
        // bucket the demand so small fluctuations don't change the digest
        h.add((receivers / 2) as u64);
        for a in allocations {
            h.add(a.radio.0 as u64);
            h.add(a.channel.unwrap_or(0) as u64);
            h.add(a.params.mcs.unwrap_or(0) as u64); // rate class
        }
        h.0
    }
}

impl RadioStrategy for RadioPolicy {
    fn decide(&self, ctx: &NameContext, medium: &dyn MediumView, now_ms: u64) -> RadioPlan {
        RadioPolicy::decide(self, ctx, medium, now_ms)
    }
    fn name(&self) -> &'static str {
        "rule-calibrated"
    }
}

// --- helpers ---

/// RSSI margin (dB) subtracted for a broad broadcast — provision the rate for the
/// weaker/more-numerous listeners, not the best single link.
const BROAD_MARGIN_DB: f32 = 6.0;
/// RSSI margin (dB) added for a single-receiver near-unicast — push the rate when
/// there's one good link to serve.
const UNICAST_MARGIN_DB: f32 = 4.0;
/// Decode-margin (dB) kept above the threshold when backing off TX power.
const POWER_SAFETY_MARGIN_DB: f32 = 6.0;
/// Most we'll back TX power off, even with huge surplus margin (dB).
const MAX_BACKOFF_DB: f32 = 18.0;
/// Approx dB per chip TXAGC index step (used to convert a dB back-off to indices).
const DB_PER_POWER_IDX: f32 = 0.5;

/// Nominal PHY rate proxy (Mbps) for the objective estimate — monotone in the
/// rate-affecting params, not a calibrated figure.
fn phy_rate_proxy(p: &TxParams) -> f32 {
    let mcs = p.mcs.unwrap_or(0) as f32;
    let bw_factor = match p.bw.unwrap_or(0) {
        1 => 2.0,
        2 => 4.0,
        3 => 0.5,
        4 => 0.25,
        _ => 1.0,
    };
    let nss = p.nss.unwrap_or(1).max(1) as f32;
    let sgi = if p.short_gi { 1.11 } else { 1.0 };
    ((mcs + 1.0) * 6.5 * bw_factor * nss * sgi).max(0.25)
}

// Tiny FNV-1a over u64 words for the consistency digest (no external dep).
struct Fnv(u64);
impl Fnv {
    fn new() -> Self {
        Fnv(0xcbf29ce484222325)
    }
    fn add(&mut self, x: u64) {
        for b in x.to_le_bytes() {
            self.0 ^= b as u64;
            self.0 = self.0.wrapping_mul(0x100000001b3);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sense::{ChannelOccupancy, MediumState};

    const W: RadioId = RadioId(0);
    const L: RadioId = RadioId(1);

    fn wifi_only() -> MediumState {
        let mut m = MediumState::new();
        m.register_radio(W, RadioCapability::wifi_monitor_5ghz(vec![149, 161, 165]));
        m
    }

    fn hetero() -> MediumState {
        let mut m = wifi_only();
        m.register_radio(L, RadioCapability::lora(vec![0]));
        m
    }

    #[test]
    fn origin_always_transmits_single_radio() {
        let m = wifi_only();
        let p = RadioPolicy::default().decide(&NameContext::new(0xAA), &m, 1_000);
        assert!(!p.suppress);
        assert_eq!(p.allocations.len(), 1);
        assert_eq!(p.allocations[0].radio, W);
    }

    #[test]
    fn relay_suppresses_when_no_rank_to_add() {
        let mut m = wifi_only();
        // downstream already satisfied: deficit ~0
        m.observe_rank_deficit(0xAA, 0.0, 1_000);
        let ctx = NameContext { is_origin: false, ..NameContext::new(0xAA) };
        let p = RadioPolicy::default().decide(&ctx, &m, 1_000);
        assert!(p.suppress);
        assert!(p.allocations.is_empty());
    }

    #[test]
    fn relay_transmits_when_innovative() {
        let mut m = wifi_only();
        m.observe_rx(W, 1, Some(-60), 1_000); // a live receiver
        m.observe_rank_deficit(0xAA, 2.0, 1_000); // still rank-deficient
        let ctx = NameContext { is_origin: false, ..NameContext::new(0xAA) };
        let p = RadioPolicy::default().decide(&ctx, &m, 1_000);
        assert!(!p.suppress);
        assert!(p.relay);
    }

    #[test]
    fn broad_broadcast_lowers_mcs_vs_unicast() {
        let mut m = wifi_only();
        for n in 0..5 {
            m.observe_rx(W, n, Some(-55), 1_000); // 5 receivers ⇒ broad
        }
        let broad = RadioPolicy::default().decide(&NameContext::new(0xAA), &m, 1_000);

        let mut m1 = wifi_only();
        m1.observe_rx(W, 0, Some(-55), 1_000); // single receiver ⇒ unicast
        let uni = RadioPolicy::default().decide(&NameContext::new(0xAA), &m1, 1_000);

        let broad_mcs = broad.allocations[0].params.mcs.unwrap();
        let uni_mcs = uni.allocations[0].params.mcs.unwrap();
        assert!(broad_mcs < uni_mcs, "broad {broad_mcs} should be < unicast {uni_mcs}");
    }

    #[test]
    fn budget_scales_with_residual_and_discounts_receivers() {
        // high residual, one receiver ⇒ some parity
        let mut m = wifi_only();
        m.observe_rx(W, 0, Some(-80), 1_000);
        m.observe_phy_per(W, 0.3);
        m.observe_rank_deficit(0xAA, 1.0, 1_000);
        let one = RadioPolicy::default().decide(&NameContext::new(0xAA), &m, 1_000);
        let parity_one = one.allocations[0].params.link_fec_redundancy.unwrap_or(0);
        assert!(parity_one > 0, "expected parity for 30% residual");

        // same residual, many decorrelated receivers ⇒ pooling discounts parity
        let mut m2 = wifi_only();
        for n in 0..6 {
            m2.observe_rx(W, n, Some(-80), 1_000);
        }
        m2.observe_phy_per(W, 0.3);
        m2.observe_rank_deficit(0xAA, 1.0, 1_000);
        let many = RadioPolicy::default().decide(&NameContext::new(0xAA), &m2, 1_000);
        let parity_many = many.allocations[0].params.link_fec_redundancy.unwrap_or(0);
        assert!(parity_many < parity_one, "pooling should discount: {parity_many} < {parity_one}");
    }

    #[test]
    fn heterogeneous_bulk_prefers_wifi_urgent_prefers_lora() {
        let m = hetero();
        let bulk = RadioPolicy::default().decide(
            &NameContext { priority: Priority::Bulk, ..NameContext::new(0xAA) },
            &m,
            1_000,
        );
        assert_eq!(bulk.allocations[0].radio, W, "bulk → high-rate Wi-Fi");

        let urgent = RadioPolicy::default().decide(
            &NameContext { priority: Priority::Urgent, ..NameContext::new(0xAA) },
            &m,
            1_000,
        );
        assert_eq!(urgent.allocations[0].radio, L, "urgent → long-range LoRa");
    }

    #[test]
    fn high_deficit_replicates_across_radios_for_diversity() {
        let mut m = hetero();
        m.observe_rank_deficit(0xAA, 3.0, 1_000); // big deficit
        let p = RadioPolicy::default().decide(&NameContext::new(0xAA), &m, 1_000);
        assert_eq!(p.allocations.len(), 2, "should replicate across both radios");
    }

    #[test]
    fn split_role_when_coded_and_heterogeneous() {
        let mut m = hetero();
        m.observe_rank_deficit(0xAA, 3.0, 1_000);
        let ctx = NameContext { generation: Some(7), ..NameContext::new(0xAA) };
        let p = RadioPolicy::default().decide(&ctx, &m, 1_000);
        assert_eq!(p.allocations.len(), 2);
        assert_eq!(p.allocations[1].role, AllocRole::Split);
    }

    #[test]
    fn consistency_digest_is_deterministic() {
        let m = hetero();
        let a = RadioPolicy::default().decide(&NameContext::new(0xAA), &m, 1_000);
        let b = RadioPolicy::default().decide(&NameContext::new(0xAA), &m, 5_000);
        assert_eq!(a.consistency, b.consistency, "same name+demand ⇒ same plan digest");
    }

    #[test]
    fn picks_least_busy_channel() {
        let mut m = wifi_only();
        m.observe_occupancy(ChannelOccupancy { radio: W, channel: 149, busy_pct: 80, ts_ms: 1 });
        m.observe_occupancy(ChannelOccupancy { radio: W, channel: 161, busy_pct: 10, ts_ms: 1 });
        m.observe_occupancy(ChannelOccupancy { radio: W, channel: 165, busy_pct: 50, ts_ms: 1 });
        let p = RadioPolicy::default().decide(&NameContext::new(0xAA), &m, 1_000);
        assert_eq!(p.allocations[0].channel, Some(161));
    }
}
