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

use crate::calibrate::{RateThresholds, STATIC_REQ_RSSI, STATIC_REQ_RSSI_SF, SfThresholds};
use crate::plan::{
    AllocRole, DataPlaneConfig, LoraRate, RadioAllocation, RadioPlan, RateParams, TxParams, WifiRate,
};
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

/// Why a [`RadioPlan`] came out the way it did — the inputs [`RadioPolicy::decide`]
/// read and the key intermediate choices, as plain data. Returned alongside the
/// plan by [`RadioPolicy::decide_traced`] so an observer (the face) can render the
/// decision's *why* to a trace span, while this pure crate stays sans-IO (no
/// tracing/OpenTelemetry dependency — observability is computed as a value here and
/// rendered at the I/O boundary).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DecisionRationale {
    /// This node originates the content (always transmits — it IS the rank).
    pub is_origin: bool,
    /// Live PIT/demand existed for the prefix (vs the manual active set).
    pub had_demand: bool,
    /// Effective wanted-receiver count driving diversity/redundancy.
    pub receivers: usize,
    /// Neighbours already holding the content (the CCLF suppression input).
    pub holders: usize,
    /// Post-pooling rank deficit — the core "does transmitting add rank?" quantity.
    pub deficit: f32,
    /// Broadcast regime (receivers ≥ threshold) → robust defaults.
    pub broad: bool,
    /// A second radio replicates for diversity (deficit ≥ threshold, ≥2 radios).
    pub replicate: bool,
    /// Set when the plan is a suppression, with the reason it stayed quiet.
    pub suppress: Option<SuppressReason>,
    /// Per chosen radio: the measured inputs behind its allocation.
    pub radios: Vec<RadioRationale>,
}

/// Why a decision suppressed rather than transmitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SuppressReason {
    /// A relay whose transmission would add no rank downstream (CCLF ∪ stop-at-rank-N).
    RelayAddsNoRank,
    /// No TX-capable radio with a channel and remaining duty budget was available.
    NoTxRadio,
}

/// The measured inputs behind one radio's allocation — the "why this radio, this
/// channel, this rate" a trace consumer needs.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RadioRationale {
    pub radio: RadioId,
    /// Capability-fit score that ranked this radio (higher = preferred).
    pub score: f32,
    /// Chosen channel (the least-busy one this radio offers).
    pub channel: Option<u8>,
    /// Sensed busy% of the chosen channel — the frame-free occupancy input (#30).
    pub channel_busy_pct: Option<u8>,
    /// Weakest wanted-receiver RSSI (dBm) driving the MCS + power pick.
    pub rssi_dbm: Option<i8>,
    /// Post-link-FEC residual erasure driving the redundancy budget.
    pub link_per: Option<f32>,
    /// Replicate vs Split role of this allocation.
    pub role: AllocRole,
}

pub struct RadioPolicy {
    cfg: PolicyConfig,
    /// Learned per-MCS RSSI thresholds (shared with a [`crate::RateCalibrator`]).
    /// `None` ⇒ use the static preset.
    learned: Option<RateThresholds>,
    /// Learned per-SF operating thresholds for LoRa (shared with a [`crate::SfCalibrator`]).
    /// `None` ⇒ use the static preset.
    learned_sf: Option<SfThresholds>,
}

impl Default for RadioPolicy {
    fn default() -> Self {
        Self::new(PolicyConfig::default())
    }
}

impl RadioPolicy {
    pub fn new(cfg: PolicyConfig) -> Self {
        Self {
            cfg,
            learned: None,
            learned_sf: None,
        }
    }

    /// Drive rate selection from a learned, online-calibrated threshold cell
    /// instead of the static preset.
    pub fn with_learned_thresholds(mut self, thresholds: RateThresholds) -> Self {
        self.learned = Some(thresholds);
        self
    }

    /// Drive LoRa spreading-factor selection from a learned threshold cell (shared with a
    /// [`crate::SfCalibrator`]) instead of the static preset.
    pub fn with_learned_sf_thresholds(mut self, thresholds: SfThresholds) -> Self {
        self.learned_sf = Some(thresholds);
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

    /// Fastest LoRa spreading factor the current thresholds allow at `rssi` (learned if present).
    fn pick_sf(&self, rssi: i8) -> u8 {
        let t = match &self.learned_sf {
            Some(cell) => *cell.read().unwrap(),
            None => STATIC_REQ_RSSI_SF,
        };
        crate::calibrate::pick_sf(rssi, &t)
    }

    /// The closed loop. Reads demand + MRMC medium state, emits a multi-radio plan
    /// optimizing airtime-per-satisfied-Interest, made cross-node-consistent. This
    /// is the [`RadioStrategy::decide`] implementation; kept inherent too for direct
    /// (monomorphized) use in tests/harness.
    ///
    /// [`RadioStrategy::decide`]: crate::RadioStrategy::decide
    pub fn decide(&self, ctx: &NameContext, view: &dyn MediumView, now_ms: u64) -> RadioPlan {
        self.decide_traced(ctx, view, now_ms).0
    }

    /// Decide the data-centric offload for a face from its capability — the face-level companion to
    /// per-object [`decide`](Self::decide). On a duty-limited broadcast bearer (LoRa sub-GHz, HaLow,
    /// BLE) airtime is THE scarce resource, so both mechanisms earn their keep: dedup keeps a repeated
    /// name off the host link, and CS-serve answers a repeat Interest locally (one hop) instead of
    /// re-fetching it end-to-end — the airtime-per-satisfied-Interest win a flood mesh can't make.
    /// Name-keyed *firmware* hopping is left OFF until the firmware carries its own common-view clock;
    /// the firmware carries the hop function regardless. (#41's clock landed host-side as
    /// `ndn_time::RadioHwClock`, and the host monitor-wifi face already actuates FHSS from it via
    /// `FaceScheduler`/`NDN_SCHED_HOP` — a separate path from this firmware flag.) Mains-powered
    /// always-on Wi-Fi (`duty_cycle_max`
    /// == 1.0, monitor) stays conservative — its host PIT/CS already dedups and airtime is cheap.
    pub fn data_plane(&self, cap: &RadioCapability) -> DataPlaneConfig {
        let duty_limited_broadcast = matches!(
            cap.kind,
            RadioKind::Lora | RadioKind::WifiHaLow | RadioKind::Ble
        ) || cap.duty_cycle_max < 1.0;
        DataPlaneConfig {
            dedup: duty_limited_broadcast,
            cs_serve: duty_limited_broadcast,
            hop: false, // gated on #41 (common-view time); function present in firmware
        }
    }

    /// [`decide`](Self::decide) plus a [`DecisionRationale`] — the inputs read and
    /// the key intermediate choices, so an observer can render *why* the plan came
    /// out this way to a trace span. Pure: the rationale is data, not a side effect.
    pub fn decide_traced(
        &self,
        ctx: &NameContext,
        view: &dyn MediumView,
        now_ms: u64,
    ) -> (RadioPlan, DecisionRationale) {
        let demand = view.demand(ctx.prefix_hash);
        let receivers = self.effective_receivers(ctx, view, now_ms);
        let holders = view.neighbors_holding(ctx.prefix_hash, now_ms);
        let deficit = demand
            .map(|d| d.rank_deficit.get_or(receivers as f32))
            .unwrap_or(receivers as f32);
        let mut why = DecisionRationale {
            is_origin: ctx.is_origin,
            had_demand: demand.is_some(),
            receivers,
            holders,
            deficit,
            ..Default::default()
        };

        // --- Innovation-aware suppression (CCLF ∪ stop-at-rank-N) ---
        // A relay stays quiet unless its transmission adds rank to a downstream
        // that still needs it: deficit must be positive AND not already covered by
        // neighbors holding it. The origin always transmits (it IS the rank).
        if !ctx.is_origin {
            let adds_rank = deficit > f32::EPSILON && holders < receivers.max(1);
            if !adds_rank {
                why.suppress = Some(SuppressReason::RelayAddsNoRank);
                return (RadioPlan::suppressed(self.consistency(ctx, &[], 0)), why);
            }
        }

        // --- Radio selection (MRMC: by capability fit to the demand) ---
        let mut tx: Vec<(RadioId, RadioCapability)> = view
            .radios()
            .into_iter()
            .filter(|(id, c)| {
                // TX-capable, has a channel, and hasn't spent its duty-cycle budget (fail-closed:
                // a sub-GHz radio over its ~1% ceiling drops out, so the packet waits rather than
                // breaking the regulatory limit; Wi-Fi's duty_cycle_max = 1.0 never trips).
                !c.rx_only
                    && !c.channels.is_empty()
                    && view.duty_used(*id, now_ms) < c.duty_cycle_max
            })
            .collect();
        if tx.is_empty() {
            why.suppress = Some(SuppressReason::NoTxRadio);
            return (RadioPlan::suppressed(self.consistency(ctx, &[], 0)), why);
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
        why.broad = broad;
        why.replicate = replicate;

        let mut allocations = Vec::with_capacity(chosen);
        for (i, (radio, cap)) in tx.iter().take(chosen).enumerate() {
            let channel = self.pick_channel(*radio, cap, view);
            let params = self.tx_params(
                *radio, cap, ctx, view, receivers, broad, deficit, channel, now_ms,
            );
            // Heterogeneous + coded ⇒ second radio carries a distinct generation
            // subset (Split); otherwise it replicates the same content.
            let role = if i > 0 && ctx.generation.is_some() && cap.bands != tx[0].1.bands {
                AllocRole::Split
            } else {
                AllocRole::Replicate
            };
            // The inputs behind this allocation, for the trace (same view the
            // params were computed from, so the "why" is faithful).
            why.radios.push(RadioRationale {
                radio: *radio,
                score: self.radio_score(cap, ctx, broad),
                channel,
                channel_busy_pct: channel.and_then(|ch| view.busy_pct(*radio, ch)),
                rssi_dbm: self.demand_set_rssi(*radio, view, now_ms),
                link_per: view.residual(*radio).and_then(|r| r.link_per.get()),
                role,
            });
            allocations.push(RadioAllocation {
                radio: *radio,
                channel,
                params,
                role,
            });
        }

        let objective = self.estimate_objective(&allocations, receivers.max(1));
        let consistency = self.consistency(ctx, &allocations, receivers);
        (
            RadioPlan {
                relay: !ctx.is_origin,
                suppress: false,
                allocations,
                objective,
                consistency,
            },
            why,
        )
    }

    // --- effective demand-set size ---
    fn effective_receivers(&self, ctx: &NameContext, view: &dyn MediumView, now_ms: u64) -> usize {
        let fanout = view
            .demand(ctx.prefix_hash)
            .map(|d| d.fanout as usize)
            .unwrap_or(0);
        fanout.max(view.receiver_count(now_ms))
    }

    // --- radio capability fit ---
    fn radio_score(&self, cap: &RadioCapability, ctx: &NameContext, broad: bool) -> f32 {
        // Normalized reach vs rate (both 0..1) so the weighting, not the raw scale,
        // decides. Bulk wants rate; urgent/broad wants reach. Sub-GHz scores high on
        // reach, Wi-Fi high on rate — the homogeneous/heterogeneous switch falls out
        // of the descriptor, no special-casing.
        let reach = cap.range_rank() as f32 / 4.0;
        let rate = cap.rate_rank(); // bearer-agnostic peak-throughput rank
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
        // LoRa-class radios have no Wi-Fi MCS/BW knobs; their reach/rate dial is the spreading
        // factor. Pick it from the same demand-set RSSI (with the broad/unicast margin) that drives
        // MCS below — a strong link runs low SF (fast), reach pressure runs high SF. Coding rate
        // rises for urgent/broadcast robustness.
        if cap.kind == RadioKind::Lora {
            let base = self.demand_set_rssi(radio, view, now_ms).unwrap_or(-105) as f32;
            let eff = if broad {
                base - BROAD_MARGIN_DB
            } else if receivers <= 1 {
                base + UNICAST_MARGIN_DB
            } else {
                base
            };
            // Clamp the pick to the radio's advertised SF span (from the capability, not a hardcode).
            let sf = self.pick_sf(eff.round().clamp(-128.0, 0.0) as i8);
            let sf = cap.sf_range().map_or(sf, |(lo, hi)| sf.clamp(lo, hi));
            let cr = if matches!(ctx.priority, Priority::Urgent) || broad {
                2
            } else {
                1
            };
            // Bandwidth is a rendezvous parameter (both ends must match to decode), so it is dialed
            // ONLY from a REAL, shared measurement — the measured weakest RSSI, never the synthetic
            // proxy (which reads strong at low PER and would trip one end into 250 kHz while the other
            // stayed at 125, a decode split). Widen to 250 kHz for Bulk on a genuinely strong, non-
            // reach link: ~2× rate and half the airtime (duty relief) at ~3 dB less sensitivity, which
            // the margin affords. No measured peer ⇒ hold the 125 kHz reach default.
            let strong = !broad && view.weakest_rssi(radio, now_ms).is_some_and(|r| r >= -85);
            let bandwidth_khz = if matches!(ctx.priority, Priority::Bulk) && strong {
                Some(250)
            } else {
                Some(125)
            };
            return TxParams {
                rate: RateParams::Lora(LoraRate {
                    spreading_factor: Some(sf),
                    coding_rate: Some(cr),
                    bandwidth_khz,
                }),
                link_fec_redundancy: self.fec_redundancy(radio, ctx, view, channel, receivers, deficit),
                // Minimum-sufficient power (spatial reuse) off the SF operating threshold, same
                // reciprocity as the Wi-Fi path — power is NOT a rendezvous parameter, so each end
                // sets its own freely. Dial off the REAL measured weakest RSSI (not the proxy), so it
                // holds the ceiling until a genuine peer margin is seen, then hands back the surplus.
                tx_power_dbm: self.decide_lora_power_dbm(cap, sf, view.weakest_rssi(radio, now_ms)),
                ..Default::default()
            };
        }

        let busy = channel.and_then(|ch| view.busy_pct(radio, ch)).unwrap_or(0);

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
        // Worst-overheard-receiver rate cap (doctrine §5): a listener that only brings up one RX
        // chain (e.g. the userspace RTL8812EU, `max_rx_mcs` = 7) cannot decode a 2-stream frame at
        // *any* index — so a neighbour advertising 1..=7 caps both the MCS ceiling and the stream
        // count, not just the MCS. `LEGACY_ONLY_RX` (0) is out of band (the legacy-rate gate handles
        // it); `None`/`FULL_RX_MCS` leave the radio's own ceiling. Without this, cognition happily
        // picks a 2-stream MCS the neighbour can never decode (measured: MCS 9 → a one-way link).
        let neighbor_rx = view.worst_neighbor_rx_mcs(now_ms);
        let mcs_ceiling = match neighbor_rx {
            Some(c) if c >= 1 => cap.max_mcs().min(c),
            _ => cap.max_mcs(),
        };
        let neighbor_single_stream =
            matches!(neighbor_rx, Some(c) if (1..=crate::report::SINGLE_STREAM_HT_RX_MCS).contains(&c));
        let mcs = self.pick_mcs(Some(eff.round().clamp(-110.0, 0.0) as i8), mcs_ceiling);

        // Bandwidth: capability ceiling, narrowed under contention.
        let mut bw = cap.max_bw();
        if busy >= self.cfg.busy_high {
            bw = bw.saturating_sub(1);
        }

        let good_snr = rssi.unwrap_or(-90) >= -60;
        let nss = if neighbor_single_stream {
            1 // a 1-RX-chain neighbour cannot decode a 2-stream frame at any MCS
        } else if ctx.priority == Priority::Bulk && good_snr {
            cap.max_nss()
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
        let stbc = div && robust && nss == 1 && cap.max_nss() >= 2 && weak;
        let csd = div && nss == 1 && weak && !stbc;

        // A-MSDU: aggregate only for bulk on a clean link (and it interleaves with
        // FEC at MSDU granularity downstream — not mutually exclusive).
        let amsdu_msdus = if ctx.priority == Priority::Bulk && !robust {
            Some(7)
        } else {
            None
        };

        TxParams {
            rate: RateParams::Wifi(WifiRate {
                mcs: Some(mcs),
                vht: cap.max_bw() >= 2,
                nss: Some(nss),
                short_gi: good_snr,
                bw: Some(bw),
                stbc,
                csd,
                ldpc,
                amsdu_msdus,
            }),
            link_fec_redundancy: self.fec_redundancy(radio, ctx, view, channel, receivers, deficit),
            edcca_ignore: ctx.priority == Priority::Urgent && busy >= self.cfg.busy_high,
            tx_power: self.decide_power(cap, mcs, rssi),
            tx_power_dbm: self.decide_power_dbm(cap, mcs, rssi),
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
        let backoff_db = self.power_backoff_db(mcs, rssi)?;
        let backoff_idx = (backoff_db / DB_PER_POWER_IDX).round() as u8;
        if backoff_idx == 0 {
            None // no surplus margin → keep calibrated full power
        } else {
            Some(cap.max_tx_power.saturating_sub(backoff_idx))
        }
    }

    /// The same back-off, expressed on the **absolute dBm scale** for a radio that
    /// has one ([`RadioCapability::tx_power_dbm`]).
    ///
    /// This is the more faithful of the two: the policy above reasons natively in
    /// dB and only converts to an index at the end, through a single
    /// chip-independent `DB_PER_POWER_IDX` fudge that no real TXAGC table obeys.
    /// When the radio takes dBm directly, that lossy step is skipped and the
    /// decided margin is what the hardware is actually told.
    ///
    /// `None` when the radio has no absolute control, or there is no surplus
    /// margin to give back — never a guess.
    fn decide_power_dbm(&self, cap: &RadioCapability, mcs: u8, rssi: Option<i8>) -> Option<i8> {
        let range = cap.tx_power_dbm?;
        let backoff_db = self.power_backoff_db(mcs, rssi)?;
        let target = i16::from(range.max) - backoff_db.round() as i16;
        Some(range.clamp(target.clamp(i16::from(i8::MIN), i16::from(i8::MAX)) as i8))
    }

    /// LoRa TX power (absolute dBm): the same minimum-sufficient / spatial-reuse policy as
    /// [`decide_power_dbm`], but the decode threshold comes from the **SF** operating table
    /// ([`STATIC_REQ_RSSI_SF`](crate::calibrate::STATIC_REQ_RSSI_SF)) rather than the Wi-Fi MCS one.
    /// A weak link keeps the ceiling (power-first); surplus margin over what the chosen SF needs is
    /// handed back for reuse, keeping [`POWER_SAFETY_MARGIN_DB`] in hand. `None` ⇒ no measured peer,
    /// leave power alone.
    fn decide_lora_power_dbm(&self, cap: &RadioCapability, sf: u8, rssi: Option<i8>) -> Option<i8> {
        let range = cap.tx_power_dbm?;
        let r = rssi? as f32;
        let req = crate::calibrate::STATIC_REQ_RSSI_SF[sf.clamp(7, 12) as usize];
        let headroom = r - req; // dB the weakest peer has over what this SF needs (reciprocity)
        let backoff = (headroom - POWER_SAFETY_MARGIN_DB).clamp(0.0, MAX_BACKOFF_DB);
        let target = i16::from(range.max) - backoff.round() as i16;
        Some(range.clamp(target.clamp(i16::from(i8::MIN), i16::from(i8::MAX)) as i8))
    }

    /// dB of power the weakest wanted receiver can spare, after keeping
    /// [`POWER_SAFETY_MARGIN_DB`] in hand and capping at [`MAX_BACKOFF_DB`].
    /// `None` = no measured peer, or no surplus — leave the power alone.
    ///
    /// Shared by both power knobs so the index and dBm paths can never drift into
    /// two different policies.
    fn power_backoff_db(&self, mcs: u8, rssi: Option<i8>) -> Option<f32> {
        let r = rssi? as f32;
        let req = self.threshold_for(mcs);
        let headroom = r - req; // dB of margin the weakest peer has (reciprocity)
        let backoff_db = (headroom - POWER_SAFETY_MARGIN_DB).clamp(0.0, MAX_BACKOFF_DB);
        (backoff_db > 0.0).then_some(backoff_db)
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
        let res = view
            .residual(radio)
            .and_then(|r| r.phy_per.get())
            .unwrap_or(0.0);
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
        channel: Option<u8>,
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

        // Pooling discount — DOUBLY GATED (`fec_pooling.rs`). With `n` receivers the
        // chance every one misses a frame is ~phy^n, so parity shrinks as `n` grows.
        // But phy^n silently assumes two things, and applying it blindly (the old
        // `phy.powi(receivers)`) under-provisions when either fails:
        //   1. ANY-OF semantics — the pool wins if *any* receiver catches each frame
        //      (cooperative relay/recode). An ALL-OF name (Urgent: every receiver must
        //      decode — alarm/control) gets NO discount; parity is sized for the single
        //      worst link. Ungated, the discount drops all-of delivery to ~0 at n≥2.
        //   2. INDEPENDENT loss. A shared interferer (a busy/contended channel,
        //      `wifi-loss-is-contention`) correlates loss across receivers, so a pool of
        //      `n` behaves like fewer. Damp the effective count toward 1 as busy rises.
        let all_of = matches!(ctx.priority, Priority::Urgent);
        let n = receivers.max(1) as f64;
        let n_eff = if all_of {
            1.0
        } else {
            // rho ≈ channel occupancy: at 100% busy the losses fully correlate and the
            // pool collapses to one effective receiver (`fec_pooling.rs` Part C).
            let rho = f64::from(channel.and_then(|ch| view.busy_pct(radio, ch)).unwrap_or(0)) / 100.0;
            1.0 + (n - 1.0) * (1.0 - rho.clamp(0.0, 1.0))
        };
        let mut eff = (f64::from(phy).powf(n_eff)) as f32;
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
    fn consistency(
        &self,
        ctx: &NameContext,
        allocations: &[RadioAllocation],
        receivers: usize,
    ) -> u64 {
        let mut h = Fnv::new();
        h.add(ctx.prefix_hash);
        // bucket the demand so small fluctuations don't change the digest
        h.add((receivers / 2) as u64);
        for a in allocations {
            h.add(a.radio.0 as u64);
            h.add(a.channel.unwrap_or(0) as u64);
            h.add(a.params.mcs().unwrap_or(0) as u64); // rate class
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
    let mcs = p.mcs().unwrap_or(0) as f32;
    let bw_factor = match p.bw().unwrap_or(0) {
        1 => 2.0,
        2 => 4.0,
        3 => 0.5,
        4 => 0.25,
        _ => 1.0,
    };
    let nss = p.nss().unwrap_or(1).max(1) as f32;
    let sgi = if p.short_gi() { 1.11 } else { 1.0 };
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
mod power_dbm_tests {
    use super::*;
    use ndn_radio_hal::DbmRange;

    /// A radio with absolute control gets an absolute decision, backed off from
    /// its own ceiling — the same margin the index path would have spent.
    #[test]
    fn advertised_range_yields_a_dbm_decision() {
        let p = RadioPolicy::default();
        let cap = RadioCapability::wifi_halow_s1g(vec![36]).with_tx_power_dbm(DbmRange::new(1, 27));
        // A very strong peer: lots of surplus margin to give back.
        let dbm = p.decide_power_dbm(&cap, 0, Some(-30)).expect("surplus margin");
        assert!(dbm < 27, "must back off below the ceiling, got {dbm}");
        assert!(dbm >= 1, "must stay inside the advertised range, got {dbm}");
    }

    /// The two scales must express the *same* policy: whenever one backs off, so
    /// does the other. This is what stops them drifting apart.
    #[test]
    fn both_scales_agree_on_when_to_back_off() {
        let p = RadioPolicy::default();
        let cap = RadioCapability::wifi_halow_s1g(vec![36]).with_tx_power_dbm(DbmRange::new(1, 27));
        for rssi in [-30i8, -50, -70, -90] {
            let idx = p.decide_power(&cap, 0, Some(rssi));
            let dbm = p.decide_power_dbm(&cap, 0, Some(rssi));
            assert_eq!(
                idx.is_some(),
                dbm.is_some(),
                "index and dBm disagreed at rssi {rssi}"
            );
        }
    }

    /// A radio that advertises no dBm range gets no dBm decision — the planner
    /// must not invent absolute power for hardware that cannot take it.
    #[test]
    fn no_advertised_range_means_no_dbm_decision() {
        let p = RadioPolicy::default();
        let cap = RadioCapability::wifi_monitor_5ghz(vec![149]); // index-only
        assert!(cap.tx_power_dbm.is_none());
        assert_eq!(p.decide_power_dbm(&cap, 0, Some(-30)), None);
        // ...but the index path still decides, so such a radio is not left un-actuated.
        assert!(p.decide_power(&cap, 0, Some(-30)).is_some());
    }

    /// No measured peer = no surplus to give back = leave the power alone.
    #[test]
    fn no_rssi_leaves_power_untouched() {
        let p = RadioPolicy::default();
        let cap = RadioCapability::wifi_halow_s1g(vec![36]).with_tx_power_dbm(DbmRange::new(1, 27));
        assert_eq!(p.decide_power_dbm(&cap, 0, None), None);
    }

    /// The back-off is bounded, so a wildly optimistic RSSI cannot drive power
    /// below what the radio can actually be commanded to.
    #[test]
    fn decision_stays_inside_the_range_under_extreme_margin() {
        let p = RadioPolicy::default();
        let range = DbmRange::new(20, 27); // a narrow-range radio
        let cap = RadioCapability::wifi_halow_s1g(vec![36]).with_tx_power_dbm(range);
        let dbm = p.decide_power_dbm(&cap, 0, Some(0)).expect("huge margin");
        assert!(
            (range.min..=range.max).contains(&dbm),
            "{dbm} escaped {range:?}"
        );
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
        let ctx = NameContext {
            is_origin: false,
            ..NameContext::new(0xAA)
        };
        let p = RadioPolicy::default().decide(&ctx, &m, 1_000);
        assert!(p.suppress);
        assert!(p.allocations.is_empty());
    }

    #[test]
    fn relay_transmits_when_innovative() {
        let mut m = wifi_only();
        m.observe_rx(W, 1, Some(-60), 1_000); // a live receiver
        m.observe_rank_deficit(0xAA, 2.0, 1_000); // still rank-deficient
        let ctx = NameContext {
            is_origin: false,
            ..NameContext::new(0xAA)
        };
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

        let broad_mcs = broad.allocations[0].params.mcs().unwrap();
        let uni_mcs = uni.allocations[0].params.mcs().unwrap();
        assert!(
            broad_mcs < uni_mcs,
            "broad {broad_mcs} should be < unicast {uni_mcs}"
        );
    }

    /// The worst-overheard-receiver cap: a neighbour that advertises a single-RX-chain capability
    /// (`SINGLE_STREAM_HT_RX_MCS` = 7) forces the transmit down to single-stream ≤ MCS 7 even on a
    /// strong bulk link — because a 1-chain radio cannot decode a 2-stream frame at *any* index. This
    /// is the fix for the field-diagnosed one-way link (a peer TXing 2-stream MCS 9 the drone's
    /// userspace RTL8812EU could never decode).
    #[test]
    fn single_stream_neighbor_caps_mcs_and_stream_count() {
        use crate::report::{FULL_RX_MCS, SINGLE_STREAM_HT_RX_MCS};
        use crate::sense::NeighborReport;

        // A strong single-receiver bulk link: uncapped, cognition provisions a high, 2-stream rate.
        let ctx = NameContext {
            priority: Priority::Bulk,
            ..NameContext::new(0xAA)
        };
        let decide_for = |max_rx: u8| {
            let mut m = wifi_only();
            m.observe_rx(W, 1, Some(-45), 1_000); // strong link ⇒ high uncapped MCS
            m.observe_report(
                1,
                NeighborReport {
                    heard_prefixes: vec![],
                    quality_dbm: Some(-45),
                    spectrum: vec![],
                    max_rx_mcs: max_rx,
                    ts_ms: 1_000,
                },
            );
            RadioPolicy::default().decide(&ctx, &m, 1_000).allocations[0].params
        };

        let full = decide_for(FULL_RX_MCS);
        let single = decide_for(SINGLE_STREAM_HT_RX_MCS);

        assert!(
            single.mcs().unwrap() <= 7,
            "1-chain neighbour must cap MCS at 7, got {:?}",
            single.mcs()
        );
        assert_eq!(single.nss(), Some(1), "1-chain neighbour cannot decode 2 streams");
        // And the cap is what changed it: the full-capable neighbour is strictly more aggressive.
        assert!(
            full.mcs().unwrap() > single.mcs().unwrap() || full.nss() > single.nss(),
            "full neighbour ({:?}/{:?} MCS/nss) should out-rate the capped one ({:?}/{:?})",
            full.mcs(),
            full.nss(),
            single.mcs(),
            single.nss(),
        );
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
        assert!(
            parity_many < parity_one,
            "pooling should discount: {parity_many} < {parity_one}"
        );
    }

    /// The pooling discount is **doubly gated** (`fec_pooling.rs`): it is legal only for
    /// any-of names on an uncorrelated channel. Ungated `phy^n` under-provisions an all-of
    /// (alarm) name to ~0 delivery at n≥2, and any name on a contended channel.
    #[test]
    fn pooling_discount_is_gated_by_semantics_and_correlation() {
        let base = || {
            let mut m = wifi_only();
            for n in 0..6 {
                m.observe_rx(W, n, Some(-80), 1_000);
            }
            m.observe_phy_per(W, 0.3);
            m.observe_rank_deficit(0xAA, 1.0, 1_000);
            m
        };
        let parity = |pri: Priority, m: &MediumState| {
            RadioPolicy::default()
                .decide(&NameContext { priority: pri, ..NameContext::new(0xAA) }, m, 1_000)
                .allocations[0]
                .params
                .link_fec_redundancy
                .unwrap_or(0)
        };

        // Baseline: a Bulk (any-of) name on a clear channel gets the full discount.
        let bulk_clear = parity(Priority::Bulk, &base());

        // SEMANTICS GATE: an Urgent (all-of — every receiver must decode) name gets NO
        // discount, so strictly more parity than the any-of name at the same count.
        let urgent_clear = parity(Priority::Urgent, &base());
        assert!(
            urgent_clear > bulk_clear,
            "all-of must not be discounted: urgent {urgent_clear} > bulk {bulk_clear}"
        );

        // CORRELATION GATE: on a fully-busy (contended) channel the losses correlate, so
        // the pool collapses toward one receiver → more parity even for a Bulk name.
        let mut busy = base();
        for ch in [149u8, 161, 165] {
            busy.observe_occupancy(ChannelOccupancy { radio: W, channel: ch, busy_pct: 100, ts_ms: 1_000 });
        }
        let bulk_busy = parity(Priority::Bulk, &busy);
        assert!(
            bulk_busy > bulk_clear,
            "correlated (busy) loss must undo the discount: busy {bulk_busy} > clear {bulk_clear}"
        );
    }

    #[test]
    fn heterogeneous_bulk_prefers_wifi_urgent_prefers_lora() {
        let m = hetero();
        let bulk = RadioPolicy::default().decide(
            &NameContext {
                priority: Priority::Bulk,
                ..NameContext::new(0xAA)
            },
            &m,
            1_000,
        );
        assert_eq!(bulk.allocations[0].radio, W, "bulk → high-rate Wi-Fi");

        let urgent = RadioPolicy::default().decide(
            &NameContext {
                priority: Priority::Urgent,
                ..NameContext::new(0xAA)
            },
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
        assert_eq!(
            p.allocations.len(),
            2,
            "should replicate across both radios"
        );
    }

    #[test]
    fn split_role_when_coded_and_heterogeneous() {
        let mut m = hetero();
        m.observe_rank_deficit(0xAA, 3.0, 1_000);
        let ctx = NameContext {
            generation: Some(7),
            ..NameContext::new(0xAA)
        };
        let p = RadioPolicy::default().decide(&ctx, &m, 1_000);
        assert_eq!(p.allocations.len(), 2);
        assert_eq!(p.allocations[1].role, AllocRole::Split);
    }

    #[test]
    fn consistency_digest_is_deterministic() {
        let m = hetero();
        let a = RadioPolicy::default().decide(&NameContext::new(0xAA), &m, 1_000);
        let b = RadioPolicy::default().decide(&NameContext::new(0xAA), &m, 5_000);
        assert_eq!(
            a.consistency, b.consistency,
            "same name+demand ⇒ same plan digest"
        );
    }

    #[test]
    fn rationale_captures_the_why_of_a_decision() {
        let mut m = wifi_only();
        m.observe_occupancy(ChannelOccupancy { radio: W, channel: 149, busy_pct: 80, ts_ms: 1 });
        m.observe_occupancy(ChannelOccupancy { radio: W, channel: 161, busy_pct: 10, ts_ms: 1 });
        m.observe_occupancy(ChannelOccupancy { radio: W, channel: 165, busy_pct: 50, ts_ms: 1 });

        // Origin transmits: the rationale explains the plan — the picked channel and
        // the occupancy that picked it are both in the "why".
        let (plan, why) = RadioPolicy::default().decide_traced(&NameContext::new(0xAA), &m, 1_000);
        assert_eq!(why.suppress, None);
        assert!(why.is_origin, "origin transmits regardless of receiver count");
        assert!(!why.radios.is_empty());
        assert_eq!(why.radios.len(), plan.allocations.len());
        let r0 = why.radios[0];
        assert_eq!(r0.channel, Some(161), "chose least-busy");
        assert_eq!(r0.channel_busy_pct, Some(10), "and the trace records why (10% busy)");
        assert_eq!(r0.channel, plan.allocations[0].channel, "input matches the output");

        // A relay with nothing to add is suppressed — and the trace says *why*.
        let (plan, why) = RadioPolicy::default().decide_traced(&NameContext::relayed(0xBB), &m, 1_000);
        assert!(plan.suppress);
        assert_eq!(why.suppress, Some(SuppressReason::RelayAddsNoRank));
    }

    #[test]
    fn picks_least_busy_channel() {
        let mut m = wifi_only();
        m.observe_occupancy(ChannelOccupancy {
            radio: W,
            channel: 149,
            busy_pct: 80,
            ts_ms: 1,
        });
        m.observe_occupancy(ChannelOccupancy {
            radio: W,
            channel: 161,
            busy_pct: 10,
            ts_ms: 1,
        });
        m.observe_occupancy(ChannelOccupancy {
            radio: W,
            channel: 165,
            busy_pct: 50,
            ts_ms: 1,
        });
        let p = RadioPolicy::default().decide(&NameContext::new(0xAA), &m, 1_000);
        assert_eq!(p.allocations[0].channel, Some(161));
    }
}
