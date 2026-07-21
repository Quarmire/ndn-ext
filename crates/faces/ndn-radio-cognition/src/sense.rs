//! The **sense bus** — the unified, MRMC-native cross-layer medium state.
//!
//! Keyed by `(RadioId, Channel)` from the first line (multi-radio / multi-channel
//! is the default, not a bolt-on): a node may hold a Wi-Fi monitor radio, a LoRa
//! radio, and an RX-only SDR sensor simultaneously, each seeing a different slice
//! of the medium. The sense bus fuses our own radios' observations + neighbors'
//! shared (named, signed) reports into one picture the policy reads.

use std::collections::HashMap;

use crate::report::ReceptionReport;

// The capability descriptor + its axes (`Band`, `RadioKind`, `TimingModel`,
// `RadioCapability`) moved down into the shared HAL crate (`ndn-radio-hal`) so a
// driver depends on one contract crate. Re-exported here so every crate-internal
// reference (`Band::`, `RadioKind::`, `TimingModel`, `RadioCapability`, used by
// this module, `policy.rs`, and the `lib.rs` re-export) still resolves through
// `crate::sense::…` / `crate::…` unchanged.
pub use ndn_radio_hal::{Band, RadioCapability, RadioKind, RateCapability, TimingModel};

/// Identifies one physical radio / face on this node. The degenerate single-radio
/// case is just one `RadioId`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RadioId(pub u16);

/// Exponentially-weighted moving average — controllers act on the EWMA, never the
/// instantaneous sample, to avoid oscillation.
#[derive(Clone, Copy, Debug)]
pub struct Ewma {
    value: Option<f32>,
    alpha: f32,
}

impl Default for Ewma {
    fn default() -> Self {
        Ewma::new(0.3)
    }
}

impl Ewma {
    /// `alpha` in (0,1] — higher tracks faster, lower is smoother.
    pub fn new(alpha: f32) -> Self {
        Self {
            value: None,
            alpha: alpha.clamp(0.001, 1.0),
        }
    }
    pub fn update(&mut self, sample: f32) {
        self.value = Some(match self.value {
            None => sample,
            Some(v) => v + self.alpha * (sample - v),
        });
    }
    pub fn get(&self) -> Option<f32> {
        self.value
    }
    /// Value or a default when unseeded.
    pub fn get_or(&self, default: f32) -> f32 {
        self.value.unwrap_or(default)
    }
}

/// Channel occupancy from the CLM/CCA engine (or, far better, an SDR PSD scan):
/// % of the medium busy on `(radio, channel)`.
#[derive(Clone, Copy, Debug)]
pub struct ChannelOccupancy {
    pub radio: RadioId,
    pub channel: u8,
    pub busy_pct: u8,
    pub ts_ms: u64,
}

/// Frame-activity rate (frames/s) at which the channel is treated as fully
/// occupied (`busy_pct` = 100). Anchored on measurement (#30/#36/#37): the
/// 8812au's `REG_RXERR_RPT` delta read ~100 frames/s on the ch6 that behaved as
/// saturated (EDCCA starved TX, heavy loss), and ~19/s on the same channel when
/// it was merely mid-load. Calibratable per environment/radio.
pub const DEFAULT_SATURATION_FPS: f32 = 100.0;

impl ChannelOccupancy {
    /// Build occupancy from a measured **frame-activity rate** (`frames_per_s`) —
    /// e.g. the 8812au frame-free sensor (`REG_RXERR_RPT` delta / window, #30).
    /// The rate is interpreted as airtime occupancy that saturates at `sat_fps`
    /// frames/s → 100% busy: `busy_pct = round(100 · frames_per_s / sat_fps)`,
    /// clamped to 0..=100. A monotone, calibrated load signal — deliberately not a
    /// physics-exact airtime integral, since per-frame length/rate isn't sensed.
    /// Pass [`DEFAULT_SATURATION_FPS`] for `sat_fps` unless calibrated otherwise.
    pub fn from_activity(
        radio: RadioId,
        channel: u8,
        frames_per_s: f32,
        sat_fps: f32,
        ts_ms: u64,
    ) -> Self {
        let busy_pct = if sat_fps > 0.0 && frames_per_s > 0.0 {
            (100.0 * frames_per_s / sat_fps).round().clamp(0.0, 100.0) as u8
        } else {
            0
        };
        ChannelOccupancy {
            radio,
            channel,
            busy_pct,
            ts_ms,
        }
    }
}

/// Residual loss *below* a layer on one radio (fraction 0..1), EWMA-smoothed. The
/// budget allocator sizes each layer's redundancy from the residual left below it.
#[derive(Clone, Copy, Debug)]
pub struct LinkResidual {
    /// Post-PHY-FEC (LDPC) frame error rate (RX-desc CRC fails / frames).
    pub phy_per: Ewma,
    /// Post-link-FEC frame erasure rate (generations not recovered).
    pub link_per: Ewma,
}

impl Default for LinkResidual {
    fn default() -> Self {
        Self {
            phy_per: Ewma::new(0.2),
            link_per: Ewma::new(0.2),
        }
    }
}

/// What a neighbor reported overhearing + its spectrum view — the cooperation
/// channel (a named, signed control frame). The same named-data fusion pattern
/// serves both spectrum reports and (later) reception/rank reports.
#[derive(Clone, Debug, Default)]
pub struct NeighborReport {
    /// Hashes of name-prefixes this neighbor recently heard (receiver multiplicity
    /// + COPE side-info hints: who already holds what).
    pub heard_prefixes: Vec<u64>,
    pub quality_dbm: Option<i8>,
    /// The neighbor's per-channel busy% view: `(channel, busy_pct)`.
    pub spectrum: Vec<(u8, u8)>,
    pub ts_ms: u64,
}

/// Demand for a named object — the control unit. Drawn from what the forwarder
/// already knows: PIT fan-out (listeners), CCLF content-connectivity score,
/// measured re-Interest rate (the real ARQ signal the budget optimizes against),
/// and the diversity reception dimension (pooled rank deficit across the demand
/// set after combining).
#[derive(Clone, Copy, Debug)]
pub struct Demand {
    /// PIT in-records / downstream faces wanting this name.
    pub fanout: u32,
    /// CCLF content-connectivity score (how wanted, regionally).
    pub ccs: f32,
    /// Measured re-Interest (re-expression) rate — ARQ-elimination's signal; the
    /// budget is allocated to drive THIS down, not an abstract residual.
    pub reinterest_rate: Ewma,
    /// Expected rank deficit of the demand set **after** macrodiversity pooling
    /// (0 = satisfied). The post-pooling budget target, not worst-link PER.
    pub rank_deficit: Ewma,
    pub ts_ms: u64,
}

impl Default for Demand {
    fn default() -> Self {
        Self {
            fanout: 0,
            ccs: 0.0,
            reinterest_rate: Ewma::new(0.3),
            rank_deficit: Ewma::new(0.3),
            ts_ms: 0,
        }
    }
}

#[derive(Clone, Debug, Default)]
struct NeighborState {
    /// RSSI EWMA per radio that hears this neighbor (LoRa hears far, Wi-Fi near).
    rssi: HashMap<RadioId, Ewma>,
    report: Option<NeighborReport>,
    last_seen_ms: u64,
}

/// The unified MRMC cross-layer medium state. Fed by each radio (RX/occupancy/
/// residual) and by cooperation (neighbor reports); read by the policy.
#[derive(Default)]
pub struct MediumState {
    radios: HashMap<RadioId, RadioCapability>,
    occupancy: HashMap<(RadioId, u8), ChannelOccupancy>,
    residual: HashMap<RadioId, LinkResidual>,
    e2e: Ewma,
    neighbors: HashMap<u64, NeighborState>,
    demand: HashMap<u64, Demand>,
    /// Per-radio on-air time records `(sent_ms, airtime_ms)` over the duty window, for enforcing
    /// [`RadioCapability::duty_cycle_max`] (LoRa sub-GHz ≈ 1%).
    airtime: HashMap<RadioId, Vec<(u64, f32)>>,
    stale_ms: u64,
}

/// Sliding window over which duty cycle is measured (1 h — the ETSI sub-GHz reference period).
pub const DUTY_WINDOW_MS: u64 = 3_600_000;

/// LoRa on-air time (ms) for `payload` bytes at the given spreading factor / bandwidth (kHz) /
/// coding rate — the Semtech airtime formula (explicit header, 8-symbol preamble, CRC on, and the
/// low-data-rate optimize engaged at SF ≥ 11). The input to duty-cycle accounting.
pub fn lora_airtime_ms(sf: u8, bw_khz: u32, cr: u8, payload: usize) -> f32 {
    let sf = sf.clamp(7, 12) as f32;
    let bw = (bw_khz.max(1) as f32) * 1000.0; // Hz
    let cr = cr.clamp(1, 4) as f32; // 1..4 → 4/5..4/8
    let t_sym = 2.0_f32.powf(sf) / bw; // seconds per symbol
    let de = if sf >= 11.0 { 1.0 } else { 0.0 }; // low-data-rate optimize
    let t_preamble = (8.0 + 4.25) * t_sym;
    let num = 8.0 * payload as f32 - 4.0 * sf + 28.0 + 16.0; // explicit header, CRC on
    let den = 4.0 * (sf - 2.0 * de);
    let payload_symb = 8.0 + ((num / den).ceil().max(0.0)) * (cr + 4.0);
    let t_payload = payload_symb * t_sym;
    (t_preamble + t_payload) * 1000.0
}

impl MediumState {
    pub fn new() -> Self {
        Self {
            e2e: Ewma::new(0.2),
            stale_ms: 10_000,
            ..Default::default()
        }
    }

    /// Maximum age (ms) before a neighbor is dropped as a live receiver.
    pub fn with_stale_ms(mut self, ms: u64) -> Self {
        self.stale_ms = ms;
        self
    }

    // ---- registration ----

    /// Declare a local radio and its capabilities (call once per radio/face).
    pub fn register_radio(&mut self, id: RadioId, cap: RadioCapability) {
        self.radios.insert(id, cap);
        self.residual.entry(id).or_default();
    }

    /// Record `airtime_ms` of on-air time for `radio` at `now_ms` — call once per transmission on a
    /// duty-cycled radio ([`lora_airtime_ms`] gives the value). Old records fall out of the window.
    pub fn record_airtime(&mut self, radio: RadioId, airtime_ms: f32, now_ms: u64) {
        let cutoff = now_ms.saturating_sub(DUTY_WINDOW_MS);
        let recs = self.airtime.entry(radio).or_default();
        recs.push((now_ms, airtime_ms));
        recs.retain(|(t, _)| *t >= cutoff);
    }

    // ---- SENSE inputs (push) ----

    pub fn observe_rx(&mut self, radio: RadioId, neighbor: u64, rssi_dbm: Option<i8>, now_ms: u64) {
        let st = self.neighbors.entry(neighbor).or_default();
        st.last_seen_ms = now_ms;
        if let Some(r) = rssi_dbm {
            st.rssi
                .entry(radio)
                .or_insert_with(|| Ewma::new(0.3))
                .update(r as f32);
        }
    }

    pub fn observe_occupancy(&mut self, occ: ChannelOccupancy) {
        self.occupancy.insert((occ.radio, occ.channel), occ);
    }

    pub fn observe_phy_per(&mut self, radio: RadioId, per: f32) {
        self.residual.entry(radio).or_default().phy_per.update(per);
    }
    pub fn observe_link_per(&mut self, radio: RadioId, per: f32) {
        self.residual.entry(radio).or_default().link_per.update(per);
    }
    pub fn observe_e2e_per(&mut self, per: f32) {
        self.e2e.update(per);
    }

    pub fn observe_report(&mut self, neighbor: u64, report: NeighborReport) {
        let now = report.ts_ms;
        let st = self.neighbors.entry(neighbor).or_default();
        st.last_seen_ms = now;
        st.report = Some(report);
    }

    /// Set/replace the demand record for a prefix-hash (from PIT + CCLF + measured
    /// re-Interest rate + pooled rank deficit).
    pub fn observe_demand(&mut self, prefix_hash: u64, demand: Demand) {
        self.demand.insert(prefix_hash, demand);
    }

    /// Feed the re-Interest rate for a prefix (the ARQ signal), creating the demand
    /// record if absent.
    pub fn observe_reinterest(&mut self, prefix_hash: u64, rate: f32, now_ms: u64) {
        let d = self.demand.entry(prefix_hash).or_default();
        d.reinterest_rate.update(rate);
        d.ts_ms = now_ms;
    }

    /// Feed the post-pooling rank deficit for a prefix (the diversity signal).
    pub fn observe_rank_deficit(&mut self, prefix_hash: u64, deficit: f32, now_ms: u64) {
        let d = self.demand.entry(prefix_hash).or_default();
        d.rank_deficit.update(deficit);
        d.ts_ms = now_ms;
    }

    pub fn prune(&mut self, now_ms: u64) {
        let stale = self.stale_ms;
        self.neighbors
            .retain(|_, s| now_ms.saturating_sub(s.last_seen_ms) <= stale);
    }

    fn fresh(&self, last_seen_ms: u64, now_ms: u64) -> bool {
        now_ms.saturating_sub(last_seen_ms) <= self.stale_ms
    }

    /// Snapshot our observations into a [`ReceptionReport`] to broadcast: which
    /// fresh neighbours we hear (+ best RSSI), the prefixes we're tracking, and our
    /// per-channel busy view (collapsed across radios). Lists are bounded by the
    /// encoder.
    pub fn snapshot_report(&self, node_id: u64, seq: u32, now_ms: u64) -> ReceptionReport {
        let mut heard_neighbors = Vec::new();
        for (&n, st) in &self.neighbors {
            if self.fresh(st.last_seen_ms, now_ms)
                && let Some(r) = st
                    .rssi
                    .values()
                    .filter_map(|e| e.get())
                    .max_by(|a, b| a.total_cmp(b))
            {
                heard_neighbors.push((n, r.round().clamp(-128.0, 0.0) as i8));
            }
        }
        let heard_prefixes: Vec<u64> = self.demand.keys().copied().collect();
        let mut spec: HashMap<u8, u8> = HashMap::new();
        for ((_, ch), occ) in &self.occupancy {
            let e = spec.entry(*ch).or_insert(0);
            *e = (*e).max(occ.busy_pct);
        }
        ReceptionReport {
            node_id,
            seq,
            ts_ms: now_ms,
            heard_neighbors,
            heard_prefixes,
            spectrum: spec.into_iter().collect(),
        }
    }
}

/// Read-only view the `RadioPolicy` decides against (decouples the policy from how
/// state was gathered). MRMC-keyed throughout.
pub trait MediumView {
    /// Local radios available, with capabilities.
    fn radios(&self) -> Vec<(RadioId, RadioCapability)>;
    fn capability(&self, radio: RadioId) -> Option<RadioCapability>;
    /// Per-radio residual loss below each layer.
    fn residual(&self, radio: RadioId) -> Option<LinkResidual>;
    /// End-to-end (network-layer) residual segment loss.
    fn e2e_residual(&self) -> Ewma;
    /// Busy% on `(radio, channel)`, if measured.
    fn busy_pct(&self, radio: RadioId, channel: u8) -> Option<u8>;
    /// Live cooperative receivers (fresh neighbors) — the multiplicity that
    /// discounts per-link redundancy.
    fn receiver_count(&self, now_ms: u64) -> usize;
    /// EWMA RSSI (dBm) of a neighbor as heard on `radio`.
    fn neighbor_rssi(&self, radio: RadioId, neighbor: u64) -> Option<i8>;
    /// Best EWMA RSSI of a neighbor across any of our radios.
    fn neighbor_best_rssi(&self, neighbor: u64) -> Option<i8>;
    /// RSSI (dBm) of the **weakest** fresh receiver heard on `radio` — the
    /// conservative demand-set representative: provision the rate/redundancy for
    /// the worst listener, not the best. `None` when no receiver is heard.
    fn weakest_rssi(&self, radio: RadioId, now_ms: u64) -> Option<i8>;
    /// Fresh neighbors reporting they already hold this prefix-hash.
    fn neighbors_holding(&self, prefix_hash: u64, now_ms: u64) -> usize;
    /// Demand for a prefix-hash, if known.
    fn demand(&self, prefix_hash: u64) -> Option<Demand>;
    /// Fraction of the duty window `radio` has spent transmitting (0.0 when nothing is recorded,
    /// e.g. an unrestricted Wi-Fi radio). The policy compares this to
    /// [`RadioCapability::duty_cycle_max`] and skips a radio that has spent its budget.
    fn duty_used(&self, _radio: RadioId, _now_ms: u64) -> f32 {
        0.0
    }
}

impl MediumView for MediumState {
    fn radios(&self) -> Vec<(RadioId, RadioCapability)> {
        let mut v: Vec<_> = self.radios.iter().map(|(id, c)| (*id, c.clone())).collect();
        v.sort_by_key(|(id, _)| *id);
        v
    }
    fn capability(&self, radio: RadioId) -> Option<RadioCapability> {
        self.radios.get(&radio).cloned()
    }
    fn duty_used(&self, radio: RadioId, now_ms: u64) -> f32 {
        let cutoff = now_ms.saturating_sub(DUTY_WINDOW_MS);
        let sum: f32 = self
            .airtime
            .get(&radio)
            .map(|recs| {
                recs.iter()
                    .filter(|(t, _)| *t >= cutoff)
                    .map(|(_, a)| *a)
                    .sum()
            })
            .unwrap_or(0.0);
        sum / DUTY_WINDOW_MS as f32
    }
    fn residual(&self, radio: RadioId) -> Option<LinkResidual> {
        self.residual.get(&radio).copied()
    }
    fn e2e_residual(&self) -> Ewma {
        self.e2e
    }
    fn busy_pct(&self, radio: RadioId, channel: u8) -> Option<u8> {
        self.occupancy.get(&(radio, channel)).map(|o| o.busy_pct)
    }
    fn receiver_count(&self, now_ms: u64) -> usize {
        self.neighbors
            .values()
            .filter(|s| self.fresh(s.last_seen_ms, now_ms))
            .count()
    }
    fn neighbor_rssi(&self, radio: RadioId, neighbor: u64) -> Option<i8> {
        self.neighbors
            .get(&neighbor)
            .and_then(|s| s.rssi.get(&radio))
            .and_then(|e| e.get())
            .map(|v| v.round().clamp(-128.0, 0.0) as i8)
    }
    fn neighbor_best_rssi(&self, neighbor: u64) -> Option<i8> {
        self.neighbors.get(&neighbor).and_then(|s| {
            s.rssi
                .values()
                .filter_map(|e| e.get())
                .max_by(|a, b| a.total_cmp(b))
                .map(|v| v.round().clamp(-128.0, 0.0) as i8)
        })
    }
    fn neighbors_holding(&self, prefix_hash: u64, now_ms: u64) -> usize {
        self.neighbors
            .values()
            .filter(|s| self.fresh(s.last_seen_ms, now_ms))
            .filter(|s| {
                s.report
                    .as_ref()
                    .is_some_and(|r| r.heard_prefixes.contains(&prefix_hash))
            })
            .count()
    }
    fn weakest_rssi(&self, radio: RadioId, now_ms: u64) -> Option<i8> {
        self.neighbors
            .values()
            .filter(|s| self.fresh(s.last_seen_ms, now_ms))
            .filter_map(|s| s.rssi.get(&radio).and_then(|e| e.get()))
            .min_by(|a, b| a.total_cmp(b))
            .map(|v| v.round().clamp(-128.0, 0.0) as i8)
    }
    fn demand(&self, prefix_hash: u64) -> Option<Demand> {
        self.demand.get(&prefix_hash).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const W: RadioId = RadioId(0);
    const L: RadioId = RadioId(1);

    fn state() -> MediumState {
        let mut m = MediumState::new();
        m.register_radio(W, RadioCapability::wifi_monitor_5ghz(vec![149, 161, 165]));
        m.register_radio(L, RadioCapability::lora(vec![0]));
        m
    }

    #[test]
    fn occupancy_from_activity_maps_frames_per_s_to_busy_pct() {
        let sat = DEFAULT_SATURATION_FPS; // 100 fps → 100% busy
        let busy = |fps: f32| ChannelOccupancy::from_activity(W, 6, fps, sat, 0).busy_pct;
        assert_eq!(busy(0.0), 0, "quiet channel");
        assert_eq!(busy(19.0), 19, "mid-load ~ the measured ch6 mid case");
        assert_eq!(busy(50.0), 50);
        assert_eq!(busy(100.0), 100, "saturated ~ the measured ch6 heavy case");
        assert_eq!(busy(250.0), 100, "clamps, never exceeds 100");
        // The policy's least-busy channel selection reads exactly this busy_pct.
        let occ = ChannelOccupancy::from_activity(W, 6, 30.0, sat, 1234);
        assert_eq!((occ.radio, occ.channel, occ.ts_ms), (W, 6, 1234));
    }

    #[test]
    fn occupancy_from_activity_tolerates_zero_saturation() {
        assert_eq!(
            ChannelOccupancy::from_activity(W, 6, 50.0, 0.0, 0).busy_pct,
            0,
            "no divide-by-zero; degenerate sat_fps → 0"
        );
    }

    #[test]
    fn rate_capability_is_bearer_typed_and_ranks_across_bearers() {
        let wifi = RadioCapability::wifi_monitor_5ghz(vec![149]);
        let lora = RadioCapability::lora(vec![0]);
        let sdr = RadioCapability::sdr_sensor(vec![36]);
        // The rate ceiling is a bearer sum type — no privileged field.
        assert!(matches!(wifi.rate, RateCapability::Wifi { max_mcs: 9, .. }));
        assert_eq!(lora.rate, RateCapability::Lora { min_sf: 7, max_sf: 12 });
        assert_eq!(sdr.rate, RateCapability::None);
        // Bearer-agnostic rank: Wi-Fi ≫ LoRa > SDR-sensor, all comparable in [0,1].
        assert!(wifi.rate_rank() > lora.rate_rank());
        assert!(lora.rate_rank() > sdr.rate_rank());
        assert_eq!(sdr.rate_rank(), 0.0);
        // Typed accessors return only for the matching bearer.
        assert_eq!(wifi.max_mcs(), 9);
        assert_eq!(lora.max_mcs(), 0); // LoRa has no MCS
        assert_eq!(lora.sf_range(), Some((7, 12)));
        assert_eq!(wifi.sf_range(), None);
    }

    #[test]
    fn lora_airtime_grows_with_sf() {
        // Airtime roughly doubles per SF step; SF12 is far slower than SF7 for the same payload.
        let a7 = lora_airtime_ms(7, 125, 1, 40);
        let a12 = lora_airtime_ms(12, 125, 1, 40);
        assert!(a7 > 0.0 && a12 > a7 * 8.0, "SF12 ≫ SF7: {a7} vs {a12}");
    }

    #[test]
    fn duty_used_accumulates_and_windows_out() {
        let mut m = state();
        // Charge 30 s of airtime → 30_000 / 3_600_000 ≈ 0.83% of the 1 h window.
        m.record_airtime(L, 30_000.0, 1_000);
        let used = m.duty_used(L, 2_000);
        assert!((used - 30_000.0 / DUTY_WINDOW_MS as f32).abs() < 1e-6);
        assert!(used < 0.01, "under the 1% LoRa ceiling: {used}");
        // A Wi-Fi radio with nothing recorded reads zero.
        assert_eq!(m.duty_used(W, 2_000), 0.0);
        // Far past the window, the record ages out.
        assert_eq!(m.duty_used(L, 1_000 + DUTY_WINDOW_MS + 1), 0.0);
    }

    #[test]
    fn ewma_smooths() {
        let mut e = Ewma::new(0.5);
        assert_eq!(e.get(), None);
        e.update(10.0);
        assert_eq!(e.get(), Some(10.0));
        e.update(20.0);
        assert_eq!(e.get(), Some(15.0));
    }

    #[test]
    fn per_radio_rssi_and_best() {
        let mut m = state();
        m.observe_rx(W, 7, Some(-55), 1_000); // near on Wi-Fi
        m.observe_rx(L, 7, Some(-95), 1_000); // far on LoRa
        assert_eq!(m.neighbor_rssi(W, 7), Some(-55));
        assert_eq!(m.neighbor_rssi(L, 7), Some(-95));
        assert_eq!(m.neighbor_best_rssi(7), Some(-55));
    }

    #[test]
    fn receiver_count_staleness() {
        let mut m = state();
        m.observe_rx(W, 1, Some(-50), 1_000);
        m.observe_rx(W, 2, Some(-60), 1_000);
        assert_eq!(m.receiver_count(1_000), 2);
        assert_eq!(m.receiver_count(20_000), 0);
        m.prune(20_000);
        assert_eq!(m.receiver_count(20_000), 0);
    }

    #[test]
    fn occupancy_and_holding_mrmc() {
        let mut m = state();
        m.observe_occupancy(ChannelOccupancy {
            radio: W,
            channel: 149,
            busy_pct: 40,
            ts_ms: 1,
        });
        assert_eq!(m.busy_pct(W, 149), Some(40));
        assert_eq!(m.busy_pct(W, 161), None);
        assert_eq!(m.busy_pct(L, 149), None); // per-radio keyed

        m.observe_report(
            7,
            NeighborReport {
                heard_prefixes: vec![0xABCD],
                quality_dbm: Some(-55),
                spectrum: vec![(149, 40)],
                ts_ms: 100,
            },
        );
        assert_eq!(m.neighbors_holding(0xABCD, 100), 1);
        assert_eq!(m.neighbors_holding(0x1234, 100), 0);
    }

    #[test]
    fn demand_signals() {
        let mut m = state();
        m.observe_reinterest(0xAA, 0.3, 5);
        m.observe_rank_deficit(0xAA, 2.0, 5);
        let d = m.demand(0xAA).unwrap();
        assert!((d.reinterest_rate.get().unwrap() - 0.3).abs() < 1e-6);
        assert!((d.rank_deficit.get().unwrap() - 2.0).abs() < 1e-6);
    }
}
