//! Airtime-per-satisfied-Interest measurement harness — A/B the cognitive control
//! loop against fixed-MCS "blast" baselines (the wfb-ng comparison).
//!
//! The optimand is **airtime per satisfied Interest**. A fixed-MCS blast (wfb-ng)
//! must pick one rate for all conditions: too high → it falls off the SNR cliff and
//! every Interest is re-expressed many times (airtime wasted on failures); too low
//! → it delivers but each frame hogs the air. The cognitive loop picks the rate per
//! measured condition, so it tracks the *lower envelope* of every fixed curve.
//!
//! This harness is **analytic and deterministic** (closed-form expected airtime, no
//! RNG) so the result is reproducible and unit-testable, and it drives the **real**
//! [`RadioControl`]/[`RadioPolicy`] for the adaptive arm — it measures the actual
//! decision code, not a re-implementation. The link model is the "truth"; the
//! controller's RSSI→MCS table is the thing under test. On-air A/B (against a real
//! receiver) is the same scoring applied to measured delivery — see the note.
//!
//! [`RadioControl`]: crate::RadioControl
//! [`RadioPolicy`]: ndn_radio_cognition::RadioPolicy

use ndn_radio_cognition::{NameContext, RadioCapability, RadioId, RadioPolicy, TxParams};

use crate::FaceId;
use crate::control::RadioControl;

/// Thermal-noise floor (dBm) the SNR is referenced to (matches the policy's
/// RSSI→MCS thresholds: rssi = NOISE_FLOOR + snr).
pub const NOISE_FLOOR_DBM: f32 = -95.0;

/// HT/VHT PHY data rate (Mbps): 20 MHz 1SS long-GI base scaled by bw/nss/SGI.
pub fn mcs_rate_mbps(p: &TxParams) -> f32 {
    // HT/VHT MCS0–9 (8–9 = VHT 256-QAM), 20 MHz, 1 SS, long GI.
    const BASE: [f32; 10] = [
        6.5, 13.0, 19.5, 26.0, 39.0, 52.0, 58.5, 65.0, 78.0, 87.75,
    ];
    let idx = p.mcs.unwrap_or(0).min(9) as usize;
    let bw = match p.bw.unwrap_or(0) {
        1 => 2.0,   // 40 MHz
        2 => 4.0,   // 80 MHz
        3 => 0.5,   // 10 MHz
        4 => 0.25,  // 5 MHz
        _ => 1.0,   // 20 MHz
    };
    let nss = p.nss.unwrap_or(1).max(1) as f32;
    let sgi = if p.short_gi { 1.0 / 0.9 } else { 1.0 }; // ~+11%
    BASE[idx] * bw * nss * sgi
}

/// Airtime (µs) to put one frame carrying `payload` bytes on the air at `p`'s rate.
pub fn frame_airtime_us(p: &TxParams, payload: usize) -> f32 {
    const PREAMBLE_US: f32 = 40.0; // HT-mixed preamble + per-frame fixed overhead
    const OVERHEAD: usize = 60; // MAC header + FCS + LLC/SNAP
    let bits = ((payload + OVERHEAD) * 8) as f32;
    PREAMBLE_US + bits / mcs_rate_mbps(p)
}

/// SNR (dB) above which an MCS decodes reliably. Aligned with the policy's RSSI→MCS
/// switch points (noise floor −95) minus a 3 dB margin — a well-calibrated
/// controller picks a rate it can actually carry; a fixed too-high MCS falls off.
pub fn required_snr_db(mcs: u8) -> f32 {
    let switch = match mcs {
        0 => 2.0,
        1 => 5.0,
        2 => 9.0,
        3 => 13.0,
        4 => 17.0,
        5 => 22.0,
        6 => 27.0,
        7 => 33.0,
        8 => 39.0,
        _ => 45.0,
    };
    switch - 3.0
}

fn logistic(x: f32) -> f32 {
    1.0 / (1.0 + (-x).exp())
}

/// The "truth": a flat-fading link at a given SNR.
pub struct LinkModel {
    pub snr_db: f32,
}

impl LinkModel {
    /// Per-frame delivery probability at the frame's MCS (LDPC adds ~2 dB gain).
    pub fn frame_delivery(&self, p: &TxParams) -> f32 {
        let req = required_snr_db(p.mcs.unwrap_or(0));
        let gain = if p.ldpc { 2.0 } else { 0.0 };
        logistic((self.snr_db + gain - req) / 1.5) // ~1.5 dB transition width
    }
}

/// Result of scoring one arm against the link.
#[derive(Clone, Copy, Debug)]
pub struct Score {
    /// The optimand: expected airtime spent per satisfied Interest (µs). Lower wins.
    pub airtime_per_satisfied_us: f32,
    /// Fraction of Interests eventually satisfied within `max_attempts`.
    pub delivery_frac: f32,
    pub mcs: u8,
    pub redundancy: u16,
}

/// Score one arm: object = one frame, link-FEC modelled as repetition (`1+r`
/// copies; a faithful-enough redundancy abstraction), ARQ re-expression up to
/// `max_attempts`.
///
/// With per-attempt object delivery `p_obj`, expected attempts to first success is
/// geometric, so the failed-attempt airtime cancels exactly:
/// `airtime/satisfied = attempt_airtime / p_obj`.
pub fn score_arm(p: &TxParams, link: &LinkModel, payload: usize, max_attempts: u32) -> Score {
    let r = p.link_fec_redundancy.unwrap_or(0);
    let pf = link.frame_delivery(p).clamp(1e-6, 1.0);
    let p_obj = 1.0 - (1.0 - pf).powi((1 + r) as i32);
    let attempt_air = (1 + r) as f32 * frame_airtime_us(p, payload);
    Score {
        airtime_per_satisfied_us: attempt_air / p_obj,
        delivery_frac: 1.0 - (1.0 - p_obj).powi(max_attempts as i32),
        mcs: p.mcs.unwrap_or(0),
        redundancy: r,
    }
}

/// Drive the **real** closed loop at `snr_db` and return the MCS it decides.
pub fn adaptive_chosen_mcs(snr_db: f32) -> u8 {
    let radio = RadioId(0);
    let mut c = RadioControl::new(RadioPolicy::default());
    c.register_radio(
        radio,
        FaceId(1),
        RadioCapability::wifi_monitor_5ghz(vec![149]),
    );
    c.set_active(vec![NameContext::new(0x1)]);
    let rssi = (NOISE_FLOOR_DBM + snr_db).round().clamp(-110.0, 0.0) as i8;
    c.observe_rx(radio, 1, Some(rssi), 1_000);
    c.tick_now(1_000)
        .first()
        .and_then(|p| p.allocations.first())
        .and_then(|a| a.params.mcs)
        .unwrap_or(0)
}

/// A common TX template differing only in MCS — so the A/B isolates *rate choice*
/// (the value of adaptation), not bandwidth/coding differences. 80 MHz VHT + LDPC,
/// single stream, long GI; every arm shares it.
pub fn template(mcs: u8) -> TxParams {
    TxParams {
        mcs: Some(mcs),
        vht: true,
        nss: Some(1),
        bw: Some(2),
        ldpc: true,
        ..Default::default()
    }
}

/// Geometric mean (the fair average for ratios across regimes).
pub fn geomean(xs: &[f32]) -> f32 {
    if xs.is_empty() {
        return f32::NAN;
    }
    let s: f32 = xs.iter().map(|x| x.max(1e-9).ln()).sum();
    (s / xs.len() as f32).exp()
}

/// A full SNR sweep: adaptive vs three fixed-MCS baselines, all on [`template`].
pub struct SweepReport {
    pub snrs: Vec<f32>,
    pub adaptive: Vec<Score>,
    pub fixed_high: Vec<Score>, // MCS9 — fast, fragile
    pub fixed_mid: Vec<Score>,  // MCS5 — compromise
    pub fixed_low: Vec<Score>,  // MCS1 — robust, slow
}

impl SweepReport {
    fn aps(scores: &[Score]) -> Vec<f32> {
        scores.iter().map(|s| s.airtime_per_satisfied_us).collect()
    }
    pub fn geomean_adaptive(&self) -> f32 {
        geomean(&Self::aps(&self.adaptive))
    }
    pub fn geomean_fixed_high(&self) -> f32 {
        geomean(&Self::aps(&self.fixed_high))
    }
    pub fn geomean_fixed_mid(&self) -> f32 {
        geomean(&Self::aps(&self.fixed_mid))
    }
    pub fn geomean_fixed_low(&self) -> f32 {
        geomean(&Self::aps(&self.fixed_low))
    }
    /// The headline: the loop beats every single fixed-MCS blast on the optimand.
    pub fn adaptive_wins(&self) -> bool {
        let a = self.geomean_adaptive();
        a <= self.geomean_fixed_high()
            && a <= self.geomean_fixed_mid()
            && a <= self.geomean_fixed_low()
    }
}

/// Run the A/B sweep over `snrs`.
pub fn ab_sweep(snrs: &[f32], payload: usize, max_attempts: u32) -> SweepReport {
    let mut r = SweepReport {
        snrs: snrs.to_vec(),
        adaptive: Vec::new(),
        fixed_high: Vec::new(),
        fixed_mid: Vec::new(),
        fixed_low: Vec::new(),
    };
    for &snr in snrs {
        let link = LinkModel { snr_db: snr };
        let chosen = adaptive_chosen_mcs(snr);
        r.adaptive
            .push(score_arm(&template(chosen), &link, payload, max_attempts));
        r.fixed_high
            .push(score_arm(&template(9), &link, payload, max_attempts));
        r.fixed_mid
            .push(score_arm(&template(5), &link, payload, max_attempts));
        r.fixed_low
            .push(score_arm(&template(1), &link, payload, max_attempts));
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn higher_mcs_is_faster_airtime() {
        let lo = frame_airtime_us(&template(1), 1000);
        let hi = frame_airtime_us(&template(9), 1000);
        assert!(hi < lo, "MCS9 should take less air than MCS1: {hi} vs {lo}");
    }

    #[test]
    fn delivery_falls_off_above_snr_cliff() {
        let weak = LinkModel { snr_db: 8.0 };
        // MCS9 needs ~42 dB SNR → near-zero delivery at 8 dB.
        assert!(weak.frame_delivery(&template(9)) < 0.05);
        // MCS1 needs ~2 dB → reliable at 8 dB.
        assert!(weak.frame_delivery(&template(1)) > 0.95);
    }

    #[test]
    fn controller_tracks_snr() {
        // weak link ⇒ low MCS; strong link ⇒ high MCS.
        assert!(adaptive_chosen_mcs(8.0) <= 2);
        assert!(adaptive_chosen_mcs(45.0) >= 8);
    }

    #[test]
    fn fixed_high_is_terrible_at_low_snr() {
        let link = LinkModel { snr_db: 10.0 };
        let high = score_arm(&template(9), &link, 1000, 8);
        let adaptive = score_arm(&template(adaptive_chosen_mcs(10.0)), &link, 1000, 8);
        assert!(
            adaptive.airtime_per_satisfied_us < high.airtime_per_satisfied_us,
            "adaptive {} should beat fixed-high {} at 10 dB",
            adaptive.airtime_per_satisfied_us,
            high.airtime_per_satisfied_us
        );
    }

    #[test]
    fn fixed_low_wastes_air_at_high_snr() {
        let link = LinkModel { snr_db: 44.0 };
        let low = score_arm(&template(1), &link, 1000, 8);
        let adaptive = score_arm(&template(adaptive_chosen_mcs(44.0)), &link, 1000, 8);
        assert!(
            adaptive.airtime_per_satisfied_us < low.airtime_per_satisfied_us,
            "adaptive {} should beat fixed-low {} at 44 dB",
            adaptive.airtime_per_satisfied_us,
            low.airtime_per_satisfied_us
        );
    }

    #[test]
    fn the_headline_adaptive_beats_every_fixed_blast() {
        // The number that answers "are we more than wfb-ng": across a realistic SNR
        // range, the loop's geomean airtime-per-satisfied-Interest is ≤ every single
        // fixed-MCS choice.
        let snrs: Vec<f32> = (5..=46).step_by(3).map(|x| x as f32).collect();
        let r = ab_sweep(&snrs, 1000, 8);
        assert!(
            r.adaptive_wins(),
            "adaptive geomean {:.0} vs high {:.0} / mid {:.0} / low {:.0}",
            r.geomean_adaptive(),
            r.geomean_fixed_high(),
            r.geomean_fixed_mid(),
            r.geomean_fixed_low(),
        );
    }
}
