//! Online rate self-calibration — learn the per-MCS RSSI thresholds from *measured*
//! delivery instead of trusting a fixed preset (which is wrong per chip / band /
//! interference profile, as the airtime harness exposed).
//!
//! Not ML/RL — a transparent stochastic-approximation (Robbins–Monro) controller
//! with a handful of interpretable parameters. Each MCS `m` has a threshold
//! `req[m]` = the RSSI above which it's used. On feedback `(mcs, rssi, delivered)`:
//! a success nudges `req[m]` **down** by `step·(1−target)`, a failure nudges it
//! **up** by `step·target`. The fixed point is `P(deliver) = target` at the
//! operating point — the threshold parks itself on the measured delivery cliff.
//!
//! The "feedback" is the content-centric ARQ signal, not link ACKs: a returning
//! Data = delivered; a re-Interest = a miss. Only **near-boundary** samples update
//! the threshold (|rssi − req[m]| ≤ window), so easy successes far above the cliff
//! don't drag it. Monotonicity (`req[m] ≥ req[m−1]`) is preserved. **Probing**
//! (deliberately sampling a higher MCS to learn its cliff) is a future refinement;
//! today it learns the cliffs of the rates the controller actually uses.
//!
//! The thresholds live in a shared cell the [`crate::RadioPolicy`] reads, so the
//! learner is a drop-in beside the policy — the architecture doesn't change.

use std::sync::{Arc, RwLock};

/// Preset per-MCS required RSSI (dBm), index = MCS. The *initial* estimate that
/// calibration then refines. (Equivalent to the original `mcs_from_rssi` table.)
pub const STATIC_REQ_RSSI: [f32; 10] = [
    -110.0, // MCS0 — always usable
    -90.0, -86.0, -82.0, -78.0, -73.0, -68.0, -62.0, -56.0, -50.0,
];

/// Shared, mutable per-MCS thresholds: the calibrator writes, the policy reads.
pub type RateThresholds = Arc<RwLock<[f32; 10]>>;

/// A fresh threshold cell seeded with the static preset.
pub fn default_thresholds() -> RateThresholds {
    Arc::new(RwLock::new(STATIC_REQ_RSSI))
}

/// Highest MCS ≤ `max_mcs` whose threshold is satisfied by `rssi_dbm`.
pub fn pick_mcs(rssi_dbm: i8, max_mcs: u8, thresholds: &[f32; 10]) -> u8 {
    let r = rssi_dbm as f32;
    let mut best = 0u8;
    for m in 0..=max_mcs.min(9) {
        if thresholds[m as usize] <= r {
            best = m;
        }
    }
    best
}

/// Adapts [`RateThresholds`] from measured delivery outcomes.
pub struct RateCalibrator {
    thresholds: RateThresholds,
    target_delivery: f32,
    step: f32,
    window: f32,
}

impl RateCalibrator {
    pub fn new(thresholds: RateThresholds, target_delivery: f32, step: f32) -> Self {
        Self {
            thresholds,
            target_delivery: target_delivery.clamp(0.5, 0.999),
            step: step.max(0.01),
            window: 10.0,
        }
    }

    /// Feed one delivery outcome for a transmission at `mcs` / `rssi_dbm`.
    pub fn observe(&self, mcs: u8, rssi_dbm: i8, delivered: bool) {
        let m = mcs.min(9) as usize;
        let r = rssi_dbm as f32;
        let mut t = self.thresholds.write().unwrap();
        // Only near-boundary samples are informative.
        if (r - t[m]).abs() > self.window {
            return;
        }
        let delta = if delivered {
            -self.step * (1.0 - self.target_delivery)
        } else {
            self.step * self.target_delivery
        };
        t[m] = (t[m] + delta).clamp(-110.0, 0.0);
        // Preserve monotonicity: req[m-1] ≤ req[m] ≤ req[m+1].
        if m > 0 {
            t[m] = t[m].max(t[m - 1]);
        }
        if m < 9 {
            t[m] = t[m].min(t[m + 1]);
        }
    }

    /// Snapshot of the current thresholds (telemetry / tests).
    pub fn thresholds(&self) -> [f32; 10] {
        *self.thresholds.read().unwrap()
    }

    /// The shared cell, to hand to [`crate::RadioPolicy::with_learned_thresholds`].
    pub fn handle(&self) -> RateThresholds {
        self.thresholds.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pick_mcs_matches_preset() {
        assert_eq!(pick_mcs(-50, 9, &STATIC_REQ_RSSI), 9);
        assert_eq!(pick_mcs(-55, 9, &STATIC_REQ_RSSI), 8);
        assert_eq!(pick_mcs(-90, 9, &STATIC_REQ_RSSI), 1);
        assert_eq!(pick_mcs(-91, 9, &STATIC_REQ_RSSI), 0);
        assert_eq!(pick_mcs(-50, 5, &STATIC_REQ_RSSI), 5, "respects max_mcs");
    }

    #[test]
    fn failures_raise_threshold_make_controller_conservative() {
        let cell = default_thresholds();
        let cal = RateCalibrator::new(cell.clone(), 0.9, 2.0);
        // At -60 dBm the preset picks MCS6 (req -68). If MCS6 keeps failing there,
        // its threshold should climb past -60 so we stop choosing it at -60.
        let before = pick_mcs(-60, 9, &cal.thresholds());
        for _ in 0..20 {
            cal.observe(before, -60, false);
        }
        let after = pick_mcs(-60, 9, &cal.thresholds());
        assert!(after < before, "persistent failure should drop the rate: {after} < {before}");
    }

    #[test]
    fn successes_lower_threshold_make_controller_aggressive() {
        let cell = default_thresholds();
        let cal = RateCalibrator::new(cell.clone(), 0.9, 2.0);
        // MCS7's preset threshold is -62. Reliable delivery just below it should
        // pull the threshold down so MCS7 becomes usable at -64.
        let t0 = cal.thresholds()[7];
        for _ in 0..30 {
            cal.observe(7, -64, true);
        }
        let t1 = cal.thresholds()[7];
        assert!(t1 < t0, "persistent success should lower the threshold: {t1} < {t0}");
    }

    #[test]
    fn monotonicity_preserved() {
        let cell = default_thresholds();
        let cal = RateCalibrator::new(cell.clone(), 0.9, 3.0);
        for _ in 0..50 {
            cal.observe(5, -73, false); // hammer one rung up
            cal.observe(6, -68, true); // and the next down
        }
        let t = cal.thresholds();
        for m in 1..10 {
            assert!(t[m] >= t[m - 1], "req must be nondecreasing at {m}: {:?}", t);
        }
    }

    #[test]
    fn far_from_boundary_samples_are_ignored() {
        let cell = default_thresholds();
        let cal = RateCalibrator::new(cell.clone(), 0.9, 2.0);
        let t0 = cal.thresholds()[7]; // -62
        // a success at -20 dBm (far above the cliff) tells us nothing about it.
        cal.observe(7, -20, true);
        assert_eq!(cal.thresholds()[7], t0, "easy far-above success must not move the cliff");
    }
}
