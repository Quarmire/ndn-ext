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

// --- LoRa spreading-factor calibration (the sub-GHz analogue of the MCS path above) ---

/// Preset per-SF operating-point RSSI (dBm), indexed by spreading factor (7–12; 0–6 unused). The
/// *initial* estimate the calibrator then refines from delivery. Monotone-decreasing in SF: a lower
/// (faster) SF needs a stronger signal, so it carries a higher threshold.
pub const STATIC_REQ_RSSI_SF: [f32; 13] = [
    0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, // SF0–6 unused
    -80.0,  // SF7
    -90.0,  // SF8
    -100.0, // SF9
    -110.0, // SF10
    -118.0, // SF11
    -125.0, // SF12 — always usable (max range)
];

/// Shared, mutable per-SF thresholds: the calibrator writes, the policy reads.
pub type SfThresholds = Arc<RwLock<[f32; 13]>>;

/// A fresh SF-threshold cell seeded with the static preset.
pub fn default_sf_thresholds() -> SfThresholds {
    Arc::new(RwLock::new(STATIC_REQ_RSSI_SF))
}

/// Lowest (fastest) spreading factor 7–12 whose operating threshold is met by `rssi_dbm`. A strong
/// link runs SF7; as the margin falls the pick climbs toward SF12 (max range).
pub fn pick_sf(rssi_dbm: i8, thresholds: &[f32; 13]) -> u8 {
    let r = rssi_dbm as f32;
    for sf in 7u8..=12 {
        if thresholds[sf as usize] <= r {
            return sf;
        }
    }
    12
}

/// Hysteretic spreading-factor pick: like [`pick_sf`] but biased to HOLD `current_sf` unless the
/// signal has moved a full `margin_db` out of the current SF's operating band. Without a deadband,
/// an RSSI parked on a threshold (e.g. −92 dBm on the −90 SF8/SF9 line) re-picks every tick, and two
/// peers dialing independently land on *mismatched* SFs — and LoRa SFs are quasi-orthogonal, so a
/// mismatch is a total decode loss, not a slow link. The deadband makes the controller leave
/// `current_sf` only when the medium is decisively out of band, so a converged pair stays converged.
///
/// Climb (to a more robust, higher SF) only once RSSI falls `margin_db` below what the current SF
/// needs; drop (to a faster, lower SF) only once RSSI rises `margin_db` above the next-faster SF's
/// threshold. Inside the band, hold. The climb never drops and the drop never climbs, so a single
/// call moves at most in one direction.
pub fn pick_sf_hysteretic(
    rssi_dbm: i8,
    current_sf: u8,
    thresholds: &[f32; 13],
    margin_db: f32,
) -> u8 {
    let r = rssi_dbm as f32;
    let c = current_sf.clamp(7, 12) as usize;
    // Current SF decisively inadequate → climb toward the ideal, but never below where we are.
    if r < thresholds[c] - margin_db {
        return pick_sf(rssi_dbm, thresholds).max(current_sf);
    }
    // Decisively into the next-faster SF's band → drop toward the ideal, but never above where we are.
    if c > 7 && r > thresholds[c - 1] + margin_db {
        return pick_sf(rssi_dbm, thresholds).min(current_sf);
    }
    current_sf // inside the deadband: hold
}

/// Adapts [`SfThresholds`] from measured delivery — the same control law as [`RateCalibrator`]:
/// a near-boundary miss raises the SF's operating threshold (pushing the controller to a
/// higher/more-robust SF), a success lowers it (a faster SF becomes usable at weaker signal).
pub struct SfCalibrator {
    thresholds: SfThresholds,
    target_delivery: f32,
    step: f32,
    window: f32,
}

impl SfCalibrator {
    pub fn new(thresholds: SfThresholds, target_delivery: f32, step: f32) -> Self {
        Self {
            thresholds,
            target_delivery: target_delivery.clamp(0.5, 0.999),
            step: step.max(0.01),
            window: 10.0,
        }
    }

    /// Feed one delivery outcome for a transmission at `sf` / `rssi_dbm`.
    pub fn observe(&self, sf: u8, rssi_dbm: i8, delivered: bool) {
        let sf = sf.clamp(7, 12) as usize;
        let r = rssi_dbm as f32;
        let mut t = self.thresholds.write().unwrap();
        if (r - t[sf]).abs() > self.window {
            return; // only near-boundary samples are informative
        }
        let delta = if delivered {
            -self.step * (1.0 - self.target_delivery)
        } else {
            self.step * self.target_delivery
        };
        t[sf] = (t[sf] + delta).clamp(-130.0, 0.0);
        // Preserve monotonicity: req[SF-1] ≥ req[SF] ≥ req[SF+1] (lower SF needs stronger signal).
        if sf > 7 {
            t[sf] = t[sf].min(t[sf - 1]);
        }
        if sf < 12 {
            t[sf] = t[sf].max(t[sf + 1]);
        }
    }

    /// Snapshot of the current thresholds (telemetry / tests).
    pub fn thresholds(&self) -> [f32; 13] {
        *self.thresholds.read().unwrap()
    }

    /// The shared cell, to hand to [`crate::RadioPolicy::with_learned_sf_thresholds`].
    pub fn handle(&self) -> SfThresholds {
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
        assert!(
            after < before,
            "persistent failure should drop the rate: {after} < {before}"
        );
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
        assert!(
            t1 < t0,
            "persistent success should lower the threshold: {t1} < {t0}"
        );
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
            assert!(
                t[m] >= t[m - 1],
                "req must be nondecreasing at {m}: {:?}",
                t
            );
        }
    }

    #[test]
    fn far_from_boundary_samples_are_ignored() {
        let cell = default_thresholds();
        let cal = RateCalibrator::new(cell.clone(), 0.9, 2.0);
        let t0 = cal.thresholds()[7]; // -62
        // a success at -20 dBm (far above the cliff) tells us nothing about it.
        cal.observe(7, -20, true);
        assert_eq!(
            cal.thresholds()[7],
            t0,
            "easy far-above success must not move the cliff"
        );
    }

    #[test]
    fn pick_sf_climbs_as_signal_weakens() {
        let t = STATIC_REQ_RSSI_SF;
        assert_eq!(pick_sf(-70, &t), 7, "strong link → fastest SF");
        assert_eq!(pick_sf(-85, &t), 8);
        assert_eq!(pick_sf(-105, &t), 10);
        assert_eq!(pick_sf(-128, &t), 12, "very weak → max range");
    }

    #[test]
    fn hysteresis_holds_sf_on_a_boundary() {
        let t = STATIC_REQ_RSSI_SF;
        let m = 4.0;
        // −92/−94 sit right on the −90 SF8/SF9 line — the on-air chatter case. A node already at
        // SF9 must HOLD SF9 (not flip to SF8) across the wiggle, so a converged pair stays paired.
        assert_eq!(pick_sf_hysteretic(-92, 9, &t, m), 9, "hold SF9 in the deadband");
        assert_eq!(pick_sf_hysteretic(-94, 9, &t, m), 9);
        assert_eq!(pick_sf_hysteretic(-88, 9, &t, m), 9, "still hold: not a full margin past −90");
        // And a node at SF8 must not chatter up either until decisively out of band.
        assert_eq!(pick_sf_hysteretic(-92, 8, &t, m), 8, "hold SF8 inside its deadband");
    }

    #[test]
    fn hysteresis_still_moves_when_signal_moves_decisively() {
        let t = STATIC_REQ_RSSI_SF;
        let m = 4.0;
        // From a strong-link SF7, a decisively weak reading jumps straight to the robust SF.
        assert_eq!(pick_sf_hysteretic(-105, 7, &t, m), 10, "climb SF7→SF10 on a strong drop");
        // A node stuck robust at SF11 with the link recovered drops toward the faster SF.
        assert!(pick_sf_hysteretic(-70, 11, &t, m) < 11, "recovered link drops SF");
        // A single call never overshoots the ideal in either direction.
        assert_eq!(pick_sf_hysteretic(-94, 7, &t, m), 9, "climb lands on the RSSI's ideal");
    }

    #[test]
    fn sf_failures_push_to_a_more_robust_factor() {
        let cell = default_sf_thresholds();
        let cal = SfCalibrator::new(cell.clone(), 0.9, 2.0);
        // SF7 keeps failing at -80 (its preset cliff) → its threshold should climb so we stop
        // choosing SF7 at -80 and move to a higher SF.
        let before = pick_sf(-80, &cal.thresholds());
        for _ in 0..20 {
            cal.observe(before, -80, false);
        }
        let after = pick_sf(-80, &cal.thresholds());
        assert!(after > before, "persistent SF failure raises SF: {after} > {before}");
    }

    #[test]
    fn sf_monotonicity_preserved() {
        let cell = default_sf_thresholds();
        let cal = SfCalibrator::new(cell.clone(), 0.9, 3.0);
        for _ in 0..50 {
            cal.observe(8, -90, false);
            cal.observe(9, -100, true);
        }
        let t = cal.thresholds();
        for sf in 8..=12 {
            assert!(t[sf] <= t[sf - 1], "SF thresholds must be nonincreasing at {sf}: {t:?}");
        }
    }
}
