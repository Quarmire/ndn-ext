//! Contextual bandit — the joint-axis tuning rung above single-axis calibration.
//!
//! Single-axis online calibration ([`crate::RateCalibrator`]) learns one cliff at a
//! time (per-MCS RSSI). But the knobs *interact*: rate ↔ power (raise power to raise
//! rate and shorten airtime, vs. lower power for spatial reuse), rate ↔ FEC
//! (robustness via a lower rate or via more parity). Hand-rules pick a fixed
//! priority order (we max rate, then trim power) — which the airtime harness showed
//! is not always optimal. A contextual bandit *learns the joint operating point per
//! situation* from the measured reward.
//!
//! Deliberately simple and embedded-friendly: a **tabular UCB1** bandit over a
//! discretized context, a handful of interpretable arms, no RNG (UCB exploration is
//! deterministic), no model. It sits **on top of** [`crate::RadioPolicy`] — the
//! policy produces the baseline plan, the bandit nudges the joint axes and learns —
//! so the architecture doesn't change; it's a drop-in beside the policy, exactly
//! like the calibrator. Reward is the optimand: **airtime per satisfied Interest**,
//! plus a small **footprint** term so spatial reuse (lower power) is valued, since
//! lowering power costs no airtime and a pure-airtime reward would ignore it.

use std::collections::HashMap;

use crate::plan::TxParams;

/// dB per chip TXAGC index (mirrors the policy's power model).
const DB_PER_POWER_IDX: f32 = 0.5;
/// Reward penalty for a delivery miss (≫ any airtime term so misses dominate).
pub const MISS_PENALTY: f32 = 5.0;
/// Weight of the spatial-footprint (power) term in the reward — small, so it breaks
/// ties toward lower power without overriding delivery/airtime.
pub const FOOTPRINT_LAMBDA: f32 = 0.3;

/// A joint adjustment to the policy's baseline operating point.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Arm {
    pub mcs_delta: i8,
    pub power_backoff_db: i8,
    pub fec_delta: i8,
}

/// The arm set spanning the rate × power × FEC tradeoff around the baseline.
pub const ARMS: [Arm; 5] = [
    Arm { mcs_delta: 0, power_backoff_db: 0, fec_delta: 0 }, // 0: baseline (trust the policy)
    Arm { mcs_delta: -1, power_backoff_db: 0, fec_delta: 0 }, // 1: more robust rate
    Arm { mcs_delta: 1, power_backoff_db: 0, fec_delta: 0 }, // 2: more aggressive rate
    Arm { mcs_delta: 0, power_backoff_db: 6, fec_delta: 0 }, // 3: trim power (spatial reuse)
    Arm { mcs_delta: -1, power_backoff_db: 0, fec_delta: 1 }, // 4: robustness via FEC, not rate
];

/// Apply an arm to a baseline [`TxParams`], clamped to the radio's capability.
pub fn apply_arm(arm: &Arm, p: &mut TxParams, max_mcs: u8, max_power: u8) {
    if let Some(m) = p.mcs {
        p.mcs = Some((m as i16 + arm.mcs_delta as i16).clamp(0, max_mcs as i16) as u8);
    }
    if arm.power_backoff_db != 0 {
        let cur = p.tx_power.unwrap_or(max_power) as i16;
        let d = (arm.power_backoff_db as f32 / DB_PER_POWER_IDX).round() as i16;
        p.tx_power = Some((cur - d).clamp(0, max_power as i16) as u8);
    }
    if arm.fec_delta != 0 {
        let cur = p.link_fec_redundancy.unwrap_or(0) as i16;
        let r = (cur + arm.fec_delta as i16).max(0);
        p.link_fec_redundancy = if r == 0 { None } else { Some(r as u16) };
    }
}

/// Relative airtime proxy (lower = faster): `(1+parity)/rate`. Monotone, not calibrated.
fn relative_airtime(p: &TxParams) -> f32 {
    let bw = match p.bw.unwrap_or(0) {
        1 => 2.0,
        2 => 4.0,
        3 => 0.5,
        4 => 0.25,
        _ => 1.0,
    };
    let rate = (p.mcs.unwrap_or(0) as f32 + 1.0) * bw * p.nss.unwrap_or(1).max(1) as f32;
    (1.0 + p.link_fec_redundancy.unwrap_or(0) as f32) / rate.max(0.5)
}

/// Reward for one transmission outcome — the optimand, online: a delivery is
/// rewarded inversely to airtime + a small footprint (power) penalty; a miss is
/// heavily penalized (wasted airtime, nothing satisfied).
pub fn reward(delivered: bool, params: &TxParams, max_power: u8) -> f32 {
    let airtime = relative_airtime(params);
    if delivered {
        let footprint = params.tx_power.unwrap_or(max_power) as f32 / max_power.max(1) as f32;
        -(airtime + FOOTPRINT_LAMBDA * footprint)
    } else {
        -(airtime + MISS_PENALTY)
    }
}

/// A discretized situation the bandit keys its learning on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Context {
    rssi_bin: u8,
    occ_bin: u8,
    recv_bin: u8,
    priority: u8,
}

impl Context {
    pub fn new(rssi_dbm: i8, busy_pct: u8, receivers: usize, priority: u8) -> Self {
        Self {
            rssi_bin: ((rssi_dbm as i32 + 95).clamp(0, 75) / 5) as u8, // 5 dB SNR bins
            occ_bin: (busy_pct / 25).min(3),
            recv_bin: match receivers {
                0 | 1 => 0,
                2 | 3 => 1,
                _ => 2,
            },
            priority: priority.min(2),
        }
    }
    fn key(&self) -> u32 {
        (self.rssi_bin as u32)
            | ((self.occ_bin as u32) << 4)
            | ((self.recv_bin as u32) << 6)
            | ((self.priority as u32) << 8)
    }
}

#[derive(Clone, Copy, Default)]
struct ArmStat {
    n: u32,
    mean: f32,
}

/// Tabular UCB1 contextual bandit.
pub struct ContextualBandit {
    stats: HashMap<u32, [ArmStat; ARMS.len()]>,
    explore_c: f32,
}

impl ContextualBandit {
    pub fn new(explore_c: f32) -> Self {
        Self {
            stats: HashMap::new(),
            explore_c: explore_c.max(0.0),
        }
    }

    /// Choose an arm for `ctx`: any unpulled arm first, then UCB1
    /// (`mean + c·√(ln N / n)`). Deterministic — no RNG.
    pub fn select(&self, ctx: &Context) -> usize {
        let arms = match self.stats.get(&ctx.key()) {
            Some(a) => a,
            None => return 0, // unseen ⇒ baseline; updates then populate it
        };
        if let Some(i) = arms.iter().position(|a| a.n == 0) {
            return i;
        }
        let total: u32 = arms.iter().map(|a| a.n).sum();
        let lnt = (total as f32).ln();
        let mut best = 0;
        let mut best_score = f32::NEG_INFINITY;
        for (i, a) in arms.iter().enumerate() {
            let ucb = a.mean + self.explore_c * (lnt / a.n as f32).sqrt();
            if ucb > best_score {
                best_score = ucb;
                best = i;
            }
        }
        best
    }

    /// Record a reward for `(ctx, arm)` (incremental mean).
    pub fn update(&mut self, ctx: &Context, arm: usize, reward: f32) {
        let arms = self
            .stats
            .entry(ctx.key())
            .or_insert_with(|| [ArmStat::default(); ARMS.len()]);
        if let Some(s) = arms.get_mut(arm) {
            s.n += 1;
            s.mean += (reward - s.mean) / s.n as f32;
        }
    }

    /// Pure-exploit best arm for `ctx` (telemetry / convergence checks).
    pub fn best(&self, ctx: &Context) -> Option<usize> {
        self.stats.get(&ctx.key()).map(|arms| {
            arms.iter()
                .enumerate()
                .max_by(|a, b| a.1.mean.total_cmp(&b.1.mean))
                .map(|(i, _)| i)
                .unwrap_or(0)
        })
    }

    /// Total pulls recorded for `ctx`.
    pub fn pulls(&self, ctx: &Context) -> u32 {
        self.stats
            .get(&ctx.key())
            .map(|a| a.iter().map(|s| s.n).sum())
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(mcs: u8) -> TxParams {
        TxParams {
            mcs: Some(mcs),
            bw: Some(2),
            nss: Some(1),
            ..Default::default()
        }
    }

    #[test]
    fn reward_orders_outcomes_correctly() {
        // delivered beats missed
        assert!(reward(true, &params(5), 63) > reward(false, &params(5), 63));
        // delivered fast beats delivered slow
        assert!(reward(true, &params(9), 63) > reward(true, &params(2), 63));
        // delivered at lower power beats delivered at full power (footprint)
        let mut lowp = params(5);
        lowp.tx_power = Some(20);
        let mut fullp = params(5);
        fullp.tx_power = Some(63);
        assert!(reward(true, &lowp, 63) > reward(true, &fullp, 63));
    }

    #[test]
    fn apply_arm_adjusts_and_clamps() {
        let mut p = params(7);
        apply_arm(&ARMS[2], &mut p, 9, 63); // +1 rate
        assert_eq!(p.mcs, Some(8));
        let mut p = params(0);
        apply_arm(&ARMS[1], &mut p, 9, 63); // -1 rate clamps at 0
        assert_eq!(p.mcs, Some(0));
        let mut p = params(5);
        apply_arm(&ARMS[3], &mut p, 9, 63); // power -6 dB = -12 idx
        assert_eq!(p.tx_power, Some(51));
        let mut p = params(5);
        apply_arm(&ARMS[4], &mut p, 9, 63); // -1 rate + fec
        assert_eq!(p.mcs, Some(4));
        assert_eq!(p.link_fec_redundancy, Some(1));
    }

    #[test]
    fn converges_to_the_best_arm() {
        let mut b = ContextualBandit::new(0.5);
        let ctx = Context::new(-60, 10, 1, 1);
        // arm 2 yields the best reward in this context; the rest are worse.
        for _ in 0..300 {
            let a = b.select(&ctx);
            let r = if a == 2 { -0.2 } else { -1.0 };
            b.update(&ctx, a, r);
        }
        assert_eq!(b.best(&ctx), Some(2));
        assert!(b.pulls(&ctx) >= 300);
    }

    #[test]
    fn explores_all_arms_before_exploiting() {
        let mut b = ContextualBandit::new(1.0);
        let ctx = Context::new(-70, 0, 1, 1);
        let mut seen = [false; ARMS.len()];
        for _ in 0..ARMS.len() {
            let a = b.select(&ctx);
            seen[a] = true;
            b.update(&ctx, a, -1.0);
        }
        assert!(seen.iter().all(|&s| s), "each arm tried once before UCB kicks in");
    }

    #[test]
    fn contexts_learn_independently() {
        let mut b = ContextualBandit::new(0.5);
        let weak = Context::new(-85, 0, 1, 1);
        let strong = Context::new(-45, 0, 1, 1);
        assert_ne!(weak, strong);
        b.update(&strong, 2, -0.1);
        assert_eq!(b.pulls(&strong), 1);
        assert_eq!(b.pulls(&weak), 0, "distinct contexts don't share learning");
    }
}
