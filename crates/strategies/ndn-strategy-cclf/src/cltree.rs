//! The **C-L tree** and **Content Connectivity Score (CCS)** — CCLF's
//! per-prefix, per-node measure of "how good is this node at returning content
//! under this name prefix?"
//!
//! CCLF defines, for a prefix `j`,
//!
//! ```text
//! CCS_j = (D_j + Σ_{i∈Desc(j)} D_i) / (I_j + Σ_{i∈Desc(j)} I_i)
//! ```
//!
//! where `I`/`D` are the Interest/Data counts this node has observed and
//! `Desc(j)` are the descendant prefixes in the namespace tree. A node on the
//! path to (or holding) the content sees Data flow back, lifting its ratio;
//! a node that only emits Interests stays low.
//!
//! ## Realization
//!
//! We keep per-prefix **EMA-smoothed** Interest/Data rates (the paper smooths
//! the connectivity signal with `α = 0.125` over a 6 s window). Each prefix
//! accumulates raw counts within the current window; every `window_ms` the
//! window folds into the smoothed rate `s ← α·win + (1-α)·s` and resets. CCS
//! for a prefix is then the ratio of the **summed smoothed rates over its
//! subtree**, clamped to `0.0..=1.0` so it composes with the Location Score on
//! a common scale.
//!
//! Prefixes are keyed by their **component byte-vectors** (`Vec<Vec<u8>>`), not
//! a flattened byte string, so subtree membership respects NDN component
//! boundaries (`/a` is a prefix of `/a/b` but not of `/ab`). In `BTreeMap`'s
//! lexicographic order a prefix's descendants form a contiguous range starting
//! at the prefix itself, so the rollup is a range scan, not a full walk.
//!
//! `no_std`; requires `alloc` (a heap) for the maps.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

/// A name prefix as its ordered component byte-vectors.
pub type Prefix = Vec<Vec<u8>>;

/// EMA smoothing factor (TCP-RTO-style), per the paper.
const ALPHA: f32 = 0.125;
/// Smoothing window — counts fold into the smoothed rate this often.
const DEFAULT_WINDOW_MS: u64 = 6_000;
/// Cap on EMA folds applied in one `roll` (bounds work after a long idle gap).
/// `(1-α)^64 ≈ 2e-4`, below `PRUNE_EPS`, so capping at 64 idle windows is
/// indistinguishable from full decay; beyond it we zero the smoothed mass.
const MAX_FOLDS: u32 = 64;
/// Below this smoothed rate a prefix is considered idle and prunable.
const PRUNE_EPS: f32 = 1e-3;

#[derive(Clone, Debug, Default)]
struct PrefixStat {
    win_i: u32,
    win_d: u32,
    s_i: f32,
    s_d: f32,
    /// `None` until the first observation; the window epoch thereafter.
    last_roll_ms: Option<u64>,
}

impl PrefixStat {
    /// Fold any elapsed windows into the smoothed rates. Bounded by `MAX_FOLDS`;
    /// beyond that the stale smoothed mass is negligible, so we zero it.
    fn roll(&mut self, now_ms: u64, window_ms: u64) {
        let last = match self.last_roll_ms {
            None => {
                self.last_roll_ms = Some(now_ms);
                return;
            }
            Some(l) => l,
        };
        if now_ms <= last {
            return;
        }
        let folds = ((now_ms - last) / window_ms) as u32;
        if folds == 0 {
            return;
        }
        // First fold absorbs the live window's counts; subsequent folds decay
        // toward zero (no new counts arrived in those windows).
        let n = folds.min(MAX_FOLDS);
        self.s_i = ALPHA * self.win_i as f32 + (1.0 - ALPHA) * self.s_i;
        self.s_d = ALPHA * self.win_d as f32 + (1.0 - ALPHA) * self.s_d;
        self.win_i = 0;
        self.win_d = 0;
        for _ in 1..n {
            self.s_i *= 1.0 - ALPHA;
            self.s_d *= 1.0 - ALPHA;
        }
        if folds >= MAX_FOLDS {
            // Idle for ≥ MAX_FOLDS windows: fully decayed for all practical
            // purposes — zero it so the prefix becomes prunable.
            self.s_i = 0.0;
            self.s_d = 0.0;
        }
        self.last_roll_ms = Some(last + folds as u64 * window_ms);
    }

    fn is_idle(&self) -> bool {
        self.win_i == 0 && self.win_d == 0 && self.s_i < PRUNE_EPS && self.s_d < PRUNE_EPS
    }
}

/// Per-node C-L tree: prefix → smoothed Interest/Data connectivity, with
/// subtree rollup to compute [`ClTree::ccs`].
pub struct ClTree {
    map: BTreeMap<Prefix, PrefixStat>,
    window_ms: u64,
}

impl ClTree {
    /// New tree with the paper's 6 s smoothing window.
    pub fn new() -> Self {
        Self {
            map: BTreeMap::new(),
            window_ms: DEFAULT_WINDOW_MS,
        }
    }

    /// New tree with a custom smoothing window (testing / tuning).
    pub fn with_window_ms(window_ms: u64) -> Self {
        Self {
            map: BTreeMap::new(),
            window_ms: window_ms.max(1),
        }
    }

    /// Record that an Interest under `prefix` was observed at `now_ms`.
    pub fn observe_interest(&mut self, prefix: Prefix, now_ms: u64) {
        let e = self.map.entry(prefix).or_default();
        e.roll(now_ms, self.window_ms);
        e.win_i = e.win_i.saturating_add(1);
    }

    /// Record that a Data under `prefix` was observed at `now_ms`.
    pub fn observe_data(&mut self, prefix: Prefix, now_ms: u64) {
        let e = self.map.entry(prefix).or_default();
        e.roll(now_ms, self.window_ms);
        e.win_d = e.win_d.saturating_add(1);
    }

    /// CCS for `prefix` at `now_ms`: summed smoothed Data over summed smoothed
    /// Interest across `prefix` and all its descendants, clamped to `0.0..=1.0`.
    /// `0.0` when nothing has been observed under the prefix.
    pub fn ccs(&mut self, prefix: &[Vec<u8>], now_ms: u64) -> f32 {
        let window_ms = self.window_ms;
        let mut sum_i = 0.0f32;
        let mut sum_d = 0.0f32;
        for (key, stat) in self.map.range_mut(prefix.to_vec()..) {
            if !starts_with(key, prefix) {
                break;
            }
            stat.roll(now_ms, window_ms);
            // Include the live window so a brand-new burst is not invisible
            // until the first fold.
            sum_i += stat.s_i + stat.win_i as f32;
            sum_d += stat.s_d + stat.win_d as f32;
        }
        if sum_i <= 0.0 {
            // CCS = D/I is undefined with no Interests. Regularize: a node that
            // has seen Data but no demand is maximally content-connected (1.0);
            // a node that has seen nothing scores 0.0.
            return if sum_d > 0.0 { 1.0 } else { 0.0 };
        }
        (sum_d / sum_i).clamp(0.0, 1.0)
    }

    /// Drop prefixes whose connectivity has decayed to idle. Call periodically
    /// to bound memory; safe to skip.
    pub fn prune(&mut self, now_ms: u64) {
        let window_ms = self.window_ms;
        self.map.retain(|_, stat| {
            stat.roll(now_ms, window_ms);
            !stat.is_idle()
        });
    }

    /// Number of tracked prefixes (observability/tests).
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether the tree is empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

impl Default for ClTree {
    fn default() -> Self {
        Self::new()
    }
}

/// Does `key` have `prefix` as a component-wise prefix?
fn starts_with(key: &[Vec<u8>], prefix: &[Vec<u8>]) -> bool {
    key.len() >= prefix.len() && key.iter().zip(prefix).all(|(a, b)| a == b)
}

/// Build a [`Prefix`] from component byte slices (convenience for callers/tests).
pub fn prefix_of<'a>(components: impl IntoIterator<Item = &'a [u8]>) -> Prefix {
    components.into_iter().map(|c| c.to_vec()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(parts: &[&str]) -> Prefix {
        parts.iter().map(|s| s.as_bytes().to_vec()).collect()
    }

    #[test]
    fn empty_prefix_has_zero_ccs() {
        let mut t = ClTree::new();
        assert_eq!(t.ccs(&p(&["a"]), 1000), 0.0);
    }

    #[test]
    fn data_lifts_ccs_interest_lowers_it() {
        let mut t = ClTree::new();
        // 1 interest, 1 data on the same prefix → ratio 1.0.
        t.observe_interest(p(&["sensors", "temp"]), 100);
        t.observe_data(p(&["sensors", "temp"]), 100);
        assert!((t.ccs(&p(&["sensors", "temp"]), 100) - 1.0).abs() < 1e-3);

        // More interests than data → ratio drops below 1.
        t.observe_interest(p(&["sensors", "temp"]), 100);
        t.observe_interest(p(&["sensors", "temp"]), 100);
        let ccs = t.ccs(&p(&["sensors", "temp"]), 100);
        assert!(ccs < 1.0 && ccs > 0.0, "expected (0,1), got {ccs}");
    }

    #[test]
    fn ccs_rolls_up_descendants() {
        let mut t = ClTree::new();
        t.observe_data(p(&["a", "b"]), 50);
        t.observe_data(p(&["a", "c"]), 50);
        t.observe_interest(p(&["a", "b"]), 50);
        // Query at the parent /a aggregates both children: 2 data / 1 interest.
        let ccs = t.ccs(&p(&["a"]), 50);
        assert!(
            (ccs - 1.0).abs() < 1e-3,
            "rolled-up ccs should clamp to 1.0, got {ccs}"
        );
    }

    #[test]
    fn component_boundary_respected() {
        let mut t = ClTree::new();
        t.observe_data(p(&["ab"]), 10);
        // /a must NOT capture /ab (different component).
        assert_eq!(t.ccs(&p(&["a"]), 10), 0.0);
        // /ab itself does.
        assert!(t.ccs(&p(&["ab"]), 10) > 0.0);
    }

    #[test]
    fn smoothing_decays_idle_prefix() {
        let mut t = ClTree::with_window_ms(1000);
        for _ in 0..10 {
            t.observe_data(p(&["x"]), 0);
        }
        let hot = t.ccs(&p(&["x"]), 0);
        assert!(hot > 0.0);
        // Far in the future with no traffic, smoothed mass decays; prune drops it.
        t.prune(1_000_000);
        assert_eq!(t.ccs(&p(&["x"]), 1_000_000), 0.0);
        assert!(t.is_empty());
    }
}
