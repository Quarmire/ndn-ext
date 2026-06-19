//! Location Score (LS) — the optional geographic term of the CCLF weight.
//!
//! CCLF defines `LS = 1 - Dist(n,d) / max(Dist(n,d), Dist(p,d))` where `n` is
//! this node, `p` the previous hop, and `d` the destination (producer). LS is
//! `1` when this node sits right on the destination and falls to `0` when the
//! node is no closer to the destination than the previous hop was — i.e. LS
//! rewards forward *progress* toward the destination and refuses to reward a
//! node that would move the Interest away.
//!
//! Distances use [`GeoPos::planar_dist2`] (a squared planar proxy — no
//! cos(latitude) correction), so this stays faithful to the relative ordering
//! the score needs without floats/trig at the source. We take an integer square
//! root here (no `libm`, no `std`) to recover a distance for the ratio.

use ndn_signals_core::GeoPos;

/// Integer square root of a `u64` (floor). Pure, `no_std`, no `libm`.
/// Newton's method seeded from the bit length; converges in a handful of steps.
pub fn isqrt_u64(n: u64) -> u64 {
    if n < 2 {
        return n;
    }
    // Seed: 2^ceil(bits/2) is an upper bound on the root.
    let mut x = 1u64 << ((64 - n.leading_zeros()).div_ceil(2));
    loop {
        let next = (x + n / x) / 2;
        if next >= x {
            return x;
        }
        x = next;
    }
}

/// CCLF Location Score for `self_pos`, given the `prev_hop` it arrived from and
/// the `dest` (producer) it is bound for. Result is clamped to `0.0..=1.0`.
///
/// Returns `1.0` when this node is co-located with the destination (or both
/// distances are zero), and `0.0` when this node is at least as far from the
/// destination as the previous hop (no progress).
pub fn location_score(self_pos: GeoPos, prev_hop: GeoPos, dest: GeoPos) -> f32 {
    let d_nd = isqrt_u64(self_pos.planar_dist2(&dest));
    let d_pd = isqrt_u64(prev_hop.planar_dist2(&dest));
    let denom = d_nd.max(d_pd);
    if denom == 0 {
        return 1.0;
    }
    let ls = 1.0 - (d_nd as f32) / (denom as f32);
    ls.clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pos(lat_e7: i32, lon_e7: i32) -> GeoPos {
        GeoPos {
            lat_e7,
            lon_e7,
            alt_cm: 0,
        }
    }

    #[test]
    fn isqrt_matches_floor_sqrt() {
        for n in [0u64, 1, 2, 3, 4, 15, 16, 17, 100, 99_980_001, u64::MAX] {
            let r = isqrt_u64(n);
            assert!(r * r <= n, "isqrt({n}) = {r} too big");
            // (r+1)^2 can overflow u64 for very large n; checked_mul guards it.
            assert!(
                (r + 1).checked_mul(r + 1).is_none_or(|sq| sq > n),
                "isqrt({n}) = {r} too small",
            );
        }
    }

    #[test]
    fn ls_is_one_at_destination() {
        let d = pos(100, 100);
        assert_eq!(location_score(d, pos(0, 0), d), 1.0);
    }

    #[test]
    fn ls_is_zero_when_no_progress() {
        // Node is farther from dest than the previous hop → no progress.
        let dest = pos(0, 0);
        let prev = pos(10, 0);
        let node = pos(20, 0);
        assert_eq!(location_score(node, prev, dest), 0.0);
    }

    #[test]
    fn ls_rewards_progress() {
        // Node is halfway between prev hop and dest → positive, < 1.
        let dest = pos(0, 0);
        let prev = pos(20, 0);
        let node = pos(10, 0);
        let ls = location_score(node, prev, dest);
        assert!((ls - 0.5).abs() < 1e-3, "expected ~0.5, got {ls}");
    }
}
