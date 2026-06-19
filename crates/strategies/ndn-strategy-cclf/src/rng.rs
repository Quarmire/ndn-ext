//! A tiny `no_std` PRNG for CCLF's randomized forwarding timer and the
//! density-suppression coin flip.
//!
//! CCLF deliberately jitters its election timer over `[0.5t, 1.5t]` and thins
//! forwarders with a `min(K·n, 1)` coin so that ties break randomly and a dense
//! neighborhood does not all forward at once. Neither needs cryptographic
//! randomness — only cheap, decorrelated draws — so a 32-bit xorshift is ample
//! and keeps the decision core dependency-free and `no_std`.

/// Marsaglia xorshift32. Not cryptographic; do not use for keys/nonces.
#[derive(Clone, Debug)]
pub struct XorShift32 {
    state: u32,
}

impl XorShift32 {
    /// Seed the generator. A zero seed is remapped (xorshift cannot leave 0).
    pub fn new(seed: u32) -> Self {
        Self {
            state: if seed == 0 { 0x9E37_79B9 } else { seed },
        }
    }

    /// Next pseudo-random `u32`.
    pub fn next_u32(&mut self) -> u32 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.state = x;
        x
    }

    /// Next draw as a fraction in `[0.0, 1.0)`.
    pub fn next_unit(&mut self) -> f32 {
        // 24 bits of mantissa precision is plenty for jitter/coin draws.
        (self.next_u32() >> 8) as f32 / (1u32 << 24) as f32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_stuck_at_zero() {
        let mut r = XorShift32::new(0);
        for _ in 0..1000 {
            assert_ne!(r.next_u32(), 0, "xorshift must not emit a run of zeros");
        }
    }

    #[test]
    fn unit_is_in_range() {
        let mut r = XorShift32::new(42);
        for _ in 0..10_000 {
            let u = r.next_unit();
            assert!((0.0..1.0).contains(&u), "unit draw {u} out of [0,1)");
        }
    }

    #[test]
    fn deterministic_for_seed() {
        let mut a = XorShift32::new(7);
        let mut b = XorShift32::new(7);
        for _ in 0..100 {
            assert_eq!(a.next_u32(), b.next_u32());
        }
    }
}
