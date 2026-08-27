//! DoS validation — the cheap-to-expensive cascade of mac-addressing-doctrine §3.2, made executable.
//!
//! The doctrine's answer to "a flooder wakes you and burns your cycles" is a cascade where each stage
//! is cheaper than the work it guards, and the last stage keys on "did I ask for this":
//!   1. **name-group filter** (~10 µs, eventually hardware) drops everything outside your registered
//!      groups — an out-of-group flood never reaches the CPU;
//!   2. **PIT gate** — Data with no matching pending Interest is dropped *before* signature verify,
//!      so fake-Data flooding cannot force a verify unless you have an outstanding Interest for that
//!      exact name;
//!   3. **per-source rate limit** — keyed on the ephemeral source nonce (§2), it bounds the residual
//!      (Interest flooding) so one source cannot force unbounded work, and a distributed flood costs
//!      the attacker one nonce per bucket.
//!
//! [`DosGate::admit`] runs a frame through the cascade and reports the stage it stopped at; only
//! [`Verdict::ReachesVerify`] frames cost the expensive operation. The tests + `examples/dos_validation`
//! quantify attacker cost (frames sent) against victim cost (verifies forced).

use std::collections::{HashMap, HashSet};
use std::hash::Hash;

/// A token-bucket rate limiter keyed on `K`. Used two ways in the cascade: keyed on the **ephemeral
/// source nonce** (`[u8;6]`, §2) to throttle one source, and keyed on the **routable prefix** (`u64`)
/// to bound the aggregate across all sources — the two limits doctrine §3.2 pairs. Per-nonce catches
/// a single flooder; per-prefix catches a distributed one that mints fresh nonces.
pub struct RateLimiter<K: Hash + Eq + Copy> {
    capacity: f64,
    refill_per_ms: f64,
    buckets: HashMap<K, (f64, u64)>, // key → (tokens, last_ms)
}

/// The per-source limiter keyed on the ephemeral nonce — the §2 nonce's DoS-attribution job actuated.
pub type PerSourceRateLimiter = RateLimiter<[u8; 6]>;

impl<K: Hash + Eq + Copy> RateLimiter<K> {
    pub fn new(capacity: f64, refill_per_ms: f64) -> Self {
        Self {
            capacity: capacity.max(0.0),
            refill_per_ms: refill_per_ms.max(0.0),
            buckets: HashMap::new(),
        }
    }

    /// Refill by elapsed time and report whether a token is available — WITHOUT consuming it. Pair
    /// with [`consume`](Self::consume) so a frame that fails a *different* limit does not drain this
    /// one (the bug when two limits are ANDed and both are consumed unconditionally).
    pub fn has_token(&mut self, key: K, now_ms: u64) -> bool {
        let cap = self.capacity;
        let refill = self.refill_per_ms;
        let (tokens, last) = self.buckets.entry(key).or_insert((cap, now_ms));
        *tokens = (*tokens + now_ms.saturating_sub(*last) as f64 * refill).min(cap);
        *last = now_ms;
        *tokens >= 1.0
    }

    /// Spend one token for `key` (call only after [`has_token`](Self::has_token) returned true).
    pub fn consume(&mut self, key: K) {
        if let Some((tokens, _)) = self.buckets.get_mut(&key)
            && *tokens >= 1.0
        {
            *tokens -= 1.0;
        }
    }

    /// Admit one frame keyed on `key` at `now_ms` if a token is available (refill + peek + consume).
    pub fn allow(&mut self, key: K, now_ms: u64) -> bool {
        if self.has_token(key, now_ms) {
            self.consume(key);
            true
        } else {
            false
        }
    }

    /// Number of distinct keys seen (for the source limiter, the attacker's nonce cost).
    pub fn keys(&self) -> usize {
        self.buckets.len()
    }
}

/// A frame the cascade evaluates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameKind {
    Interest,
    Data,
}

/// Where a frame stopped in the cascade. Only [`ReachesVerify`](Verdict::ReachesVerify) costs the
/// expensive operation (signature verify for Data / full processing for an Interest).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Stage 1: not in a registered name-group — dropped before the CPU wakes.
    DroppedAtFilter,
    /// Stage 2: Data with no matching pending Interest — dropped before verify.
    DroppedAtPit,
    /// Stage 3: source over its per-nonce rate budget.
    DroppedAtRateLimit,
    /// Passed every gate — this is the only path that pays for verify.
    ReachesVerify,
}

/// The §3.2 cascade for one node: its registered name-groups (the filter = its roles), its PIT (names
/// it has outstanding Interests for), and the paired Interest rate limiters — **per-source** (nonce)
/// and **per-prefix** (aggregate). An Interest is admitted only if it passes *both*: the per-source
/// limit stops one flooder, the per-prefix limit stops a distributed one that rotates nonces.
pub struct DosGate {
    groups: HashSet<u64>,
    pending: HashSet<u64>,
    per_source: RateLimiter<[u8; 6]>,
    per_prefix: RateLimiter<u64>,
}

impl DosGate {
    /// `groups` = the name-groups this node filters for (consumer subs ∪ produced ∪ routed prefixes).
    /// The per-source burst is small (one neighbour's fair share); the per-prefix aggregate is larger
    /// (it fronts for many legitimate sources) but still bounds a distributed flood.
    pub fn new(
        groups: impl IntoIterator<Item = u64>,
        source_capacity: f64,
        source_refill_per_ms: f64,
    ) -> Self {
        // Default per-prefix aggregate: 128× the per-source burst (many legit neighbours), same refill.
        let prefix_cap = (source_capacity * 128.0).max(source_capacity);
        Self {
            groups: groups.into_iter().collect(),
            pending: HashSet::new(),
            per_source: RateLimiter::new(source_capacity, source_refill_per_ms),
            per_prefix: RateLimiter::new(prefix_cap, source_refill_per_ms * 128.0),
        }
    }

    /// Set the per-prefix aggregate Interest budget explicitly (default is 128× the per-source burst).
    pub fn with_prefix_limit(mut self, capacity: f64, refill_per_ms: f64) -> Self {
        self.per_prefix = RateLimiter::new(capacity, refill_per_ms);
        self
    }

    /// Record that this node has an outstanding Interest for `name_hash` (a PIT breadcrumb), so a
    /// matching Data will pass the PIT gate.
    pub fn expect(&mut self, name_hash: u64) {
        self.pending.insert(name_hash);
    }

    /// Run a frame through the cascade.
    pub fn admit(
        &mut self,
        kind: FrameKind,
        group: u64,
        name_hash: u64,
        src: [u8; 6],
        now_ms: u64,
    ) -> Verdict {
        // Stage 1 — the name-group filter (drops out-of-group floods before anything expensive).
        if !self.groups.contains(&group) {
            return Verdict::DroppedAtFilter;
        }
        match kind {
            // Stage 2 — the PIT gate: unsolicited Data is dropped BEFORE verify.
            FrameKind::Data => {
                if self.pending.contains(&name_hash) {
                    Verdict::ReachesVerify
                } else {
                    Verdict::DroppedAtPit
                }
            }
            // Stage 3 — the paired rate limits on Interests: per-source (nonce) AND per-prefix
            // (aggregate). Admit only if both have a token, so neither a single flooder nor a
            // nonce-rotating distributed flood gets through unbounded.
            FrameKind::Interest => {
                // Peek BOTH before consuming: a frame that fails one limit must not spend the other's
                // token (else a nonce-rotating flood drains the per-prefix budget with rejected frames).
                if self.per_source.has_token(src, now_ms)
                    && self.per_prefix.has_token(group, now_ms)
                {
                    self.per_source.consume(src);
                    self.per_prefix.consume(group);
                    Verdict::ReachesVerify
                } else {
                    Verdict::DroppedAtRateLimit
                }
            }
        }
    }

    /// Distinct source nonces the per-source limiter has tracked (a distributed flood's nonce cost).
    pub fn distinct_sources(&self) -> usize {
        self.per_source.keys()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WANTED: u64 = 0x1111;
    const OTHER: u64 = 0x2222;
    const SRC_A: [u8; 6] = [0x02, 1, 1, 1, 1, 1];
    const SRC_B: [u8; 6] = [0x02, 2, 2, 2, 2, 2];

    /// Stage 1: a flood of frames for a group I don't subscribe to never reaches verify.
    #[test]
    fn out_of_group_flood_dropped_at_filter() {
        let mut gate = DosGate::new([WANTED], 8.0, 0.0);
        let reached = (0..1000)
            .filter(|i| gate.admit(FrameKind::Data, OTHER, *i, SRC_A, 0) == Verdict::ReachesVerify)
            .count();
        assert_eq!(
            reached, 0,
            "the name-group filter drops every out-of-group frame"
        );
    }

    /// Stage 2: fake Data for names I never requested is dropped BEFORE verify (the key claim).
    #[test]
    fn fake_data_flood_dropped_before_verify() {
        let mut gate = DosGate::new([WANTED], 8.0, 0.0);
        // In-group but unsolicited: no PIT breadcrumb for any of these names.
        let verify = (0..1000)
            .filter(|i| {
                gate.admit(FrameKind::Data, WANTED, 0xdead_0000 + i, SRC_A, 0)
                    == Verdict::ReachesVerify
            })
            .count();
        assert_eq!(verify, 0, "no outstanding Interest ⇒ no verify forced");
        // A solicited Data (I expressed the Interest) does pass.
        gate.expect(42);
        assert_eq!(
            gate.admit(FrameKind::Data, WANTED, 42, SRC_A, 0),
            Verdict::ReachesVerify
        );
    }

    /// Stage 3: an Interest flood from ONE source is throttled to its bucket; the rest are dropped.
    #[test]
    fn interest_flood_rate_limited_per_source() {
        let mut gate = DosGate::new([WANTED], 8.0, 0.0); // burst 8, no refill (all at t=0)
        let admitted = (0..1000)
            .filter(|i| {
                gate.admit(FrameKind::Interest, WANTED, *i, SRC_A, 0) == Verdict::ReachesVerify
            })
            .count();
        assert_eq!(admitted, 8, "one source is bounded to its burst capacity");
    }

    /// The residual the doctrine acknowledges: a distributed flood gets `capacity` per DISTINCT nonce,
    /// so the attacker pays one nonce per bucket — the cost is attributed, not unbounded-per-source.
    #[test]
    fn distributed_flood_costs_one_nonce_per_bucket() {
        let mut gate = DosGate::new([WANTED], 4.0, 0.0);
        let mut admitted = 0;
        for s in 0u8..10 {
            let src = [0x02, s, s, s, s, s];
            admitted += (0..100)
                .filter(|i| {
                    gate.admit(FrameKind::Interest, WANTED, *i, src, 0) == Verdict::ReachesVerify
                })
                .count();
        }
        assert_eq!(
            admitted, 40,
            "10 nonces × burst 4 = 40 — linear in the attacker's nonce count"
        );
        assert_eq!(gate.distinct_sources(), 10);
    }

    /// The limiter refills over time (sustained rate), so a legitimate steady sender is not starved.
    #[test]
    fn limiter_refills_over_time() {
        let mut lim = PerSourceRateLimiter::new(1.0, 0.001); // 1 token/1000 ms
        assert!(lim.allow(SRC_B, 0), "first token from the burst");
        assert!(!lim.allow(SRC_B, 0), "burst spent");
        assert!(lim.allow(SRC_B, 1000), "refilled after 1000 ms");
    }
}
