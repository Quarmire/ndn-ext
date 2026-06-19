//! Network-layer named-neighbor table — the density source for CCLF's
//! suppression rule `p = min(K·n, 1)`.
//!
//! **Identity is the neighbor's NDN node name, never a link/host address.** In
//! a mobile / monitor-mode / connectionless-broadcast setting, MAC addresses
//! and face↔peer bindings rotate, spoof, and churn, so a neighbor count built
//! on them is fragile and manipulable. Instead a neighbor "counts" when its
//! signed presence has been observed at the network layer — either piggybacked
//! as a presence/announcement adornment on Data this node overheard being
//! forwarded, or via a dedicated idle-fallback beacon. The caller is expected
//! to admit only trust-schema-validated names (see crate docs); this table only
//! tracks distinct names and ages them out.
//!
//! Counts are scoped **per egress radio (`F`)** because CCLF density is about
//! local contention, which differs per radio on a multi-radio node. The `F`
//! here is a *local* radio face, not a remote-host identity.
//!
//! `no_std`; requires `alloc`.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

/// A neighbor's network-layer identity: its node name as component byte-vectors.
pub type NodeName = Vec<Vec<u8>>;

/// Default freshness window — a neighbor unheard for this long stops counting.
/// Several beacon intervals so an occasional miss does not drop the count.
const DEFAULT_TTL_MS: u64 = 30_000;

/// Per-egress-radio table of distinct named neighbors, aged by last-heard time.
pub struct NamedNeighborTable<F: Copy + Ord> {
    per_face: BTreeMap<F, BTreeMap<NodeName, u64>>,
    ttl_ms: u64,
}

impl<F: Copy + Ord> NamedNeighborTable<F> {
    /// New table with the default freshness window.
    pub fn new() -> Self {
        Self {
            per_face: BTreeMap::new(),
            ttl_ms: DEFAULT_TTL_MS,
        }
    }

    /// New table with a custom freshness window.
    pub fn with_ttl_ms(ttl_ms: u64) -> Self {
        Self {
            per_face: BTreeMap::new(),
            ttl_ms: ttl_ms.max(1),
        }
    }

    /// Record that named neighbor `name` was heard on radio `face` at `now_ms`.
    /// The caller must have already authenticated `name` (trust schema).
    pub fn observe(&mut self, face: F, name: NodeName, now_ms: u64) {
        self.per_face.entry(face).or_default().insert(name, now_ms);
    }

    /// Distinct fresh named neighbors heard on `face` as of `now_ms`. Prunes
    /// stale entries as a side effect, so the count is always current.
    pub fn count(&mut self, face: F, now_ms: u64) -> u32 {
        let ttl = self.ttl_ms;
        let Some(map) = self.per_face.get_mut(&face) else {
            return 0;
        };
        map.retain(|_, &mut last| now_ms.saturating_sub(last) <= ttl);
        map.len() as u32
    }

    /// Drop every stale entry across all radios (periodic maintenance).
    pub fn prune(&mut self, now_ms: u64) {
        let ttl = self.ttl_ms;
        self.per_face.retain(|_, map| {
            map.retain(|_, &mut last| now_ms.saturating_sub(last) <= ttl);
            !map.is_empty()
        });
    }
}

impl<F: Copy + Ord> Default for NamedNeighborTable<F> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(s: &str) -> NodeName {
        s.split('/')
            .filter(|c| !c.is_empty())
            .map(|c| c.as_bytes().to_vec())
            .collect()
    }

    #[test]
    fn counts_distinct_names_per_face() {
        let mut t = NamedNeighborTable::<u8>::new();
        t.observe(1, name("/ndn/a"), 0);
        t.observe(1, name("/ndn/b"), 0);
        t.observe(1, name("/ndn/a"), 0); // dup name → still 2
        t.observe(2, name("/ndn/c"), 0); // different radio
        assert_eq!(t.count(1, 0), 2);
        assert_eq!(t.count(2, 0), 1);
        assert_eq!(t.count(3, 0), 0);
    }

    #[test]
    fn stale_neighbors_age_out() {
        let mut t = NamedNeighborTable::<u8>::with_ttl_ms(1000);
        t.observe(1, name("/ndn/a"), 0);
        t.observe(1, name("/ndn/b"), 500);
        assert_eq!(t.count(1, 600), 2);
        // At t=1400, /a (age 1400) is stale, /b (age 900) still fresh.
        assert_eq!(t.count(1, 1400), 1);
        // At t=2000, both stale (/b age 1500 > ttl).
        assert_eq!(t.count(1, 2000), 0);
    }
}
