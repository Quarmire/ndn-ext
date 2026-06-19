//! PIT → [`Demand`]: turn forwarding-plane Interest/Data events into the per-prefix
//! demand the control plane optimizes against.
//!
//! [`DemandTracker`] **shadows the PIT's in-record lifecycle**: each downstream
//! face that expresses an unsatisfied Interest for a prefix is an in-record (→
//! fan-out = how many listeners); a repeat before satisfaction is a re-Interest (→
//! the ARQ signal the redundancy budget drives down); a returning Data satisfies
//! and clears the in-records. This is the content-centric replacement for the
//! per-link ACK feedback that classic rate control relies on.
//!
//! Pure / push-based, like the sense bus and the signal store: the forwarder (which
//! holds the PIT and the names) calls [`DemandTracker::on_interest`] /
//! [`DemandTracker::on_data`]; the control plane reads [`DemandTracker::snapshot`]
//! and [`DemandTracker::active_contexts`]. Keeping it event-fed (rather than reading
//! the PIT directly) keeps the control plane free of engine/forwarding deps — the
//! events *are* what the PIT accumulates.

use std::collections::HashMap;

use crate::policy::NameContext;
use crate::sense::{Demand, Ewma};

/// Tracks per-prefix demand from Interest/Data events, shadowing PIT in-records.
pub struct DemandTracker {
    prefixes: HashMap<u64, PrefixDemand>,
    /// In-record freshness window (the PIT entry lifetime): a downstream counts
    /// toward fan-out only while its in-record is unexpired.
    pit_lifetime_ms: u64,
    /// Drop a prefix entirely after this much inactivity.
    stale_ms: u64,
}

struct PrefixDemand {
    /// downstream face → time of its most recent in-record.
    downstreams: HashMap<u64, u64>,
    /// Fraction of Interests for this prefix that were re-expressions (0..1 EWMA).
    reinterest: Ewma,
    last_activity_ms: u64,
}

impl DemandTracker {
    pub fn new(pit_lifetime_ms: u64) -> Self {
        Self {
            prefixes: HashMap::new(),
            pit_lifetime_ms: pit_lifetime_ms.max(1),
            stale_ms: pit_lifetime_ms.saturating_mul(4).max(2_000),
        }
    }

    /// A downstream face expressed an Interest for `prefix_hash`. A repeat from the
    /// same downstream while its in-record is still fresh is a **re-Interest**.
    /// Returns `true` if this was a re-expression (a delivery miss signal).
    pub fn on_interest(&mut self, prefix_hash: u64, downstream: u64, now_ms: u64) -> bool {
        let lifetime = self.pit_lifetime_ms;
        let e = self.prefixes.entry(prefix_hash).or_insert_with(|| PrefixDemand {
            downstreams: HashMap::new(),
            reinterest: Ewma::new(0.3),
            last_activity_ms: now_ms,
        });
        let reexpressed = e
            .downstreams
            .get(&downstream)
            .is_some_and(|&t| now_ms.saturating_sub(t) <= lifetime);
        e.reinterest.update(if reexpressed { 1.0 } else { 0.0 });
        e.downstreams.insert(downstream, now_ms);
        e.last_activity_ms = now_ms;
        reexpressed
    }

    /// Data returned for `prefix_hash` — satisfies and clears the in-records (the
    /// re-Interest history persists as the ARQ signal).
    pub fn on_data(&mut self, prefix_hash: u64, now_ms: u64) {
        if let Some(e) = self.prefixes.get_mut(&prefix_hash) {
            e.downstreams.clear();
            e.last_activity_ms = now_ms;
        }
    }

    /// Live downstream count (fresh in-records) for a prefix.
    pub fn fanout(&self, prefix_hash: u64, now_ms: u64) -> u32 {
        self.prefixes
            .get(&prefix_hash)
            .map(|e| e.fanout(self.pit_lifetime_ms, now_ms))
            .unwrap_or(0)
    }

    /// The [`Demand`] record for a prefix, if tracked.
    pub fn demand(&self, prefix_hash: u64, now_ms: u64) -> Option<Demand> {
        self.prefixes
            .get(&prefix_hash)
            .map(|e| e.to_demand(self.pit_lifetime_ms, now_ms))
    }

    /// All tracked prefixes' demand, for folding into the sense bus.
    pub fn snapshot(&self, now_ms: u64) -> Vec<(u64, Demand)> {
        self.prefixes
            .iter()
            .map(|(&ph, e)| (ph, e.to_demand(self.pit_lifetime_ms, now_ms)))
            .collect()
    }

    /// Prefixes with live demand (fan-out > 0), as relayed [`NameContext`]s for the
    /// policy to decide on.
    pub fn active_contexts(&self, now_ms: u64) -> Vec<NameContext> {
        self.prefixes
            .iter()
            .filter(|(_, e)| e.fanout(self.pit_lifetime_ms, now_ms) > 0)
            .map(|(&ph, _)| NameContext::relayed(ph))
            .collect()
    }

    /// Drop prefixes idle beyond `stale_ms`.
    pub fn prune(&mut self, now_ms: u64) {
        let stale = self.stale_ms;
        self.prefixes
            .retain(|_, e| now_ms.saturating_sub(e.last_activity_ms) <= stale);
    }

    pub fn len(&self) -> usize {
        self.prefixes.len()
    }
    pub fn is_empty(&self) -> bool {
        self.prefixes.is_empty()
    }
}

impl PrefixDemand {
    fn fanout(&self, lifetime: u64, now: u64) -> u32 {
        self.downstreams
            .values()
            .filter(|&&t| now.saturating_sub(t) <= lifetime)
            .count() as u32
    }
    fn to_demand(&self, lifetime: u64, now: u64) -> Demand {
        Demand {
            fanout: self.fanout(lifetime, now),
            ccs: 0.0, // CCLF supplies this when wired
            reinterest_rate: self.reinterest,
            rank_deficit: Ewma::new(0.3), // diversity supplies this later
            ts_ms: self.last_activity_ms,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fanout_counts_distinct_fresh_downstreams() {
        let mut t = DemandTracker::new(4_000);
        t.on_interest(0xAA, 1, 1_000);
        t.on_interest(0xAA, 2, 1_000);
        t.on_interest(0xAA, 3, 1_000);
        assert_eq!(t.fanout(0xAA, 1_000), 3);
        // a fourth, distinct prefix is independent
        t.on_interest(0xBB, 1, 1_000);
        assert_eq!(t.fanout(0xBB, 1_000), 1);
        assert_eq!(t.fanout(0xAA, 1_000), 3);
    }

    #[test]
    fn stale_in_records_drop_out_of_fanout() {
        let mut t = DemandTracker::new(4_000);
        t.on_interest(0xAA, 1, 1_000);
        assert_eq!(t.fanout(0xAA, 1_000), 1);
        assert_eq!(t.fanout(0xAA, 6_000), 0); // > pit_lifetime later
    }

    #[test]
    fn reexpression_is_detected_as_reinterest() {
        let mut t = DemandTracker::new(4_000);
        // first expression: not a re-Interest
        t.on_interest(0xAA, 1, 1_000);
        let r0 = t.demand(0xAA, 1_000).unwrap().reinterest_rate.get().unwrap();
        // same downstream re-expresses before satisfaction
        t.on_interest(0xAA, 1, 1_500);
        t.on_interest(0xAA, 1, 2_000);
        let r1 = t.demand(0xAA, 2_000).unwrap().reinterest_rate.get().unwrap();
        assert!(r1 > r0, "re-Interest rate should rise: {r1} > {r0}");
    }

    #[test]
    fn on_data_clears_fanout() {
        let mut t = DemandTracker::new(4_000);
        t.on_interest(0xAA, 1, 1_000);
        t.on_interest(0xAA, 2, 1_000);
        assert_eq!(t.fanout(0xAA, 1_000), 2);
        t.on_data(0xAA, 1_100);
        assert_eq!(t.fanout(0xAA, 1_100), 0);
        assert!(t.active_contexts(1_100).is_empty());
    }

    #[test]
    fn active_contexts_are_relayed_and_demanded() {
        let mut t = DemandTracker::new(4_000);
        t.on_interest(0xAA, 1, 1_000);
        let ctxs = t.active_contexts(1_000);
        assert_eq!(ctxs.len(), 1);
        assert_eq!(ctxs[0].prefix_hash, 0xAA);
        assert!(!ctxs[0].is_origin, "PIT-driven demand ⇒ we're relaying, not origin");
    }

    #[test]
    fn prune_drops_idle_prefixes() {
        let mut t = DemandTracker::new(4_000);
        t.on_interest(0xAA, 1, 1_000);
        assert_eq!(t.len(), 1);
        t.prune(1_000);
        assert_eq!(t.len(), 1);
        t.prune(1_000_000);
        assert_eq!(t.len(), 0);
    }
}
