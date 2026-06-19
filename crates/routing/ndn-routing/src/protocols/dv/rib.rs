//! ndn-dv destination-vector RIB + update processing per SPEC.md §4.
//!
//! Keyed by destination router name (the prefix table is a separate
//! concern; see [`super::prefix`]). Each [`RibEntry`] tracks one
//! cost-per-neighbor plus a cached best-and-second-best `(neighbor, cost)`
//! pair that feeds directly into outgoing `Advertisement` rows per SPEC §4
//! *Advertisement Computation*.
//!
//! Cross-referenced against `ndnd/dv/table/rib.go` and
//! `ndnd/dv/dv/table_algo.go`. The dirty-reset / apply / prune pattern
//! in `apply_advertisement` mirrors ndnd: every cost via the peer is set
//! to `INFINITY` before the new advertisement is applied, so destinations
//! the peer no longer mentions are pruned at the end.

use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

use ndn_packet::Name;

use crate::protocols::dv::tlv::{AdvEntry, Advertisement};

/// Maximum representable cost; values at or above `INFINITY` are
/// unreachable. Per SPEC.md §4 *Update Processing*, the default is 16.
pub const INFINITY: u32 = 16;

/// Link cost added when traversing a peer link. SPEC.md §4 uses `+1`
/// directly. ndnd carries this as `LocalCost` in config (default 1).
pub const LOCAL_COST: u32 = 1;

/// `(neighbor, cost)` for the outgoing `AdvEntry { NextHop, Cost }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BestRoute {
    pub neighbor: Name,
    pub cost: u32,
}

/// Best-route delta emitted by [`DvRib::apply_advertisement`] and
/// [`DvRib::remove_neighbor`] so downstream consumers (FIB-updater,
/// dashboards) can react.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RibChange {
    pub destination: Name,
    pub old_best: Option<BestRoute>,
    pub new_best: Option<BestRoute>,
}

/// `costs` is the canonical state; `lowest1`/`lowest2` are cached for
/// cheap advertisement production.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RibEntry {
    pub destination: Name,
    pub costs: HashMap<Name, u32>,
    pub lowest1: u32,
    pub next_hop1: Option<Name>,
    /// Second-best cost feeds `OtherCost` for poison-reverse-aware
    /// advertisement generation per SPEC §4 *Advertisement Computation*.
    pub lowest2: u32,
    pub next_hop2: Option<Name>,
}

pub struct DvRib {
    self_name: Name,
    /// Self is pre-installed at `cost=0` so [`produce_advertisement`]
    /// always includes a `self -> self @ cost=0` row, letting neighbours
    /// learn how to reach us.
    entries: RwLock<HashMap<Name, RibEntry>>,
    /// Tracked so `remove_neighbor` can iterate neighbours without
    /// scanning every entry's `costs` map. Mirrors ndnd's `r.neighbors`.
    neighbors: RwLock<HashSet<Name>>,
}

impl DvRib {
    pub fn new(self_name: Name) -> Self {
        let mut entries = HashMap::new();
        let mut self_costs = HashMap::new();
        self_costs.insert(self_name.clone(), 0);
        entries.insert(
            self_name.clone(),
            RibEntry {
                destination: self_name.clone(),
                costs: self_costs,
                lowest1: 0,
                next_hop1: Some(self_name.clone()),
                lowest2: INFINITY,
                next_hop2: None,
            },
        );
        let mut neighbors = HashSet::new();
        neighbors.insert(self_name.clone());
        Self {
            self_name,
            entries: RwLock::new(entries),
            neighbors: RwLock::new(neighbors),
        }
    }

    pub fn self_name(&self) -> &Name {
        &self.self_name
    }

    /// Implements SPEC.md §4 *Update Processing*:
    /// 1. Dirty-reset every existing cost via `peer` to `INFINITY`.
    /// 2. For each `AdvEntry`, candidate cost is `entry.cost + LOCAL_COST`.
    ///    If the peer's `next_hop` is us, poison-reverse to
    ///    `entry.other_cost + LOCAL_COST` (or skip if `other_cost >= INFINITY`).
    ///    Skip entries naming `self` as destination.
    /// 3. Refresh `lowest1` / `lowest2` and prune unreachable entries.
    ///
    /// Returns one [`RibChange`] per destination whose best route changed.
    pub fn apply_advertisement(&self, peer: &Name, adv: &Advertisement) -> Vec<RibChange> {
        let mut entries = self.entries.write().expect("DvRib::entries poisoned");
        let mut neighbors = self.neighbors.write().expect("DvRib::neighbors poisoned");
        neighbors.insert(peer.clone());

        let old_bests: HashMap<Name, Option<BestRoute>> = entries
            .iter()
            .map(|(n, e)| (n.clone(), best_route_of(e)))
            .collect();

        for entry in entries.values_mut() {
            if entry.costs.contains_key(peer) {
                entry.costs.insert(peer.clone(), INFINITY);
            }
        }

        for adv_entry in &adv.entries {
            if adv_entry.destination == self.self_name {
                continue;
            }
            let Some(cost) = compute_received_cost(adv_entry, &self.self_name) else {
                continue;
            };
            let entry = entries
                .entry(adv_entry.destination.clone())
                .or_insert_with(|| RibEntry {
                    destination: adv_entry.destination.clone(),
                    costs: HashMap::new(),
                    lowest1: INFINITY,
                    next_hop1: None,
                    lowest2: INFINITY,
                    next_hop2: None,
                });
            entry.costs.insert(peer.clone(), cost);
        }

        let mut changes = Vec::new();
        let mut to_remove = Vec::new();
        for (name, entry) in entries.iter_mut() {
            refresh(entry);
            if entry.lowest1 >= INFINITY {
                to_remove.push(name.clone());
            }
        }
        for (name, entry) in entries.iter() {
            let old = old_bests.get(name).cloned().unwrap_or(None);
            let new = if entry.lowest1 < INFINITY {
                best_route_of(entry)
            } else {
                None
            };
            if old != new {
                changes.push(RibChange {
                    destination: name.clone(),
                    old_best: old,
                    new_best: new,
                });
            }
        }
        for name in &to_remove {
            entries.remove(name);
        }

        changes
    }

    /// Drop every route via `neighbor`; call when a neighbour times
    /// out or its face goes down.
    pub fn remove_neighbor(&self, neighbor: &Name) -> Vec<RibChange> {
        let mut entries = self.entries.write().expect("DvRib::entries poisoned");
        let mut neighbors = self.neighbors.write().expect("DvRib::neighbors poisoned");
        if !neighbors.remove(neighbor) {
            return Vec::new();
        }

        let old_bests: HashMap<Name, Option<BestRoute>> = entries
            .iter()
            .map(|(n, e)| (n.clone(), best_route_of(e)))
            .collect();

        for entry in entries.values_mut() {
            entry.costs.remove(neighbor);
            refresh(entry);
        }

        let mut changes = Vec::new();
        let mut to_remove = Vec::new();
        for (name, entry) in entries.iter() {
            let old = old_bests.get(name).cloned().unwrap_or(None);
            let new = if entry.lowest1 < INFINITY {
                best_route_of(entry)
            } else {
                None
            };
            if old != new {
                changes.push(RibChange {
                    destination: name.clone(),
                    old_best: old,
                    new_best: new,
                });
            }
            if entry.lowest1 >= INFINITY && name != &self.self_name {
                to_remove.push(name.clone());
            }
        }
        for name in &to_remove {
            entries.remove(name);
        }

        changes
    }

    pub fn best_route(&self, destination: &Name) -> Option<BestRoute> {
        let entries = self.entries.read().expect("DvRib::entries poisoned");
        entries.get(destination).and_then(best_route_of)
    }

    /// Sorted alphabetically by destination for stable diagnostics.
    pub fn snapshot(&self) -> Vec<RibEntry> {
        let entries = self.entries.read().expect("DvRib::entries poisoned");
        let mut snap: Vec<RibEntry> = entries.values().cloned().collect();
        snap.sort_by(|a, b| a.destination.cmp(&b.destination));
        snap
    }

    /// Outgoing `Advertisement` per SPEC.md §4 *Advertisement Computation*:
    /// each row carries `lowest1` as `Cost` and `lowest2` as `OtherCost`
    /// (the latter is `INFINITY` when only one path is known — peers see
    /// "no poison-reverse fallback" and avoid creating a loop).
    /// Includes `self -> self @ cost=0`.
    pub fn produce_advertisement(&self) -> Advertisement {
        let entries = self.entries.read().expect("DvRib::entries poisoned");
        let mut adv_entries = Vec::with_capacity(entries.len());
        let mut sorted: Vec<&RibEntry> = entries.values().collect();
        // Lex sort makes output byte-stable and matches the lex tiebreak
        // used elsewhere.
        sorted.sort_by(|a, b| a.destination.cmp(&b.destination));
        for entry in sorted {
            if entry.lowest1 >= INFINITY {
                continue;
            }
            let next_hop = entry
                .next_hop1
                .clone()
                .expect("lowest1 < INFINITY implies next_hop1 is Some");
            adv_entries.push(AdvEntry {
                destination: entry.destination.clone(),
                next_hop,
                cost: entry.lowest1 as u64,
                other_cost: entry.lowest2 as u64,
            });
        }
        Advertisement {
            entries: adv_entries,
        }
    }
}

/// Cost we'd record for an AdvEntry from a peer per SPEC.md §4
/// *Update Processing*. Returns `None` to skip — cost at/above
/// `INFINITY`, or poison-reverse fallback unavailable.
fn compute_received_cost(adv: &AdvEntry, self_name: &Name) -> Option<u32> {
    let raw = if adv.next_hop == *self_name {
        if adv.other_cost >= INFINITY as u64 {
            return None;
        }
        adv.other_cost
    } else {
        if adv.cost >= INFINITY as u64 {
            return None;
        }
        adv.cost
    };
    let cost = (raw as u32).saturating_add(LOCAL_COST);
    if cost >= INFINITY { None } else { Some(cost) }
}

/// Refresh cached `lowest1`/`lowest2` from the `costs` map.
/// Lex tiebreak via `Name::cmp` per SPEC.md §4 *Notes*.
fn refresh(entry: &mut RibEntry) {
    let mut lowest1 = INFINITY;
    let mut lowest2 = INFINITY;
    let mut next_hop1: Option<Name> = None;
    let mut next_hop2: Option<Name> = None;
    for (hop, &cost) in &entry.costs {
        let beats_first =
            cost < lowest1 || (cost == lowest1 && next_hop1.as_ref().is_none_or(|nh| hop < nh));
        if beats_first {
            lowest2 = lowest1;
            next_hop2 = next_hop1.take();
            lowest1 = cost;
            next_hop1 = Some(hop.clone());
        } else {
            let beats_second =
                cost < lowest2 || (cost == lowest2 && next_hop2.as_ref().is_none_or(|nh| hop < nh));
            if beats_second {
                lowest2 = cost;
                next_hop2 = Some(hop.clone());
            }
        }
    }
    entry.lowest1 = lowest1;
    entry.lowest2 = lowest2;
    entry.next_hop1 = next_hop1;
    entry.next_hop2 = next_hop2;
}

fn best_route_of(entry: &RibEntry) -> Option<BestRoute> {
    if entry.lowest1 >= INFINITY {
        return None;
    }
    entry.next_hop1.as_ref().map(|nh| BestRoute {
        neighbor: nh.clone(),
        cost: entry.lowest1,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn name(s: &str) -> Name {
        Name::from_str(s).expect("valid name")
    }

    fn adv(entries: Vec<AdvEntry>) -> Advertisement {
        Advertisement { entries }
    }

    fn entry(dest: &str, next_hop: &str, cost: u64, other_cost: u64) -> AdvEntry {
        AdvEntry {
            destination: name(dest),
            next_hop: name(next_hop),
            cost,
            other_cost,
        }
    }

    #[test]
    fn new_rib_contains_self_at_cost_zero() {
        let rib = DvRib::new(name("/me"));
        assert_eq!(
            rib.best_route(&name("/me")),
            Some(BestRoute {
                neighbor: name("/me"),
                cost: 0,
            }),
        );
    }

    #[test]
    fn apply_advertisement_installs_route() {
        let rib = DvRib::new(name("/me"));
        let changes =
            rib.apply_advertisement(&name("/peer"), &adv(vec![entry("/dst", "/x", 3, 7)]));
        // dst now reachable via peer at cost 4 (= 3 + LOCAL_COST 1).
        assert_eq!(
            rib.best_route(&name("/dst")),
            Some(BestRoute {
                neighbor: name("/peer"),
                cost: 4,
            }),
        );
        // Exactly one change: /dst None -> Some.
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].destination, name("/dst"));
        assert_eq!(changes[0].old_best, None);
        assert_eq!(
            changes[0].new_best,
            Some(BestRoute {
                neighbor: name("/peer"),
                cost: 4,
            }),
        );
    }

    #[test]
    fn apply_advertisement_updates_cost_when_repeated() {
        let rib = DvRib::new(name("/me"));
        rib.apply_advertisement(&name("/peer"), &adv(vec![entry("/dst", "/x", 3, 7)]));
        let changes = rib.apply_advertisement(
            &name("/peer"),
            &adv(vec![entry("/dst", "/x", 5, 9)]), // peer now sees /dst at higher cost
        );
        assert_eq!(rib.best_route(&name("/dst")).unwrap().cost, 6); // 5 + 1
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].old_best.as_ref().unwrap().cost, 4);
        assert_eq!(changes[0].new_best.as_ref().unwrap().cost, 6);
    }

    #[test]
    fn poison_reverse_uses_other_cost_when_next_hop_is_self() {
        let rib = DvRib::new(name("/me"));
        // Peer says: I reach /dst via /me at cost=3, OR via someone else at cost=5.
        // We must use the "other" path (cost=5) when learning from this peer,
        // because the primary path loops through us.
        let changes =
            rib.apply_advertisement(&name("/peer"), &adv(vec![entry("/dst", "/me", 3, 5)]));
        // cost = other_cost (5) + LOCAL_COST (1) = 6
        assert_eq!(rib.best_route(&name("/dst")).unwrap().cost, 6);
        assert_eq!(changes[0].new_best.as_ref().unwrap().cost, 6);
    }

    #[test]
    fn poison_reverse_drops_when_other_cost_is_infinity() {
        let rib = DvRib::new(name("/me"));
        // Peer says: I reach /dst only via /me; no alternative.
        let changes = rib.apply_advertisement(
            &name("/peer"),
            &adv(vec![entry("/dst", "/me", 3, INFINITY as u64)]),
        );
        // Must not install a route — would create a loop.
        assert_eq!(rib.best_route(&name("/dst")), None);
        assert!(changes.is_empty());
    }

    #[test]
    fn cost_at_infinity_minus_one_plus_one_is_dropped() {
        let rib = DvRib::new(name("/me"));
        let changes = rib.apply_advertisement(
            &name("/peer"),
            &adv(vec![entry("/dst", "/x", (INFINITY - 1) as u64, 0)]),
        );
        // (INFINITY - 1) + 1 = INFINITY → dropped.
        assert_eq!(rib.best_route(&name("/dst")), None);
        assert!(changes.is_empty());
    }

    #[test]
    fn cost_above_infinity_dropped() {
        let rib = DvRib::new(name("/me"));
        let changes =
            rib.apply_advertisement(&name("/peer"), &adv(vec![entry("/dst", "/x", 100, 0)]));
        assert_eq!(rib.best_route(&name("/dst")), None);
        assert!(changes.is_empty());
    }

    #[test]
    fn ignores_advertisement_to_self() {
        let rib = DvRib::new(name("/me"));
        let changes =
            rib.apply_advertisement(&name("/peer"), &adv(vec![entry("/me", "/peer", 3, 5)]));
        // Self entry must remain at cost 0 via self.
        assert_eq!(
            rib.best_route(&name("/me")),
            Some(BestRoute {
                neighbor: name("/me"),
                cost: 0,
            }),
        );
        assert!(changes.is_empty());
    }

    #[test]
    fn best_route_picks_lowest_cost_across_neighbors() {
        let rib = DvRib::new(name("/me"));
        rib.apply_advertisement(&name("/p1"), &adv(vec![entry("/dst", "/x", 9, 11)]));
        rib.apply_advertisement(&name("/p2"), &adv(vec![entry("/dst", "/x", 3, 7)]));
        // p1 offers cost 10, p2 offers cost 4 — best is p2.
        let best = rib.best_route(&name("/dst")).unwrap();
        assert_eq!(best.neighbor, name("/p2"));
        assert_eq!(best.cost, 4);
    }

    #[test]
    fn lex_tiebreak_picks_lex_smallest_neighbor_name() {
        let rib = DvRib::new(name("/me"));
        rib.apply_advertisement(&name("/zzz"), &adv(vec![entry("/dst", "/x", 3, 5)]));
        rib.apply_advertisement(&name("/aaa"), &adv(vec![entry("/dst", "/x", 3, 5)]));
        // Both at cost 4; tiebreak picks /aaa.
        assert_eq!(
            rib.best_route(&name("/dst")).unwrap().neighbor,
            name("/aaa")
        );
    }

    #[test]
    fn destination_dropped_when_no_longer_advertised() {
        let rib = DvRib::new(name("/me"));
        // First sync: peer advertises /a and /b.
        rib.apply_advertisement(
            &name("/peer"),
            &adv(vec![entry("/a", "/x", 2, 4), entry("/b", "/x", 5, 7)]),
        );
        assert!(rib.best_route(&name("/a")).is_some());
        assert!(rib.best_route(&name("/b")).is_some());

        // Second sync: peer no longer advertises /b. /b should be pruned.
        let changes = rib.apply_advertisement(&name("/peer"), &adv(vec![entry("/a", "/x", 2, 4)]));
        assert!(rib.best_route(&name("/a")).is_some());
        assert_eq!(rib.best_route(&name("/b")), None);
        // /b's best went Some -> None.
        assert!(
            changes.iter().any(|c| c.destination == name("/b")
                && c.old_best.is_some()
                && c.new_best.is_none())
        );
    }

    #[test]
    fn destination_via_multiple_neighbors_survives_one_dropping_it() {
        let rib = DvRib::new(name("/me"));
        rib.apply_advertisement(&name("/p1"), &adv(vec![entry("/dst", "/x", 2, 4)]));
        rib.apply_advertisement(&name("/p2"), &adv(vec![entry("/dst", "/x", 5, 7)]));
        // p1 drops /dst — should fall back to p2.
        rib.apply_advertisement(&name("/p1"), &adv(vec![]));
        let best = rib.best_route(&name("/dst")).unwrap();
        assert_eq!(best.neighbor, name("/p2"));
        assert_eq!(best.cost, 6);
    }

    #[test]
    fn remove_neighbor_clears_routes() {
        let rib = DvRib::new(name("/me"));
        rib.apply_advertisement(&name("/peer"), &adv(vec![entry("/dst", "/x", 2, 4)]));
        assert!(rib.best_route(&name("/dst")).is_some());

        let changes = rib.remove_neighbor(&name("/peer"));
        assert_eq!(rib.best_route(&name("/dst")), None);
        assert!(changes.iter().any(|c| c.destination == name("/dst")
            && c.old_best.is_some()
            && c.new_best.is_none()),);
    }

    #[test]
    fn remove_neighbor_unknown_is_noop() {
        let rib = DvRib::new(name("/me"));
        let changes = rib.remove_neighbor(&name("/never_seen"));
        assert!(changes.is_empty());
    }

    #[test]
    fn remove_neighbor_keeps_routes_via_other_neighbors() {
        let rib = DvRib::new(name("/me"));
        rib.apply_advertisement(&name("/p1"), &adv(vec![entry("/dst", "/x", 2, 4)]));
        rib.apply_advertisement(&name("/p2"), &adv(vec![entry("/dst", "/x", 5, 7)]));
        // p1 goes away — falls back to p2.
        rib.remove_neighbor(&name("/p1"));
        let best = rib.best_route(&name("/dst")).unwrap();
        assert_eq!(best.neighbor, name("/p2"));
        assert_eq!(best.cost, 6);
    }

    #[test]
    fn produce_advertisement_includes_self_at_cost_zero() {
        let rib = DvRib::new(name("/me"));
        let out = rib.produce_advertisement();
        assert_eq!(out.entries.len(), 1);
        assert_eq!(out.entries[0].destination, name("/me"));
        assert_eq!(out.entries[0].next_hop, name("/me"));
        assert_eq!(out.entries[0].cost, 0);
        assert_eq!(out.entries[0].other_cost, INFINITY as u64);
    }

    #[test]
    fn produce_advertisement_after_apply_round_trips_via_neighbor() {
        let rib = DvRib::new(name("/me"));
        rib.apply_advertisement(&name("/peer"), &adv(vec![entry("/dst", "/x", 3, 7)]));
        let out = rib.produce_advertisement();
        // Self + /dst — two entries (sorted lex).
        assert_eq!(out.entries.len(), 2);
        // Find /dst entry.
        let dst_entry = out.entries.iter().find(|e| e.destination == name("/dst"));
        let dst_entry = dst_entry.expect("/dst must appear in advertisement");
        assert_eq!(dst_entry.next_hop, name("/peer"));
        assert_eq!(dst_entry.cost, 4);
        assert_eq!(dst_entry.other_cost, INFINITY as u64); // only one path known
    }

    #[test]
    fn produce_advertisement_other_cost_reflects_second_best() {
        let rib = DvRib::new(name("/me"));
        rib.apply_advertisement(&name("/p1"), &adv(vec![entry("/dst", "/x", 2, 4)]));
        rib.apply_advertisement(&name("/p2"), &adv(vec![entry("/dst", "/x", 5, 7)]));
        // Best: p1 at cost 3. Second-best: p2 at cost 6.
        let out = rib.produce_advertisement();
        let dst = out
            .entries
            .iter()
            .find(|e| e.destination == name("/dst"))
            .unwrap();
        assert_eq!(dst.next_hop, name("/p1"));
        assert_eq!(dst.cost, 3);
        assert_eq!(dst.other_cost, 6);
    }

    #[test]
    fn produce_advertisement_excludes_unreachable() {
        let rib = DvRib::new(name("/me"));
        rib.apply_advertisement(&name("/peer"), &adv(vec![entry("/dst", "/x", 2, 4)]));
        rib.remove_neighbor(&name("/peer"));
        let out = rib.produce_advertisement();
        // Only self should remain.
        assert_eq!(out.entries.len(), 1);
        assert_eq!(out.entries[0].destination, name("/me"));
    }

    #[test]
    fn two_router_exchange_converges() {
        // r1 starts. r2 sends its initial advertisement (just self).
        // r1 receives it → r1's RIB now knows how to reach r2.
        let r1 = DvRib::new(name("/r1"));
        let r2 = DvRib::new(name("/r2"));

        // r2's outgoing advertisement: just (r2 -> r2 @ 0).
        let r2_adv = r2.produce_advertisement();
        let changes = r1.apply_advertisement(&name("/r2"), &r2_adv);
        // r1 should now have a route to r2 via r2 at cost 1.
        assert_eq!(
            r1.best_route(&name("/r2")),
            Some(BestRoute {
                neighbor: name("/r2"),
                cost: 1,
            }),
        );
        // And it should be reflected in r1's next advertisement.
        let r1_adv = r1.produce_advertisement();
        assert!(
            r1_adv
                .entries
                .iter()
                .any(|e| e.destination == name("/r2") && e.cost == 1 && e.next_hop == name("/r2")),
        );
        // Symmetric: r2 receives r1's advertisement (which now mentions r2).
        // Per poison reverse, r2's RIB must NOT install a route to itself via r1
        // — the AdvEntry { dest: /r2, next_hop: /r2, ... } in r1_adv is filtered
        // out by the self-destination guard.
        let _ = r2.apply_advertisement(&name("/r1"), &r1_adv);
        // r2 still knows its own cost-zero self entry.
        assert_eq!(r2.best_route(&name("/r2")).unwrap().cost, 0);
        // And now r2 knows how to reach r1 via r1.
        assert_eq!(r2.best_route(&name("/r1")).unwrap().neighbor, name("/r1"));
        // r2 also picked up the change.
        assert!(changes.iter().any(|c| c.destination == name("/r2")));
    }
}
