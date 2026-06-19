//! Name Prefix Table — maps advertised prefixes to nexthop sets.
//!
//! Consumes two event streams:
//! - `LsdbEvent` (NameLsa installs/updates/removals) — tracks which
//!   router originates which prefixes.
//! - `RoutingSnapshot` (Dijkstra result) — refreshes per-router nexthops.
//!
//! Spec divergence from C++ NLSR
//! (`NLSR/src/route/name-prefix-table.{hpp,cpp}`):
//! `shared_ptr<RoutingTablePoolEntry>` pool replaced with a plain
//! `HashMap<router_name, RoutingTableEntry>`; nexthops are small enough
//! to clone on update.

use std::collections::{HashMap, HashSet};

use ndn_packet::Name;

use crate::protocols::nlsr::lsa::Lsa;
use crate::protocols::nlsr::lsdb::{LsdbEvent, LsdbUpdate};
use crate::protocols::nlsr::routing_table::{NextHop, RoutingSnapshot, RoutingTableEntry};

struct NptEntry {
    dest_routers: HashSet<Name>,
}

pub struct NamePrefixTable {
    entries: HashMap<Name, NptEntry>,
    router_pool: HashMap<Name, RoutingTableEntry>,
}

#[allow(clippy::new_without_default)]
impl NamePrefixTable {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            router_pool: HashMap::new(),
        }
    }

    /// NPT only tracks remote prefixes; own-router LSAs are skipped.
    /// C++: `NamePrefixTable::updateFromLsdb`
    /// (`NLSR/src/route/name-prefix-table.cpp:60`).
    pub fn update_from_lsdb(&mut self, event: &LsdbEvent, own_router: &Name) {
        let Lsa::Name(name_lsa) = &event.lsa else {
            return;
        };

        if &name_lsa.origin_router == own_router {
            return;
        }

        let router = name_lsa.origin_router.clone();

        match &event.update {
            LsdbUpdate::Installed => {
                self.add_prefix(router.clone(), router.clone());
                for p in &name_lsa.prefixes {
                    self.add_prefix(p.name.clone(), router.clone());
                }
                // Pool entry exists even before nexthops are known.
                self.router_pool
                    .entry(router)
                    .or_insert_with(|| RoutingTableEntry {
                        dest_router: name_lsa.origin_router.clone(),
                        nexthops: Vec::new(),
                    });
            }
            LsdbUpdate::Updated => {
                for added in &event.prefixes_added {
                    self.add_prefix(added.clone(), router.clone());
                }
                for removed in &event.prefixes_removed {
                    self.remove_prefix(removed, &router);
                }
            }
            LsdbUpdate::Removed => {
                self.remove_prefix(&router, &router.clone());
                for p in &name_lsa.prefixes {
                    self.remove_prefix(&p.name, &router);
                }
                self.router_pool.remove(&router);
            }
        }
    }

    /// Refreshes per-router nexthops; FIB/RIB updates are driven by
    /// the caller. C++: `NamePrefixTable::updateWithNewRoute`
    /// (`NLSR/src/route/name-prefix-table.cpp:110`).
    pub fn update_with_new_route(&mut self, snapshot: &RoutingSnapshot) {
        for (router, pool_entry) in &mut self.router_pool {
            let new_nexthops = snapshot
                .get(router)
                .map(|e| e.nexthops.clone())
                .unwrap_or_default();
            pool_entry.nexthops = new_nexthops;
        }
    }

    /// Return the nexthop list for a given prefix.
    ///
    /// Collects nexthops from all routers advertising the prefix.
    pub fn nexthops_for_prefix(&self, prefix: &Name) -> Vec<NextHop> {
        let Some(entry) = self.entries.get(prefix) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for router in &entry.dest_routers {
            if let Some(rte) = self.router_pool.get(router) {
                out.extend_from_slice(&rte.nexthops);
            }
        }
        out
    }

    pub fn snapshot(&self) -> Vec<(Name, Vec<NextHop>)> {
        self.entries
            .keys()
            .map(|prefix| (prefix.clone(), self.nexthops_for_prefix(prefix)))
            .collect()
    }

    fn add_prefix(&mut self, prefix: Name, dest_router: Name) {
        self.entries
            .entry(prefix)
            .or_insert_with(|| NptEntry {
                dest_routers: HashSet::new(),
            })
            .dest_routers
            .insert(dest_router);
    }

    fn remove_prefix(&mut self, prefix: &Name, dest_router: &Name) {
        if let Some(entry) = self.entries.get_mut(prefix) {
            entry.dest_routers.remove(dest_router);
            if entry.dest_routers.is_empty() {
                self.entries.remove(prefix);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use ndn_packet::Name;

    use super::*;
    use crate::protocols::nlsr::lsa::{
        Lsa,
        name::{NameLsa, PrefixInfo},
    };
    use crate::protocols::nlsr::lsdb::LsdbUpdate;
    use crate::protocols::nlsr::routing_table::{NextHop, RoutingSnapshot, RoutingTableEntry};

    fn name(s: &str) -> Name {
        s.parse().unwrap()
    }

    fn future_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
            + 300_000
    }

    fn install_event(origin: &str, prefixes: &[&str]) -> LsdbEvent {
        LsdbEvent {
            update: LsdbUpdate::Installed,
            lsa: Lsa::Name(NameLsa {
                origin_router: name(origin),
                seq_no: 1,
                expiration_ms: future_ms(),
                prefixes: prefixes
                    .iter()
                    .map(|p| PrefixInfo {
                        name: name(p),
                        cost: 0.0,
                    })
                    .collect(),
            }),
            prefixes_added: prefixes.iter().map(|p| name(p)).collect(),
            prefixes_removed: vec![],
        }
    }

    fn removed_event(origin: &str, prefixes: &[&str]) -> LsdbEvent {
        LsdbEvent {
            update: LsdbUpdate::Removed,
            lsa: Lsa::Name(NameLsa {
                origin_router: name(origin),
                seq_no: 1,
                expiration_ms: future_ms(),
                prefixes: prefixes
                    .iter()
                    .map(|p| PrefixInfo {
                        name: name(p),
                        cost: 0.0,
                    })
                    .collect(),
            }),
            prefixes_added: vec![],
            prefixes_removed: prefixes.iter().map(|p| name(p)).collect(),
        }
    }

    fn make_snapshot(entries: Vec<(&str, Vec<(&str, f64)>)>) -> RoutingSnapshot {
        RoutingSnapshot {
            entries: entries
                .into_iter()
                .map(|(dest, nexthops)| RoutingTableEntry {
                    dest_router: name(dest),
                    nexthops: nexthops
                        .into_iter()
                        .map(|(face, cost)| NextHop {
                            face_uri: face.to_owned(),
                            cost,
                        })
                        .collect(),
                })
                .collect(),
        }
    }

    #[test]
    fn install_populates_entries() {
        let mut npt = NamePrefixTable::new();
        let own = name("/self");
        npt.update_from_lsdb(&install_event("/routerA", &["/prefix/a"]), &own);

        // After install, the prefix is tracked but nexthops are empty until routing runs.
        let hops = npt.nexthops_for_prefix(&name("/prefix/a"));
        assert!(hops.is_empty(), "no nexthops before routing table update");
    }

    #[test]
    fn routing_update_populates_nexthops() {
        let mut npt = NamePrefixTable::new();
        let own = name("/self");

        npt.update_from_lsdb(&install_event("/routerA", &["/prefix/a"]), &own);

        let snap = make_snapshot(vec![("/routerA", vec![("udp://10.0.0.1", 5.0)])]);
        npt.update_with_new_route(&snap);

        let hops = npt.nexthops_for_prefix(&name("/prefix/a"));
        assert_eq!(hops.len(), 1);
        assert_eq!(hops[0].face_uri, "udp://10.0.0.1");
        assert!((hops[0].cost - 5.0).abs() < 1e-9);
    }

    #[test]
    fn removal_clears_prefix() {
        let mut npt = NamePrefixTable::new();
        let own = name("/self");

        npt.update_from_lsdb(&install_event("/routerA", &["/prefix/a"]), &own);
        npt.update_from_lsdb(&removed_event("/routerA", &["/prefix/a"]), &own);

        let hops = npt.nexthops_for_prefix(&name("/prefix/a"));
        assert!(hops.is_empty(), "prefix removed from NPT");
    }

    #[test]
    fn own_router_lsa_skipped() {
        let mut npt = NamePrefixTable::new();
        let own = name("/self");

        npt.update_from_lsdb(&install_event("/self", &["/prefix/own"]), &own);
        assert!(
            npt.nexthops_for_prefix(&name("/prefix/own")).is_empty(),
            "own-router prefixes not tracked in NPT"
        );
    }

    #[test]
    fn multi_router_prefix_aggregates_nexthops() {
        let mut npt = NamePrefixTable::new();
        let own = name("/self");

        npt.update_from_lsdb(&install_event("/routerA", &["/shared/prefix"]), &own);
        npt.update_from_lsdb(&install_event("/routerB", &["/shared/prefix"]), &own);

        let snap = make_snapshot(vec![
            ("/routerA", vec![("udp://10.0.0.1", 5.0)]),
            ("/routerB", vec![("udp://10.0.0.2", 10.0)]),
        ]);
        npt.update_with_new_route(&snap);

        let hops = npt.nexthops_for_prefix(&name("/shared/prefix"));
        assert_eq!(hops.len(), 2, "nexthops from both routers aggregated");
    }
}
