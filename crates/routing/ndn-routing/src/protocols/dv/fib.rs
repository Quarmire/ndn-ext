//! ndn-dv FIB computation per SPEC.md §4 *FIB Computation*.
//!
//! Joins [`DvRib`], [`PrefixTable`], and a caller-supplied neighbour→face
//! binding into per-prefix FIB rows. For each prefix announced in the
//! global prefix table, emits one or more `(face, cost)` pairs where
//! `cost = announce_cost + rib_cost_to_exit_router`. Multiple next-hops
//! per prefix are emitted; the engine deduplicates and lets strategies
//! multipath.
//!
//! Also emits per-router prefix-sync subscription prefixes
//! (`<network>/32=DV/32=PFS/<router>`) so incoming `PrefixOpList` Data
//! fetches for each known router can be FIB-routed to the neighbour we
//! reach that router through (second half of ndnd `dv/table_algo.go::updateFib`).
//!
//! Pure function over read-only views; the engine-wiring layer applies
//! these `FibUpdate`s to the engine FIB.

use std::collections::HashMap;

use ndn_packet::{Name, NameComponent};
use ndn_transport::FaceId;

use crate::protocols::dv::prefix::PrefixTable;
use crate::protocols::dv::rib::{DvRib, INFINITY};

/// `next_hops` is sorted by cost ascending; ties broken by face id for
/// determinism.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FibUpdate {
    pub prefix: Name,
    pub next_hops: Vec<NextHop>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NextHop {
    pub cost: u32,
    pub face: FaceId,
}

// FaceId has no Ord impl; sort manually on (cost, face.0).
impl Ord for NextHop {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.cost
            .cmp(&other.cost)
            .then_with(|| self.face.0.cmp(&other.face.0))
    }
}

impl PartialOrd for NextHop {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// `network` is the network-prefix root used to construct per-router
/// Prefix Sync FIB entries (`/<network>/32=DV/32=PFS/<router>`).
///
/// Routers with no known face binding are silently skipped. Self-served
/// prefixes appear with empty `next_hops`; callers filter on
/// `next_hops.is_empty()`.
pub fn compute_fib_updates(
    rib: &DvRib,
    prefix_table: &PrefixTable,
    network: &Name,
    face_for_neighbor: impl Fn(&Name) -> Option<FaceId>,
) -> Vec<FibUpdate> {
    let mut out: HashMap<Name, Vec<NextHop>> = HashMap::new();

    let self_name = rib.self_name();
    for entry in rib.snapshot() {
        if &entry.destination == self_name {
            continue;
        }
        if entry.lowest1 >= INFINITY {
            continue;
        }
        let next_hops_to_router = collect_next_hops(&entry.costs, &face_for_neighbor);
        if next_hops_to_router.is_empty() {
            continue;
        }

        let psync_route = prefix_sync_route(network, &entry.destination);
        merge_into(&mut out, psync_route, &next_hops_to_router, 0);

        for (prefix, announce_cost) in prefix_table.prefixes_for_router(&entry.destination) {
            merge_into(&mut out, prefix, &next_hops_to_router, announce_cost);
        }
    }

    let mut updates: Vec<FibUpdate> = out
        .into_iter()
        .map(|(prefix, mut next_hops)| {
            next_hops.sort();
            FibUpdate { prefix, next_hops }
        })
        .collect();
    updates.sort_by(|a, b| a.prefix.cmp(&b.prefix));
    updates
}

/// Translates a RIB entry's per-neighbour cost map into next-hops by
/// looking up each neighbour's face binding. Drops `INFINITY` costs and
/// neighbours with no face binding.
fn collect_next_hops(
    costs: &HashMap<Name, u32>,
    face_for_neighbor: &impl Fn(&Name) -> Option<FaceId>,
) -> Vec<NextHop> {
    let mut out = Vec::new();
    for (neighbor, &cost) in costs {
        if cost >= INFINITY {
            continue;
        }
        if let Some(face) = face_for_neighbor(neighbor) {
            out.push(NextHop { cost, face });
        }
    }
    out
}

fn merge_into(out: &mut HashMap<Name, Vec<NextHop>>, prefix: Name, base: &[NextHop], extra: u32) {
    let row = out.entry(prefix).or_default();
    for nh in base {
        let cost = nh.cost.saturating_add(extra);
        row.push(NextHop {
            cost,
            face: nh.face,
        });
    }
}

/// Per-router subscription prefix in the Prefix Sync group, per SPEC.md §2:
/// `<network>/32=DV/32=PFS/<router>`.
fn prefix_sync_route(network: &Name, router: &Name) -> Name {
    let mut name = network.clone();
    name = name
        .append_component(NameComponent::keyword(bytes::Bytes::from_static(b"DV")))
        .append_component(NameComponent::keyword(bytes::Bytes::from_static(b"PFS")));
    for c in router.components() {
        name = name.append_component(c.clone());
    }
    name
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::str::FromStr;

    use crate::protocols::dv::tlv::{AdvEntry, Advertisement};

    fn name(s: &str) -> Name {
        Name::from_str(s).expect("valid name")
    }

    fn faces(pairs: &[(&str, u64)]) -> HashMap<Name, FaceId> {
        pairs.iter().map(|(n, f)| (name(n), FaceId(*f))).collect()
    }

    fn lookup(map: &HashMap<Name, FaceId>) -> impl Fn(&Name) -> Option<FaceId> + '_ {
        |n: &Name| map.get(n).copied()
    }

    fn adv(entries: Vec<(&str, &str, u64, u64)>) -> Advertisement {
        Advertisement {
            entries: entries
                .into_iter()
                .map(|(dest, nh, c, oc)| AdvEntry {
                    destination: name(dest),
                    next_hop: name(nh),
                    cost: c,
                    other_cost: oc,
                })
                .collect(),
        }
    }

    /// Standard scenario: self=/me, network=/ndn, one neighbor=/peer
    /// on face 7, that neighbor advertises reachability to /r1.
    fn fixture() -> (DvRib, PrefixTable, HashMap<Name, FaceId>, Name) {
        let rib = DvRib::new(name("/me"));
        rib.apply_advertisement(&name("/peer"), &adv(vec![("/r1", "/x", 2, 4)]));
        let pt = PrefixTable::new(name("/me"));
        let face_map = faces(&[("/peer", 7)]);
        (rib, pt, face_map, name("/ndn"))
    }

    #[test]
    fn empty_rib_and_table_yields_no_updates() {
        let rib = DvRib::new(name("/me"));
        let pt = PrefixTable::new(name("/me"));
        let map = faces(&[]);
        let out = compute_fib_updates(&rib, &pt, &name("/ndn"), lookup(&map));
        assert!(out.is_empty());
    }

    #[test]
    fn reachable_router_gets_prefix_sync_fib_entry() {
        let (rib, pt, map, network) = fixture();
        let out = compute_fib_updates(&rib, &pt, &network, lookup(&map));
        // We expect exactly one entry: the per-router PFS subscription
        // prefix `/ndn/32=DV/32=PFS/r1` (cost = RIB cost to /r1 = 3).
        assert_eq!(out.len(), 1);
        let entry = &out[0];
        // Check the keyword components are present.
        let comps = entry.prefix.components();
        assert_eq!(comps[0].value.as_ref(), b"ndn");
        assert_eq!(comps[1].value.as_ref(), b"DV");
        assert_eq!(comps[2].value.as_ref(), b"PFS");
        assert_eq!(comps[3].value.as_ref(), b"r1");
        assert_eq!(entry.next_hops.len(), 1);
        assert_eq!(entry.next_hops[0].face, FaceId(7));
        assert_eq!(entry.next_hops[0].cost, 3); // 2 + LOCAL_COST(1)
    }

    #[test]
    fn announced_prefix_gets_fib_entry_with_composed_cost() {
        let (rib, pt, map, network) = fixture();
        // /r1 announces /shop at cost=5 in the global table.
        pt.apply_op_list(&crate::protocols::dv::tlv::PrefixOpList {
            exit_router: name("/r1"),
            reset: false,
            adds: vec![crate::protocols::dv::tlv::PrefixOpAdd {
                name: name("/shop"),
                cost: 5,
            }],
            removes: vec![],
        });
        let out = compute_fib_updates(&rib, &pt, &network, lookup(&map));
        // Two FIB updates: /ndn/DV/PFS/r1 and /shop.
        assert_eq!(out.len(), 2);
        let shop = out.iter().find(|u| u.prefix == name("/shop")).unwrap();
        assert_eq!(shop.next_hops.len(), 1);
        assert_eq!(shop.next_hops[0].face, FaceId(7));
        // Composed cost: announce_cost (5) + rib_cost_via_neighbor (3) = 8.
        assert_eq!(shop.next_hops[0].cost, 8);
    }

    #[test]
    fn multipath_via_two_neighbors_emits_two_next_hops() {
        let rib = DvRib::new(name("/me"));
        rib.apply_advertisement(&name("/peer-a"), &adv(vec![("/r1", "/x", 2, 4)]));
        rib.apply_advertisement(&name("/peer-b"), &adv(vec![("/r1", "/x", 5, 7)]));
        let pt = PrefixTable::new(name("/me"));
        let map = faces(&[("/peer-a", 7), ("/peer-b", 9)]);
        let out = compute_fib_updates(&rib, &pt, &name("/ndn"), lookup(&map));
        // One prefix (/ndn/DV/PFS/r1), two next-hops.
        assert_eq!(out.len(), 1);
        let entry = &out[0];
        assert_eq!(entry.next_hops.len(), 2);
        // Sorted by cost ascending.
        assert_eq!(entry.next_hops[0].cost, 3); // 2 + 1
        assert_eq!(entry.next_hops[0].face, FaceId(7));
        assert_eq!(entry.next_hops[1].cost, 6); // 5 + 1
        assert_eq!(entry.next_hops[1].face, FaceId(9));
    }

    #[test]
    fn neighbor_with_no_face_binding_is_skipped() {
        let rib = DvRib::new(name("/me"));
        rib.apply_advertisement(&name("/peer"), &adv(vec![("/r1", "/x", 2, 4)]));
        let pt = PrefixTable::new(name("/me"));
        // No face binding for /peer — should produce no updates.
        let map = faces(&[]);
        let out = compute_fib_updates(&rib, &pt, &name("/ndn"), lookup(&map));
        assert!(out.is_empty());
    }

    #[test]
    fn self_destination_is_skipped() {
        // Even with a "/me" entry in the RIB (always there), it
        // must NOT produce a `/ndn/DV/PFS/me` FIB entry — we don't
        // need to sync our own prefix list back to ourselves.
        let rib = DvRib::new(name("/me"));
        let pt = PrefixTable::new(name("/me"));
        let map = faces(&[]);
        let out = compute_fib_updates(&rib, &pt, &name("/ndn"), lookup(&map));
        assert!(out.is_empty());
    }

    #[test]
    fn multiple_announcers_get_separate_fib_entries() {
        // /shop is announced by both /r1 (cost 5) and /r2 (cost 3).
        // We reach /r1 via /peer-a face=7 (cost 3) and /r2 via /peer-b
        // face=9 (cost 1). We should see both next-hops in the FIB
        // entry for /shop with composed costs 8 and 4.
        let rib = DvRib::new(name("/me"));
        rib.apply_advertisement(&name("/peer-a"), &adv(vec![("/r1", "/x", 2, 4)]));
        rib.apply_advertisement(&name("/peer-b"), &adv(vec![("/r2", "/x", 0, 2)]));
        let pt = PrefixTable::new(name("/me"));
        pt.apply_op_list(&crate::protocols::dv::tlv::PrefixOpList {
            exit_router: name("/r1"),
            reset: false,
            adds: vec![crate::protocols::dv::tlv::PrefixOpAdd {
                name: name("/shop"),
                cost: 5,
            }],
            removes: vec![],
        });
        pt.apply_op_list(&crate::protocols::dv::tlv::PrefixOpList {
            exit_router: name("/r2"),
            reset: false,
            adds: vec![crate::protocols::dv::tlv::PrefixOpAdd {
                name: name("/shop"),
                cost: 3,
            }],
            removes: vec![],
        });
        let map = faces(&[("/peer-a", 7), ("/peer-b", 9)]);
        let out = compute_fib_updates(&rib, &pt, &name("/ndn"), lookup(&map));
        let shop = out
            .iter()
            .find(|u| u.prefix == name("/shop"))
            .expect("/shop must be in FIB");
        assert_eq!(shop.next_hops.len(), 2);
        // Sorted by cost: via /peer-b at 4 (rib 1 + announce 3), then
        // via /peer-a at 8 (rib 3 + announce 5).
        assert_eq!(shop.next_hops[0].face, FaceId(9));
        assert_eq!(shop.next_hops[0].cost, 4);
        assert_eq!(shop.next_hops[1].face, FaceId(7));
        assert_eq!(shop.next_hops[1].cost, 8);
    }

    #[test]
    fn output_is_lex_sorted_by_prefix() {
        // Same setup as multiple_announcers test, but verify the
        // top-level FibUpdate list is sorted.
        let rib = DvRib::new(name("/me"));
        rib.apply_advertisement(
            &name("/peer"),
            &adv(vec![
                ("/zzz", "/x", 1, 3),
                ("/aaa", "/x", 1, 3),
                ("/mmm", "/x", 1, 3),
            ]),
        );
        let pt = PrefixTable::new(name("/me"));
        let map = faces(&[("/peer", 5)]);
        let out = compute_fib_updates(&rib, &pt, &name("/ndn"), lookup(&map));
        let prefixes: Vec<String> = out.iter().map(|u| u.prefix.to_string()).collect();
        let mut sorted = prefixes.clone();
        sorted.sort();
        assert_eq!(prefixes, sorted);
    }
}
