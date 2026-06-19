//! Routing table — Dijkstra link-state computation and result storage.
//!
//! Each Dijkstra run publishes a [`RoutingSnapshot`] on a
//! `tokio::sync::watch` channel; `NamePrefixTable` subscribes to refresh
//! nexthop lists.
//!
//! Spec divergences from C++ NLSR
//! (`NLSR/src/route/{routing-table,routing-calculator-link-state}.{hpp,cpp}`):
//! - No `RoutingTablePoolEntry`; `NextHop` is small and cloned per run.
//! - `boost.signals2` `afterRoutingChange` hook → `watch` channel.
//!
//! Every LSA change reruns Dijkstra. O(V²) per change; acceptable at
//! the NLSR scale of <100 routers.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::sync::Arc;

use ndn_packet::Name;
use tokio::sync::watch;

use crate::protocols::nlsr::lsa::{Lsa, LsaType, adjacency::Adjacent};
use crate::protocols::nlsr::lsdb::Lsdb;

/// C++ equivalent: `NextHop` in `NLSR/src/route/nexthop.hpp`.
#[derive(Clone, Debug, PartialEq)]
pub struct NextHop {
    pub face_uri: String,
    /// IEEE 754 double; matches C++ NLSR's cost type.
    pub cost: f64,
}

#[derive(Clone, Debug)]
pub struct RoutingTableEntry {
    pub dest_router: Name,
    pub nexthops: Vec<NextHop>,
}

#[derive(Clone, Debug, Default)]
pub struct RoutingSnapshot {
    pub entries: Vec<RoutingTableEntry>,
}

impl RoutingSnapshot {
    pub fn get(&self, dest: &Name) -> Option<&RoutingTableEntry> {
        self.entries.iter().find(|e| &e.dest_router == dest)
    }
}

pub struct RoutingTable {
    snapshot_tx: watch::Sender<Arc<RoutingSnapshot>>,
}

/// Matches `Adjacent::NON_ADJACENT_COST` (`NLSR/src/adjacent.hpp:43`).
pub const NON_ADJACENT: f64 = -1.0;

impl RoutingTable {
    pub fn new() -> (Self, watch::Receiver<Arc<RoutingSnapshot>>) {
        let (tx, rx) = watch::channel(Arc::new(RoutingSnapshot::default()));
        (Self { snapshot_tx: tx }, rx)
    }

    pub fn snapshot_watch(&self) -> watch::Receiver<Arc<RoutingSnapshot>> {
        self.snapshot_tx.subscribe()
    }

    /// C++: `calculateLinkStateRoutingPath`
    /// (`NLSR/src/route/routing-calculator-link-state.cpp`).
    pub fn recompute(&self, lsdb: &Lsdb, self_name: &Name) {
        let snapshot = compute_routes(lsdb, self_name);
        let _ = self.snapshot_tx.send(Arc::new(snapshot));
    }
}

/// Builds the adjacency matrix from AdjLSAs, symmetrizes asymmetric
/// links (taking the higher cost), and runs one Dijkstra per direct
/// neighbour of `self_name`. Returns an empty snapshot if `self_name`
/// has no AdjLSA or adjacencies.
#[allow(clippy::needless_range_loop)]
pub fn compute_routes(lsdb: &Lsdb, self_name: &Name) -> RoutingSnapshot {
    let adj_lsas: Vec<_> = lsdb
        .iter_by_type(LsaType::Adjacency)
        .filter_map(|lsa| {
            if let Lsa::Adjacency(a) = lsa {
                Some(a)
            } else {
                None
            }
        })
        .collect();

    if adj_lsas.is_empty() {
        return RoutingSnapshot::default();
    }

    // Assign an integer index to every router name encountered in the LSAs.
    let mut name_to_idx: HashMap<Name, usize> = HashMap::new();
    for lsa in &adj_lsas {
        let n = name_to_idx.len();
        name_to_idx.entry(lsa.origin_router.clone()).or_insert(n);
        for adj in &lsa.adjacencies {
            let n = name_to_idx.len();
            name_to_idx.entry(adj.name.clone()).or_insert(n);
        }
    }
    let n = name_to_idx.len();
    let mut idx_to_name: Vec<Name> = vec![Name::root(); n];
    for (name, &idx) in &name_to_idx {
        idx_to_name[idx] = name.clone();
    }

    let Some(&source_idx) = name_to_idx.get(self_name) else {
        return RoutingSnapshot::default();
    };

    let own_adj: Vec<Adjacent> = adj_lsas
        .iter()
        .find(|l| &l.origin_router == self_name)
        .map(|l| l.adjacencies.clone())
        .unwrap_or_default();

    if own_adj.is_empty() {
        return RoutingSnapshot::default();
    }

    // Build N×N adjacency matrix; NON_ADJACENT marks absent links.
    let mut matrix = vec![vec![NON_ADJACENT; n]; n];
    for lsa in &adj_lsas {
        let Some(&row) = name_to_idx.get(&lsa.origin_router) else {
            continue;
        };
        for adj in &lsa.adjacencies {
            let Some(&col) = name_to_idx.get(&adj.name) else {
                continue;
            };
            matrix[row][col] = adj.link_cost;
        }
    }

    // Symmetrize: asymmetric links use the higher cost; one-sided links are
    // broken.  Matches C++ `makeAdjMatrix` correction pass in
    // `routing-calculator-link-state.cpp`.
    for r in 0..n {
        for c in (r + 1)..n {
            let to = matrix[r][c];
            let from = matrix[c][r];
            if to == from {
                continue;
            }
            let corrected = if to >= 0.0 && from >= 0.0 {
                to.max(from)
            } else {
                NON_ADJACENT
            };
            matrix[r][c] = corrected;
            matrix[c][r] = corrected;
        }
    }

    // Multi-path: one Dijkstra simulation per direct neighbor.
    // Each simulation pretends only that neighbor is accessible from source,
    // exposing all paths that route through it.
    let mut result: HashMap<usize, Vec<NextHop>> = HashMap::new();

    for adj in &own_adj {
        let Some(&nbr_idx) = name_to_idx.get(&adj.name) else {
            continue;
        };
        if matrix[source_idx][nbr_idx] < 0.0 {
            continue; // link is down
        }
        let face_uri = adj.face_uri.clone();

        let mut sim = matrix.clone();
        for c in 0..n {
            if c != nbr_idx {
                sim[source_idx][c] = NON_ADJACENT;
                sim[c][source_idx] = NON_ADJACENT;
            }
        }

        let dist = dijkstra(&sim, source_idx, n);

        for dest in 0..n {
            if dest == source_idx {
                continue;
            }
            let d = dist[dest];
            if d < f64::MAX / 2.0 {
                result.entry(dest).or_default().push(NextHop {
                    face_uri: face_uri.clone(),
                    cost: d,
                });
            }
        }
    }

    let entries = result
        .into_iter()
        .map(|(idx, nexthops)| RoutingTableEntry {
            dest_router: idx_to_name[idx].clone(),
            nexthops,
        })
        .collect();

    RoutingSnapshot { entries }
}

/// Dijkstra's shortest-path algorithm with a binary min-heap.
///
/// For non-negative finite `f64` costs, IEEE 754 bit representation preserves
/// numerical ordering, so `cost.to_bits()` is directly comparable as `u64`.
/// Returns a distance vector; unreachable nodes have `dist[v] ≥ f64::MAX/2`.
fn dijkstra(matrix: &[Vec<f64>], source: usize, n: usize) -> Vec<f64> {
    const INF: f64 = f64::MAX / 2.0;
    let mut dist = vec![INF; n];
    dist[source] = 0.0;

    let mut heap: BinaryHeap<Reverse<(u64, usize)>> = BinaryHeap::new();
    heap.push(Reverse((0u64, source)));

    while let Some(Reverse((d_bits, u))) = heap.pop() {
        let d = f64::from_bits(d_bits);
        if d > dist[u] {
            continue; // stale heap entry
        }
        for v in 0..n {
            let edge = matrix[u][v];
            if edge < 0.0 {
                continue;
            }
            let new_dist = dist[u] + edge;
            if new_dist < dist[v] {
                dist[v] = new_dist;
                heap.push(Reverse((new_dist.to_bits(), v)));
            }
        }
    }

    dist
}

//
// Topology from NLSR/tests/route/test-routing-calculator-link-state.cpp:
//
//   A ──5──  B
//    \      /
//    10   17
//      \ /
//       C
//
// Source = A.  Expected multi-path routes (via each neighbor separately):
//   to B: via B face (cost 5)  and via C face (cost 10+17=27)
//   to C: via C face (cost 10) and via B face (cost 5+17=22)

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use ndn_packet::Name;

    use super::*;
    use crate::protocols::nlsr::lsa::{
        Lsa,
        adjacency::{AdjacencyLsa, Adjacent},
    };
    use crate::protocols::nlsr::lsdb::Lsdb;

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

    fn adj(neighbor: &str, face_uri: &str, cost: f64) -> Adjacent {
        Adjacent {
            name: name(neighbor),
            face_uri: face_uri.to_owned(),
            link_cost: cost,
        }
    }

    fn adj_lsa(origin: &str, adjs: Vec<Adjacent>) -> Lsa {
        Lsa::Adjacency(AdjacencyLsa {
            origin_router: name(origin),
            seq_no: 1,
            expiration_ms: future_ms(),
            adjacencies: adjs,
        })
    }

    const A: &str = "/ndn/site/A";
    const B: &str = "/ndn/site/B";
    const C: &str = "/ndn/site/C";
    const A_FACE: &str = "udp4://10.0.0.1:6363";
    const B_FACE: &str = "udp4://10.0.0.2:6363";
    const C_FACE: &str = "udp4://10.0.0.3:6363";
    const AB: f64 = 5.0;
    const AC: f64 = 10.0;
    const BC: f64 = 17.0;

    /// Build a triangle LSDB (A as source).
    fn triangle_lsdb() -> Lsdb {
        let db = Lsdb::new(name(A));
        db.install(adj_lsa(A, vec![adj(B, B_FACE, AB), adj(C, C_FACE, AC)]));
        db.install(adj_lsa(B, vec![adj(C, C_FACE, BC), adj(A, A_FACE, AB)]));
        db.install(adj_lsa(C, vec![adj(A, A_FACE, AC), adj(B, B_FACE, BC)]));
        db
    }

    fn nexthops_for(snap: &RoutingSnapshot, dest: &str) -> Vec<NextHop> {
        snap.get(&name(dest))
            .map(|e| e.nexthops.clone())
            .unwrap_or_default()
    }

    fn has_nexthop(nexthops: &[NextHop], face: &str, cost: f64) -> bool {
        nexthops
            .iter()
            .any(|nh| nh.face_uri == face && (nh.cost - cost).abs() < 1e-9)
    }

    /// G.04 dijkstra — basic triangle topology.
    ///
    /// Verifies multi-path Dijkstra matches the C++ reference:
    /// `NLSR/tests/route/test-routing-calculator-link-state.cpp::Basic`
    #[test]
    fn dijkstra_basic_triangle() {
        let db = triangle_lsdb();
        let snap = compute_routes(&db, &name(A));

        let to_b = nexthops_for(&snap, B);
        assert!(has_nexthop(&to_b, B_FACE, AB), "A→B via B face cost {AB}");
        assert!(
            has_nexthop(&to_b, C_FACE, AC + BC),
            "A→B via C face cost {}",
            AC + BC
        );

        let to_c = nexthops_for(&snap, C);
        assert!(has_nexthop(&to_c, C_FACE, AC), "A→C via C face cost {AC}");
        assert!(
            has_nexthop(&to_c, B_FACE, AB + BC),
            "A→C via B face cost {}",
            AB + BC
        );
    }

    /// G.04 dijkstra — asymmetric link costs.
    ///
    /// Matches `NLSR/tests/route/test-routing-calculator-link-state.cpp::Asymmetric`
    #[test]
    fn dijkstra_asymmetric_costs() {
        let higher_bc = BC + 1.0;
        let db = Lsdb::new(name(A));
        db.install(adj_lsa(A, vec![adj(B, B_FACE, AB), adj(C, C_FACE, AC)]));
        db.install(adj_lsa(
            B,
            vec![adj(C, C_FACE, higher_bc), adj(A, A_FACE, AB)],
        ));
        db.install(adj_lsa(C, vec![adj(A, A_FACE, AC), adj(B, B_FACE, BC)]));

        let snap = compute_routes(&db, &name(A));

        let to_b = nexthops_for(&snap, B);
        assert!(has_nexthop(&to_b, B_FACE, AB));
        assert!(has_nexthop(&to_b, C_FACE, AC + higher_bc));

        let to_c = nexthops_for(&snap, C);
        assert!(has_nexthop(&to_c, C_FACE, AC));
        assert!(has_nexthop(&to_c, B_FACE, AB + higher_bc));
    }

    /// G.04 dijkstra — broken link drops path.
    ///
    /// Matches `NLSR/tests/route/test-routing-calculator-link-state.cpp::NonAdjacentCost`
    #[test]
    fn dijkstra_broken_link() {
        let db = Lsdb::new(name(A));
        db.install(adj_lsa(A, vec![adj(B, B_FACE, AB), adj(C, C_FACE, AC)]));
        // B reports B→C as NON_ADJACENT
        db.install(adj_lsa(B, vec![adj(A, A_FACE, AB)]));
        db.install(adj_lsa(C, vec![adj(A, A_FACE, AC), adj(B, B_FACE, BC)]));

        let snap = compute_routes(&db, &name(A));

        let to_b = nexthops_for(&snap, B);
        assert!(
            has_nexthop(&to_b, B_FACE, AB),
            "direct path to B still exists"
        );
        assert!(
            !has_nexthop(&to_b, C_FACE, AC + BC),
            "no path via C (link B-C broken)"
        );

        let to_c = nexthops_for(&snap, C);
        assert!(
            has_nexthop(&to_c, C_FACE, AC),
            "direct path to C still exists"
        );
        assert!(
            !has_nexthop(&to_c, B_FACE, AB + BC),
            "no path via B (link B-C broken)"
        );
    }

    /// G.04 dijkstra — source router absent yields empty snapshot.
    #[test]
    fn dijkstra_source_absent() {
        let db = Lsdb::new(name(A));
        // Only B and C install LSAs; A is missing.
        db.install(adj_lsa(B, vec![adj(C, C_FACE, BC)]));
        db.install(adj_lsa(C, vec![adj(B, B_FACE, BC)]));

        let snap = compute_routes(&db, &name(A));
        assert!(snap.entries.is_empty(), "no routes when source is absent");
    }

    /// Watch channel receives updated snapshot after recompute.
    #[test]
    fn routing_table_watch_fires() {
        let (rt, mut rx) = RoutingTable::new();
        let db = triangle_lsdb();
        rt.recompute(&db, &name(A));

        let snap = rx.borrow_and_update();
        assert!(
            !snap.entries.is_empty(),
            "snapshot populated after recompute"
        );
    }
}
