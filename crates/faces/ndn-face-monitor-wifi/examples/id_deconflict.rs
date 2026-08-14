//! Ephemeral-ID deconfliction — quantitative harness (permutation over arms × field width × density).
//!
//! The ID keys per-PHY SOFT STATE only (RSSI, timing, dedup). A "collision" = a common neighbour
//! hears two DISTINCT transmitters under one ID within its soft-state window → its view of that ID
//! is aliased ("a less clear view of the medium"). We measure that alias rate and the rotation churn
//! it costs, to answer: how small can the field go with ACTIVE deconfliction vs birthday-only luck?
//!
//! Arms:
//!  - random   : pick a uniform b-bit ID on the 5-min §2 rotation; never react (birthday baseline).
//!  - pfs      : Pick-Free-Slot — pick an ID not currently observed among neighbours.
//!  - pfs+dar  : + Detect-And-Rotate — a common neighbour that sees an alias marks a conflict hint,
//!               which it can only deliver PIGGYBACKED ON ITS NEXT DATA FRAME (no beacon). Senders
//!               that hear that data frame and hold the conflicted ID rotate. So hint delivery is
//!               gated by the neighbour actually having traffic — which the PTX sweep stresses.
//!
//! Hidden terminals arise from the spatial hearing graph (two nodes out of range of each other but
//! both in range of a third). `cargo run --example id_deconflict --release -p ndn-face-monitor-wifi --features libusb-backend`

use std::collections::{HashMap, HashSet};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn f(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
    fn u(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Arm {
    Random,
    Pfs,
    PfsDar,
}

const L: f64 = 100.0; // area side
const R: f64 = 25.0; // hearing range
const W: u32 = 15; // soft-state window (rounds)
const ROT: u32 = 500; // §2 periodic rotation period
const T: u32 = 2000;
const WARM: u32 = 300;

// Returns (alias_rate_percent, reactive_rotations_per_node_per_1000r, avg_neighbors, hidden_frac).
fn run(arm: Arm, b: u32, n: usize, ptx: f64, seed: u64) -> (f64, f64, f64, f64) {
    let mut rng = Rng(seed.wrapping_mul(0x243f_6a88_85a3_08d3).wrapping_add(1));
    let space = 1u64 << b;
    let pos: Vec<(f64, f64)> = (0..n).map(|_| (rng.f() * L, rng.f() * L)).collect();
    let hear: Vec<Vec<usize>> = (0..n)
        .map(|i| {
            (0..n)
                .filter(|&j| j != i && (pos[i].0 - pos[j].0).hypot(pos[i].1 - pos[j].1) <= R)
                .collect()
        })
        .collect();

    // Topology stats.
    let (mut nbr_sum, mut hid_pairs, mut tot_pairs) = (0.0, 0u64, 0u64);
    for i in 0..n {
        nbr_sum += hear[i].len() as f64;
        for a in 0..hear[i].len() {
            for c in (a + 1)..hear[i].len() {
                let (x, y) = (hear[i][a], hear[i][c]);
                tot_pairs += 1;
                if !hear[x].contains(&y) {
                    hid_pairs += 1;
                }
            }
        }
    }
    let avg_nbr = nbr_sum / n as f64;
    let hidden_frac = if tot_pairs > 0 { hid_pairs as f64 / tot_pairs as f64 } else { 0.0 };

    let mut id: Vec<u32> = (0..n).map(|_| rng.u(space) as u32).collect();
    // observed[v]: id -> (sender -> last_round)
    let mut obs: Vec<HashMap<u32, HashMap<usize, u32>>> = vec![HashMap::new(); n];
    let mut flagged = vec![false; n];
    // pending[v]: conflict-hint IDs v has detected but not yet piggybacked onto a data frame.
    let mut pending: Vec<HashSet<u32>> = vec![HashSet::new(); n];

    let assign = |rng: &mut Rng, obs_u: &HashMap<u32, HashMap<usize, u32>>, r: u32| -> u32 {
        if arm == Arm::Random {
            return rng.u(space) as u32;
        }
        // Pick-Free-Slot: avoid IDs with a live sender in our own observation.
        let taken: HashSet<u32> = obs_u
            .iter()
            .filter(|(_, s)| s.values().any(|&t| r.saturating_sub(t) <= W))
            .map(|(&k, _)| k)
            .collect();
        let start = rng.u(space) as u32;
        for off in 0..space as u32 {
            let cand = (start + off) % space as u32;
            if !taken.contains(&cand) {
                return cand;
            }
        }
        rng.u(space) as u32
    };

    let (mut alias_acc, mut alias_n, mut react_rot) = (0.0, 0u64, 0u64);
    for r in 0..T {
        if r > 0 && r % ROT == 0 {
            for u in 0..n {
                id[u] = assign(&mut rng, &obs[u], r);
            }
        }
        for u in 0..n {
            if flagged[u] {
                id[u] = assign(&mut rng, &obs[u], r);
                flagged[u] = false;
                if r >= WARM {
                    react_rot += 1;
                }
            }
        }
        // transmissions — a data frame also DELIVERS the sender's piggybacked conflict hints.
        for u in 0..n {
            if rng.f() < ptx {
                if arm == Arm::PfsDar && !pending[u].is_empty() {
                    for &w in &hear[u] {
                        if pending[u].contains(&id[w]) {
                            flagged[w] = true; // heard the hint on a real data frame ⇒ rotate next round
                        }
                    }
                    pending[u].clear();
                }
                for &v in &hear[u] {
                    obs[v].entry(id[u]).or_default().insert(u, r);
                }
            }
        }
        // detect aliases (metric + queue a hint to piggyback later — NOT a beacon)
        if r >= WARM {
            for v in 0..n {
                let (mut distinct, mut aliased) = (0u32, 0u32);
                for (&idk, senders) in obs[v].iter() {
                    let live = senders.values().filter(|&&t| r.saturating_sub(t) <= W).count();
                    if live == 0 {
                        continue;
                    }
                    distinct += 1;
                    if live >= 2 {
                        aliased += 1;
                        if arm == Arm::PfsDar {
                            pending[v].insert(idk); // will ride v's next data frame
                        }
                    }
                }
                if distinct > 0 {
                    alias_acc += aliased as f64 / distinct as f64;
                    alias_n += 1;
                }
            }
        }
    }
    let alias_pct = 100.0 * alias_acc / alias_n.max(1) as f64;
    let churn = react_rot as f64 / n as f64 / ((T - WARM) as f64 / 1000.0);
    (alias_pct, churn, avg_nbr, hidden_frac)
}

fn avg(arm: Arm, b: u32, n: usize, ptx: f64) -> (f64, f64, f64, f64) {
    let (mut a, mut c, mut nb, mut hf) = (0.0, 0.0, 0.0, 0.0);
    const SEEDS: u64 = 8;
    for s in 0..SEEDS {
        let (aa, cc, nn, hh) = run(arm, b, n, ptx, s + 1);
        a += aa;
        c += cc;
        nb += nn;
        hf += hh;
    }
    (a / SEEDS as f64, c / SEEDS as f64, nb / SEEDS as f64, hf / SEEDS as f64)
}

fn main() {
    let nmed = 45usize;
    let dtx = 0.3;
    let (_, _, nb, hf) = avg(Arm::Pfs, 8, nmed, dtx);
    println!(
        "Spatial hearing graph, N={nmed} in {L}x{L}, R={R}. avg neighbours={nb:.1}, hidden-terminal pairs={:.0}%.",
        hf * 100.0
    );
    println!("NO BEACONS: the DAR hint rides the common neighbour's data frames only.\n");
    println!("ALIAS RATE (% of a neighbour's ID-view that is ambiguous) / reactive rotations per node per 1000 rounds:");
    println!("{:<10} {:>16} {:>16} {:>16}", "arm", "b=6 (64)", "b=8 (256)", "b=10 (1024)");
    for (name, arm) in [("random", Arm::Random), ("pfs", Arm::Pfs), ("pfs+dar", Arm::PfsDar)] {
        let mut cells = Vec::new();
        for b in [6u32, 8, 10] {
            let (a, c, _, _) = avg(arm, b, nmed, dtx);
            cells.push(format!("{a:5.2}% / {c:4.1}"));
        }
        println!("{:<10} {:>16} {:>16} {:>16}", name, cells[0], cells[1], cells[2]);
    }

    println!("\nTRAFFIC sweep at b=8 — does piggyback survive when the network is quiet? (PTX = per-round tx prob)");
    println!("{:<10} {:>16} {:>16} {:>16} {:>16}", "arm", "PTX=0.05", "PTX=0.15", "PTX=0.30", "PTX=0.60");
    for (name, arm) in [("random", Arm::Random), ("pfs+dar", Arm::PfsDar)] {
        let mut cells = Vec::new();
        for ptx in [0.05f64, 0.15, 0.30, 0.60] {
            let (a, c, _, _) = avg(arm, 8, nmed, ptx);
            cells.push(format!("{a:5.2}%/{c:4.1}"));
        }
        println!("{:<10} {:>16} {:>16} {:>16} {:>16}", name, cells[0], cells[1], cells[2], cells[3]);
    }
    println!("\nalias% = ambiguous fraction of the ID-view (lower=clearer); churn = reactive rotations/node/1000r.");
    println!("If pfs+dar stays well under random across PTX, the hint needs no beacon — data frames carry it.");

    // Record to CSV for the chapter's evidence set.
    let dir = "docs/data/name-filter";
    let _ = std::fs::create_dir_all(dir);
    if let Ok(mut f) = std::fs::File::create(format!("{dir}/id.csv")) {
        use std::io::Write;
        writeln!(f, "sweep,arm,bits,density_n,ptx,alias_pct,churn").unwrap();
        for (name, arm) in [("random", Arm::Random), ("pfs", Arm::Pfs), ("pfs+dar", Arm::PfsDar)] {
            for b in [6u32, 8, 10] {
                let (a, c, _, _) = avg(arm, b, nmed, dtx);
                writeln!(f, "width,{name},{b},{nmed},{dtx},{a:.4},{c:.3}").unwrap();
            }
        }
        for (name, arm) in [("random", Arm::Random), ("pfs+dar", Arm::PfsDar)] {
            for ptx in [0.05f64, 0.15, 0.30, 0.60] {
                let (a, c, _, _) = avg(arm, 8, nmed, ptx);
                writeln!(f, "traffic,{name},8,{nmed},{ptx},{a:.4},{c:.3}").unwrap();
            }
        }
        for (name, arm) in [("random", Arm::Random), ("pfs+dar", Arm::PfsDar)] {
            for n in [25usize, 45, 70] {
                let (a, c, _, hf) = avg(arm, 8, n, dtx);
                let _ = hf;
                writeln!(f, "density,{name},8,{n},{dtx},{a:.4},{c:.3}").unwrap();
            }
        }
        println!("wrote {dir}/id.csv");
    }
}
