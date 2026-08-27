//! **Name Filter validation harness** — realistic NDN traffic, thorough sweeps, recorded to CSV,
//! instrumented with tracing spans. Backs the Name Filter chapter (docs/name-filter-chapter.md).
//!
//! Mechanisms validated:
//!   1. Blur STRUCTURE   — Bloom vs GCS vs xor: bits/prefix + FP at matched field budgets.
//!   2. Blur ALLOCATION  — full / head=C / graduated / importance-weighted: FALSE NEGATIVES (safety)
//!                         + FP + bits. head=C is expected UNSAFE on deep names.
//!   3. DEPTH            — FP vs realistic name depth distribution.
//!   4. Ephemeral ID     — deconfliction arms × field width × density × traffic (beacon-free).
//!
//! Traffic: Zipf-popular namespace roots, deep versioned/segmented names (mode ~10 components),
//! FIB (shallow routes) / PIT / CS (deep names) registration sets — not the toy disjoint names.
//!
//! `cargo run --example name_filter_eval --release -p ndn-face-monitor-wifi --features libusb-backend`
//! Writes CSVs under docs/data/name-filter/ and prints a span-timing summary.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Write as _;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tracing_subscriber::layer::Context;
use tracing_subscriber::prelude::*;
use tracing_subscriber::registry::LookupSpan;

// A monotonic-clock span-duration aggregation Layer (none ships in ndn-observability; the recipe's
// gotcha is that OTLP timestamps are wall-clock, so latency is measured here with `Instant`).
#[derive(Clone, Default)]
struct LatLayer {
    d: Arc<Mutex<BTreeMap<&'static str, Vec<u64>>>>,
}
impl<S> tracing_subscriber::Layer<S> for LatLayer
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(
        &self,
        _a: &tracing::span::Attributes<'_>,
        id: &tracing::span::Id,
        ctx: Context<'_, S>,
    ) {
        if let Some(s) = ctx.span(id) {
            s.extensions_mut().insert(Instant::now());
        }
    }
    fn on_close(&self, id: tracing::span::Id, ctx: Context<'_, S>) {
        if let Some(s) = ctx.span(&id) {
            if let Some(t0) = s.extensions().get::<Instant>() {
                self.d
                    .lock()
                    .unwrap()
                    .entry(s.name())
                    .or_default()
                    .push(t0.elapsed().as_nanos() as u64);
            }
        }
    }
}

// ---------- deterministic PRNG ----------
struct Rng(u64);
impl Rng {
    fn new(s: u64) -> Self {
        Rng(s
            .wrapping_mul(0x243f_6a88_85a3_08d3)
            .wrapping_add(0x9e37_79b9))
    }
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
        if n == 0 { 0 } else { self.next() % n }
    }
    fn zipf(&mut self, n: usize, s: f64) -> usize {
        // inverse-CDF-ish Zipf via rejection on a harmonic table (n small here).
        let h: Vec<f64> = (1..=n)
            .scan(0.0, |acc, k| {
                *acc += 1.0 / (k as f64).powf(s);
                Some(*acc)
            })
            .collect();
        let target = self.f() * h[n - 1];
        h.iter().position(|&c| c >= target).unwrap_or(n - 1)
    }
}

// ---------- one keyed hash (stands in for SipHash-under-GroupKey) ----------
fn hh(bytes: &[u8], seed: u64) -> u64 {
    let mut x = 0xcbf2_9ce4_8422_2325u64 ^ seed;
    for &b in bytes {
        x = (x ^ b as u64).wrapping_mul(0x0000_0100_0000_01b3);
    }
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

// ---------- realistic NDN traffic corpus ----------
type Name = Vec<String>; // components

struct Corpus {
    names: Vec<Name>, // the traffic stream (deep names)
    fib: Vec<Name>,   // shallow routing prefixes (registered)
    depths: Vec<usize>,
}

fn gen_corpus(seed: u64, n_names: usize) -> Corpus {
    let mut rng = Rng::new(seed);
    const ROOTS: usize = 32;
    const ROOT_DEPTH: usize = 3; // /ndn/<org>/<app>
    // Per-root vocabulary of mid path components (names under a root share structure).
    let roots: Vec<Name> = (0..ROOTS)
        .map(|r| (0..ROOT_DEPTH).map(|c| format!("r{r}c{c}")).collect())
        .collect();
    let vocab: Vec<Vec<String>> = (0..ROOTS)
        .map(|r| (0..8).map(|w| format!("w{r}_{w}")).collect())
        .collect();

    let mut names = Vec::with_capacity(n_names);
    let mut depths = Vec::with_capacity(n_names);
    for _ in 0..n_names {
        let r = rng.zipf(ROOTS, 1.1); // popular roots dominate
        let mut nm = roots[r].clone();
        let path_len = 2 + rng.u(7) as usize; // 2..8 mid components
        for _ in 0..path_len {
            let w = rng.u(vocab[r].len() as u64) as usize;
            nm.push(vocab[r][w].clone());
        }
        // version + segment tail (high entropy)
        nm.push(format!("v{}", rng.u(1000)));
        nm.push(format!("s{}", rng.u(100000)));
        depths.push(nm.len());
        names.push(nm);
    }
    // FIB: the roots (depth 3) + depth-4 aggregates under popular roots.
    let mut fib: Vec<Name> = roots.clone();
    for r in 0..8 {
        let mut a = roots[r].clone();
        a.push(vocab[r][0].clone());
        fib.push(a);
    }
    Corpus { names, fib, depths }
}

fn prefixes(name: &Name) -> Vec<Name> {
    (1..=name.len()).map(|j| name[..j].to_vec()).collect()
}
fn slash(p: &[String]) -> Vec<u8> {
    let mut s = Vec::new();
    for c in p {
        s.push(b'/');
        s.extend_from_slice(c.as_bytes());
    }
    s
}

// ---------- Blur structures over a name's prefix set ----------
const CLAMP: usize = 12; // deepest level encoded (raised from 8 to fit deep names)

// per-level k schedule for a named allocation policy, given importance weights.
fn k_schedule(alloc: &str, level: usize, importance: &[f64]) -> usize {
    match alloc {
        "full" => 4,
        "head3" => {
            if level <= 3 {
                4
            } else {
                0
            }
        }
        "graduated" => match level {
            1..=3 => 4,
            4..=7 => 3,
            _ => 2,
        },
        "importance" => {
            // 1..4 bits by the level's measured importance (registration frequency), floor 1.
            let w = importance
                .get(level.saturating_sub(1))
                .copied()
                .unwrap_or(0.0);
            (1.0 + 3.0 * w).round().clamp(1.0, 4.0) as usize
        }
        _ => 4,
    }
}

// Bloom Blur: OR of per-level k bit-positions into m bits. Returns (frame bits as u128 for m<=128).
fn bloom_build(name: &Name, m: u64, alloc: &str, imp: &[f64]) -> u128 {
    let mut f = 0u128;
    for (j, pfx) in prefixes(name).iter().enumerate().take(CLAMP) {
        let k = k_schedule(alloc, j + 1, imp);
        for i in 0..k {
            f |= 1u128 << (hh(&slash(pfx), 0x100 + i as u64) % m);
        }
    }
    f
}
fn bloom_mask(pfx: &[String], m: u64, k: usize) -> u128 {
    let mut mm = 0u128;
    for i in 0..k {
        mm |= 1u128 << (hh(&slash(pfx), 0x100 + i as u64) % m);
    }
    mm
}

// GCS Blur: Golomb-coded set of the prefix hashes. Returns (encoded bits, sorted member hashes, U).
fn gcs_build(name: &Name, mgol: u64) -> (u64, Vec<u64>, u64) {
    let pfx: Vec<Name> = prefixes(name).into_iter().take(CLAMP).collect();
    let nn = pfx.len() as u64;
    let u = nn * mgol;
    let mut hs: Vec<u64> = pfx.iter().map(|p| hh(&slash(p), 0xC5) % u).collect();
    hs.sort_unstable();
    hs.dedup();
    let b = (63 - mgol.leading_zeros()) as u64;
    let cutoff = (1u64 << (b + 1)) - mgol;
    let mut bits = 4;
    let mut prev = 0u64;
    for &x in &hs {
        let (q, r) = (x - prev, (x - prev) % mgol);
        bits += (q / mgol + 1) + if r < cutoff { b } else { b + 1 };
        prev = x;
    }
    (bits, hs, u)
}

// xor8 filter of the prefix set: 8-bit fingerprints, 3-wise, peeled construction.
// Returns (table, cap, winning_seed) so the query can reproduce the exact slot mapping.
fn xor_pos(key: u64, i: usize, seed: u64, block: usize) -> usize {
    i * block + (hh(&key.to_le_bytes(), seed ^ (i as u64 * 0xabcd)) % block as u64) as usize
}
fn xor_build(name: &Name) -> Option<(Vec<u8>, usize, u64)> {
    let keys: Vec<u64> = prefixes(name)
        .iter()
        .take(CLAMP)
        .map(|p| hh(&slash(p), 0x777))
        .collect();
    let n = keys.len();
    let block = ((1.23 * n as f64) as usize + 32).max(3) / 3 + 1;
    let cap = block * 3;
    for seed in 0..128u64 {
        let mut sets: Vec<Vec<usize>> = vec![Vec::new(); cap];
        for (ki, &k) in keys.iter().enumerate() {
            for i in 0..3 {
                sets[xor_pos(k, i, seed, block)].push(ki);
            }
        }
        let mut stack: Vec<(usize, usize)> = Vec::new();
        let mut queue: Vec<usize> = (0..cap).filter(|&s| sets[s].len() == 1).collect();
        let mut removed = vec![false; n];
        while let Some(s) = queue.pop() {
            let live: Vec<usize> = sets[s].iter().copied().filter(|&ki| !removed[ki]).collect();
            if live.len() != 1 {
                continue;
            }
            let ki = live[0];
            removed[ki] = true;
            stack.push((ki, s));
            for i in 0..3 {
                let s2 = xor_pos(keys[ki], i, seed, block);
                if sets[s2].iter().copied().filter(|&x| !removed[x]).count() == 1 {
                    queue.push(s2);
                }
            }
        }
        if stack.len() != n {
            continue;
        }
        let mut table = vec![0u8; cap];
        for &(ki, s) in stack.iter().rev() {
            let fp = (hh(&keys[ki].to_le_bytes(), 0x5eed) & 0xff) as u8;
            let x: u8 = (0..3)
                .map(|i| xor_pos(keys[ki], i, seed, block))
                .filter(|&p| p != s)
                .fold(fp, |a, p| a ^ table[p]);
            table[s] = x;
        }
        return Some((table, cap, seed));
    }
    None
}
fn xor_contains(table: &[u8], cap: usize, seed: u64, key: u64) -> bool {
    let block = cap / 3;
    let fp = (hh(&key.to_le_bytes(), 0x5eed) & 0xff) as u8;
    // membership iff fingerprint == XOR of the three slots (fold from 0, not fp).
    let x = (0..3).fold(0u8, |a, i| a ^ table[xor_pos(key, i, seed, block)]);
    x == fp
}

fn ensure_dir(p: &str) {
    let _ = std::fs::create_dir_all(p);
}

fn main() {
    let dir = "docs/data/name-filter";
    ensure_dir(dir);
    let corpus = gen_corpus(1, 20_000);
    let dmode = {
        let mut h = HashMap::new();
        for &d in &corpus.depths {
            *h.entry(d).or_insert(0u32) += 1;
        }
        let (mut best, mut bc) = (0, 0);
        for (d, c) in h {
            if c > bc {
                bc = c;
                best = d;
            }
        }
        best
    };
    let avg_depth = corpus.depths.iter().sum::<usize>() as f64 / corpus.depths.len() as f64;
    println!(
        "Corpus: {} names, avg depth {:.1}, modal depth {}, {} FIB prefixes.",
        corpus.names.len(),
        avg_depth,
        dmode,
        corpus.fib.len()
    );

    // Importance profile = registration frequency at each depth (calibration pass).
    let mut imp = vec![0.0f64; CLAMP];
    for f in &corpus.fib {
        for j in 0..f.len().min(CLAMP) {
            imp[j] += 1.0;
        }
    }
    let maxi = imp.iter().cloned().fold(0.0, f64::max).max(1.0);
    for x in imp.iter_mut() {
        *x /= maxi;
    }

    // ---------- Sweep 1: DEPTH (FP vs name depth, full Bloom m=94) ----------
    {
        let mut w = std::fs::File::create(format!("{dir}/depth.csv")).unwrap();
        writeln!(w, "depth,bits,per_mask_fp").unwrap();
        let m = 94u64;
        // bucket corpus names by depth
        let mut by_depth: HashMap<usize, Vec<&Name>> = HashMap::new();
        for nm in &corpus.names {
            by_depth.entry(nm.len()).or_default().push(nm);
        }
        let mut depths: Vec<usize> = by_depth.keys().copied().collect();
        depths.sort_unstable();
        for d in depths {
            let names = &by_depth[&d];
            let (mut bits, mut fp, mut trials) = (0u64, 0u64, 0u64);
            for (t, nm) in names.iter().enumerate().take(4000) {
                let f = bloom_build(nm, m, "full", &imp);
                bits += f.count_ones() as u64;
                // disjoint registration (another root's depth-3 prefix)
                let dr = &corpus.fib[(t + 7) % corpus.fib.len()];
                if !nm.starts_with(&dr[..dr.len().min(nm.len())]) {
                    let mask = bloom_mask(dr, m, 4);
                    if f & mask == mask {
                        fp += 1;
                    }
                    trials += 1;
                }
            }
            let n = names.len().min(4000) as u64;
            writeln!(
                w,
                "{d},{:.2},{:.5}",
                bits as f64 / n.max(1) as f64,
                fp as f64 / trials.max(1) as f64
            )
            .unwrap();
        }
        println!("wrote depth.csv");
    }

    // ---------- Sweep 2: ALLOCATION (FN safety + FP + bits) ----------
    {
        let mut w = std::fs::File::create(format!("{dir}/allocation.csv")).unwrap();
        writeln!(w, "alloc,avg_bits,fn_rate,fp_rate").unwrap();
        let m = 94u64;
        for alloc in ["full", "head3", "graduated", "importance"] {
            let (mut bits, mut fnn, mut fntot, mut fp, mut fptot) = (0u64, 0u64, 0u64, 0u64, 0u64);
            for (t, nm) in corpus.names.iter().enumerate().take(8000) {
                let f = bloom_build(nm, m, alloc, &imp);
                bits += f.count_ones() as u64;
                // FN: query a GENUINE prefix at a mid depth (4..min(depth,CLAMP)). Must match.
                let depth = nm.len().min(CLAMP);
                if depth >= 4 {
                    let jr = 4 + (t % (depth - 3).max(1));
                    let jr = jr.min(depth);
                    let k = k_schedule(alloc, jr, &imp);
                    fntot += 1;
                    if k == 0 {
                        fnn += 1; // level not encoded ⇒ receiver at this depth misses it
                    } else {
                        let mask = bloom_mask(&nm[..jr], m, k);
                        if f & mask != mask {
                            fnn += 1;
                        }
                    }
                }
                // FP: a disjoint FIB prefix (different root).
                let dr = &corpus.fib[(t + 5) % corpus.fib.len()];
                if !nm.starts_with(&dr[..dr.len().min(nm.len())]) {
                    let k = k_schedule(alloc, dr.len(), &imp).max(1);
                    let mask = bloom_mask(dr, m, k);
                    fptot += 1;
                    if f & mask == mask {
                        fp += 1;
                    }
                }
            }
            let n = corpus.names.len().min(8000) as u64;
            writeln!(
                w,
                "{alloc},{:.2},{:.5},{:.5}",
                bits as f64 / n as f64,
                fnn as f64 / fntot.max(1) as f64,
                fp as f64 / fptot.max(1) as f64
            )
            .unwrap();
        }
        println!("wrote allocation.csv");
    }

    // ---------- Sweep 3: STRUCTURE (Bloom vs GCS vs xor: bits + FP + FN) ----------
    {
        let mut w = std::fs::File::create(format!("{dir}/structure.csv")).unwrap();
        writeln!(w, "structure,target_fp,avg_bits,measured_fp,measured_fn").unwrap();
        for (tgt, mgol, k, m) in [("1pct", 100u64, 7usize, 128u64), ("0.1pct", 1000, 10, 256)] {
            // Bloom at optimal k, m sized to ~ same target.
            let (mut b_bits, mut b_fp, mut b_fpt, mut b_fn, mut b_fnt) =
                (0u64, 0u64, 0u64, 0u64, 0u64);
            let (mut g_bits, mut g_fp, mut g_fpt, mut g_fn, mut g_fnt) =
                (0u64, 0u64, 0u64, 0u64, 0u64);
            let (mut x_bits, mut x_fp, mut x_fpt, mut x_fn, mut x_fnt, mut x_ok) =
                (0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
            for (t, nm) in corpus.names.iter().enumerate().take(6000) {
                // Bloom (m bits, k) — but m as u128 cap 128; use m up to 128 for 1pct, 256 needs bigger -> use bit array.
                // Use a Vec<bool> bloom to allow m>128.
                let mut bf = vec![false; m as usize];
                for pfx in prefixes(nm).iter().take(CLAMP) {
                    for i in 0..k {
                        bf[(hh(&slash(pfx), 0x100 + i as u64) % m) as usize] = true;
                    }
                }
                b_bits += m; // fixed field
                // GCS
                let (gb, ghs, gu) = gcs_build(nm, mgol);
                g_bits += gb;
                // xor
                let xr = xor_build(nm);
                if let Some((_, cap, _)) = xr {
                    x_bits += (cap * 8) as u64;
                    x_ok += 1;
                }

                // genuine prefix (root, depth 3) — must match (FN check)
                let gp = &nm[..3.min(nm.len())];
                let gpk = hh(&slash(gp), 0x777);
                b_fnt += 1;
                if !(0..k).all(|i| bf[(hh(&slash(gp), 0x100 + i as u64) % m) as usize]) {
                    b_fn += 1;
                }
                g_fnt += 1;
                if ghs.binary_search(&(hh(&slash(gp), 0xC5) % gu)).is_err() {
                    g_fn += 1;
                }
                if let Some((ref tbl, cap, sd)) = xr {
                    x_fnt += 1;
                    if !xor_contains(tbl, cap, sd, gpk) {
                        x_fn += 1;
                    }
                }
                // disjoint prefix (FP check)
                let dr = &corpus.fib[(t + 11) % corpus.fib.len()];
                if !nm.starts_with(&dr[..dr.len().min(nm.len())]) {
                    let drk = hh(&slash(dr), 0x777);
                    b_fpt += 1;
                    if (0..k).all(|i| bf[(hh(&slash(dr), 0x100 + i as u64) % m) as usize]) {
                        b_fp += 1;
                    }
                    g_fpt += 1;
                    if ghs.binary_search(&(hh(&slash(dr), 0xC5) % gu)).is_ok() {
                        g_fp += 1;
                    }
                    if let Some((ref tbl, cap, sd)) = xr {
                        x_fpt += 1;
                        if xor_contains(tbl, cap, sd, drk) {
                            x_fp += 1;
                        }
                    }
                }
            }
            let n = corpus.names.len().min(6000) as u64;
            let np = CLAMP as u64; // ~prefixes per name
            writeln!(
                w,
                "bloom,{tgt},{:.2},{:.5},{:.5}",
                b_bits as f64 / n as f64 / np as f64,
                b_fp as f64 / b_fpt.max(1) as f64,
                b_fn as f64 / b_fnt.max(1) as f64
            )
            .unwrap();
            writeln!(
                w,
                "gcs,{tgt},{:.2},{:.5},{:.5}",
                g_bits as f64 / n as f64 / np as f64,
                g_fp as f64 / g_fpt.max(1) as f64,
                g_fn as f64 / g_fnt.max(1) as f64
            )
            .unwrap();
            writeln!(
                w,
                "xor,{tgt},{:.2},{:.5},{:.5}",
                x_bits as f64 / x_ok.max(1) as f64 / np as f64,
                x_fp as f64 / x_fpt.max(1) as f64,
                x_fn as f64 / x_fnt.max(1) as f64
            )
            .unwrap();
        }
        println!("wrote structure.csv");
    }

    println!("wrote structure.csv");

    // ---------- Traced pass: real spans on the filter ops → per-op latency (monotonic) +
    //            the actual ndn-observability OTLP-in-Data pipeline (#107). ----------
    use ndn_observability::{NdnObservabilityLayer, SpanPublisher, SpanRetention, ratio_sampler};
    use ndn_packet::Name as NdnName;
    use ndn_packet::NameComponent;
    let publisher = SpanPublisher::new(
        NdnName::from_components([
            NameComponent::generic(bytes::Bytes::from_static(b"localhost")),
            NameComponent::generic(bytes::Bytes::from_static(b"named-radio")),
            NameComponent::generic(bytes::Bytes::from_static(b"mac")),
            NameComponent::generic(bytes::Bytes::from_static(b"filter-eval")),
        ]),
        SpanRetention::default(),
    );
    let otlp = NdnObservabilityLayer::new(std::sync::Arc::clone(&publisher), ratio_sampler(1.0));
    let lat = LatLayer::default();
    {
        let _g = tracing::subscriber::set_default(
            tracing_subscriber::registry().with(lat.clone()).with(otlp),
        );
        let mut r = Rng::new(99);
        for _ in 0..4000 {
            let nm = &corpus.names[r.u(corpus.names.len() as u64) as usize];
            {
                let _s = tracing::info_span!(target: "mac.blur", "blur_build_bloom").entered();
                std::hint::black_box(bloom_build(nm, 94, "importance", &imp));
            }
            {
                let _s = tracing::info_span!(target: "mac.blur", "blur_build_gcs").entered();
                std::hint::black_box(gcs_build(nm, 100));
            }
            {
                let _s = tracing::info_span!(target: "mac.blur", "blur_build_xor").entered();
                std::hint::black_box(xor_build(nm));
            }
            let f = bloom_build(nm, 94, "importance", &imp);
            {
                let _s = tracing::info_span!(target: "mac.query", "blur_query_fib").entered();
                for fp in &corpus.fib {
                    std::hint::black_box(f & bloom_mask(fp, 94, 4));
                }
            }
        }
    }
    {
        let mut w = std::fs::File::create(format!("{dir}/latency.csv")).unwrap();
        writeln!(w, "op,count,mean_ns,p50_ns,p99_ns").unwrap();
        for (name, v) in lat.d.lock().unwrap().iter() {
            let mut v = v.clone();
            v.sort_unstable();
            let mean = v.iter().sum::<u64>() / v.len().max(1) as u64;
            let p = |q: f64| v[((v.len() as f64 * q) as usize).min(v.len() - 1)];
            writeln!(w, "{name},{},{mean},{},{}", v.len(), p(0.5), p(0.99)).unwrap();
        }
        println!("wrote latency.csv (via tracing spans, monotonic clock)");
    }

    // Drain the OTLP-in-Data spans the NdnObservabilityLayer produced (each is a Data packet whose
    // content is an OTLP trace.proto Span). Record a sample + the count as evidence the real
    // pipeline ran on the filter ops.
    {
        let total = publisher.len();
        let mut w = std::fs::File::create(format!("{dir}/traces.ndjson")).unwrap();
        let ids = publisher.recent_span_ids(20);
        for (trace, span) in &ids {
            if let Some(wire) = publisher.lookup(trace, span) {
                // wire is the Data packet; its content is an OTLP trace.proto Span (0x0A 0x10 = trace_id).
                writeln!(
                    w,
                    "{{\"trace\":\"{}\",\"span\":\"{}\",\"data_wire_bytes\":{}}}",
                    hex(trace),
                    hex(span),
                    wire.len()
                )
                .unwrap();
            }
        }
        println!(
            "OTLP-in-Data: {total} spans produced through ndn-observability; sampled 20 → traces.ndjson"
        );
    }
    println!("Sweeps done. ID sweep is id_deconflict.rs; all data under {dir}/.");
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
