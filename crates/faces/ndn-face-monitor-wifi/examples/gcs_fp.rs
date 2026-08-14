//! GCS (Golomb-Coded Set) vs Bloom for the Blur — fractional bits per prefix, measured.
//! Same hash, same name model. At a matched false-positive target, how many bits does each spend
//! per prefix, and how many prefix-levels fit in a fixed 94-bit field?
//! GCS floor ≈ log2(1/ε) bits/elem; Bloom ≈ 1.44·log2(1/ε). The ~30% gap is the "decimal bits" win.
//! `cargo run --example gcs_fp --release -p ndn-face-monitor-wifi --features libusb-backend`

fn h(bytes: &[u8], seed: u64) -> u64 {
    let mut x = 0xcbf2_9ce4_8422_2325u64 ^ seed;
    for &b in bytes {
        x = (x ^ b as u64).wrapping_mul(0x0000_0100_0000_01b3);
    }
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^= x >> 31;
    x
}

// The prefixes (levels 1..d) of a depth-d name under one of a few shared heads.
fn prefixes(salt: u32, d: usize) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut cur = Vec::new();
    for c in 0..d {
        cur.push(b'/');
        let v = if c == 0 { salt % 8 } else { salt.wrapping_mul(2654435761).wrapping_add(c as u32 * 40503) };
        cur.extend_from_slice(format!("{:04x}", v & 0xffff).as_bytes());
        out.push(cur.clone());
    }
    out
}

// Golomb code length (bits) for a gap, parameter M (truncated-binary remainder).
fn golomb_len(gap: u64, m: u64) -> u64 {
    let q = gap / m;
    let r = gap % m;
    let b = (63 - m.leading_zeros()) as u64; // floor(log2 M)
    let cutoff = (1u64 << (b + 1)) - m;
    let rem = if r < cutoff { b } else { b + 1 };
    (q + 1) + rem // unary quotient (q ones + terminating 0) + remainder
}

// Encode a prefix set as a GCS at rate M; return (bits, sorted member hashes over U = n*M).
fn gcs(set: &[Vec<u8>], m: u64) -> (u64, Vec<u64>, u64) {
    let n = set.len() as u64;
    let u = n * m;
    let mut hs: Vec<u64> = set.iter().map(|p| h(p, 0xC5) % u).collect();
    hs.sort_unstable();
    hs.dedup();
    let mut bits = 4; // ~4 bits to carry n (the element count), BIP-158 style
    let mut prev = 0u64;
    for &x in &hs {
        bits += golomb_len(x - prev, m);
        prev = x;
    }
    (bits, hs, u)
}

fn main() {
    const TRIALS: u32 = 200_000;
    println!("Same hash + name model. FN=0 for both (membership structures). d=8 (deep, clamped).\n");
    println!("{:<7} {:>12} {:>12} {:>10}   {:>12} {:>12} {:>10}", "target", "GCS b/elem", "GCS FP", "GCS/94b", "Bloom b/elem", "Bloom FP", "Bloom/94b");

    for (label, eps) in [("~1%", 0.01f64), ("~0.1%", 0.001)] {
        let d = 8usize;
        let m_gcs = (1.0 / eps).round() as u64;
        // Bloom sized to the same target: optimal k, m/n = k/ln2.
        let k = ((1.0f64 / eps).log2()).round().max(1.0) as usize;
        let bits_per_elem_bloom = (k as f64 / std::f64::consts::LN_2).round() as usize;
        let m_bloom = bits_per_elem_bloom * d;

        let (mut gcs_bits_tot, mut gcs_fp, mut bloom_fp) = (0u64, 0u64, 0u64);
        for t in 0..TRIALS {
            let set = prefixes(t, d);
            // GCS
            let (bits, hs, u) = gcs(&set, m_gcs);
            gcs_bits_tot += bits;
            // Bloom bit array
            let mut bf = vec![false; m_bloom];
            for p in &set {
                for i in 0..k {
                    bf[(h(p, i as u64) % m_bloom as u64) as usize] = true;
                }
            }
            // Query a disjoint prefix (different low bits ⇒ genuinely different components).
            let q = prefixes(t.wrapping_mul(40507).wrapping_add(1_234_567), 3).pop().unwrap();
            if hs.binary_search(&(h(&q, 0xC5) % u)).is_ok() {
                gcs_fp += 1;
            }
            if (0..k).all(|i| bf[(h(&q, i as u64) % m_bloom as u64) as usize]) {
                bloom_fp += 1;
            }
        }
        let gcs_be = gcs_bits_tot as f64 / (TRIALS as u64 * d as u64) as f64;
        let g_fp = gcs_fp as f64 * 100.0 / TRIALS as f64;
        let b_fp = bloom_fp as f64 * 100.0 / TRIALS as f64;
        println!(
            "{:<7} {:>11.2}b {:>11.3}% {:>9.1} {:>11}b {:>11.3}% {:>9.1}",
            label, gcs_be, g_fp, 94.0 / gcs_be,
            format!("{bits_per_elem_bloom}"), b_fp, 94.0 / bits_per_elem_bloom as f64
        );
    }
    println!("\n'/94b' = prefix-levels that fit in a 94-bit field at that FP. Higher = more crammed in.");
}
