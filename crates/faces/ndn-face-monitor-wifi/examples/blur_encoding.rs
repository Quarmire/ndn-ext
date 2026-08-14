//! Blur encodings compared on the axis that matters: FALSE NEGATIVES (safety) + FP + bits.
//! Deep names (depth 10) with shared heads (the realistic NDN case my earlier disjoint test hid).
//!  - full       : every level, k=4 (clamped at 8). Safe (no FN) but saturates → high FP on deep.
//!  - head3      : only levels 1..3, k=4. THE NAIVE ONE — blind past level 3.
//!  - graduated  : EVERY level kept, but k tapers by depth (mixed precision, the "quantize don't
//!                 truncate" idea). Head levels precise, deep levels coarse — but none dropped.
//! `cargo run --example blur_encoding --release -p ndn-face-monitor-wifi --features libusb-backend`

fn main() {
    use ndn_face_monitor_wifi::{OPEN_GROUP_KEY, tier0::positions};
    let key = &OPEN_GROUP_KEY.0;
    const CLAMP: usize = 8;

    // k per level (1-indexed) for each encoding; 0 = level not encoded.
    fn kj(mode: &str, level: usize) -> usize {
        match mode {
            "full" => 4,
            "head3" => if level <= 3 { 4 } else { 0 },
            // graduated: precise head, coarse tail, nothing blind.
            "graduated" => match level { 1..=3 => 4, 4..=6 => 3, _ => 2 },
            _ => 0,
        }
    }

    // A depth-d name under one of NHEADS shared roots (Zipf-ish: many names per popular head).
    const NHEADS: u32 = 8;
    fn prefix_at(salt: u32, depth: usize, j: usize) -> Vec<u8> {
        let mut s = Vec::new();
        for c in 0..j.min(depth) {
            s.push(b'/');
            // component 0 = shared head root (few distinct); deeper = high-entropy per-name.
            let v = if c == 0 { salt % NHEADS } else { salt.wrapping_mul(2654435761).wrapping_add(c as u32 * 40503) };
            s.extend_from_slice(format!("{:04x}", v & 0xffff).as_bytes());
        }
        s
    }
    // Set level-j bits (first kj positions) into a 94-bit frame.
    let set_level = |frame: &mut u128, name_salt: u32, d: usize, j: usize, k: usize| {
        let p = positions(key, &prefix_at(name_salt, d, j));
        for i in 0..k {
            *frame |= 1u128 << (p[i] as u32);
        }
    };
    let build = |mode: &str, salt: u32, d: usize| -> (u128, u32) {
        let mut f = 0u128;
        for j in 1..=d.min(CLAMP) {
            let k = kj(mode, j);
            set_level(&mut f, salt, d, j, k);
        }
        (f, f.count_ones())
    };
    // A registration's mask at depth r for this encoding (its own kj), over a given name.
    let mask_of = |mode: &str, salt: u32, d: usize, r: usize| -> Option<u128> {
        let k = kj(mode, r);
        if k == 0 { return None; } // level not encoded ⇒ receiver cannot use the Blur here
        let mut m = 0u128;
        let p = positions(key, &prefix_at(salt, d, r));
        for i in 0..k { m |= 1u128 << (p[i] as u32); }
        Some(m)
    };

    const TRIALS: u32 = 100_000;
    println!("Deep names d=10, {NHEADS} shared heads. FN = wanted frame MISSED (must be 0).\n");
    println!("{:<10} {:>5} {:>28} {:>16}", "encoding", "bits", "FALSE NEG @ genuine depth", "FP @ disjoint");
    println!("{:<10} {:>5} {:>7}{:>7}{:>7}{:>7} {:>8}{:>8}", "", "", "d=2", "d=4", "d=6", "d=8", "reg d=3", "reg d=6");
    for mode in ["full", "head3", "graduated"] {
        let mut bits_tot = 0u64;
        let mut fn_at = [0u64; 4];   // genuine-prefix registrations at depths 2,4,6,8
        let mut fp = [0u64; 2];      // disjoint registrations at depth 3, 6
        let depths = [2usize, 4, 6, 8];
        for t in 0..TRIALS {
            let (frame, b) = build(mode, t, 10);
            bits_tot += b as u64;
            // FN: register the frame's OWN prefix (genuinely wanted) at each depth.
            for (idx, &r) in depths.iter().enumerate() {
                match mask_of(mode, t, 10, r) {
                    Some(m) => { if frame & m != m { fn_at[idx] += 1; } }   // encoded but missed
                    None => { fn_at[idx] += 1; }                            // not encoded ⇒ can't match ⇒ miss
                }
            }
            // FP: a disjoint name's prefix (never a real prefix of this frame). The salt must differ
            // in the LOW 16 bits — those are the only bits the component formatter uses.
            let dsalt = t.wrapping_mul(40507).wrapping_add(1_234_567);
            for (idx, &r) in [3usize, 6].iter().enumerate() {
                if let Some(m) = mask_of(mode, dsalt, 10, r) {
                    if frame & m == m { fp[idx] += 1; }
                }
            }
        }
        let pct = |x: u64| x as f64 * 100.0 / TRIALS as f64;
        println!(
            "{:<10} {:>5.1} {:>6.1}%{:>6.1}%{:>6.1}%{:>6.1}% {:>7.3}%{:>7.3}%",
            mode, bits_tot as f64 / TRIALS as f64,
            pct(fn_at[0]), pct(fn_at[1]), pct(fn_at[2]), pct(fn_at[3]),
            pct(fp[0]), pct(fp[1])
        );
    }
    println!("\n(FN must be 0 everywhere — a nonzero column is a dropped wanted frame, i.e. the encoding is unsafe.)");
}
