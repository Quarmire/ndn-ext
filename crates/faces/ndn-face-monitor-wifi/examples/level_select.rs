//! Level selection vs full encoding, at both depth profiles — measured.
//! "full"    = insert every prefix level (clamped at MAX_DEPTH=8), today's behaviour.
//! "head=C"  = insert only the shallow C routing levels; the full name rides a separate exact-match
//!             fingerprint (not shown here — its FP is ~2^-w for a w-bit fingerprint).
//! The claim to test: head=C makes the in-frame FIB false-positive rate INDEPENDENT of name depth.
//! `cargo run --example level_select --release -p ndn-face-monitor-wifi --features libusb-backend`

fn main() {
    use ndn_face_monitor_wifi::{OPEN_GROUP_KEY, PrefixFilter};
    let key = &OPEN_GROUP_KEY.0;

    fn comp(salt: u32, c: usize) -> String {
        let v = salt.wrapping_mul(2654435761).wrapping_add(c as u32 * 40503);
        format!("{:04x}", v & 0xffff)
    }
    // The j-th prefix (levels 1..=j) of the depth-d name for `salt`, as slash bytes.
    fn prefix(d: usize, salt: u32, j: usize) -> Vec<u8> {
        let mut s = Vec::new();
        for c in 0..j.min(d) {
            s.push(b'/');
            s.extend_from_slice(comp(salt, c).as_bytes());
        }
        s
    }
    fn full_name(d: usize, salt: u32) -> Vec<u8> {
        prefix(d, salt, d)
    }
    // A disjoint depth-3 FIB registration (never a real prefix of the traffic names).
    fn reg(salt: u32) -> Vec<u8> {
        let mut s = Vec::new();
        for c in 0..3 {
            let v = 0xbeef_0000u32 ^ salt.wrapping_mul(2246822519).wrapping_add(c as u32 * 7919);
            s.push(b'/');
            s.extend_from_slice(format!("{:04x}", v & 0xffff).as_bytes());
        }
        s
    }
    fn or_into(acc: &mut [u8; 12], m: &PrefixFilter) {
        for (a, b) in acc.iter_mut().zip(m.0.iter()) {
            *a |= *b;
        }
    }
    fn bits(f: &[u8; 12]) -> u32 {
        f.iter().map(|b| b.count_ones()).sum()
    }

    const TRIALS: u32 = 200_000;
    // Build the frame filter two ways and measure per-mask FIB FP + union over E=32.
    let measure = |d: usize, mode: &str, c: usize| -> (f64, f64, f64) {
        let (mut fp, mut bits_tot) = (0u64, 0u64);
        for t in 0..TRIALS {
            let frame: [u8; 12] = if mode == "full" {
                let mut f = PrefixFilter::new();
                f.insert_name(key, &full_name(d, t));
                f.0
            } else {
                // head=C: OR the masks for the first C prefix levels only.
                let mut acc = [0u8; 12];
                for j in 1..=c.min(d) {
                    or_into(&mut acc, &PrefixFilter::mask_for(key, &prefix(d, t, j)));
                }
                acc
            };
            bits_tot += bits(&frame) as u64;
            let m = PrefixFilter::mask_for(key, &reg(t));
            if PrefixFilter::from_wire(frame).may_match(&m) {
                fp += 1;
            }
        }
        let p = fp as f64 / TRIALS as f64;
        (bits_tot as f64 / TRIALS as f64, p * 100.0, (1.0 - (1.0 - p).powi(32)) * 100.0)
    };

    println!("m=94, k=4. per-mask FIB FP over {TRIALS} disjoint depth-3 registrations.\n");
    println!("{:<18} {:<10} {:>9} {:>13} {:>13}", "profile", "encoding", "avg bits", "per-mask FP", "union E=32");
    for (label, d) in [("shallow (ours) d=2", 2usize), ("deep (NDN) d=10", 10)] {
        let (b0, p0, u0) = measure(d, "full", 0);
        println!("{:<18} {:<10} {:>9.1} {:>12.4}% {:>12.2}%", label, "full", b0, p0, u0);
        for c in [3usize, 4] {
            let (b, p, u) = measure(d, "head", c);
            println!("{:<18} {:<10} {:>9.1} {:>12.4}% {:>12.2}%", "", format!("head={c}"), b, p, u);
        }
    }
    println!("\nexact-match fingerprint (PIT-exact + CS): FP = 2^-w  →  16b: 0.0015%   24b: 6e-6%   32b: 2.3e-8%");
}
