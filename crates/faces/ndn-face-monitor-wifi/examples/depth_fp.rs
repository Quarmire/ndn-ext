//! How name DEPTH drives the in-frame filter — measured, not assumed.
//! For each transmitted name depth d: bits set in the 94-bit frame filter, the per-mask false
//! positive against disjoint registrations, and the union FP a receiver with E registrations sees.
//! `cargo run --example depth_fp --release -p ndn-face-monitor-wifi --features libusb-backend`

fn main() {
    use ndn_face_monitor_wifi::{OPEN_GROUP_KEY, PrefixFilter};
    let key = &OPEN_GROUP_KEY.0;

    // A depth-d name /c0/c1/.../c{d-1}, components salted so different depths aren't nested copies.
    fn name(d: usize, salt: u32) -> Vec<u8> {
        let mut s = Vec::new();
        for c in 0..d {
            s.push(b'/');
            let v = salt.wrapping_mul(2654435761).wrapping_add(c as u32 * 40503);
            s.extend_from_slice(format!("{:04x}", v & 0xffff).as_bytes());
        }
        s
    }
    // A disjoint registration prefix (never a real prefix of the above) at depth rd.
    fn reg(rd: usize, salt: u32) -> Vec<u8> {
        let mut s = Vec::new();
        for c in 0..rd {
            s.push(b'/');
            let v = 0xdead_0000u32 ^ salt.wrapping_mul(2246822519).wrapping_add(c as u32 * 7919);
            s.extend_from_slice(format!("{:04x}", v & 0xffff).as_bytes());
        }
        s
    }

    const TRIALS: u32 = 200_000;
    println!("m=94 bits, k=4.  Per-mask FP measured over {TRIALS} disjoint depth-3 registrations.");
    println!("{:>5} {:>10} {:>12} {:>14} {:>14} {:>14}", "depth", "bits set", "per-mask FP", "unionE=8", "unionE=32", "unionE=128");
    for d in [1usize, 2, 3, 4, 6, 8, 10, 12] {
        // Average bits set across many names of this depth.
        let mut bits_tot = 0u64;
        const NB: u32 = 2000;
        for s in 0..NB {
            let mut f = PrefixFilter::new();
            f.insert_name(key, &name(d, s));
            bits_tot += f.0.iter().map(|b| b.count_ones() as u64).sum::<u64>();
        }
        let bits = bits_tot as f64 / NB as f64;

        // Per-mask FP: build one frame filter, query many disjoint registrations.
        let mut fp = 0u64;
        for t in 0..TRIALS {
            let mut f = PrefixFilter::new();
            f.insert_name(key, &name(d, t));
            let m = PrefixFilter::mask_for(key, &reg(3, t));
            if f.may_match(&m) {
                fp += 1;
            }
        }
        let p = fp as f64 / TRIALS as f64;
        let union = |e: i32| (1.0 - (1.0 - p).powi(e)) * 100.0;
        println!(
            "{:>5} {:>10.1} {:>11.4}% {:>13.2}% {:>13.2}% {:>13.2}%",
            d, bits, p * 100.0, union(8), union(32), union(128)
        );
    }
}
