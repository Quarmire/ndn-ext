//! DoS validation — the §3.2 cascade under attack, quantified. Runs the three floods the doctrine
//! must survive and reports, for each, how many frames reach the expensive operation (verify) and the
//! victim's CPU cost with the cascade vs. without any defense (every frame verified).
//!
//! Run: `cargo run -p ndn-radio-cognition --example dos_validation`

use ndn_radio_cognition::dos::{DosGate, FrameKind, Verdict};

const WANTED: u64 = 0x1111; // a group the victim subscribes to
const OTHER: u64 = 0x2222; // a group it does not
const FRAMES: u64 = 100_000; // the attacker's budget

// Relative CPU cost per cascade stage (verify dominates — that is the whole point of gating it).
const C_FILTER: u64 = 1;
const C_PIT: u64 = 2;
const C_RATELIMIT: u64 = 1;
const C_VERIFY: u64 = 100;

fn cost(v: Verdict) -> u64 {
    match v {
        Verdict::DroppedAtFilter => C_FILTER,
        Verdict::DroppedAtPit => C_FILTER + C_PIT,
        Verdict::DroppedAtRateLimit => C_FILTER + C_RATELIMIT,
        Verdict::ReachesVerify => C_FILTER + C_PIT + C_VERIFY,
    }
}

fn report(name: &str, verifies: u64, victim_cost: u64) {
    let no_defense = FRAMES * (C_FILTER + C_PIT + C_VERIFY); // if every frame were verified
    println!(
        "  {name:<34} {verifies:>8}   {:>10}   {:>10}   {:>6.0}×",
        victim_cost,
        no_defense,
        no_defense as f64 / victim_cost.max(1) as f64
    );
}

fn main() {
    println!("DoS validation — {FRAMES} attacker frames through the §3.2 cascade\n");
    println!(
        "  attack                              verifies   victim cost   no-defense   reduction"
    );

    // 1. Out-of-group flood: frames for a group the victim never registered.
    {
        let mut gate = DosGate::new([WANTED], 8.0, 0.0);
        let (mut verifies, mut c) = (0u64, 0u64);
        for i in 0..FRAMES {
            let v = gate.admit(FrameKind::Data, OTHER, i, [0x02, 1, 1, 1, 1, 1], 0);
            c += cost(v);
            if v == Verdict::ReachesVerify {
                verifies += 1;
            }
        }
        report("out-of-group Data flood", verifies, c);
    }

    // 2. Fake-Data flood: in-group, but for names the victim never requested (no PIT breadcrumb).
    {
        let mut gate = DosGate::new([WANTED], 8.0, 0.0);
        let (mut verifies, mut c) = (0u64, 0u64);
        for i in 0..FRAMES {
            let v = gate.admit(
                FrameKind::Data,
                WANTED,
                0xdead_0000 + i,
                [0x02, 1, 1, 1, 1, 1],
                0,
            );
            c += cost(v);
            if v == Verdict::ReachesVerify {
                verifies += 1;
            }
        }
        report("fake-Data flood (in-group)", verifies, c);
    }

    // 3. Interest flood from ONE source: throttled to its per-nonce bucket.
    {
        let mut gate = DosGate::new([WANTED], 8.0, 0.0); // burst 8, no refill (all at t=0)
        let (mut verifies, mut c) = (0u64, 0u64);
        for i in 0..FRAMES {
            let v = gate.admit(FrameKind::Interest, WANTED, i, [0x02, 3, 3, 3, 3, 3], 0);
            c += cost(v);
            if v == Verdict::ReachesVerify {
                verifies += 1;
            }
        }
        report("Interest flood (1 source)", verifies, c);
    }

    // 4. Distributed Interest flood: a fresh nonce every 8 frames — the residual, but attributed.
    {
        let mut gate = DosGate::new([WANTED], 8.0, 0.0);
        let (mut verifies, mut c) = (0u64, 0u64);
        for i in 0..FRAMES {
            let s = (i / 8) as u32; // rotate nonce every burst to defeat the per-source cap
            let src = [0x02, s as u8, (s >> 8) as u8, (s >> 16) as u8, 0, 0];
            let v = gate.admit(FrameKind::Interest, WANTED, i, src, 0);
            c += cost(v);
            if v == Verdict::ReachesVerify {
                verifies += 1;
            }
        }
        report("Interest flood (distributed nonces)", verifies, c);
        println!(
            "  ↳ {} distinct nonces minted, yet the per-PREFIX aggregate limit still bounds the total.",
            gate.distinct_sources()
        );
    }

    println!(
        "\nTakeaway: the two floods that try to force verify (out-of-group, fake-Data) reach it ZERO"
    );
    println!(
        "times — dropped at the filter / PIT gate before the expensive op. Interest flooding is the"
    );
    println!(
        "residual, and the PAIRED limits hold it: per-source (nonce) stops one flooder, per-prefix"
    );
    println!(
        "(aggregate) stops a distributed one that rotates nonces — so even 12.5k nonces are bounded"
    );
    println!(
        "to the prefix budget, not 100k verifies. Keeping MACs would not help — MAC filters are"
    );
    println!("spoofable and broadcast bypasses them (doctrine §3.2).");
}
