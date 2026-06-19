//! A/B the cognitive control loop against fixed-MCS "blast" baselines on the
//! optimand **airtime per satisfied Interest** — the number that answers "are we
//! more than wfb-ng?".
//!
//! Run: `cargo run -p ndn-face-monitor-wifi --example airtime_ab`
//!
//! The adaptive arm drives the *real* `RadioControl`/`RadioPolicy`; the fixed arms
//! are single-MCS blasts. All arms share one TX template (80 MHz VHT + LDPC, 1 SS)
//! so the only difference is the rate decision. Lower airtime/satisfied = better.
//!
//! On-air version (manual, needs the OPi receiver): mount `RadioControl` on the
//! `radio-ping` TX via `LpLinkService::with_extra_feature` + `face_composed`, run
//! it vs `MonitorWifiFace::with_fixed_mcs`, and feed measured delivered-bytes /
//! airtime into the same `score_arm` scoring.

use ndn_face_monitor_wifi::measure::{Score, ab_sweep};

fn row(label: &str, s: &Score) -> String {
    format!(
        "{label:>10}  MCS{:<2} r{:<2} {:>9.0}  {:>6.1}%",
        s.mcs,
        s.redundancy,
        s.airtime_per_satisfied_us,
        s.delivery_frac * 100.0
    )
}

fn main() {
    let snrs: Vec<f32> = (5..=46).step_by(3).map(|x| x as f32).collect();
    let payload = 1000usize;
    let max_attempts = 8u32;
    let r = ab_sweep(&snrs, payload, max_attempts);

    println!("Airtime per satisfied Interest (µs) — lower is better");
    println!("payload {payload} B, ARQ ≤ {max_attempts} attempts, 80 MHz VHT+LDPC 1SS\n");
    println!(
        "{:>5}  | {:>26} | {:>26} | {:>26} | {:>26}",
        "SNR", "ADAPTIVE (the loop)", "fixed MCS9 (fast)", "fixed MCS5 (mid)", "fixed MCS1 (robust)"
    );
    println!("{}", "-".repeat(5 + 4 * 29));
    for (i, snr) in r.snrs.iter().enumerate() {
        println!(
            "{snr:>5.0}  |{} |{} |{} |{}",
            row("adapt", &r.adaptive[i]),
            row("mcs9", &r.fixed_high[i]),
            row("mcs5", &r.fixed_mid[i]),
            row("mcs1", &r.fixed_low[i]),
        );
    }

    let (ga, gh, gm, gl) = (
        r.geomean_adaptive(),
        r.geomean_fixed_high(),
        r.geomean_fixed_mid(),
        r.geomean_fixed_low(),
    );
    println!("\nGeomean airtime/satisfied across the sweep (µs):");
    println!("  ADAPTIVE  {ga:>9.0}");
    println!("  MCS9      {gh:>9.0}  ({:.2}× adaptive)", gh / ga);
    println!("  MCS5      {gm:>9.0}  ({:.2}× adaptive)", gm / ga);
    println!("  MCS1      {gl:>9.0}  ({:.2}× adaptive)", gl / ga);

    if r.adaptive_wins() {
        let worst_fixed = gh.min(gm).min(gl);
        println!(
            "\n✅ The loop beats every fixed blast: {:.2}× better than the best single fixed MCS.",
            worst_fixed / ga
        );
        println!("   That margin is the answer to \"more than wfb-ng?\" — a number, not a claim.");
    } else {
        println!("\n❌ A fixed MCS matched/beat the loop on this sweep — investigate the RSSI→MCS calibration.");
        std::process::exit(1);
    }
}
