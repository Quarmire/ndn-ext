//! Probe a radio's absolute-dBm power control and, optionally, drive it.
//!
//! Verifies the discovery half of the generic power path on real hardware: which
//! mechanism was found, what range it claims, and what the radio reports applying.
//!
//! ```text
//! dbm_probe <iface>            # report what was discovered
//! dbm_probe <iface> <dBm>...   # discover, then set each power in turn
//! ```

use ndn_face_monitor_wifi::dbm_power::Mac80211Knobs;
use ndn_face_monitor_wifi::RadioKnobs;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let Some(iface) = args.get(1) else {
        eprintln!("usage: dbm_probe <iface> [dBm ...]");
        std::process::exit(2);
    };

    let knobs = Mac80211Knobs::discover(iface);
    println!("iface     : {iface}");
    println!("mechanism : {}", knobs.mechanism_name());
    match knobs.tx_power_range() {
        Some(r) => println!("range     : {}..={} dBm (span {} dB)", r.min, r.max, r.span_db()),
        None => println!("range     : none — no absolute control found (index-only radio)"),
    }

    for a in args.iter().skip(2) {
        let want: i8 = match a.parse() {
            Ok(v) => v,
            Err(_) => {
                eprintln!("skipping non-numeric {a:?}");
                continue;
            }
        };
        match knobs.set_tx_power_dbm(want) {
            Ok(applied) if applied == want => println!("set {want:>3} dBm -> applied {applied} dBm"),
            Ok(applied) => println!("set {want:>3} dBm -> applied {applied} dBm  (clamped)"),
            Err(e) => println!("set {want:>3} dBm -> FAILED: {e}"),
        }
    }
}
