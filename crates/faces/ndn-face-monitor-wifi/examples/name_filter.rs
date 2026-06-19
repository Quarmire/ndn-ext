//! DCNLA name-group hardware RX filter demo.
//!
//! Programs the chip to accept only frames whose BSSID (addr3) equals the
//! name-group hash of a prefix (`name_group_mac`), so the silicon drops every
//! other name-group before it reaches the host — "the name is the address."
//! Then listens and counts frames carrying the magic `DCNLA-TEST` marker.
//!
//! Usage: `name_filter <prefix> [secs] [channel]`
//!   env NAME_FILTER_OFF=1 → stay promiscuous (baseline; accept all groups).
//!
//! Validate against a peer that injects to a chosen BSSID (e.g. the OPi
//! `inject_bssid.pl <bssid_hex> <n>`): a subscribed-group inject is received,
//! an unsubscribed-group inject is dropped in hardware (count ~0), while the
//! promiscuous baseline receives both.
#[cfg(feature = "libusb-backend")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use ndn_face_monitor_wifi::{LibUsbRtl88xxBackend, name_group_mac};

    // argv[1] may be a comma-separated list of prefixes (multi-prefix DCNLA).
    let prefixes_arg = std::env::args().nth(1).unwrap_or_else(|| "/sensors/temp".to_string());
    let secs: u64 = std::env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(10);
    let ch: u8 = std::env::args().nth(3).and_then(|s| s.parse().ok()).unwrap_or(149);

    let prefixes: Vec<&str> = prefixes_arg.split(',').collect();
    let groups: Vec<[u8; 6]> = prefixes.iter().map(|p| name_group_mac(p.as_bytes())).collect();
    let fmt = |m: &[u8; 6]| m.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":");
    for (p, g) in prefixes.iter().zip(&groups) {
        println!("prefix {p:?} → name-group MAC {}", fmt(g));
    }

    let b = LibUsbRtl88xxBackend::open_monitor(ch)?;
    if std::env::var("NAME_FILTER_OFF").is_ok() {
        b.clear_name_group_filter()?;
        println!("RX = promiscuous monitor (no name filter) — accepts ALL groups");
    } else if groups.len() == 1 {
        b.set_name_group_filter(groups[0])?;
        let (rcr, bssid, msr) = b.name_group_filter_state()?;
        println!("RX = DCNLA single-group filter (BSSID match) — drops other groups in HW");
        println!("     readback: RCR={rcr:#010x} BSSID={} MSR={msr} (1=AdHoc)", fmt(&bssid));
    } else {
        b.set_name_group_filter_multi(&groups)?;
        let (rcr, _, msr) = b.name_group_filter_state()?;
        println!(
            "RX = DCNLA multi-prefix ({} name-groups): HW multicast-narrow (AM) + SW set-match",
            groups.len()
        );
        println!("     readback: RCR={rcr:#010x} (AM bit2={}) MSR={msr}", (rcr >> 2) & 1);
    }

    println!("listening on ch{ch} for {secs}s…");
    let magic = b"DCNLA-TEST";
    let multi = groups.len() > 1 && std::env::var("NAME_FILTER_OFF").is_err();
    let t0 = std::time::Instant::now();
    let (mut hits, mut subscribed) = (0u32, 0u32);
    while t0.elapsed().as_secs() < secs {
        if let Some(f) = b.recv_raw(500)?
            && f.windows(magic.len()).any(|w| w == magic)
        {
            hits += 1;
            // Multi-prefix SW set-match over the HW multicast-narrowed stream:
            // does the frame carry one of the subscribed name-group MACs?
            if groups.iter().any(|g| f.windows(6).any(|w| w == g)) {
                subscribed += 1;
            }
        }
    }
    if multi {
        println!(
            "ch{ch}: {hits} multicast marker frames via HW (AM), {subscribed} in a subscribed \
             name-group (SW set); {} other-multicast dropped by SW",
            hits - subscribed
        );
    } else {
        println!("ch{ch}: {hits} frames carrying the DCNLA marker");
    }
    Ok(())
}

#[cfg(not(feature = "libusb-backend"))]
fn main() {
    eprintln!("rebuild with `--features libusb-backend` (needs an RTL8812EU dongle)");
}
