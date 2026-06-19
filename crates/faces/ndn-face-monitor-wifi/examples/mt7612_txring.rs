//! MT7612U async TX-ring throughput: submit-ahead libusb URBs (pipelined) vs the
//! synchronous ~0.7ms/transfer ceiling. Measures payload goodput at a few sizes.
//! `--features libusb-backend --example mt7612_txring`
#[cfg(all(feature = "libusb-backend", target_os = "linux"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use ndn_face_monitor_wifi::{McsDescriptor, Mt7612uBackend};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    let dev = Arc::new(Mt7612uBackend::open()?);
    dev.bring_up()?;
    // NDN_TX_BAND=5g → clean 5GHz ch36 @ VHT80 (the throughput channel); else 2.4 ch6.
    let band = std::env::var("NDN_TX_BAND").unwrap_or_default();
    if band == "5g" {
        // The 5GHz/80MHz blob was captured as a ch6→ch36/80 *delta*, so establish
        // the ch6 (2.4GHz) baseline first, then apply the delta — on a cold device
        // there is no prior channel state for the delta to build on.
        dev.set_channel_ch6()?;
        dev.set_channel_5g80()?;
    } else {
        dev.set_channel_ch6()?;
    }
    dev.setup_monitor_rx()?;
    let chip = dev.chip_id()?;
    dev.pause_drain(true); // no sync RX while the ring owns libusb events
    std::thread::sleep(Duration::from_millis(100));

    // NDN_TX_EDCA=min strips AIFS/backoff — decomposes the ~280µs fixed overhead.
    if std::env::var("NDN_TX_EDCA").unwrap_or_default() == "min" {
        dev.set_edca_aggressive()?;
        println!("EDCA minimized (AIFSN=1, CW=0)");
    }
    let depth: usize = std::env::var("NDN_TX_DEPTH").ok().and_then(|s| s.parse().ok()).unwrap_or(256);
    let ring = dev.new_tx_ring(depth);
    // NDN_TX_RATE: ht7 | vht9 | vht9sgi | vht9_2ss | vht9_2ss_sgi (default ht7)
    println!("chip 0x{chip:04x}, async TX ring depth={depth}, band={}",
             if band == "5g" { "5GHz ch36/80" } else { "2.4 ch6/20" });
    let mk = |plen: usize| -> Vec<u8> {
        let mut f = vec![0x08u8, 0x00, 0x00, 0x00];
        f.extend_from_slice(&[0xff; 6]);
        f.extend_from_slice(&[0x02, 0x4e, 0x44, 0x4e, 0x00, 0x01]);
        f.extend_from_slice(&[0xff; 6]);
        f.extend_from_slice(&[0x00, 0x00]);
        f.extend_from_slice(&[0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x86, 0x24]);
        f.extend_from_slice(&vec![0xA5u8; plen]);
        f
    };

    // Single-MPDU ceiling sweep: each rate × frame size, all in one device session.
    // 1SS rates first, then enable the 2nd TX chain (0x820=0x31) for the 2SS rates.
    // Frame sizes go to ~4090B (the 12-bit TXWI len_ctl max) to amortize the fixed
    // ~283µs/transfer overhead as far as a single MPDU can.
    let sgi = |m: McsDescriptor| McsDescriptor { short_gi: true, ..m };
    let rates: &[(&str, McsDescriptor, bool)] = &[
        ("vht9-1ss     ", McsDescriptor::vht(9), false),
        ("vht9-1ss-sgi ", sgi(McsDescriptor::vht(9)), false),
        ("vht9-2ss     ", McsDescriptor::vht_2ss(9), true),
        ("vht9-2ss-sgi ", sgi(McsDescriptor::vht_2ss(9)), true),
    ];
    let n = 12000usize;
    let mut chains_2ss = false;
    for (label, mcs, two_ss) in rates {
        if *two_ss && !chains_2ss {
            dev.set_tx_chains(true)?;
            chains_2ss = true;
            std::thread::sleep(Duration::from_millis(50));
        }
        // ~5700B is the on-air-verified single-MPDU TX cap (6000B+ dropped by the
        // device); bigger frames amortize the ~300µs fixed overhead → more goodput.
        for plen in [4090usize, 5000, 5500, 5700] {
            let bulk = dev.build_data_bulk(&mk(plen), mcs);
            let t = Instant::now();
            let (done, errs) = ring.saturate(bulk, n);
            let el = t.elapsed();
            let per = el.as_secs_f64() / done.max(1) as f64 * 1e6;
            let mbps = (done as usize * plen * 8) as f64 / el.as_secs_f64() / 1e6;
            println!("{label} plen={plen:4}: {:5.1} Mb/s, {:.0} fps, {:.0} us/frame, {} errs",
                     mbps, done as f64 / el.as_secs_f64(), per, errs);
        }
    }
    println!("done.");
    Ok(())
}
#[cfg(not(all(feature = "libusb-backend", target_os = "linux")))]
fn main() {}
