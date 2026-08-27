//! Task #25's unresolved fork, in one probe: is the >=2200 B cliff **TX or RX**?
//!
//! Every hypothesis so far quietly assumed one side. This decides it, below both
//! `WifiPhy` and NDNLPv2 — just raw 802.11 data frames at a size sweep.
//!
//!   tx  — inject N data frames at each of 800/1400/1800/2200/2600/3000 B, tagged
//!         so the peer can size them from the payload alone.
//!   rx  — report every RAW bulk-IN transfer's length, and what our parser makes
//!         of it. `rx_raw` sees the bytes the dongle DMA'd *before*
//!         `parse_rx_buffer` gets an opinion, so a frame that arrives but fails to
//!         parse looks different from one that never arrived at all.
//!
//! Reading it:
//!   raw transfers ~= the big sizes  -> the frames ARRIVE; the bug is our RX parse.
//!   raw transfers only ever small   -> nothing big is on the air; the bug is TX.
//!
//!   # peer first
//!   sudo NDN_RADIO_NO_RESET=1 LD_LIBRARY_PATH=$(nix path-info nixpkgs#libusb1)/lib \
//!       ./size_fork rx
//!   sudo NDN_RADIO_NO_RESET=1 LD_LIBRARY_PATH=... ./size_fork tx
#[cfg(feature = "libusb-backend")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use ndn_phy_wifi::Rtl8812auBackend;
    use std::collections::BTreeMap;
    use std::time::{Duration, Instant};

    // Override with e.g. `size_fork tx 2200,2300,2400` to narrow a cliff.
    let sizes: Vec<usize> = std::env::args()
        .nth(2)
        .map(|s| s.split(',').filter_map(|x| x.trim().parse().ok()).collect())
        .unwrap_or_else(|| vec![800, 1400, 1800, 2200, 2600, 3000]);
    const PER_SIZE: usize = 40;
    const DESC_RATE_6M: u32 = 0x04;
    const SRC: [u8; 6] = [0x02, 0x4e, 0x44, 0x4e, 0x88, 0x12];
    const DST: [u8; 6] = [0x02, 0x4e, 0x44, 0x4e, 0x88, 0x13];

    let mode = std::env::args().nth(1).unwrap_or_else(|| "rx".into());

    let b = Rtl8812auBackend::open()?;
    b.power_on()?;
    b.mac_enable_dma()?;
    b.init_llt()?;
    b.download_firmware()?;
    b.mac_config()?;
    b.mac_init_queues()?;
    b.bb_config()?;
    b.rf_config()?;
    b.set_channel(6)?;
    b.iq_calibrate()?;
    b.lc_calibrate()?;
    b.set_tx_power(0x3f)?;
    b.start_rx_dma()?;
    println!("8812AU pid={:#06x} up on ch6", b.pid());

    if mode == "tx" {
        for size in sizes {
            // A plain 802.11 data frame: FC(data) | dur | addr1 | addr2 | addr3 | seq,
            // then a payload whose first bytes carry the intended size.
            for i in 0..PER_SIZE {
                let mut f = Vec::with_capacity(size);
                f.extend_from_slice(&[0x08, 0x00, 0x00, 0x00]);
                f.extend_from_slice(&DST);
                f.extend_from_slice(&SRC);
                f.extend_from_slice(&DST);
                f.extend_from_slice(&((i as u16) << 4).to_le_bytes());
                f.extend_from_slice(b"SZ");
                f.extend_from_slice(&(size as u32).to_le_bytes());
                while f.len() < size {
                    f.push((f.len() & 0xff) as u8);
                }
                b.send_frame(&f, DESC_RATE_6M)?;
                std::thread::sleep(Duration::from_millis(4));
            }
            println!("tx: sent {PER_SIZE} x {size} B");
        }
        println!("tx: done");
        return Ok(());
    }

    // rx: bucket transfer lengths. `rxraw` reads the DMA'd bytes; `rx` reads what
    // the parser hands up. Run one or the other — never both in one loop.
    let raw_mode = mode == "rxraw";
    println!("rx: reporting raw bulk-IN transfer sizes for 60s …");
    let mut raw_hist: BTreeMap<usize, u32> = BTreeMap::new();
    let mut parsed_hist: BTreeMap<usize, u32> = BTreeMap::new();
    let mut buf = vec![0u8; 16384];
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(60) {
        // ONE reader only. Calling rx_raw and poll_frame in the same loop makes
        // them steal bulk-IN transfers from each other and halves both counts —
        // which reads exactly like 50% packet loss, and is not.
        if raw_mode {
            if let Ok(n) = b.rx_raw(&mut buf)
                && n > 0
            {
                *raw_hist.entry(bucket(n)).or_default() += 1;
            }
        } else if let Ok(Some(cf)) = b.poll_frame() {
            *parsed_hist.entry(bucket(cf.payload.len())).or_default() += 1;
        }
    }

    println!("\n  raw bulk-IN transfer sizes (the bytes the dongle DMA'd):");
    for (b0, n) in &raw_hist {
        println!("    ~{b0:>5} B  x{n}");
    }
    println!("\n  what parse_rx_buffer handed up:");
    for (b0, n) in &parsed_hist {
        println!("    ~{b0:>5} B  x{n}");
    }
    // Only one histogram is populated per run (one reader), so a verdict can only
    // come from comparing two runs — `rxraw` then `rx`. Printing one here read
    // "big frames ARRIVE but do not parse" on EVERY rxraw run, because the parsed
    // histogram is empty by construction. A probe that always reaches the same
    // conclusion is not evidence (found 2026-07-16).
    let hist = if raw_mode { &raw_hist } else { &parsed_hist };
    let big = hist.keys().any(|k| *k >= 2000);
    println!(
        "\n  {} saw {} big (>=2000 B) frames. Run the other mode and compare:\n  \
         big in rxraw but not in rx -> the bug is RX PARSE.\n  \
         big in neither             -> the bug is TX (or RX DMA).",
        if raw_mode { "rxraw" } else { "rx" },
        if big { "SOME" } else { "NO" },
    );
    Ok(())
}

/// Round to a bucket so the histogram is readable. `SZ_BUCKET=8` narrows it when
/// pinning a cliff to the byte.
#[cfg(feature = "libusb-backend")]
fn bucket(n: usize) -> usize {
    let w: usize = std::env::var("SZ_BUCKET")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200);
    (n / w) * w
}

#[cfg(not(feature = "libusb-backend"))]
fn main() {
    eprintln!("build with --features libusb-backend");
}
