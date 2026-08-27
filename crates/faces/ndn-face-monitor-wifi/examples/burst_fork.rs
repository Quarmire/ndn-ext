//! Is the multi-fragment cliff **length** or **burst**? One knob decides it.
//!
//! Task #27 assumes a length-dependent PER: "p ~= 1.00 at 1432 B, p ~= 0.83 at
//! 2272 B", and concludes the planner should trade frame length per name. But the
//! evidence for that came from *fragmented objects*, where length and
//! back-to-back-ness move together — a bigger object is both longer frames AND
//! more of them, sent as fast as the LP layer can hand them over. Those are two
//! different mechanisms and the sweep cannot separate them.
//!
//! This can. Fix the size, vary ONLY the inter-frame gap:
//!
//!   gap=0 (burst) delivers far worse than gap=4 (paced)  -> BURST. Frame length
//!     is innocent; the planner has no MTU decision to make, and the fix is
//!     pacing (or an RX FIFO that keeps up), not a per-name MTU.
//!   gap makes no difference, but big sizes lose          -> LENGTH. #27's
//!     premise holds and p(len) is real.
//!
//! Prior evidence for BURST, which is why this probe exists: `size_fork tx` sleeps
//! 4 ms between frames and measured 2200/2260/2300 B at 100% delivery — the exact
//! lengths the object sweep says arrive ~83% of the time.
//!
//!   # peer first
//!   sudo NDN_RADIO_NO_RESET=1 LD_LIBRARY_PATH=$(nix path-info nixpkgs#libusb1)/lib \
//!       ./burst_fork rx 60
//!   # then, on the other board — sizes and gaps are swept for you
//!   sudo NDN_RADIO_NO_RESET=1 LD_LIBRARY_PATH=... ./burst_fork tx
#[cfg(feature = "libusb-backend")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use ndn_face_monitor_wifi::Rtl8812auBackend;
    use std::collections::BTreeMap;
    use std::time::{Duration, Instant};

    const SIZES: [usize; 4] = [800, 1400, 2000, 2260];
    // 0 = as fast as the driver will take them (what LP fragmentation does today).
    const GAPS_US: [u64; 4] = [0, 500, 2000, 4000];
    const PER_CELL: usize = 30;
    const DESC_RATE_6M: u32 = 0x04;
    const SRC: [u8; 6] = [0x02, 0x4e, 0x44, 0x4e, 0x88, 0x14];
    const DST: [u8; 6] = [0x02, 0x4e, 0x44, 0x4e, 0x88, 0x15];
    const MAGIC: &[u8; 2] = b"BF";

    let mode = std::env::args().nth(1).unwrap_or_else(|| "rx".into());
    let secs: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(120);

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
        for &size in &SIZES {
            for &gap in &GAPS_US {
                for i in 0..PER_CELL {
                    // FC(data) | dur | a1 | a2 | a3 | seq, then BF | size | gap | i.
                    let mut f = Vec::with_capacity(size);
                    f.extend_from_slice(&[0x08, 0x00, 0x00, 0x00]);
                    f.extend_from_slice(&DST);
                    f.extend_from_slice(&SRC);
                    f.extend_from_slice(&DST);
                    f.extend_from_slice(&((i as u16) << 4).to_le_bytes());
                    f.extend_from_slice(MAGIC);
                    f.extend_from_slice(&(size as u32).to_le_bytes());
                    f.extend_from_slice(&(gap as u32).to_le_bytes());
                    f.extend_from_slice(&(i as u32).to_le_bytes());
                    while f.len() < size {
                        f.push((f.len() & 0xff) as u8);
                    }
                    b.send_frame(&f, DESC_RATE_6M)?;
                    if gap > 0 {
                        std::thread::sleep(Duration::from_micros(gap));
                    }
                }
                // Idle between cells so one cell's backlog cannot bleed into the
                // next and smear the very effect being measured.
                std::thread::sleep(Duration::from_millis(300));
                println!("tx: {PER_CELL} x {size} B at gap {gap} us");
            }
        }
        println!("tx: done");
        return Ok(());
    }

    // rx: count DISTINCT seq per (size, gap). Distinct, because a retry would
    // otherwise inflate delivery — and RETRY_LIMIT is 0 here, but count what is
    // true rather than what is assumed.
    //
    // TWO readers, run one at a time (never together — rx_raw and poll_frame in
    // one loop steal transfers from each other and read as exactly 50% loss):
    //   rx       — rx_raw, the bytes the dongle DMA'd. What the radio achieved.
    //   rxparsed — poll_frame, i.e. through parse_rx_buffer. What the stack kept.
    //
    // The difference between them at gap 0 is the cell that matters. `rx_raw` is a
    // tight loop; `parse_rx_buffer` does real per-frame work, so a reader that
    // keeps up when frames are 4 ms apart may not when LP fragmentation hands them
    // over back-to-back — which is exactly how a fragmented object is sent.
    let parsed = mode == "rxparsed";
    println!(
        "rx: counting distinct frames per (size, gap) for {secs}s via {} …",
        if parsed {
            "poll_frame (PARSED)"
        } else {
            "rx_raw (RAW)"
        }
    );
    let mut seen: BTreeMap<(usize, u64), std::collections::HashSet<u32>> = BTreeMap::new();
    let mut buf = vec![0u8; 16384];
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(secs) {
        let hit = if parsed {
            match b.poll_frame() {
                Ok(Some(cf)) => Some(cf.payload.to_vec()),
                _ => None,
            }
        } else {
            match b.rx_raw(&mut buf) {
                Ok(n) if n > 0 => Some(buf[..n].to_vec()),
                _ => None,
            }
        };
        let Some(f) = hit else { continue };
        // Find our tag rather than assume a fixed RX descriptor length.
        let Some(p) = f.windows(2).position(|w| w == MAGIC) else {
            continue;
        };
        if p + 14 > f.len() {
            continue;
        }
        let size = u32::from_le_bytes(f[p + 2..p + 6].try_into().unwrap()) as usize;
        let gap = u32::from_le_bytes(f[p + 6..p + 10].try_into().unwrap()) as u64;
        let seq = u32::from_le_bytes(f[p + 10..p + 14].try_into().unwrap());
        if SIZES.contains(&size) && GAPS_US.contains(&gap) && (seq as usize) < PER_CELL {
            seen.entry((size, gap)).or_default().insert(seq);
        }
    }

    println!("\n  distinct delivered / {PER_CELL} sent\n");
    print!("{:>7}", "size");
    for g in GAPS_US {
        print!("{:>12}", format!("gap {g}us"));
    }
    println!();
    for size in SIZES {
        print!("{size:>7}");
        for gap in GAPS_US {
            let got = seen.get(&(size, gap)).map(|s| s.len()).unwrap_or(0);
            print!("{:>12}", format!("{got}/{PER_CELL}"));
        }
        println!();
    }
    println!(
        "\n  Read the ROWS: if a row is flat, length is what matters and pacing is\n  \
         irrelevant. Read the COLUMNS: if gap 0 is much worse than gap 4000 at the\n  \
         same size, the loss is burst and frame length is innocent."
    );
    Ok(())
}

#[cfg(not(feature = "libusb-backend"))]
fn main() {
    eprintln!("build with --features libusb-backend");
}
