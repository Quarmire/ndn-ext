//! Task #28: is there a **length term** at the margin?
//!
//! Task #27 refuted a length-dependent PER and closed the per-name-MTU question —
//! but every measurement behind it was taken at -52 dBm, far from the noise floor,
//! where a longer frame's extra bits cost nothing. Physics insists a length term
//! exists *somewhere*: at a given BER, `P(frame ok) = (1-BER)^bits`, so a 2260 B
//! frame carries ~2.8x the bits of an 800 B one and must die sooner as SNR falls.
//!
//! The question is whether it appears at a **usable operating point**. If it does,
//! #27 is refuted only for strong links and the per-name MTU knob returns for
//! reach-limited names — which is the regime a named-radio mesh actually lives in.
//!
//! **The knob is the RATE, not the power** — and that is a corrected decision, not
//! a preference (2026-07-16). The first cut of this probe swept the sender's TXAGC
//! (`set_tx_power`, documented as a 0-63 index) expecting ~0.25 dB/step. On air it
//! was binary: `0x3f` delivered, and `0x30` — nominally ~3.75 dB down, with ~30 dB
//! of margin in hand — delivered *nothing*, at every size. A 4 dB backoff cannot
//! silence a link with 30 dB of headroom, so that register's semantics are not what
//! its doc-comment claims and any curve drawn against it would be fiction. It is a
//! "pragmatic stand-in for the full EFUSE table" (rtl8812au.rs:5218), and it shows.
//!
//! Rate is the better instrument anyway, on two counts. It is *calibrated* — each
//! MCS has a published SNR requirement, so stepping the rate up steps the margin
//! down in known increments. And it is *actionable*: `mcs` is already a per-name
//! knob the policy decides (`TxParams::rate`), whereas TXAGC exists only for
//! spatial-reuse backoff. A length term found against rate is one cognition can
//! actually use; a length term found against TXAGC would need a knob we don't have.
//!
//! So: fix the power at max, sweep size x rate, and let the receiver report the
//! RSSI so the operating point is recorded rather than assumed.
//!
//! Read it: if the 2260 B row degrades FASTER than the 800 B row as the rate
//! climbs, p is a function of (len, SNR-margin) and #27's "max MTU always wins"
//! reopens for reach-limited names. If all rows fall together, length is
//! irrelevant at every margin and #27 stands.
//!
//!   # peer first
//!   sudo NDN_RADIO_NO_RESET=1 LD_LIBRARY_PATH=$(nix path-info nixpkgs#libusb1)/lib \
//!       ./reach_fork rx 300
//!   sudo NDN_RADIO_NO_RESET=1 LD_LIBRARY_PATH=... ./reach_fork tx
#[cfg(feature = "libusb-backend")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use ndn_face_monitor_wifi::Rtl8812auBackend;
    use std::collections::BTreeMap;
    use std::time::{Duration, Instant};

    const SIZES: [usize; 4] = [800, 1400, 2000, 2260];
    /// DESC_RATE codes, most robust -> least. Legacy 6M (0x04) and 54M (0x0b);
    /// HT MCS0 (0x0c), MCS4 (0x10), MCS7 (0x13). Required SNR climbs steeply along
    /// this axis, so it is a margin sweep with calibrated steps. A rate the part
    /// will not emit shows up as an all-zero column and is reported as UNUSABLE
    /// rather than quietly read as loss.
    const RATES: [u8; 5] = [0x04, 0x0b, 0x0c, 0x10, 0x13];
    const PER_CELL: usize = 30;
    const SRC: [u8; 6] = [0x02, 0x4e, 0x44, 0x4e, 0x88, 0x16];
    const DST: [u8; 6] = [0x02, 0x4e, 0x44, 0x4e, 0x88, 0x17];
    const MAGIC: &[u8; 2] = b"RF";

    let mode = std::env::args().nth(1).unwrap_or_else(|| "rx".into());
    let arg2 = std::env::args().nth(2);

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
        let passes: usize = arg2.as_deref().and_then(|s| s.parse().ok()).unwrap_or(3);
        println!("tx: max power, sweeping rates {RATES:02x?} x {passes} passes");
        // Interleave passes rather than repeating each cell back-to-back: ambient
        // 2.4 GHz traffic drifts over minutes, and a cell measured only once, only
        // at one moment, measures the moment. Round-robin spreads every cell
        // across the whole run so drift hits all of them alike.
        for pass in 0..passes {
            for &rate in &RATES {
                for &size in &SIZES {
                    for i in 0..PER_CELL {
                        let seq = (pass * PER_CELL + i) as u32;
                        let mut f = Vec::with_capacity(size);
                        f.extend_from_slice(&[0x08, 0x00, 0x00, 0x00]);
                        f.extend_from_slice(&DST);
                        f.extend_from_slice(&SRC);
                        f.extend_from_slice(&DST);
                        f.extend_from_slice(&((i as u16) << 4).to_le_bytes());
                        f.extend_from_slice(MAGIC);
                        f.extend_from_slice(&(size as u32).to_le_bytes());
                        f.extend_from_slice(&(rate as u32).to_le_bytes());
                        f.extend_from_slice(&seq.to_le_bytes());
                        while f.len() < size {
                            f.push((f.len() & 0xff) as u8);
                        }
                        b.send_frame(&f, rate as u32)?;
                        // 1 ms: burst is a settled non-factor (burst_fork), and
                        // pacing keeps one cell's backlog out of the next.
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
            }
            println!("tx: pass {} / {passes} done", pass + 1);
            std::thread::sleep(Duration::from_millis(300));
        }
        println!("tx: done");
        return Ok(());
    }

    let secs: u64 = arg2.and_then(|s| s.parse().ok()).unwrap_or(300);
    let passes: usize = std::env::var("RF_PASSES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3);
    let sent = PER_CELL * passes;
    println!("rx: counting per (size, rate) for {secs}s via poll_frame …");
    let mut seen: BTreeMap<(usize, u8), std::collections::HashSet<u32>> = BTreeMap::new();
    // RSSI per rate: records the operating point instead of assuming it.
    let mut rssi: BTreeMap<u8, (i32, u32)> = BTreeMap::new();
    let t0 = Instant::now();
    // ONE reader (rx_raw + poll_frame together steal transfers and read as 50%
    // loss). poll_frame, because it carries the RSSI.
    while t0.elapsed() < Duration::from_secs(secs) {
        let Ok(Some(cf)) = b.poll_frame() else { continue };
        let f = &cf.payload;
        let Some(p) = f.windows(2).position(|w| w == MAGIC) else {
            continue;
        };
        if p + 14 > f.len() {
            continue;
        }
        let size = u32::from_le_bytes(f[p + 2..p + 6].try_into().unwrap()) as usize;
        let rate = u32::from_le_bytes(f[p + 6..p + 10].try_into().unwrap()) as u8;
        let seq = u32::from_le_bytes(f[p + 10..p + 14].try_into().unwrap());
        if SIZES.contains(&size) && RATES.contains(&rate) && (seq as usize) < sent {
            seen.entry((size, rate)).or_default().insert(seq);
            if let Some(r) = cf.rssi_dbm {
                let e = rssi.entry(rate).or_insert((0, 0));
                e.0 += r as i32;
                e.1 += 1;
            }
        }
    }

    println!("\n  distinct delivered / {sent} sent ({passes} interleaved passes)\n");
    print!("{:>7}", "size");
    for r in RATES {
        print!("{:>12}", format!("rate {r:#04x}"));
    }
    println!();
    for size in SIZES {
        print!("{size:>7}");
        for r in RATES {
            let got = seen.get(&(size, r)).map(|s| s.len()).unwrap_or(0);
            print!("{:>12}", format!("{got}/{sent}"));
        }
        println!();
    }
    print!("\n{:>7}", "rssi");
    for r in RATES {
        let s = match rssi.get(&r) {
            Some((sum, n)) if *n > 0 => format!("{} dBm", sum / (*n as i32)),
            _ => "-".into(),
        };
        print!("{s:>12}");
    }
    println!();
    // Name the dead columns instead of letting a reader mistake "the part won't
    // emit this rate" for "this rate is unreachable".
    let dead: Vec<String> = RATES
        .iter()
        .filter(|r| SIZES.iter().all(|s| seen.get(&(*s, **r)).is_none()))
        .map(|r| format!("{r:#04x}"))
        .collect();
    if !dead.is_empty() {
        println!(
            "\n  UNUSABLE (all-zero column, every size): {}\n  \
             Nothing arrived at ANY size, including the shortest — that is the part\n  \
             refusing the rate code, not a reach limit. Excluded from the read below.",
            dead.join(", ")
        );
    }
    println!(
        "\n  Compare the 800 B row against the 2260 B row as the rate climbs.\n  \
         2260 falling FASTER -> a real (len x SNR-margin) term; task #27's\n  \
         'max MTU always wins' holds only where margin is plentiful.\n  \
         Rows falling together -> length is irrelevant at every margin; #27 stands."
    );
    Ok(())
}

#[cfg(not(feature = "libusb-backend"))]
fn main() {
    eprintln!("build with --features libusb-backend");
}
