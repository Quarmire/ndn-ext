//! On-air TX-power characterization for the RTL8812AU (#38, "get the power knob
//! working"). Two roles on ch6, one per OPi:
//!
//!   RX:  sudo NDN_RADIO_NO_RESET=1 ./pwr_sweep8812au rx
//!   TX:  sudo NDN_RADIO_NO_RESET=1 ./pwr_sweep8812au tx
//!
//! The TX role sweeps `set_tx_power(idx)` over `[LO..=HI]` (step `STEP`), sending
//! `N` frames at each idx with the power index encoded in the **source MAC's last
//! byte** (`02:4e:44:4e:88:<idx>`). The RX role reads that byte back and bins the
//! per-frame RSSI by idx, so the printed table IS the measured idx→dBm transfer
//! function of the knob — the only honest way to know whether it is monotone (a
//! usable dB control) or a cliff (memory: `0x3f` delivers, `0x30` nothing).
//!
//! Env (TX): NDN_SWEEP_LO=0x10 NDN_SWEEP_HI=0x3f NDN_SWEEP_STEP=1 NDN_SWEEP_N=20
//!           NDN_SWEEP_REPS=3
#[cfg(feature = "libusb-backend")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use ndn_face_monitor_wifi::Rtl8812auBackend;
    use std::collections::BTreeMap;
    use std::time::Duration;

    let mode = std::env::args().nth(1).unwrap_or_else(|| "rx".into());
    const DESC_RATE_6M: u32 = 0x04;
    const OUI: [u8; 5] = [0x02, 0x4e, 0x44, 0x4e, 0x88]; // "NDN"+88, idx in byte 5

    let env_u8 = |k: &str, d: u8| {
        std::env::var(k)
            .ok()
            .and_then(|s| u8::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok())
            .unwrap_or(d)
    };

    let ch: u8 = std::env::var("NDN_CH").ok().and_then(|s| s.trim().parse().ok()).unwrap_or(6);
    let b = Rtl8812auBackend::open()?;
    println!("opened RTL8812AU pid={:#06x} role={mode}", b.pid());
    b.power_on()?;
    b.mac_enable_dma()?;
    b.init_llt()?;
    let (ver, sub) = b.download_firmware()?;
    b.mac_config()?;
    b.mac_init_queues()?;
    b.bb_config()?;
    b.rf_config()?;
    b.set_channel(ch)?;
    // Read the EFUSE TX-power calibration so the sweep exercises the calibrated knob
    // (set_tx_power folds idx as an offset onto the fused base). NDN_TXPWR_DBG=1 prints
    // the parsed base — the on-hardware validation of the EFUSE read.
    if let Err(e) = b.load_tx_power_info() {
        eprintln!("load_tx_power_info failed (flat fallback): {e:?}");
    }
    if std::env::var_os("NDN_SKIP_CAL").is_none() {
        b.iq_calibrate()?;
        b.lc_calibrate()?;
    }
    b.start_rx_dma()?;
    println!("✓ 8812au up on ch{ch} (fw {ver}.{sub})");

    if mode == "rx" {
        println!("binning RSSI by TX power idx (Ctrl-C to stop)…");
        // idx -> (count, sum_rssi, min, max)
        let mut bins: BTreeMap<u8, (u64, i64, i8, i8)> = BTreeMap::new();
        let mut heard = 0u64;
        loop {
            if let Some(f) = b.poll_frame()? {
                let Some(addr) = f.addr else { continue };
                if addr[..5] != OUI {
                    continue;
                }
                let Some(rssi) = f.rssi_dbm else { continue };
                let idx = addr[5];
                let e = bins.entry(idx).or_insert((0, 0, 127, -128));
                e.0 += 1;
                e.1 += rssi as i64;
                e.2 = e.2.min(rssi);
                e.3 = e.3.max(rssi);
                heard += 1;
                if heard % 20 == 0 {
                    println!("\n--- {heard} frames — idx→RSSI(dBm) ---");
                    println!(" idx  n   mean   min  max");
                    for (idx, (n, sum, mn, mx)) in &bins {
                        println!(
                            "0x{idx:02x} {n:>3}  {:>5.1}  {mn:>4} {mx:>4}",
                            *sum as f64 / *n as f64
                        );
                    }
                }
            }
        }
    }

    // ── TX sweep ──
    b.write8(0x522, 0x00)?; // release TXPAUSE (IQK leaves it 0x3f)
    // Monitor injection must not defer to energy-detect carrier sense — otherwise the
    // reset-default EDCCA threshold can read the channel "busy" and the TX engine holds
    // frames in the FIFO (measured as ~2% duty / clumped blast). Blast regardless.
    let _ = b.disable_edcca();
    // Clear any stuck modulated continuous-TX (0x914[18:16]) left armed by a prior
    // NDN_CONTTX run — otherwise it emits a steady TXAGC-independent carrier that masks
    // the real per-index data TX.
    let _ = b.stop_continuous_tx();
    // NDN_2T=1: force BOTH antenna paths to transmit (rTxPath_Jaguar 0x80C low word =
    // 0x3333 = A+B for every rate group). A 6M OFDM is otherwise 1-stream on path A, so
    // an SDR cabled to path B sees only ~60 dB-down leakage. With 2T, whichever port is
    // cabled carries the full signal.
    if std::env::var("NDN_2T").is_ok() {
        let cur = b.read32(0x80c)?;
        b.write32(0x80c, (cur & 0xffff_0000) | 0x3333)?;
        println!("2T forced: 0x80C={:#010x}", b.read32(0x80c)?);
    }
    // NDN_C24 / NDN_E24: raw hex override of the OFDM power-by-rate registers (path A
    // 0xC24/0xC28, path B 0xE24/0xE28), bypassing the calibrated set_tx_power. Used to
    // drive the two paths independently and map which B210 port carries which path.
    let hx = |k: &str| -> Option<u32> {
        std::env::var(k)
            .ok()
            .and_then(|s| u32::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok())
    };
    let raw_c = hx("NDN_C24");
    let raw_e = hx("NDN_E24");
    let reps = env_u8("NDN_SWEEP_REPS", 3);
    let n = env_u8("NDN_SWEEP_N", 20);

    // Two knobs to characterize:
    //  - default: the coarse per-rate power-by-rate index (`set_tx_power`, 0xC24…).
    //  - NDN_SWEEP_SCALE=1: the BB OFDM TX **digital scale** in 0xC1C/0xE1C[31:20]
    //    (default 0x2d4). This is the fine, wide-range attenuator; per-rate is held
    //    at 0x3f so the PA stays in its linear region and only the digital gain moves.
    let scale_mode = std::env::var("NDN_SWEEP_SCALE").is_ok();

    if scale_mode {
        b.set_tx_power(0x3f)?; // PA at full; sweep only the digital scale
        // scale ∈ [lo<<4 .. hi<<4], encode (scale>>4) in the MAC byte (0x04..0x3f).
        let lo = env_u8("NDN_SWEEP_LO", 0x04); // scale 0x040
        let hi = env_u8("NDN_SWEEP_HI", 0x3f); // scale 0x3f0
        let step = env_u8("NDN_SWEEP_STEP", 2).max(1);
        println!(
            "SCALE sweep 0xC1C[31:20] {:#05x}..={:#05x} step {:#05x}, {n} frames/step, {reps} reps",
            (lo as u32) << 4,
            (hi as u32) << 4,
            (step as u32) << 4
        );
        for rep in 0..reps {
            let mut hib = lo;
            loop {
                let scale = (hib as u32) << 4; // 12-bit digital scale (field value)
                for reg in [0xC1Cu16, 0xE1C] {
                    let cur = b.read32(reg)?;
                    let new = (cur & !0xFFF0_0000) | ((scale << 20) & 0xFFF0_0000);
                    b.write32(reg, new)?;
                }
                let rb = b.read32(0xC1C)?;
                let src: [u8; 6] = [OUI[0], OUI[1], OUI[2], OUI[3], OUI[4], hib];
                let beacon = build_beacon(&src, ch);
                for _ in 0..n {
                    for ep in [0x02u8, 0x03, 0x04] {
                        let _ = b.send_frame_ep(ep, &beacon, DESC_RATE_6M);
                    }
                    std::thread::sleep(Duration::from_millis(3));
                }
                if hib == lo {
                    println!("rep {rep}: scale {scale:#05x} → 0xC1C rb={rb:#010x}");
                }
                if hib >= hi {
                    break;
                }
                hib = hib.saturating_add(step);
            }
            println!("rep {rep} done");
        }
        println!("sweep complete (scale)");
        return Ok(());
    }

    // NDN_BLAST=1: inject frames back-to-back with no inter-frame sleep, so the TX
    // is ~continuous (high duty) — an SDR then reads plain mean in-band power as the
    // TX level, no burst-gating or duty correction needed. This is the mode for an
    // adjacent-SDR absolute power sweep. Default keeps the 3ms-paced beacons (for the
    // RSSI-by-idx peer role, where each frame is a discrete RSSI sample).
    let blast = std::env::var("NDN_BLAST").is_ok();
    // NDN_CONTTX=1: arm modulated CONTINUOUS TX (steady 100%-duty OFDM carrier). Each
    // idx dwells ~1s at its calibrated power so an SDR reads a clean steady level — the
    // right mode for a conducted absolute power sweep. A staircase of mean power vs
    // time then maps directly to idx (ascending).
    let conttx = std::env::var("NDN_CONTTX").is_ok();
    let out_ep = b.endpoints().1; // the real bulk-OUT endpoint (avoid blocking on invalid EPs)

    // NDN_BENCH: deterministic TX-datapath throughput probe — inject 1400 B data
    // frames as fast as possible for 8s and report frames/sec, errors (USB timeouts),
    // and per-frame latency. A healthy 6M datapath should sustain ~500 fps (airtime
    // limit); ~10 fps + high errors = the FIFO isn't draining (write_bulk blocking).
    if std::env::var("NDN_BENCH").is_ok() {
        b.write8(0x522, 0x00)?;
        let _ = b.disable_edcca();
        // Defensively clear any stuck continuous-TX mode from a prior run.
        let _ = b.stop_continuous_tx();
        b.set_tx_power(0x3f)?;
        let src: [u8; 6] = [OUI[0], OUI[1], OUI[2], OUI[3], OUI[4], 0x3f];
        let frame = build_data(&src, &vec![0x5a; 1400]);
        let (mut sent, mut errs) = (0u64, 0u64);
        let t0 = std::time::Instant::now();
        let mut last = t0;
        while t0.elapsed() < Duration::from_secs(8) {
            let fs = std::time::Instant::now();
            match b.send_frame_ep(out_ep, &frame, DESC_RATE_6M) {
                Ok(()) => sent += 1,
                Err(_) => errs += 1,
            }
            let lat = fs.elapsed();
            if last.elapsed() >= Duration::from_secs(1) {
                println!(
                    "bench: {sent} sent, {errs} errs, {:.0} fps, last-frame {:?}",
                    sent as f64 / t0.elapsed().as_secs_f64(),
                    lat
                );
                last = std::time::Instant::now();
            }
        }
        println!(
            "BENCH: {sent} sent, {errs} errs in {:.1}s = {:.0} fps",
            t0.elapsed().as_secs_f64(),
            sent as f64 / t0.elapsed().as_secs_f64()
        );
        return Ok(());
    }
    let lo = env_u8("NDN_SWEEP_LO", 0x10);
    let hi = env_u8("NDN_SWEEP_HI", 0x3f);
    let step = env_u8("NDN_SWEEP_STEP", 1).max(1);
    if conttx {
        let dwell_ms: u64 = std::env::var("NDN_DWELL_MS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1000);
        b.set_tx_power(hi)?;
        b.start_continuous_tx()?;
        let src: [u8; 6] = [OUI[0], OUI[1], OUI[2], OUI[3], OUI[4], hi];
        let prime = build_data(&src, &[0x5a; 1400]);
        for ep in [0x02u8, 0x03, 0x04] {
            let _ = b.send_frame_ep(ep, &prime, DESC_RATE_6M);
        }
        println!("CONTTX armed; sweep idx {lo:#04x}..={hi:#04x} step {step}, {dwell_ms}ms/idx");
        let mut idx = lo;
        loop {
            b.set_tx_power(idx)?;
            let a = b.read32(0xC24)?;
            println!("idx {idx:#04x} → TXAGC A(0xC24)={a:#010x}");
            // Feed frames continuously for the dwell — in continuous-TX mode the chip
            // transmits them back-to-back with no inter-frame gap = steady carrier.
            let t0 = std::time::Instant::now();
            while t0.elapsed() < Duration::from_millis(dwell_ms) {
                for ep in [0x02u8, 0x03, 0x04] {
                    let _ = b.send_frame_ep(ep, &prime, DESC_RATE_6M);
                }
            }
            if idx >= hi {
                break;
            }
            idx = idx.saturating_add(step);
        }
        b.stop_continuous_tx()?;
        println!("sweep complete (conttx)");
        return Ok(());
    }
    println!(
        "sweep idx {lo:#04x}..={hi:#04x} step {step}, {n} frames/idx, {reps} reps{}",
        if blast { " [BLAST/continuous]" } else { "" }
    );
    // A bigger payload fills more airtime per frame at high duty (cleaner carrier).
    let payload: Vec<u8> = if blast { vec![0x5a; 1400] } else { Vec::new() };
    for rep in 0..reps {
        let mut idx = lo;
        loop {
            b.set_tx_power(idx)?;
            // Raw per-path override (maps port↔path): write the OFDM registers directly.
            if let Some(c) = raw_c {
                b.write32(0xc24, c)?;
                b.write32(0xc28, c)?;
            }
            if let Some(e) = raw_e {
                b.write32(0xe24, e)?;
                b.write32(0xe28, e)?;
            }
            // Read back BOTH path registers as commanded-index proof (0xC24 = path A,
            // 0xE24 = path B). Tagged with the idx so a log grep can match the exact run.
            let a = b.read32(0xC24)?;
            let bp = b.read32(0xE24)?;
            println!("RB idx={idx:#04x} C24={a:#010x} E24={bp:#010x}");
            let mut src = OUI.to_vec();
            src.push(idx);
            let src: [u8; 6] = src.try_into().unwrap();
            let frame = if blast {
                build_data(&src, &payload)
            } else {
                build_beacon(&src, ch)
            };
            // Blast: many more frames per idx (no sleep) so each idx dwells long
            // enough for the SDR to average a clean level.
            let count = if blast { n as u32 * 400 } else { n as u32 };
            // Blast sends ONLY to the real bulk-out endpoint: sending to invalid EPs
            // blocks the full 100ms USB timeout each, which was capping duty at ~2%.
            let eps: &[u8] = if blast {
                std::slice::from_ref(&out_ep)
            } else {
                &[0x02, 0x03, 0x04]
            };
            for _ in 0..count {
                for &ep in eps {
                    let _ = b.send_frame_ep(ep, &frame, DESC_RATE_6M);
                }
                if !blast {
                    std::thread::sleep(Duration::from_millis(3));
                }
            }
            if idx >= hi {
                break;
            }
            idx = idx.saturating_add(step);
        }
        println!("rep {rep} done");
    }
    println!("sweep complete");
    Ok(())
}

/// A minimal 802.11 data frame carrying `payload` — used for the continuous
/// (blast) power sweep, where a bigger frame + no inter-frame gap gives the SDR a
/// near-steady carrier to average.
#[cfg(feature = "libusb-backend")]
fn build_data(src: &[u8; 6], payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(24 + payload.len());
    f.extend_from_slice(&[0x08, 0x00]); // FC: data
    f.extend_from_slice(&[0x00, 0x00]); // duration
    f.extend_from_slice(&[0xff; 6]); // addr1 broadcast
    f.extend_from_slice(src); // addr2 = SA (carries idx)
    f.extend_from_slice(src); // addr3
    f.extend_from_slice(&[0x00, 0x00]); // seq
    f.extend_from_slice(payload);
    f
}

#[cfg(feature = "libusb-backend")]
fn build_beacon(src: &[u8; 6], channel: u8) -> Vec<u8> {
    let mut f = Vec::with_capacity(48);
    f.extend_from_slice(&[0x80, 0x00]); // FC: mgmt beacon
    f.extend_from_slice(&[0x00, 0x00]); // duration
    f.extend_from_slice(&[0xff; 6]); // addr1 broadcast
    f.extend_from_slice(src); // addr2 = SA (carries idx)
    f.extend_from_slice(src); // addr3 = BSSID
    f.extend_from_slice(&[0x00, 0x00]); // seq
    f.extend_from_slice(&[0u8; 8]); // timestamp
    f.extend_from_slice(&[0x64, 0x00]); // beacon interval
    f.extend_from_slice(&[0x00, 0x00]); // capability
    f.extend_from_slice(&[0x00, 0x04, b'S', b'W', b'P', b'0']); // SSID "SWP0"
    f.extend_from_slice(&[0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24]);
    f.extend_from_slice(&[0x03, 0x01, channel]); // DS param (channel)
    f
}

#[cfg(not(feature = "libusb-backend"))]
fn main() {
    eprintln!("build with --features libusb-backend");
}
