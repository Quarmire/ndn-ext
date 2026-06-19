//! List USB devices (and flag Realtek 88xx dongles) via the same rusb stack the
//! userspace backend uses. Build: `cargo run --example usb_probe -p
//! ndn-face-monitor-wifi --features libusb-backend`.

#[cfg(feature = "libusb-backend")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use rusb::UsbContext;
    let ctx = rusb::Context::new()?;
    for dev in ctx.devices()?.iter() {
        let d = dev.device_descriptor()?;
        let realtek = d.vendor_id() == 0x0bda;
        let mark = if realtek { "  <-- Realtek" } else { "" };
        if realtek || std::env::args().any(|a| a == "--all") {
            println!(
                "bus {:03} addr {:03}  {:04x}:{:04x}  class {:#04x}{}",
                dev.bus_number(),
                dev.address(),
                d.vendor_id(),
                d.product_id(),
                d.class_code(),
                mark
            );
        }
        if realtek {
            // Try to open + read the active config's endpoints (the backend path).
            match dev.open() {
                Ok(_h) => match dev.active_config_descriptor() {
                    Ok(cfg) => {
                        for iface in cfg.interfaces() {
                            for id in iface.descriptors() {
                                for ep in id.endpoint_descriptors() {
                                    println!(
                                        "    iface {} ep {:#04x} {:?} {:?} mps {}",
                                        id.interface_number(),
                                        ep.address(),
                                        ep.direction(),
                                        ep.transfer_type(),
                                        ep.max_packet_size(),
                                    );
                                }
                            }
                        }
                    }
                    Err(e) => println!("    (no active config: {e})"),
                },
                Err(e) => println!("    (cannot open: {e})"),
            }
        }
    }

    // Open via the backend and read identity registers over the vendor request.
    use ndn_face_monitor_wifi::{LibUsbRtl88xxBackend, REG_SYS_CFG};
    match LibUsbRtl88xxBackend::open() {
        Ok(mut radio) => {
            println!("\nbackend opened; register reads:");
            for (name, addr) in [
                ("REG_SYS_ISO_CTRL(0x00)", 0x0000u16),
                ("REG_SYS_FUNC_EN(0x02)", 0x0002),
                ("REG_SYS_CFG(0xF0)", REG_SYS_CFG),
                ("REG_SYS_CFG2(0xFC)", 0x00fc),
            ] {
                match radio.read32(addr) {
                    Ok(v) => println!("  {name:24} = {v:#010x}"),
                    Err(e) => println!("  {name:24} = ERR {e}"),
                }
            }
            match radio.chip_info() {
                Ok(c) => println!(
                    "  chip: id={:#04x} ({}) cut={} (B-cut expected on this dongle)",
                    c.chip_id,
                    if c.chip_id == ndn_face_monitor_wifi::CHIP_ID_8822E {
                        "8822E — RTL8812EU"
                    } else {
                        "UNEXPECTED"
                    },
                    c.cut,
                ),
                Err(e) => println!("  chip: ERR {e}"),
            }

            if std::env::args().any(|a| a == "--power-on") {
                let r = |a| {
                    radio
                        .read8(a)
                        .map(|v| format!("{v:#04x}"))
                        .unwrap_or_else(|e| format!("ERR {e}"))
                };
                println!(
                    "\npower-on: before  0x05={} 0x06={} CR(0x100)={} 0xF5={}",
                    r(0x05),
                    r(0x06),
                    r(0x100),
                    r(0xf5)
                );
                match radio.power_on() {
                    Ok(()) => println!("  power_on() OK (all polls reached target)"),
                    Err(e) => println!("  power_on() FAILED: {e}"),
                }
                println!(
                    "          after   0x05={} 0x06={} CR(0x100)={} 0xF5={}",
                    r(0x05),
                    r(0x06),
                    r(0x100),
                    r(0xf5)
                );
            }

            if std::env::args().any(|a| a == "--regs") {
                // Power/clock-domain registers, in the same set read live from
                // the working kernel driver on OPi-0 (debugfs read_reg) — diff
                // these to find any enable the userspace init still misses.
                if let Err(e) = radio.power_on() {
                    println!("power_on ERR {e}");
                }
                println!("\npost-power-on register dump (golden = kernel-driver live values):");
                for addr in [
                    0x0000u16, 0x0004, 0x0008, 0x0010, 0x001c, 0x0028, 0x0030, 0x0034, 0x0040,
                    0x004c, 0x0064, 0x00ec, 0x00f0, 0x00f4, 0x00fc, 0x0100, 0x1018, 0x1044, 0x1064,
                    0x1080, 0x1100,
                ] {
                    match radio.read32(addr) {
                        Ok(v) => println!("  {addr:#06x} = {v:#010x}"),
                        Err(e) => println!("  {addr:#06x} = ERR {e}"),
                    }
                }
            }

            if std::env::args().any(|a| a == "--fw") {
                if let Err(e) = radio.power_on() {
                    println!("power_on ERR {e}");
                }
                let fw = ndn_face_monitor_wifi::LibUsbRtl88xxBackend::firmware_nic();
                println!("\nfirmware blob: {} bytes; downloading…", fw.len());
                match radio.download_firmware(fw) {
                    Ok(ver) => {
                        // Golden fw_info reports "FW VER -1.27" → expect v1.27.
                        println!("  download_firmware() OK — fw {ver} alive");
                        match radio.read16(0x0080) {
                            Ok(v) => println!("  REG_MCUFW_CTRL = {v:#06x} (0xc078 = fw ready)"),
                            Err(e) => println!("  REG_MCUFW_CTRL = ERR {e}"),
                        }
                    }
                    Err(e) => println!("  download_firmware() FAILED: {e}"),
                }
            }

            if std::env::args().any(|a| a == "--mac-init") {
                // Full chain: power on → firmware → MAC init → monitor cfg,
                // then dump MAC registers 0x0000-0x07FC in the same format as
                // the golden kernel dump for diffing:
                //   cargo run ... -- --mac-init > /tmp/our_mac_regs.txt
                //   diff golden/opi0-2026-06-12/mac_reg_dump.txt /tmp/...
                if let Err(e) = radio.power_on() {
                    println!("power_on ERR {e}");
                }
                if let Err(e) = radio
                    .download_firmware(ndn_face_monitor_wifi::LibUsbRtl88xxBackend::firmware_nic())
                {
                    println!("download_firmware ERR {e}");
                }
                match radio.mac_init() {
                    Ok(()) => println!("mac_init() OK (auto-LLT + h2c space verified)"),
                    Err(e) => println!("mac_init() FAILED: {e}"),
                }
                match radio.monitor_cfg() {
                    Ok(()) => println!("monitor_cfg() OK (RCR=0x90000001 + MACID)"),
                    Err(e) => println!("monitor_cfg() FAILED: {e}"),
                }
                println!("======= MAC REG =======");
                for base in (0x0000u16..0x0800).step_by(16) {
                    print!("{base:#06x}");
                    for off in (0..16).step_by(4) {
                        match radio.read32(base + off) {
                            Ok(v) => print!(" {v:#010x} "),
                            Err(e) => print!(" ERR({e})"),
                        }
                    }
                    println!();
                }
            }

            if std::env::args().any(|a| a == "--phy") {
                // Full chain through BB/RF: power → fw → MAC init → monitor →
                // phy tables → ch161/BW20. Then dump BB + RF registers for
                // diffing against golden bb_reg_dump/rf_reg_dump.
                if let Err(e) = radio.power_on() {
                    println!("power_on ERR {e}");
                }
                if let Err(e) = radio
                    .download_firmware(ndn_face_monitor_wifi::LibUsbRtl88xxBackend::firmware_nic())
                {
                    println!("download_firmware ERR {e}");
                }
                if let Err(e) = radio.mac_init() {
                    println!("mac_init ERR {e}");
                }
                if let Err(e) = radio.monitor_cfg() {
                    println!("monitor_cfg ERR {e}");
                }
                match radio.phy_init() {
                    Ok(()) => println!("phy_init() OK (PHY_REG+AGC+RadioA/B tables loaded)"),
                    Err(e) => println!("phy_init() FAILED: {e}"),
                }
                match radio.set_channel_bw20(161) {
                    Ok(()) => println!("set_channel_bw20(161) OK"),
                    Err(e) => println!("set_channel_bw20(161) FAILED: {e}"),
                }
                if std::env::args().any(|a| a == "--cal") {
                    // Firmware IQK + DPK diagnostic (the fw runs them via H2C).
                    match radio.fw_iqk(false, false) {
                        Ok(()) => println!("fw_iqk OK (done flag raised)"),
                        Err(e) => println!("fw_iqk: {e}"),
                    }
                    let _ = radio.fw_dpk();
                    println!("fw_dpk sent");
                }
                use ndn_face_monitor_wifi::RfPath;
                for (name, path) in [("RF_A", RfPath::A), ("RF_B", RfPath::B)] {
                    print!("{name} 0x00/0x18/0x1a/0xb0/0xdf =");
                    for reg in [0x00u32, 0x18, 0x1a, 0xb0, 0xdf] {
                        match radio.rf_read(path, reg, 0xfffff) {
                            Ok(v) => print!(" {v:#07x}"),
                            Err(e) => print!(" ERR({e})"),
                        }
                    }
                    println!();
                }
                println!("======= BB REG =======");
                for base in (0x0800u16..0x1000)
                    .step_by(16)
                    .chain((0x1800u16..0x2000).step_by(16))
                {
                    print!("{base:#06x}");
                    for off in (0..16).step_by(4) {
                        match radio.read32(base + off) {
                            Ok(v) => print!(" {v:#010x} "),
                            Err(e) => print!(" ERR({e})"),
                        }
                    }
                    println!();
                }
                println!("======= RF REG =======");
                for (name, path) in [("RF_A", RfPath::A), ("RF_B", RfPath::B)] {
                    println!("[{name}]");
                    for base in (0x00u32..0x100).step_by(8) {
                        print!("{base:#04x}:");
                        for off in 0..8 {
                            match radio.rf_read(path, base + off, 0xfffff) {
                                Ok(v) => print!(" {v:05x}"),
                                Err(e) => print!(" ERR({e})"),
                            }
                        }
                        println!();
                    }
                }
            }

            if std::env::args().any(|a| a == "--rx") {
                // Bring up via the library path, then print received NDN frames
                // (ethertype 0x8624). Verify the userspace RX path: a peer
                // injects on the same channel and these should appear.
                let chan: u8 = std::env::args()
                    .position(|a| a == "--chan")
                    .and_then(|i| std::env::args().nth(i + 1))
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(149);
                let secs: u64 = std::env::args()
                    .position(|a| a == "--secs")
                    .and_then(|i| std::env::args().nth(i + 1))
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(15);
                match radio.bring_up(chan) {
                    Ok(()) => println!("  RX bring-up OK on ch{chan}; listening {secs}s…"),
                    Err(e) => println!("  bring-up FAILED: {e}"),
                }
                // --replayinit: replay the working driver's full BB init (>=0x800)
                // to test whether the RX datapath gate (like the TX one) lives
                // there. --rxregs N..M: force a MAC RXDMA register range too.
                if std::env::args().any(|a| a == "--replayinit")
                    && let Ok(txt) = std::fs::read_to_string("/tmp/opi_regseq.txt")
                {
                    {
                        let mut n = 0u32;
                        for line in txt.lines() {
                            let mut it = line.split_whitespace();
                            let (Some(a), Some(w), Some(v)) = (it.next(), it.next(), it.next())
                            else {
                                continue;
                            };
                            let addr =
                                u32::from_str_radix(a.trim_start_matches("0x"), 16).unwrap_or(0);
                            let val =
                                u32::from_str_radix(v.trim_start_matches("0x"), 16).unwrap_or(0);
                            let width: u8 = w.parse().unwrap_or(4);
                            let lo = std::env::var("REPLAY_LO")
                                .ok()
                                .and_then(|s| {
                                    u32::from_str_radix(s.trim_start_matches("0x"), 16).ok()
                                })
                                .unwrap_or(0x800);
                            let hi = std::env::var("REPLAY_HI")
                                .ok()
                                .and_then(|s| {
                                    u32::from_str_radix(s.trim_start_matches("0x"), 16).ok()
                                })
                                .unwrap_or(0xffff);
                            if !(lo..=hi).contains(&addr) {
                                continue;
                            }
                            let _ = match width {
                                1 => radio.write8(addr as u16, val as u8),
                                2 => radio.write16(addr as u16, val as u16),
                                _ => radio.write32(addr as u16, val),
                            };
                            n += 1;
                        }
                        let _ = radio.set_channel_bw20(chan);
                        println!("  replayed {n} BB writes for RX test");
                    }
                }
                // Raw-RX probe: does the chip deliver ANY bulk-IN data? Splits
                // "RXDMA/RCR not delivering" from "parse_rx rejects frames".
                let mut raw_hits = 0u32;
                let (mut et_hits, mut marker_hits) = (0u32, 0u32);
                let win = |b: &[u8], pat: &[u8]| b.windows(pat.len()).any(|w| w == pat);
                for _ in 0..400 {
                    match radio.recv_raw(50) {
                        Ok(Some(b)) if !b.is_empty() => {
                            raw_hits += 1;
                            // ethertype 0x8624 and our injected payload "OPI"
                            if win(&b, &[0x86, 0x24]) {
                                et_hits += 1;
                            }
                            if win(&b, b"OPI-RX") {
                                marker_hits += 1;
                            }
                            if raw_hits <= 2 {
                                println!("  RAW {} bytes: {:02x?}", b.len(), &b[..b.len().min(64)]);
                            }
                        }
                        _ => {}
                    }
                }
                println!(
                    "  raw reads: {raw_hits}/400; buffers with ethertype 0x8624: {et_hits}; \
                     with our 'OPI-RX' payload: {marker_hits}"
                );
                // Ambient-AP RSSI: the Mac's view of nearby transmitters (by
                // BSSID/addr3). Compare to the OPi's tcpdump RSSI of the SAME
                // BSSIDs — equal RX gains ⇒ the -62/-74 peer asymmetry is TX
                // power; unequal ⇒ it's RX gain.
                let mut aps: std::collections::HashMap<[u8; 6], i8> =
                    std::collections::HashMap::new();
                for _ in 0..800 {
                    if let Ok(Some(b)) = radio.recv_raw(50) {
                        if b.len() < 26 {
                            continue;
                        }
                        let w0 = u32::from_le_bytes(b[0..4].try_into().unwrap());
                        let pkt_len = (w0 & 0x3fff) as usize;
                        let drvinfo = ((w0 >> 16) & 0xf) as usize * 8;
                        let shift = ((w0 >> 24) & 0x3) as usize;
                        if b[24] & 0x0f == 0 {
                            continue; // CCK phy-status layout differs
                        }
                        let rssi = ((b[25] as i16) - 110).clamp(-128, 0) as i8;
                        let start = 24 + drvinfo + shift;
                        if start + 22 > b.len() || pkt_len < 22 {
                            continue;
                        }
                        let mut bssid = [0u8; 6];
                        bssid.copy_from_slice(&b[start + 16..start + 22]);
                        let e = aps.entry(bssid).or_insert(-128);
                        *e = (*e).max(rssi);
                    }
                }
                let mut v: Vec<_> = aps.into_iter().collect();
                v.sort_by_key(|(_, r)| -(*r as i32));
                println!("  Mac's RSSI of ambient transmitters (top, by addr3):");
                for (b, r) in v.iter().take(10) {
                    println!(
                        "    {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}  {r} dBm",
                        b[0], b[1], b[2], b[3], b[4], b[5]
                    );
                }
                let rt = tokio::runtime::Runtime::new().unwrap();
                use ndn_face_monitor_wifi::FrameIo;
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
                let mut n = 0u32;
                rt.block_on(async {
                    while std::time::Instant::now() < deadline {
                        match tokio::time::timeout(
                            std::time::Duration::from_millis(500),
                            radio.recv_frame(),
                        )
                        .await
                        {
                            Ok(Ok(f)) => {
                                n += 1;
                                if n <= 20 || n.is_multiple_of(100) {
                                    println!(
                                        "  RX #{n}: {} bytes from {:02x?} rssi={:?} mcs={:?} payload={:02x?}",
                                        f.payload.len(),
                                        f.addr,
                                        f.rssi_dbm,
                                        f.mcs_index,
                                        &f.payload[..f.payload.len().min(12)],
                                    );
                                }
                            }
                            Ok(Err(e)) => println!("  RX error: {e}"),
                            Err(_) => {} // 500ms idle tick
                        }
                    }
                });
                println!("  received {n} NDN frames in {secs}s");
            }

            if std::env::args().any(|a| a == "--inject") {
                // Full bring-up then transmit a burst of named-radio frames on
                // ch161. Capture on the OPi: sudo tcpdump -i wlu1u1 -e -n.
                let bringup = || -> Result<(), Box<dyn std::error::Error>> {
                    // --useinit: exercise the encapsulated library bring-up
                    // (LibUsbRtl88xxBackend::bring_up) that the bearer's
                    // MonitorWifiFace::open_libusb uses — instead of the
                    // step-by-step diagnostic path below.
                    if std::env::args().any(|a| a == "--useinit") {
                        let chan: u8 = std::env::args()
                            .position(|a| a == "--chan")
                            .and_then(|i| std::env::args().nth(i + 1))
                            .and_then(|v| v.parse().ok())
                            .unwrap_or(161);
                        radio.bring_up(chan)?;
                        println!("  bring_up({chan}) via library path");
                        return Ok(());
                    }
                    radio.power_on()?;
                    radio.download_firmware(
                        ndn_face_monitor_wifi::LibUsbRtl88xxBackend::firmware_nic(),
                    )?;
                    radio.mac_init()?;
                    radio.monitor_cfg()?;
                    radio.send_general_info()?;
                    radio.phy_init()?;
                    // --chan N selects the 5 GHz channel (default 161).
                    let chan: u8 = std::env::args()
                        .position(|a| a == "--chan")
                        .and_then(|i| std::env::args().nth(i + 1))
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(161);
                    radio.set_channel_bw20(chan)?;
                    println!("  channel set to {chan}");
                    // Firmware RF calibration (channel-dependent): IQK keys the
                    // TX path + corrects IQ; DPK linearizes the PA.
                    // --noiqk: skip FW IQK/DPK (calibration is not the on-air
                    // gate — bb_tx_datapath_init below is).
                    if !std::env::args().any(|a| a == "--noiqk") {
                        radio.fw_iqk(false, false)?;
                        radio.fw_dpk()?;
                    } else {
                        println!("  skipped fw_iqk/fw_dpk (--noiqk)");
                    }
                    // Bring up the BB transmit datapath — the on-air gate. Runs
                    // last (after calibration); without it the BB never
                    // modulates queued frames. --nobbtx skips it to A/B test.
                    if !std::env::args().any(|a| a == "--nobbtx") {
                        radio.bb_tx_datapath_init()?;
                        radio.set_channel_bw20(chan)?; // re-tune after datapath init
                        println!("  BB TX datapath init applied");
                    }
                    if std::env::args().any(|a| a == "--txpwr") {
                        // Proper TXAGC reference set (clears the 0x1c90[15]
                        // write-protect first). --pwr N sets the index (default
                        // 0x3f = max); tune with the SDR.
                        let idx: u32 = std::env::args()
                            .position(|a| a == "--pwr")
                            .and_then(|i| std::env::args().nth(i + 1))
                            .and_then(|v| u32::from_str_radix(v.trim_start_matches("0x"), 16).ok())
                            .unwrap_or(0x3f);
                        radio.set_tx_power(idx)?;
                        println!("  set TX power index {idx:#x} (0x1c90[15] cleared)");
                    }
                    if std::env::args().any(|a| a == "--txblock") {
                        // A whole BB-TX sub-block is all-zeros in our config
                        // (TX DFIR / TSSI / gain-by-rate tables) — golden has
                        // real values. Write them to test if this unconfigured
                        // sub-block is what gives zero TX output.
                        for (reg, val) in [
                            (0x1a30u16, 0x02eb0800u32),
                            (0x1a34, 0x02e93800),
                            (0x1a48, 0x00080000),
                            (0x1a4c, 0xb0000080),
                            (0x1a50, 0x96080000),
                            (0x1a54, 0x1000e30b),
                            (0x1a58, 0x00005881),
                            (0x1a60, 0xfefe0000),
                            (0x1a68, 0x000000eb),
                            (0x1a6c, 0x00000015),
                            (0x1b98, 0x000a4034),
                            (0x1b9c, 0x00000088),
                            (0x1e40, 0xfffeffff),
                            (0x1e44, 0x2824201c),
                            (0x1e48, 0x3834302c),
                            (0x1e50, 0x2824201c),
                            (0x1e54, 0x3834302c),
                            (0x1e58, 0xfe44403c),
                            (0x1e60, 0x4440412f),
                            (0x1e80, 0x55005500),
                            (0x1eb8, 0x00000b00),
                        ] {
                            radio.write32(reg, val)?;
                        }
                        println!("  wrote golden BB-TX sub-block (TX DFIR/TSSI/gain)");
                    }
                    if std::env::args().any(|a| a == "--txfix") {
                        // Match golden MAC TX-control regs: REG_CR bit 9
                        // (MAC_SEC_EN — plaintext frames still traverse the TX
                        // security engine) and REG_FWHW_TXQ_CTRL+2 bit 6.
                        let cr = radio.read16(0x100)?;
                        radio.write16(0x100, cr | (1 << 9))?;
                        let txq = radio.read32(0x420)?;
                        radio.write32(0x420, txq & !(1 << 22))?;
                        println!("  set REG_CR MAC_SEC_EN + matched FWHW_TXQ_CTRL");
                    }
                    if std::env::args().any(|a| a == "--ofdm") {
                        // 0x1c3c bit 0 = OFDM block enable. The cal_init/phy
                        // tables leave it 0 → the OFDM modulator is off, so MCS
                        // frames never transmit (the RF tone still works).
                        let v = radio.read32(0x1c3c)?;
                        println!("  0x1c3c was {v:#010x} (bit0 OFDM-on = {})", v & 1);
                        radio.write32(0x1c3c, v | 1)?;
                        println!("  set OFDM block on (0x1c3c[0]=1)");
                    }
                    if std::env::args().any(|a| a == "--clearcal") {
                        // The cal_init table's IQK-phy-setup left the BB TX path
                        // in cal/debug mode (0x180c[31]/0x410c[31] path A/B,
                        // 0x1cd0[31:28], 0x1e24[17]); clear them so normal TX
                        // can drive the OFDM modulator.
                        for (reg, mask) in [
                            (0x180cu16, 0x8000_0000u32),
                            (0x410c, 0x8000_0000),
                            (0x1cd0, 0xf000_0000),
                            (0x1e24, 0x0002_0000),
                        ] {
                            let v = radio.read32(reg)? & !mask;
                            radio.write32(reg, v)?;
                        }
                        println!("  cleared BB cal-mode bits");
                    }
                    if std::env::args().any(|a| a == "--withtone") {
                        // Force RF into TX mode (like the single tone) while
                        // injecting: if the SDR sees modulation bursts over the
                        // steady carrier, the BB modulates frames fine and the
                        // real gate is per-packet RF/RFE TX switching.
                        radio.single_tone(true)?;
                        println!("  forced RF TX mode (carrier on) during inject");
                    }
                    if std::env::args().any(|a| a == "--nocca") {
                        // Disable OFDM CCA (0x1d58[11:3]=0x1ff) — if the BB
                        // always senses the channel busy, EDCA never grants a TX
                        // opportunity and the queued frame never goes out.
                        let v = radio.read32(0x1d58)? & !0xff8;
                        radio.write32(0x1d58, v | 0x1ff << 3)?;
                        println!("  disabled OFDM CCA");
                    }
                    Ok(())
                };
                let ok = match bringup() {
                    Ok(()) => {
                        println!("  bring-up OK (power→fw→mac→monitor→phy→ch161)");
                        true
                    }
                    Err(e) => {
                        println!("  bring-up FAILED: {e}");
                        false
                    }
                };
                if ok && std::env::args().any(|a| a == "--replayh2c") {
                    // Replay the firmware init H2C stream captured from the
                    // working kernel driver (usbmon) — hex lines in
                    // /tmp/h2c_seq.txt, one 32-byte packet per line. Tests
                    // whether a missing firmware TX-state command is the gate.
                    let txt = std::fs::read_to_string("/tmp/h2c_seq.txt")
                        .expect("write captured H2C hex to /tmp/h2c_seq.txt");
                    let mut n = 0;
                    for line in txt.lines().filter(|l| !l.trim().is_empty()) {
                        let bytes: Vec<u8> = (0..line.len())
                            .step_by(2)
                            .map(|i| u8::from_str_radix(&line[i..i + 2], 16).unwrap())
                            .collect();
                        radio.send_h2c_raw(&bytes)?;
                        n += 1;
                    }
                    println!("  replayed {n} captured firmware H2C packets");
                }
                if ok && std::env::args().any(|a| a == "--forcemac") {
                    // Force the MAC protocol/WMAC/scheduler registers to the
                    // values the working OPi kernel driver ends init with
                    // (captured via usbmon, 2026-06-13). These are registers my
                    // mac_init either skips (mine=0) or sets differently —
                    // candidates for the TX-FIFO-stall gate. Excludes per-device
                    // (MAC addr), status, and command (CAMCMD) registers.
                    let forced: &[(u16, u32)] = &[
                        (0x022c, 0x80000000),
                        (0x0420, 0x00311f83), // FWHW_TXQ_CTRL: clear our extra bit22
                        (0x042c, 0x40000000),
                        (0x045c, 0x10050000),
                        (0x0480, 0xa0000020), // INIRTS_RATE_SEL
                        (0x0494, 0xfe01f015), // WMAC/protection region (mine=0)
                        (0x0498, 0x40000000),
                        (0x04a4, 0x003ff015),
                        (0x04a8, 0x40000000),
                        (0x04cc, 0x08010000),
                        (0x04e0, 0x00000098), // NEED_CPU_HANDLE
                        (0x0510, 0x001c0000),
                        (0x0518, 0x09000000),
                        (0x0540, 0x00006404), // TBTT_PROHIBIT: clear our extra bit31
                        (0x0550, 0x01001018),
                        (0x0558, 0x00000204),
                        (0x0574, 0x0b000000),
                        (0x05b0, 0x00000001),
                        (0x05b4, 0x00000000),
                        (0x060c, 0x85000018),
                        (0x0638, 0x00006a50),
                        (0x0640, 0x00400021),
                        (0x066c, 0x00050002),
                        (0x06c0, 0xaaaaaaaa), // BT_COEX_TABLE
                        (0x06c4, 0xaaaaaaaa),
                        (0x06dc, 0x04840000),
                    ];
                    for &(a, v) in forced {
                        radio.write32(a, v)?;
                    }
                    println!(
                        "  forced {} MAC protocol/WMAC regs to working values",
                        forced.len()
                    );
                }
                if ok && std::env::args().any(|a| a == "--forcebb") {
                    // DIAGNOSTIC (hypothesis DISPROVEN): force the BB registers
                    // that differ from the working OPi to its values. The zeros
                    // in mine (0x1e40-0x1e60, 0x1e80, 0x1ed4) turned out to be
                    // RX-AGC / channel-measurement registers written by phydm's
                    // runtime watchdog (phydm_ccx.c / phydm_dig.c), NOT the TX
                    // datapath — the working driver's values are just the result
                    // of its watchdog having run. Forcing them CRASHES the dongle
                    // off USB (a CCX trigger like 0x1e5c). Kept only as a record.
                    let bb: &[(u16, u32)] = &[
                        (0x0820, 0x11111131),
                        (0x0828, 0x30fb181c),
                        (0x1018, 0x00000050),
                        (0x1040, 0x146cdbff),
                        (0x1044, 0x00007a00),
                        (0x1064, 0x000000f3),
                        (0x1080, 0x00050100),
                        (0x1204, 0x0011f000),
                        (0x1208, 0xa1000730),
                        (0x1330, 0x80000000),
                        (0x1448, 0x00060006),
                        (0x144c, 0x00060006),
                        (0x14c0, 0x0001a000),
                        (0x1610, 0x055e3f87),
                        (0x167c, 0x00000070),
                        (0x169c, 0x000007ce),
                        (0x1700, 0xc00f0038),
                        (0x1704, 0x00007700),
                        (0x1808, 0x0003351f),
                        (0x180c, 0x97f00063),
                        (0x1868, 0x00002801),
                        (0x18a0, 0x00330000),
                        (0x18ac, 0x00008230),
                        (0x18e8, 0x00811800),
                        (0x1a04, 0x81000008),
                        (0x1a2c, 0x12ba8000),
                        (0x1ac8, 0x00001107),
                        (0x1b00, 0x0000000a),
                        (0x1b98, 0x000a4034),
                        (0x1b9c, 0x00000088),
                        (0x1c3c, 0x01051f43),
                        (0x1c90, 0x00e41708),
                        (0x1d30, 0x50209d00),
                        (0x1e2c, 0xe4e40400),
                        (0x1e40, 0x57e457e4),
                        (0x1e44, 0x36302a24),
                        (0x1e48, 0x5a50463c),
                        (0x1e50, 0x2c282420),
                        (0x1e54, 0x3c383430),
                        (0x1e58, 0xfe484440),
                        (0x1e5c, 0xc56400ff),
                        (0x1e60, 0x786e412f),
                        (0x1e80, 0x55005500),
                        (0x1ed4, 0x800c0040),
                        (0x1ed8, 0x8005000c),
                        (0x1edc, 0x80020005),
                        (0x1ee0, 0x80000002),
                        (0x1ee4, 0xf0000000),
                        (0x1ef0, 0x30000a80),
                        (0x1ef4, 0x40001266),
                        (0x1ef8, 0x3b000100),
                    ];
                    for &(a, v) in bb {
                        radio.write32(a, v)?;
                    }
                    println!(
                        "  forced {} BB TX-datapath regs to working values",
                        bb.len()
                    );
                }
                if ok && std::env::args().any(|a| a == "--bbfix") {
                    // The 65 DISTINCT BB datapath registers (final values, in
                    // first-write order) from the working init's 0x1800-0x1fff
                    // range — the essential subset that the full replay proved
                    // unblocks on-air TX, minus the ~2000 calibration-churn
                    // writes. If this clean set transmits, it's the port.
                    let regs: &[(u16, u32)] = &[
                        (0x1d3c, 0xf8000000),
                        (0x180c, 0x97f00063),
                        (0x1c3c, 0x01051f43),
                        (0x1cd0, 0x7f000000),
                        (0x1e24, 0x80023000),
                        (0x1a04, 0x81000008),
                        (0x1a2c, 0x12ba8000),
                        (0x1d30, 0x50209d00),
                        (0x1e2c, 0xe4e40400),
                        (0x1840, 0x00002000),
                        (0x1844, 0x00003000),
                        (0x1d70, 0x20202020),
                        (0x1830, 0x70fb0001),
                        (0x1860, 0xf0041ff8),
                        (0x1810, 0x62150684),
                        (0x1868, 0x00002801),
                        (0x1818, 0x020184ff),
                        (0x1e70, 0x00001000),
                        (0x1808, 0x0003351f),
                        (0x1b00, 0x0000000a),
                        (0x1b9c, 0x00000088),
                        (0x1b98, 0x000a4034),
                        (0x1e80, 0x55005500),
                        (0x1ac8, 0x00001107),
                        (0x1ad0, 0xa33529f0),
                        (0x1e60, 0x786e412f),
                        (0x1e44, 0x36302a24),
                        (0x1e48, 0x5a50463c),
                        (0x1e5c, 0xc56400ff),
                        (0x1e40, 0x57e457e4),
                        (0x1e50, 0x2c282420),
                        (0x1e54, 0x3c383430),
                        (0x1e58, 0xfe484440),
                        (0x1ee4, 0xf0000000),
                        (0x1ed4, 0x800c0040),
                        (0x1ed8, 0x8005000c),
                        (0x1edc, 0x80020005),
                        (0x1ee0, 0x80000002),
                        (0x1e84, 0x00000000),
                        (0x18ac, 0x00008230),
                        (0x1a20, 0x52840000),
                        (0x1a24, 0x3e18fec8),
                        (0x1a28, 0x00150a88),
                        (0x1a98, 0xacc4c040),
                        (0x1a9c, 0x0006c8b2),
                        (0x1aa0, 0x00faf0de),
                        (0x1aac, 0x00122344),
                        (0x1ab0, 0x0fffffff),
                        (0x1a14, 0x111443a8),
                        (0x1a80, 0x208e7532),
                        (0x1c80, 0x2238e000),
                        (0x1944, 0x00070bcb),
                        (0x1940, 0xc1000000),
                        (0x1ee8, 0x00000000),
                        (0x1d94, 0x4038000a),
                        (0x1abc, 0x82008080),
                        (0x1ae8, 0xc2100002),
                        (0x1aec, 0x000000f6),
                        (0x1c90, 0x00e41708),
                        (0x18a0, 0x00330000),
                        (0x18e8, 0x00811800),
                        (0x1eec, 0x0280a933),
                        (0x1ef0, 0x30000a80),
                        (0x1ef4, 0x40001266),
                        (0x1ef8, 0x3b000100),
                    ];
                    for &(a, v) in regs {
                        radio.write32(a, v)?;
                    }
                    let chan: u8 = std::env::args()
                        .position(|a| a == "--chan")
                        .and_then(|i| std::env::args().nth(i + 1))
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(149);
                    let _ = radio.set_channel_bw20(chan);
                    println!(
                        "  applied {} distinct BB datapath regs; re-tuned ch{chan}",
                        regs.len()
                    );
                }
                if ok && std::env::args().any(|a| a == "--replayinit") {
                    // Replay the working driver's FULL BB/RF/cal init sequence
                    // (every captured vendor write with addr >= 0x800, in the
                    // kernel's original order) on top of my bring-up. Tests
                    // whether the complete phydm/halrf BB datapath setup — which
                    // my abbreviated phy_init skips — is what unblocks on-air TX.
                    // In-order replay avoids the out-of-order crash --forcebb hit.
                    let txt = std::fs::read_to_string("/tmp/opi_regseq.txt")
                        .expect("captured init sequence at /tmp/opi_regseq.txt");
                    let mut n = 0u32;
                    for line in txt.lines() {
                        let mut it = line.split_whitespace();
                        let (Some(a), Some(w), Some(v)) = (it.next(), it.next(), it.next()) else {
                            continue;
                        };
                        let addr = u32::from_str_radix(a.trim_start_matches("0x"), 16).unwrap_or(0);
                        let width: u8 = w.parse().unwrap_or(4);
                        let val = u32::from_str_radix(v.trim_start_matches("0x"), 16).unwrap_or(0);
                        // Range configurable via REPLAY_LO/REPLAY_HI to bisect
                        // which part of the full init is essential (default = all
                        // BB/RF/cal, 0x800..0xffff; MAC handled by mac_init).
                        let lo = std::env::var("REPLAY_LO")
                            .ok()
                            .and_then(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).ok())
                            .unwrap_or(0x800);
                        let hi = std::env::var("REPLAY_HI")
                            .ok()
                            .and_then(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).ok())
                            .unwrap_or(0xffff);
                        if addr < lo || addr > hi {
                            continue;
                        }
                        let r = match width {
                            1 => radio.write8(addr as u16, val as u8),
                            2 => radio.write16(addr as u16, val as u16),
                            _ => radio.write32(addr as u16, val),
                        };
                        if let Err(e) = r {
                            println!("  replay STALLED at {addr:#06x} (#{n}): {e}");
                            break;
                        }
                        n += 1;
                    }
                    // Re-tune to the inject channel (replay set the capture's).
                    let chan: u8 = std::env::args()
                        .position(|a| a == "--chan")
                        .and_then(|i| std::env::args().nth(i + 1))
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(149);
                    let _ = radio.set_channel_bw20(chan);
                    println!("  replayed {n} BB/RF/cal writes; re-tuned ch{chan}");
                }
                if ok && std::env::args().any(|a| a == "--macdump") {
                    // Dump the whole MAC register space (0x0..0x800) as dwords so
                    // it can be diffed against the working OPi init sequence to
                    // find a TX-scheduler/EDCA gate not in the golden value dump.
                    for addr in (0x0u16..0x2000).step_by(4) {
                        let v = radio.read32(addr).unwrap_or(0xdead_beef);
                        println!("MACDUMP {addr:#06x} {v:#010x}");
                    }
                    return Ok(());
                }
                if ok {
                    use ndn_face_monitor_wifi::{InjectFrame, McsDescriptor};
                    // --qsel N: override the TX queue selector (default MGT 0x12;
                    // try BE=0x00 to test a normal EDCA data queue).
                    if let Some(q) = std::env::args()
                        .position(|a| a == "--qsel")
                        .and_then(|i| std::env::args().nth(i + 1))
                        .and_then(|v| u8::from_str_radix(v.trim_start_matches("0x"), 16).ok())
                    {
                        radio.set_tx_qsel(q);
                        println!("  TX qsel = {q:#x}");
                    }
                    // --ep N: override the bulk-OUT endpoint (default HIGH 0x05;
                    // try 0x06 NORMAL / 0x08 LOW to test whether a different
                    // hardware DMA queue is serviced by the MAC scheduler).
                    if let Some(ep) = std::env::args()
                        .position(|a| a == "--ep")
                        .and_then(|i| std::env::args().nth(i + 1))
                        .and_then(|v| u8::from_str_radix(v.trim_start_matches("0x"), 16).ok())
                    {
                        radio.set_bulk_out(ep);
                        println!("  bulk-OUT endpoint = {ep:#x}");
                    }
                    // TX-engine control registers vs OPi golden (the master TX
                    // state machine — a global stall lives here, not per-queue).
                    for (name, addr, golden) in [
                        ("REG_CR(0x100)", 0x0100u16, 0x000006ffu32),
                        ("REG_PTCL(0x520)", 0x0520u16, 0x00002f0fu32),
                        ("REG_TXBUF(0x600)", 0x0600, 0x04004000),
                        ("REG_TCR(0x604)", 0x0604, 0x00303000),
                        ("REG_RCR(0x608)", 0x0608, 0x90000001),
                        ("REG_TX_RPT(0x60c)", 0x060c, 0x85000418),
                    ] {
                        let v = radio.read32(addr).unwrap_or(0);
                        let flag = if v == golden { "==golden" } else { "DIFF" };
                        println!("  {name:18} = {v:#010x}  (golden {golden:#010x}) {flag}");
                    }
                    let rt = tokio::runtime::Runtime::new().unwrap();
                    // Real TX-activity registers — verified to change on the
                    // WORKING OPi when it transmits (0x2de0 does NOT, it was a
                    // bogus signal). If these change here, the chip IS keying
                    // frames (gate would be weak power, not a MAC stall).
                    let txregs = [0x2d00u16, 0x2d04, 0x2d08, 0x2d20, 0x2d24, 0x2de4];
                    let txstat = || {
                        txregs
                            .iter()
                            .map(|&a| format!("{a:#06x}={:#x}", radio.read32(a).unwrap_or(0)))
                            .collect::<Vec<_>>()
                            .join(" ")
                    };
                    let txstat0 = txstat();
                    // Available pages per queue (FIFOPAGE_INFO_1/2/3 0x230/4/8
                    // [27:16]) HQ/LQ/NQ — drop if frames pile up unTX'd.
                    let pages = || {
                        let r = |a: u16| (radio.read32(a).unwrap_or(0) >> 16) & 0xfff;
                        format!("HQ={} LQ={} NQ={}", r(0x230), r(0x234), r(0x238))
                    };
                    let pages0 = pages();
                    // --secs N: inject as fast as possible for N seconds (for SDR
                    // capture overlap). Default: 20 frames at 50 ms.
                    let secs: Option<u64> = std::env::args()
                        .position(|a| a == "--secs")
                        .and_then(|i| std::env::args().nth(i + 1))
                        .and_then(|v| v.parse().ok());
                    let deadline =
                        secs.map(|s| std::time::Instant::now() + std::time::Duration::from_secs(s));
                    let n = if deadline.is_some() { usize::MAX } else { 20 };
                    match secs {
                        Some(s) => println!("\ninjecting continuously for {s}s on ch161 (MCS1)…"),
                        None => println!("\ninjecting 20 frames on ch161 (MCS1, 20 MHz)…"),
                    }
                    let mut sent = 0usize;
                    for i in 0..n {
                        if deadline.is_some_and(|dl| std::time::Instant::now() >= dl) {
                            break;
                        }
                        let payload = bytes::Bytes::from(format!("ndn-rs monitor-wifi probe #{i}"));
                        let frame = InjectFrame::broadcast(payload, McsDescriptor::CONSERVATIVE);
                        match rt.block_on(
                            <ndn_face_monitor_wifi::LibUsbRtl88xxBackend as ndn_face_monitor_wifi::FrameIo>::inject(&radio, frame),
                        ) {
                            Ok(()) => sent += 1,
                            Err(e) => {
                                println!("  inject #{i} FAILED: {e}");
                                break;
                            }
                        }
                        if deadline.is_none() {
                            std::thread::sleep(std::time::Duration::from_millis(50));
                        }
                    }
                    println!(
                        "  injected {sent} frames; pages [{pages0}] -> [{}]",
                        pages()
                    );
                    println!("  TX-activity regs BEFORE: {txstat0}");
                    println!("  TX-activity regs AFTER : {}", txstat());
                    println!(
                        "  → verify on a peer in monitor mode: \
                         sudo tcpdump -i <mon> -nn 'wlan addr2 02:4e:44:4e:00:01'"
                    );
                }
            }

            if std::env::args().any(|a| a == "--tone") {
                // Emit a continuous carrier on --chan (default 100) for --secs
                // (default 8) so an SDR can confirm whether the PA radiates at
                // all. Full bring-up first (RF configured + channel set).
                let chan: u8 = std::env::args()
                    .position(|a| a == "--chan")
                    .and_then(|i| std::env::args().nth(i + 1))
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(100);
                let secs: u64 = std::env::args()
                    .position(|a| a == "--secs")
                    .and_then(|i| std::env::args().nth(i + 1))
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(8);
                let bring = || -> Result<(), Box<dyn std::error::Error>> {
                    radio.power_on()?;
                    radio.download_firmware(
                        ndn_face_monitor_wifi::LibUsbRtl88xxBackend::firmware_nic(),
                    )?;
                    radio.mac_init()?;
                    radio.monitor_cfg()?;
                    radio.send_general_info()?;
                    radio.phy_init()?;
                    radio.set_channel_bw20(chan)?;
                    radio.fw_iqk(false, false)?;
                    radio.fw_dpk()?;
                    Ok(())
                };
                match bring() {
                    Ok(()) => println!("bring-up OK; channel {chan}"),
                    Err(e) => println!("bring-up FAILED: {e}"),
                }
                match radio.single_tone(true) {
                    Ok(()) => println!("single_tone ON — carrier {secs}s on ch{chan}"),
                    Err(e) => println!("single_tone FAILED: {e}"),
                }
                if std::env::args().any(|a| a == "--maxgain") {
                    // Crank the digital TX gain: OFDM TX-AGC reference
                    // (0x18e8/0x41e8 [16:10]) + the BB TX scaling (0x81c
                    // [20:14]). If the single-carrier strengthens in the FFT,
                    // digital gain is the lever for the weak modulated output.
                    for reg in [0x18e8u16, 0x41e8] {
                        let v = radio.read32(reg).unwrap_or(0) & !0x0001_fc00;
                        let _ = radio.write32(reg, v | (0x3f << 10));
                    }
                    let v = radio.read32(0x81c).unwrap_or(0) & !0x001f_c000;
                    let _ = radio.write32(0x81c, v | (0x3f << 14));
                    println!("  cranked digital TX gain (0x18e8/0x41e8/0x81c)");
                }
                if std::env::args().any(|a| a == "--carrier") {
                    // Also drive the BB OFDM modulator (single carrier). If the
                    // SDR spectrum gains an offset subcarrier vs the bare tone,
                    // the BB→DAC→RF datapath works.
                    match radio.single_carrier(true) {
                        Ok(()) => println!("single_carrier ON (BB modulator)"),
                        Err(e) => println!("single_carrier FAILED: {e}"),
                    }
                }
                std::thread::sleep(std::time::Duration::from_secs(secs));
                let _ = radio.single_carrier(false);
                let _ = radio.single_tone(false);
                println!("tone/carrier OFF");
            }

            if std::env::args().any(|a| a == "--mac") {
                if let Err(e) = radio.power_on() {
                    println!("power_on ERR {e}");
                }
                // Full physical EFUSE dump → logical map decode → MAC. Diff the
                // logical rows against the golden kernel-driver dump in
                // golden/opi0-2026-06-12/efuse_map.txt (MAC = logical 0x157,
                // 78:22:88:d9:93:e6 on the testbed dongle).
                match radio.efuse_dump_physical() {
                    Ok(physical) => {
                        println!("physical EFUSE: {} bytes read", physical.len());
                        match ndn_face_monitor_wifi::LibUsbRtl88xxBackend::efuse_decode_logical(
                            &physical,
                        ) {
                            Ok(logical) => {
                                for base in
                                    (0x000..0x0d0).step_by(16).chain((0x100..0x180).step_by(16))
                                {
                                    print!("logical[{base:#05x}] =");
                                    for b in &logical[base..base + 16] {
                                        print!(" {b:02x}");
                                    }
                                    println!();
                                }
                                let m = &logical[0x157..0x15d];
                                println!(
                                    "MAC @0x157 = {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                    m[0], m[1], m[2], m[3], m[4], m[5]
                                );
                            }
                            Err(e) => println!("logical decode ERR {e}"),
                        }
                    }
                    Err(e) => println!("physical dump ERR {e}"),
                }
            }
        }
        Err(e) => println!("\nbackend open failed: {e}"),
    }
    Ok(())
}

#[cfg(not(feature = "libusb-backend"))]
fn main() {
    eprintln!("build with --features libusb-backend");
    std::process::exit(1);
}
