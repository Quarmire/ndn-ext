//! Milestone 8 bring-up: bring the RTL8812AU all the way up (M1–M7 + M6), then
//! either inject a beacon at legacy 6 Mbps OFDM on channel 6 (`tx`, default) or
//! capture and print whatever is on the channel (`rx`). Run on the OPi on the
//! blacklisted/clean device:
//!   sudo modprobe -r rtw88_8812au
//!   sudo NDN_RADIO_NO_RESET=1 LD_LIBRARY_PATH=$(nix path-info nixpkgs#libusb1)/lib \
//!       ./target/debug/examples/inject8812au [tx|rx]
//! Verify TX on a second monitor radio (the wlu1 8812EU) sniffing ch6:
//!   tshark -i wlu1 -f 'wlan[0]==0x80' -Y 'wlan.ssid=="NDN-8812AU-TEST"'
#[cfg(feature = "libusb-backend")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use ndn_face_monitor_wifi::Rtl8812auBackend;
    use std::time::Duration;

    let mode = std::env::args().nth(1).unwrap_or_else(|| "tx".into());
    const DESC_RATE_6M: u32 = 0x04;
    let our_mac: [u8; 6] = [0x02, 0x4e, 0x44, 0x4e, 0x88, 0x12]; // "NDN" + 8812

    // ── Bring the radio up (M1–M7 + M6) ──
    let b = Rtl8812auBackend::open()?;
    println!("opened RTL8812AU pid={:#06x}", b.pid());
    b.power_on()?;
    b.mac_enable_dma()?;
    b.init_llt()?;
    let (ver, sub) = b.download_firmware()?;
    println!("✓ firmware {ver}.{sub} up");
    b.mac_config()?;
    b.mac_init_queues()?;
    b.bb_config()?;
    b.rf_config()?;
    b.set_channel(6)?;
    if std::env::var_os("NDN_SKIP_CAL").is_none() {
        let iqk = b.iq_calibrate()?;
        b.lc_calibrate()?;
        println!(
            "✓ radio up on ch6 — IQK A.TX={} B.TX={}",
            iqk.tx_a, iqk.tx_b
        );
    } else {
        println!("✓ radio up on ch6 — calibration SKIPPED (NDN_SKIP_CAL)");
    }
    // Release RX DMA LAST — calibration re-pauses it (RW_RELEASE_EN), so this
    // must follow iq_calibrate to take effect.
    b.start_rx_dma()?;

    if mode == "rxdiag" {
        // Dump the RX datapath registers to see why bulk-IN delivers nothing.
        println!(
            "CR(0x100)        = {:#06x}  (MACRXEN bit7)",
            b.read16(0x100)?
        );
        println!("RCR(0x608)       = {:#010x}", b.read32(0x608)?);
        println!("TRXDMA_CTRL(0x10C)= {:#06x}", b.read16(0x10c)?);
        println!("RXFF_BNDY(0x114) = {:#06x}", b.read16(0x114)?);
        println!(
            "RXDMA_AGG_PG_TH(0x280) = {:#06x}  (lo=pages hi=timeout)",
            b.read16(0x280)?
        );
        let pktnum = b.read32(0x284)?;
        println!(
            "RXPKT_NUM(0x284) = {:#010x}  RXDMA_IDLE(bit17)={} RW_RELEASE(bit18)={}",
            pktnum,
            (pktnum >> 17) & 1,
            (pktnum >> 18) & 1
        );
        println!("RXDMA_STATUS(0x288) = {:#010x}", b.read32(0x288)?);
        println!("USB_SPECIAL_OPT(0xFE55) = {:#04x}", b.read8(0xfe55)?);
        println!(
            "USB_AGG_TO(0xFE5C)/TH(0xFE5D) = {:#04x}/{:#04x}",
            b.read8(0xfe5c)?,
            b.read8(0xfe5d)?
        );
        return Ok(());
    }

    if mode == "rxraw" {
        println!("raw bulk-IN reads on ch6 (RX DMA check) …");
        let mut buf = vec![0u8; 16384];
        for i in 0..40 {
            let n = b.rx_raw(&mut buf)?;
            if n > 0 {
                let hd = &buf[..n.min(32)];
                println!("read #{i}: {n} bytes  head={hd:02x?}");
            }
        }
        return Ok(());
    }

    if mode == "rx" {
        println!("capturing on ch6 (Ctrl-C to stop) …");
        let mut heard = 0u64;
        loop {
            if let Some(f) = b.poll_frame()? {
                heard += 1;
                let fc = f.payload.first().copied().unwrap_or(0);
                let (typ, sub) = ((fc >> 2) & 0x3, (fc >> 4) & 0xf);
                println!(
                    "#{heard:<4} len={:<4} type={typ} subtype={sub} src={:02x?} → {:02x?}",
                    f.payload.len(),
                    f.addr.unwrap_or_default(),
                    f.group.unwrap_or_default(),
                );
            }
        }
    }

    // Diagnostics: is TX paused / enabled after calibration?
    println!(
        "TXPAUSE(0x522)={:#04x}  CR(0x100)={:#06x}  (MACTXEN bit6, MACRXEN bit7)",
        b.read8(0x522)?,
        b.read16(0x100)?
    );
    // The IQK leaves TXPAUSE=0x3f (not in its backup set); force-clear it so all
    // TX queues are released before injecting.
    b.write8(0x522, 0x00)?;
    println!("TXPAUSE force-cleared → {:#04x}", b.read8(0x522)?);

    // TX power: the per-rate power-by-rate registers are unset (PA silent), so
    // load a uniform mid power index.
    println!(
        "TXAGC OFDM6-18 A(0xC24)={:#010x} B(0xE24)={:#010x} before",
        b.read32(0xC24)?,
        b.read32(0xE24)?
    );
    let pwr = std::env::var("NDN_TXPWR")
        .ok()
        .and_then(|s| u8::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        .unwrap_or(0x3f);
    b.set_tx_power(pwr)?;
    println!(
        "TXAGC after set_tx_power({pwr:#04x}): A(0xC24)={:#010x} B(0xE24)={:#010x}",
        b.read32(0xC24)?,
        b.read32(0xE24)?
    );

    // ── TX: inject a beacon on each OUT endpoint, tagged by SSID, every 100 ms.
    // Whichever endpoint actually radiates shows up in the sniffer's SSID. ──
    let eps: [(u8, &[u8]); 3] = [
        (0x02, b"NDN-EP02"),
        (0x03, b"NDN-EP03"),
        (0x04, b"NDN-EP04"),
    ];
    let beacons: Vec<Vec<u8>> = eps
        .iter()
        .map(|(_, ssid)| build_beacon(&our_mac, 6, ssid))
        .collect();
    println!("injecting beacons on EP 0x02/0x03/0x04 at 6 Mbps OFDM on ch6 …");
    let mut sent = 0u64;
    loop {
        for (i, (ep, _)) in eps.iter().enumerate() {
            if let Err(e) = b.send_frame_ep(*ep, &beacons[i], DESC_RATE_6M) {
                eprintln!("send on {ep:#04x} failed after {sent}: {e}");
                return Err(e.into());
            }
        }
        sent += 1;
        if sent % 10 == 0 {
            println!("  … {sent} rounds sent (×3 EPs)");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// A minimal valid 802.11 beacon: mgmt header + fixed params + SSID / rates / DS.
#[cfg(feature = "libusb-backend")]
fn build_beacon(src: &[u8; 6], channel: u8, ssid: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(64);
    f.extend_from_slice(&[0x80, 0x00]); // FC: mgmt, beacon
    f.extend_from_slice(&[0x00, 0x00]); // duration
    f.extend_from_slice(&[0xff; 6]); // addr1 = broadcast
    f.extend_from_slice(src); // addr2 = SA
    f.extend_from_slice(src); // addr3 = BSSID
    f.extend_from_slice(&[0x00, 0x00]); // seq (HW overwrites)
    f.extend_from_slice(&[0u8; 8]); // timestamp
    f.extend_from_slice(&[0x64, 0x00]); // beacon interval (100 TU)
    f.extend_from_slice(&[0x00, 0x00]); // capability
    f.push(0x00); // SSID element
    f.push(ssid.len() as u8);
    f.extend_from_slice(ssid);
    // Supported rates: 1, 2, 5.5, 11, 6, 9, 12, 18 Mbps.
    f.extend_from_slice(&[0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24]);
    f.extend_from_slice(&[0x03, 0x01, channel]); // DS parameter set (channel)
    f
}

#[cfg(not(feature = "libusb-backend"))]
fn main() {
    eprintln!("build with --features libusb-backend");
}
