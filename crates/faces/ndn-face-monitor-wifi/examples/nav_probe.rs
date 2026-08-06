//! #96 measurement — does an injected monitor-mode frame carry our chosen
//! **Duration/ID (NAV)** field onto the air intact, and (with a saturated victim
//! link on the same channel) does a stock 802.11 station defer to it?
//!
//! This binary is the **transmitter** half. It brings the RTL8812AU-family part up
//! exactly as `inject8812au` does (proven to radiate), then injects, at a chosen
//! rate on ch6 / 6 Mbps OFDM:
//!   - a **beacon** (mgmt/beacon) tagged SSID "NDN-NAV-B", and
//!   - a **QoS-data** frame tagged with an "NDN-NAV-D" payload marker,
//! both carrying a Duration value from `NDN_DUR` (hex, default 0x1234 = 4660 µs,
//! a plain NAV value with bit15 clear). Source MAC is fixed so the receiver can
//! filter to our frames only.
//!
//! Part (a) — Duration survives the hardware: capture on a *neutral* monitor NIC
//! (ath9k_htc / mt76x0u, not another Realtek) and read `wlan.duration` back:
//!   sudo iw dev wlu1u2 set type monitor; sudo iw dev wlu1u2 set channel 6
//!   sudo tshark -i wlu1u2 -f 'wlan src 02:4e:44:4e:88:12' \
//!       -T fields -e wlan.fc.type_subtype -e wlan.duration
//! Expect every row's duration == NDN_DUR. If the hardware clobbers it, the lease
//! needs its own frame bits (design gate, §5 of named-filter-mac-redesign.md).
//!
//! Part (b) — a stock station defers: run a saturated iperf3 over a real 802.11
//! link on ch6, inject at a high rate with a large NDN_DUR, and compare the
//! victim's throughput against NDN_DUR=0. A drop that scales with rate·duration is
//! NAV deference.
//!
//! Env: NDN_DUR (hex NAV µs, default 1234), NDN_RATE_HZ (inject rate, default 200),
//! NDN_DUR_SECS (run length, default 20), NDN_TXPWR (power index, default 3f).
#[cfg(feature = "libusb-backend")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use ndn_face_monitor_wifi::Rtl8812auBackend;
    use std::time::{Duration, Instant};

    const DESC_RATE_6M: u32 = 0x04;
    let our_mac: [u8; 6] = [0x02, 0x4e, 0x44, 0x4e, 0x88, 0x12];

    let dur: u16 = std::env::var("NDN_DUR")
        .ok()
        .and_then(|s| u16::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        .unwrap_or(0x1234);
    let rate_hz: u64 = std::env::var("NDN_RATE_HZ")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(200);
    let secs: u64 = std::env::var("NDN_DUR_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(20);

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
        b.iq_calibrate()?;
        b.lc_calibrate()?;
    }
    b.start_rx_dma()?;
    b.write8(0x522, 0x00)?; // force-clear TXPAUSE (IQK leaves it 0x3f)
    let pwr = std::env::var("NDN_TXPWR")
        .ok()
        .and_then(|s| u8::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        .unwrap_or(0x3f);
    b.set_tx_power(pwr)?;

    // Which NAV vehicle to spam. "rts"/"cts" are the canonical NAV-setting control
    // frames every compliant station defers to; "data"/"beacon" test whether a
    // broadcast frame's Duration is honoured; default sends beacon+data.
    let mode = std::env::var("NDN_MODE").unwrap_or_else(|_| "both".into());
    // A foreign RA so a victim reads the RTS/CTS as "not for me" and sets its NAV.
    let foreign: [u8; 6] = [0x02, 0xde, 0xad, 0xbe, 0xef, 0x01];
    let frames: Vec<(Vec<u8>, &str)> = match mode.as_str() {
        "rts" => vec![(build_rts(&our_mac, &foreign, dur), "rts")],
        "cts" => vec![(build_cts(&foreign, dur), "cts")],
        "data" => vec![(build_qos_data(&our_mac, b"NDN-NAV-D", dur), "data")],
        // Reception/CCA positive control: a large frame, spammed with no NAV, to
        // occupy real airtime. If this collapses the victim's iperf but the NAV
        // arms do not, the victims *do* hear us and NAV-in-frame is simply ignored.
        "flood" => vec![(build_qos_data(&our_mac, &[0x5a; 1400], dur), "flood")],
        "beacon" => vec![(build_beacon(&our_mac, 6, b"NDN-NAV-B", dur), "beacon")],
        _ => vec![
            (build_beacon(&our_mac, 6, b"NDN-NAV-B", dur), "beacon"),
            (build_qos_data(&our_mac, b"NDN-NAV-D", dur), "data"),
        ],
    };
    let labels: Vec<&str> = frames.iter().map(|(_, l)| *l).collect();
    println!(
        "injecting {labels:?} dur={dur:#06x} ({dur} us) @ {rate_hz} Hz for {secs}s \
         on ch6 6Mbps; src={our_mac:02x?}"
    );

    let period = Duration::from_micros(1_000_000 / rate_hz.max(1));
    let end = Instant::now() + Duration::from_secs(secs);
    let mut sent = 0u64;
    // Endpoint 0x04 is the one that radiated in the inject8812au sweep.
    while Instant::now() < end {
        for (f, _) in &frames {
            b.send_frame_ep(0x04, f, DESC_RATE_6M)?;
        }
        sent += 1;
        if sent % rate_hz == 0 {
            println!("  … {sent} rounds");
        }
        std::thread::sleep(period);
    }
    println!("done: {sent} rounds (×{} frames)", frames.len());
    Ok(())
}

/// Beacon with a caller-chosen Duration (normally 0 for a real beacon).
#[cfg(feature = "libusb-backend")]
fn build_beacon(src: &[u8; 6], channel: u8, ssid: &[u8], dur: u16) -> Vec<u8> {
    let mut f = Vec::with_capacity(64);
    f.extend_from_slice(&[0x80, 0x00]); // FC: mgmt, beacon
    f.extend_from_slice(&dur.to_le_bytes()); // duration/ID
    f.extend_from_slice(&[0xff; 6]); // addr1 = broadcast
    f.extend_from_slice(src); // addr2 = SA
    f.extend_from_slice(src); // addr3 = BSSID
    f.extend_from_slice(&[0x00, 0x00]); // seq (HW overwrites)
    f.extend_from_slice(&[0u8; 8]); // timestamp
    f.extend_from_slice(&[0x64, 0x00]); // beacon interval
    f.extend_from_slice(&[0x00, 0x00]); // capability
    f.push(0x00);
    f.push(ssid.len() as u8);
    f.extend_from_slice(ssid);
    f.extend_from_slice(&[0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24]);
    f.extend_from_slice(&[0x03, 0x01, channel]);
    f
}

/// A QoS-data frame (the frame class the named-radio lease actually rides) to a
/// broadcast addr1, carrying a caller-chosen Duration and a payload marker.
#[cfg(feature = "libusb-backend")]
fn build_qos_data(src: &[u8; 6], marker: &[u8], dur: u16) -> Vec<u8> {
    let mut f = Vec::with_capacity(64);
    f.extend_from_slice(&[0x88, 0x00]); // FC: data, subtype QoS-data
    f.extend_from_slice(&dur.to_le_bytes()); // duration/ID
    f.extend_from_slice(&[0xff; 6]); // addr1 = broadcast (receiver/DA)
    f.extend_from_slice(src); // addr2 = TA/SA
    f.extend_from_slice(src); // addr3 = BSSID
    f.extend_from_slice(&[0x00, 0x00]); // seq (HW overwrites)
    f.extend_from_slice(&[0x00, 0x00]); // QoS control
    f.extend_from_slice(marker);
    f
}

/// An RTS control frame (FC 0xB4) — the canonical NAV-setting frame. A station
/// hearing an RTS whose RA is not its own sets its NAV to this Duration.
#[cfg(feature = "libusb-backend")]
fn build_rts(ta: &[u8; 6], ra: &[u8; 6], dur: u16) -> Vec<u8> {
    let mut f = Vec::with_capacity(16);
    f.extend_from_slice(&[0xb4, 0x00]); // FC: control, RTS
    f.extend_from_slice(&dur.to_le_bytes());
    f.extend_from_slice(ra); // addr1 = RA
    f.extend_from_slice(ta); // addr2 = TA
    f
}

/// A CTS control frame (FC 0xC4) — like CTS-to-self. Stations hearing it set NAV.
#[cfg(feature = "libusb-backend")]
fn build_cts(ra: &[u8; 6], dur: u16) -> Vec<u8> {
    let mut f = Vec::with_capacity(10);
    f.extend_from_slice(&[0xc4, 0x00]); // FC: control, CTS
    f.extend_from_slice(&dur.to_le_bytes());
    f.extend_from_slice(ra); // addr1 = RA
    f
}

#[cfg(not(feature = "libusb-backend"))]
fn main() {
    eprintln!("build with --features libusb-backend");
}
