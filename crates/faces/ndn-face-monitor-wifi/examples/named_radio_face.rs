//! Wire the RTL8812EU userspace driver into a named-radio [`MonitorWifiFace`]
//! and transmit NDN frames on 5 GHz monitor mode — no kernel driver.
//!
//! ```text
//! cargo run --example named_radio_face -p ndn-face-monitor-wifi \
//!     --features libusb-backend -- [channel] [count]
//! ```
//!
//! Verify on a peer in monitor mode on the same channel:
//! `sudo tcpdump -i <mon> -nn 'wlan addr2 02:4e:44:4e:00:01'`.

#[cfg(feature = "libusb-backend")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use bytes::Bytes;
    use ndn_face_monitor_wifi::{
        FaceId, InjectFrame, LibUsbRtl88xxBackend, McsDescriptor, MonitorWifiFace, FrameIo,
    };
    use std::sync::Arc;

    let channel: u8 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(149);
    let count: usize = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(500);
    // argv[3] = fixed MCS index (for a PER/goodput-vs-rate sweep), argv[4] =
    // payload bytes (large frames make on-air time, not USB, the bottleneck).
    let mcs_idx: u8 = std::env::args()
        .nth(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let psize: usize = std::env::args()
        .nth(4)
        .and_then(|s| s.parse().ok())
        .unwrap_or(7);

    // One call: find the dongle, run the full monitor-mode bring-up (power,
    // firmware, MAC, BB/RF + calibration, and the BB transmit datapath), and
    // hand back a TX/RX-ready backend.
    let backend = Arc::new(LibUsbRtl88xxBackend::open_monitor(channel)?);
    // Self-maintaining link: the DM watchdog (thermal TX-power tracking + RX
    // DIG) ticks every 2 s on its own thread for the backend's lifetime.
    let _watchdog = backend.spawn_watchdog();
    // RADIO_BW=40|80|10|5 switches the channel bandwidth (`channel` is the
    // primary 20 MHz). Default 20 MHz.
    if let Ok(s) = std::env::var("RADIO_BW") {
        use ndn_face_monitor_wifi::ChannelBw;
        let bw = match s.as_str() {
            "40" => ChannelBw::Bw40,
            "80" => ChannelBw::Bw80,
            "10" => ChannelBw::Nb10,
            "5" => ChannelBw::Nb5,
            _ => ChannelBw::Bw20,
        };
        backend.set_channel(channel, bw)?;
        println!("bandwidth set to {s} MHz (primary ch{channel})");
    }
    // RADIO_CSD=1 enables Cyclic Shift Diversity: 1-stream OFDM frames go out
    // both antennas with the standard cyclic shift (TX diversity, no rate cost).
    // Mutually exclusive with STBC. Call after the channel/bandwidth is set.
    if std::env::var("RADIO_CSD").is_ok() {
        backend.set_tx_csd(true)?;
        let r820 = backend.read32(0x820)?;
        println!(
            "CSD enabled — 0x820={r820:#06x}, 1SS OFDM path[1:0]={} (3=AB both antennas)",
            r820 & 0x3
        );
    }
    // RADIO_EDCCA_IGNORE=1 makes the MAC ignore EDCCA → transmit named data
    // under contention instead of deferring (data-centric, not AP-etiquette).
    if std::env::var("RADIO_EDCCA_IGNORE").is_ok() {
        backend.set_edcca_ignore(true)?;
        println!("EDCCA ignored — TX will not defer to in-air energy");
    }
    // RADIO_EDCCA="<l2h>[,<h2l>]" (dBm) raises the EDCCA busy/clear thresholds
    // so ordinary traffic no longer holds off our TX (h2l defaults to l2h-8).
    if let Ok(s) = std::env::var("RADIO_EDCCA") {
        let mut it = s.split(',');
        let l2h: i8 = it.next().and_then(|v| v.trim().parse().ok()).unwrap_or(10);
        let h2l: i8 = it.next().and_then(|v| v.trim().parse().ok()).unwrap_or(l2h - 8);
        backend.set_edcca_threshold(l2h, h2l)?;
        println!("EDCCA threshold set: L2H={l2h} dBm, H2L={h2l} dBm");
    }
    println!("RTL8812EU up on 5 GHz ch{channel} (monitor mode)");
    // RADIO_TXPWR=<idx hex> raises the TXAGC reference (0x3f = max) to probe
    // whether the link is power-starved at higher MCS.
    if let Ok(p) = std::env::var("RADIO_TXPWR")
        && let Ok(idx) = u32::from_str_radix(p.trim_start_matches("0x"), 16)
    {
        backend.set_tx_power(idx)?;
        println!("TX power index set to {idx:#x}");
    }
    // RADIO_PERRATE=1: write the per-rate TXAGC table (0x3a00) the working
    // driver sets (OFDM/HT rates at index 0x7c) — our bb_tx_datapath_init never
    // does, so OFDM/HT rates likely TX at near-zero per-rate power. Clear the
    // 0x1c90[15] write-protect first.
    if std::env::var("RADIO_RFGAIN").is_ok() {
        backend.force_max_tx_gain()?;
        println!("forced max RF TX gain (RF 0x00[4:0]=0)");
    }
    if std::env::var("RADIO_PERRATE").is_ok() {
        let v = backend.read32(0x1c90)? & !(1 << 15);
        backend.write32(0x1c90, v)?;
        for (a, val) in [
            (0x3a04u16, 0x02020202u32),
            (0x3a08, 0x02020202),
            (0x3a14, 0x7c7c7c7c),
            (0x3a18, 0x7c7c7c7c),
            (0x3a34, 0x7c7c0000),
            (0x3a38, 0x7c7c7c7c),
            (0x3a3c, 0x7c7c7c7c),
        ] {
            backend.write32(a, val)?;
        }
        println!("per-rate TXAGC table (0x3a00) written");
    }

    // Build the named-radio face. Mount it on a ForwarderEngine with
    // `face.into_face()`; the LpLinkService then fragments/reassembles NDN
    // packets across injected frames. `MonitorWifiFace::open_libusb(id, channel)`
    // collapses the two steps above into one when you don't need the backend
    // handle.
    let _face = MonitorWifiFace::new(FaceId(1), backend.clone());

    // Flood `count` frames of `psize` pattern bytes at fixed MCS `mcs_idx`.
    //   RADIO_VHT=1  inject 802.11ac (VHT) instead of 802.11n (HT)
    //   RADIO_NSS=2  VHT 2-stream (needs VHT; HT stream count is in mcs_idx)
    //   RADIO_STBC=1 space-time diversity (1 stream over both antennas)
    //   RADIO_LDPC=1 LDPC FEC instead of BCC
    let data: Bytes = (0..psize).map(|i| (i & 0xff) as u8).collect();
    let vht = std::env::var("RADIO_VHT").is_ok();
    let nss2 = std::env::var("RADIO_NSS").ok().as_deref() == Some("2");
    let mut mcs = match (vht, nss2) {
        (true, true) => McsDescriptor::vht_2ss(mcs_idx),
        (true, false) => McsDescriptor::vht(mcs_idx),
        (false, _) => McsDescriptor::ht(mcs_idx),
    };
    if std::env::var("RADIO_STBC").is_ok() {
        mcs = mcs.with_stbc();
    }
    if std::env::var("RADIO_LDPC").is_ok() {
        mcs = mcs.with_ldpc();
    }
    let phy = if vht { "VHT" } else { "HT" };
    let coding = match (mcs.stbc, mcs.ldpc) {
        (true, true) => " +STBC +LDPC",
        (true, false) => " +STBC",
        (false, true) => " +LDPC",
        (false, false) => "",
    };
    println!("flooding {count} x {psize}-byte frames at {phy} MCS{mcs_idx}{coding}…");
    let t0 = std::time::Instant::now();
    for _ in 0..count {
        backend
            .inject(InjectFrame::broadcast(data.clone(), mcs))
            .await?;
    }
    let dt = t0.elapsed().as_secs_f64();
    // Let the chip drain its TX FIFO on-air before we close the USB handle.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    println!(
        "transmitted {count} frames in {dt:.2}s ({:.0} fps) at MCS{mcs_idx}",
        count as f64 / dt
    );
    Ok(())
}

#[cfg(not(feature = "libusb-backend"))]
fn main() {
    eprintln!("rebuild with `--features libusb-backend` (needs an RTL8812EU dongle)");
}
