//! **On-air NAN data path between two nodes.**
//!
//! The end-to-end Phase 2 test: bring a radio up, create a real NAN Data
//! Interface, negotiate an NDP over the air with the M1–M4 handshake, then send
//! UDP over the socket `request_ndp` hands back.
//!
//! Both nodes request a path from each other. There is no accept side in the
//! `NanBackend` trait, and the data-path port is well-known, so each node binds
//! `[fe80::<its iid>%nan0]:6363` and can therefore receive what the other sends.
//!
//! Run (o5p-0 has the RTL8812AU; o5p-1's 8812EU goes through AF_PACKET monitor):
//! ```text
//! # o5p-0
//! sudo modprobe -r rtw88_8812au
//! sudo NDN_RADIO_NO_RESET=1 LD_LIBRARY_PATH=$(nix path-info nixpkgs#libusb1)/lib \
//!     ./target/debug/examples/nan_ndp 8812au a
//! # o5p-1
//! sudo iw dev wlu1 set type monitor && sudo ip link set wlu1 up && sudo iw dev wlu1 set channel 6
//! sudo ./target/debug/examples/nan_ndp afpacket:wlu1 b
//! ```
#[cfg(all(feature = "libusb-backend", target_os = "linux"))]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;
    use std::time::Duration;

    use ndn_face_wifi_aware::{NanBackend, NanServiceName};
    use ndn_frame_io::{AfPacketBackend, FrameFormat, FrameIo};
    use ndn_nan::ndi::NdiInterface;
    use ndn_nan_core::NanConfig;

    // Node identities. The NMI carries discovery; the NDI is the data interface
    // whose EUI-64 becomes the address a path is negotiated to.
    const NMI_A: [u8; 6] = [0x02, 0x4e, 0x41, 0x4e, 0x00, 0x31];
    const NMI_B: [u8; 6] = [0x02, 0x4e, 0x41, 0x4e, 0x00, 0x32];
    const NDI_A: [u8; 6] = [0x02, 0x4e, 0x44, 0x49, 0x00, 0x31];
    const NDI_B: [u8; 6] = [0x02, 0x4e, 0x44, 0x49, 0x00, 0x32];
    const SERVICE: &str = "org.ndn.ndp";

    let radio_arg = std::env::args().nth(1).unwrap_or_else(|| "8812au".into());
    let node = std::env::args().nth(2).unwrap_or_else(|| "a".into());
    // `measure` reports how well we hear the peer, without running the stack:
    // link quality is the thing to establish before blaming anything above it.
    let measure = std::env::args().nth(3).as_deref() == Some("measure");
    let (nmi, ndi_mac, peer_nmi) = if node == "a" {
        (NMI_A, NDI_A, NMI_B)
    } else {
        (NMI_B, NDI_B, NMI_A)
    };

    // ── The radio ──
    let radio: Arc<dyn FrameIo> = if let Some(iface) = radio_arg.strip_prefix("afpacket:") {
        println!("[{node}] radio: AF_PACKET monitor on {iface}");
        Arc::new(AfPacketBackend::new(iface, FrameFormat::Raw80211)?)
    } else {
        use ndn_phy_wifi::Rtl8812auBackend;
        let b = Rtl8812auBackend::open()?;
        println!(
            "[{node}] radio: RTL8812AU pid={:#06x} — bringing up",
            b.pid()
        );
        b.power_on()?;
        b.mac_enable_dma()?;
        b.init_llt()?;
        let (ver, sub) = b.download_firmware()?;
        b.mac_config()?;
        b.mac_init_queues()?;
        b.bb_config()?;
        b.rf_config()?;
        b.set_channel(6)?;
        b.iq_calibrate()?;
        b.lc_calibrate()?;
        b.set_tx_power(0x3f)?;
        b.start_rx_dma()?; // last: calibration re-pauses RX DMA
        let b = Arc::new(b);
        // Keep a bulk-IN read always in flight; without it we only read during a
        // recv_frame call and lose whatever arrives in between (see
        // Rtl8812auBackend::spawn_rx_pump). Depth 1 — one reader, so ordered.
        b.spawn_rx_pump(1);
        println!("[{node}] ✓ 8812AU up (fw {ver}.{sub}) on ch6, TX max, RX pumped");
        b
    };

    if measure {
        return measure_link(radio, peer_nmi, &node).await;
    }

    // ── The data interface ──
    let ndi = Arc::new(NdiInterface::open("nan0", ndi_mac)?);
    println!(
        "[{node}] ✓ NDI {} mac={} link_local={}",
        ndi.name(),
        mac(&ndi_mac),
        ndi.link_local()
    );

    // ── The NAN stack, with the NDI bridged to the radio ──
    let cfg = NanConfig::new(nmi, 6, if node == "a" { 200 } else { 180 }).with_ndi(ndi_mac);
    let driver = ndn_nan::spawn_with(radio, cfg, None, Some(ndi.clone()));
    let svc = NanServiceName(SERVICE.to_string());
    driver.publish(&svc).await?;
    driver.subscribe(&svc).await?;
    println!("[{node}] NAN up: nmi={} service={SERVICE:?}", mac(&nmi));

    // ── Discovery (not required for request_ndp, but proves we hear each other) ──
    let seen = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if driver.drain_matches().iter().any(|m| m.peer == peer_nmi) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap_or(false);
    println!(
        "[{node}] discovery of {}: {}",
        mac(&peer_nmi),
        if seen { "✓ heard" } else { "✗ NOT heard" }
    );

    // ── The data path ──
    println!("[{node}] requesting NDP to {} …", mac(&peer_nmi));
    let link = match driver.request_ndp(peer_nmi).await {
        Ok(l) => l,
        Err(e) => {
            println!("[{node}] ✗ NDP FAILED: {e}");
            return Ok(());
        }
    };
    println!(
        "[{node}] ★ NDP UP: local={} peer={}",
        link.socket.local_addr()?,
        link.peer_addr
    );

    // ── Carry traffic over it ──
    // Keep sending for the whole window rather than stopping at the first
    // receive: the peer only hears us while it is still running, so an early
    // return would starve it and make a working link look one-directional.
    let mut got = 0u32;
    for i in 0..20 {
        let msg = format!("hello-from-{node}-{i}");
        let _ = link.socket.send_to(msg.as_bytes(), link.peer_addr).await;
        let mut buf = [0u8; 256];
        match tokio::time::timeout(Duration::from_millis(700), link.socket.recv_from(&mut buf))
            .await
        {
            Ok(Ok((n, from))) => {
                got += 1;
                println!(
                    "[{node}] ★★ RECEIVED over the NDP: {:?} from {from}",
                    String::from_utf8_lossy(&buf[..n])
                );
            }
            Ok(Err(e)) => println!("[{node}] recv error: {e}"),
            Err(_) => {}
        }
    }
    println!("[{node}] data path carried {got} datagram(s) inbound");
    Ok(())
}

/// Report the peer's signal and how many of its frames actually reach us.
///
/// The peer beacons once per Discovery Window (512 TU ≈ 524 ms), so ~11 frames
/// should arrive in 6 s. Anything far below that is the link, not the stack.
#[cfg(all(feature = "libusb-backend", target_os = "linux"))]
async fn measure_link(
    radio: std::sync::Arc<dyn ndn_frame_io::FrameIo>,
    peer_nmi: [u8; 6],
    node: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use ndn_nan_core::frame::classify;
    use std::time::{Duration, Instant};

    println!("[{node}] measuring {} for 30s …", mac(&peer_nmi));
    let start = Instant::now();
    let (mut heard, mut rssi_sum, mut rssi_n, mut worst, mut best) =
        (0u32, 0i32, 0u32, 0i8, -128i8);
    let mut window = Instant::now();
    let mut in_window = 0u32;

    while start.elapsed() < Duration::from_secs(30) {
        let Ok(cf) = radio.recv_frame().await else {
            break;
        };
        let Ok(f) = classify(&cf.payload) else {
            continue;
        };
        if f.header.addr2 != peer_nmi {
            continue;
        }
        heard += 1;
        in_window += 1;
        if let Some(r) = cf.rssi_dbm {
            rssi_sum += r as i32;
            rssi_n += 1;
            if r < worst || worst == 0 {
                worst = r;
            }
            if r > best {
                best = r;
            }
        }
        if window.elapsed() >= Duration::from_secs(6) {
            let avg = if rssi_n > 0 {
                rssi_sum / rssi_n as i32
            } else {
                0
            };
            println!(
                "[{node}] 6s window: {in_window} frames from peer (expect ~11 beacons) | \
                 rssi avg {avg} best {best} worst {worst} dBm"
            );
            window = Instant::now();
            in_window = 0;
        }
    }
    let avg = if rssi_n > 0 {
        rssi_sum / rssi_n as i32
    } else {
        0
    };
    println!(
        "[{node}] TOTAL: {heard} frames from the peer in 30s (expect ~57) | rssi avg {avg} dBm"
    );
    Ok(())
}

#[cfg(all(feature = "libusb-backend", target_os = "linux"))]
fn mac(m: &[u8; 6]) -> String {
    m.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

// The stub also covers non-Linux: this example drives `AfPacketBackend` and `ndn_nan::ndi`, both
// `#[cfg(target_os = "linux")]`, so gating on the feature alone made
// `cargo build --all-targets --all-features` fail to compile on macOS — a build break that only
// appeared under a flag combination nobody routinely ran.
#[cfg(not(all(feature = "libusb-backend", target_os = "linux")))]
fn main() {
    eprintln!("nan_ndp needs Linux + --features libusb-backend");
}
