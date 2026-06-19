//! On-air link test between two co-located userspace drivers on one host:
//! the **RTL8812EU** (`LibUsbRtl88xxBackend`) and the **RTL8811CU**
//! (`Rtl8821cuBackend`), both in 5 GHz monitor mode. One injects a marker
//! frame, the other listens; hearing it proves the transmitter *radiates*
//! (not just that its FIFO drains).
//!
//! Default: 8811CU TX → 8812EU RX (tests the new driver's TX).
//! `NDN_RADIO_REVERSE=1`: 8812EU TX → 8811CU RX (validates the harness using the
//! 8812EU's verified TX + the 8811CU's verified RX).
//! `cargo run -p ndn-face-monitor-wifi --features libusb-backend --example tx_onair`
#[cfg(feature = "libusb-backend")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use bytes::Bytes;
    use ndn_face_monitor_wifi::{
        FrameIo, InjectFrame, LibUsbRtl88xxBackend, McsDescriptor, Rtl8821cuBackend,
    };
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    let ch: u8 = std::env::var("NDN_RADIO_CHANNEL").ok().and_then(|s| s.parse().ok()).unwrap_or(36);
    let reverse = std::env::var("NDN_RADIO_REVERSE").is_ok();
    const MARKER: &[u8] = b"TXONAIR-link";

    // Open both, picking RX vs TX role per `reverse`. spawn_rx_pump is on the
    // concrete type, so bring up the RX device's pump before casting to dyn.
    // When the c811 is the receiver, keep a concrete handle to read its raw RX
    // counter (ambient included) — tells us if its RX survives the dual-device
    // USB context vs. just that no NDN markers matched.
    let mut c811_rx: Option<Arc<Rtl8821cuBackend>> = None;
    let (tx, rx, tx_name, rx_name): (Arc<dyn FrameIo>, Arc<dyn FrameIo>, _, _) = if reverse {
        println!("RX: RTL8811CU (0bda:c811) monitor ch {ch}");
        let rxc = Arc::new(Rtl8821cuBackend::open_monitor(ch)?);
        rxc.spawn_rx_pump(4);
        c811_rx = Some(rxc.clone());
        println!("TX: RTL8812EU (0bda:a81a) monitor ch {ch}");
        let tx = Arc::new(LibUsbRtl88xxBackend::open_monitor(ch)?);
        (tx, rxc, "8812EU", "8811CU")
    } else {
        println!("RX: RTL8812EU (0bda:a81a) monitor ch {ch}");
        let rx = Arc::new(LibUsbRtl88xxBackend::open_monitor(ch)?);
        rx.spawn_rx_pump(4);
        println!("TX: RTL8811CU (0bda:c811) monitor ch {ch}");
        let tx = Arc::new(Rtl8821cuBackend::open_monitor(ch)?);
        (tx, rx, "8811CU", "8812EU")
    };

    let tx_task = {
        let tx = tx.clone();
        tokio::spawn(async move {
            for i in 0..600u32 {
                let mut p = MARKER.to_vec();
                p.extend_from_slice(&i.to_le_bytes());
                let _ = tx
                    .inject(InjectFrame::broadcast(Bytes::from(p), McsDescriptor::CONSERVATIVE))
                    .await;
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
    };

    // Radiation proof is payload-independent: count frames whose source addr2 is
    // our injector MAC (DEFAULT_SRC). Works for both data frames (marker payload)
    // and probe-reqs (NDN_RADIO_PROBE, marker in a vendor IE) which don't parse to
    // an NDN payload but still carry our addr2.
    const OUR_SRC: [u8; 6] = [0x02, 0x4e, 0x44, 0x4e, 0x00, 0x01];
    println!("{rx_name} listening 6 s for {tx_name}-injected frames ...");
    let deadline = Instant::now() + Duration::from_secs(6);
    let (mut heard, mut other, mut from_src) = (0u32, 0u32, 0u32);
    while Instant::now() < deadline {
        if let Ok(Ok(f)) = tokio::time::timeout(Duration::from_millis(500), rx.recv_frame()).await {
            if f.addr == Some(OUR_SRC) {
                from_src += 1;
                if from_src <= 3 {
                    println!("  FROM-US #{from_src}: src={:?} grp={:?} {} bytes rssi={:?} mcs={:?}",
                        f.addr, f.group, f.payload.len(), f.rssi_dbm, f.mcs_index);
                }
            }
            if f.payload.starts_with(MARKER) {
                heard += 1;
            } else {
                other += 1;
            }
        }
    }
    let _ = tx_task.await;
    println!("(frames received with our source addr2 {OUR_SRC:02x?}: {from_src})");

    if let Some(c) = &c811_rx {
        println!("(c811 RX raw frames seen during test, ambient incl.: {})", c.raw_rx_count());
    }
    println!("\nRESULT: {rx_name} heard {heard} {tx_name} frames ({other} other NDN frames).");
    if heard > 0 {
        println!("  ✅ {tx_name} TX RADIATES — confirmed on air by {rx_name}.");
    } else {
        println!("  ❌ {rx_name} heard no {tx_name} frames.");
    }
    Ok(())
}
#[cfg(not(feature = "libusb-backend"))]
fn main() {}
