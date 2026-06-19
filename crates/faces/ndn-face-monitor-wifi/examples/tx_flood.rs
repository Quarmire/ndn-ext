//! TX-only flood from the RTL8811CU for on-air verification by an external,
//! trusted receiver (e.g. a kernel-driver dongle in monitor mode capturing the
//! air). Injects a distinctive marker payload as fast as practical for
//! `NDN_RADIO_SECS` seconds on `NDN_RADIO_CHANNEL`. Grep the receiver's capture
//! for the ASCII marker `C811-ONAIR` (hex 43 38 31 31 2d 4f 4e 41 49 52).
//! `cargo run -p ndn-face-monitor-wifi --features libusb-backend --example tx_flood`
#[cfg(feature = "libusb-backend")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use bytes::Bytes;
    use ndn_face_monitor_wifi::{FrameIo, InjectFrame, McsDescriptor, Rtl8821cuBackend};
    use std::time::{Duration, Instant};

    let ch: u8 = std::env::var("NDN_RADIO_CHANNEL").ok().and_then(|s| s.parse().ok()).unwrap_or(36);
    let secs: u64 = std::env::var("NDN_RADIO_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(8);
    const MARKER: &[u8] = b"C811-ONAIR";

    println!("opening RTL8811CU, monitor ch {ch} ...");
    let dev = Rtl8821cuBackend::open_monitor(ch)?;
    println!("RFE profile {:?}; flooding marker frames for {secs}s ...", dev.rfe_profile());

    let deadline = Instant::now() + Duration::from_secs(secs);
    let (mut sent, mut err) = (0u32, 0u32);
    while Instant::now() < deadline {
        let mut p = MARKER.to_vec();
        p.extend_from_slice(&sent.to_le_bytes());
        match dev.inject(InjectFrame::broadcast(Bytes::from(p), McsDescriptor::CONSERVATIVE)).await {
            Ok(()) => sent += 1,
            Err(_) => err += 1,
        }
        if sent % 200 == 0 {
            tokio::time::sleep(Duration::from_millis(1)).await; // yield
        }
    }
    println!("done: injected {sent} marker frames ({err} errors) on ch {ch}");
    Ok(())
}
#[cfg(not(feature = "libusb-backend"))]
fn main() {}
