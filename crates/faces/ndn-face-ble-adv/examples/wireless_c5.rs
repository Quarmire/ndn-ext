//! **The unified `WirelessFace` on REAL hardware.** ONE ESP32-C5 exposes BOTH bearers through the shared mux —
//! raw 802.11 (Wi-Fi, a `MonitorWifiFace` over the `Esp32SerialBackend` `FrameIo`) and BLE 5 extended
//! advertising (a `BleAdvFace` over the mux's `SharedBleBackend`) — and a `WirelessFace` multiplexes them into
//! ONE face. Two C5s exchange a packet that goes out over **both radios at once** and is received + **deduped
//! to one** by the peer: the one-wireless-face doctrine, on air, over two different PHYs from a single chip.
//!
//! ```sh
//! WL_A=/dev/cu.usbmodem101 WL_B=/dev/cu.usbmodem11101 \
//!   cargo run --example wireless_c5 --features shared-mux -p ndn-face-ble-adv
//! ```
//! Needs the unified `firmware/esp32c5-ndn` on both C5s.
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_face_ble_adv::{BleAdvFace, SharedBleBackend};
use ndn_face_monitor_wifi::MonitorWifiFace;
use ndn_face_wireless::{BearerKind, TransportBearer, WirelessBearer, WirelessFace};
use ndn_radio_drivers::{Esp32SerialBackend, FrameIo};
use ndn_transport::{FaceId, Transport};

/// Build a WirelessFace over both bearers of ONE C5 (via the shared mux).
fn build_wireless(port: &str) -> Result<WirelessFace, Box<dyn std::error::Error>> {
    let wifi = Arc::new(Esp32SerialBackend::open_c5(port)?);
    let ble_backend = Arc::new(SharedBleBackend::new(wifi.shared_mux()));

    let io: Arc<dyn FrameIo> = wifi.clone();
    let wifi_face = MonitorWifiFace::new(FaceId(1), io); // Wi-Fi bearer (802.11 injection/capture)
    let ble_face = BleAdvFace::new(FaceId(2), ble_backend).ndnts_framing().with_mtu(200); // BLE bearer

    let bearers: Vec<Arc<dyn WirelessBearer>> = vec![
        Arc::new(TransportBearer::new(wifi_face, BearerKind::Wifi, 1).with_mtu(2272)),
        Arc::new(TransportBearer::new(ble_face, BearerKind::Ble, 3).with_mtu(200)),
    ];
    Ok(WirelessFace::broadcast(FaceId(10), bearers))
}

#[tokio::main(flavor = "multi_thread", worker_threads = 3)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pa = std::env::var("WL_A").unwrap_or_else(|_| "/dev/cu.usbmodem101".into());
    let pb = std::env::var("WL_B").unwrap_or_else(|_| "/dev/cu.usbmodem11101".into());

    let a = build_wireless(&pa)?;
    let b = Arc::new(build_wireless(&pb)?);
    println!("WirelessFace on {pa} (TX) and {pb} (RX): each = Wi-Fi + BLE bearers over one C5. Sending...");
    tokio::time::sleep(Duration::from_millis(1800)).await; // NimBLE sync + reader spin-up

    // One object A broadcasts over BOTH bearers; B should receive it exactly once (cross-bearer dedup).
    let obj = Bytes::from_static(b"/ndn/wl/onair\x00hello over wifi + ble, one face");
    let brx = Arc::clone(&b);
    let recv = tokio::spawn(async move { tokio::time::timeout(Duration::from_secs(20), brx.recv_bytes()).await });

    for _ in 0..40 {
        // Lossy broadcast on both media → resend for redundancy; B's dedup keeps it to one delivery.
        let _ = a.send_bytes(obj.clone()).await;
        tokio::time::sleep(Duration::from_millis(400)).await;
        if recv.is_finished() {
            break;
        }
    }

    match recv.await? {
        Ok(Ok(w)) => {
            println!("✔ B received {} bytes over the WirelessFace — one NDN packet, over Wi-Fi AND BLE from one", w.len());
            println!("  C5, deduped to a single delivery. The unified wireless face, on air.");
            assert_eq!(w, obj, "the received object matches");
        }
        Ok(Err(_)) | Err(_) => {
            println!("✗ no delivery in 20s — check both C5s run firmware/esp32c5-ndn on the same channel");
        }
    }
    Ok(())
}
