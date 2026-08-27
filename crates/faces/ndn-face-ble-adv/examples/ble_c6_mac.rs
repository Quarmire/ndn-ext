//! **ESP32-C6 BLE PHY → the Mac's own Bluetooth.** Two real named-radio BLE PHYs across two different
//! stacks: the **C6** (Espressif NimBLE, driven over its serial bridge) advertises named data via the ND
//! manufacturer AD (company `0x4E44`), and the **Mac's built-in Bluetooth** ([`MacBleBackend`], Apple
//! CoreBluetooth via btleplug) scans and decodes it. This is how we validate a C6 BLE PHY on air without
//! a second ESP board — the peer is the host radio itself.
//!
//! The Mac PHY is receive-only on the adv bearer (CoreBluetooth won't broadcast manufacturer data — see
//! [`MacBleBackend`]), so the direction is fixed: C6 transmits, Mac receives. We broadcast a distinct
//! payload per round and count how many the Mac hears.
//!
//! ```sh
//! WL_C6=/dev/cu.usbmodem2101 NDR_ROUNDS=20 \
//!   cargo run --example ble_c6_mac --features shared-mux,mac -p ndn-face-ble-adv
//! ```
//! The C6 must run the unified `firmware/esp32c5-ndn` (built for esp32c6). macOS will ask for Bluetooth
//! permission for the terminal the first time — grant it, or scanning yields nothing.
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_face_ble_adv::{AdvBackend, MacBleBackend, SharedBleBackend};
use ndn_radio_drivers::Esp32SerialBackend;

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let port = std::env::var("WL_C6").unwrap_or_else(|_| "/dev/cu.usbmodem2101".into());
    let rounds: u32 = std::env::var("NDR_ROUNDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20);

    // The C6 as a BLE advertiser (TX), over its serial bridge (unified firmware, shared Wi-Fi/BLE mux).
    let wifi = Arc::new(Esp32SerialBackend::open_c5(&port)?);
    let c6: Arc<dyn AdvBackend> = Arc::new(SharedBleBackend::new(wifi.shared_mux()));

    // The Mac's own Bluetooth as the receiver (RX): CoreBluetooth scan for ND manufacturer adverts.
    let mac = MacBleBackend::open().await?;

    println!("C6 (serial {port}) advertises → the Mac's Bluetooth scans. {rounds} rounds.");
    tokio::time::sleep(Duration::from_millis(1500)).await; // NimBLE ext-adv + CoreBluetooth spin-up

    let mut received = 0u32;
    for r in 0..rounds {
        let payload = format!("C6-BLE->MAC #{r}");
        c6.broadcast(Bytes::from(payload.clone().into_bytes()))
            .await?;

        // Wait up to 600 ms for the Mac to surface THIS advert (older adverts in the queue are skipped;
        // the controller dedups the 3-event burst so we see each payload once).
        let deadline = tokio::time::Instant::now() + Duration::from_millis(600);
        while let Ok(Ok(sf)) = tokio::time::timeout_at(deadline, mac.next_scanned()).await {
            if sf.frame.as_ref() == payload.as_bytes() {
                received += 1;
                println!(
                    "  #{r}: Mac heard {payload:?}  (link-id {:02x?})",
                    sf.addr.unwrap_or_default()
                );
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(120)).await;
    }

    println!("\n  Mac Bluetooth received {received}/{rounds} named adverts from the C6 BLE PHY.");
    println!("  → C6 (NimBLE) TX ↔ Mac (CoreBluetooth) RX: named data over BLE across two stacks.");
    std::process::exit(if received > 0 { 0 } else { 1 });
}
