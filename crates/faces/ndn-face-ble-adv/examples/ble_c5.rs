//! Two ESP32-C5 BLE backends exchanging a payload through the `AdvBackend` trait, on air.
//!
//! ```sh
//! BLE_A=/dev/cu.usbmodem1101 BLE_B=/dev/cu.usbmodem6 \
//!   cargo run --example ble_c5 --features serial -p ndn-face-ble-adv
//! ```
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_face_ble_adv::{AdvBackend, Esp32BleBackend};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let a = std::env::var("BLE_A").unwrap_or_else(|_| "/dev/cu.usbmodem1101".into());
    let b = std::env::var("BLE_B").unwrap_or_else(|_| "/dev/cu.usbmodem6".into());
    let tx = Arc::new(Esp32BleBackend::open(&a)?);
    let rx = Arc::new(Esp32BleBackend::open(&b)?);
    tokio::time::sleep(Duration::from_millis(1500)).await; // let NimBLE reach sync on both

    // A tiny NDN-ish payload (a Data-shaped blob is enough to prove carriage).
    let payload = Bytes::from(vec![0x06, 0x12, 0x07, 0x0a, b'/', b'n', b'd', b'n', b'/', b'b', b'l', b'e',
                                   b'/', b'r', b'u', b's', b't', 0xAB, 0xCD, 0xEF]);

    let txc = tx.clone();
    let pl = payload.clone();
    let spam = tokio::spawn(async move {
        for _ in 0..300 {
            let _ = txc.broadcast(pl.clone()).await;
            tokio::time::sleep(Duration::from_millis(40)).await;
        }
    });

    let (mut got, mut matched) = (0u32, 0u32);
    let mut first: Option<(i8, [u8; 6])> = None;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    while tokio::time::Instant::now() < deadline && matched < 5 {
        if let Ok(Ok(sf)) = tokio::time::timeout(Duration::from_millis(500), rx.next_scanned()).await {
            got += 1;
            if sf.frame == payload {
                matched += 1;
                if first.is_none() {
                    first = Some((sf.rssi_dbm.unwrap_or(0), sf.addr.unwrap_or_default()));
                }
            }
        }
    }
    spam.abort();
    println!("A → BLE → B via AdvBackend: scanned {got}, matched {matched}");
    if let Some((rssi, addr)) = first {
        println!("  first match: rssi {rssi} dBm from {}", addr.map(|x| format!("{x:02x}")).join(":"));
    }
    assert!(matched > 0, "no matching BLE advertisements received on B");
    println!("✔ named data carried over BLE 5 extended advertising, C5 → C5");
    Ok(())
}
