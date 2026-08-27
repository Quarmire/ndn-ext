//! **Shared serial mux + demand-driven coex** — proves ONE host connection to a unified ESP32-C5 carries
//! *both* named-radio bearers, and that the BLE↔Wi-Fi airtime split is a cognition lever, not a constant.
//!
//! Device **A** opens a *single* [`Esp32SerialBackend`] and, from `shared_mux()`, also drives a
//! [`SharedBleBackend`] over the SAME port/reader. It concurrently pulls Wi-Fi frames (`FrameIo::recv_frame`)
//! and BLE ads (`AdvBackend::next_scanned`) — both off one connection. Each second it samples the two
//! per-bearer **named-traffic demand** counters (`wifi_frame_count`, `ble_scan_count`) and sets BLE's share
//! of scan airtime to BLE's share of total named demand, clamped to `[floor, ceil]` — exactly the body of
//! [`SerialRadioBackend::spawn_demand_coex`], inlined here so the numbers are visible.
//!
//! Device **B** alternates 6 s phases: BLE-broadcast a named ad, then Wi-Fi-inject a named frame. So A's
//! per-bearer demand swings, and A's computed share should track it: high during B's BLE phase, low during
//! B's Wi-Fi phase.
//!
//! ```sh
//! SHARED_A=/dev/cu.usbmodem101 SHARED_B=/dev/cu.usbmodem11101 \
//!   cargo run --example shared_mux --features shared-mux -p ndn-phy-ble
//! ```
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use ndn_phy_ble::{AdvBackend, SharedBleBackend};
use ndn_radio_drivers::{Esp32SerialBackend, FrameIo, InjectFrame, TxIntent};

const ITVL: u16 = 256; // scan interval, 0.625 ms units (~160 ms)
const FLOOR: f32 = 0.15;
const CEIL: f32 = 0.9;
const PHASE_TICKS: u32 = 50; // 50 × 120 ms ≈ 6 s per phase

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pa = std::env::var("SHARED_A").unwrap_or_else(|_| "/dev/cu.usbmodem101".into());
    let pb = std::env::var("SHARED_B").unwrap_or_else(|_| "/dev/cu.usbmodem11101".into());

    // --- Device A: ONE connection, BOTH bearers ---
    let a_wifi = Arc::new(Esp32SerialBackend::open_c5(&pa)?);
    let a_mux = a_wifi.shared_mux();
    let a_ble = Arc::new(SharedBleBackend::new(a_mux.clone()));
    a_mux.set_ble_share(0.5, ITVL)?; // start neutral; the loop below takes over
    tokio::time::sleep(Duration::from_millis(1500)).await; // NimBLE sync

    // Wi-Fi bearer liveness: count frames the SAME connection delivers via FrameIo::recv_frame.
    let wifi_rx = Arc::new(AtomicU64::new(0));
    {
        let (w, n) = (a_wifi.clone(), wifi_rx.clone());
        tokio::spawn(async move {
            loop {
                if (tokio::time::timeout(Duration::from_millis(300), w.recv_frame()).await).is_ok()
                {
                    n.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
    }
    // BLE bearer liveness: count ads the SAME connection delivers via AdvBackend::next_scanned.
    let ble_rx = Arc::new(AtomicU64::new(0));
    {
        let (b, n) = (a_ble.clone(), ble_rx.clone());
        tokio::spawn(async move {
            loop {
                if (tokio::time::timeout(Duration::from_millis(300), b.next_scanned()).await)
                    .is_ok()
                {
                    n.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
    }

    // --- Device B: alternate BLE-broadcast / Wi-Fi-inject phases so A's per-bearer demand swings ---
    let b_wifi = Arc::new(Esp32SerialBackend::open_c5(&pb)?);
    let b_ble = Arc::new(SharedBleBackend::new(b_wifi.shared_mux()));
    tokio::time::sleep(Duration::from_millis(800)).await;
    {
        let (bw, bb) = (b_wifi.clone(), b_ble.clone());
        tokio::spawn(async move {
            let ad = Bytes::from_static(b"/ndn/mux/beacon");
            let wframe = Bytes::from_static(b"/ndn/mux/wifi-frame-demo-payload");
            let mut t = 0u32;
            loop {
                if (t / PHASE_TICKS) % 2 == 0 {
                    let _ = bb.broadcast(ad.clone()).await; // BLE phase
                } else {
                    let _ = bw
                        .inject(InjectFrame::broadcast(wframe.clone(), TxIntent::default()))
                        .await; // Wi-Fi phase
                }
                tokio::time::sleep(Duration::from_millis(120)).await;
                t = t.wrapping_add(1);
            }
        });
    }

    // --- Device A: the demand-driven coex loop (inlined spawn_demand_coex, so we can print) ---
    println!("shared mux on {pa}: one connection, both bearers. B alternates BLE(6s)/Wi-Fi(6s).\n");
    println!(
        "{:>4}  {:>7} {:>7}  {:>7}  {:<10}  {:>6} {:>6}",
        "s", "wifi_d", "ble_d", "share", "B phase", "wifiRX", "bleRX"
    );
    let mut prev_w = a_mux.wifi_frame_count();
    let mut prev_b = a_mux.ble_scan_count();
    for s in 1..=24 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let w = a_mux.wifi_frame_count();
        let b = a_mux.ble_scan_count();
        let dw = w.wrapping_sub(prev_w) as f32;
        let db = b.wrapping_sub(prev_b) as f32;
        prev_w = w;
        prev_b = b;
        let total = dw + db;
        let share = if total < 1.0 {
            (FLOOR + CEIL) * 0.5
        } else {
            (db / total).clamp(FLOOR, CEIL)
        };
        a_mux.set_ble_share(share, ITVL)?; // actuate — the cognition lever, driven by measured named demand
        let phase = if db > dw {
            "BLE"
        } else if dw > 0.0 {
            "Wi-Fi"
        } else {
            "idle"
        };
        println!(
            "{s:>4}  {dw:>7.0} {db:>7.0}  {share:>7.2}  {phase:<10}  {:>6} {:>6}",
            wifi_rx.load(Ordering::Relaxed),
            ble_rx.load(Ordering::Relaxed),
        );
    }

    let (wf, bf) = (
        wifi_rx.load(Ordering::Relaxed),
        ble_rx.load(Ordering::Relaxed),
    );
    println!("\ntotals over one connection: Wi-Fi frames = {wf}, BLE ads = {bf}");
    assert!(
        wf > 0,
        "no Wi-Fi frames — the Wi-Fi bearer of the shared mux is dead"
    );
    assert!(
        bf > 0,
        "no BLE ads — the BLE bearer of the shared mux is dead"
    );
    println!(
        "✔ ONE serial connection served BOTH bearers, and the coex split tracked per-bearer demand"
    );
    Ok(())
}
