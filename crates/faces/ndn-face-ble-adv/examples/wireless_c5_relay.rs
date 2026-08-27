//! **Defer + overhear-cancel, on air** — the one thing 2 nodes couldn't show. THREE ESP32-C5s: a producer, a
//! consumer, and a **relay** in between, each a `ForwarderEngine` over ONE `Radio` (Wi-Fi+BLE via the
//! shared mux). The relay routes the prefix and would re-broadcast every Interest it overhears — but the
//! `soft-prefix-reach-defer` strategy makes it **defer** the re-broadcast and **cancel** when it overhears the
//! producer's Data first. We measure the relay's outbound count (`Radio::tx_counter`) under the flood
//! baseline vs the defer strategy: flood re-broadcasts every Interest, defer suppresses the redundant ones.
//!
//! ```sh
//! # flood baseline (relay re-broadcasts everything):
//! WL_PROD=/dev/cu.usbmodem101 WL_CONS=/dev/cu.usbmodemB WL_RELAY=/dev/cu.usbmodemC NDR_STRATEGY=broadcast \
//!   cargo run --example wireless_c5_relay --features shared-mux -p ndn-face-ble-adv
//! # defer + overhear-cancel (relay suppresses the redundant re-broadcasts):
//! WL_PROD=... WL_CONS=... WL_RELAY=... NDR_STRATEGY=soft-prefix-reach-defer \
//!   cargo run --example wireless_c5_relay --features shared-mux -p ndn-face-ble-adv
//! ```
//! Needs THREE C5s on `firmware/esp32c5-ndn`.
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use ndn_app::{EngineAppExt, EngineBuilder};
use ndn_engine::builder::EngineConfig;
use ndn_face_ble_adv::{BlePhy, SharedBleBackend};
use ndn_face_monitor_wifi::WifiPhy;
use ndn_face_wireless::{PhyKind, Radio, TransportPhy, WirelessPhy};
use ndn_packet::Name;
use ndn_packet::encode::DataBuilder;
use ndn_radio_drivers::{Esp32SerialBackend, FrameIo};
use ndn_strategy_reach as _;
use ndn_transport::FaceId;
use tokio_util::sync::CancellationToken;

const WIRELESS_FACE: FaceId = FaceId(10);

fn build_wireless(port: &str) -> Result<Radio, Box<dyn std::error::Error>> {
    let wifi = Arc::new(Esp32SerialBackend::open_c5(port)?);
    let ble_backend = Arc::new(SharedBleBackend::new(wifi.shared_mux()));
    let io: Arc<dyn FrameIo> = wifi.clone();
    let phys: Vec<Arc<dyn WirelessPhy>> = vec![
        Arc::new(TransportPhy::new(WifiPhy::new(FaceId(1), io), PhyKind::Wifi, 1).with_mtu(2272)),
        Arc::new(
            TransportPhy::new(
                BlePhy::new(FaceId(2), ble_backend)
                    .ndnts_framing()
                    .with_mtu(200),
                PhyKind::Ble,
                3,
            )
            .with_mtu(200),
        ),
    ];
    Ok(Radio::broadcast(WIRELESS_FACE, phys))
}

fn strategy() -> String {
    std::env::var("NDR_STRATEGY").unwrap_or_else(|_| "soft-prefix-reach-defer".into())
}

fn hook(engine: &ndn_engine::ForwarderEngine, prefix: &Name) {
    let strat =
        ndn_strategy::registry::create_by_name(strategy().as_bytes()).expect("strategy registered");
    engine.strategy_table().insert(prefix, strat);
}

#[tokio::main(flavor = "multi_thread", worker_threads = 6)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ports = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.into());
    let (pp, pc, pr) = (
        ports("WL_PROD", "/dev/cu.usbmodem101"),
        ports("WL_CONS", "/dev/cu.usbmodem11101"),
        ports("WL_RELAY", "/dev/cu.usbmodem11401"),
    );
    let prefix: Name = "/ndn/wl/svc".parse().unwrap();

    // Producer.
    let (engine_p, shutdown_p) = EngineBuilder::new(EngineConfig::default())
        .face(build_wireless(&pp)?)
        .build()
        .await?;
    hook(&engine_p, &prefix);
    let cancel_p = CancellationToken::new();
    let producer = engine_p.register_producer(prefix.clone(), cancel_p.child_token());

    // Relay: routes the prefix out its wireless face + strategy. Measure its outbound (re-broadcast) count.
    let relay_face = build_wireless(&pr)?;
    let relay_tx = relay_face.tx_counter();
    let (engine_r, shutdown_r) = EngineBuilder::new(EngineConfig::default())
        .face(relay_face)
        .build()
        .await?;
    engine_r.fib().add_nexthop(&prefix, WIRELESS_FACE, 0);
    hook(&engine_r, &prefix);

    // Consumer.
    let (engine_c, shutdown_c) = EngineBuilder::new(EngineConfig::default())
        .face(build_wireless(&pc)?)
        .build()
        .await?;
    engine_c.fib().add_nexthop(&prefix, WIRELESS_FACE, 0);
    hook(&engine_c, &prefix);
    let cancel_c = CancellationToken::new();
    let mut consumer = engine_c.app_consumer(cancel_c.child_token());

    println!(
        "3 C5s (producer / relay / consumer), each engine + {} over a Radio.",
        strategy()
    );
    tokio::time::sleep(Duration::from_millis(1800)).await;

    let payload = b"defer + overhear-cancel on air".to_vec();
    let want = payload.clone();
    let producer_task = tokio::spawn(async move {
        let _ = producer
            .serve(move |i, r| {
                let name = (*i.name).clone();
                let body = payload.clone();
                async move {
                    r.respond_bytes(DataBuilder::new(name, &body).build())
                        .await
                        .ok();
                }
            })
            .await;
    });

    // Distinct names each round so every fetch is a fresh transaction the relay overhears.
    let rounds: u32 = std::env::var("NDR_ROUNDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30);
    let mut delivered = 0u32;
    for r in 0..rounds {
        let name: Name = format!("/ndn/wl/svc/{r}").parse().unwrap();
        if let Ok(v) = consumer.fetch_unverified(name).await {
            if v.trust_unchecked()
                .content()
                .map(|c| c.as_ref() == want.as_slice())
                .unwrap_or(false)
            {
                delivered += 1;
            }
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }

    let relay_rebroadcasts = relay_tx.load(Ordering::Relaxed);
    println!("\n  strategy = {}", strategy());
    println!("  delivered {delivered}/{rounds}");
    println!("  RELAY outbound (re-broadcasts + data-forwards) = {relay_rebroadcasts}");
    println!(
        "  → flood re-broadcasts every overheard Interest; defer+overhear-cancel suppresses the redundant ones."
    );

    cancel_p.cancel();
    cancel_c.cancel();
    producer_task.abort();
    let _ = (shutdown_p, shutdown_r, shutdown_c);
    // Exit immediately: the graceful engine+serial shutdown blocks on the blocking reader threads, which
    // leaves the process wedged and the USB-JTAG port locked. process::exit reclaims everything cleanly.
    std::process::exit(0);
}
