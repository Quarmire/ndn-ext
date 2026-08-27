//! **The whole stack, on air.** Two ESP32-C5s, each running a real `ForwarderEngine` whose ONE face is a
//! [`Radio`] multiplexing that C5's Wi-Fi (802.11) + BLE (ext-adv) phys via the shared mux — with
//! the **soft-prefix-reach forwarding strategy** hooked above it. A full NDN Interest→Data roundtrip crosses
//! the air, forwarded by the strategy over the unified wireless face:
//!
//! ```text
//!  consumer engine (C5 B)                          producer engine (C5 A)
//!  app_consumer ─FIB→ Radio ==(Wi-Fi+BLE)==> Radio ─FIB→ register_producer
//!        ▲   soft-prefix-reach-defer  <===air====   soft-prefix-reach-defer   serve()
//! ```
//! This closes the whole thread: doctrine (one wireless face) → forwarding-under-flux strategy → unified face
//! over real phys → a forwarding engine, all on hardware.
//!
//! ```sh
//! WL_A=/dev/cu.usbmodem101 WL_B=/dev/cu.usbmodem11101 \
//!   cargo run --example wireless_c5_engine --features shared-mux -p ndn-phy-ble
//! ```
//! Needs the unified `firmware/esp32c5-ndn` on both C5s.
use std::sync::Arc;
use std::time::Duration;

use ndn_app::{EngineAppExt, EngineBuilder};
use ndn_engine::builder::EngineConfig;
use ndn_phy_ble::{BlePhy, SharedBleBackend};
use ndn_phy_wifi::WifiPhy;
use ndn_radio::{PhyKind, Radio, TransportPhy, WirelessPhy};
use ndn_packet::Name;
use ndn_packet::encode::DataBuilder;
use ndn_radio_drivers::{Esp32SerialBackend, FrameIo};
use ndn_strategy_reach as _; // force-link so `soft-prefix-reach-defer` is in the registry (linkme)
use ndn_transport::FaceId;
use tokio_util::sync::CancellationToken;

const WIRELESS_FACE: FaceId = FaceId(10);

/// A Radio over both phys of ONE C5 (Wi-Fi FrameIo + BLE over the shared mux).
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

/// Register `soft-prefix-reach-defer` on `prefix` in this engine's strategy table.
fn hook_strategy(engine: &ndn_engine::ForwarderEngine, prefix: &Name) {
    let strat = ndn_strategy::registry::create_by_name(b"soft-prefix-reach-defer")
        .expect("soft-prefix-reach-defer registered (linkme)");
    engine.strategy_table().insert(prefix, strat);
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pa = std::env::var("WL_A").unwrap_or_else(|_| "/dev/cu.usbmodem101".into()); // producer C5
    let pb = std::env::var("WL_B").unwrap_or_else(|_| "/dev/cu.usbmodem11101".into()); // consumer C5
    let prefix: Name = "/ndn/wl/svc".parse().unwrap();

    // Producer engine over C5 A's Radio.
    let (engine_p, shutdown_p) = EngineBuilder::new(EngineConfig::default())
        .face(build_wireless(&pa)?)
        .build()
        .await?;
    hook_strategy(&engine_p, &prefix);
    let cancel_p = CancellationToken::new();
    let producer = engine_p.register_producer(prefix.clone(), cancel_p.child_token());

    // Consumer engine over C5 B's Radio: route the prefix OUT the wireless face + strategy.
    let (engine_c, shutdown_c) = EngineBuilder::new(EngineConfig::default())
        .face(build_wireless(&pb)?)
        .build()
        .await?;
    engine_c.fib().add_nexthop(&prefix, WIRELESS_FACE, 0);
    hook_strategy(&engine_c, &prefix);
    let cancel_c = CancellationToken::new();
    let mut consumer = engine_c.app_consumer(cancel_c.child_token());

    println!(
        "Two C5s, each: ForwarderEngine + soft-prefix-reach-defer over ONE Radio (Wi-Fi+BLE)."
    );
    tokio::time::sleep(Duration::from_millis(1800)).await; // NimBLE sync + reader spin-up

    let payload = b"the whole stack, on air".to_vec();
    let want = payload.clone();
    let producer_task = tokio::spawn(async move {
        let _ = producer
            .serve(move |interest, responder| {
                let name = (*interest.name).clone();
                let body = payload.clone();
                async move {
                    responder
                        .respond_bytes(DataBuilder::new(name, &body).build())
                        .await
                        .ok();
                }
            })
            .await;
    });

    println!(
        "consumer engine: fetching {prefix} over the Radio (engine + strategy, retry on loss)..."
    );
    let mut got = None;
    for attempt in 1..=60u32 {
        if let Ok(v) = consumer.fetch_unverified(prefix.clone()).await {
            got = Some(v.trust_unchecked());
            println!("  ✔ Data returned on attempt {attempt}");
            break;
        }
        if attempt % 10 == 0 {
            println!("  ...still trying ({attempt})");
        }
    }

    cancel_p.cancel();
    cancel_c.cancel();
    producer_task.abort();

    match got {
        Some(data) => {
            let content = data.content().map(|c| c.to_vec()).unwrap_or_default();
            println!(
                "consumer fetched {} → {:?}",
                *data.name,
                String::from_utf8_lossy(&content)
            );
            assert_eq!(*data.name, prefix);
            assert_eq!(content, want);
            println!(
                "✔ WHOLE STACK ON AIR: engine + soft-prefix-reach strategy + Radio (Wi-Fi+BLE, one C5) — Interest→Data roundtrip."
            );
        }
        None => println!(
            "✗ no roundtrip in 60 attempts — check both C5s run firmware/esp32c5-ndn on the same channel"
        ),
    }

    let _ = shutdown_p.shutdown().await;
    let _ = shutdown_c.shutdown().await;
    Ok(())
}
