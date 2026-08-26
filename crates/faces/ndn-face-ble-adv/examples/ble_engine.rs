//! **Engine-level NDN roundtrip over BLE** — the BLE face driven by a real forwarding engine (PIT/FIB),
//! not the raw face. Two `ForwarderEngine`s, one per ESP32-C5, linked *only* by a [`BleAdvFace`]:
//!
//! ```text
//!  consumer engine (dev B)                          producer engine (dev A)
//!  ┌───────────────────────┐   BLE 5 ext-adv    ┌───────────────────────┐
//!  │ app_consumer ─FIB→ BLE│===================>│ BLE ─FIB→ register_producer
//!  │        ▲          face │<===================│ face          serve()  │
//!  └────────┼──────────────┘   (on air)         └───────────────────────┘
//!   fetch() │ Data via PIT                          Interest→Data
//! ```
//!
//! The consumer's engine routes `/ndn/ble/eng` out the BLE face (FIB); the Interest crosses the air; the
//! producer's engine routes it to a local producer (FIB, installed by `register_producer`); the Data returns
//! across the air and the consumer's **PIT** matches it back to the waiting `fetch`. Unlike `ble_roundtrip`
//! (raw face + manual TLV), this exercises the whole forwarder: FIB lookup, PIT, ContentStore, and the
//! engine's own NDNLPv2 link service on the BLE face. Data is kept small (one advertisement, no fragmentation)
//! so loss is a whole-packet retransmit, absorbed by re-`fetch` — the honest reliability model for lossy
//! broadcast (large Data needs link-FEC; see the named-radio design).
//!
//! ```sh
//! BLE_A=/dev/cu.usbmodem101 BLE_B=/dev/cu.usbmodem11101 \
//!   cargo run --example ble_engine --features shared-mux -p ndn-face-ble-adv
//! ```
use std::sync::Arc;
use std::time::Duration;

use ndn_app::{EngineAppExt, EngineBuilder};
use ndn_engine::EngineConfig;
use ndn_face_ble_adv::{BleAdvFace, SharedBleBackend};
use ndn_packet::encode::DataBuilder;
use ndn_packet::Name;
use ndn_radio_drivers::Esp32SerialBackend;
use ndn_transport::FaceId;
use tokio_util::sync::CancellationToken;

const BLE_FACE_A: FaceId = FaceId(100); // producer node's on-air face
const BLE_FACE_B: FaceId = FaceId(200); // consumer node's on-air face

#[tokio::main(flavor = "multi_thread", worker_threads = 3)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pa = std::env::var("BLE_A").unwrap_or_else(|_| "/dev/cu.usbmodem101".into()); // producer device
    let pb = std::env::var("BLE_B").unwrap_or_else(|_| "/dev/cu.usbmodem11101".into()); // consumer device
    let prefix: Name = "/ndn/ble/eng".parse().unwrap();

    // --- Producer node (device A): engine linked by a BLE face + a local producer for the prefix ---
    let a_wifi = Arc::new(Esp32SerialBackend::open_c5(&pa)?);
    let a_mux = a_wifi.shared_mux();
    a_mux.set_ble_share(0.9, 256)?; // this demo is all-BLE; give the scan the airtime
    let a_ble = Arc::new(SharedBleBackend::new(a_mux));
    let (engine_p, shutdown_p) = EngineBuilder::new(EngineConfig::default())
        .face(BleAdvFace::new(BLE_FACE_A, a_ble)) // default NDNLPv2 framing → engine's LpLinkService
        .build()
        .await?;
    let cancel_p = CancellationToken::new();
    // register_producer installs the FIB route prefix → the local producer face, so Interests that arrive
    // on the BLE face are forwarded to serve().
    let producer = engine_p.register_producer(prefix.clone(), cancel_p.child_token());

    // --- Consumer node (device B): engine linked by a BLE face, prefix routed OUT that face ---
    let b_wifi = Arc::new(Esp32SerialBackend::open_c5(&pb)?);
    let b_mux = b_wifi.shared_mux();
    b_mux.set_ble_share(0.9, 256)?;
    let b_ble = Arc::new(SharedBleBackend::new(b_mux));
    let (engine_c, shutdown_c) = EngineBuilder::new(EngineConfig::default())
        .face(BleAdvFace::new(BLE_FACE_B, b_ble))
        .build()
        .await?;
    engine_c.fib().add_nexthop(&prefix, BLE_FACE_B, 0); // /ndn/ble/eng → the BLE face
    let cancel_c = CancellationToken::new();
    let mut consumer = engine_c.app_consumer(cancel_c.child_token());

    tokio::time::sleep(Duration::from_millis(1800)).await; // NimBLE sync on both dongles

    // Producer answers every Interest for the prefix with a small Data (also cached in its ContentStore).
    let payload = b"hello over BLE, via the forwarding engine (PIT/FIB)".to_vec();
    let want = payload.clone();
    let producer_task = tokio::spawn(async move {
        let _ = producer
            .serve(move |interest, responder| {
                let name = (*interest.name).clone();
                let body = payload.clone();
                async move {
                    let wire = DataBuilder::new(name, &body).build();
                    responder.respond_bytes(wire).await.ok();
                }
            })
            .await;
    });

    // Consumer fetches through its engine. BLE broadcast is lossy → re-fetch until the roundtrip lands
    // (each fetch is a fresh Interest; the producer's CS serves repeats cheaply).
    println!("consumer engine: fetching {prefix} over BLE (engine PIT/FIB, retry on loss)...");
    let mut got = None;
    for attempt in 1..=40u32 {
        match consumer.fetch_unverified(prefix.clone()).await {
            Ok(v) => {
                got = Some(v.trust_unchecked());
                println!("  ✔ Data returned on attempt {attempt}");
                break;
            }
            Err(_) if attempt % 5 == 0 => println!("  ...still trying ({attempt})"),
            Err(_) => {}
        }
    }

    cancel_p.cancel();
    cancel_c.cancel();
    producer_task.abort();

    let data = got.ok_or("engine roundtrip over BLE did not complete in 40 attempts")?;
    let content = data.content().map(|c| c.to_vec()).unwrap_or_default();
    println!(
        "consumer engine fetched {} → {:?}",
        *data.name,
        String::from_utf8_lossy(&content)
    );
    assert_eq!(*data.name, prefix, "returned Data name mismatch");
    assert_eq!(content, want, "returned Data content mismatch");

    let _ = shutdown_p.shutdown().await;
    let _ = shutdown_c.shutdown().await;
    println!("✔ engine-level NDN roundtrip over BLE: Interest routed by FIB → on air → producer → Data via PIT");
    Ok(())
}
