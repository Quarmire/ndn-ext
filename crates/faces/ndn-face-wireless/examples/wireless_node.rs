//! **Any board, one wireless face.** Brings the ESP32 **CYD** (Wi-Fi serial-radio), the **Heltec** /
//! **S3+LoRa** boards (SX12xx), the **BW16**, and a plain **C5** up to par with the shared-mux C5s: each
//! becomes a first-class [`WirelessPhy`] of ONE [`Radio`], and a real `ForwarderEngine` runs over
//! it. Attach whichever phys this node has by env var — the face fragments per-phy, dedups across
//! phys, and the reach policy chooses which phy(s) carry each packet.
//!
//! ```text
//!   WL_WIFI  ─→ SerialRadioBackend ─→ WifiPhy ─┐
//!                                                       ├─→ Radio ─→ ForwarderEngine (+ strategy)
//!   WL_LORA  ─→ LoraSerialBackend  ─→ LoraPhy ────────┘
//! ```
//!
//! Every board here speaks the same host contract as the C5 (the `[4E 44 …]` ND wire protocol for Wi-Fi,
//! the 7E-A5 protocol for LoRa), so the CYD and a Heltec are just two more phys — no new face type.
//!
//! ```sh
//! # CYD as a Wi-Fi phy, consumer role, fetch /ndn/wl/svc from a peer producer:
//! WL_WIFI=/dev/cu.usbserial-11410 WL_ROLE=consumer \
//!   cargo run --example wireless_node -p ndn-face-wireless
//! # Heltec (SX1276) as a LoRa phy, producer role:
//! WL_LORA=/dev/cu.usbserial-0001 WL_ROLE=producer \
//!   cargo run --example wireless_node -p ndn-face-wireless
//! # A HETEROGENEOUS node: ONE wireless face spanning a CYD (Wi-Fi) AND a Heltec (LoRa), name-routed —
//! # robust names go out LoRa (longest reach), throughput names go out Wi-Fi (highest MTU):
//! WL_WIFI=/dev/cu.usbserial-11410 WL_LORA=/dev/cu.usbserial-0001 WL_POLICY=classify WL_ROLE=producer \
//!   cargo run --example wireless_node -p ndn-face-wireless
//! ```
//! CYD/BW16 need `firmware/esp32-cyd-radio` (or the BW16 802.11 bridge); the LoRa boards need the 7E-A5
//! Rust LoRa firmware (`waveshare-lora-rs` / `heltec-lora-rs`). Peers must share a channel/air params.
use std::env;
use std::sync::Arc;
use std::time::Duration;

use ndn_app::{EngineAppExt, EngineBuilder};
use ndn_engine::builder::EngineConfig;
use ndn_face_lora::LoraPhy;
use ndn_face_monitor_wifi::WifiPhy;
use ndn_face_wireless::{
    BroadcastAllPhys, NameReachClassifier, PhyKind, Radio, ReachClass, TransportPhy, WirelessPhy,
};
use ndn_packet::Name;
use ndn_packet::encode::DataBuilder;
use ndn_radio_drivers::{FrameIo, LoraSerialBackend, MAX_LORA_PAYLOAD, SerialRadioBackend};
use ndn_strategy_reach as _; // force-link the soft-prefix-reach strategies into the registry (linkme)
use ndn_transport::FaceId;
use tokio_util::sync::CancellationToken;

const WIRELESS_FACE: FaceId = FaceId(10);

fn env_or(k: &str, d: &str) -> String {
    env::var(k).unwrap_or_else(|_| d.into())
}

/// Assemble a [`Radio`] from whichever boards are wired up (env `WL_WIFI` / `WL_LORA`).
fn build_wireless(prefix: &Name) -> Result<Radio, Box<dyn std::error::Error>> {
    let mut phys: Vec<Arc<dyn WirelessPhy>> = Vec::new();

    // Wi-Fi phy: a CYD / BW16 / plain-C5 running the serial 802.11 bridge. SerialRadioBackend::open
    // pulses DTR→CEN to boot our firmware on a CH340/CP2102 board (the CYD/BW16); a native-USB-JTAG C5
    // would use open_no_reset, but for the CYD the reset pulse is correct.
    if let Ok(port) = env::var("WL_WIFI") {
        let ch: u8 = env_or("WL_CHANNEL", "6").parse().unwrap_or(6);
        let be = Arc::new(SerialRadioBackend::open(&port)?);
        if let Err(e) = be.set_channel(ch) {
            eprintln!("  ! WL_WIFI set_channel({ch}) failed: {e} (continuing on firmware default)");
        }
        let io: Arc<dyn FrameIo> = be;
        let face = WifiPhy::new(FaceId(1), io);
        // 802.11 airtime-optimal ceiling ~2272 B; range_rank 1 (shortest of the three phys).
        phys.push(Arc::new(
            TransportPhy::new(face, PhyKind::Wifi, 1).with_mtu(2272),
        ));
        println!("  + Wi-Fi phy on {port} (ch {ch}, MTU 2272)");
    }

    // Wi-Fi phy over a libusb Realtek USB dongle (e.g. the 8812au) — `WL_WIFI_USB=8812` (hex PID).
    // open_named_radio brings up monitor + inject and hands back an `Arc<dyn FrameIo>`, same contract as
    // the serial board, so the USB radio is just another PHY. Lets a node produce/relay over a real USB
    // Wi-Fi radio while the CYD consumes over its serial 802.11 PHY — a cross-radio roundtrip on one host.
    if let Ok(pid_s) = env::var("WL_WIFI_USB") {
        let pid = u16::from_str_radix(pid_s.trim_start_matches("0x"), 16).unwrap_or(0x8812);
        let ch: u8 = env_or("WL_CHANNEL", "6").parse().unwrap_or(6);
        let radio = ndn_radio_drivers::open_named_radio(pid, ch)?;
        let io = radio.io();
        let face = WifiPhy::new(FaceId(3), io);
        phys.push(Arc::new(
            TransportPhy::new(face, PhyKind::Wifi, 1).with_mtu(2272),
        ));
        println!("  + Wi-Fi(USB 0x{pid:04x}) phy (ch {ch}, MTU 2272)");
    }

    // LoRa phy: a Heltec (SX1276) / S3+LoRa (SX126x) / Waveshare dongle on the 7E-A5 Rust firmware.
    if let Ok(port) = env::var("WL_LORA") {
        let be = Arc::new(LoraSerialBackend::open(&port)?);
        let io: Arc<dyn FrameIo> = be;
        let face = LoraPhy::new(FaceId(2), io);
        // One LoRa frame is the MTU (LpLinkService fragments above this); range_rank 5 = longest reach.
        phys.push(Arc::new(
            TransportPhy::new(face, PhyKind::LoRa, 5).with_mtu(MAX_LORA_PAYLOAD),
        ));
        println!("  + LoRa phy on {port} (MTU {MAX_LORA_PAYLOAD})");
    }

    if phys.is_empty() {
        return Err("set at least one of WL_WIFI / WL_LORA to a serial port".into());
    }

    // Policy: `classify` routes by name (robust→longest-reach phy i.e. LoRa, throughput→highest-MTU i.e.
    // Wi-Fi); anything else broadcasts on all phys (macrodiversity, the safe default for a single peer).
    match env::var("WL_POLICY").as_deref() {
        Ok("classify") => {
            let clf = NameReachClassifier::new(ReachClass::Redundant)
                .rule(prefix.clone(), ReachClass::Robust)
                .rule(
                    format!("{prefix}/fast").parse::<Name>().unwrap(),
                    ReachClass::Throughput,
                );
            println!("  policy = name-classify (default robust; /fast → throughput)");
            Ok(Radio::new(WIRELESS_FACE, phys, Arc::new(clf)))
        }
        _ => {
            println!("  policy = broadcast-all-phys");
            Ok(Radio::new(WIRELESS_FACE, phys, Arc::new(BroadcastAllPhys)))
        }
    }
}

fn hook_strategy(engine: &ndn_engine::ForwarderEngine, prefix: &Name) {
    let name = env_or("NDR_STRATEGY", "soft-prefix-reach-defer");
    let strat = ndn_strategy::registry::create_by_name(name.as_bytes())
        .unwrap_or_else(|| panic!("strategy {name} not registered"));
    engine.strategy_table().insert(prefix, strat);
    println!("  strategy = {name}");
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let role = env_or("WL_ROLE", "consumer");
    let prefix: Name = env_or("WL_PREFIX", "/ndn/wl/svc").parse()?;
    println!("wireless_node: role={role} prefix={prefix}");

    let face = build_wireless(&prefix)?;
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(face)
        .build()
        .await?;
    hook_strategy(&engine, &prefix);
    tokio::time::sleep(Duration::from_millis(1500)).await; // reader spin-up / radio settle

    let exit_ok;
    match role.as_str() {
        "producer" => {
            let cancel = CancellationToken::new();
            let producer = engine.register_producer(prefix.clone(), cancel.child_token());
            let body = env_or("WL_PAYLOAD", "hello from a named-radio phy").into_bytes();
            let secs: u64 = env_or("WL_SECS", "60").parse().unwrap_or(60);
            println!("producer: serving {prefix} for {secs}s");
            let task = tokio::spawn(async move {
                let _ = producer
                    .serve(move |i, r| {
                        let name = (*i.name).clone();
                        let body = body.clone();
                        async move {
                            r.respond_bytes(DataBuilder::new(name, &body).build())
                                .await
                                .ok();
                        }
                    })
                    .await;
            });
            tokio::time::sleep(Duration::from_secs(secs)).await;
            cancel.cancel();
            task.abort();
            exit_ok = true;
        }
        _ => {
            // Consumer: route the prefix out the wireless face, then fetch distinct names each round.
            engine.fib().add_nexthop(&prefix, WIRELESS_FACE, 0);
            let cancel = CancellationToken::new();
            let mut consumer = engine.app_consumer(cancel.child_token());
            let rounds: u32 = env_or("WL_ROUNDS", "20").parse().unwrap_or(20);
            let mut delivered = 0u32;
            println!("consumer: fetching {rounds} names under {prefix} ...");
            for r in 0..rounds {
                let name: Name = format!("{prefix}/{r}").parse()?;
                if let Ok(v) = consumer.fetch_unverified(name.clone()).await {
                    if v.trust_unchecked().content().is_some() {
                        delivered += 1;
                    }
                }
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
            println!("\nconsumer: delivered {delivered}/{rounds}");
            cancel.cancel();
            exit_ok = delivered > 0;
        }
    }

    let _ = shutdown;
    // Exit immediately: graceful engine+serial shutdown blocks on the blocking reader threads and wedges
    // the USB port. process::exit reclaims everything cleanly (the C5/CYD/LoRa serial-thread gotcha).
    std::process::exit(if exit_ok { 0 } else { 1 });
}
