//! Two-node NDN Interest/Data exchange over a monitor-mode Wi-Fi radio face.
//!
//! Run a producer on one node and a consumer on another, each with an
//! RTL8812EU dongle in 5 GHz monitor mode on the same channel:
//!
//! ```text
//! # node A (Linux, kernel monitor driver):
//! radio-ping producer --afpacket wlu1u1
//! # node B (macOS, userspace driver):
//! radio-ping consumer --libusb 149
//! ```
//!
//! The consumer expresses `/demo/radio/ping`; the engine forwards it out the
//! radio face; the producer's engine delivers it to the local producer, which
//! answers with Data that travels back over the air along the PIT reverse path.
//!
//! Both forwarders run with `SecurityProfile::Disabled` so they relay the
//! peer's Data verbatim (the Default profile would drop unsigned peer Data).

use std::sync::Arc;

use anyhow::{Result, bail};
use ndn_app::{EngineAppExt, EngineBuilder};
use ndn_engine::SignalView; // read radio RSSI/rate from the engine's signal store
use ndn_face_monitor_wifi::{FaceId, McsDescriptor, MonitorWifiFace, FrameIo};
use ndn_packet::Name;
use ndn_security::SecurityProfile;
use tokio_util::sync::CancellationToken;

const PREFIX: &str = "/demo/radio";
const RADIO_FACE: FaceId = FaceId(10);

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let role = args.get(1).map(String::as_str).unwrap_or("");

    let backend = build_backend(&args)?;
    // Embedded forwarder with just the radio face; Disabled profile relays
    // peer Data (Default drops unsigned peer Data).
    let mut builder = EngineBuilder::new(Default::default()).security_profile(SecurityProfile::Disabled);

    // Rate control. Default = fixed MCS1: measurement shows this link is
    // power-starved (peer hears us at ~-74 dBm at 2 ft), so MCS>1 delivers ~0%
    // — adaptive climbing OFF MCS1 would break the link until TX power is raised
    // (per-device EFUSE power-by-rate). RADIO_PING_ADAPTIVE=1 forces the
    // RSSI-driven picker; RADIO_PING_MCS=<n> pins a fixed MCS.
    let face = MonitorWifiFace::new(RADIO_FACE, backend);
    let face = if std::env::var("RADIO_PING_ADAPTIVE").is_ok() {
        println!("rate: ADAPTIVE (RSSI-driven MCS)");
        face.with_adaptive_mcs()
    } else {
        let n = std::env::var("RADIO_PING_MCS").ok().and_then(|s| s.parse::<u8>().ok()).unwrap_or(1);
        println!("rate: FIXED MCS{n}");
        face.with_fixed_mcs(McsDescriptor::ht(n))
    };
    // Publish the radio's per-frame RSSI/rate into the engine's shared signal
    // store (the same table strategies read via StrategyContext::signals), so
    // forwarding can be cross-layer-aware. `builder.signals()` is the live store.
    let face = face.with_signal_sink(builder.signals());
    let radio = face.into_face();

    builder.add_face_composed(radio);
    let (engine, shutdown) = builder.build().await?;
    let cancel = CancellationToken::new();

    match role {
        "producer" => {
            // RADIO_PING_SIZE bytes of a self-describing pattern (byte i = i&0xff)
            // so the consumer can verify reassembly byte-exact. Sizes above the
            // ~2.2 KB link MTU exercise NDNLPv2 fragmentation across frames.
            let size: usize = std::env::var("RADIO_PING_SIZE")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(18);
            let payload: bytes::Bytes = (0..size).map(|i| (i & 0xff) as u8).collect();
            let producer = engine.register_producer(PREFIX, cancel.child_token());
            println!("producer serving {PREFIX}/* — {size}-byte pattern payload");
            producer
                .serve(move |interest, responder| {
                    let payload = payload.clone();
                    async move {
                        let name: Name = (*interest.name).clone();
                        println!("  <- Interest {name} (-> {} B)", payload.len());
                        let _ = responder.respond(name, payload).await;
                    }
                })
                .await?;
        }
        "consumer" => {
            // Route the prefix out the radio face, then express Interests.
            engine.fib().add_nexthop(&Name::from(PREFIX), RADIO_FACE, 0);
            let mut consumer = engine.app_consumer(cancel.child_token());
            // Broadcast injection is unacknowledged and lossy, so retry across
            // distinct names (the producer serves the whole prefix) until one
            // round-trip lands.
            let tries = 40;
            println!("consumer fetching {PREFIX}/ping/<n> over the radio ({tries} tries)…");
            let mut got = false;
            for i in 0..tries {
                let name = Name::from(format!("{PREFIX}/ping/{i}").as_str());
                // Short lifetime so a lost Interest fails fast and we retry.
                let builder = ndn_packet::encode::InterestBuilder::new(name)
                    .lifetime(std::time::Duration::from_millis(700));
                match consumer.fetch_with(builder).await {
                    Ok(data) => {
                        let content = data.content().map(|c| c.as_ref()).unwrap_or(&[]);
                        // Verify the reassembled content matches the pattern.
                        let bad = content.iter().enumerate().find(|(j, b)| **b != (*j & 0xff) as u8);
                        let verdict = match bad {
                            None => "pattern OK".to_string(),
                            Some((j, b)) => format!("MISMATCH at {j}: {:#x}", *b),
                        };
                        println!(
                            "GOT DATA on try {i}: {} — {} bytes, {verdict}",
                            data.name,
                            content.len(),
                        );
                        // The cross-layer signals the radio face published for
                        // the frames that carried this Data — what a measured
                        // strategy would forward on.
                        if let Some(sig) = engine.signals().link(RADIO_FACE) {
                            println!(
                                "  radio link signals: RSSI {} dBm, rate {} Mb/s",
                                sig.rssi_dbm.map_or("?".into(), |r| r.to_string()),
                                sig.observed_tput_bps.map_or("?".into(), |b| (b / 1_000_000).to_string()),
                            );
                        }
                        got = true;
                        break;
                    }
                    Err(_) => print!("."),
                }
                use std::io::Write;
                let _ = std::io::stdout().flush();
            }
            if !got {
                shutdown.shutdown().await;
                bail!("\nno Data after {tries} tries");
            }
        }
        _ => bail!("usage: radio-ping <producer|consumer> [--libusb <chan> | --afpacket <iface>]"),
    }

    shutdown.shutdown().await;
    Ok(())
}

/// Build the radio backend from `--libusb <chan>` (userspace driver, needs the
/// `libusb` feature) or `--afpacket <iface>` (Linux kernel monitor driver).
fn build_backend(args: &[String]) -> Result<Arc<dyn FrameIo>> {
    if let Some(i) = args.iter().position(|a| a == "--libusb") {
        let _chan_idx = i + 1;
        #[cfg(feature = "libusb")]
        {
            let chan: u8 = args.get(_chan_idx).and_then(|s| s.parse().ok()).unwrap_or(149);
            let be = ndn_face_monitor_wifi::LibUsbRtl88xxBackend::open_monitor(chan)?;
            println!("RTL8812EU (userspace/libusb) up on ch{chan}");
            return Ok(Arc::new(be));
        }
        #[cfg(not(feature = "libusb"))]
        bail!("--libusb requires building with `--features libusb`");
    }
    if let Some(i) = args.iter().position(|a| a == "--afpacket") {
        let _iface_idx = i + 1;
        #[cfg(target_os = "linux")]
        {
            let iface = args.get(_iface_idx).cloned().unwrap_or_else(|| "wlu1u1".into());
            let be = ndn_face_monitor_wifi::AfPacketBackend::new(
                &iface,
                ndn_face_monitor_wifi::FrameFormat::default(),
            )?;
            println!("RTL8812EU (kernel/af_packet) on {iface}");
            return Ok(Arc::new(be));
        }
        #[cfg(not(target_os = "linux"))]
        bail!("--afpacket is Linux-only");
    }
    bail!("specify a radio backend: --libusb <chan> | --afpacket <iface>")
}
