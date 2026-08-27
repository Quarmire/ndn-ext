//! **The ESP32-C5 as a first-class NDN face in a ForwarderEngine** (dual-band serial bridge).
//!
//! The step 2–5 work proved the C5 as a `FrameIo`/`RadioKnobs`/`RadioProfile`; this proves it as a
//! *forwarder face*, exactly as `ar9271_relay` does for the AR9271. Its `OpenRadio` (io + knobs + time
//! + dual-band profile) is wrapped in a [`WifiPhy`] via `from_open` — so the discovered
//! capability is the real dual-band one, not the placeholder `WifiPhy::new` invents — composed
//! into an `EngineBuilder`, and a demo prefix routed out it. Interests expressed on the app face are
//! FORWARDED BY THE ENGINE out the C5 and hit the air as real LP-framed NDN (ethertype 0x8624); the
//! mt76 witness counts them, and the face's RX pump delivers received NDN back into the engine.
//!
//! ```sh
//! C5_PORT=/dev/cu.usbmodem1101 NODE_CH=1 TICKS=40 \
//!   cargo run --example c5_relay --features serial-radio -p ndn-radio-node
//! ```
use std::time::Duration;

use bytes::Bytes;
use ndn_engine::{EngineBuilder, EngineConfig};
use ndn_face_local::InProcFace;
use ndn_face_monitor_wifi::{
    Bandwidth, Esp32SerialBackend, FaceId, RadioKnobs, RadioProfile, WifiPhy,
};
use ndn_packet::encode::InterestBuilder;
use ndn_packet::{Data, Name, NameComponent};
use ndn_transport::FaceId as TransportFaceId;

const APP_FACE_ID: TransportFaceId = TransportFaceId(10_000);
const RADIO_FACE_ID: TransportFaceId = TransportFaceId(1);

fn env_u64(k: &str, d: u64) -> u64 {
    std::env::var(k)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(d)
}

fn demo_prefix() -> Name {
    Name::from_components([NameComponent::generic(Bytes::from_static(b"radio-demo"))])
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let port = std::env::var("C5_PORT").unwrap_or_else(|_| "/dev/cu.usbmodem1101".into());
    let ch = env_u64("NODE_CH", 1) as u8;
    let ticks = env_u64("TICKS", 40);
    let tick_ms = env_u64("NODE_TICK_MS", 100);

    // Open the C5 as an OpenRadio (io + knobs + time + dual-band profile), tune it via its own knob.
    let radio = Esp32SerialBackend::open_c5_radio(&port)?;
    if let Some(k) = &radio.knobs {
        k.set_channel(ch, Bandwidth::Bw20)?;
    }
    let cap = radio.profile.as_ref().expect("C5 profile").capability();
    println!(
        "C5 open on {port} ch{ch} — bands {:?}, channels {:?}; wrapping its FrameIo in a WifiPhy (engine face {})",
        cap.bands, cap.channels, RADIO_FACE_ID.0
    );

    // Compose the engine: an in-proc app face + the C5 radio face (capability discovered from the profile).
    let (app_face, app_handle) = InProcFace::new(APP_FACE_ID, 64);
    let radio_face = WifiPhy::from_open(FaceId(RADIO_FACE_ID.0), radio, cap).into_face();
    let builder = EngineBuilder::new(EngineConfig::default())
        .face(app_face)
        .face_composed(radio_face);
    let (engine, _shutdown) = builder.build().await?;
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Route the demo prefix out the C5 face: an Interest for /radio-demo/* forwards on air.
    engine.fib().add_nexthop(&demo_prefix(), RADIO_FACE_ID, 0);
    println!("FIB: /radio-demo → C5 face. Expressing {ticks} Interests (each forwards on air)…");

    let mut got = 0u32;
    for seq in 0..ticks {
        let name = Name::from_components([
            NameComponent::generic(Bytes::from_static(b"radio-demo")),
            NameComponent::generic(Bytes::copy_from_slice(seq.to_string().as_bytes())),
        ]);
        app_handle
            .send(InterestBuilder::new(name).must_be_fresh().build())
            .await?;
        if let Ok(Some(wire)) =
            tokio::time::timeout(Duration::from_millis(tick_ms), app_handle.recv()).await
        {
            if let Ok(d) = Data::decode(wire) {
                got += 1;
                println!(
                    "  seq {seq}: Data over the C5 ({} B) ✓",
                    d.content().map(|c| c.len()).unwrap_or(0)
                );
            }
        }
    }

    println!(
        "\n→ {ticks} Interests forwarded out the C5 engine face (on-air LP-NDN); {got} Data returned.\n\
         The ESP32-C5 is a live ForwarderEngine face: engine egress → real 0x8624 frames on air, serial\n\
         RX → engine ingress. An mt76 witness counting our SA confirms the on-air half."
    );
    Ok(())
}
