//! **#11 — the AR9271 as a first-class NDN face in a ForwarderEngine.**
//!
//! The lease/filter/rate work proved the AR9271 as a `FrameIo`; this proves it as a *forwarder face*:
//! its `FrameIo` is wrapped in a [`WifiPhy`] (the same LP link-service path the RTL8822E relay
//! uses), composed into an `EngineBuilder`, and a demo prefix is routed out it. Interests expressed on
//! the app face are then FORWARDED BY THE ENGINE out the AR9271 and hit the air as real LP-framed NDN
//! (ethertype 0x8624) — a second radio in monitor/rx (e.g. `tx_probe NDN_ROLE=rx`) or the mt76 witness
//! counts them. The face's RX pump (`NDN_ATH9K_PUMP=1`, set below) delivers any received NDN back into
//! the engine, so a producer on the other side would close the Interest→Data loop.
//!
//! This is the AR9271 doing what only the Realtek parts could before: carrying engine traffic on air.
//!
//! ```sh
//! sudo NDN_ATH9K_FW=~/ath9k-fw/target_firmware/build/k2/htc_9271.fw \
//!      NDN_ATH9K_PUMP=1 TICKS=40 NODE_CH=1 /tmp/ar9271_relay
//! ```
use std::time::Duration;

use bytes::Bytes;
use ndn_engine::{EngineBuilder, EngineConfig};
use ndn_face_local::InProcFace;
use ndn_face_monitor_wifi::{FaceId, WifiPhy, open_ath9k};
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
    let ch = env_u64("NODE_CH", 1) as u8;
    let ticks = env_u64("TICKS", 40) as u64;
    let tick_ms = env_u64("NODE_TICK_MS", 100);

    // Open the AR9271 through the production path (loads fw, brings up the PHY, starts the RX pump if
    // NDN_ATH9K_PUMP is set) and take its FrameIo — the exact `Arc<dyn FrameIo>` a face consumes.
    let radio = open_ath9k(ch)?;
    let io = radio.io.clone();
    println!(
        "AR9271 open on ch{ch}; wrapping its FrameIo in a WifiPhy (engine face {})",
        RADIO_FACE_ID.0
    );

    // Compose the engine: an in-proc app face + the AR9271 radio face.
    let (app_face, app_handle) = InProcFace::new(APP_FACE_ID, 64);
    let radio_face = WifiPhy::new(FaceId(RADIO_FACE_ID.0), io).into_face();
    let builder = EngineBuilder::new(EngineConfig::default())
        .face(app_face)
        .face_composed(radio_face);
    let (engine, _shutdown) = builder.build().await?;
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Route the demo prefix out the AR9271 face: an Interest for /radio-demo/* forwards on air.
    engine.fib().add_nexthop(&demo_prefix(), RADIO_FACE_ID, 0);
    println!(
        "FIB: /radio-demo → AR9271 face. Expressing {ticks} Interests (each forwards on air)…"
    );

    // Drain any Data the engine delivers back to the app (a producer on the far side would answer).
    let mut got = 0u32;
    for seq in 0..ticks {
        let name = Name::from_components([
            NameComponent::generic(Bytes::from_static(b"radio-demo")),
            NameComponent::generic(Bytes::copy_from_slice(seq.to_string().as_bytes())),
        ]);
        app_handle
            .send(InterestBuilder::new(name).must_be_fresh().build())
            .await?;
        // Short wait: if a producer answered over the air, the engine forwards the Data back here.
        if let Ok(Some(wire)) =
            tokio::time::timeout(Duration::from_millis(tick_ms), app_handle.recv()).await
        {
            if let Ok(d) = Data::decode(wire) {
                got += 1;
                println!(
                    "  seq {seq}: Data over the AR9271 ({} B) ✓",
                    d.content().map(|c| c.len()).unwrap_or(0)
                );
            }
        }
    }

    println!(
        "\n→ {ticks} Interests forwarded out the AR9271 engine face (on-air LP-NDN); {got} Data returned.\n\
         The AR9271 is a live ForwarderEngine face: engine egress → real 0x8624 frames on air, RX pump\n\
         → engine ingress. A witness/rx-radio counting our SA confirms the on-air half."
    );
    Ok(())
}
