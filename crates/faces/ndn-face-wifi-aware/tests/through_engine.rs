//! Phase 1.5 through-engine witness: NDN actually traverses the NAN
//! coordination bearer, including NDNLPv2 fragmentation/reassembly.
//!
//! Two independent `ForwarderEngine`s are linked by a hardware-free
//! `LoopbackNanBus`: each gets a `NanCoordFace` endpoint on the shared cluster.
//! A producer on engine B serves a **2 KB** Data — well over the 255 B follow-up
//! MTU — so the engine's LP link service must fragment it across many follow-up
//! messages and engine A must reassemble. A consumer on engine A fetches it and
//! must get the payload back byte-for-byte. This exercises the full path:
//! Interest A → NAN follow-up → B → producer → fragmented Data → many follow-ups
//! → A reassembles → consumer.
//!
//! Reverify: `cargo test -p ndn-face-wifi-aware --test through_engine`

use std::sync::Arc;
use std::time::Duration;

use ndn_app::EngineAppExt;
use ndn_engine::{EngineBuilder, EngineConfig, ForwarderEngine};
use ndn_face_wifi_aware::{FOLLOWUP_MTU, LoopbackNanBus, NanCoordFace};
use ndn_packet::Name;
use ndn_packet::encode::DataBuilder;
use ndn_security::SecurityProfile;
use tokio_util::sync::CancellationToken;

const NMI_A: [u8; 6] = [0xA0; 6];
const NMI_B: [u8; 6] = [0xB0; 6];

async fn build_engine() -> ForwarderEngine {
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .security_profile(SecurityProfile::Disabled)
        .build()
        .await
        .expect("engine build");
    // Keep the engine running for the test's duration.
    std::mem::forget(shutdown);
    engine
}

#[tokio::test]
async fn large_data_fragments_and_reassembles_over_nan() {
    let cancel = CancellationToken::new();
    let engine_a = build_engine().await;
    let engine_b = build_engine().await;

    // One shared NAN cluster; a coordination face on each engine.
    let bus = LoopbackNanBus::new();
    let id_a = engine_a.faces().alloc_id();
    let id_b = engine_b.faces().alloc_id();
    engine_a.add_face(
        NanCoordFace::new(id_a, Arc::new(bus.endpoint(1, NMI_A, -50))),
        cancel.child_token(),
    );
    engine_b.add_face(
        NanCoordFace::new(id_b, Arc::new(bus.endpoint(2, NMI_B, -50))),
        cancel.child_token(),
    );

    let prefix: Name = "/nan/test".parse().unwrap();

    // A forwards Interests for the prefix out its NAN face; the Data returns on
    // the PIT reverse path, so no route is needed on the way back.
    engine_a.fib().add_nexthop(&prefix, id_a, 0);

    // Producer on B serves a payload several follow-up messages long.
    let payload: Vec<u8> = (0..2000u32).map(|i| (i % 251) as u8).collect();
    assert!(
        payload.len() > FOLLOWUP_MTU * 4,
        "payload must span several follow-up fragments to exercise reassembly"
    );
    let producer = engine_b.register_producer(prefix.clone(), cancel.child_token());
    let data_name = prefix.clone();
    let served = payload.clone();
    tokio::spawn(async move {
        producer
            .serve(move |_interest, responder| {
                let wire = DataBuilder::new(data_name.clone(), &served).build();
                async move {
                    responder.respond_bytes(wire).await.ok();
                }
            })
            .await
            .ok();
    });

    // Consumer on A fetches across the cluster.
    let mut consumer = engine_a.app_consumer(cancel.child_token());
    let data = tokio::time::timeout(Duration::from_secs(5), consumer.fetch(prefix.clone()))
        .await
        .expect("fetch did not complete within 5s (fragmentation/reassembly stalled)")
        .expect("fetch failed");

    assert_eq!(
        data.content().map(|b| b.as_ref()),
        Some(payload.as_slice()),
        "the 2 KB payload must arrive intact after fragmentation + reassembly over NAN",
    );

    cancel.cancel();
}
