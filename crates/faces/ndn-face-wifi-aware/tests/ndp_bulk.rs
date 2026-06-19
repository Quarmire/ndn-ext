//! Phase 2 witness: the NAN data path (NDP) carries bulk as a plain `UdpFace`.
//!
//! Each node requests an NDP to the other (`NanBackend::request_ndp`), gets a
//! bound UDP socket + peer address, and wraps it in an `ndn-face-native`
//! `UdpFace` — the "bulk on IP, no new transport code" tier. A producer on B
//! serves an 8 KB Data under `/bulk`; a consumer on A fetches it over the NDP
//! UDP face. Proves the request_ndp → UdpFace handoff works end to end.
//!
//! Reverify: `cargo test -p ndn-face-wifi-aware --test ndp_bulk`

use std::sync::Arc;
use std::time::Duration;

use ndn_app::EngineAppExt;
use ndn_engine::{EngineBuilder, EngineConfig, ForwarderEngine};
use ndn_face::net::UdpFace;
use ndn_face_wifi_aware::{LoopbackNanBus, NanBackend};
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
    std::mem::forget(shutdown);
    engine
}

#[tokio::test]
async fn ndp_bulk_flows_over_udp_face() {
    let cancel = CancellationToken::new();
    let bus = LoopbackNanBus::new();
    let backend_a: Arc<dyn NanBackend> = Arc::new(bus.endpoint(1, NMI_A, -50));
    let backend_b: Arc<dyn NanBackend> = Arc::new(bus.endpoint(2, NMI_B, -50));

    // Each side negotiates an NDP to the other and wraps it as a UdpFace.
    let ndp_a = backend_a.request_ndp(NMI_B).await.expect("A NDP");
    let ndp_b = backend_b.request_ndp(NMI_A).await.expect("B NDP");

    let engine_a = build_engine().await;
    let engine_b = build_engine().await;

    let id_a = engine_a.faces().alloc_id();
    engine_a.add_face(
        UdpFace::from_socket(id_a, ndp_a.socket, ndp_a.peer_addr),
        cancel.child_token(),
    );
    let id_b = engine_b.faces().alloc_id();
    engine_b.add_face(
        UdpFace::from_socket(id_b, ndp_b.socket, ndp_b.peer_addr),
        cancel.child_token(),
    );

    let prefix: Name = "/bulk".parse().unwrap();
    // A routes /bulk over its NDP face; Data returns on the PIT reverse path.
    engine_a.fib().add_nexthop(&prefix, id_a, 0);

    // Producer on B serves an 8 KB "bulk" object.
    let payload: Vec<u8> = (0..8192u32).map(|i| (i % 251) as u8).collect();
    let producer = engine_b.register_producer(prefix.clone(), cancel.child_token());
    let name = prefix.clone();
    let served = payload.clone();
    tokio::spawn(async move {
        producer
            .serve(move |_interest, responder| {
                let wire = DataBuilder::new(name.clone(), &served).build();
                async move {
                    responder.respond_bytes(wire).await.ok();
                }
            })
            .await
            .ok();
    });

    let mut consumer = engine_a.app_consumer(cancel.child_token());
    let data = tokio::time::timeout(Duration::from_secs(5), consumer.fetch(prefix.clone()))
        .await
        .expect("bulk fetch within 5s")
        .expect("fetch failed");
    assert_eq!(
        data.content().map(|b| b.as_ref()),
        Some(payload.as_slice()),
        "8 KB bulk object must arrive intact over the NDP UDP face",
    );

    cancel.cancel();
}
