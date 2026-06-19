//! Phase 3 witness: NAN service publish/subscribe drives NDN route install.
//!
//! Node B advertises a NAN service bound to prefix `/svc` and serves it. Node A
//! subscribes to that service via a `NanDiscovery` registered as its discovery
//! protocol — **no manual FIB route is configured on A**. When the engine ticks
//! `NanDiscovery`, the match (B offering the service) installs a route for
//! `/svc` toward A's NAN coordination face. The witness asserts (1) the route
//! appears purely from discovery, and (2) a consumer on A can then fetch `/svc`
//! end-to-end across the cluster.
//!
//! Reverify: `cargo test -p ndn-face-wifi-aware --test discovery`

use std::sync::Arc;
use std::time::Duration;

use ndn_app::EngineAppExt;
use ndn_engine::{EngineBuilder, EngineConfig, ForwarderEngine, ShutdownHandle};
use ndn_face_wifi_aware::{LoopbackNanBus, NanBackend, NanCoordFace, NanDiscovery, NanServiceName};
use ndn_packet::Name;
use ndn_packet::encode::DataBuilder;
use ndn_security::SecurityProfile;
use tokio_util::sync::CancellationToken;

const NMI_A: [u8; 6] = [0xA0; 6];
const NMI_B: [u8; 6] = [0xB0; 6];
const SERVICE: &str = "ndn-svc";

async fn poll_until(timeout: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if cond() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    cond()
}

#[tokio::test]
async fn nan_service_match_installs_route_and_fetch_works() {
    let cancel = CancellationToken::new();
    let bus = LoopbackNanBus::new();
    let prefix: Name = "/svc".parse().unwrap();

    // ── Node A: subscribes to the service via NanDiscovery (no manual FIB). ──
    let backend_a: Arc<dyn NanBackend> = Arc::new(bus.endpoint(1, NMI_A, -50));
    let mut builder_a =
        EngineBuilder::new(EngineConfig::default()).security_profile(SecurityProfile::Disabled);
    let coord_id_a = builder_a.alloc_face_id();
    let discovery = NanDiscovery::new(Arc::clone(&backend_a), coord_id_a)
        .discover(NanServiceName::new(SERVICE), prefix.clone())
        .await
        .expect("subscribe");
    builder_a.register_discovery(Arc::new(discovery));
    let (engine_a, sd_a): (ForwarderEngine, ShutdownHandle) =
        builder_a.build().await.expect("engine A build");
    std::mem::forget(sd_a);
    engine_a.add_face(
        NanCoordFace::new(coord_id_a, Arc::clone(&backend_a)),
        cancel.child_token(),
    );

    // ── Node B: advertises the service and serves /svc. ─────────────────────
    let backend_b: Arc<dyn NanBackend> = Arc::new(bus.endpoint(2, NMI_B, -50));
    backend_b
        .publish(&NanServiceName::new(SERVICE))
        .await
        .expect("publish");
    let (engine_b, sd_b) = EngineBuilder::new(EngineConfig::default())
        .security_profile(SecurityProfile::Disabled)
        .build()
        .await
        .expect("engine B build");
    std::mem::forget(sd_b);
    let coord_id_b = engine_b.faces().alloc_id();
    engine_b.add_face(
        NanCoordFace::new(coord_id_b, Arc::clone(&backend_b)),
        cancel.child_token(),
    );
    let producer = engine_b.register_producer(prefix.clone(), cancel.child_token());
    let name = prefix.clone();
    tokio::spawn(async move {
        producer
            .serve(move |_interest, responder| {
                let wire = DataBuilder::new(name.clone(), b"discovered!").build();
                async move {
                    responder.respond_bytes(wire).await.ok();
                }
            })
            .await
            .ok();
    });

    // (1) Discovery installs the route — purely from the NAN match, no manual FIB.
    let routed = poll_until(Duration::from_secs(3), || {
        engine_a.fib().lpm(&"/svc/data".parse().unwrap()).is_some()
    })
    .await;
    assert!(
        routed,
        "NanDiscovery should install a /svc route from the NAN service match"
    );

    // (2) The discovered route is usable end-to-end.
    let mut consumer = engine_a.app_consumer(cancel.child_token());
    let data = tokio::time::timeout(Duration::from_secs(5), consumer.fetch(prefix.clone()))
        .await
        .expect("fetch within 5s")
        .expect("fetch failed");
    assert_eq!(
        data.content().map(|b| b.as_ref()),
        Some(b"discovered!".as_ref()),
        "consumer must fetch /svc over the route discovery installed",
    );

    cancel.cancel();
}
