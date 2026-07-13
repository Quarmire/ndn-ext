#![cfg(feature = "engine")]
//! Gate for [`ndnsf_rs::over_face`]: the four-phase `NdnsfCarrier` runs over a
//! **real** `ndn-engine` forwarder/face — the same substrate `ndn-rpc`'s
//! `FaceRpcCarrier` uses — instead of a private in-memory channel mesh. A
//! provider and a user, each bound to the engine via `over_face`, complete a
//! REQUEST→ACK→SELECTION→RESPONSE exchange end to end (Sync Interests, mapping
//! queries, and publication fetches all forwarded by the engine).

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use ndn_app::EngineBuilder;
use ndn_engine::EngineConfig;
use ndnsf_rs::{NdnsfCarrier, over_face};
use ndn_packet::Name;
use ndn_service_core::{Carrier, Dispatch, Invocation, OpId, ServiceError, ServiceId};
use ndn_sync::{SvSyncConfig, SvsConfig};
use tokio_util::sync::CancellationToken;

fn name(s: &str) -> Name {
    s.parse().unwrap()
}

/// A brisk sync cadence so the four phases converge quickly under test.
fn cfg() -> SvSyncConfig {
    SvSyncConfig {
        svs: SvsConfig {
            sync_interval: Duration::from_millis(50),
            jitter_ms: 0,
            ..Default::default()
        },
        ..Default::default()
    }
}

/// Echoes the request payload — proving data flows both ways over the engine.
struct EchoDispatch;
#[async_trait]
impl Dispatch for EchoDispatch {
    async fn dispatch(&self, inv: Invocation) -> Result<Bytes, ServiceError> {
        Ok(inv.request)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ndnsf_carrier_runs_over_a_real_engine() {
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .build()
        .await
        .expect("engine build");
    let cancel = CancellationToken::new();
    let group = name("/muas");
    let svc = ServiceId::new(name("/svc/echo"));

    // Provider bob: its SVS group runs over the engine (multicast on /muas, its
    // data prefix routed to its face).
    let bob_ps = over_face(
        &engine,
        name("/muas/bob"),
        group.clone(),
        cfg(),
        cancel.child_token(),
    )
    .await;
    let bob = NdnsfCarrier::new(bob_ps, name("/muas/bob"), group.clone()).insecure();
    bob.serve(&svc, Arc::new(EchoDispatch)).await.unwrap();

    // User alice: same group, same engine.
    let alice_ps = over_face(
        &engine,
        name("/muas/alice"),
        group.clone(),
        cfg(),
        cancel.child_token(),
    )
    .await;
    let alice = NdnsfCarrier::new(alice_ps, name("/muas/alice"), group.clone())
        .insecure()
        .token("utok");

    // A full four-phase call, forwarded end to end by the engine.
    let resp = tokio::time::timeout(
        Duration::from_secs(15),
        alice.invoke(&svc, &OpId::new("echo"), Bytes::from_static(b"ping")),
    )
    .await
    .expect("call did not complete over the engine")
    .expect("four-phase call failed");
    assert_eq!(
        resp.payload,
        Bytes::from_static(b"ping"),
        "the request must round-trip through the four-phase carrier over a real engine",
    );

    drop(cancel);
    drop(engine);
    shutdown.shutdown().await;
}
