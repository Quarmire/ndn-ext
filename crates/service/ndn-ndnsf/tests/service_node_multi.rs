#![cfg(feature = "driver")]
//! Witness for `ServiceNode`: several services over ONE shared `SvsPubSub`.
//!
//! `/muas/bob` vends two services (`/svc/echo`, `/svc/cam`) from a single node —
//! two `serve` loops sharing one pub/sub, one wire identity, one publication
//! stream. The four-phase driver routes each request by its `serviceName`, so the
//! echo handler answers only echo and the cam handler answers only cam (the
//! routing fix this exercises: without it, both loops would answer every
//! request). `/muas/alice` calls both via co-located `ServiceUser`s.

use std::time::Duration;

use bytes::Bytes;
use ndn_ndnsf::roles::ServiceNode;
use ndn_packet::Name;
use ndn_sync::{SvSyncConfig, SvsConfig, SvsPubSub};
use tokio::sync::mpsc;

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

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

fn medium() -> (SvsPubSub, SvsPubSub) {
    let group = n("/muas");
    let (a_out_tx, mut a_out_rx) = mpsc::channel::<Bytes>(256);
    let (a_in_tx, a_in_rx) = mpsc::channel::<Bytes>(256);
    let (b_out_tx, mut b_out_rx) = mpsc::channel::<Bytes>(256);
    let (b_in_tx, b_in_rx) = mpsc::channel::<Bytes>(256);
    tokio::spawn(async move {
        while let Some(x) = a_out_rx.recv().await {
            let _ = b_in_tx.send(x).await;
        }
    });
    tokio::spawn(async move {
        while let Some(x) = b_out_rx.recv().await {
            let _ = a_in_tx.send(x).await;
        }
    });
    let provider_ps = SvsPubSub::join(group.clone(), n("/muas/bob"), a_out_tx, a_in_rx, cfg());
    let user_ps = SvsPubSub::join(group, n("/muas/alice"), b_out_tx, b_in_rx, cfg());
    (provider_ps, user_ps)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_node_serves_two_services_routed_by_name() {
    let (provider_ps, user_ps) = medium();

    // One provider node, two services over one shared pub/sub.
    let bob = ServiceNode::new(provider_ps, n("/muas/bob"), n("/muas"));
    let echo = bob.provider(n("/svc/echo"));
    let cam = bob.provider(n("/svc/cam"));
    let echo_task = tokio::spawn(async move { echo.serve(|_c, req| Bytes::copy_from_slice(req)).await });
    let cam_task = tokio::spawn(async move { cam.serve(|_c, _req| Bytes::from_static(b"frame")).await });

    // One user node, calling both services.
    let alice = ServiceNode::new(user_ps, n("/muas/alice"), n("/muas"));
    let echo_user = alice.user(n("/svc/echo")).token("utok");
    let cam_user = alice.user(n("/svc/cam")).token("utok");

    let echo_reply = tokio::time::timeout(
        Duration::from_secs(6),
        echo_user.call(n("/muas/bob"), Bytes::from_static(b"ping")),
    )
    .await
    .ok()
    .flatten();
    let cam_reply = tokio::time::timeout(
        Duration::from_secs(6),
        cam_user.call(n("/muas/bob"), Bytes::from_static(b"snap")),
    )
    .await
    .ok()
    .flatten();

    assert_eq!(
        echo_reply,
        Some(Bytes::from_static(b"ping")),
        "the echo service must answer echo with the echoed payload"
    );
    assert_eq!(
        cam_reply,
        Some(Bytes::from_static(b"frame")),
        "the cam service must answer cam with its own payload (no cross-answer)"
    );

    echo_task.abort();
    cam_task.abort();
}
