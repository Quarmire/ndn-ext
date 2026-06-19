#![cfg(feature = "driver")]
//! End-to-end witness: a full four-phase NDNSF exchange over real SVS pub/sub.
//!
//! Two `SvsPubSub` nodes (provider + user) converge over a broker-crossed
//! in-memory medium (mirroring ndn-sync's own pubsub tests). The user `call`
//! drives REQUEST→ACK→SELECTION→RESPONSE; the provider `serve_provider` loop
//! ACKs (issuing a token), then on the token-bearing SELECTION runs the handler
//! and responds. Run with `--features driver`.

use std::time::Duration;

use bytes::Bytes;
use ndn_ndnsf::driver::{call, serve_provider};
use ndn_ndnsf::tokens::PendingCoordination;
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn four_phase_over_svs_round_trip() {
    let group = n("/muas");

    // In-memory medium: each node's outbound is forwarded to the other's inbound.
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
    let user_ps = SvsPubSub::join(group.clone(), n("/muas/alice"), b_out_tx, b_in_rx, cfg());

    let handler = |_coord: &PendingCoordination, req: &Bytes| -> Bytes {
        assert_eq!(req.as_ref(), b"ping");
        Bytes::from_static(b"pong")
    };

    let resp = tokio::select! {
        _ = serve_provider(&provider_ps, n("/muas/bob"), n("/svc/echo"), group.clone(), 3600, handler) => None,
        r = tokio::time::timeout(
            Duration::from_secs(10),
            call(
                &user_ps,
                n("/muas/alice"),
                n("/muas/bob"),
                n("/svc/echo"),
                n("/r1"),
                group.clone(),
                Bytes::from_static(b"ping"),
                "utok",
            ),
        ) => r.ok().flatten(),
    };

    assert_eq!(
        resp,
        Some(Bytes::from_static(b"pong")),
        "the four-phase exchange should round-trip a response over SVS"
    );
}
