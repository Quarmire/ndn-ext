#![cfg(feature = "driver")]
//! Targeted-mode witness over SVS: the user bootstraps a token pool from a
//! provider, then invokes it directly (REQUEST→RESPONSE, no ACK/SELECTION) with
//! a pooled token. A bogus token fails closed — no response.

use std::time::Duration;

use bytes::Bytes;
use ndn_ndnsf::driver::{bootstrap_targeted, call_targeted, serve_provider};
use ndn_ndnsf::tokens::PendingCoordination;
use ndn_ndnsf::trust::TrustCtx;
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
async fn targeted_fast_path_over_svs() {
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
    let user_ps = SvsPubSub::join(group.clone(), n("/muas/alice"), b_out_tx, b_in_rx, cfg());
    let trust = TrustCtx::insecure();

    let handler = |_c: &PendingCoordination, _req: &Bytes| -> Bytes { Bytes::from_static(b"pong") };

    let user_flow = async {
        // Bootstrap: obtain a pool of single-use tokens from the provider.
        let tokens = bootstrap_targeted(
            &user_ps,
            n("/muas/alice"),
            n("/muas/bob"),
            n("/svc/echo"),
            n("/r0"),
            group.clone(),
            "utok",
            &trust,
        )
        .await;
        // Targeted call with a pooled token: direct REQUEST→RESPONSE.
        let good = if let Some(tok) = tokens.first() {
            call_targeted(
                &user_ps,
                n("/muas/alice"),
                n("/muas/bob"),
                n("/svc/echo"),
                n("/r1"),
                group.clone(),
                Bytes::from_static(b"ping"),
                "utok",
                tok,
                &trust,
            )
            .await
        } else {
            None
        };
        // A bogus token coordinates nothing → no response (fail closed).
        let bad = tokio::time::timeout(
            Duration::from_secs(1),
            call_targeted(
                &user_ps,
                n("/muas/alice"),
                n("/muas/bob"),
                n("/svc/echo"),
                n("/r2"),
                group.clone(),
                Bytes::from_static(b"ping"),
                "utok",
                "bogus-token",
                &trust,
            ),
        )
        .await
        .ok()
        .flatten();
        (tokens.len(), good, bad)
    };

    let (ntokens, good, bad) = tokio::select! {
        _ = serve_provider(&provider_ps, n("/muas/bob"), n("/svc/echo"), group.clone(), 3600, &trust, handler) => (0, None, None),
        r = tokio::time::timeout(Duration::from_secs(10), user_flow) => r.unwrap_or((0, None, None)),
    };

    assert!(ntokens >= 1, "bootstrap should return a token pool");
    assert_eq!(
        good,
        Some(Bytes::from_static(b"pong")),
        "targeted call should respond"
    );
    assert_eq!(bad, None, "a bogus token must fail closed (no response)");
}
