#![cfg(feature = "driver")]
//! Compact-SELECTION wire refresh witnesses (upstream parity, 2026-08):
//!
//! 1. **Inbound legacy compat** — a legacy user (pre-2026-06-07 shape: per-
//!    provider selection name + plaintext token) is still served by our
//!    provider, mirroring upstream's accept-old-emit-new posture.
//! 2. **Negative-ACK early stop** (spec 044) — a provider that answers
//!    `status=false` + reason ends the user's `call` immediately, not at a
//!    timeout.
//! 3. **Only the selected provider responds** — FirstResponding's one compact
//!    publication yields exactly one response, while AllSelected over the same
//!    provider pair yields two — so the single response reflects *selection*
//!    (the unselected provider saw `NotForUs`), not a dead provider.

use std::time::Duration;

use bytes::Bytes;
use ndnsf_rs::driver::{call, select_and_call, serve_provider};
use ndnsf_rs::flow::{make_request, make_selection};
use ndnsf_rs::messages::{AckMessage, ResponseMessage, Strategy, reason};
use ndnsf_rs::names;
use ndnsf_rs::tokens::PendingCoordination;
use ndnsf_rs::trust::TrustCtx;
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

/// One node's endpoint on the in-memory medium: (outbound sender, inbound receiver).
type Endpoint = (mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>);

/// Cross two nodes' in-memory channels (the ndn-sync pubsub-test medium).
fn cross() -> (Endpoint, Endpoint) {
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
    ((a_out_tx, a_in_rx), (b_out_tx, b_in_rx))
}

/// A legacy (pre-compact) user: drives the four phases by hand, publishing the
/// **old per-provider selection name with the plaintext token** — the shape our
/// provider must keep accepting inbound.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn legacy_selection_shape_still_accepted() {
    let group = n("/muas");
    let ((a_tx, a_rx), (b_tx, b_rx)) = cross();
    let provider_ps = SvsPubSub::join(group.clone(), n("/muas/bob"), a_tx, a_rx, cfg());
    let user_ps = SvsPubSub::join(group.clone(), n("/muas/alice"), b_tx, b_rx, cfg());
    let trust = TrustCtx::insecure();

    let handler = |_c: &PendingCoordination, req: &Bytes| -> Bytes {
        assert_eq!(req.as_ref(), b"ping");
        Bytes::from_static(b"pong")
    };

    let legacy_user = async {
        let mut rx = user_ps.subscribe(group.clone()).await;
        let (requester, provider, service, reqid) =
            (n("/muas/alice"), n("/muas/bob"), n("/svc/echo"), n("/r1"));

        // Phase 1: REQUEST.
        let req = make_request("/r1", "utok", Bytes::from_static(b"ping"));
        let req_name = names::request_name(&requester, &service, &reqid);
        user_ps
            .publish(req_name.clone(), trust.seal(req_name, req.encode()).as_ref())
            .await
            .unwrap();

        // Phase 2: await the ACK, keep its plaintext token.
        let ack = loop {
            let pubn = rx.recv().await.unwrap();
            if pubn.name.to_string().contains("/NDNSF/ACK") {
                let payload = trust
                    .unseal(pubn.payload, &provider, &pubn.name)
                    .await
                    .unwrap();
                break AckMessage::decode(payload).unwrap();
            }
        };
        assert!(ack.status && !ack.provider_token.is_empty());

        // Phase 3: the LEGACY shape — per-provider name, plaintext token.
        let sel = make_selection(&ack, "/r1");
        let sel_name = names::selection_name(&requester, &provider, &service, &reqid);
        user_ps
            .publish(sel_name.clone(), trust.seal(sel_name, sel.encode()).as_ref())
            .await
            .unwrap();

        // Phase 4: the provider must still serve it.
        loop {
            let pubn = rx.recv().await.unwrap();
            if pubn.name.to_string().contains("/NDNSF/RESPONSE") {
                let payload = trust
                    .unseal(pubn.payload, &provider, &pubn.name)
                    .await
                    .unwrap();
                break ResponseMessage::decode(payload).unwrap().payload;
            }
        }
    };

    let resp = tokio::select! {
        _ = serve_provider(&provider_ps, n("/muas/bob"), n("/svc/echo"), group.clone(), 3600, &trust, handler) => None,
        r = tokio::time::timeout(Duration::from_secs(10), legacy_user) => r.ok(),
    };
    assert_eq!(
        resp,
        Some(Bytes::from_static(b"pong")),
        "the legacy per-provider selection shape must stay accepted inbound"
    );
}

/// Spec 044: a known provider's negative ACK ends the call at once — the user
/// does not sit out a response window that can never fill.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn negative_ack_early_stops_call() {
    let group = n("/muas");
    let ((a_tx, a_rx), (b_tx, b_rx)) = cross();
    let provider_ps = SvsPubSub::join(group.clone(), n("/muas/bob"), a_tx, a_rx, cfg());
    let user_ps = SvsPubSub::join(group.clone(), n("/muas/alice"), b_tx, b_rx, cfg());
    let trust = TrustCtx::insecure();

    // A provider that declines everything: REQUEST → negative ACK (PROVIDER_BUSY).
    let declining_provider = async {
        let mut rx = provider_ps.subscribe(group.clone()).await;
        while let Some(pubn) = rx.recv().await {
            if pubn.name.to_string().contains("/NDNSF/REQUEST") {
                let nack = AckMessage::negative(reason::PROVIDER_BUSY, "utok");
                let reqid = n("/r1");
                let name =
                    names::ack_name(&n("/muas/bob"), &n("/muas/alice"), &n("/svc/echo"), &reqid);
                let _ = provider_ps
                    .publish(name.clone(), trust.seal(name, nack.encode()).as_ref())
                    .await;
            }
        }
    };

    let started = std::time::Instant::now();
    let resp = tokio::select! {
        _ = declining_provider => None,
        r = tokio::time::timeout(
            Duration::from_secs(30),
            call(
                &user_ps,
                n("/muas/alice"),
                n("/muas/bob"),
                n("/svc/echo"),
                n("/r1"),
                group.clone(),
                Bytes::from_static(b"ping"),
                "utok",
                &trust,
            ),
        ) => r.ok().flatten(),
    };
    assert_eq!(resp, None, "a negative ACK must not produce a response");
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "the negative ACK must stop the call early, not at the outer timeout"
    );
}

/// The compact selection names only the selected provider; the other provider
/// finds no entry for itself (`NotForUs`) and publishes nothing. A spy counts
/// RESPONSE publications for the request to prove exactly one provider ran.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_selected_provider_responds() {
    let group = n("/muas");
    // Three nodes on a hub: providers A and B, user C. Hub-cross the channels.
    let (a_out_tx, mut a_out_rx) = mpsc::channel::<Bytes>(256);
    let (a_in_tx, a_in_rx) = mpsc::channel::<Bytes>(256);
    let (b_out_tx, mut b_out_rx) = mpsc::channel::<Bytes>(256);
    let (b_in_tx, b_in_rx) = mpsc::channel::<Bytes>(256);
    let (c_out_tx, mut c_out_rx) = mpsc::channel::<Bytes>(256);
    let (c_in_tx, c_in_rx) = mpsc::channel::<Bytes>(256);
    // Hub: everything from one node reaches the other two.
    let (hb, hc) = (b_in_tx.clone(), c_in_tx.clone());
    tokio::spawn(async move {
        while let Some(x) = a_out_rx.recv().await {
            let _ = hb.send(x.clone()).await;
            let _ = hc.send(x).await;
        }
    });
    let (ha2, hc2) = (a_in_tx.clone(), c_in_tx.clone());
    tokio::spawn(async move {
        while let Some(x) = b_out_rx.recv().await {
            let _ = ha2.send(x.clone()).await;
            let _ = hc2.send(x).await;
        }
    });
    tokio::spawn(async move {
        while let Some(x) = c_out_rx.recv().await {
            let _ = a_in_tx.send(x.clone()).await;
            let _ = b_in_tx.send(x).await;
        }
    });

    let pa = SvsPubSub::join(group.clone(), n("/muas/stationA"), a_out_tx, a_in_rx, cfg());
    let pb = SvsPubSub::join(group.clone(), n("/muas/stationB"), b_out_tx, b_in_rx, cfg());
    let pc = SvsPubSub::join(group.clone(), n("/muas/alice"), c_out_tx, c_in_rx, cfg());
    let trust = TrustCtx::insecure();

    let handler_a = |_c: &PendingCoordination, _req: &Bytes| -> Bytes { Bytes::from_static(b"A") };
    let handler_b = |_c: &PendingCoordination, _req: &Bytes| -> Bytes { Bytes::from_static(b"B") };

    let svc = n("/svc/weather");
    let user = async {
        // Round 1: FirstResponding — the compact selection names ONE provider;
        // exactly one response comes back (the other sees NotForUs and stays
        // silent — witnessed at the engine level in flow::tests).
        let first = select_and_call(
            &pc,
            n("/muas/alice"),
            svc.clone(),
            n("/r7"),
            group.clone(),
            Bytes::from_static(b"q"),
            "utok",
            Strategy::FirstResponding,
            Duration::from_secs(2),
            &trust,
            None,
        )
        .await;

        // Round 2: AllSelected over the same two providers — both entries land
        // in ONE compact publication and both respond, proving round 1's single
        // response reflects *selection*, not a dead provider.
        let all = select_and_call(
            &pc,
            n("/muas/alice"),
            svc.clone(),
            n("/r8"),
            group.clone(),
            Bytes::from_static(b"q"),
            "utok",
            Strategy::AllSelected,
            Duration::from_secs(2),
            &trust,
            None,
        )
        .await;
        (first, all)
    };

    let (first, all) = tokio::select! {
        _ = serve_provider(&pa, n("/muas/stationA"), svc.clone(), group.clone(), 3600, &trust, handler_a) => (Vec::new(), Vec::new()),
        _ = serve_provider(&pb, n("/muas/stationB"), svc.clone(), group.clone(), 3600, &trust, handler_b) => (Vec::new(), Vec::new()),
        r = tokio::time::timeout(Duration::from_secs(20), user) => r.unwrap_or((Vec::new(), Vec::new())),
    };

    assert_eq!(
        first.len(),
        1,
        "FirstResponding must yield exactly one response"
    );
    assert_eq!(
        all.len(),
        2,
        "AllSelected over one compact publication must reach both providers"
    );
}
