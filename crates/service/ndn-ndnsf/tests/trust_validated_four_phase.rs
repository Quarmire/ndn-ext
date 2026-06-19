#![cfg(feature = "driver")]
//! NSF-A3 (trust half) witness: per-message signature validation wired through
//! the four-phase flow over SVS. Each node signs every message it publishes and
//! verifies every message it consumes against the phase's expected sender (the
//! faithful NSF `MessageValidator` placement — trust is enforced in the flow,
//! not at the sync substrate). A signed exchange between mutually-trusting peers
//! round-trips; a provider whose validator does not trust the requester rejects
//! the REQUEST and the call fails closed (no ACK, no RESPONSE).

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_ndnsf::driver::{call, serve_provider};
use ndn_ndnsf::tokens::PendingCoordination;
use ndn_ndnsf::trust::TrustCtx;
use ndn_security::KeyChain;
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

/// Build a broker-crossed in-memory SVS medium and return (provider_ps, user_ps).
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

/// Drive one signed call. `provider_trust`/`user_trust` configure each side's
/// signer + inbound validator. Returns the response payload, if any.
async fn signed_call(provider_trust: TrustCtx, user_trust: TrustCtx) -> Option<Bytes> {
    let (provider_ps, user_ps) = medium();
    let group = n("/muas");
    let handler = |_c: &PendingCoordination, req: &Bytes| -> Bytes {
        assert_eq!(req.as_ref(), b"ping");
        Bytes::from_static(b"pong")
    };
    tokio::select! {
        _ = serve_provider(&provider_ps, n("/muas/bob"), n("/svc/echo"), group.clone(), 3600, &provider_trust, handler) => None,
        r = tokio::time::timeout(
            Duration::from_secs(6),
            call(
                &user_ps,
                n("/muas/alice"),
                n("/muas/bob"),
                n("/svc/echo"),
                n("/r1"),
                group.clone(),
                Bytes::from_static(b"ping"),
                "utok",
                &user_trust,
            ),
        ) => r.ok().flatten(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signed_four_phase_round_trips_between_trusting_peers() {
    let alice = KeyChain::ephemeral("/muas/alice").unwrap();
    let bob = KeyChain::ephemeral("/muas/bob").unwrap();

    // Provider signs as bob, trusts the requester (alice). User signs as alice,
    // trusts the provider (bob). Each verifies the other's messages.
    let provider_trust = TrustCtx::new(bob.signer().unwrap(), Arc::new(alice.validator()));
    let user_trust = TrustCtx::new(alice.signer().unwrap(), Arc::new(bob.validator()));

    let resp = signed_call(provider_trust, user_trust).await;
    assert_eq!(
        resp,
        Some(Bytes::from_static(b"pong")),
        "a signed four-phase exchange between mutually-trusting peers must round-trip"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn request_from_untrusted_requester_fails_closed() {
    let alice = KeyChain::ephemeral("/muas/alice").unwrap();
    let bob = KeyChain::ephemeral("/muas/bob").unwrap();

    // The provider's validator trusts only its OWN anchor (bob) — not alice. The
    // requester signs as alice; the provider rejects the REQUEST at validation,
    // so no ACK is ever published and the call cannot progress.
    let provider_trust = TrustCtx::new(bob.signer().unwrap(), Arc::new(bob.validator()));
    let user_trust = TrustCtx::new(alice.signer().unwrap(), Arc::new(bob.validator()));

    let resp = signed_call(provider_trust, user_trust).await;
    assert_eq!(
        resp, None,
        "a REQUEST whose signer the provider does not trust must fail closed (no response)"
    );
}
