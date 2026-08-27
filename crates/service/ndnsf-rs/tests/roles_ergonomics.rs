#![cfg(feature = "driver")]
//! Worked example + witness for the ergonomic role wrappers (spec §11.2 mode 1).
//!
//! The same echo service, written with `ServiceProvider`/`ServiceUser` instead of
//! the raw `driver` free functions — a closure handler on the provider, a single
//! `call` on the user, request ids auto-assigned. Proves the role surface
//! round-trips on the same wire, both unsigned and with NSF-A3 trust enabled.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_packet::Name;
use ndn_security::KeyChain;
use ndn_sync::{SvSyncConfig, SvsConfig, SvsPubSub};
use ndnsf_rs::roles::{ServiceProvider, ServiceUser};
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

/// A broker-crossed in-memory SVS medium: (provider_ps, user_ps) in `/muas`.
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn roles_echo_round_trips() {
    let (provider_ps, user_ps) = medium();
    let svc = n("/svc/echo");
    let group = n("/muas");

    let provider =
        ServiceProvider::new(provider_ps, n("/muas/bob"), svc.clone(), group.clone()).insecure();
    let user = ServiceUser::new(user_ps, n("/muas/alice"), svc, group)
        .insecure()
        .token("utok");

    let reply = tokio::select! {
        _ = provider.serve(|_coord, req| Bytes::copy_from_slice(req)) => None,
        r = tokio::time::timeout(Duration::from_secs(6), user.call(n("/muas/bob"), Bytes::from_static(b"ping"))) => r.ok().flatten(),
    };
    assert_eq!(
        reply,
        Some(Bytes::from_static(b"ping")),
        "the role wrappers must round-trip an echo over the four-phase wire"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn roles_signed_round_trips() {
    let alice = KeyChain::ephemeral("/muas/alice").unwrap();
    let bob = KeyChain::ephemeral("/muas/bob").unwrap();
    let (provider_ps, user_ps) = medium();
    let svc = n("/svc/echo");
    let group = n("/muas");

    // `.signed(..)` turns on NSF-A3 message trust — provider signs as bob and
    // trusts the requester; user signs as alice and trusts the provider.
    let provider = ServiceProvider::new(provider_ps, n("/muas/bob"), svc.clone(), group.clone())
        .signed(bob.signer().unwrap(), Arc::new(alice.validator()));
    let user = ServiceUser::new(user_ps, n("/muas/alice"), svc, group)
        .token("utok")
        .signed(alice.signer().unwrap(), Arc::new(bob.validator()));

    let reply = tokio::select! {
        _ = provider.serve(|_coord, req| Bytes::copy_from_slice(req)) => None,
        r = tokio::time::timeout(Duration::from_secs(6), user.call(n("/muas/bob"), Bytes::from_static(b"ping"))) => r.ok().flatten(),
    };
    assert_eq!(
        reply,
        Some(Bytes::from_static(b"ping")),
        "the signed role wrappers must round-trip between trusting peers"
    );
}
