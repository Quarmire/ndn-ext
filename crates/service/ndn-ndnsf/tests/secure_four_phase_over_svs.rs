#![cfg(feature = "driver")]
//! NSF-A3 witness: KP-ABE access control wired through the four-phase flow over
//! SVS. The provider's handler NAC-seals its response under the service's
//! attribute; an authorized user (holding a ServiceController-issued policy key
//! satisfied by it) decrypts the response after the exchange, while an
//! unauthorized key fails closed — the payload never affects its state.

use std::time::Duration;

use bytes::Bytes;
use ndn_foundation_types::Hash;
use ndn_ndnsf::access::{open_with, seal_for};
use ndn_ndnsf::driver::{call, serve_provider};
use ndn_ndnsf::tokens::PendingCoordination;
use ndn_ndnsf::trust::TrustCtx;
use ndn_packet::Name;
use ndn_security::abe::{PolicyExpr, lsw_keygen, lsw_setup};
use ndn_sync::{SvSyncConfig, SvsConfig, SvsPubSub};
use tokio::sync::mpsc;

const AAD: &[u8] = b"/svc/echo/r1";

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
async fn secure_four_phase_access_controlled() {
    // The ServiceController's KP-ABE master keypair + the authorized user's key.
    let (mp, ms) = lsw_setup().unwrap();
    let kgc = (n("/muas/controller"), Hash::of(&mp.public_key_bytes), mp.clone());
    let authorized = lsw_keygen(
        &mp,
        &ms,
        &PolicyExpr::parse("service:echo OR service:cam").unwrap(),
    )
    .unwrap();

    // Broker-crossed SVS medium (as in the plaintext driver witness).
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
    let trust = TrustCtx::default();

    // The provider seals its echoed response under the service attribute.
    let handler = move |_c: &PendingCoordination, req: &Bytes| -> Bytes {
        seal_for(
            n("/muas/bob/CK/1"),
            &["service:echo".to_string()],
            &kgc,
            req.as_ref(),
            AAD,
        )
        .expect("seal response")
    };

    let sealed = tokio::select! {
        _ = serve_provider(&provider_ps, n("/muas/bob"), n("/svc/echo"), group.clone(), 3600, &trust, handler) => None,
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
                &trust,
            ),
        ) => r.ok().flatten(),
    };
    let sealed = sealed.expect("the four-phase exchange should deliver a sealed response");

    // The authorized user decrypts the response.
    assert_eq!(open_with(&authorized, &sealed, AAD).unwrap(), b"ping");

    // An unauthorized key (policy not satisfied) fails closed — no plaintext.
    let unauthorized = lsw_keygen(&mp, &ms, &PolicyExpr::parse("service:other").unwrap()).unwrap();
    assert!(open_with(&unauthorized, &sealed, AAD).is_err());
}
