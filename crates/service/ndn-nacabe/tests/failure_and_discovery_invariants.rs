#![cfg(feature = "service")]
//! NSF-A4 / F1 / F2 witnesses for the NAC consumer (`ParamFetcher`).
//!
//! * **NSF-A4** — permission/parameter discovery uses an *unsigned* Interest; the
//!   returned Data is the authenticated object. An unsigned `PUBPARAMS` fetch
//!   succeeds when the response validates against the configured anchor.
//! * **NSF-F1** — a validation failure invokes the registered failure callback
//!   exactly once.
//! * **NSF-F2** — the failure carries the failed Data name and a reason (the same
//!   data the always-on `tracing::warn!` logs).
//!
//! Run with `--features service`.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use ndn_app::{Consumer, EngineBuilder, Producer};
use ndn_engine::{EngineConfig, ForwarderEngine, ShutdownHandle};
use ndn_face::local::InProcFace;
use ndn_nacabe::{CpAuthority, ParamFetcher, serve_cp};
use ndn_packet::Name;
use ndn_security::KeyChain;
use ndn_security::abe::bsw_setup;
use ndn_transport::FaceId;

/// Stand up an in-proc engine with an AA serving `PUBPARAMS` (signed by `aa_kc`)
/// and return a `Consumer` wired to it, plus the serve task + shutdown handles.
async fn aa_harness(
    aa_kc: &KeyChain,
    aa_prefix: &Name,
) -> (
    Consumer,
    tokio::task::JoinHandle<Result<(), ndn_app::AppError>>,
    ShutdownHandle,
    ForwarderEngine,
) {
    let (mp, ms) = bsw_setup().unwrap();
    let authority = Arc::new(CpAuthority::new(mp, ms));

    let (c_face, c_handle) = InProcFace::new(FaceId(1), 64);
    let (p_face, p_handle) = InProcFace::new(FaceId(2), 64);
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(c_face)
        .face(p_face)
        .build()
        .await
        .unwrap();
    engine.fib().add_nexthop(aa_prefix, FaceId(2), 0);

    let producer = Producer::from_handle(p_handle, aa_prefix.clone());
    let consumer = Consumer::from_handle(c_handle);
    // Request-validator is irrelevant here (no DKEY); trust the AA's own anchor.
    let serve = tokio::spawn(serve_cp(
        producer,
        aa_prefix.clone(),
        authority,
        aa_kc.signer().unwrap(),
        Arc::new(aa_kc.validator()),
    ));
    (consumer, serve, shutdown, engine)
}

#[tokio::test]
async fn unsigned_discovery_returns_authenticated_params() {
    // NSF-A4: an unsigned PUBPARAMS discovery is accepted because the *response*
    // validates against the AA anchor (data-centric trust).
    let aa_kc = KeyChain::ephemeral("/muas/aa").unwrap();
    let aa_prefix: Name = "/muas/aa".parse().unwrap();
    let (consumer, serve, shutdown, engine) = aa_harness(&aa_kc, &aa_prefix).await;

    let mut fetcher = ParamFetcher::new(consumer, aa_prefix.clone(), Arc::new(aa_kc.validator()));
    let params = fetcher.fetch_public_params().await;
    assert!(params.is_ok(), "an unsigned discovery must return authenticated params");

    drop(fetcher);
    drop(engine);
    shutdown.shutdown().await;
    serve.abort();
}

#[tokio::test]
async fn validation_failure_fires_callback_once_with_name_and_reason() {
    // The AA signs with its key, but the fetcher trusts a *stranger* anchor, so
    // the PUBPARAMS response fails validation.
    let aa_kc = KeyChain::ephemeral("/muas/aa").unwrap();
    let stranger = KeyChain::ephemeral("/muas/stranger").unwrap();
    let aa_prefix: Name = "/muas/aa".parse().unwrap();
    let (consumer, serve, shutdown, engine) = aa_harness(&aa_kc, &aa_prefix).await;

    let calls = Arc::new(AtomicUsize::new(0));
    let captured: Arc<Mutex<Option<(Name, String)>>> = Arc::new(Mutex::new(None));
    let calls_cb = calls.clone();
    let captured_cb = captured.clone();

    let mut fetcher = ParamFetcher::new(consumer, aa_prefix.clone(), Arc::new(stranger.validator()))
        .with_failure_callback(Arc::new(move |name: &Name, reason: &str| {
            calls_cb.fetch_add(1, Ordering::SeqCst);
            *captured_cb.lock().unwrap() = Some((name.clone(), reason.to_string()));
        }));

    let result = fetcher.fetch_public_params().await;
    assert!(result.is_err(), "an unverifiable response must fail closed");

    // NSF-F1: exactly one callback invocation.
    assert_eq!(calls.load(Ordering::SeqCst), 1, "the failure callback must fire exactly once");
    // NSF-F2: the failure carries the failed name and a non-empty reason.
    let (name, reason) = captured.lock().unwrap().clone().expect("callback captured a failure");
    assert!(name.has_prefix(&aa_prefix), "failure name is the discovery Data name: {name}");
    assert!(!reason.is_empty(), "failure reason must be populated");

    drop(fetcher);
    drop(engine);
    shutdown.shutdown().await;
    serve.abort();
}
