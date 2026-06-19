//! Cert-chain trust witness: instead of pinning a raw Ed25519 key (TOFU), the
//! consumer validates the SEEK reply through an ndn-security `Validator`. The
//! producer signs with a cert-bearing identity under `/NPD` (which the
//! hierarchical trust schema authorises to sign `/NPD/SEEK/...`); a consumer
//! whose validator trusts that anchor accepts it, and one whose validator trusts
//! a *different* anchor rejects an untrusted producer.

use std::sync::Arc;

use ndn_app::{Consumer, EngineBuilder, Producer};
use ndn_coding::FecPolicy;
use ndn_engine::EngineConfig;
use ndn_face::local::InProcFace;
use ndn_packet::Name;
use ndn_security::{KeyChain, Validator};
use ndn_transport::FaceId;

use ndn_pipes::{Confidentiality, PipeConsumer, PipeError, PipeParams, PipeProducer};

/// Stand up a single-engine pipe whose producer signs with `producer_kc`; the
/// consumer validates the SEEK reply with `validator`. Returns the open result.
async fn open_with(producer_kc: &KeyChain, validator: Arc<Validator>) -> Result<(), PipeError> {
    let (consumer_face, consumer_handle) = InProcFace::new(FaceId(1), 256);
    let (producer_face, producer_handle) = InProcFace::new(FaceId(2), 256);
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(consumer_face)
        .face(producer_face)
        .build()
        .await
        .expect("engine build");
    let root: Name = "/".parse().unwrap();
    engine.fib().add_nexthop(&root, FaceId(2), 0);

    let producer = PipeProducer::new(Producer::from_handle(producer_handle, root))
        .with_signer(producer_kc.signer().expect("signer"))
        .serve_object(
            &"/sensors/temp/v=42".parse().unwrap(),
            b"unused",
            &FecPolicy::systematic(8, 12).unwrap(),
            1,
            &[],
            &Confidentiality::None,
        );
    let serve = tokio::spawn(async move { producer.serve().await });

    let mut pc = PipeConsumer::new(Consumer::from_handle(consumer_handle)).with_validator(validator);
    let result = pc.open("/sensors/temp", PipeParams::default()).await.map(|_| ());

    drop(pc);
    drop(engine);
    shutdown.shutdown().await;
    let _ = serve.await;
    result
}

#[tokio::test]
async fn consumer_accepts_a_producer_chaining_to_the_trusted_anchor() {
    let producer_kc = KeyChain::ephemeral("/NPD").unwrap();
    let validator = Arc::new(producer_kc.validator());
    open_with(&producer_kc, validator)
        .await
        .expect("a producer that chains to the trusted anchor validates");
}

#[tokio::test]
async fn consumer_rejects_an_untrusted_producer() {
    // The consumer trusts one `/NPD` anchor...
    let trusted_kc = KeyChain::ephemeral("/NPD").unwrap();
    let validator = Arc::new(trusted_kc.validator());
    // ...but a different `/NPD` identity (its self-signed cert is not the anchor)
    // signs the reply: the validator can't chain it.
    let evil_kc = KeyChain::ephemeral("/NPD").unwrap();
    let err = open_with(&evil_kc, validator).await.unwrap_err();
    assert!(
        matches!(err, PipeError::Crypto(_)),
        "untrusted producer must be refused, got: {err:?}"
    );
}
