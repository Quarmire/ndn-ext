//! Slice-9 witness: producer identity authentication. The producer signs the
//! SEEK reply with its Ed25519 identity key; a consumer that pins the matching
//! trust anchor authenticates the producer before trusting the sealed pipe id —
//! so an on-path MITM cannot substitute its own key + pipe id. A consumer that
//! pins the *wrong* anchor refuses the reply.

use ndn_app::{Consumer, EngineBuilder, Producer};
use ndn_engine::EngineConfig;
use ndn_face::local::InProcFace;
use ndn_packet::Name;
use ndn_transport::FaceId;

use ndn_pipes::{
    Confidentiality, PipeConsumer, PipeError, PipeParams, PipeProducer, ed25519_public,
};

/// Bring up a single-engine pipe whose producer signs with `producer_sk`; the
/// consumer pins `anchor`. Returns the result of opening the pipe.
async fn open_with(producer_sk: [u8; 32], anchor: [u8; 32]) -> Result<(), PipeError> {
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
        .with_identity(producer_sk, "/pipes/producer/KEY")
        .serve_object(
            &"/sensors/temp/v=42".parse().unwrap(),
            b"unused",
            &ndn_coding::FecPolicy::systematic(8, 12).unwrap(),
            1,
            &[],
            &Confidentiality::None,
        );
    let serve = tokio::spawn(async move { producer.serve().await });

    let mut pc =
        PipeConsumer::new(Consumer::from_handle(consumer_handle)).with_trust_anchor(anchor);
    let result = pc.open("/sensors/temp", PipeParams::default()).await.map(|_| ());

    drop(pc);
    drop(engine);
    shutdown.shutdown().await;
    let _ = serve.await;
    result
}

#[tokio::test]
async fn consumer_with_the_right_anchor_authenticates_the_producer() {
    let producer_sk = [3u8; 32];
    let anchor = ed25519_public(&producer_sk);
    open_with(producer_sk, anchor)
        .await
        .expect("authentic producer signature is accepted");
}

#[tokio::test]
async fn consumer_with_the_wrong_anchor_rejects_the_reply() {
    let producer_sk = [3u8; 32];
    // A different producer's anchor — as if a MITM signed with its own key.
    let wrong_anchor = ed25519_public(&[9u8; 32]);
    let err = open_with(producer_sk, wrong_anchor).await.unwrap_err();
    assert!(
        matches!(err, PipeError::Crypto(_)),
        "unauthenticated producer must be refused, got: {err:?}"
    );
}
