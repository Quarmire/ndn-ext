//! Slice-3 witness: encrypt-then-code confidentiality over a pipe. The producer
//! seals the payload, then segments + codes the ciphertext; a consumer with the
//! content key decodes and decrypts, while one without it cannot read the bulk.
//! Proves the coded/relay layer only ever handles ciphertext.

use ndn_app::{Consumer, EngineBuilder, Producer};
use ndn_coding::FecPolicy;
use ndn_engine::EngineConfig;
use ndn_face::local::InProcFace;
use ndn_packet::Name;
use ndn_transport::FaceId;

use ndn_pipes::{Confidentiality, PipeConsumer, PipeError, PipeParams, PipeProducer};

const KEY: [u8; 32] = [7u8; 32];

/// Stand up an AEAD-sealed pipe; the consumer fetches with `consumer_params`.
async fn run(consumer_params: PipeParams) -> (Vec<u8>, Result<Vec<u8>, PipeError>) {
    let payload: Vec<u8> = (0..2000u32).map(|i| (i % 251) as u8).collect();
    let policy = FecPolicy::systematic(8, 12).unwrap();
    let object: Name = "/sensors/temp/v=42".parse().unwrap();

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

    // Producer seals under KEY, then codes the ciphertext.
    let producer = PipeProducer::new(Producer::from_handle(producer_handle, root)).serve_object(
        &object,
        &payload,
        &policy,
        1,
        &[],
        &Confidentiality::Aead(KEY),
    );
    let serve = tokio::spawn(async move { producer.serve().await });

    let mut pc = PipeConsumer::new(Consumer::from_handle(consumer_handle));
    let pipe = pc.open("/sensors/temp", consumer_params).await.expect("pipe");
    let got = pc.fetch(&pipe, "/v=42").await.map(|b| b.to_vec());

    drop(pc);
    drop(engine);
    shutdown.shutdown().await;
    let _ = serve.await;
    (payload, got)
}

#[tokio::test]
async fn consumer_with_the_key_recovers_plaintext() {
    let (payload, got) = run(PipeParams::default().with_aead_key(KEY)).await;
    assert_eq!(got.expect("decrypts"), payload);
}

#[tokio::test]
async fn consumer_with_wrong_key_cannot_read_the_bulk() {
    // Decodes the ciphertext fine, but the AEAD tag fails → no plaintext.
    let (_payload, got) = run(PipeParams::default().with_aead_key([9u8; 32])).await;
    assert!(matches!(got, Err(PipeError::Crypto(_))), "wrong key must not decrypt");
}
