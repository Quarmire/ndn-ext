//! Slice-7 witness: the handshake crypto. The producer seals a random pipe id +
//! pipe key to the consumer's X25519 public key (carried in the SEEK app-params),
//! so only the consumer can JOIN. The pipe key never appears in a name, so a
//! party that learns the pipe id from the JOIN cannot forge a TEARDOWN: the
//! producer rejects a teardown bearing the wrong key, and reclaims only on the
//! real one.
//!
//! (The seal/open confidentiality property — wrong key cannot recover the id —
//! is unit-tested in `crypto.rs`; here we prove it end to end through teardown.)

use bytes::Bytes;
use ndn_app::{Consumer, EngineBuilder, Producer};
use ndn_engine::EngineConfig;
use ndn_face::local::InProcFace;
use ndn_packet::Name;
use ndn_transport::FaceId;

use ndn_pipes::{Confidentiality, Pipe, PipeConsumer, PipeParams, PipeProducer};

#[tokio::test]
async fn pipe_key_authenticates_teardown() {
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

    let producer = PipeProducer::new(Producer::from_handle(producer_handle, root)).serve_object(
        &"/sensors/temp/v=42".parse().unwrap(),
        b"unused",
        &ndn_coding::FecPolicy::systematic(8, 12).unwrap(),
        1,
        &[],
        &Confidentiality::None,
    );
    let serve = tokio::spawn(async move { producer.serve().await });

    let mut pc = PipeConsumer::new(Consumer::from_handle(consumer_handle));
    let pipe = pc.open("/sensors/temp", PipeParams::default()).await.expect("pipe");
    assert!(pc.is_alive(&pipe).await, "pipe is live after the sealed handshake");

    // Forge a teardown that knows the pipe id (as a relay would from the JOIN)
    // but carries the wrong pipe key. The producer must refuse it.
    let forged = Pipe {
        teardown_secret: Bytes::from_static(&[0u8; 16]),
        ..pipe.clone()
    };
    assert!(pc.close(&forged).await.is_err(), "forged teardown is not acked");
    assert!(pc.is_alive(&pipe).await, "pipe survives a forged teardown");

    // The real pipe key reclaims it.
    pc.close(&pipe).await.expect("authentic teardown acked");
    assert!(!pc.is_alive(&pipe).await, "pipe is reclaimed by the authentic key");

    drop(pc);
    drop(engine);
    shutdown.shutdown().await;
    let _ = serve.await;
}
