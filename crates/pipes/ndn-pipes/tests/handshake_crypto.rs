//! Slice-7 witness: the handshake crypto. The producer seals a random pipe id +
//! pipe key to the consumer's X25519 public key (carried in the SEEK app-params),
//! so only the consumer can JOIN. The pipe key never appears in a name, so a
//! party that learns the pipe id from the JOIN cannot forge a teardown: the
//! forwarder's membership authorizer rejects a PathControl teardown bearing the wrong
//! key (no reap), and reclaims only on the real one.
//!
//! (The seal/open confidentiality property — wrong key cannot recover the id —
//! is unit-tested in `crypto.rs`; here we prove it end to end through teardown.)
//!
//! Built with the `engine` feature (the membership check lives in the forwarder hook).
#![cfg(feature = "engine")]

use std::sync::Arc;

use bytes::Bytes;
use ndn_app::{Consumer, EngineBuilder, Producer};
use ndn_engine::EngineConfig;
use ndn_face::local::InProcFace;
use ndn_packet::Name;
use ndn_transport::FaceId;

use ndn_pipes::{Confidentiality, Pipe, PipeConsumer, PipeParams, PipeProducer, PipeTeardownControl};

#[tokio::test]
async fn pipe_key_authenticates_teardown() {
    let (consumer_face, consumer_handle) = InProcFace::new(FaceId(1), 256);
    let (producer_face, producer_handle) = InProcFace::new(FaceId(2), 256);
    let root: Name = "/".parse().unwrap();

    let producer = PipeProducer::new(Producer::from_handle(producer_handle, root.clone()))
        .serve_object(
            &"/sensors/temp/v=42".parse().unwrap(),
            b"unused",
            &ndn_coding::FecPolicy::systematic(8, 12).unwrap(),
            1,
            &[],
            &Confidentiality::None,
        );
    // The forwarder reaps a teardown only if it carries the held pipe key (membership).
    let adapter = Arc::new(PipeTeardownControl::new(producer.registry()));
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(consumer_face)
        .face(producer_face)
        .path_authorizer(adapter.clone())
        .path_control_observer(adapter.clone())
        .build()
        .await
        .expect("engine build");
    engine.fib().add_nexthop(&root, FaceId(2), 0);

    let serve = tokio::spawn(async move { producer.serve().await });

    let mut pc = PipeConsumer::new(Consumer::from_handle(consumer_handle));
    let pipe = pc.open("/sensors/temp", PipeParams::default()).await.expect("pipe");
    assert!(pc.is_alive(&pipe).await, "pipe is live after the sealed handshake");

    // Forge a teardown that knows the pipe id (as a relay would from the JOIN) but
    // carries the wrong pipe key. The forwarder's authorizer rejects it — no reap — so
    // the pipe survives. (The walk is fire-and-forget; the rejection is observable only
    // through the pipe staying alive.)
    let forged = Pipe {
        teardown_secret: Bytes::from_static(&[0u8; 16]),
        ..pipe.clone()
    };
    pc.close(&forged).await.expect("forged teardown emitted");
    assert!(pc.is_alive(&pipe).await, "pipe survives a forged teardown — wrong key, no reap");

    // The real pipe key reclaims it.
    pc.close(&pipe).await.expect("authentic teardown emitted");
    assert!(!pc.is_alive(&pipe).await, "pipe is reclaimed by the authentic key");

    drop(pc);
    drop(engine);
    shutdown.shutdown().await;
    let _ = serve.await;
}
