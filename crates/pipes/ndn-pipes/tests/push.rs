//! Push witness: the producer **pushes** the coded bulk to the consumer over the
//! reflexive reverse route (server-initiated delivery), making the route the
//! JOIN installs load-bearing. After SEEK, the consumer JOINs carrying the
//! reflexive name and serves the producer's reverse pushes — each a reverse
//! Interest carrying one coded segment — absorbing them until K-of-N recovers
//! the sealed bulk, which it then decrypts.
//!
//! Three in-process faces (like the reflexive end-to-end test): the consumer,
//! the producer's serve face, and the producer's side face for the reverse
//! pushes. FIB routes `/NPD` (SEEK/JOIN) to the producer; the reflexive route
//! carries `/rfx/<pipe_id>/push/<i>` back to the consumer.

use ndn_app::{Consumer, EngineBuilder, Producer};
use ndn_coding::FecPolicy;
use ndn_engine::EngineConfig;
use ndn_face::local::InProcFace;
use ndn_packet::Name;
use ndn_transport::FaceId;

use ndn_pipes::{Confidentiality, PipeConsumer, PipeParams, PipeProducer};

#[tokio::test]
async fn producer_pushes_coded_bulk_over_the_reflexive_route() {
    let payload: Vec<u8> = (0..2000u32).map(|i| (i % 251) as u8).collect();
    let policy = FecPolicy::systematic(8, 12).unwrap();
    let key = [7u8; 32];

    let (consumer_face, consumer_handle) = InProcFace::new(FaceId(1), 256);
    let (serve_face, serve_handle) = InProcFace::new(FaceId(2), 256);
    let (side_face, side_handle) = InProcFace::new(FaceId(3), 256);
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(consumer_face)
        .face(serve_face)
        .face(side_face)
        .build()
        .await
        .expect("engine build");
    assert!(engine.reflexive().is_enabled(), "reflexive forwarding must be on");

    // SEEK/JOIN flow toward the producer; the reverse pushes route reflexively.
    let npd: Name = "/NPD".parse().unwrap();
    engine.fib().add_nexthop(&npd, FaceId(2), 0);

    // Producer seals + codes the payload to push, and serves with a side face.
    let producer = PipeProducer::new(Producer::from_handle(serve_handle, "/".parse().unwrap()))
        .push_object(&payload, &policy, 1, &Confidentiality::Aead(key));
    let side = Consumer::from_handle(side_handle);
    let serve = tokio::spawn(async move { producer.serve_pushing(side).await });

    // Consumer receives the pushed, sealed, coded bulk and decrypts it.
    let mut pc = PipeConsumer::new(Consumer::from_handle(consumer_handle));
    let got = pc
        .receive("/sensors/temp", PipeParams::default().with_aead_key(key))
        .await
        .expect("pushed bulk received");

    assert_eq!(got, payload, "consumer recovers + decrypts the producer-pushed bulk");

    drop(pc);
    drop(engine);
    shutdown.shutdown().await;
    let _ = serve.await;
}
