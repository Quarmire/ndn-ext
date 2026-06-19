//! Slice-1 witness: the SEEK→JOIN→CHECK handshake establishes a pipe over an
//! embedded engine with two in-process faces — no radio hardware.
//!
//! ```text
//!   consumer (Face 1) --SEEK /NPD/SEEK/sensors/temp--> [engine] --FIB /--> producer (Face 2)
//!   producer mints pipe_id, returns it; consumer JOINs (+reflexive pipe_id), then CHECKs.
//! ```

use ndn_app::{Consumer, EngineBuilder, Producer};
use ndn_engine::EngineConfig;
use ndn_face::local::InProcFace;
use ndn_packet::Name;
use ndn_transport::FaceId;

use ndn_pipes::{PipeConsumer, PipeParams, PipeProducer};

#[tokio::test]
async fn seek_join_check_establishes_a_pipe() {
    let (consumer_face, consumer_handle) = InProcFace::new(FaceId(1), 64);
    let (producer_face, producer_handle) = InProcFace::new(FaceId(2), 64);

    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(consumer_face)
        .face(producer_face)
        .build()
        .await
        .expect("engine build");

    // The producer answers every NDN-Pipes control message; route all names to
    // it (SEEK/JOIN live under /NPD, CHECK under the dynamic /{pipe_id}).
    let root: Name = "/".parse().unwrap();
    engine.fib().add_nexthop(&root, FaceId(2), 0);

    let producer = PipeProducer::new(Producer::from_handle(producer_handle, root));
    let serve = tokio::spawn(async move { producer.serve().await });

    let mut pc = PipeConsumer::new(Consumer::from_handle(consumer_handle));
    let pipe = pc
        .open("/sensors/temp", PipeParams::default())
        .await
        .expect("pipe should establish via SEEK→JOIN→CHECK");

    assert_eq!(pipe.namespace.to_string(), "/sensors/temp");
    assert!(!pipe.id.as_bytes().is_empty(), "producer minted a pipe id");
    assert_eq!(pipe.pipe_len, 1);

    drop(pc);
    drop(engine);
    shutdown.shutdown().await;
    let _ = serve.await;
}
