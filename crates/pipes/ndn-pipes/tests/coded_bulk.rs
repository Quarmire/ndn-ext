//! Slice-2 witness: coded bulk transfer over a pipe — K-of-N FEC recovers the
//! object losslessly *and* with segments withheld (simulated wire loss), over
//! an embedded engine with two in-process faces.

use ndn_app::{Consumer, EngineBuilder, Producer};
use ndn_coding::FecPolicy;
use ndn_engine::EngineConfig;
use ndn_face::local::InProcFace;
use ndn_packet::Name;
use ndn_transport::FaceId;

use ndn_pipes::{Confidentiality, PipeConsumer, PipeParams, PipeProducer};

async fn run(skip: &'static [u16]) -> (Vec<u8>, Vec<u8>) {
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

    let producer = PipeProducer::new(Producer::from_handle(producer_handle, root))
        .serve_object(&object, &payload, &policy, 1, skip, &Confidentiality::None);
    let serve = tokio::spawn(async move { producer.serve().await });

    let mut pc = PipeConsumer::new(Consumer::from_handle(consumer_handle));
    let pipe = pc
        .open("/sensors/temp", PipeParams::default().with_fec(8, 12))
        .await
        .expect("pipe establishes");
    let got = pc.fetch(&pipe, "/v=42").await.expect("coded fetch recovers");

    drop(pc);
    drop(engine);
    shutdown.shutdown().await;
    let _ = serve.await;
    (payload, got.to_vec())
}

#[tokio::test]
async fn coded_bulk_round_trips_without_loss() {
    let (payload, got) = run(&[]).await;
    assert_eq!(got, payload, "all segments present → exact recovery");
}

#[tokio::test]
async fn coded_bulk_recovers_under_loss() {
    // Withhold 3 of 12 source segments; 9 ≥ K=8 remain → recover via parity.
    let (payload, got) = run(&[1, 4, 6]).await;
    assert_eq!(got, payload, "K-of-N FEC recovers despite withheld segments");
}
