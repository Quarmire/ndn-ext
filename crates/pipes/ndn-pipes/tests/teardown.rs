//! Slice-6 witness: teardown. A pipe is reclaimed two ways — an explicit
//! TEARDOWN from the consumer, and PUI inactivity (no CHECK keep-alive within
//! the Promised Use Interval). A live pipe answers CHECK with `OK`; a reclaimed
//! one goes silent, so the consumer's liveness probe times out to `false`.
//! CHECK doubles as the keep-alive, so steady use renews the promise.

use std::time::Duration;

use ndn_app::{Consumer, EngineBuilder, Producer};
use ndn_engine::EngineConfig;
use ndn_face::local::InProcFace;
use ndn_packet::Name;
use ndn_transport::FaceId;

use ndn_pipes::{Confidentiality, PipeConsumer, PipeParams, PipeProducer};

/// Stand up a single-engine consumer↔producer pipe; the producer's PUI is `pui`.
/// Returns the wired-up consumer + the open pipe, plus the teardown handles.
async fn open_pipe(
    pui: Duration,
) -> (
    PipeConsumer,
    ndn_pipes::Pipe,
    ndn_engine::ForwarderEngine,
    ndn_engine::ShutdownHandle,
    tokio::task::JoinHandle<Result<(), ndn_app::AppError>>,
) {
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
        .with_pui(pui)
        .serve_object(
            &"/sensors/temp/v=42".parse().unwrap(),
            b"unused-by-this-witness",
            &ndn_coding::FecPolicy::systematic(8, 12).unwrap(),
            1,
            &[],
            &Confidentiality::None,
        );
    let serve = tokio::spawn(async move { producer.serve().await });

    let mut pc = PipeConsumer::new(Consumer::from_handle(consumer_handle));
    let pipe = pc
        .open("/sensors/temp", PipeParams::default())
        .await
        .expect("pipe establishes");
    (pc, pipe, engine, shutdown, serve)
}

#[tokio::test]
async fn explicit_teardown_reclaims_the_pipe() {
    let (mut pc, pipe, engine, shutdown, serve) = open_pipe(Duration::from_secs(10)).await;

    assert!(pc.is_alive(&pipe).await, "pipe is live right after opening");
    pc.close(&pipe).await.expect("teardown acked");
    assert!(!pc.is_alive(&pipe).await, "torn-down pipe no longer answers CHECK");
    // Teardown is idempotent — a repeat is a harmless no-op (suppression floor).
    pc.close(&pipe).await.expect("repeat teardown still acks");

    drop(pc);
    drop(engine);
    shutdown.shutdown().await;
    let _ = serve.await;
}

#[tokio::test]
async fn pui_inactivity_tears_down_an_idle_pipe() {
    let (mut pc, pipe, engine, shutdown, serve) = open_pipe(Duration::from_millis(120)).await;

    assert!(pc.is_alive(&pipe).await, "pipe is live within the PUI");
    // Stay quiet past the Promised Use Interval; no CHECK keep-alive.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!pc.is_alive(&pipe).await, "idle pipe is reclaimed after the PUI lapses");

    drop(pc);
    drop(engine);
    shutdown.shutdown().await;
    let _ = serve.await;
}

#[tokio::test]
async fn check_keepalive_renews_the_pui() {
    let (mut pc, pipe, engine, shutdown, serve) = open_pipe(Duration::from_millis(200)).await;

    // Each CHECK renews the promise; total elapsed (>200ms) exceeds one PUI, yet
    // the pipe stays live because use keeps refreshing it.
    for _ in 0..3 {
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert!(pc.is_alive(&pipe).await, "steady CHECK use keeps the pipe live");
    }

    drop(pc);
    drop(engine);
    shutdown.shutdown().await;
    let _ = serve.await;
}
