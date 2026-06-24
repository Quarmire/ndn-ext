//! G3 slice 2 — the relay PUI-teardown monitor, end to end. A relay that holds a pipe
//! key (slice 1) but sees no namespace activity for longer than its per-hop threshold
//! announces a teardown, which reaps the pipe. To prove the *monitor* (not the
//! producer's own lazy PUI expiry) caused it, the consumer keeps CHECK-renewing the
//! producer throughout — so the pipe would stay live forever but for the relay's
//! announcement.

use std::time::Duration;

use ndn_app::{Consumer, EngineBuilder, Producer};
use ndn_engine::EngineConfig;
use ndn_face::local::InProcFace;
use ndn_packet::Name;
use ndn_transport::FaceId;

use ndn_pipes::{
    Confidentiality, PipeConsumer, PipeParams, PipeProducer, PipeRelay, run_relay_monitor,
};

const PUI: Duration = Duration::from_millis(120);
const TIMEOUT: Duration = Duration::from_secs(4);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relay_monitor_tears_down_an_idle_pipe_despite_active_checks() {
    let (c_face, c_h) = InProcFace::new(FaceId(1), 256);
    let (p_face, p_h) = InProcFace::new(FaceId(2), 256);
    let (f_face, f_h) = InProcFace::new(FaceId(3), 256);
    let (r_face, r_h) = InProcFace::new(FaceId(4), 256);
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(c_face)
        .face(p_face)
        .face(f_face)
        .face(r_face)
        .build()
        .await
        .expect("engine build");
    let root: Name = "/".parse().unwrap();
    engine.fib().add_nexthop(&root, FaceId(2), 0);

    let producer = PipeProducer::new(Producer::from_handle(p_h, root))
        .with_pui(PUI)
        .serve_object(
            &"/sensors/temp/v=1".parse().unwrap(),
            b"x",
            &ndn_coding::FecPolicy::systematic(8, 12).unwrap(),
            1,
            &[],
            &Confidentiality::None,
        );
    let serve = tokio::spawn(async move { producer.serve().await });

    let mut pc = PipeConsumer::new(Consumer::from_handle(c_h));
    let ns: Name = "/sensors/temp".parse().unwrap();
    let pipe = pc.open(ns.clone(), PipeParams::default()).await.expect("pipe opens");

    // A relay learns the pipe key at hop 0 (threshold == PUI), then runs its monitor
    // over the fetcher consumer. It never sees activity (note_activity is never called),
    // so it will announce teardown after the PUI.
    let relay = PipeRelay::new(Producer::from_handle(r_h, Name::from("/COMMON")));
    let mut fetcher = Consumer::from_handle(f_h);
    assert!(
        relay
            .learn_pipe_key(&mut fetcher, &ns, pipe.id.as_bytes(), 0, 1, TIMEOUT)
            .await,
        "relay learns the key"
    );
    let monitor = tokio::spawn(run_relay_monitor(
        relay.store(),
        fetcher,
        Duration::ZERO,        // quantum (hop 0 ⇒ threshold == PUI)
        Duration::from_millis(40), // poll cadence
    ));

    // Keep CHECK-renewing the producer the whole time: the pipe would never lazily
    // expire, so any teardown must come from the relay's monitor.
    let mut torn = false;
    for _ in 0..18 {
        if !pc.is_alive(&pipe).await {
            torn = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    assert!(
        torn,
        "the relay's inactivity monitor tore the pipe down despite active CHECK keep-alives"
    );

    monitor.abort();
    drop(pc);
    drop(engine);
    shutdown.shutdown().await;
    let _ = serve.await;
}
