//! G3 slices 2+4 — the relay PUI-teardown monitor, end to end, over PathControl. A
//! relay that holds a pipe key (slice 1) but sees no namespace activity for longer than
//! its per-hop threshold announces a PathControl `Teardown`; the single path-walk reaps
//! the producer's pipe state *and* the relay's own per-hop state (the emitter's engine
//! hook). To prove the *monitor* (not the producer's own lazy PUI expiry) caused it, the
//! consumer keeps CHECK-renewing the producer throughout — so the pipe would stay live
//! forever but for the relay's announcement.
#![cfg(feature = "engine")]

use std::sync::Arc;
use std::time::Duration;

use ndn_app::{Consumer, EngineBuilder, Producer};
use ndn_engine::EngineConfig;
use ndn_face::local::InProcFace;
use ndn_packet::Name;
use ndn_transport::FaceId;

use ndn_pipes::{
    Confidentiality, PipeConsumer, PipeParams, PipeProducer, PipeRelay, PipeTeardownControl,
    run_relay_monitor,
};

const PUI: Duration = Duration::from_millis(120);
const TIMEOUT: Duration = Duration::from_secs(4);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relay_monitor_pathcontrol_teardown_reaps_producer_and_relay() {
    let (c_face, c_h) = InProcFace::new(FaceId(1), 256);
    let (p_face, p_h) = InProcFace::new(FaceId(2), 256);
    let (f_face, f_h) = InProcFace::new(FaceId(3), 256);
    let (r_face, r_h) = InProcFace::new(FaceId(4), 256);

    // Build producer + relay first so their teardown adapters can be registered on the
    // engine before they serve. The producer adapter authorizes (it holds the pipe key)
    // and reaps the producer's registry; the relay adapter reaps the relay's store. The
    // monitor's PathControl teardown walks through both in one sweep.
    let root: Name = "/".parse().unwrap();
    let producer = PipeProducer::new(Producer::from_handle(p_h, root.clone()))
        .with_pui(PUI)
        .serve_object(
            &"/sensors/temp/v=1".parse().unwrap(),
            b"x",
            &ndn_coding::FecPolicy::systematic(8, 12).unwrap(),
            1,
            &[],
            &Confidentiality::None,
        );
    let registry = producer.registry();
    let relay = PipeRelay::new(Producer::from_handle(r_h, Name::from("/COMMON")));
    let store = relay.store();

    let prod_adapter = Arc::new(PipeTeardownControl::new(registry));
    let relay_adapter = Arc::new(PipeTeardownControl::new(store.clone()));

    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(c_face)
        .face(p_face)
        .face(f_face)
        .face(r_face)
        .path_authorizer(prod_adapter.clone())
        .path_control_observer(prod_adapter.clone())
        .path_control_observer(relay_adapter.clone())
        .build()
        .await
        .expect("engine build");
    engine.fib().add_nexthop(&root, FaceId(2), 0);

    let serve = tokio::spawn(async move { producer.serve().await });

    let mut pc = PipeConsumer::new(Consumer::from_handle(c_h));
    let ns: Name = "/sensors/temp".parse().unwrap();
    let pipe = pc.open(ns.clone(), PipeParams::default()).await.expect("pipe opens");

    // The relay learns the pipe key at hop 0 (threshold == PUI), then runs its monitor.
    // It never sees activity (note_activity is never called), so it announces a
    // PathControl teardown after the PUI.
    let mut fetcher = Consumer::from_handle(f_h);
    assert!(
        relay
            .learn_pipe_key(&mut fetcher, &ns, pipe.id.as_bytes(), 0, 1, TIMEOUT)
            .await,
        "relay learns the key"
    );
    assert!(store.pipe_key(pipe.id.as_bytes()).is_some(), "relay holds the pipe");
    let monitor = tokio::spawn(run_relay_monitor(
        relay.store(),
        fetcher,
        Duration::ZERO,            // quantum (hop 0 ⇒ threshold == PUI)
        Duration::from_millis(40), // poll cadence
    ));

    // Keep CHECK-renewing the producer the whole time: the pipe would never lazily
    // expire, so any teardown must come from the relay monitor's PathControl walk.
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
        "the relay monitor's PathControl teardown reaped the producer despite active CHECKs"
    );
    // The same walk reaped the relay's own per-hop state (its engine's hook saw the
    // teardown the monitor emitted into it).
    assert!(
        store.pipe_key(pipe.id.as_bytes()).is_none(),
        "the relay's own pipe state was reaped by the same walk"
    );

    monitor.abort();
    drop(pc);
    drop(engine);
    shutdown.shutdown().await;
    let _ = serve.await;
}
