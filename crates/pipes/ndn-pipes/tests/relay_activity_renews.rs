//! G3 slice-2 caveat closed — the relay PUI monitor is now fed by *real* data-plane
//! traffic. With a `RelayActivity` observer registered on the engine, an actively-fetched
//! pipe is renewed (its namespace keeps showing traffic) and survives the monitor; once
//! the fetching stops and the namespace goes quiet past the PUI, the monitor's PathControl
//! teardown reaps it. This is the inverse of `relay_teardown_monitor` (which proves the
//! teardown fires when there is *no* activity).
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
    RelayActivity, run_relay_monitor,
};

const PUI: Duration = Duration::from_millis(150);
const TIMEOUT: Duration = Duration::from_secs(4);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn active_fetch_renews_a_pipe_then_idle_tears_it_down() {
    let (c_face, c_h) = InProcFace::new(FaceId(1), 256);
    let (p_face, p_h) = InProcFace::new(FaceId(2), 256);
    let (f_face, f_h) = InProcFace::new(FaceId(3), 256);
    let (r_face, r_h) = InProcFace::new(FaceId(4), 256);

    let root: Name = "/".parse().unwrap();
    let producer = PipeProducer::new(Producer::from_handle(p_h, root.clone()))
        .with_pui(PUI)
        .serve_object(
            &"/sensors/temp/v=1".parse().unwrap(),
            b"the-bulk-payload",
            &ndn_coding::FecPolicy::systematic(8, 12).unwrap(),
            1,
            &[],
            &Confidentiality::None,
        );
    let relay = PipeRelay::new(Producer::from_handle(r_h, Name::from("/COMMON")));
    let store = relay.store();

    // The relay's teardown adapter (reaps on a membership teardown) + its data-plane
    // activity observer (renews on traffic under a held pipe's namespace).
    let teardown = Arc::new(PipeTeardownControl::new(store.clone()));
    let activity = Arc::new(RelayActivity::new(store.clone()));

    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(c_face)
        .face(p_face)
        .face(f_face)
        .face(r_face)
        .path_authorizer(teardown.clone())
        .path_control_observer(teardown.clone())
        .with_name_activity_observer(activity.clone())
        .build()
        .await
        .expect("engine build");
    engine.fib().add_nexthop(&root, FaceId(2), 0);

    let serve = tokio::spawn(async move { producer.serve().await });

    let mut pc = PipeConsumer::new(Consumer::from_handle(c_h));
    let ns: Name = "/sensors/temp".parse().unwrap();
    let pipe = pc
        .open(ns.clone(), PipeParams::default().with_fec(8, 12))
        .await
        .expect("pipe opens");

    let mut fetcher = Consumer::from_handle(f_h);
    assert!(
        relay
            .learn_pipe_key(&mut fetcher, &ns, pipe.id.as_bytes(), 0, 1, TIMEOUT)
            .await,
        "relay learns the key"
    );
    assert!(
        store.pipe_key(pipe.id.as_bytes()).is_some(),
        "relay holds the pipe"
    );

    let monitor = tokio::spawn(run_relay_monitor(
        store.clone(),
        fetcher,
        Duration::ZERO,            // quantum (hop 0 ⇒ threshold == PUI)
        Duration::from_millis(40), // poll cadence
    ));

    // Active phase: keep fetching the object (bulk traffic under the namespace) for well
    // past the PUI. Each fetch's interests cross the engine → RelayActivity renews the
    // pipe, so the monitor never finds it idle.
    for _ in 0..6 {
        let got = pc.fetch(&pipe, "/v=1").await.expect("object fetches");
        assert_eq!(got.as_ref(), b"the-bulk-payload");
        tokio::time::sleep(Duration::from_millis(60)).await;
    }
    assert!(
        store.pipe_key(pipe.id.as_bytes()).is_some(),
        "an actively-fetched pipe is NOT torn down (data-plane traffic renewed it)"
    );

    // Idle phase: stop fetching. With the namespace quiet past the PUI, the monitor's
    // PathControl teardown walks through and the hook reaps the relay's state.
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(2) && store.pipe_key(pipe.id.as_bytes()).is_some() {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        store.pipe_key(pipe.id.as_bytes()).is_none(),
        "once idle past the PUI, the monitor tears the pipe down"
    );

    monitor.abort();
    drop(pc);
    drop(engine);
    shutdown.shutdown().await;
    let _ = serve.await;
}
