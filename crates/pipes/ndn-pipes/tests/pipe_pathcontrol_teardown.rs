//! G3 slice 4 — pipe teardown over the generic **PathControl** path-walk.
//!
//! The receive side from slice 3, now driven by the forwarder's PathControl hook
//! instead of a bespoke `/COMMON/{id}/TEARDOWN` serve arm. A relay holds a pipe key
//! (slice 1); registering [`PipeTeardownControl`] on its engine as both the
//! `PathAuthorizer` and the `PathControlObserver` means a PathControl `Teardown` walking
//! the pipe's path is authorized by membership (the pipe key in app-params) and reaps
//! the relay's per-hop state — the forwarder, not the app, does the cleanup. A teardown
//! carrying the wrong key never gets past the authorizer.
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
    pipe_teardown_interest,
};

const TIMEOUT: Duration = Duration::from_secs(4);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pathcontrol_teardown_reaps_relay_state_membership_authed() {
    let (c_face, c_h) = InProcFace::new(FaceId(1), 256);
    let (p_face, p_h) = InProcFace::new(FaceId(2), 256);
    let (r_face, r_h) = InProcFace::new(FaceId(3), 256);
    let (t_face, t_h) = InProcFace::new(FaceId(4), 256);

    // The relay (holds the per-hop pipe state). Its store backs the PathControl adapter
    // we register on the engine as the teardown authorizer + observer.
    let relay = PipeRelay::new(Producer::from_handle(r_h, Name::from("/COMMON")));
    let store = relay.store();
    let adapter = Arc::new(PipeTeardownControl::new(store.clone()));

    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(c_face)
        .face(p_face)
        .face(r_face)
        .face(t_face)
        .path_authorizer(adapter.clone())
        .path_control_observer(adapter.clone())
        .build()
        .await
        .expect("engine build");
    let root: Name = "/".parse().unwrap();
    engine.fib().add_nexthop(&root, FaceId(2), 0); // SEEK/JOIN/PIPE → producer

    let producer = PipeProducer::new(Producer::from_handle(p_h, root)).serve_object(
        &"/sensors/temp/v=1".parse().unwrap(),
        b"x",
        &ndn_coding::FecPolicy::systematic(8, 12).unwrap(),
        1,
        &[],
        &Confidentiality::None,
    );
    let serve = tokio::spawn(async move { producer.serve().await });

    // Consumer opens the pipe (yields the pipe id + pipe key); the relay learns the same
    // pipe key from the producer via the PIPE exchange (slice 1).
    let ns: Name = "/sensors/temp".parse().unwrap();
    let mut pc = PipeConsumer::new(Consumer::from_handle(c_h));
    let pipe = pc
        .open(ns.clone(), PipeParams::default())
        .await
        .expect("pipe opens");
    let id = pipe.id.as_bytes().to_vec();

    let mut tool = Consumer::from_handle(t_h);
    assert!(
        relay
            .learn_pipe_key(&mut tool, &ns, &id, 0, 1, TIMEOUT)
            .await,
        "relay learns the pipe key"
    );
    assert!(store.pipe_key(&id).is_some(), "relay holds the pipe");

    // A PathControl Teardown with the WRONG key never clears the authorizer ⇒ dropped by
    // the forwarder; the relay's state survives. (No Data comes back — the fetch times
    // out, which is expected for a one-way control walk.)
    let wrong = pipe_teardown_interest(&ns, &id, b"not-the-pipe-key", 1);
    let _ = tool.fetch_wire(wrong, Duration::from_millis(300)).await;
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert!(
        store.pipe_key(&id).is_some(),
        "a non-member PathControl teardown leaves the relay's state intact"
    );

    // The correct pipe key ⇒ membership ⇒ the hook reaps the relay's per-hop state as the
    // Teardown walks through, with no pipe-aware serve loop involved.
    let right = pipe_teardown_interest(&ns, &id, pipe.teardown_secret.as_ref(), 2);
    let _ = tool.fetch_wire(right, Duration::from_millis(300)).await;
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(2) && store.pipe_key(&id).is_some() {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        store.pipe_key(&id).is_none(),
        "a membership PathControl teardown reaps the relay's state via the forwarder hook"
    );

    drop(pc);
    drop(engine);
    shutdown.shutdown().await;
    let _ = serve.await;
}
