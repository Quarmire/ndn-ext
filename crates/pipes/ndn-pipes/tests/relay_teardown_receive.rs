//! G3 slice 3 — the relay's teardown-receive handler, end to end. An on-path relay
//! that holds a pipe key (slice 1) reaps its pipe state on a membership-authenticated
//! inbound TEARDOWN, and rejects one carrying the wrong key. This is the receive side
//! that gives a path-walk real per-hop state to clean (slice 4).

use std::time::Duration;

use ndn_app::{Consumer, EngineBuilder, Producer};
use ndn_engine::EngineConfig;
use ndn_face::local::InProcFace;
use ndn_packet::Name;
use ndn_packet::encode::InterestBuilder;
use ndn_transport::FaceId;

use ndn_pipes::{
    Confidentiality, PipeConsumer, PipeParams, PipeProducer, PipeRelay, teardown_name,
};

const TIMEOUT: Duration = Duration::from_secs(4);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relay_reaps_on_authenticated_teardown_rejects_wrong_key() {
    let (c_face, c_h) = InProcFace::new(FaceId(1), 256);
    let (p_face, p_h) = InProcFace::new(FaceId(2), 256);
    let (r_face, r_h) = InProcFace::new(FaceId(3), 256);
    let (t_face, t_h) = InProcFace::new(FaceId(4), 256);
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(c_face)
        .face(p_face)
        .face(r_face)
        .face(t_face)
        .build()
        .await
        .expect("engine build");
    let root: Name = "/".parse().unwrap();
    engine.fib().add_nexthop(&root, FaceId(2), 0); // SEEK/JOIN/PIPE → producer

    let producer = PipeProducer::new(Producer::from_handle(p_h, root))
        .serve_object(
            &"/sensors/temp/v=1".parse().unwrap(),
            b"x",
            &ndn_coding::FecPolicy::systematic(8, 12).unwrap(),
            1,
            &[],
            &Confidentiality::None,
        );
    let serve = tokio::spawn(async move { producer.serve().await });

    let ns: Name = "/sensors/temp".parse().unwrap();
    let mut pc = PipeConsumer::new(Consumer::from_handle(c_h));
    let pipe = pc.open(ns.clone(), PipeParams::default()).await.expect("pipe opens");
    let id = pipe.id.as_bytes().to_vec();

    // The relay learns the pipe key (PIPE → producer), then serves /COMMON.
    let relay = PipeRelay::new(Producer::from_handle(r_h, Name::from("/COMMON")));
    let store = relay.store();
    let mut tool = Consumer::from_handle(t_h);
    assert!(
        relay.learn_pipe_key(&mut tool, &ns, &id, 0, 1, TIMEOUT).await,
        "relay learns the key"
    );

    // Route this pipe's control band to the relay (more specific than root→producer),
    // then start serving so teardowns for it reach the relay.
    let pipe_common = Name::from("/COMMON").append(&id);
    engine.fib().add_nexthop(&pipe_common, FaceId(3), 0);
    let relay_serve = tokio::spawn(async move { relay.serve().await });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let teardown = |key: &[u8]| {
        InterestBuilder::new(teardown_name(&id))
            .app_parameters(key.to_vec())
            .lifetime(Duration::from_millis(250))
            .build()
    };

    // Wrong key ⇒ the relay drops it ⇒ the request times out, and the pipe stays held.
    assert!(
        tool.fetch_wire(teardown(b"wrong-key"), Duration::from_millis(300)).await.is_err(),
        "a non-member teardown is dropped (times out)"
    );
    assert!(store.pipe_key(&id).is_some(), "rejected teardown leaves the relay's state intact");

    // Correct pipe key ⇒ BYE ack ⇒ the relay reaped its pipe state.
    let bye = tool.fetch_wire(teardown(pipe.teardown_secret.as_ref()), TIMEOUT).await;
    assert!(bye.is_ok(), "a member teardown is acked");
    assert!(store.pipe_key(&id).is_none(), "the relay reaped its pipe state on teardown");

    relay_serve.abort();
    drop(pc);
    drop(engine);
    shutdown.shutdown().await;
    let _ = serve.await;
}
