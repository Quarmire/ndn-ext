//! G3 slice 1 — the relay pipe-key handoff. The PIPE exchange (thesis Table 8)
//! distributes the pipe key (the teardown credential) to on-path nodes: a node sends
//! a PIPE Interest carrying its session public key; the holder seals `pipe_key ‖ PUI`
//! to it. Here a third node recovers the *same* pipe key the consumer holds, and a
//! `PipeRelay` learns + holds it — the prerequisite for relay-side PUI teardown.

use std::time::Duration;

use ndn_app::{Consumer, EngineBuilder, Producer};
use ndn_engine::EngineConfig;
use ndn_face::local::InProcFace;
use ndn_packet::Name;
use ndn_transport::FaceId;

use ndn_pipes::{
    Confidentiality, PipeConsumer, PipeParams, PipeProducer, PipeRelay, fetch_pipe_key,
};

const PUI: Duration = Duration::from_secs(30);
const TIMEOUT: Duration = Duration::from_secs(4);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pipe_exchange_hands_the_key_to_on_path_nodes() {
    // Faces: consumer(1), producer(2), and two extra app faces (3,4) for an
    // independent PIPE fetch and the relay's upstream fetch. All /COMMON + / route
    // to the producer in this single-engine topology.
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

    // Producer serves a pipe; it mints + holds the pipe key.
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

    // Consumer opens the pipe; it holds the pipe key as `teardown_secret`.
    let mut pc = PipeConsumer::new(Consumer::from_handle(c_h));
    let pipe = pc.open("/sensors/temp", PipeParams::default()).await.expect("pipe opens");
    let pipe_id = pipe.id.as_bytes().to_vec();

    // (1) An independent on-path node fetches the pipe key via the PIPE exchange and
    // recovers the SAME key the consumer holds — without it ever crossing in clear.
    let mut fetcher = Consumer::from_handle(f_h);
    let (fetched_key, fetched_pui) = fetch_pipe_key(&mut fetcher, &pipe_id, 1, TIMEOUT)
        .await
        .expect("PIPE exchange returns the sealed key");
    assert_eq!(
        fetched_key.as_ref(),
        pipe.teardown_secret.as_ref(),
        "the fetched pipe key matches the consumer's teardown credential"
    );
    assert_eq!(fetched_pui, PUI, "PUI travels with the key");

    // (2) A PipeRelay learns + holds the key (membership), so it can authorize a
    // teardown of its own state later (slices 2–3). Its producer face (4) is unused
    // here; learn drives over the `fetcher` consumer.
    let relay = PipeRelay::new(Producer::from_handle(r_h, Name::from("/COMMON")));
    let learned = relay.learn_pipe_key(&mut fetcher, &pipe_id, 1, TIMEOUT).await;
    assert!(learned, "relay learns the pipe key via the PIPE exchange");
    let store = relay.store();
    assert_eq!(
        store.pipe_key(&pipe_id).as_deref(),
        Some(pipe.teardown_secret.as_ref()),
        "relay now holds the same pipe key"
    );
    // A wrong key is rejected while the entry is live…
    assert!(
        !store.teardown_authorized(&pipe_id, Some(b"wrong")),
        "a non-member key cannot tear down the relay's pipe state"
    );
    // …and the real pipe key authorizes + reaps it (membership).
    assert!(
        store.teardown_authorized(&pipe_id, Some(pipe.teardown_secret.as_ref())),
        "holding the pipe key authorizes teardown"
    );
    assert!(store.pipe_key(&pipe_id).is_none(), "an authorized teardown reaped the entry");

    drop(pc);
    drop(engine);
    shutdown.shutdown().await;
    let _ = serve.await;
}
