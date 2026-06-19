//! Slice-5 witness: GHL hop accounting. Across a consumer—relay—producer path,
//! every node derives its hop index from `GHL − remaining HopLimit` with no
//! coordination (thesis Fig. 12):
//!
//!   - the **producer** reports the pipe length it observed in the SEEK reply,
//!     so the consumer learns the true multi-hop length (not an assumed 1);
//!   - the **relay** answers CONTEXT on the COMMON band with the hop index it
//!     derived *for itself* — strictly between consumer and producer;
//!   - the data plane still flows through the relay (which now serves COMMON).

use ndn_app::{Consumer, EngineBuilder, Producer};
use ndn_coding::FecPolicy;
use ndn_engine::EngineConfig;
use ndn_face::local::InProcFace;
use ndn_packet::Name;
use ndn_sim::{LinkConfig, SimLink};
use ndn_transport::FaceId;

use ndn_pipes::{Confidentiality, PipeConsumer, PipeParams, PipeProducer, PipeRelay};

#[tokio::test]
async fn ghl_gives_each_node_its_hop_index() {
    let payload: Vec<u8> = (0..2000u32).map(|i| (i % 251) as u8).collect();
    let policy = FecPolicy::systematic(8, 12).unwrap();
    let object: Name = "/sensors/temp/v=42".parse().unwrap();
    let root: Name = "/".parse().unwrap();
    let common: Name = "/COMMON".parse().unwrap();

    // Links: consumer↔relay (faces 10/11), relay↔producer (faces 12/13).
    let (cr_c, cr_r) = SimLink::pair(FaceId(10), FaceId(11), LinkConfig::default(), 256);
    let (rp_r, rp_p) = SimLink::pair(FaceId(12), FaceId(13), LinkConfig::default(), 256);
    let (consumer_app, consumer_handle) = InProcFace::new(FaceId(1), 256);
    let (producer_app, producer_handle) = InProcFace::new(FaceId(2), 256);
    let (relay_app, relay_handle) = InProcFace::new(FaceId(3), 256);

    let (ce, sc) = EngineBuilder::new(EngineConfig::default())
        .face(consumer_app)
        .face(cr_c)
        .build()
        .await
        .expect("consumer engine");
    let (re, sr) = EngineBuilder::new(EngineConfig::default())
        .face(cr_r)
        .face(rp_r)
        .face(relay_app)
        .build()
        .await
        .expect("relay engine");
    let (pe, sp) = EngineBuilder::new(EngineConfig::default())
        .face(producer_app)
        .face(rp_p)
        .build()
        .await
        .expect("producer engine");

    // FIB: the relay keeps the COMMON control band local (its own app) and
    // forwards everything else — SEEK/JOIN/CHECK and the bulk — to the producer.
    ce.fib().add_nexthop(&root, FaceId(10), 0); // consumer → relay
    re.fib().add_nexthop(&common, FaceId(3), 0); // relay control → relay app
    re.fib().add_nexthop(&root, FaceId(12), 0); // everything else → producer
    pe.fib().add_nexthop(&root, FaceId(2), 0); //  producer → its app

    let producer = PipeProducer::new(Producer::from_handle(producer_handle, root)).serve_object(
        &object,
        &payload,
        &policy,
        1,
        &[],
        &Confidentiality::None,
    );
    let serve_p = tokio::spawn(async move { producer.serve().await });
    let relay = PipeRelay::new(Producer::from_handle(relay_handle, common));
    let serve_r = tokio::spawn(async move { relay.serve().await });

    let mut pc = PipeConsumer::new(Consumer::from_handle(consumer_handle));
    let pipe = pc
        .open("/sensors/temp", PipeParams::default().with_fec(8, 12))
        .await
        .expect("pipe establishes across the relay");

    // The producer derived the pipe length from GHL: consumer-engine, relay-
    // engine and producer-engine each decremented once → 3 hops to the producer.
    assert_eq!(pipe.pipe_len, 3, "producer reports the GHL-derived pipe length");

    // The relay answers CONTEXT with the hop it derived for itself: two decrements
    // (consumer + relay engines) lie between the consumer and the relay app.
    let relay_hop = pc.context(&pipe, 1).await.expect("relay answers CONTEXT");
    assert_eq!(relay_hop, 2, "relay derives its own hop index from GHL");
    assert!(
        (relay_hop as u32) < pipe.pipe_len,
        "hop indices are monotonic along the path: consumer < relay < producer"
    );

    // Data plane still flows through the relay while it serves the control band.
    let got = pc.fetch(&pipe, "/v=42").await.expect("bulk arrives through the relay");
    assert_eq!(got, payload, "coded bulk recovered while the relay handles COMMON");

    drop(pc);
    drop(ce);
    drop(re);
    drop(pe);
    sc.shutdown().await;
    sr.shutdown().await;
    sp.shutdown().await;
    let _ = serve_p.await;
    let _ = serve_r.await;
}
