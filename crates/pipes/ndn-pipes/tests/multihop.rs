//! Slice-4 witness: a pipe works **multi-hop** through a relay, and the relay —
//! a plain NDN forwarder with no content key — only ever carries ciphertext.
//!
//! ```text
//!  consumer-app─[consumer engine]══SimLink══[relay engine]══SimLink══[producer engine]─producer-app
//! ```
//! The SEEK→JOIN→CHECK handshake and the encrypt-then-code bulk traverse the
//! relay; it forwards the sealed coded segments it can neither read nor forge.

use ndn_app::{Consumer, EngineBuilder, Producer};
use ndn_coding::FecPolicy;
use ndn_engine::EngineConfig;
use ndn_face::local::InProcFace;
use ndn_packet::Name;
use ndn_sim::{LinkConfig, SimLink};
use ndn_transport::FaceId;

use ndn_pipes::{Confidentiality, PipeConsumer, PipeParams, PipeProducer};

/// Build a consumer—relay—producer topology, serve a sealed coded object (the
/// producer withholds `skip` segment indices), and fetch it from two hops away.
async fn run(skip: &'static [u16]) -> (Vec<u8>, Vec<u8>) {
    let payload: Vec<u8> = (0..3000u32).map(|i| (i % 251) as u8).collect();
    let policy = FecPolicy::systematic(8, 12).unwrap();
    let key = [7u8; 32];
    let object: Name = "/sensors/temp/v=42".parse().unwrap();
    let root: Name = "/".parse().unwrap();

    // Links: consumer↔relay (faces 10/11), relay↔producer (faces 12/13).
    let (cr_c, cr_r) = SimLink::pair(FaceId(10), FaceId(11), LinkConfig::default(), 256);
    let (rp_r, rp_p) = SimLink::pair(FaceId(12), FaceId(13), LinkConfig::default(), 256);
    let (consumer_app, consumer_handle) = InProcFace::new(FaceId(1), 256);
    let (producer_app, producer_handle) = InProcFace::new(FaceId(2), 256);

    // Three forwarders.
    let (ce, sc) = EngineBuilder::new(EngineConfig::default())
        .face(consumer_app)
        .face(cr_c)
        .build()
        .await
        .expect("consumer engine");
    let (re, sr) = EngineBuilder::new(EngineConfig::default())
        .face(cr_r)
        .face(rp_r)
        .build()
        .await
        .expect("relay engine");
    let (pe, sp) = EngineBuilder::new(EngineConfig::default())
        .face(producer_app)
        .face(rp_p)
        .build()
        .await
        .expect("producer engine");

    // FIB: every name flows toward the producer; Data returns along the PIT.
    ce.fib().add_nexthop(&root, FaceId(10), 0); // consumer → relay
    re.fib().add_nexthop(&root, FaceId(12), 0); // relay    → producer
    pe.fib().add_nexthop(&root, FaceId(2), 0); //  producer → its app

    // Producer: seal under the content key, then code (encrypt-then-code).
    let producer = PipeProducer::new(Producer::from_handle(producer_handle, root)).serve_object(
        &object,
        &payload,
        &policy,
        1,
        skip,
        &Confidentiality::Aead(key),
    );
    let serve = tokio::spawn(async move { producer.serve().await });

    // Consumer (two hops away): open the pipe and fetch the sealed coded object.
    let mut pc = PipeConsumer::new(Consumer::from_handle(consumer_handle));
    let pipe = pc
        .open("/sensors/temp", PipeParams::default().with_aead_key(key))
        .await
        .expect("pipe establishes across the relay");
    let got = pc
        .fetch(&pipe, "/v=42")
        .await
        .expect("coded confidential bulk arrives through the relay");

    drop(pc);
    drop(ce);
    drop(re);
    drop(pe);
    sc.shutdown().await;
    sr.shutdown().await;
    sp.shutdown().await;
    let _ = serve.await;
    (payload, got.to_vec())
}

#[tokio::test]
async fn pipe_works_multihop_through_a_relay() {
    let (payload, got) = run(&[]).await;
    assert_eq!(got, payload, "consumer recovers + decrypts the multi-hop bulk");
}

#[tokio::test]
async fn coded_bulk_recovers_through_a_relay_under_loss() {
    // The relay forwards sealed coded segments it can't read; 3 source segments
    // are dropped on the wire, yet K-of-N parity still recovers the plaintext.
    let (payload, got) = run(&[1, 4, 6]).await;
    assert_eq!(got, payload, "FEC recovers the sealed bulk despite multi-hop loss");
}
