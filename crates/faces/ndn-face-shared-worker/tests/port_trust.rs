//! A tab's port into the worker is not a trusted peer by default.
//!
//! A tab can bridge a remote peer (a page relaying WebRTC or WebTransport
//! bytes), so Data arriving on a port the default way is checked like Data from
//! any network face: a forgery is refused and never cached. Only an explicit
//! `accept_program` skips the check, which a worker none of whose tabs bridges
//! a remote peer may choose.
//!
//! The rig is a forwarder with no trust anchors (every signed Data from a
//! validated face is refused `untrusted-root`), a consumer app face and one
//! port face built from channels. The test plays the tab at the far end of the
//! channels: it answers the consumer's Interest with Data signed by a key nobody
//! certified, then asks again to see whether the forgery was cached.

use std::time::Duration;

use bytes::Bytes;
use ndn_engine::{EngineBuilder, EngineConfig};
use ndn_face_local::InProcFace;
use ndn_face_shared_worker::WorkerPortFace;
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_packet::lp::LpPacket;
use ndn_packet::{Data, Name, Refusal, SignatureType};
use ndn_security::{Ed25519Signer, SecurityProfile, Signer};
use ndn_transport::FaceId;
use tokio::sync::mpsc;

const CONSUMER: u64 = 1;
const PORT: u64 = 2;

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

fn payload_of(wire: &Bytes) -> Option<Bytes> {
    match LpPacket::decode(wire.clone()) {
        Ok(lp) => lp.fragment,
        Err(_) => Some(wire.clone()),
    }
}

fn is_interest(wire: &Bytes) -> bool {
    payload_of(wire).is_some_and(|p| p.first() == Some(&0x05))
}

fn is_data(wire: &Bytes) -> bool {
    match LpPacket::decode(wire.clone()) {
        Ok(lp) => lp.nack.is_none() && lp.fragment.is_some_and(|p| Data::decode(p).is_ok()),
        Err(_) => Data::decode(wire.clone()).is_ok(),
    }
}

fn refusal_of(wire: &Bytes) -> Option<Refusal> {
    LpPacket::decode(wire.clone()).ok()?.nack?.reason?.refusal()
}

/// `/t/doc` signed by a key no anchor covers.
fn forged_doc() -> Bytes {
    let signer = Ed25519Signer::from_seed(&[5; 32], n("/t/KEY/k"));
    DataBuilder::new(n("/t/doc"), b"forged").sign_sync(
        SignatureType::SignatureEd25519,
        Some(signer.key_name()),
        |region| signer.sign_sync(region).unwrap(),
    )
}

async fn recv_within(rx: &mut mpsc::Receiver<Bytes>, ms: u64) -> Option<Bytes> {
    tokio::time::timeout(Duration::from_millis(ms), rx.recv())
        .await
        .ok()
        .flatten()
}

/// A forged Data sent over a port face built the default way is refused (the
/// consumer is told why) and not cached: the second Interest reaches the tab
/// again. Fails if the default port face is a program face.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forged_data_on_a_default_port_face_is_refused_and_never_cached() {
    let (consumer_face, consumer) = InProcFace::new(FaceId(CONSUMER), 64);
    // `tx_out` carries the worker's packets to the tab; `tx_in` the tab's to the worker.
    let (tx_out, mut rx_out) = mpsc::channel::<Bytes>(64);
    let (tx_in, rx_in) = mpsc::channel::<Bytes>(64);
    let port = WorkerPortFace::from_channels(FaceId(PORT), tx_out, rx_in);

    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .security_profile(SecurityProfile::Default)
        .face(consumer_face)
        .face(port)
        .build()
        .await
        .expect("engine build");
    engine.fib().add_nexthop(&n("/t"), FaceId(PORT), 0);

    let ask = || {
        InterestBuilder::new(n("/t/doc"))
            .lifetime(Duration::from_secs(4))
            .build()
    };
    consumer.send(ask()).await.expect("send Interest");
    let at_tab = recv_within(&mut rx_out, 1000)
        .await
        .expect("the Interest reaches the tab");
    assert!(is_interest(&at_tab));
    tx_in
        .send(forged_doc())
        .await
        .expect("tab sends the forgery");

    let first = tokio::time::timeout(Duration::from_millis(800), consumer.recv())
        .await
        .ok()
        .flatten()
        .expect("the consumer hears back");
    assert!(
        !is_data(&first),
        "forged Data on a default port face was delivered to the consumer"
    );
    assert_eq!(refusal_of(&first), Some(Refusal::UntrustedRoot));

    consumer.send(ask()).await.expect("send second Interest");
    let asked_again = recv_within(&mut rx_out, 500)
        .await
        .is_some_and(|w| is_interest(&w));
    assert!(
        asked_again,
        "the second Interest was answered from the content store: the forgery was cached"
    );
    shutdown.shutdown().await;
}
