//! Hardware-integration witness: a full pipe runs over the **802.11 monitor-mode
//! named-radio bearer** instead of an in-process link. Two engines sit on a
//! shared `LoopbackMonitorBus` (the hardware-free stand-in for the air; the real
//! deployment swaps in `AfPacketBackend` over a monitor-mode interface), each
//! with a `MonitorWifiFace`. The SEEK→JOIN→CHECK handshake and the
//! encrypt-then-code bulk cross the air — fragmented by `LpLinkService` and
//! reassembled — proving the protocol works on the actual radio face.
//!
//! ```text
//!  consumer-app─[engine A]─[MonitorWifiFace]∿∿ air ∿∿[MonitorWifiFace]─[engine B]─producer-app
//! ```

use std::sync::Arc;

use ndn_app::{Consumer, EngineBuilder, Producer};
use ndn_coding::FecPolicy;
use ndn_engine::EngineConfig;
use ndn_face_monitor_wifi::{LoopbackMonitorBus, MonitorWifiFace};
use ndn_face::local::InProcFace;
use ndn_packet::Name;
use ndn_transport::FaceId;

use ndn_pipes::{Confidentiality, PipeConsumer, PipeParams, PipeProducer};

/// Run the pipe over two radios on a shared bus. When `name_group` is set, both
/// radios bind to that name-group (frames addressed to/from the name-derived
/// group MAC — the thesis's coupling/DCNLA). `skip` withholds producer segments
/// to model per-frame air loss; FEC recovers from any K.
async fn run(name_group: Option<&'static str>, skip: &'static [u16]) -> (Vec<u8>, Vec<u8>) {
    let payload: Vec<u8> = (0..2000u32).map(|i| (i % 251) as u8).collect();
    let policy = FecPolicy::systematic(8, 12).unwrap();
    let key = [7u8; 32];
    let object: Name = "/sensors/temp/v=42".parse().unwrap();
    let root: Name = "/".parse().unwrap();

    // The shared medium and two radios on it (strong RSSI = high MCS).
    let bus = LoopbackMonitorBus::new();
    let mk = |id: u64, fid: FaceId| {
        let f = MonitorWifiFace::new(fid, Arc::new(bus.endpoint(id, -55)));
        match name_group {
            Some(g) => f.with_name_group(g),
            None => f,
        }
        .into_face()
    };
    let radio_a = mk(1, FaceId(10));
    let radio_b = mk(2, FaceId(11));

    let (consumer_app, consumer_handle) = InProcFace::new(FaceId(1), 256);
    let (producer_app, producer_handle) = InProcFace::new(FaceId(2), 256);

    // Consumer node: app + radio. Producer node: app + radio.
    let (ce, sc) = EngineBuilder::new(EngineConfig::default())
        .face(consumer_app)
        .face_composed(radio_a)
        .build()
        .await
        .expect("consumer engine");
    let (pe, sp) = EngineBuilder::new(EngineConfig::default())
        .face(producer_app)
        .face_composed(radio_b)
        .build()
        .await
        .expect("producer engine");

    // Consumer routes everything onto the air; producer hands it to its app.
    ce.fib().add_nexthop(&root, FaceId(10), 0);
    pe.fib().add_nexthop(&root, FaceId(2), 0);

    let producer = PipeProducer::new(Producer::from_handle(producer_handle, root)).serve_object(
        &object,
        &payload,
        &policy,
        1,
        skip,
        &Confidentiality::Aead(key),
    );
    let serve = tokio::spawn(async move { producer.serve().await });

    let mut pc = PipeConsumer::new(Consumer::from_handle(consumer_handle));
    let pipe = pc
        .open("/sensors/temp", PipeParams::default().with_aead_key(key))
        .await
        .expect("pipe establishes over the radio");
    let got = pc
        .fetch(&pipe, "/v=42")
        .await
        .expect("coded confidential bulk arrives over the radio");

    drop(pc);
    drop(ce);
    drop(pe);
    sc.shutdown().await;
    sp.shutdown().await;
    let _ = serve.await;
    (payload, got.to_vec())
}

#[tokio::test]
async fn pipe_handshake_and_coded_bulk_over_the_radio() {
    let (payload, got) = run(None, &[]).await;
    assert_eq!(got, payload, "consumer recovers + decrypts the bulk over the air");
}

#[tokio::test]
async fn name_grouped_pipe_recovers_under_air_loss() {
    // Both radios bound to one name-group (the coupling); 3 of 12 segments are
    // dropped "on the air", yet K-of-N parity still recovers the sealed bulk.
    let (payload, got) = run(Some("/sensors/temp"), &[1, 4, 6]).await;
    assert_eq!(got, payload, "FEC recovers the sealed bulk over a name-grouped radio");
}
