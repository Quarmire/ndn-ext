//! A `Reliable` flood over one QUIC link into a consumer that is not reading (the shape of
//! ndf's `N2R` row: a data-layer node attached to its forwarder through the app face, the link
//! a face of that forwarder, a receiver on a forwarder of its own).
//!
//! What it asserts is the receiving side of the link (docs/specs/channel.md §14.4, §14.10). The
//! receiver's node reads its frames in one task that waits for room in a blocked `Items`, so the
//! app face's side inbox fills behind it. A stream frame the forwarder's link reader found no room
//! for used to be dropped there and counted `sink_full`, while the sender had been told `Ok`: a
//! gap in a `Reliable` channel the sender's own forwarder caused. Now the link's stream lane waits
//! with the frame in hand and stops taking the stream, so back pressure reaches the sender
//! through QUIC flow control; and since the lane is a task of its own, the NDN packets of the same
//! link are never held back by it.
//!
//! So: with the consumer not reading and the lane held, NDN Interests across the link are still
//! answered; then every message arrives, in order, and no forwarder counted a `sink_full`.

use std::time::Duration;

use bytes::Bytes;
use ndn_app::EngineAppExt;
use ndn_engine::side::SideId;
use ndn_heap::{ChannelMode, EmitOptions, GetNotice, GetOptions, Items, Name, Select};
use tokio_util::sync::CancellationToken;

#[allow(dead_code)]
#[path = "../examples/common/pair.rs"]
mod pair;
#[allow(dead_code)]
#[path = "../examples/common/relay.rs"]
mod relay;

use relay::{Build, Mesh, Party, Runtimes, name};

/// Messages emitted, and their size: far more than the receiver can buffer anywhere (its
/// `Items` queue 1 MiB, the app face's side inbox 8 MiB, the link's inbox 4 MiB and the
/// stream's flow-control window), so the sender is held back and every buffer is full.
const MESSAGES: u64 = 60_000;
const SIZE: usize = 1_024;

fn live(party: &Party) -> Items {
    party
        .heap
        .get(
            Select::Prefix(Name::root()),
            GetOptions {
                kept: false,
                ..GetOptions::default()
            },
        )
        .expect("a member of the space")
}

async fn eventually(what: &str, mut done: impl FnMut() -> bool) {
    let start = std::time::Instant::now();
    while !done() {
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "gave up waiting for: {what}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reliable_flood_into_a_consumer_that_is_not_reading_is_held_back_never_lost() {
    let mesh = Mesh::new(&Runtimes::current(), 1, false, Build::default()).await;
    let receiver = &mesh.receivers[0];
    let mut items = live(receiver);
    let here = tokio::runtime::Handle::current();
    let info = Mesh::ask_in(
        &here,
        &receiver.node,
        &mesh.sender.node,
        ChannelMode::Reliable,
    )
    .await;
    eventually("HELLO", || items.hello_seen()).await;
    eventually("the route stands at the sender's forwarder", || {
        mesh.sender.site.engine.side().sinks(SideId(info.channel)) == 1
    })
    .await;

    // NDN across the same link: a producer at the sender's forwarder, a route at the receiver's.
    let cancel = CancellationToken::new();
    let producer = mesh
        .sender
        .site
        .engine
        .register_producer(name("/probe"), cancel.child_token());
    let served = tokio::spawn(async move {
        let _ = producer
            .serve(|interest, responder| async move {
                let _ = responder.respond((*interest.name).clone(), "ok").await;
            })
            .await;
    });
    receiver
        .site
        .engine
        .fib()
        .add_nexthop(&name("/probe"), mesh.joined()[0].a_face, 1);
    let mut consumer = receiver.site.engine.app_consumer(cancel.child_token());

    let path = name("/bench/flood");
    let emit = async {
        for i in 0..MESSAGES {
            let mut message = vec![0u8; SIZE];
            message[..8].copy_from_slice(&i.to_be_bytes());
            mesh.sender
                .heap
                .emit(&path, Bytes::from(message), EmitOptions::reliable())
                .await
                .expect("the sender is a writer");
        }
    };

    let receive = async {
        // The consumer is not reading: wait until the receiver's forwarder has had to hold a
        // stream frame (every buffer between the sender and the consumer is full).
        eventually("the receiver's link lane holds a stream frame", || {
            receiver.site.engine.side().stats().stream_held >= 1
        })
        .await;

        // The lane waits; NDN on the same link does not: every Interest is answered.
        for i in 0..20 {
            tokio::time::timeout(
                Duration::from_secs(10),
                consumer.fetch(name(&format!("/probe/{i}"))),
            )
            .await
            .unwrap_or_else(|_| {
                panic!("Interest {i} across the link was not answered while the stream was held")
            })
            .unwrap_or_else(|e| panic!("Interest {i} across the link failed: {e}"));
        }

        // Now read: all of it, in order, nothing else.
        let mut next = 0u64;
        let mut notices = Vec::new();
        while next < MESSAGES {
            match tokio::time::timeout(Duration::from_secs(10), items.next()).await {
                Ok(Some(Ok(got))) => {
                    let seq = u64::from_be_bytes(got.bytes[..8].try_into().unwrap());
                    assert_eq!(seq, next, "message {next} was expected, {seq} came");
                    assert_eq!(got.bytes.len(), SIZE);
                    next += 1;
                }
                Ok(Some(Err(notice @ GetNotice::Lagged { .. }))) => {
                    notices.push(format!("{notice:?}"));
                    break;
                }
                Ok(Some(Err(other))) => notices.push(format!("{other:?}")),
                Ok(None) | Err(_) => break,
            }
        }
        (next, notices)
    };

    let ((), (got, notices)) = tokio::time::timeout(Duration::from_secs(180), async {
        tokio::join!(emit, receive)
    })
    .await
    .expect("the flood and its receiver finished");
    cancel.cancel();
    served.abort();

    let (r, s) = (
        receiver.site.engine.side().stats(),
        mesh.sender.site.engine.side().stats(),
    );
    eprintln!("receiver forwarder {r:?}\nsender forwarder {s:?}");
    assert!(notices.is_empty(), "the consumer was told: {notices:?}");
    assert_eq!(got, MESSAGES, "messages delivered in order");
    assert_eq!(
        (r.sink_full, r.sink_error, r.stream_stalled),
        (0, 0, 0),
        "a stream frame was lost at the receiver's forwarder: {r:?}"
    );
    assert_eq!(
        (s.sink_full, s.sink_error),
        (0, 0),
        "a stream frame was lost at the sender's forwarder: {s:?}"
    );
    assert!(r.stream_held >= 1, "{r:?}");
}

/// The forwarder's wait for room at a sink ends well before a peer's write finds the link
/// without progress. A lane holds the stream's inbox full while it waits, so the peer's writer
/// sees no credit for as long as the wait lasts; if the wait were as long as `STREAM_STALL`, the
/// peer would close the link first, and an honest sender would lose its link to a third party's
/// sink that does not read (security review F2 of the stream lane). The wait is at most a third
/// of the bound, so one wait, its release and the drain after it fit in it with room to spare.
#[test]
fn the_lanes_wait_for_a_sink_ends_well_before_the_peers_write_stall() {
    assert!(
        ndn_engine::side::STREAM_HOLD_MAX * 3 <= ndn_face_quic::STREAM_STALL,
        "the lane waits {:?} for a sink; the peer's writer closes the link after {:?}",
        ndn_engine::side::STREAM_HOLD_MAX,
        ndn_face_quic::STREAM_STALL
    );
}
