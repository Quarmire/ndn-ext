//! Stage 4 end to end (SHAPES-CHANNEL.md §8, §13): a channel fanned out through forwarders over
//! real QUIC links. A sender, a relay and up to four receivers, each on a forwarder of its own
//! (`examples/common/relay.rs`); the relay has no identity, no trust and no data layer, only
//! routes toward the people's names and its side table. Each receiver asks the sender for the
//! channel with the real signed ask: the Interest goes receiver -> relay -> sender, the session
//! Data returns with its `SideRoute` and installs a route at every hop, and `Heap::emit` at the
//! sender reaches both receivers' `Heap::live` through the relay.

use std::time::{Duration, Instant};

use bytes::Bytes;
use ndn_engine::side::{SideConfig, SideId, SideLimits};
use ndn_face_quic::LinkHandle;
use ndn_heap::{EmitOptions, GetNotice, GetOptions, Got, Items, LiveEnd, Name, Select};

#[allow(dead_code)]
#[path = "../examples/common/pair.rs"]
mod pair;
#[allow(dead_code)]
#[path = "../examples/common/relay.rs"]
mod relay;

use relay::{Build, Mesh, Party, Runtimes, name};

fn live(party: &Party) -> Items {
    party
        .heap
        .live(Select::Prefix(Name::root()), GetOptions::default())
        .expect("a member of the space")
}

async fn next(items: &mut Items) -> Result<Got, GetNotice> {
    tokio::time::timeout(Duration::from_secs(10), items.next())
        .await
        .expect("an item within 10 s")
        .expect("the stream is open")
}

async fn eventually(what: &str, mut done: impl FnMut() -> bool) {
    let start = Instant::now();
    while !done() {
        assert!(
            start.elapsed() < Duration::from_secs(15),
            "gave up waiting for: {what}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Frames a link sent, and frames it received, on both carriers.
fn tx_frames(link: &LinkHandle) -> u64 {
    let s = link.side_stats();
    s.datagram_tx_frames + s.stream_tx_frames
}

fn rx_frames(link: &LinkHandle) -> u64 {
    let s = link.side_stats();
    s.datagram_rx_frames + s.stream_rx_frames
}

async fn emit(mesh: &Mesh, path: &str, bytes: &[u8]) {
    mesh.sender
        .heap
        .emit(
            &name(path),
            Bytes::copy_from_slice(bytes),
            EmitOptions::latest(),
        )
        .await
        .expect("the sender is a writer");
}

/// Every receiver asked, the route standing at every hop, and the sender's `HELLO` seen at all.
struct Fanned {
    mesh: Mesh,
    items: Vec<Items>,
    channel: u64,
}

async fn fanned_out(receivers: usize) -> Fanned {
    let mesh = Mesh::new(&Runtimes::current(), receivers, true, Build::default()).await;
    let items: Vec<Items> = mesh.receivers.iter().map(live).collect();
    let here = tokio::runtime::Handle::current();
    let mut channel = None;
    for r in &mesh.receivers {
        let info = Mesh::ask(&here, &r.node, &mesh.sender.node).await;
        assert_eq!(
            *channel.get_or_insert(info.channel),
            info.channel,
            "one channel, {receivers} receivers"
        );
    }
    let channel = channel.expect("a receiver");
    let relay = mesh.relay.as_ref().expect("a relay");
    eventually("the relay holds every receiver as a sink", || {
        relay.engine.side().sinks(SideId(channel)) == receivers
    })
    .await;
    eventually("HELLO at every receiver", || {
        items.iter().all(Items::hello_seen)
    })
    .await;
    Fanned {
        channel,
        mesh,
        items,
    }
}

/// Everything that moves a frame, read at one moment: the sender's link, the relay's engine and
/// links, the receivers' links.
#[derive(Debug)]
struct Counts {
    sender_link_tx: u64,
    sender_in: u64,
    sender_out: u64,
    relay_link_rx_from_sender: u64,
    relay_in: u64,
    relay_out: u64,
    relay_link_tx: Vec<u64>,
    receiver_link_rx: Vec<u64>,
}

fn counts(mesh: &Mesh) -> Counts {
    let relay = mesh.relay.as_ref().unwrap();
    let (s, r) = (
        mesh.sender.site.engine.side().stats(),
        relay.engine.side().stats(),
    );
    Counts {
        sender_link_tx: tx_frames(&mesh.sender.link),
        sender_in: s.frames_in,
        sender_out: s.frames_out,
        relay_link_rx_from_sender: rx_frames(&mesh.relay_links[0]),
        relay_in: r.frames_in,
        relay_out: r.frames_out,
        relay_link_tx: mesh.relay_links[1..].iter().map(tx_frames).collect(),
        receiver_link_rx: mesh.receivers.iter().map(|r| rx_frames(&r.link)).collect(),
    }
}

/// `receivers` behind a relay get every message, and one copy of each frame leaves the sender.
async fn one_copy(receivers: usize) {
    let Fanned {
        mesh,
        mut items,
        channel,
    } = fanned_out(receivers).await;
    let relay = mesh.relay.as_ref().unwrap();

    // The relay holds the route with a sink for each receiver; the sender's forwarder holds it
    // with one (the relay), the receivers' with one each (their node).
    let routes = relay.engine.side().list();
    let route = routes.iter().find(|r| r.id == channel).expect("the route");
    assert_eq!(route.sinks.len(), receivers, "the relay's sinks: {route:?}");
    let at_sender = mesh.sender.site.engine.side().list();
    let sender_route = at_sender.iter().find(|r| r.id == channel).expect("route");
    assert_eq!(sender_route.sinks.len(), 1, "one link out of the sender");

    // Quiet, then one message at a time (so that each is a frame of its own), each seen by all.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let before = counts(&mesh);
    const M: u64 = 12;
    for i in 0..M {
        let (path, payload) = (format!("/m/{i}"), format!("message {i}"));
        emit(&mesh, &path, payload.as_bytes()).await;
        for items in &mut items {
            let got = next(items).await.expect("an item");
            assert_eq!(got.path.to_string(), path);
            assert_eq!(&got.bytes[..], payload.as_bytes());
            assert_eq!(&got.writer, mesh.sender.node.name());
        }
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let after = counts(&mesh);
    let d = |f: fn(&Counts) -> u64| f(&after) - f(&before);
    let sent = d(|c| c.sender_link_tx);
    let n = receivers as u64;

    // Every message was a frame at least (the checkpoints that follow are frames too).
    assert!(sent >= M, "{M} messages sent in {sent} frames");
    // One copy of each frame leaves the sender: its forwarder has one sink for the channel, so
    // what its app face handed in is what its link sent...
    assert_eq!(
        d(|c| c.sender_in),
        sent,
        "sender: frames in\n{before:?}\n{after:?}"
    );
    assert_eq!(
        d(|c| c.sender_out),
        sent,
        "sender: frames out\n{before:?}\n{after:?}"
    );
    // ...the relay received exactly those and made a copy for each of its sinks, and each
    // receiver's link carried the same frames once...
    assert_eq!(
        d(|c| c.relay_link_rx_from_sender),
        sent,
        "{before:?}\n{after:?}"
    );
    assert_eq!(d(|c| c.relay_in), sent, "{before:?}\n{after:?}");
    assert_eq!(d(|c| c.relay_out), n * sent, "{before:?}\n{after:?}");
    for i in 0..receivers {
        assert_eq!(
            after.relay_link_tx[i] - before.relay_link_tx[i],
            sent,
            "relay link {i}\n{before:?}\n{after:?}"
        );
        assert_eq!(
            after.receiver_link_rx[i] - before.receiver_link_rx[i],
            sent,
            "receiver {i}\n{before:?}\n{after:?}"
        );
    }
    let stats = relay.engine.side().stats();
    assert_eq!(
        stats.sink_full + stats.sink_error + stats.unrouted,
        0,
        "{stats:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_receivers_behind_a_relay_get_every_message_and_the_sender_link_carries_one_copy_of_each_frame()
 {
    one_copy(2).await;
}

/// Rung `C3` of the stage 4 gate (SHAPES-CHANNEL.md §13): one sender, four receivers behind a
/// relay. The sender's link carries one copy of each frame, whoever is behind the relay.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn four_receivers_behind_a_relay_get_every_message_and_the_sender_link_carries_one_copy_of_each_frame()
 {
    one_copy(4).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_receiver_that_unsubscribes_leaves_the_other_receiving_and_the_relay_with_one_sink() {
    let Fanned {
        mesh,
        mut items,
        channel,
    } = fanned_out(2).await;
    let mut b = items.pop().unwrap();
    let a = items.pop().unwrap();
    let relay = mesh.relay.as_ref().unwrap();
    let route_sinks = |site: &relay::Site| site.engine.side().sinks(SideId(channel));
    let unsubs = relay.engine.side().stats().unsubs;

    // A leaves: its `Items` is dropped, its session ends, and an `Unsub` goes up its link.
    drop(a);
    eventually("the relay is down to one sink", || route_sinks(relay) == 1).await;
    assert!(relay.engine.side().stats().unsubs > unsubs);
    let routes = relay.engine.side().list();
    let route = routes
        .iter()
        .find(|r| r.id == channel)
        .expect("route stands");
    assert_eq!(route.sinks.len(), 1);
    assert_eq!(
        mesh.receivers[0].site.engine.side().sinks(SideId(channel)),
        0,
        "A's own forwarder let go of the route"
    );
    assert_eq!(
        mesh.sender.site.engine.side().sinks(SideId(channel)),
        1,
        "the sender still has its one sink: B is behind it"
    );

    // B goes on receiving.
    emit(&mesh, "/after", b"still here").await;
    let got = next(&mut b).await.expect("an item");
    assert_eq!(got.path.to_string(), "/after");
    assert_eq!(&got.bytes[..], b"still here");

    // B leaves too: the last sink goes, the relay's route with it, and the `Unsub` reaches the
    // sender, whose route goes.
    drop(b);
    eventually("the relay has no route", || route_sinks(relay) == 0).await;
    eventually("the sender has no route", || {
        mesh.sender.site.engine.side().sinks(SideId(channel)) == 0
    })
    .await;
    assert!(relay.engine.side().list().iter().all(|r| r.id != channel));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relay_that_cannot_install_the_route_ends_the_session_with_no_path_after_two_seconds() {
    // A forwarder that predates the header never installs a route; one whose table takes no
    // route is the same to the receiver: the session Data arrives, the frames do not.
    let build = Build {
        relay_side: SideConfig {
            limits: SideLimits {
                routes: 0,
                ..SideLimits::default()
            },
            ..SideConfig::default()
        },
        ..Build::default()
    };
    let mesh = Mesh::new(&Runtimes::current(), 1, true, build).await;
    let mut items = live(&mesh.receivers[0]);
    let here = tokio::runtime::Handle::current();
    let info = Mesh::ask(&here, &mesh.receivers[0].node, &mesh.sender.node).await;
    let asked = Instant::now();
    let relay = mesh.relay.as_ref().unwrap();
    assert_eq!(relay.engine.side().sinks(SideId(info.channel)), 0);
    assert!(relay.engine.side().stats().refused_table_full >= 1);

    // Nothing before the two seconds (a `HELLO` that never comes is no news sooner)...
    let waited = tokio::time::timeout(Duration::from_millis(1500), items.next()).await;
    assert!(waited.is_err(), "told too early: {waited:?}");
    // ...then the receiver is told what is wrong and what to do.
    let GetNotice::LiveEnded(end) = next(&mut items).await.unwrap_err() else {
        panic!("a LiveEnded notice");
    };
    let late = asked.elapsed();
    let LiveEnd::NoPath { why } = &end else {
        panic!("not NoPath: {end:?}");
    };
    assert!(
        why.contains("a forwarder between you and the sender does not carry channel frames"),
        "{why}"
    );
    assert!(
        late >= Duration::from_millis(1900) && late < Duration::from_secs(6),
        "told after {late:?}"
    );
    assert!(!items.hello_seen());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_receiver_linked_to_the_sender_directly_gets_every_message() {
    let mesh = Mesh::new(&Runtimes::current(), 1, false, Build::default()).await;
    let mut items = live(&mesh.receivers[0]);
    let here = tokio::runtime::Handle::current();
    let info = Mesh::ask(&here, &mesh.receivers[0].node, &mesh.sender.node).await;
    eventually("HELLO", || items.hello_seen()).await;
    assert_eq!(
        mesh.sender.site.engine.side().sinks(SideId(info.channel)),
        1
    );
    for i in 0..10 {
        let (path, payload) = (format!("/d/{i}"), format!("direct {i}"));
        emit(&mesh, &path, payload.as_bytes()).await;
        let got = next(&mut items).await.expect("an item");
        assert_eq!(got.path.to_string(), path);
        assert_eq!(&got.bytes[..], payload.as_bytes());
    }
}

/// A receiver lets the channel go (its `Items` dropped: the session ends, an `Unsub` goes up the
/// links and every route of the channel goes) and later takes it again: the same ask, a new
/// session, a route made anew at every hop, and the frames flow again.
async fn a_receiver_that_left_takes_the_channel_again(relay: bool) {
    let mesh = Mesh::new(&Runtimes::current(), 1, relay, Build::default()).await;
    let here = tokio::runtime::Handle::current();
    for round in 0..3 {
        let mut items = live(&mesh.receivers[0]);
        let info = Mesh::ask(&here, &mesh.receivers[0].node, &mesh.sender.node).await;
        let waiting = Instant::now();
        while !items.hello_seen() {
            assert!(
                waiting.elapsed() < Duration::from_secs(5),
                "round {round}: no HELLO within 5 s of the ask\nsender table {:?}\nsender link {:?}\nreceiver table {:?}\nreceiver link {:?}\nrelay table {:?}",
                mesh.sender.site.engine.side().stats(),
                mesh.sender.link.side_stats(),
                mesh.receivers[0].site.engine.side().stats(),
                mesh.receivers[0].link.side_stats(),
                mesh.relay.as_ref().map(|r| r.engine.side().stats()),
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let (path, payload) = (format!("/again/{round}"), format!("round {round}"));
        emit(&mesh, &path, payload.as_bytes()).await;
        let got = next(&mut items).await.expect("an item");
        assert_eq!(got.path.to_string(), path);
        assert_eq!(&got.bytes[..], payload.as_bytes());

        drop(items);
        eventually("every route of the channel is gone", || {
            mesh.sender.site.engine.side().sinks(SideId(info.channel)) == 0
                && mesh.receivers[0]
                    .site
                    .engine
                    .side()
                    .sinks(SideId(info.channel))
                    == 0
                && mesh
                    .relay
                    .as_ref()
                    .is_none_or(|r| r.engine.side().sinks(SideId(info.channel)) == 0)
        })
        .await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_receiver_that_left_takes_the_channel_again_on_a_direct_link() {
    a_receiver_that_left_takes_the_channel_again(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_receiver_that_left_takes_the_channel_again_behind_a_relay() {
    a_receiver_that_left_takes_the_channel_again(true).await;
}
