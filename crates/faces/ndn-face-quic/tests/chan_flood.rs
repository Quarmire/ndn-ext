//! A `Latest` flood through the sender's own forwarder over one QUIC link (the shape of ndf's
//! channel row: a data-layer node attached to its forwarder through the app face, the link a
//! face of that forwarder, a receiver on a forwarder of its own): at 1 KiB and 8 KiB, and with
//! 256 paths cycled, back to back.
//!
//! What it asserts is the sender's first hop. A datagram frame the node hands to its forwarder
//! used to be queued at the app face and found a full link only when the face's reader took it
//! from the queue: refused there, counted `sink_full`, and told to no one, with the newest
//! message of every path in the frame. A node holding the link face itself is told `Full` and
//! keeps the message pending, coalescing; now a node on a forwarder is told the same, so no
//! frame it hands over is lost at its own forwarder (`sink_full` and `sink_error` stay 0), the
//! receiver is told nothing but `Lagged` (no checkpoint contradicts an honest sender, no session
//! ends), and a share of what was emitted arrives.

use std::time::{Duration, Instant};

use bytes::Bytes;
use ndn_engine::side::SideId;
use ndn_heap::{EmitOptions, GetNotice, GetOptions, Items, Name, Select};

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
    let start = Instant::now();
    while !done() {
        assert!(
            start.elapsed() < Duration::from_secs(15),
            "gave up waiting for: {what}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// What the receiver's consumer saw: items, and every notice that was not an item.
#[derive(Debug, Default)]
struct Seen {
    items: u64,
    lagged: u64,
    missed: u64,
    other: Vec<String>,
}

/// The sender emits `size`-octet messages over 256 paths back to back for `run`; the receiver's
/// consumer takes what comes meanwhile and until the link has been quiet for a second.
/// Returns the messages emitted, what the consumer saw and the sender forwarder's counters.
async fn flood(size: usize, run: Duration) -> (u64, Seen, ndn_engine::side::SideStats) {
    let build = Build {
        transport: ndn_face_quic::LinkTransportConfig {
            path_mtu_max: 9_000,
            ..ndn_face_quic::LinkTransportConfig::default()
        },
        ..Build::default()
    };
    let mesh = Mesh::new(&Runtimes::current(), 1, false, build).await;
    let mut items = live(&mesh.receivers[0]);
    let here = tokio::runtime::Handle::current();
    let info = Mesh::ask(&here, &mesh.receivers[0].node, &mesh.sender.node).await;
    eventually("HELLO", || items.hello_seen()).await;
    eventually("the sender's link takes the datagram size", || {
        mesh.sender.link.max_datagram_size() >= Some(8_900)
    })
    .await;
    eventually("the route stands at the sender's forwarder", || {
        mesh.sender.site.engine.side().sinks(SideId(info.channel)) == 1
    })
    .await;

    let consumer = tokio::spawn(async move {
        let mut seen = Seen::default();
        // Quiet for a second: the flood is over and what the link holds has been read.
        while let Ok(Some(next)) = tokio::time::timeout(Duration::from_secs(1), items.next()).await
        {
            match next {
                Ok(_) => seen.items += 1,
                Err(GetNotice::Lagged { missed, .. }) => {
                    seen.lagged += 1;
                    seen.missed += missed;
                }
                Err(other) => seen.other.push(format!("{other:?}")),
            }
        }
        seen
    });

    let paths: Vec<Name> = (0..256).map(|i| name(&format!("/bench/{i}"))).collect();
    let payload = Bytes::from(vec![7u8; size]);
    let (start, mut emitted) = (Instant::now(), 0u64);
    while start.elapsed() < run {
        for path in &paths {
            mesh.sender
                .heap
                .emit(path, payload.clone(), EmitOptions::latest())
                .await
                .expect("the sender is a writer");
            emitted += 1;
        }
    }
    let seen = consumer.await.expect("the consumer ran");
    (emitted, seen, mesh.sender.site.engine.side().stats())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_latest_flood_loses_no_frame_the_node_handed_to_its_forwarder() {
    for size in [1_024, 8_192] {
        let (emitted, seen, stats) = flood(size, Duration::from_millis(1_500)).await;
        let share = 100.0 * seen.items as f64 / emitted as f64;
        eprintln!(
            "{size} B: emitted {emitted}, delivered {} ({share:.1} %), lagged {} (missed {}); sender forwarder {stats:?}",
            seen.items, seen.lagged, seen.missed
        );
        assert_eq!(
            (stats.sink_full, stats.sink_error),
            (0, 0),
            "{size} B: a frame the node handed to its forwarder was lost at the forwarder's \
             link face and the node was not told: {stats:?}"
        );
        assert!(
            seen.other.is_empty(),
            "{size} B: the receiver was told something other than Lagged (a checkpoint \
             contradicting an honest sender, or a session ended): {:?}",
            seen.other
        );
        // The link is the limit (it carries a few Gbit/s; the emitter offers far more and `Latest`
        // replaces what it cannot send), and so is the consumer's own speed (a `Latest` receiver
        // replaces what its consumer has not taken), so the share of what was emitted is only
        // floored well above the collapse (0.08 %). How much of the link's octets the consumer
        // keeps up with depends on the machine's load and the build, and is not asserted.
        assert!(
            share >= 0.5,
            "{size} B: {share:.1} % of {emitted} emitted messages arrived ({} items, lagged {} \
             missed {}): {stats:?}",
            seen.items,
            seen.lagged,
            seen.missed
        );
    }
}
