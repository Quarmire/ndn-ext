//! The channel path of a query over real links (REPLY-25 stage 4, docs/specs/query.md, the channel
//! path; docs/specs/channel.md §14.13): a **server** (a writer, serving `/world`), a **relay**, an
//! **asker** and a **second receiver** behind the same relay, each on a forwarder of its own
//! (`examples/common/relay.rs`), every hop a real QUIC link.
//!
//! Both receivers hold a session of the server's `Ask` channel, so both are sinks of **one route**
//! at the relay and at the server's forwarder. The asker queries with `QueryPath::Channel`: a
//! `QUERY` frame goes up the route (leaving a breadcrumb at each forwarder it crosses) and the
//! sealed `ANSWER` comes back down the breadcrumbs. The answer must reach the asker's forwarder
//! and no other: the second receiver's link carries nothing, its forwarder sees nothing, and each
//! breadcrumb is gone once the answer passed.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use ndn_engine::side::{SideId, SideStats};
use ndn_face_quic::LinkHandle;
use ndn_heap::{
    Ask, ChannelMode, GetNotice, GetOptions, Got, Items, Kind, Live, Name, Query, QueryPath, Reply,
    Select, Targets, Via,
};

#[allow(dead_code)]
#[path = "../examples/common/pair.rs"]
mod pair;
#[allow(dead_code)]
#[path = "../examples/common/relay.rs"]
mod relay;

use relay::{Build, Mesh, Party, Runtimes, Site, name, space};

/// A query of `bytes` to `server` by `via`, nothing else asked of `get`.
fn query_options(server: &Name, bytes: &[u8], via: QueryPath) -> GetOptions {
    let mut ask = Ask::new(Bytes::copy_from_slice(bytes));
    ask.targets = Targets::Devices(vec![server.clone()]);
    ask.via = via;
    ask.deadline = Duration::from_secs(5);
    GetOptions {
        kept: false,
        live: Live::Off,
        ask: Some(ask),
        ..GetOptions::default()
    }
}

/// What one query told: the answers, then the notices up to `AnswersDone`.
async fn drain(items: &mut Items) -> (Vec<Got>, Vec<GetNotice>) {
    let (mut got, mut notices) = (Vec::new(), Vec::new());
    loop {
        let next = tokio::time::timeout(Duration::from_secs(10), items.next())
            .await
            .expect("an item or a notice within 10 s");
        match next {
            Some(Ok(answer)) => got.push(answer),
            Some(Err(notice)) => {
                let done = matches!(notice, GetNotice::AnswersDone { .. });
                notices.push(notice);
                if done {
                    return (got, notices);
                }
            }
            None => return (got, notices),
        }
    }
}

/// Ask `server` once by the channel, again until it answers: the space's record takes a moment to
/// reach the asker over the links.
async fn ask_until_answered(
    party: &Party,
    server: &Name,
    bytes: &[u8],
) -> (Vec<Got>, Vec<GetNotice>) {
    let start = Instant::now();
    loop {
        // `get` refuses while the owner's first entries are not held yet (a `NotReady` that says
        // so): the record reaches the asker over the links in a moment.
        let got = party.heap.get(
            Select::Path(name("/world/pickup")),
            query_options(server, bytes, QueryPath::Channel),
        );
        match got {
            Ok(mut items) => {
                let (got, notices) = drain(&mut items).await;
                if !got.is_empty() || start.elapsed() > Duration::from_secs(30) {
                    return (got, notices);
                }
            }
            Err(e) if start.elapsed() > Duration::from_secs(30) => {
                panic!("a member of the space may ask: {e} (next: {:?})", e.next())
            }
            Err(_) => {}
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

fn stats(site: &Site) -> SideStats {
    site.engine.side().stats()
}

fn rx_frames(link: &LinkHandle) -> u64 {
    let s = link.side_stats();
    s.datagram_rx_frames + s.stream_rx_frames
}

fn tx_frames(link: &LinkHandle) -> u64 {
    let s = link.side_stats();
    s.datagram_tx_frames + s.stream_tx_frames
}

async fn quiet() {
    tokio::time::sleep(Duration::from_millis(400)).await;
}

/// The whole scenario, in a sealed space (a public space lists no reader here: its receivers are
/// followers, and a query needs a listed asker; that case is the heap's own test).
async fn the_answer_reaches_only_the_asker() {
    let mesh = Mesh::new(&Runtimes::current(), 2, true, Build::default()).await;
    let relay = mesh.relay.as_ref().expect("a relay");
    let server = mesh.sender.node.name().clone();
    let (asker, other) = (&mesh.receivers[0], &mesh.receivers[1]);

    // The server answers `/world`: it says whom it answered and by which path.
    let runs = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&runs);
    let _serving = mesh
        .sender
        .heap
        .serve(name("/world"), move |q: Query| {
            counted.fetch_add(1, Ordering::SeqCst);
            async move {
                assert_eq!(q.via, Via::Sealed, "the channel path");
                Reply::Answer(Bytes::from(format!(
                    "granted to {} ({})",
                    q.asker.device,
                    String::from_utf8_lossy(&q.bytes)
                )))
            }
        })
        .expect("a writer serves");

    // The second receiver holds a session of the server's `Ask` channel, so it is a sink of the
    // same route as the asker will be: the exposure the test is about.
    let here = tokio::runtime::Handle::current();
    let channel = {
        let (node, server) = (other.node.handle(), server.clone());
        here.spawn(async move {
            let start = Instant::now();
            loop {
                match node
                    .ask_channel_in(&space(), &server, ChannelMode::Ask)
                    .await
                {
                    Ok(info) => return info.channel,
                    Err(e) if start.elapsed() < Duration::from_secs(30) => {
                        let _ = e;
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                    Err(e) => panic!("the second receiver asked for an Ask session: {e}"),
                }
            }
        })
        .await
        .unwrap()
    };
    // What the second receiver would see of anything that reached it.
    let mut watching = other
        .heap
        .get(
            Select::Prefix(Name::root()),
            GetOptions {
                kept: false,
                ..GetOptions::default()
            },
        )
        .expect("a member of the space");

    // The asker queries; the first answer is the one under test.
    let (got, notices) = ask_until_answered(asker, &server, b"the pickup").await;
    assert_eq!(got.len(), 1, "one answer: {got:?} {notices:?}");
    let answer = &got[0];
    assert_eq!(&answer.bytes[..], b"granted to /carol/tablet (the pickup)");
    assert_eq!(answer.path, name("/world/pickup"));
    assert_eq!(answer.author.writer, server);
    assert_eq!(answer.author.by, name("/bob"));
    let Kind::Answered(answered) = &answer.kind else {
        panic!("an answer: {:?}", answer.kind);
    };
    assert_eq!(answered.via, Via::Sealed);
    assert!(answered.refusal.is_none());
    assert!(
        matches!(
            notices.last(),
            Some(GetNotice::AnswersDone {
                asked: 1,
                answered: 1,
                refused: 0,
                failed: 0,
                silent: 0,
                ..
            })
        ),
        "{notices:?}"
    );
    assert_eq!(runs.load(Ordering::SeqCst), 1, "the handler ran once");

    // Both receivers are sinks of the one route.
    eventually("both receivers are sinks of the route at the relay", || {
        relay.engine.side().sinks(SideId(channel)) == 2
    })
    .await;

    // A second query, measured: nothing else moves, so every counter's delta is the query's.
    quiet().await;
    let sites = [&mesh.sender.site, relay, &asker.site, &other.site];
    let before: Vec<SideStats> = sites.iter().map(|s| stats(s)).collect();
    let other_link_rx = rx_frames(&other.link);
    let relay_to_other_tx = tx_frames(&mesh.relay_links[2]);
    let relay_to_asker_tx = tx_frames(&mesh.relay_links[1]);

    let (got, _) = ask_until_answered(asker, &server, b"again").await;
    assert_eq!(got.len(), 1);
    assert_eq!(&got[0].bytes[..], b"granted to /carol/tablet (again)");
    quiet().await;

    let after: Vec<SideStats> = sites.iter().map(|s| stats(s)).collect();
    let delta = |i: usize, f: fn(&SideStats) -> u64| f(&after[i]) - f(&before[i]);
    // The sender's forwarder, the relay and the asker's forwarder each passed one QUERY up and
    // one ANSWER down; the second receiver's forwarder saw neither.
    for (i, hop) in [
        "the server's forwarder",
        "the relay",
        "the asker's forwarder",
    ]
    .iter()
    .enumerate()
    {
        assert_eq!(delta(i, |s| s.queries), 1, "{hop} passed one QUERY up");
        assert_eq!(delta(i, |s| s.answers), 1, "{hop} passed one ANSWER down");
    }
    assert_eq!(
        delta(3, |s| s.queries),
        0,
        "the second receiver sent no query"
    );
    assert_eq!(
        delta(3, |s| s.answers),
        0,
        "the second receiver's forwarder saw no answer"
    );
    // The relay never fanned the answer out: one link carried it, toward the asker; the link
    // toward the second receiver carried nothing, and neither did its receiving end.
    assert_eq!(
        tx_frames(&mesh.relay_links[2]) - relay_to_other_tx,
        0,
        "the relay sent nothing toward the second receiver"
    );
    assert_eq!(
        tx_frames(&mesh.relay_links[1]) - relay_to_asker_tx,
        1,
        "the relay sent the one ANSWER toward the asker"
    );
    assert_eq!(
        rx_frames(&other.link) - other_link_rx,
        0,
        "the second receiver's link received nothing"
    );
    // Every breadcrumb was consumed by its answer, at every hop, and nothing was refused.
    for (i, site) in sites.iter().enumerate() {
        let s = stats(site);
        assert_eq!(s.breadcrumbs, 0, "site {i} holds no breadcrumb: {s:?}");
        assert_eq!(
            s.unmatched + s.late + s.pit_dup + s.pit_full + s.pit_face_full + s.pit_route_full,
            0,
            "site {i} refused nothing of the side PIT: {s:?}"
        );
        assert_eq!(
            s.wrong_source + s.malformed + s.unrouted,
            0,
            "site {i}: {s:?}"
        );
    }
    // The second receiver's live stream saw nothing at all.
    let nothing = tokio::time::timeout(Duration::from_millis(500), watching.next()).await;
    assert!(nothing.is_err(), "the second receiver was told {nothing:?}");
    assert_eq!(runs.load(Ordering::SeqCst), 2, "one handler run per query");
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn in_a_sealed_space_the_answer_reaches_only_the_asker_and_every_breadcrumb_is_consumed() {
    the_answer_reaches_only_the_asker().await;
}

/// A query goes to the server that asked for it and its answer to the asker that asked, whoever
/// else holds a session: a second asker's own query gets its own answer, not the first's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_askers_behind_one_relay_each_get_only_their_own_answer() {
    let mesh = Mesh::new(&Runtimes::current(), 2, true, Build::default()).await;
    let server = mesh.sender.node.name().clone();
    let _serving = mesh
        .sender
        .heap
        .serve(name("/world"), |q: Query| async move {
            Reply::Answer(Bytes::from(format!("for {}", q.asker.device)))
        })
        .expect("a writer serves");
    let (carol, dave) = (&mesh.receivers[0], &mesh.receivers[1]);
    let (c, d) = tokio::join!(
        ask_until_answered(carol, &server, b"c"),
        ask_until_answered(dave, &server, b"d")
    );
    assert_eq!(c.0.len(), 1);
    assert_eq!(d.0.len(), 1);
    assert_eq!(&c.0[0].bytes[..], b"for /carol/tablet");
    assert_eq!(&d.0[0].bytes[..], b"for /dave/watch");
    quiet().await;
    for site in [
        &mesh.sender.site,
        mesh.relay.as_ref().unwrap(),
        &carol.site,
        &dave.site,
    ] {
        assert_eq!(stats(site).breadcrumbs, 0);
    }
    // Each asker's forwarder passed exactly its own answer.
    assert_eq!(stats(&carol.site).answers, 1);
    assert_eq!(stats(&dave.site).answers, 1);
}
