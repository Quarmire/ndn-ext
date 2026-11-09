//! Signals between real `ndn_data::Device`s: on one host over a run's ring, over
//! one link between two forwarders, and at 60 Hz from four senders on both.

mod common;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use common::{Engine, World, engine, link, n, no_quota, no_ring};
use ndn_app::EngineAppExt;
use ndn_surface::signal::wire::{self, Packet};
use ndn_surface::signal::{Signal, SignalError, SignalOptions, SignalSubscriber};

const WITHIN: Duration = Duration::from_secs(20);

async fn next(sub: &mut SignalSubscriber, within: Duration) -> Option<Signal> {
    tokio::time::timeout(within, sub.next())
        .await
        .ok()
        .flatten()
}

fn system_us() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64
}

/// A sealed folder's signals cross a link sealed: what the forwarders carry is a
/// `SignalSealed` (a key id, a nonce, a ciphertext), and the member reads them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sealed_scopes_signals_cross_a_link_sealed_and_open_for_a_member() {
    let world = World::new("/alice", &["/alice/laptop", "/alice/phone"]).await;
    let (a, b) = (engine().await, engine().await);
    link(
        &a,
        &b,
        world.ns(),
        &["/alice/laptop"],
        &["/alice/phone"],
        &world.cancel,
    )
    .await;
    let laptop = world.host(&a, "/alice/laptop", no_ring()).await;
    let phone = world
        .host(&b, "/alice/phone", SignalOptions::default())
        .await;
    // What a forwarder on the path sees of the group.
    let tap = b.engine.app_face(world.cancel.child_token());
    tap.register_prefix(&wire::sync_group(world.ns()))
        .await
        .unwrap();
    let secret = n("/alice/32=data/secret");
    laptop.share(&secret, world.ns(), true).await;
    let mut sub = phone.subscribe(&secret, WITHIN).await;
    let mut run = laptop.signals.open(&secret).await.unwrap();
    let mut seen = None;
    for i in 0u32..50 {
        run.send(b"cursor", &i.to_be_bytes()).await.unwrap();
        if let Some(s) = next(&mut sub, Duration::from_millis(500)).await {
            seen = Some(s);
            break;
        }
    }
    let s = seen.expect("a member opens the sealed scope's signals");
    assert_eq!(s.scope, secret);
    assert_eq!(s.sender, n("/alice/laptop/KEY/1"));
    let carried = loop {
        let wire = tokio::time::timeout(Duration::from_secs(5), tap.recv())
            .await
            .expect("the tap hears the group")
            .unwrap();
        let Ok(interest) = ndn_packet::Interest::decode(wire) else {
            continue;
        };
        if let Some(packet) = wire::push_packet(&interest) {
            break packet;
        }
    };
    assert!(
        matches!(wire::decode_packet(carried), Ok(Packet::Sealed(_))),
        "a sealed scope's packet travels sealed"
    );
    world.cancel.cancel();
}

/// A receiver whose clock is ahead by more than a signal's ttl plus the clock
/// skew drops every signal as expired and delivers none.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_signal_past_its_expires_and_the_skew_is_dropped() {
    let world = World::new("/alice", &["/alice/laptop", "/alice/phone"]).await;
    let e = engine().await;
    let laptop = world.host(&e, "/alice/laptop", no_ring()).await;
    let ahead = SignalOptions {
        clock: Some(Arc::new(|| system_us() + 40_000_000)),
        ..SignalOptions::default()
    };
    let phone = world.host(&e, "/alice/phone", ahead).await;
    let board = n("/alice/32=data/board");
    laptop.share(&board, world.ns(), false).await;
    let mut sub = phone.subscribe(&board, WITHIN).await;
    let mut run = laptop.signals.open(&board).await.unwrap();
    for i in 0u32..5 {
        run.send(b"cursor", &i.to_be_bytes()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(next(&mut sub, Duration::from_millis(500)).await.is_none());
    let stats = phone.signals.stats();
    assert_eq!(stats.delivered, 0, "{stats:?}");
    assert_eq!(stats.expired, 5, "2 s ttl + 30 s skew < 40 s: {stats:?}");
    world.cancel.cancel();
}

/// A sender is held to §5: address, payload, batch, ttl and packet sizes, and
/// 120 packets/s with a burst of 30 per run. Its clock stands still here, so
/// the bucket never refills.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sender_is_held_to_its_limits() {
    let world = World::new("/alice", &["/alice/laptop"]).await;
    let e = engine().await;
    let now = system_us();
    let still = SignalOptions {
        clock: Some(Arc::new(move || now)),
        local_ring: false,
        ..SignalOptions::default()
    };
    let laptop = world.host(&e, "/alice/laptop", still).await;
    let (board, secret) = (n("/alice/32=data/board"), n("/alice/32=data/secret"));
    laptop.share(&board, world.ns(), false).await;
    laptop.share(&secret, world.ns(), true).await;
    let mut run = laptop.signals.open(&board).await.unwrap();
    let too_large = |r: Result<_, SignalError>| match r {
        Err(SignalError::TooLarge { what, .. }) => what,
        other => panic!("refused TooLarge, not {other:?}"),
    };
    assert_eq!(
        too_large(run.send(&[0; 65], b"").await.map(|_| ())),
        "an address"
    );
    assert_eq!(
        too_large(run.send(b"a", &[0; 769]).await.map(|_| ())),
        "a payload"
    );
    let many: Vec<(&[u8], &[u8])> = vec![(b"a", b"p"); 33];
    assert_eq!(
        too_large(run.send_batch(&many).await.map(|_| ())),
        "a batch (signals)"
    );
    assert_eq!(
        too_large(
            run.send_for(b"a", b"p", Duration::from_secs(61))
                .await
                .map(|_| ())
        ),
        "a ttl (ms)"
    );
    // A full signal doesn't fit beside the header: the header rides alone first.
    run.send(&[0; 64], &[0; 768]).await.unwrap();
    assert_eq!(laptop.signals.stats().sent_packets, 2);
    for _ in 0..28 {
        run.send(b"cursor", b"p").await.unwrap();
    }
    match run.send(b"cursor", b"p").await {
        Err(e @ SignalError::RateLimited { retry_after }) => {
            assert_eq!(
                retry_after,
                Duration::from_micros(8334),
                "one packet per 1/120 s"
            );
            assert_eq!(e.next(), ndn_data::NextStep::RetryLater);
        }
        other => panic!("over its burst of 30 the run is rate limited, not {other:?}"),
    }
    // Sealed, a full signal is over the packet limit.
    let mut sealed = laptop.signals.open(&secret).await.unwrap();
    assert_eq!(
        too_large(sealed.send(&[0; 64], &[0; 768]).await.map(|_| ())),
        "the packet"
    );
    run.close().await;
    sealed.send(b"a", b"p").await.unwrap();
    laptop.signals.shutdown();
    assert!(matches!(
        sealed.send(b"a", b"p").await,
        Err(SignalError::Closed)
    ));
    world.cancel.cancel();
}

/// A scope the data layer refuses for its name (no `32=data`) is refused with
/// that refusal and its own next step — fix the name — not as a membership one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_scope_that_is_no_data_layer_name_is_refused_with_the_data_layers_reason() {
    let world = World::new("/alice", &["/alice/laptop"]).await;
    let e = engine().await;
    let laptop = world.host(&e, "/alice/laptop", no_ring()).await;
    let bad = n("/alice/board");
    for refused in [
        laptop.signals.subscribe(&bad).await.map(|_| ()),
        laptop.signals.open(&bad).await.map(|_| ()),
    ] {
        match refused {
            Err(e @ SignalError::Data(ndn_data::DataError::BadName { .. })) => {
                assert_eq!(e.next(), ndn_data::NextStep::FixName, "{e}");
            }
            other => panic!("refused with the data layer's BadName, not {other:?}"),
        }
    }
    world.cancel.cancel();
}

/// A full-size signal sent first, whose packet has no room for the run header,
/// arrives after a header-only packet.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_full_signal_arrives_after_its_header_rode_alone() {
    let world = World::new("/alice", &["/alice/laptop", "/alice/phone"]).await;
    let e = engine().await;
    let laptop = world.host(&e, "/alice/laptop", no_ring()).await;
    let phone = world
        .host(&e, "/alice/phone", SignalOptions::default())
        .await;
    let board = n("/alice/32=data/board");
    laptop.share(&board, world.ns(), false).await;
    let mut sub = phone.subscribe(&board, WITHIN).await;
    let mut run = laptop.signals.open(&board).await.unwrap();
    let seq = run.send(&[7; 64], &[9; 768]).await.unwrap();
    let s = next(&mut sub, Duration::from_secs(5))
        .await
        .expect("the full signal arrives");
    assert_eq!((s.seq, s.address.len(), s.payload.len()), (seq, 64, 768));
    assert_eq!(
        laptop.signals.stats().sent_packets,
        2,
        "a header-only packet, then the signal"
    );
    let stats = phone.signals.stats();
    assert_eq!((stats.delivered, stats.unknown_run), (1, 0), "{stats:?}");
    world.cancel.cancel();
}

/// Two devices of `/alice` on one engine: the laptop shares the board and sends,
/// the phone subscribes. The phone admits the run's header from the first
/// packet, which came over the forwarder, attaches to the run's ring, and from
/// then on receives off the ring.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn after_its_first_packet_a_local_runs_signals_come_off_its_ring() {
    let world = World::new("/alice", &["/alice/laptop", "/alice/phone"]).await;
    let e = engine().await;
    let laptop = world
        .host(&e, "/alice/laptop", SignalOptions::default())
        .await;
    let phone = world
        .host(&e, "/alice/phone", SignalOptions::default())
        .await;
    let board = n("/alice/32=data/board");
    laptop.share(&board, world.ns(), false).await;
    let mut sub = phone.subscribe(&board, WITHIN).await;
    let mut run = laptop.signals.open(&board).await.unwrap();

    let mut got = Vec::new();
    for i in 0u32..100 {
        run.send(b"cursor", &i.to_be_bytes()).await.unwrap();
        if let Some(s) = next(&mut sub, Duration::from_millis(500)).await {
            let local = s.local;
            got.push(s);
            if local {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let first = got
        .first()
        .expect("the phone receives the laptop's signals");
    assert!(
        !first.local,
        "the first signal came over the forwarder: no ring is attached before its header"
    );
    assert_eq!(first.sender, n("/alice/laptop/KEY/1"));
    assert_eq!(first.address.as_ref(), b"cursor");
    assert_eq!(first.scope, board);
    let last = got.last().unwrap();
    assert!(
        last.local,
        "after the header, the run's ring carries its packets"
    );
    assert_eq!(last.run, run.id());
    let stats = phone.signals.stats();
    assert!(stats.local >= 1);
    assert_eq!(
        stats.bad_signature + stats.not_member + stats.malformed,
        0,
        "{stats:?}"
    );
    world.cancel.cancel();
}

/// The laptop on one engine, the phone on another, the engines joined by a UDP
/// face: the laptop's signals are pushed into `/alice/32=sync` and arrive.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_members_signals_arrive_over_one_link() {
    let world = World::new("/alice", &["/alice/laptop", "/alice/phone"]).await;
    let (a, b) = (engine().await, engine().await);
    link(
        &a,
        &b,
        world.ns(),
        &["/alice/laptop"],
        &["/alice/phone"],
        &world.cancel,
    )
    .await;
    let laptop = world.host(&a, "/alice/laptop", no_ring()).await;
    let phone = world
        .host(&b, "/alice/phone", SignalOptions::default())
        .await;
    let board = n("/alice/32=data/board");
    laptop.share(&board, world.ns(), false).await;
    let mut sub = phone.subscribe(&board, WITHIN).await;
    let mut run = laptop.signals.open(&board).await.unwrap();
    let mut seen = None;
    for i in 0u32..50 {
        let seq = run.send(b"presence", &i.to_be_bytes()).await.unwrap();
        if let Some(s) = next(&mut sub, Duration::from_millis(500)).await {
            seen = Some((seq, s));
            break;
        }
    }
    let (seq, s) = seen.expect("a member's signal arrives over the link");
    assert_eq!(s.seq, seq);
    assert!(!s.local);
    assert_eq!(s.sender, n("/alice/laptop/KEY/1"));
    assert_eq!(s.address, Bytes::from_static(b"presence"));
    world.cancel.cancel();
}

/// Four runs send at 60 Hz for 2 s, each to its own address. No signal is lost:
/// each is delivered, or stale (a newer one of its address was delivered first —
/// on one host, while the reader attaches to a ring, a forwarder copy can come
/// after the ring's next); each address's last is read. Four runs at 60 Hz push
/// 240 Interests/s, over the default push budget: the engines here carry no
/// relay quota, so the sender's budget is raised ([`no_quota`]).
async fn sixty_hertz_from_four(
    sender_engine: &Engine,
    receiver_engine: &Engine,
    world: &World,
    sender: SignalOptions,
) {
    let laptop = world.host(sender_engine, "/alice/laptop", sender).await;
    let phone = world
        .host(receiver_engine, "/alice/phone", SignalOptions::default())
        .await;
    let board = n("/alice/32=data/board");
    laptop.share(&board, world.ns(), false).await;
    let mut sub = phone.subscribe(&board, WITHIN).await;
    const SENDERS: usize = 4;
    const PER_SENDER: u64 = 120;
    let reader = tokio::spawn(async move {
        let mut last: HashMap<Bytes, u64> = HashMap::new();
        while let Some(s) = next(&mut sub, Duration::from_secs(1)).await {
            last.insert(s.address.clone(), s.seq);
        }
        last
    });
    let mut senders = Vec::new();
    for i in 0..SENDERS {
        let mut run = laptop.signals.open(&board).await.unwrap();
        senders.push(tokio::spawn(async move {
            let address = format!("cursor/{i}");
            let mut tick = tokio::time::interval(Duration::from_micros(16_667));
            let mut last = 0;
            for k in 0..PER_SENDER {
                tick.tick().await;
                last = run
                    .send(address.as_bytes(), &k.to_be_bytes())
                    .await
                    .unwrap();
            }
            (Bytes::from(address), last, run)
        }));
    }
    let mut sent = HashMap::new();
    let mut runs = Vec::new();
    for s in senders {
        let (address, last, run) = s.await.unwrap();
        sent.insert(address, last);
        runs.push(run);
    }
    let last = reader.await.unwrap();
    let stats = phone.signals.stats();
    assert_eq!(
        stats.delivered + stats.stale,
        SENDERS as u64 * PER_SENDER,
        "no loss on a clean path: {stats:?}"
    );
    assert_eq!(last, sent, "every sender's last signal per address is read");
    assert_eq!(
        stats.unknown_run + stats.flood + stats.expired + stats.malformed,
        0,
        "{stats:?}"
    );
    drop(runs);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sixty_hertz_from_four_senders_on_one_host_loses_nothing() {
    let world = World::new("/alice", &["/alice/laptop", "/alice/phone"]).await;
    let e = engine().await;
    sixty_hertz_from_four(&e, &e, &world, no_quota(SignalOptions::default())).await;
    world.cancel.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sixty_hertz_from_four_senders_over_a_link_loses_nothing() {
    let world = World::new("/alice", &["/alice/laptop", "/alice/phone"]).await;
    let (a, b) = (engine().await, engine().await);
    link(
        &a,
        &b,
        world.ns(),
        &["/alice/laptop"],
        &["/alice/phone"],
        &world.cancel,
    )
    .await;
    sixty_hertz_from_four(&a, &b, &world, no_quota(no_ring())).await;
    world.cancel.cancel();
}
