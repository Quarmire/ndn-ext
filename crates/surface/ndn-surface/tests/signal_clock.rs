//! The clock signals are dated by (signals.md §3.3, §13.8): never behind a time this device
//! dated signals by before, across a restart, and never stepping back while it runs.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use common::{World, engine, n, no_ring};
use futures::StreamExt;
use ndn_data::DataLayer;
use ndn_surface::signal::{Signal, SignalError, SignalOptions, SignalSubscriber};
use ndn_sync::MemoryStore;

const WITHIN: Duration = Duration::from_secs(20);
const HOUR_US: u64 = 3_600_000_000;

fn system_us() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64
}

async fn next(sub: &mut SignalSubscriber, within: Duration) -> Option<Signal> {
    tokio::time::timeout(within, sub.next())
        .await
        .ok()
        .flatten()
}

/// Options of a sender whose clock reads `clock` and whose packets cross the forwarder.
fn dated_by(clock: impl Fn() -> u64 + Send + Sync + 'static) -> SignalOptions {
    SignalOptions {
        clock: Some(Arc::new(clock)),
        ..no_ring()
    }
}

/// A member restarts with its clock an hour behind: bob's laptop signalled by the real time,
/// stopped, and starts again on its store with a clock that stepped back. Its signals are
/// dated above everything it dated before, so alice's phone hears it again: the sequences
/// are above the earlier run's, and its `Expires` is in time for a receiver whose clock is right.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_member_restarted_with_its_clock_an_hour_behind_is_heard_again() {
    let world = World::new("/alice", &["/alice/laptop", "/alice/phone"]).await;
    let e = engine().await;
    let store = Arc::new(MemoryStore::new());
    let laptop = world
        .host_on(&e, "/alice/laptop", no_ring(), Arc::clone(&store))
        .await;
    let phone = world
        .host(&e, "/alice/phone", SignalOptions::default())
        .await;
    let board = n("/alice/32=data/board");
    laptop.share(&board, world.ns(), false).await;
    let mut sub = phone.subscribe(&board, WITHIN).await;
    let mut run = laptop.signals.open(&board).await.unwrap();
    let mut before = 0;
    for i in 0u8..3 {
        before = run.send(b"cursor", &[i]).await.unwrap();
        assert!(
            next(&mut sub, Duration::from_secs(5)).await.is_some(),
            "the first run is heard"
        );
    }
    run.close().await;
    laptop.signals.shutdown();
    laptop.device.shutdown();

    let laptop = world
        .host_on(
            &e,
            "/alice/laptop",
            dated_by(|| system_us() - HOUR_US),
            store,
        )
        .await;
    let mut changes = laptop
        .device
        .watch(&board, &ndn_data::Frontier::new())
        .await
        .expect("the restarted device follows the folder");
    tokio::spawn(async move { while changes.next().await.is_some() {} });
    let deadline = std::time::Instant::now() + WITHIN;
    let mut run = loop {
        match laptop.signals.open(&board).await {
            Ok(run) => break run,
            Err(SignalError::NotReady { .. }) if std::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(e) => panic!("the restarted device cannot open a run: {e}"),
        }
    };
    let seq = run.send(b"cursor", b"again").await.unwrap();
    assert!(
        seq > before,
        "the new run's sequences start above the run before it: {seq} after {before}"
    );
    let heard = next(&mut sub, Duration::from_secs(5)).await;
    let stats = phone.signals.stats();
    let s = heard.unwrap_or_else(|| {
        panic!("the restarted member is not heard: its signals are expired or stale ({stats:?})")
    });
    assert_eq!((s.seq, s.payload.as_ref()), (seq, &b"again"[..]));
    world.cancel.cancel();
}

/// A clock that steps back while the process runs never dates a signal earlier than one
/// before it: the next signal's sequence and `Expires` are not below the last's, and a receiver
/// whose clock is right still hears it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_clock_that_steps_back_while_running_never_dates_a_signal_earlier() {
    let world = World::new("/alice", &["/alice/laptop", "/alice/phone"]).await;
    let e = engine().await;
    let now = Arc::new(AtomicU64::new(system_us()));
    let clock = Arc::clone(&now);
    let laptop = world
        .host(
            &e,
            "/alice/laptop",
            dated_by(move || clock.load(Ordering::SeqCst)),
        )
        .await;
    let phone = world
        .host(&e, "/alice/phone", SignalOptions::default())
        .await;
    let board = n("/alice/32=data/board");
    laptop.share(&board, world.ns(), false).await;
    let mut sub = phone.subscribe(&board, WITHIN).await;
    let mut run = laptop.signals.open(&board).await.unwrap();
    let first = run.send(b"cursor", b"before").await.unwrap();
    let s1 = next(&mut sub, Duration::from_secs(5))
        .await
        .expect("the signal before the step is heard");
    // The clock steps back an hour and, the next moment, runs on.
    now.store(system_us() - HOUR_US, Ordering::SeqCst);
    let mut seen = vec![(s1.seq, s1.expires)];
    for i in 0u8..3 {
        tokio::time::sleep(Duration::from_millis(30)).await;
        now.fetch_add(30_000, Ordering::SeqCst);
        let seq = run.send(b"cursor", &[i]).await.unwrap();
        assert!(seq > first);
        let s = next(&mut sub, Duration::from_secs(5))
            .await
            .unwrap_or_else(|| {
                panic!(
                    "the signal after the clock stepped back is not heard: {:?}",
                    phone.signals.stats()
                )
            });
        seen.push((s.seq, s.expires));
    }
    assert!(
        seen.windows(2).all(|w| w[1].0 > w[0].0 && w[1].1 >= w[0].1),
        "sequences rise and Expires never falls: {seen:?}"
    );
    world.cancel.cancel();
}

/// The limit (signals.md §13.8): the floor never moves a sender's clock forward to real time.
/// A device with no earlier signals whose clock is an hour behind dates by it, and a receiver
/// whose clock is right drops every signal as expired.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sender_whose_clock_stays_behind_real_time_is_still_expired_for_receivers() {
    let world = World::new("/alice", &["/alice/laptop", "/alice/phone"]).await;
    let e = engine().await;
    let laptop = world
        .host(&e, "/alice/laptop", dated_by(|| system_us() - HOUR_US))
        .await;
    let phone = world
        .host(&e, "/alice/phone", SignalOptions::default())
        .await;
    let board = n("/alice/32=data/board");
    laptop.share(&board, world.ns(), false).await;
    let mut sub = phone.subscribe(&board, WITHIN).await;
    let mut run = laptop.signals.open(&board).await.unwrap();
    for i in 0u8..5 {
        run.send(b"cursor", &[i]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(next(&mut sub, Duration::from_millis(500)).await.is_none());
    let stats = phone.signals.stats();
    assert_eq!(
        (stats.delivered, stats.expired),
        (0, 5),
        "a clock behind real time still dates signals that are expired: {stats:?}"
    );
    world.cancel.cancel();
}
