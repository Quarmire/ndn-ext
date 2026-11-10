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

/// The warnings the process logged: one capture, set as the global subscriber by the first
/// test that asks for it.
fn warnings() -> Arc<std::sync::Mutex<Vec<String>>> {
    use std::sync::{LazyLock, Mutex};
    struct Capture(Arc<Mutex<Vec<String>>>);
    struct Message(String);
    impl tracing::field::Visit for Message {
        fn record_debug(&mut self, f: &tracing::field::Field, v: &dyn std::fmt::Debug) {
            if f.name() == "message" {
                self.0 = format!("{v:?}");
            }
        }
    }
    impl tracing::Subscriber for Capture {
        fn enabled(&self, m: &tracing::Metadata<'_>) -> bool {
            *m.level() <= tracing::Level::WARN
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, e: &tracing::Event<'_>) {
            let mut m = Message(String::new());
            e.record(&mut m);
            self.0.lock().unwrap().push(m.0);
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }
    static LOG: LazyLock<Arc<Mutex<Vec<String>>>> = LazyLock::new(|| {
        let log = Arc::new(Mutex::new(Vec::new()));
        tracing::subscriber::set_global_default(Capture(Arc::clone(&log)))
            .expect("no other subscriber in this test binary");
        log
    });
    Arc::clone(&LOG)
}

/// A restarted device's run in `board`, asked again while its record is being read.
async fn reopened(host: &common::Host, board: &ndn_data::Name) -> ndn_surface::signal::SignalRun {
    let mut changes = host
        .device
        .watch(board, &ndn_data::Frontier::new())
        .await
        .expect("the restarted device follows the folder");
    tokio::spawn(async move { while changes.next().await.is_some() {} });
    let deadline = std::time::Instant::now() + WITHIN;
    loop {
        match host.signals.open(board).await {
            Ok(run) => return run,
            Err(SignalError::NotReady { .. }) if std::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(e) => panic!("the restarted device cannot open a run: {e}"),
        }
    }
}

/// What a signal was dated by, in ms: its `Expires` less the default ttl.
fn dated_ms(s: &Signal) -> u64 {
    s.expires - SignalOptions::default().ttl.as_millis() as u64
}

/// A crash loop (round 4, M4): 50 restarts, the raw clock running on between them, each opening
/// a run and sending. The reading stays within a second of the raw clock, and the sequences rise
/// strictly. A floor that reserved 5 s ahead of every start moved the reading 5 s ahead per
/// restart, and a receiver dropped everything after the seventh.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fifty_quick_restarts_neither_ratchet_the_clock_nor_lower_a_sequence() {
    let world = World::new("/alice", &["/alice/laptop", "/alice/phone"]).await;
    let e = engine().await;
    let store = Arc::new(MemoryStore::new());
    let phone = world
        .host(&e, "/alice/phone", SignalOptions::default())
        .await;
    let board = n("/alice/32=data/board");
    let mut sub = None;
    let mut last = None;
    for restart in 0u8..50 {
        let laptop = world
            .host_on(&e, "/alice/laptop", dated_by(system_us), Arc::clone(&store))
            .await;
        if restart == 0 {
            laptop.share(&board, world.ns(), false).await;
            sub = Some(phone.subscribe(&board, WITHIN).await);
        }
        let sub = sub.as_mut().expect("subscribed at the first start");
        let mut run = reopened(&laptop, &board).await;
        let seq = run.send(b"cursor", &[restart]).await.unwrap();
        assert!(
            last.is_none_or(|l| seq > l),
            "restart {restart}: sequence {seq} is not above the last restart's {last:?}"
        );
        last = Some(seq);
        let heard = next(sub, Duration::from_secs(5)).await.unwrap_or_else(|| {
            panic!(
                "restart {restart}: the signal is not heard (a clock ratcheted ahead of real time \
                 is expired for a receiver): {:?}",
                phone.signals.stats()
            )
        });
        let off = dated_ms(&heard).abs_diff(system_us() / 1000);
        assert!(
            off < 1000,
            "restart {restart}: the signal is dated {off} ms from the raw clock, not within a second"
        );
        run.close().await;
        laptop.signals.shutdown();
        laptop.device.shutdown();
    }
    world.cancel.cancel();
}

/// A forward step the clock was then corrected from (M4): a clock 2 h ahead dates signals by
/// it; the clock is corrected and the device restarts. The reading is the raw clock again, the
/// warning says why the time held was not kept, and a receiver whose clock is right hears it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_clock_corrected_after_a_two_hour_forward_step_is_read_as_it_is_again() {
    let log = warnings();
    let world = World::new("/alice", &["/alice/laptop", "/alice/phone"]).await;
    let e = engine().await;
    let store = Arc::new(MemoryStore::new());
    let phone = world
        .host(&e, "/alice/phone", SignalOptions::default())
        .await;
    let board = n("/alice/32=data/board");
    let ahead = dated_by(|| system_us() + 2 * HOUR_US);
    let laptop = world
        .host_on(&e, "/alice/laptop", ahead, Arc::clone(&store))
        .await;
    laptop.share(&board, world.ns(), false).await;
    let mut sub = phone.subscribe(&board, WITHIN).await;
    let mut run = laptop.signals.open(&board).await.unwrap();
    run.send(b"cursor", b"ahead").await.unwrap();
    run.close().await;
    laptop.signals.shutdown();
    laptop.device.shutdown();

    // Corrected: the clock reads real time again, and the device starts.
    let laptop = world
        .host_on(&e, "/alice/laptop", dated_by(system_us), store)
        .await;
    let mut run = reopened(&laptop, &board).await;
    run.send(b"cursor", b"corrected").await.unwrap();
    let heard = next(&mut sub, Duration::from_secs(5))
        .await
        .unwrap_or_else(|| {
            panic!(
                "the corrected clock is not read as it is: its signals are dated 2 h ahead and \
                 dropped ({:?})",
                phone.signals.stats()
            )
        });
    assert_eq!(heard.payload.as_ref(), b"corrected");
    let off = dated_ms(&heard).abs_diff(system_us() / 1000);
    assert!(off < 1000, "dated {off} ms from the raw clock");
    assert!(
        log.lock()
            .unwrap()
            .iter()
            .any(|w| w.contains("time hint") && w.contains("ahead of the clock")),
        "the start from the raw clock is logged: {:?}",
        log.lock().unwrap()
    );
    world.cancel.cancel();
}

/// A receiver whose own reading is 10 min ahead (M4): its clock stepped forward, was corrected,
/// and the device restarted on the hint. It judges what it hears by the raw clock, so a sender
/// whose clock is right is still delivered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_receiver_whose_reading_is_ten_minutes_ahead_still_hears_a_right_clocked_sender() {
    let world = World::new("/alice", &["/alice/laptop", "/alice/phone"]).await;
    let e = engine().await;
    let store = Arc::new(MemoryStore::new());
    let laptop = world.host(&e, "/alice/laptop", no_ring()).await;
    let board = n("/alice/32=data/board");
    laptop.share(&board, world.ns(), false).await;

    // The phone dated by a clock 10 min ahead, then stopped.
    let ahead = dated_by(|| system_us() + 600_000_000);
    let phone = world
        .host_on(&e, "/alice/phone", ahead, Arc::clone(&store))
        .await;
    let _ = phone.subscribe(&board, WITHIN).await;
    let mut run = reopened(&phone, &board).await;
    run.send(b"cursor", b"ahead").await.unwrap();
    run.close().await;
    phone.signals.shutdown();
    phone.device.shutdown();

    // It starts again with the clock right: its reading is still 10 min ahead.
    let phone = world
        .host_on(&e, "/alice/phone", SignalOptions::default(), store)
        .await;
    let mut sub = phone.subscribe(&board, WITHIN).await;
    let mut run = reopened(&laptop, &board).await;
    run.send(b"cursor", b"on time").await.unwrap();
    let heard = next(&mut sub, Duration::from_secs(5))
        .await
        .unwrap_or_else(|| {
            panic!(
                "a sender with a right clock is not heard by a receiver whose reading is 10 min \
                 ahead ({:?})",
                phone.signals.stats()
            )
        });
    assert_eq!(heard.payload.as_ref(), b"on time");
    world.cancel.cancel();
}

/// A device restarted with its clock an hour behind still hears others (signals.md §13.8): its
/// reading holds the time it last dated by, so how far ahead a signal may be dated is measured
/// from that, and a sender whose clock is right is not "more than 60 s ahead". Its raw clock
/// still judges liveness.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_restarted_with_its_clock_an_hour_behind_still_hears_a_right_clocked_sender() {
    let world = World::new("/alice", &["/alice/laptop", "/alice/phone"]).await;
    let e = engine().await;
    let store = Arc::new(MemoryStore::new());
    let laptop = world.host(&e, "/alice/laptop", no_ring()).await;
    let board = n("/alice/32=data/board");
    laptop.share(&board, world.ns(), false).await;

    // The phone dated by a right clock, then stopped.
    let phone = world
        .host_on(&e, "/alice/phone", no_ring(), Arc::clone(&store))
        .await;
    let _ = phone.subscribe(&board, WITHIN).await;
    let mut run = reopened(&phone, &board).await;
    run.send(b"cursor", b"before").await.unwrap();
    run.close().await;
    phone.signals.shutdown();
    phone.device.shutdown();

    // It starts again with its clock an hour behind.
    let behind = dated_by(|| system_us() - HOUR_US);
    let phone = world.host_on(&e, "/alice/phone", behind, store).await;
    let mut sub = phone.subscribe(&board, WITHIN).await;
    let mut run = reopened(&laptop, &board).await;
    run.send(b"cursor", b"on time").await.unwrap();
    let heard = next(&mut sub, Duration::from_secs(5))
        .await
        .unwrap_or_else(|| {
            panic!(
                "a sender with a right clock is not heard by a device whose clock is an hour \
                 behind ({:?})",
                phone.signals.stats()
            )
        });
    assert_eq!(heard.payload.as_ref(), b"on time");
    world.cancel.cancel();
}
