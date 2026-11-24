//! What signals keep of their clock in the store (signals.md §3.3, §3.5): the sequence counter,
//! durable before it is answered and never lowered by a crash, and the lazily written time hint.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::Duration;

use super::*;

/// A store whose disk keeps only what a returned flush made durable: writes wait in `pending`
/// until `sync` moves them to `durable`, and a crash is the store that `durable` is. While
/// held, `sync` waits.
#[derive(Default)]
struct Lossy {
    durable: Mutex<HashMap<Name, Bytes>>,
    pending: Mutex<HashMap<Name, Bytes>>,
    held: Mutex<bool>,
    let_go: Condvar,
    /// Writes of the sequence counter.
    clock_writes: AtomicUsize,
    /// Writes of the time hint.
    time_writes: AtomicUsize,
}

impl Lossy {
    /// The store a power loss leaves: what was durable.
    fn crash(&self) -> Arc<Lossy> {
        let after = Lossy::default();
        *after.durable.lock().unwrap() = self.durable.lock().unwrap().clone();
        Arc::new(after)
    }

    fn hold(&self, on: bool) {
        *self.held.lock().unwrap() = on;
        self.let_go.notify_all();
    }
}

impl DataStore for Lossy {
    fn insert(&self, name: Name, wire: Bytes) {
        if name == counter_name() {
            self.clock_writes.fetch_add(1, Ordering::SeqCst);
        }
        if name == time_name() {
            self.time_writes.fetch_add(1, Ordering::SeqCst);
        }
        self.pending.lock().unwrap().insert(name, wire);
    }
    fn get(&self, name: &Name) -> Option<Bytes> {
        let pending = self.pending.lock().unwrap().get(name).cloned();
        pending.or_else(|| self.durable.lock().unwrap().get(name).cloned())
    }
    fn remove(&self, name: &Name) {
        self.pending.lock().unwrap().remove(name);
        self.durable.lock().unwrap().remove(name);
    }
    fn sync(&self) -> std::io::Result<()> {
        let mut held = self.held.lock().unwrap();
        while *held {
            held = self.let_go.wait(held).unwrap();
        }
        let moved: Vec<_> = self.pending.lock().unwrap().drain().collect();
        self.durable.lock().unwrap().extend(moved);
        Ok(())
    }
}

/// A process over `store`: what `Signals::start` loads of it.
fn started(store: &Arc<Lossy>) -> Durable {
    Durable::load(Arc::clone(store) as Arc<dyn DataStore>)
}

/// The sequence counter: `sequences(n)` answers a counter above `n` by one block, only once it
/// is durable; a number below the counter writes nothing; a crash while the barrier is held
/// leaves the counter at what was answered before, so no sequence above it was given; and a
/// restart reads the counter back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_sequence_counter_is_durable_before_it_is_answered_and_a_crash_never_lowers_it() {
    let store = Arc::new(Lossy::default());
    let laptop = Arc::new(started(&store));
    assert_eq!(laptop.floor(), 0, "a new process has given no sequence");
    let first = laptop.sequences(1_000).await.unwrap();
    assert_eq!(first, 1_000 + SEQ_BLOCK);
    assert_eq!(laptop.floor(), first);

    // What a power loss leaves holds it.
    let after = store.crash();
    assert_eq!(started(&after).floor(), first);

    // Inside the block nothing is written.
    let writes = store.clock_writes.load(Ordering::SeqCst);
    assert_eq!(laptop.sequences(first).await.unwrap(), first);
    assert_eq!(store.clock_writes.load(Ordering::SeqCst), writes);

    // Past it, with the barrier held: the answer waits, and a crash now leaves the counter
    // where it was answered last, below the number asked, which no sequence was given from.
    store.hold(true);
    let asked = first + 1;
    let waiting = {
        let laptop = Arc::clone(&laptop);
        tokio::spawn(async move { laptop.sequences(asked).await })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!waiting.is_finished(), "not answered before it is durable");
    assert_eq!(
        started(&store.crash()).floor(),
        first,
        "a restart after the dropped barrier is below the number asked, never below one answered"
    );
    store.hold(false);
    let second = waiting.await.unwrap().unwrap();
    assert_eq!(second, asked + SEQ_BLOCK);
    assert_eq!(started(&store.crash()).floor(), second);
}

/// A store that cannot make the counter durable gives no sequence: the answer is the store's
/// failure, and the floor stays where it was.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_counter_the_store_cannot_make_durable_gives_no_sequence() {
    #[derive(Default)]
    struct Failing(Lossy);
    impl DataStore for Failing {
        fn insert(&self, name: Name, wire: Bytes) {
            self.0.insert(name, wire);
        }
        fn get(&self, name: &Name) -> Option<Bytes> {
            self.0.get(name)
        }
        fn remove(&self, name: &Name) {
            self.0.remove(name);
        }
        fn sync(&self) -> std::io::Result<()> {
            Err(std::io::Error::other("the disk is full"))
        }
    }
    let laptop = Durable::load(Arc::new(Failing::default()));
    match laptop.sequences(1).await {
        Err(SignalError::Heap(e @ HeapError::Local { .. })) => {
            let why = e.to_string();
            assert!(why.contains("disk is full"), "{why}");
        }
        other => panic!("a counter that is not durable gives no sequence: {other:?}"),
    }
    assert_eq!(laptop.floor(), 0, "no sequence was given");
}

/// The time hint: noting a time never waits for the barrier and reserves nothing; a second's
/// movement is written, less is not; it moves down as well as up, so a clock corrected after
/// running ahead takes the hint with it; and a restart reads what was made durable.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_time_hint_is_lazy_follows_the_clock_down_and_is_read_back() {
    let store = Arc::new(Lossy::default());
    let laptop = started(&store);
    assert_eq!(laptop.hint(), 0, "a new process dated nothing");

    // With the barrier held a note still returns at once, and writes the hint as it is.
    store.hold(true);
    let at = 1_700_000_000_000_000u64;
    laptop.note_time(at);
    assert_eq!(
        laptop.hint(),
        at,
        "the hint is the time noted, with no reserve"
    );
    assert_eq!(store.time_writes.load(Ordering::SeqCst), 1);
    store.hold(false);

    // Within a second: nothing written. A second on: written.
    laptop.note_time(at + 999_999);
    assert_eq!(store.time_writes.load(Ordering::SeqCst), 1);
    assert_eq!(laptop.hint(), at);
    laptop.note_time(at + 1_000_000);
    assert_eq!(store.time_writes.load(Ordering::SeqCst), 2);
    assert_eq!(laptop.hint(), at + 1_000_000);

    // A clock corrected two hours back: the hint follows it.
    let corrected = at - 7_200_000_000;
    laptop.note_time(corrected);
    assert_eq!(laptop.hint(), corrected);

    // The hint moves no sequence: the counter is untouched by it.
    assert_eq!(laptop.floor(), 0);
    assert_eq!(store.clock_writes.load(Ordering::SeqCst), 0);

    // Made durable by the next barrier (here a sequence block's), a restart reads it back.
    laptop.sequences(1).await.unwrap();
    assert_eq!(started(&store.crash()).hint(), corrected);
}
