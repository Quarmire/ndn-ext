//! The link memory over a [`DataStore`] (ndn-link.md §17C.4, plan D14): the notes
//! under `/localhost/ndn-link/memory/<key>`, the rules on keys and values, the
//! bound on the notes, durability before a write returns, and a restart on the
//! same store.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, UNIX_EPOCH};

use bytes::Bytes;
use ndn_face_quic::{Direction, KeyFingerprint};
use ndn_packet::Name;
use ndn_sync::{DataStore, MemoryStore, StoreOp};

use super::{
    DeviceMemory, LISTEN_PORT_KEY, NOTE_PART_MAX, NOTE_VALUE_MAX, NOTES_PER_AREA_MAX, NoteError,
};
use crate::memory::{LinkMemory, PeerRecord};

fn mem() -> Arc<dyn DataStore> {
    Arc::new(MemoryStore::new())
}

fn note_name(key: &str) -> Name {
    format!("/localhost/ndn-link/memory/{key}").parse().unwrap()
}

/// A store whose disk keeps only what a returned [`DataStore::sync`] made
/// durable (a power loss is [`Lossy::after_power_loss`]), that counts the
/// syncs, and whose sync can be made to fail or to wait.
struct Lossy {
    live: MemoryStore,
    disk: MemoryStore,
    pending: parking_lot::Mutex<Vec<StoreOp>>,
    /// While set, a sync does not finish.
    frozen: AtomicBool,
    /// Set by the first sync that started.
    entered: AtomicBool,
    /// While set, a sync fails and makes nothing durable.
    failing: AtomicBool,
    syncs: AtomicUsize,
    /// What `sync_is_immediate` answers.
    immediate: bool,
}

impl Lossy {
    fn new() -> Arc<Lossy> {
        Lossy::answering(false)
    }

    fn answering(immediate: bool) -> Arc<Lossy> {
        Arc::new(Lossy {
            live: MemoryStore::new(),
            disk: MemoryStore::new(),
            pending: parking_lot::Mutex::new(Vec::new()),
            frozen: AtomicBool::new(false),
            entered: AtomicBool::new(false),
            failing: AtomicBool::new(false),
            syncs: AtomicUsize::new(0),
            immediate,
        })
    }

    /// What the disk holds after a power loss, as a store that opens on it.
    fn after_power_loss(&self) -> Arc<Lossy> {
        let next = Lossy::new();
        for (name, wire) in self.disk.scan_under(&Name::root(), 0) {
            next.live.insert(name.clone(), wire.clone());
            next.disk.insert(name, wire);
        }
        next
    }

    fn on_disk(&self, name: &Name) -> Option<Bytes> {
        self.disk.get(name)
    }

    fn syncs(&self) -> usize {
        self.syncs.load(Ordering::SeqCst)
    }
}

impl DataStore for Lossy {
    fn insert(&self, name: Name, wire: Bytes) {
        self.pending
            .lock()
            .push(StoreOp::Insert(name.clone(), wire.clone()));
        self.live.insert(name, wire);
    }
    fn get(&self, name: &Name) -> Option<Bytes> {
        self.live.get(name)
    }
    fn scan_under(&self, prefix: &Name, limit: usize) -> Vec<(Name, Bytes)> {
        self.live.scan_under(prefix, limit)
    }
    fn remove(&self, name: &Name) {
        self.pending.lock().push(StoreOp::Remove(name.clone()));
        self.live.remove(name);
    }
    fn sync(&self) -> std::io::Result<()> {
        self.syncs.fetch_add(1, Ordering::SeqCst);
        self.entered.store(true, Ordering::SeqCst);
        while self.frozen.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(5));
        }
        if self.failing.load(Ordering::SeqCst) {
            return Err(std::io::Error::other("the disk refused the flush"));
        }
        let ops = std::mem::take(&mut *self.pending.lock());
        self.disk.apply(ops);
        Ok(())
    }
    fn sync_is_immediate(&self) -> bool {
        self.immediate
    }
}

/// The words of a refusal of the request, or a failure of the test.
fn why(e: NoteError) -> String {
    match e {
        NoteError::Refused { why, .. } => why,
        other => panic!("a refusal of the request was expected, got {other:?}"),
    }
}

fn record() -> PeerRecord {
    PeerRecord {
        key: KeyFingerprint([7; 32]),
        device: "/ann/member/laptop".parse().unwrap(),
        addresses: vec!["192.0.2.7:4433".parse().unwrap()],
        last_contact: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        origin: Direction::Accepted,
        port: Some(4433),
    }
}

#[tokio::test]
async fn a_note_is_kept_listed_replaced_and_removed() {
    let store = mem();
    let notes = DeviceMemory::new(Arc::clone(&store)).notes.clone();
    assert_eq!(notes.get("a").unwrap(), None);
    notes.put("a", b"one").await.unwrap();
    notes.put("b", b"").await.unwrap();
    assert_eq!(notes.get("a").unwrap().as_deref(), Some(&b"one"[..]));
    assert_eq!(notes.get("b").unwrap().as_deref(), Some(&b""[..]));
    notes.put("a", b"two").await.unwrap();
    let listed = notes.list().unwrap();
    assert_eq!(
        listed
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_ref()))
            .collect::<Vec<_>>(),
        vec![("a", &b"two"[..]), ("b", &b""[..])],
        "listed by key"
    );
    // The area is a whole component, not a prefix of characters, and a name
    // deeper than a key is no note of it.
    store.insert(
        "/localhost/ndn-link/memory-other/a".parse().unwrap(),
        Bytes::from_static(b"x"),
    );
    store.insert(
        "/localhost/ndn-link/memory/a/deeper".parse().unwrap(),
        Bytes::from_static(b"x"),
    );
    assert_eq!(notes.list().unwrap().len(), 2);
    notes.remove("a").await.unwrap();
    notes.remove("never-was").await.unwrap();
    assert_eq!(notes.get("a").unwrap(), None);
    assert_eq!(notes.list().unwrap().len(), 1);
}

/// What `tests/memory.rs` reads from a device's store: a note is the value as
/// given, at `/localhost/ndn-link/memory/<key>`, and nothing else.
#[tokio::test]
async fn a_note_sits_under_the_local_prefix_as_its_octets() {
    let store = mem();
    let notes = DeviceMemory::new(Arc::clone(&store)).notes.clone();
    notes.put("a", b"one").await.unwrap();
    assert_eq!(
        store.get(&note_name("a")).as_deref(),
        Some(&b"one"[..]),
        "the value is the note's octets"
    );
    assert_eq!(
        store.scan_under(&Name::root(), 0).len(),
        1,
        "one note is one stored name"
    );
    notes.remove("a").await.unwrap();
    assert!(store.scan_under(&Name::root(), 0).is_empty());
}

#[tokio::test]
async fn a_key_that_breaks_a_rule_is_refused_naming_it() {
    let store = Lossy::new();
    let notes = DeviceMemory::new(store.clone()).notes.clone();
    let long = "k".repeat(NOTE_PART_MAX + 1);
    for (key, rule) in [
        ("", "is empty"),
        ("a/b", "contains a '/'"),
        ("a\nb", "control character"),
        ("a\u{7f}", "control character"),
        (long.as_str(), "octets long"),
    ] {
        let put = why(notes.put(key, b"x").await.unwrap_err());
        assert!(put.contains(rule), "put {key:?}: {put}");
        assert!(put.contains("use 1 to 64 octets"), "put {key:?}: {put}");
        assert!(why(notes.get(key).unwrap_err()).contains(rule));
        assert!(why(notes.remove(key).await.unwrap_err()).contains(rule));
    }
    assert_eq!(NOTE_PART_MAX, 64);
    assert_eq!(store.syncs(), 0, "a refused call writes and syncs nothing");
    assert!(store.scan_under(&Name::root(), 0).is_empty());
    // Exactly 64 octets is fine; so is a key that is not ASCII.
    notes.put(&"k".repeat(NOTE_PART_MAX), b"x").await.unwrap();
    notes.put("clé", b"x").await.unwrap();
}

#[tokio::test]
async fn a_value_is_at_most_four_kibibytes() {
    let notes = DeviceMemory::new(mem()).notes.clone();
    assert_eq!(NOTE_VALUE_MAX, 4096);
    notes.put("big", &vec![1; NOTE_VALUE_MAX]).await.unwrap();
    let e = why(notes
        .put("big", &vec![1; NOTE_VALUE_MAX + 1])
        .await
        .unwrap_err());
    assert!(e.contains("at most 4096 octets"), "{e}");
    assert!(e.contains("keep less in a note"), "{e}");
    assert_eq!(notes.get("big").unwrap().unwrap().len(), NOTE_VALUE_MAX);
}

#[tokio::test]
async fn the_notes_are_at_most_a_thousand_and_twenty_four() {
    let store = mem();
    let notes = DeviceMemory::new(Arc::clone(&store)).notes.clone();
    assert_eq!(NOTES_PER_AREA_MAX, 1024);
    // Filled through the store, as a long-lived host would have: a thousand
    // puts through the barrier would only make this slow.
    for i in 0..NOTES_PER_AREA_MAX {
        store.insert(note_name(&format!("k{i}")), Bytes::from_static(b"x"));
    }
    assert_eq!(notes.list().unwrap().len(), NOTES_PER_AREA_MAX);
    let e = why(notes.put("one-more", b"x").await.unwrap_err());
    assert!(e.contains("1024 notes already"), "{e}");
    assert!(e.contains("remove one"), "{e}");
    assert_eq!(notes.get("one-more").unwrap(), None);
    // Replacing one is no new note.
    notes.put("k5", b"y").await.unwrap();
    notes.remove("k5").await.unwrap();
    notes.put("one-more", b"x").await.unwrap();
    assert_eq!(notes.list().unwrap().len(), NOTES_PER_AREA_MAX);
}

#[tokio::test]
async fn notes_come_back_after_a_restart_on_the_same_store() {
    let store = mem();
    let first = DeviceMemory::new(Arc::clone(&store));
    first.notes.put("a", b"one").await.unwrap();
    first.notes.put("gone", b"x").await.unwrap();
    first.notes.remove("gone").await.unwrap();
    first.save(&record()).await.unwrap();
    first.save_listen_port(Some(4433)).await.unwrap();
    drop(first);

    let again = DeviceMemory::new(store);
    assert_eq!(again.notes.get("a").unwrap().as_deref(), Some(&b"one"[..]));
    assert_eq!(again.notes.get("gone").unwrap(), None);
    assert_eq!(again.load().unwrap(), vec![record()]);
    assert_eq!(again.load_listen_port().unwrap(), Some(4433));
    again.remove(&record().key).await.unwrap();
    again.save_listen_port(None).await.unwrap();
    assert!(again.load().unwrap().is_empty());
    assert_eq!(again.load_listen_port().unwrap(), None);
    assert_eq!(
        again.notes.get(LISTEN_PORT_KEY).unwrap(),
        None,
        "no port is no note"
    );
}

/// A put or a remove that returned was behind the store's barrier, on the
/// store's own thread rather than the runtime's, and one still waiting for it
/// is not durable.
#[tokio::test]
async fn a_write_that_returned_survives_a_power_loss_and_one_still_waiting_is_not_durable() {
    let store = Lossy::new();
    let notes = DeviceMemory::new(store.clone()).notes.clone();
    notes.put("kept", b"one").await.unwrap();
    notes.put("removed", b"x").await.unwrap();
    notes.remove("removed").await.unwrap();
    assert_eq!(store.syncs(), 3, "one barrier per write");

    // The disk is frozen: a put does not return, and the disk does not have it.
    store.frozen.store(true, Ordering::SeqCst);
    store.entered.store(false, Ordering::SeqCst);
    let waiting = {
        let notes = notes.clone();
        tokio::spawn(async move { notes.put("waiting", b"two").await })
    };
    while !store.entered.load(Ordering::SeqCst) {
        tokio::task::yield_now().await;
    }
    assert!(
        !waiting.is_finished(),
        "put returned before the store's barrier passed"
    );
    assert!(store.on_disk(&note_name("waiting")).is_none());
    let lost = store.after_power_loss();
    store.frozen.store(false, Ordering::SeqCst);
    waiting.await.unwrap().unwrap();
    assert!(
        store.on_disk(&note_name("waiting")).is_some(),
        "the barrier passed, so the note is on disk"
    );

    // After the power loss: what returned is there, a removal that returned
    // stays, and the memory starts on it.
    let again = DeviceMemory::new(lost).notes.clone();
    assert_eq!(again.get("kept").unwrap().as_deref(), Some(&b"one"[..]));
    assert_eq!(again.get("removed").unwrap(), None);
    assert_eq!(again.get("waiting").unwrap(), None);
}

/// A store that keeps nothing across a restart says its sync is immediate and
/// is called inline; the barrier is still asked for.
#[tokio::test]
async fn a_store_whose_sync_is_immediate_is_synced_too() {
    let store = Lossy::answering(true);
    let notes = DeviceMemory::new(store.clone()).notes.clone();
    notes.put("a", b"one").await.unwrap();
    notes.remove("a").await.unwrap();
    assert_eq!(store.syncs(), 2);
}

/// A put whose sync fails is an error saying so, and what the link memory
/// reports to its host is the same words.
#[tokio::test]
async fn a_write_whose_sync_fails_is_an_error_saying_why() {
    let store = Lossy::new();
    let memory = DeviceMemory::new(store.clone());
    memory.save(&record()).await.unwrap();
    store.failing.store(true, Ordering::SeqCst);

    let e = memory.notes.put("a", b"one").await.unwrap_err();
    assert!(matches!(e, NoteError::Local { .. }), "{e:?}");
    let words = e.to_string();
    assert!(words.contains("the disk refused the flush"), "{words}");
    assert!(words.contains("not known to be durable"), "{words}");
    assert!(words.contains("try again"), "{words}");
    assert!(
        store.on_disk(&note_name("a")).is_none(),
        "what a failed barrier did not make durable is not on the disk"
    );

    let saved = memory.save(&record()).await.unwrap_err();
    assert!(saved.contains("the disk refused the flush"), "{saved}");
    let removed = memory.remove(&record().key).await.unwrap_err();
    assert!(removed.contains("the disk refused the flush"), "{removed}");
    let port = memory.save_listen_port(Some(1)).await.unwrap_err();
    assert!(port.contains("the disk refused the flush"), "{port}");
    let removed_port = memory.save_listen_port(None).await.unwrap_err();
    assert!(
        removed_port.contains("the disk refused the flush"),
        "{removed_port}"
    );
}
