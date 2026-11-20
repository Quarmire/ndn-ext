//! Link status as it changes: [`Links::watch`], a bounded, coalesced table of
//! the last state of each peer by key.
//!
//! The table is the only state: a [`LinkWatch`] holds a cursor (the table's
//! version when it last looked), never a queue, so a watcher that does not
//! read costs nothing, and a peer that flaps between two reads shows once, in
//! its newest state. Each event is recorded where it happens: a link comes
//! up in [`Links::establish`](crate::links), its last path ends where the
//! path's task unregisters it, and what this device does about it is said by
//! [`dial_loop`](crate::links::dial_loop) where it decides.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

use parking_lot::Mutex;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

pub use ndn_face_quic::Direction;
use ndn_face_quic::{KeyFingerprint, LinkError};
use ndn_mgmt_wire::LinkDetail;
use ndn_packet::Name;

use crate::admission::Admitted;
use crate::links::{Links, link_error_detail};
use crate::peer::{LinkMode, PeerId};
use crate::policy::BACKOFF_FIRST;
use crate::status::PathKind;

/// Peers the status table holds at most. A peer beyond it takes the place of
/// the one longest unchanged among those that are `Gone`, then those that are
/// down for another reason, then those that are up.
pub const LINK_STATES_MAX: usize = 256;

/// What this device does about a link that is down.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Next {
    /// It dials the peer again, within `within`.
    Redialling { within: Duration },
    /// The peer has no address to dial: it links in, or a relay or the host
    /// gives an address later.
    WaitingForAddress,
    /// It dials the peer when the link is wanted: the host asks, traffic
    /// waits for it, the relay is needed.
    WhenWanted,
    /// This device is offline ([`Links::set_online`]): it makes no attempt,
    /// and dials the peer again when it is back online.
    WhenOnline,
    /// It does not dial the peer again.
    Gone,
}

/// A peer's link now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LinkState {
    /// Linked since `since`, the link made by `direction`.
    Up {
        direction: Direction,
        since: SystemTime,
    },
    /// Not linked. `direction` is that of the link that was lost (`None`:
    /// there never was one); `why` is plain words and names no address;
    /// `next` says what this device does.
    Down {
        direction: Option<Direction>,
        why: LinkDetail,
        next: Next,
    },
}

/// One peer's link, by the key it linked or was dialled with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerLink {
    pub key: KeyFingerprint,
    /// The peer's device name, from the identity its certificates proved.
    pub device: Option<Name>,
    pub state: LinkState,
}

/// What an observer of the links is told, as it happens: the hook of what
/// learns from links (not a queue: the observer runs inline).
#[derive(Clone, Debug)]
pub(crate) enum LinkEvent {
    /// A path of a link was admitted.
    Up {
        key: KeyFingerprint,
        device: Option<Name>,
        /// Where the path's peer is, as the connection shows it (a hint only).
        remote: SocketAddr,
        direction: Direction,
        kind: PathKind,
        /// The peer entry that expected the key, if one did.
        peer: Option<PeerId>,
        /// An identity admitted it: not an enrollment or introduction link,
        /// nor a peer admitted by its expected key alone.
        identified: bool,
    },
    /// The last path of the link to `key` ended.
    Down {
        key: KeyFingerprint,
        why: LinkDetail,
    },
}

type Observer = Arc<dyn Fn(&LinkEvent) + Send + Sync>;

struct Entry {
    link: PeerLink,
    /// The peer entry the link was made for.
    peer: Option<PeerId>,
    /// The table's version when this entry last changed.
    changed: u64,
}

/// The states, by key, and what the dial loops decided per peer entry.
struct StateTable {
    entries: HashMap<KeyFingerprint, Entry>,
    version: u64,
    /// What each peer entry's dial loop last said it does next: read when a
    /// link ends, which may be before or after the loop decides.
    intents: HashMap<PeerId, Next>,
    max: usize,
}

impl StateTable {
    fn new(max: usize) -> Self {
        Self {
            entries: HashMap::new(),
            version: 0,
            intents: HashMap::new(),
            max,
        }
    }

    /// Records `state` for `key`; `false` when nothing changed.
    fn set(
        &mut self,
        key: KeyFingerprint,
        device: Option<Name>,
        peer: Option<PeerId>,
        state: LinkState,
    ) -> bool {
        if let Some(entry) = self.entries.get_mut(&key) {
            let device = device.or_else(|| entry.link.device.clone());
            let peer = peer.or(entry.peer);
            if entry.link.state == state && entry.link.device == device && entry.peer == peer {
                return false;
            }
            self.version += 1;
            entry.link = PeerLink { key, device, state };
            entry.peer = peer;
            entry.changed = self.version;
            return true;
        }
        if self.entries.len() >= self.max
            && let Some(victim) = self.victim()
        {
            self.entries.remove(&victim);
        }
        self.version += 1;
        self.entries.insert(
            key,
            Entry {
                link: PeerLink { key, device, state },
                peer,
                changed: self.version,
            },
        );
        true
    }

    /// The entry to give up for a new one: `Gone` first, then down, then up,
    /// the longest unchanged of each.
    fn victim(&self) -> Option<KeyFingerprint> {
        self.entries
            .iter()
            .min_by_key(|(_, e)| {
                let rank = match e.link.state {
                    LinkState::Down {
                        next: Next::Gone, ..
                    } => 0,
                    LinkState::Down { .. } => 1,
                    LinkState::Up { .. } => 2,
                };
                (rank, e.changed)
            })
            .map(|(k, _)| *k)
    }

    /// A path of the link to `key` was admitted. A direct path joins a link
    /// that is up and changes nothing.
    fn up(
        &mut self,
        key: KeyFingerprint,
        device: Option<Name>,
        peer: Option<PeerId>,
        direction: Direction,
        kind: PathKind,
    ) -> bool {
        let is_up = |t: &Self| {
            t.entries
                .get(&key)
                .is_some_and(|e| matches!(e.link.state, LinkState::Up { .. }))
        };
        if kind == PathKind::Direct && is_up(self) {
            return false;
        }
        if let Some(peer) = peer {
            self.intents.remove(&peer);
        }
        let state = LinkState::Up {
            direction,
            since: SystemTime::now(),
        };
        self.set(key, device, peer, state)
    }

    /// The last path of the link to `key` ended, saying `why`. `next`
    /// applies unless a dial loop already said what it does about `peer`.
    fn down(
        &mut self,
        key: KeyFingerprint,
        device: Option<Name>,
        peer: Option<PeerId>,
        direction: Direction,
        why: LinkDetail,
        next: Next,
    ) -> bool {
        let next = peer
            .and_then(|p| self.intents.get(&p).copied())
            .unwrap_or(next);
        let state = LinkState::Down {
            direction: Some(direction),
            why,
            next,
        };
        self.set(key, device, peer, state)
    }

    /// A dial of `peer` failed, saying `why`, and `next` is what its loop
    /// does. The state is that of `key`, or of the key the peer showed
    /// before; a peer never keyed, or linked now, has none to change.
    fn failed(
        &mut self,
        key: Option<KeyFingerprint>,
        peer: PeerId,
        why: LinkDetail,
        next: Next,
    ) -> bool {
        self.intents.insert(peer, next);
        let key = key.or_else(|| {
            self.entries
                .iter()
                .find(|(_, e)| e.peer == Some(peer))
                .map(|(k, _)| *k)
        });
        let Some(key) = key else { return false };
        let direction = match self.entries.get(&key).map(|e| &e.link.state) {
            Some(LinkState::Up { .. }) => return false,
            Some(LinkState::Down { direction, .. }) => *direction,
            None => None,
        };
        let state = LinkState::Down {
            direction,
            why,
            next,
        };
        self.set(key, None, Some(peer), state)
    }

    /// What `peer`'s dial loop does next: told to the peer's entries that
    /// are down, and kept for the link that ends later.
    fn decide(&mut self, peer: PeerId, next: Next) -> bool {
        self.intents.insert(peer, next);
        let mut changed = false;
        for entry in self.entries.values_mut() {
            if entry.peer != Some(peer) {
                continue;
            }
            if let LinkState::Down { next: old, .. } = &mut entry.link.state
                && *old != next
            {
                *old = next;
                changed = true;
                self.version += 1;
                entry.changed = self.version;
            }
        }
        changed
    }

    /// The peer entry `peer` is over: nothing more is decided for it.
    fn forget(&mut self, peer: PeerId) {
        self.intents.remove(&peer);
    }

    /// This device went offline: every peer that is down is down because of
    /// it, and is dialled again when this device is back online. A peer's
    /// later outcome (up, or a failed dial) replaces what is said here.
    fn offline(&mut self, why: &LinkDetail) -> bool {
        let mut changed = false;
        for entry in self.entries.values_mut() {
            if let LinkState::Down {
                why: old,
                next: old_next,
                ..
            } = &mut entry.link.state
                && (*old != *why || *old_next != Next::WhenOnline)
            {
                *old = why.clone();
                *old_next = Next::WhenOnline;
                changed = true;
                self.version += 1;
                entry.changed = self.version;
            }
        }
        for next in self.intents.values_mut() {
            *next = Next::WhenOnline;
        }
        changed
    }

    /// The entries changed after `cursor`, the longest unchanged first.
    fn since(&self, cursor: u64) -> Vec<PeerLink> {
        let mut changed: Vec<&Entry> = self
            .entries
            .values()
            .filter(|e| e.changed > cursor)
            .collect();
        changed.sort_by_key(|e| e.changed);
        changed.into_iter().map(|e| e.link.clone()).collect()
    }

    fn all(&self) -> Vec<PeerLink> {
        self.since(0)
    }
}

struct Shared {
    table: Mutex<StateTable>,
    wake: Notify,
    closed: AtomicBool,
}

/// A device's link states and the observers of its links. Owned by the
/// [`Links`]; the end of the links ends every watcher.
pub(crate) struct LinkStates {
    shared: Arc<Shared>,
    observers: Mutex<Vec<Observer>>,
}

impl Default for LinkStates {
    fn default() -> Self {
        Self {
            shared: Arc::new(Shared {
                table: Mutex::new(StateTable::new(LINK_STATES_MAX)),
                wake: Notify::new(),
                closed: AtomicBool::new(false),
            }),
            observers: Mutex::new(Vec::new()),
        }
    }
}

impl Drop for LinkStates {
    fn drop(&mut self) {
        self.shared.closed.store(true, Ordering::Release);
        self.shared.wake.notify_waiters();
    }
}

impl LinkStates {
    fn publish(&self, changed: bool) {
        if changed {
            self.shared.wake.notify_waiters();
        }
    }

    fn emit(&self, event: &LinkEvent) {
        let observers: Vec<Observer> = self.observers.lock().clone();
        for observe in observers {
            observe(event);
        }
    }
}

/// A watcher of the links' states: what [`Links::watch`] returns. It holds
/// a place in the table, not a queue of changes.
pub struct LinkWatch {
    shared: Arc<Shared>,
    cancel: CancellationToken,
    /// The table's version when this watcher last looked; `None` before the
    /// first look.
    cursor: Option<u64>,
}

impl LinkWatch {
    /// The state of every peer now.
    pub fn current(&self) -> Vec<PeerLink> {
        self.shared.table.lock().all()
    }

    /// The first call returns the table now, at once (empty when no peer
    /// has linked or been dialled yet); each later call waits for a change
    /// and returns the peers that changed since this watcher last looked,
    /// one entry per peer, in its newest state: a peer that went down and up
    /// again between two looks shows once, up. `None` once the links ended.
    pub async fn changed(&mut self) -> Option<Vec<PeerLink>> {
        loop {
            let wake = self.shared.wake.notified();
            tokio::pin!(wake);
            wake.as_mut().enable();
            {
                let table = self.shared.table.lock();
                let batch = match self.cursor {
                    None => Some(table.all()),
                    Some(cursor) => Some(table.since(cursor)).filter(|b| !b.is_empty()),
                };
                if let Some(batch) = batch {
                    self.cursor = Some(table.version);
                    return Some(batch);
                }
            }
            if self.shared.closed.load(Ordering::Acquire) {
                return None;
            }
            tokio::select! {
                biased;
                () = self.cancel.cancelled() => return None,
                () = &mut wake => {}
            }
        }
    }
}

impl Links {
    /// The state of every peer's link now, and each change as it happens: a
    /// link up (dialled, accepted, or a direct path), down with the reason
    /// in plain words, what this device does about it, and a failed dial of
    /// a peer whose key is known. Peers are keyed by key; at most
    /// [`LINK_STATES_MAX`] are kept. See [`LinkWatch`].
    pub fn watch(&self) -> LinkWatch {
        LinkWatch {
            shared: Arc::clone(&self.states.shared),
            cancel: self.cancel.clone(),
            cursor: None,
        }
    }

    /// `observe` runs for every [`LinkEvent`], inline where it happens: it
    /// must not block.
    pub(crate) fn observe(&self, observe: Observer) {
        self.states.observers.lock().push(observe);
    }

    /// A path of an admitted link is up.
    pub(crate) fn watch_up(
        &self,
        admitted: &Admitted,
        kind: PathKind,
        direction: Direction,
        remote: SocketAddr,
    ) {
        let device = admitted.identity().map(|i| i.device.clone());
        let changed = self.states.shared.table.lock().up(
            admitted.fingerprint,
            device.clone(),
            admitted.peer,
            direction,
            kind,
        );
        self.states.publish(changed);
        self.states.emit(&LinkEvent::Up {
            key: admitted.fingerprint,
            device,
            remote,
            direction,
            kind,
            peer: admitted.peer,
            identified: admitted.enrollment.is_none() && !admitted.identities.is_empty(),
        });
    }

    /// The last path of the link to `key` ended (and `why` is the close).
    /// Nothing changes when a link to the key came up again meanwhile.
    pub(crate) fn watch_down(
        &self,
        key: KeyFingerprint,
        device: Option<Name>,
        peer: Option<PeerId>,
        direction: Direction,
        why: &LinkError,
    ) {
        let offline = !self.is_online();
        let why = if offline {
            plain(&crate::online::offline_detail())
        } else {
            // A link closed by a let-go names the folder and the record
            // (§8.8), on this side as on the other.
            let detail = link_error_detail(why);
            plain(&match self.departures.take_let_go(&key) {
                Some(let_go) => detail.caused_by(let_go),
                None => detail,
            })
        };
        let next = if offline {
            Next::WhenOnline
        } else {
            self.default_next(peer)
        };
        if offline && let Some(peer) = peer {
            // The intent of an offline device wins over a loop's earlier word.
            self.states
                .shared
                .table
                .lock()
                .decide(peer, Next::WhenOnline);
        }
        let changed = {
            let mut table = self.states.shared.table.lock();
            // Looked at under the table's lock, so a link made again between
            // the unregistering and here is not overwritten.
            !self.table.is_linked(&key)
                && table.down(key, device, peer, direction, why.clone(), next)
        };
        self.states.publish(changed);
        if changed {
            self.states.emit(&LinkEvent::Down { key, why });
        }
    }

    /// What peer `id`'s dial loop does next, once it decided.
    pub(crate) fn watch_next(&self, id: PeerId, next: Next) {
        let changed = self.states.shared.table.lock().decide(id, next);
        self.states.publish(changed);
    }

    /// This device went offline: say so for every peer that is down.
    pub(crate) fn watch_offline(&self) {
        let why = plain(&crate::online::offline_detail());
        let changed = self.states.shared.table.lock().offline(&why);
        self.states.publish(changed);
    }

    /// A dial of peer `id` (expecting `key`) failed.
    pub(crate) fn watch_failed(
        &self,
        id: PeerId,
        key: Option<KeyFingerprint>,
        why: &LinkDetail,
        next: Next,
    ) {
        let changed = self
            .states
            .shared
            .table
            .lock()
            .failed(key, id, plain(why), next);
        self.states.publish(changed);
    }

    /// Peer entry `id` was removed: its dial loop decides nothing more.
    pub(crate) fn watch_forget(&self, id: PeerId) {
        self.states.shared.table.lock().forget(id);
    }

    /// What this device does about a lost link to peer `id` before its dial
    /// loop says so: it dials the peers it is told to keep, and nobody else.
    fn default_next(&self, id: Option<PeerId>) -> Next {
        let Some((id, peer)) = id.and_then(|id| Some((id, self.peers.get(id)?))) else {
            return Next::Gone;
        };
        if !self.has_path(id, &peer) {
            Next::WaitingForAddress
        } else if !peer.persistent && peer.mode == LinkMode::Always {
            Next::Gone
        } else {
            Next::Redialling {
                within: BACKOFF_FIRST,
            }
        }
    }
}

/// What a reason says of an address: nothing.
const AN_ADDRESS: &str = "an address";

/// The most characters of any one sentence or parameter a watcher is given;
/// longer ones end in `…`. Above the bound on a peer's own words
/// (`ndn_face_quic::PEER_TEXT_MAX`), which a sentence quotes with a little
/// of ours.
const WATCH_TEXT_MAX: usize = 1024;

/// `detail` as a watcher sees it: its words and facts as one line of
/// printable text each (no control or invisible characters, whatever a peer
/// put in its close text), with each address (socket address, IP address,
/// `host:port`) replaced by "an address", at most [`WATCH_TEXT_MAX`]
/// characters. A watcher sees keys, device names and plain-words reasons,
/// never where a device is.
fn plain(detail: &LinkDetail) -> LinkDetail {
    LinkDetail {
        code: detail.code.clone(),
        params: detail
            .params
            .iter()
            .map(|(k, v)| (k.clone(), watchable(v)))
            .collect(),
        text: watchable(&detail.text),
        causes: detail.causes.iter().map(plain).collect(),
    }
}

/// `text` for a watcher: cleaned first (an address with an invisible
/// character in it is still an address), then its addresses scrubbed, then
/// bounded.
fn watchable(text: &str) -> String {
    ndn_face_quic::bounded_text(
        &without_addresses(&ndn_face_quic::clean_text(text)),
        WATCH_TEXT_MAX,
    )
}

fn without_addresses(text: &str) -> String {
    text.split(' ')
        .map(|word| {
            let core = word.trim_matches(|c| matches!(c, '(' | ')' | ',' | ';' | '\'' | '"'));
            let core = core.trim_end_matches([':', '.']);
            if is_address(core) {
                word.replacen(core, AN_ADDRESS, 1)
            } else {
                word.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn is_address(word: &str) -> bool {
    if word.parse::<std::net::SocketAddr>().is_ok() || word.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    // host:port
    word.rsplit_once(':').is_some_and(|(host, port)| {
        !host.is_empty()
            && host.chars().any(|c| c.is_ascii_alphabetic() || c == '.')
            && (1..=5).contains(&port.len())
            && port.bytes().all(|b| b.is_ascii_digit())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_mgmt_wire::link_code as code;

    fn key(n: u8) -> KeyFingerprint {
        KeyFingerprint([n; 32])
    }

    fn why(text: &str) -> LinkDetail {
        LinkDetail::new(code::LINK_CLOSED_BY_PEER, text)
    }

    fn redial() -> Next {
        Next::Redialling {
            within: BACKOFF_FIRST,
        }
    }

    fn is_up(link: &PeerLink) -> bool {
        matches!(link.state, LinkState::Up { .. })
    }

    fn up(t: &mut StateTable, n: u8) -> bool {
        t.up(key(n), None, None, Direction::Dialed, PathKind::Link)
    }

    fn down(t: &mut StateTable, n: u8, next: Next) -> bool {
        t.down(key(n), None, None, Direction::Dialed, why("closed"), next)
    }

    #[test]
    fn a_peer_that_flapped_between_two_looks_is_one_entry_the_newest() {
        let mut t = StateTable::new(8);
        assert!(up(&mut t, 1));
        let cursor = t.version;
        for _ in 0..50 {
            assert!(down(&mut t, 1, redial()));
            assert!(up(&mut t, 1));
        }
        assert!(down(&mut t, 1, redial()));
        assert!(up(&mut t, 1));
        let changed = t.since(cursor);
        assert_eq!(changed.len(), 1, "one entry per peer");
        assert!(is_up(&changed[0]), "the newest state: {changed:?}");
        assert_eq!(t.entries.len(), 1);
    }

    #[test]
    fn a_cursor_sees_only_what_changed_after_it_oldest_first() {
        let mut t = StateTable::new(8);
        up(&mut t, 1);
        up(&mut t, 2);
        let cursor = t.version;
        assert!(t.since(cursor).is_empty());
        up(&mut t, 3);
        down(&mut t, 1, Next::Gone);
        let keys: Vec<_> = t.since(cursor).iter().map(|l| l.key).collect();
        assert_eq!(keys, vec![key(3), key(1)]);
        assert_eq!(t.all().len(), 3);
    }

    #[test]
    fn the_same_state_again_changes_nothing() {
        let mut t = StateTable::new(8);
        assert!(down(&mut t, 1, redial()));
        let version = t.version;
        assert!(!down(&mut t, 1, redial()), "same state, same reason");
        assert_eq!(t.version, version);
    }

    #[test]
    fn the_table_stays_within_its_bound_and_gives_up_gone_then_down_then_up() {
        let mut t = StateTable::new(LINK_STATES_MAX);
        // Peers 0..255 up; then 10 and 20 go down (redialled), and 40, then
        // 30, go gone.
        let keys: Vec<KeyFingerprint> = (0..LINK_STATES_MAX).map(key_of).collect();
        for k in &keys {
            t.up(*k, None, None, Direction::Dialed, PathKind::Link);
        }
        for (i, next) in [
            (10, redial()),
            (20, redial()),
            (40, Next::Gone),
            (30, Next::Gone),
        ] {
            t.down(
                keys[i],
                None,
                None,
                Direction::Accepted,
                why("closed"),
                next,
            );
        }
        assert_eq!(t.entries.len(), LINK_STATES_MAX);
        // 40 went `Gone` before 30 did: 40 is the longest unchanged of them.
        t.up(key_of(1000), None, None, Direction::Dialed, PathKind::Link);
        assert_eq!(t.entries.len(), LINK_STATES_MAX);
        assert!(!t.entries.contains_key(&keys[40]), "gone, oldest, first");
        t.up(key_of(1001), None, None, Direction::Dialed, PathKind::Link);
        assert!(!t.entries.contains_key(&keys[30]), "then the other gone");
        t.up(key_of(1002), None, None, Direction::Dialed, PathKind::Link);
        assert!(!t.entries.contains_key(&keys[10]), "then down, oldest");
        t.up(key_of(1003), None, None, Direction::Dialed, PathKind::Link);
        assert!(!t.entries.contains_key(&keys[20]));
        // Only up ones are left to give up: the longest unchanged.
        t.up(key_of(1004), None, None, Direction::Dialed, PathKind::Link);
        assert!(!t.entries.contains_key(&keys[0]));
        assert!(t.entries.contains_key(&keys[1]));
        assert_eq!(t.entries.len(), LINK_STATES_MAX);
        // Many more peers than the bound never grow it.
        for n in 2000..2000 + 5 * LINK_STATES_MAX {
            t.up(key_of(n), None, None, Direction::Accepted, PathKind::Link);
            assert!(t.entries.len() <= LINK_STATES_MAX);
        }
    }

    fn key_of(n: usize) -> KeyFingerprint {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&(n as u64).to_be_bytes());
        KeyFingerprint(bytes)
    }

    #[test]
    fn a_direct_path_joining_a_link_that_is_up_changes_nothing() {
        let mut t = StateTable::new(8);
        assert!(up(&mut t, 1));
        let version = t.version;
        assert!(!t.up(key(1), None, None, Direction::Accepted, PathKind::Direct));
        assert_eq!(t.version, version);
        // But a direct path that is the only one makes the peer up.
        assert!(t.up(key(2), None, None, Direction::Dialed, PathKind::Direct));
    }

    #[test]
    fn what_the_dial_loop_decides_reaches_a_link_that_ended_before_or_after() {
        let mut t = StateTable::new(8);
        let peer = PeerId(3);
        // The loop decides first, the link ends after: the decision stands.
        t.up(key(1), None, Some(peer), Direction::Dialed, PathKind::Link);
        assert!(!t.decide(peer, Next::Gone), "nothing is down yet");
        t.down(
            key(1),
            None,
            Some(peer),
            Direction::Dialed,
            why("closed"),
            redial(),
        );
        assert!(matches!(
            t.entries[&key(1)].link.state,
            LinkState::Down {
                next: Next::Gone,
                ..
            }
        ));
        // The link ends first, the loop decides after: the entry is told.
        t.up(key(1), None, Some(peer), Direction::Dialed, PathKind::Link);
        t.down(
            key(1),
            None,
            Some(peer),
            Direction::Dialed,
            why("closed"),
            redial(),
        );
        assert!(t.decide(peer, Next::WhenWanted));
        assert!(matches!(
            t.entries[&key(1)].link.state,
            LinkState::Down {
                next: Next::WhenWanted,
                ..
            }
        ));
    }

    #[test]
    fn a_failed_dial_is_a_down_state_of_the_key_and_never_hides_a_link_that_is_up() {
        let mut t = StateTable::new(8);
        let peer = PeerId(1);
        assert!(t.failed(Some(key(1)), peer, why("refused"), redial()));
        let LinkState::Down { direction, .. } = &t.entries[&key(1)].link.state else {
            panic!("down");
        };
        assert_eq!(*direction, None, "no link was ever up");
        // A peer with no key and none shown yet has nothing to show.
        assert!(!t.failed(None, PeerId(2), why("refused"), redial()));
        assert!(t.entries.len() == 1);
        // It is up now: a late failure of an older dial does not hide that.
        t.up(
            key(1),
            None,
            Some(peer),
            Direction::Accepted,
            PathKind::Link,
        );
        assert!(!t.failed(Some(key(1)), peer, why("refused"), redial()));
        assert!(is_up(&t.entries[&key(1)].link));
    }

    #[test]
    fn the_device_name_is_kept_once_known() {
        let mut t = StateTable::new(8);
        let name: Name = "/ns/member/d1".parse().unwrap();
        t.up(
            key(1),
            Some(name.clone()),
            None,
            Direction::Dialed,
            PathKind::Link,
        );
        down(&mut t, 1, Next::Gone);
        assert_eq!(t.entries[&key(1)].link.device, Some(name));
    }

    /// A watcher that never reads holds a cursor over the table: its size is
    /// fixed, whatever happens to the links, and the table behind it is as
    /// small as the peers are many.
    #[tokio::test]
    async fn a_watcher_that_never_reads_costs_no_memory() {
        let states = LinkStates::default();
        let mut watch = LinkWatch {
            shared: Arc::clone(&states.shared),
            cancel: CancellationToken::new(),
            cursor: None,
        };
        assert!(
            size_of::<LinkWatch>() <= 4 * size_of::<usize>(),
            "a watcher is a handle and a cursor, not a queue"
        );
        {
            let mut t = states.shared.table.lock();
            for _ in 0..100_000 {
                up(&mut t, 1);
                down(&mut t, 1, redial());
            }
        }
        states.publish(true);
        assert_eq!(states.shared.table.lock().entries.len(), 1);
        let first = watch.changed().await.unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(watch.current().len(), 1);
    }

    #[tokio::test]
    async fn the_first_look_is_the_table_now_and_later_ones_wait_for_a_change() {
        let states = LinkStates::default();
        {
            let mut t = states.shared.table.lock();
            up(&mut t, 1);
            up(&mut t, 2);
        }
        let mut late = LinkWatch {
            shared: Arc::clone(&states.shared),
            cancel: CancellationToken::new(),
            cursor: None,
        };
        assert_eq!(late.changed().await.unwrap().len(), 2, "state first");
        let waiting = tokio::time::timeout(Duration::from_millis(100), late.changed()).await;
        assert!(waiting.is_err(), "nothing changed: it waits");
        let shared = Arc::clone(&states.shared);
        let reader = tokio::spawn(async move {
            let mut late = late;
            late.changed().await
        });
        tokio::task::yield_now().await;
        {
            let mut t = shared.table.lock();
            down(&mut t, 2, Next::Gone);
        }
        states.publish(true);
        let got = reader.await.unwrap().unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].key, key(2));
        // The links ending ends the watcher.
        let mut ending = LinkWatch {
            shared: Arc::clone(&states.shared),
            cancel: CancellationToken::new(),
            cursor: Some(shared.table.lock().version),
        };
        drop(states);
        assert!(ending.changed().await.is_none());
    }

    #[tokio::test]
    async fn observers_run_inline_for_each_event() {
        let states = LinkStates::default();
        let seen = Arc::new(Mutex::new(0usize));
        let count = Arc::clone(&seen);
        states
            .observers
            .lock()
            .push(Arc::new(move |_: &LinkEvent| *count.lock() += 1));
        states.emit(&LinkEvent::Down {
            key: key(1),
            why: why("closed"),
        });
        assert_eq!(*seen.lock(), 1);
    }

    #[test]
    fn a_reason_names_no_address() {
        let cause = LinkDetail::new(
            code::DIAL_FAILED,
            "no answer from 127.0.0.1:4000 within 5 s (is the device running?)",
        )
        .with(
            "error",
            "cannot resolve relay.example.org:6363: refused, try [::1]:6363.",
        );
        let detail = LinkDetail::new(
            code::DIAL_FAILED,
            "its last dial failed: no answer from 127.0.0.1:4000 within 5 s (is the device running?)",
        )
        .with("addr", "192.0.2.7")
        .caused_by(cause);
        let plain = plain(&detail);
        let all = format!("{plain:?}");
        for forbidden in [
            "127.0.0.1",
            "4000",
            "192.0.2.7",
            "example.org",
            "6363",
            "::1",
        ] {
            assert!(!all.contains(forbidden), "{forbidden} left in {all}");
        }
        assert!(
            plain
                .text
                .contains("no answer from an address within 5 s (is the device running?)")
        );
        assert!(
            plain.causes[0]
                .text
                .starts_with("no answer from an address")
        );
        assert_eq!(plain.code, code::DIAL_FAILED);
        // Words stay words.
        let said = "the other device closed the link: it is shutting down; it links again (0.5 s)";
        assert_eq!(without_addresses(said), said);
    }

    /// A watcher shows what it is given to a person: whatever a hostile
    /// device put in its close text, a status carries one bounded line of
    /// printable words, with the address it quotes still scrubbed.
    #[test]
    fn a_peer_close_text_is_one_bounded_line_of_printable_words() {
        let hostile = format!(
            "pay now\n2026-01-01 INFO forged line \x1b[2J\x1b[31m\u{202E}reversed\u{200B} at 203.0.113.9\u{200B}:6363 {}",
            "persuade ".repeat(1000)
        );
        let error = LinkError::Refused {
            reason: Some(ndn_face_quic::CloseReason::Revoked),
            text: hostile.clone(),
        };
        let detail = link_error_detail(&error).caused_by(LinkDetail::new(
            code::DIAL_FAILED,
            format!("it said: {hostile}"),
        ));
        let plain = plain(&detail);
        let mut texts = vec![
            plain.text.clone(),
            plain.causes[0].text.clone(),
            plain
                .params
                .iter()
                .find(|(k, _)| k.as_str() == "text")
                .expect("the peer's text is a parameter")
                .1
                .clone(),
        ];
        texts.extend(plain.params.values().cloned());
        for text in texts {
            assert!(
                !text.chars().any(|c| c.is_control()
                    || matches!(c, '\u{202E}' | '\u{200B}' | '\u{2066}'..='\u{2069}')),
                "control or invisible characters reached the watcher: {text:?}"
            );
            assert!(
                text.chars().count() <= WATCH_TEXT_MAX,
                "{} characters",
                text.chars().count()
            );
            assert!(
                !text.contains("203.0.113.9") && !text.contains("6363"),
                "{text:?}"
            );
        }
        assert!(plain.text.contains("pay now 2026-01-01 INFO forged line"));
        assert!(plain.text.contains("an address"), "{}", plain.text);
    }
}
