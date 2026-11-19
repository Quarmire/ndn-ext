//! Memory of linked peers across restarts (`ndn-rs/docs/specs/ndn-link.md`
//! §17C): what a device learned of the peers it links with — their key, their
//! device, the addresses that worked — kept in a store the host gives
//! ([`LinkMemory`]), read at start, written behind, and used to dial them
//! again without a peer entry, a relay or a list the host keeps.
//!
//! The rules this module keeps, in the spec's words:
//!
//! 1. The key is authenticated and the address is a hint: a record is made
//!    only for a link admitted by an identity validated in a held namespace;
//!    a redial uses the handshake that accepts only the holder of the key.
//! 2. Peers are redialled in the background, with the [`Backoff`] of
//!    [`MemoryOptions`]; a peer with no address waits for a new one.
//! 3. A peer is not dialled when no held context admits it
//!    ([`not_redialled`]).
//! 4. A remembered peer is never admitted by its key alone
//!    (`PeerSpec::remembered`, enforced in `decide_identified`).
//! 5. Bounds and expiry are [`MemoryOptions`]; [`Links::forget`] is how a
//!    host says a member left.
//! 6. A record is saved in the background once its addresses changed, each
//!    at most once in [`MemoryOptions::save_interval`]; nothing waits on the
//!    store, and a store that fails is logged and reported by
//!    [`Links::report`].
//! 7. The addresses are hints with a bound on what they can do: loopback
//!    and link-local ones are not kept or dialled
//!    ([`MemoryOptions::include_local`]), the redials are staggered
//!    ([`MemoryOptions::dials_at_once`]), and an accepted link's source
//!    address never replaces one this device dialled.
//!
//! The logic (the [`Book`], the decision of rule 3) knows nothing of
//! QUIC; the loops that dial are at the end.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant, SystemTime};

use ndn_face_quic::{Direction, KeyFingerprint};
use ndn_mgmt_wire::{LinkDetail, link_code as code};
use ndn_packet::Name;
use parking_lot::Mutex;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use crate::links::Links;
use crate::peer::{LinkMode, PeerId, PeerSpec};
use crate::policy::{Backoff, MESSAGE_DEADLINE};
use crate::status::PathKind;
use crate::watch::{LinkEvent, Next};

/// The future a [`LinkMemory`] returns.
pub type MemoryFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// What a host gives [`Links::remember`] to keep what it learned of peers:
/// read once at start, written behind the host's durability barrier. A store
/// holds each peer's key (public), its device name and, unless
/// [`MemoryOptions::persist_addresses`] is off, the addresses it was last
/// reached at, **in the clear**: none of it is a secret, and nothing it holds
/// admits anyone (§17C), but it says who this device talks to and where, so
/// the permissions of the file or database it lives in are the host's to set
/// (readable by this device's user only).
pub trait LinkMemory: Send + Sync {
    /// Every record kept. A record the store cannot read is the store's to
    /// leave out; the error is for a store that cannot be read at all.
    fn load(&self) -> Result<Vec<PeerRecord>, String>;
    /// Keep `record`, replacing the one of its key; returns once the store
    /// made it durable.
    fn save<'a>(&'a self, record: &'a PeerRecord) -> MemoryFuture<'a, Result<(), String>>;
    /// Remove the record of `key`, if any; returns once the store made the
    /// removal durable.
    fn remove<'a>(&'a self, key: &'a KeyFingerprint) -> MemoryFuture<'a, Result<(), String>>;
    /// The port this device listened on when it last stopped, if the store
    /// kept one (§17D.2): `None` when none was kept. The error is for a store
    /// that cannot be read at all. **Required**: a store that cannot keep a
    /// port says so here, by an error, and its host knows the port is not
    /// remembered.
    fn load_listen_port(&self) -> Result<Option<u16>, String>;
    /// Keep `port` as the port this device listens on (`None`: keep none,
    /// and remove the one kept); returns once the store made it durable. Not
    /// called with a port when [`MemoryOptions::persist_addresses`] is off:
    /// then only `None`, which removes one a run before it wrote.
    fn save_listen_port<'a>(&'a self, port: Option<u16>) -> MemoryFuture<'a, Result<(), String>>;
}

/// What is remembered of a peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerRecord {
    /// The key the peer proves in the handshake: what a redial pins.
    pub key: KeyFingerprint,
    /// The device the peer proved to be, in a namespace this device held.
    pub device: Name,
    /// Where the peer was reached, most recent first, at most
    /// [`MemoryOptions::addresses_max`]: hints, trusted for nothing.
    pub addresses: Vec<SocketAddr>,
    /// The last time the peer was linked.
    pub last_contact: SystemTime,
    /// Who first made the link: this device dialled the peer, or the peer
    /// dialled in. Kept as it was at the first contact.
    pub origin: Direction,
    /// The listening port the peer last linked from or was dialled at (a
    /// device that listens dials from its link socket, §13.1), the last
    /// contact's: where to try an address a contact reports without a port
    /// that works (§17D.2). A hint, trusted for nothing; not kept (like the
    /// addresses) under [`MemoryOptions::persist_addresses`] off.
    pub port: Option<u16>,
}

/// What [`Links::remember`] keeps, and for how long.
#[derive(Clone, Debug)]
pub struct MemoryOptions {
    /// Peers kept at most: one more evicts the one least recently in contact.
    pub peers_max: usize,
    /// Addresses kept per peer: a redial makes at most this many dials per
    /// attempt.
    pub addresses_max: usize,
    /// A peer not in contact for this long is forgotten (at the next prune).
    pub expires: Duration,
    /// When a redial is made again. The standing dial backoff by default.
    pub redial: Backoff,
    /// Peers redialled at the same time, each racing at most `addresses_max`
    /// addresses: a start-up with many records dials them a few at a time,
    /// not all at once. 4 by default (at most 16 handshakes at once).
    pub dials_at_once: usize,
    /// Keep and dial loopback and link-local addresses, which reach only
    /// this machine or this link. Off by default, as for the addresses of a
    /// code (data-layer.md §19.2): what a store or a stranger's link names
    /// must not make this device send datagrams to services on itself or on
    /// its link (169.254.169.254, say). A host that links devices on one
    /// machine, or one link, turns it on.
    pub include_local: bool,
    /// Write the addresses to the store. On by default; off, a record is
    /// written without them (the store then holds only each peer's key and
    /// device name, and its last contact) and the addresses a run learns
    /// live in memory for that run: a peer is redialled in the run that
    /// learned its address, and after a restart waits for its next contact.
    pub persist_addresses: bool,
    /// A record is written to the store at most once in this long. What
    /// changes in between is kept in memory and written when the time is
    /// up, or at [`Links::shutdown`]: a peer that reconnects again and again
    /// is a few writes (flash wear, an fsync each), not one per reconnect.
    /// One minute by default; the first write of a record is not delayed.
    pub save_interval: Duration,
}

impl Default for MemoryOptions {
    fn default() -> Self {
        Self {
            peers_max: 64,
            addresses_max: 4,
            expires: Duration::from_secs(30 * 24 * 3600),
            redial: Backoff::default(),
            dials_at_once: 4,
            include_local: false,
            persist_addresses: true,
            save_interval: Duration::from_secs(60),
        }
    }
}

impl MemoryOptions {
    fn addresses(&self) -> usize {
        self.addresses_max.max(1)
    }

    fn peers(&self) -> usize {
        self.peers_max.max(1)
    }

    fn dials(&self) -> usize {
        self.dials_at_once.max(1)
    }
}

/// An address worth dialling: not unspecified, multicast or broadcast, with a
/// port, and, unless `include_local`, not a loopback or link-local one (the
/// rule the hint of a code has, data-layer.md §19.2).
fn usable(addr: &SocketAddr, include_local: bool) -> bool {
    let ip = addr.ip().to_canonical();
    addr.port() != 0
        && !ip.is_unspecified()
        && !ip.is_multicast()
        && !matches!(ip, std::net::IpAddr::V4(v4) if v4.is_broadcast())
        && (include_local || !crate::candidates::is_local(ip))
}

/// `addr` as a dial uses it: an IPv4 address a dual-stack socket shows
/// mapped is the IPv4 address.
fn canonical(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}

// ---- the book: records, bounds, expiry -------------------------------------------------------

/// A record and what the store holds of it.
struct Slot {
    record: PeerRecord,
    /// The `last_contact` the store holds: a contact is saved again only
    /// when it moved the addresses, or the store's is a quarter of
    /// `expires` behind (so a peer in contact does not expire, and the store
    /// is not written at every link).
    persisted: SystemTime,
}

/// What a contact changed, for the store.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Learned {
    /// The record is to be saved.
    pub(crate) save: bool,
    /// A new record took the place of this one, the least recently in
    /// contact.
    pub(crate) evicted: Option<KeyFingerprint>,
}

/// The records in memory: the bounds and the expiry, with no I/O.
pub(crate) struct Book {
    options: MemoryOptions,
    slots: HashMap<KeyFingerprint, Slot>,
}

impl Book {
    /// The book of `records` as the store gave them at `now`: the newest
    /// record of each key, the addresses cleaned (those a dial would not use
    /// dropped, and with `persist_addresses` off all of them) and cut to the
    /// bound, those not in contact for `expires` dropped, and no more than
    /// `peers_max` kept (the least recently in contact dropped). The second
    /// value is the keys the store holds records of that are not kept.
    pub(crate) fn load(
        options: MemoryOptions,
        records: Vec<PeerRecord>,
        now: SystemTime,
    ) -> (Self, Vec<KeyFingerprint>) {
        let mut newest: HashMap<KeyFingerprint, PeerRecord> = HashMap::new();
        for mut record in records {
            let mut seen = HashSet::new();
            record.addresses = record
                .addresses
                .iter()
                .map(|a| canonical(*a))
                .filter(|a| {
                    options.persist_addresses && usable(a, options.include_local) && seen.insert(*a)
                })
                .take(options.addresses())
                .collect();
            if !options.persist_addresses {
                record.port = None;
            }
            match newest.get(&record.key) {
                Some(other) if other.last_contact >= record.last_contact => {}
                _ => {
                    newest.insert(record.key, record);
                }
            }
        }
        let mut book = Self {
            options,
            slots: HashMap::new(),
        };
        let mut dropped = Vec::new();
        let mut kept: Vec<PeerRecord> = newest.into_values().collect();
        kept.sort_by(|a, b| b.last_contact.cmp(&a.last_contact).then(a.key.cmp(&b.key)));
        for record in kept {
            if book.expired(&record, now) || book.slots.len() >= book.options.peers() {
                dropped.push(record.key);
                continue;
            }
            book.slots.insert(
                record.key,
                Slot {
                    persisted: record.last_contact,
                    record,
                },
            );
        }
        (book, dropped)
    }

    fn expired(&self, record: &PeerRecord, now: SystemTime) -> bool {
        now.duration_since(record.last_contact)
            .is_ok_and(|age| age >= self.options.expires)
    }

    pub(crate) fn get(&self, key: &KeyFingerprint) -> Option<&PeerRecord> {
        self.slots.get(key).map(|s| &s.record)
    }

    pub(crate) fn records(&self) -> Vec<PeerRecord> {
        let mut records: Vec<PeerRecord> = self.slots.values().map(|s| s.record.clone()).collect();
        records.sort_by(|a, b| b.last_contact.cmp(&a.last_contact).then(a.key.cmp(&b.key)));
        records
    }

    /// The peer `key`, reached at `addr` by a link `direction` made, at
    /// `now`. An address a dial would use ([`usable`]) moves to the front
    /// of the list; a new peer past `peers_max` evicts the one least
    /// recently in contact. The device the peer proved replaces the one
    /// remembered; the record's `origin` is the direction of the first
    /// contact.
    ///
    /// The address of a link the peer opened is its source address: the
    /// port is the peer's own choice and changes at every reconnect of a
    /// device that dials from a socket of its own. It is kept only for a
    /// peer that has no address yet (it is then the one to try, and what a
    /// peer that listens and dials from its listening socket has), and never
    /// moves or adds to a list that holds one. The addresses a peer is
    /// reached at are those this device dialled.
    pub(crate) fn learn(
        &mut self,
        key: KeyFingerprint,
        device: Name,
        addr: SocketAddr,
        direction: Direction,
        now: SystemTime,
    ) -> Learned {
        let addr = canonical(addr);
        let keep = self.options.addresses();
        let local = self.options.include_local;
        let persists = self.options.persist_addresses;
        if let Some(slot) = self.slots.get_mut(&key) {
            let record = &mut slot.record;
            let mut changed = false;
            if record.device != device {
                record.device = device;
                changed = true;
            }
            if usable(&addr, local)
                && (direction == Direction::Dialed || record.addresses.is_empty())
                && record.addresses.first() != Some(&addr)
            {
                record.addresses.retain(|a| *a != addr);
                record.addresses.insert(0, addr);
                record.addresses.truncate(keep);
                // With the addresses not persisted, the store holds none to
                // bring up to date.
                changed |= persists;
            }
            // The port of a link this device dialled is the peer's listening
            // port; the source port of one the peer opened is its own choice
            // (it changes at every reconnect of a device that dials from a
            // socket of its own), so it only fills a port not known yet.
            if usable(&addr, local)
                && (direction == Direction::Dialed || record.port.is_none())
                && record.port != Some(addr.port())
            {
                record.port = Some(addr.port());
                // Not persisted either with the addresses off.
                changed |= persists;
            }
            record.last_contact = record.last_contact.max(now);
            let behind =
                now.duration_since(slot.persisted).unwrap_or_default() >= self.options.expires / 4;
            if changed || behind {
                slot.persisted = record.last_contact;
            }
            return Learned {
                save: changed || behind,
                evicted: None,
            };
        }
        let mut evicted = None;
        if self.slots.len() >= self.options.peers() {
            evicted = self
                .slots
                .values()
                .min_by(|a, b| {
                    a.record
                        .last_contact
                        .cmp(&b.record.last_contact)
                        .then(a.record.key.cmp(&b.record.key))
                })
                .map(|s| s.record.key);
            if let Some(victim) = evicted {
                self.slots.remove(&victim);
            }
        }
        self.slots.insert(
            key,
            Slot {
                record: PeerRecord {
                    key,
                    device,
                    addresses: if usable(&addr, local) {
                        vec![addr]
                    } else {
                        Vec::new()
                    },
                    last_contact: now,
                    origin: direction,
                    port: usable(&addr, local).then_some(addr.port()),
                },
                persisted: now,
            },
        );
        Learned {
            save: true,
            evicted,
        }
    }

    /// The peer `key` is in contact at `now` (its link is up, or just
    /// ended); whether the record is to be saved again.
    pub(crate) fn touch(&mut self, key: &KeyFingerprint, now: SystemTime) -> bool {
        let Some(slot) = self.slots.get_mut(key) else {
            return false;
        };
        slot.record.last_contact = slot.record.last_contact.max(now);
        let behind =
            now.duration_since(slot.persisted).unwrap_or_default() >= self.options.expires / 4;
        if behind {
            slot.persisted = slot.record.last_contact;
        }
        behind
    }

    /// The peer `key` was reached over a direct path whose far end is the
    /// port `port` (its link socket's, §14): that is its listening port.
    /// Whether the record is to be saved again (the port changed, and the
    /// store keeps it).
    pub(crate) fn set_port(&mut self, key: &KeyFingerprint, port: u16) -> bool {
        let persists = self.options.persist_addresses;
        let Some(slot) = self.slots.get_mut(key) else {
            return false;
        };
        if port == 0 || slot.record.port == Some(port) {
            return false;
        }
        slot.record.port = Some(port);
        if persists {
            slot.persisted = slot.record.last_contact;
        }
        persists
    }

    /// Mark the record of `key` as saved as it is now.
    pub(crate) fn persisted(&mut self, key: &KeyFingerprint) {
        if let Some(slot) = self.slots.get_mut(key) {
            slot.persisted = slot.record.last_contact;
        }
    }

    pub(crate) fn remove(&mut self, key: &KeyFingerprint) -> bool {
        self.slots.remove(key).is_some()
    }

    /// The records not in contact for `expires` at `now`.
    pub(crate) fn expired_keys(&self, now: SystemTime) -> Vec<KeyFingerprint> {
        self.slots
            .values()
            .filter(|s| self.expired(&s.record, now))
            .map(|s| s.record.key)
            .collect()
    }
}

// ---- rule 3: which remembered peers are dialled ----------------------------------------------

/// What a device knows when it decides whether a remembered peer may be
/// dialled (and so remembered): its trust contexts, its certificates and its
/// grants.
pub(crate) trait Standing {
    /// A trust context of the namespace governing `device` is held here.
    fn holds_namespace_of(&self, device: &Name) -> bool;
    /// This device holds a certificate in the namespace governing `device`:
    /// its serving policy `own` serves the device's links.
    fn is_in_namespace_of(&self, device: &Name) -> bool;
    /// A live grant covers `key` (a person this device introduced).
    fn granted(&self, key: &KeyFingerprint) -> bool;
}

/// Why the remembered peer `device` (key `key`, first linked as `origin`) is
/// not dialled now, in words that say what to do; `None` when it may be:
/// its device is under a namespace this device holds, and it is a peer this
/// device dialled itself, a device of a namespace this device is in, or a
/// person a live grant covers (§17C.2, rule 3). A record this refuses is not
/// dialled and not admitted, and is dropped at expiry.
pub(crate) fn not_redialled(
    standing: &dyn Standing,
    key: &KeyFingerprint,
    device: &Name,
    origin: Direction,
) -> Option<String> {
    if !standing.holds_namespace_of(device) {
        return Some(format!(
            "{device} is of a namespace whose trust context this device does not hold, so it is \
             not dialled and would not be admitted; adopt that namespace again to link with it, \
             or forget its key {key}"
        ));
    }
    match origin {
        Direction::Dialed => None,
        Direction::Accepted if standing.is_in_namespace_of(device) || standing.granted(key) => None,
        Direction::Accepted => Some(format!(
            "{device} linked in to this device, and this device holds no certificate in its \
             namespace and no live grant covers its key {key}; it is dialled again once an \
             introduction grants it a link"
        )),
    }
}

// ---- the report ------------------------------------------------------------------------------

/// What the link memory holds and does, for [`Links::report`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MemoryReport {
    /// The peers remembered, most recently in contact first.
    pub peers: Vec<RememberedPeer>,
    /// Why the store last failed (read, write or remove), in words; `None`
    /// when its last use worked. The links work without it.
    pub store_error: Option<String>,
}

/// One remembered peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RememberedPeer {
    pub record: PeerRecord,
    pub state: RememberedState,
}

/// What this device does about a remembered peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RememberedState {
    /// Linked now.
    Linked,
    /// Dialling it now.
    Dialling,
    /// The last dial failed; the next is within this long.
    Redialling { within: Duration },
    /// It has no address: it waits for one (the peer links in, or a relay
    /// reports it).
    WaitingForAddress,
    /// No held context admits it: not dialled, and `why`.
    NotDialled { why: String },
    /// Every address kept for it failed (it may have restarted on another
    /// port), and no relay both devices use is linked: this device cannot
    /// reach it now, and it reaches this device when it dials this device's
    /// current address, or when both link to a relay. A statement, not a
    /// retry loop: the redial backoff is unchanged.
    NoPath { why: String },
    /// This device is offline ([`Links::set_online`]): no dial is made.
    Offline,
}

// ---- the memory ------------------------------------------------------------------------------

/// How long a redial waits for its handshakes.
const DIAL_WITHIN: Duration = MESSAGE_DEADLINE;

/// How long a peer that cannot be dialled is looked at again: what changes
/// that (a trust context adopted, a grant made) wakes it at once; this is
/// for what has no hook.
const RECHECK: Duration = Duration::from_secs(30);

/// IP addresses a contact reported for a peer that a redial tries at the
/// peer's last-known port, besides the addresses that worked: the bound on
/// what a stranger's source address can make this device dial.
const REPORTED_MAX: usize = 2;

/// A redial loop's handle.
struct Redial {
    wake: Arc<Notify>,
    /// Skip the rest of the current wait: this device is back online, or its
    /// addresses changed (§17D).
    kick: Arc<Notify>,
    stop: CancellationToken,
    state: Arc<Mutex<RememberedState>>,
}

struct Inner {
    book: Book,
    redials: HashMap<KeyFingerprint, Redial>,
    /// Records to save, as they are when the writer gets to them.
    dirty: HashSet<KeyFingerprint>,
    /// Keys to remove from the store.
    doomed: HashSet<KeyFingerprint>,
    /// When each record was last written: a record is written again only
    /// once `save_interval` has passed.
    saved_at: HashMap<KeyFingerprint, Instant>,
    /// The listening port the writer owes the store: `Some(None)` removes
    /// the one it holds.
    port_owed: Option<Option<u16>>,
    /// IP addresses contacts reported for peers that this run has not
    /// dialled at yet, newest first, at most [`REPORTED_MAX`] each: dialled
    /// at the peer's last-known port beside its kept addresses (§17D.2). Not
    /// kept in the store.
    reported: HashMap<KeyFingerprint, Vec<std::net::IpAddr>>,
}

impl Inner {
    /// A contact reported `ip` for the peer `key` (it linked in from there,
    /// or a direct path reached it there): kept, newest first and bounded,
    /// when no address kept for the peer is at that IP already, and when a
    /// dial would use it ([`usable`]).
    fn report(&mut self, key: KeyFingerprint, ip: std::net::IpAddr, include_local: bool) {
        let ip = ip.to_canonical();
        if !usable(&SocketAddr::new(ip, 1), include_local) {
            return;
        }
        if self
            .book
            .get(&key)
            .is_some_and(|r| r.addresses.iter().any(|a| a.ip().to_canonical() == ip))
        {
            return;
        }
        let ips = self.reported.entry(key).or_default();
        ips.retain(|known| *known != ip);
        ips.insert(0, ip);
        ips.truncate(REPORTED_MAX);
    }
}

/// The link memory of one [`Links`].
pub(crate) struct Memory {
    store: Arc<dyn LinkMemory>,
    options: MemoryOptions,
    links: Weak<Links>,
    inner: Mutex<Inner>,
    /// One store operation at a time: a save never lands after the removal
    /// that follows it.
    io: tokio::sync::Mutex<()>,
    write_wake: Notify,
    failure: Mutex<Option<String>>,
    cancel: CancellationToken,
    /// How many peers are dialled at once (`MemoryOptions::dials_at_once`).
    dials: Arc<tokio::sync::Semaphore>,
}

impl Memory {
    /// The memory over `store` for `links`.
    fn start(
        links: &Arc<Links>,
        store: Arc<dyn LinkMemory>,
        options: MemoryOptions,
    ) -> Arc<Memory> {
        let on = Arc::clone(links);
        Memory::open(
            Arc::downgrade(links),
            links.cancel_token().child_token(),
            store,
            options,
            move |kept| on.settle_listen_port(kept),
        )
    }

    /// The memory over `store`: loaded, pruned, its writer and the loops of
    /// the records it holds started. A store that cannot be read is said in
    /// the log and in the report; the links work without it. Everything
    /// stops at `cancel`.
    fn open(
        links: Weak<Links>,
        cancel: CancellationToken,
        store: Arc<dyn LinkMemory>,
        options: MemoryOptions,
        bind: impl FnOnce(Option<u16>) -> Option<u16>,
    ) -> Arc<Memory> {
        let now = SystemTime::now();
        let (records, failure) = match store.load() {
            Ok(records) => (records, None),
            Err(e) => {
                let words = format!(
                    "the link memory could not be read ({e}): peers are remembered from now on, \
                     but none from before; check the store it is kept in"
                );
                tracing::warn!(target: "face.quic", "{words}");
                (Vec::new(), Some(words))
            }
        };
        // The addresses a store holds that this run will not keep (it does not
        // persist them) are written out of it.
        let mut failure = failure;
        let (kept_port, scrub_port) = match store.load_listen_port() {
            Ok(port) => (
                port.filter(|_| options.persist_addresses),
                port.is_some() && !options.persist_addresses,
            ),
            Err(e) => {
                let words = format!(
                    "the link memory could not read the listening port ({e}): this device keeps \
                     the port its host gave it, and writes it again once the store works"
                );
                tracing::warn!(target: "face.quic", "{words}");
                failure.get_or_insert(words);
                (None, false)
            }
        };
        // The listening socket takes the kept port again before any loop dials
        // from it; the port it listens on now is owed the store when it is
        // not the one kept.
        let listening = bind(kept_port);
        let port_owed = if scrub_port {
            Some(None)
        } else if options.persist_addresses && listening.is_some() && listening != kept_port {
            Some(listening)
        } else {
            None
        };
        let scrub: Vec<KeyFingerprint> = if options.persist_addresses {
            Vec::new()
        } else {
            records
                .iter()
                .filter(|r| !r.addresses.is_empty() || r.port.is_some())
                .map(|r| r.key)
                .collect()
        };
        let dials = options.dials();
        let (book, dropped) = Book::load(options.clone(), records, now);
        let dirty: HashSet<KeyFingerprint> = scrub
            .into_iter()
            .filter(|k| book.get(k).is_some())
            .collect();
        let memory = Arc::new(Memory {
            store,
            options,
            links,
            inner: Mutex::new(Inner {
                book,
                redials: HashMap::new(),
                dirty,
                doomed: dropped.into_iter().collect(),
                saved_at: HashMap::new(),
                port_owed,
                reported: HashMap::new(),
            }),
            io: tokio::sync::Mutex::new(()),
            write_wake: Notify::new(),
            failure: Mutex::new(failure),
            cancel,
            dials: Arc::new(tokio::sync::Semaphore::new(dials)),
        });
        let keys: Vec<KeyFingerprint> = memory
            .inner
            .lock()
            .book
            .records()
            .iter()
            .map(|r| r.key)
            .collect();
        for key in keys {
            memory.start_redial(key);
        }
        tokio::spawn(write_behind(Arc::clone(&memory)));
        memory.write_wake.notify_one();
        memory
    }

    /// Start the loop that keeps the record of `key` dialled.
    fn start_redial(self: &Arc<Self>, key: KeyFingerprint) {
        let mut inner = self.inner.lock();
        if inner.redials.contains_key(&key) || inner.book.get(&key).is_none() {
            return;
        }
        let redial = Redial {
            wake: Arc::new(Notify::new()),
            kick: Arc::new(Notify::new()),
            stop: self.cancel.child_token(),
            state: Arc::new(Mutex::new(RememberedState::Dialling)),
        };
        tokio::spawn(redial_loop(
            Arc::clone(self),
            key,
            redial.stop.clone(),
            Arc::clone(&redial.wake),
            Arc::clone(&redial.kick),
            Arc::clone(&redial.state),
        ));
        inner.redials.insert(key, redial);
    }

    fn wake(&self, key: &KeyFingerprint) {
        if let Some(r) = self.inner.lock().redials.get(key) {
            r.wake.notify_one();
        }
    }

    /// Every loop looks again: a trust context was adopted, or a grant made.
    pub(crate) fn wake_all(&self) {
        for r in self.inner.lock().redials.values() {
            r.wake.notify_one();
        }
    }

    /// Every loop dials now, whatever its backoff was: this device is back
    /// online, or its addresses changed. The dials ride the turns of
    /// `dials_at_once`.
    pub(crate) fn kick_all(&self) {
        for r in self.inner.lock().redials.values() {
            r.kick.notify_one();
        }
    }

    /// A turn at the dials the memory staggers (`dials_at_once`), for a
    /// dial that every loop of these links makes at once.
    pub(crate) async fn turn(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
        Arc::clone(&self.dials).acquire_owned().await.ok()
    }

    /// The addresses to dial the peer of `record` at: the IP addresses
    /// contacts reported for it at its last-known port (newest first), then
    /// the addresses that worked.
    fn dial_list(&self, record: &PeerRecord) -> Vec<SocketAddr> {
        let mut list: Vec<SocketAddr> = Vec::new();
        let inner = self.inner.lock();
        if let (Some(port), Some(ips)) = (record.port, inner.reported.get(&record.key)) {
            list.extend(ips.iter().map(|ip| SocketAddr::new(*ip, port)));
        }
        drop(inner);
        for addr in &record.addresses {
            if !list.contains(addr) {
                list.push(*addr);
            }
        }
        list
    }

    /// A direct path to the peer `key` is up, its far end `remote`: that is
    /// the peer's link socket, so its listening port, and its IP address is
    /// one to try at that port (§17D.2).
    fn direct_contact(&self, key: &KeyFingerprint, remote: SocketAddr) {
        let remote = canonical(remote);
        let mut inner = self.inner.lock();
        if inner.book.get(key).is_none() {
            return;
        }
        let save = inner.book.set_port(key, remote.port());
        inner.report(*key, remote.ip(), self.options.include_local);
        if save {
            inner.dirty.insert(*key);
            drop(inner);
            self.write_wake.notify_one();
        }
    }

    fn record(&self, key: &KeyFingerprint) -> Option<PeerRecord> {
        self.inner.lock().book.get(key).cloned()
    }

    /// The peer `key` was reached at `addr`, a link `direction` made:
    /// remember it, to be saved when that changed what is kept, and dial it
    /// when it is new.
    pub(crate) fn learn(
        self: &Arc<Self>,
        key: KeyFingerprint,
        device: Name,
        addr: SocketAddr,
        direction: Direction,
        now: SystemTime,
    ) {
        let (learned, address_list) = {
            let mut inner = self.inner.lock();
            let learned = inner.book.learn(key, device, addr, direction, now);
            if learned.save {
                inner.dirty.insert(key);
            }
            if let Some(victim) = learned.evicted {
                if let Some(r) = inner.redials.remove(&victim) {
                    r.stop.cancel();
                }
                inner.dirty.remove(&victim);
                inner.doomed.insert(victim);
            }
            if direction == Direction::Accepted {
                inner.report(key, addr.ip(), self.options.include_local);
            }
            (learned, inner.book.get(&key).map(|r| r.addresses.clone()))
        };
        if let (Some(links), Some(addresses)) = (self.links.upgrade(), address_list) {
            links.remembered_addresses(&key, addresses);
        }
        self.start_redial(key);
        self.wake(&key);
        if learned.save || learned.evicted.is_some() {
            self.write_wake.notify_one();
        }
    }

    /// The peer `key` is in contact at `now`.
    fn touch(&self, key: &KeyFingerprint, now: SystemTime) {
        let mut inner = self.inner.lock();
        if inner.book.touch(key, now) {
            inner.dirty.insert(*key);
            drop(inner);
            self.write_wake.notify_one();
        }
    }

    /// The peer `key` is not remembered any more: its record is removed from
    /// memory, its loop stopped, its removal from the store queued (and made
    /// by [`Self::forget`] before it returns).
    fn drop_record(&self, key: &KeyFingerprint) -> bool {
        let mut inner = self.inner.lock();
        let had = inner.book.remove(key);
        if let Some(r) = inner.redials.remove(key) {
            r.stop.cancel();
        }
        inner.dirty.remove(key);
        inner.saved_at.remove(key);
        had
    }

    /// Forget the peer `key`: no record, no redial, no address; the store's
    /// record removed before this returns.
    pub(crate) async fn forget(&self, key: &KeyFingerprint) {
        self.drop_record(key);
        self.inner.lock().doomed.remove(key);
        let _io = self.io.lock().await;
        let result = self.store.remove(key).await;
        self.note(result, "remove a peer from");
    }

    /// Everything the writer owes the store, now. For a host that is
    /// stopping; the writer does it behind otherwise.
    pub(crate) async fn flush(&self) {
        let now = SystemTime::now();
        {
            // Peers linked now are in contact now.
            let keys: Vec<KeyFingerprint> = self
                .inner
                .lock()
                .book
                .records()
                .iter()
                .map(|r| r.key)
                .collect();
            if let Some(links) = self.links.upgrade() {
                for key in keys.into_iter().filter(|k| links.table.is_linked(k)) {
                    self.touch(&key, now);
                }
            }
        }
        self.drain().await;
    }

    fn note(&self, result: Result<(), String>, doing: &str) {
        let mut failure = self.failure.lock();
        match result {
            Ok(()) => *failure = None,
            Err(e) => {
                let words = format!(
                    "the link memory could not {doing} its store ({e}): the links work without \
                     it, and what is learned is kept in memory only until the store works again; \
                     check the store it is kept in"
                );
                tracing::warn!(target: "face.quic", "{words}");
                *failure = Some(words);
            }
        }
    }

    /// Everything owed the store, now: prune what expired (not a peer that
    /// is linked: it is in contact), then write and remove what is owed,
    /// until nothing is, whatever `save_interval` says.
    async fn drain(&self) {
        self.write_owed(true).await;
    }

    /// What is owed the store and due: the removals, and the saves of the
    /// records not written within `save_interval`. Those not due stay owed;
    /// the time until the first of them is.
    async fn write_due(&self) -> Option<Duration> {
        self.write_owed(false).await
    }

    async fn write_owed(&self, all: bool) -> Option<Duration> {
        loop {
            let now = SystemTime::now();
            let tick = Instant::now();
            let mut later: Option<Duration> = None;
            let (removals, saves) = {
                let linked =
                    |k: &KeyFingerprint| self.links.upgrade().is_some_and(|l| l.table.is_linked(k));
                let mut inner = self.inner.lock();
                for key in inner.book.expired_keys(now) {
                    if linked(&key) {
                        continue;
                    }
                    inner.book.remove(&key);
                    if let Some(r) = inner.redials.remove(&key) {
                        r.stop.cancel();
                    }
                    inner.dirty.remove(&key);
                    inner.doomed.insert(key);
                }
                let mut due = HashSet::new();
                for key in std::mem::take(&mut inner.dirty) {
                    let wait = inner
                        .saved_at
                        .get(&key)
                        .and_then(|at| {
                            self.options
                                .save_interval
                                .checked_sub(tick.saturating_duration_since(*at))
                        })
                        .filter(|wait| !all && !wait.is_zero());
                    match wait {
                        None => {
                            due.insert(key);
                        }
                        Some(wait) => {
                            inner.dirty.insert(key);
                            later = Some(later.map_or(wait, |l| l.min(wait)));
                        }
                    }
                }
                (std::mem::take(&mut inner.doomed), due)
            };
            let port_owed = self.inner.lock().port_owed.take();
            if removals.is_empty() && saves.is_empty() && port_owed.is_none() {
                return later;
            }
            for key in removals {
                let _io = self.io.lock().await;
                // Learned again since: its save follows.
                if self.inner.lock().book.get(&key).is_some() && !saves.contains(&key) {
                    continue;
                }
                let result = self.store.remove(&key).await;
                self.inner.lock().saved_at.remove(&key);
                self.note(result, "remove a peer from");
            }
            for key in saves {
                let _io = self.io.lock().await;
                // Read once the store is ours: a forget that came first has
                // removed it, and nothing is written back.
                let Some(mut record) = self.record(&key) else {
                    continue;
                };
                if !self.options.persist_addresses {
                    record.addresses.clear();
                    record.port = None;
                }
                let result = self.store.save(&record).await;
                {
                    let mut inner = self.inner.lock();
                    if result.is_ok() {
                        inner.book.persisted(&key);
                    }
                    inner.saved_at.insert(key, Instant::now());
                }
                self.note(result, "save a peer in");
            }
            if let Some(port) = port_owed {
                let _io = self.io.lock().await;
                let result = self.store.save_listen_port(port).await;
                let failed = result.is_err();
                self.note(result, "save the listening port in");
                if failed {
                    // Owed still, unless a newer port came meanwhile; tried
                    // again later rather than in a loop.
                    self.inner.lock().port_owed.get_or_insert(port);
                    return Some(RECHECK);
                }
            }
        }
    }

    /// The memory as `Links::report` shows it.
    pub(crate) fn report(&self) -> MemoryReport {
        let inner = self.inner.lock();
        MemoryReport {
            peers: inner
                .book
                .records()
                .into_iter()
                .map(|record| {
                    let state = inner
                        .redials
                        .get(&record.key)
                        .map(|r| r.state.lock().clone())
                        .unwrap_or(RememberedState::Dialling);
                    RememberedPeer { record, state }
                })
                .collect(),
            store_error: self.failure.lock().clone(),
        }
    }
}

/// The writer: what is owed the store is written behind, never waited for,
/// each record at most once in `save_interval`; what that defers is written
/// when its time is up, and everything at the end.
async fn write_behind(memory: Arc<Memory>) {
    loop {
        let deferred = memory.write_due().await;
        let timer = async {
            match deferred {
                Some(within) => tokio::time::sleep(within).await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            () = memory.cancel.cancelled() => {
                memory.drain().await;
                return;
            }
            () = memory.write_wake.notified() => {}
            () = timer => {}
        }
    }
}

// ---- the links' side ---------------------------------------------------------------------------

impl Standing for Links {
    fn holds_namespace_of(&self, device: &Name) -> bool {
        self.trust.keyring().held_for(device).is_some()
    }

    fn is_in_namespace_of(&self, device: &Name) -> bool {
        let judge = self.judge();
        judge.own_role_in(&judge.namespace_of(device)).is_some()
    }

    fn granted(&self, key: &KeyFingerprint) -> bool {
        self.grants.has_live(key, std::time::SystemTime::now())
    }
}

impl Links {
    /// Keep what this device learns of its peers in `memory`, and dial them
    /// again from it: loads the records (those not in contact for
    /// `options.expires` are dropped), dials in the background each peer
    /// that a held context admits ([`MemoryOptions::redial`] is the dial
    /// policy), and from now on keeps each peer that links by an identity in
    /// a held namespace: its key, its device and the addresses that worked.
    ///
    /// The key is what a redial trusts; an address is a hint, and the
    /// handshake accepts only the holder of the key. A remembered peer is
    /// never admitted by its key alone: it is an identified device or it is
    /// not linked, so a member who was removed and still holds its key is
    /// refused as any device is. Call it once; a second call is ignored and
    /// says so.
    pub fn remember(self: &Arc<Self>, memory: Arc<dyn LinkMemory>, options: MemoryOptions) {
        let started = Memory::start(self, memory, options);
        if self.memory.set(Arc::clone(&started)).is_err() {
            started.cancel.cancel();
            tracing::warn!(
                target: "face.quic",
                "Links::remember was called again: the first memory is kept, and this one is \
                 ignored"
            );
            return;
        }
        let observed = Arc::downgrade(&started);
        self.observe(Arc::new(move |event| {
            if let Some(memory) = observed.upgrade() {
                memory.observe(event);
            }
        }));
        let adopted = Arc::downgrade(&started);
        self.trust.keyring().on_adoption(move |_| {
            if let Some(memory) = adopted.upgrade() {
                memory.wake_all();
            }
        });
    }

    /// The host's link socket listens, and the store kept `kept` as the port
    /// this device listened on (§17D.2): bind the kept port again when it is
    /// not the one in use, free, and a port a device may be reached at (not
    /// 0, not below [`LISTEN_PORT_MIN`](crate::policy::LISTEN_PORT_MIN)),
    /// else keep listening where it does. Returns the port the socket listens
    /// on now (`None` when the host's socket does not listen); the peers are
    /// told (presence refreshed, direct paths punched again with the
    /// candidates of the port in use) when it is not the one they knew.
    pub(crate) fn settle_listen_port(self: &Arc<Self>, kept: Option<u16>) -> Option<u16> {
        let socket = self.socket.as_ref().filter(|s| s.is_listening())?;
        let local = socket.local_addr().ok()?;
        let mut now = local.port();
        if let Some(port) = kept.filter(|port| *port != now) {
            if port < crate::policy::LISTEN_PORT_MIN {
                tracing::warn!(
                    target: "face.quic",
                    "the port kept for this device, {port}, is below {}: it is not a port this device \
                     rebinds to; it keeps listening on {now}",
                    crate::policy::LISTEN_PORT_MIN
                );
            } else {
                match std::net::UdpSocket::bind(SocketAddr::new(local.ip(), port))
                    .and_then(|bound| socket.rebind(bound))
                {
                    Ok(()) => {
                        tracing::info!(
                            target: "face.quic",
                            "this device listens on its kept port {port} again (it was bound to {now})"
                        );
                        now = port;
                    }
                    Err(e) => tracing::warn!(
                        target: "face.quic",
                        "the port kept for this device, {port}, cannot be bound again ({e}): it keeps \
                         listening on {now}, and keeps that"
                    ),
                }
            }
        }
        if kept.is_some_and(|port| port != now) {
            self.announce_all();
            self.direct.kick();
        }
        Some(now)
    }

    /// Whether a relay this device is linked to lists the peer `key` as
    /// linked to it too: a path both devices use, whatever their own
    /// addresses are.
    pub(crate) fn shares_relay_with(&self, key: &KeyFingerprint) -> bool {
        self.present
            .lock()
            .iter()
            .any(|(relay, keys)| keys.contains(key) && self.table.link_to(*relay).is_some())
    }

    /// A turn at the dials the link memory staggers, when there is one: the
    /// dials every loop makes at once (online again, an address change) take
    /// turns at `dials_at_once`.
    pub(crate) async fn dial_turn(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
        match self.memory.get() {
            Some(memory) => memory.turn().await,
            None => None,
        }
    }

    /// Forget the peer with `key`: its record is removed (durably, before
    /// this returns), no redial is made and any address learned is dropped.
    /// A link already up stays up while a held context admits it: the layer,
    /// not this call, ends the links of removed members (§8.7, §17C). A peer
    /// that links in again is remembered again.
    pub async fn forget(&self, key: &KeyFingerprint) {
        if let Some(memory) = self.memory.get() {
            memory.forget(key).await;
        }
    }

    /// What this device's link memory holds and does; `None` when
    /// [`Links::remember`] was not called.
    pub(crate) fn memory_report(&self) -> Option<MemoryReport> {
        self.memory.get().map(|m| m.report())
    }

    /// Write what the link memory owes its store: a host that is stopping
    /// calls it (as [`Links::shutdown`] does).
    pub(crate) async fn flush_memory(&self) {
        if let Some(memory) = self.memory.get() {
            memory.flush().await;
        }
    }

    /// The addresses peer `key` is dialled at, for the peer entry its
    /// redial keeps: where its dial loop, and what is told of it, look.
    fn remembered_addresses(&self, key: &KeyFingerprint, addresses: Vec<SocketAddr>) {
        let ids: Vec<PeerId> = self
            .peers
            .iter()
            .into_iter()
            .filter(|(_, p)| p.remembered && p.key == Some(*key))
            .map(|(id, _)| id)
            .collect();
        let mut introduced = self.introduced.lock();
        for id in ids {
            introduced.insert(id, addresses.clone());
        }
    }

    /// The peer entry the redial of `record` dials as (made when there is
    /// none): its key pins the dial and admits nothing
    /// (`PeerSpec::remembered`).
    fn remembered_peer(&self, record: &PeerRecord) -> PeerId {
        let existing = self
            .peers
            .iter()
            .into_iter()
            .find(|(_, p)| p.remembered && p.key == Some(record.key));
        let id = match existing {
            Some((id, _)) => id,
            None => self.peers.add(PeerSpec {
                label: record.device.to_string(),
                key: Some(record.key),
                device: Some(record.device.clone()),
                persistent: true,
                direct: false,
                remembered: true,
                linked_in: record.origin == Direction::Accepted,
                mode: LinkMode::Always,
                ..PeerSpec::default()
            }),
        };
        self.introduced.lock().insert(id, record.addresses.clone());
        id
    }

    /// The redial of the peer with `key` is over: its peer entry goes.
    fn end_remembered_peer(&self, key: &KeyFingerprint) {
        let ids: Vec<PeerId> = self
            .peers
            .iter()
            .into_iter()
            .filter(|(_, p)| p.remembered && p.key == Some(*key))
            .map(|(id, _)| id)
            .collect();
        for id in ids {
            self.forget_dialled(id);
        }
    }
}

impl Memory {
    /// What the links tell: a path up is contact, and (for a link admitted
    /// by an identity) what is learned; a link ended is contact too.
    fn observe(self: &Arc<Self>, event: &LinkEvent) {
        let now = SystemTime::now();
        match event {
            LinkEvent::Up {
                key,
                device,
                remote,
                direction,
                kind,
                peer,
                identified,
            } => {
                self.wake(key);
                if *identified && *kind == PathKind::Direct {
                    self.direct_contact(key, *remote);
                    return;
                }
                if *kind != PathKind::Link || !identified {
                    return;
                }
                let (Some(device), Some(links)) = (device, self.links.upgrade()) else {
                    return;
                };
                // A peer the host lists, and a relay a namespace advertises,
                // have their entries: the host keeps them. The peers this
                // device dialled by a code's hint, and its own redials, are
                // in `introduced`.
                if let Some(id) = peer
                    && !links.introduced.lock().contains_key(id)
                {
                    return;
                }
                let known = self.record(key);
                let origin = known.map_or(*direction, |r| r.origin);
                let device = device.clone();
                if let Some(why) = not_redialled(links.as_ref(), key, &device, origin) {
                    tracing::debug!(target: "face.quic", %key, "not remembered: {why}");
                    return;
                }
                self.learn(*key, device, *remote, *direction, now);
            }
            LinkEvent::Down { key, why } => {
                tracing::debug!(target: "face.quic", %key, "a link ended: {}", why.text);
                self.touch(key, now);
                self.wake(key);
            }
        }
    }
}

/// Keep the record of `key` dialled until it is forgotten: dial it when it
/// has an address and a held context admits it, wait for its link to end
/// when it is up, wait when it cannot be dialled and look again when
/// something that decides it changes.
async fn redial_loop(
    memory: Arc<Memory>,
    key: KeyFingerprint,
    stop: CancellationToken,
    wake: Arc<Notify>,
    kick: Arc<Notify>,
    state: Arc<Mutex<RememberedState>>,
) {
    let mut backoff = memory.options.redial.clone();
    // Wait for `wake` or `within`; `false` when the loop is to end.
    let pause = |within: Option<Duration>| {
        let stop = stop.clone();
        let wake = Arc::clone(&wake);
        async move {
            let timer = async {
                match within {
                    Some(d) => tokio::time::sleep(d).await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                () = stop.cancelled() => false,
                () = wake.notified() => true,
                () = timer => true,
            }
        }
    };
    // Wait out a backoff of `within`, or until this device is kicked (back
    // online, its addresses changed); `false` when the loop is to end.
    let rest = |within: Duration| {
        let stop = stop.clone();
        let kick = Arc::clone(&kick);
        async move {
            tokio::select! {
                () = stop.cancelled() => false,
                () = kick.notified() => true,
                () = tokio::time::sleep(within) => true,
            }
        }
    };
    loop {
        let (Some(links), Some(record)) = (memory.links.upgrade(), memory.record(&key)) else {
            break;
        };
        if stop.is_cancelled() {
            break;
        }
        if let Some(why) = not_redialled(links.as_ref(), &key, &record.device, record.origin) {
            *state.lock() = RememberedState::NotDialled { why };
            links.end_remembered_peer(&key);
            drop(links);
            if !pause(Some(RECHECK)).await {
                break;
            }
            continue;
        }
        if !links.is_online() {
            // Offline: no dial, and the status says so; online again, the
            // peer is dialled at once.
            *state.lock() = RememberedState::Offline;
            let id = links.remembered_peer(&record);
            links.watch_failed_remembered(
                id,
                &key,
                &crate::online::offline_detail(),
                Next::WhenOnline,
            );
            let online = links.online.subscribe();
            drop(links);
            if !crate::online::wait_online(online, &stop).await {
                break;
            }
            backoff.reset();
            continue;
        }
        if links.table.is_linked(&key) {
            *state.lock() = RememberedState::Linked;
            backoff.reset();
            drop(links);
            // In contact for as long as it is up: noted now and again, so a
            // link that outlives `expires` is not forgotten at a restart.
            if !pause(Some(memory.options.expires / 8)).await {
                break;
            }
            memory.touch_if_linked(&key);
            if !memory.is_linked(&key) {
                // It dropped: the other device may be restarting.
                if !rest(backoff.after_drop()).await {
                    break;
                }
            }
            continue;
        }
        if memory.dial_list(&record).is_empty() {
            *state.lock() = RememberedState::WaitingForAddress;
            links.watch_next_remembered(&key, Next::WaitingForAddress);
            drop(links);
            if !pause(None).await {
                break;
            }
            continue;
        }
        *state.lock() = RememberedState::Dialling;
        drop(links);
        // A few peers at a time: a store with many records is not dialled all
        // at once (and each wait for a turn can be stopped).
        let turn = tokio::select! {
            () = stop.cancelled() => break,
            turn = memory.dials.acquire() => turn,
        };
        let Ok(turn) = turn else { break };
        // What held when the turn came is looked at again: the peer may have
        // been forgotten, linked, or no longer admitted while it waited.
        let (Some(links), Some(record)) = (memory.links.upgrade(), memory.record(&key)) else {
            break;
        };
        let addresses = memory.dial_list(&record);
        if stop.is_cancelled()
            || addresses.is_empty()
            || !links.is_online()
            || links.table.is_linked(&key)
            || not_redialled(links.as_ref(), &key, &record.device, record.origin).is_some()
        {
            continue;
        }
        let id = links.remembered_peer(&PeerRecord {
            addresses: addresses.clone(),
            ..record.clone()
        });
        let outcome = links.dial_race(id, key, &addresses, DIAL_WITHIN).await;
        drop(turn);
        match outcome {
            Ok(_) if memory.is_linked(&key) => {
                backoff.reset();
                continue;
            }
            Ok(_) => {
                // Up and gone again at once: not a link to hammer.
                let wait = backoff.after_failure(false);
                *state.lock() = RememberedState::Redialling { within: wait };
                drop(links);
                if !rest(wait).await {
                    break;
                }
            }
            Err(_) if !links.is_online() => {
                // Went offline during the dial: the top of the loop waits.
                drop(links);
            }
            Err(detail) => {
                let wait = backoff.after_failure(false);
                tracing::debug!(
                    target: "face.quic",
                    device = %record.device,
                    retry_in_secs = wait.as_secs_f32(),
                    "redial of a remembered peer failed: {}",
                    detail.text
                );
                if links.shares_relay_with(&key) {
                    links.watch_failed_remembered(
                        id,
                        &key,
                        &detail,
                        Next::Redialling { within: wait },
                    );
                    *state.lock() = RememberedState::Redialling { within: wait };
                } else {
                    let why = no_path_words(&record.device);
                    let mut no_path = LinkDetail::new(code::NO_PATH, why.clone())
                        .with("device", record.device.to_string());
                    no_path.append("; the last attempt: ", detail);
                    links.watch_failed_remembered(id, &key, &no_path, Next::WaitingForAddress);
                    *state.lock() = RememberedState::NoPath { why };
                }
                drop(links);
                if !rest(wait).await {
                    break;
                }
            }
        }
    }
    if let Some(links) = memory.links.upgrade() {
        links.end_remembered_peer(&key);
    }
}

/// What a device says when it cannot reach a remembered peer at all (§17D.2).
fn no_path_words(device: &Name) -> String {
    format!(
        "every address this device kept for {device} failed, {device}'s port may have changed, and \
         no relay both of you use is linked; {device} reaches this device when it dials this \
         device's current address, or when you both link to a relay"
    )
}

impl Memory {
    fn is_linked(&self, key: &KeyFingerprint) -> bool {
        self.links.upgrade().is_some_and(|l| l.table.is_linked(key))
    }

    fn touch_if_linked(&self, key: &KeyFingerprint) {
        if self.is_linked(key) {
            self.touch(key, SystemTime::now());
        }
    }
}

impl Links {
    /// Tell the link status what the redial of `key` does next.
    fn watch_next_remembered(&self, key: &KeyFingerprint, next: Next) {
        if let Some((id, _)) = self
            .peers
            .iter()
            .into_iter()
            .find(|(_, p)| p.remembered && p.key == Some(*key))
        {
            self.watch_next(id, next);
        }
    }

    /// A redial of peer `id` (expecting `key`) failed.
    fn watch_failed_remembered(
        &self,
        id: PeerId,
        key: &KeyFingerprint,
        why: &LinkDetail,
        next: Next,
    ) {
        self.watch_failed(id, Some(*key), why, next);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn key(b: u8) -> KeyFingerprint {
        KeyFingerprint([b; 32])
    }

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn record(b: u8, last: u64) -> PeerRecord {
        PeerRecord {
            key: key(b),
            device: n(&format!("/ann/member/d{b}")),
            addresses: vec![addr(&format!("192.0.2.{b}:4433"))],
            last_contact: at(last),
            origin: Direction::Dialed,
            port: Some(4433),
        }
    }

    /// Options for the cases that read the store at once after a change: no
    /// delay between two writes of a record (the case of that delay uses the
    /// defaults).
    fn options(peers_max: usize, addresses_max: usize, expires: u64) -> MemoryOptions {
        MemoryOptions {
            peers_max,
            addresses_max,
            expires: Duration::from_secs(expires),
            save_interval: Duration::ZERO,
            ..MemoryOptions::default()
        }
    }

    #[test]
    fn addresses_are_most_recent_first_and_bounded() {
        let (mut book, _) = Book::load(options(8, 3, 1000), Vec::new(), at(0));
        let device = n("/ann/member/laptop");
        for (i, a) in ["192.0.2.1:1", "192.0.2.2:2", "192.0.2.3:3", "192.0.2.4:4"]
            .into_iter()
            .enumerate()
        {
            book.learn(
                key(1),
                device.clone(),
                addr(a),
                Direction::Dialed,
                at(i as u64),
            );
        }
        let r = book.get(&key(1)).unwrap();
        assert_eq!(
            r.addresses,
            vec![
                addr("192.0.2.4:4"),
                addr("192.0.2.3:3"),
                addr("192.0.2.2:2")
            ],
            "the oldest went when the fourth came"
        );
        // An address already held moves to the front and is not held twice.
        book.learn(
            key(1),
            device,
            addr("192.0.2.2:2"),
            Direction::Dialed,
            at(9),
        );
        let r = book.get(&key(1)).unwrap();
        assert_eq!(
            r.addresses,
            vec![
                addr("192.0.2.2:2"),
                addr("192.0.2.4:4"),
                addr("192.0.2.3:3")
            ]
        );
    }

    #[test]
    fn a_v4_address_shown_mapped_is_the_v4_address_and_unusable_ones_are_not_kept() {
        let (mut book, _) = Book::load(options(8, 4, 1000), Vec::new(), at(0));
        let device = n("/ann/member/laptop");
        book.learn(
            key(1),
            device.clone(),
            addr("[::ffff:192.0.2.1]:4433"),
            Direction::Accepted,
            at(0),
        );
        for bad in ["0.0.0.0:4433", "192.0.2.9:0", "224.0.0.1:4433"] {
            book.learn(
                key(1),
                device.clone(),
                addr(bad),
                Direction::Accepted,
                at(1),
            );
        }
        assert_eq!(
            book.get(&key(1)).unwrap().addresses,
            vec![addr("192.0.2.1:4433")]
        );
        // A peer first met at an unusable address is a peer with none.
        book.learn(
            key(2),
            device,
            addr("0.0.0.0:1"),
            Direction::Accepted,
            at(0),
        );
        assert!(book.get(&key(2)).unwrap().addresses.is_empty());
    }

    #[test]
    fn more_peers_than_the_bound_evict_the_least_recently_in_contact() {
        let (mut book, _) = Book::load(options(2, 4, 1000), Vec::new(), at(0));
        book.learn(
            key(1),
            n("/a/d1"),
            addr("192.0.2.1:1"),
            Direction::Dialed,
            at(10),
        );
        book.learn(
            key(2),
            n("/a/d2"),
            addr("192.0.2.2:2"),
            Direction::Dialed,
            at(20),
        );
        // Contact moves 1 ahead of 2.
        book.touch(&key(1), at(30));
        let learned = book.learn(
            key(3),
            n("/a/d3"),
            addr("192.0.2.3:3"),
            Direction::Dialed,
            at(40),
        );
        assert_eq!(learned.evicted, Some(key(2)));
        assert!(learned.save);
        assert!(book.get(&key(2)).is_none());
        let keys: Vec<_> = book.records().iter().map(|r| r.key).collect();
        assert_eq!(keys, vec![key(3), key(1)], "most recently in contact first");
    }

    #[test]
    fn load_drops_the_expired_the_surplus_and_the_duplicates_and_cleans_addresses() {
        let mut messy = record(1, 900);
        messy.addresses = vec![
            addr("192.0.2.1:1"),
            addr("192.0.2.1:1"),
            addr("0.0.0.0:5"),
            addr("192.0.2.2:2"),
            addr("192.0.2.3:3"),
        ];
        let older_twin = PeerRecord {
            addresses: vec![addr("192.0.2.77:7")],
            ..record(1, 800)
        };
        let (book, dropped) = Book::load(
            options(2, 2, 500),
            vec![
                messy,
                older_twin,
                record(2, 950),
                record(3, 940),
                record(4, 100),
            ],
            at(1000),
        );
        let kept: Vec<_> = book.records().iter().map(|r| r.key).collect();
        assert_eq!(kept, vec![key(2), key(3)], "two kept, the most recent");
        assert!(dropped.contains(&key(1)), "over peers_max: dropped");
        assert!(
            dropped.contains(&key(4)),
            "no contact for 900 s of 500: expired"
        );
        assert!(!dropped.contains(&key(2)));
        let (book, _) = Book::load(
            options(8, 2, 500),
            vec![
                PeerRecord {
                    addresses: vec![
                        addr("192.0.2.1:1"),
                        addr("192.0.2.1:1"),
                        addr("0.0.0.0:5"),
                        addr("192.0.2.2:2"),
                        addr("192.0.2.3:3"),
                    ],
                    ..record(1, 900)
                },
                PeerRecord {
                    addresses: vec![addr("192.0.2.77:7")],
                    ..record(1, 800)
                },
            ],
            at(1000),
        );
        assert_eq!(
            book.get(&key(1)).unwrap().addresses,
            vec![addr("192.0.2.1:1"), addr("192.0.2.2:2")],
            "the newest record of the key, deduplicated, no unspecified address, cut to the bound"
        );
    }

    #[test]
    fn a_record_expires_after_no_contact_and_contact_keeps_it() {
        let (mut book, _) =
            Book::load(options(8, 4, 100), vec![record(1, 0), record(2, 0)], at(50));
        assert!(book.expired_keys(at(99)).is_empty());
        book.touch(&key(2), at(90));
        let mut gone = book.expired_keys(at(100));
        gone.sort();
        assert_eq!(gone, vec![key(1)]);
        assert!(book.remove(&key(1)));
        assert!(book.expired_keys(at(189)).is_empty());
        assert_eq!(book.expired_keys(at(190)), vec![key(2)]);
    }

    #[test]
    fn a_contact_is_saved_when_the_addresses_moved_or_the_store_is_far_behind() {
        let (mut book, _) = Book::load(options(8, 4, 400), Vec::new(), at(0));
        let device = n("/ann/member/laptop");
        let first = book.learn(
            key(1),
            device.clone(),
            addr("192.0.2.1:1"),
            Direction::Dialed,
            at(0),
        );
        assert!(first.save);
        let again = book.learn(
            key(1),
            device.clone(),
            addr("192.0.2.1:1"),
            Direction::Dialed,
            at(10),
        );
        assert!(
            !again.save,
            "the same address a moment later is not written again"
        );
        let moved = book.learn(
            key(1),
            device.clone(),
            addr("192.0.2.2:2"),
            Direction::Dialed,
            at(20),
        );
        assert!(moved.save);
        // 100 s (a quarter of expires) after what the store holds.
        let late = book.learn(
            key(1),
            device.clone(),
            addr("192.0.2.2:2"),
            Direction::Dialed,
            at(130),
        );
        assert!(late.save, "the store is a quarter of `expires` behind");
        assert!(!book.touch(&key(1), at(140)));
        assert!(book.touch(&key(1), at(240)));
        // Another device name proved at the same key is the new name.
        let renamed = book.learn(
            key(1),
            n("/ann/member/phone"),
            addr("192.0.2.2:2"),
            Direction::Dialed,
            at(241),
        );
        assert!(renamed.save);
        assert_eq!(book.get(&key(1)).unwrap().device, n("/ann/member/phone"));
    }

    #[test]
    fn the_origin_is_that_of_the_first_contact() {
        let (mut book, _) = Book::load(options(8, 4, 400), Vec::new(), at(0));
        let device = n("/ann/member/laptop");
        book.learn(
            key(1),
            device.clone(),
            addr("192.0.2.1:1"),
            Direction::Accepted,
            at(0),
        );
        book.learn(
            key(1),
            device,
            addr("192.0.2.1:1"),
            Direction::Dialed,
            at(5),
        );
        assert_eq!(book.get(&key(1)).unwrap().origin, Direction::Accepted);
    }

    struct Facts {
        held: bool,
        own: bool,
        grant: bool,
    }

    impl Standing for Facts {
        fn holds_namespace_of(&self, _: &Name) -> bool {
            self.held
        }
        fn is_in_namespace_of(&self, _: &Name) -> bool {
            self.own
        }
        fn granted(&self, _: &KeyFingerprint) -> bool {
            self.grant
        }
    }

    #[test]
    fn rule_three_a_peer_is_dialled_only_when_a_held_context_admits_it() {
        let device = n("/bob/member/phone");
        let why = |held, own, grant, origin| {
            not_redialled(&Facts { held, own, grant }, &key(1), &device, origin)
        };
        // A namespace not held: never, whatever else is true.
        for origin in [Direction::Dialed, Direction::Accepted] {
            let words =
                why(false, true, true, origin).expect("a namespace not held is not dialled");
            assert!(words.contains("does not hold"), "{words}");
            assert!(words.contains("forget"), "{words}");
        }
        // A peer this device dialled, in a held namespace: dialled.
        assert_eq!(why(true, false, false, Direction::Dialed), None);
        // A peer that dialled in: only as a device of a namespace this device
        // is in, or a person a live grant covers.
        assert_eq!(why(true, true, false, Direction::Accepted), None);
        assert_eq!(why(true, false, true, Direction::Accepted), None);
        let words = why(true, false, false, Direction::Accepted)
            .expect("a person whose grant ended is not dialled");
        assert!(words.contains("no live grant"), "{words}");
    }

    /// A store in memory that can be made to fail.
    #[derive(Default)]
    struct Shelf {
        records: Mutex<HashMap<KeyFingerprint, PeerRecord>>,
        failing: parking_lot::Mutex<bool>,
        saves: AtomicUsize,
        removes: AtomicUsize,
        /// The listening port the store holds, and the writes it took.
        port: parking_lot::Mutex<Option<u16>>,
        port_writes: parking_lot::Mutex<Vec<Option<u16>>>,
    }

    impl Shelf {
        fn with(records: Vec<PeerRecord>) -> Arc<Self> {
            let shelf = Self::default();
            shelf
                .records
                .lock()
                .extend(records.into_iter().map(|r| (r.key, r)));
            Arc::new(shelf)
        }

        fn kept(&self, key: &KeyFingerprint) -> Option<PeerRecord> {
            self.records.lock().get(key).cloned()
        }
    }

    impl LinkMemory for Shelf {
        fn load(&self) -> Result<Vec<PeerRecord>, String> {
            if *self.failing.lock() {
                return Err("the disk is gone".into());
            }
            Ok(self.records.lock().values().cloned().collect())
        }
        fn save<'a>(&'a self, record: &'a PeerRecord) -> MemoryFuture<'a, Result<(), String>> {
            Box::pin(async move {
                if *self.failing.lock() {
                    return Err("the disk is full".into());
                }
                self.saves.fetch_add(1, Ordering::SeqCst);
                self.records.lock().insert(record.key, record.clone());
                Ok(())
            })
        }
        fn remove<'a>(&'a self, key: &'a KeyFingerprint) -> MemoryFuture<'a, Result<(), String>> {
            Box::pin(async move {
                if *self.failing.lock() {
                    return Err("the disk is full".into());
                }
                self.removes.fetch_add(1, Ordering::SeqCst);
                self.records.lock().remove(key);
                Ok(())
            })
        }
        fn load_listen_port(&self) -> Result<Option<u16>, String> {
            if *self.failing.lock() {
                return Err("the disk is gone".into());
            }
            Ok(*self.port.lock())
        }
        fn save_listen_port<'a>(
            &'a self,
            port: Option<u16>,
        ) -> MemoryFuture<'a, Result<(), String>> {
            Box::pin(async move {
                if *self.failing.lock() {
                    return Err("the disk is full".into());
                }
                self.port_writes.lock().push(port);
                *self.port.lock() = port;
                Ok(())
            })
        }
    }

    /// A memory over `shelf` with no links behind it: the records, the
    /// writer and the bounds, nothing that dials.
    fn memory_over(shelf: &Arc<Shelf>, options: MemoryOptions) -> Arc<Memory> {
        memory_binding(shelf, options, |_| None)
    }

    /// The same, with `bind` as the listening socket: it is told the port the
    /// store kept and answers the port it listens on.
    fn memory_binding(
        shelf: &Arc<Shelf>,
        options: MemoryOptions,
        bind: impl FnOnce(Option<u16>) -> Option<u16>,
    ) -> Arc<Memory> {
        Memory::open(
            Weak::new(),
            CancellationToken::new(),
            Arc::clone(shelf) as Arc<dyn LinkMemory>,
            options,
            bind,
        )
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[tokio::test]
    async fn a_contact_is_written_behind_once_and_not_again_for_the_same_address() {
        let shelf = Shelf::with(Vec::new());
        let memory = memory_over(&shelf, options(8, 4, 1_000_000));
        let device = n("/ann/member/laptop");
        memory.learn(
            key(1),
            device.clone(),
            addr("192.0.2.1:1"),
            Direction::Dialed,
            SystemTime::now(),
        );
        memory.drain().await;
        assert_eq!(
            shelf.kept(&key(1)).unwrap().addresses,
            vec![addr("192.0.2.1:1")]
        );
        assert_eq!(shelf.saves.load(Ordering::SeqCst), 1);
        memory.learn(
            key(1),
            device.clone(),
            addr("192.0.2.1:1"),
            Direction::Dialed,
            SystemTime::now(),
        );
        memory.drain().await;
        assert_eq!(
            shelf.saves.load(Ordering::SeqCst),
            1,
            "nothing changed: nothing written"
        );
        memory.learn(
            key(1),
            device,
            addr("192.0.2.2:2"),
            Direction::Dialed,
            SystemTime::now(),
        );
        memory.drain().await;
        assert_eq!(shelf.saves.load(Ordering::SeqCst), 2);
        assert_eq!(
            shelf.kept(&key(1)).unwrap().addresses,
            vec![addr("192.0.2.2:2"), addr("192.0.2.1:1")]
        );
    }

    #[tokio::test]
    async fn the_records_come_back_at_the_next_start_and_the_expired_are_removed_from_the_store() {
        let now = now_secs();
        let shelf = Shelf::with(vec![record(1, now - 10), record(2, now - 5000)]);
        let memory = memory_over(&shelf, options(8, 4, 1000));
        memory.drain().await;
        let report = memory.report();
        assert_eq!(
            report
                .peers
                .iter()
                .map(|p| p.record.key)
                .collect::<Vec<_>>(),
            vec![key(1)]
        );
        assert!(shelf.kept(&key(1)).is_some());
        assert!(
            shelf.kept(&key(2)).is_none(),
            "a record with no contact for `expires` is removed at start"
        );
    }

    #[tokio::test]
    async fn an_entry_that_expires_while_running_is_pruned_after_the_next_write() {
        let now = now_secs();
        let shelf = Shelf::with(vec![record(1, now - 60)]);
        let memory = memory_over(&shelf, options(8, 4, 100));
        memory.drain().await;
        assert!(shelf.kept(&key(1)).is_some());
        // Time moves on: the record is past `expires` at the next prune, which
        // follows any write.
        {
            let mut inner = memory.inner.lock();
            let slot = inner.book.slots.get_mut(&key(1)).unwrap();
            slot.record.last_contact = at(now - 500);
        }
        memory.learn(
            key(2),
            n("/ann/member/d2"),
            addr("192.0.2.2:2"),
            Direction::Dialed,
            SystemTime::now(),
        );
        memory.drain().await;
        assert!(shelf.kept(&key(1)).is_none());
        assert!(shelf.kept(&key(2)).is_some());
    }

    #[tokio::test]
    async fn forget_removes_durably_and_nothing_written_behind_brings_it_back() {
        let shelf = Shelf::with(Vec::new());
        let memory = memory_over(&shelf, options(8, 4, 1_000_000));
        memory.learn(
            key(1),
            n("/ann/member/laptop"),
            addr("192.0.2.1:1"),
            Direction::Dialed,
            SystemTime::now(),
        );
        // Forgotten before the writer ran: it never writes it, and the store
        // holds nothing when `forget` returns.
        memory.forget(&key(1)).await;
        memory.drain().await;
        assert!(shelf.kept(&key(1)).is_none());
        assert!(memory.report().peers.is_empty());
        // Written, then forgotten.
        memory.learn(
            key(2),
            n("/ann/member/phone"),
            addr("192.0.2.2:2"),
            Direction::Dialed,
            SystemTime::now(),
        );
        memory.drain().await;
        assert!(shelf.kept(&key(2)).is_some());
        memory.forget(&key(2)).await;
        assert!(
            shelf.kept(&key(2)).is_none(),
            "removed before forget returned"
        );
        memory.drain().await;
        assert!(shelf.kept(&key(2)).is_none());
    }

    #[tokio::test]
    async fn a_store_that_fails_is_reported_and_the_memory_keeps_working() {
        let shelf = Shelf::with(Vec::new());
        let memory = memory_over(&shelf, options(8, 4, 1_000_000));
        *shelf.failing.lock() = true;
        memory.learn(
            key(1),
            n("/ann/member/laptop"),
            addr("192.0.2.1:1"),
            Direction::Dialed,
            SystemTime::now(),
        );
        memory.drain().await;
        let report = memory.report();
        assert_eq!(report.peers.len(), 1, "what is learned is kept in memory");
        let words = report.store_error.expect("a failing store is reported");
        assert!(words.contains("disk is full"), "{words}");
        assert!(words.contains("links work without it"), "{words}");
        // The store comes back: the next change is written and the report clears.
        *shelf.failing.lock() = false;
        memory.learn(
            key(1),
            n("/ann/member/laptop"),
            addr("192.0.2.2:2"),
            Direction::Dialed,
            SystemTime::now(),
        );
        memory.drain().await;
        assert_eq!(memory.report().store_error, None);
        assert_eq!(
            shelf.kept(&key(1)).unwrap().addresses[0],
            addr("192.0.2.2:2")
        );
    }

    #[tokio::test]
    async fn a_store_that_cannot_be_read_is_reported_and_starts_empty() {
        let shelf = Shelf::with(vec![record(1, now_secs())]);
        *shelf.failing.lock() = true;
        let memory = memory_over(&shelf, options(8, 4, 1_000_000));
        let report = memory.report();
        assert!(report.peers.is_empty());
        assert!(report.store_error.unwrap().contains("could not be read"));
    }

    #[tokio::test]
    async fn the_bound_on_peers_removes_the_evicted_peer_from_the_store() {
        let shelf = Shelf::with(Vec::new());
        let memory = memory_over(&shelf, options(2, 4, 1_000_000));
        let t = now_secs();
        for (b, dt) in [(1u8, 0u64), (2, 1), (3, 2)] {
            memory.learn(
                key(b),
                n(&format!("/ann/member/d{b}")),
                addr(&format!("192.0.2.{b}:1")),
                Direction::Dialed,
                at(t + dt),
            );
            memory.drain().await;
        }
        assert!(
            shelf.kept(&key(1)).is_none(),
            "the least recently in contact went"
        );
        assert!(shelf.kept(&key(2)).is_some() && shelf.kept(&key(3)).is_some());
    }

    /// L6 (round 6): the filter of the round-4 hint decoder, in the book. A
    /// store, or a link, that offers a loopback or link-local address does
    /// not make this device send datagrams to services on itself or on its
    /// link (169.254.169.254 among them).
    #[test]
    fn loopback_and_link_local_addresses_are_not_kept() {
        let planted = [
            "127.0.0.1:4433",
            "169.254.169.254:80",
            "[fe80::1]:4433",
            "[::1]:4433",
        ];
        let mut record = record(1, 90);
        record.addresses = planted
            .iter()
            .map(|a| addr(a))
            .chain([addr("192.0.2.1:4433")])
            .collect();
        let (mut book, _) = Book::load(options(8, 8, 1000), vec![record], at(100));
        assert_eq!(
            book.get(&key(1)).unwrap().addresses,
            vec![addr("192.0.2.1:4433")],
            "loopback and link-local addresses were read from the store"
        );
        for bad in planted {
            book.learn(
                key(2),
                n("/ann/member/laptop"),
                addr(bad),
                Direction::Dialed,
                at(100),
            );
        }
        assert!(
            book.get(&key(2)).unwrap().addresses.is_empty(),
            "loopback and link-local addresses were learned: {:?}",
            book.get(&key(2)).unwrap().addresses
        );
    }

    /// A host that links devices on one machine (or one link) says so, and
    /// then the addresses of this machine and this link are kept.
    #[test]
    fn a_host_on_one_machine_keeps_loopback_addresses() {
        let mut local = record(1, 90);
        local.addresses = vec![addr("127.0.0.1:4433"), addr("169.254.7.7:4433")];
        let on_one_machine = MemoryOptions {
            include_local: true,
            ..options(8, 8, 1000)
        };
        let (mut book, _) = Book::load(on_one_machine, vec![local], at(100));
        assert_eq!(
            book.get(&key(1)).unwrap().addresses,
            vec![addr("127.0.0.1:4433"), addr("169.254.7.7:4433")]
        );
        book.learn(
            key(2),
            n("/ann/member/laptop"),
            addr("[::1]:4433"),
            Direction::Dialed,
            at(100),
        );
        assert_eq!(
            book.get(&key(2)).unwrap().addresses,
            vec![addr("[::1]:4433")]
        );
        // The unspecified, multicast and broadcast addresses are for nobody.
        for bad in ["0.0.0.0:1", "224.0.0.1:1", "255.255.255.255:1", "[::]:1"] {
            book.learn(
                key(3),
                n("/ann/member/laptop"),
                addr(bad),
                Direction::Dialed,
                at(100),
            );
        }
        assert!(book.get(&key(3)).unwrap().addresses.is_empty());
    }

    /// A host that does not want addresses on disk: the store holds none (and
    /// those it held are written out), and a run still redials the peers it
    /// reached by the addresses it learned.
    #[tokio::test]
    async fn addresses_are_not_written_when_the_host_says_not_to() {
        let shelf = Shelf::with(vec![record(1, now_secs())]);
        assert!(!shelf.kept(&key(1)).unwrap().addresses.is_empty());
        let memory = memory_over(
            &shelf,
            MemoryOptions {
                persist_addresses: false,
                ..options(8, 4, 1_000_000)
            },
        );
        memory.drain().await;
        assert!(
            shelf.kept(&key(1)).unwrap().addresses.is_empty(),
            "an address a store held was not written out of it"
        );
        memory.learn(
            key(2),
            n("/ann/member/laptop"),
            addr("192.0.2.2:4433"),
            Direction::Dialed,
            SystemTime::now(),
        );
        memory.drain().await;
        let kept = shelf.kept(&key(2)).expect("the peer is remembered");
        assert!(
            kept.addresses.is_empty(),
            "an address was written: {:?}",
            kept.addresses
        );
        assert_eq!(kept.device, n("/ann/member/laptop"));
        let in_memory = memory
            .report()
            .peers
            .into_iter()
            .find(|p| p.record.key == key(2))
            .unwrap();
        assert_eq!(
            in_memory.record.addresses,
            vec![addr("192.0.2.2:4433")],
            "this run keeps the address it learned"
        );
        // Another address is no reason to write the record again.
        let before = shelf.saves.load(Ordering::SeqCst);
        memory.learn(
            key(2),
            n("/ann/member/laptop"),
            addr("192.0.2.3:4433"),
            Direction::Dialed,
            SystemTime::now(),
        );
        memory.drain().await;
        assert_eq!(shelf.saves.load(Ordering::SeqCst), before);
    }

    /// L7 (round 6): an accepted link's source address is the peer's own
    /// choice (a fresh port at each reconnect); it never moves a list that
    /// holds addresses, so a peer that reconnects 100 times changes nothing.
    #[test]
    fn an_accepted_link_never_changes_the_addresses_held() {
        let (mut book, _) = Book::load(options(8, 4, 1000), Vec::new(), at(0));
        let device = n("/ann/member/laptop");
        let first = book.learn(
            key(1),
            device.clone(),
            addr("192.0.2.1:4433"),
            Direction::Dialed,
            at(0),
        );
        assert!(first.save);
        for port in 1000..1100u16 {
            let learned = book.learn(
                key(1),
                device.clone(),
                addr(&format!("192.0.2.1:{port}")),
                Direction::Accepted,
                at(1),
            );
            assert!(
                !learned.save,
                "an accepted link from port {port} asked for a write"
            );
        }
        assert_eq!(
            book.get(&key(1)).unwrap().addresses,
            vec![addr("192.0.2.1:4433")],
            "the source ports of accepted links were kept"
        );
        // A peer first met on an accepted link, with no address yet, has the
        // address it came from as the one to try; the next reconnect does not
        // move it.
        book.learn(
            key(2),
            device.clone(),
            addr("192.0.2.2:4433"),
            Direction::Accepted,
            at(0),
        );
        let later = book.learn(
            key(2),
            device,
            addr("192.0.2.2:5555"),
            Direction::Accepted,
            at(1),
        );
        assert!(!later.save);
        assert_eq!(
            book.get(&key(2)).unwrap().addresses,
            vec![addr("192.0.2.2:4433")]
        );
    }

    /// L7 (round 6): a peer reached at one of two addresses and linking again
    /// and again, a hundred times, is a few writes of the store, not a hundred
    /// (flash wear, an fsync each).
    #[tokio::test]
    async fn a_peer_that_links_a_hundred_times_costs_few_writes() {
        let shelf = Shelf::with(Vec::new());
        let memory = memory_over(&shelf, MemoryOptions::default());
        let device = n("/ann/member/laptop");
        for i in 0..100u16 {
            memory.learn(
                key(1),
                device.clone(),
                addr(if i % 2 == 0 {
                    "192.0.2.1:4433"
                } else {
                    "192.0.2.2:4433"
                }),
                Direction::Dialed,
                SystemTime::now(),
            );
            tokio::time::sleep(Duration::from_millis(3)).await;
        }
        let writes = shelf.saves.load(Ordering::SeqCst);
        assert!(
            writes <= 3,
            "a peer that linked 100 times was written {writes} times"
        );
    }

    /// §17D.2: the port a record keeps is the one of the last contact this
    /// device dialled; a peer's own source ports (accepted links) only fill
    /// a port not known yet, so a peer that reconnects from a new port at
    /// every link is not a write at every link.
    #[test]
    fn a_record_keeps_the_listening_port_of_the_contact_this_device_dialled() {
        let (mut book, _) = Book::load(options(8, 4, 1000), Vec::new(), at(0));
        let device = n("/ann/member/laptop");
        let first = book.learn(
            key(1),
            device.clone(),
            addr("192.0.2.1:4433"),
            Direction::Dialed,
            at(0),
        );
        assert!(first.save);
        assert_eq!(book.get(&key(1)).unwrap().port, Some(4433));
        for port in 1000..1100u16 {
            let learned = book.learn(
                key(1),
                device.clone(),
                addr(&format!("192.0.2.1:{port}")),
                Direction::Accepted,
                at(1),
            );
            assert!(
                !learned.save,
                "an accepted link from port {port} asked for a write"
            );
        }
        assert_eq!(book.get(&key(1)).unwrap().port, Some(4433));
        // Dialled at a new port (the peer restarted on it): the port moves,
        // and the record is to be saved.
        let moved = book.learn(
            key(1),
            device.clone(),
            addr("192.0.2.1:5000"),
            Direction::Dialed,
            at(2),
        );
        assert!(moved.save);
        assert_eq!(book.get(&key(1)).unwrap().port, Some(5000));
        // A direct path whose far end is at a port says the same, and an
        // unusable port says nothing.
        assert!(book.set_port(&key(1), 6000));
        assert!(!book.set_port(&key(1), 6000), "nothing changed");
        assert!(!book.set_port(&key(1), 0));
        assert!(!book.set_port(&key(9), 6000), "no record, no port");
        assert_eq!(book.get(&key(1)).unwrap().port, Some(6000));
    }

    /// §17D.2 under `persist_addresses = false`: no port is read from the
    /// store, and a change of it asks for no write; what a run learns lives
    /// in memory for that run, as the addresses do.
    #[test]
    fn the_record_port_is_not_kept_when_the_addresses_are_not() {
        let off = MemoryOptions {
            persist_addresses: false,
            ..options(8, 4, 1000)
        };
        let (mut book, _) = Book::load(off, vec![record(1, 10)], at(20));
        assert_eq!(book.get(&key(1)).unwrap().port, None, "dropped at load");
        let device = n("/ann/member/d1");
        let learned = book.learn(
            key(1),
            device,
            addr("192.0.2.1:7000"),
            Direction::Dialed,
            at(21),
        );
        assert!(
            !learned.save,
            "a port that is not persisted is no reason to write"
        );
        assert_eq!(
            book.get(&key(1)).unwrap().port,
            Some(7000),
            "kept for this run"
        );
        assert!(
            !book.set_port(&key(1), 7001),
            "and no write for a direct path's either"
        );
    }

    /// §17D.2: the contacts' reports are bounded, newest first, never at an
    /// address already kept or one a dial would not use, and dialled at the
    /// peer's port before the addresses that worked.
    #[tokio::test]
    async fn reported_addresses_are_dialled_at_the_last_known_port_before_the_kept_ones() {
        let shelf = Shelf::with(vec![record(1, now_secs())]);
        let memory = memory_over(&shelf, options(8, 4, 1_000_000));
        let device = n("/ann/member/d1");
        {
            let mut inner = memory.inner.lock();
            inner.report(key(1), "192.0.2.1".parse().unwrap(), false); // already kept
            inner.report(key(1), "127.0.0.1".parse().unwrap(), false); // local
            inner.report(key(1), "198.51.100.1".parse().unwrap(), false);
            inner.report(key(1), "198.51.100.2".parse().unwrap(), false);
            inner.report(key(1), "198.51.100.3".parse().unwrap(), false);
            inner.report(key(1), "198.51.100.2".parse().unwrap(), false);
        }
        let kept = memory.record(&key(1)).unwrap();
        assert_eq!(kept.device, device);
        assert_eq!(
            memory.dial_list(&kept),
            vec![
                addr("198.51.100.2:4433"),
                addr("198.51.100.3:4433"),
                addr("192.0.2.1:4433")
            ],
            "two reports at most (newest first), then what worked"
        );
        // With no port known, a reported IP has nowhere to be tried.
        let no_port = PeerRecord { port: None, ..kept };
        assert_eq!(memory.dial_list(&no_port), vec![addr("192.0.2.1:4433")]);
    }

    /// §17D.2: the listening port is kept with the memory and written behind.
    /// The socket takes the kept port again; what it listens on after that is
    /// owed the store when it is not the kept one, and nothing is written when
    /// it is.
    #[tokio::test]
    async fn the_listening_port_is_kept_when_it_changed_and_not_written_when_it_did_not() {
        // Nothing kept yet: the port in use is written.
        let shelf = Shelf::with(Vec::new());
        let memory = memory_binding(&shelf, options(8, 4, 1_000_000), |kept| {
            assert_eq!(kept, None);
            Some(5000)
        });
        memory.drain().await;
        assert_eq!(*shelf.port.lock(), Some(5000));
        // The same port at the next start: told what was kept, and no write.
        let again = memory_binding(&shelf, options(8, 4, 1_000_000), |kept| {
            assert_eq!(kept, Some(5000));
            Some(5000)
        });
        again.drain().await;
        assert_eq!(
            *shelf.port_writes.lock(),
            vec![Some(5000)],
            "no second write"
        );
        // The kept port was taken: the one in use is the one kept now.
        let moved = memory_binding(&shelf, options(8, 4, 1_000_000), |kept| {
            assert_eq!(kept, Some(5000));
            Some(6000)
        });
        moved.drain().await;
        assert_eq!(*shelf.port.lock(), Some(6000));
        // A host whose socket does not listen has no port to keep.
        let dial_only = memory_binding(&shelf, options(8, 4, 1_000_000), |_| None);
        dial_only.drain().await;
        assert_eq!(*shelf.port.lock(), Some(6000), "a dial-only host leaves it");
    }

    /// §17D.2: under `persist_addresses = false` no port is kept, the memory
    /// does not hand the kept one to the socket, and one written before is
    /// removed.
    #[tokio::test]
    async fn no_port_is_written_when_the_host_says_not_to_and_one_written_before_goes() {
        let shelf = Shelf::with(Vec::new());
        *shelf.port.lock() = Some(5000);
        let off = MemoryOptions {
            persist_addresses: false,
            ..options(8, 4, 1_000_000)
        };
        let memory = memory_binding(&shelf, off, |kept| {
            assert_eq!(
                kept, None,
                "a port kept before is not used when nothing is kept"
            );
            Some(7000)
        });
        memory.drain().await;
        assert_eq!(
            *shelf.port.lock(),
            None,
            "the one written earlier is removed"
        );
        assert_eq!(
            *shelf.port_writes.lock(),
            vec![None],
            "and no port was ever written: {:?}",
            shelf.port_writes.lock()
        );
    }

    /// §17D.2: a store that cannot say what port it kept is said in the report
    /// and the port in use is kept for when it works again.
    #[tokio::test]
    async fn a_store_that_cannot_be_read_is_reported_and_the_port_is_written_when_it_works() {
        let shelf = Shelf::with(Vec::new());
        *shelf.failing.lock() = true;
        let memory = memory_binding(&shelf, options(8, 4, 1_000_000), |kept| {
            assert_eq!(kept, None);
            Some(5000)
        });
        memory.drain().await;
        let said = memory
            .report()
            .store_error
            .expect("the failure is reported");
        assert!(said.contains("could not"), "{said}");
        assert_eq!(*shelf.port.lock(), None);
        *shelf.failing.lock() = false;
        memory.drain().await;
        assert_eq!(
            *shelf.port.lock(),
            Some(5000),
            "owed until the store worked"
        );
    }
}
