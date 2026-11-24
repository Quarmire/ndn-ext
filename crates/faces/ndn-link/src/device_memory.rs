//! A data-layer node's store as the link memory (feature `introductions`;
//! `ndn-rs/docs/specs/ndn-link.md` §17C.4): one note per peer, named by the
//! peer's key in hex, at `/localhost/ndn-link/memory/<key>` in the node's
//! [`DataStore`] (a prefix no device serves; the value is the note's octets).
//!
//! The note is local, unauthenticated host data: what it holds is a hint and
//! decides nothing, so a note that does not decode is dropped, and a note whose
//! key is not the one it is named by is dropped too (a record is only ever read
//! as the key it names). A note is durable once `save` or `remove` returns: the
//! store's barrier ([`DataStore::sync`]) passed, on a blocking thread.
//!
//! The note holds the peer's key, its device name and its last-seen addresses
//! in the clear (data-layer.md §19.9 rule 6): the permissions of the device's
//! store are the host's to set, and `MemoryOptions::persist_addresses` keeps
//! the addresses out of it.
//!
//! The value, version 2 (version 1, the same without the last field, is still
//! read), all integers big-endian:
//!
//! | octets | |
//! |---|---|
//! | 1 | version, `1` |
//! | 1 | origin: `0` this device dialled, `1` the peer dialled in |
//! | 8 | last contact, seconds since the Unix epoch |
//! | 32 | the peer's key fingerprint |
//! | 2 + n | the device's name, as a Name TLV, `n` octets |
//! | 1 + … | the address count (at most 255), then for each: `4` or `6`, the address (4 or 16 octets), the port (2) |
//! | 2 | the peer's last-known listening port, `0` for none (version 2 only; ndn-link.md §17D.2) |
//!
//! The port this device listens on is one more local note of the same area,
//! `listen-port`: 2 octets, big-endian, never served, written and removed
//! under the same durability and the same
//! [`MemoryOptions::persist_addresses`](crate::MemoryOptions::persist_addresses)
//! option as the addresses.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, UNIX_EPOCH};

use bytes::Bytes;
use ndn_face_quic::{Direction, KeyFingerprint};
use ndn_packet::{Name, NameComponent};
use ndn_sync::DataStore;

use crate::memory::{LinkMemory, MemoryFuture, PeerRecord};

/// The longest key of a note, in octets.
const NOTE_PART_MAX: usize = 64;

/// The largest value of a note, in octets.
const NOTE_VALUE_MAX: usize = 4096;

/// How many notes the link memory holds.
const NOTES_PER_AREA_MAX: usize = 1024;

/// Notes are counted and written under this lock, not in the store's: counting
/// the notes reads them from the store. It is shared by every memory of the
/// process, as two of them may keep one store; a note's write is a store write
/// and nothing else.
static WRITING: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

/// The prefix of the link memory's notes in the store.
static AREA: LazyLock<Name> =
    LazyLock::new(|| "/localhost/ndn-link/memory".parse().expect("a valid name"));

/// Why a note was not read, kept or removed.
#[derive(Debug)]
enum NoteError {
    /// The key or the value breaks a rule, or the area is full: nothing was
    /// written. `why` says which rule and what to do.
    Refused { name: Name, why: String },
    /// The store could not make the write durable. The write is in the store
    /// and not known to be durable.
    Local { reason: String },
}

impl std::fmt::Display for NoteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NoteError::Refused { name, why } => write!(f, "{name}: {why}"),
            NoteError::Local { reason } => write!(f, "local failure: {reason}"),
        }
    }
}

impl std::error::Error for NoteError {}

/// `key` as a part of a note's name the rules allow, or the rule it breaks.
fn check_key(key: &str) -> Result<(), NoteError> {
    let refuse = |why: String| NoteError::Refused {
        name: AREA.clone(),
        why: format!(
            "a note key {key:?} {why}; use 1 to {NOTE_PART_MAX} octets with no '/' and no \
             control character"
        ),
    };
    if key.is_empty() {
        return Err(refuse("is empty".into()));
    }
    if key.len() > NOTE_PART_MAX {
        return Err(refuse(format!("is {} octets long", key.len())));
    }
    if key.contains('/') {
        return Err(refuse("contains a '/'".into()));
    }
    if key.chars().any(char::is_control) {
        return Err(refuse("contains a control character".into()));
    }
    Ok(())
}

fn note_name(key: &str) -> Name {
    AREA.clone()
        .append_component(NameComponent::generic(Bytes::copy_from_slice(
            key.as_bytes(),
        )))
}

/// The notes of the link memory in a store: small values by key, durable once
/// [`put`](Self::put) or [`remove`](Self::remove) returns. Cheap to clone.
#[derive(Clone)]
struct Notes {
    store: Arc<dyn DataStore>,
}

impl Notes {
    /// The note `key`: `None` when there is none, [`NoteError::Refused`] when
    /// the key breaks a rule.
    fn get(&self, key: &str) -> Result<Option<Bytes>, NoteError> {
        check_key(key)?;
        Ok(self.store.get(&note_name(key)))
    }

    /// Every note, `(key, value)` by key.
    fn list(&self) -> Result<Vec<(String, Bytes)>, NoteError> {
        Ok(self.listed())
    }

    fn listed(&self) -> Vec<(String, Bytes)> {
        let depth = AREA.components().len();
        let mut out: Vec<(String, Bytes)> = self
            .store
            .scan_under(&AREA, 0)
            .into_iter()
            .filter_map(|(name, value)| {
                let comps = name.components();
                if comps.len() != depth + 1 {
                    return None;
                }
                let key = std::str::from_utf8(&comps[depth].value).ok()?.to_owned();
                Some((key, value))
            })
            .collect();
        out.sort();
        out
    }

    /// Keep `value` as the note `key`, replacing one: returns once the store's
    /// durability barrier passed, so a note a `put` returned for survives a
    /// power loss.
    ///
    /// [`NoteError::Refused`] when the key breaks a rule, when `value` is over
    /// [`NOTE_VALUE_MAX`] octets, or when the memory holds
    /// [`NOTES_PER_AREA_MAX`] notes already and `key` is not one of them
    /// (remove one first); nothing is written. [`NoteError::Local`] when the
    /// store cannot make the write durable.
    async fn put(&self, key: &str, value: &[u8]) -> Result<(), NoteError> {
        check_key(key)?;
        if value.len() > NOTE_VALUE_MAX {
            return Err(NoteError::Refused {
                name: note_name(key),
                why: format!(
                    "a note's value is at most {NOTE_VALUE_MAX} octets and this is {}; keep \
                     less in a note",
                    value.len()
                ),
            });
        }
        let name = note_name(key);
        {
            // The count and the write are one step: two puts cannot both take
            // the last place.
            let _write = WRITING.lock();
            if !self.store.contains(&name) && self.listed().len() >= NOTES_PER_AREA_MAX {
                return Err(NoteError::Refused {
                    name,
                    why: format!(
                        "the link memory holds {NOTES_PER_AREA_MAX} notes already, the most it \
                         may; remove one before keeping another"
                    ),
                });
            }
            self.store.insert(name, Bytes::copy_from_slice(value));
        }
        self.barrier().await
    }

    /// Remove the note `key` (none is not an error): returns once the store's
    /// durability barrier passed, so a removal that returned is not undone by
    /// a power loss. Refusals as [`put`](Self::put).
    async fn remove(&self, key: &str) -> Result<(), NoteError> {
        check_key(key)?;
        {
            let _write = WRITING.lock();
            self.store.remove(&note_name(key));
        }
        self.barrier().await
    }

    /// The store's barrier: inline for a store that says it touches no disk,
    /// on a blocking thread otherwise (it waits for the disk).
    async fn barrier(&self) -> Result<(), NoteError> {
        let synced = if self.store.sync_is_immediate() {
            self.store.sync()
        } else {
            let store = Arc::clone(&self.store);
            tokio::task::spawn_blocking(move || store.sync())
                .await
                .map_err(|e| NoteError::Local {
                    reason: format!(
                        "the store's barrier did not finish ({e}); the note is not known to be \
                         durable: try again after the runtime is running"
                    ),
                })?
        };
        synced.map_err(|e| NoteError::Local {
            reason: format!(
                "the store could not make the note durable ({e}); the note is not known to be \
                 durable: try again, and if it keeps failing check the store's disk"
            ),
        })
    }
}

const VERSION: u8 = 2;
/// The records of the first version have no port.
const VERSION_1: u8 = 1;

/// The key of the note that holds the port this device listens on: not a peer
/// key (those are 64 hexadecimal digits), so no record is named by it.
const LISTEN_PORT_KEY: &str = "listen-port";

/// The link memory kept in a node's [`DataStore`]: one record per peer key,
/// written behind the store's barrier. Give it to
/// [`Links::remember`](crate::Links::remember).
pub struct DeviceMemory {
    notes: Notes,
}

impl DeviceMemory {
    /// The link memory in `store` (a data-layer node's store, `Node::store()`):
    /// what an earlier memory over the same store wrote is read back.
    pub fn new(store: Arc<dyn DataStore>) -> Arc<Self> {
        Arc::new(Self {
            notes: Notes { store },
        })
    }
}

impl LinkMemory for DeviceMemory {
    fn load(&self) -> Result<Vec<PeerRecord>, String> {
        let listed = self.notes.list().map_err(|e| e.to_string())?;
        let mut records = Vec::with_capacity(listed.len());
        let mut dropped = Vec::new();
        for (name, value) in listed {
            // The port this device listens on is no record: it is read by
            // `load_listen_port`, and not dropped here.
            if name == LISTEN_PORT_KEY {
                continue;
            }
            match decode(&value) {
                Ok(record) if record.key.to_string() == name => records.push(record),
                Ok(record) => {
                    tracing::warn!(
                        target: "face.quic",
                        "a link memory note named {name} holds the record of {}: dropped",
                        record.key
                    );
                    dropped.push(name);
                }
                Err(why) => {
                    tracing::warn!(
                        target: "face.quic",
                        "a link memory note named {name} cannot be read ({why}): dropped"
                    );
                    dropped.push(name);
                }
            }
        }
        // What cannot be read is removed, behind: a note nothing will ever
        // read should not take a place of the area.
        if !dropped.is_empty()
            && let Ok(runtime) = tokio::runtime::Handle::try_current()
        {
            let notes = self.notes.clone();
            runtime.spawn(async move {
                for name in dropped {
                    if let Err(e) = notes.remove(&name).await {
                        tracing::warn!(
                            target: "face.quic",
                            "a link memory note that cannot be read stays: {e}"
                        );
                        break;
                    }
                }
            });
        }
        Ok(records)
    }

    fn save<'a>(&'a self, record: &'a PeerRecord) -> MemoryFuture<'a, Result<(), String>> {
        Box::pin(async move {
            let value = encode(record);
            self.notes
                .put(&record.key.to_string(), &value)
                .await
                .map_err(|e| e.to_string())
        })
    }

    fn remove<'a>(&'a self, key: &'a KeyFingerprint) -> MemoryFuture<'a, Result<(), String>> {
        Box::pin(async move {
            self.notes
                .remove(&key.to_string())
                .await
                .map_err(|e| e.to_string())
        })
    }

    fn load_listen_port(&self) -> Result<Option<u16>, String> {
        let Some(value) = self.notes.get(LISTEN_PORT_KEY).map_err(|e| e.to_string())? else {
            return Ok(None);
        };
        match <[u8; 2]>::try_from(value.as_ref()) {
            Ok(octets) => Ok(Some(u16::from_be_bytes(octets)).filter(|port| *port != 0)),
            Err(_) => {
                // A hint that decides nothing: dropped as an unreadable record is.
                tracing::warn!(
                    target: "face.quic",
                    "the link memory's listen-port note holds {} octets, not 2: dropped",
                    value.len()
                );
                Ok(None)
            }
        }
    }

    fn save_listen_port<'a>(&'a self, port: Option<u16>) -> MemoryFuture<'a, Result<(), String>> {
        Box::pin(async move {
            match port {
                Some(port) => self
                    .notes
                    .put(LISTEN_PORT_KEY, &port.to_be_bytes())
                    .await
                    .map_err(|e| e.to_string()),
                None => self
                    .notes
                    .remove(LISTEN_PORT_KEY)
                    .await
                    .map_err(|e| e.to_string()),
            }
        })
    }
}

/// `record` as a note's value.
pub(crate) fn encode(record: &PeerRecord) -> Vec<u8> {
    let mut out = vec![
        VERSION,
        match record.origin {
            Direction::Dialed => 0,
            Direction::Accepted => 1,
        },
    ];
    let seconds = record
        .last_contact
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    out.extend_from_slice(&seconds.to_be_bytes());
    out.extend_from_slice(&record.key.0);
    let device = record.device.encode_to_tlv();
    out.extend_from_slice(
        &u16::try_from(device.len())
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    out.extend_from_slice(&device);
    let addresses = &record.addresses[..record.addresses.len().min(255)];
    out.push(addresses.len() as u8);
    for addr in addresses {
        match addr.ip() {
            IpAddr::V4(ip) => {
                out.push(4);
                out.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                out.push(6);
                out.extend_from_slice(&ip.octets());
            }
        }
        out.extend_from_slice(&addr.port().to_be_bytes());
    }
    out.extend_from_slice(&record.port.unwrap_or(0).to_be_bytes());
    out
}

/// A reader over a note's value that refuses to read past its end.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.0.len() < n {
            return Err(format!(
                "it ends {} octets short",
                n.saturating_sub(self.0.len())
            ));
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], String> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }
}

/// A note's value as a record, or why not. Never panics: any octets are
/// either a record or refused.
pub(crate) fn decode(value: &[u8]) -> Result<PeerRecord, String> {
    let mut r = Reader(value);
    let [version, origin] = r.array::<2>()?;
    if version != VERSION && version != VERSION_1 {
        return Err(format!(
            "it is version {version}, and this reads versions {VERSION_1} and {VERSION}"
        ));
    }
    let origin = match origin {
        0 => Direction::Dialed,
        1 => Direction::Accepted,
        other => return Err(format!("its origin is {other}, not 0 or 1")),
    };
    let seconds = u64::from_be_bytes(r.array()?);
    let last_contact = UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .ok_or_else(|| format!("its last contact, {seconds} s after 1970, is out of range"))?;
    let key = KeyFingerprint(r.array()?);
    let length = usize::from(u16::from_be_bytes(r.array()?));
    let device = Name::decode_from_tlv(Bytes::copy_from_slice(r.take(length)?))
        .map_err(|e| format!("its device name is not a Name: {e:?}"))?;
    let [count] = r.array::<1>()?;
    let mut addresses = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        let [family] = r.array::<1>()?;
        let ip = match family {
            4 => IpAddr::V4(Ipv4Addr::from(r.array::<4>()?)),
            6 => IpAddr::V6(Ipv6Addr::from(r.array::<16>()?)),
            other => return Err(format!("an address is of family {other}, not 4 or 6")),
        };
        addresses.push(SocketAddr::new(ip, u16::from_be_bytes(r.array()?)));
    }
    let port = if version == VERSION {
        Some(u16::from_be_bytes(r.array()?)).filter(|port| *port != 0)
    } else {
        None
    };
    if !r.0.is_empty() {
        return Err(format!("{} octets follow the last address", r.0.len()));
    }
    Ok(PeerRecord {
        key,
        device,
        addresses,
        port,
        last_contact,
        origin,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> PeerRecord {
        PeerRecord {
            key: KeyFingerprint([7; 32]),
            device: "/ann/member/laptop".parse().unwrap(),
            addresses: vec![
                "192.0.2.7:4433".parse().unwrap(),
                "[2001:db8::1]:4433".parse().unwrap(),
            ],
            last_contact: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            origin: Direction::Accepted,
            port: Some(4433),
        }
    }

    #[test]
    fn a_record_round_trips() {
        let r = record();
        assert_eq!(decode(&encode(&r)).unwrap(), r);
        let none = PeerRecord {
            addresses: Vec::new(),
            origin: Direction::Dialed,
            ..record()
        };
        assert_eq!(decode(&encode(&none)).unwrap(), none);
    }

    /// A record written before the port was kept (version 1: the value ends
    /// with the addresses) is still read, with no port; one written now has
    /// the port, and a record with none reads back with none.
    #[test]
    fn a_version_1_record_is_read_with_no_port_and_the_port_round_trips() {
        let r = record();
        let mut v1 = encode(&r);
        v1.truncate(v1.len() - 2);
        v1[0] = 1;
        assert_eq!(
            decode(&v1).unwrap(),
            PeerRecord {
                port: None,
                ..r.clone()
            },
            "version 1 has no port"
        );
        assert_eq!(encode(&r)[0], 2, "records are written as version 2");
        assert_eq!(decode(&encode(&r)).unwrap().port, Some(4433));
        let none = PeerRecord { port: None, ..r };
        assert_eq!(decode(&encode(&none)).unwrap().port, None);
        // A version-1 value that carries the version 2 field is not version 1.
        let mut padded = v1.clone();
        padded.extend_from_slice(&[0x11, 0x51]);
        assert!(decode(&padded).unwrap_err().contains("follow"));
    }

    #[test]
    fn garbage_is_refused_and_never_panics() {
        let good = encode(&record());
        // Every cut of a good value, and every single-octet change of it,
        // is a record or a refusal.
        for cut in 0..good.len() {
            assert!(decode(&good[..cut]).is_err(), "cut at {cut}");
        }
        for at in 0..good.len() {
            for flip in [0x01, 0x80, 0xff] {
                let mut bad = good.clone();
                bad[at] ^= flip;
                let _ = decode(&bad);
            }
        }
        let mut long = good.clone();
        long.push(0);
        assert!(decode(&long).unwrap_err().contains("follow"));
        let mut other_version = good.clone();
        other_version[0] = 3;
        assert!(decode(&other_version).unwrap_err().contains("version 3"));
        // Octets from a generator, of every length up to 300.
        let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
        for len in 0..300 {
            let junk: Vec<u8> = (0..len)
                .map(|_| {
                    seed = seed
                        .wrapping_mul(6_364_136_223_846_793_005)
                        .wrapping_add(1_442_695_040_888_963_407);
                    (seed >> 33) as u8
                })
                .collect();
            let _ = decode(&junk);
        }
        assert!(decode(&[]).is_err());
    }
}

#[cfg(test)]
#[path = "device_memory_store_tests.rs"]
mod store_tests;
