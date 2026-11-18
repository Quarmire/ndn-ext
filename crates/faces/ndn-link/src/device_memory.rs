//! A data-layer device's local notes as the link memory (feature
//! `introductions`; `ndn-rs/docs/specs/ndn-link.md` §17C.4): one note per peer,
//! under the area `link-memory`, named by the peer's key in hex.
//!
//! The note is local, unauthenticated host data ([`ndn_data::device::LocalNotes`]):
//! what it holds is a hint and decides nothing, so a note that does not decode
//! is dropped, and a note whose key is not the one it is named by is dropped
//! too (a record is only ever read as the key it names).
//!
//! The value, version 1, all integers big-endian:
//!
//! | octets | |
//! |---|---|
//! | 1 | version, `1` |
//! | 1 | origin: `0` this device dialled, `1` the peer dialled in |
//! | 8 | last contact, seconds since the Unix epoch |
//! | 32 | the peer's key fingerprint |
//! | 2 + n | the device's name, as a Name TLV, `n` octets |
//! | 1 + … | the address count (at most 255), then for each: `4` or `6`, the address (4 or 16 octets), the port (2) |

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use bytes::Bytes;
use ndn_data::Device;
use ndn_data::device::LocalNotes;
use ndn_face_quic::{Direction, KeyFingerprint};
use ndn_packet::Name;

use crate::memory::{LinkMemory, MemoryFuture, PeerRecord};

/// The area of the device's notes the link memory keeps its records in.
pub const AREA: &str = "link-memory";

const VERSION: u8 = 1;

/// The link memory kept in a [`Device`]'s local notes: one record per peer
/// key, written behind the device's store barrier. Give it to
/// [`Links::remember`](crate::Links::remember).
pub struct DeviceMemory {
    notes: LocalNotes,
}

impl DeviceMemory {
    /// The link memory in `device`'s local store.
    pub fn new(device: &Device) -> Arc<Self> {
        Arc::new(Self {
            notes: device.local_notes(AREA),
        })
    }
}

impl LinkMemory for DeviceMemory {
    fn load(&self) -> Result<Vec<PeerRecord>, String> {
        let listed = self.notes.list().map_err(|e| e.to_string())?;
        let mut records = Vec::with_capacity(listed.len());
        let mut dropped = Vec::new();
        for (name, value) in listed {
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
    if version != VERSION {
        return Err(format!(
            "it is version {version}, and this reads version {VERSION}"
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
    if !r.0.is_empty() {
        return Err(format!("{} octets follow the last address", r.0.len()));
    }
    Ok(PeerRecord {
        key,
        device,
        addresses,
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
        other_version[0] = 2;
        assert!(decode(&other_version).unwrap_err().contains("version 2"));
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
