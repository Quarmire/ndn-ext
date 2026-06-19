//! TLV codec for ndn-dv distance-vector routing.
//!
//! Wire format per `ndnd/dv/SPEC.md` §3. Type codes pinned against
//! `ndnd/dv/tlv/definitions.go`.

#![allow(clippy::result_large_err)]

use std::fmt;

use bytes::Bytes;
use ndn_packet::{Name, decode_nni, tlv_type};
use ndn_tlv::{TlvReader, TlvWriter};

pub const T_ADVERTISEMENT: u64 = 201;
pub const T_ADV_ENTRY: u64 = 202;
/// Reused as `ExitRouter` inside `PrefixOpList`.
pub const T_DESTINATION: u64 = 204;
pub const T_NEXT_HOP: u64 = 206;
/// Also used inside `PrefixOpAdd`.
pub const T_COST: u64 = 208;
pub const T_OTHER_COST: u64 = 210;
pub const T_PREFIX_OP_LIST: u64 = 301;
/// Empty value; presence is the signal.
pub const T_PREFIX_OP_RESET: u64 = 302;
pub const T_PREFIX_OP_ADD: u64 = 304;
pub const T_PREFIX_OP_REMOVE: u64 = 306;

/// `Status` field codes — `Status` has no outer wrapper in ndnd's encoder;
/// the Data Content directly holds the field sequence
/// (`ndnd/dv/tlv/definitions.go:57-70`).
pub const T_VERSION: u64 = 0x191;
pub const T_NETWORK_NAME: u64 = 0x193;
pub const T_ROUTER_NAME: u64 = 0x195;
pub const T_N_RIB_ENTRIES: u64 = 0x197;
pub const T_N_NEIGHBORS: u64 = 0x199;
pub const T_N_FIB_ENTRIES: u64 = 0x19B;

#[derive(Debug, PartialEq, Eq)]
pub enum DvTlvError {
    Malformed,
    WrongType {
        expected: u64,
        got: u64,
    },
    MissingField(&'static str),
    /// NonNegativeInteger width was not 1, 2, 4, or 8 octets.
    InvalidNniWidth(usize),
}

impl fmt::Display for DvTlvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DvTlvError::Malformed => write!(f, "malformed ndn-dv TLV"),
            DvTlvError::WrongType { expected, got } => {
                write!(f, "expected ndn-dv TLV type {expected}, got {got}")
            }
            DvTlvError::MissingField(name) => write!(f, "required ndn-dv field missing: {name}"),
            DvTlvError::InvalidNniWidth(n) => {
                write!(
                    f,
                    "NonNegativeInteger width must be 1/2/4/8 octets, got {n}"
                )
            }
        }
    }
}

impl std::error::Error for DvTlvError {}

/// A router's full advertisement; content of an
/// `/localhop/<router>/32=DV/32=ADV/...` Data packet (SPEC.md §2).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Advertisement {
    pub entries: Vec<AdvEntry>,
}

/// Reachability info for one destination router.
///
/// Per SPEC.md §4 *Advertisement Computation*, `other_cost` is the cost
/// via the second-best next-hop (used by neighbours doing poison reverse).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdvEntry {
    pub destination: Name,
    pub next_hop: Name,
    pub cost: u64,
    pub other_cost: u64,
}

/// Sender's prefix-table operations, propagated through the global
/// `/<network>/32=DV/32=PFS/32=svs` SVS group (SPEC.md §4 *Prefix Sync*).
/// Operations are processed in strict sequence order at receivers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrefixOpList {
    /// Router whose prefix table this `PrefixOpList` updates.
    /// Wire-encoded inside a `Destination` TLV (type 204).
    pub exit_router: Name,
    /// Sent on router startup to clear stale entries at all peers.
    pub reset: bool,
    pub adds: Vec<PrefixOpAdd>,
    pub removes: Vec<PrefixOpRemove>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrefixOpAdd {
    pub name: Name,
    pub cost: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrefixOpRemove {
    pub name: Name,
}

/// `PrefixOpList` is boxed because it carries the full prefix-table
/// operation list and is only sent on prefix-table changes — keeping
/// the enum compact on the hotter advertisement path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Packet {
    Advertisement(Advertisement),
    PrefixOpList(Box<PrefixOpList>),
}

impl Packet {
    pub fn encode(&self) -> Bytes {
        match self {
            Packet::Advertisement(a) => a.encode(),
            Packet::PrefixOpList(p) => p.encode(),
        }
    }

    pub fn decode(bytes: &Bytes) -> Result<Self, DvTlvError> {
        let mut r = TlvReader::new(bytes.clone());
        let (typ, value) = r.read_tlv().map_err(|_| DvTlvError::Malformed)?;
        match typ {
            T_ADVERTISEMENT => Ok(Packet::Advertisement(Advertisement::decode_value(value)?)),
            T_PREFIX_OP_LIST => Ok(Packet::PrefixOpList(Box::new(PrefixOpList::decode_value(
                value,
            )?))),
            other => Err(DvTlvError::WrongType {
                expected: T_ADVERTISEMENT,
                got: other,
            }),
        }
    }
}

/// NDN NonNegativeInteger: shortest big-endian representation
/// (1, 2, 4, or 8 octets).
fn encode_nni(value: u64) -> Vec<u8> {
    if value <= 0xFF {
        vec![value as u8]
    } else if value <= 0xFFFF {
        (value as u16).to_be_bytes().to_vec()
    } else if value <= 0xFFFF_FFFF {
        (value as u32).to_be_bytes().to_vec()
    } else {
        value.to_be_bytes().to_vec()
    }
}

fn write_nni_tlv(w: &mut TlvWriter, typ: u64, value: u64) {
    w.write_tlv(typ, &encode_nni(value));
}

/// Wrap a `Name` inside an outer TLV (`Destination`, `NextHop`, or
/// `ExitRouter` — all share this shape per SPEC.md §3).
fn write_name_field(w: &mut TlvWriter, outer_type: u64, name: &Name) {
    w.write_nested(outer_type, |inner| {
        inner.write_raw(&name.encode_to_tlv());
    });
}

fn decode_name_field(value: Bytes) -> Result<Name, DvTlvError> {
    Name::decode_from_tlv(value).map_err(|_| DvTlvError::Malformed)
}

fn decode_nni_value(value: &Bytes) -> Result<u64, DvTlvError> {
    decode_nni(value).map_err(|_| DvTlvError::InvalidNniWidth(value.len()))
}

impl Advertisement {
    /// Encode as a full `Advertisement` TLV including the outer 201 wrapper.
    /// Use when the bytes are nested inside [`Packet`].
    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        self.write_into(&mut w);
        w.finish()
    }

    /// Encode without the outer 201 wrapper — just the concatenated
    /// `AdvEntry` TLVs. Mirrors ndnd's `AdvertisementEncoder::EncodeInto`
    /// which emits each entry as a bare 0xCA TLV.
    pub fn encode_content(&self) -> Bytes {
        let mut w = TlvWriter::new();
        for entry in &self.entries {
            entry.write_into(&mut w);
        }
        w.finish()
    }

    pub fn decode_content(bytes: &Bytes) -> Result<Self, DvTlvError> {
        Self::decode_value(bytes.clone())
    }

    pub fn decode(bytes: &Bytes) -> Result<Self, DvTlvError> {
        let mut r = TlvReader::new(bytes.clone());
        let (typ, value) = r.read_tlv().map_err(|_| DvTlvError::Malformed)?;
        if typ != T_ADVERTISEMENT {
            return Err(DvTlvError::WrongType {
                expected: T_ADVERTISEMENT,
                got: typ,
            });
        }
        Self::decode_value(value)
    }

    pub fn decode_value(value: Bytes) -> Result<Self, DvTlvError> {
        let mut entries = Vec::new();
        let mut r = TlvReader::new(value);
        while !r.is_empty() {
            let (typ, v) = r.read_tlv().map_err(|_| DvTlvError::Malformed)?;
            if typ != T_ADV_ENTRY {
                return Err(DvTlvError::WrongType {
                    expected: T_ADV_ENTRY,
                    got: typ,
                });
            }
            entries.push(AdvEntry::decode_value(v)?);
        }
        Ok(Advertisement { entries })
    }

    fn write_into(&self, w: &mut TlvWriter) {
        w.write_nested(T_ADVERTISEMENT, |inner| {
            for entry in &self.entries {
                entry.write_into(inner);
            }
        });
    }
}

impl AdvEntry {
    fn write_into(&self, w: &mut TlvWriter) {
        w.write_nested(T_ADV_ENTRY, |inner| {
            write_name_field(inner, T_DESTINATION, &self.destination);
            write_name_field(inner, T_NEXT_HOP, &self.next_hop);
            write_nni_tlv(inner, T_COST, self.cost);
            write_nni_tlv(inner, T_OTHER_COST, self.other_cost);
        });
    }

    fn decode_value(value: Bytes) -> Result<Self, DvTlvError> {
        let mut destination: Option<Name> = None;
        let mut next_hop: Option<Name> = None;
        let mut cost: Option<u64> = None;
        let mut other_cost: Option<u64> = None;
        let mut r = TlvReader::new(value);
        while !r.is_empty() {
            let (typ, v) = r.read_tlv().map_err(|_| DvTlvError::Malformed)?;
            match typ {
                T_DESTINATION => destination = Some(decode_name_field(v)?),
                T_NEXT_HOP => next_hop = Some(decode_name_field(v)?),
                T_COST => cost = Some(decode_nni_value(&v)?),
                T_OTHER_COST => other_cost = Some(decode_nni_value(&v)?),
                _ => {}
            }
        }
        Ok(AdvEntry {
            destination: destination.ok_or(DvTlvError::MissingField("Destination"))?,
            next_hop: next_hop.ok_or(DvTlvError::MissingField("NextHop"))?,
            cost: cost.ok_or(DvTlvError::MissingField("Cost"))?,
            other_cost: other_cost.ok_or(DvTlvError::MissingField("OtherCost"))?,
        })
    }
}

impl PrefixOpList {
    /// Encode as a full `PrefixOpList` TLV including the outer 301 wrapper.
    /// Use when the bytes are nested inside [`Packet`].
    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        self.write_into(&mut w);
        w.finish()
    }

    /// Encode without the outer 301 wrapper — just the concatenated inner
    /// fields. Mirrors ndnd's `PrefixOpListEncoder::EncodeInto`.
    pub fn encode_content(&self) -> Bytes {
        let mut w = TlvWriter::new();
        write_name_field(&mut w, T_DESTINATION, &self.exit_router);
        if self.reset {
            w.write_tlv(T_PREFIX_OP_RESET, &[]);
        }
        for add in &self.adds {
            add.write_into(&mut w);
        }
        for rm in &self.removes {
            rm.write_into(&mut w);
        }
        w.finish()
    }

    pub fn decode_content(bytes: &Bytes) -> Result<Self, DvTlvError> {
        Self::decode_value(bytes.clone())
    }

    pub fn decode(bytes: &Bytes) -> Result<Self, DvTlvError> {
        let mut r = TlvReader::new(bytes.clone());
        let (typ, value) = r.read_tlv().map_err(|_| DvTlvError::Malformed)?;
        if typ != T_PREFIX_OP_LIST {
            return Err(DvTlvError::WrongType {
                expected: T_PREFIX_OP_LIST,
                got: typ,
            });
        }
        Self::decode_value(value)
    }

    pub fn decode_value(value: Bytes) -> Result<Self, DvTlvError> {
        let mut exit_router: Option<Name> = None;
        let mut reset = false;
        let mut adds = Vec::new();
        let mut removes = Vec::new();
        let mut r = TlvReader::new(value);
        while !r.is_empty() {
            let (typ, v) = r.read_tlv().map_err(|_| DvTlvError::Malformed)?;
            match typ {
                T_DESTINATION => exit_router = Some(decode_name_field(v)?),
                T_PREFIX_OP_RESET => reset = true,
                T_PREFIX_OP_ADD => adds.push(PrefixOpAdd::decode_value(v)?),
                T_PREFIX_OP_REMOVE => removes.push(PrefixOpRemove::decode_value(v)?),
                _ => {}
            }
        }
        Ok(PrefixOpList {
            exit_router: exit_router.ok_or(DvTlvError::MissingField("ExitRouter"))?,
            reset,
            adds,
            removes,
        })
    }

    fn write_into(&self, w: &mut TlvWriter) {
        w.write_nested(T_PREFIX_OP_LIST, |inner| {
            write_name_field(inner, T_DESTINATION, &self.exit_router);
            if self.reset {
                inner.write_tlv(T_PREFIX_OP_RESET, &[]);
            }
            for add in &self.adds {
                add.write_into(inner);
            }
            for rm in &self.removes {
                rm.write_into(inner);
            }
        });
    }
}

impl PrefixOpAdd {
    fn write_into(&self, w: &mut TlvWriter) {
        w.write_nested(T_PREFIX_OP_ADD, |inner| {
            inner.write_raw(&self.name.encode_to_tlv());
            write_nni_tlv(inner, T_COST, self.cost);
        });
    }

    fn decode_value(value: Bytes) -> Result<Self, DvTlvError> {
        let mut name: Option<Name> = None;
        let mut cost: Option<u64> = None;
        let mut r = TlvReader::new(value);
        while !r.is_empty() {
            let (typ, v) = r.read_tlv().map_err(|_| DvTlvError::Malformed)?;
            match typ {
                t if t == tlv_type::NAME => {
                    name = Some(Name::decode(v).map_err(|_| DvTlvError::Malformed)?);
                }
                T_COST => cost = Some(decode_nni_value(&v)?),
                _ => {}
            }
        }
        Ok(PrefixOpAdd {
            name: name.ok_or(DvTlvError::MissingField("Name (PrefixOpAdd)"))?,
            cost: cost.ok_or(DvTlvError::MissingField("Cost (PrefixOpAdd)"))?,
        })
    }
}

impl PrefixOpRemove {
    fn write_into(&self, w: &mut TlvWriter) {
        w.write_nested(T_PREFIX_OP_REMOVE, |inner| {
            inner.write_raw(&self.name.encode_to_tlv());
        });
    }

    fn decode_value(value: Bytes) -> Result<Self, DvTlvError> {
        let mut name: Option<Name> = None;
        let mut r = TlvReader::new(value);
        while !r.is_empty() {
            let (typ, v) = r.read_tlv().map_err(|_| DvTlvError::Malformed)?;
            if typ == tlv_type::NAME {
                name = Some(Name::decode(v).map_err(|_| DvTlvError::Malformed)?);
            }
        }
        Ok(PrefixOpRemove {
            name: name.ok_or(DvTlvError::MissingField("Name (PrefixOpRemove)"))?,
        })
    }
}

/// Runtime-status report mirroring ndnd's `Status` struct
/// (`ndnd/dv/tlv/definitions.go:57`). Served as the Data Content body
/// at `/localhost/nlsr/status` (the prefix ndnd's `dvc` consumer
/// expresses to).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    pub version: String,
    pub network_name: Name,
    pub router_name: Name,
    pub n_rib_entries: u64,
    pub n_neighbors: u64,
    pub n_fib_entries: u64,
}

impl Status {
    /// Encode as bare Content bytes (no outer wrapper). Matches
    /// ndnd's `StatusEncoder::EncodeInto` which emits each field as a
    /// top-level TLV inside the Data Content.
    pub fn encode_content(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_tlv(T_VERSION, self.version.as_bytes());
        write_name_field(&mut w, T_NETWORK_NAME, &self.network_name);
        write_name_field(&mut w, T_ROUTER_NAME, &self.router_name);
        write_nni_tlv(&mut w, T_N_RIB_ENTRIES, self.n_rib_entries);
        write_nni_tlv(&mut w, T_N_NEIGHBORS, self.n_neighbors);
        write_nni_tlv(&mut w, T_N_FIB_ENTRIES, self.n_fib_entries);
        w.finish()
    }

    /// Tolerates unknown non-critical TLVs per NDN evolution rules.
    pub fn decode_content(bytes: &Bytes) -> Result<Self, DvTlvError> {
        let mut version: Option<String> = None;
        let mut network_name: Option<Name> = None;
        let mut router_name: Option<Name> = None;
        let mut n_rib_entries: Option<u64> = None;
        let mut n_neighbors: Option<u64> = None;
        let mut n_fib_entries: Option<u64> = None;
        let mut r = TlvReader::new(bytes.clone());
        while !r.is_empty() {
            let (typ, v) = r.read_tlv().map_err(|_| DvTlvError::Malformed)?;
            match typ {
                T_VERSION => {
                    version = Some(
                        std::str::from_utf8(&v)
                            .map_err(|_| DvTlvError::Malformed)?
                            .to_owned(),
                    );
                }
                T_NETWORK_NAME => network_name = Some(decode_name_field(v)?),
                T_ROUTER_NAME => router_name = Some(decode_name_field(v)?),
                T_N_RIB_ENTRIES => n_rib_entries = Some(decode_nni_value(&v)?),
                T_N_NEIGHBORS => n_neighbors = Some(decode_nni_value(&v)?),
                T_N_FIB_ENTRIES => n_fib_entries = Some(decode_nni_value(&v)?),
                _ => {}
            }
        }
        Ok(Status {
            version: version.ok_or(DvTlvError::MissingField("Version"))?,
            network_name: network_name.ok_or(DvTlvError::MissingField("NetworkName"))?,
            router_name: router_name.ok_or(DvTlvError::MissingField("RouterName"))?,
            n_rib_entries: n_rib_entries.ok_or(DvTlvError::MissingField("NRibEntries"))?,
            n_neighbors: n_neighbors.ok_or(DvTlvError::MissingField("NNeighbors"))?,
            n_fib_entries: n_fib_entries.ok_or(DvTlvError::MissingField("NFibEntries"))?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn name(s: &str) -> Name {
        Name::from_str(s).expect("valid name")
    }

    #[test]
    fn advertisement_empty_roundtrip() {
        let adv = Advertisement::default();
        let bytes = adv.encode();
        let decoded = Advertisement::decode(&bytes).unwrap();
        assert_eq!(adv, decoded);
    }

    #[test]
    fn advertisement_empty_byte_level() {
        // ADVERTISEMENT-TYPE=201 (0xC9) with empty value.
        assert_eq!(&Advertisement::default().encode()[..], &[0xC9, 0x00]);
    }

    #[test]
    fn advertisement_single_entry_roundtrip() {
        let adv = Advertisement {
            entries: vec![AdvEntry {
                destination: name("/a"),
                next_hop: name("/b"),
                cost: 5,
                other_cost: 99,
            }],
        };
        let bytes = adv.encode();
        let decoded = Advertisement::decode(&bytes).unwrap();
        assert_eq!(adv, decoded);
    }

    #[test]
    fn advertisement_single_entry_byte_level() {
        // Hand-computed against SPEC.md §3:
        // Advertisement(201) { AdvEntry(202) { Destination(204) Name(/a),
        //                                      NextHop(206) Name(/b),
        //                                      Cost(208) = 5,
        //                                      OtherCost(210) = 99 } }
        let adv = Advertisement {
            entries: vec![AdvEntry {
                destination: name("/a"),
                next_hop: name("/b"),
                cost: 5,
                other_cost: 99,
            }],
        };
        let expected: &[u8] = &[
            0xC9, 0x16, //                Advertisement, len 22
            0xCA, 0x14, //                AdvEntry,      len 20
            0xCC, 0x05, //                Destination,   len 5
            0x07, 0x03, //                  Name,        len 3
            0x08, 0x01, 0x61, //             Component 'a'
            0xCE, 0x05, //                NextHop,       len 5
            0x07, 0x03, //                  Name,        len 3
            0x08, 0x01, 0x62, //             Component 'b'
            0xD0, 0x01, 0x05, //          Cost=5
            0xD2, 0x01, 0x63, //          OtherCost=99
        ];
        assert_eq!(&adv.encode()[..], expected);
    }

    #[test]
    fn advertisement_multi_entry_roundtrip() {
        let adv = Advertisement {
            entries: vec![
                AdvEntry {
                    destination: name("/ndn/edu/ucla"),
                    next_hop: name("/ndn/edu/arizona"),
                    cost: 3,
                    other_cost: 7,
                },
                AdvEntry {
                    destination: name("/ndn/edu/mit"),
                    next_hop: name("/ndn/edu/ucla"),
                    cost: 5,
                    other_cost: 11,
                },
            ],
        };
        let bytes = adv.encode();
        let decoded = Advertisement::decode(&bytes).unwrap();
        assert_eq!(adv, decoded);
    }

    #[test]
    fn adv_entry_cost_widths_roundtrip() {
        // Cost values triggering NNI widths 1, 2, 4, 8.
        for &c in &[
            0u64,
            0xFF,
            0x100,
            0xFFFF,
            0x1_0000,
            0xFFFF_FFFF,
            0x1_0000_0000,
            u64::MAX,
        ] {
            let adv = Advertisement {
                entries: vec![AdvEntry {
                    destination: name("/a"),
                    next_hop: name("/b"),
                    cost: c,
                    other_cost: c,
                }],
            };
            let decoded = Advertisement::decode(&adv.encode()).unwrap();
            assert_eq!(adv, decoded, "cost roundtrip failed for {c}");
        }
    }

    #[test]
    fn advertisement_rejects_wrong_outer_type() {
        // Encode a PrefixOpList, try to decode as Advertisement.
        let pol = PrefixOpList {
            exit_router: name("/r"),
            reset: true,
            adds: vec![],
            removes: vec![],
        };
        let err = Advertisement::decode(&pol.encode()).unwrap_err();
        assert!(matches!(
            err,
            DvTlvError::WrongType {
                expected: T_ADVERTISEMENT,
                got: T_PREFIX_OP_LIST
            }
        ));
    }

    #[test]
    fn adv_entry_rejects_missing_destination() {
        // Hand-craft an AdvEntry missing the Destination TLV.
        let mut w = TlvWriter::new();
        w.write_nested(T_ADVERTISEMENT, |inner| {
            inner.write_nested(T_ADV_ENTRY, |entry| {
                // No Destination.
                write_name_field(entry, T_NEXT_HOP, &name("/b"));
                write_nni_tlv(entry, T_COST, 5);
                write_nni_tlv(entry, T_OTHER_COST, 99);
            });
        });
        let bytes = w.finish();
        assert_eq!(
            Advertisement::decode(&bytes).unwrap_err(),
            DvTlvError::MissingField("Destination"),
        );
    }

    #[test]
    fn adv_entry_rejects_missing_other_cost() {
        let mut w = TlvWriter::new();
        w.write_nested(T_ADVERTISEMENT, |inner| {
            inner.write_nested(T_ADV_ENTRY, |entry| {
                write_name_field(entry, T_DESTINATION, &name("/a"));
                write_name_field(entry, T_NEXT_HOP, &name("/b"));
                write_nni_tlv(entry, T_COST, 5);
                // No OtherCost.
            });
        });
        let bytes = w.finish();
        assert_eq!(
            Advertisement::decode(&bytes).unwrap_err(),
            DvTlvError::MissingField("OtherCost"),
        );
    }

    #[test]
    fn advertisement_tolerates_unknown_fields_inside_entry() {
        // Unknown TLV codes inside an AdvEntry are ignored (NDN
        // forward-compatibility convention).
        let mut w = TlvWriter::new();
        w.write_nested(T_ADVERTISEMENT, |inner| {
            inner.write_nested(T_ADV_ENTRY, |entry| {
                write_name_field(entry, T_DESTINATION, &name("/a"));
                write_name_field(entry, T_NEXT_HOP, &name("/b"));
                write_nni_tlv(entry, T_COST, 5);
                write_nni_tlv(entry, T_OTHER_COST, 99);
                // Unknown TLV type, ignored.
                entry.write_tlv(0xE0, &[0x01, 0x02, 0x03]);
            });
        });
        let bytes = w.finish();
        let decoded = Advertisement::decode(&bytes).unwrap();
        assert_eq!(decoded.entries.len(), 1);
        assert_eq!(decoded.entries[0].cost, 5);
    }

    #[test]
    fn adv_entry_rejects_invalid_nni_width() {
        // NNI must be 1/2/4/8 octets per NDN spec; 3 bytes is invalid.
        let mut w = TlvWriter::new();
        w.write_nested(T_ADVERTISEMENT, |inner| {
            inner.write_nested(T_ADV_ENTRY, |entry| {
                write_name_field(entry, T_DESTINATION, &name("/a"));
                write_name_field(entry, T_NEXT_HOP, &name("/b"));
                entry.write_tlv(T_COST, &[0x01, 0x02, 0x03]); // bad width
                write_nni_tlv(entry, T_OTHER_COST, 99);
            });
        });
        let bytes = w.finish();
        assert_eq!(
            Advertisement::decode(&bytes).unwrap_err(),
            DvTlvError::InvalidNniWidth(3),
        );
    }

    #[test]
    fn advertisement_rejects_non_adv_entry_inner() {
        // Advertisement containing something that is NOT an AdvEntry.
        let mut w = TlvWriter::new();
        w.write_nested(T_ADVERTISEMENT, |inner| {
            inner.write_tlv(0xE0, &[]); // bogus
        });
        let bytes = w.finish();
        let err = Advertisement::decode(&bytes).unwrap_err();
        assert!(matches!(
            err,
            DvTlvError::WrongType {
                expected: T_ADV_ENTRY,
                got: 0xE0
            }
        ));
    }

    #[test]
    fn prefix_op_list_minimal_roundtrip() {
        // Just the exit-router; no reset / adds / removes.
        let pol = PrefixOpList {
            exit_router: name("/router"),
            reset: false,
            adds: vec![],
            removes: vec![],
        };
        let bytes = pol.encode();
        let decoded = PrefixOpList::decode(&bytes).unwrap();
        assert_eq!(pol, decoded);
    }

    #[test]
    fn prefix_op_list_reset_roundtrip() {
        let pol = PrefixOpList {
            exit_router: name("/router"),
            reset: true,
            adds: vec![],
            removes: vec![],
        };
        let decoded = PrefixOpList::decode(&pol.encode()).unwrap();
        assert_eq!(pol, decoded);
    }

    #[test]
    fn prefix_op_list_reset_byte_level() {
        // PrefixOpList(301) { Destination(204) Name(/r), PrefixOpReset(302)= }
        // 301 is encoded as 3-byte varint: 0xFD 0x01 0x2D
        // 302 is encoded as 3-byte varint: 0xFD 0x01 0x2E
        let pol = PrefixOpList {
            exit_router: name("/r"),
            reset: true,
            adds: vec![],
            removes: vec![],
        };
        let expected: &[u8] = &[
            0xFD, 0x01, 0x2D, // PrefixOpList type=301
            0x0B, //               length 11
            0xCC, 0x05, //         Destination, len 5
            0x07, 0x03, //           Name, len 3
            0x08, 0x01, 0x72, //       Component 'r'
            0xFD, 0x01, 0x2E, // PrefixOpReset type=302
            0x00, //               len 0
        ];
        assert_eq!(&pol.encode()[..], expected);
    }

    #[test]
    fn prefix_op_list_adds_removes_roundtrip() {
        let pol = PrefixOpList {
            exit_router: name("/r"),
            reset: false,
            adds: vec![
                PrefixOpAdd {
                    name: name("/p1"),
                    cost: 1,
                },
                PrefixOpAdd {
                    name: name("/p2"),
                    cost: 256,
                },
            ],
            removes: vec![PrefixOpRemove { name: name("/old") }],
        };
        let decoded = PrefixOpList::decode(&pol.encode()).unwrap();
        assert_eq!(pol, decoded);
    }

    #[test]
    fn prefix_op_list_rejects_missing_exit_router() {
        let mut w = TlvWriter::new();
        w.write_nested(T_PREFIX_OP_LIST, |inner| {
            inner.write_tlv(T_PREFIX_OP_RESET, &[]);
        });
        let bytes = w.finish();
        assert_eq!(
            PrefixOpList::decode(&bytes).unwrap_err(),
            DvTlvError::MissingField("ExitRouter"),
        );
    }

    #[test]
    fn prefix_op_add_rejects_missing_cost() {
        let mut outer = TlvWriter::new();
        outer.write_nested(T_PREFIX_OP_LIST, |inner| {
            write_name_field(inner, T_DESTINATION, &name("/r"));
            inner.write_nested(T_PREFIX_OP_ADD, |add| {
                add.write_raw(&name("/p").encode_to_tlv());
                // No Cost.
            });
        });
        let bytes = outer.finish();
        assert_eq!(
            PrefixOpList::decode(&bytes).unwrap_err(),
            DvTlvError::MissingField("Cost (PrefixOpAdd)"),
        );
    }

    #[test]
    fn prefix_op_remove_rejects_missing_name() {
        let mut outer = TlvWriter::new();
        outer.write_nested(T_PREFIX_OP_LIST, |inner| {
            write_name_field(inner, T_DESTINATION, &name("/r"));
            inner.write_nested(T_PREFIX_OP_REMOVE, |_rm| {
                // No Name.
            });
        });
        let bytes = outer.finish();
        assert_eq!(
            PrefixOpList::decode(&bytes).unwrap_err(),
            DvTlvError::MissingField("Name (PrefixOpRemove)"),
        );
    }

    #[test]
    fn packet_dispatches_advertisement() {
        let adv = Advertisement {
            entries: vec![AdvEntry {
                destination: name("/a"),
                next_hop: name("/b"),
                cost: 1,
                other_cost: 2,
            }],
        };
        let bytes = adv.encode();
        let pkt = Packet::decode(&bytes).unwrap();
        assert_eq!(pkt, Packet::Advertisement(adv));
    }

    #[test]
    fn packet_dispatches_prefix_op_list() {
        let pol = PrefixOpList {
            exit_router: name("/r"),
            reset: false,
            adds: vec![PrefixOpAdd {
                name: name("/p"),
                cost: 1,
            }],
            removes: vec![],
        };
        let bytes = pol.encode();
        let pkt = Packet::decode(&bytes).unwrap();
        assert_eq!(pkt, Packet::PrefixOpList(Box::new(pol)));
    }

    #[test]
    fn packet_rejects_unknown_outer() {
        // Type 0xE0 — not Advertisement (201) or PrefixOpList (301).
        let mut w = TlvWriter::new();
        w.write_tlv(0xE0, &[]);
        let err = Packet::decode(&w.finish()).unwrap_err();
        assert!(matches!(err, DvTlvError::WrongType { got: 0xE0, .. }));
    }

    #[test]
    fn status_encode_decode_round_trip() {
        let s = Status {
            version: "ndn-rs/0.1.0".to_owned(),
            network_name: name("/ndn"),
            router_name: name("/ndn/r-rs"),
            n_rib_entries: 7,
            n_neighbors: 3,
            n_fib_entries: 12,
        };
        let bytes = s.encode_content();
        let back = Status::decode_content(&bytes).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn status_decode_tolerates_unknown_non_critical_fields() {
        // Build wire bytes with a Version + Network/Router/NNI
        // fields PLUS an unknown TLV type 0x300 (non-critical
        // by NDN evolution rules: even-numbered ≥ 32). Parser
        // must skip it and decode the rest cleanly.
        let mut w = TlvWriter::new();
        w.write_tlv(T_VERSION, b"x");
        write_name_field(&mut w, T_NETWORK_NAME, &name("/n"));
        write_name_field(&mut w, T_ROUTER_NAME, &name("/r"));
        write_nni_tlv(&mut w, T_N_RIB_ENTRIES, 1);
        write_nni_tlv(&mut w, T_N_NEIGHBORS, 2);
        write_nni_tlv(&mut w, T_N_FIB_ENTRIES, 3);
        w.write_tlv(0x300, b"future-field-bytes");
        let bytes = w.finish();
        let s = Status::decode_content(&bytes).expect("unknown non-critical must be skipped");
        assert_eq!(s.version, "x");
        assert_eq!(s.n_neighbors, 2);
    }

    #[test]
    fn status_decode_rejects_missing_required_field() {
        // Missing NRibEntries — parser must surface a MissingField error.
        let mut w = TlvWriter::new();
        w.write_tlv(T_VERSION, b"x");
        write_name_field(&mut w, T_NETWORK_NAME, &name("/n"));
        write_name_field(&mut w, T_ROUTER_NAME, &name("/r"));
        write_nni_tlv(&mut w, T_N_NEIGHBORS, 1);
        write_nni_tlv(&mut w, T_N_FIB_ENTRIES, 1);
        let err = Status::decode_content(&w.finish()).unwrap_err();
        assert!(
            matches!(err, DvTlvError::MissingField("NRibEntries")),
            "got {err:?}",
        );
    }

    /// Pinned against ndnd's `tlv/definitions.go` `Status` (lines 57-70):
    /// if ndnd renumbers we want a hard test failure, not silent drift.
    #[test]
    fn status_type_codes_match_ndnd() {
        assert_eq!(T_VERSION, 0x191);
        assert_eq!(T_NETWORK_NAME, 0x193);
        assert_eq!(T_ROUTER_NAME, 0x195);
        assert_eq!(T_N_RIB_ENTRIES, 0x197);
        assert_eq!(T_N_NEIGHBORS, 0x199);
        assert_eq!(T_N_FIB_ENTRIES, 0x19B);
    }

    #[test]
    fn encode_nni_widths() {
        assert_eq!(encode_nni(0), vec![0x00]);
        assert_eq!(encode_nni(0xFF), vec![0xFF]);
        assert_eq!(encode_nni(0x100), vec![0x01, 0x00]);
        assert_eq!(encode_nni(0xFFFF), vec![0xFF, 0xFF]);
        assert_eq!(encode_nni(0x1_0000), vec![0x00, 0x01, 0x00, 0x00]);
        assert_eq!(encode_nni(0xFFFF_FFFF), vec![0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(
            encode_nni(0x1_0000_0000),
            vec![0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]
        );
    }
}
