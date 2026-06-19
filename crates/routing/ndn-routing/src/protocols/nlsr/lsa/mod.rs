//! Link State Advertisements for NLSR. Three concrete LSA types share
//! a common header (origin router, sequence number, expiration time);
//! `Lsa` is a Rust enum in place of C++ NLSR's virtual-dispatch
//! hierarchy (`NLSR/src/lsa/lsa.hpp:1-130`).

pub mod adjacency;
pub mod coordinate;
pub mod name;

pub use adjacency::AdjacencyLsa;
pub use coordinate::CoordinateLsa;
pub use name::{NameLsa, PrefixInfo};

use ndn_packet::Name;
use ndn_tlv::{TlvReader, TlvWriter};

// TLV type codes per NLSR/src/tlv-nlsr.hpp:32-50.
pub(crate) const TLV_LSA: u64 = 128;
pub(crate) const TLV_SEQ_NO: u64 = 130;
pub(crate) const TLV_ADJACENCY_LSA: u64 = 131;
pub(crate) const TLV_ADJACENCY: u64 = 132;
pub(crate) const TLV_COORDINATE_LSA: u64 = 133;
pub(crate) const TLV_HYPERBOLIC_RADIUS: u64 = 135;
pub(crate) const TLV_HYPERBOLIC_ANGLE: u64 = 136;
pub(crate) const TLV_NAME_LSA: u64 = 137;
/// ASCII `"YYYY-MM-DD HH:MM:SS"`.
pub(crate) const TLV_EXPIRATION_TIME: u64 = 139;
/// IEEE 754 double, 8 bytes big-endian.
pub(crate) const TLV_COST: u64 = 140;
pub(crate) const TLV_URI: u64 = 141;
pub(crate) const TLV_PREFIX_INFO: u64 = 146;

// NDN Packet Format v0.3 §2.1.
const TLV_NAME: u64 = 7;

/// Mirrors `Lsa::Type` (`NLSR/src/lsa/lsa.hpp:35`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LsaType {
    Adjacency,
    Name,
    Coordinate,
}

#[derive(Clone, Debug)]
pub enum Lsa {
    Adjacency(AdjacencyLsa),
    Name(NameLsa),
    Coordinate(CoordinateLsa),
}

impl Lsa {
    pub fn lsa_type(&self) -> LsaType {
        match self {
            Lsa::Adjacency(_) => LsaType::Adjacency,
            Lsa::Name(_) => LsaType::Name,
            Lsa::Coordinate(_) => LsaType::Coordinate,
        }
    }

    pub fn origin_router(&self) -> &ndn_packet::Name {
        match self {
            Lsa::Adjacency(l) => &l.origin_router,
            Lsa::Name(l) => &l.origin_router,
            Lsa::Coordinate(l) => &l.origin_router,
        }
    }

    pub fn seq_no(&self) -> u64 {
        match self {
            Lsa::Adjacency(l) => l.seq_no,
            Lsa::Name(l) => l.seq_no,
            Lsa::Coordinate(l) => l.seq_no,
        }
    }

    pub fn expiration_ms(&self) -> u64 {
        match self {
            Lsa::Adjacency(l) => l.expiration_ms,
            Lsa::Name(l) => l.expiration_ms,
            Lsa::Coordinate(l) => l.expiration_ms,
        }
    }

    pub fn wire_encode(&self) -> bytes::Bytes {
        match self {
            Lsa::Adjacency(l) => l.wire_encode(),
            Lsa::Name(l) => l.wire_encode(),
            Lsa::Coordinate(l) => l.wire_encode(),
        }
    }

    pub fn wire_decode(
        lsa_type: LsaType,
        input: bytes::Bytes,
    ) -> Result<Self, crate::protocols::nlsr::NlsrError> {
        match lsa_type {
            LsaType::Adjacency => AdjacencyLsa::wire_decode(input)
                .map(Lsa::Adjacency)
                .map_err(Into::into),
            LsaType::Name => NameLsa::wire_decode(input)
                .map(Lsa::Name)
                .map_err(Into::into),
            LsaType::Coordinate => CoordinateLsa::wire_decode(input)
                .map(Lsa::Coordinate)
                .map_err(Into::into),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum LsaCodecError {
    Tlv(ndn_tlv::TlvError),
    WrongType { expected: u64, got: u64 },
    MissingField(&'static str),
    InvalidUtf8,
    InvalidDateTime,
    InvalidDouble,
}

impl std::fmt::Display for LsaCodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LsaCodecError::Tlv(e) => write!(f, "TLV error: {e}"),
            LsaCodecError::WrongType { expected, got } => {
                write!(f, "wrong TLV type: expected {expected:#x}, got {got:#x}")
            }
            LsaCodecError::MissingField(s) => write!(f, "missing required field: {s}"),
            LsaCodecError::InvalidUtf8 => write!(f, "invalid UTF-8 in string field"),
            LsaCodecError::InvalidDateTime => write!(f, "invalid ExpirationTime datetime"),
            LsaCodecError::InvalidDouble => write!(f, "Cost/radius field must be 8 bytes"),
        }
    }
}

impl std::error::Error for LsaCodecError {}

impl From<ndn_tlv::TlvError> for LsaCodecError {
    fn from(e: ndn_tlv::TlvError) -> Self {
        LsaCodecError::Tlv(e)
    }
}

/// NDN NonNegativeInteger (minimum-width big-endian). Mirrors ndn-cxx
/// `prependNonNegativeIntegerBlock`.
pub(crate) fn write_nonneg_integer(w: &mut TlvWriter, typ: u64, v: u64) {
    let b = v.to_be_bytes();
    let slice = match v {
        0..=0xFF => &b[7..],
        0x100..=0xFFFF => &b[6..],
        0x10000..=0xFFFF_FFFF => &b[4..],
        _ => &b[..],
    };
    w.write_tlv(typ, slice);
}

pub(crate) fn read_nonneg_integer(data: &[u8]) -> u64 {
    let mut val: u64 = 0;
    for &b in data {
        val = (val << 8) | u64::from(b);
    }
    val
}

/// 8-byte big-endian IEEE 754 double (ndn-cxx `prependDoubleBlock`).
pub(crate) fn write_double(w: &mut TlvWriter, typ: u64, v: f64) {
    w.write_tlv(typ, &v.to_be_bytes());
}

pub(crate) fn read_double(data: &[u8]) -> Result<f64, LsaCodecError> {
    let arr: [u8; 8] = data.try_into().map_err(|_| LsaCodecError::InvalidDouble)?;
    Ok(f64::from_be_bytes(arr))
}

pub(crate) fn write_name(w: &mut TlvWriter, name: &Name) {
    let bytes = name.encode_to_tlv();
    w.write_raw(&bytes);
}

pub(crate) fn read_name(r: &mut TlvReader) -> Result<Name, LsaCodecError> {
    let (typ, inner) = r.read_tlv()?;
    if typ != TLV_NAME {
        return Err(LsaCodecError::WrongType {
            expected: TLV_NAME,
            got: typ,
        });
    }
    Name::decode(inner).map_err(|_| LsaCodecError::MissingField("Name"))
}

/// C++: `Lsa::wireEncode` (`NLSR/src/lsa/lsa.cpp:44-59`).
pub(crate) fn write_lsa_header(
    w: &mut TlvWriter,
    origin_router: &Name,
    seq_no: u64,
    expiration_ms: u64,
) {
    w.write_nested(TLV_LSA, |inner| {
        write_name(inner, origin_router);
        write_nonneg_integer(inner, TLV_SEQ_NO, seq_no);
        let ts = format_expiration_time(expiration_ms);
        inner.write_tlv(TLV_EXPIRATION_TIME, ts.as_bytes());
    });
}

/// C++: `Lsa::wireDecode` (`NLSR/src/lsa/lsa.cpp:65-98`).
pub(crate) fn read_lsa_header(r: &mut TlvReader) -> Result<(Name, u64, u64), LsaCodecError> {
    let (typ, inner_bytes) = r.read_tlv()?;
    if typ != TLV_LSA {
        return Err(LsaCodecError::WrongType {
            expected: TLV_LSA,
            got: typ,
        });
    }
    let mut inner = TlvReader::new(inner_bytes);

    let origin_router = read_name(&mut inner)?;

    let (seq_typ, seq_bytes) = inner.read_tlv()?;
    if seq_typ != TLV_SEQ_NO {
        return Err(LsaCodecError::WrongType {
            expected: TLV_SEQ_NO,
            got: seq_typ,
        });
    }
    let seq_no = read_nonneg_integer(&seq_bytes);

    let (exp_typ, exp_bytes) = inner.read_tlv()?;
    if exp_typ != TLV_EXPIRATION_TIME {
        return Err(LsaCodecError::WrongType {
            expected: TLV_EXPIRATION_TIME,
            got: exp_typ,
        });
    }
    let ts = std::str::from_utf8(&exp_bytes).map_err(|_| LsaCodecError::InvalidUtf8)?;
    let expiration_ms = parse_expiration_time(ts)?;

    Ok((origin_router, seq_no, expiration_ms))
}

// ndn-cxx encodes ExpirationTime as "YYYY-MM-DD HH:MM:SS" (UTC,
// second precision); sub-second precision is dropped on encode
// (`ndn::time::toString` in lsa.cpp:48).

/// Format Unix ms timestamp as "YYYY-MM-DD HH:MM:SS" (UTC).
pub(crate) fn format_expiration_time(ms: u64) -> String {
    let secs = ms / 1000;
    let (year, month, day) = days_to_ymd((secs / 86400) as i64);
    let t = (secs % 86400) as u32;
    let h = t / 3600;
    let m = (t % 3600) / 60;
    let s = t % 60;
    format!("{year:04}-{month:02}-{day:02} {h:02}:{m:02}:{s:02}")
}

pub(crate) fn parse_expiration_time(s: &str) -> Result<u64, LsaCodecError> {
    if s.len() != 19 {
        return Err(LsaCodecError::InvalidDateTime);
    }
    let year = s[0..4]
        .parse::<i32>()
        .map_err(|_| LsaCodecError::InvalidDateTime)?;
    let month = s[5..7]
        .parse::<u32>()
        .map_err(|_| LsaCodecError::InvalidDateTime)?;
    let day = s[8..10]
        .parse::<u32>()
        .map_err(|_| LsaCodecError::InvalidDateTime)?;
    let h = s[11..13]
        .parse::<i64>()
        .map_err(|_| LsaCodecError::InvalidDateTime)?;
    let m = s[14..16]
        .parse::<i64>()
        .map_err(|_| LsaCodecError::InvalidDateTime)?;
    let sec = s[17..19]
        .parse::<i64>()
        .map_err(|_| LsaCodecError::InvalidDateTime)?;
    let days = ymd_to_days(year, month, day);
    let unix_secs = days * 86400 + h * 3600 + m * 60 + sec;
    Ok(unix_secs as u64 * 1000)
}

// Howard Hinnant's `civil_from_days` algorithm.
// Converts days since Unix epoch (1970-01-01) to (year, month, day).
// Reference: https://howardhinnant.github.io/date_algorithms.html
fn days_to_ymd(z: i64) -> (i32, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 {
        z / 146097
    } else {
        (z - 146096) / 146097
    };
    let doe = (z - era * 146097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m, d)
}

// Howard Hinnant's `days_from_civil` algorithm.
// Converts (year, month, day) to days since Unix epoch (1970-01-01).
fn ymd_to_days(y: i32, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y as i64 - 1 } else { y as i64 };
    let era = if y >= 0 { y / 400 } else { (y - 399) / 400 };
    let yoe = (y - era * 400) as u64; // [0, 399]
    let mp = if m > 2 { m as u64 - 3 } else { m as u64 + 9 }; // [0, 11]
    let doy = (153 * mp + 2) / 5 + d as u64 - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146097 + doe as i64 - 719468
}

#[cfg(test)]
mod roundtrip {
    use super::*;
    use crate::protocols::nlsr::lsa::{
        LsaCodecError, adjacency::AdjacencyLsa, coordinate::CoordinateLsa, name::NameLsa,
    };
    use bytes::Bytes;

    // Golden bytes from NLSR/tests/lsa/test-adj-lsa.cpp:30-37
    const ADJ_LSA1: &[u8] = &[
        0x83, 0x58, 0x80, 0x2D, 0x07, 0x13, 0x08, 0x03, 0x6E, 0x64, 0x6E, 0x08, 0x04, 0x73, 0x69,
        0x74, 0x65, 0x08, 0x06, 0x72, 0x6F, 0x75, 0x74, 0x65, 0x72, 0x82, 0x01, 0x0C, 0x8B, 0x13,
        0x32, 0x30, 0x32, 0x30, 0x2D, 0x30, 0x33, 0x2D, 0x32, 0x36, 0x20, 0x30, 0x34, 0x3A, 0x31,
        0x33, 0x3A, 0x33, 0x34, 0x84, 0x27, 0x07, 0x16, 0x08, 0x03, 0x6E, 0x64, 0x6E, 0x08, 0x04,
        0x73, 0x69, 0x74, 0x65, 0x08, 0x09, 0x61, 0x64, 0x6A, 0x61, 0x63, 0x65, 0x6E, 0x63, 0x79,
        0x8D, 0x03, 0x3A, 0x2F, 0x2F, 0x8C, 0x08, 0x40, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    // Golden bytes from NLSR/tests/lsa/test-adj-lsa.cpp:39-49 (two adjacencies)
    const ADJ_LSA_EXTRA_NEIGHBOR: &[u8] = &[
        0x83, 0x80, 0x80, 0x2D, 0x07, 0x13, 0x08, 0x03, 0x6E, 0x64, 0x6E, 0x08, 0x04, 0x73, 0x69,
        0x74, 0x65, 0x08, 0x06, 0x72, 0x6F, 0x75, 0x74, 0x65, 0x72, 0x82, 0x01, 0x0C, 0x8B, 0x13,
        0x32, 0x30, 0x32, 0x30, 0x2D, 0x30, 0x33, 0x2D, 0x32, 0x36, 0x20, 0x30, 0x34, 0x3A, 0x31,
        0x33, 0x3A, 0x33, 0x34, 0x84, 0x27, 0x07, 0x16, 0x08, 0x03, 0x6E, 0x64, 0x6E, 0x08, 0x04,
        0x73, 0x69, 0x74, 0x65, 0x08, 0x09, 0x61, 0x64, 0x6A, 0x61, 0x63, 0x65, 0x6E, 0x63, 0x79,
        0x8D, 0x03, 0x3A, 0x2F, 0x2F, 0x8C, 0x08, 0x40, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x84, 0x26, 0x07, 0x15, 0x08, 0x03, 0x6E, 0x64, 0x6E, 0x08, 0x03, 0x65, 0x64, 0x75, 0x08,
        0x09, 0x61, 0x64, 0x6A, 0x61, 0x63, 0x65, 0x6E, 0x63, 0x79, 0x8D, 0x03, 0x3A, 0x2F, 0x2F,
        0x8C, 0x08, 0x40, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    // Golden bytes from NLSR/tests/lsa/test-name-lsa.cpp:33-46 (two prefixes)
    const NAME_LSA1: &[u8] = &[
        0x89, 0x4F, 0x80, 0x23, 0x07, 0x09, 0x08, 0x07, 0x72, 0x6F, 0x75, 0x74, 0x65, 0x72, 0x31,
        0x82, 0x01, 0x0C, 0x8B, 0x13, 0x32, 0x30, 0x32, 0x30, 0x2D, 0x30, 0x33, 0x2D, 0x32, 0x36,
        0x20, 0x30, 0x34, 0x3A, 0x31, 0x33, 0x3A, 0x33, 0x34, 0x92, 0x13, 0x07, 0x07, 0x08, 0x05,
        0x6E, 0x61, 0x6D, 0x65, 0x31, 0x8C, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x92, 0x13, 0x07, 0x07, 0x08, 0x05, 0x6E, 0x61, 0x6D, 0x65, 0x32, 0x8C, 0x08, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    // Golden bytes from NLSR/tests/lsa/test-name-lsa.cpp:48-64 (three prefixes)
    const NAME_LSA_EXTRA_NAME: &[u8] = &[
        0x89, 0x64, 0x80, 0x23, 0x07, 0x09, 0x08, 0x07, 0x72, 0x6F, 0x75, 0x74, 0x65, 0x72, 0x31,
        0x82, 0x01, 0x0C, 0x8B, 0x13, 0x32, 0x30, 0x32, 0x30, 0x2D, 0x30, 0x33, 0x2D, 0x32, 0x36,
        0x20, 0x30, 0x34, 0x3A, 0x31, 0x33, 0x3A, 0x33, 0x34, 0x92, 0x13, 0x07, 0x07, 0x08, 0x05,
        0x6E, 0x61, 0x6D, 0x65, 0x31, 0x8C, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x92, 0x13, 0x07, 0x07, 0x08, 0x05, 0x6E, 0x61, 0x6D, 0x65, 0x32, 0x8C, 0x08, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x92, 0x13, 0x07, 0x07, 0x08, 0x05, 0x6E, 0x61, 0x6D,
        0x65, 0x33, 0x8C, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    // Golden bytes from NLSR/tests/lsa/test-coordinate-lsa.cpp:52-58 (radius=2.5, angles=[30,30])
    const COORDINATE_LSA1: &[u8] = &[
        0x85, 0x43, 0x80, 0x23, 0x07, 0x09, 0x08, 0x07, 0x72, 0x6F, 0x75, 0x74, 0x65, 0x72, 0x31,
        0x82, 0x01, 0x0C, 0x8B, 0x13, 0x32, 0x30, 0x32, 0x30, 0x2D, 0x30, 0x33, 0x2D, 0x32, 0x36,
        0x20, 0x30, 0x34, 0x3A, 0x31, 0x33, 0x3A, 0x33, 0x34, 0x87, 0x08, 0x40, 0x04, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x88, 0x08, 0x40, 0x3E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88,
        0x08, 0x40, 0x3E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    // Golden bytes from NLSR/tests/lsa/test-coordinate-lsa.cpp:60-65 (one angle=40.0)
    const COORDINATE_LSA_DIFF_ANGLE: &[u8] = &[
        0x85, 0x39, 0x80, 0x23, 0x07, 0x09, 0x08, 0x07, 0x72, 0x6F, 0x75, 0x74, 0x65, 0x72, 0x31,
        0x82, 0x01, 0x0C, 0x8B, 0x13, 0x32, 0x30, 0x32, 0x30, 0x2D, 0x30, 0x33, 0x2D, 0x32, 0x36,
        0x20, 0x30, 0x34, 0x3A, 0x31, 0x33, 0x3A, 0x33, 0x34, 0x87, 0x08, 0x40, 0x04, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x88, 0x08, 0x40, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    fn bytes(b: &[u8]) -> Bytes {
        Bytes::copy_from_slice(b)
    }

    #[test]
    fn adj_lsa_roundtrip_single() {
        let lsa = AdjacencyLsa::wire_decode(bytes(ADJ_LSA1)).unwrap();
        assert_eq!(lsa.origin_router.to_string(), "/ndn/site/router");
        assert_eq!(lsa.seq_no, 12);
        assert_eq!(lsa.adjacencies.len(), 1);
        assert_eq!(lsa.adjacencies[0].name.to_string(), "/ndn/site/adjacency");
        assert_eq!(lsa.adjacencies[0].face_uri, "://");
        assert!((lsa.adjacencies[0].link_cost - 10.0).abs() < 1e-9);

        let re_encoded = lsa.wire_encode();
        assert_eq!(re_encoded.as_ref(), ADJ_LSA1, "ADJ_LSA1 roundtrip failed");
    }

    #[test]
    fn adj_lsa_roundtrip_two_neighbors() {
        let lsa = AdjacencyLsa::wire_decode(bytes(ADJ_LSA_EXTRA_NEIGHBOR)).unwrap();
        assert_eq!(lsa.adjacencies.len(), 2);
        assert_eq!(lsa.adjacencies[0].name.to_string(), "/ndn/site/adjacency");
        assert_eq!(lsa.adjacencies[1].name.to_string(), "/ndn/edu/adjacency");

        let re_encoded = lsa.wire_encode();
        assert_eq!(
            re_encoded.as_ref(),
            ADJ_LSA_EXTRA_NEIGHBOR,
            "ADJ_LSA_EXTRA_NEIGHBOR roundtrip failed"
        );
    }

    #[test]
    fn name_lsa_roundtrip_two_prefixes() {
        let lsa = NameLsa::wire_decode(bytes(NAME_LSA1)).unwrap();
        assert_eq!(lsa.origin_router.to_string(), "/router1");
        assert_eq!(lsa.seq_no, 12);
        assert_eq!(lsa.prefixes.len(), 2);
        assert_eq!(lsa.prefixes[0].name.to_string(), "/name1");
        assert!((lsa.prefixes[0].cost - 0.0).abs() < 1e-9);
        assert_eq!(lsa.prefixes[1].name.to_string(), "/name2");

        let re_encoded = lsa.wire_encode();
        assert_eq!(re_encoded.as_ref(), NAME_LSA1, "NAME_LSA1 roundtrip failed");
    }

    #[test]
    fn name_lsa_roundtrip_three_prefixes() {
        let lsa = NameLsa::wire_decode(bytes(NAME_LSA_EXTRA_NAME)).unwrap();
        assert_eq!(lsa.prefixes.len(), 3);
        assert_eq!(lsa.prefixes[2].name.to_string(), "/name3");

        let re_encoded = lsa.wire_encode();
        assert_eq!(
            re_encoded.as_ref(),
            NAME_LSA_EXTRA_NAME,
            "NAME_LSA_EXTRA_NAME roundtrip failed"
        );
    }

    #[test]
    fn coordinate_lsa_roundtrip_two_angles() {
        let lsa = CoordinateLsa::wire_decode(bytes(COORDINATE_LSA1)).unwrap();
        assert_eq!(lsa.origin_router.to_string(), "/router1");
        assert_eq!(lsa.seq_no, 12);
        assert!((lsa.radius - 2.5).abs() < 1e-9);
        assert_eq!(lsa.angles.len(), 2);
        assert!((lsa.angles[0] - 30.0).abs() < 1e-9);
        assert!((lsa.angles[1] - 30.0).abs() < 1e-9);

        let re_encoded = lsa.wire_encode();
        assert_eq!(
            re_encoded.as_ref(),
            COORDINATE_LSA1,
            "COORDINATE_LSA1 roundtrip failed"
        );
    }

    #[test]
    fn coordinate_lsa_roundtrip_one_angle() {
        let lsa = CoordinateLsa::wire_decode(bytes(COORDINATE_LSA_DIFF_ANGLE)).unwrap();
        assert_eq!(lsa.angles.len(), 1);
        assert!((lsa.angles[0] - 40.0).abs() < 1e-9);

        let re_encoded = lsa.wire_encode();
        assert_eq!(
            re_encoded.as_ref(),
            COORDINATE_LSA_DIFF_ANGLE,
            "COORDINATE_LSA_DIFF_ANGLE roundtrip failed"
        );
    }

    #[test]
    fn expiration_time_format_parse() {
        // 1585196014943ms → "2020-03-26 04:13:34" (sub-seconds discarded)
        // Verified against: NLSR/tests/lsa/test-adj-lsa.cpp:78
        let formatted = format_expiration_time(1585196014943);
        assert_eq!(formatted, "2020-03-26 04:13:34");

        let parsed = parse_expiration_time("2020-03-26 04:13:34").unwrap();
        assert_eq!(parsed, 1585196014000); // sub-second zeroed

        // Re-format is stable
        assert_eq!(format_expiration_time(parsed), "2020-03-26 04:13:34");
    }

    #[test]
    fn expiration_time_unix_epoch() {
        assert_eq!(format_expiration_time(0), "1970-01-01 00:00:00");
        assert_eq!(parse_expiration_time("1970-01-01 00:00:00").unwrap(), 0);
    }

    #[test]
    fn adj_lsa_empty_input() {
        let err = AdjacencyLsa::wire_decode(Bytes::new()).unwrap_err();
        assert!(
            matches!(err, LsaCodecError::Tlv(_)),
            "expected Tlv error, got {err:?}"
        );
    }

    #[test]
    fn adj_lsa_wrong_outer_type() {
        // type=0x07 (Name) instead of 0x83 (AdjacencyLsa)
        let bad = Bytes::from_static(&[0x07, 0x00]);
        let err = AdjacencyLsa::wire_decode(bad).unwrap_err();
        assert_eq!(
            err,
            LsaCodecError::WrongType {
                expected: TLV_ADJACENCY_LSA,
                got: 7
            }
        );
    }

    #[test]
    fn adj_lsa_truncated_inner() {
        // Valid outer type+length but content cut short
        let bad = Bytes::from_static(&[0x83, 0x10, 0x80, 0x02, 0x07, 0x00]);
        let err = AdjacencyLsa::wire_decode(bad).unwrap_err();
        assert!(
            matches!(
                err,
                LsaCodecError::Tlv(_)
                    | LsaCodecError::MissingField(_)
                    | LsaCodecError::WrongType { .. }
            ),
            "expected codec error, got {err:?}"
        );
    }

    #[test]
    fn name_lsa_wrong_outer_type() {
        let bad = Bytes::from_static(&[0x83, 0x00]); // AdjacencyLsa type, not NameLsa
        let err = NameLsa::wire_decode(bad).unwrap_err();
        assert_eq!(
            err,
            LsaCodecError::WrongType {
                expected: TLV_NAME_LSA,
                got: TLV_ADJACENCY_LSA
            }
        );
    }

    #[test]
    fn coordinate_lsa_missing_radius() {
        // CoordinateLsa header only, no HyperbolicRadius
        let bad = Bytes::from_static(&[
            0x85, 0x27, 0x80, 0x23, 0x07, 0x09, 0x08, 0x07, 0x72, 0x6F, 0x75, 0x74, 0x65, 0x72,
            0x31, 0x82, 0x01, 0x0C, 0x8B, 0x13, 0x32, 0x30, 0x32, 0x30, 0x2D, 0x30, 0x33, 0x2D,
            0x32, 0x36, 0x20, 0x30, 0x34, 0x3A, 0x31, 0x33, 0x3A, 0x33, 0x34,
        ]);
        let err = CoordinateLsa::wire_decode(bad).unwrap_err();
        assert!(
            matches!(err, LsaCodecError::MissingField(_) | LsaCodecError::Tlv(_)),
            "expected MissingField or Tlv error, got {err:?}"
        );
    }

    #[test]
    fn invalid_datetime_length() {
        let err = parse_expiration_time("2020-03-26").unwrap_err();
        assert_eq!(err, LsaCodecError::InvalidDateTime);
    }
}
