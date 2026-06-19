//! Name LSA — NDN name prefixes a router advertises into the routing
//! domain. Rebuilt on every local prefix-list change and flooded via
//! PSync.
//!
//! C++ ref: `NLSR/src/lsa/name-lsa.{hpp,cpp}`,
//! `NLSR/src/name-prefix-list.hpp:39-100`.

use bytes::Bytes;
use ndn_packet::Name;
use ndn_tlv::{TlvReader, TlvWriter};

use super::{
    LsaCodecError, TLV_COST, TLV_NAME_LSA, TLV_PREFIX_INFO, read_double, read_lsa_header,
    read_name, write_double, write_lsa_header, write_name,
};

/// Wire: `PrefixInfo = PREFIX-INFO-TYPE TLV-LENGTH Name Cost`
/// (NLSR/src/name-prefix-list.hpp:73-78). C++: `PrefixInfo`.
#[derive(Clone, Debug, PartialEq)]
pub struct PrefixInfo {
    pub name: Name,
    pub cost: f64,
}

/// Wire: `NameLsa = NAME-LSA-TYPE TLV-LENGTH Lsa 1*PrefixInfo`
/// (NLSR/src/lsa/name-lsa.hpp:37-42). Wall-clock millisecond
/// timestamps serialise with second precision.
#[derive(Clone, Debug)]
pub struct NameLsa {
    pub origin_router: Name,
    pub seq_no: u64,
    pub expiration_ms: u64,
    pub prefixes: Vec<PrefixInfo>,
}

impl NameLsa {
    /// C++: `NameLsa::wireEncode` (`NLSR/src/lsa/name-lsa.cpp:44-59`).
    pub fn wire_encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(TLV_NAME_LSA, |outer| {
            write_lsa_header(outer, &self.origin_router, self.seq_no, self.expiration_ms);
            for p in &self.prefixes {
                outer.write_nested(TLV_PREFIX_INFO, |pi| {
                    write_name(pi, &p.name);
                    write_double(pi, TLV_COST, p.cost);
                });
            }
        });
        w.finish()
    }

    /// C++: `NameLsa::wireDecode` (`NLSR/src/lsa/name-lsa.cpp:83-114`).
    pub fn wire_decode(input: Bytes) -> Result<Self, LsaCodecError> {
        let mut r = TlvReader::new(input);
        let (outer_typ, outer_bytes) = r.read_tlv()?;
        if outer_typ != TLV_NAME_LSA {
            return Err(LsaCodecError::WrongType {
                expected: TLV_NAME_LSA,
                got: outer_typ,
            });
        }
        let mut outer = TlvReader::new(outer_bytes);

        let (origin_router, seq_no, expiration_ms) = read_lsa_header(&mut outer)?;

        let mut prefixes = Vec::new();
        while !outer.is_empty() {
            let (pi_typ, pi_bytes) = outer.read_tlv()?;
            if pi_typ != TLV_PREFIX_INFO {
                return Err(LsaCodecError::WrongType {
                    expected: TLV_PREFIX_INFO,
                    got: pi_typ,
                });
            }
            let mut pi_r = TlvReader::new(pi_bytes);

            let name = read_name(&mut pi_r)?;

            let (cost_typ, cost_bytes) = pi_r.read_tlv()?;
            if cost_typ != TLV_COST {
                return Err(LsaCodecError::WrongType {
                    expected: TLV_COST,
                    got: cost_typ,
                });
            }
            let cost = read_double(&cost_bytes)?;

            prefixes.push(PrefixInfo { name, cost });
        }

        Ok(NameLsa {
            origin_router,
            seq_no,
            expiration_ms,
            prefixes,
        })
    }

    /// Returns `(changed, prefixes_added, prefixes_removed)`.
    pub fn update(&mut self, _newer: &NameLsa) -> (bool, Vec<PrefixInfo>, Vec<PrefixInfo>) {
        todo!("NameLsa::update")
    }
}
