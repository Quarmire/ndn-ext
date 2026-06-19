//! Adjacency LSA — active neighbours and link costs as seen by the
//! originating router. Flooded on every neighbour ACTIVE↔INACTIVE
//! transition.
//!
//! C++ ref: `NLSR/src/lsa/adj-lsa.{hpp,cpp}`, `NLSR/src/adjacent.{hpp,cpp}`.

use bytes::Bytes;
use ndn_packet::Name;
use ndn_tlv::{TlvReader, TlvWriter};

use super::{
    LsaCodecError, TLV_ADJACENCY, TLV_ADJACENCY_LSA, TLV_COST, TLV_URI, read_double,
    read_lsa_header, read_name, write_double, write_lsa_header, write_name,
};

/// Wire: `Adjacency = ADJACENCY-TYPE TLV-LENGTH Name Uri Cost`
/// (NLSR/src/adjacent.hpp:39-45). C++ equivalent: `Adjacent`.
#[derive(Clone, Debug, PartialEq)]
pub struct Adjacent {
    pub name: Name,
    /// NFD face URI string (e.g. `"udp://10.0.0.1"` or `"://"`).
    pub face_uri: String,
    /// IEEE 754 double; ndn-cxx ceil()s for display, never for the
    /// wire value.
    pub link_cost: f64,
}

/// Wire: `AdjLsa = ADJACENCY-LSA-TYPE TLV-LENGTH Lsa *Adjacency`
/// (NLSR/src/lsa/adj-lsa.hpp:38-42). Wall-clock millisecond timestamps
/// are serialised with second precision.
#[derive(Clone, Debug)]
pub struct AdjacencyLsa {
    pub origin_router: Name,
    /// Monotonically increasing per-type sequence number.
    pub seq_no: u64,
    pub expiration_ms: u64,
    pub adjacencies: Vec<Adjacent>,
}

impl AdjacencyLsa {
    /// C++: `AdjLsa::wireEncode` (`NLSR/src/lsa/adj-lsa.cpp:44-60`).
    pub fn wire_encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(TLV_ADJACENCY_LSA, |outer| {
            write_lsa_header(outer, &self.origin_router, self.seq_no, self.expiration_ms);
            for adj in &self.adjacencies {
                outer.write_nested(TLV_ADJACENCY, |a| {
                    write_name(a, &adj.name);
                    a.write_tlv(TLV_URI, adj.face_uri.as_bytes());
                    write_double(a, TLV_COST, adj.link_cost);
                });
            }
        });
        w.finish()
    }

    /// C++: `AdjLsa::wireDecode` (`NLSR/src/lsa/adj-lsa.cpp:83-113`).
    pub fn wire_decode(input: Bytes) -> Result<Self, LsaCodecError> {
        let mut r = TlvReader::new(input);
        let (outer_typ, outer_bytes) = r.read_tlv()?;
        if outer_typ != TLV_ADJACENCY_LSA {
            return Err(LsaCodecError::WrongType {
                expected: TLV_ADJACENCY_LSA,
                got: outer_typ,
            });
        }
        let mut outer = TlvReader::new(outer_bytes);

        let (origin_router, seq_no, expiration_ms) = read_lsa_header(&mut outer)?;

        let mut adjacencies = Vec::new();
        while !outer.is_empty() {
            let (adj_typ, adj_bytes) = outer.read_tlv()?;
            if adj_typ != TLV_ADJACENCY {
                return Err(LsaCodecError::WrongType {
                    expected: TLV_ADJACENCY,
                    got: adj_typ,
                });
            }
            let mut adj_r = TlvReader::new(adj_bytes);

            let name = read_name(&mut adj_r)?;

            let (uri_typ, uri_bytes) = adj_r.read_tlv()?;
            if uri_typ != TLV_URI {
                return Err(LsaCodecError::WrongType {
                    expected: TLV_URI,
                    got: uri_typ,
                });
            }
            let face_uri = std::str::from_utf8(&uri_bytes)
                .map_err(|_| LsaCodecError::InvalidUtf8)?
                .to_owned();

            let (cost_typ, cost_bytes) = adj_r.read_tlv()?;
            if cost_typ != TLV_COST {
                return Err(LsaCodecError::WrongType {
                    expected: TLV_COST,
                    got: cost_typ,
                });
            }
            let link_cost = read_double(&cost_bytes)?;

            adjacencies.push(Adjacent {
                name,
                face_uri,
                link_cost,
            });
        }

        Ok(AdjacencyLsa {
            origin_router,
            seq_no,
            expiration_ms,
            adjacencies,
        })
    }

    /// Returns whether the adjacency set changed.
    pub fn update(&mut self, _newer: &AdjacencyLsa) -> bool {
        todo!("AdjacencyLsa::update")
    }
}
