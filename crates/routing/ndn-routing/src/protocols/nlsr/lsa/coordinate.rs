//! Coordinate LSA — hyperbolic (r, θ) coordinates from one router.
//! Only built and flooded under `HyperbolicState::On` / `DryRun`. The
//! codec lives here for wire completeness; HR routing itself is not
//! wired yet.
//!
//! C++ ref: `NLSR/src/lsa/coordinate-lsa.{hpp,cpp}`.

use bytes::Bytes;
use ndn_packet::Name;
use ndn_tlv::{TlvReader, TlvWriter};

use super::{
    LsaCodecError, TLV_COORDINATE_LSA, TLV_HYPERBOLIC_ANGLE, TLV_HYPERBOLIC_RADIUS, read_double,
    read_lsa_header, write_double, write_lsa_header,
};

/// Wire: `CoordinateLsa = COORDINATE-LSA-TYPE TLV-LENGTH Lsa
/// HyperbolicRadius 1*HyperbolicAngle` (NLSR/src/lsa/coordinate-lsa.hpp:38-47).
/// Wall-clock millisecond timestamps serialise with second precision.
#[derive(Clone, Debug)]
pub struct CoordinateLsa {
    pub origin_router: Name,
    pub seq_no: u64,
    pub expiration_ms: u64,
    /// `r ≥ 0`.
    pub radius: f64,
    /// One per dimension; typically one value for 2-D HR routing.
    pub angles: Vec<f64>,
}

impl CoordinateLsa {
    /// C++: `CoordinateLsa::wireEncode`
    /// (`NLSR/src/lsa/coordinate-lsa.cpp:41-59`).
    pub fn wire_encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(TLV_COORDINATE_LSA, |outer| {
            write_lsa_header(outer, &self.origin_router, self.seq_no, self.expiration_ms);
            write_double(outer, TLV_HYPERBOLIC_RADIUS, self.radius);
            for &angle in &self.angles {
                write_double(outer, TLV_HYPERBOLIC_ANGLE, angle);
            }
        });
        w.finish()
    }

    /// C++: `CoordinateLsa::wireDecode`
    /// (`NLSR/src/lsa/coordinate-lsa.cpp:82-120`).
    pub fn wire_decode(input: Bytes) -> Result<Self, LsaCodecError> {
        let mut r = TlvReader::new(input);
        let (outer_typ, outer_bytes) = r.read_tlv()?;
        if outer_typ != TLV_COORDINATE_LSA {
            return Err(LsaCodecError::WrongType {
                expected: TLV_COORDINATE_LSA,
                got: outer_typ,
            });
        }
        let mut outer = TlvReader::new(outer_bytes);

        let (origin_router, seq_no, expiration_ms) = read_lsa_header(&mut outer)?;

        if outer.is_empty() {
            return Err(LsaCodecError::MissingField("HyperbolicRadius"));
        }
        let (radius_typ, radius_bytes) = outer.read_tlv()?;
        if radius_typ != TLV_HYPERBOLIC_RADIUS {
            return Err(LsaCodecError::WrongType {
                expected: TLV_HYPERBOLIC_RADIUS,
                got: radius_typ,
            });
        }
        let radius = read_double(&radius_bytes)?;

        let mut angles = Vec::new();
        while !outer.is_empty() {
            let (angle_typ, angle_bytes) = outer.read_tlv()?;
            if angle_typ != TLV_HYPERBOLIC_ANGLE {
                return Err(LsaCodecError::WrongType {
                    expected: TLV_HYPERBOLIC_ANGLE,
                    got: angle_typ,
                });
            }
            angles.push(read_double(&angle_bytes)?);
        }

        Ok(CoordinateLsa {
            origin_router,
            seq_no,
            expiration_ms,
            radius,
            angles,
        })
    }

    pub fn update(&mut self, _newer: &CoordinateLsa) -> bool {
        todo!("CoordinateLsa::update")
    }
}
