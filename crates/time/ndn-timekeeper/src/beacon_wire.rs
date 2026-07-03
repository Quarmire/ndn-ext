//! The time-beacon wire codec — the bytes a signed time-beacon Data carries as
//! its Content.
//!
//! Per the design there is no new *wire crate*: a beacon is a signed Data
//! packet under `/<scope>/time/<node>/<seq>`, and this is the encoding of its
//! Content. NDN Content is opaque bytes, so this is a small self-describing
//! layout the publisher and consumer agree on — a version byte followed by the
//! peer's `(seq, wall ± uncertainty, capability)` in fixed big-endian fields.
//! The signature over the Data (validated up in the security layer) is what
//! makes the beacon trustworthy; this module only (de)serialises the payload.

use bytes::Bytes;
use ndn_time::capability::{Holdover, TimeSourceKind, Traceability};
use ndn_time::{ClockCapability, MeasurementProvenance, TimeBeacon, TimeInterval};

/// Wire version. Bump on any layout change; the decoder rejects other versions.
pub const BEACON_WIRE_VERSION: u8 = 1;

/// Exact encoded length: version + seq + wall + uncertainty + kind + trace +
/// flags + base_uncertainty + drift + allan + aging.
const ENCODED_LEN: usize = 1 + 8 + 8 + 8 + 1 + 1 + 1 + 8 + 4 + 4 + 4;

const FLAG_DISCIPLINABLE: u8 = 1 << 0;
const FLAG_REFERENCE_ONLY: u8 = 1 << 1;
const FLAG_TEMP_SENSITIVE: u8 = 1 << 2;

fn kind_to_u8(k: TimeSourceKind) -> u8 {
    match k {
        TimeSourceKind::Gnss => 0,
        TimeSourceKind::Ptp => 1,
        TimeSourceKind::Ntp => 2,
        TimeSourceKind::Rtc => 3,
        TimeSourceKind::Oscillator => 4,
        TimeSourceKind::PeerDerived => 5,
        TimeSourceKind::Manual => 6,
    }
}

fn u8_to_kind(b: u8) -> Option<TimeSourceKind> {
    Some(match b {
        0 => TimeSourceKind::Gnss,
        1 => TimeSourceKind::Ptp,
        2 => TimeSourceKind::Ntp,
        3 => TimeSourceKind::Rtc,
        4 => TimeSourceKind::Oscillator,
        5 => TimeSourceKind::PeerDerived,
        6 => TimeSourceKind::Manual,
        _ => return None,
    })
}

fn trace_to_u8(t: Traceability) -> u8 {
    match t {
        Traceability::Utc => 0,
        Traceability::Tai => 1,
        Traceability::Gnss => 2,
        Traceability::Ensemble => 3,
        Traceability::None => 4,
    }
}

fn u8_to_trace(b: u8) -> Option<Traceability> {
    Some(match b {
        0 => Traceability::Utc,
        1 => Traceability::Tai,
        2 => Traceability::Gnss,
        3 => Traceability::Ensemble,
        4 => Traceability::None,
        _ => return None,
    })
}

/// A decoded beacon payload — the peer's assertion, before it is turned into a
/// discipline sample (which needs *our* reception circumstances).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct DecodedBeacon {
    /// The peer's beacon sequence number (monotone per node).
    pub seq: u64,
    /// The peer's wall estimate, Unix ns.
    pub wall_ns: i64,
    /// The peer's stated uncertainty (half-width), ns.
    pub uncertainty_ns: u64,
    /// The peer's self-described clock capability.
    pub cap: ClockCapability,
}

impl DecodedBeacon {
    /// Combine with *our* reception circumstances into a [`TimeBeacon`] the
    /// discipline loop can ingest. `captured_mono_ns` is our monotonic clock at
    /// reception; `prov` is what our validation established (which key signed
    /// it, over which path, replay-protected?).
    pub fn into_beacon(self, captured_mono_ns: u64, prov: MeasurementProvenance) -> TimeBeacon {
        TimeBeacon {
            wall: TimeInterval::new(self.wall_ns, self.uncertainty_ns),
            cap: self.cap,
            captured_mono_ns,
            prov,
        }
    }
}

/// Encode a beacon payload into Data-Content bytes.
pub fn encode(seq: u64, wall_ns: i64, uncertainty_ns: u64, cap: &ClockCapability) -> Bytes {
    let mut b = Vec::with_capacity(ENCODED_LEN);
    b.push(BEACON_WIRE_VERSION);
    b.extend_from_slice(&seq.to_be_bytes());
    b.extend_from_slice(&wall_ns.to_be_bytes());
    b.extend_from_slice(&uncertainty_ns.to_be_bytes());
    b.push(kind_to_u8(cap.kind));
    b.push(trace_to_u8(cap.traceable));
    let mut flags = 0u8;
    if cap.disciplinable {
        flags |= FLAG_DISCIPLINABLE;
    }
    if cap.reference_only {
        flags |= FLAG_REFERENCE_ONLY;
    }
    if cap.holdover.temp_sensitive {
        flags |= FLAG_TEMP_SENSITIVE;
    }
    b.push(flags);
    b.extend_from_slice(&cap.base_uncertainty_ns.to_be_bytes());
    b.extend_from_slice(&cap.holdover.drift_ppm.to_bits().to_be_bytes());
    b.extend_from_slice(&cap.holdover.allan_dev_1s.to_bits().to_be_bytes());
    b.extend_from_slice(&cap.holdover.aging_ppm_per_day.to_bits().to_be_bytes());
    Bytes::from(b)
}

/// Decode a beacon payload, or `None` on a wrong version / short buffer / bad
/// enum. Never panics on arbitrary input.
pub fn decode(content: &[u8]) -> Option<DecodedBeacon> {
    if content.len() < ENCODED_LEN || content[0] != BEACON_WIRE_VERSION {
        return None;
    }
    let mut o = 1;
    let take8 = |o: &mut usize| -> [u8; 8] {
        let v = content[*o..*o + 8].try_into().unwrap();
        *o += 8;
        v
    };
    let take4 = |o: &mut usize| -> [u8; 4] {
        let v = content[*o..*o + 4].try_into().unwrap();
        *o += 4;
        v
    };
    let seq = u64::from_be_bytes(take8(&mut o));
    let wall_ns = i64::from_be_bytes(take8(&mut o));
    let uncertainty_ns = u64::from_be_bytes(take8(&mut o));
    let kind = u8_to_kind(content[o])?;
    o += 1;
    let traceable = u8_to_trace(content[o])?;
    o += 1;
    let flags = content[o];
    o += 1;
    let base_uncertainty_ns = u64::from_be_bytes(take8(&mut o));
    let drift_ppm = f32::from_bits(u32::from_be_bytes(take4(&mut o)));
    let allan_dev_1s = f32::from_bits(u32::from_be_bytes(take4(&mut o)));
    let aging_ppm_per_day = f32::from_bits(u32::from_be_bytes(take4(&mut o)));

    Some(DecodedBeacon {
        seq,
        wall_ns,
        uncertainty_ns,
        cap: ClockCapability {
            kind,
            traceable,
            holdover: Holdover {
                drift_ppm,
                allan_dev_1s,
                aging_ppm_per_day,
                temp_sensitive: flags & FLAG_TEMP_SENSITIVE != 0,
            },
            base_uncertainty_ns,
            disciplinable: flags & FLAG_DISCIPLINABLE != 0,
            reference_only: flags & FLAG_REFERENCE_ONLY != 0,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_every_field() {
        let cap = ClockCapability::gnss_disciplined();
        let wire = encode(7, 1_700_000_000_500, 30, &cap);
        let d = decode(&wire).expect("valid");
        assert_eq!(d.seq, 7);
        assert_eq!(d.wall_ns, 1_700_000_000_500);
        assert_eq!(d.uncertainty_ns, 30);
        assert_eq!(d.cap, cap, "capability survives the round-trip");
    }

    #[test]
    fn rejects_wrong_version_and_short_input() {
        let wire = encode(1, 0, 0, &ClockCapability::oscillator_tcxo());
        let mut bad = wire.to_vec();
        bad[0] = 2; // wrong version
        assert!(decode(&bad).is_none());
        assert!(decode(&wire[..wire.len() - 1]).is_none(), "truncated");
        assert!(decode(&[]).is_none());
    }

    #[test]
    fn decoded_beacon_becomes_a_time_beacon() {
        use ndn_time::provenance::{Authenticity, KeyId, PathId};
        let cap = ClockCapability::oscillator_tcxo();
        let d = decode(&encode(3, 1_700_000_000_000, 2_000, &cap)).unwrap();
        let prov = MeasurementProvenance {
            distance_bounded: false,
            replay_protected: true,
            authenticity: Authenticity::AuthenticatedDomainPeer(KeyId(9)),
            path: PathId(2),
        };
        let beacon = d.into_beacon(42, prov);
        assert_eq!(beacon.wall.center_ns, 1_700_000_000_000);
        assert_eq!(beacon.wall.radius_ns, 2_000);
        assert_eq!(beacon.captured_mono_ns, 42);
    }
}
