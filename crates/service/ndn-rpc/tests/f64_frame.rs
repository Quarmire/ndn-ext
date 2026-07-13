//! Gate: `f64`/`f32` implement `Frame`, so a **number-heavy contract** (flight
//! telemetry) frames each numeric field *per-field and length-prefixed* via
//! `#[derive(Frame)]` — no whole-struct JSON fallback. The per-field framing is
//! skippable-TLV-compatible: appending a field is forward-compatible, an older
//! peer reads the prefix fields it knows and ignores the rest.

use ndn_service_core::Frame;
use ndn_service_macro::Frame;

/// A number-heavy flight contract — the case that previously fell back to a
/// whole-struct JSON `Frame` for lack of an `f64` impl.
#[derive(Frame, Debug, PartialEq)]
struct Telemetry {
    lat: f64,
    lon: f64,
    alt_m: f32,
    heading_deg: f64,
    airspeed_ms: f32,
    fix_quality: u32,
}

/// The same contract evolved by **appending** a field (the forward-compatible
/// change). An older peer decoding as [`Telemetry`] must still read the prefix.
#[derive(Frame, Debug, PartialEq)]
struct TelemetryV2 {
    lat: f64,
    lon: f64,
    alt_m: f32,
    heading_deg: f64,
    airspeed_ms: f32,
    fix_quality: u32,
    battery_v: f32,
}

/// A single `f64` field to pin the per-field wire shape.
#[derive(Frame)]
struct OneF64 {
    v: f64,
}

#[test]
fn number_heavy_contract_round_trips() {
    let t = Telemetry {
        lat: 37.241_92,
        lon: -115.816_58,
        alt_m: 1360.5,
        heading_deg: 271.333_333_333,
        airspeed_ms: 42.7,
        fix_quality: 3,
    };
    let wire = t.encode();
    let back = Telemetry::decode(&wire).expect("telemetry must decode");
    // Bit-exact round-trip: the floats survive the length-prefixed field framing.
    assert_eq!(back, t);
}

#[test]
fn f64_field_is_per_field_length_prefixed() {
    // One f64 field on the wire is `[u32 len = 8][8 LE bytes]` = 12 bytes — the
    // per-field length prefix, not a positional or JSON encoding.
    let wire = OneF64 { v: 1.5 }.encode();
    assert_eq!(wire.len(), 12, "one f64 field = 4-byte length + 8-byte value");
    assert_eq!(&wire[0..4], &8u32.to_le_bytes(), "length prefix is 8");
    assert_eq!(&wire[4..12], &1.5f64.to_le_bytes(), "little-endian f64 body");
}

#[test]
fn appended_field_is_forward_compatible() {
    let v2 = TelemetryV2 {
        lat: 37.241_92,
        lon: -115.816_58,
        alt_m: 1360.5,
        heading_deg: 271.333_333_333,
        airspeed_ms: 42.7,
        fix_quality: 3,
        battery_v: 22.4,
    };
    let wire = v2.encode();
    // An older peer that only knows `Telemetry` reads its fields and skips the
    // appended `battery_v` — the length-prefixing makes the extra field skippable.
    let old = Telemetry::decode(&wire).expect("older peer must still decode the prefix");
    assert_eq!(
        old,
        Telemetry {
            lat: v2.lat,
            lon: v2.lon,
            alt_m: v2.alt_m,
            heading_deg: v2.heading_deg,
            airspeed_ms: v2.airspeed_ms,
            fix_quality: v2.fix_quality,
        }
    );
}
