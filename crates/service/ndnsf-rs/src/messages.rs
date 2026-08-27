//! NDNSF four-phase message taxonomy + TLV wire.
//!
//! The four messages of the exchange — `Request` / `Ack` / `Selection` /
//! `Response` — encoded with NDNSF's faithful TLV type numbers (so an ndn-rs
//! node interoperates with a C++ NDNSF node at the protocol level). Decoding is
//! tolerant (sub-fields read by type in a loop), so unknown/optional fields and
//! reordering do not break interop. This increment carries the core fields the
//! protocol + the [`crate::tokens`] state machine need; advanced fields
//! (strategy, policy-epoch, assignment payload) extend the same loop.

use bytes::Bytes;
use ndn_packet::Name;
use ndn_tlv::{TlvReader, TlvWriter};

/// `RequestMessage` envelope.
pub const REQUEST_MSG: u64 = 128;
/// `ResponseMessage` envelope.
pub const RESPONSE_MSG: u64 = 129;
/// `RequestAckMessage` envelope.
pub const ACK_MSG: u64 = 130;
/// `ServiceSelectionMessage` envelope.
pub const SELECTION_MSG: u64 = 131;

const PAYLOAD: u64 = 151;
const STATUS: u64 = 152;
const ERROR_INFO: u64 = 153;
const REQUEST_ID: u64 = 154;
const STRATEGY: u64 = 155;
const PROVIDER_NAME: u64 = 158;
const TARGET_IDENTITY: u64 = 161;
const USER_TOKEN: u64 = 170;
const PROVIDER_TOKEN: u64 = 171;
const ASSIGNMENT_PAYLOAD: u64 = 184;
const REQUEST_MODE: u64 = 189;
const SELECTION_PROVIDER_ENTRY: u64 = 0xF503;
const ATTEMPT: u64 = 0xF626;
const TLV_NAME: u64 = 0x07;

/// Negative-ACK reason codes (upstream spec 044 / `NegativeAckReason.hpp`). A
/// provider that cannot serve a request answers `status=false` with one of these
/// strings in the ACK's `error_info` field — **no new wire message** — and a user
/// holding an explicit provider list may stop early once every known provider
/// has negative-ACKed, instead of running out its ACK window.
pub mod reason {
    /// The provider's pending-request table is full.
    pub const QUEUE_FULL: &str = "QUEUE_FULL";
    /// The provider is busy (generic capacity).
    pub const PROVIDER_BUSY: &str = "PROVIDER_BUSY";
    /// The provider's accelerator is busy.
    pub const GPU_BUSY: &str = "GPU_BUSY";
    /// A model/artifact the request needs is not resident.
    pub const MODEL_UNAVAILABLE: &str = "MODEL_UNAVAILABLE";
    /// The requester is not authorized for this service.
    pub const PERMISSION_DENIED: &str = "PERMISSION_DENIED";
    /// The request is malformed/unsupported by this provider.
    pub const UNSUPPORTED_REQUEST: &str = "UNSUPPORTED_REQUEST";
    /// An internal provider error.
    pub const INTERNAL_ERROR: &str = "INTERNAL_ERROR";
    /// An execution lease was rejected.
    pub const LEASE_REJECTED: &str = "LEASE_REJECTED";
    /// An execution lease expired.
    pub const LEASE_EXPIRED: &str = "LEASE_EXPIRED";
    /// The operation's deadline passed before the provider could act.
    pub const OPERATION_EXPIRED: &str = "OPERATION_EXPIRED";

    /// Whether `reason` is one of the recommended (interoperable) codes. A
    /// non-recommended string still travels — the vocabulary is advisory, not
    /// load-bearing (faithful to upstream's `isRecommended`).
    pub fn is_recommended(reason: &str) -> bool {
        matches!(
            reason,
            QUEUE_FULL
                | PROVIDER_BUSY
                | GPU_BUSY
                | MODEL_UNAVAILABLE
                | PERMISSION_DENIED
                | UNSUPPORTED_REQUEST
                | INTERNAL_ERROR
                | LEASE_REJECTED
                | LEASE_EXPIRED
                | OPERATION_EXPIRED
        )
    }
}

/// The provider-bound selection **token-proof hash** (upstream compact V2
/// SELECTION): `SHA-256("SELECTION" ‖ requesterURI ‖ providerURI ‖ serviceURI ‖
/// providerToken)`, uppercase hex — so the shared (group-visible) selection
/// payload proves possession of a provider's token *to that provider only*,
/// without ever carrying the plaintext token. An empty `provider_token` yields
/// the empty string (faithful to upstream's guard).
///
/// Interop caveat: the URI inputs must render identically on both stacks. For
/// names of unreserved characters (alphanumerics, `-._~`) ndn-rs `Name` display
/// and ndn-cxx `Name::toUri()` agree; exotic components (other punctuation,
/// typed components) may percent-encode differently and then the hashes differ.
pub fn selection_token_proof_hash(
    requester: &Name,
    provider: &Name,
    service: &Name,
    provider_token: &str,
) -> String {
    use sha2::{Digest, Sha256};
    if provider_token.is_empty() {
        return String::new();
    }
    let mut h = Sha256::new();
    h.update(b"SELECTION");
    h.update(requester.to_string().as_bytes());
    h.update(provider.to_string().as_bytes());
    h.update(service.to_string().as_bytes());
    h.update(provider_token.as_bytes());
    let digest = h.finalize();
    let mut s = String::with_capacity(64);
    for b in digest {
        use core::fmt::Write;
        let _ = write!(s, "{b:02X}");
    }
    s
}

/// Provider-selection strategy a user requests (NDNSF `StrategyType`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Strategy {
    /// Select the first provider to ACK (default).
    #[default]
    FirstResponding,
    /// Select a random provider among those that ACK.
    RandomSelection,
    /// Select every provider that ACKs.
    AllSelected,
}

impl Strategy {
    fn to_u8(self) -> u8 {
        match self {
            Strategy::FirstResponding => 0,
            Strategy::RandomSelection => 1,
            Strategy::AllSelected => 2,
        }
    }
    fn from_u8(v: u8) -> Self {
        match v {
            1 => Strategy::RandomSelection,
            2 => Strategy::AllSelected,
            _ => Strategy::FirstResponding,
        }
    }
}

/// Request mode (NDNSF `RequestModeType`): the full four-phase exchange, or the
/// Targeted fast path that skips ACK/SELECTION using a pre-shared token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum RequestMode {
    /// REQUEST→ACK→SELECTION→RESPONSE (default).
    #[default]
    Normal,
    /// Direct REQUEST→RESPONSE to a known provider with a pre-issued token.
    Targeted,
    /// Targeted invocation that also requests a fresh token batch.
    TargetedBootstrap,
}

impl RequestMode {
    fn to_u8(self) -> u8 {
        match self {
            RequestMode::Normal => 0,
            RequestMode::Targeted => 1,
            RequestMode::TargetedBootstrap => 2,
        }
    }
    fn from_u8(v: u8) -> Self {
        match v {
            1 => RequestMode::Targeted,
            2 => RequestMode::TargetedBootstrap,
            _ => RequestMode::Normal,
        }
    }
}

/// A malformed NDNSF message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MsgError {
    /// The outer TLV type was not the expected message type.
    #[error("unexpected message type")]
    WrongType,
    /// The bytes were truncated or otherwise unparseable.
    #[error("malformed message")]
    Malformed,
}

// --- small TLV helpers -------------------------------------------------------

fn put_str(w: &mut TlvWriter, typ: u64, s: &str) {
    if !s.is_empty() {
        w.write_nested(typ, |i| i.write_raw(s.as_bytes()));
    }
}
fn put_bytes(w: &mut TlvWriter, typ: u64, b: &[u8]) {
    if !b.is_empty() {
        w.write_nested(typ, |i| i.write_raw(b));
    }
}
fn put_bool(w: &mut TlvWriter, typ: u64, v: bool) {
    w.write_nested(typ, |i| i.write_raw(&[u8::from(v)]));
}
fn put_u8(w: &mut TlvWriter, typ: u64, v: u8) {
    w.write_nested(typ, |i| i.write_raw(&[v]));
}
fn put_name(w: &mut TlvWriter, typ: u64, name: &Name) {
    w.write_nested(typ, |i| i.write_raw(&name.encode_to_tlv()));
}
/// NDN NonNegativeInteger: minimal 1/2/4/8-byte big-endian (upstream's
/// `makeNonNegativeIntegerBlock`).
fn put_nonneg(w: &mut TlvWriter, typ: u64, v: u64) {
    w.write_nested(typ, |i| {
        if v <= u64::from(u8::MAX) {
            i.write_raw(&[v as u8]);
        } else if v <= u64::from(u16::MAX) {
            i.write_raw(&(v as u16).to_be_bytes());
        } else if v <= u64::from(u32::MAX) {
            i.write_raw(&(v as u32).to_be_bytes());
        } else {
            i.write_raw(&v.to_be_bytes());
        }
    });
}
fn as_nonneg(b: &Bytes) -> u64 {
    // Tolerant: any 1..=8-byte big-endian value; longer/empty reads as 0.
    if b.is_empty() || b.len() > 8 {
        return 0;
    }
    b.iter().fold(0u64, |acc, &x| (acc << 8) | u64::from(x))
}

/// Read the inner sub-TLVs of a message envelope of type `expected`, returning
/// `(type, value)` pairs for a caller to fold into a struct.
fn open_envelope(bytes: Bytes, expected: u64) -> Result<Vec<(u64, Bytes)>, MsgError> {
    let mut outer = TlvReader::new(bytes);
    let (typ, body) = outer.read_tlv().map_err(|_| MsgError::Malformed)?;
    if typ != expected {
        return Err(MsgError::WrongType);
    }
    let mut r = TlvReader::new(body);
    let mut fields = Vec::new();
    while !r.is_empty() {
        fields.push(r.read_tlv().map_err(|_| MsgError::Malformed)?);
    }
    Ok(fields)
}

fn as_str(b: &Bytes) -> Result<String, MsgError> {
    String::from_utf8(b.to_vec()).map_err(|_| MsgError::Malformed)
}

fn as_name(b: &Bytes) -> Result<Name, MsgError> {
    let mut r = TlvReader::new(b.clone());
    let (typ, inner) = r.read_tlv().map_err(|_| MsgError::Malformed)?;
    if typ != TLV_NAME {
        return Err(MsgError::Malformed);
    }
    Name::decode(inner).map_err(|_| MsgError::Malformed)
}

/// Phase 1 — a user's service request.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RequestMessage {
    /// Unique request identifier.
    pub request_id: String,
    /// An opaque capability token the user presents and the provider echoes. NOTE:
    /// the four-phase flow does **not** validate it — it is carried, not load-bearing
    /// (red-team SEC-30). Payload authorization is the caller's job, via KP-ABE
    /// access control (`access::seal_for` / `open_with`), not this field.
    pub user_token: String,
    /// The request payload.
    pub payload: Bytes,
    /// Provider-selection strategy the user requests.
    pub strategy: Strategy,
    /// Whether this is the full four-phase exchange or a Targeted fast path.
    pub request_mode: RequestMode,
    /// For a Targeted request, the intended provider.
    pub target_provider: Option<Name>,
    /// For a Targeted request, the pre-issued provider token presented directly
    /// (empty in NormalRequest).
    pub provider_token: String,
}

impl RequestMessage {
    /// Encode to the NDNSF wire.
    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(REQUEST_MSG, |i| {
            put_str(i, REQUEST_ID, &self.request_id);
            put_str(i, USER_TOKEN, &self.user_token);
            put_bytes(i, PAYLOAD, &self.payload);
            put_u8(i, STRATEGY, self.strategy.to_u8());
            put_u8(i, REQUEST_MODE, self.request_mode.to_u8());
            if let Some(tp) = &self.target_provider {
                put_name(i, TARGET_IDENTITY, tp);
            }
            put_str(i, PROVIDER_TOKEN, &self.provider_token);
        });
        w.finish()
    }
    /// Decode from the NDNSF wire (tolerant of field order / unknown fields).
    pub fn decode(bytes: Bytes) -> Result<Self, MsgError> {
        let mut m = Self::default();
        for (typ, val) in open_envelope(bytes, REQUEST_MSG)? {
            match typ {
                REQUEST_ID => m.request_id = as_str(&val)?,
                USER_TOKEN => m.user_token = as_str(&val)?,
                PAYLOAD => m.payload = val,
                STRATEGY => m.strategy = Strategy::from_u8(val.first().copied().unwrap_or(0)),
                REQUEST_MODE => {
                    m.request_mode = RequestMode::from_u8(val.first().copied().unwrap_or(0))
                }
                TARGET_IDENTITY => m.target_provider = Some(as_name(&val)?),
                PROVIDER_TOKEN => m.provider_token = as_str(&val)?,
                _ => {} // ignore unknown/optional fields
            }
        }
        Ok(m)
    }
}

/// Phase 2 — a provider's acknowledgement, carrying the one-time provider token.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AckMessage {
    /// Whether the provider can serve the request. `false` is a **negative ACK**
    /// (spec 044): `error_info` then carries a [`reason`] code.
    pub status: bool,
    /// On a negative ACK, the reason code (see [`reason`]); empty otherwise.
    /// Upstream's `RequestAckMessage.message`, on the `ErrorInfo` TLV.
    pub error_info: String,
    /// Echoes the request's user token.
    pub user_token: String,
    /// The single-use provider token the user must present in its SELECTION.
    pub provider_token: String,
    /// Optional ACK metadata payload.
    pub payload: Bytes,
}

impl AckMessage {
    /// Encode to the NDNSF wire.
    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(ACK_MSG, |i| {
            put_bool(i, STATUS, self.status);
            put_str(i, ERROR_INFO, &self.error_info);
            put_str(i, USER_TOKEN, &self.user_token);
            put_str(i, PROVIDER_TOKEN, &self.provider_token);
            put_bytes(i, PAYLOAD, &self.payload);
        });
        w.finish()
    }
    /// Decode from the NDNSF wire.
    pub fn decode(bytes: Bytes) -> Result<Self, MsgError> {
        let mut m = Self::default();
        for (typ, val) in open_envelope(bytes, ACK_MSG)? {
            match typ {
                STATUS => m.status = val.first().copied().unwrap_or(0) != 0,
                ERROR_INFO => m.error_info = as_str(&val)?,
                USER_TOKEN => m.user_token = as_str(&val)?,
                PROVIDER_TOKEN => m.provider_token = as_str(&val)?,
                PAYLOAD => m.payload = val,
                _ => {}
            }
        }
        Ok(m)
    }

    /// A negative ACK (`status=false`) with a [`reason`] code, echoing the
    /// request's user token. Carries no provider token — nothing is pending.
    pub fn negative(reason: &str, user_token: &str) -> Self {
        Self {
            status: false,
            error_info: reason.to_string(),
            user_token: user_token.to_string(),
            ..Self::default()
        }
    }
}

/// One provider's slot in a **compact** (unified V2) SELECTION: who is selected,
/// the proof it may consume its own token, and its per-provider assignment.
/// Faithful to upstream `SelectionProviderEntry` (TLV `0xF503`): the provider
/// name travels as its **URI string** (not a wire-encoded Name), the proof hash
/// rides the `ProviderToken` TLV number.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectionProviderEntry {
    /// The selected provider.
    pub provider_name: Name,
    /// [`selection_token_proof_hash`] over this provider's token — never the
    /// plaintext token (the security point of the compact shape).
    pub provider_token_hash: String,
    /// Optional per-provider assignment payload.
    pub assignment_payload: Bytes,
}

impl SelectionProviderEntry {
    fn encode_into(&self, w: &mut TlvWriter) {
        w.write_nested(SELECTION_PROVIDER_ENTRY, |i| {
            put_str(i, PROVIDER_NAME, &self.provider_name.to_string());
            put_str(i, PROVIDER_TOKEN, &self.provider_token_hash);
            put_bytes(i, ASSIGNMENT_PAYLOAD, &self.assignment_payload);
        });
    }
    fn decode(body: Bytes) -> Result<Self, MsgError> {
        let mut provider_name: Option<Name> = None;
        let mut provider_token_hash = String::new();
        let mut assignment_payload = Bytes::new();
        let mut r = TlvReader::new(body);
        while !r.is_empty() {
            let (typ, val) = r.read_tlv().map_err(|_| MsgError::Malformed)?;
            match typ {
                PROVIDER_NAME => {
                    provider_name = Some(as_str(&val)?.parse().map_err(|_| MsgError::Malformed)?);
                }
                PROVIDER_TOKEN => provider_token_hash = as_str(&val)?,
                ASSIGNMENT_PAYLOAD => assignment_payload = val,
                _ => {}
            }
        }
        // An entry without a provider name selects nobody — malformed.
        let provider_name = provider_name.ok_or(MsgError::Malformed)?;
        Ok(Self {
            provider_name,
            provider_token_hash,
            assignment_payload,
        })
    }
}

/// Phase 3 — the user's selection of provider(s).
///
/// Two accepted shapes, both decoded by the same tolerant loop:
///
/// * **Compact / unified V2** (what upstream emits today, and what our driver
///   emits): one publication under `/<requester>/NDNSF/SELECTION/<service>/<id>`
///   whose `provider_entries` name each **selected** provider with a token-proof
///   hash. A provider that finds no entry for itself was not selected.
/// * **Legacy per-provider** (pre-2026-06-07; still accepted inbound): a
///   per-provider name carrying the plaintext `provider_token`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectionMessage {
    /// Legacy shape only: the plaintext single-use provider token. Empty in the
    /// compact shape (the proof hash in each entry replaces it).
    pub provider_token: String,
    /// The request id this selection resolves.
    pub request_id: String,
    /// Compact shape: one entry per **selected** provider.
    pub provider_entries: Vec<SelectionProviderEntry>,
    /// Selection attempt counter (upstream TLV `0xF626`; starts at 1).
    pub attempt: u64,
}

impl Default for SelectionMessage {
    fn default() -> Self {
        Self {
            provider_token: String::new(),
            request_id: String::new(),
            provider_entries: Vec::new(),
            attempt: 1,
        }
    }
}

impl SelectionMessage {
    /// Encode to the NDNSF wire.
    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(SELECTION_MSG, |i| {
            put_str(i, REQUEST_ID, &self.request_id);
            put_str(i, PROVIDER_TOKEN, &self.provider_token);
            put_nonneg(i, ATTEMPT, self.attempt);
            for entry in &self.provider_entries {
                entry.encode_into(i);
            }
        });
        w.finish()
    }
    /// Decode from the NDNSF wire.
    pub fn decode(bytes: Bytes) -> Result<Self, MsgError> {
        let mut m = Self::default();
        for (typ, val) in open_envelope(bytes, SELECTION_MSG)? {
            match typ {
                PROVIDER_TOKEN => m.provider_token = as_str(&val)?,
                REQUEST_ID => m.request_id = as_str(&val)?,
                ATTEMPT => m.attempt = as_nonneg(&val),
                SELECTION_PROVIDER_ENTRY => {
                    m.provider_entries
                        .push(SelectionProviderEntry::decode(val)?);
                }
                _ => {}
            }
        }
        Ok(m)
    }
}

/// Phase 4 — the selected provider's response.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ResponseMessage {
    /// Whether the invocation succeeded.
    pub status: bool,
    /// Error detail when `status` is false.
    pub error_info: String,
    /// The result payload.
    pub payload: Bytes,
}

impl ResponseMessage {
    /// Encode to the NDNSF wire.
    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(RESPONSE_MSG, |i| {
            put_bool(i, STATUS, self.status);
            put_str(i, ERROR_INFO, &self.error_info);
            put_bytes(i, PAYLOAD, &self.payload);
        });
        w.finish()
    }
    /// Decode from the NDNSF wire.
    pub fn decode(bytes: Bytes) -> Result<Self, MsgError> {
        let mut m = Self::default();
        for (typ, val) in open_envelope(bytes, RESPONSE_MSG)? {
            match typ {
                STATUS => m.status = val.first().copied().unwrap_or(0) != 0,
                ERROR_INFO => m.error_info = as_str(&val)?,
                PAYLOAD => m.payload = val,
                _ => {}
            }
        }
        Ok(m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trip() {
        let m = RequestMessage {
            request_id: "r1".into(),
            user_token: "utok".into(),
            payload: Bytes::from_static(b"do the thing"),
            ..Default::default()
        };
        let decoded = RequestMessage::decode(m.encode()).unwrap();
        assert_eq!(decoded, m);
        // defaults are faithful: FirstResponding / Normal.
        assert_eq!(decoded.strategy, Strategy::FirstResponding);
        assert_eq!(decoded.request_mode, RequestMode::Normal);
    }

    #[test]
    fn request_strategy_mode_target_round_trip() {
        let m = RequestMessage {
            request_id: "r2".into(),
            user_token: "utok".into(),
            payload: Bytes::new(),
            strategy: Strategy::RandomSelection,
            request_mode: RequestMode::Targeted,
            target_provider: Some("/muas/bob".parse().unwrap()),
            provider_token: "ptok".into(),
        };
        assert_eq!(RequestMessage::decode(m.encode()).unwrap(), m);
    }

    #[test]
    fn ack_round_trip() {
        let m = AckMessage {
            status: true,
            user_token: "utok".into(),
            provider_token: "ptok".into(),
            ..Default::default()
        };
        assert_eq!(AckMessage::decode(m.encode()).unwrap(), m);
    }

    #[test]
    fn selection_round_trip() {
        let m = SelectionMessage {
            provider_token: "ptok".into(),
            request_id: "r1".into(),
            ..Default::default()
        };
        assert_eq!(SelectionMessage::decode(m.encode()).unwrap(), m);
    }

    #[test]
    fn response_round_trip() {
        let m = ResponseMessage {
            status: false,
            error_info: "denied".into(),
            payload: Bytes::new(),
        };
        assert_eq!(ResponseMessage::decode(m.encode()).unwrap(), m);
    }

    #[test]
    fn ack_negative_reason_round_trip() {
        let m = AckMessage::negative(reason::QUEUE_FULL, "utok");
        let decoded = AckMessage::decode(m.encode()).unwrap();
        assert!(!decoded.status);
        assert_eq!(decoded.error_info, "QUEUE_FULL");
        assert!(decoded.provider_token.is_empty());
        assert!(reason::is_recommended(&decoded.error_info));
        assert!(!reason::is_recommended("MADE_UP"));
    }

    #[test]
    fn compact_selection_round_trip() {
        let m = SelectionMessage {
            request_id: "r1".into(),
            attempt: 2,
            provider_entries: vec![
                SelectionProviderEntry {
                    provider_name: "/met/stationA".parse().unwrap(),
                    provider_token_hash: "AB".repeat(32),
                    assignment_payload: Bytes::from_static(b"role=primary;"),
                },
                SelectionProviderEntry {
                    provider_name: "/met/stationB".parse().unwrap(),
                    provider_token_hash: "CD".repeat(32),
                    assignment_payload: Bytes::new(),
                },
            ],
            ..Default::default()
        };
        assert_eq!(SelectionMessage::decode(m.encode()).unwrap(), m);
    }

    #[test]
    fn legacy_selection_still_round_trips() {
        // The pre-compact shape (plaintext token, no entries) must keep decoding —
        // upstream and we both accept it inbound.
        let m = SelectionMessage {
            provider_token: "ptok".into(),
            request_id: "r1".into(),
            ..Default::default()
        };
        let decoded = SelectionMessage::decode(m.encode()).unwrap();
        assert_eq!(decoded, m);
        assert!(decoded.provider_entries.is_empty());
        assert_eq!(decoded.attempt, 1);
    }

    #[test]
    fn selection_token_proof_hash_matches_upstream_recipe() {
        // Pinned vector: SHA-256("SELECTION" ‖ "/muas/alice" ‖ "/met/stationA" ‖
        // "/svc/weather" ‖ "deadbeef"), uppercase hex — the exact byte-feed order
        // of upstream computeSelectionProviderTokenProofHash (utils.cpp).
        let h = selection_token_proof_hash(
            &"/muas/alice".parse().unwrap(),
            &"/met/stationA".parse().unwrap(),
            &"/svc/weather".parse().unwrap(),
            "deadbeef",
        );
        assert_eq!(
            h,
            "D806419D1323BD3D555F00E13377348D0D2AE068F278D2196C4B6BF57CAD0B06"
        );
        // Empty token ⇒ empty hash (faithful guard).
        assert_eq!(
            selection_token_proof_hash(
                &"/a".parse().unwrap(),
                &"/b".parse().unwrap(),
                &"/c".parse().unwrap(),
                ""
            ),
            ""
        );
    }

    #[test]
    fn decode_rejects_wrong_envelope_type() {
        // An ACK is not a Request.
        let ack = AckMessage {
            status: true,
            ..Default::default()
        };
        assert_eq!(
            RequestMessage::decode(ack.encode()),
            Err(MsgError::WrongType)
        );
    }

    #[test]
    fn decode_tolerates_unknown_fields() {
        // A Request with an extra (future) sub-field still decodes its known ones.
        let mut w = TlvWriter::new();
        w.write_nested(REQUEST_MSG, |i| {
            i.write_nested(REQUEST_ID, |x| x.write_raw(b"r1"));
            i.write_nested(0x1FE, |x| x.write_raw(b"future")); // unknown field
        });
        let m = RequestMessage::decode(w.finish()).unwrap();
        assert_eq!(m.request_id, "r1");
    }
}
