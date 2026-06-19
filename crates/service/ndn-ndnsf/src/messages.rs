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
const USER_TOKEN: u64 = 170;
const PROVIDER_TOKEN: u64 = 171;

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

/// Phase 1 — a user's service request.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RequestMessage {
    /// Unique request identifier.
    pub request_id: String,
    /// One-time user token authorizing this request.
    pub user_token: String,
    /// The request payload.
    pub payload: Bytes,
}

impl RequestMessage {
    /// Encode to the NDNSF wire.
    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(REQUEST_MSG, |i| {
            put_str(i, REQUEST_ID, &self.request_id);
            put_str(i, USER_TOKEN, &self.user_token);
            put_bytes(i, PAYLOAD, &self.payload);
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
                _ => {} // ignore unknown/optional fields
            }
        }
        Ok(m)
    }
}

/// Phase 2 — a provider's acknowledgement, carrying the one-time provider token.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AckMessage {
    /// Whether the provider can serve the request.
    pub status: bool,
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
                USER_TOKEN => m.user_token = as_str(&val)?,
                PROVIDER_TOKEN => m.provider_token = as_str(&val)?,
                PAYLOAD => m.payload = val,
                _ => {}
            }
        }
        Ok(m)
    }
}

/// Phase 3 — the user's selection of a provider, presenting its provider token.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SelectionMessage {
    /// The single-use provider token from the chosen provider's ACK.
    pub provider_token: String,
    /// The request id this selection resolves.
    pub request_id: String,
}

impl SelectionMessage {
    /// Encode to the NDNSF wire.
    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(SELECTION_MSG, |i| {
            put_str(i, PROVIDER_TOKEN, &self.provider_token);
            put_str(i, REQUEST_ID, &self.request_id);
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
        };
        assert_eq!(RequestMessage::decode(m.encode()).unwrap(), m);
    }

    #[test]
    fn ack_round_trip() {
        let m = AckMessage {
            status: true,
            user_token: "utok".into(),
            provider_token: "ptok".into(),
            payload: Bytes::new(),
        };
        assert_eq!(AckMessage::decode(m.encode()).unwrap(), m);
    }

    #[test]
    fn selection_round_trip() {
        let m = SelectionMessage {
            provider_token: "ptok".into(),
            request_id: "r1".into(),
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
    fn decode_rejects_wrong_envelope_type() {
        // An ACK is not a Request.
        let ack = AckMessage {
            status: true,
            ..Default::default()
        };
        assert_eq!(RequestMessage::decode(ack.encode()), Err(MsgError::WrongType));
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
