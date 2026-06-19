//! The service abstraction core: the **contract ⇄ carrier seam** (service-layer
//! spec §12).
//!
//! A *service* is a typed set of **unary** operations (request → response). A
//! [`Carrier`] is the pluggable backend that names, transports, multiplexes, and
//! secures an invocation. One service definition runs over any carrier — Tier-0
//! `ndn-rpc` ([`ndn_rpc::RpcCarrier`]), the NDNSF four-phase, or v2 — unchanged.
//!
//! This crate holds only the seam (no transport): the [`Carrier`] /
//! [`SelectCarrier`] traits, the server-side [`Dispatch`] a service exposes, the
//! [`Frame`] message-framing trait, and the [`Invocation`] / [`Response`] context
//! objects. The `#[ndn_service]` macro (planned) emits, from a unary trait, the
//! per-op [`Frame`] types, a [`Dispatch`] impl that routes an [`OpId`] to the
//! typed handler, and a client generic over `C: Carrier`.
//!
//! Design invariants (§12.5), enforced by convention here and by carriers:
//! - **Unary only.** Streaming/pub-sub is a *separate* primitive, not a member.
//! - **Evolvable framing.** [`Frame`] implementors use TLV with skippable unknown
//!   fields (never positional encoding), so services evolve by appending fields.
//! - **Idempotent ops.** A carrier may retry or multicast; operations must be
//!   idempotent (multi-provider carriers additionally enforce once-only).

#![deny(missing_docs)]

use std::sync::Arc;

use bytes::Bytes;
use ndn_packet::Name;

// Re-exports so `#[ndn_service]`-generated code can reference everything through
// this crate, without the consumer needing these as direct dependencies.
#[doc(hidden)]
pub use async_trait;
#[doc(hidden)]
pub use bytes;
#[doc(hidden)]
pub use ndn_packet;

/// A service identity: the name prefix the service is reached under
/// (e.g. `/svc/echo`). Operations hang below it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceId(Name);

impl ServiceId {
    /// Wrap a service prefix name.
    pub fn new(prefix: Name) -> Self {
        Self(prefix)
    }

    /// The service prefix name.
    pub fn name(&self) -> &Name {
        &self.0
    }
}

impl From<Name> for ServiceId {
    fn from(n: Name) -> Self {
        Self(n)
    }
}

/// An operation identity within a service — the method name (e.g. `"echo"`),
/// carried as a single name component by name-based carriers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpId(String);

impl OpId {
    /// An operation id from its method name.
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// The method name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Typed message ⇄ wire framing. Implementors MUST use TLV with skippable unknown
/// fields (the `#[ndn_service]` macro derives this); decoding tolerates appended
/// fields so a service can evolve without breaking peers (§12.5).
pub trait Frame: Sized + Send {
    /// Encode to wire bytes.
    fn encode(&self) -> Bytes;
    /// Decode from wire bytes, tolerating unknown trailing fields.
    fn decode(bytes: &[u8]) -> Result<Self, ServiceError>;
}

/// Why a service invocation did not yield a usable response.
#[derive(Debug)]
pub enum ServiceError {
    /// A request/response payload could not be decoded.
    Decode(String),
    /// No such operation, or no provider answered.
    NotFound,
    /// The handler ran but failed.
    Handler(String),
    /// The carrier's transport failed.
    Transport(String),
    /// The request was rejected for lack of authorization (trust/capability/ABE).
    Unauthorized(String),
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceError::Decode(e) => write!(f, "service payload decode failed: {e}"),
            ServiceError::NotFound => write!(f, "no such operation or no provider answered"),
            ServiceError::Handler(e) => write!(f, "service handler failed: {e}"),
            ServiceError::Transport(e) => write!(f, "service transport failed: {e}"),
            ServiceError::Unauthorized(e) => write!(f, "service request unauthorized: {e}"),
        }
    }
}

impl std::error::Error for ServiceError {}

/// A single provider's response to an invocation.
#[derive(Clone, Debug)]
pub struct Response {
    /// The provider that produced this response (the Data's name/signer scope).
    pub producer: Name,
    /// The response payload (a [`Frame`]-encoded message, opaque to the carrier).
    pub payload: Bytes,
}

/// The server-side context a carrier hands each inbound invocation. The
/// `requester` is populated by carriers that authenticate the request (so a
/// handler can make access decisions); `None` on unauthenticated carriers.
#[derive(Clone, Debug)]
pub struct Invocation {
    /// The operation being invoked.
    pub op: OpId,
    /// The request payload (a [`Frame`]-encoded message).
    pub request: Bytes,
    /// The authenticated requester identity, if the carrier established one.
    pub requester: Option<Name>,
}

/// A service's server side: route an [`Invocation`] to the matching typed handler
/// and return the encoded response. The `#[ndn_service]` macro emits this; a
/// carrier drives it from inbound requests.
#[async_trait::async_trait]
pub trait Dispatch: Send + Sync + 'static {
    /// Handle one invocation, returning the [`Frame`]-encoded response bytes.
    async fn dispatch(&self, invocation: Invocation) -> Result<Bytes, ServiceError>;
}

/// A pluggable backend: it names, transports, multiplexes, and secures service
/// invocations. The macro-generated client is generic over `C: Carrier`, so one
/// definition runs over any carrier.
#[async_trait::async_trait]
pub trait Carrier: Send + Sync {
    /// Invoke `op` of `svc` with `request` bytes; return one provider's response.
    /// For multi-provider backends this applies the carrier's default selection;
    /// see [`SelectCarrier`] for explicit strategies.
    async fn invoke(
        &self,
        svc: &ServiceId,
        op: &OpId,
        request: Bytes,
    ) -> Result<Response, ServiceError>;

    /// Mount `dispatch` as the server for `svc`. Returns once the service is
    /// serving (registry/engine-backed carriers dispatch asynchronously; loop-
    /// based carriers spawn their receive loop). Errors if mounting fails.
    async fn serve(&self, svc: &ServiceId, dispatch: Arc<dyn Dispatch>) -> Result<(), ServiceError>;
}

/// How a multi-provider carrier selects among responders. Mirrors NDNSF's
/// selection strategies; carriers that reach exactly one provider do not
/// implement [`SelectCarrier`] at all (compile-time depth-as-needed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Strategy {
    /// The first provider to respond.
    FirstResponding,
    /// One provider chosen at random among responders.
    Random,
    /// Every responding provider.
    All,
}

/// A [`Carrier`] refinement for backends that reach **many** providers: invoke and
/// collect responses per a [`Strategy`]. The generated client exposes the
/// `*_select` methods only where `C: SelectCarrier`.
#[async_trait::async_trait]
pub trait SelectCarrier: Carrier {
    /// Invoke `op` of `svc`, gathering responses per `strategy`.
    async fn invoke_select(
        &self,
        svc: &ServiceId,
        op: &OpId,
        request: Bytes,
        strategy: Strategy,
    ) -> Result<Vec<Response>, ServiceError>;
}

/// Length-delimited field framing used by `#[ndn_service]`-generated message
/// types: a request struct's fields are each encoded with their [`Frame`] and
/// concatenated length-prefixed. Decoding reads its known fields in order and
/// ignores any trailing bytes, so appending a field is forward-compatible (an
/// older peer reads the fields it knows). Reordering/removing fields is a
/// breaking change. (A tag-per-field TLV upgrade — full unordered skippability —
/// is a later codec revision; it does not change the generated API.)
pub mod framing {
    use super::ServiceError;
    use bytes::{BufMut, Bytes, BytesMut};

    /// Concatenate already-encoded fields, each length-prefixed.
    pub fn encode_fields(fields: &[Bytes]) -> Bytes {
        let mut buf = BytesMut::new();
        for field in fields {
            buf.put_u32_le(field.len() as u32);
            buf.put_slice(field);
        }
        buf.freeze()
    }

    /// Read the next length-delimited field from `bytes`, advancing `pos`.
    pub fn read_field<'a>(bytes: &'a [u8], pos: &mut usize) -> Result<&'a [u8], ServiceError> {
        let start = *pos;
        let header_end = start
            .checked_add(4)
            .filter(|&e| e <= bytes.len())
            .ok_or_else(|| ServiceError::Decode("truncated field length".into()))?;
        let len = u32::from_le_bytes(bytes[start..header_end].try_into().unwrap()) as usize;
        let field_end = header_end
            .checked_add(len)
            .filter(|&e| e <= bytes.len())
            .ok_or_else(|| ServiceError::Decode("truncated field body".into()))?;
        *pos = field_end;
        Ok(&bytes[header_end..field_end])
    }
}

/// `Frame` for the primitive argument/return types `#[ndn_service]` supports out
/// of the box. Custom types implement [`Frame`] themselves.
mod frame_impls {
    use super::{Frame, ServiceError};
    use bytes::Bytes;

    impl Frame for () {
        fn encode(&self) -> Bytes {
            Bytes::new()
        }
        fn decode(_bytes: &[u8]) -> Result<Self, ServiceError> {
            Ok(())
        }
    }

    impl Frame for String {
        fn encode(&self) -> Bytes {
            Bytes::copy_from_slice(self.as_bytes())
        }
        fn decode(bytes: &[u8]) -> Result<Self, ServiceError> {
            String::from_utf8(bytes.to_vec()).map_err(|e| ServiceError::Decode(e.to_string()))
        }
    }

    impl Frame for Vec<u8> {
        fn encode(&self) -> Bytes {
            Bytes::copy_from_slice(self)
        }
        fn decode(bytes: &[u8]) -> Result<Self, ServiceError> {
            Ok(bytes.to_vec())
        }
    }

    impl Frame for Bytes {
        fn encode(&self) -> Bytes {
            self.clone()
        }
        fn decode(bytes: &[u8]) -> Result<Self, ServiceError> {
            Ok(Bytes::copy_from_slice(bytes))
        }
    }

    impl Frame for bool {
        fn encode(&self) -> Bytes {
            Bytes::copy_from_slice(&[*self as u8])
        }
        fn decode(bytes: &[u8]) -> Result<Self, ServiceError> {
            match bytes.first() {
                Some(0) => Ok(false),
                Some(_) => Ok(true),
                None => Err(ServiceError::Decode("empty bool".into())),
            }
        }
    }

    macro_rules! frame_int {
        ($($t:ty),*) => {$(
            impl Frame for $t {
                fn encode(&self) -> Bytes {
                    Bytes::copy_from_slice(&self.to_le_bytes())
                }
                fn decode(bytes: &[u8]) -> Result<Self, ServiceError> {
                    let arr = bytes.try_into().map_err(|_| {
                        ServiceError::Decode(concat!("expected ", stringify!($t)).into())
                    })?;
                    Ok(<$t>::from_le_bytes(arr))
                }
            }
        )*};
    }
    frame_int!(u32, u64, i32, i64);
}
