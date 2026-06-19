//! Tier-0 NDN RPC — the generic invocation core.
//!
//! A service call to a *known* provider is exactly what NDN already does well: a
//! (signed) Interest carries the request, a (signed) Data carries the response —
//! one round trip, no sync, no discovery. This crate is the minimal primitive
//! for that: an [`RpcHandler`] (`&Interest -> Data`) registered under a name in
//! an [`RpcRegistry`], dispatched by longest-prefix match. The result Data is
//! injected back into the forwarder pipeline, where it caches in the Content
//! Store and aggregates in the PIT like any other Data.
//!
//! This is the extraction target for `ndn-compute`: `ndn-compute` is the
//! *specialization* where the handler is a deterministic pure function (with its
//! own typed-argument codec and determinism rules). The generic
//! handler/registry/dispatch mechanism lives here so the v2 service tiers
//! (`ndn-rpc` Tier-0, discovery, collaboration) and in-network compute share one
//! RPC stack rather than each re-deriving it. See
//! `docs/specs/service-layer.md` (§3.1, D1).
//!
//! Authorization (when required) is the capability presented and proven by the
//! signature on the request Interest (`ndn-security::capability`), verified
//! offline by the handler — never on the dispatch hot path here.

use std::sync::Arc;

use ndn_packet::{Data, Interest, Name};
use ndn_store::NameTrie;

mod carrier;
pub use carrier::RpcCarrier;

/// A handler invoked for Interests whose name longest-prefix-matches a
/// registered name. The returned Data is injected back into the pipeline and
/// cached like any other Data.
pub trait RpcHandler: Send + Sync + 'static {
    /// Produce the response Data for `interest`, or an [`RpcError`].
    fn handle(
        &self,
        interest: &Interest,
    ) -> impl std::future::Future<Output = Result<Data, RpcError>> + Send;
}

/// Why an RPC dispatch did not produce a response.
#[derive(Debug)]
pub enum RpcError {
    /// No handler longest-prefix-matched the Interest name.
    NotFound,
    /// The handler ran but failed.
    HandlerFailed(String),
    /// The request (name components / `ApplicationParameters`) could not be
    /// decoded into the handler's expected arguments.
    BadRequest(String),
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpcError::NotFound => write!(f, "no RPC handler for this name"),
            RpcError::HandlerFailed(e) => write!(f, "RPC handler failed: {e}"),
            RpcError::BadRequest(e) => write!(f, "bad RPC request: {e}"),
        }
    }
}

impl std::error::Error for RpcError {}

/// A longest-prefix-match registry of [`RpcHandler`]s keyed by name prefix.
pub struct RpcRegistry {
    handlers: NameTrie<Arc<dyn ErasedHandler>>,
}

trait ErasedHandler: Send + Sync + 'static {
    fn handle_erased<'a>(
        &'a self,
        interest: &'a Interest,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Data, RpcError>> + Send + 'a>>;
}

impl<H: RpcHandler> ErasedHandler for H {
    fn handle_erased<'a>(
        &'a self,
        interest: &'a Interest,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Data, RpcError>> + Send + 'a>>
    {
        Box::pin(self.handle(interest))
    }
}

impl RpcRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self {
            handlers: NameTrie::new(),
        }
    }

    /// Register `handler` for the name `prefix` (longest-prefix match at dispatch).
    pub fn register<H: RpcHandler>(&self, prefix: &Name, handler: H) {
        self.handlers.insert(prefix, Arc::new(handler));
    }

    /// Dispatch `interest` to the most specific registered handler, if any.
    /// `None` means no prefix matched; `Some(Err(..))` means a handler ran and
    /// failed.
    pub async fn dispatch(&self, interest: &Interest) -> Option<Result<Data, RpcError>> {
        let handler = self.handlers.lpm(&interest.name)?;
        Some(handler.handle_erased(interest).await)
    }
}

impl Default for RpcRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use ndn_packet::NameComponent;
    use ndn_tlv::TlvWriter;

    fn minimal_data() -> Data {
        let nc = {
            let mut w = TlvWriter::new();
            w.write_tlv(0x08, b"test");
            w.finish()
        };
        let name = {
            let mut w = TlvWriter::new();
            w.write_tlv(0x07, &nc);
            w.finish()
        };
        let pkt = {
            let mut w = TlvWriter::new();
            w.write_tlv(0x06, &name);
            w.finish()
        };
        Data::decode(pkt).unwrap()
    }

    struct EchoHandler;
    impl RpcHandler for EchoHandler {
        async fn handle(&self, _interest: &Interest) -> Result<Data, RpcError> {
            Ok(minimal_data())
        }
    }

    struct FailHandler;
    impl RpcHandler for FailHandler {
        async fn handle(&self, _interest: &Interest) -> Result<Data, RpcError> {
            Err(RpcError::HandlerFailed("intentional".into()))
        }
    }

    fn interest(comp: &'static str) -> Interest {
        Interest::new(Name::from_components([NameComponent::generic(
            Bytes::from_static(comp.as_bytes()),
        )]))
    }

    #[tokio::test]
    async fn dispatch_to_registered_handler() {
        let reg = RpcRegistry::new();
        reg.register(
            &Name::from_components([NameComponent::generic(Bytes::from_static(b"svc"))]),
            EchoHandler,
        );
        let r = reg.dispatch(&interest("svc")).await;
        assert!(matches!(r, Some(Ok(_))));
    }

    #[tokio::test]
    async fn dispatch_no_match_returns_none() {
        let reg = RpcRegistry::new();
        assert!(reg.dispatch(&interest("unknown")).await.is_none());
    }

    #[tokio::test]
    async fn dispatch_handler_error_propagates() {
        let reg = RpcRegistry::new();
        reg.register(
            &Name::from_components([NameComponent::generic(Bytes::from_static(b"fail"))]),
            FailHandler,
        );
        let r = reg.dispatch(&interest("fail")).await.unwrap();
        assert!(matches!(r, Err(RpcError::HandlerFailed(_))));
    }

    #[test]
    fn error_display_non_empty() {
        assert!(!RpcError::NotFound.to_string().is_empty());
        assert!(!RpcError::HandlerFailed("x".into()).to_string().is_empty());
        assert!(!RpcError::BadRequest("y".into()).to_string().is_empty());
    }
}
