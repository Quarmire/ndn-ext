//! `RpcCarrier` — the Tier-0 [`Carrier`] over this crate's `RpcRegistry`.
//!
//! Maps the transport-independent service seam (`ndn-service-core`) onto a single
//! signed Interest → Data exchange: an invocation of `op` on service `/svc/…`
//! becomes an Interest named `/svc/…/<op>` carrying the request as
//! `ApplicationParameters`; the response Data's content is the reply. A
//! `RpcRegistry` holds the mounted services; dispatch is longest-prefix match.
//!
//! Scope of this implementation: it is an **in-process loopback** over a real
//! `RpcRegistry` with real `Interest`/`Data` packets — `invoke` dispatches through
//! the same registry `serve` mounted into, proving the `Carrier`/`Dispatch`/`Frame`
//! seam end to end. A face-backed variant (express the Interest over a `Consumer`,
//! serve the registry from a `Producer` on an engine) is the *same* `Carrier` impl
//! wired to a transport — deferred; that engine plumbing is already witnessed in
//! `ndn-nacabe`. This carrier reaches exactly one provider, so it deliberately
//! does **not** implement `SelectCarrier`.
//!
//! The request Interest here is unsigned, so `Invocation::requester` is `None`. A
//! secure RpcCarrier signs the request and populates `requester` from the verified
//! signer (the secure-by-default posture of §12.5) — a later increment.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_packet::{Data, Interest};
use ndn_service_core::{
    Carrier, Dispatch, Invocation, OpId, Response, ServiceError, ServiceId,
};

use crate::{RpcError, RpcHandler, RpcRegistry};

/// A Tier-0 carrier: services mount into an `RpcRegistry`; invocations are a
/// single Interest → Data exchange dispatched by longest-prefix match.
pub struct RpcCarrier {
    registry: Arc<RpcRegistry>,
}

impl RpcCarrier {
    /// A carrier with a fresh, empty registry.
    pub fn new() -> Self {
        Self {
            registry: Arc::new(RpcRegistry::new()),
        }
    }

    /// A carrier over an existing registry (e.g. one an engine also dispatches to).
    pub fn with_registry(registry: Arc<RpcRegistry>) -> Self {
        Self { registry }
    }

    /// The underlying registry.
    pub fn registry(&self) -> &Arc<RpcRegistry> {
        &self.registry
    }
}

impl Default for RpcCarrier {
    fn default() -> Self {
        Self::new()
    }
}

/// The `RpcHandler` that adapts an inbound Interest to a `Dispatch` call: it reads
/// the op from the name component after the service prefix and the request from
/// `ApplicationParameters`, then wraps the dispatcher's reply in a response Data.
struct CarrierHandler {
    /// Component count of the service prefix; the op is the next component.
    service_len: usize,
    dispatch: Arc<dyn Dispatch>,
}

impl RpcHandler for CarrierHandler {
    async fn handle(&self, interest: &Interest) -> Result<Data, RpcError> {
        let comps = interest.name.components();
        let op = comps
            .get(self.service_len)
            .map(|c| OpId::new(String::from_utf8_lossy(c.value.as_ref()).into_owned()))
            .ok_or_else(|| RpcError::BadRequest("interest carries no operation component".into()))?;
        let request = interest.app_parameters().cloned().unwrap_or_default();
        let invocation = Invocation {
            op,
            request,
            requester: None, // unsigned loopback; a secure carrier fills this in
        };
        let reply = self.dispatch.dispatch(invocation).await.map_err(|e| match e {
            ServiceError::NotFound => RpcError::NotFound,
            ServiceError::Decode(m) => RpcError::BadRequest(m),
            other => RpcError::HandlerFailed(other.to_string()),
        })?;
        let wire = DataBuilder::new((*interest.name).clone(), reply.as_ref()).sign_digest_sha256();
        Data::decode(wire).map_err(|e| RpcError::HandlerFailed(format!("response encode failed: {e}")))
    }
}

#[async_trait]
impl Carrier for RpcCarrier {
    async fn invoke(
        &self,
        svc: &ServiceId,
        op: &OpId,
        request: Bytes,
    ) -> Result<Response, ServiceError> {
        let name = svc.name().clone().append(op.as_str());
        let wire = InterestBuilder::new(name)
            .app_parameters(request.to_vec())
            .build();
        let interest =
            Interest::decode(wire).map_err(|e| ServiceError::Transport(e.to_string()))?;
        match self.registry.dispatch(&interest).await {
            Some(Ok(data)) => Ok(Response {
                producer: svc.name().clone(),
                payload: data.content().cloned().unwrap_or_default(),
            }),
            Some(Err(RpcError::NotFound)) | None => Err(ServiceError::NotFound),
            Some(Err(RpcError::BadRequest(e))) => Err(ServiceError::Decode(e)),
            Some(Err(RpcError::HandlerFailed(e))) => Err(ServiceError::Handler(e)),
        }
    }

    async fn serve(&self, svc: &ServiceId, dispatch: Arc<dyn Dispatch>) -> Result<(), ServiceError> {
        let handler = CarrierHandler {
            service_len: svc.name().len(),
            dispatch,
        };
        self.registry.register(svc.name(), handler);
        Ok(())
    }
}
