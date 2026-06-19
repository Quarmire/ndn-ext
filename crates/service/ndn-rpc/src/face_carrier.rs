//! `FaceRpcCarrier` — the **face-backed** Tier-0 [`Carrier`] (feature `engine`).
//!
//! The same `Carrier` contract as the in-process [`RpcCarrier`](crate::RpcCarrier),
//! but its I/O goes over a real engine/forwarder instead of an in-memory registry:
//! `invoke` expresses the Interest over an `ndn-app` [`Consumer`] (the forwarder
//! routes it to wherever the provider is, and the response Data flows back through
//! the PIT, cached in the Content Store); `serve` runs an `ndn-app` [`Producer`]'s
//! serve loop, dispatching inbound Interests to the [`Dispatch`]. So provider and
//! consumer live in **separate processes/machines**, reachable over the network —
//! turning the proven seam into real distributed services. The `#[ndn_service]`
//! client, `DiscoveryCarrier`, and the PyO3 binding run over this unchanged.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use ndn_app::{Consumer, Producer};
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_packet::Name;
use ndn_service_core::{
    Carrier, Dispatch, HintedCarrier, Invocation, OpId, Response, ServiceError, ServiceId,
};
use tokio::sync::Mutex;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(4);

/// A face-backed Tier-0 carrier. A client holds a [`Consumer`] (for `invoke`); a
/// provider holds a [`Producer`] (for `serve`); a node doing both holds both.
pub struct FaceRpcCarrier {
    consumer: Option<Mutex<Consumer>>,
    producer: Mutex<Option<Producer>>,
    fetch_timeout: Duration,
}

impl FaceRpcCarrier {
    /// A client carrier: `invoke` over `consumer`; `serve` errors (no producer).
    pub fn client(consumer: Consumer) -> Self {
        Self {
            consumer: Some(Mutex::new(consumer)),
            producer: Mutex::new(None),
            fetch_timeout: DEFAULT_TIMEOUT,
        }
    }

    /// A serving carrier: `serve` over `producer`; `invoke` errors (no consumer).
    pub fn server(producer: Producer) -> Self {
        Self {
            consumer: None,
            producer: Mutex::new(Some(producer)),
            fetch_timeout: DEFAULT_TIMEOUT,
        }
    }

    /// A carrier that both invokes and serves.
    pub fn new(consumer: Consumer, producer: Producer) -> Self {
        Self {
            consumer: Some(Mutex::new(consumer)),
            producer: Mutex::new(Some(producer)),
            fetch_timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Set the per-invocation fetch timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.fetch_timeout = timeout;
        self
    }
}

/// Build the response Data for an inbound service Interest by routing it to
/// `dispatch`. `service_len` is the component count of the service prefix (the op
/// is the next component); the response Data is named after the Interest.
async fn handle_request(
    interest: ndn_packet::Interest,
    responder: ndn_app::Responder,
    dispatch: Arc<dyn Dispatch>,
    service_len: usize,
) {
    let comps = interest.name.components();
    let Some(op) = comps
        .get(service_len)
        .map(|c| OpId::new(String::from_utf8_lossy(c.value.as_ref()).into_owned()))
    else {
        return; // malformed — drop (the client fails closed on timeout)
    };
    let request = interest.app_parameters().cloned().unwrap_or_default();
    let invocation = Invocation {
        op,
        request,
        requester: None, // a signed-Interest variant would fill this from the signer
    };
    let Ok(reply) = dispatch.dispatch(invocation).await else {
        return; // dispatch error — no response (fail closed)
    };
    let wire = DataBuilder::new((*interest.name).clone(), reply.as_ref()).sign_digest_sha256();
    let _ = responder.respond_bytes(wire).await;
}

#[async_trait]
impl Carrier for FaceRpcCarrier {
    async fn invoke(
        &self,
        svc: &ServiceId,
        op: &OpId,
        request: Bytes,
    ) -> Result<Response, ServiceError> {
        self.invoke_hinted(svc, op, request, None).await
    }

    async fn serve(&self, svc: &ServiceId, dispatch: Arc<dyn Dispatch>) -> Result<(), ServiceError> {
        let producer = self
            .producer
            .lock()
            .await
            .take()
            .ok_or_else(|| ServiceError::Transport("carrier has no producer to serve with".into()))?;
        let service_len = svc.name().len();
        producer
            .serve(move |interest, responder| {
                handle_request(interest, responder, Arc::clone(&dispatch), service_len)
            })
            .await
            .map_err(|e| ServiceError::Transport(e.to_string()))
    }
}

#[async_trait]
impl HintedCarrier for FaceRpcCarrier {
    async fn invoke_hinted(
        &self,
        svc: &ServiceId,
        op: &OpId,
        request: Bytes,
        hint: Option<&Name>,
    ) -> Result<Response, ServiceError> {
        let consumer = self
            .consumer
            .as_ref()
            .ok_or_else(|| ServiceError::Transport("carrier has no consumer to invoke with".into()))?;
        let name = svc.name().clone().append(op.as_str());
        let mut builder = InterestBuilder::new(name).app_parameters(request.to_vec());
        if let Some(h) = hint {
            builder = builder.forwarding_hint(vec![h.clone()]);
        }
        let wire = builder.build();
        let data = consumer
            .lock()
            .await
            .fetch_wire(wire, self.fetch_timeout)
            .await
            .map_err(|e| ServiceError::Transport(e.to_string()))?;
        Ok(Response {
            producer: svc.name().clone(),
            payload: data.content().cloned().unwrap_or_default(),
        })
    }
}
