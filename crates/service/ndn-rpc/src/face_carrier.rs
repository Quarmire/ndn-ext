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
use ndn_security::{InterestValidationOutcome, SignWith, Signer, ValidationResult, Validator};
use ndn_service_core::{
    Carrier, Dispatch, HintedCarrier, Invocation, OpId, Response, ServiceError, ServiceId,
};
use tokio::sync::Mutex;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(4);

/// A face-backed Tier-0 carrier. A client holds a [`Consumer`] (for `invoke`); a
/// provider holds a [`Producer`] (for `serve`); a node doing both holds both.
///
/// Like [`RpcCarrier`](crate::RpcCarrier), it can authenticate requests over the
/// canonical signed-Interest contract: [`with_signer`](Self::with_signer) signs each
/// outbound request; [`with_validator`](Self::with_validator) verifies inbound
/// requests and sets `Invocation::requester` to the verified `KeyLocator` identity. A
/// validator-equipped server **drops** (does not answer) an unsigned/invalid request,
/// so the client fails closed on timeout — the wire equivalent of `Unauthorized`.
///
/// **G2.3 — rejection manifests as a timeout, not a distinct error.** Because NDN drops
/// rather than NACKs an unauthorized Interest, the client cannot distinguish "rejected as
/// unauthorized" from "lost / no producer / slow" — both surface as
/// `ServiceError::Transport` after `fetch_timeout` (default 4 s). This is inherent to the
/// silent-drop model (unlike the in-process [`RpcCarrier`](crate::RpcCarrier), which can
/// return `Unauthorized` directly). Tune `fetch_timeout` to trade failure latency vs.
/// tolerance; an application that needs an explicit authorization verdict should use an
/// app-layer NACK convention rather than inferring it from the timeout.
pub struct FaceRpcCarrier {
    consumer: Option<Mutex<Consumer>>,
    producer: Mutex<Option<Producer>>,
    fetch_timeout: Duration,
    signer: Option<Arc<dyn Signer>>,
    validator: Option<Arc<Validator>>,
}

impl FaceRpcCarrier {
    /// A client carrier: `invoke` over `consumer`; `serve` errors (no producer).
    pub fn client(consumer: Consumer) -> Self {
        Self {
            consumer: Some(Mutex::new(consumer)),
            producer: Mutex::new(None),
            fetch_timeout: DEFAULT_TIMEOUT,
            signer: None,
            validator: None,
        }
    }

    /// A serving carrier: `serve` over `producer`; `invoke` errors (no consumer).
    pub fn server(producer: Producer) -> Self {
        Self {
            consumer: None,
            producer: Mutex::new(Some(producer)),
            fetch_timeout: DEFAULT_TIMEOUT,
            signer: None,
            validator: None,
        }
    }

    /// A carrier that both invokes and serves.
    pub fn new(consumer: Consumer, producer: Producer) -> Self {
        Self {
            consumer: Some(Mutex::new(consumer)),
            producer: Mutex::new(Some(producer)),
            fetch_timeout: DEFAULT_TIMEOUT,
            signer: None,
            validator: None,
        }
    }

    /// Set the per-invocation fetch timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.fetch_timeout = timeout;
        self
    }

    /// Sign each outbound request with `signer` (the requester identity the serve
    /// side authenticates). Mirrors [`RpcCarrier::with_signer`](crate::RpcCarrier::with_signer).
    pub fn with_signer(mut self, signer: Arc<dyn Signer>) -> Self {
        self.signer = Some(signer);
        self
    }

    /// Verify each inbound request with `validator` and authenticate its requester;
    /// a carrier with a validator drops unsigned/invalid requests (fail closed).
    pub fn with_validator(mut self, validator: Arc<Validator>) -> Self {
        self.validator = Some(validator);
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
    validator: Option<Arc<Validator>>,
    signer: Option<Arc<dyn Signer>>,
) {
    let comps = interest.name.components();
    let Some(op) = comps
        .get(service_len)
        .map(|c| OpId::new(String::from_utf8_lossy(c.value.as_ref()).into_owned()))
    else {
        return; // malformed — drop (the client fails closed on timeout)
    };
    // Authenticate the request when a validator is configured: it must verify, and
    // its KeyLocator name is the requester. An unsigned/invalid request is dropped
    // (no response → the client times out) — fail closed over the wire.
    let requester = match &validator {
        None => None,
        Some(v) => match v.validate_interest(&interest).await {
            InterestValidationOutcome::Valid => {
                match interest.sig_info().and_then(|si| si.key_locator_name()) {
                    Some(n) => Some((*n).clone()),
                    None => return, // signed but no KeyLocator — refuse
                }
            }
            InterestValidationOutcome::Invalid(_) | InterestValidationOutcome::Pending => return,
        },
    };
    let request = interest.app_parameters().cloned().unwrap_or_default();
    let invocation = Invocation {
        op,
        request,
        requester,
    };
    let Ok(reply) = dispatch.dispatch(invocation).await else {
        return; // dispatch error — no response (fail closed)
    };
    // Sign the response with this node's identity when configured; else a digest.
    let name = (*interest.name).clone();
    let wire = match &signer {
        Some(s) => match DataBuilder::new(name, reply.as_ref()).sign_with_sync(s.as_ref()) {
            Ok(w) => w,
            Err(_) => return, // can't sign the response — drop
        },
        None => DataBuilder::new(name, reply.as_ref()).sign_digest_sha256(),
    };
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
        let validator = self.validator.clone();
        let signer = self.signer.clone();
        producer
            .serve(move |interest, responder| {
                handle_request(
                    interest,
                    responder,
                    Arc::clone(&dispatch),
                    service_len,
                    validator.clone(),
                    signer.clone(),
                )
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
        // Sign the request when a signer is configured; else send it unsigned.
        let wire = match &self.signer {
            Some(s) => builder
                .sign_with_sync(s.as_ref())
                .map_err(|e| ServiceError::Unauthorized(format!("request sign failed: {e}")))?,
            None => builder.build(),
        };
        let data = consumer
            .lock()
            .await
            .fetch_wire(wire, self.fetch_timeout)
            .await
            .map_err(|e| ServiceError::Transport(e.to_string()))?;
        // G2.1: verify the response against trust when a validator is configured — over a
        // real face an unverified response could be a forgery from any responder on the
        // name. (No validator ⇒ caller opted out, as before.)
        if let Some(v) = &self.validator {
            match v.validate(&data).await {
                ValidationResult::Valid(_) => {}
                ValidationResult::Pending => {
                    return Err(ServiceError::Unauthorized(
                        "response signer certificate unavailable".into(),
                    ));
                }
                ValidationResult::Invalid(e) => {
                    return Err(ServiceError::Unauthorized(format!(
                        "response verification failed: {e}"
                    )));
                }
            }
        }
        Ok(Response {
            producer: svc.name().clone(),
            payload: data.content().cloned().unwrap_or_default(),
        })
    }
}
