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
//! ## Authenticated requests (the secure carrier)
//!
//! By default the request Interest is unsigned and `Invocation::requester` is `None`
//! (in-process loopback). Attach a [`with_signer`](RpcCarrier::with_signer) to *sign*
//! each request, and a [`with_validator`](RpcCarrier::with_validator) to *verify* it
//! on the serve side and set `requester` to the **verified** `KeyLocator` name. This
//! is the canonical NDN signed-Interest contract — `SignWith::sign_with_sync` +
//! `Validator::validate_interest` + `KeyLocator`-as-identity — the same shape the
//! framework command path (`ndn-service`) and NFD-style management commands use; it
//! is *not* ABE/NAC-specific. A validator-equipped carrier **fails closed**: an
//! unsigned or invalid request is rejected with `ServiceError::Unauthorized`.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_packet::{Data, Interest, Name};
use ndn_security::{
    InterestValidationOutcome, ReplayCheck, ReplayGuard, SignWith, Signer, ValidationResult,
    Validator,
};
use ndn_service_core::{
    Carrier, Dispatch, HintedCarrier, Invocation, Metadata, OpId, Response, ServiceError,
    ServiceId, framing,
};

use crate::{RpcError, RpcHandler, RpcRegistry};

/// A Tier-0 carrier: services mount into an `RpcRegistry`; invocations are a
/// single Interest → Data exchange dispatched by longest-prefix match.
pub struct RpcCarrier {
    registry: Arc<RpcRegistry>,
    /// When set, sign each outbound request Interest (the requester's identity).
    signer: Option<Arc<dyn Signer>>,
    /// When set, verify each inbound request and authenticate its requester;
    /// unsigned/invalid requests are rejected (fail closed). The same validator
    /// verifies the **response** on the invoke side (G2.1).
    validator: Option<Arc<Validator>>,
    /// Anti-replay for inbound requests (G2.2). Auto-enabled in secure mode
    /// ([`with_validator`](Self::with_validator)); dedups on the signed-Interest
    /// nonce (clock-free), so a captured signed request can't be re-dispatched.
    replay: Option<Arc<ReplayGuard>>,
}

impl RpcCarrier {
    /// A carrier with a fresh, empty registry.
    pub fn new() -> Self {
        Self {
            registry: Arc::new(RpcRegistry::new()),
            signer: None,
            validator: None,
            replay: None,
        }
    }

    /// A carrier over an existing registry (e.g. one an engine also dispatches to).
    pub fn with_registry(registry: Arc<RpcRegistry>) -> Self {
        Self {
            registry,
            signer: None,
            validator: None,
            replay: None,
        }
    }

    /// Sign each outbound request with `signer`; the response side reads the verified
    /// signer name as the requester. (Mirrors `MgmtClient::with_signer`.)
    pub fn with_signer(mut self, signer: Arc<dyn Signer>) -> Self {
        self.signer = Some(signer);
        self
    }

    /// Verify each inbound request with `validator` and authenticate its requester.
    /// A carrier with a validator **fails closed** on unsigned/invalid requests, verifies
    /// the response on the invoke side (G2.1), and enables anti-replay on inbound requests
    /// (G2.2 — dedups on the signed-Interest nonce, clock-free).
    pub fn with_validator(mut self, validator: Arc<Validator>) -> Self {
        self.validator = Some(validator);
        // Secure mode ⇒ anti-replay on requests. monotonic=false: dedup on the random
        // nonce only, never a wall clock (no trusted-time dependency).
        self.replay
            .get_or_insert_with(|| Arc::new(ReplayGuard::new(256, false)));
        self
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
    /// When set, verify the request and authenticate its requester (fail closed).
    validator: Option<Arc<Validator>>,
    /// When set, reject a replayed request (dedup on the signed-Interest nonce).
    replay: Option<Arc<ReplayGuard>>,
    /// When set, sign the response Data with this node's identity (else digest).
    signer: Option<Arc<dyn Signer>>,
}

impl CarrierHandler {
    /// Authenticate the request: with a validator, the request must verify and its
    /// `KeyLocator` name becomes the requester; without one, the requester is `None`
    /// (the unsigned loopback). Returns the requester identity, or rejects.
    async fn authenticate(&self, interest: &Interest) -> Result<Option<Name>, RpcError> {
        let Some(validator) = &self.validator else {
            return Ok(None); // no validator ⇒ unauthenticated loopback
        };
        match validator.validate_interest(interest).await {
            InterestValidationOutcome::Valid => {}
            InterestValidationOutcome::Pending => {
                return Err(RpcError::Unauthorized(
                    "signer certificate not available".into(),
                ));
            }
            InterestValidationOutcome::Invalid(e) => {
                return Err(RpcError::Unauthorized(e.to_string()));
            }
        }
        // Anti-replay (G2.2): a captured signed request must not be re-dispatched. Dedup on
        // the signed-Interest nonce; an Interest with no anti-replay field can't be deduped
        // (the requester should include a SignatureNonce) but still must verify above.
        if let Some(rg) = &self.replay
            && let Some(si) = interest.sig_info()
            && matches!(rg.check(si), ReplayCheck::Replay)
        {
            return Err(RpcError::Unauthorized("replayed request rejected".into()));
        }
        // The verified KeyLocator name *is* the authenticated requester (NDN
        // signed-Interest identity), not a name the caller merely claims.
        let requester = interest
            .sig_info()
            .and_then(|si| si.key_locator_name())
            .map(|n| (*n).clone())
            .ok_or_else(|| RpcError::Unauthorized("signed request carries no KeyLocator".into()))?;
        Ok(Some(requester))
    }
}

impl RpcHandler for CarrierHandler {
    async fn handle(&self, interest: &Interest) -> Result<Data, RpcError> {
        let comps = interest.name.components();
        let op = comps
            .get(self.service_len)
            .map(|c| OpId::new(String::from_utf8_lossy(c.value.as_ref()).into_owned()))
            .ok_or_else(|| {
                RpcError::BadRequest("interest carries no operation component".into())
            })?;
        let requester = self.authenticate(interest).await?;
        // The request travels as an opaque metadata+payload envelope: recover the
        // carrier-uniform slot (a trace context, etc.) and the inner request.
        let params = interest.app_parameters().cloned().unwrap_or_default();
        let (metadata, request) =
            framing::decode_envelope(&params).map_err(|e| RpcError::BadRequest(e.to_string()))?;
        let invocation = Invocation {
            op,
            request,
            requester,
            metadata: metadata.clone(),
        };
        let reply = self
            .dispatch
            .dispatch(invocation)
            .await
            .map_err(|e| match e {
                ServiceError::NotFound => RpcError::NotFound,
                ServiceError::Decode(m) => RpcError::BadRequest(m),
                ServiceError::Unauthorized(m) => RpcError::Unauthorized(m),
                other => RpcError::HandlerFailed(other.to_string()),
            })?;
        // Reflect the request's slot onto the response (context propagation) and
        // frame it back beside the reply payload — the same opaque envelope.
        let body = framing::encode_envelope(&metadata, &reply);
        // Sign the response with this node's identity when configured; else a bare
        // digest (loopback integrity), as before.
        let name = (*interest.name).clone();
        let wire = match &self.signer {
            Some(signer) => DataBuilder::new(name, body.as_ref())
                .sign_with_sync(signer.as_ref())
                .map_err(|e| RpcError::HandlerFailed(format!("response sign failed: {e}")))?,
            None => DataBuilder::new(name, body.as_ref()).sign_digest_sha256(),
        };
        Data::decode(wire)
            .map_err(|e| RpcError::HandlerFailed(format!("response encode failed: {e}")))
    }
}

#[async_trait]
impl Carrier for RpcCarrier {
    async fn invoke_meta(
        &self,
        svc: &ServiceId,
        op: &OpId,
        request: Bytes,
        metadata: Metadata,
    ) -> Result<Response, ServiceError> {
        self.invoke_hinted_meta(svc, op, request, None, metadata)
            .await
    }

    async fn serve(
        &self,
        svc: &ServiceId,
        dispatch: Arc<dyn Dispatch>,
    ) -> Result<(), ServiceError> {
        let handler = CarrierHandler {
            service_len: svc.name().len(),
            dispatch,
            validator: self.validator.clone(),
            replay: self.replay.clone(),
            signer: self.signer.clone(),
        };
        self.registry.register(svc.name(), handler);
        Ok(())
    }
}

#[async_trait]
impl HintedCarrier for RpcCarrier {
    async fn invoke_hinted_meta(
        &self,
        svc: &ServiceId,
        op: &OpId,
        request: Bytes,
        hint: Option<&Name>,
        metadata: Metadata,
    ) -> Result<Response, ServiceError> {
        let name = svc.name().clone().append(op.as_str());
        // Carry the opaque metadata slot beside the request in one envelope.
        let body = framing::encode_envelope(&metadata, &request);
        let mut builder = InterestBuilder::new(name).app_parameters(body.to_vec());
        if let Some(h) = hint {
            // Steer the forwarder toward the selected provider while the content
            // name stays shared across providers (the data-centric convention).
            builder = builder.forwarding_hint(vec![h.clone()]);
        }
        // Sign the request when a signer is configured (so the serve side can
        // authenticate the requester); else send it unsigned (loopback).
        let wire = match &self.signer {
            Some(signer) => builder
                .sign_with_sync(signer.as_ref())
                .map_err(|e| ServiceError::Unauthorized(format!("request sign failed: {e}")))?,
            None => builder.build(),
        };
        let interest =
            Interest::decode(wire).map_err(|e| ServiceError::Transport(e.to_string()))?;
        match self.registry.dispatch(&interest).await {
            Some(Ok(data)) => {
                // G2.1: verify the response against trust when secure — an unverified
                // response could be a forgery/substitution. (Skipped when no validator is
                // configured: the in-process loopback is digest-only by design.)
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
                // Recover the reflected metadata slot and the reply payload.
                let content = data.content().cloned().unwrap_or_default();
                let (metadata, payload) = framing::decode_envelope(&content)?;
                Ok(Response {
                    producer: svc.name().clone(),
                    payload,
                    metadata,
                })
            }
            Some(Err(RpcError::NotFound)) | None => Err(ServiceError::NotFound),
            Some(Err(RpcError::BadRequest(e))) => Err(ServiceError::Decode(e)),
            Some(Err(RpcError::Unauthorized(e))) => Err(ServiceError::Unauthorized(e)),
            Some(Err(RpcError::HandlerFailed(e))) => Err(ServiceError::Handler(e)),
        }
    }
}
