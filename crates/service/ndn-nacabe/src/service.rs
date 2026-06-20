//! NDN service surface (feature `service`) — the attribute authority serving
//! `PUBPARAMS`/`DKEY` over an `ndn-app` Producer, and the consumer-side
//! [`ParamFetcher`]. This is the over-NDN shell over the sans-IO issuance core
//! in [`crate::authority`]; it carries the O4 protocol-level invariants:
//!
//! * **NSF-A1** — the `DKEY` request is validated before any key is issued, and
//!   the consumer validates the authority's response before using it.
//! * **NSF-A2** — the key is issued to the **validated signer's** identity (from
//!   the request's `KeyLocator`), never to a name the requester merely claims,
//!   so a requester can only obtain its *own* key.
//! * **NSF-F5** — every negative path fails closed (no response Data).

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_app::{AppError, Consumer, Producer};
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_packet::{Name, NameComponent};
use ndn_security::validator::InterestValidationOutcome;
use ndn_security::{SignWith, Signer, Validator};
use tracing::warn;

use crate::authority::CpAuthority;
use crate::names::{self, DKEY};

const DKEY_FETCH_TIMEOUT: Duration = Duration::from_secs(4);

/// A consumer validation-failure hook (NSF-F1): invoked exactly once per failed
/// authority response, with the failed Data name and a human-readable reason.
pub type ValidationFailureHook = Arc<dyn Fn(&Name, &str) + Send + Sync>;

/// A live, fail-closed **issuance gate** for the network `DKEY` path: given the
/// already-authenticated requester identity and its advertised X25519 recipient
/// key, produce the sealed decryption key — or `None` to refuse.
///
/// This is the seam that lets a caller gate issuance on a **live** policy (the v2
/// `issue_decryption_key` over a `PolicyAuthority`), so a *revoked* requester is
/// refused even though it still has a stale entry in the authority's own grant
/// table (red-team SEC-06). The NDNSF-compat caller passes a closure that defers to
/// the authority's grant table, e.g. `move |id, recip| authority.issue_dkey(id, recip).ok()`.
pub type IssueFn = Arc<dyn Fn(&Name, &[u8]) -> Option<Bytes> + Send + Sync>;

/// Derive the signing identity from a key name `/<id>/KEY/<keyid>` → `/<id>`.
fn identity_of(key_name: &Name) -> Option<Name> {
    let key_comp = NameComponent::generic(Bytes::from_static(b"KEY"));
    let comps = key_name.components();
    let idx = comps.iter().position(|c| *c == key_comp)?;
    Some(Name::from_components(comps[..idx].iter().cloned()))
}

/// Run the CP-ABE attribute authority's serve loop on `producer` (bound to the
/// authority prefix). Serves `PUBPARAMS` and answers validated `DKEY` requests.
/// `aa_signer` signs the response Data; `request_validator` authenticates `DKEY`
/// requests.
pub async fn serve_cp(
    producer: Producer,
    aa_prefix: Name,
    authority: Arc<CpAuthority>,
    aa_signer: Arc<dyn Signer>,
    request_validator: Arc<Validator>,
    issue: IssueFn,
) -> Result<(), AppError> {
    let pubparams = names::pubparams_name(&aa_prefix);
    let dkey_prefix = aa_prefix.append(DKEY);
    producer
        .serve(move |interest, responder| {
            let authority = authority.clone();
            let aa_signer = aa_signer.clone();
            let request_validator = request_validator.clone();
            let issue = issue.clone();
            let pubparams = pubparams.clone();
            let dkey_prefix = dkey_prefix.clone();
            async move {
                let name = (*interest.name).clone();

                // PUBPARAMS — an unsigned discovery fetch; the *Data* is the
                // authenticated object (NSF-A4), signed by the authority.
                if name == pubparams {
                    if let Ok(wire) = DataBuilder::new(name, authority.public_params().as_ref())
                        .sign_with_sync(&*aa_signer)
                    {
                        responder.respond_bytes(wire).await.ok();
                    }
                    return;
                }

                if !name.has_prefix(&dkey_prefix) {
                    return;
                }

                // NSF-A1: the DKEY request must be validly signed.
                if !matches!(
                    request_validator.validate_interest(&interest).await,
                    InterestValidationOutcome::Valid
                ) {
                    return; // fail closed
                }
                // NSF-A2: issue to the validated signer's identity, not a claimed one.
                let Some(signer_key) = interest.sig_info().and_then(|si| si.key_locator_name())
                else {
                    return;
                };
                let Some(identity) = identity_of(&signer_key) else {
                    return;
                };
                // The requester advertises its ephemeral X25519 key in the params.
                let Some(recipient_public) = interest.app_parameters() else {
                    return;
                };
                // The issuance gate fails closed; for the v2 path it consults the
                // live policy, so a revoked requester is refused here even if it
                // still has a stale entry in the authority's grant table (SEC-06).
                if let Some(sealed) = issue(&identity, recipient_public)
                    && let Ok(wire) =
                        DataBuilder::new(name, sealed.as_ref()).sign_with_sync(&*aa_signer)
                {
                    responder.respond_bytes(wire).await.ok();
                }
            }
        })
        .await
}

/// Run the KP-ABE attribute authority's serve loop — identical to [`serve_cp`]
/// but issuing policy keys (the NDNSF `ServiceController` model).
pub async fn serve_kp(
    producer: Producer,
    aa_prefix: Name,
    authority: Arc<crate::authority::KpAuthority>,
    aa_signer: Arc<dyn Signer>,
    request_validator: Arc<Validator>,
    issue: IssueFn,
) -> Result<(), AppError> {
    let pubparams = names::pubparams_name(&aa_prefix);
    let dkey_prefix = aa_prefix.append(DKEY);
    producer
        .serve(move |interest, responder| {
            let authority = authority.clone();
            let aa_signer = aa_signer.clone();
            let request_validator = request_validator.clone();
            let issue = issue.clone();
            let pubparams = pubparams.clone();
            let dkey_prefix = dkey_prefix.clone();
            async move {
                let name = (*interest.name).clone();
                if name == pubparams {
                    if let Ok(wire) = DataBuilder::new(name, authority.public_params().as_ref())
                        .sign_with_sync(&*aa_signer)
                    {
                        responder.respond_bytes(wire).await.ok();
                    }
                    return;
                }
                if !name.has_prefix(&dkey_prefix) {
                    return;
                }
                if !matches!(
                    request_validator.validate_interest(&interest).await,
                    InterestValidationOutcome::Valid
                ) {
                    return;
                }
                let Some(signer_key) = interest.sig_info().and_then(|si| si.key_locator_name())
                else {
                    return;
                };
                let Some(identity) = identity_of(&signer_key) else {
                    return;
                };
                let Some(recipient_public) = interest.app_parameters() else {
                    return;
                };
                if let Some(sealed) = issue(&identity, recipient_public)
                    && let Ok(wire) =
                        DataBuilder::new(name, sealed.as_ref()).sign_with_sync(&*aa_signer)
                {
                    responder.respond_bytes(wire).await.ok();
                }
            }
        })
        .await
}

/// Consumer-side fetcher for an attribute authority's public parameters and the
/// requester's sealed decryption key. Verifies the authority's responses
/// (NSF-A1, consumer side) against `aa_validator`.
pub struct ParamFetcher {
    consumer: Consumer,
    aa_prefix: Name,
    aa_validator: Arc<Validator>,
    on_failure: Option<ValidationFailureHook>,
}

impl ParamFetcher {
    /// Construct over an existing forwarder connection.
    pub fn new(consumer: Consumer, aa_prefix: Name, aa_validator: Arc<Validator>) -> Self {
        Self {
            consumer,
            aa_prefix,
            aa_validator,
            on_failure: None,
        }
    }

    /// Register a validation-failure callback (NSF-F1). It fires exactly once for
    /// each authority response that fails validation, receiving the Data name and
    /// the failure reason. Independent of the always-on `tracing` log (NSF-F2).
    pub fn with_failure_callback(mut self, on_failure: ValidationFailureHook) -> Self {
        self.on_failure = Some(on_failure);
        self
    }

    /// Fetch and verify the authority's public parameters.
    pub async fn fetch_public_params(&mut self) -> Result<Bytes, AppError> {
        let data = self
            .consumer
            .fetch(names::pubparams_name(&self.aa_prefix))
            .await?;
        self.verified_content(data).await
    }

    /// Express a signed `DKEY` request advertising `recipient_public` (the
    /// ephemeral X25519 key the issued key will be sealed to), and return the
    /// verified sealed-key bytes. Sign with the requester's `signer` — the
    /// authority issues to that validated identity (NSF-A2).
    pub async fn obtain_decryption_key(
        &mut self,
        signer: &dyn Signer,
        recipient_public: &[u8],
    ) -> Result<Bytes, AppError> {
        let dkey_name = names::dkey_request_name(&self.aa_prefix, signer.key_name());
        let wire = InterestBuilder::new(dkey_name)
            .must_be_fresh()
            .app_parameters(recipient_public.to_vec())
            .sign_sync(signer.sig_type(), Some(signer.key_name()), |region| {
                signer.sign_sync(region).expect("CPU-only signer")
            });
        let data = self.consumer.fetch_wire(wire, DKEY_FETCH_TIMEOUT).await?;
        self.verified_content(data).await
    }

    async fn verified_content(&self, data: ndn_packet::Data) -> Result<Bytes, AppError> {
        use ndn_security::validator::ValidationResult;
        match self.aa_validator.validate(&data).await {
            ValidationResult::Valid(safe) => Ok(safe.data().content().cloned().unwrap_or_default()),
            other => {
                // NSF-F2: log the failed name and reason; NSF-F1: invoke the
                // failure callback exactly once. Then fail closed.
                let name: Name = (*data.name).clone();
                let reason = match other {
                    ValidationResult::Invalid(err) => err.to_string(),
                    ValidationResult::Pending => {
                        "certificate chain unresolved (validation pending)".to_string()
                    }
                    ValidationResult::Valid(_) => unreachable!(),
                };
                warn!(name = %name, reason = %reason, "attribute-authority response failed validation");
                if let Some(cb) = &self.on_failure {
                    cb(&name, &reason);
                }
                Err(AppError::Unverified(format!(
                    "attribute-authority response failed validation: {reason}"
                )))
            }
        }
    }
}
