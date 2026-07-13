//! Per-message trust validation (the trust half of NSF-A3, feature `driver`).
//!
//! NDNSF validates each four-phase message against the configured trust validator
//! before its payload affects runtime state. This module is that mechanism: a
//! message is published as a **signed Data** ([`sign_message`]); a receiver
//! [`verify_message`]s it before acting — the signature must validate against the
//! trust anchors **and** the signer identity must be under the message's expected
//! sender (so a node cannot publish a `/<provider>/NDNSF/ACK/…` it did not sign).
//! Either failure rejects the message (fail closed) — its payload never affects
//! state. Reuses `ndn_security`'s real `Signer`/`Validator`, not new crypto.
//!
//! [`TrustCtx`] bundles a node's outbound signer and inbound validator and is
//! threaded through the [`crate::driver`] flow, so every REQUEST/ACK/SELECTION/
//! RESPONSE is sealed on publish and verified on receipt. An empty `TrustCtx`
//! (the default) is the unsigned fast path — backward compatible.

use std::sync::Arc;

use bytes::Bytes;
use ndn_packet::Data;
use ndn_packet::Name;
use ndn_packet::encode::DataBuilder;
use ndn_security::validator::ValidationResult;
use ndn_security::{SignWith, Signer, Validator};
use ndn_sync::{IngestValidator, PublisherSigner};

/// Sign `payload` as a Data named `name`, producing the wire blob a four-phase
/// publisher puts on the group. The Data's `KeyLocator` records the signer.
pub fn sign_message(signer: &dyn Signer, name: Name, payload: &[u8]) -> Option<Bytes> {
    DataBuilder::new(name, payload).sign_with_sync(signer).ok()
}

/// Per-node trust for the four-phase driver: an optional `signer` (this node
/// signs every message it publishes) and `validator` (this node verifies every
/// message it consumes, against the phase's expected sender).
///
/// **Secure by default (fail closed).** With no validator, inbound messages are
/// *rejected* — `TrustCtx::default()` accepts nothing, so a carrier/role that
/// never calls [`signed`](Self::new) or [`insecure`](Self::insecure) serves no
/// one rather than silently trusting forged, unauthenticated input (red-team
/// SEC-02). Running unauthenticated is a deliberate, explicit choice via
/// [`insecure`](Self::insecure) (e.g. a genuinely public, unsigned-broadcast
/// deployment) — never an accident.
///
/// This is the faithful NSF `MessageValidator` placement: trust is enforced
/// per-message in the flow (a `/<sender>/NDNSF/<phase>/…` message whose
/// signature does not validate against the configured anchors, or whose signer
/// is not under the phase's expected sender, never affects state) — *not* at the
/// sync substrate, whose `IngestValidator` gates durable storage, a separate
/// concern.
#[derive(Clone, Default)]
pub struct TrustCtx {
    /// Signs this node's outbound four-phase messages. `None` ⇒ publish raw.
    pub signer: Option<Arc<dyn Signer>>,
    /// Verifies inbound four-phase messages. `None` ⇒ reject (unless
    /// [`allow_unsigned`](Self::insecure) was explicitly set).
    pub validator: Option<Arc<Validator>>,
    /// Explicit opt-in to accepting unsigned inbound messages when no validator is
    /// configured. `false` by default (fail closed); set only via [`insecure`](Self::insecure).
    pub allow_unsigned: bool,
}

impl TrustCtx {
    /// A node that both signs its messages and validates the ones it receives.
    pub fn new(signer: Arc<dyn Signer>, validator: Arc<Validator>) -> Self {
        Self {
            signer: Some(signer),
            validator: Some(validator),
            allow_unsigned: false,
        }
    }

    /// The **explicit** unsigned/unauthenticated posture: publish raw and accept
    /// inbound without verifying. Use only for a genuinely public, unsigned
    /// deployment — every participant on the shared medium can then impersonate any
    /// requester (red-team SEC-02). Prefer [`new`](Self::new).
    pub fn insecure() -> Self {
        Self {
            signer: None,
            validator: None,
            allow_unsigned: true,
        }
    }

    /// Whether this context will accept unauthenticated inbound messages (no
    /// validator, unsigned explicitly allowed) — used to warn at serve time.
    pub fn is_insecure(&self) -> bool {
        self.validator.is_none() && self.allow_unsigned
    }

    /// Wrap `msg` as a signed Data named `name` when a signer is set, returning
    /// the wire blob to publish; otherwise return `msg` unchanged (raw).
    pub fn seal(&self, name: Name, msg: Bytes) -> Bytes {
        match &self.signer {
            Some(s) => sign_message(&**s, name, &msg).unwrap_or(msg),
            None => msg,
        }
    }

    /// Recover the inner message bytes from an inbound publication `payload`.
    /// With a validator set, `payload` must be a signed Data that validates, whose
    /// signer is under `expected_sender`, **and whose own name equals
    /// `expected_name`** (the outer publication name the flow routes on) — else
    /// `None` (fail closed). With no validator, the message is rejected unless
    /// [`insecure`](Self::insecure) was chosen, in which case `payload` is returned
    /// as-is.
    pub async fn unseal(
        &self,
        payload: Bytes,
        expected_sender: &Name,
        expected_name: &Name,
    ) -> Option<Bytes> {
        match &self.validator {
            Some(v) => verify_message(v, payload, expected_sender, expected_name).await,
            None if self.allow_unsigned => Some(payload),
            None => None, // fail closed: no validator and not explicitly insecure
        }
    }
}

/// Bridge an `ndn_security` signer into an `ndn-sync` [`PublisherSigner`], so a
/// `SvsPubSub` built with `join_secured` signs every publication with the node's
/// key (substrate-level publisher authentication). CPU-only signing.
///
/// Note: four-phase **message** trust is enforced in the flow via [`TrustCtx`]
/// (the faithful NSF `MessageValidator` placement). This substrate signer is the
/// orthogonal *durable-store* path — sign publications so a repo/ingest peer can
/// validate before persisting them (see [`ingest_validator`]).
pub fn publisher_signer(signer: Arc<dyn Signer>) -> PublisherSigner {
    let sig_type = signer.sig_type();
    let key_locator = signer.key_name().clone();
    PublisherSigner {
        sig_type,
        key_locator,
        sign: Arc::new(move |region| signer.sign_sync(region).expect("CPU-only signer")),
    }
}

/// Bridge an `ndn_security::Validator` into an `ndn-sync` [`IngestValidator`]: a
/// fetched publication is **stored** only if its Data signature validates against
/// the validator's trust anchors (fail closed). Hand the result to
/// `SvsPubSub::join_secured`.
///
/// Scope: this gates the sync substrate's **durable-store / ingest** path, not
/// pub/sub *delivery* — `SvsPubSub::fetch_publication` (the subscriber-delivery
/// path) is not gated by it. Four-phase message trust is therefore enforced in
/// the flow by [`TrustCtx`] (per-message, against each phase's expected sender),
/// and this validator additionally protects what a repo/ingest peer persists.
pub fn ingest_validator(validator: Arc<Validator>) -> IngestValidator {
    Arc::new(move |wire: Bytes| {
        let validator = validator.clone();
        Box::pin(async move {
            match Data::decode(wire) {
                Ok(data) => matches!(validator.validate(&data).await, ValidationResult::Valid(_)),
                Err(_) => false,
            }
        })
    })
}

/// Validate a signed-message blob before acting on it. Returns the inner payload
/// only if (a) the signature validates against `validator`'s anchors, (b) the
/// signer identity is under `expected_sender`, and (c) the signed Data's own name
/// equals `expected_name`. `None` (fail closed) otherwise.
pub async fn verify_message(
    validator: &Validator,
    blob: Bytes,
    expected_sender: &Name,
    expected_name: &Name,
) -> Option<Bytes> {
    let data = Data::decode(blob).ok()?;
    // Bind the message to its protocol coordinate: the signed Data's own name must
    // equal the publication name the four-phase logic routes on. Without this, a
    // validly-signed message could be replayed under a different outer name — a
    // different phase, request-id, or service (red-team SEC-04).
    if &*data.name != expected_name {
        return None;
    }
    // The signer (KeyLocator) must be under the expected sender identity — a
    // provider cannot answer "as" another, even with a valid key of its own.
    let signer = data.sig_info()?.key_locator_name()?;
    if !signer.has_prefix(expected_sender) {
        return None;
    }
    match validator.validate(&data).await {
        ValidationResult::Valid(safe) => safe.data().content().cloned(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_security::KeyChain;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    #[tokio::test]
    async fn valid_message_from_expected_sender_accepted() {
        let kc = KeyChain::ephemeral("/muas/alice").unwrap();
        let blob = sign_message(
            &*kc.signer().unwrap(),
            n("/muas/alice/NDNSF/REQUEST/x/r1"),
            b"hi",
        )
        .unwrap();
        let got = verify_message(
            &kc.validator(),
            blob,
            &n("/muas/alice"),
            &n("/muas/alice/NDNSF/REQUEST/x/r1"),
        )
        .await;
        assert_eq!(got.as_deref(), Some(b"hi".as_slice()));
    }

    #[tokio::test]
    async fn wrong_sender_prefix_rejected() {
        let kc = KeyChain::ephemeral("/muas/alice").unwrap();
        let blob = sign_message(
            &*kc.signer().unwrap(),
            n("/muas/alice/NDNSF/REQUEST/x/r1"),
            b"hi",
        )
        .unwrap();
        // The message claims to be from /muas/bob, but alice signed it.
        assert!(
            verify_message(
                &kc.validator(),
                blob,
                &n("/muas/bob"),
                &n("/muas/alice/NDNSF/REQUEST/x/r1"),
            )
            .await
            .is_none()
        );
    }

    #[tokio::test]
    async fn untrusted_signer_rejected() {
        let alice = KeyChain::ephemeral("/muas/alice").unwrap();
        let mallory = KeyChain::ephemeral("/muas/mallory").unwrap();
        let blob = sign_message(
            &*mallory.signer().unwrap(),
            n("/muas/mallory/NDNSF/ACK/x/r1"),
            b"spoof",
        )
        .unwrap();
        // alice's validator does not trust mallory's anchor.
        assert!(
            verify_message(
                &alice.validator(),
                blob,
                &n("/muas/mallory"),
                &n("/muas/mallory/NDNSF/ACK/x/r1"),
            )
            .await
            .is_none()
        );
    }

    #[tokio::test]
    async fn tampered_message_rejected() {
        let kc = KeyChain::ephemeral("/muas/alice").unwrap();
        let blob = sign_message(
            &*kc.signer().unwrap(),
            n("/muas/alice/NDNSF/REQUEST/x/r1"),
            b"hi",
        )
        .unwrap();
        let mut bad = blob.to_vec();
        let last = bad.len() - 1;
        bad[last] ^= 0xff;
        assert!(
            verify_message(
                &kc.validator(),
                Bytes::from(bad),
                &n("/muas/alice"),
                &n("/muas/alice/NDNSF/REQUEST/x/r1"),
            )
            .await
            .is_none()
        );
    }

    #[tokio::test]
    async fn replayed_under_a_different_coordinate_rejected() {
        // SEC-04: a message alice validly signed for one coordinate must not verify
        // when the flow presents it under a different outer publication name (a
        // different request-id / phase / service).
        let kc = KeyChain::ephemeral("/muas/alice").unwrap();
        let blob = sign_message(
            &*kc.signer().unwrap(),
            n("/muas/alice/NDNSF/REQUEST/x/r1"),
            b"hi",
        )
        .unwrap();
        let got = verify_message(
            &kc.validator(),
            blob,
            &n("/muas/alice"),
            &n("/muas/alice/NDNSF/REQUEST/x/r2"), // routed as r2 — must be rejected
        )
        .await;
        assert!(
            got.is_none(),
            "a message must not verify under a coordinate it wasn't signed for"
        );
    }
}
