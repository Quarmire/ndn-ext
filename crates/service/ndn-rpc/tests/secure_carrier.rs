//! The **secure** `RpcCarrier`: a signed request authenticates its requester.
//!
//! This exercises the canonical NDN signed-Interest contract end to end over the
//! Tier-0 carrier — `with_signer` signs the request, `with_validator` verifies it and
//! sets `Invocation::requester` to the *verified* `KeyLocator` name — the same shape
//! `ndn-service`'s command path and NFD-style mgmt commands use (no ABE/NAC). It also
//! pins the secure-by-default reject: a validator-equipped carrier fails closed on an
//! unsigned request.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use ndn_packet::Name;
use ndn_rpc::RpcCarrier;
use ndn_security::Validator;
use ndn_security::cert_cache::Certificate;
use ndn_security::signer::{Ed25519Signer, Signer};
use ndn_security::trust_schema::{NamePattern, PatternComponent, SchemaRule, TrustSchema};
use ndn_service_core::{Carrier, Dispatch, Invocation, OpId, ServiceError, ServiceId};

fn name(s: &str) -> Name {
    s.parse().unwrap()
}

/// Accept any key for any name — the trust decision under test is *signature
/// verification + requester extraction*, not the schema.
fn open_schema() -> TrustSchema {
    let mut schema = TrustSchema::new();
    schema.add_rule(SchemaRule {
        data_pattern: NamePattern(vec![PatternComponent::MultiCapture("_".into())]),
        key_pattern: NamePattern(vec![PatternComponent::MultiCapture("_".into())]),
    });
    schema
}

/// A dispatcher that echoes back the authenticated requester (or "anon").
struct WhoamiDispatch;
#[async_trait]
impl Dispatch for WhoamiDispatch {
    async fn dispatch(&self, inv: Invocation) -> Result<Bytes, ServiceError> {
        let who = inv
            .requester
            .map(|n| n.to_string())
            .unwrap_or_else(|| "anon".into());
        Ok(Bytes::from(who))
    }
}

const KEY_NAME: &str = "/operators/alice/KEY/k1";

/// Build a validator that trusts the test signer's key.
fn validator_trusting(signer: &Ed25519Signer, key_name: &Name) -> Validator {
    let validator = Validator::new(open_schema());
    validator.cert_cache().insert(Certificate {
        name: Arc::new(key_name.clone()),
        public_key: Bytes::copy_from_slice(&signer.public_key_bytes()),
        valid_from: 0,
        valid_until: u64::MAX,
        issuer: None,
        signed_region: None,
        sig_value: None,
        sig_type: ndn_packet::SignatureType::SignatureEd25519,
    });
    validator
}

/// A signed request → the serve side verifies it and the dispatcher sees the
/// verified signer as the requester.
#[tokio::test]
async fn signed_request_authenticates_requester() {
    let key_name = name(KEY_NAME);
    let signer = Ed25519Signer::from_seed(&[9u8; 32], key_name.clone());
    let validator = validator_trusting(&signer, &key_name);

    let carrier = RpcCarrier::new()
        .with_signer(Arc::new(signer) as Arc<dyn Signer>)
        .with_validator(Arc::new(validator));
    let svc = ServiceId::new(name("/svc/echo"));
    carrier.serve(&svc, Arc::new(WhoamiDispatch)).await.unwrap();

    let resp = carrier
        .invoke(&svc, &OpId::new("whoami"), Bytes::new())
        .await
        .expect("signed request must be authorized");
    assert_eq!(
        std::str::from_utf8(&resp.payload).unwrap(),
        KEY_NAME,
        "requester must be the verified KeyLocator identity, not anonymous"
    );
}

/// A validator-equipped carrier with no signer sends an unsigned request — the
/// serve side must reject it (secure-by-default fail-closed).
#[tokio::test]
async fn unsigned_request_is_rejected_by_secure_server() {
    let key_name = name(KEY_NAME);
    let signer = Ed25519Signer::from_seed(&[9u8; 32], key_name.clone());
    let validator = validator_trusting(&signer, &key_name);

    // Validator wired, but NO signer ⇒ the request goes out unsigned.
    let carrier = RpcCarrier::new().with_validator(Arc::new(validator));
    let svc = ServiceId::new(name("/svc/echo"));
    carrier.serve(&svc, Arc::new(WhoamiDispatch)).await.unwrap();

    let r = carrier
        .invoke(&svc, &OpId::new("whoami"), Bytes::new())
        .await;
    assert!(
        matches!(r, Err(ServiceError::Unauthorized(_))),
        "an unsigned request must be rejected as Unauthorized, got {r:?}"
    );
}

/// G2.1: the invoke side verifies the *response*. A server signs its response with a key
/// the client's validator does not trust → the client rejects it rather than returning
/// unverified content. (Two carriers over one registry: the server authenticates nothing
/// and signs with alice; the client trusts nobody.)
#[tokio::test]
async fn untrusted_response_is_rejected_on_invoke() {
    use ndn_rpc::RpcRegistry;
    let key_name = name(KEY_NAME);
    let alice = Ed25519Signer::from_seed(&[9u8; 32], key_name.clone());

    let registry = Arc::new(RpcRegistry::new());
    // Server: signs responses with alice, accepts unsigned requests (no validator).
    let server =
        RpcCarrier::with_registry(registry.clone()).with_signer(Arc::new(alice) as Arc<dyn Signer>);
    let svc = ServiceId::new(name("/svc/echo"));
    server.serve(&svc, Arc::new(WhoamiDispatch)).await.unwrap();

    // Client: a validator that trusts NObody (empty cert cache) ⇒ the alice-signed
    // response can't be verified.
    let client =
        RpcCarrier::with_registry(registry).with_validator(Arc::new(Validator::new(open_schema())));
    let r = client
        .invoke(&svc, &OpId::new("whoami"), Bytes::new())
        .await;
    assert!(
        matches!(r, Err(ServiceError::Unauthorized(_))),
        "an unverifiable response must be rejected, got {r:?}"
    );
}

/// No signer and no validator = the plain in-process loopback: the request is
/// unsigned and the requester is anonymous (back-compat).
#[tokio::test]
async fn loopback_without_security_is_anonymous() {
    let carrier = RpcCarrier::new();
    let svc = ServiceId::new(name("/svc/echo"));
    carrier.serve(&svc, Arc::new(WhoamiDispatch)).await.unwrap();

    let resp = carrier
        .invoke(&svc, &OpId::new("whoami"), Bytes::new())
        .await
        .unwrap();
    assert_eq!(std::str::from_utf8(&resp.payload).unwrap(), "anon");
}
