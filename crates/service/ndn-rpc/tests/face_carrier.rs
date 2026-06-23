#![cfg(feature = "engine")]
//! The face-backed carrier turns the proven seam into a **real** network service
//! call: a `#[ndn_service]` client invokes a provider that lives behind a
//! different face on the forwarder. The Interest is routed by the engine (FIB) to
//! the provider's face; the response Data flows back through the PIT — not a
//! shared in-process registry.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use ndn_app::{Consumer, EngineBuilder, Producer};
use ndn_engine::EngineConfig;
use ndn_face::local::InProcFace;
use ndn_packet::Name;
use ndn_rpc::FaceRpcCarrier;
use ndn_security::cert_cache::Certificate;
use ndn_security::signer::{Ed25519Signer, Signer};
use ndn_security::trust_schema::{NamePattern, PatternComponent, SchemaRule, TrustSchema};
use ndn_security::Validator;
use ndn_service_core::{Carrier, Dispatch, Invocation, OpId, ServiceError, ServiceId};
use ndn_service_macro::ndn_service;
use ndn_transport::FaceId;

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

#[ndn_service]
trait Echo {
    async fn echo(&self, msg: String) -> String;
}

struct EchoImpl;
impl Echo for EchoImpl {
    async fn echo(&self, msg: String) -> String {
        format!("echo:{msg}")
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn macro_client_calls_a_provider_over_the_engine() {
    let svc_prefix = n("/svc/echo");

    // One engine acting as the forwarder; a consumer face and a producer face.
    let (c_face, c_handle) = InProcFace::new(FaceId(1), 64);
    let (p_face, p_handle) = InProcFace::new(FaceId(2), 64);
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(c_face)
        .face(p_face)
        .build()
        .await
        .unwrap();
    // Route the service prefix to the provider's face.
    engine.fib().add_nexthop(&svc_prefix, FaceId(2), 0);

    // Provider: serve the macro dispatch over a Producer on its face.
    let producer = Producer::from_handle(p_handle, svc_prefix.clone());
    let serve = tokio::spawn(async move {
        let server = FaceRpcCarrier::server(producer);
        let svc = ServiceId::new(n("/svc/echo"));
        let _ = server.serve(&svc, Arc::new(EchoDispatch(Arc::new(EchoImpl)))).await;
    });

    // Client: a generated EchoClient over a face-backed carrier on its own face.
    let consumer = Consumer::from_handle(c_handle);
    let client = EchoClient::new(FaceRpcCarrier::client(consumer), ServiceId::new(svc_prefix));

    let reply = tokio::time::timeout(Duration::from_secs(8), client.echo("ping".into()))
        .await
        .expect("call timed out")
        .expect("echo failed");
    assert_eq!(reply, "echo:ping", "a real cross-face service call over the engine");

    serve.abort();
    drop(engine);
    shutdown.shutdown().await;
}

// --- signed (authenticated) face-carrier calls ---

const KEY_NAME: &str = "/operators/alice/KEY/k1";

/// Echo the authenticated requester back to the client (or "anon").
struct WhoamiDispatch;
#[async_trait]
impl Dispatch for WhoamiDispatch {
    async fn dispatch(&self, inv: Invocation) -> Result<Bytes, ServiceError> {
        Ok(Bytes::from(
            inv.requester.map(|n| n.to_string()).unwrap_or_else(|| "anon".into()),
        ))
    }
}

fn open_schema() -> TrustSchema {
    let mut schema = TrustSchema::new();
    schema.add_rule(SchemaRule {
        data_pattern: NamePattern(vec![PatternComponent::MultiCapture("_".into())]),
        key_pattern: NamePattern(vec![PatternComponent::MultiCapture("_".into())]),
    });
    schema
}

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

/// Spin up a one-engine two-face forwarder routing `/svc/whoami` to a provider.
async fn whoami_engine() -> (Consumer, Producer, ndn_engine::ForwarderEngine, ndn_engine::ShutdownHandle) {
    let svc_prefix = n("/svc/whoami");
    let (c_face, c_handle) = InProcFace::new(FaceId(1), 64);
    let (p_face, p_handle) = InProcFace::new(FaceId(2), 64);
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(c_face)
        .face(p_face)
        .build()
        .await
        .unwrap();
    engine.fib().add_nexthop(&svc_prefix, FaceId(2), 0);
    (
        Consumer::from_handle(c_handle),
        Producer::from_handle(p_handle, svc_prefix),
        engine,
        shutdown,
    )
}

/// A *signed* request routed over the engine: the provider verifies it and the
/// dispatcher sees the verified signer as the requester. Also proves a signed
/// Interest (with its ParametersSha256Digest component) routes + PIT-matches.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signed_request_authenticates_requester_over_engine() {
    let key_name = n(KEY_NAME);
    let signer = Ed25519Signer::from_seed(&[9u8; 32], key_name.clone());
    let validator = validator_trusting(&signer, &key_name);
    let (consumer, producer, engine, shutdown) = whoami_engine().await;

    let serve = tokio::spawn(async move {
        let server = FaceRpcCarrier::server(producer).with_validator(Arc::new(validator));
        let _ = server
            .serve(&ServiceId::new(n("/svc/whoami")), Arc::new(WhoamiDispatch))
            .await;
    });

    let client = FaceRpcCarrier::client(consumer).with_signer(Arc::new(signer) as Arc<dyn Signer>);
    let resp = tokio::time::timeout(
        Duration::from_secs(8),
        client.invoke(&ServiceId::new(n("/svc/whoami")), &OpId::new("whoami"), Bytes::new()),
    )
    .await
    .expect("call timed out")
    .expect("signed call must be authorized");
    assert_eq!(std::str::from_utf8(&resp.payload).unwrap(), KEY_NAME);

    serve.abort();
    drop(engine);
    shutdown.shutdown().await;
}

/// A provider with a validator drops an unsigned request → the client fails closed
/// on timeout (the wire equivalent of Unauthorized).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unsigned_request_dropped_by_secure_provider_over_engine() {
    let key_name = n(KEY_NAME);
    let signer = Ed25519Signer::from_seed(&[9u8; 32], key_name.clone());
    let validator = validator_trusting(&signer, &key_name);
    let (consumer, producer, engine, shutdown) = whoami_engine().await;

    let serve = tokio::spawn(async move {
        let server = FaceRpcCarrier::server(producer).with_validator(Arc::new(validator));
        let _ = server
            .serve(&ServiceId::new(n("/svc/whoami")), Arc::new(WhoamiDispatch))
            .await;
    });

    // Client with no signer ⇒ unsigned request ⇒ provider drops it ⇒ timeout.
    let client = FaceRpcCarrier::client(consumer).with_timeout(Duration::from_millis(600));
    let r = client
        .invoke(&ServiceId::new(n("/svc/whoami")), &OpId::new("whoami"), Bytes::new())
        .await;
    assert!(r.is_err(), "an unsigned request must not be answered, got {r:?}");

    serve.abort();
    drop(engine);
    shutdown.shutdown().await;
}
