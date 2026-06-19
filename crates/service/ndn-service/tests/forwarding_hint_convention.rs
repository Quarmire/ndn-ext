#![cfg(feature = "discovery")]
//! The forwarding-hint naming convention over the real `ServiceDiscoveryDirectory`
//! (the data-centric alternative): all providers share the content name
//! `/svc/echo`; a selected provider is reached via a forwarding hint (= its node).
//! End-to-end through `DiscoveryCarrier<RpcCarrier>` — the hint rides on the
//! shared-name Interest (a real forwarder would steer by it; here a capturing
//! handler at the shared name confirms the hint is on the wire).

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use ndn_discovery::ServiceDiscoveryProtocol;
use ndn_packet::encode::DataBuilder;
use ndn_packet::{Data, Interest, Name};
use ndn_rpc::{RpcCarrier, RpcError, RpcHandler, RpcRegistry};
use ndn_service::{DiscoveryCarrier, NamingConvention, ProviderDirectory, ServiceDiscoveryDirectory};
use ndn_service_core::{Carrier, OpId, ServiceId};

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

/// Records the forwarding hint of the most recent inbound Interest.
struct CaptureHint(Arc<Mutex<Option<String>>>);
impl RpcHandler for CaptureHint {
    async fn handle(&self, interest: &Interest) -> Result<Data, RpcError> {
        *self.0.lock().unwrap() = interest
            .forwarding_hint()
            .and_then(|hs| hs.first())
            .map(|h| h.to_string());
        let wire = DataBuilder::new((*interest.name).clone(), b"ok").sign_digest_sha256();
        Data::decode(wire).map_err(|e| RpcError::HandlerFailed(e.to_string()))
    }
}

#[tokio::test]
async fn forwarding_hint_convention_shares_name_and_steers_by_hint() {
    let registry = Arc::new(RpcRegistry::new());
    let captured = Arc::new(Mutex::new(None));
    // One shared content name; the hint (not the name) distinguishes providers.
    registry.register(&n("/svc/echo"), CaptureHint(captured.clone()));

    let sd = Arc::new(ServiceDiscoveryProtocol::with_defaults(n("/site/sd")));
    let dir = Arc::new(ServiceDiscoveryDirectory::with_convention(
        sd,
        NamingConvention::ForwardingHint,
    ));
    let svc = ServiceId::new(n("/svc/echo"));

    // Two providers advertise the SHARED service name; their node is the hint.
    dir.advertise(&svc, &n("/p1")).await;
    dir.advertise(&svc, &n("/p2")).await;

    // The directory resolves a shared callable with per-node forwarding hints.
    let entries = dir.providers(&svc).await;
    assert_eq!(entries.len(), 2, "both providers discovered under the shared name");
    assert!(
        entries.iter().all(|e| e.callable == n("/svc/echo")),
        "shared content name across providers"
    );
    let hints: HashSet<String> = entries
        .iter()
        .filter_map(|e| e.forwarding_hint.as_ref().map(|h| h.to_string()))
        .collect();
    assert!(hints.contains("/p1") && hints.contains("/p2"), "per-node hints: {hints:?}");

    // Through the carrier: invoke the shared name; the selected provider's hint
    // rides on the Interest (a real forwarder steers by it).
    let consumer = DiscoveryCarrier::new(dir, RpcCarrier::with_registry(registry), n("/consumer"));
    consumer.invoke(&svc, &OpId::new("echo"), bytes::Bytes::new()).await.unwrap();
    let got = captured.lock().unwrap().clone();
    assert!(
        got == Some("/p1".to_string()) || got == Some("/p2".to_string()),
        "the shared-name Interest must carry a selected provider's hint: {got:?}"
    );
}
