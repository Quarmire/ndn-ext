#![cfg(feature = "discovery")]
//! Witness: the real `ServiceDiscoveryDirectory` (backed by
//! `ServiceDiscoveryProtocol`) feeds the Tier-1 `DiscoveryCarrier` — the same
//! role `MemoryDirectory` played, now over the production discovery protocol.
//! Providers advertise via the directory (`publish`); the consumer discovers them
//! via `all_records` (suffix-matched on the service) and invokes over Tier-0.
//!
//! Providers and consumer share one `ServiceDiscoveryProtocol` instance, so the
//! advertised records are visible locally; cross-node, the host engine syncs
//! records into each node's protocol (ndn-discovery's witnessed responsibility).

use std::collections::HashSet;
use std::sync::Arc;

use ndn_discovery::ServiceDiscoveryProtocol;
use ndn_packet::Name;
use ndn_rpc::{RpcCarrier, RpcRegistry};
use ndn_service::{DiscoveryCarrier, ProviderDirectory, ServiceDiscoveryDirectory};
use ndn_service_core::{Carrier, ServiceId, Strategy};
use ndn_service_macro::ndn_service;

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

#[ndn_service]
trait Echo {
    async fn echo(&self, msg: String) -> String;
}

struct EchoImpl {
    tag: String,
}
impl Echo for EchoImpl {
    async fn echo(&self, msg: String) -> String {
        format!("{}:{msg}", self.tag)
    }
}

fn dispatch(tag: &str) -> Arc<EchoDispatch<EchoImpl>> {
    Arc::new(EchoDispatch(Arc::new(EchoImpl { tag: tag.into() })))
}

#[tokio::test]
async fn sd_directory_feeds_discovery_carrier() {
    let registry = Arc::new(RpcRegistry::new());
    let sd = Arc::new(ServiceDiscoveryProtocol::with_defaults(n("/site/sd")));
    let dir = Arc::new(ServiceDiscoveryDirectory::new(sd.clone()));
    let svc = ServiceId::new(n("/svc/echo"));

    // Two providers advertise (publish) /svc/echo via the SD-backed directory and
    // serve it over the shared Tier-0 carrier.
    let p1 = DiscoveryCarrier::new(
        dir.clone(),
        RpcCarrier::with_registry(registry.clone()),
        n("/p1"),
    );
    p1.serve(&svc, dispatch("p1")).await.unwrap();
    let p2 = DiscoveryCarrier::new(
        dir.clone(),
        RpcCarrier::with_registry(registry.clone()),
        n("/p2"),
    );
    p2.serve(&svc, dispatch("p2")).await.unwrap();

    // The directory itself resolves the providers from the SD protocol's records.
    let found: HashSet<String> = dir
        .providers(&svc)
        .await
        .into_iter()
        .map(|e| e.callable.to_string())
        .collect();
    assert!(
        found.contains("/p1/svc/echo"),
        "p1 not discovered: {found:?}"
    );
    assert!(
        found.contains("/p2/svc/echo"),
        "p2 not discovered: {found:?}"
    );

    // A #[ndn_service] client runs over the discovery carrier backed by real SD.
    let consumer = DiscoveryCarrier::new(
        dir.clone(),
        RpcCarrier::with_registry(registry.clone()),
        n("/consumer"),
    );
    let client = EchoClient::new(consumer, svc);

    let one = client.echo("hi".into()).await.unwrap();
    assert!(
        one == "p1:hi" || one == "p2:hi",
        "a discovered provider must answer: {one}"
    );

    let many = client
        .echo_select("hi".into(), Strategy::All)
        .await
        .unwrap();
    let texts: HashSet<String> = many.into_iter().map(|(_, t)| t).collect();
    assert!(texts.contains("p1:hi"), "p1 missing: {texts:?}");
    assert!(texts.contains("p2:hi"), "p2 missing: {texts:?}");
}
