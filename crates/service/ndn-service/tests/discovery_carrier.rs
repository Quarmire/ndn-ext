//! Witness: the Tier-1 `DiscoveryCarrier` discovers providers of a logical
//! service and invokes them over an inner Tier-0 carrier. A `#[ndn_service]`
//! client runs over it unchanged — and crucially, the discovery layer provides
//! `SelectCarrier` (multi-provider) even though the inner `RpcCarrier` is unary,
//! so the generated `echo_select` gathers every discovered provider.

use std::collections::HashSet;
use std::sync::Arc;

use ndn_packet::Name;
use ndn_rpc::{RpcCarrier, RpcRegistry};
use ndn_service::{DiscoveryCarrier, MemoryDirectory, NamingConvention, ProviderDirectory};
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
async fn discovery_selects_among_providers_over_tier0() {
    // One shared Tier-0 registry (in-process loopback) + one shared directory.
    let registry = Arc::new(RpcRegistry::new());
    let dir = Arc::new(MemoryDirectory::new());
    let svc = ServiceId::new(n("/svc/echo"));

    // Two providers offer /svc/echo, each a DiscoveryCarrier over the shared
    // RpcCarrier; serve advertises their callable and registers their dispatch.
    let p1 = DiscoveryCarrier::new(dir.clone(), RpcCarrier::with_registry(registry.clone()), n("/p1"));
    p1.serve(&svc, dispatch("p1")).await.unwrap();
    let p2 = DiscoveryCarrier::new(dir.clone(), RpcCarrier::with_registry(registry.clone()), n("/p2"));
    p2.serve(&svc, dispatch("p2")).await.unwrap();

    // The consumer's client speaks the macro-generated Echo over discovery.
    let consumer =
        DiscoveryCarrier::new(dir.clone(), RpcCarrier::with_registry(registry.clone()), n("/consumer"));
    let client = EchoClient::new(consumer, svc);

    // invoke → best-first → one discovered provider answers.
    let one = client.echo("hi".into()).await.unwrap();
    assert!(one == "p1:hi" || one == "p2:hi", "a discovered provider must answer: {one}");

    // echo_select(All): DiscoveryCarrier is a SelectCarrier even though RpcCarrier
    // is not — the discovery layer adds the multi-provider fan-out.
    let many = client.echo_select("hi".into(), Strategy::All).await.unwrap();
    let texts: HashSet<String> = many.into_iter().map(|(_, t)| t).collect();
    assert!(texts.contains("p1:hi"), "p1 missing: {texts:?}");
    assert!(texts.contains("p2:hi"), "p2 missing: {texts:?}");
}

#[tokio::test]
async fn forwarding_hint_convention_shares_name_with_per_node_hints() {
    // The data-centric convention: all providers share the content name; the
    // selected provider is reached via a forwarding hint (= its node).
    let dir = MemoryDirectory::with_convention(NamingConvention::ForwardingHint);
    let svc = ServiceId::new(n("/svc/echo"));

    let serve = dir.advertise(&svc, &n("/p1")).await;
    dir.advertise(&svc, &n("/p2")).await;
    assert_eq!(serve, n("/svc/echo"), "providers serve the shared content name");

    let entries = dir.providers(&svc).await;
    assert_eq!(entries.len(), 2);
    assert!(
        entries.iter().all(|e| e.callable == n("/svc/echo")),
        "all providers share one content name"
    );
    let hints: HashSet<String> = entries
        .iter()
        .filter_map(|e| e.forwarding_hint.as_ref().map(|h| h.to_string()))
        .collect();
    assert!(hints.contains("/p1") && hints.contains("/p2"), "per-node hints: {hints:?}");
}

#[tokio::test]
async fn no_provider_discovered_fails_closed() {
    let registry = Arc::new(RpcRegistry::new());
    let dir = Arc::new(MemoryDirectory::new());
    let consumer =
        DiscoveryCarrier::new(dir, RpcCarrier::with_registry(registry), n("/consumer"));
    // Nothing advertised for /svc/ghost.
    let client = EchoClient::new(consumer, ServiceId::new(n("/svc/ghost")));
    assert!(client.echo("hi".into()).await.is_err(), "no discovered provider → fail closed");
}
