//! Tier-1 discovery-selection carrier (service-layer §3.2).
//!
//! A logical service may be offered by many providers. This carrier discovers the
//! provider set for a service via a [`ProviderDirectory`] (Tier-1), selects among
//! them, and invokes the chosen provider(s) over an **inner Tier-0 carrier** `C`
//! (e.g. `ndn-rpc`'s `RpcCarrier`) — "selection yields a provider set; the call
//! drops to Tier-0". The discovery layer therefore *adds* multi-provider
//! [`SelectCarrier`] on top of a plain unary inner [`Carrier`].
//!
//! The directory is a seam: [`MemoryDirectory`] is the in-process implementation
//! used to prove the carrier; a production directory wraps
//! `ndn-discovery::service_discovery::ServiceDiscoveryProtocol` (its `all_records`
//! for the set and `measurements` for RTT-ranking), with its own service↔provider
//! naming convention. The carrier is agnostic to which directory backs it.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use ndn_packet::Name;
use ndn_service_core::{Carrier, OpId, Response, SelectCarrier, ServiceError, ServiceId, Strategy};

/// A discovered provider of a service: the Tier-0 callable name to invoke it at,
/// and an optional round-trip estimate for ranking (lower is better).
#[derive(Clone, Debug)]
pub struct ProviderEntry {
    /// The provider's callable service prefix (the inner carrier's target).
    pub callable: Name,
    /// Round-trip estimate for fastest-first ranking, if known.
    pub rtt: Option<Duration>,
}

/// Tier-1 provider discovery: the set of providers offering a service, and the
/// advertisement of a local offering. Implementations rank `providers` best-first
/// (e.g. lowest RTT). A production impl reads
/// `ServiceDiscoveryProtocol::{all_records, measurements}`; [`MemoryDirectory`] is
/// the in-process one used in tests.
#[async_trait]
pub trait ProviderDirectory: Send + Sync {
    /// Providers offering `service`, best-first.
    async fn providers(&self, service: &ServiceId) -> Vec<ProviderEntry>;
    /// Advertise that this node offers `service` at the Tier-0 `callable` prefix.
    async fn advertise(&self, service: &ServiceId, callable: &Name);
}

/// A discovery-selection carrier: discover → select → invoke over the inner
/// Tier-0 carrier `C`. `node` is this node's prefix; the callable it advertises
/// for a service is `<node>/<service>`.
pub struct DiscoveryCarrier<C: Carrier> {
    directory: Arc<dyn ProviderDirectory>,
    inner: C,
    node: Name,
    round_robin: AtomicUsize,
}

impl<C: Carrier> DiscoveryCarrier<C> {
    /// A carrier for `node` that discovers via `directory` and invokes over `inner`.
    pub fn new(directory: Arc<dyn ProviderDirectory>, inner: C, node: Name) -> Self {
        Self {
            directory,
            inner,
            node,
            round_robin: AtomicUsize::new(0),
        }
    }

    /// The callable prefix this node advertises for `svc`: `<node>/<service>`.
    fn callable(&self, svc: &ServiceId) -> Name {
        let mut name = self.node.clone();
        for c in svc.name().components() {
            name = name.append_component(c.clone());
        }
        name
    }
}

#[async_trait]
impl<C: Carrier> Carrier for DiscoveryCarrier<C> {
    async fn invoke(
        &self,
        svc: &ServiceId,
        op: &OpId,
        request: Bytes,
    ) -> Result<Response, ServiceError> {
        // Best-first: invoke the top-ranked discovered provider over Tier-0.
        let provider = self
            .directory
            .providers(svc)
            .await
            .into_iter()
            .next()
            .ok_or(ServiceError::NotFound)?;
        self.inner
            .invoke(&ServiceId::new(provider.callable), op, request)
            .await
    }

    async fn serve(&self, svc: &ServiceId, dispatch: Arc<dyn ndn_service_core::Dispatch>) -> Result<(), ServiceError> {
        // Advertise this node's offering, then serve it on the inner Tier-0 carrier.
        let callable = self.callable(svc);
        self.directory.advertise(svc, &callable).await;
        self.inner.serve(&ServiceId::new(callable), dispatch).await
    }
}

#[async_trait]
impl<C: Carrier> SelectCarrier for DiscoveryCarrier<C> {
    async fn invoke_select(
        &self,
        svc: &ServiceId,
        op: &OpId,
        request: Bytes,
        strategy: Strategy,
    ) -> Result<Vec<Response>, ServiceError> {
        let providers = self.directory.providers(svc).await;
        if providers.is_empty() {
            return Ok(Vec::new());
        }
        let chosen: Vec<ProviderEntry> = match strategy {
            Strategy::FirstResponding => providers.into_iter().take(1).collect(),
            Strategy::All => providers,
            Strategy::Random => {
                // Round-robin one provider — spreads load without an RNG dependency
                // (true randomization is deferred; the contract is "one provider").
                let idx = self.round_robin.fetch_add(1, Ordering::Relaxed) % providers.len();
                providers.into_iter().nth(idx).into_iter().collect()
            }
        };
        let mut responses = Vec::new();
        for p in chosen {
            if let Ok(r) = self
                .inner
                .invoke(&ServiceId::new(p.callable), op, request.clone())
                .await
            {
                responses.push(r);
            }
        }
        Ok(responses)
    }
}

/// An in-process [`ProviderDirectory`] — the seam used to prove the carrier. A
/// production directory wraps `ServiceDiscoveryProtocol`.
#[derive(Default)]
pub struct MemoryDirectory {
    table: Mutex<HashMap<Name, Vec<ProviderEntry>>>,
}

impl MemoryDirectory {
    /// An empty directory.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl ProviderDirectory for MemoryDirectory {
    async fn providers(&self, service: &ServiceId) -> Vec<ProviderEntry> {
        self.table
            .lock()
            .expect("directory lock")
            .get(service.name())
            .cloned()
            .unwrap_or_default()
    }

    async fn advertise(&self, service: &ServiceId, callable: &Name) {
        self.table
            .lock()
            .expect("directory lock")
            .entry(service.name().clone())
            .or_default()
            .push(ProviderEntry {
                callable: callable.clone(),
                rtt: None,
            });
    }
}
