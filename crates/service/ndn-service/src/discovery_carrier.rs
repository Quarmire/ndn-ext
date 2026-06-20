//! Tier-1 discovery-selection carrier (service-layer §3.2).
//!
//! A logical service may be offered by many providers. This carrier discovers the
//! provider set for a service via a [`ProviderDirectory`] (Tier-1), selects among
//! them, and invokes the chosen provider(s) over an **inner Tier-0 carrier** `C`
//! (e.g. `ndn-rpc`'s `RpcCarrier`) — "selection yields a provider set; the call
//! drops to Tier-0". The discovery layer therefore *adds* multi-provider
//! [`SelectCarrier`] on top of a plain inner [`Carrier`].
//!
//! Two [naming conventions](NamingConvention) for addressing a selected provider,
//! both behind the same [`ProviderDirectory`] seam (the carrier is agnostic):
//! - [`NamingConvention::NodeScoped`]: each provider has a distinct callable name
//!   `<node>/<service>`; the name itself addresses the provider (no hint).
//! - [`NamingConvention::ForwardingHint`]: all providers share the content name
//!   `<service>`; a selected provider is reached via an NDN **forwarding hint**
//!   (= its node), the more data-centric model (one content name, the network
//!   routes). Requires the inner carrier to honour hints ([`HintedCarrier`]).

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use ndn_packet::Name;
use ndn_service_core::{
    Carrier, HintedCarrier, OpId, Response, SelectCarrier, ServiceError, ServiceId, Strategy,
};

/// How a provider of a logical service is named and addressed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NamingConvention {
    /// Each provider serves a distinct callable `<node>/<service>`; the name
    /// addresses the provider directly (no forwarding hint).
    NodeScoped,
    /// All providers share the content name `<service>`; a selected provider is
    /// reached via a forwarding hint (= its node). The data-centric convention.
    ForwardingHint,
}

/// The names a convention assigns for `service` at `node`:
/// `(serve_name, callable, forwarding_hint)`.
fn names_for(conv: NamingConvention, service: &Name, node: &Name) -> (Name, Name, Option<Name>) {
    match conv {
        NamingConvention::NodeScoped => {
            let mut callable = node.clone();
            for c in service.components() {
                callable = callable.append_component(c.clone());
            }
            (callable.clone(), callable, None)
        }
        NamingConvention::ForwardingHint => (service.clone(), service.clone(), Some(node.clone())),
    }
}

/// A discovered provider of a service: the Tier-0 callable name to invoke it at,
/// an optional forwarding hint steering to it (the data-centric convention), and
/// an optional round-trip estimate for ranking (lower is better).
#[derive(Clone, Debug)]
pub struct ProviderEntry {
    /// The provider's callable name (the inner carrier's target).
    pub callable: Name,
    /// A forwarding hint to steer to this provider, when the shared-name
    /// convention is used; `None` when the callable itself addresses it.
    pub forwarding_hint: Option<Name>,
    /// Round-trip estimate for fastest-first ranking, if known.
    pub rtt: Option<Duration>,
}

/// Tier-1 provider discovery: the set of providers offering a service, and the
/// advertisement of a local offering. `advertise` returns the name the caller
/// should **serve** under (the directory owns the naming convention, so serve and
/// invoke agree). Implementations rank `providers` best-first.
#[async_trait]
pub trait ProviderDirectory: Send + Sync {
    /// Providers offering `service`, best-first.
    async fn providers(&self, service: &ServiceId) -> Vec<ProviderEntry>;
    /// Advertise that `node` offers `service`; returns the name to serve under.
    async fn advertise(&self, service: &ServiceId, node: &Name) -> Name;
}

/// A discovery-selection carrier: discover → select → invoke over the inner
/// Tier-0 carrier `C`. `node` is this node's identity (used when advertising). The
/// inner carrier must honour forwarding hints ([`HintedCarrier`]) so both naming
/// conventions work (a `None` hint is the node-scoped case).
pub struct DiscoveryCarrier<C: HintedCarrier> {
    directory: Arc<dyn ProviderDirectory>,
    inner: C,
    node: Name,
    round_robin: AtomicUsize,
}

impl<C: HintedCarrier> DiscoveryCarrier<C> {
    /// A carrier for `node` that discovers via `directory` and invokes over `inner`.
    pub fn new(directory: Arc<dyn ProviderDirectory>, inner: C, node: Name) -> Self {
        Self {
            directory,
            inner,
            node,
            round_robin: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl<C: HintedCarrier> Carrier for DiscoveryCarrier<C> {
    async fn invoke(
        &self,
        svc: &ServiceId,
        op: &OpId,
        request: Bytes,
    ) -> Result<Response, ServiceError> {
        // Best-first: invoke the top-ranked discovered provider over Tier-0,
        // steering with its forwarding hint when the shared-name convention applies.
        let provider = self
            .directory
            .providers(svc)
            .await
            .into_iter()
            .next()
            .ok_or(ServiceError::NotFound)?;
        self.inner
            .invoke_hinted(
                &ServiceId::new(provider.callable),
                op,
                request,
                provider.forwarding_hint.as_ref(),
            )
            .await
    }

    async fn serve(&self, svc: &ServiceId, dispatch: Arc<dyn ndn_service_core::Dispatch>) -> Result<(), ServiceError> {
        // The directory (owner of the naming convention) returns the serve name.
        let serve_name = self.directory.advertise(svc, &self.node).await;
        self.inner.serve(&ServiceId::new(serve_name), dispatch).await
    }
}

#[async_trait]
impl<C: HintedCarrier> SelectCarrier for DiscoveryCarrier<C> {
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
                .invoke_hinted(
                    &ServiceId::new(p.callable),
                    op,
                    request.clone(),
                    p.forwarding_hint.as_ref(),
                )
                .await
            {
                responses.push(r);
            }
        }
        Ok(responses)
    }
}

/// Cap on tracked providers per service, so a flood of advertisements (or one
/// node re-advertising) can't grow the directory — or its O(n log n) ranked read —
/// without bound (red-team SEC-27).
const MAX_PROVIDERS_PER_SERVICE: usize = 256;

/// An in-process [`ProviderDirectory`] — the seam used to prove the carrier.
/// Honours a [`NamingConvention`] (default [`NodeScoped`](NamingConvention::NodeScoped)).
pub struct MemoryDirectory {
    convention: NamingConvention,
    table: Mutex<HashMap<Name, Vec<ProviderEntry>>>,
}

impl MemoryDirectory {
    /// An empty directory using the node-scoped convention.
    pub fn new() -> Self {
        Self::with_convention(NamingConvention::NodeScoped)
    }

    /// An empty directory using `convention`.
    pub fn with_convention(convention: NamingConvention) -> Self {
        Self {
            convention,
            table: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for MemoryDirectory {
    fn default() -> Self {
        Self::new()
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

    async fn advertise(&self, service: &ServiceId, node: &Name) -> Name {
        let (serve, callable, forwarding_hint) =
            names_for(self.convention, service.name(), node);
        let mut table = self.table.lock().expect("directory lock");
        let entries = table.entry(service.name().clone()).or_default();
        // Re-advertising the same provider refreshes rather than duplicates, and the
        // per-service set is capped (drop oldest) so growth and ranked-read cost stay
        // bounded (red-team SEC-27).
        let dup = entries
            .iter()
            .any(|e| e.callable == callable && e.forwarding_hint == forwarding_hint);
        if !dup {
            if entries.len() >= MAX_PROVIDERS_PER_SERVICE {
                entries.remove(0);
            }
            entries.push(ProviderEntry {
                callable,
                forwarding_hint,
                rtt: None,
            });
        }
        serve
    }
}
