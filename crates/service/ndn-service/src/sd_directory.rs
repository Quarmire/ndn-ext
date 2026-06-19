//! A production [`ProviderDirectory`] backed by `ndn-discovery`'s
//! `ServiceDiscoveryProtocol` (feature `discovery`).
//!
//! Naming convention: a provider advertises a **node-scoped callable**
//! `<node>/<service>` as the service record's announced prefix (exactly what
//! [`DiscoveryCarrier::serve`](crate::DiscoveryCarrier) produces). The directory
//! returns records whose announced prefix has `service` as a **suffix**, and
//! ranks them best-first by measured RTT (`rtt_p50`, else `last_rtt`).
//!
//! This adapter is a *read/advertise view* over the protocol's current state:
//! `providers` reads `all_records` + `measurements`, `advertise` calls `publish`.
//! The actual cross-node browse/sync that populates `all_records` on a consumer
//! is driven by the host engine that runs `ServiceDiscoveryProtocol` as a
//! `DiscoveryProtocol` plugin (witnessed in `ndn-discovery`); this crate does not
//! own that loop.

use std::sync::Arc;

use async_trait::async_trait;
use ndn_discovery::{ServiceDiscoveryProtocol, ServiceRecord};
use ndn_packet::Name;
use ndn_service_core::ServiceId;

use crate::discovery_carrier::{ProviderDirectory, ProviderEntry};

/// A [`ProviderDirectory`] over a shared `ServiceDiscoveryProtocol`.
pub struct ServiceDiscoveryDirectory {
    sd: Arc<ServiceDiscoveryProtocol>,
}

impl ServiceDiscoveryDirectory {
    /// A directory reading from / advertising to `sd`.
    pub fn new(sd: Arc<ServiceDiscoveryProtocol>) -> Self {
        Self { sd }
    }
}

/// Does `name` end with `suffix`'s components?
fn ends_with(name: &Name, suffix: &Name) -> bool {
    let n = name.components();
    let s = suffix.components();
    n.len() >= s.len() && n[n.len() - s.len()..].iter().zip(s).all(|(a, b)| a == b)
}

/// `name` with its trailing `suffix` components removed (the node prefix).
fn strip_suffix(name: &Name, suffix: &Name) -> Name {
    let n = name.components();
    let s = suffix.components();
    if ends_with(name, suffix) {
        Name::from_components(n[..n.len() - s.len()].iter().cloned())
    } else {
        name.clone()
    }
}

#[async_trait]
impl ProviderDirectory for ServiceDiscoveryDirectory {
    async fn providers(&self, service: &ServiceId) -> Vec<ProviderEntry> {
        let svc = service.name();
        let mut entries: Vec<ProviderEntry> = self
            .sd
            .all_records()
            .into_iter()
            .filter(|r| ends_with(&r.announced_prefix, svc))
            .map(|r| {
                let rtt = self
                    .sd
                    .measurements(&r.announced_prefix)
                    .into_iter()
                    .find(|m| m.node_name == r.node_name)
                    .and_then(|m| m.rtt_p50.or(m.last_rtt));
                ProviderEntry {
                    callable: r.announced_prefix,
                    rtt,
                }
            })
            .collect();
        // Best-first: known RTT ascending, then unknown.
        entries.sort_by(|a, b| match (a.rtt, b.rtt) {
            (Some(x), Some(y)) => x.cmp(&y),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        });
        entries
    }

    async fn advertise(&self, service: &ServiceId, callable: &Name) {
        // Publish the node-scoped callable as the record's announced prefix; the
        // node identity is the callable with the service suffix stripped (so RTT
        // measurements key consistently per provider).
        let node = strip_suffix(callable, service.name());
        self.sd.publish(ServiceRecord::new(callable.clone(), node));
    }
}
