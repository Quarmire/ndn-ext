//! A production [`ProviderDirectory`] backed by `ndn-discovery`'s
//! `ServiceDiscoveryProtocol` (feature `discovery`).
//!
//! Supports both [`NamingConvention`]s:
//! - [`NodeScoped`](NamingConvention::NodeScoped): a provider advertises
//!   `<node>/<service>` as the record's announced prefix; the directory returns
//!   records whose announced prefix has `service` as a **suffix**, callable =
//!   that prefix, no hint.
//! - [`ForwardingHint`](NamingConvention::ForwardingHint): a provider advertises
//!   the shared `<service>` as the announced prefix (with its node as the record's
//!   node name); the directory returns the shared callable and a forwarding hint =
//!   the record's node — the data-centric model (one content name, the forwarder
//!   steers).
//!
//! Either way it is a *read/advertise view*: `providers` reads `all_records` +
//! `measurements` (ranked best-first by `rtt_p50`/`last_rtt`), `advertise` calls
//! `publish`. The cross-node browse/sync that populates `all_records` is the host
//! engine's job (the protocol is a `DiscoveryProtocol` plugin, witnessed in
//! `ndn-discovery`); this crate does not own that loop.

use std::sync::Arc;

use async_trait::async_trait;
use ndn_discovery::{ServiceDiscoveryProtocol, ServiceRecord};
use ndn_packet::Name;
use ndn_service_core::ServiceId;

use crate::discovery_carrier::{NamingConvention, ProviderDirectory, ProviderEntry};

/// A [`ProviderDirectory`] over a shared `ServiceDiscoveryProtocol`.
pub struct ServiceDiscoveryDirectory {
    sd: Arc<ServiceDiscoveryProtocol>,
    convention: NamingConvention,
}

impl ServiceDiscoveryDirectory {
    /// A directory over `sd` using the node-scoped convention.
    pub fn new(sd: Arc<ServiceDiscoveryProtocol>) -> Self {
        Self::with_convention(sd, NamingConvention::NodeScoped)
    }

    /// A directory over `sd` using `convention`.
    pub fn with_convention(
        sd: Arc<ServiceDiscoveryProtocol>,
        convention: NamingConvention,
    ) -> Self {
        Self { sd, convention }
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

/// `<base>/<service>`.
fn append_service(base: &Name, service: &Name) -> Name {
    let mut name = base.clone();
    for c in service.components() {
        name = name.append_component(c.clone());
    }
    name
}

impl ServiceDiscoveryDirectory {
    /// RTT for `(announced_prefix, node)`, best of `rtt_p50` then `last_rtt`.
    fn rtt_of(&self, announced: &Name, node: &Name) -> Option<std::time::Duration> {
        self.sd
            .measurements(announced)
            .into_iter()
            .find(|m| &m.node_name == node)
            .and_then(|m| m.rtt_p50.or(m.last_rtt))
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
            .filter_map(|r| match self.convention {
                // Node-scoped: announced prefix ends with the service; callable is
                // that per-provider prefix, no hint.
                NamingConvention::NodeScoped => {
                    if !ends_with(&r.announced_prefix, svc) {
                        return None;
                    }
                    let rtt = self.rtt_of(&r.announced_prefix, &r.node_name);
                    Some(ProviderEntry {
                        callable: r.announced_prefix,
                        forwarding_hint: None,
                        rtt,
                    })
                }
                // Forwarding-hint: announced prefix is exactly the shared service;
                // callable is the shared name, hint = the record's node.
                NamingConvention::ForwardingHint => {
                    if r.announced_prefix.components() != svc.components() {
                        return None;
                    }
                    let rtt = self.rtt_of(&r.announced_prefix, &r.node_name);
                    Some(ProviderEntry {
                        callable: svc.clone(),
                        forwarding_hint: Some(r.node_name),
                        rtt,
                    })
                }
            })
            .collect();
        entries.sort_by(|a, b| match (a.rtt, b.rtt) {
            (Some(x), Some(y)) => x.cmp(&y),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        });
        entries
    }

    async fn advertise(&self, service: &ServiceId, node: &Name) -> Name {
        let svc = service.name();
        let (announced, serve) = match self.convention {
            // Node-scoped: announce + serve the per-provider name <node>/<service>.
            NamingConvention::NodeScoped => {
                let callable = append_service(node, svc);
                (callable.clone(), callable)
            }
            // Forwarding-hint: announce + serve the shared service name; the node
            // is the record's node (how the forwarder reaches this provider).
            NamingConvention::ForwardingHint => (svc.clone(), svc.clone()),
        };
        // For node-scoped, the node identity is the callable minus the service
        // suffix (consistent with how measurements key per provider); for the
        // shared-name convention it is `node` directly.
        let node_name = match self.convention {
            NamingConvention::NodeScoped => strip_suffix(&announced, svc),
            NamingConvention::ForwardingHint => node.clone(),
        };
        self.sd.publish(ServiceRecord::new(announced, node_name));
        serve
    }
}
