//! Pluggable neighbor and service discovery implementations.
//!
//! Re-exports the trait shapes from `ndn-discovery-core` and adds the
//! native protocols:
//!
//! - [`autoconfig`] — NDN AutoConfig hub discovery (multicast + NDN-FCH)
//! - [`probe`] — per-neighbor liveness probe
//! - [`ether_nd`] — Ethernet wrapper around [`probe`]
//! - [`service_discovery`] — NDNSD-style announce + browse with
//!   optional body encryption

#![allow(missing_docs)]

pub use ndn_discovery_core::{backoff, context, mac_addr, neighbor, no_discovery, protocol, scope};

pub mod autoconfig;
pub mod composite;
pub mod config;
#[cfg(all(feature = "ether-nd", target_os = "linux"))]
pub mod ether_nd;
#[cfg(feature = "mgmt")]
pub mod mgmt;
pub mod prefix_announce;
pub mod probe;
pub mod service_discovery;
pub mod strategy;
pub mod wire;

pub use autoconfig::{AutoConfigDiscovery, build_hub_data, build_hub_discovery_interest};
pub use composite::CompositeDiscovery;
pub use config::{
    DiscoveryConfig, DiscoveryProfile, DiscoveryScope, HelloStrategyKind, PrefixAnnouncementMode,
    DigestSigner, DigestVerifier, KeyedVerifier, RecordSigner, RecordVerifier, ServiceDiscoveryConfig,
    SignerAdapter, VerifyVerdict,
};
#[cfg(all(feature = "ether-nd", target_os = "linux"))]
pub use ether_nd::EtherNeighborDiscovery;
pub use ndn_discovery_core::{
    BackoffConfig, BackoffState, DiscoveryContext, DiscoveryProtocol, FaceLifecycleContext,
    InboundMeta, LinkAddr, MacAddr, NeighborContext, NeighborEntry, NeighborState, NeighborTable,
    NeighborTableView, NeighborUpdate, NoDiscovery, ProtocolId, RoutingTableContext, global_root,
    gossip_prefix, is_link_local, is_nd_packet, is_sd_packet, localhop_autoconf_hub, mgmt_prefix,
    nd_root, ndn_local, peers_prefix, probe_ping, routing_lsa, routing_prefix, scope_root, sd_root,
    sd_service_info_under, sd_services, sd_services_under, sd_updates, sd_updates_under, site_root,
};
pub use prefix_announce::{
    ServiceRecord, build_browse_interest, build_browse_interest_under, make_body_name,
    make_record_name, make_record_name_under,
};
pub use probe::{NeighborProbeProtocol, build_probe_interest, probe_name_prefix};
pub use service_discovery::encryption::{DecryptError, EncryptError, EncryptionHook, NoEncryption};
pub use service_discovery::{ServiceDiscoveryProtocol, decode_peer_list};
pub use strategy::composite::CompositeStrategy;
pub use strategy::{
    BackoffScheduler, NeighborProbeStrategy, PassiveScheduler, ProbeRequest, ReactiveScheduler,
    TriggerEvent, build_strategy,
};
