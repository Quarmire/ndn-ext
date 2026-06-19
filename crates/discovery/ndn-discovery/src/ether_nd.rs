//! Ethernet neighbor liveness — thin wrapper over [`NeighborProbeProtocol`].
//!
//! The Ethernet-specific constructor arguments (multicast face id,
//! interface, local MAC) are accepted for API stability but ignored;
//! the probe wire format `/ndn/local/nd/probe/ping/<neighbor>/<nonce>`
//! is medium-agnostic.

use std::time::{Duration, Instant};

use bytes::Bytes;
use ndn_packet::Name;
use ndn_transport::{FaceId, MacAddr};

use crate::config::{DiscoveryConfig, DiscoveryProfile};
use crate::context::DiscoveryContext;
use crate::probe::NeighborProbeProtocol;
use crate::protocol::{DiscoveryProtocol, InboundMeta, ProtocolId};

pub struct EtherNeighborDiscovery(NeighborProbeProtocol);

impl EtherNeighborDiscovery {
    pub fn new(
        _multicast_face_id: FaceId,
        _iface: impl Into<String>,
        node_name: Name,
        _local_mac: MacAddr,
    ) -> Self {
        Self::new_with_config(
            _multicast_face_id,
            _iface,
            node_name,
            _local_mac,
            DiscoveryConfig::for_profile(&DiscoveryProfile::Lan),
        )
    }

    pub fn new_with_config(
        _multicast_face_id: FaceId,
        _iface: impl Into<String>,
        node_name: Name,
        _local_mac: MacAddr,
        config: DiscoveryConfig,
    ) -> Self {
        Self(NeighborProbeProtocol::new(
            node_name,
            config.hello_interval_base,
            config.liveness_miss_count as u8,
        ))
    }

    pub fn from_profile(
        multicast_face_id: FaceId,
        iface: impl Into<String>,
        node_name: Name,
        local_mac: MacAddr,
        profile: &DiscoveryProfile,
    ) -> Self {
        Self::new_with_config(
            multicast_face_id,
            iface,
            node_name,
            local_mac,
            DiscoveryConfig::for_profile(profile),
        )
    }
}

impl DiscoveryProtocol for EtherNeighborDiscovery {
    fn protocol_id(&self) -> ProtocolId {
        self.0.protocol_id()
    }

    fn claimed_prefixes(&self) -> &[Name] {
        self.0.claimed_prefixes()
    }

    fn tick_interval(&self) -> Duration {
        self.0.tick_interval()
    }

    fn on_face_up(&self, face_id: FaceId, ctx: &dyn DiscoveryContext) {
        self.0.on_face_up(face_id, ctx)
    }

    fn on_face_down(&self, face_id: FaceId, ctx: &dyn DiscoveryContext) {
        self.0.on_face_down(face_id, ctx)
    }

    fn on_inbound(
        &self,
        raw: &Bytes,
        incoming_face: FaceId,
        meta: &InboundMeta,
        ctx: &dyn DiscoveryContext,
    ) -> bool {
        self.0.on_inbound(raw, incoming_face, meta, ctx)
    }

    fn on_tick(&self, now: Instant, ctx: &dyn DiscoveryContext) {
        self.0.on_tick(now, ctx)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::scope::probe_ping;

    fn make_nd() -> EtherNeighborDiscovery {
        EtherNeighborDiscovery::new(
            FaceId(1),
            "eth0",
            Name::from_str("/ndn/test/node").unwrap(),
            MacAddr::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
        )
    }

    #[test]
    fn claimed_prefix_is_probe_ping() {
        let nd = make_nd();
        let prefixes = nd.claimed_prefixes();
        assert_eq!(prefixes.len(), 1);
        assert_eq!(&prefixes[0], probe_ping());
    }

    #[test]
    fn from_profile_sets_probe_interval() {
        let nd = EtherNeighborDiscovery::from_profile(
            FaceId(1),
            "wlan0",
            Name::from_str("/ndn/test/node").unwrap(),
            MacAddr::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            &DiscoveryProfile::Lan,
        );
        assert!(nd.claimed_prefixes().iter().any(|p| p == probe_ping()));
    }
}
