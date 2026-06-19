//! NAN service discovery → NDN routes.
//!
//! [`NanDiscovery`] is a [`DiscoveryProtocol`] that turns NAN publish/subscribe
//! matches into FIB routes: when a peer advertising a subscribed service is
//! seen, a route for the bound NDN coordination prefix is installed toward the
//! NAN coordination face. This is the headline NDN-alignment of Wi-Fi Aware —
//! name-based service discovery in silicon feeding the forwarder's route table.
//!
//! NAN service names hash to opaque service IDs and cannot be reversed to an NDN
//! name, so the service↔prefix binding is configured: [`discover`](NanDiscovery::discover)
//! says "subscribe to service S, and route prefix P toward the cluster when a
//! peer offering S appears." [`advertise`](NanDiscovery::advertise) is the dual
//! (publish S so peers discover this node).

use std::sync::Arc;
use std::time::Instant;

use ndn_discovery_core::{DiscoveryContext, DiscoveryProtocol, InboundMeta, ProtocolId};
use ndn_packet::Name;
use ndn_transport::{FaceError, FaceId};

use crate::{NanBackend, NanServiceName};

/// FIB-owner tag for routes this protocol installs (so they are cleaned up
/// together when the coordination face goes down).
const NAN_PROTO: ProtocolId = ProtocolId("nan-discovery");

/// Installs NDN routes from NAN service matches. Construct with [`new`](Self::new),
/// declare subscriptions/advertisements with [`discover`](Self::discover) /
/// [`advertise`](Self::advertise) (async — they call the backend), then register
/// it as the engine's discovery protocol. Routes for matched prefixes are
/// installed toward `coord_face` on each tick.
pub struct NanDiscovery {
    backend: Arc<dyn NanBackend>,
    /// The NAN coordination face matched prefixes route toward.
    coord_face: FaceId,
    /// Subscribed service → NDN prefix to route when a peer offering it appears.
    bindings: Vec<(NanServiceName, Name)>,
    /// Empty — `NanDiscovery` installs routes, it does not intercept packets.
    claimed: Vec<Name>,
    cost: u32,
}

impl NanDiscovery {
    /// New discovery driver over `backend`, routing matched prefixes toward the
    /// NAN coordination face `coord_face` (typically the same backend's
    /// [`NanCoordFace`](crate::NanCoordFace)).
    pub fn new(backend: Arc<dyn NanBackend>, coord_face: FaceId) -> Self {
        Self {
            backend,
            coord_face,
            bindings: Vec::new(),
            claimed: Vec::new(),
            cost: 0,
        }
    }

    /// Cost for installed routes (default 0).
    pub fn cost(mut self, cost: u32) -> Self {
        self.cost = cost;
        self
    }

    /// Subscribe to NAN service `service` and, when a peer advertising it is
    /// matched, install a route for `prefix` toward the coordination face.
    pub async fn discover(
        mut self,
        service: impl Into<NanServiceName>,
        prefix: impl Into<Name>,
    ) -> Result<Self, FaceError> {
        let service = service.into();
        self.backend.subscribe(&service).await?;
        self.bindings.push((service, prefix.into()));
        Ok(self)
    }

    /// Advertise NAN service `service` so peers discover this node.
    pub async fn advertise(self, service: impl Into<NanServiceName>) -> Result<Self, FaceError> {
        self.backend.publish(&service.into()).await?;
        Ok(self)
    }
}

impl DiscoveryProtocol for NanDiscovery {
    fn protocol_id(&self) -> ProtocolId {
        NAN_PROTO
    }

    fn claimed_prefixes(&self) -> &[Name] {
        &self.claimed
    }

    fn on_face_up(&self, _face_id: FaceId, _ctx: &dyn DiscoveryContext) {}

    fn on_face_down(&self, face_id: FaceId, ctx: &dyn DiscoveryContext) {
        // The coordination face is gone — drop the routes that pointed at it.
        if face_id == self.coord_face {
            ctx.remove_fib_entries_by_owner(NAN_PROTO);
        }
    }

    fn on_inbound(
        &self,
        _raw: &bytes::Bytes,
        _incoming_face: FaceId,
        _meta: &InboundMeta,
        _ctx: &dyn DiscoveryContext,
    ) -> bool {
        // Route-install only; never consumes packets.
        false
    }

    fn on_tick(&self, _now: Instant, ctx: &dyn DiscoveryContext) {
        for m in self.backend.drain_matches() {
            if let Some((_, prefix)) = self.bindings.iter().find(|(s, _)| *s == m.service) {
                tracing::debug!(
                    %prefix,
                    peer = ?m.peer,
                    "NAN match → installing route toward coordination face"
                );
                ctx.add_fib_entry(prefix, self.coord_face, self.cost, NAN_PROTO);
            }
        }
    }
}
