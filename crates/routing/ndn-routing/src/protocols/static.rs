//! Static routing protocol — installs pre-configured routes at startup
//! under `origin::STATIC` (255). Routes are permanent (no expiry) and
//! flushed from the RIB on `RoutingManager::disable`.

use ndn_mgmt_wire::control_parameters::{origin, route_flags};
use ndn_engine::observability::targets as t;
use ndn_engine::{RibRoute, RoutingHandle, RoutingProtocol, RoutingProtocolStatus};
use ndn_packet::Name;
use ndn_transport::FaceId;
use tokio_util::sync::CancellationToken;
use tracing::info;

#[derive(Clone, Debug)]
pub struct StaticRoute {
    pub prefix: Name,
    pub face_id: FaceId,
    /// Lower is preferred.
    pub cost: u32,
}

/// Per NDN convention, static routes use `origin::STATIC` (255) — the
/// highest origin — and therefore lose to dynamically-learned routes
/// from NLSR/DVR when costs are equal.
pub struct StaticProtocol {
    routes: Vec<StaticRoute>,
}

impl StaticProtocol {
    pub fn new(routes: Vec<StaticRoute>) -> Self {
        Self { routes }
    }
}

impl RoutingProtocol for StaticProtocol {
    fn origin(&self) -> u64 {
        origin::STATIC
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn status(&self) -> RoutingProtocolStatus {
        let mut s = RoutingProtocolStatus::empty(origin::STATIC);
        s.counters
            .insert("nRoutes".to_owned(), self.routes.len() as u64);
        s
    }

    fn start(&self, handle: RoutingHandle, cancel: CancellationToken) -> ndn_runtime::TaskHandle {
        let routes = self.routes.clone();
        tokio::spawn(async move {
            for route in &routes {
                handle.rib.add(
                    &route.prefix,
                    RibRoute {
                        face_id: route.face_id,
                        origin: origin::STATIC,
                        cost: route.cost,
                        flags: route_flags::CHILD_INHERIT,
                        expires_at: None,
                    },
                );
                handle.rib.apply_to_fib(&route.prefix, &handle.fib);
                info!(
                    target: t::ROUTING_STATIC,
                    prefix = %route.prefix,
                    face_id = route.face_id.0,
                    cost = route.cost,
                    "static route installed"
                );
            }
            cancel.cancelled().await;
        })
        .into()
    }
}
