//! [`FaceSink`] over an ndn-rs [`ForwarderEngine`]: what a host embedding
//! the engine (a forwarder daemon, a mobile app) gives [`Links`](crate::Links)
//! for its faces and routes.

use ndn_engine::ForwarderEngine;
use ndn_engine::rib::RibRoute;
use ndn_mgmt_wire::control_parameters::{origin, route_flags};
use ndn_packet::Name;
use ndn_transport::{Face, FaceId, FacePersistency};
use tokio_util::sync::CancellationToken;

use crate::host::{FaceSink, Route};

/// The engine: link faces as persistent faces, their routes as static RIB
/// routes that cover the names under them.
#[derive(Clone)]
pub struct EngineFaces(pub ForwarderEngine);

impl FaceSink for EngineFaces {
    fn alloc_face_id(&self) -> FaceId {
        self.0.faces().alloc_id()
    }

    fn add_face(&self, face: Face, cancel: CancellationToken) {
        self.0.add_composed_face(face, cancel, FacePersistency::Persistent);
    }

    fn remove_face(&self, face: FaceId) {
        self.0.remove_face(face);
    }

    fn add_routes(&self, face: FaceId, routes: &[Route]) {
        let rib = self.0.rib();
        let fib = self.0.fib();
        for route in routes {
            rib.add(
                &route.prefix,
                RibRoute {
                    face_id: face,
                    origin: origin::STATIC,
                    cost: route.cost,
                    flags: route_flags::CHILD_INHERIT,
                    expires_at: None,
                },
            );
            rib.apply_to_fib(&route.prefix, &fib);
        }
    }

    fn remove_routes(&self, face: FaceId, prefixes: &[Name]) {
        let rib = self.0.rib();
        let fib = self.0.fib();
        for prefix in prefixes {
            if rib.remove(prefix, face, origin::STATIC) {
                rib.apply_to_fib(prefix, &fib);
            }
        }
    }

    fn transit(&self, namespace: &Name, served: bool) {
        let transit = self.0.transit();
        if served {
            transit.add(namespace);
        } else {
            transit.remove(namespace);
        }
    }
}
