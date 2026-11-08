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
/// routes that cover the names under them. While a namespace is in transit
/// it runs the namespace's sync group with the multicast strategy
/// ([`ndn_namespace::sync_group::carry`]), so its devices linked here
/// reach each other in it; the last transit of it ends that
/// ([`ndn_namespace::sync_group::release`], which leaves a namespace the
/// engine holds as the trust-context library set it).
#[derive(Clone)]
pub struct EngineFaces(pub ForwarderEngine);

impl FaceSink for EngineFaces {
    fn alloc_face_id(&self) -> FaceId {
        self.0.faces().alloc_id()
    }

    fn add_face(&self, face: Face, cancel: CancellationToken) {
        self.0
            .add_composed_face(face, cancel, FacePersistency::Persistent);
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
            transit.add(namespace, || {
                ndn_namespace::sync_group::carry(&self.0, namespace);
            });
        } else {
            transit.remove(namespace, || {
                ndn_namespace::sync_group::release(&self.0, namespace);
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ndn_engine::{EngineBuilder, EngineConfig};
    use ndn_security::{SecurityManager, SignedTrustContext};

    use super::*;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    /// The strategy set at exactly `prefix`, by name.
    fn strategy_at(engine: &ForwarderEngine, prefix: &str) -> Option<String> {
        engine
            .strategy_table()
            .dump()
            .into_iter()
            .find(|(p, _)| *p == n(prefix))
            .map(|(_, s)| s.name().to_string())
    }

    /// A served namespace's group runs with multicast from its first
    /// transit to its last; a held namespace's keeps the strategy the
    /// trust-context library gave it.
    #[tokio::test]
    async fn a_namespace_in_transit_runs_its_group_with_multicast_until_the_last_transit_ends() {
        let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
            .security(Arc::new(SecurityManager::new()))
            .build()
            .await
            .unwrap();
        let faces = EngineFaces(engine.clone());
        let visitor = n("/visitor");
        faces.transit(&visitor, true);
        faces.transit(&visitor, true);
        let multicast = strategy_at(&engine, "/visitor/32=sync").expect("a strategy");
        assert!(multicast.contains("multicast"), "{multicast}");
        faces.transit(&visitor, false);
        assert_eq!(
            strategy_at(&engine, "/visitor/32=sync"),
            Some(multicast.clone())
        );
        faces.transit(&visitor, false);
        assert_eq!(strategy_at(&engine, "/visitor/32=sync"), None);

        let home = n("/home");
        let keyring = engine.keyring().expect("the engine validates");
        keyring
            .adopt(Arc::new(SignedTrustContext::hierarchical(home.clone())))
            .unwrap();
        ndn_namespace::sync_group::carry(&engine, &home);
        faces.transit(&home, true);
        faces.transit(&home, false);
        assert_eq!(strategy_at(&engine, "/home/32=sync"), Some(multicast));
        shutdown.shutdown().await;
    }
}
