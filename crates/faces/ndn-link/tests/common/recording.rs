//! A forwarder's [`FaceSink`] that remembers what the links gave it
//! (`tests/joiner.rs`): the engine's own [`EngineFaces`], every route and face
//! removal recorded in order, so a case asserts on the routes the link layer
//! installed and removed, not on a FIB the test could have filled itself.

use ndn_engine::ForwarderEngine;
use ndn_link::policy::JOINED_ROUTE_COST;
use ndn_link::{EngineFaces, FaceSink, Route};
use ndn_packet::Name;
use ndn_transport::{Face, FaceId};
use parking_lot::Mutex;
use tokio_util::sync::CancellationToken;

/// One call the links made on the forwarder that changes its routes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Call {
    AddRoutes(FaceId, Vec<Route>),
    RemoveRoutes(FaceId, Vec<Name>),
    RemoveFace(FaceId),
}

/// [`EngineFaces`], recording its route and face removals.
pub struct Recording {
    engine: EngineFaces,
    calls: Mutex<Vec<Call>>,
}

impl Recording {
    pub fn new(engine: ForwarderEngine) -> Recording {
        Recording {
            engine: EngineFaces(engine),
            calls: Mutex::new(Vec::new()),
        }
    }

    /// Every call so far, in order.
    pub fn calls(&self) -> Vec<Call> {
        self.calls.lock().clone()
    }

    /// The prefixes the links ever gave any face at the joiner's cost, sorted,
    /// once each.
    pub fn ever_joined(&self) -> Vec<Name> {
        let mut out: Vec<Name> = Vec::new();
        for call in self.calls.lock().iter() {
            if let Call::AddRoutes(_, routes) = call {
                for r in routes.iter().filter(|r| r.cost == JOINED_ROUTE_COST) {
                    if !out.contains(&r.prefix) {
                        out.push(r.prefix.clone());
                    }
                }
            }
        }
        out.sort();
        out
    }

    /// The joiner's routes in force now, as the calls say: `(face, prefix)`
    /// sorted by face, then prefix. A route removed, or a face removed, is
    /// not in force.
    pub fn joined_now(&self) -> Vec<(FaceId, Name)> {
        let mut now: Vec<(FaceId, Name)> = Vec::new();
        for call in self.calls.lock().iter() {
            match call {
                Call::AddRoutes(f, routes) => {
                    for r in routes.iter().filter(|r| r.cost == JOINED_ROUTE_COST) {
                        if !now.contains(&(*f, r.prefix.clone())) {
                            now.push((*f, r.prefix.clone()));
                        }
                    }
                }
                Call::RemoveRoutes(f, prefixes) => {
                    now.retain(|(face, prefix)| *face != *f || !prefixes.contains(prefix));
                }
                Call::RemoveFace(f) => now.retain(|(face, _)| *face != *f),
            }
        }
        now.sort_by(|a, b| (a.0.0, &a.1).cmp(&(b.0.0, &b.1)));
        now
    }

    /// Whether the links removed `prefix` from `face` with `remove_routes`.
    pub fn removed_route(&self, face: FaceId, prefix: &Name) -> bool {
        self.calls.lock().iter().any(|c| {
            matches!(c, Call::RemoveRoutes(f, prefixes) if *f == face && prefixes.contains(prefix))
        })
    }

    /// Whether the links removed `face`.
    pub fn removed_face(&self, face: FaceId) -> bool {
        self.calls
            .lock()
            .iter()
            .any(|c| matches!(c, Call::RemoveFace(f) if *f == face))
    }
}

impl FaceSink for Recording {
    fn alloc_face_id(&self) -> FaceId {
        self.engine.alloc_face_id()
    }

    fn add_face(&self, face: Face, cancel: CancellationToken) {
        self.engine.add_face(face, cancel);
    }

    fn remove_face(&self, face: FaceId) {
        self.calls.lock().push(Call::RemoveFace(face));
        self.engine.remove_face(face);
    }

    fn add_routes(&self, face: FaceId, routes: &[Route]) {
        self.calls
            .lock()
            .push(Call::AddRoutes(face, routes.to_vec()));
        self.engine.add_routes(face, routes);
    }

    fn remove_routes(&self, face: FaceId, prefixes: &[Name]) {
        self.calls
            .lock()
            .push(Call::RemoveRoutes(face, prefixes.to_vec()));
        self.engine.remove_routes(face, prefixes);
    }

    fn routes_to(&self, face: FaceId) -> bool {
        self.engine.routes_to(face)
    }

    fn transit(&self, namespace: &Name, served: bool) {
        self.engine.transit(namespace, served);
    }
}
