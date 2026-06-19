#![cfg(feature = "discovery")]
//! Engine-wired cross-node discovery: two **separate** `ServiceDiscoveryProtocol`
//! instances discover each other over a wire, driven by a minimal host loop
//! (the role the `ndn-engine` plays in production: tick the protocol, provide a
//! `DiscoveryContext`, route `send_on` bytes between nodes). Node A advertises a
//! service via the real `ServiceDiscoveryDirectory`; node B discovers it through
//! the protocol's own tick-driven browse → rendezvous, not a shared instance.

use std::sync::{Arc, Mutex};
use std::time::Instant;

use bytes::Bytes;
use ndn_discovery::{
    DiscoveryContext, DiscoveryProtocol, FaceLifecycleContext, InboundMeta, MacAddr,
    NeighborContext, NeighborEntry, NeighborState, NeighborTableView, NeighborUpdate, ProtocolId,
    RoutingTableContext, ServiceDiscoveryProtocol,
};
use ndn_packet::Name;
use ndn_service::{ProviderDirectory, ServiceDiscoveryDirectory};
use ndn_service_core::ServiceId;
use ndn_transport::{Face, FaceId};

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

/// Each node's single face to its peer.
const LINK: FaceId = FaceId(1);

/// A neighbor table listing one reachable peer over [`LINK`].
struct PeerTable {
    peer: Name,
}
impl PeerTable {
    fn entry(&self) -> NeighborEntry {
        let mut e = NeighborEntry::new(self.peer.clone());
        e.state = NeighborState::Established { last_seen: Instant::now() };
        e.faces.push((LINK, MacAddr([0u8; 6]), "link".into()));
        e
    }
}
impl NeighborTableView for PeerTable {
    fn get(&self, name: &Name) -> Option<NeighborEntry> {
        (name == &self.peer).then(|| self.entry())
    }
    fn all(&self) -> Vec<NeighborEntry> {
        vec![self.entry()]
    }
    fn face_for_peer(&self, _mac: &MacAddr, _iface: &str) -> Option<FaceId> {
        Some(LINK)
    }
}

/// The host's `DiscoveryContext`: lists the peer, captures `send_on` into an
/// outbox the host routes to the peer's `on_inbound`. FIB/face hooks are no-ops.
struct HostCtx {
    peer: Name,
    outbox: Mutex<Vec<Bytes>>,
}
impl HostCtx {
    fn new(peer: Name) -> Self {
        Self { peer, outbox: Mutex::new(Vec::new()) }
    }
    fn drain(&self) -> Vec<Bytes> {
        self.outbox.lock().unwrap().drain(..).collect()
    }
}
impl FaceLifecycleContext for HostCtx {
    fn alloc_face_id(&self) -> FaceId {
        LINK
    }
    fn add_face(&self, _: Arc<Face>) -> FaceId {
        LINK
    }
    fn remove_face(&self, _: FaceId) {}
}
impl RoutingTableContext for HostCtx {
    fn add_fib_entry(&self, _: &Name, _: FaceId, _: u32, _: ProtocolId) {}
    fn remove_fib_entry(&self, _: &Name, _: FaceId, _: ProtocolId) {}
    fn remove_fib_entries_by_owner(&self, _: ProtocolId) {}
}
impl NeighborContext for HostCtx {
    fn neighbors(&self) -> Arc<dyn NeighborTableView> {
        Arc::new(PeerTable { peer: self.peer.clone() })
    }
    fn update_neighbor(&self, _: NeighborUpdate) {}
}
impl DiscoveryContext for HostCtx {
    fn send_on(&self, _face: FaceId, pkt: Bytes) {
        self.outbox.lock().unwrap().push(pkt);
    }
    fn now(&self) -> Instant {
        Instant::now()
    }
}

#[tokio::test]
async fn two_nodes_discover_a_service_over_the_wire() {
    // Two independent protocol instances + their host contexts (peers of each other).
    let a = Arc::new(ServiceDiscoveryProtocol::with_defaults(n("/site/a")));
    let b = Arc::new(ServiceDiscoveryProtocol::with_defaults(n("/site/b")));
    let a_ctx = HostCtx::new(n("/site/b"));
    let b_ctx = HostCtx::new(n("/site/a"));

    // Node A advertises a service through the real SD-backed directory.
    let svc = ServiceId::new(n("/svc/echo"));
    ServiceDiscoveryDirectory::new(a.clone()).advertise(&svc, &n("/p1")).await;

    // Host loop: tick both (their own browse fires), route each node's send_on
    // bytes to the peer's on_inbound. A's browse → B answers (empty); B's browse
    // → A answers with a rendezvous carrying A's record → B learns it.
    let meta = InboundMeta::none();
    for _ in 0..6 {
        let now = Instant::now();
        a.on_tick(now, &a_ctx);
        b.on_tick(now, &b_ctx);
        for pkt in a_ctx.drain() {
            b.on_inbound(&pkt, LINK, &meta, &b_ctx);
        }
        for pkt in b_ctx.drain() {
            a.on_inbound(&pkt, LINK, &meta, &a_ctx);
        }
    }

    // Node B discovered A's advertised service over the wire (its directory sees it).
    let providers = ServiceDiscoveryDirectory::new(b.clone()).providers(&svc).await;
    let callables: Vec<String> = providers.iter().map(|e| e.callable.to_string()).collect();
    assert!(
        callables.iter().any(|c| c == "/p1/svc/echo"),
        "B must discover A's service via cross-node browse, saw: {callables:?}"
    );
}
