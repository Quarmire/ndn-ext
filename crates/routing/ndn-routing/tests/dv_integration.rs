//! G.05 Stage 6g — two-engine integration witness for ndn-dv.
//!
//! Wires two real [`ForwarderEngine`]s via an in-memory bridged
//! face pair (a `MemoryLink`), registers a [`DvProtocol`] on each,
//! and asserts convergence: Adv Sync teaches each router about the
//! other; Pfx Sync propagates locally-announced prefixes.
//!
//! Uses short sync intervals (100 ms) so convergence completes
//! within a sub-second tokio::time::sleep window.

use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use ndn_discovery::neighbor::{NeighborEntry, NeighborState};
use ndn_discovery::{DiscoveryProtocol, MacAddr, NeighborContext, NeighborUpdate};
use ndn_engine::{EngineBuilder, EngineConfig};
use ndn_face::local::InProcFace;
use ndn_packet::Name;
use ndn_routing::protocols::dv::{DvConfig, DvProtocol};
use ndn_transport::{FaceError, FaceId, FaceKind, Transport};
use tokio::sync::mpsc;

// ─── MemoryLink — in-memory engine↔engine Face ──────────────────────────────

/// One end of an in-memory bidirectional face pair. Implements
/// [`Face`] so it can be installed in an `EngineBuilder` via
/// `face(...)`. Sends bytes through its tx channel; the matched end
/// reads them through its rx channel. Test-only.
struct MemoryLink {
    id: FaceId,
    rx: tokio::sync::Mutex<mpsc::Receiver<Bytes>>,
    tx: mpsc::Sender<Bytes>,
}

impl MemoryLink {
    /// Create a linked pair. Bytes sent on `a` arrive at `b.recv()`
    /// and vice versa.
    fn pair(id_a: FaceId, id_b: FaceId, buffer: usize) -> (MemoryLink, MemoryLink) {
        let (a_to_b_tx, a_to_b_rx) = mpsc::channel(buffer);
        let (b_to_a_tx, b_to_a_rx) = mpsc::channel(buffer);
        (
            MemoryLink {
                id: id_a,
                rx: tokio::sync::Mutex::new(b_to_a_rx),
                tx: a_to_b_tx,
            },
            MemoryLink {
                id: id_b,
                rx: tokio::sync::Mutex::new(a_to_b_rx),
                tx: b_to_a_tx,
            },
        )
    }
}

impl Transport for MemoryLink {
    fn id(&self) -> FaceId {
        self.id
    }
    fn kind(&self) -> FaceKind {
        // Treat as a local-scope face so the pipeline doesn't try
        // to LP-encode/decode the bytes (the link carries raw NDN
        // packets just like an InProcFace).
        FaceKind::App
    }
    async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
        self.rx.lock().await.recv().await.ok_or(FaceError::Closed)
    }
    async fn send_bytes(&self, pkt: Bytes) -> Result<(), FaceError> {
        self.tx.send(pkt).await.map_err(|_| FaceError::Closed)
    }
}

// ─── Engine + DvProtocol bring-up helper ────────────────────────────────────

struct DvEngine {
    engine: Arc<ndn_engine::ForwarderEngine>,
    shutdown: ndn_engine::ShutdownHandle,
    dv: Arc<DvProtocol>,
    /// FaceId of the MemoryLink end this engine owns; the test uses
    /// it to seed the NeighborTable and to bind the FIB nexthop.
    link_face_id: FaceId,
}

fn name(s: &str) -> Name {
    Name::from_str(s).expect("valid name")
}

/// Construct an engine + DvProtocol pair from a fresh face triple
/// (link, fetch, produce). The link face is what's exchanged
/// between the two test engines; the fetch/produce InProcHandles
/// stay inside DvProtocol for Consumer/Producer wiring.
///
/// `trust = None` uses [`ndn_routing::protocols::dv::signing::InsecureTrust`]
/// (the `DigestSha256` default). `Some(_)` wires a custom
/// [`DvTrust`](`ndn_routing::protocols::dv::signing::DvTrust`) — e.g.
/// `StaticTrust` for the Stage 5b witness or `LvsTrust` for 5c.
async fn build_dv_engine(
    router_name: &str,
    boot: u64,
    link_face: MemoryLink,
    link_face_id: FaceId,
    fetch_face_id: FaceId,
    produce_face_id: FaceId,
    trust: Option<ndn_routing::protocols::dv::signing::DvTrustHandle>,
) -> DvEngine {
    let (fetch_face, fetch_handle) = InProcFace::new(fetch_face_id, 256);
    let (produce_face, produce_handle) = InProcFace::new(produce_face_id, 256);

    let mut cfg = DvConfig::new(name("/ndn"), name(router_name), boot);
    // Short intervals so the test converges within sub-second.
    cfg.adv_sync_interval = Duration::from_millis(100);
    cfg.pfx_sync_interval = Duration::from_millis(100);
    // Keep dead-interval long so neighbours aren't killed mid-test.
    cfg.router_dead_interval = Duration::from_secs(60);

    let dv = match trust {
        None => DvProtocol::with_io(cfg, fetch_handle, produce_handle, produce_face_id),
        Some(t) => {
            DvProtocol::with_io_and_trust(cfg, fetch_handle, produce_handle, produce_face_id, t)
        }
    };

    let mut builder = EngineBuilder::new(EngineConfig::default())
        .face(link_face)
        .face(fetch_face)
        .face(produce_face);
    builder.register_discovery(Arc::clone(&dv) as Arc<dyn DiscoveryProtocol>);
    builder.register_routing_protocol(Arc::clone(&dv) as Arc<dyn ndn_engine::RoutingProtocol>);
    let (engine, shutdown) = builder.build().await.expect("engine build");

    DvEngine {
        engine: Arc::new(engine),
        shutdown,
        dv,
        link_face_id,
    }
}

/// Seed the engine's `NeighborTable` with `peer_router_name`
/// reachable via `link_face_id`. DvProtocol's `on_tick` reads from
/// this table to know who to fan-out sync to. No bootstrap FIB
/// install is needed — Stage 6h makes `DvProtocol::on_inbound`
/// install the per-peer `/localhop/<peer>/DV/ADV` entry on first
/// sync receipt.
fn seed_neighbor(engine: &DvEngine, peer_router_name: &str) {
    let mut entry = NeighborEntry::new(name(peer_router_name));
    entry.state = NeighborState::Established {
        last_seen: Instant::now(),
    };
    entry
        .faces
        .push((engine.link_face_id, MacAddr::new([0; 6]), String::new()));
    engine
        .engine
        .discovery_ctx()
        .update_neighbor(NeighborUpdate::Upsert(entry));
}

// ─── Convergence cases ──────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn adv_sync_two_routers_learn_each_other() {
    let (link_a, link_b) = MemoryLink::pair(FaceId(100), FaceId(200), 256);

    let r1 = build_dv_engine(
        "/r1",
        1000,
        link_a,
        FaceId(100),
        FaceId(101),
        FaceId(102),
        None,
    )
    .await;
    let r2 = build_dv_engine(
        "/r2",
        2000,
        link_b,
        FaceId(200),
        FaceId(201),
        FaceId(202),
        None,
    )
    .await;
    seed_neighbor(&r1, "/r2");
    seed_neighbor(&r2, "/r1");

    // Advance each router's seq so the sync state vector carries a
    // non-trivial seq for the peer to consume.
    r1.dv.sync().advance_seq();
    r2.dv.sync().advance_seq();

    // Wait for convergence — sync emits every 100 ms; allow several
    // round-trips for the Adv Data fetch leg too.
    tokio::time::sleep(Duration::from_millis(2500)).await;

    // Each DvSync should now have a tracked seq for the other peer.
    assert_eq!(
        r1.dv.sync().neighbor_seq(&name("/r2")),
        Some((2000, 1)),
        "r1's view of r2's (boot, seq)",
    );
    assert_eq!(
        r2.dv.sync().neighbor_seq(&name("/r1")),
        Some((1000, 1)),
        "r2's view of r1's (boot, seq)",
    );

    // Each DvRib should have a route to the other router (cost = 1,
    // the LOCAL_COST per SPEC.md §4 update processing, since the
    // peer's self-entry is at cost 0).
    let r1_best = r1.dv.rib().best_route(&name("/r2"));
    assert!(
        r1_best.is_some(),
        "r1 should have a route to /r2 after Adv convergence",
    );
    assert_eq!(r1_best.as_ref().unwrap().neighbor, name("/r2"));
    assert_eq!(r1_best.unwrap().cost, 1);

    let r2_best = r2.dv.rib().best_route(&name("/r1"));
    assert!(r2_best.is_some(), "r2 should have a route to /r1");
    assert_eq!(r2_best.unwrap().cost, 1);

    r1.shutdown.shutdown().await;
    r2.shutdown.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pfx_sync_propagates_local_announcement() {
    let (link_a, link_b) = MemoryLink::pair(FaceId(300), FaceId(400), 256);

    let r1 = build_dv_engine(
        "/r1",
        1000,
        link_a,
        FaceId(300),
        FaceId(301),
        FaceId(302),
        None,
    )
    .await;
    let r2 = build_dv_engine(
        "/r2",
        2000,
        link_b,
        FaceId(400),
        FaceId(401),
        FaceId(402),
        None,
    )
    .await;
    seed_neighbor(&r1, "/r2");
    seed_neighbor(&r2, "/r1");

    // Bring up Adv Sync first so each router learns about the other.
    r1.dv.sync().advance_seq();
    r2.dv.sync().advance_seq();
    tokio::time::sleep(Duration::from_millis(2500)).await;

    // r1 announces /shop. Manually advance pfx seq so the next
    // Pfx Sync emission carries the new state vector. (Stage 6d's
    // snapshot-only mode: peers fetch our snap() on advance.)
    r1.dv.prefix_table().announce_local(name("/shop"), 1);
    r1.dv.pfx_sync().advance_seq();

    // Wait for Pfx Sync round-trip.
    tokio::time::sleep(Duration::from_millis(2500)).await;

    // r2's PrefixTable should now contain /shop announced by /r1.
    let routers = r2.dv.prefix_table().routers_for_prefix(&name("/shop"));
    assert_eq!(
        routers,
        vec![(name("/r1"), 1)],
        "r2 should have learned that /r1 announces /shop",
    );

    r1.shutdown.shutdown().await;
    r2.shutdown.shutdown().await;
}

/// Stage 5a + 5b witness — both engines sign with Ed25519 *and*
/// verify the peer's signature against a pre-shared
/// [`StaticTrust`] public-key registry. End-to-end convergence
/// proves:
///
/// 1. (5a) outgoing path encodes Ed25519-signed inner Data,
/// 2. (5b) receive path runs `StaticTrust::validate` and accepts
///    the peer's wire because the KeyLocator name resolves in
///    `trusted_keys` and the signature crypto checks out.
///
/// If 5b were broken (validate dropping the packet), `process_sync_interest`
/// would return an empty `SyncReceipt` and the peer's seq would
/// never enter our `DvSync` — the `neighbor_seq` assert would
/// fail with `None`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ed25519_signed_routers_converge() {
    use ndn_routing::protocols::dv::signing::StaticTrust;
    use ndn_security::{Ed25519Signer, Signer};

    let r1_key = name("/ndn/r1/KEY/dv");
    let r2_key = name("/ndn/r2/KEY/dv");

    let r1_signer = Arc::new(Ed25519Signer::from_seed(&[1u8; 32], r1_key.clone()));
    let r2_signer = Arc::new(Ed25519Signer::from_seed(&[2u8; 32], r2_key.clone()));

    let r1_public = r1_signer
        .public_key()
        .expect("Ed25519Signer exposes its public key");
    let r2_public = r2_signer
        .public_key()
        .expect("Ed25519Signer exposes its public key");

    // r1 signs with r1's key; trusts r2's key for incoming.
    let r1_trust = StaticTrust::new(Some(r1_signer.clone() as Arc<dyn Signer>))
        .trust_key(r2_key.clone(), r2_public.clone())
        .handle();
    let r2_trust = StaticTrust::new(Some(r2_signer.clone() as Arc<dyn Signer>))
        .trust_key(r1_key.clone(), r1_public.clone())
        .handle();

    let (link_a, link_b) = MemoryLink::pair(FaceId(500), FaceId(600), 256);

    let r1 = build_dv_engine(
        "/r1",
        1000,
        link_a,
        FaceId(500),
        FaceId(501),
        FaceId(502),
        Some(r1_trust),
    )
    .await;
    let r2 = build_dv_engine(
        "/r2",
        2000,
        link_b,
        FaceId(600),
        FaceId(601),
        FaceId(602),
        Some(r2_trust),
    )
    .await;
    seed_neighbor(&r1, "/r2");
    seed_neighbor(&r2, "/r1");

    r1.dv.sync().advance_seq();
    r2.dv.sync().advance_seq();
    tokio::time::sleep(Duration::from_millis(2500)).await;

    assert_eq!(
        r1.dv.sync().neighbor_seq(&name("/r2")),
        Some((2000, 1)),
        "r1 must track r2's seq across the Ed25519-signed sync wire",
    );
    assert_eq!(r2.dv.sync().neighbor_seq(&name("/r1")), Some((1000, 1)),);
    assert!(
        r1.dv.rib().best_route(&name("/r2")).is_some(),
        "Adv Data fetch over Ed25519-signed wire must apply to the RIB",
    );
    assert!(r2.dv.rib().best_route(&name("/r1")).is_some());

    r1.shutdown.shutdown().await;
    r2.shutdown.shutdown().await;
}

/// Stage 5b negative witness — a router signing with an *unknown*
/// key cannot inject state into a peer that only trusts the legit
/// key set. The forged Sync Interests still arrive on the link face,
/// but `StaticTrust::validate` drops them because the attacker's
/// KeyLocator name isn't in `trusted_keys`. `DvSync.neighbor_seq` on
/// the victim stays `None`; no FIB or RIB state moves.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forged_signed_peer_is_rejected_by_static_trust() {
    use ndn_routing::protocols::dv::signing::StaticTrust;
    use ndn_security::{Ed25519Signer, Signer};

    let legit_key = name("/ndn/r1/KEY/dv");
    let legit_signer = Arc::new(Ed25519Signer::from_seed(&[1u8; 32], legit_key.clone()));
    let legit_public = legit_signer.public_key().unwrap();

    // The attacker uses /attacker/KEY/evil — not in r2's
    // trusted_keys.
    let evil_signer = Arc::new(Ed25519Signer::from_seed(
        &[9u8; 32],
        name("/attacker/KEY/evil"),
    ));

    let attacker_trust = StaticTrust::new(Some(evil_signer.clone() as Arc<dyn Signer>)).handle();
    // r2 trusts only the legit key. Receiving a packet signed by the
    // attacker (with KeyLocator naming the attacker's key) hits the
    // trusted-keys lookup miss and gets dropped.
    let victim_trust = StaticTrust::new(Some(legit_signer.clone() as Arc<dyn Signer>))
        .trust_key(legit_key, legit_public)
        .handle();

    let (link_a, link_b) = MemoryLink::pair(FaceId(700), FaceId(800), 256);

    let attacker = build_dv_engine(
        "/r1",
        1000,
        link_a,
        FaceId(700),
        FaceId(701),
        FaceId(702),
        Some(attacker_trust),
    )
    .await;
    let victim = build_dv_engine(
        "/r2",
        2000,
        link_b,
        FaceId(800),
        FaceId(801),
        FaceId(802),
        Some(victim_trust),
    )
    .await;
    seed_neighbor(&attacker, "/r2");
    seed_neighbor(&victim, "/r1");

    attacker.dv.sync().advance_seq();
    victim.dv.sync().advance_seq();
    tokio::time::sleep(Duration::from_millis(2500)).await;

    // Victim must NOT have learned the forged sequence.
    assert_eq!(
        victim.dv.sync().neighbor_seq(&name("/r1")),
        None,
        "victim must reject forged Sync Interests at validate()",
    );
    assert!(
        victim.dv.rib().best_route(&name("/r1")).is_none(),
        "no RIB state should move under a rejected wire",
    );

    attacker.shutdown.shutdown().await;
    victim.shutdown.shutdown().await;
}
