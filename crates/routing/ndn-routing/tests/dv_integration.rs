//! G.05 Stage 6g — multi-engine integration witness for ndn-dv.
//!
//! Wires real [`ForwarderEngine`]s via in-memory bridged face pairs
//! (`MemoryLink`s), registers a [`DvProtocol`] on each, and asserts
//! convergence: Adv Sync teaches each router about the others, also
//! beyond its neighbours; Pfx Sync propagates locally-announced prefixes.
//!
//! Uses short sync intervals (100 ms; emitted at each 1 s tick) so
//! convergence completes within a few seconds.

use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
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
    /// Shared by both ends: once set, the link drops everything sent.
    cut: Arc<AtomicBool>,
}

impl MemoryLink {
    /// Create a linked pair. Bytes sent on `a` arrive at `b.recv()`
    /// and vice versa.
    fn pair(id_a: FaceId, id_b: FaceId, buffer: usize) -> (MemoryLink, MemoryLink) {
        let (a_to_b_tx, a_to_b_rx) = mpsc::channel(buffer);
        let (b_to_a_tx, b_to_a_rx) = mpsc::channel(buffer);
        let cut = Arc::new(AtomicBool::new(false));
        (
            MemoryLink {
                id: id_a,
                rx: tokio::sync::Mutex::new(b_to_a_rx),
                tx: a_to_b_tx,
                cut: Arc::clone(&cut),
            },
            MemoryLink {
                id: id_b,
                rx: tokio::sync::Mutex::new(a_to_b_rx),
                tx: b_to_a_tx,
                cut,
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
        if self.cut.load(Ordering::Relaxed) {
            return Ok(());
        }
        self.tx.send(pkt).await.map_err(|_| FaceError::Closed)
    }
}

// ─── Engine + DvProtocol bring-up helper ────────────────────────────────────

struct DvEngine {
    engine: Arc<ndn_engine::ForwarderEngine>,
    shutdown: ndn_engine::ShutdownHandle,
    dv: Arc<DvProtocol>,
    /// FaceId of the first MemoryLink end this engine owns; the test
    /// uses it to seed the NeighborTable and to bind the FIB nexthop.
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
/// `trust = None` uses [`ndn_routing::protocols::dv::signing::DvInsecure`]
/// (the `DigestSha256` default). `Some(_)` wires a custom
/// [`DvTrust`](`ndn_routing::protocols::dv::signing::DvTrust`) — e.g.
/// `DvStaticKeys` for the Stage 5b witness or `DvLvs` for 5c.
async fn build_dv_engine(
    router_name: &str,
    boot: u64,
    link_face: MemoryLink,
    fetch_face_id: FaceId,
    produce_face_id: FaceId,
    trust: Option<ndn_routing::protocols::dv::signing::DvTrustHandle>,
) -> DvEngine {
    // Keep dead-interval long so neighbours aren't killed mid-test.
    build_router(
        router_name,
        boot,
        vec![link_face],
        fetch_face_id,
        produce_face_id,
        trust,
        Duration::from_secs(60),
    )
    .await
}

/// [`build_dv_engine`] for a router owning every end in `links`, whose
/// neighbours are dropped after `router_dead_interval` of silence.
async fn build_router(
    router_name: &str,
    boot: u64,
    links: Vec<MemoryLink>,
    fetch_face_id: FaceId,
    produce_face_id: FaceId,
    trust: Option<ndn_routing::protocols::dv::signing::DvTrustHandle>,
    router_dead_interval: Duration,
) -> DvEngine {
    let (fetch_face, fetch_handle) = InProcFace::new(fetch_face_id, 256);
    let (produce_face, produce_handle) = InProcFace::new(produce_face_id, 256);

    let mut cfg = DvConfig::new(name("/ndn"), name(router_name), boot);
    // Short intervals so the test converges quickly.
    cfg.adv_sync_interval = Duration::from_millis(100);
    cfg.pfx_sync_interval = Duration::from_millis(100);
    cfg.router_dead_interval = router_dead_interval;

    let dv = match trust {
        None => DvProtocol::with_io(cfg, fetch_handle, produce_handle, produce_face_id),
        Some(t) => {
            DvProtocol::with_io_and_trust(cfg, fetch_handle, produce_handle, produce_face_id, t)
        }
    };

    let link_face_id = links.first().expect("a router has a link").id;
    let mut builder = EngineBuilder::new(EngineConfig::default());
    for link in links {
        builder = builder.face(link);
    }
    let mut builder = builder.face(fetch_face).face(produce_face);
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
    seed_neighbor_on(engine, peer_router_name, engine.link_face_id);
}

/// [`seed_neighbor`] reachable via `face`.
fn seed_neighbor_on(engine: &DvEngine, peer_router_name: &str, face: FaceId) {
    let mut entry = NeighborEntry::new(name(peer_router_name));
    entry.state = NeighborState::Established {
        last_seen: Instant::now(),
    };
    entry
        .faces
        .push((face, MacAddr::new([0; 6]), String::new()));
    engine
        .engine
        .discovery_ctx()
        .update_neighbor(NeighborUpdate::Upsert(entry));
}

// ─── Convergence cases ──────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn adv_sync_two_routers_learn_each_other() {
    let (link_a, link_b) = MemoryLink::pair(FaceId(100), FaceId(200), 256);

    let r1 = build_dv_engine("/r1", 1000, link_a, FaceId(101), FaceId(102), None).await;
    let r2 = build_dv_engine("/r2", 2000, link_b, FaceId(201), FaceId(202), None).await;
    seed_neighbor(&r1, "/r2");
    seed_neighbor(&r2, "/r1");

    // Sync emits at each 1 s tick; each router publishes a new
    // advertisement once it learns the other, which the other fetches.
    assert!(
        eventually(Duration::from_secs(10), || knows(&r1, &r2)
            && knows(&r2, &r1))
        .await,
        "each router tracks the other's current (boot, seq)",
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

    let r1 = build_dv_engine("/r1", 1000, link_a, FaceId(301), FaceId(302), None).await;
    let r2 = build_dv_engine("/r2", 2000, link_b, FaceId(401), FaceId(402), None).await;
    seed_neighbor(&r1, "/r2");
    seed_neighbor(&r2, "/r1");

    // Bring up Adv Sync first so each router learns about the other.
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

/// Poll `cond` until it holds or `within` elapses; whether it held.
async fn eventually(within: Duration, cond: impl Fn() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + within;
    while tokio::time::Instant::now() < deadline {
        if cond() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    cond()
}

/// Whether `a` tracks `b`'s current `(boot, seq)` and has a route to it.
fn knows(a: &DvEngine, b: &DvEngine) -> bool {
    let b_name = &b.dv.config().router;
    a.dv.sync().neighbor_seq(b_name) == Some((b.dv.config().boot, b.dv.sync().current_seq()))
        && a.dv.rib().best_route(b_name).is_some()
}

/// The nexthops `engine`'s FIB holds for exactly `prefix`, as `(face, cost)`.
fn fib_hops(engine: &DvEngine, prefix: &Name) -> Vec<(FaceId, u32)> {
    engine
        .engine
        .fib()
        .dump()
        .into_iter()
        .filter(|(name, _)| name == prefix)
        .flat_map(|(_, entry)| {
            entry
                .nexthops
                .iter()
                .map(|h| (h.face_id, h.cost))
                .collect::<Vec<_>>()
        })
        .collect()
}

/// A prefix an app registers on r1 (`rib/register`, origin app) is
/// readvertised: DV announces it, so r2 learns r1 serves it. When the app's
/// face goes down, the RIB withdraws it and r2 forgets it — no manual
/// `announce_local`, the production path end to end.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn registered_prefix_is_advertised_and_withdrawn_with_its_face() {
    use ndn_engine::rib::RibRoute;

    let (link_a, link_b) = MemoryLink::pair(FaceId(500), FaceId(600), 256);
    let r1 = build_dv_engine("/r1", 1000, link_a, FaceId(501), FaceId(502), None).await;
    let r2 = build_dv_engine("/r2", 2000, link_b, FaceId(601), FaceId(602), None).await;
    seed_neighbor(&r1, "/r2");
    seed_neighbor(&r2, "/r1");

    // What rib/register does for an app on face 509.
    let app_face = FaceId(509);
    let shop = name("/shop");
    let rib = r1.engine.rib();
    rib.add(
        &shop,
        RibRoute {
            face_id: app_face,
            origin: 0,
            cost: 0,
            flags: 0,
            expires_at: None,
        },
    );
    rib.readvertise_announce(&shop, 0);

    let learned = || r2.dv.prefix_table().routers_for_prefix(&shop);
    assert!(
        eventually(Duration::from_secs(10), || learned()
            == vec![(name("/r1"), 0)])
        .await,
        "r2 should learn that /r1 announces /shop, got {:?}",
        learned()
    );

    // The app's face goes down (it crashed): the RIB drops its routes and
    // withdraws the prefix from DV.
    rib.handle_face_down(app_face, &r1.engine.fib());
    assert!(
        eventually(Duration::from_secs(10), || learned().is_empty()).await,
        "r2 should forget /shop once r1 withdraws it, got {:?}",
        learned()
    );

    r1.shutdown.shutdown().await;
    r2.shutdown.shutdown().await;
}

/// Stage 5a + 5b witness — both engines sign with Ed25519 *and*
/// verify the peer's signature against a pre-shared
/// [`DvStaticKeys`] public-key registry. End-to-end convergence
/// proves:
///
/// 1. (5a) outgoing path encodes Ed25519-signed inner Data,
/// 2. (5b) receive path runs `DvStaticKeys::validate` and accepts
///    the peer's wire because the KeyLocator name resolves in
///    `trusted_keys` and the signature crypto checks out.
///
/// If 5b were broken (validate dropping the packet), `process_sync_interest`
/// would return an empty `SyncReceipt` and the peer's seq would
/// never enter our `DvSync` — the `neighbor_seq` assert would
/// fail with `None`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ed25519_signed_routers_converge() {
    use ndn_routing::protocols::dv::signing::DvStaticKeys;
    use ndn_security::{ActiveSigner, Ed25519Signer, Signer};

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
    let r1_trust = DvStaticKeys::new(Some(Arc::new(ActiveSigner::new(r1_signer.clone()))))
        .trust_key(r2_key.clone(), r2_public.clone())
        .handle();
    let r2_trust = DvStaticKeys::new(Some(Arc::new(ActiveSigner::new(r2_signer.clone()))))
        .trust_key(r1_key.clone(), r1_public.clone())
        .handle();

    let (link_a, link_b) = MemoryLink::pair(FaceId(500), FaceId(600), 256);

    let r1 = build_dv_engine(
        "/r1",
        1000,
        link_a,
        FaceId(501),
        FaceId(502),
        Some(r1_trust),
    )
    .await;
    let r2 = build_dv_engine(
        "/r2",
        2000,
        link_b,
        FaceId(601),
        FaceId(602),
        Some(r2_trust),
    )
    .await;
    seed_neighbor(&r1, "/r2");
    seed_neighbor(&r2, "/r1");

    assert!(
        eventually(Duration::from_secs(10), || knows(&r1, &r2)
            && knows(&r2, &r1))
        .await,
        "each router must track the other's seq across the Ed25519-signed sync wire",
    );
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
/// but `DvStaticKeys::validate` drops them because the attacker's
/// KeyLocator name isn't in `trusted_keys`. `DvSync.neighbor_seq` on
/// the victim stays `None`; no FIB or RIB state moves.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forged_signed_peer_is_rejected_by_static_trust() {
    use ndn_routing::protocols::dv::signing::DvStaticKeys;
    use ndn_security::{ActiveSigner, Ed25519Signer, Signer};

    let legit_key = name("/ndn/r1/KEY/dv");
    let legit_signer = Arc::new(Ed25519Signer::from_seed(&[1u8; 32], legit_key.clone()));
    let legit_public = legit_signer.public_key().unwrap();

    // The attacker uses /attacker/KEY/evil — not in r2's
    // trusted_keys.
    let evil_signer = Arc::new(Ed25519Signer::from_seed(
        &[9u8; 32],
        name("/attacker/KEY/evil"),
    ));

    let attacker_trust =
        DvStaticKeys::new(Some(Arc::new(ActiveSigner::new(evil_signer.clone())))).handle();
    // r2 trusts only the legit key. Receiving a packet signed by the
    // attacker (with KeyLocator naming the attacker's key) hits the
    // trusted-keys lookup miss and gets dropped.
    let victim_trust = DvStaticKeys::new(Some(Arc::new(ActiveSigner::new(legit_signer.clone()))))
        .trust_key(legit_key, legit_public)
        .handle();

    let (link_a, link_b) = MemoryLink::pair(FaceId(700), FaceId(800), 256);

    let attacker = build_dv_engine(
        "/r1",
        1000,
        link_a,
        FaceId(701),
        FaceId(702),
        Some(attacker_trust),
    )
    .await;
    let victim = build_dv_engine(
        "/r2",
        2000,
        link_b,
        FaceId(801),
        FaceId(802),
        Some(victim_trust),
    )
    .await;
    seed_neighbor(&attacker, "/r2");
    seed_neighbor(&victim, "/r1");

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

/// A line r1 – r2 – r3. r1 learns r3 through r2, two hops away, and routes
/// r3's registered prefix via r2 at cost 2: r2 re-advertises once it has
/// learned r3. When the r2–r3 link fails, r2 drops r3 and re-advertises,
/// and r1 forgets r3 and the prefix's route.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn routes_beyond_a_neighbour_follow_its_advertisements() {
    use ndn_engine::rib::RibRoute;
    use ndn_routing::protocols::dv::rib::BestRoute;

    let (l12, l21) = MemoryLink::pair(FaceId(1100), FaceId(1200), 256);
    let (l23, l32) = MemoryLink::pair(FaceId(1201), FaceId(1300), 256);
    let cut_23 = Arc::clone(&l23.cut);
    // Sync goes out at every 1 s tick, so a neighbour silent for 3 s is gone.
    let dead = Duration::from_secs(3);
    let r1 = build_router(
        "/r1",
        1000,
        vec![l12],
        FaceId(1101),
        FaceId(1102),
        None,
        dead,
    )
    .await;
    let r2 = build_router(
        "/r2",
        2000,
        vec![l21, l23],
        FaceId(1202),
        FaceId(1203),
        None,
        dead,
    )
    .await;
    let r3 = build_router(
        "/r3",
        3000,
        vec![l32],
        FaceId(1301),
        FaceId(1302),
        None,
        dead,
    )
    .await;
    seed_neighbor_on(&r1, "/r2", FaceId(1100));
    seed_neighbor_on(&r2, "/r1", FaceId(1200));
    seed_neighbor_on(&r2, "/r3", FaceId(1201));
    seed_neighbor_on(&r3, "/r2", FaceId(1300));

    // What rib/register does for an app on r3's face 1309.
    let shop = name("/shop");
    let r3_rib = r3.engine.rib();
    r3_rib.add(
        &shop,
        RibRoute {
            face_id: FaceId(1309),
            origin: 0,
            cost: 0,
            flags: 0,
            expires_at: None,
        },
    );
    r3_rib.readvertise_announce(&shop, 0);

    let to_r3 = || r1.dv.rib().best_route(&name("/r3"));
    let via_r2 = Some(BestRoute {
        neighbor: name("/r2"),
        cost: 2,
    });
    assert!(
        eventually(Duration::from_secs(15), || to_r3() == via_r2
            && fib_hops(&r1, &shop) == vec![(FaceId(1100), 2)])
        .await,
        "r1 should reach r3 and /shop via r2 at cost 2, got {:?} and {:?}",
        to_r3(),
        fib_hops(&r1, &shop),
    );

    cut_23.store(true, Ordering::Relaxed);
    assert!(
        eventually(Duration::from_secs(30), || to_r3().is_none()
            && fib_hops(&r1, &shop).is_empty())
        .await,
        "r1 should forget r3 and /shop once r2 loses r3, got {:?} and {:?}",
        to_r3(),
        fib_hops(&r1, &shop),
    );

    for r in [r1, r2, r3] {
        r.shutdown.shutdown().await;
    }
}
