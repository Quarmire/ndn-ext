//! The link lifecycle of an embedded host (ndn-rs `ndn-link.md` §17D), on real
//! QUIC links between real devices of one namespace: going offline and online,
//! the listening port a device keeps and takes again, a peer that cannot be
//! reached at all, and a listening host whose address changes.
//!
//! Every device is on this machine, on a loopback address of its own where a
//! case needs to tell them apart. Nothing here asserts a time as correctness:
//! the bounds are the limits of `within` (a case that waits for what the layer
//! must do) and, for what must not happen, a span checked as often as `within`
//! looks (a count of datagrams that stays zero).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use ndn_app::{Consumer, EngineAppExt, Node};
use ndn_engine::{EngineBuilder, EngineConfig, ForwarderEngine, ShutdownHandle};
use ndn_face_quic::{KeyFingerprint, LinkEndpoint, LinkKey, LinkKeySource, LinkTransportConfig};
use ndn_link::EngineFaces;
use ndn_link::{
    AddressSource, AddressWatch, ConfiguredEndpoints, FaceSink, HostCandidates, LinkMemory,
    LinkSetup, LinkState, LinkTrust, Links, MemoryFuture, MemoryOptions, Next, PeerRecord,
    PeerSpec, RelaySource, RelayUse, RememberedState, Route, link_code,
};
use ndn_packet::Name;
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_security::{
    Certificate, Ed25519Signer, Keyring, SecurityManager, SecurityProfile, SignedTrustContext,
    Signer,
};
use ndn_transport::{Face, FaceId, FaceKind};
use parking_lot::Mutex;
use tokio_util::sync::CancellationToken;

const NS: &str = "/home";

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

// ---- the namespace and its devices -------------------------------------------------------------

/// The namespace: its root key and signed trust context (default link policy:
/// members link and get direct paths, `node` devices relay).
struct Home {
    root: SecurityManager,
    root_key: Name,
    context: Arc<SignedTrustContext>,
}

impl Home {
    fn new() -> Self {
        let root = SecurityManager::new();
        let root_key = n(&format!("{NS}/KEY/root"));
        root.generate_ed25519(root_key.clone()).unwrap();
        let signer = root.get_signer_sync(&root_key).unwrap();
        let anchor = root
            .issue_self_signed(&root_key, signer.public_key().unwrap(), u64::MAX)
            .unwrap();
        let context = SignedTrustContext::hierarchical(n(NS)).with_version(1);
        context.add_anchor(anchor);
        Self {
            root,
            root_key,
            context: Arc::new(context),
        }
    }

    async fn certify(&self, key_name: &Name, public_key: Bytes) -> Certificate {
        self.root
            .certify_as(
                key_name,
                public_key,
                &self.root_key,
                3_600_000,
                ndn_security::cert_name::NDNCERT_ISSUER,
                None,
            )
            .await
            .unwrap()
    }
}

struct Trust {
    keyring: Arc<Keyring>,
    chain: Vec<Bytes>,
}

impl LinkTrust for Trust {
    fn keyring(&self) -> &Arc<Keyring> {
        &self.keyring
    }
    fn own_chain(&self) -> Vec<Bytes> {
        self.chain.clone()
    }
    fn known_certificate(&self, _: &Name) -> Option<Certificate> {
        None
    }
    fn known_certificate_of_key(&self, _: &KeyFingerprint) -> Option<Certificate> {
        None
    }
}

/// The faces a device's links add, as its forwarder would run them.
#[derive(Default)]
struct Recorder {
    next: AtomicU64,
    live: Mutex<Vec<FaceId>>,
    faces: Mutex<Vec<Arc<Face>>>,
}

impl Recorder {
    /// The newest link face still up, if any.
    fn newest_link(&self) -> Option<Arc<Face>> {
        let live = self.live.lock();
        self.faces
            .lock()
            .iter()
            .rev()
            .find(|f| f.kind() == FaceKind::Quic && live.contains(&f.id()))
            .cloned()
    }

    fn live_links(&self) -> usize {
        self.live.lock().len()
    }
}

impl FaceSink for Recorder {
    fn alloc_face_id(&self) -> FaceId {
        FaceId(self.next.fetch_add(1, Ordering::SeqCst) + 1)
    }
    fn add_face(&self, face: Face, _: CancellationToken) {
        if face.kind() == FaceKind::Quic {
            self.live.lock().push(face.id());
        }
        self.faces.lock().push(Arc::new(face));
    }
    fn remove_face(&self, face: FaceId) {
        self.live.lock().retain(|f| *f != face);
    }
    fn add_routes(&self, _: FaceId, _: &[Route]) {}
    fn remove_routes(&self, _: FaceId, _: &[Name]) {}
    fn routes_to(&self, _: FaceId) -> bool {
        false
    }
    fn transit(&self, _: &Name, _: bool) {}
}

/// A link memory in a map that records what was written of the port.
#[derive(Default)]
struct Shelf {
    records: Mutex<HashMap<KeyFingerprint, PeerRecord>>,
    port: Mutex<Option<u16>>,
    port_writes: Mutex<Vec<Option<u16>>>,
}

impl Shelf {
    fn with(records: Vec<PeerRecord>) -> Arc<Shelf> {
        let shelf = Shelf::default();
        shelf
            .records
            .lock()
            .extend(records.into_iter().map(|r| (r.key, r)));
        Arc::new(shelf)
    }

    fn get(&self, key: &KeyFingerprint) -> Option<PeerRecord> {
        self.records.lock().get(key).cloned()
    }
}

impl LinkMemory for Shelf {
    fn load(&self) -> Result<Vec<PeerRecord>, String> {
        Ok(self.records.lock().values().cloned().collect())
    }
    fn save<'a>(&'a self, record: &'a PeerRecord) -> MemoryFuture<'a, Result<(), String>> {
        Box::pin(async move {
            self.records.lock().insert(record.key, record.clone());
            Ok(())
        })
    }
    fn remove<'a>(&'a self, key: &'a KeyFingerprint) -> MemoryFuture<'a, Result<(), String>> {
        Box::pin(async move {
            self.records.lock().remove(key);
            Ok(())
        })
    }
    fn load_listen_port(&self) -> Result<Option<u16>, String> {
        Ok(*self.port.lock())
    }
    fn save_listen_port<'a>(&'a self, port: Option<u16>) -> MemoryFuture<'a, Result<(), String>> {
        Box::pin(async move {
            self.port_writes.lock().push(port);
            *self.port.lock() = port;
            Ok(())
        })
    }
}

/// A set of addresses a case changes by hand: what the address watcher reads.
struct ManualAddresses(Mutex<Vec<IpAddr>>);

impl ManualAddresses {
    fn new(addrs: &[&str]) -> Arc<Self> {
        Arc::new(Self(Mutex::new(
            addrs.iter().map(|a| a.parse().unwrap()).collect(),
        )))
    }

    fn set(&self, addrs: &[&str]) {
        *self.0.lock() = addrs.iter().map(|a| a.parse().unwrap()).collect();
    }
}

impl AddressSource for ManualAddresses {
    fn addresses(&self) -> Vec<IpAddr> {
        self.0.lock().clone()
    }
}

/// A UDP socket nothing answers from: it counts the datagrams (QUIC
/// Initials) sent to it.
struct Bait {
    socket: UdpSocket,
}

impl Bait {
    fn new() -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        Self { socket }
    }

    fn addr(&self) -> SocketAddr {
        self.socket.local_addr().unwrap()
    }

    /// Datagrams that arrived since the last call.
    fn seen(&self) -> usize {
        let mut buf = [0u8; 2048];
        let mut count = 0;
        while self.socket.recv_from(&mut buf).is_ok() {
            count += 1;
        }
        count
    }
}

/// What a device on a forwarder of its own has besides its links: an app node
/// to produce and fetch with. (Punches and the data of a link cross the
/// forwarder: a recording `FaceSink` carries neither.)
struct Engined {
    node: Node,
    signer: Arc<Ed25519Signer>,
    _engine: ForwarderEngine,
    _shutdown: ShutdownHandle,
}

/// A device alone with its links: its faces recorded, or on a forwarder.
struct Dev {
    links: Arc<Links>,
    faces: Arc<Recorder>,
    key: KeyFingerprint,
    addr: SocketAddr,
    endpoint: Arc<LinkEndpoint>,
    cancel: CancellationToken,
    name: Name,
    engined: Option<Engined>,
}

impl Drop for Dev {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

fn transport() -> LinkTransportConfig {
    LinkTransportConfig {
        // An address where nothing answers fails in a second, not five.
        handshake_timeout: Duration::from_secs(1),
        ..LinkTransportConfig::default()
    }
}

/// The fingerprint of the key a device of `seed` links with.
fn fingerprint_of(seed: u8) -> KeyFingerprint {
    LinkKey::from_signer(Arc::new(Ed25519Signer::from_seed(
        &[seed; 32],
        n("/x/KEY/k"),
    )))
    .unwrap()
    .fingerprint()
}

/// `/home/member/<name>`, listening at `bind`, linking with `peers`.
async fn dev(home: &Home, name: &str, seed: u8, bind: &str, peers: Vec<PeerSpec>) -> Dev {
    dev_as(home, "member", name, seed, bind, peers).await
}

async fn dev_as(
    home: &Home,
    role: &str,
    name: &str,
    seed: u8,
    bind: &str,
    peers: Vec<PeerSpec>,
) -> Dev {
    build(home, role, name, seed, bind, peers, false).await
}

/// A member on a forwarder of its own.
async fn dev_engine(home: &Home, name: &str, seed: u8, bind: &str, peers: Vec<PeerSpec>) -> Dev {
    build(home, "member", name, seed, bind, peers, true).await
}

async fn build(
    home: &Home,
    role: &str,
    name: &str,
    seed: u8,
    bind: &str,
    peers: Vec<PeerSpec>,
    engine: bool,
) -> Dev {
    let device = n(&format!("{NS}/{role}/{name}"));
    let key_name = n(&format!("{NS}/{role}/{name}/KEY/k{seed}"));
    let signer = Arc::new(Ed25519Signer::from_seed(&[seed; 32], key_name.clone()));
    let cert = home.certify(&key_name, signer.public_key().unwrap()).await;
    let key = LinkKey::from_signer(Arc::clone(&signer) as Arc<dyn Signer>).unwrap();
    let fingerprint = key.fingerprint();
    let keyring = Arc::new(Keyring::new());
    keyring.adopt(Arc::clone(&home.context)).unwrap();
    let transport = transport();
    let key: Arc<dyn LinkKeySource> = Arc::new(key);
    let endpoint = Arc::new(
        LinkEndpoint::bind(bind.parse().unwrap(), Arc::clone(&key), &transport, true).unwrap(),
    );
    let addr = endpoint.local_addr().unwrap();
    let faces = Arc::new(Recorder::default());
    let (sink, engined): (Arc<dyn FaceSink>, Option<Engined>) = if engine {
        let (forwarder, shutdown) = EngineBuilder::new(EngineConfig::default())
            .security_profile(SecurityProfile::Disabled)
            .build()
            .await
            .unwrap();
        let node = forwarder.app_node(CancellationToken::new());
        (
            Arc::new(EngineFaces(forwarder.clone())),
            Some(Engined {
                node,
                signer: Arc::clone(&signer),
                _engine: forwarder,
                _shutdown: shutdown,
            }),
        )
    } else {
        (Arc::clone(&faces) as Arc<dyn FaceSink>, None)
    };
    let cancel = CancellationToken::new();
    let links = Links::start(
        LinkSetup {
            peers,
            key,
            trust: Arc::new(Trust {
                keyring,
                chain: vec![cert.data_wire().unwrap()],
            }),
            faces: sink,
            paths: Arc::new(ConfiguredEndpoints),
            // Devices on one machine: loopback host candidates.
            candidates: vec![Arc::new(HostCandidates {
                include_local: true,
            })],
            socket: Some(Arc::clone(&endpoint)),
            transport,
            relays: Default::default(),
            service: Default::default(),
            direct: Default::default(),
        },
        cancel.clone(),
    );
    Dev {
        links,
        faces,
        key: fingerprint,
        addr,
        endpoint,
        cancel,
        name: device,
        engined,
    }
}

/// The options of these cases: every device is on this machine, so the loopback
/// addresses they link at are kept (off by default); a record is written at
/// once.
fn on_this_machine() -> MemoryOptions {
    MemoryOptions {
        include_local: true,
        save_interval: Duration::ZERO,
        ..MemoryOptions::default()
    }
}

/// Ann's peer entry for `to`: dialled at its address, kept dialled.
fn peer_to(to: &Dev) -> PeerSpec {
    PeerSpec {
        label: to.name.to_string(),
        key: Some(to.key),
        device: Some(to.name.clone()),
        endpoints: vec![to.addr.to_string()],
        persistent: true,
        ..PeerSpec::default()
    }
}

/// A record of `of` as a store could hold it: where it was reached, and its
/// listening port.
fn record_of(of: &Dev, addresses: Vec<SocketAddr>, port: Option<u16>) -> PeerRecord {
    PeerRecord {
        key: of.key,
        device: of.name.clone(),
        addresses,
        last_contact: std::time::SystemTime::now(),
        origin: ndn_link::Direction::Dialed,
        port,
    }
}

fn linked(on: &Dev, key: KeyFingerprint) -> bool {
    on.links
        .report()
        .links
        .iter()
        .any(|l| l.key == Some(key) && !l.paths.is_empty())
}

fn holds_no_link(on: &Dev) -> bool {
    on.links.report().links.iter().all(|l| l.paths.is_empty())
}

fn state_of(on: &Dev, key: KeyFingerprint) -> Option<LinkState> {
    on.links
        .watch()
        .current()
        .into_iter()
        .find(|p| p.key == key)
        .map(|p| p.state)
}

fn remembered(on: &Dev, key: KeyFingerprint) -> Option<(PeerRecord, RememberedState)> {
    on.links
        .report()
        .memory
        .expect("the links keep a memory")
        .peers
        .into_iter()
        .find(|p| p.record.key == key)
        .map(|p| (p.record, p.state))
}

/// The port that is free now.
fn free_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn within(what: &str, limit: Duration, mut done: impl FnMut() -> bool) -> Duration {
    let start = Instant::now();
    while !done() {
        assert!(start.elapsed() < limit, "not within {limit:?}: {what}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    start.elapsed()
}

/// `within`, and when it fails the reports of `devs` are in the message.
async fn within_dumping(
    what: &str,
    limit: Duration,
    devs: &[&Dev],
    mut done: impl FnMut() -> bool,
) {
    let start = Instant::now();
    while !done() {
        if start.elapsed() >= limit {
            let reports: Vec<String> = devs
                .iter()
                .map(|d| format!("{}: {:#?}", d.name, d.links.report()))
                .collect();
            panic!("not within {limit:?}: {what}\n{}", reports.join("\n"));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// `holds` stays true for `span`, checked as often as `within` looks: for what
/// must not happen, which no event announces.
async fn throughout(what: &str, span: Duration, mut holds: impl FnMut() -> bool) {
    let start = Instant::now();
    while start.elapsed() < span {
        assert!(holds(), "{what}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

const LONG: Duration = Duration::from_secs(30);

/// The words one device types: an Interest of a name no one has seen, sent
/// over its newest link; whether the other device's newest link received it.
async fn typed(from: &Dev, to: &Dev, counter: &AtomicU64) -> bool {
    let (Some(tx), Some(rx)) = (from.faces.newest_link(), to.faces.newest_link()) else {
        return false;
    };
    let name = format!("/words/{}", counter.fetch_add(1, Ordering::SeqCst));
    let wire = ndn_packet::encode::InterestBuilder::new(n(&name))
        .lifetime(Duration::from_secs(10))
        .build();
    if tx.send_bytes(wire).await.is_err() {
        return false;
    }
    tokio::time::timeout(Duration::from_millis(300), async {
        while let Ok(wire) = rx.recv_bytes().await {
            let wire = if ndn_packet::lp::is_lp_packet(&wire) {
                match ndn_packet::lp::LpPacket::decode(wire) {
                    Ok(lp) => match lp.fragment {
                        Some(fragment) => fragment,
                        None => continue,
                    },
                    Err(_) => continue,
                }
            } else {
                wire
            };
            if ndn_packet::Interest::decode(wire).is_ok_and(|i| i.name.to_string() == name) {
                return true;
            }
        }
        false
    })
    .await
    .unwrap_or(false)
}

/// Words typed at `from` cross to `to`: how long it took, within `limit`.
async fn words_cross(from: &Dev, to: &Dev, limit: Duration) -> Duration {
    let counter = AtomicU64::new(0);
    let start = Instant::now();
    loop {
        if typed(from, to, &counter).await {
            return start.elapsed();
        }
        assert!(
            start.elapsed() < limit,
            "words typed at {} did not cross to {} within {limit:?}",
            from.name,
            to.name
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Two devices, Ann and Bob, linked: Bob dials Ann and each remembers the other.
async fn linked_pair(home: &Home) -> (Dev, Dev, Arc<Shelf>, Arc<Shelf>) {
    let ann = dev(home, "ann", 1, "127.0.0.1:0", Vec::new()).await;
    let bob = dev(home, "bob", 2, "127.0.0.1:0", vec![peer_to(&ann)]).await;
    let (at_ann, at_bob) = (Shelf::with(Vec::new()), Shelf::with(Vec::new()));
    ann.links.remember(at_ann.clone(), on_this_machine());
    bob.links.remember(at_bob.clone(), on_this_machine());
    within("Ann and Bob link", LONG, || {
        linked(&ann, bob.key) && linked(&bob, ann.key)
    })
    .await;
    (ann, bob, at_ann, at_bob)
}

// ---- offline and online ------------------------------------------------------------------------

/// SHAPES-R7 D: offline closes every link and makes no attempt (not even when
/// asked, or when the network changes: a UDP socket that every dial would hit
/// sees nothing), the watcher says why, the peer sees a link closed by the
/// other device (not a grant that ended), and online links the remembered and
/// configured peers again from the same memory.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn offline_closes_every_link_and_makes_no_attempt_and_online_links_the_peers_again() {
    let home = Home::new();
    let bait = Bait::new();
    let ann = dev(&home, "ann", 1, "127.0.0.1:0", Vec::new()).await;
    let ghost = KeyFingerprint([0xEE; 32]);
    let bob = dev(
        &home,
        "bob",
        2,
        "127.0.0.1:0",
        vec![
            peer_to(&ann),
            // A device that does not exist: every dial of it is a datagram to
            // `bait`.
            PeerSpec {
                label: "ghost".into(),
                key: Some(ghost),
                endpoints: vec![bait.addr().to_string()],
                persistent: true,
                ..PeerSpec::default()
            },
        ],
    )
    .await;
    ann.links
        .remember(Shelf::with(Vec::new()), on_this_machine());
    // Bob remembers Ann as well as listing her: a device that dialled a peer of
    // its host's list keeps no record of it, one that links from memory does.
    let at_bob = Shelf::with(vec![record_of(&ann, vec![ann.addr], Some(ann.addr.port()))]);
    bob.links.remember(at_bob.clone(), on_this_machine());
    within("Ann and Bob link", LONG, || {
        linked(&ann, bob.key) && linked(&bob, ann.key)
    })
    .await;
    within("the ghost is dialled while Bob is online", LONG, || {
        bait.seen() > 0
    })
    .await;

    bob.links.set_online(false);
    assert!(!bob.links.is_online());
    within("Bob holds no link", LONG, || holds_no_link(&bob)).await;
    within("Ann's link to Bob ends", LONG, || !linked(&ann, bob.key)).await;
    // What Bob says of Ann: down because of him, and dialled when he is back.
    within("Bob's watch says offline", LONG, || {
        matches!(
            state_of(&bob, ann.key),
            Some(LinkState::Down { why, next: Next::WhenOnline, .. }) if why.code == link_code::OFFLINE
        )
    })
    .await;
    // What Ann sees: the link closed by the other device, in its words.
    match state_of(&ann, bob.key) {
        Some(LinkState::Down { why, .. }) => {
            assert_eq!(why.code, link_code::LINK_CLOSED_BY_PEER, "{why:?}");
            assert!(
                why.text.contains("went offline")
                    || why.params.values().any(|v| v.contains("went offline")),
                "Ann was told why: {why:?}"
            );
        }
        other => panic!("Ann's state of Bob: {other:?}"),
    }
    // What Bob's memory says of Ann.
    within("the memory says offline", LONG, || {
        matches!(
            remembered(&bob, ann.key),
            Some((_, RememberedState::Offline))
        )
    })
    .await;

    // No attempt is made: not when the host asks, not when the network
    // changes. Nothing reaches a socket every dial of the ghost would.
    // A handshake begun before the device went offline ends by its own
    // timeout (1 s here); no new one begins.
    tokio::time::sleep(Duration::from_millis(1600)).await;
    bait.seen();
    for id in bob.links.report().links.iter().filter_map(|l| l.peer) {
        bob.links.connect(id);
    }
    bob.links.network_changed(None);
    throughout(
        "an Initial left an offline device",
        Duration::from_secs(3),
        || bait.seen() == 0,
    )
    .await;

    bob.links.set_online(true);
    assert!(bob.links.is_online());
    within("the ghost is dialled again", LONG, || bait.seen() > 0).await;
    within("Ann and Bob link again, from the same memory", LONG, || {
        linked(&ann, bob.key) && linked(&bob, ann.key)
    })
    .await;
    assert!(
        at_bob.get(&ann.key).is_some(),
        "the memory Bob had kept is the one he links from"
    );
    words_cross(&ann, &bob, LONG).await;
}

/// SHAPES-R7 D: an offline device refuses inbound handshakes before they
/// begin, with no reply of substance: the dialling device gets no answer (its
/// handshake times out) and not a refusal it could read.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_offline_device_answers_no_inbound_attempt_and_takes_no_link() {
    let home = Home::new();
    let bob = dev(&home, "bob", 2, "127.0.0.1:0", Vec::new()).await;
    bob.links
        .remember(Shelf::with(Vec::new()), on_this_machine());
    bob.links.set_online(false);
    let ann = dev(&home, "ann", 1, "127.0.0.1:0", vec![peer_to(&bob)]).await;
    within("Ann's dial of Bob fails", LONG, || {
        matches!(state_of(&ann, bob.key), Some(LinkState::Down { .. }))
    })
    .await;
    match state_of(&ann, bob.key) {
        Some(LinkState::Down { why, .. }) => {
            assert_eq!(
                why.code,
                link_code::LINK_CONNECT,
                "no answer, not a refusal: {why:?}"
            );
            assert!(why.text.contains("no answer"), "{why:?}");
        }
        other => panic!("{other:?}"),
    }
    throughout(
        "an offline device took a link",
        Duration::from_secs(2),
        || holds_no_link(&bob) && bob.faces.live_links() == 0,
    )
    .await;
    bob.links.set_online(true);
    within("Ann dials Bob once he is online", LONG, || {
        linked(&ann, bob.key) && linked(&bob, ann.key)
    })
    .await;
}

/// SHAPES-R7 D: five cycles with the same memory leave no state in the host:
/// the same peers, the same records, one link face each side, one entry per
/// peer in the watcher.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn five_offline_and_online_cycles_with_the_same_memory_keep_no_state_in_the_host() {
    let home = Home::new();
    let (ann, bob, at_ann, _) = linked_pair(&home).await;
    let census = |on: &Dev| {
        let report = on.links.report();
        (
            report.links.len(),
            report.memory.as_ref().map_or(0, |m| m.peers.len()),
            on.links.watch().current().len(),
        )
    };
    let (before_ann, before_bob) = (census(&ann), census(&bob));
    for cycle in 0..5 {
        bob.links.set_online(false);
        within(&format!("cycle {cycle}: Bob holds no link"), LONG, || {
            holds_no_link(&bob)
        })
        .await;
        bob.links.set_online(true);
        within(&format!("cycle {cycle}: linked again"), LONG, || {
            linked(&ann, bob.key) && linked(&bob, ann.key)
        })
        .await;
    }
    words_cross(&bob, &ann, LONG).await;
    assert_eq!(
        census(&ann),
        before_ann,
        "Ann kept something of Bob's cycles"
    );
    assert_eq!(census(&bob), before_bob, "Bob kept something of his cycles");
    within("one link face each side", LONG, || {
        ann.faces.live_links() == 1 && bob.faces.live_links() == 1
    })
    .await;
    assert_eq!(
        at_ann.records.lock().len(),
        1,
        "one record, not one per cycle"
    );
}

/// SHAPES-R7 D: going online wakes every redial at once and they are
/// staggered by `dials_at_once`: with two at once, six unreachable peers are
/// not all dialled in the first moments.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn going_online_redials_a_few_peers_at_a_time() {
    let home = Home::new();
    let baits: Vec<Bait> = (0..6).map(|_| Bait::new()).collect();
    let ann = dev(&home, "ann", 1, "127.0.0.1:0", Vec::new()).await;
    let ghosts: Vec<PeerRecord> = baits
        .iter()
        .enumerate()
        .map(|(i, bait)| PeerRecord {
            key: KeyFingerprint([0x40 + i as u8; 32]),
            device: n(&format!("{NS}/member/ghost{i}")),
            addresses: vec![bait.addr()],
            last_contact: std::time::SystemTime::now(),
            origin: ndn_link::Direction::Dialed,
            port: None,
        })
        .collect();
    ann.links.set_online(false);
    ann.links.remember(
        Shelf::with(ghosts),
        MemoryOptions {
            dials_at_once: 2,
            ..on_this_machine()
        },
    );
    // Offline from the first moment: no record is dialled.
    throughout(
        "a record was dialled offline",
        Duration::from_secs(2),
        || baits.iter().all(|b| b.seen() == 0),
    )
    .await;
    ann.links.set_online(true);
    // The first moments: no more than two are dialled at once.
    tokio::time::sleep(Duration::from_millis(600)).await;
    let first = baits.iter().filter(|b| b.seen() > 0).count();
    assert!(
        (1..=2).contains(&first),
        "{first} of 6 peers were dialled in the first moments, with dials_at_once = 2"
    );
    // And the rest take their turns.
    let mut dialled = first;
    within(
        "every peer is dialled in its turn",
        Duration::from_secs(30),
        || {
            dialled += baits.iter().filter(|b| b.seen() > 0).count();
            dialled >= 6
        },
    )
    .await;
}

// ---- the listening port ------------------------------------------------------------------------

/// SHAPES-R7 D: the kept port is bound again when it is free.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_kept_port_is_bound_again_when_it_is_free() {
    let home = Home::new();
    let ann = dev(&home, "ann", 1, "127.0.0.1:0", Vec::new()).await;
    let first = ann.addr.port();
    let kept = free_port();
    assert_ne!(kept, first);
    let shelf = Shelf::with(Vec::new());
    *shelf.port.lock() = Some(kept);
    ann.links.remember(shelf.clone(), on_this_machine());
    assert_eq!(
        ann.endpoint.local_addr().unwrap(),
        SocketAddr::new(ann.addr.ip(), kept),
        "the socket listens on the kept port again, on the same address"
    );
    ann.links.shutdown().await;
    assert!(
        shelf.port_writes.lock().is_empty(),
        "the kept port is the one in use: nothing to write: {:?}",
        shelf.port_writes.lock()
    );
}

/// SHAPES-R7 D: a kept port that is taken is not bound: the device keeps the
/// port it has, and keeps that.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn another_port_is_used_and_kept_when_the_kept_one_is_taken() {
    let home = Home::new();
    let ann = dev(&home, "ann", 1, "127.0.0.1:0", Vec::new()).await;
    let first = ann.addr.port();
    let taker = UdpSocket::bind("127.0.0.1:0").unwrap();
    let taken = taker.local_addr().unwrap().port();
    let shelf = Shelf::with(Vec::new());
    *shelf.port.lock() = Some(taken);
    ann.links.remember(shelf.clone(), on_this_machine());
    assert_eq!(
        ann.endpoint.local_addr().unwrap().port(),
        first,
        "the port kept is not free: the device keeps listening where it does"
    );
    ann.links.shutdown().await;
    assert_eq!(*shelf.port.lock(), Some(first), "and keeps that one");
    drop(taker);
}

/// SHAPES-R7 D: with nothing kept, the port in use is kept.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_port_in_use_is_kept_when_none_was() {
    let home = Home::new();
    let ann = dev(&home, "ann", 1, "127.0.0.1:0", Vec::new()).await;
    let shelf = Shelf::with(Vec::new());
    ann.links.remember(shelf.clone(), on_this_machine());
    ann.links.shutdown().await;
    assert_eq!(*shelf.port.lock(), Some(ann.addr.port()));
}

/// SHAPES-R7 D: `persist_addresses = false` keeps no port: none is written,
/// the one a run before wrote is removed, and the socket is not moved to it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_port_is_kept_when_the_addresses_are_not() {
    let home = Home::new();
    let ann = dev(&home, "ann", 1, "127.0.0.1:0", Vec::new()).await;
    let first = ann.addr.port();
    let shelf = Shelf::with(Vec::new());
    *shelf.port.lock() = Some(free_port());
    ann.links.remember(
        shelf.clone(),
        MemoryOptions {
            persist_addresses: false,
            ..on_this_machine()
        },
    );
    ann.links.shutdown().await;
    assert_eq!(
        ann.endpoint.local_addr().unwrap().port(),
        first,
        "not moved"
    );
    assert_eq!(
        *shelf.port.lock(),
        None,
        "the one written before is removed"
    );
    assert_eq!(
        *shelf.port_writes.lock(),
        vec![None],
        "and no port was written: {:?}",
        shelf.port_writes.lock()
    );
}

/// SHAPES-R7 D: a kept port of 0 or below 1024 is never a bind target: the
/// device listens where it does (whatever the system allows the user).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_kept_port_below_1024_or_zero_is_not_a_bind_target() {
    for kept in [0u16, 1, 80, 1023] {
        let home = Home::new();
        let ann = dev(&home, "ann", 1, "127.0.0.1:0", Vec::new()).await;
        let first = ann.addr.port();
        let shelf = Shelf::with(Vec::new());
        *shelf.port.lock() = Some(kept);
        ann.links.remember(shelf.clone(), on_this_machine());
        assert_eq!(
            ann.endpoint.local_addr().unwrap().port(),
            first,
            "port {kept} was bound"
        );
        ann.links.shutdown().await;
        assert_eq!(*shelf.port.lock(), Some(first), "kept {kept}, now {first}");
    }
}

/// SHAPES-R7 D: a contact that reports a new IP for a peer that has no
/// address that works is dialled at that IP and the port the record keeps. Ann
/// remembers Bob at an address where he no longer is; Bob dialled her once, once
/// only; Ann is told the one that works by that contact, and dials it when the
/// link is lost.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_new_ip_a_contact_reports_is_dialled_at_the_port_the_record_keeps() {
    let home = Home::new();
    let ann = dev(&home, "ann", 1, "127.0.0.1:0", Vec::new()).await;
    let bob = dev(&home, "bob", 2, "127.0.0.2:0", Vec::new()).await;
    let port = bob.addr.port();
    // Ann's record of Bob: his port, at an IP he has left.
    let shelf = Shelf::with(vec![record_of(
        &bob,
        vec![SocketAddr::new("127.0.0.1".parse().unwrap(), port)],
        Some(port),
    )]);
    ann.links.remember(shelf, on_this_machine());
    // Bob dials Ann once (no redial of his: a peer that is not persistent), as
    // a device that moved would.
    let mut once = peer_to(&ann);
    once.persistent = false;
    bob.links.add_peer(once);
    within("Bob links to Ann", LONG, || {
        linked(&ann, bob.key) && linked(&bob, ann.key)
    })
    .await;
    let (record, _) = remembered(&ann, bob.key).unwrap();
    assert_eq!(
        record.addresses,
        vec![SocketAddr::new("127.0.0.1".parse().unwrap(), port)],
        "an accepted link never changes the addresses kept"
    );
    // The link is lost; Bob does not dial again. Ann dials him: the IP the
    // contact reported, at his port.
    ann.links.set_online(false);
    within("Ann holds no link", LONG, || holds_no_link(&ann)).await;
    ann.links.set_online(true);
    within("Ann links to Bob at the IP he reported", LONG, || {
        linked(&ann, bob.key) && linked(&bob, ann.key)
    })
    .await;
    words_cross(&ann, &bob, LONG).await;
}

/// `a` answers every Interest under its device name with a signed Data.
async fn produce(a: &Dev) -> ndn_app::ServeGuard {
    let e = a.engined.as_ref().expect("a device on a forwarder");
    let signer = Arc::clone(&e.signer);
    e.node
        .serve(a.name.clone(), move |interest, responder| {
            let signer = Arc::clone(&signer);
            async move {
                let wire = DataBuilder::new((*interest.name).clone(), b"words".as_slice())
                    .sign_sync(signer.sig_type(), Some(signer.key_name()), |region| {
                        signer.sign_sync(region).unwrap()
                    });
                let _ = responder.respond_bytes(wire).await;
            }
        })
        .await
        .unwrap()
}

/// `from` fetches `name` (an Interest, and the Data an app of `to` answers it
/// with) within `limit`.
async fn fetch_across(from: &Dev, name: &Name, limit: Duration) {
    let mut consumer = Consumer::new(from.engined.as_ref().unwrap().node.connection());
    let start = Instant::now();
    loop {
        let got = consumer
            .fetch_with(InterestBuilder::new(name.clone()).lifetime(Duration::from_secs(2)))
            .await;
        if got.is_ok() {
            return;
        }
        assert!(
            start.elapsed() < limit,
            "{} fetched {name} within {limit:?}: no ({:?})",
            from.name,
            got.err()
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// SHAPES-R7 D: two devices that both restart on new ports, each holding the
/// other's old port, and both linked to a relay they use, exchange an Interest
/// and its Data again (the relay carries it) and are never reported without a
/// path; the punch by membership then makes a direct path at the new ports,
/// and each record holds the port the other listens on now.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn devices_that_restarted_on_new_ports_find_each_other_through_a_relay() {
    let home = Home::new();
    let relay = build(&home, "node", "relay", 1, "127.0.0.1:0", Vec::new(), true).await;
    let to_relay = |relay: &Dev| PeerSpec {
        label: "relay".into(),
        device: Some(relay.name.clone()),
        endpoints: vec![relay.addr.to_string()],
        persistent: true,
        relay_use: Some(RelayUse {
            source: RelaySource::User,
            preference: 0,
        }),
        ..Default::default()
    };
    let ann = dev_engine(&home, "ann", 2, "127.0.0.1:0", vec![to_relay(&relay)]).await;
    let bob = dev_engine(&home, "bob", 3, "127.0.0.1:0", vec![to_relay(&relay)]).await;
    // Each kept the other's old port: nothing listens there now.
    let (old_ann, old_bob) = (free_port(), free_port());
    let at = |port: u16| vec![SocketAddr::from(([127, 0, 0, 1], port))];
    ann.links.remember(
        Shelf::with(vec![record_of(&bob, at(old_bob), Some(old_bob))]),
        on_this_machine(),
    );
    bob.links.remember(
        Shelf::with(vec![record_of(&ann, at(old_ann), Some(old_ann))]),
        on_this_machine(),
    );
    let _ann_serves = produce(&ann).await;
    let _bob_serves = produce(&bob).await;
    within_dumping(
        "both are linked to the relay",
        Duration::from_secs(30),
        &[&relay, &ann, &bob],
        || linked(&ann, relay.key) && linked(&bob, relay.key),
    )
    .await;
    // The words cross, whichever path carries them.
    fetch_across(&bob, &ann.name.clone().append("hello"), LONG).await;
    fetch_across(&ann, &bob.name.clone().append("hello"), LONG).await;
    assert!(
        !matches!(
            remembered(&ann, bob.key),
            Some((_, RememberedState::NoPath { .. }))
        ) && !matches!(
            remembered(&bob, ann.key),
            Some((_, RememberedState::NoPath { .. }))
        ),
        "a relay both use is linked: that is a path"
    );
    // And the punch by membership finds the new ports.
    let direct = |on: &Dev, to: KeyFingerprint| {
        on.links
            .report()
            .links
            .iter()
            .filter(|l| l.key == Some(to))
            .flat_map(|l| l.paths.iter())
            .any(|p| p.kind == ndn_link::PathKind::Direct)
    };
    within_dumping(
        "a direct path between them, at the new ports",
        Duration::from_secs(60),
        &[&relay, &ann, &bob],
        || direct(&ann, bob.key) && direct(&bob, ann.key),
    )
    .await;
    within_dumping(
        "each record holds the port the other listens on now",
        LONG,
        &[&ann, &bob],
        || {
            remembered(&ann, bob.key).is_some_and(|(r, _)| r.port == Some(bob.addr.port()))
                && remembered(&bob, ann.key).is_some_and(|(r, _)| r.port == Some(ann.addr.port()))
        },
    )
    .await;
    fetch_across(&bob, &ann.name.clone().append("again"), LONG).await;
}

// ---- no path -----------------------------------------------------------------------------------

/// SHAPES-R7 D: where neither side can reach the other with no relay at all,
/// the report says so, in plain words, and the watcher with it; the redial
/// goes on with its backoff.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_no_kept_address_reaches_and_no_relay_links_is_no_path() {
    let home = Home::new();
    let ann = dev(&home, "ann", 1, "127.0.0.1:0", Vec::new()).await;
    // Bob listens nowhere Ann kept.
    let bob = dev(&home, "bob", 2, "127.0.0.1:0", Vec::new()).await;
    let gone = free_port();
    let shelf = Shelf::with(vec![record_of(
        &bob,
        vec![SocketAddr::from(([127, 0, 0, 1], gone))],
        Some(gone),
    )]);
    ann.links.remember(shelf, on_this_machine());
    within("the memory says there is no path", LONG, || {
        matches!(
            remembered(&ann, bob.key),
            Some((_, RememberedState::NoPath { .. }))
        )
    })
    .await;
    let Some((_, RememberedState::NoPath { why })) = remembered(&ann, bob.key) else {
        unreachable!()
    };
    for words in ["relay", "port", "current address", "bob"] {
        assert!(why.contains(words), "no {words:?} in {why:?}");
    }
    within("the watcher says no-path and waiting for an address", LONG, || {
        matches!(
            state_of(&ann, bob.key),
            Some(LinkState::Down { why, next: Next::WaitingForAddress, .. }) if why.code == link_code::NO_PATH
        )
    })
    .await;
    // A statement, not a retry loop: the redial goes on, and Bob, once he is
    // where Ann dials, is linked.
    drop(bob);
}

// ---- a listening host's address changes --------------------------------------------------------

/// SHAPES-R7 E, case F4 (ndf-rs scenario F4): Alice's laptop, which Bob
/// dialled, moves from one address to another; words typed after the move
/// cross within the time of a redial. `moves` is the move: it is told Alice and
/// Bob; `watch` replaces Alice's address source (the default reads the
/// interfaces).
///
/// Bob's fingerprint is the smaller, so the link Bob dialled is the one both
/// keep when both dial: the case that fails while the link Bob dialled is not
/// replaced by Alice's new one (a QUIC server cannot follow its address).
async fn laptop_moves(
    alice_bind: &str,
    alice_dialled_at: &str,
    bob_bind: &str,
    source: Option<Arc<ManualAddresses>>,
    moves: impl FnOnce(&Dev, &Dev),
) -> Duration {
    let home = Home::new();
    // Bob has the smaller key.
    let (mut seed_alice, mut seed_bob) = (1u8, 2u8);
    if fingerprint_of(seed_bob) > fingerprint_of(seed_alice) {
        std::mem::swap(&mut seed_alice, &mut seed_bob);
    }
    let alice = dev(&home, "alice", seed_alice, alice_bind, Vec::new()).await;
    let mut to_alice = peer_to(&alice);
    to_alice.endpoints = vec![format!("{alice_dialled_at}:{}", alice.addr.port())];
    let bob = dev(&home, "bob", seed_bob, bob_bind, vec![to_alice]).await;
    assert!(bob.key < alice.key);
    alice
        .links
        .remember(Shelf::with(Vec::new()), on_this_machine());
    bob.links
        .remember(Shelf::with(Vec::new()), on_this_machine());
    if let Some(source) = &source {
        alice.links.watch_addresses_from(
            AddressWatch {
                poll: Duration::from_secs(1),
                enabled: true,
            },
            Arc::clone(source) as Arc<dyn AddressSource>,
        );
    }
    within("Alice and Bob link", LONG, || {
        linked(&alice, bob.key) && linked(&bob, alice.key)
    })
    .await;
    words_cross(&alice, &bob, LONG).await;
    // A link older than a simultaneous dial can be: what a new link of the
    // same device replaces.
    tokio::time::sleep(ndn_link::policy::DIAL_RACE_WINDOW + Duration::from_secs(1)).await;

    moves(&alice, &bob);
    let took = words_cross(&alice, &bob, Duration::from_secs(10)).await;
    words_cross(&bob, &alice, Duration::from_secs(10)).await;
    eprintln!("words crossed {took:?} after the move");
    took
}

/// F4 with the address source controlled: Alice's socket moves (the harness
/// plays the system, as `tests/direct.rs` does for a direct path) and the set of
/// addresses the watcher reads changes; the watcher does the rest.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn words_typed_after_the_laptop_moved_cross_within_a_redial_by_a_controlled_source() {
    let source = ManualAddresses::new(&["10.1.0.1"]);
    let seen = Arc::clone(&source);
    laptop_moves(
        "127.0.0.2:0",
        "127.0.0.2",
        "127.0.0.4:0",
        Some(source),
        move |alice, _bob| {
            // The system moves Alice's socket: the old address is gone for good.
            let socket = UdpSocket::bind("127.0.0.3:0").unwrap();
            alice.endpoint.rebind(socket).unwrap();
            // What Alice's watcher reads changes: 10.1.0.1 went, 10.2.0.1 came.
            seen.set(&["10.2.0.1"]);
        },
    )
    .await;
}

/// F4 in a network namespace, the interfaces' addresses really changing: the
/// default address source and the netlink subscription. The case runs this
/// binary again in a user and network namespace of its own (`unshare -rn`, no
/// root); where that is not possible here, it says so and the controlled-source
/// case above is the one that runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn words_typed_after_the_laptop_moved_cross_within_a_redial_in_a_network_namespace() {
    const IN_NAMESPACE: &str = "NDN_LINK_F4_IN_NAMESPACE";
    let ip = |args: &[&str]| {
        let out = std::process::Command::new("ip")
            .args(args)
            .output()
            .expect("ip runs");
        assert!(
            out.status.success(),
            "ip {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    if std::env::var_os(IN_NAMESPACE).is_none() {
        // The parent: run this case in a namespace if one can be made.
        let probe = std::process::Command::new("unshare")
            .args(["-rn", "ip", "link", "set", "lo", "up"])
            .output();
        if !probe.is_ok_and(|o| o.status.success()) {
            eprintln!(
                "no user and network namespace can be made here (unshare -rn): the address change \
                 is tested with a controlled source only"
            );
            return;
        }
        let me = std::env::current_exe().unwrap();
        let out = std::process::Command::new("unshare")
            .args(["-rn"])
            .arg(me)
            .args([
                "words_typed_after_the_laptop_moved_cross_within_a_redial_in_a_network_namespace",
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(IN_NAMESPACE, "1")
            .output()
            .expect("the case runs in the namespace");
        let said = String::from_utf8_lossy(&out.stdout).to_string()
            + &String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "in the namespace:\n{said}");
        return;
    }
    // In the namespace: only `lo`, with the addresses of the case.
    ip(&["link", "set", "lo", "up"]);
    ip(&["addr", "add", "10.1.0.1/32", "dev", "lo"]);
    ip(&["addr", "add", "10.3.0.1/32", "dev", "lo"]);
    // Alice listens on every address (a desktop's socket); Bob on one that
    // stays.
    laptop_moves("0.0.0.0:0", "10.1.0.1", "10.3.0.1:0", None, |alice, bob| {
        // Bob reaches Alice at 10.1.0.1: the address Alice is dialled at.
        let _ = (alice, bob);
        ip(&["addr", "del", "10.1.0.1/32", "dev", "lo"]);
        ip(&["addr", "add", "10.2.0.1/32", "dev", "lo"]);
    })
    .await;
}
