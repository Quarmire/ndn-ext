//! The joiner's routes (ndn-rs `ndn-link.md` §8.7 rules 16–18, SHAPES-R9 §A):
//! the namespaces of the other writers of a folder this device joined, routed
//! over its link to the inviter and over no other link.
//!
//! First at the level of the links, with no data layer (a controlled set of
//! [`JoinedRoutes`], real QUIC links over loopback, a forwarder stand-in that
//! records every route it is given): the route appears on the inviter's
//! identified full link and on no other, none for a link no identity of the
//! owner admitted, an introduction link gets none and gets them once it is
//! made again as a full link, the set is replaced whole and bounded, and the
//! routes go with the link and return with it. Then over real data-layer
//! devices on real forwarders (REPLY-18's G11): Ann invites Bob and, by a
//! second invitation, Carol; Bob's forwarder routes Carol's namespace over his
//! link to Ann by what his device derives, and no FIB entry is made by the
//! test.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use parking_lot::Mutex;

use common::recording::is_public_name;
use common::{
    Embedded, LONG, Person, Setup, dials, embedded, invited, invited_in, linked, n, puts, reads,
    reshare, routed_over, text, until,
};
use ndn_cert::onboarding::rdr_prefix;
use ndn_face_quic::{KeyFingerprint, LinkEndpoint, LinkKey, LinkKeySource, LinkTransportConfig};
use ndn_heap::MembersChange;
use ndn_invite::Role;
use ndn_link::policy::{JOINED_FOLDERS_MAX, JOINED_ROUTE_COST, JOINED_ROUTES_MAX, VIA_RELAY_COST};
use ndn_link::{
    ConfiguredEndpoints, FaceSink, Grant, GrantRole, JoinedRoutes, LinkSetup, LinkTrust, Links,
    PeerSpec, Quotas, RelayService, Route, ServePolicy,
};
use ndn_packet::{Data, Name};
use ndn_security::{
    Certificate, Ed25519Signer, Keyring, SignedTrustContext, Signer, encode_cert_data, sync_group,
};
use ndn_transport::{Face, FaceId, FaceKind};
use tokio_util::sync::CancellationToken;

const T: Duration = Duration::from_secs(10);

/// The folder of Ann's grants here.
const FOLDER: &str = "/a/32=data/notes";

fn now_ns() -> u64 {
    let since = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap();
    u64::try_from(since.as_nanos()).unwrap()
}

async fn certificate(
    key: &Name,
    public_key: [u8; 32],
    issuer: &Ed25519Signer,
    issuer_id: &str,
) -> Bytes {
    let hour = 3_600_000_000_000;
    let name = ndn_security::cert_name::new_cert_name(key, issuer_id);
    encode_cert_data(
        &name,
        &public_key,
        issuer,
        now_ns() - hour,
        now_ns() + 24 * hour,
    )
    .await
    .unwrap()
}

/// A namespace as `ndn-cert` makes one: a root key with its self-signed
/// certificate, and the CA the root certified.
struct Namespace {
    name: Name,
    root: Bytes,
    ca: Ed25519Signer,
    ca_cert: Bytes,
}

async fn namespace(name: &str, seed: u8) -> Namespace {
    let name = n(name);
    let root = Ed25519Signer::from_seed(&[seed; 32], name.clone().append("KEY").append("root"));
    let root_cert = certificate(root.key_name(), root.public_key_bytes(), &root, "self").await;
    let ca = Ed25519Signer::from_seed(
        &[seed + 1; 32],
        name.clone().append("CA").append("KEY").append("ca"),
    );
    let ca_cert = certificate(ca.key_name(), ca.public_key_bytes(), &root, "NA").await;
    Namespace {
        name,
        root: root_cert,
        ca,
        ca_cert,
    }
}

impl Namespace {
    fn context(&self) -> Arc<SignedTrustContext> {
        let schema = ndn_cert::namespace_schema(&self.name).unwrap();
        let ctx = SignedTrustContext::hierarchical(self.name.clone())
            .with_schema_blobs(schema.blobs())
            .unwrap()
            .schema_authoritative()
            .with_ca_endpoint(self.name.clone().append("CA"))
            .with_version(1);
        let root = Certificate::decode(&Data::decode(self.root.clone()).unwrap()).unwrap();
        assert!(ctx.add_anchor(root));
        Arc::new(ctx)
    }

    /// The key of device `/<ns>/<role>/<device>`, certified by its CA.
    async fn device(&self, role: &str, device: &str, seed: u8) -> DeviceKey {
        let name = self
            .name
            .clone()
            .append(role)
            .append(device)
            .append("KEY")
            .append("k");
        let signer = Ed25519Signer::from_seed(&[seed; 32], name);
        let cert = certificate(
            signer.key_name(),
            signer.public_key_bytes(),
            &self.ca,
            "NDNCERT",
        )
        .await;
        DeviceKey {
            signer: Arc::new(signer),
            chain: vec![cert, self.ca_cert.clone()],
        }
    }
}

struct DeviceKey {
    signer: Arc<Ed25519Signer>,
    chain: Vec<Bytes>,
}

impl DeviceKey {
    fn link_key(&self) -> LinkKey {
        LinkKey::from_signer(Arc::clone(&self.signer) as Arc<dyn Signer>).unwrap()
    }

    fn fingerprint(&self) -> KeyFingerprint {
        self.link_key().fingerprint()
    }
}

struct Trust {
    keyring: Arc<Keyring>,
    chain: Vec<Bytes>,
}

impl Trust {
    fn new(held: &[&Namespace], chain: Vec<Bytes>) -> Self {
        let keyring = Keyring::new();
        for ns in held {
            keyring.adopt(ns.context()).unwrap();
        }
        Self {
            keyring: Arc::new(keyring),
            chain,
        }
    }
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

/// A forwarder stand-in: the link faces and routes it is given, every route
/// added (at any cost) and every one removed, in order.
#[derive(Default)]
struct Faces {
    next: AtomicU64,
    live: Mutex<Vec<FaceId>>,
    faces: Mutex<Vec<(FaceId, Arc<Face>)>>,
    routes: Mutex<Vec<(FaceId, Route)>>,
    added: Mutex<Vec<(FaceId, Route)>>,
    removed: Mutex<Vec<(FaceId, Name)>>,
    changed: tokio::sync::Notify,
}

impl Faces {
    /// The routes in force at the joiner's cost: `(face, prefix)`, sorted.
    fn joined(&self) -> Vec<(FaceId, Name)> {
        let mut out: Vec<(FaceId, Name)> = self
            .routes
            .lock()
            .iter()
            .filter(|(_, r)| r.cost == JOINED_ROUTE_COST && !is_public_name(&r.prefix))
            .map(|(f, r)| (*f, r.prefix.clone()))
            .collect();
        out.sort_by(|a, b| (a.0.0, &a.1).cmp(&(b.0.0, &b.1)));
        out
    }

    /// The prefixes in force at the joiner's cost over any face, sorted.
    fn joined_prefixes(&self) -> Vec<Name> {
        let mut out: Vec<Name> = self.joined().into_iter().map(|(_, p)| p).collect();
        out.sort();
        out
    }

    /// How many times `prefix` was added at the joiner's cost, to any face.
    fn joined_additions(&self, prefix: &Name) -> usize {
        self.added
            .lock()
            .iter()
            .filter(|(_, r)| r.cost == JOINED_ROUTE_COST && r.prefix == *prefix)
            .count()
    }

    /// Calls the links made that add or remove routes, so far.
    fn route_calls(&self) -> usize {
        self.added.lock().len() + self.removed.lock().len()
    }

    async fn send(&self, packet: &Bytes) {
        let face = self.faces.lock().last().map(|(_, f)| Arc::clone(f));
        face.expect("a link face")
            .send_bytes(packet.clone())
            .await
            .expect("the link carries a send");
    }

    async fn receive(&self) -> Bytes {
        let face = self.faces.lock().last().map(|(_, f)| Arc::clone(f));
        face.expect("a link face")
            .recv_bytes()
            .await
            .expect("the link delivers")
    }

    /// Wait until `done` holds, woken by each change rather than polling.
    async fn settles(&self, what: &str, done: impl Fn(&Self) -> bool) {
        let wait = async {
            loop {
                let change = self.changed.notified();
                tokio::pin!(change);
                change.as_mut().enable();
                if done(self) {
                    return;
                }
                change.await;
            }
        };
        tokio::time::timeout(T, wait).await.unwrap_or_else(|_| {
            panic!(
                "{what}: not within {} s (live faces {:?}, joined routes {:?})",
                T.as_secs(),
                self.live.lock(),
                self.joined()
            )
        });
    }
}

impl FaceSink for Faces {
    fn alloc_face_id(&self) -> FaceId {
        FaceId(self.next.fetch_add(1, Ordering::SeqCst) + 1)
    }
    fn add_face(&self, face: Face, _: CancellationToken) {
        if face.kind() == FaceKind::Quic {
            self.live.lock().push(face.id());
            self.faces.lock().push((face.id(), Arc::new(face)));
        }
        self.changed.notify_waiters();
    }
    fn remove_face(&self, face: FaceId) {
        self.live.lock().retain(|f| *f != face);
        self.faces.lock().retain(|(f, _)| *f != face);
        self.routes.lock().retain(|(f, _)| *f != face);
        self.changed.notify_waiters();
    }
    fn add_routes(&self, face: FaceId, routes: &[Route]) {
        self.added
            .lock()
            .extend(routes.iter().map(|r| (face, r.clone())));
        if self.live.lock().contains(&face) {
            self.routes
                .lock()
                .extend(routes.iter().map(|r| (face, r.clone())));
        }
        self.changed.notify_waiters();
    }
    fn remove_routes(&self, face: FaceId, prefixes: &[Name]) {
        self.removed
            .lock()
            .extend(prefixes.iter().map(|p| (face, p.clone())));
        self.routes
            .lock()
            .retain(|(f, r)| *f != face || !prefixes.contains(&r.prefix));
        self.changed.notify_waiters();
    }
    fn routes_to(&self, face: FaceId) -> bool {
        self.routes.lock().iter().any(|(f, _)| *f == face)
    }
    fn transit(&self, _: &Name, _: bool) {}
}

/// Links on a loopback socket (when `listen`), serving `serve`.
fn start(
    key: LinkKey,
    trust: Trust,
    peers: Vec<PeerSpec>,
    listen: bool,
    serve: ServePolicy,
    cancel: &CancellationToken,
) -> (Arc<Links>, Arc<Faces>, Option<String>) {
    common::log_to_file();
    let transport = LinkTransportConfig::default();
    let key: Arc<dyn LinkKeySource> = Arc::new(key);
    let socket = listen.then(|| {
        Arc::new(
            LinkEndpoint::bind(
                "127.0.0.1:0".parse().unwrap(),
                Arc::clone(&key),
                &transport,
                true,
            )
            .unwrap(),
        )
    });
    let addr = socket.as_ref().map(|s| s.local_addr().unwrap().to_string());
    let faces = Arc::new(Faces::default());
    let links = Links::start(
        LinkSetup {
            peers,
            key,
            trust: Arc::new(trust),
            faces: Arc::clone(&faces) as Arc<dyn FaceSink>,
            paths: Arc::new(ConfiguredEndpoints),
            candidates: Vec::new(),
            socket,
            transport,
            relays: Default::default(),
            service: RelayService {
                serve,
                ..RelayService::default()
            },
            direct: Default::default(),
            reliability: Default::default(),
        },
        cancel.child_token(),
    );
    (links, faces, addr)
}

fn open() -> ServePolicy {
    ServePolicy::Open {
        quotas: Quotas::default(),
    }
}

/// A peer Bob dials by its key, and dials again whenever the link drops.
fn peer(label: &str, links: &Links, endpoint: &str) -> PeerSpec {
    PeerSpec {
        label: label.into(),
        key: links.key_fingerprint(),
        endpoints: vec![endpoint.to_string()],
        persistent: true,
        ..PeerSpec::default()
    }
}

/// The face of `links`' link to the device with `key`.
fn face_to(links: &Links, key: KeyFingerprint) -> FaceId {
    links
        .report()
        .links
        .iter()
        .find(|l| l.key == Some(key))
        .and_then(|l| l.paths.first())
        .map(|p| p.face)
        .unwrap_or_else(|| panic!("no link to {key}"))
}

/// The routes of a folder the joiner writes in (its writers' sync groups are routed).
fn routes(inviter: KeyFingerprint, owner: &str, namespaces: &[&str]) -> JoinedRoutes {
    JoinedRoutes {
        inviter,
        owner: n(owner),
        namespaces: namespaces.iter().map(|s| n(s)).collect(),
        push: true,
    }
}

/// The same folder for a joiner that only reads in it.
fn reader(routes: JoinedRoutes) -> JoinedRoutes {
    JoinedRoutes {
        push: false,
        ..routes
    }
}

/// Bob, a device of `/b` holding `/a`, `/b` and `/e`, linked to three devices
/// that all open their links to him: Ann and Dave, two devices of `/a`, and
/// Erin, a device of `/e`.
struct Bob {
    cancel: CancellationToken,
    links: Arc<Links>,
    at: Arc<Faces>,
    /// Ann's links: she can go offline and come back.
    ann_links: Arc<Links>,
    ann: KeyFingerprint,
    dave: KeyFingerprint,
    erin: KeyFingerprint,
}

async fn bob_linked_to_three() -> Bob {
    let cancel = CancellationToken::new();
    let (a, b, e) = (
        namespace("/a", 10).await,
        namespace("/b", 20).await,
        namespace("/e", 40).await,
    );
    let ann = a.device("node", "relay", 90).await;
    let dave = a.device("node", "spare", 91).await;
    let erin = e.device("node", "relay", 92).await;
    let bob = b.device("member", "phone", 22).await;
    let serve = |key: &DeviceKey, held: &[&Namespace]| {
        start(
            key.link_key(),
            Trust::new(held, key.chain.clone()),
            Vec::new(),
            true,
            open(),
            &cancel,
        )
    };
    let (ann_links, _, ann_addr) = serve(&ann, &[&a, &b]);
    let (dave_links, _, dave_addr) = serve(&dave, &[&a, &b]);
    let (erin_links, _, erin_addr) = serve(&erin, &[&e, &b]);
    let (links, at, _) = start(
        bob.link_key(),
        Trust::new(&[&a, &b, &e], bob.chain.clone()),
        vec![
            peer("ann", &ann_links, &ann_addr.unwrap()),
            peer("dave", &dave_links, &dave_addr.unwrap()),
            peer("erin", &erin_links, &erin_addr.unwrap()),
        ],
        false,
        ServePolicy::Own,
        &cancel,
    );
    at.settles("bob is linked to the three", |f| f.live.lock().len() == 3)
        .await;
    Bob {
        cancel,
        links,
        at,
        ann_links,
        ann: ann.fingerprint(),
        dave: dave.fingerprint(),
        erin: erin.fingerprint(),
    }
}

/// A route toward each namespace is installed over the **full, identified
/// link of the inviter's key** and over no other: not over Dave's link, a
/// device of the same owner namespace with another key; and not over the link
/// of a key that no identity of the folder's owner admitted, whatever the set
/// says its owner is. The cost is above every real path's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_route_is_installed_over_the_inviters_identified_link_and_over_no_other() {
    let bob = bob_linked_to_three().await;
    let ann_face = face_to(&bob.links, bob.ann);
    let costs = || -> Vec<u32> {
        bob.at
            .added
            .lock()
            .iter()
            .filter(|(_, r)| r.prefix == n("/c"))
            .map(|(_, r)| r.cost)
            .collect()
    };

    bob.links.set_joined_routes(vec![
        routes(bob.ann, "/a", &["/c", "/d"]),
        // Erin proved an identity of `/e`, not of `/a`: no route over it,
        // though the set names it as the inviter of a folder of `/a`.
        routes(bob.erin, "/a", &["/x"]),
        // Ann's key, a folder of an owner none of her identities is in.
        routes(bob.ann, "/zzz", &["/y"]),
    ]);

    assert_eq!(
        bob.at.joined(),
        vec![(ann_face, n("/c")), (ann_face, n("/d"))],
        "the routes of the joined folders are not exactly the inviter's link's"
    );
    assert_eq!(
        costs(),
        vec![VIA_RELAY_COST + 1000],
        "the route does not cost the relay's cost and a thousand"
    );
    // Each writer's sync group is routed beside the namespace: a data layer
    // registers the groups of the other writers with its own forwarder, and
    // that entry would shadow the namespace's route for every name of the group.
    for ns in ["/c", "/d"] {
        assert_eq!(
            bob.at.joined_additions(&sync_group(&n(ns))),
            1,
            "{ns}'s sync group was not routed over the inviter's link"
        );
    }
    for stray in ["/x", "/y"] {
        assert_eq!(
            bob.at.joined_additions(&n(stray)),
            0,
            "{stray} was routed over a link that is not the inviter's identified link"
        );
    }
    let over_dave = face_to(&bob.links, bob.dave);
    assert!(
        bob.at.joined().iter().all(|(f, _)| *f != over_dave),
        "Dave's link, another key of the owner's namespace, got a route"
    );
    bob.cancel.cancel();
}

/// The set is replaced whole: a namespace the set no longer lists is removed
/// through `remove_routes`, one it still lists stays untouched, the same set
/// again changes nothing, and the empty set removes every route.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_route_the_set_drops_is_removed_and_the_same_set_again_changes_nothing() {
    let bob = bob_linked_to_three().await;
    let ann_face = face_to(&bob.links, bob.ann);

    bob.links
        .set_joined_routes(vec![routes(bob.ann, "/a", &["/c", "/d"])]);
    assert_eq!(bob.at.joined().len(), 2);
    let calls = bob.at.route_calls();

    bob.links
        .set_joined_routes(vec![routes(bob.ann, "/a", &["/c", "/d"])]);
    assert_eq!(
        bob.at.route_calls(),
        calls,
        "the same set again made the forwarder change"
    );

    bob.links
        .set_joined_routes(vec![routes(bob.ann, "/a", &["/d"])]);
    assert_eq!(bob.at.joined(), vec![(ann_face, n("/d"))]);
    assert!(
        bob.at.removed.lock().contains(&(ann_face, n("/c"))),
        "the route the set dropped was not removed with remove_routes"
    );
    assert!(
        bob.at
            .removed
            .lock()
            .contains(&(ann_face, sync_group(&n("/c")))),
        "the sync group of the dropped namespace was not removed with remove_routes"
    );
    assert_eq!(
        bob.at.joined_additions(&n("/d")),
        1,
        "a namespace the set kept was added again"
    );

    bob.links.set_joined_routes(Vec::new());
    assert!(
        bob.at.joined().is_empty(),
        "the empty set left routes: {:?}",
        bob.at.joined()
    );
    assert!(bob.at.removed.lock().contains(&(ann_face, n("/d"))));
    bob.cancel.cancel();
}

/// A reader entry is routed `<W>` and not `<W>/32=sync`, a writer entry both:
/// the group is the writer-push route. The entry's role changing replaces the
/// routes at once, whichever way.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_a_writer_entry_is_routed_the_sync_groups() {
    let bob = bob_linked_to_three().await;
    let ann_face = face_to(&bob.links, bob.ann);
    let group = sync_group(&n("/c"));

    bob.links
        .set_joined_routes(vec![reader(routes(bob.ann, "/a", &["/c"]))]);
    assert_eq!(bob.at.joined(), vec![(ann_face, n("/c"))]);
    assert_eq!(
        bob.at.joined_additions(&group),
        0,
        "a reader entry was routed the writer's sync group"
    );

    bob.links
        .set_joined_routes(vec![routes(bob.ann, "/a", &["/c"])]);
    assert_eq!(
        bob.at.joined_additions(&group),
        1,
        "a writer entry was not routed the sync group"
    );

    bob.links
        .set_joined_routes(vec![reader(routes(bob.ann, "/a", &["/c"]))]);
    assert!(
        bob.at.removed.lock().contains(&(ann_face, group.clone())),
        "the entry demoted to a reader kept the sync group"
    );
    assert_eq!(bob.at.joined(), vec![(ann_face, n("/c"))]);

    // A writer entry of another folder beside a reader entry of the same
    // namespace: the writer's group is routed (one route for the namespace).
    bob.links.set_joined_routes(vec![
        reader(routes(bob.ann, "/a", &["/c"])),
        routes(bob.ann, "/a", &["/c"]),
    ]);
    assert_eq!(bob.at.joined_additions(&group), 2, "(added again once)");
    bob.cancel.cancel();
}

/// The same writer in two folders is one route; a folder's prefixes and the
/// folders are bounded, and what exceeds the bound is dropped (the warning
/// says why), the first ones kept.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_set_is_bounded_and_the_same_writer_in_two_folders_is_one_route() {
    let bob = bob_linked_to_three().await;
    let ann_face = face_to(&bob.links, bob.ann);

    bob.links.set_joined_routes(vec![
        routes(bob.ann, "/a", &["/c"]),
        routes(bob.ann, "/a", &["/c", "/d"]),
    ]);
    assert_eq!(
        bob.at.joined(),
        vec![(ann_face, n("/c")), (ann_face, n("/d"))]
    );
    assert_eq!(
        bob.at.joined_additions(&n("/c")),
        1,
        "the same writer in two folders was routed twice"
    );

    // One folder listing more prefixes than the bound.
    let many: Vec<String> = (0..JOINED_ROUTES_MAX + 6)
        .map(|i| format!("/w{i}"))
        .collect();
    let refs: Vec<&str> = many.iter().map(String::as_str).collect();
    bob.links
        .set_joined_routes(vec![routes(bob.ann, "/a", &refs)]);
    let routed = bob.at.joined_prefixes();
    assert_eq!(
        routed.len(),
        JOINED_ROUTES_MAX,
        "more or fewer prefixes than the bound were routed"
    );
    for kept in &many[..JOINED_ROUTES_MAX] {
        assert!(routed.contains(&n(kept)), "{kept} was dropped");
    }

    // More folders than the bound, one prefix each.
    let folders: Vec<String> = (0..JOINED_FOLDERS_MAX + 4)
        .map(|i| format!("/f{i}"))
        .collect();
    bob.links.set_joined_routes(
        folders
            .iter()
            .map(|f| routes(bob.ann, "/a", &[f.as_str()]))
            .collect(),
    );
    let routed = bob.at.joined_prefixes();
    assert_eq!(
        routed.len(),
        JOINED_FOLDERS_MAX,
        "the folders after the bound were routed: {routed:?}"
    );
    assert!(routed.contains(&n(&folders[JOINED_FOLDERS_MAX - 1])));
    assert!(!routed.contains(&n(&folders[JOINED_FOLDERS_MAX])));
    bob.cancel.cancel();
}

/// A link that goes down loses its routes with its face, and the link made
/// again gets them at registration, with no new call to the links. Ann goes
/// offline (her links close, Bob's other links stand) and comes back; Bob
/// dials her again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_routes_go_with_the_link_and_return_when_it_is_up_again() {
    let bob = bob_linked_to_three().await;
    let ann_face = face_to(&bob.links, bob.ann);
    bob.links
        .set_joined_routes(vec![routes(bob.ann, "/a", &["/c"])]);
    assert_eq!(bob.at.joined(), vec![(ann_face, n("/c"))]);

    bob.ann_links.set_online(false);
    bob.at
        .settles("bob's link to ann is down", |f| f.live.lock().len() == 2)
        .await;
    assert!(
        bob.at.joined().is_empty(),
        "a link that went down kept its routes: {:?}",
        bob.at.joined()
    );

    bob.ann_links.set_online(true);
    bob.at
        .settles("the joiner's route returns with the link", |f| {
            !f.joined().is_empty()
        })
        .await;
    let again = face_to(&bob.links, bob.ann);
    assert_ne!(again, ann_face, "the link came back on the face it lost");
    assert_eq!(bob.at.joined(), vec![(again, n("/c"))]);
    bob.cancel.cancel();
}

/// The set is consulted at registration: a set given before the link exists
/// is installed when the link is up. A link made only to introduce — the
/// dialler holds no namespace of the inviter yet, so the device shows no
/// identity it can validate — gets none, and gets them once it is made again
/// as a full link, after the namespace is held.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_introduction_link_gets_none_and_the_full_link_made_again_gets_them() {
    let cancel = CancellationToken::new();
    let (a, b) = (namespace("/a", 10).await, namespace("/b", 20).await);
    let ann = a.device("node", "relay", 90).await;
    let bob = b.device("member", "phone", 22).await;
    let (_ann_links, _, ann_addr) = start(
        ann.link_key(),
        Trust::new(&[&a, &b], ann.chain.clone()),
        Vec::new(),
        true,
        open(),
        &cancel,
    );
    // Bob holds `/b` only: Ann's namespace is not his yet.
    let trust = Trust::new(&[&b], bob.chain.clone());
    let keyring = Arc::clone(&trust.keyring);
    let (links, at, _) = start(
        bob.link_key(),
        trust,
        Vec::new(),
        false,
        ServePolicy::Own,
        &cancel,
    );
    let inviter = ann.fingerprint();
    links.set_joined_routes(vec![routes(inviter, "/a", &["/c"])]);
    links
        .dial_by_key(
            inviter,
            n("/a/node/relay"),
            vec![ann_addr.unwrap().parse().unwrap()],
            T,
            Vec::new(),
        )
        .await
        .expect("bob dials ann by her key");
    at.settles("bob has the link", |f| f.live.lock().len() == 1)
        .await;
    let introduction = face_to(&links, inviter);
    assert!(
        at.joined().is_empty(),
        "a link whose device shows no identity bob can validate got routes: {:?}",
        at.joined()
    );

    // Bob comes to hold Ann's namespace: the link is made again, as a full
    // link, and gets them.
    keyring.adopt(a.context()).unwrap();
    at.settles("the full link gets the joiner's route", |f| {
        !f.joined().is_empty()
    })
    .await;
    let full = face_to(&links, inviter);
    assert_ne!(full, introduction, "the link was not made again");
    assert_eq!(at.joined(), vec![(full, n("/c"))]);
    cancel.cancel();
}

/// A device that only *claims* the owner's namespace gets none: Ann's chain
/// carries the root of `/a`, and Bob, who holds no context of `/a`, serves her
/// as a device of a namespace not held (its root is the hello's own word, so
/// the identity proves nothing about `/a`). Her key is the set's inviter and
/// the identity's namespace is the set's owner, yet no route is installed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_that_only_claims_the_owners_namespace_gets_no_route() {
    let cancel = CancellationToken::new();
    let (a, b) = (namespace("/a", 10).await, namespace("/b", 20).await);
    let ann = a.device("node", "relay", 90).await;
    let bob = b.device("member", "phone", 22).await;
    let (bob_links, at_bob, bob_addr) = start(
        bob.link_key(),
        Trust::new(&[&b], bob.chain.clone()),
        Vec::new(),
        true,
        open(),
        &cancel,
    );
    let mut chain = ann.chain.clone();
    chain.push(a.root.clone());
    let (_ann_links, _, _) = start(
        ann.link_key(),
        Trust::new(&[&a], chain),
        vec![peer("bob", &bob_links, &bob_addr.unwrap())],
        false,
        ServePolicy::Own,
        &cancel,
    );
    at_bob
        .settles("bob serves ann's link", |f| f.live.lock().len() == 1)
        .await;
    bob_links.set_joined_routes(vec![routes(ann.fingerprint(), "/a", &["/c"])]);
    assert!(
        at_bob.joined().is_empty(),
        "a served device that claims the owner's namespace by its own root got routes: {:?}",
        at_bob.joined()
    );
    cancel.cancel();
}

/// An enrollment link gets none: Bob holds the context of `/a` and no
/// certificate in it, and names Ann's device (not her key), so he links to
/// her for his enrollment only. Her certificate validates in `/a`, her key is
/// the set's inviter and `/a` the owner, yet the link is no full link.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_enrollment_link_gets_none() {
    let cancel = CancellationToken::new();
    let (a, b) = (namespace("/a", 10).await, namespace("/b", 20).await);
    let ann = a.device("node", "relay", 90).await;
    let bob = b.device("member", "phone", 22).await;
    let (_ann_links, _, ann_addr) = start(
        ann.link_key(),
        Trust::new(&[&a, &b], ann.chain.clone()),
        Vec::new(),
        true,
        ServePolicy::Own,
        &cancel,
    );
    let by_device = PeerSpec {
        label: "ann".into(),
        device: Some(n("/a/node/relay")),
        endpoints: vec![ann_addr.unwrap()],
        persistent: false,
        ..PeerSpec::default()
    };
    let (links, at, _) = start(
        bob.link_key(),
        Trust::new(&[&a, &b], bob.chain.clone()),
        vec![by_device],
        false,
        ServePolicy::Own,
        &cancel,
    );
    at.settles("bob has the enrollment link", |f| f.live.lock().len() == 1)
        .await;
    links.set_joined_routes(vec![routes(ann.fingerprint(), "/a", &["/c"])]);
    assert!(
        at.joined().is_empty(),
        "an enrollment link got routes: {:?}",
        at.joined()
    );
    cancel.cancel();
}

/// A reader-role joiner is routed the same prefixes (a route is a path, not a
/// right) and what it pushes stays dropped at the inviter: a reader pushes
/// only under its own device's names, the writer's public names cross only
/// for a writer, and the next packet after a promotion shows it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reader_is_routed_the_writers_namespaces_and_what_it_pushes_stays_dropped() {
    let cancel = CancellationToken::new();
    let (a, b, c) = (
        namespace("/a", 10).await,
        namespace("/b", 20).await,
        namespace("/c", 30).await,
    );
    let ann = a.device("node", "relay", 90).await;
    let phone = b.device("member", "phone", 22).await;
    let (ann_links, at_ann, ann_addr) = start(
        ann.link_key(),
        Trust::new(&[&a, &b, &c], ann.chain.clone()),
        Vec::new(),
        true,
        ServePolicy::Own,
        &cancel,
    );
    let grant = |role| Grant {
        key: phone.fingerprint(),
        namespaces: vec![n("/b")],
        role,
        folder: n(FOLDER),
        until: None,
    };
    ann_links.grant(grant(GrantRole::Reader));
    let (links, at_phone, _) = start(
        phone.link_key(),
        Trust::new(&[&a, &b, &c], phone.chain.clone()),
        vec![peer("ann", &ann_links, &ann_addr.unwrap())],
        false,
        ServePolicy::Own,
        &cancel,
    );
    at_ann
        .settles("ann links the phone as a reader", |f| {
            f.live.lock().len() == 1
        })
        .await;
    at_phone
        .settles("the phone has its link", |f| f.live.lock().len() == 1)
        .await;

    links.set_joined_routes(vec![routes(ann.fingerprint(), "/a", &["/c"])]);
    assert_eq!(
        at_phone.joined(),
        vec![(face_to(&links, ann.fingerprint()), n("/c"))],
        "a reader is routed the writers' namespaces"
    );

    let pushed = |name: &str| ndn_packet::encode::DataBuilder::new(n(name), b"x").build();
    // Public by design, and carried by a grant of `/b`: its namespace's sync
    // group. (The folder owner's group is the data layer's to name, per
    // space: with no data layer on this device it carries none of it.)
    let (public, own) = ("/b/32=sync/probe", "/b/member/phone/seal/1");
    let next = async || {
        let got = tokio::time::timeout(Duration::from_secs(5), at_ann.receive())
            .await
            .expect("nothing arrived within 5 s");
        let got = match ndn_packet::lp::LpPacket::decode(got.clone()) {
            Ok(lp) => lp.fragment.unwrap_or(got),
            Err(_) => got,
        };
        Data::decode(got).expect("a Data").name.to_string()
    };
    at_phone.send(&pushed(public)).await;
    at_phone.send(&pushed(own)).await;
    assert_eq!(
        next().await,
        n(own).to_string(),
        "the reader's push under a public name crossed: the route let a reader push"
    );

    // Promoted: the same link, the next packet shows it.
    ann_links.grant(grant(GrantRole::Writer));
    at_phone.send(&pushed(public)).await;
    assert_eq!(
        next().await,
        n(public).to_string(),
        "the writer's push under a public name did not cross"
    );
    cancel.cancel();
}

// --- real data-layer devices on real forwarders (REPLY-18's G11) ---

/// The face of `on`'s link to `key`, as its report has it now.
fn face_of(on: &Embedded, key: KeyFingerprint) -> FaceId {
    face_to(&on.links, key)
}

/// What `on`'s forwarder routes to `prefix` over `face`, with its cost: its FIB.
fn fib_cost(on: &Embedded, prefix: &Name, face: FaceId) -> Option<u32> {
    on.engine
        .fib()
        .dump()
        .into_iter()
        .filter(|(p, _)| p == prefix)
        .flat_map(|(_, e)| e.nexthops.clone())
        .find(|h| h.face_id == face)
        .map(|h| h.cost)
}

/// Ann invites Bob and, by a second invitation, Carol, both writers; they
/// never met. Bob's forwarder is given a route toward Carol's namespace over
/// his link to Ann, at the joiner's cost, by what his device derives from the
/// record, and toward nothing else: not his own namespace, not Ann's, not a
/// name no record lists; Carol's, symmetrically, toward Bob's; Ann's none (no
/// folder was joined by her). Carol writes and Bob reads it. A record without
/// Carol takes the route at the next notification. With `by_name`, Bob's and
/// Carol's hosts serve their own namespace's context on their engines and
/// adopt each other's self-certifying namespace **by name through their own
/// engines** (`adopt_scoped_via_engine`: the trust context is an Interest
/// that crosses Bob's forwarder, the link to Ann, Ann's forwarder and her
/// link to Carol): the test hands them no context and makes no FIB entry, so
/// each hop has the route the links installed or the Interest dies there
/// ("no route for …").
async fn g11(faulty: bool, by_name: bool) {
    let alice = Person::new("/alice").await;
    let bobs = Person::self_certifying([0xb2; 32]).await;
    let carols = Person::self_certifying([0xc2; 32]).await;
    let named = Setup {
        scoped_by_name: by_name,
        ..Setup::dialer()
    };
    let ann = embedded(&alice, common::ANN, Setup::inviter()).await;
    let bob = embedded(&bobs, &bobs.device("phone"), named.clone()).await;
    let carol = embedded(&carols, &carols.device("phone"), named).await;
    let folder = n(common::FOLDER);
    if faulty {
        inject(&[&ann, &bob, &carol]);
    }

    invited(&ann, &bob, Role::Writer).await;
    invited_in(&ann, &carol, &folder, Role::Writer).await;
    until("ann is linked to both", LONG, async || {
        linked(&ann, bob.key) && linked(&ann, carol.key)
    })
    .await;

    until(
        "bob routes carol's namespace over his link to ann",
        LONG,
        async || bob.sink.joined_now() == vec![(face_of(&bob, ann.key), carols.ns.clone())],
    )
    .await;
    until(
        "carol routes bob's namespace over her link to ann",
        LONG,
        async || carol.sink.joined_now() == vec![(face_of(&carol, ann.key), bobs.ns.clone())],
    )
    .await;
    // The route is in Bob's FIB at the joiner's cost, made by the links.
    assert_eq!(
        fib_cost(&bob, &carols.ns, face_of(&bob, ann.key)),
        Some(JOINED_ROUTE_COST),
        "bob's FIB: {:?}",
        routed_over(&bob, ann.key)
    );
    // (Without the test host's own group routes, which are cost 0 on the same
    // entry, the sync group has the joiner's route.)
    if by_name {
        assert_eq!(
            fib_cost(&bob, &sync_group(&carols.ns), face_of(&bob, ann.key)),
            Some(JOINED_ROUTE_COST),
            "bob's FIB does not route Carol's sync group over his link to Ann"
        );
    }
    // Ann's grant link to Carol routes Carol's public names outside her
    // devices (the trust context), so Ann's forwarder can relay Bob's fetch.
    until(
        "ann routes carol's trust context toward carol",
        LONG,
        async || {
            ann.sink
                .routed_at_joiner_cost(face_of(&ann, carol.key), &rdr_prefix(&carols.ns))
        },
    )
    .await;
    // Nothing else, ever: not his own namespace, not Ann's, not a stranger's.
    assert_eq!(
        bob.sink.ever_joined(),
        vec![carols.ns.clone()],
        "bob was routed more than the record lists"
    );
    assert!(ann.sink.ever_joined().is_empty(), "ann joined no folder");

    // Carol writes, Bob reads it through Ann, no route of the test's. Under
    // the faulty profile each round trip may take several attempts.
    let patience = if faulty { LONG * 4 } else { LONG };
    let written = folder.clone().append("from-carol");
    puts(&carol, &written, text("carol writes"), patience).await;
    until("bob reads carol's note", patience, async || {
        reads(&bob, &written, "carol writes").await
    })
    .await;

    // The host calls `serve` once more: it follows the device still (one
    // task for these links, the second call's), and the record's change is
    // seen. A record without Carol: Bob's route goes at the next notification.
    bob.hints.serve(&bob.invites);
    reshare(&ann, &folder, &[alice.ns.clone(), bobs.ns.clone()]).await;
    until(
        "bob's route toward carol is removed",
        patience,
        async || bob.sink.joined_now().is_empty(),
    )
    .await;
    let face = face_of(&bob, ann.key);
    assert!(
        bob.sink.removed_route(face, &carols.ns),
        "the route toward a writer the record dropped was not removed with remove_routes: {:?}",
        bob.sink.calls()
    );
    assert!(linked(&ann, bob.key), "the link of a listed member ended");
}

/// The faulty profile of the conformance, on the packets arriving at each
/// device.
fn inject(devices: &[&Embedded]) {
    #[cfg(feature = "fault-injection")]
    for (i, d) in devices.iter().enumerate() {
        let profile = ndn_link::Faults::parse(ndn_link::FAULTY)
            .unwrap()
            .with_seed(9 + i as u64);
        d.links.inject_faults(ndn_link::FaultPlan::new(profile));
    }
    #[cfg(not(feature = "fault-injection"))]
    let _ = devices;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn g11_bob_is_routed_carols_namespace_and_reads_carol_through_ann() {
    g11(false, false).await;
}

/// G11 with the conformance's FAULTY profile on every link (drops,
/// duplicates, forgeries, delays, reordering): the routes are the same.
#[cfg(feature = "fault-injection")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn g11_faulty_bob_is_routed_carols_namespace_and_reads_carol_through_ann() {
    g11(true, false).await;
}

/// G11 as ndf's host does it: Bob adopts Carol's namespace by name through his
/// own engine, over the route his links installed toward her namespace and
/// the one Ann's link to Carol gives her forwarder for the namespace's trust
/// context.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn g11_bob_fetches_carols_context_by_name_through_the_joiners_route_and_anns() {
    g11(false, true).await;
}

/// The same under the conformance's FAULTY profile.
#[cfg(feature = "fault-injection")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn g11_faulty_bob_fetches_carols_context_by_name_through_the_joiners_route_and_anns() {
    g11(true, true).await;
}

/// A link that goes down loses the route with its face, and the link made
/// again (the joiner dials the inviter once it needs it) has it at
/// registration.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bobs_route_goes_with_his_link_and_returns_when_it_is_up_again() {
    let alice = Person::new("/alice").await;
    let bobs = Person::self_certifying([0xb2; 32]).await;
    let carols = Person::self_certifying([0xc2; 32]).await;
    let ann = embedded(&alice, common::ANN, Setup::inviter()).await;
    let bob = embedded(&bobs, &bobs.device("phone"), Setup::dialer()).await;
    let carol = embedded(&carols, &carols.device("phone"), Setup::dialer()).await;
    let folder = n(common::FOLDER);
    invited(&ann, &bob, Role::Writer).await;
    invited_in(&ann, &carol, &folder, Role::Writer).await;
    until("bob routes carol's namespace", LONG, async || {
        bob.sink.joined_now() == vec![(face_of(&bob, ann.key), carols.ns.clone())]
    })
    .await;
    let before = face_of(&bob, ann.key);

    bob.links.set_online(false);
    until("bob's links are down", LONG, async || {
        !linked(&bob, ann.key)
    })
    .await;
    assert!(bob.sink.removed_face(before));
    assert!(
        bob.sink.joined_now().is_empty(),
        "a link that went down kept its route: {:?}",
        bob.sink.joined_now()
    );

    bob.links.set_online(true);
    until("bob dials ann again", LONG, async || {
        dials(&bob, &ann).await.is_ok()
    })
    .await;
    until("the route returns with the link", LONG, async || {
        bob.sink.joined_now() == vec![(face_of(&bob, ann.key), carols.ns.clone())]
    })
    .await;
    assert_ne!(face_of(&bob, ann.key), before);
}

/// A link of another key gets none, however it is admitted and whoever it
/// is: a second device of Ann's person (`/alice`, so an identity of the
/// folder's owner admits it at Bob, which holds `/alice` from the join, and a
/// grant of his links it) dials Bob, and Bob's route is over his link to Ann
/// only. (Carol's own key cannot link to Bob here: no one but a grant links
/// a person of a namespace Bob does not hold, and Bob holds no context of
/// Carol's.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_link_of_another_key_gets_no_route() {
    let alice = Person::new("/alice").await;
    let bobs = Person::self_certifying([0xb2; 32]).await;
    let carols = Person::self_certifying([0xc2; 32]).await;
    let ann = embedded(&alice, common::ANN, Setup::inviter()).await;
    let tablet = embedded(&alice, "/alice/member/tablet", Setup::dialer()).await;
    let bob = embedded(&bobs, &bobs.device("phone"), Setup::inviter()).await;
    let carol = embedded(&carols, &carols.device("phone"), Setup::dialer()).await;
    let folder = n(common::FOLDER);
    invited(&ann, &bob, Role::Writer).await;
    invited_in(&ann, &carol, &folder, Role::Writer).await;
    until("bob routes carol's namespace", LONG, async || {
        bob.sink.joined_now() == vec![(face_of(&bob, ann.key), carols.ns.clone())]
    })
    .await;

    // Bob admits Ann's tablet by a grant: its key is another key of `/alice`.
    bob.links.grant(Grant {
        key: tablet.key,
        namespaces: vec![alice.ns.clone()],
        role: GrantRole::Writer,
        folder: folder.clone(),
        until: None,
    });
    dials(&tablet, &bob)
        .await
        .expect("the tablet's dial to bob, which grants its key");
    until("bob has the tablet's link", LONG, async || {
        linked(&bob, tablet.key)
    })
    .await;
    let tablets_face = face_of(&bob, tablet.key);
    assert_ne!(tablets_face, face_of(&bob, ann.key));
    assert_eq!(
        bob.sink.joined_now(),
        vec![(face_of(&bob, ann.key), carols.ns.clone())],
        "a link of another key got a route"
    );
    assert!(
        bob.sink
            .calls()
            .iter()
            .all(|c| !matches!(c, common::recording::Call::AddRoutes(f, r)
                if *f == tablets_face && r.iter().any(|r| r.cost == JOINED_ROUTE_COST && !is_public_name(&r.prefix)))),
        "the tablet's link to Bob was given the joiner's routes"
    );
}

/// A joiner that restarts is routed from what its device holds: the folders
/// it joined are given to the links when the host serves the device again
/// (`LinkHints::serve`), before any link is up, and the link it dials then
/// has the route at registration.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restarted_joiner_is_routed_from_its_device_when_the_link_is_up() {
    let alice = Person::new("/alice").await;
    let bobs = Person::self_certifying([0xb2; 32]).await;
    let carols = Person::self_certifying([0xc2; 32]).await;
    let ann = embedded(&alice, common::ANN, Setup::inviter()).await;
    let bob = embedded(&bobs, &bobs.device("phone"), Setup::dialer()).await;
    let carol = embedded(&carols, &carols.device("phone"), Setup::dialer()).await;
    let folder = n(common::FOLDER);
    invited(&ann, &bob, Role::Writer).await;
    invited_in(&ann, &carol, &folder, Role::Writer).await;
    until("bob routes carol's namespace", LONG, async || {
        bob.sink.joined_now() == vec![(face_of(&bob, ann.key), carols.ns.clone())]
    })
    .await;

    let bob = bob.restart(Setup::dialer()).await;
    until("bob dials ann again", LONG, async || {
        dials(&bob, &ann).await.is_ok()
    })
    .await;
    until(
        "the restarted joiner is routed carol's namespace",
        LONG,
        async || bob.sink.joined_now() == vec![(face_of(&bob, ann.key), carols.ns.clone())],
    )
    .await;
}

/// Ann's members record for `folder` again, with `person`, a reader, listed
/// as a writer too.
async fn promote(ann: &Embedded, folder: &Name, person: &Name) {
    ann.heap(folder)
        .change(MembersChange {
            add_writers: vec![person.clone()],
            ..MembersChange::default()
        })
        .await
        .unwrap();
}

/// Ann's members record for `folder` again, without `person`: a removal takes
/// the person from both roles (a writer demoted to a reader is this removal
/// and an admission, so the removal ends the person's grant and mirror).
async fn removes(ann: &Embedded, folder: &Name, person: &Name) {
    ann.heap(folder)
        .change(MembersChange {
            remove: vec![person.clone()],
            ..MembersChange::default()
        })
        .await
        .unwrap();
}

/// A reader-role joiner (Bob reads the folder Carol writes in) is routed the
/// writer's namespace and **not her sync group**, the writer-push route: it
/// lets a device push and hear notices, and a reader has none. The routes
/// follow the record's role at the next notification: a record that promotes
/// Bob to a writer brings the group route, one that demotes him takes it away
/// and leaves the namespace. Bob's host makes no route of its own (by name).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reader_joiner_is_routed_the_namespace_and_not_the_group_until_a_record_promotes_it() {
    let alice = Person::new("/alice").await;
    let bobs = Person::self_certifying([0xb2; 32]).await;
    let carols = Person::self_certifying([0xc2; 32]).await;
    let named = Setup {
        scoped_by_name: true,
        ..Setup::dialer()
    };
    let ann = embedded(&alice, common::ANN, Setup::inviter()).await;
    let bob = embedded(&bobs, &bobs.device("phone"), named.clone()).await;
    let carol = embedded(&carols, &carols.device("phone"), named).await;
    let folder = n(common::FOLDER);
    let group = sync_group(&carols.ns);
    invited(&ann, &bob, Role::Reader).await;
    invited_in(&ann, &carol, &folder, Role::Writer).await;
    until(
        "a reader is routed the writer's namespace",
        LONG,
        async || bob.sink.joined_now() == vec![(face_of(&bob, ann.key), carols.ns.clone())],
    )
    .await;
    let face = face_of(&bob, ann.key);
    assert_eq!(
        fib_cost(&bob, &carols.ns, face),
        Some(JOINED_ROUTE_COST),
        "a reader's FIB lacks the writer's namespace"
    );
    assert_eq!(
        fib_cost(&bob, &group, face),
        None,
        "a reader was routed the writer's sync group"
    );
    assert!(!bob.sink.routed_at_joiner_cost(face, &group));

    // A record that makes Bob a writer: the group is routed.
    promote(&ann, &folder, &bobs.ns).await;
    until(
        "the promoted joiner is routed the group",
        LONG,
        async || fib_cost(&bob, &group, face_of(&bob, ann.key)) == Some(JOINED_ROUTE_COST),
    )
    .await;

    // One that removes Bob (the heap has no demotion in place: a writer made a
    // reader is a removal and an admission, and the removal ends the mirror):
    // every route of the joiner goes, the group's and the namespace's.
    removes(&ann, &folder, &bobs.ns).await;
    until("the removed joiner loses its routes", LONG, async || {
        bob.sink.joined_now().is_empty() && fib_cost(&bob, &group, face).is_none()
    })
    .await;
    assert_eq!(bob.sink.ever_joined(), vec![carols.ns.clone()]);
}
