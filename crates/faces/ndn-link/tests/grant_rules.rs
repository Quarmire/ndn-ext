//! What a grant admits, at the level of the admission rules, on real QUIC
//! links over loopback (the devices-and-forwarders cases are `tests/grants.rs`;
//! ndn-rs `ndn-link.md` §8.7).
//!
//! Ann's relay keeps `own`: it holds the namespaces A (its own, certified),
//! B and C (held, no certificate in them), and a grant for one key of B.
//! The key is served and no other is; of what the key's hello shows, only the
//! granted namespace is admitted and routed; a grant that is replaced with
//! other namespaces, revoked, or run out ends the link it alone admitted.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use parking_lot::Mutex;

use ndn_face_quic::{
    Admission, CloseReason, Direction, KeyFingerprint, LinkEndpoint, LinkError, LinkHello, LinkKey,
    LinkKeySource, LinkTransportConfig, Membership,
};
use ndn_link::{
    ConfiguredEndpoints, FaceSink, Grant, GrantRole, LinkMemory, LinkSetup, LinkTrust, Links,
    MemoryFuture, MemoryOptions, OwnMembership, PeerRecord, PeerSpec, Route,
};
use ndn_packet::{Data, Name};
use ndn_security::{
    Certificate, Ed25519Signer, Keyring, SignedTrustContext, Signer, encode_cert_data,
};
use ndn_transport::{Face, FaceId, FaceKind};
use tokio_util::sync::CancellationToken;

/// The folder of Ann's every grant here: its collections are what a grant
/// link carries.
const FOLDER: &str = "/a/32=data/notes";

const T: Duration = Duration::from_secs(10);

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

/// What Ann routes over the link of a grant for `/b`: the person's device
/// and sync group, and the public names of `/b` outside the devices (its
/// trust context, the root's key and the CA's key).
fn routes_of_a_grant_for_b() -> Vec<Name> {
    let mut routes = vec![
        n("/b/member/phone"),
        n("/b/32=sync"),
        ndn_cert::onboarding::rdr_prefix(&n("/b")),
        n("/b/KEY"),
        n("/b/CA/KEY"),
    ];
    routes.sort();
    routes
}

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

    fn membership(&self, namespace: &Namespace) -> OwnMembership {
        OwnMembership {
            namespace: namespace.name.clone(),
            chain: self.chain.clone(),
            signer: Arc::clone(&self.signer) as Arc<dyn Signer>,
        }
    }

    /// Its chain as a hello carries it: ending in the namespace's root.
    fn hello_chain(&self, namespace: &Namespace) -> Vec<Bytes> {
        let mut chain = self.chain.clone();
        chain.push(namespace.root.clone());
        chain
    }
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

struct Trust {
    keyring: Arc<Keyring>,
    chain: Vec<Bytes>,
    memberships: Vec<OwnMembership>,
}

impl Trust {
    fn new(held: &[&Namespace], chain: Vec<Bytes>, memberships: Vec<OwnMembership>) -> Self {
        let keyring = Keyring::new();
        for ns in held {
            keyring.adopt(ns.context()).unwrap();
        }
        Self {
            keyring: Arc::new(keyring),
            chain,
            memberships,
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
    fn own_memberships(&self) -> Vec<OwnMembership> {
        self.memberships.clone()
    }
    fn known_certificate(&self, _: &Name) -> Option<Certificate> {
        None
    }
    fn known_certificate_of_key(&self, _: &KeyFingerprint) -> Option<Certificate> {
        None
    }
}

/// The link faces and routes a device's forwarder gets.
#[derive(Default)]
struct Recorder {
    next: AtomicU64,
    live: Mutex<Vec<FaceId>>,
    faces: Mutex<Vec<(FaceId, Arc<Face>)>>,
    routes: Mutex<Vec<(FaceId, Route)>>,
    changed: tokio::sync::Notify,
}

impl Recorder {
    /// Send `packet` over the one link face this side has.
    async fn send(&self, packet: &Bytes) {
        let face = self.faces.lock().last().map(|(_, f)| Arc::clone(f));
        face.expect("a link face")
            .send_bytes(packet.clone())
            .await
            .expect("the link carries a send");
    }

    /// The next packet the link face delivers (what its scope let through).
    async fn receive(&self) -> Bytes {
        let face = self.faces.lock().last().map(|(_, f)| Arc::clone(f));
        face.expect("a link face")
            .recv_bytes()
            .await
            .expect("the link delivers")
    }

    fn sorted_routes(&self) -> Vec<Name> {
        let mut routed: Vec<Name> = self
            .routes
            .lock()
            .iter()
            .map(|(_, r)| r.prefix.clone())
            .collect();
        routed.sort();
        routed
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
        tokio::time::timeout(T, wait)
            .await
            .unwrap_or_else(|_| panic!("{what}: not within {} s", T.as_secs()));
    }
}

impl FaceSink for Recorder {
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
        if self.live.lock().contains(&face) {
            self.routes
                .lock()
                .extend(routes.iter().map(|r| (face, r.clone())));
        }
        self.changed.notify_waiters();
    }
    fn remove_routes(&self, face: FaceId, prefixes: &[Name]) {
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

fn start(
    key: LinkKey,
    trust: Trust,
    peers: Vec<PeerSpec>,
    listen: bool,
    cancel: &CancellationToken,
) -> (Arc<Links>, Arc<Recorder>, Option<String>) {
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
    let faces = Arc::new(Recorder::default());
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
            service: Default::default(),
            direct: Default::default(),
            reliability: Default::default(),
        },
        cancel.child_token(),
    );
    (links, faces, addr)
}

/// Ann as a device of another namespace dials her: by her key (a device not
/// enrolled in A has no business naming a device of A).
fn ann_peer(ann: &Links, endpoint: &str) -> PeerSpec {
    PeerSpec {
        label: "ann".into(),
        key: ann.key_fingerprint(),
        endpoints: vec![endpoint.to_string()],
        persistent: false,
        ..PeerSpec::default()
    }
}

/// Dial `addr` with link key `key` and `certificates`, no memberships, and
/// say how the other side answered: its verdict, or the reason and text it
/// closed with.
async fn dial_with(
    addr: &str,
    key: LinkKey,
    certificates: Vec<Bytes>,
    memberships: impl AsyncFnOnce(&[u8; 32]) -> Vec<Membership>,
) -> Result<(), LinkError> {
    let endpoint = LinkEndpoint::bind(
        "127.0.0.1:0".parse().unwrap(),
        Arc::new(key),
        &LinkTransportConfig::default(),
        false,
    )
    .unwrap();
    let mut hs = endpoint.connect(addr.parse().unwrap(), None).await?;
    let channel = hs.channel_binding()?;
    let hello = LinkHello {
        certificates,
        memberships: memberships(&channel).await,
        direct_path: None,
    };
    hs.exchange_hello(&hello, T).await?;
    hs.admit(FaceId(1), T, Admission::default()).await.map(drop)
}

/// The refusal `result` is: its close reason and the sentence it carries.
fn refusal(result: Result<(), LinkError>) -> (Option<CloseReason>, String) {
    match result {
        Err(LinkError::Refused { reason, text }) => (reason, text),
        Err(e) => panic!("expected a refusal, got {e}"),
        Ok(()) => panic!("expected a refusal, the link was admitted"),
    }
}

fn an_hour_on() -> SystemTime {
    SystemTime::now() + Duration::from_secs(3600)
}

/// Ann: a relay of A holding B and C too, serving `own`.
async fn ann(
    a: &Namespace,
    b: &Namespace,
    c: &Namespace,
    cancel: &CancellationToken,
) -> (Arc<Links>, Arc<Recorder>, String) {
    let key = a.device("node", "relay", 90).await;
    let (links, faces, addr) = start(
        key.link_key(),
        Trust::new(&[a, b, c], key.chain.clone(), Vec::new()),
        Vec::new(),
        true,
        cancel,
    );
    (links, faces, addr.unwrap())
}

/// A grant of one key of B links that key — and routes B's device and B's
/// sync group, nothing of the other namespace its hello shows (a membership
/// of C) — and links no other key of B. Replacing the grant with one for
/// another namespace, a later one for the same, revoking it and its running
/// out each do what they say.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_grant_links_its_key_in_its_namespace_and_routes_nothing_else_it_shows() {
    let cancel = CancellationToken::new();
    let (a, b, c) = (
        namespace("/a", 10).await,
        namespace("/b", 20).await,
        namespace("/c", 30).await,
    );
    let (ann_links, at_ann, addr) = ann(&a, &b, &c, &cancel).await;
    let phone_b = b.device("member", "phone", 22).await;
    let phone_c = c.device("member", "phone", 32).await;
    let other_b = b.device("member", "tablet", 23).await;

    // No grant: Ann holds B and has no certificate in it; `own` refuses.
    let (reason, text) = refusal(
        dial_with(
            &addr,
            phone_b.link_key(),
            phone_b.hello_chain(&b),
            async |_| Vec::new(),
        )
        .await,
    );
    assert_eq!(reason, Some(CloseReason::NotServed), "{text}");
    assert!(text.contains("inviting you"), "{text}");
    assert!(at_ann.live.lock().is_empty());

    // Granted: the phone links, shows its C membership too, and is routed as
    // B's device only.
    ann_links.grant(Grant {
        key: phone_b.fingerprint(),
        namespaces: vec![n("/b")],
        role: GrantRole::Writer,
        folder: n(FOLDER),
        until: Some(an_hour_on()),
    });
    let (_phone, at_phone, _) = start(
        phone_b.link_key(),
        Trust::new(
            &[&a, &b, &c],
            phone_b.chain.clone(),
            vec![phone_c.membership(&c)],
        ),
        vec![ann_peer(&ann_links, &addr)],
        false,
        &cancel,
    );
    at_ann
        .settles("ann routes the phone", |f| !f.sorted_routes().is_empty())
        .await;
    let expected = routes_of_a_grant_for_b();
    assert_eq!(
        at_ann.sorted_routes(),
        expected,
        "a grant for B carried C's membership, or lost B's routes"
    );
    assert_eq!(at_ann.live.lock().len(), 1);
    at_phone
        .settles("the phone has its link", |f| f.live.lock().len() == 1)
        .await;
    assert_eq!(at_phone.live.lock().len(), 1);
    let report = ann_links.report();
    let link = report.links.first().expect("a link");
    assert!(link.granted.is_some(), "{link:#?}");

    // Another key of B gets nothing from it.
    let (reason, text) = refusal(
        dial_with(
            &addr,
            other_b.link_key(),
            other_b.hello_chain(&b),
            async |_| Vec::new(),
        )
        .await,
    );
    assert_eq!(reason, Some(CloseReason::NotServed), "{text}");
    assert_eq!(at_ann.live.lock().len(), 1, "another key of B was linked");

    // A later `until` for the same namespaces leaves the link as it is, and
    // the report shows the new date.
    let face = at_ann.live.lock()[0];
    let later = an_hour_on() + Duration::from_secs(60);
    ann_links.grant(Grant {
        key: phone_b.fingerprint(),
        namespaces: vec![n("/b")],
        role: GrantRole::Writer,
        folder: n(FOLDER),
        until: Some(later),
    });
    assert_eq!(
        ann_links.report().links[0].granted.as_ref().unwrap().until,
        Some(later)
    );
    assert_eq!(
        *at_ann.live.lock(),
        vec![face],
        "a later `until` made the link again"
    );

    // The same key granted for another namespace ends the link the old grant
    // admitted: it was admitted in B.
    ann_links.grant(Grant {
        key: phone_b.fingerprint(),
        namespaces: vec![n("/c")],
        role: GrantRole::Writer,
        folder: n(FOLDER),
        until: Some(later),
    });
    at_ann
        .settles("the link of the replaced grant closes", |f| {
            f.live.lock().is_empty()
        })
        .await;

    // Revoked: the next dial names it.
    assert!(ann_links.revoke_grants(&phone_b.fingerprint()));
    let (reason, text) = refusal(
        dial_with(
            &addr,
            phone_b.link_key(),
            phone_b.hello_chain(&b),
            async |_| Vec::new(),
        )
        .await,
    );
    assert_eq!(reason, Some(CloseReason::NotServed), "{text}");
    assert!(
        text.contains("the grant ended") && text.contains("revoked"),
        "{text}"
    );
    assert!(ann_links.grants().is_empty());
    cancel.cancel();
}

/// The same key presenting another namespace than the granted one is linked
/// for the granted one only: its link key is certified in C (not granted), its
/// membership is of B (granted), and what is routed is B's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_same_key_showing_another_namespace_is_linked_for_the_granted_one_only() {
    let cancel = CancellationToken::new();
    let (a, b, c) = (
        namespace("/a", 10).await,
        namespace("/b", 20).await,
        namespace("/c", 30).await,
    );
    let (ann_links, at_ann, addr) = ann(&a, &b, &c, &cancel).await;
    let phone_c = c.device("member", "phone", 32).await;
    let phone_b = b.device("member", "phone", 22).await;
    ann_links.grant(Grant {
        key: phone_c.fingerprint(),
        namespaces: vec![n("/b")],
        role: GrantRole::Writer,
        folder: n(FOLDER),
        until: Some(an_hour_on()),
    });
    let (_phone, _, _) = start(
        phone_c.link_key(),
        Trust::new(
            &[&a, &b, &c],
            phone_c.chain.clone(),
            vec![phone_b.membership(&b)],
        ),
        vec![ann_peer(&ann_links, &addr)],
        false,
        &cancel,
    );
    at_ann
        .settles("ann routes the phone", |f| !f.sorted_routes().is_empty())
        .await;
    let expected = routes_of_a_grant_for_b();
    assert_eq!(
        at_ann.sorted_routes(),
        expected,
        "the granted key was routed for a namespace the grant does not list"
    );
    cancel.cancel();
}

/// A grant of a key for a namespace this device holds no context of (so the
/// key is served only by its own root's certificate, which `own` never trusts
/// to serve) links nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_grant_for_a_namespace_not_held_links_nothing() {
    let cancel = CancellationToken::new();
    let (a, b, c) = (
        namespace("/a", 10).await,
        namespace("/b", 20).await,
        namespace("/c", 30).await,
    );
    let d = namespace("/d", 40).await;
    let (ann_links, at_ann, addr) = ann(&a, &b, &c, &cancel).await;
    let dan = d.device("member", "phone", 42).await;
    ann_links.grant(Grant {
        key: dan.fingerprint(),
        namespaces: vec![n("/d")],
        role: GrantRole::Writer,
        folder: n(FOLDER),
        until: Some(an_hour_on()),
    });
    let (reason, text) = refusal(
        dial_with(&addr, dan.link_key(), dan.hello_chain(&d), async |_| {
            Vec::new()
        })
        .await,
    );
    assert_eq!(reason, Some(CloseReason::NotServed), "{text}");
    assert!(at_ann.live.lock().is_empty());
    cancel.cancel();
}

/// A grant that runs out closes the link it admitted at `until`, with no one
/// asking: the task wakes at the earliest `until`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_grant_that_runs_out_closes_its_link_at_until() {
    let cancel = CancellationToken::new();
    let (a, b, c) = (
        namespace("/a", 10).await,
        namespace("/b", 20).await,
        namespace("/c", 30).await,
    );
    let (ann_links, at_ann, addr) = ann(&a, &b, &c, &cancel).await;
    let phone_b = b.device("member", "phone", 22).await;
    let tablet_b = b.device("member", "tablet", 23).await;
    let started = std::time::Instant::now();
    // Two grants: the later one is made first, so the task must wake for the
    // earlier one when it is made.
    ann_links.grant(Grant {
        key: tablet_b.fingerprint(),
        namespaces: vec![n("/b")],
        role: GrantRole::Writer,
        folder: n(FOLDER),
        until: Some(an_hour_on()),
    });
    ann_links.grant(Grant {
        key: phone_b.fingerprint(),
        namespaces: vec![n("/b")],
        role: GrantRole::Writer,
        folder: n(FOLDER),
        until: Some(SystemTime::now() + Duration::from_secs(3)),
    });
    let (_phone, at_phone, _) = start(
        phone_b.link_key(),
        Trust::new(&[&a, &b, &c], phone_b.chain.clone(), Vec::new()),
        vec![ann_peer(&ann_links, &addr)],
        false,
        &cancel,
    );
    at_ann
        .settles("ann links the phone", |f| f.live.lock().len() == 1)
        .await;
    at_ann
        .settles("the link closes at until", |f| f.live.lock().is_empty())
        .await;
    assert!(
        started.elapsed() >= Duration::from_secs(2),
        "the link closed {:?} after a grant of 3 s",
        started.elapsed()
    );
    at_phone
        .settles("the phone sees it closed", |f| f.live.lock().is_empty())
        .await;
    assert_eq!(
        ann_links.grants().len(),
        1,
        "only the other grant is in force"
    );
    let (reason, text) = refusal(
        dial_with(
            &addr,
            phone_b.link_key(),
            phone_b.hello_chain(&b),
            async |_| Vec::new(),
        )
        .await,
    );
    assert_eq!(reason, Some(CloseReason::NotServed), "{text}");
    assert!(text.contains("it expired"), "{text}");
    cancel.cancel();
}

/// Dial `addr` as a device that sends its hello at once and its verdict only
/// after `stall`: the other side has judged the hello (and read the grant)
/// long before, and waits in its handshake for the verdict. The endpoint is
/// returned with the link, which it keeps up.
async fn dial_stalling(
    addr: &str,
    key: LinkKey,
    certificates: Vec<Bytes>,
    stall: impl Future<Output = ()>,
) -> Result<(LinkEndpoint, ndn_face_quic::Link), LinkError> {
    let endpoint = LinkEndpoint::bind(
        "127.0.0.1:0".parse().unwrap(),
        Arc::new(key),
        &LinkTransportConfig::default(),
        false,
    )
    .unwrap();
    let mut hs = endpoint.connect(addr.parse().unwrap(), None).await?;
    let hello = LinkHello {
        certificates,
        memberships: Vec::new(),
        direct_path: None,
    };
    hs.exchange_hello(&hello, T).await?;
    stall.await;
    let link = hs.admit(FaceId(1), T, Admission::default()).await?;
    Ok((endpoint, link))
}

/// How long a stalling dialer waits before its verdict: Ann judged its hello
/// (a few milliseconds on loopback) well before.
const STALL: Duration = Duration::from_millis(1500);

/// A handshake in flight when its grant is revoked: Ann read the grant when
/// the hello came, the grant ended while she waited for the verdict, and the
/// link is registered after the close that revocation made looked for links.
/// It must not stay: the removed person would keep a link by always having a
/// handshake in flight.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_handshake_in_flight_when_its_grant_is_revoked_does_not_keep_its_link() {
    let cancel = CancellationToken::new();
    let (a, b, c) = (
        namespace("/a", 10).await,
        namespace("/b", 20).await,
        namespace("/c", 30).await,
    );
    let (ann_links, at_ann, addr) = ann(&a, &b, &c, &cancel).await;
    let phone_b = b.device("member", "phone", 22).await;
    ann_links.grant(Grant {
        key: phone_b.fingerprint(),
        namespaces: vec![n("/b")],
        role: GrantRole::Writer,
        folder: n(FOLDER),
        until: Some(an_hour_on()),
    });

    let revoke = async {
        tokio::time::sleep(STALL / 3).await;
        assert!(
            ann_links.revoke_grants(&phone_b.fingerprint()),
            "no grant was in force to revoke"
        );
    };
    let dial = dial_stalling(&addr, phone_b.link_key(), phone_b.hello_chain(&b), async {
        tokio::time::sleep(STALL).await;
    });
    let (dialed, ()) = tokio::join!(dial, revoke);
    let (_endpoint, link) = dialed.unwrap_or_else(|e| {
        panic!(
            "the handshake did not straddle the revoke (Ann judged the hello after it, or refused \
             it): {e}"
        )
    });

    // Ann closes it, saying what ended, though the revoke found it unregistered.
    let closed = tokio::time::timeout(T, link.handle.closed())
        .await
        .unwrap_or_else(|_| {
            panic!("the link of a revoked grant stayed up: its handshake straddled the revoke")
        });
    let (reason, text) = refusal(Err::<(), _>(closed));
    assert_eq!(reason, Some(CloseReason::NotServed), "{text}");
    assert!(
        text.contains("the grant ended") && text.contains("revoked"),
        "{text}"
    );
    at_ann
        .settles("ann holds no link", |f| f.live.lock().is_empty())
        .await;
    cancel.cancel();
}

/// The same at the grant's date: a person who knows when it runs out starts a
/// handshake just before and stalls it past.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_handshake_in_flight_when_its_grant_expires_does_not_keep_its_link() {
    let cancel = CancellationToken::new();
    let (a, b, c) = (
        namespace("/a", 10).await,
        namespace("/b", 20).await,
        namespace("/c", 30).await,
    );
    let (ann_links, at_ann, addr) = ann(&a, &b, &c, &cancel).await;
    let phone_b = b.device("member", "phone", 22).await;
    let until = SystemTime::now() + Duration::from_secs(3);
    ann_links.grant(Grant {
        key: phone_b.fingerprint(),
        namespaces: vec![n("/b")],
        role: GrantRole::Writer,
        folder: n(FOLDER),
        until: Some(until),
    });

    let (_endpoint, link) = dial_stalling(
        &addr,
        phone_b.link_key(),
        phone_b.hello_chain(&b),
        async {
            // Past the date, by the wall clock the grant is judged on.
            let wait = until.duration_since(SystemTime::now()).unwrap_or_default()
                + Duration::from_millis(500);
            tokio::time::sleep(wait).await;
        },
    )
    .await
    .unwrap_or_else(|e| {
        panic!(
            "the handshake did not straddle the expiry (Ann judged the hello after it, or refused \
             it): {e}"
        )
    });
    assert!(
        SystemTime::now() > until,
        "the verdict was sent before the grant ran out"
    );

    let closed = tokio::time::timeout(T, link.handle.closed())
        .await
        .unwrap_or_else(|_| {
            panic!(
                "the link of a grant that had run out stayed up: its handshake straddled the date"
            )
        });
    let (reason, text) = refusal(Err::<(), _>(closed));
    assert_eq!(reason, Some(CloseReason::NotServed), "{text}");
    assert!(
        text.contains("the grant ended") && text.contains("it expired"),
        "{text}"
    );
    at_ann
        .settles("ann holds no link", |f| f.live.lock().is_empty())
        .await;
    cancel.cancel();
}

/// A link memory in a map, with one record.
struct Shelf(Mutex<std::collections::HashMap<KeyFingerprint, PeerRecord>>);

impl LinkMemory for Shelf {
    fn load(&self) -> Result<Vec<PeerRecord>, String> {
        Ok(self.0.lock().values().cloned().collect())
    }
    fn save<'a>(&'a self, record: &'a PeerRecord) -> MemoryFuture<'a, Result<(), String>> {
        Box::pin(async move {
            self.0.lock().insert(record.key, record.clone());
            Ok(())
        })
    }
    fn remove<'a>(&'a self, key: &'a KeyFingerprint) -> MemoryFuture<'a, Result<(), String>> {
        Box::pin(async move {
            self.0.lock().remove(key);
            Ok(())
        })
    }
    fn load_listen_port(&self) -> Result<Option<u16>, String> {
        Ok(None)
    }
    fn save_listen_port<'a>(&'a self, _: Option<u16>) -> MemoryFuture<'a, Result<(), String>> {
        Box::pin(async { Ok(()) })
    }
}

/// Ann remembers Bob, who dialled in first and whom her grant links, and Bob
/// grants Ann in turn (mutual invitations): when the link drops, Ann's
/// redial of Bob is a link Bob's grant admits on his side and hers does on
/// Ann's. It must carry Ann's grant — in her report, and so that the grant's
/// end closes it — as the link Bob dialled in on did, not be admitted by the
/// remembered entry with no grant, no quota and no scope.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_redial_of_a_remembered_peer_that_linked_in_is_the_grants_and_its_end_closes_it() {
    let cancel = CancellationToken::new();
    let (a, b, c) = (
        namespace("/a", 10).await,
        namespace("/b", 20).await,
        namespace("/c", 30).await,
    );
    let (ann_links, at_ann, _) = ann(&a, &b, &c, &cancel).await;
    let phone_b = b.device("member", "phone", 22).await;
    let (bob_links, _, bob_addr) = start(
        phone_b.link_key(),
        Trust::new(&[&a, &b], phone_b.chain.clone(), Vec::new()),
        Vec::new(),
        true,
        &cancel,
    );
    let hour = Some(an_hour_on());
    // Mutual: each grants the other's key.
    ann_links.grant(Grant {
        key: phone_b.fingerprint(),
        namespaces: vec![n("/b")],
        role: GrantRole::Writer,
        folder: n(FOLDER),
        until: hour,
    });
    bob_links.grant(Grant {
        key: ann_links.key_fingerprint().expect("ann has a key"),
        namespaces: vec![n("/a")],
        role: GrantRole::Writer,
        folder: n("/b/32=data/notes"),
        until: hour,
    });

    // What Ann's memory holds of Bob, who first dialled in.
    let shelf = Arc::new(Shelf(Mutex::new(
        [PeerRecord {
            key: phone_b.fingerprint(),
            device: n("/b/member/phone"),
            addresses: vec![bob_addr.expect("bob listens").parse().unwrap()],
            last_contact: SystemTime::now(),
            origin: Direction::Accepted,
            port: None,
        }]
        .into_iter()
        .map(|r| (r.key, r))
        .collect(),
    )));
    ann_links.remember(
        shelf,
        MemoryOptions {
            include_local: true,
            ..MemoryOptions::default()
        },
    );
    at_ann
        .settles("ann redials bob", |f| f.live.lock().len() == 1)
        .await;

    let report = ann_links.report();
    let link = report.links.first().expect("a link");
    assert!(
        link.granted.is_some(),
        "the redial of a remembered peer that dialled in carries no grant: {link:#?}"
    );

    // Bob is removed: the grant ends, and the redial's link closes with it.
    assert!(ann_links.revoke_grants(&phone_b.fingerprint()));
    at_ann
        .settles("the redial's link closes with the grant", |f| {
            f.live.lock().is_empty()
        })
        .await;
    cancel.cancel();
}

/// The role of a grant is the one the members record in force gives now (the
/// data layer derives it again and calls `grant` again): a writer demoted to a
/// reader no longer pushes what a writer pushes, **at the next packet, on the
/// same link** — the link is not closed (round 7: it was, in round 6, saying
/// it was replaced; the invariant is now no weaker: what the old role pushed
/// is dropped at once, and a promotion widens it again at once).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_grant_whose_role_changed_narrows_the_pushes_at_the_next_packet() {
    let cancel = CancellationToken::new();
    let (a, b, c) = (
        namespace("/a", 10).await,
        namespace("/b", 20).await,
        namespace("/c", 30).await,
    );
    let (ann_links, at_ann, addr) = ann(&a, &b, &c, &cancel).await;
    let phone_b = b.device("member", "phone", 22).await;
    let grant = |role| Grant {
        key: phone_b.fingerprint(),
        namespaces: vec![n("/b")],
        role,
        folder: n(FOLDER),
        until: None,
    };
    ann_links.grant(grant(GrantRole::Writer));
    let (_phone, at_phone, _) = start(
        phone_b.link_key(),
        Trust::new(&[&a, &b, &c], phone_b.chain.clone(), Vec::new()),
        vec![ann_peer(&ann_links, &addr)],
        false,
        &cancel,
    );
    at_ann
        .settles("ann links the phone as a writer", |f| {
            f.live.lock().len() == 1
        })
        .await;
    at_phone
        .settles("the phone has its link", |f| f.live.lock().len() == 1)
        .await;
    let face = at_ann.live.lock()[0];

    // What the phone pushes: Data under the folder namespace's sync group (a
    // public name a writer's entry carries, a reader's does not) and Data
    // under its own device name (which either role carries).
    let pushed = |name: &str| ndn_packet::encode::DataBuilder::new(n(name), b"x").build();
    let public = "/a/32=sync/probe";
    let own = "/b/member/phone/seal/1";
    let push = async |name: &str| at_phone.send(&pushed(name)).await;
    let arrives = async |name: &str| {
        let got = tokio::time::timeout(Duration::from_secs(5), at_ann.receive())
            .await
            .unwrap_or_else(|_| panic!("{name} did not arrive within 5 s"));
        // The link face delivers the packet in its link-protocol frame.
        let got = match ndn_packet::lp::LpPacket::decode(got.clone()) {
            Ok(lp) => lp.fragment.unwrap_or(got),
            Err(_) => got,
        };
        let seen = ndn_packet::Data::decode(got)
            .map(|d| d.name.to_string())
            .unwrap_or_else(|e| format!("something undecodable ({e:?})"));
        assert_eq!(seen, n(name).to_string(), "the next packet to arrive");
        true
    };

    push(public).await;
    assert!(
        arrives(public).await,
        "a writer's push under a public name crossed"
    );

    // Demoted: the same link, the next packet narrower.
    ann_links.grant(grant(GrantRole::Reader));
    push(public).await;
    push(own).await;
    assert!(
        arrives(own).await,
        "the first packet to arrive after the demotion is the one under its own name: the \
         public one was dropped (a reader pushes only under its own device names)"
    );
    assert_eq!(
        at_ann.live.lock().as_slice(),
        [face],
        "the demotion closed or replaced the link"
    );
    let grants = ann_links.grants();
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].role, GrantRole::Reader);

    // Promoted again: widened at the next packet, still the same link.
    ann_links.grant(grant(GrantRole::Writer));
    push(public).await;
    assert!(
        arrives(public).await,
        "a promotion shows at the next packet"
    );
    assert_eq!(at_ann.live.lock().as_slice(), [face]);
    cancel.cancel();
}

/// A person who writes in one folder and reads in another pushes under the
/// first folder's names only, judged per entry at every packet (round 7 A):
/// the writer's entry of a folder of `/a` carries `/a`'s public names, the
/// reader's entry of a folder of `/c` carries `/c`'s but widens no push
/// scope. Swapping the roles swaps what is dropped, on the same link.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_writer_of_one_folder_and_a_reader_of_another_push_under_the_writers_names_only() {
    let cancel = CancellationToken::new();
    let (a, b, c) = (
        namespace("/a", 10).await,
        namespace("/b", 20).await,
        namespace("/c", 30).await,
    );
    let (ann_links, at_ann, addr) = ann(&a, &b, &c, &cancel).await;
    let phone_b = b.device("member", "phone", 22).await;
    let (first, second) = (n(FOLDER), n("/c/32=data/other"));
    let entry = |folder: &Name, role| Grant {
        key: phone_b.fingerprint(),
        namespaces: vec![n("/b")],
        role,
        folder: folder.clone(),
        until: None,
    };
    ann_links.grant(entry(&first, GrantRole::Writer));
    ann_links.grant(entry(&second, GrantRole::Reader));
    let (_phone, at_phone, _) = start(
        phone_b.link_key(),
        Trust::new(&[&a, &b, &c], phone_b.chain.clone(), Vec::new()),
        vec![ann_peer(&ann_links, &addr)],
        false,
        &cancel,
    );
    at_ann
        .settles("ann links the phone", |f| f.live.lock().len() == 1)
        .await;
    at_phone
        .settles("the phone has its link", |f| f.live.lock().len() == 1)
        .await;
    let face = at_ann.live.lock()[0];

    let (in_a, in_c) = ("/a/32=sync/probe", "/c/32=sync/probe");
    let push = async |name: &str| {
        at_phone
            .send(&ndn_packet::encode::DataBuilder::new(n(name), b"x").build())
            .await
    };
    // What arrived next at Ann, by its name.
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

    // The reader's folder's name is pushed first and dropped: the first to
    // arrive is the writer's.
    push(in_c).await;
    push(in_a).await;
    assert_eq!(
        next().await,
        n(in_a).to_string(),
        "a Data under the names of a folder the person only reads crossed"
    );

    // Swapped: the same link, the next packets judged by the new roles.
    ann_links.grant(entry(&first, GrantRole::Reader));
    ann_links.grant(entry(&second, GrantRole::Writer));
    push(in_a).await;
    push(in_c).await;
    assert_eq!(
        next().await,
        n(in_c).to_string(),
        "a Data under the names of a folder the person now only reads crossed"
    );
    assert_eq!(
        at_ann.live.lock().as_slice(),
        [face],
        "a role change closed the link"
    );
    cancel.cancel();
}
