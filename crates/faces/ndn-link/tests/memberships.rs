//! A device takes part in several namespaces with one link key: its hello
//! carries its link key's chain (namespace A) and a membership of C (its C
//! key's chain, bound to the connection). Over loopback: a relay serving
//! only C admits it by its C membership; a relay of A alone still admits it
//! by its link key's certificate; a membership whose binding is not the
//! certificate key's, or was made for another connection, is refused; a
//! hello without memberships (an older device) links, and an older
//! listener that skips memberships admits a newer device by its link key.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use parking_lot::Mutex;

use ndn_face_quic::{
    Admission, CloseReason, KeyFingerprint, LinkEndpoint, LinkError, LinkHello, LinkKey,
    LinkKeySource, LinkTransportConfig, MEMBERSHIP, Membership, PeerKey,
};
use ndn_link::{
    ConfiguredEndpoints, FaceSink, LinkSetup, LinkTrust, Links, OwnMembership, PeerSpec,
    RelaySource, RelayUse, Route,
};
use ndn_packet::{Data, Name};
use ndn_security::{
    Certificate, Ed25519Signer, Keyring, SignedTrustContext, Signer, encode_cert_data,
};
use ndn_transport::{Face, FaceId, FaceKind};
use tokio_util::sync::CancellationToken;

const T: Duration = Duration::from_secs(5);

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

fn now_ns() -> u64 {
    let since = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    u64::try_from(since.as_nanos()).unwrap()
}

/// A certificate Data of `key` (a key name) for `public_key`, issued by
/// `issuer`, valid from an hour ago for a day.
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
/// certificate, and the CA (`<ns>/CA`) the root certified.
struct Namespace {
    name: Name,
    root: Bytes,
    ca: Ed25519Signer,
    ca_cert: Bytes,
}

/// One device key in a namespace: its signer, and its chain as the device
/// keeps it (its certificate, then its CA's).
struct DeviceKey {
    signer: Arc<Ed25519Signer>,
    chain: Vec<Bytes>,
}

impl DeviceKey {
    fn link_key(&self) -> LinkKey {
        LinkKey::from_signer(Arc::clone(&self.signer) as Arc<dyn Signer>).unwrap()
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
    /// Its trust context, as a device holding it has it.
    fn context(&self) -> Arc<SignedTrustContext> {
        self.context_revoking(1, None)
    }

    /// Its trust context at `version`, revoking `revoked` when given.
    fn context_revoking(&self, version: u64, revoked: Option<&str>) -> Arc<SignedTrustContext> {
        let schema = ndn_cert::namespace_schema(&self.name).unwrap();
        let mut ctx = SignedTrustContext::hierarchical(self.name.clone())
            .with_schema_blobs(schema.blobs())
            .unwrap()
            .schema_authoritative()
            .with_ca_endpoint(self.name.clone().append("CA"))
            .with_version(version);
        if let Some(name) = revoked {
            ctx = ctx.with_revocation(n(name));
        }
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

/// A device's trust data: the namespaces it holds, its link key's chain,
/// and its memberships of others.
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

/// The link faces and routes a device's forwarder gets: a face's routes go
/// with it, as a forwarder drops them when the face is removed.
#[derive(Default)]
struct Recorder {
    next: AtomicU64,
    live: Mutex<Vec<FaceId>>,
    routes: Mutex<Vec<(FaceId, Route)>>,
    /// Woken on every change of the faces or routes.
    changed: tokio::sync::Notify,
}

impl Recorder {
    fn routed(&self) -> Vec<Name> {
        self.routes
            .lock()
            .iter()
            .map(|(_, r)| r.prefix.clone())
            .collect()
    }

    fn sorted_routes(&self) -> Vec<Name> {
        let mut routed = self.routed();
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
        }
        self.changed.notify_waiters();
    }
    fn remove_face(&self, face: FaceId) {
        self.live.lock().retain(|f| *f != face);
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
    fn transit(&self, _: &Name, _: bool) {}
}

/// Start a device with link key `key`, trust `trust` and peers `peers`;
/// listening when `listen`. Returns its links, its forwarder, and the
/// address it listens at.
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
        },
        cancel.child_token(),
    );
    (links, faces, addr)
}

fn relay_peer(device: &str, endpoint: Option<String>) -> PeerSpec {
    PeerSpec {
        label: device.into(),
        device: Some(n(device)),
        endpoints: endpoint.into_iter().collect(),
        persistent: false,
        ..PeerSpec::default()
    }
}

async fn until(what: &str, mut done: impl FnMut() -> bool) {
    let start = tokio::time::Instant::now();
    while start.elapsed() < T {
        if done() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("{what}: not within {} s", T.as_secs());
}

/// The device of these tests: its link key is `/a/member/phone`'s, and it
/// is a member of C as `/c/member/phone` with another key.
struct Phone {
    a: DeviceKey,
    c: DeviceKey,
}

async fn phone(a: &Namespace, c: &Namespace) -> Phone {
    Phone {
        a: a.device("member", "phone", 12).await,
        c: c.device("member", "phone", 32).await,
    }
}

/// A relay serving only C (it holds C alone, and is `/c/node/relay`)
/// admits the device holding A by its link key and C by a membership — by
/// that membership, and routes it as its C device only, with C's sync
/// group. The device knows the relay by its own C membership.
#[tokio::test]
async fn a_relay_serving_only_c_admits_an_a_and_c_device_by_its_c_membership() {
    let cancel = CancellationToken::new();
    let (a, c) = (namespace("/a", 10).await, namespace("/c", 30).await);
    let relay_key = c.device("node", "relay", 90).await;
    let (_relay, at_relay, addr) = start(
        relay_key.link_key(),
        Trust::new(&[&c], relay_key.chain.clone(), Vec::new()),
        Vec::new(),
        true,
        &cancel,
    );
    let phone = phone(&a, &c).await;
    let (_phone, at_phone, _) = start(
        phone.a.link_key(),
        Trust::new(
            &[&a, &c],
            phone.a.chain.clone(),
            vec![phone.c.membership(&c)],
        ),
        vec![relay_peer("/c/node/relay", addr)],
        false,
        &cancel,
    );
    until("both sides link", || {
        at_relay.live.lock().len() == 1 && at_phone.live.lock().len() == 1
    })
    .await;
    until("the relay routes the phone", || {
        !at_relay.routed().is_empty()
    })
    .await;
    assert_eq!(at_relay.routed(), [n("/c/member/phone"), n("/c/32=sync")]);
    // The relay is a node of C this device dials: C goes there, and C's
    // sync group.
    assert_eq!(at_phone.routed(), [n("/c"), n("/c/32=sync")]);
    cancel.cancel();
}

/// A relay of A alone admits the same device by its link key's certificate,
/// as before memberships: its C membership is of a namespace the relay
/// neither holds nor serves, and only A is routed (with A's sync group).
#[tokio::test]
async fn an_a_only_relay_admits_the_device_by_its_link_key_as_before() {
    let cancel = CancellationToken::new();
    let (a, c) = (namespace("/a", 10).await, namespace("/c", 30).await);
    let relay_key = a.device("node", "relay", 91).await;
    let (_relay, at_relay, addr) = start(
        relay_key.link_key(),
        Trust::new(&[&a], relay_key.chain.clone(), Vec::new()),
        Vec::new(),
        true,
        &cancel,
    );
    let phone = phone(&a, &c).await;
    let (_phone, at_phone, _) = start(
        phone.a.link_key(),
        Trust::new(
            &[&a, &c],
            phone.a.chain.clone(),
            vec![phone.c.membership(&c)],
        ),
        vec![relay_peer("/a/node/relay", addr)],
        false,
        &cancel,
    );
    until("both sides link", || {
        at_relay.live.lock().len() == 1 && at_phone.live.lock().len() == 1
    })
    .await;
    until("the relay routes the phone", || {
        !at_relay.routed().is_empty()
    })
    .await;
    assert_eq!(at_relay.routed(), [n("/a/member/phone"), n("/a/32=sync")]);
    cancel.cancel();
}

/// Dial `addr` with link key `key`, send `hello` (its memberships made by
/// `memberships` from this connection's binding value), and return how the
/// other side answered: its verdict, or the reason it closed with.
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

fn refused_with(result: Result<(), LinkError>, code: CloseReason) {
    match result {
        Err(LinkError::Refused { reason, text }) => assert_eq!(reason, Some(code), "{text}"),
        Err(e) => panic!("expected a refusal with {code:?}, got {e}"),
        Ok(()) => panic!("expected a refusal with {code:?}, the link was admitted"),
    }
}

/// A membership of C whose binding is signed by a key that is not the C
/// certificate's (the sender does not hold it) is refused, saying why,
/// and the relay installs nothing.
#[tokio::test]
async fn a_membership_bound_by_another_key_than_its_certificates_is_refused() {
    let cancel = CancellationToken::new();
    let (a, c) = (namespace("/a", 10).await, namespace("/c", 30).await);
    let relay_key = c.device("node", "relay", 90).await;
    let (_relay, at_relay, addr) = start(
        relay_key.link_key(),
        Trust::new(&[&c], relay_key.chain.clone(), Vec::new()),
        Vec::new(),
        true,
        &cancel,
    );
    let addr = addr.unwrap();
    let phone = phone(&a, &c).await;
    let link_key = phone.a.link_key();
    let fingerprint = link_key.fingerprint();
    let forger = Ed25519Signer::from_seed(&[77; 32], n("/c/member/phone/KEY/forged"));
    let c_chain = phone.c.hello_chain(&c);
    let result = dial_with(&addr, link_key, phone.a.hello_chain(&a), async |channel| {
        vec![
            Membership::sign(&forger, &fingerprint, channel, c_chain)
                .await
                .unwrap(),
        ]
    })
    .await;
    refused_with(result, CloseReason::MembershipNotBound);
    assert!(at_relay.live.lock().is_empty());
    cancel.cancel();
}

/// A membership bound by its own key, but for another connection (a
/// binding replayed onto this one), is refused.
#[tokio::test]
async fn a_membership_bound_to_another_connection_is_refused() {
    let cancel = CancellationToken::new();
    let (a, c) = (namespace("/a", 10).await, namespace("/c", 30).await);
    let relay_key = c.device("node", "relay", 90).await;
    let (_relay, at_relay, addr) = start(
        relay_key.link_key(),
        Trust::new(&[&c], relay_key.chain.clone(), Vec::new()),
        Vec::new(),
        true,
        &cancel,
    );
    let addr = addr.unwrap();
    let phone = phone(&a, &c).await;
    let fingerprint = phone.a.link_key().fingerprint();
    // The binding value of one connection…
    let first = LinkEndpoint::bind(
        "127.0.0.1:0".parse().unwrap(),
        Arc::new(phone.a.link_key()),
        &LinkTransportConfig::default(),
        false,
    )
    .unwrap();
    let other = first
        .connect(addr.parse().unwrap(), None)
        .await
        .unwrap()
        .channel_binding()
        .unwrap();
    // …shown on another.
    let c_chain = phone.c.hello_chain(&c);
    let signer = Arc::clone(&phone.c.signer);
    let result = dial_with(
        &addr,
        phone.a.link_key(),
        phone.a.hello_chain(&a),
        async |channel| {
            assert_ne!(*channel, other, "two connections share no binding value");
            vec![
                Membership::sign(signer.as_ref(), &fingerprint, &other, c_chain)
                    .await
                    .unwrap(),
            ]
        },
    )
    .await;
    refused_with(result, CloseReason::MembershipNotBound);
    assert!(at_relay.live.lock().is_empty());
    cancel.cancel();
}

/// A hello without memberships, as a device before them sends it, links
/// with a relay that knows them; and a listener before them, which skips
/// the Membership elements (an even TLV-TYPE above 31) and reads only the
/// link key's chain, links with a device that sends them.
#[tokio::test]
async fn hellos_without_memberships_and_listeners_without_them_still_link() {
    let cancel = CancellationToken::new();
    let c = namespace("/c", 30).await;
    // An older device of C: its link key is its C key, its hello carries
    // that key's chain only.
    let relay_key = c.device("node", "relay", 90).await;
    let (_relay, at_relay, addr) = start(
        relay_key.link_key(),
        Trust::new(&[&c], relay_key.chain.clone(), Vec::new()),
        Vec::new(),
        true,
        &cancel,
    );
    let old = c.device("member", "old", 40).await;
    dial_with(
        &addr.unwrap(),
        old.link_key(),
        old.hello_chain(&c),
        async |_| Vec::new(),
    )
    .await
    .unwrap();
    until("the relay links the older device", || {
        at_relay.live.lock().len() == 1
    })
    .await;

    // An older listener: it skips what it does not know.
    const { assert!(MEMBERSHIP > 31 && MEMBERSHIP.is_multiple_of(2)) };
    let a = namespace("/a", 10).await;
    let listener_key = c.device("node", "old-relay", 91).await;
    let listener = LinkEndpoint::bind(
        "127.0.0.1:0".parse().unwrap(),
        Arc::new(listener_key.link_key()),
        &LinkTransportConfig::default(),
        true,
    )
    .unwrap();
    let listen_at = listener.local_addr().unwrap().to_string();
    let phone = phone(&a, &c).await;
    let phone_a_key = PeerKey::from_spki(phone.a.link_key().spki()).unwrap();
    let older = async {
        let mut hs = listener.accept().await.unwrap().handshake().await.unwrap();
        let ours = LinkHello {
            certificates: listener_key.hello_chain(&c),
            ..LinkHello::default()
        };
        let theirs = hs.exchange_hello(&ours, T).await.unwrap();
        // Its link key's chain is A's; the C membership rides along.
        assert_eq!(hs.peer_key(), &phone_a_key);
        assert_eq!(theirs.memberships.len(), 1);
        hs.admit(FaceId(9), T, Admission::default()).await.unwrap()
    };
    let (_phone, at_phone, _) = start(
        phone.a.link_key(),
        Trust::new(
            &[&a, &c],
            phone.a.chain.clone(),
            vec![phone.c.membership(&c)],
        ),
        vec![relay_peer("/c/node/old-relay", Some(listen_at))],
        false,
        &cancel,
    );
    let _link = tokio::time::timeout(T, older)
        .await
        .expect("the older listener admits");
    until("the device links the older listener", || {
        at_phone.live.lock().len() == 1
    })
    .await;
    cancel.cancel();
}

/// A relay of A and C admits the device by both its A link key and its C
/// membership, and routes both its names and both namespaces' sync groups.
/// Revoking its C key while it is linked takes C from the link (its C
/// route and C's group go) and keeps the link up by A; revoking its A key
/// then leaves it no identity, and the link is closed with its routes.
#[tokio::test]
async fn revoking_one_membership_keeps_the_link_by_another_and_the_last_closes_it() {
    let cancel = CancellationToken::new();
    let (a, c) = (namespace("/a", 10).await, namespace("/c", 30).await);
    let relay_c = c.device("node", "relay", 90).await;
    let relay_a = a.device("node", "relay", 91).await;
    let trust = Trust::new(
        &[&a, &c],
        relay_c.chain.clone(),
        vec![relay_a.membership(&a)],
    );
    let keyring = Arc::clone(&trust.keyring);
    let (_relay, at_relay, addr) = start(relay_c.link_key(), trust, Vec::new(), true, &cancel);
    let phone = phone(&a, &c).await;
    let (_phone, at_phone, _) = start(
        phone.a.link_key(),
        Trust::new(
            &[&a, &c],
            phone.a.chain.clone(),
            vec![phone.c.membership(&c)],
        ),
        vec![relay_peer("/c/node/relay", addr)],
        false,
        &cancel,
    );
    at_relay
        .settles("the relay routes the phone in both namespaces", |r| {
            r.sorted_routes()
                == sorted(&[
                    "/a/member/phone",
                    "/a/32=sync",
                    "/c/member/phone",
                    "/c/32=sync",
                ])
        })
        .await;

    keyring
        .adopt_update(c.context_revoking(2, Some("/c/member/phone/KEY/k")))
        .unwrap();
    at_relay
        .settles("the C routes go", |r| {
            r.sorted_routes() == sorted(&["/a/member/phone", "/a/32=sync"])
        })
        .await;
    assert_eq!(
        at_relay.live.lock().len(),
        1,
        "the link stays, admitted by A"
    );

    keyring
        .adopt_update(a.context_revoking(2, Some("/a/member/phone/KEY/k")))
        .unwrap();
    at_relay
        .settles("the link closes with its routes", |r| {
            r.live.lock().is_empty() && r.routed().is_empty()
        })
        .await;
    at_phone
        .settles("the device's side closes", |r| r.live.lock().is_empty())
        .await;
    cancel.cancel();
}

/// The names `names`, sorted.
fn sorted(names: &[&str]) -> Vec<Name> {
    let mut names: Vec<Name> = names.iter().map(|s| n(s)).collect();
    names.sort();
    names
}

/// A namespace's sync group follows the link: two devices of `/home/bob` (a
/// namespace of two components) route `/home/bob/32=sync` over their link
/// as soon as it is up, beside each other's names, and lose it with the
/// link when it goes.
#[tokio::test]
async fn the_sync_group_is_routed_over_a_link_while_it_is_up() {
    let cancel = CancellationToken::new();
    let bob = namespace("/home/bob", 50).await;
    let relay_key = bob.device("node", "relay", 92).await;
    let (_relay, at_relay, addr) = start(
        relay_key.link_key(),
        Trust::new(&[&bob], relay_key.chain.clone(), Vec::new()),
        Vec::new(),
        true,
        &cancel,
    );
    let phone_key = bob.device("member", "phone", 52).await;
    let (phone, at_phone, _) = start(
        phone_key.link_key(),
        Trust::new(&[&bob], phone_key.chain.clone(), Vec::new()),
        vec![relay_peer("/home/bob/node/relay", addr)],
        false,
        &cancel,
    );
    at_relay
        .settles("the relay routes the phone and the group to it", |r| {
            r.routed() == [n("/home/bob/member/phone"), n("/home/bob/32=sync")]
        })
        .await;
    at_phone
        .settles(
            "the phone routes the namespace and the group to the relay",
            |r| r.routed() == [n("/home/bob"), n("/home/bob/32=sync")],
        )
        .await;
    let face = at_relay.live.lock()[0];
    assert!(
        at_relay.routes.lock().iter().all(|(f, _)| *f == face),
        "the group goes to the link's face"
    );

    // The phone stops using the relay: the link goes, and the group with it
    // on both sides.
    phone.remove_peer(ndn_link::PeerId(0));
    at_relay
        .settles("the relay's link and its routes go", |r| {
            r.live.lock().is_empty() && r.routed().is_empty()
        })
        .await;
    at_phone
        .settles("the phone's link and its routes go", |r| {
            r.live.lock().is_empty() && r.routed().is_empty()
        })
        .await;
    cancel.cancel();
}

/// A device of A using a relay its person added routes A and the relay's
/// own name over the relay's link. A namespace it follows later (B's
/// trust context adopted while linked, no certificate in it) is routed
/// over that link at once, at the relay's rank; one it no longer follows
/// (the host forgot it) loses its route, and A stays routed.
#[tokio::test]
async fn a_namespace_followed_later_is_routed_over_the_relay_link_at_once() {
    let cancel = CancellationToken::new();
    let (a, b) = (namespace("/a", 10).await, namespace("/b", 20).await);
    let relay_key = a.device("node", "relay", 93).await;
    let (_relay, _, addr) = start(
        relay_key.link_key(),
        Trust::new(&[&a], relay_key.chain.clone(), Vec::new()),
        Vec::new(),
        true,
        &cancel,
    );
    let phone_key = a.device("member", "phone", 94).await;
    let trust = Trust::new(&[&a], phone_key.chain.clone(), Vec::new());
    let keyring = Arc::clone(&trust.keyring);
    let relay = PeerSpec {
        relay_use: Some(RelayUse {
            source: RelaySource::User,
            preference: 0,
        }),
        ..relay_peer("/a/node/relay", addr)
    };
    let (phone, at_phone, _) = start(phone_key.link_key(), trust, vec![relay], false, &cancel);
    let over = |r: &Recorder, prefix: &str| {
        let face = r.live.lock().first().copied();
        r.routes
            .lock()
            .iter()
            .any(|(f, route)| Some(*f) == face && route.prefix == n(prefix))
    };
    at_phone
        .settles("the phone routes A over the relay link", |r| over(r, "/a"))
        .await;
    assert!(!over(&at_phone, "/b"), "B is routed before it is followed");

    keyring.adopt(b.context()).unwrap();
    at_phone
        .settles("B, followed now, is routed over the relay link", |r| {
            over(r, "/b")
        })
        .await;

    assert!(keyring.forget(&n("/b")));
    phone.followed_changed();
    at_phone
        .settles("B, no longer followed, loses its route", |r| !over(r, "/b"))
        .await;
    assert!(over(&at_phone, "/a"), "A stays routed over the relay link");
    cancel.cancel();
}
