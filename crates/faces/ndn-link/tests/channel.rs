//! Channel frames over real links of two devices of one namespace on loopback
//! (ndn-link.md §17A): an own-namespace member's link carries them both ways, by
//! datagram and by stream, and `Links::report` counts them; a guest's link carries
//! none, drops what the guest sends and stays up; a link that carries only channel
//! frames (its stream bytes included) is not closed as quiet, and neither is one the
//! forwarder holds a side route to, while an idle one is.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use ndn_face_quic::{
    KeyFingerprint, LinkEndpoint, LinkKey, LinkKeySource, LinkTransportConfig, SideStats,
};
use ndn_link::{
    ConfiguredEndpoints, FaceSink, LinkSetup, LinkTrust, Links, PeerSpec, RelayService, Route,
};
use ndn_packet::Name;
use ndn_security::{
    Certificate, Ed25519Signer, Keyring, SecurityManager, SignedTrustContext, Signer,
};
use ndn_transport::{Face, FaceId, FaceKind, SideClass, SideRefused};
use parking_lot::Mutex;
use tokio_util::sync::CancellationToken;

const NS: &str = "/home";

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

/// The namespace: its root key and signed trust context.
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

/// A forwarder as the links see it: the faces it was given, and how many side routes it
/// says point at any face.
#[derive(Default)]
struct Recorder {
    next: AtomicU64,
    live: Mutex<Vec<FaceId>>,
    faces: Mutex<Vec<Arc<Face>>>,
    side_routes: AtomicUsize,
}

impl Recorder {
    /// The link face (the library's own in-process faces are not counted).
    fn link_face(&self) -> Arc<Face> {
        self.faces
            .lock()
            .iter()
            .find(|f| f.kind() == FaceKind::Quic)
            .cloned()
            .expect("the link face")
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
    fn side_routes(&self, _: FaceId) -> usize {
        self.side_routes.load(Ordering::SeqCst)
    }
    fn transit(&self, _: &Name, _: bool) {}
}

struct Device {
    links: Arc<Links>,
    at: Arc<Recorder>,
    key: KeyFingerprint,
    addr: Option<String>,
}

/// `/home/<role>/<name>`, linking the namespace's other devices that come in, and
/// dialling `peers`.
async fn device(
    home: &Home,
    role: &str,
    name: &str,
    seed: u8,
    listens: Option<Duration>,
    peers: Vec<PeerSpec>,
    cancel: &CancellationToken,
) -> Device {
    let key_name = n(&format!("{NS}/{role}/{name}/KEY/k{seed}"));
    let signer = Arc::new(Ed25519Signer::from_seed(&[seed; 32], key_name.clone()));
    let cert = home.certify(&key_name, signer.public_key().unwrap()).await;
    let link_key = LinkKey::from_signer(Arc::clone(&signer) as Arc<dyn Signer>).unwrap();
    let key = link_key.fingerprint();
    let keyring = Arc::new(Keyring::new());
    keyring.adopt(Arc::clone(&home.context)).unwrap();
    let transport = LinkTransportConfig {
        quiet_close: listens.unwrap_or(QUIET),
        ..LinkTransportConfig::default()
    };
    let link_key: Arc<dyn LinkKeySource> = Arc::new(link_key);
    let socket = Arc::new(
        LinkEndpoint::bind(
            "127.0.0.1:0".parse().unwrap(),
            Arc::clone(&link_key),
            &transport,
            listens.is_some(),
        )
        .unwrap(),
    );
    let addr = listens.map(|_| socket.local_addr().unwrap().to_string());
    let at = Arc::new(Recorder::default());
    let links = Links::start(
        LinkSetup {
            peers,
            key: link_key,
            trust: Arc::new(Trust {
                keyring,
                chain: vec![cert.data_wire().unwrap()],
            }),
            faces: Arc::clone(&at) as Arc<dyn FaceSink>,
            paths: Arc::new(ConfiguredEndpoints),
            candidates: Vec::new(),
            socket: Some(socket),
            transport,
            relays: Default::default(),
            service: RelayService::default(),
            direct: Default::default(),
            reliability: Default::default(),
        },
        cancel.child_token(),
    );
    Device {
        links,
        at,
        key,
        addr,
    }
}

fn dials(listener: &Device) -> Vec<PeerSpec> {
    vec![PeerSpec {
        label: listener.key.to_string(),
        key: Some(listener.key),
        endpoints: listener.addr.clone().into_iter().collect(),
        persistent: false,
        ..PeerSpec::default()
    }]
}

fn frame(tag: u8, len: usize) -> Bytes {
    let mut v = vec![tag; len.max(2)];
    v[0] = 0x00;
    Bytes::from(v)
}

async fn within(what: &str, limit: Duration, mut done: impl FnMut() -> bool) {
    let start = tokio::time::Instant::now();
    while start.elapsed() < limit {
        if done() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("{what}: not within {} s", limit.as_secs());
}

async fn recv(face: &Face) -> Bytes {
    tokio::time::timeout(Duration::from_secs(5), face.recv_bytes())
        .await
        .expect("a frame within 5 s")
        .unwrap()
}

/// What `on`'s report says of the side path of its link to `key`.
fn side_of(on: &Device, key: KeyFingerprint) -> SideStats {
    on.links
        .report()
        .links
        .into_iter()
        .find(|l| l.key == Some(key))
        .expect("a link to that key")
        .side
}

const QUIET: Duration = Duration::from_secs(60);

#[tokio::test]
async fn a_members_link_carries_channel_frames_both_ways_and_the_report_counts_them() {
    let cancel = CancellationToken::new();
    let home = Home::new();
    let l = device(&home, "member", "l", 1, Some(QUIET), Vec::new(), &cancel).await;
    let a = device(&home, "member", "a", 2, None, dials(&l), &cancel).await;
    within("both sides link", Duration::from_secs(10), || {
        a.at.live.lock().len() == 1 && l.at.live.lock().len() == 1
    })
    .await;
    let (fa, fl) = (a.at.link_face(), l.at.link_face());

    fa.send_side(frame(1, 200), SideClass::Datagram)
        .await
        .unwrap();
    assert_eq!(recv(&fl).await, frame(1, 200));
    fl.send_side(frame(2, 300), SideClass::Stream)
        .await
        .unwrap();
    assert_eq!(recv(&fa).await, frame(2, 300));
    fa.send_side(frame(3, 50_000), SideClass::Stream)
        .await
        .unwrap();
    assert_eq!(recv(&fl).await, frame(3, 50_000));

    let at_a = side_of(&a, l.key);
    assert_eq!((at_a.datagram_tx_frames, at_a.datagram_tx_bytes), (1, 200));
    assert_eq!((at_a.stream_tx_frames, at_a.stream_tx_bytes), (1, 50_000));
    assert_eq!((at_a.stream_rx_frames, at_a.stream_rx_bytes), (1, 300));
    let at_l = side_of(&l, a.key);
    assert_eq!(
        (
            at_l.datagram_rx_frames,
            at_l.stream_rx_frames,
            at_l.stream_tx_frames
        ),
        (1, 1, 1)
    );
    assert_eq!(at_l.refused, 0);
    cancel.cancel();
}

#[tokio::test]
async fn a_guests_link_carries_no_channel_frames_drops_what_the_guest_sends_and_stays_up() {
    let cancel = CancellationToken::new();
    let home = Home::new();
    let l = device(&home, "member", "l", 1, Some(QUIET), Vec::new(), &cancel).await;
    let g = device(&home, "guest", "g", 2, None, dials(&l), &cancel).await;
    within("both sides link", Duration::from_secs(10), || {
        g.at.live.lock().len() == 1 && l.at.live.lock().len() == 1
    })
    .await;
    let (fg, fl) = (g.at.link_face(), l.at.link_face());

    // The member's side does not carry a guest's link.
    assert_eq!(
        fl.send_side(frame(1, 100), SideClass::Datagram).await,
        Err(SideRefused::NotCarried)
    );
    assert_eq!(
        fl.forward_side(frame(1, 100), SideClass::Stream),
        Err(SideRefused::NotCarried)
    );
    // The guest's side carries (it is linked to a member), the member drops and counts,
    // and neither link closes.
    // (The forwarder's reader of the face is what takes the datagram in.)
    let reader = Arc::clone(&fl);
    let reading = tokio::spawn(async move { while reader.recv_bytes().await.is_ok() {} });
    fg.send_side(frame(2, 100), SideClass::Datagram)
        .await
        .unwrap();
    within(
        "the member counts the frame it refused",
        Duration::from_secs(5),
        || side_of(&l, g.key).refused == 3,
    )
    .await;
    let seen = side_of(&l, g.key);
    assert_eq!((seen.datagram_rx_frames, seen.frames()), (0, 0));
    assert_eq!(side_of(&g, l.key).datagram_tx_frames, 1);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        (g.at.live.lock().len(), l.at.live.lock().len()),
        (1, 1),
        "a frame a link does not carry is no reason to close it"
    );
    reading.abort();
    cancel.cancel();
}

/// A link another device dialed here that carries no NDN packet is closed once quiet, and
/// channel stream bytes do not keep it open while nothing routes them: a peer that sends
/// channel frames the forwarder drops (no side route to its link) is not using the link.
#[tokio::test]
async fn channel_stream_bytes_nobody_routes_do_not_keep_a_link_open() {
    let cancel = CancellationToken::new();
    let home = Home::new();
    let quiet = Duration::from_secs(1);
    let l = device(&home, "member", "l", 1, Some(quiet), Vec::new(), &cancel).await;
    let busy = device(&home, "member", "busy", 2, None, dials(&l), &cancel).await;
    let idle = device(&home, "member", "idle", 3, None, dials(&l), &cancel).await;
    within("both link", Duration::from_secs(10), || {
        busy.at.live.lock().len() == 1
            && idle.at.live.lock().len() == 1
            && l.at.live.lock().len() == 2
    })
    .await;
    let face = busy.at.link_face();
    let sending = tokio::spawn(async move {
        let mut sent = 0u32;
        for i in 0..60u8 {
            if face
                .send_side(frame(i, 1000), SideClass::Stream)
                .await
                .is_err()
            {
                break;
            }
            sent += 1;
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        sent
    });
    within(
        "the idle link closes as quiet",
        Duration::from_secs(8),
        || idle.at.live.lock().is_empty(),
    )
    .await;
    within(
        "the link whose channel stream bytes nothing routes closes as quiet too",
        Duration::from_secs(8),
        || l.at.live.lock().is_empty(),
    )
    .await;
    assert!(
        sending.await.unwrap() > 0,
        "the frames did cross before the link was closed"
    );
    cancel.cancel();
}

/// While the forwarder holds a side route to a link, what the peer sends on its channel
/// stream is routed traffic: the link is not quiet however long it carries no NDN packet,
/// and once the route goes the quiet period runs from the last channel byte.
#[tokio::test]
async fn channel_stream_bytes_count_as_activity_while_the_link_has_a_side_route() {
    let cancel = CancellationToken::new();
    let home = Home::new();
    let l = device(
        &home,
        "member",
        "l",
        1,
        Some(Duration::from_secs(1)),
        Vec::new(),
        &cancel,
    )
    .await;
    l.at.side_routes.store(1, Ordering::SeqCst);
    let busy = device(&home, "member", "busy", 2, None, dials(&l), &cancel).await;
    within("both link", Duration::from_secs(10), || {
        busy.at.live.lock().len() == 1 && l.at.live.lock().len() == 1
    })
    .await;
    let (face, reader) = (busy.at.link_face(), l.at.link_face());
    let reading = tokio::spawn(async move { while reader.recv_bytes().await.is_ok() {} });
    for i in 0..8u8 {
        face.send_side(frame(i, 1000), SideClass::Stream)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(l.at.live.lock().len(), 1, "a routed link stays");
    // The route goes and the peer sends no more: the link closes once quiet.
    l.at.side_routes.store(0, Ordering::SeqCst);
    within(
        "the unrouted quiet link closes",
        Duration::from_secs(8),
        || l.at.live.lock().is_empty(),
    )
    .await;
    reading.abort();
    cancel.cancel();
}

/// A link the forwarder holds a side route to counts as routed: not closed as quiet.
#[tokio::test]
async fn a_link_with_a_side_route_is_routed_and_is_not_closed_as_quiet() {
    let cancel = CancellationToken::new();
    let home = Home::new();
    let l = device(
        &home,
        "member",
        "l",
        1,
        Some(Duration::from_secs(1)),
        Vec::new(),
        &cancel,
    )
    .await;
    l.at.side_routes.store(1, Ordering::SeqCst);
    let a = device(&home, "member", "a", 2, None, dials(&l), &cancel).await;
    within("both link", Duration::from_secs(10), || {
        a.at.live.lock().len() == 1 && l.at.live.lock().len() == 1
    })
    .await;
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert_eq!(
        l.at.live.lock().len(),
        1,
        "a quiet link with a side route is routed"
    );
    // The route goes: the quiet link is closed.
    l.at.side_routes.store(0, Ordering::SeqCst);
    within(
        "the unrouted quiet link closes",
        Duration::from_secs(8),
        || l.at.live.lock().is_empty(),
    )
    .await;
    cancel.cancel();
}
