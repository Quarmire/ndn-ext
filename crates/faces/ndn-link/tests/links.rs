//! Two devices over loopback: a link admitted by expected keys gets its face
//! and routes, and goes away when the link ends; a device nobody expects is
//! refused and gets nothing; an `off` link stays closed until asked; an
//! on-demand link closes when idle; losing the preferred relay moves to the
//! next. (Each side also adds its signalling and waiting faces, app faces;
//! only link faces are counted here.)

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;

use bytes::Bytes;
use ndn_face_quic::{KeyFingerprint, LinkEndpoint, LinkKey, LinkKeySource, LinkTransportConfig};
use ndn_link::{
    ConfiguredEndpoints, FaceSink, HoldLimits, LinkHints, LinkMode, LinkSetup, LinkTrust, Links, PeerSpec,
    RelayService, RelaySource, RelayUse, Route, WakeNotifier, WakeRequest,
};
use ndn_packet::Name;
use ndn_security::{Certificate, Ed25519Signer, Keyring};
use ndn_transport::{Face, FaceId, FaceKind};
use tokio_util::sync::CancellationToken;

fn key(seed: u8) -> LinkKey {
    LinkKey::from_signer(Arc::new(Ed25519Signer::from_seed(
        &[seed; 32],
        format!("/ns/member/d{seed}/KEY/k").parse().unwrap(),
    )))
    .unwrap()
}

/// No namespace held, no certificate: links only by expected keys.
struct NoTrust(Arc<Keyring>);

impl LinkTrust for NoTrust {
    fn keyring(&self) -> &Arc<Keyring> {
        &self.0
    }
    fn own_chain(&self) -> Vec<Bytes> {
        Vec::new()
    }
    fn known_certificate(&self, _: &Name) -> Option<Certificate> {
        None
    }
    fn known_certificate_of_key(&self, _: &KeyFingerprint) -> Option<Certificate> {
        None
    }
}

#[derive(Default)]
struct Recorder {
    next: AtomicU64,
    live: Mutex<Vec<FaceId>>,
    routes: Mutex<Vec<(FaceId, Route)>>,
    /// Every face added, as the forwarder would run it.
    faces: Mutex<Vec<Arc<Face>>>,
}

impl Recorder {
    /// The `nth` face of the forwarder's own (the library's in-process
    /// faces: signalling first, then waiting), or the `nth` link face.
    fn face(&self, link: bool, nth: usize) -> Arc<Face> {
        self.faces
            .lock()
            .iter()
            .filter(|f| (f.kind() == FaceKind::Quic) == link)
            .nth(nth)
            .cloned()
            .expect("the face")
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
    fn add_routes(&self, face: FaceId, routes: &[Route]) {
        if !self.live.lock().contains(&face) {
            return;
        }
        self.routes
            .lock()
            .extend(routes.iter().map(|r| (face, r.clone())));
    }
    fn remove_routes(&self, face: FaceId, prefixes: &[Name]) {
        self.routes
            .lock()
            .retain(|(f, r)| *f != face || !prefixes.contains(&r.prefix));
    }
    fn transit(&self, _: &Name, _: bool) {}
}

fn hints() -> LinkHints {
    LinkHints {
        enroll: "enroll".into(),
        renew: "renew".into(),
        refresh: "refresh".into(),
        peer_entry: "peer".into(),
        expect_key: "expect {key}".into(),
    }
}

fn peer(key: KeyFingerprint, endpoint: Option<String>, routes: Option<Vec<Name>>) -> PeerSpec {
    PeerSpec {
        label: key.to_string(),
        key: Some(key),
        endpoints: endpoint.into_iter().collect(),
        routes,
        persistent: false,
        ..PeerSpec::default()
    }
}

fn start(key: LinkKey, peers: Vec<PeerSpec>, listen: bool, cancel: &CancellationToken) -> (Arc<Links>, Arc<Recorder>, Option<String>) {
    start_with(key, peers, listen, cancel, RelayService::default())
}

fn start_with(
    key: LinkKey,
    peers: Vec<PeerSpec>,
    listen: bool,
    cancel: &CancellationToken,
    service: RelayService,
) -> (Arc<Links>, Arc<Recorder>, Option<String>) {
    let transport = LinkTransportConfig::default();
    let key: Arc<dyn LinkKeySource> = Arc::new(key);
    let socket = listen.then(|| {
        Arc::new(LinkEndpoint::bind("127.0.0.1:0".parse().unwrap(), Arc::clone(&key), &transport, true).unwrap())
    });
    let addr = socket.as_ref().map(|s| s.local_addr().unwrap().to_string());
    let faces = Arc::new(Recorder::default());
    let links = Links::start(
        LinkSetup {
            peers,
            key,
            trust: Arc::new(NoTrust(Arc::new(Keyring::new()))),
            faces: Arc::clone(&faces) as Arc<dyn FaceSink>,
            paths: Arc::new(ConfiguredEndpoints),
            candidates: Vec::new(),
            socket,
            transport,
            hints: hints(),
            relays: Default::default(),
            service,
            direct: Default::default(),
        },
        cancel.child_token(),
    );
    (links, faces, addr)
}

async fn until(what: &str, done: impl FnMut() -> bool) {
    within(what, Duration::from_secs(5), done).await;
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

#[tokio::test]
async fn expected_keys_link_with_routes_and_the_face_goes_with_the_link() {
    let cancel = CancellationToken::new();
    let (a, b) = (key(1), key(2));
    let (fa, fb) = (a.fingerprint(), b.fingerprint());
    let (listener, at_b, addr) = start(b, vec![peer(fa, None, None)], true, &cancel);
    let (dialer, at_a, _) = start(
        a,
        vec![peer(fb, addr, Some(vec!["/b".parse().unwrap()]))],
        false,
        &cancel,
    );
    until("both sides link", || {
        at_a.live.lock().len() == 1 && at_b.live.lock().len() == 1
    })
    .await;
    let routes = at_a.routes.lock().clone();
    assert_eq!(routes.len(), 1);
    assert_eq!(
        routes[0].1,
        Route {
            prefix: "/b".parse().unwrap(),
            cost: 0
        }
    );
    // A peer that names neither routes nor a device gets none.
    assert!(at_b.routes.lock().is_empty());

    listener.shutdown().await;
    until("the link's faces are removed", || {
        at_a.live.lock().is_empty() && at_b.live.lock().is_empty()
    })
    .await;
    drop(dialer);
    cancel.cancel();
}

#[tokio::test]
async fn a_device_nobody_expects_is_refused() {
    let cancel = CancellationToken::new();
    let (a, b) = (key(3), key(4));
    let fb = b.fingerprint();
    let (_listener, at_b, addr) = start(b, Vec::new(), true, &cancel);
    let (_dialer, at_a, _) = start(a, vec![peer(fb, addr, None)], false, &cancel);
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(at_a.live.lock().is_empty());
    assert!(at_b.live.lock().is_empty());
    cancel.cancel();
}

#[tokio::test]
async fn an_off_link_stays_closed_until_asked() {
    let cancel = CancellationToken::new();
    let (a, b) = (key(5), key(6));
    let (fa, fb) = (a.fingerprint(), b.fingerprint());
    let (_listener, _, addr) = start(b, vec![peer(fa, None, None)], true, &cancel);
    let spec = PeerSpec {
        mode: LinkMode::Off,
        persistent: true,
        ..peer(fb, addr, None)
    };
    let (dialer, at_a, _) = start(a, vec![spec], false, &cancel);
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(at_a.live.lock().is_empty(), "an off link was dialled unasked");
    let id = dialer.report().links[0].peer.unwrap();
    dialer.connect(id);
    until("the asked link comes up", || at_a.live.lock().len() == 1).await;
    dialer.disconnect(id);
    until("the link closes once no longer asked", || at_a.live.lock().is_empty()).await;
    cancel.cancel();
}

#[tokio::test]
async fn an_on_demand_link_closes_when_idle_and_the_host_is_not_active() {
    let cancel = CancellationToken::new();
    let (a, b) = (key(7), key(8));
    let (fa, fb) = (a.fingerprint(), b.fingerprint());
    let (_listener, _, addr) = start(b, vec![peer(fa, None, None)], true, &cancel);
    let spec = PeerSpec {
        mode: LinkMode::OnDemand {
            idle: Duration::from_secs(1),
        },
        persistent: true,
        ..peer(fb, addr, Some(vec!["/b".parse().unwrap()]))
    };
    let (dialer, at_a, _) = start(a, vec![spec], false, &cancel);
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert!(at_a.live.lock().is_empty(), "an on-demand link was dialled with no need");
    dialer.set_active(true);
    until("the link comes up while the host is active", || at_a.live.lock().len() == 1).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(at_a.live.lock().len(), 1, "an active host's on-demand link closed");
    dialer.set_active(false);
    until("the idle link closes once the host is not active", || at_a.live.lock().is_empty()).await;
    cancel.cancel();
}

#[tokio::test]
async fn losing_the_preferred_relay_moves_to_the_next() {
    let cancel = CancellationToken::new();
    let relay_cancel = CancellationToken::new();
    let (a, r1, r2) = (key(9), key(10), key(11));
    let fa = a.fingerprint();
    let (f1, f2) = (r1.fingerprint(), r2.fingerprint());
    let (first, at_r1, addr1) = start(r1, vec![peer(fa, None, None)], true, &relay_cancel);
    let (_second, at_r2, addr2) = start(r2, vec![peer(fa, None, None)], true, &cancel);
    let relay = |fp, addr, preference| PeerSpec {
        relay_use: Some(RelayUse {
            source: RelaySource::User,
            preference,
        }),
        persistent: true,
        ..peer(fp, addr, Some(vec!["/home".parse().unwrap()]))
    };
    let (_device, at_a, _) = start(a, vec![relay(f1, addr1, 0), relay(f2, addr2, 1)], false, &cancel);
    until("the preferred relay links", || at_r1.live.lock().len() == 1).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(at_r2.live.lock().is_empty(), "the second relay was linked while the first one is");
    assert_eq!(at_a.routes.lock()[0].1.cost, 0);

    first.shutdown().await;
    relay_cancel.cancel();
    // The relay said it shuts down: the next one stands in at once, with no
    // redial of the first one waiting out its 5 s handshake timeout.
    within("traffic moves to the next relay", Duration::from_secs(3), || {
        at_r2.live.lock().len() == 1
    })
    .await;
    let routes = at_a.routes.lock().clone();
    assert!(
        routes.iter().any(|(_, r)| r.prefix == "/home".parse().unwrap() && r.cost == 1),
        "{routes:?}"
    );
    cancel.cancel();
}

#[derive(Default)]
struct Wakes(Mutex<Vec<WakeRequest>>);

impl WakeNotifier for Wakes {
    fn wake(&self, request: WakeRequest) {
        self.0.lock().push(request);
    }
}

/// What the forwarder hands the waiting face: an Interest for `name`.
fn interest(name: &str) -> Bytes {
    ndn_packet::encode::InterestBuilder::new(name.parse::<Name>().unwrap())
        .lifetime(Duration::from_secs(10))
        .build()
}

#[tokio::test]
async fn a_relay_holds_and_wakes_a_sleeping_device_and_delivers_when_it_links_again() {
    let cancel = CancellationToken::new();
    let (device, relay) = (key(12), key(13));
    let (fd, fr) = (device.fingerprint(), relay.fingerprint());
    let wakes = Arc::new(Wakes::default());
    let service = RelayService {
        hold: Some(HoldLimits {
            per_device: 2,
            ..HoldLimits::default()
        }),
        wake: Some(Arc::clone(&wakes) as Arc<dyn WakeNotifier>),
        ..RelayService::default()
    };
    let (at_relay, relay_faces, addr) = start_with(
        relay,
        vec![peer(fd, None, Some(vec!["/dev".parse().unwrap()]))],
        true,
        &cancel,
        service,
    );
    let spec = PeerSpec {
        mode: LinkMode::Off,
        hold: true,
        persistent: true,
        ..peer(fr, addr, None)
    };
    let (dev, dev_faces, _) = start(device, vec![spec], false, &cancel);
    let id = dev.report().links[0].peer.unwrap();
    dev.set_wake_token(id, Some(Bytes::from_static(b"tok")));
    dev.connect(id);
    until("the device links", || relay_faces.live.lock().len() == 1).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(at_relay.report().links[0].asleep.is_none(), "a linked device counts as asleep");

    dev.disconnect(id);
    until("the relay counts the device asleep", || {
        at_relay.report().links[0].asleep.is_some()
    })
    .await;
    let waiting = relay_faces.face(false, 1);
    for n in 1..=3 {
        waiting.send_bytes(interest(&format!("/dev/x{n}"))).await.unwrap();
    }
    // The third is over the device's bound: Nacked at once.
    let nack = tokio::time::timeout(Duration::from_secs(2), waiting.recv_bytes())
        .await
        .expect("a Nack for the Interest over the bound")
        .unwrap();
    assert!(ndn_packet::lp::is_lp_packet(&nack));
    until("two Interests are held", || {
        at_relay.report().links[0].asleep.as_ref().is_some_and(|a| a.held == 2)
    })
    .await;
    {
        let wakes = wakes.0.lock();
        assert_eq!(wakes.len(), 1, "woken once for Interests within the wake interval");
        assert_eq!(wakes[0].token.as_ref(), b"tok");
        assert_eq!(wakes[0].key, fd);
    }

    dev.connect(id);
    until("the device links again", || relay_faces.live.lock().len() == 1).await;
    let link = dev_faces.face(true, 1);
    let mut names = Vec::new();
    for _ in 0..2 {
        let wire = tokio::time::timeout(Duration::from_secs(3), link.recv_bytes())
            .await
            .expect("a held Interest over the new link")
            .unwrap();
        let wire = if ndn_packet::lp::is_lp_packet(&wire) {
            ndn_packet::lp::LpPacket::decode(wire).unwrap().fragment.expect("a whole Interest")
        } else {
            wire
        };
        names.push(ndn_packet::Interest::decode(wire).unwrap().name.to_string());
    }
    names.sort();
    assert_eq!(names, ["/dev/x1", "/dev/x2"]);
    assert!(at_relay.report().links[0].asleep.is_none());
    assert_eq!(wakes.0.lock().len(), 1, "a linked device was woken");
    cancel.cancel();
}
