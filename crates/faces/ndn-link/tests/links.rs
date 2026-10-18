//! Two devices over loopback: a link admitted by expected keys gets its face
//! and routes, and goes away when the link ends; a device nobody expects is
//! refused and gets nothing. (Each side also adds its signalling face, an
//! app face; only link faces are counted here.)

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;

use bytes::Bytes;
use ndn_face_quic::{KeyFingerprint, LinkEndpoint, LinkKey, LinkKeySource, LinkTransportConfig};
use ndn_link::{
    ConfiguredEndpoints, FaceSink, LinkHints, LinkSetup, LinkTrust, Links, PeerSpec, Route,
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
}

impl FaceSink for Recorder {
    fn alloc_face_id(&self) -> FaceId {
        FaceId(self.next.fetch_add(1, Ordering::SeqCst) + 1)
    }
    fn add_face(&self, face: Face, _: CancellationToken) {
        if face.kind() == FaceKind::Quic {
            self.live.lock().push(face.id());
        }
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
        device: None,
        endpoints: endpoint.into_iter().collect(),
        relay: None,
        routes,
        persistent: false,
        reliability: false,
        direct: true,
    }
}

fn start(key: LinkKey, peers: Vec<PeerSpec>, listen: bool, cancel: &CancellationToken) -> (Arc<Links>, Arc<Recorder>, Option<String>) {
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
        },
        cancel.child_token(),
    );
    (links, faces, addr)
}

async fn until(what: &str, mut done: impl FnMut() -> bool) {
    for _ in 0..100 {
        if done() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("{what}: not within 5 s");
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
