//! Link status as it changes (`Links::watch`), over real QUIC links between
//! two devices on loopback: a late watcher is told the state first; a link
//! that ends is reported with its reason and what the device does about it;
//! a link that comes back is reported up; many flaps between two looks are
//! one entry, the newest; a refused first dial is a down state of the key it
//! expected. (The table's bound, eviction and cursor are unit tests of the
//! table, `src/watch.rs`.)

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use ndn_face_quic::{
    CloseReason, KeyFingerprint, LinkEndpoint, LinkKey, LinkKeySource, LinkTransportConfig,
};
use ndn_link::{
    ConfiguredEndpoints, Direction, FaceSink, LinkMode, LinkSetup, LinkState, LinkTrust, LinkWatch,
    Links, Next, PeerLink, PeerSpec, RelayService, Route, link_code,
};
use ndn_packet::Name;
use ndn_security::{Certificate, Ed25519Signer, Keyring};
use ndn_transport::{Face, FaceId};
use parking_lot::Mutex;
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
struct Sink {
    next: AtomicU64,
    faces: Mutex<Vec<Face>>,
}

impl FaceSink for Sink {
    fn alloc_face_id(&self) -> FaceId {
        FaceId(self.next.fetch_add(1, Ordering::SeqCst) + 1)
    }
    fn add_face(&self, face: Face, _: CancellationToken) {
        self.faces.lock().push(face);
    }
    fn remove_face(&self, _: FaceId) {}
    fn add_routes(&self, _: FaceId, _: &[Route]) {}
    fn remove_routes(&self, _: FaceId, _: &[Name]) {}
    fn routes_to(&self, _: FaceId) -> bool {
        false
    }
    fn transit(&self, _: &Name, _: bool) {}
}

fn peer(key: KeyFingerprint, endpoint: Option<&str>, persistent: bool) -> PeerSpec {
    PeerSpec {
        label: key.to_string(),
        key: Some(key),
        endpoints: endpoint.map(str::to_string).into_iter().collect(),
        persistent,
        ..PeerSpec::default()
    }
}

/// A link socket of `key` at `at` (`127.0.0.1:0`: any port).
fn bind(key: &Arc<dyn LinkKeySource>, at: &str) -> Result<Arc<LinkEndpoint>, String> {
    LinkEndpoint::bind(
        at.parse().unwrap(),
        Arc::clone(key),
        &LinkTransportConfig::default(),
        true,
    )
    .map(Arc::new)
    .map_err(|e| e.to_string())
}

fn start(
    key: LinkKey,
    peers: Vec<PeerSpec>,
    socket: Option<Arc<LinkEndpoint>>,
    cancel: &CancellationToken,
) -> Arc<Links> {
    let key: Arc<dyn LinkKeySource> = Arc::new(key);
    Links::start(
        LinkSetup {
            peers,
            key,
            trust: Arc::new(NoTrust(Arc::new(Keyring::new()))),
            faces: Arc::new(Sink::default()),
            paths: Arc::new(ConfiguredEndpoints),
            candidates: Vec::new(),
            socket,
            transport: LinkTransportConfig::default(),
            relays: Default::default(),
            service: RelayService::default(),
            direct: Default::default(),
        },
        cancel.child_token(),
    )
}

/// A device that listens, with its address.
fn listener(
    key: LinkKey,
    peers: Vec<PeerSpec>,
    cancel: &CancellationToken,
) -> (Arc<Links>, String) {
    let shared: Arc<dyn LinkKeySource> = Arc::new(key.clone());
    let socket = bind(&shared, "127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap().to_string();
    (start(key, peers, Some(socket), cancel), addr)
}

async fn within(what: &str, mut done: impl FnMut() -> bool) {
    let start = tokio::time::Instant::now();
    while start.elapsed() < Duration::from_secs(30) {
        if done() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("{what}: not within 30 s");
}

/// The state of `key` now, by a fresh watcher.
fn state(links: &Links, key: KeyFingerprint) -> Option<PeerLink> {
    links.watch().current().into_iter().find(|l| l.key == key)
}

fn is_up(link: &Option<PeerLink>) -> bool {
    matches!(
        link,
        Some(PeerLink {
            state: LinkState::Up { .. },
            ..
        })
    )
}

fn is_down(link: &Option<PeerLink>) -> bool {
    matches!(
        link,
        Some(PeerLink {
            state: LinkState::Down { .. },
            ..
        })
    )
}

/// The first change `watch` reports that `wanted` takes.
async fn change(watch: &mut LinkWatch, what: &str, wanted: impl Fn(&PeerLink) -> bool) -> PeerLink {
    let found = tokio::time::timeout(Duration::from_secs(30), async {
        while let Some(batch) = watch.changed().await {
            if let Some(link) = batch.into_iter().find(|l| wanted(l)) {
                return Some(link);
            }
        }
        None
    })
    .await;
    match found {
        Ok(Some(link)) => link,
        Ok(None) => panic!("{what}: the watch ended"),
        Err(_) => panic!("{what}: no such change within 30 s"),
    }
}

fn up(link: &PeerLink) -> bool {
    matches!(link.state, LinkState::Up { .. })
}

fn down(link: &PeerLink) -> bool {
    matches!(link.state, LinkState::Down { .. })
}

/// What a down state says: its reason's code and words, and what it does.
fn why_next(link: &PeerLink) -> (String, String, Next, Option<Direction>) {
    match &link.state {
        LinkState::Down {
            why,
            next,
            direction,
        } => (why.code.clone(), why.text.clone(), *next, *direction),
        up => panic!("not down: {up:?}"),
    }
}

/// A watcher started after the links came up is told the state first, from
/// either side's view; a watcher of devices that have linked with nobody
/// is told the table is empty, at once.
#[tokio::test]
async fn a_late_watcher_gets_the_current_state_first() {
    let cancel = CancellationToken::new();
    let (a, b) = (key(1), key(2));
    let (fa, fb) = (a.fingerprint(), b.fingerprint());
    let (la, addr) = listener(a, vec![peer(fb, None, true)], &cancel);
    let db = start(b, vec![peer(fa, Some(&addr), true)], None, &cancel);

    let mut early = db.watch();
    assert!(
        early.changed().await.unwrap().is_empty(),
        "nothing linked yet: the first look is the empty table, at once"
    );
    within("both sides see the link up", || {
        is_up(&state(&la, fb)) && is_up(&state(&db, fa))
    })
    .await;

    // Late: the state comes first, whole.
    let mut late = la.watch();
    let first = late.changed().await.unwrap();
    assert_eq!(first.len(), 1, "{first:?}");
    assert_eq!(first[0].key, fb);
    assert!(
        matches!(
            first[0].state,
            LinkState::Up {
                direction: Direction::Accepted,
                ..
            }
        ),
        "the listener accepted it: {first:?}"
    );
    assert_eq!(late.current(), first);
    let dialer = db.watch().changed().await.unwrap();
    assert_eq!(dialer.len(), 1);
    assert_eq!(dialer[0].key, fa);
    assert!(
        matches!(
            dialer[0].state,
            LinkState::Up {
                direction: Direction::Dialed,
                ..
            }
        ),
        "the dialer dialled it: {dialer:?}"
    );
    // The early watcher was told the link came up, once, as a change.
    let came = change(&mut early, "the early watcher is told", up).await;
    assert_eq!(came.key, fa);
    cancel.cancel();
}

/// A peer that shuts down: its link is down, with the reason it gave, in
/// plain words (no address), and what this device does: it dials a
/// persistent peer again (and the link is up when the peer is back), and
/// does not dial a peer that is not persistent.
#[tokio::test]
async fn a_peer_that_shuts_down_is_down_with_its_reason_redialled_when_persistent_gone_when_not() {
    let cancel = CancellationToken::new();
    let lcancel = CancellationToken::new();
    let (l, d1, d2) = (key(3), key(4), key(5));
    let (fl, f1, f2) = (l.fingerprint(), d1.fingerprint(), d2.fingerprint());
    let (links, addr) = listener(
        l.clone(),
        vec![peer(f1, None, true), peer(f2, None, true)],
        &lcancel,
    );
    let one = start(d1, vec![peer(fl, Some(&addr), true)], None, &cancel);
    let two = start(d2, vec![peer(fl, Some(&addr), false)], None, &cancel);
    let (mut w1, mut w2) = (one.watch(), two.watch());
    change(&mut w1, "the persistent dialler links", up).await;
    change(&mut w2, "the other dialler links", up).await;

    links.shutdown().await;

    let lost = change(&mut w1, "the persistent peer's link is down", down).await;
    let (code, text, next, direction) = why_next(&lost);
    assert_eq!(code, link_code::LINK_CLOSED_BY_PEER, "{text}");
    assert!(text.contains("shutting down"), "the reason it gave: {text}");
    assert!(
        !text.contains("127.0.0.1"),
        "no address in a reason: {text}"
    );
    assert_eq!(direction, Some(Direction::Dialed));
    assert!(
        matches!(next, Next::Redialling { within } if within <= Duration::from_secs(30)),
        "a persistent peer is dialled again: {next:?}"
    );
    let lost = change(&mut w2, "the other peer's link is down", down).await;
    let (_, text, next, _) = why_next(&lost);
    assert!(text.contains("shutting down"), "{text}");
    assert_eq!(next, Next::Gone, "not persistent: not dialled again");

    // The peer is back at the same place: the redial finds it, and the link
    // is reported up again, newest state.
    lcancel.cancel();
    drop(links);
    let shared: Arc<dyn LinkKeySource> = Arc::new(l.clone());
    let mut socket = None;
    within("the old socket is released", || {
        socket = bind(&shared, &addr).ok();
        socket.is_some()
    })
    .await;
    let back = start(
        l,
        vec![peer(f1, None, true), peer(f2, None, true)],
        socket,
        &cancel,
    );
    let again = change(&mut w1, "the link is reported up again", up).await;
    assert_eq!(again.key, fl);
    assert!(
        matches!(
            again.state,
            LinkState::Up {
                direction: Direction::Dialed,
                ..
            }
        ),
        "{again:?}"
    );
    drop(back);
    cancel.cancel();
}

/// A link that flaps many times between two looks shows once: the newest
/// state. Each close says why (the other device's own words), and a device
/// that links in and has no address for the peer is `WaitingForAddress`;
/// the device that closed its own link says so, and dials when it is
/// wanted.
#[tokio::test]
async fn many_flaps_between_two_looks_are_one_entry_the_newest() {
    let cancel = CancellationToken::new();
    let (a, b) = (key(6), key(7));
    let (fa, fb) = (a.fingerprint(), b.fingerprint());
    let (la, addr) = listener(a, vec![peer(fb, None, true)], &cancel);
    let spec = PeerSpec {
        mode: LinkMode::Off,
        ..peer(fa, Some(&addr), true)
    };
    let db = start(b, vec![spec], None, &cancel);
    let id = db.report().links[0].peer.unwrap();

    let mut watch = la.watch();
    assert!(watch.changed().await.unwrap().is_empty());
    let mut theirs = db.watch();
    theirs.changed().await.unwrap();

    for round in 0..5 {
        db.connect(id);
        within("it links when asked", || is_up(&state(&la, fb))).await;
        db.disconnect(id);
        within("it closes when not asked", || is_down(&state(&la, fb))).await;
        if round == 0 {
            let at_a = state(&la, fb).unwrap();
            let (code, text, next, direction) = why_next(&at_a);
            assert_eq!(code, link_code::LINK_CLOSED_BY_PEER, "{text}");
            assert!(
                text.contains("turned its link off"),
                "its own words: {text}"
            );
            assert_eq!(direction, Some(Direction::Accepted));
            assert_eq!(
                next,
                Next::WaitingForAddress,
                "this device has no address for it: it links in"
            );
            let at_b = change(&mut theirs, "the closing side says so", down).await;
            let (_, text, next, direction) = why_next(&at_b);
            assert!(text.contains("turned its link off"), "{text}");
            assert_eq!(next, Next::WhenWanted, "it links again when asked");
            assert_eq!(direction, Some(Direction::Dialed));
        }
    }
    db.connect(id);
    within("the last link is up", || is_up(&state(&la, fb))).await;

    let batch = watch.changed().await.unwrap();
    assert_eq!(batch.len(), 1, "one entry for the peer: {batch:?}");
    assert_eq!(batch[0].key, fb);
    assert!(up(&batch[0]), "the newest state: {batch:?}");
    let more = tokio::time::timeout(Duration::from_millis(300), watch.changed()).await;
    assert!(more.is_err(), "nothing changed since the look: {more:?}");

    // And a look after a close shows the close, once.
    db.disconnect(id);
    let closed = change(&mut watch, "the close is reported", down).await;
    assert_eq!(closed.key, fb);
    cancel.cancel();
}

/// A first dial that the other device refuses is a down state of the key
/// the peer entry expected, with the reason it gave and no address: redialled
/// (after the longer wait a refusal gets) for a persistent peer, `Gone` for
/// one that is not.
#[tokio::test]
async fn a_refused_first_dial_is_a_down_state_of_the_expected_key() {
    let cancel = CancellationToken::new();
    let (b, a1, a2) = (key(8), key(9), key(10));
    let fb = b.fingerprint();
    // Nobody is expected here: every dial is refused.
    let (_listener, addr) = listener(b, Vec::new(), &cancel);
    let persistent = start(a1, vec![peer(fb, Some(&addr), true)], None, &cancel);
    let once = start(a2, vec![peer(fb, Some(&addr), false)], None, &cancel);

    for (links, persistent) in [(&persistent, true), (&once, false)] {
        let mut watch = links.watch();
        let refused = change(&mut watch, "the refusal is reported", down).await;
        assert_eq!(refused.key, fb, "the key the peer entry expects");
        let (code, text, next, direction) = why_next(&refused);
        assert_eq!(code, link_code::LINK_CLOSED_BY_PEER, "{text}");
        assert!(!text.is_empty() && !text.contains("127.0.0.1"), "{text}");
        assert_eq!(direction, None, "no link was ever up");
        if persistent {
            assert!(
                matches!(next, Next::Redialling { within } if within >= Duration::from_secs(1)),
                "a refusal is retried after the long wait: {next:?}"
            );
        } else {
            assert_eq!(next, Next::Gone);
        }
    }
    cancel.cancel();
}

/// What a device that refuses every link says as its reason: a forged log
/// line, a terminal escape, a bidi override, a zero-width character, the
/// address of a third party, and a page of words.
fn hostile_reason() -> String {
    format!(
        "your key is revoked\n2026-01-01 INFO forged line \x1b[2J\x1b[31m \u{202E}now\u{200B} see 203.0.113.9:6363{}",
        " persuade".repeat(500)
    )
}

/// Whatever a hostile device writes in the reason it refuses with, the
/// status of that peer shows one bounded line of printable words: no control
/// or invisible character, no address, at most `WATCH_TEXT_MAX` characters.
#[tokio::test]
async fn a_hostile_refusal_text_is_one_bounded_line_in_the_status() {
    let cancel = CancellationToken::new();
    let (a, b) = (key(11), key(12));
    let fb = b.fingerprint();
    let shared: Arc<dyn LinkKeySource> = Arc::new(b);
    let socket = bind(&shared, "127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap().to_string();
    let refuser = {
        let socket = Arc::clone(&socket);
        tokio::spawn(async move {
            while let Some(incoming) = socket.accept().await {
                if let Ok(hs) = incoming.handshake().await {
                    hs.refuse(CloseReason::Unrecognized, &hostile_reason());
                }
            }
        })
    };
    let once = start(a, vec![peer(fb, Some(&addr), false)], None, &cancel);
    let mut watch = once.watch();
    let refused = change(&mut watch, "the refusal is reported", down).await;
    let LinkState::Down { why, .. } = &refused.state else {
        panic!("not down: {refused:?}")
    };
    let mut texts = vec![why.text.clone()];
    texts.extend(why.params.values().cloned());
    for text in texts {
        assert!(
            !text.chars().any(|c| c.is_control()
                || matches!(c, '\u{202E}' | '\u{200B}' | '\u{2066}'..='\u{2069}')),
            "control or invisible characters reached the status: {text:?}"
        );
        assert!(
            text.chars().count() <= 1024,
            "{} characters",
            text.chars().count()
        );
        assert!(
            !text.contains("203.0.113.9"),
            "an address in the status: {text:?}"
        );
    }
    assert!(
        why.text
            .contains("your key is revoked 2026-01-01 INFO forged line"),
        "{}",
        why.text
    );
    refuser.abort();
    cancel.cancel();
}
