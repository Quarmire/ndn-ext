//! Direct paths on real forwarders: two members of a namespace linked to its
//! relay get a direct path by membership, and when one of them moves to
//! another address (`Links::network_changed`) the direct path is made again
//! at once from the new address, whichever of the two dialled it. A QUIC
//! server cannot migrate (RFC 9000 §9): without the punch again, the device
//! that accepted the path would lose it until the other's idle timeout.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use ndn_engine::{EngineBuilder, EngineConfig, ShutdownHandle};
use ndn_face_quic::{KeyFingerprint, LinkEndpoint, LinkKey, LinkKeySource, LinkTransportConfig};
use ndn_link::{
    ConfiguredEndpoints, EngineFaces, HostCandidates, LinkHints, LinkSetup, LinkTrust, Links, PathKind, PeerSpec,
    RelaySource, RelayUse,
};
use ndn_packet::Name;
use ndn_security::{Certificate, Ed25519Signer, Keyring, SecurityManager, SecurityProfile, SignedTrustContext, Signer};
use tokio_util::sync::CancellationToken;

const NS: &str = "/home";

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

/// The namespace: its root key and signed trust context (default link
/// policy: members link and get direct paths, `node` devices relay).
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

/// A device on a forwarder of its own, its links on a loopback socket.
struct Device {
    links: Arc<Links>,
    key: KeyFingerprint,
    addr: SocketAddr,
    cancel: CancellationToken,
    _shutdown: ShutdownHandle,
}

impl Drop for Device {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

async fn device(home: &Home, name: &str, seed: u8, listen: bool, peers: Vec<PeerSpec>) -> Device {
    let key_name = n(&format!("{NS}{name}/KEY/k{seed}"));
    let signer = Arc::new(Ed25519Signer::from_seed(&[seed; 32], key_name.clone()));
    let cert = home.certify(&key_name, signer.public_key().unwrap()).await;
    let key = LinkKey::from_signer(signer).unwrap();
    let fingerprint = key.fingerprint();
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .security_profile(SecurityProfile::Disabled)
        .build()
        .await
        .unwrap();
    let keyring = Arc::new(Keyring::new());
    assert!(keyring.adopt(Arc::clone(&home.context)));
    let transport = LinkTransportConfig::default();
    let key: Arc<dyn LinkKeySource> = Arc::new(key);
    let socket = Arc::new(LinkEndpoint::bind("127.0.0.1:0".parse().unwrap(), Arc::clone(&key), &transport, listen).unwrap());
    let addr = socket.local_addr().unwrap();
    let cancel = CancellationToken::new();
    let links = Links::start(
        LinkSetup {
            peers,
            key,
            trust: Arc::new(Trust {
                keyring,
                chain: vec![cert.data_wire().unwrap()],
            }),
            faces: Arc::new(EngineFaces(engine)),
            paths: Arc::new(ConfiguredEndpoints),
            // Devices on one machine: loopback host candidates.
            candidates: vec![Arc::new(HostCandidates { include_local: true })],
            socket: Some(socket),
            transport,
            hints: LinkHints {
                enroll: "enroll it".into(),
                renew: "renew it".into(),
                refresh: "refresh it".into(),
                peer_entry: "[[peer]]".into(),
                expect_key: "expect {key}".into(),
            },
            relays: Default::default(),
            service: Default::default(),
            direct: Default::default(),
        },
        cancel.clone(),
    );
    Device {
        links,
        key: fingerprint,
        addr,
        cancel,
        _shutdown: shutdown,
    }
}

/// A member `/home/member/<name>` linked to `relay`, which it uses.
async fn member(home: &Home, name: &str, seed: u8, relay: &Device) -> Device {
    let to_relay = PeerSpec {
        label: "relay".into(),
        device: Some(n(&format!("{NS}/node/relay"))),
        endpoints: vec![relay.addr.to_string()],
        persistent: true,
        relay_use: Some(RelayUse {
            source: RelaySource::User,
            preference: 0,
        }),
        ..Default::default()
    };
    device(home, &format!("/member/{name}"), seed, false, vec![to_relay]).await
}

/// The remote address of `on`'s direct path to the device with key `to`.
fn direct_to(on: &Device, to: KeyFingerprint) -> Option<SocketAddr> {
    on.links
        .report()
        .links
        .iter()
        .filter(|l| l.key == Some(to))
        .flat_map(|l| l.paths.iter())
        .find(|p| p.kind == PathKind::Direct)
        .and_then(|p| p.remote)
}

async fn within(what: &str, limit: Duration, mut done: impl FnMut() -> bool) -> Duration {
    let start = Instant::now();
    while !done() {
        assert!(start.elapsed() < limit, "not within {limit:?}: {what}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    start.elapsed()
}

/// Move the member with the larger key fingerprint (`larger`), or the
/// other, and check the direct path is made again from its new address
/// well within the direct-path idle timeout (8 s).
async fn a_moved_member_gets_its_direct_path_again(larger: bool) {
    let home = Home::new();
    let relay = device(&home, "/node/relay", 1, true, Vec::new()).await;
    let a = member(&home, "a", 2, &relay).await;
    let b = member(&home, "b", 3, &relay).await;
    let (mover, other) = if (a.key > b.key) == larger { (&a, &b) } else { (&b, &a) };
    within("a direct path between the members", Duration::from_secs(20), || {
        direct_to(mover, other.key).is_some() && direct_to(other, mover.key) == Some(mover.addr)
    })
    .await;

    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let moved = socket.local_addr().unwrap();
    assert_ne!(moved, mover.addr);
    mover.links.network_changed(Some(socket));
    let took = within(
        "the direct path made again from the moved member's new address",
        Duration::from_secs(4),
        || direct_to(other, mover.key) == Some(moved) && direct_to(mover, other.key).is_some(),
    )
    .await;
    // The old path went with the move: the other member has one direct
    // path to the mover, at its new address.
    let report = other.links.report();
    let paths: Vec<_> = report
        .links
        .iter()
        .filter(|l| l.key == Some(mover.key))
        .flat_map(|l| l.paths.iter())
        .filter(|p| p.kind == PathKind::Direct)
        .collect();
    assert_eq!(paths.len(), 1, "{paths:?}");
    eprintln!("direct path again {took:?} after the move (mover has the larger key: {larger})");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_member_that_accepted_its_direct_path_gets_it_again_at_once_after_moving() {
    // The larger fingerprint answers the punch and accepts the dial: the
    // QUIC server, which cannot migrate.
    a_moved_member_gets_its_direct_path_again(true).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_member_that_dialled_its_direct_path_gets_it_again_at_once_after_moving() {
    a_moved_member_gets_its_direct_path_again(false).await;
}
