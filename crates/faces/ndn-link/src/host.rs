//! What the host provides: trust data, the forwarder's faces and routes,
//! and where to dial.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use ndn_face_quic::KeyFingerprint;
use ndn_packet::Name;
use ndn_security::{Certificate, Keyring, Signer};
use ndn_transport::{Face, FaceId};
use tokio_util::sync::CancellationToken;

use crate::peer::{PeerId, PeerSpec};

/// A namespace this device is a member of: its certificate there and the
/// key that certificate certifies.
#[derive(Clone)]
pub struct OwnMembership {
    /// The namespace, e.g. `/work`.
    pub namespace: Name,
    /// This device's certificate in the namespace, then that certificate's
    /// issuers, nearest first (wire-encoded Data).
    pub chain: Vec<Bytes>,
    /// The key the certificate certifies, which signs this membership's
    /// binding to each link ([`ndn_face_quic::Membership`]).
    pub signer: Arc<dyn Signer>,
}

impl std::fmt::Debug for OwnMembership {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnMembership")
            .field("namespace", &self.namespace)
            .field("key", self.signer.key_name())
            .finish()
    }
}

/// The trust data links are admitted from.
pub trait LinkTrust: Send + Sync + 'static {
    /// The trust contexts this device holds, kept current by the host
    /// (links whose certificates a newly adopted version revokes are closed
    /// from its revocation events).
    fn keyring(&self) -> &Arc<Keyring>;

    /// This device's hello: the certificate of the key it links with now
    /// (its TLS key, the node key), then that certificate's issuers,
    /// nearest first (wire-encoded Data). Empty when the current key has no
    /// certificate.
    fn own_chain(&self) -> Vec<Bytes>;

    /// Every namespace this device is a member of, with its certificate
    /// chain and key there. The one the link key's certificate is in may be
    /// listed too; the others are shown on each link as a membership bound
    /// to it, so a peer identifies this device in each. A device holding
    /// one identity (its link key's) has none beyond it.
    fn own_memberships(&self) -> Vec<OwnMembership> {
        Vec::new()
    }

    /// A certificate this device already has — one it serves, or one it
    /// validated and cached — by name (a key name picks the newest valid
    /// one). Never fetched: a peer's chain is validated before its link is
    /// up.
    fn known_certificate(&self, name: &Name) -> Option<Certificate>;

    /// A certificate this device already has of the key with `fingerprint`
    /// (SHA-256 of the key as a certificate carries it), whatever its name
    /// — the newest valid one, else the newest. Never fetched. A key that
    /// sends no certificate is told revoked by it.
    fn known_certificate_of_key(&self, fingerprint: &KeyFingerprint) -> Option<Certificate>;
}

/// A route a link gets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    pub prefix: Name,
    pub cost: u32,
}

/// The host's forwarder: where an admitted link's face and routes go.
pub trait FaceSink: Send + Sync + 'static {
    /// The id the next link face gets.
    fn alloc_face_id(&self) -> FaceId;

    /// Run an admitted link's face until `cancel` (or until the link ends,
    /// when [`remove_face`](Self::remove_face) follows). A link face is
    /// persistent: only its link's end removes it.
    fn add_face(&self, face: Face, cancel: CancellationToken);

    /// The link of `face` ended.
    fn remove_face(&self, face: FaceId);

    /// Route `routes` to `face`, each prefix covering the names under it.
    fn add_routes(&self, face: FaceId, routes: &[Route]);

    /// Take the routes of `prefixes` from `face` again (routes this crate
    /// added with [`add_routes`](Self::add_routes); the face stays).
    fn remove_routes(&self, face: FaceId, prefixes: &[Name]);

    /// A device of `namespace`, a namespace this device does not hold, is
    /// linked here and served by the serving policy (`true`), or one such
    /// link ended (`false`; calls pair up). While any is linked, the
    /// forwarder carries the namespace's Data **in transit**: it forwards
    /// it to the Interests pending for it without validating it (it holds
    /// neither the namespace's trust context nor its certificates; the
    /// devices that asked validate it) and caches none of it. A forwarder
    /// that validates nothing in transit anyway does nothing here.
    fn transit(&self, namespace: &Name, served: bool);
}

/// Where a peer may be dialled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PathCandidate {
    /// A `host:port` endpoint, resolved when it is dialled (every address
    /// it resolves to, in order).
    Endpoint(String),
    /// An address known already (discovered, or learned from another
    /// device).
    Address(SocketAddr),
}

/// Where to dial each peer, in order of preference; the first path that
/// links wins.
pub trait PathSource: Send + Sync + 'static {
    fn candidates(&self, id: PeerId, peer: &PeerSpec) -> Vec<PathCandidate>;
}

/// The paths the peer's configuration names: its endpoints, in order.
#[derive(Clone, Copy, Debug, Default)]
pub struct ConfiguredEndpoints;

impl PathSource for ConfiguredEndpoints {
    fn candidates(&self, _: PeerId, peer: &PeerSpec) -> Vec<PathCandidate> {
        peer.endpoints
            .iter()
            .cloned()
            .map(PathCandidate::Endpoint)
            .collect()
    }
}
