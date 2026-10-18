//! What the host provides: trust data, the forwarder's faces and routes,
//! where to dial, and the words its users know.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use ndn_face_quic::KeyFingerprint;
use ndn_packet::Name;
use ndn_security::{Certificate, Keyring};
use ndn_transport::{Face, FaceId};
use tokio_util::sync::CancellationToken;

use crate::peer::{PeerId, PeerSpec};

/// The trust data links are admitted from.
pub trait LinkTrust: Send + Sync + 'static {
    /// The trust contexts this device holds, kept current by the host
    /// (links whose certificates a newly adopted version revokes are closed
    /// from its revocation events).
    fn keyring(&self) -> &Arc<Keyring>;

    /// This device's hello: the certificate of the key it links with now,
    /// then that certificate's issuers, nearest first (wire-encoded Data).
    /// Empty when the current key has no certificate.
    fn own_chain(&self) -> Vec<Bytes>;

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
        peer.endpoints.iter().cloned().map(PathCandidate::Endpoint).collect()
    }
}

/// How the person at a device does what a refusal or a log line asks of
/// them, in the host's own terms (its commands, its configuration).
#[derive(Clone, Debug)]
pub struct LinkHints {
    /// How to enroll this device, e.g. "`ndn-fwd enroll <invite link>`, or
    /// by an admin's approval".
    pub enroll: String,
    /// How to renew a certificate, e.g. "`ndn-fwd renew`".
    pub renew: String,
    /// How to fetch the newest trust context, e.g. "`ndn-fwd context
    /// refresh`".
    pub refresh: String,
    /// What the host's configuration calls a [`PeerSpec`], e.g.
    /// "[[peer]]".
    pub peer_entry: String,
    /// How to make this device expect a key; `{key}` stands for the key's
    /// fingerprint. E.g. "add [[peer]] key = \"{key}\" to the other
    /// device's config".
    pub expect_key: String,
}
