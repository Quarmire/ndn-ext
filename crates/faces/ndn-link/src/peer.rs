//! The devices this one links with, as the host's configuration names them.

use ndn_face_quic::KeyFingerprint;
use ndn_packet::Name;

/// A peer's place in [`LinkSetup::peers`](crate::LinkSetup::peers).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PeerId(pub usize);

/// A device this one links with: dials when it has endpoints, and admits
/// (or confirms) when it links in.
#[derive(Clone, Debug)]
pub struct PeerSpec {
    /// How messages name the peer (its device name, else its key).
    pub label: String,
    /// The expected fingerprint of its key: a dial fails unless the peer
    /// presents that key, and a link with that key is admitted whatever its
    /// certificate.
    pub key: Option<KeyFingerprint>,
    /// The device (`/<namespace>/<role>/<device>`) it must prove to be.
    pub device: Option<Name>,
    /// `host:port` endpoints to dial, in order.
    pub endpoints: Vec<String>,
    /// The peer this one is reached through.
    pub relay: Option<PeerId>,
    /// The routes over its link, instead of the default ones.
    pub routes: Option<Vec<Name>>,
    /// Dial it again whenever its link drops.
    pub persistent: bool,
    /// NDNLPv2 reliability on its link.
    pub reliability: bool,
}

/// The configured peers, with which of them other peers are reached
/// through.
pub(crate) struct Peers {
    specs: Vec<PeerSpec>,
    is_relay: Vec<bool>,
}

impl Peers {
    pub(crate) fn new(specs: Vec<PeerSpec>) -> Self {
        let is_relay = (0..specs.len())
            .map(|i| specs.iter().any(|p| p.relay == Some(PeerId(i))))
            .collect();
        Self { specs, is_relay }
    }

    pub(crate) fn get(&self, id: PeerId) -> &PeerSpec {
        &self.specs[id.0]
    }

    /// Whether another peer is reached through `id`.
    pub(crate) fn is_relay(&self, id: PeerId) -> bool {
        self.is_relay[id.0]
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (PeerId, &PeerSpec)> {
        self.specs.iter().enumerate().map(|(i, p)| (PeerId(i), p))
    }

    /// The peer expecting key `fingerprint`, or naming `device`.
    pub(crate) fn find(&self, fingerprint: KeyFingerprint, device: Option<&Name>) -> Option<PeerId> {
        self.specs
            .iter()
            .position(|p| p.key == Some(fingerprint) || device.is_some_and(|d| p.device.as_ref() == Some(d)))
            .map(PeerId)
    }

    /// The peers reached through `relay`.
    pub(crate) fn reached_through(&self, relay: PeerId) -> impl Iterator<Item = &PeerSpec> {
        self.specs.iter().filter(move |p| p.relay == Some(relay))
    }
}
