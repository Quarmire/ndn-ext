//! The devices this one links with, as the host's configuration names them
//! (or as its namespace advertises its relays), and how each link is kept.

use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;

use ndn_face_quic::KeyFingerprint;
use ndn_packet::Name;

/// A peer's place among this device's peers: stable for the life of
/// [`Links`](crate::Links), also after other peers are removed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerId(pub usize);

/// When a link to a peer is up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkMode {
    /// Always: dialled at once and again whenever it drops; QUIC keep-alives
    /// hold the NAT bindings on the path open. Costs a packet every
    /// keep-alive interval both ways, and keeps a phone's radio waking.
    Always,
    /// On demand: dialled when the host says it is active
    /// ([`Links::set_active`](crate::Links::set_active)), or when an
    /// Interest would go out over the link's routes (the Interest waits for
    /// the link and is sent over it once it is up); closed (as
    /// [`CloseReason::Asleep`](ndn_face_quic::CloseReason::Asleep)) after
    /// `idle` without traffic while the host is not active. Nothing is sent
    /// while it is closed; the first Interest after waits for a handshake.
    OnDemand { idle: Duration },
    /// Off: configured, never dialled until the host asks
    /// ([`Links::connect`](crate::Links::connect)).
    Off,
}

impl LinkMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Always => "always",
            Self::OnDemand { .. } => "on-demand",
            Self::Off => "off",
        }
    }
}

/// Where this device learned of a relay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelaySource {
    /// The person at this device added it (its config, an app's call): its
    /// own server, a community relay, a hosted service.
    User,
    /// The namespace advertises it in its trust context (the root device
    /// listed it).
    Namespace(Name),
}

impl RelaySource {
    /// `user`, or `namespace:<ns>`.
    pub fn describe(&self) -> String {
        match self {
            Self::User => "user".into(),
            Self::Namespace(ns) => format!("namespace:{ns}"),
        }
    }
}

/// A peer this device uses as a relay: one of the devices it links to so
/// that the others of its namespace reach it, and it them, through it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayUse {
    pub source: RelaySource,
    /// Lower is preferred. Of equal preference, a user's relay comes before
    /// the namespace's.
    pub preference: u32,
}

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
    /// The peer this one is reached through. A peer reached through a relay
    /// that names its `device` gets a direct path when the networks allow
    /// it (unless `direct` is false).
    pub relay: Option<PeerId>,
    /// The routes over its link, instead of the default ones.
    pub routes: Option<Vec<Name>>,
    /// Dial it again whenever its link drops.
    pub persistent: bool,
    /// NDNLPv2 reliability on its link.
    pub reliability: bool,
    /// Direct paths with it: this device punches them when it is reached
    /// through a relay, and admits its punches. `false` turns both off.
    pub direct: bool,
    /// When its link is up.
    pub mode: LinkMode,
    /// `Some`: this device uses the peer as a relay (routes its namespaces
    /// over it, at a cost by preference, and fails over between relays).
    pub relay_use: Option<RelayUse>,
    /// Ask the peer (a relay) to hold Interests for this device while it is
    /// asleep, and deliver them when it links again.
    pub hold: bool,
}

impl Default for PeerSpec {
    fn default() -> Self {
        Self {
            label: String::new(),
            key: None,
            device: None,
            endpoints: Vec::new(),
            relay: None,
            routes: None,
            persistent: true,
            reliability: false,
            direct: true,
            mode: LinkMode::Always,
            relay_use: None,
            hold: false,
        }
    }
}

/// The peers, with which of them other peers are reached through. Peers
/// are added and removed while links run; a removed peer's id is not
/// reused.
#[derive(Default)]
pub(crate) struct Peers {
    slots: RwLock<Vec<Option<Arc<PeerSpec>>>>,
}

impl Peers {
    pub(crate) fn new(specs: Vec<PeerSpec>) -> Self {
        Self {
            slots: RwLock::new(specs.into_iter().map(|p| Some(Arc::new(p))).collect()),
        }
    }

    pub(crate) fn get(&self, id: PeerId) -> Option<Arc<PeerSpec>> {
        self.slots.read().get(id.0).cloned().flatten()
    }

    /// The label of `id`, or a placeholder once it was removed.
    pub(crate) fn label(&self, id: PeerId) -> String {
        self.get(id)
            .map_or_else(|| format!("removed peer {}", id.0), |p| p.label.clone())
    }

    pub(crate) fn add(&self, spec: PeerSpec) -> PeerId {
        let mut slots = self.slots.write();
        slots.push(Some(Arc::new(spec)));
        PeerId(slots.len() - 1)
    }

    pub(crate) fn remove(&self, id: PeerId) -> Option<Arc<PeerSpec>> {
        self.slots.write().get_mut(id.0).and_then(Option::take)
    }

    /// Change `id`'s spec; `false` when it was removed.
    pub(crate) fn update(&self, id: PeerId, change: impl FnOnce(&mut PeerSpec)) -> bool {
        let mut slots = self.slots.write();
        let Some(Some(spec)) = slots.get_mut(id.0) else {
            return false;
        };
        change(Arc::make_mut(spec));
        true
    }

    /// Whether `id` is a relay: another peer is reached through it, or this
    /// device uses it as one.
    pub(crate) fn is_relay(&self, id: PeerId) -> bool {
        let slots = self.slots.read();
        slots.get(id.0).cloned().flatten().is_some_and(|p| p.relay_use.is_some())
            || slots.iter().flatten().any(|p| p.relay == Some(id))
    }

    pub(crate) fn iter(&self) -> Vec<(PeerId, Arc<PeerSpec>)> {
        self.slots
            .read()
            .iter()
            .enumerate()
            .filter_map(|(i, p)| p.clone().map(|p| (PeerId(i), p)))
            .collect()
    }

    /// The peer expecting key `fingerprint`, or naming `device`.
    pub(crate) fn find(&self, fingerprint: KeyFingerprint, device: Option<&Name>) -> Option<PeerId> {
        self.find_any(fingerprint, device.as_slice())
    }

    /// The first peer expecting key `fingerprint`, or naming one of
    /// `devices` (the names a device proved, in each of its namespaces).
    pub(crate) fn find_any(&self, fingerprint: KeyFingerprint, devices: &[&Name]) -> Option<PeerId> {
        self.slots
            .read()
            .iter()
            .position(|p| {
                p.as_ref().is_some_and(|p| {
                    p.key == Some(fingerprint) || p.device.as_ref().is_some_and(|d| devices.contains(&d))
                })
            })
            .map(PeerId)
    }

    /// The peers reached through `relay`.
    pub(crate) fn reached_through(&self, relay: PeerId) -> Vec<Arc<PeerSpec>> {
        self.slots
            .read()
            .iter()
            .flatten()
            .filter(|p| p.relay == Some(relay))
            .cloned()
            .collect()
    }
}
