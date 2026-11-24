//! The live links: one per device pair, each with its paths (the link
//! dialled or accepted, and a direct path a punch made), which one stays
//! when both dial, links to make again after an enrollment or a change of
//! this device's memberships, and the links (or the memberships of links) a
//! revocation ends.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime};

use parking_lot::Mutex;
use tokio_util::sync::CancellationToken;

use ndn_face_quic::{CloseReason, Direction, KeyFingerprint, LinkHandle};
use ndn_packet::Name;
use ndn_security::{SignedTrustContext, sync_group};
use ndn_transport::{Face, FaceId};

use crate::admission::{Identity, RENEW};
use crate::grants::Grant;
use crate::host::Route;
use crate::joined::JoinedSet;
use crate::peer::PeerId;
use crate::policy::{DIAL_RACE_WINDOW, JOINED_ROUTE_COST};
use crate::routes::RelayRoutes;
use crate::status::{PathKind, PathStatus};

/// Which link stays when a link to a device that is already linked comes
/// up: each side dialled the other (the directions differ), and both keep
/// the link dialled by the device with the smaller key fingerprint. In any
/// other case the newer link replaces the older one (the other device
/// dialled again, having lost the older one). `mine` is `None` when this
/// device has no usable key: the newer link wins.
pub fn keeps_existing(
    existing: Direction,
    new: Direction,
    mine: Option<KeyFingerprint>,
    theirs: KeyFingerprint,
) -> bool {
    existing != new
        && mine.is_some_and(|mine| {
            let keep_mine = mine < theirs;
            (existing == Direction::Dialed) == keep_mine
        })
}

/// One way a link reaches its device: a QUIC connection and its face.
pub(crate) struct LinkPath {
    pub(crate) face: FaceId,
    pub(crate) handle: LinkHandle,
    pub(crate) direction: Direction,
    /// [`PathKind::Link`] or [`PathKind::Direct`].
    pub(crate) kind: PathKind,
    /// Cancelled once the path's face and routes are gone.
    pub(crate) gone: CancellationToken,
    pub(crate) since: Instant,
    /// Sends over the path's face directly, past the forwarder: Interests
    /// that waited for this link (on demand, or held while the device
    /// slept) go out this way.
    pub(crate) sender: Arc<Face>,
    /// The routes the path's face got.
    pub(crate) routes: Vec<Route>,
    /// On a link path to a relay this device uses (with no `routes` of its
    /// own): the namespaces it routes as the relay's and their cost, kept
    /// current by [`LinkTable::reroute_relays`].
    pub(crate) relay: Option<RelayRoutes>,
    /// A full link: a path of kind [`PathKind::Link`] that is no enrollment,
    /// introduction or departure link. Only a full link gets the joiner's
    /// routes.
    pub(crate) full: bool,
    /// The prefixes of the joiner's routes ([`LinkTable::reroute_joined`])
    /// this path's face got, and no other route of it is among them.
    pub(crate) joined: Vec<Name>,
}

/// What a link path's face gains and loses when the namespaces it routes
/// over a relay change ([`LinkTable::reroute_relays`]).
pub(crate) struct Rerouted {
    pub(crate) face: FaceId,
    pub(crate) added: Vec<Route>,
    pub(crate) removed: Vec<Name>,
}

/// A path that ended, as [`LinkTable::unregister`] reports it.
pub(crate) struct Ended {
    pub(crate) peer: Option<PeerId>,
    /// The identities the link was admitted by (still), the deciding one
    /// first.
    pub(crate) identities: Vec<Identity>,
    pub(crate) kind: PathKind,
    pub(crate) routes: Vec<Route>,
    /// It was an enrollment link.
    pub(crate) enrolling: bool,
    /// No path of the link is left: the device is not linked any more.
    pub(crate) last: bool,
}

/// A device linked over a full link, for presence: its identity in the
/// namespace asked for.
pub(crate) struct Member {
    pub(crate) fingerprint: KeyFingerprint,
    pub(crate) identity: Identity,
    pub(crate) handle: LinkHandle,
}

/// A membership a revocation took from a link that stays up (another
/// membership still admits it): the routes its face loses, and the link's
/// handle, to tell the device it is no longer listed in that namespace.
pub(crate) struct Dropped {
    pub(crate) namespace: Name,
    pub(crate) routes: Vec<(FaceId, Vec<Name>)>,
    pub(crate) handle: Option<LinkHandle>,
}

/// A direct path up now, as [`LinkTable::direct_paths`] lists it.
pub(crate) struct DirectUp {
    pub(crate) fingerprint: KeyFingerprint,
    pub(crate) peer: Option<PeerId>,
    pub(crate) device: Option<Name>,
    pub(crate) handle: LinkHandle,
    /// Cancelled once the path's face and routes are gone.
    pub(crate) gone: CancellationToken,
}

/// A path as the table keeps it.
struct LivePath {
    path: LinkPath,
    generation: u64,
}

/// A link to one device, by its key.
struct LiveLink {
    peer: Option<PeerId>,
    /// The identities it was admitted by, the deciding one first.
    identities: Vec<Identity>,
    /// The grant that admitted it, when no policy did: its end closes the
    /// link.
    grant: Option<Grant>,
    /// The namespaces this device showed in its hello on the link path
    /// (its link key's and its memberships'): when they change, the link
    /// is made again.
    shown: Vec<Name>,
    /// The namespaces this link is an enrollment link for, on either side,
    /// for this device's enrollment: once this device enrolls in one, the
    /// link is made again as a full link.
    enrolling: Vec<Name>,
    /// Its paths: at most one of each kind (the one-link rule applies per
    /// kind).
    paths: Vec<LivePath>,
}

impl LiveLink {
    fn close(&self, reason: CloseReason, text: &str) {
        for p in &self.paths {
            p.path.handle.close(reason, text);
        }
    }
}

/// What [`LinkTable::register`] records about an admitted link.
pub(crate) struct Registration {
    pub(crate) fingerprint: KeyFingerprint,
    pub(crate) peer: Option<PeerId>,
    pub(crate) identities: Vec<Identity>,
    /// The namespaces this device showed in its hello (sorted).
    pub(crate) shown: Vec<Name>,
    pub(crate) enrolling: Vec<Name>,
    pub(crate) path: LinkPath,
    /// The grant that admitted the link, when no policy did.
    pub(crate) grant: Option<Grant>,
}

/// A live link as [`LinkTable::views`] reports it.
pub(crate) struct LinkView {
    pub(crate) fingerprint: KeyFingerprint,
    pub(crate) peer: Option<PeerId>,
    pub(crate) device: Option<Name>,
    /// The grant that admitted the link, when one did.
    pub(crate) granted: Option<Grant>,
    pub(crate) paths: Vec<PathStatus>,
}

/// Which of the links this device accepted an address change lost.
#[derive(Clone, Copy)]
pub(crate) enum Gone<'a> {
    /// Every one: the host says the network changed, and not what changed.
    Every,
    /// Those accepted at one of these addresses of this device.
    At(&'a BTreeSet<IpAddr>),
}

#[derive(Default)]
pub(crate) struct LinkTable {
    live: Mutex<HashMap<KeyFingerprint, LiveLink>>,
    generation: AtomicU64,
    /// Peers to dial again once (even when not persistent): their
    /// enrollment link was closed because this device enrolled.
    relink: Mutex<HashSet<PeerId>>,
    /// The joiner's routes ([`Links::set_joined_routes`](crate::Links::set_joined_routes)),
    /// read under `live` by every registration and reroute, so what a path
    /// is given is always of the newest set.
    joined: Mutex<JoinedSet>,
    /// Notified when a link is admitted: its certificates may lapse before the
    /// ones the task that ends lapsed links sleeps for.
    lapse_wake: Arc<tokio::sync::Notify>,
}

const ALREADY_LINKED: &str = "a link between these two devices already exists";
const ALREADY_DIRECT: &str = "a newer direct path between these two devices took this one's place";

impl LinkTable {
    /// Record an admitted path and return its generation; `None` when the
    /// path of its kind already in place stays and this one was closed
    /// instead. A path of another kind joins the link: a direct path is a
    /// second path of the link to that device, not a link of its own.
    pub(crate) fn register(&self, link: Registration, mine: Option<KeyFingerprint>) -> Option<u64> {
        let generation = self.register_path(link, mine);
        self.lapse_wake.notify_one();
        generation
    }

    fn register_path(&self, link: Registration, mine: Option<KeyFingerprint>) -> Option<u64> {
        let generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        let kind = link.path.kind;
        let text = match kind {
            PathKind::Direct => ALREADY_DIRECT,
            _ => ALREADY_LINKED,
        };
        let mut live = self.live.lock();
        let new = LivePath {
            path: link.path,
            generation,
        };
        let Some(existing) = live.get_mut(&link.fingerprint) else {
            live.insert(
                link.fingerprint,
                LiveLink {
                    peer: link.peer,
                    identities: link.identities,
                    grant: link.grant,
                    shown: link.shown,
                    enrolling: link.enrolling,
                    paths: vec![new],
                },
            );
            return Some(generation);
        };
        // Only a link registered within `DIAL_RACE_WINDOW` can be the other
        // half of a simultaneous dial; an older one that the same device
        // dials past has been lost on its side (it moved, §17D.3), and the
        // newer link, proven by the same key, replaces it.
        if existing
            .paths
            .iter()
            .filter(|p| p.path.kind == kind)
            .filter(|p| p.path.since.elapsed() < DIAL_RACE_WINDOW)
            .any(|p| keeps_existing(p.path.direction, new.path.direction, mine, link.fingerprint))
        {
            new.path.handle.close(CloseReason::Replaced, text);
            return None;
        }
        for p in existing.paths.iter().filter(|p| p.path.kind == kind) {
            p.path.handle.close(CloseReason::Replaced, text);
        }
        existing.paths.retain(|p| p.path.kind != kind);
        if link.peer.is_some() {
            existing.peer = link.peer;
        }
        if !link.identities.is_empty() {
            existing.identities = link.identities;
            existing.grant = link.grant;
        }
        if kind == PathKind::Link {
            existing.enrolling = link.enrolling;
            existing.shown = link.shown;
        }
        existing.paths.push(new);
        Some(generation)
    }

    /// The path of `generation` to `fingerprint` ended; the link ends with
    /// its last path. `None` when the path was not registered (any more).
    pub(crate) fn unregister(&self, fingerprint: KeyFingerprint, generation: u64) -> Option<Ended> {
        let mut live = self.live.lock();
        let link = live.get_mut(&fingerprint)?;
        let at = link.paths.iter().position(|p| p.generation == generation)?;
        let path = link.paths.remove(at).path;
        let ended = Ended {
            peer: link.peer,
            identities: link.identities.clone(),
            kind: path.kind,
            routes: path.routes,
            enrolling: !link.enrolling.is_empty(),
            last: link.paths.is_empty(),
        };
        if ended.last {
            live.remove(&fingerprint);
        }
        Some(ended)
    }

    /// The face of the link path to `peer`.
    pub(crate) fn link_face(&self, peer: PeerId) -> Option<FaceId> {
        let live = self.live.lock();
        live.values()
            .filter(|l| l.peer == Some(peer))
            .flat_map(|l| l.paths.iter())
            .find(|p| p.path.kind == PathKind::Link)
            .map(|p| p.path.face)
    }

    /// Whether the device with key `fingerprint` is linked (over any path).
    pub(crate) fn is_linked(&self, fingerprint: &KeyFingerprint) -> bool {
        self.live.lock().contains_key(fingerprint)
    }

    /// Whether the device with key `fingerprint` is linked and has shown a
    /// certificate of a namespace this device holds.
    pub(crate) fn is_identified(&self, fingerprint: &KeyFingerprint) -> bool {
        self.live
            .lock()
            .get(fingerprint)
            .is_some_and(|l| !l.identities.is_empty())
    }

    /// The sender of the link to the device with key `fingerprint` (its
    /// link path, else its direct path).
    pub(crate) fn sender_to(&self, fingerprint: &KeyFingerprint) -> Option<Arc<Face>> {
        let live = self.live.lock();
        let link = live.get(fingerprint)?;
        link.paths
            .iter()
            .find(|p| p.path.kind == PathKind::Link)
            .or_else(|| link.paths.first())
            .map(|p| Arc::clone(&p.path.sender))
    }

    /// The key of the device linked as `peer`, and the sender of its link
    /// path.
    pub(crate) fn peer_sender(&self, peer: PeerId) -> Option<(KeyFingerprint, Arc<Face>)> {
        let live = self.live.lock();
        live.iter()
            .filter(|(_, l)| l.peer == Some(peer))
            .find_map(|(fp, l)| {
                l.paths
                    .iter()
                    .find(|p| p.path.kind == PathKind::Link)
                    .map(|p| (*fp, Arc::clone(&p.path.sender)))
            })
    }

    /// The devices linked over a full link path with an identity in
    /// `namespace`, each with that identity.
    pub(crate) fn members(&self, namespace: &Name) -> Vec<Member> {
        let live = self.live.lock();
        live.iter()
            .filter(|(_, l)| l.enrolling.is_empty())
            .filter_map(|(fp, l)| {
                let identity = l.identities.iter().find(|id| &id.namespace == namespace)?;
                let path = l.paths.iter().find(|p| p.path.kind == PathKind::Link)?;
                Some(Member {
                    fingerprint: *fp,
                    identity: identity.clone(),
                    handle: path.path.handle.clone(),
                })
            })
            .collect()
    }

    /// The devices the link to `fingerprint` was admitted by now, in the
    /// namespaces this device holds: whom a departure told over that link is
    /// told by. Empty for a link that is none of a full link's (an enrollment
    /// link, an introduction link, a link with no identity of a held
    /// namespace): what such a peer says is not heard.
    pub(crate) fn peer_devices(&self, fingerprint: &KeyFingerprint) -> Vec<Name> {
        let live = self.live.lock();
        live.get(fingerprint)
            .filter(|l| {
                l.enrolling.is_empty() && l.paths.iter().any(|p| p.path.kind == PathKind::Link)
            })
            .map(|l| {
                l.identities
                    .iter()
                    .filter(|id| id.served.is_none())
                    .map(|id| id.device.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Direct paths up now.
    pub(crate) fn direct_count(&self) -> usize {
        self.live
            .lock()
            .values()
            .filter(|l| l.paths.iter().any(|p| p.path.kind == PathKind::Direct))
            .count()
    }

    /// The live link path of kind [`PathKind::Link`] to `peer`, if any (the
    /// one its dial loop keeps).
    pub(crate) fn link_to(&self, peer: PeerId) -> Option<LinkHandle> {
        self.path_to(|l, _| l.peer == Some(peer), PathKind::Link)
    }

    /// The direct path up to the device with key `fingerprint`, or to
    /// `peer`, with that device's key. A path that ended, or that this side
    /// closed, is not up even before its end is handled.
    pub(crate) fn direct_to(
        &self,
        fingerprint: Option<KeyFingerprint>,
        peer: Option<PeerId>,
    ) -> Option<(KeyFingerprint, LinkHandle)> {
        let live = self.live.lock();
        live.iter()
            .filter(|(fp, l)| Some(**fp) == fingerprint || (peer.is_some() && l.peer == peer))
            .find_map(|(fp, l)| {
                l.paths
                    .iter()
                    .find(|p| p.path.kind == PathKind::Direct && !p.path.handle.is_closed())
                    .map(|p| (*fp, p.path.handle.clone()))
            })
    }

    /// The direct paths up now (as [`LinkTable::direct_to`] counts them).
    pub(crate) fn direct_paths(&self) -> Vec<DirectUp> {
        let live = self.live.lock();
        live.iter()
            .flat_map(|(fp, l)| {
                l.paths
                    .iter()
                    .filter(|p| p.path.kind == PathKind::Direct && !p.path.handle.is_closed())
                    .map(|p| DirectUp {
                        fingerprint: *fp,
                        peer: l.peer,
                        device: l.identities.first().map(|id| id.device.clone()),
                        handle: p.path.handle.clone(),
                        gone: p.path.gone.clone(),
                    })
            })
            .collect()
    }

    fn path_to(
        &self,
        matches: impl Fn(&LiveLink, &KeyFingerprint) -> bool,
        kind: PathKind,
    ) -> Option<LinkHandle> {
        let live = self.live.lock();
        live.iter()
            .filter(|(fp, l)| matches(l, fp))
            .flat_map(|(_, l)| l.paths.iter())
            .find(|p| p.path.kind == kind)
            .map(|p| p.path.handle.clone())
    }

    /// The addresses linked devices see this device at, through the socket
    /// bound at `local` now: its reflexive candidates there. From full links
    /// only (an enrollment link's other side is not confirmed).
    pub(crate) fn observed(&self, local: SocketAddr) -> Vec<SocketAddr> {
        let live = self.live.lock();
        let mut out: Vec<SocketAddr> = Vec::new();
        for link in live.values().filter(|l| l.enrolling.is_empty()) {
            for p in &link.paths {
                if p.path.handle.local_address() == Some(local)
                    && let Some(addr) = p.path.handle.observed_address()
                    && !out.contains(&addr)
                {
                    out.push(addr);
                }
            }
        }
        out
    }

    /// Every live link with its paths, for status.
    pub(crate) fn views(&self) -> Vec<LinkView> {
        let now = Instant::now();
        let live = self.live.lock();
        live.iter()
            .map(|(fp, l)| LinkView {
                granted: l.grant.clone(),
                fingerprint: *fp,
                peer: l.peer,
                device: l.identities.first().map(|id| id.device.clone()),
                paths: l
                    .paths
                    .iter()
                    .map(|p| PathStatus {
                        kind: p.path.kind,
                        face: p.path.face,
                        remote: Some(p.path.handle.remote_address()),
                        rtt: Some(p.path.handle.rtt()),
                        age: now.saturating_duration_since(p.path.since),
                        reliability: p.path.sender.link_service.snapshot().lp_reliability,
                        via: None,
                    })
                    .collect(),
            })
            .collect()
    }

    /// Close the link to `fingerprint` when only a grant admitted it and
    /// `closes` says so of the identities it was admitted by, saying `text`;
    /// `true` when one was closed.
    pub(crate) fn close_granted(
        &self,
        fingerprint: &KeyFingerprint,
        reason: CloseReason,
        text: &str,
        closes: impl Fn(&[Identity]) -> bool,
    ) -> bool {
        let live = self.live.lock();
        match live.get(fingerprint) {
            Some(link) if link.grant.is_some() && closes(&link.identities) => {
                link.close(reason, text);
                true
            }
            _ => false,
        }
    }

    /// The handles of the paths of the link to `fingerprint` when only a
    /// grant admitted it: what narrows to a departure when its last entry
    /// ends.
    pub(crate) fn granted_handles(&self, fingerprint: &KeyFingerprint) -> Vec<LinkHandle> {
        let live = self.live.lock();
        match live.get(fingerprint) {
            Some(link) if link.grant.is_some() => {
                link.paths.iter().map(|p| p.path.handle.clone()).collect()
            }
            _ => Vec::new(),
        }
    }

    /// Close every path of every link (the device went offline), saying
    /// `text`.
    pub(crate) fn close_all(&self, reason: CloseReason, text: &str) {
        let live = self.live.lock();
        for link in live.values() {
            link.close(reason, text);
        }
    }

    /// Close the link paths (not direct paths) this device accepted that an
    /// address change lost (`gone`), saying why: a QUIC server cannot follow
    /// its address (RFC 9000 §9), so a link accepted at an address that is
    /// gone is lost to both sides until an idle timeout. The device dials
    /// again from where it is now. A link accepted at an address that stays
    /// is not touched; nor is one whose accepted-at address is not known
    /// ([`LinkHandle::accepted_ip`]): which address went cannot say it is
    /// lost, and a link that is lost ends at the idle timeout or by the other
    /// device's dial, as any does. Returns how many were closed.
    pub(crate) fn close_accepted(&self, gone: Gone<'_>) -> usize {
        let live = self.live.lock();
        let mut closed = 0;
        for link in live.values() {
            for p in link.paths.iter().filter(|p| {
                p.path.kind == PathKind::Link && p.path.direction == Direction::Accepted
            }) {
                let text = match gone {
                    Gone::Every => "this device's address changed: a link it accepted cannot \
                                    follow it, and this device links again from where it is now"
                        .to_string(),
                    Gone::At(addresses) => {
                        let Some(ip) = p
                            .path
                            .handle
                            .accepted_ip()
                            .filter(|ip| addresses.contains(ip))
                        else {
                            continue;
                        };
                        format!(
                            "this device's address {ip} is gone: a link accepted at it cannot \
                             follow it, and this device links again from where it is now"
                        )
                    }
                };
                p.path.handle.close(CloseReason::Released, &text);
                closed += 1;
            }
        }
        closed
    }

    /// This device now holds the certificates `certificates`: close each
    /// enrollment link for a namespace one of them is certified in, and mark
    /// its peer to be dialled again, now as an enrolled device.
    pub(crate) fn relink_enrolled(&self, certificates: &[Name]) {
        self.relink_where(|link| {
            let (ns, cert) = link.enrolling.iter().find_map(|ns| {
                certificates
                    .iter()
                    .find(|c| ndn_cert::roles::parse_device_key(ns, c).is_some())
                    .map(|c| (ns, c))
            })?;
            Some(format!(
                "this device enrolled in {ns} ({cert}); it links again as an enrolled device"
            ))
        });
    }

    /// This device's namespaces are `shown` now (sorted): close each full
    /// link whose hello showed others, and mark its peer to be dialled again,
    /// so the other device knows this one in each of them. A link this
    /// device did not dial is dialled again by the other device (the close
    /// is transient).
    pub(crate) fn relink_changed(&self, shown: &[Name]) {
        self.relink_where(|link| {
            if !link.enrolling.is_empty() || link.shown == shown {
                return None;
            }
            Some(format!(
                "this device's trusted prefixes changed (now {}); it links again to show them",
                if shown.is_empty() {
                    "none".to_string()
                } else {
                    crate::admission::list(shown)
                }
            ))
        });
    }

    /// A trust context was adopted: close each full link to a device this
    /// device dialled by its key alone (no identity of it admitted yet) whose
    /// namespace `held` now says this device holds, and mark its peer to be
    /// dialled again, so the device is identified in it and admitted by its
    /// certificate (an introduction's joiner dials the inviter by key before
    /// it trusts its namespace). A link to a peer `introduced` (one a code's
    /// dial added) is made again whatever enrollment its party told this
    /// device it is on: the party chose that verdict, and the dial was never
    /// for an enrollment.
    pub(crate) fn relink_identified(
        &self,
        held: impl Fn(PeerId) -> bool,
        introduced: impl Fn(PeerId) -> bool,
    ) {
        self.relink_where(|link| {
            let peer = link.peer?;
            (link.identities.is_empty()
                && (link.enrolling.is_empty() || introduced(peer))
                && held(peer))
            .then(|| {
                "this device now holds the namespace of the device this link reaches; it links \
                 again to identify it"
                    .to_string()
            })
        });
    }

    /// Close the link paths of each link `why` gives a reason for, with
    /// [`CloseReason::Enrolled`], marking their peers to be dialled again.
    fn relink_where(&self, why: impl Fn(&LiveLink) -> Option<String>) {
        let mut closing = Vec::new();
        {
            let live = self.live.lock();
            for link in live.values() {
                let Some(text) = why(link) else { continue };
                for p in link.paths.iter().filter(|p| p.path.kind == PathKind::Link) {
                    closing.push((p.path.handle.clone(), p.path.face, link.peer, text.clone()));
                }
            }
        }
        // Marked before closing, so the dial loop that sees the close dials
        // again.
        self.relink
            .lock()
            .extend(closing.iter().filter_map(|(_, _, peer, _)| *peer));
        for (handle, face, _, text) in closing {
            tracing::info!(target: "face.quic", face = face.0, "{text}");
            handle.close(CloseReason::Enrolled, &text);
        }
    }

    /// Whether `peer` is to be dialled again once.
    pub(crate) fn take_relink(&self, peer: PeerId) -> bool {
        self.relink.lock().remove(&peer)
    }

    /// `ctx`, newly adopted, revokes certificates: take from each link the
    /// identities in its namespace whose certificate (or an issuer of it) it
    /// revokes. A link left with no identity is closed; one that another
    /// membership still admits stays, losing the routes of that identity
    /// (returned, for the caller to take from the forwarder).
    pub(crate) fn close_revoked(&self, ctx: &Arc<SignedTrustContext>) -> Vec<Dropped> {
        self.drop_identities(
            CloseReason::Revoked,
            |id| {
                if !id.device.has_prefix(ctx.namespace()) {
                    return None;
                }
                id.certificates
                    .iter()
                    .find(|c| ctx.is_revoked(c))
                    .map(|revoked| {
                        format!(
                            "{revoked} is revoked in {} (trust context v{})",
                            ctx.namespace(),
                            ctx.version()
                        )
                    })
            },
            None,
        )
    }

    /// The certificate of an identity of a live link lapsed (the clock passed
    /// its NotAfter): as for a revocation, take the identity from its link,
    /// closing a link left with none ([`CloseReason::Unrecognized`]: the key has
    /// no valid certificate now, as a hello with the lapsed one is refused), and
    /// return what a link that stays loses.
    pub(crate) fn close_lapsed(&self, now: SystemTime) -> Vec<Dropped> {
        self.drop_identities(CloseReason::Unrecognized, |id| id.lapse(now), Some(RENEW))
    }

    /// When the first certificate of an identity of a live link lapses.
    pub(crate) fn next_lapse(&self) -> Option<SystemTime> {
        self.live
            .lock()
            .values()
            .flat_map(|link| link.identities.iter())
            .filter_map(|id| id.lapses.as_ref().map(|(_, at)| *at))
            .min()
    }

    /// Wakes the task that ends the links of lapsed certificates when a link is
    /// admitted (its identities may lapse before the ones it slept for).
    pub(crate) fn lapse_wake(&self) -> Arc<tokio::sync::Notify> {
        Arc::clone(&self.lapse_wake)
    }

    /// Take from each link the identities `ended` gives a reason for (every one
    /// that has: a link may lose several). A link left with no identity is
    /// closed with `reason` and the words `text; this link is closed[: advice]`;
    /// one that another membership still admits stays, losing the routes of
    /// that identity (returned, for the caller to take from the forwarder).
    fn drop_identities(
        &self,
        reason: CloseReason,
        ended: impl Fn(&Identity) -> Option<String>,
        advice: Option<&str>,
    ) -> Vec<Dropped> {
        let mut dropped = Vec::new();
        let mut live = self.live.lock();
        for link in live.values_mut() {
            while let Some((at, text)) = link
                .identities
                .iter()
                .enumerate()
                .find_map(|(at, id)| ended(id).map(|text| (at, text)))
            {
                let id = link.identities.remove(at);
                if link.identities.is_empty() {
                    let text = closed_text(&text, advice);
                    for p in &link.paths {
                        tracing::warn!(target: "face.quic", face = p.path.face.0, peer = %id.device, "{text}");
                    }
                    link.close(reason, &text);
                    break;
                }
                let mut prefixes = vec![id.device.clone(), id.namespace.clone()];
                // The namespace's sync group goes with the last identity in it.
                if !link.identities.iter().any(|i| i.namespace == id.namespace) {
                    prefixes.push(sync_group(&id.namespace));
                }
                let mut routes = Vec::new();
                for p in &mut link.paths {
                    let gone: Vec<Name> = p
                        .path
                        .routes
                        .iter()
                        .filter(|r| prefixes.contains(&r.prefix))
                        .map(|r| r.prefix.clone())
                        .collect();
                    p.path.routes.retain(|r| !prefixes.contains(&r.prefix));
                    tracing::warn!(
                        target: "face.quic",
                        face = p.path.face.0,
                        peer = %id.device,
                        "{text}; the link stays, admitted by {}, without its routes in {}",
                        link.identities.iter().map(|i| i.device.to_string()).collect::<Vec<_>>().join(", "),
                        id.namespace
                    );
                    if !gone.is_empty() {
                        routes.push((p.path.face, gone));
                    }
                }
                dropped.push(Dropped {
                    namespace: id.namespace,
                    routes,
                    handle: link
                        .paths
                        .iter()
                        .find(|p| p.path.kind == PathKind::Link)
                        .map(|p| p.path.handle.clone()),
                });
            }
        }
        dropped
    }

    /// Route over each link path to a relay the namespaces `routed` gives
    /// for its peer now (`None`: leave it): the path's record gains the
    /// new ones and loses the ones no longer given, a prefix another of
    /// its routes still needs staying routed. What each face gains and
    /// loses, for the caller to give the forwarder.
    pub(crate) fn reroute_relays(
        &self,
        routed: impl Fn(PeerId) -> Option<Vec<Name>>,
    ) -> Vec<Rerouted> {
        let mut out = Vec::new();
        let mut live = self.live.lock();
        for link in live.values_mut() {
            let Some(now) = link.peer.and_then(&routed) else {
                continue;
            };
            for p in &mut link.paths {
                let path = &mut p.path;
                let Some(relay) = path.relay.as_mut() else {
                    continue;
                };
                let mut added = Vec::new();
                for ns in now.iter().filter(|ns| !relay.namespaces.contains(ns)) {
                    let route = Route {
                        prefix: ns.clone(),
                        cost: relay.cost,
                    };
                    if !path.routes.iter().any(|r| r.prefix == *ns) {
                        added.push(route.clone());
                    }
                    path.routes.push(route);
                }
                let mut removed = Vec::new();
                for ns in relay.namespaces.iter().filter(|ns| !now.contains(ns)) {
                    if let Some(at) = path.routes.iter().position(|r| r.prefix == *ns) {
                        path.routes.remove(at);
                    }
                    if !path.routes.iter().any(|r| r.prefix == *ns) {
                        removed.push(ns.clone());
                    }
                }
                relay.namespaces.clone_from(&now);
                if !added.is_empty() || !removed.is_empty() {
                    out.push(Rerouted {
                        face: path.face,
                        added,
                        removed,
                    });
                }
            }
        }
        out
    }

    /// Route over each full link path the prefixes of the joiner's set it
    /// is wanted for now (`set`, when given, replaces the set first): the
    /// path's face gains the new ones and loses the ones no longer wanted.
    /// A prefix one of the path's own routes already has is left to that
    /// route (never overwritten with this one's cost, never removed on its
    /// behalf). `apply` is told each face's change **while the table is
    /// locked**: a path that ends leaves the table before its face is
    /// removed, so a change is never given to a face that is gone. It must
    /// not call back into the links.
    pub(crate) fn reroute_joined(&self, set: Option<JoinedSet>, mut apply: impl FnMut(&Rerouted)) {
        let mut live = self.live.lock();
        let mut joined = self.joined.lock();
        if let Some(set) = set {
            *joined = set;
        }
        for (fingerprint, link) in live.iter_mut() {
            let wanted = joined.wanted(fingerprint, &link.identities);
            for p in &mut link.paths {
                let path = &mut p.path;
                let now: Vec<Name> = if path.full && path.kind == PathKind::Link {
                    wanted
                        .iter()
                        .filter(|ns| !path.routes.iter().any(|r| r.prefix == **ns))
                        .cloned()
                        .collect()
                } else {
                    Vec::new()
                };
                let added: Vec<Route> = now
                    .iter()
                    .filter(|ns| !path.joined.contains(ns))
                    .map(|ns| Route {
                        prefix: ns.clone(),
                        cost: JOINED_ROUTE_COST,
                    })
                    .collect();
                let removed: Vec<Name> = path
                    .joined
                    .iter()
                    .filter(|ns| !now.contains(ns))
                    .filter(|ns| !path.routes.iter().any(|r| r.prefix == **ns))
                    .cloned()
                    .collect();
                path.joined = now;
                if !added.is_empty() || !removed.is_empty() {
                    apply(&Rerouted {
                        face: path.face,
                        added,
                        removed,
                    });
                }
            }
        }
    }

    /// Give the full link paths of `key`'s link, when a grant admitted it, the
    /// routes of `routes` they lack (a route a path has is left alone), and
    /// tell `apply` the face and what was added, with the table locked (it
    /// must not call back into the links). A link that is no grant's, or an
    /// enrollment, introduction or departure path, gets none.
    pub(crate) fn add_grant_routes(
        &self,
        key: &KeyFingerprint,
        routes: &[Route],
        mut apply: impl FnMut(FaceId, &[Route]),
    ) {
        let mut live = self.live.lock();
        let Some(link) = live.get_mut(key).filter(|l| l.grant.is_some()) else {
            return;
        };
        for p in &mut link.paths {
            let path = &mut p.path;
            if !path.full || path.kind != PathKind::Link {
                continue;
            }
            let added: Vec<Route> = routes
                .iter()
                .filter(|r| !path.routes.iter().any(|have| have.prefix == r.prefix))
                .cloned()
                .collect();
            if !added.is_empty() {
                path.routes.extend(added.iter().cloned());
                apply(path.face, &added);
            }
        }
    }
}

/// The words a link closed for the loss of its last identity carries: why, that
/// the link is closed, and (when there is something to do) what to do.
fn closed_text(why: &str, advice: Option<&str>) -> String {
    match advice {
        Some(advice) => format!("{why}; this link is closed: {advice}"),
        None => format!("{why}; this link is closed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn when_both_dial_the_smaller_fingerprints_dial_stays() {
        let small = KeyFingerprint([1; 32]);
        let large = KeyFingerprint([2; 32]);
        // This device has the smaller key: its own dial stays, the
        // other's is closed, whichever came up first.
        assert!(keeps_existing(
            Direction::Dialed,
            Direction::Accepted,
            Some(small),
            large
        ));
        assert!(!keeps_existing(
            Direction::Accepted,
            Direction::Dialed,
            Some(small),
            large
        ));
        // The larger key: the other device's dial stays.
        assert!(keeps_existing(
            Direction::Accepted,
            Direction::Dialed,
            Some(large),
            small
        ));
        assert!(!keeps_existing(
            Direction::Dialed,
            Direction::Accepted,
            Some(large),
            small
        ));
        // Same direction (a redial after a lost link): the newer wins.
        for dir in [Direction::Dialed, Direction::Accepted] {
            assert!(!keeps_existing(dir, dir, Some(small), large));
        }
        assert!(!keeps_existing(
            Direction::Dialed,
            Direction::Accepted,
            None,
            large
        ));
    }

    /// R12 L2(b): the words a link closed for a lapsed certificate carries say which
    /// certificate lapsed and when, that the link is closed, and what to do.
    #[test]
    fn a_link_closed_for_a_lapsed_certificate_says_why_and_what_to_do() {
        use std::time::Duration;
        let cert: Name = "/a/member/phone/KEY/k/NDNCERT/v=1".parse().unwrap();
        let at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let id = Identity {
            namespace: "/a".parse().unwrap(),
            version: 1,
            device: "/a/member/phone".parse().unwrap(),
            role: ndn_cert::roles::Role::Member,
            certificates: vec![cert.clone()],
            served: None,
            lapses: Some((cert.clone(), at)),
        };
        let why = id.lapse(at + Duration::from_secs(1)).expect("lapsed");
        let text = closed_text(&why, Some(RENEW));
        for must in [
            cert.to_string().as_str(),
            "2023-11-14 22:13:20 UTC",
            "NotAfter",
            "this link is closed",
            "renew",
        ] {
            assert!(text.contains(must), "`{must}` is not in: {text}");
        }
    }
}
