//! The live links: one per device pair, each with its paths (the link
//! dialled or accepted, and a direct path a punch made), which one stays
//! when both dial, links to make again after an enrollment or a change of
//! this device's memberships, and the links (or the memberships of links) a
//! revocation ends.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use parking_lot::Mutex;
use tokio_util::sync::CancellationToken;

use ndn_face_quic::{CloseReason, Direction, KeyFingerprint, LinkHandle};
use ndn_packet::Name;
use ndn_security::SignedTrustContext;
use ndn_transport::{Face, FaceId};

use crate::admission::Identity;
use crate::host::Route;
use crate::peer::PeerId;
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
}

/// A live link as [`LinkTable::views`] reports it.
pub(crate) struct LinkView {
    pub(crate) fingerprint: KeyFingerprint,
    pub(crate) peer: Option<PeerId>,
    pub(crate) device: Option<Name>,
    pub(crate) paths: Vec<PathStatus>,
}

#[derive(Default)]
pub(crate) struct LinkTable {
    live: Mutex<HashMap<KeyFingerprint, LiveLink>>,
    generation: AtomicU64,
    /// Peers to dial again once (even when not persistent): their
    /// enrollment link was closed because this device enrolled.
    relink: Mutex<HashSet<PeerId>>,
}

const ALREADY_LINKED: &str = "a link between these two devices already exists";
const ALREADY_DIRECT: &str = "a newer direct path between these two devices took this one's place";

impl LinkTable {
    /// Record an admitted path and return its generation; `None` when the
    /// path of its kind already in place stays and this one was closed
    /// instead. A path of another kind joins the link: a direct path is a
    /// second path of the link to that device, not a link of its own.
    pub(crate) fn register(&self, link: Registration, mine: Option<KeyFingerprint>) -> Option<u64> {
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
                    shown: link.shown,
                    enrolling: link.enrolling,
                    paths: vec![new],
                },
            );
            return Some(generation);
        };
        if existing
            .paths
            .iter()
            .filter(|p| p.path.kind == kind)
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
                        via: None,
                    })
                    .collect(),
            })
            .collect()
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
        let mut dropped = Vec::new();
        let mut live = self.live.lock();
        for link in live.values_mut() {
            let Some(at) = link.identities.iter().position(|id| {
                id.device.has_prefix(ctx.namespace())
                    && id.certificates.iter().any(|c| ctx.is_revoked(c))
            }) else {
                continue;
            };
            let id = link.identities.remove(at);
            let revoked = id
                .certificates
                .iter()
                .find(|c| ctx.is_revoked(c))
                .expect("found above");
            let text = format!(
                "{revoked} is revoked in {} (trust context v{})",
                ctx.namespace(),
                ctx.version()
            );
            if link.identities.is_empty() {
                let text = format!("{text}; this link is closed");
                for p in &link.paths {
                    tracing::warn!(target: "face.quic", face = p.path.face.0, peer = %id.device, "{text}");
                }
                link.close(CloseReason::Revoked, &text);
                continue;
            }
            let prefixes = [id.device.clone(), id.namespace.clone()];
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
                    ctx.namespace()
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
        dropped
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
}
