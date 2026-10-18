//! The live links: one per device pair, each with its paths (the link
//! dialled or accepted, and a direct path a punch made), which one stays
//! when both dial, links to make again after an enrollment, and links a
//! revocation ends.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use parking_lot::Mutex;

use ndn_face_quic::{CloseReason, Direction, KeyFingerprint, LinkHandle};
use ndn_packet::Name;
use ndn_security::SignedTrustContext;
use ndn_transport::FaceId;

use crate::admission::Identity;
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
    /// The address of this side's socket.
    pub(crate) local: Option<SocketAddr>,
    pub(crate) since: Instant,
}

/// A path as the table keeps it.
struct LivePath {
    path: LinkPath,
    generation: u64,
}

/// A link to one device, by its key.
struct LiveLink {
    peer: Option<PeerId>,
    identity: Option<Identity>,
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
    pub(crate) identity: Option<Identity>,
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
                    identity: link.identity,
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
        if link.identity.is_some() {
            existing.identity = link.identity;
        }
        if kind == PathKind::Link {
            existing.enrolling = link.enrolling;
        }
        existing.paths.push(new);
        Some(generation)
    }

    /// The path of `generation` to `fingerprint` ended; the link ends with
    /// its last path.
    pub(crate) fn unregister(&self, fingerprint: KeyFingerprint, generation: u64) {
        let mut live = self.live.lock();
        if let Some(link) = live.get_mut(&fingerprint) {
            link.paths.retain(|p| p.generation != generation);
            if link.paths.is_empty() {
                live.remove(&fingerprint);
            }
        }
    }

    /// The live link path of kind [`PathKind::Link`] to `peer`, if any (the
    /// one its dial loop keeps).
    pub(crate) fn link_to(&self, peer: PeerId) -> Option<LinkHandle> {
        self.path_to(|l, _| l.peer == Some(peer), PathKind::Link)
    }

    /// The direct path to the device with key `fingerprint`, or to `peer`.
    pub(crate) fn direct_to(&self, fingerprint: Option<KeyFingerprint>, peer: Option<PeerId>) -> Option<LinkHandle> {
        self.path_to(
            |l, fp| Some(*fp) == fingerprint || (peer.is_some() && l.peer == peer),
            PathKind::Direct,
        )
    }

    fn path_to(&self, matches: impl Fn(&LiveLink, &KeyFingerprint) -> bool, kind: PathKind) -> Option<LinkHandle> {
        let live = self.live.lock();
        live.iter()
            .filter(|(fp, l)| matches(l, fp))
            .flat_map(|(_, l)| l.paths.iter())
            .find(|p| p.path.kind == kind)
            .map(|p| p.path.handle.clone())
    }

    /// The addresses linked devices see this device at, through the socket
    /// bound at `local`: its reflexive candidates there. From full links
    /// only (an enrollment link's other side is not confirmed).
    pub(crate) fn observed(&self, local: SocketAddr) -> Vec<SocketAddr> {
        let live = self.live.lock();
        let mut out: Vec<SocketAddr> = Vec::new();
        for link in live.values().filter(|l| l.enrolling.is_empty()) {
            for p in &link.paths {
                if p.path.local == Some(local)
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
                device: l.identity.as_ref().map(|id| id.device.clone()),
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

    /// This device switched to the key certified by `certificate`: close
    /// each enrollment link for a namespace that key is certified in, and
    /// mark its peer to be dialled again, now as an enrolled device.
    pub(crate) fn relink_enrolled(&self, certificate: &Name) {
        let mut closing = Vec::new();
        {
            let live = self.live.lock();
            for link in live.values() {
                let Some(ns) = link
                    .enrolling
                    .iter()
                    .find(|ns| ndn_cert::roles::parse_device_key(ns, certificate).is_some())
                else {
                    continue;
                };
                let text = format!(
                    "this device enrolled in {ns} ({certificate}); it links again as an enrolled device"
                );
                for p in &link.paths {
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
        self.relink
            .lock()
            .remove(&peer)
    }

    /// Close each link whose certificate (or an issuer of it) `ctx`, newly
    /// adopted, revokes.
    pub(crate) fn close_revoked(&self, ctx: &Arc<SignedTrustContext>) {
        let live = self.live.lock();
        for link in live.values() {
            let Some(id) = &link.identity else { continue };
            if !id.device.has_prefix(ctx.namespace()) {
                continue;
            }
            if let Some(revoked) = id.certificates.iter().find(|c| ctx.is_revoked(c)) {
                let text = format!(
                    "{revoked} is revoked in {} (trust context v{}); this link is closed",
                    ctx.namespace(),
                    ctx.version()
                );
                for p in &link.paths {
                    tracing::warn!(target: "face.quic", face = p.path.face.0, peer = %id.device, "{text}");
                }
                link.close(CloseReason::Revoked, &text);
            }
        }
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
        assert!(keeps_existing(Direction::Dialed, Direction::Accepted, Some(small), large));
        assert!(!keeps_existing(Direction::Accepted, Direction::Dialed, Some(small), large));
        // The larger key: the other device's dial stays.
        assert!(keeps_existing(Direction::Accepted, Direction::Dialed, Some(large), small));
        assert!(!keeps_existing(Direction::Dialed, Direction::Accepted, Some(large), small));
        // Same direction (a redial after a lost link): the newer wins.
        for dir in [Direction::Dialed, Direction::Accepted] {
            assert!(!keeps_existing(dir, dir, Some(small), large));
        }
        assert!(!keeps_existing(Direction::Dialed, Direction::Accepted, None, large));
    }
}
