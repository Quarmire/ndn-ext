//! The live links: one per device pair, which one stays when both dial,
//! links to make again after an enrollment, and links a revocation ends.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;

use ndn_face_quic::{CloseReason, Direction, KeyFingerprint, LinkHandle};
use ndn_packet::Name;
use ndn_security::SignedTrustContext;
use ndn_transport::FaceId;

use crate::admission::Identity;
use crate::peer::PeerId;

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
}

/// A link to one device, by its key.
struct LiveLink {
    generation: u64,
    peer: Option<PeerId>,
    identity: Option<Identity>,
    /// The namespaces this link is an enrollment link for, on either side,
    /// for this device's enrollment: once this device enrolls in one, the
    /// link is made again as a full link.
    enrolling: Vec<Name>,
    /// The paths of the link; one today (the one-link rule keeps one
    /// connection per device pair).
    paths: Vec<LinkPath>,
}

impl LiveLink {
    fn close(&self, reason: CloseReason, text: &str) {
        for path in &self.paths {
            path.handle.close(reason, text);
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

#[derive(Default)]
pub(crate) struct LinkTable {
    live: Mutex<HashMap<KeyFingerprint, LiveLink>>,
    generation: AtomicU64,
    /// Peers to dial again once (even when not persistent): their
    /// enrollment link was closed because this device enrolled.
    relink: Mutex<HashSet<PeerId>>,
}

const ALREADY_LINKED: &str = "a link between these two devices already exists";

impl LinkTable {
    /// Record an admitted link and return its generation; `None` when the
    /// link already in place stays and this one was closed instead.
    pub(crate) fn register(&self, link: Registration, mine: Option<KeyFingerprint>) -> Option<u64> {
        let generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        let mut live = self.live.lock();
        if let Some(existing) = live.get(&link.fingerprint) {
            if existing
                .paths
                .iter()
                .any(|p| keeps_existing(p.direction, link.path.direction, mine, link.fingerprint))
            {
                link.path.handle.close(CloseReason::Replaced, ALREADY_LINKED);
                return None;
            }
            existing.close(CloseReason::Replaced, ALREADY_LINKED);
        }
        live.insert(
            link.fingerprint,
            LiveLink {
                generation,
                peer: link.peer,
                identity: link.identity,
                enrolling: link.enrolling,
                paths: vec![link.path],
            },
        );
        Some(generation)
    }

    /// The link of `generation` to `fingerprint` ended.
    pub(crate) fn unregister(&self, fingerprint: KeyFingerprint, generation: u64) {
        let mut live = self.live.lock();
        if live
            .get(&fingerprint)
            .is_some_and(|l| l.generation == generation)
        {
            live.remove(&fingerprint);
        }
    }

    /// The live link to `peer`, if any.
    pub(crate) fn link_to(&self, peer: PeerId) -> Option<LinkHandle> {
        let live = self.live.lock();
        live.values()
            .find(|l| l.peer == Some(peer))
            .and_then(|l| l.paths.first())
            .map(|p| p.handle.clone())
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
                for path in &link.paths {
                    closing.push((path.handle.clone(), path.face, link.peer, text.clone()));
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
                for path in &link.paths {
                    tracing::warn!(target: "face.quic", face = path.face.0, peer = %id.device, "{text}");
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
