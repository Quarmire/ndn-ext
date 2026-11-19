//! The joiner's routes: the namespaces of the other writers of a folder this
//! device joined, routed over its link to the inviter (ndn-rs `ndn-link.md`
//! §8.7, rules 16–18; SHAPES-R9 §A).
//!
//! The inviter's grant link carries the names of the folder's other writers
//! (their summary roots, sync groups, trust contexts, keys and certificates),
//! but only the joiner's own forwarder can send an Interest for them over it:
//! it needs a route. The device knows which writers the folder's members
//! record lists (`Device::joined_folders`), the link layer knows which link is
//! the inviter's, and a host keeps no link state, so the link layer installs
//! the route itself, on the strength of data the device verified and over the
//! one link that can be trusted to carry it: [`Links::set_joined_routes`].
//!
//! [`Links::set_joined_routes`]: crate::Links::set_joined_routes

use std::collections::BTreeSet;

use ndn_face_quic::KeyFingerprint;
use ndn_packet::Name;

use crate::admission::Identity;
use crate::policy::{JOINED_FOLDERS_MAX, JOINED_ROUTES_MAX};

/// A folder this device joined, and the namespaces its link to the inviter
/// routes for it.
///
/// A route is a path, not a right: what may be fetched over the link is
/// decided by the inviter's per-packet filter for the entry the inviter holds
/// for this device, so a reader-role joiner is routed the same prefixes and
/// the inviter drops what a reader may not fetch or push.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JoinedRoutes {
    /// The inviter's link key. The route is installed over the full link
    /// whose handshake proved this key, and over no other.
    pub inviter: KeyFingerprint,
    /// The folder's namespace, which is the inviter's. The link must have
    /// been admitted by an identity that validates in it: a key shown by a
    /// device of no such namespace gets no route, whatever it is named.
    pub owner: Name,
    /// The prefixes to route: the other writers' namespaces, as the device
    /// derived them from the members record in force (never this device's own
    /// namespace, nor one above or below it).
    pub namespaces: Vec<Name>,
}

/// The set as [`Links::set_joined_routes`](crate::Links::set_joined_routes)
/// holds it: within its bounds, replaced whole.
#[derive(Clone, Debug, Default)]
pub(crate) struct JoinedSet(Vec<JoinedRoutes>);

impl JoinedSet {
    /// `routes` within [`JOINED_FOLDERS_MAX`] folders and [`JOINED_ROUTES_MAX`]
    /// distinct prefixes in all, in the order given; what exceeds them is
    /// dropped, with a warning that says so.
    pub(crate) fn bounded(routes: Vec<JoinedRoutes>) -> Self {
        let given = routes.len();
        let mut kept = Vec::new();
        let mut prefixes: BTreeSet<Name> = BTreeSet::new();
        let mut dropped = 0usize;
        for mut folder in routes.into_iter().take(JOINED_FOLDERS_MAX) {
            let mut taken = Vec::new();
            for ns in folder.namespaces {
                if taken.contains(&ns) {
                    continue;
                }
                if prefixes.contains(&ns) || prefixes.len() < JOINED_ROUTES_MAX {
                    prefixes.insert(ns.clone());
                    taken.push(ns);
                } else {
                    dropped += 1;
                }
            }
            folder.namespaces = taken;
            kept.push(folder);
        }
        if given > JOINED_FOLDERS_MAX {
            tracing::warn!(
                target: "face.quic",
                given,
                "the joined folders are more than the {JOINED_FOLDERS_MAX} this device routes: \
                 the folders after the first {JOINED_FOLDERS_MAX} get no route; end the folders \
                 you no longer use"
            );
        }
        if dropped > 0 {
            tracing::warn!(
                target: "face.quic",
                dropped,
                "the joined folders list more than {JOINED_ROUTES_MAX} distinct namespaces: \
                 {dropped} get no route; a folder with fewer writers, or fewer joined folders, \
                 routes them all"
            );
        }
        Self(kept)
    }

    /// The prefixes to route over the link to `fingerprint`, whose identities
    /// are `identities`: those of each folder whose inviter it is and whose
    /// owner one of its identities validates in (an identity of a namespace
    /// held here; a served device of a namespace not held proves nothing
    /// about it). Sorted, once each.
    pub(crate) fn wanted(
        &self,
        fingerprint: &KeyFingerprint,
        identities: &[Identity],
    ) -> BTreeSet<Name> {
        self.0
            .iter()
            .filter(|f| f.inviter == *fingerprint)
            .filter(|f| {
                identities
                    .iter()
                    .any(|id| id.served.is_none() && id.namespace == f.owner)
            })
            .flat_map(|f| f.namespaces.iter().cloned())
            .collect()
    }
}
