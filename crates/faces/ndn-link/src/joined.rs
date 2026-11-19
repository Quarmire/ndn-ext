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
use ndn_security::sync_group;

use crate::admission::Identity;
use crate::policy::{JOINED_FOLDERS_MAX, JOINED_ROUTES_MAX};

/// A folder this device joined, and the namespaces its link to the inviter
/// routes for it.
///
/// A route is a path, not a right: what may be fetched over the link is
/// decided by the inviter's per-packet filter for the entry the inviter holds
/// for this device, so the inviter drops what a reader may not fetch or push,
/// whatever is routed here ([`JoinedRoutes::push`] says what a reader is not
/// routed).
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
    /// This device writes in the folder: the other writers' sync groups
    /// (`<W>/32=sync`) are routed beside `<W>`. The group is how a writer's
    /// notices and pushes travel, so it is the route a writer-role joiner has
    /// and a reader-role joiner (`false`) has not: a reader is routed `<W>`
    /// only (what it reads of a writer lies under `<W>`), and nothing that
    /// lets it push is installed. The role is the record's, so a record that
    /// promotes or demotes the device re-routes at the next notification.
    pub push: bool,
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
    /// are `identities`: for each folder whose inviter it is and whose owner
    /// one of its identities validates in (an identity of a namespace held
    /// here; a served device of a namespace not held proves nothing about
    /// it), each writer's namespace **and, for a folder this device writes in
    /// ([`JoinedRoutes::push`]), its sync group** (`<W>/32=sync`).
    /// The group needs its own route: this device's data layer registers the
    /// other writers' groups with its own forwarder (to hear their notices),
    /// and a forwarder's longest-prefix match returns that one entry alone, so
    /// a route at `<W>` is shadowed for every name of the group and the
    /// group's Interests would never leave (the by-name case of
    /// `tests/joiner.rs` shows it). Sorted, once each.
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
            .flat_map(|f| {
                f.namespaces.iter().flat_map(move |ns| {
                    let group = f.push.then(|| sync_group(ns));
                    std::iter::once(ns.clone()).chain(group)
                })
            })
            .collect()
    }
}
