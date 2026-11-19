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

use std::collections::{BTreeMap, BTreeSet};

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
    /// derived them from the members record in force (each names itself: the
    /// namespace of a context held, or a self-certifying person's; never this
    /// device's own namespace, nor above or below it or another held one).
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

/// Whether `ns` is the root or overlaps `/localhost` or `/localhop` (equal, under
/// or above): a route for it over a peer's link would divert this host's own
/// scopes, or every name.
fn overlaps_local_scope(ns: &Name) -> bool {
    ["localhost", "localhop"].into_iter().any(|scope| {
        let scope = Name::root().append(scope);
        ns.has_prefix(&scope) || scope.has_prefix(ns)
    })
}

impl JoinedSet {
    /// `routes` within [`JOINED_FOLDERS_MAX`] folders and [`JOINED_ROUTES_MAX`]
    /// distinct prefixes in all; what exceeds them is dropped, with a warning
    /// that says so.
    ///
    /// **Each inviter has an equal share of both bounds** (the bound divided by
    /// the number of inviters, at least one; a sole inviter has all of it), taken
    /// from its folders in the order given. Without it, one inviter whose
    /// folders sort first and list the most writers uses up every slot, and the
    /// folders of every other inviter get no route: a denial of service by
    /// whoever invited this device first. The share is not lent to the others
    /// when an inviter does not use it: that keeps the rule one line, and what
    /// one inviter lists never changes what another gets.
    ///
    /// A prefix that overlaps `/localhost` or `/localhop`, or is the root, is
    /// never routed whatever it came from: they are scopes of this host and of
    /// its direct neighbours, which no peer's link may carry Interests for.
    pub(crate) fn bounded(routes: Vec<JoinedRoutes>) -> Self {
        let given = routes.len();
        let inviters: BTreeSet<KeyFingerprint> = routes.iter().map(|f| f.inviter).collect();
        let folder_share = (JOINED_FOLDERS_MAX / inviters.len().max(1)).max(1);
        let route_share = (JOINED_ROUTES_MAX / inviters.len().max(1)).max(1);
        let mut kept = Vec::new();
        let mut prefixes: BTreeSet<Name> = BTreeSet::new();
        let mut per_inviter: BTreeMap<KeyFingerprint, (usize, BTreeSet<Name>)> = BTreeMap::new();
        let (mut folders_dropped, mut dropped, mut local) = (0usize, 0usize, 0usize);
        for mut folder in routes {
            let (folders, own) = per_inviter.entry(folder.inviter).or_default();
            if kept.len() >= JOINED_FOLDERS_MAX || *folders >= folder_share {
                folders_dropped += 1;
                continue;
            }
            *folders += 1;
            let mut taken = Vec::new();
            for ns in folder.namespaces {
                if taken.contains(&ns) {
                    continue;
                }
                if overlaps_local_scope(&ns) {
                    local += 1;
                    continue;
                }
                let room = own.contains(&ns)
                    || (own.len() < route_share
                        && (prefixes.contains(&ns) || prefixes.len() < JOINED_ROUTES_MAX));
                if room {
                    prefixes.insert(ns.clone());
                    own.insert(ns.clone());
                    taken.push(ns);
                } else {
                    dropped += 1;
                }
            }
            folder.namespaces = taken;
            kept.push(folder);
        }
        if folders_dropped > 0 {
            tracing::warn!(
                target: "face.quic",
                given,
                "the joined folders are more than this device routes ({JOINED_FOLDERS_MAX} in all, \
                 shared equally by the inviters): {folders_dropped} folders get no route; end the \
                 folders you no longer use"
            );
        }
        if dropped > 0 {
            tracing::warn!(
                target: "face.quic",
                dropped,
                "the joined folders list more than this device routes ({JOINED_ROUTES_MAX} \
                 distinct namespaces in all, shared equally by the inviters): {dropped} get no \
                 route; a folder with fewer writers, or fewer joined folders, routes them all"
            );
        }
        if local > 0 {
            tracing::warn!(
                target: "face.quic",
                local,
                "a joined folder lists {local} names under /localhost or /localhop, or the root: \
                 they are not routed over a peer's link"
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

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    fn folder(inviter: u8, namespaces: Vec<Name>) -> JoinedRoutes {
        JoinedRoutes {
            inviter: KeyFingerprint([inviter; 32]),
            owner: n("/owner"),
            namespaces,
            push: true,
        }
    }

    /// `count` writers named `/<tag>-<i>`.
    fn writers(tag: &str, count: usize) -> Vec<Name> {
        (0..count).map(|i| n(&format!("/{tag}-{i:02}"))).collect()
    }

    fn kept_by(set: &JoinedSet, inviter: u8) -> Vec<&JoinedRoutes> {
        set.0
            .iter()
            .filter(|f| f.inviter == KeyFingerprint([inviter; 32]))
            .collect()
    }

    /// Round-9 L1: one inviter's folders, sorted first, cannot use up the
    /// budget of namespaces: another inviter's folder keeps its writers.
    #[test]
    fn one_inviter_with_four_full_folders_does_not_starve_another_inviters_folder() {
        let per_folder = JOINED_ROUTES_MAX / 4;
        let mut routes: Vec<JoinedRoutes> = (0..4)
            .map(|i| folder(1, writers(&format!("a{i}"), per_folder)))
            .collect();
        routes.push(folder(2, writers("b", 16)));
        let set = JoinedSet::bounded(routes);
        let b = kept_by(&set, 2);
        assert_eq!(b.len(), 1, "the other inviter's folder was dropped");
        assert_eq!(
            b[0].namespaces,
            writers("b", 16),
            "the other inviter's folder lost writers to a first inviter's four folders"
        );
        let all: BTreeSet<&Name> = set.0.iter().flat_map(|f| &f.namespaces).collect();
        assert!(
            all.len() <= JOINED_ROUTES_MAX,
            "{} namespaces kept, over the bound",
            all.len()
        );
    }

    /// Round-9 L1, the same for the folders: sixteen of one inviter's folders
    /// do not take every slot.
    #[test]
    fn one_inviter_with_sixteen_folders_does_not_starve_another_inviters_folder() {
        let mut routes: Vec<JoinedRoutes> = (0..JOINED_FOLDERS_MAX)
            .map(|i| folder(1, vec![n(&format!("/a{i:02}"))]))
            .collect();
        routes.push(folder(2, vec![n("/b")]));
        let set = JoinedSet::bounded(routes);
        assert_eq!(
            kept_by(&set, 2).len(),
            1,
            "the other inviter's folder got no slot"
        );
        assert!(set.0.len() <= JOINED_FOLDERS_MAX);
    }

    /// A sole inviter has the whole budget, and the first of its prefixes are
    /// kept.
    #[test]
    fn a_sole_inviter_has_the_whole_budget() {
        let set = JoinedSet::bounded(vec![folder(1, writers("w", JOINED_ROUTES_MAX + 6))]);
        assert_eq!(set.0[0].namespaces, writers("w", JOINED_ROUTES_MAX));
    }

    /// Defence in depth (round-9 M1): whatever the device listed, a prefix
    /// that overlaps `/localhost` or `/localhop`, or the root, is not routed.
    #[test]
    fn the_local_scopes_and_the_root_are_never_routed() {
        let set = JoinedSet::bounded(vec![folder(
            1,
            vec![
                n("/localhost"),
                n("/localhost/x"),
                n("/localhop"),
                n("/localhop/x"),
                Name::root(),
                n("/carol"),
            ],
        )]);
        assert_eq!(set.0[0].namespaces, vec![n("/carol")]);
    }
}
