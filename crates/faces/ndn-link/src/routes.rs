//! The routes an admitted link gets.

use ndn_cert::roles::Role;
use ndn_packet::Name;
use ndn_security::cert_name::key_name_of;
use ndn_security::sync_group;

use crate::admission::{Admitted, Enrollment, Identity};
use crate::host::Route;
use crate::peer::{PeerSpec, Peers};
use crate::policy::VIA_RELAY_COST;

/// The routes a relay this device uses gets: the namespaces of this device
/// it is used for and the namespaces this device follows, at the relay's
/// rank. A link path keeps the ones it routed, so a namespace followed
/// later is routed over it at once ([`Links::followed_changed`]).
///
/// [`Links::followed_changed`]: crate::Links::followed_changed
#[derive(Clone, Debug)]
pub(crate) struct RelayRoutes {
    pub(crate) namespaces: Vec<Name>,
    pub(crate) cost: u32,
}

/// The routes over a link to the admitted peer: the peer's `routes`, else
/// this device's namespaces for a relay it uses (`relay`: at the relay's
/// rank) followed by the relay's own default routes (its device name, or
/// the namespace of a `node` this device dials), else, for each identity
/// the peer was admitted by, its namespace for a relay this device dials
/// (a `node` device whose peer entry has a path — whichever side's dial
/// the link came from) or its device name; the routes of the peers reached
/// through it; for each served identity, its issuers' key names
/// ([`issuer_routes`]); and the sync group of each namespace the peer was
/// admitted in, held here or served ([`group_routes`]). An enrollment
/// link: none on the relay (answers return the way their Interests came),
/// the namespace on the enrolling device. A prefix may appear twice (a
/// relay namespace that is also a default route): the forwarder keeps one
/// route per prefix and face, and a namespace no longer routed keeps the
/// route its other entry needs.
pub(crate) fn routes_for(
    peers: &Peers,
    admitted: &Admitted,
    dials: bool,
    relay: Option<RelayRoutes>,
) -> Vec<Route> {
    match &admitted.enrollment {
        Some(Enrollment::Relay(_)) => return Vec::new(),
        Some(Enrollment::Device(ns)) => {
            return vec![Route {
                prefix: ns.clone(),
                cost: 0,
            }];
        }
        None => {}
    }
    let base = relay.as_ref().map_or(0, |r| r.cost);
    let at = |cost| move |prefix| Route { prefix, cost };
    let peer = admitted.peer.and_then(|i| peers.get(i));
    let own = match (&relay, peer.as_ref().and_then(|p| p.routes.clone())) {
        (Some(r), None) => {
            let mut own = r.namespaces.clone();
            own.extend(default_routes(peer.as_deref(), &admitted.identities, dials));
            own
        }
        _ => default_routes(peer.as_deref(), &admitted.identities, dials),
    };
    let mut routes: Vec<Route> = own.into_iter().map(at(base)).collect();
    if let Some(index) = admitted.peer {
        for reached in peers.reached_through(index) {
            routes.extend(
                default_routes(Some(&reached), &[], false)
                    .into_iter()
                    .map(at(base + VIA_RELAY_COST)),
            );
        }
    }
    routes.extend(issuer_routes(&admitted.identities, base));
    let carried = admitted.identities.iter().map(|id| &id.namespace);
    routes.extend(group_routes(carried, base));
    routes
}

/// The routes a link gets for the issuers of its served identities: the
/// key name (`<identity>/KEY/<key-id>`) of each certificate a served
/// identity's hello showed beyond its device name, once, at `cost`. This
/// device holds no trust context of a served namespace, so it neither
/// validates nor caches its certificates; a consumer validating a served
/// device's Data fetches the chain by name, and the device answers its own
/// issuer certificates (the ones it keeps from its enrollment, or a CA's
/// own). A held identity gets none: this device resolves its chain itself.
fn issuer_routes(identities: &[Identity], cost: u32) -> Vec<Route> {
    let mut routes: Vec<Route> = Vec::new();
    for id in identities.iter().filter(|id| id.served.is_some()) {
        for cert in &id.certificates {
            let prefix = key_name_of(cert);
            if !prefix.has_prefix(&id.device) && !routes.iter().any(|r| r.prefix == prefix) {
                routes.push(Route { prefix, cost });
            }
        }
    }
    routes
}

/// The routes a link carrying `namespaces` gets for their sync groups:
/// `<ns>/32=sync` ([`ndn_security::sync_group`]) for each, once, at `cost`.
/// A link carries a namespace when its peer was admitted in it: as a
/// member of a namespace this device holds, or served for one it does not
/// (a relay's served devices). Its forwarder runs the group with the
/// multicast strategy (the trust-context library for a held namespace, the
/// host's [`FaceSink::transit`](crate::FaceSink::transit) while a served
/// one is in transit), so a Sync Interest goes over every such link and to
/// the local member, whose own registration of the group sits beside these
/// routes. They come and go with the link's other routes: added when it is
/// up, taken when it ends or a revocation takes the namespace's membership
/// from it.
pub fn group_routes<'a>(namespaces: impl IntoIterator<Item = &'a Name>, cost: u32) -> Vec<Route> {
    let mut routes: Vec<Route> = Vec::new();
    for ns in namespaces {
        let prefix = sync_group(ns);
        if !routes.iter().any(|r| r.prefix == prefix) {
            routes.push(Route { prefix, cost });
        }
    }
    routes
}

/// The prefixes a link to `peer` will route, known before it is up (for
/// the waiting routes of an on-demand link): its `routes`, else, for a
/// relay it uses, the namespaces its link path routes
/// (`relay_namespaces`) and its device name, else its device name.
pub(crate) fn predicted_routes(peer: &PeerSpec, relay_namespaces: &[Name]) -> Vec<Name> {
    if let Some(routes) = &peer.routes {
        return routes.clone();
    }
    let mut routes = Vec::new();
    if peer.relay_use.is_some() {
        routes.extend_from_slice(relay_namespaces);
    }
    if let Some(device) = &peer.device
        && !routes.contains(device)
    {
        routes.push(device.clone());
    }
    routes
}

fn default_routes(peer: Option<&PeerSpec>, identities: &[Identity], dials: bool) -> Vec<Name> {
    if let Some(routes) = peer.and_then(|p| p.routes.clone()) {
        return routes;
    }
    if identities.is_empty() {
        return peer.and_then(|p| p.device.clone()).into_iter().collect();
    }
    let mut out: Vec<Name> = Vec::new();
    for id in identities {
        let prefix = identity_route(id, peer.is_some() && dials);
        if !out.contains(&prefix) {
            out.push(prefix);
        }
    }
    out
}

/// The route a link gets for one identity of its peer: the namespace of a
/// `node` this device dials, else the device name.
pub(crate) fn identity_route(id: &Identity, dialled_peer: bool) -> Name {
    if id.role == Role::Node && dialled_peer {
        id.namespace.clone()
    } else {
        id.device.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::PeerId;
    use ndn_face_quic::KeyFingerprint;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    fn spec(device: &str, relay: Option<usize>) -> PeerSpec {
        PeerSpec {
            label: device.into(),
            device: Some(n(device)),
            relay: relay.map(PeerId),
            ..PeerSpec::default()
        }
    }

    fn admitted(
        peer: Option<usize>,
        identity: Option<Identity>,
        enrollment: Option<Enrollment>,
    ) -> Admitted {
        Admitted {
            fingerprint: KeyFingerprint([0; 32]),
            identities: identity.into_iter().collect(),
            peer: peer.map(PeerId),
            enrollment,
            quota: None,
            quotas: Vec::new(),
        }
    }

    fn id(device: &str, role: Role) -> Identity {
        Identity {
            namespace: n("/home"),
            version: 1,
            device: n(device),
            role,
            certificates: Vec::new(),
            served: None,
        }
    }

    fn route(prefix: &str, cost: u32) -> Route {
        Route {
            prefix: n(prefix),
            cost,
        }
    }

    #[test]
    fn a_dialled_relay_routes_its_namespace_and_the_peers_behind_it() {
        let peers = Peers::new(vec![
            spec("/home/node/relay", None),
            spec("/home/member/laptop", Some(0)),
        ]);
        let relay = admitted(Some(0), Some(id("/home/node/relay", Role::Node)), None);
        assert_eq!(
            routes_for(&peers, &relay, true, None),
            [
                route("/home", 0),
                route("/home/member/laptop", VIA_RELAY_COST),
                route("/home/32=sync", 0)
            ]
        );
        // A node that linked in unasked is routed by its device name.
        let unasked = admitted(None, Some(id("/home/node/relay", Role::Node)), None);
        assert_eq!(
            routes_for(&peers, &unasked, false, None),
            [route("/home/node/relay", 0), route("/home/32=sync", 0)]
        );
    }

    /// A relay in use routes this device's namespaces at its rank, and its
    /// own device name beside them (a relay of a namespace this device does
    /// not hold is known by its entry's `device`), so an Interest whose
    /// forwarding hint names the relay goes over its link.
    #[test]
    fn a_relay_in_use_routes_this_devices_namespace_and_its_own_name_at_its_rank() {
        let mut community = spec("/other/node/relay", None);
        community.relay_use = Some(crate::peer::RelayUse {
            source: crate::peer::RelaySource::User,
            preference: 5,
        });
        let peers = Peers::new(vec![community, spec("/home/member/laptop", Some(0))]);
        let relay = admitted(Some(0), None, None);
        let rank = RelayRoutes {
            namespaces: vec![n("/home")],
            cost: 2,
        };
        assert_eq!(
            routes_for(&peers, &relay, true, Some(rank)),
            [
                route("/home", 2),
                route("/other/node/relay", 2),
                route("/home/member/laptop", 2 + VIA_RELAY_COST)
            ]
        );
    }

    #[test]
    fn a_node_with_a_peer_entry_this_device_does_not_dial_is_routed_by_its_device_name() {
        let peers = Peers::new(vec![spec("/home/node/relay", None)]);
        let inbound = admitted(Some(0), Some(id("/home/node/relay", Role::Node)), None);
        assert_eq!(
            routes_for(&peers, &inbound, false, None),
            [route("/home/node/relay", 0), route("/home/32=sync", 0)]
        );
    }

    /// The group of each namespace the peer was admitted in goes over the
    /// link once, whatever its name's length: a held one's, and a served
    /// one's (a namespace this device carries without holding it).
    #[test]
    fn a_link_routes_the_sync_group_of_each_namespace_it_carries() {
        let peers = Peers::new(Vec::new());
        let mut link = admitted(None, Some(id("/home/member/phone", Role::Member)), None);
        let mut bob = id("/home/bob/member/phone", Role::Member);
        bob.namespace = n("/home/bob");
        let mut served = id("/visitor/member/tab", Role::Member);
        served.namespace = n("/visitor");
        served.served = Some(KeyFingerprint([7; 32]));
        link.identities
            .extend([id("/home/admin/phone", Role::Admin), bob, served]);
        assert_eq!(
            routes_for(&peers, &link, false, None),
            [
                route("/home/member/phone", 0),
                route("/home/admin/phone", 0),
                route("/home/bob/member/phone", 0),
                route("/visitor/member/tab", 0),
                route("/home/32=sync", 0),
                route("/home/bob/32=sync", 0),
                route("/visitor/32=sync", 0),
            ]
        );
    }

    /// A served identity's link routes the key name of each issuer its
    /// hello showed, once, beside its device name (its own certificate is
    /// under that already); a held identity's link routes none: this device
    /// resolves a held chain itself.
    #[test]
    fn a_served_identity_routes_its_issuers_key_names() {
        let peers = Peers::new(Vec::new());
        let mut held = id("/home/member/phone", Role::Member);
        held.certificates = vec![
            n("/home/member/phone/KEY/p/home/v=1"),
            n("/home/CA/KEY/ca/NA/v=1"),
        ];
        let mut link = admitted(None, Some(held), None);
        let mut served = id("/visitor/member/tab", Role::Member);
        served.namespace = n("/visitor");
        served.served = Some(KeyFingerprint([7; 32]));
        served.certificates = vec![
            n("/visitor/member/tab/KEY/t/NA/v=1"),
            n("/visitor/CA/KEY/ca/NA/v=1"),
            n("/visitor/KEY/root/self/v=1"),
        ];
        let mut again = served.clone();
        again.device = n("/visitor/member/pad");
        again.certificates = vec![
            n("/visitor/member/pad/KEY/d/NA/v=1"),
            n("/visitor/CA/KEY/ca/NA/v=2"),
        ];
        link.identities.extend([served, again]);
        assert_eq!(
            routes_for(&peers, &link, false, None),
            [
                route("/home/member/phone", 0),
                route("/visitor/member/tab", 0),
                route("/visitor/member/pad", 0),
                route("/visitor/CA/KEY/ca", 0),
                route("/visitor/KEY/root", 0),
                route("/home/32=sync", 0),
                route("/visitor/32=sync", 0),
            ]
        );
    }

    #[test]
    fn enrollment_links_route_the_namespace_on_the_device_only() {
        let peers = Peers::new(Vec::new());
        assert!(
            routes_for(
                &peers,
                &admitted(None, None, Some(Enrollment::Relay(vec![n("/home")]))),
                false,
                None
            )
            .is_empty()
        );
        assert_eq!(
            routes_for(
                &peers,
                &admitted(None, None, Some(Enrollment::Device(n("/home")))),
                true,
                None
            ),
            [route("/home", 0)]
        );
    }
}
