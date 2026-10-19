//! The routes an admitted link gets.

use ndn_cert::roles::Role;
use ndn_packet::Name;

use crate::admission::{Admitted, Enrollment, Identity};
use crate::host::Route;
use crate::peer::{PeerSpec, Peers};
use crate::policy::VIA_RELAY_COST;

/// The routes a relay this device uses gets: the namespaces of this device
/// it is used for, at the relay's rank.
pub(crate) struct RelayRoutes {
    pub(crate) namespaces: Vec<Name>,
    pub(crate) cost: u32,
}

/// The routes over a link to the admitted peer: the peer's `routes`, else
/// this device's namespaces for a relay it uses (`relay`: at the relay's
/// rank), else, for each identity the peer was admitted by, its namespace
/// for a relay this device dials (a `node` device whose peer entry has a
/// path — whichever side's dial the link came from) or its device name;
/// and the routes of the peers reached through it. An enrollment link:
/// none on the relay (answers return the way their Interests came), the
/// namespace on the enrolling device.
pub(crate) fn routes_for(peers: &Peers, admitted: &Admitted, dials: bool, relay: Option<RelayRoutes>) -> Vec<Route> {
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
        (Some(r), None) if !r.namespaces.is_empty() => r.namespaces.clone(),
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
    routes
}

/// The prefixes a link to `peer` will route, known before it is up (for
/// the waiting routes of an on-demand link): its `routes`, else, for a
/// relay it uses, the namespaces of this device it uses it for
/// (`relay_namespaces`), else its device name.
pub(crate) fn predicted_routes(peer: &PeerSpec, relay_namespaces: &[Name]) -> Vec<Name> {
    if let Some(routes) = &peer.routes {
        return routes.clone();
    }
    if peer.relay_use.is_some() && !relay_namespaces.is_empty() {
        return relay_namespaces.to_vec();
    }
    peer.device.clone().into_iter().collect()
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

    fn admitted(peer: Option<usize>, identity: Option<Identity>, enrollment: Option<Enrollment>) -> Admitted {
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
        let peers = Peers::new(vec![spec("/home/node/relay", None), spec("/home/member/laptop", Some(0))]);
        let relay = admitted(Some(0), Some(id("/home/node/relay", Role::Node)), None);
        assert_eq!(
            routes_for(&peers, &relay, true, None),
            [route("/home", 0), route("/home/member/laptop", VIA_RELAY_COST)]
        );
        // A node that linked in unasked is routed by its device name.
        let unasked = admitted(None, Some(id("/home/node/relay", Role::Node)), None);
        assert_eq!(routes_for(&peers, &unasked, false, None), [route("/home/node/relay", 0)]);
    }

    #[test]
    fn a_relay_in_use_routes_this_devices_namespace_at_its_rank() {
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
            [route("/home", 2), route("/home/member/laptop", 2 + VIA_RELAY_COST)]
        );
    }

    #[test]
    fn a_node_with_a_peer_entry_this_device_does_not_dial_is_routed_by_its_device_name() {
        let peers = Peers::new(vec![spec("/home/node/relay", None)]);
        let inbound = admitted(Some(0), Some(id("/home/node/relay", Role::Node)), None);
        assert_eq!(routes_for(&peers, &inbound, false, None), [route("/home/node/relay", 0)]);
    }

    #[test]
    fn enrollment_links_route_the_namespace_on_the_device_only() {
        let peers = Peers::new(Vec::new());
        assert!(
            routes_for(&peers, &admitted(None, None, Some(Enrollment::Relay(vec![n("/home")]))), false, None)
                .is_empty()
        );
        assert_eq!(
            routes_for(&peers, &admitted(None, None, Some(Enrollment::Device(n("/home")))), true, None),
            [route("/home", 0)]
        );
    }
}
