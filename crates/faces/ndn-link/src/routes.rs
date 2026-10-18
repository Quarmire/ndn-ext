//! The routes an admitted link gets.

use ndn_cert::roles::Role;
use ndn_packet::Name;

use crate::admission::{Admitted, Enrollment, Identity};
use crate::host::Route;
use crate::peer::{PeerSpec, Peers};
use crate::policy::VIA_RELAY_COST;

/// The routes over a link to the admitted peer: the peer's `routes`, else
/// its namespace for a relay this device dials (a `node` device whose peer
/// entry has a path — whichever side's dial the link came from), else its
/// device name; and the routes of the peers reached through it. An
/// enrollment link: none on the relay (answers return the way their
/// Interests came), the namespace on the enrolling device.
pub(crate) fn routes_for(peers: &Peers, admitted: &Admitted, dials: bool) -> Vec<Route> {
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
    let at = |cost| move |prefix| Route { prefix, cost };
    let peer = admitted.peer.map(|i| peers.get(i));
    let mut routes: Vec<Route> = default_routes(peer, admitted.identity.as_ref(), dials)
        .into_iter()
        .map(at(0))
        .collect();
    if let Some(index) = admitted.peer {
        for reached in peers.reached_through(index) {
            routes.extend(default_routes(Some(reached), None, false).into_iter().map(at(VIA_RELAY_COST)));
        }
    }
    routes
}

fn default_routes(peer: Option<&PeerSpec>, identity: Option<&Identity>, dials: bool) -> Vec<Name> {
    if let Some(routes) = peer.and_then(|p| p.routes.clone()) {
        return routes;
    }
    match identity {
        Some(id) if id.role == Role::Node && peer.is_some() && dials => vec![id.namespace.clone()],
        Some(id) => vec![id.device.clone()],
        None => peer.and_then(|p| p.device.clone()).into_iter().collect(),
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
            key: None,
            device: Some(n(device)),
            endpoints: Vec::new(),
            relay: relay.map(PeerId),
            routes: None,
            persistent: true,
            reliability: false,
        }
    }

    fn admitted(peer: Option<usize>, identity: Option<Identity>, enrollment: Option<Enrollment>) -> Admitted {
        Admitted {
            fingerprint: KeyFingerprint([0; 32]),
            identity,
            peer: peer.map(PeerId),
            enrollment,
        }
    }

    fn id(device: &str, role: Role) -> Identity {
        Identity {
            namespace: n("/home"),
            version: 1,
            device: n(device),
            role,
            certificates: Vec::new(),
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
            routes_for(&peers, &relay, true),
            [route("/home", 0), route("/home/member/laptop", VIA_RELAY_COST)]
        );
        // A node that linked in unasked is routed by its device name.
        let unasked = admitted(None, Some(id("/home/node/relay", Role::Node)), None);
        assert_eq!(routes_for(&peers, &unasked, false), [route("/home/node/relay", 0)]);
    }

    #[test]
    fn a_node_with_a_peer_entry_this_device_does_not_dial_is_routed_by_its_device_name() {
        let peers = Peers::new(vec![spec("/home/node/relay", None)]);
        let inbound = admitted(Some(0), Some(id("/home/node/relay", Role::Node)), None);
        assert_eq!(routes_for(&peers, &inbound, false), [route("/home/node/relay", 0)]);
    }

    #[test]
    fn enrollment_links_route_the_namespace_on_the_device_only() {
        let peers = Peers::new(Vec::new());
        assert!(routes_for(&peers, &admitted(None, None, Some(Enrollment::Relay(vec![n("/home")]))), false).is_empty());
        assert_eq!(
            routes_for(&peers, &admitted(None, None, Some(Enrollment::Device(n("/home")))), true),
            [route("/home", 0)]
        );
    }
}
