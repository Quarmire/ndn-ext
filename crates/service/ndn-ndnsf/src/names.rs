//! NDNSF V2 phase-name builders.
//!
//! The four-phase exchange names, faithful to NDNSF's V2 wire layout (a single
//! unified `serviceName` endpoint path, never ServiceName + FunctionName):
//!
//! * Request:   `/<requester>/NDNSF/REQUEST/<serviceName...>/<requestId>`
//! * ACK:       `/<provider>/NDNSF/ACK/<requester-uri>/<serviceName...>/<requestId>`
//! * Selection: `/<requester>/NDNSF/SELECTION/<provider-uri>/<serviceName...>/<requestId>`
//! * Response:  `/<provider>/NDNSF/RESPONSE/<requester-uri>/<serviceName...>/<requestId>`
//!
//! The peer (`<requester-uri>`/`<provider-uri>`) is encoded as a single generic
//! component carrying the peer name's URI, so it never collides with the
//! variable-length `serviceName` path.

use ndn_packet::Name;

/// NDNSF protocol marker component.
pub const NDNSF: &str = "NDNSF";
/// Phase component: a service request.
pub const REQUEST: &str = "REQUEST";
/// Phase component: a provider's acknowledgement.
pub const ACK: &str = "ACK";
/// Phase component: the user's provider selection.
pub const SELECTION: &str = "SELECTION";
/// Phase component: the selected provider's response.
pub const RESPONSE: &str = "RESPONSE";

fn append_name(mut base: Name, suffix: &Name) -> Name {
    for comp in suffix.components() {
        base = base.append_component(comp.clone());
    }
    base
}

/// Append a peer name as one generic component carrying its URI.
fn append_peer_uri(base: Name, peer: &Name) -> Name {
    base.append(peer.to_string().as_bytes())
}

/// `/<requester>/NDNSF/REQUEST/<service...>/<request_id...>`
pub fn request_name(requester: &Name, service: &Name, request_id: &Name) -> Name {
    let base = requester.clone().append(NDNSF).append(REQUEST);
    append_name(append_name(base, service), request_id)
}

/// `/<provider>/NDNSF/ACK/<requester-uri>/<service...>/<request_id...>`
pub fn ack_name(provider: &Name, requester: &Name, service: &Name, request_id: &Name) -> Name {
    let base = append_peer_uri(provider.clone().append(NDNSF).append(ACK), requester);
    append_name(append_name(base, service), request_id)
}

/// `/<requester>/NDNSF/SELECTION/<provider-uri>/<service...>/<request_id...>`
pub fn selection_name(requester: &Name, provider: &Name, service: &Name, request_id: &Name) -> Name {
    let base = append_peer_uri(requester.clone().append(NDNSF).append(SELECTION), provider);
    append_name(append_name(base, service), request_id)
}

/// `/<provider>/NDNSF/RESPONSE/<requester-uri>/<service...>/<request_id...>`
pub fn response_name(provider: &Name, requester: &Name, service: &Name, request_id: &Name) -> Name {
    let base = append_peer_uri(provider.clone().append(NDNSF).append(RESPONSE), requester);
    append_name(append_name(base, service), request_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    #[test]
    fn request_name_layout() {
        let name = request_name(&n("/muas/alice"), &n("/svc/mavlink"), &n("/r1"));
        assert_eq!(name, n("/muas/alice/NDNSF/REQUEST/svc/mavlink/r1"));
    }

    #[test]
    fn ack_name_carries_requester_as_single_component() {
        let name = ack_name(&n("/muas/bob"), &n("/muas/alice"), &n("/svc/mavlink"), &n("/r1"));
        assert!(name.has_prefix(&n("/muas/bob/NDNSF/ACK")));
        // muas, bob, NDNSF, ACK, <requester-uri>, svc, mavlink, r1 = the requester
        // collapses to a single component, so the total is 8 (not 9).
        assert_eq!(name.components().len(), 8);
    }

    #[test]
    fn selection_and_response_roundtrip_prefixes() {
        let sel = selection_name(&n("/muas/alice"), &n("/muas/bob"), &n("/svc/x"), &n("/r9"));
        assert!(sel.has_prefix(&n("/muas/alice/NDNSF/SELECTION")));
        let resp = response_name(&n("/muas/bob"), &n("/muas/alice"), &n("/svc/x"), &n("/r9"));
        assert!(resp.has_prefix(&n("/muas/bob/NDNSF/RESPONSE")));
    }
}
