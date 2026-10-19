//! Link admission for QUIC links between devices of personal namespaces.
//!
//! [`ndn_face_quic`] carries a link: the TLS handshake with the devices' NDN
//! keys, the hello and verdict messages, the scoped face. This crate decides
//! everything a forwarder or an app has to decide the same way for links to
//! work between implementations: which links are admitted, what an
//! admitted link carries, which routes it gets, when a link is made again,
//! how often a failed dial is retried, and which link stays when two
//! devices dial each other.
//!
//! # Admission
//!
//! A link is identified by the two devices' keys, never by an address.
//! After the handshake each side sends its certificate and issuer chain; a
//! link is admitted from signed data, by either rule:
//!
//! - the certificate validates in a namespace this device holds, its key is
//!   the key the handshake proved, it is not revoked, and the namespace's
//!   link policy (in its trust context) lets the device's role link — and,
//!   when a [`PeerSpec`] names a `device`, it is that device;
//! - the key is the expected fingerprint of a [`PeerSpec`] (`key`), for a
//!   device of another namespace or one not enrolled yet.
//!
//! Validation is offline: the chain the peer sent, then certificates the
//! host already has ([`LinkTrust::known_certificate`]), never a fetch — the
//! link is not up yet.
//!
//! Otherwise the link is closed with a reason the other side logs — unless
//! it can be an **enrollment link**, which carries only a device's
//! enrollment: Interests for the namespace's CA endpoints, its trust context
//! (`<ns>/32=trust-context`) and its certificates, and their answers;
//! nothing else in either direction ([`ndn_face_quic::LinkScope`]). Two
//! sides make one:
//!
//! - a relay (this device holds a certificate of a role the namespace's
//!   link policy lets relay) admits a device it does not know on an
//!   enrollment link when the namespace's link policy allows them and its
//!   trust context names a CA endpoint; rate-limited, at most
//!   [`policy::ENROLLMENT_LINKS_MAX`] at once
//!   ([`policy::ENROLLMENT_LINKS_PER_SOURCE`] from one address), closed
//!   after [`policy::ENROLLMENT_IDLE`] carrying nothing. Its verdict tells
//!   the device. A key the relay knows a revoked certificate of
//!   ([`LinkTrust::known_certificate_of_key`]) is refused as revoked, with
//!   or without a certificate in its hello;
//! - a device holding no certificate in the namespace of the relay its
//!   [`PeerSpec`] names, which it therefore cannot confirm yet, links to it
//!   for its enrollment only.
//!
//! Once the device enrolls (the host switches to the enrolled key and calls
//! [`Links::key_switched`]), it closes the enrollment link and dials again,
//! now presenting its certificate: a full link, without anyone doing
//! anything. A link whose certificate a newly adopted version of the trust
//! context revokes is closed at once.
//!
//! # Routes, redial, one link per pair
//!
//! Each admitted link is a face (NDNLPv2 over QUIC datagrams) with routes:
//! the [`PeerSpec`]'s `routes`, else the peer's namespace for a relay (a
//! `node` device this device dials — its [`PathSource`] gives it a path —
//! whichever side's dial the link came from) or the peer's device name, plus
//! the routes of the peers reached through it (`relay`, at
//! [`policy::VIA_RELAY_COST`]). Persistent peers are dialled again with
//! [`Backoff`] whenever their link drops. Between two devices there is one
//! link: when both dial, the link dialled by the device with the smaller key
//! fingerprint stays ([`keeps_existing`]).
//!
//! # What a host provides
//!
//! A host (a forwarder daemon, a mobile app's embedded engine) starts
//! [`Links`] with a [`LinkSetup`]:
//!
//! - **The link key** ([`ndn_face_quic::LinkKeySource`]): the key this
//!   device links with now. It must sign synchronously (a key that only
//!   signs asynchronously cannot do a TLS handshake).
//! - **Trust** ([`LinkTrust`]): the keyring holding the trust contexts this
//!   device adopted, this device's own certificate chain for its current key,
//!   and certificates it already knows (served or cached).
//! - **Faces and routes** ([`FaceSink`]): face ids, adding a link's face to
//!   the forwarder, removing it when the link ends, adding the routes this
//!   crate decides.
//! - **Paths** ([`PathSource`]): where to dial each peer. [`ConfiguredEndpoints`]
//!   dials the [`PeerSpec`]'s `host:port` endpoints.
//! - **Peers** ([`PeerSpec`]): the devices this one links with, parsed from
//!   the host's configuration.
//! - **The link socket**, when it listens (a [`ndn_face_quic::LinkEndpoint`]);
//!   dial-only sockets are bound here when needed.
//! - **Hints** ([`LinkHints`]): how a person at this device enrolls it or
//!   renews a certificate, quoted in refusals and logs.
//! - **Key switches**: [`Links::key_switched`] after the device switched to
//!   another key (it enrolled).
//!
//! The host keeps the rest: parsing its configuration, the forwarder, and
//! management.
//!
//! # Direct paths
//!
//! A peer behind a NAT is reached through a relay: routes over the relay's
//! link at [`policy::VIA_RELAY_COST`]. For each peer reached through a relay
//! whose `device` its [`PeerSpec`] names, this device punches a direct
//! path: a signed punch Interest to `<device>/32=link/32=punch/<session>`
//! through the relay carries its candidate addresses ([`CandidateSource`]s,
//! plus the reflexive addresses its links report); the peer, having
//! admitted the sender as it would a link, answers with its own in signed
//! Data; both probe each other's signed candidates from their link sockets;
//! the device with the smaller fingerprint dials. The connection is admitted
//! like a link and joins the link to that device as its direct path, with
//! routes at cost 0; the relay's routes stay, so traffic falls back when
//! it ends, and the device punches again with backoff. The link policy
//! (`direct_paths`) and [`PeerSpec::direct`] turn it off. [`Links::report`]
//! says, per device, which paths are up and why a direct path is not.
//!
//! Beyond peer entries, devices of a namespace that meet at a common relay
//! make direct paths **by membership**: the relay tells each member which
//! others of its namespace are linked to it (presence, on the link's
//! control stream, filtered by the namespace's direct-path role matrix;
//! names and keys, never addresses), and the device with the smaller key
//! fingerprint punches, at most [`DirectOptions::max_paths`] at once.
//!
//! # Relays
//!
//! Any device that others can reach is a relay for the devices it serves:
//! its [`ServePolicy`] says whom (its own namespaces by default; listed
//! namespaces by root fingerprint; or any, within [`Quotas`]). A device
//! chooses which relays it uses ([`RelayOptions`]): the ones its namespace
//! advertises in its trust context, the ones its person added
//! ([`PeerSpec::relay_use`]), or none; the `count` most preferred reachable
//! ones are linked, and traffic fails over to the next when one is lost.
//! A relay of another namespace forwards signed packets it cannot forge, but
//! it sees the names it forwards (and any content not encrypted end to
//! end). It carries the Data of a namespace it serves but does not hold in
//! transit, unvalidated and uncached ([`FaceSink::transit`]): the devices
//! that asked for it validate it.
//!
//! # Link modes and reachability while asleep
//!
//! Each link has a [`LinkMode`]: always up, on demand (dialled when the host
//! is active or an Interest waits for it, closed when idle), or off (until
//! the host asks). A device may ask its relay to hold its Interests while
//! it is asleep and to wake it ([`PeerSpec::hold`],
//! [`Links::set_wake_token`]); a relay offers that per its
//! [`RelayService`], waking through the host's [`WakeNotifier`].

#![cfg(not(target_arch = "wasm32"))]

mod admission;
mod asleep;
mod candidates;
mod control;
mod direct;
#[cfg(feature = "engine")]
mod engine;
mod host;
mod links;
mod peer;
pub mod policy;
mod presence;
mod punch;
mod relays;
mod routes;
mod serving;
mod signal;
mod slots;
mod status;
mod table;
mod waiting;

pub use asleep::{HoldLimits, RelayService, WAKE_INTERVAL, WakeNotifier, WakeRequest};
pub use candidates::{AdvertisedCandidates, Candidate, CandidateKind, CandidateSource, HostCandidates};
#[cfg(feature = "engine")]
pub use engine::EngineFaces;
pub use host::{ConfiguredEndpoints, FaceSink, LinkHints, LinkTrust, PathCandidate, PathSource, Route};
pub use links::{LinkSetup, Links};
pub use peer::{LinkMode, PeerId, PeerSpec, RelaySource, RelayUse};
pub use policy::Backoff;
pub use presence::{DirectOptions, PRESENCE_MAX};
pub use relays::RelayOptions;
pub use serving::{Quotas, ServePolicy};
pub use status::{
    AsleepStatus, DirectState, DirectStatus, LinkReport, LinkStatus, PathKind, PathStatus, RelayState, RelayStatus,
};
pub use table::keeps_existing;
pub use waiting::{DEMAND_PER_PEER, DEMAND_TOTAL, WAITING_COST};
