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
//! After the handshake each side sends its certificate and issuer chain
//! for its link key, and a membership for each other namespace it is a
//! member of with another key (that key's chain, bound to the connection by
//! that key's signature, [`ndn_face_quic::Membership`]); the peer is
//! identified in every namespace it proves, and a link is admitted from
//! signed data, by either rule:
//!
//! - a certificate (its link key's, or a membership's) validates in a
//!   namespace this device holds, its key is the key the handshake proved
//!   (or bound to it), it is not revoked, and the namespace's link policy
//!   (in its trust context) lets the device's role link — and, when a
//!   [`PeerSpec`] names a `device`, it is that device; unasked, the
//!   [`ServePolicy`] serves one of the namespaces proved;
//! - the key is the expected fingerprint of a [`PeerSpec`] (`key`), for a
//!   device of another namespace or one not enrolled yet.
//!
//! A device is named `/<namespace>/<role>/<device>` (one component for the
//! role, what the device does there, such as `member`; one for the device)
//! and its certificate `/<namespace>/<role>/<device>/KEY/<key-id>/<issuer>/<version>`.
//! A certificate of another shape identifies no device, and the refusal says
//! the shape expected, the name it had and what to do (ndn-rs
//! `docs/specs/ndn-link.md` §7.1).
//!
//! Validation is offline: the chain the peer sent, then certificates the
//! host already has ([`LinkTrust::known_certificate`]), never a fetch — the
//! link is not up yet. A membership whose binding does not verify (a
//! certificate of a key the peer does not hold, or a binding made for
//! another connection) refuses the link.
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
//! Once the device enrolls (the host adds the enrolled identity to its
//! memberships and calls [`Links::identities_changed`]), it closes the
//! enrollment link and dials again, now presenting its certificate: a full
//! link, without anyone doing anything. A revocation adopted while linked
//! takes the revoked membership from the link (its routes and presence),
//! and closes the link when no membership admitting it is left.
//!
//! # Routes, redial, one link per pair
//!
//! Each admitted link is a face (NDNLPv2 over QUIC datagrams) with routes:
//! the [`PeerSpec`]'s `routes`, else the peer's namespace for a relay (a
//! `node` device this device dials — its [`PathSource`] gives it a path —
//! whichever side's dial the link came from) or the peer's device name, plus
//! the routes of the peers reached through it (`relay`, at
//! [`policy::VIA_RELAY_COST`]), plus, for a served peer, the key names of
//! the issuers its hello showed (consumers fetch its chain from it), plus
//! the sync group `<ns>/32=sync` of each
//! namespace the peer was admitted in — held here, or served by the
//! serving policy ([`group_routes`]; `ndn-rs/docs/specs/data-layer.md`
//! §12) — which runs with the multicast strategy: by the host's
//! trust-context library for a held namespace, by the host's
//! [`FaceSink::transit`] while a served one is in transit. A revocation
//! that takes a membership from a link takes its routes, the group's with
//! them; the link's end takes them all. Persistent peers are
//! dialled again with [`Backoff`] whenever their link drops. Between two
//! devices there is one link: when both dial, the link dialled by the device
//! with the smaller key fingerprint stays ([`keeps_existing`]).
//!
//! # What a host provides
//!
//! A host (a forwarder daemon, a mobile app's embedded engine) starts
//! [`Links`] with a [`LinkSetup`]:
//!
//! - **The link key** ([`ndn_face_quic::LinkKeySource`]): the key this
//!   device links with now, one per device (a forwarder's node key). It
//!   must sign synchronously (a key that only signs asynchronously cannot
//!   do a TLS handshake).
//! - **Trust** ([`LinkTrust`]): the keyring holding the trust contexts this
//!   device adopted, this device's own certificate chain for its link key,
//!   its memberships of other namespaces ([`OwnMembership`]), and
//!   certificates it already knows (served or cached).
//! - **Faces and routes** ([`FaceSink`]): face ids, adding a link's face to
//!   the forwarder, removing it when the link ends, adding the routes this
//!   crate decides.
//! - **Paths** ([`PathSource`]): where to dial each peer. [`ConfiguredEndpoints`]
//!   dials the [`PeerSpec`]'s `host:port` endpoints.
//! - **Peers** ([`PeerSpec`]): the devices this one links with, parsed from
//!   the host's configuration.
//! - **The link socket**, when it listens (a [`ndn_face_quic::LinkEndpoint`]);
//!   dial-only sockets are bound here when needed.
//! - **Identity changes**: [`Links::identities_changed`] after the device's
//!   link key or memberships changed (it enrolled in a namespace).
//!
//! The host keeps the rest: parsing its configuration, the forwarder,
//! management, and the words its users read. What this crate reports or
//! refuses in words is a [`LinkDetail`] (a code of [`link_code`] with
//! parameters, and a neutral sentence that names no host's commands or
//! configuration); a host words the codes in its own terms
//! ([`LinkDetail::render`]; [`LinkWords`] says the ones that stand in for
//! its peer entries, renewal and expected keys).
//!
//! # Direct paths
//!
//! A peer behind a NAT is reached through a relay: routes over the relay's
//! link at [`policy::VIA_RELAY_COST`]. For each peer reached through a relay
//! whose `device` its [`PeerSpec`] names, this device punches a direct
//! path: a signed punch Interest to `<device>/32=link/32=punch/<session>`
//! through the relay carries its candidate addresses ([`CandidateSource`]s,
//! plus the reflexive addresses its links report) and, when its link key is
//! not certified in the punched device's namespace, its membership of it
//! bound to the punch; the peer, having admitted the sender as it would a
//! link, answers with its own in signed Data; both probe each other's
//! signed candidates from their link sockets; the device with the smaller
//! fingerprint dials. The connection is admitted
//! like a link and joins the link to that device as its direct path, with
//! routes at cost 0; the relay's routes stay, so traffic falls back when
//! it ends, and the device punches again with backoff. The link policy
//! (`direct_paths`) and [`PeerSpec::direct`] turn it off. [`Links::report`]
//! says, per device, which paths are up and why a direct path is not.
//!
//! Beyond peer entries, devices of a namespace that meet at a common relay
//! make direct paths **by membership**: the relay tells each member which
//! others of its namespace are linked to it (presence, per namespace the
//! member was admitted in, on the link's control stream, filtered by the
//! namespace's direct-path role matrix; names and keys, never addresses),
//! and the device with the smaller key fingerprint punches, at most
//! [`DirectOptions::max_paths`] at once.
//!
//! # Introductions
//!
//! A device that hands out introduction codes gives its links what its
//! introductions serve ([`Links::set_introductions`], an [`Introductions`]).
//! While one of its offers is open, a device it knows nothing of is admitted
//! on an **introduction link** rather than refused: Interests for the names
//! of the one exchange (the offer's record and the ask) and their answers
//! cross it, nothing else, within the enrollment links' slots and rates; with
//! no offer open a stranger is refused as any other. The joiner dials the
//! inviter by the key and addresses of its code's link hint
//! ([`Links::dial_by_key`]): every address at once, the handshake accepting
//! only the device holding the key; the address is where to try and is
//! trusted for nothing, and the device name the code claims is no route: the
//! link routes only the introduction's prefixes until the device proves a
//! certificate, and is taken down when the join fails
//! ([`Links::undial_by_key`]). A short code names no key, only one address:
//! [`Links::dial_first`] dials it with none to expect, links whoever answers
//! on the same terms and returns the key it proved. Once the joiner holds the inviter's namespace
//! its link is made again, and the inviter admits it by its certificate: as a
//! full link when its [`ServePolicy`] serves the joiner's namespace or a
//! **grant** ([`Grant`], [`Links::grant`]) does. A person it introduced is
//! another person's namespace, which the default `own` refuses; the grant
//! says *the device holding this link key may link here, as a person of these
//! namespaces, in the scope of this folder, until then* (or with no date: it
//! follows the folder's members record), and `own` plus the grant is tighter
//! and enough (an inviter no longer has to choose `open` or `listed`; `open`
//! is as it was, and a grant adds nothing to it). A person invited into
//! several folders holds one entry per folder ([`Grant::folder`]); the link
//! stands while any entry does. A grant admits that key in those namespaces
//! only, under the quotas; what its link carries and what the person may push
//! are judged at every packet against the entries live then: the names of
//! the folders, of the person's own devices, of the introduction and the
//! namespaces' public ones (certificates, trust contexts, sync groups) cross,
//! an unsealed collection of this device outside the folders is not answered
//! over it ([`Introductions::grant_carries`]), and Data the person pushes
//! passes only under its own device names or under the names of a folder it
//! writes in. It ends at its date, when it is revoked
//! ([`Links::revoke_grant`], [`Links::revoke_grants`]) or when a held record
//! leaves the person out. An entry ending closes nothing while another
//! stands; the last closes the links it alone admitted (a link whose
//! handshake straddled the end included) and names what ended in the refusal
//! of the key's next link, or, when a held record left the person out and a
//! departure mark is held ([`Links::depart`]), narrows them in place to that
//! record, which the person is told of ([`DepartureSink`]), and closes them
//! once it is carried (`ndn-rs/docs/specs/ndn-link.md` §8.8). With the
//! `introductions` feature, `LinkHints` gives a data layer device its three
//! halves (its hint, its dial, its undial), serves its
//! `ndn_data::IntroductionSurface`, installs the device's grants and
//! departure marks and registers its departure sink (`LinkHints::serve`,
//! `grant`, `revoke_grant`; `end_grant`, `end_grant_in` and `renew_grant` make
//! a host's own end or renewal durable).
//!
//! A person who joined a folder reads the folder's other writers through the
//! inviter's link, and its forwarder has no route toward their namespaces:
//! [`Links::set_joined_routes`] gives the link layer the set of folders the
//! device joined ([`JoinedRoutes`]: the inviter's key, the folder's owner, the
//! other writers' namespaces; `LinkHints::serve` follows the device's
//! `joined_folders` with it). Each namespace, and for a writer-role joiner
//! its sync group (a reader is routed the namespace only), is routed over the **full link of
//! the inviter's key**, admitted by an identity of the owner's namespace, at a
//! cost above every real path ([`policy::JOINED_ROUTE_COST`]; cost decides only
//! among routes of the same prefix, a forwarder takes the longest prefix first,
//! so the device lists only names that cannot take a name from a better route),
//! and over no other link; it goes with the entry, the record's writer and the
//! link, and it is a path, not a right: the inviter's filter decides what
//! crosses it. At most [`policy::JOINED_ROUTES_MAX`] prefixes in
//! [`policy::JOINED_FOLDERS_MAX`] folders, shared equally by the inviters, and
//! none under or over `/localhost` or `/localhop`
//! (`ndn-rs/docs/specs/ndn-link.md` §8.7).
//!
//! The inviter's side is routed too: a link admitted by a live grant entry (the
//! inviter's grant of a person, and the mirror a joiner keeps of its inviter)
//! routes, beside the person's devices and sync group, the public names of
//! each namespace the grant lists that lie outside the devices — the trust
//! context (`<ns>/32=trust-context`), the root's key names (`<ns>/KEY`) and
//! the CA's (`<ns>/CA/KEY`), the names its filter already carries — at
//! [`policy::JOINED_ROUTE_COST`], so the inviter's forwarder relays a
//! joiner's Interest for another writer's trust context toward that writer.
//! Never for a link a policy admitted, nor an enrollment, introduction or
//! departure link; they go with the link's face like its other routes.
//!
//! # Link memory
//!
//! A device that restarts keeps what it learned of its peers, and links with
//! them again with no peer entry, relay or list of the host's:
//! [`Links::remember`] takes a [`LinkMemory`] (with the feature
//! `introductions`, `DeviceMemory` keeps it in a data-layer device's local
//! notes). It records, for each peer a link was admitted for by an identity in
//! a held namespace, its key, its device and the addresses that worked, and
//! dials them again in the background. The key is what a redial trusts and an
//! address is a hint; a remembered peer is never admitted by its key alone, is
//! not dialled when no held context (a namespace this device holds, a live
//! grant) admits it, and is forgotten by [`Links::forget`]
//! (`ndn-rs/docs/specs/ndn-link.md` §17C). When an identified peer opens a link
//! to this device, its record's address is brought up to date: the IP the link
//! came from, with the port the record holds, goes first; the source port is
//! the peer's own choice and is never recorded.
//!
//! # Relays
//!
//! Any device that others can reach is a relay for the devices it serves:
//! its [`ServePolicy`] says whom (its own namespaces by default; listed
//! namespaces by root fingerprint; or any, within [`Quotas`]). A device
//! chooses which relays it uses ([`RelayOptions`]): the ones its namespaces
//! advertise in their trust contexts, the ones its person added
//! ([`PeerSpec::relay_use`]), or none; for each namespace it is a member
//! of, the `count` most preferred reachable ones are linked, and traffic
//! fails over to the next when one is lost. A relay's link routes the
//! namespaces it is used for and each namespace this device follows.
//! A relay of another namespace forwards signed packets it cannot forge, but
//! it sees the names it forwards (and any content not encrypted end to
//! end). It carries the Data of a namespace it serves but does not hold in
//! transit, unvalidated and uncached ([`FaceSink::transit`]): the devices
//! that asked for it validate it. It needs no trust context of the people
//! it carries: their devices' links route their namespace's sync group,
//! which it runs with the multicast strategy while they are linked.
//!
//! # Link modes and reachability while asleep
//!
//! Each link has a [`LinkMode`]: always up, on demand (dialled when the host
//! is active or an Interest waits for it, closed when idle), or off (until
//! the host asks). A device may ask its relay to hold its Interests while
//! it is asleep and to wake it ([`PeerSpec::hold`],
//! [`Links::set_wake_token`]); a relay offers that per its
//! [`RelayService`], waking through the host's [`WakeNotifier`].
//!
//! # Offline, online, the listening port, and the address
//!
//! [`Links::set_online`] says the device is offline: every link and direct path
//! closes, no inbound attempt is answered and none is made, and
//! [`Links::watch`] shows each peer down with [`Next::WhenOnline`]; online again,
//! the remembered and configured peers are dialled at once (staggered by
//! [`MemoryOptions::dials_at_once`]). [`Links::remember`] keeps the port the
//! host's link socket listens on with the memory ([`LinkMemory::load_listen_port`],
//! [`LinkMemory::save_listen_port`]) and binds it again after a restart when it
//! is free; a peer that cannot be reached at all is [`RememberedState::NoPath`].
//! [`Links::watch_addresses`] watches the device's own addresses (netlink on
//! Linux, a bounded poll everywhere, or an [`AddressSource`] of the host's) and
//! does what [`Links::network_changed`] does when they change. ndn-rs
//! `docs/specs/ndn-link.md` §17D.
//!
//! # The fault layer (cargo feature `fault-injection`, **for tests only**)
//!
//! Off by default and never to be enabled by a shipped binary
//! (`tools/check-shipped-features.sh` fails when one does): a wrapper on each link's
//! face applies the conformance's seeded fault profile (drop, duplicate, forge, delay,
//! reorder, block loss) to the packets arriving on it, or drops or passes them, as an
//! optional host verdict says per packet (`Links::inject_faults`). A build that has it
//! logs a warning at start and
//! says so in [`LinkReport::fault_injection`]. ndn-rs `docs/specs/ndn-link.md` §17B.

#![cfg(not(target_arch = "wasm32"))]

mod admission;
mod asleep;
mod candidates;
mod control;
mod departures;
#[cfg(feature = "introductions")]
mod device_memory;
mod direct;
#[cfg(feature = "engine")]
mod engine;
#[cfg(feature = "fault-injection")]
mod fault;
mod fault_report;
mod grants;
#[cfg(feature = "introductions")]
mod hints;
mod host;
mod introduce;
mod joined;
mod links;
mod memory;
mod netwatch;
mod online;
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
mod watch;

pub use asleep::{HoldLimits, RelayService, WAKE_INTERVAL, WakeNotifier, WakeRequest};
pub use candidates::{
    AdvertisedCandidates, Candidate, CandidateKind, CandidateSource, HostCandidates,
};
pub use departures::{Departure, DepartureOptions, DepartureSink, DepartureTaking, NotTaken};
#[cfg(feature = "introductions")]
pub use device_memory::DeviceMemory;
#[cfg(feature = "engine")]
pub use engine::EngineFaces;
#[cfg(feature = "fault-injection")]
pub use fault::{FaultFrame, FaultJudge, FaultKind, FaultPlan, FaultVerdict};
pub use fault_report::FaultReport;
pub use grants::{Grant, GrantRole};
#[cfg(feature = "introductions")]
pub use hints::LinkHints;
pub use host::{
    ConfiguredEndpoints, FaceSink, LinkTrust, OwnMembership, PathCandidate, PathSource, Route,
};
pub use introduce::Introductions;
pub use joined::JoinedRoutes;
pub use links::{LinkSetup, Links};
pub use memory::{
    LinkMemory, MemoryFuture, MemoryOptions, MemoryReport, PeerRecord, RememberedPeer,
    RememberedState,
};
/// The fault profile a [`FaultPlan`] carries, and the conformance's `--faulty` one
/// (ndn-rs `ndn-link.md` §17B); **for tests only**.
#[cfg(feature = "fault-injection")]
pub use ndn_faults::{FAULTY, Faults};
pub use ndn_mgmt_wire::{LinkDetail, LinkWords, link_code};
pub use netwatch::{AddressSource, AddressWatch, InterfaceAddresses};
pub use peer::{LinkMode, PeerId, PeerSpec, RelaySource, RelayUse};
pub use policy::Backoff;
pub use presence::{DirectOptions, PRESENCE_MAX};
pub use relays::RelayOptions;
pub use routes::group_routes;
pub use serving::{Quotas, ServePolicy};
pub use status::{
    AsleepStatus, DirectState, DirectStatus, LinkReport, LinkStatus, PathKind, PathStatus,
    RelayState, RelayStatus,
};
pub use table::keeps_existing;
pub use waiting::{DEMAND_PER_PEER, DEMAND_TOTAL, WAITING_COST};
pub use watch::{Direction, LINK_STATES_MAX, LinkState, LinkWatch, Next, PeerLink};
