//! QUIC links between forwarders.
//!
//! A link is a QUIC connection between two devices, identified by their NDN
//! keys:
//!
//! - **Identity.** TLS 1.3 with RFC 7250 raw public keys on both sides: the
//!   key each side presents *is* its NDN device key (Ed25519 or P-256), and
//!   the handshake signature is made with it ([`LinkKey`]). No X.509, no CA,
//!   no host names. The handshake proves only that the peer holds the key it
//!   presents ([`PeerKey`]); a dial that configured an expected fingerprint
//!   fails unless the peer presents exactly that key.
//! - **Admission.** After the handshake each side sends a [`LinkHello`] with
//!   its NDN certificate and issuer chain, and admits or refuses the link
//!   from it ([`Handshaken::admit`] with a [`LinkVerdict`],
//!   [`Handshaken::refuse`] with a [`CloseReason`]). Deciding admission
//!   (validation against held trust contexts, link policy, expected
//!   fingerprints) is the caller's — the `ndn-link` crate decides it the
//!   way every implementation must: this crate carries the messages.
//! - **Memberships.** The TLS key is one per device. A device that is a
//!   member of other namespaces with other keys adds a [`Membership`] per
//!   namespace to its hello: that key's certificate chain and its
//!   signature binding the TLS key to this connection
//!   ([`Handshaken::channel_binding`], [`binding_transcript`]), which a
//!   receiver checks with [`Membership::verify`].
//! - **Scope.** A side may admit a link that carries less than everything —
//!   an *enrollment link*, or a link bounded only by its rates
//!   ([`LinkScope`], [`Carries::Everything`]): its face drops, both ways,
//!   every packet outside the scope, Nacks the Interests among them (NoRoute;
//!   Congestion for one dropped for rate), and rate-limits what it receives
//!   by frames and bytes, per link and optionally with buckets several links
//!   share ([`SharedRate`]). The verdict tells the peer of an
//!   enrollment link.
//! - **Framing.** NDN packets ride QUIC DATAGRAM frames as NDNLPv2 frames; the
//!   face's link service fragments a packet larger than the connection's
//!   current datagram size ([`LinkFace`]), and NDNLPv2 reliability can be
//!   enabled per link. No stream, so no head-of-line blocking: NDN packets
//!   never travel on a stream.
//!   [`LinkHandle::datagrams`] counts them, so a caller can close a link
//!   that carried nothing for a while.
//! - **Side path.** Beside NDN packets a link carries *channel frames*, whose
//!   first octet is `0x00` (no NDN packet starts with it), as QUIC datagrams
//!   and on one unidirectional stream per direction, on the link's own
//!   connection ([`LinkFace::send_side`](ndn_transport::Transport::send_side)).
//!   Both hellos must carry `ChannelCaps` ([`LinkHello::channel_caps`]) and the
//!   admitting side's [`ChannelPolicy`] must carry; the stream is granted only
//!   then, after the verdict. A channel datagram waits behind
//!   about a millisecond of the connection's send rate of NDN traffic
//!   ([`QUEUE_FLOOR`] to [`QUEUE_CAP`]); the bytes each way may be held to a
//!   [`FairShare`] of a namespace's pool; none of it is judged by the NDN scope
//!   or answered with a Nack. [`LinkHandle::side_stats`] counts it.
//! - **Transport.** Keep-alive and idle timeout are set explicitly
//!   ([`LinkTransportConfig`], within NAT-safe bounds with
//!   [`LinkTransportConfig::bounded`]); connection migration keeps a link
//!   across an address change ([`LinkEndpoint::rebind`]). A host may hand
//!   the endpoint a socket it bound itself, to a network interface or a
//!   phone's Wi-Fi or cellular network ([`LinkEndpoint::from_socket`]).
//!   Inbound attempts are bounded before their handshake, and so are the
//!   inbound links admitted and still up ([`HandshakeLimits`]).
//! - **Reachability.** After the verdict a device tells a relay whether to
//!   hold Interests for it while it sleeps and how to wake it
//!   ([`LinkHandle::send_reachability`], [`Reachability`]); a relay tells a
//!   device which devices of its namespaces are linked there
//!   ([`LinkHandle::send_presence`], [`Presence`]). A device closing its
//!   link to sleep says so ([`CloseReason::Asleep`]). What to do with them
//!   is the `ndn-link` crate's.
//! - **Departure.** An inviter that let a person go tells them which members
//!   record to fetch ([`LinkHandle::send_departure`], [`Departure`]); a link
//!   scope may narrow in place ([`Narrowing`]).
//! - **Direct paths.** Each side tells the other the address it sees it at
//!   ([`LinkHandle::observed_address`]), which is how a device behind a NAT
//!   learns its address beyond it. The link socket sends and receives the
//!   probes of a hole punch ([`LinkEndpoint::send_probe`],
//!   [`LinkEndpoint::watch_probes`]), accepts the punched connection even
//!   when it does not listen ([`LinkEndpoint::allow_inbound`]), and dials it
//!   ([`LinkEndpoint::connect_direct`]); the dialer names the punch in its
//!   hello ([`LinkHello::direct_path`]). When and where to punch is the
//!   `ndn-link` crate's.
//!
//! Crypto is rustls on the **ring** provider, the stack ndn-rs already uses.

#![cfg(not(target_arch = "wasm32"))]

mod endpoint;
mod key;
mod link;
mod membership;
mod message;
mod probe;
mod scope;
mod side;
mod text;
mod verify;

pub use endpoint::{
    ALPN_LINK, HandshakeLimits, InboundWindow, Incoming, LINK_SOCKET_BUFFER, LinkEndpoint,
    LinkTransportConfig,
};
pub use key::{KeyError, KeyFingerprint, LinkKey, LinkKeyAlgorithm, LinkKeySource, PeerKey};
pub use link::{
    Admission, DATAGRAM_FLOOR, Direction, Handshaken, Link, LinkError, LinkFace, LinkHandle,
};
pub use membership::{
    BINDING_LABEL, ChannelBinding, MEMBERSHIP, MEMBERSHIP_EXPORTER_LABEL, MEMBERSHIPS_MAX,
    Membership, binding_transcript,
};
pub use message::{
    CHANNEL_CAPS_V1, CloseReason, DEPARTURES_MAX, Departure, FOLLOW_DEPTH_MAX, FOLLOW_SPACE_MAX,
    FOLLOWS_MAX, LINK_PROTOCOL_VERSION, LinkHello, LinkVerdict, PathSession, Presence,
    PresentDevice, Reachability, WAKE_TOKEN_MAX, check_followed_group, decode_udp_address,
    encode_udp_address,
};
pub use probe::{PROBE_LEN, ProbeWatch, decode_probe, encode_probe};
pub use scope::{
    CONGESTION_NACKS, Carries, FAIR_CAPACITY, FAIR_FLOOR, FAIR_INTERVAL, FairMember, FairShare,
    Flow, LinkScope, NameFilter, Narrowing, RateLimit, RatedInterests, ScopeCounts, SharedRate,
};
pub use side::{
    ChannelPolicy, DATAGRAM_SEND_BUFFER, QUEUE_CAP, QUEUE_FLOOR, STREAM_FRAME_MAX,
    STREAM_QUEUE_MAX, SideLimits, SideStats,
};
pub use text::{PEER_TEXT_MAX, bounded_text, clean_text, sanitize_peer_text};
