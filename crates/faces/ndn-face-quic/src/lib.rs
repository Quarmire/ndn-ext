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
//!   every packet outside the scope, Nacks the Interests among them, and
//!   rate-limits what it receives, per link and optionally with a bucket
//!   several links share ([`SharedRate`]). The verdict tells the peer of an
//!   enrollment link.
//! - **Framing.** NDN packets ride QUIC DATAGRAM frames as NDNLPv2 frames; the
//!   face's link service fragments a packet larger than the connection's
//!   current datagram size ([`LinkFace`]), and NDNLPv2 reliability can be
//!   enabled per link. No stream, so no head-of-line blocking.
//!   [`LinkHandle::datagrams`] counts them, so a caller can close a link
//!   that carried nothing for a while.
//! - **Transport.** Keep-alive and idle timeout are set explicitly
//!   ([`LinkTransportConfig`], within NAT-safe bounds with
//!   [`LinkTransportConfig::bounded`]); connection migration keeps a link
//!   across an address change ([`LinkEndpoint::rebind`]). A host may hand
//!   the endpoint a socket it bound itself, to a network interface or a
//!   phone's Wi-Fi or cellular network ([`LinkEndpoint::from_socket`]).
//!   Inbound attempts are bounded before their handshake
//!   ([`HandshakeLimits`]).
//! - **Reachability.** After the verdict a device tells a relay whether to
//!   hold Interests for it while it sleeps and how to wake it
//!   ([`LinkHandle::send_reachability`], [`Reachability`]); a relay tells a
//!   device which devices of its namespaces are linked there
//!   ([`LinkHandle::send_presence`], [`Presence`]). A device closing its
//!   link to sleep says so ([`CloseReason::Asleep`]). What to do with them
//!   is the `ndn-link` crate's.
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
mod verify;

pub use endpoint::{ALPN_LINK, HandshakeLimits, InboundWindow, Incoming, LinkEndpoint, LinkTransportConfig};
pub use key::{KeyError, KeyFingerprint, LinkKey, LinkKeyAlgorithm, LinkKeySource, PeerKey};
pub use membership::{
    BINDING_LABEL, ChannelBinding, MEMBERSHIP, MEMBERSHIP_EXPORTER_LABEL, MEMBERSHIPS_MAX, Membership,
    binding_transcript,
};
pub use link::{
    Admission, DATAGRAM_FLOOR, Direction, Handshaken, Link, LinkError, LinkFace, LinkHandle,
};
pub use message::{
    CloseReason, LINK_PROTOCOL_VERSION, LinkHello, LinkVerdict, PathSession, Presence, PresentDevice,
    Reachability, WAKE_TOKEN_MAX, decode_udp_address, encode_udp_address,
};
pub use probe::{PROBE_LEN, ProbeWatch, decode_probe, encode_probe};
pub use scope::{Carries, LinkScope, RateLimit, SharedRate};
