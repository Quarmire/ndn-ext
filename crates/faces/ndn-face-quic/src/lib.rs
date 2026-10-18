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
//!   fingerprints) is the caller's: this crate carries the messages.
//! - **Scope.** A side may admit a link that carries less than everything —
//!   an *enrollment link* ([`LinkScope`]): its face drops, both ways, every
//!   packet outside the scope, Nacks the Interests among them, and
//!   rate-limits what it receives. The verdict tells the peer.
//! - **Framing.** NDN packets ride QUIC DATAGRAM frames as NDNLPv2 frames; the
//!   face's link service fragments a packet larger than the connection's
//!   current datagram size ([`LinkFace`]), and NDNLPv2 reliability can be
//!   enabled per link. No stream, so no head-of-line blocking.
//! - **Transport.** Keep-alive and idle timeout are set explicitly
//!   ([`LinkTransportConfig`]), sized for NAT bindings; connection migration
//!   keeps a link across an address change ([`LinkEndpoint::rebind`]).
//!   Inbound attempts are bounded before their handshake
//!   ([`HandshakeLimits`]).
//!
//! Crypto is rustls on the **ring** provider, the stack ndn-rs already uses.

#![cfg(not(target_arch = "wasm32"))]

mod endpoint;
mod key;
mod link;
mod message;
mod scope;
mod verify;

pub use endpoint::{ALPN_LINK, HandshakeLimits, Incoming, LinkEndpoint, LinkTransportConfig};
pub use key::{KeyError, KeyFingerprint, LinkKey, LinkKeyAlgorithm, LinkKeySource, PeerKey};
pub use link::{
    Admission, DATAGRAM_FLOOR, Direction, Handshaken, Link, LinkError, LinkFace, LinkHandle,
};
pub use message::{CloseReason, LINK_PROTOCOL_VERSION, LinkHello, LinkVerdict};
pub use scope::{Carries, LinkScope, RateLimit};
