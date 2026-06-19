//! Handshake confidentiality and producer-identity signing.
//!
//! The producer seals the freshly-minted pipe id + pipe key to the consumer's
//! public key (via [`ndn_sealed_box`], domain-separated by the pipes salt), so
//! only the consumer can recover them and JOIN — and a relay that later sees the
//! JOIN learns the id but never the pipe key, so it cannot forge a TEARDOWN.
//!
//! Bare ECDH is MITM-open; that is closed by **signing the SEEK reply** with the
//! producer's identity key ([`ed25519_sign`]) and verifying it against a pinned
//! trust anchor on the consumer — see [`PipeProducer::with_identity`] /
//! [`PipeConsumer::with_trust_anchor`].
//!
//! [`PipeProducer::with_identity`]: crate::PipeProducer::with_identity
//! [`PipeConsumer::with_trust_anchor`]: crate::PipeConsumer::with_trust_anchor

use ndn_sealed_box::Recipient;

/// HKDF domain separation for the pipe handshake (distinct from other contexts
/// that share the sealed-box primitive, e.g. ndn-compute's reflexive params).
const PIPES_SALT: &[u8] = b"ndn-pipes/handshake/v1";

/// Length of a minted pipe id, and of the pipe key (the teardown secret).
pub const PIPE_ID_LEN: usize = 16;
pub const PIPE_KEY_LEN: usize = 16;

/// The consumer's ephemeral X25519 session for one pipe handshake. The public
/// key rides in the SEEK app-params; [`Self::open`] consumes the private half.
pub struct ConsumerSession {
    /// The 32-byte X25519 public key to advertise in the SEEK app-params.
    pub public: [u8; 32],
    recipient: Recipient,
}

impl ConsumerSession {
    /// Generate a fresh per-handshake keypair.
    pub fn generate() -> Option<Self> {
        let recipient = Recipient::generate()?;
        Some(Self {
            public: recipient.public,
            recipient,
        })
    }

    /// Open the sealed handshake bundle produced by [`seal`] for this session.
    pub fn open(self, blob: &[u8]) -> Option<Vec<u8>> {
        self.recipient.open(PIPES_SALT, blob)
    }
}

/// Seal `secret` to the consumer whose X25519 public key is `consumer_public`.
pub fn seal(consumer_public: &[u8], secret: &[u8]) -> Option<Vec<u8>> {
    ndn_sealed_box::seal(PIPES_SALT, consumer_public, secret)
}

/// `n` cryptographically-random bytes (a minted pipe id or pipe key).
pub fn random_bytes(n: usize) -> Option<Vec<u8>> {
    ndn_sealed_box::random_bytes(n)
}

/// Ed25519 signature (64 bytes) over `region`, for signing a SEEK reply Data
/// with the producer's identity key — binds the sealed handshake to an
/// authenticated producer, closing the MITM gap of bare ECDH.
pub fn ed25519_sign(signing_key: &[u8; 32], region: &[u8]) -> [u8; 64] {
    use ed25519_dalek::{Signer, SigningKey};
    SigningKey::from_bytes(signing_key).sign(region).to_bytes()
}

/// The Ed25519 public key (the consumer's trust anchor) for a signing key.
pub fn ed25519_public(signing_key: &[u8; 32]) -> [u8; 32] {
    use ed25519_dalek::SigningKey;
    SigningKey::from_bytes(signing_key).verifying_key().to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_round_trips_and_blob_is_opaque() {
        let session = ConsumerSession::generate().unwrap();
        let pub_bytes = session.public;
        let secret = b"pipe-id-16-bytes\x00pipe-key";
        let blob = seal(&pub_bytes, secret).unwrap();
        assert!(!blob.windows(4).any(|w| w == b"pipe"), "blob is ciphertext");
        assert_eq!(session.open(&blob).unwrap(), secret);
    }

    #[test]
    fn a_different_session_cannot_open() {
        let s1 = ConsumerSession::generate().unwrap();
        let p1 = s1.public;
        let s2 = ConsumerSession::generate().unwrap();
        let blob = seal(&p1, b"only for s1").unwrap();
        assert!(s2.open(&blob).is_none());
    }
}
