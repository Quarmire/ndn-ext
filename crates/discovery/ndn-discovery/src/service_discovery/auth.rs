//! Authentication seam for service-discovery Data (records, bodies, peer
//! lists). Mirrors [`encryption`](super::encryption): pluggable
//! [`RecordSigner`] / [`RecordVerifier`] injected via
//! [`ServiceDiscoveryConfig`](crate::config::ServiceDiscoveryConfig).
//!
//! Security model (see the audit / `config.rs` defaults):
//! - The default signer is [`DigestSigner`] — a *real* DigestSha256
//!   (replacing the old all-zero stub), giving **integrity** with no key.
//! - The default verifier is **`None`**, which is *fail-closed*: an
//!   unverified record is still browseable but **never auto-installs a
//!   FIB route**. Routes install only once a verifier is configured.
//! - [`DigestVerifier`] adds integrity checking; [`KeyedVerifier`] adds
//!   real Ed25519 **authenticity** against a set of trusted keys. Full
//!   trust-schema / chain validation is the embedder's job (supply a
//!   custom `RecordVerifier` wrapping `ndn_security::Validator`).
//!
//! The discovery `on_inbound` path is synchronous; the ndn-security
//! crypto futures are pure-CPU (no I/O), so [`KeyedVerifier`] drives them
//! with a single poll rather than a runtime block.

use std::collections::HashMap;
use std::future::Future;
use std::task::{Context, Poll, Waker};

use bytes::Bytes;
use ndn_packet::{Data, Name, SignatureType};
use ndn_security::{Ed25519Verifier, Signer, VerifyOutcome, Verifier};

/// Outcome of verifying an inbound SD Data.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)] // transient verdict; not stored in bulk
pub enum VerifyVerdict {
    /// Signature checks out; `identity` is the trusted signer name
    /// (KeyLocator for asymmetric, the Data name for DigestSha256).
    Verified { identity: Name },
    /// Well-formed but not trusted (bad signature / unknown key).
    Untrusted,
    /// Could not be parsed / no signature.
    Malformed,
}

#[derive(Debug)]
pub enum SignError {
    Internal(String),
}

impl std::fmt::Display for SignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Internal(s) => write!(f, "sign error: {s}"),
        }
    }
}

/// Signs the SD Data signed-region. [`signing_info`](Self::signing_info)
/// supplies the `SignatureType` code + optional KeyLocator name used when
/// building the Data; [`sign`](Self::sign) produces the SignatureValue.
pub trait RecordSigner: Send + Sync {
    fn signing_info(&self) -> (u64, Option<Name>);
    fn sign(&self, signed_region: &[u8]) -> Result<Bytes, SignError>;
}

/// Verifies an inbound SD Data before it is stored / acted on.
pub trait RecordVerifier: Send + Sync {
    fn verify(&self, data: &Data) -> VerifyVerdict;
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let d = ring::digest::digest(&ring::digest::SHA256, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

// ---- Signers -------------------------------------------------------------

/// Default signer: real `DigestSha256` (integrity, no key). Replaces the
/// legacy all-zero stub signature.
#[derive(Debug, Default, Clone, Copy)]
pub struct DigestSigner;

impl RecordSigner for DigestSigner {
    fn signing_info(&self) -> (u64, Option<Name>) {
        (SignatureType::DigestSha256.code(), None)
    }
    fn sign(&self, signed_region: &[u8]) -> Result<Bytes, SignError> {
        Ok(Bytes::copy_from_slice(&sha256(signed_region)))
    }
}

/// Adapts an `ndn_security::Signer` (e.g. an `Ed25519Signer` from a
/// KeyChain) into a [`RecordSigner`] for authenticated announcements.
pub struct SignerAdapter(pub std::sync::Arc<dyn Signer>);

impl RecordSigner for SignerAdapter {
    fn signing_info(&self) -> (u64, Option<Name>) {
        (self.0.sig_type().code(), Some(self.0.key_name().clone()))
    }
    fn sign(&self, signed_region: &[u8]) -> Result<Bytes, SignError> {
        self.0
            .sign_sync(signed_region)
            .map_err(|e| SignError::Internal(e.to_string()))
    }
}

// ---- Verifiers -----------------------------------------------------------

/// Integrity-only verifier: accepts a Data iff its `DigestSha256`
/// signature matches a recomputed digest. No authenticity (anyone can
/// produce a valid digest) — use to gate against corruption / for
/// browse-only integrity, not against forgery.
#[derive(Debug, Default, Clone, Copy)]
pub struct DigestVerifier;

impl RecordVerifier for DigestVerifier {
    fn verify(&self, data: &Data) -> VerifyVerdict {
        let Some(info) = data.sig_info() else {
            return VerifyVerdict::Malformed;
        };
        if info.sig_type != SignatureType::DigestSha256 {
            return VerifyVerdict::Untrusted;
        }
        if sha256(data.signed_region()).as_slice() == data.sig_value() {
            VerifyVerdict::Verified {
                identity: (*data.name).clone(),
            }
        } else {
            VerifyVerdict::Untrusted
        }
    }
}

/// Authenticity verifier: accepts a Data iff it carries an Ed25519
/// signature by a KeyLocator name in the trusted set, valid over the
/// signed region. Keys are raw 32-byte Ed25519 public keys.
#[derive(Default)]
pub struct KeyedVerifier {
    keys: HashMap<Name, Vec<u8>>,
}

impl KeyedVerifier {
    pub fn new() -> Self {
        Self::default()
    }

    /// Trust `key_name` with the given raw 32-byte Ed25519 public key.
    pub fn trust(mut self, key_name: Name, public_key: impl Into<Vec<u8>>) -> Self {
        self.keys.insert(key_name, public_key.into());
        self
    }
}

impl RecordVerifier for KeyedVerifier {
    fn verify(&self, data: &Data) -> VerifyVerdict {
        let Some(info) = data.sig_info() else {
            return VerifyVerdict::Malformed;
        };
        if info.sig_type != SignatureType::SignatureEd25519 {
            return VerifyVerdict::Untrusted;
        }
        let Some(kl) = info.key_locator_name() else {
            return VerifyVerdict::Untrusted;
        };
        let Some(pk) = self.keys.get(&kl) else {
            return VerifyVerdict::Untrusted;
        };
        match poll_once(Ed25519Verifier.verify(data.signed_region(), data.sig_value(), pk)) {
            Some(Ok(VerifyOutcome::Valid)) => VerifyVerdict::Verified {
                identity: (*kl).clone(),
            },
            _ => VerifyVerdict::Untrusted,
        }
    }
}

/// Drive a pure-CPU (non-pending) future to completion with a single
/// poll. Returns `None` only if the future unexpectedly pends — the
/// ndn-security verify futures never do.
fn poll_once<F: Future>(fut: F) -> Option<F::Output> {
    let mut cx = Context::from_waker(Waker::noop());
    let mut fut = std::pin::pin!(fut);
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_packet::encode::DataBuilder;

    fn sign_data(name: &str, content: &[u8], signer: &dyn RecordSigner) -> Bytes {
        let (sig_code, kl) = signer.signing_info();
        DataBuilder::new(name.parse::<Name>().unwrap(), content).sign_sync(
            SignatureType::from_code(sig_code),
            kl.as_ref(),
            |region| signer.sign(region).unwrap_or_default(),
        )
    }

    #[test]
    fn digest_sign_verify_roundtrip() {
        let wire = sign_data("/sd/x", b"hello", &DigestSigner);
        let data = Data::decode(wire).unwrap();
        assert!(matches!(
            DigestVerifier.verify(&data),
            VerifyVerdict::Verified { .. }
        ));
    }

    #[test]
    fn digest_verify_rejects_tamper() {
        let wire = sign_data("/sd/x", b"hello", &DigestSigner);
        let mut bad = wire.to_vec();
        // Flip a content byte (inside the signed region).
        let n = bad.len();
        bad[n / 2] ^= 0xFF;
        if let Ok(data) = Data::decode(Bytes::from(bad)) {
            assert_ne!(
                DigestVerifier.verify(&data),
                VerifyVerdict::Verified {
                    identity: "/sd/x".parse().unwrap()
                }
            );
        }
    }

    #[test]
    fn digest_verify_rejects_zero_stub() {
        // The legacy stub: SignatureType=0, SignatureValue=32 zero bytes.
        let mut w = ndn_tlv::TlvWriter::new();
        w.write_nested(ndn_packet::tlv_type::DATA, |w: &mut ndn_tlv::TlvWriter| {
            crate::wire::write_name_tlv(w, &"/sd/x".parse::<Name>().unwrap());
            w.write_tlv(ndn_packet::tlv_type::CONTENT, b"hi");
            w.write_nested(ndn_packet::tlv_type::SIGNATURE_INFO, |w: &mut ndn_tlv::TlvWriter| {
                w.write_tlv(ndn_packet::tlv_type::SIGNATURE_TYPE, &[0u8]);
            });
            w.write_tlv(ndn_packet::tlv_type::SIGNATURE_VALUE, &[0u8; 32]);
        });
        if let Ok(data) = Data::decode(w.finish()) {
            assert_eq!(DigestVerifier.verify(&data), VerifyVerdict::Untrusted);
        }
    }
}
