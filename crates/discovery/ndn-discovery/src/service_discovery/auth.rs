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
use ndn_packet::encode::DataBuilder;
use ndn_packet::{Data, Name, SignatureType};
use ndn_security::{ActiveSigner, Ed25519Verifier, Signer, Verifier, VerifyOutcome};

/// Outcome of verifying an inbound SD Data.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)] // transient verdict; not stored in bulk
pub enum VerifyVerdict {
    /// Signature checks out; `identity` is the trusted signer name (KeyLocator for
    /// asymmetric, the Data name for DigestSha256). `authentic` is `true` only for
    /// **keyed** (asymmetric) verification — a `DigestSha256` digest proves
    /// integrity, not authorship (anyone can compute one), so it is `false`. Only an
    /// authentic verdict may drive FIB auto-population (red-team SEC-11).
    Verified { identity: Name, authentic: bool },
    /// Well-formed but not trusted (bad signature / unknown key).
    Untrusted,
    /// Could not be parsed / no signature.
    Malformed,
}

/// Signs an SD Data. The SignatureType, KeyLocator and SignatureValue of one
/// record all come from one key, even when the signer's key changes while
/// records are being signed ([`ActiveSigner`]).
pub trait RecordSigner: Send + Sync {
    /// Finish `builder` into a signed Data wire.
    fn sign_data(&self, builder: DataBuilder) -> Bytes;
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
    fn sign_data(&self, builder: DataBuilder) -> Bytes {
        builder.sign_digest_sha256()
    }
}

/// Adapts an `ndn_security::Signer` (e.g. an `Ed25519Signer` from a
/// KeyChain) into a [`RecordSigner`] for authenticated announcements. A
/// signing failure yields an empty SignatureValue, which no verifier accepts.
pub struct SignerAdapter(pub std::sync::Arc<dyn Signer>);

impl RecordSigner for SignerAdapter {
    fn sign_data(&self, builder: DataBuilder) -> Bytes {
        let signer = &self.0;
        builder.sign_sync(signer.sig_type(), Some(signer.key_name()), |region| {
            signer.sign_sync(region).unwrap_or_default()
        })
    }
}

/// Signs each record with the key the node signs with at that moment: one
/// [`ActiveSigner::current`] snapshot per record.
impl RecordSigner for ActiveSigner {
    fn sign_data(&self, builder: DataBuilder) -> Bytes {
        SignerAdapter(self.current()).sign_data(builder)
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
            // Integrity only — a digest proves no authorship, so it is NOT authentic
            // and must never drive FIB (SEC-11).
            VerifyVerdict::Verified {
                identity: (*data.name).clone(),
                authentic: false,
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
                authentic: true,
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

    fn sign_data(name: &str, content: &[u8], signer: &dyn RecordSigner) -> Bytes {
        signer.sign_data(DataBuilder::new(name.parse::<Name>().unwrap(), content))
    }

    /// While another thread keeps switching the node's key, every record
    /// signed through the [`ActiveSigner`] verifies under the key its
    /// KeyLocator names.
    #[test]
    fn every_record_names_the_key_that_signed_it() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let keys: Vec<Arc<dyn Signer>> = (1u8..=4)
            .map(|i| {
                let name = format!("/home/bob/member/d{i}/KEY/k").parse().unwrap();
                Arc::new(ndn_security::Ed25519Signer::from_seed(&[i; 32], name)) as Arc<dyn Signer>
            })
            .collect();
        let verifier = keys.iter().fold(KeyedVerifier::new(), |v, k| {
            v.trust(k.key_name().clone(), k.public_key().unwrap().to_vec())
        });
        let active = Arc::new(ActiveSigner::new(Arc::clone(&keys[0])));
        let stop = Arc::new(AtomicBool::new(false));
        let switches = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let switcher = {
            let (active, stop, keys) = (Arc::clone(&active), Arc::clone(&stop), keys.clone());
            let switches = Arc::clone(&switches);
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let n = switches.fetch_add(1, Ordering::Relaxed) + 1;
                    active.replace(Arc::clone(&keys[n % keys.len()]));
                }
            })
        };
        while switches.load(Ordering::Relaxed) == 0 {
            std::thread::yield_now();
        }
        let before = switches.load(Ordering::Relaxed);
        for n in 0..500 {
            let wire = sign_data(&format!("/sd/{n}"), b"x", active.as_ref());
            let verdict = verifier.verify(&Data::decode(wire).unwrap());
            assert!(
                matches!(
                    verdict,
                    VerifyVerdict::Verified {
                        authentic: true,
                        ..
                    }
                ),
                "record {n}: {verdict:?}"
            );
        }
        let during = switches.load(Ordering::Relaxed) - before;
        stop.store(true, Ordering::Relaxed);
        switcher.join().unwrap();
        assert!(during > 0, "the key changed while records were signed");
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
                    identity: "/sd/x".parse().unwrap(),
                    authentic: false,
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
            w.write_nested(
                ndn_packet::tlv_type::SIGNATURE_INFO,
                |w: &mut ndn_tlv::TlvWriter| {
                    w.write_tlv(ndn_packet::tlv_type::SIGNATURE_TYPE, &[0u8]);
                },
            );
            w.write_tlv(ndn_packet::tlv_type::SIGNATURE_VALUE, &[0u8; 32]);
        });
        if let Ok(data) = Data::decode(w.finish()) {
            assert_eq!(DigestVerifier.verify(&data), VerifyVerdict::Untrusted);
        }
    }
}
