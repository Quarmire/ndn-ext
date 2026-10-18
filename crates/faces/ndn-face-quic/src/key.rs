//! The keys a link is made with: this device's NDN key, presented in TLS as
//! an RFC 7250 raw public key and used for the handshake signature, and the
//! peer's key as the handshake proved it.

use std::fmt;
use std::sync::Arc;

use bytes::Bytes;
use ndn_packet::SignatureType;
use ndn_security::{ActiveSigner, Signer};
use rustls::pki_types::CertificateDer;
use rustls::sign::CertifiedKey;
use rustls::{SignatureAlgorithm, SignatureScheme};
use sha2::{Digest, Sha256};

/// DER prefix of an Ed25519 SubjectPublicKeyInfo (RFC 8410), followed by the
/// 32-byte key.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
/// DER prefix of a P-256 SubjectPublicKeyInfo (id-ecPublicKey, prime256v1),
/// followed by the 65-byte uncompressed point.
const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// The key algorithms a link key can use: the two NDN device key types.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkKeyAlgorithm {
    Ed25519,
    EcdsaP256,
}

impl LinkKeyAlgorithm {
    fn scheme(self) -> SignatureScheme {
        match self {
            Self::Ed25519 => SignatureScheme::ED25519,
            Self::EcdsaP256 => SignatureScheme::ECDSA_NISTP256_SHA256,
        }
    }

    fn rustls_algorithm(self) -> SignatureAlgorithm {
        match self {
            Self::Ed25519 => SignatureAlgorithm::ED25519,
            Self::EcdsaP256 => SignatureAlgorithm::ECDSA,
        }
    }
}

/// SHA-256 over a key as an NDN certificate carries it (the raw 32 bytes of
/// an Ed25519 key, the SubjectPublicKeyInfo of a P-256 key): the same
/// fingerprint an anchor link uses for a namespace's root key, so a device's
/// fingerprint reads the same wherever it is shown.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeyFingerprint(pub [u8; 32]);

impl KeyFingerprint {
    /// The fingerprint of an NDN public key (certificate `Content` form).
    pub fn of_ndn_key(ndn_public_key: &[u8]) -> Self {
        Self(Sha256::digest(ndn_public_key).into())
    }

    /// Parse 64 hex digits (the form [`Display`](fmt::Display) prints).
    pub fn from_hex(text: &str) -> Option<Self> {
        let text = text.trim();
        if text.len() != 64 {
            return None;
        }
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(text.get(2 * i..2 * i + 2)?, 16).ok()?;
        }
        Some(Self(out))
    }
}

impl fmt::Display for KeyFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for KeyFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyFingerprint({self})")
    }
}

/// A peer's public key, as its TLS handshake proved possession of it.
#[derive(Clone, PartialEq, Eq)]
pub struct PeerKey {
    algorithm: LinkKeyAlgorithm,
    spki: Bytes,
}

impl PeerKey {
    /// Parse a raw public key (SubjectPublicKeyInfo DER). Only the NDN device
    /// key types are links' keys.
    pub fn from_spki(spki: &[u8]) -> Result<Self, KeyError> {
        let algorithm = if spki.len() == ED25519_SPKI_PREFIX.len() + 32
            && spki.starts_with(&ED25519_SPKI_PREFIX)
        {
            LinkKeyAlgorithm::Ed25519
        } else if spki.len() == P256_SPKI_PREFIX.len() + 65
            && spki.starts_with(&P256_SPKI_PREFIX)
            && spki[P256_SPKI_PREFIX.len()] == 0x04
        {
            LinkKeyAlgorithm::EcdsaP256
        } else {
            return Err(KeyError::Unsupported(
                "the key is neither Ed25519 nor P-256, the two NDN device key types".into(),
            ));
        };
        Ok(Self {
            algorithm,
            spki: Bytes::copy_from_slice(spki),
        })
    }

    pub fn algorithm(&self) -> LinkKeyAlgorithm {
        self.algorithm
    }

    /// The SubjectPublicKeyInfo the peer presented.
    pub fn spki(&self) -> &Bytes {
        &self.spki
    }

    /// The key as an NDN certificate carries it: the raw 32 bytes for
    /// Ed25519, the SubjectPublicKeyInfo for P-256. Compare a certificate's
    /// `public_key` with this.
    pub fn ndn_public_key(&self) -> Bytes {
        match self.algorithm {
            LinkKeyAlgorithm::Ed25519 => self.spki.slice(ED25519_SPKI_PREFIX.len()..),
            LinkKeyAlgorithm::EcdsaP256 => self.spki.clone(),
        }
    }

    pub fn fingerprint(&self) -> KeyFingerprint {
        KeyFingerprint::of_ndn_key(&self.ndn_public_key())
    }
}

impl fmt::Debug for PeerKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerKey")
            .field("algorithm", &self.algorithm)
            .field("fingerprint", &self.fingerprint())
            .finish()
    }
}

/// Why a key cannot be a link key.
#[derive(Debug, Clone, thiserror::Error)]
pub enum KeyError {
    #[error("{0}")]
    Unsupported(String),
    #[error(
        "this device's key {key} signs only asynchronously (a hardware token or a key custodian), \
         and a link handshake needs a synchronous signature; run the daemon with a software device \
         key in its PIB (`[security] identity`), as `ndn-fwd enroll` makes"
    )]
    AsyncOnly { key: String },
}

/// This device's link key now: its NDN public key as a SubjectPublicKeyInfo
/// and the signer that makes the TLS 1.3 CertificateVerify signature with it.
/// TLS 1.3 signs a context string that no NDN packet starts with, so using
/// the device key for both is safe.
#[derive(Clone)]
pub struct LinkKey {
    algorithm: LinkKeyAlgorithm,
    spki: Bytes,
    signer: Arc<dyn Signer>,
}

impl fmt::Debug for LinkKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinkKey")
            .field("key", self.signer.key_name())
            .field("fingerprint", &self.fingerprint())
            .finish()
    }
}

impl LinkKey {
    /// The link key of an NDN signer: an Ed25519 or P-256 key that signs
    /// synchronously.
    pub fn from_signer(signer: Arc<dyn Signer>) -> Result<Self, KeyError> {
        let key = signer.public_key().ok_or_else(|| {
            KeyError::Unsupported(format!(
                "this device's key {} does not expose its public key",
                signer.key_name()
            ))
        })?;
        let (algorithm, spki) = match signer.sig_type() {
            SignatureType::SignatureEd25519 => {
                let raw: [u8; 32] = key.as_ref().try_into().map_err(|_| {
                    KeyError::Unsupported(format!(
                        "this device's Ed25519 key {} is not 32 bytes",
                        signer.key_name()
                    ))
                })?;
                (LinkKeyAlgorithm::Ed25519, ndn_security::spki::wrap_ed25519(&raw))
            }
            SignatureType::SignatureSha256WithEcdsa => (LinkKeyAlgorithm::EcdsaP256, key),
            other => {
                return Err(KeyError::Unsupported(format!(
                    "this device's key {} is a {other:?} key; a link needs an Ed25519 or P-256 \
                     device key",
                    signer.key_name()
                )));
            }
        };
        // A signer behind an async boundary refuses `sign_sync`; find out now,
        // not in the middle of a handshake.
        if signer.sign_sync(b"ndn-link key probe").is_err() {
            return Err(KeyError::AsyncOnly {
                key: signer.key_name().to_string(),
            });
        }
        PeerKey::from_spki(&spki)?;
        Ok(Self {
            algorithm,
            spki,
            signer,
        })
    }

    /// This key's signature over `label`, if it signs at all.
    pub(crate) fn sign_label(&self, label: &[u8]) -> Option<Bytes> {
        self.signer.sign_sync(label).ok()
    }

    pub fn fingerprint(&self) -> KeyFingerprint {
        match self.algorithm {
            LinkKeyAlgorithm::Ed25519 => {
                KeyFingerprint::of_ndn_key(&self.spki[ED25519_SPKI_PREFIX.len()..])
            }
            LinkKeyAlgorithm::EcdsaP256 => KeyFingerprint::of_ndn_key(&self.spki),
        }
    }

    /// The NDN key name of this key.
    pub fn key_name(&self) -> &ndn_packet::Name {
        self.signer.key_name()
    }

    /// The key as TLS carries it (its SubjectPublicKeyInfo); a device also
    /// names itself with it in the signed messages of a direct-path punch.
    pub fn spki(&self) -> &Bytes {
        &self.spki
    }

    /// The NDN signer of this key: the key signs NDN packets too (the
    /// signed Interest and Data of a direct-path punch).
    pub fn signer(&self) -> &Arc<dyn Signer> {
        &self.signer
    }

    pub(crate) fn certified(&self) -> Arc<CertifiedKey> {
        Arc::new(CertifiedKey::new(
            vec![CertificateDer::from(self.spki.to_vec())],
            Arc::new(TlsSigningKey {
                algorithm: self.algorithm,
                signer: Arc::clone(&self.signer),
            }),
        ))
    }
}

/// Where a link endpoint takes this device's key from, once per handshake,
/// so a key the daemon switches to (an enrollment) applies to the next link.
pub trait LinkKeySource: Send + Sync + 'static {
    fn current(&self) -> Result<LinkKey, KeyError>;
}

impl LinkKeySource for ActiveSigner {
    fn current(&self) -> Result<LinkKey, KeyError> {
        LinkKey::from_signer(ActiveSigner::current(self))
    }
}

impl LinkKeySource for LinkKey {
    fn current(&self) -> Result<LinkKey, KeyError> {
        Ok(self.clone())
    }
}

struct TlsSigningKey {
    algorithm: LinkKeyAlgorithm,
    signer: Arc<dyn Signer>,
}

impl fmt::Debug for TlsSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsSigningKey")
            .field("algorithm", &self.algorithm)
            .field("key", self.signer.key_name())
            .finish()
    }
}

impl rustls::sign::SigningKey for TlsSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn rustls::sign::Signer>> {
        let scheme = self.algorithm.scheme();
        offered.contains(&scheme).then(|| {
            Box::new(TlsSigner {
                scheme,
                signer: Arc::clone(&self.signer),
            }) as Box<dyn rustls::sign::Signer>
        })
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm.rustls_algorithm()
    }
}

struct TlsSigner {
    scheme: SignatureScheme,
    signer: Arc<dyn Signer>,
}

impl fmt::Debug for TlsSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsSigner").field("scheme", &self.scheme).finish()
    }
}

impl rustls::sign::Signer for TlsSigner {
    /// Ed25519 signs the message itself; the P-256 signer hashes it with
    /// SHA-256 and returns a DER signature — both exactly what TLS 1.3 wants.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        self.signer
            .sign_sync(message)
            .map(|sig| sig.to_vec())
            .map_err(|e| rustls::Error::General(format!("device key signature: {e}")))
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_security::{EcdsaP256Signer, Ed25519Signer};

    #[test]
    fn a_link_key_fingerprint_is_the_certificate_key_fingerprint() {
        let ed = Ed25519Signer::from_seed(&[7; 32], "/ns/member/a/KEY/k".parse().unwrap());
        let raw = ed.public_key_bytes();
        let key = LinkKey::from_signer(Arc::new(ed)).unwrap();
        assert_eq!(key.fingerprint(), KeyFingerprint::of_ndn_key(&raw));
        let peer = PeerKey::from_spki(&key.spki).unwrap();
        assert_eq!(peer.ndn_public_key().as_ref(), &raw);
        assert_eq!(peer.fingerprint(), key.fingerprint());

        let ec = EcdsaP256Signer::from_seed(&[9; 32], "/ns/node/r/KEY/k".parse().unwrap()).unwrap();
        let spki = ec.public_key().unwrap();
        let key = LinkKey::from_signer(Arc::new(ec)).unwrap();
        let peer = PeerKey::from_spki(&spki).unwrap();
        assert_eq!(peer.ndn_public_key(), spki);
        assert_eq!(peer.fingerprint(), key.fingerprint());
    }

    #[test]
    fn fingerprints_round_trip_through_hex() {
        let fp = KeyFingerprint([0xab; 32]);
        assert_eq!(KeyFingerprint::from_hex(&fp.to_string()), Some(fp));
        assert_eq!(KeyFingerprint::from_hex("ab"), None);
    }
}
