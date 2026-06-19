//! Data-plane confidentiality for a pipe's bulk — the **encrypt-then-code**
//! axis the thesis lacked. The producer encrypts the payload *before* it is
//! segmented and coded, so the coded/relay layer (and any recoder) only ever
//! handles ciphertext: it can recode combinations it can neither read nor
//! forge. The consumer decodes, then decrypts.
//!
//! This is the **Tier-0 / NAC baseline**: a pre-shared 32-byte content key,
//! ChaCha20-Poly1305 (`ndn-crypto-core`, no_std — runs on an MCU). *How the
//! content key is distributed* is the NAC layer (per-group key-wrap) — a gap
//! still to build; here the key is pre-shared (commissioning-time). The Tier-2
//! ABE policy-wrap (`ndn-abe`) layers on by wrapping this same content key.

use bytes::Bytes;
use ndn_crypto_core::{open_in_place, seal_in_place};

/// Sealed-blob layout: `nonce(12) ‖ tag(16) ‖ ciphertext`.
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const HEADER: usize = NONCE_LEN + TAG_LEN;

/// How a pipe protects its bulk content.
#[derive(Clone, Default)]
pub enum Confidentiality {
    /// Cleartext bulk — authenticity only (signed Data), no read-control.
    #[default]
    None,
    /// AEAD under a pre-shared content key (Tier-0 / NAC baseline).
    Aead([u8; 32]),
}

impl core::fmt::Debug for Confidentiality {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Confidentiality::None => f.write_str("None"),
            Confidentiality::Aead(_) => f.write_str("Aead(<content-key>)"),
        }
    }
}

impl Confidentiality {
    pub fn is_some(&self) -> bool {
        !matches!(self, Confidentiality::None)
    }

    /// Encrypt `plaintext` for the bulk (called before segmenting). Returns the
    /// payload that is segmented + coded — ciphertext when AEAD, plaintext
    /// otherwise.
    pub fn seal(&self, plaintext: &[u8]) -> Bytes {
        match self {
            Confidentiality::None => Bytes::copy_from_slice(plaintext),
            Confidentiality::Aead(key) => {
                // TODO: random nonce per object; fixed here for the one-shot
                // pipe-object witness (a pipe carries one object per generation).
                let nonce = [0u8; NONCE_LEN];
                let mut buf = plaintext.to_vec();
                let tag = seal_in_place(key, &nonce, b"", &mut buf).expect("valid key length");
                let mut out = Vec::with_capacity(HEADER + buf.len());
                out.extend_from_slice(&nonce);
                out.extend_from_slice(&tag);
                out.extend_from_slice(&buf);
                Bytes::from(out)
            }
        }
    }

    /// Decrypt a recovered bulk blob (called after decoding). `None` on auth
    /// failure (wrong key / tampered) — confidentiality + integrity in one.
    pub fn open(&self, sealed: &[u8]) -> Option<Bytes> {
        match self {
            Confidentiality::None => Some(Bytes::copy_from_slice(sealed)),
            Confidentiality::Aead(key) => {
                if sealed.len() < HEADER {
                    return None;
                }
                let mut nonce = [0u8; NONCE_LEN];
                nonce.copy_from_slice(&sealed[..NONCE_LEN]);
                let mut tag = [0u8; TAG_LEN];
                tag.copy_from_slice(&sealed[NONCE_LEN..HEADER]);
                let mut ct = sealed[HEADER..].to_vec();
                open_in_place(key, &nonce, b"", &mut ct, &tag).then(|| Bytes::from(ct))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aead_round_trips_and_ciphertext_is_opaque() {
        let conf = Confidentiality::Aead([7u8; 32]);
        let plain = b"the bulk content a relay must not read";
        let sealed = conf.seal(plain);
        assert_ne!(sealed.as_ref(), plain, "sealed bulk is ciphertext, not plaintext");
        assert_eq!(conf.open(&sealed).unwrap().as_ref(), plain);
        // Wrong key fails (auth) — read-control holds.
        assert!(Confidentiality::Aead([8u8; 32]).open(&sealed).is_none());
    }
}
