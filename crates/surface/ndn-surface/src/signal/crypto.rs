//! Run keys and seals.
//!
//! A run key is a fresh Ed25519 key (ed25519-dalek) whose public half the device
//! key binds in the run header; it signs [`CONTEXT`] ‖ the `SignalBody` value up
//! to `RunSignature`. A sealed scope's packet is that signed body encrypted with
//! XChaCha20-Poly1305 under the scope's signal key, a random 24-octet nonce, and
//! associated data [`CONTEXT`] ‖ KeyId: sign, then encrypt.

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{Tag, XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use super::wire::{
    CONTEXT, KEY_ID_LEN, NONCE_LEN, RunId, SIGNATURE_LEN, Sealed, TAG_LEN, encode_sealed,
};

/// Random octets from the operating system.
pub(crate) fn random<const N: usize>() -> Result<[u8; N], getrandom::Error> {
    let mut out = [0u8; N];
    getrandom::getrandom(&mut out)?;
    Ok(out)
}

/// A run's ephemeral signing key.
pub(crate) struct RunKey {
    signing: SigningKey,
    public: [u8; 32],
    id: RunId,
}

impl RunKey {
    /// A fresh run key from the operating system's randomness.
    pub(crate) fn generate() -> Result<RunKey, getrandom::Error> {
        Ok(RunKey::from_secret(&random::<32>()?))
    }

    pub(crate) fn from_secret(secret: &[u8; 32]) -> RunKey {
        let signing = SigningKey::from_bytes(secret);
        let public = signing.verifying_key().to_bytes();
        RunKey {
            signing,
            public,
            id: RunId::of_key(&public),
        }
    }

    pub(crate) fn public(&self) -> &[u8; 32] {
        &self.public
    }

    pub(crate) fn id(&self) -> RunId {
        self.id
    }

    /// The run signature over `region` (a body value up to `RunSignature`);
    /// `scratch` holds [`CONTEXT`] ‖ `region` and is reused across packets.
    pub(crate) fn sign(&self, region: &[u8], scratch: &mut Vec<u8>) -> [u8; SIGNATURE_LEN] {
        message(region, scratch);
        self.signing.sign(scratch).to_bytes()
    }
}

fn message(region: &[u8], scratch: &mut Vec<u8>) {
    scratch.clear();
    scratch.extend_from_slice(CONTEXT);
    scratch.extend_from_slice(region);
}

/// Whether `signature` is the run key `key`'s over `region` (strict Ed25519:
/// no malleable signature, no weak key).
pub(crate) fn verify(
    key: &VerifyingKey,
    region: &[u8],
    signature: &[u8; SIGNATURE_LEN],
    scratch: &mut Vec<u8>,
) -> bool {
    message(region, scratch);
    key.verify_strict(scratch, &Signature::from_bytes(signature))
        .is_ok()
}

fn aad(key_id: &[u8; KEY_ID_LEN]) -> [u8; 12 + KEY_ID_LEN] {
    let mut aad = [0u8; 12 + KEY_ID_LEN];
    aad[..12].copy_from_slice(CONTEXT);
    aad[12..].copy_from_slice(key_id);
    aad
}

/// Seal the `SignalBody` TLV `body` under the signal key `key` (id `key_id`)
/// with `nonce`: the whole `SignalSealed` packet.
pub(crate) fn seal(
    key: &[u8; 32],
    key_id: &[u8; KEY_ID_LEN],
    nonce: &[u8; NONCE_LEN],
    body: &[u8],
) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(key.into());
    encode_sealed(key_id, nonce, body, |region| {
        let tag = cipher
            .encrypt_in_place_detached(XNonce::from_slice(nonce), &aad(key_id), region)
            .expect("a packet is far below XChaCha20-Poly1305's message limit");
        tag.into()
    })
}

/// The `SignalBody` TLV `sealed` carries, if it opens under `key`; `None` when
/// it was altered or sealed under another key or key id.
pub(crate) fn open(key: &[u8; 32], sealed: &Sealed) -> Option<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let split = sealed.ciphertext.len() - TAG_LEN;
    let mut plain = sealed.ciphertext[..split].to_vec();
    let tag = Tag::from_slice(&sealed.ciphertext[split..]);
    cipher
        .decrypt_in_place_detached(
            XNonce::from_slice(&sealed.nonce),
            &aad(&sealed.key_id),
            &mut plain,
            tag,
        )
        .ok()?;
    Some(plain)
}

#[cfg(test)]
mod tests {
    use super::super::wire::{Packet, decode_packet};
    use super::*;
    use bytes::Bytes;

    fn sealed(key: &[u8; 32], key_id: &[u8; 8]) -> Sealed {
        let wire = seal(key, key_id, &[24; 24], b"a SignalBody");
        match decode_packet(Bytes::from(wire)).unwrap() {
            Packet::Sealed(s) => s,
            Packet::Body(_) => panic!("sealed"),
        }
    }

    #[test]
    fn a_sealed_packet_opens_only_under_its_key_and_key_id() {
        let s = sealed(&[1; 32], &[8; 8]);
        assert_eq!(open(&[1; 32], &s).as_deref(), Some(&b"a SignalBody"[..]));
        assert_eq!(open(&[2; 32], &s), None, "another key does not open it");
        let mut relabelled = s.clone();
        relabelled.key_id = [9; 8];
        assert_eq!(
            open(&[1; 32], &relabelled),
            None,
            "the key id is bound as associated data"
        );
        let mut altered = s;
        let mut c = altered.ciphertext.to_vec();
        c[0] ^= 1;
        altered.ciphertext = Bytes::from(c);
        assert_eq!(open(&[1; 32], &altered), None, "an altered ciphertext");
    }

    #[test]
    fn a_run_signature_verifies_only_over_what_it_signed_by_its_key() {
        let key = RunKey::from_secret(&[3; 32]);
        let other = RunKey::from_secret(&[4; 32]);
        let mut scratch = Vec::new();
        let sig = key.sign(b"region", &mut scratch);
        let public = VerifyingKey::from_bytes(key.public()).unwrap();
        assert!(verify(&public, b"region", &sig, &mut scratch));
        assert!(!verify(&public, b"regioN", &sig, &mut scratch));
        let public_other = VerifyingKey::from_bytes(other.public()).unwrap();
        assert!(!verify(&public_other, b"region", &sig, &mut scratch));
        assert_eq!(key.id(), RunId::of_key(key.public()));
    }
}
