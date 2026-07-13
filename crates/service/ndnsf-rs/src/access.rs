//! KP-ABE access control for the four-phase payloads (NSF-A3, feature `driver`).
//!
//! NDNSF gates service access through the `ServiceController`'s KP-ABE: a payload
//! is NAC-sealed tagged with the service's attributes, and only a participant
//! holding a key whose policy is satisfied by them can read it. This module is
//! the thin adapter that bundles `ndn-nacabe`'s content-key flow into a single
//! payload blob the four-phase driver carries unchanged:
//!
//! * [`seal_for`] — seal `plaintext` under `attributes` (the provider side).
//! * [`open_with`] — open it with a `ServiceController`-issued policy key (the
//!   user side). **Fails closed** when the key's policy is not satisfied — an
//!   unauthorized participant gets no plaintext, so the payload never affects
//!   its runtime state (NSF-A3).
//!
//! Wire bundle: `len(ck_data) u32-BE ‖ ck_data ‖ sealed`, where `ck_data` is the
//! ABE-wrapped content key and `sealed` is the symmetric-sealed content.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use ndn_foundation_types::Hash;
use ndn_nacabe::ckdata::{open_kp, seal_kp};
use ndn_nacabe::{CkData, NacError};
use ndn_packet::Name;
use ndn_security::Sealed;
use ndn_security::abe::{KpMasterParams, KpPolicyKey};

/// Seal `plaintext` for the given KP-ABE `attributes` (e.g. `["service:echo"]`).
/// `ck_name` names the content-key object; `kgc` is the controller's
/// `(name, master_params_hash, KpMasterParams)`. Returns the bundled payload the
/// four-phase driver carries as-is.
///
/// `aad` MUST uniquely bind this sealed object's context — derive it from the full
/// response/request name with [`context_aad`], **never** a constant or coarse
/// value. ABE attests *who* may read, not *which* object: with a reused AAD a
/// sealed response for one request opens as the answer to another with the same
/// attributes (red-team SEC-20). The matching [`open_with`] must pass the same AAD.
pub fn seal_for(
    ck_name: Name,
    attributes: &[String],
    kgc: &(Name, Hash, KpMasterParams),
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Bytes, NacError> {
    let (ck_data, sealed) = seal_kp(ck_name, attributes, kgc, plaintext, aad)?;
    let ck = ck_data.to_content_bytes();
    let sb = sealed.to_bytes();
    let mut out = BytesMut::with_capacity(4 + ck.len() + sb.len());
    out.put_u32(ck.len() as u32);
    out.put_slice(&ck);
    out.put_slice(&sb);
    Ok(out.freeze())
}

/// Open a [`seal_for`] bundle with a `ServiceController`-issued policy key. Fails
/// closed ([`NacError`]) if the key's policy is not satisfied by the bundle's
/// attributes, or the bundle is malformed.
pub fn open_with(key: &KpPolicyKey, blob: &[u8], aad: &[u8]) -> Result<Vec<u8>, NacError> {
    let mut b = blob;
    if b.remaining() < 4 {
        return Err(NacError::MalformedCkData);
    }
    let ck_len = b.get_u32() as usize;
    if b.remaining() < ck_len {
        return Err(NacError::MalformedCkData);
    }
    let ck_content = Bytes::copy_from_slice(&b[..ck_len]);
    let sealed_bytes = &b[ck_len..];
    // The CK-data name is metadata; unwrap uses only the wrapped ciphertext.
    let ck_data = CkData::from_parts(Name::from_components(core::iter::empty()), ck_content)?;
    let sealed = Sealed::from_bytes(sealed_bytes).map_err(|_| NacError::MalformedCkData)?;
    open_kp(&ck_data, key, &sealed, aad)
}

/// The canonical AAD binding a sealed payload to its `name` context — the TLV
/// encoding of the full response/request name (provider ‖ service ‖ request-id ‖
/// segment…). Pass the same value to [`seal_for`] and [`open_with`] so a sealed
/// payload cannot be replayed under a different name (red-team SEC-20); injective,
/// unlike a hand-built string.
pub fn context_aad(name: &Name) -> Bytes {
    name.encode_to_tlv()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_security::abe::{PolicyExpr, lsw_keygen, lsw_setup};

    fn name(s: &str) -> Name {
        s.parse().unwrap()
    }

    fn controller() -> (KpMasterParams, ndn_security::abe::KpMasterSecret) {
        lsw_setup().unwrap()
    }

    #[test]
    fn authorized_key_opens_unauthorized_fails_closed() {
        let (mp, ms) = controller();
        let kgc = (
            name("/muas/controller"),
            Hash::of(&mp.public_key_bytes),
            mp.clone(),
        );
        let aad = b"/svc/echo/r1";

        // Provider seals a response tagged with the service attribute.
        let blob = seal_for(
            name("/p/CK/1"),
            &["service:echo".into()],
            &kgc,
            b"pong",
            aad,
        )
        .unwrap();

        // An authorized user (policy satisfied by the attribute) reads it.
        let ok_key = lsw_keygen(
            &mp,
            &ms,
            &PolicyExpr::parse("service:echo OR service:cam").unwrap(),
        )
        .unwrap();
        assert_eq!(open_with(&ok_key, &blob, aad).unwrap(), b"pong");

        // An unauthorized user's key policy is not satisfied → fail closed.
        let bad_key = lsw_keygen(
            &mp,
            &ms,
            &PolicyExpr::parse("service:other AND perm:admin").unwrap(),
        )
        .unwrap();
        assert!(open_with(&bad_key, &blob, aad).is_err());
    }

    #[test]
    fn malformed_bundle_fails_closed() {
        let (mp, ms) = controller();
        let key = lsw_keygen(&mp, &ms, &PolicyExpr::parse("service:echo").unwrap()).unwrap();
        assert!(open_with(&key, &[0u8; 2], b"aad").is_err()); // too short for the length prefix
    }
}
