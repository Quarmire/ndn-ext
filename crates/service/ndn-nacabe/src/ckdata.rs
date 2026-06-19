//! Content-key (CK) indirection — the heart of the NAC data flow.
//!
//! Content is sealed under a random symmetric content key ([`ContentKey`]); the
//! CK is ABE-wrapped (CP-ABE under a policy, or KP-ABE tagged with attributes)
//! into a separately-named, cacheable **CK-data** object published at
//! `/<producer-id>/CK/<nonce>`. A decryptor fetches the content, follows the
//! reference to the CK-data, unwraps the CK with the decryption key the
//! attribute authority issued it, and opens the content. Wrap-once / seal-many:
//! a producer ABE-wraps a CK once and symmetric-seals many payloads under it.
//!
//! This module is the sans-IO core — the named exchanges (authority serving
//! `PUBPARAMS`/`DKEY`, the `ParamFetcher`) layer on top, built on `ndn-app`.

use bytes::Bytes;
use ndn_foundation_types::{Hash, TlvDecode, TlvEncode};
use ndn_packet::Name;
use ndn_security::abe::{
    AbeCiphertext, AbeError, BswAttributeKeys, BswMasterParams, KpMasterParams, KpPolicyKey,
    PolicyExpr, decrypt, decrypt_kp, encrypt, encrypt_kp,
};
use ndn_security::confidentiality::ConfidentialityError;
use ndn_security::{ContentKey, Sealed};

/// Length of a content key (matches [`ndn_security::confidentiality::CK_LEN`]).
const CK_LEN: usize = 32;

/// Errors from the NAC content-key layer.
#[derive(Debug, thiserror::Error)]
pub enum NacError {
    /// The ABE wrap/unwrap failed (policy not satisfied, wrong keys, malformed).
    #[error("ABE error: {0}")]
    Abe(#[from] AbeError),
    /// The symmetric open failed (wrong CK, AAD mismatch, or tampered content).
    #[error("content open failed: {0}")]
    Confidentiality(#[from] ConfidentialityError),
    /// An unwrapped content key did not have exactly 32 bytes.
    #[error("unwrapped content key has wrong length")]
    BadContentKeyLength,
    /// CK-data content bytes were not a valid ABE ciphertext container.
    #[error("malformed CK-data")]
    MalformedCkData,
}

/// A named, ABE-wrapped content key — the CK-data object. On the wire it is a
/// (signed) Data named [`CkData::name`] whose Content is the wrapped CK
/// ([`CkData::to_content_bytes`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CkData {
    /// The CK-data object name, e.g. `/<producer-id>/CK/<nonce>`.
    pub name: Name,
    /// The ABE-wrapped content key (CP-ABE policy or KP-ABE attributes inside).
    pub wrapped: AbeCiphertext,
}

impl CkData {
    /// Wrap `ck` under a CP-ABE `policy` (producer-controlled). `kgc` is
    /// `(authority_name, master_params_hash, BswMasterParams)`.
    pub fn wrap_cp(
        name: Name,
        ck: &ContentKey,
        policy: &PolicyExpr,
        kgc: &(Name, Hash, BswMasterParams),
    ) -> Result<Self, NacError> {
        let wrapped = encrypt(policy, ck.expose(), kgc)?;
        Ok(Self { name, wrapped })
    }

    /// Wrap `ck` tagged with KP-ABE `attributes` (the authority-governed model
    /// the NDNSF controller uses). `kgc` is `(authority_name,
    /// master_params_hash, KpMasterParams)`.
    pub fn wrap_kp(
        name: Name,
        ck: &ContentKey,
        attributes: &[String],
        kgc: &(Name, Hash, KpMasterParams),
    ) -> Result<Self, NacError> {
        let wrapped = encrypt_kp(attributes, ck.expose(), kgc)?;
        Ok(Self { name, wrapped })
    }

    /// Unwrap the content key with CP-ABE attribute keys (fails closed if the
    /// keys' attributes do not satisfy the wrapped policy).
    pub fn unwrap_cp(&self, keys: &BswAttributeKeys) -> Result<ContentKey, NacError> {
        ck_from_bytes(decrypt(&self.wrapped, keys)?)
    }

    /// Unwrap the content key with a KP-ABE policy key (fails closed if the
    /// key's policy is not satisfied by the wrapped attributes).
    pub fn unwrap_kp(&self, key: &KpPolicyKey) -> Result<ContentKey, NacError> {
        ck_from_bytes(decrypt_kp(&self.wrapped, key)?)
    }

    /// The Data Content bytes of the CK-data object (the wrapped CK container).
    pub fn to_content_bytes(&self) -> Bytes {
        self.wrapped.encode_to_bytes()
    }

    /// Reconstruct a CK-data object from its name and Data Content bytes.
    pub fn from_parts(name: Name, content: Bytes) -> Result<Self, NacError> {
        let wrapped =
            AbeCiphertext::decode_from_bytes(content).map_err(|_| NacError::MalformedCkData)?;
        Ok(Self { name, wrapped })
    }
}

fn ck_from_bytes(bytes: Vec<u8>) -> Result<ContentKey, NacError> {
    let arr: [u8; CK_LEN] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| NacError::BadContentKeyLength)?;
    Ok(ContentKey::from_bytes(arr))
}

/// Producer side (CP-ABE): seal `plaintext` under a fresh content key and wrap
/// that key under `policy`. Returns the CK-data object and the sealed content.
pub fn seal_cp(
    ck_name: Name,
    policy: &PolicyExpr,
    kgc: &(Name, Hash, BswMasterParams),
    plaintext: &[u8],
    aad: &[u8],
) -> Result<(CkData, Sealed), NacError> {
    let ck = ContentKey::generate();
    let ck_data = CkData::wrap_cp(ck_name, &ck, policy, kgc)?;
    let sealed = ck.seal(plaintext, aad);
    Ok((ck_data, sealed))
}

/// Consumer side (CP-ABE): unwrap the content key from `ck_data` with `keys`,
/// then open `sealed`. Fails closed end-to-end if the keys do not satisfy the
/// policy (no content key, no plaintext).
pub fn open_cp(
    ck_data: &CkData,
    keys: &BswAttributeKeys,
    sealed: &Sealed,
    aad: &[u8],
) -> Result<Vec<u8>, NacError> {
    let ck = ck_data.unwrap_cp(keys)?;
    Ok(ck.open(sealed, aad)?)
}

/// Producer side (KP-ABE): seal `plaintext` under a fresh content key tagged
/// with `attributes`.
pub fn seal_kp(
    ck_name: Name,
    attributes: &[String],
    kgc: &(Name, Hash, KpMasterParams),
    plaintext: &[u8],
    aad: &[u8],
) -> Result<(CkData, Sealed), NacError> {
    let ck = ContentKey::generate();
    let ck_data = CkData::wrap_kp(ck_name, &ck, attributes, kgc)?;
    let sealed = ck.seal(plaintext, aad);
    Ok((ck_data, sealed))
}

/// Consumer side (KP-ABE): unwrap with a policy key, then open. Fails closed if
/// the key-policy is not satisfied by the ciphertext attributes.
pub fn open_kp(
    ck_data: &CkData,
    key: &KpPolicyKey,
    sealed: &Sealed,
    aad: &[u8],
) -> Result<Vec<u8>, NacError> {
    let ck = ck_data.unwrap_kp(key)?;
    Ok(ck.open(sealed, aad)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_security::abe::{bsw_keygen, bsw_setup, lsw_keygen, lsw_setup};

    fn name(s: &str) -> Name {
        s.parse().unwrap()
    }

    #[test]
    fn cp_ck_data_full_round_trip_and_wire() {
        let (mp, ms) = bsw_setup().unwrap();
        let kgc = (name("/hospital/kgc"), Hash::of(&mp.public_key_bytes), mp);
        let policy = PolicyExpr::parse("role:doctor AND dept:cardiology").unwrap();
        let aad = b"/records/patient-42";

        let (ck_data, sealed) =
            seal_cp(name("/dr/CK/7"), &policy, &kgc, b"ECG trace", aad).unwrap();

        // CK-data survives a Content-bytes round trip (it rides as Data Content).
        let ck_data = CkData::from_parts(ck_data.name.clone(), ck_data.to_content_bytes()).unwrap();

        let keys =
            bsw_keygen(&kgc.2, &ms, &["role:doctor".into(), "dept:cardiology".into()]).unwrap();
        assert_eq!(open_cp(&ck_data, &keys, &sealed, aad).unwrap(), b"ECG trace");
    }

    #[test]
    fn cp_unauthorized_fails_closed() {
        // NSF-F5 at the protocol composition: wrong attributes yield no content
        // key and no plaintext.
        let (mp, ms) = bsw_setup().unwrap();
        let kgc = (name("/hospital/kgc"), Hash::of(&mp.public_key_bytes), mp);
        let policy = PolicyExpr::parse("role:doctor").unwrap();
        let (ck_data, sealed) = seal_cp(name("/dr/CK/1"), &policy, &kgc, b"secret", b"aad").unwrap();

        let wrong = bsw_keygen(&kgc.2, &ms, &["role:nurse".into()]).unwrap();
        assert!(open_cp(&ck_data, &wrong, &sealed, b"aad").is_err());
    }

    #[test]
    fn kp_ck_data_full_round_trip() {
        // The NDNSF controller model: producer tags the CK with attributes, the
        // authority issues a key whose policy is satisfied by them.
        let (mp, ms) = lsw_setup().unwrap();
        let kgc = (name("/muas/controller"), Hash::of(&mp.public_key_bytes), mp);
        let attrs = vec!["service:mavlink".to_string()];
        let aad = b"/muas/cmd/1";

        let (ck_data, sealed) = seal_kp(name("/p/CK/3"), &attrs, &kgc, b"takeoff", aad).unwrap();
        let key =
            lsw_keygen(&kgc.2, &ms, &PolicyExpr::parse("service:mavlink OR service:camera").unwrap())
                .unwrap();
        assert_eq!(open_kp(&ck_data, &key, &sealed, aad).unwrap(), b"takeoff");
    }
}
