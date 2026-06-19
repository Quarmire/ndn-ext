//! NAC protocol name components and name builders.
//!
//! These are the names the C++ NAC-ABE stack uses, so the (future) attribute
//! authority, the `ParamFetcher`, and the faithful NDNSF compat layer all speak
//! the same wire naming. Protocol-level interop with the C++ stack holds at this
//! layer; only the ABE *ciphertext bytes* do not interoperate (see
//! `docs/specs/service-layer.md` §7.3).

use ndn_packet::Name;

/// Public-parameters name component: `/<aa>/PUBPARAMS`.
pub const PUBPARAMS: &str = "PUBPARAMS";
/// Decryption-key name component: `/<aa>/DKEY/<key-name>`.
pub const DKEY: &str = "DKEY";
/// Content-key object component: `/<producer-id>/CK/<nonce>`.
pub const CK: &str = "CK";
/// "Encrypted-by" marker used to reference the CK object a payload is sealed under.
pub const ENC_BY: &str = "ENC-BY";
/// Data-owner policy-push command component.
pub const SET_POLICY: &str = "SET_POLICY";

/// The public-parameters name an attribute authority serves: `/<aa>/PUBPARAMS`.
pub fn pubparams_name(aa: &Name) -> Name {
    aa.clone().append(PUBPARAMS)
}

/// The decryption-key request name a decryptor expresses:
/// `/<aa>/DKEY/<requester-key-name...>`. The requester's key name is appended
/// component-wise so the authority can recover it and validate the requester's
/// certificate before issuing.
pub fn dkey_request_name(aa: &Name, requester_key: &Name) -> Name {
    let mut n = aa.clone().append(DKEY);
    for comp in requester_key.components() {
        n = n.append_component(comp.clone());
    }
    n
}

/// The content-key object name a producer publishes: `/<producer-id>/CK/<nonce>`.
/// `nonce` is a caller-supplied random value (kept out of this sans-IO layer so
/// it stays deterministic and testable).
pub fn ck_data_name(producer_id: &Name, nonce: u32) -> Name {
    producer_id
        .clone()
        .append(CK)
        .append(nonce.to_string().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    #[test]
    fn pubparams_name_appends_component() {
        let name = pubparams_name(&n("/muas/aa"));
        assert_eq!(name, n("/muas/aa/PUBPARAMS"));
    }

    #[test]
    fn dkey_request_name_carries_requester_key() {
        let name = dkey_request_name(&n("/muas/aa"), &n("/muas/alice/KEY/k1"));
        assert_eq!(name, n("/muas/aa/DKEY/muas/alice/KEY/k1"));
    }

    #[test]
    fn ck_data_name_has_ck_and_nonce() {
        let name = ck_data_name(&n("/muas/alice"), 42);
        assert_eq!(name, n("/muas/alice/CK/42"));
    }
}
