//! Attribute-authority issuance and `ParamFetcher` key recovery — the NAC key
//! distribution, sans-IO.
//!
//! The authority holds the ABE master secret and a per-identity grant table. On
//! an **authenticated** decryption-key request (the NDN service shell validates
//! the signed `DKEY` Interest and passes the verified requester identity), it:
//!
//! 1. looks up the requester's grant — **fails closed** if absent (NSF-A2/F5);
//! 2. generates the decryption key (CP attribute keys / KP policy key);
//! 3. **seals** it to the requester's advertised ephemeral X25519 public key, so
//!    only that requester can open it (confidential DKEY delivery).
//!
//! The `open_*_dkey` functions are the `ParamFetcher` side: a requester opens
//! the sealed key with the [`Recipient`] it generated for the request.
//!
//! What stays in the NDN service shell (gated by the O4 invariants before it
//! lands): validating the signed `DKEY` Interest (NSF-A1), binding the verified
//! signer identity to the advertised X25519 key, serving `PUBPARAMS`/`DKEY` over
//! an `ndn-app` Producer, and the consumer-side fetch loop.

use std::collections::HashMap;

use bytes::Bytes;
use ndn_packet::Name;
use ndn_sealed_box::{Recipient, seal};
use ndn_security::abe::{
    BswAttributeKeys, BswMasterParams, BswMasterSecret, KpMasterParams, KpMasterSecret,
    KpPolicyKey, PolicyExpr, bsw_keygen, lsw_keygen,
};

use tracing::instrument;

use crate::ckdata::NacError;

/// Domain-separation salt binding a sealed blob to the NAC DKEY context.
const DKEY_SEAL_SALT: &[u8] = b"ndn-nacabe/DKEY/v1";

/// A CP-ABE attribute authority: master secret + per-identity attribute grants.
pub struct CpAuthority {
    params: BswMasterParams,
    secret: BswMasterSecret,
    grants: HashMap<Name, Vec<String>>,
}

impl CpAuthority {
    /// Construct from a freshly generated CP-ABE master key pair.
    pub fn new(params: BswMasterParams, secret: BswMasterSecret) -> Self {
        Self {
            params,
            secret,
            grants: HashMap::new(),
        }
    }

    /// Enroll a requester: grant `attributes` to `identity`. Only enrolled
    /// identities can obtain a key.
    pub fn grant(&mut self, identity: Name, attributes: Vec<String>) {
        self.grants.insert(identity, attributes);
    }

    /// The `PUBPARAMS` payload — the public encryption parameters producers fetch.
    pub fn public_params(&self) -> Bytes {
        self.params.public_key_bytes.clone()
    }

    /// Issue an attribute key for an **already-authenticated** `requester`,
    /// sealed to its advertised X25519 `recipient_public`. Fails closed
    /// ([`NacError::Unauthorized`]) if the requester has no grant.
    #[instrument(skip(self, recipient_public), fields(requester = %requester, scheme = "cp-abe"))]
    pub fn issue_dkey(
        &self,
        requester: &Name,
        recipient_public: &[u8],
    ) -> Result<Bytes, NacError> {
        let attrs = self.grants.get(requester).ok_or(NacError::Unauthorized)?;
        let keys = bsw_keygen(&self.params, &self.secret, attrs)?;
        let sealed = seal(DKEY_SEAL_SALT, recipient_public, &keys.keys_bytes)
            .ok_or(NacError::SealFailed)?;
        Ok(Bytes::from(sealed))
    }
}

/// A KP-ABE attribute authority: master secret + per-identity policy grants
/// (the NDNSF `ServiceController` model — the key carries the policy).
pub struct KpAuthority {
    params: KpMasterParams,
    secret: KpMasterSecret,
    grants: HashMap<Name, PolicyExpr>,
}

impl KpAuthority {
    /// Construct from a freshly generated KP-ABE master key pair.
    pub fn new(params: KpMasterParams, secret: KpMasterSecret) -> Self {
        Self {
            params,
            secret,
            grants: HashMap::new(),
        }
    }

    /// Enroll a requester: grant a key-`policy` to `identity`.
    pub fn grant(&mut self, identity: Name, policy: PolicyExpr) {
        self.grants.insert(identity, policy);
    }

    /// The `PUBPARAMS` payload.
    pub fn public_params(&self) -> Bytes {
        self.params.public_key_bytes.clone()
    }

    /// Issue a policy key for an authenticated `requester`, sealed to its
    /// advertised X25519 key, using this authority's **own grant table**. Fails
    /// closed if the requester has no grant (the NDNSF-compat path).
    #[instrument(skip(self, recipient_public), fields(requester = %requester, scheme = "kp-abe"))]
    pub fn issue_dkey(
        &self,
        requester: &Name,
        recipient_public: &[u8],
    ) -> Result<Bytes, NacError> {
        let policy = self.grants.get(requester).ok_or(NacError::Unauthorized)?;
        self.issue_with_policy(requester, policy, recipient_public)
    }

    /// Issue a policy key for `requester` under an **explicit** key-`policy`,
    /// sealed to its advertised X25519 key — the policy source is the caller's
    /// (e.g. a v2 `PolicyAuthority`'s current signed grant), not this authority's
    /// grant table. Keygen + seal only; authorization is the caller's
    /// responsibility (the caller fails closed before calling this).
    #[instrument(skip(self, policy, recipient_public), fields(requester = %requester, scheme = "kp-abe"))]
    pub fn issue_with_policy(
        &self,
        requester: &Name,
        policy: &PolicyExpr,
        recipient_public: &[u8],
    ) -> Result<Bytes, NacError> {
        let _ = requester; // present for the tracing span
        let key = lsw_keygen(&self.params, &self.secret, policy)?;
        let sealed = seal(DKEY_SEAL_SALT, recipient_public, &key.key_bytes)
            .ok_or(NacError::SealFailed)?;
        Ok(Bytes::from(sealed))
    }
}

/// `ParamFetcher` side: open a sealed CP-ABE attribute key with the `recipient`
/// generated for the request.
pub fn open_cp_dkey(recipient: Recipient, sealed: &[u8]) -> Result<BswAttributeKeys, NacError> {
    let bytes = recipient
        .open(DKEY_SEAL_SALT, sealed)
        .ok_or(NacError::UnsealFailed)?;
    Ok(BswAttributeKeys {
        keys_bytes: Bytes::from(bytes),
    })
}

/// `ParamFetcher` side: open a sealed KP-ABE policy key.
pub fn open_kp_dkey(recipient: Recipient, sealed: &[u8]) -> Result<KpPolicyKey, NacError> {
    let bytes = recipient
        .open(DKEY_SEAL_SALT, sealed)
        .ok_or(NacError::UnsealFailed)?;
    Ok(KpPolicyKey {
        key_bytes: Bytes::from(bytes),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ckdata::{open_cp, open_kp, seal_cp, seal_kp};
    use ndn_foundation_types::Hash;
    use ndn_security::abe::{bsw_setup, lsw_setup};

    fn name(s: &str) -> Name {
        s.parse().unwrap()
    }

    #[test]
    fn cp_end_to_end_issue_seal_open_decrypt() {
        // Authority setup + a producer's KGC reference share the same params.
        let (mp, ms) = bsw_setup().unwrap();
        let mut aa = CpAuthority::new(mp.clone(), ms);
        aa.grant(name("/muas/alice"), vec!["role:analyst".into()]);

        // Producer wraps a CK under a policy alice satisfies.
        let kgc = (name("/muas/aa"), Hash::of(&mp.public_key_bytes), mp);
        let policy = PolicyExpr::parse("role:analyst OR role:commander").unwrap();
        let (ck_data, sealed_content) =
            seal_cp(name("/p/CK/1"), &policy, &kgc, b"intel", b"/intel/v1").unwrap();

        // alice requests her DKEY: generates a Recipient, AA seals to it.
        let recipient = Recipient::generate().unwrap();
        let sealed_dkey = aa.issue_dkey(&name("/muas/alice"), &recipient.public).unwrap();

        // alice opens the sealed DKEY, then decrypts the content end-to-end.
        let keys = open_cp_dkey(recipient, &sealed_dkey).unwrap();
        assert_eq!(open_cp(&ck_data, &keys, &sealed_content, b"/intel/v1").unwrap(), b"intel");
    }

    #[test]
    fn issue_fails_closed_for_unenrolled_requester() {
        // NSF-A2 / NSF-F5: the authority refuses to issue to an unknown identity.
        let (mp, ms) = bsw_setup().unwrap();
        let aa = CpAuthority::new(mp, ms);
        let recipient = Recipient::generate().unwrap();
        assert!(matches!(
            aa.issue_dkey(&name("/muas/mallory"), &recipient.public),
            Err(NacError::Unauthorized)
        ));
    }

    #[test]
    fn sealed_dkey_opens_only_for_the_requesting_recipient() {
        // Confidential delivery: a DKEY sealed to recipient A cannot be opened
        // by a different recipient B.
        let (mp, ms) = bsw_setup().unwrap();
        let mut aa = CpAuthority::new(mp, ms);
        aa.grant(name("/muas/alice"), vec!["role:analyst".into()]);
        let alice = Recipient::generate().unwrap();
        let sealed = aa.issue_dkey(&name("/muas/alice"), &alice.public).unwrap();

        let eve = Recipient::generate().unwrap();
        assert!(matches!(open_cp_dkey(eve, &sealed), Err(NacError::UnsealFailed)));
    }

    #[test]
    fn kp_end_to_end_issue_seal_open_decrypt() {
        let (mp, ms) = lsw_setup().unwrap();
        let mut aa = KpAuthority::new(mp.clone(), ms);
        // The controller grants alice a policy over the services she may read.
        aa.grant(
            name("/muas/alice"),
            PolicyExpr::parse("service:mavlink OR service:camera").unwrap(),
        );

        let kgc = (name("/muas/controller"), Hash::of(&mp.public_key_bytes), mp);
        let (ck_data, sealed_content) =
            seal_kp(name("/p/CK/2"), &["service:mavlink".into()], &kgc, b"cmd", b"/cmd/1").unwrap();

        let recipient = Recipient::generate().unwrap();
        let sealed_dkey = aa.issue_dkey(&name("/muas/alice"), &recipient.public).unwrap();
        let key = open_kp_dkey(recipient, &sealed_dkey).unwrap();
        assert_eq!(open_kp(&ck_data, &key, &sealed_content, b"/cmd/1").unwrap(), b"cmd");
    }
}
