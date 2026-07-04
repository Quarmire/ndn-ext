//! ABE-by-role key distribution (feature `issuance`) — the scalable, data-centric
//! delivery of role-scoped keys, and the unification this layer was aiming for.
//!
//! Instead of sealing each member's scope keys to its public key one box per
//! member ([`crate::key_dist`]), each scope key is **ABE-wrapped under its scope
//! attribute** (`scope:<name>`) exactly once — a published, cacheable object any
//! member whose role covers the scope can open. A member holds a single KP-ABE key
//! whose policy is the OR of the scopes its role grants
//! ([`RoleScopePolicy::key_policy_for`](crate::session::RoleScopePolicy::key_policy_for)),
//! issued by the KP-ABE authority via the policy→issuance loop ([`crate::issuance`]);
//! it assembles its [`ScopeKeyring`] by opening exactly the wrapped scope keys it
//! is entitled to. The controller never enumerates members — granting a role
//! access to a scope is one ABE encryption, not O(members) re-sealing.
//!
//! This is §6.1's CK-indirection ("ABE-wrapped CK") applied to scope keys, on the
//! same KP-ABE `ServiceController` model as the rest of the confidentiality layer.

use ndn_foundation_types::Hash;
use ndn_packet::Name;
use ndn_security::abe::{
    AbeCiphertext, AbeError, KpMasterParams, KpPolicyKey, decrypt_kp, encrypt_kp,
};
use ndn_security::confidentiality::{CK_LEN, ContentKey};

use crate::session::{SCOPE_ATTR, ScopeKeyring};

/// The ABE attribute a scope's key is wrapped under.
fn scope_attr(scope: &str) -> String {
    format!("{SCOPE_ATTR}{scope}")
}

/// One scope key, ABE-wrapped under its scope attribute. Published **once per
/// scope** (not per member); any member whose role's KP-ABE key covers the scope
/// attribute can open it.
#[derive(Clone)]
pub struct WrappedScopeKey {
    /// The scope this key unlocks.
    pub scope: String,
    /// The scope key bytes, KP-ABE-encrypted under `scope:<scope>`.
    pub ciphertext: AbeCiphertext,
}

/// ABE-wrap every scope key in `all` under its scope attribute, using the KP-ABE
/// master params (`kgc_name` names the authority; `params` are its public params).
/// The result is published — per scope, not per member.
pub fn wrap_scope_keys(
    all: &ScopeKeyring,
    kgc_name: Name,
    params: &KpMasterParams,
) -> Result<Vec<WrappedScopeKey>, AbeError> {
    let kgc = (kgc_name, Hash::of(&params.public_key_bytes), params.clone());
    let mut wrapped = Vec::new();
    for scope in all.scopes() {
        let key = all.get(scope).expect("scope present in its own keyring");
        let ciphertext = encrypt_kp(&[scope_attr(scope)], key.expose(), &kgc)?;
        wrapped.push(WrappedScopeKey {
            scope: scope.to_string(),
            ciphertext,
        });
    }
    Ok(wrapped)
}

/// Assemble a member's [`ScopeKeyring`] from the published `wrapped` scope keys,
/// opening each with the member's KP-ABE `key`. Only scopes whose attribute the
/// key's policy satisfies are recovered — the role gate, enforced by ABE, with no
/// per-member targeting.
pub fn unwrap_scope_keys(wrapped: &[WrappedScopeKey], key: &KpPolicyKey) -> ScopeKeyring {
    let mut keyring = ScopeKeyring::new();
    for w in wrapped {
        if let Ok(bytes) = decrypt_kp(&w.ciphertext, key)
            && let Ok(raw) = <[u8; CK_LEN]>::try_from(bytes.as_slice())
        {
            keyring = keyring.with(&w.scope, ContentKey::from_bytes(raw));
        }
    }
    keyring
}
