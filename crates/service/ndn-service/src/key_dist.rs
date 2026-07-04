//! Key distribution (service-layer §3.3): provision a member's role-scoped
//! keyring by **sealing its scope keys to the member's X25519 key**
//! (`ndn-sealed-box`). This connects the role→scope access policy (who *may* read
//! which scopes) to a concrete member: a controller holding all scope keys and the
//! [`RoleScopePolicy`] seals exactly the keys for the member's role to it; only
//! that member can open them into a [`ScopeKeyring`].
//!
//! It is the counterpart to the dynamic policy authority: a `PolicyAuthority`
//! decides *whether* a principal is granted a role; this hands the principal the
//! *keys* its role entails. Distribution is per member (a sealed box), so revoking
//! a member is epoch rotation of the affected scope keys + re-provisioning the
//! remaining members — the same honest ABE-revocation story (§4.4).

use bytes::Bytes;
use ndn_sealed_box::Recipient;
use ndn_security::confidentiality::ContentKey;
use ndn_service_core::Frame;
use ndn_service_core::framing::{encode_fields, read_field};

use crate::session::{RoleScopePolicy, ScopeKeyring};

/// Domain separator for sealed keyrings.
const KEYRING_SALT: &[u8] = b"ndn-service/keyring/v1";

/// Seal the keyring for `role` — exactly the scope keys its role is granted
/// (derived from `all_keys` via `policy`) — to `recipient_public` (the member's
/// X25519 public key). Returns the sealed blob the member opens with
/// [`open_keyring`]; `None` on a sealing failure.
pub fn provision_keyring<R: Eq + std::hash::Hash + Clone>(
    role: &R,
    policy: &RoleScopePolicy<R>,
    all_keys: &ScopeKeyring,
    recipient_public: &[u8],
) -> Option<Bytes> {
    let keyring = policy.keyring_for(role, all_keys);
    let plaintext = encode_keyring(&keyring);
    ndn_sealed_box::seal(KEYRING_SALT, recipient_public, &plaintext).map(Bytes::from)
}

/// Open a sealed keyring (from [`provision_keyring`]) with the member's
/// `recipient`. `None` if the blob was not sealed to this recipient or is
/// malformed.
pub fn open_keyring(recipient: Recipient, sealed: &[u8]) -> Option<ScopeKeyring> {
    let plaintext = recipient.open(KEYRING_SALT, sealed)?;
    decode_keyring(&plaintext)
}

/// Encode a keyring as repeated `(scope, key-bytes)` length-delimited fields.
fn encode_keyring(keyring: &ScopeKeyring) -> Bytes {
    let mut fields: Vec<Bytes> = Vec::new();
    for scope in keyring.scopes() {
        let key = keyring
            .get(scope)
            .expect("scope present in its own keyring");
        fields.push(Frame::encode(&scope.to_string()));
        fields.push(Bytes::copy_from_slice(key.expose()));
    }
    encode_fields(&fields)
}

fn decode_keyring(bytes: &[u8]) -> Option<ScopeKeyring> {
    let mut keyring = ScopeKeyring::new();
    let mut pos = 0usize;
    while pos < bytes.len() {
        let scope = String::decode(read_field(bytes, &mut pos).ok()?).ok()?;
        let key_field = read_field(bytes, &mut pos).ok()?;
        let key: [u8; ndn_security::confidentiality::CK_LEN] = key_field.try_into().ok()?;
        keyring = keyring.with(scope, ContentKey::from_bytes(key));
    }
    Some(keyring)
}
