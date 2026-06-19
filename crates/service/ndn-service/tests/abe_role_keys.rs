#![cfg(feature = "issuance")]
//! Witness: ABE-by-role key distribution. Each scope key is ABE-wrapped under its
//! scope attribute ONCE (not per member); a member holds a single KP-ABE key whose
//! policy is the OR of its role's scopes and assembles its keyring by opening only
//! the wrapped scope keys it is entitled to. No per-member targeting; a scope the
//! role does not grant stays sealed.

use std::collections::HashSet;

use ndn_packet::Name;
use ndn_security::abe::{PolicyExpr, lsw_keygen, lsw_setup};
use ndn_security::confidentiality::ContentKey;
use ndn_service::{RoleScopePolicy, ScopeKeyring, unwrap_scope_keys, wrap_scope_keys};

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Role {
    Commander,
    Observer,
}

#[test]
fn role_kp_key_opens_only_its_granted_scopes() {
    let (mp, ms) = lsw_setup().unwrap();

    // Three confidentiality scopes; the role→scope policy.
    let all = ScopeKeyring::new()
        .with("control", ContentKey::from_bytes([1u8; 32]))
        .with("telemetry", ContentKey::from_bytes([2u8; 32]))
        .with("secret", ContentKey::from_bytes([3u8; 32]));
    let policy = RoleScopePolicy::new()
        .grant(Role::Commander, "control")
        .grant(Role::Commander, "telemetry")
        .grant(Role::Observer, "telemetry");

    // The controller ABE-wraps each scope key ONCE (per scope, not per member).
    let wrapped = wrap_scope_keys(&all, n("/muas/controller"), &mp).unwrap();
    assert_eq!(wrapped.len(), 3, "one published object per scope");

    // Each member holds a KP-ABE key for its role's policy (issued by the KP-ABE
    // authority; here generated directly — the policy→issuance loop is witnessed
    // separately).
    let commander_key = lsw_keygen(
        &mp,
        &ms,
        &PolicyExpr::parse(&policy.key_policy_for(&Role::Commander).unwrap()).unwrap(),
    )
    .unwrap();
    let observer_key = lsw_keygen(
        &mp,
        &ms,
        &PolicyExpr::parse(&policy.key_policy_for(&Role::Observer).unwrap()).unwrap(),
    )
    .unwrap();

    // Each member assembles its keyring from the SAME published wrapped keys.
    let commander_kr = unwrap_scope_keys(&wrapped, &commander_key);
    let observer_kr = unwrap_scope_keys(&wrapped, &observer_key);

    let commander_scopes: HashSet<&str> = commander_kr.scopes().collect();
    let observer_scopes: HashSet<&str> = observer_kr.scopes().collect();
    assert_eq!(commander_scopes, HashSet::from(["control", "telemetry"]), "no secret");
    assert_eq!(observer_scopes, HashSet::from(["telemetry"]), "only telemetry");

    // The recovered keys are the genuine scope keys (open content sealed by them).
    let aad = b"/muas/session/control";
    let sealed = all.get("control").unwrap().seal(b"advance", aad);
    let opened = commander_kr.get("control").unwrap().open(&sealed, aad).unwrap();
    assert_eq!(opened, b"advance", "ABE-recovered key is the real scope key");
}
