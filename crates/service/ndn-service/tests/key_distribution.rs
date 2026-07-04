//! Witness: a member receives its role-scoped keyring by sealed box. The
//! controller seals exactly the role's scope keys to the member's X25519 key;
//! only the member can open them, and the recovered keys are the real scope keys.

use std::collections::HashSet;

use ndn_sealed_box::Recipient;
use ndn_security::confidentiality::ContentKey;
use ndn_service::{RoleScopePolicy, ScopeKeyring, open_keyring, provision_keyring};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Role {
    Commander,
    Observer,
}

#[test]
fn member_receives_only_its_roles_scope_keys() {
    let all = ScopeKeyring::new()
        .with("control", ContentKey::from_bytes([1u8; 32]))
        .with("telemetry", ContentKey::from_bytes([2u8; 32]));
    let policy = RoleScopePolicy::new()
        .grant(Role::Commander, "control")
        .grant(Role::Commander, "telemetry")
        .grant(Role::Observer, "telemetry");

    // The controller seals the observer's keyring to the member's public key.
    let member = Recipient::generate().unwrap();
    let pubkey = member.public;
    let sealed = provision_keyring(&Role::Observer, &policy, &all, &pubkey).unwrap();

    // A stranger cannot open it (sealed to the member only).
    let stranger = Recipient::generate().unwrap();
    assert!(
        open_keyring(stranger, &sealed).is_none(),
        "sealed to the member only"
    );

    // The member opens its role-scoped keyring: exactly the observer's scopes.
    let keyring = open_keyring(member, &sealed).expect("member opens its keyring");
    let scopes: HashSet<&str> = keyring.scopes().collect();
    assert_eq!(
        scopes,
        HashSet::from(["telemetry"]),
        "observer receives only telemetry"
    );

    // The distributed key IS the real scope key: it opens content sealed by it.
    let aad = b"/muas/session/telemetry";
    let original = all.get("telemetry").unwrap();
    let sealed_msg = original.seal(b"21C", aad);
    let opened = keyring
        .get("telemetry")
        .unwrap()
        .open(&sealed_msg, aad)
        .unwrap();
    assert_eq!(
        opened, b"21C",
        "the distributed key is the genuine scope key"
    );
}

#[test]
fn commander_gets_all_granted_scopes() {
    let all = ScopeKeyring::new()
        .with("control", ContentKey::from_bytes([1u8; 32]))
        .with("telemetry", ContentKey::from_bytes([2u8; 32]));
    let policy = RoleScopePolicy::new()
        .grant(Role::Commander, "control")
        .grant(Role::Commander, "telemetry");

    let member = Recipient::generate().unwrap();
    let pubkey = member.public;
    let sealed = provision_keyring(&Role::Commander, &policy, &all, &pubkey).unwrap();
    let keyring = open_keyring(member, &sealed).unwrap();
    let scopes: HashSet<&str> = keyring.scopes().collect();
    assert_eq!(scopes, HashSet::from(["control", "telemetry"]));
}
