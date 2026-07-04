#![cfg(feature = "config")]
//! Witness: the declarative policy front-end. Loading a TOML policy and reloading
//! it into a live PolicyAuthority applies the diff — (re)grant changed/new
//! principals, revoke dropped ones — with no restart, and is idempotent.

use ndn_packet::Name;
use ndn_security::KeyChain;
use ndn_service::{PolicyAuthority, load_policy_toml, reload};

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

#[test]
fn reload_applies_diff_and_is_idempotent() {
    let kc = KeyChain::ephemeral("/muas/group").unwrap();
    let mut authority = PolicyAuthority::new(n("/muas/group"), kc.signer().unwrap());

    // Initial state: alice granted directly (as if from a prior run).
    authority.grant(n("/muas/alice"), "service:echo");
    let v0 = authority.version();

    // A config grants alice (changed policy) + bob (new), and drops nobody else.
    let toml = r#"
        [[grant]]
        principal = "/muas/alice"
        policy    = "service:echo OR service:cam"

        [[grant]]
        principal = "/muas/bob"
        policy    = "service:telemetry"
    "#;
    let desired = load_policy_toml(toml).expect("policy parses");

    let report = reload(&mut authority, &desired);
    // alice re-granted (policy changed) + bob granted; nothing revoked.
    assert_eq!(report.granted.len(), 2, "alice (changed) + bob (new)");
    assert!(report.revoked.is_empty());
    assert!(
        report.version > v0,
        "changes bumped the version (no restart)"
    );
    assert_eq!(
        authority.grant_state(&n("/muas/alice")).unwrap().policy,
        "service:echo OR service:cam"
    );
    assert_eq!(
        authority.grant_state(&n("/muas/bob")).unwrap().policy,
        "service:telemetry"
    );

    // Reloading the SAME config is a no-op (idempotent).
    let again = reload(&mut authority, &desired);
    assert!(
        again.is_noop(),
        "re-applying an unchanged file changes nothing"
    );
    assert_eq!(again.version, report.version);

    // A config that drops bob revokes it.
    let toml2 = r#"
        [[grant]]
        principal = "/muas/alice"
        policy    = "service:echo OR service:cam"
    "#;
    let desired2 = load_policy_toml(toml2).unwrap();
    let report2 = reload(&mut authority, &desired2);
    assert_eq!(
        report2.revoked,
        vec![n("/muas/bob")],
        "bob dropped from the file → revoked"
    );
    assert!(report2.granted.is_empty(), "alice unchanged");
    assert!(authority.grant_state(&n("/muas/bob")).unwrap().revoked);
}
