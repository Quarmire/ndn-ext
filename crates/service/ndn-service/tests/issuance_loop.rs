#![cfg(feature = "issuance")]
//! The policy→issuance loop: the v2 `PolicyAuthority` (source of truth) gates
//! KP-ABE key issuance by the `KpAuthority` (key authority). A granted principal
//! receives a real key that decrypts content under its policy; a revoked one
//! receives nothing — reflecting the live policy with no restart.

use ndn_foundation_types::Hash;
use ndn_nacabe::{KpAuthority, open_kp, open_kp_dkey, seal_kp};
use ndn_packet::Name;
use ndn_sealed_box::Recipient;
use ndn_security::KeyChain;
use ndn_security::abe::lsw_setup;
use ndn_service::{IssueError, PolicyAuthority, issue_decryption_key};

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

#[test]
fn policy_gates_issuance_live() {
    let (mp, ms) = lsw_setup().unwrap();
    let kp = KpAuthority::new(mp.clone(), ms);

    // The policy authority is trust-rooted for its scope.
    let kc = KeyChain::ephemeral("/muas/group").unwrap();
    let mut policy = PolicyAuthority::new(n("/muas/group"), kc.signer().unwrap());
    let alice = n("/muas/alice");

    // 1. No grant → issuance fails closed.
    let r0 = Recipient::generate().unwrap();
    assert!(
        matches!(
            issue_decryption_key(&policy, &kp, &alice, &r0.public),
            Err(IssueError::Unauthorized)
        ),
        "an ungranted principal must get no key"
    );

    // 2. Grant alice → a real key issues that decrypts content under its policy.
    policy.grant(alice.clone(), "service:echo OR service:cam");
    let r1 = Recipient::generate().unwrap();
    let r1_pub = r1.public;
    let sealed = issue_decryption_key(&policy, &kp, &alice, &r1_pub).expect("granted → key issued");
    let key = open_kp_dkey(r1, &sealed).expect("the sealed dkey opens to a real policy key");

    let kgc = (n("/muas/group"), Hash::of(&mp.public_key_bytes), mp.clone());
    let (ck, ct) = seal_kp(n("/c/CK/1"), &["service:echo".into()], &kgc, b"intel", b"/aad").unwrap();
    assert_eq!(
        open_kp(&ck, &key, &ct, b"/aad").unwrap(),
        b"intel",
        "the issued key must actually decrypt content its policy satisfies"
    );

    // 3. Revoke alice on the live authority (no restart) → issuance fails closed.
    policy.revoke(&alice);
    let r2 = Recipient::generate().unwrap();
    assert!(
        matches!(
            issue_decryption_key(&policy, &kp, &alice, &r2.public),
            Err(IssueError::Revoked)
        ),
        "after a live revoke, the same authority issues no key — no restart"
    );
}
