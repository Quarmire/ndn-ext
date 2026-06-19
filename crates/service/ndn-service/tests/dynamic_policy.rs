//! Witness: v2 policy is **dynamic** — grant and revoke take effect on a live
//! authority, producing signed, versioned grant objects, with no restart.

use ndn_packet::Name;
use ndn_security::KeyChain;
use ndn_service::{PolicyAuthority, verify_grant};

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

#[tokio::test]
async fn grant_and_revoke_are_dynamic_without_restart() {
    // The authority is trust-rooted for its scope: its signing identity is the
    // scope, so its signature validates hierarchically for `<scope>/policy/…`.
    let kc = KeyChain::ephemeral("/muas/group").unwrap();
    let validator = kc.validator();
    let alice = n("/muas/alice");
    let bob = n("/muas/bob");

    let mut authority = PolicyAuthority::new(n("/muas/group"), kc.signer().unwrap());
    assert_eq!(authority.version(), 0, "fresh authority starts at version 0");

    // Grant alice, then bob — on the same live authority (no restart).
    let v1 = authority.grant(alice.clone(), "service:echo");
    let v2 = authority.grant(bob.clone(), "service:cam");
    assert!(v1 < v2, "each mutation bumps the policy version");

    // alice's signed grant validates against the authority anchor and carries
    // the granted policy, not revoked.
    let g = verify_grant(&validator, authority.signed_grant(&alice).unwrap())
        .await
        .expect("alice's grant must validate");
    assert_eq!(g.policy, "service:echo");
    assert!(!g.revoked);
    assert_eq!(g.version, v1);

    // Revoke alice at runtime — no restart. The freshly signed object now
    // reports revoked at a newer version.
    let v3 = authority.revoke(&alice);
    assert!(v3 > v2, "revocation bumps the version");
    let g = verify_grant(&validator, authority.signed_grant(&alice).unwrap())
        .await
        .expect("a revoked grant is still a validly signed object");
    assert!(g.revoked, "revocation is observable on the live authority");
    assert_eq!(g.version, v3);

    // bob is unaffected by alice's revocation.
    let g = verify_grant(&validator, authority.signed_grant(&bob).unwrap())
        .await
        .unwrap();
    assert!(!g.revoked);

    // A consumer that does not trust this authority rejects its grants (the
    // grant's authority is established by signature, not by name alone).
    let stranger = KeyChain::ephemeral("/elsewhere").unwrap();
    assert!(
        verify_grant(&stranger.validator(), authority.signed_grant(&bob).unwrap())
            .await
            .is_none(),
        "an untrusted authority's grant must fail closed"
    );

    // No grant for an unknown principal.
    assert!(authority.signed_grant(&n("/muas/ghost")).is_none());
}
