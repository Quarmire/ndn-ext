//! Witness: the signed command front-end drives the live `PolicyAuthority`. An
//! authorized operator's signed grant/revoke command takes effect (version bump,
//! new signed grant returned) with no restart; an unauthorized command fails
//! closed and does not mutate policy.

use std::sync::Arc;

use ndn_packet::Name;
use ndn_security::KeyChain;
use ndn_service::{PolicyAuthority, PolicyController, grant_command, revoke_command, verify_grant};

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

#[tokio::test]
async fn signed_grant_and_revoke_commands_drive_the_live_authority() {
    // The authority is self-administered: its scope key is the admin operator.
    let admin = KeyChain::ephemeral("/muas/group").unwrap();
    let authority = PolicyAuthority::new(n("/muas/group"), admin.signer().unwrap());
    let mut controller =
        PolicyController::new(authority, Arc::new(admin.validator()), n("/muas/group"));
    let alice = n("/muas/alice");

    // A signed grant command is accepted; the response is the new signed grant.
    let cmd = grant_command(&n("/muas/group"), &*admin.signer().unwrap(), &alice, "service:echo", 1)
        .unwrap();
    let resp = controller.handle(cmd).await.expect("authorized grant accepted");
    let g = verify_grant(&admin.validator(), resp).await.expect("response is a valid signed grant");
    assert_eq!(g.policy, "service:echo");
    assert!(!g.revoked);
    assert_eq!(controller.authority().version(), 1, "the grant bumped the version live");

    // A signed revoke command takes effect on the same running controller.
    let cmd = revoke_command(&n("/muas/group"), &*admin.signer().unwrap(), &alice, 2).unwrap();
    let resp = controller.handle(cmd).await.expect("authorized revoke accepted");
    let g = verify_grant(&admin.validator(), resp).await.unwrap();
    assert!(g.revoked, "revoke command takes effect without restart");
    assert_eq!(controller.authority().version(), 2);

    // An unauthorized command (signed by a stranger the admin validator does not
    // trust, and not under the admin prefix) fails closed — and mutates nothing.
    let evil = KeyChain::ephemeral("/evil").unwrap();
    let cmd = grant_command(&n("/muas/group"), &*evil.signer().unwrap(), &n("/muas/mallory"), "service:all", 3)
        .unwrap();
    assert!(
        controller.handle(cmd).await.is_none(),
        "an unauthorized command must be rejected"
    );
    assert_eq!(
        controller.authority().version(),
        2,
        "a rejected command must not mutate policy"
    );
    assert!(
        controller.authority().grant_state(&n("/muas/mallory")).is_none(),
        "the rejected grant must not have been applied"
    );
}

#[tokio::test]
async fn replayed_command_is_rejected() {
    // SEC-09: a captured signed command cannot be replayed to undo a later mutation.
    let admin = KeyChain::ephemeral("/muas/group").unwrap();
    let authority = PolicyAuthority::new(n("/muas/group"), admin.signer().unwrap());
    let mut controller =
        PolicyController::new(authority, Arc::new(admin.validator()), n("/muas/group"));
    let alice = n("/muas/alice");

    // Operator grants alice at seq=100, then revokes at seq=200 (per-operator
    // monotonic sequence numbers — not clocks).
    let grant =
        grant_command(&n("/muas/group"), &*admin.signer().unwrap(), &alice, "service:echo", 100).unwrap();
    assert!(controller.handle(grant.clone()).await.is_some(), "grant at seq=100 accepted");
    let revoke = revoke_command(&n("/muas/group"), &*admin.signer().unwrap(), &alice, 200).unwrap();
    assert!(controller.handle(revoke).await.is_some(), "revoke at seq=200 accepted");
    assert!(controller.authority().grant_state(&alice).unwrap().revoked);

    // An attacker replays the captured seq=100 grant to resurrect alice — rejected,
    // and policy is unchanged (still revoked).
    assert!(
        controller.handle(grant).await.is_none(),
        "a replayed (stale-sequence) command must be rejected"
    );
    assert!(
        controller.authority().grant_state(&alice).unwrap().revoked,
        "replay must not resurrect the grant"
    );
}
