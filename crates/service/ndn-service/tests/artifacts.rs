//! Witness: artifact provisioning. A member provisions a named confidential
//! object in a session scope; another member with the scope fetches and opens it.
//! A node lacking the scope key cannot obtain the artifact share at all (the role
//! gate), and a larger artifact rides SvsPubSub's segmentation.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_packet::Name;
use ndn_security::confidentiality::ContentKey;
use ndn_service::{RoleScopePolicy, ScopeKeyring, ScopedSession};
use ndn_sync::{SvSyncConfig, SvsConfig, SvsPubSub};
use tokio::sync::mpsc;

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

fn cfg() -> SvSyncConfig {
    SvSyncConfig {
        svs: SvsConfig {
            sync_interval: Duration::from_millis(50),
            jitter_ms: 0,
            ..Default::default()
        },
        ..Default::default()
    }
}

fn hub(nodes: &[&str], group: &Name) -> Vec<SvsPubSub> {
    let mut outs = Vec::new();
    let mut ins = Vec::new();
    let mut pubsubs = Vec::new();
    for node in nodes {
        let (out_tx, out_rx) = mpsc::channel::<Bytes>(256);
        let (in_tx, in_rx) = mpsc::channel::<Bytes>(256);
        pubsubs.push(SvsPubSub::join(group.clone(), n(node), out_tx, in_rx, cfg()));
        outs.push(out_rx);
        ins.push(in_tx);
    }
    let ins = Arc::new(ins);
    for (i, mut out_rx) in outs.into_iter().enumerate() {
        let ins = ins.clone();
        tokio::spawn(async move {
            while let Some(msg) = out_rx.recv().await {
                for (j, tx) in ins.iter().enumerate() {
                    if j != i {
                        let _ = tx.send(msg.clone()).await;
                    }
                }
            }
        });
    }
    pubsubs
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Role {
    Member,
    Outsider,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn artifact_provision_and_fetch_is_scope_confidential() {
    let group = n("/muas");
    let session = n("/muas/session/op-falcon");

    let all = ScopeKeyring::new().with("plans", ContentKey::from_bytes([9u8; 32]));
    let policy = RoleScopePolicy::new().grant(Role::Member, "plans");
    let member_kr = policy.keyring_for(&Role::Member, &all);
    let outsider_kr = policy.keyring_for(&Role::Outsider, &all); // empty

    let mut pss = hub(&["/muas/alice", "/muas/bob"], &group).into_iter();
    let alice = ScopedSession::new(session.clone(), Arc::new(pss.next().unwrap()), member_kr.clone());
    let bob = ScopedSession::new(session.clone(), Arc::new(pss.next().unwrap()), member_kr);

    // A subscriber must exist before the one-shot artifact is published.
    let bob_artifacts = bob.artifacts("plans").expect("member has the plans scope");
    let fetch = tokio::spawn(async move { bob_artifacts.fetch("mission").await });

    // Give the subscription a moment to register, then provision.
    tokio::time::sleep(Duration::from_millis(200)).await;
    // A few KB exercises SvsPubSub segmentation.
    let content = vec![0xABu8; 4096];
    alice
        .artifacts("plans")
        .expect("member has the plans scope")
        .provision("mission", &content)
        .await
        .unwrap();

    let got = tokio::time::timeout(Duration::from_secs(8), fetch)
        .await
        .expect("fetch timed out")
        .expect("join")
        .expect("artifact not delivered");
    assert_eq!(got.as_ref(), content.as_slice(), "member fetches and opens the artifact");

    // An outsider (no scope key) cannot even obtain the artifact share.
    let outsider = ScopedSession::new(session, Arc::new(SvsPubSub::join(
        group,
        n("/muas/mallory"),
        mpsc::channel(8).0,
        mpsc::channel(8).1,
        cfg(),
    )), outsider_kr);
    assert!(
        outsider.artifacts("plans").is_none(),
        "a node without the scope key cannot access the artifact share"
    );
}
