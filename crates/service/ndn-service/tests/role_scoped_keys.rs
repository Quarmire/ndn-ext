//! Witness: role-scoped keys. A role grants a set of scopes; a member is
//! provisioned with exactly those scope keys, so it can read only the topics in
//! those scopes. Here a Commander reads the `control` and `telemetry` scopes; an
//! Observer reads `telemetry` only and cannot even open a `control` topic.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_packet::Name;
use ndn_security::confidentiality::ContentKey;
use ndn_service::{RoleScopePolicy, ScopeKeyring, ScopedSession};
use ndn_service_core::framing::{encode_fields, read_field};
use ndn_service_core::{Frame, ServiceError};
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Role {
    Commander,
    Observer,
}

#[derive(Debug, PartialEq, Eq)]
struct Order {
    verb: String,
}
impl Frame for Order {
    fn encode(&self) -> Bytes {
        encode_fields(&[Frame::encode(&self.verb)])
    }
    fn decode(b: &[u8]) -> Result<Self, ServiceError> {
        let mut p = 0;
        Ok(Order { verb: String::decode(read_field(b, &mut p)?)? })
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Reading {
    celsius: u64,
}
impl Frame for Reading {
    fn encode(&self) -> Bytes {
        encode_fields(&[Frame::encode(&self.celsius)])
    }
    fn decode(b: &[u8]) -> Result<Self, ServiceError> {
        let mut p = 0;
        Ok(Reading { celsius: u64::decode(read_field(b, &mut p)?)? })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn roles_grant_scopes_and_gate_topics() {
    let group = n("/muas");
    let session = n("/muas/session/op-falcon");

    // The full set of scope keys, and the role→scope access policy.
    let all_keys = ScopeKeyring::new()
        .with("control", ContentKey::from_bytes([1u8; 32]))
        .with("telemetry", ContentKey::from_bytes([2u8; 32]));
    let policy = RoleScopePolicy::new()
        .grant(Role::Commander, "control")
        .grant(Role::Commander, "telemetry")
        .grant(Role::Observer, "telemetry");

    // Each member's keyring is derived from its role.
    let commander_kr = policy.keyring_for(&Role::Commander, &all_keys);
    let observer_kr = policy.keyring_for(&Role::Observer, &all_keys);
    let commander_scopes: HashSet<&str> = commander_kr.scopes().collect();
    let observer_scopes: HashSet<&str> = observer_kr.scopes().collect();
    assert_eq!(commander_scopes, HashSet::from(["control", "telemetry"]));
    assert_eq!(observer_scopes, HashSet::from(["telemetry"]));

    let mut pss = hub(&["/muas/alice", "/muas/bob", "/muas/carol"], &group).into_iter();
    let alice_ps = Arc::new(pss.next().unwrap()); // commander, publishes
    let bob_ps = Arc::new(pss.next().unwrap()); // observer
    let carol_ps = Arc::new(pss.next().unwrap()); // commander, reads control

    let alice = ScopedSession::new(session.clone(), alice_ps, commander_kr.clone());
    let bob = ScopedSession::new(session.clone(), bob_ps, observer_kr);
    let carol = ScopedSession::new(session, carol_ps, commander_kr);

    // Observer cannot even obtain a `control` topic — its role grants no key.
    assert!(
        bob.topic::<Order>("control", "orders").is_none(),
        "an observer must not access the control scope"
    );

    // Commander reader (carol) subscribes to control; observer (bob) to telemetry.
    let mut carol_control = carol.topic::<Order>("control", "orders").unwrap().subscribe().await;
    let mut bob_telemetry = bob.topic::<Reading>("telemetry", "temps").unwrap().subscribe().await;

    // Commander (alice) publishes into both scopes.
    alice.topic::<Order>("control", "orders").unwrap().publish(&Order { verb: "advance".into() }).await.unwrap();
    alice.topic::<Reading>("telemetry", "temps").unwrap().publish(&Reading { celsius: 21 }).await.unwrap();

    // A commander reads the control order; the observer reads telemetry.
    let order = tokio::time::timeout(Duration::from_secs(6), carol_control.recv())
        .await
        .expect("control recv timed out")
        .expect("session closed");
    assert_eq!(order, Order { verb: "advance".into() }, "a commander reads the control scope");

    let reading = tokio::time::timeout(Duration::from_secs(6), bob_telemetry.recv())
        .await
        .expect("telemetry recv timed out")
        .expect("session closed");
    assert_eq!(reading, Reading { celsius: 21 }, "an observer reads the telemetry scope");
}

#[test]
fn derived_scope_keys_are_distinct_and_deterministic() {
    // SEC-19: HKDF-derived scope keys are bound to their scope name — distinct
    // scopes get distinct keys (one scope's key cannot open another's), and the
    // derivation is deterministic for the same master.
    let master = [7u8; 32];
    let kr = ScopeKeyring::derive(&master, &["control", "telemetry"]);
    let control = kr.get("control").unwrap();
    let telemetry = kr.get("telemetry").unwrap();

    let aad = b"/sess/topic";
    let sealed = control.seal(b"secret", aad);
    assert!(
        telemetry.open(&sealed, aad).is_err(),
        "a different scope's key must not open it (SEC-19)"
    );
    assert_eq!(control.open(&sealed, aad).unwrap(), b"secret");

    // Same master + scope re-derives the same key.
    let kr2 = ScopeKeyring::derive(&master, &["control"]);
    let sealed2 = kr2.get("control").unwrap().seal(b"x", aad);
    assert_eq!(control.open(&sealed2, aad).unwrap(), b"x", "same master+scope -> same key");
}
