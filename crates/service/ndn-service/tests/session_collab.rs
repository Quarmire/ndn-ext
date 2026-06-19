//! Witness: Tier-2 collaboration. Two session members sharing a scope key exchange
//! a confidential typed feed; a non-member (same topic name, no scope key) gets
//! the sealed bytes but no plaintext. Roles are typed (an enum, not a string).

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_packet::Name;
use ndn_security::confidentiality::ContentKey;
use ndn_service::Session;
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

/// Typed roles — an enum, not a string key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    Commander,
    Observer,
}

#[derive(Debug, PartialEq, Eq)]
struct Order {
    verb: String,
    target: u64,
}
impl Frame for Order {
    fn encode(&self) -> Bytes {
        encode_fields(&[Frame::encode(&self.verb), Frame::encode(&self.target)])
    }
    fn decode(bytes: &[u8]) -> Result<Self, ServiceError> {
        let mut pos = 0usize;
        Ok(Order {
            verb: String::decode(read_field(bytes, &mut pos)?)?,
            target: u64::decode(read_field(bytes, &mut pos)?)?,
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_feed_is_confidential_to_members() {
    let group = n("/muas");
    let session_name = n("/muas/session/op-falcon");

    // Members share a scope key; the outsider has a different key.
    let scope_key_bytes = [7u8; 32];
    let mut pss = hub(&["/muas/alice", "/muas/bob", "/muas/mallory"], &group).into_iter();
    let alice_ps = Arc::new(pss.next().unwrap());
    let bob_ps = Arc::new(pss.next().unwrap());
    let mallory_ps = Arc::new(pss.next().unwrap());

    let mut alice: Session<Role> =
        Session::new(session_name.clone(), alice_ps, ContentKey::from_bytes(scope_key_bytes));
    alice.admit(n("/muas/alice"), Role::Commander);
    alice.admit(n("/muas/bob"), Role::Observer);

    let bob: Session<Role> =
        Session::new(session_name.clone(), bob_ps, ContentKey::from_bytes(scope_key_bytes));

    // Mallory is NOT a member — a different scope key.
    let mallory: Session<Role> =
        Session::new(session_name, mallory_ps, ContentKey::from_bytes([0u8; 32]));

    // Typed roles are queryable.
    assert_eq!(alice.role_of(&n("/muas/alice")), Some(&Role::Commander));
    assert_eq!(alice.role_of(&n("/muas/bob")), Some(&Role::Observer));
    assert_eq!(alice.role_of(&n("/muas/eve")), None);

    let orders = alice.scoped_topic::<Order>("orders");
    let mut bob_feed = bob.scoped_topic::<Order>("orders").subscribe().await;
    let mut mallory_feed = mallory.scoped_topic::<Order>("orders").subscribe().await;

    let order = Order { verb: "advance".into(), target: 12 };
    orders.publish(&order).await.unwrap();

    // A member with the scope key reads the order in the clear.
    let got = tokio::time::timeout(Duration::from_secs(6), bob_feed.recv())
        .await
        .expect("member recv timed out")
        .expect("session closed");
    assert_eq!(got, order, "a member must read the confidential feed");

    // A non-member receives the sealed bytes but no plaintext — recv yields
    // nothing within the window (its key cannot open the order).
    let mallory_got = tokio::time::timeout(Duration::from_secs(2), mallory_feed.recv()).await;
    assert!(
        mallory_got.is_err(),
        "a non-member must not read the session feed (no scope key)"
    );
}
