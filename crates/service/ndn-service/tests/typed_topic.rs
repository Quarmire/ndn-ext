//! Witness: `Topic<T>` is a typed feed — a publisher emits structured values and
//! a subscriber receives the decoded stream over an SVS group. This is the Tier-2
//! pub/sub primitive (the "feed", distinct from a service op's "call").

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_packet::Name;
use ndn_service::Topic;
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

/// Fully interconnect `nodes` over an in-memory hub.
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

/// A structured topic message — `T` need not be a scalar.
#[derive(Debug, PartialEq, Eq)]
struct Reading {
    sensor: String,
    celsius: u64,
}

impl Frame for Reading {
    fn encode(&self) -> Bytes {
        encode_fields(&[Frame::encode(&self.sensor), Frame::encode(&self.celsius)])
    }
    fn decode(bytes: &[u8]) -> Result<Self, ServiceError> {
        let mut pos = 0usize;
        Ok(Reading {
            sensor: String::decode(read_field(bytes, &mut pos)?)?,
            celsius: u64::decode(read_field(bytes, &mut pos)?)?,
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn typed_feed_delivers_published_values() {
    let group = n("/fleet");
    let topic_name = n("/fleet/telemetry");
    let mut pss = hub(&["/fleet/sensor", "/fleet/dash"], &group).into_iter();
    let pub_ps = Arc::new(pss.next().unwrap());
    let sub_ps = Arc::new(pss.next().unwrap());

    let publisher: Topic<Reading> = Topic::new(pub_ps, topic_name.clone());
    let subscriber: Topic<Reading> = Topic::new(sub_ps, topic_name);
    let mut feed = subscriber.subscribe().await;

    let sent = [
        Reading { sensor: "bow".into(), celsius: 21 },
        Reading { sensor: "stern".into(), celsius: 23 },
        Reading { sensor: "bow".into(), celsius: 22 },
    ];
    for r in &sent {
        publisher.publish(r).await.unwrap();
    }

    let mut got = Vec::new();
    for _ in 0..sent.len() {
        let r = tokio::time::timeout(Duration::from_secs(6), feed.recv())
            .await
            .expect("feed recv timed out")
            .expect("topic closed early");
        got.push(r);
    }

    // Every published reading was delivered, decoded into the typed struct.
    got.sort_by(|a, b| (a.celsius, &a.sensor).cmp(&(b.celsius, &b.sensor)));
    let mut want: Vec<Reading> = sent.into_iter().collect();
    want.sort_by(|a, b| (a.celsius, &a.sensor).cmp(&(b.celsius, &b.sensor)));
    assert_eq!(got, want, "the typed feed must deliver every published value, decoded");
}
