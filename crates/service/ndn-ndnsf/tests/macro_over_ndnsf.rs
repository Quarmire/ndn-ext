#![cfg(feature = "driver")]
//! The end-to-end payoff: a `#[ndn_service]`-defined service runs over the
//! four-phase `NdnsfCarrier` unchanged, and the macro-generated `*_select` method
//! (gated `where C: SelectCarrier`) gathers every provider under `Strategy::All`.
//! Same macro, same definition, a different carrier than `ndn-rpc`'s macro test.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_ndnsf::NdnsfCarrier;
use ndn_packet::Name;
use ndn_service_core::{Carrier, ServiceId, Strategy};
use ndn_service_macro::ndn_service;
use ndn_sync::{SvSyncConfig, SvsConfig, SvsPubSub};
use tokio::sync::mpsc;

fn name(s: &str) -> Name {
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
    for n in nodes {
        let (out_tx, out_rx) = mpsc::channel::<Bytes>(256);
        let (in_tx, in_rx) = mpsc::channel::<Bytes>(256);
        pubsubs.push(SvsPubSub::join(group.clone(), name(n), out_tx, in_rx, cfg()));
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

#[ndn_service]
trait Greeter {
    async fn greet(&self, who: String) -> String;
}

struct GreeterImpl {
    tag: String,
}
impl Greeter for GreeterImpl {
    async fn greet(&self, who: String) -> String {
        format!("{}:hello {who}", self.tag)
    }
}

fn greeter(tag: &str) -> Arc<GreeterDispatch<GreeterImpl>> {
    Arc::new(GreeterDispatch(Arc::new(GreeterImpl { tag: tag.into() })))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn macro_service_over_ndnsf_and_select() {
    let group = name("/muas");
    let svc = ServiceId::new(name("/svc/greet"));
    let mut pss = hub(&["/muas/bob", "/muas/carol", "/muas/alice"], &group).into_iter();
    let bob_ps = pss.next().unwrap();
    let carol_ps = pss.next().unwrap();
    let alice_ps = pss.next().unwrap();

    let bob = NdnsfCarrier::new(bob_ps, name("/muas/bob"), group.clone()).insecure();
    bob.serve(&svc, greeter("bob")).await.unwrap();
    let carol = NdnsfCarrier::new(carol_ps, name("/muas/carol"), group.clone()).insecure();
    carol.serve(&svc, greeter("carol")).await.unwrap();

    let alice = NdnsfCarrier::new(alice_ps, name("/muas/alice"), group.clone()).insecure().token("utok");
    let client = GreeterClient::new(alice, svc);

    // Unary (FirstResponding) — one provider answers.
    let one = tokio::time::timeout(Duration::from_secs(10), client.greet("ada".into()))
        .await
        .expect("greet timed out")
        .expect("greet failed");
    assert!(one.ends_with("hello ada"), "unexpected unary reply: {one}");

    // Generated `greet_select` (where C: SelectCarrier) gathers both providers.
    let many = tokio::time::timeout(
        Duration::from_secs(10),
        client.greet_select("ada".into(), Strategy::All),
    )
    .await
    .expect("greet_select timed out")
    .expect("greet_select failed");
    let texts: HashSet<String> = many.into_iter().map(|(_, t)| t).collect();
    assert!(texts.contains("bob:hello ada"), "bob missing: {texts:?}");
    assert!(texts.contains("carol:hello ada"), "carol missing: {texts:?}");

    drop(bob);
    drop(carol);
}
