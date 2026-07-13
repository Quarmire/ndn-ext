#![cfg(feature = "driver")]
//! Gate: the carrier-uniform **metadata slot** rides intact through the NDNSF
//! four-phase carrier. A client sets an opaque slot (a W3C trace context) on the
//! invocation; it must (a) arrive at the **peer** on `Invocation::metadata`
//! (across REQUEST→ACK→SELECTION→RESPONSE, beside the op envelope) and (b) come
//! back **intact** on the returned `Response::metadata`. Red-capable: a four-phase
//! carrier that dropped or mangled the slot would fail these assertions.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use ndnsf_rs::NdnsfCarrier;
use ndn_packet::Name;
use ndn_service_core::{Carrier, Dispatch, Invocation, Metadata, OpId, ServiceError, ServiceId};
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

/// Fully interconnect `nodes` over an in-memory hub (each node's outbound is
/// broadcast to every other node's inbound).
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

fn trace_context() -> Metadata {
    let mut m = Metadata::new();
    m.insert(
        "traceparent".into(),
        Bytes::from_static(b"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
    );
    m.insert("tracestate".into(), Bytes::from_static(b"congo=t61rcWkgMzE"));
    m
}

/// Records the metadata the peer saw; never touches the response slot.
struct CaptureDispatch(Arc<Mutex<Option<Metadata>>>);
#[async_trait]
impl Dispatch for CaptureDispatch {
    async fn dispatch(&self, inv: Invocation) -> Result<Bytes, ServiceError> {
        *self.0.lock().unwrap() = Some(inv.metadata.clone());
        Ok(Bytes::from_static(b"pong"))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn metadata_round_trips_over_ndnsf_carrier() {
    let group = name("/muas");
    let svc = ServiceId::new(name("/svc/trace"));
    let mut pss = hub(&["/muas/bob", "/muas/alice"], &group).into_iter();
    let bob_ps = pss.next().unwrap();
    let alice_ps = pss.next().unwrap();

    let seen = Arc::new(Mutex::new(None));
    let bob = NdnsfCarrier::new(bob_ps, name("/muas/bob"), group.clone()).insecure();
    bob.serve(&svc, Arc::new(CaptureDispatch(seen.clone())))
        .await
        .unwrap();

    let alice = NdnsfCarrier::new(alice_ps, name("/muas/alice"), group.clone())
        .insecure()
        .token("utok");

    let ctx = trace_context();
    let resp = tokio::time::timeout(
        Duration::from_secs(10),
        alice.invoke_meta(&svc, &OpId::new("op"), Bytes::new(), ctx.clone()),
    )
    .await
    .expect("call did not complete")
    .expect("call failed");

    assert_eq!(resp.payload, Bytes::from_static(b"pong"));
    // (a) the peer received the slot verbatim across the four phases.
    assert_eq!(
        seen.lock().unwrap().as_ref(),
        Some(&ctx),
        "the trace context must arrive at the provider on Invocation::metadata"
    );
    // (b) it round-trips intact on the four-phase RESPONSE.
    assert_eq!(
        resp.metadata, ctx,
        "the trace context must come back intact on Response::metadata"
    );

    drop(bob);
}
