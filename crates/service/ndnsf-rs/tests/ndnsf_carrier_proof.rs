#![cfg(feature = "driver")]
//! Proof that the service seam (service-layer §12) is **transport-independent**:
//! the same hand-written `#[ndn_service]`-shaped Echo service that runs over
//! Tier-0 `RpcCarrier` (see `ndn-rpc/tests/carrier_proof.rs`) runs here over the
//! NDNSF four-phase `NdnsfCarrier` — unchanged. Because the four-phase reaches
//! many providers, this also exercises `SelectCarrier`: the client's
//! `echo_select` method is gated `where C: SelectCarrier` (compile-time
//! depth-as-needed) and gathers every provider under `Strategy::All`.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use ndnsf_rs::NdnsfCarrier;
use ndn_packet::Name;
use ndn_service_core::{
    Carrier, Dispatch, Frame, Invocation, OpId, SelectCarrier, ServiceError, ServiceId, Strategy,
};
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

/// Fully interconnect `nodes` over an in-memory hub: each node's outbound is
/// broadcast to every other node's inbound. Returns one `SvsPubSub` per node.
fn hub(nodes: &[&str], group: &Name) -> Vec<SvsPubSub> {
    let mut outs = Vec::new();
    let mut ins = Vec::new();
    let mut pubsubs = Vec::new();
    for n in nodes {
        let (out_tx, out_rx) = mpsc::channel::<Bytes>(256);
        let (in_tx, in_rx) = mpsc::channel::<Bytes>(256);
        pubsubs.push(SvsPubSub::join(
            group.clone(),
            name(n),
            out_tx,
            in_rx,
            cfg(),
        ));
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

// --- the macro's output shape (same as the RpcCarrier proof) ---

struct EchoReq {
    msg: String,
}
struct EchoResp {
    text: String,
}
impl Frame for EchoReq {
    fn encode(&self) -> Bytes {
        Bytes::copy_from_slice(self.msg.as_bytes())
    }
    fn decode(bytes: &[u8]) -> Result<Self, ServiceError> {
        Ok(EchoReq {
            msg: String::from_utf8(bytes.to_vec())
                .map_err(|e| ServiceError::Decode(e.to_string()))?,
        })
    }
}
impl Frame for EchoResp {
    fn encode(&self) -> Bytes {
        Bytes::copy_from_slice(self.text.as_bytes())
    }
    fn decode(bytes: &[u8]) -> Result<Self, ServiceError> {
        Ok(EchoResp {
            text: String::from_utf8(bytes.to_vec())
                .map_err(|e| ServiceError::Decode(e.to_string()))?,
        })
    }
}

#[async_trait]
trait EchoService: Send + Sync + 'static {
    async fn echo(&self, msg: String) -> String;
}

/// Tags its reply so multi-provider selection is observable.
struct EchoImpl {
    tag: String,
}
#[async_trait]
impl EchoService for EchoImpl {
    async fn echo(&self, msg: String) -> String {
        format!("{}:{}", self.tag, msg)
    }
}

struct EchoDispatch<S: EchoService>(Arc<S>);
#[async_trait]
impl<S: EchoService> Dispatch for EchoDispatch<S> {
    async fn dispatch(&self, inv: Invocation) -> Result<Bytes, ServiceError> {
        match inv.op.as_str() {
            "echo" => {
                let req = EchoReq::decode(&inv.request)?;
                Ok(EchoResp {
                    text: self.0.echo(req.msg).await,
                }
                .encode())
            }
            _ => Err(ServiceError::NotFound),
        }
    }
}

struct EchoClient<C: Carrier> {
    carrier: C,
    svc: ServiceId,
}
impl<C: Carrier> EchoClient<C> {
    async fn echo(&self, msg: String) -> Result<String, ServiceError> {
        let resp = self
            .carrier
            .invoke(&self.svc, &OpId::new("echo"), EchoReq { msg }.encode())
            .await?;
        Ok(EchoResp::decode(&resp.payload)?.text)
    }

    /// Available only when the carrier reaches many providers.
    async fn echo_select(
        &self,
        msg: String,
        strategy: Strategy,
    ) -> Result<Vec<(Name, String)>, ServiceError>
    where
        C: SelectCarrier,
    {
        let resps = self
            .carrier
            .invoke_select(
                &self.svc,
                &OpId::new("echo"),
                EchoReq { msg }.encode(),
                strategy,
            )
            .await?;
        resps
            .into_iter()
            .map(|r| EchoResp::decode(&r.payload).map(|d| (r.producer, d.text)))
            .collect()
    }
}

fn dispatch_for(tag: &str) -> Arc<dyn Dispatch> {
    Arc::new(EchoDispatch(Arc::new(EchoImpl { tag: tag.into() })))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn echo_round_trips_over_ndnsf_carrier() {
    let group = name("/muas");
    let svc = ServiceId::new(name("/svc/echo"));
    let mut pss = hub(&["/muas/bob", "/muas/alice"], &group).into_iter();
    let bob_ps = pss.next().unwrap();
    let alice_ps = pss.next().unwrap();

    let bob = NdnsfCarrier::new(bob_ps, name("/muas/bob"), group.clone()).insecure();
    bob.serve(&svc, dispatch_for("bob")).await.unwrap();

    let alice = NdnsfCarrier::new(alice_ps, name("/muas/alice"), group.clone())
        .insecure()
        .token("utok");
    let client = EchoClient {
        carrier: alice,
        svc: svc.clone(),
    };

    let reply = tokio::time::timeout(Duration::from_secs(10), client.echo("ping".into()))
        .await
        .expect("call did not complete")
        .expect("echo failed");
    assert_eq!(
        reply, "bob:ping",
        "the same service definition must round-trip over the four-phase carrier"
    );

    drop(bob);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invoke_select_all_gathers_every_provider() {
    let group = name("/muas");
    let svc = ServiceId::new(name("/svc/echo"));
    let mut pss = hub(&["/muas/bob", "/muas/carol", "/muas/alice"], &group).into_iter();
    let bob_ps = pss.next().unwrap();
    let carol_ps = pss.next().unwrap();
    let alice_ps = pss.next().unwrap();

    let bob = NdnsfCarrier::new(bob_ps, name("/muas/bob"), group.clone()).insecure();
    bob.serve(&svc, dispatch_for("bob")).await.unwrap();
    let carol = NdnsfCarrier::new(carol_ps, name("/muas/carol"), group.clone()).insecure();
    carol.serve(&svc, dispatch_for("carol")).await.unwrap();

    let alice = NdnsfCarrier::new(alice_ps, name("/muas/alice"), group.clone())
        .insecure()
        .token("utok");
    let client = EchoClient {
        carrier: alice,
        svc,
    };

    let resps = tokio::time::timeout(
        Duration::from_secs(10),
        client.echo_select("hi".into(), Strategy::All),
    )
    .await
    .expect("select did not complete")
    .expect("select failed");
    let texts: HashSet<String> = resps.into_iter().map(|(_, t)| t).collect();
    assert!(
        texts.contains("bob:hi"),
        "bob must respond under All: {texts:?}"
    );
    assert!(
        texts.contains("carol:hi"),
        "carol must respond under All: {texts:?}"
    );

    drop(bob);
    drop(carol);
}
