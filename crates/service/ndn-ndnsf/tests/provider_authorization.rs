#![cfg(feature = "driver")]
//! Gate (red-capable) for per-service **provider authorization** (SEC-05): a
//! trusted-but-unlisted group member's ACK must be refused before it can be
//! selected. Two providers serve `/svc/echo` in one group — `bob` (listed in the
//! policy) and `mallory` (a group member the policy does NOT list). A client with
//! the provider policy must gather only `bob` under `Strategy::All`; a client with
//! no policy gathers both — proving it is the enforcement, not timing, that
//! excludes `mallory`.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use ndn_ndnsf::{NdnsfCarrier, ServicePolicy};
use ndn_packet::Name;
use ndn_service_core::{
    Carrier, Dispatch, Invocation, OpId, SelectCarrier, ServiceError, ServiceId, Strategy,
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

/// Answers every op with a fixed provider tag, so selection is observable.
struct TagDispatch(&'static [u8]);
#[async_trait]
impl Dispatch for TagDispatch {
    async fn dispatch(&self, _inv: Invocation) -> Result<Bytes, ServiceError> {
        Ok(Bytes::from_static(self.0))
    }
}

/// The policy authorizes only `/muas/bob` to serve `echo`; `mallory` is a trusted
/// group member the policy omits.
const POLICY: &str = r#"
    [[providers]]
    identity = "/muas/bob"
    allowed_services = ["echo"]
"#;

/// Gather every tag a client selects under `Strategy::All`.
async fn tags(carrier: &NdnsfCarrier, svc: &ServiceId) -> Vec<String> {
    let resps = tokio::time::timeout(
        Duration::from_secs(10),
        carrier.invoke_select(svc, &OpId::new("echo"), Bytes::from_static(b"hi"), Strategy::All),
    )
    .await
    .expect("select did not complete")
    .expect("select failed");
    resps
        .into_iter()
        .map(|r| String::from_utf8_lossy(&r.payload).into_owned())
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unauthorized_provider_ack_is_refused() {
    let group = name("/muas");
    let svc = ServiceId::new(name("/svc/echo"));
    let mut pss = hub(
        &["/muas/bob", "/muas/mallory", "/muas/open", "/muas/auth"],
        &group,
    )
    .into_iter();
    let bob_ps = pss.next().unwrap();
    let mallory_ps = pss.next().unwrap();
    let open_ps = pss.next().unwrap();
    let auth_ps = pss.next().unwrap();

    // Both providers serve the same service in the group (insecure isolates the
    // authorization decision from signing, which trust_validated_four_phase covers).
    let bob = NdnsfCarrier::new(bob_ps, name("/muas/bob"), group.clone()).insecure();
    bob.serve(&svc, Arc::new(TagDispatch(b"bob"))).await.unwrap();
    let mallory = NdnsfCarrier::new(mallory_ps, name("/muas/mallory"), group.clone()).insecure();
    mallory
        .serve(&svc, Arc::new(TagDispatch(b"mallory")))
        .await
        .unwrap();

    // Control: a client with no provider policy gathers BOTH — mallory is live and
    // would be selected, so its later absence is enforcement, not timing.
    let open = NdnsfCarrier::new(open_ps, name("/muas/open"), group.clone())
        .insecure()
        .token("utok");
    let open_tags = tags(&open, &svc).await;
    assert!(
        open_tags.contains(&"bob".to_string()) && open_tags.contains(&"mallory".to_string()),
        "without a policy, both providers must respond: {open_tags:?}"
    );

    // Enforced: a client with the provider policy gathers ONLY bob — mallory's ACK
    // is refused before selection despite it being a group member.
    let policy = ServicePolicy::from_toml(POLICY).unwrap();
    let authed = NdnsfCarrier::new(auth_ps, name("/muas/auth"), group.clone())
        .insecure()
        .token("utok")
        .with_provider_policy(&policy);
    let authed_tags = tags(&authed, &svc).await;
    assert!(
        authed_tags.contains(&"bob".to_string()),
        "the authorized provider (bob) must still respond: {authed_tags:?}"
    );
    assert!(
        !authed_tags.contains(&"mallory".to_string()),
        "an unauthorized provider (mallory) must be refused: {authed_tags:?}"
    );

    drop(bob);
    drop(mallory);
}
