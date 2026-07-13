//! The same weather domain as `ndnsf-rs`'s example, but over the **v2** layer —
//! showing what v2 adds beyond a plain call:
//!
//! 1. **Discovery** (Tier-1): the client doesn't know the stations; it *discovers*
//!    the service and selects among providers (vs Tier-0's known provider, or
//!    NDNSF's group broadcast).
//! 2. **Feed** (`Topic<T>`): weather is naturally a stream — a sensor *publishes*
//!    observations, a dashboard *subscribes*. A feed, not a call.
//! 3. **Confidential collaboration** (`ScopedSession` + role-scoped keys): a
//!    premium forecast channel only members with the scope key can read.
//!
//! Run: `cargo run -p ndn-service --example weather`

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_packet::Name;
use ndn_rpc::{RpcCarrier, RpcRegistry};
use ndn_security::confidentiality::ContentKey;
use ndn_service::{
    DiscoveryCarrier, MemoryDirectory, RoleScopePolicy, ScopeKeyring, ScopedSession, Topic,
};
use ndn_service_core::{Carrier, ServiceId, Strategy};
use ndn_service_macro::{Frame, ndn_service};
use ndn_sync::{SvSyncConfig, SvsConfig, SvsPubSub};
use tokio::sync::mpsc;

// --- The service + message types (same domain as the ndnsf-rs example). ---

#[derive(Frame, Debug, Clone)]
struct Forecast {
    city: String,
    day: u32,
    high_c: i32,
    low_c: i32,
    summary: String,
}

#[derive(Frame, Debug, Clone)]
struct Observation {
    city: String,
    temp_c: i32,
}

#[ndn_service]
trait Weather {
    async fn forecast(&self, city: String, day: u32) -> Forecast;
}

struct Station {
    name: String,
    bias_c: i32,
}
impl Weather for Station {
    async fn forecast(&self, city: String, day: u32) -> Forecast {
        let base = 18 + (city.len() as i32 % 8) + day as i32;
        Forecast {
            city,
            day,
            high_c: base + self.bias_c + 3,
            low_c: base + self.bias_c - 4,
            summary: format!("{}: partly cloudy", self.name),
        }
    }
}

fn station(name: &str, bias_c: i32) -> Arc<WeatherDispatch<Station>> {
    Arc::new(WeatherDispatch(Arc::new(Station {
        name: name.into(),
        bias_c,
    })))
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Role {
    Premium,
    Free,
}

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    discovery().await;
    println!();
    feed().await;
    println!();
    confidential().await;
}

/// Tier-1: the client discovers the service (it was given no provider) and selects.
async fn discovery() {
    println!("== v2 Tier-1 (DiscoveryCarrier): discover the service, then call ==");
    let registry = Arc::new(RpcRegistry::new());
    let dir = Arc::new(MemoryDirectory::new());
    let svc = ServiceId::new(n("/weather"));

    // Two stations advertise + serve over a shared Tier-0 carrier (in-process here;
    // a real deployment uses ServiceDiscoveryDirectory over a forwarder).
    let s1 = DiscoveryCarrier::new(
        dir.clone(),
        RpcCarrier::with_registry(registry.clone()),
        n("/met/s1"),
    );
    s1.serve(&svc, station("station-1", 0)).await.unwrap();
    let s2 = DiscoveryCarrier::new(
        dir.clone(),
        RpcCarrier::with_registry(registry.clone()),
        n("/met/s2"),
    );
    s2.serve(&svc, station("station-2", 2)).await.unwrap();

    // The client knows only the *service* name — discovery finds the providers.
    let app = DiscoveryCarrier::new(dir, RpcCarrier::with_registry(registry), n("/met/app"));
    let client = WeatherClient::new(app, svc);

    let f = client.forecast("Berlin".into(), 1).await.unwrap();
    println!(
        "  discovered + forecast(Berlin, 1) -> high {}C  [{}]",
        f.high_c, f.summary
    );

    let all = client
        .forecast_select("Berlin".into(), 1, Strategy::All)
        .await
        .unwrap();
    println!("  forecast_select(All) across discovered stations:");
    for (provider, fc) in all {
        println!("    {provider} -> high {}C  [{}]", fc.high_c, fc.summary);
    }
}

/// Tier-2: a feed — a sensor publishes observations, a dashboard subscribes.
async fn feed() {
    println!("== v2 Tier-2 (Topic<T>): a live observation FEED (not a call) ==");
    let group = n("/met");
    let mut pss = hub(&["/met/sensor", "/met/dash"], &group).into_iter();
    let sensor_ps = Arc::new(pss.next().unwrap());
    let dash_ps = Arc::new(pss.next().unwrap());
    let topic = n("/met/observations");

    let sensor: Topic<Observation> = Topic::new(sensor_ps, topic.clone());
    let dashboard: Topic<Observation> = Topic::new(dash_ps, topic);
    let mut feed = dashboard.subscribe().await;

    for temp_c in [19, 20, 21] {
        sensor
            .publish(&Observation {
                city: "Berlin".into(),
                temp_c,
            })
            .await
            .unwrap();
    }

    println!("  dashboard receives the stream:");
    for _ in 0..3 {
        let o = tokio::time::timeout(Duration::from_secs(6), feed.recv())
            .await
            .expect("feed timed out")
            .expect("topic closed");
        println!("    {} = {}C", o.city, o.temp_c);
    }
}

/// Tier-2: a confidential premium channel, gated by a role-scoped key.
async fn confidential() {
    println!("== v2 Tier-2 (ScopedSession + role-scoped keys): a PREMIUM channel ==");
    let group = n("/met");
    let session = n("/met/session/premium");

    // Only the Premium role is granted the `premium` scope key.
    let all_keys = ScopeKeyring::new().with("premium", ContentKey::from_bytes([42u8; 32]));
    let policy = RoleScopePolicy::new().grant(Role::Premium, "premium");
    let member_kr = policy.keyring_for(&Role::Premium, &all_keys);
    let outsider_kr = policy.keyring_for(&Role::Free, &all_keys); // empty

    let mut pss = hub(&["/met/forecaster", "/met/member", "/met/outsider"], &group).into_iter();
    let forecaster = ScopedSession::new(
        session.clone(),
        Arc::new(pss.next().unwrap()),
        member_kr.clone(),
    );
    let member = ScopedSession::new(session.clone(), Arc::new(pss.next().unwrap()), member_kr);
    let outsider = ScopedSession::new(session, Arc::new(pss.next().unwrap()), outsider_kr);

    // An outsider cannot even obtain the premium topic (no scope key).
    println!(
        "  outsider can access the premium channel: {}",
        outsider.topic::<Forecast>("premium", "forecasts").is_some()
    );

    let mut member_feed = member
        .topic::<Forecast>("premium", "forecasts")
        .expect("member has the premium scope")
        .subscribe()
        .await;

    forecaster
        .topic::<Forecast>("premium", "forecasts")
        .expect("forecaster has the premium scope")
        .publish(&Forecast {
            city: "Berlin".into(),
            day: 1,
            high_c: 31,
            low_c: 22,
            summary: "premium model: clear skies".into(),
        })
        .await
        .unwrap();

    let f = tokio::time::timeout(Duration::from_secs(6), member_feed.recv())
        .await
        .expect("premium recv timed out")
        .expect("session closed");
    println!(
        "  member reads the premium forecast: high {}C  [{}]",
        f.high_c, f.summary
    );
}

// --- A tiny in-memory SVS medium so the example runs without a forwarder. ---

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
        pubsubs.push(SvsPubSub::join(
            group.clone(),
            n(node),
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
