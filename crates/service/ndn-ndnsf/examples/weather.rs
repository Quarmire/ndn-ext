//! A small weather service — the same `#[ndn_service]` definition run two ways:
//! a direct **Tier-0** call (one Interest → Data) and the **NDNSF four-phase**
//! (REQUEST → ACK → SELECTION → RESPONSE, with multi-provider selection). It
//! shows a *parameterized request* (`city`, `day`) and a *structured response*
//! (`Forecast`), proving the typed surface fits both carriers unchanged.
//!
//! Run: `cargo run -p ndn-ndnsf --example weather --features driver`

use std::sync::Arc;

use bytes::Bytes;
use ndn_ndnsf::NdnsfCarrier;
use ndn_packet::Name;
use ndn_rpc::RpcCarrier;
use ndn_service_core::{Carrier, ServiceId, Strategy};
use ndn_service_macro::{Frame, ndn_service};
use ndn_sync::{SvSyncConfig, SvsConfig, SvsPubSub};
use tokio::sync::mpsc;

// --- The service definition: a parameterized request, a structured response. ---

/// A structured response — `#[derive(Frame)]` makes typed data ergonomic.
#[derive(Frame, Debug, Clone)]
struct Forecast {
    city: String,
    day: u32,
    high_c: i32,
    low_c: i32,
    summary: String,
}

#[ndn_service]
trait Weather {
    /// The forecast for `city`, `day` days from now.
    async fn forecast(&self, city: String, day: u32) -> Forecast;
}

/// A weather station (the service implementation). Plain `async fn` — no macros.
struct Station {
    name: String,
    bias_c: i32,
}
impl Weather for Station {
    async fn forecast(&self, city: String, day: u32) -> Forecast {
        // Deterministic toy data so the example is reproducible.
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
    Arc::new(WeatherDispatch(Arc::new(Station { name: name.into(), bias_c })))
}

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    tier0().await;
    println!();
    ndnsf().await;
}

/// Tier-0: a direct call to a *known* provider — one signed Interest → Data.
async fn tier0() {
    println!("== Tier-0 (RpcCarrier): a direct call to a known service ==");
    let carrier = RpcCarrier::new();
    let svc = ServiceId::new(n("/weather"));
    carrier.serve(&svc, station("metoffice", 0)).await.unwrap();

    let client = WeatherClient::new(carrier, svc);
    let f = client.forecast("London".into(), 1).await.unwrap();
    println!(
        "  forecast(London, day 1) -> high {}C / low {}C  [{}]",
        f.high_c, f.low_c, f.summary
    );
}

/// NDNSF: the four-phase, with multi-provider selection — two stations offer the
/// service; the app discovers/selects among them, exactly as NDNSF does.
async fn ndnsf() {
    println!("== NDNSF four-phase (NdnsfCarrier): REQUEST -> ACK -> SELECTION -> RESPONSE ==");
    let group = n("/met");
    let svc = ServiceId::new(n("/weather"));
    let mut pss = hub(&["/met/stationA", "/met/stationB", "/met/app"], &group).into_iter();

    // `serve` spawns the four-phase loop and returns; the station carriers must
    // stay alive for their loops to run (held in this scope below).
    let a = NdnsfCarrier::new(pss.next().unwrap(), n("/met/stationA"), group.clone());
    a.serve(&svc, station("station-A", 0)).await.unwrap();
    let b = NdnsfCarrier::new(pss.next().unwrap(), n("/met/stationB"), group.clone());
    b.serve(&svc, station("station-B", 2)).await.unwrap();

    // The app holds a user capability token and speaks the same generated client.
    let app = NdnsfCarrier::new(pss.next().unwrap(), n("/met/app"), group).token("forecast-cap");
    let client = WeatherClient::new(app, svc);

    // A normal call: one station is selected (first to respond) and answers.
    let f = client.forecast("Paris".into(), 2).await.unwrap();
    println!(
        "  forecast(Paris, day 2) -> high {}C / low {}C  [{}]",
        f.high_c, f.low_c, f.summary
    );

    // NDNSF selection: ask ALL stations and gather every forecast.
    let all = client.forecast_select("Paris".into(), 2, Strategy::All).await.unwrap();
    println!("  forecast_select(Paris, day 2, All) — every station responds:");
    for (provider, fc) in all {
        println!(
            "    {provider} -> high {}C / low {}C  [{}]",
            fc.high_c, fc.low_c, fc.summary
        );
    }

    // Keep the station carriers alive until here; dropping them stops their loops.
    drop(a);
    drop(b);
}

// --- A tiny in-memory SVS medium so the example runs without a forwarder. ---

fn cfg() -> SvSyncConfig {
    SvSyncConfig {
        svs: SvsConfig {
            sync_interval: std::time::Duration::from_millis(50),
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
