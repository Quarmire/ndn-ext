# ndn-ndnsf

A faithful Rust port of the **NDN Service Framework (NDNSF)** four-phase service
RPC, on the ndn-rs substrate. An NDNSF service request is a four-phase exchange
over an SVS sync group:

```
REQUEST  →  ACK  →  SELECTION  →  RESPONSE
(user publishes a request; providers ACK with a token; the user SELECTs one;
 the selected provider runs the handler and RESPONSEs)
```

This crate reimplements that protocol so an ndn-rs node interoperates with a C++
NDNSF node at the protocol level (the ABE *ciphertext bytes* excepted — see
`docs/specs/service-layer.md` §7.3), and holds it to NDNSF's audited security
properties via the O4 invariant catalogue (`docs/specs/ndnsf-invariants.md`).

## What's here

| Module | Surface |
|---|---|
| `messages` | the four-phase TLV taxonomy (Request/Ack/Selection/Response, types 128–131) + `Strategy` (FirstResponding / RandomSelection / AllSelected) and `RequestMode` (Normal / Targeted / TargetedBootstrap) |
| `tokens` | the provider-token lifecycle + pending-coordination state machine (the security/coordination guard: NSF-T/S invariants) |
| `flow` | the sans-IO orchestration (`ProviderEngine`: `on_request` / `on_selection` / `consume_selection`) |
| `driver` | the flow over `ndn-sync` SVS pub/sub (`serve_provider`, `call`, `select_and_call`, the targeted modes) — feature `driver` |
| `roles` | ergonomic `ServiceProvider` / `ServiceUser` / `ServiceNode` (multi-service over one engine) |
| `carrier` | **`NdnsfCarrier`** — the four-phase as a `Carrier` (+ `SelectCarrier`), so a `#[ndn_service]` definition runs over it unchanged |
| `trust` | `TrustCtx` — per-message sign/verify (NSF-A3 trust half, the faithful `MessageValidator` placement) |
| `access` | KP-ABE access control — NAC-seal a response under the service's attributes (NSF-A3 authorization) |
| `policy` | a TOML access policy → `ndn-nacabe::KpAuthority` grants |

## Example

A weather service run over both the NDNSF four-phase and Tier-0, with a
*parameterized request* and a *structured response*:

```bash
cargo run -p ndn-ndnsf --example weather --features driver
```

### Walkthrough: `examples/weather.rs`

One service definition, used unchanged over both carriers:

```rust
#[derive(Frame, Clone)]                 // structured "response with data"
struct Forecast { city: String, day: u32, high_c: i32, low_c: i32, summary: String }

#[ndn_service]
trait Weather {
    async fn forecast(&self, city: String, day: u32) -> Forecast;
}

struct Station { name: String, bias_c: i32 }
impl Weather for Station {              // a plain async impl — no macros
    async fn forecast(&self, city: String, day: u32) -> Forecast { /* … */ }
}
```

**Tier-0** — a direct call to a *known* provider (one signed Interest → Data):

```rust
let carrier = RpcCarrier::new();
let svc = ServiceId::new("/weather".parse()?);
carrier.serve(&svc, station("metoffice", 0)).await?;

let client = WeatherClient::new(carrier, svc);
let f = client.forecast("London".into(), 1).await?;   // -> Forecast { high_c: 28, … }
```

**NDNSF four-phase** — two stations offer the service in a sync group; the app
discovers/selects among them (`REQUEST → ACK → SELECTION → RESPONSE`), exactly as
NDNSF does. `forecast_select(All)` gathers a forecast from *every* station:

```rust
let svc = ServiceId::new("/weather".parse()?);

// `serve` spawns the four-phase loop and returns, so the station carriers must
// stay alive in scope (don't move them into a spawned task that then drops them).
let a = NdnsfCarrier::new(a_ps, "/met/stationA".parse()?, group.clone());
a.serve(&svc, station("station-A", 0)).await?;
let b = NdnsfCarrier::new(b_ps, "/met/stationB".parse()?, group.clone());
b.serve(&svc, station("station-B", 2)).await?;

let app = NdnsfCarrier::new(app_ps, "/met/app".parse()?, group).token("forecast-cap");
let client = WeatherClient::new(app, svc);

let one = client.forecast("Paris".into(), 2).await?;                   // first to respond
let all = client.forecast_select("Paris".into(), 2, Strategy::All).await?; // every station
```

Output:

```
== Tier-0 (RpcCarrier): a direct call to a known service ==
  forecast(London, day 1) -> high 28C / low 21C  [metoffice: partly cloudy]

== NDNSF four-phase (NdnsfCarrier): REQUEST -> ACK -> SELECTION -> RESPONSE ==
  forecast(Paris, day 2) -> high 28C / low 21C  [station-A: partly cloudy]
  forecast_select(Paris, day 2, All) — every station responds:
    /met/stationA -> high 28C / low 21C  [station-A: partly cloudy]
    /met/stationB -> high 30C / low 23C  [station-B: partly cloudy]
```

The *same* `#[ndn_service]` client and `WeatherDispatch` run over Tier-0 and the
NDNSF four-phase — only the carrier differs. (`Carrier`, `ServiceId`, and
`Strategy` come from [`ndn-service-core`](../ndn-service-core).) See
`examples/weather.rs` for the full, runnable source.

## Faithfulness

The O4 catalogue (`docs/specs/ndnsf-invariants.md`) maps each NDNSF security
invariant (auth NSF-A1–A4, tokens T1–T6, state S1–S5, failure F1–F5) to a Rust
witness; the catalogue has no open gaps. Where this layer corrects NDNSF (e.g.
authority-as-signed-Data, dynamic policy) those changes live in the **v2** crate
`ndn-service`, not here — this crate stays a faithful compat port.

## Acknowledgements

This crate is a port of the **NDN Service Framework (NDNSF)**, a C++ service-RPC
framework built on `ndn-cxx`; the four-phase protocol, the `ServiceController`
model, and the security invariants are NDNSF's design. Our thanks to the NDNSF
authors and the wider **Named Data Networking** project. KP-ABE access control is
provided by [`ndn-nacabe`](../ndn-nacabe), the NAC-ABE port (see its
acknowledgements). This is an independent reimplementation for interoperability
and study, not affiliated with or endorsed by the original projects.
