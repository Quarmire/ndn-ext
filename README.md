# ndn-ext

Extensions for the [ndn-rs](https://github.com/Quarmire/ndn-rs) core library —
everything non-standard or optional, grouped by domain:

- `crates/faces/` — non-standard faces: serial, SHM, Bluetooth, AF_XDP, QUIC,
  WebSocket, WebRTC, WebTransport, monitor-mode Wi-Fi, BLE-adv, Wi-Fi Aware, LoRa, …
- `crates/service/` — the service/RPC stack: `#[ndn_service]` macro, carrier seam,
  Tier-0 RPC, NDNSF compat, lease/session (strategic — see workspace STATE.md)
- `crates/streams/` — stream sessions over the service seam
- `crates/routing/`, `crates/discovery/` — routing + neighbor/service discovery
- `crates/strategies/` — non-standard forwarding strategies (CCLF, wasm)
- `crates/compute/` — named-function compute + sealed-box
- `crates/coding/` — FEC / content coding · `crates/pipes/` — NDN-Pipes
- `crates/time/` — named-time runtime (sources → timekeeper → driver)
- `crates/surface/` — named zero-copy SHM surfaces (consumed by ndf-rs)
- `crates/dashboard/` — shared dashboard core · `crates/ratelimit/`, `crates/onboarding/`

Removed crates are ledgered in [`ARCHIVE.md`](ARCHIVE.md) (git history is the
archive). Part of the [ndn-rs](https://github.com/Quarmire/ndn-rs) ecosystem.
See [`ATTRIBUTION.md`](ATTRIBUTION.md).
