# ndn-ext

Extensions for the [ndn-rs](https://github.com/Quarmire/ndn-rs) core library —
everything non-standard or optional, grouped by domain:

- `crates/faces/` — non-standard faces: serial, SHM, Bluetooth, AF_XDP, QUIC,
  WebSocket, WebRTC, WebTransport, monitor-mode Wi-Fi, BLE-adv, Wi-Fi Aware, …
- `crates/routing/`, `crates/discovery/` — routing + neighbor/service discovery
- `crates/strategies/` — non-standard forwarding strategies (CCLF, wasm)
- `crates/compute/` — named-function compute + sealed-box
- `crates/coding/` — content segmentation / recoding · `crates/pipes/` — NDN-Pipes
- `crates/bindings/` — wasm, web-attach, Python (maturin)
- `crates/dashboard/` — shared dashboard core · `crates/ratelimit/`, `crates/onboarding/`

Part of the [ndn-rs](https://github.com/Quarmire/ndn-rs) ecosystem. See [`ATTRIBUTION.md`](ATTRIBUTION.md).
