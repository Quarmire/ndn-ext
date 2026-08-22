# Archived code ledger

Git history is the archive. Each row names the last commit that contains the
item; recover with `git checkout <sha> -- <path>`.

| Path | ~LOC | Last SHA | Why | Date |
|---|---|---|---|---|
| crates/bindings/ndn-wasm | 2,448 | be150dc | Not a binding: standalone in-browser NDN simulator for UI views that exist nowhere; reimplemented FIB/PIT/CS | 2026-08-21 |
| crates/bindings/ndn-web-attach | 266 | f9f0b86 | Self-declared scaffold, bodies unimplemented; cited a design note that never existed | 2026-08-21 |
| crates/bindings/ndn-python | 295 | be150dc | Coverage fossil (15 blocking fns, none of the Node/sync/trust API), 0 tests, 0 consumers — D8 ruling: delete; revisit bindings after the prelude is real | 2026-08-21 |
| crates/discovery/ndn-discovery-broadcast | 314 | be150dc | Served only the ndn-web-attach scaffold; zero consumers | 2026-08-21 |
| crates/faces/ndn-signal-sources | 348 | be150dc | Superseded by migration: its trait moved to ndn-rs's ndn-signals-core; leftover framework imported by nothing | 2026-08-21 |
| crates/faces/ndn-remote-signer-webrtc | 106 | 8d34990 | Zero consumers, zero tests, "compile-verified" only; dragged the WebRTC stack into default builds | 2026-08-21 |
| crates/faces/ndn-face-onion | 773 | f9f0b86 | Research primitive (ANDaNA-style onion crypto), well-written but not a face and consumed by nothing — archived as research, not deleted for cause | 2026-08-21 |
