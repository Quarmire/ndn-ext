# Attribution

Third-party work this repo builds on, ports, or is inspired by. Provisional
notes for proper crediting later.

## Monitor-mode Wi-Fi face (`crates/faces/ndn-face-monitor-wifi`)
- **wfb-ng** — base concept (monitor-mode + raw frame injection), reframed/modified data-centrically.
- **svpcom/rtl8812eu** (kernel driver) — firmware blob + register/init sequences **ported**; phydm BB/RF tables (`array_mp_8822e_*`) copied verbatim.
- **devourer** (OpenIPC, userspace RTL8812AU driver) — userspace libusb backend; **port / inspiration**.
- **Realtek phydm** — BB/RF calibration tables.

## Routing & discovery
- **NLSR** (named-data) — link-state routing; interop with the C++ NLSR reference.
- **ndn-dv** (ndnd) — distance-vector routing, per ndnd's `dv/SPEC.md`.
- **NDN AutoConfig** (NFD `ndn-autoconfig`) + **NDN-FCH** — hub discovery.

## Coding & compute
- **RLNC** (Random Linear Network Coding) — in-network recoding; with systematic K-of-N FEC. [`ndn-coding`]
- **RICE** (reflexive remote invocation over the reverse path, §8) + **NFN** (Named Function Networking) — in-network compute. [`ndn-compute`]

## Service layer
- **NDN Service Framework (NDNSF)** (matianxing1992, C++/ndn-cxx) — the four-phase
  service RPC (REQUEST→ACK→SELECTION→RESPONSE over SVS), `ServiceController`
  KP-ABE model, targeted invocation, compact-selection token-proof hashes, and
  negative-ACK vocabulary: **faithfully ported** in `ndnsf-rs` (baseline
  upstream `5e9e7aa`, 2026-08-12). Two further upstream *mechanisms* are ported
  in mechanism, not wire: the fail-closed execution-lease authority (upstream
  spec 085) → `ndn-lease`, and the stream-session state engine + FEC-protected
  live streaming (upstream specs 057/089/095) → `ndn-stream-session` (FEC via
  our `ndn-coding` instead of upstream's XOR/GF256 parity).
- **NAC-ABE** (named-data) — attribute-based access control naming and CK
  indirection; **ported** in `ndn-nacabe` (ABE ciphertexts via `rabe`, not
  interoperable with openabe — documented).

## Strategies & transport
- **CCLF** — research-derived cross-layer, link-quality-aware forwarding strategy.
- **NDN-Pipes** — faithful to the NDN-Pipes thesis protocol (incl. DCNLA), on a modern substrate.

## Dependencies of note
- **aya** + **xdpilone** — AF_XDP face (`crates/faces/ndn-face-afxdp`).
