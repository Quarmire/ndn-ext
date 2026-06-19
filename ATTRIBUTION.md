# Attribution

Third-party work this repo builds on, ports, or is inspired by. Provisional
notes for proper crediting later.

## Monitor-mode Wi-Fi face (`crates/faces/ndn-face-monitor-wifi`)
- **wfb-ng** — base concept (monitor-mode + raw frame injection), reframed/modified data-centrically.
- **svpcom/rtl8812eu** (kernel driver) — firmware blob + register/init sequences **ported**; phydm BB/RF tables (`array_mp_8822e_*`) copied verbatim.
- **devourer** (OpenIPC, userspace RTL8812AU driver) — userspace libusb backend; **port / inspiration**.
- **Realtek phydm** — BB/RF calibration tables.

## Strategies / transport
- **CCLF** (`crates/strategies/ndn-strategy-cclf`) — **research-derived** cross-layer, link-quality-aware forwarding (CCLF / DCNLA / EDCCA concepts).
- **NDN-Pipes** (`crates/pipes/ndn-pipes`) — **faithful to the NDN-Pipes thesis** protocol, on a modern substrate.

## Dependencies of note
- **aya** + **xdpilone** — AF_XDP face (`crates/faces/ndn-face-afxdp`).
