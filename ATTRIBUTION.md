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

## Strategies & transport
- **CCLF** — research-derived cross-layer, link-quality-aware forwarding strategy.
- **NDN-Pipes** — faithful to the NDN-Pipes thesis protocol (incl. DCNLA), on a modern substrate.

## Dependencies of note
- **aya** + **xdpilone** — AF_XDP face (`crates/faces/ndn-face-afxdp`).
