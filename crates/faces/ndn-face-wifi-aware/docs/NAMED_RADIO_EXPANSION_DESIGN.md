# Named-Radio Expansion: Wi-Fi Aware (NAN), BLE, and Embedded — Design

> Audience: humans + LLMs working on the radio faces. This is the research-backed
> architecture and phased plan to take `ndn-face-wifi-aware`, `ndn-face-ble-adv`,
> and the named-radio substrate from "trait + loopback only" to **real,
> feature-maximized backends** on desktop, with embedded (ESP32) kept
> design-compatible. It is grounded in six research sweeps (NAN spec/feature
> surface, opennan internals, Linux nl80211 NAN, macOS/Windows native NAN, BLE
> maximization, ESP32 open-MAC); their verdicts are cited inline as **[R:topic]**.

---

## 1. The shape of the problem, and the one insight that organizes it

NDN's radio faces already separate **the NDN face** from **the radio behind it**
via three trait seams:

- **`NanBackend`** (`ndn-face-wifi-aware`) — connectionless coordination
  (`broadcast`/`next_followup`), service discovery (`publish`/`subscribe`/
  `drain_matches`), and bulk handoff (`request_ndp` → a UDP socket). The
  `NanCoordFace` (NDN `Transport`) and `NanDiscovery` (NAN match → FIB route)
  already consume it. **Only a loopback backend exists.**
- **`AdvBackend`** (`ndn-face-ble-adv`) — connectionless broadcast
  (`broadcast`/`next_scanned`). **Only a loopback backend exists.**
- **`FrameIo` + `RadioKnobs`** (`ndn-frame-io` / `ndn-face-monitor-wifi`) — raw
  802.11 inject/capture + slow knobs (`set_channel`, power, EDCCA). **Mature**:
  USB drivers, AF_PACKET, radiotap, MCS, FEC, A-MSDU, cognition.

**The organizing insight:** *a userspace NAN stack is a state machine that sits
between `FrameIo` (down) and `NanBackend` (up).* It reuses the entire mature
monitor substrate for PHY/MAC mechanics (radiotap, per-frame MCS, RSSI →
`SignalStore`, channel tuning) and adds only the NAN-specific logic (cluster
sync, master election, Discovery-Window scheduling, Service-Discovery-Frame
codec, service matching, NDP handshake). This is exactly what **opennan** is, and
its design maps almost 1:1 onto `FrameIo` **[R:opennan]**. Everything else in
this document is additional `NanBackend`/`AdvBackend` implementations for other
platforms behind the *same* seams.

---

## 2. Platform reality check (what's actually reachable)

| Platform | Native NAN | Practical path | Verdict |
|---|---|---|---|
| **Linux + monitor/inject NIC** | n/a | **userspace NAN on `FrameIo`** (opennan port) | ✅ **primary** — full sync NAN, S23-interop, portable |
| **Linux + ordinary managed NIC** | mainline: none | **wpa_supplicant 2.11 NAN-USD** (off-channel action frames) | ✅ discovery+follow-up only, no NDP/sync **[R:nl80211]** |
| **Linux + future iwlwifi / Android FullMAC** | nl80211 `START_NAN` | native `NanBackend` over netlink | ⚠️ gate behind capability detection; **no in-tree driver today** **[R:nl80211]** |
| **macOS desktop** | none (Apple Wi-Fi Aware is **iOS-only**) | monitor/inject is **blocked** on modern macOS | ❌ no first-class path; AWDL-via-IO80211 is a frontier rabbit hole **[R:macos]** |
| **Windows desktop** | none (only Wi-Fi Direct) | injection unsupported (Npcap) | ❌ not feasible **[R:macos]** |
| **ESP32 (C6/S3/S2/...)** | ESP-IDF ships native NAN | esp-idf-svc `NanBackend`, or open-MAC FoA injection | ✅ design-compatible; build deferred **[R:esp32]** |

**Consequences for build order:** desktop NAN leads with the **userspace
monitor-mode** path (works on the capable monitor radios already driven by this
stack, and is the only route that gives *full* synchronized NAN + NDP). The
**NAN-USD** path is the high-value complement for commodity laptops that lack
monitor mode. Native nl80211 and macOS/Windows native are effectively dead today
and are stubbed behind capability detection, not built.

---

## 3. Architecture: a sans-I/O NAN core, platform drivers around it

To serve desktop (tokio) **and** embedded (embassy/no_std) from one
byte-compatible implementation, the NAN protocol is a **sans-I/O** core: a pure
state machine with no sockets, no async, no clock of its own. Platform drivers
feed it time + inbound frames and transmit its outbound frames.

```
            ┌──────────────────────── ndn-nan-core (no_std + alloc) ───────────────────────┐
            │  wire:   attribute TLV codec · beacon/SDF/NAF builders+parsers ·             │
            │          service-id hash (SHA-256[..6] of lowercased name)   [byte-exact]    │
            │  engine: software-TSF + DW scheduler · sync + master/anchor election ·       │
            │          cluster merge · publish/subscribe/follow-up · (Phase 2) NDP M1–M4   │
            │                                                                              │
            │  pub fn poll(&mut self, now: Tu, inbound: &[RxFrame]) -> Step {              │
            │      Step { tx: Vec<TxFrame>, channel: Option<u8>, events: Vec<NanEvent>,    │
            │             wake_at: Tu }                                                    │
            │  }                                                                           │
            └──────────────────────────────────────────────────────────────────────────────┘
                 ▲ poll(now, inbound)                    │ tx / set_channel / events
                 │                                       ▼
   ┌─────────────────────────────┐        ┌──────────────────────────────────────────────┐
   │ desktop driver  (ndn-nan)   │        │ embedded driver (later)                       │
   │ tokio timer + FrameIo +     │        │ embassy timer + FoA VIF / esp-wifi-hal        │
   │ RadioKnobs::set_channel     │        │                                               │
   │ ── impl NanBackend ─────────┤        │ ── impl NanBackend (no_std) ──────────────────┤
   └──────────────┬──────────────┘        └───────────────────────────────────────────────┘
                  │ NanBackend
                  ▼
        NanCoordFace / NanDiscovery / request_ndp  (existing ndn-face-wifi-aware)
```

Why sans-I/O: (1) the timing/sync logic is the subtle part and must be unit-
testable deterministically (feed synthetic frames + a fake clock, assert exact
output bytes — the S23-byte-compatibility guarantee); (2) it makes the **same
core** run under tokio on desktop and embassy on ESP32, satisfying the
"design-compatible embedded" requirement structurally rather than by
duplication; (3) it isolates the one crate that must be byte-perfect from all I/O
concerns.

### 3.1 Crate layout (new)

- **`ndn-nan-core`** — `#![no_std]` + `alloc`. The wire codec + the sans-I/O
  engine. Depends on nothing platform-specific. `heapless`/`alloc` buffers;
  time as a `u64` TU newtype, never `std::time`. The opennan port lives here as
  idiomatic Rust. **This is the byte-compatibility-critical crate** — fuzz +
  golden-vector tested against real captures.
- **`ndn-nan`** — `std`. Desktop driver: owns a `tokio` timer task, an
  `Arc<dyn FrameIo>` and an `Arc<dyn RadioKnobs>`, runs the `poll` loop, and
  **implements `NanBackend`** (so it drops straight into the existing
  `NanCoordFace`). Also hosts the `wpa_supplicant` NAN-USD backend (Phase 3) and
  the nl80211 stub (Phase 3) as alternative `NanBackend`s.
- Embedded crate(s) are **deferred** (Phase 5) but the `-core` API is shaped now
  so they're a thin driver, not a rewrite.

### 3.2 Reused, not rebuilt

- **Frame transport:** `FrameIo::inject`/`recv_frame` + `RadioKnobs::set_channel`
  — no new radio code; the RTL8812EU / MT7612U / AF_PACKET backends already
  provide monitor inject/capture with radiotap RSSI. NAN sync beacons + SDFs are
  just different 802.11 frame *bodies* on the same path.
- **Signals:** captured-frame RSSI → `SignalStore` (the face already does this);
  NAN peers feed the same measured/CCLF strategies.
- **Capability:** register the NAN radio in `MediumState` via `RadioCapability`
  (add `RadioKind::WifiAware`, band 2.4/5 GHz) so cognition can reason about it.
- **Bulk:** `request_ndp()` already returns a `UdpSocket` + peer addr that the
  caller wraps in `ndn-face`'s `UdpFace` — Phase 2 fills in the real NDP; the
  seam is untouched.

---

## 4. The NAN wire layer (byte-exact, from opennan + the dissector)

These constants are interop-critical and verified against opennan source +the
Wireshark `wifi_nan` dissector **[R:opennan][R:nan-features]**:

- **OUI** `50:6F:9A` (Wi-Fi Alliance). Beacon vendor IE id `0xDD`, OUI type
  `0x13`. SDF = **public action** frame `category=0x04, action=0x09, oui=50:6F:9A,
  oui_type=0x13`. NAF (data-path/ranging/schedule) `oui_type=0x18` with an
  `oui_subtype`.
- **Cluster ID** base `50:6F:9A:01:xx:xx` in addr3; broadcast dest
  `51:6F:9A:01:00:00`.
- **Attribute TLV** = `id(u8) | length(u16 LE) | body`. Everything multi-byte is
  **little-endian**.
- **Service ID** = first **6 bytes** of standard **SHA-256** of the
  **lowercased** UTF-8 service name. Matches Android `WifiAwareManager` and the
  S23 exactly.
- **Timing:** DW interval **512 TU**, DW length **16 TU**, 1 TU = 1024 µs. Sync
  beacon every 512 TU; discovery beacon every 100 TU (MASTER, outside DW).
- **Master rank** = `pref·2^56 + random_factor·2^48 + MAC` packed LE as a u64
  (preference MSB); `>` gives preference-dominant ordering. Software TSF =
  `now − base_time`, slewed to the anchor master's beacon `time_stamp`; a 32-sample
  moving-average error filter absorbs userspace jitter (target < 3 TU).

**Attribute coverage (full catalog known, build incrementally):** Master
Indication `0x00`, Cluster `0x01`, Service ID List `0x02`, **SDA `0x03`**, SDEA
`0x0E`, Device Capability `0x0F`, **NDP `0x10`**, NAN Availability `0x12`, NDC
`0x13`, NDL `0x14`, NDL QoS `0x15`, Ranging `0x0C`/`0x1A`/`0x1B`/`0x1C`, Cipher
Suite Info `0x22`, Security Context `0x23`, Shared-Key Descriptor `0x24`, **NDPE
`0x29`** (IPv6 IID + transport port/protocol), Device Capability Extension `0x2A`
(6 GHz), NIRA `0x2B`, Pairing Bootstrapping `0x2C`, Vendor Specific `0xDD`. NAF
subtypes: ranging 1–4, **data-path 5–9** (Request/Response/Confirm/Key-Install/
Terminate), schedule 10–13. **[R:nan-features]**

**Feasibility caveats to honor:** open NDP + NCS-SK + NDPE socket handoff + USD
are all demonstrated tractable in userspace; **FTM ranging** (needs PHY
timestamping) and **PASN password-pairing** (needs 802.11 auth-frame inject) are
the two features that are hard/infeasible over pure monitor mode — schedule them
last / frontier. **[R:nan-features]**

---

## 5. Exposing the full feature surface (the "first-class API" goal)

The `NanBackend` trait stays minimal (it's the engine↔radio seam). Feature
richness is exposed through **config structs** mirroring Android's
`PublishConfig`/`SubscribeConfig`, surfaced on `NanCoordFace`/`NanDiscovery`:

```rust
pub struct PublishConfig {
    pub service: NanServiceName,
    pub publish_type: PublishType,          // Unsolicited | Solicited | Both
    pub ttl: Option<Duration>,
    pub ssi: Option<Bytes>,                  // service-specific info
    pub tx_match_filter: Option<MatchFilter>,
    pub srf: Option<ServiceResponseFilter>,  // restrict responder set
    pub range_limited: Option<RssiBand>,     // discovery RSSI gate
    pub needs_ndp: bool, pub needs_security: bool, pub needs_ranging: bool, // SDEA bits
    pub instant_comm: Option<u8>,            // ICM channel
}
pub struct SubscribeConfig { /* active/passive, rx_match_filter, min/max distance, ... */ }
```

Each maps to SDA/SDEA bits the wire layer already knows. This is how
"expose every feature" is realized without a sprawling trait: the *capability*
is in `ndn-nan-core`; the *API* is config the app sets. Ranging, pairing, and
USD-mode are flags here too (built as their phases land).

---

## 6. BLE maximization (parallel workstream)

Same seam (`AdvBackend`), three real backends in increasing capability
**[R:ble]**:

1. **`bluer` extended-advertising backend (ship now).** `broadcast()` registers a
   BlueZ `Advertisement` with the ~245 B NDN frame in `manufacturer_data` and
   `secondary_channel = Coded` for **free long range**; `next_scanned()` drives
   `Adapter` discovery → `ScannedFrame{frame, addr, rssi}`. Replaces loopback as
   the default real Linux BLE backend. Matches the existing `EXTENDED_ADV_MTU`.
2. **Raw HCI `HCI_CHANNEL_USER` backend (capability).** Hand-rolled
   `AF_BLUETOOTH`/`SOCK_RAW` socket (via `nix`/`libc`) + `bt-hci` structs:
   `LE Set Extended Advertising Parameters/Data/Enable` (0x2036/37/39), coded
   primary PHY, multiple advertising sets, periodic advertising, and explicit
   `LE Extended Advertising Report` (meta 0x3E/0x0D) parsing (RSSI@13, addr@3–8,
   payload@24, reassemble across "more-to-come"). Needed for anything `bluer`
   hides.
3. **PAwR bidirectional (research frontier).** Periodic Advertising with Responses
   (BLE 5.4) = **connectionless Interest→subevent / Data→response-slot** — the
   genuinely novel NDN-over-broadcast bidirectional bearer. Requires raw HCI +
   a PAwR controller (nRF54L15 / ESP32-C6); the Linux host side is immature, so
   this is a custom-host-stack project, parked as a frontier item.

BLE is independent of NAN and can proceed in parallel once NAN Phase 1 is moving.

---

## 7. Embedded (design-compatible now, build deferred) [R:esp32]

- **`ndn-nan-core` is `no_std` from day one** so it compiles for Xtensa/RISC-V.
  Time is a TU `u64`; buffers are `heapless`/`alloc`; no `std::time`. This is the
  concrete "design-compatible" deliverable.
- **Two embedded tracks, both later:** (a) **native ESP-IDF NAN** as a
  `NanBackend` via `esp-idf-svc` on **ESP32-C6** — real certified NAN for "free"
  (closed blob, ch6/2.4 GHz, std/IDF Rust); (b) **open-MAC FoA injection VIF** on
  **ESP32/S2** for raw named-radio, modeled on the existing `foa_awdl`
  connectionless protocol (the ideal template). `esp-wifi-hal`'s
  `transmit`/`receive`/`set_channel` map ~1:1 to `FrameIo`, and MCS injection
  actually works there (unlike the closed blob).
- **Chip order when built:** C6 first (native NAN + BLE5 + mature Rust), ESP32
  classic for open-MAC injection, defer C5 (no Rust HAL yet).

---

## 8. Phased plan

Each phase ends with a witness (test or on-air demo). The S23 is the on-air
interop reference throughout.

- **Phase 0 — `ndn-nan-core` wire layer.** Attribute TLV codec, beacon/SDF
  builders+parsers, service-ID hash. `no_std`. Golden-vector + fuzz tests; decode
  a real S23 NAN capture and re-encode byte-identically. *Witness: round-trip +
  golden vectors green.*
- **Phase 1 — userspace monitor-mode NAN (MVP → full).**
  - 1a MVP: fixed ch6, permanent-MASTER, software-TSF sync to S23 beacon,
    publish/subscribe + follow-up. *Witness: S23 subscriber discovers our
    publisher and exchanges a follow-up; and our subscriber discovers an S23
    publisher.*
  - 1b Full: master/anchor election, cluster merge, multi-channel DW (6/44/149)
    via `set_channel` hopping, RSSI→`SignalStore`, `RadioCapability` registration.
    Wire into `NanCoordFace` + `NanDiscovery`. *Witness: through-engine NDN
    Interest/Data over real NAN between two laptops + the S23.*
- **Phase 2 — NDP/NDPE data path.** M1–M4 NAF handshake, NDPE (IPv6 IID +
  transport port/protocol), NDI virtual interface (EUI-64 `fe80::`), open NDP +
  NCS-SK security; `request_ndp()` returns a real bound UDP socket → `UdpFace`.
  *Witness: bulk NDN transfer over a real NAN data path.*
- **Phase 3 — commodity-desktop NAN.** `wpa_supplicant` NAN-USD `NanBackend`
  (control-socket: `NAN_PUBLISH`/`NAN_SUBSCRIBE`/`NAN_TRANSMIT` + events) for
  managed-mode laptops; nl80211 native `NanBackend` behind capability detection
  (future iwlwifi/FullMAC). *Witness: discovery+follow-up on an ordinary Intel/ath
  laptop with no monitor mode.*
- **Phase 4 — BLE backends.** `bluer` ext-adv backend (default), raw-HCI backend
  (capability). PAwR parked as frontier. *Witness: real BLE NDN broadcast +
  Coded-PHY long-range between two hosts.*
- **Phase 5 — embedded build.** ESP-IDF NAN `NanBackend` on C6 and/or FoA
  injection VIF on ESP32. *Witness: NDN frame desktop ↔ ESP32 over NAN or raw
  injection.*

**Frontier (not scheduled):** FTM ranging, PASN password-pairing, NAN-USD as
Wi-Fi Direct / DPP / Matter bootstrap, 6 GHz NAN, macOS AWDL-via-IO80211.

---

## 9. Risks & open questions

- **Active monitor + injection holding DW timing** is the hard real-world
  dependency (opennan needs ath9k/nexmon-class active monitor). Confirm which of
  the stack's existing USB backends (RTL8812EU, MT7612U) can hold DW timing and
  inject NAN action frames; the MT7612U is verified TX-on-air on ch6 (the NAN
  2.4 GHz DW channel), which is promising.
- **Channel-switch latency** for multi-band DWs (6→44→149) must stay within the
  16 TU window; may pin MVP to ch6 only.
- **NDPE Transport-Port/Protocol TLV codepoints, NDP-QoS layout, cipher-suite
  wire IDs** need verification against the paywalled v4.0 spec or AOSP HAL before
  Phase 2 ships byte-compatible.
- **Sync drift** is opennan's documented weak point; the moving-average filter
  must be ported faithfully.

---

## 10. Source map (research provenance)

Six research sweeps underpin this design; full reports are in the session record.
Load-bearing verdicts: opennan is a near-1:1 `FrameIo` blueprint for the
discovery+sync half **[R:opennan]**; native nl80211 NAN is dead on mainline,
NAN-USD is the commodity fallback **[R:nl80211]**; macOS/Windows desktop NAN is
unreachable **[R:macos]**; ESP-IDF already ships NAN and FoA is the open-MAC
injection vehicle **[R:esp32]**; the full attribute catalog + NDP/NDPE/ranging/
security feasibility is mapped **[R:nan-features]**; BLE ext-adv ships via `bluer`,
PAwR is the bidirectional frontier **[R:ble]**.
