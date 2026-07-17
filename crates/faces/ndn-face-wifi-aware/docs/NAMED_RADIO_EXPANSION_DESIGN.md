# Named-Radio Expansion: Wi-Fi Aware (NAN), BLE, and Embedded — Design

> Audience: humans + LLMs working on the radio faces. This is the research-backed
> architecture and phased plan to take `ndn-face-wifi-aware`, `ndn-face-ble-adv`,
> and the named-radio substrate from "trait + loopback only" to **real,
> feature-maximized backends** on desktop, with embedded (ESP32) kept
> design-compatible. It is grounded in six research sweeps (NAN spec/feature
> surface, opennan internals, Linux nl80211 NAN, macOS/Windows native NAN, BLE
> maximization, ESP32 open-MAC); their verdicts are cited inline as **[R:topic]**.

---

## 0. STATUS (2026-07-16) — read this before believing any tense below

This document was written as a **forward plan**. Phases 0, 1 and 2 have since
shipped and been proven on air, and the rest of the prose was never re-tensed.
Where a section still says "will" about something that is done, this section is
the authority; the phase list in §8 carries per-phase status inline.

| phase | state | evidence |
|---|---|---|
| 0 — `ndn-nan-core` wire layer | **done** | `ndn-nan-core/src/{wire,attr,frame,service}.rs`; golden-vector + round-trip tests |
| 1 — userspace monitor-mode NAN | **done, proven on air** | mutual Wi-Fi Aware discovery with a **stock Samsung S23**, over our own userspace RTL8812AU driver. `ndn-nan-core` (sans-I/O engine) + `ndn-nan` (std driver, `FrameIo` + tokio) both ship |
| 1c — election role transitions, multi-channel DW hopping | **not built** | `ndn-nan-core/src/engine.rs:37` says so; task #19 |
| 2 — NDP/NDPE data path | **mechanism done, proven between our own nodes; since demoted to an interop bearer** | M1–M4 in `engine.rs`, NDPE codec in `attr.rs`, NDI TAP in `ndn-nan/src/ndi.rs`. Two OPis: 4/4 runs both paths up, 18–20 distinct datagrams each way, 0 duplicates, real IPv6 UDP over 802.11. **Read the proof narrowly:** the datagrams were ~14 B (no bulk transfer has ever crossed an NDP — the phase's own witness, retired not met), **NCS-SK security was not built** (open NDP only), and it was **never tested against a stock device's NDP** — the S23 proof covers discovery only. §8 and `NAMED_RADIO_COURSE_CORRECTION.md` |
| 3 — commodity-desktop NAN (NAN-USD, nl80211) | **not built** | no backend in tree; task #11 |
| 4 — BLE backends | **not built** | `ndn-face-ble-adv/src/` is still `{lib, loopback}.rs`; task #12 |
| 5 — embedded build | **not built** | task #13 |

Two claims in this document have **not** aged into truth and are corrected in
place below: the `NanBackend` loopback line (§1) is false — `ndn-nan` is a real
backend — while the `AdvBackend` loopback line beside it is still **accurate**,
because Phase 4 never started. And `RadioCapability` registration for the NAN
radio (§3.2) is **still unbuilt**: `RadioKind` has no `WifiAware` variant.

The config-struct API of §5 (`PublishConfig` / `SubscribeConfig`) is **design,
not code** — neither type exists, and neither does the wire encoding for most of
what it would set (no SRF, no match filters, no TTL). §5's "the capability is in
`ndn-nan-core`, the API is config the app sets" is the one structural claim here
that overstated what was built; §5 now says so.

One thing the plan never anticipated, worth knowing before trusting the interop
proof: to make a stock S23 surface us at all, our SDF must carry a **NAN
Availability** attribute (`0x12`), and the engine currently **replays the two
Availability attributes a real S23 emits, byte-for-byte as constants**
(`attr::encode_availability`) rather than encoding its own schedule. It is
sound — we are TSF-merged into that cluster, so the schedule applies — and it is
documented honestly at the source, but it means our advertised availability is
borrowed, not computed, and it will not survive Phase 1c's multi-channel DWs. A
validated `AvailabilityHeader` codec exists and is tested against those same S23
bytes; switching the engine onto it needs an on-air re-test (task #20).

**And one decision here has since been reconsidered.** §3.2 and Phase 2 specify
NDP/NDPE as the bulk tier. That decision shipped and works, but it is now judged
a host-centric regression: `request_ndp()` hands back a UDP socket on an IPv6
link-local over a TAP netdev, which is exactly the addressing NDN exists to
escape. The argument, the evidence, and the demotion are in
**`NAMED_RADIO_COURSE_CORRECTION.md`** (in-tree, alongside this file), which
this plan does not attempt to summarise or pre-empt. The short form: NDP is kept
as an **interop bearer** — if a stock device offers a data path, we answer — but
our own traffic rides `FrameFormat::RawNdn`, where the name is the addressing.
The plan is not edited to agree with the correction; both are on the record, and
the correction is the later judgement.

---

## 1. The shape of the problem, and the one insight that organizes it

NDN's radio faces already separate **the NDN face** from **the radio behind it**
via three trait seams:

- **`NanBackend`** (`ndn-face-wifi-aware`) — connectionless coordination
  (`broadcast`/`next_followup`), service discovery (`publish`/`subscribe`/
  `drain_matches`), and bulk handoff (`request_ndp` → a UDP socket). The
  `NanCoordFace` (NDN `Transport`) and `NanDiscovery` (NAN match → FIB route)
  already consume it. ~~**Only a loopback backend exists.**~~ *Corrected
  2026-07-16: `ndn-nan::NanDriver` is a real backend and has talked to an S23.*
- **`AdvBackend`** (`ndn-face-ble-adv`) — connectionless broadcast
  (`broadcast`/`next_scanned`). **Only a loopback backend exists.** *Still true:
  Phase 4 has not started.*
- **`FrameIo` + `RadioKnobs`** (`ndn-radio-hal`, re-exported by `ndn-frame-io`
  and `ndn-radio-cognition`) — raw 802.11 inject/capture + slow knobs
  (`set_channel`, power, EDCCA). **Mature**: USB drivers, AF_PACKET, radiotap,
  MCS, FEC, A-MSDU, cognition. *Corrected 2026-07-16: these traits were
  attributed to `ndn-face-monitor-wifi` when this was written. `ndn-radio-hal`
  (a later crate, `ndn-rs/crates/core/ndn-radio-hal`) now owns them along with
  `TxIntent`, `InjectFrame`, `CapturedFrame`, `RadioCapability`, `RadioKind`,
  `Bandwidth` and the rest of the bearer-agnostic contract. The USB drivers
  themselves moved out again, to the separate `ndn-radio-drivers` repo.*

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
            │          cluster merge · publish/subscribe/follow-up · NDP M1–M4 [shipped]  │
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
  just different 802.11 frame *bodies* on the same path. **This held.** `ndn-nan`
  takes an `Arc<dyn FrameIo>` and an optional `RadioChannel` (satisfied by any
  `RadioKnobs` via `knobs_channel`) and needed no bespoke radio code. The radio
  that actually carried Phases 1 and 2 was the **RTL8812AU**, not the two named
  here; the drivers now live in the `ndn-radio-drivers` repo.
- **Signals:** captured-frame RSSI → `SignalStore` (the face already does this);
  NAN peers feed the same measured/CCLF strategies. **Done** at the face seam:
  `NanCoordFace::with_signal_sink`.
- **Capability:** register the NAN radio in `MediumState` via `RadioCapability`
  (add `RadioKind::WifiAware`, band 2.4/5 GHz) so cognition can reason about it.
  **Not built** (checked 2026-07-16): `RadioKind` has no `WifiAware` variant and
  nothing in `ndn-nan` constructs a `RadioCapability`. Note also the ownership
  drift — `RadioCapability` and `RadioKind` are `ndn-radio-hal` types, not
  cognition's; the registration is a HAL descriptor a driver publishes, and
  cognition consumes it.
- **Bulk:** `request_ndp()` returns an `NdpLink` — a bound UDP socket + peer addr
  that the caller wraps in `ndn-face`'s `UdpFace`. Phase 2 filled in the real
  NDP and the seam was indeed untouched, exactly as this bullet predicted. *That
  is the part that aged worst: the seam's cheapness was the argument for the
  design, and the design imports host addressing wholesale. See
  `NAMED_RADIO_COURSE_CORRECTION.md` §2.3, which quotes this plan's "the seam is
  untouched" as the economy argument it convicts. The bulk tier's stated premise
  — that connectionless small-frame faces are lossy for multi-fragment objects —
  turned out to be an artifact of two of our own bugs (an off-by-24 `MONITOR_MTU`
  and a missing RX pump), not a property of name-addressed broadcast.*

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
  *Correction 2026-07-16: `master_rank` shipped exactly as specified and is
  load-bearing for cluster merge. The **filter did not ship** — the engine jams
  the TSF straight to the beacon timestamp on every sync. This sentence describes
  an intent, not the code; see §9.*

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

**Status 2026-07-16: this section is design, not code.** Neither `PublishConfig`
nor `SubscribeConfig` exists. `NanBackend::publish`/`subscribe` take a bare
`&NanServiceName`; the engine registers a service function and nothing more.

The *capability* claim below — "the capability is in `ndn-nan-core`; the API is
config the app sets" — is weaker than it reads. `attr.rs` types SDA and SDEA,
and `Sdea` carries a `discovery_range_limited` bool. But the SRF, the tx/rx
match filters, the RSSI band, the TTL and instant-comm have **no types at all**
in the core, not merely no callers. So this section is a sketch of an API over a
wire layer that does not yet encode most of what the API would set. The trait
did stay minimal, which is the claim that held.

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

- **Phase 0 — `ndn-nan-core` wire layer. [DONE]** Attribute TLV codec, beacon/SDF
  builders+parsers, service-ID hash. `no_std`. Golden-vector + fuzz tests; decode
  a real S23 NAN capture and re-encode byte-identically. *Witness: round-trip +
  golden vectors green.*
- **Phase 1 — userspace monitor-mode NAN (MVP → full). [DONE — PROVEN ON AIR]**
  - 1a MVP **[done, on air]**: fixed ch6, permanent-MASTER, software-TSF sync to
    S23 beacon, publish/subscribe + follow-up. *Witness met: mutual Wi-Fi Aware
    discovery with a stock Samsung S23, over our own userspace RTL8812AU driver —
    both directions.*
  - 1b Full **[partly done]**: cluster merge **[done]** (`engine.rs` grades a
    heard cluster by anchor-master rank and adopts the higher), RSSI→`SignalStore`
    **[done]**, wired into `NanCoordFace` + `NanDiscovery` **[done]**.
    `RadioCapability` registration **[not built]**.
  - 1c **[not built]** — master/anchor election *role transitions* and
    multi-channel DW (6/44/149) hopping via `set_channel`. `engine.rs:37` states
    this openly: the rank is advertised, the transitions are not run. Task #19.
    *Reframed since:* `NAMED_RADIO_COURSE_CORRECTION.md` §4 argues "who is master"
    is host-centric framing, and that our own clusters should anchor by
    **contribution** (`cclf_elect`), keeping NAN's MAC-based rank only on the
    interop path.
- **Phase 2 — NDP/NDPE data path. [DONE — PROVEN ON AIR, AND SINCE DEMOTED]**
  M1–M4 NAF handshake, NDPE (IPv6 IID + transport port/protocol), NDI virtual
  interface (EUI-64 `fe80::`); `request_ndp()` returns a real bound UDP socket →
  `UdpFace`. The mechanism shipped; **the witness this phase set itself did not.**
  *Original witness: "bulk NDN transfer over a real NAN data path." NOT MET
  (2026-07-16)* — the data path carried ~14-byte datagrams between two of our own
  nodes, and no bulk NDN transfer has ever crossed an NDP. The phase is done in the
  sense that the handshake, the NDI, and the bound socket all work on air; it is
  not done in the sense its own acceptance criterion asked for, and since the tier's
  premise has been refuted (below), the criterion is retired rather than pursued.
  Three caveats worth recording:
  - Delivered as specified except **NCS-SK security**, which was not built (open
    NDP only), and the **transport port**, which is a well-known constant
    (`NDP_PORT = 6363`) rather than negotiated — the NDPE Service Info sub-TLV
    layout is the paywalled part, and `ndn-nan/src/lib.rs:96` records the choice
    not to invent bytes and put a fabricated claim of WFA semantics on the air.
    The cost is one data path per node. Task #23 would have negotiated real ports;
    the correction says **do not work it**.
  - Proof: two OPis, 4/4 runs with both paths up, 18–20 distinct datagrams each
    way, 0 duplicates, real IPv6 UDP over 802.11. The datagrams were ~14 bytes —
    the "bulk" in "bulk tier" has never actually been carried over NDP.
  - **This phase's premise has been reconsidered.** It is kept as an interop
    bearer and demoted from being our data path; see
    `NAMED_RADIO_COURSE_CORRECTION.md`, and the engine's own module docs, which
    now say so at the source.
- **Phase 3 — commodity-desktop NAN. [NOT BUILT]** `wpa_supplicant` NAN-USD `NanBackend`
  (control-socket: `NAN_PUBLISH`/`NAN_SUBSCRIBE`/`NAN_TRANSMIT` + events) for
  managed-mode laptops; nl80211 native `NanBackend` behind capability detection
  (future iwlwifi/FullMAC). *Witness: discovery+follow-up on an ordinary Intel/ath
  laptop with no monitor mode.* *Added 2026-07-16: the correction's §11 asks that
  NAN-USD get the survival test — it is another standard's host-centric control
  plane — **before** it is built, not after.*
- **Phase 4 — BLE backends. [NOT BUILT]** `bluer` ext-adv backend (default),
  raw-HCI backend (capability). PAwR parked as frontier. *Witness: real BLE NDN
  broadcast + Coded-PHY long-range between two hosts.*
- **Phase 5 — embedded build. [NOT BUILT]** ESP-IDF NAN `NanBackend` on C6 and/or FoA
  injection VIF on ESP32. *Witness: NDN frame desktop ↔ ESP32 over NAN or raw
  injection.*

**Frontier (not scheduled):** FTM ranging, PASN password-pairing, NAN-USD as
Wi-Fi Direct / DPP / Matter bootstrap, 6 GHz NAN, macOS AWDL-via-IO80211.

---

## 9. Risks & open questions

*Reviewed 2026-07-16, after Phases 1 and 2 went on air. Three of these four are
settled; the resolutions are more useful than the risks were, so they are
recorded rather than deleted.*

- ~~**Active monitor + injection holding DW timing** is the hard real-world
  dependency (opennan needs ath9k/nexmon-class active monitor). Confirm which of
  the stack's existing USB backends (RTL8812EU, MT7612U) can hold DW timing and
  inject NAN action frames.~~ **RETIRED.** DW timing holds. The radio that proved
  it was neither of the two guessed here: it was the **RTL8812AU**, on our own
  userspace driver, and it held DW timing well enough for a stock S23 to discover
  us and be discovered. The premise that this needed ath9k/nexmon-class hardware
  was wrong.
- **Channel-switch latency** for multi-band DWs (6→44→149) must stay within the
  16 TU window. **Still open, and the MVP did pin to ch6** — exactly as this
  bullet's fallback predicted. It stays open because multi-channel DW hopping is
  Phase 1c and unbuilt (task #19), so the latency has never been measured.
- ~~**NDPE Transport-Port/Protocol TLV codepoints, NDP-QoS layout, cipher-suite
  wire IDs** need verification against the paywalled v4.0 spec or AOSP HAL before
  Phase 2 ships byte-compatible.~~ **RESOLVED — and the method is reusable, so
  record it.** Neither the paywalled v4.0 spec nor the AOSP HAL was needed. The
  codepoints came from **Wireshark's open `wifi_nan` dissector**, whose field
  offsets and bit masks `attr.rs` mirrors directly, and they were validated by
  round-tripping real captures through **tshark**: encode our bytes, let the
  dissector read them, and check it reports the fields we meant. A dissector is a
  spec someone already paid for and published as code; when a wire format is
  paywalled, read the reader. That is now the default route for any WFA codepoint
  this stack needs.
  **The one part it did not cover, honestly:** the NDPE **Service Info sub-TLV**
  body — where the real transport port lives — is *not* in the open dissector.
  Rather than invent bytes and put a fabricated claim of WFA semantics on the
  air, Phase 2 shipped a well-known port (`NDP_PORT = 6363`), at the cost of one
  data path per node. **NDP-QoS and the cipher suites were never built at all**,
  so their layouts remain unverified — Phase 2 shipped open NDP with no security.
- **Sync drift** is opennan's documented weak point; the moving-average filter
  must be ported faithfully. **Still open — and the filter was never ported.**
  §4 above specifies a 32-sample moving-average error filter targeting < 3 TU;
  no such filter exists in `engine.rs`. Both sync paths simply **jam** the
  software TSF to the beacon's timestamp (`base_time_usec = now - timestamp`):
  once on a cluster merge, and again on every same-cluster beacon "to track
  drift". That was enough for S23 interop on a single fixed channel, so the risk
  never came due — but §4 describes a filter this codebase does not have, and
  nothing has measured our residual sync error. Treat both as unknown until
  Phase 1c forces the question.

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
