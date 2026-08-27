# Named-data radio (monitor-mode WiFi) — *extension*

> **Non-standard extension.** Nothing here is an NDN community spec. It is a
> pragmatic bearer that carries spec NDN (Packet Format v0.3 + NDNLPv2) over a
> raw radio. `ndn-face-monitor-wifi` is `[package.metadata.scope] = "extension"`.

> **Doc location.** This doc lives at `crates/faces/ndn-face-monitor-wifi/docs/`
> and is **tracked**. It was gitignored until 2026-07-16 — which is how the
> doctrine below came to be contradicted by an in-tree, reviewed design without
> anyone noticing. The doctrine is now versioned; the rest of this directory
> remains staging. Read it together with
> [`../../ndn-face-wifi-aware/docs/NAMED_RADIO_COURSE_CORRECTION.md`](../../ndn-face-wifi-aware/docs/NAMED_RADIO_COURSE_CORRECTION.md),
> which is authoritative where the two disagree.

`ndn-face-monitor-wifi` is a **connectionless 802.11 monitor-mode injection
face** — the data-centric reframing of wfb-ng, with association, MAC addressing,
and ARQ discarded. There is no destination address: the **NDN name is the
addressing**. Every monitor-mode receiver in range hears every injected frame
and evaluates it against its own PIT/FIB/CS.

It is **one bearer** in a much larger named-data-radio vision (see
[Status](#scope--status) below); it is the slice that runs on ~$60 of commodity
hardware today by riding the existing 802.11 OFDM PHY rather than a custom one.

## The two walls, and why monitor mode clears them

* **Legacy-rate wall.** Managed-mode multicast falls back to a basic rate
  (1/6/24 Mbps) because group-addressed frames get no ACKs, so the AP can't
  rate-adapt. That is a property of the *managed-mode MAC*, not the radio. A
  monitor-mode **injected** frame carries its own rate/MCS in the radiotap TX
  header — we pick the MCS per frame, near link rate, no AP floor.
* **No ARQ / no rate feedback.** What injection gives up, the architecture
  already replaces: loss → FEC/RLNC (`ndn-coding`) instead of retransmits;
  rate feedback → per-frame RSSI in the cross-layer signal store
  (`ndn-signals-core`) driving adaptive MCS, instead of a MAC back-channel.

## Layers

| Layer | Entry point | Use |
|-------|-------------|-----|
| transport | `MonitorWifiFace` | a `Face` (`FaceKind::Wfb`, `AdHoc`); rides `LpLinkService` for NDNLPv2 fragmentation |
| backend | `FrameIo` (owned by `ndn-radio-hal`; re-exported here) | inject/recv raw frames — `AfPacketBackend` (Linux `SOCK_RAW`), the userspace libusb drivers (re-exported under the `libusb-backend` feature; they now live in the separate `ndn-radio-drivers` repo), or `LoopbackMonitorBus` (CI) |
| framing | `frame::build` / `frame::parse` (radiotap) · `frame::build_dot11` / `frame::parse_dot11` (bare 802.11, for HW backends with their own descriptor) | platform-neutral `radiotap ++ 802.11 ++ body` per `FrameFormat` |
| rate | `radiotap::build_tx_header` / `build_tx_legacy` | per-frame MCS (defeats the legacy wall) or legacy rate |
| adapt | `McsPolicy` / `mcs_for_rssi` | RSSI-driven MCS selection from observed signal |

`FrameFormat` multiplexes wire formats on one monitor interface:
`RawNdn { ethertype }` (our peers), `EspNow { oui }` (ESP32 interop), and the
reserved `Wfb` / `HaLowVendorAction` variants. All on-air (de)framing lives in
the platform-neutral `frame.rs` (in `ndn-frame-io`), so every format is
unit-tested off-target; only the socket / USB I/O is platform-specific.

```rust
use ndn_face_monitor_wifi::{AfPacketBackend, FrameFormat, MonitorWifiFace};
use ndn_transport::FaceId;
use std::sync::Arc;

// Linux, CAP_NET_RAW, interface already in monitor mode.
let backend = Arc::new(AfPacketBackend::new("wlan0", FrameFormat::default())?);
let face = MonitorWifiFace::new(FaceId(1), backend)
    .with_adaptive_mcs()       // pick MCS from observed RSSI
    .into_face();              // pairs LpLinkService for fragmentation
```

## ESP-NOW interop

`FrameFormat::EspNow` builds/parses the ESP-NOW vendor-action frame (802.11
Action, category `0x7f`, OUI `18:fe:34`, element type `0x04`, version `0x02`),
so a $5 ESP32 running stock `esp-wifi` ESP-NOW is a named-data peer. The
companion firmware is the `ndn-espnow` project (no_std esp-hal + esp-radio),
**now ported to the dual-band ESP32-C5** (RISC-V). ESP-NOW bodies are ≤250 B, so
an ESP-NOW face sets a small MTU.

First-class ESP-NOW face path:

```rust
use ndn_face_monitor_wifi::{ESPNOW_OUI, FrameFormat, MonitorWifiFace, ESPNOW_MTU};

// Linux AF_PACKET:
let backend = Arc::new(AfPacketBackend::new("wlan0", FrameFormat::EspNow { oui: ESPNOW_OUI })?);
let face = MonitorWifiFace::espnow(FaceId(1), backend).into_face(); // MTU = ESPNOW_MTU (250)

// macOS / no kernel monitor driver — one call, opens the dongle in 5 GHz
// monitor mode and sets the ESP-NOW format (libusb-backend feature):
let face = MonitorWifiFace::open_libusb_espnow(FaceId(1), /* channel */ 36)?.into_face();
```

Both `AfPacketBackend` and `LibUsbRtl88xxBackend` share the exact on-air ESP-NOW
byte layout via `frame::build_dot11` / `frame::parse_dot11`. On 5 GHz inject at a
basic OFDM rate (6 Mbps, `NDN_RADIO_TX_RATE=4`) — 1 Mbps DSSS does not exist on
5 GHz. See [`esp-now-c5-dual-band-2026-06-17.md`](esp-now-c5-dual-band-2026-06-17.md)
for the C5 bring-up and the bidirectional 5 GHz on-air result.

## Hardware validation

Proven over the air on two Orange Pi 5 Pro + RTL8812EU (svpcom `8812eu`), the
userspace libusb RTL8812EU/8822E backend on macOS, an ESP32-S3, and an
**ESP32-C5** (dual-band):

* **Rate wall (Phase 0):** injected MCS0/3/7 captured at exactly the requested
  index — the wall is a managed-mode artifact (`testbed/bench/wifi_inject_rate.sh`).
* **Round-trip (Phase 1):** real Interest/Data over the air with NDNLPv2
  fragment reassembly (`examples/monitor_roundtrip.rs`).
* **FEC (Phase 4):** K-of-N recovery (`ndn-coding` engine-free codec) hit **100%**
  delivery at object sizes where uncoded multi-fragment dropped to 37–60%.
  *Re-read this baseline with suspicion (2026-07-16):* two bugs in our own stack
  were depressing multi-fragment delivery — `MONITOR_MTU` was 2296, 24 too large,
  so every full-MTU LP fragment went on air at 2328 B and the radio silently
  dropped it (ndn-rs e81c9922); and the 8812AU had no RX pump, a bulk-IN read
  being in flight only *during* a `recv_frame` call, so back-to-back fragments
  arrived with nothing draining the FIFO (ndn-ext 7d65d80). The FEC result stands
  as measured; what is no longer safe is the *inference* that connectionless
  multi-fragment delivery is intrinsically poor. It was our off-by-24 and our
  missing reader thread. The raw radio is blameless: 2200/2260/2300 B frames
  deliver 100%, 2312 B+ never arrive — correct 802.11 behaviour.
* **ESP-NOW (Phase 3) — bidirectional on 5 GHz (2026-06-17):** with a dual-band
  **ESP32-C5** in `BandMode::_5G` on channel 36 and the RTL8812EU driven from
  macOS via the libusb backend, **both** directions work: C5 → dongle (NDN
  Interest `/esp/hello` received, RSSI ≈ −44) and dongle → C5 (injected ESP-NOW
  received by the C5). This closes the long-standing "M2" gap — the reverse
  direction the 2.4 GHz-only ESP32-S3 could never close, because these wfb
  dongles inject on 5 GHz only.

## Scope & status

This face is the **monitor-mode-WiFi slice** of the named-data-radio vision. The
vision is radio-agnostic: names should seed not just *which frame* but *which
spectrum, hop sequence, and modulation*. We built the part that rides 802.11's
existing PHY; the software-defined-PHY part is largely future work.

| Theme | Status |
|-------|--------|
| WiFi monitor-mode injection face | **built** (this crate) |
| Per-frame MCS / rate selection (defeats legacy wall) | **built** |
| RLNC/FEC over broadcast | **built** (`ndn-coding` core) |
| NDNLPv2 fragmentation/reassembly | **built** |
| RSSI cross-layer signals + adaptive MCS | **built** |
| ESP-NOW bearer + ESP32 peer | **built** (bidirectional on 5 GHz with the dual-band ESP32-C5; 2.4 GHz with the S3) |
| First-class ESP-NOW face (`MonitorWifiFace::espnow` / `open_libusb_espnow`) | **built** |
| Userspace libusb backend (RTL8812EU/8822E) — non-Linux portability | **built** (5 GHz monitor inject/RX on macOS) |
| BLE advertising face | built (`ndn-face-ble-adv`) |
| WiFi Aware (NAN) face | built — **and since superseded, see the 2026-07-16 note below** |
| Userspace NAN engine + driver (mutual discovery with a stock Samsung S23) | **built** (`ndn-nan` std face, `ndn-nan-core` sans-IO engine) |
| NAN rendezvous as a strategy, not engine internals | **built** (`ndn-nan-core/src/rendezvous.rs`: `DiscoveryWindow` / `AlwaysOn`) |
| NDP/NDPE data path (M1–M4 handshake, NDI TAP, `request_ndp()` → bound UDP socket) | **built** — an *interop bearer*, **not our data path** |
| CCLF forwarder election | built (`ndn-strategy-cclf`) |
| No-host-addressing / verify-on-decode doctrine | built (doctrine) — **and this doc was gitignored, so nothing enforced it** |
| **Distributed diversity reception** (macrodiversity, swarm aggregator) | designed, **not built** |
| **Friend-forwarder** for sleepy/low-power nodes | designed, not built |
| Fragment-stream-key reassembly (bearer-keyed) | not built |
| **Name-seeded FHSS** + narrow-channel spectrum + demand widening | designed, **not built** — needs SDR |
| **Custom modulation** (GFSK/GMSK/CSS/DSSS) on SDR | designed, not built — needs SDR (AD9363/Zynq) |
| Time-sync + coordination-announcement (FHSS prerequisites) | designed, not built |
| HaLow (802.11ah) bearer | future — needs Morse Micro hardware |
| LoRa / SX1262 bearer | future — needs hardware |
| ESP32 Tier B (raw NDN-ethertype 802.11, not ESP-NOW) | future |

The largest **software-buildable** gaps (no exotic hardware) are distributed
diversity reception (rides the FEC we already have) and the friend-forwarder.
The largest **vision** gap is the software-defined PHY (FHSS + modulation by
name), which gates on SDR hardware and a DSP effort — that is the part where a
*name* tunes the actual radio, not just the frame.

## Status-board correction — 2026-07-16

The board above was written before the userspace NAN work and had gone stale in a
way that mattered, so record what changed rather than quietly restating it.

**What the board understated.** "WiFi Aware (NAN) face — built" described a thin
face. Since then Phase 1 (monitor-mode NAN engine + our own userspace RTL8812AU
driver) achieved *mutual* Wi-Fi Aware discovery with a stock Samsung S23, and
Phase 2 built the full NDP/NDPE data path — M1–M4 handshake, NDPE codec, NDI TAP
interface, proven between two Orange Pis (4/4 runs, both paths up, 18–20 distinct
datagrams each way, zero duplicates). Any claim elsewhere that "only a loopback
backend exists" is false.

**What the board could not have said, and is the point of this doc.** That NDP
data path is **NDN-over-UDP-over-IPv6-over-Ethernet-over-802.11** — every
host-centric layer this doc exists to reject, faithfully reproduced. It is
legitimate as an **interop bearer** for reaching phones we do not control. It is
not our data path. Our own traffic rides `FrameFormat::RawNdn`, where the name is
the addressing. The `NAMED_RADIO_COURSE_CORRECTION.md` companion is the full
argument.

The mechanism of the drift is worth naming: this doc was gitignored while the
plan that contradicts it was in-tree and reviewed. `ARCHITECTURE.md:357` justified
the NDP bulk tier on the grounds that "connectionless small-frame faces are lossy
for multi-fragment objects." That was true when written, and it was true because
of an off-by-24 MTU and a missing reader thread in our own stack (see the FEC note
above), both fixed 2026-07-16. It was never intrinsic to name-addressed broadcast.
