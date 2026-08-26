# NDR for FPV: a DroneBridge alternative, and CRSF-over-NDR — feasibility spike

**Question.** Can the Named Data Radio (NDR) MAC serve (a) as a DroneBridge / wifibroadcast alternative for
the FPV **datalink** (HD video down + bidirectional telemetry), and/or (b) as the transport for **CRSF** —
the RC **control** link that ExpressLRS/Crossfire run?

**Short answer.** These are two different problems with two different verdicts:
- **(a) Datalink — strong fit, do it.** NDR *is* raw 802.11 injection with a name-addressed MAC; it replaces
  WFB's transport and adds real advantages (name-multiplexing, cognitive rate/reach adaptation, the airtime
  lease, multi-radio diversity). Use the **libusb Wi-Fi backends** (8812au/mt76), not the serial bridge.
- **(b) CRSF control — protocol fit is excellent, latency fit is gated by *where the MAC runs*.** The payload
  and the named-lease MAC suit a periodic control stream almost perfectly, but ExpressLRS-class latency
  (<5–10 ms) is impossible with a **host-driven** radio — the measured interconnect tax
  (`docs/link-latency-decomposition.md`) is ~6 ms on the serial bridge and a few ms even on native libusb.
  Control-grade CRSF-over-NDR requires the **NDR MAC on the radio MCU** (the open-firmware path), and the
  **LoRa NDR firmware is the ExpressLRS-shaped answer**.

---

## The two systems, by the numbers

| | DroneBridge / wifibroadcast (WFB-ng) | CRSF (ExpressLRS / Crossfire) |
|---|---|---|
| Role | FPV **datalink**: HD video down + MAVLink telemetry | RC **control**: 16 channels up + telemetry/link-stats down |
| PHY | raw 802.11 monitor injection (RTL8812AU), broadcast | LoRa / FLRC on a dedicated 2.4 GHz/900 MHz MCU |
| Frame | UDP-in-802.11, FEC 4-of-12, MCS1, ~7 Mbit/s sum (half-duplex) | 26-byte RC frame (16×11-bit + CRC-8), tiny OTA packet |
| Rate | continuous video bitrate | 50–1000 Hz (250 Hz = 4 ms typical) |
| Latency | tens of ms (video buffered); graceful FEC falloff | single-digit ms stick-to-air; hard real-time |
| Addressing | shared link-id + channel | bound TX↔RX pair |
| Host in loop? | yes (companion computer runs WFB) | **no** — the air protocol runs on the radio MCU |

The critical structural difference is the last row: WFB tolerates a host because video is latency-tolerant;
ExpressLRS achieves its latency precisely *because there is no host* — the MCU does the air protocol directly.

---

## (a) NDR as a DroneBridge / WFB alternative — **strong fit**

WFB and NDR are the *same shape*: raw 802.11 injection, no association, broadcast, FEC. NDR is WFB with a
**named MAC** bolted on where WFB has none. Mapping is direct:

| WFB concept | NDR equivalent |
|---|---|
| link-id + channel | a **name**: `/drone/7/video`, `/drone/7/mavlink`, `/gcs/rc` (Tier-0 filter admits by prefix) |
| fixed MCS1 you pick | the **rate + reach levers**, adapted per-name from the worst-overheard receiver |
| Reed-Solomon FEC block | **link-FEC** (systematic K-of-N, `LINK_FEC_MAGIC`), per-name redundancy |
| multiple adapters for diversity | **MRMC** macrodiversity as a first-class capability |
| manual video/telemetry sharing | the **named airtime lease** (video = Bulk lane, telemetry = its own name) |

**What NDR genuinely adds over DroneBridge/OpenHD:**
1. **Name-multiplexing** — many drones and GCSs share one medium with no pairing; each stream is a name,
   admitted by the receiver's prefix filter. WFB needs a distinct link-id per link; NDR does it natively.
2. **Cognitive per-name adaptation** — WFB's fixed MCS is its known weakness (you trade range for bitrate
   once, globally). NDR adapts each name independently: video drops MCS for range while telemetry holds a
   robust rate; HE ER-SU/DCM available for the control/telemetry stream.
3. **The airtime lease** — video can't starve telemetry, because each is a named lease; WFB has no MAC.

**What NDR reuses (does not replace):** the camera → H.265 encoder → packetizer pipeline is unchanged; NDR
replaces only the *transport* (inject named frames instead of WFB frames). The GCS-side decode is unchanged.

**Backend choice — important:** the ~7 Mbit/s video budget needs a **native libusb Wi-Fi backend**
(8812au/a81a/mt76) — the *same PHY WFB uses*, so the same throughput. The **serial-bridged backends (C5/BW16)
cap at ~4.6 Mbit/s** by USB-CDC (`link-latency-decomposition.md`) — fine for telemetry, too slow for HD video.

**Verdict (a):** NDR is a credible DroneBridge alternative for the datalink today, with real advantages, on
the libusb backends. The missing piece is integration work (map streams→names, wire the video packetizer to
`inject`), not a capability gap. Prototype path: a `/drone/*` name scheme + a MAVLink-over-NDR and
video-over-NDR shim reusing the existing `MonitorWifiFace`.

---

## (b) CRSF over NDR — **protocol fits, latency depends on where the MAC runs**

### Protocol fit — excellent
A CRSF RC frame is 26 bytes — one NDR frame, trivially. The natural name map:
- `/drone/7/rc` — the 16-channel uplink (periodic, latency-critical → a **reserved Latency-class lease**).
- `/drone/7/telem` — telemetry down (battery/GPS/attitude → Bulk-ish).
- `/drone/7/linkstat` — RSSI/SNR/LQ (the CRSF `0x14` link-statistics frame).

A periodic, latency-critical, named stream is *exactly* what the reserved lane of the named airtime lease
was designed for — CRSF-over-NDR is a named TDMA control channel, stronger than ExpressLRS's CSMA-free-but-
bound model, and it multiplexes many `/*/rc` control links by name with **no binding/pairing** (ExpressLRS
binds one TX to one RX; NDR admits by prefix). The reach lever (MostRobust → base MCS + STBC/LDPC, or HE
ER-SU) is the robustness ExpressLRS gets from LoRa spreading — the same idea, a different PHY.

### Latency fit — this is the whole question, and #5 answers it
CRSF needs single-digit-ms, 250–1000 Hz. From `docs/link-latency-decomposition.md`:

| NDR path | one-way latency | 250 Hz? | 1000 Hz? | control-grade? |
|---|---|---|---|---|
| **host over serial bridge** (C5/BW16) | ~6 ms (USB-CDC ×1) | marginal | no | **no** — the bridge alone blows the budget |
| **host over native libusb** (8812au/mt76) | ~1–3 ms (host stack + libusb) | yes | marginal | telemetry + low-rate control only |
| **NDR MAC on the radio MCU** (open firmware) | tens of µs–sub-ms (no host) | yes | yes | **yes** — the ExpressLRS model |

The physics floor is µs (airtime 25–71 µs) + ns (propagation); every ms is *host + interconnect*. So:
- A **host-driven** NDR radio can carry CRSF **telemetry** and **low-rate (50–150 Hz) control** on native
  libusb — useful, but not a 500–1000 Hz stick link.
- **Control-grade** CRSF-over-NDR requires the NDR MAC to run **on the radio MCU**, removing the host from the
  control loop — which is *exactly how ExpressLRS is built*.

### The synergy: the LoRa NDR firmware is the ExpressLRS-shaped path
ExpressLRS = LoRa/FLRC PHY + the air protocol on a dedicated MCU. **Our LoRa NDR firmware** (Waveshare SX1262
+ GD32) already runs an **on-device NDN data plane** (name filter, dedup, relay, CS-serve, CSMA) with **no
host in the loop** — the same architecture. CRSF-over-NDR most naturally lands there: parse CRSF on the FC
UART, carry the 26-byte RC frame as a named LoRa NDR frame, and the latency is LoRa airtime + on-MCU
processing (µs–low-ms), not a host round-trip. This is the path that can actually hit ExpressLRS rates, and
it reuses firmware we already have. (The AR9271 open Wi-Fi firmware is the higher-bandwidth analog for the
same "MAC on the MCU" principle.)

### Verdict (b)
- **Telemetry / link-stats over NDR:** feasible now, any backend — it's just named periodic frames.
- **Low-rate control (≤150 Hz) over host libusb:** feasible now; a `CRSF↔NDR` bridge parsing the FC UART.
- **ExpressLRS-class control (250–1000 Hz, <5 ms):** requires the **NDR MAC on the radio MCU**; the **LoRa
  NDR firmware is the right vehicle** (host-out-of-loop, LoRa PHY, on-device NDN plane already built).
- Do **not** attempt control-grade CRSF over a serial-bridged (USB-CDC) radio — #5 proves the bridge alone
  eats the budget.

---

## Recommended prototype path (smallest steps first)

1. **CRSF↔NDR bridge** (host, any backend): parse CRSF frames from a FC/handset UART, map to `/drone/N/{rc,
   telem,linkstat}`, carry over `MonitorWifiFace`. Proves the protocol mapping + telemetry + low-rate control.
   Measures the real round-trip with `link_latency.py`-style instrumentation → sets the honest rate ceiling.
2. **Datalink shim** (host, libusb): MAVLink-over-NDR + video-over-NDR reusing the existing inject path; the
   DroneBridge-alternative datalink. Reuses the camera/encoder, replaces the transport.
3. **CRSF-on-LoRa-NDR-firmware** (on-MCU): move the CRSF-frame carriage into the LoRa NDR firmware's data
   plane — the ExpressLRS-shaped control link, host out of the loop. The path to control-grade latency.

## What NDR uniquely offers an FPV/RC link (vs DroneBridge + ExpressLRS as separate systems)
- **One named fabric for video + telemetry + control** — three names, one MAC, instead of a WFB datalink
  plus a separate ExpressLRS control radio.
- **No pairing/binding** — `/droneA/rc`, `/droneB/rc`, `/gcs/*` multiplex by name; add a drone by naming it.
- **Cognitive reach adaptation per stream** and **multi-radio diversity** as first-class capabilities.
- **Deterministic latency by name** — the reserved Latency lane is a named-TDMA guarantee for the control
  stream, once the MAC runs where the latency budget allows (on the MCU).

---

*Sources: [tbs-crsf-spec](https://github.com/tbs-fpv/tbs-crsf-spec/blob/main/crsf.md),
[ExpressLRS](https://www.expresslrs.org/), [DroneBridge](https://github.com/DroneBridge/DroneBridge),
[wifibroadcast/WFB-ng via PX4](https://docs.px4.io/main/en/companion_computer/video_streaming_wfb_ng_wifi.html).
Latency figures measured in `docs/link-latency-decomposition.md`.*
