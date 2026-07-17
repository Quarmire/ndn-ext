# The named-radio subsystem (`ndn-face-monitor-wifi`)

> Audience: both humans and LLMs working on this crate. It explains *what* this
> subsystem is, *why* it is shaped the way it is (the conceptual break from how
> radios are managed in IP networks), *how* a radio backend plugs in, and where
> the hard-won device details live so they are not re-derived. Identifiers are
> given as `file:symbol` so they can be jumped to.

---

## 1. TL;DR

The **named-radio subsystem** turns commodity USB Wi‑Fi dongles into *userspace
radio backends for NDN*. It is three crates, and knowing which owns what is the
first thing to get right:

| crate | owns |
|---|---|
| **`ndn-radio-hal`** (`ndn-rs/crates/core/ndn-radio-hal`) | the **contract**: `FrameIo`, `WifiRadio`, `TxIntent`, `InjectFrame`, `CapturedFrame`, `McsDescriptor`, `McsPolicy`, `RadioKnobs`, `Bandwidth`, `RadioCapability`, `RadioKind`, `Band`, `TimingModel`. |
| **`ndn-radio-drivers`** (a sibling repo, `~/Documents/Dev/ndn-workspace/ndn-radio-drivers`) | the **drivers**: every userspace chip port and its `FrameIo` / `RadioKnobs` impls. |
| **`ndn-face-monitor-wifi`** (*this* crate) | the **face and the seam**: `MonitorWifiFace` (the NDN `Transport`), `control::RadioControl` (the sense→decide→act binding to `ndn-radio-cognition`), `measure` (the airtime optimand), `channel_manager` (nl80211 tuning), and `radio.rs` — which is now only a re-export of the HAL's `RadioKnobs`/`Bandwidth`. |

*(Historical note, 2026-07: this crate used to hold all of the above. `FrameIo` and
friends moved down to `ndn-radio-hal` so a driver depends on one contract crate;
the drivers then moved out to their own repo. `ndn-frame-io` and
`ndn-radio-cognition` re-export the HAL types, and `src/lib.rs` re-exports the
drivers under the `libusb-backend` / `bw16` features, so every existing
`ndn_face_monitor_wifi::…` path still resolves. Only the **ownership** changed —
but a doc that says "this crate implements `FrameIo`" is now wrong, and paths like
`src/mt7612/` are dead links.)*

A backend implements one data-plane trait ([`FrameIo`]) — plus [`WifiRadio`] if it
can be told an exact 802.11 rate — and one control-plane trait ([`RadioKnobs`]),
and declares what it can do (`RadioCapability`). `MonitorWifiFace` and the
cognitive control plane drive any backend through those traits without knowing
which chip it is.

The ports, all now in **`ndn-radio-drivers/src/`**:

| backend | chip | role | TX radiates? |
|---|---|---|---|
| `LibUsbRtl88xxBackend` (`libusb_rtl88xx.rs`) | RTL8812EU / 8822E | feature-rich 5 GHz data radio (the A-MSDU reference) | descriptor-correct; full RF cal partial |
| `Mt7612uBackend` (`mt7612/`) | MediaTek MT7612U (mt76x2u) | TX-capable 2.4/5 GHz | **yes — verified on-air** |
| `Rtl8812auBackend` (`rtl8812au.rs`) | RTL8812AU | the NAN/Wi-Fi-Aware workhorse | **yes — TX+RX on air; carried mutual Wi-Fi Aware discovery with a stock Samsung S23, and the NDP data path between two OPis** |
| `Rtl8821cuBackend` (`rtl8821c/`) | RTL8821CU | RX-only (TX firmware-gated) | no |
| `Rtl8733buBackend` (`libusb_rtl8733b.rs`) | RTL8731BU / 8733BU (1x1) | ground-up port, **honestly paused** at M4 | not yet |
| `Bw16SerialBackend` (`bw16_serial.rs`) | RTL8720DN dev board over USB-serial | serial-bridged `FrameIo` | unproven — pending a firmware flash |
| `LoraSerialBackend` (`lora_serial.rs`) | SX1262 (Waveshare USB dongle) | the sub-GHz reach radio — *not* Wi-Fi, and the proof the HAL is bearer-agnostic | **yes — on-air link verified between two OPis** |

---

## 2. Why this is different: IP radio vs **named radio**

This is the single most important thing to internalise, because it dictates every
interface choice below.

### How radios are managed in an IP network (the thing we are *not* doing)

In a conventional IP stack a radio is **an interface** — `wlan0` — owned by a
kernel driver that hides the silicon behind a tall, stateful protocol stack:
802.11 association to one BSS, then DHCP, then an IP address, then routing/NAT
above that. Consequences:

- **One radio = one uncooperative silo.** It associates to a single AP, holds a
  single IP, and runs *its own* rate control, power, and channel logic privately.
  Two radios on the same node do not share a view of the medium or schedule
  jointly; they contend blindly.
- **The radio is a dumb pipe.** Its real capabilities — modulation/coding, MIMO
  streams, channel width, TX power, energy-detect thresholds — are buried in the
  driver and exposed (if at all) per-interface. The network layer cannot reason
  about them.
- **Addressing is by host.** Frames are addressed to MAC/IP endpoints. *What* the
  data is (its name) is irrelevant to the radio.
- **Adding a radio is a burden.** Another interface to configure, bridge, route
  over — and it still won't cooperate with the others.

### What we do instead: a radio is a **pool of stateful capability**

In NDN the *name* of the data is the address. A radio here is not an interface
with an IP — it is a **declared bundle of capabilities** (`RadioCapability`:
band, max MCS/NSS/bandwidth, channels, TX-power ceiling, agility, rx-only) thrown
into a *shared medium model* that the control plane reasons over globally:

- **Capabilities are pooled and composable.** A high-rate 5 GHz radio, a
  long-range sub-GHz radio, and an RX-only SDR sensor all serve the *same* named
  data, each used for what it is best at — the control plane maps each named
  object to the radio(s) that fit it (`RadioPolicy::decide`), rather than pinning
  data to an interface.
- **Radios cooperate.** They share medium state and do cooperative sensing
  (neighbours exchange `ReceptionReport`s), so power/channel/contention decisions
  are *joint*, and reception is pooled across radios (macrodiversity) instead of
  per-link.
- **Control is a loop, not a config.** `RadioControl` runs **sense → decide →
  act** every tick: fold RSSI / demand / occupancy into the medium (SENSE), ask
  the policy per named object what to do (DECIDE), and push the slow knobs +
  per-frame rate to the radios (ACT). Delivery success/failure feeds back as
  reward (`observe_delivery`).
- **The knobs are first-class.** Everything the IP stack hides — MCS, STBC, LDPC,
  CSD, channel width (including non-standard 5/10 MHz), EDCCA — is an explicit
  actuator in the alphabet the policy chooses from (`TxParams`).

### Where monitor-mode Wi‑Fi fits (the bridge)

Commodity Wi‑Fi hardware normally only exists as the IP-interface silo above.
**Monitor mode is the bridge:** it strips association/IP entirely and gives raw
802.11 frame *inject* and *capture*. That is exactly the [`FrameIo`] surface —
so a $15 dongle becomes a raw capability the named-radio plane can orchestrate
by name, not a `wlan0` you route over.

This bridge is significant (it makes ubiquitous hardware usable), but it is still
*a bridge*. The full named-radio concept spans arbitrary radios (SDR, LoRa,
mmWave) as pooled capability; monitor-mode Wi‑Fi is the first and most practical
on-ramp, not the destination. This document is about the on-ramp — for the full
vision and the data-centric framing see the sibling docs
[`named-radio.md`](./named-radio.md) and
[`named-radio-vision-frontier.md`](./named-radio-vision-frontier.md).

---

## 3. Architecture: two seams

A radio has a fast **data plane** and a slow **control plane**, and they are
separate traits owned by separate crates. A backend is "a `FrameIo` impl plus a
`RadioKnobs` impl, with a declared `RadioCapability`."

```
                    ndn-radio-cognition (pure decision engine)
                     RadioPolicy / MediumState / TxParams
                                      │  decide()
                                      ▼
   control::RadioControl  ── sense ──▶ decide ──▶ act ──┐         (this crate)
       (LinkServiceFeature tick: SENSE→DECIDE→ACT)      │
                                                        │ apply(RadioAllocation)
                  ┌─────────────────────────────────────┤
                  ▼ (slow, stateful)                     ▼ (per-frame rate via cell)
            RadioKnobs                              MonitorWifiFace
       set_channel / set_tx_power                  (NDN Transport: MTU, name-group
       set_tx_csd / set_edcca_ignore                addressing, FEC, A-MSDU batching)
                  │                                       │ inject_at / recv_frame
                  └──────────────┬────────────────────────┘
                                 ▼
                  FrameIo / WifiRadio / RadioKnobs / RadioCapability
                            (the contract: ndn-radio-hal)
                inject(InjectFrame{tx: TxIntent}) — the backend resolves it
                inject_at(InjectFrame, McsDescriptor) — an exact rate
                        recv_frame() -> CapturedFrame
                                 ▼
              concrete backend (RTL8812AU / MT7612U / SX1262 / …)
                            (ndn-radio-drivers)
                                 ▼
                              USB / silicon / air
```

### 3.1 Data plane — [`FrameIo`]

Defined in **`ndn-rs/crates/core/ndn-radio-hal/src/lib.rs`** (not this crate), and
re-exported by `ndn-frame-io` (so `ndn_frame_io::FrameIo` still resolves), so it is
shared with every other frame transport (loopback, AF_PACKET, LoRa, …):

```rust
#[async_trait]
pub trait FrameIo: Send + Sync + 'static {
    async fn inject(&self, frame: InjectFrame) -> Result<(), FaceError>;
    async fn inject_batch(&self, frames: Vec<InjectFrame>) -> Result<(), FaceError>; // default loops inject
    async fn recv_frame(&self) -> Result<CapturedFrame, FaceError>;                  // single-consumer
}

#[async_trait]
pub trait WifiRadio: FrameIo {                                    // 802.11 backends only
    async fn inject_at(&self, frame: InjectFrame, mcs: McsDescriptor) -> Result<(), FaceError>;
    async fn inject_batch_at(&self, frames: Vec<(InjectFrame, McsDescriptor)>) -> Result<(), FaceError>;
}
```

- `InjectFrame { payload: Bytes, tx: TxIntent, dst: [u8;6], src: [u8;6] }` —
  what rides per-frame is **intent, not a rate**: `TxIntent { reliability, reach }`,
  where `reliability` is `MostRobust | Balanced | Throughput` and `reach` is
  `Broadcast | Group`. The backend resolves intent to its own PHY
  (`McsDescriptor::for_intent` on 802.11; a spreading factor on LoRa).
  `dst`/`src` are name-derived group MACs, not host IDs.
- **The exact rate travels on a different call.** A caller that has *already*
  resolved a concrete `McsDescriptor { index, short_gi, vht, nss, stbc, ldpc }` —
  a fixed-rate bench, or the cognitive face whose plan cell names an MCS — uses
  [`WifiRadio`]`::inject_at`. This is the 2026-07 correction to the older design in
  which `InjectFrame.mcs` carried the rate: on a broadcast, un-ACKed medium there
  is no per-receiver feedback to rate-adapt against, so the *default* seam should
  state a goal and let the bearer meet it — and a non-802.11 backend should not
  have to pretend an MCS index means something. Docs that say the per-frame rate
  rides on `InjectFrame.mcs` predate this.
- `CapturedFrame { payload, addr, group, rssi_dbm, mcs_index }`.
- The shared **`frame::build_dot11` / `frame::parse_dot11`** build/parse the bare
  802.11 frame for the active `FrameFormat` (NDN ethertype `0x8624` by default,
  ESP‑NOW, …). Backends reuse these so all backends speak the same wire format —
  the chip-specific part is only the TX descriptor and RX descriptor around the
  802.11 frame.

### 3.2 Control plane — [`RadioKnobs`] (`ndn-radio-hal`, re-exported by `src/radio.rs`)

The *slow, stateful* knobs. Only `set_channel` is required; the rest default to
no-ops so a port "adds capability uniformly" — it works the day it can tune, and
grows power/CSD/EDCCA as those are ported, with no change to the trait or the
control plane.

```rust
pub trait RadioKnobs: Send + Sync {
    fn set_channel(&self, channel: u8, bw: Bandwidth) -> Result<(), FaceError>;
    fn set_tx_power(&self, _idx: u32) -> Result<(), FaceError> { Ok(()) }             // default no-op
    fn set_tx_csd(&self, _on: bool) -> Result<(), FaceError> { Ok(()) }               // default no-op
    fn set_edcca_ignore(&self, _on: bool) -> Result<(), FaceError> { Ok(()) }         // default no-op
    fn set_spreading_factor(&self, _sf: u8) -> Result<(), FaceError> { Ok(()) }       // default no-op (LoRa)
    // …and the LoRa coding-rate dial; see ndn-radio-hal for the full list.
}
```

That the trait now also carries `set_spreading_factor` is the uniform-capability
rule doing its job in the other direction: the sub-GHz reach dial was added for the
SX1262 without any Wi-Fi backend, or the control plane, changing a line — an
optional knob only the radio that has it overrides. Cognition drives SF the way it
drives MCS (down for close/bulk, up for far/urgent).

The trait and the enum moved down into `ndn-radio-hal` (so a driver depends on one
contract crate); `src/radio.rs` is now a `pub use ndn_radio_hal::{Bandwidth,
RadioKnobs}` plus the rationale above it, and the `RadioKnobs` impls travel with
their backend types in `ndn-radio-drivers` (the orphan rule requires it, now that
both trait and types are foreign to this crate).

`Bandwidth { Bw20, Bw40, Bw80, Nb10, Nb5 }` carries `code()`/`from_code()`
matching `WifiRate.bw` / `RateCapability::Wifi { max_bw, .. }`
(`0=20,1=40,2=80,3=10,4=5`).

The cognition plane reaches these knobs through the `RadioActuators` trait
(`ndn-radio-cognition`, one method `apply(&RadioAllocation)`); `control.rs`'s
`LibUsbActuator` is the adapter that maps a decided `TxParams` slice onto the
`RadioKnobs` setters + writes the per-frame `TxParams` into a shared cell the
face's `select_mcs` reads. `LibUsbActuator` holds an `Arc<dyn RadioKnobs>`, so it
drives **any** backend — `RadioControl::libusb_actuator(radio, backend)` takes an
`Arc<dyn RadioKnobs>` and an `Arc<ConcreteBackend>` coerces in at the call site.
MT7612 plugs in identically to RTL (see `examples/mt7612_cognition.rs`).

### 3.3 Capability — `RadioCapability` (`ndn-radio-hal`, re-exported by `ndn-radio-cognition`)

The declaration that makes a radio "a pool of capability": `kind, bands, rate,
channels, max_tx_power, agile, rx_only, timing, duty_cycle_max, max_payload,
half_duplex`. Registered via `RadioControl::register_radio(radio_id, face,
capability)` (`control.rs:202`). This is the single switch between the homogeneous
(identical radios → channel assignment + spatial reuse) and heterogeneous
(divergent radios → object→radio fit) regimes.

Two shape changes since this doc was first written, both driven by making LoRa a
first-class radio rather than a special case:

- **No bearer's rate model is privileged.** The old flat `max_mcs/max_nss/max_bw`
  became `rate: RateCapability`, a sum: `None` (an RX-only sensor) | `Wifi {
  max_mcs, max_nss, max_bw }` | `Lora { min_sf, max_sf }`. A bearer-agnostic
  consumer reads the reach/rate tradeoff through `rate_rank()`; a Wi-Fi-specific
  one uses the typed accessors. LoRa has no MCS and Wi-Fi has no spreading factor,
  and the descriptor now says so instead of pretending.
- **`band` became `bands: Vec<Band>`** (several parts are dual-band), and the
  descriptor grew the bearer-agnostic operational axes a heterogeneous planner
  needs: `timing: TimingModel { AlwaysOn | DutyCycled }` (a *description* of the
  radio's duty behaviour; nothing reads it to pick a rendezvous mode today — see
  §4.1), `duty_cycle_max` (LoRa sub-GHz is ~0.01),
  `max_payload`, and `half_duplex`. The point is that a new PHY can be *described*
  rather than special-cased.

The mirror of this on the actuator side is `TxParams { link_fec_redundancy,
edcca_ignore, tx_power, rate: RateParams }`, where `RateParams` is the same kind of
sum (`None | Wifi(WifiRate) | Lora(LoraRate)`) — so the three knobs that are
genuinely bearer-agnostic sit at the top level and the PHY-specific ones are
quarantined in the arm.

> **How much of that reaches the air, as of 2026-07-17.** `RadioControl::apply`
> (`control.rs`) actuates channel+bandwidth, CSD, `edcca_ignore`, `tx_power`, and
> LoRa's SF/CR, then hands the whole `TxParams` to the face's `planned` cell, where
> `select_mcs` reads the rate fields per frame. So `rate`, `tx_power`, and
> `edcca_ignore` are wired.
>
> **`link_fec_redundancy` is not.** It rides into that same `planned` cell and
> nothing in the send path ever reads it: no code emits a parity frame or otherwise
> changes a transmission because of it. Of its 16 references across both repos,
> `policy.rs` decides it, `contextual.rs` mutates it, `measure.rs::score_arm`
> *models* it offline (as repetition, for scoring arms), and `control.rs:602` logs
> it. None actuate. Meanwhile FEC demonstrably works: coded beat uncoded at every
> object size, measured contemporaneously (800 B 23/30 vs 10/30, 2200 B 6/30 vs
> 1/30) — but that is application-layer `ndn-coding`, driven by the bench's
> `coded_shape`, not by the plan. Task #32.
>
> Separately, the rate axis is wired but **mostly unemittable on this part**: the
> 8812AU puts only DESC `0x04` (legacy 6M) and `0x0c` (HT MCS0) on air; `0x0b`,
> `0x10`, `0x13` measured 0/90 at *every* frame size, shortest included (task #31).
> That is a driver gap, not a wiring gap — do not conflate them.
>
> *(An earlier revision of this note claimed `grep` found `link_fec_redundancy`
> "read only by cognition and its tests. No face, no driver." That was produced by a
> grep truncated with `head -10`, which cut off the two references in this very
> crate. The conclusion survived; the evidence for it did not. Corrected 2026-07-17
> — and it is precisely the truncated-evidence trap this project keeps re-learning.)*

---

## 4. How it integrates with `ndn-rs`

- **`MonitorWifiFace`** (`src/lib.rs`) is the NDN `Transport`. It holds a
  `backend: Arc<dyn FrameIo>` and owns the NDN-face concerns *above* the frame
  substrate: MTU/fragmentation (`LpLinkService`), name-group addressing &
  hardware group-filtering, RSSI capture → `SignalStore`, adaptive MCS, optional
  link-FEC (`FaceFec`), and A-MSDU batching (`TxBatcher`). It is device-agnostic.
- **`control::RadioControl`** is a `LinkServiceFeature`: the engine's per-face
  tick drives `tick_now`, which is the SENSE→DECIDE→ACT loop binding the pure
  `ndn-radio-cognition` engine to real radios. Data in: RSSI (from the face's
  `SignalStore`), PIT-shadow demand (`on_interest`/`on_data`), occupancy,
  neighbour reception reports. Decisions out: `RadioPlan` per named object.
  Commands back: `actuator.apply` → `RadioKnobs` + the per-frame `TxParams` cell.
  Reward back: `observe_delivery`.
- **`measure.rs`** scores the *real* adaptive loop against fixed-rate baselines
  (airtime per satisfied Interest) — the optimand, not a reimplementation.

Net data path of one received frame: USB bulk-IN → backend `recv_frame` →
`CapturedFrame` (with RSSI) → `MonitorWifiFace` → `SignalStore` (feeds SENSE) +
NDN LpPacket up the stack. One sent Interest/Data: NDN → `MonitorWifiFace`
(fragment, name-group MAC, choose MCS from the planned cell) → `FrameIo::inject`
→ backend TX descriptor → USB bulk-OUT → air.

### 4.1 Where the Wi‑Fi Aware (NAN) stack fits — and the one exception in it

This document went a long time without mentioning NAN, and that silence had a
cost: the doctrine of §2 was stated here while a bearer that contradicts it was
built next door, and nothing in this file objected. So, honestly:

**What it is.** `ndn-nan-core` is a sans-IO Wi-Fi Aware engine; `ndn-nan` is its
std driver (`FrameIo` + tokio); `ndn-face-wifi-aware` is the NDN face over it.
They sit *above* the same seam this document describes — NAN injects and captures
802.11 management frames through `FrameIo` under `FrameFormat::Raw80211`, over the
same `Rtl8812auBackend` in `ndn-radio-drivers`. Proven, not sketched: mutual
Wi-Fi Aware discovery with a stock Samsung S23 over our own userspace driver, and
an NDP data path between two OPis.

**Its coordination tier is name-native and belongs here.** Service
publish/subscribe becomes an NDN `DiscoveryProtocol`; follow-up messages are the
face's Interests and small Data. No association, no host address — names on a
broadcast medium, exactly the §2 argument. The rendezvous machinery is a good
citizen too: Discovery Windows were lifted out of the engine into a strategy
(`ndn-nan-core/src/rendezvous.rs`: `DiscoveryWindow` / `AlwaysOn`), so a DW is one
implementation among several rather than a foundation.

That seam is real but only half-wired, and the honest version matters (2026-07-16):
the caller injects the strategy through `NanEngine::with_rendezvous`
(engine.rs:365), and `NanEngine::new` hardcodes `Box::new(DiscoveryWindow)`
(engine.rs:355). The only production construction site — `ndn-nan/src/lib.rs:189` —
uses plain `new`, so every shipped NAN node runs a DW and `AlwaysOn` has no
non-test caller in either repo. `TimingModel` is a HAL capability descriptor that
the NAN stack has never read (`grep -rn TimingModel` over `ndn-nan-core/src` and
`ndn-nan/src` returns nothing); the name collision with `rendezvous::AlwaysOn` is
a coincidence, not a wiring. Selecting rendezvous from the radio's declared
`TimingModel` is the obvious next step and is the "declared capability, not a
special case" move of §3.3 — it is not built.

**Its data path is the exception, and it is a documented one.** `request_ndp()`
runs the M1–M4 NDP/NDPE handshake and hands back a bound UDP socket on an IPv6
link-local over a TAP interface (`ndn-nan/src/ndi.rs`). That is host addressing —
addr1/addr2 are NDI MACs, addr3 is the cluster BSSID, the receive filter asks *who
sent this*, and the whole stack of EUI-64 / DAD / ports comes with it. It is
precisely the thing §2 says we are not doing, and precisely the thing
`AMPDU_PORT_SCOPE.md` refused 179 Mb/s to avoid.

The resolution, as of **2026-07-16**: **NDP is an interop bearer, not our data
path.** If a stock phone offers us a data path, we speak its language — that is
worth having, and it is what the NDP work bought. Our own traffic rides
`FrameFormat::RawNdn`, where the NDN name is the addressing and `dst`/`src` are
name-derived group MACs (§3.1). The prescription is *keep NAN's sync/DW/SDF,
invert NDP*; the NDI is a swappable adapter, not a foundation.

The original justification for the NDP bulk tier — that a connectionless
small-frame face is lossy for multi-fragment objects — **did not survive
investigation, and the record should say so plainly.** That loss was **four** bugs
in our own stack, all fixed on 2026-07-16.

Two were in the radio path: `MONITOR_MTU` was 2296, which subtracted LLC/SNAP from
the 802.11 2304-octet ceiling but forgot the 24-byte MAC header, so a full-MTU LP
fragment went on air at 2328 B and the radio dropped it silently (anything that
*fragmented* lost every fragment; single-frame objects were fine); and the 8812AU
never ran an RX pump, so a bulk-IN read was in flight only *during* a `recv_frame`
call and back-to-back fragments arrived with nothing draining the FIFO.

Two more were in the fragmentation path, and they made the **bench itself lie**:
`LpLinkService::send` advanced its fragment sequence counter by 1 per packet
although an `n`-fragment packet consumes `n` sequences, so consecutive packets
overlapped; and `monitor_roundtrip`'s `decapsulate` keyed reassembly on the raw wire
sequence rather than `sequence - frag_index`. Together, fragments of *different*
objects collided on one key and completed groups that were never sent — packets
stitched from two objects, which decode and were counted as delivered. Every
multi-fragment number the bench printed before this was fiction, including an
earlier revision of this paragraph (`800/1400 B → 12/12; 4000 → 9/12; 16000 →
3/12`), now withdrawn. See `ndn-packet/tests/reassembly_key.rs`.

Re-measured with all four fixed — two OPis at -52 dBm, 3 runs per cell, producer MTU
verified from its own log — delivery out of 30 at MTU 2272: 1400 B → 29/30, 2200 →
29/30, 4000 (2 fragments) → 29/30, 8000 (4) → 22/30, 16000 (8) → 17/30. Fitted
per-frame `p ≈ 0.93-0.98`, with **no length term**: `burst_fork` held the size fixed
and swept only the inter-frame gap, and every cell landed 26-30/30 whether the frame
was 800 B or 2260 B and whether 30 frames went back-to-back or 4 ms apart. The radio
itself was blameless throughout: 2200/2260/2300 B frames deliver 100%, 2312 B and up
never arrive, which is the 2304 ceiling behaving correctly. Multi-fragment loss on a
name-addressed broadcast was four bugs of ours, not a property of the medium.

The full argument, including the parts that convict this project out of its own
documents, is in
[`NAMED_RADIO_COURSE_CORRECTION.md`](../../ndn-face-wifi-aware/docs/NAMED_RADIO_COURSE_CORRECTION.md),
which is in-tree and authoritative on this question.

---

## 5. Adding a new userspace driver port (the recipe)

The port itself now lands in **`ndn-radio-drivers`**, not here; what stays on this
side is the face, the capability declaration, and the actuator wiring. The recipe
is otherwise unchanged.

1. **Bring-up.** Get the chip from cold to firmware-running to RX-capable in
   userspace via libusb. The reliable method is **golden-trace replay**: capture
   the vendor/kernel driver bringing the device up under `usbmon`
   (`tcpdump -i usbmonN -w …`), turn the capture into an ordered op-stream, and
   replay it byte-faithfully. Diff your own run against the golden when it
   misbehaves — that is how every MT7612U bug below was found.
2. **`impl FrameIo`.** `inject`: resolve `frame.tx` (the `TxIntent`) to a PHY rate
   — `McsDescriptor::for_intent` on 802.11 — then `frame::build_dot11(self.format,
   &frame)` → wrap in the chip TX descriptor → bulk-OUT. `recv_frame`: bulk-IN →
   strip the chip RX descriptor → `frame::parse_dot11`. Reuse the shared `frame`
   helpers so the wire format matches every other backend.
3. **`impl WifiRadio`** if the chip is 802.11: `inject_at` is the same path with
   the rate handed in instead of resolved, and it is what the cognitive face and
   the fixed-rate benches call. A non-Wi-Fi bearer implements only `FrameIo`.
4. **`impl RadioKnobs`.** At minimum `set_channel`; add power/CSD/EDCCA (or SF /
   coding rate) as you port them. Return an explicit error for channels/widths not
   yet captured (that is the honest capability boundary — see `Mt7612uBackend`'s
   ch6 guard).
5. **Declare `RadioCapability`** at registration and (later) provide a
   `RadioActuators` adapter so the cognition plane can drive it.
6. **Document the chip specifics** — with the driver, in `ndn-radio-drivers`. §6
   below is the MT7612U instance of this, kept here for now because the examples
   that exercise it still live in this crate.

### Operational gotchas (learned the hard way)

- **Failed runs wedge the device.** A run interrupted mid-firmware-download (or a
  kill-timeout) leaves the USB controller crashed (`ASIC revision: ffffffff`);
  *no* host-side recovery worked (uhubctl power-cycle 6–60 s, EHCI
  unbind/rebind) because the OPi's USB ports sit behind a ganged hub that never
  drops VBUS. **A physical replug is the only reset.** Run backends detached with
  no kill-timeout so firmware load finishes cleanly.
- **`NDN_RADIO_NO_RESET=1`** skips the libusb device reset that, stacked on a cold
  re-enumeration, re-wedges the FCE download.
- The kernel driver and our userspace driver fight over a warm device (kernel
  firmware-reload fails `-110` while ours, which detects firmware already
  running, succeeds). Set the interface unmanaged (`nmcli`) and `modprobe -r` the
  kernel module before running userspace.
- A second adapter in kernel **monitor mode** is the cheapest on-air verification
  receiver — raw-search the pcap for the source MAC (`tcpdump`'s text SA display
  can mis-format). **But two receiver gotchas cost a lot of time, so they are now
  fixed tooling:**

### Test rig & on-air verification (the OPi `mds-o5p-1`)

The OPi has the **MT7612U = `wlan0`** (`mt76x2u`, the device under test) and a
**Realtek `wlu1`** (`rtl88x2eu`, `0bda:a81a`, the monitor *receiver*). To verify
the MT7612 transmits, run our libusb driver on `wlan0` and capture on `wlu1`.

Two non-obvious receiver requirements (staged as `~/rx_monitor.sh` on the OPi):

1. **`monitor otherbss`** — the kernel Realtek monitor *filters broadcast DATA
   frames from other BSSes by default*. Without it, mgmt frames are captured but
   data frames look like they never radiated (this faked a multi-hour "data TX is
   firmware-gated" dead-end). Always:
   `ip link set wlu1 down; iw dev wlu1 set monitor otherbss fcsfail; ip link set wlu1 up; iw dev wlu1 set channel <ch>`.
2. **`wlu1` has a 5 GHz-only RF frontend** (its `iw phy` *lists* 2.4 GHz ch1-11
   but the frontend can't hear weak 2.4 GHz). On 2.4 GHz it only catches the
   *adjacent* MT7612 (strong); ambient 2.4 GHz reads as 0 frames. Fine for
   adjacency verification; use 5 GHz for sensitive RX.

NetworkManager keeps re-grabbing both radios → run once:
`sudo nmcli device set wlan0 managed no; sudo nmcli device set wlu1 managed no`.

Other fixed tooling on the OPi: `~/caprun.sh` (run our binary under usbmon),
`~/inject_data.py` / `~/inject_wfb.py` (kernel data-frame injectors via raw
AF_PACKET — the wfb variant sets radiotap TX_FLAGS=NOACK + MCS), `python3` only
via `nix shell nixpkgs#python3`. Build: `nix shell
github:NixOS/nixpkgs/nixos-unstable#cargo …#rustc nixpkgs#gcc nixpkgs#pkg-config
nixpkgs#libusb1 -c cargo build …`. Run our driver: `sudo modprobe -r mt76x2u`
(after a **physical replug** for a cold device — warm bring-up wedges the fw
re-download) then `sudo LD_LIBRARY_PATH=$(nix path-info nixpkgs#libusb1)/lib
NDN_RADIO_NO_RESET=1 ./target/debug/examples/<ex>`.

---

## 6. MT7612U specifics (mt76x2u) — the captured truth

> **The code this section describes now lives in `ndn-radio-drivers`**, and the
> paths below are relative to *that* repo. The split is not clean and it is worth
> knowing which side you are on: the driver, its vendored firmware, and its replay
> blobs went with the driver; the **generator scripts and the golden captures
> stayed here** (`scripts/gen_mt7612_*.py`, `golden/`), as do the `mt7612_*`
> examples that exercise the port. Hard-won device truth is expensive to re-derive,
> so it is recorded rather than moved.

Firmware (vendored, byte-identical to linux-firmware):
`ndn-radio-drivers/fw/mt7612/mt7662.bin` (ILM+DLM) + `mt7662_rom_patch.bin`.
Bring-up = `ndn-radio-drivers/src/mt7612/init_replay.bin` (generated by *this*
crate's `scripts/gen_mt7612_replay.py` from `golden/…/golden_init.pcap`).

**USB register access:** write32 = vendor `bReq 0x06` (`wValue=addr>>16,
wIndex=addr&0xffff`, 4-byte LE); read32 = `0x07`; CFG write `0x46` / read `0x47`;
WRITE_FCE `0x42`; DEV_MODE `0x01`. Endpoints: OUT cmd `0x08`, **WLAN data TX
`0x07`** (AC_VO), data RX IN `0x84`, cmd-response IN `0x85`.

**Firmware load:** ROM patch → `0x90000`, ILM → `0x80000`, **DLM → `0x110800`**
(see below), via per-chunk FCE descriptor (`0x0230..0x0236`) + bulk to ep 0x08 +
inter-chunk `0x09a8` handshake; then WMT activate (class `bReq 0x01 wValue 0x12`
bytes `6f fc 08 01 …`), load-IVB (`DEV_MODE wValue 0x12`), runtime reconfig
(`0x0730=0x1140fb`, `0x0800=1`, `0x9018=0xc40020`).

**The five bugs that stood between "firmware loads" and "RX+TX work"** (each found
by usbmon-diffing our run vs golden):

1. **Settle delays after DEV_MODE download-mode switches.** Golden waits 8.67 ms
   after `DEV_MODE wValue=1` and ~20 ms after load-IVB; firing the next write
   immediately times out and *hard-wedges* the device.
2. **Exact captured seq on replayed MCU commands.** mt76 uses `seq==0` for
   fire-and-forget (no response); only `seq!=0` ACKs on ep 0x85. Forcing a
   rolling seq + waiting on every command fills the FIFO (~90 cmds) and wedges.
3. **Classify firmware chunks by their preceding FCE descriptor, not length.** A
   region's partial last chunk (<2048 B) was mis-tagged as an MCU command and
   replayed as raw firmware bytes into the running MCU.
4. **DLM offset `0x110800`, not `0x110000` (THE root cause of the silence).**
   This adapter is ASIC rev `76120044` (E3) → `MT_MCU_DLM_ADDR_E3 = 0x110800`.
   Loading DLM 0x800 low let the firmware boot and answer bootrom + a couple
   commands, then go silent on calibration commands. Confirmed by COM_REG0 ready
   = ours `0x1138f9` vs golden `0x1140f9` (off by exactly 0x800).
5. **RF channel-set is separate from init.** `golden_init` is init-only; the
   kernel tunes the channel on a later `iw set channel`. `set_channel_ch6` replays
   `chanset_replay.bin` (194 RF/BB writes + 32 cal cmds captured from
   `iw dev wlan0 set monitor; set channel 6`).

**RX descriptor** (before the 802.11 frame on ep 0x84): `MT76_RXD_LEN = 36`
(MT_RX_INFO 4 + RXWI 32), 4-byte FCE-info trailer after the frame, RXWI RSSI[0]
at offset 18. Verified: a beacon's FC + broadcast addr1 land at offset 36.

**TX descriptor** (on ep 0x07): `[info u32][TXWI 20B][802.11 frame][4B tail]`
padded to 4. `info = round_up(TXWI+frame,4) | 80211(b19) | WIV(b24) | QSEL2(b26)`
(= `0x050800f0` for a 240-B body). TXWI rate word (offset 2) is built by
`mt76_rate_val`: `index[5:0] | LDPC[6] | BW[8:7] | SGI[9] | STBC[11:10] |
PHY[15:13]` (PHY OFDM=1/HT=2/VHT=4). **Verified on-air**: an independent monitor
captured 388/400 verbatim probes + 399/400 `transmit()`-built probes.

Verified end-to-end: `bring_up` (0 errors, 465 cmd responses) → `set_channel_ch6`
→ monitor RX (live 802.11) and radiating TX.

---

## 7. Roadmap (what's next, with the mt76 register map)

The RTL8812EU driver is the feature reference; these map its knobs onto mt76x2.

- **Wire MT7612 into cognition.** ✅ DONE — `LibUsbActuator` is now generic over
  `Arc<dyn RadioKnobs>`, `RadioCapability::wifi_monitor_2ghz` exists, and
  `examples/mt7612_cognition.rs` drives the MT7612 through one sense→decide→act
  tick with the same actuator as RTL.
- **Data-frame TX.** ✅ RADIATES. `FrameIo::inject` builds NDN 802.11 *data*
  frames; these go on **ep 0x04** (data AC) with the data TXWI (**wcid 0xff,
  ack_ctl 0** — broadcast/no-station, no ACK), NOT the mgmt path (ep 0x07).
  IMPORTANT LESSON: an earlier "data frames don't radiate" was a **receiver
  artifact** — the kernel Realtek monitor filters other-BSS data frames in plain
  monitor mode, so they looked un-radiated. Always verify with the receiver in
  `monitor otherbss` mode (see "Test rig & on-air verification" in §5). HT-rate vs CCK doesn't matter for
  radiation (mgmt verified at both); the TX descriptor carries MCS/STBC/LDPC.
- **Throughput (#3): the lever is BIG FRAMES, not aggregation — and the ceiling
  moved.** *Read this bullet as a log, not as a current number: it records two
  successive measurement campaigns, and both are superseded. See the dated
  reconciliation at the end of it for where the ceiling actually stands.* A
  raised-MTU rapid-burst kernel capture
  proved the kernel does **not** USB-aggregate (2000 frames → 2000 single-MPDU
  316 B transfers); wfb-ng's throughput is just 1500 B (MTU) frames × the
  transfer rate. Our driver **bypasses the kernel's 1500 B monitor MTU** (writes
  raw MPDUs to ep 0x04, up to ~4095 B = the 12-bit TXWI len field). fps is
  **constant ~1400/s** across sizes → goodput = fps × payload: 256 B→2.8,
  1000 B→11.2, 2000 B→22.3, 3000 B→33.5, **4000 B→44.8 Mb/s**, all written. So set
  a large face MTU. Confirmed radiating ≤2304 B (standard MSDU); >2304 B is
  USB-accepted + transmitting (constant fps) but the Realtek test receiver can't
  witness oversized frames — in-system the receiver is our own MT7612 (any size).
  Both aggregation levers were moot (A-MSDU gated; the device doesn't chain
  USB-agg units). Further: faster per-transfer rate would need async URBs (`nusb`).
  *(Earlier "23.6 Mb/s / ep-0x04 limit / needs aggregation" notes were wrong.)*
  Implemented: a `spawn_tx_pump(depth)` (threads `write_bulk` off the executor;
  `inject` builds+enqueues), `spawn_rx_pump(depth)`, and A-MSDU
  (`build_amsdu_body`/`inject_batch`). Measured (depth-32 pump, HT MCS7), all
  frames written + radiated: 256 B→4.2, 700 B→11.2, 1400 B→18.9, **2000 B→23.6
  Mb/s**. **Two corrected misconceptions:** (1) there is **no ~1–2 KB ep-0x04
  limit** — single *plain-data* frames up to 2000 B write whole and radiate; the
  short-write was specific to the A-MSDU *QoS-data* (FC 0x88) frames, which
  separately **stall** (firmware likely drops QoS-data broadcast without a TID/BA
  context — open). (2) The device serializes single MPDUs at ~1500–2000/s and
  **libusb *synchronous* transfers don't pipeline** (a depth-32 multi-thread pump
  gave the same fps as 1 thread — each sync transfer serializes on the libusb
  event loop). The on-air radiotap confirms the TXWI rate is honored. **Levers to
  go higher (toward wfb-ng's 30–50+ Mb/s):** (a) single MSDU caps at 2304 B
  (~26 Mb/s); (b) **async URB pipelining** — `rusb 0.9` has no async transfer
  API, so this needs `nusb` or raw `libusb1-sys` FFI (a real USB-layer change);
  (c) **A-MSDU** for many MSDUs/MPDU (the RTL's 265 Mb/s lever) once the QoS-data
  stall is solved.

  **Reconciliation (2026-07-16). Neither 44.8 nor 23.6 Mb/s is the ceiling any
  more; lever (b) was built.** `ndn-radio-drivers/src/mt7612/tx_async.rs` is an
  async libusb URB ring — many transfers in flight, completions on one dedicated
  event thread — built on `libusb1-sys` (the backend `rusb` already uses, so no new
  USB dependency; Linux-only). Its header records the measurement that motivated
  it: synchronous `write_bulk` blocks ~0.7 ms per transfer while the kernel
  pipelines back-to-back transfers ~5 µs apart — a 140× gap, and the reason fps
  was pinned at a constant ~1400/s regardless of frame size. That constant is what
  makes 44.8 Mb/s an artifact of the *host* transfer path rather than a property of
  the radio. With the ring, `AMPDU_PORT_SCOPE.md` (`:3-4`, `:69`) reports **~3,500
  fps** and treats **~106 Mb/s** as the single-MPDU ceiling — consistent with
  ~3,500 fps × the ~4095 B the 12-bit TXWI `len_ctl` allows. Take **~106 Mb/s** as
  the current figure and the numbers above as the two campaigns that preceded it.
  These are not re-measured here (this pass touched no hardware); the sequence is
  reconstructed from the source and the sibling doc, and the intermediate campaigns
  are left standing because each one corrected a real misconception. Lever (c)
  remains open, and `AMPDU_PORT_SCOPE.md` argues that on a broadcast bearer it —
  and A-MPDU — stay closed on architectural grounds, not RE grounds: ~106 Mb/s is
  the price of the open broadcast property.
- **Per-channel + bandwidth.** Capture the RF program for more channels / 40/80
  MHz the same way as ch6; lift `RadioKnobs::set_channel` past the ch6 guard.
- **Feature-max (register map for mt76x2):** STBC/LDPC/SGI/NSS already in the TXWI
  rate word (`mt76_rate_val`); per-rate **TX power** → `mt76x2_phy_set_txpower` /
  EEPROM rate-power tables; **EDCCA** → `MT_TXOP_CTRL_CFG` / ED-CCA BBP regs,
  ignore-CS via `MT_PROT_CFG`/`MT_TX_RTS_CFG`; **CLM / airtime** → `MT_CH_IDLE` /
  `MT_CH_BUSY`; **thermal** → `MT_TEMP_SENSOR` / TSSI compensate; **CSD** has no
  per-frame knob on mt76x2 (spatial streams via TXWI NSS); **beamforming**
  untouched (available in hardware, not yet explored).
- **Reliability (open problem).** Re-opening our driver wedges the device, so each
  on-device test needs a physical replug. Diagnosed: the MCU firmware does NOT
  persist across process re-open (COM_REG0 reads the cold value `0x80140EBB` on a
  warm re-open, not the `0x1140fb` start_mcu wrote), and the cold re-download then
  wedges on stale FCE/USB-DMA state; a libusb `reset()` doesn't clear the on-chip
  MCU. So a warm fast-path can't work and only a VBUS cycle gives a clean device.
  Needs a software MCU/FCE reset (WMT reset cmd, or FCE re-init before the cold
  download) — the kernel mt76x2u manages this on re-bind; we don't yet.

---

## 8. File index

Paths are given from the workspace root (`~/Documents/Dev/ndn-workspace`), since
the subsystem now spans three repos.

| concern | location |
|---|---|
| **the contract**: `FrameIo` · `WifiRadio` · `InjectFrame` · `CapturedFrame` · `TxIntent` · `McsDescriptor` · `McsPolicy` · `RadioKnobs` · `Bandwidth` · `RadioCapability` · `RadioKind` · `Band` · `TimingModel` | `ndn-rs/crates/core/ndn-radio-hal/src/lib.rs` |
| shared 802.11 build/parse, `FrameFormat`, `MONITOR_MTU`, AF_PACKET + loopback backends, HAL re-exports | `ndn-rs/crates/core/ndn-frame-io/src/` (`lib.rs`, `frame.rs`) |
| `RadioKnobs` + `Bandwidth` re-export (and why they moved) | `ndn-ext/crates/faces/ndn-face-monitor-wifi/src/radio.rs` |
| NDN face / Transport | `ndn-ext/crates/faces/ndn-face-monitor-wifi/src/lib.rs` (`MonitorWifiFace`) |
| cognition binding (sense→decide→act) | `ndn-ext/crates/faces/ndn-face-monitor-wifi/src/control.rs` (`RadioControl`, `LibUsbActuator`) |
| airtime optimand | `ndn-ext/crates/faces/ndn-face-monitor-wifi/src/measure.rs` |
| nl80211 channel control (Linux) | `ndn-ext/crates/faces/ndn-face-monitor-wifi/src/channel_manager.rs` |
| pure decision engine, `TxParams`/`RateParams`, `RadioPolicy` | `ndn-ext/crates/faces/ndn-radio-cognition/src/` (`plan.rs`, `policy.rs`, `sense.rs`) |
| **all drivers** | `ndn-radio-drivers/src/` — `libusb_rtl88xx.rs` (8812EU/8822E) · `mt7612/` · `rtl8812au.rs` · `rtl8821c/` · `libusb_rtl8733b.rs` · `bw16_serial.rs` · `lora_serial.rs` · `rx_pump.rs` · `mt7612/tx_async.rs` (async URB ring) |
| replay generators + golden captures (stayed with this crate) | `ndn-ext/crates/faces/ndn-face-monitor-wifi/scripts/`, `…/golden/` |
| Wi-Fi Aware / NAN (see §4.1) | `ndn-ext/crates/faces/ndn-nan-core/` (sans-IO engine, `rendezvous.rs`) · `ndn-ext/crates/faces/ndn-nan/` (std driver, `ndi.rs`) · `ndn-ext/crates/faces/ndn-face-wifi-aware/` (the face) |

[`FrameIo`]: ../../../../../ndn-rs/crates/core/ndn-radio-hal/src/lib.rs
[`WifiRadio`]: ../../../../../ndn-rs/crates/core/ndn-radio-hal/src/lib.rs
[`RadioKnobs`]: ../src/radio.rs
