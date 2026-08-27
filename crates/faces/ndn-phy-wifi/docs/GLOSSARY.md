# NDR MAC — Canonical Vocabulary

**Status: normative.** This is the single source of truth for terminology in the Named Data Radio (NDR)
MAC design. Its job is to **stop terminology drift**: where a concept has been called several things, one
name is declared **canonical** and the others are marked *(avoid)*. Where an acronym was never expanded,
it is expanded here (or flagged as needing the author's confirmation). Where the docs describe code that
has since changed, the drift is noted so the stale prose can be corrected.

Rule of use: in code, comments, commit messages, tests, and telemetry span names, use the **canonical**
term. If you need a synonym for prose flow, use it once and in parentheses point back to the canonical head.

Conventions: `CodeType` = a real type/trait/field. *(avoid: …)* = a synonym or stale term not to use as
the head. **[NEEDS AUTHOR CONFIRM]** = a definition (usually an acronym expansion) the corpus never fixed.

---

## 0. The four facets (the design's spine)

The MAC answers four questions; each is a **facet** (a *chapter* of the design), and every mechanism below
belongs to exactly one:

| Facet | Question | Canonical mechanisms |
|---|---|---|
| **WHO** | which frames do I admit? | Tier-0 prefix-set filter, Tier-1 BF tables, ephemeral source ID |
| **WHEN** | when may I transmit? | named airtime lease, slot, CCLF, claimable slot |
| **WHERE** | on which channel? | medium-keyed slot, FHSS hop schedule |
| **HOW-WELL** | at what rate/reach? | rate lever, reach lever, worst-overheard-receiver cap |

"Facet" is a design term, not a code type.

---

## 1. Addressing & identity (WHO)

### Tier-0 filter — *canonical head: **Tier-0 filter*** (type: `PrefixFilter`)
The in-frame, zero-parse receive filter. The sender inserts **every prefix** of the frame's name
(root-first, capped at `MAX_DEPTH`) into a Bloom filter carried in the 802.11 address octets; a receiver
ANDs its own precomputed per-prefix masks against it. Over-accepts (false positives possible) but **never**
false-negatives. Decouples granularity: the sender ships all prefix depths, each receiver matches at its own.
- Encoded: `tier0.rs` (`PrefixFilter`, `may_match`, `positions`, `for_each_prefix`, `to_wire`).
- **Canonical parameters (from code, authoritative):** 126-bit filter, `K = 4` hashes, `FILL_CAP = 64`,
  `PrefixFilter([u8; 16])`. *(avoid the "94-bit / FILL_CAP 48" figures — those are stale in
  `wire-format-spec.md` §3/§11/§12; the `[CODE: 94]` annotations there predate the migration.)*
- *(avoid these synonyms as the head: "the Blur", "address Blur", "Blurred Name", "prefix-set Bloom
  filter", "the name filter", "the fingerprint". Use **Tier-0 filter**; "prefix-set Bloom filter" is
  acceptable as the one-line expansion of what it *is*.)*

### Tier-1 tables (types: `Table`, `Tier1`, `Verdict`)
Receiver-side, **post-parse** Bloom-filter tables (BF-FIB / BF-PIT / BF-CS) that answer the
direction the in-frame filter cannot: *"the packet name is a prefix of my table entry."* Each of FIB/PIT/CS
is a filter; updates are ordered 0→1 before 1→0; Basic CS (no Active CS). `tier1.rs`.

### Tier-2 (no code type — the reference)
The exact NFD name tree. **Correctness lives here alone**; Tiers 0/1 only ever over-admit. `named-filter-mac-redesign.md` §3.

### Ephemeral source — **two distinct things, do not conflate**
- **Ephemeral nonce** (`EphemeralSource`): a 46-bit SipHash-rotating source tag in the **legacy** address
  layout, rotating per-boot (`NONCE_ROTATION_MS = 300000`, ~5 min). `frame.rs`.
- **Ephemeral ID** (`EphemeralId`): the **8-bit** ID at `addr3[4]` in the **Tier-0** layout. `ephemeral_id.rs`
  (`ID_BITS = 8`, `ID_SPACE = 256`).
- Both have **no routing meaning** — they key per-neighbour RSSI, per-source DoS limiting, neighbour-density
  count, and relay-vs-owner discrimination, never host routing state.
- *(avoid: calling both "the ephemeral source nonce". The 8-bit one is the **ephemeral ID**; the 46-bit one
  is the **ephemeral nonce**. Both are now built — neither is hypothetical.)*

### PFS / DAR — the two mechanisms that make an 8-bit ID safe
- **PFS = Pick-Free-Slot**: on boot/rotation, pick an ID not recently overheard (initial pick only; blind
  to hidden nodes).
- **DAR = Detect-And-Rotate**: a *common neighbour* that overhears one ID carrying two distinct contents
  piggybacks a 1-bit `FLAG_ID_COLLISION`; the aliasing sender rotates. Beacon-free.
- `ephemeral_id.rs` (`note_collision`, `AliasDetector::observe`, `FLAG_ID_COLLISION`).

### addr1/addr2/addr3 layout
- **Tier-0 layout:** `addr1[0..6] ‖ addr2[0..6] ‖ addr3[0..4]` = the 16-byte filter; `addr3[4]` = 8-bit
  ephemeral ID; `addr3[5]` = flags. `addr1` I/G+U/L bits forced to `0b11` (a no-ACK group marker).
- **Legacy layout:** `addr1` = broadcast, `addr2` = 8-bit-ID + random, `addr3` = copy of dst.
- Encoded as `InjectFrame { dst, src, addr3 }` / `CapturedFrame { group, addr, addr3 }`; pack at
  `medium.rs`.

### "No host identity" doctrine
Host *identity* is removed; the receive *filter* is kept but re-keyed host→content. No host MAC, no
association, no peer tables. Only **soft-state projections** of the forwarder's PIT/FIB/CS descend below the
network layer, and their loss costs performance, never correctness (the §7 invariant). Canonical statement:
`mac-addressing-doctrine.md`.

### `RadioId` (type: `RadioId(u16)`)
A **device-local** handle indexing one of a node's own radios; medium state is keyed `(RadioId, Channel)`.
**Not an on-air identity** — it never leaves the node, so it does not violate "no host identity". `sense.rs`.

> **DEAD TERMS (removed from code 2026-08-06, #91d — do not use):** `name_group_mac`, `name_group`,
> `name_group_uni`, `prefix_key`, `group_prefix_key`, "group MAC", "name-group hash". These were the former
> destination-field name-hash addressing, deleted because *an in-frame name hash cannot express
> longest-prefix match* — replaced by the Tier-0 filter. Several docs still cite them as live
> (`mac-addressing-doctrine.md` beyond its §8 banner, `RADIO_SUBSYSTEM.md`, `NAMED_RADIO_COURSE_CORRECTION.md`);
> that prose is stale. Survivors: `siphash24`, `GroupKey`, `OPEN_GROUP_KEY` (the trust context for the filter).

---

## 2. The named airtime lease (WHEN)

### Named airtime lease
A transmit grant = a lease of **L consecutive base slots**, held by a **name**, at a **class**, computed
from the common-view clock. Subsumes the fixed slot (which is `(reserved, L = 1, class 0)`).
`named-filter-mac-redesign.md` §5; `schedule.rs`; env `NDN_SCHED_LEASE`.

### Slot (type: `SlotSchedule`)
Airtime chopped into slots on a common-view clock. `owner_slot = slot_key % slots`, a pure function of
name + clock; `owner_slot_in(prefix_hash, class)` places latency names in reserved lanes, bulk in open
slots. `schedule.rs`. The slot key is `prefix_hash` over the first `slot_depth` name components.

### Lease class (type: `LeaseClass`)
- **Canonical (code):** `LeaseClass::{ Latency, Bulk }` — two classes are **built**.
- A third class, **urgent-bulk** (preemption between two open-slot classes), is **designed but NOT built**
  — it has "no legal home yet" because preemption is an *ownership* question, not a suppression one
  (`mac-synthesis.md` §2 law 6). State this explicitly; do not imply three live classes.
- *(avoid the doc variants "class 0/1/2", "alarm/report", "Urgent" as if they were the code enum.)*

### CCLF = **Content Connectivity and Location Forwarding**
The cooperative-forwarding suppression rule: on gaining content worth forwarding, schedule a rebroadcast at
`arrival + jitter`; if you **overhear** the same *named content* forwarded first, **cancel**. Content-keyed,
never host-keyed. The same jitter also serves as the *within-slot election* for claimable slots.
- Encoded: `cclf-named-mac.md` (canonical description), `coop.rs` (`CoopRelay`), `cclf_jitter_us` /
  `cclf_elect` (`sched.rs`).
- **One acronym, three jobs — disambiguate at the call site:** (a) broadcast-storm suppression / cooperative
  forwarding (`coop.rs`); (b) the within-slot claim election (`sched.rs`); (c) `cclf_elect` reused as a
  generic contribution-based election kernel. Say which you mean.

### Claimable slot
An owned-but-reclaimable slot: if the owner is overheard idle and the claimant's own turn is not imminent,
the claimant contends via a CCLF jitter and claims. Env `NDN_SCHED_CLAIM=1`. `FaceScheduler::gate`.

### Medium-keyed slot
Before slot lookup the operating channel is folded into the key
(`medium_keyed = prefix_hash XOR (channel * 0x9E37_79B9)`), so two radios on different channels own
different slots — **one medium = one schedule**. `sched.rs`.

### Co-owner (D1)
Two **distinct** active names hashing to the same slot (the `hash % N` pigeonhole once active names > N).
Fix: detection-triggered **shared-slot backoff** — turn-taking bought only when a co-owner is *locally
evident*. `mac-design-roots.md` §1.

### Superframe / epoch / guard — three different things
- **Superframe:** the set of `SlotSchedule.slots` slots that the schedule repeats over.
- **Epoch:** the rotation counter — `epoch(t) = now_us / dwell_us` (channel) or the slot-rotation term in
  `owner = H(name) + epoch mod N`. Fed by `ClockSource`. `schedule.rs`.
- **Guard:** the inter-node clock-disagreement margin a slot must leave — `ClockSource::guard_us()` =
  **1000 µs (Wall) / 200 µs (CommonView) / 10 µs (Hardware)**. A guard is **not** a reserved lane; keep them
  separate. `sched.rs`.

### The "gate" — **overloaded; always qualify**
- **slot-gate:** `FaceScheduler::gate` — the outbound-TX choke point that waits for a name's owned slot.
- **name-gate:** `NameGate` / `RxFilter` — the **RX** name-filter admission gate. `name_gate.rs`.
- Never write "the gate" unqualified. Say **slot-gate** or **name-gate**.

### Worst-overheard-receiver / force-legacy (HOW-WELL, lives here because it gates the lease's rate)
Rate/power is driven by the **worst overheard reception report** for a content group; a legacy-only-RX
neighbour **forces the legacy basic rate** every receiver can decode. The one piece of link adaptation that
survives namelessness (keyed on the name-group, not a peer). `medium.rs`, `control.rs`,
`mac-addressing-doctrine.md` §5. Report sentinels: `LEGACY_ONLY_RX = 0`, `SINGLE_STREAM_HT_RX_MCS = 7`,
`FULL_RX_MCS = 9` (`report.rs`).

---

## 3. Timing & clock

### Common-view clock (types: `MeshCv`, `mesh_common_view()`)
The shared sense of time every node derives so slots line up **with no coordinator**. Measured: hardware
RXTSFL tracked a shared reference to ~0.4 µs vs ~55 µs for software stamps. Enabled by the hardware-TSF work
("#41"). *(avoid treating "common-view", "the #41 clock", and "hardware TSF common-view" as different
things — one concept.)*

### TSF = **Timing Synchronization Function** (802.11)
The hardware free-running microsecond counter every 802.11 MAC maintains. Never expanded in the corpus —
expanded here. "Port TSF" = the per-interface TSF (reads 0 while unassociated on the ESP32-C5).

### `RadioHwClock`
The `ndn_time` disciplining type holding a hardware-domain clock, fed from each `CapturedFrame.stamp`
(32-bit RXTSFL unwrapped against the host clock; software fallback until the first stamp). The scheduler
reads it for `epoch(t)` under `NDN_SCHED_CLOCK=hw`. Defined in `ndn-time`.

### `ClockSource { Wall, Hardware, CommonView }` — **not** `RadioClockKind`
The **sched-local** enum selecting what feeds `epoch(t)`: `Wall` (wall-clock µs, NTP-common at ms),
`Hardware` (disciplined HW TSF, µs-local), `CommonView` (radio-native, reads an offset to the network
reference). Env `NDN_SCHED_CLOCK=wall|hw|cv`. `sched.rs`.
- **Distinct enum, do not conflate:** `RadioClockKind { FreeRunRxStamp, PortTsf, HostRecv }` (in `ndn-time`)
  is a **clock-quality tier**, not the epoch selector. `ClockSource` picks *what the scheduler uses*;
  `RadioClockKind` ranks *how good a given stamp is*.

### `LinkStamp` / `LatchPoint`
A per-frame hardware RX timestamp (`LinkStamp`) carrying its clock domain + honest precision, and the point
it was latched (`LatchPoint`). `CapturedFrame.stamp`. Defined in `ndn-time`.

### NetworkTime / `RefBelief`
The stratum/reference-election layer over the common-view clock. `RefBelief { ref_id, stratum,
offset_to_ref }` drives a network-time reference election (#75); a beacon carries the emitter's belief for
multi-hop composition (`MeshCv.belief`). Defined in `ndn-time`.

### "beacon" — **six senses; always qualify**
1. **time beacon** — the actual on-air timing frame: `TIME_BEACON_MAGIC = [0x7E,'T','B']`, 19 bytes
   `ref_us ‖ map_digest`, injected raw, bypasses the slot-gate. `sched.rs`. **This is the only "beacon"
   that exists as a live artifact.**
2. **TimeToken** — a *design* concept (not built): an 8-byte field hardware would overwrite with the TX TSF
   at transmit, making *any* frame a timing reference. Not reachable on current silicon. `timing-rides-named-data.md`.
   No code type named `TimeToken` exists.
3. **802.11 beacon engine** — the chip mechanism that would emit #2.
4. **discovery beacon** — explicitly **rejected** ("there is no dedicated discovery beacon").
5. **signed beacon** — the security upgrade path (`mac-synthesis.md` §5a), future.
6. **software `TimeBeacon`** — the millisecond-limited stopgap struct.

Write "time beacon" for #1; never bare "beacon".

---

## 4. Rate / reach / robustness (HOW-WELL)

### `TxIntent { reliability, reach }`
The bearer-agnostic transmit contract on every `InjectFrame` — states *what* to achieve; the backend
resolves it to a PHY rate. `ndn-radio-hal`.

### `Reliability { MostRobust, Balanced, Throughput }`
The robustness objective (the primary axis on a no-ARQ broadcast). `MostRobust` → base MCS + STBC + LDPC
(or HE ER-SU + DCM on an HE radio); `Balanced` → conservative default; `Throughput` → top validated rate +
short GI.

### **"reach" is overloaded — two unrelated meanings. This is the worst overload in the design.**
- **`Reach { Broadcast, Group }`** = **AUDIENCE** — who the frame is for (every in-range RX, or a
  name-group). This is the `TxIntent.reach` field.
- **the reach lever** = **LINK RANGE / ROBUSTNESS** — the robustness knobs (STBC, LDPC, ER-SU, DCM, lower
  MCS, narrower bandwidth) and `Band::range_rank` / "reach class".
- **Canonical fix:** use **`Reach`** (capitalized, the type) only for *audience*; use **"reach lever"** or
  **"range/robustness"** for *link range*. Never write bare "reach" for the robustness knobs.

### The two levers
- **rate lever** — MCS up/down, trading airtime for throughput.
- **reach lever** — robustness/range: STBC, LDPC, ER-SU, DCM, lower MCS, narrow bandwidth.
Both are decided per-name from name-need + measured link. Informal design terms (`link-adaptation-chapter.md`,
`mac-synthesis.md`); not code types.

### `McsDescriptor { index, short_gi, vht, nss, stbc, ldpc, he, dcm, er_su }`
The concrete 802.11 rate an exact-rate inject uses (`inject_at`). Resolved from `TxIntent` via
`McsDescriptor::for_intent(intent, max_index, vht_cap, he_cap)`. `ndn-radio-hal`.

### Rate/reach acronyms (all expanded here — several were only in code)
- **MCS** = Modulation-and-Coding Scheme index. HT 0–7 (1SS) / 8–15 (2SS); VHT-1SS 0–8. `MAX_RELIABLE_MCS = 7`
  is an RTL8812EU-validated figure, **not** a workspace ceiling (#83).
- **STBC** = Space-Time Block Coding — Alamouti-encode one stream across both antennas; pure TX diversity,
  no receiver feedback (ideal for un-ACKed broadcast).
- **LDPC** = Low-Density Parity-Check — FEC alternative to the mandatory **BCC** (Binary Convolutional Code),
  ~1.5–2 dB coding gain.
- **CSD** = Cyclic-Shift Diversity — second-chain antenna diversity (a slow `RadioKnobs::set_tx_csd`, distinct
  from the per-frame STBC descriptor bit).
- **DCM** = (HE) Dual-Carrier Modulation — each bit on two widely-spaced subcarriers; halves rate for
  frequency diversity (~few dB). HE-only; `McsDescriptor.dcm`.
- **ER-SU** = (HE) Extended-Range Single-User — repeated, 3 dB-boosted preamble, ~2–4 dB sensitivity; the
  strongest single-frame reach mode. **MCS 0–2 only** (the PHY silently drops higher MCS). HE-only; `McsDescriptor.er_su`.

### `RateParams` (decided) vs `RateCapability` (declared) — the parallel pair
- **`RateParams` = `None | Wifi(WifiRate) | Lora(LoraRate)`** — the **decided** per-frame rate inside
  `TxParams` (actuator side). `plan.rs`.
- **`RateCapability` = `None | Wifi{max_mcs,max_nss,max_bw} | Lora{min_sf,max_sf}`** — the radio's **declared
  ceiling** (capability side). `he_cap: bool` on `RadioCapability` gates the HE reach levers. `ndn-radio-hal`.
- *(avoid saying "WifiRate" for both — `WifiRate` is the decided side only.)*

> **`link_fec_redundancy` is decided but NOT actuated in the send path** (`RADIO_SUBSYSTEM.md` §3.3) — a
> known wiring gap. Treat the term as *aspirational* until wired.

---

## 5. Sensing

### Occupancy — **collapses three fidelities; qualify which**
- **frame-activity occupancy** (shipped): a hardware count of *decodable* frames read without decoding
  (`REG_RXERR_RPT 0x0664` on the 8812au; the C5's per-frame counter). **Not energy/CCA.**
- **energy occupancy:** an energy-detect / CCA / EDCCA reading.
- **PSD occupancy:** true occupancy from an SDR power-spectral-density scan.
All surface as `ChannelOccupancy { busy_pct }` keyed `(RadioId, channel)` in `MediumState`, but they measure
different things — say which. `sense.rs`, `RadioKnobs::read_channel_activity`, `frame-free-sensing.md`.

### EDCCA = **Enhanced Detection Clear Channel Assessment** (802.11 term)
Energy-detect carrier sense: the MAC defers TX when channel energy exceeds a threshold. Wired as
`RadioKnobs::set_edcca_ignore`, but **measured to be a cliff, not a usable static knob** on a saturated
channel. `edcca-contention-findings.md`. *(The docs gloss it "energy-detect carrier sense"; the standard
name is spelled out here.)*

### LBT / CAD
- **LBT** = Listen-Before-Talk — the generic channel-access-by-sensing concept; on LoRa realized as
  firmware CAD-based CSMA.
- **CAD** = Channel Activity Detection — the SX1262 preamble/energy detect without decoding (LoRa-native
  carrier sense, the cousin of EDCCA). `lora-scalable-mac-design.md`.

### PhyMetrics `{ snr_db, evm_db, cfo_hz }`
Per-frame PHY **quality** — how *clean* a frame arrived (vs RSSI = how *loud*). The decode predictor.
`ndn-radio-hal`. (**CFO** = Carrier Frequency Offset; **EVM** = Error-Vector Magnitude.)

---

## 6. The seams / HAL

Four traits, one object each face holds behind `Arc<dyn …>`:

| Trait | Plane | Key methods |
|---|---|---|
| **`FrameIo`** | data-plane | `inject`, `inject_batch`, `recv_frame`, `inject_at`, `inject_at_clock`, `inject_after`, `set_rate`, `mesh_common_view` |
| **`RadioKnobs`** | control-plane (slow, stateful) | `set_channel` (only required); `set_tx_power[_dbm]`, `set_tx_csd`, `set_edcca_ignore`, `set_spreading_factor`, `tx_discipline`, `read_channel_activity`, `configure_name_filter` (all default no-op) |
| **`RadioTime`** | named-time surface | `time_sources`, `clock_steering`, `steer_clock_ppm`, `read_clock` |
| **`RadioProfile`** | static capability | `capability() -> RadioCapability` |

### The inject family (the "write-once seam")
- `inject(frame)` — now; resolves `TxIntent`.
- `inject_at(frame, mcs)` — exact MCS (= `set_rate` + `inject`).
- `inject_at_clock(frame, target_tick, domain)` — **absolute** instant on a radio clock (the hardware side of
  a named lease).
- `inject_after(frame, delay_us)` — **relative**, reconcile-free (device timebase); the one `FaceScheduler`
  uses to drive a hardware lease with no clock conversion.
- All default to inject-now, so a radio with no scheduled-TX engine relies on the scheduler's software
  slot-gate.
- **"write-once seam"** = the doctrine that the object-safe trait a face actually holds (`FrameIo`) must
  carry the overridable behaviour, so a backend's override (e.g. A-MSDU) can't be silently lost. This is why
  the old `WifiRadio` trait was **removed** (#83) and its methods moved onto `FrameIo`.

### `TxDiscipline { BestEffort, PromptBounded{max_delay_ns}, ScheduledAt{granularity_ns} }`
What the TX path can *promise* about timing; the scheduler reads it to skip its software sleep when the radio
can self-place. `ndn-radio-hal`.

### `RadioCapability`
The declared bundle: `kind, bands, rate, he_cap, channels, max_tx_power, tx_power_dbm, retune_us, rx_only,
duty_cycle_max, max_payload, half_duplex, csi`. The switch between homogeneous (identical caps → channel
assignment) and heterogeneous (divergent caps → object→radio mapping) regimes.

> **Removed capability fields still described as live in `RADIO_SUBSYSTEM.md` (stale):** `agile: bool`
> (→ measured `retune_us` + `can_hop(dwell)`), `TimingModel { AlwaysOn, DutyCycled }` (removed — zero readers,
> wrong for LoRa), and the whole `WifiRadio` trait (removed #83).

---

## 7. Cognition

### Cognition / cognitive control plane
The sense→decide→act loop that picks rate/coding/channel/power per named object. Crate:
`ndn-radio-cognition`. `RadioControl` binds it to radios (a SENSE→DECIDE→ACT tick).

### `RadioPolicy` (cognition) vs `RatePolicy` (face) — **do not confuse; different layers**
- **`RadioPolicy`** — the cognition **decide plane**: `decide(name_ctx, medium, now) -> RadioPlan`. Implements
  the `RadioStrategy` trait. `ndn-radio-cognition/src/policy.rs`. **This is the cognition decision type.**
- **`RatePolicy`** — a **thin face-local wrapper** around `McsPolicy` (Fixed/Adaptive per-frame MCS
  selection). `ndn-face-monitor-wifi/src/lib.rs`. Not a cognition type.
- There is **no** cognition type named `RatePolicy`. When you mean the decision plane, say `RadioPolicy`.

### `TxParams { link_fec_redundancy, edcca_ignore, tx_power, tx_power_dbm, rate: RateParams }`
The actuator-side per-frame **decision output**. `plan.rs`.

### `RadioPlan`
The per-radio allocation output of `decide`: which radios carry the object, at what `TxParams`, plus the
relay/suppress decision and a cross-node **consistency digest** (`consistency: u64`, FNV-1a over prefix_hash
+ receivers + per-alloc radio/channel/mcs). `plan.rs`.

### `NameTableObserver` — a **forwarder-core** trait, not cognition
`ndn_fwd_core::store::NameTableObserver`, implemented by `Tier1Feed`: the forwarder pushes FIB/PIT/CS
name-table changes into the Tier-1 filters. `tier1.rs`. *(The user's mental model filed it under cognition;
it is a forwarder→face seam. Distinct from `DemandTracker` (PIT→`Demand`) and `NameContext`
(`{prefix_hash, priority}`) — three different "name observation" surfaces.)*

---

## 8. The name-hash keyspaces — **three, by design**

An earlier "one shared keyspace" claim (#44) was **retracted**. There are three hash families and that is
correct:
1. **keyed SipHash-2-4** — the wire filter and `EphemeralSource` (unforgeable / unlinkable).
2. **unkeyed FNV-1a-64 `prefix_hash`** — slot / channel / demand / consistency (every node must compute it
   *identically*, so it must be keyless). `lib.rs`.
3. **process-local `DefaultHasher`** — the PIT key (never leaves the process).

What must actually be shared across nodes is the **name normalization** (`ndn_name_to_slash` /
`Tier1Feed::slash` — three renderings pinned to agree), **not** the hash. *(FNV = Fowler–Noll–Vo.)*

---

## 9. Coding / FEC axes

- **link-FEC** (`link_fec.rs`, `LINK_FEC_MAGIC = 0xFC`) — systematic K-of-N with a generation header, no
  peer to ACK. **FEC = Forward Error Correction.**
- **F1** — end-to-end coding (`fec.rs` / `CodedAssembler`).
- **F2** — in-network **RLNC** recode (`recode.rs`, crosses trust, scaffolding). **RLNC = Random Linear
  Network Coding.**
- **F3 = COPE** — inter-flow XOR (`cope.rs`). *Note: F3 is COPE, not RLNC; link-layer RLNC is a distinct
  intra-flow upgrade of link-FEC.*

---

## Acronyms — quick reference

| Acronym | Expansion | Note |
|---|---|---|
| **CCLF** | Content Connectivity and Location Forwarding | cooperative-forwarding suppression + within-slot election |
| **TSF** | Timing Synchronization Function | 802.11 hardware µs counter |
| **EDCCA** | Enhanced Detection Clear Channel Assessment | glossed only as "energy-detect carrier sense" in docs |
| **PFS / DAR** | Pick-Free-Slot / Detect-And-Rotate | 8-bit-ID deconfliction |
| **MCS** | Modulation-and-Coding Scheme | |
| **STBC / CSD** | Space-Time Block Coding / Cyclic-Shift Diversity | TX diversity |
| **LDPC / BCC** | Low-Density Parity-Check / Binary Convolutional Code | FEC codecs |
| **DCM / ER-SU** | (HE) Dual-Carrier Modulation / Extended-Range Single-User | HE reach levers |
| **LBT / CAD** | Listen-Before-Talk / Channel Activity Detection | sensing |
| **CFO / EVM** | Carrier Frequency Offset / Error-Vector Magnitude | PhyMetrics |
| **FEC / RLNC** | Forward Error Correction / Random Linear Network Coding | coding axes |
| **FNV** | Fowler–Noll–Vo | the unkeyed slot/channel hash |
| **NAV** | Network Allocation Vector | 802.11 virtual carrier sense |
| **FHSS / MRMC** | Frequency-Hopping Spread Spectrum / Multi-Radio Multi-Channel | WHERE facet |
| **TSCH** | Time-Slotted Channel Hopping | prior-art comparison |
| **PSD** | Power Spectral Density | SDR occupancy |

---

## Drift the docs still carry (fix these when touching the doc)

1. **Stale `[CODE: 94:46]` annotations** — `wire-format-spec.md`, `named-filter-mac-redesign.md` describe the
   filter as 94-bit / nonce 46-bit; code is **126-bit filter, 8-bit ID built**.
2. **Dead addressing terms** (`name_group_mac`, `prefix_key`, "group MAC") still cited as live outside
   `mac-addressing-doctrine.md` §8's banner.
3. **Removed HAL items** (`WifiRadio` trait, `agile: bool`, `TimingModel`) still documented as live in
   `RADIO_SUBSYSTEM.md`.
4. **`link_fec_redundancy`** documented as applied but not actuated in the send path.
5. **CCLF / TSF / EDCCA** expansions missing from source docs (fixed here).
