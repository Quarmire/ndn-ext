# Bearer, Face, and Radio — one wireless face, competent MAC below it

Resolves *"is a new bearer (BLE advertising, NAN, LoRa) a **face** or a **radio capability**?"* and how
coexisting bearers/radios relate. The answer: **neither** — a bearer is a seam *below* a **single wireless
face**, and everything about using the medium lives behind that face. This reconciles "the ether is the face"
(`mac-addressing-doctrine.md` §4) with first principles and with the **soft-state test** (§7), and treats the
in-tree *bearer → face* crate layout (`BleAdvFace`/`MonitorWifiFace`/`NanCoordFace` as NFD faces) as **drift to
be corrected**. Defers to `../../ndn-face-wifi-aware/docs/NAMED_RADIO_COURSE_CORRECTION.md` where it rules; uses
`GLOSSARY.md` terms.

## 0. TL;DR

Wireless exists **for mobility**; a stable, wire-like link is the *degenerate subset* (use a wire when it's
real — the wire always wins). So the MAC must assume **perpetual flux**, and the only stable abstraction to
offer upward is **exactly one wireless face** — the "helper"/discovery face — with *all* medium concerns
(radio, bearer, sector, channel, rate, reach, **coex**, cooperation, fragmentation, mobility tracking) behind
it. Regions/sectors/bearers are **never** NFD-visible faces: surfacing one is a **§7 soft-state violation** (L2
handing L3 a location-keyed route it cannot recompile). A new bearer is a trait-seam + a `RadioCapability`,
below the face.

## 1. Why NFD cannot own radio decisions

NFD's forwarding intelligence assumes **a face is a link whose responder is attributable**: best-route/ASF
rank nexthops by measured RTT — "this Data came from that face, so it costs X." Broadcast wireless breaks this
at the root: responders are **many, with different reach**, and by doctrine there is **no host identity** to
attribute to (`mac-addressing-doctrine.md` §2). NFD's multicast strategy only **floods**; nothing in NFD
models airtime, hidden terminals, contention, coex, or probabilistic reach. Exposing wireless as faces asks
NFD to actuate a radio with a model it does not have. (Empirically, wireless-NDN work pushes the intelligence
*out* of NFD into broadcast + suppression — our CCLF is exactly that — which is the tell.)

**The IP indictment.** Treating each radio as a *wireless wire* (an L2 link, L3 routes among them) is the
first-principles error; OLSR/AODV/batman-adv exist to paper over the fact that the "wires" share spectrum and
have probabilistic reach. NDN can do better only if the name lets a competent MAC own the medium and expose the
smallest honest abstraction upward.

## 2. Mobility-first (why there is only one face)

Wireless links exist **first and foremost to enable mobile connectivity**. A wireless link that resembles a
wire is a *tiny subset* that *falls out of* the mobile case when motion happens to be zero for a while — never
a reason wireless exists, because a wire is always superior for a truly fixed link. The NDR MAC is **general
infrastructure**, not reserved for an application, so **every case always applies** and the design must target
the essence (motion), not the degenerate corner (temporary stillness).

And **link condition is never static** — it is not a property of your own radio but of the **presence and
movement of peers** and the environment. Even a bolted-down node sees perpetual flux: peers move, appear,
sleep, and interfere. So there is no durable "region" to name. A "region" is *soft location*, and soft location
changes continuously.

## 3. The principle: exactly one wireless face

- **Face** = the NFD-facing unit = **one wireless "helper"/discovery face** for the node's whole wireless
  subsystem (alongside genuinely different faces — e.g. a wired uplink). NFD does what it is good at:
  `name → face` by FIB + PIT reverse-path, over a single broadcast face where there is **no nexthop selection
  to botch**. Forwarding to it means *"I don't know where this name lives — MAC, handle it."*
- **Medium** = `(RadioId, Channel)` — the internal **airtime-scheduling** unit (*"one medium = one schedule"*,
  `GLOSSARY`). Many, below the face. (Face ≠ medium; conflating them was the drift.)
- **Bearer** = a PHY family — a trait seam (`FrameIo+RadioKnobs` / `AdvBackend` / `NanBackend`), the
  bearer-agnostic contract in `ndn-radio-hal`. Below the face.
- **Radio** = the physical device (`RadioId`), published as `RadioCapability`/`RadioKind` the MAC consumes
  (`NAMED_RADIO_EXPANSION_DESIGN.md` §3.2). Below the face.

**Regions/sectors/bearers are never NFD-visible faces — the §7 argument makes it a rule, not a preference.**
The soft-state test (`mac-addressing-doctrine.md` §7): *"the moment L2 holds something the network layer cannot
recompile — a host-keyed route, a persistent peer identity — the host-centric coupling is back through the side
door."* A MAC-offered regional face that NFD installs in its FIB is **L2 surfacing a location-derived route L3
keys on** — forbidden. Under perpetual flux (§2) it is also unstable, but §7 forbids it even where it looks
stable.

**Consequence:** `BleAdvFace`/`MonitorWifiFace`/`NanCoordFace` as *NFD faces* is the wireless-wire error
re-committed (`named-radio.md` admits the doctrine was "contradicted by an in-tree design without anyone
noticing"). They are **bearers under one wireless face.** The shared mux (`SerialRadioBackend` unifying Wi-Fi
`FrameIo` + BLE `AdvBackend`) is a step toward this; the correct next move is **one face over it**, not a second
face.

## 4. The conversation over the one face (NFD is not redundant)

One face does **not** make NFD a dumb name-forwarder — its competence is **orthogonal**: NFD owns the
*namespace* (which name, trust, reliability class, PIT/what's-wanted, congestion response); the MAC owns the
*medium* (which photons, when, where, how). The dialogue rides the **one** face:

- **Descending (NFD → MAC):** the name itself (the MAC derives structure from the prefix), the name's
  reliability/policy class, `ForwardingHint` producer-region priors, and **PIT pressure** — notably **PIT
  lifetime bounds the MAC's exploration effort** (the MAC pursues a name across radios only as long as NFD
  still wants it).
- **Ascending (MAC → NFD):** NDNLPv2 **congestion marks** (NFD understands and shapes Interest rate to them —
  a place NFD has *real* competence, US-7) and Data carrying `Measured<T>` provenance — never trusted scalars
  (`NAMED_RADIO_COURSE_CORRECTION.md` §5).

## 5. Coex

Nothing NFD ever sees. Two bearers on one antenna are **mutually exclusive in time** on one RF front-end — a
same-`RadioId` time-exclusion the `(RadioId, Channel)` scheduler must represent (MRMC otherwise assumes
distinct media run concurrently — *"cover channels with radios, not hops"*, `mac-synthesis.md`). The
demand-driven split (`SerialRadioBackend::spawn_demand_coex`) allocates that exclusion **internal to the MAC**,
not two faces that secretly contend.

## 6. MTU and fragmentation — bearer-native ceiling below the face

The one face presents **no fixed MTU** upward. **Fragmentation lives below bearer selection**, sized to each
bearer's **capability ceiling** (`RadioCapability.max_payload`: 802.11 ≈ 2272 B, BLE ext-adv ≈ 245 B, NAN
≤ 255 B). Different MTUs are correct; the wire format is *"negotiated by MTU and context"*
(`name-filter-chapter.md` §8). LP *semantics* may ride above; LP *fragmentation* is bearer-native below (the
`BleFraming::Ndnts` path is the precedent). There is **no airtime-optimal fragment size** — within a bearer
delivery is `p^n` with per-frame `p` length-independent, so bigger is better-or-equal and the tuning knob was
**retired** (`NAMED_RADIO_COURSE_CORRECTION.md` §10.2); **A-MPDU aggregation is rejected** (unicast+ARQ breaks
broadcast, §2.1) — only A-MSDU. Efficiency = **use each bearer's max ceiling**.

## 7. Where the decisions live

Physical-truth functions cannot ascend: RSSI, timing, airtime, reach, contention are measured *at the radio*
and travel up as **`Measured<T>` with provenance** (`NAMED_RADIO_COURSE_CORRECTION.md` §5); `range_rank`/reach,
rate, coding, channel are already **cognition functions**, computed **per name** and refined by measured link
state. Beware the **"strategy" overload**: CCLF ships as `ndn-strategy-cclf` ("forwarder election") but is
*radio-cooperation policy below the forwarder*, **not** the NFD best-route/ASF pipeline. Bearer selection is
name-seeded and today **frontier** (`mac-synthesis.md` §8.6; `named-radio-vision-frontier.md`, "NOT
near-term").

## 8. The frontier this exposes

With face-count settled at **one**, the whole hard problem is naked and lives entirely inside the MAC:

> Get a named Interest/Data to/from **wherever it currently is**, over a medium where "wherever" is always
> moving and unknown — using only **name-derived structure** and **soft, decaying measurement**, with **no held
> peer or region table** (§7).

The MAC's only legal memory is a **name-prefix reachability prior**: *"Data under prefix P recently arrived via
radio R / sector S / bearer B"* — soft, **decaying**, content-keyed, never host-keyed. It is the forwarding
analog of the **nonce-keyed RSSI map** and **content-keyed CCLF** (both already §7-clean). The open question —
**the structure and decay law of that prior**, such that it beats pure flooding under mobility without ever
hardening into a route — is worked in `wireless-forwarding-under-flux.md` (the exhaustive solution space) and
`wireless-face-user-stories.md` (the requirements).

## 9. One-line consequences

1. Add a bearer → add a **trait-seam backend + `RadioCapability`**, **below** the one wireless face — never a
   new NFD face.
2. Expose **exactly one wireless face** (the helper/discovery face) per node; never per-PHY/bearer/radio/region.
3. MTU is a **bearer ceiling** below the face; fragment bearer-native; the face presents no fixed MTU upward.
4. Keep medium measurement + actuation **at the radio**, ascending as `Measured<T>`; NFD routes among faces by
   name, responds to congestion, and bounds MAC exploration via PIT lifetime — it does not pick
   bearers/rates/channels/coex.
