# named-radio — course correction

*2026-07-16. Written after Phase 2 (NAN data path) completed and proved on air, and
after re-reading what this project had already decided.*

Companion to `NAMED_RADIO_EXPANSION_DESIGN.md` (the phase plan this note corrects),
`~/Downloads/latest/named-radio-design-rationale.html` (the rationale it convicts
us against), and `~/Downloads/latest/named-time.md` (the sibling subsystem that
already solved two problems we were about to solve badly).

---

## 0. The finding

**Phase 2 is a host-centric regression, and this project predicted it two weeks
before it happened.**

`request_ndp()` returns a **bound UDP socket on an IPv6 link-local address over a
virtual Ethernet interface**. That is NDN-over-UDP-over-IPv6-over-Ethernet-over-
802.11. Every host-centric layer is present and we reproduced each faithfully:
MAC addressing, EUI-64, duplicate-address detection, ports.

The rationale doc states the thesis we violated:

> NDN is the semantic escape — address by name, not host. named-radio is the
> MAC/PHY escape — exploit broadcast, don't fight it. Two halves of the same move.

And it had already tried NAN specifically:

> **NAN Discovery Windows** — a broadcast rendezvous bolted back on top of a
> unicast MAC by time-sync. The 34 ms timing fight we just won is the cost of that
> retrofit.

We then paid that cost twice more (§2).

---

## 1. The test we skipped

The rationale prescribes a four-step method for every incumbent mechanism:

> 1 · Name the incumbent. 2 · Name its function. 3 · Name the assumption (almost
> always: unicast, host-addressed, associated). 4 · Survival test. Does that
> assumption survive name-addressed broadcast?

Run on NDP, which we never did:

| step | NDP |
|---|---|
| incumbent | NAN Data Path (NDP/NDPE, M1–M4) |
| function | establish an L2 link between **two hosts** so IP can run over it |
| assumption | unicast, host-addressed, associated — **all three** |
| survival test | **fails all three** |

NDP exists so an Android app can call `connect()`. Its purpose *is* the thing we
are escaping. It should have been admitted as an **interop bearer** — "if a stock
device offers us a data path, speak its language" — and never as *our* data path.

The tell was in the bugs, not the design review. Phase 2's open work (task #23) is
**negotiating per-path transport ports**, and the blocker is that the port TLV's
layout is paywalled. *A name has no port.* We were blocked on acquiring a
host-centric field we should not have wanted. Likewise "one data path per node" —
a socket-binding artifact with no meaning for names.

## 1.1 Worked: the MAC address, as we actually used it

The rationale works the fields and reaches a verdict:

| field | function | verdict |
|---|---|---|
| addr1 · dest | which receiver keeps it | **→ the name is the filter** |
| addr3 · BSSID | infrastructure binding | **→ no infrastructure** |
| addr2 · source | dedup · demux · metrics | **→ redesign, not identity** |

`ndn-nan/src/ndi.rs::eth_to_dot11`, written 2026-07-16:

```rust
out.extend_from_slice(&dst);        // addr1 = receiver (the peer's NDI)   ← a host
out.extend_from_slice(&src);        // addr2 = transmitter (our NDI)       ← a host
out.extend_from_slice(&cluster_id); // addr3 = BSSID (the NAN cluster)     ← infrastructure
```

Three fields, three verdicts, zero applied. And `dot11_to_eth` filters
`if dst != our_ndi` — the receiver keeps it **by MAC**, not by name.

The rationale's admission traps name two more:

> **Never keyed on identity** — the moment the filter asks "who sent this," you've
> rebuilt the MAC.

`ndi::DuplicateFilter` keys on `(sender, seq)`. The doc's answer is the coding
layer's **generation nonce**, or a per-frame content hash — *per-message, not
per-sender*.

> Metrics don't rescue the tag either: per-neighbour RSSI presupposes the
> point-to-point link abstraction broadcast dissolves — what you want is
> name-driven feedback (Interest-satisfaction), not link-layer per-sender SNR.

We key RSSI per neighbour in `MediumState`.

---

## 2. What the regression cost, measured

Every Phase 2 defect traces to importing the unicast model. This is the evidence,
not rhetoric — each was found on air today:

| defect | root cause | host-centric premise |
|---|---|---|
| retry storm: 20 receives, 1 distinct payload; 19 datagrams starved | MAC retries an **unACKed unicast** frame to its limit | *"ACK/ARQ tuned to one receiver"* |
| NDP id collision: whoever requested second always timed out | an NDP id is unique only in its **initiator's** scope | per-host session identity |
| DAD `EADDRNOTAVAIL` | IPv6 duplicate-address detection on a link-local | host addressing |
| task #23 blocked | per-path **transport port** layout is paywalled | ports |

The retry storm is the sharpest. We fixed it with `RETRY_LIMIT=0` *because a
monitor peer never ACKs* — i.e. we spent the day discovering that unicast ARQ is
meaningless on a broadcast-native medium. The rationale says so in one line.

**And the counter-evidence, which matters:** the LoRa cognition loop shipped the
same day is the vision working. Priority derives from the **name**
(`alarm`=Urgent); fan-out is PIT in-records; the redundancy budget is driven by
**measured re-Interest** — literally *"name-driven feedback (Interest-
satisfaction)"*. Nothing in it is host-addressed. The stack is not lost; one
bearer went the wrong way.

---

## 3. What was already right (do not rebuild)

- **`FrameFormat::RawNdn`** — the data-centric bearer, already shipped, its own
  comment: *"addr1/addr3 = destination group (or broadcast); addr2 = name-derived
  source. **The NDN name is the addressing — these fields are a name-keyed index,
  not host ids.**"* `MonitorWifiFace` carries NDN over it with no IP anywhere.
- **`Rendezvous`** — the DW is *"one implementation among (always-on,
  TSCH-by-name, ALOHA)"*, selected by power budget, never foundational. The
  refactor the rationale demanded is **done**.
- **`RadioCapability` / `TxIntent`** — honest numbers through descriptors; the
  generic core never speaks TSFT/EDCCA/MCS.
- **`ndn-radio-drivers` split** — the rationale's "driver-repo question" answered
  exactly as prescribed (HAL first, let it settle, then lift). **Done.**

---

## 4. Election is host-centric too — and named-time already fixed it

Task #19 ("Phase 1c: master/anchor election") inherits NAN's rank:

```
master_rank = preference·2⁵⁶ + random·2⁴⁸ + MAC
```

Arbitrary **host identity**. "Who is master of the network" is the framing we
reject.

`named-time.md` §8 solved this for clocks, and the mechanism generalises:

> **The anchor election — the best local clock self-selects.** Reuses the CCLF
> kernel (`cclf_elect`) verbatim, swapping content-connectivity for clock quality.
> … A local GPS out-elects a WAN NTP uplink by construction. **Failover is the same
> mechanism as election.**

Election **by contribution**, not identity — and it is already a kernel in this
codebase (`cclf_elect`), already re-targeted once. The named-radio instance is the
third: swap clock quality for *what this radio contributes to the data* — content
held (`neighbors_holding`), demand served (`Demand.fanout`), reach
(`range_rank`). All three are already computed in `ndn-radio-cognition`.

**Keep NAN's rank for interop clusters** (an S23 will not negotiate on
contribution). Use contribution-based anchoring for our own. That is the
interop/native split this note argues for generally.

---

## 5. Trust: the intuition has a mechanism already

The instinct was *"you work with the data directly (trust contexts or
something?)"*. Both sibling docs land on the same answer, independently:

- `named-time.md` §13: *"QoS becomes physical and per-name — `NameContext.priority`
  → cognitive plane → PHY (rate/FEC/power/`TxDiscipline`), with the class
  **schema-gated by name** so it can't be grabbed. Same trust-binding as the
  time-authority gate."*
- rationale §8: *"Authority, not a group key. … admission of authorities is a named
  **LVS schema** — only keys authorised for a namespace are admitted — reached
  independently by named-time's Sybil analysis."*

So the trust context is an **LVS schema pinning which keys may speak for which
namespace**, and it is what stops a priority class (or an anchor claim, or a
rendezvous slot) from being grabbed. Not new machinery — the same gate named-time
uses for time authority.

Note the correction named-time forces on naive de-bundling (rationale §7):

> Logical functions ascend; **physical-truth functions cannot**. Signing decides
> who and whether-altered; it never decides where the emitter physically was or
> when the photons actually arrived. … So the bottom is **the sole source of
> physical truth**, carried upward as typed, uncertainty-and-exposure-bounded
> measurements — not as trusted scalars.

This is the guardrail against over-correcting: "everything ascends to names" is
wrong. RSSI, timestamps, distance bounds stay at the PHY — they just travel as
`Measured<T>` with `sigma` **and** `MeasurementProvenance`, not as bare numbers.

---

## 6. Devourer — what it contributes

`OpenIPC/devourer` is the same architectural bet (userspace libusb, skip
mac80211), on more silicon than we support — including **Wi-Fi 6** and the
**8812EU** we already own. Two readings.

**As a mirror.** Its `scheduled-mac` **abolishes association** — grants are
declarative, published in beacon IEs; beacons ride the MAC-timed **TBTT grid below
the CSMA/queueing layer**. It rejects the same incumbent we do. But its grants are
keyed **by MAC address**, with a UE registry and a cellular downlink: it swapped
one host-centric control plane for another. **The named-data move is the same
rejection with slots keyed by name/demand** — which `rendezvous.rs` already names
`TSCH-by-name`.

**As a supplier of honest numbers** — for descriptors we currently populate with
guesses:

| devourer mechanism | fills the seam that today is | doc |
|---|---|---|
| **`TxReport`** — per-frame ACK/no-ACK via C2H | `observe_phy_per`, *inferred* from Interest→Data round-trip misses | named-time Cut 1 neighbourhood |
| **`SetAckResponder`** — hardware ACK, dynamically retargetable | why we set `RETRY_LIMIT=0`: *a monitor peer never ACKs* | rationale §5 (ARQ) |
| **NHM 12-bucket noise histogram**, CCA/false-alarm counters, DIG, per-tone interference localiser — **frame-free** | `ChannelOccupancy{busy_pct}` — a coarse placeholder driving `pick_channel` | cognition SENSE |
| **hardware TSF** (`ReadTsf`, RX latch `RxAtrib.tsfl`), sub-µs | our **software** TSF jammed off beacon timestamps | named-time Cut 1 (`LinkStamp`) |
| **TBTT-timed departure + async URBs** | `TxDiscipline::ScheduledAt{granularity_ns}` — named-time Cut 2 says *"when scheduled-TX hardware appears, nothing above the trait changes"*; it says the URLLC lane waits on *"`ScheduledAt` hardware + async URBs"*. **Devourer has both.** | named-time Cut 2 |
| 5/10 MHz narrowband, FHSS 0.5–2.5 ms/hop | reach/rate knobs beyond MCS; makes multi-channel DW (#19) nearly free | `RadioCapability` |
| A-MPDU (+30%) | we have A-MSDU only (8822E) | — |

The last row of the first block is the important one: **devourer plausibly unlocks
`TxDiscipline::ScheduledAt` on commodity Realtek**, which is the precondition
named-time set for TSCH-by-name and the URLLC lane. That is the bridge from
"devourer is interesting" to "devourer serves the vision."

Also worth stealing: their adaptive link **probes actively** — power/MCS sweeps and
CW tones on a beacon feed to find the boundary *before* frame loss finds it. Our
cognition is purely reactive.

Rung check (rationale §3): devourer is the **same rung** — driver owned, firmware
and PHY rented. It does not climb to SDR/open-MAC. It maximises the rung we're on,
which is worth a great deal and is not the same as the differentiated research.

---

## 7. What this changes

1. **Demote NDP/NDI to an interop bearer.** Keep it — it works, it is proven, and a
   stock device that offers a data path deserves an answer. But it is *not* our
   data path, and **task #23 should not be worked**: negotiating per-path
   transport ports is buying deeper into the wrong model. Our nodes carry NDN over
   `RawNdn`, which needs no NDI, no IPv6, no ports, and has no port collision.
2. **Reframe task #19.** Not "master election". Contribution-based anchoring via
   `cclf_elect` (named-time §8's third instance) + name-keyed rendezvous. Keep
   NAN's rank on the interop path only.
3. **Retire the identity-keyed artifacts** as the coding layer lands:
   `DuplicateFilter(sender, seq)` → generation nonce / content hash.
4. **Feed the SENSE bus real evidence** from devourer's mechanisms — that is the
   cheapest large win, and it strengthens the data-centric half.
5. **Keep one non-Wi-Fi bearer first-class.** LoRa is currently the *most*
   data-centric thing we have. The rule of three exists so a trait is not "that
   backend's API in a costume".

## 8. The pattern to watch for

The rationale caught the engine hardcoding `in_dw`/`dw_index` and called it
*"foundation-by-accident"*, noting:

> The real foundation is the seam we already have **and then immediately
> violated**: `poll(now, heard) → { tx, wake_at }`

Same shape, again: we built `RawNdn` (name-addressed), then built a second bearer
that host-addresses. **Building the right seam does not prevent violating it.** The
phase plan is a poor guard here, because a standard's phases import that standard's
model — Phase 3 (NAN-USD) is another standard's host-centric control plane, and
deserves the §1 survival test *before* it is built, not after.
