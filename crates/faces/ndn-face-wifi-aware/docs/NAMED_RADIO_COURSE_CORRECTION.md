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

## 2.1 The precedent that decides it

This is not a new judgement call. **We already made it, against a bigger prize.**

`ndn-face-monitor-wifi/docs/AMPDU_PORT_SCOPE.md` records rejecting **A-MPDU — a
proven 179 Mb/s** — on architectural grounds:

> 1. **A-MPDU is unicast + ARQ; the NDN bearer is broadcast + no-ARQ.** … A
>    broadcast NDN bearer has **no peer and no ACKs**.
> 2. **It changes the communication model.** Real aggregation ties TX to *one* peer
>    station, not "any monitor receiver." That breaks the open broadcast/multicast
>    property that makes named-radio attractive.
>
> This is a **bearer-architecture decision** (broadcast vs unicast-with-BA), not
> just reverse-engineering.

Every clause applies to NDP verbatim: it ties TX to one peer station (NDI MACs +
negotiated path), it has ACKs (well — it *wants* them; see the retry storm), and it
is unicast. We turned down 179 Mb/s to protect the broadcast property, then built
NDP, which spends it. **Same decision, opposite conclusion, three weeks apart.**

And the status table in `named-radio.md:129` lists:

> `| No-host-addressing / verify-on-decode doctrine | built (doctrine) |`

The doctrine is recorded as **built** while a shipped bearer violates it.

## 2.2 The ratified doctrine that pre-empts "regression" — and why it does not cover NAN

The strongest objection is not in the NAN docs; it is in `ndn-rs/ARCHITECTURE.md`,
and it is **ratified doctrine**, not drift. Two parts.

**(a) The two-tier design is a considered answer to a real limit** (`:357-363`):

> The named-radio faces above are connectionless and small-frame (NAN follow-ups
> ≤255 B, BLE advertisements ≤~245 B) — fine for presence, discovery, and small
> Interest/Data, but **lossy for multi-fragment objects**. The high-throughput tier
> is a **NAN NDP**: a real IPv6 link-local Wi-Fi connection between two peers, over
> which the node runs UDP.

**(b) The below-the-Face defence** (`:385-388`):

> **It stays data-centric:** once the group forms it is just a multi-access IP
> subnet … so the host-centric group-owner election lives *below* the Face. Above
> it, `FaceKind::WifiDirect` faces carry only names —

That is coherent: host-centricity below the Face is invisible above it, so who
cares. **Attack the doctrine on its own terms, not the artifact.**

**The defence is sound for Wi-Fi Direct and unsound for NAN**, for one reason: with
Wi-Fi Direct the IP subnet is *the kernel's, and free* — you get a working
multi-access link by asking. Using it is pragmatism, and the host-centric parts
genuinely are below a seam we did not write.

With NAN **we wrote the state machine ourselves.** Nobody handed us a subnet. We
*synthesised* the host addressing by hand — a TAP netdev, an EUI-64, DAD, a
`fe80::`, a port allocation scheme — while `RawNdn` and `name_group_mac` sat in the
same workspace. Below-the-Face is a defence for *inheriting* a host-centric layer.
It is not a licence to *build* one.

And (a)'s premise does not survive contact either: the ≤255 B limit is a property
of **NAN follow-ups**, not of the radio. `RawNdn` is an 802.11 **data** frame —
~2300 B, with A-MSDU already shipping on the 8822E. The bulk tier never needed IP;
it needed a data frame. We reached for a socket because a socket was familiar.

The tell is that `ARCHITECTURE.md` cannot hold both claims at once. At `:327-334`
it lists `ndn-face-wifi-aware` in the family where:

> the NDN *name* is the only addressing — **no association, no pairing, no host
> addresses**

and at `:357` it gives that same face an IPv6 link-local and a UDP socket. Both
sentences are in one document. Only the coordination tier satisfies the first.

## 2.3 The fair counter-argument

The regression was an **explicit trade, not an oversight**, and the note must say
so. `ndn-face-wifi-aware/src/lib.rs:8-12` designs the split deliberately:

> 1. **service publish/subscribe** → an NDN `DiscoveryProtocol`;
> 2. **follow-up messages** (small, connectionless) → *this* face, the name-native
>    **coordination** channel …;
> 3. **NDP** (NAN data path, IPv6 link-local) → a plain `UdpFace` for **bulk**
>    (no new transport code — reuses `ndn-face-native`).

The justification is economy: *"no new transport code"*, and
`NAMED_RADIO_EXPANSION_DESIGN.md:127` — *"the seam is untouched."* That is a real
argument and it bought a real result.

Note the tell, though: **only #2 is called "name-native."** The doc knew.

**Two things make the correction cheap rather than a rewrite:**

- The regression is **contained in one module**. `ndi.rs`'s own header concedes the
  cause honestly — *"A kernel/firmware NAN stack does this conversion in the
  device… **the kernel's IP stack wants Ethernet**"* — i.e. the host-centrism is
  imposed by the borrowed standard, at the adapter. Meanwhile the engine stays
  name-clean: it *"settles which addresses a data path uses"* and never binds one.
  So NDI is a **swappable adapter, not a foundation**.
- `RawNdn` already exists and needs none of it.

## 2.3 The constructive alternative already ships

The answer to "then what *is* the link-layer address?" is in
`named-radio-vision-frontier.md:44-51` — a three-layer naming scheme:

> Layer 0 *listen-by-signal-space* (zero bytes — interest = where you tune);
> Layer 1 *match-by-hash* (truncated BLAKE3 commitment per droplet, for PIT/CS
> match + hardware filtering, à la name-group MAC); Layer 2 *resolve-by-name* (full
> name rides the signed Data)
> … Layer 1 has a real analog already (**`name_group_mac`**).

The link-layer address is a **truncation of the name**, not a host identity — and
`name_group_mac` ships today. `RADIO_SUBSYSTEM.md:143` states it plainly:
*"`dst`/`src` are name-derived group MACs, not host IDs."*

And the same doc gives the template for adopting a host-centric standard without
importing its model (`named-radio-vision-frontier.md:65-70`, on TSCH):

> keep 802.15.4e TSCH machinery but **invert the host-centric parts**: a **cell
> belongs to a name** … the hop grid is name-keyed

That is the prescription for NAN: **keep sync/DW/SDF, invert NDP.**

Finally, the frontier doc states the thesis in the form the instinct reached for
(`named-radio-vision-frontier.md:11-19`):

> You don't join a network; you stand where certain names are bright and read by
> name / write by emitting. *Peers are data too* — a node publishes
> capability/observation as named signed Data (`/can-serve/…`, reception/spectrum
> reports), **never "I am device X."**

NDPE advertises *"I am device X, at `fe80::<my EUI-64>`, on port P."* The doctrinal
violation was written down in advance.

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

## 8. Why the doctrine did not guard anything

The sweep turned up a structural cause worth more than any single argument here.

**The named-radio doctrine is homeless.** `docs/named-radio.md` and
`docs/named-radio-vision-frontier.md` — which carry nearly every quote in §1–§3 —
are **gitignored staging docs**, and the "eventual home" they name
(`.claude/notes/named-radio/`) **does not exist in the workspace**. Meanwhile
`NAMED_RADIO_EXPANSION_DESIGN.md` — the phase plan that specified NDP — sits
in-tree, versioned, and reviewed.

So the doctrine that forbids host addressing is unversioned and unfindable, while
the plan that violates it is the durable artifact. A doctrine that is not in the
repo cannot guard the repo. **That asymmetry is the mechanism of the drift**, and
it is more fixable than any argument: give the doctrine a home in-tree.

Two supporting gaps:

- **`RADIO_SUBSYSTEM.md` never mentions NAN.** The crate doc that contains the
  "IP radio vs named radio" argument and the NAN data path have never been
  reconciled in writing — which is likely why nobody noticed.
- **The `//!` docs of `ndn-nan` and `ndn-nan-core` contain no data-centric framing
  at all** — pure protocol mechanics — while `ndn-face-monitor-wifi` is saturated
  with it. The asymmetry in the *code* mirrors the asymmetry in the docs.

## 9. Scope discipline — this is not "start over"

`named-radio-vision-frontier.md:100-108` sets the house style, and it binds this
note:

> Every grand piece lands on something built: the field's *law* is the suppress
> predicate (`policy.rs`); its *eyes* are the reception/spectrum reports
> (`control.rs`) … The vision is **"notice the built pieces are facets of one
> object," not "start over."**

Accordingly, nothing here proposes deleting working code. NDP/NDI stays, proven, as
the interop bearer. `RawNdn`, `Rendezvous`, `RadioCapability`, `cclf_elect`,
`name_group_mac` all already exist — the correction is mostly **re-pointing**, plus
one honest demotion.

## 10. The pattern to watch for

The rationale caught the engine hardcoding `in_dw`/`dw_index` and called it
*"foundation-by-accident"*, noting:

> The real foundation is the seam we already have **and then immediately
> violated**: `poll(now, heard) → { tx, wake_at }`

Same shape, again: we built `RawNdn` (name-addressed), then built a second bearer
that host-addresses. **Building the right seam does not prevent violating it.** The
phase plan is a poor guard here, because a standard's phases import that standard's
model — Phase 3 (NAN-USD) is another standard's host-centric control plane, and
deserves the §1 survival test *before* it is built, not after.
