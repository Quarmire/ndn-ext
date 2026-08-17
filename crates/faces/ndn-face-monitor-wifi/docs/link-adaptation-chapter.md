# Link Adaptation — how well a name is carried

**Status: design hypothesis for the fourth MAC facet.** *How well* a name is carried — its rate, its
redundancy, its reliability target — is the last of the four questions (after *who/what*, *when*,
*where/with-what*). Unlike the others it is **mostly already built and on air**: per-name rate, per-name
systematic link-FEC, and the worst-receiver rate cap all ship and are measured. So this chapter's job is
not to propose an architecture but to **rank the levers by measured effect, bound where each is valid,
and close the one cross-facet seam** (rate → lease). Every number is sim over the 11n rate/erasure model
or `RadioBus`; the on-air anchors (#33/#34 plan-driven FEC, #46/#47 worst-receiver, #48 HT/VHT) are cited
where they exist. Companion to `name-filter-chapter.md` (*who*), `temporal-access-chapter.md` (*when*),
and `spectrum-multiradio-chapter.md` (*where / with-what*).

Evidence: `ndn-sim/.../examples/{link_adapt,slot_closure,fec_pooling}.rs`; data `docs/data/link-adapt/*.csv`;
visualization `link-adaptation-validation.html`.

---

## 1. Introduction — no ACKs, one rate for all

Classical link adaptation runs on a feedback loop: transmit, read the ACK, measure the per-frame loss,
adjust the rate. A **named broadcast radio breaks that twice**. There is no PHY ACK (a broadcast frame has
no unicast destination, and #96 measured that stock 802.11 ignores even the NAV in an injected frame), and
one broadcast transmission must serve every receiver of a name at once — the **worst-receiver penalty**,
where the weakest member throttles the group. The rate/FEC *knobs* were built facet-by-facet (#27 rate,
#29/#33 FEC); what this chapter settles is which knob actually moves delivery, and under what conditions.

The feedback question turns out to be **already answered in the shipping code**, and the answer is the
named-data one: the loop is closed by named data, not by ACKs. Reception reports (`/localhop/radio/report`)
carry "who heard me at what RSSI," closing the outbound rate/power loop (`control.rs:439`); NDN
**re-Interest** is the delivery signal, feeding a `RateCalibrator` and a contextual bandit at object
granularity (`control.rs:295`). It is *not* open-loop-RSSI-only. An earlier draft of this facet proposed
that loop as new design — it is not; the doctrine was already right, and the honest contribution here is
to measure it and bound the levers that ride it.

## 2. Terminology

- **Worst-receiver rate** — the highest PHY rate every audible receiver of a name can decode
  (`worst_neighbor_rx_mcs` → `mcs_ceiling`). The leader-based-multicast base.
- **Reliability target** — a per-name-class property: *alarm* (serve every receiver, including the
  straggler) vs *bulk* (serve the group, let stragglers re-Interest). Sets how hard the link works.
- **Any-of / all-of** — whether a generation succeeds if *any* receiver catches each frame (cooperative
  relay/recode) or *every* receiver must decode (the alarm case). Opposite poles; the name picks.
- **Pooling discount** — `fec_redundancy`'s reduction of parity as the neighbour count grows (`phy^n`).
- **Lease** — the airtime a name reserves (the *when* facet); this chapter shows it **equals** the link
  decision.

## 3. Three levers, ranked by measured airtime (`link_adapt.rs`)

A heterogeneous name-group (RSSI −84 … −56 dBm, one straggler below MCS0's floor), a generation of K=32,
the 11n rate→erasure cliff. Three candidate levers, measured:

- **(1) The per-name reliability target dominates.** An *alarm* name must serve the −84 dBm straggler; its
  airtime is gated by that straggler no matter the coding. A *bulk* name drops the straggler (it
  re-Interests later) and runs at a higher rate: **28 ms vs 56 ms, a 2× cut from a single class bit.**
- **(2) Coding is a real but smaller lever.** Rateless (incremental redundancy — stream until decode) vs
  systematic K-of-N (a pre-sized block) — **both rate-swept, fairly** — differ by **32%** (rateless 56.8 ms
  vs systematic 74.8 ms for the alarm case). The gap is exactly block-vs-incremental waste. *(An earlier
  version pinned FEC to MCS0 while sweeping rateless, a rigged 59% — corrected.)*
- **(3) Rate selection stays mandatory.** The −84 dBm straggler cannot clear even MCS0 (21% erasure at the
  most robust rate); **coding is not optional for the tail — it is required.** No amount of rate choice
  serves it without redundancy, and no redundancy is free of a rate.

Rateless's non-airtime gift is **decoupling**: the strong receiver finishes in 30 ms — 2× sooner than the
straggler — regardless of when the sender stops streaming. Rate stays mandatory, coding helps modestly,
and the *name's target* is the master dial.

## 4. The rate → lease closure (`slot_closure.rs`) — HOW-WELL is WHEN

A name's lease duration (the *when* facet) is not an independent parameter: it **is** the airtime its
adapted rate needs to move its generation to its reliability target —
`airtime(adapted_rate, generation, target)`. But the code's `slot_us` is a fixed env constant
(`SlotSchedule::from_airtime` has zero production callers, #85). A fixed slot is wrong two ways at once: if
`A_name < slot` the lease over-reserves and the tail is idle (wasted airtime); if `A_name > slot` the
generation spills the boundary and — with the guard band (#84) — the overflow is lost.

**Measured** over a name mix whose airtimes come from the link decision (delivery split by class, because
raw name count is a rigged metric — a small slot maximizes count by dropping every alarm and packing cheap
bulk):

| policy | alarm served | airtime efficiency |
|---|---|---|
| fixed 8–16 ms | **0%** | 14–44% |
| fixed 32 ms | 20% | 37% |
| fixed 64–128 ms | 6–12% | 14–21% |
| **rate-derived (`from_airtime`)** | **55%** | **98%** |

No fixed slot wins: small slots serve *zero* alarm names (their worst-receiver leases all exceed the
slot), large slots waste airtime and starve throughput. **Rate-derived leases serve the alarm class at
98% efficiency** — because the lease is sized to each name's true need. The 55% is budget-limited, not
policy-limited (a real scheduler adds alarm-priority). This is the seam #85 named, closed: the *when*
facet's slot length is computed by the *how-well* facet.

## 5. The ephemeral count → FEC pooling (`fec_pooling.rs`) — a real but doubly-gated lever

The ephemeral source nonce (§2) cannot carry per-peer rate state (it rotates every frame), so rate
adaptation does not key on it — it keys on the durable reception-report id (§7). The nonce's honest
contribution is the neighbour **count**: the §2 source-nonce density feeds `receiver_count`, which feeds
`fec_redundancy`'s pooling discount (`policy.rs:669`): `eff = phy^n`, `parity = ceil(k·eff/(1−eff))`. As
the count grows, parity — and airtime — shrink. **Measured**: ~30% airtime off by n≥3, pool-delivery
holding. But `phy^n` silently assumes two things, and both gates are load-bearing:

- **Semantics gate.** `phy^n` (all n receivers miss a frame) is an **any-of** model — the pool wins if any
  neighbour catches each frame. Applied to an **all-of** name (every receiver must decode — the alarm
  case) delivery **collapses to 0% at n≥2**: parity shrinks toward zero exactly when all-of needs it to
  grow. Correctly sized all-of (no n-discount) holds ~99%ⁿ.
- **Independence gate.** `phy^n` assumes independent loss. Correlated loss — one interferer hitting all
  receivers, the contention reality (`wifi-loss-is-contention`) — drives delivery **97% → 46% → 3% → 0%**
  as the common component climbs to 0.30. `phy^n` overstates the pool.

**Code finding.** `fec_redundancy` applies `phy^n` **unconditionally** — no any-of/all-of check, no
correlation input. As written it under-provisions an alarm (all-of) name at high neighbour count, and any
name on a contended (correlated) channel — a decided-lever-missing-guard of the same species as the
spectrum §9 seams. The discount must read the name's reliability semantics *and* a correlation estimate,
not just the count.

## 6. What overhear can and cannot do

On a broadcast radio, same-channel overhear (the CCLF suppression channel) is a free source of neighbour
RSSI — real link sensing that complements reception reports. But **overhearing your own content
re-forwarded is not an implicit ACK**: a relay re-broadcasts on `H(name) % C`, very likely a *different*
channel than the origin is camped on, so the origin cannot count on hearing it. Overhear gives sensing,
not delivery confirmation. The delivery signal stays re-Interest (pull) + reception reports.

## 7. Identity — ephemeral for the count, durable for the rate

Rate adaptation needs to accumulate per-peer link quality; you cannot do that on an identity that rotates
every frame. So the design **splits identity by job**: the §2 ephemeral source nonce (`[u8;6]`, per-frame)
feeds density, DoS attribution, and the FEC *count*; the reception-report `node_id` (`u64`, persistent)
carries the per-peer rate/RSSI state and the worst-receiver cap. The ephemeral plane never undermines rate
adaptation because rate never keys on it — two granularities for two jobs.

## 8. The spine — three observations across the facet

1. **The name's reliability semantics is the master control.** It picks the airtime target (§3), the lease
   length (§4), *and* whether the pooling discount is even legal (§5). Rate, FEC, and coding are
   subordinate knobs beneath the class bit.
2. **The shared-map law, third appearance.** Occupancy had to be *shared* for rendezvous (spectrum),
   link-state for the schedule (§4, divergent worst-rate reads desync it 21→2.9), correlation/count for
   pooling (§5). Every facet needs a shared view or it breaks. This is a structural invariant of the whole
   MAC, not a per-facet accident.
3. **Feedback is named, not ACKed.** Reception reports close the RSSI loop; re-Interest closes the rate
   loop; overhear senses but does not confirm. The control plane is the data plane — again.

## 9. Capability floor and asymmetry

Link adaptation is capability-graded with a floor. The floor is the **legacy basic rate every neighbour
can decode**: reports and broadcasts always ride it (`send_robust`), and a `LEGACY_ONLY_RX` neighbour
forces data down to it. The graded rungs above are the single-stream HT cap (`SINGLE_STREAM_HT_RX_MCS=7`,
the userspace RTL8812EU's one RX chain, measured 2026-08-13), full HT/VHT (#48: the a81a's HT TX is broken,
VHT works), and rateless coding (a capability, unwired at the link — §10). Every node advertises its RX
capability; the sender caps to the worst audible one.

## 10. Measured results

| claim | result | source |
|---|---|---|
| **name-target vs coding** | target 2× (56→28 ms); coding 32% | `link_adapt.csv` |
| **rate mandatory (tail)** | −84 dBm straggler: 21% erasure at MCS0, no decode without FEC | `link_adapt.csv` |
| **rateless decoupling** | strong RX finishes 2× sooner than the straggler | `link_adapt.csv` |
| **rate-derived lease** | 55% alarm served at 98% efficiency; no fixed slot > 20% | `slot_closure.csv` |
| **lease needs shared link-state** | 21 → 2.9 delivered as worst-rate misreads 0→30% | `slot_closure.csv` |
| **pooling discount** | ~30% airtime off by n≥3, delivery held | `fec_pooling.csv` |
| **discount is any-of only** | all-of + discount → 0% at n≥2 | `fec_pooling.csv` |
| **discount needs independence** | correlated loss → 97→0% | `fec_pooling.csv` |

## 11. Open / decided-but-unactuated

- **`fec_redundancy`'s `phy^n` is ungated** (§5) — needs an any-of/all-of semantics gate and a correlation
  estimate. The sharpest actionable finding of the facet.
- **The rate → lease closure is unactuated** (§4) — `SlotSchedule::from_airtime` has zero production
  callers (#85); the slot is still an env constant. The sim shows the payoff; the wiring is pending.
- **The legacy-basic-rate auto-trigger is unwired** (#46/#47) — the graded single-stream cap actuates, but
  nothing flips the `legacy_gate` from a `LEGACY_ONLY_RX` advert outside tests; *data* frames don't drop to
  legacy when a legacy-only neighbour appears.
- **Per-frame PER / TxReport (#42) — is it worth building?** Delivery is inferred at object granularity
  from re-Interest, which already closes the rate loop. The honest home for per-frame PER is
  overhear-based sensing (§6), not a PHY ACK. Whether it beats object-granularity feedback is unmeasured —
  measure before building the driver work.
- **Rateless/RLNC is unwired at the link** (#58) — the F2 codec attaches to the forwarder, not the radio.
  §3 measured that its airtime win over systematic FEC is modest (32%); its real value is decoupling and
  the any-of pool. Worth wiring only where those pay.

## 12. References

1. Kuri & Kasera / Sun et al. *Leader-Based Rate Adaptive Multicasting for Wireless LANs.* GLOBECOM 2007.
2. *A leader-based multicast scheme with a Raptor code in IEEE 802.11 multi-rate WLANs.* EURASIP JWCN 2014.
3. Shokrollahi. *Raptor Codes* / Luby, *LT Codes* — rateless/fountain erasure coding.
4. Ho et al. *A Random Linear Network Coding Approach to Multicast.* IEEE Trans. IT 2006 (RLNC).
5. In-tree: `named-airtime-lease.md`, `temporal-access-chapter.md`; #29/#33/#34 (link FEC on air),
   #46/#47/#48 (worst-receiver), #42 (feedback), #58 (RLNC), #62 (§2 ephemeral nonce), #85 (from_airtime).
