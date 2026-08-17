# The Named-Data Radio MAC — a synthesis

**Status: the four facets, joined.** Four questions define a medium-access protocol — *who/what* may
transmit, *when*, *where* in spectrum, and *how well* — and this workspace has now worked each into a
validated design hypothesis with its own chapter (`name-filter-chapter.md`, `temporal-access-chapter.md`,
`spectrum-multiradio-chapter.md`, `link-adaptation-chapter.md`). This document is not a fifth facet; it is
the argument that the four are **one protocol**, sharing a small set of structural laws, and an honest
ledger of what is measured **on air** versus in sim.

The thesis in one line: **everything is computed from the name and a common-view clock, so nodes meet and
coordinate with no beacon and no coordinator; the protocol is capability-adaptive above a floor every node
can run; and every control signal is itself named data.**

---

## 1. The four facets, in one table

| facet | question | the named move | headline measured result | on-air? |
|---|---|---|---|---|
| **Name filter** | who / what | in-frame prefix-set Bloom (the "blurred name") — a receiver admits a frame by prefix, not address | 87.1% reject, 0.46% FP, **zero false negatives** / 2500 frames | **yes** (#106 + §4) |
| **Temporal access** | when | `owner(t)=H(name)+epoch mod N` on a common-view clock — the slot is computed, not announced | claimable slot **+119%**; named lease **+148%**; µs common-view (0.4 µs vs 55 µs) | **yes** (#73/#41) |
| **Spectrum + multi-radio** | where / with-what | `channel(name)=H(name)%C` + a **shared** occupancy map; cover channels with radios, not fast hops | static+shared-avoid 100% vs FHSS 85%; single-radio viable only via cooperative sensing | sim (FHSS not on air) |
| **Link adaptation** | how well | worst-receiver rate + per-name reliability target + rateless FEC; the lease **is** the link decision | name-target 2× > coding 32%; rate mandatory; the ungated `phy^n` finding | **partial** (§4) |

## 2. The spine — five laws the facets share

These are not per-facet accidents; each appears in three or four facets, which is the evidence that the
four are one protocol.

1. **Everything is computed from name + clock (beacon-free).** The filter is `H(prefix)`, the slot is
   `H(name)+epoch`, the channel is `H(name)%C`. No facet announces a schedule; both endpoints derive it.
   Dedicated beacons — "the bane of current wireless networks" — appear nowhere. Discovery, timing, and
   rendezvous ride overheard data or are computed outright.

2. **The name's reliability semantics is the master control.** The class bit (alarm / bulk) sets the
   airtime target (link §3), the lease length (link §4), *and* whether the FEC pooling discount is even
   legal (link §5, any-of vs all-of). Rate, FEC, coding, and slot length are subordinate knobs beneath it.

3. **The shared-map law.** Every facet needs a *shared* view or it breaks: occupancy must be shared or
   rendezvous diverges (spectrum, 100%→42%); link-state must be shared or the rate-derived schedule
   desyncs (link §4, 21→2.9); the FEC pooling discount needs shared correlation/count or it
   under-provisions (link §5). A local-only view is the failure mode in three facets independently.

4. **Feedback is named, not ACKed.** There are no PHY ACKs on a broadcast radio (and #96 measured that
   stock 802.11 ignores even the NAV). Instead: reception reports close the RSSI/power loop, NDN
   re-Interest closes the rate loop, overhear *senses* (but does not confirm — a re-forward rides another
   channel). The control plane is the data plane.

5. **Capability-adaptive above a floor.** Nodes are asymmetric in radio count *and* silicon. The design
   degrades gracefully because there is a **floor every node runs** — the legacy basic rate every receiver
   decodes, the single commodity radio consuming a neighbour's shared map, the worst-receiver cap. Fast
   FHSS, wideband sensing, multi-radio diversity, and rateless coding are capabilities *above* the floor.

## 3. What it costs on COTS — and the custom-hardware target

The recurring adversary across all four facets is **commodity Wi-Fi silicon**: the 16 ms `set_channel`
retune that kills fast FHSS and forces multi-radio (spectrum §5); the ignored NAV that means a lease must
self-enforce (temporal, #96); the absent per-frame ACK that pushes feedback onto named data (link §1); the
a81a's broken HT TX that this very synthesis's on-air run caught again (§4). Each facet spends design
effort routing *around* the hardware. That is the case for the custom target (#100, #102): a named
wake-up radio with hardware-scheduled TX and sub-µs timestamping (the LR2021 testbed already removes two
of these constraints) would let the computed-not-announced ideal run without the COTS tax.

## 4. On-air evidence — an honest ledger

The synthesis is only as real as its measurements. This is the full ledger, including the sim-only and the
negative:

| claim | status | evidence |
|---|---|---|
| Name filter admits by prefix, rejects mis-addressed | **on air** | #106 shadow (87.1% reject, 0 FN); **§4 run** (new/* 100% admitted, old/* 100% rejected) |
| Rate plan actuates on air | **on air** | **§4 run** (plan 0/2/4/7 → decoded mcs 0/2/4/7) |
| Link-FEC delivers on real radios | **on air** | #33/#34; **§4 run** (filter survives FEC coding path) |
| Worst-receiver cap / legacy floor | **on air** | #46/#47/#48 (a81a HT broken → VHT; graded single-stream cap) |
| µs common-view + time-slice scheduler | **on air** | #41 (0.4 µs), #73 (two OPis) |
| a81a HT MCS9 does not cleanly actuate | **on air (negative)** | **§4 run** (plan9 → decoded mcs1) |
| Rate cliff gates delivery | **sim only** | `link_adapt.rs`; §4 saw **flat ~78% MCS0–7** at bench range (link saturated — cliff is at the margin) |
| Slot gate improves delivery at N=2 | **on air (negative)** | #111 (actuates but costs 6–9× throughput at N=2 on a clean channel) |
| Cooperative occupancy map consumed for avoidance | **actuated** (`875ddfe`) | §9.5 `busy_pct` fuses neighbour spectrum; §9.2 unsensed≠clear |
| FEC pooling discount gated (semantics + correlation) | **actuated** (`9e56253`) | `fec_redundancy` all-of/any-of + busy-correlation gates |
| Rate→lease closure | **already actuated** (#85) | `from_airtime` IS wired; sized from the *conservative shared* rate (see §5) |
| Operating channel folds into the slot key (§9.3) | **actuated** (`0fcf053`) | static multi-radio gets distinct per-channel schedules |
| FHSS name→channel unified with occupancy (§9.1) | **moot on COTS** | FHSS is retune-disabled by `vet_hop`; unify only matters with fast-retune hardware |

### The §4 synthesis run (2026-08-17)

A fresh cross-facet measurement over the genuinely heterogeneous bench: **a81a** (o5p-0, 2T2R VHT) →
**8812au** (o5p-2, 2T2R), 5 GHz ch149, via the `tier0_fec_onair` A/B. It establishes three things at once
and honestly reports a fourth:

- The previously-**unverified** o5p-0↔o5p-2 5 GHz link is live and strong (~2800 frames/arm sent, ~78%
  decoded).
- **Name filter on air, under link-FEC** — every `new/*` (shipped addressing) row `admitted==heard,
  rejected==0`; every `old/*` (pre-fix) row 100% rejected. The WHO facet, on real air, through the coding
  path.
- **Rate actuation on air** — decoded rate tracks the plan for MCS 0/2/4/7.
- **The honest quirk** — plan MCS9 decoded as mcs1, the a81a HT-broken remap (#48), caught live; and decode
  was **flat across MCS0–7**, so no rate cliff is observable at bench range (the link is saturated — the
  cliff lives at the margin, exactly as `link_adapt.rs` models). Reported, not hidden.

## 5. Actuation pass (2026-08-17) — and a correction

Prompted to "actuate the three sim-only facets," the honest outcome was two actuations and one
correction:

- **FEC pooling gates — actuated** (`9e56253`). `fec_redundancy` applied `phy^n` unconditionally; it is
  now doubly gated (an all-of/`Urgent` name gets no discount; a busy channel damps the effective receiver
  count toward 1). This was the sharpest finding and it is now code.
- **Cooperative occupancy map — actuated** (`875ddfe`). `busy_pct` fused only the *local* map (§9.5); it
  now fuses the neighbour spectrum reports too, which is what makes single-radio avoidance work
  (`multi_radio.rs`). And an unsensed channel is no longer treated as clear (§9.2).
- **Rate→lease closure — already actuated, and I was wrong to call it a gap.** `from_airtime` is wired in
  production (#85, test `the_slot_is_derived_from_airtime_and_the_clocks_guard`) and *deliberately* sizes
  the slot from the **conservative shared rate** — because "the slot map must come out identical at every
  node." That is this synthesis's own shared-map law (§2.3), and `slot_closure.rs` **violated it** by
  sizing each slot from its private adapted rate; that sim overstated the rate-derived win. The production
  code is right; the correction is mine.

- **Slot-key operating-channel fold — actuated** (`0fcf053`). The slot key's channel term was written
  only by an FHSS retune, so two *static* radios on different channels shared one schedule (§9.3). The
  bring-up channel now rides the bearer into the scheduler, so static multi-radio earns distinct
  per-channel schedules — #89's per-medium concurrency, extended to the non-hopping case.

Still open: FHSS name→channel unified with occupancy (§9.1) is **moot on COTS** (retune-disabled by
`vet_hop` — it only matters with fast-retune hardware); the multi-radio optimizer + on-air FHSS remain
sim-only. Those are the remaining honest gaps.
- **The rate cliff needs a marginal link.** Bench range saturates; a real cliff measurement needs
  attenuation or distance, or the weaker MT7610U at range.
- **The custom target (#100/#102)** is where the computed-not-announced protocol runs without the COTS tax.
- **A top-level protocol spec** — wire formats, the name-hash keyspace (#44), the state machines — is the
  document that would follow this synthesis once the sim-only facets are actuated and flown.

## 6. References

The four facet chapters (`name-filter`, `temporal-access`, `spectrum-multiradio`, `link-adaptation`) and
their validation artifacts; the doctrine home (#24); the on-air anchors #33/#34/#41/#46/#47/#48/#73/#106/#111;
the custom-hardware direction #100/#102 (LR2021 + nRF54L15 testbed).
