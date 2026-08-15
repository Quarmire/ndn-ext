# Temporal Access — the named grant on a common-view clock

**Status: design hypothesis for one MAC facet.** This chapter specifies the temporal-access layer of
the Named Data Radio (NDR) MAC — *when* a node may transmit — and reports its validation. The grant
primitive and its refinements are **built and on-air** (the scheduler in `src/sched.rs`); its
foundation, the **cross-node clock**, is the part newly validated in depth here. The open piece — the
adaptive controller that decides *whether to impose a schedule at all* — is named in §9 and not yet
designed. Cross-facet interactions are noted in §10. Companion to `name-filter-chapter.md` (the *who*;
this is the *when*).

Evidence: `ndn-sim/.../examples/{clock_phase_gap,clock_mac_tie}.rs` (drive the production `Timekeeper`,
`NetworkTime`, and `RadioBus`); data `docs/data/clock-phase/{residual,mac_tie}.csv` + `traces.ndjson`
(OTLP-in-Data); visualization `temporal-access-clock-validation.html`; scheduler results
`p5-results.md`.

---

## 1. Introduction

Contention is the named radio's pain: a shared half-duplex broadcast medium, hidden and exposed
terminals, and — measured — carrier sense that *hurts* when misapplied (LoRa LBT at N=3 collapsed
delivery 205→64; EDCCA starves a clean channel). Scheduling trades a little flexibility for
collision-freedom and a bounded latency tail, which the real-time classes (alarm, telemetry) need.

The NDR move is to assign each slot to a **name**, not a host: `owner(t) = H(name) + epoch(t) mod N`,
**computed, never announced**. Every node derives the same ownership from the name and a shared clock,
so there is no roster to join, elect, or repair — a node that appears or vanishes just leaves its
computed slots unused (self-healing). The slot is a collision-free transmit grant for its content; the
[token](named-token-scheduling.md), realized in time.

This buys collision-freedom **only if nodes agree on `epoch(t)`**. So the whole facet rests on a
shared, accurate clock — and the accuracy achievable on commodity radios is the deep question this
chapter answers.

## 2. Terminology

- **Grant** — a `(slot, channel)` a name owns on the common-view clock, computed from `(name, clock)`.
- **Superframe** — `N × slot_us`; the schedule repeats each superframe.
- **Guard band** — the slack in a slot beyond the frame airtime; must exceed the cross-node clock
  **residual** or adjacent-slot owners collide.
- **CCLF** — the within-slot election: overhear-and-cancel, fitness-jitter; decides *which server of a
  name* transmits (schedule ⟂ demand).
- **Lease** — a won slot held for multiple base slots, amortizing the election (LeaseClass Latency/Bulk).
- **Residual** — a node's cross-node clock error vs the common view; the guard-band floor.

## 3. The grant primitive (built)

`SlotSchedule` (`ndn-radio-cognition`) is the pure decision; `FaceScheduler` (`src/sched.rs`) gates
every outbound data frame at one TX choke point on it. Robust control frames bypass.

- **Ownership**, class-aware and **medium-keyed**: `owner_slot_in(H(name), class)` XORed with the
  channel, so a name owns a *different* slot on ch36 than ch149 — access latency divides by the number
  of independent media. Latency and Bulk classes punch disjoint lanes so they cannot collide by
  construction.
- **Within-slot election (CCLF)**: the slot grants the medium to the *name*; if several nodes hold that
  content, the smallest-jitter one transmits and suppresses the rest. The jitter window is sized by
  *detection time*, mixes the epoch so the winner rotates (no starvation), and shortens under backlog.
- **Claimable slots** (`NDN_SCHED_CLAIM`): an owned-but-idle slot opens to a CCLF claim by another name
  with data — the demand-adaptive refinement (**+119%** measured). Positive-evidence gated: a slot is
  claimed only if the owner is provably absent (nonce presence + relay discounting), never on silence.
- **The lease** (`NDN_SCHED_LEASE`): a won slot buys the rest of a multi-slot lease, not one frame,
  with an owner-return contract (yield the instant the owner is heard). Both ends are **computed** —
  because, per §6, nothing can *tell* a station to stop.

The grant costs **nothing on the wire**: slot and channel are a pure function of `(name, clock)`, and
the class rides the same name-keyed `GroupTable` the Name Filter uses. No in-frame bits, no control
frames — computed and overheard.

## 4. The clock substrate

Time is a capability-graded substrate (`ndn-time`): `RadioHwClock` disciplines a local clock from RX
hardware timestamps; `NetworkTime` composes single-hop offsets into a network timeline; `Timekeeper`
(`ndn-timekeeper`) is the servo (intersection + skew regression). The scheduler reads `now_us()` and
sizes the guard from the clock source: **Wall 1000 µs · CommonView 200 µs · Hardware 10 µs**.

The RX timestamp is the exploitable instrument: it is latched on **preamble correlation** — a physics
event — so it is µs-precise (~0.4 µs, #74) even on commodity chips. The TX side is not timestamped on
COTS. §5 is about getting cross-node time anyway.

## 5. Closing the cross-node phase gap (validated)

**The gap.** `RadioHwClock::common_view()` is "bounded by the master's build→air TX latency." A
build-stamped beacon is stale by that latency at reception, biasing every offset estimate.
Measured over the real `Timekeeper` (`clock_phase_gap.rs`): the residual tracks the latency and
**breaks convergence above ~50 µs** — 46 ms of "sync" at 1 ms latency.

**The exploit — sub-µs from RX stamps alone, no TX-timestamp feature.** Build time on the RX stamps
COTS gives us and cancel the untimestamped TX side:

| discipline (no HW TX-stamp) | residual, any latency | how |
|---|---|---|
| build (naive) | ∝ latency (breaks >50 µs) | — |
| **calibrate** | mean removed → jitter (good to ~200 µs) | subtract the per-radio constant, average the jitter |
| **shared reference** | **6.7 µs, flat** | RX-stamp a common ambient beacon; the latency **cancels in the receiver pair** |
| air (HW TX-stamp, ideal) | 6.7 µs | stamp at radiate — needs the feature |

The shared-reference exploit reaches the ideal floor with only RX stamps, because a common emission's
TX latency (mean *and* jitter) is identical for both receivers and cancels in their difference —
"don't reconstruct the instrument, exploit a common event." WiFi supplies those events free (every AP
beacon, every neighbour's frame).

**Multi-hop — mechanism, not limit.** A chain first showed a 3-hop *horizon* — but that was the
Timekeeper's *uncertainty fusion* (correct for a mesh where every node hears the reference), which does
not propagate a chain. `NetworkTime`'s **explicit stratum composition** propagates all 8 hops with no
horizon. **Design decision: drive the cross-node clock with `NetworkTime` composition; reserve the
Timekeeper's uncertainty fusion for single-hop/mesh and the local servo.** And the exploit *compounds
with depth*: the systematic build gap accumulates `k·txlat` (linear), while the zero-mean air/shared
residual accumulates only `√k·jitter` → **~3 µs at 8 hops**. A deep mesh strengthens the case for the
shared reference.

**What it earns (over the real `RadioBus`, `clock_mac_tie.rs`).** A residual must fit inside the guard
or adjacent-slot owners collide. Delivery sweep:

| clock (residual) | guard 10 µs | 1000 µs |
|---|---|---|
| air/shared 8-hop (3 µs) | **100%** | 100% |
| air/shared 1-hop (7 µs) | 95% | 100% |
| software / build @1 ms | 20% | 97% |

And the guard's price: **10 µs guard → 25 Mb/s, 144 µs p99; 1000 µs guard → 0.5 Mb/s, 7 ms p99** — a
**50× goodput gain and 49× latency reduction**. Closing the phase gap is what earns the slots, and it
needs no TX-timestamp feature.

## 6. Self-enforcement — the NAV is a dead letter (measured)

#96 measured that stock 802.11 **ignores the virtual carrier sense**: RTS/QoS/CTS-to-self with a
28.7 ms NAV left victim throughput at baseline, while a physical-CCA control throttled it to ~13%. So a
hard constraint: **the lease and slot MUST be self-enforced by computed listen-before-talk against the
Tier-0 filter — never delegated to the 802.11 Duration field.** Both ends of the lease are computed
because nothing can be *told* to stop.

## 7. Capability floor and gradient

Clock quality is capability-graded, and the floor is load-bearing: **the guard is set by the worst
clock in the neighbourhood** (every node must agree where a slot begins), so one poor clock widens the
guard for all — unless the schedule runs per-capability sub-groups (an open design question).

| tier (all nodes → capable) | residual | guard | slot density |
|---|---|---|---|
| floor: wall/host | ~ms | 1000 µs | sparse (the #111 tax) |
| +RX-stamp + calibrate | ~50 µs | 200 µs | moderate |
| +RX-stamp + **shared reference** | ~7 µs (√k·… multi-hop) | 10 µs | dense (25 Mb/s) |
| +HW TX-stamp | ~7 µs | 10 µs | dense (no common ref needed) |

The shared-reference tier reaches the dense regime on commodity hardware — the design targets it as the
practical ceiling, with wall as the universal floor.

## 8. Measured results

| item | result | source |
|---|---|---|
| **Clock-phase gap** | build ∝ latency, breaks >50 µs (46 ms @1 ms) | `clock_phase_gap.rs`, real Timekeeper |
| **Shared-ref / calibrate** | 6.7 µs flat / jitter-limited — **no TX-stamp** | `residual.csv` |
| **Multi-hop** | Timekeeper horizons @3 hops; **NetworkTime holds 8 hops (3 µs)** | `residual.csv` |
| **MAC tie-in** | residual > guard → collisions; tight clock → 10 µs guard | `mac_tie.csv`, real RadioBus |
| **Payoff** | **50× goodput, 49× latency** vs a ms clock | `mac_tie.csv` |
| **Lease** | **+148%** throughput (elections constant ~1/superframe; lease multiplies a win) | `p5-results.md` |
| **Claimable slot** | +119% demand-adaptive | code refs (#76) |
| **Reserved lanes** | refuted at bench (0.4 pp) — owner-return + capture already protect the owner | `p5-results.md` |
| **NAV** | ignored — self-enforce, don't delegate | #96, named-filter-mac-redesign §10 |
| **Telemetry** | 25 OTLP-in-Data spans via ndn-observability | `traces.ndjson` (#107) |

## 9. The reservation overlay (designed + validated)

The negatives (LBT/EDCCA hurt when misapplied; the #111 tax) say scheduling is **not free**. The
instinct was a binary *engage/disengage* controller — but that is the wrong structure (a mode switch
is discontinuous and leaves coexistence undefined). The MAC literature solved this 40 years ago as a
**reservation overlay** — [PRMA](https://www.netlab.tkk.fi/opetus/s38149/s02/reports/PRMA_jl.pdf) /
[Reservation-ALOHA](https://en.wikipedia.org/wiki/Reservation_ALOHA), the modern
[grant-free/grant-based](https://pmc.ncbi.nlm.nih.gov/articles/PMC6720724/) hybrid — where reservation
and contention run **simultaneously**, and the codebase already approximates it (claimable slot +
owner-protection + lease + class = a named PRMA/R-ALOHA).

**The design is a per-name choice, not a node mode:**
- **Latency-class content RESERVES** its owned slot (protected, PRMA-voice-like).
- **Bulk content CONTENDS** for idle/unreserved slots via the claimable-slot/CCLF mechanism
  (R-ALOHA data), immediate at low load — and *escalates to reserving* only when its traffic is
  *measured* contended (fusing occupancy #30 + observed collisions). Capability-floored: a clockless
  node can only contend + CCA.
- **"Disengaged" is not a node** — it is unreserved airtime, accessed by contention that still defers
  around computed reservations. Same MAC, no reservation of its own.

**Validated over the real `RadioBus`** (`reservation_overlay.rs`, hidden terminals, tight 7 µs clock):
the overlay is best-or-tied in every load cell — it holds the **latency class at 112 µs** (vs
contention's 1377 µs tail, 12×) *and* gives **bulk 76 µs at low load** (better than TDMA's 228 µs, via
idle-slot reuse) rising to a bounded 232 µs at saturation. It subsumes contention (which collapses
under hidden-terminal collisions) and TDMA (which wastes idle slots). This also reconciles #111 (N=2,
no hidden terminals): the reserve-vs-contend policy correctly *contends* there.

**Coexistence — the honest limit (§10 gradient, measured worst-case).** Purely-uncooperative *foreign*
traffic (ignores the schedule, never learns) degrades reservations toward contention — **10% foreign
already blows the latency tail 8× (112→939 µs)**. No time-sharing MAC protects a reservation from a
node that ignores it and cannot be heard. CCA helps for *audible* foreign; the **self-announcing
reservation** (its periodic occupancy) lets a *cooperative-but-clockless* node learn and avoid it; but
a genuinely foreign device does neither. So the design decision is firm: **foreign traffic is handled
by *avoidance* (sense + move in frequency/time — the coband-cognition path), not by *time-sharing*.**
Reservation governs the cooperative set; cooperative and foreign occupants are separated, not
interleaved.

**The escalation policy (validated, `reserve_policy.rs`).** Capability-graded: the **reactive floor**
(collision-hysteresis, no sensing — every node runs it) already gets near-full burst protection (p99 6
vs contention's 9) at **~1/5 the airtime cost of always-reserve (12% reserved vs 59%)**. Occupancy
fusion (#30) is a *gated* add-on — it adds little in this regime, and its meta-weight (occupancy's
measured predictiveness) correctly **discounts a misleading sensor** (no over-reservation), satisfying
"fuse only when it helps." Default to the floor; fuse occupancy only where it is measured predictive.

**The CRDSA/SIC tail (measured — and it corrected the design).** Replica diversity **without SIC does
not raise the contention ceiling — it *hurts* at saturation** (delivery 38%→5% as replicas grow, since
replicas add load). The CRDSA throughput gain fundamentally requires **SIC** (soft-symbol
cancellation), which commodity 802.11 does not expose. So the base MAC does **not** rely on coded
random access: on COTS, the answer to saturation is *reservation escalation* (above) or *load
reduction* (rate/FEC — the link-adaptation facet). **SIC-CRDSA is a custom-silicon ceiling (#100),
noted, not designed into the COTS MAC.**

## 10. Open cross-facet interactions

- **The Name Filter interaction is benign** — the grant is computed from `(name, clock)` and shares the
  `GroupTable`, so it adds no in-frame bits. The remaining coupling is semantic (one name-keyed table).
- **FHSS vs slotting are mutually exclusive on Wi-Fi** — `set_channel` is ~16 ms, so `vet_hop` refuses a
  hop schedule whose retune eats the dwell. Composing `(slot, channel)` needs a fast-retune radio.
- **Cross-node clock over ambient beacons is unproven on air** — the RX floor and the cancellation are
  measured single-node/in-sim; disciplining to real AP beacons via `CommonViewPool` is the next on-air step.
- **Per-capability sub-schedules** — whether a mixed-clock neighbourhood must run one wide guard or can
  partition by clock tier is undesigned.

## 11. References

1. Elson, Girod, Estrin. *Fine-Grained Network Time Synchronization (RBS).* OSDI 2002 — receiver-side
   common-view (the shared-reference cancellation).
2. Maróti et al. *The Flooding Time Synchronization Protocol (FTSP).* SenSys 2004 — stratum composition.
3. IEEE 1588 (PTP) — two-way exchange cancelling symmetric path delay.
4. In-tree: `time-slice-mac.md`, `cclf-named-mac.md`, `named-token-scheduling.md`; tasks
   #41/#74/#75 (hardware common-view), #93 (lease), #96 (NAV), #111 (slotting tax), #107 (OTLP).
