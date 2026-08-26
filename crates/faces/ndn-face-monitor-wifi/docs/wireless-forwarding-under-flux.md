# Wireless forwarding under flux — the reachability-prior solution space

The frontier exposed by `bearer-face-radio-coex.md` §8 and `wireless-face-user-stories.md`: with exactly one
wireless face, the MAC must *get a named Interest/Data to/from wherever it currently is, over a medium where
"wherever" is always moving and unknown, using only name-derived structure and soft, decaying measurement, with
no held peer or region table (§7).* This is the exhaustive solution enumeration, the ruled-out set, the
composed base candidate, and the simulation plan to iterate toward the optimum. Grounded in two literatures
(DTN/MANET/stigmergic; ICN/NDN-over-wireless) that **independently converge** on the same shape.

## 1. Invariants every solution must satisfy (the hard filters)

A candidate is **ruled out** if it fails any of these:

1. **§7 soft-state.** Every bit of held state must be recompilable at any time; its loss costs performance,
   never correctness. → *no held path, no held route, no peer/region table.*
2. **No host identity.** Forwarding keys on name/content + self-measured physical dimensions only (ephemeral
   nonce, RSSI, sector, bearer). → *anything indexing state by a stable node/destination ID is out.*
3. **Beats flooding.** Must reduce airtime vs pure broadcast under motion, while never delivering *less*.
4. **Airtime-bounded.** Bounded cost under load (a copy/airtime budget), no congestive collapse.
5. **Behind one face.** Works across bearers/radios/sectors invisibly to NFD (`bearer-face-radio-coex.md`).

## 2. The six-axis decomposition (so solutions combine, not just compete)

Every scheme is one choice per axis; the optimum is a *composition*, found by swapping one axis at a time.

| # | Axis | Options (→ = chosen in the base, §5) |
|---|------|------|
| 1 | **Memory structure** | none/flood · prefix→bearer scalar (pheromone/EWMA) · **→ prefix→sector counting-Bloom** · named-interest→gradient · Beta-posterior per (prefix,bearer) · name-prefix backlog · PIT breadcrumb (substrate) |
| 2 | **Decay law** | hard TTL (**→ KITE refresh-or-die**) · **→ geometric evaporation `w←(1−ρ)w` / EWMA** · counting-BF decrement-on-tick · sliding window · consumption-drains-it · bandit discount factor |
| 3 | **Decision rule** | argmax exploit · proportional-stochastic (pheromone α/β) · **→ threshold→flood-fallback** · **→ discounted bandit (UCB/Thompson)** · gradient-descend |
| 4 | **Exploration on miss/stale** | full flood · **→ scoped/TTL flood (copy-budgeted)** · hop-seq-from-prefix probe · **→ passive overhear-and-learn** · **→ bandit probe bonus** |
| 5 | **Cooperation/suppression** | **→ CCLF content-keyed cancel** · **→ deferred-broadcast timer ordering (LFBL)** · MPR relay-set thinning · **→ in-frame BF gossip (BLOOGO)** |
| 6 | **Feedback source** | **→ own Data (PIT satisfaction)** · **→ overheard Data** · overheard Interest · **→ reception reports** — all keyed on ephemeral nonce + RSSI-bin, never identity |

## 3. Candidate families mapped onto the axes (the catalog)

| Family | Contributes to axis | Keep / role |
|---|---|---|
| **Epidemic + Spray-and-Wait** (DTN) | 1 (none), 4 (flood+copy budget) | **The correctness floor.** A fully-decayed prior degrades to epidemic-with-a-copy/airtime-budget (= our named lease). |
| **Stigmergic pheromone** (AntHocNet/ARA) | 1 (scalar), 2 (`w←(1−ρ)w`+reinforce), 3 (proportional) | **Closest template** — `τ(bearer,prefix)`, evaporation = the decay law, reinforce-on-Data-return. Drop destination indexing. |
| **Directed Diffusion / GRAB** (gradient) | 1 (gradient), 2 (timeout+reinforce) | Data-centric, already identity-free ("NDN before NDN"): named-interest → decaying gradient. |
| **EWMA / Encounter-Based (EBR)** | 2 (EWMA) | Cheapest legal scalar: per-bearer "recent named traffic" `EV←α·now+(1−α)EV`. |
| **Discounted / Thompson bandit** | 3 (decision), 4 (probe) | **The controller.** Answers *when a prior beats flooding*: exploit while confidence tight, **flood when discounted confidence decays past the UCB bonus.** Beta-posterior = calibrated staleness. |
| **Backpressure, commodity = name-prefix** | 1 (backlog), 2 (drains free) | Optional: backlog gradient decays "for free" via consumption; use as a bias term, flood at low load. |
| **NDN Self-Learning** (Shi) | 4 (discover-on-broadcast), 6 (record-on-Data) | Keep the **discover/record loop**; **delete route-hardening + Nack-only teardown** (that *is* the forbidden hardening). |
| **V-NDN / Navigo** | 1 (prefix→reach-coord), whole-loop | **Published proof** a soft, re-discoverable `prefix→where-last-reachable` binding beats flooding under mobility without a route. Swap geo-area → sector/bearer/RSSI. |
| **LFBL / deferred broadcast** | 5 (defer-timer ordering) | **Zero neighbor state, identity-free.** The prior sets defer priority: higher recent-reach → shorter timer → fires first; others self-suppress. = our CCLF. |
| **BFR / BLOOGO** (Bloom reachability) | 1 (counting-Bloom), 5 (in-frame gossip) | **The storage.** Counting/decaying Bloom per sector *is* the prior; BLOOGO's in-frame BF rides the lease frame so neighbours gossip belief with no peer table. = our prefix-set BF. |
| **ASF** (adaptive forwarding) | 3 (reinforcement loop) | Keep the *control loop*; **discard RTT + per-nexthop attribution** (both collapse on a shared broadcast face). Re-key to (prefix, physical-reach), reinforce on RSSI/success. |
| **KITE / MAP-Me** (locator-free mobility) | 2 (refresh-or-die), whole-loop | **The published archetype of the decay law:** a name-keyed reachability breadcrumb that must be refreshed or it evaporates, with flooding as the floor. |
| **PIT reverse-path + scoped flooding** | substrate | **Correctness floor + transactional route.** Name-keyed, identity-free, self-expiring; the prior only ever *scopes the flood* the PIT then carries. |

## 4. Ruled out (by the §1 filters)

| Ruled out | Filter it fails | Salvage |
|---|---|---|
| AODV / DSR / OLSR / DSDV (held routes) | 1, 2 — commit to a discrete path; coherence collapses under mobility, re-discovery diverges | sequence-number freshness; MPR relay-set thinning |
| NLSR / link-state for NDN | 1, 2 — global topology-DB can't converge faster than motion; control storms | hyperbolic/greedy coordinate *idea* (but must be self-measured, decaying) |
| GPSR + GLS (geographic) | 2 — needs destination coordinate + node-ID→location directory | stateless beacon-refreshed greedy-descent, but descend the *reach* gradient (sector), not Euclidean |
| PRoPHET **transitivity** (β); MaxProp/RAPID dest-probability vectors | 2 — mathematically require a stable destination identity to chain/index | PRoPHET's encounter-reinforce + `γ^K` aging *shape* (re-keyed to prefix) |
| ASF **RTT + nexthop attribution** | 2 — attribution collapses on one broadcast face with an anonymous, changing responder set; RTT measures contention + the serial-bridge artifact, not reach | the reinforcement control loop only |
| Self-learning **route hardening** | 1 — persistent FIB + Nack-only teardown is the forbidden hardening | the discover/record loop only |
| Any neighbor/peer table | 2 | re-key every observable onto sector/bearer/RSSI |

## 5. The composed base candidate

**Name:** *soft prefix-reach* forwarding. Both literatures converge here; every piece maps to §1-legal state.

- **Memory (axis 1):** per node, `prior[sector] = countingBloom(name-prefixes)` — one counting Bloom per
  radio/sector/bearer, cell = a prefix's reach weight. (= our existing prefix-set Bloom, made counting.)
- **Decay (axis 2), two time constants:**
  - *Event refresh (KITE):* on Data-return / overheard Data / reception report for prefix `P` via sector `s`,
    `insert(prior[s], P, +g)` and reset `P`'s TTL on `s`.
  - *Ambient decay (pheromone/EWMA):* slow tick `prior[s] *= (1−ρ)`; a prefix whose weight falls below `θ` or
    whose TTL expires is forgotten. Between events, `w ← w·e^(−Δt/τ)`.
- **Decision (axis 3), per Interest for `P`:** query each sector's BF → weight vector `w[s]`.
  - if `max(w) > θ_exploit`: **bias** — set the LFBL defer-timer ordering so high-`w` sectors fire first /
    transmit on those bearer(s); a discounted-UCB bonus occasionally probes elsewhere to keep the prior honest.
  - else (cold/decayed): **scope = all** → full scoped flood, **bounded by a per-name copy/airtime budget**
    (Spray + our named lease). *This floor is what stops it hardening.*
- **Cooperation (axis 5):** content-keyed CCLF cancel + LFBL defer-ordering driven by the prior; the belief is
  gossiped as an **in-frame decaying BF** (BLOOGO) riding the lease frame — no peer table.
- **Feedback (axis 6):** own Data (PIT satisfaction) + overheard Data + reception reports, keyed on the
  **ephemeral nonce + RSSI-bin** (no identity).
- **Substrate:** the **PIT reverse-path** carries every transaction and is always correct; the prior only ever
  *scopes the flood*.

**The correctness invariant (why it can never harden):** a cold or wrong prior only ever **widens** the flood
scope. It can never create a route that must be explicitly invalidated. Lose the entire prior → the node
degrades to scoped-flood epidemic (a performance cost), never to non-delivery. This is §7 soft-state, satisfied
by construction.

## 6. It's mostly built already

The composed base is not greenfield — the literature *validates the shape we've been building* and supplies
only the missing **decay law**:

- prefix→sector counting-Bloom = **`name-filter-is-prefix-set-bloom`** made counting.
- defer-timer suppression = **CCLF** (`ndn-strategy-cclf`), content-keyed.
- copy/airtime budget = the **named airtime lease**.
- reach feedback keyed on nonce+RSSI = the **nonce-keyed RSSI map** + reception reports (`ndn-radio-cognition`).
- in-frame belief gossip = the **advertised-belief** we already exchange between hops.
- The **new** pieces: (a) the two-constant decay law (KITE-TTL + pheromone/EWMA tick); (b) the bandit
  exploit/explore gate; (c) turning the prefix-set BF into a *counting, decaying* per-sector prior.

## 7. Evaluation plan — ndn-sim (the harness is ready)

`ndn-sim` (`/ndn-sim/crates/ndn-sim`, ~21k LOC) runs **real `ForwarderEngine`s** on a deterministic DES kernel
over a mobility-aware radio bus with **PER + SINR + capture + hidden-terminal + half-duplex + airtime** already
modeled. **The physics substrate needs no change.** Work is targeted:

- **A. Mobility.** Expose `RandomWaypoint`/`Waypoint` through the scenario schema + live command (today only
  static/linear are reachable — documented gap); add a **speed/pause-time sweep axis**; add Gauss-Markov +
  reference-point-group models. *(`src/world.rs`, `src/scenario.rs`, `src/control_plane.rs`, `src/mcp.rs`.)*
- **B. Single-face baseline.** Already correct — `SimRadioFace`/`RadioBus` is one broadcast face per node.
  Author radio-only scenarios with `interference_range_factor>1`, `set_sinr_interference(true)`,
  `set_half_duplex(true)` so exploration cost is meaningful.
- **C. The new forwarding strategy (the real work — in the engine, not the sim).** Implement the §5 base as a
  `Strategy` alongside `ndn-strategy-cclf`: the per-sector counting-Bloom prior, the two-constant decay, the
  bandit gate, feeding from `ndn_signals_core::LinkSignals` + reception reports (already bridged in
  `src/cognition.rs`). The sim consumes it via `set_strategy` — engine-obliviousness preserved.
- **D. Real name-filter admission.** Port the in-frame Tier-0 prefix-Bloom into `src/radio.rs`'s RX path
  (today it's energy-accounting only) so name-keyed *admission* is simulated.
- **E. Metrics + the sweep.** Add **exploration cost vs mobility rate** (floods issued because the prior was
  stale) and **prior staleness at decision time** to `src/telemetry.rs`/`src/netstat.rs`; write
  `examples/ndr_mobility_sweep.rs` (real engines over `RadioBus`, RandomWaypoint at swept speed/density,
  `DesKernel` for reproducibility) emitting delivery ratio, airtime-per-satisfied-Interest, exploration count,
  prior-staleness — **replacing** the abstract `examples/mobility_study.rs` (BFS connectivity, not the fabric).

**Per-axis A/B protocol.** Hold the base fixed; swap one axis and measure: decay law (TTL-only vs EWMA-only vs
both vs discounted-bandit) · decision (argmax vs proportional vs bandit) · exploration (full vs scoped vs
probe) · memory (scalar EWMA vs counting-Bloom vs Beta-posterior). Optimum = the composition that maximizes
delivery-per-airtime across the mobility-rate sweep.

**Fidelity caveats to carry (from the on-air ledger, `mac-synthesis.md`):** the rate cliff and FHSS are
sim-only; `slot_closure` once overstated a slot win by sizing from private rate (shared-map-law violation); the
**hidden-terminal effect is exactly what a 3-node bench can't show and only a multi-node mobile sim can** — so
run enough nodes with `interference_range_factor>1` for exploration-cost numbers to mean anything. Anchor sim
trends against on-air where possible (`real-wifi-multihop-ground-truth`).

## 8. Open tuning parameters (the sim finds these)

`g` (reinforce gain) · `ρ` / `τ` (evaporation / EWMA constant) · per-prefix TTL · `θ_exploit`, `θ` (forget) ·
bandit discount + exploration-bonus weight · copy/airtime budget per name · Bloom size + `k` (we measured `k=4`
for the Tier-0 filter — revisit for a *counting* BF). The tuning tension is universal: decay fast enough that a
stale binding fades before it misleads, slow enough to keep signal — `ρ`/`τ` vs the mobility rate is *the* A/B.

## 9. Iteration protocol

The base (§5) is the starting composition, not the answer. Iterate: (1) build C+D+E; (2) run the §7 sweep;
(3) swap one axis (§2 table) and re-run; (4) keep the winner, repeat. The doc's family catalog (§3) is the
menu of axis-options to try. Rule-outs (§4) are closed unless a filter assumption changes.

### References (mechanism → source)
PRoPHET (IETF draft-irtf-dtnrg-prophet-03) · Spray-and-Wait (Spyropoulos 2005) · AntHocNet/ARA (ACO) · Directed
Diffusion/GRAB · EBR · discounted-UCB / Thompson (non-stationary bandits) · backpressure (Tassiulas-Ephremides)
· NDN Self-Learning (Shi 2017, NFD #4279) · V-NDN/Navigo (Grassi 2013/2015) · NLSR (Hoque 2013) · LFBL (Meisel
2010) · BFR (Marandi 2017) / BLOOGO (Angius 2012) · ASF + prefix-granularity (Liang 2020) · KITE (2018) /
MAP-Me (2016).
