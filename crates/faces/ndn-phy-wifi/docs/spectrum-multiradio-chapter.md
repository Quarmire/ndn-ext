# Spectrum Access & Multi-Radio — the named channel and the pool

**Status: design hypothesis for two coupled MAC facets.** *Where* a name transmits (spectrum access)
and *with what* a node covers the spectrum (multi-radio) cannot be separated: the ~16 ms Wi-Fi retune
tax makes multi-radio the answer to multi-channel coverage, and interference *avoidance* depends
structurally on the multi-radio *sensor* role. So they share one chapter. Both primitives are partly
built but **disjoint and half-inert** (survey §9); this specifies their unification. Every number is
sim over `RadioBus`/channel models; FHSS has **no on-air validation** (sim only). Companion to
`name-filter-chapter.md` (*who*) and `temporal-access-chapter.md` (*when*).

Evidence: `ndn-sim/.../examples/{spectrum_access,multi_radio,multi_radio_opt}.rs`; data
`docs/data/spectrum-access/*.csv`; visualization `spectrum-multiradio-validation.html`.

---

## 1. Introduction

A name must transmit *somewhere* in frequency, and a node has only so many radios to *be* there. The
named move is the same as everywhere else: **the channel is computed from the name** — `channel(name)`
from `H(name)` — so a producer and a consumer of that name meet with no coordinator and no announced
schedule. Hopping the name across channels (FHSS) adds frequency diversity and jam-resistance.

But one measured fact dominates the whole facet: **on COTS Wi-Fi, `set_channel` is a ~16 ms blocking
call** (#97). That is fatal against a µs/ms slot and even against a fast hop, so `can_hop` (retune·4 ≤
dwell) and `vet_hop` *disable* hopping whenever the dwell is short. The retune tax reshapes the design:
fast per-radio FHSS is impractical on COTS, and covering many channels means many *radios*, not fast
hopping. That is why this is a *where + with-what* chapter.

## 2. Terminology

- **Named channel** — `channel(name)` a name uses, computed from `H(name)` (a fixed channel on
  slow-retune radios; a per-epoch hop sequence on fast-retune ones).
- **Occupancy map** — per-`(radio, channel)` `busy%`, the input to avoidance. Must be *shared*.
- **Avoidance** — moving a name off a foreign-occupied channel to a clearer one.
- **Roles** — a radio's job: *mover* (data on a name's channel), *sensor* (sweep to fill the map),
  *rendezvous listener* (discovery channel), *relay* (bridge bands).
- **Coverage / diversity** — radios on *different* channels (be everywhere) vs the *same* channel
  (receive one thing robustly).

## 3. The named channel — static base, the survey's gaps

The base is **static name→channel** (`H(name) % C`): a fixed channel per name — trivial rendezvous
(both compute it), interference *isolated* per channel, **zero retune tax**, and it composes with the
slot schedule (the slot is already `medium_keyed(name XOR channel)`). `HopSchedule` degenerates to this
when `vet_hop` disables hopping. Four gaps the survey found, all decided-but-unactuated:

- **§9.1 — FHSS and occupancy-avoidance are disjoint.** `HopSchedule::channel` keys on the raw name
  hash and ignores `busy%`; `pick_channel` selects the least-busy channel but never enters the map. **No
  path makes the name→channel map avoid an occupied channel.** This is the headline unification.
- **§9.2 — occupancy is single-channel-sensed** → `pick_channel` treats every unsensed channel as
  clearest (0) → selection is *biased toward channels it can't see*. Structurally a multi-radio job (§7).
- **§9.3 — the static channel is inert in the slot key** — `current_ch` is written only by FHSS
  `retune()`, so two static radios on *different* channels compute the *same* slot key. **Fix: feed the
  actual operating channel into `medium_keyed`** so static multi-radio earns the per-channel benefit.
- **§9.5 — cooperative spectrum reports are published but not consumed** for channel selection.

## 4. Shared avoidance — unifying FHSS and occupancy, rendezvous-preserving

Avoidance (adapt the channel to occupancy) and rendezvous (deterministic channel) tension directly: if
two endpoints avoid by their *own* local view they flee to *different* clear channels and lose each
other. The resolution is **sharing**: the name→channel map draws from a channel set pruned by a
**shared** occupancy map (local + the cooperative reports of §9.5 + a periodic sweep), so both endpoints
compute the same pruned map. **Measured** (`spectrum_access.rs`): shared occupancy holds rendezvous at
**100%**; divergent per-node avoidance collapses it (81% → 42% as sensing noise grows). So the §9.1
unification MUST route through the *shared* map — that is the whole design constraint.

And static+shared-avoidance **beats FHSS retune-free**: under a persistent per-channel interferer,
static-spread isolates interference to 1/C of names but *starves* them (worst-name 7%); FHSS spreads
the loss fairly (worst 84%) but pays the retune tax and can't compose with slots; **static + shared
avoid recovers the starved names to 100%/100%**. Fast FHSS stays a *fast-retune-hardware capability*
(the LR2021, #104), not the COTS base.

## 5. The retune tax → multi-radio

A single 16 ms-retune radio can hold **one** channel. To cover the *C* channels a node's names live on,
you add radios, not hops — multi-radio does *in space* what a single radio fails to do *in time*.
Measured (`multi_radio.rs`): one radio covers only ~36% of a node's Zipf-spread interests; six cover
88% simultaneously. And avoidance itself needs the *sensor* role — a single radio senses one channel, so
its avoidance is blind (66% delivery) until the pool completes the map (100%). Multi-radio is not a
luxury; it is how spectrum access's own avoidance is made to work.

## 6. The pool and its roles

A node's radios are a **heterogeneous, local pool** (Wi-Fi/LoRa/HaLow — different bands, channels,
retune costs; the `RadioMediumFace` already carries multiple `RadioBearer`s, `RadioId` threaded). No air
protocol — the node orchestrates its own hardware. Each radio takes a **role**: *mover*, *sensor*,
*rendezvous listener*, *relay*. A scarce radio is **multi-role** (time-shares mover + occasional sweep).

## 7. The assignment optimizer (for 1–3 radios, asymmetric)

4+ radios is rare even in labs; nodes differ in radio count *and* capability; single-radio is the common
case. The optimizer allocates **scarce, heterogeneous radio-time** across roles to maximize delivered
demand — movers follow *effective* (post-avoidance) demand, one radio's time goes to sensing if no
neighbour covers it, and time-sharing lets a lone radio approximate multiple roles. **Measured**
(`multi_radio_opt.rs`):

- **Cooperative sensing makes single-radio viable.** At R=1, self-sensing delivers **0%** (a lone radio
  can't both move and sweep enough for correct avoidance); **consuming a neighbour's shared map delivers
  46%.** The asymmetry doctrine, measured: **rich nodes sense-and-share; poor/single-radio nodes
  consume-and-move.** The free-ride is what makes them work — and it is why §9.5 (consume cooperative
  reports) is load-bearing, not optional.
- **The optimizer beats naive at scarce R** (R=2: 46% vs 28%) by spending a radio on sensing for correct
  avoidance rather than keeping all radios blind movers.
- **Diminishing returns past R=2–3** (46 → 72 → 90 → 95; the 4th radio adds 5%) — the design targets
  1–3 radios, matching reality.

## 8. Coverage vs diversity

The pool's other trade: radios on *different* channels (coverage) vs the *same* channel (RX
macro-diversity, combine). **Measured** crossover at per-radio delivery **p ≈ 0.5**: on a *marginal*
link, concentrate and combine (diversity wins); on a *good* link, spread (coverage wins). The optimizer
chooses per link margin and demand spread. (The MRMC on-air ground truth — multi-radio holds ~90% at 3
hops where a single radio collapses — is the diversity payoff at network scale.)

## 9. Capability floor, asymmetry, and the single-radio node

Spectrum quality is capability-graded and the **floor is load-bearing**: a single-radio node cannot
self-sense enough to avoid correctly, so it must **consume a shared occupancy map** built by richer
neighbours (§7). This makes the whole design degrade gracefully across asymmetry — every node
contributes what it can (a rich node sweeps and relays; a poor node moves and free-rides) and the
shared map is the connective tissue. Fast FHSS, wideband SDR sensing, and fast retune are capabilities
*above* the floor; the base runs on one commodity radio consuming cooperative reports.

## 10. Measured results

| claim | result | source |
|---|---|---|
| **static+shared-avoid vs FHSS** | 100%/100% vs 85%/84%, retune-free | `spectrum.csv` |
| **shared vs divergent avoidance** | rendezvous 100% vs 81%→42% (noise) | `spectrum.csv` |
| **sensing coverage → avoidance** | 66% (1 ch) → 100% (full pool) | `multiradio.csv` |
| **radio count → interest coverage** | 36% (1) → 88% (6) | `multiradio.csv` |
| **single-radio via cooperative map** | R=1: 0% (self) → 46% (coop) | `optimizer.csv` |
| **optimizer vs naive** | R=2: 46% vs 28% | `optimizer.csv` |
| **diminishing returns** | coop 46→72→90→95 over R=1..4 | `optimizer.csv` |
| **coverage vs diversity** | crossover at p≈0.5 | `optimizer.csv` |

## 11. Open

- **Cold-start / blind rendezvous.** For a *known* name, name→channel is trivial; for an *unknown* name
  or unsynced clocks, use a guaranteed-time-to-rendezvous channel-hopping sequence
  ([jump-stay / quorum](https://ieeexplore.ieee.org/document/5935066/)) or the `freq_agile`
  SENSE→SELECT→ANNOUNCE pattern — a well-known discovery sequence, self-announcing. Not yet designed in.
- **On-air FHSS is unvalidated** (sim only; the survey flags "nothing checked against a spectrum
  capture"), and the four code gaps (§9.1/§9.2/§9.3/§9.5) are unactuated.
- **The assignment optimizer is a static allocation** here; a slow re-planner driven by drifting
  interest + occupancy is the next fidelity step.

## 12. References

1. Liu, Lin, Zhou, et al. *Jump-Stay based channel-hopping for guaranteed blind rendezvous.* INFOCOM 2011.
2. Cormio & Chowdhury. *Survey on DSA / dynamic frequency selection for distributed cognitive networks.* 2012.
3. Goodman et al. *Packet Reservation Multiple Access (PRMA)* — the reservation/contention overlay lineage (WHEN).
4. In-tree: `time-slice-mac.md`, `cclf-named-mac.md`; #40 (name-keyed FHSS), #97/#98 (retune), #30
   (occupancy), #71 (multi-radio eval), #104 (LR2021 fast retune), and the MRMC on-air ground truth.
