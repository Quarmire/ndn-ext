# NDR MAC test suite & benchmarks

How we validate the Named Data Radio MAC. The suite is **organized by the four facets**
(`GLOSSARY.md` §0 — WHO / WHEN / WHERE / HOW-WELL) and layered by what each kind of test can prove:

| Layer | What it proves | Where | CI? |
|---|---|---|---|
| **1. Unit tests** | a mechanism works in specific cases | `#[cfg(test)]` in `tier0.rs`, `sched.rs`, `schedule.rs`, `policy.rs`, `ephemeral_id.rs`, `coop.rs`, … | ✅ |
| **2. Design-invariant tests** | a MAC *promise* holds over a **corpus** (statistical regressions caught) | `tests/mac_facets.rs` | ✅ |
| **3. On-air benchmarks** | the promise holds on **real hardware**, with measured numbers | `examples/*` + `firmware/esp32c5-ndn/tools/link_latency.py` | ❌ (needs radios) |

The philosophy: unit tests catch *"this case broke"*, invariant tests catch *"the guarantee eroded"* (e.g. a
filter that quietly over-admits, a schedule that starves a slot — invisible to a single-case test), and
benchmarks catch *"it's true in code but not on air"* (the recurring lesson of this project).

---

## Layer 2 — design-invariant suite (`tests/mac_facets.rs`)

Deterministic (seeded splitmix64 PRNG), no hardware. `cargo test -p ndn-face-monitor-wifi --test mac_facets`.

| Test | Facet | Promise | Threshold |
|---|---|---|---|
| `who_filter_never_false_negatives` | WHO | a receiver admits **every** frame under its registered prefix | exact (0 false-negatives over ≥5000 checks) |
| `who_filter_over_admission_is_bounded` | WHO | over-admission (Bloom FP) is far below "matches everything" | empirical FP < 0.25 (k=4, m=126) |
| `who_over_full_filter_is_inert` | WHO | a filter stuffed past `FILL_CAP` matches nothing (DoS guard) | 200/200 masks rejected |
| `when_owner_slot_is_a_pure_function` | WHEN | `owner_slot` is deterministic & in range (no clock/state term) | exact |
| `when_slots_are_fair_across_names` | WHEN | airtime is ~uniformly divided; no slot starves | every slot share ∈ [0.5×, 2×] uniform (n=8000) |
| `when_medium_keying_decorrelates_channels` | WHEN | same name on two channels owns different slots (#89) | > 50% differ (ideal 87.5% at 8 slots) |
| `when_lease_class_lanes_are_disjoint` | WHEN | Latency→reserved, Bulk→open, never crossing | exact |
| `howwell_reliability_orders_robustness` | HOW-WELL | `for_intent`: MostRobust ≤ Balanced ≤ Throughput in rate | monotone + MostRobust carries STBC+LDPC |
| `howwell_he_reach_levers_gated_on_capability` | HOW-WELL | ER-SU/DCM used iff `he_cap`; else HT+STBC+LDPC | exact |

**Gaps to fill next** (invariant tests worth adding): WHO — ephemeral-ID PFS/DAR collision convergence;
WHEN — CCLF suppression converges (one forwarder wins); claimable-slot reclaim doesn't double-grant;
WHERE — FHSS hop is name-pure and visits every channel over an epoch window; HOW-WELL — worst-overheard-
receiver cap never resolves above a legacy-only neighbour's advertised ceiling.

---

## Layer 3 — on-air benchmark catalog

Each measures a facet on real radios and reports numbers (not just pass/fail). Run individually with the
noted features/hardware. These are the *measured* counterpart to the Layer-2 invariants.

### WHO — addressing / filter
- **`name_filter_eval`** — Tier-0 filter admit/drop rates on air + the OTLP span pipeline over the filter ops.
- **`tier0_fec_onair`** — Tier-0 addressing end-to-end with link-FEC (the prefix-set filter under real loss).

### WHEN — the airtime lease
- **`slot_airtest` / `slot_ab_onair`** — two named senders under the slot MAC: measures per-name slot
  occupancy and collision-free turns (the fairness invariant, on air). *Bench metric:* frames-in-owned-slot
  fraction, A↔B airtime split.
- **`sched_cv_airtest`** — the common-view clock alignment that the slots ride (µs residual after drift).
- **`c5_slot`** — the hardware named airtime lease on two ESP32-C5s (`inject_at_clock`); each name lands in
  the slot `SlotSchedule` assigns it. *Bench metric:* in-slot placement %, jitter.
- **`airtime_ab_onair`** — A/B airtime accounting.

### WHERE — channel
- **`occupancy_onair`** — the frame-free occupancy counter vs the real frame rate (the sensing accuracy
  benchmark; see `read_channel_activity`). *Bench metric:* counter/frame-rate tracking ratio.

### HOW-WELL — rate / reach
- **`reach_fork`** — reach-lever sweep: does dropping MCS / adding STBC-LDPC / (HE) ER-SU+DCM extend the
  decode range? *Bench metric:* delivered fraction vs rate/reach setting at fixed distance.
- **`size_fork` / `burst_fork` / `fec_fork`** — MTU, burst pacing, and link-FEC redundancy sweeps
  (the p^n delivery model; the levers that trade airtime for delivery).

### Cross-cutting — latency
- **`firmware/esp32c5-ndn/tools/link_latency.py`** — the link-ping decomposition (`docs/link-latency-
  decomposition.md`): propagation (ns) vs airtime (µs) vs interconnect (ms). *Bench metric:* the % of the
  ping attributable to the radio vs the serial bridge (measured ~1% vs ~99%).

---

## Running

```sh
# Layer 1 + 2 (deterministic, CI):
cargo test -p ndn-face-monitor-wifi          # unit + invariant suite
cargo test -p ndn-face-monitor-wifi --test mac_facets   # just the facet invariants

# Layer 3 (needs radios): each example documents its own hardware + env. Examples are gated behind
# `dev-examples` (and some behind `libusb-backend` / `serial-radio`); see Cargo.toml [[example]] blocks.
cargo run --features dev-examples --example slot_airtest -- <pid> <ch>
python3 firmware/esp32c5-ndn/tools/link_latency.py       # two ESP32-C5s
```

## Adding a test

- A new **mechanism** case → a `#[test]` in that module (Layer 1).
- A new **guarantee** ("the MAC promises X") → a corpus test in `tests/mac_facets.rs` (Layer 2). State the
  promise in the doc-comment, pick a threshold that a *degenerate* implementation fails, and seed the PRNG.
- A new **measured** claim → an `examples/*` benchmark that prints the number, catalogued above by facet.
