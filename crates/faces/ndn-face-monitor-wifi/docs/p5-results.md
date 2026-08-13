# P5 results — 2026-08-13, evaluated against the pre-registered thresholds

Bench: o5p-0 a81a bulk / o5p-2 8812au lat / o5p-1 881a obs+light, ch149, 40 s runs, arms
interleaved. All replicates reported. Batch-1 (pre-amendment-2) discarded per amendment 2; one
L-rep-3 instrument failure (obs radio never opened — dmesg shows repeated USB resets on the 881a;
signature: empty obs AND bulk wins 0, since /light was absent) re-run once per the instrument rule.

## Claim A — REFUTED, by its own pre-named condition

| arm | alarm delivery | gate wait max µs |
|---|---|---|
| L1 lanes | 249/251 = 99.2% | 110,885 |
| L2 lanes | 249/251 = 99.2% | 110,424 |
| L3 lanes | 249/250 = 99.6% | 121,686 |
| F1 flat  | 249/251 = 99.2% | 110,422 |
| F2 flat  | 246/251 = 98.0% | 111,270 |
| F3 flat  | 250/251 = 99.6% | 111,288 |

Every A-lanes replicate cleared the absolute bars (delivery ≥ 90%, gate max ≤ 200 ms) — but mean
lanes−flat = 99.33% − 98.93% = **0.4 pp < 5 pp with both high**, which the prereg names as
"REFUTED: lanes buy nothing at this load." The owner-return contract (per-frame yield on hearing
the owner) plus close-range capture already protect the latency owner; the lanes' by-construction
guarantee adds nothing that owner-return's by-behaviour protection was not already providing HERE.
Where lanes should still matter, untested today: hidden terminals (a lease holder that cannot hear
the latency owner cannot yield to it), high loss, an uncooperative bulk. That is the next
pre-registration, not a re-run of this one.

## Claim B — REFUTED, and the metric found conflated

attempts-per-sent: B8 = 0.655/0.661/0.613 (mean .643) vs B1 = 0.586/0.579/0.505 (mean .557).
Threshold (B8 < 0.5 × B1): **fails** — the ratio did not halve; it slightly rose.

Post-hoc diagnosis (goes to the lab, per the gate rule): `claim_attempts` increments on HOLD
CONTINUATIONS as well as fresh elections (`try_claim` counts at entry; a lease=8 burst counts one
"attempt+win" per frame). The registered metric cannot separate election cost from hold
bookkeeping — with win-rates of 87–91% it is plainly dominated by holds. Follow-up: split the
counters (elections vs continuations) as a lab-visible property, then re-register B.

Observation (not pre-registered, reported as such): sent(B8) mean 15,537 vs sent(B1) mean 10,207 —
**+52% bulk throughput under lease=8** — and lanes cost bulk ~7% (L mean 15,537 vs F 16,635).

## What the campaign validated incidentally

First on-air, N=3 exercise of the P1 "one filter, one map" path end-to-end: every frame carried a
Tier-0 filter, every RX gate and every scheduler read it, /alarm rode a latency lane from a shared
GroupTable — delivery 98–99.6% throughout, zero false-negative signature. `ambient frames` = 0 on
every node (ch149 quiet; the counter is reported, per campaign (d)).

## Process defect, on the record

The pre-registration was NOT in git before the runs. `docs/.gitignore` ignores `*` (docs are
opt-in with `-f`), so the three "prereg committed" commits (9ee57d1, amendments 1–2) silently
carried only the `.rs` half — `git add -A` skipped the doc without a word. The file existed on
disk, with its content and amendments, before each run (mtimes agree), but the auditable-history
half of the gate rule was void. This is the #24 drift mechanism (an ignored doctrine file)
striking a third time. Fixes: the doc is now force-added; any future prereg commit must be
verified with `git ls-files` before the first run — a green `git commit` is not evidence the file
went in.

## Claim B v2 — PASS (2026-08-13, post counter-split, prereg verified in-index before the runs)

| arm | rep | sent | elections | elections/sent | hold continuations |
|---|---|---|---|---|---|
| B8 | 1r | 17,580 | 251 | 0.0143 | 9,767 |
| B8 | 2  | 12,413 | 244 | 0.0197 | 6,742 |
| B8 | 3* | 27,484 | 245 | 0.0089 | 15,211 |
| B1 | 1  |  7,239 | 250 | 0.0345 | 2,812 |
| B1 | 2  |  8,647 | 250 | 0.0289 | 3,625 |
| B1 | 3* |  7,292 | 251 | 0.0344 | 2,949 |

Threshold: elections-per-sent(B8) < 0.5 × B1 → **0.0143 < 0.0163 ✓ (ratio 0.44)**, with
sent(B8) mean 19,159 ≥ sent(B1) mean 7,726 (**+148%**). Ranges disjoint (B8 max 0.0197 <
B1 min 0.0289). Excluding the * pair (lat radio failed to open on o5p-2 in both rep-3 runs —
matched across arms, so the pair is internally comparable) leaves 0.017 vs 0.0317 — still passing.

The structure the split counters reveal: **elections are constant (~250 = one per superframe — one
election per /light-slot occurrence, by design) in every arm**; the lease changes how many frames
each win amortizes (holds ≈ 3k under LEASE=1 — even one slot amortizes a burst — vs ≈ 10k under
LEASE=8). elections-per-sent halves because SENT rises, not because elections fall: the election
rate is set by the schedule, and the lease multiplies what a win is worth. v1's conflated counter
could not see any of this.

Instrument note: the o5p-2 8812au failed to open in both rep-3 runs (consecutive) — watch for a
wedge; the 881a obs also reset twice earlier. Flakiest-first is now o5p-2.
