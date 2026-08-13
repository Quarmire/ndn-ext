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
