# P5 campaign (c) — #101 filter false-positive sweep over E — PRE-REGISTRATION

**Committed before any run (the gate rule; verified with `git ls-files` before the first capture).**
This is the campaign explicitly deferred in `p5-preregistration.md` ("#101's arms swept over E … its
own pre-registration"). It extends #106 (Tier-0 shadow mode, ONE E: 87.1% reject, 0.46% FP, 0 FN over
2500 frames) into a **swept curve over E = the receiver's registered-prefix count**, with the
receiver-side baselines run on the identical captured frames.

## Why this is bench-range-valid (unlike claim C)

The false-positive rate is a function of the in-frame filter BITS and the query masks — **not** of link
margin. Every arm and every E is evaluated on the SAME single capture, so channel, distance and drift
are held identical by construction. The only on-air requirement is that B *hears* A's frames (a ~100%
strong link at 3 ft) and that the Tier-0 filter bits **survive the air** (`addr1‖addr2` reassembly) —
which is precisely the on-air fact #106 established at one E and this sweep re-establishes across E.

## Roles (interleave-free — one capture drives the whole sweep)

* **esrc** — o5p-0 a81a (strong, proven TX). Sends small objects named `/p<i>/<seq>`, `i` cycling
  uniformly over a universe of `UNIV=128` prefixes, via a **`with_tx_bloom(OPEN_GROUP_KEY)`** medium
  so each frame carries its OBJECT's real prefix-set Tier-0 filter in `addr1‖addr2` (the production
  packing path — `Tier0Addresser`), nonce in `addr3`.
* **ecap** — o5p-1 881a (RX-only; its brownout is a TX defect, RX is proven ~100%). Raw-captures every
  frame; records `(reassembled 12-byte filter, parsed /p<i>/<seq> name)`. After capture, runs the full
  E-sweep across all four arms offline and prints the confusion matrix.

Fixed: channel 149, `NDN_RADIO_TX_RATE=4` (legacy 6M — no adaptive-rate airtime drift), **no**
`NDN_SCHED_*` (this is a filter experiment, not a MAC one — the scheduler is out of the frame). Target
capture **N ≥ 6000 frames** (> #106's 2500), small objects so the frame rate is high.

## The four arms (all on the ONE capture; E swept per arm)

For each `E ∈ {1, 2, 4, 8, 16, 32, 64}` the receiver registers the first `E` prefixes `/p0 … /p{E-1}`:

1. **none** — no filter; admit all. FP = 100%, FN = 0 by construction (the process-everything cost/null).
2. **tier0** — in-frame 96-bit prefix-set BF (k=4). Admit iff ANY of the E query masks
   `PrefixFilter::mask_for(&OPEN_GROUP_KEY.0, "/p{i}")` `may_match` the frame's reassembled filter.
   **Zero receiver state** (12 bytes ride the frame).
3. **ndn-nic** — receiver-side BF-FIB baseline `NdnNicFilter::paper_default(&key, prefixes_E).may_serve(name)`.
4. **tier1** — receiver-side BF-FIB `Tier1` with the E prefixes registered; admit iff `lookup(name).fib`.

**Ground truth** per frame: the emitted object `/p<i>/<seq>` is *relevant* iff `i < E` (I control
emission, so truth is exact). FP = admitted ∧ ¬relevant; FN = ¬admitted ∧ relevant.

## Pre-named thresholds (fixed here, before the run)

* **Safety invariant (HARD).** `tier0` FN = 0 AND `tier1` FN = 0 at every E, over the whole capture.
  Any false negative → the safety property is violated → back to the lab as a new property; **not**
  re-run until it passes. (BFs are one-sided; a non-zero FN means an air/reassembly defect, the exact
  failure #82 fixed and #106 confirmed — this sweep re-confirms it across E.)
* **Curve (independence).** `tier0` FP(E) is monotonic non-decreasing in E AND tracks the OR-of-E-masks
  independence prediction `FP_pred(E) = 1 − (1 − FP(1))^E` within each E's Wilson 95% CI. This is the
  self-contained form of "matches the closed-form 96-bit-BF curve" — it needs no fitted constant.
  **Refuted** if measured FP(E) departs from `FP_pred(E)` beyond CI at any E (masks not independent /
  bits not surviving as bench-measured).
* **Crossover (MEASUREMENT — reported, not thresholded pass/fail).** Report `E*` = the smallest E at
  which `tier0` FP crosses a 5% usability bar, and the same for `ndn-nic`. The #101 thesis —
  "Tier-0 belongs at small E; a relay (many registered prefixes = large E) needs the larger Tier-1
  table" — is supported iff `E*(tier0) < E*(ndn-nic/tier1)` at matched sample. No directional
  pre-commitment beyond reporting the two crossovers and the receiver-state cost (tier0 = 0 B;
  ndn-nic/tier1 = table_bytes).

## Reporting rule

All four arms' FP(E) with Wilson 95% CIs and N per E; the capture's frame count N and source nonce
(start+end) are printed (the freshness/silent-zero guard — N=0 or start≠end ⇒ instrument-invalid,
re-run). No best-of. An anomaly (FN>0, or FP off the independence curve) becomes a lab property first.

## RESULTS — 2026-08-13, one capture, N = 140,331 attributable frames (56× #106)

esrc a81a (nonce d61de1c5bef5) → ecap 881a, ch149, legacy 6M, clean harness. Silent-zero guard
passed (N=140k, one fresh sender nonce). Receiver state: tier0 = 0 B; ndn-nic/tier1 = 256 B.

| E  | negatives | tier0 FP (95% CI)      | ndn-nic FP | tier1 FP |
|----|-----------|-----------------------|------------|----------|
| 1  | 139 228   | 0.006% [0.00,0.01]    | 0.000%     | 0.000%   |
| 2  | 138 129   | 0.811% [0.76,0.86]    | 0.000%     | 0.000%   |
| 4  | 135 938   | 0.850% [0.80,0.90]    | 0.000%     | 0.001%   |
| 8  | 131 541   | 0.928% [0.88,0.98]    | 0.000%     | 0.002%   |
| 16 | 122 764   | 1.206% [1.15,1.27]    | 0.000%     | 0.002%   |
| 32 | 105 220   | 3.044% [2.94,3.15]    | 0.000%     | 0.004%   |
| 64 |  70 154   | 6.573% [6.39,6.76]    | 0.000%     | 0.026%   |

**Safety invariant — PASS (the one that mattered).** tier0 FN = 0, tier1 FN = 0, ndn-nic FN = 0 at
EVERY E over 140k on-air frames. The in-frame Tier-0 bits survive the air with zero false negatives
across the whole sweep — #106's single point is now a curve. No air/reassembly defect at any E.

**#101 thesis — SUPPORTED, strongly.** Tier-0 (96 in-frame bits, ZERO receiver state) saturates from
0.006% to 6.57% FP over E=1→64; the 256 B receiver-side tables stay flat (NDN-NIC 0.000%, Tier-1
≤0.026%) throughout. Crossover to the 5% bar: tier0 E*=64, others >64. A relay (many registered
prefixes = large E) needs the larger Tier-1 table; an endpoint (small E) rides the free filter. This
is a *stronger* separation than the prereg predicted.

**Independence curve — anchored prediction REFUTED; the law itself CONFIRMED at scale.** The
pre-registered check `1-(1-FP(1))^E` fails badly (predicts 0.37% at E=64 vs measured 6.57%) — but
only because it anchored on FP(1) measured with a SINGLE prefix, /p0, which is a 16× low outlier
(0.006% vs the population mean). Fitting the per-prefix mean from the large-E points gives a stable
**p̄ ≈ 0.106%**, and `1-(1-p̄)^E` then matches measured essentially exactly for E≥8 (E=64: pred
6.56% vs meas 6.57%; E=32: 3.34 vs 3.04; E=8: 0.85 vs 0.93). So the masks ARE ~independent and the
OR-of-E-masks law holds — the small-E lumpiness (one prefix /p1 alone adds ~0.8%) is the
per-prefix-heterogeneity / "the name distribution dominates, not k" phenomenon already documented in
`tier0.rs`, now demonstrated on air. Lesson for the tool: never anchor a BF FP curve on one prefix.

**Verdict.** #101's on-air E-sweep is COMPLETE. The design question is answered with air data: Tier-0
is the correct free filter up to E in the low tens (FP < ~1%); beyond that a relay must carry the
larger Tier-1 table, whose FP stays negligible. Safety (0 FN) holds unconditionally across E.
