# P5 pre-registration — committed before any run (the gate rule)

**Date fixed: 2026-08-13, before the first arm.** Suite state at registration: MAC lab P1–P5 and
P7–P9 green, P6 flipped for the recognizable relay, residual red-by-design; golden vectors green
in all three tier0 implementations; coverage table full-or-excluded. Tool: `examples/campaign_p5.rs`.

**Bench**: o5p-0 a81a = `bulk`, o5p-2 8812au = `lat`, o5p-1 881a = `obs` (RX-only — its measured
brownout is a TX defect). Channel 149. All arms interleaved (the 08-11 lesson: an all-off-then-
all-on ordering was fully confounded by drift), 3 replicates per arm.

**Fixed parameters, and why.** `NDN_SCHED_SLOT=8:20000` — the explicit escape-hatch form, because
the derived slot on `wall` clocks is ~2 ms and cross-node NTP skew between the OPis is of that
order; the schedule must dominate the skew. `NDN_RADIO_TX_RATE=4` (legacy 6M broadcast — the P3.12
pinned-rate ruling; adaptive rate mid-run changes the arm's airtime). `RATE=20` for `lat`
(20 alarms/s). Tier-0 addressing ON via `with_bloom_latency` on all nodes — this campaign is also
the first on-air exercise of the P1 mask-attribution path; `ambient frames` is reported everywhere
and is expected NONZERO now (foreign ch149 traffic hits the origin gate instead of the parser).

## Claim A — reserved lanes bound latency delivery under saturating bulk (#93/P3-on-air)

Arms (both with `NDN_SCHED_CLAIM=1 NDN_SCHED_LEASE=8` at `bulk`):
* **A-lanes**: `NDN_SCHED_RESERVE=4` (lanes 0,4; `/alarm` is latency-class → placed in a lane)
* **A-flat** : `NDN_SCHED_RESERVE=0` (no lanes; an 8-slot bulk lease may cover `/alarm`'s slot)

Counters: `obs`'s `heard /alarm` vs `lat`'s `sent` (delivery ratio); `lat`'s `gate wait max/p99`.

Pre-named thresholds:
* **PASS** if, in every A-lanes replicate: alarm delivery ≥ 90% AND `gate wait max` ≤ 200 000 µs
  (superframe 160 ms + 2 slots), AND mean A-lanes delivery exceeds mean A-flat delivery by ≥ 10 pp.
* **Refuted** if A-flat ≈ A-lanes (< 5 pp) with both high: lanes buy nothing at this load — a real
  negative result to be reported as such, not re-run until it agrees.
* Anything else (e.g. A-lanes < 90%): anomaly → back to the lab as a new property before any re-run.

## Claim B — a multi-slot lease cuts election overhead (#93/#95)

Arms (both `NDN_SCHED_RESERVE=4`, claim on): **B-1** `NDN_SCHED_LEASE=1` vs **B-8** `NDN_SCHED_LEASE=8`.

Counters: `bulk`'s `claim attempts/wins` and `sent`.

Pre-named threshold: **PASS** if attempts-per-sent(B-8) < 0.5 × attempts-per-sent(B-1) with
sent(B-8) ≥ sent(B-1). **Refuted** if attempts/sent is unchanged (the lease is not actually
amortizing elections) or sent drops (leases cost more than they save).

Note: claim A's arms double as B-8 replicates (same env); B-1 runs are additional.

## Amendment 1 — 2026-08-13, after the sanity run, BEFORE any counted run

The 10 s sanity run exposed a design flaw in claim B's arms: `bulk`'s wins were 0/344
**correctly** — `/alarm` lives in a lane (unclaimable by design) and the other open slots have no
audible owner (evidence-refused, #94). Claim B was unmeasurable in the registered topology.

Fix: `lat` additionally sends `/light` (bulk-class, registered on all nodes) at 1/s — an audible,
97%-idle open-slot owner, the same role the +119% measurement's light sender played. Thresholds for
A and B are UNCHANGED. Sanity-run numbers are not campaign data and are not reported as such.

## Amendment 2 — 2026-08-13, after batch 1, before the counted campaign

Batch 1 (discarded; reported in the appendix of the results) found: (a) the arm-F observer opened
no radio (instrument failure); (b) claim B still unmeasurable — amendment 1 put `/light` on `lat`,
whose nonce then evidenced two slots and was DISCOUNTED by P4's relay rule, the multi-group
conservatism working as designed. Fix: `/light` moves to the `obs` node (own nonce, single group ⇒
legitimately claimable; 1 f/s is far below the 881a's sustained-TX brownout regime). Thresholds
unchanged. The campaign proper is 3×3 interleaved runs under this tooling.

## Deferred, explicitly

Campaign (c) — #101's four arms swept over E, Wi-Fi and LoRa reported separately — is its own
pre-registration (different tool, different bench roles); not covered here. Campaign (d)'s
requirement (ambient reported alongside) is folded into every run above.

## Reporting rule

All replicate values are reported (no best-of); arms interleaved; a run with any DEBUG-class
`NDN_*` variable set is invalid (the run header shows them). Anomalies become lab properties first.
