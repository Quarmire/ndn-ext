# Claim C pre-registration — reserved lanes under a HIDDEN bulk holder

**Registered 2026-08-13, before any counted run.** This is where both P5 refutations point: claim A
found lanes redundant when the lease holder can HEAR the latency owner (owner-return already
yields); the P4 residual is precisely a holder that cannot. The lanes' by-construction guarantee
should earn its cost exactly when by-behaviour yielding is impossible — that is this campaign's
single claim.

## Preconditions (hard gates, in order)

1. **o5p-2 8812au physically replugged.** It left the bus 2026-08-13 (USB disconnect after two
   open-failures; the known wedge, replug-only recovery). No arm runs until `lsusb` shows it and a
   10 s link check passes.
2. **TX-power instrument.** The TXAGC knob (`NDN_RADIO_TXPWR` via `RadioKnobs::set_tx_power`,
   wired in campaign_p5) is APPLIED but its RF effect is UNVERIFIED at bench range: a
   default/8/2 sweep moved B-side delivery not at all (67/75/74% — delivery saturates with ~60 dB
   of margin at ~3 ft, so delivery cannot see a TXAGC swing there). Before the topology hunt, the
   knob's effect must be verified by an RSSI instrument, not delivery: an obs-side per-frame RSSI
   mean (CapturedFrame.rssi, to be surfaced in campaign_p5) or the B210 SDR method. A knob that
   does not measurably move RSSI is the decided-but-unactuated defect and voids the campaign.
3. **Topology gate.** Hidden(A,C) must be MEASURED, not assumed: A→C delivery < 20% AND A→B ≥ 90%
   AND C→B ≥ 90%, at the chosen power/placement, verified immediately before EVERY arm (the
   topology is the instrument; it drifts with any cable/antenna movement). If the bench cannot
   produce this with power alone (plausible at ~3 ft — see precondition 2), the documented
   fallbacks are antenna removal on A/C, physical separation, or a foil screen; if none succeeds,
   the campaign is VOID for this bench and says so — it does not degrade into an audible-topology
   re-run of claim A.

## Roles

A = bulk (a81a, o5p-0), lease `NDN_SCHED_LEASE=8`, claim on. C = latency owner (`/alarm`,
latency-class) + light open-slot owner (`/light`) — 8812au, o5p-2. B = obs (881a, o5p-1), hears
both. A and C mutually hidden. All: `NDN_SCHED_SLOT=8:20000`, `NDN_RADIO_TX_RATE=4`, Tier-0 on
(with_bloom_latency), 3 replicates/arm, interleaved, topology re-verified between arms.

## The claim

Under a hidden bulk holder, `/alarm` delivery at B survives WITH lanes and degrades WITHOUT them:

* **C-lanes** (`NDN_SCHED_RESERVE=4`): A's leases cannot cover `/alarm`'s lane by construction —
  hiddenness is irrelevant to a rule that never needed hearing. Predict delivery(B← C's /alarm)
  ≥ 90%.
* **C-flat** (`NDN_SCHED_RESERVE=0`): A's 8-slot leases cover `/alarm`'s slot; A cannot hear C to
  yield (the P4 residual, live); frames collide at B. Predict delivery < 75%.

**PASS** if every C-lanes replicate ≥ 90% and mean(C-lanes) − mean(C-flat) ≥ 15 pp.
**Refuted** if the difference < 5 pp — meaning either capture at B rescues the collisions (report
the RSSI asymmetry) or leases rarely intersect `/alarm`'s slot at this load; either way lanes
remain unearned on this bench and the result stands.
Counters: B's `heard /alarm` vs C's `sent`; A's `elections/holds` (the lease must actually be
exercising — holds ≈ 0 voids the arm as unloaded); `ambient frames` everywhere; RSSI means at B
for A-frames and C-frames (the capture-asymmetry diagnostic).

## Power settings recorded for this campaign (the second half of the 2026-08-13 ask)

* Wi-Fi campaign radios: `NDN_RADIO_TXPWR=8` pinned in all claim-C run scripts once verified by
  RSSI (precondition 2) — both for RF (hiddenness) and USB power-budget hygiene (the a81a/881a
  brownout family is a power-delivery defect).
* Sub-GHz persistent radios, honest state: NRC halow0 (o5p-0) IGNORES `iw set txpower` (readback
  pinned 30 dBm); Morse wlan0 (o5p-2) likewise (21 dBm; `morse_cli` not on PATH — it is the
  authoritative tool). Reducing these needs the HAL dBm path or their vendor CLIs — tracked as
  bench hygiene, not a claim-C dependency (they carry no campaign traffic).

## Gate status — 2026-08-13, post-replug

* **Gate 1 (o5p-2 replug): PASSED.** Moved to a USB2 port; opens and hears (~1000 frames/run) —
  the USB2 move also sidesteps the SuperSpeed reset loop that preceded the wedge.
* **Gate 2 (TXAGC RF-verified): NOT PASSED, evidence recorded.** Five-point sweep
  (default/16/8/2/0) with the new RSSI meter at BOTH receivers: frames from the a81a read
  0 dBm mean everywhere, at every index; delivery unmoved. The meter itself is not fake —
  cross-sender rows vary (C's /light reads −9 dBm at B) — but 0 dBm is the conversion's ceiling,
  so at ~3 ft the receivers sit at/above the meter's range and the sweep cannot yet distinguish
  "knob dead on the a81a's legacy-rate path" from "receivers saturated". Discriminators that need
  no RF: read back the TXAGC registers after set_tx_power (knob actuation, driver-level); check
  `realtek_rx::rssi_dbm`'s clamp. The authoritative RF instrument remains the B210 SDR method.
* **Gate 3 (hidden topology): UNREACHED**, and the sweep makes power-only hiddenness look
  unlikely at this geometry (full mutual audibility with 30 dB commanded swing). The cheapest
  fallback is ANTENNA REMOVAL on A and C at the next bench visit — one minute, and reversible.

No counted arm has run. The campaign waits on gate 2's discriminators + gate 3's fallback.

## Gate 2 — PASSED 2026-08-13 (B210, ndn-radio-drivers 061274c)

The TXAGC knob is RF-verified: monotone over idx 20..=63, ~9.6 dB span (~0.22 dB/step), replicated
±0.1–0.3 dB across three scrambled passes with a linearity-certified instrument (0.98–0.99 dB/dB).
Found and guarded: idx < 20 UNDERFLOWS to a max-gain plateau ~11 dB ABOVE calibrated power — the
driver now clamps to 20..=63. Campaign power settings must use the measured scale: minimum real
power = idx 20 (≈ −9.6 dB vs default 63).

Consequence for gate 3: 9.6 dB of authority cannot create hidden(A,C) at this geometry by power
alone — the ANTENNA-REMOVAL fallback is now the plan of record for the topology gate.

## Gate 3 — route revised 2026-08-13: software hearing matrix (antenna removal excluded by the operator)

Physical constraint update: antenna removal is not an option. Combined with the measured facts —
B receives A at ≥ −5 dBm (the RSSI meter's ceiling) against a ≈ −92 dBm legacy-6M decode floor,
i.e. **~90 dB of link margin vs 9.6 dB of verified TXAGC authority (061274c)** — hiddenness cannot
be created electronically or by any bench-scale physical measure short of relocation/shielding.

Route of record: **`NDN_SCHED_DEAF_SRC=<hex nonce prefix>`** on the bulk node (A), making it deaf
to C's §2 nonce at the scheduler's input — the MAC lab's hearing matrix realized on real radios.
The MAC's information topology is exactly hidden-terminal (A cannot yield to an owner it never
hears); the collisions at B remain PHYSICALLY real (both radios radiate; B's delivery counts
measure genuine RF interference). The only emulated element is WHY A cannot hear C, which is
outside the mechanism under test.

Honesty clauses:
* The var is DebugBisect-classed and appears in every run header. The prereg's "any DEBUG-class
  var invalidates a run" rule gets exactly ONE named exception: `NDN_SCHED_DEAF_SRC` on node A
  only, because here it IS the topology, not a confounder. Any other DEBUG var still voids.
* The topology gate becomes: A's scheduler counters show ZERO domain attribution of C's frames
  over a full pre-arm window (deafness verified end-to-end), while B hears both at ≥ 90%.
* Scope limit stated: this validates the MAC's hidden-terminal behaviour, not RF capture effects
  of true spatial hiddenness — those need the sub-GHz field fleet at real distances (plan-P4's
  original endpoint), and results will say so.
* TX power for the arms: pinned at the verified scale (`NDN_RADIO_TXPWR` ∈ 20..=63, 061274c's
  clamp) — power is a controlled variable here, not the hiding mechanism.

## Role correction + instrument status — 2026-08-13 late

**Role table corrected** (found while validating the deafness instrument): C sends `/alarm` ONLY;
B (obs) carries `/light` — as the amendment-2 tooling already does. The original text gave C both,
which is wrong twice over: (a) A's leases need a claimable open slot from an AUDIBLE owner, and in
this campaign that must be B, since A is deaf to C; (b) a C sending two groups would be discounted
by P4's multi-group rule even in the hearing control. The deafness matters exactly once: A's
owner-return yield across `/alarm`'s slot — hearing-A yields (lease Ends when C's alarm lands),
deaf-A rolls through and collides at B. The discriminating counters are therefore B's `/alarm`
delivery and A's hold_continuations-through-the-alarm-slot, per arm.

**Instrument validated at the plumbing level**: each run prints its §2 nonce at start AND end
(rotation = 5 min, nonce also fresh per process — a straddled run self-invalidates); C's printed
nonce feeds A's `NDN_SCHED_DEAF_SRC`; verified live (nonce stable across a 90 s run, deafness
applied in the RX hook before the scheduler). The BEHAVIOURAL validation coincides with the
campaign's own C-flat arm and is not double-counted as a separate gate.

## RESULTS — 2026-08-13, counted arms (3×2 interleaved, deaf-A throughout)

| arm | rep | /alarm delivery (of 282) | bulk sent | A elections/holds |
|---|---|---|---|---|
| L (lanes) | 1r | 274 = 97.2% | 25,254 | 214 / 15,514 |
| L | 2 | 276 = 97.9% | 27,922 | 216 / 16,782 |
| L | 3 | 279 = 98.9% | 30,317 | 214 / 17,956 |
| F (flat) | 1 | 267 = 94.7% | 24,392 | 219 / 15,378 |
| F | 2 | 271 = 96.1% | 28,786 | 216 / 18,249 |
| F | 3 | 271 = 96.1% | 24,954 | 218 / 15,994 |

Means: lanes 98.0%, flat 95.6%. **Difference 2.4 pp < the 5 pp refuted bar ⇒ REFUTED as
registered** — though note the effect is REAL: direction as predicted in all pairs and the ranges
are disjoint (lanes min 97.2 > flat max 96.1). The mechanism exists; its magnitude at this load is
~2 pp, not the ≥15 pp registered.

**Diagnosis, quantitative.** A's frames are ~15 B ≈ 90 µs at 6M; at ~750 f/s that is **~7% airtime
duty**. A lease grants the RIGHT to a slot, but with frames this small the right is not OCCUPATION:
in the flat arm the lease "covers" /alarm's slot while A is on-air ~7% of it, so alarm collision
probability ≈ duty ⇒ flat delivery ≈ 93–96% (observed 95.6%). The hidden-terminal deafness worked
exactly as built (A never yielded — holds ran full; the ~2 pp deficit is the collisions that DID
happen); what was missing is airtime pressure. The prereg pinned rate and slots but not PAYLOAD
SIZE — the third campaign in a row where the unpinned variable was the story.

**Claim-C v2 (to register before any re-run): identical arms with MTU-sized bulk payloads**
(~1400 B ≈ 2 ms at 6M ⇒ a lease-held slot is ~substantially occupied), same thresholds. Predicted:
flat collapses toward ~duty-limited delivery, lanes hold ≥90%.

Instrument log: nonce-rotation self-invalidation fired once (as designed); one 881a open-failure
re-run (signature: empty obs + A elections≈1); the raw-meter/medium-reader HALF-SPLIT was caught by
its 50%-on-both-groups signature and fixed (obs is now raw-only, single consumer — batch discarded);
two runs discarded for a stale-binary deploy (a zigbuild error count was printed and not gated on —
process error, now the deploy gates on zero errors). RSSI asymmetry at B (bulk −8..−11, alarm
−1..−15) recorded; capture cannot explain the result since collisions were rare.

## Claim-C v2 — registered 2026-08-13, before its runs

Identical to the counted v1 arms in every respect except ONE pinned addition: **bulk payload =
1400 B** (`BULK_PAYLOAD`, printed in every run header) ⇒ ~1.9 ms per frame at the pinned 6M ⇒ a
lease-held 20 ms slot is substantially occupied (~10 back-to-back frames), which is the airtime
pressure v1 lacked. Alarm frames stay small (latency traffic is small by nature).

Arms: C-lanes (`RESERVE=4`) vs C-flat (`RESERVE=0`), 3 replicates interleaved, deaf-A throughout,
same roles, same instrument log rules (nonce start=end; obs raw-only; deploy gated on zero build
errors). Thresholds UNCHANGED from v1: PASS = every lanes replicate ≥ 90% alarm delivery AND
mean(lanes) − mean(flat) ≥ 15 pp; REFUTED < 5 pp.

## v2 RESULTS — 2026-08-13: ANOMALY (the third branch), returned to the lab before any re-run

| arm | rep | /alarm delivery | A sent (1400 B) | duty est. |
|---|---|---|---|---|
| L | 1 | 240/282 = 85.1% | 12,003 | ~66% |
| L | 2r | 221/282 = 78.4% | 15,172 | ~83% |
| L | 3 | 259/282 = 91.8% | 10,647 | ~59% |
| F | 1 | 243/282 = 86.2% | 12,656 | ~70% |
| F | 2 | 237/282 = 84.0% | 13,760 | ~76% |
| F | 3 | 242/282 = 85.8% | 11,482 | ~63% |

Means: lanes 85.1%, flat 85.3%. Two lanes replicates < 90% (the PASS bar) and lanes−flat ≈ 0 pp.
This is neither PASS nor the registered refutation shape (both arms are NOT high): **anomaly**.

**Diagnosis.** Alarms are lost ~15% even in the lanes arm, where A never transmits during lane
slots *in its own clock's view* — and that qualifier is the mechanism. The campaign runs
`clock=wall` (NTP): A's and C's slot maps are offset by the cross-node skew (order ~ms). The
`fits_now` guard keeps a frame inside the sender's OWN slot boundary, but with skew there is no
shared boundary: a 1.9 ms bulk frame legitimately launched near A's view of a slot end radiates
into C's view of the lane start, and C's alarm (launched at ITS lane start, no CSMA) collides with
it. v1's 90 µs frames made a boundary straddle nearly free; v2's 1.9 ms frames × ~66% duty ×
per-superframe boundary exposure ≈ the observed ~15%, in BOTH arms — lanes cannot protect against
a skewed map, because under skew the lane itself is not where the bulk node thinks it is.
Supporting: the loss tracks per-replicate duty (worst L rep = highest duty, best = lowest).

**Required before any v3 run (the gate rule):**
1. Lab property **P11**: per-node clock offset in the lab harness + airtime-overlap bookkeeping in
   the modeled medium; assert boundary-collision rate ∝ duty × (skew + frame_airtime)/slot and
   that lanes do NOT protect under skew ≥ ~frame airtime. Red until the fix, then flipped.
2. The fix the anomaly points at is already built and idle: the **hardware common-view clock**
   (#41/#74, `NDN_SCHED_CLOCK=hw|cv`, 10 µs guard vs the wall clock's ms-class skew). v3 = the
   same arms on the common-view clock (one node `NDN_SCHED_MASTER=1`), predicting the boundary
   loss collapses and the lanes/flat separation FINALLY becomes visible. This is the convergence
   the whole stack was built for: µs-class shared time is what makes long-frame slotting real.

Instrument log additions: one nonce-rotation invalidation (L2, re-run); bulk frames report as `/?`
at the obs (the tiny-frame parser does not read 0xfd TLV lengths — counts are correct since
nothing else 1400 B is on air; parser fix queued with the P11 work).
