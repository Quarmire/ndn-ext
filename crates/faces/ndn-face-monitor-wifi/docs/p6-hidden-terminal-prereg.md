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
