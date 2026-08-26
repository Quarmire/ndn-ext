# Wireless faces: user stories → requirements on the one-face MAC

A reasoning artifact, **not doctrine**. Its earlier job — deciding *which distinctions become faces* — is
**settled**: there is **one** wireless face (`bearer-face-radio-coex.md`). Mobility is the essence of wireless,
every "stable" case is a degenerate transient, and surfacing a region/sector/bearer as an NFD face is a **§7
soft-state violation**. So these stories no longer ask *"is this a face?"* — **every one resolves behind the
single face.** They now serve as the **requirements list** for what the MAC must do behind that face, and as
the stress cases the forwarding-under-flux design (`wireless-forwarding-under-flux.md`) must survive.

## Why every case always applies

The NDR MAC is **general infrastructure**, not scoped to an application. So we cannot design for a subset. And
link condition is **never static** — it is set by the *presence and movement of peers* and the environment, not
by your own radio. Even a fixed node with fixed radios lives in perpetual flux. Therefore each story below is
**always in play simultaneously**, and the MAC must handle all of them behind one face without ever hardening a
peer/region/route into held state.

## The stories (now: what the MAC must do behind the one face)

Each: scenario (grounded in our hardware) · the flux it introduces · the **requirement** it places on the
behind-the-face MAC.

- **US-1 — Coex, same neighbors, two bearers (the C5).** Wi-Fi + BLE reach the same neighbors; one is BLE-only
  and sleepy. *Requirement:* pick bearer(s) per name by measured reach + demand, arbitrate the shared antenna
  in time (coex), never surface the bearer choice upward.
- **US-2 — Two PHYs, currently-disjoint name populations (co-band bench).** `/backbone` currently answered on
  Wi-Fi, `/sensors` on LoRa. *Flux:* the split is *current*, not durable — a sensor may appear on Wi-Fi.
  *Requirement:* a **soft, decaying name-prefix reachability prior** ("P recently arrived via bearer B") that
  biases without ever becoming a route; re-forms when producers move.
- **US-3 — Cold start / the discovery face.** No prior for `/foo`. *Requirement:* exploration — derive
  hop-seq/channel from the prefix, update the Tier-0 filter, transmit on some/all radios; bound the effort by
  the PIT lifetime; deposit a prior on success.
- **US-4 & US-5 — Sector antennas, stable vs mobile producer.** Three identical 120° radios; a fixed camera
  vs a crossing drone. *The pair is the proof:* identical hardware, and *neither* becomes a face — the fixed
  camera is just a transient case of the mobile one. *Requirement:* track *where a prefix is currently
  answered from* (which sector/radio) as decaying soft state, re-aim per transmission, tolerate the producer
  moving across sectors with graceful prior decay — no sector face, no FIB churn.
- **US-6 — Reliability-critical control loop (CRSF/FPV).** Bounded-loss Interest; producer on 2 radios.
  *Requirement:* macrodiversity — the MAC (which alone knows radio independence + reach) decides to emit on
  multiple radios for the name's reliability class; NFD supplies only the class (name-computed).
- **US-7 — Saturated air / backpressure.** Airtime saturated; NFD keeps injecting. *Requirement:* translate
  measured airtime into an **NDNLPv2 congestion mark** ascending; NFD shapes Interest rate — the one place NFD
  has real competence, so the interface must carry it.
- **US-8 — A radio dies mid-flight.** *Requirement:* absorb it — redistribute the name's traffic to remaining
  radios via the reachability prior; loss of the dead radio's priors costs performance, not correctness (§7);
  no face-down event to NFD.
- **US-9 — Wired + wireless multi-homing.** Ethernet uplink + wireless. *Requirement (grounding):* the node is
  **not** one face — wireless is one face *alongside* the genuinely-different wired face; NFD picks
  wired-vs-wireless by name (its actual job). Anchors the boundary.
- **US-10 — ForwardingHint / producer region.** Interest carries a producer-region hint. *Requirement:* the
  MAC consumes the hint as a **reachability prior seed** (descending intent), not as a route.
- **US-11 — Policy-pinned bearer.** `/emergency` must egress long-range LoRa regardless of efficiency.
  *Requirement:* the name's policy class overrides measured-optimal in the MAC's bearer choice — expressed as a
  name/class attribute the MAC obeys, not a face NFD selects.
- **US-12 — Asymmetric / one-way reach.** A neighbor hears our BLE but not our Wi-Fi (the worst-receiver case
  we already handle). *Requirement:* reach asymmetry is per-neighbour soft state inside one face; never a face
  split. Confirms reach is MAC-internal.

## What the stories require of the MAC (the consolidated spec)

Behind one face, the MAC must:

1. **Explore** on cold start / prior-miss (US-3), bounded by PIT lifetime.
2. Hold a **decaying, content-keyed name-prefix reachability prior** — which radio/sector/bearer recently
   delivered a prefix's Data — that biases (re)transmission and re-forms under motion (US-2, US-4/5, US-8, US-10).
3. **Actuate per name**: bearer/radio/sector/rate/coding/coex choice from name class + measured reach
   (US-1, US-6, US-11).
4. **Cooperate + suppress** content-keyed (CCLF) so broadcast redundancy doesn't melt the air.
5. **Converse over the one face**: consume descending name/class/hint/PIT-pressure; emit ascending congestion
   marks + `Measured<T>` (US-7, US-10).
6. Never hold a **peer/region/route table** — all of the above is soft state recompilable at any time (§7).

Requirements 1–3 are the frontier; their design space and ruling-out is in `wireless-forwarding-under-flux.md`.

## Not concluding

The face question is closed; the **forwarding-under-flux** question is open and is where the exhaustive
solution enumeration + simulation-backed ruling-out now goes.
