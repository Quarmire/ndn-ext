# The data-centric time-slice MAC

*Design note under the [mac-addressing-doctrine](./mac-addressing-doctrine.md). The temporal half of the
named-radio scheduling story; companion to [cclf-named-mac](./cclf-named-mac.md) (the within-slot
election), [named-token-scheduling](./named-token-scheduling.md) (the unifying grant), and the frequency
sibling, name-keyed FHSS. The "time" deliverable (task #61).*

## The idea

Divide airtime into slots on a **common-view clock**, and assign each slot to a **name**, not a host:

```
owner(t) = schedule( name-group | traffic-class , epoch(t) )
```

Every node derives the same slot ownership from (a) the name/class and (b) the shared clock — so the
schedule is **computed, never announced**. A slot is a collision-free transmit grant for its name; that
is the [token](./named-token-scheduling.md), realized in the time dimension. No coordinator, no host
identity, no passed frame.

Contrast with host-centric TDMA (which assigns slots to *stations* and needs a membership roster): here
the slot belongs to the *content*, and any node with data under that name may use it. Membership is
implicit in the naming, so there is nothing to join, elect, or repair.

## Why time (and why this shape)

Contention is the named-radio pain — half-duplex broadcast, exposed terminals, the storm CCLF fights.
CSMA-style contention is work-conserving but its collision rate climbs with load; scheduling trades a
little flexibility for **collision-freedom and bounded latency**, which the real-time traffic classes
need (the alarm/telemetry starvation seen on the LoRa MAC, #18, is exactly a scheduling failure — bulk
traffic drowning latency-critical traffic under contention).

The data-centric shape buys three things a host-TDMA can't:

- **Traffic-class determinism** — give the *alarm* and *report* classes their own guaranteed slots
  (aligned with the legacy-basic-rate-by-class decision, #46/#47) so they never starve behind bulk.
- **Zero membership** — a node that appears or vanishes changes nothing; the schedule is a function of
  names + time, and a missing node just leaves its computed slots unused (self-healing, §7 soft-state).
- **Composability** — the slot is one axis; the [FHSS](./named-token-scheduling.md) channel is the other.
  A name owns `(slot, channel) = (H(name)+epoch mod N, hop(H(name), epoch))` — a time-frequency grant,
  both computed from the same name + clock.

## The mechanism

1. **Slot ownership** — `owner(t) = H(name-group) + epoch(t)  (mod N)` for a name-scoped schedule, or a
   fixed class→slot map for traffic-class scheduling. Both endpoints and relays for a name compute the
   same owner.
2. **Within-slot election** — the slot grants the medium to the *name*; if several nodes hold data under
   that name, [CCLF](./cclf-named-mac.md) (jittered overhear-and-suppress) picks which one transmits.
   This is the schedule ⟂ demand factor that keeps it stateless.
3. **Claimable slots (the demand-adaptive refinement)** — a fixed name-slot wastes the idle slots of
   silent names. So a slot is *owned* but *claimable*: if the owner is idle, the slot opens to a CCLF
   election among other names with data. `token_schedule.rs` measured this — the claimable slot is the
   upper envelope of both fixed-TDMA (deterministic, wastes idle) and pure-CCLF (reuses all, collapses
   under contention), and strictly beats both at moderate contention while keeping the bounded per-name
   access gap. See [named-token-scheduling](./named-token-scheduling.md) for the numbers.

## The hard dependency — common-view time

The whole scheme is collision-free *only if nodes agree on `epoch(t)`*. A node whose clock is wrong
transmits in the wrong slot and collides. So the enabling resource is a **shared, accurate clock**:

- **Today:** a software TSF anchors the DiscoveryWindow / slot boundaries — adequate to validate the
  mechanism, but its jitter caps how tight the slots (and the guard bands) can be.
- **Needed:** hardware TSF common-view timing (**task #41**) — sub-µs agreement across nodes lets the
  slots shrink, the guard bands narrow, and the computed token stay collision-free at scale. This note's
  scheme is exactly why #41 is the enabling hardware task, not a nicety.
- **Measured on air (2026-07-28):** the hardware RX TSF *is* that clock. Over 204 shared AP beacons, the
  hardware RXTSFL (`radiotap.mactime`, the RX-descriptor `dword5` field the driver already parses via
  `realtek_rx::rx_stamp`) tracked the common beacon reference to **~0.4 µs** (µs-resolution floor), versus
  **55 µs** for the software (pcap) arrival time — **135×**, and the real userspace software TSF is worse
  still. So a node syncing to a shared beacon (an AP, or one node's clock-master broadcast) holds sub-µs
  common view. **Shared clock, not nan-buried (2026-07-28):** the disciplining logic now lives in
  `ndn_time::RadioHwClock` (next to `LinkStamp`/`Discipline`) — a shared substrate any face consumes, not
  a property of the nan runtime. It disciplines a hardware-domain clock from each `CapturedFrame.stamp`
  (per-domain, 32-bit `RXTSFL` unwrapped against the host clock, software fallback until the first stamp).
  The nan runtime is now one *consumer* of it; **this scheduler is the next consumer** — when the
  claimable-slot strategy lands in the face, it reads `RadioHwClock::now()` for `epoch(t)` so the slots
  ride the same sub-µs hardware clock. See [[hardware-tsf-common-view]] ("why nan only") for the full
  radio-`LinkStamp` → shared clock → all-consumers architecture (incl. the cross-node `CommonViewPool`).

The trade against a self-timed scheme (a passed token needs no clock because the token frame *is* the
sync) is deliberate: named-data radio takes the clock dependency in exchange for statelessness,
namelessness, and self-healing — and pins the clock accuracy as the one thing hardware must provide.

## Status & how to use it

- **Actuated on the real face (2026-07-28, #72):** the fixed name-owned slot gate is wired into the
  deployed `RunningMedium` TX path. `ndn_radio_cognition::SlotSchedule` is the pure decision
  (`owner_slot = prefix_hash % N`, `wait_us` = µs to the name's next owned slot); the face's
  `FaceScheduler` (`src/sched.rs`) gates every outbound *data* frame at the one TX choke point
  (`TxBearer::inject_with_intent`) on it, keyed on the frame's own first name components. Robust control
  frames bypass. Enable with `NDN_SCHED_SLOT=N:slot_us` (e.g. `8:3000`); unset ⇒ send path unchanged.
  The epoch is wall-clock µs by default (common-view across NTP-synced nodes at ~ms, proportionate to
  ms-scale data-frame slots); `NDN_SCHED_CLOCK=hw` rides the hardware `RadioHwClock` (fed from RX
  stamps) for µs slots — cross-node phase then needs a clock-master TimeBeacon (see below).
- **Designed + measured, not yet actuated:** the *claimable* (demand-adaptive) slot — the owner-idle →
  CCLF-election branch. The fixed gate is live; adding the claim means the face checks "did the owner
  transmit this slot?" (overhear) and, if not, runs the existing `coop.rs` CCLF election among other
  pending name-groups. Reuses the slot clock + CCLF already present.
- **Cross-node phase (the remaining honest gap):** the wall-clock epoch is common-view at ~ms; tight
  µs-slot operation on the hardware clock additionally needs a shared reference (a clock-master's
  periodic broadcast / common AP beacon) disciplined via `ndn_time`'s `CommonViewPool`/`TimeBeacon` —
  the local RX-TSF is precise but not itself cross-node-aligned. Wired hook (`on_rx_stamp`), not yet the
  full discipline.
- **Do not** introduce a slot-owner roster, a join/leave protocol, or any per-station schedule state —
  ownership must stay a pure function of (name, clock).
