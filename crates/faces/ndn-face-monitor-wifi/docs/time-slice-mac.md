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

The trade against a self-timed scheme (a passed token needs no clock because the token frame *is* the
sync) is deliberate: named-data radio takes the clock dependency in exchange for statelessness,
namelessness, and self-healing — and pins the clock accuracy as the one thing hardware must provide.

## Status & how to use it

- **Realized:** the name/class time-slice over the software common-view clock (#61), validated in sim.
- **Designed + measured, not yet in the face:** the claimable (demand-adaptive) slot — implement as a
  radio plan/strategy that transmits the owner's pending data collision-free, else runs the existing CCLF
  election among other pending name-groups. Reuses the slot clock + CCLF already present; the only new
  logic is the owner-idle → open-to-election branch.
- **Blocked on:** hardware TSF (#41) for tight, collision-free slots at scale.
- **Do not** introduce a slot-owner roster, a join/leave protocol, or any per-station schedule state —
  ownership must stay a pure function of (name, clock).
