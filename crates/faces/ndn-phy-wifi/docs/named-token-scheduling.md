# The named token — token-passing, transformed for named-data radio

*Design note. Derived 2026-07-27; measured in `ndn-sim/examples/token_schedule.rs`. Sits under the
[mac-addressing-doctrine](./mac-addressing-doctrine.md); this is its scheduling corollary.*

## The question

Do token-ring / token-passing concepts have a future on a named-data broadcast radio — as a forwarding
strategy or a radio plan — or are they a dead end? And can a token be transformed to fit a
multicast/broadcast medium?

## The one-line answer

**Literal token-*passing* is a dead end. The token *concept* — a collision-free transmit grant — is not
only alive, it is the right frame for the whole time/frequency scheduling story, and a demand-adaptive
form of it measurably beats both fixed TDMA and pure CCLF.**

## Why the literal token dies against the doctrine

Token ring/bus buys three things worth wanting on a half-duplex broadcast medium — collision-free
scheduling, bounded latency, and fairness. Contention is *the* named-radio problem (it recurs in CCLF,
multi-channel, LBT, and slotting), so the appeal is real. But the mechanism fights every doctrine
principle:

- **The token is passed to the *next host*.** That is an ordered ring of host identities — precisely
  what the doctrine removes (the source field is an ephemeral nonce; there is no "next node").
- **Ring membership + ordering is hard state.** It fails the §7 soft-state test: it cannot be recomputed
  from the forwarder, and losing it wedges the ring.
- **The passer is a single point of failure on a lossy medium.** Token loss → ring stall → a
  re-election storm, on a channel where frames drop routinely.
- **Idle-slot rotation waste** — the token circulates past stations with nothing to send.

So: passing a physical token — no.

## The transformation: a token is a function, not an object

The move that defines named-data radio is *replace host-keyed with name-keyed*. Applied to the token:
**the right to transmit stops being an object that circulates and becomes a function `grant(name, clock)`
that every node evaluates locally.** Nobody holds or passes it; everyone computes whose *name* owns the
medium right now from the shared common-view clock. That is still a token — a collision-free transmit
grant — but it is:

- keyed to a **name**, not a host (doctrine-compliant);
- **computed, not passed** (no ring, no membership, no token-loss recovery — self-healing: a dropped
  node simply misses its computed slots);
- collision-free (one name's turn at a time — the token benefit, retained).

It is already built in both dimensions of the medium:

- **Time** — the time-slice MAC over the common-view clock: the slot `H(name) + epoch` *is* the token.
- **Frequency** — name-keyed FHSS (`channel = hop(H(name), epoch)`): the name holds a channel for its
  epoch; the hop schedule is the token circulating through the frequency axis, again computed not passed.

The multicast transform is native: the grant-holder's transmission is the broadcast every interested
node overhears, CS-caches, and CCLF-suppresses around. A token ring's "everyone sees the holder transmit"
*is* the named-radio broadcast. The grant designates a *transmit right*, not a receiver — the name does
the addressing.

## Where a token-*like* idea earns new ground (and the measurement)

Fixed name-TDMA inherits token-ring's flaw: the grant rotates past *idle* names, wasting their slots, and
caps a name at `1/N` of the airtime even when everyone else is silent. Token ring's own fix was
demand-adaptive passing (skip idle stations). Its **doctrine-compliant form is a *claimable* slot**:

> A slot is **owned** by name `t mod N`. If the owner has data, it transmits — a guaranteed,
> collision-free turn. If the owner is **idle**, the slot **opens to a CCLF election** among the names
> that *do* have data (jittered rebroadcast + overhear-and-suppress). No passed token, no host state; the
> owner keeps determinism, idle slots get reused.

This factors scheduling from demand cleanly — the split that keeps it stateless:

- **slot = the grant for the NAME** (collision-free scheduling), ⟂
- **CCLF-within-slot = which of the name's servers actually transmits** (demand-adaptive, stateless).

Raced against pure fixed-TDMA and pure CCLF in a slotted model (saturated sources; load = number of
active names = contention level):

| active names | fixed TDMA | pure CCLF | demand-adaptive |
|---:|---:|---:|---:|
| 2  | 0.12 | 0.88 | **0.89** |
| 4  | 0.25 | 0.68 | **0.76** |
| 8  | 0.50 | 0.41 | **0.70** |
| 16 | **1.00** | 0.15 | **1.00** |
| **p99 access gap (slots)** | 16 (flat) | → **507** | **16 (flat)** |

Reading it:

- **Fixed TDMA** is deterministic (a name's turn comes exactly every `N` slots — p99 gap 16) but wastes
  the idle slots of silent names, so throughput is capped at `active/N`.
- **Pure CCLF** reuses every slot but its collision rate climbs with the number of contenders until it
  collapses (85% collisions at 16 active, throughput 0.15) and its access gap goes ragged (507 slots) as
  unlucky names starve.
- **Demand-adaptive claimable slots** are the **upper envelope** of both — tracking CCLF when names are
  few, TDMA when many — and *strictly beat both through the middle* (0.70 vs 0.50 / 0.41 at 8 active),
  while keeping TDMA's bounded 16-slot access gap throughout.

So the token concept earns its keep — as a name-keyed, clock-derived, *reclaimable* grant, with no passed
token, no ring, and no host identity.

## The one honest cost — and the dependency it names

A literal token is *self-timed*: the token frame **is** the synchronization, so no clock is needed. The
computed grant trades that for a **common-view clock dependency** — if a node's clock is wrong it
transmits in the wrong slot and collides. That is the entire cost of the transformation, and it is why
**hardware TSF common-view timing (task #41)** is the enabling work: the software TSF that clocks the
time-slice MAC today is the stopgap; sub-µs hardware TSF is what lets the computed token stay
collision-free at scale.

## How this was derived (the reasoning trail)

1. **Start from the doctrine** — no host identity; L2 is soft-state the forwarder can recompile (§7).
2. **The recurring pain is contention** — half-duplex broadcast, surfaced in CCLF suppression, the
   multi-channel work, LBT, and time-slotting. Token passing is historically *the* collision-free answer,
   so it is worth asking whether it fits.
3. **Test the literal token against the doctrine** — it fails on host identity, hard ring state, and
   lossy-medium fragility. Dead.
4. **Apply the name-keyed transform** — turn the grant from an object into `grant(name, clock)`. Notice
   this is *already realized*: the time-slice MAC (token in time) and name-keyed FHSS (token in
   frequency) are exactly implicit, computed, name-keyed tokens.
5. **Find the residual gap** — fixed name-TDMA still has token-ring's idle-slot waste. The doctrine-clean
   fix is a *claimable* slot (owner-first, CCLF-reclaim), factoring scheduling ⟂ demand.
6. **Measure it** — the claimable slot dominates both pure TDMA and pure CCLF across contention and keeps
   determinism (`token_schedule.rs`).
7. **Name the cost** — the computed token depends on a shared clock, pinning the value of hardware TSF
   (#41).

## Status and how to use it

- **Realized:** the computed name-token in time (time-slice MAC) and frequency (FHSS rendezvous), both
  validated in sim.
- **Designed + measured, not yet in the face:** the *claimable* (demand-adaptive) slot. Implement it as a
  radio-plan/strategy that, per name-group slot, transmits the owner's pending data collision-free, and
  otherwise runs the existing CCLF election among other pending name-groups. It reuses machinery already
  present (the slot clock + CCLF suppression); the new logic is only the owner-idle → open-to-election
  branch.
- **Blocked on:** hardware TSF common-view timing (#41) for collision-free operation at scale.
- **Not to build:** anything that reintroduces a passed token, a ring, or persistent host/peer state.
