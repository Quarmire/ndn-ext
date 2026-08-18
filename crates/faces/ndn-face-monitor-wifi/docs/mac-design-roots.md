# The MAC's roots — where each problem came from, and proof it is not imaginary

The named-data-radio MAC has grown by iterative review, and a review can hallucinate a problem and
then "fix" it. This doc traces the design and its three most recent findings (D1/D2/D3) back to the
**originating design commitment** each derives from, with the in-tree citation, so a reader can
confirm we solved a real problem rather than an invented one. The test is always the same: *name the
commitment, show it is stated in a source document written before the finding, and show the finding
is a consequence of it — not a strawman.*

## 0. The originating problem

**Contention on a half-duplex, broadcast, ad-hoc, coordinator-free named-data radio.** Every node
shares one channel; there are no ACKs, no association, no AP. The whole MAC exists to let named data
share that medium without a coordinator, computing every coordination artifact from `(name, clock)`
rather than announcing it.

- `time-slice-mac.md:16-18,27` — "Contention is the named-radio pain — half-duplex broadcast, exposed
  terminals, the storm CCLF fights"; the schedule is "computed, never announced… No coordinator, no
  host [state]."
- `cclf-named-mac.md:92` — "it needs no ACKs, no election messages, no coordinator."

This is a real problem (contention is measured throughout #36/#37/#54/#111), and the coordinator-free
constraint is a deliberate commitment, not a convenience. Everything below is a consequence of it.

## 1. D1 — the owner-slot residue collision

**Commitment it derives from:** ownership is *computed*, `owner_slot = prefix_hash % N`, and the
result is claimed to be **collision-free at scale**.

- Mechanism, stated: `time-slice-mac.md:90` (`owner_slot = prefix_hash % N`);
  `named-filter-mac-redesign.md:233` ("the name whose registered prefix hashes to `s mod N`").
- Guarantee, stated **unconditionally**: `named-token-scheduling.md:107` ("collision-free at scale"),
  `:46` ("one name's turn at a time"), `time-slice-mac.md:66` ("the computed token stay collision-free
  at scale").
- Regime, measured: `named-token-scheduling.md:91` evaluates **16 active names**; the deployed
  schedule is ~8 slots (`NDN_SCHED_SLOT=8:20000`, p6-hidden-terminal-prereg.md:33).

**Why it is real, not imaginary.** `hash % N` is a residue class: with more than `N` *active* names,
two distinct names deterministically share a slot (pigeonhole). Both then take the "collision-free
turn" and collide at their receivers, unseen by either. The doctrine promises collision-freedom *at
scale* and measures a 16-active regime against 8 slots, yet **no document anywhere acknowledges two
distinct active names sharing a slot** (verified by grep across all `docs/*.md`; the only "collide"
hit is the flat-hash false-positive discussion at `mac-addressing-doctrine.md:330`, a different
subject). D1 is therefore the gap between a stated guarantee and the mechanism's actual reach — a real
unaddressed contradiction. It is **distinct from the hidden terminal** (#94/p6), which is *can't-hear
the owner*, not *two owners of one slot*.

Fix (f04449d, validated on air a0a8bb4): detection-triggered co-owner sub-draw — turn-taking is bought
only when a co-owner is locally evident. It does not change the `hash % N` map; it repairs the reach
of the guarantee the map already promised.

## 2. D2 — the unpinned schedule parameters

**Commitment it derives from:** the **shared-map law** — a computed schedule is collision-free *only
if every node computes the same map*.

- `mac-synthesis.md:39` (§2.3) — "Every facet needs a *shared* view or it breaks."
- `temporal-access-chapter.md:31` — "This buys collision-freedom **only if nodes agree on
  `epoch(t)`**", and `:135` — "every node must agree where a slot begins."

**Why it is real.** The slot map is a function of slot width, slot count, reserved-lane stride, clock
class, and the channel set — all of which were read from per-node env vars (`NDN_SCHED_SLOT`, etc.,
`sched.rs` `from_env`). Two nodes with different `NDN_SCHED_SLOT` silently compute disjoint maps: no
error, no collision report. The shared-map law says these must be identical; nothing enforced or even
detected a mismatch. D2 is a direct, unmet consequence of a stated law.

Fix (a4e0220/845f3ea): a versioned `SchedParams` capturing the shared set, digested onto the time
beacon so a mismatch is **detected** (not corrected — the design corrects nothing, by §2 law 6).

## 3. D3 — the slot key re-coupled the granularity the filter decoupled

**Commitment it derives from:** the name filter's central innovation — **every receiver matches at
its own granularity** (the roles thesis).

- `named-filter-mac-redesign.md:92-93` — "the granularity the receiver registered. With a prefix-set
  BF the sender ships *all* granularities at once and every receiver matches at *its own*.
  Longest-prefix match becomes a receiver-local decision."
- `name-filter-chapter.md:49` — "E — the number of prefixes a receiver has registered" (per-node).

**Why it is real.** The same redesign doc that makes granularity per-receiver *also* defines the slot
owner as "the name whose **registered prefix** hashes to `s mod N`" (`:233`) — and P1 implemented the
slot key as the *longest locally-registered prefix* (`sched.rs`, pre-fix). Registration tables are
legitimately per-node (that is the roles thesis), so node A (`/x`) and node B (`/x/y`) key one name to
different slots. The filter deliberately decoupled granularity; the slot key silently re-coupled it.
D3 is a latent contradiction **inside the source design**, not an external invention.

Fix (a4e0220): the slot key is a shared constant, `H(first slot_depth components)`; the filter keeps
per-receiver granularity, the slot does not.

## 4. The honest test for future findings

Before "fixing" anything, name the commitment it derives from and cite the source document. If no such
commitment exists — if the problem cannot be traced to a stated design decision or a measured regime —
treat it as suspect until a measurement or a source proves it real. D1/D2/D3 each pass this test; that
is the difference between a repair and an invention.
