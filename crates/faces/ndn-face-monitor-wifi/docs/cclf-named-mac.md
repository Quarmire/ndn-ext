# CCLF for the named-data MAC — cooperative forwarding, and its variations

*Design note under the [mac-addressing-doctrine](./mac-addressing-doctrine.md) (§4 defines CCLF
canonically). Companion to [named-token-scheduling](./named-token-scheduling.md) and
[time-slice-mac](./time-slice-mac.md). Measured in `ndn-sim/examples/coding_cclf_scale.rs`; implemented
in `ndn-radio-cognition/src/coop.rs`.*

## What CCLF is

On a named-data broadcast radio there is no "next hop" to unicast to — a relay that wants to forward
just re-broadcasts, and every neighbour that also holds the content would do the same. Unmanaged, that is
the **broadcast storm**: N redundant copies of every packet. CCLF is the cooperative-forwarding rule that
suppresses the redundancy without a coordinator or host state:

> On gaining content worth forwarding, a node schedules a re-broadcast at `arrival + jitter`. Before its
> timer fires, if it **overhears** the same named content already forwarded (by anyone), it **cancels**
> its own transmission. The node with the smallest jitter wins the election and forwards; the rest fall
> silent.

Two moving parts:

- **The overhear-cancel** — a counter-based suppression with threshold 1. The suppression *key is the
  content* (the name-group hash / the Data itself via the Content Store), **not a host**. A node
  suppresses because *the data* was served, regardless of who served it. This is the doctrine move: the
  cancel keys on the name, not on a peer identity.
- **The jitter** — a per-node delay that encodes *forwarding fitness*. The best-placed relay draws the
  smallest jitter, transmits first, and suppresses the others. Fitness can be link quality, position
  (macro-diversity), remaining energy, or role. It is soft-state — recomputable, losable — so it never
  becomes a peer table (doctrine §7).

CCLF composes natively with the rest of the named data plane: the overheard forward is also a **CS cache
fill** and a **PIT breadcrumb**, so suppression and caching and reverse-route learning are the *same*
event. That fusion is the point — one overhear does three jobs.

## Why it matters (measured)

`coding_cclf_scale.rs` (#68) disseminated a generation across a random geometric graph, sweeping density:

- **Flood (no CCLF):** airtime blows up with density — the storm. At 200 nodes it spends ~2350 tx.
- **CCLF:** ~half the airtime (~1190 tx at 200 nodes) for the same delivery — nodes overhear that
  neighbours already covered the content and stay quiet.

The result is robust across loss and coding. (The companion finding: *coding* is ~neutral for
whole-network flooding — CCLF is the lever, not the codec.) CCLF is also the **within-slot election** in
the [time-slice](./time-slice-mac.md) and [token](./named-token-scheduling.md) designs: the slot grants
the medium to a *name*; CCLF decides *which of the name's servers* transmits. That two-level factor
(schedule ⟂ demand) is what keeps the whole MAC stateless.

## Variations (the design space)

CCLF is one point in the classic broadcast-suppression taxonomy, re-keyed to content. The dials:

1. **Overhear-cancel, threshold C = 1** *(coop.rs default)* — cancel on the first overheard copy. Maximum
   suppression, minimum redundancy. Fragile at the edges: the suppressed node might have been the only one
   that would reach a corner receiver, so an unlucky loss punches a hole.

2. **Counter-based, C = k** — cancel only after hearing *k* copies. Trades airtime for coverage
   robustness — a higher C keeps a little redundancy so a single loss doesn't strand a corner. The knob to
   turn up on lossy or sparse edges; turn down in dense cores.

3. **Fitness-jittered** — `jitter = f(fitness)` so the best relay forwards first. Sub-variants by what
   "fitness" means:
   - **Distance/position-based** (classic): jitter ∝ 1/(distance from the last sender) → the *farthest*
     node forwards first, maximizing new coverage per transmission (the macro-diversity win). Needs a
     coarse RSSI/position estimate (soft-state, per the §2 nonce-keyed RSSI map).
   - **Link-quality-based**: the node with the best onward links forwards → fewer downstream retries.
   - **Energy-aware**: higher residual energy → lower jitter → load-levels forwarding across the mesh
     (the §4 cooperation-vs-power dial).
   - **Role-weighted**: designated relays draw lower jitter than opportunistic ones.

4. **Density-adaptive window** — scale the jitter window `W` with the local neighbour count (from the §2
   nonce-density map): dense → wide W → more overhearing → more suppression; sparse → narrow W → forward
   fast, don't dawdle. Keeps the election latency proportional to how much suppression is actually
   available.

5. **Name/role-scoped** — a node running the relay role for `/X` suppresses only against *other `/X`
   forwarders*, not against unrelated traffic. Scopes the election to the name-group so independent flows
   don't cross-suppress.

6. **Coding-aware** — with RLNC the "same content" test is *innovation*, not identity: suppress your
   pending coded packet only if the overheard one renders it non-innovative to the neighbourhood. Softens
   the C=1 hole problem (any surviving coded packet still helps), at the cost of the innovation check.

## How it stays inside the doctrine

- **Content-keyed, not host-keyed** — you suppress because the *named data* was served; you never learn
  or store *who* served it.
- **Soft-state** — the jitter, the density estimate, the pending re-broadcast are all recomputable from
  the forwarder's PIT/CS/subscriptions; lose them and the worst case is a redundant transmission, not a
  wedged ring (§7).
- **No feedback channel required** — suppression is by *overhearing*, the free side-effect of a shared
  broadcast medium; it needs no ACKs, no election messages, no coordinator.

## Status & how to use it

- **Implemented:** the C=1 overhear-cancel with fitness-jitter (`coop.rs`), the density input (§2 nonce
  map), and the airtime validation (#68).
- **Design space open:** counter threshold C, the fitness function choice, density-adaptive W, and
  coding-aware suppression are dials, not yet swept on air. The counter-threshold C is the first knob to
  characterize on hardware (airtime vs edge-coverage), because the sim can only bound it — real PER at the
  mesh edge sets where C should sit.
- **Composes with:** the time-slice / token schedule (CCLF is the within-slot election), the §2 nonce
  density (feeds the window + distance fitness), and the CS/PIT (overhear = cache + breadcrumb).
- **Do not** re-key any of this on a host/peer identity — the moment suppression remembers *who*
  forwarded rather than *what* was forwarded, it is a peer table through the side door.
