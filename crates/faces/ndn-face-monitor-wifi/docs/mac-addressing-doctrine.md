# Named-radio MAC-addressing doctrine — the decision

**Status: decided 2026-07-17.** This is the reference for what the named-radio link
layer does with the 802.11 address fields, why, and where the line sits between the
bearer and the forwarder. It supersedes ad-hoc reasoning in chat logs and design
notes. It is tracked in-tree deliberately (a doctrine that reviewers cannot see is a
doctrine that cannot object — see the `.gitignore` note and `named-radio.md`).

Prior art it draws on: V-MAC ("Pub/Sub in the Air", Elbadry et al., SEC '20) — a
64-bit name-hash encoding field + a driver-resident Lingering Encoding Table (LET)
filtering at ~10 µs even with millions of names; wfb-ng (MAC fields repurposed as
link-id + radio-port, still endpoint-ish); NDN's PIT/FIB/CS forwarding model. None
is treated as truth; the decision below is ours.

---

## 0. The decision, in one paragraph

A MAC "address" is not one thing — it bundles ~six functions (below). The named
radio **removes host *identity*, keeps the receive *filter*, and re-keys the filter
from host to data.** Concretely: the **destination field carries a fixed-width
name-group hash** (already implemented as `name_group_mac`); the **source field
carries an ephemeral, per-boot, rotating nonce with no routing meaning** — not a
host id; **no host MAC exists anywhere.** Everything the link layer holds is
**soft-state projection**: a recompilable shadow of the forwarder's PIT/FIB/subscriptions,
whose loss costs performance, never correctness. Authority — names, trust, strategy,
caching, PIT-proper with its nonces and faces — stays above the bearer.

---

## 1. What a MAC address is secretly doing, and where each function goes

| Function of the host address | Fate under data-centric broadcast |
|---|---|
| (1) cheap pre-parse receive filter | **survives, re-keyed** host → name-group hash (V-MAC LET, our `name_group_mac`) |
| (2) demux to the right upper entity | subsumed by the name |
| (3) return-path anchor (ACK/retx/BA) | **demoted**: mandatory-and-host-keyed → optional-and-nonce-keyed (see §5) |
| (4) peg for per-peer PHY state (rate, sounding, MU-MIMO) | the one function with **no clean name substitute** — a closed-loop channel is inherently a radio *pair*. Honest cost of namelessness. Partial rebuild per name-group (§5). |
| (5) sequence scoping for dedup/reassembly | re-keys to **data identity** (RLNC generation IDs, FEC block indices are name-derived) + the ephemeral source nonce scopes concurrent producers |
| (6) regulatory/diagnostic identity | the ephemeral nonce (rotated), never a persistent host id |

The debate "remove MAC addressing" is imprecise: only host **identity** is removed.
The **filter** is re-keyed, not deleted. Both the scale objection and the
"how-is-this-different" objection assume the filter is gone; it is not.

---

## 2. What earns an identifier below the network layer

**Host identity: no.** Association, pairwise handshakes, peer tables, a spoofable
name for "me" — all removed. Keeping any of them re-imports host-centric coupling.

**A data-group identifier (name-group hash): nearly non-negotiable.** Receivers need
an O(1) predicate that runs *before* parse, decode, and verify — at line rate,
eventually in hardware. Variable-length semantic names cannot do that; the hash is
the *compiled form* of the name, the way a FIB entry is the compiled form of a
routing decision. V-MAC's LET is the existence proof. Already built:
`name_group_mac`.

**An ephemeral transmitter nonce: the defensible middle, and we keep it.** A random
per-boot (rotating) tag with no routing meaning. It buys, cheaply:
- **per-frame RSSI attribution** — makes the `SignalStore` a per-neighbour map rather
  than an ambient scalar (needed for CCLF's density term and macro-diversity). *This
  was hit empirically: RSSI-per-neighbour needs a per-transmitter tag at frame time,
  and presence-as-named-data cannot supply it per frame.*
- **DoS attribution** — local per-source rate-limiting of a flood (§3).
- **sequence/generation scoping** when two producers emit under one prefix at once.

Its costs: linkability over its lifetime (rotate it), a few header bytes, and a
temptation to creep toward host semantics — resisted by making it non-persistent and
**forbidding the forwarder from ever keying routing state on it.** That last rule is
the whole discipline.

---

## 3. The two objections, answered

### 3.1 Scale / power — "nodes must listen to everything all the time"

**True on monitor mode, and measured:** ~99 ambient frames/s on a busy channel with a
passive listener (this workspace, `reg_probe`, 2026-07-17). The radio hands the host
every frame and we filter in software. That CPU/power tax is real — but it is an
artifact of **monitor mode** (a bring-up expedient), not of the architecture.

The architectural claim is that the name-group hash is a **hardware receive
predicate** — the direct descendant of the multicast-address filter every NIC already
implements. On aligned hardware a node registers the name-groups it cares about and
the radio drops everything else *before waking the CPU* — the **same wake-filter power
profile as MAC filtering**. V-MAC proves the O(1) filter at ~10 µs with millions of
names.

The residual delta, for frames that pass the filter, is **NDN-forwarding cost** (name
longest-prefix-match, signature verify). It (a) exists independent of MAC addressing,
(b) is gated behind the same filter, (c) is amortised by caching, (d) falls on
producers/forwarders more than consumers. Keeping MACs would not reduce it.

**Measured, 2026-07-21 (task #43, `filter_cpu` on the real 8812au — the chip's own
RX filter, `set_rx_group_filter`, not a BPF proxy).** A peer injected at a fixed
total rate; the receiver read host CPU with the chip promiscuous ("process
everything") vs the chip dropping frames not addressed to the name-group (RCR AAP
cleared + APM exact-match). Idle baseline 0.0%. At ~1800 frames/s of *ambient*
(non-matching) load on top of the wanted traffic:

| injected total | Arm A promiscuous (delivered, host CPU) | Arm B chip-filtered (delivered, CPU) |
|---|---|---|
| 200/s (0 ambient) | 147/s, 1.4% | 44/s, 0.5% |
| 2000/s (~1800 ambient) | 1443/s, **8.9%** | 143/s, **1.4%** |

The chip-filtered node's CPU stays flat at its *wanted-traffic* cost (~1.4%,
independent of ambient — the chip dropped the ~1800/s of "not for me" frames before
USB); the promiscuous node's CPU climbs with total ambient (6.4× here, and it scales
linearly toward core saturation at ~10⁴ frames/s). Per-delivered-frame cost is the
same in both arms (~60–120 µs) — the *only* difference is how many frames reach the
host, which the name-group filter controls. **This is the MAC-filter power profile,
re-keyed to content: the "listen to everything" tax is a monitor-mode artifact, not
the architecture.** (Caveat: absolute delivery was link-limited and noisy between
runs, 22–72%; the load-invariance claim rests on the same-injection 2000/s cell,
where the filter's drop is unambiguous. A real forwarder adds name-LPM + verify per
delivered frame, but those are gated behind this same filter.)

### 3.2 "How is this different from MAC filtering, and you need the filter anyway for DoS"

**Concede: it is re-keyed filtering, not the absence of filtering.** The difference is
not "no filter"; it is *what the key is and what else it does*:

- **Self-describing key, no join protocol.** A multicast MAC is a host-assigned label
  needing a control plane (association / IGMP-like group management / a rendezvous
  server) to map "what I want" → "which group". The name hash *is* the content: a
  consumer subscribes to the name directly, a producer advertises nothing, and the
  receiver set is open (a cache or new subscriber filters the same frame in). Multicast
  without group management.
- **One key does filter + forward + cache + suppress.** A MAC filter is terminal and
  tells the forwarder nothing about content. The name-hash filter is the *same key*
  the PIT/FIB/CS use, so an overheard Data matching a pending Interest is cached and
  cancels my redundant transmit (CCLF), and an overheard Interest for a prefix I hold
  is served. **That fusion is the novelty, not the filtering.**
- **No host identity to track or spoof-target.** A moving node keeps no address; its
  "address" is the content it wants.

**DoS — the premise flips.** MAC filtering was *never* a DoS defence: MAC addresses are
unauthenticated and trivially spoofable, and broadcast bypasses the filter — a flooder
uses your MAC or broadcasts and wakes you anyway. Named-data's real DoS surface (a
flood of frames hashing to a name you subscribe to, forcing wasted cycles) is answered
by a **cheap-to-expensive cascade**, stronger *because* its last stage keys on "did I
ask for this":
1. hardware name-hash filter (~10 µs) drops everything outside your registered groups;
2. **PIT gating** — Data with no matching pending Interest is dropped *before* verify,
   so a flooder cannot force a signature verification unless you have an outstanding
   Interest for that exact name (fake-Data flooding bounded to names you requested);
3. only then verify.
The residual (Interest-flooding) exists in wired NDN too and is handled the same way —
per-source (nonce-attributed) and per-prefix rate limits. DoS is a network-layer
question that keeping MACs does not solve and removing them does not uniquely create.

---

## 4. Cooperative forwarding under a name filter — the crux

**The objection:** if a node only listens to names it wants, a relay never hears the
prefixes it must forward for a distant consumer, so multi-hop cooperation breaks.

**Resolution: a node's filter set is its *roles*, not just its consumption.** The
receive filter is populated by the union of:
`consumer subscriptions ∪ produced/cached prefixes ∪ FIB-routed prefixes ∪ pending
PIT names`. A cooperative relay's filter is *deliberately broader* than a leaf
consumer's — it registers the prefixes it forwards for, exactly as a router's
forwarding table is broader than an endpoint's. Cooperation works because the
forwarder role adds entries to the filter.

Three properties keep that from collapsing back to "listen to everything":

1. **Asymmetric granularity — coarse Interests, fine Data.** Interest reception filters
   on **FIB-covered prefixes** (`/x/*`, one aggregatable hash — the prefix-hash, not the
   full name). Data reception filters on **pending PIT entries** (full names, demand-
   driven, self-cleaning as they expire). You listen to prefixes you route for +
   names currently in flight through you — neither is "everything" unless you are a
   deliberate default-route node.
2. **Listen broadly for cheap Interests, narrowly for expensive Data.** Interests are
   small and infrequent relative to Data. A node can afford to hear Interests across a
   trust/interest domain, and then *pull only the Data it commits to relaying* into its
   fine filter. This asymmetry is the main efficiency lever for cooperation.
3. **Demand creates ephemeral relay state (the PIT projection).** A node need not
   statically subscribe to relay-prefixes. On hearing an Interest it could help forward
   *and* being well-positioned (good links both ways), it temporarily adds that name to
   its filter and participates via **CCLF** (overhear-and-cancel: set a rebroadcast
   timer, cancel if a better-placed node transmits first). So "helpful listening" is
   scoped to actual current demand, and self-cleans.

**Broadcast changes the shape of cooperation.** On a shared medium the ether *is* the
face — every node in range is one hop. "Reaching the target" is a coverage-and-
suppression question (does *some* in-range node rebroadcast, and which one *should*),
not an address-directed chain. CCLF answers "which one" by suppression; the filter
answers "which nodes are even candidates" by role registration.

**The filter width is the cooperation-vs-power dial — and that is the thesis, not a
bug.** How much of the namespace a node volunteers to relay = how broad its filter =
how much CPU/power it spends helping others. A battery leaf consumer relays nothing
(narrow filter, low power); a mains-powered node volunteers broad prefixes (wide
filter, high power). Forwarding capacity is a **declared contribution**, per the
named-radio thesis that a radio publishes what it can contribute — a constrained node
declines the relay role and stays cheap.

**The open problem — how the FIB forms — evaluated (task #45).** Three models, a
spectrum of how much state you spend to avoid flooding: **(a) structured routing** (a
protocol builds `prefix → nexthop`; efficient on a stable topology, but heavy under
mobility and a "nexthop" is degenerate where the ether is the only face); **(b)
reactive/demand-driven** (no FIB — listen within a trust scope, CCLF-suppressed
rebroadcast, PIT breadcrumb as the return path; zero-config, mobility-robust,
broadcast-native, costs flooding bounded by scope + CCLF + hop-limit); **(c)
contribution-anchored** (advertise relay capability *by name*, peers form soft gradients
— the thesis applied to forwarding and the power dial made explicit, but it needs a
bootstrap and is really an optimisation layer over (b)).

**Decision: (b) is the baseline** — it always works (no convergence, no bootstrap), it
is what (a) and (c) refine, and it composes directly with the CCLF suppression already
in `RadioPolicy` and the name-group filter. (c) is the optimisation layer and ties the
anchoring/election work (#19); (a) is the stable-topology specialisation.

**Prototyped and tested** in `ndn-radio-cognition/src/coop.rs` (`CoopRelay`): the
reactive relay state machine — ephemeral PIT projection, CCLF timer-suppression
(jittered rebroadcast + overhear-cancel), the reverse-path, scope bounding — with a
modelled multi-hop broadcast+adjacency medium. Four tests assert the four claims that
answer the objection: an Interest reaches a producer **two hops** away and the Data
returns along the breadcrumbs; **redundant relays are CCLF-suppressed** (only the
better-placed one forwards); an **out-of-scope node hears the Interest but does not
relay** (the filter is roles, and its width is a choice — the cooperation-vs-power
dial); **unsolicited Data is dropped** (the DoS gate). Not yet done: on-air multi-hop
(needs ≥3 spatially-separated radios) and the (c) contribution-advertisement layer.

---

## 5. What does *not* have a clean name-keyed substitute

- **Closed-loop MIMO / beamforming / MU-MIMO** anchor to a specific TX–RX *channel* — a
  radio pair, not a name. This is the honest, irreducible cost of namelessness. You do
  not get MU-MIMO back.
- **Partial rebuild per name-group:** the part of link adaptation that matters for
  multicast *does* come back keyed on the name — power/rate driven by the *worst
  overheard report for that content group* is a closed loop whose anchor is the name,
  not a peer.
- **Optional return path:** the return path is not dead, it is demoted. Where reliable
  unicast is wanted (bulk transfer, the NDI interop path where the retry storm bit us,
  task #21), a hardware ACK anchored on the **ephemeral nonce** is available (devourer's
  `SetAckResponder` is a retargetable hardware ACK — task #42). Re-key, don't delete.

---

## 6. Where the projection lives, per bearer

| Bearer | Name-hash filter | PIT-projection state | Notes |
|---|---|---|---|
| **monitor mode** (now) | software/BPF fast-path (NIC delivers all) | userspace shadow | pays the process-everything tax (measured ~99 fps); name-hash rides reinterpreted address fields for cheap SW match + to stay inert to real networks; block/generation seq must live in our own payload (firmware may rewrite 802.11 seq); no ACK machinery except by avoiding it (broadcast/no-ACK) |
| **V-MAC / hardware LET** | driver-resident, real O(1) | driver LET lingering entries carry push; DACK holds per-burst bitmap + representative election | consumer-report rate control = a PIT-adjacent producer-side structure keyed by name, not host |
| **SDR / preamble-CAM** | name-group at preamble/syncword → filter *before demod* | hardware entry timers, generation-gated RLNC | the power win AP buffering never had; name-aware channel access (prefix-hashed slots), occupancy published as named data |

---

## 7. The invariant (the test to apply to any future L2 change)

Everything below the network layer must be **soft state — a projection the forwarder
can recompile at any time, whose loss costs performance but never correctness.** What
may descend: anything expressible as a per-frame predicate or transform, parameterised
from above, operating at channel time-scales — *match this hash-set, stamp this MCS,
measure this RSSI, run this code, fire this timer, defer this slot.* What stays up:
authority — names, trust, strategy, caching, PIT-proper with nonces and faces.

**The moment L2 holds something the network layer cannot recompile — a pairwise
association, a host-keyed route, a persistent peer identity — the host-centric coupling
is back through the side door.** That is the line, and it is why folding the whole link
layer into NDN is wrong even though monitor mode gives the control to do it: channel
access, sync, and coding need microsecond reaction and fixed-width fields; names are
variable-length and semantic; keeping the bearer semantically thin is what preserves
one forwarder over WiFi, SDR, and wire.
