# Name filtering and the NDR MAC — redesign

*Design note, 2026-08-05. Sits under [mac-addressing-doctrine](./mac-addressing-doctrine.md) and
supersedes the addressing half of it; extends [named-token-scheduling](./named-token-scheduling.md)
and [time-slice-mac](./time-slice-mac.md). Triggered by the observation that **hashes in the frame
cannot express prefix matching**, and informed by NDN-NIC (Shi, Liang, Wu, Liu, Zhang — ICN'16).*

---

## 1. The defect, stated precisely

The frame carries name-derived addresses today (`ndn-frame-io/src/frame.rs`):

```rust
name_group_mac(key, name)  -> siphash24(name)          // 46 bits, exact name
name_group(key, prefix, full_name, group)
      -> H(routable_prefix)[24] ‖ H(full_name)[24]     // the "loose + tight" split
prefix_key(addr) -> addr with the low 3 bytes zeroed   // the loose half alone
```

That split **is** the loose/tight two-hash idea, already built. Its limit is not precision — it is
expressiveness:

> `name_group` commits to **one** prefix granularity, chosen by the **sender**. A receiver matches
> only if it registered *that exact prefix*. If the sender picks `/A/b` and my FIB holds `/A`, the two
> 24-bit hashes are unrelated and I match nothing.

So the frame supports **exact match at a granularity agreed out of band**, and cannot do longest-prefix
match at all. Since a prefix is the *normal* FIB entry in NDN, this is not an edge case — it is the
common case. Widening to 96 bits (addr1‖addr2) makes the hash more precise and **not one bit more
expressive**. The plan of 96-bit hash + 48-bit nonce is therefore correctly abandoned.

The root cause: a hash destroys hierarchy. NDN names *are* hierarchy. Any in-frame construct that
must answer "is one of the receiver's prefixes an ancestor of this name?" has to preserve the
**prefix set**, not the name.

---

## 2. What NDN-NIC offers, and the cost-model twist

NDN-NIC filters incoming NDN packets in NIC hardware using three Bloom filters (BF-FIB, BF-PIT,
BF-CS) totalling 16 KB, dropping 96.30% of received packets and cutting host CPU by 95.92%. The
mechanisms, and our verdict on each:

| Mechanism | Verdict | Why |
|---|---|---|
| **No false negatives, ever** | **Take, as a hard rule** | A BF may over-accept; it may never drop something valid. Makes an aggressive MAC filter *safe to be wrong*. This is the single most important property to import. |
| **Two prefix-match directions, two placements** | **Take — this is the answer** | (a) *table entry is a prefix of the packet name* → enumerate the packet name's prefixes and query. (b) *packet name is a prefix of a table entry* → insert **all prefixes** of table names, query with the packet name. Hashes have no answer to prefix matching; *prefix sets* do. |
| **CBF in software, plain BF in hardware** | **Take** | Counting BFs support deletion, plain BFs don't. Mirror one into the other. Maps exactly onto our host-driver ↔ firmware split — and we already run an on-device name filter in the LoRa firmware, which is literally the paper's "constrained NIC microcontroller." |
| **Update order: apply 0→1 changes before 1→0** | **Take** | Guarantees a partially-updated filter still has no false negatives. On a radio, table updates race with air traffic continuously; this makes the race benign for free. |
| **Incremental hashing cached on name-tree nodes** | **Take** | Prefix hashes are shared by construction; compute once per node. We already walk names. |
| **Basic CS** (skip CS names already covered by a FIB prefix) | **Take** | Cheap, no downside, directly applicable to our CS-serve. |
| **k = 2 H3 hash functions** | **REJECT — does not transfer** | See §3.1. Their k=2 is optimal for *their* regime (n ≈ 10⁵ keys, m = 65536 bits). Our in-frame regime is n ≈ 4–8, m = 94. Blindly copying k=2 would cost ~2 orders of magnitude of false-positive rate. |
| **Active CS** (Transformation / Aggregation / Reversion + degree thresholds) | **REJECT for now** | It deliberately trades exact-match FPs for *prefix-match* FPs — broadening BF-FIB coverage. On a NIC a false positive costs a PCIe transfer and some CPU. On our radio it costs **a receiver wakeup and a decode**, and if it reaches the relay decision, **an on-air retransmission**. Our FP is priced in airtime and energy, not cycles. Revisit only if table memory ever binds — it doesn't. |

**The scale inversion.** The paper's binding constraint is *table memory on the NIC* (fit 10⁵ names in
16 KB). Ours is *bits in the frame* (94 of them) — our tables are hundreds of prefixes and a small CS,
sitting in host RAM we have plenty of. **Their optimization targets and ours are different problems.**
Their *structure* transfers; their *sizing results do not*.

**Related work worth reading next** (from NDN-NIC's citations; not yet read in full, flagged as such):
Rothenberg et al., *In-packet Bloom filters* [15] — this is precisely the Tier-0 idea below and should
be read before we finalize the frame format; Wang et al., *NameFilter: two-stage Bloom filters* [19] —
the principled form of the loose/tight instinct; Li et al., *MaPIT* [11] — mapping BF for PIT, relevant
to Tier 1; Quan et al., *Adaptive Prefix Bloom filter* [13]; Dharmapurikar et al. [5] — LPM via BFs,
the origin of direction-(a) enumeration.

---

## 3. The redesign: a three-tier name filter

The paper does everything at the receiver, after the name is parsed. Our advantage — and the whole
point of a name-based MAC — is that we control the frame. So we push the dominant matching direction
**into the frame**, where it costs zero parse.

### Tier 0 — in-frame prefix-set Bloom filter (`addr1 ‖ addr2`), zero parse

The sender inserts **every prefix of the frame's name** into a small Bloom filter and puts it in the
address fields. A receiver tests its own registered prefixes against it with a precomputed mask.

```
sender:    name /A/b/c  →  prefixes { /, /A, /A/b, /A/b/c }  →  k·4 bits set in a 94-bit BF
receiver:  for each registered prefix P (mask precomputed once):
               if (frame_bf & mask[P]) == mask[P]  →  maybe under P  →  accept, parse
           else  →  definitely not under P  →  drop, never touch the payload
```

This is direction (a) — *my table entry is a prefix of the frame's name* — which covers **FIB matching
for both Interest and Data**, the dominant filter. It has no false negatives.

**The architectural win is not the CPU saving. It is decoupling.** Today the sender must guess the
granularity the receiver registered. With a prefix-set BF the sender ships *all* granularities at once
and every receiver matches at *its own*. Longest-prefix match becomes a receiver-local decision, as it
should be. That eliminates the out-of-band agreement `name_group` silently requires.

#### 3.1 Sizing — why k = 2 is wrong for us

`p ≈ (1 − e^(−kn/m))^k` with `m = 94` usable bits (96 minus the I/G and U/L bits of the first octet,
which must stay locally-administered — see §6.1) and `n` = name depth:

| n (depth) | k=2 | k=3 | **k=6** | k=8 |
|---:|---:|---:|---:|---:|
| 4  | 0.67% | 0.17% | **0.013%** | 0.003% |
| 6  | 1.4%  | 0.53% | **0.10%**  | 0.05% |
| 8  | 2.4%  | 1.1%  | **0.41%**  | 0.35% |
| 12 | 5.1%  | 3.0%  | **2.4%**   | 2.8% |

Optimal k is `(m/n)·ln2`, which for n≈4–8 is far above 2. **Recommendation: k = 6, and cap insertion at
the first D = 8 name components** (deeper matching is a software-tier concern anyway). Worst case
**0.41% false positive — a 99.6% zero-parse rejection rate in 12 bytes**, against the paper's 96.30%
in 16 KB. The cap is what keeps the tail bounded; without it a deep name degrades the filter for
everyone.

Hash: **H3** as the paper recommends (cheap, parallelizable, hardware-friendly) rather than our current
siphash24, which is heavier and serial. Keyed per group so a private group's filter is unlinkable —
`GroupKey` already exists and carries over unchanged.

#### 3.2 Receiver cost

Precompute one 94-bit mask per registered prefix. A test is two `u64` AND-compares. For E entries that
is 2E word-ops per frame — for the hundreds of prefixes a node actually registers, hundreds of ns. This
is why the big tables belong in Tier 1: the mask-scan is O(E) and only stays free while E is small.

### Tier 1 — receiver-side BF-FIB / BF-PIT / BF-CS (NDN-NIC, near-verbatim)

Direction (b) — *the packet name is a prefix of my table entry* — cannot be answered from the frame's
BF (it needs the receiver's names, which the frame doesn't carry). It needs the parsed name, so it runs
after Tier 0 admits the frame: CBFs maintained in software, mirrored into BFs, 0→1-before-1→0 update
ordering, Basic CS applied. This is the paper's design, adopted as-is, minus Active CS.

### Tier 2 — the exact name tree

NFD semantics, unchanged. Tiers 0 and 1 only ever *over*-admit, so correctness lives here alone.

---

## 4. Is the demand-adaptive claimable slot fully designed?

**No.** It is *measured* (it dominates fixed-TDMA and pure CCLF across contention — see
[named-token-scheduling](./named-token-scheduling.md)) and *partially implemented*
(`FaceScheduler::gate`, `NDN_SCHED_CLAIM=1`). Seven gaps stand between that and a design:

1. **No airtime-fit test (guard band).** `gate` returns the instant `owns_now()` is true, with no check
   that the frame will *finish* inside the slot. A 2272 B frame at 6 Mbps is ~3 ms and does not fit a
   3 ms slot at all. Slotting is collision-free today only because the operator picks
   `slot_us ≫ airtime`. **(task #84)**
2. **Slot size is an env constant, not derived.** `SlotSchedule::from_airtime` exists, is documented and
   tested, and has **zero production callers**. **(#85)**
3. **"Demand-adaptive" does not read demand.** The claim triggers on *owner idleness*, never on
   *claimant demand magnitude* — a node with 1 packet and a node with 1000 contend identically.
   `DemandTracker` exists in cognition and is not in the claim path.
4. **The claim is per-slot, so bulk thrashes.** Winning a slot buys exactly one slot. There is no
   notion of claiming a *run*, so a large object pays the CCLF jitter and the election on every frame.
5. **No owner-return semantics.** If the owner wakes after a claimant has taken its slot, they collide.
   There is no yield contract.
6. **Static claim jitter ⇒ permanent claimant starvation.** `cclf_jitter_us(hash, slot_us)` is a pure
   function of the name; the lower-jitter claimant wins *every* idle slot forever. The measured
   anti-starvation result was for **owners** under fixed rotation and does not cover claimants. **(#87)**
7. **Hidden terminal — the real hole.** Slot *ownership* is a pure function of `(name, clock)`, so
   every node agrees. Slot *idleness* is **local**. Node C, out of range of the owner, sees silence,
   claims, and collides at B. The mechanism has no answer today.
   **Fix: silence is only evidence of idleness if you have positive evidence the owner is in range.**
   Require a recent hearing of the owner's name-group before treating its silence as an idle slot —
   derivable from the per-nonce RSSI store we already keep. Never-heard ⇒ indistinguishable from
   hidden ⇒ do not claim.

Gap 8 is really an instance of the filter problem: the idle test today is `last_rx < slot_start` over
**any** overheard frame — a time beacon, a foreign network, or an overrun from gap 1 all mark the owner
busy. It is an energy detector wearing a token's clothes, and we have measured what energy detection
does to this medium (LoRa LBT at N=3: delivered 205 → 64). **Tier 0 fixes it directly: AND the frame's
BF against the current slot owner's mask and you know, without parsing, whether that frame was the
owner using its turn.** The filter redesign is what makes the token a *named* token. **(#88)**

---

## 5. The MAC: one primitive, three traffic classes

The ask is time-slotting for latency-critical, something else for bulk, something else for urgent bulk
— *unless one design subsumes them*. One does.

### The named airtime lease

> A transmit grant is a **lease of L consecutive base slots**, held by a **name**, at a **class**,
> computed from the common-view clock and announced in the frame.

The timeline is a sequence of **base slots** of duration `airtime(MTU @ basic rate) + guard` (derived —
gap 2). Each base slot `s` has, as a pure function of `s`:

- an **owner**: the name whose registered prefix hashes to `s mod N` (today's computed token), and
- a **reservation bit**: every R-th slot is *reserved* — owner-only, never claimable.

Everything else is the **claimable pool**.

| class | reserved? | L | preemption | fits |
|---|---|---|---|---|
| **0 — latency-critical** | yes | 1 | preempts nothing, preemptible by nothing | control, alarms, time beacons; bounded access delay = `R·N·slot` |
| **1 — urgent bulk** | no | `L_max` | **may preempt class 2** at any base-slot boundary | a large object under deadline |
| **2 — bulk** | no | `L_max` | yields to class 1 | elastic transfer |

Today's fixed slot is exactly `(reserved, L=1, class 0)` — so this **generalizes** rather than replaces,
and the existing on-air results stay valid.

### Why it coexists with itself

**Reserved lanes are implicit, never announced.** A bulk claimant computes the reservation schedule
itself and simply never claims a reserved slot. No signalling, no negotiation, no coordinator — the same
property that makes the computed token work makes class coexistence work.

**A lease is a sequence of base slots, not one continuous burst.** The leaseholder is therefore off the
air at every base-slot boundary — which is precisely the listen point that makes preemption
implementable: a class-2 holder re-checks each boundary and yields if a class-1 claimant has started.
Half-duplex forces the gap anyway; the design spends it.

### Announcing the lease — use the field that already means this

The 802.11 **Duration/ID field is a NAV announcement**: "the medium is busy for the next N µs." That is
a lease, exactly. Writing our lease length there costs **zero new frame bits** and buys something free:
**co-located commodity 802.11 hardware honours NAV**, so nearby stock Wi-Fi defers to our leases. That
is real external coexistence for no cost — and it is the one place where speaking 802.11's language
does not reintroduce host addressing, because the field names *time*, not an identity.

### Deriving the class without parsing

Insert **synthetic class tokens** into the Tier-0 filter (e.g. a reserved pseudo-prefix per class)
alongside the name prefixes. A receiver then determines a frame's class with one more mask AND — zero
parse — at the cost of one extra inserted element (n → n+1 in the §3.1 table; negligible at k=6).

The class itself comes from **the name**, via the signed prefix registration / `NameContext` already in
cognition — not a per-frame flag. That keeps it NDN-native and verifiable. A liar can set a favourable
class token, and the honest answer is: the frame's name is checkable once parsed, so lying is detectable
*ex post*, and the ephemeral source nonce lets a run of frames be attributed without host identity. The
lease is advisory, as NAV always was; this is not a new exposure.

---

## 6. Ripple analysis — what the filter redesign changes

### 6.1 Frame format and addressing
`addr1 ‖ addr2` become the 94-bit prefix-set BF; `addr3` stays the 48-bit ephemeral source nonce
(doctrine §2, per-frame RSSI keying — unchanged). **Constraint discovered:** the I/G and U/L bits of the
first octet must keep their locally-administered/group meaning, or we start emitting frames that look
like real devices' unicast traffic. Reserve those two bits; the filter is 94 bits, not 96. Retires
`name_group`, `name_group_mac`, `name_group_uni`, `prefix_key`, `group_prefix_key`, `RxFilter::Prefix`
and the `siphash24` path. `mac_addressing_doctrine.rs` needs rewriting around prefix-set semantics.
*Option not taken:* the 2-byte sequence-control field would give 110 bits; deferred until the FP
measurements say we need it.

### 6.2 The MAC slot key
`prefix_hash(name, group_depth)` with a **global** `NDN_SCHED_GROUP_DEPTH` is the same
one-granularity-fits-all mistake as `name_group`. The slot must key on the **longest registered prefix
covering the name** — which is exactly what the name tree behind Tier 1 yields. `NDN_SCHED_GROUP_DEPTH`
is deleted; `FaceScheduler` gains a reference to the filter instead of a bare hash.

### 6.3 The receive pipeline
A filter stage lands between the RX pump and the link service, so irrelevant frames die before LP
reassembly. **This is open task #43** (measure CPU/power for process-everything vs a hardware-style name
filter) — the redesign gives it its subject, and NDN-NIC gives it the comparison baseline.

### 6.4 The shared name-hash keyspace — task #44 is answered
Open task #44 asks for one hash function shared across filter / FIB-prefix / PIT / generation-IDs.
**The answer is the paper's:** one H3 family, keyed, with prefix hashes cached on name-tree nodes and
reused by every consumer. Close #44 against this design.

### 6.5 Relay-role population — task #45
BF-FIB answers "do I serve this prefix?" in two word-ops, which is the input a node needs to decide
whether it is a relay for a frame. #45 becomes tractable.

### 6.6 The LoRa firmware
On-device name filter / dedup / relay / CS-serve already ships and is exactly the paper's constrained
target. It gains prefix matching, and the CBF/BF split is what lets the host push updates to it safely.

### 6.7 Time beacons
`TIME_BEACON_MAGIC` in the payload becomes a reserved prefix in the filter — identifiable with a mask
AND, no payload peek, and it stops being a magic byte string that could collide with real data.

### 6.8 Cognition
`DemandTracker` and `NameContext` re-key from `prefix_hash` to the registered prefix — which is also
what gap 3 (demand-aware claiming) needs, so the two land together.

---

## 7. What must be validated before building

1. **The FP model on real names.** §3.1 assumes independent hashes and a depth distribution. Measure
   against our actual name corpus; the depth cap D is the parameter that matters.
2. **The Tier-0 rejection rate on air**, against the paper's 96.30% baseline — with the receiver
   *actually* skipping the parse, so the CPU/power claim in #43 is measured, not modelled.
3. **The hidden-terminal claim guard (gap 7)** in sim first — it is the one gap that can make the
   claimable slot *worse* than fixed TDMA, and it cannot be seen in a 3-node bench where everyone hears
   everyone.
4. **NAV honouring.** Does a stock 802.11 station actually defer to a Duration field in an injected
   monitor-mode frame? If yes, §5's free external coexistence is real; if no, the lease needs its own
   bits. This is a one-afternoon SDR/second-radio measurement and it gates a design choice — do it
   early.

---

## 8. Amendments — corrections, modernization, and the custom-hardware question

*Added 2026-08-05 in the same session, in response to review. Two claims in §3 were overstated and are
corrected here rather than quietly edited, because the overstatement is instructive.*

### 8.1 Correction: "99.6% in 12 bytes vs 96.30% in 16 KB" is not a fair comparison

That side-by-side is rhetorically neat and misleading. The two numbers describe different things:

- The paper's **16 KB is receiver-side table memory** summarizing 10⁵⁺ names — *"here is a compressed
  picture of everything I want; check the incoming name against it."* It needs the incoming name, so it
  needs a parse.
- Our **12 bytes is per-frame space** carrying **one name's** prefix set — *"here is a compressed picture
  of what this frame is; check your wants against it."* It needs no parse.

Tier 0 is not "the same result with a thousand times less memory." It is **the same job moved earlier in
the pipeline**, and it is not free: those 12 bytes are spent on every frame's airtime forever, and the
receiver-side cost is **O(E)** in registered prefixes rather than O(name depth). §8.3 removes the O(E)
limit; the airtime cost is permanent and is the honest price of zero-parse filtering.

### 8.2 Correction: on commodity Wi-Fi we get the CPU win but *not* the wakeup win

NDN-NIC's headline is a **95.92% CPU reduction *and* a power reduction from not waking the host**. In
monitor mode a commodity NIC delivers **everything** — the USB RX pump has already woken us and copied
the frame before any filter of ours can run. So on the current hardware Tier 0 buys host CPU (skip the
parse, the LP reassembly, the name decode) and buys **nothing in energy at the radio**.

The exception is real and already in our hands: **the LoRa firmware's on-device filter drops frames
before the host serial transfer**, which is the paper's actual win. Task #43 must therefore measure the
two paths separately and must not report a Wi-Fi CPU saving as if it were the paper's power result.

### 8.3 Ten years on — what to modernize, aspect by aspect

| NDN-NIC (2016) | 2026 | Why |
|---|---|---|
| One structure (BF + CBF mirror) for FIB, PIT and CS | **One structure per table** | FIB is near-static and small → an **immutable xor / binary-fuse / ribbon filter** (~10–25% smaller at equal FP, faster queries, rebuilt on the rare FIB change). PIT and CS churn per packet → a **cuckoo filter**, which supports deletion *natively* and thereby **deletes the entire CBF-mirror machinery**. They used one hammer because that was the 2016 toolkit. |
| Flat BF layout | **Blocked layout** | All k probes in one cache line — the standard modern engineering win for a mutable filter. |
| k = 2, chosen because parallel hash logic was expensive | **k ≈ 6, cheap hashing** | ARMv8 crypto extensions (the OPi's A76/A55) make AES-based keyed hashing nearly free, and double hashing (Kirsch–Mitzenmacher) derives k probes from 2 hashes. The constraint that forced k=2 no longer exists. |
| Active CS (Transformation / Aggregation / Reversion) | **Skip; also skip learned filters** | Already rejected on cost-model grounds (§2). Learned Bloom filters are the modern temptation and are worse for us: they need a trained model and a stable key distribution, and they reintroduce false negatives unless sandwiched. The *goal* — adaptively choose which prefixes to insert — is better served by a demand-driven policy we already have the inputs for. |
| Receiver scan proportional to table size | **Bitslice the Tier-0 scan** | Store entry masks **transposed** (one bit-plane per filter bit): one pass of ~94 AND/OR ops tests **every** entry at once — **O(m) instead of O(E)**. This is the classic packet-classification trick and it removes §3.2's scaling limit outright. |
| Filter on a NIC (never actually built — simulated) | **eBPF/XDP is the modern kernel-adjacent location** | Did not exist for them. Relevant if we ever run a kernel-driver path; not for our userspace driver. And note their hardware was never built, which is a standing caution on their numbers. |

### 8.4 GPU / NPU backends — the honest answer is no

The paper's future work mentions GPU Bloom filters, and pluggable accelerator backends are an appealing
idea. For the **per-frame MAC filter, reject it**:

- It is **latency-bound with a batch size of one**. GPU BF results win on millions of batched queries;
  we have one frame with a budget measured in microseconds, and kernel-dispatch/PCIe latency alone is
  tens of microseconds — longer than an entire slot.
- An **NPU does dense low-precision matmul**. Bitwise approximate-membership testing is not that shape.
  Forcing it there costs more than the scalar loop it replaces.

A **backend trait is still worth having**, just for the right backends: **scalar** (baseline, portable),
**NEON/AVX SIMD**, **bitsliced** (§8.3), and **MCU** (the LoRa firmware). Selection belongs in the
existing capability model. The only defensible GPU use is **offline**: bulk-rebuilding an immutable
xor/ribbon filter over a large CS — not the data path.

### 8.5 Is this design as good as it gets, or is it Wi-Fi accommodation?

Both. Sorting them matters, because it tells us what to build when we control the PHY.

**Artifacts of commodity 802.11**, in descending cost:

1. **No hardware-scheduled TX.** This is the biggest loss — **larger than any filter improvement**. We
   approximate a slot with a host-side sleep plus EDCCA-off, which is *why* guard bands must be large.
   A TSF-scheduled transmit shrinks the guard from milliseconds to microseconds, which is what makes
   short slots possible at all. `TxDiscipline::ScheduledAt` already models this and no commodity part
   delivers it.
2. **94 bits, in address fields.** The MAC header is the only space a receiver can examine cheaply.
   A real header field at 256 bits with k=8 gives FP ~10⁻⁵ even at depth 12.
3. **No early-abort receive** (§8.2) — the energy win is unreachable.
4. **32 bytes/frame** of 802.11 header + LLC/SNAP we do not need. 3.5% at a 900 B payload; brutal at
   LoRa's 256 B.
5. **CSMA is something we fight** (`set_cca_ignore`) rather than compose with.

**What custom hardware buys — the prize is a *named wake-up radio*.** 802.11ba (Wake-Up Radio) is the
standardized shape: a low-power companion receiver decodes a tiny OOK frame and wakes the main radio.
Put the prefix-set Bloom filter **in the wake-up frame** and the node's entire duty cycle keys on
**name matching**. That is the one *qualitative* change in the whole analysis: the filter stops being a
CPU optimization and becomes **the energy architecture** — and it is finally a consumer for
`TimingModel::DutyCycled` (#90).

**Would we keep the design? Yes.** Prefix-set filter in the frame, grants computed as `f(name, clock)`,
no host identity — all survive unchanged. Only **sizing and enforcement** change (bigger filter, guards
in µs, leases enforced rather than advisory). That is the reassuring result: **the commodity-hardware
version is a faithful degradation of the custom-hardware design, not a different design.**

### 8.6 The name-keyed hop sequence needs re-evaluation — and not because of the filter

`channel = hop(H(name), epoch)` is presented as the frequency-axis twin of the time token, the two
"composing" so a name owns `(slot, channel)`. **On this hardware they do not compose.**

**`set_channel` is a ~16 ms blocking call** (`sched.rs:82,392`). Against the scheduler's own example
dwell of 120 ms that is **13% of airtime burned retuning**; against the 3 ms slots the slot schedule
uses, a retune spans *five slots* and destroys the slot structure outright. Worse, `NDN_SCHED_HOP`'s
`dwell_us` and `NDN_SCHED_SLOT`'s `slot_us` are independent environment values with **nothing requiring
dwell to be a multiple of the slot**, and nothing stopping a frame or lease from straddling a hop
boundary.

Three consequences:

1. **Drop the jam-evasion claim.** A 120 ms dwell is trivially followed by any adversary. What we have
   is slow *channel assignment*, and it should be called that.
2. **With multiple radios you do not hop — you occupy.** Assign `name → (radio, channel)` per epoch and
   the retune cost vanishes; the "hop" becomes which bearer serves the name. This is the real answer,
   it ties directly to per-bearer gating (#89), and it is what the measured MRMC result already
   argues for (~90% held at 3 hops vs single-radio collapse to ~1/5).
3. **The actual threat is co-band interference from ourselves and our neighbours** (HaLow/LoRa
   co-banding, Wi-Fi contention) — measured, repeatedly. For that, **occupancy-driven channel avoidance
   beats blind hopping**, which is already the recorded co-band cognition design. The hop schedule
   should be demoted from "the frequency token" to *one input* to a mostly occupancy-driven channel
   assignment.

Supporting defect: **`RadioCapability.agile: bool`** ("fast-FHSS-capable") is `true` for every Wi-Fi
preset — radios that take 16 ms to retune — and is **read by nothing**. It should be a *measured*
`retune_us`, so a schedule that cannot be met is rejected at plan time instead of silently burning
airtime. (#97, #98)

And the filter redesign does touch the hop key: `hop(prefix_hash(name, group_depth))` inherits exactly
the same one-granularity-fits-all defect as the slot key, and takes the same fix — key on the longest
*registered* prefix (§6.2).
