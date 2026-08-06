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

#### Hash — DECIDED: `siphash24`, one function everywhere (amended 2026-08-06)

> This paragraph originally specified **H3** ("cheap, parallelizable, hardware-friendly … rather than
> our current siphash24, which is heavier and serial"), §6.4 closed #44 against H3, the first
> implementation actually shipped keyed **FNV-1a-64**, and §9 measured the curve on FNV. Four
> statements, three different hashes. **The decision is `siphash24`, in both copies of `tier0`
> (`ndn-ext` and the LR2021 firmware), for the FIB/PIT/dedup keyspace, and for `EphemeralSource`.**
>
> **Why not H3.** H3 is a *universal* family — excellent false-positive bounds, genuinely cheap — but
> it is linear over GF(2) and not a PRF. An adversary who observes filters can solve for the matrix
> and then compute, or deliberately collide with, a private group's pre-parse filter. That is the
> attack `mac-addressing-doctrine.md` §8 assigns the `GroupKey` to prevent, and a pre-parse filter is
> exactly where an outsider wants a collision: it is the cheapest DoS surface we have.
>
> **Why "heavier and serial" was the wrong objection.** It priced the wrong operation. The receiver
> precomputes one mask per *registered prefix* (§3.2), so the per-frame RX cost is two `u64`
> AND-compares and **zero hashing**. Hashing happens only on TX (≤ `MAX_DEPTH` = 8 prefixes per name)
> and once per registration. At that rate SipHash's cost is not measurable against a frame's airtime,
> and it buys the property the design depends on.
>
> **Why the speed of a "better" hash buys nothing here.** §9 measured that at m=94 the false-positive
> rate is dominated by collisions *between* the k positions, not by hash quality — swapping in two
> independent keyed hashes moved nothing. Re-measured under SipHash the curve is unchanged
> (0.00 / 0.39 / 0.91 / 0.78 % at depths 2/4/6/8, against FNV's 0.095 / 0.24 / 0.80 / 0.94 %). So the
> hash choice is free on the FP axis and should be made on the security axis, which is what this does.
>
> Keyed per group so a private group's filter is unlinkable — `GroupKey` already exists and carries
> over unchanged, now used in **full** (16 bytes; the FNV implementation truncated it to 8).

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

> **Built 2026-08-06 (#91b), single-radio face.** `MonitorWifiFace` now carries the filter on air:
> `TxAddr::PrefixBloom { key }` compiles each object's inner NDN name into a [`PrefixFilter`] and puts
> its 12 wire bytes in `addr1 ‖ addr2` (all fragments of an object share it, cached by LP base
> sequence); `RxFilter::Bloom(masks)` reconstructs the frame's filter from `addr1 ‖ addr2` (via
> `CapturedFrame.group ‖ .addr`) and tests each registered-prefix mask — **no `InjectFrame` /
> `build_dot11` / `parse_dot11` change was needed**, since those two fields already round-trip the 12
> bytes. Builders: `with_bloom_producer` / `with_bloom_relay` / `with_bloom_consumer`. Proven end to
> end over the loopback medium (`bloom_addressing_prefix_and_granularity_decoupling`): a `/x` relay
> hears the whole family and a `/x/y/z` consumer matches at its *own* granularity — the decoupling a
> name hash cannot do. Wire NDN names are rendered to a `/`-joined byte form (`ndn_name_to_slash`) so
> TX and a receiver's `/`-string registration hash identical bytes.
>
> **Built 2026-08-06 (#91c), multi-radio path + nonce in addr3.** `InjectFrame` and `CapturedFrame`
> gained `addr3: Option<[u8;6]>`; `build_dot11` writes `frame.addr3.unwrap_or(dst)` and `parse_dot11`
> surfaces `body[16..22]`, so the ephemeral nonce rides `addr3` under the Tier-0 layout (`addr1‖addr2`
> being the filter) and `None` reproduces the legacy `addr3=dst` byte-for-byte. The a81a driver's own
> build/parse and the loopback bus thread it too. `RadioMediumFace::with_bloom(key, prefixes)` wires
> the deployed multi-radio path: TX computes each object's filter into `addr1‖addr2` with the nonce in
> `addr3` (a non-first fragment falls back to broadcast — a safe over-accept); the per-bearer RX reader
> drops frames whose filter is under no registered mask *before* signals/engine, and keys the
> per-neighbour `SignalStore` on `addr3.or(addr2)` (correct for both layouts). Test
> `medium_bloom_filters_and_keys_nonce_from_addr3`: a `/x` relay hears the family, a `/w` node hears
> none, and two different-name objects from one producer arrive under **one** neighbour address (the
> addr3 nonce, not the addr2 filter half).
>
> **Built 2026-08-06 (#91d), name_group deleted + single-radio nonce.** `name_group`, `name_group_mac`,
> `name_group_uni`, `prefix_key`, `tag_local`, `group_prefix_key`, `TxAddr::Group`/`SplitByName`,
> `RxFilter::Exact`/`Prefix` and the `with_name_group*`/`with_split_producer`/`with_prefix_relay`/
> `with_exact_consumer` builders are **gone**; `TxAddr` is `{Broadcast, PrefixBloom}` and `RxFilter` is
> `{Open, Bloom}`. `siphash24`/`GroupKey`/`OPEN_GROUP_KEY`/`EphemeralSource` stay — `EphemeralSource`
> uses `siphash24`, so that "retire the siphash24 path" meant the name-group path, not the primitive.
> The one external consumer (ndn-pipes' `with_name_group`) migrated to `with_bloom_consumer`; its
> over-air test still passes. The hardware exact-match RX filter (`set_name_group_filter`) survives as a
> flat one-address matcher — the Tier-0 prefix-set filter is a software mask-scan, not expressible in
> that silicon (§8.5). The single-radio `MonitorWifiFace` now carries an `EphemeralSource` and stamps a
> distinct nonce into `addr3` on the Bloom path, closing the last #91c gap. Deleted the four
> now-obsolete addressing tests + `tests/mac_addressing_doctrine.rs` + the `name_filter` example; the
> Bloom round-trip tests (`bloom_addressing_*`, `medium_bloom_*`) are the contract now.

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
**The answer is one keyed family shared by every consumer**, with prefix hashes cached on name-tree
nodes and reused. That was originally written as the paper's H3; it is **`siphash24`** — see the
amended hash decision in §3.1 for why the security axis decides this and the speed axis does not.
Sharing it is now literal rather than aspirational: `siphash24` already keys `EphemeralSource`, so the
stack has one keyed-hash primitive rather than a second family. Close #44 against this design.

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

### 8.1b MEASURED (#101): Tier-0's false-positive rate scales with E, and that bounds where it belongs

§8.1 said the receiver-side cost is O(E) in registered prefixes. Implementing the NDN-NIC baseline
(`src/ndn_nic.rs`) and running both over identical traffic shows the O(E) term is worse than a *work*
cost — **each registered mask is another independent chance to false-positive**, so the FP rate grows
with E while NDN-NIC's shrinks as its table fills out.

At **equal receiver state** (the baseline gets exactly the bytes Tier-0's masks occupy, 12 B each):

| E | state | Tier-0 reject / FP | NDN-NIC reject / FP |
|---|---|---|---|
| 2 | 24 B | 98.59% / 0.617% | 98.97% / 0.227% |
| 8 | 96 B | 95.15% / 1.705% | 96.65% / 0.155% |
| 32 | 384 B | 70.03% / **19.7%** | 87.09% / 0.129% |
| 128 | 1536 B | 31.64% / **36.2%** | 49.56% / 0.076% |

Zero false negatives for both at every point.

**This is a real limit on Tier-0, not a tuning issue.** A 94-bit filter tested against E masks
saturates: past roughly 8–32 registered prefixes the reject rate collapses and the filter stops
paying for its 12 bytes of airtime. So Tier-0 belongs where **E is small** — a consumer, a sensor, an
endpoint with a handful of interests — which is exactly the split `RxFilter` already describes
("a relay passes many; a consumer one"). **A relay with a large FIB wants Tier-1 (#92), not a bigger
Tier-0.** The two tiers are not redundant and neither subsumes the other.

Also worth stating because the first run of this A/B looked like a Tier-0 loss and was not a fair
test: giving the baseline its paper default of 16 KB to hold **2** prefixes over-provisions it ~5000x
and it scores a perfect 87.5% / 0% FP. That number means nothing. Any comparison of these two designs
has to fix either the state budget or the prefix count, or it is measuring provisioning, not design.

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
| k = 2, chosen because parallel hash logic was expensive | **k = 4 measured** (§9), from 2 hashes | Double hashing (Kirsch–Mitzenmacher) derives k probes from 2 hashes, so the constraint that forced k=2 is gone. The "cheap hashing / AES extensions" argument is **withdrawn**: per §3.1 the hash is not on the per-frame RX path at all, so its cost never bound the design and should not have driven the choice. |
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


---

## 9. Amendment — the sizing above is WRONG, measured. k = 4, not 6.

*Added 2026-08-05 after building the filter and measuring it on hardware
(`ndn-radio-drivers/firmware/lr2021-nrf54l15-rs/src/tier0.rs` + `src/bin/m7_filter_test.rs`,
20 000 trials per point on an nRF54L15).*

§3.1 picked **k = 6** from `p ≈ (1 − e^(−kn/M))^k`, whose optimum `(M/n)·ln2` is ~7 at these sizes.
Measured at the depth cap, the optimum is **k = 4**:

| k | bits set | FP at depth 8 |
|---|---|---|
| 3 | 25/94 | 1.99% |
| **4** | **29/94** | **0.94%** ← measured optimum |
| 5 | 35/94 | 0.98% |
| 6 | 42/94 | 1.09% |
| 8 | 53/94 | 1.50% |

**Why the formula looked wrong here — RETRACTED 2026-08-06.** This section argued that the closed
form fails at m=94 because a query's k positions are not independent, so the true optimum sits
*below* the predicted ~6, and concluded "small-m Bloom filters are their own regime — do not size
this one from the asymptotic formula."

**The sweep behind that claim was broken.** Its false-positive queries came from
`make_name(d, 0x10000 + t)`, and that helper formats the salt as four hex digits — so `0x10000`
truncated away and the "disjoint" queries shared their leading components with the registered name.
Genuine ancestors were being counted as false positives, and they land differently as k varies,
which is what produced the apparent optimum.

**With the generator fixed, the picture is that there is no measurable optimum in k = 4..8.** Two
independently written harnesses rank them differently by more than their error bars:

| k | bits set | host, 200 names / 400k trials (±1σ) | device, 12 names / 20k |
|---|---|---|---|
| 3 | 23/94 | 1.043% ± 0.016 | 1.02% |
| **4** | **28/94** | **0.586% ± 0.012** | 0.91% |
| 5 | 34/94 | 0.671% ± 0.013 | 0.46% |
| 6 | 38/94 | 0.665% ± 0.013 | 0.27% |
| 8 | 48/94 | 0.670% ± 0.013 | 0.67% |

Only **k = 3 is consistently bad**. The rest sit inside the sub-1.5% band the design needs, and which
one "wins" tracks the *name distribution*, not k. **k = 4 stands** — it wins the one measurement with
tight error bars, sets the fewest bits (28/94, headroom before saturation), costs the fewest hashes
per frame, and is what the on-air shadow-mode result (#106) was measured at.

**The transferable lesson is not the one this section originally drew.** It is not "measure, don't
compute" — the computed answer was never shown to be wrong. It is that **a measurement that
contradicts theory deserves the same scrutiny as a theory that contradicts measurement**, and that a
single harness with ~50 events is not a result. This constant was wrong in *both* directions before
anyone checked the generator.

Ruled out first: deriving `h1`/`h2` by splitting one FNV-1a-64 output was the prime suspect for
correlated positions (FNV's high bits are its weak half). Two **independent** keyed hashes measured
no better, which is what isolates the cause to small-m rather than hash quality.

> **Amended 2026-08-06.** This table was measured under keyed FNV-1a-64 with the broken generator
> described above, so **both** its axes were off. Under `siphash24`, with the disjointness fixed and
> averaged over 12 registered names, k=4 measures **0.00 / 0.53 / 0.70 / 0.56 %** at depths 2/4/6/8
> (bits set 12/19/23/30). Still the sub-1% regime, still zero false negatives at every depth — the
> conclusions that depended only on the *magnitude* survive; the one that depended on the *ordering
> across k* did not. Live assertions in `tier0::tests::false_positive_rate_matches_measured_curve`,
> and the k comparison in `ksweep_host_replication`.

### On-air validation — #106 shadow mode, SipHash, k=4

Tier-0's justification has two halves and only one is visible to a passive counter: it rejects most
irrelevant frames, and **it never drops a wanted one**. Nothing that ACTS on the filter can measure
the second — you cannot count what you silently discarded. Shadow mode runs the filter on every
frame, ignores its verdict, lets everything through, and checks the verdict against ground truth
computed by really prefix-matching the name (carried in the frame purely as an oracle).

**16 500 CRC-valid frames**, LR2021 at 2477 MHz, 16 namespaces at depth 2–6, 2 registered:

| | |
|---|---|
| reject ratio | **87.32%** (14 408 frames never parsed) |
| **false negatives** | **0** |
| FP over irrelevant | **0.201% ± 0.037** (29/14 437) |
| FP over accepted | 1.39% (29/2 092 parses wasted) |
| crc-failed, excluded before the filter | 2 |

The reject ratio sits 0.18 points under the 87.5% ceiling the traffic mix sets (2 of 16 namespaces =
12.5% genuinely wanted; observed 12.50%), and that gap **is** the false-positive leakage — the four
numbers are mutually consistent, which is why all four are reported.

FP lands slightly under the bench band (0.53–0.70% at depths 4–6, §9), as expected for a different
name mix. The earlier FNV run measured 0.457% ± 0.145 over 2 500 frames; the two are consistent
(≈1.7σ apart), so this is **not** evidence that SipHash filters better — only that changing the hash
for its cryptographic property cost nothing on the FP axis, which is the claim §3.1 makes.

**Report both FP denominators.** FP-over-irrelevant is the filter's true false-positive rate and the
only figure comparable to §9; FP-over-accepted is the operational "share of parse work wasted".
Quoting only the latter looks ~7× worse than the design and invites a chase after nothing.

**The measured curve at k = 4** (this replaces the predicted table in §3.1):

| name depth | bits set | false positive | zero-parse rejection |
|---|---|---|---|
| 2 | 12/94 | 0.095% | 99.9% |
| 4 | 19/94 | 0.24% | 99.8% |
| 6 | 27/94 | 0.80% | 99.2% |
| 8 (cap) | 29/94 | **0.94%** | **99.06%** |

**Zero false negatives at every depth**, checked on every iteration rather than sampled — the
property the whole design rests on holds.

> **Caveat discovered porting Tier 0 into ndn-ext (2026-08-06).** The depth-8 `0.94%` above is only
> valid when the FP query namespace is disjoint from the filter's at *every* prefix depth. The
> on-device `m7_filter_test` drew non-leaf query components from the same low range as the filter name
> (`/0000/0001/…`) — harmless until `clamp_prefix` was added, but with clamping present a depth-8
> query that shares the filter's first seven components truncates onto the filter's genuine depth-7
> ancestor and *correctly* matches. Re-running the old harness now reports ~13% at depth 8 — an
> artifact of the overlapping namespace, not a filter regression. The ported test
> (`ndn-face-monitor-wifi/src/tier0.rs`, `make_disjoint_name`) fixes the harness and reproduces the
> sub-1% curve. Lesson: measure FP against non-ancestors that are disjoint under clamping.

The §3.1 conclusion survives with a slightly weaker constant: worst case **0.94% FP ⇒ 99.06%
zero-parse rejection in 12 bytes**, not the 0.41% predicted. Still the right design; still far better
than the ~2.4% that copying NDN-NIC's k=2 would have given. Validation item 1 of §7 ("the FP model on
real names") is now **closed by measurement** — and the answer was that the model was optimistic.

---

## 10. Amendment — §7 validation item 4 (NAV honouring) is MEASURED, and the answer is NO. Do not announce the lease in the Duration field.

*Added 2026-08-06 after measuring on hardware (o5p-1: RTL8812AU-VS `0bda:881a` injector +
ath9k-HTC `0cf3:9271` and MT7612U `0e8d:7610` as a co-located victim IBSS pair, ch6 2437 MHz;
`ndn-face-monitor-wifi/examples/nav_probe.rs`, the `NDN_NAVUSEHDR` gate in
`ndn-radio-drivers/src/rtl8812au.rs::build_txdesc`). §5 proposed announcing the named airtime lease
"for free" in the 802.11 **Duration/ID (NAV)** field on the bet that co-located commodity Wi-Fi
honours NAV and defers to our leases. **The bet loses.** Two independent measurements:*

### 10.1 Part (a) — can we even put a chosen NAV on the air? Yes, but only with a driver bit.

By **default the RTL8812AU MAC recomputes and overwrites the Duration/ID field** on an
injected monitor-mode frame — measured 60 µs on a 6 Mbps beacon and 124 µs on a QoS-data frame,
never the `0x1234` we wrote, cross-validated by tshark's `wlan.duration` and by reading the raw MPDU
bytes 2–3 off a **neutral** (non-Realtek) ath9k capture. The value we place in the frame is discarded.

The fix is one TX-descriptor bit: **`NAVUSEHDR` (DWORD3 bit 15)** tells the MAC to transmit the
header's Duration verbatim. With `NDN_NAVUSEHDR=1` the ath9k reads back **exactly 4660 (0x1234)** on
every beacon and every data frame. So an arbitrary NAV *is* expressible on this hardware — it was
never a frame-format problem, it was a driver default. (Untested on the 8822E/`a81a` path, which
writes no NAV field and leaves HWSEQ clear; not decision-relevant — see 10.3.)

### 10.2 Part (b) — do stock stations defer to it? No — not even to a canonical RTS/CTS.

A saturated UDP link between two commodity stations (ath9k ↔ mt76, each in its own netns so traffic
is forced over the air) on the injector's channel. Arms, throughput (receiver-side, 8 s each):

| arm | throughput | reads as |
|---|---|---|
| baseline (no injection) | 11.1 Mbit/s | — |
| **flood** — large frames, **NAV=0**, spammed | **1.49 Mbit/s** | **reception + physical CCA confirmed** |
| RTS, NAV = 28672 µs (`NAVUSEHDR`) | 12.9 Mbit/s | **no deference** |
| QoS-data, NAV = 28672 µs | 13.0 Mbit/s | **no deference** |
| CTS-to-self, NAV = 28672 µs | 12.6 Mbit/s | **no deference** |

The **flood arm is the instrument check** the [hardware-truth-method] demands: it collapses the same
victims to ~13 % of baseline, proving they *hear* the injector and honour **physical** carrier sense.
Against that positive control, the NAV arms sitting at (or fractionally above) baseline is an
unambiguous negative — **the stations ignore the virtual carrier sense (NAV) in our injected frames**,
including a real RTS and a real CTS-to-self, the two frames 802.11 supposedly guarantees deference to.

The likely cause is NAV-attack hardening: modern commodity firmware updates its NAV only from frames
inside a recognised exchange / its own BSS, not from arbitrary overheard frames (our frames carry a
foreign BSSID and belong to no exchange the victim is part of). That is a *defensive* behaviour and we
will not out-argue it from userspace.

### 10.3 Consequence for the design

- **§5's "zero-cost external coexistence" is retracted.** Nearby non-NDN Wi-Fi will **not** defer to a
  lease we write into Duration/ID. The lease cannot be announced *for free* to strangers, on this
  hardware, ever.
- **The lease is not dead — its enforcement must be ours.** It is still `f(name, clock)`, still
  computed identically by every NDN node, and our own receivers parse the frame regardless, so the
  lease value can ride our **own** frame structure (payload / a reserved Tier-0 class token, §5) and be
  enforced by our nodes' computed listen-before-talk against the Tier-0 filter — **not** delegated to
  802.11 NAV. Self-enforced slotting is what the on-air token results already rested on; this
  measurement just removes the tempting shortcut of borrowing commodity NAV.
- **Which chip injects is irrelevant to this conclusion** — the failure is at the *receivers*, so
  testing the 8822E injector would not change it.
- **Custom-hardware note (§8.5).** This is another artifact of commodity 802.11, and a strong one:
  when we control the PHY/MAC (the AR9271 open firmware, #109; a wake-up radio), a lease *can* be
  enforced rather than advised, because our own MAC decides deference. The design is a faithful
  degradation, exactly as §8.5 argued — the commodity version simply must self-enforce.

Validation item 4 of §7 is **closed by measurement: NO.** The `NDN_NAVUSEHDR` gate and `nav_probe`
example are kept as the reproduction harness.
