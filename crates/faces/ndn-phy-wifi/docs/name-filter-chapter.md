# The Name Filter — the Blurred Name

**Status: design hypothesis for one MAC subsystem, validated in isolation.** This chapter specifies
the name-filtering layer of the Named Data Radio (NDR) MAC and reports the measurements that back it.
It is *not* a finished MAC: how this subsystem shares the address budget with, constrains, and is
constrained by the other facets (time sync, slotted access, named-token scheduling, channel
hopping/rendezvous, multi-radio) is **not yet designed** — see §12. Every number here is host-side
simulation over a modeled name corpus; the on-air result exists at a single point (#106), not yet as
the swept curves below.

Evidence set (reproducible): `examples/{depth_fp,level_select,blur_encoding,gcs_fp,id_deconflict,name_filter_eval}.rs`;
recorded data `docs/data/name-filter/{depth,allocation,structure,latency,id}.csv` + `traces.ndjson`;
visualization `docs/name-filter-validation.html`.

---

## 1. Introduction (the problem, and the idea)

On a shared radio medium every transmission is heard by every node in range. A Named Data node must
decide, for each frame, whether the frame is *for it* — whether the frame's Data satisfies an
Interest it holds, or its Interest matches a route or a cached object it can serve. In stock 802.11,
frames are addressed to a **host** (a MAC address); NDN frames carry no host address, so the receiver
must accept every frame, hand it to software, and parse the name to decide. That is the cost NDN-NIC
(Shi et al., ICN'16) set out to remove by putting three receiver-side Bloom filters (BF-FIB, BF-PIT,
BF-CS) on a network card — but that card is hypothetical (their evaluation is simulation), and it
does not exist on any commodity radio.

The idea here is different: **let the frame carry a lossy, blurred image of its own name, in the bits
a commodity radio already exposes** (the 802.11 address fields), so that a receiver can decide
relevance *before* parsing — often before waking the host. The sender computes the blur once; each of
the *N* receivers reads it with a few fixed-offset loads and bit-ANDs. Where NDN-NIC moves the work
to custom silicon, we move it to a one-time sender computation and a trivial receiver check. We call
the in-frame structure the **Blurred Name** (the *Blur*).

A Blur can produce a *false positive* — the receiver thinks a frame might be relevant when it is not,
and wastes a parse — but it must **never** produce a *false negative*: it must never let a receiver
drop a frame it genuinely wanted. That asymmetry is the spine of the whole design.

## 2. Terminology

- **Blur** — the in-frame, prefix-match membership structure over the object name's prefix set. Rides
  the address fields. Answers FIB (routes) and PIT-by-prefix, with no parse.
- **Fingerprint** — a single carried hash of the full name, for exact-match questions (PIT-exact,
  Content Store). Separate field, same keyspace.
- **CS Filter** — the receiver-side Bloom filter of cached names (this *is* NDN-NIC's BF-CS, kept
  verbatim and named as such). Probed by the carried Fingerprint, still no parse.
- **Ephemeral ID** — a short per-transmitter tag keying soft PHY state (RSSI, timing, dedup). Not an
  identity; rotates; cooperatively deconflicted.
- **E** — the number of prefixes a receiver has registered (its query count).
- **d** — a name's depth (component count). **C** — the deepest level the Blur encodes (the clamp).

## 3. The membership math, per structure

A Bloom filter of `m` bits, `k` hashes, `n` inserted keys has, per query, false-positive probability

> **p ≈ (1 − e^(−kn/m))^k** — monotonically increasing in `n`, decreasing in `m`; optimal `k = (m/n)·ln2`.

The three structures differ in *what plays each role*, and getting that right is the design:

| | **Blur (in-frame)** | **CS Filter (receiver-side)** |
|---|---|---|
| `m` | the address budget (94→256 bits) — **cannot grow with load** | RAM (KB–MB) — grows with need |
| `n` | one object's prefix chain, depth `d` (small, per frame) | all cached names |
| query | the receiver's `E` registered prefixes, OR'd (each a `k`-bit mask) | the frame's carried Fingerprint |
| decision FP | **1 − (1 − p)^E** — rises with the receiver's registration count | classic BF, held low by growing `m` |
| parse? | **no** | no (Fingerprint carried) |

**GCS (Golomb-Coded Set)** is an alternative Blur realization: hash the `n` prefixes into `[0, n·M)`,
Golomb-code the sorted gaps. Space ≈ `n·log₂(1/ε)` — the information floor, ~`1/1.44` of Bloom —
at the cost of `O(n)` sequential decode and no random access. **ε = 1/M** is its target FP.

## 4. The Blur — structure, allocation, safety

### 4.1 Structure choice (measured, §11)

The Blur's per-name set is tiny (`d ≈ 12` prefixes), and that decides the structure:

- **GCS** — 6.96 bits/prefix, ~35% under Bloom. Use on **airtime-scarce media (LoRa)**; sequential
  decode is fine for `n ≈ 12`.
- **Bloom** — 10.67 bits/prefix, random-access, hardware-friendly bit-AND. Use on **wide address
  fields (802.11) and custom silicon**.
- **xor** — *rejected for the Blur*: measured 30 bits/prefix (its fixed construction slack dominates
  at `n ≈ 12`), despite a low FP. Space-efficient only for large sets.

The structure MUST be self-described by the filter's TLV tag so a receiver knows how to read it. One
grammar, per-medium instance.

### 4.2 Level allocation — the safety floor

The Blur inserts one `k`-bit contribution per prefix level. Naïvely encoding only the head levels
(`head=C`) is **unsafe**: a receiver registered deeper than `C` queries bits the sender never set and
**drops a wanted frame** — measured **100% false negatives** on genuine depth-4+ registrations (§11).

Therefore: **the Blur MUST encode every level within the clamp `C` with `k ≥ 1`** (no blind level).
Precision is *tapered*, not truncated:

- **graduated** — fixed schedule (e.g. `k = 4,4,4,3,3,3,2…` by depth). Safe, cheaper than full.
- **importance-weighted** — `k` per level allocated by a **calibration pass**: each level's weight is
  its measured discriminative value (component entropy × registration frequency at that depth), then
  bits are water-filled to minimize total FP under the budget, floored at `k = 1`. Low-entropy shared
  heads (`/ndn/edu`) earn few bits — a popular prefix narrows almost nothing. **Measured best: 17.8
  bits at 1.09% FP, FN 0** — 44% smaller than full encoding *and* lower FP (§11).

Depth is the dominant FP driver (bits set ≈ `k·d`), so bounding the *encoded* levels bounds FP
independent of the name's true depth. A benchmark on shallow names understates FP by 10–20× (§11).

### 4.3 The precision profile and its agreement

The per-level precision profile MUST be shared sender↔receiver (a receiver querying with more bits
than the sender set would false-negative). Agreement, in order of preference:

1. **Group context** (default): the profile is derived from the namespace and distributed once with
   the trust anchor, exactly like the GroupKey. Zero air, unspoken — both sides compute it.
2. **Named object**: for dynamic adaptation, the profile is a Data object `/<group>/mac/profile/<v>`;
   a piggybacked version tag signals a bump and a node fetches it by Interest. The control plane *is*
   the data plane.

**No beacons** (see §10). The safety contract: the profile is an upper bound the sender guarantees; a
receiver MAY query at ≤ that precision (higher FP, never a miss).

## 5. The Fingerprint — exact match

Prefix-match (Blur) and exact-match cannot share one projection: the Blur folds each level into the
narrow frame `m`; exact match needs the *raw* full-name hash to index a receiver-side table. So the
frame carries a separate **Fingerprint** — a few bytes of the full name's hash, from the same
SipHash-under-GroupKey pipeline as the Blur (one hash computation, two projections; #44). It serves
**PIT-exact** (a Data whose name equals an outstanding Interest) and **CS-exact**. FP = `2⁻ʷ` for a
`w`-bit Fingerprint (24 bits → 6e-6%). On the tightest media the Fingerprint MAY be omitted; exact
matches then fall back to a parse.

## 6. The CS Filter — NDN-NIC, kept

The Content Store is large and churns, so it stays a receiver-side counting Bloom filter — **this is
NDN-NIC's BF-CS design, unchanged, and is named NDN-NIC.** It is probed by the frame's carried
Fingerprint, so the Blur→CS handoff needs **no parse**. It is the only receiver-side table the
pipeline retains; FIB and PIT-by-prefix are answered in-frame by the Blur.

## 7. The pipeline

```
frame ─▶ BLUR  ──(OR of E registered masks; no parse)──▶ FIB / PIT-by-prefix hit? ─┐
    └──▶ FINGERPRINT ──(probe)──▶ PIT-exact set · CS Filter (NDN-NIC) ─────────────┤ any hit
                                                                                    ▼
   all miss ⇒ dropped, never parsed                                    parse name → forward / satisfy / serve
```

## 8. Wire format

The 802.11 address budget is 3 × 48 = 144 bits (a few reserved for I/G, U/L). Allocation:

- **Blur**: up to **128 bits** across `addr1‖addr2‖addr3`. On COTS this is software-checked in
  monitor mode; on silicon that filters addresses, hardware-checked. To reach **256 bits**, the extra
  ~116 bits ride a **fixed-offset body prefix** (software-early, no TLV walk) — same wire format,
  hardware checks as far as it can.
- **Ephemeral ID**: **8 bits** (see §9).
- **Fingerprint**: a body TLV (optional per medium).

The filter field is **TLV-encoded** and adapts in three dimensions — width, structure (Bloom/GCS),
and encoded level-set — negotiated by MTU and context. LoRa carries a shallow, narrow GCS + short
Fingerprint; 802.11 a full Bloom in the address fields + Fingerprint in the body.

## 9. Ephemeral ID and cooperative deconfliction

The ID keys soft state only, so collisions cost a "less clear view," never correctness (names are in
the payload; integrity is the signature). Rather than a large birthday-avoidance field:

- **Pick-Free-Slot (PFS)**: choose an ID not observed among neighbours (from overheard traffic —
  listen-before-transmit, which CCA already does). Alone, PFS ≈ random under hidden terminals (§11).
- **Detect-And-Rotate (DAR)**: a common neighbour that sees two transmitters under one ID marks a
  conflict hint, delivered **piggybacked on its next data frame** — no beacon. The senders rotate.

**Measured: 8 bits with PFS+DAR gives 0.04% aliasing — 29× under birthday — beacon-free, at ~0.2
rotations/node/1000 rounds, holding down to a near-idle network (§11).** Dedup keys on `(ID ‖
name-hash)` so even a residual collision never suppresses a distinct frame. Field ≥ 8 bits (6 is
viable but tighter); rotation still serves the §2 unlinkability requirement.

## 10. Control-plane tenet — no dedicated frames

Beacons are pure fixed overhead and are **forbidden**. All coordination is (a) *overheard* (ID
census, PFS), (b) *computed* from names / group context / the clock (level profile, time sync — the
µs common-view already rides ordinary frames, #74), or (c) *piggybacked* on data that would be sent
anyway (DAR hints, profile-version tags). Dynamic parameters are named data objects fetched on
demand. Control cost is demand-proportional and zero when idle. The one hard case — cold-start
rendezvous on an empty channel — is deferred to the channel-rendezvous facet, addressed there by
deterministic name→channel mapping (#40), not beaconing.

## 11. Validation (measured)

Realistic corpus: 20,000 names, Zipf-popular roots, versioned/segmented deep names (mean depth 10,
modal 11), FIB/PIT/CS registration roles. See `docs/name-filter-validation.html` for charts.

| mechanism | result | source |
|---|---|---|
| **Safety invariant** | FN = 0 for full/graduated/importance over 8,000 deep names; **head=C = 100% FN** (unsafe) | `allocation.csv`, `blur_encoding.rs` |
| **Allocation** | importance-weighted **17.8 b, FP 1.09%, FN 0** — best on all three axes | `allocation.csv` |
| **Structure** | GCS 6.96 b/prefix < Bloom 10.67 < xor 30.26 (all FN 0); GCS ~35% under Bloom | `structure.csv`, `gcs_fp.rs` |
| **Depth** | per-mask FP 0.25%→2.7% over depth 7→13, clamp-flattened | `depth.csv`, `depth_fp.rs` |
| **Ephemeral ID** | PFS+DAR 8-bit: 0.04% alias (29× under random), beacon-free, robust to PTX 0.05–0.6 and density | `id.csv`, `id_deconflict.rs` |
| **Cost / telemetry** | build 1.84–3.51 µs, FIB query 9.19 µs; **10,000 OTLP spans** via ndn-observability on the filter ops | `latency.csv`, `traces.ndjson` |

Telemetry: filter ops are `tracing`-instrumented; a monotonic-clock layer records latency (OTLP
timestamps are wall-clock, unfit for it — the observability recipe's own caveat), and the real
`NdnObservabilityLayer` publishes each span as an OTLP `trace.proto` message in an NDN Data packet
(#107).

## 12. Open cross-facet interactions (why this is a hypothesis)

- **Shared address budget.** Blur + Fingerprint + 8-bit ID claim the 144 address bits, but slotted
  access and named-token scheduling *also* key on names and may demand in-frame bits. No arbiter yet.
- **Profile-as-data circularity.** Fetching the precision profile as a named object assumes a
  CS/forwarding layer whose filtering is the very thing under test.
- **MAC-level relay/cache/serve** is asserted capability-adaptive but unmeasured, and its coupling to
  time-sync and the token scheduler is undesigned.
- **Traffic realism & on-air.** The corpus is synthetic; a testbed trace and the swept on-air curves
  (beyond #106's single point) are the honest next inputs.

## 13. References

1. Shi, Liang, Wu, Liu, Zhang. *NDN-NIC: Name-based Filtering on Network Interface Card.* ACM ICN 2016.
2. Bloom. *Space/Time Trade-offs in Hash Coding with Allowable Errors.* CACM 1970.
3. Jokela et al. *LIPSIN: Line Speed Publish/Subscribe Inter-Networking (in-packet Bloom filters).* SIGCOMM 2009.
4. Dharmapurikar, Krishnamurthy, Taylor. *Longest Prefix Matching using Bloom Filters.* SIGCOMM 2003.
5. Graf, Lemire. *Xor Filters.* ACM JEA 2020. · Dillinger et al. *Ribbon Filter.* 2021.
6. Golomb-Coded Sets (BIP-158). · Fan et al. *Cuckoo Filter.* CoNEXT 2014.
7. In-tree: `mac-addressing-doctrine.md` (§2 ephemeral source), `time-slice-mac.md`, tasks #44/#91/#92/#101/#106/#107.
