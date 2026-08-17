# Named-Data Radio MAC — On-Air Wire-Format Specification

**Status: specification, read from the shipping code (2026-08-17).** This is the byte-level contract a
second implementation (the LR2021 firmware, an ath9k-htc C port, a fresh receiver) must match to
interoperate on air. Every field, magic, offset, and endianness below is transcribed from source with a
`file:line` citation; nothing here is aspirational. It is the concrete companion to the four facet
chapters and `mac-synthesis.md`.

**Conformance.** The key words MUST, MUST NOT, SHOULD, and MAY are used per RFC 2119. A divergence in any
**cross-implementation invariant** (§12) is not a lost optimization — it is a **silent false negative on
air**: frames that should match are dropped with no error.

Types live in three crates: the 802.11/radiotap builders and the `EphemeralSource`/`InjectFrame` types in
`ndn-rs/crates/core/ndn-frame-io` + `ndn-radio-hal` (re-exported by the face crate,
`ndn-face-monitor-wifi/src/lib.rs:106`); the MAC logic in `ndn-radio-cognition` and
`ndn-face-monitor-wifi`; the coding in `ndn-coding`.

> **⚠ NORMATIVE vs CURRENT-CODE — the address partition is migrating (2026-08-17).** The Blurred Name
> redesign (`name-filter-chapter.md`, commit `4706a58`) decided a new split of the 144 address bits:
> **a 126-bit Blur filter + an 8-bit ephemeral ID + an 8-bit flags byte** (the "128 : 8" design, realized
> byte-aligned while keeping the 2-bit local-group reservation). The 8-bit ID is viable *only* with
> **cooperative deconfliction** (§4). The tables below are **normative** (the target contract). Where the
> shipping code still implements the older **94-bit filter + 46-bit random nonce** it is flagged
> `[CODE: 94:46]`; that migration is in progress (§16).

---

## 1. Design invariants that shape the wire

Three doctrine rules explain *why* the bytes are what they are:

1. **No host identity on the wire.** The source address is not a MAC — it is an **ephemeral nonce** (§4)
   that rotates every 5 minutes. There is no node address field anywhere in the data frame.
2. **The receiver admits by name, not by address.** The destination address bytes are not an address —
   they are a **prefix-set Bloom filter** (§3), and a receiver admits a frame if its registered prefix
   *might* be in that set. Addressing is content-centric.
3. **Everything else is computed, not announced.** The slot, the channel, and the FEC budget are pure
   functions of the name and a common-view clock (§7–§10); the only control frames on air are the
   reception report (§6) and the time beacon (§7), both carried as ordinary named data or raw injects.

## 2. The name-hash keyspace (#44) — two families, one normalization

The protocol uses **two deliberately different hash families**, and an implementation MUST use the right
one for each surface (`tier1.rs:767`):

- **Wire filter → keyed SipHash-2-4.** The Blurred-Name Bloom (§3) hashes prefixes with SipHash-2-4 under
  a shared 16-byte key. Keyed so the filter is unforgeable and so a passive listener cannot cheaply
  enumerate names. Reference vector (`ndn-frame-io/src/frame.rs:54,:596`): key = `00 01 … 0f`, data =
  `00 … 0e` → `0xa129ca6149be45e5`.
- **Computed access → unkeyed FNV-1a-64.** The slot owner, channel, demand, and consistency digest hash
  the name with **`prefix_hash`** — unkeyed FNV-1a-64, so *every* node computes the identical value with
  no shared secret (`ndn-radio-cognition/src/lib.rs:97`):

  ```
  h = 0xcbf29ce484222325                       # FNV offset basis
  for component c in name:
      for byte b in c: h = (h XOR b) * 0x100000001b3
      h = (h XOR 0x2f) * 0x100000001b3          # '/' (0x2f) between components
  ```

  The `0x2f` separator MUST be folded in after each component so `["ab","c"] != ["a","bc"]`.

The **only** thing the two families share is the name *normalization*: components joined by `/`. The
three renderings of that normalization (`ndn_name_to_slash`, `Tier1Feed::slash`, `Tier1Feed::slash_name`)
MUST agree byte-for-byte (`tier1.rs:767`) or every match silently fails.

## 2a. Filter width is a cascade — address floor, body tier, receiver table

The prefix-set filter exists at **three graduated widths**, AND-composed and each with **zero false
negatives**; a sender picks how far up it climbs per name, a receiver applies each stage only if the one
below passed:

| stage | width | where | cost | checked when | for |
|---|---|---|---|---|---|
| **Address Blur** | **126 bits** | the 144 address bits (§3) | 0 body bytes | before the body is parsed (hardware-checkable) | the universal floor — every frame |
| **Body prefix-set** | **≤ 256 bits** | a body-prefix TLV | ~32 body bytes | only if the address Blur passed | deep names / dense FIBs where 126 b saturates |
| **NDN-NIC BF-FIB** | receiver table | receiver RAM (Tier-1) | 0 wire bytes | only if the frame is admitted | a relay whose FIB is too large for any in-frame filter |

- The address Blur is the **capability floor** (free, universal, pre-parse). The 256-bit body prefix-set
  is **capability-above-floor** — optional, signalled by `FLAG_BODY_PREFIX` in the flags byte (§5.4), and
  applied only to frames that already passed the address gate, so it costs the rejecting majority nothing.
- Both in-frame stages use the **same keyed-SipHash keyspace** (§2), so a receiver computes its prefix
  masks once and applies them at both widths. Intersecting two zero-FN filters stays zero-FN; the FP rate
  multiplies down.
- The 32 body bytes are airtime the **sender** pays per flagged frame, so the width is a **name-driven
  precision knob**: a shallow endpoint name rides the free floor; a deep name into a dense relay buys the
  256-bit tier. On a bit-starved bearer (LoRa) the body filter MAY use **GCS** (~35% fewer bits, sequential
  decode) instead of Bloom — the TLV tag selects the structure per medium.

## 3. The Blurred Name — address Blur (prefix-set Bloom filter)

Source: `ndn-face-monitor-wifi/src/tier0.rs`. Struct `PrefixFilter` — **normatively `[u8; 16]`** spanning
addr1‖addr2‖addr3[0..4] (126 usable bits). `[CODE: [u8;12], addr1‖addr2, 94 usable bits]`.

**Parameters (all pinned; §12):**

| param | normative | `[CODE]` | source |
|---|---|---|---|
| `M_BITS` (usable bits) | **126** | 94 | `tier0.rs:63` |
| `K` (hashes/prefix) | **4** | 4 | `tier0.rs:98` |
| `MAX_DEPTH` (deepest prefix) | **8** | 8 | `tier0.rs:102` |
| `FILL_CAP` (admission popcount) | **64** | 48 | `tier0.rs:126` |
| `RESERVED_MASK0` | `0b0000_0011` | same | `tier0.rs:130` |
| hash | SipHash-2-4, 16-byte key | same | `tier0.rs:154` |

`FILL_CAP` scales with `M_BITS` (it is the ~½·m universal-wake bound); at m=126 it is **64**
(`[CODE: 48]` at m=94).

**Bit geometry.** The normative filter is a **16-byte array** = addr1‖addr2‖addr3[0..4] = 128 physical
bits. Physical bits 0 and 1 (the I/G and U/L bits of addr1 octet 0) are **reserved** `0b11` (§1 no-ACK
group marker), leaving **126 usable**. Usable bit `p ∈ [0,126)` maps to physical bit `p+2`:
`array[(p+2)/8] |= 1 << ((p+2)%8)` (`set_bit`, `tier0.rs:237`). `[CODE: a 12-byte array (addr1‖addr2), 94
usable bits — the filter does not yet extend into addr3.]`

**K positions — double hashing (Kirsch–Mitzenmacher)** (`positions`, `tier0.rs:169`):

```
h1 = siphash24(key,  prefix) as u32
h2 = (siphash24(key2, prefix) as u32) | 1        # key2 = key XOR KEY2_DOMAIN; |1 forces an odd stride
bit_i = (h1 + i*h2) mod M_BITS   for i in 0..4    # four usable-bit indices; M_BITS=126 (CODE: 94)
```
`KEY2_DOMAIN = b"ndn/tier0-h2\0\0\0\0"` (`tier0.rs:162`).

**Insertion.** For a name, insert **every prefix root-first** — `/`, `/A`, `/A/b`, … capped at `MAX_DEPTH`
slashes (`for_each_prefix`, `tier0.rs:187`; `insert_name`, `:249`) — setting the K bits of each.

**Membership test (the receiver's gate, `may_match`, `tier0.rs:276`):**
1. If `popcount(filter) > FILL_CAP (48)` → return **false** (an over-full filter is inert — the
   universal-wake bound).
2. Else pure AND of the receiver's precomputed prefix mask against the 12 filter bytes, excluding the two
   reserved bits of byte 0. A miss is **exact** (definitely not under this prefix); a match may be a false
   positive costing only a parse. **Zero false negatives** is the invariant.

A receiver MUST clamp its registered prefix to `MAX_DEPTH − 1` components before building its mask
(`clamp_prefix`, `tier0.rs:216`) to avoid false negatives against deeper-inserted names.

**Wire placement.** `to_wire()` (`tier0.rs:306`) forces `w[0] = (w[0] & !0b11) | 0b11` and yields the 12
bytes; they map to the address fields in array order (§5.2). Golden vectors: `tier0.rs:701`.

## 4. The ephemeral ID — 8 bits + cooperative deconfliction

**Normative: an 8-bit ephemeral ID** in `addr3[4]` (§5.3). The 46-bit random nonce is what forces the
filter down to 94 bits; shrinking the ID to 8 bits frees 32 address bits to the filter (94 → 126). Eight
bits is enough **only because aliases are deconflicted cooperatively** rather than made improbable by
width — this is the load-bearing dependency, and it MUST be built before the field is narrowed (§16).

`[CODE: an [u8;6] SipHash-rotating nonce, EphemeralSource { boot_seed, rotation_period_ms },
NONCE_ROTATION_MS = 300000; derivation frame.rs:139: m = siphash24(boot_seed, now_ms/period)[0..6],
m[0] = (m[0] & 0xFC) | 0x02. Low 46 bits form the body.]`

**Cooperative deconfliction (beacon-free; `id_deconflict.rs`, sim-measured 0.04% alias, 29× under the
birthday bound):**
- **Pick-Free-Slot (PFS)** — on boot / rotation, a node picks an 8-bit ID not seen among IDs it has
  recently overheard. PFS alone ≈ random against *hidden* nodes (it cannot see IDs it does not hear), so
  it is only the initial pick.
- **Detect-And-Rotate (DAR)** — the workhorse. When a **common neighbour** overhears two senders using the
  same ID (an alias it can attribute to distinct content/timing), it piggybacks a 1-bit *collision*
  signal on data it already sends; a node receiving that signal for its ID rotates. No dedicated frame —
  the signal rides existing traffic (the control-plane tenet: overhear / piggyback, never beacon).

**Consumers key on the ID, never on host identity:** per-neighbour RSSI, per-source DoS token bucket, the
neighbour-density count for the FEC pooling discount, and relay-vs-owner discrimination. All are soft
state whose worst case under a residual alias is a merged RSSI estimate or an over-counted neighbour —
never a delivery failure — which is why 8 bits + deconfliction is safe where a durable address would not
be.

## 5. The injected 802.11 monitor frame

Builder `build_dot11()` (`ndn-frame-io/src/frame.rs:269`); decode `parse_dot11()` (`:371`).
Full buffer = **radiotap TX header ‖ 802.11 header ‖ LLC/SNAP ‖ EtherType ‖ payload**.

### 5.1 radiotap TX header (HT variant, `radiotap.rs:68`, `TX_HEADER_LEN = 13`)

All multi-byte fields **little-endian**:
```
off 0 : u8  version = 0
off 1 : u8  pad     = 0
off 2 : u16 len     = 13
off 4 : u32 present = (1<<15 TX_FLAGS) | (1<<19 MCS)
off 8 : u16 TX_FLAGS = NOACK
off 10: u8  MCS.known = HAVE_MCS | HAVE_BW | HAVE_GI
off 11: u8  MCS.flags = BW_20 | (short_gi ? 0x04 : 0)
off 12: u8  MCS.index = <mcs>
```
Legacy variant `build_tx_legacy()` (len 12): a RATE byte at off 8 in 500 kbps units (2 = 1 Mbps).
S1G (HaLow) variant `build_tx_s1g()` (len 10): TX_FLAGS = NOACK only, no rate field. **All injected
frames MUST set TX_FLAGS = NOACK** — the MAC does not use link-layer acknowledgement (feedback is named;
see the synthesis).

### 5.2 802.11 header — Data frame, 24 bytes (`frame.rs:274`)

```
off  0 : Frame Control = 0x08 0x00      # type=Data(2), subtype=0 — a Data frame, NOT QoS-Data
off  2 : Duration/ID   = 0x00 0x00      # NAV is not honoured on air (#96); left zero
off  4 : addr1 (RA/DA) = filter[0..6]   OR broadcast   ← Blurred-Name filter, HIGH 6 bytes
off 10 : addr2 (TA/SA) = filter[6..12]  OR nonce       ← Blurred-Name filter, LOW 6 bytes
off 16 : addr3 (BSSID) = nonce          OR copy of dst ← §4 ephemeral nonce (Tier-0 layout)
off 22 : SeqCtrl       = 0x00 0x00
off 24 : LLC/SNAP      = AA AA 03 00 00 00
off 30 : EtherType     = <ethertype> big-endian (0x8624 for RawNdn)
off 32 : payload       = LP-framed NDN packet
```

The QoS-Data subtype `0x88 0x00` is used **only** for the A-MSDU aggregation path (`build_amsdu`,
`frame.rs:237`); a conformant plain data frame MUST use `0x08 0x00`.

### 5.3 The normative address partition (18 bytes = addr1‖addr2‖addr3)

The 144 address bits are partitioned **filter ‖ ID ‖ flags**. An implementation with a name in hand
(first fragment) MUST use the Tier-0 layout; a fragment with no name MUST fall back to the legacy
broadcast layout.

| bytes | field | Tier-0 layout | legacy layout |
|---|---|---|---|
| addr1[0..6] | Blur filter, part 1 | `filter[0..6]` (addr1[0] bits 0–1 = `0b11`) | `BROADCAST` `ff×6` |
| addr2[0..6] | Blur filter, part 2 | `filter[6..12]` | 8-bit ID in addr2[0], rest random |
| addr3[0..4] | Blur filter, part 3 | `filter[12..16]` | copy of addr1 |
| addr3[4] | **ephemeral ID** | 8-bit ID (§4) | — |
| addr3[5] | **flags** (§5.4) | flags byte | — |

So the 16-byte `PrefixFilter` occupies addr1‖addr2‖addr3[0..4]; the ID and flags occupy the last two bytes
of addr3. `BROADCAST = [0xff;6]` (`radio-hal:27`); `DEFAULT_SRC` (`radio-hal:31`) is legacy/loopback only.
A receiver reconstructs the 16-byte filter from `addr1 ‖ addr2 ‖ addr3[0..4]`, reads the ID from
`addr3[4]`, and the flags from `addr3[5]`.

`[CODE: filter = addr1‖addr2 (12 bytes only); addr3 = the full 46-bit nonce (no ID/flags split);
receiver reads nonce = addr3.or(addr2), filter = from_wire(addr1‖addr2) — medium.rs:945,:1378.]`

### 5.4 The flags byte (`addr3[5]`)

A new normative byte carrying per-frame options; `0x00` on a plain frame. Bit assignments (LSB first):

| bit | name | meaning |
|---|---|---|
| 0 | `FLAG_BODY_PREFIX` | a ≤256-bit body-prefix filter TLV follows the LP header (§2a) |
| 1 | `FLAG_ID_COLLISION` | piggybacked Detect-And-Rotate signal: "I overheard your ID aliased" (§4) |
| 2–7 | reserved | MUST be 0; reserved for a wire version field |

The flags byte is what lets the 256-bit body tier and the DAR deconfliction signal ride existing frames
without a flag-day — it is the versioning surface the frame layout otherwise lacks (§13).

## 6. Reception report

Source `ndn-radio-cognition/src/report.rs`. The report is the *content value* of an NDN Data packet
published on **`/localhop/radio/report/<node>`** (`control.rs:359`); the codec below is that value.

Constants: `REPORT_MAGIC = 0xCD` (`:21`), `REPORT_VERSION = 2` (`:24`), `MAX_ENTRIES = 32` (`:26`).
All multi-byte fields **little-endian** (`encode_report`, `:79`):

```
off  0 : u8  MAGIC   = 0xCD
off  1 : u8  VERSION = 0x02
off  2 : u64 node_id
off 10 : u32 seq
off 14 : u64 ts_ms
off 22 : u8  max_rx_mcs               # v2 ONLY; v1 omits and is read as FULL_RX_MCS (9)
         u8  nn = min(len, 32)        # heard_neighbors
         nn × { u64 id ; i8 rssi }
         u8  np = min(len, 32)        # heard_prefixes
         np × { u64 prefix_hash }     # FNV prefix_hash (§2)
         u8  ns = min(len, 32)        # spectrum
         ns × { u8 channel ; u8 busy_pct }
```

Decode (`decode_report`, `:134`) MUST reject a bad magic, MUST accept only version 1 or 2, MUST read
`max_rx_mcs` only when `version >= 2` (else `FULL_RX_MCS = 9`), and MUST cap every vector at
`MAX_ENTRIES`. `max_rx_mcs` values: `LEGACY_ONLY_RX = 0`, `SINGLE_STREAM_HT_RX_MCS = 7`, `FULL_RX_MCS =
9`. This report closes the outbound rate/power loop and drives the worst-receiver cap and the FEC pooling
discount.

## 7. Time beacon

Source `sched.rs`. `TIME_BEACON_MAGIC = [0x7E, 0x54, 0x42]` (`0x7E 'T' 'B'`, `:208`) — chosen not to
collide with an NDN first byte (Interest `0x05`, Data `0x06`, LP `0x64`).

```
off 0 : [3] MAGIC  = 7E 54 42
off 3 : u64 ref_us  (LITTLE-endian, the master's monotonic reference time in µs)
```
Total 11 bytes (`build_beacon`, `:489`; `parse_beacon`, `:505`). The beacon is injected **raw** — it MUST
NOT pass through the slot gate, so the clock signal never waits on a data slot — and is suppressed on RX
as non-NDN. It carries only `ref_us`; the receiver derives the common-view offset from it plus the
hardware RX timestamp (`ingest_common_view`, `:531`), and a network-time stratum/reference election runs
over `RefBelief { ref_id, stratum, offset_to_ref }` (#75).

This is the **only** periodic frame in the protocol, and it exists solely because sub-µs slotting needs a
shared clock — it is a timing reference, not a discovery beacon (there is no dedicated discovery beacon).

## 8. Link-FEC generation header

Source `ndn-coding/src/link_fec.rs`. `LINK_FEC_MAGIC = 0xFC` (`:54`), header `HDR = 6` bytes (`frame`,
`:59`):

```
off 0 : u8  MAGIC      = 0xFC
off 1 : u16 generation (LITTLE-endian)
off 3 : u8  k           # source frame count
off 4 : u8  n           # = k + redundancy; total tagged frames (n <= 255)
off 5 : u8  index       # 0..k = source frames, k..n = parity frames
off 6 : ...  coded segment
```

Each source segment is wrapped `[len: u16 BIG-endian] ‖ payload` and zero-padded to the generation's max
length before encoding (`encode`, `:130`); `untrim` (`:71`) restores it. A generation of K sources is
emitted as indices `0..k` followed by R parity indices `k..n`; the generation counter increments
(wrapping) per generation. **The N frames of a generation MUST be spread across separate MPDUs** — a
single FCS failure otherwise loses all N (`:29`). Systematic: a receiver delivers source frames on arrival
and only invokes recovery when a generation completes (`absorb`, `:201`).

## 9. Computed access — slot and channel (no wire bytes)

These are not transmitted; both endpoints compute them from the name (`prefix_hash`, §2) and the
common-view epoch. An implementation MUST compute them identically.

- **Slot owner** (`schedule.rs:256`): `owner_slot = prefix_hash % slots`. With reserved latency lanes
  (`owner_slot_in`, `:134`): a `Latency` name → `(prefix_hash % reserved_slots) * reserved_stride`; a
  `Bulk` name → the nth open slot skipping reserved lanes.
- **Medium keying** (`sched.rs:690`): before the slot lookup, the operating channel is folded in —
  `medium_keyed = prefix_hash XOR (channel as u64 * 0x9E37_79B9)` — so two radios on different channels
  own different slots (a single medium = one schedule).
- **Channel** (`schedule.rs:338`): `channel = classes[(prefix_hash + epoch) % C]`, `epoch = now_us /
  dwell_us`. A static (non-hopping) deployment fixes `epoch`'s effect and degenerates to `H(name) % C`.
- **CCLF within-slot jitter** (`sched.rs:731`): `mixed = prefix_hash XOR (epoch * 0x9E37_79B9_7F4A_7C15)`;
  `draw = (mixed XOR (mixed >> 32)) % window`.

## 10. Consistency digest

`RadioPlan.consistency: u64` (`plan.rs:253`), computed by `consistency()` (`policy.rs:752`) as FNV-1a-64
(basis/prime as §2, over `to_le_bytes()` words) folding, in order: `prefix_hash`, `receivers/2`, then per
allocation `radio.0`, `channel.unwrap_or(0)`, `mcs().unwrap_or(0)`. It lets an overhearer detect and
suppress a contradictory re-transmit. It is carried in-band with the object, not as a separate frame.

## 11. Constant registry

| name | value | field | source |
|---|---|---|---|
| Frame Control (data) | `0x08 0x00` | 802.11 FC | `frame.rs:278` |
| EtherType (RawNdn) | `0x8624` (BE) | 802.11 | `frame.rs` |
| `BROADCAST` | `ff ff ff ff ff ff` | addr | `radio-hal:27` |
| `DEFAULT_SRC` | `02 4e 44 4e 00 01` | addr (legacy) | `radio-hal:31` |
| Tier-0 `M_BITS` / `K` / `MAX_DEPTH` / `FILL_CAP` | **`126 / 4 / 8 / 64`** (`[CODE: 94/4/8/48]`) | address Blur | `tier0.rs:63,98,102,126` |
| Tier-0 `RESERVED_MASK0` | `0x03` | Blur byte 0 | `tier0.rs:130` |
| `KEY2_DOMAIN` | `"ndn/tier0-h2\0\0\0\0"` | Blur h2 | `tier0.rs:162` |
| `EPHEMERAL_ID_BITS` | **`8`** (addr3[4]) (`[CODE: 46-bit nonce]`) | ID | §4 |
| `FLAG_BODY_PREFIX` / `FLAG_ID_COLLISION` | bit 0 / bit 1 of addr3[5] | flags | §5.4 |
| body prefix-set width | **`≤ 256` bits** (TLV; Bloom or GCS) | cascade | §2a |
| `LINK_FEC_MAGIC` / `HDR` | `0xFC` / `6` | FEC | `link_fec.rs:54,57` |
| `REPORT_MAGIC` / `VERSION` / `MAX_ENTRIES` | `0xCD` / `2` / `32` | report | `report.rs:21,24,26` |
| `FULL_RX_MCS` / `SINGLE_STREAM_HT_RX_MCS` / `LEGACY_ONLY_RX` | `9 / 7 / 0` | report | `report.rs:28,39,32` |
| `TIME_BEACON_MAGIC` | `7E 54 42` | beacon | `sched.rs:208` |
| FNV-1a-64 basis / prime | `0xcbf29ce484222325` / `0x100000001b3` | prefix_hash | `lib.rs:97` |
| component separator | `0x2f` (`/`) | prefix_hash | `lib.rs:97` |
| medium-key mult | `0x9E37_79B9` | slot key | `sched.rs:690` |

## 12. Cross-implementation conformance

A second implementation (LR2021 firmware, ath9k-htc C, a bench receiver) **MUST** match, byte-for-byte:

1. **Tier-0 parameters** `k=4, m=94, max_depth=8, fill_cap=48, hash=siphash24, reserved_mask0=0x03` and
   the SipHash key — pinned in `ndn-radio-drivers/golden/tier0/vectors.txt` (`tier0.rs:680`). A mismatch is
   a silent false negative on air.
2. **The name normalization** (§2) across all three renderings (`tier1.rs:767`).
3. **The endianness of every multi-byte field** exactly as tabulated (note the deliberate mix: link-FEC
   `generation` is LE but its segment length prefix is BE; the report is all-LE).
4. **NOACK on every injected radiotap header** (§5.1).

Golden test vectors for the Bloom filter (`tier0.rs:701`) and the SipHash primitive (`frame.rs:596`)
serve as the conformance oracle; a new implementation SHOULD reproduce them before going on air.

## 13. Versioning

Only the **reception report** carries an explicit version byte (`0xCD 0x02`), with a defined v1→v2
upgrade (the `max_rx_mcs` byte, §6). The frame layout, Bloom parameters, nonce derivation, link-FEC
header, and time beacon are **unversioned** and are pinned by the golden vectors (§12); a change to any of
them is a flag-day and MUST bump the golden vectors in lockstep across all implementations. A future
in-band frame version would most naturally ride a reserved EtherType or an LP header TLV, neither of which
is allocated today.

## 14. Not specified here

- **FHSS hop-set negotiation.** The channel is computed (§9), but the *set* of channel classes and dwell
  is a local config (`NDN_SCHED_HOP`), not an on-air field; a hop schedule is only meaningful with
  fast-retune hardware (moot on COTS Wi-Fi, `vet_hop`).
- **A third lease class (urgent-bulk).** The named airtime lease carries only Latency/Bulk on air; the
  third class needed an observable channel that #96 removed (stock 802.11 ignores the NAV).
- **Cooperative-forwarding FIB population** (#45) — how a relay learns which prefixes to carry.
- **NAN / BLE / embedded bearer framings** — this document covers the 802.11 monitor bearer; other
  bearers reuse the LP-NDN payload and the computed-access rules but frame differently.

## 15. Migration status (normative 128:8 vs code 94:46)

The normative layout above is the Blurred Name redesign's decided contract; the shipping code implements
the older split. The migration (this session's actuation) proceeds in dependency order — the ID field
MUST NOT be narrowed before its deconfliction enabler exists:

1. **Widen the address Blur** — `PrefixFilter` `[u8;12] → [u8;16]`, `M_BITS 94 → 126`, `FILL_CAP 48 → 64`,
   the filter spanning addr1‖addr2‖addr3[0..4]; update `to_wire`/`from_wire`/`set_bit`/`positions`/
   `mask_for`/`may_match`/popcount and the golden vectors.
2. **Repack the frame** — filter into addr3[0..4], the ID field into addr3[4], the flags byte into
   addr3[5]; update the TX packing (`medium.rs:945`) and RX reconstruction (`medium.rs:1378`).
3. **Build cooperative deconfliction (PFS + DAR)** — the enabler that makes an 8-bit ID safe; only then
   narrow `EphemeralSource` from 46 bits to 8.
4. **Cross-implementation** — regenerate the golden vectors and propagate to the LR2021 firmware
   (`lr2021-nrf54l15-rs/src/tier0.rs`) and the ath9k-htc C copy; a divergence is a silent on-air FN.
5. **The 256-bit body tier** (§2a) and the `FLAG_BODY_PREFIX` path are a later addition, unblocked by the
   flags byte but not part of the address-partition migration.

## 16. References

The four facet chapters (`name-filter`, `temporal-access`, `spectrum-multiradio`, `link-adaptation`),
`mac-synthesis.md`, and the source cited inline. Task anchors: #44 (name-hash keyspace), #82/#92/#106
(Tier-0 addressing on air), #62 (ephemeral nonce), #41/#74/#75 (common-view clock + beacon), #29/#33/#34
(link-FEC), #96 (NAV ignored → NOACK + self-enforced lease).
