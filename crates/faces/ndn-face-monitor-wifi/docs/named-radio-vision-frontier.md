# Named-radio vision — frontier ideas (parked)

> **Home (2026-07-16).** This *is* the home. The doc was previously staged and
> gitignored, and named `.claude/notes/named-radio/` as its eventual home — a
> directory that never existed and, being under an ignored `.claude/`, could not
> have been versioned anyway. It now lives tracked, beside
> [`named-radio.md`](named-radio.md) and the in-tree
> [`../../ndn-face-wifi-aware/docs/NAMED_RADIO_COURSE_CORRECTION.md`](../../ndn-face-wifi-aware/docs/NAMED_RADIO_COURSE_CORRECTION.md).
> **FRONTIER — NOT near-term.** None of this is in code, and that's correct. These
> are the genuinely-novel ideas from the 2026-06-17 brainstorm that go *beyond* what's
> already built (see the reconciliation/backlog docs for what's real). Captured so
> they're preserved without masquerading as a sprint. Inline flags mark where the
> idea is strong vs where it's hand-wavy.

## The narrative spine: the medium as a decaying spatial cache

Reframe the radio not as links but as a **content-addressable field**: named, signed
data has a freshness (decays in time), a spatial extent (decays with distance/hops),
and demand-reinforcement (data many want is re-emitted/re-cached more, so it "glows
brighter" and reaches farther). You don't join a network; you stand where certain
names are bright and read by name / write by emitting. *Peers are data too* —
a node publishes capability/observation as named signed Data (`/can-serve/…`,
reception/spectrum reports), never "I am device X."

**The conservation law** (the unifying principle, and the one already half-real):
*transmit if it adds innovation toward demand.* Energy ∝ rank delivered ∝ demand
present. — This is the strongest idea in the brainstorm and it is **already the
suppress predicate in `policy.rs::decide`**; "the field" is just the narrative
generalization of code that exists. Worth keeping as the north-star framing.

## Frontier mechanisms (each: idea · why compelling · depends on · honest tier)

### Name-keyed chirp waveform (semantic CSS)
- **Idea:** for the ambient sensor/embedded substrate, base on chirp spread spectrum
  (LoRa-class: constant-envelope, sub-GHz, self-syncing, drift-tolerant, MCU-demodable),
  but derive chirp params (SF, sub-band, slope) from the prefix hash so different
  content is quasi-orthogonal in signal space — FHSS-by-name generalized to the whole
  modulation parameter space. Frames dissolve into rateless RLNC-coded "innovation
  droplets" tagged `(name-hash, generation)`.
- **Why compelling:** content separates emitters with no coordinator; per-prefix
  privacy/jam-resistance; matches the sensor beneficiary.
- **Depends on:** SDR (testbed), the RLNC substrate.
- **Tier:** near-frontier waveform R&D. ⚑ Flag: "collisions recovered by macrodiversity
  not retransmit" needs a real capture-effect/interference analysis before it's more
  than a hope at scale.

### Three-layer naming on air
- **Idea:** Layer 0 *listen-by-signal-space* (zero bytes — interest = where you tune,
  because chirp params are name-keyed); Layer 1 *match-by-hash* (truncated BLAKE3
  commitment per droplet, for PIT/CS match + hardware filtering, à la name-group MAC);
  Layer 2 *resolve-by-name* (full name rides the signed Data + low-rate manifests,
  never per-droplet).
- **Why compelling:** free where possible, compact where you must commit, full where
  you must verify; Layer 1 has a real analog already (`name_group_mac`).
- **Tier:** the hash/name layers are buildable on existing seams; Layer 0 depends on
  name-keyed chirp.

### Discovery without beacons
- **Idea:** silence by default; presence as a decaying side-effect of useful data
  (generalize A-LAL); content-scoped listening replaces capability advertising; one
  thin **SVS-synced delta rendezvous** for cold-start (O(changes), not O(nodes×rate));
  IBLT/Bloom set-reconciliation gossip for ambient availability.
- **Why compelling:** directly attacks beacon-hell's root cause (overhead decoupled
  from demand). Mostly rides existing seams (SVS, A-LAL).
- **Tier:** the **most buildable** item here; arguably promotable to the backlog if/when
  ambient discovery becomes a priority.

### TSCH-by-name (deterministic real-time)
- **Idea:** keep 802.15.4e TSCH machinery but invert the host-centric parts: a **cell
  belongs to a name** (producer transmits in it, standing-Interest subscribers listen →
  deterministic multicast in one cell); the hop grid is name-keyed
  (`freq = HopSeq[(ASN + chanOffset + H(prefix)) mod nCh]`); the schedule is an
  SVS-synced named dataset, not Enhanced Beacons; sync rides traffic + a CCLF-elected
  `/localhop/time/anchor`; one slotframe carries both dedicated (real-time) and shared
  (ambient) cells; with MRMC the grid is 3-D (slot × radio × freq).
- **Why compelling:** turns the real-time gap into the deadline-class corner of the
  same field; reuses NDNPIPES (rails) + CCLF (election) + SVS (schedule).
- **Depends on:** tight time sync (the hard dependency real-time forces — GPSDO/PTP for
  the anchor); MRMC (done) for the 3-D grid.
- **Tier:** substantial system design; real-time is the whole separate regime.

### Real-time regime, generally
Push via persistent Interests (V-MAC-style) + unsolicited Data; systematic K=1–2 /
intra-packet FEC (first byte usable immediately); **selection** diversity (first clean
copy wins) not pooling; a fast waveform lane (GFSK/OFDM burst — trades the chirp's
range for speed: long-range and low-latency cannot share one emission); hard freshness
/ drop-if-late. — Note `NameContext.priority` (`Bulk/Normal/Urgent`) already exists as
the hook a latency class would extend.

### The capstone — one emission serving both deadline classes
A producer emits **systematic-then-coded**: leading systematic symbols are the
real-time copy (instant, first-clean-wins), trailing parity/rateless is the bulk copy
(macrodiversity-pooled). The *receiver's* deadline class — not the producer's — decides
which it takes. Real-time and delay-tolerant unified in one named flow. ⚑ Elegant;
unproven; the cleanest single idea to prototype once a fast lane exists.

### Far frontier (research-grade, flagged honestly)
- **LSH of hierarchical names → contiguous signal-space**, so subscribing to a prefix
  = tuning to a region. ⚑ "LSH on hierarchical names is genuinely hard, collisions
  need care" (the transcript's own caveat) — treat as a thesis question.
- **Demand-shaped propagation as physics** — popular data propagates farther because
  more nodes relay it. The publishable framing; needs the field to actually exist first.

## Anchor to reality

Every grand piece lands on something built: the field's *law* is the suppress
predicate (`policy.rs`); its *eyes* are the reception/spectrum reports (`control.rs`)
and a future SDR sensor; its *reconstruction* is macrodiversity (`AllocRole`); its
*reach across bands* is MRMC (`RadioCapability`); its *cooperation* is CCLF; its
*rails* when stability is worth it are NDNPIPES. The vision is "notice the built pieces
are facets of one object," not "start over." Build discovery + naming layers when they
earn priority; prototype semantic chirp on the SDR; keep the rest as the thesis.
