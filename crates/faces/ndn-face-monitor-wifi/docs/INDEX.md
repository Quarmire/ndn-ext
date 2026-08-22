# ndn-face-monitor-wifi docs — INDEX

*Reading order and status ledger for this directory — the named-data-radio doctrine, the four MAC
facet chapters, and the campaign record — plus the sibling design docs in
`../../ndn-face-wifi-aware/docs/`.*

Statuses used below:

- **CURRENT** — the live reference for its topic.
- **SUPERSEDED-BY \<file\>** — read the successor instead; kept for the record.
- **HISTORICAL-RESULTS** — a dated record (preregistration, measured outcome, bring-up); correct as
  of its date, not maintained afterwards.
- **DATA** — evidence artifact (CSV/trace, validation page, harness script) backing a doc above it.

## Tracked vs. untracked, in one sentence

`docs/.gitignore` ignores everything here by default (`*`) and allowlists only the doctrine set, but
that allowlist is no longer the tracked set: today git tracks 37 paths in this directory (this index
included) — the doctrine files plus the later force-added facet chapters, synthesis, wire-format
spec, preregistrations, results, validation pages, harness script, and name-filter data — while
exactly five bring-up notes (`AMPDU_PORT_SCOPE.md`, `esp-now-c5-dual-band-2026-06-17.md`,
`radio-cognition-frontier-backlog.md`, `radio-cognition-reconciliation-2026-06-17.md`,
`rtl8821cu-port-reference.md`) remain untracked staging, present only on the bring-up machine.

## The three generations of radio design docs

1. **2026-07-16, `../../ndn-face-wifi-aware/docs/`** — the NAN expansion:
   [`NAMED_RADIO_EXPANSION_DESIGN.md`](../../ndn-face-wifi-aware/docs/NAMED_RADIO_EXPANSION_DESIGN.md)
   (the phased plan; phases 0–2 shipped) and
   [`NAMED_RADIO_COURSE_CORRECTION.md`](../../ndn-face-wifi-aware/docs/NAMED_RADIO_COURSE_CORRECTION.md)
   (the finding that Phase 2's NDP data path is a host-centric regression, demoted to an interop
   bearer). **The correction supersedes the expansion design's Phase-2 decision** — the expansion
   doc's own §0 status header names the correction as the authority, and `named-radio.md` defers to
   it "where the two disagree".
2. **2026-07-17, `RADIO_SUBSYSTEM.md`** — the subsystem architecture (crates, seams, backends,
   device details). Still the architecture reference; it predates the MAC facet chapters and does
   not cover them.
3. **2026-08, the MAC design generation** — `named-radio-primer.md` (08-18), the four facet
   chapters (08-14 … 08-17), `mac-synthesis.md`, and `wire-format-spec.md`. This is the current
   design-of-record for the MAC itself.

## Reading order

Start at the top; each step assumes the ones above it.

1. [`named-radio-primer.md`](named-radio-primer.md) — the ten-minute, jargon-free on-ramp. Read
   this first; everything else assumes its picture.
2. [`named-radio.md`](named-radio.md) — the doctrine: a non-standard *extension* bearer, the name
   is the addressing, no association/MAC/ARQ.
3. [`mac-addressing-doctrine.md`](mac-addressing-doctrine.md) — the decided rules for the 802.11
   address fields (its addressing half since superseded — see the table).
4. [`mac-design-roots.md`](mac-design-roots.md) — each MAC problem traced to its originating
   commitment, with citations, so you can verify the problems are real.
5. The four facet chapters: [`name-filter-chapter.md`](name-filter-chapter.md) (*who/what*),
   [`temporal-access-chapter.md`](temporal-access-chapter.md) (*when*),
   [`spectrum-multiradio-chapter.md`](spectrum-multiradio-chapter.md) (*where / with what*),
   [`link-adaptation-chapter.md`](link-adaptation-chapter.md) (*how well*).
6. [`mac-synthesis.md`](mac-synthesis.md) — the four facets argued as one protocol, with the
   on-air-vs-sim ledger.
7. [`wire-format-spec.md`](wire-format-spec.md) — the normative byte-level on-air contract for a
   second implementation.
8. [`RADIO_SUBSYSTEM.md`](RADIO_SUBSYSTEM.md) — the crate/driver architecture underneath it all:
   the `FrameIo` / `RadioKnobs` seams, the backend recipe, the per-chip details.

Then the design notes, campaign record, and sibling docs as needed (tables below).

## Inventory

### Doctrine & entry points (tracked)

| file | status | one line |
|---|---|---|
| [`named-radio-primer.md`](named-radio-primer.md) | CURRENT | Jargon-free primer: the name answers *who/when/where/how-carefully*; read first (2026-08-18). |
| [`named-radio.md`](named-radio.md) | CURRENT | The doctrine doc: extension bearer over monitor-mode Wi-Fi; the COURSE_CORRECTION is authoritative where they disagree (2026-07-16). |
| [`named-radio-vision-frontier.md`](named-radio-vision-frontier.md) | CURRENT | Parked frontier ideas beyond the shipping doctrine (2026-07-16). |
| [`mac-addressing-doctrine.md`](mac-addressing-doctrine.md) | CURRENT (addressing half SUPERSEDED-BY `named-filter-mac-redesign.md`) | The 2026-07-17 decision on the 802.11 address fields; §4 remains the canonical CCLF definition. |
| [`RADIO_SUBSYSTEM.md`](RADIO_SUBSYSTEM.md) | CURRENT | Subsystem architecture: three crates (`ndn-radio-hal` contract, `ndn-radio-drivers` ports, this crate's face+seam), backend recipe, device details (2026-07-17; carries its own historical note on the crate split). |

### MAC design — current generation (tracked)

| file | status | one line |
|---|---|---|
| [`mac-design-roots.md`](mac-design-roots.md) | CURRENT | Traces the design and findings D1/D2/D3 to their originating commitments, with in-tree citations (2026-08-18). |
| [`name-filter-chapter.md`](name-filter-chapter.md) | CURRENT | Facet chapter, *who/what*: the Blurred Name prefix-set filter, validated in isolation (sim + one on-air point, #106). |
| [`temporal-access-chapter.md`](temporal-access-chapter.md) | CURRENT | Facet chapter, *when*: the named grant on a common-view clock; grant built and on-air, clock validated in depth. |
| [`spectrum-multiradio-chapter.md`](spectrum-multiradio-chapter.md) | CURRENT | Facet chapter, *where / with what*: named channel + multi-radio pool, unified; sim only, FHSS has no on-air validation. |
| [`link-adaptation-chapter.md`](link-adaptation-chapter.md) | CURRENT | Facet chapter, *how well*: per-name rate/FEC levers ranked by measured effect; mostly built and on air. |
| [`mac-synthesis.md`](mac-synthesis.md) | CURRENT | The four facets joined as one protocol; the honest on-air-vs-sim ledger. |
| [`wire-format-spec.md`](wire-format-spec.md) | CURRENT | Byte-level on-air wire-format spec transcribed from shipping code with `file:line` citations (2026-08-17). |

### Design notes the chapters grew from (tracked)

| file | status | one line |
|---|---|---|
| [`named-filter-mac-redesign.md`](named-filter-mac-redesign.md) | CURRENT | The Blurred Name redesign (prefix matching in the address bits); supersedes the addressing half of `mac-addressing-doctrine.md`; `name-filter-chapter.md` + `wire-format-spec.md` carry the validated/normative form. |
| [`named-token-scheduling.md`](named-token-scheduling.md) | CURRENT | Token-passing transformed into the named grant — the scheduling corollary of the doctrine. |
| [`time-slice-mac.md`](time-slice-mac.md) | CURRENT | The data-centric time-slice MAC — the temporal half of the scheduling story (task #61). |
| [`cclf-named-mac.md`](cclf-named-mac.md) | CURRENT | CCLF cooperative forwarding and variants under the doctrine; measured in `ndn-sim`. |
| [`timing-rides-named-data.md`](timing-rides-named-data.md) | CURRENT | Hardware TX timestamping as named data — where the common-view clock comes from (task #74). |

### Campaign record — preregistrations & results (tracked)

| file | status | one line |
|---|---|---|
| [`bench-harness-hygiene.md`](bench-harness-hygiene.md) | CURRENT | Pre-experiment checklist distilled from a 2-day false "hardware wedge" hunt; read before any multi-node on-air run. |
| [`p5-preregistration.md`](p5-preregistration.md) | HISTORICAL-RESULTS | P5 scheduler-campaign preregistration, committed before any run (2026-08-13). |
| [`p5-results.md`](p5-results.md) | HISTORICAL-RESULTS | P5 outcomes against the preregistered thresholds (claim A refuted by its own pre-named condition). |
| [`p5c-eswep-prereg.md`](p5c-eswep-prereg.md) | HISTORICAL-RESULTS | P5(c) preregistration: the #101 filter false-positive sweep over E (registered-prefix count). |
| [`p6-hidden-terminal-prereg.md`](p6-hidden-terminal-prereg.md) | HISTORICAL-RESULTS | Claim-C preregistration: reserved lanes under a *hidden* bulk holder (2026-08-13). |

### Evidence & tooling (tracked)

| file | status | one line |
|---|---|---|
| [`claim-c-harness.sh`](claim-c-harness.sh) | DATA | The claim-C three-node run harness, with its hard-won hygiene rules inline. |
| [`name-filter-validation.html`](name-filter-validation.html) | DATA | Validation page for `name-filter-chapter.md`. |
| [`temporal-access-clock-validation.html`](temporal-access-clock-validation.html) | DATA | Validation page for `temporal-access-chapter.md` (clock-phase gap). |
| [`spectrum-multiradio-validation.html`](spectrum-multiradio-validation.html) | DATA | Validation page for `spectrum-multiradio-chapter.md`. |
| [`link-adaptation-validation.html`](link-adaptation-validation.html) | DATA | Validation page for `link-adaptation-chapter.md`. |
| [`mac-synthesis-validation.html`](mac-synthesis-validation.html) | DATA | Validation page for `mac-synthesis.md`. |
| [`wire-format-validation.html`](wire-format-validation.html) | DATA | Rendered companion to `wire-format-spec.md`. |
| [`data/name-filter/`](data/name-filter/) | DATA | Recorded evidence for `name-filter-chapter.md`: `allocation.csv`, `depth.csv`, `id.csv`, `latency.csv`, `structure.csv`, `traces.ndjson`. |

### Untracked staging notes (bring-up machine only — not in a fresh clone)

| file | status | one line |
|---|---|---|
| `AMPDU_PORT_SCOPE.md` | HISTORICAL-RESULTS | MT7612U A-MPDU de-risk (179 Mb/s proven possible) and the scope/risk list; `RADIO_SUBSYSTEM.md` records the push declined on architectural grounds. |
| `esp-now-c5-dual-band-2026-06-17.md` | HISTORICAL-RESULTS | Dated bring-up: bidirectional NDN-over-ESP-NOW on 5 GHz with the dual-band ESP32-C5. |
| `radio-cognition-reconciliation-2026-06-17.md` | HISTORICAL-RESULTS | Dated reconciliation of a green-field brainstorm transcript against the code actually built. |
| `radio-cognition-frontier-backlog.md` | CURRENT | The genuinely-unbuilt radio-cognition backlog, ordered; eventual home `ndn-radio-cognition`. |
| `rtl8821cu-port-reference.md` | CURRENT | rtw88-derived reference for the userspace RTL8821CU port (register/init details, `file:line` cites). |

### Sibling docs — `../../ndn-face-wifi-aware/docs/`

| file | status | one line |
|---|---|---|
| [`NAMED_RADIO_COURSE_CORRECTION.md`](../../ndn-face-wifi-aware/docs/NAMED_RADIO_COURSE_CORRECTION.md) | CURRENT | The 2026-07-16 finding: NAN NDP is a host-centric regression, demoted to an interop bearer; authoritative where it and any older doc disagree. |
| [`NAMED_RADIO_EXPANSION_DESIGN.md`](../../ndn-face-wifi-aware/docs/NAMED_RADIO_EXPANSION_DESIGN.md) | SUPERSEDED-BY `NAMED_RADIO_COURSE_CORRECTION.md` | The NAN/BLE/embedded phase plan (phases 0–2 shipped, status table inline); its Phase-2 NDP-as-data-path decision is overturned by the correction, which its own §0 names as the authority. |
