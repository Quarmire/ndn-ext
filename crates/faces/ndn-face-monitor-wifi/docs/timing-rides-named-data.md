# Timing rides named data — generalized hardware TX timestamping

*Design note under the [mac-addressing-doctrine](./mac-addressing-doctrine.md). The data-centric answer
to "where does the common-view clock come from" — companion to [time-slice-mac](./time-slice-mac.md)
(which consumes the clock) and [hardware-tsf-common-view](../../../../..) (task #41, the measurement that
motivated it). Task #74.*

## The reframing

Host-centric 802.11 has a special frame that carries time: the **beacon**. An AP's hardware writes its
TSF into the beacon's Timestamp field at the instant of transmission, and stations discipline to it. That
is the wrong shape for named-data radio twice over:

1. **It is infrastructure.** A beacon is an AP asserting "I am the timekeeper for this BSS." Monitor-mode
   named-data radio has no AP, no BSS, no managed hosts — depending on a beacon is depending on exactly
   the infrastructure the doctrine removes. (We measured a 0.26–1.15 µs common-view floor against a campus
   AP — but only as an *instrument* to prove the hardware RX path resolves µs; the AP is not a source we
   may build on. See [hardware-tsf-common-view](#).)
2. **It is a dedicated frame type.** Named-data radio does not send beacons; it sends **named data**. A
   separate timing frame is airtime spent on something other than content, and a control-plane object the
   doctrine would rather not have.

The data-centric move: **time is not a frame type, it is an attribute any transmission can carry.** If the
MAC stamps its TSF into *any* outgoing frame — not just a beacon — then **every named-data transmission is
a common-view timing reference for everyone who overhears it.** No dedicated beacon, no timekeeper role,
no announced schedule. The clock emerges from traffic, the way suppression and neighbour-RSSI already do.

## The mechanism: the TimeToken

A frame that opts into timing carries a **TimeToken**: an 8-byte field at a fixed offset that the
**hardware overwrites with the local TSF at the moment of transmission** (not at build time — that is the
whole point; build-time software stamping is TX-latency-bound at ~ms, which is why the software
`TimeBeacon` tops out there). A receiver latches the frame's arrival with its own hardware RX TSF
(`RXTSFL`, already in `CapturedFrame.stamp`). The pair

```
(transmitter's TX TSF from the TimeToken,  our RX TSF at arrival)
```

are two hardware clock reads of **one shared on-air event**. Differencing them cancels the transmitter's
TX latency and the propagation delay (~ns), leaving the offset between the two nodes' clocks at the
RX-stamp floor (~µs). This is GPS-common-view, re-keyed to content: the shared event is not a satellite
or an AP beacon but *a neighbour's data frame*.

## Why this is doctrine-clean

- **No host identity.** The TimeToken is a *clock reading*, not a name or an address. It says "my TSF was
  X when this left the antenna" — nothing about who "I" am. The transmitter is still keyed only by its
  ephemeral §2 nonce.
- **Soft-state (§7).** The receiver's model of a neighbour's clock is a learned affine map (offset +
  skew), recomputable from the next few frames. Lose it — or let the §2 nonce rotate (every 5 min) — and
  it re-learns from the next frames with **no time jump** (the node's underlying TSF is continuous across
  a nonce rotation; only the *key* changes). A dropped map costs a few frames of re-convergence, never a
  wedged state.
- **Computed, not announced.** Nothing is negotiated. The hardware stamps; the receiver reads. Two nodes
  that never exchanged a control message agree on each other's clocks by overhearing each other's data.
- **One overhear, four jobs.** A single received frame is now: (a) the named **data**, (b) a **CCLF**
  suppression signal (the content was served), (c) a **nonce-keyed RSSI** sample (§2 neighbour map), and
  (d) a **common-view time** observation. That fusion is the point — timing costs zero extra airtime
  because it rides the traffic already flowing.

## The receive side: per-source clock maps, fused

Each TimeToken-bearing frame yields a cross-domain observation. It feeds `ndn_time::DomainMap` — a
streaming affine estimator `observe(peer_raw, our_raw)` that learns a neighbour's clock↔ours mapping with
frequency **skew** and a **residual** (= the live precision), keyed on the source nonce:

```
per-neighbour:  DomainMap { source: peer_TSF_domain, target: our_TSF_domain }
                .observe(tx_token_tsf, rx_stamp.raw)   // every overheard frame
```

A node hears TimeTokens from *many* transmitters, so it holds a small set of per-neighbour maps. From
there the existing time stack takes over: `election` picks a reference (or the demand-adaptive slot owner
doubles as it), `discipline`/`combine` fuse multiple neighbours (Marzullo) for robustness, and the
`time-slice-mac` reads the resulting disciplined clock for `epoch(t)`. The `CommonViewPool`
(inter-receiver offsets) is the multi-hop generalization: two nodes that both overhear a third's frame
learn *their own* mutual offset from it, even out of each other's range.

## The type seam

- `CapturedFrame.stamp: Option<LinkStamp>` — **our** RX hardware latch (our domain). *Exists.*
- `CapturedFrame.tx_stamp: Option<LinkStamp>` — the **transmitter's** TX TSF from the TimeToken (their
  domain, keyed on the source nonce). *Added by #74.* `None` for a frame with no TimeToken (the default;
  timing is opt-in per frame so it costs nothing when unwanted).
- The pair is a `DomainMap` observation. Nothing else in the data path changes; a frame without a
  TimeToken flows exactly as before.

## Hardware realization (RTL8822E / 88xx, our userspace driver)

**The honest silicon boundary (#74 register survey).** On the RTL8822E — and the 8812au/8821c/8733b
family — the MAC has exactly **one** mechanism to write its TSF into an outgoing frame: the **beacon
engine**. A frame transmitted from the **beacon queue** (`QSEL = 0x10`) with `REG_BCN_CTRL (0x0550)`
bit 3 `EN_BCN_FUNCTION = 1` and bit 4 `DIS_TSF_UDT = 0` gets its body **bytes 24–31** (the first 8 bytes
after the 24-byte MAC header — the 802.11 beacon Timestamp slot) overwritten with the live 64-bit TSF at
the instant of transmission. The driver already *proves* this hardware is active by default: it explicitly
sets `DIS_TSF_UDT` while downloading reserved pages (`download_firmware`, `libusb_rtl88xx.rs:1398`) so the
page bytes are *not* clobbered, and it harvests other nodes' beacon-body TSF the same way (the #41 RX side
channel). `EN_BCN_FUNCTION` is left on in `init_edca_cfg:2110`, so the TSF free-runs.

**So the full "any data frame carries a TimeToken" is NOT reachable on this silicon.** There is no
per-descriptor "insert TSF" bit (`build_tx_body` sets no such field, and `EN_HWSEQ` is deliberately left
clear); and the only per-frame TX-time feedback, a **C2H TX report with TXTSFL**, is *not implemented*
(only `WLAN_TXQ_RPT_EN` at `0x0421` is set; C2H frames are detected and dropped at `:5007`) and it is
unknown whether this firmware even reports a TSF. Two honest routes to true per-frame stamping exist, both
out of scope here: (a) **different silicon** with a TX-descriptor timestamp-insert bit; (b) implement the
**C2H-TXTSFL** path — set `SPE_RPT` + a packet id in the descriptor, decode the dropped C2H reports, and
carry "my last frame aired at TSF X" in a follow-up named frame (PTP-follow-up style, itself named data).

**What IS reachable, and is doctrine-clean: an ON-DEMAND, software-triggered single stamped frame — never
a periodic hardware beacon.** A fixed-interval beacon timer is host-centric (an AP announces on a schedule
regardless of need) and spends airtime when no one is listening. Instead we drive the beacon engine in its
**software-beacon** mode (`ENSWBCN`, `REG_CR+1 0x0101` bit 0) as a **one-shot**: the node emits a single
hardware-stamped timing frame *when it decides one is useful* — piggybacked with a data burst it is
sending anyway, at a slot boundary the scheduler is about to use, or when a neighbour signals it needs to
sync. Demand-driven, under full software control, zero airtime when idle — the same rule as every other
named-data transmission. It is a *beacon* only in the 802.11-framing sense; semantically it is the node's
on-demand named-data timing emission, our content, our ephemeral-nonce BSSID, no AP. The generalization
survives on the two sides we control:

- **RX generalizes fully.** A receiver extracts the TimeToken → `CapturedFrame.tx_stamp` from *any* frame
  carrying it at the known offset, not only `FC == 0x80` — so the moment silicon (or the C2H path) can
  stamp data frames, the receive pipeline already common-views them. The per-source `DomainMap` fusion is
  frame-type-agnostic.
- **The abstraction generalizes fully.** `tx_stamp` + `DomainMap` + nonce-keying are the model; the
  beacon engine is merely the one *emitter* this chip offers. A node on better silicon drops in a
  per-frame emitter with no change above the driver.

**Registers for the emitter:** `REG_MBSSID_BCN_SPACE (0x0554)` = beacon interval (TU); `REG_BCN_CTRL
(0x0550)` = `EN_BCN_FUNCTION` set, `DIS_TSF_UDT` clear; load the frame to the beacon reserved page via the
existing `dl_rsvd_page` (`ENSWBCN` + `REG_FIFOPAGE_CTRL_2 0x0204` + poll `BCN_VALID 0x8000`). Place the
TimeToken at body offset 24 (bytes 24–31) so the hardware writes it.

## Status (#74, 2026-07-28) — SELF-CONTAINED µs, PROVEN ON AIR

- **The self-contained µs clock source works, no AP.** o5p-0 armed a timing beacon on our own BSSID
  (`02:4e:44:4e:ca:fe`); o5p-1's `beacon_cv` received it at **0.52 µs** first-diff jitter (2 µs spread) —
  our own node is a sub-µs common-view reference for its neighbours, with zero infrastructure. This is
  the ms→µs jump the software beacon could not make.
- **The fix (rtw88/rtl8xxxu sequence).** The beacon *loaded* (BCN_VALID) all along; it did not *air*
  because `emit_timing_frame` never armed the beacon queue for TBTT DMA — and in fact cleared the arm
  bit. Three corrections: (1) **SET `EN_BCNQ_DL`** (`REG_FWHW_TXQ_CTRL 0x0422` bit6) — the "make it fire"
  arm (`rtw_core_enable_beacon`); (2) **load to `RSVD_BOUNDARY` (1946)**, where the beacon queue DMAs
  from post-init, not page 0; (3) `REG_BCN_CTRL = EN_BCN_FUNCTION | DIS_TSF_UDT` (both) — and the
  TX-Timestamp insertion is a *separate always-on* HW function, so `DIS_TSF_UDT` set is correct and still
  stamps.
- **On-demand = arm/disarm WINDOW, not per-frame single-shot.** `emit_timing_frame` arms;
  `stop_timing_beacon` (clears `EN_BCNQ_DL`) closes. A node beacons only while it has armed a window —
  demand-driven, never a blind free-running beacon. A *single-frame* pulse (rapid arm→one→disarm) does
  NOT work on this silicon (measured): the beacon engine must stay stably armed across a couple of TBTTs
  to fire (the BCNDMATIM/DRVERLYINT prep pipeline + TSF-phase settling), so the controllable unit is the
  window (≥ a few TBTTs), not one frame. Within a window the MAC re-stamps + re-airs at TBTT.
- **Hardware truth (unchanged):** insertion is beacon-engine only on the 8822E — "any data frame carries
  a TimeToken" needs different silicon or the C2H-TXTSFL path; the RX side + `DomainMap` abstraction
  generalize regardless.
- **Still open:** wire `tx_stamp` on `CapturedFrame` + generalize the RX side channel beyond `FC==0x80`
  so *any* TimeToken-bearing frame feeds the per-source `DomainMap` (the abstraction is ready); feed the
  disciplined clock from our own neighbour beacons into the scheduler's `cv` mode (replacing the AP
  instrument). **Do not** key the per-source clock map on anything but the ephemeral nonce.
