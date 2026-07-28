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

*(filled from the #74 silicon research — the register-level mechanism for making the MAC insert its TSF
into a transmitted frame, generalized beyond the beacon queue where the hardware allows, and the frame
layout that places the TimeToken where the hardware writes it.)*

## Status

- **Measured:** the RX common-view floor is sub-µs through our own driver (0.26–1.15 µs, both OPis, same
  reference) — the receive side is proven.
- **Building (#74):** the transmit side — hardware TSF insertion on our own frames, generalized to any
  frame per this note, so a self-contained mesh reaches µs common-view with no AP.
- **Do not** reintroduce a dedicated timekeeper node or a beacon-only timing frame if the hardware can
  stamp general frames; and **do not** key the per-source clock map on anything but the ephemeral nonce.
