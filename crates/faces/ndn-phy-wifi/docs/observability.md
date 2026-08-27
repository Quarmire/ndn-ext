# NDR MAC observability — OpenTelemetry, organized by facet

The NDR stack is already **OpenTelemetry-native**: `tracing` spans are captured by
`ndn_observability::NdnObservabilityLayer`, serialized to **OTLP protobuf**, and published **as NDN Data**
under an observability prefix (`ndn-observability` is *OTLP-in-Data* — the traces travel on the same named
substrate as everything else). Traces are **stitched across the radio hop**: an outbound frame carries this
node's trace-id and an inbound frame adopts the peer's, so one trace spans multiple nodes
(`bind_global_trace_stitch`, `ndn-radio-node/src/main.rs`).

This doc maps that machinery to the four MAC facets (`GLOSSARY.md` §0) so a trace is **analyzable in the
canonical vocabulary**: what each facet decided, why, and where the time went.

## The pipeline (already installed)

```
tracing span/event (target "named_radio")
      │  NdnObservabilityLayer  (ratio_sampler, trace-id stitch)
      ▼
OTLP protobuf Span  ──published as──►  NDN Data under obs_prefix()
      │
      ▼  consumer Interests the trace by name (or the console mirror: RUST_LOG=named_radio=debug)
```

- Install: `SpanPublisher::new(obs_prefix(), …)` + `mount_observability(engine, publisher, cancel)`.
- Consume: Interest the observability prefix for OTLP spans, or set `RUST_LOG=named_radio=debug` for the
  human-readable console mirror. The trace-id links a decision on one node to its effect on another.

## The facet map — where each facet is observable

The cognition loop is a **span tree** (`RadioControl::tick`, `control.rs`); the per-frame MAC activity is
**counters** (spans would be too fine at ~kHz frame rates — metrics are the right tool there).

### Span tree (per cognition tick — the SENSE→DECIDE→ACT loop)
```
radio_tick { now_ms }
├─ sense                       (WHERE: occupancy_read per radio → channel_busy_pct)
├─ decide                      (the policy runs)
│  └─ decision { prefix, origin, demand, receivers, holders, deficit, broad, replicate }   ← the WHY (inputs)
│     └─ event "radio: decision"                                                            ← the WHAT (outputs)
│        WHERE:     channel
│        HOW-WELL:  mcs, bw, nss, ldpc, stbc, csd, he, dcm, er_su, tx_power, link_fec, edcca_ignore
│        meta:      radio, score, role, strategy, consistency, relay, objective
├─ refine { bandit }
└─ actuate → apply { radio, channel }
```
- **WHERE** = the `channel` field on the decision event + the `sense`/`occupancy_read` spans (busy_pct).
- **HOW-WELL** = the rate/reach fields on the decision event. The **reach levers** (`he`/`dcm`/`er_su`) are
  traced here (added for this — the reach escalation is now analyzable, not invisible). The `decision` span's
  input fields (`deficit`, `receivers`, `rssi_dbm`, `link_per`) are the *why* behind the chosen rate/reach.

### Counters (per-frame — the metric side)
- **WHEN** (the airtime lease): `FaceScheduler` `SchedStats` — `shared_slot_backoffs`, `claim_attempts`,
  `claim_wins`, `elections`, `elections_won`, `hold_continuations`, `ambient_rx`. **Emitted through OTLP**
  every ~1024 gated frames as a `named_radio::when` event (`slot lease: WHEN-facet counters`), so slot
  contention rides the same OTLP-in-Data stream as the decisions (and is also readable directly via
  `FaceScheduler::shared_slot_backoffs()` &c). *These quantify slot contention (co-owners), claimable-slot
  reclaim, and CCLF election cost.*
- **WHO** (the filter): Tier-0 admit/drop — on the C5/ath9k firmware as `ndr_stats` (`seen`, `passed`,
  `dropped_by_filter`) read pre-USB; host-side via the `NameGate`. *These quantify the §8.2 pre-USB drop win.*
- **timing**: the link-latency decomposition (`link-latency-decomposition.md`) — propagation (ns) / airtime
  (µs) / interconnect (ms). The `link_latency.py` tool is the measured signal; the ratio (radio % vs bridge
  %) is the headline metric.

## Example analyses

**"Why did `/alarm/…` go out at MCS0 + ER-SU + DCM?"** — find the `decision` span for that `prefix`; read the
HOW-WELL outputs (`mcs=0, he=true, er_su=true, dcm=true`) next to the inputs on the same span
(`deficit`, low `rssi_dbm`, `receivers`) — the reach-corner escalation (`he_cap && robust && weak`) is right
there. Cross-node: the peer's trace (stitched) shows what it *received* (its RX `mcs`/SNR from `PhyMetrics`).

**"Is this slot contended?"** — `elections` / `elections_won` and `shared_slot_backoffs` rising together mean
co-owners are turn-taking in one slot (the D1 pigeonhole); `claim_wins` rising means idle slots are being
reclaimed (healthy). Both are WHEN counters.

**"Where's the ping latency?"** — `link_latency.py`: if the radio % is ~1% and the interconnect % is ~99%,
the bridge is the bottleneck (not the MAC) — the #5 result.

## Gaps / follow-ons

- **Export the WHO (filter) counters through OTLP.** WHEN is now emitted (the sampled `named_radio::when`
  event); the WHO admit/drop counters (`ndr_stats` on-firmware, `NameGate` host-side) are still accessor-only
  — a companion sampled `named_radio::who` event would surface the §8.2 pre-USB drop win in the same stream.
- **A per-object end-to-end span** stitching the cognition decision → the frame's slot placement (WHEN) →
  the receiver's RX rate/SNR (HOW-WELL, other node) into one trace, so a delivered/lost object is a single
  analyzable timeline. The trace-id stitch already makes this possible; it needs the WHEN/RX legs emitted.
- **OTLP metrics (not just spans).** `ndn-observability` publishes spans today; the counters above are
  naturally OTLP *metrics* (sums/gauges). A metrics exporter over the same substrate is the next layer.
