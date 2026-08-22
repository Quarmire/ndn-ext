# ndn-stream-session

Sans-IO **stream-session state engine** for NDN — the state a live named-data
stream needs on each side, with no transport attached:

| Module | Mechanism |
|---|---|
| `reorder` | seq-keyed reorder buffer: out-of-order arrivals deliver in order; duplicates/stale drop; gaps tracked, bounded (`max_span`), and explicitly skippable — a late reply can never shift the stream |
| `fetch` | adaptive windowed fetcher: RTT-EWMA (Karn's rule), additive-increase/halve-on-loss window, retry budgets → typed `GiveUp`, frontier-bound catch-up **and** predictive (reserve-ahead) live operation |
| `fec` | K-of-N repair groups over `ndn-coding`'s systematic MDS codec: any R losses per K-group recover from R parity items — strictly stronger than fixed XOR-one/GF256-two parity at equal overhead |
| `SessionConsumer` / `SessionProducer` | the composition + **session epochs**: a stream identity is (name, session); consumers lock to the highest session seen, so a restarted producer's stream never interleaves with its previous life |

Everything is clock-free (caller-supplied monotonic milliseconds) and
deterministic; binding to a transport (exact-name Interests, SVS,
`serve_latest`) is the caller's ~50 lines: name items `(stream, session, seq)`,
feed arrivals in, act on the `FetchAction`s out.

Witness highlights: `end_to_end_loss_recovered_by_fec_without_refetch` (a lost
item recovers from parity with no retransmission round-trip),
`session_reset_drops_old_state_and_relocks`,
`give_up_skips_the_hole_and_reports_loss` (loss is explicit, never a silent
permanent stall), `out_of_order_arrival_delivers_in_order` (the reorder-fetch
mechanism skyfall's NS-6 asked for).

## Attribution

Mechanism parity with (not a port of) the **NDN Service Framework**'s stream
substrate — its specs 057 ("core streaming substrate"), 089 ("stream parity"),
and 095 (FEC control): the generic stream state engine its UAV application
forced into that framework's core. Rebuilt sans-IO for the ndn-rs stack, with
FEC delegated to `ndn-coding` instead of bespoke XOR parity. See
`ndn-ext/ATTRIBUTION.md`.
