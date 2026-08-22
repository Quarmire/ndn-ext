# ndn-lease

Fail-closed **execution leases** for NDN services, sans-IO: a provider-local
`LeaseTable` that is the *only* authority over its own capacity.

```
prepare ─▶ Prepared ─commit▶ Committed ─activate▶ Executing ─release▶ Released
              │abort             │abort                │
              ▼                  ▼                     ▼ (running work must release)
           Aborted            Aborted               Released
   any live state ── TTL ──▶ Expired
```

Properties (each carried by a unit witness):

- **Boot epochs** — every lease names the provider instance that issued it; a
  restarted provider answers old leases with a typed `StaleEpoch`/`Unknown`,
  never a silent grant. Lease state is memory-local by design.
- **Conflict keys** — exclusive resources (`"gpu0"`, `"model-q"`): a prepare
  overlapping any live lease's keys is refused; terminal states free them.
- **Idempotency replay** — the same idempotency key with the same plan digest
  returns the *same* lease (safe retry); a different digest is refused — a
  retry must not smuggle in different work.
- **Holder + plan binding** — only the prepared-for identity drives the lease,
  and activation revalidates the plan digest committed at prepare time.
- **Fail closed** — every refusal (including `TableFull` at the cap) changes
  nothing; there is no untracked-local fallback.
- **Clock-free** — the caller supplies monotonic seconds; the machine is
  deterministic and directly testable.

Tier-agnostic: nothing here knows about the four-phase, Tier-0, or any
transport. A carrier surfaces refusals in its own vocabulary — the NDNSF
carrier's natural mapping is the negative-ACK reasons `LEASE_REJECTED` /
`LEASE_EXPIRED` (`ndnsf_rs::messages::reason`).

## Attribution

The mechanism (not the wire) is ported from the **NDN Service Framework**'s
`ProviderExecutionLeaseTable` (its spec 085, "core boundary fail-closed
leases") — the execution-authority design its distributed-inference workload
forced into that framework's core — redesigned here for the tiered ndn-rs
service stack. See `ndn-ext/ATTRIBUTION.md`.
