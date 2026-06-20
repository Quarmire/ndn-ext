# ndn-service-core

The foundation of the ndn-rs service layer: the **contract ⇄ carrier seam** plus
the portable message layer every service crate shares. One crate, **two scales** —
a full node (`std`) and a constrained leaf (`default-features = false`).

## What's here

| Surface | Feature | `no_std`? |
|---|---|---|
| `Frame` / `framing` — typed message ⇄ wire framing (evolvable TLV) | always | ✅ |
| `ServiceError`, `ServiceId`, `OpId`, `Invocation`, `Response` — the vocabulary | always | ✅ |
| `publish::Publisher` / `PublicationSink` / `Publication` — the embedded leaf producer | always | ✅ |
| `publish::ScopeKey` — symmetric ChaCha20-Poly1305 confidentiality | `seal` | ✅ |
| `Carrier` / `Dispatch` / `SelectCarrier` / `HintedCarrier` — the pluggable carrier seam | `std` (default) | — |
| `ScriptDispatch` — the untyped op→`bytes→bytes` seam (PyO3 / boltffi) | `std` (default) | — |

The async carrier traits and `ScriptDispatch` need the default `std` feature (they
assume an executor and a hash map). With `default-features = false` the crate is
`no_std + alloc` and exposes only the portable message layer + the leaf producer.

## Two scales

**Full node** — the seam the macro generates against and the carriers implement
(`ndn-rpc`, `ndn-ndnsf`, `ndn-service`). One `#[ndn_service]` definition runs over
any `Carrier` unchanged. See [`ndn-service`](../ndn-service) and the
service-layer spec (`docs/specs/service-layer.md` §12).

**Constrained leaf** — `ndn_service_core::publish` is the lightest NDN producer
surface: frame a typed value, name it `<topic>/seq=N`, (optionally) seal it with a
symmetric scope key, and emit it through a `PublicationSink`. No runtime, no sync
engine, no `std`. The role split (heavy machinery on the gateway, symmetric keys on
the leaf; `docs/specs/service-layer.md` §6, §13) is what makes a sensor's job this
small.

```bash
# the leaf producer, on the host (watch the bytes):
cargo run -p ndn-service-core --example embedded_sensor --features seal

# the SAME producer, cross-compiled for a Cortex-M4F MCU (STM32F4 / nRF52):
cargo build -p ndn-service-core --no-default-features --features seal \
    --target thumbv7em-none-eabihf
```

### Walkthrough: `examples/embedded_sensor.rs`

A typed reading frames with the same `#[derive(Frame)]` the rest of the stack uses
(proc-macros run on the host, so the derive serves `no_std` leaves too):

```rust
#[derive(Frame, Clone, Debug, PartialEq)]
struct Reading { decicelsius: i32, humidity_pct: u32 }   // integer fields — no FPU

// A typed, append-only feed. `publish` frames → names <topic>/seq=N → emits.
let mut sensor = Publisher::<Reading>::new("/sensor/lab-3/temp".parse()?);
sensor.publish(&Reading { decicelsius: 213, humidity_pct: 41 }, &mut radio)?;

// A gateway picks publications off the air and decodes with the SAME Frame type.
let reading = Reading::decode(&publication.payload)?;
```

Confidential publishing is a one-line change — a `ScopeKey` the gateway handed down
(it ran the ABE-by-role / sealed-box distribution; the leaf just holds the key):

```rust
let key = ScopeKey::from_bytes(scope_key_bytes);          // delivered out of band
let mut secure = Publisher::<Reading>::sealed("/sensor/lab-3/secure".parse()?, key.clone());
secure.publish(&reading, &mut radio)?;                    // payload is now AEAD ciphertext
let aad = sealed.name.encode_to_tlv();                    // the leaf bound the name as AAD
let opened = key.open(&aad, &sealed.payload).unwrap();    // a member gateway reads it
```

The sealed payload is byte-aligned with `ndn-security`'s `ContentKey`
(`nonce ‖ tag ‖ ciphertext`), so a capable node opens a leaf's publication directly
with `Sealed::from_bytes` + `ContentKey::open` — proven bidirectionally in
[`ndn-service/tests/leaf_seal_interop.rs`](../ndn-service/tests/leaf_seal_interop.rs).

Output:

```
== leaf publishes a typed feed: /sensor/lab-3/temp/seq=N ==
    on air: /sensor/lab-3/temp/seq=0  (16 payload bytes)
  gateway decodes the feed:
    /sensor/lab-3/temp/seq=0 -> 21.3 °C, 41% RH
== leaf publishes a CONFIDENTIAL feed (symmetric scope key) ==
    on air: /sensor/lab-3/secure/seq=0  (44 payload bytes)
  member gateway (has key) reads: 22.1 °C, 39% RH
  outsider (wrong key) is denied — AEAD authentication fails
```

## Embedded support — honest boundaries

- **ARM bare metal (`thumbv7em-none-eabihf`): clean.** The producer + `seal` + the
  whole chain (`ndn-packet`, `ndn-crypto-core`, `chacha20poly1305`) compile with no
  `std`.
- **ESP32-C3 (`riscv32imc`): one firmware-level flag.** The chip has no hardware
  atomic CAS, so `bytes` (via `portable-atomic`) needs a single-core CAS polyfill —
  a `critical-section` impl the firmware crate (esp-hal) supplies, standard for
  every `no_std` crate on that target. Our code, `ndn-packet`, and `ndn-crypto-core`
  all compile for it; `bytes` is the gate.
- The `ScopeKey` seal envelope is byte-aligned with `ndn-security`'s `ContentKey`
  (`nonce ‖ tag ‖ ciphertext`, name bound as AAD), so leaf seals and native opens
  interoperate both directions (`leaf_seal_interop.rs`). The only leaf-specific
  choice is nonce *derivation* (sequence, not RNG), which the wire format is
  agnostic to.

See `docs/specs/service-layer.md` §12 (the seam) and §13 (the embedded leaf).
