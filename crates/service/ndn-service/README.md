# ndn-service

The **v2 service layer** for ndn-rs: an alternative to the faithful NDNSF compat
port ([`ndn-ndnsf`](../ndn-ndnsf)) that keeps what NDNSF got right and corrects
what it didn't, built on the shared service seam. Its defining move is
**authority-as-signed-Data** (an authority's decisions are signed, named,
cacheable Data objects, not the live state of a running daemon), which makes
policy *dynamic by construction*.

It is one part of a small stack:

| Crate | Role |
|---|---|
| [`ndn-service-core`](../ndn-service-core) | the seam: `Carrier` / `SelectCarrier` / `HintedCarrier` / `Dispatch` / `Frame`, the `ServiceId`/`OpId`/`Invocation`/`Response` vocabulary, and `ScriptDispatch` (the untyped scripting seam) |
| [`ndn-service-macro`](../ndn-service-macro) | `#[ndn_service]` (a typed trait → messages + dispatch + a carrier-generic client) and `#[derive(Frame)]` (structured request/response types) |
| [`ndn-rpc`](../ndn-rpc) | Tier-0: `RpcCarrier` (in-process) and `FaceRpcCarrier` (over a real forwarder, feature `engine`) |
| [`ndn-ndnsf`](../ndn-ndnsf) | the NDNSF four-phase carrier (compat) |
| **ndn-service** | the v2 layer below |

## What's here

**Authority & dynamic policy** (`docs/specs/service-layer.md` §4.4):

- `PolicyAuthority` — a scoped authority holding **versioned, signed** access
  grants; `grant` / `revoke` take effect on the live authority and bump a version
  (no restart). `signed_grant` emits the current signed object; `verify_grant`
  validates it (fail closed).
- `command` — the operator→authority input channel: signed
  `/<scope>/policy/{grant,revoke}` command Interests applied by a
  `PolicyController` (authorize first, then mutate).
- `config` (feature) — the declarative twin: load a TOML policy and `reload` it
  into a live authority (diff → grant/revoke).
- `issuance` (feature) — the policy→issuance loop: `issue_decryption_key` gates
  KP-ABE key issuance on the current grant, fail closed.

**Tier-1 discovery** (§3.2):

- `DiscoveryCarrier<C>` — discover the provider set via a `ProviderDirectory`,
  select, and invoke over an inner Tier-0 carrier; it *adds* `SelectCarrier` over a
  unary inner carrier. Both naming conventions (`NamingConvention::NodeScoped` and
  the data-centric `ForwardingHint`).
- `ServiceDiscoveryDirectory` (feature `discovery`) — the production directory over
  `ndn-discovery`'s `ServiceDiscoveryProtocol`.

**Tier-2 collaboration** (§3.3):

- `Topic<T>` — a typed pub/sub *feed* (distinct from a service op's *call*).
- `Session` / `ScopedTopic` — confidential typed topics sealed under a scope key.
- `ScopeKeyring` / `RoleScopePolicy` / `ScopedSession` — **role-scoped keys**: a
  role grants scopes, a member holds only its role's scope keys.
- key distribution — **`key_dist`** (sealed-box per member, simple) and
  **`abe_dist`** (ABE-by-role: scope keys ABE-wrapped per attribute, opened by a
  role-derived KP-ABE key — scalable, data-centric; feature `issuance`).
- `ArtifactShare` — named confidential objects provisioned/fetched in a session.

## Examples

The same weather domain, two ways — so the differences are visible side by side:

```bash
# v2: discovery-based reach (Tier-1), a typed feed (Topic<T>), and a
# confidential role-gated channel (ScopedSession + role-scoped keys).
cargo run -p ndn-service --example weather

# compat: the same #[ndn_service] call over Tier-0 and the NDNSF four-phase.
cargo run -p ndn-ndnsf --example weather --features driver
```

The Tier-0/NDNSF example is *call-only* (reach a known provider, or broadcast to a
group); the v2 example adds what those can't express — **discovering** the service,
a **feed** (publish/subscribe, not request/response), and a **confidential
channel** only members holding the scope key can read.

## Features

`discovery` (real `ServiceDiscoveryProtocol` directory), `issuance` (KP-ABE
issuance loop + ABE-by-role distribution), `config` (TOML policy reload). All off
by default to keep the core light.

## Acknowledgements

This layer builds on ideas from the **NDN Service Framework (NDNSF)** — which
[`ndn-ndnsf`](../ndn-ndnsf) ports faithfully and this crate improves on — and on
**NAC-ABE** for attribute-based confidentiality (via
[`ndn-nacabe`](../ndn-nacabe)). It is built on **Named Data Networking** concepts
throughout. See those crates' READMEs and `docs/specs/service-layer.md` for the
full design and acknowledgements.
