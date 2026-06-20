# ndn-nacabe

A Rust port of the **NAC-ABE** protocol — Named-data Access Control with
Attribute-Based Encryption — for ndn-rs. It distributes attribute keys and
encrypts content so that only holders of a satisfying ABE key can read it, all
over named, signed NDN Data.

The core is the **content-key (CK) indirection**: content is encrypted with a
fresh symmetric content key (ChaCha20-Poly1305), and that CK is ABE-wrapped under
a set of attributes. A consumer who holds an ABE key whose policy is satisfied by
those attributes unwraps the CK and decrypts the content. This keeps the
expensive ABE operation on a small key, not the payload.

## What's here

| Module | Surface |
|---|---|
| `authority` | `KpAuthority` / `CpAuthority` — attribute authorities holding the ABE master secret + a per-identity grant table. `issue_dkey` (table-backed) and `issue_with_policy` (explicit policy) issue a decryption key sealed to the requester's ephemeral X25519 key. `open_kp_dkey` / `open_cp_dkey` open it. |
| `ckdata` | the CK-indirection: `seal_kp` / `open_kp` (KP-ABE) and `seal_cp` / `open_cp` (CP-ABE) — seal/open content under attributes, plus the `CkData` container and `NacError`. |
| `names` | the `PUBPARAMS` / `DKEY` / `CK` / `ENC-BY` name conventions. |
| `service` | the over-NDN shell (feature `service`): `serve_cp` / `serve_kp` run an authority that serves `PUBPARAMS` and answers validated `DKEY` requests; `ParamFetcher` is the consumer side (fetch + verify params, obtain a sealed key), with a `ValidationFailureHook` (NSF-F1) and `tracing` of failures (NSF-F2). |

Supported schemes: **KP-ABE** (key-policy; the NDNSF `ServiceController` model —
the key carries the policy, the ciphertext carries attributes) and **CP-ABE**
(ciphertext-policy). The sans-IO crypto/CK core is light enough for
embedded/wasm consumers; the over-NDN `service` surface is opt-in.

## Example

A *premium* weather report sealed under an attribute — only a subscriber the
authority issued a satisfying key to can read it:

```bash
cargo run -p ndn-nacabe --example premium_forecast
```

### Walkthrough: `examples/premium_forecast.rs`

The three NAC-ABE moves. First, the **authority** holds the master keys and enrolls
subscribers with key-policies (what attributes each subscriber's key satisfies):

```rust
let (mp, ms) = lsw_setup()?;                    // KP-ABE master keys
let mut authority = KpAuthority::new(mp.clone(), ms);
authority.grant("/sub/alice".parse()?, PolicyExpr::parse("tier:premium OR tier:pro")?);
authority.grant("/sub/bob".parse()?,   PolicyExpr::parse("tier:free")?);
```

A **publisher** seals content under attributes — the content-key (CK) indirection:
a fresh content key encrypts the text, and the CK is ABE-wrapped under the
attributes:

```rust
let kgc = ("/wx/authority".parse()?, Hash::of(&mp.public_key_bytes), mp);
let (ck, ct) = seal_kp(
    "/wx/CK/1".parse()?,
    &["tier:premium".to_string()],              // the attribute the reader must satisfy
    &kgc,
    b"Premium: clear skies, high 31C, low 22C",
    b"/wx/premium/2026-06-19",                  // AAD
)?;
```

A **subscriber** gets its key sealed to a fresh X25519 recipient (the over-the-wire
DKEY delivery), opens it, and decrypts — if its policy satisfies the attribute:

```rust
let recipient = Recipient::generate()?;
let sealed = authority.issue_dkey(&"/sub/alice".parse()?, &recipient.public)?;
let alice_key = open_kp_dkey(recipient, &sealed)?;          // alice's KP-ABE key

let plain = open_kp(&ck, &alice_key, &ct, aad)?;            // alice (premium) -> ok
// bob's key is `tier:free`; open_kp(&ck, &bob_key, &ct, aad) returns Err — fail closed
```

Output:

```
publisher sealed a premium forecast under attribute `tier:premium`
alice (premium) reads: Premium: clear skies, high 31C, low 22C
bob (free) is denied — the attribute policy is not satisfied
```

This is the same "premium channel" idea as the `ndn-service` example, one layer
down: there a `ScopedSession` gates a feed with a *symmetric* scope key; here the
gate is a *KP-ABE attribute* and a per-subscriber issued key (which is how
ABE-by-role distribution hands scope keys out in the v2 layer).

## Use with the service layer

`ndn-nacabe` backs the confidentiality of both the compat and v2 service layers:
`ndn-ndnsf::access` NAC-seals four-phase responses under service attributes, and
`ndn-service` uses it for the policy→issuance loop and ABE-by-role scope-key
distribution. See `docs/specs/service-layer.md` §6.

## Acknowledgements

This crate is a port of the **NAC-ABE** library (Named-data Access Control with
ABE), a C++ project on `ndn-cxx` from the **Named Data Networking** community; the
CK-indirection design and the access-control protocol are theirs. The ABE
cryptography is provided by the [`rabe`](https://github.com/Fraunhofer-AISEC/rabe)
Rust crate; the schemes are **LSW** KP-ABE (Lewko–Sahai–Waters) and **BSW** CP-ABE
(Bethencourt–Sahai–Waters). Sealed-box key delivery uses X25519
(`ndn-sealed-box`). Our thanks to the NAC-ABE authors, the `rabe` authors, and the
NDN project. This is an independent reimplementation, not affiliated with or
endorsed by the original projects.
