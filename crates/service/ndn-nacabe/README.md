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
