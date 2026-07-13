//! NAC protocol over ndn-rs — Named-data Access Control key distribution.
//!
//! The "NAC protocol" (Sense 2 in `docs/specs/service-layer.md` §6) is the named
//! key-distribution scheme: an **attribute authority** publishes public
//! parameters and issues decryption keys over NDN, producers wrap a random
//! **content key** (CK) under ABE and publish it as a separately-named CK-data
//! object, and content is symmetric-sealed under the CK. This crate builds that
//! flow on the shared primitives — `ndn-security`'s ABE schemes (CP/KP/MA) and
//! content-key confidentiality — and is the layer the faithful NDNSF compat
//! (`ndnsf-rs`) sits on.
//!
//! Interop is protocol-level: the names ([`names`]) match the C++ NAC-ABE stack,
//! but the ABE ciphertext bytes do not interoperate (§7.3).
//!
//! ## Status
//!
//! This crate currently lands the **sans-IO core**: the [`CkData`] object
//! (named, ABE-wrapped content key) and the producer/consumer CK-data flow
//! ([`seal_cp`]/[`open_cp`], [`seal_kp`]/[`open_kp`]), plus the NAC naming
//! ([`names`]). The named exchanges over NDN — the attribute authority serving
//! `PUBPARAMS` and issuing `DKEY` (validating the requester's certificate and
//! wrapping the issued key to it), and the consumer-side `ParamFetcher` — layer
//! on top using `ndn-app`, and are gated by the NDNSF security invariants
//! catalogue (`docs/specs/ndnsf-invariants.md`, O4): the protocol-level
//! invariants (validate-before-decrypt, signer-matches-controller-path,
//! fail-callback-exactly-once) must have passing witnesses before they land.

#![deny(missing_docs)]

pub mod authority;
pub mod ckdata;
pub mod names;
#[cfg(feature = "service")]
pub mod service;

pub use authority::{CpAuthority, KpAuthority, open_cp_dkey, open_kp_dkey};
pub use ckdata::{CkData, NacError, open_cp, open_kp, seal_cp, seal_kp};
#[cfg(feature = "service")]
pub use service::{IssueFn, ParamFetcher, ValidationFailureHook, serve_cp, serve_kp};
