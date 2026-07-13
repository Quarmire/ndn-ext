//! Faithful NDN Service Framework (NDNSF) compatibility layer.
//!
//! NDNSF is a four-phase service-RPC framework: a user publishes a `REQUEST`
//! into an SVS group, providers `ACK`, the user `SELECTION`s one, and the
//! selected provider sends a `RESPONSE`. This crate reimplements that protocol
//! faithfully on the ndn-rs substrate — `ndn-sync` (SVS), `ndn-nacabe` (the NAC
//! key distribution + KP-ABE `ServiceController`), and `ndn-rpc` — so an ndn-rs
//! node interoperates with a C++ NDNSF node at the protocol level (the ABE
//! *ciphertext bytes* excepted; see `docs/specs/service-layer.md` §7.3).
//!
//! Held to NDNSF's audited security properties via the O4 invariant catalogue
//! (`docs/specs/ndnsf-invariants.md`).
//!
//! ## Layout
//!
//! - [`tokens`] — provider-token lifecycle + pending-state machine (O4
//!   token/state invariants NSF-T1/T3/T4/T5/T6, NSF-S1–S5).
//! - [`names`] — the V2 four-phase name builders.
//! - [`messages`] — the message TLV taxonomy (Request/Ack/Selection/Response,
//!   type numbers 128–131) + [`Strategy`]/[`RequestMode`].
//! - [`flow`] — the sans-IO orchestration ([`ProviderEngine`]).
//! - `driver` — the four-phase flow over `ndn-sync` SVS pub/sub (feature
//!   `driver`).
//! - `roles` — ergonomic `ServiceProvider`/`ServiceUser` wrappers over the
//!   driver (spec §11.2 mode 1).
//! - `trust` / `access` — per-message trust (`TrustCtx`, NSF-A3 trust half)
//!   and KP-ABE access control (NSF-A3 authorization).
//! - `policy` — TOML/`PolicyBuilder` → `ndn-nacabe` `KpAuthority` grants.

#![deny(missing_docs)]

#[cfg(feature = "driver")]
pub mod access;
#[cfg(feature = "driver")]
pub mod carrier;
#[cfg(feature = "driver")]
pub mod driver;
#[cfg(feature = "engine")]
pub mod engine;
pub mod flow;
pub mod messages;
pub mod names;
#[cfg(feature = "driver")]
pub mod policy;
#[cfg(feature = "driver")]
pub mod roles;
pub mod tokens;
#[cfg(feature = "driver")]
pub mod trust;

pub use flow::{FlowError, ProviderEngine, make_request, make_selection};
pub use messages::{
    AckMessage, MsgError, RequestMessage, RequestMode, ResponseMessage, SelectionMessage, Strategy,
};
pub use tokens::{PendingCoordination, PendingProviderTokens, ProviderToken, TokenError};

#[cfg(feature = "driver")]
pub use carrier::NdnsfCarrier;
#[cfg(feature = "driver")]
pub use policy::{ProviderAuthorizer, ServicePolicy};
#[cfg(feature = "engine")]
pub use engine::over_face;
#[cfg(feature = "driver")]
pub use roles::{ServiceNode, ServiceProvider, ServiceUser};
#[cfg(feature = "driver")]
pub use trust::TrustCtx;
