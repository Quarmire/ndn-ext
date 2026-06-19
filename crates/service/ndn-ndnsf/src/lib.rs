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
//! ## Status
//!
//! This crate currently lands the **sans-IO core**:
//! - [`tokens`] — the provider-token lifecycle and pending-state machine, the
//!   coordination guard carrying the O4 token/state invariants (NSF-T1/T3/T4/T5/T6,
//!   NSF-S1–S5).
//! - [`names`] — the V2 four-phase name builders.
//!
//! Still to land: the message TLV taxonomy (Request/Ack/Selection/Response,
//! type numbers 128–131), and the four-phase flow over SVS pub/sub (the
//! `ServiceProvider`/`ServiceUser` roles), wiring `ndn-nacabe`'s KP-ABE
//! `ServiceController` for access control.

#![deny(missing_docs)]

#[cfg(feature = "driver")]
pub mod driver;
pub mod flow;
pub mod messages;
pub mod names;
pub mod tokens;

pub use flow::{FlowError, ProviderEngine, make_request, make_selection};
pub use messages::{AckMessage, MsgError, RequestMessage, ResponseMessage, SelectionMessage};
pub use tokens::{PendingCoordination, PendingProviderTokens, ProviderToken, TokenError};
