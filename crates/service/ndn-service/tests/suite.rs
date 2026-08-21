//! Single consolidated integration-test binary (P1 compile-cost work).
//!
//! `autotests = false` in Cargo.toml routes every `tests/*.rs` file through
//! this one `[[test]]` target, so the crate links ONE test binary instead of
//! fifteen. The per-topic files stay in place as modules; add a new
//! `#[path]` line here when adding a test file.
//!
//! Feature gating is unchanged: the `issuance`/`discovery`/`config` modules
//! keep their `#![cfg(feature = ...)]` inner attributes, mirrored on the
//! `mod` lines below, so those tests still compile only when the matching
//! feature is enabled.

#[cfg(feature = "issuance")]
#[path = "abe_role_keys.rs"]
mod abe_role_keys;
#[path = "artifacts.rs"]
mod artifacts;
#[cfg(feature = "config")]
#[path = "config_reload.rs"]
mod config_reload;
#[cfg(feature = "discovery")]
#[path = "cross_node_discovery.rs"]
mod cross_node_discovery;
#[path = "discovery_carrier.rs"]
mod discovery_carrier;
#[path = "dynamic_policy.rs"]
mod dynamic_policy;
#[cfg(feature = "discovery")]
#[path = "forwarding_hint_convention.rs"]
mod forwarding_hint_convention;
#[cfg(feature = "issuance")]
#[path = "issuance_loop.rs"]
mod issuance_loop;
#[path = "key_distribution.rs"]
mod key_distribution;
#[path = "leaf_seal_interop.rs"]
mod leaf_seal_interop;
#[path = "role_scoped_keys.rs"]
mod role_scoped_keys;
#[cfg(feature = "discovery")]
#[path = "sd_directory.rs"]
mod sd_directory;
#[path = "session_collab.rs"]
mod session_collab;
#[path = "signed_commands.rs"]
mod signed_commands;
#[path = "typed_topic.rs"]
mod typed_topic;
