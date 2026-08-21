//! Single consolidated integration-test binary (P1 compile-cost work).
//!
//! `autotests = false` in Cargo.toml routes every `tests/*.rs` file through
//! this one `[[test]]` target, so the crate links ONE test binary instead of
//! fourteen. The per-topic files stay in place as modules; add a new
//! `#[path]` line here when adding a test file.
//!
//! Feature gating is unchanged: the `engine`-gated modules keep their
//! `#![cfg(feature = "engine")]` inner attributes, mirrored on the `mod`
//! lines below, so those tests still compile only under
//! `--features engine` (CI's dedicated engine-gated step).

#[path = "cert_chain.rs"]
mod cert_chain;
#[path = "coded_bulk.rs"]
mod coded_bulk;
#[path = "confidentiality.rs"]
mod confidentiality;
#[path = "handshake.rs"]
mod handshake;
#[cfg(feature = "engine")]
#[path = "handshake_crypto.rs"]
mod handshake_crypto;
#[cfg(feature = "engine")]
#[path = "mgmt.rs"]
mod mgmt;
#[path = "over_monitor_wifi.rs"]
mod over_monitor_wifi;
#[cfg(feature = "engine")]
#[path = "pipe_pathcontrol_teardown.rs"]
mod pipe_pathcontrol_teardown;
#[path = "producer_identity.rs"]
mod producer_identity;
#[path = "push.rs"]
mod push;
#[cfg(feature = "engine")]
#[path = "relay_activity_renews.rs"]
mod relay_activity_renews;
#[path = "relay_key_handoff.rs"]
mod relay_key_handoff;
#[cfg(feature = "engine")]
#[path = "relay_teardown_monitor.rs"]
mod relay_teardown_monitor;
#[cfg(feature = "engine")]
#[path = "teardown.rs"]
mod teardown;
