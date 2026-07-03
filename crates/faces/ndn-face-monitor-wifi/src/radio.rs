//! Uniform radio-knob abstraction shared by the userspace backends.
//!
//! Two distinct seams separate the *data plane* from the *control plane* of a
//! radio (see `docs/RADIO_SUBSYSTEM.md`):
//!
//! - **Data plane** = [`crate::FrameIo`] (`inject` / `recv_frame`) — get bytes
//!   on and off the air. Per-frame rate/coding rides with each
//!   [`crate::InjectFrame`]`.mcs`.
//! - **Control plane** = [`RadioKnobs`] (this trait) — the *slow, stateful*
//!   knobs a plan-slice sets: channel, TX power, contention behaviour. This is
//!   the ACT half of the named-radio sense→decide→act loop.
//!
//! A backend overrides only the knobs it actually supports; every optional knob
//! has a default no-op, so a new port "adds capability uniformly" — it works the
//! day it can tune a channel, and gains power/CSD/EDCCA control as those are
//! ported, without changing the trait or the control plane that drives it.

// The radio control-plane trait + the channel-bandwidth enum moved down into the
// shared HAL crate (`ndn-radio-hal`) so a driver depends on one contract crate.
// Re-exported here so `crate::radio::Bandwidth` / `crate::radio::RadioKnobs` (and
// the `super::*` in the tests below) still resolve unchanged.
pub use ndn_radio_hal::{Bandwidth, RadioKnobs};

// The `RadioKnobs` impls for the driver backends (`LibUsbRtl88xxBackend`,
// `Mt7612uBackend`) moved into `ndn-radio-drivers` alongside the backend types —
// the orphan rule requires the impl travel with the local type now that both the
// trait (`ndn-radio-hal`) and the types are foreign to this crate.
