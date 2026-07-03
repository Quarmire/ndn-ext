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

#[cfg(feature = "libusb-backend")]
mod impls {
    use super::{Bandwidth, RadioKnobs};
    use ndn_transport::FaceError;

    impl RadioKnobs for crate::LibUsbRtl88xxBackend {
        fn set_channel(&self, channel: u8, bw: Bandwidth) -> Result<(), FaceError> {
            let cbw = match bw {
                Bandwidth::Bw20 => crate::ChannelBw::Bw20,
                Bandwidth::Bw40 => crate::ChannelBw::Bw40,
                Bandwidth::Bw80 => crate::ChannelBw::Bw80,
                Bandwidth::Nb10 => crate::ChannelBw::Nb10,
                Bandwidth::Nb5 => crate::ChannelBw::Nb5,
            };
            crate::LibUsbRtl88xxBackend::set_channel(self, channel, cbw)
        }
        fn set_tx_power(&self, idx: u32) -> Result<(), FaceError> {
            crate::LibUsbRtl88xxBackend::set_tx_power(self, idx)
        }
        fn set_tx_csd(&self, on: bool) -> Result<(), FaceError> {
            crate::LibUsbRtl88xxBackend::set_tx_csd(self, on)
        }
        fn set_edcca_ignore(&self, on: bool) -> Result<(), FaceError> {
            crate::LibUsbRtl88xxBackend::set_edcca_ignore(self, on)
        }
    }

    impl RadioKnobs for crate::Mt7612uBackend {
        fn set_channel(&self, channel: u8, bw: Bandwidth) -> Result<(), FaceError> {
            // Only channel 6 / 20 MHz has been captured + replayed so far. Other
            // channels need the per-channel RF program captured the same way
            // (see docs/RADIO_SUBSYSTEM.md "Adding a channel"). This is the
            // "capability added incrementally" boundary made explicit.
            if channel == 6 && bw == Bandwidth::Bw20 {
                crate::Mt7612uBackend::set_channel_ch6(self)
            } else {
                Err(FaceError::Io(std::io::Error::other(format!(
                    "mt7612u: only ch6/20MHz tuned so far (requested ch{channel}/{bw:?})"
                ))))
            }
        }
        // set_tx_power / set_tx_csd / set_edcca_ignore: default no-ops until the
        // mt76x2 power-table / TXOP-CTRL / ED-CCA registers are ported.
    }
}
