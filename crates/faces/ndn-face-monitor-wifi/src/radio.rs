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

use ndn_transport::FaceError;

/// Channel bandwidth, uniform across backends. The numeric `code()` matches the
/// cognition plane's `TxParams.bw` / `RadioCapability.max_bw` encoding and the
/// RTL `ChannelBw` discriminants: `0=20, 1=40, 2=80, 3=10MHz, 4=5MHz`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Bandwidth {
    /// 20 MHz (standard).
    #[default]
    Bw20,
    /// 40 MHz.
    Bw40,
    /// 80 MHz (VHT).
    Bw80,
    /// 10 MHz narrowband (non-standard; longer range / lower rate).
    Nb10,
    /// 5 MHz narrowband.
    Nb5,
}

impl Bandwidth {
    /// Numeric code shared with `TxParams.bw` / `RadioCapability.max_bw`.
    pub fn code(self) -> u8 {
        match self {
            Bandwidth::Bw20 => 0,
            Bandwidth::Bw40 => 1,
            Bandwidth::Bw80 => 2,
            Bandwidth::Nb10 => 3,
            Bandwidth::Nb5 => 4,
        }
    }

    /// Inverse of [`code`](Self::code); unknown codes fall back to 20 MHz.
    pub fn from_code(c: u8) -> Self {
        match c {
            1 => Bandwidth::Bw40,
            2 => Bandwidth::Bw80,
            3 => Bandwidth::Nb10,
            4 => Bandwidth::Nb5,
            _ => Bandwidth::Bw20,
        }
    }
}

/// The uniform stateful-knob surface every userspace radio backend exposes to
/// the named-radio control plane. Implementors are wrapped behind a
/// `RadioActuators` adapter (see `control.rs`) so a single generic actuator can
/// drive any radio.
///
/// Only [`set_channel`](Self::set_channel) is required — a radio that cannot at
/// least tune is not useful. The remaining knobs default to no-ops so a port can
/// land RX/TX first and grow contention/power control later. Per-frame
/// rate/STBC/LDPC/short-GI/NSS is NOT here; that travels with each
/// [`crate::InjectFrame`]`.mcs` on the data plane.
pub trait RadioKnobs: Send + Sync {
    /// Tune to `channel` at bandwidth `bw`. Returns an error if the radio cannot
    /// reach that channel/width (e.g. a port that has only captured one channel).
    fn set_channel(&self, channel: u8, bw: Bandwidth) -> Result<(), FaceError>;

    /// Set the TXAGC reference index (a back-off below the regulatory ceiling;
    /// never used to exceed it). Default: no-op (radio runs at its init power).
    fn set_tx_power(&self, _idx: u32) -> Result<(), FaceError> {
        Ok(())
    }

    /// Enable cyclic-shift diversity on the second chain (1-stream robustness via
    /// antenna diversity). Default: no-op (not supported / single-chain).
    fn set_tx_csd(&self, _on: bool) -> Result<(), FaceError> {
        Ok(())
    }

    /// Ignore EDCCA so TX proceeds under channel contention. Default: no-op.
    fn set_edcca_ignore(&self, _on: bool) -> Result<(), FaceError> {
        Ok(())
    }
}

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
