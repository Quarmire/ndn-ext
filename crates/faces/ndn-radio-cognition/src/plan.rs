//! The **act** side — what the policy emits and the face applies.
//!
//! MRMC-native: a [`RadioPlan`] is a *per-radio allocation* (which radios carry a
//! named object, on which channels, with what parameters, replicated for
//! diversity or split across a coding generation), **plus** the CCLF-style
//! relay/suppress decision and a cross-node *consistency digest* so overhearers
//! converge on a compatible plan instead of fighting. The single-radio case is
//! the degenerate one-allocation plan.

use crate::sense::RadioId;

/// Per-transmission PHY/link actuator settings for **one** radio. `None`/`false`
/// means "leave at the actuator's current value". This is the actuator alphabet —
/// every knob built into the monitor-wifi driver appears here as policy output,
/// not as a standalone toggle.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct TxParams {
    pub mcs: Option<u8>,
    pub vht: bool,
    pub nss: Option<u8>,
    pub short_gi: bool,
    /// Channel-bandwidth code (0=20,1=40,2=80,3=10,4=5), matching `ChannelBw`.
    pub bw: Option<u8>,
    pub stbc: bool,
    pub csd: bool,
    pub ldpc: bool,
    /// Target A-MSDU size in MSDUs (0/None = no aggregation).
    pub amsdu_msdus: Option<u16>,
    /// Link-FEC parity frames per generation (0/None = no link-FEC). Sized by the
    /// shared redundancy budget, discounted by receiver multiplicity.
    pub link_fec_redundancy: Option<u16>,
    /// Transmit under contention (ignore EDCCA) — for priority named data only.
    pub edcca_ignore: bool,
    /// TX-power index (chip TXAGC scale, higher = more power). **`None` = leave the
    /// hard-won calibrated/regulatory/PA-backoff power untouched** — the control
    /// plane only ever sets this to *reduce* power below the calibrated max when the
    /// demand set has SNR margin to spare (for spatial reuse), never to exceed it.
    pub tx_power: Option<u8>,
}

/// How a radio's transmission relates to the others in the plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AllocRole {
    /// Same content on this radio too — spatial/frequency macrodiversity.
    Replicate,
    /// A distinct subset of the coding generation (heterogeneous split: e.g. bulk
    /// on Wi-Fi, long-range subset on LoRa). Receivers accumulate rank from any.
    Split,
}

/// One radio's slice of a [`RadioPlan`].
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RadioAllocation {
    pub radio: RadioId,
    /// Channel to use / hop to before transmitting (None = stay).
    pub channel: Option<u8>,
    pub params: TxParams,
    pub role: AllocRole,
}

/// The full cross-layer, multi-radio decision for one named object.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct RadioPlan {
    /// Which radios carry this object (empty ⇒ nothing to do / suppressed).
    pub allocations: Vec<RadioAllocation>,
    /// CCLF: this node is the elected relay for the object.
    pub relay: bool,
    /// CCLF + stop-at-rank-N: stay quiet (a non-innovative duplicate — downstream
    /// demand already satisfied / covered by others).
    pub suppress: bool,
    /// Predicted **airtime per satisfied Interest** (relative; lower is better) —
    /// the optimand, surfaced for comparison/telemetry and A/B against fixed-MCS.
    pub objective: f32,
    /// Cross-node consistency digest over the salient choices (prefix bucket +
    /// radio/channel/rate class). Independent nodes computing from the same
    /// name+demand land on the same digest → overhearers converge; a mismatch on
    /// the wire flags a contradictory re-transmit to suppress.
    pub consistency: u64,
}

impl RadioPlan {
    /// A do-nothing / suppressed plan.
    pub fn suppressed(consistency: u64) -> Self {
        Self {
            suppress: true,
            consistency,
            ..Default::default()
        }
    }

    /// The degenerate single-radio plan.
    pub fn single(radio: RadioId, channel: Option<u8>, params: TxParams) -> Self {
        Self {
            allocations: vec![RadioAllocation {
                radio,
                channel,
                params,
                role: AllocRole::Replicate,
            }],
            ..Default::default()
        }
    }

    pub fn allocation_for(&self, radio: RadioId) -> Option<&RadioAllocation> {
        self.allocations.iter().find(|a| a.radio == radio)
    }
}

/// Applied to one radio by its face (the actuator API the control plane drives).
/// The `MonitorWifiFace`/backend implements this over its knobs; a LoRa/BLE face
/// implements what it can; an RX-only SDR sensor implements none of the TX side.
/// The `LinkServiceFeature` splits a [`RadioPlan`] across the node's face group
/// and calls `apply` on each radio's [`RadioAllocation`] (channel + params).
pub trait RadioActuators {
    fn radio_id(&self) -> RadioId;
    /// Apply this radio's slice of the plan: tune the channel (if set), then set the
    /// per-transmission [`TxParams`]. Implementations apply what they can and ignore
    /// the rest.
    fn apply(&self, alloc: &RadioAllocation) -> Result<(), RadioError>;
}

#[derive(Debug, Clone)]
pub struct RadioError(pub String);

impl core::fmt::Display for RadioError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "radio actuator error: {}", self.0)
    }
}
impl std::error::Error for RadioError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_plan_degenerate() {
        let p = RadioPlan::single(RadioId(0), Some(149), TxParams::default());
        assert_eq!(p.allocations.len(), 1);
        assert!(p.allocation_for(RadioId(0)).is_some());
        assert!(p.allocation_for(RadioId(1)).is_none());
        assert_eq!(p.allocations[0].role, AllocRole::Replicate);
    }

    #[test]
    fn suppressed_plan() {
        let p = RadioPlan::suppressed(42);
        assert!(p.suppress);
        assert!(p.allocations.is_empty());
        assert_eq!(p.consistency, 42);
    }
}
