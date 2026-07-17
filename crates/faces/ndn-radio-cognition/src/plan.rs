//! The **act** side — what the policy emits and the face applies.
//!
//! MRMC-native: a [`RadioPlan`] is a *per-radio allocation* (which radios carry a
//! named object, on which channels, with what parameters, replicated for
//! diversity or split across a coding generation), **plus** the CCLF-style
//! relay/suppress decision and a cross-node *consistency digest* so overhearers
//! converge on a compatible plan instead of fighting. The single-radio case is
//! the degenerate one-allocation plan.

use crate::sense::RadioId;

/// Per-transmission actuator settings for **one** radio. The **bearer-agnostic** knobs every radio
/// understands live here directly; the PHY rate/robustness knobs live in [`RateParams`], a sum type
/// keyed by bearer, so a consumer matches on the bearer it is driving and *cannot* read another
/// bearer's fields. No radio's rate model is privileged — Wi-Fi's MCS and LoRa's spreading factor
/// are peer variants, not a base struct with the other bolted on. Read the PHY knobs through the
/// typed accessors ([`TxParams::mcs`], [`TxParams::spreading_factor`], …), which return a value only
/// for the matching variant. `None`/`false` means "leave at the actuator's current value".
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct TxParams {
    /// Link-FEC parity frames per generation (0/None = no link-FEC). Sized by the shared redundancy
    /// budget, discounted by receiver multiplicity. Bearer-agnostic.
    pub link_fec_redundancy: Option<u16>,
    /// Transmit under contention (ignore EDCCA / LBT) — for priority named data only. Bearer-agnostic.
    pub edcca_ignore: bool,
    /// TX-power index (chip TXAGC scale, higher = more power). **`None` = leave the hard-won
    /// calibrated/regulatory/PA-backoff power untouched** — only ever reduced below the calibrated
    /// max for spatial reuse, never exceeded. Bearer-agnostic.
    pub tx_power: Option<u8>,
    /// Bearer-specific PHY rate/robustness knobs.
    pub rate: RateParams,
}

// NO per-name frame-length / MTU knob lives here, and that is a measured decision
// (2026-07-16, task #27) rather than an omission.
//
// The case for one was a length-dependent PER: if longer frames are likelier to
// die, an `Urgent` name should ask for short frames and a `Bulk` name for long
// ones, and no single MTU serves both. On air, between two OPis at -52 dBm:
//
//   * `burst_fork` fixed the frame size and varied only the inter-frame gap.
//     Every cell landed 26-30/30 — 800 B and 2260 B alike, a 30-frame
//     back-to-back burst as well as one paced 4 ms apart. Per-frame p ~= 0.93
//     with no length term and no burst term.
//   * The object sweep then fit p ~= 0.93-0.98 per frame at BOTH a 1024 B and a
//     2272 B MTU. Delivery is p^n, so the only lever is minimizing n, and a
//     bigger MTU was better-or-equal in every row (4000 B: 24/30 at MTU 1024 ->
//     29/30 at 2272). There is no crossover, so there is no name-dependent
//     optimum: max MTU always wins.
//
// The 0.83 that motivated the knob was an artifact of the bench, which keyed
// reassembly on the raw LP sequence and stitched fragments of different objects
// together (ndn-packet/tests/reassembly_key.rs). Building this knob would have
// been building a control surface to dodge our own bug — the NDP bulk tier again
// (NAMED_RADIO_COURSE_CORRECTION.md §10.1). Add it if a weak-link test ever shows
// a real length term at the margin; the strong-link regime does not have one.
//
// The name-dependent lever that IS real for multi-fragment objects is
// `link_fec_redundancy` above: at 8-17 fragments even p = 0.95 leaves 40-66%
// delivery, and an outer code fixes that with no peer to ACK.

/// The bearer-specific PHY knobs. A radio matches on its own variant; there is no cross-bearer field.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum RateParams {
    /// No PHY knobs decided — leave the radio at its current values.
    #[default]
    None,
    /// Wi-Fi (802.11).
    Wifi(WifiRate),
    /// LoRa (sub-GHz).
    Lora(LoraRate),
}

/// Wi-Fi (802.11) PHY knobs — MCS, bandwidth, spatial streams, and robustness coding.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct WifiRate {
    /// Modulation-and-coding-scheme index.
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
}

/// LoRa (sub-GHz) PHY knobs — the reach/rate dial (spreading factor) and coding rate.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct LoraRate {
    /// Spreading factor 7–12 — the reach/rate dial (the peer of Wi-Fi's `mcs`).
    pub spreading_factor: Option<u8>,
    /// Coding rate `1`=4/5 … `4`=4/8 — a robustness/FEC dial.
    pub coding_rate: Option<u8>,
}

impl TxParams {
    /// Bearer-agnostic knobs plus a Wi-Fi rate.
    pub fn wifi(wifi: WifiRate) -> Self {
        Self {
            rate: RateParams::Wifi(wifi),
            ..Default::default()
        }
    }
    /// Bearer-agnostic knobs plus a LoRa rate.
    pub fn lora(lora: LoraRate) -> Self {
        Self {
            rate: RateParams::Lora(lora),
            ..Default::default()
        }
    }

    /// Wi-Fi MCS, or `None` for a non-Wi-Fi radio.
    pub fn mcs(&self) -> Option<u8> {
        if let RateParams::Wifi(w) = &self.rate { w.mcs } else { None }
    }
    /// Wi-Fi spatial streams, or `None` for a non-Wi-Fi radio.
    pub fn nss(&self) -> Option<u8> {
        if let RateParams::Wifi(w) = &self.rate { w.nss } else { None }
    }
    /// Wi-Fi channel-bandwidth code, or `None` for a non-Wi-Fi radio.
    pub fn bw(&self) -> Option<u8> {
        if let RateParams::Wifi(w) = &self.rate { w.bw } else { None }
    }
    /// Wi-Fi VHT flag (false unless a Wi-Fi rate sets it).
    pub fn vht(&self) -> bool {
        matches!(self.rate, RateParams::Wifi(w) if w.vht)
    }
    /// Wi-Fi short-GI flag.
    pub fn short_gi(&self) -> bool {
        matches!(self.rate, RateParams::Wifi(w) if w.short_gi)
    }
    /// Wi-Fi STBC flag.
    pub fn stbc(&self) -> bool {
        matches!(self.rate, RateParams::Wifi(w) if w.stbc)
    }
    /// Wi-Fi cyclic-shift-diversity flag.
    pub fn csd(&self) -> bool {
        matches!(self.rate, RateParams::Wifi(w) if w.csd)
    }
    /// Wi-Fi LDPC flag.
    pub fn ldpc(&self) -> bool {
        matches!(self.rate, RateParams::Wifi(w) if w.ldpc)
    }
    /// Wi-Fi A-MSDU size, or `None` for a non-Wi-Fi radio.
    pub fn amsdu_msdus(&self) -> Option<u16> {
        if let RateParams::Wifi(w) = &self.rate { w.amsdu_msdus } else { None }
    }
    /// LoRa spreading factor, or `None` for a non-LoRa radio.
    pub fn spreading_factor(&self) -> Option<u8> {
        if let RateParams::Lora(l) = &self.rate { l.spreading_factor } else { None }
    }
    /// LoRa coding rate, or `None` for a non-LoRa radio.
    pub fn coding_rate(&self) -> Option<u8> {
        if let RateParams::Lora(l) = &self.rate { l.coding_rate } else { None }
    }
    /// Mutable access to the Wi-Fi rate (e.g. for the Minstrel-style probe bump), if this is Wi-Fi.
    pub fn wifi_mut(&mut self) -> Option<&mut WifiRate> {
        if let RateParams::Wifi(w) = &mut self.rate { Some(w) } else { None }
    }
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
