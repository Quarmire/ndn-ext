//! # ndn-radio-cognition — cross-layer cognitive control plane for the named-data radio
//!
//! The integrating layer that turns the radio's PHY/link **actuators** (MCS, BW,
//! STBC/CSD/LDPC, A-MSDU, EDCCA, link-FEC, channel) and **sensors** (RSSI, PER,
//! occupancy, neighbor reports) into a **system**: a closed-loop, cooperative,
//! name-driven control plane — a *data-centric MAC* — rather than a drawer of
//! static point-to-point knobs (which would make the radio wfb-ng).
//!
//! Design: the note this used to cite
//! (`.claude/notes/named-radio/cross-layer-cognitive-stack-2026-06-15.md`) was never
//! in the workspace — that directory does not exist and the file is not recoverable
//! (checked 2026-07-16). The surviving statement of the argument is
//! `ndn-face-monitor-wifi/docs/RADIO_SUBSYSTEM.md` §2-§3, and the doctrine it
//! answers to is `ndn-face-wifi-aware/docs/NAMED_RADIO_COURSE_CORRECTION.md`.
//!
//! ## The loop
//! - **SENSE** ([`MediumState`]) — the unified, **MRMC-native** cross-layer medium
//!   state, keyed by `(RadioId, Channel)`, fused from our own radios + neighbors'
//!   named/signed reports.
//! - **DECIDE** ([`RadioPolicy::decide`]) — measured-adaptive; reads a
//!   [`MediumView`] + the [`NameContext`] and emits a [`RadioPlan`], optimizing the
//!   single optimand **airtime per satisfied Interest over the demand set**.
//! - **ACT** ([`RadioActuators`]) — the face applies its slice of the plan.
//!
//! ## Resolved doctrine baked into the types
//! - **Multi-radio / multi-channel from day one.** State is `(RadioId, Channel)`-keyed
//!   and a [`RadioPlan`] is a *per-radio allocation*; single-radio is the degenerate
//!   one-entry case. [`RadioCapability`] is the single switch between homogeneous
//!   (NDNPIPES) and heterogeneous (NDN-CRAHNs: LoRa + Wi-Fi) regimes.
//! - **One plane, not two.** The relay/suppress decision is the CCLF-style election;
//!   the actuators are its widened output vocabulary, not a parallel subsystem.
//! - **Innovation-aware suppression** unifies CCLF (drop duplicate) and
//!   stop-at-rank-N (transmit only if it adds rank to a rank-deficient downstream) —
//!   the receive-side (macrodiversity) and transmit-side (medium-sharing) cooperation
//!   are two views of one predicate.
//! - **Redundancy is ONE budget**, sized from the residual left below each layer,
//!   discounted by macrodiversity receiver multiplicity, biased by the measured
//!   re-Interest rate (the real ARQ signal), targeting post-pooling rank deficit.
//! - **SDR is the richest RX-only [`RadioCapability`]** (a spectrum instrument),
//!   not a new PHY: it drops into the sense bus and upgrades the faked occupancy
//!   input. The SDR-as-modem / FHSS-by-name arc stays the frontier.
//!
//! ## Purity
//! Pure / sans-IO / runtime-agnostic (like `ndn-signals-core`). The engine↔face I/O
//! — feeding the bus from PIT/CS/CCLF and driving the face actuators — lives in the
//! `LinkServiceFeature` seam, **not** here, so the logic stays unit-testable and
//! face-agnostic.

mod calibrate;
pub mod coop;
mod contextual;
pub mod dos;
mod demand;
mod plan;
mod policy;
mod report;
pub mod schedule;
mod sense;
mod strategy;

pub use calibrate::{
    RateCalibrator, RateThresholds, STATIC_REQ_RSSI, STATIC_REQ_RSSI_SF, SfCalibrator,
    SfThresholds, default_sf_thresholds, default_thresholds, pick_sf, pick_sf_hysteretic,
};
pub use contextual::{
    ARMS, Arm, ArmChoice, Context, ContextualBandit, FOOTPRINT_LAMBDA, MISS_PENALTY, apply_arm, reward,
};
pub use demand::DemandTracker;
pub use plan::{
    AllocRole, DataPlaneConfig, LoraRate, RadioActuators, RadioAllocation, RadioError, RadioPlan,
    RateParams, TxParams, WifiRate,
};
pub use policy::{
    DecisionRationale, NameContext, PolicyConfig, Priority, RadioPolicy, RadioRationale,
    SuppressReason,
};
pub use report::{
    FULL_RX_MCS, LEGACY_ONLY_RX, MAX_ENTRIES, REPORT_MAGIC, ReceptionReport, decode_report,
    encode_report,
};
pub use schedule::{HopSchedule, SlotSchedule};
pub use sense::{
    Band, ChannelOccupancy, DEFAULT_SATURATION_FPS, DUTY_WINDOW_MS, Demand, Ewma, LinkResidual,
    MediumState, MediumView, NeighborReport, RadioCapability, RadioId, RadioKind, RateCapability,
    TimingModel, lora_airtime_ms,
};
pub use strategy::RadioStrategy;

/// Re-exported so the `LinkServiceFeature` can translate the face's decoded
/// `LinkSignals` into [`MediumState::observe_rx`] inputs.
pub use ndn_signals_core::LinkSignals;

/// Canonical prefix-hash (FNV-1a over the name components, with a separator) — the
/// opaque key that ties demand, the sense bus, `NameContext`, and the consistency
/// digest together. The forwarder uses this to turn a `Name` prefix into the key
/// the control plane is keyed on.
pub fn prefix_hash(components: &[&[u8]]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for c in components {
        for &b in *c {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        // component separator so ["ab","c"] ≠ ["a","bc"]
        h ^= 0x2f;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}
