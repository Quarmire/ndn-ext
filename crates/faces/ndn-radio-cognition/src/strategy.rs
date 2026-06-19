//! [`RadioStrategy`] — the radio-layer analogue of the forwarding `Strategy` trait.
//!
//! The ndn-rs design exposes a pluggable **decision trait per layer**: `Strategy`
//! (where to forward), `RoutingProtocol`, `ContentStore`, `DiscoveryProtocol`. The
//! radio decision — *how to transmit* a named object — is the same kind of seam, so
//! it gets the same treatment:
//!
//! | forwarding              | radio                          |
//! |-------------------------|--------------------------------|
//! | `Strategy`              | [`RadioStrategy`]              |
//! | `ForwardingAction`      | [`RadioPlan`]                 |
//! | `StrategyContext`       | [`NameContext`] + [`MediumView`] |
//! | `CclfStrategy` (impl)   | [`crate::RadioPolicy`] (rule/calibrated impl) |
//!
//! A `RadioStrategy` maps `(name-context, medium-state)` → a [`RadioPlan`]. It is
//! the *decision*; the I/O host that runs it, feeds the sense bus, and applies the
//! plan (the `RadioControl` `LinkServiceFeature`) is the radio analogue of the
//! forwarding pipeline that runs a `Strategy`.

use crate::plan::RadioPlan;
use crate::policy::NameContext;
use crate::sense::MediumView;

/// Pluggable radio transmission-decision logic (object-safe: takes `&dyn MediumView`).
pub trait RadioStrategy: Send + Sync {
    /// Decide the joint per-radio transmission plan for a named object.
    fn decide(&self, ctx: &NameContext, medium: &dyn MediumView, now_ms: u64) -> RadioPlan;

    /// Strategy name (kebab-case), for telemetry / management — mirrors
    /// `Strategy::name`.
    fn name(&self) -> &'static str {
        "radio-strategy"
    }
}
