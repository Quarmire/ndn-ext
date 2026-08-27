//! The named-data-radio **cognition** telemetry as a generic mgmt introspection
//! surface.
//!
//! The radio control plane *actuates* its radios itself (rate / channel / power /
//! FEC, decided every ~500 ms), so an operator UI should **observe what cognition
//! decided**, not offer manual radio knobs. This adapter exposes a live, read-only
//! snapshot of [`RadioControl::telemetry`] through the sans-io [`ControlSurface`]
//! trait — served generically by the mgmt server under `/localhost/nfd/ext/list`
//! as `key=value` text (no protobuf; trivial to consume from a WASM dashboard).
//!
//! It holds an `Arc<RadioControl>` (a separate handle from the one the cognition
//! loop runs on) and reads a fresh snapshot per `stats()` call — `telemetry()` is
//! `&self` and only briefly locks `last_plans`, so it is safe to call at any
//! cadence from the mgmt dispatch thread.

use std::sync::Arc;

use ndn_mgmt_wire::control_surface::{ControlInfo, ControlStats, ControlSurface};

use crate::control::RadioControl;

/// `ControlSurface` adapter over the radio cognition control plane.
///
/// Registered with the engine via `MgmtHandles::control_surfaces`; the mgmt server
/// renders it under the `[named-radio]` section of the `/localhost/nfd/ext/list`
/// dataset. Read-only — `set_option` stays the trait default (rejects).
pub struct RadioCognitionSurface {
    control: Arc<RadioControl>,
}

impl RadioCognitionSurface {
    /// Wrap a shared radio control handle. Cheap; clone the `Arc` you already have.
    pub fn new(control: Arc<RadioControl>) -> Self {
        Self { control }
    }
}

/// `Option<T>` → display string, `"-"` for `None` (matches the trace-site
/// `?a.channel` debug intent while staying human/parse friendly).
fn opt<T: std::fmt::Display>(v: Option<T>) -> String {
    v.map(|x| x.to_string()).unwrap_or_else(|| "-".to_string())
}

impl ControlSurface for RadioCognitionSurface {
    fn name(&self) -> &str {
        "named-radio"
    }

    fn describe(&self) -> ControlInfo {
        let t = self.control.telemetry();
        ControlInfo {
            caps: vec![
                ("subsystem".into(), "named-radio-cognition".into()),
                ("strategy".into(), t.strategy.into()),
                ("actuation".into(), "rate+channel+power+fec".into()),
                ("readonly".into(), "true".into()),
            ],
            // Read-only: cognition owns actuation; the UI observes, it does not set.
            options: Vec::new(),
        }
    }

    fn stats(&self) -> ControlStats {
        let t = self.control.telemetry();
        let mut e: Vec<(String, String)> = Vec::new();

        // --- Aggregate cognition state ---
        e.push(("strategy".into(), t.strategy.into()));
        e.push(("managed_objects".into(), t.managed_objects.to_string()));
        e.push(("suppressed".into(), t.suppressed.to_string()));
        e.push(("objective".into(), format!("{:.4}", t.objective)));
        if let Some(th) = t.learned_thresholds {
            let joined = th
                .iter()
                .map(|v| format!("{v:.1}"))
                .collect::<Vec<_>>()
                .join(",");
            e.push(("learned_thresholds".into(), joined));
        }

        // --- Per-radio DECIDED plan (what cognition actuated) ---
        // Flatten every allocation across the active plans keyed by radio id, using
        // the exact accessors the decision trace site emits (control.rs "radio:
        // decision"): channel, mcs, nss, bw, he, tx_power, link_fec + plan flags.
        for plan in &t.plans {
            for a in &plan.allocations {
                let id = a.radio.0;
                let k = |field: &str| format!("radio.{id}.{field}");
                e.push((k("channel"), opt(a.channel)));
                e.push((k("mcs"), opt(a.params.mcs())));
                e.push((k("nss"), opt(a.params.nss())));
                e.push((k("bw"), opt(a.params.bw())));
                e.push((k("he"), a.params.he().to_string()));
                e.push((k("tx_power"), opt(a.params.tx_power)));
                e.push((k("link_fec"), opt(a.params.link_fec_redundancy)));
                e.push((k("suppress"), plan.suppress.to_string()));
                e.push((k("relay"), plan.relay.to_string()));
                e.push((k("objective"), format!("{:.4}", plan.objective)));
            }
        }

        ControlStats { entries: e }
    }
}
