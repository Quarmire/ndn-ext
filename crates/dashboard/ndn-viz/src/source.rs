//! Per-dataset freshness model + small forwarder-field mapping helpers.
//!
//! Salvage §1.4 (archived `ndn-dashboard-next/src/engine.rs`): every panel
//! carries its own [`DatasetSource`] provenance — `Fresh` / `Stale` /
//! `Disconnected` / `Unsupported` — instead of one global "connected" flag, so a
//! read-only or partial target still renders truthfully. This is the pattern the
//! shared viz layer's data sources implement; the concrete row types stay with
//! each consumer (dashboard-core, ndn-sim).

/// Freshness of a single management dataset behind a panel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DatasetState {
    Fresh,
    Stale { age_s: u64 },
    Disconnected,
    Unsupported,
}

impl DatasetState {
    pub fn label(self) -> String {
        match self {
            Self::Fresh => "fresh".into(),
            Self::Stale { age_s } => format!("stale {age_s}s"),
            Self::Disconnected => "disconnected".into(),
            Self::Unsupported => "unsupported".into(),
        }
    }

    pub fn tone(self) -> &'static str {
        match self {
            Self::Fresh => "good",
            Self::Stale { .. } => "amber",
            Self::Disconnected => "bad",
            Self::Unsupported => "muted",
        }
    }

    /// Whether this state reflects data actually obtained (fresh or aged), vs none.
    pub fn has_data(self) -> bool {
        matches!(self, Self::Fresh | Self::Stale { .. })
    }
}

/// A named dataset plus its freshness and last-update stamp (epoch seconds).
///
/// `last_update_unix_s` is supplied by the consumer (which owns the clock — this
/// crate never reads time); `None` means "no successful read yet".
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DatasetSource {
    pub name: &'static str,
    pub state: DatasetState,
    pub last_update_unix_s: Option<u64>,
}

impl DatasetSource {
    pub fn new(name: &'static str, state: DatasetState, last_update_unix_s: Option<u64>) -> Self {
        Self {
            name,
            state,
            last_update_unix_s,
        }
    }
}

/// Map a fetch `Result` to `Fresh` (ok) or `Disconnected` (err) — the common case.
pub fn dataset_state_from_result<T, E>(result: &Result<T, E>) -> DatasetState {
    if result.is_ok() {
        DatasetState::Fresh
    } else {
        DatasetState::Disconnected
    }
}

/// NFD face-scope code → label.
pub fn face_scope_label(scope: u64) -> &'static str {
    match scope {
        0 => "non-local",
        1 => "local",
        _ => "unknown",
    }
}

/// NFD face-persistency code → label.
pub fn face_persistency_label(persistency: u64) -> &'static str {
    match persistency {
        0 => "persistent",
        1 => "on-demand",
        2 => "permanent",
        _ => "unknown",
    }
}

/// Satisfaction percentage (0..=100), saturating, division-by-zero safe.
pub fn satisfaction_pct(satisfied: u64, total: u64) -> u8 {
    satisfied
        .saturating_mul(100)
        .checked_div(total)
        .unwrap_or(0)
        .min(100) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dataset_state_tone_and_label() {
        assert_eq!(DatasetState::Fresh.tone(), "good");
        assert_eq!(DatasetState::Stale { age_s: 45 }.label(), "stale 45s");
        assert!(DatasetState::Stale { age_s: 1 }.has_data());
        assert!(!DatasetState::Disconnected.has_data());
        assert_eq!(DatasetState::Unsupported.tone(), "muted");
    }

    #[test]
    fn result_maps_to_freshness() {
        let ok: Result<(), ()> = Ok(());
        let err: Result<(), ()> = Err(());
        assert_eq!(dataset_state_from_result(&ok), DatasetState::Fresh);
        assert_eq!(dataset_state_from_result(&err), DatasetState::Disconnected);
    }

    #[test]
    fn field_mappers() {
        assert_eq!(face_scope_label(1), "local");
        assert_eq!(face_persistency_label(2), "permanent");
        assert_eq!(satisfaction_pct(0, 0), 0);
        assert_eq!(satisfaction_pct(5, 10), 50);
        assert_eq!(satisfaction_pct(20, 10), 100);
    }
}
