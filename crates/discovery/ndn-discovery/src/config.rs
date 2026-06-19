//! [`DiscoveryProfile`] captures deployment intent; [`DiscoveryConfig`]
//! holds the concrete numeric parameters. Callers pick a profile and
//! optionally override individual fields.

use std::sync::Arc;
use std::time::Duration;

use ndn_packet::Name;

pub use ndn_discovery_core::DiscoveryScope;

pub use crate::service_discovery::auth::{
    DigestSigner, DigestVerifier, KeyedVerifier, RecordSigner, RecordVerifier, SignError,
    SignerAdapter, VerifyVerdict,
};
pub use crate::service_discovery::encryption::{
    DecryptError, EncryptError, EncryptionHook, NoEncryption,
};

/// Probe-scheduling algorithm. Controls *when* hellos are sent; the
/// state machine itself is independent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HelloStrategyKind {
    /// Exponential backoff with jitter.
    Backoff,
    /// Event-driven; no timer in steady state.
    Reactive,
    /// Hellos only on unknown source MAC; backoff fallback when quiet.
    Passive,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrefixAnnouncementMode {
    Static,
    /// Prefix list carried in `SERVED-PREFIX` fields of every Hello Data.
    InHello,
    NlsrLsa,
}

#[derive(Clone, Debug)]
pub struct DiscoveryConfig {
    pub hello_strategy: HelloStrategyKind,
    pub hello_interval_base: Duration,
    pub hello_interval_max: Duration,
    /// `0.0`-`0.5`.
    pub hello_jitter: f32,
    /// Time without a response before `Established -> Stale`.
    pub liveness_timeout: Duration,
    /// Consecutive misses before `Stale -> Absent` (face/FIB removal).
    pub liveness_miss_count: u32,
    pub probe_timeout: Duration,
    pub prefix_announcement: PrefixAnnouncementMode,
    pub auto_create_faces: bool,
    pub tick_interval: Duration,
}

impl DiscoveryConfig {
    pub fn for_profile(profile: &DiscoveryProfile) -> Self {
        match profile {
            DiscoveryProfile::Static => Self::static_routes(),
            DiscoveryProfile::Lan => Self::lan(),
            DiscoveryProfile::Campus => Self::campus(),
            DiscoveryProfile::Mobile => Self::mobile(),
            DiscoveryProfile::HighMobility => Self::high_mobility(),
            DiscoveryProfile::Asymmetric => Self::asymmetric(),
            DiscoveryProfile::Custom(c) => c.clone(),
        }
    }

    fn static_routes() -> Self {
        Self {
            hello_strategy: HelloStrategyKind::Backoff,
            hello_interval_base: Duration::from_secs(3600),
            hello_interval_max: Duration::from_secs(3600),
            hello_jitter: 0.0,
            liveness_timeout: Duration::MAX,
            liveness_miss_count: u32::MAX,
            probe_timeout: Duration::from_secs(5),
            prefix_announcement: PrefixAnnouncementMode::Static,
            auto_create_faces: false,
            tick_interval: Duration::from_secs(1),
        }
    }

    /// Invariant: `liveness_timeout` > `hello_interval_max * (1 + jitter)`
    /// so a healthy peer at full backoff cannot trigger a false Stale.
    /// Here `20 * 1.25 = 25 < 30`; failure detection 90s.
    fn lan() -> Self {
        Self {
            hello_strategy: HelloStrategyKind::Backoff,
            hello_interval_base: Duration::from_secs(5),
            hello_interval_max: Duration::from_secs(20),
            hello_jitter: 0.25,
            liveness_timeout: Duration::from_secs(30),
            liveness_miss_count: 3,
            probe_timeout: Duration::from_secs(5),
            prefix_announcement: PrefixAnnouncementMode::InHello,
            auto_create_faces: true,
            tick_interval: Duration::from_millis(500),
        }
    }

    /// Invariant: `100 * 1.10 = 110 < 120`; failure detection ~6 min.
    fn campus() -> Self {
        Self {
            hello_strategy: HelloStrategyKind::Backoff,
            hello_interval_base: Duration::from_secs(30),
            hello_interval_max: Duration::from_secs(100),
            hello_jitter: 0.10,
            liveness_timeout: Duration::from_secs(120),
            liveness_miss_count: 3,
            probe_timeout: Duration::from_secs(10),
            prefix_announcement: PrefixAnnouncementMode::NlsrLsa,
            auto_create_faces: true,
            tick_interval: Duration::from_millis(500),
        }
    }

    /// Invariant: `2 * 1.15 = 2.3 < 3`; failure detection 15s.
    fn mobile() -> Self {
        Self {
            hello_strategy: HelloStrategyKind::Reactive,
            hello_interval_base: Duration::from_millis(200),
            hello_interval_max: Duration::from_secs(2),
            hello_jitter: 0.15,
            liveness_timeout: Duration::from_secs(3),
            liveness_miss_count: 5,
            probe_timeout: Duration::from_millis(500),
            prefix_announcement: PrefixAnnouncementMode::InHello,
            auto_create_faces: true,
            tick_interval: Duration::from_millis(50),
        }
    }

    /// Invariant: `500 * 1.10 = 550 < 750`; failure detection 2.25s.
    fn high_mobility() -> Self {
        Self {
            hello_strategy: HelloStrategyKind::Passive,
            hello_interval_base: Duration::from_millis(50),
            hello_interval_max: Duration::from_millis(500),
            hello_jitter: 0.10,
            liveness_timeout: Duration::from_millis(750),
            liveness_miss_count: 3,
            probe_timeout: Duration::from_millis(200),
            prefix_announcement: PrefixAnnouncementMode::InHello,
            auto_create_faces: true,
            tick_interval: Duration::from_millis(20),
        }
    }

    fn asymmetric() -> Self {
        Self {
            hello_strategy: HelloStrategyKind::Passive,
            hello_interval_base: Duration::from_secs(5),
            hello_interval_max: Duration::from_secs(30),
            hello_jitter: 0.10,
            liveness_timeout: Duration::from_secs(60),
            liveness_miss_count: 3,
            probe_timeout: Duration::from_secs(10),
            prefix_announcement: PrefixAnnouncementMode::Static,
            auto_create_faces: false,
            tick_interval: Duration::from_millis(500),
        }
    }
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self::lan()
    }
}

#[derive(Clone, Debug, Default)]
pub enum DiscoveryProfile {
    Static,
    #[default]
    Lan,
    Campus,
    Mobile,
    HighMobility,
    Asymmetric,
    Custom(DiscoveryConfig),
}

/// Configuration for the service-discovery layer (`/ndn/local/sd/`).
#[derive(Clone)]
pub struct ServiceDiscoveryConfig {
    pub auto_populate_fib: bool,
    pub auto_populate_scope: DiscoveryScope,
    /// Should exceed manual route cost.
    pub auto_fib_cost: u32,
    /// Entries expire after `freshness_period * multiplier`, clamped to
    /// `[auto_fib_min_ttl, auto_fib_max_ttl]`.
    pub auto_fib_ttl_multiplier: f32,
    /// Lower bound on an auto-FIB entry's lifetime (also the floor when a
    /// record's `freshness_ms` is 0).
    pub auto_fib_min_ttl: Duration,
    /// Upper bound on an auto-FIB entry's lifetime — prevents a forged
    /// `freshness_ms` from pinning a route indefinitely.
    pub auto_fib_max_ttl: Duration,
    /// Empty = accept any.
    pub auto_populate_prefix_filter: Vec<Name>,
    /// Cap on stored peer records (evict least-recently-seen when full).
    pub max_records_per_scope: usize,
    /// Cap on stored body blobs / `has_body` markers.
    pub max_body_entries: usize,
    /// Cap on the registration-rate-limit map (bounds memory under a
    /// name-varying flood).
    pub max_rate_limit_entries: usize,
    /// A `pending_fetches` waiter older than this is dropped on tick.
    pub fetch_timeout: Duration,
    pub max_registrations_per_producer: u32,
    pub max_registrations_window: Duration,
    pub relay_records: bool,
    /// LRU cap on `(prefix, node_name)` provider entries.
    pub measurement_capacity: usize,
    /// Entries unseen for longer than this are evicted lazily on the
    /// next [`ServiceDiscoveryProtocol::measurements`] call.
    pub measurement_idle_ttl: Duration,
    /// Default [`NoEncryption`] (pass-through).
    pub encryption_hook: Arc<dyn EncryptionHook>,
    /// Signs outgoing SD/body/peer Data. Default [`DigestSigner`]
    /// (real DigestSha256 integrity). Supply a [`SignerAdapter`] over a
    /// KeyChain signer for authenticated announcements.
    pub record_signer: Arc<dyn RecordSigner>,
    /// Gates inbound records/bodies. Default `None` is **fail-closed**:
    /// unverified records are browseable but never auto-install FIB
    /// routes. Set a [`DigestVerifier`] / [`KeyedVerifier`] / custom
    /// verifier to enable auto-FIB.
    pub record_verifier: Option<Arc<dyn RecordVerifier>>,
}

impl std::fmt::Debug for ServiceDiscoveryConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceDiscoveryConfig")
            .field("auto_populate_fib", &self.auto_populate_fib)
            .field("auto_populate_scope", &self.auto_populate_scope)
            .field("auto_fib_cost", &self.auto_fib_cost)
            .field("auto_fib_ttl_multiplier", &self.auto_fib_ttl_multiplier)
            .field("auto_fib_min_ttl", &self.auto_fib_min_ttl)
            .field("auto_fib_max_ttl", &self.auto_fib_max_ttl)
            .field("max_records_per_scope", &self.max_records_per_scope)
            .field("max_body_entries", &self.max_body_entries)
            .field("max_rate_limit_entries", &self.max_rate_limit_entries)
            .field("fetch_timeout", &self.fetch_timeout)
            .field(
                "max_registrations_per_producer",
                &self.max_registrations_per_producer,
            )
            .field("max_registrations_window", &self.max_registrations_window)
            .field("relay_records", &self.relay_records)
            .field("measurement_capacity", &self.measurement_capacity)
            .field("measurement_idle_ttl", &self.measurement_idle_ttl)
            .field("encryption_hook", &"<dyn EncryptionHook>")
            .field("record_signer", &"<dyn RecordSigner>")
            .field(
                "record_verifier",
                &self.record_verifier.as_ref().map(|_| "<dyn RecordVerifier>"),
            )
            .finish()
    }
}

impl Default for ServiceDiscoveryConfig {
    fn default() -> Self {
        Self {
            auto_populate_fib: true,
            auto_populate_scope: DiscoveryScope::LinkLocal,
            auto_fib_cost: 100,
            auto_fib_ttl_multiplier: 2.0,
            auto_fib_min_ttl: Duration::from_secs(5),
            auto_fib_max_ttl: Duration::from_secs(300),
            auto_populate_prefix_filter: Vec::new(),
            max_records_per_scope: 1000,
            max_body_entries: 512,
            max_rate_limit_entries: 1024,
            fetch_timeout: Duration::from_secs(8),
            max_registrations_per_producer: 10,
            max_registrations_window: Duration::from_secs(60),
            relay_records: false,
            measurement_capacity: 256,
            measurement_idle_ttl: Duration::from_secs(600),
            encryption_hook: Arc::new(NoEncryption),
            record_signer: Arc::new(DigestSigner),
            record_verifier: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lan_profile_has_backoff() {
        let cfg = DiscoveryConfig::for_profile(&DiscoveryProfile::Lan);
        assert_eq!(cfg.hello_strategy, HelloStrategyKind::Backoff);
        assert!(cfg.auto_create_faces);
        assert!(cfg.hello_interval_base < cfg.hello_interval_max);
    }

    #[test]
    fn mobile_profile_is_reactive() {
        let cfg = DiscoveryConfig::for_profile(&DiscoveryProfile::Mobile);
        assert_eq!(cfg.hello_strategy, HelloStrategyKind::Reactive);
        assert!(cfg.hello_interval_base < Duration::from_secs(1));
    }

    #[test]
    fn custom_profile_roundtrips() {
        let mut custom = DiscoveryConfig::for_profile(&DiscoveryProfile::Lan);
        custom.liveness_miss_count = 7;
        let profile = DiscoveryProfile::Custom(custom.clone());
        let out = DiscoveryConfig::for_profile(&profile);
        assert_eq!(out.liveness_miss_count, 7);
    }

    #[test]
    fn static_profile_never_expires() {
        let cfg = DiscoveryConfig::for_profile(&DiscoveryProfile::Static);
        assert!(!cfg.auto_create_faces);
        assert_eq!(cfg.liveness_miss_count, u32::MAX);
    }
}
