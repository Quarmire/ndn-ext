//! NDNSD-style service record publish/browse + a demand-driven peer
//! list.
//!
//! Peer list wire format: `PeerList ::= (PEER-ENTRY)*`,
//! `PEER-ENTRY ::= 0xE0 length Name`.

pub mod auth;
mod browsing;
pub mod encryption;
mod fib_auto;
pub(crate) mod measurements;
mod records;

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::Instant;

use bytes::Bytes;
use ndn_packet::Name;
use ndn_transport::FaceId;
use tokio::sync::oneshot;
use tracing::{debug, info};

use crate::config::ServiceDiscoveryConfig;
use crate::context::DiscoveryContext;
use crate::prefix_announce::ServiceRecord;
use crate::protocol::{DiscoveryProtocol, InboundMeta, ProtocolId};
use crate::scope::{peers_prefix, sd_root, sd_service_info_under, sd_services_under};

pub use browsing::decode_peer_list;
use fib_auto::AutoFibEntry;
use measurements::MeasurementStore;
pub use measurements::ProviderMeasurement;
use records::{ProducerRateLimit, RecordEntry};

const PROTOCOL: ProtocolId = ProtocolId("service-discovery");

/// Attach in a [`CompositeDiscovery`](crate::CompositeDiscovery) for
/// service record publish/browse and demand-driven neighbor queries.
pub struct ServiceDiscoveryProtocol {
    #[expect(dead_code)]
    node_name: Name,
    /// Default `/ndn/local/sd`. `services/` and `service-info/` derive
    /// from this.
    pub(super) root: Name,
    pub(super) config: ServiceDiscoveryConfig,
    claimed: Vec<Name>,
    pub(super) local_records: Mutex<Vec<RecordEntry>>,
    /// Keyed by `(prefix-hash-hex, node_name-string)`.
    pub(super) body_store: Mutex<HashMap<(String, String), Bytes>>,
    /// Deduplicated on `(announced_prefix, node_name)`.
    pub(super) peer_records: Mutex<Vec<ServiceRecord>>,
    pub(super) rate_limits: Mutex<HashMap<String, ProducerRateLimit>>,
    pub(super) auto_fib: Mutex<Vec<AutoFibEntry>>,
    /// Keyed on the neighbor table (not face id) to avoid browsing
    /// management or app faces.
    pub(super) browsed_neighbors: Mutex<HashSet<Name>>,
    pub(super) last_browse: Mutex<Option<Instant>>,
    /// body Name -> (send_at, waiting senders). `send_at` is used to
    /// compute RTT when the Data arrives.
    #[allow(clippy::type_complexity)]
    pub(super) pending_fetches: Mutex<HashMap<String, (Instant, Vec<oneshot::Sender<Bytes>>)>>,
    /// `None` = unknown, `Some(true)` = body seen, `Some(false)` = missed.
    pub(super) has_body_map: Mutex<HashMap<(String, String), bool>>,
    pub(super) measurements: Mutex<MeasurementStore>,
}

impl ServiceDiscoveryProtocol {
    pub fn new(node_name: Name, root: Name, config: ServiceDiscoveryConfig) -> Self {
        let services = sd_services_under(&root);
        let service_info = sd_service_info_under(&root);
        let claimed = vec![services, service_info, peers_prefix().clone()];
        let measurements =
            MeasurementStore::new(config.measurement_capacity, config.measurement_idle_ttl);
        Self {
            node_name,
            root,
            config,
            claimed,
            local_records: Mutex::new(Vec::new()),
            body_store: Mutex::new(HashMap::new()),
            peer_records: Mutex::new(Vec::new()),
            rate_limits: Mutex::new(HashMap::new()),
            auto_fib: Mutex::new(Vec::new()),
            browsed_neighbors: Mutex::new(HashSet::new()),
            last_browse: Mutex::new(None),
            pending_fetches: Mutex::new(HashMap::new()),
            has_body_map: Mutex::new(HashMap::new()),
            measurements: Mutex::new(measurements),
        }
    }

    pub fn with_defaults(node_name: Name) -> Self {
        Self::new(
            node_name,
            sd_root().clone(),
            ServiceDiscoveryConfig::default(),
        )
    }

    /// Stale entries are evicted lazily on this call.
    pub fn measurements(&self, announced_prefix: &Name) -> Vec<ProviderMeasurement> {
        self.measurements
            .lock()
            .unwrap()
            .measurements(announced_prefix, Instant::now())
    }

    /// Body name under `<root>/service-info/` sharing the rendezvous
    /// record's `(prefix-hash, node, v=<ts>)` triple.
    pub fn body_name_for(&self, record: &ServiceRecord, timestamp_ms: u64) -> Name {
        use crate::prefix_announce::{make_body_name, make_record_name_under};
        let rendezvous = make_record_name_under(
            &self.root,
            &record.announced_prefix,
            &record.node_name,
            timestamp_ms,
        );
        make_body_name(&rendezvous, &self.root)
    }

    /// `None` = not yet observed; `Some(true)` = body fetched at least
    /// once; `Some(false)` = miss or decryption failure.
    pub fn provider_has_body(&self, announced_prefix: &Name, node_name: &Name) -> Option<bool> {
        use records::prefix_hash_hex;
        let k = (prefix_hash_hex(announced_prefix), node_name.to_string());
        self.has_body_map.lock().unwrap().get(&k).copied()
    }
}

impl DiscoveryProtocol for ServiceDiscoveryProtocol {
    fn protocol_id(&self) -> ProtocolId {
        PROTOCOL
    }

    fn claimed_prefixes(&self) -> &[Name] {
        &self.claimed
    }

    fn on_face_up(&self, _face_id: FaceId, _ctx: &dyn DiscoveryContext) {}

    fn on_face_down(&self, face_id: FaceId, ctx: &dyn DiscoveryContext) {
        {
            let mut local = self.local_records.lock().unwrap();
            let before = local.len();
            local.retain(|e| e.owner_face != Some(face_id));
            let removed = before - local.len();
            if removed > 0 {
                info!(face = ?face_id, count = removed, "ServiceDiscovery: withdrew local records for downed face");
            }
        }

        let affected: Vec<Name> = ctx
            .neighbors()
            .all()
            .into_iter()
            .filter(|e| e.faces.iter().any(|(fid, _, _)| *fid == face_id))
            .map(|e| e.node_name.clone())
            .collect();

        if !affected.is_empty() {
            let mut peer_recs = self.peer_records.lock().unwrap();
            peer_recs.retain(|r| !affected.contains(&r.node_name));
            debug!(
                nodes = ?affected.iter().map(|n| n.to_string()).collect::<Vec<_>>(),
                "ServiceDiscovery: evicted peer records for face-down nodes",
            );
        }

        let mut fib_removals: Vec<(Name, FaceId)> = Vec::new();
        {
            let mut auto_fib = self.auto_fib.lock().unwrap();
            auto_fib.retain(|e| {
                if e.face_id == face_id {
                    fib_removals.push((e.prefix.clone(), e.face_id));
                    false
                } else {
                    true
                }
            });
        }
        for (prefix, fid) in &fib_removals {
            ctx.remove_fib_entry(prefix, *fid, PROTOCOL);
        }
        if !fib_removals.is_empty() {
            debug!(count = fib_removals.len(), face = ?face_id, "ServiceDiscovery: removed auto-FIB entries for downed face");
        }

        if !affected.is_empty() {
            let mut seen = self.browsed_neighbors.lock().unwrap();
            for name in &affected {
                seen.remove(name);
            }
        }
    }

    fn on_inbound(
        &self,
        raw: &Bytes,
        incoming_face: FaceId,
        _meta: &InboundMeta,
        ctx: &dyn DiscoveryContext,
    ) -> bool {
        match raw.first() {
            Some(&0x05) => {
                if self.handle_sd_interest(raw, incoming_face, ctx) {
                    return true;
                }
                self.handle_peers_interest(raw, incoming_face, ctx)
            }
            Some(&0x06) => self.handle_sd_data(raw, incoming_face, ctx),
            _ => false,
        }
    }

    fn on_tick(&self, now: Instant, ctx: &dyn DiscoveryContext) {
        self.expire_auto_fib(now, ctx);
        self.expire_local_records(now);
        self.prune_rate_limits(now);
        self.prune_pending_fetches(now);
        let browse_interval = self.compute_browse_interval(now);
        self.browse_neighbors(now, browse_interval, ctx);
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::time::Duration;

    use super::*;
    use crate::wire::write_name_tlv;
    use crate::{MacAddr, NeighborTable};
    use ndn_tlv::TlvWriter;

    fn name(s: &str) -> Name {
        Name::from_str(s).unwrap()
    }

    fn make_sd() -> ServiceDiscoveryProtocol {
        ServiceDiscoveryProtocol::with_defaults(name("/ndn/test/node"))
    }

    #[test]
    fn publish_and_withdraw() {
        let sd = make_sd();
        let rec = ServiceRecord::new(name("/ndn/sensor/temp"), name("/ndn/test/node"));
        sd.publish(rec);
        {
            let records = sd.local_records.lock().unwrap();
            assert_eq!(records.len(), 1);
        }
        sd.withdraw(&name("/ndn/sensor/temp"));
        {
            let records = sd.local_records.lock().unwrap();
            assert!(records.is_empty());
        }
    }

    #[test]
    fn publish_replaces_existing() {
        let sd = make_sd();
        let rec1 = ServiceRecord {
            announced_prefix: name("/ndn/sensor/temp"),
            node_name: name("/ndn/test/node"),
            freshness_ms: 30_000,
            version: 0,
            capabilities: 0,
        };
        let mut rec2 = rec1.clone();
        rec2.freshness_ms = 60_000;
        sd.publish(rec1);
        sd.publish(rec2);
        let records = sd.local_records.lock().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].record.freshness_ms, 60_000);
    }

    #[test]
    fn claimed_prefixes_includes_sd_and_peers() {
        use crate::scope::{sd_root, sd_services_under};
        let sd = make_sd();
        let claimed = sd.claimed_prefixes();
        let expected_svc = sd_services_under(sd_root());
        assert!(
            claimed.iter().any(|p| p.has_prefix(&expected_svc)),
            "claimed should include the services prefix"
        );
        assert!(claimed.iter().any(|p| p == peers_prefix()));
    }

    #[test]
    fn decode_peer_list_roundtrip() {
        let mut w = TlvWriter::new();
        let n1 = name("/ndn/test/peer1");
        let n2 = name("/ndn/test/peer2");
        w.write_nested(0xE0, |w: &mut TlvWriter| {
            write_name_tlv(w, &n1);
        });
        w.write_nested(0xE0, |w: &mut TlvWriter| {
            write_name_tlv(w, &n2);
        });
        let content = w.finish();
        let decoded = decode_peer_list(&content);
        assert_eq!(decoded.len(), 2);
    }

    #[test]
    fn auto_fib_ttl_expiry_on_tick() {
        use crate::context::DiscoveryContext;
        use crate::{NeighborTableView, NeighborUpdate};
        use std::sync::{Arc, Mutex as StdMutex};

        struct TrackCtx {
            now: Instant,
            removed: StdMutex<Vec<Name>>,
        }
        impl ndn_discovery_core::FaceLifecycleContext for TrackCtx {
            fn alloc_face_id(&self) -> FaceId {
                FaceId(0)
            }
            fn add_face(&self, _: Arc<ndn_transport::Face>) -> FaceId {
                FaceId(0)
            }
            fn remove_face(&self, _: FaceId) {}
        }
        impl ndn_discovery_core::RoutingTableContext for TrackCtx {
            fn add_fib_entry(&self, _: &Name, _: FaceId, _: u32, _: ProtocolId) {}
            fn remove_fib_entry(&self, prefix: &Name, _: FaceId, _: ProtocolId) {
                self.removed.lock().unwrap().push(prefix.clone());
            }
            fn remove_fib_entries_by_owner(&self, _: ProtocolId) {}
        }
        impl ndn_discovery_core::NeighborContext for TrackCtx {
            fn neighbors(&self) -> Arc<dyn NeighborTableView> {
                NeighborTable::new()
            }
            fn update_neighbor(&self, _: NeighborUpdate) {}
        }
        impl DiscoveryContext for TrackCtx {
            fn send_on(&self, _: FaceId, _: Bytes) {}
            fn now(&self) -> Instant {
                self.now
            }
        }

        let sd = make_sd();
        let now = Instant::now();
        let ctx = TrackCtx {
            now,
            removed: StdMutex::new(Vec::new()),
        };

        // Manually insert an already-expired auto-FIB entry.
        {
            let mut af = sd.auto_fib.lock().unwrap();
            af.push(AutoFibEntry {
                prefix: name("/ndn/sensor/temp"),
                face_id: FaceId(7),
                expires_at: now - Duration::from_millis(1),
                node_name: name("/ndn/test/peer"),
            });
        }

        sd.on_tick(now, &ctx);
        let removed = ctx.removed.lock().unwrap();
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0], name("/ndn/sensor/temp"));
        assert!(sd.auto_fib.lock().unwrap().is_empty());
    }

    // ---- Audit-fix tests (auth / TTL / version / bounds) ----------------

    use std::sync::{Arc as StdArc, Mutex as StdMutex2};

    struct FibCtx {
        now: Instant,
        added: StdMutex2<Vec<(Name, FaceId, u32)>>,
    }
    impl FibCtx {
        fn at(now: Instant) -> Self {
            Self {
                now,
                added: StdMutex2::new(Vec::new()),
            }
        }
    }
    impl ndn_discovery_core::FaceLifecycleContext for FibCtx {
        fn alloc_face_id(&self) -> FaceId {
            FaceId(0)
        }
        fn add_face(&self, _: StdArc<ndn_transport::Face>) -> FaceId {
            FaceId(0)
        }
        fn remove_face(&self, _: FaceId) {}
    }
    impl ndn_discovery_core::RoutingTableContext for FibCtx {
        fn add_fib_entry(&self, p: &Name, f: FaceId, c: u32, _: ProtocolId) {
            self.added.lock().unwrap().push((p.clone(), f, c));
        }
        fn remove_fib_entry(&self, _: &Name, _: FaceId, _: ProtocolId) {}
        fn remove_fib_entries_by_owner(&self, _: ProtocolId) {}
    }
    impl ndn_discovery_core::NeighborContext for FibCtx {
        fn neighbors(&self) -> StdArc<dyn crate::context::NeighborTableView> {
            NeighborTable::new()
        }
        fn update_neighbor(&self, _: crate::NeighborUpdate) {}
    }
    impl crate::context::DiscoveryContext for FibCtx {
        fn send_on(&self, _: FaceId, _: Bytes) {}
        fn now(&self) -> Instant {
            self.now
        }
    }

    fn inbound_record(prefix: &str, node: &str, freshness_ms: u64, version: u64) -> Bytes {
        let rec = ServiceRecord {
            announced_prefix: name(prefix),
            node_name: name(node),
            freshness_ms,
            capabilities: 0,
            version,
        };
        rec.build_data(version.max(1))
    }

    #[test]
    fn fail_closed_no_verifier_skips_fib_but_browses() {
        // Default config (no verifier): an inbound record is stored for
        // browsing but installs NO FIB route (audit #1, headline).
        let sd = make_sd();
        let ctx = FibCtx::at(Instant::now());
        let pkt = inbound_record("/ndn/svc/x", "/ndn/peer/n", 30_000, 1);
        sd.on_inbound(&pkt, FaceId(10), &crate::InboundMeta::none(), &ctx);

        assert_eq!(sd.peer_records.lock().unwrap().len(), 1, "stored for browsing");
        assert!(
            ctx.added.lock().unwrap().is_empty(),
            "fail-closed: unverified record must not install FIB"
        );
    }

    #[test]
    fn verified_record_installs_fib() {
        // With a DigestVerifier configured, the (DigestSha256-signed)
        // record verifies and DOES auto-install a FIB route.
        let cfg = ServiceDiscoveryConfig {
            record_verifier: Some(StdArc::new(crate::DigestVerifier)),
            ..ServiceDiscoveryConfig::default()
        };
        let sd = ServiceDiscoveryProtocol::new(name("/ndn/test/node"), sd_root().clone(), cfg);
        let ctx = FibCtx::at(Instant::now());
        let pkt = inbound_record("/ndn/svc/x", "/ndn/peer/n", 30_000, 1);
        sd.on_inbound(&pkt, FaceId(10), &crate::InboundMeta::none(), &ctx);

        let added = ctx.added.lock().unwrap();
        assert_eq!(added.len(), 1, "verified record installs FIB");
        assert_eq!(added[0].0, name("/ndn/svc/x"));
    }

    #[test]
    fn fib_ttl_is_clamped() {
        // A forged huge freshness_ms cannot pin a route past max_ttl (#2).
        let cfg = ServiceDiscoveryConfig {
            record_verifier: Some(StdArc::new(crate::DigestVerifier)),
            auto_fib_max_ttl: Duration::from_secs(300),
            ..ServiceDiscoveryConfig::default()
        };
        let sd = ServiceDiscoveryProtocol::new(name("/ndn/test/node"), sd_root().clone(), cfg);
        let now = Instant::now();
        let ctx = FibCtx::at(now);
        let pkt = inbound_record("/ndn/svc/x", "/ndn/peer/n", u64::MAX, 1);
        sd.on_inbound(&pkt, FaceId(10), &crate::InboundMeta::none(), &ctx);

        let af = sd.auto_fib.lock().unwrap();
        assert_eq!(af.len(), 1);
        assert!(
            af[0].expires_at <= now + Duration::from_secs(300) + Duration::from_millis(1),
            "TTL must be clamped to auto_fib_max_ttl"
        );
    }

    #[test]
    fn anti_rollback_keeps_newer_version() {
        // A replayed older-version record cannot overwrite a newer one (#4).
        let sd = make_sd();
        let ctx = FibCtx::at(Instant::now());
        sd.on_inbound(
            &inbound_record("/ndn/svc/x", "/ndn/peer/n", 30_000, 5),
            FaceId(10),
            &crate::InboundMeta::none(),
            &ctx,
        );
        sd.on_inbound(
            &inbound_record("/ndn/svc/x", "/ndn/peer/n", 30_000, 3),
            FaceId(10),
            &crate::InboundMeta::none(),
            &ctx,
        );
        let recs = sd.peer_records.lock().unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].version, 5, "stale v3 must not overwrite v5");

        drop(recs);
        sd.on_inbound(
            &inbound_record("/ndn/svc/x", "/ndn/peer/n", 30_000, 9),
            FaceId(10),
            &crate::InboundMeta::none(),
            &ctx,
        );
        assert_eq!(sd.peer_records.lock().unwrap()[0].version, 9, "v9 upgrades v5");
    }

    #[test]
    fn rate_limit_map_is_bounded() {
        // A flood of distinct (attacker-chosen) identities cannot grow the
        // rate-limit map without bound (#3/#5).
        let cfg = ServiceDiscoveryConfig {
            max_rate_limit_entries: 16,
            ..ServiceDiscoveryConfig::default()
        };
        let sd = ServiceDiscoveryProtocol::new(name("/ndn/test/node"), sd_root().clone(), cfg);
        let now = Instant::now();
        for i in 0..1000u32 {
            let id = name(&format!("/ndn/attacker/{i}"));
            sd.check_rate_limit(&id, now);
        }
        assert!(
            sd.rate_limits.lock().unwrap().len() <= 16,
            "rate-limit map must stay within max_rate_limit_entries"
        );
    }

    #[test]
    fn peer_records_capped() {
        // peer_records is bounded by max_records_per_scope (#5).
        let cfg = ServiceDiscoveryConfig {
            max_records_per_scope: 8,
            ..ServiceDiscoveryConfig::default()
        };
        let sd = ServiceDiscoveryProtocol::new(name("/ndn/test/node"), sd_root().clone(), cfg);
        let ctx = FibCtx::at(Instant::now());
        for i in 0..50u32 {
            let pkt = inbound_record(&format!("/ndn/svc/{i}"), "/ndn/peer/n", 30_000, 1);
            sd.on_inbound(&pkt, FaceId(10), &crate::InboundMeta::none(), &ctx);
        }
        assert!(
            sd.peer_records.lock().unwrap().len() <= 8,
            "peer_records must stay within max_records_per_scope"
        );
    }

    #[test]
    fn relay_records_sends_to_other_peers() {
        use crate::context::DiscoveryContext;
        use crate::{
            NeighborEntry, NeighborState, NeighborTable, NeighborTableView, NeighborUpdate,
        };
        use std::sync::{Arc, Mutex as StdMutex};

        struct RelayCtx {
            neighbors: Arc<NeighborTable>,
            sent: StdMutex<Vec<(FaceId, Bytes)>>,
        }
        impl ndn_discovery_core::FaceLifecycleContext for RelayCtx {
            fn alloc_face_id(&self) -> FaceId {
                FaceId(99)
            }
            fn add_face(&self, _: Arc<ndn_transport::Face>) -> FaceId {
                FaceId(99)
            }
            fn remove_face(&self, _: FaceId) {}
        }
        impl ndn_discovery_core::RoutingTableContext for RelayCtx {
            fn add_fib_entry(&self, _: &Name, _: FaceId, _: u32, _: ProtocolId) {}
            fn remove_fib_entry(&self, _: &Name, _: FaceId, _: ProtocolId) {}
            fn remove_fib_entries_by_owner(&self, _: ProtocolId) {}
        }
        impl ndn_discovery_core::NeighborContext for RelayCtx {
            fn neighbors(&self) -> Arc<dyn NeighborTableView> {
                Arc::clone(&self.neighbors) as Arc<dyn NeighborTableView>
            }
            fn update_neighbor(&self, u: NeighborUpdate) {
                self.neighbors.apply(u);
            }
        }
        impl DiscoveryContext for RelayCtx {
            fn send_on(&self, face_id: FaceId, pkt: Bytes) {
                self.sent.lock().unwrap().push((face_id, pkt));
            }
            fn now(&self) -> Instant {
                Instant::now()
            }
        }

        let cfg = ServiceDiscoveryConfig {
            relay_records: true,
            auto_populate_fib: false, // keep test focused on relay only
            ..ServiceDiscoveryConfig::default()
        };
        let sd = ServiceDiscoveryProtocol::new(name("/ndn/test/node"), sd_root().clone(), cfg);

        let neighbors = NeighborTable::new();
        // Add two reachable neighbors with different faces.
        let mut e1 = NeighborEntry::new(name("/ndn/peer/a"));
        e1.state = NeighborState::Established {
            last_seen: Instant::now(),
        };
        e1.faces = vec![(FaceId(10), MacAddr([0u8; 6]), "eth0".into())];
        let mut e2 = NeighborEntry::new(name("/ndn/peer/b"));
        e2.state = NeighborState::Established {
            last_seen: Instant::now(),
        };
        e2.faces = vec![(FaceId(20), MacAddr([0u8; 6]), "eth0".into())];
        neighbors.apply(NeighborUpdate::Upsert(e1));
        neighbors.apply(NeighborUpdate::Upsert(e2));

        let ctx = RelayCtx {
            neighbors,
            sent: StdMutex::new(Vec::new()),
        };

        // Build a valid service record Data packet arriving on face 10.
        let rec = ServiceRecord {
            announced_prefix: name("/ndn/sensor/temp"),
            node_name: name("/ndn/peer/a"),
            freshness_ms: 10_000,
            capabilities: 0,
            version: 0,
        };
        let pkt = rec.build_data(1000);

        sd.on_inbound(&pkt, FaceId(10), &crate::InboundMeta::none(), &ctx);

        let sent = ctx.sent.lock().unwrap();
        // Should relay to face 20 (peer/b), not back to face 10 (source).
        assert!(
            sent.iter().any(|(fid, _)| *fid == FaceId(20)),
            "should relay to peer/b"
        );
        assert!(
            !sent.iter().any(|(fid, _)| *fid == FaceId(10)),
            "must not relay back to source face"
        );
    }

    struct BodyCtx {
        sent: std::sync::Mutex<Vec<(FaceId, Bytes)>>,
    }
    impl BodyCtx {
        fn new() -> Self {
            Self {
                sent: std::sync::Mutex::new(Vec::new()),
            }
        }
        fn drain_sent(&self) -> Vec<(FaceId, Bytes)> {
            self.sent.lock().unwrap().drain(..).collect()
        }
    }
    impl ndn_discovery_core::FaceLifecycleContext for BodyCtx {
        fn alloc_face_id(&self) -> FaceId {
            FaceId(0)
        }
        fn add_face(&self, _: std::sync::Arc<ndn_transport::Face>) -> FaceId {
            FaceId(0)
        }
        fn remove_face(&self, _: FaceId) {}
    }
    impl ndn_discovery_core::RoutingTableContext for BodyCtx {
        fn add_fib_entry(&self, _: &Name, _: FaceId, _: u32, _: ProtocolId) {}
        fn remove_fib_entry(&self, _: &Name, _: FaceId, _: ProtocolId) {}
        fn remove_fib_entries_by_owner(&self, _: ProtocolId) {}
    }
    impl ndn_discovery_core::NeighborContext for BodyCtx {
        fn neighbors(&self) -> std::sync::Arc<dyn crate::context::NeighborTableView> {
            crate::neighbor::NeighborTable::new()
        }
        fn update_neighbor(&self, _: crate::neighbor::NeighborUpdate) {}
    }
    impl crate::context::DiscoveryContext for BodyCtx {
        fn send_on(&self, fid: FaceId, pkt: Bytes) {
            self.sent.lock().unwrap().push((fid, pkt));
        }
        fn now(&self) -> Instant {
            Instant::now()
        }
    }

    #[test]
    fn r1b_new_publisher_new_finder_roundtrip() {
        let publisher = ServiceDiscoveryProtocol::with_defaults(name("/ndn/pub/node"));
        let finder = ServiceDiscoveryProtocol::with_defaults(name("/ndn/find/node"));

        let rec = ServiceRecord::new(name("/ndn/svc/alpha"), name("/ndn/pub/node"));
        let body_payload = Bytes::from_static(b"hello-body");
        publisher.publish_with_body(rec.clone(), body_payload.clone());

        // Finder receives a browse interest from publisher → publisher responds with rendezvous Data.
        let ctx = BodyCtx::new();
        let browse_interest = crate::prefix_announce::build_browse_interest();
        publisher.on_inbound(
            &browse_interest,
            FaceId(1),
            &crate::protocol::InboundMeta::none(),
            &ctx,
        );
        let sent = ctx.drain_sent();
        assert!(
            !sent.is_empty(),
            "publisher should respond to browse interest"
        );

        // Feed the rendezvous Data into the finder.
        let rendezvous_pkt = sent[0].1.clone();
        finder.on_inbound(
            &rendezvous_pkt,
            FaceId(2),
            &crate::protocol::InboundMeta::none(),
            &ctx,
        );

        // Finder now has the record in peer_records.
        assert!(!finder.peer_records.lock().unwrap().is_empty());

        // Compute the body name.
        let ts = publisher.local_records.lock().unwrap()[0].published_at_ms;
        let body_name = publisher.body_name_for(&rec, ts);

        // Build a body-fetch Interest and send it to the publisher.
        let body_interest = {
            use ndn_packet::encode::InterestBuilder;
            InterestBuilder::new(body_name.clone())
                .must_be_fresh()
                .lifetime(std::time::Duration::from_secs(4))
                .build()
        };
        let ctx2 = BodyCtx::new();
        publisher.on_inbound(
            &body_interest,
            FaceId(3),
            &crate::protocol::InboundMeta::none(),
            &ctx2,
        );
        let body_sent = ctx2.drain_sent();
        assert!(
            !body_sent.is_empty(),
            "publisher should respond to body Interest"
        );

        // Feed the body Data into the finder.
        // First, inject the peer record so the hook lookup works.
        finder.peer_records.lock().unwrap().push(rec.clone());
        let body_data = body_sent[0].1.clone();
        finder.on_inbound(
            &body_data,
            FaceId(4),
            &crate::protocol::InboundMeta::none(),
            &ctx,
        );

        // Verify has_body heuristic is set.
        assert_eq!(
            finder.provider_has_body(&rec.announced_prefix, &rec.node_name),
            Some(true)
        );
    }

    #[test]
    fn r1b_new_publisher_old_finder_compat() {
        let publisher = ServiceDiscoveryProtocol::with_defaults(name("/ndn/pub/node"));

        let rec = ServiceRecord::new(name("/ndn/svc/beta"), name("/ndn/pub/node"));
        publisher.publish_with_body(rec.clone(), Bytes::from_static(b"body-content"));

        // Old finder sees only the rendezvous Interest/Data exchange.
        let ctx = BodyCtx::new();
        let browse_interest = crate::prefix_announce::build_browse_interest();
        publisher.on_inbound(
            &browse_interest,
            FaceId(1),
            &crate::protocol::InboundMeta::none(),
            &ctx,
        );
        let sent = ctx.drain_sent();

        // Rendezvous Data is returned; old finder uses it without body fetch.
        assert!(!sent.is_empty(), "publisher responds with rendezvous Data");
        // Old finder does not call fetch_service_info — no assertion needed beyond the Data arriving.
    }

    #[test]
    fn r1b_old_publisher_new_finder_timeout_fallback() {
        let old_publisher = ServiceDiscoveryProtocol::with_defaults(name("/ndn/old/node"));
        let new_finder = ServiceDiscoveryProtocol::with_defaults(name("/ndn/find/node"));

        // Old publisher publishes rendezvous only (no body bytes).
        let rec = ServiceRecord::new(name("/ndn/svc/gamma"), name("/ndn/old/node"));
        old_publisher.publish(rec.clone());

        // New finder receives rendezvous.
        let ctx = BodyCtx::new();
        let browse_interest = crate::prefix_announce::build_browse_interest();
        old_publisher.on_inbound(
            &browse_interest,
            FaceId(1),
            &crate::protocol::InboundMeta::none(),
            &ctx,
        );
        let sent = ctx.drain_sent();
        assert!(!sent.is_empty());
        let rendezvous_pkt = sent[0].1.clone();
        new_finder.on_inbound(
            &rendezvous_pkt,
            FaceId(2),
            &crate::protocol::InboundMeta::none(),
            &ctx,
        );

        // New finder calls fetch_service_info — no faces reachable, so Interest is not sent.
        let ts = old_publisher.local_records.lock().unwrap()[0].published_at_ms;
        let body_name = new_finder.body_name_for(&rec, ts);
        let mut rx = new_finder.fetch_service_info(body_name, &ctx);

        // No body Data arrives → receiver remains open (old publisher has no body).
        // The finder detects via try_recv that no body is available and falls back.
        assert!(
            rx.try_recv().is_err(),
            "no body arrives: finder falls back to rendezvous"
        );
    }

    #[test]
    fn r1b_multi_root_disjoint() {
        use std::str::FromStr;

        let root_a = Name::from_str("/zone/a/sd").unwrap();
        let root_b = Name::from_str("/zone/b/sd").unwrap();

        let sd_a = ServiceDiscoveryProtocol::new(
            name("/ndn/node"),
            root_a.clone(),
            ServiceDiscoveryConfig::default(),
        );
        let _sd_b = ServiceDiscoveryProtocol::new(
            name("/ndn/node"),
            root_b.clone(),
            ServiceDiscoveryConfig::default(),
        );

        // Publish under root_a.
        let rec_a = ServiceRecord::new(name("/svc/a"), name("/ndn/node"));
        sd_a.publish(rec_a.clone());

        // Build a browse Interest for root_b's namespace.
        let browse_b = crate::prefix_announce::build_browse_interest_under(&root_b);
        let ctx = BodyCtx::new();
        // Send the root_b browse interest to sd_a — sd_a should NOT respond.
        sd_a.on_inbound(
            &browse_b,
            FaceId(1),
            &crate::protocol::InboundMeta::none(),
            &ctx,
        );
        let sent = ctx.drain_sent();
        assert!(
            sent.is_empty(),
            "sd_a must not respond to root_b browse interest"
        );

        // Send the root_a browse interest to sd_a — sd_a SHOULD respond.
        let browse_a = crate::prefix_announce::build_browse_interest_under(&root_a);
        sd_a.on_inbound(
            &browse_a,
            FaceId(1),
            &crate::protocol::InboundMeta::none(),
            &ctx,
        );
        let sent2 = ctx.drain_sent();
        assert!(
            !sent2.is_empty(),
            "sd_a must respond to its own root browse interest"
        );
    }

    #[test]
    fn r2_measurements_two_providers_sorted_with_p50() {
        use std::time::Duration;

        let sd = make_sd();
        let prefix = name("/ndn/svc/probe");
        let node_a = name("/ndn/site/node-a");
        let node_b = name("/ndn/site/node-b");

        // Empty store → empty result.
        assert!(sd.measurements(&prefix).is_empty());

        // Drive a few RTTs per provider via the protocol's store.
        let now = Instant::now();
        {
            let mut store = sd.measurements.lock().unwrap();
            for ms in [10, 20, 30] {
                store.record_rtt(&prefix, &node_a, Duration::from_millis(ms), now);
            }
            for ms in [50, 60, 70, 80, 90] {
                store.record_rtt(&prefix, &node_b, Duration::from_millis(ms), now);
            }
        }

        let out = sd.measurements(&prefix);
        assert_eq!(out.len(), 2);
        // Sorted by node_name string: "/ndn/site/node-a" < "/ndn/site/node-b".
        assert_eq!(out[0].node_name, node_a);
        assert_eq!(out[1].node_name, node_b);
        // p50 of [10, 20, 30] = element at index 1 of sorted = 20ms.
        assert_eq!(out[0].rtt_p50, Some(Duration::from_millis(20)));
        // p50 of [50, 60, 70, 80, 90] = index 2 = 70ms.
        assert_eq!(out[1].rtt_p50, Some(Duration::from_millis(70)));
        // last_rtt is the most recent sample.
        assert_eq!(out[0].last_rtt, Some(Duration::from_millis(30)));
        assert_eq!(out[1].last_rtt, Some(Duration::from_millis(90)));
    }

    #[test]
    fn r3_encryption_hook_roundtrip() {
        use crate::service_discovery::encryption::XorMaskHook;
        use std::sync::Arc;

        let hook = Arc::new(XorMaskHook(0xAB));
        let cfg = ServiceDiscoveryConfig {
            encryption_hook: hook,
            ..ServiceDiscoveryConfig::default()
        };
        let publisher =
            ServiceDiscoveryProtocol::new(name("/ndn/enc/node"), sd_root().clone(), cfg.clone());
        let finder = ServiceDiscoveryProtocol::new(name("/ndn/find/node"), sd_root().clone(), cfg);

        let rec = ServiceRecord::new(name("/ndn/enc/svc"), name("/ndn/enc/node"));
        let plaintext = Bytes::from_static(b"secret-body");
        publisher.publish_with_body(rec.clone(), plaintext.clone());

        // The body_store should hold the XOR-masked bytes, not plaintext.
        let hash_hex = {
            use records::prefix_hash_hex;
            prefix_hash_hex(&rec.announced_prefix)
        };
        let stored = publisher
            .body_store
            .lock()
            .unwrap()
            .get(&(hash_hex, rec.node_name.to_string()))
            .cloned();
        assert!(stored.is_some(), "body should be stored");
        assert_ne!(
            stored.as_deref(),
            Some(plaintext.as_ref()),
            "stored bytes should be wrapped"
        );

        // Build a body Interest and send to publisher.
        let ts = publisher.local_records.lock().unwrap()[0].published_at_ms;
        let body_name = publisher.body_name_for(&rec, ts);
        let body_interest = {
            use ndn_packet::encode::InterestBuilder;
            InterestBuilder::new(body_name)
                .must_be_fresh()
                .lifetime(std::time::Duration::from_secs(4))
                .build()
        };
        let ctx = BodyCtx::new();
        publisher.on_inbound(
            &body_interest,
            FaceId(1),
            &crate::protocol::InboundMeta::none(),
            &ctx,
        );
        let body_data_pkt = ctx.drain_sent().into_iter().next().unwrap().1;

        // Feed body Data into the finder. First inject the peer record so the hook can unwrap.
        finder.peer_records.lock().unwrap().push(rec.clone());
        finder.on_inbound(
            &body_data_pkt,
            FaceId(2),
            &crate::protocol::InboundMeta::none(),
            &ctx,
        );

        // has_body should be true after successful unwrap.
        assert_eq!(
            finder.provider_has_body(&rec.announced_prefix, &rec.node_name),
            Some(true)
        );
    }

    #[test]
    fn r3_decrypt_failure_drops_body() {
        use crate::service_discovery::encryption::AlwaysFailDecrypt;
        use std::sync::Arc;

        let hook = Arc::new(AlwaysFailDecrypt);
        let cfg = ServiceDiscoveryConfig {
            encryption_hook: hook,
            ..ServiceDiscoveryConfig::default()
        };
        let publisher = ServiceDiscoveryProtocol::with_defaults(name("/ndn/pub/node"));
        let finder = ServiceDiscoveryProtocol::new(name("/ndn/find/node"), sd_root().clone(), cfg);

        let rec = ServiceRecord::new(name("/ndn/svc/fail"), name("/ndn/pub/node"));
        publisher.publish_with_body(rec.clone(), Bytes::from_static(b"some-data"));

        let ts = publisher.local_records.lock().unwrap()[0].published_at_ms;
        let body_name = publisher.body_name_for(&rec, ts);
        let body_interest = {
            use ndn_packet::encode::InterestBuilder;
            InterestBuilder::new(body_name)
                .must_be_fresh()
                .lifetime(std::time::Duration::from_secs(4))
                .build()
        };
        let ctx = BodyCtx::new();
        publisher.on_inbound(
            &body_interest,
            FaceId(1),
            &crate::protocol::InboundMeta::none(),
            &ctx,
        );
        let body_data_pkt = ctx.drain_sent().into_iter().next().unwrap().1;

        // Inject peer record into finder.
        finder.peer_records.lock().unwrap().push(rec.clone());
        finder.on_inbound(
            &body_data_pkt,
            FaceId(2),
            &crate::protocol::InboundMeta::none(),
            &ctx,
        );

        // Decryption failure: has_body should be false (marked as miss).
        assert_eq!(
            finder.provider_has_body(&rec.announced_prefix, &rec.node_name),
            Some(false)
        );
        // Measurements should not be corrupted.
        let ms = finder.measurements(&rec.announced_prefix);
        assert!(
            ms.is_empty(),
            "no RTT should be recorded on decrypt failure"
        );
    }
}
