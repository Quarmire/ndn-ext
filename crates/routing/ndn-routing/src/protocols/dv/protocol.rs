//! `DvProtocol` — ndn-dv top-level [`RoutingProtocol`] implementation.
//!
//! Owns the three pure-logic modules ([`DvSync`], [`DvRib`],
//! [`PrefixTable`]) and orchestrates them under a single tokio task
//! tree rooted at the engine-supplied [`CancellationToken`].
//!
//! Hybrid engine integration: [`DiscoveryProtocol`] for Sync I/O
//! (passive face binding, per-face fan-out), `ndn-app` Consumer/Producer
//! for named-Data Adv / Pfx fetch+serve.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use ndn_app::{Consumer, Producer};
use ndn_mgmt_wire::control_parameters::origin;
use ndn_mgmt_wire::control_parameters::route_flags;
use ndn_discovery::{
    DiscoveryContext, DiscoveryProtocol, InboundMeta, NeighborTableView, ProtocolId,
};
use ndn_engine::observability::targets as t;
use ndn_engine::rib::RibRoute;
use ndn_engine::{
    ConfigError, ConfigUpdate, RoutingHandle, RoutingProtocol, RoutingProtocolStatus,
};
use ndn_face::local::InProcHandle;
use ndn_packet::{Interest, Name};
use ndn_transport::FaceId;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, trace, warn};

use crate::protocols::dv::fib::{FibUpdate, NextHop, compute_fib_updates};
use crate::protocols::dv::pfx_sync::DvPfxSync;
use crate::protocols::dv::prefix::PrefixTable;
use crate::protocols::dv::rib::DvRib;
use crate::protocols::dv::sync::{DvSync, SyncKind};
use crate::protocols::dv::tlv::{Advertisement, PrefixOpList};
use ndn_sync::NeighborAdvance;

/// Protocol identifier used in `DiscoveryProtocol::protocol_id`.
pub const DV_PROTOCOL_ID: ProtocolId = ProtocolId("ndn-dv");

/// How long a passive-incoming face remains a valid send target for
/// passive Sync Interest emission, in the absence of further passive
/// syncs from that face. Roughly 4× the default sync interval —
/// matches ndnd's "RouterDeadInterval" mental model for passive bindings.
const PASSIVE_FACE_TTL: Duration = Duration::from_secs(120);

/// Defaults match `ndnd/dv/config/config.go`.
#[derive(Clone, Debug)]
pub struct DvConfig {
    /// Network root prefix — used to build sync Interest names
    /// `/localhop/<network>/32=DV/32=ADS/{ACT,PSV}`.
    pub network: Name,
    pub router: Name,
    /// Router startup time in milliseconds since the Unix epoch, per
    /// SPEC.md §2. Carried in Advertisement Data names as the `t=<boot>`
    /// component and inside the SVS v3 state vector.
    pub boot: u64,
    /// ndnd's `AdvertSyncInterval`. Default 30 s.
    pub adv_sync_interval: Duration,
    /// Periodic prefix-sync broadcast when no change is pending.
    /// Default 30 s.
    pub pfx_sync_interval: Duration,
    /// Silent-neighbour timeout; on expiry the binding is dropped and
    /// routes via that neighbour are pruned. Default 60 s
    /// (≈ 2× sync interval, matching ndnd).
    pub router_dead_interval: Duration,
}

impl DvConfig {
    /// Construct a config with defaults matching ndnd.
    pub fn new(network: Name, router: Name, boot: u64) -> Self {
        Self {
            network,
            router,
            boot,
            adv_sync_interval: Duration::from_secs(30),
            pfx_sync_interval: Duration::from_secs(30),
            router_dead_interval: Duration::from_secs(60),
        }
    }
}

/// Top-level ndn-dv protocol. Composes the pure-logic building
/// blocks ([`DvSync`], [`DvRib`], [`PrefixTable`]) and registers
/// with the engine via [`RoutingProtocol`].
///
/// Wrap in `Arc` (returned from [`Self::new`]); the `Arc` is shared
/// between the engine's routing registry and any caller that needs
/// to introspect or drive the protocol (e.g. mgmt verb handlers).
pub struct DvProtocol {
    config: DvConfig,
    /// Runtime-mutable interval overrides for `verb::DVR_CONFIG`.
    /// `on_tick` reads these atomics rather than `self.config.*` so
    /// operators can edit cadence without restarting the forwarder.
    adv_sync_interval_ms: AtomicU64,
    pfx_sync_interval_ms: AtomicU64,
    /// `Arc<_>` so the dead-neighbour loop spawned in `start()` reads
    /// live values across the cancellation token.
    router_dead_interval_ms: Arc<AtomicU64>,
    sync: Arc<DvSync>,
    /// Shares the router boot timestamp with [`sync`] but tracks an
    /// independent sequence number (per SPEC.md §4: separate group).
    pfx_sync: Arc<DvPfxSync>,
    rib: Arc<DvRib>,
    prefix_table: Arc<PrefixTable>,
    /// Active + passive Sync Interest prefixes for `DiscoveryProtocol`.
    claimed: Vec<Name>,
    last_active_emit: Mutex<Option<Instant>>,
    last_passive_emit: Mutex<Option<Instant>>,
    last_pfx_emit: Mutex<Option<Instant>>,
    /// Faces from which we recently received a passive Sync Interest;
    /// our passive Sync is sent back on these. Entries older than
    /// `PASSIVE_FACE_TTL` are pruned at emit time. Mirrors ndnd's
    /// `passive` neighbour-binding behaviour.
    passive_faces: RwLock<HashMap<FaceId, Instant>>,
    /// Unbounded because back-pressure on sync ingress would drop
    /// packets and break the protocol; the fetcher dedupes by
    /// `(name, boot, seq)`.
    advance_tx: mpsc::UnboundedSender<NeighborAdvance>,
    advance_rx: Mutex<Option<mpsc::UnboundedReceiver<NeighborAdvance>>>,
    /// Caller supplies via [`with_io`]; consumed by `start()`. `None`
    /// disables the fetch task (test-only `new()` constructor).
    fetch_handle: Mutex<Option<InProcHandle>>,
    /// `None` disables the producer task.
    produce_handle: Mutex<Option<InProcHandle>>,
    /// Paired with `produce_handle`'s InProcFace; `start()` installs a
    /// FIB entry routing the advertisement-data prefix here.
    produce_face_id: Option<FaceId>,
    /// Sites mutating `DvRib` or `PrefixTable` call `notify_waiters()`;
    /// the FIB-updater task awaits `notified()` to trigger a recompute.
    notify_recompute: Arc<tokio::sync::Notify>,
    /// Independent from `advance_tx` so the two protocol legs don't
    /// share queue state.
    pfx_advance_tx: mpsc::UnboundedSender<NeighborAdvance>,
    pfx_advance_rx: Mutex<Option<mpsc::UnboundedReceiver<NeighborAdvance>>>,
}

impl DvProtocol {
    /// Test-only constructor: no I/O wiring; `start()` will not spawn
    /// the fetcher/producer tasks. Use [`with_io`] in production.
    pub fn new(config: DvConfig) -> Arc<Self> {
        Self::build(
            config,
            None,
            None,
            None,
            crate::protocols::dv::signing::InsecureTrust::handle(),
        )
    }

    /// Like [`new`] but threads a custom
    /// [`crate::protocols::dv::signing::DvTrust`].
    pub fn new_with_trust(
        config: DvConfig,
        trust: crate::protocols::dv::signing::DvTrustHandle,
    ) -> Arc<Self> {
        Self::build(config, None, None, None, trust)
    }

    /// Production constructor. The caller creates two
    /// [`ndn_face::local::InProcFace`] pairs (outgoing fetches, serving
    /// incoming fetches), installs the engine-side halves via
    /// [`ndn_engine::EngineBuilder::face`], and passes the application
    /// handles plus the producer face id here. `start()` installs a FIB
    /// entry routing `/localhop/<self>/32=DV/32=ADV` to the producer face.
    pub fn with_io(
        config: DvConfig,
        fetch_handle: InProcHandle,
        produce_handle: InProcHandle,
        produce_face_id: FaceId,
    ) -> Arc<Self> {
        Self::build(
            config,
            Some(fetch_handle),
            Some(produce_handle),
            Some(produce_face_id),
            crate::protocols::dv::signing::InsecureTrust::handle(),
        )
    }

    /// Like [`with_io`] with a custom
    /// [`crate::protocols::dv::signing::DvTrust`].
    pub fn with_io_and_trust(
        config: DvConfig,
        fetch_handle: InProcHandle,
        produce_handle: InProcHandle,
        produce_face_id: FaceId,
        trust: crate::protocols::dv::signing::DvTrustHandle,
    ) -> Arc<Self> {
        Self::build(
            config,
            Some(fetch_handle),
            Some(produce_handle),
            Some(produce_face_id),
            trust,
        )
    }

    fn build(
        config: DvConfig,
        fetch_handle: Option<InProcHandle>,
        produce_handle: Option<InProcHandle>,
        produce_face_id: Option<FaceId>,
        trust: crate::protocols::dv::signing::DvTrustHandle,
    ) -> Arc<Self> {
        let sync = Arc::new(DvSync::with_trust(
            config.network.clone(),
            config.router.clone(),
            config.boot,
            Arc::clone(&trust),
        ));
        let pfx_sync = Arc::new(DvPfxSync::with_trust(
            config.network.clone(),
            config.router.clone(),
            config.boot,
            trust,
        ));
        let rib = Arc::new(DvRib::new(config.router.clone()));
        let prefix_table = Arc::new(PrefixTable::new(config.router.clone()));
        let claimed = vec![sync.active_sync_prefix(), sync.passive_sync_prefix()];
        let (advance_tx, advance_rx) = mpsc::unbounded_channel();
        let (pfx_advance_tx, pfx_advance_rx) = mpsc::unbounded_channel();
        let adv_ms = config.adv_sync_interval.as_millis() as u64;
        let pfx_ms = config.pfx_sync_interval.as_millis() as u64;
        let dead_ms = config.router_dead_interval.as_millis() as u64;
        Arc::new(Self {
            config,
            adv_sync_interval_ms: AtomicU64::new(adv_ms),
            pfx_sync_interval_ms: AtomicU64::new(pfx_ms),
            router_dead_interval_ms: Arc::new(AtomicU64::new(dead_ms)),
            sync,
            pfx_sync,
            rib,
            prefix_table,
            claimed,
            last_active_emit: Mutex::new(None),
            last_passive_emit: Mutex::new(None),
            last_pfx_emit: Mutex::new(None),
            passive_faces: RwLock::new(HashMap::new()),
            advance_tx,
            advance_rx: Mutex::new(Some(advance_rx)),
            fetch_handle: Mutex::new(fetch_handle),
            produce_handle: Mutex::new(produce_handle),
            produce_face_id,
            pfx_advance_tx,
            pfx_advance_rx: Mutex::new(Some(pfx_advance_rx)),
            notify_recompute: Arc::new(tokio::sync::Notify::new()),
        })
    }

    pub fn config(&self) -> &DvConfig {
        &self.config
    }

    pub fn sync(&self) -> &Arc<DvSync> {
        &self.sync
    }

    pub fn pfx_sync(&self) -> &Arc<DvPfxSync> {
        &self.pfx_sync
    }

    pub fn rib(&self) -> &Arc<DvRib> {
        &self.rib
    }

    pub fn prefix_table(&self) -> &Arc<PrefixTable> {
        &self.prefix_table
    }

    fn classify_sync_interest(&self, raw: &Bytes) -> Option<SyncKind> {
        let interest = Interest::decode(raw.clone()).ok()?;
        let name = &interest.name;
        if name.has_prefix(&self.sync.active_sync_prefix()) {
            Some(SyncKind::Active)
        } else if name.has_prefix(&self.sync.passive_sync_prefix()) {
            Some(SyncKind::Passive)
        } else {
            None
        }
    }

    /// Per SPEC §4 *Advertisement Broadcast*, active syncs go to
    /// "neighbours explicitly registered" — every neighbour the
    /// engine's `NeighborTable` knows about.
    fn emit_active_sync(&self, neighbors: &Arc<dyn NeighborTableView>, ctx: &dyn DiscoveryContext) {
        let interest = self.sync.build_sync_interest(SyncKind::Active);
        let all = neighbors.all();
        if all.is_empty() {
            trace!(target: t::ROUTING_DV, "no neighbours — skipping active sync emission");
            return;
        }
        for neighbor in &all {
            for (face_id, _, _) in &neighbor.faces {
                ctx.send_on(*face_id, interest.clone());
                trace!(
                    target: t::ROUTING_DV,
                    neighbor = %neighbor.node_name,
                    face = face_id.0,
                    "active sync sent",
                );
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn build_adv_data_response(&self, requested: &Name) -> Option<Bytes> {
        build_adv_data_response(&self.sync, &self.rib, requested)
    }

    /// Pfx Sync emission lives here in `on_tick` rather than in a
    /// separate tokio task so we don't share the fetch `Consumer`
    /// between fetch-and-await flow and fire-and-forget send (which
    /// could leak Nack responses into a concurrent fetch's recv path).
    fn emit_pfx_sync(&self, neighbors: &Arc<dyn NeighborTableView>, ctx: &dyn DiscoveryContext) {
        let interest = self.pfx_sync.build_sync_interest();
        let all = neighbors.all();
        if all.is_empty() {
            return;
        }
        for neighbor in &all {
            for (face_id, _, _) in &neighbor.faces {
                ctx.send_on(*face_id, interest.clone());
            }
        }
    }

    /// Build and fan-out a passive Sync Interest to every face we've
    /// recently received passive syncs from. Per SPEC §4 *Advertisement
    /// Broadcast*: "Passive Advertisement Sync Interests are sent to
    /// all neighbours, on the incoming face of the neighbour's Sync
    /// Interest." Expired bindings (`PASSIVE_FACE_TTL`) are pruned
    /// in place.
    fn emit_passive_sync(&self, ctx: &dyn DiscoveryContext) {
        let now = ctx.now();
        let mut passive = self
            .passive_faces
            .write()
            .expect("DvProtocol::passive_faces poisoned");
        passive.retain(|_face, last_seen| now.duration_since(*last_seen) < PASSIVE_FACE_TTL);
        if passive.is_empty() {
            trace!(target: t::ROUTING_DV, "no passive faces — skipping passive sync emission");
            return;
        }
        let interest = self.sync.build_sync_interest(SyncKind::Passive);
        for face_id in passive.keys() {
            ctx.send_on(*face_id, interest.clone());
            trace!(
                target: t::ROUTING_DV,
                face = face_id.0,
                "passive sync sent",
            );
        }
    }
}

impl DiscoveryProtocol for DvProtocol {
    fn protocol_id(&self) -> ProtocolId {
        DV_PROTOCOL_ID
    }

    fn claimed_prefixes(&self) -> &[Name] {
        &self.claimed
    }

    fn on_face_up(&self, _face_id: FaceId, _ctx: &dyn DiscoveryContext) {
        // Active sync to the new face emits on the next `on_tick`
        // once the engine's NeighborTable surfaces it.
    }

    fn on_face_down(&self, face_id: FaceId, _ctx: &dyn DiscoveryContext) {
        let mut passive = self
            .passive_faces
            .write()
            .expect("DvProtocol::passive_faces poisoned");
        passive.remove(&face_id);
    }

    fn on_inbound(
        &self,
        raw: &Bytes,
        incoming_face: FaceId,
        _meta: &InboundMeta,
        ctx: &dyn DiscoveryContext,
    ) -> bool {
        let Some(kind) = self.classify_sync_interest(raw) else {
            return false; // not a sync Interest; let the pipeline handle it.
        };

        let receipt = match self.sync.process_sync_interest(raw, incoming_face, kind) {
            Ok(r) => r,
            Err(e) => {
                debug!(
                    target: t::ROUTING_DV,
                    face = incoming_face.0,
                    err = %e,
                    "sync parse failed",
                );
                return false;
            }
        };

        for advance in &receipt.advances {
            debug!(
                target: t::ROUTING_DV,
                neighbor = %advance.name,
                boot = advance.boot,
                seq = advance.seq,
                "neighbour seq advanced — enqueuing Adv Data fetch",
            );
            // Best-effort: at shutdown the fetcher is gone and the
            // advance is dropped, which is correct.
            let _ = self.advance_tx.send(advance.clone());
        }
        for change in &receipt.face_changes {
            debug!(
                target: t::ROUTING_DV,
                neighbor = %change.neighbor,
                old = ?change.old_face.map(|f| f.0),
                new = change.new_face.0,
                active = change.now_active,
                "neighbour face binding changed",
            );
            // Install (or rebind) a bootstrap FIB entry that routes
            // the peer's Advertisement Data fetches to the face the
            // sync arrived on. Without this, the first
            // `consumer.fetch(/localhop/<peer>/DV/ADV/...)` in
            // `fetcher_loop` has no FIB entry. ndnd achieves the same
            // via /localhop multicast across all neighbour faces;
            // we install per-peer for spec-precise routing.
            let adv_prefix = DvSync::peer_advertisement_data_prefix(&change.neighbor);
            if let Some(old) = change.old_face
                && old != change.new_face
            {
                ctx.remove_fib_entry(&adv_prefix, old, DV_PROTOCOL_ID);
            }
            ctx.add_fib_entry(&adv_prefix, change.new_face, 0, DV_PROTOCOL_ID);
        }

        // Remember passive-incoming faces so subsequent ticks fan
        // our own passive syncs back on them.
        if kind == SyncKind::Passive {
            let mut passive = self
                .passive_faces
                .write()
                .expect("DvProtocol::passive_faces poisoned");
            passive.insert(incoming_face, ctx.now());
        }
        true
    }

    fn on_tick(&self, now: Instant, ctx: &dyn DiscoveryContext) {
        let interval = Duration::from_millis(self.adv_sync_interval_ms.load(Ordering::Relaxed));
        let neighbors = ctx.neighbors();

        let should_send_active = self
            .last_active_emit
            .lock()
            .expect("DvProtocol::last_active_emit poisoned")
            .is_none_or(|t| now.duration_since(t) >= interval);
        if should_send_active {
            self.emit_active_sync(&neighbors, ctx);
            *self.last_active_emit.lock().unwrap() = Some(now);
        }

        let should_send_passive = self
            .last_passive_emit
            .lock()
            .expect("DvProtocol::last_passive_emit poisoned")
            .is_none_or(|t| now.duration_since(t) >= interval);
        if should_send_passive {
            self.emit_passive_sync(ctx);
            *self.last_passive_emit.lock().unwrap() = Some(now);
        }

        let pfx_interval = Duration::from_millis(self.pfx_sync_interval_ms.load(Ordering::Relaxed));
        let should_send_pfx = self
            .last_pfx_emit
            .lock()
            .expect("DvProtocol::last_pfx_emit poisoned")
            .is_none_or(|t| now.duration_since(t) >= pfx_interval);
        if should_send_pfx {
            self.emit_pfx_sync(&neighbors, ctx);
            *self.last_pfx_emit.lock().unwrap() = Some(now);
        }
    }

    fn tick_interval(&self) -> Duration {
        // Poll at 1 s; emissions are gated above by `adv_sync_interval`.
        Duration::from_secs(1)
    }
}

impl RoutingProtocol for DvProtocol {
    fn origin(&self) -> u64 {
        ndn_mgmt_wire::control_parameters::origin::DVR
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    /// Counter shape mirrors ndnd's `dv status`
    /// (`ndnd/tools/dvc/dvc_status.go`): network / router /
    /// RIB-entries / neighbour count / FIB-entries.
    /// The same struct backs `verb::DVR_STATUS` and the GET half of
    /// `verb::DVR_CONFIG`, so runtime-mutable intervals
    /// (`adv_sync_secs`, `pfx_sync_secs`, `router_dead_secs`) ride
    /// in `fields`.
    fn status(&self) -> RoutingProtocolStatus {
        let rib_size = self.rib.snapshot().len();
        let neighbor_count = self.sync.tracked_neighbor_count();
        let pfx_table_size = self.prefix_table.snap().adds.len();

        let mut s = RoutingProtocolStatus::empty(ndn_mgmt_wire::control_parameters::origin::DVR);
        s.network = Some(self.config.network.clone());
        s.router = Some(self.config.router.clone());
        s.fields
            .insert("boot".to_owned(), self.sync.boot().to_string());
        s.fields
            .insert("adv_seq".to_owned(), self.sync.current_seq().to_string());
        s.fields.insert(
            "pfx_seq".to_owned(),
            self.pfx_sync.current_seq().to_string(),
        );
        s.fields.insert(
            "adv_sync_secs".to_owned(),
            (self.adv_sync_interval_ms.load(Ordering::Relaxed) / 1000).to_string(),
        );
        s.fields.insert(
            "pfx_sync_secs".to_owned(),
            (self.pfx_sync_interval_ms.load(Ordering::Relaxed) / 1000).to_string(),
        );
        s.fields.insert(
            "router_dead_secs".to_owned(),
            (self.router_dead_interval_ms.load(Ordering::Relaxed) / 1000).to_string(),
        );
        s.counters.insert("nRibEntries".to_owned(), rib_size as u64);
        s.counters
            .insert("nNeighbors".to_owned(), neighbor_count as u64);
        s.counters
            .insert("nPrefixEntries".to_owned(), pfx_table_size as u64);
        s
    }

    /// Atomic stores happen only after every field is accepted, so a
    /// failure leaves the protocol unchanged.
    ///
    /// Keys: `adv_sync_secs`, `pfx_sync_secs`, `router_dead_secs`.
    /// Values parse as `u64` in `1..=3600` — the one-hour cap prevents
    /// a `0` typo silently disabling the protocol.
    fn apply_config(&self, update: &ConfigUpdate) -> Result<usize, ConfigError> {
        let mut parsed: Vec<(&str, u64)> = Vec::with_capacity(update.fields.len());
        for (k, v) in &update.fields {
            let key = match k.as_str() {
                "adv_sync_secs" | "pfx_sync_secs" | "router_dead_secs" => k.as_str(),
                _ => return Err(ConfigError::UnknownKey(k.clone())),
            };
            let secs: u64 = v.parse().map_err(|_| ConfigError::BadValue {
                key: k.clone(),
                value: v.clone(),
                reason: "not a non-negative integer".to_owned(),
            })?;
            if !(1..=3600).contains(&secs) {
                return Err(ConfigError::BadValue {
                    key: k.clone(),
                    value: v.clone(),
                    reason: "must be in 1..=3600".to_owned(),
                });
            }
            parsed.push((key, secs));
        }
        for (k, secs) in &parsed {
            let ms = *secs * 1000;
            let atomic = match *k {
                "adv_sync_secs" => &self.adv_sync_interval_ms,
                "pfx_sync_secs" => &self.pfx_sync_interval_ms,
                "router_dead_secs" => self.router_dead_interval_ms.as_ref(),
                _ => unreachable!(),
            };
            atomic.store(ms, Ordering::Relaxed);
        }
        Ok(parsed.len())
    }

    /// Spawns the fetcher and producer tasks if `with_io` provided
    /// InProcHandles; otherwise the task tree is empty. The returned
    /// `JoinHandle` resolves when `cancel` fires.
    fn start(&self, handle: RoutingHandle, cancel: CancellationToken) -> ndn_runtime::TaskHandle {
        let router = self.config.router.clone();

        // Install FIB entries for our served prefixes so peer fetches
        // and incoming Pfx Sync Interests arrive at the producer face.
        if let Some(face_id) = self.produce_face_id {
            let adv_prefix = self.sync.advertisement_data_prefix();
            handle.fib.add_nexthop(&adv_prefix, face_id, 0);
            let pfx_data_prefix = self.pfx_sync.prefix_data_prefix();
            handle.fib.add_nexthop(&pfx_data_prefix, face_id, 0);
            let pfx_sync_group = self.pfx_sync.sync_group_prefix();
            handle.fib.add_nexthop(&pfx_sync_group, face_id, 0);
            debug!(
                target: t::ROUTING_DV,
                adv = %adv_prefix,
                pfx_data = %pfx_data_prefix,
                pfx_sync = %pfx_sync_group,
                face = face_id.0,
                "FIB entries installed for DV-served prefixes",
            );
        }

        let fetch_handle = self.fetch_handle.lock().unwrap().take();
        let produce_handle = self.produce_handle.lock().unwrap().take();
        let advance_rx = self
            .advance_rx
            .lock()
            .unwrap()
            .take()
            .expect("DvProtocol::start() called twice — advance_rx already taken");
        let pfx_advance_rx = self
            .pfx_advance_rx
            .lock()
            .unwrap()
            .take()
            .expect("DvProtocol::start() called twice — pfx_advance_rx already taken");

        let sync = Arc::clone(&self.sync);
        let pfx_sync = Arc::clone(&self.pfx_sync);
        let rib = Arc::clone(&self.rib);
        let prefix_table = Arc::clone(&self.prefix_table);
        let pfx_advance_tx_for_producer = self.pfx_advance_tx.clone();
        let notify_recompute = Arc::clone(&self.notify_recompute);
        let network = self.config.network.clone();

        let engine_rib = Arc::clone(&handle.rib);
        let engine_fib = Arc::clone(&handle.fib);
        let dead_interval_ms = Arc::clone(&self.router_dead_interval_ms);

        tokio::spawn(async move {
            info!(target: t::ROUTING_DV, router = %router, "ndn-dv starting");

            // One fetcher task drains both adv and pfx advance queues
            // on a single Consumer. Fetches are serialised — one
            // NdnConnection can't correlate concurrent fetches without
            // PIT tokens (ndn-app limitation).
            let fetcher_task = fetch_handle.map(|h| {
                let cancel = cancel.child_token();
                let pfx_sync = Arc::clone(&pfx_sync);
                let rib = Arc::clone(&rib);
                let prefix_table = Arc::clone(&prefix_table);
                let notify_recompute = Arc::clone(&notify_recompute);
                tokio::spawn(fetcher_loop(
                    h,
                    advance_rx,
                    pfx_advance_rx,
                    pfx_sync,
                    rib,
                    prefix_table,
                    notify_recompute,
                    cancel,
                ))
            });

            // One producer task serves Adv Data, Pfx Data, and
            // receives incoming Pfx Sync Interests (dispatch by name).
            let producer_task = produce_handle.map(|h| {
                let cancel = cancel.child_token();
                let sync = Arc::clone(&sync);
                let pfx_sync = Arc::clone(&pfx_sync);
                let rib = Arc::clone(&rib);
                let prefix_table = Arc::clone(&prefix_table);
                tokio::spawn(producer_loop(
                    h,
                    sync,
                    pfx_sync,
                    rib,
                    prefix_table,
                    pfx_advance_tx_for_producer,
                    cancel,
                ))
            });

            // FIB-updater is always spawned — the engine RIB is the
            // authoritative target for our routes regardless of
            // whether fetcher/producer are wired. Idles on
            // `notify_recompute` when nothing is changing.
            let fib_updater_task = {
                let cancel = cancel.child_token();
                let sync = Arc::clone(&sync);
                let rib = Arc::clone(&rib);
                let prefix_table = Arc::clone(&prefix_table);
                let notify_recompute = Arc::clone(&notify_recompute);
                tokio::spawn(fib_updater_loop(
                    sync,
                    rib,
                    prefix_table,
                    engine_rib,
                    engine_fib,
                    network,
                    notify_recompute,
                    cancel,
                ))
            };

            // Dead-neighbour ticker is only meaningful when I/O is
            // wired — without sync updates `last_seen` never bumps
            // and everything looks "dead".
            let dead_neighbor_task = if fetcher_task.is_some() {
                let cancel = cancel.child_token();
                let sync = Arc::clone(&sync);
                let rib = Arc::clone(&rib);
                let notify = Arc::clone(&notify_recompute);
                Some(tokio::spawn(dead_neighbor_loop(
                    sync,
                    rib,
                    dead_interval_ms,
                    notify,
                    cancel,
                )))
            } else {
                None
            };

            cancel.cancelled().await;
            if let Some(t) = fetcher_task {
                let _ = t.await;
            }
            if let Some(t) = producer_task {
                let _ = t.await;
            }
            let _ = fib_updater_task.await;
            if let Some(t) = dead_neighbor_task {
                let _ = t.await;
            }
            info!(target: t::ROUTING_DV, router = %router, "ndn-dv stopped");
        })
        .into()
    }
}

/// Build a Data response for an incoming Advertisement Data fetch,
/// or `None` if the requested name doesn't match our current
/// `(boot, seq)`. Only the current advertisement is served; older
/// versions are not retained (ndnd's `MemoryFifoDir` replay isn't
/// mirrored). Signing flows through [`DvSync::trust`].
///
/// ndnd's consumer expresses Interest at the segmented path
/// `/.../t=<boot>/v=<seq>/seg=0`; we reply with a single-segment
/// Data carrying `FinalBlockId=seg=0`. Content is the bare AdvEntry
/// sequence (no outer 0xC9 wrapper), matching
/// `AdvertisementEncoder::EncodeInto` in
/// `ndnd/dv/tlv/zz_generated.go:244`.
fn build_adv_data_response(sync: &DvSync, rib: &DvRib, requested: &Name) -> Option<Bytes> {
    let boot = sync.boot();
    let seq = sync.current_seq();
    let object_prefix = sync.advertisement_data_name(boot, seq);
    let expected = object_prefix.append_segment(0);
    if requested != &expected {
        return None;
    }
    let content = rib.produce_advertisement().encode_content();
    Some(crate::protocols::dv::signing::encode_inner_segmented_data(
        &expected,
        &content,
        0,
        sync.trust().as_ref(),
    ))
}

/// Snapshot-only: the served Data always carries the full current
/// state of `prefix_table` as a Reset+Adds PrefixOpList. Same
/// rdr_2024 segmentation and bare-content convention as Adv Data.
/// Returns `None` if the requested name doesn't match our current
/// `(boot, seq)` in the Pfx Sync group.
fn build_pfx_data_response(
    pfx_sync: &DvPfxSync,
    prefix_table: &PrefixTable,
    requested: &Name,
) -> Option<Bytes> {
    let boot = pfx_sync.boot();
    let seq = pfx_sync.current_seq();
    let object_prefix = pfx_sync.prefix_data_name(boot, seq);
    let expected = object_prefix.append_segment(0);
    if requested != &expected {
        return None;
    }
    let content = prefix_table.snap().encode_content();
    Some(crate::protocols::dv::signing::encode_inner_segmented_data(
        &expected,
        &content,
        0,
        pfx_sync.trust().as_ref(),
    ))
}

/// Drains both advance-signal queues (adv + pfx) on a single
/// Consumer. Fetches are serialised because one `NdnConnection`
/// can't correlate concurrent Interests without PIT tokens
/// (`consumer.rs:188`); ndn-dv's throughput is modest enough.
#[allow(clippy::too_many_arguments)]
async fn fetcher_loop(
    handle: InProcHandle,
    mut advance_rx: mpsc::UnboundedReceiver<NeighborAdvance>,
    mut pfx_advance_rx: mpsc::UnboundedReceiver<NeighborAdvance>,
    pfx_sync: Arc<DvPfxSync>,
    rib: Arc<DvRib>,
    prefix_table: Arc<PrefixTable>,
    notify_recompute: Arc<tokio::sync::Notify>,
    cancel: CancellationToken,
) {
    let mut consumer = Consumer::from_handle(handle);
    let network = pfx_sync.network().clone();
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            adv = advance_rx.recv() => {
                let Some(adv) = adv else { break };
                fetch_and_apply_adv(&mut consumer, &adv, &rib, pfx_sync.trust().as_ref(), &notify_recompute).await;
            }
            adv = pfx_advance_rx.recv() => {
                let Some(adv) = adv else { break };
                fetch_and_apply_pfx(&mut consumer, &adv, &network, &prefix_table, pfx_sync.trust().as_ref(), &notify_recompute).await;
            }
        }
    }
}

async fn fetch_and_apply_adv(
    consumer: &mut Consumer,
    adv: &NeighborAdvance,
    rib: &DvRib,
    trust: &dyn crate::protocols::dv::signing::DvTrust,
    notify_recompute: &tokio::sync::Notify,
) {
    // ndnd's `client.Consume` always segments; single-segment fetch
    // is sufficient for the typical Advertisement payload (< MTU).
    let target =
        DvSync::peer_advertisement_data_name(&adv.name, adv.boot, adv.seq).append_segment(0);
    trace!(
        target: t::ROUTING_DV,
        peer = %adv.name, boot = adv.boot, seq = adv.seq,
        "Adv Data fetch starting",
    );
    match consumer.fetch(target).await {
        Ok(data) => {
            // Refuse to apply Adv Data we can't trust. Insecure
            // deployments still pass since `InsecureTrust::validate`
            // returns `true`.
            if !crate::protocols::dv::signing::validate_inner_data(&data, trust) {
                warn!(
                    target: t::ROUTING_DV,
                    peer = %adv.name, boot = adv.boot, seq = adv.seq,
                    "Adv Data dropped — DvTrust::validate returned false",
                );
                return;
            }
            let content_bytes = match data.content() {
                Some(c) => Bytes::copy_from_slice(c),
                None => Bytes::new(),
            };
            match Advertisement::decode_content(&content_bytes) {
                Ok(advertisement) => {
                    let changes = rib.apply_advertisement(&adv.name, &advertisement);
                    if !changes.is_empty() {
                        notify_recompute.notify_waiters();
                    }
                    debug!(
                        target: t::ROUTING_DV,
                        peer = %adv.name, changes = changes.len(),
                        "Adv Data applied to RIB",
                    );
                }
                Err(e) => warn!(
                    target: t::ROUTING_DV,
                    peer = %adv.name, err = %e,
                    "Adv Data content does not decode as Advertisement TLV",
                ),
            }
        }
        Err(e) => debug!(
            target: t::ROUTING_DV,
            peer = %adv.name, boot = adv.boot, seq = adv.seq, err = %e,
            "Adv Data fetch failed (will retry on next advance)",
        ),
    }
}

/// Apply via [`apply_plan`].
#[derive(Debug, Default, PartialEq, Eq)]
struct FibPlan {
    adds: Vec<(Name, NextHop)>,
    removes: Vec<(Name, FaceId)>,
    /// Caller invokes `rib.apply_to_fib` on each so the FIB picks
    /// up the change.
    affected: HashSet<Name>,
}

/// Returns the plan and the new snapshot the caller stores as the
/// next call's `prev`.
fn compute_diff_plan(
    prev: &HashMap<Name, Vec<NextHop>>,
    new_updates: Vec<FibUpdate>,
) -> (FibPlan, HashMap<Name, Vec<NextHop>>) {
    let new_state: HashMap<Name, Vec<NextHop>> = new_updates
        .into_iter()
        .map(|u| (u.prefix, u.next_hops))
        .collect();
    let mut plan = FibPlan::default();

    for (prefix, hops) in prev {
        if !new_state.contains_key(prefix) {
            for hop in hops {
                plan.removes.push((prefix.clone(), hop.face));
            }
            plan.affected.insert(prefix.clone());
        }
    }
    for (prefix, new_hops) in &new_state {
        let prev_hops = prev.get(prefix);
        let mut delta = false;
        for hop in new_hops {
            let was_installed = prev_hops
                .map(|p| p.iter().any(|h| h.face == hop.face && h.cost == hop.cost))
                .unwrap_or(false);
            if !was_installed {
                plan.adds.push((prefix.clone(), *hop));
                delta = true;
            }
        }
        if let Some(prev_hops) = prev_hops {
            for prev_hop in prev_hops {
                if !new_hops.iter().any(|h| h.face == prev_hop.face) {
                    plan.removes.push((prefix.clone(), prev_hop.face));
                    delta = true;
                }
            }
        } else if !new_hops.is_empty() {
            delta = true;
        }
        if delta {
            plan.affected.insert(prefix.clone());
        }
    }
    (plan, new_state)
}

fn apply_plan(plan: &FibPlan, rib: &ndn_engine::Rib, fib: &ndn_engine::Fib) {
    for (prefix, hop) in &plan.adds {
        rib.add(
            prefix,
            RibRoute {
                face_id: hop.face,
                origin: origin::DVR,
                cost: hop.cost,
                flags: route_flags::CHILD_INHERIT,
                expires_at: None,
            },
        );
    }
    for (prefix, face) in &plan.removes {
        rib.remove(prefix, *face, origin::DVR);
    }
    for prefix in &plan.affected {
        rib.apply_to_fib(prefix, fib);
    }
}

/// Bounded above by `router_dead_interval / 4` so stale neighbours
/// are caught within that fraction of the dead-interval.
const DEAD_NEIGHBOR_TICK: Duration = Duration::from_secs(10);

/// Pfx Sync peers are not tracked for liveness here — their peer
/// set is SVS-group membership with no per-neighbour face state.
async fn dead_neighbor_loop(
    sync: Arc<DvSync>,
    rib: Arc<DvRib>,
    dead_interval_ms: Arc<AtomicU64>,
    notify_recompute: Arc<tokio::sync::Notify>,
    cancel: CancellationToken,
) {
    let mut ticker = tokio::time::interval(DEAD_NEIGHBOR_TICK);
    ticker.tick().await; // skip first immediate tick
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            _ = ticker.tick() => {
                let now = Instant::now();
                let dead_interval = Duration::from_millis(dead_interval_ms.load(Ordering::Relaxed));
                let dead = sync.dead_neighbors(now, dead_interval);
                if dead.is_empty() {
                    continue;
                }
                let mut any_change = false;
                for neighbor in &dead {
                    debug!(
                        target: t::ROUTING_DV,
                        neighbor = %neighbor,
                        "neighbour timed out; clearing face binding and RIB routes",
                    );
                    sync.forget_neighbor(neighbor);
                    let changes = rib.remove_neighbor(neighbor);
                    if !changes.is_empty() {
                        any_change = true;
                    }
                }
                if any_change {
                    notify_recompute.notify_waiters();
                }
            }
        }
    }
}

/// Debounces notifications, recomputes via [`compute_fib_updates`],
/// diffs against in-task state, applies deltas to the engine RIB.
#[allow(clippy::too_many_arguments)]
async fn fib_updater_loop(
    sync: Arc<DvSync>,
    rib: Arc<DvRib>,
    prefix_table: Arc<PrefixTable>,
    engine_rib: Arc<ndn_engine::Rib>,
    engine_fib: Arc<ndn_engine::Fib>,
    network: Name,
    notify_recompute: Arc<tokio::sync::Notify>,
    cancel: CancellationToken,
) {
    let mut installed: HashMap<Name, Vec<NextHop>> = HashMap::new();
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            _ = notify_recompute.notified() => {
                // Coalesce notify bursts (one advertisement applies
                // many entries; recompute once per burst).
                tokio::time::sleep(Duration::from_millis(50)).await;

                let updates = compute_fib_updates(
                    &rib,
                    &prefix_table,
                    &network,
                    |neighbor| sync.neighbor_face(neighbor).map(|(face, _is_active)| face),
                );
                let (plan, new_installed) = compute_diff_plan(&installed, updates);
                if plan.adds.is_empty() && plan.removes.is_empty() {
                    trace!(target: t::ROUTING_DV, "FIB recompute produced no deltas");
                    continue;
                }
                debug!(
                    target: t::ROUTING_DV,
                    adds = plan.adds.len(),
                    removes = plan.removes.len(),
                    affected = plan.affected.len(),
                    "FIB updater applying diff to engine RIB",
                );
                apply_plan(&plan, &engine_rib, &engine_fib);
                installed = new_installed;
            }
        }
    }
}

async fn fetch_and_apply_pfx(
    consumer: &mut Consumer,
    adv: &NeighborAdvance,
    network: &Name,
    prefix_table: &PrefixTable,
    trust: &dyn crate::protocols::dv::signing::DvTrust,
    notify_recompute: &tokio::sync::Notify,
) {
    let target =
        DvPfxSync::peer_prefix_data_name(network, &adv.name, adv.boot, adv.seq).append_segment(0);
    trace!(
        target: t::ROUTING_DV,
        peer = %adv.name, boot = adv.boot, seq = adv.seq,
        "Pfx Data fetch starting",
    );
    match consumer.fetch(target).await {
        Ok(data) => {
            if !crate::protocols::dv::signing::validate_inner_data(&data, trust) {
                warn!(
                    target: t::ROUTING_DV,
                    peer = %adv.name, boot = adv.boot, seq = adv.seq,
                    "Pfx Data dropped — DvTrust::validate returned false",
                );
                return;
            }
            let content_bytes = match data.content() {
                Some(c) => Bytes::copy_from_slice(c),
                None => Bytes::new(),
            };
            match PrefixOpList::decode_content(&content_bytes) {
                Ok(ops) => {
                    let changes = prefix_table.apply_op_list(&ops);
                    if !changes.is_empty() {
                        notify_recompute.notify_waiters();
                    }
                    debug!(
                        target: t::ROUTING_DV,
                        peer = %adv.name, changes = changes.len(),
                        "Pfx Data applied to PrefixTable",
                    );
                }
                Err(e) => warn!(
                    target: t::ROUTING_DV,
                    peer = %adv.name, err = %e,
                    "Pfx Data content does not decode as PrefixOpList TLV",
                ),
            }
        }
        Err(e) => debug!(
            target: t::ROUTING_DV,
            peer = %adv.name, boot = adv.boot, seq = adv.seq, err = %e,
            "Pfx Data fetch failed (will retry on next advance)",
        ),
    }
}

/// Serves four kinds of Interest delivered to our InProcFace via
/// the engine's FIB:
///
/// 1. Adv Data fetch → respond from `DvRib`.
/// 2. Pfx Data fetch → respond from `PrefixTable`'s snap.
/// 3. Pfx Sync Interest → decode peer state vector, enqueue advances
///    for the pfx-fetcher task; no Data response.
/// 4. Anything else → Nack so the requester fails fast.
async fn producer_loop(
    handle: InProcHandle,
    sync: Arc<DvSync>,
    pfx_sync: Arc<DvPfxSync>,
    rib: Arc<DvRib>,
    prefix_table: Arc<PrefixTable>,
    pfx_advance_tx: mpsc::UnboundedSender<NeighborAdvance>,
    cancel: CancellationToken,
) {
    // Producer's prefix is metadata only — the producer answers
    // any DV-namespace Interest routed to its face. We use the
    // network root as a stable label.
    let prefix = pfx_sync.network().clone();
    let producer = Producer::from_handle(handle, prefix);
    let pfx_sync_group = pfx_sync.sync_group_prefix();
    let serve_fut = producer.serve(move |interest, responder| {
        let sync = Arc::clone(&sync);
        let pfx_sync = Arc::clone(&pfx_sync);
        let rib = Arc::clone(&rib);
        let prefix_table = Arc::clone(&prefix_table);
        let pfx_advance_tx = pfx_advance_tx.clone();
        let pfx_sync_group = pfx_sync_group.clone();
        async move {
            if let Some(data) = build_adv_data_response(&sync, &rib, &interest.name) {
                let _ = responder.respond_bytes(data).await;
                trace!(target: t::ROUTING_DV, requested = %interest.name, "served Adv Data");
                return;
            }
            if let Some(data) = build_pfx_data_response(&pfx_sync, &prefix_table, &interest.name) {
                let _ = responder.respond_bytes(data).await;
                trace!(target: t::ROUTING_DV, requested = %interest.name, "served Pfx Data");
                return;
            }
            // A Pfx Sync Interest carries the sync group prefix plus
            // a `ParametersSha256DigestComponent` appended by the
            // InterestBuilder; `has_prefix` strips that off naturally.
            if interest.name.has_prefix(&pfx_sync_group) {
                if let Some(app_param) = interest.app_parameters() {
                    match pfx_sync.process_sync_app_param(app_param) {
                        Ok(advances) => {
                            for adv in advances {
                                let _ = pfx_advance_tx.send(adv);
                            }
                        }
                        Err(e) => debug!(
                            target: t::ROUTING_DV,
                            err = %e,
                            "Pfx Sync Interest AppParam parse failed",
                        ),
                    }
                }
                // Sync Interests have no reply; drop responder.
                drop(responder);
                return;
            }
            let _ = responder.nack(ndn_packet::NackReason::NoRoute).await;
            trace!(
                target: t::ROUTING_DV,
                requested = %interest.name,
                "fetch nacked — name does not match any DV-served prefix",
            );
        }
    });
    tokio::select! {
        biased;
        _ = cancel.cancelled() => {},
        _ = serve_fut => {},
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::sync::Mutex as StdMutex;

    use ndn_discovery::neighbor::{NeighborEntry, NeighborState, NeighborTable};
    use ndn_discovery::{MacAddr, NeighborTableView, NeighborUpdate};
    use ndn_transport::Face;

    use super::*;

    fn name(s: &str) -> Name {
        Name::from_str(s).expect("valid name")
    }

    /// Captures every `send_on` call so tests can assert what
    /// packets went where. Mirrors the TrackCtx pattern from
    /// ndn-discovery's probe tests.
    struct TrackCtx {
        neighbors: Arc<NeighborTable>,
        sent: StdMutex<Vec<(FaceId, Bytes)>>,
        fib_adds: StdMutex<Vec<(Name, FaceId, u32, ProtocolId)>>,
        fib_removes: StdMutex<Vec<(Name, FaceId, ProtocolId)>>,
        now: Instant,
    }

    impl TrackCtx {
        fn new() -> Self {
            Self {
                neighbors: NeighborTable::new(),
                sent: StdMutex::new(Vec::new()),
                fib_adds: StdMutex::new(Vec::new()),
                fib_removes: StdMutex::new(Vec::new()),
                now: Instant::now(),
            }
        }
        fn add_neighbor(&self, name: Name, face_id: FaceId) {
            let mut entry = NeighborEntry::new(name.clone());
            entry.state = NeighborState::Established {
                last_seen: self.now,
            };
            entry
                .faces
                .push((face_id, MacAddr::new([0; 6]), String::new()));
            self.neighbors.apply(NeighborUpdate::Upsert(entry));
        }
        fn sent(&self) -> Vec<(FaceId, Bytes)> {
            self.sent.lock().unwrap().clone()
        }
        fn fib_adds(&self) -> Vec<(Name, FaceId, u32, ProtocolId)> {
            self.fib_adds.lock().unwrap().clone()
        }
        fn fib_removes(&self) -> Vec<(Name, FaceId, ProtocolId)> {
            self.fib_removes.lock().unwrap().clone()
        }
    }

    impl ndn_discovery::FaceLifecycleContext for TrackCtx {
        fn alloc_face_id(&self) -> FaceId {
            FaceId(0)
        }
        fn add_face(&self, _: Arc<Face>) -> FaceId {
            FaceId(0)
        }
        fn remove_face(&self, _: FaceId) {}
    }
    impl ndn_discovery::RoutingTableContext for TrackCtx {
        fn add_fib_entry(&self, prefix: &Name, face: FaceId, cost: u32, owner: ProtocolId) {
            self.fib_adds
                .lock()
                .unwrap()
                .push((prefix.clone(), face, cost, owner));
        }
        fn remove_fib_entry(&self, prefix: &Name, face: FaceId, owner: ProtocolId) {
            self.fib_removes
                .lock()
                .unwrap()
                .push((prefix.clone(), face, owner));
        }
        fn remove_fib_entries_by_owner(&self, _: ProtocolId) {}
    }
    impl ndn_discovery::NeighborContext for TrackCtx {
        fn neighbors(&self) -> Arc<dyn NeighborTableView> {
            self.neighbors.clone()
        }
        fn update_neighbor(&self, u: NeighborUpdate) {
            self.neighbors.apply(u);
        }
    }
    impl DiscoveryContext for TrackCtx {
        fn send_on(&self, face_id: FaceId, pkt: Bytes) {
            self.sent.lock().unwrap().push((face_id, pkt));
        }
        fn now(&self) -> Instant {
            self.now
        }
    }

    #[test]
    fn config_defaults_match_ndnd() {
        let cfg = DvConfig::new(name("/ndn"), name("/r"), 100);
        assert_eq!(cfg.adv_sync_interval, Duration::from_secs(30));
        assert_eq!(cfg.pfx_sync_interval, Duration::from_secs(30));
        assert_eq!(cfg.router_dead_interval, Duration::from_secs(60));
    }

    #[test]
    fn new_constructs_owned_state() {
        let proto = DvProtocol::new(DvConfig::new(name("/ndn"), name("/r1"), 100));
        assert_eq!(proto.config().router, name("/r1"));
        assert_eq!(proto.sync().router_name(), &name("/r1"));
        assert_eq!(proto.rib().self_name(), &name("/r1"));
        assert_eq!(proto.prefix_table().self_router(), &name("/r1"));
    }

    #[test]
    fn origin_is_dvr() {
        let proto = DvProtocol::new(DvConfig::new(name("/ndn"), name("/r"), 100));
        assert_eq!(proto.origin(), ndn_mgmt_wire::control_parameters::origin::DVR);
    }

    /// `apply_config` accepts the three runtime-mutable keys,
    /// updates atomics atomically, and rejects unknown / out-of-range
    /// input without partial application.
    #[test]
    fn apply_config_round_trips_via_atomics() {
        use ndn_engine::{ConfigError, ConfigUpdate, RoutingProtocol};
        let proto = DvProtocol::new(DvConfig::new(name("/ndn"), name("/r1"), 1));
        let update = ConfigUpdate::parse("adv_sync_secs=12&pfx_sync_secs=20&router_dead_secs=90")
            .expect("syntactically valid");
        let n = proto.apply_config(&update).expect("valid triple");
        assert_eq!(n, 3);
        let s = proto.status();
        assert_eq!(
            s.fields.get("adv_sync_secs").map(String::as_str),
            Some("12")
        );
        assert_eq!(
            s.fields.get("pfx_sync_secs").map(String::as_str),
            Some("20")
        );
        assert_eq!(
            s.fields.get("router_dead_secs").map(String::as_str),
            Some("90"),
        );

        // Unknown key → reject, leaves atomics alone.
        let bad = ConfigUpdate::parse("adv_sync_secs=5&hello=1").unwrap();
        let err = proto.apply_config(&bad).unwrap_err();
        assert!(matches!(err, ConfigError::UnknownKey(ref k) if k == "hello"));
        assert_eq!(
            proto
                .status()
                .fields
                .get("adv_sync_secs")
                .map(String::as_str),
            Some("12"),
            "atomics rolled back on validation failure",
        );

        // Out-of-range → reject.
        let oob = ConfigUpdate::parse("adv_sync_secs=0").unwrap();
        let err = proto.apply_config(&oob).unwrap_err();
        assert!(
            matches!(err, ConfigError::BadValue { ref reason, .. } if reason.contains("1..=3600")),
            "got: {err:?}",
        );
    }

    /// `status()` reports the keys ndnd's `dv status` exposes so
    /// operators can inspect DV state via the `dvr-status` mgmt verb.
    #[test]
    fn status_lists_ndnd_style_keys() {
        use ndn_engine::RoutingProtocol;
        let proto = DvProtocol::new(DvConfig::new(name("/ndn"), name("/r1"), 1234));
        let s = proto.status();
        assert_eq!(s.origin, ndn_mgmt_wire::control_parameters::origin::DVR);
        assert_eq!(
            s.network.as_ref().map(|n| n.to_string()).as_deref(),
            Some("/ndn")
        );
        assert_eq!(
            s.router.as_ref().map(|n| n.to_string()).as_deref(),
            Some("/r1")
        );
        assert_eq!(s.fields.get("boot").map(String::as_str), Some("1234"));
        for k in &["nRibEntries", "nNeighbors", "nPrefixEntries"] {
            assert!(s.counters.contains_key(*k), "missing counter `{k}`");
        }
    }

    #[test]
    fn protocol_id_is_ndn_dv() {
        let proto = DvProtocol::new(DvConfig::new(name("/ndn"), name("/r"), 100));
        assert_eq!(proto.protocol_id(), DV_PROTOCOL_ID);
    }

    #[test]
    fn claimed_prefixes_include_active_and_passive_sync() {
        let proto = DvProtocol::new(DvConfig::new(name("/ndn"), name("/r"), 100));
        let claimed = proto.claimed_prefixes();
        assert_eq!(claimed.len(), 2);
        // Active = /localhop/ndn/32=DV/32=ADS/32=ACT
        assert_eq!(claimed[0].components()[4].value.as_ref(), b"ACT");
        // Passive = /localhop/ndn/32=DV/32=ADS/32=PSV
        assert_eq!(claimed[1].components()[4].value.as_ref(), b"PSV");
    }

    #[test]
    fn on_inbound_ignores_non_sync_interest() {
        let proto = DvProtocol::new(DvConfig::new(name("/ndn"), name("/r"), 100));
        let ctx = TrackCtx::new();
        // Random Interest — should pass through (return false).
        let mut w = ndn_tlv::TlvWriter::new();
        w.write_nested(ndn_packet::tlv_type::INTEREST, |w| {
            w.write_nested(ndn_packet::tlv_type::NAME, |w| {
                w.write_tlv(0x08, b"not-sync");
            });
            w.write_tlv(ndn_packet::tlv_type::NONCE, &[0, 0, 0, 1]);
        });
        let raw = w.finish();
        let consumed = proto.on_inbound(&raw, FaceId(7), &InboundMeta::none(), &ctx);
        assert!(!consumed);
    }

    #[test]
    fn on_inbound_consumes_active_sync_and_records_advance() {
        // /r2 emits an active Sync Interest; /r1 (proto) receives it on
        // face 7. /r1 should consume it, advance its tracked seq for /r2,
        // and bind /r2 → face 7 in DvSync.
        let proto_r1 = DvProtocol::new(DvConfig::new(name("/ndn"), name("/r1"), 100));
        let peer_r2 = crate::protocols::dv::sync::DvSync::new(name("/ndn"), name("/r2"), 200);
        peer_r2.advance_seq();
        let wire = peer_r2.build_sync_interest(SyncKind::Active);
        let ctx = TrackCtx::new();
        let consumed = proto_r1.on_inbound(&wire, FaceId(7), &InboundMeta::none(), &ctx);
        assert!(consumed);
        assert_eq!(proto_r1.sync().neighbor_seq(&name("/r2")), Some((200, 1)));
        assert_eq!(
            proto_r1.sync().neighbor_face(&name("/r2")),
            Some((FaceId(7), true)),
        );
    }

    /// Stage 6h — on the first sync from a new peer, `on_inbound`
    /// must install a per-peer bootstrap FIB entry so the follow-up
    /// `consumer.fetch(/localhop/<peer>/DV/ADV/...)` can route.
    /// Without this, the witness in `tests/dv_integration.rs`
    /// regressed — see commit message for that file.
    #[test]
    fn on_inbound_installs_bootstrap_fib_on_first_face_binding() {
        let proto_r1 = DvProtocol::new(DvConfig::new(name("/ndn"), name("/r1"), 100));
        let peer_r2 = crate::protocols::dv::sync::DvSync::new(name("/ndn"), name("/r2"), 200);
        peer_r2.advance_seq();
        let wire = peer_r2.build_sync_interest(SyncKind::Active);
        let ctx = TrackCtx::new();
        proto_r1.on_inbound(&wire, FaceId(7), &InboundMeta::none(), &ctx);
        let adds = ctx.fib_adds();
        let expected_prefix =
            crate::protocols::dv::sync::DvSync::peer_advertisement_data_prefix(&name("/r2"));
        assert_eq!(
            adds,
            vec![(expected_prefix, FaceId(7), 0, DV_PROTOCOL_ID)],
            "first-contact must install one per-peer bootstrap FIB entry",
        );
        assert!(ctx.fib_removes().is_empty(), "no removes on first binding",);
    }

    /// Stage 6h — when a peer's face binding flips (e.g. multi-homed
    /// neighbour that becomes reachable on a different face), the
    /// old bootstrap entry must be removed before the new one is
    /// installed so the FIB doesn't accumulate stale nexthops.
    #[test]
    fn on_inbound_rebinds_bootstrap_fib_when_face_changes() {
        let proto_r1 = DvProtocol::new(DvConfig::new(name("/ndn"), name("/r1"), 100));
        let peer_r2 = crate::protocols::dv::sync::DvSync::new(name("/ndn"), name("/r2"), 200);
        peer_r2.advance_seq();
        let wire1 = peer_r2.build_sync_interest(SyncKind::Active);
        peer_r2.advance_seq();
        let wire2 = peer_r2.build_sync_interest(SyncKind::Active);
        let ctx = TrackCtx::new();
        proto_r1.on_inbound(&wire1, FaceId(7), &InboundMeta::none(), &ctx);
        proto_r1.on_inbound(&wire2, FaceId(9), &InboundMeta::none(), &ctx);
        let prefix =
            crate::protocols::dv::sync::DvSync::peer_advertisement_data_prefix(&name("/r2"));
        assert_eq!(
            ctx.fib_removes(),
            vec![(prefix.clone(), FaceId(7), DV_PROTOCOL_ID)],
            "rebind must remove old nexthop",
        );
        assert_eq!(
            ctx.fib_adds(),
            vec![
                (prefix.clone(), FaceId(7), 0, DV_PROTOCOL_ID),
                (prefix, FaceId(9), 0, DV_PROTOCOL_ID),
            ],
            "rebind must add new nexthop",
        );
    }

    #[test]
    fn on_inbound_passive_sync_tracks_face_for_emission() {
        // Receiving a passive sync from /r2 on face 9 should add face 9
        // to the passive-faces set so the next on_tick fans a passive
        // sync back to face 9.
        let proto_r1 = DvProtocol::new(DvConfig::new(name("/ndn"), name("/r1"), 100));
        let peer_r2 = crate::protocols::dv::sync::DvSync::new(name("/ndn"), name("/r2"), 200);
        peer_r2.advance_seq();
        let wire = peer_r2.build_sync_interest(SyncKind::Passive);
        let ctx = TrackCtx::new();
        proto_r1.on_inbound(&wire, FaceId(9), &InboundMeta::none(), &ctx);
        assert!(
            proto_r1
                .passive_faces
                .read()
                .unwrap()
                .contains_key(&FaceId(9)),
            "passive face must be recorded for future emission",
        );
    }

    #[test]
    fn first_tick_emits_active_sync_to_every_neighbour_face() {
        let proto = DvProtocol::new(DvConfig::new(name("/ndn"), name("/r1"), 100));
        proto.sync().advance_seq();
        let ctx = TrackCtx::new();
        ctx.add_neighbor(name("/r2"), FaceId(7));
        ctx.add_neighbor(name("/r3"), FaceId(8));
        proto.on_tick(ctx.now, &ctx);
        let sent = ctx.sent();
        // Each neighbour gets both an active Adv Sync AND a Pfx Sync
        // Interest. 2 neighbours × 2 emissions = 4 packets.
        assert_eq!(sent.len(), 4);
        let faces: Vec<FaceId> = sent.iter().map(|(f, _)| *f).collect();
        // Each face appears twice (once per protocol leg).
        assert_eq!(faces.iter().filter(|&&f| f == FaceId(7)).count(), 2);
        assert_eq!(faces.iter().filter(|&&f| f == FaceId(8)).count(), 2);
    }

    #[test]
    fn on_tick_respects_sync_intervals() {
        // Two consecutive ticks within the interval emit only on
        // the first tick (subsequent ticks are gated by last_*_emit).
        let mut cfg = DvConfig::new(name("/ndn"), name("/r1"), 100);
        cfg.adv_sync_interval = Duration::from_secs(60);
        cfg.pfx_sync_interval = Duration::from_secs(60);
        let proto = DvProtocol::new(cfg);
        let ctx = TrackCtx::new();
        ctx.add_neighbor(name("/r2"), FaceId(7));
        proto.on_tick(ctx.now, &ctx);
        let first_count = ctx.sent().len();
        // Second tick 1 s later — both intervals are 60 s, so should NOT emit.
        let later = ctx.now + Duration::from_secs(1);
        proto.on_tick(later, &ctx);
        assert_eq!(
            ctx.sent().len(),
            first_count,
            "tick within interval must not re-emit",
        );
        // Should be exactly 2 emissions on the first tick (active adv
        // + pfx); passive is empty.
        assert_eq!(first_count, 2);
    }

    #[test]
    fn on_tick_emits_passive_sync_to_recorded_passive_faces() {
        // /r2 sends us a passive sync first; the on_tick after should
        // send a passive Sync back on the same face.
        let proto = DvProtocol::new(DvConfig::new(name("/ndn"), name("/r1"), 100));
        proto.sync().advance_seq();
        let peer = crate::protocols::dv::sync::DvSync::new(name("/ndn"), name("/r2"), 200);
        peer.advance_seq();
        let passive_in = peer.build_sync_interest(SyncKind::Passive);
        let ctx = TrackCtx::new();
        proto.on_inbound(&passive_in, FaceId(9), &InboundMeta::none(), &ctx);

        proto.on_tick(ctx.now, &ctx);
        // Sent packets include a passive Sync to face 9 (no active
        // since there are no neighbours in the NeighborTable).
        let sent = ctx.sent();
        assert!(
            sent.iter().any(|(f, _)| *f == FaceId(9)),
            "passive sync must be sent on face 9: {:?}",
            sent.iter().map(|(f, _)| f).collect::<Vec<_>>()
        );
    }

    #[test]
    fn on_inbound_advance_is_enqueued_for_fetcher() {
        // After receiving an Active sync from /r2 with seq=1, the
        // advance should be available on the receiver half of the
        // mpsc so the fetcher task (spawned in start()) can pick it
        // up. Use try_recv() to confirm without an actual fetcher.
        let proto_r1 = DvProtocol::new(DvConfig::new(name("/ndn"), name("/r1"), 100));
        let peer = crate::protocols::dv::sync::DvSync::new(name("/ndn"), name("/r2"), 200);
        peer.advance_seq();
        let wire = peer.build_sync_interest(SyncKind::Active);
        let ctx = TrackCtx::new();
        proto_r1.on_inbound(&wire, FaceId(7), &InboundMeta::none(), &ctx);

        let mut rx = proto_r1.advance_rx.lock().unwrap().take().unwrap();
        let advance = rx.try_recv().expect("advance should be enqueued");
        assert_eq!(advance.name, name("/r2"));
        assert_eq!(advance.boot, 200);
        assert_eq!(advance.seq, 1);
        // No further advances queued.
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn duplicate_sync_does_not_double_enqueue() {
        // Same (boot, seq) arriving twice on the sync layer should
        // only generate ONE advance signal — DvSync's `apply_entry`
        // skip rule already filters; we just verify the wiring.
        let proto = DvProtocol::new(DvConfig::new(name("/ndn"), name("/r1"), 100));
        let peer = crate::protocols::dv::sync::DvSync::new(name("/ndn"), name("/r2"), 200);
        peer.advance_seq();
        let wire = peer.build_sync_interest(SyncKind::Active);
        let ctx = TrackCtx::new();
        proto.on_inbound(&wire, FaceId(7), &InboundMeta::none(), &ctx);
        proto.on_inbound(&wire, FaceId(7), &InboundMeta::none(), &ctx);
        let mut rx = proto.advance_rx.lock().unwrap().take().unwrap();
        assert!(rx.try_recv().is_ok());
        assert!(
            rx.try_recv().is_err(),
            "duplicate sync must not double-enqueue"
        );
    }

    #[test]
    fn build_adv_data_response_returns_some_for_current_name() {
        let proto = DvProtocol::new(DvConfig::new(name("/ndn"), name("/r1"), 100));
        let seq = proto.sync().advance_seq();
        // Stage 7b — segmented name: `/.../t=/v=/seg=0`. ndnd consumer
        // expresses Interest at this segmented name.
        let expected_name = proto
            .sync()
            .advertisement_data_name(100, seq)
            .append_segment(0);
        let resp = proto
            .build_adv_data_response(&expected_name)
            .expect("current name must return Some(Data wire bytes)");
        // Round-trip: decoded Data has matching name and content
        // parseable as Advertisement.
        let data = ndn_packet::Data::decode(resp).expect("valid Data");
        assert_eq!(*data.name, expected_name);
        let content = data.content().expect("non-empty content");
        let content_bytes = bytes::Bytes::copy_from_slice(content);
        let adv = Advertisement::decode_content(&content_bytes).expect("valid Advertisement TLV");
        // Self at cost 0 is always in our advertisement (per Stage 3).
        assert!(
            adv.entries
                .iter()
                .any(|e| e.destination == name("/r1") && e.cost == 0)
        );
    }

    #[test]
    fn build_adv_data_response_returns_none_for_stale_name() {
        let proto = DvProtocol::new(DvConfig::new(name("/ndn"), name("/r1"), 100));
        proto.sync().advance_seq(); // current = 1
        // Request seq=99 (we've never published that).
        let stale = proto.sync().advertisement_data_name(100, 99);
        assert!(
            proto.build_adv_data_response(&stale).is_none(),
            "stale (boot, seq) request must return None",
        );
        // Different boot timestamp also misses.
        let wrong_boot = proto.sync().advertisement_data_name(999, 1);
        assert!(proto.build_adv_data_response(&wrong_boot).is_none());
    }

    #[test]
    fn build_adv_data_response_reflects_current_rib_state() {
        // After applying a peer's advertisement, our outgoing
        // advertisement should include the new destination — proving
        // the producer-side path reads the live RIB.
        let proto = DvProtocol::new(DvConfig::new(name("/ndn"), name("/r1"), 100));
        let seq = proto.sync().advance_seq();
        let peer_adv = Advertisement {
            entries: vec![crate::protocols::dv::tlv::AdvEntry {
                destination: name("/r2"),
                next_hop: name("/x"),
                cost: 2,
                other_cost: 4,
            }],
        };
        proto.rib().apply_advertisement(&name("/peer"), &peer_adv);

        let expected_name = proto
            .sync()
            .advertisement_data_name(100, seq)
            .append_segment(0);
        let resp = proto.build_adv_data_response(&expected_name).unwrap();
        let data = ndn_packet::Data::decode(resp).unwrap();
        let content = bytes::Bytes::copy_from_slice(data.content().unwrap());
        let adv = Advertisement::decode_content(&content).unwrap();
        assert!(
            adv.entries.iter().any(|e| e.destination == name("/r2")),
            "advertisement must include /r2 after peer taught us a route",
        );
    }

    #[test]
    fn pfx_sync_starts_with_independent_seq() {
        let proto = DvProtocol::new(DvConfig::new(name("/ndn"), name("/r1"), 100));
        // Adv Sync and Pfx Sync each have their own seq counter.
        assert_eq!(proto.sync().current_seq(), 0);
        assert_eq!(proto.pfx_sync().current_seq(), 0);
        proto.sync().advance_seq();
        assert_eq!(proto.sync().current_seq(), 1);
        assert_eq!(proto.pfx_sync().current_seq(), 0);
        proto.pfx_sync().advance_seq();
        assert_eq!(proto.sync().current_seq(), 1);
        assert_eq!(proto.pfx_sync().current_seq(), 1);
    }

    #[test]
    fn first_tick_also_emits_pfx_sync() {
        let proto = DvProtocol::new(DvConfig::new(name("/ndn"), name("/r1"), 100));
        let ctx = TrackCtx::new();
        ctx.add_neighbor(name("/r2"), FaceId(7));
        proto.on_tick(ctx.now, &ctx);
        // 1 active Adv Sync + 1 Pfx Sync to face 7 = 2 packets.
        assert_eq!(ctx.sent().len(), 2);
        // Verify one of them is a Pfx Sync (name has the sync group prefix).
        let pfx_group = proto.pfx_sync().sync_group_prefix();
        let pfx_sent = ctx.sent().iter().any(|(_, pkt)| {
            if let Ok(interest) = ndn_packet::Interest::decode(pkt.clone()) {
                interest.name.has_prefix(&pfx_group)
            } else {
                false
            }
        });
        assert!(pfx_sent, "at least one Pfx Sync Interest must be emitted");
    }

    #[test]
    fn build_pfx_data_response_returns_some_for_current_name() {
        let proto = DvProtocol::new(DvConfig::new(name("/ndn"), name("/r1"), 100));
        // Announce some prefixes so the snap is non-trivial.
        proto.prefix_table().announce_local(name("/shop"), 1);
        proto.prefix_table().announce_local(name("/news"), 2);
        let seq = proto.pfx_sync().advance_seq();

        let expected_name = proto
            .pfx_sync()
            .prefix_data_name(100, seq)
            .append_segment(0);
        let resp =
            super::build_pfx_data_response(&proto.pfx_sync, &proto.prefix_table, &expected_name)
                .expect("current pfx name must return Some");

        let data = ndn_packet::Data::decode(resp).expect("valid Data");
        assert_eq!(*data.name, expected_name);
        let content = bytes::Bytes::copy_from_slice(data.content().unwrap());
        let ops = crate::protocols::dv::tlv::PrefixOpList::decode_content(&content)
            .expect("valid PrefixOpList");
        // Snap always carries Reset = true.
        assert!(ops.reset);
        assert!(ops.adds.iter().any(|a| a.name == name("/shop")));
        assert!(ops.adds.iter().any(|a| a.name == name("/news")));
    }

    #[test]
    fn build_pfx_data_response_returns_none_for_stale_name() {
        let proto = DvProtocol::new(DvConfig::new(name("/ndn"), name("/r1"), 100));
        proto.pfx_sync().advance_seq();
        let stale = proto.pfx_sync().prefix_data_name(100, 999);
        assert!(
            super::build_pfx_data_response(&proto.pfx_sync, &proto.prefix_table, &stale).is_none(),
        );
    }

    fn hop(face: u64, cost: u32) -> NextHop {
        NextHop {
            face: FaceId(face),
            cost,
        }
    }

    fn update(prefix: &str, hops: Vec<NextHop>) -> FibUpdate {
        FibUpdate {
            prefix: name(prefix),
            next_hops: hops,
        }
    }

    #[test]
    fn diff_plan_empty_to_empty_is_noop() {
        let prev = HashMap::new();
        let (plan, new_state) = super::compute_diff_plan(&prev, vec![]);
        assert!(plan.adds.is_empty());
        assert!(plan.removes.is_empty());
        assert!(plan.affected.is_empty());
        assert!(new_state.is_empty());
    }

    #[test]
    fn diff_plan_empty_to_one_prefix_adds() {
        let prev = HashMap::new();
        let (plan, _) = super::compute_diff_plan(&prev, vec![update("/p", vec![hop(7, 3)])]);
        assert_eq!(plan.adds.len(), 1);
        assert_eq!(plan.adds[0].0, name("/p"));
        assert_eq!(plan.adds[0].1.face, FaceId(7));
        assert_eq!(plan.adds[0].1.cost, 3);
        assert!(plan.removes.is_empty());
        assert!(plan.affected.contains(&name("/p")));
    }

    #[test]
    fn diff_plan_removed_prefix_emits_removes() {
        let mut prev = HashMap::new();
        prev.insert(name("/p"), vec![hop(7, 3), hop(8, 5)]);
        let (plan, new_state) = super::compute_diff_plan(&prev, vec![]);
        assert_eq!(plan.removes.len(), 2);
        assert!(
            plan.removes
                .iter()
                .any(|(n, f)| n == &name("/p") && f == &FaceId(7))
        );
        assert!(
            plan.removes
                .iter()
                .any(|(n, f)| n == &name("/p") && f == &FaceId(8))
        );
        assert!(plan.adds.is_empty());
        assert!(plan.affected.contains(&name("/p")));
        assert!(new_state.is_empty());
    }

    #[test]
    fn diff_plan_unchanged_prefix_is_noop() {
        let mut prev = HashMap::new();
        prev.insert(name("/p"), vec![hop(7, 3)]);
        let (plan, _) = super::compute_diff_plan(&prev, vec![update("/p", vec![hop(7, 3)])]);
        assert!(plan.adds.is_empty());
        assert!(plan.removes.is_empty());
        assert!(
            plan.affected.is_empty(),
            "no delta = no apply_to_fib needed"
        );
    }

    #[test]
    fn diff_plan_cost_change_replaces_via_add() {
        // rib.add is idempotent for (prefix, face, origin); cost
        // update is just another `add` call. No explicit remove.
        let mut prev = HashMap::new();
        prev.insert(name("/p"), vec![hop(7, 3)]);
        let (plan, _) = super::compute_diff_plan(&prev, vec![update("/p", vec![hop(7, 5)])]);
        assert_eq!(plan.adds.len(), 1);
        assert_eq!(plan.adds[0].1.cost, 5);
        assert!(plan.removes.is_empty());
        assert!(plan.affected.contains(&name("/p")));
    }

    #[test]
    fn diff_plan_face_change_emits_add_and_remove() {
        // Same prefix, different face: add new, remove old.
        let mut prev = HashMap::new();
        prev.insert(name("/p"), vec![hop(7, 3)]);
        let (plan, _) = super::compute_diff_plan(&prev, vec![update("/p", vec![hop(9, 4)])]);
        assert_eq!(plan.adds.len(), 1);
        assert_eq!(plan.adds[0].1.face, FaceId(9));
        assert_eq!(plan.removes.len(), 1);
        assert_eq!(plan.removes[0].1, FaceId(7));
        assert!(plan.affected.contains(&name("/p")));
    }

    #[test]
    fn diff_plan_multipath_grows() {
        // Prev: prefix via face 7. New: same via 7 + new via 9.
        let mut prev = HashMap::new();
        prev.insert(name("/p"), vec![hop(7, 3)]);
        let (plan, _) =
            super::compute_diff_plan(&prev, vec![update("/p", vec![hop(7, 3), hop(9, 5)])]);
        // Only the new face is added; existing one unchanged.
        assert_eq!(plan.adds.len(), 1);
        assert_eq!(plan.adds[0].1.face, FaceId(9));
        assert!(plan.removes.is_empty());
    }

    #[test]
    fn diff_plan_multipath_shrinks() {
        // Prev: prefix via faces 7, 9. New: only 7.
        let mut prev = HashMap::new();
        prev.insert(name("/p"), vec![hop(7, 3), hop(9, 5)]);
        let (plan, _) = super::compute_diff_plan(&prev, vec![update("/p", vec![hop(7, 3)])]);
        assert_eq!(plan.removes.len(), 1);
        assert_eq!(plan.removes[0].1, FaceId(9));
        assert!(plan.adds.is_empty());
    }

    #[test]
    fn notify_is_arc_clonable_into_tasks() {
        let proto = DvProtocol::new(DvConfig::new(name("/ndn"), name("/r"), 100));
        let n1 = Arc::clone(&proto.notify_recompute);
        let n2 = Arc::clone(&proto.notify_recompute);
        n1.notify_waiters(); // doesn't panic; multiple clones share the same Notify
        assert!(Arc::ptr_eq(&n1, &n2));
    }

    #[test]
    fn on_face_down_clears_passive_binding() {
        let proto = DvProtocol::new(DvConfig::new(name("/ndn"), name("/r1"), 100));
        let peer = crate::protocols::dv::sync::DvSync::new(name("/ndn"), name("/r2"), 200);
        peer.advance_seq();
        let wire = peer.build_sync_interest(SyncKind::Passive);
        let ctx = TrackCtx::new();
        proto.on_inbound(&wire, FaceId(9), &InboundMeta::none(), &ctx);
        assert!(proto.passive_faces.read().unwrap().contains_key(&FaceId(9)));

        proto.on_face_down(FaceId(9), &ctx);
        assert!(!proto.passive_faces.read().unwrap().contains_key(&FaceId(9)));
    }
}
