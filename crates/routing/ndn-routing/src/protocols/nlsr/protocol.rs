//! NLSR routing protocol — `RoutingProtocol` integration point.
//!
//! `NlsrProtocol::start()` spawns all NLSR sub-tasks (hello loop,
//! LSDB expiry, sync loop, routing-calc loop, NPT→RIB writer) under a
//! shared `CancellationToken`.
//!
//! C++ reference: `NLSR/src/nlsr.{hpp,cpp}`.

use std::collections::HashSet;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use ndn_app::{Connection, Consumer, InProcConnection};
use ndn_mgmt_wire::control_parameters::{origin, route_flags};
use ndn_engine::observability::targets as t;
use ndn_engine::{
    LsdbEntry, NeighborInfo, RibRoute, RoutingHandle, RoutingProtocol, RoutingProtocolStatus,
};
use ndn_face::local::InProcHandle;
use ndn_packet::lp::{LpHeaders, encode_lp_with_headers};
use ndn_packet::{Name, NameComponent};
use ndn_sync::{PSyncConfig, SyncHandle, SyncUpdate, join_psync_group};
use ndn_transport::{FaceId, FaceTable};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{Instrument as _, debug, info, warn};

use crate::protocols::nlsr::{
    hello::{HelloConfig, HelloNeighborConfig, HelloProtocol},
    lsa::LsaType,
    lsdb::Lsdb,
    name_prefix_table::NamePrefixTable,
    routing_table::{NextHop, RoutingTable},
    sync::NlsrSync,
};

/// C++ equivalent: `Adjacent` config fields in
/// `NLSR/src/conf-parameter.hpp`.
#[derive(Clone, Debug)]
pub struct NeighborConfig {
    pub name: Name,
    /// e.g. `udp4://10.0.0.2:6363`.
    pub face_uri: String,
    /// Dijkstra link cost (≥ 0).
    pub link_cost: f64,
}

/// Loaded from `[routing.nlsr]` in `ndnd.toml` via
/// `ndn_config::NlsrTomlConfig`. Timing defaults match
/// `NLSR/src/conf-parameter.hpp`.
#[derive(Clone)]
pub struct NlsrConfig {
    pub own_router: Name,
    pub network: Name,
    pub neighbors: Vec<NeighborConfig>,
    /// Prefixes this router originates into the NLSR mesh.
    pub name_prefixes: Vec<Name>,
    /// Defaults to `/localhop/<network>/nlsr/LSA`.
    pub lsa_prefix: Name,
    /// Defaults to `/localhop/<network>/nlsr/sync/v=12`.
    /// C++ NLSR uses SYNC_VERSION=12 (`NLSR/src/conf-parameter.hpp:534`).
    pub sync_prefix: Name,

    /// `LSA_REFRESH_TIME_DEFAULT` = 1800.
    pub lsa_refresh_secs: u32,
    pub adj_lsa_build_interval_secs: u32,
    pub routing_calc_interval_secs: u32,
    pub hello_interval_secs: u32,
    /// Hellos retried before a neighbour is declared Inactive.
    pub hello_retries: u32,
    pub hello_timeout_secs: u32,
    pub sync_interest_lifetime_ms: u64,

    /// `None` emits `DigestSha256` and accepts everything — matches
    /// ndnd's `KeyChainUri = "insecure"` mode used in the testbed.
    /// Production deployments pass [`ndn_security::StaticTrust`] or
    /// [`ndn_security::LvsTrust`].
    pub trust_policy: Option<Arc<dyn ndn_security::TrustPolicy>>,

    /// `0` = no limit (`MAX_FACES_PER_PREFIX_DEFAULT`).
    pub max_faces_per_prefix: usize,
}

impl NlsrConfig {
    /// `/localhop/<network>/nlsr/LSA`. C++ equivalent:
    /// `ConfParameter::getLsaPrefix()` (`NLSR/src/conf-parameter.hpp:123`).
    pub fn default_lsa_prefix(network: &Name) -> Name {
        let mut name = Name::root().append(b"localhop" as &[u8]);
        for comp in network.components() {
            name = name.append_component(comp.clone());
        }
        name.append(b"nlsr" as &[u8]).append(b"LSA" as &[u8])
    }

    /// `/localhop/<network>/nlsr/sync/v=12`. C++ equivalent:
    /// `ConfParameter::getSyncPrefix()` (SYNC_VERSION constant at
    /// `NLSR/src/conf-parameter.hpp:534`).
    pub fn default_sync_prefix(network: &Name) -> Name {
        let mut name = Name::root().append(b"localhop" as &[u8]);
        for comp in network.components() {
            name = name.append_component(comp.clone());
        }
        name.append(b"nlsr" as &[u8])
            .append(b"sync" as &[u8])
            .append_version(12)
    }
}

impl Default for NlsrConfig {
    fn default() -> Self {
        let network: Name = "/ndn".parse().unwrap_or_else(|_| Name::root());
        let lsa_prefix = Self::default_lsa_prefix(&network);
        let sync_prefix = Self::default_sync_prefix(&network);
        Self {
            own_router: Name::root(),
            network,
            lsa_prefix,
            sync_prefix,
            neighbors: Vec::new(),
            name_prefixes: Vec::new(),
            lsa_refresh_secs: 1800,
            adj_lsa_build_interval_secs: 10,
            routing_calc_interval_secs: 15,
            hello_interval_secs: 60,
            hello_retries: 3,
            hello_timeout_secs: 1,
            sync_interest_lifetime_ms: 60_000,
            trust_policy: None,
            max_faces_per_prefix: 0,
        }
    }
}

/// Application-side I/O supplied to NLSR via [`NlsrProtocol::with_io`].
/// Every face NLSR touches is engine-registered and reached via the
/// ndn-app `Consumer`/`Producer` surface. See
/// `binaries/ndn-fwd/src/main.rs` for the canonical wiring:
///
/// 1. Open one engine UDP face per neighbour; capture `(name, face_id)`
///    pairs into `neighbor_face_ids`.
/// 2. Allocate one `InProcFace`/`InProcHandle` pair per Hello loop;
///    pass the handle as `hello_neighbor_handles`.
/// 3. Allocate one shared `InProcFace`/`InProcHandle` pair for the
///    Sync + LSA outbound consumer; pass as `sync_lsa_handle`.
/// 4. Mount three `Producer::serve` instances (Hello / Sync / LSA) for
///    inbound Interests with FIB entries pointing at their faces;
///    owned by the caller, not represented here.
pub struct NlsrIo {
    /// Engine-side `FaceId` of the UDP link to each neighbour.
    /// Hello loops use these to pin outbound Interests via
    /// `Consumer::fetch_on`; the Sync/LSA outbound task currently pins
    /// to the first neighbour (multi-peer fan-out is a follow-up).
    pub neighbor_face_ids: Vec<(Name, FaceId)>,

    /// Per-neighbour `InProcHandle` for Hello loops, paired by name
    /// with `neighbor_face_ids`. Each loop wraps its handle in a
    /// dedicated `Consumer` so Hello timeouts don't interleave across
    /// neighbours — see the per-loop note on
    /// [`HelloProtocol::start`].
    pub hello_neighbor_handles: Vec<(Name, InProcHandle)>,

    /// Shared `InProcHandle` for outbound Sync + LSA fetch traffic and
    /// the inbound-Data path that those fetches generate via the
    /// engine PIT.
    pub sync_lsa_handle: InProcHandle,
}

/// NLSR routing protocol.
///
/// C++ equivalent: top-level `Nlsr` class in `NLSR/src/nlsr.hpp`.
///
/// All sub-components are pre-built in `with_io`.  `start()` only
/// spawns the async tasks, following the same `Arc<Inner>` split used
/// by [`crate::protocols::dv::DvProtocol`].
pub struct NlsrProtocol {
    config: Arc<NlsrConfig>,
    lsdb: Arc<Lsdb>,
    hello: HelloProtocol,
    nlsr_sync: Arc<NlsrSync>,
    routing_table: Arc<RoutingTable>,
    /// Receiver for LSA fetch requests from `NlsrSync`.  Taken (via `Option`)
    /// exactly once in `start()` to pass to the LSA I/O task.
    lsa_fetch_rx: StdMutex<Option<mpsc::Receiver<(Name, LsaType, u64)>>>,
    /// Inbound channel for Sync Interests routed via the engine's FIB.
    /// Surface for the `Producer::serve` mount at `sync_prefix` to push
    /// PSync wire bytes into the protocol; `start()` consumes the
    /// receiver and folds it into the PSync task.
    psync_in_tx: mpsc::Sender<ndn_sync::PSyncInbound>,
    psync_in_rx: StdMutex<Option<mpsc::Receiver<ndn_sync::PSyncInbound>>>,
    /// Engine-side IO supplied via `with_io` and taken once in `start()`.
    /// `None` ⇒ the protocol runs in stub mode (no outbound traffic),
    /// which is the supported state for unit tests that exercise only
    /// the LSDB / routing-table machinery.
    io: StdMutex<Option<NlsrIo>>,
}

impl NlsrProtocol {
    /// Callers drive an ndn-app `Producer::serve` mounted on
    /// `/<own_router>/nlsr/INFO` that responds to remote Hello
    /// Interests; register the producer face in the engine FIB at
    /// that prefix.
    pub fn hello_protocol(&self) -> HelloProtocol {
        self.hello.clone()
    }

    /// Used by the `Producer::serve` mount at the sync prefix to
    /// deliver Interests into the PSync task; the producer awaits the
    /// oneshot reply and writes it back via its `Responder`.
    pub fn sync_inbound_sender(&self) -> mpsc::Sender<ndn_sync::PSyncInbound> {
        self.psync_in_tx.clone()
    }

    pub fn sync_prefix(&self) -> Name {
        self.config.sync_prefix.clone()
    }

    pub fn lsa_prefix(&self) -> Name {
        self.config.lsa_prefix.clone()
    }

    /// Look up the LSDB and return the wire-encoded Data response
    /// (or `None` if the Interest doesn't match a known own-router
    /// LSA). Used by the `Producer::serve` mount at the LSA prefix.
    pub fn handle_lsa_interest(&self, interest_wire: bytes::Bytes) -> Option<bytes::Bytes> {
        serve_lsa_interest_sync(
            interest_wire,
            &self.config.lsa_prefix,
            &self.config.network,
            &self.config.own_router,
            &self.lsdb,
        )
    }

    /// Stub mode: `start()` runs but exchanges no wire traffic. Used
    /// by unit tests that exercise only LSDB / routing-table state.
    pub fn new(config: NlsrConfig) -> Arc<Self> {
        Self::build(config, None)
    }

    /// See [`NlsrIo`] for the wiring contract.
    pub fn with_io(config: NlsrConfig, io: NlsrIo) -> Arc<Self> {
        Self::build(config, Some(io))
    }

    fn build(config: NlsrConfig, io: Option<NlsrIo>) -> Arc<Self> {
        let config = Arc::new(config);
        let lsdb = Arc::new(Lsdb::new(config.own_router.clone()));

        let (lsa_fetch_tx, lsa_fetch_rx) = mpsc::channel::<(Name, LsaType, u64)>(32);
        let (nlsr_sync, _route_notify) = NlsrSync::new(
            config.own_router.clone(),
            config.network.clone(),
            config.lsa_prefix.clone(),
            Arc::clone(&lsdb),
            lsa_fetch_tx,
        );

        let hello_cfg = HelloConfig {
            own_router: config.own_router.clone(),
            neighbors: config
                .neighbors
                .iter()
                .map(|n| HelloNeighborConfig {
                    name: n.name.clone(),
                    face_uri: n.face_uri.clone(),
                    link_cost: n.link_cost,
                })
                .collect(),
            hello_interval_secs: config.hello_interval_secs,
            hello_retries: config.hello_retries,
            hello_timeout_secs: config.hello_timeout_secs,
            lsa_refresh_ms: config.lsa_refresh_secs as u64 * 1000,
        };
        let (hello, _adj_rx) = HelloProtocol::new(hello_cfg, Arc::clone(&lsdb));

        let (routing_table, _snap_rx) = RoutingTable::new();

        let (psync_in_tx, psync_in_rx) = mpsc::channel::<ndn_sync::PSyncInbound>(256);

        Arc::new(Self {
            config,
            lsdb,
            hello,
            nlsr_sync: Arc::new(nlsr_sync),
            routing_table: Arc::new(routing_table),
            lsa_fetch_rx: StdMutex::new(Some(lsa_fetch_rx)),
            psync_in_tx,
            psync_in_rx: StdMutex::new(Some(psync_in_rx)),
            io: StdMutex::new(io),
        })
    }
}

impl RoutingProtocol for NlsrProtocol {
    fn origin(&self) -> u64 {
        origin::NLSR
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    /// Counters / peer list / LSDB shape parallels `nlsrc status`.
    fn status(&self) -> RoutingProtocolStatus {
        let lsdb_snap = self.lsdb.snapshot();
        let lsdb_size = self.lsdb.len();
        let routes_size = self.routing_table.snapshot_watch().borrow().entries.len();
        let neighbor_count = self.config.neighbors.len();

        let mut s = RoutingProtocolStatus::empty(origin::NLSR);
        s.network = Some(self.config.network.clone());
        s.router = Some(self.config.own_router.clone());
        s.counters
            .insert("nNeighbors".to_owned(), neighbor_count as u64);
        s.counters
            .insert("nLsdbEntries".to_owned(), lsdb_size as u64);
        s.counters
            .insert("nRoutingEntries".to_owned(), routes_size as u64);

        s.neighbors = self
            .config
            .neighbors
            .iter()
            .map(|n| NeighborInfo {
                name: n.name.clone(),
                face_uri: n.face_uri.clone(),
                link_cost: n.link_cost,
                state: None,
            })
            .collect();

        // `LsdbSnapshot::Display` already emits the canonical
        // `<type> <originator> seq=<n>` body; reuse it as a single
        // `LsdbEntry::summary` to populate the typed shape without
        // re-parsing LSDB internals.
        let summary = format!("{lsdb_snap}");
        if !summary.is_empty() {
            s.lsdb.push(LsdbEntry {
                lsa_type: "snapshot".to_owned(),
                originator: self.config.own_router.clone(),
                sequence: 0,
                summary,
            });
        }
        s
    }

    /// Spawns: LSDB age-out, Hello protocol, NlsrSync (LSDB ↔ PSync),
    /// routing recompute, and the NPT→RIB writer. Returns when
    /// `cancel` fires.
    fn start(&self, handle: RoutingHandle, cancel: CancellationToken) -> ndn_runtime::TaskHandle {
        let config = Arc::clone(&self.config);
        let lsdb = Arc::clone(&self.lsdb);
        let hello = self.hello.clone();
        let nlsr_sync = Arc::clone(&self.nlsr_sync);
        let routing_table = Arc::clone(&self.routing_table);
        let (rib, fib, faces) = (
            Arc::clone(&handle.rib),
            Arc::clone(&handle.fib),
            Arc::clone(&handle.faces),
        );
        // Readvertise: locally-registered app prefixes (via rib/register) are
        // announced in our NameLSA so peers learn them without manual config.
        let readvertised = Arc::new(ndn_engine::ReadvertisedPrefixes::new());
        rib.set_readvertise_destination(
            Arc::clone(&readvertised) as Arc<dyn ndn_engine::ReadvertiseDestination>,
        );
        let lsa_fetch_rx = self
            .lsa_fetch_rx
            .lock()
            .unwrap()
            .take()
            .expect("NlsrProtocol::start() called more than once");
        let engine_psync_in_rx = self
            .psync_in_rx
            .lock()
            .unwrap()
            .take()
            .expect("NlsrProtocol::start() called more than once");
        let io = self.io.lock().unwrap().take();

        let own_router_str = config.own_router.to_string();
        tokio::spawn(
          async move {
            info!(target: t::ROUTING_NLSR, router = %config.own_router, "NLSR starting");

            // 1. LSDB age-out background task.
            let _age_out = Arc::clone(&lsdb).start_age_out_task(cancel.child_token());

            // 2. Originate own NameLSA so remote nodes learn our prefixes —
            // configured static prefixes plus any readvertised app prefixes.
            let name_lsa_seq = Arc::new(std::sync::atomic::AtomicU64::new(1));
            let refresh_ms = config.lsa_refresh_secs as u64 * 1000;
            let merged = merge_name_prefixes(&config.name_prefixes, &readvertised);
            lsdb.build_own_name_lsa(
                &merged,
                name_lsa_seq.load(std::sync::atomic::Ordering::Relaxed),
                refresh_ms,
            );
            debug!(
                target: t::ROUTING_NLSR,
                router = %config.own_router,
                prefixes = merged.len(),
                "own NameLSA installed"
            );

            // Re-originate the NameLSA (bumped seq) whenever the readvertised
            // set changes, so a runtime rib/register propagates to peers
            // promptly via the existing LSDB→PSync publish path.
            {
                let lsdb_r = Arc::clone(&lsdb);
                let config_r = Arc::clone(&config);
                let readv = Arc::clone(&readvertised);
                let seq = Arc::clone(&name_lsa_seq);
                let reorig_cancel = cancel.child_token();
                tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            _ = reorig_cancel.cancelled() => break,
                            _ = readv.changed() => {
                                let s = seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                                let merged = merge_name_prefixes(&config_r.name_prefixes, &readv);
                                lsdb_r.build_own_name_lsa(
                                    &merged,
                                    s,
                                    config_r.lsa_refresh_secs as u64 * 1000,
                                );
                                debug!(
                                    target: t::ROUTING_NLSR,
                                    seq = s,
                                    prefixes = merged.len(),
                                    "own NameLSA re-originated (readvertise change)"
                                );
                            }
                        }
                    }
                });
            }

            // Hello protocol: one Consumer per neighbour loop, so
            // Hello timeouts don't interleave across neighbours. Each
            // loop pins outbound Interests via `Consumer::fetch_on`
            // (NDNLPv2 `NextHopFaceId`, TLV 0x0330).
            type HelloPairs = Vec<(Name, FaceId, Consumer)>;
            type NeighborIds = Vec<(Name, FaceId)>;
            let (hello_neighbors, neighbor_face_ids, sync_lsa_handle): (
                HelloPairs,
                NeighborIds,
                Option<InProcHandle>,
            ) = if let Some(io) = io {
                let face_id_by_name: std::collections::HashMap<Name, FaceId> =
                    io.neighbor_face_ids.iter().cloned().collect();
                let mut hello_pairs = Vec::with_capacity(io.hello_neighbor_handles.len());
                for (name, h) in io.hello_neighbor_handles {
                    let Some(fid) = face_id_by_name.get(&name).copied() else {
                        warn!(
                            target: t::ROUTING_NLSR,
                            neighbor = %name,
                            "NLSR: Hello handle supplied without matching neighbor_face_ids entry; skipping",
                        );
                        continue;
                    };
                    let conn: Arc<dyn Connection> = Arc::new(InProcConnection::new(h));
                    hello_pairs.push((name, fid, Consumer::new(conn)));
                }
                (hello_pairs, io.neighbor_face_ids, Some(io.sync_lsa_handle))
            } else {
                (Vec::new(), Vec::new(), None)
            };
            let _hello_task = hello.start(hello_neighbors, cancel.child_token());

            // PSync + LSA I/O wiring.
            //
            // Outbound Interests (PSync + LSA fetch) leave through the
            // shared `sync_lsa_handle`: a single bridge task drains
            // `face_send_tx`, wraps each Interest with `NextHopFaceId`
            // pinning the first neighbour's face, and calls
            // `Connection::send`. The engine honours the LP header and
            // forwards directly, bypassing the FIB so we don't loop
            // back through our own Producer mounts.
            //
            // Inbound Data (responses) arrives via PIT match at the
            // same handle; `conn_recv_demux` splits by name prefix
            // into PSync vs LSA install.
            //
            // Inbound Sync Interests do NOT use this handle — they
            // enter through the dedicated `Producer::serve` mount at
            // `sync_prefix` (owned by `binaries/ndn-fwd`) and
            // arrive on `engine_psync_in_rx` (folded below).

            let psync_handle: SyncHandle = if let Some(handle) = sync_lsa_handle {
                let pin_face_id = neighbor_face_ids.first().map(|(_, f)| *f);
                let conn: Arc<dyn Connection> = Arc::new(InProcConnection::new(handle));

                let (face_send_tx, face_send_rx) = mpsc::channel::<bytes::Bytes>(256);
                let (psync_in_tx, psync_in_rx) = mpsc::channel::<ndn_sync::PSyncInbound>(256);
                let (lsa_in_tx, lsa_in_rx) = mpsc::channel::<bytes::Bytes>(256);

                // Bridge engine-side inbound Sync Interests (from the
                // Producer mount at sync_prefix) into the same PSync
                // receiver that owns outbound sends — otherwise our
                // peer's Sync Interests are silently dropped and
                // bidirectional reconciliation never happens.
                //
                // C++ NLSR achieves this via two NFD app faces
                // (NLSR/src/communication/sync-logic-handler.cpp);
                // ndn-rs runs the engine and NLSR in one process and
                // routes both directions through the same channel.
                let bridge_tx = psync_in_tx.clone();
                let mut engine_rx = engine_psync_in_rx;
                let bridge_cancel = cancel.child_token();
                tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            _ = bridge_cancel.cancelled() => break,
                            Some(item) = engine_rx.recv() => {
                                let _ = bridge_tx.send(item).await;
                            }
                            else => break,
                        }
                    }
                });

                tokio::spawn(
                    conn_recv_demux(
                        Arc::clone(&conn),
                        config.lsa_prefix.clone(),
                        psync_in_tx,
                        lsa_in_tx,
                        cancel.child_token(),
                    )
                    .instrument(tracing::info_span!(target: t::ROUTING_NLSR, "nlsr_conn_demux")),
                );

                tokio::spawn(
                    conn_send_task(
                        face_send_rx,
                        Arc::clone(&conn),
                        pin_face_id,
                        cancel.child_token(),
                    )
                    .instrument(tracing::info_span!(target: t::ROUTING_NLSR, "nlsr_conn_send")),
                );

                // LSA I/O task is outbound-fetch only; inbound serve
                // is handled by the `Producer::serve` mount in
                // `binaries/ndn-fwd` calling
                // [`NlsrProtocol::handle_lsa_interest`].
                tokio::spawn(
                    lsa_io_task(
                        config.lsa_prefix.clone(),
                        config.network.clone(),
                        lsa_in_rx,
                        face_send_tx.clone(),
                        lsa_fetch_rx,
                        Arc::clone(&lsdb),
                        cancel.child_token(),
                    )
                    .instrument(tracing::info_span!(target: t::ROUTING_NLSR, "lsa_io")),
                );

                let psync_cfg = PSyncConfig {
                    sync_interval: Duration::from_millis(
                        config.sync_interest_lifetime_ms / 60,
                    ),
                    ..PSyncConfig::default()
                };
                // PSync group `/localhop/<network>/nlsr/sync/v=12`
                // (C++ NLSR SYNC_VERSION=12,
                // NLSR/src/conf-parameter.hpp:534).
                join_psync_group(config.sync_prefix.clone(), face_send_tx, psync_in_rx, psync_cfg)
            } else {
                warn!(target: t::ROUTING_NLSR, "NLSR: no sync IO handle available; running in stub mode (no outbound PSync)");
                stub_sync_handle(cancel.child_token())
            };

            let nlsr_sync_c = Arc::clone(&nlsr_sync);
            tokio::spawn(
                nlsr_sync_c
                    .run(psync_handle, cancel.child_token())
                    .instrument(tracing::info_span!(target: t::ROUTING_NLSR, "nlsr_sync")),
            );

            // Routing recompute + NPT → RIB writer: on every AdjLSA
            // or NameLSA change, rerun Dijkstra, refresh the NPT, diff
            // against the previous RIB snapshot, and apply.
            let rt = Arc::clone(&routing_table);
            let lsdb_rt = Arc::clone(&lsdb);
            let rib_rt = Arc::clone(&rib);
            let fib_rt = Arc::clone(&fib);
            let faces_rt = Arc::clone(&faces);
            let own_router = config.own_router.clone();
            let nlsr_origin = origin::NLSR;
            let max_faces = config.max_faces_per_prefix;
            let recompute_cancel = cancel.child_token();

            tokio::spawn(
                async move {
                    let mut npt = NamePrefixTable::new();
                    let mut lsdb_events = lsdb_rt.event_stream();
                    let mut snap_rx = rt.snapshot_watch();
                    let mut rib_installed: HashSet<(Name, String)> = HashSet::new();

                    loop {
                        tokio::select! {
                            biased;
                            _ = recompute_cancel.cancelled() => break,

                            Ok(event) = lsdb_events.recv() => {
                                npt.update_from_lsdb(&event, &own_router);
                                if matches!(
                                    event.lsa.lsa_type(),
                                    LsaType::Adjacency | LsaType::Name
                                ) {
                                    rt.recompute(&lsdb_rt, &own_router);
                                }
                            }

                            Ok(()) = snap_rx.changed() => {
                                let snapshot = snap_rx.borrow_and_update().clone();
                                npt.update_with_new_route(&snapshot);
                                rib_installed = apply_npt_to_rib(
                                    &npt.snapshot(),
                                    &rib_installed,
                                    &rib_rt,
                                    &fib_rt,
                                    &faces_rt,
                                    nlsr_origin,
                                    max_faces,
                                );
                            }
                        }
                    }
                }
                .instrument(tracing::info_span!(target: t::ROUTING_NLSR, "nlsr_recompute")),
            );

            cancel.cancelled().await;
            info!(target: t::ROUTING_NLSR, router = %config.own_router, "NLSR stopped");
          }
          .instrument(tracing::info_span!(
              target: t::ROUTING_NLSR,
              "nlsr_coordinator",
              router = own_router_str,
          )),
        )
        .into()
    }
}

/// Union of the statically-configured NameLSA prefixes and the prefixes
/// readvertised from local rib/register, deduped in canonical name order.
fn merge_name_prefixes(
    static_prefixes: &[Name],
    readvertised: &ndn_engine::ReadvertisedPrefixes,
) -> Vec<Name> {
    let mut set: std::collections::BTreeSet<Name> = static_prefixes.iter().cloned().collect();
    set.extend(readvertised.snapshot());
    set.into_iter().collect()
}

/// O(n) over the face table; uses [`FaceTable::face_info`] so the
/// lookup returns just the face id — what `rib.add` / `rib.remove`
/// need.
fn find_face_id_by_uri(faces: &FaceTable, uri: &str) -> Option<FaceId> {
    faces
        .face_info()
        .into_iter()
        .find(|info| info.remote_uri.as_deref() == Some(uri))
        .map(|info| info.id)
}

/// Pins each Interest's NDNLPv2 `NextHopFaceId` (TLV 0x0330) to
/// `pin_face_id` so the engine bypasses FIB lookup. `None` sends the
/// packet as-is and lets the strategy handle it via FIB (test path).
async fn conn_send_task(
    mut rx: mpsc::Receiver<bytes::Bytes>,
    conn: Arc<dyn Connection>,
    pin_face_id: Option<FaceId>,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            Some(pkt) = rx.recv() => {
                let wire = match pin_face_id {
                    Some(fid) => {
                        let headers = LpHeaders {
                            pit_token: None,
                            congestion_mark: None,
                            incoming_face_id: None,
                            next_hop_face_id: Some(fid.0),
                            cache_policy: None,
                        };
                        encode_lp_with_headers(&pkt, &headers)
                    }
                    None => pkt,
                };
                if conn.send(wire).await.is_err() {
                    warn!(target: t::ROUTING_NLSR, "NLSR conn send: connection closed");
                    break;
                }
            }
        }
    }
}

/// Splits inbound bytes onto PSync vs LSA paths by inspecting the
/// first TLV byte (0x05 Interest / 0x06 Data) and checking whether
/// the name falls under `lsa_prefix`. Inbound bytes here are usually
/// Data (PIT matches for our outbound fetches), but the demux also
/// handles Interests that arrive opportunistically.
async fn conn_recv_demux(
    conn: Arc<dyn Connection>,
    lsa_prefix: Name,
    psync_tx: mpsc::Sender<ndn_sync::PSyncInbound>,
    lsa_tx: mpsc::Sender<bytes::Bytes>,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            opt = conn.recv() => {
                match opt {
                    Some(pkt) => {
                        if is_lsa_packet(&pkt, &lsa_prefix) {
                            let _ = lsa_tx.send(pkt).await;
                        } else {
                            let _ = psync_tx.send(pkt.into()).await;
                        }
                    }
                    None => {
                        warn!(target: t::ROUTING_NLSR, "NLSR conn recv demux: connection closed");
                        break;
                    }
                }
            }
        }
    }
}

fn is_lsa_packet(raw: &bytes::Bytes, lsa_prefix: &Name) -> bool {
    if raw.len() < 2 {
        return false;
    }
    let name = match raw[0] {
        0x05 => ndn_packet::Interest::decode(raw.clone())
            .ok()
            .map(|i| (*i.name).clone()),
        0x06 => ndn_packet::Data::decode(raw.clone())
            .ok()
            .map(|d| (*d.name).clone()),
        _ => None,
    };
    name.map(|n| n.has_prefix(lsa_prefix)).unwrap_or(false)
}

/// Outbound: when `NlsrSync` receives a PSync update without inline
/// mapping bytes (C++ NLSR path), we get `(origin_router, lsa_type,
/// seq)` and build/send an LSA Interest via `face_send_tx`.
///
/// Inbound: Data returned via PIT match on the shared sync/LSA
/// handle arrives on `lsa_in_rx` and is installed in the LSDB.
///
/// Inbound LSA *Interests* are handled by the `Producer::serve`
/// mount in `binaries/ndn-fwd` calling
/// [`NlsrProtocol::handle_lsa_interest`].
async fn lsa_io_task(
    lsa_prefix: Name,
    network: Name,
    mut lsa_in_rx: mpsc::Receiver<bytes::Bytes>,
    face_send_tx: mpsc::Sender<bytes::Bytes>,
    mut lsa_fetch_rx: mpsc::Receiver<(Name, LsaType, u64)>,
    lsdb: Arc<Lsdb>,
    cancel: CancellationToken,
) {
    use ndn_packet::encode::InterestBuilder;

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,

            // Outbound fetch: PSync update arrived without mapping bytes.
            Some((origin_router, lsa_type, seq_no)) = lsa_fetch_rx.recv() => {
                // Build Interest name: <lsa_prefix>/<router_suffix>/<TYPE>/<seqNo>
                // router_suffix = origin_router minus network prefix components.
                // C++ NLSR: lsdb.cpp:137 — lsaInterest = updateName; lsaInterest.appendNumber(seqNo)
                let type_str: &[u8] = match lsa_type {
                    LsaType::Adjacency => b"ADJACENCY",
                    LsaType::Name => b"NAME",
                    LsaType::Coordinate => b"COORDINATE",
                };
                let network_len = network.components().len();
                let mut interest_name = lsa_prefix.clone();
                for comp in origin_router.components().iter().skip(network_len) {
                    interest_name = interest_name.append_component(comp.clone());
                }
                // seqNo as GenericNameComponent with NNI value — C++ appendNumber().
                interest_name = interest_name
                    .append(type_str)
                    .append_component(NameComponent::generic(encode_nni_minimal(seq_no)));

                // LsaInterestLifetime = 4 s per C++ lsdb.cpp:497.
                let interest_bytes = InterestBuilder::new(interest_name.clone())
                    .lifetime(Duration::from_secs(4))
                    .can_be_prefix()
                    .build();

                tracing::trace!(
                    target: t::ROUTING_NLSR,
                    %interest_name, %origin_router, ?lsa_type, seq_no,
                    "LSA fetch: expressing Interest"
                );
                let _ = face_send_tx.send(interest_bytes).await;
            }

            // Inbound LSA Data — install into the LSDB.
            Some(pkt) = lsa_in_rx.recv() => {
                if pkt.is_empty() { continue; }
                if pkt[0] == 0x06 {
                    install_lsa_from_data(pkt, &lsa_prefix, &network, &lsdb).await;
                }
            }
        }
    }
}

/// Returns the Data wire if the Interest matches an own-router LSA
/// we hold, otherwise `None`.
fn serve_lsa_interest_sync(
    pkt: bytes::Bytes,
    lsa_prefix: &Name,
    network: &Name,
    own_router: &Name,
    lsdb: &Arc<Lsdb>,
) -> Option<bytes::Bytes> {
    use ndn_packet::encode::DataBuilder;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    let interest = ndn_packet::Interest::decode(pkt).ok()?;
    let interest_name = (*interest.name).clone();
    let comps = interest_name.components();

    // Strip trailing /<version>/<segment> if present (SegmentFetcher
    // retry; C++ lsdb.cpp:217).
    let base: &[ndn_packet::NameComponent] = if comps.len() >= 2
        && comps[comps.len() - 1].as_segment().is_some()
        && comps[comps.len() - 2].as_version().is_some()
    {
        &comps[..comps.len() - 2]
    } else {
        comps
    };

    let prefix_len = lsa_prefix.components().len();
    if base.len() < prefix_len + 3 {
        return None;
    }

    for (a, b) in base[..prefix_len].iter().zip(lsa_prefix.components()) {
        if a != b {
            return None;
        }
    }

    let seq_no = nni_from_comp(&base[base.len() - 1])?;
    let lsa_type = match base[base.len() - 2].value.as_ref() {
        b"ADJACENCY" => LsaType::Adjacency,
        b"NAME" => LsaType::Name,
        b"COORDINATE" => LsaType::Coordinate,
        _ => return None,
    };

    let router_comps = &base[prefix_len..base.len() - 2];
    let origin_router = Name::from_components(
        network
            .components()
            .iter()
            .chain(router_comps.iter())
            .cloned(),
    );

    // C++ NLSR's `processInterestForLsa` only serves own-router LSAs;
    // other routers' LSAs come from storage.
    if &origin_router != own_router {
        tracing::trace!(
            target: t::ROUTING_NLSR, %origin_router,
            "LSA Interest for non-own router — ignoring"
        );
        return None;
    }

    let Some(lsa) = lsdb.lookup(&origin_router, lsa_type) else {
        tracing::trace!(target: t::ROUTING_NLSR, %origin_router, ?lsa_type, "LSA not in LSDB");
        return None;
    };

    // Serve only when seqNo matches (C++ lsdb.cpp:276).
    if lsa.seq_no() != seq_no {
        tracing::trace!(
            target: t::ROUTING_NLSR,
            %origin_router, ?lsa_type, seq_no, stored = lsa.seq_no(),
            "LSA seqNo mismatch, not serving"
        );
        return None;
    }

    let lsa_bytes = lsa.wire_encode();

    // Data name: `<base_interest_name>/<version=µs>/<seg=0>`
    // (C++ lsdb.cpp:279).
    let version = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64;
    let base_name = Name::from_components(base.iter().cloned());
    let data_name = base_name.append_version(version).append_segment(0);

    // DigestSha256 matches the testbed's permissive_validation=true.
    // Engine identity-key signing is a follow-up once the receive
    // path threads the engine Validator.
    let data_bytes = DataBuilder::new(data_name.clone(), &lsa_bytes)
        .freshness(Duration::from_secs(3600))
        .final_block_id_typed_seg(0)
        .sign_digest_sha256();

    tracing::trace!(
        target: t::ROUTING_NLSR,
        %data_name, %origin_router, ?lsa_type, seq_no,
        "LSA serve: sending Data"
    );
    Some(data_bytes)
}

/// Data name:
/// `<lsa_prefix>/<router_suffix>/<TYPE>/<seqNo>/<version>/<seg=0>`.
/// C++ ref: `Lsdb::afterFetchLsa` (`NLSR/src/lsdb.cpp:557`).
async fn install_lsa_from_data(
    pkt: bytes::Bytes,
    lsa_prefix: &Name,
    network: &Name,
    lsdb: &Arc<Lsdb>,
) {
    let Ok(data) = ndn_packet::Data::decode(pkt) else {
        return;
    };
    let data_name = (*data.name).clone();
    let comps = data_name.components();

    // Strip trailing /<version>/<segment> to get the base (= Interest) name.
    let base: &[ndn_packet::NameComponent] = if comps.len() >= 2
        && comps[comps.len() - 1].as_segment().is_some()
        && comps[comps.len() - 2].as_version().is_some()
    {
        &comps[..comps.len() - 2]
    } else {
        comps
    };

    let prefix_len = lsa_prefix.components().len();
    if base.len() < prefix_len + 3 {
        return;
    }

    let seq_no = match nni_from_comp(&base[base.len() - 1]) {
        Some(n) => n,
        None => return,
    };
    let lsa_type = match base[base.len() - 2].value.as_ref() {
        b"ADJACENCY" => LsaType::Adjacency,
        b"NAME" => LsaType::Name,
        b"COORDINATE" => LsaType::Coordinate,
        _ => return,
    };

    let router_comps = &base[prefix_len..base.len() - 2];
    let origin_router = Name::from_components(
        network
            .components()
            .iter()
            .chain(router_comps.iter())
            .cloned(),
    );

    let Some(content) = data.content() else {
        tracing::warn!(target: t::ROUTING_NLSR, %origin_router, ?lsa_type, seq_no, "LSA Data has no content");
        return;
    };

    // Data-signature validation is not yet wired into this receive
    // path — the engine Validator supports RSA/ECDSA but lives on a
    // separate codepath. Until lsa_io_task threads it, NLSR keeps
    // permissive_validation=true.
    match crate::protocols::nlsr::lsa::Lsa::wire_decode(lsa_type, content.clone()) {
        Ok(lsa) => {
            let result = lsdb.install(lsa);
            tracing::trace!(
                target: t::ROUTING_NLSR,
                %origin_router, ?lsa_type, seq_no, ?result,
                "LSA installed from Data"
            );
        }
        Err(e) => {
            tracing::warn!(
                target: t::ROUTING_NLSR,
                %origin_router, ?lsa_type, seq_no, error = %e,
                "LSA Data: wire_decode failed"
            );
        }
    }
}

/// Handles typed (`SequenceNum`, `Segment`) and raw generic NNI
/// components (C++ `appendNumber()`).
fn nni_from_comp(comp: &ndn_packet::NameComponent) -> Option<u64> {
    comp.as_sequence_num()
        .or_else(|| comp.as_segment())
        .or_else(|| parse_nni_bytes(&comp.value))
}

fn parse_nni_bytes(value: &[u8]) -> Option<u64> {
    match value.len() {
        1 => Some(value[0] as u64),
        2 => Some(u16::from_be_bytes([value[0], value[1]]) as u64),
        4 => Some(u32::from_be_bytes([value[0], value[1], value[2], value[3]]) as u64),
        8 => Some(u64::from_be_bytes(value.try_into().ok()?)),
        _ => None,
    }
}

/// Minimal big-endian NNI; C++ `appendNumber()` format.
fn encode_nni_minimal(n: u64) -> bytes::Bytes {
    let b = n.to_be_bytes();
    bytes::Bytes::copy_from_slice(match n {
        0..=0xFF => &b[7..],
        0x100..=0xFFFF => &b[6..],
        0x10000..=0xFFFF_FFFF => &b[4..],
        _ => &b,
    })
}

fn stub_sync_handle(cancel: CancellationToken) -> SyncHandle {
    let (_update_tx, update_rx) = mpsc::channel::<SyncUpdate>(1);
    let (publish_tx, _publish_rx) = mpsc::channel::<(Name, Option<bytes::Bytes>)>(1);
    SyncHandle::new(update_rx, publish_tx, cancel)
}

/// Diffs the new NPT snapshot against the currently installed RIB
/// set, applies the delta, and returns the new installed set.
fn apply_npt_to_rib(
    new_entries: &[(Name, Vec<NextHop>)],
    old_installed: &HashSet<(Name, String)>,
    rib: &ndn_engine::Rib,
    fib: &ndn_engine::Fib,
    faces: &Arc<FaceTable>,
    nlsr_origin: u64,
    max_faces: usize,
) -> HashSet<(Name, String)> {
    let mut new_installed: HashSet<(Name, String)> = HashSet::new();

    // Add new/updated routes.
    for (prefix, nexthops) in new_entries {
        let hops: &[NextHop] = if max_faces > 0 && nexthops.len() > max_faces {
            &nexthops[..max_faces]
        } else {
            nexthops
        };

        for nh in hops {
            new_installed.insert((prefix.clone(), nh.face_uri.clone()));

            let Some(face_id) = find_face_id_by_uri(faces, &nh.face_uri) else {
                debug!(
                    target: t::ROUTING_NLSR,
                    prefix = %prefix,
                    uri = %nh.face_uri,
                    "NLSR: no face for nexthop URI, skipping RIB entry"
                );
                continue;
            };

            rib.add(
                prefix,
                RibRoute {
                    face_id,
                    origin: nlsr_origin,
                    cost: nh.cost as u32,
                    flags: route_flags::CHILD_INHERIT,
                    expires_at: None,
                },
            );
            rib.apply_to_fib(prefix, fib);
            info!(target: t::ROUTING_NLSR, prefix = %prefix, uri = %nh.face_uri, cost = nh.cost, "NLSR route added");
        }
    }

    // Remove routes that are no longer in the NPT.
    for (prefix, uri) in old_installed {
        if !new_installed.contains(&(prefix.clone(), uri.clone()))
            && let Some(face_id) = find_face_id_by_uri(faces, uri)
        {
            rib.remove(prefix, face_id, nlsr_origin);
            rib.apply_to_fib(prefix, fib);
            info!(target: t::ROUTING_NLSR, prefix = %prefix, uri = %uri, "NLSR route removed");
        }
    }

    new_installed
}
