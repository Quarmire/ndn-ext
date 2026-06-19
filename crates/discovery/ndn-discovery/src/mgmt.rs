//! NFD-compatible management modules for discovery — `/localhost/nfd/discovery`
//! and `/localhost/nfd/service`.
//!
//! These used to live in `ndn-mgmt`, which forced `ndn-mgmt` (a core/spec crate)
//! to depend on `ndn-discovery` (an extension). They now live here and implement
//! [`ndn_mgmt::MgmtModule`] (a downstream→core dependency), capturing the
//! discovery handles at construction. A host wires them in via
//! [`MgmtHandles::extra_modules`](ndn_mgmt::MgmtHandles); `ndn-mgmt` no longer
//! references discovery at all. The neighbor-table dump (`neighbors`) stays in
//! `ndn-mgmt` because its types (`NeighborState`/`NeighborTable`) live in
//! `ndn-discovery-core`, which `ndn-mgmt` still shares.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use async_trait::async_trait;

use ndn_engine::ForwarderEngine;
use ndn_mgmt::module::{MgmtContext, MgmtModule};
use ndn_mgmt::{MgmtResponse, is_management_face, is_reserved_name};
use ndn_mgmt_wire::{
    ControlParameters, ControlResponse,
    control_response::status,
    nfd_command::{module, verb},
};
use ndn_packet::Name;
use ndn_transport::FaceId;

use crate::config::{DiscoveryConfig, HelloStrategyKind, PrefixAnnouncementMode};
use crate::service_discovery::ServiceDiscoveryProtocol;
use crate::prefix_announce::ServiceRecord;

// ---------------------------------------------------------------------------
// `/localhost/nfd/discovery/{status, config}` — runtime-mutable Hello config.
// ---------------------------------------------------------------------------

/// Serves `discovery/{status,config}`. Holds the shared, runtime-mutable
/// [`DiscoveryConfig`]; `None` means discovery is not enabled on this host.
pub struct DiscoveryMgmtModule {
    cfg: Option<Arc<RwLock<DiscoveryConfig>>>,
}

impl DiscoveryMgmtModule {
    pub fn new(cfg: Option<Arc<RwLock<DiscoveryConfig>>>) -> Self {
        Self { cfg }
    }
}

fn handle_discovery(
    verb_name: &[u8],
    params: ControlParameters,
    discovery_cfg: Option<&Arc<RwLock<DiscoveryConfig>>>,
) -> ControlResponse {
    match verb_name {
        v if v == b"status" => discovery_status(discovery_cfg),
        v if v == verb::CONFIG => discovery_config_set(params, discovery_cfg),
        _ => ControlResponse::error(status::NOT_FOUND, "unknown discovery verb"),
    }
}

fn discovery_status(discovery_cfg: Option<&Arc<RwLock<DiscoveryConfig>>>) -> ControlResponse {
    let Some(cfg_lock) = discovery_cfg else {
        return ControlResponse::error(status::NOT_FOUND, "discovery not enabled");
    };
    let cfg = cfg_lock.read().unwrap();
    let strategy_str = match cfg.hello_strategy {
        HelloStrategyKind::Backoff => "backoff",
        HelloStrategyKind::Reactive => "reactive",
        HelloStrategyKind::Passive => "passive",
    };
    let prefix_ann_str = match cfg.prefix_announcement {
        PrefixAnnouncementMode::Static => "static",
        PrefixAnnouncementMode::InHello => "in-hello",
        PrefixAnnouncementMode::NlsrLsa => "nlsr-lsa",
    };
    let text = format!(
        "discovery: enabled\n\
         hello_strategy: {strategy_str}\n\
         hello_interval_base_ms: {}\n\
         hello_interval_max_ms: {}\n\
         hello_jitter: {:.2}\n\
         liveness_timeout_ms: {}\n\
         liveness_miss_count: {}\n\
         probe_timeout_ms: {}\n\
         prefix_announcement: {prefix_ann_str}\n\
         auto_create_faces: {}\n\
         tick_interval_ms: {}\n",
        cfg.hello_interval_base.as_millis(),
        cfg.hello_interval_max.as_millis(),
        cfg.hello_jitter,
        cfg.liveness_timeout.as_millis(),
        cfg.liveness_miss_count,
        cfg.probe_timeout.as_millis(),
        cfg.auto_create_faces,
        cfg.tick_interval.as_millis(),
    );
    ControlResponse::ok_empty(text)
}

fn discovery_config_set(
    params: ControlParameters,
    discovery_cfg: Option<&Arc<RwLock<DiscoveryConfig>>>,
) -> ControlResponse {
    let Some(cfg_lock) = discovery_cfg else {
        return ControlResponse::error(status::NOT_FOUND, "discovery not enabled");
    };
    let Some(query) = &params.uri else {
        return discovery_status(discovery_cfg);
    };
    {
        let mut cfg = cfg_lock.write().unwrap();
        for pair in query.split('&') {
            let mut parts = pair.splitn(2, '=');
            let key = parts.next().unwrap_or("").trim();
            let val = parts.next().unwrap_or("").trim();
            match key {
                "hello_interval_base_ms" => {
                    if let Ok(ms) = val.parse::<u64>() {
                        cfg.hello_interval_base = Duration::from_millis(ms);
                    }
                }
                "hello_interval_max_ms" => {
                    if let Ok(ms) = val.parse::<u64>() {
                        cfg.hello_interval_max = Duration::from_millis(ms);
                    }
                }
                "hello_jitter" => {
                    if let Ok(v) = val.parse::<f32>() {
                        cfg.hello_jitter = v.clamp(0.0, 0.5);
                    }
                }
                "liveness_timeout_ms" => {
                    if let Ok(ms) = val.parse::<u64>() {
                        cfg.liveness_timeout = Duration::from_millis(ms);
                    }
                }
                "liveness_miss_count" => {
                    if let Ok(v) = val.parse::<u32>() {
                        cfg.liveness_miss_count = v;
                    }
                }
                "probe_timeout_ms" => {
                    if let Ok(ms) = val.parse::<u64>() {
                        cfg.probe_timeout = Duration::from_millis(ms);
                    }
                }
                "auto_create_faces" => {
                    cfg.auto_create_faces = val == "true" || val == "1";
                }
                _ => {}
            }
        }
        tracing::info!(target: "discovery", params = %query, "discovery/config updated");
    }
    discovery_status(discovery_cfg)
}

#[async_trait]
impl MgmtModule for DiscoveryMgmtModule {
    fn name(&self) -> &'static [u8] {
        module::DISCOVERY
    }

    async fn dispatch(
        &self,
        verb: &[u8],
        params: ControlParameters,
        _ctx: &MgmtContext<'_>,
    ) -> MgmtResponse {
        handle_discovery(verb, params, self.cfg.as_ref()).into()
    }
}

// ---------------------------------------------------------------------------
// `/localhost/nfd/service/{list, browse, announce, withdraw}` — ndn-rs SD.
// ---------------------------------------------------------------------------

/// Serves `service/{list,browse,announce,withdraw}`. Holds the service-discovery
/// protocol handle and the discovery-claimed namespaces; `sd = None` means
/// service discovery is not enabled.
pub struct ServiceMgmtModule {
    sd: Option<Arc<ServiceDiscoveryProtocol>>,
    claimed: Vec<Name>,
}

impl ServiceMgmtModule {
    pub fn new(sd: Option<Arc<ServiceDiscoveryProtocol>>, claimed: Vec<Name>) -> Self {
        Self { sd, claimed }
    }
}

fn handle_service(
    verb_name: &[u8],
    params: ControlParameters,
    engine: &ForwarderEngine,
    source_face: Option<FaceId>,
    discovery_sd: Option<&ServiceDiscoveryProtocol>,
    discovery_claimed: &[Name],
) -> ControlResponse {
    let sd = match discovery_sd {
        Some(s) => s,
        None => {
            return ControlResponse::error(status::NOT_FOUND, "service discovery is not enabled");
        }
    };
    match verb_name {
        v if v == verb::LIST => service_list(sd),
        v if v == verb::BROWSE => service_browse(params, sd),
        v if v == verb::ANNOUNCE => {
            service_announce(params, sd, engine, source_face, discovery_claimed)
        }
        v if v == verb::WITHDRAW => service_withdraw(params, sd),
        _ => ControlResponse::error(status::NOT_FOUND, "unknown service verb"),
    }
}

fn service_list(sd: &ServiceDiscoveryProtocol) -> ControlResponse {
    let records = sd.local_records();
    let mut text = format!("{} services\n", records.len());
    for r in &records {
        text.push_str(&format!(
            "  {}  node={}  freshness={}ms\n",
            r.announced_prefix, r.node_name, r.freshness_ms,
        ));
    }
    ControlResponse::ok_empty(text)
}

fn service_browse(params: ControlParameters, sd: &ServiceDiscoveryProtocol) -> ControlResponse {
    let filter = params.name;
    let records = sd.all_records();
    let filtered: Vec<_> = records
        .iter()
        .filter(|r| {
            filter
                .as_ref()
                .is_none_or(|p| r.announced_prefix.has_prefix(p))
        })
        .collect();
    let mut text = format!("{} services\n", filtered.len());
    for r in &filtered {
        text.push_str(&format!(
            "  {}  node={}  freshness={}ms\n",
            r.announced_prefix, r.node_name, r.freshness_ms,
        ));
    }
    ControlResponse::ok_empty(text)
}

fn service_announce(
    params: ControlParameters,
    sd: &ServiceDiscoveryProtocol,
    engine: &ForwarderEngine,
    source_face: Option<FaceId>,
    discovery_claimed: &[Name],
) -> ControlResponse {
    let prefix = match params.name {
        Some(n) => n,
        None => return ControlResponse::error(status::BAD_PARAMS, "Name is required"),
    };

    if !is_management_face(source_face, engine) {
        let shadows_discovery = discovery_claimed
            .iter()
            .any(|cp| prefix.has_prefix(cp) || cp.has_prefix(&prefix));
        if shadows_discovery {
            return ControlResponse::error(
                status::UNAUTHORIZED,
                format!("prefix {prefix} overlaps with a discovery-owned namespace"),
            );
        }
    }

    if is_reserved_name(&prefix) && !is_management_face(source_face, engine) {
        return ControlResponse::error(
            status::UNAUTHORIZED,
            format!("prefix {prefix} is reserved for operator use"),
        );
    }

    let node_name = sd
        .local_records()
        .into_iter()
        .next()
        .map(|r| r.node_name)
        .unwrap_or_else(|| prefix.clone());

    let record = ServiceRecord::new(prefix.clone(), node_name);
    let owner_face = engine.fib().lpm(&prefix).and_then(|e| {
        e.nexthops_excluding(source_face.unwrap_or(FaceId::INVALID))
            .into_iter()
            .next()
            .map(|nh| nh.face_id)
    });

    if let Some(face) = owner_face {
        sd.publish_with_owner(record, face);
        tracing::info!(target: "discovery", prefix = %prefix, owner_face = ?face, "service/announce (owned by face)");
    } else {
        sd.publish(record);
        tracing::info!(target: "discovery", prefix = %prefix, "service/announce (permanent — no FIB route found)");
    }

    let echo = ControlParameters {
        name: Some(prefix),
        ..Default::default()
    };
    ControlResponse::ok("OK", echo)
}

fn service_withdraw(params: ControlParameters, sd: &ServiceDiscoveryProtocol) -> ControlResponse {
    let prefix = match params.name {
        Some(n) => n,
        None => return ControlResponse::error(status::BAD_PARAMS, "Name is required"),
    };

    sd.withdraw(&prefix);
    tracing::info!(target: "discovery", prefix = %prefix, "service/withdraw");

    let echo = ControlParameters {
        name: Some(prefix),
        ..Default::default()
    };
    ControlResponse::ok("OK", echo)
}

#[async_trait]
impl MgmtModule for ServiceMgmtModule {
    fn name(&self) -> &'static [u8] {
        module::SERVICE
    }

    async fn dispatch(
        &self,
        verb: &[u8],
        params: ControlParameters,
        ctx: &MgmtContext<'_>,
    ) -> MgmtResponse {
        handle_service(
            verb,
            params,
            ctx.engine,
            ctx.source_face,
            self.sd.as_deref(),
            &self.claimed,
        )
        .into()
    }
}
