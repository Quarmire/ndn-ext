//! Service-layer dataset models — the forwarder's service-discovery state.
//!
//! Pure model + wire parsing for the ndn-discovery management datasets
//! (`service/browse`, `service/list`, `discovery/status`). Consumers own the
//! transport: they send the signed commands (these are extended mgmt modules
//! — always signed), hand the response text here, and render the typed result.
//!
//! **Read-only, by construction:** nothing in this module mutates — no
//! `announce`/`withdraw`.
//!
//! Scope note (service-layer.md): the NDNSF four-phase exchange status
//! (REQUEST→ACK→SELECTION→RESPONSE) and NAC-ABE access grants are not yet
//! observable — the forwarder does not run the NDNSF compatibility layer
//! (`ndnsf-rs`). When it does, its status belongs here.

/// One service-discovery record: a service prefix announced by a node, with
/// the announcing node's name and the record's freshness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceRecord {
    /// The announced service prefix (e.g. `/service/telemetry`).
    pub prefix: String,
    /// The announcing node's node-name (e.g. `/nodes/abc`).
    pub node: String,
    /// Freshness period in milliseconds (`0` = rely on NDN FreshnessPeriod).
    pub freshness_ms: u64,
    /// `true` when this node itself announced the record (present in
    /// `service/list`).
    pub local: bool,
}

/// The forwarder's runtime discovery (Hello) configuration, as reported by
/// `discovery/status`.
#[derive(Debug, Clone, PartialEq)]
pub struct DiscoveryStatus {
    /// `backoff` | `reactive` | `passive`.
    pub hello_strategy: String,
    pub hello_interval_base_ms: u64,
    pub hello_interval_max_ms: u64,
    pub hello_jitter: f32,
    pub liveness_timeout_ms: u64,
    pub liveness_miss_count: u32,
    pub probe_timeout_ms: u64,
    /// `static` | `in-hello` | `nlsr-lsa`.
    pub prefix_announcement: String,
    pub auto_create_faces: bool,
    pub tick_interval_ms: u64,
}

/// A point-in-time snapshot of the service layer as the forwarder sees it.
#[derive(Debug, Clone, Default)]
pub struct ServiceState {
    /// `None` when discovery is not enabled on the forwarder.
    pub discovery: Option<DiscoveryStatus>,
    /// All known service records (local + peer-discovered).
    pub services: Vec<ServiceRecord>,
}

/// Parse a `service/browse` (or `service/list`) response body.
///
/// Producer format (ndn-discovery mgmt): a `"{n} services"` header line, then
/// one `"  {prefix}  node={node}  freshness={ms}ms"` line per record. NDN name
/// components may contain spaces, so each line is anchored from the right: the
/// `  freshness=` tail, then the last `  node=`, and whatever remains (minus
/// the two-space indent) is the prefix.
pub fn parse_service_browse(text: &str) -> Vec<ServiceRecord> {
    let mut out = Vec::new();
    for line in text.lines() {
        let Some(fpos) = line.rfind("  freshness=") else {
            continue; // header or malformed
        };
        let tail = &line[fpos + "  freshness=".len()..];
        let Some(ms_str) = tail.strip_suffix("ms") else {
            continue;
        };
        let Ok(freshness_ms) = ms_str.parse::<u64>() else {
            continue;
        };
        let head = &line[..fpos];
        let Some(npos) = head.rfind("  node=") else {
            continue;
        };
        let prefix = head[..npos].trim_start();
        let node = &head[npos + "  node=".len()..];
        if prefix.is_empty() || node.is_empty() {
            continue;
        }
        out.push(ServiceRecord {
            prefix: prefix.to_string(),
            node: node.to_string(),
            freshness_ms,
            local: false,
        });
    }
    out
}

/// Parse a `discovery/status` response body. `None` when discovery is not
/// enabled (the producer answers 404 in that case, and any non-`enabled`
/// body is treated as absent rather than half-parsed).
pub fn parse_discovery_status(text: &str) -> Option<DiscoveryStatus> {
    let mut st = DiscoveryStatus {
        hello_strategy: String::new(),
        hello_interval_base_ms: 0,
        hello_interval_max_ms: 0,
        hello_jitter: 0.0,
        liveness_timeout_ms: 0,
        liveness_miss_count: 0,
        probe_timeout_ms: 0,
        prefix_announcement: String::new(),
        auto_create_faces: false,
        tick_interval_ms: 0,
    };
    let mut enabled = false;
    for line in text.lines() {
        let Some((k, v)) = line.split_once(": ") else {
            continue;
        };
        match k {
            "discovery" => enabled = v == "enabled",
            "hello_strategy" => st.hello_strategy = v.to_string(),
            "hello_interval_base_ms" => st.hello_interval_base_ms = v.parse().ok()?,
            "hello_interval_max_ms" => st.hello_interval_max_ms = v.parse().ok()?,
            "hello_jitter" => st.hello_jitter = v.parse().ok()?,
            "liveness_timeout_ms" => st.liveness_timeout_ms = v.parse().ok()?,
            "liveness_miss_count" => st.liveness_miss_count = v.parse().ok()?,
            "probe_timeout_ms" => st.probe_timeout_ms = v.parse().ok()?,
            "prefix_announcement" => st.prefix_announcement = v.to_string(),
            "auto_create_faces" => st.auto_create_faces = v == "true" || v == "1",
            "tick_interval_ms" => st.tick_interval_ms = v.parse().ok()?,
            _ => {}
        }
    }
    enabled.then_some(st)
}

/// Failure to read the service-layer state (constructed by the consumer that
/// owns the transport).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceReadError {
    /// The command was rejected by the forwarder. For these extended modules
    /// the common case is an unsigned command — `service/*` and
    /// `discovery/*` always require the operator signing identity.
    Rejected { status: u64, text: String },
    /// Transport / decode failure on the management seam.
    Transport(String),
}

impl std::fmt::Display for ServiceReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejected { status, text } => write!(f, "rejected: status {status} {text}"),
            Self::Transport(e) => write!(f, "transport: {e}"),
        }
    }
}

impl std::error::Error for ServiceReadError {}
