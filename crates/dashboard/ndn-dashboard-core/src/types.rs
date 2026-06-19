//! Typed data models and text-response parsers for the NDN management protocol.

/// Severity level of a captured router log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl LogLevel {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_uppercase().as_str() {
            "TRACE" => Some(Self::Trace),
            "DEBUG" => Some(Self::Debug),
            "INFO" => Some(Self::Info),
            "WARN" => Some(Self::Warn),
            "ERROR" => Some(Self::Error),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Trace => "TRACE",
            Self::Debug => "DEBUG",
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
        }
    }

    pub fn color(self) -> &'static str {
        match self {
            Self::Trace => "#8b949e",
            Self::Debug => "#58a6ff",
            Self::Info => "#3fb950",
            Self::Warn => "#d29922",
            Self::Error => "#f85149",
        }
    }

    pub fn bg(self) -> &'static str {
        match self {
            Self::Trace => "#1c2128",
            Self::Debug => "#0c2d6b",
            Self::Info => "#1a4731",
            Self::Warn => "#3d3000",
            Self::Error => "#4e1717",
        }
    }
}

/// A single parsed log entry from the router process.
#[derive(Debug, Clone, PartialEq)]
pub struct LogEntry {
    pub timestamp: String,
    pub level: LogLevel,
    pub thread_id: Option<String>,
    pub target: String,
    pub message: String,
}

/// Strip common ANSI CSI sequences (`ESC [ ... letter`) from `s`.
fn strip_ansi(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\x1b' && bytes.get(i + 1) == Some(&b'[') {
            i += 2;
            while i < bytes.len() && !bytes[i].is_ascii_alphabetic() {
                i += 1;
            }
            i += 1;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

impl LogEntry {
    /// Parse a compact-format tracing line `"TIMESTAMP  LEVEL target: message ..."`.
    /// Falls back to a raw Info entry if the line cannot be parsed.
    pub fn parse_line(s: &str) -> Self {
        let s = strip_ansi(s);
        let s = s.trim();
        Self::parse_line_inner(s)
    }

    fn parse_line_inner(s: &str) -> Self {
        let raw_fallback = || Self {
            timestamp: String::new(),
            level: LogLevel::Info,
            thread_id: None,
            target: String::new(),
            message: s.to_owned(),
        };

        let (timestamp, rest) = match s.split_once(' ') {
            Some(pair) => pair,
            None => return raw_fallback(),
        };
        let rest = rest.trim_start();

        let (level_str, rest) = match rest.split_once(' ') {
            Some(pair) => pair,
            None => return raw_fallback(),
        };
        let level = match LogLevel::parse(level_str.trim()) {
            Some(l) => l,
            None => return raw_fallback(),
        };
        let rest = rest.trim_start();

        let (thread_id, rest) = if rest.starts_with("ThreadId(") {
            match rest.split_once(' ') {
                Some((tid, r)) => (Some(tid.to_owned()), r.trim_start()),
                None => (None, rest),
            }
        } else {
            (None, rest)
        };

        let (target, message) = match rest.find(": ") {
            Some(i) => (&rest[..i], &rest[i + 2..]),
            None => ("", rest),
        };

        Self {
            timestamp: timestamp.to_owned(),
            level,
            thread_id,
            target: target.to_owned(),
            message: message.to_owned(),
        }
    }
}

/// Forwarder status from the NFD ForwarderStatus (`status/general`) dataset.
/// `n_faces` is not part of this dataset (it comes from `faces/list`); it stays
/// 0 here and is shown from the faces view.
#[derive(Debug, Clone, Default)]
pub struct ForwarderStatus {
    pub n_faces: u64,
    pub n_fib: u64,
    pub n_pit: u64,
    pub n_cs: u64,
    pub nfd_version: String,
}

impl ForwarderStatus {
    pub fn from_general(gs: &ndn_mgmt_wire::GeneralStatus) -> Self {
        Self {
            n_faces: 0,
            n_fib: gs.n_fib_entries,
            n_pit: gs.n_pit_entries,
            n_cs: gs.n_cs_entries,
            nfd_version: gs.nfd_version.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct FaceInfo {
    pub face_id: u64,
    pub remote_uri: Option<String>,
    pub local_uri: Option<String>,
    pub persistency: String,
    pub kind: Option<String>,
    pub face_scope: u64,
    pub link_type: u64,
    pub mtu: Option<u64>,
    pub n_in_interests: u64,
    pub n_out_interests: u64,
    pub n_in_data: u64,
    pub n_out_data: u64,
    pub n_in_bytes: u64,
    pub n_out_bytes: u64,
    pub n_in_nacks: u64,
    pub n_out_nacks: u64,
    /// NFD FaceFlags bitmap (`Flags`=0x6c). Bit 0 = LocalFieldsEnabled,
    /// 1 = LpReliabilityEnabled, 2 = CongestionMarkingEnabled. Read-only here;
    /// runtime-mutable via `faces/update`.
    pub flags: u64,
}

impl FaceInfo {
    /// Parse from `faces/list` response text.
    #[allow(dead_code)]
    pub fn parse_list(text: &str) -> Vec<Self> {
        let mut faces = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if !line.starts_with("faceid=") {
                continue;
            }
            let mut f = FaceInfo {
                face_id: 0,
                remote_uri: None,
                local_uri: None,
                persistency: "Unknown".into(),
                kind: None,
                face_scope: 0,
                link_type: 0,
                mtu: None,
                n_in_interests: 0,
                n_out_interests: 0,
                n_in_data: 0,
                n_out_data: 0,
                n_in_bytes: 0,
                n_out_bytes: 0,
                n_in_nacks: 0,
                n_out_nacks: 0,
                flags: 0,
            };
            for token in line.split_whitespace() {
                if let Some((k, v)) = token.split_once('=') {
                    match k {
                        "faceid" => f.face_id = v.parse().unwrap_or(0),
                        "remote" => f.remote_uri = Some(v.into()),
                        "local" => f.local_uri = Some(v.into()),
                        "persistency" => f.persistency = v.into(),
                        "kind" => f.kind = Some(v.into()),
                        _ => {}
                    }
                }
            }
            faces.push(f);
        }
        faces
    }

    pub fn kind_label(&self) -> &str {
        if let Some(k) = &self.kind {
            return k.as_str();
        }
        let uri = self
            .remote_uri
            .as_deref()
            .or(self.local_uri.as_deref())
            .unwrap_or("");
        match uri {
            u if u.starts_with("udp4://") || u.starts_with("udp://") => "UDP",
            u if u.starts_with("tcp4://") || u.starts_with("tcp://") => "TCP",
            u if u.starts_with("ws://") || u.starts_with("wss://") => "WS",
            u if u.starts_with("ether://") => "Ether",
            u if u.starts_with("shm://") => "SHM",
            u if u.starts_with("unix://") => "Unix",
            u if u.starts_with("internal://") => {
                let kind = &u["internal://".len()..];
                match kind {
                    "app" => "App",
                    "shm" => "SHM",
                    "management" => "Mgmt",
                    "internal" => "Internal",
                    "web-socket" => "WS",
                    "unix" => "Unix",
                    _ => "Local",
                }
            }
            _ => "?",
        }
    }

    pub fn kind_badge_class(&self) -> &str {
        match self.kind_label() {
            "UDP" => "badge badge-green",
            "TCP" => "badge badge-blue",
            "WS" => "badge badge-yellow",
            "Ether" => "badge badge-yellow",
            "SHM" => "badge badge-gray",
            "Unix" => "badge badge-gray",
            "App" => "badge badge-purple",
            "Mgmt" => "badge badge-gray",
            "Internal" => "badge badge-gray",
            "Local" => "badge badge-gray",
            _ => "badge badge-gray",
        }
    }
}

#[derive(Debug, Clone)]
pub struct NextHop {
    pub face_id: u64,
    pub cost: u32,
}

#[derive(Debug, Clone)]
pub struct FibEntry {
    pub prefix: String,
    pub nexthops: Vec<NextHop>,
}

impl FibEntry {
    /// Parse from `fib/list` response text.
    #[allow(dead_code)]
    pub fn parse_list(text: &str) -> Vec<Self> {
        let mut entries = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if !line.starts_with('/') {
                continue;
            }
            let (prefix, nexthops_text) = match line.find(" nexthops=") {
                Some(i) => (&line[..i], &line[i + " nexthops=".len()..]),
                None => (line, "[]"),
            };
            entries.push(FibEntry {
                prefix: prefix.trim().to_string(),
                nexthops: parse_nexthops(nexthops_text),
            });
        }
        entries
    }
}

#[allow(dead_code)]
fn parse_nexthops(text: &str) -> Vec<NextHop> {
    let inner = text.trim_matches(|c| c == '[' || c == ']');
    inner
        .split(',')
        .filter_map(|part| {
            let part = part.trim();
            if part.is_empty() {
                return None;
            }
            let mut nh = NextHop {
                face_id: 0,
                cost: 0,
            };
            for token in part.split_whitespace() {
                if let Some((k, v)) = token.split_once('=') {
                    match k {
                        "faceid" => nh.face_id = v.parse().unwrap_or(0),
                        "cost" => nh.cost = v.parse().unwrap_or(0),
                        _ => {}
                    }
                }
            }
            Some(nh)
        })
        .collect()
}

#[derive(Debug, Clone)]
pub struct CsInfo {
    pub capacity_bytes: u64,
    pub n_entries: u64,
    pub used_bytes: u64,
    pub hits: u64,
    pub misses: u64,
    pub variant: String,
}

impl CsInfo {
    /// Parse `"capacity=67108864B entries=42 used=1234B hits=100 misses=50 variant=lru"`.
    pub fn parse(text: &str) -> Option<Self> {
        let mut info = CsInfo {
            capacity_bytes: 0,
            n_entries: 0,
            used_bytes: 0,
            hits: 0,
            misses: 0,
            variant: String::new(),
        };
        let mut found = false;
        for token in text.split_whitespace() {
            if let Some((k, v)) = token.split_once('=') {
                found = true;
                let v = v.trim_end_matches('B');
                match k {
                    "capacity" => info.capacity_bytes = v.parse().unwrap_or(0),
                    "entries" => info.n_entries = v.parse().unwrap_or(0),
                    "used" => info.used_bytes = v.parse().unwrap_or(0),
                    "hits" => info.hits = v.parse().unwrap_or(0),
                    "misses" => info.misses = v.parse().unwrap_or(0),
                    "variant" => info.variant = v.to_string(),
                    _ => {}
                }
            }
        }
        found.then_some(info)
    }

    pub fn hit_rate_pct(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            self.hits as f64 / total as f64 * 100.0
        }
    }

    pub fn capacity_mb(&self) -> f64 {
        self.capacity_bytes as f64 / 1_048_576.0
    }

    pub fn used_mb(&self) -> f64 {
        self.used_bytes as f64 / 1_048_576.0
    }
}

#[derive(Debug, Clone, Default)]
pub struct FaceCounter {
    pub face_id: u64,
    pub in_interests: u64,
    pub in_data: u64,
    pub out_interests: u64,
    pub out_data: u64,
    pub in_bytes: u64,
    pub out_bytes: u64,
}

impl FaceCounter {
    /// Parse from `faces/counters` response text. Retained for older routers; the
    /// main path derives counters from `face_list()`.
    #[allow(dead_code)]
    pub fn parse_list(text: &str) -> Vec<Self> {
        let mut out = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if !line.starts_with("faceid=") {
                continue;
            }
            let mut c = FaceCounter::default();
            for token in line.split_whitespace() {
                if let Some((k, v)) = token.split_once('=') {
                    let n: u64 = v.parse().unwrap_or(0);
                    match k {
                        "faceid" => c.face_id = n,
                        "in_interests" => c.in_interests = n,
                        "in_data" => c.in_data = n,
                        "out_interests" => c.out_interests = n,
                        "out_data" => c.out_data = n,
                        "in_bytes" => c.in_bytes = n,
                        "out_bytes" => c.out_bytes = n,
                        _ => {}
                    }
                }
            }
            out.push(c);
        }
        out
    }
}

#[derive(Debug, Clone)]
pub struct FaceRtt {
    pub face_id: u64,
    pub srtt_ms: f64,
}

#[derive(Debug, Clone)]
pub struct MeasurementEntry {
    pub prefix: String,
    pub satisfaction_rate: f32,
    pub face_rtts: Vec<FaceRtt>,
}

impl MeasurementEntry {
    /// Parse from `measurements/list` response text.
    pub fn parse_list(text: &str) -> Vec<Self> {
        let mut out = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if !line.starts_with("prefix=") {
                continue;
            }
            let mut prefix = String::new();
            let mut sat_rate = 0.0f32;
            let mut face_rtts = Vec::new();

            let (main_part, rtt_part) = match line.find(" rtt=[") {
                Some(i) => (&line[..i], &line[i + " rtt=[".len()..line.len() - 1]),
                None => (line, ""),
            };

            for token in main_part.split_whitespace() {
                if let Some((k, v)) = token.split_once('=') {
                    match k {
                        "prefix" => prefix = v.to_string(),
                        "sat_rate" => sat_rate = v.parse().unwrap_or(0.0),
                        _ => {}
                    }
                }
            }

            for token in rtt_part.split_whitespace() {
                if let Some((k, v)) = token.split_once('=') {
                    let face_id: u64 = k.strip_prefix("face").unwrap_or("0").parse().unwrap_or(0);
                    let srtt_ms: f64 = v.trim_end_matches("ms").parse().unwrap_or(0.0);
                    face_rtts.push(FaceRtt { face_id, srtt_ms });
                }
            }

            if !prefix.is_empty() {
                out.push(MeasurementEntry {
                    prefix,
                    satisfaction_rate: sat_rate,
                    face_rtts,
                });
            }
        }
        out
    }

    pub fn sat_rate_class(&self) -> &'static str {
        if self.satisfaction_rate >= 0.9 {
            "badge badge-green"
        } else if self.satisfaction_rate >= 0.5 {
            "badge badge-yellow"
        } else {
            "badge badge-red"
        }
    }
}

/// One sample of aggregated traffic (summed across all faces).
#[derive(Debug, Clone, Default)]
pub struct ThroughputSample {
    pub in_bytes: u64,
    pub out_bytes: u64,
    pub in_interests: u64,
    pub out_interests: u64,
}

impl ThroughputSample {
    /// `elapsed_secs` is the poll interval (typically 3.0).
    pub fn rate_from_delta(
        prev: &ThroughputSample,
        curr: &ThroughputSample,
        elapsed_secs: f64,
    ) -> ThroughputSample {
        let delta = |a: u64, b: u64| b.saturating_sub(a);
        ThroughputSample {
            in_bytes: (delta(prev.in_bytes, curr.in_bytes) as f64 / elapsed_secs) as u64,
            out_bytes: (delta(prev.out_bytes, curr.out_bytes) as f64 / elapsed_secs) as u64,
            in_interests: (delta(prev.in_interests, curr.in_interests) as f64 / elapsed_secs)
                as u64,
            out_interests: (delta(prev.out_interests, curr.out_interests) as f64 / elapsed_secs)
                as u64,
        }
    }

    pub fn from_counters(counters: &[FaceCounter]) -> ThroughputSample {
        ThroughputSample {
            in_bytes: counters.iter().map(|c| c.in_bytes).sum(),
            out_bytes: counters.iter().map(|c| c.out_bytes).sum(),
            in_interests: counters.iter().map(|c| c.in_interests).sum(),
            out_interests: counters.iter().map(|c| c.out_interests).sum(),
        }
    }

    pub fn from_face_counter(c: &FaceCounter) -> ThroughputSample {
        ThroughputSample {
            in_bytes: c.in_bytes,
            out_bytes: c.out_bytes,
            in_interests: c.in_interests,
            out_interests: c.out_interests,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SessionEntry {
    pub kind: String,
    pub params: String,
}

#[derive(Debug, Clone)]
pub struct NeighborInfo {
    pub node_name: String,
    /// "Established", "Stale", "Probing", or "Absent".
    pub state: String,
    pub last_seen_s: Option<f64>,
    pub rtt_us: Option<u32>,
    pub face_ids: Vec<u64>,
}

impl NeighborInfo {
    /// Parse from `neighbors/list` response text.
    pub fn parse_list(text: &str) -> Vec<Self> {
        let mut out = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if !line.starts_with('/') {
                continue;
            }
            let mut tokens = line.split_whitespace();
            let node_name = match tokens.next() {
                Some(n) => n.to_string(),
                None => continue,
            };

            let rest: Vec<&str> = tokens.collect();
            let rest_str = rest.join(" ");

            let (main_part, faces_part) = match rest_str.find("faces=[") {
                Some(i) => (&rest_str[..i], &rest_str[i + "faces=[".len()..]),
                None => (rest_str.as_str(), ""),
            };
            let faces_part = faces_part.trim_end_matches(']');

            let face_ids: Vec<u64> = faces_part
                .split(',')
                .filter_map(|s| s.trim().parse().ok())
                .collect();

            let mut state = "Unknown".to_string();
            let mut last_seen_s: Option<f64> = None;
            let mut rtt_us: Option<u32> = None;

            for token in main_part.split_whitespace() {
                if let Some((k, v)) = token.split_once('=') {
                    match k {
                        "state" => state = v.to_string(),
                        "last_seen" => {
                            last_seen_s = v.trim_end_matches('s').parse().ok();
                        }
                        "rtt" if v != "None" => {
                            rtt_us = v.trim_end_matches("us").parse().ok();
                        }
                        _ => {}
                    }
                }
            }

            out.push(NeighborInfo {
                node_name,
                state,
                last_seen_s,
                rtt_us,
                face_ids,
            });
        }
        out
    }

    pub fn state_badge_class(&self) -> &'static str {
        match self.state.as_str() {
            "Established" => "badge badge-green",
            "Stale" => "badge badge-yellow",
            "Probing" => "badge badge-blue",
            _ => "badge badge-gray",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SecurityKeyInfo {
    pub name: String,
    pub has_cert: bool,
    pub valid_until: String,
    /// Base64url-no-pad-encoded public-key bytes from the cert's
    /// `public_key` field. Empty when the key has no cert or the
    /// mgmt wire predates the `public_key=` extension. The §4.7 DID
    /// lens emits this as a multibase-prefixed `publicKeyMultibase`
    /// value when present.
    pub public_key_b64: String,
}

impl SecurityKeyInfo {
    /// Everything before the `/KEY/<id>` suffix (`/lab/alice/KEY/k1` → `/lab/alice`).
    /// Returns the full name when no `KEY` component is found.
    pub fn identity_name(&self) -> &str {
        match self.name.rfind("/KEY/") {
            Some(i) => &self.name[..i],
            None => &self.name,
        }
    }

    /// Component immediately after `/KEY/`, or `""` when absent.
    pub fn key_id(&self) -> &str {
        match self.name.rfind("/KEY/") {
            Some(i) => {
                let tail = &self.name[i + 5..];
                tail.split('/').next().unwrap_or("")
            }
            None => "",
        }
    }

    /// Always `None` — `security/identity-list` doesn't surface the issued-at
    /// timestamp yet.
    pub fn valid_from_unix_s(&self) -> Option<u64> {
        None
    }

    /// `None` for permanent or missing certs.
    pub fn valid_until_unix_s(&self) -> Option<u64> {
        if self.valid_until == "never" || self.valid_until == "-" {
            return None;
        }
        let ns_str = self.valid_until.strip_suffix("ns")?;
        let ns = ns_str.parse::<u64>().ok()?;
        Some(ns / 1_000_000_000)
    }

    /// Negative when expired; `None` for permanent or missing certs.
    pub fn days_to_expiry(&self) -> Option<i64> {
        if self.valid_until == "never" || self.valid_until == "-" {
            return None;
        }
        if let Some(ns_str) = self.valid_until.strip_suffix("ns")
            && let Ok(ns) = ns_str.parse::<u64>()
        {
            let expiry_secs = (ns / 1_000_000_000) as i64;
            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            return Some((expiry_secs - now_secs) / 86400);
        }
        None
    }

    pub fn expiry_badge(&self) -> (&'static str, String) {
        match self.days_to_expiry() {
            None if self.valid_until == "never" => ("badge badge-green", "permanent".to_string()),
            None => ("badge badge-gray", "—".to_string()),
            Some(d) if d < 0 => ("badge badge-red", "expired".to_string()),
            Some(0) => ("badge badge-red", "< 1d".to_string()),
            Some(d) if d < 7 => ("badge badge-red", format!("{d}d left")),
            Some(d) if d < 30 => ("badge badge-yellow", format!("{d}d left")),
            Some(d) => ("badge badge-green", format!("{d}d left")),
        }
    }

    /// Parse from `security/identity-list` response text.
    pub fn parse_list(text: &str) -> Vec<Self> {
        let mut out = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if !line.starts_with("name=") {
                continue;
            }
            let mut name = String::new();
            let mut has_cert = false;
            let mut valid_until = "-".to_string();
            let mut public_key_b64 = String::new();
            for token in line.split_whitespace() {
                if let Some((k, v)) = token.split_once('=') {
                    match k {
                        "name" => name = v.to_string(),
                        "has_cert" => has_cert = v == "true",
                        "valid_until" => valid_until = v.to_string(),
                        "public_key" if v != "-" => public_key_b64 = v.to_string(),
                        _ => {}
                    }
                }
            }
            if !name.is_empty() {
                out.push(SecurityKeyInfo {
                    name,
                    has_cert,
                    valid_until,
                    public_key_b64,
                });
            }
        }
        out
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AnchorInfo {
    pub name: String,
    /// Which forwarder trust store this anchor lives in: `engine` (Data
    /// validation), `mgmt` (command authorization), `localhop`. `None` for
    /// older forwarders whose `anchor-list` didn't carry a source.
    pub source: Option<String>,
}

impl AnchorInfo {
    pub fn parse_list(text: &str) -> Vec<Self> {
        let mut out = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            // Tokens are `key=value` separated by whitespace; an NDN name has
            // no spaces, so `name=<name>` is a single token.
            let mut name: Option<String> = None;
            let mut source: Option<String> = None;
            for tok in line.split_whitespace() {
                if let Some(v) = tok.strip_prefix("name=") {
                    name = Some(v.to_string());
                } else if let Some(v) = tok.strip_prefix("source=") {
                    source = Some(v.to_string());
                }
            }
            if let Some(name) = name {
                out.push(AnchorInfo { name, source });
            }
        }
        out
    }
}

#[derive(Debug, Clone)]
pub struct StrategyEntry {
    pub prefix: String,
    pub strategy: String,
}

impl StrategyEntry {
    /// Parse from `strategy-choice/list` response text.
    #[allow(dead_code)]
    pub fn parse_list(text: &str) -> Vec<Self> {
        let mut entries = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if !line.starts_with("prefix=") {
                continue;
            }
            let mut prefix = String::new();
            let mut strategy = String::new();
            for token in line.split_whitespace() {
                if let Some((k, v)) = token.split_once('=') {
                    match k {
                        "prefix" => prefix = v.to_string(),
                        "strategy" => strategy = v.to_string(),
                        _ => {}
                    }
                }
            }
            if !prefix.is_empty() {
                entries.push(StrategyEntry { prefix, strategy });
            }
        }
        entries
    }

    /// Strips the NDN name prefix and trailing version component for display
    /// (`/localhost/nfd/strategy/best-route/v=5` → `best-route`). Handles both
    /// the canonical `v=<n>` version component and the legacy `v<n>` form.
    pub fn short_name(&self) -> &str {
        self.strategy
            .rsplit('/')
            .find(|s| !is_version_component(s))
            .unwrap_or(&self.strategy)
    }
}

/// A trailing NDN version component as it renders in a name URI: `v=5`
/// (canonical, TLV 0x36) or the legacy bare `v5`.
fn is_version_component(s: &str) -> bool {
    let digits = s.strip_prefix("v=").or_else(|| s.strip_prefix('v'));
    matches!(digits, Some(d) if !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
}

/// Parsed from `discovery/status` response.
#[derive(Debug, Clone, Default)]
pub struct DiscoveryStatus {
    pub enabled: bool,
    pub strategy: String,
    pub hello_interval_base_ms: u64,
    pub hello_interval_max_ms: u64,
    pub tick_interval_ms: u64,
    pub liveness_timeout_s: u64,
    pub liveness_miss_count: u32,
    pub probe_timeout_ms: u64,
    pub prefix_announcement: bool,
}

impl DiscoveryStatus {
    /// Parse from `discovery/status` text (one `key: value` per line).
    pub fn parse(text: &str) -> Option<Self> {
        let mut s = Self::default();
        let mut found = false;
        for line in text.lines() {
            let line = line.trim();
            if let Some((k, v)) = line.split_once(':') {
                found = true;
                let v = v.trim();
                match k.trim() {
                    "discovery" => s.enabled = v == "enabled",
                    "hello_strategy" => s.strategy = v.to_string(),
                    "hello_interval_base_ms" => s.hello_interval_base_ms = v.parse().unwrap_or(0),
                    "hello_interval_max_ms" => s.hello_interval_max_ms = v.parse().unwrap_or(0),
                    "tick_interval_ms" => s.tick_interval_ms = v.parse().unwrap_or(0),
                    "liveness_timeout_s" => s.liveness_timeout_s = v.parse().unwrap_or(0),
                    "liveness_miss_count" => s.liveness_miss_count = v.parse().unwrap_or(0),
                    "probe_timeout_ms" => s.probe_timeout_ms = v.parse().unwrap_or(0),
                    "prefix_announcement" => s.prefix_announcement = v == "true",
                    _ => {}
                }
            }
        }
        found.then_some(s)
    }
}

/// Parsed from `routing/dvr-status` response.
#[derive(Debug, Clone, Default)]
pub struct DvrStatus {
    pub update_interval_ms: u64,
    pub route_ttl_ms: u64,
    pub route_count: u32,
}

impl DvrStatus {
    /// Parse from `routing/dvr-status` text (one `key: value` per line).
    pub fn parse(text: &str) -> Option<Self> {
        let mut s = Self::default();
        let mut found = false;
        for line in text.lines() {
            let line = line.trim();
            if let Some((k, v)) = line.split_once(':') {
                found = true;
                let v = v.trim();
                match k.trim() {
                    "update_interval_ms" => s.update_interval_ms = v.parse().unwrap_or(0),
                    "route_ttl_ms" => s.route_ttl_ms = v.parse().unwrap_or(0),
                    "route_count" => s.route_count = v.parse().unwrap_or(0),
                    _ => {}
                }
            }
        }
        found.then_some(s)
    }
}

/// Parsed from `security/ca-info` response text (newline-separated `key=value`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CaInfo {
    pub ca_prefix: String,
    pub ca_info: String,
    pub max_validity_days: u32,
    pub challenges: Vec<String>,
}

impl CaInfo {
    pub fn parse(text: &str) -> Option<Self> {
        let mut s = Self::default();
        let mut found = false;
        for line in text.lines() {
            let line = line.trim();
            if let Some((k, v)) = line.split_once('=') {
                match k {
                    "ca_prefix" => {
                        s.ca_prefix = v.to_string();
                        found = true;
                    }
                    "ca_info" => s.ca_info = v.to_string(),
                    "max_validity_days" => s.max_validity_days = v.parse().unwrap_or(365),
                    "challenges" => {
                        s.challenges = v
                            .split(',')
                            .map(|c| c.trim().to_string())
                            .filter(|c| !c.is_empty())
                            .collect()
                    }
                    _ => {}
                }
            }
        }
        found.then_some(s)
    }
}

/// A single trust schema rule returned by `security/schema-list`.
#[derive(Debug, Clone, PartialEq)]
pub struct SchemaRuleInfo {
    pub index: usize,
    pub data_pattern: String,
    pub key_pattern: String,
}

impl SchemaRuleInfo {
    /// Plain-English rendering of the rule for the "permissions as sentences"
    /// view: data names matching the left pattern are trusted only when signed
    /// by a key matching the right pattern. Empty patterns degrade to "any".
    pub fn sentence(&self) -> String {
        let data = if self.data_pattern.trim().is_empty() {
            "any name"
        } else {
            self.data_pattern.trim()
        };
        let key = if self.key_pattern.trim().is_empty() {
            "any key"
        } else {
            self.key_pattern.trim()
        };
        format!("Data matching {data} is trusted only when signed by a key matching {key}.")
    }

    /// Parse from `security/schema-list` response text. Per-line format:
    /// `[<index>] <data_pattern> => <key_pattern>`.
    pub fn parse_list(text: &str) -> Vec<Self> {
        let mut out = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            let bracket_end = match line.strip_prefix('[').and_then(|s| s.find(']')) {
                Some(i) => i + 1,
                None => continue,
            };
            let rest = line[bracket_end + 1..].trim();
            if let Some((data, key)) = rest.split_once(" => ") {
                let index = line[1..bracket_end].parse().unwrap_or(out.len());
                out.push(SchemaRuleInfo {
                    index,
                    data_pattern: data.trim().to_string(),
                    key_pattern: key.trim().to_string(),
                });
            }
        }
        out
    }
}

/// Dashboard-side mirror of the forwarder's `MgmtAccessPolicy`. Field names
/// must stay byte-identical with the server's serde derive so JSON round-trips
/// cleanly through `policy-get` / `policy-set`.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct MgmtAccessPolicySnapshot {
    pub ephemeral_allowed: bool,
    pub localhop_disabled: bool,
    pub replay_window_secs: u64,
    pub require_signed_commands: bool,
    pub validator_anchor: Option<String>,
}

impl MgmtAccessPolicySnapshot {
    pub fn from_json(body: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(body)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

/// Parsed from `security/validation-stats`. Newer forwarders emit `*_total` +
/// `probe_unix_ns` so the dashboard derives per-second rates client-side; older
/// forwarders only emit `*_per_sec` (always zero).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ValidationStats {
    pub validator_present: bool,
    pub verified_per_sec: u64,
    pub rejected_per_sec: u64,
    /// `None` when the forwarder predates the totals wire shape.
    pub verified_total: Option<u64>,
    pub rejected_total: Option<u64>,
    /// Unix-epoch ns sampling timestamp.
    pub probe_unix_ns: Option<u64>,
}

impl ValidationStats {
    pub fn parse(text: &str) -> Self {
        let mut out = Self::default();
        for line in text.lines() {
            if let Some((k, v)) = line.trim().split_once('=') {
                match k {
                    "validator_present" => out.validator_present = v == "true",
                    "verified_per_sec" => out.verified_per_sec = v.parse().unwrap_or(0),
                    "rejected_per_sec" => out.rejected_per_sec = v.parse().unwrap_or(0),
                    "verified_total" => out.verified_total = v.parse().ok(),
                    "rejected_total" => out.rejected_total = v.parse().ok(),
                    "probe_unix_ns" => out.probe_unix_ns = v.parse().ok(),
                    _ => {}
                }
            }
        }
        out
    }

    /// Per-second `(verified, rejected)` rate between two samples. Returns
    /// `None` when either sample lacks totals/probe fields or the time delta
    /// is zero or backward.
    pub fn rate_against(&self, prev: &Self) -> Option<(u64, u64)> {
        let (cur_v, cur_r, cur_t) = (
            self.verified_total?,
            self.rejected_total?,
            self.probe_unix_ns?,
        );
        let (prev_v, prev_r, prev_t) = (
            prev.verified_total?,
            prev.rejected_total?,
            prev.probe_unix_ns?,
        );
        if cur_t <= prev_t {
            return None;
        }
        let delta_secs = (cur_t - prev_t) as f64 / 1_000_000_000.0;
        if delta_secs <= 0.0 {
            return None;
        }
        let dv = cur_v.saturating_sub(prev_v) as f64;
        let dr = cur_r.saturating_sub(prev_r) as f64;
        Some(((dv / delta_secs) as u64, (dr / delta_secs) as u64))
    }
}

/// Dashboard-side mirror of the JSON `security/validate` returns.
#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
pub struct TrustValidationResult {
    pub verdict: TrustVerdict,
    #[serde(default)]
    pub chain: Vec<TrustChainStep>,
    #[serde(default)]
    pub schema_rules_applied: Vec<SchemaRuleApplied>,
    #[serde(default)]
    pub failure_diagnosis: Option<FailureDiagnosis>,
    #[serde(default)]
    pub challenge_attestations: Vec<ChallengeAttestation>,
}

impl TrustValidationResult {
    pub fn from_json(body: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(body)
    }
}

/// `"Valid"` or `{ "Invalid": { failed_at, reason } }`.
#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
pub enum TrustVerdict {
    Valid,
    Invalid { failed_at: String, reason: String },
}

impl TrustVerdict {
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }
}

#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
pub struct TrustChainStep {
    pub name: String,
    pub signed_by: String,
}

#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
pub struct SchemaRuleApplied {
    pub data_pattern: String,
    pub key_pattern: String,
    pub matches: bool,
}

#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
pub struct FailureDiagnosis {
    pub kind: String,
    pub hint: String,
}

#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
pub struct ChallengeAttestation {
    /// The challenge type the CA recorded in the cert's
    /// `AdditionalDescription` (e.g. `"device-approval"`, `"token"`,
    /// `"all-of"`).
    pub kind: String,
    /// Rendered summary (`performed_at` + evidence) for display.
    #[serde(default)]
    pub detail: String,
}

impl From<ndn_config::FaceStatus> for FaceInfo {
    fn from(fs: ndn_config::FaceStatus) -> Self {
        let persistency = fs.persistency_str().to_owned();
        FaceInfo {
            face_id: fs.face_id,
            remote_uri: if fs.uri.is_empty() {
                None
            } else {
                Some(fs.uri)
            },
            local_uri: if fs.local_uri.is_empty() {
                None
            } else {
                Some(fs.local_uri)
            },
            persistency,
            kind: None,
            face_scope: fs.face_scope,
            link_type: fs.link_type,
            mtu: fs.mtu,
            n_in_interests: fs.n_in_interests,
            n_out_interests: fs.n_out_interests,
            n_in_data: fs.n_in_data,
            n_out_data: fs.n_out_data,
            n_in_bytes: fs.n_in_bytes,
            n_out_bytes: fs.n_out_bytes,
            n_in_nacks: fs.n_in_nacks,
            n_out_nacks: fs.n_out_nacks,
            flags: fs.flags,
        }
    }
}

impl From<ndn_config::FibEntry> for FibEntry {
    fn from(fe: ndn_config::FibEntry) -> Self {
        FibEntry {
            prefix: fe.name.to_string(),
            nexthops: fe
                .nexthops
                .into_iter()
                .map(|nh| NextHop {
                    face_id: nh.face_id,
                    cost: nh.cost as u32,
                })
                .collect(),
        }
    }
}

impl From<ndn_config::StrategyChoice> for StrategyEntry {
    fn from(sc: ndn_config::StrategyChoice) -> Self {
        StrategyEntry {
            prefix: sc.name.to_string(),
            strategy: sc.strategy.to_string(),
        }
    }
}

/// A single route entry inside a RIB entry (one per nexthop / origin).
#[derive(Debug, Clone)]
pub struct RibRoute {
    pub face_id: u64,
    /// Origin code: 0=app, 65=client, 128=nlsr, 255=static.
    pub origin: u64,
    pub cost: u64,
    /// Bitmask: 0x1=child-inherit, 0x2=capture.
    pub flags: u64,
    /// Expiration in milliseconds, if set.
    pub expiration_period: Option<u64>,
}

impl RibRoute {
    #[allow(dead_code)]
    pub fn origin_label(&self) -> String {
        match self.origin {
            0 => "app".to_string(),
            64 => "autoreg".to_string(),
            65 => "client".to_string(),
            66 => "autoconf".to_string(),
            127 => "dvr".to_string(),
            128 => "nlsr".to_string(),
            129 => "prefix-ann".to_string(),
            255 => "static".to_string(),
            n => n.to_string(),
        }
    }

    #[allow(dead_code)]
    pub fn flags_label(&self) -> String {
        let mut parts = Vec::new();
        if self.flags & 0x01 != 0 {
            parts.push("child-inherit");
        }
        if self.flags & 0x02 != 0 {
            parts.push("capture");
        }
        if parts.is_empty() {
            "—".to_string()
        } else {
            parts.join(",")
        }
    }
}

/// A RIB entry — one name prefix with one or more routes.
#[derive(Debug, Clone)]
pub struct RibEntryInfo {
    pub prefix: String,
    pub routes: Vec<RibRoute>,
}

#[cfg(feature = "desktop")]
impl From<ndn_config::RibEntry> for RibEntryInfo {
    fn from(re: ndn_config::RibEntry) -> Self {
        RibEntryInfo {
            prefix: re.name.to_string(),
            routes: re
                .routes
                .into_iter()
                .map(|r| RibRoute {
                    face_id: r.face_id,
                    origin: r.origin,
                    cost: r.cost,
                    flags: r.flags,
                    expiration_period: r.expiration_period,
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strategy_short_name_strips_canonical_and_legacy_versions() {
        let sn = |s: &str| {
            StrategyEntry {
                prefix: "/x".into(),
                strategy: s.into(),
            }
            .short_name()
            .to_string()
        };
        assert_eq!(sn("/localhost/nfd/strategy/multicast/v=5"), "multicast");
        assert_eq!(sn("/localhost/nfd/strategy/best-route/v=5"), "best-route");
        assert_eq!(sn("/ndn/strategy/best-route/v5"), "best-route"); // legacy
        assert_eq!(
            sn("/localhost/nfd/strategy/self-learning/v=1"),
            "self-learning"
        );
    }

    #[test]
    fn schema_rule_sentence_reads_plainly() {
        let r = SchemaRuleInfo {
            index: 0,
            data_pattern: "/lab/alice/<type>".into(),
            key_pattern: "/lab/alice/KEY/<id>".into(),
        };
        let s = r.sentence();
        assert!(s.contains("/lab/alice/<type>"));
        assert!(s.contains("/lab/alice/KEY/<id>"));
        assert!(s.contains("signed by"));
        // Empty patterns degrade to readable defaults, not blanks.
        let empty = SchemaRuleInfo {
            index: 1,
            data_pattern: String::new(),
            key_pattern: "  ".into(),
        };
        assert!(empty.sentence().contains("any name"));
        assert!(empty.sentence().contains("any key"));
    }

    #[test]
    fn trust_validation_result_valid_minimal() {
        let body = r#"{"verdict":"Valid"}"#;
        let r = TrustValidationResult::from_json(body).expect("valid parse");
        assert!(r.verdict.is_valid());
        assert!(r.chain.is_empty());
        assert!(r.schema_rules_applied.is_empty());
        assert!(r.failure_diagnosis.is_none());
        assert!(r.challenge_attestations.is_empty());
    }

    #[test]
    fn trust_validation_result_invalid_with_diagnosis() {
        let body = r#"{
            "verdict": { "Invalid": { "failed_at": "/lab/x", "reason": "stub" } },
            "chain": [],
            "schema_rules_applied": [],
            "failure_diagnosis": { "kind": "ChainNotResolved", "hint": "install anchor" },
            "challenge_attestations": []
        }"#;
        let r = TrustValidationResult::from_json(body).expect("invalid parse");
        assert!(!r.verdict.is_valid());
        match r.verdict {
            TrustVerdict::Invalid { failed_at, reason } => {
                assert_eq!(failed_at, "/lab/x");
                assert_eq!(reason, "stub");
            }
            _ => panic!("expected Invalid"),
        }
        let diag = r.failure_diagnosis.expect("diagnosis present");
        assert_eq!(diag.kind, "ChainNotResolved");
        assert!(diag.hint.contains("install"));
    }

    #[test]
    fn trust_validation_result_full_chain() {
        let body = r#"{
            "verdict": "Valid",
            "chain": [
                { "name": "/lab/alice/KEY/k1/router-ca/v=1", "signed_by": "/lab/router-ca/KEY/k0" },
                { "name": "/lab/router-ca/KEY/k0", "signed_by": "/lab/router-ca/KEY/k0" }
            ],
            "schema_rules_applied": [
                { "data_pattern": "/lab/*/KEY/*", "key_pattern": "/lab/router-ca/KEY/*", "matches": true }
            ]
        }"#;
        let r = TrustValidationResult::from_json(body).expect("full parse");
        assert_eq!(r.chain.len(), 2);
        assert_eq!(r.chain[0].signed_by, "/lab/router-ca/KEY/k0");
        assert_eq!(r.schema_rules_applied.len(), 1);
        assert!(r.schema_rules_applied[0].matches);
    }

    #[test]
    fn trust_validation_result_unknown_fields_dont_fail() {
        let body = r#"{
            "verdict": "Valid",
            "chain": [],
            "future_field_xyz": [1, 2, 3],
            "another_unknown": { "nested": true }
        }"#;
        let r = TrustValidationResult::from_json(body).expect("ignores extras");
        assert!(r.verdict.is_valid());
    }

    #[test]
    fn mgmt_access_policy_round_trip_through_json() {
        let p = MgmtAccessPolicySnapshot {
            ephemeral_allowed: true,
            localhop_disabled: false,
            replay_window_secs: 120,
            require_signed_commands: true,
            validator_anchor: Some("/lab/router-ca/KEY/k0".into()),
        };
        let json = p.to_json();
        let parsed = MgmtAccessPolicySnapshot::from_json(&json).expect("round-trip");
        assert_eq!(parsed, p);
    }

    #[test]
    fn mgmt_access_policy_unknown_fields_dont_fail() {
        let body = r#"{
            "ephemeral_allowed": false,
            "localhop_disabled": true,
            "replay_window_secs": 120,
            "require_signed_commands": true,
            "validator_anchor": "/lab/router-ca/KEY/k0",
            "new_field_v2": "ignored",
            "another": 42
        }"#;
        let p = MgmtAccessPolicySnapshot::from_json(body).expect("parses");
        assert!(p.require_signed_commands);
        assert!(p.localhop_disabled);
        assert_eq!(p.replay_window_secs, 120);
    }

    #[test]
    fn mgmt_access_policy_anchor_null_becomes_none() {
        let body = r#"{
            "ephemeral_allowed": false,
            "localhop_disabled": true,
            "replay_window_secs": 120,
            "require_signed_commands": true,
            "validator_anchor": null
        }"#;
        let p = MgmtAccessPolicySnapshot::from_json(body).expect("parses");
        assert!(p.validator_anchor.is_none());
    }

    #[test]
    fn validation_stats_parses_all_fields() {
        let text = "validator_present=true\nverified_per_sec=42\nrejected_per_sec=7\n";
        let stats = ValidationStats::parse(text);
        assert!(stats.validator_present);
        assert_eq!(stats.verified_per_sec, 42);
        assert_eq!(stats.rejected_per_sec, 7);
    }

    #[test]
    fn validation_stats_handles_missing_lines() {
        let text = "validator_present=false\n";
        let stats = ValidationStats::parse(text);
        assert!(!stats.validator_present);
        assert_eq!(stats.verified_per_sec, 0);
        assert_eq!(stats.rejected_per_sec, 0);
    }

    #[test]
    fn validation_stats_parses_totals_and_probe_ts() {
        let text = "validator_present=true\n\
                    verified_per_sec=0\n\
                    rejected_per_sec=0\n\
                    verified_total=42\n\
                    rejected_total=7\n\
                    probe_unix_ns=1700000000000000000\n";
        let stats = ValidationStats::parse(text);
        assert!(stats.validator_present);
        assert_eq!(stats.verified_total, Some(42));
        assert_eq!(stats.rejected_total, Some(7));
        assert_eq!(stats.probe_unix_ns, Some(1_700_000_000_000_000_000));
    }

    #[test]
    fn validation_stats_rate_against_computes_per_second() {
        let prev = ValidationStats {
            validator_present: true,
            verified_per_sec: 0,
            rejected_per_sec: 0,
            verified_total: Some(100),
            rejected_total: Some(10),
            probe_unix_ns: Some(1_700_000_000_000_000_000),
        };
        let cur = ValidationStats {
            validator_present: true,
            verified_per_sec: 0,
            rejected_per_sec: 0,
            verified_total: Some(160),
            rejected_total: Some(13),
            probe_unix_ns: Some(1_700_000_003_000_000_000),
        };
        assert_eq!(cur.rate_against(&prev), Some((20, 1)));
    }

    #[test]
    fn validation_stats_rate_against_returns_none_when_no_totals() {
        let prev = ValidationStats {
            validator_present: true,
            verified_per_sec: 0,
            rejected_per_sec: 0,
            verified_total: None,
            rejected_total: None,
            probe_unix_ns: None,
        };
        let cur = ValidationStats {
            validator_present: true,
            verified_per_sec: 0,
            rejected_per_sec: 0,
            verified_total: Some(1),
            rejected_total: Some(0),
            probe_unix_ns: Some(1_700_000_000_000_000_000),
        };
        assert_eq!(cur.rate_against(&prev), None);
    }

    #[test]
    fn validation_stats_rate_against_rejects_zero_or_backward_delta() {
        let s = ValidationStats {
            validator_present: true,
            verified_per_sec: 0,
            rejected_per_sec: 0,
            verified_total: Some(1),
            rejected_total: Some(0),
            probe_unix_ns: Some(1_700_000_000_000_000_000),
        };
        assert_eq!(s.rate_against(&s), None);
        let future = ValidationStats {
            probe_unix_ns: Some(1_699_999_999_000_000_000),
            ..s
        };
        assert_eq!(future.rate_against(&s), None);
    }

    #[test]
    fn validation_stats_tolerates_unknown_keys() {
        let text = "validator_present=true\n\
                    verified_per_sec=10\n\
                    future_key=xyz\n\
                    rejected_per_sec=2\n";
        let stats = ValidationStats::parse(text);
        assert_eq!(stats.verified_per_sec, 10);
        assert_eq!(stats.rejected_per_sec, 2);
    }

    #[test]
    fn security_key_info_identity_and_key_id() {
        let k = SecurityKeyInfo {
            name: "/lab/alice/KEY/k1".into(),
            has_cert: true,
            valid_until: "never".into(),
            public_key_b64: String::new(),
        };
        assert_eq!(k.identity_name(), "/lab/alice");
        assert_eq!(k.key_id(), "k1");
    }

    #[test]
    fn security_key_info_handles_missing_key_component() {
        let k = SecurityKeyInfo {
            name: "/lab/alice".into(),
            has_cert: false,
            valid_until: "-".into(),
            public_key_b64: String::new(),
        };
        assert_eq!(k.identity_name(), "/lab/alice");
        assert_eq!(k.key_id(), "");
    }
}
