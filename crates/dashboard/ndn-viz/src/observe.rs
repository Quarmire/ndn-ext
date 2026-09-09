//! NDN-native observability: OTLP `Span` decode, the `/recent` fetch contract,
//! and the trace/span view-model algebra.
//!
//! Ported from the archived `ndn-dashboard-next` (SHA `a81e1c8`,
//! `src/observe/mod.rs`) — the salvage inventory's §1.1-1.3. The mock/posture
//! summary, the `ForwarderProfile` coupling, and the desktop-socket fetch loop
//! were dropped: consumers own the transport (fetch the Data), this module
//! decodes and shapes it. Everything here is pure — no I/O, no clock, no deps.

use std::collections::{BTreeMap, HashMap, HashSet};

/// The default prefix the ndn-rs observability publisher serves span Data under.
pub const DEFAULT_OBSERVABILITY_PREFIX: &str = "/localhost/nfd/observability";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpanView {
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub name: String,
    pub target: String,
    pub interest_name: Option<String>,
    pub face_id: Option<i64>,
    pub strategy: Option<String>,
    pub status: SpanStatus,
    pub duration_us: u64,
    /// OTLP `start_time_unix_nano` — absolute, for timeline bar placement.
    pub start_unix_nano: u64,
    /// OTLP `end_time_unix_nano` — absolute, for timeline bar placement.
    pub end_unix_nano: u64,
    /// Every decoded attribute (key, value), in wire order — for tooltips and
    /// inspection. The well-known ones are also lifted into the typed fields above.
    pub attrs: Vec<(String, String)>,
}

impl SpanView {
    /// Span duration in nanoseconds (full OTLP resolution; `duration_us` is this / 1000).
    pub fn duration_nanos(&self) -> u64 {
        self.end_unix_nano.saturating_sub(self.start_unix_nano)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpanStatus {
    Unset,
    Ok,
    Error,
}

impl SpanStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Unset => "unset",
            Self::Ok => "ok",
            Self::Error => "error",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraceView {
    pub trace_id: String,
    pub span_count: usize,
    pub root_name: String,
    pub duration_us: u64,
    pub has_pit_fanout: bool,
    pub spans: Vec<SpanView>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpanTreeRow {
    pub span: SpanView,
    pub depth: usize,
    pub child_count: usize,
    pub orphaned_parent: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PitFanOutRow {
    pub span_name: String,
    pub face_id: Option<i64>,
    pub interest_name: Option<String>,
    pub status: SpanStatus,
    pub duration_us: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BridgeExportState {
    Unknown,
    NotAttached,
    Ready,
    Error,
    Unavailable,
}

impl BridgeExportState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Unknown => "bridge unknown",
            Self::NotAttached => "bridge not attached",
            Self::Ready => "bridge observed",
            Self::Error => "bridge error",
            Self::Unavailable => "bridge unavailable",
        }
    }

    pub fn tone(self) -> &'static str {
        match self {
            Self::Ready => "good",
            Self::Unknown | Self::NotAttached => "amber",
            Self::Unavailable => "muted",
            Self::Error => "bad",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BridgeExportStatus {
    pub state: BridgeExportState,
    pub detail: String,
}

impl BridgeExportStatus {
    pub fn new(state: BridgeExportState, detail: impl Into<String>) -> Self {
        Self {
            state,
            detail: detail.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogEvidenceRow {
    pub seq: u64,
    pub target: String,
    pub level: String,
    pub message: String,
    pub matched_by: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecentSpanRef {
    pub trace_id: String,
    pub span_id: String,
}

impl RecentSpanRef {
    pub fn new(trace_id: impl Into<String>, span_id: impl Into<String>) -> Self {
        Self {
            trace_id: trace_id.into(),
            span_id: span_id.into(),
        }
    }
}

/// Provenance of an observability read, consumed by [`bridge_status_from_logs`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObserveSourceState {
    Live,
    Empty,
    Unsupported,
    Disabled,
    Degraded,
    Error,
}

impl ObserveSourceState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Live => "live spans",
            Self::Empty => "no spans",
            Self::Unsupported => "not supported",
            Self::Disabled => "disabled",
            Self::Degraded => "degraded",
            Self::Error => "fetch error",
        }
    }

    pub fn tone(self) -> &'static str {
        match self {
            Self::Live => "good",
            Self::Empty | Self::Disabled | Self::Degraded => "amber",
            Self::Unsupported => "muted",
            Self::Error => "bad",
        }
    }
}

/// Failure decoding the `/recent` span listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObserveFetchError {
    /// The `/recent` body was not the expected `trace-hex32/span-hex16` lines.
    MalformedRecent,
}

impl std::fmt::Display for ObserveFetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedRecent => f.write_str("malformed recent span listing"),
        }
    }
}

impl std::error::Error for ObserveFetchError {}

/// Parse the observability `/recent` listing (newline `trace-hex32/span-hex16`).
pub fn parse_recent_listing(bytes: &[u8]) -> Result<Vec<RecentSpanRef>, ObserveFetchError> {
    let text = std::str::from_utf8(bytes).map_err(|_| ObserveFetchError::MalformedRecent)?;
    let mut refs = Vec::new();
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let Some((trace_id, span_id)) = line.split_once('/') else {
            return Err(ObserveFetchError::MalformedRecent);
        };
        if !is_hex_of_len(trace_id, 32) || !is_hex_of_len(span_id, 16) {
            return Err(ObserveFetchError::MalformedRecent);
        }
        refs.push(RecentSpanRef::new(trace_id, span_id));
    }
    Ok(refs)
}

/// Build the Data name a single span is served under, from a `/recent` ref.
pub fn span_data_name(prefix: &str, span_ref: &RecentSpanRef) -> String {
    format!(
        "{}/traces/{}/spans/{}",
        prefix.trim_end_matches('/'),
        span_ref.trace_id,
        span_ref.span_id
    )
}

/// Parse an `ndn-ipc` `log_get_recent` body (first line is the sequence header).
pub fn parse_recent_log_response(body: &str) -> Vec<LogEvidenceRow> {
    body.lines()
        .skip(1)
        .enumerate()
        .map(|(index, line)| parse_log_line(index as u64 + 1, line))
        .collect()
}

fn parse_log_line(seq: u64, line: &str) -> LogEvidenceRow {
    let (level, target, message) = parse_tracing_line(line);
    LogEvidenceRow {
        seq,
        target,
        level,
        message,
        matched_by: String::new(),
    }
}

fn parse_tracing_line(line: &str) -> (String, String, String) {
    let level = ["TRACE", "DEBUG", "INFO", "WARN", "ERROR"]
        .into_iter()
        .find(|level| line.contains(level))
        .unwrap_or("LOG")
        .to_ascii_lowercase();
    let target = line
        .split_whitespace()
        .find(|part| part.ends_with(':') && part.contains('.'))
        .map(|part| part.trim_end_matches(':').to_string())
        .unwrap_or_else(|| "runtime".into());
    (level, target, line.to_string())
}

/// Multi-term AND filter across every operator-facing trace/span field.
pub fn filter_traces(traces: &[TraceView], query: &str) -> Vec<TraceView> {
    let terms: Vec<String> = query
        .split_whitespace()
        .map(|term| term.to_ascii_lowercase())
        .collect();
    if terms.is_empty() {
        return traces.to_vec();
    }

    traces
        .iter()
        .filter(|trace| terms.iter().all(|term| trace_matches(trace, term)))
        .cloned()
        .collect()
}

/// Log lines whose text mentions any identifier from `trace`, labelled by what matched.
pub fn correlated_logs_for_trace(
    trace: &TraceView,
    logs: &[LogEvidenceRow],
) -> Vec<LogEvidenceRow> {
    let needles = trace_log_needles(trace);
    logs.iter()
        .filter_map(|row| {
            let haystack = format!(
                "{} {} {}",
                row.target.to_ascii_lowercase(),
                row.level.to_ascii_lowercase(),
                row.message.to_ascii_lowercase()
            );
            let matched = needles
                .iter()
                .find(|needle| !needle.value.is_empty() && haystack.contains(&needle.value));
            matched.map(|needle| {
                let mut row = row.clone();
                row.matched_by = needle.label.clone();
                row
            })
        })
        .take(8)
        .collect()
}

fn trace_log_needles(trace: &TraceView) -> Vec<LogNeedle> {
    let mut needles = vec![
        LogNeedle::new("trace id", &trace.trace_id),
        LogNeedle::new("root span", &trace.root_name),
    ];
    for span in &trace.spans {
        needles.push(LogNeedle::new("span id", &span.span_id));
        needles.push(LogNeedle::new("span name", &span.name));
        needles.push(LogNeedle::new("target", &span.target));
        if let Some(name) = span.interest_name.as_deref() {
            needles.push(LogNeedle::new("Interest", name));
        }
        if let Some(face_id) = span.face_id {
            needles.push(LogNeedle::new("face", face_id.to_string()));
        }
        if let Some(strategy) = span.strategy.as_deref() {
            needles.push(LogNeedle::new("strategy", strategy));
        }
    }
    needles
}

struct LogNeedle {
    label: String,
    value: String,
}

impl LogNeedle {
    fn new(label: impl Into<String>, value: impl ToString) -> Self {
        Self {
            label: label.into(),
            value: value.to_string().to_ascii_lowercase(),
        }
    }
}

/// Flatten a trace into indented parent→child rows (cycle- and orphan-safe).
pub fn span_tree_rows(trace: &TraceView) -> Vec<SpanTreeRow> {
    let span_index: HashMap<&str, usize> = trace
        .spans
        .iter()
        .enumerate()
        .map(|(index, span)| (span.span_id.as_str(), index))
        .collect();
    let mut children: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    let mut roots = Vec::new();

    for (index, span) in trace.spans.iter().enumerate() {
        match span.parent_span_id.as_deref() {
            Some(parent) if span_index.contains_key(parent) => {
                children.entry(parent).or_default().push(index);
            }
            _ => roots.push(index),
        }
    }

    for indexes in children.values_mut() {
        indexes.sort_by(|left, right| trace.spans[*left].span_id.cmp(&trace.spans[*right].span_id));
    }
    roots.sort_by(|left, right| trace.spans[*left].span_id.cmp(&trace.spans[*right].span_id));

    let mut rows = Vec::new();
    let mut visited = HashSet::new();
    for root in roots {
        push_span_tree_row(
            root,
            0,
            trace,
            &children,
            &span_index,
            &mut visited,
            &mut rows,
        );
    }
    for index in 0..trace.spans.len() {
        if !visited.contains(&index) {
            push_span_tree_row(
                index,
                0,
                trace,
                &children,
                &span_index,
                &mut visited,
                &mut rows,
            );
        }
    }
    rows
}

/// Derive `ndn-otel-bridge` export status from recent forwarder log evidence.
pub fn bridge_status_from_logs(
    logs: &[LogEvidenceRow],
    source: ObserveSourceState,
) -> BridgeExportStatus {
    if matches!(
        source,
        ObserveSourceState::Unsupported | ObserveSourceState::Disabled | ObserveSourceState::Error
    ) {
        return BridgeExportStatus::new(
            BridgeExportState::Unavailable,
            "NDN-native span publishing is not available for bridge export.",
        );
    }

    if logs.iter().any(|row| {
        row.message.contains("ndn-otel-bridge")
            && row.message.to_ascii_lowercase().contains("error")
    }) {
        return BridgeExportStatus::new(
            BridgeExportState::Error,
            "Recent logs mention ndn-otel-bridge errors.",
        );
    }

    if logs
        .iter()
        .any(|row| row.message.contains("ndn-otel-bridge"))
    {
        return BridgeExportStatus::new(
            BridgeExportState::Ready,
            "Recent logs mention ndn-otel-bridge activity.",
        );
    }

    BridgeExportStatus::new(
        BridgeExportState::NotAttached,
        "No ndn-otel-bridge activity was observed in recent forwarder logs.",
    )
}

#[allow(clippy::too_many_arguments)]
fn push_span_tree_row(
    index: usize,
    depth: usize,
    trace: &TraceView,
    children: &BTreeMap<&str, Vec<usize>>,
    span_index: &HashMap<&str, usize>,
    visited: &mut HashSet<usize>,
    rows: &mut Vec<SpanTreeRow>,
) {
    if !visited.insert(index) {
        return;
    }

    let span = &trace.spans[index];
    let child_indexes = children
        .get(span.span_id.as_str())
        .cloned()
        .unwrap_or_default();
    rows.push(SpanTreeRow {
        span: span.clone(),
        depth,
        child_count: child_indexes.len(),
        orphaned_parent: span
            .parent_span_id
            .as_deref()
            .is_some_and(|parent| !span_index.contains_key(parent)),
    });

    for child in child_indexes {
        push_span_tree_row(child, depth + 1, trace, children, span_index, visited, rows);
    }
}

/// The `pit.*` spans of a trace, as a flat fan-out table.
pub fn pit_fanout_rows(trace: &TraceView) -> Vec<PitFanOutRow> {
    trace
        .spans
        .iter()
        .filter(|span| span.name.starts_with("pit."))
        .map(|span| PitFanOutRow {
            span_name: span.name.clone(),
            face_id: span.face_id,
            interest_name: span.interest_name.clone(),
            status: span.status,
            duration_us: span.duration_us,
        })
        .collect()
}

fn trace_matches(trace: &TraceView, term: &str) -> bool {
    text_matches(&trace.trace_id, term)
        || text_matches(&trace.root_name, term)
        || trace.spans.iter().any(|span| span_matches(span, term))
}

fn span_matches(span: &SpanView, term: &str) -> bool {
    text_matches(&span.trace_id, term)
        || text_matches(&span.span_id, term)
        || span
            .parent_span_id
            .as_deref()
            .is_some_and(|value| text_matches(value, term))
        || text_matches(&span.name, term)
        || text_matches(&span.target, term)
        || span
            .interest_name
            .as_deref()
            .is_some_and(|value| text_matches(value, term))
        || span
            .face_id
            .map(|face| face.to_string().contains(term))
            .unwrap_or(false)
        || span
            .strategy
            .as_deref()
            .is_some_and(|value| text_matches(value, term))
        || text_matches(span.status.label(), term)
}

fn text_matches(value: &str, term: &str) -> bool {
    value.to_ascii_lowercase().contains(term)
}

fn is_hex_of_len(value: &str, len: usize) -> bool {
    value.len() == len && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Group a flat span list into per-trace [`TraceView`]s (sorted, PIT-fanout flagged).
pub fn group_spans(mut spans: Vec<SpanView>) -> Vec<TraceView> {
    spans.sort_by(|a, b| a.trace_id.cmp(&b.trace_id).then(a.span_id.cmp(&b.span_id)));
    let mut traces = Vec::new();
    let mut current: Option<TraceView> = None;
    for span in spans {
        if current
            .as_ref()
            .map(|trace| trace.trace_id != span.trace_id)
            .unwrap_or(true)
        {
            if let Some(trace) = current.take() {
                traces.push(trace);
            }
            current = Some(TraceView {
                trace_id: span.trace_id.clone(),
                span_count: 0,
                root_name: span.name.clone(),
                duration_us: 0,
                has_pit_fanout: false,
                spans: Vec::new(),
            });
        }
        let trace = current.as_mut().expect("trace exists");
        trace.duration_us = trace.duration_us.saturating_add(span.duration_us);
        trace.has_pit_fanout |= span.name == "pit.satisfy" || span.name == "pit.nack";
        trace.span_count += 1;
        trace.spans.push(span);
    }
    if let Some(trace) = current {
        traces.push(trace);
    }
    traces
}

/// Decode one bare OTLP `Span` protobuf (the wire the ndn-rs publisher emits).
pub fn decode_otlp_span(bytes: &[u8]) -> Result<SpanView, DecodeError> {
    let mut reader = ProtoReader::new(bytes);
    let mut trace_id = None;
    let mut span_id = None;
    let mut parent_span_id = None;
    let mut name = None;
    let mut start = 0u64;
    let mut end = 0u64;
    let mut target = String::new();
    let mut interest_name = None;
    let mut face_id = None;
    let mut strategy = None;
    let mut status = SpanStatus::Unset;
    let mut attrs = Vec::new();

    while !reader.is_empty() {
        let (field, wire) = reader.read_key()?;
        match (field, wire) {
            (1, Wire::Len) => trace_id = Some(hex(reader.read_len()?)),
            (2, Wire::Len) => span_id = Some(hex(reader.read_len()?)),
            (4, Wire::Len) => parent_span_id = Some(hex(reader.read_len()?)),
            (5, Wire::Len) => name = Some(String::from_utf8_lossy(reader.read_len()?).to_string()),
            (7, Wire::Fixed64) => start = reader.read_fixed64()?,
            (8, Wire::Fixed64) => end = reader.read_fixed64()?,
            (9, Wire::Len) => {
                let attr = decode_attr(reader.read_len()?)?;
                match attr.key.as_str() {
                    "ndn.target" => target = attr.value.clone(),
                    "interest.name" => interest_name = Some(attr.value.clone()),
                    "face.id" => face_id = attr.value.parse().ok(),
                    "strategy.name" => strategy = Some(attr.value.clone()),
                    _ => {}
                }
                attrs.push((attr.key, attr.value));
            }
            (15, Wire::Len) => status = decode_status(reader.read_len()?)?,
            _ => reader.skip(wire)?,
        }
    }

    Ok(SpanView {
        trace_id: trace_id.ok_or(DecodeError::MissingField("trace_id"))?,
        span_id: span_id.ok_or(DecodeError::MissingField("span_id"))?,
        parent_span_id,
        name: name.ok_or(DecodeError::MissingField("name"))?,
        target,
        interest_name,
        face_id,
        strategy,
        status,
        duration_us: end.saturating_sub(start) / 1000,
        start_unix_nano: start,
        end_unix_nano: end,
        attrs,
    })
}

/// Failure decoding an OTLP `Span`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    Malformed,
    MissingField(&'static str),
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed => f.write_str("malformed protobuf"),
            Self::MissingField(field) => write!(f, "missing OTLP span field {field}"),
        }
    }
}

impl std::error::Error for DecodeError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Wire {
    Varint,
    Fixed64,
    Len,
}

struct ProtoReader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> ProtoReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.bytes.len()
    }

    fn read_key(&mut self) -> Result<(u64, Wire), DecodeError> {
        let key = self.read_varint()?;
        let wire = match key & 0x07 {
            0 => Wire::Varint,
            1 => Wire::Fixed64,
            2 => Wire::Len,
            _ => return Err(DecodeError::Malformed),
        };
        Ok((key >> 3, wire))
    }

    fn read_varint(&mut self) -> Result<u64, DecodeError> {
        let mut out = 0u64;
        let mut shift = 0;
        loop {
            let b = *self.bytes.get(self.pos).ok_or(DecodeError::Malformed)?;
            self.pos += 1;
            out |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return Ok(out);
            }
            shift += 7;
            if shift > 63 {
                return Err(DecodeError::Malformed);
            }
        }
    }

    fn read_len(&mut self) -> Result<&'a [u8], DecodeError> {
        let len = self.read_varint()? as usize;
        let end = self.pos.checked_add(len).ok_or(DecodeError::Malformed)?;
        let slice = self
            .bytes
            .get(self.pos..end)
            .ok_or(DecodeError::Malformed)?;
        self.pos = end;
        Ok(slice)
    }

    fn read_fixed64(&mut self) -> Result<u64, DecodeError> {
        let end = self.pos.checked_add(8).ok_or(DecodeError::Malformed)?;
        let slice = self
            .bytes
            .get(self.pos..end)
            .ok_or(DecodeError::Malformed)?;
        self.pos = end;
        Ok(u64::from_le_bytes(slice.try_into().expect("8 bytes")))
    }

    fn skip(&mut self, wire: Wire) -> Result<(), DecodeError> {
        match wire {
            Wire::Varint => {
                self.read_varint()?;
            }
            Wire::Fixed64 => {
                self.read_fixed64()?;
            }
            Wire::Len => {
                self.read_len()?;
            }
        }
        Ok(())
    }
}

struct Attr {
    key: String,
    value: String,
}

fn decode_attr(bytes: &[u8]) -> Result<Attr, DecodeError> {
    let mut reader = ProtoReader::new(bytes);
    let mut key = String::new();
    let mut value = String::new();
    while !reader.is_empty() {
        let (field, wire) = reader.read_key()?;
        match (field, wire) {
            (1, Wire::Len) => key = String::from_utf8_lossy(reader.read_len()?).to_string(),
            (2, Wire::Len) => value = decode_any_value(reader.read_len()?)?,
            _ => reader.skip(wire)?,
        }
    }
    Ok(Attr { key, value })
}

fn decode_any_value(bytes: &[u8]) -> Result<String, DecodeError> {
    let mut reader = ProtoReader::new(bytes);
    while !reader.is_empty() {
        let (field, wire) = reader.read_key()?;
        match (field, wire) {
            (1, Wire::Len) => return Ok(String::from_utf8_lossy(reader.read_len()?).to_string()),
            (3, Wire::Varint) => return Ok((reader.read_varint()? as i64).to_string()),
            (4, Wire::Varint) => return Ok((reader.read_varint()? != 0).to_string()),
            _ => reader.skip(wire)?,
        }
    }
    Ok(String::new())
}

fn decode_status(bytes: &[u8]) -> Result<SpanStatus, DecodeError> {
    let mut reader = ProtoReader::new(bytes);
    let mut status = SpanStatus::Unset;
    while !reader.is_empty() {
        let (field, wire) = reader.read_key()?;
        match (field, wire) {
            (3, Wire::Varint) => {
                status = match reader.read_varint()? {
                    1 => SpanStatus::Ok,
                    2 => SpanStatus::Error,
                    _ => SpanStatus::Unset,
                };
            }
            _ => reader.skip(wire)?,
        }
    }
    Ok(status)
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_len(out: &mut Vec<u8>, field: u64, payload: &[u8]) {
        out.push(((field << 3) | 2) as u8);
        out.push(payload.len() as u8);
        out.extend_from_slice(payload);
    }

    fn encode_fixed64(out: &mut Vec<u8>, field: u64, value: u64) {
        out.push(((field << 3) | 1) as u8);
        out.extend_from_slice(&value.to_le_bytes());
    }

    fn attr(key: &str, value: &str) -> Vec<u8> {
        let mut any = Vec::new();
        encode_len(&mut any, 1, value.as_bytes());
        let mut out = Vec::new();
        encode_len(&mut out, 1, key.as_bytes());
        encode_len(&mut out, 2, &any);
        out
    }

    fn mock_trace() -> TraceView {
        let spans = vec![
            SpanView {
                trace_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                span_id: "0000000000000001".into(),
                parent_span_id: None,
                name: "interest".into(),
                target: "fwd.pipeline".into(),
                interest_name: Some("/demo/video/keyframe".into()),
                face_id: Some(7),
                strategy: Some("best-route".into()),
                status: SpanStatus::Ok,
                duration_us: 3400,
                start_unix_nano: 1_000_000,
                end_unix_nano: 4_400_000,
                attrs: vec![
                    ("interest.name".into(), "/demo/video/keyframe".into()),
                    ("ndn.target".into(), "fwd.pipeline".into()),
                ],
            },
            SpanView {
                trace_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                span_id: "0000000000000002".into(),
                parent_span_id: Some("0000000000000001".into()),
                name: "pit.satisfy".into(),
                target: "fwd.pit".into(),
                interest_name: Some("/demo/video/keyframe".into()),
                face_id: Some(11),
                strategy: None,
                status: SpanStatus::Ok,
                duration_us: 120,
                start_unix_nano: 4_400_000,
                end_unix_nano: 4_520_000,
                attrs: vec![("interest.name".into(), "/demo/video/keyframe".into())],
            },
        ];
        group_spans(spans).remove(0)
    }

    #[test]
    fn decode_minimal_otlp_span() {
        let mut span = Vec::new();
        encode_len(&mut span, 1, &[0x11; 16]);
        encode_len(&mut span, 2, &[0x22; 8]);
        encode_len(&mut span, 5, b"interest");
        encode_fixed64(&mut span, 7, 1_000);
        encode_fixed64(&mut span, 8, 11_000);
        encode_len(&mut span, 9, &attr("interest.name", "/a/b"));
        encode_len(&mut span, 9, &attr("ndn.target", "fwd.pipeline"));
        let decoded = decode_otlp_span(&span).expect("decode");
        assert_eq!(decoded.trace_id, "11111111111111111111111111111111");
        assert_eq!(decoded.span_id, "2222222222222222");
        assert_eq!(decoded.interest_name.as_deref(), Some("/a/b"));
        assert_eq!(decoded.duration_us, 10);
        assert_eq!(decoded.start_unix_nano, 1_000);
        assert_eq!(decoded.end_unix_nano, 11_000);
        assert_eq!(decoded.duration_nanos(), 10_000);
        assert_eq!(decoded.target, "fwd.pipeline");
        // Every attribute is retained in wire order, well-known ones included.
        assert_eq!(
            decoded.attrs,
            vec![
                ("interest.name".to_string(), "/a/b".to_string()),
                ("ndn.target".to_string(), "fwd.pipeline".to_string()),
            ]
        );
    }

    #[test]
    fn grouping_marks_pit_fanout() {
        let trace = mock_trace();
        assert!(trace.has_pit_fanout);
        assert_eq!(trace.span_count, 2);
    }

    #[test]
    fn parses_recent_span_listing() {
        let refs = parse_recent_listing(
            b"11111111111111111111111111111111/2222222222222222\n33333333333333333333333333333333/4444444444444444\n",
        )
        .expect("recent listing");
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].trace_id, "11111111111111111111111111111111");
        assert_eq!(refs[0].span_id, "2222222222222222");
    }

    #[test]
    fn rejects_malformed_recent_span_listing() {
        assert_eq!(
            parse_recent_listing(b"not-a-trace").unwrap_err(),
            ObserveFetchError::MalformedRecent
        );
        assert_eq!(
            parse_recent_listing(b"11111111111111111111111111111111/nothex").unwrap_err(),
            ObserveFetchError::MalformedRecent
        );
    }

    #[test]
    fn builds_span_data_name_from_recent_ref() {
        let span_ref = RecentSpanRef::new("11111111111111111111111111111111", "2222222222222222");
        assert_eq!(
            span_data_name("/localhost/nfd/observability/", &span_ref),
            "/localhost/nfd/observability/traces/11111111111111111111111111111111/spans/2222222222222222"
        );
    }

    #[test]
    fn filters_traces_by_all_operator_fields() {
        let trace = mock_trace();
        let traces = vec![trace.clone()];
        for query in [
            "aaaaaaaa",
            "interest",
            "fwd.pit",
            "11",
            "best-route",
            "ok",
            "/demo/video",
        ] {
            let filtered = filter_traces(&traces, query);
            assert_eq!(filtered, vec![trace.clone()], "query {query}");
        }
    }

    #[test]
    fn filters_traces_by_all_query_terms() {
        let trace = mock_trace();
        let traces = vec![trace.clone()];
        assert_eq!(filter_traces(&traces, "best-route ok"), vec![trace]);
        assert!(filter_traces(&traces, "best-route error").is_empty());
        assert!(filter_traces(&traces, "missing").is_empty());
    }

    #[test]
    fn builds_parent_child_span_tree_rows() {
        let trace = mock_trace();
        let rows = span_tree_rows(&trace);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].span.name, "interest");
        assert_eq!(rows[0].depth, 0);
        assert_eq!(rows[0].child_count, 1);
        assert_eq!(rows[1].span.name, "pit.satisfy");
        assert_eq!(rows[1].depth, 1);
        assert!(!rows[1].orphaned_parent);
    }

    #[test]
    fn span_tree_marks_missing_parents_as_orphaned_roots() {
        let mut trace = mock_trace();
        trace.spans[1].parent_span_id = Some("missing-parent".into());
        let rows = span_tree_rows(&trace);
        let orphan = rows
            .iter()
            .find(|row| row.span.name == "pit.satisfy")
            .expect("pit row");
        assert_eq!(orphan.depth, 0);
        assert!(orphan.orphaned_parent);
    }

    #[test]
    fn extracts_pit_fanout_rows() {
        let trace = mock_trace();
        let rows = pit_fanout_rows(&trace);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].span_name, "pit.satisfy");
        assert_eq!(rows[0].face_id, Some(11));
        assert_eq!(rows[0].status, SpanStatus::Ok);
    }

    #[test]
    fn parses_recent_log_response_into_evidence_rows() {
        let rows = parse_recent_log_response(
            "42\n2026-05-28T00:00:00Z  INFO fwd.pipeline: received /demo/video/keyframe",
        );
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].seq, 1);
        assert_eq!(rows[0].level, "info");
        assert_eq!(rows[0].target, "fwd.pipeline");
    }

    #[test]
    fn correlates_logs_under_selected_trace() {
        let trace = mock_trace();
        let logs = vec![
            LogEvidenceRow {
                seq: 1,
                target: "fwd.pipeline".into(),
                level: "info".into(),
                message: "received /demo/video/keyframe".into(),
                matched_by: String::new(),
            },
            LogEvidenceRow {
                seq: 2,
                target: "other".into(),
                level: "info".into(),
                message: "unrelated".into(),
                matched_by: String::new(),
            },
        ];
        let rows = correlated_logs_for_trace(&trace, &logs);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].seq, 1);
        assert!(!rows[0].matched_by.is_empty());
    }

    #[test]
    fn bridge_status_uses_recent_log_evidence() {
        let logs = vec![LogEvidenceRow {
            seq: 7,
            target: "bridge".into(),
            level: "info".into(),
            message: "ndn-otel-bridge starting".into(),
            matched_by: String::new(),
        }];
        assert_eq!(
            bridge_status_from_logs(&logs, ObserveSourceState::Live).state,
            BridgeExportState::Ready
        );
        assert_eq!(
            bridge_status_from_logs(&[], ObserveSourceState::Disabled).state,
            BridgeExportState::Unavailable
        );
    }
}
