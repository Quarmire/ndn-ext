//! `ndn-viz` — the UI-agnostic data-visualization layer for NDN operator tooling.
//!
//! This crate is the "shared data-visualization layer (ndn-sim + dashboard)" the
//! dashboard salvage inventory pointed every reusable observability piece at. It
//! holds **pure** model + wire code — zero UI imports, zero I/O, zero runtime
//! dependencies — so both the browser dashboard (wasm32) and `ndn-sim` (native)
//! can build on it unchanged. Consumers own the transport: they fetch the Data,
//! this crate decodes and shapes it.
//!
//! Modules:
//! - [`observe`] — the OTLP `Span` decoder, the `/recent` fetch contract
//!   (parse + name-shape), and the trace/span view-model algebra (grouping,
//!   parent/child tree flattening, PIT-fanout, multi-term filtering, log
//!   correlation, bridge-status derivation).
//! - [`control`] — the generic `/localhost/nfd/ext/list` control-surface ingest
//!   ([`control::ControlSurfaces`]) plus typed projections over it:
//!   [`control::RadioCognition`] (decided plan), [`control::HardwareInventory`]
//!   (device substrate + PHY health), and [`control::Monitors`] (long-running
//!   watchers). Radio / hardware / monitors all ride the one ext mechanism.
//! - [`source`] — the per-dataset freshness model ([`source::DatasetState`] /
//!   [`source::DatasetSource`]) so every panel carries its own provenance
//!   instead of one global connected flag.
//!
//! **wasm-cleanliness is a contract, not a hope.** Nothing here may call the
//! platform clock, filesystem, environment, networking, or process APIs — the
//! `std` modules that panic or are unusable on `wasm32-unknown-unknown`. The
//! integration test in `tests/wasm_clean.rs` enforces it by scanning the source
//! for those module paths (it is the authority on the exact banned list).

pub mod control;
pub mod observe;
pub mod service;
pub mod source;

pub use control::{
    ControlSurfaces, HardwareInventory, Monitor, Monitors, ObjectStats, RadioCognition,
    RadioDevice, RadioRow, Subsystem, parse_ext_list,
};

pub use observe::{
    BridgeExportState, BridgeExportStatus, DEFAULT_OBSERVABILITY_PREFIX, DecodeError,
    LogEvidenceRow, ObserveFetchError, PitFanOutRow, RecentSpanRef, SpanStatus, SpanTreeRow,
    SpanView, TraceView, bridge_status_from_logs, correlated_logs_for_trace, decode_otlp_span,
    filter_traces, group_spans, parse_recent_listing, parse_recent_log_response, pit_fanout_rows,
    span_data_name, span_tree_rows,
};
pub use service::{
    DiscoveryStatus, ServiceReadError, ServiceRecord, ServiceState, parse_discovery_status,
    parse_service_browse,
};
pub use source::{DatasetSource, DatasetState, dataset_state_from_result};
