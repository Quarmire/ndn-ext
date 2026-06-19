//! Engine-attachment seam for browser NDN apps.
//!
//! A browser NDN app should not branch on *where* its engine lives. It binds a
//! prefix / opens a consumer and talks to a [`Face`], full stop. Whether that
//! face leads to an engine built in this very tab, a per-origin SharedWorker
//! shared across tabs, or an out-of-page engine (browser extension / native
//! `ndn-fwd` companion) is a deployment concern, not an app-code concern.
//!
//! [`EngineAttachment`] is that seam. The app picks (or [`auto`]-detects) an
//! attachment, calls [`EngineAttachment::attach`], and receives an
//! [`AppHandle`] — the only surface app code touches.
//!
//! # Sharing-scope tiers
//!
//! | Variant | Sharing | When |
//! |---------|---------|------|
//! | [`InPage`](EngineAttachment::InPage) | none (per-tab) | standalone / offline / single-tab |
//! | [`SharedWorker`](EngineAttachment::SharedWorker) | same-origin, all tabs | **default** — shared CS + PIT aggregation, invisible |
//! | [`External`](EngineAttachment::External) | cross-origin / persistent | the only case that *forces* a dedicated engine (SharedWorker is same-origin only) |
//!
//! # Status
//!
//! Scaffold. The variants and the [`AppHandle`] contract are fixed; the bodies
//! are unimplemented (see `TODO`s). Design rationale and witness plan live in
//! `.claude/notes/wasm-app-template/engine-attachment-2026-05-23.md`.
//!
//! [`Face`]: https://docs.rs/ndn-transport

#![forbid(unsafe_code)]

use std::sync::Arc;

use ndn_app::{Consumer, EngineAppExt, ForwarderEngine, Producer, ShutdownHandle};
use ndn_packet::Name;
use ndn_runtime::Runtime;
use thiserror::Error;
use tokio_util::sync::CancellationToken;

/// Per-tab in-page engine configuration.
#[derive(Debug, Clone, Default)]
pub struct InPageConfig {
    /// Optional upstream face URI (e.g. a WebTransport endpoint). `None` builds
    /// a producer/cache-only engine with no default route.
    ///
    /// TODO(upstream): not yet honored — wiring it needs a WebTransport face
    /// dial (`ndn-face-webtransport-wasm`) plus a default `/ → upstream` route.
    /// Today every in-page engine is upstream-less (local pub/sub + cache).
    pub upstream_url: Option<String>,
}

/// How a browser app obtains the engine-facing [`Face`](crate).
#[derive(Debug, Clone)]
pub enum EngineAttachment {
    /// Build a full engine in this tab. Zero-config; no cross-tab sharing.
    InPage(InPageConfig),
    /// Attach to the per-origin SharedWorker engine, booting it if absent.
    /// `worker_url` is the bundled SharedWorker entrypoint script.
    SharedWorker { worker_url: String },
    /// Attach to an out-of-page engine reachable over a host-provided channel
    /// (extension `MessagePort`, native companion socket bridged to a Face).
    External { endpoint: String },
}

impl EngineAttachment {
    /// Choose the best available backing for the current environment.
    ///
    /// Preference order: SharedWorker (same-origin sharing, invisible) when the
    /// platform supports it and a `worker_url` is supplied, else in-page.
    ///
    /// TODO(wasm): real feature-detection — probe `self instanceof SharedWorker`
    /// availability via `web-sys` before choosing `SharedWorker`. Some mobile
    /// browsers and service-worker contexts lack it; those must fall back to
    /// [`InPage`](EngineAttachment::InPage).
    pub fn auto(cfg: InPageConfig, worker_url: Option<String>) -> Self {
        match worker_url {
            Some(url) if shared_worker_supported() => {
                EngineAttachment::SharedWorker { worker_url: url }
            }
            _ => EngineAttachment::InPage(cfg),
        }
    }

    /// Resolve this attachment to the app-facing handle.
    ///
    /// This is the one async step an app performs at startup; everything after
    /// goes through [`AppHandle`].
    pub async fn attach(self) -> Result<AppHandle, AttachError> {
        match self {
            // In-page: embed a full engine in this context and drive it through
            // ndn-app's EngineAppExt client surface. Same end-state on native
            // (EngineBuilder, async) and wasm32 (WasmEngineBuilder, sync) — both
            // yield a `ForwarderEngine` that consumer()/register_producer() use.
            // TODO(upstream): honor `cfg.upstream_url` (WebTransport dial +
            //   default route). TODO(mgmt): optionally `mount_management` so the
            //   engine answers `/localhost/nfd/...` for protocol-uniform control.
            EngineAttachment::InPage(_cfg) => {
                let runtime = ndn_runtime::default_runtime();
                let (engine, shutdown) = build_in_page_engine(Arc::clone(&runtime)).await?;
                Ok(AppHandle {
                    engine,
                    _shutdown: shutdown,
                    cancel: CancellationToken::new(),
                    runtime,
                })
            }
            // TODO(shared-worker): boot/connect the SharedWorker, hand its
            // `MessagePort` to `ndn-face-shared-worker`, register prefixes over
            // the bridge. The engine lives in the worker; this tab is a client.
            EngineAttachment::SharedWorker { .. } => {
                Err(AttachError::Unimplemented("shared-worker tier"))
            }
            // TODO(external): connect the host-provided channel, adapt it to a
            // Face, return the client end.
            EngineAttachment::External { .. } => Err(AttachError::Unimplemented("external tier")),
        }
    }
}

/// Build an embedded engine for the current target. Native uses the async
/// `EngineBuilder`; wasm32 uses the single-threaded `WasmEngineBuilder`.
#[cfg(not(target_arch = "wasm32"))]
async fn build_in_page_engine(
    _runtime: Arc<dyn Runtime>,
) -> Result<(ForwarderEngine, ShutdownHandle), AttachError> {
    ndn_app::EngineBuilder::new(Default::default())
        .build()
        .await
        .map_err(|e| AttachError::Transport(format!("{e:?}")))
}

#[cfg(target_arch = "wasm32")]
async fn build_in_page_engine(
    runtime: Arc<dyn Runtime>,
) -> Result<(ForwarderEngine, ShutdownHandle), AttachError> {
    ndn_app::WasmEngineBuilder::new(ndn_app::WasmEngineConfig::default())
        .with_runtime(runtime)
        .build()
        .map_err(|e| AttachError::Transport(format!("{e:?}")))
}

/// The app-facing surface. Topology-agnostic by construction: app code calls
/// [`consumer`](Self::consumer) / [`register_producer`](Self::register_producer)
/// the same way regardless of which tier produced the handle.
///
/// Holds the embedded engine alive (via `_shutdown`); dropping the `AppHandle`
/// tears the engine down. `cancel` is the parent token for app faces — they go
/// away with the handle.
pub struct AppHandle {
    engine: ForwarderEngine,
    /// Keeps engine tasks alive until the handle drops.
    _shutdown: ShutdownHandle,
    cancel: CancellationToken,
    runtime: Arc<dyn Runtime>,
}

impl AppHandle {
    /// A [`Consumer`] over a fresh in-process app face. Use `fetch` /
    /// `fetch_object` on it.
    pub fn consumer(&self) -> Consumer {
        self.engine.app_consumer(self.cancel.child_token())
    }

    /// A [`Producer`] bound to `prefix` (its FIB route is installed). Use
    /// `serve` / `publish_object` on it.
    pub fn register_producer(&self, prefix: impl Into<Name>) -> Producer {
        self.engine
            .register_producer(prefix, self.cancel.child_token())
    }

    /// Escape hatch to the embedded engine — e.g. to install additional
    /// faces/routes. Most apps need only the two methods above (plus
    /// [`mount_management`](Self::mount_management) for wire control).
    pub fn engine(&self) -> &ForwarderEngine {
        &self.engine
    }

    /// The runtime driving this engine — for spawning app-side tasks.
    pub fn runtime(&self) -> Arc<dyn Runtime> {
        Arc::clone(&self.runtime)
    }

    /// Mount NFD-compatible management on the in-page engine, **requiring**
    /// command Interests to be signed and validated by `command_validator`
    /// (build one from trust anchors, e.g. via `ndn_pib_idb::IdbPib`).
    ///
    /// Secure by default: this seam exposes no permissive (unsigned-accepted)
    /// mgmt path. A shared in-page/worker engine must not take `/localhost/nfd/...`
    /// commands from anyone, so the validator is mandatory and
    /// `require_signed_commands` is forced on. Without calling this, the engine
    /// simply isn't wire-manageable (apps use the typed `consumer`/`producer`
    /// API). Data-plane verification remains the consumer's job, separately.
    ///
    /// Wasm-only: native in-page deployments use `ndn-fwd`'s full builder
    /// (discovery/PIB wiring) rather than this seam.
    #[cfg(target_arch = "wasm32")]
    pub fn mount_management(&self, command_validator: Arc<ndn_security::Validator>) {
        use std::collections::HashMap;
        use std::sync::Mutex as StdMutex;

        let handles = ndn_mgmt::MgmtHandles {
            extra_modules: Vec::new(),
            face_provisioners: Vec::new(),
            control_surfaces: Vec::new(),
            security_is_ephemeral: false,
            command_validator: Some(Arc::clone(&command_validator)),
            localhop_command_validator: Some(command_validator),
            require_signed_commands: true,
            command_replay_cache: Some(Arc::new(StdMutex::new(HashMap::new()))),
            command_response_signer: None,
            log_inspector: None,
            coding_handler: None,
            rate_limit_handler: None,
            compute_handler: None,
            ble_handler: None,
            approval_handler: None,
            webtransport_status_handler: None,
        };
        let config = Arc::new(ndn_config::ForwarderConfig::default());
        let fut =
            ndn_mgmt::mount_management(&self.engine, self.cancel.child_token(), config, handles);
        self.runtime.spawn(Box::pin(fut));
    }
}

/// Why an [`attach`](EngineAttachment::attach) failed.
#[derive(Debug, Error)]
pub enum AttachError {
    /// Tier not yet implemented (scaffold stage).
    #[error("engine-attachment tier not yet implemented: {0}")]
    Unimplemented(&'static str),
    /// The chosen backing is unavailable in this environment
    /// (e.g. SharedWorker requested on a platform that lacks it).
    #[error("engine-attachment backing unavailable: {0}")]
    Unsupported(String),
    /// The transport/connection step failed.
    #[error("engine-attachment transport error: {0}")]
    Transport(String),
}

/// Whether the current platform exposes the SharedWorker API.
///
/// TODO(wasm): replace this conservative stub with a real `web-sys` probe.
/// Native builds (tests/tools) report `false` so [`auto`](EngineAttachment::auto)
/// resolves to in-page off-target.
#[inline]
fn shared_worker_supported() -> bool {
    cfg!(target_arch = "wasm32")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_falls_back_to_in_page_off_target() {
        // Off wasm, even with a worker_url, auto() must choose in-page.
        let a = EngineAttachment::auto(InPageConfig::default(), Some("worker.js".into()));
        assert!(matches!(a, EngineAttachment::InPage(_)));
    }

    #[test]
    fn auto_in_page_when_no_worker_url() {
        let a = EngineAttachment::auto(InPageConfig::default(), None);
        assert!(matches!(a, EngineAttachment::InPage(_)));
    }
}
