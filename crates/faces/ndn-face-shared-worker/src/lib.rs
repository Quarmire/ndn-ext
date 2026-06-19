//! SharedWorker face: one engine per origin, shared across every tab.
//!
//! A single [`SharedWorker`](web_sys::SharedWorker) hosts the engine. Each
//! tab opens a [`MessagePort`](web_sys::MessagePort) and installs a
//! [`SharedWorkerProxyFace`]; inside the worker, each connected port becomes
//! a [`WorkerPortFace`] from the engine's POV.
//!
//! Wire format: raw NDN TLV bytes, one packet per `postMessage`, transferred
//! as an [`ArrayBuffer`](js_sys::ArrayBuffer) so the move is zero-copy.
//!
//! `MessagePort` is `!Send`; the `Face` trait requires `Send + Sync + 'static`.
//! Each face holds two [`mpsc`](tokio::sync::mpsc) channels and a pump task
//! spawned via [`ndn_runtime::Runtime`] owns the JS port for its lifetime.
//!
//! The worker dies when the last connected tab closes; cross-session state
//! needs a separate strategy (e.g. IndexedDB-backed PIB).
//!
//! Native compiles as a no-op stub (types are wasm32-only).
//!
//! Peer-reuse — sharing a single WebRTC peering across tabs — is deferred.
//!
//! Service Workers aren't the right tool: they're activated by `fetch` and
//! scoped to HTTP request interception, not long-lived application state.

#![deny(rust_2018_idioms)]

mod codec;
mod error;

pub use error::SharedWorkerFaceError;

#[cfg(target_arch = "wasm32")]
mod proxy;
#[cfg(target_arch = "wasm32")]
mod worker;

#[cfg(target_arch = "wasm32")]
pub use proxy::SharedWorkerProxyFace;
#[cfg(target_arch = "wasm32")]
pub use worker::{WorkerListener, WorkerPortFace, init_worker_scope};
