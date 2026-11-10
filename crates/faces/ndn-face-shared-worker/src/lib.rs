//! SharedWorker face: one engine per origin, shared across every tab.
//!
//! A single `SharedWorker` hosts the engine. Each
//! tab opens a `MessagePort` and installs a
//! `SharedWorkerProxyFace`; inside the worker, each connected port becomes
//! a `WorkerPortFace` from the engine's POV.
//!
//! Wire format: raw NDN TLV bytes, one packet per `postMessage`, transferred
//! as an `ArrayBuffer` so the move is zero-copy.
//!
//! `MessagePort` is `!Send`; the `Face` trait requires `Send + Sync + 'static`.
//! Each face holds two [`mpsc`](tokio::sync::mpsc) channels and a pump task
//! spawned via [`ndn_runtime::Runtime`] owns the JS port for its lifetime.
//!
//! The worker dies when the last connected tab closes; cross-session state
//! needs a separate strategy (e.g. IndexedDB-backed PIB).
//!
//! Native builds have [`WorkerPortFace`] (a plain pair of channels) so its
//! trust can be tested without a browser; the listener, the pump and the
//! tab-side proxy are wasm32-only.
//!
//! Trust: a port the worker accepts with `WorkerListener::accept_one` is a
//! validated face, so Data a tab sends is checked before it is cached or
//! forwarded. `WorkerListener::accept_program` skips that check and is only
//! for a worker none of whose tabs bridges a remote peer. The tab's own proxy
//! (`SharedWorkerProxyFace`) is a program face: its peer is the worker of its
//! own origin.
//!
//! Peer-reuse — sharing a single WebRTC peering across tabs — is deferred.
//!
//! Service Workers aren't the right tool: they're activated by `fetch` and
//! scoped to HTTP request interception, not long-lived application state.

#![deny(rust_2018_idioms)]

mod codec;
mod error;
mod port_face;

pub use error::SharedWorkerFaceError;
pub use port_face::WorkerPortFace;

#[cfg(target_arch = "wasm32")]
mod proxy;
#[cfg(target_arch = "wasm32")]
mod worker;

#[cfg(target_arch = "wasm32")]
pub use proxy::SharedWorkerProxyFace;
#[cfg(target_arch = "wasm32")]
pub use worker::{WorkerListener, init_worker_scope};
