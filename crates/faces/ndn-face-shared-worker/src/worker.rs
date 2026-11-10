//! Worker-side: accept inbound `MessagePort`s and surface each as a [`Face`].
//!
//! Every tab that opens a `SharedWorker` handle triggers a `connect` event
//! on the [`SharedWorkerGlobalScope`]; [`WorkerListener::accept_one`] yields
//! the next inbound port wrapped as a [`WorkerPortFace`].

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::{Mutex, mpsc};
use tracing::warn;
use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;
use wasm_bindgen::closure::Closure;
use web_sys::{MessageEvent, MessagePort, SharedWorkerGlobalScope};

use ndn_runtime::Runtime;
use ndn_transport::{FaceId, FaceTrust};

use crate::codec::{decode_inbound, encode_outbound};
use crate::error::SharedWorkerFaceError;
use crate::port_face::WorkerPortFace;

/// Acceptor-style listener bound to the current [`SharedWorkerGlobalScope`].
/// Construct once per worker via [`init_worker_scope`]; inbound ports are
/// queued so `accept_one` is a clean `await`.
pub struct WorkerListener {
    rx: Mutex<mpsc::UnboundedReceiver<MessagePort>>,
    tx: mpsc::UnboundedSender<MessagePort>,
    /// Holds the JS `onconnect` closure for the scope's lifetime.
    _on_connect: Closure<dyn FnMut(JsValue)>,
}

impl WorkerListener {
    /// Yield the next inbound tab connection as a [`WorkerPortFace`] driven
    /// on `runtime`. Caller supplies a fresh [`FaceId`] (typically via the
    /// engine's `face_table.alloc_id()`).
    ///
    /// The face is [`FaceTrust::Validated`]: the forwarder checks the
    /// signature of every Data the tab sends before caching or forwarding it.
    /// A tab can be a bridge for a remote peer (a WebRTC or WebTransport page
    /// relaying what a peer sent), and a `MessagePort` says nothing about who
    /// is on the far side of that page. Use [`Self::accept_program`] only when
    /// you know no tab does that.
    pub async fn accept_one(
        &self,
        id: FaceId,
        runtime: Arc<dyn Runtime>,
    ) -> Result<WorkerPortFace, SharedWorkerFaceError> {
        self.accept(id, FaceTrust::Validated, runtime).await
    }

    /// Like [`Self::accept_one`], but the face is [`FaceTrust::Program`]: its
    /// Data is cached and forwarded without a signature check, and its
    /// `/localhost` and management Interests are treated as coming from a
    /// local program.
    ///
    /// Call this only for a worker none of whose tabs bridges a remote peer
    /// (a page that forwards bytes from WebRTC, WebTransport, or any other
    /// network source). If any tab does, a remote peer's forged Data would
    /// pass as local, so use [`Self::accept_one`] for that worker.
    pub async fn accept_program(
        &self,
        id: FaceId,
        runtime: Arc<dyn Runtime>,
    ) -> Result<WorkerPortFace, SharedWorkerFaceError> {
        self.accept(id, FaceTrust::Program, runtime).await
    }

    async fn accept(
        &self,
        id: FaceId,
        trust: FaceTrust,
        runtime: Arc<dyn Runtime>,
    ) -> Result<WorkerPortFace, SharedWorkerFaceError> {
        let mut rx = self.rx.lock().await;
        let port = rx.recv().await.ok_or(SharedWorkerFaceError::Closed)?;
        Ok(port_face(id, trust, port, runtime))
    }

    /// Enqueue an inbound [`MessagePort`] directly — for JS-side bootstraps
    /// that buffered `connect` events before [`init_worker_scope`] ran.
    ///
    /// Does NOT call `port.start()`: that would dispatch queued messages
    /// with no listener attached and the HTML spec drops them. The pump's
    /// `set_onmessage` starts the port safely.
    pub fn accept_port(&self, port: MessagePort) {
        let _ = self.tx.send(port);
    }
}

/// Wire `port` to a [`WorkerPortFace`]: two channels, and a pump task on
/// `runtime` that owns the `!Send` port for its lifetime.
fn port_face(
    id: FaceId,
    trust: FaceTrust,
    port: MessagePort,
    runtime: Arc<dyn Runtime>,
) -> WorkerPortFace {
    let (tx_out, rx_out) = mpsc::channel::<Bytes>(64);
    let (tx_in, rx_in) = mpsc::channel::<Bytes>(64);

    runtime.spawn(Box::pin(port_pump(port, rx_out, tx_in)));

    WorkerPortFace::with_trust(id, trust, tx_out, rx_in)
}

/// Bind the worker-scope `onconnect` handler and return the [`WorkerListener`].
/// Call exactly once per worker; calling twice orphans the first listener.
pub fn init_worker_scope() -> Result<WorkerListener, SharedWorkerFaceError> {
    let scope = js_sys::global()
        .dyn_into::<SharedWorkerGlobalScope>()
        .map_err(|_| SharedWorkerFaceError::NotInWorkerScope)?;

    let (tx, rx) = mpsc::unbounded_channel::<MessagePort>();
    let tx = Rc::new(tx);

    let tx_for_cb = Rc::clone(&tx);
    let on_connect: Closure<dyn FnMut(JsValue)> = Closure::wrap(Box::new(move |ev: JsValue| {
        let event: MessageEvent = ev.unchecked_into();
        // W3C spec: SharedWorker connect events always populate exactly one
        // port at index 0.
        let ports = event.ports();
        let Some(port_val) = ports.get(0).dyn_into::<MessagePort>().ok() else {
            warn!(target: "face.shared-worker.worker", "connect event missing port[0]");
            return;
        };
        // Do not start() — see WorkerListener::accept_port.
        if tx_for_cb.send(port_val).is_err() {
            warn!(target: "face.shared-worker.worker", "listener dropped; ignoring inbound connect");
        }
    }));
    scope.set_onconnect(Some(on_connect.as_ref().unchecked_ref()));

    Ok(WorkerListener {
        rx: Mutex::new(rx),
        tx: (*tx).clone(),
        _on_connect: on_connect,
    })
}

async fn port_pump(
    port: MessagePort,
    mut rx_out: mpsc::Receiver<Bytes>,
    tx_in: mpsc::Sender<Bytes>,
) {
    let _on_message = install_onmessage(&port, tx_in);

    while let Some(pkt) = rx_out.recv().await {
        let array = encode_outbound(&pkt);
        let buffer: JsValue = array.buffer().into();
        let transfer = js_sys::Array::new();
        transfer.push(&buffer);
        if let Err(e) = port.post_message_with_transferable(&array.into(), &transfer) {
            warn!(target: "face.shared-worker.worker", error=?e, "post_message failed; closing pump");
            break;
        }
    }
}

fn install_onmessage(
    port: &MessagePort,
    tx_in: mpsc::Sender<Bytes>,
) -> Closure<dyn FnMut(JsValue)> {
    let tx = Rc::new(RefCell::new(tx_in));
    let cb: Closure<dyn FnMut(JsValue)> = Closure::wrap(Box::new(move |ev: JsValue| {
        let event: MessageEvent = ev.unchecked_into();
        let Some(bytes) = decode_inbound(event.data()) else {
            warn!(target: "face.shared-worker.worker", "ignored inbound non-buffer payload");
            return;
        };
        let tx = tx.borrow();
        if let Err(e) = tx.try_send(bytes) {
            warn!(target: "face.shared-worker.worker", error=?e, "inbound channel full; dropping");
        }
    }));
    port.set_onmessage(Some(cb.as_ref().unchecked_ref()));
    cb
}
