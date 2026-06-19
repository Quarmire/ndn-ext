//! Tab-side: a [`Face`] that proxies to a [`SharedWorker`] over a [`MessagePort`].

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::{Mutex, mpsc};
use tracing::warn;
use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;
use wasm_bindgen::closure::Closure;
use web_sys::{MessageEvent, MessagePort, SharedWorker};

use ndn_runtime::Runtime;
use ndn_transport::{FaceError, FaceId, FaceKind, Transport};

use crate::codec::{decode_inbound, encode_outbound};
use crate::error::SharedWorkerFaceError;

/// Tab-side proxy face: every Interest/Data is shipped over a [`MessagePort`]
/// to the per-origin [`SharedWorker`] hosting the engine.
///
/// Same Send/Sync bridge shape as `BrowserWebTransportFace`: two channels +
/// one pump task that owns the `!Send` `MessagePort`. Drop closes the outbound
/// channel, the pump exits, the port is GC'd.
pub struct SharedWorkerProxyFace {
    id: FaceId,
    worker_url: String,
    tx_out: mpsc::Sender<Bytes>,
    rx_in: Mutex<mpsc::Receiver<Bytes>>,
}

impl SharedWorkerProxyFace {
    /// Open or join the per-origin `SharedWorker` at `url` and wire its
    /// [`MessagePort`] into a `Face`. Same-origin tabs that pass the same
    /// `(url, name)` pair land on the same worker instance.
    pub fn connect(
        id: FaceId,
        url: &str,
        name: Option<&str>,
        runtime: Arc<dyn Runtime>,
    ) -> Result<Self, SharedWorkerFaceError> {
        let worker = match name {
            Some(n) => SharedWorker::new_with_str(url, n),
            None => SharedWorker::new(url),
        }
        .map_err(|e| SharedWorkerFaceError::Construct(format!("{e:?}")))?;

        let port = worker.port();
        // Do NOT call port.start() here — setting onmessage in the pump
        // implicitly starts it. Calling start() before onmessage exists
        // dispatches queued messages with no listener, which the HTML spec
        // silently drops.
        Self::from_port(id, url.to_string(), port, runtime)
    }

    /// Wire an arbitrary [`MessagePort`] into a [`Face`] (for tests that
    /// hand-roll a `MessageChannel` instead of a real `SharedWorker`).
    pub fn from_port(
        id: FaceId,
        worker_url: String,
        port: MessagePort,
        runtime: Arc<dyn Runtime>,
    ) -> Result<Self, SharedWorkerFaceError> {
        let (tx_out, rx_out) = mpsc::channel::<Bytes>(64);
        let (tx_in, rx_in) = mpsc::channel::<Bytes>(64);

        runtime.spawn(Box::pin(pump(port, rx_out, tx_in)));

        Ok(Self {
            id,
            worker_url,
            tx_out,
            rx_in: Mutex::new(rx_in),
        })
    }
}

impl Transport for SharedWorkerProxyFace {
    fn id(&self) -> FaceId {
        self.id
    }

    fn kind(&self) -> FaceKind {
        // Same-origin, same-host local IPC; `App` is the closest FaceKind
        // (Local scope + backpressure congestion policy).
        FaceKind::App
    }

    fn remote_uri(&self) -> Option<String> {
        Some(format!("shared-worker://{}", self.worker_url))
    }

    async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
        let mut rx = self.rx_in.lock().await;
        rx.recv().await.ok_or(FaceError::Closed)
    }

    async fn send_bytes(&self, pkt: Bytes) -> Result<(), FaceError> {
        self.tx_out.send(pkt).await.map_err(|_| FaceError::Closed)
    }
}

async fn pump(port: MessagePort, mut rx_out: mpsc::Receiver<Bytes>, tx_in: mpsc::Sender<Bytes>) {
    let _on_message = install_onmessage(&port, tx_in);

    while let Some(pkt) = rx_out.recv().await {
        let array = encode_outbound(&pkt);
        // Transfer the ArrayBuffer (zero-copy move across the port).
        let buffer: JsValue = array.buffer().into();
        let transfer = js_sys::Array::new();
        transfer.push(&buffer);
        if let Err(e) = port.post_message_with_transferable(&array.into(), &transfer) {
            warn!(target: "face.shared-worker", error=?e, "post_message failed; closing pump");
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
            warn!(target: "face.shared-worker", "ignored inbound message with non-buffer payload");
            return;
        };
        // Bounded try_send: a back-pressured engine drops the inbound, same
        // as a congested network face.
        let tx = tx.borrow();
        if let Err(e) = tx.try_send(bytes) {
            warn!(target: "face.shared-worker", error=?e, "inbound channel full; dropping");
        }
    }));
    port.set_onmessage(Some(cb.as_ref().unchecked_ref()));
    cb
}
