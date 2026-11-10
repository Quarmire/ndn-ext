//! The worker-side face for one tab's port, as a plain pair of channels.
//!
//! A pump task (wasm-only, in `worker.rs`) owns the `!Send` `MessagePort` and
//! moves packets between it and these channels. The face itself touches no JS,
//! so it compiles and is tested natively: what a worker does with a packet
//! depends on the face's trust, and that must be checkable without a browser.

use bytes::Bytes;
use tokio::sync::{Mutex, mpsc};

use ndn_transport::{FaceError, FaceId, FaceKind, FaceTrust, Transport};

/// A face backed by one tab→worker `MessagePort`. Mirror of
/// `SharedWorkerProxyFace` on the tab side.
///
/// Built the default way it is [`FaceTrust::Validated`]: a tab can bridge a
/// remote peer (a page relaying WebRTC or WebTransport bytes) and a port does
/// not say who is on the far side of the page, so the forwarder checks the
/// signature of Data it sends before caching or forwarding it. A worker none of
/// whose tabs bridges a remote peer can ask for [`FaceTrust::Program`] with
/// `WorkerListener::accept_program`.
pub struct WorkerPortFace {
    id: FaceId,
    trust: FaceTrust,
    tx_out: mpsc::Sender<Bytes>,
    rx_in: Mutex<mpsc::Receiver<Bytes>>,
}

impl WorkerPortFace {
    /// A validated face over `tx_out` (packets for the tab) and `rx_in`
    /// (packets from it).
    pub fn from_channels(
        id: FaceId,
        tx_out: mpsc::Sender<Bytes>,
        rx_in: mpsc::Receiver<Bytes>,
    ) -> Self {
        Self::with_trust(id, FaceTrust::Validated, tx_out, rx_in)
    }

    pub(crate) fn with_trust(
        id: FaceId,
        trust: FaceTrust,
        tx_out: mpsc::Sender<Bytes>,
        rx_in: mpsc::Receiver<Bytes>,
    ) -> Self {
        Self {
            id,
            trust,
            tx_out,
            rx_in: Mutex::new(rx_in),
        }
    }
}

impl Transport for WorkerPortFace {
    fn id(&self) -> FaceId {
        self.id
    }

    fn kind(&self) -> FaceKind {
        FaceKind::App
    }

    fn trust(&self) -> FaceTrust {
        self.trust
    }

    fn remote_uri(&self) -> Option<String> {
        Some(format!("shared-worker-port://tab/{}", self.id.0))
    }

    async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
        let mut rx = self.rx_in.lock().await;
        rx.recv().await.ok_or(FaceError::Closed)
    }

    async fn send_bytes(&self, pkt: Bytes) -> Result<(), FaceError> {
        self.tx_out.send(pkt).await.map_err(|_| FaceError::Closed)
    }
}
