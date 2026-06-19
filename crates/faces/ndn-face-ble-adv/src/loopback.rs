//! A hardware-free advertising medium: every endpoint's broadcast is heard by
//! every *other* endpoint on the same bus, with a configurable observed RSSI.
//! Models the shared-medium, half-duplex (no self-hearing), fire-and-forget
//! semantics of BLE advertising — enough to exercise the face, NDNLPv2
//! fragmentation/reassembly, and RSSI plumbing through a real engine without a
//! radio.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use ndn_transport::FaceError;
use tokio::sync::{Mutex, broadcast};

use crate::{AdvBackend, ScannedFrame};

#[derive(Clone)]
struct Advert {
    sender: u64,
    addr: [u8; 6],
    frame: Bytes,
}

/// A shared advertising medium. Clone-free; hand out [`LoopbackEndpoint`]s with
/// [`endpoint`](Self::endpoint).
pub struct LoopbackAdvBus {
    tx: broadcast::Sender<Arc<Advert>>,
}

impl LoopbackAdvBus {
    pub fn new() -> Self {
        let (tx, _rx) = broadcast::channel(1024);
        Self { tx }
    }

    /// Attach an endpoint identified by `node_id` (used to suppress
    /// self-hearing), advertising from `addr`, and observing `observed_rssi_dbm`
    /// on every frame it receives.
    pub fn endpoint(&self, node_id: u64, addr: [u8; 6], observed_rssi_dbm: i8) -> LoopbackEndpoint {
        LoopbackEndpoint {
            node_id,
            addr,
            observed_rssi_dbm,
            tx: self.tx.clone(),
            rx: Mutex::new(self.tx.subscribe()),
        }
    }
}

impl Default for LoopbackAdvBus {
    fn default() -> Self {
        Self::new()
    }
}

/// One node on a [`LoopbackAdvBus`]. Implements [`AdvBackend`].
pub struct LoopbackEndpoint {
    node_id: u64,
    addr: [u8; 6],
    observed_rssi_dbm: i8,
    tx: broadcast::Sender<Arc<Advert>>,
    rx: Mutex<broadcast::Receiver<Arc<Advert>>>,
}

#[async_trait]
impl AdvBackend for LoopbackEndpoint {
    async fn broadcast(&self, frame: Bytes) -> Result<(), FaceError> {
        // No subscribers is not an error on a broadcast medium (nobody is
        // listening — the advert is simply lost, like real advertising).
        let _ = self.tx.send(Arc::new(Advert {
            sender: self.node_id,
            addr: self.addr,
            frame,
        }));
        Ok(())
    }

    async fn next_scanned(&self) -> Result<ScannedFrame, FaceError> {
        let mut rx = self.rx.lock().await;
        loop {
            match rx.recv().await {
                Ok(advert) if advert.sender != self.node_id => {
                    return Ok(ScannedFrame {
                        frame: advert.frame.clone(),
                        addr: Some(advert.addr),
                        rssi_dbm: Some(self.observed_rssi_dbm),
                    });
                }
                // Own transmission — a radio does not hear itself.
                Ok(_) => continue,
                // Slow consumer dropped frames; keep going (lossy medium).
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return Err(FaceError::Closed),
            }
        }
    }
}
