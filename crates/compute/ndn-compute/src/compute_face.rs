use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::{Mutex, mpsc};
use tracing::warn;

use ndn_packet::Interest;
use ndn_transport::{FaceError, FaceId, FaceKind, FaceTrust, Transport};

use crate::ComputeRegistry;

/// Synthetic face that dispatches Interests to [`ComputeRegistry`] handlers
/// and surfaces the resulting Data through [`Transport::recv_bytes`]. Wire
/// FIB routes to its [`FaceId`] to direct Interests here.
pub struct ComputeFace {
    id: FaceId,
    registry: Arc<ComputeRegistry>,
    tx: mpsc::Sender<Bytes>,
    rx: Mutex<mpsc::Receiver<Bytes>>,
}

impl ComputeFace {
    pub fn new(id: FaceId, registry: Arc<ComputeRegistry>) -> Self {
        Self::with_capacity(id, registry, 64)
    }

    pub fn with_capacity(id: FaceId, registry: Arc<ComputeRegistry>, capacity: usize) -> Self {
        let (tx, rx) = mpsc::channel(capacity);
        Self {
            id,
            registry,
            tx,
            rx: Mutex::new(rx),
        }
    }
}

impl Transport for ComputeFace {
    fn id(&self) -> FaceId {
        self.id
    }

    fn kind(&self) -> FaceKind {
        FaceKind::Compute
    }

    /// The handlers behind a compute face are programs of this process.
    fn trust(&self) -> FaceTrust {
        FaceTrust::Program
    }

    /// `send_bytes` decodes an Interest and drops anything else, so a side frame
    /// would be reported as sent and discarded. Refused instead.
    async fn send_side(
        &self,
        _frame: Bytes,
        _class: ndn_transport::SideClass,
    ) -> Result<(), ndn_transport::SideRefused> {
        Err(ndn_transport::SideRefused::NotCarried)
    }

    fn side_frame_max(&self) -> usize {
        0
    }

    async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
        self.rx.lock().await.recv().await.ok_or(FaceError::Closed)
    }

    async fn send_bytes(&self, pkt: Bytes) -> Result<(), FaceError> {
        let interest = match Interest::decode(pkt) {
            Ok(i) => i,
            Err(e) => {
                warn!("ComputeFace: failed to decode Interest: {e}");
                return Ok(());
            }
        };

        let registry = Arc::clone(&self.registry);
        let tx = self.tx.clone();

        tokio::spawn(async move {
            match registry.dispatch(&interest).await {
                Some(Ok(data)) => {
                    let wire = data.raw().clone();
                    if tx.send(wire).await.is_err() {
                        warn!(
                            "ComputeFace: pipeline receiver dropped before Data could be injected"
                        );
                    }
                }
                Some(Err(e)) => {
                    warn!("ComputeFace: handler error for {:?}: {e}", interest.name);
                }
                None => {
                    warn!("ComputeFace: no handler registered for {:?}", interest.name);
                }
            }
        });

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_transport::{SIDE_MARKER, SideClass, SideRefused};

    #[tokio::test]
    async fn a_compute_face_carries_no_side_frame() {
        let face = ComputeFace::new(FaceId(4), Arc::new(ComputeRegistry::new()));
        let frame = Bytes::from_static(&[SIDE_MARKER, 0x20, 1, 2]);
        for class in [SideClass::Datagram, SideClass::Stream] {
            assert_eq!(
                face.send_side(frame.clone(), class).await,
                Err(SideRefused::NotCarried)
            );
        }
        assert_eq!(face.side_frame_max(), 0);
    }
}
