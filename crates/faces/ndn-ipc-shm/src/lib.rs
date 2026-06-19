//! SHM data plane for [`ndn-ipc`](ndn_ipc)'s `ForwarderClient`.
//!
//! Extension crate (non-standard): keeps the shared-memory ring face out of the
//! spec `ndn-ipc` crate so the two can live in independent repos. `ndn-ipc`
//! exposes the [`DataPlane`]/[`DataPlaneFactory`] seam and ships only the
//! Unix-socket data plane; this crate plugs the fast SHM ring in behind it.
//!
//! Call [`install`] once at process start. Thereafter the standard
//! `ForwarderClient::connect`/`connect_with_mtu`/`connect_with_name` paths
//! attach an SHM ring when the router can create one, falling back to the Unix
//! socket otherwise. With `install` never called, every client stays Unix-only.
//!
//! The platform constraint lives here: SHM is only attempted on Unix, non-mobile
//! targets. On other targets [`install`] still registers, but `SpscHandle::connect`
//! fails and the client falls back to Unix — so callers need no `cfg`.

use async_trait::async_trait;
use bytes::Bytes;
use tokio_util::sync::CancellationToken;

use ndn_face_shm::spsc::SpscHandle;
use ndn_ipc::forwarder_client::{
    DataPlane, DataPlaneFactory, ForwarderError, register_data_plane_factory,
};
use ndn_ipc::mgmt_client::MgmtClient;

/// Install the SHM data-plane factory process-wide. Idempotent: the first call
/// wins and returns `true`; later calls return `false` and are ignored.
pub fn install() -> bool {
    register_data_plane_factory(Box::new(ShmFactory))
}

/// Creates the router-side `shm://` face and connects an [`SpscHandle`] to it.
struct ShmFactory;

#[async_trait]
impl DataPlaneFactory for ShmFactory {
    async fn connect(
        &self,
        mgmt: &MgmtClient,
        name: &str,
        mtu: Option<usize>,
        cancel: CancellationToken,
    ) -> Result<Box<dyn DataPlane>, ForwarderError> {
        let resp = mgmt
            .face_create_with_mtu(&format!("shm://{name}"), mtu.map(|m| m as u64))
            .await?;
        let face_id = resp.face_id.ok_or(ForwarderError::MalformedResponse)?;

        let mut handle =
            SpscHandle::connect(name).map_err(|e| ForwarderError::DataPlane(e.to_string()))?;
        handle.set_cancel(cancel);

        Ok(Box::new(ShmDataPlane { handle, face_id }))
    }
}

/// The SHM ring as a [`DataPlane`]. No NDNLP framing — the engine frames on the
/// far side of the ring.
struct ShmDataPlane {
    handle: SpscHandle,
    face_id: u64,
}

#[async_trait]
impl DataPlane for ShmDataPlane {
    async fn send(&self, pkt: Bytes) -> Result<(), ForwarderError> {
        self.handle
            .send_bytes(pkt)
            .await
            .map_err(|e| ForwarderError::DataPlane(e.to_string()))
    }

    async fn send_batch(&self, pkts: &[Bytes]) -> Result<(), ForwarderError> {
        // Single atomic tail advance + one wakeup for the whole batch.
        self.handle
            .send_batch(pkts)
            .await
            .map_err(|e| ForwarderError::DataPlane(e.to_string()))
    }

    async fn recv(&self) -> Option<Bytes> {
        self.handle.recv_bytes().await
    }

    fn face_id(&self) -> u64 {
        self.face_id
    }
}
