//! Shared-memory NDN faces (desktop Unix) — unique to ndn-rs
//! among NDN implementations. A POSIX `shm_open` region carries a lock-free
//! SPSC ring per direction; named FIFOs drive the wakeup path.
//!
//! `ShmFace` is the engine side (register with `ForwarderEngine::add_face`);
//! `ShmHandle` is the application side.
//!
//! ```no_run
//! # use ndn_face_shm::{ShmFace, ShmHandle};
//! # use ndn_transport::FaceId;
//! let face = ShmFace::create(FaceId(5), "myapp").unwrap();
//! let handle = ShmHandle::connect("myapp").unwrap();
//! ```

#[cfg(unix)]
pub mod spsc;

/// Re-export of [`spsc::slot_size_for_mtu`] for callers that don't depend
/// on the `spsc` submodule directly.
#[cfg(unix)]
pub fn slot_size_for_mtu(mtu: usize) -> u32 {
    spsc::slot_size_for_mtu(mtu)
}

#[derive(Debug, thiserror::Error)]
pub enum ShmError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("SHM name contains an interior NUL byte")]
    InvalidName,
    #[error("SHM region has wrong magic number (stale or wrong name?)")]
    InvalidMagic,
    #[error("packet exceeds the SHM slot size")]
    PacketTooLarge,
    #[error("SHM face closed (peer died or cancelled)")]
    Closed,
}

#[cfg(unix)]
pub type ShmFace = spsc::SpscFace;

#[cfg(unix)]
pub type ShmHandle = spsc::SpscHandle;

/// Capability-scoped (fd-passed) control-socket handshake — the G11 "Option A"
/// path that replaces named SHM objects/FIFOs. [`mint_token`] mints the
/// one-time capability; the engine serves the face's fds with [`serve_fd_handoff`];
/// the client receives them with [`connect_fd_handoff`].
#[cfg(unix)]
pub use spsc::{
    ShmToken, connect_fd_handoff, control_socket_path, mint_token, serve_fd_handoff,
    serve_fd_handoff_loop,
};

/// Zero-copy large-buffer passing (G11 increment 3): a [`SharedBuffer`] holds a
/// large opaque payload in anonymous shared memory; [`send_fds`]/[`recv_fds`]
/// hand its fd between processes for in-place (no-copy) consumption.
#[cfg(unix)]
pub use spsc::{SharedBuffer, SharedBufferReader, recv_fds, send_fds};

/// Sealed streaming ring (kernel-enforced single-writer): the producer writes the
/// data region and consumers map it read-only, so a consumer cannot forge a frame.
/// The "local surface" substrate — integrity + origin without a per-frame signature.
#[cfg(unix)]
pub use spsc::{SealedReader, SealedWriter, connect_sealed_handoff, serve_sealed_handoff};
