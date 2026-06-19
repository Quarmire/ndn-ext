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
