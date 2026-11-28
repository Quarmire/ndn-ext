//! Custom SPSC shared-memory face (Unix, `spsc-shm` feature). One named
//! POSIX SHM region holds two lock-free SPSC ring buffers; named FIFOs
//! integrated with Tokio's epoll/kqueue drive wakeup.
//!
//! Layout:
//!
//! ```text
//! Cache line 0 (off   0–63):  magic u64 | capacity u32 | slot_size u32 | pad
//! Cache line 1 (off  64–127): a2e_tail AtomicU32   app writes, engine reads
//! Cache line 2 (off 128–191): a2e_head AtomicU32   engine writes, app reads
//! Cache line 3 (off 192–255): e2a_tail AtomicU32   engine writes, app reads
//! Cache line 4 (off 256–319): e2a_head AtomicU32   app writes, engine reads
//! Cache line 5 (off 320–383): a2e_parked AtomicU32 engine sets before sleeping on a2e
//! Cache line 6 (off 384–447): e2a_parked AtomicU32 app sets before sleeping on e2a
//! Data block (off 448–N):     a2e ring (capacity × slot_stride bytes)
//! Data block (off N–end):     e2a ring (capacity × slot_stride bytes)
//!   slot_stride = 4 (length prefix) + slot_size (payload area)
//! ```
//!
//! Wakeup protocol: producer loads `parked` with `SeqCst` after the ring
//! push; consumer stores `parked` with `SeqCst` before its second ring
//! check. The total order prevents the producer from missing a sleeping
//! consumer.
use portable_atomic::AtomicU64;
use std::ffi::CString;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use bytes::Bytes;

use ndn_transport::{FaceError, FaceId, FaceKind, FaceTrust, SideClass, SideRefused, Transport};

use crate::ShmError;

const MAGIC: u64 = 0x4E44_4E5F_5348_4D00; // b"NDN_SHM\0"

/// Default slots per ring (~4.4 MiB per face with the default slot size).
pub const DEFAULT_CAPACITY: u32 = 256;

/// Default slot payload size (~8.75 KiB); larger segments negotiate via
/// the `faces/create` `mtu` parameter.
pub const DEFAULT_SLOT_SIZE: u32 = 8960;

/// Target per-face SHM ring budget; capacity scales inversely with slot
/// size so large-slot faces don't blow up memory.
const SHM_BUDGET: usize = 2 * DEFAULT_CAPACITY as usize * slot_stride(DEFAULT_SLOT_SIZE);

/// NDN Data wire overhead above raw content (TLV headers + name + signature).
pub const SHM_SLOT_OVERHEAD: usize = 16 * 1024;

/// Slot size for Data packets with up to `mtu` content bytes, rounded up to
/// the next 64-byte cache line.
pub fn slot_size_for_mtu(mtu: usize) -> u32 {
    let raw = mtu.saturating_add(SHM_SLOT_OVERHEAD);
    let aligned = raw.div_ceil(64) * 64;
    aligned.min(u32::MAX as usize) as u32
}

/// Ring capacity that keeps total ring memory within `SHM_BUDGET`;
/// returns at least 16.
pub fn capacity_for_slot(slot_size: u32) -> u32 {
    let stride = slot_stride(slot_size);
    let cap = SHM_BUDGET / (2 * stride);
    (cap as u32).max(16)
}

const OFF_A2E_TAIL: usize = 64;
const OFF_A2E_HEAD: usize = 128;
const OFF_E2A_TAIL: usize = 192;
const OFF_E2A_HEAD: usize = 256;
const OFF_A2E_PARKED: usize = 320;
const OFF_E2A_PARKED: usize = 384;
const HEADER_SIZE: usize = 448;

const fn slot_stride(slot_size: u32) -> usize {
    4 + slot_size as usize
}

/// Iterations of `spin_loop` before falling through to the pipe wakeup
/// path (~sub-µs on modern hardware).
const SPIN_ITERS: u32 = 64;

/// A ring that is never empty yields to the runtime once in this many packets handed
/// out ([`SpscFace::recv_bytes`]): the reader loop that calls it awaits nothing else, so
/// without this a peer that keeps the ring full holds a worker thread.
const POPS_PER_YIELD: u32 = 32;

fn shm_total_size(capacity: u32, slot_size: u32) -> usize {
    HEADER_SIZE + 2 * capacity as usize * slot_stride(slot_size)
}

/// Largest region geometry we'll map from a peer-declared header — a guard against
/// mapping gigabytes off a bogus or hostile header.
const MAX_REGION_SIZE: usize = 256 * 1024 * 1024;

/// Validate a header-declared ring geometry before it's used for any indexing or
/// mapping. A `capacity` of 0 is the dangerous one — every ring op computes
/// `index % capacity`, so a zero would SIGFPE; a 0 `slot_size` and an oversized
/// region are rejected for the same defensive reason the sealed paths already do.
/// The size is computed with checked arithmetic so a hostile geometry can't even
/// overflow the bounds check itself.
fn validate_geometry(capacity: u32, slot_size: u32) -> Result<(), ShmError> {
    if capacity == 0 || slot_size == 0 {
        return Err(ShmError::InvalidGeometry);
    }
    let stride = 4usize.checked_add(slot_size as usize);
    let total = stride
        .and_then(|s| s.checked_mul(capacity as usize))
        .and_then(|s| s.checked_mul(2))
        .and_then(|s| s.checked_add(HEADER_SIZE));
    match total {
        Some(t) if t <= MAX_REGION_SIZE => Ok(()),
        _ => Err(ShmError::InvalidGeometry),
    }
}

fn a2e_ring_offset() -> usize {
    HEADER_SIZE
}
fn e2a_ring_offset(capacity: u32, slot_size: u32) -> usize {
    HEADER_SIZE + capacity as usize * slot_stride(slot_size)
}

fn posix_shm_name(name: &str) -> String {
    format!("/ndn-shm-{name}")
}

fn a2e_pipe_path(name: &str) -> PathBuf {
    PathBuf::from(format!("/tmp/.ndn-{name}.a2e.pipe"))
}

fn e2a_pipe_path(name: &str) -> PathBuf {
    PathBuf::from(format!("/tmp/.ndn-{name}.e2a.pipe"))
}

/// Check that the region behind `fd`, handed over by a peer, is sealed against what the
/// peer must not do to it (see [`ShmRegion::from_fd_sealed`]): shrinking or growing it
/// always; writing it too when `writable` is false. A no-op where there are no seals
/// (not Linux).
#[cfg(target_os = "linux")]
fn check_peer_seals(fd: RawFd, writable: bool) -> Result<(), ShmError> {
    let mut need = libc::F_SEAL_SHRINK | libc::F_SEAL_GROW;
    if !writable {
        need |= libc::F_SEAL_FUTURE_WRITE;
    }
    let have = unsafe { libc::fcntl(fd, libc::F_GET_SEALS) };
    if have == -1 {
        let e = std::io::Error::last_os_error();
        return Err(ShmError::Io(std::io::Error::new(
            e.kind(),
            format!(
                "the shared-memory region a peer handed over cannot be checked for seals ({e}): \
                 it is not a sealed memfd, so the peer could resize it under this process; \
                 refuse it and attach to a ring whose owner creates sealed regions"
            ),
        )));
    }
    let missing = need & !have;
    if missing != 0 {
        let mut what = Vec::new();
        if missing & libc::F_SEAL_SHRINK != 0 {
            what.push("shrinking (the peer could make this process fault with SIGBUS)");
        }
        if missing & libc::F_SEAL_GROW != 0 {
            what.push("growing");
        }
        if missing & libc::F_SEAL_FUTURE_WRITE != 0 {
            what.push("writing (any process with the object could forge what readers see)");
        }
        return Err(ShmError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "the shared-memory region a peer handed over is not sealed against {}: refuse it, \
                 and ask the ring's owner to create its regions with this crate (sealed memfds)",
                what.join(", ")
            ),
        )));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn check_peer_seals(_fd: RawFd, _writable: bool) -> Result<(), ShmError> {
    Ok(())
}

/// Verify the object behind `fd` is at least `size` bytes before it's mapped — a
/// region truncated below its declared geometry would SIGBUS on first access to the
/// short pages. `fstat` is cheap and runs once at open/handoff time.
fn fstat_at_least(fd: RawFd, size: usize) -> Result<(), ShmError> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } == -1 {
        return Err(ShmError::Io(std::io::Error::last_os_error()));
    }
    if (st.st_size as u64) < size as u64 {
        return Err(ShmError::InvalidGeometry);
    }
    Ok(())
}

/// Owns a POSIX SHM mapping; the creator unlinks the name on drop.
struct ShmRegion {
    ptr: *mut u8,
    size: usize,
    shm_name: Option<CString>,
}

unsafe impl Send for ShmRegion {}
unsafe impl Sync for ShmRegion {}

impl ShmRegion {
    fn create(shm_name: &str, size: usize) -> Result<Self, ShmError> {
        let cname = CString::new(shm_name).map_err(|_| ShmError::InvalidName)?;
        // Clear any region left behind by a previous run of *ours* (same uid), then
        // create exclusively. With O_EXCL we are guaranteed to be the creator, so the
        // 0o600 mode below is the region's real mode — a squatter who pre-created the
        // name (esp. a different uid we can't unlink) makes shm_open fail with EEXIST
        // rather than us silently adopting their region (and their permissions).
        unsafe { libc::shm_unlink(cname.as_ptr()) };
        let ptr = unsafe {
            let fd = libc::shm_open(
                cname.as_ptr(),
                libc::O_CREAT | libc::O_EXCL | libc::O_RDWR,
                // 0o600 (owner-only): at 0o666 any local user can attach, read every
                // frame, and inject forged ones into the ring. Owner-only matches the
                // 0o600 wakeup FIFOs (which already gate this named path to a single
                // uid). Cross-uid sharing (e.g. a root router ↔ an unprivileged app)
                // must go through the capability fd-handoff or sealed path, where
                // access is gated by a token rather than filesystem perms.
                0o600 as libc::mode_t as libc::c_uint,
            );
            if fd == -1 {
                return Err(ShmError::Io(std::io::Error::last_os_error()));
            }

            if libc::ftruncate(fd, size as libc::off_t) == -1 {
                libc::close(fd);
                return Err(ShmError::Io(std::io::Error::last_os_error()));
            }

            let p = libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            );
            libc::close(fd);
            if p == libc::MAP_FAILED {
                return Err(ShmError::Io(std::io::Error::last_os_error()));
            }
            p as *mut u8
        };
        Ok(ShmRegion {
            ptr,
            size,
            shm_name: Some(cname),
        })
    }

    fn open(shm_name: &str, size: usize) -> Result<Self, ShmError> {
        let cname = CString::new(shm_name).map_err(|_| ShmError::InvalidName)?;
        let ptr = unsafe {
            let fd = libc::shm_open(cname.as_ptr(), libc::O_RDWR, 0);
            if fd == -1 {
                return Err(ShmError::Io(std::io::Error::last_os_error()));
            }

            // The object's real size must cover the mapping we're about to make:
            // mapping past the end and then touching those pages is a SIGBUS, so a
            // region truncated below its header-declared geometry must be rejected,
            // not mapped.
            if let Err(e) = fstat_at_least(fd, size) {
                libc::close(fd);
                return Err(e);
            }

            let p = libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            );
            libc::close(fd);
            if p == libc::MAP_FAILED {
                return Err(ShmError::Io(std::io::Error::last_os_error()));
            }
            p as *mut u8
        };
        Ok(ShmRegion {
            ptr,
            size,
            shm_name: None,
        })
    }

    /// Create an **anonymous**, capability-scoped SHM region. The fd is handed to
    /// the peer out-of-band ([`send_fds`]); the region never appears in a shared
    /// namespace.
    ///
    /// **Linux:** a `memfd` sealed against `F_SEAL_SHRINK | F_SEAL_GROW` (and
    /// `F_SEAL_SEAL`, so no peer can add a seal that would stop another peer mapping
    /// it). Every holder of the fd may write the *contents* — that is what the
    /// region is for — but none can truncate it, so no peer can make a mapping of it
    /// fault (`SIGBUS`) in another process. The seals are applied after the region
    /// is sized and mapped.
    ///
    /// **Other Unix (macOS):** there is no `memfd`, so the region is a `shm_open`
    /// object at `0o600`, unlinked at once; its fd **can** be `ftruncate`d by
    /// whoever holds it. There the "a peer cannot shrink the region" guarantee
    /// does not hold: only the same-uid, token-gated peers that are handed the fd
    /// can do it.
    fn create_anon(size: usize) -> Result<(Self, OwnedFd), ShmError> {
        #[cfg(target_os = "linux")]
        {
            Self::create_sealed_memfd(size, false)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Self::create_anon_posix(size)
        }
    }

    /// A `memfd` of `size` bytes, mapped read-write here, then sealed against
    /// resizing; with `peers_read_only` also against any later write through the fd
    /// (`F_SEAL_FUTURE_WRITE`), which leaves **this** process's existing writable
    /// mapping working and refuses every other writable mapping and `write(2)`,
    /// whatever descriptor it comes through — a `/proc/self/fd/N` reopen with
    /// `O_RDWR` included, which is what a plain `O_RDONLY` fd does not stop for a
    /// same-uid peer.
    #[cfg(target_os = "linux")]
    fn create_sealed_memfd(
        size: usize,
        peers_read_only: bool,
    ) -> Result<(Self, OwnedFd), ShmError> {
        let fd = unsafe {
            libc::memfd_create(
                c"ndn-shm".as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
            )
        };
        if fd == -1 {
            let e = std::io::Error::last_os_error();
            return Err(ShmError::Io(std::io::Error::new(
                e.kind(),
                format!(
                    "memfd_create failed ({e}): a shared-memory ring needs sealed memfd regions \
                     (Linux 3.17, 5.1 for write seals); run on a kernel that has them, or allow \
                     memfd_create in this process's seccomp filter"
                ),
            )));
        }
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        if unsafe { libc::ftruncate(fd, size as libc::off_t) } == -1 {
            return Err(ShmError::Io(std::io::Error::last_os_error()));
        }
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            return Err(ShmError::Io(std::io::Error::last_os_error()));
        }
        // Owned from here: a failed seal unmaps.
        let region = ShmRegion {
            ptr: p as *mut u8,
            size,
            shm_name: None,
        };
        let mut seals = libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_SEAL;
        if peers_read_only {
            seals |= libc::F_SEAL_FUTURE_WRITE;
        }
        if unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) } == -1 {
            let e = std::io::Error::last_os_error();
            return Err(ShmError::Io(std::io::Error::new(
                e.kind(),
                format!(
                    "sealing a shared-memory region failed ({e}): the ring needs F_SEAL_SHRINK, \
                     F_SEAL_GROW and F_SEAL_FUTURE_WRITE (Linux 5.1)"
                ),
            )));
        }
        Ok((region, owned))
    }

    /// The portable stand-in for the sealed `memfd` (see [`create_anon`](Self::create_anon)):
    /// `shm_open` a high-entropy `O_EXCL` name at `0o600`, map it, then `shm_unlink` the
    /// name *immediately* so the region survives only through the returned fd. The
    /// `O_EXCL` retry loop defeats name pre-creation, the immediate unlink and `0o600`
    /// close the `/dev/shm` listing leak the named-region path has. The fd can be
    /// resized by its holders.
    #[cfg(not(target_os = "linux"))]
    fn create_anon_posix(size: usize) -> Result<(Self, OwnedFd), ShmError> {
        static ANON_CTR: AtomicU64 = AtomicU64::new(0);
        let pid = unsafe { libc::getpid() };
        for _ in 0..64 {
            let n = ANON_CTR.fetch_add(1, Ordering::Relaxed);
            let name = format!("/ndnshm-{pid}-{n}");
            let cname = CString::new(name).map_err(|_| ShmError::InvalidName)?;
            let fd = unsafe {
                libc::shm_open(
                    cname.as_ptr(),
                    libc::O_CREAT | libc::O_EXCL | libc::O_RDWR,
                    0o600 as libc::mode_t as libc::c_uint,
                )
            };
            if fd == -1 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EEXIST) {
                    continue; // name collision (or squatting) — pick another
                }
                return Err(ShmError::Io(err));
            }
            // Unlink the name now: the region lives on via `fd` + our mapping.
            unsafe { libc::shm_unlink(cname.as_ptr()) };
            let owned = unsafe { OwnedFd::from_raw_fd(fd) };
            let ptr = unsafe {
                if libc::ftruncate(fd, size as libc::off_t) == -1 {
                    return Err(ShmError::Io(std::io::Error::last_os_error()));
                }
                let p = libc::mmap(
                    std::ptr::null_mut(),
                    size,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    fd,
                    0,
                );
                if p == libc::MAP_FAILED {
                    return Err(ShmError::Io(std::io::Error::last_os_error()));
                }
                p as *mut u8
            };
            return Ok((
                ShmRegion {
                    ptr,
                    size,
                    shm_name: None, // already unlinked — nothing to clean on drop
                },
                owned,
            ));
        }
        Err(ShmError::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not allocate an anonymous SHM name after 64 tries",
        )))
    }

    /// Map a region received as an fd (via [`recv_fds`]). The caller owns `fd`'s
    /// lifetime; this only mmaps it (and `munmap`s on drop). No name is involved,
    /// so nothing is unlinked on drop.
    fn from_fd(fd: RawFd, size: usize) -> Result<Self, ShmError> {
        fstat_at_least(fd, size)?;
        let ptr = unsafe {
            let p = libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            );
            if p == libc::MAP_FAILED {
                return Err(ShmError::Io(std::io::Error::last_os_error()));
            }
            p as *mut u8
        };
        Ok(ShmRegion {
            ptr,
            size,
            shm_name: None,
        })
    }

    /// Create an anonymous region the **producer maps read-write** while consumers
    /// can only ever read it: the only writable access is the producer's own mapping
    /// (which is never transmittable), so no other process — not a consumer, not a
    /// third party who obtains the fd — can write the region. This is the
    /// kernel-enforced single-writer foundation: integrity + origin without a
    /// per-frame signature, because forgery is *impossible*, not merely *trusted*.
    ///
    /// **Linux:** a `memfd` sealed with `F_SEAL_FUTURE_WRITE | F_SEAL_SHRINK |
    /// F_SEAL_GROW | F_SEAL_SEAL` after the producer mapped it. The seal is on the
    /// object, not on the descriptor, so it holds against a peer of the **same uid**
    /// too: reopening `/proc/self/fd/N` (or `/proc/<pid>/fd/N`) with `O_RDWR`, then
    /// `mmap(PROT_WRITE)`, `write(2)` or `ftruncate`, all fail with `EPERM`.
    ///
    /// **Other Unix (macOS):** the object is `shm_open`ed `0o600`, a second `O_RDONLY`
    /// fd is what consumers get, the name is unlinked and the writable fd closed.
    /// A consumer cannot map it writable through that fd, but nothing stops a process
    /// of the **same uid** that can reach the object some other way from reopening
    /// it read-write: there the guarantee is across uids only.
    fn create_anon_ro(size: usize) -> Result<(Self, OwnedFd), ShmError> {
        #[cfg(target_os = "linux")]
        {
            Self::create_sealed_memfd(size, true)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Self::create_anon_ro_posix(size)
        }
    }

    /// See [`create_anon_ro`](Self::create_anon_ro): open the object `O_RDWR`, open a
    /// *second* `O_RDONLY` fd to it, `shm_unlink` the name, map the RW fd, then close it
    /// (the mapping stays writable). The returned `OwnedFd` is read-only — `SCM_RIGHTS`
    /// preserves the `O_RDONLY` mode, and `mmap(PROT_WRITE)` on it is refused.
    #[cfg(not(target_os = "linux"))]
    fn create_anon_ro_posix(size: usize) -> Result<(Self, OwnedFd), ShmError> {
        static ANON_RO_CTR: AtomicU64 = AtomicU64::new(0);
        let pid = unsafe { libc::getpid() };
        for _ in 0..64 {
            let n = ANON_RO_CTR.fetch_add(1, Ordering::Relaxed);
            let name = format!("/ndnshmro-{pid}-{n}");
            let cname = CString::new(name).map_err(|_| ShmError::InvalidName)?;
            let rw_fd = unsafe {
                libc::shm_open(
                    cname.as_ptr(),
                    libc::O_CREAT | libc::O_EXCL | libc::O_RDWR,
                    0o600 as libc::mode_t as libc::c_uint,
                )
            };
            if rw_fd == -1 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EEXIST) {
                    continue;
                }
                return Err(ShmError::Io(err));
            }
            let owned_rw = unsafe { OwnedFd::from_raw_fd(rw_fd) };
            // A read-only fd to the same object, opened while the name still exists.
            let ro_fd = unsafe { libc::shm_open(cname.as_ptr(), libc::O_RDONLY, 0) };
            // Unlink now: the object lives on via the open fds / mapping.
            unsafe { libc::shm_unlink(cname.as_ptr()) };
            if ro_fd == -1 {
                return Err(ShmError::Io(std::io::Error::last_os_error()));
            }
            let ro_owned = unsafe { OwnedFd::from_raw_fd(ro_fd) };
            let ptr = unsafe {
                if libc::ftruncate(owned_rw.as_raw_fd(), size as libc::off_t) == -1 {
                    return Err(ShmError::Io(std::io::Error::last_os_error()));
                }
                let p = libc::mmap(
                    std::ptr::null_mut(),
                    size,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    owned_rw.as_raw_fd(),
                    0,
                );
                if p == libc::MAP_FAILED {
                    return Err(ShmError::Io(std::io::Error::last_os_error()));
                }
                p as *mut u8
            };
            // Drop the RW fd: the writable mapping persists, but no writable fd
            // exists anymore to transmit or re-map.
            drop(owned_rw);
            return Ok((
                ShmRegion {
                    ptr,
                    size,
                    shm_name: None,
                },
                ro_owned,
            ));
        }
        Err(ShmError::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not allocate an anonymous SHM name after 64 tries",
        )))
    }

    /// Map a received fd **read-only** (`PROT_READ`). Pairs with the read-only fd
    /// from [`create_anon_ro`](Self::create_anon_ro): a consumer can read in place
    /// but the kernel refuses any writable mapping of this fd.
    fn from_fd_ro(fd: RawFd, size: usize) -> Result<Self, ShmError> {
        fstat_at_least(fd, size)?;
        let ptr = unsafe {
            let p = libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ,
                libc::MAP_SHARED,
                fd,
                0,
            );
            if p == libc::MAP_FAILED {
                return Err(ShmError::Io(std::io::Error::last_os_error()));
            }
            p as *mut u8
        };
        Ok(ShmRegion {
            ptr,
            size,
            shm_name: None,
        })
    }

    /// Map a region **a peer handed over** as the fd of a ring: first check, on Linux,
    /// that the object is sealed so the peer cannot change it under this mapping, then
    /// map it. `writable`: a region this process writes (the peer may write it
    /// too, so it must at least be unshrinkable); otherwise a region only the peer
    /// writes, which must also be sealed against any further write, and is mapped
    /// read-only. A region that is not sealed is refused, with the reason: a peer
    /// that can still `ftruncate` it can make this process fault (`SIGBUS`) on any
    /// access, and a peer that can still write a region meant to be read-only can
    /// forge what its readers see.
    ///
    /// Not Linux: there are no seals; this is [`from_fd`](Self::from_fd) or
    /// [`from_fd_ro`](Self::from_fd_ro).
    fn from_fd_sealed(fd: RawFd, size: usize, writable: bool) -> Result<Self, ShmError> {
        check_peer_seals(fd, writable)?;
        if writable {
            Self::from_fd(fd, size)
        } else {
            Self::from_fd_ro(fd, size)
        }
    }

    fn as_ptr(&self) -> *mut u8 {
        self.ptr
    }

    /// # Safety
    /// Must be called exactly once immediately after `create()`, before any
    /// other process opens the region.
    unsafe fn write_header(&self, capacity: u32, slot_size: u32) {
        unsafe {
            (self.ptr as *mut u64).write_unaligned(MAGIC);
            (self.ptr.add(8) as *mut u32).write_unaligned(capacity);
            (self.ptr.add(12) as *mut u32).write_unaligned(slot_size);
        }
    }

    /// # Safety
    /// The region must have been initialised by `write_header`.
    unsafe fn read_header(&self) -> Result<(u32, u32), ShmError> {
        unsafe {
            let magic = (self.ptr as *const u64).read_unaligned();
            if magic != MAGIC {
                return Err(ShmError::InvalidMagic);
            }
            let capacity = (self.ptr.add(8) as *const u32).read_unaligned();
            let slot_size = (self.ptr.add(12) as *const u32).read_unaligned();
            Ok((capacity, slot_size))
        }
    }
}

impl Drop for ShmRegion {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ptr as *mut libc::c_void, self.size);
            if let Some(ref n) = self.shm_name {
                libc::shm_unlink(n.as_ptr());
            }
        }
    }
}

/// Returns `false` if the ring is full.
///
/// # Safety
/// `base` must be a valid SHM mapping; `data.len() <= slot_size`.
unsafe fn ring_push(
    base: *mut u8,
    ring_off: usize,
    tail_off: usize,
    head_off: usize,
    capacity: u32,
    slot_size: u32,
    data: &[u8],
) -> bool {
    debug_assert!(data.len() <= slot_size as usize);

    let tail_a = unsafe { AtomicU32::from_ptr(base.add(tail_off) as *mut u32) };
    let head_a = unsafe { AtomicU32::from_ptr(base.add(head_off) as *mut u32) };

    let t = tail_a.load(Ordering::Relaxed);
    let h = head_a.load(Ordering::Acquire);
    if t.wrapping_sub(h) >= capacity {
        return false;
    }

    let idx = (t % capacity) as usize;
    let slot = unsafe { base.add(ring_off + idx * slot_stride(slot_size)) };

    unsafe {
        (slot as *mut u32).write_unaligned(data.len() as u32);
        std::ptr::copy_nonoverlapping(data.as_ptr(), slot.add(4), data.len());
    }
    tail_a.store(t.wrapping_add(1), Ordering::Release);
    true
}

/// **Zero-copy produce:** reserve the next slot, write the `len` prefix, run
/// `fill` to write the payload **in place** (no `memcpy` from a source buffer —
/// the producer counterpart of [`ring_peek_consume`]), then advance tail.
/// Returns `false` (without calling `fill`) if the ring is full. `fill` receives
/// exactly `len` bytes of slot payload.
///
/// # Safety
/// Same as [`ring_push`]; `len <= slot_size`.
#[allow(clippy::too_many_arguments)] // positional ring params, like the other ring_* helpers
unsafe fn ring_reserve_commit(
    base: *mut u8,
    ring_off: usize,
    tail_off: usize,
    head_off: usize,
    capacity: u32,
    slot_size: u32,
    len: usize,
    fill: impl FnOnce(&mut [u8]),
) -> bool {
    debug_assert!(len <= slot_size as usize);
    let tail_a = unsafe { AtomicU32::from_ptr(base.add(tail_off) as *mut u32) };
    let head_a = unsafe { AtomicU32::from_ptr(base.add(head_off) as *mut u32) };

    let t = tail_a.load(Ordering::Relaxed);
    let h = head_a.load(Ordering::Acquire);
    if t.wrapping_sub(h) >= capacity {
        return false;
    }
    let idx = (t % capacity) as usize;
    let slot = unsafe { base.add(ring_off + idx * slot_stride(slot_size)) };
    unsafe {
        (slot as *mut u32).write_unaligned(len as u32);
        let payload = std::slice::from_raw_parts_mut(slot.add(4), len);
        fill(payload);
    }
    tail_a.store(t.wrapping_add(1), Ordering::Release);
    true
}

/// One Acquire load + one Release store per batch. Returns the number
/// pushed.
///
/// # Safety
/// Same as [`ring_push`]; every `pkt.len() <= slot_size`.
unsafe fn ring_push_batch(
    base: *mut u8,
    ring_off: usize,
    tail_off: usize,
    head_off: usize,
    capacity: u32,
    slot_size: u32,
    pkts: &[&[u8]],
) -> usize {
    if pkts.is_empty() {
        return 0;
    }
    let tail_a = unsafe { AtomicU32::from_ptr(base.add(tail_off) as *mut u32) };
    let head_a = unsafe { AtomicU32::from_ptr(base.add(head_off) as *mut u32) };

    let mut t = tail_a.load(Ordering::Relaxed);
    let h = head_a.load(Ordering::Acquire);
    let free = capacity.wrapping_sub(t.wrapping_sub(h));
    let to_push = (free as usize).min(pkts.len());
    if to_push == 0 {
        return 0;
    }

    for pkt in &pkts[..to_push] {
        debug_assert!(pkt.len() <= slot_size as usize);
        let idx = (t % capacity) as usize;
        let slot = unsafe { base.add(ring_off + idx * slot_stride(slot_size)) };
        unsafe {
            (slot as *mut u32).write_unaligned(pkt.len() as u32);
            std::ptr::copy_nonoverlapping(pkt.as_ptr(), slot.add(4), pkt.len());
        }
        t = t.wrapping_add(1);
    }
    tail_a.store(t, Ordering::Release);
    to_push
}

/// A ring whose cursors say something no correct producer and consumer can have
/// written: more unread slots than the ring has. Either cursor lives in memory the
/// peer can write, so a peer that sets the tail (or the head) far off — `head + 2^31` —
/// would otherwise make the consumer pop garbage slots forever.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RingCorrupt {
    head: u32,
    tail: u32,
    capacity: u32,
}

impl std::fmt::Display for RingCorrupt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the ring's read cursor is {} and its write cursor {}: {} unread slots in a ring of \
             {}, which no correct peer writes — the peer corrupted the ring (or is hostile), so \
             the face is closed; restart the peer and let it reconnect",
            self.head,
            self.tail,
            self.tail.wrapping_sub(self.head),
            self.capacity,
        )
    }
}

/// The unread slots of a ring, or why the cursors cannot be believed: `h == t` is
/// empty, `t - h <= capacity` is a ring the producer has filled at most, anything else
/// is a cursor the peer wrote.
fn ring_unread(h: u32, t: u32, capacity: u32) -> Result<u32, RingCorrupt> {
    let n = t.wrapping_sub(h);
    if n > capacity {
        return Err(RingCorrupt {
            head: h,
            tail: t,
            capacity,
        });
    }
    Ok(n)
}

/// `Ok(None)` if empty; `Err` if the cursors are out of range (see [`RingCorrupt`]).
///
/// # Safety
/// Same as [`ring_push`].
unsafe fn ring_pop(
    base: *mut u8,
    ring_off: usize,
    tail_off: usize,
    head_off: usize,
    capacity: u32,
    slot_size: u32,
) -> Result<Option<Bytes>, RingCorrupt> {
    let tail_a = unsafe { AtomicU32::from_ptr(base.add(tail_off) as *mut u32) };
    let head_a = unsafe { AtomicU32::from_ptr(base.add(head_off) as *mut u32) };

    let h = head_a.load(Ordering::Relaxed);
    let t = tail_a.load(Ordering::Acquire);
    if ring_unread(h, t, capacity)? == 0 {
        return Ok(None);
    }

    let idx = (h % capacity) as usize;
    let slot = unsafe { base.add(ring_off + idx * slot_stride(slot_size)) };

    let len = unsafe { (slot as *const u32).read_unaligned() as usize };
    let len = len.min(slot_size as usize);
    let data = unsafe { Bytes::copy_from_slice(std::slice::from_raw_parts(slot.add(4), len)) };

    head_a.store(h.wrapping_add(1), Ordering::Release);
    Ok(Some(data))
}

/// **Zero-copy consume:** borrow the head slot's payload in place, run `f` on it,
/// then advance head — no intermediate `Bytes` allocation/`memcpy` (unlike
/// [`ring_pop`]). The borrow is confined to `f`'s execution and head is advanced
/// only after `f` returns, so the single producer cannot overwrite the slot
/// mid-read (it cannot reuse this index until head passes it). `Ok(None)` if empty,
/// and then the closure is left in the `Option` untouched; `Err` if the cursors are out of range.
///
/// For a consumer that processes-and-discards within `f` (e.g. a renderer, a
/// digest, or a streaming sink) this removes the slot→heap copy. It is NOT for a
/// consumer that must *retain* the bytes past `f` (e.g. forwarding into a PIT/CS,
/// which must own the Data beyond the transient slot) — use [`ring_pop`] there.
///
/// # Safety
/// Same as [`ring_pop`].
unsafe fn ring_peek_consume<R, F: FnOnce(&[u8]) -> R>(
    base: *mut u8,
    ring_off: usize,
    tail_off: usize,
    head_off: usize,
    capacity: u32,
    slot_size: u32,
    f: &mut Option<F>,
) -> Result<Option<R>, RingCorrupt> {
    let tail_a = unsafe { AtomicU32::from_ptr(base.add(tail_off) as *mut u32) };
    let head_a = unsafe { AtomicU32::from_ptr(base.add(head_off) as *mut u32) };

    let h = head_a.load(Ordering::Relaxed);
    let t = tail_a.load(Ordering::Acquire);
    if ring_unread(h, t, capacity)? == 0 {
        return Ok(None);
    }

    let idx = (h % capacity) as usize;
    let slot = unsafe { base.add(ring_off + idx * slot_stride(slot_size)) };
    let len = unsafe { (slot as *const u32).read_unaligned() as usize };
    let len = len.min(slot_size as usize);
    let out = {
        let view = unsafe { std::slice::from_raw_parts(slot.add(4), len) };
        (f.take().expect("a consume closure is called once"))(view)
    };
    head_a.store(h.wrapping_add(1), Ordering::Release);
    Ok(Some(out))
}

/// Send file descriptors to a connected Unix-socket peer via `SCM_RIGHTS`,
/// alongside one byte of normal data (the kernel requires ancillary data to
/// ride with ≥1 data byte). Up to 8 fds in one message. This is how an
/// anonymous (`ShmRegion::create_anon`) region + its wakeup channels are
/// handed to the peer **without ever appearing in a shared namespace**. Also the
/// low-level utility for passing a [`SharedBuffer`]'s fd (zero-copy large-buffer
/// delivery).
pub fn send_fds(sock: RawFd, fds: &[RawFd]) -> std::io::Result<()> {
    if fds.is_empty() || fds.len() > 8 {
        return Err(std::io::Error::other("send_fds: 1..=8 fds required"));
    }
    let mut dummy: [u8; 1] = [0xED];
    let mut iov = libc::iovec {
        iov_base: dummy.as_mut_ptr() as *mut libc::c_void,
        iov_len: 1,
    };
    let fds_bytes = std::mem::size_of_val(fds);
    let mut cbuf = [0u8; 128]; // > CMSG_SPACE(8 * size_of::<RawFd>())
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov as *mut libc::iovec;
    msg.msg_iovlen = 1 as _;
    msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = unsafe { libc::CMSG_SPACE(fds_bytes as libc::c_uint) } as _;
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(fds_bytes as libc::c_uint) as _;
        std::ptr::copy_nonoverlapping(fds.as_ptr(), libc::CMSG_DATA(cmsg) as *mut RawFd, fds.len());
        loop {
            let n = libc::sendmsg(sock, &msg, 0);
            if n < 0 {
                let e = std::io::Error::last_os_error();
                if e.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            return Ok(());
        }
    }
}

/// Receive up to `max` file descriptors from a Unix-socket peer (`SCM_RIGHTS`),
/// as `OwnedFd`s. Errors if the peer closed without sending, or if the control
/// buffer was truncated (which would silently leak the in-flight fds). Counterpart
/// of [`send_fds`] for receiving a [`SharedBuffer`] fd.
pub fn recv_fds(sock: RawFd, max: usize) -> std::io::Result<Vec<OwnedFd>> {
    let mut dummy = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: dummy.as_mut_ptr() as *mut libc::c_void,
        iov_len: 1,
    };
    let mut cbuf = [0u8; 128];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov as *mut libc::iovec;
    msg.msg_iovlen = 1 as _;
    msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cbuf.len() as _;
    let n = unsafe {
        loop {
            let r = libc::recvmsg(sock, &mut msg, 0);
            if r < 0 {
                let e = std::io::Error::last_os_error();
                if e.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            break r;
        }
    };
    if n == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "peer closed before sending fds",
        ));
    }
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(std::io::Error::other("fd control message truncated"));
    }
    let mut fds = Vec::new();
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let data = libc::CMSG_DATA(cmsg);
                let payload = (*cmsg).cmsg_len as usize - (data as usize - cmsg as usize);
                let count = payload / std::mem::size_of::<RawFd>();
                for i in 0..count {
                    if fds.len() >= max {
                        // Close any fds beyond the cap so they don't leak.
                        let raw = (data as *const RawFd).add(i).read_unaligned();
                        libc::close(raw);
                        continue;
                    }
                    let raw = (data as *const RawFd).add(i).read_unaligned();
                    fds.push(OwnedFd::from_raw_fd(raw));
                }
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }
    Ok(fds)
}

/// A 32-byte one-time capability token gating the SHM control-socket fd handoff.
pub type ShmToken = [u8; 32];

/// Mint a high-entropy capability token. Uses `getentropy(2)` (kernel CSPRNG,
/// no file descriptor — present on both Linux and macOS), so it can't fail under
/// fd pressure the way opening `/dev/urandom` would.
pub fn mint_token() -> std::io::Result<ShmToken> {
    let mut t = [0u8; 32];
    fill_entropy(&mut t)?;
    Ok(t)
}

/// Fill `buf` with cryptographic entropy. `getentropy` is absent from the `libc`
/// crate's musl bindings, so read `/dev/urandom` — portable across glibc/musl/macOS.
fn fill_entropy(buf: &mut [u8]) -> std::io::Result<()> {
    use std::io::Read;
    std::fs::File::open("/dev/urandom")?.read_exact(buf)
}

/// The control-socket path for a capability `token` (Option-A bootstrap): under
/// the temp dir, named by **SHA-256(token)** (hex). One-way, so the visible
/// filename never reveals the token; **unguessable without the token**, so no
/// path needs to cross the wire and an outsider can neither find nor squat the
/// socket. The router and client derive the same path from the token that rides
/// the (signed) face-create command.
pub fn control_socket_path(token: &ShmToken) -> std::path::PathBuf {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(token);
    let mut hex = String::with_capacity(16);
    // 8 hash bytes (64 bits) — unguessable without the token, collision-safe for
    // random tokens, and short enough to keep the whole socket path under the
    // Unix `SUN_LEN` limit (~104 on macOS). Under `/tmp` (short on every Unix,
    // matching the wakeup-FIFO convention) rather than the long macOS temp dir.
    for b in &digest[..8] {
        use std::fmt::Write;
        let _ = write!(hex, "{b:02x}");
    }
    std::path::PathBuf::from("/tmp").join(format!(".ndn-shm-ctl-{hex}.sock"))
}

/// Constant-time equality — no early-out timing leak when comparing the token.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

const AUTH_TAG_SERVER: u8 = b'S';
const AUTH_TAG_CLIENT: u8 = b'C';

/// Handshake MAC over the capability: `SHA-256(K ++ tag ++ Nc ++ Ns)`. `K` is a
/// 32-byte uniformly-random secret and the message is fixed-length, so this is a
/// sound MAC here — length-extension doesn't apply to a fixed-format message, and
/// the `S`/`C` tag domain-separates the two directions (defeats reflection).
fn auth_mac(k: &ShmToken, tag: u8, nc: &[u8; 32], ns: &[u8; 32]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(k);
    h.update([tag]);
    h.update(nc);
    h.update(ns);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

fn nonce() -> std::io::Result<[u8; 32]> {
    let mut n = [0u8; 32];
    fill_entropy(&mut n)?;
    Ok(n)
}

/// The whole of one handshake on a control socket — connect, mutual authentication, and
/// the hand-over of the fds — may take this long, **on either end**. A peer that is
/// silent, or answers a byte at a time, is dropped when it passes; the listener serves
/// the others meanwhile (see [`Handoff`]), and a client whose owner is silent gets an
/// error that says so instead of waiting for ever.
pub const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// A control-socket stream whose every read and write is bounded by one deadline for
/// the whole exchange: before each call the stream's timeout is set to what is left, so
/// a peer that trickles bytes cannot stretch the handshake past the deadline.
struct Bounded<'a> {
    s: &'a mut std::os::unix::net::UnixStream,
    end: std::time::Instant,
    /// Who is silent, for the error: "the client" or "the ring's owner".
    silent: &'static str,
}

impl Bounded<'_> {
    fn timed_out(&self) -> std::io::Error {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!(
                "{} did not answer within {} s of the control-socket handshake",
                self.silent,
                HANDSHAKE_TIMEOUT.as_secs()
            ),
        )
    }

    /// Set the stream's timeouts to the time left; the deadline passing is an error.
    fn arm(&self) -> std::io::Result<()> {
        let left = self
            .end
            .saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return Err(self.timed_out());
        }
        self.s.set_read_timeout(Some(left))?;
        self.s.set_write_timeout(Some(left))
    }

    /// A timeout of the socket as the handshake's own, other errors as they are.
    fn mapped(&self, e: std::io::Error) -> std::io::Error {
        if matches!(
            e.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ) {
            self.timed_out()
        } else {
            e
        }
    }
}

impl std::io::Read for Bounded<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.arm()?;
        let r = self.s.read(buf);
        r.map_err(|e| self.mapped(e))
    }
}

impl std::io::Write for Bounded<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.arm()?;
        let r = self.s.write(buf);
        r.map_err(|e| self.mapped(e))
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.s.flush()
    }
}

/// What a producer's side of the handshake found.
enum Auth {
    /// The peer proved the capability.
    Proved,
    /// The peer answered, and the proof is wrong.
    Wrong,
    /// The peer closed before sending a single octet: a probe (a writer checking whether
    /// a socket path is live), not an attempt.
    Probe,
}

fn auth_server_over<S: std::io::Read + std::io::Write>(
    s: &mut S,
    k: &ShmToken,
) -> std::io::Result<Auth> {
    let mut nc = [0u8; 32];
    let first = loop {
        match s.read(&mut nc) {
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            r => break r?,
        }
    };
    if first == 0 {
        return Ok(Auth::Probe);
    }
    s.read_exact(&mut nc[first..])?;
    let ns = nonce()?;
    s.write_all(&ns)?;
    s.write_all(&auth_mac(k, AUTH_TAG_SERVER, &nc, &ns))?;
    let mut proof_c = [0u8; 32];
    s.read_exact(&mut proof_c)?;
    Ok(
        if ct_eq(&proof_c, &auth_mac(k, AUTH_TAG_CLIENT, &nc, &ns)) {
            Auth::Proved
        } else {
            Auth::Wrong
        },
    )
}

fn auth_client_over<S: std::io::Read + std::io::Write>(
    s: &mut S,
    k: &ShmToken,
) -> std::io::Result<bool> {
    let nc = nonce()?;
    s.write_all(&nc)?;
    let mut ns = [0u8; 32];
    s.read_exact(&mut ns)?;
    let mut proof_s = [0u8; 32];
    s.read_exact(&mut proof_s)?;
    if !ct_eq(&proof_s, &auth_mac(k, AUTH_TAG_SERVER, &nc, &ns)) {
        return Ok(false); // producer can't prove k — squatter; abort, leak nothing
    }
    s.write_all(&auth_mac(k, AUTH_TAG_CLIENT, &nc, &ns))?;
    Ok(true)
}

/// **Producer-side mutual auth** over a connected blocking stream: prove knowledge
/// of capability `k` to the consumer and verify the consumer's proof — the raw `k`
/// never crosses the wire. Returns `Ok(true)` iff the consumer proved `k`. Because
/// the consumer independently verifies the producer, a squatter that doesn't know
/// `k` is rejected by the consumer and never harvests the secret. The exchange is
/// bounded by [`HANDSHAKE_TIMEOUT`] as a whole (`TimedOut` after it); the stream's own
/// timeouts are cleared on return.
pub fn mutual_auth_server(
    s: &mut std::os::unix::net::UnixStream,
    k: &ShmToken,
) -> std::io::Result<bool> {
    let end = std::time::Instant::now() + HANDSHAKE_TIMEOUT;
    let out = auth_server_over(
        &mut Bounded {
            s: &mut *s,
            end,
            silent: "the client",
        },
        k,
    );
    let _ = s.set_read_timeout(None);
    let _ = s.set_write_timeout(None);
    match out? {
        Auth::Proved => Ok(true),
        Auth::Wrong => Ok(false),
        Auth::Probe => Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "the client closed before the handshake began",
        )),
    }
}

/// **Consumer-side mutual auth**: send a nonce, verify the producer proved `k`
/// (reject a squatter, revealing nothing), then send our own proof. Returns
/// `Ok(true)` iff the producer is authentic; the caller must abort on `false`. Bounded
/// by [`HANDSHAKE_TIMEOUT`] as a whole: a producer that does not answer is a `TimedOut`
/// error, not a wait for ever. The stream's own timeouts are cleared on return.
pub fn mutual_auth_client(
    s: &mut std::os::unix::net::UnixStream,
    k: &ShmToken,
) -> std::io::Result<bool> {
    let end = std::time::Instant::now() + HANDSHAKE_TIMEOUT;
    let out = auth_client_over(
        &mut Bounded {
            s: &mut *s,
            end,
            silent: "the ring's owner",
        },
        k,
    );
    let _ = s.set_read_timeout(None);
    let _ = s.set_write_timeout(None);
    out
}

/// Unauthorized connections one *process* (kernel-reported uid + pid of the
/// connecting peer) may make inside [`UNAUTH_WINDOW`] before the producer
/// refuses its connections until the window passes.
const UNAUTH_PER_PEER_MAX: u32 = 16;

/// Unauthorized connections one *uid* may make inside [`UNAUTH_WINDOW`] summed
/// over all its processes. The per-process bound alone is evaded by forking (a
/// fresh pid gets a fresh allowance, uid unchanged); this larger second bound
/// caps that. It is larger so that a few honest misconfigured clients of one
/// user (each its own pid) don't reach it, and it is keyed by uid — never
/// shared across users — so a hostile user cannot lock out another user's
/// clients. Same-uid processes are inside the capability's trust boundary
/// (anything that user runs can read the token the same way the client does),
/// so refusing that uid for one window costs nothing the attacker didn't
/// already hold.
const UNAUTH_PER_UID_MAX: u32 = 64;

/// Fixed window, opened by a counter's first unauthorized connection and
/// measured on the monotonic clock. When it ends the counter is forgotten.
/// Refused connections do not extend it (so a peer is served again exactly one
/// window after its first failure, however hard it keeps knocking). This
/// bounds *availability* only; authorization is always the token handshake and
/// never depends on this table or on time.
const UNAUTH_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);

/// Hard bound on counters kept. When full, the counter with the oldest window
/// is evicted, so a process minting pids cannot grow the table (it can at most
/// forget older counters, which only relaxes the availability bound).
const UNAUTH_TABLE_MAX: usize = 1024;

/// The credential the kernel reports for the connecting process
/// (`SO_PEERCRED`, taken at `connect`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Peer {
    Process {
        uid: u32,
        pid: Option<i32>,
    },
    /// `peer_cred` failed. All such peers share one bucket with the per-process
    /// bound — we cannot tell them apart, so they cannot be allowed an unbounded
    /// number of tries each.
    Unidentified,
}

impl Peer {
    fn of(stream: &tokio::net::UnixStream) -> Self {
        match stream.peer_cred() {
            Ok(c) => Peer::Process {
                uid: c.uid(),
                pid: c.pid(),
            },
            Err(_) => Peer::Unidentified,
        }
    }
}

impl std::fmt::Display for Peer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Peer::Process { uid, pid: Some(p) } => write!(f, "uid {uid} pid {p}"),
            Peer::Process { uid, pid: None } => write!(f, "uid {uid} (pid unknown)"),
            Peer::Unidentified => write!(f, "an unidentified peer (no SO_PEERCRED)"),
        }
    }
}

/// What a counter counts: one process, or all processes of one uid.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Scope {
    Process(Peer),
    Uid(u32),
}

impl Scope {
    fn bound(self) -> u32 {
        match self {
            Scope::Process(_) => UNAUTH_PER_PEER_MAX,
            Scope::Uid(_) => UNAUTH_PER_UID_MAX,
        }
    }
}

impl std::fmt::Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Scope::Process(p) => write!(f, "{p}"),
            Scope::Uid(u) => write!(f, "uid {u} (all its processes)"),
        }
    }
}

/// A peer over its bound: who, and how long until the window passes.
#[derive(Debug, PartialEq, Eq)]
struct Refusal {
    scope: Scope,
    retry_in: std::time::Duration,
}

#[derive(Clone, Copy)]
struct Counter {
    window_start: std::time::Instant,
    failures: u32,
    /// Insertion order, to break eviction ties between equal `window_start`s.
    seq: u64,
}

/// Per-credential bound on unauthorized connections to a handoff socket, so one
/// misbehaving local process cannot make the producer stop serving the rest.
///
/// **Rule for a peer over its bound: it is refused until its window passes,
/// whether or not it would now authenticate.** Refusal happens before any read
/// (cheap: the stream is just closed), so authorization is not even attempted,
/// and an attacker can never learn from timing or outcome whether a guess was
/// close. The alternative — still serving an over-bound peer that authenticates
/// — needs the full handshake (reads, entropy, two MACs) for every attempt of a
/// hammering peer, which is exactly the cost the bound exists to cap. An honest
/// client stuck behind its own earlier failures retries after the window.
/// Successes never clear a counter (else a peer alternates one good connect
/// with a flood).
///
/// The clock is passed in (`now`, monotonic) so tests do not sleep.
struct UnauthGate {
    table: std::collections::HashMap<Scope, Counter>,
    next_seq: u64,
}

impl UnauthGate {
    fn new() -> Self {
        Self {
            table: std::collections::HashMap::new(),
            next_seq: 0,
        }
    }

    fn scopes(peer: Peer) -> [Option<Scope>; 2] {
        match peer {
            Peer::Process { uid, .. } => [Some(Scope::Process(peer)), Some(Scope::Uid(uid))],
            Peer::Unidentified => [Some(Scope::Process(peer)), None],
        }
    }

    fn remaining(c: &Counter, now: std::time::Instant) -> std::time::Duration {
        UNAUTH_WINDOW.saturating_sub(now.saturating_duration_since(c.window_start))
    }

    /// The counter for `scope` if its window is still open.
    fn live(&self, scope: Scope, now: std::time::Instant) -> Option<&Counter> {
        self.table
            .get(&scope)
            .filter(|c| !Self::remaining(c, now).is_zero())
    }

    /// Admit a new connection from `peer`, or say why not.
    fn admit(&self, peer: Peer, now: std::time::Instant) -> Result<(), Refusal> {
        for scope in Self::scopes(peer).into_iter().flatten() {
            if let Some(c) = self.live(scope, now)
                && c.failures >= scope.bound()
            {
                return Err(Refusal {
                    scope,
                    retry_in: Self::remaining(c, now),
                });
            }
        }
        Ok(())
    }

    /// Count one unauthorized connection from `peer`. Returns the refusal that
    /// now applies if this failure is the one that reached a bound.
    fn record_failure(&mut self, peer: Peer, now: std::time::Instant) -> Option<Refusal> {
        let mut tripped = None;
        for scope in Self::scopes(peer).into_iter().flatten() {
            if self.live(scope, now).is_none() {
                // Absent or past its window: start a fresh window, within the hard bound.
                self.table.remove(&scope);
                self.make_room(now);
                let seq = self.next_seq;
                self.next_seq += 1;
                self.table.insert(
                    scope,
                    Counter {
                        window_start: now,
                        failures: 0,
                        seq,
                    },
                );
            }
            let c = self.table.get_mut(&scope).expect("inserted above");
            c.failures = c.failures.saturating_add(1);
            if c.failures == scope.bound() && tripped.is_none() {
                tripped = Some(Refusal {
                    scope,
                    retry_in: Self::remaining(c, now),
                });
            }
        }
        tripped
    }

    /// Leave space for one more counter: drop counters whose window has passed,
    /// and if the table is still full, the one with the oldest window.
    fn make_room(&mut self, now: std::time::Instant) {
        if self.table.len() < UNAUTH_TABLE_MAX {
            return;
        }
        self.table.retain(|_, c| !Self::remaining(c, now).is_zero());
        while self.table.len() >= UNAUTH_TABLE_MAX {
            let oldest = self
                .table
                .iter()
                .min_by_key(|(_, c)| (c.window_start, c.seq))
                .map(|(s, _)| *s)
                .expect("table is non-empty when full");
            self.table.remove(&oldest);
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.table.len()
    }
}

/// Handshakes one listener runs at once, in all. A silent peer holds one of these for
/// at most [`HANDSHAKE_TIMEOUT`]; a connection that arrives with all taken is closed at
/// once (its client sees the end of the stream and retries).
const HANDSHAKES_IN_FLIGHT_MAX: usize = 16;

/// Handshakes in flight for one uid. Less than the total, so that one user opening
/// silent connections cannot take every place and keep the others out.
const HANDSHAKES_PER_UID_MAX: usize = 8;

/// How a connection's handshake ended.
enum Handshake {
    /// The peer proved the capability; the stream is ready for the hand-over.
    Authorized(std::os::unix::net::UnixStream),
    /// The peer answered and did not know the capability.
    Wrong,
    /// The peer connected and closed without a word.
    Probe,
    /// The peer went silent past the deadline, or the socket failed mid-way.
    Failed(std::io::Error),
}

/// One connection's handshake, bounded by [`HANDSHAKE_TIMEOUT`] in all (blocking: it runs
/// on a blocking task).
fn run_handshake(mut s: std::os::unix::net::UnixStream, token: ShmToken) -> Handshake {
    let end = std::time::Instant::now() + HANDSHAKE_TIMEOUT;
    let out = auth_server_over(
        &mut Bounded {
            s: &mut s,
            end,
            silent: "the client",
        },
        &token,
    );
    match out {
        Ok(Auth::Proved) => {
            // The hand-over that follows is bounded too.
            let _ = s.set_read_timeout(None);
            let _ = s.set_write_timeout(Some(HANDSHAKE_TIMEOUT));
            Handshake::Authorized(s)
        }
        Ok(Auth::Wrong) => Handshake::Wrong,
        Ok(Auth::Probe) => Handshake::Probe,
        Err(e) => Handshake::Failed(e),
    }
}

/// The accept loop of a control socket. Each connection's handshake runs in a task of its
/// own (at most [`HANDSHAKES_IN_FLIGHT_MAX`], [`HANDSHAKES_PER_UID_MAX`] per uid, each
/// ended by [`HANDSHAKE_TIMEOUT`]), so a peer that connects and sends nothing, or one
/// octet at a time, holds one place for five seconds and never the loop. The
/// [`UnauthGate`] is applied on accept and fed when a handshake ends: a wrong proof or a
/// silent peer counts against the peer, a connect-and-close with no octet (a probe, such
/// as [`bind_exclusive`](crate::ring_carrier::bind_exclusive)'s) does not.
///
/// **Only a failure of the listener ends the loop** — a connection's failure, at any
/// step, is logged with its reason and what to do, and the loop goes on.
struct Handoff {
    listener: tokio::net::UnixListener,
    token: ShmToken,
    what: &'static str,
    gate: UnauthGate,
    in_flight: tokio::task::JoinSet<(Peer, Handshake)>,
    per_uid: std::collections::HashMap<Option<u32>, usize>,
}

impl Handoff {
    fn new(listener: tokio::net::UnixListener, token: ShmToken, what: &'static str) -> Self {
        Self {
            listener,
            token,
            what,
            gate: UnauthGate::new(),
            in_flight: tokio::task::JoinSet::new(),
            per_uid: std::collections::HashMap::new(),
        }
    }

    fn uid(peer: Peer) -> Option<u32> {
        match peer {
            Peer::Process { uid, .. } => Some(uid),
            Peer::Unidentified => None,
        }
    }

    /// The next connection whose peer proved the capability.
    async fn next_authorized(&mut self) -> std::io::Result<std::os::unix::net::UnixStream> {
        loop {
            tokio::select! {
                accepted = self.listener.accept() => match accepted {
                    Ok((stream, _addr)) => self.admit(stream),
                    Err(e) => self.accept_failed(e).await?,
                },
                Some(done) = self.in_flight.join_next(), if !self.in_flight.is_empty() => {
                    if let Some(s) = self.settle(done) {
                        return Ok(s);
                    }
                }
            }
        }
    }

    /// A connection arrived: refuse it cheaply, or start its handshake.
    fn admit(&mut self, stream: tokio::net::UnixStream) {
        let what = self.what;
        let peer = Peer::of(&stream);
        if let Err(r) = self.gate.admit(peer, std::time::Instant::now()) {
            tracing::debug!(
                "{what}: refused a connection from {peer} without reading it: {} is over its \
                 {} unauthorized connections; it is served again in {}s — if this is a \
                 legitimate client, fix its token and retry then",
                r.scope,
                r.scope.bound(),
                r.retry_in.as_secs() + 1,
            );
            return; // dropping the stream closes it
        }
        let uid = Self::uid(peer);
        let busy = self.per_uid.get(&uid).copied().unwrap_or(0);
        if self.in_flight.len() >= HANDSHAKES_IN_FLIGHT_MAX || busy >= HANDSHAKES_PER_UID_MAX {
            tracing::debug!(
                "{what}: refused a connection from {peer}: {} handshakes are in flight ({busy} of \
                 this peer's uid); each ends within {} s — the client retries",
                self.in_flight.len(),
                HANDSHAKE_TIMEOUT.as_secs(),
            );
            return;
        }
        let std_stream = match stream
            .into_std()
            .and_then(|s| s.set_nonblocking(false).map(|()| s))
        {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    "{what}: could not take over a connection from {peer} ({e}); it is dropped \
                     and the listener keeps serving — the client should connect again"
                );
                return;
            }
        };
        *self.per_uid.entry(uid).or_default() += 1;
        let token = self.token;
        self.in_flight
            .spawn_blocking(move || (peer, run_handshake(std_stream, token)));
    }

    /// A handshake ended: the authorized stream, or nothing (the peer is counted or not).
    fn settle(
        &mut self,
        done: Result<(Peer, Handshake), tokio::task::JoinError>,
    ) -> Option<std::os::unix::net::UnixStream> {
        let what = self.what;
        let (peer, outcome) = match done {
            Ok(d) => d,
            Err(e) => {
                // The peer is not known: forget the per-uid counts rather than keep a stale one.
                self.per_uid.clear();
                tracing::warn!(
                    "{what}: a handshake task failed ({e}); that connection is dropped and the \
                     listener keeps serving"
                );
                return None;
            }
        };
        let uid = Self::uid(peer);
        if let Some(n) = self.per_uid.get_mut(&uid) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                self.per_uid.remove(&uid);
            }
        }
        match outcome {
            Handshake::Authorized(s) => return Some(s),
            Handshake::Wrong => note_unauthorized(&mut self.gate, peer, what),
            Handshake::Probe => tracing::debug!(
                "{what}: {peer} connected and closed without a word (a probe): not counted"
            ),
            Handshake::Failed(e) => {
                tracing::debug!(
                    "{what}: the handshake with {peer} failed ({e}): counted as an unauthorized \
                     connection; a legitimate client retries"
                );
                note_unauthorized(&mut self.gate, peer, what);
            }
        }
        None
    }

    /// `accept` failed. Resource exhaustion and aborted connections are not the listener's
    /// end: wait and go on. Anything else (the listener closed) ends the loop.
    async fn accept_failed(&self, e: std::io::Error) -> std::io::Result<()> {
        let what = self.what;
        match e.raw_os_error() {
            Some(n) if [libc::EMFILE, libc::ENFILE, libc::ENOMEM, libc::ENOBUFS].contains(&n) => {
                tracing::warn!(
                    "{what}: accept failed ({e}): this process is out of file descriptors or \
                     memory. Waiting 100 ms and trying again; close descriptors this process \
                     holds, or raise its limit"
                );
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                Ok(())
            }
            _ if matches!(
                e.kind(),
                std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::Interrupted
                    | std::io::ErrorKind::WouldBlock
            ) =>
            {
                Ok(())
            }
            _ => Err(e),
        }
    }

    /// Say why one hand-over to an authorized peer failed, and go on.
    fn handover_failed(&self, why: &str, e: &dyn std::fmt::Display) {
        tracing::warn!(
            "{}: {why} ({e}). That attempt is dropped and the listener keeps serving — if the \
             client left, it should connect again; if the owner could not set up a place for it \
             (the reason above), act on that",
            self.what
        );
    }
}

/// Run `f` on `s` on a blocking task (the hand-over is a few small socket calls, bounded
/// by the stream's write timeout).
async fn on_blocking<F>(s: std::os::unix::net::UnixStream, f: F) -> std::io::Result<()>
where
    F: FnOnce(&mut std::os::unix::net::UnixStream) -> std::io::Result<()> + Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let mut s = s;
        f(&mut s)
    })
    .await
    .map_err(|e| std::io::Error::other(format!("hand-over task: {e}")))?
}

/// Count an unauthorized connection against `peer`; warn once when that
/// reaches a bound (later refusals log at debug).
fn note_unauthorized(gate: &mut UnauthGate, peer: Peer, what: &str) {
    if let Some(r) = gate.record_failure(peer, std::time::Instant::now()) {
        tracing::warn!(
            "{what}: {} made {} unauthorized connections; refusing all its connections for \
             {}s. The other peers are unaffected. If this is a legitimate client it holds a \
             wrong token — give it the token minted for this socket and retry after that; \
             otherwise stop the process",
            r.scope,
            r.scope.bound(),
            r.retry_in.as_secs(),
        );
    }
}

/// **Engine side of the Option-A handshake:** serve the face's three fds
/// (`[region, a2e_write, e2a_read]` from [`SpscFace::create_anon_with`]) to the
/// first client that presents `token`, via `SCM_RIGHTS`, then return. Takes
/// ownership of `listener` (unbinds on drop). **The token is the capability**
/// (constant-time compared), so the socket may be world-connectable; an
/// unauthorized connector is **rejected and the loop keeps listening** — a bad
/// connector can't consume the one-shot handoff (the accept-until-authorized
/// hardening), and neither can an authorized one that leaves before taking the fds:
/// the handoff is spent only by a hand-over that succeeded. Unauthorized attempts are
/// bounded **per peer credential** ([`UnauthGate`]) and every handshake by
/// [`HANDSHAKE_TIMEOUT`], run apart from the accept loop: a peer that connects and
/// says nothing delays no one.
pub async fn serve_fd_handoff(
    listener: tokio::net::UnixListener,
    token: ShmToken,
    fds: [OwnedFd; 3],
) -> std::io::Result<()> {
    let mut hs = Handoff::new(listener, token, "shm control");
    loop {
        let s = hs.next_authorized().await?;
        let raw = [fds[0].as_raw_fd(), fds[1].as_raw_fd(), fds[2].as_raw_fd()];
        match on_blocking(s, move |s| send_fds(s.as_raw_fd(), &raw)).await {
            Ok(()) => return Ok(()),
            Err(e) => hs.handover_failed("could not hand the fds to an authorized client", &e),
        }
    }
}

/// **Multi-peer variant of [`serve_fd_handoff`]** for fan-out (1→N): keep
/// listening and, for *each* authorized connection, call `mint` to produce a fresh
/// set of three fds (a freshly-created ring pair) and hand them to that peer. The
/// caller's `mint` typically creates a new [`SpscFace`] and stashes it so it can
/// broadcast to every attached peer. Unauthorized connectors are rejected and the
/// loop continues; so does a failure to mint or to hand over for one peer. Returns
/// only when the listener fails (socket closed).
#[cfg(unix)]
pub async fn serve_fd_handoff_loop<F>(
    listener: tokio::net::UnixListener,
    token: ShmToken,
    mut mint: F,
) -> std::io::Result<()>
where
    F: FnMut() -> std::io::Result<[OwnedFd; 3]>,
{
    let mut hs = Handoff::new(listener, token, "shm control");
    loop {
        let s = hs.next_authorized().await?;
        // Mint a fresh ring for this peer; on failure, drop the peer and continue.
        let fds = match mint() {
            Ok(fds) => fds,
            Err(e) => {
                hs.handover_failed("could not create a ring for an authorized client", &e);
                continue;
            }
        };
        let raw = [fds[0].as_raw_fd(), fds[1].as_raw_fd(), fds[2].as_raw_fd()];
        if let Err(e) = on_blocking(s, move |s| send_fds(s.as_raw_fd(), &raw)).await {
            hs.handover_failed("could not hand the fds to an authorized client", &e);
        }
        // `fds` (our copies) drop here; the peer holds its dup'd set.
    }
}

/// Connect to a control socket by `path` inside `end`: a connect that would wait (the
/// listener's backlog is full, or nothing accepts) is a `TimedOut` error at the deadline,
/// not a wait for ever.
pub(crate) fn connect_bounded(
    path: &std::path::Path,
    end: std::time::Instant,
) -> std::io::Result<std::os::unix::net::UnixStream> {
    use std::os::unix::ffi::OsStrExt;
    let bytes = path.as_os_str().as_bytes();
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if bytes.len() >= addr.sun_path.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("control socket path is too long for a unix socket: {path:?}"),
        ));
    }
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (d, b) in addr.sun_path.iter_mut().zip(bytes) {
        *d = *b as libc::c_char;
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    const EXTRA: libc::c_int = libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    const EXTRA: libc::c_int = 0;
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | EXTRA, 0) };
    if fd == -1 {
        return Err(std::io::Error::last_os_error());
    }
    // Owned from here: closed on every return.
    let sock = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
    if EXTRA == 0 {
        set_nonblock_cloexec(fd).map_err(|e| match e {
            ShmError::Io(e) => e,
            other => std::io::Error::other(other.to_string()),
        })?;
    }
    loop {
        let r = unsafe {
            libc::connect(
                fd,
                &addr as *const libc::sockaddr_un as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
            )
        };
        if r == 0 {
            break;
        }
        let e = std::io::Error::last_os_error();
        match e.kind() {
            std::io::ErrorKind::Interrupted => {}
            std::io::ErrorKind::WouldBlock => {
                if std::time::Instant::now() >= end {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!(
                            "the control socket {path:?} did not accept the connection within {} s \
                             (its backlog is full: the process behind it is not serving)",
                            HANDSHAKE_TIMEOUT.as_secs()
                        ),
                    ));
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            _ => return Err(e),
        }
    }
    sock.set_nonblocking(false)?;
    Ok(sock)
}

/// The client's half common to every handoff: connect, authenticate the producer, all
/// inside [`HANDSHAKE_TIMEOUT`]. Returns the stream and the deadline the rest of the
/// exchange must keep.
fn client_session(
    path: &std::path::Path,
    token: &ShmToken,
    what: &str,
) -> Result<(std::os::unix::net::UnixStream, std::time::Instant), ShmError> {
    let end = std::time::Instant::now() + HANDSHAKE_TIMEOUT;
    let mut s = connect_bounded(path, end).map_err(ShmError::Io)?;
    let proved = auth_client_over(
        &mut Bounded {
            s: &mut s,
            end,
            silent: "the ring's owner",
        },
        token,
    )
    .map_err(ShmError::Io)?;
    if !proved {
        // PermissionDenied, not `other`: a caller that retries a connect that raced the
        // producer's bind must not retry this (each retry is one more rejection counted
        // against this process's `UNAUTH_PER_PEER_MAX` allowance).
        return Err(ShmError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("{what}: producer failed authentication (possible name squatter)"),
        )));
    }
    Ok((s, end))
}

/// Receive up to `max` fds inside the handshake's deadline.
fn recv_fds_by(
    s: &mut std::os::unix::net::UnixStream,
    end: std::time::Instant,
    max: usize,
) -> Result<Vec<OwnedFd>, ShmError> {
    let b = Bounded {
        s,
        end,
        silent: "the ring's owner",
    };
    b.arm().map_err(ShmError::Io)?;
    recv_fds(b.s.as_raw_fd(), max).map_err(|e| ShmError::Io(b.mapped(e)))
}

/// **Client side of the Option-A handshake:** connect to the control socket at
/// `path`, present `token`, receive the face's three fds, and build the
/// [`SpscHandle`]. Blocking — call via `spawn_blocking` from async code. The whole
/// exchange is bounded by [`HANDSHAKE_TIMEOUT`]: a producer that does not answer is a
/// `TimedOut` error saying so.
pub fn connect_fd_handoff(
    path: &std::path::Path,
    token: &ShmToken,
) -> Result<SpscHandle, ShmError> {
    let (mut s, end) = client_session(path, token, "shm control")?;
    let mut fds = recv_fds_by(&mut s, end, 3)?;
    if fds.len() != 3 {
        return Err(ShmError::Io(std::io::Error::other(
            "shm control: expected 3 fds",
        )));
    }
    // order: [region, a2e_write, e2a_read]
    let e2a_read = fds.pop().unwrap();
    let a2e_write = fds.pop().unwrap();
    let region = fds.pop().unwrap();
    SpscHandle::from_fds(region, a2e_write, e2a_read)
}

/// **Sealed handoff (producer side):** hand one authorized consumer the three
/// sealed-ring fds `[data_ro, ctrl_rw, wake_r]`. The geometry is read from the data
/// region header by the consumer (authoritative), so no metadata rides the wire.
/// Like [`serve_fd_handoff`] but for the sealed ring. One consumer (1:1);
/// unauthorized connectors are rejected, bounded per peer credential
/// ([`UnauthGate`]); the listener never stops because of them.
#[cfg(unix)]
pub async fn serve_sealed_handoff(
    listener: tokio::net::UnixListener,
    token: ShmToken,
    fds: [OwnedFd; 3],
) -> std::io::Result<()> {
    let mut hs = Handoff::new(listener, token, "shm control");
    loop {
        let s = hs.next_authorized().await?;
        let raw = [fds[0].as_raw_fd(), fds[1].as_raw_fd(), fds[2].as_raw_fd()];
        match on_blocking(s, move |s| send_fds(s.as_raw_fd(), &raw)).await {
            Ok(()) => return Ok(()),
            Err(e) => {
                hs.handover_failed("could not hand the sealed fds to an authorized client", &e)
            }
        }
    }
}

/// **Sealed handoff (consumer side):** connect, mutually authenticate, and receive
/// the three sealed-ring fds `[data_ro, ctrl_rw, wake_r]`. The geometry is read from
/// the data-region header by [`SealedReader::from_fds`], not the wire. Blocking —
/// call via `spawn_blocking`, then build the reader in async context. Bounded by
/// [`HANDSHAKE_TIMEOUT`] as a whole.
#[cfg(unix)]
pub fn connect_sealed_handoff(
    path: &std::path::Path,
    token: &ShmToken,
) -> Result<(OwnedFd, OwnedFd, OwnedFd), ShmError> {
    let (mut s, end) = client_session(path, token, "shm control")?;
    let fds = recv_fds_by(&mut s, end, 3)?;
    if fds.len() != 3 {
        return Err(ShmError::Io(std::io::Error::other(
            "shm control: expected 3 sealed fds",
        )));
    }
    let mut it = fds.into_iter();
    let data = it.next().unwrap();
    let ctrl = it.next().unwrap();
    let wake = it.next().unwrap();
    Ok((data, ctrl, wake))
}

fn set_nonblock_cloexec(fd: RawFd) -> Result<(), ShmError> {
    unsafe {
        let fl = libc::fcntl(fd, libc::F_GETFL);
        if fl == -1 || libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK) == -1 {
            return Err(ShmError::Io(std::io::Error::last_os_error()));
        }
        let fdfl = libc::fcntl(fd, libc::F_GETFD);
        if fdfl == -1 || libc::fcntl(fd, libc::F_SETFD, fdfl | libc::FD_CLOEXEC) == -1 {
            return Err(ShmError::Io(std::io::Error::last_os_error()));
        }
    }
    Ok(())
}

/// An anonymous wakeup pipe `(read_end, write_end)`, both non-blocking +
/// close-on-exec. Replaces the named-FIFO wakeup for fd-passed faces — `pipe`
/// + `fcntl` rather than Linux-only `pipe2`, so it builds on macOS too.
fn anon_pipe() -> Result<(OwnedFd, OwnedFd), ShmError> {
    let mut fds = [0 as RawFd; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } == -1 {
        return Err(ShmError::Io(std::io::Error::last_os_error()));
    }
    let r = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let w = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    set_nonblock_cloexec(r.as_raw_fd())?;
    set_nonblock_cloexec(w.as_raw_fd())?;
    Ok((r, w))
}

/// `O_RDWR` avoids the blocking-open problem where `open` blocks until the
/// other end has also opened the FIFO.
fn open_fifo_rdwr(path: &std::path::Path) -> Result<std::os::unix::io::OwnedFd, ShmError> {
    use std::os::unix::io::{FromRawFd, OwnedFd};
    let cpath = CString::new(path.to_str().unwrap_or("")).map_err(|_| ShmError::InvalidName)?;
    let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDWR | libc::O_NONBLOCK) };
    if fd == -1 {
        return Err(ShmError::Io(std::io::Error::last_os_error()));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

async fn pipe_await(
    rx: &tokio::io::unix::AsyncFd<std::os::unix::io::OwnedFd>,
) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    loop {
        let mut guard = rx.readable().await?;
        let mut buf = [0u8; 64];
        let fd = rx.get_ref().as_raw_fd();
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        guard.clear_ready();
        if n > 0 {
            return Ok(());
        }
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "SHM wakeup pipe closed (peer died)",
            ));
        }
        if n == -1 {
            let err = std::io::Error::last_os_error();
            if err.kind() != std::io::ErrorKind::WouldBlock {
                return Err(err);
            }
        }
    }
}

/// Ignores `EAGAIN` — a full pipe buffer means the consumer is already
/// being woken.
fn pipe_write(tx: &std::os::unix::io::OwnedFd) {
    use std::os::unix::io::AsRawFd;
    let b = [1u8];
    unsafe {
        libc::write(tx.as_raw_fd(), b.as_ptr() as *const libc::c_void, 1);
    }
}

/// Engine-side SPSC SHM face.
pub struct SpscFace {
    id: FaceId,
    shm: ShmRegion,
    capacity: u32,
    slot_size: u32,
    a2e_off: usize,
    e2a_off: usize,
    a2e_rx: tokio::io::unix::AsyncFd<std::os::unix::io::OwnedFd>,
    e2a_tx: std::os::unix::io::OwnedFd,
    /// Held for the length of one push into the e2a ring. The ring has one
    /// producer in law, but the sender task (`send_bytes`) and any number of
    /// forwarder reader tasks (`forward_side`) all push on this face, so a push
    /// is exclusive. A push copies at most one slot under it and never waits.
    tx: std::sync::Mutex<()>,
    // `None` for an anonymous (fd-passed) face: it has no named FIFOs to unlink —
    // its wakeup channels are anonymous pipes received over the control socket.
    a2e_pipe_path: Option<PathBuf>,
    e2a_pipe_path: Option<PathBuf>,
    /// Why the face was closed on a ring it could not believe: the peer wrote a cursor no
    /// correct peer writes (see [`RingCorrupt`]). Set once; `recv_bytes` answers
    /// [`FaceError::Closed`] from then on, which ends the forwarder's reader for the face.
    corrupt: std::sync::OnceLock<String>,
    /// Packets handed out, so a hot ring yields to the runtime every [`POPS_PER_YIELD`].
    pops: AtomicU32,
}

impl SpscFace {
    pub fn create(id: FaceId, name: &str) -> Result<Self, ShmError> {
        Self::create_with(id, name, DEFAULT_CAPACITY, DEFAULT_SLOT_SIZE)
    }

    /// Slot size scales for Data packets with up to `mtu` content bytes.
    pub fn create_for_mtu(id: FaceId, name: &str, mtu: usize) -> Result<Self, ShmError> {
        let ss = slot_size_for_mtu(mtu);
        Self::create_with(id, name, capacity_for_slot(ss), ss)
    }

    pub fn create_with(
        id: FaceId,
        name: &str,
        capacity: u32,
        slot_size: u32,
    ) -> Result<Self, ShmError> {
        let size = shm_total_size(capacity, slot_size);
        let shm = ShmRegion::create(&posix_shm_name(name), size)?;
        unsafe {
            shm.write_header(capacity, slot_size);
        }

        let a2e_off = a2e_ring_offset();
        let e2a_off = e2a_ring_offset(capacity, slot_size);

        use tokio::io::unix::AsyncFd;

        let a2e_path = a2e_pipe_path(name);
        let e2a_path = e2a_pipe_path(name);

        let _ = std::fs::remove_file(&a2e_path);
        let _ = std::fs::remove_file(&e2a_path);

        for p in [&a2e_path, &e2a_path] {
            let cp = CString::new(p.to_str().unwrap_or("")).map_err(|_| ShmError::InvalidName)?;
            if unsafe { libc::mkfifo(cp.as_ptr(), 0o600) } == -1 {
                return Err(ShmError::Io(std::io::Error::last_os_error()));
            }
        }

        let a2e_fd = open_fifo_rdwr(&a2e_path)?;
        let a2e_rx = AsyncFd::new(a2e_fd).map_err(ShmError::Io)?;

        let e2a_tx = open_fifo_rdwr(&e2a_path)?;

        Ok(SpscFace {
            id,
            shm,
            capacity,
            slot_size,
            a2e_off,
            e2a_off,
            a2e_rx,
            e2a_tx,
            tx: std::sync::Mutex::new(()),
            a2e_pipe_path: Some(a2e_path),
            e2a_pipe_path: Some(e2a_path),
            corrupt: std::sync::OnceLock::new(),
            pops: AtomicU32::new(0),
        })
    }

    /// Create an **anonymous, capability-scoped** face: an fd-only SHM region
    /// (`ShmRegion::create_anon`) + two anonymous wakeup pipes — **no named SHM
    /// object, no named FIFOs**, so nothing appears in any shared namespace.
    /// Returns the engine-side face plus the three fds to hand the peer via
    /// [`send_fds`], in the fixed order **`[region, a2e_write, e2a_read]`**; the
    /// peer rebuilds with [`SpscHandle::from_fds`]. This is the G11 capability-
    /// scoped data plane: the fds *are* the capability.
    pub fn create_anon_with(
        id: FaceId,
        capacity: u32,
        slot_size: u32,
    ) -> Result<(Self, [OwnedFd; 3]), ShmError> {
        use tokio::io::unix::AsyncFd;

        let size = shm_total_size(capacity, slot_size);
        let (shm, region_fd) = ShmRegion::create_anon(size)?;
        unsafe {
            shm.write_header(capacity, slot_size);
        }
        let a2e_off = a2e_ring_offset();
        let e2a_off = e2a_ring_offset(capacity, slot_size);

        // a2e wakeup: face reads, peer writes. e2a wakeup: face writes, peer reads.
        let (a2e_r, a2e_w) = anon_pipe()?;
        let (e2a_r, e2a_w) = anon_pipe()?;
        let a2e_rx = AsyncFd::new(a2e_r).map_err(ShmError::Io)?;

        let face = SpscFace {
            id,
            shm,
            capacity,
            slot_size,
            a2e_off,
            e2a_off,
            a2e_rx,
            e2a_tx: e2a_w,
            tx: std::sync::Mutex::new(()),
            a2e_pipe_path: None,
            e2a_pipe_path: None,
            corrupt: std::sync::OnceLock::new(),
            pops: AtomicU32::new(0),
        };
        Ok((face, [region_fd, a2e_w, e2a_r]))
    }

    /// Anonymous face with the default ring geometry. See [`create_anon_with`].
    ///
    /// [`create_anon_with`]: Self::create_anon_with
    pub fn create_anon(id: FaceId) -> Result<(Self, [OwnedFd; 3]), ShmError> {
        Self::create_anon_with(id, DEFAULT_CAPACITY, DEFAULT_SLOT_SIZE)
    }

    /// Anonymous face whose slot size carries Data with up to `mtu` content
    /// bytes (the capability-scoped counterpart of [`create_for_mtu`]).
    ///
    /// [`create_for_mtu`]: Self::create_for_mtu
    pub fn create_anon_for_mtu(id: FaceId, mtu: usize) -> Result<(Self, [OwnedFd; 3]), ShmError> {
        let ss = slot_size_for_mtu(mtu);
        Self::create_anon_with(id, capacity_for_slot(ss), ss)
    }

    /// The a2e ring's next packet. The face is closed (`Err(Closed)`, from then on) when
    /// the peer has written a cursor no correct peer writes: the reason is kept
    /// ([`closed_reason`](Self::closed_reason)) and logged once.
    fn pop_a2e(&self) -> Result<Option<Bytes>, FaceError> {
        self.check_ring()?;
        unsafe {
            ring_pop(
                self.shm.as_ptr(),
                self.a2e_off,
                OFF_A2E_TAIL,
                OFF_A2E_HEAD,
                self.capacity,
                self.slot_size,
            )
        }
        .map_err(|c| self.close_corrupt(c))
    }

    /// In-place twin of [`pop_a2e`](Self::pop_a2e): `f` is called, once, only when a
    /// packet was there.
    fn peek_consume_a2e<R, F: FnOnce(&[u8]) -> R>(
        &self,
        f: &mut Option<F>,
    ) -> Result<Option<R>, FaceError> {
        self.check_ring()?;
        unsafe {
            ring_peek_consume(
                self.shm.as_ptr(),
                self.a2e_off,
                OFF_A2E_TAIL,
                OFF_A2E_HEAD,
                self.capacity,
                self.slot_size,
                f,
            )
        }
        .map_err(|c| self.close_corrupt(c))
    }

    /// `Err(Closed)` once the ring was found corrupt.
    fn check_ring(&self) -> Result<(), FaceError> {
        if self.corrupt.get().is_some() {
            Err(FaceError::Closed)
        } else {
            Ok(())
        }
    }

    /// Close the face for a ring the peer corrupted: keep the reason, log it once.
    fn close_corrupt(&self, c: RingCorrupt) -> FaceError {
        let reason = c.to_string();
        if self.corrupt.set(reason.clone()).is_ok() {
            tracing::error!(face = %self.id, "shm face closed: {reason}");
        }
        FaceError::Closed
    }

    /// The e2a ring is full for good when the peer wrote its read cursor out of range
    /// (the write cursor is ours): close the face rather than wait for room that never
    /// comes.
    fn check_e2a(&self) -> Result<(), FaceError> {
        let tail = unsafe { AtomicU32::from_ptr(self.shm.as_ptr().add(OFF_E2A_TAIL) as *mut u32) };
        let head = unsafe { AtomicU32::from_ptr(self.shm.as_ptr().add(OFF_E2A_HEAD) as *mut u32) };
        let (h, t) = (head.load(Ordering::Acquire), tail.load(Ordering::Relaxed));
        ring_unread(h, t, self.capacity)
            .map(|_| ())
            .map_err(|c| self.close_corrupt(c))
    }

    /// Why the face closed itself, if it did: the peer corrupted the ring (the text says
    /// which cursors and what to do). `None` while the ring is sound.
    pub fn closed_reason(&self) -> Option<&str> {
        self.corrupt.get().map(String::as_str)
    }

    /// Yield to the runtime on every [`POPS_PER_YIELD`]-th packet handed out, so a peer
    /// that keeps the ring full cannot hold a worker thread: a reader loop that awaits
    /// nothing else has no other point at which to give it up.
    async fn relax(&self) {
        if self.pops.fetch_add(1, Ordering::Relaxed) % POPS_PER_YIELD == POPS_PER_YIELD - 1 {
            tokio::task::yield_now().await;
        }
    }

    /// **Non-blocking, zero-syscall receive** — the busy-poll low-latency path.
    /// Returns the next packet if one is waiting, else `None` (the caller spins).
    /// A tight `loop { if let Some(p) = face.try_recv() {…} else { spin_loop() } }`
    /// hits the shared-memory round-trip floor (~hundreds of ns) at the cost of a
    /// busy core; use [`recv_bytes`](Self::recv_bytes) (spin-then-park) when CPU
    /// efficiency matters more than the last microsecond. `None` for ever once the face
    /// closed itself ([`closed_reason`](Self::closed_reason)).
    pub fn try_recv(&self) -> Option<Bytes> {
        self.pop_a2e().ok().flatten()
    }

    /// Non-blocking, zero-copy [`recv_with`](Self::recv_with): if a packet is
    /// waiting, consume it in place via `f`; else `None`. The busy-poll path with
    /// no slot→heap copy.
    pub fn try_recv_with<R>(&self, f: impl FnOnce(&[u8]) -> R) -> Option<R> {
        let mut f = Some(f);
        self.peek_consume_a2e(&mut f).ok().flatten()
    }

    fn e2a_has_space(&self) -> bool {
        let tail = unsafe { AtomicU32::from_ptr(self.shm.as_ptr().add(OFF_E2A_TAIL) as *mut u32) };
        let head = unsafe { AtomicU32::from_ptr(self.shm.as_ptr().add(OFF_E2A_HEAD) as *mut u32) };
        tail.load(Ordering::Relaxed)
            .wrapping_sub(head.load(Ordering::Acquire))
            < self.capacity
    }

    /// **Zero-copy send** to the e2a ring (increment 4): reserve a slot and write
    /// `len` bytes into it **in place** via `f` — serialize/encode straight into
    /// shared memory, no intermediate buffer or memcpy (the producer mirror of
    /// [`recv_with`](Self::recv_with)). Same yield-until-space backpressure +
    /// parked-peer wakeup as [`send_bytes`](Self::send_bytes).
    pub async fn send_with(&self, len: usize, f: impl FnOnce(&mut [u8])) -> Result<(), FaceError> {
        if len > self.slot_size as usize {
            return Err(FaceError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "payload exceeds SHM slot size",
            )));
        }
        let parked =
            unsafe { AtomicU32::from_ptr(self.shm.as_ptr().add(OFF_E2A_PARKED) as *mut u32) };
        let mut f = Some(f);
        loop {
            {
                let _push = self.tx.lock().unwrap_or_else(|e| e.into_inner());
                if self.e2a_has_space() {
                    // The lock makes this the only producer: space can't vanish,
                    // so the commit succeeds.
                    let committed = unsafe {
                        ring_reserve_commit(
                            self.shm.as_ptr(),
                            self.e2a_off,
                            OFF_E2A_TAIL,
                            OFF_E2A_HEAD,
                            self.capacity,
                            self.slot_size,
                            len,
                            f.take().unwrap(),
                        )
                    };
                    debug_assert!(committed);
                    break;
                }
            }
            self.check_e2a()?;
            tokio::task::yield_now().await;
        }
        if parked.load(Ordering::SeqCst) != 0 {
            pipe_write(&self.e2a_tx);
        }
        Ok(())
    }

    /// Whether the e2a ring has a free slot now: the read [`try_push_e2a`](Self::try_push_e2a)
    /// makes first. The consumer only frees slots, so a slot seen free stays free until this
    /// side pushes.
    fn has_room_e2a(&self) -> bool {
        let tail = unsafe { AtomicU32::from_ptr(self.shm.as_ptr().add(OFF_E2A_TAIL) as *mut u32) };
        let head = unsafe { AtomicU32::from_ptr(self.shm.as_ptr().add(OFF_E2A_HEAD) as *mut u32) };
        let t = tail.load(Ordering::Relaxed);
        let h = head.load(Ordering::Acquire);
        t.wrapping_sub(h) < self.capacity
    }

    fn try_push_e2a(&self, data: &[u8]) -> bool {
        let _push = self.tx.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            ring_push(
                self.shm.as_ptr(),
                self.e2a_off,
                OFF_E2A_TAIL,
                OFF_E2A_HEAD,
                self.capacity,
                self.slot_size,
                data,
            )
        }
    }

    fn try_push_batch_e2a(&self, pkts: &[&[u8]]) -> usize {
        let _push = self.tx.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            ring_push_batch(
                self.shm.as_ptr(),
                self.e2a_off,
                OFF_E2A_TAIL,
                OFF_E2A_HEAD,
                self.capacity,
                self.slot_size,
                pkts,
            )
        }
    }

    /// Push every packet under one tail advance.
    pub async fn send_batch(&self, pkts: &[Bytes]) -> Result<(), FaceError> {
        if pkts.is_empty() {
            return Ok(());
        }
        for pkt in pkts {
            if pkt.len() > self.slot_size as usize {
                return Err(FaceError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "packet exceeds SHM slot size",
                )));
            }
        }
        let parked =
            unsafe { AtomicU32::from_ptr(self.shm.as_ptr().add(OFF_E2A_PARKED) as *mut u32) };
        let views: Vec<&[u8]> = pkts.iter().map(|p| p.as_ref()).collect();
        let mut start = 0usize;
        while start < views.len() {
            let pushed = self.try_push_batch_e2a(&views[start..]);
            if pushed == 0 {
                self.check_e2a()?;
                tokio::task::yield_now().await;
                continue;
            }
            start += pushed;
            if parked.load(Ordering::SeqCst) != 0 {
                pipe_write(&self.e2a_tx);
            }
        }
        Ok(())
    }
}

impl SpscFace {
    /// The refusals every side call shares: not a side frame, or longer than a slot.
    fn check_side(&self, frame: &[u8]) -> Result<(), SideRefused> {
        if frame.first() != Some(&ndn_transport::SIDE_MARKER) {
            return Err(SideRefused::Malformed);
        }
        let max = self.slot_size as usize;
        if frame.len() > max {
            return Err(SideRefused::TooLarge {
                size: frame.len(),
                max,
            });
        }
        Ok(())
    }
}

impl SpscFace {
    /// **Zero-copy receive** from the a2e ring: wait for a packet, then run `f`
    /// on the payload **borrowed in place** in the shared slot (no
    /// `Bytes`/`memcpy`), returning `f`'s result. Same spin→park→FIFO-wakeup
    /// wait as [`recv_bytes`](Self::recv_bytes), but for a consumer that
    /// processes-and-discards within `f` (renderer / digest / streaming sink).
    /// Use `recv_bytes` when the bytes must be *retained* past `f`.
    pub async fn recv_with<R>(&self, f: impl FnOnce(&[u8]) -> R) -> Result<R, FaceError> {
        let parked =
            unsafe { AtomicU32::from_ptr(self.shm.as_ptr().add(OFF_A2E_PARKED) as *mut u32) };
        let mut f = Some(f);
        loop {
            if let Some(out) = self.peek_consume_a2e(&mut f)? {
                self.relax().await;
                return Ok(out);
            }
            for _ in 0..SPIN_ITERS {
                std::hint::spin_loop();
                if let Some(out) = self.peek_consume_a2e(&mut f)? {
                    self.relax().await;
                    return Ok(out);
                }
            }
            parked.store(1, Ordering::SeqCst);
            if let Some(out) = self.peek_consume_a2e(&mut f)? {
                parked.store(0, Ordering::Relaxed);
                self.relax().await;
                return Ok(out);
            }
            pipe_await(&self.a2e_rx)
                .await
                .map_err(|_| FaceError::Closed)?;
            parked.store(0, Ordering::Relaxed);
        }
    }
}

impl Drop for SpscFace {
    fn drop(&mut self) {
        if let Some(p) = &self.a2e_pipe_path {
            let _ = std::fs::remove_file(p);
        }
        if let Some(p) = &self.e2a_pipe_path {
            let _ = std::fs::remove_file(p);
        }
    }
}

impl Transport for SpscFace {
    fn id(&self) -> FaceId {
        self.id
    }
    fn kind(&self) -> FaceKind {
        FaceKind::Shm
    }

    /// The far end of a shared-memory ring is a program of this host that
    /// opened the segment: the region is created owner-only (`0o600`) or
    /// anonymous and capability-scoped, so only a process of the owning user
    /// (or one handed the capability) can attach.
    fn trust(&self) -> FaceTrust {
        FaceTrust::Program
    }

    /// MTU is baked into the slot size at create time; the ring layout
    /// cannot change without re-mapping the segment.
    fn set_send_mtu(&self, _mtu: Option<u64>) -> Result<Option<u64>, ndn_transport::MtuError> {
        Err(ndn_transport::MtuError::Immutable)
    }

    /// SHM faces live for the lifetime of the shared segment; persistency
    /// is intrinsic, not a setting.
    fn set_persistency(
        &self,
        _persistency: ndn_transport::FacePersistency,
    ) -> Result<(), ndn_transport::PersistencyError> {
        Err(ndn_transport::PersistencyError::Immutable)
    }

    /// A side frame is one ring slot: the longest it can be is the slot size.
    /// (`send_mtu` stays `None`: the link service of a local face never
    /// fragments, and NDN packets are bounded by the slot at the sender.)
    fn side_frame_max(&self) -> usize {
        self.slot_size as usize
    }

    /// A ring push. The ring is reliable and ordered (a full ring waits), so
    /// both classes are served and `class` is ignored. Refuses what the default
    /// refuses, with the slot as the limit: a frame that does not start with the
    /// marker is [`Malformed`](SideRefused::Malformed) (an NDN packet never takes
    /// the side path) and one over a slot [`TooLarge`](SideRefused::TooLarge)
    /// (this face has no `send_mtu`, so the default would surface the slot check
    /// as an I/O error).
    async fn send_side(&self, frame: Bytes, _class: SideClass) -> Result<(), SideRefused> {
        self.check_side(&frame)?;
        self.send_bytes(frame).await.map_err(Into::into)
    }

    /// The non-blocking twin of [`send_side`](Self::send_side), for a forwarder
    /// that must not stall its reader: a push into the ring if a slot is free,
    /// else [`Full`](SideRefused::Full) at once (the frame is dropped by the
    /// caller, who counts it). A reader parked on the ring is woken as `send_side`
    /// wakes it. `class` is ignored: the ring is one reliable, ordered carrier.
    fn forward_side(&self, frame: Bytes, _class: SideClass) -> Result<(), SideRefused> {
        self.check_side(&frame)?;
        if !self.try_push_e2a(&frame) {
            return Err(SideRefused::Full);
        }
        let parked =
            unsafe { AtomicU32::from_ptr(self.shm.as_ptr().add(OFF_E2A_PARKED) as *mut u32) };
        if parked.load(Ordering::SeqCst) != 0 {
            pipe_write(&self.e2a_tx);
        }
        Ok(())
    }

    /// Whether the e2a ring has a free slot: what `forward_side` reads first.
    fn side_room(&self, _class: SideClass) -> bool {
        self.has_room_e2a()
    }

    /// [`side_room`](Self::side_room) for this frame, with the refusals `forward_side` makes
    /// first ([`check_side`](Self::check_side)): a frame it refuses another way (an NDN packet,
    /// one over a slot) is no frame to wait for a free slot for, since waiting would end in the
    /// same refusal, later. A slot takes any frame that fits it, so a free slot is room.
    fn side_room_for(&self, frame: &[u8], _class: SideClass) -> bool {
        self.check_side(frame).is_err() || self.has_room_e2a()
    }

    /// The next packet of the a2e ring. A peer that corrupts the ring's cursors closes
    /// the face (`Err(Closed)`, the reason in [`closed_reason`](SpscFace::closed_reason));
    /// a peer that keeps the ring full does not hold the thread: every
    /// [`POPS_PER_YIELD`]-th packet yields to the runtime.
    async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
        let parked =
            unsafe { AtomicU32::from_ptr(self.shm.as_ptr().add(OFF_A2E_PARKED) as *mut u32) };
        loop {
            if let Some(pkt) = self.pop_a2e()? {
                self.relax().await;
                return Ok(pkt);
            }
            for _ in 0..SPIN_ITERS {
                std::hint::spin_loop();
                if let Some(pkt) = self.pop_a2e()? {
                    self.relax().await;
                    return Ok(pkt);
                }
            }
            // SeqCst orders this against the app's ring push so the wakeup
            // is never missed.
            parked.store(1, Ordering::SeqCst);
            // Recheck: catches pushes between the first check and the flag store.
            if let Some(pkt) = self.pop_a2e()? {
                parked.store(0, Ordering::Relaxed);
                self.relax().await;
                return Ok(pkt);
            }

            pipe_await(&self.a2e_rx)
                .await
                .map_err(|_| FaceError::Closed)?;

            parked.store(0, Ordering::Relaxed);
        }
    }

    async fn send_bytes(&self, pkt: Bytes) -> Result<(), FaceError> {
        if pkt.len() > self.slot_size as usize {
            return Err(FaceError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "packet exceeds SHM slot size",
            )));
        }
        let parked =
            unsafe { AtomicU32::from_ptr(self.shm.as_ptr().add(OFF_E2A_PARKED) as *mut u32) };
        loop {
            if self.try_push_e2a(&pkt) {
                break;
            }
            self.check_e2a()?;
            tokio::task::yield_now().await;
        }
        if parked.load(Ordering::SeqCst) != 0 {
            pipe_write(&self.e2a_tx);
        }
        Ok(())
    }
}

/// A handle to one end of the single-producer/single-consumer shared-memory
/// ring, tied to the mapped shared-memory region and its ring capacity.
pub struct SpscHandle {
    shm: ShmRegion,
    capacity: u32,
    slot_size: u32,
    a2e_off: usize,
    e2a_off: usize,
    e2a_rx: tokio::io::unix::AsyncFd<std::os::unix::io::OwnedFd>,
    a2e_tx: std::os::unix::io::OwnedFd,
    cancel: tokio_util::sync::CancellationToken,
    /// Set when the engine side wrote a cursor out of range: the handle reads nothing
    /// more (see [`RingCorrupt`]).
    corrupt: std::sync::OnceLock<String>,
}

impl SpscHandle {
    pub fn connect(name: &str) -> Result<Self, ShmError> {
        let shm_name_str = posix_shm_name(name);
        let cname = CString::new(shm_name_str.as_str()).map_err(|_| ShmError::InvalidName)?;

        let (capacity, slot_size) = unsafe {
            let fd = libc::shm_open(cname.as_ptr(), libc::O_RDONLY, 0);
            if fd == -1 {
                return Err(ShmError::Io(std::io::Error::last_os_error()));
            }
            let p = libc::mmap(
                std::ptr::null_mut(),
                HEADER_SIZE,
                libc::PROT_READ,
                libc::MAP_SHARED,
                fd,
                0,
            );
            libc::close(fd);
            if p == libc::MAP_FAILED {
                return Err(ShmError::Io(std::io::Error::last_os_error()));
            }
            let base = p as *const u8;
            let magic = (base as *const u64).read_unaligned();
            if magic != MAGIC {
                libc::munmap(p, HEADER_SIZE);
                return Err(ShmError::InvalidMagic);
            }
            let cap = (base.add(8) as *const u32).read_unaligned();
            let slen = (base.add(12) as *const u32).read_unaligned();
            libc::munmap(p, HEADER_SIZE);
            (cap, slen)
        };

        // Reject a bogus geometry (esp. capacity==0 → `% capacity` SIGFPE) before
        // it's used to size the mapping or index any ring.
        validate_geometry(capacity, slot_size)?;
        let size = shm_total_size(capacity, slot_size);
        let shm = ShmRegion::open(&shm_name_str, size)?;
        unsafe { shm.read_header()? };

        let a2e_off = a2e_ring_offset();
        let e2a_off = e2a_ring_offset(capacity, slot_size);

        use tokio::io::unix::AsyncFd;

        let a2e_path = a2e_pipe_path(name);
        let e2a_path = e2a_pipe_path(name);

        let a2e_tx = open_fifo_rdwr(&a2e_path)?;
        let e2a_fd = open_fifo_rdwr(&e2a_path)?;
        let e2a_rx = AsyncFd::new(e2a_fd).map_err(ShmError::Io)?;

        Ok(SpscHandle {
            shm,
            capacity,
            slot_size,
            a2e_off,
            e2a_off,
            e2a_rx,
            a2e_tx,
            cancel: tokio_util::sync::CancellationToken::new(),
            corrupt: std::sync::OnceLock::new(),
        })
    }

    /// Rebuild a handle from the three fds received via [`recv_fds`], in the
    /// order produced by [`SpscFace::create_anon_with`]:
    /// **`[region, a2e_write, e2a_read]`**. The region's capacity/slot size are
    /// read from its header after mapping (the fds are the only handle — no name).
    pub fn from_fds(
        region_fd: OwnedFd,
        a2e_write: OwnedFd,
        e2a_read: OwnedFd,
    ) -> Result<Self, ShmError> {
        use tokio::io::unix::AsyncFd;

        // Read the header from the fd to learn the geometry, then map the full
        // region. (O_NONBLOCK on the pipe ends rides the open-file-description
        // across SCM_RIGHTS, so the received fds are already non-blocking.)
        // The region is the peer's to hand over, so it must be one the peer cannot shrink
        // under this mapping (Linux: sealed memfd).
        check_peer_seals(region_fd.as_raw_fd(), true)?;
        fstat_at_least(region_fd.as_raw_fd(), HEADER_SIZE)?;
        let (capacity, slot_size) = unsafe {
            let p = libc::mmap(
                std::ptr::null_mut(),
                HEADER_SIZE,
                libc::PROT_READ,
                libc::MAP_SHARED,
                region_fd.as_raw_fd(),
                0,
            );
            if p == libc::MAP_FAILED {
                return Err(ShmError::Io(std::io::Error::last_os_error()));
            }
            let base = p as *const u8;
            let magic = (base as *const u64).read_unaligned();
            if magic != MAGIC {
                libc::munmap(p, HEADER_SIZE);
                return Err(ShmError::InvalidMagic);
            }
            let cap = (base.add(8) as *const u32).read_unaligned();
            let slen = (base.add(12) as *const u32).read_unaligned();
            libc::munmap(p, HEADER_SIZE);
            (cap, slen)
        };

        // Defensive bound: even though the region is handed by a trusted (token-
        // gated) peer, refuse an absurd or degenerate geometry — a zero capacity
        // would SIGFPE on the first `% capacity`, an oversized one would mmap
        // gigabytes — rather than trust the header.
        validate_geometry(capacity, slot_size)?;
        let size = shm_total_size(capacity, slot_size);
        let shm = ShmRegion::from_fd_sealed(region_fd.as_raw_fd(), size, true)?;
        // region_fd may now be dropped — the mapping persists. The pipe fds are
        // retained (they carry the wakeups).
        drop(region_fd);

        let a2e_off = a2e_ring_offset();
        let e2a_off = e2a_ring_offset(capacity, slot_size);
        let e2a_rx = AsyncFd::new(e2a_read).map_err(ShmError::Io)?;

        Ok(SpscHandle {
            shm,
            capacity,
            slot_size,
            a2e_off,
            e2a_off,
            e2a_rx,
            a2e_tx: a2e_write,
            cancel: tokio_util::sync::CancellationToken::new(),
            corrupt: std::sync::OnceLock::new(),
        })
    }

    pub fn set_cancel(&mut self, cancel: tokio_util::sync::CancellationToken) {
        self.cancel = cancel;
    }

    fn try_push_a2e(&self, data: &[u8]) -> bool {
        unsafe {
            ring_push(
                self.shm.as_ptr(),
                self.a2e_off,
                OFF_A2E_TAIL,
                OFF_A2E_HEAD,
                self.capacity,
                self.slot_size,
                data,
            )
        }
    }

    fn try_pop_e2a(&self) -> Option<Bytes> {
        if self.corrupt.get().is_some() {
            return None;
        }
        match unsafe {
            ring_pop(
                self.shm.as_ptr(),
                self.e2a_off,
                OFF_E2A_TAIL,
                OFF_E2A_HEAD,
                self.capacity,
                self.slot_size,
            )
        } {
            Ok(pkt) => pkt,
            Err(c) => {
                self.close_corrupt(c);
                None
            }
        }
    }

    /// The other side wrote a cursor no correct peer writes: read nothing more, say why.
    fn close_corrupt(&self, c: RingCorrupt) {
        let reason = c.to_string();
        if self.corrupt.set(reason.clone()).is_ok() {
            tracing::error!("shm handle closed: {reason}");
        }
    }

    /// Why the handle stopped reading, if the ring was corrupted. `None` while sound.
    pub fn closed_reason(&self) -> Option<&str> {
        self.corrupt.get().map(String::as_str)
    }

    fn try_push_batch_a2e(&self, pkts: &[&[u8]]) -> usize {
        unsafe {
            ring_push_batch(
                self.shm.as_ptr(),
                self.a2e_off,
                OFF_A2E_TAIL,
                OFF_A2E_HEAD,
                self.capacity,
                self.slot_size,
                pkts,
            )
        }
    }

    /// Yields cooperatively if the ring fills mid-batch.
    pub async fn send_batch(&self, pkts: &[Bytes]) -> Result<(), ShmError> {
        if self.cancel.is_cancelled() {
            return Err(ShmError::Closed);
        }
        if pkts.is_empty() {
            return Ok(());
        }
        for pkt in pkts {
            if pkt.len() > self.slot_size as usize {
                return Err(ShmError::PacketTooLarge);
            }
        }
        let parked =
            unsafe { AtomicU32::from_ptr(self.shm.as_ptr().add(OFF_A2E_PARKED) as *mut u32) };
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        let views: Vec<&[u8]> = pkts.iter().map(|p| p.as_ref()).collect();
        let mut start = 0usize;
        while start < views.len() {
            let pushed = self.try_push_batch_a2e(&views[start..]);
            if pushed == 0 {
                if self.cancel.is_cancelled() {
                    return Err(ShmError::Closed);
                }
                if tokio::time::Instant::now() >= deadline {
                    return Err(ShmError::Closed);
                }
                tokio::task::yield_now().await;
                continue;
            }
            start += pushed;
            // Wake after each partial push so a batch larger than the ring
            // cannot deadlock.
            if parked.load(Ordering::SeqCst) != 0 {
                pipe_write(&self.a2e_tx);
            }
        }
        Ok(())
    }

    /// Yields cooperatively if the ring is full; uses a wall-clock deadline
    /// for backpressure.
    pub async fn send_bytes(&self, pkt: Bytes) -> Result<(), ShmError> {
        if self.cancel.is_cancelled() {
            return Err(ShmError::Closed);
        }
        if pkt.len() > self.slot_size as usize {
            return Err(ShmError::PacketTooLarge);
        }
        let parked =
            unsafe { AtomicU32::from_ptr(self.shm.as_ptr().add(OFF_A2E_PARKED) as *mut u32) };
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if self.try_push_a2e(&pkt) {
                break;
            }
            if self.cancel.is_cancelled() {
                return Err(ShmError::Closed);
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(ShmError::Closed);
            }
            tokio::task::yield_now().await;
        }
        if parked.load(Ordering::SeqCst) != 0 {
            pipe_write(&self.a2e_tx);
        }
        Ok(())
    }

    /// Returns `None` when closed.
    pub async fn recv_bytes(&self) -> Option<Bytes> {
        if self.cancel.is_cancelled() {
            return None;
        }
        let parked =
            unsafe { AtomicU32::from_ptr(self.shm.as_ptr().add(OFF_E2A_PARKED) as *mut u32) };
        loop {
            if let Some(pkt) = self.try_pop_e2a() {
                return Some(pkt);
            }
            if self.corrupt.get().is_some() {
                return None;
            }
            for _ in 0..SPIN_ITERS {
                std::hint::spin_loop();
                if let Some(pkt) = self.try_pop_e2a() {
                    return Some(pkt);
                }
            }
            parked.store(1, Ordering::SeqCst);
            if let Some(pkt) = self.try_pop_e2a() {
                parked.store(0, Ordering::Relaxed);
                return Some(pkt);
            }

            tokio::select! {
                result = pipe_await(&self.e2a_rx) => {
                    parked.store(0, Ordering::Relaxed);
                    if result.is_err() { return None; }
                }
                _ = self.cancel.cancelled() => {
                    parked.store(0, Ordering::Relaxed);
                    return None;
                }
            }
        }
    }

    fn try_peek_consume_e2a<R, F: FnOnce(&[u8]) -> R>(&self, f: &mut Option<F>) -> Option<R> {
        if self.corrupt.get().is_some() {
            return None;
        }
        match unsafe {
            ring_peek_consume(
                self.shm.as_ptr(),
                self.e2a_off,
                OFF_E2A_TAIL,
                OFF_E2A_HEAD,
                self.capacity,
                self.slot_size,
                f,
            )
        } {
            Ok(out) => out,
            Err(c) => {
                self.close_corrupt(c);
                None
            }
        }
    }

    /// **Non-blocking, zero-syscall receive** — the busy-poll low-latency path
    /// (app side). Returns the next packet if waiting, else `None` (caller
    /// spins). Tight-loop polling hits the shared-memory floor at the cost of a
    /// busy core; use [`recv_bytes`](Self::recv_bytes) when CPU efficiency wins.
    pub fn try_recv(&self) -> Option<Bytes> {
        self.try_pop_e2a()
    }

    /// Non-blocking, zero-copy [`recv_with`](Self::recv_with): consume the next
    /// packet in place via `f` if waiting, else `None`.
    pub fn try_recv_with<R>(&self, f: impl FnOnce(&[u8]) -> R) -> Option<R> {
        let mut f = Some(f);
        self.try_peek_consume_e2a(&mut f)
    }

    fn a2e_has_space(&self) -> bool {
        let tail = unsafe { AtomicU32::from_ptr(self.shm.as_ptr().add(OFF_A2E_TAIL) as *mut u32) };
        let head = unsafe { AtomicU32::from_ptr(self.shm.as_ptr().add(OFF_A2E_HEAD) as *mut u32) };
        tail.load(Ordering::Relaxed)
            .wrapping_sub(head.load(Ordering::Acquire))
            < self.capacity
    }

    /// **Zero-copy send** to the a2e ring (increment 4): reserve a slot and write
    /// `len` bytes into it **in place** via `f` — encode straight into shared
    /// memory, no intermediate buffer or memcpy. Same wall-clock-deadline
    /// backpressure + cancel handling as [`send_bytes`](Self::send_bytes).
    pub async fn send_with(&self, len: usize, f: impl FnOnce(&mut [u8])) -> Result<(), ShmError> {
        if self.cancel.is_cancelled() {
            return Err(ShmError::Closed);
        }
        if len > self.slot_size as usize {
            return Err(ShmError::PacketTooLarge);
        }
        let parked =
            unsafe { AtomicU32::from_ptr(self.shm.as_ptr().add(OFF_A2E_PARKED) as *mut u32) };
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut f = Some(f);
        loop {
            if self.a2e_has_space() {
                let committed = unsafe {
                    ring_reserve_commit(
                        self.shm.as_ptr(),
                        self.a2e_off,
                        OFF_A2E_TAIL,
                        OFF_A2E_HEAD,
                        self.capacity,
                        self.slot_size,
                        len,
                        f.take().unwrap(),
                    )
                };
                debug_assert!(committed);
                break;
            }
            if self.cancel.is_cancelled() {
                return Err(ShmError::Closed);
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(ShmError::Closed);
            }
            tokio::task::yield_now().await;
        }
        if parked.load(Ordering::SeqCst) != 0 {
            pipe_write(&self.a2e_tx);
        }
        Ok(())
    }

    /// **Zero-copy receive** from the e2a ring: wait for a packet, then run `f`
    /// on the payload **borrowed in place** in the shared slot (no
    /// `Bytes`/`memcpy`), returning `Some(f(..))`. `None` on close/cancel. This
    /// is the app/renderer-side counterpart to [`SpscFace::recv_with`] — the
    /// common consume-in-place case (a local renderer reading Data the forwarder
    /// hands it). Use [`recv_bytes`](Self::recv_bytes) when the bytes must be
    /// retained past `f`.
    pub async fn recv_with<R>(&self, f: impl FnOnce(&[u8]) -> R) -> Option<R> {
        if self.cancel.is_cancelled() {
            return None;
        }
        let parked =
            unsafe { AtomicU32::from_ptr(self.shm.as_ptr().add(OFF_E2A_PARKED) as *mut u32) };
        let mut f = Some(f);
        loop {
            if let Some(out) = self.try_peek_consume_e2a(&mut f) {
                return Some(out);
            }
            if self.corrupt.get().is_some() {
                return None;
            }
            for _ in 0..SPIN_ITERS {
                std::hint::spin_loop();
                if let Some(out) = self.try_peek_consume_e2a(&mut f) {
                    return Some(out);
                }
            }
            parked.store(1, Ordering::SeqCst);
            if let Some(out) = self.try_peek_consume_e2a(&mut f) {
                parked.store(0, Ordering::Relaxed);
                return Some(out);
            }
            tokio::select! {
                result = pipe_await(&self.e2a_rx) => {
                    parked.store(0, Ordering::Relaxed);
                    if result.is_err() { return None; }
                }
                _ = self.cancel.cancelled() => {
                    parked.store(0, Ordering::Relaxed);
                    return None;
                }
            }
        }
    }
}

/// A standalone **anonymous shared-memory buffer** for zero-copy passing of a
/// large opaque payload — a render frame, a video buffer, an ML tensor — between
/// processes (G11 increment 3). Distinct from the SPSC ring: there is no copy and
/// no named object. The producer writes the bytes **in place**; the fd is handed
/// to the consumer ([`send_fds`] over the face's control socket), which maps it
/// ([`SharedBuffer::from_fd`]) and reads **in place**. The fd is the capability.
///
/// This is the substrate for fd/DMA-BUF large-buffer delivery: publish a small
/// named Data describing the buffer (id / `len` / format), pass the fd out of
/// band, and the consumer renders straight from the mapping — pairing with the
/// consume-in-place pattern of [`SpscHandle::recv_with`]. On Linux a producer may
/// instead hand a **DMA-BUF** fd (GPU-exported): the passing channel is identical;
/// the consumer maps it the same way or imports it into the GPU.
pub struct SharedBuffer {
    region: ShmRegion,
    len: usize,
}

impl SharedBuffer {
    /// Create a writable anonymous buffer of `len` bytes (rounded up to a page by
    /// the kernel). Returns the mapped buffer plus the fd to hand the consumer.
    pub fn create(len: usize) -> Result<(Self, OwnedFd), ShmError> {
        let (region, fd) = ShmRegion::create_anon(len.max(1))?;
        Ok((Self { region, len }, fd))
    }

    /// Create a buffer the **producer maps read-write** while handing consumers a
    /// **read-only fd** (`ShmRegion::create_anon_ro`). The producer is the sole
    /// writer — enforced by the kernel, not by trust — so frames a consumer reads
    /// provably originated from the producer, with no per-frame signature. Pair with
    /// [`SharedBufferReader::from_fd`]. This is the multi-reader multicast case in
    /// pure form: one buffer, N read-only readers, one exclusive writer.
    pub fn create_ro(len: usize) -> Result<(Self, OwnedFd), ShmError> {
        let (region, ro_fd) = ShmRegion::create_anon_ro(len.max(1))?;
        Ok((Self { region, len }, ro_fd))
    }

    /// Map a buffer received as an fd (its `len` known from the published
    /// descriptor). The caller owns `fd`'s lifetime; this only maps it.
    pub fn from_fd(fd: RawFd, len: usize) -> Result<Self, ShmError> {
        let region = ShmRegion::from_fd(fd, len.max(1))?;
        Ok(Self { region, len })
    }

    /// Logical length in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// `true` if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The bytes, borrowed in place from the shared mapping (zero-copy read).
    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.region.as_ptr(), self.len) }
    }

    /// The bytes, mutable — the producer fills these in place before handing the
    /// fd off (and a consumer with a writable mapping may write back).
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.region.as_ptr(), self.len) }
    }
}

/// A **read-only** view of a [`SharedBuffer`], mapped from the read-only fd handed
/// out by [`SharedBuffer::create_ro`]. The kernel refuses any writable mapping of
/// that fd, so a consumer (or any process that obtains the fd) can read in place but
/// cannot forge — the producer's exclusive write capability *is* the authenticity
/// guarantee. There is, by design, no `as_mut_slice`.
pub struct SharedBufferReader {
    region: ShmRegion,
    len: usize,
}

impl SharedBufferReader {
    /// Map a read-only fd (from [`SharedBuffer::create_ro`]); `len` is known from the
    /// published descriptor. Errors if the fd is not read-mappable.
    pub fn from_fd(fd: RawFd, len: usize) -> Result<Self, ShmError> {
        let region = ShmRegion::from_fd_ro(fd, len.max(1))?;
        Ok(Self { region, len })
    }

    /// Logical length in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// `true` if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The bytes, borrowed in place from the read-only mapping (zero-copy read).
    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.region.as_ptr(), self.len) }
    }
}

// ===========================================================================
// Sealed ring (kernel-enforced single-writer streaming) — the "local surface"
// substrate. Two regions:
//   * DATA  (producer read-write, consumer READ-ONLY): magic | capacity |
//     slot_size | tail (producer cursor) | slots. The producer is the sole writer
//     — a consumer physically cannot forge a frame (kernel-enforced via the
//     read-only fd). Integrity + origin without a per-frame signature.
//   * CTRL  (read-write to both): head (consumer cursor) | parked. The consumer
//     writes its read cursor here; corrupting it only harms that consumer's own
//     channel (it cannot reach another consumer's ring, and the producer
//     bounds-checks the gap so a bogus head can never cause an out-of-bounds or an
//     overwrite-driven forge — at worst the consumer loses/stalls its own frames).
// One-way; a duplex sealed channel is two of these. SPSC.
// ===========================================================================

const SEALED_OFF_TAIL: usize = 64; // in DATA region (own cache line)
const SEALED_DATA_HEADER: usize = 128; // slots start here in DATA
const SEALED_OFF_HEAD: usize = 0; // in CTRL region
const SEALED_OFF_PARKED: usize = 64; // in CTRL region (own cache line)
const SEALED_CTRL_SIZE: usize = 128;

fn sealed_data_size(capacity: u32, slot_size: u32) -> usize {
    SEALED_DATA_HEADER + capacity as usize * slot_stride(slot_size)
}

/// Producer end of a sealed ring: writes frames into the data region (which it
/// alone can write) and hands consumers a **read-only** data fd, a read-write
/// control fd, and a wakeup-pipe read end.
pub struct SealedWriter {
    data: ShmRegion, // read-write mapping
    ctrl: ShmRegion, // read-write mapping (reads the consumer's head + parked)
    capacity: u32,
    slot_size: u32,
    wake_tx: OwnedFd, // write end of the consumer wakeup pipe
}

impl SealedWriter {
    /// Create a sealed ring. Returns the writer plus `(data_ro_fd, ctrl_rw_fd,
    /// wake_pipe_read_fd)` to hand the consumer; `capacity`/`slot_size` travel
    /// out-of-band (the consumer needs them to size its mappings). Dropping the
    /// writer closes `wake_tx`, which the consumer sees as end-of-stream.
    pub fn create(
        capacity: u32,
        slot_size: u32,
    ) -> Result<(Self, OwnedFd, OwnedFd, OwnedFd), ShmError> {
        let (data, data_ro_fd) = ShmRegion::create_anon_ro(sealed_data_size(capacity, slot_size))?;
        let (ctrl, ctrl_rw_fd) = ShmRegion::create_anon(SEALED_CTRL_SIZE)?;
        let (wake_r, wake_w) = anon_pipe()?; // consumer reads wake_r, producer writes wake_w
        unsafe {
            (data.as_ptr() as *mut u64).write_unaligned(MAGIC);
            (data.as_ptr().add(8) as *mut u32).write_unaligned(capacity);
            (data.as_ptr().add(12) as *mut u32).write_unaligned(slot_size);
            // tail / head / parked are zero from ftruncate.
        }
        Ok((
            Self {
                data,
                ctrl,
                capacity,
                slot_size,
                wake_tx: wake_w,
            },
            data_ro_fd,
            ctrl_rw_fd,
            wake_r,
        ))
    }

    fn tail(&self) -> &AtomicU32 {
        unsafe { AtomicU32::from_ptr(self.data.as_ptr().add(SEALED_OFF_TAIL) as *mut u32) }
    }
    fn head(&self) -> &AtomicU32 {
        unsafe { AtomicU32::from_ptr(self.ctrl.as_ptr().add(SEALED_OFF_HEAD) as *mut u32) }
    }
    fn parked(&self) -> &AtomicU32 {
        unsafe { AtomicU32::from_ptr(self.ctrl.as_ptr().add(SEALED_OFF_PARKED) as *mut u32) }
    }

    /// True if the ring currently has space (consumer head bounds-checked).
    pub fn has_space(&self) -> bool {
        let t = self.tail().load(Ordering::Relaxed);
        let h = self.head().load(Ordering::Acquire);
        // A bogus head (consumer-controlled) only ever makes the gap look >= capacity
        // ⇒ "full" ⇒ we refuse to write. Never an overwrite, never out-of-bounds.
        t.wrapping_sub(h) < self.capacity
    }

    // Commit one slot at the current tail (caller guaranteed space) + wake a parked
    // consumer.
    fn commit(&self, len: usize, fill: impl FnOnce(&mut [u8])) {
        let t = self.tail().load(Ordering::Relaxed);
        let idx = (t % self.capacity) as usize;
        let slot = unsafe {
            self.data
                .as_ptr()
                .add(SEALED_DATA_HEADER + idx * slot_stride(self.slot_size))
        };
        unsafe {
            (slot as *mut u32).write_unaligned(len as u32);
            let payload = std::slice::from_raw_parts_mut(slot.add(4), len);
            fill(payload);
        }
        self.tail().store(t.wrapping_add(1), Ordering::Release);
        if self.parked().load(Ordering::SeqCst) != 0 {
            pipe_write(&self.wake_tx);
        }
    }

    /// Non-blocking zero-copy send: reserve the next slot and write `len` bytes in
    /// place via `fill`. Returns `false` (without calling `fill`) if full — for
    /// fan-out, where a stuck consumer must not block the others.
    pub fn try_send_with(&self, len: usize, fill: impl FnOnce(&mut [u8])) -> bool {
        if len > self.slot_size as usize || !self.has_space() {
            return false;
        }
        self.commit(len, fill);
        true
    }

    /// Non-blocking copy send.
    pub fn try_send(&self, data: &[u8]) -> bool {
        self.try_send_with(data.len(), |slot| slot.copy_from_slice(data))
    }

    /// Blocking (async) zero-copy send: yields until the ring has space, then writes
    /// `len` bytes in place via `fill`. Reliable backpressure for the 1:1 path (a
    /// slow consumer paces the producer). Errors if `len` exceeds the slot.
    pub async fn send_with(
        &self,
        len: usize,
        fill: impl FnOnce(&mut [u8]),
    ) -> Result<(), ShmError> {
        if len > self.slot_size as usize {
            return Err(ShmError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "payload exceeds sealed slot size",
            )));
        }
        let mut fill = Some(fill);
        loop {
            if self.has_space() {
                self.commit(len, fill.take().unwrap());
                return Ok(());
            }
            tokio::task::yield_now().await;
        }
    }
}

/// Consumer end of a sealed ring: maps the data region **read-only** (cannot
/// forge), the control region read-write (writes its read cursor + parked flag),
/// and owns the wakeup-pipe read end (its EOF = the producer is gone).
pub struct SealedReader {
    data: ShmRegion, // read-only mapping
    ctrl: ShmRegion, // read-write mapping
    capacity: u32,
    slot_size: u32,
    wake_rx: tokio::io::unix::AsyncFd<OwnedFd>,
}

impl SealedReader {
    /// Map the fds handed by [`SealedWriter::create`]: `data_fd` read-only,
    /// `ctrl_fd` read-write, `wake_fd` the wakeup pipe read end (kept). The ring
    /// geometry is read from the data-region **header** (producer-written, in the
    /// read-only region — the authoritative source) and **bounded**, so bogus
    /// geometry can never drive an over-map (SIGBUS) or a gigabyte `mmap`. Must be
    /// called within a Tokio runtime (for the wakeup `AsyncFd`).
    pub fn from_fds(
        data_fd: OwnedFd,
        ctrl_fd: OwnedFd,
        wake_fd: OwnedFd,
    ) -> Result<Self, ShmError> {
        // Read magic + geometry from the header page first (small, always in bounds).
        // Regions a peer hands over are checked before they are mapped: the data region
        // must be sealed against any write and any resize (a reader of it cannot be
        // faulted, nor shown a frame the producer did not write), the control region
        // against resizing.
        check_peer_seals(data_fd.as_raw_fd(), false)?;
        check_peer_seals(ctrl_fd.as_raw_fd(), true)?;
        fstat_at_least(data_fd.as_raw_fd(), SEALED_DATA_HEADER)?;
        let (capacity, slot_size) = unsafe {
            let p = libc::mmap(
                std::ptr::null_mut(),
                SEALED_DATA_HEADER,
                libc::PROT_READ,
                libc::MAP_SHARED,
                data_fd.as_raw_fd(),
                0,
            );
            if p == libc::MAP_FAILED {
                return Err(ShmError::Io(std::io::Error::last_os_error()));
            }
            let base = p as *const u8;
            let magic = (base as *const u64).read_unaligned();
            let cap = (base.add(8) as *const u32).read_unaligned();
            let slen = (base.add(12) as *const u32).read_unaligned();
            libc::munmap(p, SEALED_DATA_HEADER);
            if magic != MAGIC {
                return Err(ShmError::InvalidMagic);
            }
            (cap, slen)
        };
        // Sanity-clamp the geometry before mapping the full region.
        if capacity == 0
            || slot_size == 0
            || sealed_data_size(capacity, slot_size) > 256 * 1024 * 1024
        {
            return Err(ShmError::InvalidMagic);
        }
        let data = ShmRegion::from_fd_sealed(
            data_fd.as_raw_fd(),
            sealed_data_size(capacity, slot_size),
            false,
        )?;
        let ctrl = ShmRegion::from_fd_sealed(ctrl_fd.as_raw_fd(), SEALED_CTRL_SIZE, true)?;
        // data_fd / ctrl_fd may now drop — the mappings persist.
        set_nonblock_cloexec(wake_fd.as_raw_fd())?;
        let wake_rx = tokio::io::unix::AsyncFd::new(wake_fd).map_err(ShmError::Io)?;
        Ok(Self {
            data,
            ctrl,
            capacity,
            slot_size,
            wake_rx,
        })
    }

    fn tail(&self) -> &AtomicU32 {
        unsafe { AtomicU32::from_ptr(self.data.as_ptr().add(SEALED_OFF_TAIL) as *mut u32) }
    }
    fn head(&self) -> &AtomicU32 {
        unsafe { AtomicU32::from_ptr(self.ctrl.as_ptr().add(SEALED_OFF_HEAD) as *mut u32) }
    }
    fn parked(&self) -> &AtomicU32 {
        unsafe { AtomicU32::from_ptr(self.ctrl.as_ptr().add(SEALED_OFF_PARKED) as *mut u32) }
    }

    fn peek_consume<R, F: FnOnce(&[u8]) -> R>(&self, f: &mut Option<F>) -> Option<R> {
        let h = self.head().load(Ordering::Relaxed);
        let t = self.tail().load(Ordering::Acquire);
        if h == t {
            return None;
        }
        let idx = (h % self.capacity) as usize;
        let slot = unsafe {
            self.data
                .as_ptr()
                .add(SEALED_DATA_HEADER + idx * slot_stride(self.slot_size))
        };
        let len =
            unsafe { (slot as *const u32).read_unaligned() as usize }.min(self.slot_size as usize);
        let out = {
            let view = unsafe { std::slice::from_raw_parts(slot.add(4), len) };
            (f.take().unwrap())(view)
        };
        self.head().store(h.wrapping_add(1), Ordering::Release);
        Some(out)
    }

    /// Non-blocking zero-copy receive: borrow the next frame in place (read-only)
    /// and pass it to `f`. `None` if empty.
    pub fn try_recv_with<R>(&self, f: impl FnOnce(&[u8]) -> R) -> Option<R> {
        let mut f = Some(f);
        self.peek_consume(&mut f)
    }

    /// Non-blocking copy receive.
    pub fn try_recv(&self) -> Option<Vec<u8>> {
        self.try_recv_with(|s| s.to_vec())
    }

    /// Blocking (async) zero-copy receive: spin → park on the wakeup pipe → read the
    /// next frame in place. `None` when the producer is gone (wakeup pipe EOF) —
    /// the sealed-ring end-of-stream signal.
    pub async fn recv_with<R>(&self, f: impl FnOnce(&[u8]) -> R) -> Option<R> {
        let mut f = Some(f);
        loop {
            if let Some(out) = self.peek_consume(&mut f) {
                return Some(out);
            }
            for _ in 0..SPIN_ITERS {
                std::hint::spin_loop();
                if let Some(out) = self.peek_consume(&mut f) {
                    return Some(out);
                }
            }
            self.parked().store(1, Ordering::SeqCst);
            if let Some(out) = self.peek_consume(&mut f) {
                self.parked().store(0, Ordering::Relaxed);
                return Some(out);
            }
            match pipe_await(&self.wake_rx).await {
                Ok(()) => self.parked().store(0, Ordering::Relaxed),
                Err(_) => {
                    self.parked().store(0, Ordering::Relaxed);
                    return None; // producer gone ⇒ end of stream
                }
            }
        }
    }
}

// ===========================================================================
// Broadcast ring (sealed, lossy SPMC) — one producer, N read-only consumers, each
// with its own cursor; a consumer that falls behind by more than the ring capacity
// is *lapped* (DropOld) and never blocks the producer or its peers. The SHM
// transport for fan-out live streams (NDF Spark): the producer is the sole writer
// of the data region (kernel-RO to consumers — integrity + origin without a
// per-frame signature), and each consumer owns one slot in a shared registry where
// it writes only its own parked flag/cursor (a corrupt entry harms only that
// consumer). Validated shape: iceoryx2 safe-overflow, Aeron positions, LMAX
// Disruptor, Kafka consumer offsets.
//
// Two regions:
//   * DATA (producer RW, consumers RO): magic | capacity | slot_size | tail (u64
//     absolute publish count) | slots. Each slot = seq:u64 | len:u32 | payload.
//     `seq` is the absolute sequence of the frame in that slot, written *after* the
//     payload (Release) and read on both sides (Acquire) as a **seqlock**: a reader
//     copies under it and rejects a frame the producer overwrote mid-read. Because
//     the producer never blocks (lossy), zero-copy borrows are unsound here — the
//     reader copies into its own buffer, unlike the reliable SPSC sealed ring.
//   * REG, one per reader (RW to that reader, RO to the writer): magic |
//     max_consumers | idx | one entry (parked u32 | cursor u64). The reader writes only
//     its own entry in its own page; the writer maps the page read-only to read `parked`
//     and wakes only parked readers; it never reads a reader's cursor for flow control
//     (it can't be stalled). No reader has the fd of another's page, so one reader can
//     neither write another's `parked` word nor corrupt the header a later attach reads.
//   Every region is a memfd sealed against shrinking and growing (Linux), so no peer can
//   make the writer's or another reader's mapping fault; the DATA region is also sealed
//   against writes through any fd, so no reader — of any uid — can write the ring.
// ===========================================================================

const BCAST_MAGIC: u64 = 0x4E44_4E5F_4243_5354; // b"NDN_BCST"
const BCAST_OFF_TAIL: usize = 64; // in DATA (own cache line)
const BCAST_DATA_HEADER: usize = 128; // slots start here in DATA
const BCAST_SLOT_HDR: usize = 16; // seq:u64 | len:u32 | pad, per slot
const BCAST_REG_HEADER: usize = 64; // the entry starts here in a reader's REG page
const BCAST_REG_STRIDE: usize = 64; // one cache line for the entry
const BCAST_OFF_PARKED: usize = 0; // within a REG entry
const BCAST_OFF_CURSOR: usize = 8; // within a REG entry (diagnostic)
const BCAST_WRITING: u64 = u64::MAX; // slot seq sentinel: producer is mid-write
const BCAST_MAX_MAP: usize = 256 * 1024 * 1024; // anti-SIGBUS clamp

fn bcast_slot_stride(slot_size: u32) -> usize {
    (BCAST_SLOT_HDR + slot_size as usize).next_multiple_of(8)
}
fn bcast_data_size(capacity: u32, slot_size: u32) -> usize {
    BCAST_DATA_HEADER + capacity as usize * bcast_slot_stride(slot_size)
}

/// Size of one reader's registry page: header + its one entry.
const BCAST_ENTRY_SIZE: usize = BCAST_REG_HEADER + BCAST_REG_STRIDE;

/// One reader as the writer holds it.
struct Consumer {
    idx: u32,
    /// The reader's registry page mapped **read-only**: the writer reads the reader's
    /// `parked` word here and can write nothing there. The reader maps the same page
    /// read-write; no other reader has a way to it.
    entry: ShmRegion,
    /// Write end of the reader's wakeup pipe. It closing at the other end (the reader
    /// left) is how the writer learns the slot is free.
    wake: OwnedFd,
}

impl Consumer {
    fn parked(&self) -> &AtomicU32 {
        let off = BCAST_REG_HEADER + BCAST_OFF_PARKED;
        unsafe { AtomicU32::from_ptr(self.entry.as_ptr().add(off) as *mut u32) }
    }
}

/// Whether nothing holds the read end of the pipe `w` any more: the reader that owned it
/// has gone (it dropped, or its process ended).
fn pipe_reader_gone(w: &OwnedFd) -> bool {
    let mut p = libc::pollfd {
        fd: w.as_raw_fd(),
        events: libc::POLLOUT,
        revents: 0,
    };
    let r = unsafe { libc::poll(&mut p, 1, 0) };
    r > 0 && p.revents & (libc::POLLERR | libc::POLLHUP) != 0
}

/// Wake the reader; `false` if its pipe has no reader left (it is gone).
fn pipe_write_alive(tx: &OwnedFd) -> bool {
    let b = [1u8];
    let n = unsafe { libc::write(tx.as_raw_fd(), b.as_ptr() as *const libc::c_void, 1) };
    n >= 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EPIPE)
}

/// Producer end of a broadcast ring. Writes frames into the data region (which it
/// alone can write) and serves each consumer a data fd that **cannot be written** by
/// anyone (sealed), a registry page of its **own**, a private wakeup pipe, and its index.
pub struct BroadcastWriter {
    data: ShmRegion,     // read-write mapping (consumers map the same region read-only)
    data_ro_fd: OwnedFd, // the sealed data fd, cloned per consumer
    capacity: u32,
    slot_size: u32,
    max_consumers: u32,
    /// The readers in place. A reader that has left (its wakeup pipe has no reader) is
    /// dropped from here when the next one registers or the next wake finds it gone, and
    /// its index is free again.
    consumers: std::sync::Mutex<Vec<Consumer>>,
    /// Held for one publish: the ring has one writer in law, but a face over it is
    /// called from the sender's task and from a forwarder's reader tasks at once, so
    /// the tail and the slot being filled are touched by one publisher at a time.
    publishing: std::sync::Mutex<()>,
}

impl BroadcastWriter {
    /// Create a broadcast ring sized for `capacity` slots of `slot_size` bytes and up
    /// to `max_consumers` readers **at a time**. The producer holds the writable mapping
    /// of the data region; consumers are added later with
    /// [`register_consumer`](Self::register_consumer).
    pub fn create(capacity: u32, slot_size: u32, max_consumers: u32) -> Result<Self, ShmError> {
        if capacity == 0 || slot_size == 0 || max_consumers == 0 {
            return Err(ShmError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "broadcast ring: capacity/slot_size/max_consumers must be non-zero",
            )));
        }
        let (data, data_ro_fd) = ShmRegion::create_anon_ro(bcast_data_size(capacity, slot_size))?;
        unsafe {
            (data.as_ptr() as *mut u64).write_unaligned(BCAST_MAGIC);
            (data.as_ptr().add(8) as *mut u32).write_unaligned(capacity);
            (data.as_ptr().add(12) as *mut u32).write_unaligned(slot_size);
            // tail is zero from ftruncate.
        }
        Ok(Self {
            data,
            data_ro_fd,
            capacity,
            slot_size,
            max_consumers,
            consumers: std::sync::Mutex::new(Vec::new()),
            publishing: std::sync::Mutex::new(()),
        })
    }

    fn tail(&self) -> &AtomicU64 {
        unsafe { AtomicU64::from_ptr(self.data.as_ptr().add(BCAST_OFF_TAIL) as *mut u64) }
    }

    /// Allocate a reader's place: a registry page of its own, a private wakeup pipe and
    /// the lowest free index. Returns `(data_fd, reg_fd, wake_read_fd, idx)` to hand it.
    ///
    /// A place is free again once its reader has left (the wakeup pipe it held has no
    /// reader), so a ring serves any number of readers over its life, up to
    /// `max_consumers` at once. When all places are held by live readers the error is
    /// [`ShmError::Refused`], which says so and what to do.
    pub fn register_consumer(&self) -> Result<(OwnedFd, OwnedFd, OwnedFd, u32), ShmError> {
        let mut consumers = self.consumers.lock().unwrap_or_else(|e| e.into_inner());
        consumers.retain(|c| !pipe_reader_gone(&c.wake));
        let Some(idx) = (0..self.max_consumers).find(|i| consumers.iter().all(|c| c.idx != *i))
        else {
            return Err(ShmError::Refused(format!(
                "ring has no free reader slots: all {} are held by live readers (a slot frees \
                 when its reader leaves); ask the owner to restart it with room for more, or \
                 retry when a reader has left",
                self.max_consumers
            )));
        };
        let (wake_r, wake_w) = anon_pipe()?;
        let (page, reg_fd) = ShmRegion::create_anon(BCAST_ENTRY_SIZE)?;
        unsafe {
            (page.as_ptr() as *mut u64).write_unaligned(BCAST_MAGIC);
            (page.as_ptr().add(8) as *mut u32).write_unaligned(self.max_consumers);
            (page.as_ptr().add(12) as *mut u32).write_unaligned(idx);
            // parked and cursor are zero from ftruncate.
        }
        // Keep only a read-only view: what the writer reads of the reader's page, it
        // cannot write; the writable mapping above ends here.
        let entry = ShmRegion::from_fd_ro(reg_fd.as_raw_fd(), BCAST_ENTRY_SIZE)?;
        drop(page);
        let data_ro = self.data_ro_fd.try_clone().map_err(ShmError::Io)?;
        consumers.push(Consumer {
            idx,
            entry,
            wake: wake_w,
        });
        Ok((data_ro, reg_fd, wake_r, idx))
    }

    /// Readers in place now (a reader that has left is not counted).
    pub fn consumer_count(&self) -> usize {
        let mut consumers = self.consumers.lock().unwrap_or_else(|e| e.into_inner());
        consumers.retain(|c| !pipe_reader_gone(&c.wake));
        consumers.len()
    }

    /// Total frames published (the absolute tail).
    pub fn published(&self) -> u64 {
        self.tail().load(Ordering::Acquire)
    }

    fn commit(&self, len: usize, fill: impl FnOnce(&mut [u8])) {
        let _publishing = self.publishing.lock().unwrap_or_else(|e| e.into_inner());
        let t = self.tail().load(Ordering::Relaxed);
        let slot = unsafe {
            self.data.as_ptr().add(
                BCAST_DATA_HEADER
                    + (t % self.capacity as u64) as usize * bcast_slot_stride(self.slot_size),
            )
        };
        let seq = unsafe { AtomicU64::from_ptr(slot as *mut u64) };
        // Mark the slot "being written" so a reader mid-overwrite rejects it, then
        // fill, then publish the slot's sequence (Release) and advance tail.
        seq.store(BCAST_WRITING, Ordering::Release);
        unsafe {
            (slot.add(8) as *mut u32).write_unaligned(len as u32);
            let payload = std::slice::from_raw_parts_mut(slot.add(BCAST_SLOT_HDR), len);
            fill(payload);
        }
        seq.store(t, Ordering::Release);
        self.tail().store(t.wrapping_add(1), Ordering::Release);
        // Wake every parked consumer; the producer is never paced by them. A reader whose
        // pipe has no reader left is gone: its place is freed.
        let mut consumers = self.consumers.lock().unwrap_or_else(|e| e.into_inner());
        consumers.retain(|c| c.parked().load(Ordering::SeqCst) == 0 || pipe_write_alive(&c.wake));
    }

    /// Publish one frame in place (zero-copy on the *write* side): `fill` writes up to
    /// `len` bytes into the slot. Returns `false` (frame dropped) if `len` exceeds the
    /// slot size. Never blocks on consumers — a lagging reader is lapped, not waited on.
    pub fn publish_with(&self, len: usize, fill: impl FnOnce(&mut [u8])) -> bool {
        if len > self.slot_size as usize {
            return false;
        }
        self.commit(len, fill);
        true
    }

    /// Publish one frame (copying `data` into the slot).
    pub fn publish(&self, data: &[u8]) -> bool {
        self.publish_with(data.len(), |slot| slot.copy_from_slice(data))
    }
}

/// Outcome of a single non-blocking peek at the broadcast ring.
enum BcastPeek {
    Got(Vec<u8>),
    Empty,
    Retry, // slot was being written / overwritten — re-read tail and try again
}

/// Consumer end of a broadcast ring: maps the data region **read-only** (cannot
/// forge), its own registry page **read-write** (writes only its own parked flag + cursor),
/// owns a private wakeup-pipe read end (EOF = producer gone), and tracks its own
/// absolute cursor. Starts at the live tail (new frames only). Lossy: if the
/// producer laps the cursor, frames are counted in [`dropped`](Self::dropped) and
/// the cursor jumps to the oldest still-available frame.
pub struct BroadcastReader {
    data: ShmRegion, // read-only mapping
    reg: ShmRegion,  // read-write mapping
    capacity: u32,
    slot_size: u32,
    idx: u32,
    next: AtomicU64,    // reader-local absolute cursor (next seq wanted)
    dropped: AtomicU64, // frames lost to lapping
    wake_rx: tokio::io::unix::AsyncFd<OwnedFd>,
}

impl BroadcastReader {
    /// Build a reader from the fds + index handed by the producer
    /// ([`BroadcastWriter::register_consumer`] / [`connect_broadcast_handoff`]):
    /// `data_fd` sealed against writes, `reg_fd` the reader's own registry page
    /// (read-write), `wake_fd` the wakeup pipe read end. A region the producer has not
    /// sealed against resizing (and the data region against writing) is refused with the
    /// reason, on Linux.
    /// Geometry is read from the (producer-written, read-only) data header and
    /// **bounded** so a bogus size can never drive an over-map. Must run within a
    /// Tokio runtime (for the wakeup `AsyncFd`).
    pub fn from_fds(
        data_fd: OwnedFd,
        reg_fd: OwnedFd,
        wake_fd: OwnedFd,
        idx: u32,
    ) -> Result<Self, ShmError> {
        // What a peer hands over must be unshrinkable under our mappings, and the data
        // region unwritable by anyone, before it is mapped or read.
        check_peer_seals(data_fd.as_raw_fd(), false)?;
        check_peer_seals(reg_fd.as_raw_fd(), true)?;
        fstat_at_least(data_fd.as_raw_fd(), BCAST_DATA_HEADER)?;
        // DATA header: magic + capacity + slot_size.
        let (capacity, slot_size) = unsafe {
            let p = libc::mmap(
                std::ptr::null_mut(),
                BCAST_DATA_HEADER,
                libc::PROT_READ,
                libc::MAP_SHARED,
                data_fd.as_raw_fd(),
                0,
            );
            if p == libc::MAP_FAILED {
                return Err(ShmError::Io(std::io::Error::last_os_error()));
            }
            let base = p as *const u8;
            let magic = (base as *const u64).read_unaligned();
            let cap = (base.add(8) as *const u32).read_unaligned();
            let slen = (base.add(12) as *const u32).read_unaligned();
            libc::munmap(p, BCAST_DATA_HEADER);
            if magic != BCAST_MAGIC {
                return Err(ShmError::InvalidMagic);
            }
            (cap, slen)
        };
        if capacity == 0 || slot_size == 0 || bcast_data_size(capacity, slot_size) > BCAST_MAX_MAP {
            return Err(ShmError::InvalidMagic);
        }
        let data = ShmRegion::from_fd_sealed(
            data_fd.as_raw_fd(),
            bcast_data_size(capacity, slot_size),
            false,
        )?;
        // The reader's own page: header (magic, max_consumers, idx) and its one entry. Only
        // this reader holds its fd, so what it finds in the header is what the writer wrote
        // unless this reader itself changed it.
        let reg = ShmRegion::from_fd_sealed(reg_fd.as_raw_fd(), BCAST_ENTRY_SIZE, true)?;
        let (magic, max_consumers) = unsafe {
            (
                (reg.as_ptr() as *const u64).read_unaligned(),
                (reg.as_ptr().add(8) as *const u32).read_unaligned(),
            )
        };
        if magic != BCAST_MAGIC || idx >= max_consumers {
            return Err(ShmError::InvalidMagic);
        }
        set_nonblock_cloexec(wake_fd.as_raw_fd())?;
        let wake_rx = tokio::io::unix::AsyncFd::new(wake_fd).map_err(ShmError::Io)?;

        // Start at the live tail — a new subscriber sees new frames, not the buffered
        // backlog (matches Aeron/Spark "join the live stream").
        let tail = unsafe {
            AtomicU64::from_ptr(data.as_ptr().add(BCAST_OFF_TAIL) as *mut u64)
                .load(Ordering::Acquire)
        };
        Ok(Self {
            data,
            reg,
            capacity,
            slot_size,
            idx,
            next: AtomicU64::new(tail),
            dropped: AtomicU64::new(0),
            wake_rx,
        })
    }

    fn tail(&self) -> &AtomicU64 {
        unsafe { AtomicU64::from_ptr(self.data.as_ptr().add(BCAST_OFF_TAIL) as *mut u64) }
    }
    fn parked(&self) -> &AtomicU32 {
        let off = BCAST_REG_HEADER + BCAST_OFF_PARKED;
        unsafe { AtomicU32::from_ptr(self.reg.as_ptr().add(off) as *mut u32) }
    }
    fn write_cursor(&self, v: u64) {
        let off = BCAST_REG_HEADER + BCAST_OFF_CURSOR;
        unsafe {
            AtomicU64::from_ptr(self.reg.as_ptr().add(off) as *mut u64).store(v, Ordering::Relaxed);
        }
    }

    /// Frames lost to lapping (producer overwrote them before this reader caught up).
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
    /// Frames the writer has published so far (the ring's absolute tail): a reader that
    /// has received `n` of them since it attached, from `published() - n` frames it did
    /// not, knows what it missed.
    pub fn published(&self) -> u64 {
        self.tail().load(Ordering::Acquire)
    }
    /// This reader's registry index.
    pub fn index(&self) -> u32 {
        self.idx
    }

    fn peek(&self) -> BcastPeek {
        let t = self.tail().load(Ordering::Acquire);
        let mut next = self.next.load(Ordering::Relaxed);
        if next >= t {
            return BcastPeek::Empty;
        }
        // DropOld: if the cursor is older than the oldest retained frame, jump forward.
        let oldest = t.saturating_sub(self.capacity as u64);
        if next < oldest {
            self.dropped.fetch_add(oldest - next, Ordering::Relaxed);
            next = oldest;
            self.next.store(next, Ordering::Relaxed);
        }
        let slot = unsafe {
            self.data.as_ptr().add(
                BCAST_DATA_HEADER
                    + (next % self.capacity as u64) as usize * bcast_slot_stride(self.slot_size),
            )
        };
        let seq = unsafe { AtomicU64::from_ptr(slot as *mut u64) };
        let s1 = seq.load(Ordering::Acquire);
        if s1 != next {
            // s1 == BCAST_WRITING (mid-write) or s1 > next (already lapped) → retry.
            return BcastPeek::Retry;
        }
        let len = unsafe { (slot.add(8) as *const u32).read_unaligned() as usize }
            .min(self.slot_size as usize);
        let mut buf = vec![0u8; len];
        unsafe {
            std::ptr::copy_nonoverlapping(slot.add(BCAST_SLOT_HDR), buf.as_mut_ptr(), len);
        }
        // Seqlock check: reject if the producer overwrote the slot during the copy.
        if seq.load(Ordering::Acquire) != next {
            return BcastPeek::Retry;
        }
        self.next.store(next + 1, Ordering::Release);
        self.write_cursor(next + 1);
        BcastPeek::Got(buf)
    }

    /// Non-blocking receive of the next frame (a copy). `None` if no new frame is
    /// available right now (lapped frames are skipped and counted in `dropped`).
    pub fn try_recv(&self) -> Option<Vec<u8>> {
        // Bound the retry budget so a hot producer lapping the exact slot can't spin
        // us forever — on exhaustion we report "nothing this poll" (lossy by design).
        let budget = 4 * self.capacity as u64 + 16;
        for _ in 0..budget {
            match self.peek() {
                BcastPeek::Got(b) => return Some(b),
                BcastPeek::Empty => return None,
                BcastPeek::Retry => std::hint::spin_loop(),
            }
        }
        None
    }

    /// Blocking (async) receive: spin → park on the wakeup pipe → read the next frame.
    /// `None` when the producer is gone (wakeup pipe EOF) — end of stream.
    pub async fn recv(&self) -> Option<Vec<u8>> {
        loop {
            if let Some(b) = self.try_recv() {
                return Some(b);
            }
            for _ in 0..SPIN_ITERS {
                std::hint::spin_loop();
                if let Some(b) = self.try_recv() {
                    return Some(b);
                }
            }
            self.parked().store(1, Ordering::SeqCst);
            if let Some(b) = self.try_recv() {
                self.parked().store(0, Ordering::Relaxed);
                return Some(b);
            }
            match pipe_await(&self.wake_rx).await {
                Ok(()) => self.parked().store(0, Ordering::Relaxed),
                Err(_) => {
                    self.parked().store(0, Ordering::Relaxed);
                    return None; // producer gone ⇒ end of stream
                }
            }
        }
    }
}

/// First octet of a refusal on the broadcast handoff: where a hand-over's fd message
/// would be, the owner sends `REFUSAL`, one octet of length and that many octets of
/// reason, and closes. A reader that gets no fds reads the reason and returns it.
const REFUSAL: u8 = 0xEE;

/// Tell a client, best effort, why it is not given the ring.
fn refuse(s: &mut std::os::unix::net::UnixStream, reason: &str) {
    use std::io::Write;
    let bytes = reason.as_bytes();
    let n = bytes.len().min(255);
    let mut msg = Vec::with_capacity(2 + n);
    msg.push(REFUSAL);
    msg.push(n as u8);
    msg.extend_from_slice(&bytes[..n]);
    let _ = s.write_all(&msg);
}

/// **Broadcast handoff (producer side):** serve the ring fds to **every** authorized
/// consumer that connects (unlike the 1:1 sealed handoff, this loops). Each consumer
/// gets a fresh registry page + wakeup pipe via [`BroadcastWriter::register_consumer`];
/// the three fds ride one `SCM_RIGHTS` message and the registry index follows as four
/// bytes. Unauthorized connectors are bounded per peer credential ([`UnauthGate`]):
/// one process over its bound is refused while the others are still served.
///
/// Each connection's handshake runs apart from this loop and is bounded by
/// [`HANDSHAKE_TIMEOUT`], so a peer that connects and says nothing delays no one. **A
/// failure with one connection never ends the loop**: a reader that leaves after
/// authenticating, a socket that fails mid-hand-over, a ring with no free reader slot (the
/// client is told why, in a refusal it reads) are logged, with what to do, and the next
/// connection is served. Runs until the listener fails or is dropped (spawn it and hold
/// the handle).
#[cfg(unix)]
pub async fn serve_broadcast_handoff(
    listener: tokio::net::UnixListener,
    token: ShmToken,
    writer: std::sync::Arc<BroadcastWriter>,
) -> std::io::Result<()> {
    let mut hs = Handoff::new(listener, token, "broadcast handoff");
    loop {
        let s = hs.next_authorized().await?;
        let ring = std::sync::Arc::clone(&writer);
        let sent = on_blocking(s, move |s| {
            use std::io::Write;
            match ring.register_consumer() {
                Ok((data_ro, reg_rw, wake_r, idx)) => {
                    send_fds(
                        s.as_raw_fd(),
                        &[data_ro.as_raw_fd(), reg_rw.as_raw_fd(), wake_r.as_raw_fd()],
                    )?;
                    // The registry index follows the fd message as four bytes.
                    s.write_all(&idx.to_le_bytes())
                }
                Err(e) => {
                    let reason = match &e {
                        ShmError::Refused(why) => why.clone(),
                        other => {
                            format!("the ring's owner could not set up a reader slot: {other}")
                        }
                    };
                    refuse(s, &reason);
                    Err(std::io::Error::other(reason))
                }
            }
        })
        .await;
        if let Err(e) = sent {
            hs.handover_failed("could not hand the ring to an authorized reader", &e);
        }
        // Keep serving the next consumer.
    }
}

/// **Broadcast handoff (consumer side):** connect, mutually authenticate, and receive
/// the three ring fds `[data_ro, reg_rw, wake_r]` plus this consumer's registry index.
/// Blocking — call via `spawn_blocking`, then build the reader in async context. The
/// whole exchange is bounded by [`HANDSHAKE_TIMEOUT`]: an owner that does not answer is a
/// `TimedOut` error that says so, and an owner with no place for this reader is
/// [`ShmError::Refused`] with its reason.
#[cfg(unix)]
pub fn connect_broadcast_handoff(
    path: &std::path::Path,
    token: &ShmToken,
) -> Result<(OwnedFd, OwnedFd, OwnedFd, u32), ShmError> {
    use std::io::Read;
    let (mut s, end) = client_session(path, token, "broadcast handoff")?;
    let fds = recv_fds_by(&mut s, end, 3)?;
    let mut b = Bounded {
        s: &mut s,
        end,
        silent: "the ring's owner",
    };
    if fds.is_empty() {
        // A refusal: its length, then its reason.
        let mut len = [0u8; 1];
        b.read_exact(&mut len).map_err(ShmError::Io)?;
        let mut why = vec![0u8; len[0] as usize];
        b.read_exact(&mut why).map_err(ShmError::Io)?;
        return Err(ShmError::Refused(
            String::from_utf8_lossy(&why).into_owned(),
        ));
    }
    if fds.len() != 3 {
        return Err(ShmError::Io(std::io::Error::other(
            "broadcast handoff: expected 3 ring fds",
        )));
    }
    let mut idx_buf = [0u8; 4];
    b.read_exact(&mut idx_buf).map_err(ShmError::Io)?;
    let mut it = fds.into_iter();
    let data = it.next().unwrap();
    let reg = it.next().unwrap();
    let wake = it.next().unwrap();
    Ok((data, reg, wake, u32::from_le_bytes(idx_buf)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_transport::Transport;

    fn test_name() -> String {
        format!("test-spsc-{}", std::process::id())
    }

    #[test]
    fn geometry_validation_rejects_degenerate_and_oversized() {
        // capacity == 0 is the dangerous one: every ring op does `% capacity`, so a
        // peer-declared zero would SIGFPE before this guard.
        assert!(matches!(
            validate_geometry(0, DEFAULT_SLOT_SIZE),
            Err(ShmError::InvalidGeometry)
        ));
        assert!(matches!(
            validate_geometry(DEFAULT_CAPACITY, 0),
            Err(ShmError::InvalidGeometry)
        ));
        // An absurd geometry that would map gigabytes is refused, not trusted.
        assert!(matches!(
            validate_geometry(u32::MAX, u32::MAX),
            Err(ShmError::InvalidGeometry)
        ));
        // The defaults are valid.
        assert!(validate_geometry(DEFAULT_CAPACITY, DEFAULT_SLOT_SIZE).is_ok());
    }

    // multi_thread runtime so AsyncFd can use the I/O driver.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn face_kind_and_id() {
        let name = test_name();
        let face = SpscFace::create(FaceId(7), &name).unwrap();
        assert_eq!(face.id(), FaceId(7));
        assert_eq!(face.kind(), FaceKind::Shm);
    }

    /// FOUNDATION PROOF (kernel-enforced single-writer): the producer maps the
    /// buffer read-write and hands out a read-only fd; a consumer reads the
    /// producer's bytes in place (and sees live updates), but the kernel REFUSES any
    /// attempt to obtain a writable mapping of that fd. Integrity + origin without a
    /// per-frame signature — forgery is impossible, not merely trusted.
    #[test]
    fn readonly_handoff_consumer_cannot_write_data_region() {
        let (mut producer, ro_fd) = SharedBuffer::create_ro(4096).unwrap();

        // Producer writes through its read-write mapping.
        producer.as_mut_slice()[..5].copy_from_slice(b"hello");

        // Consumer maps the handed read-only fd and reads the producer's bytes.
        let reader = SharedBufferReader::from_fd(ro_fd.as_raw_fd(), 4096).unwrap();
        assert_eq!(&reader.as_slice()[..5], b"hello");

        // A producer update is visible to the consumer (genuinely shared, zero-copy).
        producer.as_mut_slice()[..5].copy_from_slice(b"world");
        assert_eq!(&reader.as_slice()[..5], b"world");

        // PROOF: the read-only fd cannot be escalated to a writable mapping.
        let attempt = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                ro_fd.as_raw_fd(),
                0,
            )
        };
        let errno = std::io::Error::last_os_error().raw_os_error();
        assert_eq!(
            attempt,
            libc::MAP_FAILED,
            "kernel must refuse a writable MAP_SHARED mapping of the read-only fd (errno {errno:?})"
        );
        // Permission denial — EACCES on Linux, EPERM on macOS; either confirms the
        // fd's read-only mode blocks the writable mapping.
        assert!(
            matches!(errno, Some(libc::EACCES) | Some(libc::EPERM)),
            "expected a permission-denial errno, got {errno:?}"
        );
    }

    /// MUTUAL AUTH: a producer that knows the capability authenticates to the
    /// consumer AND verifies the consumer — both directions, no secret on the wire.
    #[test]
    fn mutual_auth_accepts_matching_key() {
        let (mut c, mut s) = std::os::unix::net::UnixStream::pair().unwrap();
        let k = [0x33u8; 32];
        let server = std::thread::spawn(move || mutual_auth_server(&mut s, &k));
        let client = mutual_auth_client(&mut c, &k).unwrap();
        assert!(client, "consumer authenticates the producer");
        assert!(
            server.join().unwrap().unwrap(),
            "producer authenticates the consumer"
        );
    }

    /// A squatter that does NOT know the capability cannot fool the consumer (its
    /// proof fails) — and the consumer never reveals the secret (it sends no proof
    /// once it detects the bad producer).
    #[test]
    fn mutual_auth_rejects_squatter() {
        let (mut c, mut s) = std::os::unix::net::UnixStream::pair().unwrap();
        let real = [0x11u8; 32];
        let wrong = [0x22u8; 32]; // squatter's guess
        let server = std::thread::spawn(move || mutual_auth_server(&mut s, &wrong));
        let client = mutual_auth_client(&mut c, &real).unwrap();
        drop(c); // closing lets the squatter's pending read see EOF (no deadlock)
        assert!(
            !client,
            "consumer must reject a producer that can't prove the capability"
        );
        // The squatter never gets a valid client proof (EOF or mismatch).
        assert!(matches!(server.join().unwrap(), Ok(false) | Err(_)));
    }

    /// SEALED RING: frames flow producer→consumer over the data region the consumer
    /// maps read-only; the consumer reads in place but the data fd cannot be mapped
    /// writable. FIFO order + empty detection verified.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sealed_ring_flows_and_is_unforgeable() {
        let (writer, data_fd, ctrl_fd, wake_fd) = SealedWriter::create(8, 256).unwrap();
        // Keep a probe handle on the data fd to test the write-refusal after handoff.
        let data_probe = data_fd.try_clone().unwrap();
        let reader = SealedReader::from_fds(data_fd, ctrl_fd, wake_fd).unwrap();

        // Producer writes 5 frames; consumer reads them in order.
        for i in 0..5u8 {
            assert!(writer.try_send(&[i; 100]), "send {i}");
        }
        for i in 0..5u8 {
            let v = reader.try_recv_with(|s| (s.len(), s[0])).expect("frame");
            assert_eq!(v, (100, i), "frame {i} in order");
        }
        assert!(reader.try_recv().is_none(), "empty after draining");

        // A late frame is seen (genuinely shared, zero-copy).
        assert!(writer.try_send(b"late"));
        assert_eq!(reader.try_recv().unwrap(), b"late");

        // PROOF: the data fd cannot be escalated to a writable mapping — a consumer
        // (or any fd holder) physically cannot forge a frame.
        let attempt = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                data_probe.as_raw_fd(),
                0,
            )
        };
        assert_eq!(
            attempt,
            libc::MAP_FAILED,
            "kernel must refuse a writable mapping of the sealed data region"
        );
    }

    /// Backpressure: a full ring refuses further sends (no overwrite), and a bogus
    /// consumer head can never drive an out-of-bounds or an overwrite-forge.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sealed_ring_full_refuses_send() {
        let (writer, data_fd, ctrl_fd, wake_fd) = SealedWriter::create(4, 64).unwrap();
        let reader = SealedReader::from_fds(data_fd, ctrl_fd, wake_fd).unwrap();
        for i in 0..4u8 {
            assert!(writer.try_send(&[i; 8]), "fill slot {i}");
        }
        assert!(!writer.try_send(b"overflow"), "full ring must refuse");
        // Drain one, then one more send fits.
        assert_eq!(reader.try_recv().unwrap(), &[0u8; 8]);
        assert!(writer.try_send(b"now-fits"));
    }

    /// Async wakeup: a parked consumer is woken by a later send, and sees
    /// end-of-stream (None) when the producer drops (wakeup pipe EOF).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sealed_ring_async_wakeup_and_eos() {
        let (writer, data_fd, ctrl_fd, wake_fd) = SealedWriter::create(8, 256).unwrap();
        let reader = SealedReader::from_fds(data_fd, ctrl_fd, wake_fd).unwrap();

        let producer = tokio::spawn(async move {
            for i in 0..4u8 {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                writer.send_with(50, |s| s.fill(i)).await.unwrap();
            }
            // drop writer → wakeup pipe closes → consumer sees EOS
        });

        for i in 0..4u8 {
            let v = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                reader.recv_with(|s| (s.len(), s[0])),
            )
            .await
            .expect("no stall")
            .expect("frame");
            assert_eq!(v, (50, i), "frame {i}");
        }
        // Producer drops → next recv parks then wakes on pipe EOF → None.
        let end = tokio::time::timeout(std::time::Duration::from_secs(2), reader.recv_with(|_| ()))
            .await
            .expect("no stall");
        assert!(end.is_none(), "producer gone ⇒ end of stream");
        producer.await.unwrap();
    }

    /// The producer's writable mapping survives closing the RW fd (the mapping, not
    /// the fd, carries write access — so no writable fd lingers to be transmitted).
    #[test]
    fn readonly_handoff_producer_mapping_outlives_rw_fd() {
        let (mut producer, ro_fd) = SharedBuffer::create_ro(64).unwrap();
        // create_ro already closed the RW fd internally; writing still works.
        producer.as_mut_slice()[0] = 0x42;
        let reader = SharedBufferReader::from_fd(ro_fd.as_raw_fd(), 64).unwrap();
        assert_eq!(reader.as_slice()[0], 0x42);
    }

    #[test]
    fn slot_size_for_mtu_no_floor_clamp() {
        // mtu=1024 → 1024 + 16384 = 17408 (already 64-aligned).
        let small = slot_size_for_mtu(1024);
        assert_eq!(small, 17408);
        assert!(small < DEFAULT_SLOT_SIZE + SHM_SLOT_OVERHEAD as u32);
        assert_eq!(slot_size_for_mtu(0), 16384);
    }

    #[test]
    fn slot_size_for_mtu_scales_up_for_large_mtu() {
        let one_mib = slot_size_for_mtu(1024 * 1024);
        assert!(one_mib >= 1024 * 1024 + SHM_SLOT_OVERHEAD as u32);
        assert_eq!(one_mib % 64, 0);
    }

    #[test]
    fn capacity_for_slot_inversely_scales() {
        assert_eq!(capacity_for_slot(DEFAULT_SLOT_SIZE), DEFAULT_CAPACITY);
        let cap_256k = capacity_for_slot(272_384);
        assert!(cap_256k < DEFAULT_CAPACITY);
        assert!(cap_256k >= 16);
        let cap_1m = capacity_for_slot(1_064_960);
        assert_eq!(cap_1m, 16);
    }

    #[test]
    fn slot_size_for_mtu_is_cache_line_aligned() {
        for mtu in [256_000, 512_000, 768_000, 1_000_000, 2_000_000] {
            let s = slot_size_for_mtu(mtu);
            assert_eq!(s % 64, 0, "slot_size_for_mtu({mtu}) = {s} not 64-aligned");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn create_for_mtu_large_segment_roundtrip() {
        // A Data packet with ~256 KiB content must pass through without
        // exceeding the SHM slot size.
        let name = format!("{}-big", test_name());
        let face = SpscFace::create_for_mtu(FaceId(42), &name, 256 * 1024).unwrap();
        let handle = SpscHandle::connect(&name).unwrap();

        let payload = Bytes::from(vec![0xABu8; 260_000]);
        handle.send_bytes(payload.clone()).await.unwrap();
        let received = tokio::time::timeout(std::time::Duration::from_secs(2), face.recv_bytes())
            .await
            .expect("timed out")
            .unwrap();
        assert_eq!(received.len(), payload.len());
        assert_eq!(&received[..16], &payload[..16]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn send_batch_app_to_engine() {
        let name = format!("{}-bae", test_name());
        let face = SpscFace::create(FaceId(20), &name).unwrap();
        let handle = SpscHandle::connect(&name).unwrap();

        let pkts: Vec<Bytes> = (0u8..16).map(|i| Bytes::from(vec![i; 64])).collect();
        handle.send_batch(&pkts).await.unwrap();

        for i in 0u8..16 {
            let received =
                tokio::time::timeout(std::time::Duration::from_secs(2), face.recv_bytes())
                    .await
                    .expect("timed out")
                    .unwrap();
            assert_eq!(received.len(), 64);
            assert_eq!(received[0], i);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn send_batch_engine_to_app() {
        let name = format!("{}-bea", test_name());
        let face = SpscFace::create(FaceId(21), &name).unwrap();
        let handle = SpscHandle::connect(&name).unwrap();

        let pkts: Vec<Bytes> = (0u8..16).map(|i| Bytes::from(vec![i; 64])).collect();
        face.send_batch(&pkts).await.unwrap();

        for i in 0u8..16 {
            let received =
                tokio::time::timeout(std::time::Duration::from_secs(2), handle.recv_bytes())
                    .await
                    .expect("timed out")
                    .unwrap();
            assert_eq!(received.len(), 64);
            assert_eq!(received[0], i);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn send_batch_exceeds_ring_capacity() {
        let name = format!("{}-bfull", test_name());
        let face = SpscFace::create(FaceId(22), &name).unwrap();
        let handle = SpscHandle::connect(&name).unwrap();

        // Send more packets than the ring can hold so the batch must yield
        // until the engine drains some slots.
        let n = 48usize;
        let pkts: Vec<Bytes> = (0..n)
            .map(|i| Bytes::from(vec![(i & 0xFF) as u8; 32]))
            .collect();

        let send_handle = tokio::spawn({
            let pkts = pkts.clone();
            async move { handle.send_batch(&pkts).await }
        });
        for i in 0..n {
            let received =
                tokio::time::timeout(std::time::Duration::from_secs(5), face.recv_bytes())
                    .await
                    .expect("timed out")
                    .unwrap();
            assert_eq!(received[0], (i & 0xFF) as u8);
        }
        send_handle.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn app_to_engine_roundtrip() {
        let name = format!("{}-ae", test_name());
        let face = SpscFace::create(FaceId(1), &name).unwrap();
        let handle = SpscHandle::connect(&name).unwrap();

        let pkt = Bytes::from_static(b"\x05\x03\x01\x02\x03");
        handle.send_bytes(pkt.clone()).await.unwrap();

        let received = tokio::time::timeout(std::time::Duration::from_secs(2), face.recv_bytes())
            .await
            .expect("timed out")
            .unwrap();

        assert_eq!(received, pkt);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn engine_to_app_roundtrip() {
        let name = format!("{}-ea", test_name());
        let face = SpscFace::create(FaceId(2), &name).unwrap();
        let handle = SpscHandle::connect(&name).unwrap();

        let pkt = Bytes::from_static(b"\x06\x03\xAA\xBB\xCC");
        face.send_bytes(pkt.clone()).await.unwrap();

        let received = tokio::time::timeout(std::time::Duration::from_secs(2), handle.recv_bytes())
            .await
            .expect("timed out")
            .unwrap();

        assert_eq!(received, pkt);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn multiple_packets_both_directions() {
        let name = format!("{}-bi", test_name());
        let face = SpscFace::create(FaceId(3), &name).unwrap();
        let handle = SpscHandle::connect(&name).unwrap();

        for i in 0u8..4 {
            handle.send_bytes(Bytes::from(vec![i; 64])).await.unwrap();
        }
        for i in 0u8..4 {
            let pkt = face.recv_bytes().await.unwrap();
            assert_eq!(&pkt[..], &vec![i; 64][..]);
        }

        for i in 0u8..4 {
            face.send_bytes(Bytes::from(vec![i + 10; 128]))
                .await
                .unwrap();
        }
        for i in 0u8..4 {
            let pkt = handle.recv_bytes().await.unwrap();
            assert_eq!(&pkt[..], &vec![i + 10; 128][..]);
        }
    }

    // --- zero-copy consume-in-place (recv_with) -------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn recv_with_handle_consumes_in_place() {
        // App/renderer side: face sends, handle consumes the slot in place via a
        // closure that derives a value (a checksum) without allocating a Bytes.
        let name = format!("{}-rwh", test_name());
        let face = SpscFace::create(FaceId(30), &name).unwrap();
        let handle = SpscHandle::connect(&name).unwrap();

        let payload = Bytes::from((0u8..200).collect::<Vec<_>>());
        let expected: u64 = payload.iter().map(|&b| b as u64).sum();
        face.send_bytes(payload.clone()).await.unwrap();

        // The closure sees the bytes borrowed from the shared slot and returns a
        // derived result; no slot→heap copy on this path.
        let sum = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            handle.recv_with(|slot| {
                assert_eq!(slot.len(), payload.len());
                slot.iter().map(|&b| b as u64).sum::<u64>()
            }),
        )
        .await
        .expect("timed out")
        .expect("closed");
        assert_eq!(sum, expected);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn recv_with_face_consumes_in_place_and_advances() {
        // Engine side: handle sends two packets, face consumes both via recv_with;
        // verify the head advances (second recv sees the second packet, not a
        // re-read of the first).
        let name = format!("{}-rwf", test_name());
        let face = SpscFace::create(FaceId(31), &name).unwrap();
        let handle = SpscHandle::connect(&name).unwrap();

        handle
            .send_bytes(Bytes::from_static(b"first"))
            .await
            .unwrap();
        handle
            .send_bytes(Bytes::from_static(b"second"))
            .await
            .unwrap();

        let a = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            face.recv_with(|slot| slot.to_vec()),
        )
        .await
        .expect("timed out")
        .unwrap();
        let b = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            face.recv_with(|slot| slot.to_vec()),
        )
        .await
        .expect("timed out")
        .unwrap();
        assert_eq!(&a, b"first");
        assert_eq!(&b, b"second");
    }

    // --- capability-scoped anonymous region via fd-passing (G11 incr. 2) ---

    #[test]
    fn anon_region_fd_passing_shares_memory() {
        use std::os::unix::net::UnixStream;

        // Anonymous region (name unlinked immediately) + a marker written in.
        let (region, fd) = ShmRegion::create_anon(4096).unwrap();
        unsafe {
            (region.as_ptr() as *mut u64).write_unaligned(0xFEED_FACE_DEAD_BEEF);
        }

        // Hand the fd to the "peer" over a socketpair via SCM_RIGHTS.
        let (a, b) = UnixStream::pair().unwrap();
        send_fds(a.as_raw_fd(), &[fd.as_raw_fd()]).unwrap();
        let received = recv_fds(b.as_raw_fd(), 1).unwrap();
        assert_eq!(received.len(), 1);

        // The received fd maps the SAME physical region — the marker is visible
        // without any shared name (proves the capability is the fd, not a path).
        let mapped = ShmRegion::from_fd(received[0].as_raw_fd(), 4096).unwrap();
        let seen = unsafe { (mapped.as_ptr() as *const u64).read_unaligned() };
        assert_eq!(
            seen, 0xFEED_FACE_DEAD_BEEF,
            "fd-passed region must share memory"
        );

        // Write through the peer mapping, read through the original → truly shared.
        unsafe {
            (mapped.as_ptr().add(8) as *mut u32).write_unaligned(0x1234_5678);
        }
        let back = unsafe { (region.as_ptr().add(8) as *const u32).read_unaligned() };
        assert_eq!(
            back, 0x1234_5678,
            "writes through the fd mapping must be shared"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn anon_face_handle_exchange_over_passed_fds() {
        use std::os::unix::net::UnixStream;
        use std::time::Duration;

        // Engine creates an anonymous, capability-scoped face + the 3 fds to hand
        // the peer. No named SHM object, no named FIFOs.
        let (face, fds) =
            SpscFace::create_anon_with(FaceId(77), DEFAULT_CAPACITY, DEFAULT_SLOT_SIZE).unwrap();

        // Pass the fds over a socketpair (stands in for the control socket the
        // mgmt bootstrap sets up in 2b-tail), then rebuild the handle from them.
        let (a, b) = UnixStream::pair().unwrap();
        send_fds(
            a.as_raw_fd(),
            &[fds[0].as_raw_fd(), fds[1].as_raw_fd(), fds[2].as_raw_fd()],
        )
        .unwrap();
        drop(fds); // release the sender-side copies; the peer holds the dups
        let mut recvd = recv_fds(b.as_raw_fd(), 3).unwrap();
        assert_eq!(recvd.len(), 3);
        // order: [region, a2e_write, e2a_read]
        let e2a_read = recvd.pop().unwrap();
        let a2e_write = recvd.pop().unwrap();
        let region = recvd.pop().unwrap();
        let handle = SpscHandle::from_fds(region, a2e_write, e2a_read).unwrap();

        // a2e ring: handle → face.
        handle.send_bytes(Bytes::from_static(b"up")).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(2), face.recv_bytes())
            .await
            .expect("timed out")
            .unwrap();
        assert_eq!(&got[..], b"up");

        // e2a ring: face → handle, consumed in place (exercises both new paths).
        face.send_bytes(Bytes::from_static(b"down")).await.unwrap();
        let down = tokio::time::timeout(Duration::from_secs(2), handle.recv_with(|s| s.to_vec()))
            .await
            .expect("timed out")
            .expect("closed");
        assert_eq!(&down[..], b"down");

        drop((a, b));
    }

    /// A side frame crosses the ring byte-identical in both directions, for both
    /// classes; one over a slot is refused `TooLarge` and nothing is pushed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_side_frame_crosses_the_ring_unchanged_and_over_a_slot_is_refused() {
        use ndn_transport::SIDE_MARKER;
        use std::os::unix::net::UnixStream;
        use std::time::Duration;

        const SLOT: u32 = 256;
        let (face, fds) = SpscFace::create_anon_with(FaceId(90), 16, SLOT).unwrap();
        assert_eq!(face.side_frame_max(), SLOT as usize);
        let (a, b) = UnixStream::pair().unwrap();
        send_fds(
            a.as_raw_fd(),
            &[fds[0].as_raw_fd(), fds[1].as_raw_fd(), fds[2].as_raw_fd()],
        )
        .unwrap();
        drop(fds);
        let mut recvd = recv_fds(b.as_raw_fd(), 3).unwrap();
        let e2a_read = recvd.pop().unwrap();
        let a2e_write = recvd.pop().unwrap();
        let region = recvd.pop().unwrap();
        let handle = SpscHandle::from_fds(region, a2e_write, e2a_read).unwrap();

        let frame = |len: usize, fill: u8| {
            let mut v = vec![fill; len];
            v[0] = SIDE_MARKER;
            Bytes::from(v)
        };

        // face → handle, both classes, the largest frame that fits.
        for (class, fill) in [(SideClass::Datagram, 0x11), (SideClass::Stream, 0x22)] {
            let f = frame(SLOT as usize, fill);
            face.send_side(f.clone(), class).await.unwrap();
            let got =
                tokio::time::timeout(Duration::from_secs(2), handle.recv_with(|s| s.to_vec()))
                    .await
                    .expect("timed out")
                    .expect("closed");
            assert_eq!(got, f.to_vec());
        }

        // handle → face: the ring is the same carrier in the other direction.
        let up = frame(40, 0x33);
        handle.send_bytes(up.clone()).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(2), face.recv_bytes())
            .await
            .expect("timed out")
            .unwrap();
        assert_eq!(got, up);

        // One octet over a slot is refused, not an I/O error, and nothing is pushed.
        assert_eq!(
            face.send_side(frame(SLOT as usize + 1, 0x44), SideClass::Stream)
                .await,
            Err(SideRefused::TooLarge {
                size: SLOT as usize + 1,
                max: SLOT as usize
            })
        );
        assert!(handle.try_recv().is_none());
        drop((a, b));
    }

    /// An anonymous face and the handle of its peer, over a ring of `capacity` slots of
    /// `slot` octets.
    fn anon_pair(id: u64, capacity: u32, slot: u32) -> (SpscFace, SpscHandle) {
        use std::os::unix::net::UnixStream;
        let (face, fds) = SpscFace::create_anon_with(FaceId(id), capacity, slot).unwrap();
        let (a, b) = UnixStream::pair().unwrap();
        send_fds(
            a.as_raw_fd(),
            &[fds[0].as_raw_fd(), fds[1].as_raw_fd(), fds[2].as_raw_fd()],
        )
        .unwrap();
        drop(fds);
        let mut recvd = recv_fds(b.as_raw_fd(), 3).unwrap();
        let e2a_read = recvd.pop().unwrap();
        let a2e_write = recvd.pop().unwrap();
        let region = recvd.pop().unwrap();
        let handle = SpscHandle::from_fds(region, a2e_write, e2a_read).unwrap();
        (face, handle)
    }

    fn marked(len: usize, fill: u8) -> Bytes {
        let mut v = vec![fill; len];
        v[0] = ndn_transport::SIDE_MARKER;
        Bytes::from(v)
    }

    /// A full ring refuses `forward_side` as `Full` at once and keeps every frame it took;
    /// `send_side` on the same full ring waits for room and then lands, in order, behind
    /// them (the ring is reliable and ordered, so a sender that may wait does).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_full_ring_refuses_forward_side_without_blocking_and_send_side_waits_for_room() {
        use std::time::Duration;
        let (face, handle) = anon_pair(91, 4, 128);
        assert!(
            face.side_room(SideClass::Datagram),
            "an empty ring has room"
        );
        for (i, class) in [
            SideClass::Datagram,
            SideClass::Stream,
            SideClass::Datagram,
            SideClass::Stream,
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(
                face.forward_side(marked(60, i as u8 + 1), class),
                Ok(()),
                "frame {i} fits a ring of 4"
            );
        }
        for class in [SideClass::Datagram, SideClass::Stream] {
            assert_eq!(
                face.forward_side(marked(60, 9), class),
                Err(SideRefused::Full),
                "a full ring is refused, never waited on"
            );
        }
        assert!(
            !face.side_room(SideClass::Datagram),
            "a full ring has no room"
        );
        // send_side waits: nothing lands while the ring is full.
        let mut waiting = Box::pin(face.send_side(marked(61, 5), SideClass::Stream));
        assert!(
            tokio::time::timeout(Duration::from_millis(150), &mut waiting)
                .await
                .is_err(),
            "send_side on a full ring waits"
        );
        // The peer takes one frame: the waiting send lands behind the four.
        let first = handle.recv_bytes().await.unwrap();
        assert_eq!(first, marked(60, 1));
        tokio::time::timeout(Duration::from_secs(2), &mut waiting)
            .await
            .expect("room made, the waiting send completes")
            .unwrap();
        for want in [marked(60, 2), marked(60, 3), marked(60, 4), marked(61, 5)] {
            assert_eq!(handle.recv_bytes().await.unwrap(), want, "in order");
        }
        assert!(
            handle.try_recv().is_none(),
            "the refused frames were not pushed"
        );
    }

    /// `side_room_for` answers for the frame in hand with the refusals `forward_side` makes
    /// first: a full ring has no room for a frame it would take, and a frame it refuses another
    /// way (an NDN packet, one over a slot) is no frame to wait for room for, since waiting
    /// would end in the same refusal, later.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn side_room_for_a_frame_reads_what_forward_side_checks() {
        let (face, _handle) = anon_pair(94, 2, 100);
        let fits = marked(60, 1);
        let over = marked(101, 1);
        let ndn = Bytes::from_static(&[0x06, 0x05, 1, 2, 3, 4, 5]);
        for class in [SideClass::Datagram, SideClass::Stream] {
            assert!(face.side_room_for(&fits, class), "an empty ring has room");
        }
        for _ in 0..2 {
            assert_eq!(face.forward_side(fits.clone(), SideClass::Datagram), Ok(()));
        }
        for class in [SideClass::Datagram, SideClass::Stream] {
            assert!(!face.side_room_for(&fits, class), "a full ring has no room");
            assert!(
                face.side_room_for(&over, class),
                "TooLarge, not Full: nothing to wait for"
            );
            assert!(
                face.side_room_for(&ndn, class),
                "Malformed, not Full: nothing to wait for"
            );
        }
        assert_eq!(
            face.forward_side(over, SideClass::Datagram),
            Err(SideRefused::TooLarge {
                size: 101,
                max: 100
            })
        );
    }

    /// `forward_side` meets the same refusals as `send_side`: an NDN packet (first octet
    /// not the marker) is `Malformed`, a frame over a slot `TooLarge`, and nothing is pushed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_side_path_of_a_ring_refuses_ndn_packets_and_oversize_frames_on_both_calls() {
        let (face, handle) = anon_pair(92, 8, 100);
        let ndn = Bytes::from_static(&[0x06, 0x05, 1, 2, 3, 4, 5]);
        let over = marked(101, 1);
        for class in [SideClass::Datagram, SideClass::Stream] {
            assert_eq!(
                face.forward_side(ndn.clone(), class),
                Err(SideRefused::Malformed)
            );
            assert_eq!(
                face.send_side(ndn.clone(), class).await,
                Err(SideRefused::Malformed)
            );
            let too_large = SideRefused::TooLarge {
                size: 101,
                max: 100,
            };
            assert_eq!(
                face.forward_side(over.clone(), class),
                Err(too_large.clone())
            );
            assert_eq!(face.send_side(over.clone(), class).await, Err(too_large));
        }
        assert_eq!(
            face.forward_side(Bytes::new(), SideClass::Datagram),
            Err(SideRefused::Malformed),
            "an empty frame is not a side frame"
        );
        assert!(handle.try_recv().is_none());
    }

    /// A frame `forward_side` pushes wakes a reader that parked on the ring, as `send_side`
    /// does: a relay that only ever calls `forward_side` must not strand its peer.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn forward_side_wakes_a_parked_reader() {
        use std::time::Duration;
        let (face, handle) = anon_pair(93, 8, 128);
        let reading = tokio::spawn(async move { handle.recv_bytes().await });
        // Long enough for the reader to spin out and park on the wake pipe.
        tokio::time::sleep(Duration::from_millis(200)).await;
        face.forward_side(marked(50, 7), SideClass::Datagram)
            .unwrap();
        let got = tokio::time::timeout(Duration::from_secs(2), reading)
            .await
            .expect("the parked reader woke")
            .unwrap();
        assert_eq!(got, Some(marked(50, 7)));
    }

    /// `forward_side` is called from the reader tasks of every face that routes to this
    /// one while the face's own sender task pushes NDN packets: the ring has one producer
    /// in law and many in fact, so a push must be exclusive. Eight threads push 300 tagged
    /// frames each, half through `forward_side` and half through `send_bytes`, at once;
    /// the peer sees every frame once, intact, in each producer's own order.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_producers_never_tear_or_lose_a_frame() {
        use std::sync::Arc;
        use std::time::Duration;
        const PRODUCERS: usize = 8;
        const EACH: u32 = 300;
        let (face, handle) = anon_pair(94, 16, 64);
        let face = Arc::new(face);
        let tagged = |p: usize, seq: u32| {
            let mut v = vec![p as u8; 48];
            v[0] = ndn_transport::SIDE_MARKER;
            v[1..5].copy_from_slice(&seq.to_be_bytes());
            Bytes::from(v)
        };
        let rt = tokio::runtime::Handle::current();
        // Producers stop when the test ends, whichever way: a failed assertion must not
        // leave threads spinning on a ring nobody drains.
        struct Stop(Arc<std::sync::atomic::AtomicBool>);
        impl Drop for Stop {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Relaxed);
            }
        }
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let _stop_on_exit = Stop(Arc::clone(&stop));
        let mut pushers = Vec::new();
        for p in 0..PRODUCERS {
            let (face, rt, stop) = (Arc::clone(&face), rt.clone(), Arc::clone(&stop));
            pushers.push(tokio::task::spawn_blocking(move || {
                for seq in 0..EACH {
                    let frame = tagged(p, seq);
                    if p % 2 == 0 {
                        loop {
                            match face.forward_side(frame.clone(), SideClass::Datagram) {
                                Ok(()) => break,
                                Err(SideRefused::Full) if !stop.load(Ordering::Relaxed) => {
                                    std::thread::yield_now()
                                }
                                Err(_) => return,
                            }
                        }
                    } else if rt
                        .block_on(tokio::time::timeout(
                            Duration::from_secs(10),
                            face.send_bytes(frame),
                        ))
                        .is_err()
                    {
                        return;
                    }
                }
            }));
        }
        let mut next = [0u32; PRODUCERS];
        let reading = async {
            for _ in 0..PRODUCERS as u32 * EACH {
                let got = handle.recv_bytes().await.expect("the ring is open");
                assert_eq!(got.len(), 48, "a frame is whole");
                let p = got[5] as usize;
                assert!(
                    got[5..].iter().all(|b| *b == p as u8) && p < PRODUCERS,
                    "a frame is one producer's, not two interleaved"
                );
                let seq = u32::from_be_bytes(got[1..5].try_into().unwrap());
                assert_eq!(seq, next[p], "producer {p}'s frames arrive in its order");
                next[p] += 1;
            }
        };
        tokio::time::timeout(Duration::from_secs(30), reading)
            .await
            .expect("every frame arrived");
        for pusher in pushers {
            pusher.await.unwrap();
        }
        assert!(handle.try_recv().is_none(), "no frame twice");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn control_socket_handshake_round_trip() {
        use std::time::Duration;

        let token = mint_token().unwrap();
        let path = control_socket_path(&token); // derived from the token (Option A)
        let _ = std::fs::remove_file(&path);
        let listener = tokio::net::UnixListener::bind(&path).unwrap();

        let (face, fds) =
            SpscFace::create_anon_with(FaceId(88), DEFAULT_CAPACITY, DEFAULT_SLOT_SIZE).unwrap();

        // Engine serves the fds to the first client presenting the token.
        let server = tokio::spawn(serve_fd_handoff(listener, token, fds));

        // Client derives the same path from its token and connects.
        let cpath = path.clone();
        let handle = tokio::task::spawn_blocking(move || connect_fd_handoff(&cpath, &token))
            .await
            .unwrap()
            .expect("handshake");
        server.await.unwrap().expect("server handoff");

        // The handed-off ring works end to end.
        handle.send_bytes(Bytes::from_static(b"hi")).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(2), face.recv_bytes())
            .await
            .expect("timed out")
            .unwrap();
        assert_eq!(&got[..], b"hi");

        std::fs::remove_file(&path).ok();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn control_socket_survives_bad_then_serves_good() {
        use std::time::Duration;

        let token = mint_token().unwrap();
        let path = control_socket_path(&token);
        let _ = std::fs::remove_file(&path);
        let listener = tokio::net::UnixListener::bind(&path).unwrap();

        let (face, fds) =
            SpscFace::create_anon_with(FaceId(89), DEFAULT_CAPACITY, DEFAULT_SLOT_SIZE).unwrap();
        let server = tokio::spawn(serve_fd_handoff(listener, token, fds));

        // 1) A WRONG-token connector is rejected — but the loop keeps listening,
        //    so it does NOT consume the one-shot handoff.
        let bad_path = path.clone();
        let bad = tokio::task::spawn_blocking(move || connect_fd_handoff(&bad_path, &[0xAAu8; 32]))
            .await
            .unwrap();
        assert!(bad.is_err(), "wrong token must be refused the fds");

        // 2) The correct client is still served after the bad attempt.
        let good_path = path.clone();
        let handle = tokio::task::spawn_blocking(move || connect_fd_handoff(&good_path, &token))
            .await
            .unwrap()
            .expect("authorized client must still be served");
        server.await.unwrap().expect("server handoff");

        handle.send_bytes(Bytes::from_static(b"ok")).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(2), face.recv_bytes())
            .await
            .expect("timed out")
            .unwrap();
        assert_eq!(&got[..], b"ok");

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn control_socket_path_is_derived_and_hides_token() {
        let token = mint_token().unwrap();
        // Deterministic for a given token; different tokens → different paths.
        assert_eq!(control_socket_path(&token), control_socket_path(&token));
        assert_ne!(control_socket_path(&token), control_socket_path(&[0u8; 32]));
        // The visible filename must NOT contain the token (one-way hash).
        let name = control_socket_path(&token).to_string_lossy().to_string();
        let tok_hex: String = token.iter().map(|b| format!("{b:02x}")).collect();
        assert!(!name.contains(&tok_hex), "path must not leak the token");
    }

    // --- zero-copy large-buffer passing (SharedBuffer, G11 incr 3) ---

    #[test]
    fn shared_buffer_fd_passing_is_zero_copy() {
        use std::os::unix::net::UnixStream;

        // Producer fills a 1 MiB buffer in place (a stand-in render frame).
        let len = 1024 * 1024;
        let (mut buf, fd) = SharedBuffer::create(len).unwrap();
        assert_eq!(buf.len(), len);
        for (i, b) in buf.as_mut_slice().iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }

        // Hand the fd to the consumer (the SCM_RIGHTS utility the control socket
        // uses); the consumer maps and reads IN PLACE — no copy of the payload.
        let (a, b) = UnixStream::pair().unwrap();
        send_fds(a.as_raw_fd(), &[fd.as_raw_fd()]).unwrap();
        drop(fd);
        let recvd = recv_fds(b.as_raw_fd(), 1).unwrap();
        assert_eq!(recvd.len(), 1);

        let view = SharedBuffer::from_fd(recvd[0].as_raw_fd(), len).unwrap();
        let s = view.as_slice();
        assert_eq!(s.len(), len);
        assert_eq!(s[0], 0);
        assert_eq!(s[250], 250);
        assert_eq!(s[251], 0);
        assert_eq!(s[len - 1], ((len - 1) % 251) as u8);

        // Truly shared: a producer write after handoff is visible to the consumer
        // mapping (same physical pages, no copy).
        buf.as_mut_slice()[42] = 0xC3;
        assert_eq!(view.as_slice()[42], 0xC3);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn try_recv_busy_poll_round_trip() {
        let name = format!("{}-trecv", test_name());
        let face = SpscFace::create(FaceId(50), &name).unwrap();
        let handle = SpscHandle::connect(&name).unwrap();

        // Empty ring → None (non-blocking).
        assert!(face.try_recv().is_none());

        // handle → face: busy-poll until the packet appears.
        handle
            .send_bytes(Bytes::from_static(b"poll"))
            .await
            .unwrap();
        let got = loop {
            if let Some(p) = face.try_recv() {
                break p;
            }
            std::hint::spin_loop();
        };
        assert_eq!(&got[..], b"poll");

        // face → handle: busy-poll, consumed in place (zero-copy).
        face.send_bytes(Bytes::from_static(b"back")).await.unwrap();
        let n = loop {
            if let Some(n) = handle.try_recv_with(|s| s.len()) {
                break n;
            }
            std::hint::spin_loop();
        };
        assert_eq!(n, 4);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn send_with_zero_copy_produce() {
        use std::time::Duration;
        let name = format!("{}-swith", test_name());
        let face = SpscFace::create(FaceId(51), &name).unwrap();
        let handle = SpscHandle::connect(&name).unwrap();

        // Producer writes the payload directly into the a2e slot — no source
        // buffer, no memcpy.
        handle
            .send_with(5, |slot| slot.copy_from_slice(b"hello"))
            .await
            .unwrap();
        let got = tokio::time::timeout(Duration::from_secs(2), face.recv_bytes())
            .await
            .expect("timed out")
            .unwrap();
        assert_eq!(&got[..], b"hello");

        // e2a direction: produce in place, consume in place (fully zero-copy).
        face.send_with(3, |slot| {
            slot[0] = 1;
            slot[1] = 2;
            slot[2] = 3;
        })
        .await
        .unwrap();
        let v = tokio::time::timeout(Duration::from_secs(2), handle.recv_with(|s| s.to_vec()))
            .await
            .expect("timed out")
            .expect("closed");
        assert_eq!(v, vec![1, 2, 3]);
    }

    #[test]
    fn anon_region_names_do_not_collide() {
        // Two anonymous regions are independent (distinct mappings), and neither
        // lingers in the namespace (created O_EXCL + unlinked).
        let (r1, _f1) = ShmRegion::create_anon(4096).unwrap();
        let (r2, _f2) = ShmRegion::create_anon(4096).unwrap();
        unsafe {
            (r1.as_ptr() as *mut u32).write_unaligned(11);
            (r2.as_ptr() as *mut u32).write_unaligned(22);
            assert_eq!((r1.as_ptr() as *const u32).read_unaligned(), 11);
            assert_eq!((r2.as_ptr() as *const u32).read_unaligned(), 22);
        }
    }

    // ---- Broadcast ring (lossy SPMC) ----

    fn reader_from(writer: &BroadcastWriter) -> BroadcastReader {
        let (data, reg, wake, idx) = writer.register_consumer().unwrap();
        BroadcastReader::from_fds(data, reg, wake, idx).unwrap()
    }

    /// One producer fans out to N readers, each with an independent cursor; within
    /// the ring capacity every reader sees every frame, in order.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn broadcast_fans_out_to_all_readers() {
        let writer = BroadcastWriter::create(8, 64, 4).unwrap();
        let r0 = reader_from(&writer);
        let r1 = reader_from(&writer);
        let r2 = reader_from(&writer);
        assert_eq!(writer.consumer_count(), 3);

        for i in 0u32..5 {
            assert!(writer.publish(&i.to_le_bytes()));
        }
        for r in [&r0, &r1, &r2] {
            for i in 0u32..5 {
                let f = r.recv().await.unwrap();
                assert_eq!(u32::from_le_bytes(f.try_into().unwrap()), i);
            }
            assert_eq!(r.dropped(), 0);
        }
    }

    /// A reader that never keeps up is *lapped*: it loses the overrun frames (counted
    /// in `dropped`) and resumes at the oldest still-retained frame — the producer is
    /// never blocked.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn broadcast_drops_old_for_lagging_reader() {
        let writer = BroadcastWriter::create(4, 64, 1).unwrap();
        let r = reader_from(&writer); // cursor starts at 0

        for i in 0u32..10 {
            assert!(writer.publish(&i.to_le_bytes())); // never blocks; laps the reader
        }
        // Capacity 4 ⇒ only frames 6..10 remain; 0..6 were dropped.
        let mut got = Vec::new();
        while let Some(f) = r.try_recv() {
            got.push(u32::from_le_bytes(f.try_into().unwrap()));
        }
        assert_eq!(got, vec![6, 7, 8, 9]);
        assert_eq!(r.dropped(), 6);
    }

    /// Kernel-enforced single-writer: a consumer's data fd cannot be escalated to a
    /// writable mapping — it can read the producer's frames but never forge one.
    #[test]
    fn broadcast_consumer_cannot_write_data_region() {
        let writer = BroadcastWriter::create(4, 64, 1).unwrap();
        let (data_ro, _reg, _wake, _idx) = writer.register_consumer().unwrap();
        let attempt = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                bcast_data_size(4, 64),
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                data_ro.as_raw_fd(),
                0,
            )
        };
        let errno = std::io::Error::last_os_error().raw_os_error();
        assert_eq!(
            attempt,
            libc::MAP_FAILED,
            "writable mapping must be refused"
        );
        assert!(matches!(errno, Some(libc::EACCES) | Some(libc::EPERM)));
    }

    /// When the producer goes away, a parked reader's blocking `recv` returns `None`
    /// (wakeup-pipe EOF) — the broadcast end-of-stream signal.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn broadcast_end_of_stream_on_producer_drop() {
        let writer = BroadcastWriter::create(4, 64, 1).unwrap();
        let r = reader_from(&writer);
        writer.publish(&7u32.to_le_bytes());
        assert_eq!(
            u32::from_le_bytes(r.recv().await.unwrap().try_into().unwrap()),
            7
        );
        drop(writer); // closes the wake pipe write end
        assert!(r.recv().await.is_none(), "producer gone ⇒ end of stream");
    }

    /// The full socket handoff path: serve to two consumers over a control socket
    /// with mutual auth, then broadcast to both.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn broadcast_handoff_round_trip() {
        let token = mint_token().unwrap();
        let path = control_socket_path(&token);
        let _ = std::fs::remove_file(&path);
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let writer = std::sync::Arc::new(BroadcastWriter::create(8, 64, 4).unwrap());
        let serve = tokio::spawn(serve_broadcast_handoff(listener, token, writer.clone()));

        let mut readers = Vec::new();
        for _ in 0..2 {
            let p = path.clone();
            let (d, rg, w, idx) =
                tokio::task::spawn_blocking(move || connect_broadcast_handoff(&p, &token))
                    .await
                    .unwrap()
                    .unwrap();
            readers.push(BroadcastReader::from_fds(d, rg, w, idx).unwrap());
        }
        // Give the serve loop a moment to register both before publishing.
        for _ in 0..1000 {
            if writer.consumer_count() == 2 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(writer.consumer_count(), 2);

        for i in 0u32..3 {
            writer.publish(&i.to_le_bytes());
        }
        for r in &readers {
            for i in 0u32..3 {
                assert_eq!(
                    u32::from_le_bytes(r.recv().await.unwrap().try_into().unwrap()),
                    i
                );
            }
        }
        serve.abort();
        let _ = std::fs::remove_file(&path);
    }

    /// Env var that turns [`bad_peer_helper_process`] into the misbehaving peer.
    const BAD_PEER_ENV: &str = "NDN_SHM_TEST_BAD_PEER_SOCK";

    /// Not a test of its own: when re-executed by
    /// [`unauthorized_peer_does_not_lock_out_other_peers`] (env var set) this
    /// process is the misbehaving peer — a *different* pid from the test process,
    /// so a different credential. Its first `UNAUTH_PER_PEER_MAX` wrong-token
    /// handshakes are answered (`Ok(false)`); once over its bound the producer
    /// closes it without a handshake (`Err`).
    #[test]
    fn bad_peer_helper_process() {
        let Ok(path) = std::env::var(BAD_PEER_ENV) else {
            return;
        };
        let wrong = [0xAAu8; 32];
        let mut answered = 0u32;
        let mut cut_off = 0u32;
        for _ in 0..24 {
            let Ok(mut s) = std::os::unix::net::UnixStream::connect(&path) else {
                cut_off += 1;
                continue;
            };
            match mutual_auth_client(&mut s, &wrong) {
                Ok(false) => answered += 1,
                Ok(true) => panic!("wrong token authenticated"),
                Err(_) => cut_off += 1,
            }
        }
        println!("bad-peer-done answered={answered} cut_off={cut_off}");
    }

    /// One local process hammering the control socket with a wrong token must not
    /// stop the producer serving *other* processes (it used to give up after 16
    /// unauthorized connections, so any local process knowing the path could deny
    /// every later attach).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unauthorized_peer_does_not_lock_out_other_peers() {
        let token = mint_token().unwrap();
        let path = control_socket_path(&token);
        let _ = std::fs::remove_file(&path);
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let writer = std::sync::Arc::new(BroadcastWriter::create(8, 64, 4).unwrap());
        let serve = tokio::spawn(serve_broadcast_handoff(listener, token, writer.clone()));

        let sock = path.clone();
        let out = tokio::task::spawn_blocking(move || {
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "spsc::tests::bad_peer_helper_process",
                    "--nocapture",
                ])
                .env(BAD_PEER_ENV, sock)
                .output()
                .unwrap()
        })
        .await
        .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success(), "bad-peer helper failed: {stdout}");
        assert!(
            stdout.contains("bad-peer-done"),
            "bad-peer helper did not run: {stdout}"
        );

        // A different process (this one) still attaches.
        let p = path.clone();
        let attached = tokio::task::spawn_blocking(move || connect_broadcast_handoff(&p, &token))
            .await
            .unwrap();
        assert!(
            attached.is_ok(),
            "legitimate attach after another peer's bad connects failed: {:?}",
            attached.err()
        );
        assert!(!serve.is_finished(), "serve loop must keep running");
        serve.abort();
        let _ = std::fs::remove_file(&path);
    }

    fn proc_peer(uid: u32, pid: i32) -> Peer {
        Peer::Process {
            uid,
            pid: Some(pid),
        }
    }

    /// Fail `peer` until it is refused; returns the refusal from the failure that tripped it.
    fn trip(gate: &mut UnauthGate, peer: Peer, now: std::time::Instant) -> Refusal {
        for _ in 0..UNAUTH_PER_PEER_MAX - 1 {
            assert_eq!(gate.record_failure(peer, now), None, "tripped early");
        }
        gate.record_failure(peer, now)
            .expect("the failure that reaches the bound reports the refusal")
    }

    /// One peer over its bound is refused; another process (even of the same
    /// uid), another uid, and the unidentified bucket are unaffected.
    #[test]
    fn unauth_gate_refuses_only_the_offending_peer() {
        let t0 = std::time::Instant::now();
        let mut gate = UnauthGate::new();
        let bad = proc_peer(1000, 4242);
        assert!(gate.admit(bad, t0).is_ok());
        let r = trip(&mut gate, bad, t0);
        assert_eq!(r.scope, Scope::Process(bad));
        assert_eq!(gate.admit(bad, t0).unwrap_err().scope, Scope::Process(bad));
        assert!(
            gate.admit(proc_peer(1000, 4243), t0).is_ok(),
            "same uid, other pid"
        );
        assert!(gate.admit(proc_peer(1001, 4242), t0).is_ok(), "other uid");
        assert!(gate.admit(Peer::Unidentified, t0).is_ok());
    }

    /// Forking to change pid keeps the uid counter: once the uid's total reaches
    /// the larger bound, every process of that uid is refused, other uids not.
    #[test]
    fn unauth_gate_uid_bound_stops_pid_cycling() {
        let t0 = std::time::Instant::now();
        let mut gate = UnauthGate::new();
        let mut tripped = None;
        for i in 0..UNAUTH_PER_UID_MAX {
            // one failure per fresh pid: no per-process bound is ever reached
            let r = gate.record_failure(proc_peer(1000, 100 + i as i32), t0);
            if r.is_some() {
                tripped = r;
            }
        }
        assert_eq!(tripped.expect("uid bound reached").scope, Scope::Uid(1000));
        assert!(
            gate.admit(proc_peer(1000, 99_999), t0).is_err(),
            "a never-seen pid of the offending uid is refused"
        );
        assert!(gate.admit(proc_peer(1001, 100), t0).is_ok());
    }

    /// Peers whose credential cannot be read share one bucket with the
    /// per-process bound; identified peers are not affected by it.
    #[test]
    fn unauth_gate_unidentified_peers_share_a_bounded_bucket() {
        let t0 = std::time::Instant::now();
        let mut gate = UnauthGate::new();
        trip(&mut gate, Peer::Unidentified, t0);
        assert_eq!(
            gate.admit(Peer::Unidentified, t0).unwrap_err().scope,
            Scope::Process(Peer::Unidentified)
        );
        assert!(gate.admit(proc_peer(1000, 1), t0).is_ok());
    }

    /// The counter table has a hard size bound however many distinct peers
    /// fail, and eviction takes the oldest counter (a tripped peer whose window
    /// is oldest is forgotten first; a recent one is kept).
    #[test]
    fn unauth_gate_table_stays_bounded_and_evicts_oldest() {
        let t0 = std::time::Instant::now();
        let mut gate = UnauthGate::new();
        let oldest = proc_peer(5, 1);
        trip(&mut gate, oldest, t0);
        let mut newest = oldest;
        for i in 0..(UNAUTH_TABLE_MAX as u32 * 3) {
            // distinct uid per peer so both its counters are new entries
            newest = proc_peer(10_000 + i, 1);
            gate.record_failure(
                newest,
                t0 + std::time::Duration::from_micros(1 + u64::from(i)),
            );
            assert!(
                gate.len() <= UNAUTH_TABLE_MAX,
                "table grew to {} (max {UNAUTH_TABLE_MAX})",
                gate.len()
            );
        }
        assert!(
            gate.admit(oldest, t0 + std::time::Duration::from_secs(1))
                .is_ok(),
            "the oldest counter was evicted"
        );
        // a peer tripped now is retained and refused
        let late = proc_peer(9, 9);
        let at = t0 + std::time::Duration::from_secs(2);
        trip(&mut gate, late, at);
        assert!(gate.admit(late, at).is_err());
        assert!(gate.len() <= UNAUTH_TABLE_MAX);
        let _ = newest;
    }

    /// A refused peer is served again once its window (from the first failure,
    /// monotonic clock) has passed, and then has a fresh allowance.
    #[test]
    fn unauth_gate_serves_peer_again_after_window() {
        let t0 = std::time::Instant::now();
        let mut gate = UnauthGate::new();
        let peer = proc_peer(1000, 7);
        let later = t0 + std::time::Duration::from_secs(5);
        for _ in 0..UNAUTH_PER_PEER_MAX - 1 {
            gate.record_failure(peer, t0);
        }
        gate.record_failure(peer, later); // reaches the bound; does not extend the window
        let almost = t0 + UNAUTH_WINDOW - std::time::Duration::from_millis(1);
        let r = gate.admit(peer, almost).unwrap_err();
        assert_eq!(r.retry_in, std::time::Duration::from_millis(1));
        // knocking while refused doesn't move the window either
        assert!(gate.admit(peer, almost).is_err());
        let reopened = t0 + UNAUTH_WINDOW;
        assert!(gate.admit(peer, reopened).is_ok(), "window passed");
        // fresh allowance: one failure doesn't trip it again
        assert_eq!(gate.record_failure(peer, reopened), None);
        assert!(gate.admit(peer, reopened).is_ok());
    }
}
