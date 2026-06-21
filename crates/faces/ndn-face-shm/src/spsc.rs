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
use std::ffi::CString;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use bytes::Bytes;

use ndn_transport::{FaceError, FaceId, FaceKind, Transport};

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

/// Ring capacity that keeps total ring memory within [`SHM_BUDGET`];
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

fn shm_total_size(capacity: u32, slot_size: u32) -> usize {
    HEADER_SIZE + 2 * capacity as usize * slot_stride(slot_size)
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
        let ptr = unsafe {
            let fd = libc::shm_open(
                cname.as_ptr(),
                libc::O_CREAT | libc::O_RDWR | libc::O_TRUNC,
                // 0o666 so an unprivileged app can connect to a router
                // running as root; the SHM name is per app instance.
                0o666 as libc::mode_t as libc::c_uint,
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

    /// Create an **anonymous**, capability-scoped SHM region: `shm_open` a
    /// high-entropy `O_EXCL` name at `0o600`, map it, then `shm_unlink` the name
    /// *immediately* so the region survives only through the returned fd — it
    /// never lingers in `/dev/shm` for another process to list/open. The fd is
    /// then handed to the peer out-of-band via `SCM_RIGHTS` ([`send_fds`]).
    ///
    /// This is the portable stand-in for Linux `memfd_create` (which is absent on
    /// macOS, the dev target): `O_CREAT|O_EXCL` + a retry loop defeats name
    /// pre-creation, and the immediate unlink + `0o600` close the `/dev/shm`
    /// listing leak the named-region path has.
    fn create_anon(size: usize) -> Result<(Self, OwnedFd), ShmError> {
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

/// Returns `None` if empty.
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
) -> Option<Bytes> {
    let tail_a = unsafe { AtomicU32::from_ptr(base.add(tail_off) as *mut u32) };
    let head_a = unsafe { AtomicU32::from_ptr(base.add(head_off) as *mut u32) };

    let h = head_a.load(Ordering::Relaxed);
    let t = tail_a.load(Ordering::Acquire);
    if h == t {
        return None;
    }

    let idx = (h % capacity) as usize;
    let slot = unsafe { base.add(ring_off + idx * slot_stride(slot_size)) };

    let len = unsafe { (slot as *const u32).read_unaligned() as usize };
    let len = len.min(slot_size as usize);
    let data = unsafe { Bytes::copy_from_slice(std::slice::from_raw_parts(slot.add(4), len)) };

    head_a.store(h.wrapping_add(1), Ordering::Release);
    Some(data)
}

/// **Zero-copy consume:** borrow the head slot's payload in place, run `f` on it,
/// then advance head — no intermediate `Bytes` allocation/`memcpy` (unlike
/// [`ring_pop`]). The borrow is confined to `f`'s execution and head is advanced
/// only after `f` returns, so the single producer cannot overwrite the slot
/// mid-read (it cannot reuse this index until head passes it). `None` if empty.
///
/// For a consumer that processes-and-discards within `f` (e.g. a renderer, a
/// digest, or a streaming sink) this removes the slot→heap copy. It is NOT for a
/// consumer that must *retain* the bytes past `f` (e.g. forwarding into a PIT/CS,
/// which must own the Data beyond the transient slot) — use [`ring_pop`] there.
///
/// # Safety
/// Same as [`ring_pop`].
unsafe fn ring_peek_consume<R>(
    base: *mut u8,
    ring_off: usize,
    tail_off: usize,
    head_off: usize,
    capacity: u32,
    slot_size: u32,
    f: impl FnOnce(&[u8]) -> R,
) -> Option<R> {
    let tail_a = unsafe { AtomicU32::from_ptr(base.add(tail_off) as *mut u32) };
    let head_a = unsafe { AtomicU32::from_ptr(base.add(head_off) as *mut u32) };

    let h = head_a.load(Ordering::Relaxed);
    let t = tail_a.load(Ordering::Acquire);
    if h == t {
        return None;
    }

    let idx = (h % capacity) as usize;
    let slot = unsafe { base.add(ring_off + idx * slot_stride(slot_size)) };
    let len = unsafe { (slot as *const u32).read_unaligned() as usize };
    let len = len.min(slot_size as usize);
    let out = {
        let view = unsafe { std::slice::from_raw_parts(slot.add(4), len) };
        f(view)
    };
    head_a.store(h.wrapping_add(1), Ordering::Release);
    Some(out)
}

/// Send file descriptors to a connected Unix-socket peer via `SCM_RIGHTS`,
/// alongside one byte of normal data (the kernel requires ancillary data to
/// ride with ≥1 data byte). Up to 8 fds in one message. This is how an
/// anonymous ([`ShmRegion::create_anon`]) region + its wakeup channels are
/// handed to the peer **without ever appearing in a shared namespace**.
fn send_fds(sock: RawFd, fds: &[RawFd]) -> std::io::Result<()> {
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
/// buffer was truncated (which would silently leak the in-flight fds).
fn recv_fds(sock: RawFd, max: usize) -> std::io::Result<Vec<OwnedFd>> {
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
    let r = unsafe { libc::getentropy(t.as_mut_ptr() as *mut libc::c_void, t.len()) };
    if r != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(t)
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

/// **Engine side of the Option-A handshake:** accept ONE client on `listener`,
/// require it to present `token`, then hand it the face's three fds
/// (`[region, a2e_write, e2a_read]` from [`SpscFace::create_anon_with`]) via
/// `SCM_RIGHTS`. The socket may be world-connectable — **the token is the
/// capability** (constant-time compared), so an unauthorized connector receives
/// nothing. Async accept; the brief blocking `SCM_RIGHTS` exchange runs on a
/// blocking task so it never stalls the runtime.
pub async fn serve_fd_handoff(
    listener: &tokio::net::UnixListener,
    token: ShmToken,
    fds: [OwnedFd; 3],
) -> std::io::Result<()> {
    let (stream, _addr) = listener.accept().await?;
    let std_stream = stream.into_std()?;
    std_stream.set_nonblocking(false)?;
    tokio::task::spawn_blocking(move || -> std::io::Result<()> {
        use std::io::Read;
        let mut s = std_stream;
        let mut tok = [0u8; 32];
        s.read_exact(&mut tok)?;
        if !ct_eq(&tok, &token) {
            return Err(std::io::Error::other("shm control: token mismatch"));
        }
        send_fds(
            s.as_raw_fd(),
            &[fds[0].as_raw_fd(), fds[1].as_raw_fd(), fds[2].as_raw_fd()],
        )
    })
    .await
    .map_err(|e| std::io::Error::other(format!("shm control handoff task: {e}")))?
}

/// **Client side of the Option-A handshake:** connect to the control socket at
/// `path`, present `token`, receive the face's three fds, and build the
/// [`SpscHandle`]. Blocking — call via `spawn_blocking` from async code.
pub fn connect_fd_handoff(path: &std::path::Path, token: &ShmToken) -> Result<SpscHandle, ShmError> {
    use std::io::Write;
    let mut s = std::os::unix::net::UnixStream::connect(path).map_err(ShmError::Io)?;
    s.write_all(token).map_err(ShmError::Io)?;
    let mut fds = recv_fds(s.as_raw_fd(), 3).map_err(ShmError::Io)?;
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
    // `None` for an anonymous (fd-passed) face: it has no named FIFOs to unlink —
    // its wakeup channels are anonymous pipes received over the control socket.
    a2e_pipe_path: Option<PathBuf>,
    e2a_pipe_path: Option<PathBuf>,
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
            a2e_pipe_path: Some(a2e_path),
            e2a_pipe_path: Some(e2a_path),
        })
    }

    /// Create an **anonymous, capability-scoped** face: an fd-only SHM region
    /// ([`ShmRegion::create_anon`]) + two anonymous wakeup pipes — **no named SHM
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
            a2e_pipe_path: None,
            e2a_pipe_path: None,
        };
        Ok((face, [region_fd, a2e_w, e2a_r]))
    }

    fn try_pop_a2e(&self) -> Option<Bytes> {
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
    }

    /// Cheap, allocation-free check: is there a packet waiting in the a2e ring?
    /// Sole-consumer invariant: if this returns `true`, a following
    /// [`Self::try_peek_consume_a2e`] is guaranteed to find the packet (only we
    /// remove from this ring; the producer can only add).
    fn a2e_has_data(&self) -> bool {
        let tail =
            unsafe { AtomicU32::from_ptr(self.shm.as_ptr().add(OFF_A2E_TAIL) as *mut u32) };
        let head =
            unsafe { AtomicU32::from_ptr(self.shm.as_ptr().add(OFF_A2E_HEAD) as *mut u32) };
        head.load(Ordering::Relaxed) != tail.load(Ordering::Acquire)
    }

    fn try_peek_consume_a2e<R>(&self, f: impl FnOnce(&[u8]) -> R) -> Option<R> {
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
    }

    fn try_push_e2a(&self, data: &[u8]) -> bool {
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
            if self.a2e_has_data() {
                return Ok(self.try_peek_consume_a2e(f.take().unwrap()).expect("data present"));
            }
            for _ in 0..SPIN_ITERS {
                std::hint::spin_loop();
                if self.a2e_has_data() {
                    return Ok(self.try_peek_consume_a2e(f.take().unwrap()).expect("data present"));
                }
            }
            parked.store(1, Ordering::SeqCst);
            if self.a2e_has_data() {
                parked.store(0, Ordering::Relaxed);
                return Ok(self.try_peek_consume_a2e(f.take().unwrap()).expect("data present"));
            }
            pipe_await(&self.a2e_rx).await.map_err(|_| FaceError::Closed)?;
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

    async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
        let parked =
            unsafe { AtomicU32::from_ptr(self.shm.as_ptr().add(OFF_A2E_PARKED) as *mut u32) };
        loop {
            if let Some(pkt) = self.try_pop_a2e() {
                return Ok(pkt);
            }
            for _ in 0..SPIN_ITERS {
                std::hint::spin_loop();
                if let Some(pkt) = self.try_pop_a2e() {
                    return Ok(pkt);
                }
            }
            // SeqCst orders this against the app's ring push so the wakeup
            // is never missed.
            parked.store(1, Ordering::SeqCst);
            // Recheck: catches pushes between the first check and the flag store.
            if let Some(pkt) = self.try_pop_a2e() {
                parked.store(0, Ordering::Relaxed);
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
            tokio::task::yield_now().await;
        }
        if parked.load(Ordering::SeqCst) != 0 {
            pipe_write(&self.e2a_tx);
        }
        Ok(())
    }
}

pub struct SpscHandle {
    shm: ShmRegion,
    capacity: u32,
    slot_size: u32,
    a2e_off: usize,
    e2a_off: usize,
    e2a_rx: tokio::io::unix::AsyncFd<std::os::unix::io::OwnedFd>,
    a2e_tx: std::os::unix::io::OwnedFd,
    cancel: tokio_util::sync::CancellationToken,
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

        let size = shm_total_size(capacity, slot_size);
        // Defensive bound: even though the region is handed by a trusted (token-
        // gated) peer, refuse an absurd geometry rather than mmap gigabytes.
        if size > 256 * 1024 * 1024 {
            return Err(ShmError::InvalidMagic);
        }
        let shm = ShmRegion::from_fd(region_fd.as_raw_fd(), size)?;
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
        unsafe {
            ring_pop(
                self.shm.as_ptr(),
                self.e2a_off,
                OFF_E2A_TAIL,
                OFF_E2A_HEAD,
                self.capacity,
                self.slot_size,
            )
        }
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

    fn e2a_has_data(&self) -> bool {
        let tail =
            unsafe { AtomicU32::from_ptr(self.shm.as_ptr().add(OFF_E2A_TAIL) as *mut u32) };
        let head =
            unsafe { AtomicU32::from_ptr(self.shm.as_ptr().add(OFF_E2A_HEAD) as *mut u32) };
        head.load(Ordering::Relaxed) != tail.load(Ordering::Acquire)
    }

    fn try_peek_consume_e2a<R>(&self, f: impl FnOnce(&[u8]) -> R) -> Option<R> {
        unsafe {
            ring_peek_consume(
                self.shm.as_ptr(),
                self.e2a_off,
                OFF_E2A_TAIL,
                OFF_E2A_HEAD,
                self.capacity,
                self.slot_size,
                f,
            )
        }
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
            if self.e2a_has_data() {
                return self.try_peek_consume_e2a(f.take().unwrap());
            }
            for _ in 0..SPIN_ITERS {
                std::hint::spin_loop();
                if self.e2a_has_data() {
                    return self.try_peek_consume_e2a(f.take().unwrap());
                }
            }
            parked.store(1, Ordering::SeqCst);
            if self.e2a_has_data() {
                parked.store(0, Ordering::Relaxed);
                return self.try_peek_consume_e2a(f.take().unwrap());
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

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_transport::Transport;

    fn test_name() -> String {
        format!("test-spsc-{}", std::process::id())
    }

    // multi_thread runtime so AsyncFd can use the I/O driver.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn face_kind_and_id() {
        let name = test_name();
        let face = SpscFace::create(FaceId(7), &name).unwrap();
        assert_eq!(face.id(), FaceId(7));
        assert_eq!(face.kind(), FaceKind::Shm);
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

        handle.send_bytes(Bytes::from_static(b"first")).await.unwrap();
        handle.send_bytes(Bytes::from_static(b"second")).await.unwrap();

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
        assert_eq!(seen, 0xFEED_FACE_DEAD_BEEF, "fd-passed region must share memory");

        // Write through the peer mapping, read through the original → truly shared.
        unsafe {
            (mapped.as_ptr().add(8) as *mut u32).write_unaligned(0x1234_5678);
        }
        let back = unsafe { (region.as_ptr().add(8) as *const u32).read_unaligned() };
        assert_eq!(back, 0x1234_5678, "writes through the fd mapping must be shared");
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn control_socket_handshake_round_trip() {
        use std::time::Duration;

        let path = std::env::temp_dir().join(format!("ndn-shm-ctl-rt-{}.sock", test_name()));
        let _ = std::fs::remove_file(&path);
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let token = mint_token().unwrap();

        let (face, fds) =
            SpscFace::create_anon_with(FaceId(88), DEFAULT_CAPACITY, DEFAULT_SLOT_SIZE).unwrap();

        // Engine serves the fds to the first client presenting the token.
        let server = tokio::spawn(async move { serve_fd_handoff(&listener, token, fds).await });

        // Client connects + presents the token (blocking helper on a blocking task).
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
    async fn control_socket_rejects_wrong_token() {
        let path = std::env::temp_dir().join(format!("ndn-shm-ctl-wt-{}.sock", test_name()));
        let _ = std::fs::remove_file(&path);
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let token = mint_token().unwrap();

        let (_face, fds) =
            SpscFace::create_anon_with(FaceId(89), DEFAULT_CAPACITY, DEFAULT_SLOT_SIZE).unwrap();
        let server = tokio::spawn(async move { serve_fd_handoff(&listener, token, fds).await });

        // A client presenting the WRONG token gets no fds.
        let wrong = [0xAAu8; 32];
        let cpath = path.clone();
        let res = tokio::task::spawn_blocking(move || connect_fd_handoff(&cpath, &wrong))
            .await
            .unwrap();
        assert!(res.is_err(), "wrong token must be refused the fds");
        assert!(server.await.unwrap().is_err(), "server must reject a bad token");

        std::fs::remove_file(&path).ok();
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
}
