//! What a peer of a shared-memory ring — a reader of the broadcast ring, the application end of a
//! face's ring, a process that finds the control socket — can and cannot do to the process that
//! owns it. Each test is an attack that a hostile or broken peer can make with what it is handed,
//! and asserts the owner survives it and says why it refused.
//!
//! Linux-only where the guarantee is a kernel one (memfd seals).
#![cfg(unix)]
// Raw fds, mappings and /proc reopens are what these tests do on purpose.
#![allow(unsafe_code)]

use std::ffi::CString;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use bytes::Bytes;
use ndn_face_shm::ring_carrier::{RING_READERS, capability_token, control_path};
use ndn_face_shm::{RingFace, ShmFace as SpscFace, connect_broadcast_handoff};
use ndn_foundation_types::Name;
use ndn_transport::{FaceError, FaceId, SIDE_MARKER, SideClass, Transport};

const SECRET: [u8; 32] = [0x5a; 32];

fn ring_name(tag: &str) -> Name {
    format!(
        "/ring-hardening/{}/{tag}/32=chan/32=ring/00ff",
        std::process::id()
    )
    .parse()
    .unwrap()
}

/// A channel frame of `len` octets, tagged `n`.
fn frame(len: usize, n: u8) -> Bytes {
    let mut v = vec![n; len];
    v[0] = SIDE_MARKER;
    Bytes::from(v)
}

async fn recv(face: &RingFace) -> Result<Bytes, FaceError> {
    tokio::time::timeout(Duration::from_secs(3), face.recv_bytes())
        .await
        .expect("a frame within 3 s")
}

/// The fds a reader is handed, as a raw process of the same uid that holds the secret gets them:
/// `(data, registry, wake, index)`.
async fn raw_attach(name: &Name) -> (OwnedFd, OwnedFd, OwnedFd, u32) {
    let path = control_path(name);
    let cap = capability_token(name, &SECRET);
    tokio::task::spawn_blocking(move || connect_broadcast_handoff(&path, &cap))
        .await
        .unwrap()
        .expect("a raw attach with the secret")
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn size_of_fd(fd: RawFd) -> usize {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::fstat(fd, &mut st) }, 0);
    st.st_size as usize
}

/// Map all of `fd` writable and set every octet from `from` on to `byte`: what a process that
/// holds a registry fd read-write can do to everything it can reach through it. Returns the
/// octets it reached.
fn scribble(fd: RawFd, from: usize, byte: u8) -> usize {
    let size = size_of_fd(fd);
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
    assert_ne!(p, libc::MAP_FAILED, "a reader maps its registry read-write");
    unsafe {
        std::ptr::write_bytes((p as *mut u8).add(from), byte, size - from);
        libc::munmap(p, size);
    }
    size
}

// ---------------------------------------------------------------------------------------------
// H3: the data region is unwritable by any reader, of the same uid too.
// ---------------------------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_same_uid_reader_cannot_reopen_the_data_fd_read_write_and_write_or_truncate_the_ring() {
    let name = ring_name("h3");
    let writer = RingFace::offer(FaceId(1), &name, &SECRET, 200)
        .await
        .unwrap();
    let reader = RingFace::attach(FaceId(2), &name, &SECRET).await.unwrap();
    let (data, _reg, _wake, _idx) = raw_attach(&name).await;

    // The fd the reader holds is the writer's object; a process of the same uid can open it again
    // through /proc with the access it wants. What it can then DO is what the ring depends on.
    let path = CString::new(format!("/proc/self/fd/{}", data.as_raw_fd())).unwrap();
    let rw = unsafe { libc::open(path.as_ptr(), libc::O_RDWR) };
    if rw >= 0 {
        let forged = [0xAAu8; 64];
        let n = unsafe { libc::pwrite(rw, forged.as_ptr().cast(), forged.len(), 200) };
        assert!(
            n == -1 && errno() == libc::EPERM,
            "write(2) through a /proc reopen of the data fd must be refused with EPERM, got {n} \
             (errno {})",
            errno()
        );
        let m = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                rw,
                0,
            )
        };
        assert!(
            m == libc::MAP_FAILED && errno() == libc::EPERM,
            "a writable mapping through the reopened data fd must be refused with EPERM (errno {})",
            errno()
        );
        let t = unsafe { libc::ftruncate(rw, 0) };
        assert!(
            t == -1 && errno() == libc::EPERM,
            "ftruncate through the reopened data fd must be refused with EPERM, got {t} (errno {})",
            errno()
        );
        unsafe { libc::close(rw) };
    }
    // The fd as handed out refuses the same.
    let t = unsafe { libc::ftruncate(data.as_raw_fd(), 0) };
    assert!(
        t == -1 && errno() == libc::EPERM,
        "ftruncate of the data fd as handed out must be refused with EPERM, got {t} (errno {})",
        errno()
    );
    let m = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            data.as_raw_fd(),
            0,
        )
    };
    assert!(
        m == libc::MAP_FAILED && errno() == libc::EPERM,
        "a writable mapping of the data fd as handed out must be refused with EPERM (errno {})",
        errno()
    );

    // And the ring is what the writer wrote.
    writer
        .send_side(frame(60, 4), SideClass::Datagram)
        .await
        .unwrap();
    assert_eq!(recv(&reader).await.unwrap(), frame(60, 4));
}

// ---------------------------------------------------------------------------------------------
// H2: a reader cannot shrink a region under the writer, reach another reader's registry page, or
// poison the header a later attach reads.
// ---------------------------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reader_cannot_truncate_its_registry_fd_and_the_writer_and_the_others_carry_on() {
    let name = ring_name("h2a");
    let writer = RingFace::offer(FaceId(1), &name, &SECRET, 200)
        .await
        .unwrap();
    let b = RingFace::attach(FaceId(2), &name, &SECRET).await.unwrap();
    let (_data, reg_a, _wake, _idx) = raw_attach(&name).await;

    let r = unsafe { libc::ftruncate(reg_a.as_raw_fd(), 0) };
    assert!(
        r == -1 && errno() == libc::EPERM,
        "ftruncate(0) of a reader's registry fd must be refused with EPERM (a region sealed \
         against shrinking), got {r} (errno {})",
        errno()
    );
    // The writer touches every reader's registry on a publish: it must not fault.
    writer
        .send_side(frame(80, 1), SideClass::Datagram)
        .await
        .unwrap();
    assert_eq!(recv(&b).await.unwrap(), frame(80, 1));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reader_cannot_clear_another_readers_wake_flag() {
    let name = ring_name("h2b");
    let writer = RingFace::offer(FaceId(1), &name, &SECRET, 200)
        .await
        .unwrap();
    let b = Arc::new(RingFace::attach(FaceId(2), &name, &SECRET).await.unwrap());
    let (_data, reg_a, _wake, _idx) = raw_attach(&name).await;

    // B has nothing to read and parks on its wakeup pipe, setting its `parked` word.
    let waiting = {
        let b = Arc::clone(&b);
        tokio::spawn(async move { b.recv_bytes().await })
    };
    tokio::time::sleep(Duration::from_millis(300)).await;

    // A writes zero over everything it can reach through its registry fd, so far as it goes.
    scribble(reg_a.as_raw_fd(), 0, 0);

    writer
        .send_side(frame(80, 2), SideClass::Datagram)
        .await
        .unwrap();
    let got = tokio::time::timeout(Duration::from_secs(3), waiting)
        .await
        .expect("B woken by the publish although A zeroed its registry")
        .unwrap();
    assert_eq!(got.unwrap(), frame(80, 2));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reader_that_corrupts_its_registry_header_does_not_stop_a_later_attach() {
    let name = ring_name("h2c");
    let writer = RingFace::offer(FaceId(1), &name, &SECRET, 200)
        .await
        .unwrap();
    let (_data, reg_a, _wake, _idx) = raw_attach(&name).await;

    // The whole header (magic, max readers, index): every octet set.
    scribble(reg_a.as_raw_fd(), 0, 0xFF);

    let third = RingFace::attach(FaceId(3), &name, &SECRET)
        .await
        .expect("a third attach must succeed after a reader corrupted the registry header");
    writer
        .send_side(frame(90, 3), SideClass::Datagram)
        .await
        .unwrap();
    assert_eq!(recv(&third).await.unwrap(), frame(90, 3));
}

/// A reader refuses a region its owner did not seal: a peer that can still resize it can fault
/// the reader, and one that can still write the data region can forge what readers see.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reader_refuses_a_region_that_is_not_sealed() {
    use ndn_face_shm::BroadcastReader;

    fn plain_memfd(size: usize) -> OwnedFd {
        use std::os::fd::FromRawFd;
        let fd = unsafe {
            libc::memfd_create(
                c"unsealed".as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
            )
        };
        assert!(fd >= 0);
        assert_eq!(unsafe { libc::ftruncate(fd, size as libc::off_t) }, 0);
        unsafe { OwnedFd::from_raw_fd(fd) }
    }
    fn pipe_read_end() -> OwnedFd {
        use std::os::fd::FromRawFd;
        let mut p = [0 as RawFd; 2];
        assert_eq!(unsafe { libc::pipe(p.as_mut_ptr()) }, 0);
        unsafe { libc::close(p[1]) };
        unsafe { OwnedFd::from_raw_fd(p[0]) }
    }

    let err =
        BroadcastReader::from_fds(plain_memfd(1 << 16), plain_memfd(4096), pipe_read_end(), 0)
            .err()
            .expect("an unsealed data region must be refused");
    let text = err.to_string();
    assert!(
        text.contains("not sealed"),
        "an unsealed data region must be refused for being unsealed, got: {text}"
    );
}

// ---------------------------------------------------------------------------------------------
// M9: a peer of a face's ring cannot pin the engine's thread, spin its sender, or fault it.
// ---------------------------------------------------------------------------------------------

const OFF_A2E_TAIL: usize = 64;
const OFF_E2A_HEAD: usize = 256;

/// Map the whole region of a face as the application end does, read-write.
fn map_region(fd: RawFd) -> *mut u8 {
    let size = size_of_fd(fd);
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
    assert_ne!(p, libc::MAP_FAILED);
    p as *mut u8
}

fn word(base: *mut u8, off: usize) -> &'static AtomicU32 {
    unsafe { AtomicU32::from_ptr(base.add(off) as *mut u32) }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_peer_that_writes_an_out_of_range_tail_closes_the_face_with_a_reason() {
    let (face, fds) = SpscFace::create_anon_with(FaceId(5), 16, 256).unwrap();
    let [region, _a2e_write, _e2a_read] = fds;
    let base = map_region(region.as_raw_fd());

    // The head is 0; a tail 2^31 ahead is 2^31 unread slots in a ring of 16.
    word(base, OFF_A2E_TAIL).store(0x8000_0000, Ordering::Release);

    let got = tokio::time::timeout(Duration::from_secs(2), face.recv_bytes())
        .await
        .expect("recv_bytes must return, not pop garbage for ever");
    assert!(
        matches!(got, Err(FaceError::Closed)),
        "a write cursor 2^31 ahead of the read cursor must close the face, got {:?}",
        got.map(|b| b.len())
    );
    let why = face
        .closed_reason()
        .expect("a face closed on a corrupt ring says why");
    assert!(
        why.contains("write cursor") && why.contains("restart the peer"),
        "the reason must name the cursors and say what to do, got: {why}"
    );
    // And it stays closed.
    assert!(matches!(face.recv_bytes().await, Err(FaceError::Closed)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_peer_that_writes_an_out_of_range_read_cursor_closes_the_face_instead_of_waiting_for_room()
 {
    let (face, fds) = SpscFace::create_anon_with(FaceId(6), 16, 256).unwrap();
    let [region, _a2e_write, _e2a_read] = fds;
    let base = map_region(region.as_raw_fd());

    // The application's read cursor of the engine's ring, set far from anything it could be.
    word(base, OFF_E2A_HEAD).store(0xFFFF_0000, Ordering::Release);

    let sent = tokio::time::timeout(
        Duration::from_secs(2),
        face.send_bytes(Bytes::from_static(b"\x05\x01\x00")),
    )
    .await
    .expect("send_bytes must fail, not wait for room that never comes");
    assert!(
        matches!(sent, Err(FaceError::Closed)),
        "a read cursor out of range must close the face, got {sent:?}"
    );
    assert!(face.closed_reason().is_some());
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_peer_cannot_truncate_the_region_of_a_face() {
    let (_face, fds) = SpscFace::create_anon_with(FaceId(7), 16, 256).unwrap();
    let [region, _a2e_write, _e2a_read] = fds;
    let r = unsafe { libc::ftruncate(region.as_raw_fd(), 0) };
    assert!(
        r == -1 && errno() == libc::EPERM,
        "ftruncate(0) of the region fd a peer holds must be refused with EPERM (sealed against \
         shrinking: the engine would fault on its next access), got {r} (errno {})",
        errno()
    );
}

/// A ring the peer has filled — within its bounds, so nothing is corrupt — holds the reader for as
/// many packets as it has slots, with nothing in between to await. A reader task must give the
/// thread up long before that, so the tasks beside it run.
#[tokio::test(flavor = "current_thread")]
async fn a_peer_that_fills_a_big_ring_does_not_hold_the_thread_of_the_reader_for_all_of_it() {
    const SLOTS: u32 = 1 << 16;
    let (face, fds) = SpscFace::create_anon_with(FaceId(8), SLOTS, 8).unwrap();
    let [region, _a2e_write, _e2a_read] = fds;
    let base = map_region(region.as_raw_fd());
    word(base, OFF_A2E_TAIL).store(SLOTS, Ordering::Release);

    let popped = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let counted = Arc::clone(&popped);
    let reader = tokio::spawn(async move {
        while face.recv_bytes().await.is_ok() {
            counted.fetch_add(1, Ordering::Relaxed);
        }
    });
    // A task that can only run when the reader gives the thread up: it reports how many packets
    // the reader had handed out by then.
    let seen = Arc::clone(&popped);
    let beside = tokio::spawn(async move { seen.load(Ordering::Relaxed) });
    let before_beside = beside.await.unwrap();
    reader.abort();
    assert!(
        before_beside < 1000,
        "a task beside the reader ran only after the reader had popped {before_beside} of the \
         {SLOTS} packets in the ring: it held the thread for all of them"
    );
}

// ---------------------------------------------------------------------------------------------
// M10: the control socket cannot be wedged by a peer without the key, and a failure with one
// connection never ends it.
// ---------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_connection_that_sends_nothing_does_not_keep_a_later_attach_from_being_served() {
    let name = ring_name("silent");
    let writer = RingFace::offer(FaceId(1), &name, &SECRET, 200)
        .await
        .unwrap();
    // Connects to the public control path and says nothing, for as long as the test runs.
    let _silent = std::os::unix::net::UnixStream::connect(control_path(&name)).unwrap();

    let reader = tokio::time::timeout(
        Duration::from_secs(3),
        RingFace::attach(FaceId(2), &name, &SECRET),
    )
    .await
    .expect("an attach must be served while a silent peer holds a connection")
    .expect("the attach succeeds");
    writer
        .send_side(frame(70, 5), SideClass::Datagram)
        .await
        .unwrap();
    assert_eq!(recv(&reader).await.unwrap(), frame(70, 5));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_peer_that_authenticates_and_leaves_does_not_end_the_serve_loop() {
    let name = ring_name("leaves");
    let writer = RingFace::offer(FaceId(1), &name, &SECRET, 200)
        .await
        .unwrap();
    for _ in 0..5 {
        let path = control_path(&name);
        let cap = capability_token(&name, &SECRET);
        tokio::task::spawn_blocking(move || {
            // Whatever the owner's state, what is asserted is the later attach, below.
            if let Ok(mut s) = std::os::unix::net::UnixStream::connect(path) {
                let _ = ndn_face_shm::mutual_auth_client(&mut s, &cap);
            }
            // Drops without taking the fds.
        })
        .await
        .unwrap();
    }
    let reader = RingFace::attach(FaceId(2), &name, &SECRET)
        .await
        .expect("a legitimate attach after peers that authenticated and left");
    writer
        .send_side(frame(70, 6), SideClass::Datagram)
        .await
        .unwrap();
    assert_eq!(recv(&reader).await.unwrap(), frame(70, 6));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_writer_probing_a_live_name_is_not_counted_as_an_unauthorized_attempt() {
    let name = ring_name("probe");
    let writer = RingFace::offer(FaceId(1), &name, &SECRET, 200)
        .await
        .unwrap();
    // More second offers than the per-peer bound of unauthorized connections (16): each probes
    // the socket by connecting and closing.
    for _ in 0..24 {
        match RingFace::offer(FaceId(2), &name, &SECRET, 200).await {
            Err(e) => assert!(
                e.to_string().contains("already serves"),
                "a second offer of a live name is AlreadyServed, got: {e}"
            ),
            Ok(_) => panic!("a live ring's name was taken over"),
        }
    }
    let reader = RingFace::attach(FaceId(3), &name, &SECRET)
        .await
        .expect("a legitimate attach is served after the probes");
    writer
        .send_side(frame(70, 7), SideClass::Datagram)
        .await
        .unwrap();
    assert_eq!(recv(&reader).await.unwrap(), frame(70, 7));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_attach_to_a_socket_that_never_answers_fails_saying_so() {
    let name = ring_name("squat");
    let path = control_path(&name);
    // A squatter: bound at the ring's path, never accepts.
    let _squatter = std::os::unix::net::UnixListener::bind(&path).unwrap();

    let started = std::time::Instant::now();
    let r = tokio::time::timeout(
        Duration::from_secs(10),
        RingFace::attach(FaceId(1), &name, &SECRET),
    )
    .await
    .expect("an attach to a silent owner must fail within its handshake deadline, not hang");
    let Err(e) = r else {
        panic!("a socket that never answers handed out a ring")
    };
    let text = e.to_string();
    assert!(
        text.contains("did not answer"),
        "the refusal must say the owner did not answer, got: {text}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(8),
        "and within the deadline: {:?}",
        started.elapsed()
    );
    let _ = std::fs::remove_file(&path);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_ring_with_every_reader_slot_taken_says_so_keeps_serving_and_reuses_a_slot_a_reader_left()
{
    let name = ring_name("slots");
    let writer = RingFace::offer(FaceId(1), &name, &SECRET, 200)
        .await
        .unwrap();
    let mut readers = Vec::new();
    for i in 0..RING_READERS {
        readers.push(
            RingFace::attach(FaceId(10 + i as u64), &name, &SECRET)
                .await
                .unwrap_or_else(|e| panic!("attach {i} of {RING_READERS}: {e}")),
        );
    }
    assert_eq!(writer.readers(), RING_READERS as usize);

    let started = std::time::Instant::now();
    let Err(e) = RingFace::attach(FaceId(99), &name, &SECRET).await else {
        panic!(
            "attach {} was given a place on a ring with {RING_READERS}",
            RING_READERS + 1
        )
    };
    let text = e.to_string();
    assert!(
        text.contains("no free reader slots") && text.contains("ask the owner to restart"),
        "the refusal must say there is no free slot and what to do, got: {text}"
    );
    assert!(
        started.elapsed() < Duration::from_millis(1500),
        "a refusal is final at once, not retried: {:?}",
        started.elapsed()
    );

    // The loop is alive, and a place a reader left is free again.
    drop(readers.remove(0));
    let again = RingFace::attach(FaceId(100), &name, &SECRET)
        .await
        .expect("an attach after a reader left takes its place");
    writer
        .send_side(frame(70, 8), SideClass::Datagram)
        .await
        .unwrap();
    assert_eq!(recv(&again).await.unwrap(), frame(70, 8));
    assert_eq!(recv(&readers[0]).await.unwrap(), frame(70, 8));
}
