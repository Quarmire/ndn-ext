//! G11 demo — **named zero-copy frame pipeline** + IPC round-trip latency.
//!
//! Two measurements, producer ↔ a real consumer *process*:
//!
//! 1. **Round-trip latency.** A busy-polled shared-memory ping-pong (an atomic
//!    sequence in a [`SharedBuffer`], no syscalls) — the data-plane floor — vs a
//!    Unix-socket ping-pong for contrast. This is the honest "how fast is the IPC
//!    itself" number (the throughput demo below signals frames over the *socket*
//!    for simplicity, so its per-frame cost is the socket round-trip, NOT this).
//!
//! 2. **Large-frame delivery throughput.** COPY (frame bytes written over the
//!    socket, consumer copies out) vs ZERO-COPY (the frame lives in a
//!    `SharedBuffer` mapped once; per frame only a `/demo/frames/v=N` signal
//!    crosses and the consumer reads in place). The NDF compositor seam.
//!
//! Run: `cargo run -p ndn-face-shm --example zero_copy_frames --release`

#[cfg(unix)]
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if let Some(pos) = args.iter().position(|a| a == "--consumer") {
        consumer(&args[pos + 1]);
    } else {
        producer();
    }
}

#[cfg(not(unix))]
fn main() {
    eprintln!("this demo is Unix-only");
}

#[cfg(unix)]
const FRAMES: u32 = 200;
#[cfg(unix)]
const SIZES: &[usize] = &[1 << 20, 8 << 20, 64 << 20]; // 1, 8, 64 MiB
#[cfg(unix)]
const LAT_WARMUP: u64 = 1000;
#[cfg(unix)]
const LAT_ITERS: u64 = 100_000;
#[cfg(unix)]
const SOCK_ITERS: usize = 20_000;
#[cfg(unix)]
const PING: usize = 0; // producer → consumer (own cache line)
#[cfg(unix)]
const PONG: usize = 64; // consumer → producer (own cache line)

#[cfg(unix)]
fn producer() {
    use ndn_face_shm::{SharedBuffer, send_fds};
    use std::io::{Read, Write};
    use std::os::unix::io::AsRawFd;
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Instant;

    let path = format!("/tmp/.ndn-zc-demo-{}.sock", std::process::id());
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).unwrap();
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--consumer")
        .arg(&path)
        .spawn()
        .expect("spawn consumer");
    let (mut sock, _) = listener.accept().unwrap();

    // ---- 1. round-trip latency ------------------------------------------
    let (mut ctrl, fd) = SharedBuffer::create(128).unwrap();
    for b in ctrl.as_mut_slice().iter_mut() {
        *b = 0;
    }
    let base = ctrl.as_mut_slice().as_mut_ptr();
    send_fds(sock.as_raw_fd(), &[fd.as_raw_fd()]).unwrap();
    drop(fd);
    // SAFETY: page-aligned mapping; PING/PONG are 8-aligned, touched only atomically.
    let ping = unsafe { AtomicU64::from_ptr(base as *mut u64) };
    let pong = unsafe { AtomicU64::from_ptr(base.add(PONG) as *mut u64) };

    let total = LAT_WARMUP + LAT_ITERS;
    let mut shm = Vec::with_capacity(LAT_ITERS as usize);
    for i in 1..=total {
        let t = Instant::now();
        ping.store(i, Ordering::Release);
        while pong.load(Ordering::Acquire) != i {
            std::hint::spin_loop();
        }
        if i > LAT_WARMUP {
            shm.push(t.elapsed().as_nanos());
        }
    }

    let mut sk = Vec::with_capacity(SOCK_ITERS);
    let ping_byte = [0u8; 8];
    for _ in 0..SOCK_ITERS {
        let t = Instant::now();
        sock.write_all(&ping_byte).unwrap();
        let mut r = [0u8; 8];
        sock.read_exact(&mut r).unwrap();
        sk.push(t.elapsed().as_nanos());
    }

    println!("round-trip latency, two processes  (lower = better)\n");
    println!("  {:<36} {:>8} {:>9} {:>9}", "", "min", "median", "p99");
    println!("  {}", "-".repeat(66));
    report("shared-memory busy-poll (the floor)", &mut shm);
    report("unix socket (for contrast)", &mut sk);
    println!(
        "\n  The SHM data plane round-trips in nanoseconds; the socket is ~10-30x\n  \
         slower (2 syscalls + a context switch). Busy-poll trades a core for the\n  \
         floor; the ring's spin-then-park path is sub-µs hot, a few µs when parked.\n"
    );

    // ---- 2. large-frame delivery throughput -----------------------------
    println!("large-frame delivery — {FRAMES} frames/size, two processes\n");
    println!(
        "  {:>9}  {:>13}  {:>13}  {:>8}   socket bytes (copy → zero-copy)",
        "frame", "copy", "zero-copy", "speedup"
    );
    println!("  {}", "-".repeat(86));
    for &len in SIZES {
        sock.write_all(&(len as u64).to_le_bytes()).unwrap();
        sock.write_all(&FRAMES.to_le_bytes()).unwrap();

        let mut frame = vec![0u8; len];
        for (i, b) in frame.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }

        let t = Instant::now();
        for _ in 0..FRAMES {
            sock.write_all(&frame).unwrap();
            let mut ack = [0u8; 1];
            sock.read_exact(&mut ack).unwrap();
        }
        let copy = t.elapsed();

        let (mut buf, fd) = SharedBuffer::create(len).unwrap();
        buf.as_mut_slice().copy_from_slice(&frame);
        send_fds(sock.as_raw_fd(), &[fd.as_raw_fd()]).unwrap();
        drop(fd);
        let t = Instant::now();
        for n in 0..FRAMES {
            sock.write_all(&n.to_le_bytes()).unwrap();
            let mut ack = [0u8; 1];
            sock.read_exact(&mut ack).unwrap();
        }
        let zc = t.elapsed();

        let speedup = copy.as_secs_f64() / zc.as_secs_f64().max(1e-9);
        println!(
            "  {:>5} MiB  {:>13.2?}  {:>13.2?}  {:>7.0}x   {} → {}",
            len >> 20,
            copy,
            zc,
            speedup,
            human(FRAMES as u64 * len as u64),
            human(FRAMES as u64 * 4),
        );
    }

    let _ = std::fs::remove_file(&path);
    let _ = child.wait();
}

#[cfg(unix)]
fn consumer(sock_path: &str) {
    use ndn_face_shm::{SharedBuffer, recv_fds};
    use std::hint::black_box;
    use std::io::{Read, Write};
    use std::os::unix::io::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::sync::atomic::{AtomicU64, Ordering};

    let mut sock = UnixStream::connect(sock_path).unwrap();

    // ---- 1. latency: echo the ping-pong ----
    let fds = recv_fds(sock.as_raw_fd(), 1).unwrap();
    let mut ctrl = SharedBuffer::from_fd(fds[0].as_raw_fd(), 128).unwrap();
    let base = ctrl.as_mut_slice().as_mut_ptr();
    let ping = unsafe { AtomicU64::from_ptr(base as *mut u64) };
    let pong = unsafe { AtomicU64::from_ptr(base.add(PONG) as *mut u64) };
    let total = LAT_WARMUP + LAT_ITERS;
    let mut last = 0u64;
    loop {
        let p = ping.load(Ordering::Acquire);
        if p != last {
            last = p;
            pong.store(p, Ordering::Release);
            if p >= total {
                break;
            }
        } else {
            std::hint::spin_loop();
        }
    }
    for _ in 0..SOCK_ITERS {
        let mut r = [0u8; 8];
        if sock.read_exact(&mut r).is_err() {
            return;
        }
        sock.write_all(&r).unwrap();
    }

    // ---- 2. throughput ----
    let mut sink = 0u64;
    loop {
        let mut lb = [0u8; 8];
        if sock.read_exact(&mut lb).is_err() {
            break;
        }
        let len = u64::from_le_bytes(lb) as usize;
        let mut fb = [0u8; 4];
        sock.read_exact(&mut fb).unwrap();
        let frames = u32::from_le_bytes(fb);

        let mut scratch = vec![0u8; len];
        for _ in 0..frames {
            sock.read_exact(&mut scratch).unwrap();
            sink = sink
                .wrapping_add(scratch[0] as u64)
                .wrapping_add(scratch[len - 1] as u64);
            sock.write_all(&[1u8]).unwrap();
        }

        let fds = recv_fds(sock.as_raw_fd(), 1).unwrap();
        let view = SharedBuffer::from_fd(fds[0].as_raw_fd(), len).unwrap();
        for _ in 0..frames {
            let mut nb = [0u8; 4];
            sock.read_exact(&mut nb).unwrap();
            let s = view.as_slice();
            sink = sink.wrapping_add(s[0] as u64).wrapping_add(s[len - 1] as u64);
            sock.write_all(&[1u8]).unwrap();
        }
    }
    let _ = PING; // (named for documentation; PONG carries the echo)
    black_box(sink);
}

#[cfg(unix)]
fn report(label: &str, s: &mut [u128]) {
    s.sort_unstable();
    let pct = |p: f64| s[(((s.len() as f64) * p) as usize).min(s.len() - 1)];
    println!(
        "  {:<36} {:>6} ns {:>6} ns {:>6} ns",
        label,
        s[0],
        pct(0.50),
        pct(0.99),
    );
}

#[cfg(unix)]
fn human(bytes: u64) -> String {
    const U: &[&str] = &["B", "KiB", "MiB", "GiB"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    format!("{v:.1} {}", U[i])
}
