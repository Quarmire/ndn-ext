//! G11 demo — **named zero-copy frame pipeline**.
//!
//! A producer hands large frames to a consumer *process* two ways and times the
//! delivery (the part the IPC is responsible for; the render/fill cost is common
//! to both and excluded):
//!
//! - **COPY** — the frame bytes are written over a Unix socket and the consumer
//!   copies them out. This is what a socket data plane (or the old copy-at-the-
//!   seam SHM ring) costs: the payload crosses the socket and is memcpy'd.
//! - **ZERO-COPY** — the frame lives in a [`SharedBuffer`] mapped **once** into
//!   both processes (its fd passed once via `SCM_RIGHTS` — the capability). Per
//!   frame only a tiny "frame ready" signal crosses; the consumer reads the bytes
//!   **in place**. No payload copy, and the payload never crosses the socket.
//!
//! Each frame is named (`/demo/frames/v=N`) — the buffer is delivered as *named
//! data* with the bytes carried by fd: the NDF compositor / render-session seam.
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
fn producer() {
    use ndn_face_shm::{SharedBuffer, send_fds};
    use std::io::{Read, Write};
    use std::os::unix::io::AsRawFd;
    use std::os::unix::net::UnixListener;
    use std::time::Instant;

    let path = format!("/tmp/.ndn-zc-demo-{}.sock", std::process::id());
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).unwrap();

    // Spawn ourselves as the consumer in a SEPARATE PROCESS.
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--consumer")
        .arg(&path)
        .spawn()
        .expect("spawn consumer");
    let (mut sock, _) = listener.accept().unwrap();

    println!("named zero-copy frame pipeline — {FRAMES} frames/size, two processes\n");
    println!(
        "  {:>9}  {:>13}  {:>13}  {:>8}   socket bytes (copy → zero-copy)",
        "frame", "copy", "zero-copy", "speedup"
    );
    println!("  {}", "-".repeat(86));

    for &len in SIZES {
        sock.write_all(&(len as u64).to_le_bytes()).unwrap();
        sock.write_all(&FRAMES.to_le_bytes()).unwrap();

        // A "rendered" frame, prepared once — delivery is what we measure.
        let mut frame = vec![0u8; len];
        for (i, b) in frame.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }

        // --- COPY: write the whole frame over the socket each time ---
        let t = Instant::now();
        for _ in 0..FRAMES {
            sock.write_all(&frame).unwrap();
            let mut ack = [0u8; 1];
            sock.read_exact(&mut ack).unwrap();
        }
        let copy = t.elapsed();

        // --- ZERO-COPY: map a SharedBuffer once, pass its fd once ---
        let (mut buf, fd) = SharedBuffer::create(len).unwrap();
        buf.as_mut_slice().copy_from_slice(&frame); // the frame, in shared memory
        send_fds(sock.as_raw_fd(), &[fd.as_raw_fd()]).unwrap();
        drop(fd);
        let t = Instant::now();
        for n in 0..FRAMES {
            // Per frame only a name/seq crosses — never the payload.
            sock.write_all(&n.to_le_bytes()).unwrap();
            let mut ack = [0u8; 1];
            sock.read_exact(&mut ack).unwrap();
        }
        let zc = t.elapsed();

        let speedup = copy.as_secs_f64() / zc.as_secs_f64().max(1e-9);
        let copy_bytes = FRAMES as u64 * len as u64;
        let zc_bytes = FRAMES as u64 * 4;
        println!(
            "  {:>5} MiB  {:>13.2?}  {:>13.2?}  {:>7.0}x   {} → {}",
            len >> 20,
            copy,
            zc,
            speedup,
            human(copy_bytes),
            human(zc_bytes),
        );
    }
    println!(
        "\n  Zero-copy delivers each frame as named data with the bytes by fd —\n  \
         the payload never crosses the socket and the consumer never copies it."
    );

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

    let mut sock = UnixStream::connect(sock_path).unwrap();
    let mut sink = 0u64;
    loop {
        let mut lb = [0u8; 8];
        if sock.read_exact(&mut lb).is_err() {
            break; // producer done
        }
        let len = u64::from_le_bytes(lb) as usize;
        let mut fb = [0u8; 4];
        sock.read_exact(&mut fb).unwrap();
        let frames = u32::from_le_bytes(fb);

        // COPY: each frame is read (copied) out of the socket.
        let mut scratch = vec![0u8; len];
        for _ in 0..frames {
            sock.read_exact(&mut scratch).unwrap();
            sink = sink
                .wrapping_add(scratch[0] as u64)
                .wrapping_add(scratch[len - 1] as u64);
            sock.write_all(&[1u8]).unwrap();
        }

        // ZERO-COPY: map the buffer once, then read each frame IN PLACE.
        let fds = recv_fds(sock.as_raw_fd(), 1).unwrap();
        let view = SharedBuffer::from_fd(fds[0].as_raw_fd(), len).unwrap();
        for _ in 0..frames {
            let mut nb = [0u8; 4];
            sock.read_exact(&mut nb).unwrap();
            let s = view.as_slice(); // borrowed from shared memory — no copy
            sink = sink.wrapping_add(s[0] as u64).wrapping_add(s[len - 1] as u64);
            sock.write_all(&[1u8]).unwrap();
        }
    }
    black_box(sink);
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
