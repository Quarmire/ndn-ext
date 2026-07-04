//! G11 APPLIED TEST #6 — bake-off: the `ndn-surface` facade vs the incumbent IPC a
//! developer would otherwise hand-roll (a Unix-domain socket with length-prefix
//! framing). Same workload — publish N frames of size S under a name, read them all
//! — measured the same way (two tokio tasks, steady-state throughput).
//!
//! The question isn't only "is SHM faster than a socket" (it is); it's *what you
//! pay or gain* for named-data ergonomics. The socket baseline gives raw bytes:
//! no names, no zero-copy, manual framing, one consumer. The surface gives NDN-named
//! frames, zero-copy local reads, a large-payload path that never copies through the
//! kernel, plus (not exercised here) capability auth, fan-out, and remote
//! transparency behind the *same* calls.
//!
//! Run: `cargo run -p ndn-surface --example bakeoff --release`

use std::time::{Duration, Instant};

use iceoryx2::prelude::*;
use ndn_surface::{NamedPublisher, NamedSubscriber};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// iceoryx2: the flagship Rust zero-copy shared-memory IPC. Typed publish/subscribe
/// over a preallocated SHM pool; the subscriber reads samples in place (zero-copy).
/// Its ports are `!Send` (single-threaded arc policy), so this drives publish +
/// receive on one thread, keeping in-flight within the buffer (paced, lossless) —
/// a measure of iceoryx2's per-operation send+receive cost.
fn bench_iox(service_name: String, frame: usize, n: usize) -> Duration {
    const BUF: usize = 64;
    let node = NodeBuilder::new().create::<ipc::Service>().unwrap();
    let service = node
        .service_builder(&service_name.as_str().try_into().unwrap())
        .publish_subscribe::<[u8]>()
        .max_publishers(1)
        .max_subscribers(1)
        .subscriber_max_buffer_size(BUF)
        .create()
        .unwrap();
    let publisher = service
        .publisher_builder()
        .initial_max_slice_len(frame)
        .create()
        .unwrap();
    let subscriber = service.subscriber_builder().create().unwrap();

    let start = Instant::now();
    let mut sent = 0usize;
    let mut got = 0usize;
    while got < n {
        // Send a burst up to BUF ahead of what's been received (no overflow).
        while sent < n && sent - got < BUF {
            let sample = publisher.loan_slice_uninit(frame).unwrap();
            let sample = sample.write_from_fn(|_| 0xAB);
            sample.send().unwrap();
            sent += 1;
        }
        // Drain everything available, reading each sample in place (zero-copy).
        while subscriber.receive().unwrap().is_some() {
            got += 1;
        }
    }
    start.elapsed()
}

/// Incumbent: a Unix-domain socket with a 4-byte LE length prefix. Raw bytes,
/// copied into the kernel on send and out into a Vec on receive. No names.
async fn bench_socket(frame: usize, n: usize) -> Duration {
    let (mut tx, mut rx) = tokio::net::UnixStream::pair().unwrap();
    let payload = vec![0xABu8; frame];
    let start = Instant::now();
    let prod = tokio::spawn(async move {
        for _ in 0..n {
            tx.write_all(&(payload.len() as u32).to_le_bytes())
                .await
                .unwrap();
            tx.write_all(&payload).await.unwrap();
        }
        tx.flush().await.unwrap();
    });
    let mut buf = vec![0u8; frame];
    let mut lenb = [0u8; 4];
    for _ in 0..n {
        rx.read_exact(&mut lenb).await.unwrap();
        let l = u32::from_le_bytes(lenb) as usize;
        rx.read_exact(&mut buf[..l]).await.unwrap();
    }
    let elapsed = start.elapsed();
    prod.await.unwrap();
    elapsed
}

/// Surface, streaming path: each frame is a real NDN Data encoded in place into the
/// SHM ring; the consumer reads it back zero-copy (borrowed). Ring sized for the
/// frame so the pipeline is deep.
async fn bench_surface_stream(name: &str, frame: usize, n: usize) -> Duration {
    let slot = (frame + 256).max(2048);
    let mut pubr = NamedPublisher::open_with_max_frame(name, slot)
        .await
        .unwrap();
    let mut sub = NamedSubscriber::connect(name).await.unwrap();
    let payload = vec![0xABu8; frame];
    let start = Instant::now();
    let prod = tokio::spawn(async move {
        for _ in 0..n {
            pubr.publish(&payload).await.unwrap();
        }
        pubr.close().await.unwrap();
    });
    let mut got = 0usize;
    while sub.next_frame(|f| f.content.len()).await.is_some() {
        got += 1;
    }
    let elapsed = start.elapsed();
    prod.await.unwrap();
    assert_eq!(got, n);
    elapsed
}

/// Surface, local (sealed) path: hash-free frames over the sealed ring (data mapped
/// read-only — forge-proof). Uniform `publish`; for in-host same-trust-domain IPC.
async fn bench_surface_local(name: &str, frame: usize, n: usize) -> Duration {
    let mut pubr = NamedPublisher::open_local_with_max_frame(name, frame)
        .await
        .unwrap();
    let mut sub = NamedSubscriber::connect_local(name).await.unwrap();
    let payload = vec![0xABu8; frame];
    let start = Instant::now();
    let prod = tokio::spawn(async move {
        for _ in 0..n {
            pubr.publish(&payload).await.unwrap();
        }
        pubr.close().await.unwrap();
    });
    let mut got = 0usize;
    while sub.next_frame(|f| f.content.len()).await.is_some() {
        got += 1;
    }
    let elapsed = start.elapsed();
    prod.await.unwrap();
    assert_eq!(got, n);
    elapsed
}

/// Surface, large path: each frame is an anonymous-shm SharedBuffer whose fd is
/// passed over the side channel; the consumer maps and reads it in place. The
/// payload never traverses the kernel socket buffer.
async fn bench_surface_large(name: &str, frame: usize, n: usize) -> Duration {
    let mut pubr = NamedPublisher::open_large(name).await.unwrap();
    let mut sub = NamedSubscriber::connect_large(name).await.unwrap();
    let start = Instant::now();
    let prod = tokio::spawn(async move {
        for _ in 0..n {
            // Write-in-place: no producer-side copy — fill the SharedBuffer directly.
            pubr.publish_large_with(frame, |slot| slot.fill(0xAB))
                .await
                .unwrap();
        }
        pubr.close().await.unwrap();
    });
    let mut got = 0usize;
    while sub.next_frame(|f| f.content.len()).await.is_some() {
        got += 1;
    }
    let elapsed = start.elapsed();
    prod.await.unwrap();
    assert_eq!(got, n);
    elapsed
}

/// Attribution probe: the raw SHM ring with NO NDN Data encode — push `frame`
/// bytes straight into the slot, read length back. Isolates the ring + async +
/// two-task cost from the per-frame Data encoding (name + SHA-256).
async fn bench_surface_raw(frame: usize, n: usize) -> Duration {
    use ndn_face_shm::{
        ShmFace, connect_fd_handoff, control_socket_path, mint_token, serve_fd_handoff,
    };
    use ndn_transport::FaceId;
    let token = mint_token().unwrap();
    let (face, fds) = ShmFace::create_anon_for_mtu(FaceId(0), frame + 64).unwrap();
    let path = control_socket_path(&token);
    let _ = std::fs::remove_file(&path);
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let t = token;
    let serve = tokio::spawn(async move {
        let _ = serve_fd_handoff(listener, t, fds).await;
    });
    let p = path.clone();
    let handle = tokio::task::spawn_blocking(move || {
        loop {
            if let Ok(h) = connect_fd_handoff(&p, &token) {
                break h;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    })
    .await
    .unwrap();
    let _ = serve.await;

    let payload = vec![0xABu8; frame];
    let start = Instant::now();
    let prod = tokio::spawn(async move {
        for _ in 0..n {
            face.send_with(frame, |s| s.copy_from_slice(&payload))
                .await
                .unwrap();
        }
        face // keep alive
    });
    let mut got = 0usize;
    while got < n {
        if handle.recv_with(|s| s.len()).await.is_some() {
            got += 1;
        } else {
            break;
        }
    }
    let elapsed = start.elapsed();
    let _ = prod.await.unwrap();
    let _ = std::fs::remove_file(&path);
    elapsed
}

fn mbps(frame: usize, n: usize, d: Duration) -> f64 {
    (frame as f64 * n as f64) / d.as_secs_f64() / 1e6
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    // Roughly constant data volume per row so small frames aren't under-sampled.
    let target_bytes = 256usize << 20;
    let sizes = [1024usize, 65_536, 1_048_576, 4_194_304];

    // Warm up paths (alloc, first-touch, socket/shm setup) off the clock.
    let _ = bench_socket(4096, 200).await;
    let _ = bench_surface_stream("/bench/warm", 4096, 200).await;
    let _ = bench_surface_large("/bench/warmlarge", 1 << 20, 8).await;
    let _ = tokio::task::spawn_blocking(|| bench_iox("bench/warm/iox".into(), 4096, 200)).await;

    let _ = bench_surface_local("/bench/warmlocal", 4096, 200).await;
    let _ = bench_surface_raw(4096, 200).await;

    println!("\n  throughput, MB/s (higher is better)\n");
    println!(
        "  {:>9} | {:>7} | {:>9} | {:>9} | {:>9} | {:>9} | {:>9} | {:>9}",
        "frame", "N", "socket", "surf", "surf-local", "surf-raw", "surf-lg", "iceoryx2"
    );
    println!("  {}", "-".repeat(96));

    for (i, &frame) in sizes.iter().enumerate() {
        let n = (target_bytes / frame).clamp(50, 200_000);

        let d_sock = bench_socket(frame, n).await;
        let d_surf = bench_surface_stream(&format!("/bench/s/{i}"), frame, n).await;
        let d_fast = bench_surface_local(&format!("/bench/f/{i}"), frame, n).await;
        let d_raw = bench_surface_raw(frame, n).await;
        let d_large = if frame >= 65_536 {
            Some(bench_surface_large(&format!("/bench/l/{i}"), frame, n).await)
        } else {
            None
        };
        let iox_name = format!("bench/iox/{i}");
        let d_iox = tokio::task::spawn_blocking(move || bench_iox(iox_name, frame, n))
            .await
            .unwrap();

        let fr = if frame >= 1 << 20 {
            format!("{} MiB", frame >> 20)
        } else {
            format!("{} KiB", frame >> 10)
        };
        let large_cell = match d_large {
            Some(d) => format!("{:.0}", mbps(frame, n, d)),
            None => "-".to_string(),
        };
        println!(
            "  {:>9} | {:>7} | {:>9.0} | {:>9.0} | {:>9.0} | {:>9.0} | {:>9} | {:>9.0}",
            fr,
            n,
            mbps(frame, n, d_sock),
            mbps(frame, n, d_surf),
            mbps(frame, n, d_fast),
            mbps(frame, n, d_raw),
            large_cell,
            mbps(frame, n, d_iox),
        );
    }
    println!(
        "\n  socket   = Unix stream + 4B length prefix (raw bytes, no names, copy both ends)\n  \
         surf     = streaming, signed NDN Data (name + SHA-256 per frame, zero-copy read)\n  \
         surf-local= sealed ring, hash-free frame, forge-proof (consumer maps data read-only)\n  \
         surf-raw = the bare ring, no Data encode at all (attribution upper bound)\n  \
         surf-lg  = open_large/publish_large (SharedBuffer fd, payload skips the kernel)\n  \
         iceoryx2 = typed zero-copy pub/sub over a preallocated SHM pool (no names, paced lossless)\n"
    );
}
