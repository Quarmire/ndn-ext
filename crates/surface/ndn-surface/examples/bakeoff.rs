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

use ndn_surface::{NamedPublisher, NamedSubscriber};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Incumbent: a Unix-domain socket with a 4-byte LE length prefix. Raw bytes,
/// copied into the kernel on send and out into a Vec on receive. No names.
async fn bench_socket(frame: usize, n: usize) -> Duration {
    let (mut tx, mut rx) = tokio::net::UnixStream::pair().unwrap();
    let payload = vec![0xABu8; frame];
    let start = Instant::now();
    let prod = tokio::spawn(async move {
        for _ in 0..n {
            tx.write_all(&(payload.len() as u32).to_le_bytes()).await.unwrap();
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
    let mut pubr = NamedPublisher::open_with_max_frame(name, slot).await.unwrap();
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

/// Surface, large path: each frame is an anonymous-shm SharedBuffer whose fd is
/// passed over the side channel; the consumer maps and reads it in place. The
/// payload never traverses the kernel socket buffer.
async fn bench_surface_large(name: &str, frame: usize, n: usize) -> Duration {
    let mut pubr = NamedPublisher::open_large(name).await.unwrap();
    let mut sub = NamedSubscriber::connect_large(name).await.unwrap();
    let payload = vec![0xABu8; frame];
    let start = Instant::now();
    let prod = tokio::spawn(async move {
        for _ in 0..n {
            pubr.publish_large(&payload).await.unwrap();
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

fn mbps(frame: usize, n: usize, d: Duration) -> f64 {
    (frame as f64 * n as f64) / d.as_secs_f64() / 1e6
}
fn per_frame_us(n: usize, d: Duration) -> f64 {
    d.as_secs_f64() * 1e6 / n as f64
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    // Roughly constant data volume per row so small frames aren't under-sampled.
    let target_bytes = 256usize << 20;
    let sizes = [1024usize, 65_536, 1_048_576, 4_194_304];

    // Warm up paths (alloc, first-touch, socket setup) off the clock.
    let _ = bench_socket(4096, 200).await;
    let _ = bench_surface_stream("/bench/warm", 4096, 200).await;
    let _ = bench_surface_large("/bench/warmlarge", 1 << 20, 8).await;

    println!(
        "\n  {:>9} | {:>6} | {:>12} {:>10} | {:>12} {:>10} | {:>12} {:>10}",
        "frame", "N", "socket MB/s", "us/frame", "surf MB/s", "us/frame", "surf-lg MB/s", "us/frame"
    );
    println!("  {}", "-".repeat(96));

    for (i, &frame) in sizes.iter().enumerate() {
        let n = (target_bytes / frame).clamp(50, 200_000);

        let d_sock = bench_socket(frame, n).await;
        let d_surf = bench_surface_stream(&format!("/bench/s/{i}"), frame, n).await;
        // The large path is for big payloads; only meaningful from ~64 KiB up.
        let d_large = if frame >= 65_536 {
            Some(bench_surface_large(&format!("/bench/l/{i}"), frame, n).await)
        } else {
            None
        };

        let fr = if frame >= 1 << 20 {
            format!("{} MiB", frame >> 20)
        } else {
            format!("{} KiB", frame >> 10)
        };
        match d_large {
            Some(d_large) => println!(
                "  {:>9} | {:>6} | {:>12.0} {:>10.2} | {:>12.0} {:>10.2} | {:>12.0} {:>10.2}",
                fr,
                n,
                mbps(frame, n, d_sock),
                per_frame_us(n, d_sock),
                mbps(frame, n, d_surf),
                per_frame_us(n, d_surf),
                mbps(frame, n, d_large),
                per_frame_us(n, d_large),
            ),
            None => println!(
                "  {:>9} | {:>6} | {:>12.0} {:>10.2} | {:>12.0} {:>10.2} | {:>12} {:>10}",
                fr,
                n,
                mbps(frame, n, d_sock),
                per_frame_us(n, d_sock),
                mbps(frame, n, d_surf),
                per_frame_us(n, d_surf),
                "-",
                "-",
            ),
        }
    }
    println!(
        "\n  socket = Unix stream + 4B length prefix (raw bytes, no names, copy both ends)\n  \
         surf   = NamedPublisher/NamedSubscriber streaming (named Data, zero-copy read)\n  \
         surf-lg= open_large/publish_large (SharedBuffer fd, payload skips the kernel)\n"
    );
}
