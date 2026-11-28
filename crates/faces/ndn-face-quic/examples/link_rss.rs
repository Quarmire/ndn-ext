//! Resident memory a link connection costs, by the bound of its path-MTU discovery.
//!
//! One process, one dialing endpoint and one listening endpoint on loopback, `n` links between
//! them (both ends of every link live in this process, so a figure per connection is the cost of
//! both ends; half of it is one end). Linux only: the resident set is `/proc/self/statm`.
//!
//! The method, in order. One link is opened first and kept, so what happens once (code pages,
//! the crypto provider, the endpoints' receive buffers) is not charged to the connections. Then:
//!
//! 1. `base`: resident set after that link settled.
//! 2. `idle`: after `n` more links are admitted and every one has left path-MTU discovery
//!    (its datagram size has not moved for half a second), with nothing sent.
//! 3. `steady`: after each of the `n` links sent a burst of channel datagrams and one stream
//!    frame of 1 MiB, the other end read them, and the connections settled again.
//! 4. `trimmed`: `steady` after the allocator was asked to return its free pages
//!    (`malloc_trim`): what is still live rather than retained.
//!
//! The line printed is `key=value` words, bytes per connection for `idle`, `steady` and
//! `trimmed` (the figure less `base`, over `n`), `peak` (the high-water mark of the resident
//! set over `base`, over `n`) and the datagram size the links settled on.
//!
//! Arguments are `key=value` words: `n` (200), `path_mtu_max` (the default of
//! `LinkTransportConfig`), `dgrams` (64 datagrams of 1 KiB per link), `parallel` (links that
//! send at once, 20). Run it in a release build, once per process, as many times as wanted:
//! `cargo run --release -p ndn-face-quic --example link_rss -- path_mtu_max=9000`.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use ndn_face_quic::{
    Admission, ChannelPolicy, Link, LinkEndpoint, LinkHello, LinkKey, LinkTransportConfig,
};
use ndn_security::Ed25519Signer;
use ndn_transport::{FaceId, SideClass, Transport};

const T: Duration = Duration::from_secs(10);
const STREAM_FRAME: usize = 1024 * 1024;

fn key(seed: u8) -> LinkKey {
    LinkKey::from_signer(Arc::new(Ed25519Signer::from_seed(
        &[seed; 32],
        format!("/bench/member/d{seed}/KEY/k").parse().unwrap(),
    )))
    .unwrap()
}

fn carrying() -> Admission {
    Admission {
        channel: ChannelPolicy {
            carry: true,
            quota: None,
        },
        ..Admission::default()
    }
}

/// `0x00 | seq | filler`, `len` octets in all.
fn frame(seq: u32, len: usize) -> Bytes {
    let mut v = vec![0xA5; len];
    v[0] = 0x00;
    v[1..5].copy_from_slice(&seq.to_be_bytes());
    Bytes::from(v)
}

/// Resident set in bytes (`statm`: pages, the second field).
fn rss() -> u64 {
    let statm = std::fs::read_to_string("/proc/self/statm").unwrap();
    let pages: u64 = statm.split(' ').nth(1).unwrap().parse().unwrap();
    pages * 4096
}

/// The resident set's high-water mark in bytes (`VmHWM`).
fn peak_rss() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let line = status.lines().find(|l| l.starts_with("VmHWM:")).unwrap();
    let kib: u64 = line.split_whitespace().nth(1).unwrap().parse().unwrap();
    kib * 1024
}

/// Ask the allocator to return its free pages to the system.
#[allow(unsafe_code)]
fn trim() {
    // SAFETY: `malloc_trim` takes no pointer and only releases memory the allocator holds free.
    unsafe { libc::malloc_trim(0) };
}

async fn open(dialer: &LinkEndpoint, listener: &LinkEndpoint) -> (Link, Link) {
    let target = listener.local_addr().unwrap();
    let accept = async {
        let mut hs = listener.accept().await.unwrap().handshake().await.unwrap();
        hs.exchange_hello(&LinkHello::default(), T).await.unwrap();
        hs.admit(FaceId(2), T, carrying()).await.unwrap()
    };
    let dial = async {
        let mut hs = dialer.connect(target, None).await.unwrap();
        hs.exchange_hello(&LinkHello::default(), T).await.unwrap();
        hs.admit(FaceId(1), T, carrying()).await.unwrap()
    };
    let (tx, rx) = tokio::join!(dial, accept);
    assert!(tx.handle.side_peer_caps() && rx.handle.side_peer_caps());
    (tx, rx)
}

/// Wait until no link's datagram size has moved for half a second, and return the smallest.
async fn settle(links: &[(Arc<Link>, Arc<Link>)]) -> usize {
    let sizes = || -> Vec<usize> {
        links
            .iter()
            .flat_map(|(a, b)| [a, b])
            .map(|l| l.handle.max_datagram_size().unwrap())
            .collect()
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    let (mut last, mut since) = (sizes(), Instant::now());
    while Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let now = sizes();
        if now != last {
            (last, since) = (now, Instant::now());
        } else if since.elapsed() >= Duration::from_millis(500) {
            break;
        }
    }
    last.into_iter().min().unwrap()
}

/// One link's burst: `dgrams` channel datagrams of 1 KiB, then one stream frame of 1 MiB; the
/// other end reads until the stream frame arrives.
async fn burst(tx: Arc<Link>, rx: Arc<Link>, dgrams: usize) {
    let reader = tokio::spawn(async move {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let wire = tokio::time::timeout(left, async {
                tokio::select! {
                    wire = rx.face.recv_bytes() => wire,
                    frame = rx.face.recv_side_stream() => frame,
                }
            })
            .await
            .expect("the stream frame arrives")
            .unwrap();
            if wire.len() == STREAM_FRAME {
                return;
            }
        }
    });
    for i in 0..dgrams {
        tx.face
            .send_side(frame(i as u32, 1024), SideClass::Datagram)
            .await
            .unwrap();
    }
    tx.face
        .send_side(frame(u32::MAX, STREAM_FRAME), SideClass::Stream)
        .await
        .unwrap();
    reader.await.unwrap();
}

fn main() {
    let kv: BTreeMap<String, String> = std::env::args()
        .skip(1)
        .map(|a| {
            let (k, v) = a.split_once('=').expect("arguments are key=value words");
            (k.to_owned(), v.to_owned())
        })
        .collect();
    let num = |k: &str, d: usize| kv.get(k).map_or(d, |v| v.parse().unwrap());
    let (n, dgrams, parallel) = (num("n", 200), num("dgrams", 64), num("parallel", 20));
    let mut config = LinkTransportConfig::default();
    if let Some(v) = kv.get("path_mtu_max") {
        config.path_mtu_max = v.parse().unwrap();
    }
    let path_mtu_max = config.path_mtu_max;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let line = rt.block_on(async move {
        let listener = LinkEndpoint::bind(
            "127.0.0.1:0".parse().unwrap(),
            Arc::new(key(2)),
            &config,
            true,
        )
        .unwrap();
        let dialer = LinkEndpoint::bind(
            "127.0.0.1:0".parse().unwrap(),
            Arc::new(key(1)),
            &config,
            false,
        )
        .unwrap();

        let warm = {
            let (a, b) = open(&dialer, &listener).await;
            vec![(Arc::new(a), Arc::new(b))]
        };
        burst(Arc::clone(&warm[0].0), Arc::clone(&warm[0].1), dgrams).await;
        settle(&warm).await;
        let base = rss();

        let mut links = Vec::with_capacity(n);
        for _ in 0..n {
            let (a, b) = open(&dialer, &listener).await;
            links.push((Arc::new(a), Arc::new(b)));
        }
        let size = settle(&links).await;
        let idle = rss();

        for chunk in links.chunks(parallel) {
            let bursts: Vec<_> = chunk
                .iter()
                .map(|(a, b)| tokio::spawn(burst(Arc::clone(a), Arc::clone(b), dgrams)))
                .collect();
            for b in bursts {
                b.await.unwrap();
            }
        }
        settle(&links).await;
        let steady = rss();
        trim();
        let trimmed = rss();
        let peak = peak_rss();

        let per = |at: u64| at.saturating_sub(base) / n as u64;
        let line = format!(
            "path_mtu_max={path_mtu_max} n={n} settled_datagram={size} base={base} \
             idle_per_conn={} steady_per_conn={} trimmed_per_conn={} peak_per_conn={}",
            per(idle),
            per(steady),
            per(trimmed),
            per(peak),
        );
        drop((links, warm, dialer, listener));
        line
    });
    println!("{line}");
    // The runtime's drop would wait for the closing connections' tasks; the line is printed.
    rt.shutdown_background();
}
