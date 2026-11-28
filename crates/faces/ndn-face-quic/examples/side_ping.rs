//! The channel carrier of an ndn-link link, measured by the method of `carrier_bench`
//! (SHAPES-CHANNEL.md §17): a real link between two `LinkEndpoint`s on loopback, a back-to-back
//! publisher on `LinkFace::send_side` for a few seconds per size and a subscriber counting what
//! `recv_bytes` returns, then the 64 B half round trip. Frames are `0x00 | seq u32 | filler`.
//!
//! No arguments: three repetitions of channel datagrams at 1 KiB, the channel stream at 1 KiB
//! and 8 KiB, and the 64 B echo. Pin from the command line:
//! `taskset -c 10-13 cargo run --release -p ndn-face-quic --example side_ping`.
//!
//! Arguments are `key=value` words:
//!
//! | key | default | meaning |
//! |---|---|---|
//! | `only` | `dgram1k,stream1k,stream8k,lat` | rows to run |
//! | `repeat`, `secs`, `rt`, `workers` | 3, 3, 2, 1 | as in `carrier_bench` |
//! | `path_mtu_max` | 1452 | `LinkTransportConfig::path_mtu_max` (this example's own default, that of `carrier_bench`'s raw rows; the library's is 9,000) |
//! | `raw_dgram`, `raw_stream1k`, `raw_stream8k` | | msg/s of the same row of `carrier_bench` at the same settings |
//! | `raw_lat` | | its 64 B half round trip p50, in microseconds |
//!
//! With the `raw_*` values the summary prints the Stage 1 gate (SHAPES-CHANNEL.md §13): the
//! half round trip at most 1.03 times the raw datagram's, and the bytes per second within 5 % of
//! the raw datagram at 1 KiB and of the raw stream at 8 KiB.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use ndn_face_quic::LinkTransportConfig;
use ndn_transport::{SideClass, Transport};

mod common;
#[path = "common/pair.rs"]
mod pair;
#[path = "common/sampler.rs"]
mod sampler;
use common::{cpu_line, median, runtime, threads, trimmed};
use pair::{Pair, connect};

struct Args {
    only: Vec<String>,
    repeat: usize,
    secs: f64,
    rt: usize,
    workers: usize,
    path_mtu_max: u16,
    profile: Option<String>,
    raw: BTreeMap<String, f64>,
}

impl Args {
    fn parse() -> Self {
        let kv: BTreeMap<String, String> = std::env::args()
            .skip(1)
            .map(|a| {
                let (k, v) = a
                    .split_once('=')
                    .unwrap_or_else(|| panic!("arguments are key=value words, got `{a}`"));
                (k.to_owned(), v.to_owned())
            })
            .collect();
        let known = [
            "only",
            "repeat",
            "secs",
            "rt",
            "workers",
            "path_mtu_max",
            "raw_dgram",
            "raw_stream1k",
            "raw_stream8k",
            "raw_lat",
            "profile",
        ];
        for k in kv.keys() {
            assert!(known.contains(&k.as_str()), "unknown argument `{k}`");
        }
        let num = |k: &str, d: f64| kv.get(k).map_or(d, |v| v.parse().expect("a number"));
        Self {
            only: kv
                .get("only")
                .map_or("dgram1k,stream1k,stream8k,lat", String::as_str)
                .split(',')
                .map(str::to_owned)
                .collect(),
            repeat: num("repeat", 3.0) as usize,
            secs: num("secs", 3.0),
            rt: num("rt", 2.0) as usize,
            workers: num("workers", 1.0) as usize,
            path_mtu_max: num("path_mtu_max", 1452.0) as u16,
            profile: kv.get("profile").cloned(),
            raw: kv
                .iter()
                .filter(|(k, _)| k.starts_with("raw_"))
                .map(|(k, v)| (k.clone(), v.parse().expect("a number")))
                .collect(),
        }
    }
}

/// `0x00 | seq | filler`, `len` octets in all.
fn frame(seq: u32, len: usize) -> Bytes {
    let mut v = vec![0xA5; len];
    v[0] = 0x00;
    v[1..5].copy_from_slice(&seq.to_be_bytes());
    Bytes::from(v)
}

struct Ctx {
    secs: f64,
    rt_tx: Arc<tokio::runtime::Runtime>,
    rt_rx: Arc<tokio::runtime::Runtime>,
    pair: Pair,
}

impl Ctx {
    fn throughput(&self, label: &str, size: usize, class: SideClass) -> f64 {
        let (stop, sent, seen) = (
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
        );
        let subscriber = {
            let _g = self.rt_rx.enter();
            let (face, seen) = (Arc::clone(&self.pair.rx), Arc::clone(&seen));
            tokio::spawn(async move {
                // The datagrams and the channel stream's frames are read apart (the forwarder
                // runs one task for each): a subscriber that counts both reads both.
                loop {
                    let got = tokio::select! {
                        wire = face.face.recv_bytes() => wire,
                        frame = face.face.recv_side_stream() => frame,
                    };
                    if got.is_err() {
                        break;
                    }
                    seen.fetch_add(1, Ordering::Relaxed);
                }
            })
        };
        let publisher = {
            let _g = self.rt_tx.enter();
            let (face, stop, sent) = (
                Arc::clone(&self.pair.tx),
                Arc::clone(&stop),
                Arc::clone(&sent),
            );
            tokio::spawn(async move {
                let msg = frame(1, size);
                while !stop.load(Ordering::Relaxed) {
                    if face.face.send_side(msg.clone(), class).await.is_err() {
                        break;
                    }
                    sent.fetch_add(1, Ordering::Relaxed);
                }
            })
        };
        std::thread::sleep(Duration::from_millis(500));
        let (c0, s0, n0, t0, st0) = (
            threads(),
            sent.load(Ordering::Relaxed),
            seen.load(Ordering::Relaxed),
            Instant::now(),
            self.pair.tx.handle.side_stats(),
        );
        std::thread::sleep(Duration::from_secs_f64(self.secs));
        let (c1, s1, n1, wall, st1) = (
            threads(),
            sent.load(Ordering::Relaxed),
            seen.load(Ordering::Relaxed),
            t0.elapsed().as_secs_f64(),
            self.pair.tx.handle.side_stats(),
        );
        stop.store(true, Ordering::Relaxed);
        publisher.abort();
        subscriber.abort();
        let recv = (n1 - n0) as f64 / wall;
        println!(
            "row {label:<9} {size:>5} B  recv {recv:>9.0} msg/s  {:>5.2} Gbit/s   sent {:>9.0} msg/s",
            recv * size as f64 * 8.0 / 1e9,
            (s1 - s0) as f64 / wall
        );
        println!(
            "    side stats (publisher): frames {} datagram, {} stream, refused {}, sink_full {}, stream_blocked {}, coalesced {}, queued_peak {} B",
            st1.datagram_tx_frames - st0.datagram_tx_frames,
            st1.stream_tx_frames - st0.stream_tx_frames,
            st1.refused - st0.refused,
            st1.sink_full - st0.sink_full,
            st1.stream_blocked - st0.stream_blocked,
            st1.coalesced - st0.coalesced,
            st1.queued_peak,
        );
        println!("    cpu: {}", cpu_line(&c0, &c1, wall));
        std::thread::sleep(Duration::from_millis(300));
        recv
    }

    /// The 64 B half round trip: 1,000 warm-up round trips, 10,000 timed, the outer percents
    /// dropped; p50, p99 and mean in microseconds. On channel datagrams (`send_side`), or, for
    /// the cost of the face alone, on plain datagrams (`send_bytes`, a frame that is not
    /// marked).
    fn latency(&self, side: bool) -> (f64, f64, f64) {
        for (link, rt) in [(&self.pair.rx, &self.rt_rx), (&self.pair.tx, &self.rt_tx)] {
            let link = Arc::clone(link);
            rt.block_on(async move {
                while tokio::time::timeout(Duration::from_millis(200), link.face.recv_bytes())
                    .await
                    .is_ok()
                {}
            });
        }
        let echo = {
            let _g = self.rt_rx.enter();
            let link = Arc::clone(&self.pair.rx);
            tokio::spawn(async move {
                while let Ok(f) = link.face.recv_bytes().await {
                    let sent = if side {
                        link.face.send_side(f, SideClass::Datagram).await.is_ok()
                    } else {
                        link.face.send_bytes(f).await.is_ok()
                    };
                    if !sent {
                        break;
                    }
                }
            })
        };
        let link = Arc::clone(&self.pair.tx);
        let (c0, t0) = (threads(), Instant::now());
        let mut samples = self.rt_tx.block_on(async move {
            let msg = if side {
                frame(7, 64)
            } else {
                Bytes::from(vec![0x06; 64])
            };
            let mut out = Vec::with_capacity(10_000);
            for i in 0..11_000 {
                let t = Instant::now();
                if side {
                    link.face
                        .send_side(msg.clone(), SideClass::Datagram)
                        .await
                        .unwrap();
                } else {
                    link.face.send_bytes(msg.clone()).await.unwrap();
                }
                link.face.recv_bytes().await.unwrap();
                if i >= 1_000 {
                    out.push(t.elapsed().as_secs_f64() * 1e6 / 2.0);
                }
            }
            out
        });
        let (c1, wall) = (threads(), t0.elapsed().as_secs_f64());
        echo.abort();
        println!("    cpu: {}", cpu_line(&c0, &c1, wall));
        let (p50, p99, mean) = trimmed(&mut samples);
        println!(
            "row {} p50 {p50:.1} us  p99 {p99:.1} us  mean {mean:.1} us (half round trip, 10,000 after 1,000, outer 1% dropped)",
            if side { "lat64    " } else { "lat64 ndn" }
        );
        std::thread::sleep(Duration::from_millis(300));
        (p50, p99, mean)
    }
}

fn main() {
    let a = Args::parse();
    println!("path_mtu_max {}", a.path_mtu_max);
    let config = LinkTransportConfig {
        path_mtu_max: a.path_mtu_max,
        ..LinkTransportConfig::default()
    };
    let mut summary: BTreeMap<String, Vec<f64>> = BTreeMap::new();
    for rep in 0..a.repeat {
        let (rt_rx, rt_tx) = if a.rt == 1 {
            let r = runtime("both", a.workers);
            (Arc::clone(&r), r)
        } else {
            (runtime("recv", a.workers), runtime("send", a.workers))
        };
        let pair = rt_tx.block_on(connect(&config, rt_rx.handle(), rt_tx.handle()));
        let ctx = Ctx {
            secs: a.secs,
            rt_tx,
            rt_rx,
            pair,
        };
        println!("--- repetition {}", rep + 1);
        if a.profile.is_some() && rep == 0 {
            let tids: Vec<u32> = threads()
                .into_iter()
                .filter(|(_, c)| ["send", "recv", "both"].contains(&c.name.as_str()))
                .map(|(t, _)| t)
                .collect();
            sampler::start(&tids);
        }
        for only in &a.only {
            let mut put = |k: &str, v: f64| summary.entry(k.to_owned()).or_default().push(v);
            match only.as_str() {
                "dgram1k" => put(
                    "dgram 1 KiB msg/s",
                    ctx.throughput("dgram", 1024, SideClass::Datagram),
                ),
                "stream1k" => put(
                    "stream 1 KiB msg/s",
                    ctx.throughput("stream", 1024, SideClass::Stream),
                ),
                "stream8k" => put(
                    "stream 8 KiB msg/s",
                    ctx.throughput("stream", 8192, SideClass::Stream),
                ),
                "lat" => {
                    let (p50, p99, _) = ctx.latency(true);
                    put("lat64 p50 us", p50);
                    put("lat64 p99 us", p99);
                }
                "lat_ndn" => {
                    let (p50, p99, _) = ctx.latency(false);
                    put("lat64 ndn p50 us", p50);
                    put("lat64 ndn p99 us", p99);
                }
                other => panic!("unknown row `{other}`"),
            }
        }
        if let Some(path) = a.profile.as_deref().filter(|_| rep == 0) {
            let names = threads().into_iter().map(|(t, c)| (t, c.name)).collect();
            sampler::dump(path, &names);
        }
        println!(
            "link: datagram size {:?}, side stats {:?}",
            ctx.pair.tx.handle.max_datagram_size(),
            ctx.pair.tx.handle.side_stats()
        );
    }
    println!("--- summary of {} repetitions: median [min, max]", a.repeat);
    let mut medians = BTreeMap::new();
    for (k, mut v) in summary {
        let (m, lo, hi) = median(&mut v);
        println!("{k:<22} {m:>12.1} [{lo:.1}, {hi:.1}]");
        medians.insert(k, m);
    }
    let gate =
        |name: &str, side: Option<&f64>, raw: Option<&f64>, higher_is_better: bool, limit: f64| {
            let (Some(side), Some(raw)) = (side, raw) else {
                return;
            };
            let ratio = side / raw;
            let ok = if higher_is_better {
                ratio >= limit
            } else {
                ratio <= limit
            };
            println!(
                "gate {name}: side {side:.1} / raw {raw:.1} = {ratio:.3} (limit {} {limit}) {}",
                if higher_is_better { ">=" } else { "<=" },
                if ok { "PASS" } else { "FAIL" }
            );
        };
    gate(
        "datagram 1 KiB",
        medians.get("dgram 1 KiB msg/s"),
        a.raw.get("raw_dgram"),
        true,
        0.95,
    );
    gate(
        "stream 1 KiB (informational)",
        medians.get("stream 1 KiB msg/s"),
        a.raw.get("raw_stream1k"),
        true,
        0.95,
    );
    gate(
        "stream 8 KiB",
        medians.get("stream 8 KiB msg/s"),
        a.raw.get("raw_stream8k"),
        true,
        0.95,
    );
    gate(
        "64 B half round trip",
        medians.get("lat64 p50 us"),
        a.raw.get("raw_lat"),
        false,
        1.03,
    );
}
