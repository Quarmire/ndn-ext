//! The channel through forwarders (stage 4, SHAPES-CHANNEL.md §8, §13) measured by the method of
//! `chan_ping`: a sender (`/bob/phone`) and one or two receivers (`/carol/tablet`, `/dave/watch`),
//! each device on a forwarder of its own (`ndn-engine`) and each forwarder on a runtime of its
//! own (`send`, `recvA`, `recvB`, and `relay` for the relay's), joined by real QUIC links on
//! loopback. The channel is set up by the real signed ask over the links, and the frames travel
//! `Heap::emit` -> the sender's forwarder -> link -> [the relay's side table -> a link for each
//! receiver] -> the receivers' forwarders -> `Heap::live`'s `Items`.
//!
//! Shapes (`shapes`, comma separated):
//!
//! | shape | meaning |
//! |---|---|
//! | `direct` | one receiver linked to the sender (one link, no relay) |
//! | `relay1` | one receiver behind a relay (two links) |
//! | `relay2` | two receivers behind a relay (three links): one copy of each frame leaves the sender |
//!
//! Rows (`only`, comma separated), run for each shape:
//!
//! | row | meaning |
//! |---|---|
//! | `lat:<size>` | the half round trip of `size` octets: `emit` /ping at the sender -> receiver A's `Items` -> A `emit`s /pong -> the sender's `Items`; 1,000 warm-up (and 300 ms) then 10,000 timed round trips, the lowest and highest 1 % dropped. In `relay2` B receives the pings too (and counts them) |
//! | `thr:<size>` | back-to-back `emit` of `size` octets over `paths` paths for `secs` seconds after 0.5 s; each receiver counts what its `Items` yields |
//! | `paced:<size>:<per second>` | `size` octets at a fixed rate for `secs` seconds after 0.5 s: the CPU (schedstat) of each runtime, as a share of one core, with the checkpoint period of `checkpoint` |
//!
//! Arguments are `key=value` words:
//!
//! | key | default | meaning |
//! |---|---|---|
//! | `shapes` | `direct,relay1,relay2` | shapes |
//! | `only` | `thr:64,lat:64` | rows |
//! | `repeat`, `secs`, `workers` | 3, 3, 1 | as in `chan_ping`; `workers` per runtime |
//! | `path_mtu_max` | 9000 | `LinkTransportConfig::path_mtu_max` |
//! | `paths` | 256 | distinct paths the `thr` rows rotate over |
//! | `checkpoint` | 20 | the checkpoint period, ms (`ChannelConfig::checkpoint`: 1 to 2,000) |
//! | `sealed` | 1 | `1`: a sealed space (readers are named persons); `0`: a public one |
//! | `timer` | 1 | `1`: each ping waits for its pong under `tokio::time::timeout`; `0`: no timer |
//!
//! Each repetition builds every shape afresh, in the order given. Pin from the command line:
//! `taskset -c 10-13 target-shared/release/examples/chan_relay`.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use ndn_face_quic::LinkTransportConfig;
use ndn_heap::{EmitOptions, GetOptions, Items, Name, Select};
use tokio::task::JoinHandle;

mod common;
#[allow(dead_code)]
#[path = "common/pair.rs"]
mod pair;
#[allow(dead_code)]
#[path = "common/relay.rs"]
mod relay;
use common::{ThreadCpu, cpu_line, median, runtime, threads, trimmed};
use relay::{Build, Mesh, Runtimes, name};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shape {
    Direct,
    Relay1,
    Relay2,
}

impl Shape {
    fn label(self) -> &'static str {
        match self {
            Shape::Direct => "direct",
            Shape::Relay1 => "relay1",
            Shape::Relay2 => "relay2",
        }
    }

    fn receivers(self) -> usize {
        if self == Shape::Relay2 { 2 } else { 1 }
    }

    fn relayed(self) -> bool {
        self != Shape::Direct
    }
}

#[derive(Clone)]
struct Args {
    shapes: Vec<Shape>,
    only: Vec<String>,
    repeat: usize,
    secs: f64,
    workers: usize,
    path_mtu_max: u16,
    paths: usize,
    checkpoint: Duration,
    sealed: bool,
    timer: bool,
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
            "shapes",
            "only",
            "repeat",
            "secs",
            "workers",
            "path_mtu_max",
            "paths",
            "checkpoint",
            "sealed",
            "timer",
        ];
        for k in kv.keys() {
            assert!(
                known.contains(&k.as_str()),
                "unknown argument `{k}` (see the file's header)"
            );
        }
        let num = |k: &str, d: f64| kv.get(k).map_or(d, |v| v.parse().expect("a number"));
        Self {
            shapes: kv
                .get("shapes")
                .map_or("direct,relay1,relay2", String::as_str)
                .split(',')
                .map(|s| match s {
                    "direct" => Shape::Direct,
                    "relay1" => Shape::Relay1,
                    "relay2" => Shape::Relay2,
                    other => panic!("shapes are direct, relay1, relay2, got `{other}`"),
                })
                .collect(),
            only: kv
                .get("only")
                .map_or("thr:64,lat:64", String::as_str)
                .split(',')
                .map(str::to_owned)
                .collect(),
            repeat: num("repeat", 3.0) as usize,
            secs: num("secs", 3.0),
            workers: num("workers", 1.0) as usize,
            path_mtu_max: num("path_mtu_max", 9000.0) as u16,
            paths: num("paths", 256.0) as usize,
            checkpoint: Duration::from_millis(num("checkpoint", 20.0) as u64),
            sealed: num("sealed", 1.0) != 0.0,
            timer: num("timer", 1.0) != 0.0,
        }
    }
}

fn loadavg() -> String {
    std::fs::read_to_string("/proc/loadavg")
        .map(|s| s.split(' ').take(3).collect::<Vec<_>>().join(" "))
        .unwrap_or_else(|e| format!("unreadable: {e}"))
}

fn everything() -> Select {
    Select::Prefix(Name::root())
}

struct Ctx {
    args: Args,
    ctl: Arc<tokio::runtime::Runtime>,
    send: Arc<tokio::runtime::Runtime>,
    relay: Arc<tokio::runtime::Runtime>,
    recv: [Arc<tokio::runtime::Runtime>; 2],
}

/// The mesh of one shape, built for the rows asked.
struct Rig {
    shape: Shape,
    mesh: Mesh,
}

impl Ctx {
    fn new(args: &Args) -> Self {
        Self {
            args: args.clone(),
            ctl: runtime("ctl", 1),
            send: runtime("send", args.workers),
            relay: runtime("relay", args.workers),
            recv: [
                runtime("recvA", args.workers),
                runtime("recvB", args.workers),
            ],
        }
    }

    fn rig(&self, shape: Shape) -> Rig {
        let rts = Runtimes {
            send: self.send.handle().clone(),
            relay: self.relay.handle().clone(),
            recv: [self.recv[0].handle().clone(), self.recv[1].handle().clone()],
        };
        let build = Build {
            transport: LinkTransportConfig {
                path_mtu_max: self.args.path_mtu_max,
                ..LinkTransportConfig::default()
            },
            sealed: self.args.sealed,
            receivers_write: self.args.only.iter().any(|o| o.starts_with("lat:")),
            checkpoint: self.args.checkpoint,
            ..Build::default()
        };
        let mesh = self
            .ctl
            .block_on(Mesh::new(&rts, shape.receivers(), shape.relayed(), build));
        Rig { shape, mesh }
    }

    fn close(&self, rig: Rig) {
        self.ctl.block_on(async move { drop(rig) });
    }

    /// Each receiver takes the channel (an `Items` first, then the ask: a session lapses with its
    /// last taker, so each row asks afresh) and waits for the sender's `HELLO` through every hop.
    fn open(&self, rig: &Rig) -> Vec<Items> {
        let items: Vec<Items> = rig
            .mesh
            .receivers
            .iter()
            .map(|r| {
                r.heap
                    .live(everything(), GetOptions::default())
                    .expect("a member")
            })
            .collect();
        self.ctl.block_on(async {
            for (i, r) in rig.mesh.receivers.iter().enumerate() {
                Mesh::ask(self.recv[i].handle(), &r.node, &rig.mesh.sender.node).await;
            }
            let start = Instant::now();
            while !items.iter().all(Items::hello_seen) {
                assert!(
                    start.elapsed() < Duration::from_secs(10),
                    "no HELLO at every receiver within 10 s"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });
        items
    }
}

/// Take what `Items` yields until it ends, counting items and their size mismatches.
async fn consume(
    mut items: Items,
    size: usize,
    seen: Arc<AtomicU64>,
    notices: Arc<AtomicU64>,
    bad: Arc<AtomicU64>,
) {
    loop {
        match items.next().await {
            Some(Ok(got)) => {
                if got.bytes.len() != size {
                    bad.fetch_add(1, Ordering::Relaxed);
                }
                seen.fetch_add(1, Ordering::Relaxed);
            }
            Some(Err(_notice)) => {
                notices.fetch_add(1, Ordering::Relaxed);
            }
            None => return,
        }
    }
}

fn frames(s: &ndn_face_quic::SideStats) -> u64 {
    s.datagram_tx_frames + s.stream_tx_frames
}

/// Each receiver's link counters and its forwarder's side table counters.
fn receiver_stats(m: &Mesh) -> Vec<(ndn_face_quic::SideStats, ndn_engine::side::SideStats)> {
    m.receivers
        .iter()
        .map(|r| (r.link.side_stats(), r.site.engine.side().stats()))
        .collect()
}

/// The labels of the runtimes' threads, for the CPU shares.
const RUNTIMES: [&str; 4] = ["send", "relay", "recvA", "recvB"];

fn cores(
    before: &BTreeMap<u32, ThreadCpu>,
    after: &BTreeMap<u32, ThreadCpu>,
    wall: f64,
    thread: &str,
) -> f64 {
    let ns = |a: &BTreeMap<u32, ThreadCpu>| -> u64 {
        a.values().filter(|c| c.name == thread).map(|c| c.ns).sum()
    };
    ns(after).saturating_sub(ns(before)) as f64 / (wall * 1e9)
}

impl Ctx {
    /// Back-to-back `emit` of `size` octets for `secs` seconds; each receiver counts what its
    /// `Items` yields. Returns the delivered rate of each receiver.
    fn throughput(&self, rig: &Rig, size: usize) -> Vec<f64> {
        let m = &rig.mesh;
        let items = self.open(rig);
        let (stop, sent, failed) = (
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
        );
        let (notices, bad) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
        let seen: Vec<Arc<AtomicU64>> = items.iter().map(|_| Arc::new(AtomicU64::new(0))).collect();
        let subscribers: Vec<JoinHandle<()>> = items
            .into_iter()
            .zip(&seen)
            .enumerate()
            .map(|(i, (items, seen))| {
                self.recv[i].spawn(consume(
                    items,
                    size,
                    Arc::clone(seen),
                    Arc::clone(&notices),
                    Arc::clone(&bad),
                ))
            })
            .collect();
        let paths: Vec<Name> = (0..self.args.paths)
            .map(|i| name(&format!("/t/{i}")))
            .collect();
        let publisher = {
            let (heap, stop, sent, failed) = (
                m.sender.heap.clone(),
                Arc::clone(&stop),
                Arc::clone(&sent),
                Arc::clone(&failed),
            );
            self.send.spawn(async move {
                let payload = Bytes::from(vec![0xA5; size]);
                'run: while !stop.load(Ordering::Relaxed) {
                    for path in &paths {
                        match heap
                            .emit(path, payload.clone(), EmitOptions::default())
                            .await
                        {
                            Ok(()) => {
                                sent.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(e) => {
                                failed.fetch_add(1, Ordering::Relaxed);
                                eprintln!("emit refused: {e} (next: {:?})", e.next());
                                break 'run;
                            }
                        }
                    }
                    // The writer and the forwarder share this worker: one pass of emissions,
                    // then they run.
                    tokio::task::yield_now().await;
                }
            })
        };
        let snap = || {
            (
                threads(),
                sent.load(Ordering::Relaxed),
                seen.iter()
                    .map(|s| s.load(Ordering::Relaxed))
                    .collect::<Vec<_>>(),
                Instant::now(),
                m.sender.link.side_stats(),
                m.relay.as_ref().map(|r| r.engine.side().stats()),
                m.relay_links
                    .iter()
                    .map(|l| l.side_stats())
                    .collect::<Vec<_>>(),
            )
        };
        std::thread::sleep(Duration::from_millis(500));
        let (c0, s0, n0, t0, l0, r0, rl0) = snap();
        let rx0 = receiver_stats(m);
        std::thread::sleep(Duration::from_secs_f64(self.args.secs));
        let (c1, s1, n1, _, l1, r1, rl1) = snap();
        let rx1 = receiver_stats(m);
        let wall = t0.elapsed().as_secs_f64();
        stop.store(true, Ordering::Relaxed);
        publisher.abort();
        for s in &subscribers {
            s.abort();
        }
        let emitted = (s1 - s0) as f64 / wall;
        let rates: Vec<f64> = n1
            .iter()
            .zip(&n0)
            .map(|(a, b)| (a - b) as f64 / wall)
            .collect();
        let size_f = size as f64 * 8.0 / 1e9;
        let per_rx = rates
            .iter()
            .zip(["A", "B"])
            .map(|(r, who)| {
                format!(
                    "{who} {r:>9.0} msg/s ({:.2} Gbit/s, {:.1} % of emitted)",
                    r * size_f,
                    100.0 * r / emitted.max(1.0)
                )
            })
            .collect::<Vec<_>>()
            .join("   ");
        println!(
            "row {} thr {size:>5} B  recv {per_rx}   emitted {emitted:>9.0} msg/s",
            rig.shape.label()
        );
        let sent_frames = frames(&l1) - frames(&l0);
        println!(
            "    sender link: {} frames/s ({} datagram, {} stream), refused {}, sink_full {}, stream_blocked {}, queued_peak {} B; wrong-size items {}, notices {}, emits refused {}",
            (sent_frames as f64 / wall) as u64,
            l1.datagram_tx_frames - l0.datagram_tx_frames,
            l1.stream_tx_frames - l0.stream_tx_frames,
            l1.refused - l0.refused,
            l1.sink_full - l0.sink_full,
            l1.stream_blocked - l0.stream_blocked,
            l1.queued_peak,
            bad.load(Ordering::Relaxed),
            notices.load(Ordering::Relaxed),
            failed.load(Ordering::Relaxed),
        );
        if let (Some(r0), Some(r1)) = (r0, r1) {
            let out: Vec<String> = rl1
                .iter()
                .zip(&rl0)
                .map(|(a, b)| format!("{}", (frames(a) - frames(b)) as f64 / wall))
                .collect();
            println!(
                "    relay: frames in {:.0}/s, out {:.0}/s ({} sinks of the route), sink_full {}, quota {}, unrouted {}, wrong_source {}; relay links sent (sender, receivers) {} frames/s",
                (r1.frames_in - r0.frames_in) as f64 / wall,
                (r1.frames_out - r0.frames_out) as f64 / wall,
                r1.sinks,
                r1.sink_full - r0.sink_full,
                r1.quota - r0.quota,
                r1.unrouted - r0.unrouted,
                r1.wrong_source - r0.wrong_source,
                out.join(", ")
            );
        }
        for (i, ((a0, e0), (a1, e1))) in rx0.iter().zip(&rx1).enumerate() {
            println!(
                "    receiver {}: link received {:.0} datagram + {:.0} stream frames/s; its forwarder: frames in {:.0}/s, out {:.0}/s, sink_full {}, unrouted {}, wrong_source {}, quota {}",
                ["A", "B"][i],
                (a1.datagram_rx_frames - a0.datagram_rx_frames) as f64 / wall,
                (a1.stream_rx_frames - a0.stream_rx_frames) as f64 / wall,
                (e1.frames_in - e0.frames_in) as f64 / wall,
                (e1.frames_out - e0.frames_out) as f64 / wall,
                e1.sink_full - e0.sink_full,
                e1.unrouted - e0.unrouted,
                e1.wrong_source - e0.wrong_source,
                e1.quota - e0.quota,
            );
        }
        println!("    cpu: {}", cpu_line(&c0, &c1, wall));
        let delivered: u64 = n1.iter().zip(&n0).map(|(a, b)| a - b).sum();
        let per = |thread: &str| -> String {
            let ns = |a: &BTreeMap<u32, ThreadCpu>| -> u64 {
                a.values().filter(|c| c.name == thread).map(|c| c.ns).sum()
            };
            let cpu = ns(&c1).saturating_sub(ns(&c0)) as f64;
            format!("{thread} {:.0} ns", cpu / (delivered.max(1) as f64))
        };
        println!(
            "    cpu per delivered message (all receivers): {}",
            RUNTIMES.map(per).join(", ")
        );
        std::thread::sleep(Duration::from_millis(300));
        rates
    }

    /// The half round trip of `size` octets, `emit` to `Items` and back through A: the sender
    /// emits /ping, A's `Items` yields it and A emits /pong, the sender's `Items` yields it. 1,000
    /// warm-up round trips (and at least 300 ms), 10,000 timed, the outer percents dropped. B, if
    /// there is one, counts the pings.
    fn latency(&self, rig: &Rig, size: usize) -> (f64, f64, f64) {
        let m = &rig.mesh;
        let mut bob_items = m
            .sender
            .heap
            .live(everything(), GetOptions::default())
            .expect("the sender is a member");
        let mut items = self.open(rig);
        // The sender takes A's channel too: the pongs come back over the same links.
        self.ctl.block_on(async {
            Mesh::ask(self.send.handle(), &m.sender.node, &m.receivers[0].node).await;
            let start = Instant::now();
            while !bob_items.hello_seen() {
                assert!(
                    start.elapsed() < Duration::from_secs(10),
                    "no HELLO at the sender"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });
        let mut b_drain = None;
        let b_seen = Arc::new(AtomicU64::new(0));
        if items.len() == 2 {
            let b = items.pop().unwrap();
            b_drain = Some(self.recv[1].spawn(consume(
                b,
                size,
                Arc::clone(&b_seen),
                Arc::new(AtomicU64::new(0)),
                Arc::new(AtomicU64::new(0)),
            )));
        }
        let mut a_items = items.pop().unwrap();
        let echo = {
            let a = m.receivers[0].heap.clone();
            self.recv[0].spawn(async move {
                let pong = name("/pong");
                while let Some(item) = a_items.next().await {
                    if let Ok(got) = item
                        && a.emit(&pong, got.bytes, EmitOptions::default())
                            .await
                            .is_err()
                    {
                        break;
                    }
                }
            })
        };
        let bob = m.sender.heap.clone();
        let timer = self.args.timer;
        let (c0, t0) = (threads(), Instant::now());
        let (mut samples, lost) = self.send.block_on(async move {
            let (ping, pong) = (name("/ping"), name("/pong"));
            let payload = Bytes::from(vec![0x06; size]);
            let mut out = Vec::with_capacity(10_000);
            let (mut lost, start) = (0u32, Instant::now());
            let mut i = 0u32;
            while out.len() < 10_000 {
                let t = Instant::now();
                bob.emit(&ping, payload.clone(), EmitOptions::default())
                    .await
                    .unwrap();
                let wait = async {
                    loop {
                        match bob_items.next().await {
                            Some(Ok(got)) if got.path == pong => return true,
                            Some(_) => {}
                            None => return false,
                        }
                    }
                };
                let answer = if timer {
                    tokio::time::timeout(Duration::from_secs(1), wait)
                        .await
                        .map_err(|_| ())
                } else {
                    Ok(wait.await)
                };
                match answer {
                    Ok(true) => {
                        i += 1;
                        if i > 1_000 && start.elapsed() > Duration::from_millis(300) {
                            out.push(t.elapsed().as_secs_f64() * 1e6 / 2.0);
                        }
                    }
                    _ => lost += 1,
                }
            }
            (out, lost)
        });
        let (c1, wall) = (threads(), t0.elapsed().as_secs_f64());
        echo.abort();
        if let Some(b) = b_drain {
            b.abort();
        }
        println!("    cpu: {}", cpu_line(&c0, &c1, wall));
        let (p50, p99, mean) = trimmed(&mut samples);
        println!(
            "row {} lat{size} p50 {p50:.1} us  p99 {p99:.1} us  mean {mean:.1} us (half round trip, emit -> Items, 10,000 after 1,000, outer 1% dropped; {lost} round trips timed out{})",
            rig.shape.label(),
            if rig.shape == Shape::Relay2 {
                format!("; B counted {} pings", b_seen.load(Ordering::Relaxed))
            } else {
                String::new()
            }
        );
        std::thread::sleep(Duration::from_millis(300));
        (p50, p99, mean)
    }

    /// `size` octets, `rate` a second, for `secs` seconds after 0.5 s; each receiver's `Items`
    /// consumed. Returns the share of one core each runtime used (send, relay, recvA, recvB).
    fn paced(&self, rig: &Rig, size: usize, rate: u64) -> [f64; 4] {
        let m = &rig.mesh;
        let items = self.open(rig);
        let (seen, notices, bad) = (
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
        );
        let subscribers: Vec<JoinHandle<()>> = items
            .into_iter()
            .enumerate()
            .map(|(i, items)| {
                self.recv[i].spawn(consume(
                    items,
                    size,
                    Arc::clone(&seen),
                    Arc::clone(&notices),
                    Arc::clone(&bad),
                ))
            })
            .collect();
        let stop = Arc::new(AtomicBool::new(false));
        let publisher = {
            let (heap, stop) = (m.sender.heap.clone(), Arc::clone(&stop));
            self.send.spawn(async move {
                let payload = Bytes::from(vec![0xA5; size]);
                let paths: Vec<Name> = (0..64).map(|i| name(&format!("/p/{i}"))).collect();
                let start = tokio::time::Instant::now();
                let mut n = 0u64;
                while !stop.load(Ordering::Relaxed) {
                    // The n-th message is due at n / rate; those overdue go out at once.
                    let due = start + Duration::from_secs_f64(n as f64 / rate as f64);
                    tokio::time::sleep_until(due).await;
                    let path = &paths[(n % 64) as usize];
                    if heap
                        .emit(path, payload.clone(), EmitOptions::default())
                        .await
                        .is_err()
                    {
                        break;
                    }
                    n += 1;
                }
            })
        };
        std::thread::sleep(Duration::from_millis(500));
        let (c0, n0, t0) = (threads(), seen.load(Ordering::Relaxed), Instant::now());
        std::thread::sleep(Duration::from_secs_f64(self.args.secs));
        let (c1, n1, wall) = (
            threads(),
            seen.load(Ordering::Relaxed),
            t0.elapsed().as_secs_f64(),
        );
        stop.store(true, Ordering::Relaxed);
        publisher.abort();
        for s in &subscribers {
            s.abort();
        }
        let shares = RUNTIMES.map(|t| cores(&c0, &c1, wall, t));
        println!(
            "row {} paced {size} B at {rate}/s, checkpoint {} ms: delivered {:.0} msg/s (all receivers); CPU, share of one core: send {:.2} %, relay {:.2} %, recvA {:.2} %, recvB {:.2} %",
            rig.shape.label(),
            self.args.checkpoint.as_millis(),
            (n1 - n0) as f64 / wall,
            shares[0] * 100.0,
            shares[1] * 100.0,
            shares[2] * 100.0,
            shares[3] * 100.0,
        );
        println!("    cpu: {}", cpu_line(&c0, &c1, wall));
        std::thread::sleep(Duration::from_millis(300));
        shares.map(|s| s * 100.0)
    }
}

fn main() {
    let a = Args::parse();
    println!("load average at start: {}", loadavg());
    println!(
        "path_mtu_max {}, paths {}, checkpoint {} ms, sealed {}",
        a.path_mtu_max,
        a.paths,
        a.checkpoint.as_millis(),
        a.sealed
    );
    let mut summary: BTreeMap<String, Vec<f64>> = BTreeMap::new();
    for rep in 0..a.repeat {
        println!("--- repetition {}", rep + 1);
        for &shape in &a.shapes {
            let ctx = Ctx::new(&a);
            println!("-- shape {}", shape.label());
            let rig = ctx.rig(shape);
            for only in &a.only {
                let mut put = |k: String, v: f64| summary.entry(k).or_default().push(v);
                let label = shape.label();
                let parts: Vec<&str> = only.split(':').collect();
                match parts.as_slice() {
                    ["lat", size] => {
                        let size: usize = size.parse().expect("a size");
                        let (p50, p99, _) = ctx.latency(&rig, size);
                        put(format!("{label} lat{size} p50 us"), p50);
                        put(format!("{label} lat{size} p99 us"), p99);
                    }
                    ["thr", size] => {
                        let size: usize = size.parse().expect("a size");
                        let rates = ctx.throughput(&rig, size);
                        for (rate, who) in rates.iter().zip(["A", "B"]) {
                            put(format!("{label} thr {size} B msg/s ({who})"), *rate);
                        }
                        if rates.len() == 2 {
                            put(
                                format!("{label} thr {size} B msg/s (A+B)"),
                                rates.iter().sum(),
                            );
                        }
                    }
                    ["paced", size, rate] => {
                        let (size, rate): (usize, u64) =
                            (size.parse().expect("a size"), rate.parse().expect("a rate"));
                        let shares = ctx.paced(&rig, size, rate);
                        let ck = a.checkpoint.as_millis();
                        for (who, share) in RUNTIMES.iter().zip(shares) {
                            put(
                                format!("{label} paced {size} B {rate}/s ck {ck} ms: {who} % core"),
                                share,
                            );
                        }
                    }
                    _ => {
                        panic!("unknown row `{only}` (lat:<size>, thr:<size>, paced:<size>:<rate>)")
                    }
                }
            }
            let m = &rig.mesh;
            println!(
                "link: sender's {:?}; relay table {:?}",
                m.sender.link.side_stats(),
                m.relay.as_ref().map(|r| r.engine.side().stats())
            );
            ctx.close(rig);
        }
    }
    println!("--- summary of {} repetitions: median [min, max]", a.repeat);
    for (k, mut v) in summary {
        let (m, lo, hi) = median(&mut v);
        println!("{k:<56} {m:>12.1} [{lo:.1}, {hi:.1}]");
    }
    println!("load average at end: {}", loadavg());
}
