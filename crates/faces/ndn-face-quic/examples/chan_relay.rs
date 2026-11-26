//! The channel through forwarders (stage 4, SHAPES-CHANNEL.md §8, §13) measured by the method of
//! `chan_ping`: a sender (`/bob/phone`) and one to four receivers (`/carol/tablet`, `/dave/watch`,
//! `/erin/laptop`, `/frank/phone`),
//! each device on a forwarder of its own (`ndn-engine`) and each forwarder on a runtime of its
//! own (`send`, `recvA` to `recvD`, and `relay` for the relay's), joined by real QUIC links on
//! loopback. The channel is set up by the real signed ask over the links, and the frames travel
//! `Heap::emit` -> the sender's forwarder -> link -> [the relay's side table -> a link for each
//! receiver] -> the receivers' forwarders -> `Heap::get`'s `Items`.
//!
//! Shapes (`shapes`, comma separated):
//!
//! | shape | meaning |
//! |---|---|
//! | `direct` | one receiver linked to the sender (one link, no relay) |
//! | `relay1` | one receiver behind a relay (two links) |
//! | `relay2` | two receivers behind a relay (three links): one copy of each frame leaves the sender |
//! | `relay4` | four receivers behind a relay (five links): rung `C3` |
//!
//! Rows (`only`, comma separated), run for each shape:
//!
//! | row | meaning |
//! |---|---|
//! | `lat:<size>` | the half round trip of `size` octets, for each receiver in turn (the others receive the pings too and count them): `emit` /ping at the sender -> the receiver's `Items` -> it `emit`s /pong -> the sender's `Items`; 1,000 warm-up (and 300 ms) then 10,000 timed round trips, the lowest and highest 1 % dropped |
//! | `thr:<size>` | back-to-back `emit` of `size` octets over `paths` paths for `secs` seconds after 0.5 s; each receiver counts what its `Items` yields |
//! | `paced:<size>:<per second>` | `size` octets at a fixed rate for `secs` seconds after 0.5 s: the CPU (schedstat) of each runtime, as a share of one core, with the checkpoint period of `checkpoint` |
//! | `c3:<size>:<messages>` | rung `C3` of the stage 4 gate (SHAPES-CHANNEL.md §13; use it with `relay4`): `messages` of `size` octets in windows of 20, each delivered to every receiver before the next; then the frame counts of the sender's link, the relay's table and its links, and a `C3 PASS` or `C3 FAIL` line: the sender link carries one copy of each frame (relay frames in = the sender link's frames out; relay frames out = receivers x that; every link of a receiver carries the same). The process exits 1 on a FAIL |
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
//! | `trust` | `prompt` | `prompt` or `verified`: `GetOptions::trust` of every receiver (`Verified` delivers a frame only after a signed checkpoint listing it verified: up to one checkpoint period of latency) |
//!
//! Each repetition builds every shape afresh, in the order given. Pin from the command line:
//! `taskset -c 10-13 target-shared/release/examples/chan_relay`.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use ndn_face_quic::LinkTransportConfig;
use ndn_heap::{EmitOptions, GetOptions, Items, Name, Select, Trust};
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
    Relay4,
}

impl Shape {
    fn label(self) -> &'static str {
        match self {
            Shape::Direct => "direct",
            Shape::Relay1 => "relay1",
            Shape::Relay2 => "relay2",
            Shape::Relay4 => "relay4",
        }
    }

    fn receivers(self) -> usize {
        match self {
            Shape::Direct | Shape::Relay1 => 1,
            Shape::Relay2 => 2,
            Shape::Relay4 => 4,
        }
    }

    fn relayed(self) -> bool {
        self != Shape::Direct
    }

    /// ` recv A` for a shape with more than one receiver, nothing for one.
    fn recv_tag(self, i: usize) -> String {
        if self.receivers() > 1 {
            format!(" recv {}", LETTERS[i])
        } else {
            String::new()
        }
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
    trust: Trust,
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
            "trust",
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
                .map_or("direct,relay1,relay2,relay4", String::as_str)
                .split(',')
                .map(|s| match s {
                    "direct" => Shape::Direct,
                    "relay1" => Shape::Relay1,
                    "relay2" => Shape::Relay2,
                    "relay4" => Shape::Relay4,
                    other => panic!("shapes are direct, relay1, relay2, relay4, got `{other}`"),
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
            trust: match kv.get("trust").map_or("prompt", String::as_str) {
                "prompt" => Trust::Prompt,
                "verified" => Trust::Verified,
                other => panic!("trust is `prompt` or `verified`, got `{other}`"),
            },
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

/// What these receivers take: the emissions of the channel, not the kept values.
fn emissions(trust: Trust) -> GetOptions {
    GetOptions {
        kept: false,
        trust,
        ..GetOptions::default()
    }
}

struct Ctx {
    args: Args,
    ctl: Arc<tokio::runtime::Runtime>,
    send: Arc<tokio::runtime::Runtime>,
    relay: Arc<tokio::runtime::Runtime>,
    recv: Vec<Arc<tokio::runtime::Runtime>>,
}

/// The mesh of one shape, built for the rows asked.
struct Rig {
    shape: Shape,
    mesh: Mesh,
}

impl Ctx {
    fn new(args: &Args, receivers: usize) -> Self {
        Self {
            args: args.clone(),
            ctl: runtime("ctl", 1),
            send: runtime("send", args.workers),
            relay: runtime("relay", args.workers),
            recv: (0..receivers)
                .map(|i| runtime(&format!("recv{}", LETTERS[i]), args.workers))
                .collect(),
        }
    }

    /// The labels of the runtimes' threads, for the CPU shares.
    fn runtime_names(&self) -> Vec<String> {
        ["send".to_owned(), "relay".to_owned()]
            .into_iter()
            .chain((0..self.recv.len()).map(|i| format!("recv{}", LETTERS[i])))
            .collect()
    }

    fn rig(&self, shape: Shape) -> Rig {
        let rts = Runtimes {
            send: self.send.handle().clone(),
            relay: self.relay.handle().clone(),
            recv: self.recv.iter().map(|r| r.handle().clone()).collect(),
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
                    .get(everything(), emissions(self.args.trust))
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

/// The receivers' labels (and their runtimes' threads: `recvA` ...).
const LETTERS: [&str; 4] = ["A", "B", "C", "D"];

/// What moved frames, read at one moment: the sender's link and engine, the relay's engine and
/// links (empty for a direct link), the receivers' links.
struct Wire {
    sender_tx: u64,
    sender_in: u64,
    sender_out: u64,
    relay_rx: u64,
    relay_in: u64,
    relay_out: u64,
    relay_tx: Vec<u64>,
    recv_rx: Vec<u64>,
}

fn rx_frames(s: &ndn_face_quic::SideStats) -> u64 {
    s.datagram_rx_frames + s.stream_rx_frames
}

fn wire(m: &Mesh) -> Wire {
    let sender = m.sender.site.engine.side().stats();
    let relay = m.relay.as_ref().map(|r| r.engine.side().stats());
    Wire {
        sender_tx: frames(&m.sender.link.side_stats()),
        sender_in: sender.frames_in,
        sender_out: sender.frames_out,
        relay_rx: m
            .relay_links
            .first()
            .map_or(0, |l| rx_frames(&l.side_stats())),
        relay_in: relay.as_ref().map_or(0, |r| r.frames_in),
        relay_out: relay.as_ref().map_or(0, |r| r.frames_out),
        relay_tx: m
            .relay_links
            .iter()
            .skip(1)
            .map(|l| frames(&l.side_stats()))
            .collect(),
        recv_rx: m
            .receivers
            .iter()
            .map(|r| rx_frames(&r.link.side_stats()))
            .collect(),
    }
}

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
            .zip(LETTERS)
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
            println!(
                "    fan-out: relay frames out / sender link frames out = {:.3} ({} receivers behind the relay; one copy per frame leaves the sender)",
                (r1.frames_out - r0.frames_out) as f64 / (sent_frames as f64).max(1.0),
                m.receivers.len()
            );
        }
        for (i, ((a0, e0), (a1, e1))) in rx0.iter().zip(&rx1).enumerate() {
            println!(
                "    receiver {}: link received {:.0} datagram + {:.0} stream frames/s; its forwarder: frames in {:.0}/s, out {:.0}/s, sink_full {}, unrouted {}, wrong_source {}, quota {}",
                LETTERS[i],
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
            self.runtime_names()
                .iter()
                .map(|t| per(t))
                .collect::<Vec<_>>()
                .join(", ")
        );
        std::thread::sleep(Duration::from_millis(300));
        rates
    }

    /// The half round trip of `size` octets, `emit` to `Items` and back through receiver `echo`:
    /// the sender emits /ping, the receiver's `Items` yields it and it emits /pong, the sender's
    /// `Items` yields it. 1,000 warm-up round trips (and at least 300 ms), 10,000 timed, the
    /// outer percents dropped. The other receivers, if there are any, count the pings.
    fn latency(&self, rig: &Rig, size: usize, echo: usize) -> (f64, f64, f64) {
        let m = &rig.mesh;
        let mut bob_items = m
            .sender
            .heap
            .get(everything(), emissions(self.args.trust))
            .expect("the sender is a member");
        let items = self.open(rig);
        // The sender takes the echoing receiver's channel too: the pongs come back over the same
        // links.
        self.ctl.block_on(async {
            Mesh::ask(self.send.handle(), &m.sender.node, &m.receivers[echo].node).await;
            let start = Instant::now();
            while !bob_items.hello_seen() {
                assert!(
                    start.elapsed() < Duration::from_secs(10),
                    "no HELLO at the sender"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });
        // The other receivers drain and count the pings.
        let mut drains = Vec::new();
        let mut counted = Vec::new();
        let mut echo_items = None;
        for (i, it) in items.into_iter().enumerate() {
            if i == echo {
                echo_items = Some(it);
            } else {
                let seen = Arc::new(AtomicU64::new(0));
                counted.push((i, Arc::clone(&seen)));
                drains.push(self.recv[i].spawn(consume(
                    it,
                    size,
                    seen,
                    Arc::new(AtomicU64::new(0)),
                    Arc::new(AtomicU64::new(0)),
                )));
            }
        }
        let mut a_items = echo_items.expect("the echoing receiver");
        let echo_task = {
            let a = m.receivers[echo].heap.clone();
            self.recv[echo].spawn(async move {
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
        echo_task.abort();
        for d in &drains {
            d.abort();
        }
        println!("    cpu: {}", cpu_line(&c0, &c1, wall));
        let (p50, p99, mean) = trimmed(&mut samples);
        let others = counted
            .iter()
            .map(|(i, s)| {
                format!(
                    "{} counted {} pings",
                    LETTERS[*i],
                    s.load(Ordering::Relaxed)
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        println!(
            "row {} lat{size}{} p50 {p50:.1} us  p99 {p99:.1} us  mean {mean:.1} us (half round trip, emit -> Items, 10,000 after 1,000, outer 1% dropped; {lost} round trips timed out{}{others})",
            rig.shape.label(),
            rig.shape.recv_tag(echo),
            if others.is_empty() { "" } else { "; " },
        );
        std::thread::sleep(Duration::from_millis(300));
        (p50, p99, mean)
    }

    /// `size` octets, `rate` a second, for `secs` seconds after 0.5 s; each receiver's `Items`
    /// consumed. Returns the share of one core each runtime used (`runtime_names` order).
    fn paced(&self, rig: &Rig, size: usize, rate: u64) -> Vec<f64> {
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
        let shares: Vec<f64> = self
            .runtime_names()
            .iter()
            .map(|t| cores(&c0, &c1, wall, t))
            .collect();
        let per_runtime = self
            .runtime_names()
            .iter()
            .zip(&shares)
            .map(|(t, s)| format!("{t} {:.2} %", s * 100.0))
            .collect::<Vec<_>>()
            .join(", ");
        println!(
            "row {} paced {size} B at {rate}/s, checkpoint {} ms: delivered {:.0} msg/s (all receivers); CPU, share of one core: {per_runtime}",
            rig.shape.label(),
            self.args.checkpoint.as_millis(),
            (n1 - n0) as f64 / wall,
        );
        println!("    cpu: {}", cpu_line(&c0, &c1, wall));
        std::thread::sleep(Duration::from_millis(300));
        shares.into_iter().map(|s| s * 100.0).collect()
    }

    /// Rung `C3` of the stage 4 gate (SHAPES-CHANNEL.md §13): `count` messages of `size` octets
    /// go out in windows of 20, each window delivered to every receiver before the next; then the
    /// frame counts of the links and of the relay's table say whether the sender's link carried
    /// one copy of each frame. Prints the counters and a `C3 PASS` or `C3 FAIL` line; returns
    /// whether it passed.
    fn one_copy(&self, rig: &Rig, size: usize, count: u64) -> bool {
        const WINDOW: u64 = 20;
        let m = &rig.mesh;
        let n = m.receivers.len();
        let items = self.open(rig);
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
        // Quiet (the HELLO and the first checkpoints are over), then the messages.
        std::thread::sleep(Duration::from_millis(300));
        let w0 = wire(m);
        let sent_all = {
            let (heap, seen) = (m.sender.heap.clone(), seen.clone());
            self.send.block_on(async move {
                let payload = Bytes::from(vec![0xA5; size]);
                let mut i = 0;
                while i < count {
                    let upto = (i + WINDOW).min(count);
                    for k in i..upto {
                        heap.emit(
                            &name(&format!("/c3/{k}")),
                            payload.clone(),
                            EmitOptions::default(),
                        )
                        .await
                        .map_err(|e| format!("emit refused: {e} (next: {:?})", e.next()))?;
                    }
                    let start = Instant::now();
                    while seen.iter().any(|s| s.load(Ordering::Relaxed) < upto) {
                        if start.elapsed() > Duration::from_secs(10) {
                            return Err(format!(
                                "messages up to {upto} not at every receiver within 10 s: {:?}",
                                seen.iter()
                                    .map(|s| s.load(Ordering::Relaxed))
                                    .collect::<Vec<_>>()
                            ));
                        }
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                    i = upto;
                }
                Ok::<(), String>(())
            })
        };
        // Whatever follows the messages (checkpoints) is counted on every link alike.
        std::thread::sleep(Duration::from_millis(300));
        let w1 = wire(m);
        for s in &subscribers {
            s.abort();
        }
        let delta = |f: fn(&Wire) -> u64| f(&w1) - f(&w0);
        let sent = delta(|w| w.sender_tx);
        let mut problems = Vec::new();
        if let Err(e) = sent_all {
            problems.push(e);
        }
        if sent < count {
            problems.push(format!("{count} messages went out in {sent} frames"));
        }
        let mut check = |what: String, got: u64, want: u64| {
            if got != want {
                problems.push(format!("{what}: {got}, expected {want}"));
            }
        };
        check(
            "sender engine frames in".into(),
            delta(|w| w.sender_in),
            sent,
        );
        check(
            "sender engine frames out".into(),
            delta(|w| w.sender_out),
            sent,
        );
        if m.relay.is_some() {
            check(
                "relay link frames in from the sender".into(),
                delta(|w| w.relay_rx),
                sent,
            );
            check("relay frames in".into(), delta(|w| w.relay_in), sent);
            check(
                "relay frames out".into(),
                delta(|w| w.relay_out),
                n as u64 * sent,
            );
            for (who, (a, b)) in LETTERS.iter().zip(w1.relay_tx.iter().zip(&w0.relay_tx)) {
                check(format!("relay link {who} frames out"), a - b, sent);
            }
        }
        for (who, (a, b)) in LETTERS.iter().zip(w1.recv_rx.iter().zip(&w0.recv_rx)) {
            check(format!("receiver {who} link frames in"), a - b, sent);
        }
        for (who, got) in LETTERS.iter().zip(&seen) {
            check(
                format!("receiver {who} items"),
                got.load(Ordering::Relaxed),
                count,
            );
        }
        check("wrong-size items".into(), bad.load(Ordering::Relaxed), 0);
        println!(
            "row {} c3 {size} B x {count}: sender link frames out {sent} ({} beyond the messages); sender engine in {} out {}; relay in {} out {} ({n} x {sent} expected); relay links out {:?}; receivers' links in {:?}; items per receiver {:?}",
            rig.shape.label(),
            sent.saturating_sub(count),
            delta(|w| w.sender_in),
            delta(|w| w.sender_out),
            delta(|w| w.relay_in),
            delta(|w| w.relay_out),
            w1.relay_tx
                .iter()
                .zip(&w0.relay_tx)
                .map(|(a, b)| a - b)
                .collect::<Vec<_>>(),
            w1.recv_rx
                .iter()
                .zip(&w0.recv_rx)
                .map(|(a, b)| a - b)
                .collect::<Vec<_>>(),
            seen.iter()
                .map(|s| s.load(Ordering::Relaxed))
                .collect::<Vec<_>>(),
        );
        let ok = problems.is_empty();
        if ok {
            println!(
                "C3 PASS ({}): the sender link carries one copy of each frame ({sent} frames out of the sender for {count} messages; every one of {n} receivers got all {count}, each over a link of its own)",
                rig.shape.label()
            );
        } else {
            println!(
                "C3 FAIL ({}): the sender link does not carry one copy of each frame: {}. Next: if the relay's frames out are not receivers x frames in, no route was installed at the relay (`side/list` on it); if the sender link carries more than the relay took in, the sender sent per receiver",
                rig.shape.label(),
                problems.join("; ")
            );
        }
        std::thread::sleep(Duration::from_millis(300));
        ok
    }
}

fn main() {
    let a = Args::parse();
    println!("load average at start: {}", loadavg());
    println!(
        "path_mtu_max {}, paths {}, checkpoint {} ms, sealed {}, trust {:?}",
        a.path_mtu_max,
        a.paths,
        a.checkpoint.as_millis(),
        a.sealed,
        a.trust
    );
    let mut summary: BTreeMap<String, Vec<f64>> = BTreeMap::new();
    let mut c3_failed = false;
    for rep in 0..a.repeat {
        println!("--- repetition {}", rep + 1);
        for &shape in &a.shapes {
            let ctx = Ctx::new(&a, shape.receivers());
            println!("-- shape {}", shape.label());
            let rig = ctx.rig(shape);
            for only in &a.only {
                let mut put = |k: String, v: f64| summary.entry(k).or_default().push(v);
                let label = shape.label();
                let parts: Vec<&str> = only.split(':').collect();
                match parts.as_slice() {
                    ["lat", size] => {
                        let size: usize = size.parse().expect("a size");
                        for echo in 0..shape.receivers() {
                            let (p50, p99, _) = ctx.latency(&rig, size, echo);
                            let tag = shape.recv_tag(echo);
                            put(format!("{label} lat{size} p50 us{tag}"), p50);
                            put(format!("{label} lat{size} p99 us{tag}"), p99);
                        }
                    }
                    ["thr", size] => {
                        let size: usize = size.parse().expect("a size");
                        let rates = ctx.throughput(&rig, size);
                        for (rate, who) in rates.iter().zip(LETTERS) {
                            put(format!("{label} thr {size} B msg/s ({who})"), *rate);
                        }
                        if rates.len() > 1 {
                            put(
                                format!(
                                    "{label} thr {size} B msg/s ({})",
                                    LETTERS[..rates.len()].join("+")
                                ),
                                rates.iter().sum(),
                            );
                        }
                    }
                    ["paced", size, rate] => {
                        let (size, rate): (usize, u64) =
                            (size.parse().expect("a size"), rate.parse().expect("a rate"));
                        let shares = ctx.paced(&rig, size, rate);
                        let ck = a.checkpoint.as_millis();
                        for (who, share) in ctx.runtime_names().iter().zip(shares) {
                            put(
                                format!("{label} paced {size} B {rate}/s ck {ck} ms: {who} % core"),
                                share,
                            );
                        }
                    }
                    ["c3", size, count] => {
                        let (size, count): (usize, u64) = (
                            size.parse().expect("a size"),
                            count.parse().expect("a count"),
                        );
                        c3_failed |= !ctx.one_copy(&rig, size, count);
                    }
                    _ => {
                        panic!(
                            "unknown row `{only}` (lat:<size>, thr:<size>, paced:<size>:<rate>, c3:<size>:<messages>)"
                        )
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
    if c3_failed {
        println!("C3 FAILED in at least one repetition (see the `C3 FAIL` lines above)");
        std::process::exit(1);
    }
}
