//! The channel (`Heap::emit` -> `Heap::live`'s `Items`, ndn-heap) over one link, measured by the
//! method of `carrier_bench` and `side_ping` (SHAPES-CHANNEL.md §12.7, rung C1): two data-layer
//! nodes, a writer (`/bob/phone`, on the `send` runtime) and a reader (`/carol/tablet`, on the
//! `recv` runtime), whose channel is set up by the real signed ask (`NodeHandle::ask_channel`) and
//! whose frames travel over ONE direct QUIC link on loopback: `Carrier` is an adapter over
//! `LinkFace::forward_side` (datagrams, refused `Full` by the link's headroom rule),
//! `LinkFace::send_side` (the stream) and `SideLimits`; frames come in by `LinkFace::recv_bytes`
//! and `NodeHandle::deliver_frame`. The two nodes share one forwarder (a third runtime, `ctl`) for
//! the space's sync and the ask, so the setup's Interests do not cross the link; the frames do.
//!
//! Rows (`only`, comma separated):
//!
//! | row | meaning |
//! |---|---|
//! | `lat` | the 64 B half round trip: `emit` /ping -> `Items` -> `emit` /pong -> `Items`; 1,000 warm-up (and 300 ms) then 10,000 timed round trips, the lowest and highest 1 % dropped |
//! | `thr:<size>` | back-to-back `emit` of `size` octets over `paths` paths for `secs` seconds after 0.5 s; the reader counts what `Items` yields |
//! | `cpu` | the per-message CPU of §12.5 with no link: 14 messages of 64 B per frame into a recording carrier (sender ns/message), then the frames through `deliver_frame` and `Items` (receiver ns/message) by `poll_next` and by `next_batch` |
//!
//! Arguments are `key=value` words:
//!
//! | key | default | meaning |
//! |---|---|---|
//! | `only` | `lat,thr:64` | rows |
//! | `repeat`, `secs`, `workers` | 3, 3, 1 | as in `side_ping` |
//! | `path_mtu_max` | 9000 | `LinkTransportConfig::path_mtu_max` (the library's default) |
//! | `paths` | 256 | distinct paths the throughput rows rotate over (`Latest` keeps the newest per path: one path would measure frames per second, not messages) |
//! | `consume` | `poll` | `poll`: `Items::next` per message; `batch`: `next_batch`; the `cpu` row runs both unless given |
//! | `msgs` | 1000000 | messages the `cpu` row times |
//! | `raw_lat`, `raw_thr_<size>` | | the raw datagram row (`carrier_bench`, `side_ping`) at the same settings: the summary prints the gates of §12.1 and §12.3 |
//! | `profile` | | a file: the sampled CPU profile of the `send` and `recv` threads (SHAPES-CHANNEL.md §17.1) |
//!
//! Pin from the command line: `taskset -c 10-13 target-shared/release/examples/chan_ping`.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use bytes::Bytes;
use ndn_app::EngineAppExt;
use ndn_engine::{EngineBuilder, ForwarderEngine};
use ndn_face_quic::{Link, LinkTransportConfig};
use ndn_heap::{
    Carrier, CarrierFuture, CarrierRefused, Config, Delivery, EmitOptions, GetOptions, Heap, Items,
    Name, Node, Readers, Select, Share, host::NodeHandle,
};
use ndn_security::{Certificate, SecurityManager, SignedTrustContext, TrustSchema, Validator};
use ndn_sync::{DataStore, MemoryStore};
use ndn_transport::{SideClass, SideRefused, Transport};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

mod common;
#[path = "common/pair.rs"]
mod pair;
#[path = "common/sampler.rs"]
mod sampler;
use common::{cpu_line, median, runtime, threads, trimmed};
use pair::{Pair, connect};

/// Zenoh's rates on this machine (SHAPES-CHANNEL.md §1.2), msg/s.
const ZENOH: [(usize, f64); 4] = [(8, 1.98e6), (64, 1.94e6), (1024, 987e3), (8192, 199.6e3)];
/// The datagram a path of 1,200 octets takes (the floor): the size §12.5's 14 messages fill.
const FLOOR_DATAGRAM: usize = 1162;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Consume {
    Poll,
    Batch,
}

impl Consume {
    fn label(self) -> &'static str {
        match self {
            Consume::Poll => "poll_next",
            Consume::Batch => "next_batch",
        }
    }
}

#[derive(Clone)]
struct Args {
    only: Vec<String>,
    repeat: usize,
    secs: f64,
    workers: usize,
    path_mtu_max: u16,
    paths: usize,
    consume: Option<Consume>,
    msgs: usize,
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
            "workers",
            "path_mtu_max",
            "paths",
            "consume",
            "msgs",
            "profile",
        ];
        for k in kv.keys() {
            assert!(
                known.contains(&k.as_str()) || k.starts_with("raw_"),
                "unknown argument `{k}` (see the file's header)"
            );
        }
        let num = |k: &str, d: f64| kv.get(k).map_or(d, |v| v.parse().expect("a number"));
        Self {
            only: kv
                .get("only")
                .map_or("lat,thr:64", String::as_str)
                .split(',')
                .map(str::to_owned)
                .collect(),
            repeat: num("repeat", 3.0) as usize,
            secs: num("secs", 3.0),
            workers: num("workers", 1.0) as usize,
            path_mtu_max: num("path_mtu_max", 9000.0) as u16,
            paths: num("paths", 256.0) as usize,
            consume: kv.get("consume").map(|v| match v.as_str() {
                "poll" => Consume::Poll,
                "batch" => Consume::Batch,
                other => panic!("consume is `poll` or `batch`, got `{other}`"),
            }),
            msgs: num("msgs", 1_000_000.0) as usize,
            profile: kv.get("profile").cloned(),
            raw: kv
                .iter()
                .filter(|(k, _)| k.starts_with("raw_"))
                .map(|(k, v)| (k.clone(), v.parse().expect("a number")))
                .collect(),
        }
    }
}

fn name(uri: &str) -> Name {
    uri.parse().expect("a valid name")
}

fn loadavg() -> String {
    std::fs::read_to_string("/proc/loadavg")
        .map(|s| s.split(' ').take(3).collect::<Vec<_>>().join(" "))
        .unwrap_or_else(|e| format!("unreadable: {e}"))
}

// ---- the carrier: an adapter over a link face --------------------------------------------------

/// A node's `Carrier` over one link: datagrams by `forward_side` (the headroom rule refuses with
/// `Full`), the stream by `send_side`, the datagram size from `SideLimits`. `on_ready` is served by
/// a writer task of the carrier's own, which waits until the link would take a datagram.
struct FaceCarrier {
    link: Arc<Link>,
    ready: Mutex<Vec<Box<dyn FnOnce() + Send>>>,
    wake: tokio::sync::Notify,
}

impl FaceCarrier {
    fn start(link: Arc<Link>, rt: &tokio::runtime::Handle) -> (Arc<Self>, JoinHandle<()>) {
        let me = Arc::new(Self {
            link,
            ready: Mutex::new(Vec::new()),
            wake: tokio::sync::Notify::new(),
        });
        let writer = rt.spawn(Arc::clone(&me).writer());
        (me, writer)
    }

    /// Run what `on_ready` was given, each once the link takes a datagram again.
    async fn writer(self: Arc<Self>) {
        loop {
            self.wake.notified().await;
            loop {
                let drains: Vec<_> =
                    std::mem::take(&mut *self.ready.lock().unwrap_or_else(PoisonError::into_inner));
                if drains.is_empty() {
                    break;
                }
                let mut yields = 0;
                loop {
                    let limits = self.link.face.side_limits();
                    if limits.queued < limits.queue_max {
                        break;
                    }
                    if yields < 256 {
                        yields += 1;
                        tokio::task::yield_now().await;
                    } else {
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                }
                for drain in drains {
                    drain();
                }
            }
        }
    }

    fn refused(refusal: SideRefused) -> CarrierRefused {
        match refusal {
            SideRefused::Full => CarrierRefused::Full,
            SideRefused::TooLarge { max, .. } => CarrierRefused::TooLarge { max },
            SideRefused::Closed => CarrierRefused::Closed,
            other => {
                eprintln!("carrier: the link refused a channel frame for good: {other}");
                CarrierRefused::Closed
            }
        }
    }
}

impl Carrier for FaceCarrier {
    fn datagram_max(&self) -> usize {
        self.link.face.side_limits().frame_max
    }

    fn has_stream(&self) -> bool {
        true
    }

    fn try_send_datagram(&self, frame: Bytes) -> Result<(), CarrierRefused> {
        self.link
            .face
            .forward_side(frame, SideClass::Datagram)
            .map_err(Self::refused)
    }

    fn send_stream(&self, frame: Bytes) -> CarrierFuture<'_, Result<(), CarrierRefused>> {
        Box::pin(async move {
            self.link
                .face
                .send_side(frame, SideClass::Stream)
                .await
                .map_err(Self::refused)
        })
    }

    fn on_ready(&self, drain: Box<dyn FnOnce() + Send>) {
        self.ready
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(drain);
        self.wake.notify_one();
    }
}

/// A carrier that records frames and takes one per `release`: the sender's CPU with no link, so
/// that the messages queued between two releases leave in one frame.
struct Tap {
    frames: Mutex<Vec<Bytes>>,
    drain: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    open: AtomicBool,
}

impl Tap {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            frames: Mutex::new(Vec::new()),
            drain: Mutex::new(None),
            open: AtomicBool::new(false),
        })
    }

    /// Let one frame through: run the drain the sender asked for.
    fn release(&self) {
        self.open.store(true, Ordering::Release);
        let drain = self
            .drain
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(drain) = drain {
            drain();
        }
    }

    fn take(&self) -> Vec<Bytes> {
        std::mem::take(&mut *self.frames.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

impl Carrier for Tap {
    fn datagram_max(&self) -> usize {
        FLOOR_DATAGRAM
    }

    fn has_stream(&self) -> bool {
        false
    }

    fn try_send_datagram(&self, frame: Bytes) -> Result<(), CarrierRefused> {
        if !self.open.swap(false, Ordering::AcqRel) {
            return Err(CarrierRefused::Full);
        }
        self.frames
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(frame);
        Ok(())
    }

    fn send_stream(&self, _frame: Bytes) -> CarrierFuture<'_, Result<(), CarrierRefused>> {
        Box::pin(async { Err(CarrierRefused::Closed) })
    }

    fn on_ready(&self, drain: Box<dyn FnOnce() + Send>) {
        *self.drain.lock().unwrap_or_else(PoisonError::into_inner) = Some(drain);
    }
}

// ---- the two nodes -----------------------------------------------------------------------------

struct Dev {
    name: Name,
    keys: Arc<SecurityManager>,
    validator: Arc<Validator>,
}

/// Each device's key is certified by its namespace's root; every validator holds every anchor and
/// every certificate. A device's namespace is its first name component.
async fn world(devices: &[&str]) -> Vec<Dev> {
    let ns_of = |n: &Name| Name::from_components(n.components()[..1].iter().cloned());
    let mut roots: Vec<(Name, SecurityManager, Name, Certificate)> = Vec::new();
    for d in devices {
        let ns = ns_of(&name(d));
        if roots.iter().any(|(r, ..)| *r == ns) {
            continue;
        }
        let mgr = SecurityManager::new();
        let key = ns.clone().append("KEY").append("root");
        mgr.generate_ed25519(key.clone()).unwrap();
        let pk = mgr.get_signer_sync(&key).unwrap().public_key().unwrap();
        let anchor = mgr.issue_self_signed(&key, pk, u64::MAX).unwrap();
        roots.push((ns, mgr, key, anchor));
    }
    let mut made = Vec::new();
    for d in devices {
        let device = name(d);
        let ns = ns_of(&device);
        let (_, root, root_key, _) = roots.iter().find(|(r, ..)| *r == ns).unwrap();
        let keys = Arc::new(SecurityManager::new());
        let key = keys
            .generate_ed25519(device.clone().append("KEY").append("1"))
            .unwrap();
        let public = keys.get_signer_sync(&key).unwrap().public_key().unwrap();
        let cert = root
            .certify(&key, public, root_key, 365 * 24 * 3600 * 1000)
            .await
            .unwrap();
        made.push((device, keys, cert));
    }
    let validator = || {
        let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
        for (ns, _, _, anchor) in &roots {
            let ctx = SignedTrustContext::hierarchical(ns.clone());
            assert!(ctx.add_anchor(anchor.clone()));
            validator.adopt_context(Arc::new(ctx)).unwrap();
        }
        for (_, _, cert) in &made {
            validator.cert_cache().insert(cert.clone());
        }
        validator
    };
    made.iter()
        .map(|(device, keys, _)| Dev {
            name: device.clone(),
            keys: Arc::clone(keys),
            validator: validator(),
        })
        .collect()
}

fn config() -> Config {
    let mut c = Config::new();
    c.settle = Duration::from_secs(3);
    c.svs.jitter_ms = 20;
    c.svs.suppression_period = Duration::from_millis(30);
    c.svs.sync_interval = Duration::from_secs(1);
    c
}

fn space() -> Name {
    name("/bob/32=data/bench")
}

/// Ask `device` for its channel until it answers: the space's record takes a moment to reach the
/// asker.
async fn ask(node: &NodeHandle, device: &Name) {
    let start = Instant::now();
    loop {
        match node.ask_channel(&space(), device).await {
            Ok(_) => return,
            Err(e) if start.elapsed() < Duration::from_secs(30) => {
                let _ = e;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(e) => panic!(
                "{} asked {device} for a channel: {e} (next: {:?})",
                node.name(),
                e.next()
            ),
        }
    }
}

/// Bob writes, Carol reads (and, with a link, the other way too for the echo).
struct Rig {
    bob: Node,
    carol: Node,
    bob_heap: Heap,
    carol_heap: Heap,
    cancel: CancellationToken,
    tasks: Vec<JoinHandle<()>>,
    pair: Option<Pair>,
    _engine: ForwarderEngine,
}

impl Drop for Rig {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
        self.bob.shutdown();
        self.carol.shutdown();
        self.cancel.cancel();
    }
}

struct Ctx {
    args: Args,
    rt_ctl: Arc<tokio::runtime::Runtime>,
    rt_tx: Arc<tokio::runtime::Runtime>,
    rt_rx: Arc<tokio::runtime::Runtime>,
}

/// Frames Carol reads off her end of the link go to her node, and Bob's to his.
async fn reader(link: Arc<Link>, node: NodeHandle, ingress: u64, dropped: Arc<AtomicU64>) {
    while let Ok(frame) = link.face.recv_bytes().await {
        if let Delivery::Dropped(_) = node.deliver_frame(frame, ingress).await {
            dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl Ctx {
    /// The nodes, the space and the channel(s). `pair`: over a link both ways; none: Bob's
    /// carrier is `tap`.
    fn rig(&self, pair: Option<Pair>, tap: Option<Arc<Tap>>, dropped: &Arc<AtomicU64>) -> Rig {
        let devs = self
            .rt_ctl
            .block_on(world(&["/bob/phone", "/carol/tablet"]));
        let cancel = CancellationToken::new();
        let (engine, transports) = self.rt_ctl.block_on(async {
            let (engine, shutdown) = EngineBuilder::new(Default::default())
                .build()
                .await
                .expect("an engine");
            shutdown.detach();
            for dev in &devs {
                let ns = Name::from_components(dev.name.components()[..1].iter().cloned());
                ndn_namespace::sync_group::carry(&engine, &ns);
            }
            let transports: Vec<_> = devs
                .iter()
                .map(|_| ndn_heap::Transport {
                    sync: engine.app_face(cancel.child_token()),
                    node: engine.app_node(cancel.child_token()),
                })
                .collect();
            (engine, transports)
        });
        let mut nodes = Vec::new();
        for (dev, transport) in devs.iter().zip(transports) {
            let rt = if nodes.is_empty() {
                &self.rt_tx
            } else {
                &self.rt_rx
            };
            nodes.push(
                rt.block_on(Node::start(
                    transport,
                    dev.name.clone(),
                    Arc::clone(&dev.keys),
                    Arc::clone(&dev.validator),
                    Arc::new(MemoryStore::new()) as Arc<dyn DataStore>,
                    config(),
                ))
                .expect("the node starts"),
            );
        }
        let carol = nodes.pop().unwrap();
        let bob = nodes.pop().unwrap();
        let share = Share {
            readers: Readers::Persons(vec![name("/bob"), name("/carol")]),
            writers: vec![name("/carol")],
        };
        let bob_heap = self.rt_tx.block_on(bob.create(&space(), share)).unwrap();
        let carol_heap = self.rt_rx.block_on(carol.open(&space())).unwrap();
        let mut tasks = Vec::new();
        if let Some(pair) = &pair {
            let (bob_carrier, w1) = FaceCarrier::start(Arc::clone(&pair.tx), self.rt_tx.handle());
            let (carol_carrier, w2) = FaceCarrier::start(Arc::clone(&pair.rx), self.rt_rx.handle());
            bob.attach_carrier(bob_carrier);
            carol.attach_carrier(carol_carrier);
            tasks.extend([
                w1,
                w2,
                self.rt_tx.spawn(reader(
                    Arc::clone(&pair.tx),
                    bob.handle(),
                    1,
                    Arc::clone(dropped),
                )),
                self.rt_rx.spawn(reader(
                    Arc::clone(&pair.rx),
                    carol.handle(),
                    2,
                    Arc::clone(dropped),
                )),
            ]);
            self.rt_tx.block_on(ask(&bob, carol.name()));
        }
        if let Some(tap) = tap {
            bob.attach_carrier(tap);
        }
        self.rt_rx.block_on(ask(&carol, bob.name()));
        Rig {
            bob,
            carol,
            bob_heap,
            carol_heap,
            cancel,
            tasks,
            pair,
            _engine: engine,
        }
    }

    fn link_rig(&self, dropped: &Arc<AtomicU64>) -> Rig {
        let config = LinkTransportConfig {
            path_mtu_max: self.args.path_mtu_max,
            ..LinkTransportConfig::default()
        };
        let pair = self
            .rt_tx
            .block_on(connect(&config, self.rt_rx.handle(), self.rt_tx.handle()));
        self.rig(Some(pair), None, dropped)
    }
}

fn everything() -> Select {
    Select::Prefix(Name::root())
}

/// Take what `Items` yields until it ends, counting items and their size mismatches.
async fn consume(
    mut items: Items,
    mode: Consume,
    size: usize,
    seen: Arc<AtomicU64>,
    notices: Arc<AtomicU64>,
    bad: Arc<AtomicU64>,
) {
    let mut buf = Vec::with_capacity(8192);
    loop {
        if mode == Consume::Batch {
            let n = items.next_batch(&mut buf);
            if n > 0 {
                let wrong = buf.iter().filter(|g| g.bytes.len() != size).count();
                buf.clear();
                bad.fetch_add(wrong as u64, Ordering::Relaxed);
                seen.fetch_add(n as u64, Ordering::Relaxed);
                continue;
            }
        }
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

impl Ctx {
    /// Back-to-back `emit` of `size` octets for `secs` seconds; the reader counts what `Items`
    /// yields. Returns the delivered rate.
    fn throughput(&self, rig: &Rig, size: usize, mode: Consume) -> f64 {
        let (stop, sent, failed) = (
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
        );
        let (seen, notices, bad) = (
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
        );
        let items = rig
            .carol_heap
            .live(everything(), GetOptions::default())
            .expect("carol is a member");
        let subscriber = self.rt_rx.spawn(consume(
            items,
            mode,
            size,
            Arc::clone(&seen),
            Arc::clone(&notices),
            Arc::clone(&bad),
        ));
        let paths: Vec<Name> = (0..self.args.paths)
            .map(|i| name(&format!("/t/{i}")))
            .collect();
        let publisher = {
            let (heap, stop, sent, failed) = (
                rig.bob_heap.clone(),
                Arc::clone(&stop),
                Arc::clone(&sent),
                Arc::clone(&failed),
            );
            self.rt_tx.spawn(async move {
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
                    // The writer and the link's driver share this worker: one pass of
                    // emissions, then they run.
                    tokio::task::yield_now().await;
                }
            })
        };
        let tx = &rig.pair.as_ref().expect("a link").tx;
        std::thread::sleep(Duration::from_millis(500));
        let (c0, s0, n0, t0, st0) = (
            threads(),
            sent.load(Ordering::Relaxed),
            seen.load(Ordering::Relaxed),
            Instant::now(),
            tx.handle.side_stats(),
        );
        std::thread::sleep(Duration::from_secs_f64(self.args.secs));
        let (c1, s1, n1, wall, st1) = (
            threads(),
            sent.load(Ordering::Relaxed),
            seen.load(Ordering::Relaxed),
            t0.elapsed().as_secs_f64(),
            tx.handle.side_stats(),
        );
        stop.store(true, Ordering::Relaxed);
        publisher.abort();
        subscriber.abort();
        let recv = (n1 - n0) as f64 / wall;
        let emitted = (s1 - s0) as f64 / wall;
        let frames = (st1.datagram_tx_frames - st0.datagram_tx_frames)
            + (st1.stream_tx_frames - st0.stream_tx_frames);
        println!(
            "row thr {size:>5} B  recv {recv:>9.0} msg/s  {:>5.2} Gbit/s   emitted {emitted:>9.0} msg/s ({:.1} % delivered)   {} frames/s, {:.1} messages per frame ({} datagram, {} stream frames)",
            recv * size as f64 * 8.0 / 1e9,
            100.0 * recv / emitted.max(1.0),
            (frames as f64 / wall) as u64,
            (n1 - n0) as f64 / frames.max(1) as f64,
            st1.datagram_tx_frames - st0.datagram_tx_frames,
            st1.stream_tx_frames - st0.stream_tx_frames,
        );
        println!(
            "    side stats (writer): refused {}, sink_full {}, stream_blocked {}, queued_peak {} B; wrong-size items {}, notices {}, emits refused {}",
            st1.refused - st0.refused,
            st1.sink_full - st0.sink_full,
            st1.stream_blocked - st0.stream_blocked,
            st1.queued_peak,
            bad.load(Ordering::Relaxed),
            notices.load(Ordering::Relaxed),
            failed.load(Ordering::Relaxed),
        );
        println!("    cpu: {}", cpu_line(&c0, &c1, wall));
        let per = |thread: &str| -> String {
            let ns = |a: &std::collections::BTreeMap<u32, common::ThreadCpu>| -> u64 {
                a.values().filter(|c| c.name == thread).map(|c| c.ns).sum()
            };
            let cpu = ns(&c1).saturating_sub(ns(&c0)) as f64;
            format!("{thread} {:.0} ns/message", cpu / ((n1 - n0).max(1) as f64))
        };
        println!(
            "    cpu per delivered message ({}): {}, {}",
            mode.label(),
            per("send"),
            per("recv")
        );
        std::thread::sleep(Duration::from_millis(300));
        recv
    }

    /// The 64 B half round trip, `emit` to `Items` and back: Bob emits /ping, Carol's `Items`
    /// yields it and she emits /pong, Bob's `Items` yields it. 1,000 warm-up round trips (and at
    /// least 300 ms, the name table's first 200 ms), 10,000 timed, the outer percents dropped.
    fn latency(&self, rig: &Rig) -> (f64, f64, f64) {
        let mut bob_items = rig
            .bob_heap
            .live(everything(), GetOptions::default())
            .expect("bob is a member");
        let mut carol_items = rig
            .carol_heap
            .live(everything(), GetOptions::default())
            .expect("carol is a member");
        let echo = {
            let carol = rig.carol_heap.clone();
            self.rt_rx.spawn(async move {
                let pong = name("/pong");
                while let Some(item) = carol_items.next().await {
                    if let Ok(got) = item
                        && carol
                            .emit(&pong, got.bytes, EmitOptions::default())
                            .await
                            .is_err()
                    {
                        break;
                    }
                }
            })
        };
        let bob = rig.bob_heap.clone();
        let (c0, t0) = (threads(), Instant::now());
        let (mut samples, lost) = self.rt_tx.block_on(async move {
            let (ping, pong) = (name("/ping"), name("/pong"));
            let payload = Bytes::from(vec![0x06; 64]);
            let mut out = Vec::with_capacity(10_000);
            let (mut lost, start) = (0u32, Instant::now());
            let mut i = 0u32;
            while out.len() < 10_000 {
                let t = Instant::now();
                bob.emit(&ping, payload.clone(), EmitOptions::default())
                    .await
                    .unwrap();
                let answer = tokio::time::timeout(Duration::from_secs(1), async {
                    loop {
                        match bob_items.next().await {
                            Some(Ok(got)) if got.path == pong => return true,
                            Some(_) => {}
                            None => return false,
                        }
                    }
                })
                .await;
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
        println!("    cpu: {}", cpu_line(&c0, &c1, wall));
        let (p50, p99, mean) = trimmed(&mut samples);
        println!(
            "row lat64 p50 {p50:.1} us  p99 {p99:.1} us  mean {mean:.1} us (half round trip, emit -> Items, 10,000 after 1,000, outer 1% dropped; {lost} round trips timed out)"
        );
        std::thread::sleep(Duration::from_millis(300));
        (p50, p99, mean)
    }

    /// §12.5: the per-message CPU at 64 B and 14 messages per frame, with no link.
    fn cpu(&self, mode: Consume) -> (f64, f64, f64) {
        let tap = Tap::new();
        let dropped = Arc::new(AtomicU64::new(0));
        let rig = self.rig(None, Some(Arc::clone(&tap)), &dropped);
        let mut items = rig
            .carol_heap
            .live(everything(), GetOptions::default())
            .expect("carol is a member");
        let paths: Vec<Name> = (0..14).map(|i| name(&format!("/c/{i}"))).collect();
        let payload = Bytes::from(vec![0xA5; 64]);
        let bob = rig.bob_heap.clone();
        let emit_frames = |rounds: usize| {
            let (bob, tap, paths, payload) = (
                bob.clone(),
                Arc::clone(&tap),
                paths.clone(),
                payload.clone(),
            );
            self.rt_tx.block_on(async move {
                for _ in 0..rounds {
                    for path in &paths {
                        bob.emit(path, payload.clone(), EmitOptions::default())
                            .await
                            .unwrap();
                    }
                    tap.release();
                }
            })
        };
        let deliver =
            |frames: Vec<Bytes>, items: &mut Items, mode: Consume| -> (Duration, Duration, u64) {
                let carol = rig.carol.handle();
                self.rt_rx.block_on(async {
                    let (mut open, mut take, mut got) = (Duration::ZERO, Duration::ZERO, 0u64);
                    let mut buf = Vec::with_capacity(64);
                    for frame in frames {
                        let t0 = Instant::now();
                        let Delivery::Delivered { messages } = carol.deliver_frame(frame, 2).await
                        else {
                            panic!("a frame of the real sender was refused");
                        };
                        let t1 = Instant::now();
                        match mode {
                            Consume::Poll => {
                                let mut taken = 0;
                                while taken < messages {
                                    match items.next().await {
                                        Some(Ok(g)) => {
                                            std::hint::black_box(&g);
                                            taken += 1;
                                        }
                                        Some(Err(_)) => {}
                                        None => panic!("the items ended"),
                                    }
                                }
                                got += taken as u64;
                            }
                            Consume::Batch => {
                                got += items.next_batch(&mut buf) as u64;
                                std::hint::black_box(&buf);
                                buf.clear();
                            }
                        }
                        let t2 = Instant::now();
                        open += t1 - t0;
                        take += t2 - t1;
                    }
                    (open, take, got)
                })
            };
        // The first messages and those within 200 ms of a bind carry their names: leave that
        // behind, delivering its frames so the receiver has the binds.
        emit_frames(100);
        std::thread::sleep(Duration::from_millis(300));
        let warm = tap.take();
        deliver(warm, &mut items, Consume::Batch);
        let rounds = self.args.msgs / 14;
        let t = Instant::now();
        emit_frames(rounds);
        let send = t.elapsed();
        let frames = tap.take();
        let per_frame = (rounds * 14) as f64 / frames.len() as f64;
        let bytes: usize = frames.iter().map(Bytes::len).sum();
        let (open, take, got) = deliver(frames, &mut items, mode);
        let messages = (rounds * 14) as f64;
        let ns = |d: Duration| d.as_secs_f64() * 1e9 / messages;
        println!(
            "row cpu 64 B x 14 ({}): sender {:.0} ns/message ({:.2} M msg/s)   receiver {:.0} ns/message = deliver_frame {:.0} + {} {:.0} ({:.2} M msg/s)   [{} messages, {:.2} per frame, {:.0} octets per frame, {} delivered, {} refused]",
            mode.label(),
            ns(send),
            1e3 / ns(send),
            ns(open + take),
            ns(open),
            mode.label(),
            ns(take),
            1e3 / ns(open + take),
            messages as u64,
            per_frame,
            bytes as f64 / (rounds as f64),
            got,
            dropped.load(Ordering::Relaxed),
        );
        (ns(send), ns(open + take), per_frame)
    }
}

fn main() {
    let a = Args::parse();
    println!("load average at start: {}", loadavg());
    println!(
        "path_mtu_max {}, paths {}, consume {:?}",
        a.path_mtu_max, a.paths, a.consume
    );
    let mut summary: BTreeMap<String, Vec<f64>> = BTreeMap::new();
    for rep in 0..a.repeat {
        let ctx = Ctx {
            rt_ctl: runtime("ctl", 1),
            rt_rx: runtime("recv", a.workers),
            rt_tx: runtime("send", a.workers),
            args: a.clone(),
        };
        println!("--- repetition {}", rep + 1);
        let dropped = Arc::new(AtomicU64::new(0));
        let mut rig: Option<Rig> = None;
        if a.profile.is_some() && rep == 0 {
            let tids: Vec<u32> = threads()
                .into_iter()
                .filter(|(_, c)| ["send", "recv", "both", "chan_ping"].contains(&c.name.as_str()))
                .map(|(t, _)| t)
                .collect();
            sampler::start(&tids);
        }
        for only in &a.only {
            let mut put = |k: String, v: f64| summary.entry(k).or_default().push(v);
            match only.split_once(':') {
                None if only == "lat" => {
                    let rig = rig.get_or_insert_with(|| ctx.link_rig(&dropped));
                    let (p50, p99, _) = ctx.latency(rig);
                    put("lat64 p50 us".into(), p50);
                    put("lat64 p99 us".into(), p99);
                }
                Some(("thr", size)) => {
                    let size: usize = size.parse().expect("a size");
                    let rig = rig.get_or_insert_with(|| ctx.link_rig(&dropped));
                    let mode = a.consume.unwrap_or(Consume::Poll);
                    put(
                        format!("thr {size} B msg/s ({})", mode.label()),
                        ctx.throughput(rig, size, mode),
                    );
                }
                None if only == "cpu" => {
                    let modes = a
                        .consume
                        .map_or(vec![Consume::Poll, Consume::Batch], |m| vec![m]);
                    for mode in modes {
                        let (send, recv, per_frame) = ctx.cpu(mode);
                        put(format!("cpu sender ns/message ({})", mode.label()), send);
                        put(format!("cpu receiver ns/message ({})", mode.label()), recv);
                        put("cpu messages per frame".into(), per_frame);
                    }
                }
                _ => panic!("unknown row `{only}` (lat, thr:<size>, cpu)"),
            }
        }
        if let Some(path) = a.profile.as_deref().filter(|_| rep == 0) {
            let names = threads().into_iter().map(|(t, c)| (t, c.name)).collect();
            sampler::dump(path, &names);
        }
        if let Some(rig) = &rig {
            let pair = rig.pair.as_ref().expect("a link");
            println!(
                "link: datagram size {:?}, writer side stats {:?}, frames refused at the reader {}",
                pair.tx.handle.max_datagram_size(),
                pair.tx.handle.side_stats(),
                dropped.load(Ordering::Relaxed)
            );
        }
    }
    println!("--- summary of {} repetitions: median [min, max]", a.repeat);
    let mut medians = BTreeMap::new();
    for (k, mut v) in summary {
        let (m, lo, hi) = median(&mut v);
        println!("{k:<40} {m:>12.1} [{lo:.1}, {hi:.1}]");
        medians.insert(k, m);
    }
    for (size, zenoh) in ZENOH {
        for (k, v) in &medians {
            if k.starts_with(&format!("thr {size} B ")) {
                println!("vs Zenoh {size} B: {v:.0} / {zenoh:.0} = {:.2}x", v / zenoh);
            }
        }
    }
    for (k, raw) in &a.raw {
        let Some(size) = k.strip_prefix("raw_thr_") else {
            continue;
        };
        for (m, v) in &medians {
            if m.starts_with(&format!("thr {size} B ")) {
                let ratio = v / raw;
                println!(
                    "gate thr {size} B: channel {v:.0} / raw {raw:.0} = {ratio:.3} (limit >= 0.9) {}",
                    if ratio >= 0.9 { "PASS" } else { "FAIL" }
                );
            }
        }
    }
    if let (Some(v), Some(raw)) = (medians.get("lat64 p50 us"), a.raw.get("raw_lat")) {
        let ratio = v / raw;
        println!(
            "gate 64 B half round trip: channel {v:.1} / raw {raw:.1} = {ratio:.3} (limit <= 1.1) {}",
            if ratio <= 1.1 { "PASS" } else { "FAIL" }
        );
    }
    println!("load average at end: {}", loadavg());
}
