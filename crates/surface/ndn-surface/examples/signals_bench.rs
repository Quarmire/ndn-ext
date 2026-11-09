//! Signals, measured between real `ndn_data::Device`s on in-process engines:
//!
//! - latency p50/p99 on one host (off the run's ring) and over one link (two
//!   engines joined by a UDP face on 127.0.0.1), sealed and unsealed;
//! - bytes per signal: the packet and the push Interest, one signal and a batch of
//!   8, with and without the run header, sealed and unsealed (as captured off the
//!   group);
//! - throughput at 60 Hz × N senders (N = 4, 16), on one host and over a link.
//!
//! Run: `cargo run --release -p ndn-surface --features signals --example signals_bench`

#[path = "../tests/common/mod.rs"]
mod common;

use std::sync::LazyLock;
use std::time::{Duration, Instant};

use common::{Engine, Host, World, engine, link, n, no_quota, no_ring};
use ndn_app::EngineAppExt;
use ndn_packet::Name;
use ndn_surface::signal::wire::{self, Packet};
use ndn_surface::signal::{SignalOptions, SignalRun, SignalSubscriber};

const WITHIN: Duration = Duration::from_secs(30);
const HZ: u64 = 60;

static BASE: LazyLock<Instant> = LazyLock::new(Instant::now);

/// µs since the bench began: one process, one clock for both ends.
fn now_us() -> u64 {
    BASE.elapsed().as_micros() as u64
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    sorted[((sorted.len() - 1) as f64 * p).round() as usize]
}

fn folder(sealed: bool) -> Name {
    n(if sealed {
        "/alice/32=data/secret"
    } else {
        "/alice/32=data/board"
    })
}

/// Engines for one host (the same engine twice) or a link (two joined by UDP).
async fn engines(
    world: &World,
    over_link: bool,
    a_devices: &[&str],
    b_devices: &[&str],
) -> (Engine, Option<Engine>) {
    let a = engine().await;
    if !over_link {
        return (a, None);
    }
    let b = engine().await;
    link(&a, &b, world.ns(), a_devices, b_devices, &world.cancel).await;
    (a, Some(b))
}

/// Open a run once `host` holds the scope's record (and sealed, its key).
async fn open(host: &Host, scope: &Name) -> SignalRun {
    let deadline = Instant::now() + WITHIN;
    loop {
        match host.signals.open(scope).await {
            Ok(r) => return r,
            Err(e) if e.next() == ndn_data::NextStep::RetryLater && Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(e) => panic!("{} cannot open a run of {scope}: {e}", host.device.name()),
        }
    }
}

/// Latency of `count` signals sent at 60 Hz after a warm-up: (p50, p99, samples) in µs.
async fn latency(sealed: bool, over_link: bool) -> (u64, u64, usize) {
    let world = World::new("/alice", &["/alice/laptop", "/alice/phone"]).await;
    let (a, b) = engines(&world, over_link, &["/alice/laptop"], &["/alice/phone"]).await;
    let b = b.as_ref().unwrap_or(&a);
    let sender = if over_link {
        no_ring()
    } else {
        SignalOptions::default()
    };
    let laptop = world.host(&a, "/alice/laptop", sender).await;
    let phone = world
        .host(b, "/alice/phone", SignalOptions::default())
        .await;
    let scope = folder(sealed);
    laptop.share(&scope, world.ns(), sealed).await;
    let mut sub = phone.subscribe(&scope, WITHIN).await;
    let mut run = open(&laptop, &scope).await;
    let want_local = !over_link;
    let reader = tokio::spawn(async move {
        let mut samples = Vec::new();
        while let Ok(Some(s)) = tokio::time::timeout(Duration::from_secs(2), sub.next()).await {
            let at = now_us();
            if s.payload[0] == 1 && s.local == want_local {
                let sent = u64::from_be_bytes(s.payload[1..9].try_into().unwrap());
                samples.push(at - sent);
            }
        }
        samples
    });
    let mut tick = tokio::time::interval(Duration::from_micros(1_000_000 / HZ));
    // Warm-up: the header is admitted and, on one host, the ring attached.
    for phase in [0u8, 1] {
        let count = if phase == 0 { 60 } else { 600 };
        for _ in 0..count {
            tick.tick().await;
            let mut payload = [0u8; 9];
            payload[0] = phase;
            payload[1..].copy_from_slice(&now_us().to_be_bytes());
            run.send(b"cursor", &payload).await.unwrap();
        }
    }
    let mut samples = reader.await.unwrap();
    samples.sort_unstable();
    world.cancel.cancel();
    (
        percentile(&samples, 0.5),
        percentile(&samples, 0.99),
        samples.len(),
    )
}

/// What the group carries for a single signal and a batch of 8, with the header
/// riding and without: (case, packet octets, Interest octets, signals).
async fn bytes(sealed: bool) -> Vec<(&'static str, usize, usize, usize)> {
    let world = World::new("/alice", &["/alice/laptop"]).await;
    let e = engine().await;
    let laptop = world.host(&e, "/alice/laptop", no_ring()).await;
    let tap = e.engine.app_face(world.cancel.child_token());
    tap.register_prefix(&wire::sync_group(world.ns()))
        .await
        .unwrap();
    let scope = folder(sealed);
    laptop.share(&scope, world.ns(), sealed).await;
    let mut run = open(&laptop, &scope).await;
    let payload = [0x5Au8; 16];
    let batch: Vec<(&[u8], &[u8])> = (0..8).map(|_| (&b"cursor"[..], &payload[..])).collect();
    run.send(b"cursor", &payload).await.unwrap();
    run.send(b"cursor", &payload).await.unwrap();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    run.send_batch(&batch).await.unwrap();
    run.send_batch(&batch).await.unwrap();
    let mut out = Vec::new();
    while out.len() < 4 {
        let wire = tokio::time::timeout(Duration::from_secs(5), tap.recv())
            .await
            .expect("the tap hears the group")
            .unwrap();
        let Ok(interest) = ndn_packet::Interest::decode(wire.clone()) else {
            continue;
        };
        let Some(packet) = wire::push_packet(&interest) else {
            continue;
        };
        let packet_len = packet.len();
        let (header, signals) = match wire::decode_packet(packet).unwrap() {
            Packet::Body(b) => (b.header.is_some(), b.signals.len()),
            // Sealed: the header rides in the first packet of each second; the
            // tap can't see inside, the order says it.
            Packet::Sealed(_) => (out.len() % 2 == 0, if out.len() < 2 { 1 } else { 8 }),
        };
        let case = match (signals, header) {
            (1, true) => "1 signal, header riding",
            (1, false) => "1 signal",
            (_, true) => "batch of 8, header riding",
            (_, false) => "batch of 8",
        };
        out.push((case, packet_len, wire.len(), signals));
    }
    world.cancel.cancel();
    out
}

/// 60 Hz from `senders` runs (four per device) for 3 s: (offered/s, delivered/s,
/// lost %, p50 µs, p99 µs).
async fn throughput(senders: usize, over_link: bool) -> (f64, f64, f64, u64, u64) {
    let devices: Vec<String> = (0..senders.div_ceil(4))
        .map(|i| format!("/alice/sender{i}"))
        .collect();
    let mut all: Vec<&str> = devices.iter().map(String::as_str).collect();
    all.push("/alice/phone");
    let world = World::new("/alice", &all).await;
    let (a, b) = engines(&world, over_link, &all[..all.len() - 1], &["/alice/phone"]).await;
    let b = b.as_ref().unwrap_or(&a);
    // Four runs per device at 60 Hz push 240 Interests/s, over the default push
    // budget: the engines here carry no relay quota, so it is raised.
    let sender = no_quota(if over_link {
        no_ring()
    } else {
        SignalOptions::default()
    });
    let mut hosts = Vec::new();
    for d in &devices {
        hosts.push(world.host(&a, d, sender.clone()).await);
    }
    let phone = world
        .host(b, "/alice/phone", SignalOptions::default())
        .await;
    let scope = folder(false);
    hosts[0].share(&scope, world.ns(), false).await;
    let mut sub: SignalSubscriber = phone.subscribe(&scope, WITHIN).await;
    for h in &hosts[1..] {
        // Each sender device follows the folder so its record arrives.
        let _ = h.subscribe(&scope, WITHIN).await;
    }
    let mut runs = Vec::new();
    for i in 0..senders {
        runs.push(open(&hosts[i / 4], &scope).await);
    }
    // Warm-up: every run's header admitted (and rings attached).
    for r in &mut runs {
        r.send(b"warm", &[0; 9]).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    while let Ok(Some(_)) = tokio::time::timeout(Duration::from_millis(100), sub.next()).await {}
    let before = phone.signals.stats();
    let reader = tokio::spawn(async move {
        let mut samples = Vec::new();
        while let Ok(Some(s)) = tokio::time::timeout(Duration::from_secs(2), sub.next()).await {
            let at = now_us();
            let sent = u64::from_be_bytes(s.payload[1..9].try_into().unwrap());
            samples.push(at - sent);
        }
        samples
    });
    const SECONDS: u64 = 3;
    let started = Instant::now();
    let mut tasks = Vec::new();
    for (i, mut run) in runs.into_iter().enumerate() {
        tasks.push(tokio::spawn(async move {
            let address = format!("cursor/{i}");
            let mut tick = tokio::time::interval(Duration::from_micros(1_000_000 / HZ));
            let mut sent = 0u64;
            for _ in 0..HZ * SECONDS {
                tick.tick().await;
                let mut payload = [1u8; 9];
                payload[1..].copy_from_slice(&now_us().to_be_bytes());
                if run.send(address.as_bytes(), &payload).await.is_ok() {
                    sent += 1;
                }
            }
            (sent, run)
        }));
    }
    let mut sent = 0;
    let mut keep = Vec::new();
    for t in tasks {
        let (s, run) = t.await.unwrap();
        sent += s;
        keep.push(run);
    }
    let elapsed = started.elapsed().as_secs_f64();
    let mut samples = reader.await.unwrap();
    samples.sort_unstable();
    let after = phone.signals.stats();
    let taken = (after.delivered + after.stale) - (before.delivered + before.stale);
    world.cancel.cancel();
    drop(keep);
    (
        sent as f64 / elapsed,
        taken as f64 / elapsed,
        100.0 * (sent.saturating_sub(taken)) as f64 / sent.max(1) as f64,
        percentile(&samples, 0.5),
        percentile(&samples, 0.99),
    )
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    now_us();
    println!("# signals bench (ndn-surface, real ndn-data devices, in-process engines)");
    println!();
    println!("## latency, 60 Hz, 600 signals after a 60-signal warm-up");
    println!("| path | sealed | p50 µs | p99 µs | samples |");
    println!("|---|---|---|---|---|");
    for over_link in [false, true] {
        for sealed in [false, true] {
            let (p50, p99, k) = latency(sealed, over_link).await;
            let path = if over_link {
                "one link (two engines, UDP 127.0.0.1)"
            } else {
                "one host (ring)"
            };
            println!("| {path} | {sealed} | {p50} | {p99} | {k} |");
        }
    }
    println!();
    println!(
        "## bytes (address `cursor`, 16-octet payload, scope /alice/32=data/<6>, group /alice/32=sync)"
    );
    println!("| sealed | case | packet | packet/signal | Interest | Interest/signal |");
    println!("|---|---|---|---|---|---|");
    for sealed in [false, true] {
        for (case, packet, interest, signals) in bytes(sealed).await {
            println!(
                "| {sealed} | {case} | {packet} | {:.1} | {interest} | {:.1} |",
                packet as f64 / signals as f64,
                interest as f64 / signals as f64
            );
        }
    }
    println!();
    println!("## throughput, 60 Hz per sender for 3 s (4 runs per sender device)");
    println!("| path | senders | offered/s | delivered/s | lost % | p50 µs | p99 µs |");
    println!("|---|---|---|---|---|---|---|");
    for over_link in [false, true] {
        for senders in [4, 16] {
            let (offered, delivered, lost, p50, p99) = throughput(senders, over_link).await;
            let path = if over_link { "one link" } else { "one host" };
            println!(
                "| {path} | {senders} | {offered:.0} | {delivered:.0} | {lost:.2} | {p50} | {p99} |"
            );
        }
    }
}
