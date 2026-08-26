//! On-air validation of the time-slice MAC (#61/#72) + the TimeBeacon common-view clock (#41/#72) on
//! real radios — task #73. Exercises the SHIPPING decision types
//! ([`ndn_radio_cognition::SlotSchedule`] + [`ndn_time::RadioHwClock::common_view`] + the face's
//! [`ndn_face_monitor_wifi::TIME_BEACON_MAGIC`] beacon format); the `FaceScheduler` env-plumbing around
//! them is already unit-tested, so here we drive the pure logic directly and measure.
//!
//! Two nodes, one broadcast channel, an `N=2` superframe. Each node decides TX-or-listen **per slot**:
//!   - **slotted:** transmit only in its own slot (master = slot 0, slave = slot 1), listen otherwise —
//!     the two nodes' transmit slots are disjoint, so a saturated blast never collides on air.
//!   - **contention:** flip a coin each slot, independent of the peer — both blast the same slot ~1/4
//!     of the time → those frames collide and are lost; the node also only listens ~1/2 as often.
//! The master also broadcasts the TimeBeacon; the slave disciplines its common-view clock to it, so
//! both compute the same current slot with no NTP and no AP. A background task drains RX continuously
//! and counts the peer's frames. So slotted should deliver markedly more of the peer's saturated blast
//! than contention — and only if the common-view clock keeps the two nodes' slots aligned, so it also
//! validates the TimeBeacon.
//!
//! Free the radio from the kernel first (see hardware-tools-runbook), then, at legacy 6M on ch40:
//!   sudo NDN_RADIO_TX_RATE=4 NDN_PID=a81a NDN_ROLE=master NDN_MODE=slotted    ./slot_airtest 40 22
//!   sudo NDN_RADIO_TX_RATE=4 NDN_PID=a81a NDN_ROLE=slave  NDN_MODE=slotted    ./slot_airtest 40 22
//! then re-run both with NDN_MODE=contention for the baseline. Delivery ratio = recv_peer / peer.sent
//! (computed across the two nodes' logs).

use std::sync::Arc;
use std::sync::atomic::Ordering;
use portable_atomic::AtomicU64;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ndn_face_monitor_wifi::{LibUsbRtl88xxBackend, TIME_BEACON_MAGIC};
use ndn_frame_io::{BROADCAST, FrameIo, InjectFrame, TxIntent};
use ndn_radio_cognition::SlotSchedule;
use ndn_time::RadioHwClock;

const N_SLOTS: u64 = 2;
const DATA_TAG: u8 = 0xDA; // payload[0] of a data frame; payload[1] = sender role tag
const BEACON_MS: u128 = 100;
const FRAME_BYTES: usize = 900; // big enough that a saturated slot is mostly airtime → real collisions

fn env(k: &str) -> Option<String> {
    std::env::var(k).ok()
}

/// A tiny deterministic RNG (no rng crate); seeded per-boot so the two nodes' contention coins are
/// independent. xorshift64.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn coin(&mut self) -> bool {
        self.next() & 1 == 0
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ch: u8 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(40);
    let pid: u16 = env("NDN_PID")
        .and_then(|s| u16::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        .unwrap_or(0x8812);
    let secs: u64 = std::env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(22);
    let master = env("NDN_ROLE").as_deref() == Some("master");
    let slotted = env("NDN_MODE").as_deref() != Some("contention");
    let hw_gate = env("NDN_HW_GATE").is_some();
    let slot_us: u64 = env("NDN_SLOT_US").and_then(|s| s.parse().ok()).unwrap_or(20_000);
    // Inter-frame pacing (µs). 0 = saturate. A light pace (e.g. 4000) keeps the medium unsaturated so
    // the TimeBeacon is not queue-delayed — the regime in which its common-view alignment is measured.
    let pace_us: u64 = env("NDN_PACE_US").and_then(|s| s.parse().ok()).unwrap_or(0);
    let warmup = Duration::from_secs(3); // let the slave lock the common-view clock before counting

    let my_role: u8 = if master { 0 } else { 1 };
    let my_slot: u64 = my_role as u64;
    let peer_tag: u8 = 1 - my_role;
    let sched = SlotSchedule::new(slot_us, N_SLOTS);
    let cv = Arc::new(Mutex::new(RadioHwClock::common_view()));
    let base = Instant::now();
    let host_us = move || base.elapsed().as_micros() as u64;

    let src = [0x02, b'M', b'D', b'R', my_role, 0x01];
    // Opened by PID through the shared factory rather than pinned to one backend: this test needs
    // to run on the RTL8733BU (the part that implements the hardware transmit gate), and the
    // factory also hands back the `RadioKnobs` the gate arm actuates. `open_named_radio` starts the
    // RX pump itself.
    let opened = ndn_radio_drivers::open_named_radio(pid, ch)?;
    let d = opened.io.clone();
    let knobs = opened.knobs.clone();
    if hw_gate && knobs.is_none() {
        eprintln!("NDN_HW_GATE set but this radio exposes no RadioKnobs — the arm would be a no-op");
    }
    println!(
        "slot_airtest: role={} mode={} ch{ch} pid={pid:04x} slot={}µs N={} secs={} frame={}B rate={}",
        if master { "master" } else { "slave" },
        if slotted { "slotted" } else { "contention" },
        slot_us, N_SLOTS, secs, FRAME_BYTES,
        env("NDN_RADIO_TX_RATE").unwrap_or_else(|| "default".into()),
    );

    let sent = Arc::new(AtomicU64::new(0));
    let recv_peer = Arc::new(AtomicU64::new(0));
    let recv_beacon = Arc::new(AtomicU64::new(0));
    // The slave's per-beacon common-view offset (ref − host), µs. Its spread = the on-air alignment
    // jitter — the TimeBeacon's common-view precision, the #41/#72 number.
    let offsets = Arc::new(Mutex::new(Vec::<i64>::new()));
    let deadline = Instant::now() + Duration::from_secs(secs);
    let count_start = base + warmup;

    // RX task: drain continuously, classify, discipline the common-view clock on a beacon. Decoupled
    // from TX so reception reflects what the half-duplex PHY actually caught (nothing while we TX).
    let rx = {
        let (d, cv, recv_peer, recv_beacon, offsets, host_us) =
            (d.clone(), cv.clone(), recv_peer.clone(), recv_beacon.clone(), offsets.clone(), host_us);
        tokio::spawn(async move {
            while Instant::now() < deadline {
                match tokio::time::timeout(Duration::from_millis(5), d.recv_frame()).await {
                    Ok(Ok(f)) => {
                        let p = &f.payload;
                        let counting = Instant::now() >= count_start;
                        if p.len() >= TIME_BEACON_MAGIC.len() + 8 && p[..3] == TIME_BEACON_MAGIC {
                            if !master {
                                let mut b = [0u8; 8];
                                b.copy_from_slice(&p[3..11]);
                                let hn = host_us();
                                let mut clk = cv.lock().unwrap();
                                clk.on_raw(u64::from_le_bytes(b), hn);
                                if counting && let Some(o) = clk.offset_us() {
                                    offsets.lock().unwrap().push(o);
                                }
                            }
                            if counting {
                                recv_beacon.fetch_add(1, Ordering::Relaxed);
                            }
                        } else if p.len() >= 2 && p[0] == DATA_TAG && p[1] == peer_tag && counting {
                            recv_peer.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    _ => {}
                }
            }
        })
    };

    // TX task (this task): decide TX-or-silent per slot; blast when transmitting.
    let mut rng = Rng((std::process::id() as u64).wrapping_mul(0x9E37_79B9) ^ (my_role as u64 + 1));
    let mut last_beacon = Instant::now() - Duration::from_millis(BEACON_MS as u64);
    let mut cur_slot_epoch = u64::MAX;
    let mut tx_this_slot = false;
    let payload_pad = vec![0u8; FRAME_BYTES];

    while Instant::now() < deadline {
        // Master: emit the beacon on wall-schedule regardless of slot (the clock signal never waits).
        //
        // ⚠ MEASURED 2026-08-25 — THIS TIMESTAMP IS TAKEN AT ENQUEUE, NOT AT TRANSMIT, and under a
        // saturated blast that is the difference between a working slot MAC and a broken one. The
        // frame sits behind a full MAC queue (~20 KB on the 8733b) and radiates tens of ms after the
        // instant it claims. Two f72b nodes measured alignment jitter of stddev 10 ms (slotted),
        // 23 ms (contention) and 89 ms (slotted + hardware gate, worst because the gate holds the
        // queue longer) — all far larger than the 20 ms slot they are meant to align, so "slotted"
        // degenerates to random and matches contention.
        //
        // The fix is not a better software beacon: it is the HARDWARE common view this stack already
        // has — per-frame RX stamps, measured this session at 0.4 us residual / 0.0034 ppm between
        // two of these radios. Stamp at transmit, or align on the receiver's own hardware stamp.
        if master && last_beacon.elapsed().as_millis() >= BEACON_MS {
            let refr = host_us();
            cv.lock().unwrap().on_raw(refr, host_us());
            let mut payload = Vec::with_capacity(11);
            payload.extend_from_slice(&TIME_BEACON_MAGIC);
            payload.extend_from_slice(&refr.to_le_bytes());
            let _ = d.inject(InjectFrame { payload: payload.into(), tx: TxIntent::ROBUST, dst: BROADCAST, src, addr3: None }).await;
            last_beacon = Instant::now();
        }

        let now = cv.lock().unwrap().now(host_us());
        let epoch = now / slot_us;
        if epoch != cur_slot_epoch {
            // New slot: (re)decide whether we transmit in it.
            cur_slot_epoch = epoch;
            let cur_slot = epoch % N_SLOTS;
            tx_this_slot = if slotted { cur_slot == my_slot } else { rng.coin() };
            // NDN_HW_GATE=1 additionally shuts the MAC outside our slot. The software decision
            // above stops us CALLING inject on time; it cannot stop frames already queued, which
            // drain into the peer's turn and collide there. Measured single-node, the software
            // decision alone confines only ~54% of traffic to its half; with the gate, 99%.
            if hw_gate && let Some(k) = knobs.as_ref() {
                let _ = k.set_tx_hold(!tx_this_slot);
            }
        }

        if tx_this_slot {
            let mut payload = Vec::with_capacity(FRAME_BYTES + 10);
            payload.push(DATA_TAG);
            payload.push(my_role);
            payload.extend_from_slice(&sent.load(Ordering::Relaxed).to_le_bytes());
            payload.extend_from_slice(&payload_pad);
            let _ = d.inject(InjectFrame { payload: payload.into(), tx: TxIntent::CONSERVATIVE, dst: BROADCAST, src, addr3: None }).await;
            sent.fetch_add(1, Ordering::Relaxed);
            if pace_us > 0 {
                tokio::time::sleep(Duration::from_micros(pace_us)).await; // unsaturated: beacons flow
            } else {
                tokio::task::yield_now().await; // saturate, but let the runtime breathe
            }
        } else {
            tokio::time::sleep(Duration::from_micros(500)).await; // silent: let the RX task work
        }
    }
    let _ = rx.await;

    let count_secs = (deadline - count_start).as_secs_f64().max(0.001);
    let disciplined = cv.lock().unwrap().is_disciplined();
    println!(
        "\n=== RESULT role={} mode={} ===\n\
         sent={}  recv_peer={}  ({:.1}/s over {:.1}s)\n\
         recv_beacon={}  common_view={}",
        if master { "master" } else { "slave" },
        if slotted { "slotted" } else { "contention" },
        sent.load(Ordering::Relaxed),
        recv_peer.load(Ordering::Relaxed),
        recv_peer.load(Ordering::Relaxed) as f64 / count_secs,
        count_secs,
        recv_beacon.load(Ordering::Relaxed),
        disciplined,
    );
    // Slave: the TimeBeacon's on-air common-view precision = the jitter of the disciplined offset.
    if !master {
        let o = offsets.lock().unwrap();
        if o.len() >= 2 {
            let mean = o.iter().sum::<i64>() as f64 / o.len() as f64;
            let var = o.iter().map(|&x| (x as f64 - mean).powi(2)).sum::<f64>() / o.len() as f64;
            let (min, max) = (*o.iter().min().unwrap(), *o.iter().max().unwrap());
            println!(
                "common-view offset: n={} stddev={:.1}µs spread(max-min)={}µs  (TimeBeacon alignment jitter)",
                o.len(), var.sqrt(), max - min,
            );
        }
    }
    Ok(())
}
