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
    // NDN_ALIGN=seq: derive the slot phase from a COMMON SOURCE's frame sequence numbers instead of
    // the software TimeBeacon.
    //
    // The beacon path stamps at enqueue, so under saturation it reports an instant tens of ms before
    // the frame actually radiates (measured: 10-89 ms jitter against a 20 ms slot), and the slot arms
    // degenerate to contention. That is a clock defect, not a MAC defect, and it hides the question
    // the test exists to answer.
    //
    // Both nodes hear the same third radio and read the same u32 sequence out of each frame, so a
    // phase derived from it is identical on both by construction — no clock, no propagation term, no
    // queue delay. This is an IDEALISED alignment used to isolate the MAC question; the production
    // path still needs hardware common view (measured separately at 0.4 us residual / 0.0034 ppm).
    let align_seq = env("NDN_ALIGN").as_deref() == Some("seq");
    // NDN_ALIGN=cv — the doctrine-correct alignment: HARDWARE RX STAMPS of a mutually-heard third
    // node's ORDINARY traffic.
    //
    // Common view is an RX-only technique: both nodes stamp the SAME frame, so the transmitter's
    // clock cancels and what remains is the offset between the two receivers (measured on these
    // radios at 0.0034 ppm / 0.4 us residual). The sequence number here identifies WHICH frame both
    // are looking at; it carries no timing. That is the difference from NDN_ALIGN=seq, which used
    // the sequence itself as the clock and so needed a dedicated paced tick — the beacon-shaped
    // crutch this design exists to avoid.
    //
    // Both nodes anchor on the same well-known frame (seq % ANCHOR == 0), so their epochs share an
    // origin without exchanging anything. Between arrivals the phase is extrapolated on the host
    // clock, which is accurate over the few ms between frames.
    let align_cv = env("NDN_ALIGN").as_deref() == Some("cv");
    // Anchor cadence must suit the SOURCE RATE, not be a fixed 256: the common-view source should
    // be as quiet as possible (it is an unslotted transmitter and collides with everyone), so at a
    // low rate every-256th would anchor once per ~13 s. Every 16th keeps re-anchoring sub-second
    // even at 20 frames/s, and the host clock extrapolates the gaps at ppm-level error.
    const ANCHOR_MASK: u32 = 0x0f;
    let cv_origin = Arc::new(Mutex::new(None::<(u64, u64)>)); // (stamp ticks, host us) at anchor
    let cv_last = Arc::new(Mutex::new(None::<(u64, u64)>)); // most recent (stamp ticks, host us)
    // One tick per slot: the common source is paced so each of its frames marks a slot boundary,
    // which keeps its airtime negligible. A saturating source would time the medium by destroying it.
    const FRAMES_PER_SLOT: u32 = 1;
    let common_seq = Arc::new(AtomicU64::new(u64::MAX));
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
    // Real ns-per-tick of this radio's RX stamp, from its own declaration — NOT assumed 1000. The
    // 8733b's is 4000, and assuming otherwise scales every derived duration by 4.
    let tick_ns = opened
        .time
        .as_ref()
        .and_then(|t| t.time_sources().first().map(|s| u64::from(s.tick_ns)))
        .unwrap_or(1_000);
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

    // PHY PPDU counters bracketing the counting window. `err` counts PPDUs the PHY BEGAN to
    // demodulate and failed — collisions and marginal decode — which is the only view of loss a
    // receiver has, since a frame destroyed on air never arrives to be counted missing.
    let phy0 = knobs.as_ref().and_then(|k| k.read_ofdm_counters().ok().flatten());
    let sent = Arc::new(AtomicU64::new(0));
    // Injects the radio REFUSED — never on air, so not part of the delivery denominator.
    let tx_failed = Arc::new(AtomicU64::new(0));
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
        let common_seq_rx = common_seq.clone();
        let cv_origin_rx = cv_origin.clone();
        let cv_last_rx = cv_last.clone();
        tokio::spawn(async move {
            while Instant::now() < deadline {
                match tokio::time::timeout(Duration::from_millis(5), d.recv_frame()).await {
                    Ok(Ok(f)) => {
                        let p = &f.payload;
                        let counting = Instant::now() >= count_start;
                        // Common-source frame (knob tag 5, u32 seq at p[4..8]) — the shared phase.
                        if p.len() >= 8 && p[2] == 0xC3 && p[1] == 5 {
                            let sq = u32::from_le_bytes([p[4], p[5], p[6], p[7]]);
                            common_seq_rx.store(u64::from(sq), Ordering::Relaxed);
                            // Hardware RX stamp of this common frame — the actual time reference.
                            if let Some(st) = f.stamp {
                                let hn = host_us();
                                *cv_last_rx.lock().unwrap() = Some((st.raw, hn));
                                if sq & ANCHOR_MASK == 0 {
                                    // RE-ANCHOR ON EVERY anchor frame, not just the first.
                                    //
                                    // "The first anchor frame I see" is NOT the same frame on both
                                    // nodes — whoever starts later misses one and anchors 256 frames
                                    // downstream, so the two phases differ by an arbitrary offset and
                                    // the slots never line up. Re-anchoring keeps both locked to the
                                    // MOST RECENT anchor, which is necessarily the same frame for
                                    // both, and the phase jump is simultaneous so it costs nothing.
                                    *cv_origin_rx.lock().unwrap() = Some((st.raw, hn));
                                }
                            }
                        }
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
        // Skip the software beacon entirely under common-view alignment: it is unused there, and
        // with the hardware gate shut outside our slot its inject BLOCKS, stalling the whole TX loop
        // — which is why arm C's master collapsed to 764 frames sent against the slave's 4470.
        if master && !align_cv && last_beacon.elapsed().as_millis() >= BEACON_MS {
            let refr = host_us();
            cv.lock().unwrap().on_raw(refr, host_us());
            let mut payload = Vec::with_capacity(11);
            payload.extend_from_slice(&TIME_BEACON_MAGIC);
            payload.extend_from_slice(&refr.to_le_bytes());
            let _ = d.inject(InjectFrame { payload: payload.into(), tx: TxIntent::ROBUST, dst: BROADCAST, src, addr3: None }).await;
            last_beacon = Instant::now();
        }

        let epoch = if align_cv {
            // Phase = (stamp - anchor) in real time, extrapolated to now on the host clock.
            match (*cv_origin.lock().unwrap(), *cv_last.lock().unwrap()) {
                (Some((o_tick, _)), Some((l_tick, l_host))) => {
                    let since_anchor_us = l_tick.wrapping_sub(o_tick) * tick_ns / 1000;
                    let extrap_us = host_us().saturating_sub(l_host);
                    (since_anchor_us + extrap_us) / slot_us
                }
                _ => u64::MAX, // no anchor heard yet — stay silent rather than transmit unaligned
            }
        } else if align_seq {
            match common_seq.load(Ordering::Relaxed) {
                u64::MAX => u64::MAX, // no common-source frame heard yet — stay silent
                sq => sq / u64::from(FRAMES_PER_SLOT),
            }
        } else {
            cv.lock().unwrap().now(host_us()) / slot_us
        };
        if epoch == u64::MAX {
            tokio::task::yield_now().await;
            continue;
        }
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

        // GUARD INTERVAL — the `fits_now` check the production FaceScheduler has (#84) and this
        // harness lacked. A 900 B frame at legacy 6 Mbps occupies ~1.2 ms, so one launched near the
        // end of a 20 ms slot keeps radiating into the NEXT owner's turn and collides there — a loss
        // charged to a node that did nothing wrong. NDN_GUARD_US=0 disables it, which is the arm
        // that measures how much of the residual loss it accounts for.
        let guard_us: u64 = env("NDN_GUARD_US").and_then(|v| v.parse().ok()).unwrap_or(0);
        let fits = if guard_us == 0 {
            true
        } else {
            let into_slot = if align_cv || align_seq {
                // phase within the current slot, from the same clock the epoch came from
                match (*cv_origin.lock().unwrap(), *cv_last.lock().unwrap()) {
                    (Some((o_tick, _)), Some((l_tick, l_host))) => {
                        let us = l_tick.wrapping_sub(o_tick) * tick_ns / 1000
                            + host_us().saturating_sub(l_host);
                        us % slot_us
                    }
                    _ => 0,
                }
            } else {
                cv.lock().unwrap().now(host_us()) % slot_us
            };
            slot_us.saturating_sub(into_slot) > guard_us
        };

        if tx_this_slot && fits {
            let mut payload = Vec::with_capacity(FRAME_BYTES + 10);
            payload.push(DATA_TAG);
            payload.push(my_role);
            payload.extend_from_slice(&sent.load(Ordering::Relaxed).to_le_bytes());
            payload.extend_from_slice(&payload_pad);
            // Count only what the radio ACCEPTED. This used to discard the result and count every
            // attempt, so a frame that never left — queue full behind a shut gate, USB error,
            // timeout — still inflated `sent`, and therefore deflated the delivery ratio computed
            // against it. That biases hardest against the gated arm, which is exactly the arm whose
            // queue is shut half the time.
            match d.inject(InjectFrame { payload: payload.into(), tx: TxIntent::CONSERVATIVE, dst: BROADCAST, src, addr3: None }).await {
                Ok(()) => {
                    sent.fetch_add(1, Ordering::Relaxed);
                }
                Err(_) => {
                    tx_failed.fetch_add(1, Ordering::Relaxed);
                }
            }
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
         sent={} tx_failed={} recv_peer={}  ({:.1}/s over {:.1}s)\n\
         recv_beacon={}  common_view={}",
        if master { "master" } else { "slave" },
        if slotted { "slotted" } else { "contention" },
        sent.load(Ordering::Relaxed),
        tx_failed.load(Ordering::Relaxed),
        recv_peer.load(Ordering::Relaxed),
        recv_peer.load(Ordering::Relaxed) as f64 / count_secs,
        count_secs,
        recv_beacon.load(Ordering::Relaxed),
        disciplined,
    );
    if let (Some((ok0, err0)), Some(k)) = (phy0, knobs.as_ref())
        && let Ok(Some((ok1, err1))) = k.read_ofdm_counters()
    {
        let (d_ok, d_err) = (ok1.wrapping_sub(ok0), err1.wrapping_sub(err0));
        let total = u32::from(d_ok) + u32::from(d_err);
        println!(
            "PHY ofdm_ok={d_ok} ofdm_err={d_err}  -> {:.1}% of PPDUs the PHY started FAILED to \
             decode (collisions / marginal), across ALL transmitters on the channel",
            if total > 0 { 100.0 * f64::from(d_err) / f64::from(total) } else { 0.0 }
        );
    }
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
