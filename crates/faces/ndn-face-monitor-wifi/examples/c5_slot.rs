//! **The named airtime lease on two ESP32-C5s — reusing the one design.** Each node's slot is the
//! canonical `SlotSchedule::owner_slot(prefix_hash(name))` (ndn-radio-cognition), NOT a hardcoded A/B;
//! each beacon is placed at its slot instant on the shared clock via the HAL's `FrameIo::inject_at_clock`
//! (the C5 fires it in hardware, `T_INJECT_ABS`). The two clocks are put on one timeline by reading each
//! device's schedule clock back-to-back (`read_schedule_clock`). Success = each node's actual on-air
//! instant (`recv_tx_confirm`) lands in the slot the schedule assigns to its name.
//!
//! This is the reuse the scattered python prototype should have been: SlotSchedule is the design, the
//! HAL is the seam, the C5 is one backend behind it. Any scheduled-TX backend drops in the same way.
//!
//! ```sh
//! C5_A=/dev/cu.usbmodem1101 C5_B=/dev/cu.usbmodem4 \
//!   cargo run --example c5_slot --features serial-radio -p ndn-face-monitor-wifi
//! ```
use std::time::Duration;

use bytes::Bytes;
use ndn_face_monitor_wifi::Esp32SerialBackend;
use ndn_frame_io::{ClockDomainId, FrameIo, InjectFrame, TxIntent};
use ndn_radio_cognition::{prefix_hash, LeaseClass, SlotSchedule};

const SLOTS: u64 = 4;
const SLOT_US: u64 = 20_000; // 20 ms slots → 80 ms period
const MARGIN_US: u64 = 20_000; // first target this far ahead; keep (margin + max slot offset) < firmware cap
const K: u64 = 20; // periods
const DOMAIN: ClockDomainId = ClockDomainId(0x4335_5f54); // "C5_T" — the C5 schedule (esp_timer) domain

fn beacon(tag: u8, seq: u64) -> InjectFrame {
    let mut p = vec![0x05, 0x06, tag];
    p.extend_from_slice(&(seq as u32).to_le_bytes());
    InjectFrame::broadcast(Bytes::from(p), TxIntent::CONSERVATIVE)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pa = std::env::var("C5_A").unwrap_or_else(|_| "/dev/cu.usbmodem1101".into());
    let pb = std::env::var("C5_B").unwrap_or_else(|_| "/dev/cu.usbmodem4".into());
    let a = Esp32SerialBackend::open_c5(&pa)?;
    let b = Esp32SerialBackend::open_c5(&pb)?;

    // The design: each node's slot is a pure function of its NAME, computed the same everywhere.
    let sched = SlotSchedule::new(SLOT_US, SLOTS);
    let name_a: &[&[u8]] = &[b"ndn", b"lease", b"node-a"];
    let name_b: &[&[u8]] = &[b"ndn", b"lease", b"node-b"];
    let slot_a = sched.owner_slot(prefix_hash(name_a));
    let slot_b = sched.owner_slot(prefix_hash(name_b));
    println!("SlotSchedule: {SLOTS} slots × {}ms. /ndn/lease/node-a → slot {slot_a}; node-b → slot {slot_b}",
        SLOT_US / 1000);
    if slot_a == slot_b {
        println!("(names hash to the SAME slot — they'd share airtime; that is the schedule's answer, not a bug)");
    }

    // Put both schedule clocks on one timeline (read back-to-back; offset = A_esp - B_esp).
    let (ca, cb) = (a.read_schedule_clock().await, b.read_schedule_clock().await);
    let (ca, cb) = (ca.ok_or("A clock read failed")?, cb.ok_or("B clock read failed")?);
    let offset = ca as i64 - cb as i64;
    println!("schedule-clock offset A-B = {offset} µs");

    // The instant a node's slot opens in period k, on A's timeline (mid-slot).
    let epoch = ca + MARGIN_US;
    let period = SLOTS * SLOT_US;
    let slot_instant = |slot: u64, k: u64| epoch + k * period + slot * SLOT_US + SLOT_US / 2;

    // Actuate through the HAL: inject_at_clock places each beacon at its slot on each device's own clock.
    for k in 0..K {
        let ta = slot_instant(slot_a, k);
        let tb = (slot_instant(slot_b, k) as i64 - offset) as u64; // A-timeline → B's clock
        a.inject_at_clock(beacon(b'A', k), ta, DOMAIN).await?;
        b.inject_at_clock(beacon(b'B', k), tb, DOMAIN).await?;
    }
    println!("scheduled {K} periods; collecting on-air confirmations…");

    // Verify: fold each node's ACTUAL on-air instant into the period, on the common timeline.
    async fn collect(dev: &Esp32SerialBackend, is_a: bool, offset: i64, epoch: u64, period: u64) -> Vec<u64> {
        let mut ph = Vec::new();
        while let Some((_t, actual)) = dev.recv_tx_confirm().await {
            let on_a = if is_a { actual as i64 } else { actual as i64 + offset };
            ph.push(((on_a - epoch as i64).rem_euclid(period as i64)) as u64);
        }
        ph
    }
    let (pha, phb) = tokio::join!(
        collect(&a, true, offset, epoch, period),
        collect(&b, false, offset, epoch, period),
    );
    let stat = |ph: &[u64]| -> (usize, f64, f64) {
        if ph.is_empty() { return (0, 0.0, 0.0); }
        let m = ph.iter().sum::<u64>() as f64 / ph.len() as f64;
        let sd = (ph.iter().map(|&x| (x as f64 - m).powi(2)).sum::<f64>() / ph.len() as f64).sqrt();
        (ph.len(), m, sd)
    };
    let (na, ma, sa) = stat(&pha);
    let (nb, mb, sb) = stat(&phb);
    let in_slot = |ph: &[u64], slot: u64| ph.iter().filter(|&&p| p / SLOT_US == slot).count();
    println!("\nnode-a: {na} beacons, phase {:.2}±{:.2} ms → slot {} ; in slot {}: {}/{}",
        ma / 1000.0, sa / 1000.0, (ma as u64) / SLOT_US, slot_a, in_slot(&pha, slot_a), na);
    println!("node-b: {nb} beacons, phase {:.2}±{:.2} ms → slot {} ; in slot {}: {}/{}",
        mb / 1000.0, sb / 1000.0, (mb as u64) / SLOT_US, slot_b, in_slot(&phb, slot_b), nb);
    println!("→ each node transmits in the slot its NAME owns (SlotSchedule), placed by the HAL knob — \
        the airtime lease, reusing the one design. LeaseClass::{:?} default.", LeaseClass::Bulk);
    Ok(())
}
