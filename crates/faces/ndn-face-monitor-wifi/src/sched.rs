//! Face-side actuation of the data-centric **time-slice MAC** (#61) and **name-keyed FHSS** (#40):
//! the [`SlotSchedule`]/[`HopSchedule`] decisions (in `ndn-radio-cognition`) applied at the real TX
//! path. Every outbound data frame passes through [`FaceScheduler::gate`], which — from the frame's
//! own name-group and a common-view clock — waits until the name owns the slot (collision-free timing)
//! and/or retunes to the name's hop channel (jam-resilient rendezvous). No coordinator, no announced
//! schedule: a slot/channel is a pure function of `(name, clock)`, so every node computes the same one.
//!
//! **The clock (honest scope).** The epoch is wall-clock microseconds by default — genuinely
//! common-view across the (NTP-synced) OPis to ~ms, which is proportionate to the ms-scale slots a full
//! Wi-Fi *data* frame needs. The sub-µs hardware TSF (#41, [`RadioHwClock`]) is wired here too — fed
//! from every inbound frame's [`CapturedFrame::stamp`](ndn_frame_io::CapturedFrame) via
//! [`FaceScheduler::on_rx_stamp`], closing the "the face never consumes `.stamp`" gap — and exposed as
//! the precision-upgrade path. Switching the *epoch* onto it (`NDN_SCHED_CLOCK=hw`) gives µs-slot
//! resolution but needs a shared reference (a clock-master TimeBeacon / common AP) for cross-node phase;
//! the local RX-TSF alone is precise but not itself common-view. Documented, not silently assumed.
//!
//! **Config** (read once at face construction, mirroring the driver-crate `NDN_*` convention):
//! - `NDN_SCHED_SLOT=N:slot_us` — time-slice on: `N` slots of `slot_us` µs (e.g. `8:3000`).
//! - `NDN_SCHED_HOP=ch,ch,…:dwell_us` — FHSS on: hop over these **real channel numbers**, dwelling
//!   `dwell_us` µs each (e.g. `1,6,11:120000` for non-overlapping 2.4 GHz).
//! - `NDN_SCHED_GROUP_DEPTH=k` — name-group granularity: hash the first `k` name components (default 1,
//!   so all data under a top prefix shares a slot/channel — the *group*, not each object).
//! - `NDN_SCHED_CLOCK=wall|hw|cv` — epoch source (default `wall`). `cv` = the radio-native common-view
//!   clock disciplined to a clock-master's time-beacon (cross-node aligned with no NTP/AP).
//! - `NDN_SCHED_MASTER=1` — this node is the clock master: it broadcasts the time-beacon that `cv`
//!   nodes discipline to. Exactly one master per timeline; the master also runs `cv` (off its own ref).
//! Unset ⇒ scheduler disabled ⇒ the send path is byte-for-byte unchanged.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ndn_radio_cognition::{HopSchedule, SlotSchedule, prefix_hash};

use crate::radio::{Bandwidth, RadioKnobs};
use ndn_frame_io::LinkStamp;
use ndn_time::RadioHwClock;

/// Which clock feeds `epoch(t)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClockSource {
    /// Wall-clock µs — common-view across NTP-synced nodes at ~ms (default; matches ms-scale slots).
    Wall,
    /// The disciplined hardware TSF (`RadioHwClock`) — µs-local; cross-node phase needs a shared ref.
    Hardware,
    /// A radio-native common-view clock disciplined to a clock-master's [`TimeBeacon`] — cross-node
    /// aligned with NO infrastructure (no NTP, no AP). The doctrine time source.
    CommonView,
}

/// The 3-byte tag that marks a [`FaceScheduler`] time-beacon on the wire, chosen to not collide with
/// an NDN packet's first byte (Interest `0x05` / Data `0x06` / LP `0x64`). Followed by the master's
/// monotonic reference time in microseconds, 8 bytes little-endian.
pub const TIME_BEACON_MAGIC: [u8; 3] = [0x7E, b'T', b'B'];

/// The face's transmit scheduler: the temporal (slot) and frequency (hop) grants, actuated.
pub struct FaceScheduler {
    slot: Option<SlotSchedule>,
    hop: Option<HopSchedule>,
    /// Name-group depth — how many leading name components define the group the schedule keys on.
    group_depth: usize,
    clock_source: ClockSource,
    /// Retune knob for FHSS (per-bearer; `None` ⇒ can't hop this bearer, slot-only).
    knobs: Option<std::sync::Arc<dyn RadioKnobs>>,
    /// Bandwidth to retune at (the bearer's operating BW).
    bw: Bandwidth,
    /// Last channel we retuned to — a hop only calls the (~16 ms) `set_channel` when it actually changes.
    current_ch: AtomicU8,
    /// The disciplined hardware clock, fed by the RX reader. Behind a mutex: the reader writes stamps,
    /// the (wall-clock-default) gate only reads it in `hw` mode.
    hw: Mutex<RadioHwClock>,
    /// The radio-native common-view clock, disciplined to a clock-master's time-beacon (`CommonView`
    /// mode). The master feeds its own reference each broadcast; slaves feed the received one.
    cv: Mutex<RadioHwClock>,
    /// This node broadcasts the time-beacon (the clock master). At most one master per timeline.
    master: bool,
    /// Monotonic base for the hardware clock's host reference and the master's reference timeline.
    base: Instant,
}

impl FaceScheduler {
    /// Build from the `NDN_SCHED_*` environment. Returns `None` when neither slot nor hop is
    /// configured — the caller then leaves the send path untouched.
    pub fn from_env(knobs: Option<std::sync::Arc<dyn RadioKnobs>>, bw: Bandwidth) -> Option<Self> {
        let slot = std::env::var("NDN_SCHED_SLOT").ok().and_then(|s| parse_slot(&s));
        let hop = std::env::var("NDN_SCHED_HOP").ok().and_then(|s| parse_hop(&s));
        if slot.is_none() && hop.is_none() {
            return None;
        }
        let group_depth = std::env::var("NDN_SCHED_GROUP_DEPTH")
            .ok()
            .and_then(|s| s.trim().parse::<usize>().ok())
            .unwrap_or(1)
            .max(1);
        let clock_source = match std::env::var("NDN_SCHED_CLOCK").ok().as_deref() {
            Some("hw") | Some("hardware") => ClockSource::Hardware,
            Some("cv") | Some("common-view") => ClockSource::CommonView,
            _ => ClockSource::Wall,
        };
        let master = std::env::var("NDN_SCHED_MASTER").ok().as_deref() == Some("1");
        Some(Self {
            slot,
            hop,
            group_depth,
            clock_source,
            knobs,
            bw,
            current_ch: AtomicU8::new(u8::MAX), // sentinel: first hop always retunes
            hw: Mutex::new(RadioHwClock::realtek()),
            cv: Mutex::new(RadioHwClock::common_view()),
            master,
            base: Instant::now(),
        })
    }

    /// Whether this node is the clock master (broadcasts the time-beacon). The face spawns the beacon
    /// task iff this is true.
    pub fn is_master(&self) -> bool {
        self.master
    }

    /// Build the next time-beacon wire (called by the master's beacon task): advances the master's own
    /// common-view clock to `now` and returns `MAGIC ‖ ref_us(le64)` for direct injection. Injected
    /// raw (not through the slot gate) so the clock signal never waits on a data slot.
    pub fn build_beacon(&self) -> bytes::Bytes {
        let ref_us = self.base.elapsed().as_micros() as u64;
        // The master reads its own reference the same way a slave reads the received one, so master and
        // slaves share the `cv.now` code path and land on the same timeline.
        let host_now = self.base.elapsed().as_micros() as u64;
        if let Ok(mut cv) = self.cv.lock() {
            cv.on_raw(ref_us, host_now);
        }
        let mut out = Vec::with_capacity(TIME_BEACON_MAGIC.len() + 8);
        out.extend_from_slice(&TIME_BEACON_MAGIC);
        out.extend_from_slice(&ref_us.to_le_bytes());
        bytes::Bytes::from(out)
    }

    /// If `payload` is a time-beacon, its master reference time (µs). The RX reader uses this to (a)
    /// discipline the common-view clock and (b) suppress the frame (it is not NDN traffic).
    pub fn parse_beacon(payload: &[u8]) -> Option<u64> {
        if payload.len() >= TIME_BEACON_MAGIC.len() + 8 && payload[..3] == TIME_BEACON_MAGIC {
            let mut b = [0u8; 8];
            b.copy_from_slice(&payload[3..11]);
            Some(u64::from_le_bytes(b))
        } else {
            None
        }
    }

    /// Discipline the common-view clock to a received master reference time (called by the RX reader
    /// for every time-beacon). After a few beacons `now_us` in `CommonView` mode reads the master's
    /// timeline, so this node's slot epochs agree with the master's and every other slave's.
    pub fn ingest_time_ref(&self, ref_us: u64) {
        let host_now = self.base.elapsed().as_micros() as u64;
        if let Ok(mut cv) = self.cv.lock() {
            cv.on_raw(ref_us, host_now);
        }
    }

    /// A one-line description of the active schedule, for the face's startup log.
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if let Some(s) = &self.slot {
            parts.push(format!("slot(N={}, {}µs)", s.slots(), s.slot_us()));
        }
        if let Some(h) = &self.hop {
            parts.push(format!("hop({:?}, dwell {}µs)", h.classes(), h.dwell_remaining_us(0)));
        }
        let role = if self.master { " [clock-master]" } else { "" };
        format!("scheduler: {} clock={:?}{} group_depth={}", parts.join(" + "), self.clock_source, role, self.group_depth)
    }

    /// Feed a hardware RX timestamp into the disciplined clock (called from the RX reader for every
    /// inbound frame that carries one). Cheap; disciplines the `RadioHwClock` used by `hw` epoch mode
    /// and surfaced for telemetry. No-op cost when the gate runs on the wall clock.
    pub fn on_rx_stamp(&self, stamp: &LinkStamp) {
        let host_now = self.base.elapsed().as_micros() as u64;
        if let Ok(mut hw) = self.hw.lock() {
            hw.on_stamp(stamp, host_now);
        }
    }

    /// The common-view epoch clock, in microseconds.
    fn now_us(&self) -> u64 {
        match self.clock_source {
            ClockSource::Wall => SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_micros() as u64)
                .unwrap_or(0),
            ClockSource::Hardware => {
                let host_now = self.base.elapsed().as_micros() as u64;
                self.hw.lock().map(|hw| hw.now(host_now)).unwrap_or(host_now)
            }
            ClockSource::CommonView => {
                let host_now = self.base.elapsed().as_micros() as u64;
                self.cv.lock().map(|cv| cv.now(host_now)).unwrap_or(host_now)
            }
        }
    }

    /// Gate one outbound data frame: retune to its hop channel and/or wait for its owned slot, from the
    /// frame's own name-group + the common-view clock. A frame with no parseable name (a control /
    /// non-NDN frame) is passed straight through. `robust` control frames should bypass entirely
    /// (the caller decides) — reports/discovery must not wait on a data slot.
    pub async fn gate(&self, wire: &[u8]) {
        let Some(hash) = self.name_group_hash(wire) else {
            return; // no name-group → not schedulable; transmit now
        };
        let now = self.now_us();

        // Frequency first: sit on the name's channel for this hop epoch.
        if let Some(hop) = &self.hop {
            let ch = hop.channel(hash, now);
            self.retune(ch).await;
        }

        // Then time: wait out the slots until this name owns the medium.
        if let Some(slot) = &self.slot {
            let wait = slot.wait_us(hash, now);
            if wait > 0 {
                tokio::time::sleep(Duration::from_micros(wait)).await;
            }
        }
    }

    /// Retune to `ch` only if it changed — `set_channel` is a ~16 ms blocking call, so it runs on the
    /// blocking pool and is skipped when we already sit on the channel.
    async fn retune(&self, ch: u8) {
        if self.current_ch.load(Ordering::Relaxed) == ch {
            return;
        }
        if let Some(knobs) = &self.knobs {
            let k = knobs.clone();
            let bw = self.bw;
            let _ = tokio::task::spawn_blocking(move || k.set_channel(ch, bw)).await;
        }
        self.current_ch.store(ch, Ordering::Relaxed);
    }

    /// Hash the frame's first `group_depth` name components — the shared `prefix_hash` keyspace (§44),
    /// so the schedule keys on the same name-group as demand/consistency. `None` if the wire carries no
    /// parseable Name (non-first LP fragment, control frame, parse miss).
    fn name_group_hash(&self, wire: &[u8]) -> Option<u64> {
        let name_tlv = crate::inner_name(wire)?;
        let comps = name_components(name_tlv, self.group_depth);
        if comps.is_empty() {
            return None;
        }
        let refs: Vec<&[u8]> = comps.iter().map(|c| *c).collect();
        Some(prefix_hash(&refs))
    }
}

/// The value bytes of the first `depth` components inside a Name TLV (`0x07 len [0x08 len v]…`).
fn name_components(name_tlv: &[u8], depth: usize) -> Vec<&[u8]> {
    let mut out = Vec::with_capacity(depth);
    // Skip the Name TLV header, descend into its value.
    let Ok((_ty, tn)) = ndn_tlv::read_varu64(name_tlv) else {
        return out;
    };
    let Ok((len, ln)) = ndn_tlv::read_varu64(&name_tlv[tn.min(name_tlv.len())..]) else {
        return out;
    };
    let start = tn + ln;
    let end = (start + len as usize).min(name_tlv.len());
    let mut body = &name_tlv[start.min(name_tlv.len())..end];
    while out.len() < depth && !body.is_empty() {
        let Ok((_ct, ctn)) = ndn_tlv::read_varu64(body) else { break };
        let Ok((clen, cln)) = ndn_tlv::read_varu64(&body[ctn.min(body.len())..]) else { break };
        let vstart = ctn + cln;
        let vend = vstart + clen as usize;
        if vend > body.len() {
            break;
        }
        out.push(&body[vstart..vend]);
        body = &body[vend..];
    }
    out
}

/// `NDN_SCHED_SLOT=N:slot_us`.
fn parse_slot(s: &str) -> Option<SlotSchedule> {
    let (n, us) = s.split_once(':')?;
    let n: u64 = n.trim().parse().ok()?;
    let us: u64 = us.trim().parse().ok()?;
    Some(SlotSchedule::new(us, n))
}

/// `NDN_SCHED_HOP=ch,ch,…:dwell_us`.
fn parse_hop(s: &str) -> Option<HopSchedule> {
    let (chans, dwell) = s.split_once(':')?;
    let classes: Vec<u8> = chans.split(',').filter_map(|c| c.trim().parse().ok()).collect();
    if classes.is_empty() {
        return None;
    }
    let dwell: u64 = dwell.trim().parse().ok()?;
    Some(HopSchedule::new(classes, dwell))
}

#[cfg(test)]
mod tests {
    use super::*;

    // A minimal Data-ish wire: bare packet (no LP) so inner_name uses it as-is: Data(0x06){Name…}.
    // Name = /ndn/alarm : 0x07 len [0x08 3 "ndn"][0x08 5 "alarm"].
    fn data_with_name() -> Vec<u8> {
        let name = [
            0x07, 0x0c, // Name, len 12 (5-byte "ndn" comp + 7-byte "alarm" comp)
            0x08, 0x03, b'n', b'd', b'n', // comp "ndn"
            0x08, 0x05, b'a', b'l', b'a', b'r', b'm', // comp "alarm"
        ];
        let mut pkt = vec![0x06, name.len() as u8]; // Data TLV wrapping the Name
        pkt.extend_from_slice(&name);
        pkt
    }

    #[test]
    fn parses_first_component_as_the_group() {
        let pkt = data_with_name();
        let name = crate::inner_name(&pkt).expect("name");
        let one = name_components(name, 1);
        assert_eq!(one, vec![&b"ndn"[..]]);
        let two = name_components(name, 2);
        assert_eq!(two, vec![&b"ndn"[..], &b"alarm"[..]]);
    }

    #[test]
    fn group_depth_changes_the_key() {
        // Two names sharing the top prefix collapse to one group at depth 1, split at depth 2.
        let h1 = prefix_hash(&[&b"ndn"[..]]);
        let h2a = prefix_hash(&[&b"ndn"[..], &b"alarm"[..]]);
        let h2b = prefix_hash(&[&b"ndn"[..], &b"bulk"[..]]);
        assert_ne!(h2a, h2b);
        assert_ne!(h1, h2a);
    }

    #[test]
    fn beacon_round_trips_and_ignores_ndn() {
        // A built beacon parses back to a plausible reference; NDN first-bytes are not beacons.
        let sched = FaceScheduler {
            slot: parse_slot("4:3000"),
            hop: None,
            group_depth: 1,
            clock_source: ClockSource::CommonView,
            knobs: None,
            bw: crate::Bandwidth::default(),
            current_ch: super::AtomicU8::new(u8::MAX),
            hw: super::Mutex::new(RadioHwClock::realtek()),
            cv: super::Mutex::new(RadioHwClock::common_view()),
            master: true,
            base: super::Instant::now(),
        };
        let wire = sched.build_beacon();
        assert!(FaceScheduler::parse_beacon(&wire).is_some());
        assert_eq!(FaceScheduler::parse_beacon(&[0x06, 0x0c, 0x07]), None); // an NDN Data
        assert_eq!(FaceScheduler::parse_beacon(&[0x64, 0x00]), None); // an LP packet
        // After ingesting a reference the common-view clock reads that timeline.
        sched.ingest_time_ref(9_000_000);
        assert!(sched.now_us() >= 9_000_000);
    }

    #[test]
    fn config_parsers_round_trip() {
        let s = parse_slot("8:3000").expect("slot");
        assert_eq!(s.owner_slot(0), 0);
        assert_eq!(s.superframe_us(), 8 * 3000);
        let h = parse_hop("1,6,11:120000").expect("hop");
        assert_eq!(h.classes(), &[1, 6, 11]);
        assert_eq!(h.dwell_remaining_us(0), 120000);
        assert!(parse_slot("garbage").is_none());
        assert!(parse_hop(":100").is_none());
    }
}
