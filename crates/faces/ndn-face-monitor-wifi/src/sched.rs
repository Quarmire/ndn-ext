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
//! - `NDN_SCHED_CLAIM=1` — claimable slots: a name may claim an idle slot (owner overheard silent) via a
//!   CCLF election, instead of wasting it — the demand-adaptive token that beats fixed name-TDMA. Off ⇒
//!   fixed owner-only slots. Best on the sub-µs `cv` clock, where µs slots + µs guards make it tight.
//! Unset ⇒ scheduler disabled ⇒ the send path is byte-for-byte unchanged.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ndn_radio_cognition::{HopSchedule, SlotSchedule, prefix_hash, wifi_airtime_us};

use crate::radio::{Bandwidth, RadioKnobs};
use ndn_frame_io::LinkStamp;
use ndn_time::{NetworkTime, RadioHwClock, RefBelief};

/// What [`FaceScheduler::hold_status`] found for the slot we may be holding (#95).
#[derive(Debug, PartialEq, Eq)]
enum HoldStatus {
    /// We hold this slot and there is room — keep transmitting without re-contending.
    Continue,
    /// We held it, and must stop: the owner spoke, or the frame no longer fits.
    Ended,
    /// We hold no claim on this slot.
    None,
}

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

/// How long a slot owner stays "known to be in range" after we last overheard it (µs).
///
/// This is a **presence** timeout, so it is set by how fast the neighbourhood changes — a node
/// walking out of range, a node dying — not by how often the owner happens to transmit. Five seconds
/// is a few seconds of pedestrian motion at 5 GHz; long enough that a once-a-second talker is
/// continuously known, short enough that a departed neighbour stops vetoing claims within one
/// human-noticeable beat.
const PRESENCE_WINDOW_US: u64 = 5_000_000;

/// How many frame-airtimes wide the CCLF draw is. The draw only has to order contenders far enough
/// apart that the loser hears the winner and cancels; 8 gives a handful of separable positions
/// without spending the slot it is competing for.
const CCLF_SPREAD: u64 = 8;

/// A snapshot of a face's common-view time state — the essentials a consumer reads from the
/// ndn-time hardware-clock plane (see [`FaceScheduler::time_status`]).
#[derive(Clone, Copy, Debug)]
pub struct TimeStatus {
    /// Current common-view time, µs — sub-µs when `hw_synced`, else software/wall fallback.
    pub now_us: u64,
    /// Disciplined to a neighbour's **hardware** timing beacon (sub-µs, self-contained, no AP/NTP).
    pub hw_synced: bool,
    /// The hardware common-view offset onto the mesh timeline (`peer_tsf − our_rxtsfl`, µs), if synced.
    pub offset_us: Option<i64>,
}

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
    /// The radio-native common-view clock, disciplined to a clock-master's SOFTWARE time-beacon
    /// (`CommonView` mode, ms). The master feeds its own reference each broadcast; slaves feed received.
    cv: Mutex<RadioHwClock>,
    /// The **hardware** common-view offset (µs), from a neighbour's HW-TSF-stamped beacon: `peer_tsf −
    /// our_rxtsfl`, both hardware clocks. When set, `CommonView` mode reads `hw.now() + this` — the peer's
    /// timeline at the RX-stamp floor (~0.5 µs), the #74 self-contained µs path — falling back to the
    /// software `cv` clock (ms) until a hardware beacon is heard. Fed by [`ingest_common_view`](Self::ingest_common_view).
    cv_hw: Mutex<Option<i64>>,
    /// This node broadcasts the time-beacon (the clock master). At most one master per timeline.
    master: bool,
    /// Multi-hop network-time state (#75): elects the lowest-id node as the network reference and
    /// composes this node's offset onto its timeline hop-by-hop. Fed by [`ingest_common_view`]. The
    /// `CommonView` epoch reads the offset to the *network reference*, not just the nearest neighbour, so
    /// nodes out of the reference's range still converge (each hop adds only the ~0.5 µs RX-stamp jitter).
    ///
    /// [`ingest_common_view`]: Self::ingest_common_view
    net: Mutex<NetworkTime>,
    /// Claimable slots (named-token-scheduling.md): a slot is OWNED by name but if its owner is idle
    /// (nothing overheard since the slot began) another name with data may CLAIM it via a CCLF election.
    /// `false` = fixed name-TDMA (owner-only). On when `NDN_SCHED_CLAIM=1`.
    claimable: bool,
    /// Common-view µs of the last overheard frame **of this scheduling domain** — the claimable
    /// decision's "is this slot idle?" input (idle ⇔ `last_domain_rx < slot_start`). `0` = nothing yet.
    ///
    /// **Domain, not energy.** This used to be every captured frame, which made the gate an energy
    /// detector on a shared channel: ch149 carries ~22 frame/s of other people's traffic, so a slot
    /// almost never looked idle and the claim path measured as ~0 gain on air (2026-08-10). But
    /// foreign traffic is not evidence about the *owner's* intent — it is interference, which the slot
    /// MAC neither schedules nor can avoid. Only frames that parse as this domain's named traffic
    /// (i.e. [`name_group_hash`](Self::name_group_hash) succeeds) mark a slot taken.
    last_domain_rx: AtomicU64,
    /// Frames seen that were NOT of this domain — pure diagnostic, so an on-air run can tell "the slot
    /// was busy" from "the channel is busy", which is the distinction the old `last_rx` erased.
    ambient_rx: AtomicU64,
    /// Times [`try_claim`](Self::try_claim) has been run, and times it won. The claim path had no
    /// observability at all, which is why it took a two-day on-air campaign to discover that a
    /// waiting frame was only ever *offered* one slot to contend for. `attempts ≈ wins ≈ 0` while the
    /// gate is plainly throttling means the contention never happens; `attempts ≫ wins` means it
    /// happens and loses.
    claim_attempts: AtomicU64,
    claim_wins: AtomicU64,
    /// The bearer's rate policy, so the airtime estimate behind the guard band (#84) uses the rate
    /// we will actually transmit at. `None` ⇒ assume the conservative broadcast rate, which
    /// over-estimates airtime — the safe direction, since a too-large estimate only defers us by a
    /// slot while a too-small one overruns someone else's.
    rate: Option<std::sync::Arc<crate::RatePolicy>>,
    /// **Positive evidence that a slot's owner is in range** (#88/#94): per slot index, the
    /// common-view µs at which we last overheard a frame whose name-group owns that slot. `0` = never.
    ///
    /// Bounded by the superframe length and allocation-free. This is what makes an idle slot readable:
    /// silence alone cannot tell a silent owner from a *hidden* one, and claiming a hidden owner's slot
    /// collides at its receiver — damage neither the claimant nor the owner can observe.
    heard_by_slot: Vec<AtomicU64>,
    /// **Backlog per name-group** (#95): frames of the group owning slot *k* that we deferred since
    /// that group last got a turn. The demand signal the CCLF election was missing — the comment on
    /// the claim called it "the demand-adaptive form that beats fixed-TDMA" while the draw was a
    /// function of name and time only, so a node with one trivial frame contended exactly as hard as
    /// one with a backlog.
    deferred_by_slot: Vec<AtomicU32>,
    /// **The won slot we are currently holding** (#95): `(slot_start_us, deadline_us)` packed as two
    /// cells. A claim used to buy exactly one frame — the next frame re-entered the election and paid
    /// the jitter again, so a burst could not use the idle slot it had just won. Holding is bounded
    /// by the slot and surrendered the moment the owner speaks.
    hold_slot_start: AtomicU64,
    /// Claim a slot whose owner we have never heard? Default **false**: an unheard owner is exactly the
    /// hidden-terminal case, and the safe reading of silence is "I cannot tell". `NDN_SCHED_CLAIM_UNKNOWN=1`
    /// opts into the throughput-first reading (claim anything idle), which is what the code did before.
    claim_unknown: bool,
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
        let claimable = std::env::var("NDN_SCHED_CLAIM").ok().as_deref() == Some("1");
        // Our node id for the network-reference election (#75): lowest id wins. Default u64::MAX = "never
        // the reference, always sync to a neighbour" (a pure follower); a node meant to be a candidate
        // sets its ephemeral nonce here via NDN_SCHED_NODE_ID.
        let node_id: u64 = std::env::var("NDN_SCHED_NODE_ID").ok().and_then(|s| s.parse().ok()).unwrap_or(u64::MAX);
        // One evidence cell per slot in the superframe (1 when there is no slot schedule at all).
        let slot_count = slot.as_ref().map(|s| s.slots() as usize).unwrap_or(1).max(1);
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
            cv_hw: Mutex::new(None),
            master,
            net: Mutex::new(NetworkTime::new(node_id)),
            claimable,
            last_domain_rx: AtomicU64::new(0),
            ambient_rx: AtomicU64::new(0),
            claim_attempts: AtomicU64::new(0),
            claim_wins: AtomicU64::new(0),
            heard_by_slot: (0..slot_count).map(|_| AtomicU64::new(0)).collect(),
            deferred_by_slot: (0..slot_count).map(|_| AtomicU32::new(0)).collect(),
            hold_slot_start: AtomicU64::new(u64::MAX),
            claim_unknown: std::env::var("NDN_SCHED_CLAIM_UNKNOWN").is_ok(),
            rate: None,
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

    /// Discipline the **hardware** common-view clock from a neighbour's HW-TSF-stamped beacon (#74): the
    /// pair `(peer_tsf, our_rxtsfl)` — the transmitter's hardware TSF from the beacon body and OUR
    /// hardware RX stamp of that same on-air event. The transmitter's TX latency cancels (one shared
    /// event), so the offset `peer_tsf − our_rxtsfl` maps our local hardware clock onto the peer's
    /// timeline at the RX-stamp floor. Every node disciplining to the same neighbour's beacon converges
    /// to sub-µs — the self-contained µs common-view. Called by the RX reader for each mesh time-beacon.
    pub fn ingest_common_view(&self, peer_tsf: u64, our_rxtsfl: u64, nbr: RefBelief) {
        // Keep our local hardware clock disciplined to the RX TSF (so `hw.now()` tracks it between
        // beacons even without other traffic).
        let host_now = self.base.elapsed().as_micros() as u64;
        if let Ok(mut hw) = self.hw.lock() {
            hw.on_raw(our_rxtsfl, host_now);
        }
        // Compose through the network-time election (#75): our hardware offset to this neighbour plus
        // the neighbour's advertised offset to its reference. For a direct beacon that carries no belief,
        // the caller passes the neighbour as its own stratum-0 reference → single-hop offset, and the
        // lowest-id neighbour is elected. The scheduler epoch then reads our offset to the *network*
        // reference (0 if we are it).
        let hw_offset = (peer_tsf as i64).wrapping_sub(our_rxtsfl as i64);
        let off = if let Ok(mut n) = self.net.lock() {
            n.observe(hw_offset, nbr);
            n.offset_to_ref()
        } else {
            hw_offset
        };
        if let Ok(mut o) = self.cv_hw.lock() {
            *o = Some(off);
        }
    }

    /// RX-reader convenience: ingest a **direct** neighbour beacon whose frame carries no advertised
    /// belief yet — treat the neighbour as a stratum-0 reference identified by its BSSID (the ephemeral
    /// nonce). Single-hop today; multi-hop (belief-carrying beacons) calls [`ingest_common_view`] with
    /// the parsed belief. The lowest-id neighbour wins the reference election.
    ///
    /// [`ingest_common_view`]: Self::ingest_common_view
    pub fn ingest_mesh_beacon(&self, peer_tsf: u64, our_rxtsfl: u64, bssid: [u8; 6]) {
        let ref_id = u64::from_le_bytes([bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5], 0, 0]);
        self.ingest_common_view(peer_tsf, our_rxtsfl, RefBelief { ref_id, stratum: 0, offset_to_ref: 0 });
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

    /// **Every captured frame**, for the claimable-slot decision (#88/#94) — the busy mark *and* the
    /// evidence of who is in range.
    ///
    /// Three things were wrong with doing this in [`on_rx_stamp`](Self::on_rx_stamp):
    ///
    /// 1. **It only ran when the frame carried a hardware stamp.** The caller's hook is
    ///    `if let (Some(sched), Some(stamp))`, and `stamp` is `None` on any radio whose driver does
    ///    not report TSFT — so on those radios `last_rx` never moved, the medium looked *permanently*
    ///    idle, and the claimable path fired on every single slot. Busy-marking must not depend on
    ///    the timing plane; it is a data-plane fact.
    /// 2. **It was an energy detector.** Any frame marked the medium busy, so "the owner is idle" was
    ///    really "nobody transmitted" — which is a different statement and a weaker one.
    /// 3. **Silence was read as permission.** Hearing nothing cannot distinguish an owner with
    ///    nothing to send from an owner we simply cannot hear. Claiming the latter's slot collides at
    ///    *its* receiver, and neither the claimant nor the owner can observe that.
    ///
    /// So this also records, per slot, when we last heard a frame whose name-group owns it. That is
    /// positive evidence the slot's user is in range, which is what makes its silence readable.
    ///
    /// **A fourth thing was wrong, and only the air showed it** (2026-08-10): the busy mark fired on
    /// *any* captured frame, including the ~22 frame/s of unrelated traffic on a shared 5 GHz channel.
    /// A slot then essentially never read as idle, so the claim path — which measured a clean 4×
    /// throughput gain with the evidence gate forced open — delivered ~0 with it closed. Foreign
    /// traffic is interference, not a statement about the slot owner, so it is counted and dropped
    /// here rather than allowed to veto a claim.
    pub fn observe_rx(&self, wire: &[u8]) {
        if !self.claimable {
            return;
        }
        let now = self.now_us();
        // Key the same way TX does, so the slot indices agree (#89).
        let Some(hash) = self.name_group_hash(wire) else {
            self.ambient_rx.fetch_add(1, Ordering::Relaxed);
            return;
        };
        self.last_domain_rx.store(now, Ordering::Relaxed);
        let keyed = self.medium_keyed(hash);
        if let Some(slot) = &self.slot {
            let k = slot.owner_slot(keyed) as usize;
            if let Some(cell) = self.heard_by_slot.get(k) {
                cell.store(now, Ordering::Relaxed);
            }
        }
    }

    /// Fold the current medium (channel) into a name hash — see the note in [`gate`](Self::gate).
    fn medium_keyed(&self, hash: u64) -> u64 {
        hash ^ u64::from(self.current_ch.load(Ordering::Relaxed)).wrapping_mul(0x9E37_79B9)
    }

    /// A deterministic within-slot CCLF jitter (µs) for this name — the demand-adaptive election among
    /// names contending for an idle slot (named-token-scheduling.md §CCLF). The smallest-jitter claimant
    /// transmits first and the rest overhear-and-cancel. Keyed on the name so it is stable and
    /// coordinator-free; bounded to the front `frac` of the slot so a claim still fits with a guard.
    /// Bind the bearer's rate policy so the guard band's airtime estimate uses the decided rate.
    pub fn with_rate(mut self, rate: std::sync::Arc<crate::RatePolicy>) -> Self {
        self.rate = Some(rate);
        self
    }

    /// The HT MCS index the next frame would ride, if a rate policy is bound.
    fn tx_mcs(&self) -> Option<u8> {
        self.rate.as_ref().map(|r| r.select().index)
    }

    fn cclf_jitter_us(&self, prefix_hash: u64, slot_us: u64, epoch: u64, airtime_us: u64) -> u64 {
        // **The window is sized by DETECTION time, not by the slot.**
        //
        // It used to be `slot_us / 2`: a claimant spent up to half the slot it was fighting for
        // *before* transmitting, so with 8 × 20 ms slots the average claim burned 5 ms of a 20 ms
        // prize. That is not what the draw has to buy. Its only job is to order contenders far enough
        // apart that the loser can hear the winner and cancel — one frame's airtime plus the RX
        // pipeline, since `still_idle` reads a *decoded* frame. So the window is a small multiple of
        // the airtime, capped by the old half-slot bound (never worse than before) and floored so a
        // tiny frame still leaves room to separate anyone.
        //
        // The cost of getting this wrong is asymmetric and that is why the multiple is 8 rather than
        // 2: too small collides claimants (they draw the same µs and neither hears the other in
        // time), too large only wastes airtime we were going to lose anyway.
        let detect = airtime_us.max(1);
        let window = (slot_us / 2).max(1).min(detect.saturating_mul(CCLF_SPREAD).max(2));
        //
        // **`epoch` is mixed in so the winner rotates** (#87). Without it the jitter was a pure
        // function of the name: the same claimant drew the same, smallest delay every idle slot and
        // won all of them, forever — a starvation the CCLF election exists to prevent, and one that
        // looks like a working election from the winner's side. Mixing the slot index re-randomises
        // the draw each slot while keeping every node's view of it identical (all nodes share the
        // common-view clock, so all compute the same epoch), which is what makes the election
        // agree without any message.
        let mixed = prefix_hash ^ epoch.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        let draw = (mixed ^ (mixed >> 32)) % window;

        // **Demand shortens the wait** (#95). The election was a function of name and time only, so a
        // node holding one trivial frame contended exactly as hard as one holding a backlog — while
        // the code called itself "the demand-adaptive form that beats fixed-TDMA". Scaling the draw
        // down by backlog makes that description true: the node with more deferred traffic tends to
        // speak first and therefore wins the idle slot.
        //
        // Unlike the owner grant, this draw does NOT need to be agreed between nodes. It is a
        // randomised backoff: contenders each pick a delay, the shortest transmits, the rest overhear
        // and cancel. Nothing has to be predicted, so a purely local demand term is safe here — which
        // is exactly why it belongs here and not in `owner_slot`.
        //
        // Bounded: the shift saturates and the result keeps a floor, so a large backlog biases the
        // election without collapsing everyone onto zero — which would replace the ordering with a
        // collision. **The bound now follows the window** rather than being a flat 4: with the window
        // sized in detection times (above), an unconditional ÷16 would squeeze every backlogged
        // claimant into a sub-airtime band where none of them can hear the others in time. So halve
        // only while the remaining band still spans at least two detection times.
        let mut max_shift = 0u32;
        while max_shift < 4 && (window >> (max_shift + 1)) >= detect.saturating_mul(2) {
            max_shift += 1;
        }
        let backlog = self.deferred_for(prefix_hash);
        let shift = backlog.min(max_shift);
        (draw >> shift).max(1)
    }

    /// **The hold decision** (#95), extracted so it can be tested on its own rather than through an
    /// async gate that reads the wall clock.
    ///
    /// A won slot buys the rest of that slot, not one frame — but only under the owner-return
    /// contract: anything overheard since the slot began means the owner (or another claimant) has
    /// spoken, and a guest yields. Without that rule, holding a claimed slot would be
    /// indistinguishable from stealing it.
    fn hold_status(
        &self,
        slot: &SlotSchedule,
        slot_start: u64,
        now: u64,
        airtime: u64,
    ) -> HoldStatus {
        if self.hold_slot_start.load(Ordering::Relaxed) != slot_start {
            return HoldStatus::None; // no hold on THIS slot (a stale hold never carries forward)
        }
        if self.last_domain_rx.load(Ordering::Relaxed) >= slot_start {
            return HoldStatus::Ended; // the owner spoke — yield
        }
        if !slot.fits_now(now, airtime) {
            return HoldStatus::Ended; // no room left in the slot we hold
        }
        HoldStatus::Continue
    }

    /// **One attempt to take the slot we are currently sitting in**, `true` ⇒ transmit now.
    ///
    /// Extracted from [`gate`](Self::gate) so it can be run at *every* slot boundary while a frame
    /// waits, not only at the instant the frame was offered — see the loop in `gate` for why that
    /// distinction was worth more than the three threshold fixes put together.
    ///
    /// Covers both halves of #95: continuing a hold we already won, and starting a fresh CCLF
    /// election for an idle slot whose owner we can hear.
    async fn try_claim(&self, slot: &SlotSchedule, hash: u64, airtime: u64) -> bool {
        if !self.claimable {
            return false;
        }
        self.claim_attempts.fetch_add(1, Ordering::Relaxed);
        let now = self.now_us();
        let slot_start = slot.slot_start_us(now);

        // **A won slot buys more than one frame** (#95). The claim used to `return` and the next
        // frame re-entered the election, paying the jitter again — so a burst could not use the very
        // slot it had just won, and the airtime it fought for went unused.
        //
        // **The owner-return contract** is the other half, and it is why holding is safe: the hold is
        // surrendered the instant anything of this domain is overheard in this slot. The owner (or
        // another claimant) has spoken ⇒ we are a guest who has outstayed the invitation, and we go
        // back to waiting for our own slot. Without that rule, holding a claimed slot would be
        // indistinguishable from stealing it.
        match self.hold_status(slot, slot_start, now, airtime) {
            HoldStatus::Continue => {
                self.claim_wins.fetch_add(1, Ordering::Relaxed);
                self.note_sent(hash);
                return true; // still ours, still room — continue the burst.
            }
            HoldStatus::Ended => {
                self.hold_slot_start.store(u64::MAX, Ordering::Relaxed);
            }
            HoldStatus::None => {}
        }

        let idle = self.last_domain_rx.load(Ordering::Relaxed) < slot_start;
        let remaining = slot.slot_remaining_us(now);
        let jitter = self.cclf_jitter_us(hash, slot.slot_us(), slot.epoch(now), airtime);
        // **Positive evidence the slot's owner is in range** (#94). Silence is only readable as
        // "idle" from someone we can actually hear; from a hidden owner it is indistinguishable from
        // a busy medium, and claiming there collides at its receiver.
        let owner_known = self.owner_in_range(slot, slot.current_slot(now) as usize, now);
        // `owned_wait > slot_us`: not worth claiming when our own turn is next anyway — and claiming
        // the slot adjacent to ours buys nothing but a boundary risk.
        // `remaining > jitter + airtime`: room for the jittered wait AND the frame itself; claiming a
        // slot we cannot finish in is the same boundary overrun as the owner path, self-inflicted.
        if !((owner_known || self.claim_unknown)
            && idle
            && slot.wait_us(hash, now) > slot.slot_us()
            && remaining > jitter + airtime)
        {
            return false;
        }
        // CCLF: wait our jitter; if the slot is STILL idle (no one claimed first), take it.
        tokio::time::sleep(Duration::from_micros(jitter)).await;
        if self.last_domain_rx.load(Ordering::Relaxed) >= slot_start {
            return false; // overheard a claimant first → cancel, and wait for our owned slot.
        }
        // Won it. Hold for the rest of THIS slot so a burst can use what we won, under the
        // owner-return contract checked on the next frame.
        self.hold_slot_start.store(slot_start, Ordering::Relaxed);
        self.claim_wins.fetch_add(1, Ordering::Relaxed);
        self.note_sent(hash);
        true
    }

    /// How many captured frames were NOT of this scheduling domain — the channel's ambient load.
    ///
    /// Worth printing at the end of any claim experiment: it separates "our slots were busy" from
    /// "the channel was busy", a distinction the old any-frame busy mark erased and which cost a
    /// whole on-air campaign to rediscover.
    pub fn ambient_frames(&self) -> u64 {
        self.ambient_rx.load(Ordering::Relaxed)
    }

    /// `(claim attempts, claims won)` — the claim path's only observability, and the reading that
    /// would have named the 2026-08-11 defect in one run instead of a campaign: a throttling gate
    /// with `attempts == frames` means each waiting frame contended exactly once and then slept
    /// through every slot it could have taken.
    pub fn claim_counts(&self) -> (u64, u64) {
        (self.claim_attempts.load(Ordering::Relaxed), self.claim_wins.load(Ordering::Relaxed))
    }

    /// **Do we have live evidence that slot `k`'s owner is within earshot?** (#94), extracted so the
    /// window can be tested without driving an async gate off the wall clock.
    ///
    /// **Presence decays on the mobility timescale, not the traffic one.** The window used to be
    /// `slot_us * slots * 4` — four superframes, 640 ms at 8 × 20 ms — which silently made the test
    /// "has the owner transmitted recently" rather than "is the owner still here". A neighbour
    /// sending once a second was therefore unknown for a third of every second, and the claim it
    /// should have permitted was refused. Measured on air 2026-08-10: one of the three reasons the
    /// evidence-gated claim gained ~10% where the same claim with the gate forced open gained 4×.
    ///
    /// So the window is a presence timeout, with the superframe only as a floor: a schedule slower
    /// than the timeout must still let at least one silent turn pass without forgetting the owner.
    fn owner_in_range(&self, slot: &SlotSchedule, k: usize, now: u64) -> bool {
        let last_heard = self.heard_by_slot.get(k).map(|c| c.load(Ordering::Relaxed)).unwrap_or(0);
        let window =
            PRESENCE_WINDOW_US.max(slot.slot_us().saturating_mul(slot.slots()).saturating_mul(2));
        last_heard != 0 && now.saturating_sub(last_heard) <= window
    }

    /// Frames of `prefix_hash`'s group deferred since it last transmitted — the backlog proxy the
    /// CCLF draw scales by. Per name-group rather than per node, so one busy group cannot lend its
    /// urgency to an idle one.
    fn deferred_for(&self, prefix_hash: u64) -> u32 {
        let Some(slot) = &self.slot else { return 0 };
        let k = slot.owner_slot(prefix_hash) as usize;
        self.deferred_by_slot.get(k).map(|c| c.load(Ordering::Relaxed)).unwrap_or(0)
    }

    /// Record that a frame of this group had to wait — the demand signal accumulating.
    fn note_deferred(&self, prefix_hash: u64) {
        if let Some(slot) = &self.slot
            && let Some(c) = self.deferred_by_slot.get(slot.owner_slot(prefix_hash) as usize)
        {
            // Saturating: the backlog is a bias, not a counter anyone reads for magnitude.
            let _ = c.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| Some(v.saturating_add(1)));
        }
    }

    /// This group got its turn — the backlog is spent.
    fn note_sent(&self, prefix_hash: u64) {
        if let Some(slot) = &self.slot
            && let Some(c) = self.deferred_by_slot.get(slot.owner_slot(prefix_hash) as usize)
        {
            c.store(0, Ordering::Relaxed);
        }
    }

    // ---- Public time API: the essentials any consumer needs from the ndn-time hardware-clock plane ----
    // (the token/slot scheduler, telemetry, a fusion layer). The low-level types — RadioHwClock,
    // LinkStamp, DomainMap, CommonViewPool — live in `ndn_time`; this is the ready-to-use radio view.

    /// The current **common-view time**, microseconds — the one clock every node in range agrees on.
    /// Sub-µs and self-contained when disciplined to a neighbour's hardware timing beacon (#74), else the
    /// software/wall fallback. This is the value a computed token/slot schedule reads for `epoch(t)`.
    pub fn common_view_now_us(&self) -> u64 {
        self.now_us()
    }

    /// Whether the clock is disciplined to a neighbour's **hardware** timing beacon — i.e. sub-µs,
    /// self-contained common-view (no AP, no NTP). `false` = still on the ms software/wall fallback.
    pub fn is_hw_synced(&self) -> bool {
        self.cv_hw.lock().ok().and_then(|o| *o).is_some()
    }

    /// The hardware common-view offset (`peer_tsf − our_rxtsfl`, µs) onto the mesh timeline, if synced.
    pub fn cv_offset_us(&self) -> Option<i64> {
        self.cv_hw.lock().ok().and_then(|o| *o)
    }

    /// A one-shot snapshot of the common-view time state — `(now_us, hw_synced, offset_us)`.
    pub fn time_status(&self) -> TimeStatus {
        let offset_us = self.cv_offset_us();
        TimeStatus { now_us: self.now_us(), hw_synced: offset_us.is_some(), offset_us }
    }

    /// This node's current network-time belief (#75) — what it advertises in its own timing beacon so
    /// the next hop composes off it (`ref_id`, `stratum`, `offset_to_ref`).
    pub fn my_belief(&self) -> RefBelief {
        self.net.lock().map(|n| n.belief()).unwrap_or(RefBelief { ref_id: u64::MAX, stratum: 0, offset_to_ref: 0 })
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
                // Prefer the HARDWARE common-view (#74, ~0.5 µs) once a neighbour's HW-stamped beacon has
                // been heard: our local hardware clock projected onto the peer's timeline. Fall back to
                // the software beacon (ms) until then.
                if let Some(off) = self.cv_hw.lock().ok().and_then(|o| *o) {
                    let local = self.hw.lock().map(|hw| hw.now(host_now)).unwrap_or(host_now);
                    (local as i64).wrapping_add(off) as u64
                } else {
                    self.cv.lock().map(|cv| cv.now(host_now)).unwrap_or(host_now)
                }
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

        // Frequency first: sit on the name's channel for this hop epoch. The hop decision uses the
        // RAW name hash — the channel must not depend on the channel.
        if let Some(hop) = &self.hop {
            let ch = hop.channel(hash, now);
            self.retune(ch).await;
        }

        // **The slot assignment is keyed to the medium, not just the name** (#89).
        //
        // `owner_slot` is `hash % slots` with no medium term, so every radio ran the identical
        // schedule: name N owned slot k on *every* bearer at the same instant. A second radio then
        // bought parallel copies of one turn rather than additional turns — the per-name access
        // latency, which is what a slot MAC costs you, did not improve at all with radio count.
        //
        // Folding the channel in staggers the assignment per medium: name N owns a different slot on
        // ch36 than on ch149, so at any instant two different names are transmitting on the two
        // channels, and each name gets one turn per superframe *per medium*. Access latency divides
        // by the number of independent media, which is the whole reason to carry more than one radio.
        //
        // Keyed on the CHANNEL rather than a radio index on purpose: radios on the same channel share
        // one medium and must agree, and two nodes' "radio 0" may sit on different channels. Every
        // node hearing this medium computes the same key with no coordination. Two bearers genuinely
        // on the same channel still coincide — correct, that is the diversity fan-out case.
        let hash = self.medium_keyed(hash);

        // Then time: the token grant.
        if let Some(slot) = &self.slot {
            // How long this frame will hold the medium. Over-estimated on purpose — see
            // `wifi_airtime_us`: under-estimating bleeds into the next owner's slot, over-estimating
            // only defers us by one.
            let airtime = wifi_airtime_us(wire.len(), self.tx_mcs());
            if slot.owns_now(hash, now) {
                // **Owning the slot is not the same as fitting in it** (#84). A frame launched near
                // the boundary keeps radiating into the next owner's turn — the exact collision this
                // MAC exists to prevent, and one charged to a *different* name, so the node causing
                // it never sees the loss. If it does not fit, fall through and wait for our next
                // slot rather than transmit across the boundary.
                if slot.fits_now(now, airtime) {
                    self.note_sent(hash); // got our turn — backlog spent
                    return; // our owned slot, with room — a collision-free turn; transmit now.
                }
            }
            // Claimable slot (named-token-scheduling.md): if this is NOT our slot but the current
            // slot's owner is IDLE, contend for it via a CCLF election rather than wasting it.
            if self.try_claim(slot, hash, airtime).await {
                return; // claimed (or holding) this slot — transmit now.
            }
            // Reaching here means this frame waits — which IS the demand signal (#95). A group that
            // keeps being deferred accumulates backlog and draws a shorter CCLF jitter next time, so
            // it wins idle slots ahead of a group with nothing queued.
            self.note_deferred(hash);

            // **Wait one slot at a time, re-contending at every boundary** — not one long sleep to
            // our own turn.
            //
            // This loop used to sleep `wait_us`, the whole gap to the owned slot, and that was the
            // suppressor that dominated all three of the others (measured 2026-08-11). A frame
            // entering the gate got exactly ONE claim evaluation, against whichever slot happened to
            // be current at that instant; if that slot was not claimable it then slept past every
            // idle slot between there and its own. With a serialized sender the evaluated slot was
            // always the one right after our own — never the neighbour's, four slots away, which was
            // the only slot we had evidence for. So the claim could not fire even though an idle,
            // known-owner slot opened once per superframe.
            //
            // It also explains the otherwise-puzzling pair of measurements from 2026-08-10: with
            // `CLAIM_UNKNOWN` the very first evaluation always succeeded (any slot is claimable), so
            // the machinery showed 4× — while the evidence-gated claim, which needs a *particular*
            // slot, essentially never got to look at one.
            //
            // A wake per slot boundary is the cost. That is ≤ `slots` wakeups per superframe per
            // waiting frame, against a 20 ms slot — cheap next to the airtime it recovers.
            loop {
                let t = self.now_us();
                if slot.owns_now(hash, t) && slot.fits_now(t, airtime) {
                    self.note_sent(hash); // our slot arrived — backlog spent
                    break;
                }
                if self.try_claim(slot, hash, airtime).await {
                    return; // won an idle slot on the way to our own.
                }
                // To the next boundary, so every intervening slot gets exactly one evaluation.
                let step = slot.slot_remaining_us(self.now_us()).max(1);
                tokio::time::sleep(Duration::from_micros(step)).await;
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
    fn hardware_common_view_beats_software_and_aligns_the_epoch() {
        // A scheduler in CommonView mode. Before any HW beacon it uses the software cv clock; after a
        // HW beacon it reads the peer's hardware timeline (the #74 µs path). Two nodes fed the SAME
        // peer beacon (same peer_tsf) land on the same epoch regardless of their own RX-stamp domain.
        let mk = || FaceScheduler {
            slot: parse_slot("8:3000"),
            hop: None,
            group_depth: 1,
            clock_source: ClockSource::CommonView,
            knobs: None,
            bw: crate::Bandwidth::default(),
            current_ch: super::AtomicU8::new(u8::MAX),
            hw: super::Mutex::new(RadioHwClock::realtek()),
            cv: super::Mutex::new(RadioHwClock::common_view()),
            cv_hw: super::Mutex::new(None),
            master: false,
            net: super::Mutex::new(ndn_time::NetworkTime::new(u64::MAX)),
            claimable: false,
            last_domain_rx: super::AtomicU64::new(0),
            ambient_rx: super::AtomicU64::new(0),
            claim_attempts: super::AtomicU64::new(0),
            claim_wins: super::AtomicU64::new(0),
            heard_by_slot: (0..8).map(|_| super::AtomicU64::new(0)).collect(),
            deferred_by_slot: (0..8).map(|_| super::AtomicU32::new(0)).collect(),
            hold_slot_start: super::AtomicU64::new(u64::MAX),
            claim_unknown: false,
            rate: None,
            base: super::Instant::now(),
        };
        let a = mk();
        let b = mk();
        // Both hear one peer beacon: peer_tsf = 5_000_000 µs. Node A's RX TSF domain reads 1_000_000 at
        // that beacon; node B's independent counter reads 8_000_000 — different domains, same event.
        let bssid = [0x02, 1, 2, 3, 4, 5]; // same reference beacon → both elect the same reference
        a.ingest_mesh_beacon(5_000_000, 1_000_000, bssid);
        b.ingest_mesh_beacon(5_000_000, 8_000_000, bssid);
        // Both now read the peer's timeline (~5_000_000 + their small elapsed) → same slot epoch.
        let (ea, eb) = (a.now_us() / 3000, b.now_us() / 3000);
        assert_eq!(ea, eb, "hardware common-view did not align the two nodes' epochs");
        assert!(a.now_us() >= 5_000_000, "should read the peer's hardware timeline, not the fallback");
    }

    #[test]
    fn cclf_jitter_is_deterministic_and_bounded() {
        let s = FaceScheduler {
            slot: parse_slot("8:3000"),
            hop: None,
            group_depth: 1,
            clock_source: ClockSource::CommonView,
            knobs: None,
            bw: crate::Bandwidth::default(),
            current_ch: super::AtomicU8::new(u8::MAX),
            hw: super::Mutex::new(RadioHwClock::realtek()),
            cv: super::Mutex::new(RadioHwClock::common_view()),
            cv_hw: super::Mutex::new(None),
            master: false,
            net: super::Mutex::new(ndn_time::NetworkTime::new(u64::MAX)),
            claimable: true,
            last_domain_rx: super::AtomicU64::new(0),
            ambient_rx: super::AtomicU64::new(0),
            claim_attempts: super::AtomicU64::new(0),
            claim_wins: super::AtomicU64::new(0),
            heard_by_slot: (0..8).map(|_| super::AtomicU64::new(0)).collect(),
            deferred_by_slot: (0..8).map(|_| super::AtomicU32::new(0)).collect(),
            hold_slot_start: super::AtomicU64::new(u64::MAX),
            claim_unknown: false,
            rate: None,
            base: super::Instant::now(),
        };
        let a = prefix_hash(&[b"ndn", b"alarm"]);
        let b = prefix_hash(&[b"ndn", b"bulk"]);

        // Within one slot the draw is deterministic — that is what lets every node compute the same
        // election with no message, since all share the common-view clock and so the same epoch.
        assert_eq!(s.cclf_jitter_us(a, 3000, 7, 200), s.cclf_jitter_us(a, 3000, 7, 200));
        // Bounded to the front half of the slot, so a claim leaves room to transmit.
        for e in 0..64 {
            assert!(s.cclf_jitter_us(a, 3000, e, 200) < 1500);
            assert!(s.cclf_jitter_us(b, 3000, e, 200) < 1500);
        }
        // Different names draw an ordering within a slot.
        assert_ne!(s.cclf_jitter_us(a, 3000, 7, 200), s.cclf_jitter_us(b, 3000, 7, 200));

        // **The winner must rotate** (#87). The jitter used to be a pure function of the name, so
        // whichever name folded to the smallest value won *every* idle slot, forever — starvation
        // that looks like a working election from the winner's side. Mixing the slot epoch
        // re-randomises the draw each slot while keeping it agreed across nodes.
        let names: Vec<u64> = (0..8)
            .map(|i| prefix_hash(&[b"ndn", format!("n{i}").as_bytes()]))
            .collect();
        let mut wins = std::collections::HashMap::new();
        for epoch in 0..2_000u64 {
            let winner = names
                .iter()
                .min_by_key(|n| s.cclf_jitter_us(**n, 3000, epoch, 200))
                .unwrap();
            *wins.entry(*winner).or_insert(0usize) += 1;
        }
        assert_eq!(wins.len(), names.len(), "every name must win some slots, got {wins:?}");
        let most = *wins.values().max().unwrap();
        assert!(
            most < 2_000 / 2,
            "no name may dominate the idle slots; the worst took {most}/2000 — with the old \
             name-only jitter one name took all 2000"
        );
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
            cv_hw: super::Mutex::new(None),
            master: true,
            net: super::Mutex::new(ndn_time::NetworkTime::new(u64::MAX)),
            claimable: false,
            last_domain_rx: super::AtomicU64::new(0),
            ambient_rx: super::AtomicU64::new(0),
            claim_attempts: super::AtomicU64::new(0),
            claim_wins: super::AtomicU64::new(0),
            heard_by_slot: (0..8).map(|_| super::AtomicU64::new(0)).collect(),
            deferred_by_slot: (0..8).map(|_| super::AtomicU32::new(0)).collect(),
            hold_slot_start: super::AtomicU64::new(u64::MAX),
            claim_unknown: false,
            rate: None,
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

    /// **A slot whose owner we have never heard must not be claimed** (#88/#94).
    ///
    /// The claim used to turn on a bare energy detector: `last_rx < slot_start` ⇒ "idle" ⇒ take it.
    /// That reads silence as permission, and silence has two causes — an owner with nothing to send,
    /// and an owner we cannot hear. Claiming the second collides at *its* receiver, damage neither
    /// the claimant nor the owner ever observes, so nothing in the system corrects it.
    ///
    /// `observe_rx` now records, per slot, when we last overheard a frame whose name-group owns that
    /// slot. That is the positive evidence: silence from a station we demonstrably hear is readable;
    /// silence from one we have never heard is not.
    #[test]
    fn a_slot_is_only_claimable_with_evidence_its_owner_is_in_range() {
        let sched = FaceScheduler {
            slot: parse_slot("8:3000"),
            hop: None,
            group_depth: 1,
            clock_source: ClockSource::Wall,
            knobs: None,
            bw: crate::Bandwidth::default(),
            current_ch: super::AtomicU8::new(36),
            hw: super::Mutex::new(RadioHwClock::realtek()),
            cv: super::Mutex::new(RadioHwClock::common_view()),
            cv_hw: super::Mutex::new(None),
            master: false,
            net: super::Mutex::new(ndn_time::NetworkTime::new(u64::MAX)),
            claimable: true,
            last_domain_rx: super::AtomicU64::new(0),
            ambient_rx: super::AtomicU64::new(0),
            claim_attempts: super::AtomicU64::new(0),
            claim_wins: super::AtomicU64::new(0),
            heard_by_slot: (0..8).map(|_| super::AtomicU64::new(0)).collect(),
            deferred_by_slot: (0..8).map(|_| super::AtomicU32::new(0)).collect(),
            hold_slot_start: super::AtomicU64::new(u64::MAX),
            claim_unknown: false,
            rate: None,
            base: super::Instant::now(),
        };
        let slot = sched.slot.as_ref().unwrap();

        // A Data frame under /ndn/alarm — what a neighbour using that group would put on air.
        let wire = {
            let mut name = Vec::new();
            for c in [&b"ndn"[..], &b"alarm"[..]] {
                name.push(0x08);
                name.push(c.len() as u8);
                name.extend_from_slice(c);
            }
            let mut tlv = vec![0x07, name.len() as u8];
            tlv.extend_from_slice(&name);
            let mut d = vec![0x06, tlv.len() as u8];
            d.extend_from_slice(&tlv);
            d
        };
        let owned = slot.owner_slot(
            sched.medium_keyed(sched.name_group_hash(&wire).expect("the frame carries a name")),
        ) as usize;

        // Nothing heard yet: every slot's owner is unknown — the hidden-terminal case.
        assert!(
            sched.heard_by_slot.iter().all(|c| c.load(super::Ordering::Relaxed) == 0),
            "no evidence before any frame is observed"
        );

        // Overhearing that group is the evidence, and it lands on THAT group's slot only.
        sched.observe_rx(&wire);
        assert!(
            sched.heard_by_slot[owned].load(super::Ordering::Relaxed) > 0,
            "hearing /ndn/alarm must mark the slot /ndn/alarm owns"
        );
        let others = sched
            .heard_by_slot
            .iter()
            .enumerate()
            .filter(|(i, c)| *i != owned && c.load(super::Ordering::Relaxed) > 0)
            .count();
        assert_eq!(others, 0, "and must not vouch for any other slot's owner");

        // It also marks the medium busy — and crucially does so with no hardware stamp involved.
        // That path used to hang off `on_rx_stamp`, which the caller only invokes for stamped
        // frames, so a radio reporting no TSFT marked the medium busy *never* and claimed always.
        assert!(
            sched.last_domain_rx.load(super::Ordering::Relaxed) > 0,
            "busy-marking must not depend on the timing plane"
        );
    }

    /// **Somebody else's traffic must not veto our claim** — the first of the three suppressors the
    /// 2026-08-10 on-air run found (`token-concept-named-radio`).
    ///
    /// `observe_rx` marked the medium busy on *every* captured frame. In monitor mode that is every
    /// frame on the channel, and ch149 carried ~22 frame/s of unrelated 802.11 traffic, so a slot
    /// essentially never satisfied `last_rx < slot_start` and the claim path never fired. The
    /// measurement that exposed it: the same claim with the evidence gate forced open
    /// (`NDN_SCHED_CLAIM_UNKNOWN`) delivered 4× — the machinery worked, its inputs were poisoned.
    ///
    /// Foreign traffic is interference. The slot MAC does not schedule it, cannot avoid it, and
    /// learns nothing about the *owner's* intent from it — so it is counted and dropped.
    #[test]
    fn ambient_traffic_does_not_mark_a_slot_busy() {
        let sched = mk_claim_sched();

        // A beacon-ish frame from an unrelated network: no NDN Name, so no name-group.
        let ambient = [0x80u8, 0x00, 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04];
        assert!(
            sched.name_group_hash(&ambient).is_none(),
            "the fixture must really be un-attributable, or this test proves nothing"
        );

        sched.observe_rx(&ambient);
        assert_eq!(
            sched.last_domain_rx.load(super::Ordering::Relaxed),
            0,
            "a frame we cannot attribute to this scheduling domain must leave every slot claimable"
        );
        assert_eq!(
            sched.ambient_rx.load(super::Ordering::Relaxed),
            1,
            "but it must still be counted, or an on-air run cannot tell a busy slot from a busy channel"
        );
        assert!(
            sched.heard_by_slot.iter().all(|c| c.load(super::Ordering::Relaxed) == 0),
            "and it is evidence about nobody's presence"
        );

        // The contrast: a frame of ours does mark it, so this is a discrimination and not a mute.
        sched.observe_rx(&data_wire(&[b"ndn", b"alarm"]));
        assert!(
            sched.last_domain_rx.load(super::Ordering::Relaxed) > 0,
            "our own domain's traffic must still mark the slot taken"
        );
    }

    /// **Presence evidence must outlive the gap between a slow talker's frames** — suppressor two.
    ///
    /// The window was four superframes: 640 ms at the 8 × 20 ms schedule used on air. The neighbour
    /// in that run transmitted once a second, so for ~360 ms of every second its slot read as
    /// *owner unknown* and the claim was refused — despite the node being audible, stationary, and
    /// three feet away. The window answers "is the owner in range", which changes when a node moves,
    /// not between two of its frames.
    #[test]
    fn presence_evidence_survives_a_once_a_second_neighbour() {
        let sched = mk_claim_sched();
        let slot = sched.slot.as_ref().unwrap();
        let superframe = slot.slot_us() * slot.slots(); // 24 ms here, 160 ms on air

        // Heard once, then silence for a full second — a 1 f/s neighbour between frames.
        sched.heard_by_slot[3].store(1_000_000, super::Ordering::Relaxed);
        assert!(
            sched.owner_in_range(slot, 3, 1_000_000 + 1_000_000),
            "a neighbour that speaks once a second is audible the whole second; the old \
             four-superframe window ({}µs) called it unknown after {}µs",
            superframe * 4,
            superframe * 4
        );

        // It is still a timeout, not an amnesty: a departed neighbour must stop vouching.
        assert!(
            !sched.owner_in_range(slot, 3, 1_000_000 + PRESENCE_WINDOW_US + 1),
            "evidence must expire, or a node that left keeps its slot reserved forever"
        );
        // And never-heard is never known — the hidden-terminal case #94 exists for.
        assert!(!sched.owner_in_range(slot, 5, 1_000_000), "silence from an unheard owner is not evidence");
    }

    /// **The CCLF draw must not spend the slot it is competing for** — suppressor three.
    ///
    /// The window was `slot_us / 2`: at 20 ms slots a claimant waited an average 5 ms before
    /// transmitting into a 20 ms prize, so a quarter of every won slot was burnt on the election.
    /// The draw only has to separate contenders by enough that the loser hears the winner and
    /// cancels — one frame's airtime — so it is sized in airtimes and merely *capped* by the old
    /// half-slot bound.
    #[test]
    fn the_cclf_draw_is_sized_by_airtime_not_by_the_slot() {
        let s = mk_claim_sched();
        let h = prefix_hash(&[b"ndn", b"bulk"]);
        let slot_us = 20_000; // the on-air schedule
        let airtime = 250; // a small frame at the conservative broadcast rate

        for e in 0..256u64 {
            let d = s.cclf_jitter_us(h, slot_us, e, airtime);
            assert!(
                d <= airtime * CCLF_SPREAD,
                "draw {d}µs exceeds the {}µs detection window; the old half-slot rule allowed \
                 {}µs — up to half the prize",
                airtime * CCLF_SPREAD,
                slot_us / 2
            );
            assert!(d >= 1, "and is never zero — zero is a collision, not an ordering");
        }

        // The cap still binds the other way: a frame so long that 8 airtimes exceed half the slot
        // must not draw past the half-slot bound, or the claim cannot fit in what it wins.
        let long = 4_000;
        for e in 0..64u64 {
            assert!(
                s.cclf_jitter_us(h, slot_us, e, long) <= slot_us / 2,
                "the half-slot cap must still hold for long frames"
            );
        }

        // Backlog may not squeeze contenders below the separation the window exists to provide —
        // the failure the old flat ÷16 would now cause: 250µs × 8 ÷ 16 = 125µs, half an airtime,
        // where neither claimant can hear the other before transmitting.
        for _ in 0..8 {
            s.note_deferred(h);
        }
        let band = (airtime * CCLF_SPREAD) >> 4;
        assert!(
            band < airtime * 2,
            "fixture check: a flat ÷16 really would collapse this window below the detection time"
        );
        let mut spread = std::collections::HashSet::new();
        for e in 0..256u64 {
            spread.insert(s.cclf_jitter_us(h, slot_us, e, airtime) / airtime);
        }
        assert!(
            spread.len() >= 2,
            "even fully backlogged, the draws must still span more than one detection time \
             ({spread:?}) — otherwise backlogged claimants collide instead of ordering"
        );
    }

    /// **A waiting frame must re-contend at every slot boundary** — the fourth suppressor, and the
    /// one that dominated the other three (measured on air 2026-08-11).
    ///
    /// The wait loop used to sleep `wait_us`, the entire gap to the owned slot. A frame therefore got
    /// exactly ONE claim evaluation, against whichever slot happened to be current when it entered
    /// the gate — and then slept past every idle slot between there and its own. With a serialized
    /// sender the evaluated slot was always the one immediately after ours, never the neighbour's
    /// four slots away, which was the only slot we had presence evidence for.
    ///
    /// That also resolves the 2026-08-10 pair of measurements: `CLAIM_UNKNOWN` made the *first*
    /// evaluation always succeed (any slot will do), so the machinery showed 4×, while the
    /// evidence-gated claim — needing one particular slot — never got to look at it.
    ///
    /// The assertion is on the seam, not on throughput: how many times the frame contended. Real
    /// time, deliberately; the gate reads the wall clock, so a paused-clock test would spin.
    #[tokio::test]
    async fn a_waiting_frame_contends_for_every_slot_it_passes() {
        let s = mk_claim_sched_slots("8:5000"); // 40 ms superframe — a few boundaries, quickly
        let slot = *s.slot.as_ref().unwrap();

        // Pick a name whose slot is FAR from the current one, so the frame really has to wait and
        // will pass several claimable slots on the way. Chosen after reading the clock, because
        // which slot is current is not ours to decide.
        let target = (slot.current_slot(s.now_us()) + 4) % slot.slots();
        let wire = (0..2000)
            .map(|i| data_wire(&[format!("n{i}").as_bytes()]))
            .find(|w| {
                let h = s.medium_keyed(s.name_group_hash(w).unwrap());
                slot.owner_slot(h) == target
            })
            .expect("some name in 2000 lands on the target slot");

        // No evidence anywhere and claim_unknown off ⇒ every contention *loses*. That is the point:
        // the test measures whether the frame gets to contend at all, not whether it wins, so a win
        // cannot end the wait early and flatter the count.
        s.gate(&wire).await;

        let (attempts, wins) = s.claim_counts();
        assert_eq!(wins, 0, "fixture check: with no presence evidence nothing may be claimed");
        assert!(
            attempts >= 3,
            "a frame waiting ~4 slots must contend for each one it passes; it contended {attempts} \
             time(s). The old single sleep to the owned slot gave exactly 1, which is why an \
             evidence-gated claim could never reach the one slot it had evidence for."
        );
    }

    /// A claimable scheduler on an arbitrary `slots:slot_us` spec.
    fn mk_claim_sched_slots(spec: &str) -> FaceScheduler {
        let mut s = mk_claim_sched();
        s.slot = parse_slot(spec);
        s
    }

    /// A Data frame carrying `comps` as its name — what a neighbour of that group puts on air.
    fn data_wire(comps: &[&[u8]]) -> Vec<u8> {
        let mut name = Vec::new();
        for c in comps {
            name.push(0x08);
            name.push(c.len() as u8);
            name.extend_from_slice(c);
        }
        let mut tlv = vec![0x07, name.len() as u8];
        tlv.extend_from_slice(&name);
        let mut d = vec![0x06, tlv.len() as u8];
        d.extend_from_slice(&tlv);
        d
    }

    /// A claimable scheduler with an 8x3ms superframe — the shape the claim tests need.
    fn mk_claim_sched() -> FaceScheduler {
        FaceScheduler {
            slot: parse_slot("8:3000"),
            hop: None,
            group_depth: 1,
            clock_source: ClockSource::Wall,
            knobs: None,
            bw: crate::Bandwidth::default(),
            current_ch: super::AtomicU8::new(36),
            hw: super::Mutex::new(RadioHwClock::realtek()),
            cv: super::Mutex::new(RadioHwClock::common_view()),
            cv_hw: super::Mutex::new(None),
            master: false,
            net: super::Mutex::new(ndn_time::NetworkTime::new(u64::MAX)),
            claimable: true,
            last_domain_rx: super::AtomicU64::new(0),
            ambient_rx: super::AtomicU64::new(0),
            claim_attempts: super::AtomicU64::new(0),
            claim_wins: super::AtomicU64::new(0),
            heard_by_slot: (0..8).map(|_| super::AtomicU64::new(0)).collect(),
            deferred_by_slot: (0..8).map(|_| super::AtomicU32::new(0)).collect(),
            hold_slot_start: super::AtomicU64::new(u64::MAX),
            claim_unknown: false,
            rate: None,
            base: super::Instant::now(),
        }
    }

    /// **The CCLF election must read demand** (#95). The claim called itself "the demand-adaptive
    /// form that beats fixed-TDMA" while drawing purely from name and time — so a node holding one
    /// trivial frame contended exactly as hard as one holding a backlog, and the description was
    /// simply untrue of the code beneath it.
    ///
    /// Backlog now scales the draw down. Note this is safe *here* and would not be in `owner_slot`:
    /// the CCLF draw is a randomised backoff (shortest speaks, others overhear and cancel), so
    /// nothing needs to be predicted across nodes, whereas the owner grant must be agreed exactly.
    #[test]
    fn backlog_shortens_the_cclf_draw_but_keeps_an_ordering() {
        let s = mk_claim_sched();
        let h = prefix_hash(&[b"ndn", b"bulk"]);

        let idle_draw = s.cclf_jitter_us(h, 3000, 7, 200);
        assert!(idle_draw >= 1, "a draw is never zero — zero is a collision, not an ordering");

        // Each deferral is a frame that wanted the medium and did not get it.
        let mut prev = idle_draw;
        for _ in 0..4 {
            s.note_deferred(h);
            let d = s.cclf_jitter_us(h, 3000, 7, 200);
            assert!(d <= prev, "backlog must not lengthen the wait: {d} > {prev}");
            prev = d;
        }
        assert!(
            prev < idle_draw,
            "a backlogged group must draw shorter than an idle one ({prev} vs {idle_draw})"
        );
        assert!(prev >= 1, "and still keep a floor, or contenders collide instead of ordering");

        // Getting a turn spends the backlog — otherwise one busy burst would win forever, which is
        // the starvation #87 just removed, reintroduced through a different door.
        s.note_sent(h);
        assert_eq!(
            s.cclf_jitter_us(h, 3000, 7, 200),
            idle_draw,
            "after transmitting, the group contends as an idle one again"
        );

        // Demand is per name-group, not per node: a busy group must not lend its urgency to a quiet
        // one that happens to share the radio.
        let other = prefix_hash(&[b"ndn", b"quiet"]);
        let before = s.cclf_jitter_us(other, 3000, 7, 200);
        for _ in 0..4 {
            s.note_deferred(h);
        }
        assert_eq!(
            s.cclf_jitter_us(other, 3000, 7, 200),
            before,
            "one group's backlog must not shorten another group's draw"
        );
    }

    /// **A won slot buys more than one frame, and is surrendered when the owner speaks** (#95).
    ///
    /// The claim used to `return` and the next frame re-entered the election from scratch, so a burst
    /// could not use the slot it had just won. Holding fixes that — but holding is only legitimate
    /// under the owner-return contract: the instant anything is overheard in the slot, the hold ends.
    /// Without that rule, holding a claimed slot is indistinguishable from stealing it.
    ///
    /// Asserts on `hold_status`, the function the gate actually branches on. A first draft of this
    /// test set the atomics and then asserted on comparisons *it had written itself* — it passed
    /// happily with the yield removed, which makes it a description, not a test.
    #[test]
    fn a_claim_holds_the_slot_until_the_owner_speaks() {
        let s = mk_claim_sched();
        let slot = s.slot.as_ref().unwrap().clone();
        let start = 30_000u64;
        let air = wifi_airtime_us(200, Some(7));

        // No claim yet ⇒ nothing to continue.
        assert_eq!(s.hold_status(&slot, start, start + 10, air), HoldStatus::None);

        // Win the slot.
        s.hold_slot_start.store(start, super::Ordering::Relaxed);
        s.last_domain_rx.store(start - 5, super::Ordering::Relaxed); // last heard BEFORE this slot began
        assert_eq!(
            s.hold_status(&slot, start, start + 10, air),
            HoldStatus::Continue,
            "held, silent, room left ⇒ the burst continues without re-contending"
        );

        // **Owner-return contract**: anything overheard inside the slot ends the hold at once.
        s.last_domain_rx.store(start + 100, super::Ordering::Relaxed);
        assert_eq!(
            s.hold_status(&slot, start, start + 150, air),
            HoldStatus::Ended,
            "the owner spoke ⇒ the guest yields; holding through this would be theft"
        );

        // Room runs out: the hold also ends at the slot boundary, so a held slot cannot overrun into
        // the next owner's turn any more than an owned one can (#84).
        s.last_domain_rx.store(start - 5, super::Ordering::Relaxed);
        let late = start + slot.slot_us() - 1;
        assert_eq!(
            s.hold_status(&slot, start, late, air),
            HoldStatus::Ended,
            "no room for the frame ⇒ stop, do not transmit across the boundary"
        );

        // A hold never carries into a later slot — the check is equality with THIS slot's start.
        let next = start + slot.slot_us();
        assert_eq!(
            s.hold_status(&slot, next, next + 10, air),
            HoldStatus::None,
            "winning one slot does not grant the next"
        );
    }

}
