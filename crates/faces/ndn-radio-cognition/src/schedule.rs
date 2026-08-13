//! The **temporal + frequency** half of the named-data MAC, actuated: WHEN and on WHICH channel a
//! name may transmit, computed from `(name, common-view epoch)` — the data-centric time-slice MAC
//! (#61) and name-keyed FHSS (#40). Both were validated in sim (`ndn-sim/examples/token_schedule.rs`,
//! `fhss_rendezvous.rs`) and gated on hardware common-view time (#41), which has now landed as the
//! shared `ndn_time::RadioHwClock`. This module is the pure decision logic; the face gates its TX
//! choke point on it, reading the epoch from the disciplined hardware clock.
//!
//! Everything here keys on the name-group's [`prefix_hash`](crate::prefix_hash) — the *one* shared
//! keyspace (§44) that already keys demand, the sense bus, and the consistency digest — so a slot /
//! channel is a pure function of `(name, clock)` with **no coordinator, no host identity, no announced
//! schedule** (doctrine §5). Every node holding the name computes the same answer.
//!
//! The two axes compose: a name owns `(slot, channel)` — the [`SlotSchedule`] grants the medium in
//! time, the [`HopSchedule`] picks the carrier, both from the same name + clock. The within-slot
//! election (several nodes holding one name's data) is CCLF ([`crate::coop`]), not part of this
//! computed grant.

/// A name-owned time-slice schedule over a common-view clock (the #61 time-slice MAC).
///
/// Airtime is divided into `slots` slots of `slot_us` each; slot `k` of every superframe is **owned**
/// by the names whose `prefix_hash % slots == k`. An owner transmits in its slot collision-free. The
/// slot is *claimable* — if the owner is idle, the face may open it to a CCLF election among other
/// pending names (`token_schedule.rs` measured this demand-adaptive form as the upper envelope of both
/// fixed-TDMA and pure CCLF); this type computes ownership, the face decides the claim.
///
/// The hard dependency is clock accuracy: slots are collision-free only if nodes agree on `epoch(t)`.
/// On a µs-airtime radio the slot is µs-wide, so it needs the µs-class hardware TSF (#41) — a coarse
/// software clock makes slotting *worse* than uncoordinated contention (`time_slice_mac.rs`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlotSchedule {
    slot_us: u64,
    slots: u64,
    /// **Reserved-lane stride** (#93): every `reserved_stride`-th slot is a reserved lane, usable
    /// only by [`LeaseClass::Latency`] names. `0` = no reserved lanes, which is exactly the
    /// behaviour every on-air result so far was measured under — so the lease generalises the
    /// measured design rather than replacing it.
    reserved_stride: u64,
}

/// **What a name's traffic needs from the medium** (#93) — the class term of a named airtime lease.
///
/// A lease is `(name, class, L base slots)`. Today's fixed slot is exactly `(reserved, L=1)`, which
/// is why this generalises the measured MAC instead of superseding it.
///
/// **Why only two classes here.** The design called for three — latency-critical, urgent-bulk, and
/// bulk, with urgent-bulk preempting bulk. Latency vs bulk is *derivable*: reserved lanes are a pure
/// function of the slot index, so every node computes the same map and a bulk holder simply never
/// takes a reserved lane — no signalling at all. Urgent-bulk vs bulk is not: both live in open
/// slots, so a bulk holder would have to learn the class of a frame it overheard, and there is
/// currently no channel for that. The design assumed the 802.11 Duration/NAV field would carry the
/// lease for free; **#96 measured that stock 802.11 ignores our NAV**, which removes that channel
/// and with it the free announcement the third class depended on.
///
/// The remaining candidate is Tier-0: `addr1‖addr2` already carries the name's prefix-set filter, so
/// a reserved class prefix could be tested by any receiver at zero extra frame bits. That is the
/// path to the third class; it is not implemented, and inventing a class that nothing can observe
/// would be another decided-but-unactuated field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LeaseClass {
    /// Reserved lane, `L = 1`, never preempted and never preempting. Alarms, control, time beacons —
    /// anything whose access delay must stay bounded no matter how much bulk traffic is queued.
    Latency,
    /// Open slots, `L` up to the lease maximum, yields at any base-slot boundary. Bulk transfer.
    Bulk,
}

/// **On-air time for one 802.11 frame**, microseconds — payload bits at the PHY rate, plus the
/// fixed per-frame overhead a slot must also cover.
///
/// Deliberately an over-estimate. It is used to decide whether a frame fits in the remaining slot
/// (`SlotSchedule::fits_now`), and the two errors are not symmetric: under-estimating lets a frame
/// bleed into the next owner's slot — a collision charged to someone else's name — while
/// over-estimating only defers our own transmission by one slot. `PREAMBLE_US` covers the PHY
/// preamble + PLCP header + SIFS-ish inter-frame slack rather than modelling each exactly; the
/// figure is a bound, not a measurement, and is marked as such because nothing here has been checked
/// against a spectrum capture.
///
/// `mcs` is the HT index; `None` assumes the conservative broadcast rate, which is the slowest thing
/// we transmit and therefore the safe assumption when the rate is not yet resolved.
pub fn wifi_airtime_us(bytes: usize, mcs: Option<u8>) -> u64 {
    /// Preamble + PLCP + inter-frame slack. HT-mixed is ~36-40 µs; 60 keeps margin.
    const PREAMBLE_US: u64 = 60;
    let rate_bps = u64::from(ndn_radio_hal::mcs_phy_rate_bps(
        mcs.unwrap_or(ndn_radio_hal::McsDescriptor::CONSERVATIVE.index),
    ))
    .max(1);
    let bits = (bytes as u64).saturating_mul(8);
    // Round up: a partial microsecond of airtime still occupies the medium.
    PREAMBLE_US + bits.saturating_mul(1_000_000).div_ceil(rate_bps)
}

impl SlotSchedule {
    /// A schedule of `slots` slots, each `slot_us` microseconds wide. `slot_us` should contain one
    /// frame's on-air time plus a guard band (sized from the PHY airtime + the clock's residual
    /// jitter); `slots` is the superframe length (the per-name access period). Both are clamped to ≥1.
    pub fn new(slot_us: u64, slots: u64) -> Self {
        Self { slot_us: slot_us.max(1), slots: slots.max(1), reserved_stride: 0 }
    }

    /// **Reserve every `stride`-th slot as a latency lane** (#93). `0` (the default) reserves
    /// nothing and reproduces the schedule every on-air result was measured under.
    ///
    /// Clamped so at least one open slot always remains: a schedule with no open slots would starve
    /// bulk traffic completely, and a stride of 1 asks for exactly that.
    pub fn with_reserved_stride(mut self, stride: u64) -> Self {
        self.reserved_stride = if stride < 2 { 0 } else { stride };
        self
    }

    /// **Is slot `k` a reserved latency lane?** A pure function of the index, so every node computes
    /// the same map with no announcement — which is what lets a bulk holder skip reserved lanes it
    /// was never told about. That property is the whole reason the lease needs no signalling, and it
    /// is the same property that makes the computed token work.
    pub fn is_reserved(&self, slot_idx: u64) -> bool {
        self.reserved_stride >= 2 && slot_idx % self.reserved_stride == 0
    }

    /// How many slots per superframe are reserved lanes.
    pub fn reserved_slots(&self) -> u64 {
        if self.reserved_stride < 2 { 0 } else { self.slots.div_ceil(self.reserved_stride) }
    }

    /// How many slots per superframe are open to bulk leases.
    pub fn open_slots(&self) -> u64 {
        self.slots - self.reserved_slots()
    }

    /// **Which slot does this name own, in its class?** (#93)
    ///
    /// A `Latency` name is placed among the *reserved* lanes and a `Bulk` name among the *open*
    /// slots, so the two classes cannot collide by construction — rather than by anyone yielding.
    /// With no reserved lanes configured this is exactly `owner_slot`, so the generalisation is
    /// behaviour-preserving at the default.
    pub fn owner_slot_in(&self, prefix_hash: u64, class: LeaseClass) -> u64 {
        if self.reserved_stride < 2 {
            return self.owner_slot(prefix_hash);
        }
        match class {
            LeaseClass::Latency => {
                let n = self.reserved_slots().max(1);
                (prefix_hash % n) * self.reserved_stride
            }
            LeaseClass::Bulk => {
                let n = self.open_slots().max(1);
                // Walk the open slots in order and take the nth — the reserved lanes are punched out
                // of the index space, so a bulk name can never land on one.
                let mut nth = prefix_hash % n;
                for k in 0..self.slots {
                    if !self.is_reserved(k) {
                        if nth == 0 {
                            return k;
                        }
                        nth -= 1;
                    }
                }
                self.slots - 1
            }
        }
    }

    /// Class-aware [`owns_now`](Self::owns_now): does `prefix_hash`'s **class-placed** slot
    /// contain `now_us`? Identical to `owns_now` when no lanes are reserved.
    pub fn owns_now_in(&self, prefix_hash: u64, class: LeaseClass, now_us: u64) -> bool {
        self.current_slot(now_us) == self.owner_slot_in(prefix_hash, class)
    }

    /// Class-aware [`wait_us`](Self::wait_us): µs until `prefix_hash`'s class-placed slot next
    /// begins (0 if inside it now). Identical to `wait_us` when no lanes are reserved.
    pub fn wait_us_in(&self, prefix_hash: u64, class: LeaseClass, now_us: u64) -> u64 {
        let target = self.owner_slot_in(prefix_hash, class);
        let cur = self.current_slot(now_us);
        if cur == target {
            return 0;
        }
        let ahead = (target + self.slots - cur) % self.slots;
        ahead * self.slot_us - (now_us % self.slot_us)
    }

    /// **How many consecutive base slots may this class hold?** (#93)
    ///
    /// `Latency` is always 1: a reserved lane exists to bound someone else's access delay, so
    /// holding it longer would defeat the thing it is for. `Bulk` may hold `l_max`, but only across
    /// *open* slots and only until a boundary check says otherwise — the lease is a sequence of base
    /// slots, not one burst, and the boundary between them is where the holder is off-air and can be
    /// preempted. Half-duplex forces that gap anyway; the lease spends it.
    pub fn lease_slots(&self, class: LeaseClass, l_max: u64) -> u64 {
        match class {
            LeaseClass::Latency => 1,
            LeaseClass::Bulk => l_max.max(1),
        }
    }

    /// **The deadline of a lease taken at `now_us`** — the end of the last base slot it covers,
    /// stopping early at the first reserved lane.
    ///
    /// Stopping at the reserved lane is the self-enforcement #96 forced on this design. The lease was
    /// meant to be announced in the 802.11 Duration/NAV field, which stock hardware turns out to
    /// ignore, so nothing external will hold the medium for us and nothing external will tell us to
    /// stop. Both ends are computed instead: we take only what the shared map says is ours to take.
    pub fn lease_deadline_us(&self, now_us: u64, class: LeaseClass, l_max: u64) -> u64 {
        let start = self.slot_start_us(now_us);
        let first = self.current_slot(now_us);
        let want = self.lease_slots(class, l_max);
        let mut held = 1;
        while held < want {
            let next = (first + held) % self.slots;
            if self.is_reserved(next) {
                break; // never squat a latency lane, even mid-lease
            }
            held += 1;
        }
        start + held * self.slot_us
    }

    /// Size a slot from the PHY **airtime** plus a **guard band**, over `slots` slots. The guard only
    /// has to cover the common-view clock's alignment jitter (plus a little slack) — so once nodes share
    /// a **sub-µs hardware clock** (#74, ~0.5 µs) the guard can be a few µs, not the milliseconds a
    /// software clock forced. `slot_us = airtime_us + guard_us`. This is what lets the token grant run at
    /// µs granularity: more slots fit a superframe, and the per-name access latency drops accordingly.
    pub fn from_airtime(airtime_us: u64, guard_us: u64, slots: u64) -> Self {
        Self::new(airtime_us + guard_us, slots)
    }

    /// **Does a frame of `airtime_us` still fit in the slot live at `now_us`?**
    ///
    /// The question the owner path never asked (#84). Owning the slot *now* is not the same as
    /// having room to transmit in it: a frame launched near the boundary keeps radiating into the
    /// next owner's slot, which is precisely the collision a slot MAC exists to prevent — and the
    /// damage lands on a *different* name's turn, so the node causing it never sees the loss.
    ///
    /// `slot_us` is meant to be `airtime + guard` ([`from_airtime`](Self::from_airtime)), so under a
    /// correctly-sized schedule a frame that starts at the slot boundary always fits; this guards
    /// the case where it does not — an oversized frame, or a slot sized by hand from an env var
    /// rather than from the airtime (#85).
    pub fn fits_now(&self, now_us: u64, airtime_us: u64) -> bool {
        self.slot_remaining_us(now_us) >= airtime_us
    }

    /// The start of the slot live at `now_us` (µs) — the slot-boundary flooring of `now`. Used to ask
    /// "has anything been heard *since this slot began*?" for the claimable (owner-idle) decision.
    pub fn slot_start_us(&self, now_us: u64) -> u64 {
        self.epoch(now_us) * self.slot_us
    }

    /// Microseconds left in the slot live at `now_us`.
    pub fn slot_remaining_us(&self, now_us: u64) -> u64 {
        self.slot_us - (now_us % self.slot_us)
    }

    /// The common-view epoch (slot index since the clock origin) at `now_us`.
    pub fn epoch(&self, now_us: u64) -> u64 {
        now_us / self.slot_us
    }

    /// The slot index (0..slots) this name owns — `prefix_hash % slots`.
    pub fn owner_slot(&self, prefix_hash: u64) -> u64 {
        prefix_hash % self.slots
    }

    /// The slot index the superframe is currently in at `now_us`.
    pub fn current_slot(&self, now_us: u64) -> u64 {
        self.epoch(now_us) % self.slots
    }

    /// Whether this name owns the slot live at `now_us` (⇒ transmit now, collision-free).
    pub fn owns_now(&self, prefix_hash: u64, now_us: u64) -> bool {
        self.owner_slot(prefix_hash) == self.current_slot(now_us)
    }

    /// Microseconds to wait until this name's next owned slot **starts**. `0` ⇒ it owns the current
    /// slot; transmit now. Otherwise the delay to the boundary of its next slot — the gate the face
    /// applies before injecting (the collision-free grant, realized).
    pub fn wait_us(&self, prefix_hash: u64, now_us: u64) -> u64 {
        let cur_epoch = self.epoch(now_us);
        let cur_slot = cur_epoch % self.slots;
        let owner = self.owner_slot(prefix_hash);
        if owner == cur_slot {
            return 0;
        }
        // Slots ahead until the owner slot comes round again (1..slots), then the µs to that boundary.
        let ahead = (owner + self.slots - cur_slot) % self.slots;
        let target_epoch = cur_epoch + ahead;
        target_epoch * self.slot_us - now_us
    }

    /// The superframe length in microseconds — the worst-case wait between a name's turns.
    pub fn superframe_us(&self) -> u64 {
        self.slot_us * self.slots
    }

    /// The number of slots per superframe (the per-name access period, in slots).
    pub fn slots(&self) -> u64 {
        self.slots
    }

    /// The width of one slot, in microseconds.
    pub fn slot_us(&self) -> u64 {
        self.slot_us
    }
}

/// A name-keyed frequency-hopping schedule (#40): the carrier a name uses at epoch `e` is
/// `classes[(prefix_hash + e) % C]` — a name-shifted walk over a set of **separated** (non-adjacent)
/// channel classes (#66's channel classes, so adjacent-channel leakage doesn't couple two flows).
///
/// Computable by anyone holding the name + the shared epoch clock, identical for every node that cares
/// about the name — the rendezvous is implicit, never negotiated. The payoff over the static
/// `channel = H(name)` hash: a persistent single-channel jammer that would kill a flow statically
/// hashed onto it only catches a hopping flow `1/C` of the time (`fhss_rendezvous.rs`). Like the slot
/// schedule, it needs common-view time so a listener knows *when* to sit on the name's channel — which
/// is why `DataPlaneConfig.hop` stayed off until #41 landed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HopSchedule {
    classes: Vec<u8>,
    dwell_us: u64,
}

impl HopSchedule {
    /// A hop schedule over `classes` (the separated channel set), dwelling `dwell_us` per hop. Falls
    /// back to a single fixed channel `[0]` if `classes` is empty; `dwell_us` clamped to ≥1.
    pub fn new(classes: Vec<u8>, dwell_us: u64) -> Self {
        let classes = if classes.is_empty() { vec![0] } else { classes };
        Self { classes, dwell_us: dwell_us.max(1) }
    }

    /// How long this schedule sits on each channel (µs) — read by
    /// `FaceScheduler::vet_hop` to cost the hop against the radio's measured retune time.
    pub fn dwell_us(&self) -> u64 {
        self.dwell_us
    }

    /// The common-view hop epoch at `now_us`.
    pub fn epoch(&self, now_us: u64) -> u64 {
        now_us / self.dwell_us
    }

    /// The channel this name sits on at `now_us` — `classes[(prefix_hash + epoch) % C]`.
    pub fn channel(&self, prefix_hash: u64, now_us: u64) -> u8 {
        let idx = prefix_hash.wrapping_add(self.epoch(now_us)) % self.classes.len() as u64;
        self.classes[idx as usize]
    }

    /// Microseconds until the next hop boundary (when the channel may change) — for scheduling the
    /// retune so a node arrives on the new channel in lockstep with everyone tracking the name.
    pub fn dwell_remaining_us(&self, now_us: u64) -> u64 {
        self.dwell_us - (now_us % self.dwell_us)
    }

    /// The separated channel classes this schedule hops over.
    pub fn classes(&self) -> &[u8] {
        &self.classes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prefix_hash;

    #[test]
    fn owner_is_a_pure_function_of_name() {
        let s = SlotSchedule::new(500, 8);
        let a = prefix_hash(&[b"ndn", b"alarm"]);
        let b = prefix_hash(&[b"ndn", b"bulk"]);
        // Same name → same owner slot from any node, any time. Different names → (usually) different.
        assert_eq!(s.owner_slot(a), s.owner_slot(a));
        assert!(s.owner_slot(a) < 8 && s.owner_slot(b) < 8);
    }

    #[test]
    fn owns_its_slot_and_waits_out_the_others() {
        let s = SlotSchedule::new(500, 4);
        let h = 0u64; // owns slot 0
        assert_eq!(s.owner_slot(h), 0);
        // At the very start of slot 0 (epoch 0), it owns now → wait 0.
        assert!(s.owns_now(h, 0));
        assert_eq!(s.wait_us(h, 0), 0);
        // Midway through slot 1 (epoch 1, now = 500..1000): not its slot; wait to slot 0 of the next
        // superframe = epoch 4 boundary = 2000 µs. now = 700 → 1300 µs.
        assert!(!s.owns_now(h, 700));
        assert_eq!(s.current_slot(700), 1);
        assert_eq!(s.wait_us(h, 700), 2000 - 700);
    }

    #[test]
    fn wait_lands_exactly_on_a_slot_boundary() {
        let s = SlotSchedule::new(500, 4);
        for h in 0..4u64 {
            for now in [0u64, 123, 700, 1999, 5001] {
                let w = s.wait_us(h, now);
                if w > 0 {
                    let arrival = now + w;
                    assert_eq!(arrival % 500, 0, "arrival not on a slot boundary");
                    assert_eq!(s.current_slot(arrival), s.owner_slot(h), "arrived in the wrong slot");
                }
            }
        }
    }

    #[test]
    fn us_slot_sizing_and_boundaries() {
        // A µs-scale slot now that the clock is sub-µs: airtime 150 µs + 6 µs guard, 16 slots.
        let s = SlotSchedule::from_airtime(150, 6, 16);
        assert_eq!(s.slot_us(), 156);
        assert_eq!(s.superframe_us(), 156 * 16);
        // slot_start floors to the slot boundary; remaining counts down to the next.
        let now = 156 * 3 + 40; // 40 µs into slot-epoch 3
        assert_eq!(s.slot_start_us(now), 156 * 3);
        assert_eq!(s.slot_remaining_us(now), 156 - 40);
        assert_eq!(s.slot_remaining_us(156 * 3), 156); // exactly on a boundary
    }

    #[test]
    fn hop_visits_every_class_and_is_shared() {
        let s = HopSchedule::new(vec![0, 2, 4, 6], 120);
        let h = prefix_hash(&[b"ndn", b"video"]);
        // Over C consecutive epochs the name visits all C separated classes (a full walk).
        let mut seen: Vec<u8> = (0..4).map(|e| s.channel(h, e * 120)).collect();
        seen.sort_unstable();
        assert_eq!(seen, vec![0, 2, 4, 6]);
        // Deterministic: the same (name, time) → the same channel for every node.
        assert_eq!(s.channel(h, 360), s.channel(h, 360));
    }

    #[test]
    fn dwell_remaining_counts_down_to_the_hop() {
        let s = HopSchedule::new(vec![0, 2, 4, 6], 120);
        assert_eq!(s.dwell_remaining_us(0), 120);
        assert_eq!(s.dwell_remaining_us(40), 80);
        assert_eq!(s.dwell_remaining_us(119), 1);
    }

    #[test]
    fn empty_classes_falls_back_to_one_channel() {
        let s = HopSchedule::new(vec![], 120);
        assert_eq!(s.channel(12345, 0), 0);
        assert_eq!(s.classes(), &[0]);
    }

    /// **A frame must not be launched across a slot boundary** (#84) — the property `fits_now`
    /// exists to enforce, stated on the numbers rather than on the call site.
    ///
    /// Owning the slot *now* was the whole of the old owner-path check, so a frame starting near the
    /// boundary kept radiating into the next owner's turn. The collision then lands on a different
    /// name's slot, which is why nothing observed it: the node causing the damage sees a clean
    /// transmit, and the victim sees loss it cannot attribute.
    #[test]
    fn a_frame_only_fits_while_the_slot_has_room_for_it() {
        // 3 ms slots, 8 of them.
        let s = SlotSchedule::new(3_000, 8);
        let airtime = wifi_airtime_us(1500, Some(7)); // ~245 µs at MCS7

        // Start of a slot: plenty of room.
        assert!(s.fits_now(0, airtime));
        assert!(s.fits_now(3_000, airtime), "and at the next boundary");
        // Comfortably inside.
        assert!(s.fits_now(1_000, airtime));
        // Too late in the slot: the frame would run past the boundary.
        assert!(
            !s.fits_now(3_000 - 10, airtime),
            "10 µs left cannot hold a {airtime} µs frame"
        );
        // The exact edge: remaining == airtime still fits, one µs less does not.
        let edge = 3_000 - airtime;
        assert!(s.fits_now(edge, airtime), "remaining == airtime is a fit");
        assert!(!s.fits_now(edge + 1, airtime), "one µs short is not");
    }

    /// The airtime estimate must scale the right way and stay conservative.
    #[test]
    fn airtime_scales_with_size_and_rate_and_errs_high() {
        let big = wifi_airtime_us(1500, Some(7));
        let small = wifi_airtime_us(100, Some(7));
        assert!(big > small, "more bytes, more airtime");

        let slow = wifi_airtime_us(1500, Some(0));
        assert!(slow > big, "a slower MCS holds the medium longer");

        // `None` must assume the conservative rate — the slow, safe end. Guessing fast here would
        // under-estimate airtime, and under-estimating is the error that overruns someone else's
        // slot; over-estimating only defers us.
        assert_eq!(wifi_airtime_us(1500, None), wifi_airtime_us(1500, Some(1)));
        assert!(wifi_airtime_us(1500, None) > big);

        // Never zero, even for an empty frame: the preamble still occupies the medium.
        assert!(wifi_airtime_us(0, Some(7)) > 0);
    }


    /// **A second radio must buy additional turns, not parallel copies of one turn** (#89).
    ///
    /// `owner_slot` is `hash % slots` with no medium term, so every bearer ran the identical
    /// schedule: name N owned slot k on *every* radio at the same instant. The per-name access
    /// latency — the thing a slot MAC actually costs you — did not improve with radio count at all.
    /// The face fixes this by folding the channel into the hash before consulting the schedule; this
    /// asserts the property that makes it worth doing.
    #[test]
    fn keying_the_hash_to_the_medium_staggers_the_schedule() {
        const SLOTS: u64 = 8;
        let s = SlotSchedule::new(3_000, SLOTS);
        // The face's key: `hash ^ channel * K`.
        let keyed = |h: u64, ch: u8| h ^ u64::from(ch).wrapping_mul(0x9E37_79B9);

        let names: Vec<u64> = (0..64u64).map(|i| i.wrapping_mul(0x9E37_79B9_7F4A_7C15)).collect();

        // Same medium ⇒ identical schedule on every bearer: two radios on one channel are ONE
        // medium and must not both think they own it independently.
        for n in &names {
            assert_eq!(
                s.owner_slot(keyed(*n, 36)),
                s.owner_slot(keyed(*n, 36)),
                "one channel, one schedule"
            );
        }

        // Different media ⇒ the assignment moves for most names, so at a given instant the two
        // channels are serving different names concurrently.
        let moved = names
            .iter()
            .filter(|n| s.owner_slot(keyed(**n, 36)) != s.owner_slot(keyed(**n, 149)))
            .count();
        assert!(
            moved > names.len() / 2,
            "the medium key must actually restagger; only {moved}/{} names moved slot",
            names.len()
        );

        // And the concurrency that buys: for each slot index, the set of names owning it on ch36
        // differs from the set owning it on ch149 — otherwise the second radio is redundant.
        let owners = |ch: u8, k: u64| {
            names.iter().filter(|n| s.owner_slot(keyed(**n, ch)) == k).count()
        };
        let differing = (0..SLOTS).filter(|k| owners(36, *k) != owners(149, *k) ||
            names.iter().any(|n| (s.owner_slot(keyed(*n, 36)) == *k) != (s.owner_slot(keyed(*n, 149)) == *k))).count();
        assert!(
            differing >= SLOTS as usize - 1,
            "nearly every slot should serve a different name set per medium, got {differing}/{SLOTS}"
        );
    }

}

/// **The named airtime lease** (#93) — the properties the design rests on, tested rather than argued.
#[cfg(test)]
mod lease_tests {
    use super::*;

    /// **The property the whole primitive exists for**: a latency name's access delay is bounded by
    /// the superframe *no matter how much bulk traffic is queued*, because a bulk lease can never
    /// occupy a reserved lane. Not by yielding, not by preemption — by construction, since the two
    /// classes are placed in disjoint slot sets that every node computes identically.
    #[test]
    fn a_bulk_lease_can_never_occupy_a_latency_lane() {
        let s = SlotSchedule::new(1000, 8).with_reserved_stride(4); // lanes 0 and 4
        assert_eq!(s.reserved_slots(), 2);
        assert_eq!(s.open_slots(), 6);
        assert!(s.is_reserved(0) && s.is_reserved(4));
        assert!(!s.is_reserved(1) && !s.is_reserved(7));

        // No bulk name, for any hash, lands on a reserved lane.
        for h in 0..2_000u64 {
            let slot = s.owner_slot_in(h, LeaseClass::Bulk);
            assert!(!s.is_reserved(slot), "bulk name {h} landed on reserved lane {slot}");
        }
        // Every latency name lands on one.
        for h in 0..2_000u64 {
            let slot = s.owner_slot_in(h, LeaseClass::Latency);
            assert!(s.is_reserved(slot), "latency name {h} landed on open slot {slot}");
        }
    }

    /// A lease is a *sequence* of base slots and it stops at the first reserved lane — even
    /// mid-lease. This is the self-enforcement #96 forced: stock 802.11 ignores the Duration/NAV
    /// field, so nothing external holds the medium for us and nothing external tells us to stop.
    /// Both ends are computed from the shared map instead.
    #[test]
    fn a_lease_stops_at_the_next_reserved_lane() {
        let s = SlotSchedule::new(1000, 8).with_reserved_stride(4); // lanes 0, 4

        // Starting in slot 1 with L=8 requested: slots 1,2,3 are open, 4 is reserved -> 3 slots.
        let now = 1 * 1000 + 10; // inside slot 1
        assert_eq!(s.current_slot(now), 1);
        assert_eq!(s.lease_deadline_us(now, LeaseClass::Bulk, 8), 1000 + 3 * 1000);

        // Starting in slot 5: 5,6,7 open, then wraps to 0 which is reserved -> 3 slots.
        let now = 5 * 1000 + 10;
        assert_eq!(s.lease_deadline_us(now, LeaseClass::Bulk, 8), 5000 + 3 * 1000);

        // Latency is always exactly one slot: a reserved lane exists to bound someone else's delay,
        // so holding it longer defeats the thing it is for.
        let now = 4 * 1000 + 10;
        assert_eq!(s.lease_deadline_us(now, LeaseClass::Latency, 8), 4000 + 1000);
    }

    /// **The generalisation must be behaviour-preserving at the default**, or every on-air number
    /// measured so far stops applying to the shipping code. With no reserved lanes a lease of 1 is
    /// exactly today's fixed slot, and class placement collapses to plain `owner_slot`.
    #[test]
    fn with_no_reserved_lanes_this_is_exactly_the_measured_schedule() {
        let s = SlotSchedule::new(20_000, 8); // the on-air schedule, unchanged
        assert_eq!(s.reserved_slots(), 0);
        assert_eq!(s.open_slots(), 8);
        for h in 0..1_000u64 {
            assert_eq!(s.owner_slot_in(h, LeaseClass::Bulk), s.owner_slot(h));
            assert_eq!(s.owner_slot_in(h, LeaseClass::Latency), s.owner_slot(h));
            assert!(!s.is_reserved(s.owner_slot(h)));
        }
        // L=1 reproduces the single-slot hold the +119% claim result was measured with.
        let now = 3 * 20_000 + 5;
        assert_eq!(s.lease_deadline_us(now, LeaseClass::Bulk, 1), 3 * 20_000 + 20_000);
    }

    /// A stride of 1 would reserve every slot and starve bulk entirely; it is clamped to "none".
    #[test]
    fn a_degenerate_stride_cannot_starve_bulk() {
        for stride in [0, 1] {
            let s = SlotSchedule::new(1000, 8).with_reserved_stride(stride);
            assert_eq!(s.reserved_slots(), 0, "stride {stride} must reserve nothing");
            assert_eq!(s.open_slots(), 8);
        }
        // And the smallest real stride still leaves bulk half the medium.
        let s = SlotSchedule::new(1000, 8).with_reserved_stride(2);
        assert_eq!(s.reserved_slots(), 4);
        assert_eq!(s.open_slots(), 4);
    }
}
