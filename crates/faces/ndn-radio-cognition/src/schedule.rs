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
        Self { slot_us: slot_us.max(1), slots: slots.max(1) }
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
