//! **The 8-bit ephemeral ID + cooperative deconfliction** — the enabler for the wire-format redesign's
//! 128:8 address partition (`wire-format-spec.md` §4).
//!
//! The Blurred Name redesign narrows the on-air source ID from a 46-bit random nonce to **8 bits**, so
//! the 38 freed address bits go to the prefix-set filter (94 → 126). Eight bits collide often (the
//! birthday bound is ~19 neighbours), so aliases are resolved **cooperatively and beacon-free**, never
//! by width:
//!
//! - **Pick-Free-Slot (PFS)** — on boot/rotation a node picks an ID it has *not* recently overheard.
//!   Cheap, but blind to *hidden* nodes (IDs it cannot hear), so it is only the initial pick.
//! - **Detect-And-Rotate (DAR)** — the workhorse. A **common neighbour** that overhears one ID carrying
//!   two distinct contents within a short window infers an alias and piggybacks a 1-bit collision signal
//!   (`FLAG_ID_COLLISION`, spec §5.4) on data it already sends; a node receiving that signal for its own
//!   ID rotates. No dedicated frame — it rides existing traffic (the control-plane tenet).
//!
//! Two halves live here: [`EphemeralId`] (the allocator — PFS + rotate-on-signal) and [`AliasDetector`]
//! (the observer — decide *when* to emit the collision signal). This module is pure decision logic with
//! no I/O; the medium wires `note_heard`/`note_collision` to the RX path and the detector's verdict to
//! the flags byte.

/// Bits in the on-air ephemeral ID (`addr3[4]`).
pub const ID_BITS: u32 = 8;
/// Size of the ID space (256).
pub const ID_SPACE: usize = 1 << ID_BITS;

/// A node's own ephemeral ID plus the Pick-Free-Slot / Detect-And-Rotate state that keeps it
/// alias-free. Soft state: a residual alias degrades an RSSI estimate or over-counts a neighbour, never
/// a delivery — which is why 8 bits + deconfliction is safe where a durable address would not be.
pub struct EphemeralId {
    id: u8,
    /// Last time (ms) each ID value was overheard on air; `0` = never. An ID heard within `stale_ms` is
    /// considered taken by a neighbour.
    seen: [u64; ID_SPACE],
    stale_ms: u64,
    rng: u64,
}

impl EphemeralId {
    /// A fresh ID, PFS-picked from an empty neighbour view (so effectively random at boot). `boot_seed`
    /// seeds the xorshift picker; `stale_ms` is how long an overheard ID stays "taken".
    pub fn new(boot_seed: u64, stale_ms: u64) -> Self {
        let mut s = Self { id: 0, seen: [0; ID_SPACE], stale_ms: stale_ms.max(1), rng: boot_seed | 1 };
        s.id = s.pick_free(0);
        s
    }

    fn next_rng(&mut self) -> u64 {
        // xorshift64 — deterministic, no std Rng (this crate is sans-IO and sans-rand).
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        self.rng
    }

    /// Pick an ID not currently taken by a fresh neighbour (PFS). Random among the free set; if every
    /// value is fresh (≥256 audible neighbours — pathological), fall back to the *stalest*, which is the
    /// least-recently-heard and so the most likely to have moved on.
    fn pick_free(&mut self, now_ms: u64) -> u8 {
        let mut free_count = 0usize;
        for i in 0..ID_SPACE {
            let t = self.seen[i];
            if t == 0 || now_ms.saturating_sub(t) > self.stale_ms {
                free_count += 1;
            }
        }
        if free_count == 0 {
            // Saturated: take the stalest (smallest last-heard timestamp).
            let mut best = 0u8;
            let mut oldest = u64::MAX;
            for i in 0..ID_SPACE {
                if self.seen[i] < oldest {
                    oldest = self.seen[i];
                    best = i as u8;
                }
            }
            return best;
        }
        // Walk to the r-th free slot (avoids allocating a Vec of frees).
        let mut target = (self.next_rng() as usize) % free_count;
        for i in 0..ID_SPACE {
            let t = self.seen[i];
            if t == 0 || now_ms.saturating_sub(t) > self.stale_ms {
                if target == 0 {
                    return i as u8;
                }
                target -= 1;
            }
        }
        self.id // unreachable given free_count>0, but keep total
    }

    /// This node's current on-air ID.
    pub fn current(&self) -> u8 {
        self.id
    }

    /// Feed an overheard source ID — PFS input. Marks the value taken so a future pick avoids it.
    pub fn note_heard(&mut self, id: u8, now_ms: u64) {
        self.seen[id as usize] = now_ms;
    }

    /// **DAR**: a common neighbour signalled our ID is aliased. Mark it taken and rotate to a free slot.
    /// Returns the new ID.
    pub fn note_collision(&mut self, now_ms: u64) -> u8 {
        self.seen[self.id as usize] = now_ms;
        self.id = self.pick_free(now_ms);
        self.id
    }

    /// Periodic PFS refresh (e.g. on the rotation period) — re-pick from the current neighbour view to
    /// bound linkability and shed a stale alias even without a DAR signal.
    pub fn rotate(&mut self, now_ms: u64) -> u8 {
        self.id = self.pick_free(now_ms);
        self.id
    }
}

/// The observer half of DAR: a node uses this on frames it overhears to decide whether to piggyback a
/// collision signal toward a sender. It flags an **alias** when one ID carries two *different* content
/// fingerprints within a short window — which one node, transmitting its own coherent stream, would not
/// produce. The fingerprint is any cheap per-sender-distinguishing value the medium already has (e.g. the
/// low bits of the frame's prefix filter, or an object-name hash).
pub struct AliasDetector {
    last: [(u64, u64); ID_SPACE], // (fingerprint, ms) per ID
    window_ms: u64,
}

impl AliasDetector {
    /// `window_ms` is how close in time two different-fingerprint frames on one ID must be to read as a
    /// live alias rather than the same node having simply moved on to new content.
    pub fn new(window_ms: u64) -> Self {
        Self { last: [(0, 0); ID_SPACE], window_ms: window_ms.max(1) }
    }

    /// Observe a frame from `id` carrying `fingerprint` at `now_ms`. Returns `true` if this looks like an
    /// alias (same ID, *different* fingerprint, within the window) — the caller should then set
    /// `FLAG_ID_COLLISION` on data it sends so the aliasing senders rotate (DAR).
    pub fn observe(&mut self, id: u8, fingerprint: u64, now_ms: u64) -> bool {
        let (fp, t) = self.last[id as usize];
        let alias = t != 0 && now_ms.saturating_sub(t) <= self.window_ms && fp != fingerprint;
        self.last[id as usize] = (fingerprint, now_ms);
        alias
    }
}

/// Flags byte (`addr3[5]`, wire-format-spec §5.4), LSB first.
pub const FLAG_BODY_PREFIX: u8 = 0b0000_0001;
pub const FLAG_ID_COLLISION: u8 = 0b0000_0010;

/// The whole cooperative-deconfliction unit the medium holds **one of** (shared, per node): the
/// allocator, the alias detector, and the pending DAR hint. The medium calls [`tx_id`](Self::tx_id) on
/// send and [`rx`](Self::rx) on receive — no other wiring.
pub struct IdDeconfliction {
    id: EphemeralId,
    detector: AliasDetector,
    /// A conflicted ID we detected and owe a DAR hint for, delivered on our next data frame.
    pending_hint: Option<u8>,
}

impl IdDeconfliction {
    pub fn new(boot_seed: u64, stale_ms: u64, window_ms: u64) -> Self {
        Self {
            id: EphemeralId::new(boot_seed, stale_ms),
            detector: AliasDetector::new(window_ms),
            pending_hint: None,
        }
    }

    /// `(addr3[4], addr3[5])` for the next TX. A pending DAR hint rides this one frame: `addr3[4]`
    /// carries the **conflicted** ID and `FLAG_ID_COLLISION` is set — sacrificing our own ID
    /// attribution on this frame (soft state) to tell the aliasing senders to rotate.
    pub fn tx_id(&mut self) -> (u8, u8) {
        match self.pending_hint.take() {
            Some(x) => (x, FLAG_ID_COLLISION),
            None => (self.id.current(), 0),
        }
    }

    /// Feed a received Tier-0 frame's ID + flags + RSSI. Runs PFS (`note_heard`), DAR-rotate (on a hint
    /// naming our ID), and DAR-detect (an ID carrying two RSSI fingerprints in the window → queue a
    /// hint). Returns `true` if this was a hint frame (its ID is the conflicted one, not a real
    /// neighbour — the caller must NOT key a neighbour on it).
    pub fn rx(&mut self, id: u8, flags: u8, rssi: Option<i8>, now_ms: u64) -> bool {
        if flags & FLAG_ID_COLLISION != 0 {
            if id == self.id.current() {
                self.id.note_collision(now_ms);
            }
            return true;
        }
        self.id.note_heard(id, now_ms);
        // Two transmitters under one ID ⇒ different RSSI within the window. A coarse ~6 dB bucket is the
        // only sender-distinguishing signal on an identity-free radio; a single fading sender may flip a
        // bucket and cost one spurious rotation (soft).
        if let Some(r) = rssi {
            let fp = (r as i64).div_euclid(6) as u64;
            if self.detector.observe(id, fp, now_ms) {
                self.pending_hint = Some(id);
            }
        }
        false
    }

    pub fn current(&self) -> u8 {
        self.id.current()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pfs_picks_an_id_no_neighbour_is_using() {
        let mut e = EphemeralId::new(0xABCD, 10_000);
        // Fill most of the space as taken; leave exactly one free (value 200).
        for i in 0..ID_SPACE {
            if i != 200 {
                e.note_heard(i as u8, 1_000);
            }
        }
        assert_eq!(e.rotate(1_000), 200, "PFS must pick the one free slot");
    }

    #[test]
    fn dar_rotates_off_a_contended_id() {
        let mut e = EphemeralId::new(0x1234, 10_000);
        let before = e.current();
        // Everyone else is silent, so the only taken value is our own after the signal → we must move.
        let after = e.note_collision(2_000);
        assert_ne!(after, before, "a collision signal must rotate our ID");
        assert_eq!(e.current(), after);
    }

    #[test]
    fn pfs_stays_alias_free_across_a_neighbourhood() {
        // 16 nodes each pick via PFS while overhearing the others' picks in turn — the beacon-free
        // deconfliction should keep them distinct (well under the 8-bit birthday bound of ~19).
        let mut nodes: Vec<EphemeralId> =
            (0..16).map(|i| EphemeralId::new(0x9E37_79B9 ^ (i as u64 * 0x100_0001), 10_000)).collect();
        // Gossip round: each node hears every already-placed node, then re-picks.
        for i in 0..nodes.len() {
            for j in 0..i {
                let heard = nodes[j].current();
                nodes[i].note_heard(heard, 1_000);
            }
            let id = nodes[i].rotate(1_000);
            // No earlier node shares it.
            for j in 0..i {
                assert_ne!(id, nodes[j].current(), "node {i} aliased node {j}");
            }
        }
    }

    #[test]
    fn deconfliction_unit_detects_aliases_and_rotates_on_a_hint() {
        let mut d = IdDeconfliction::new(0xABCD, 10_000, 500);
        // Normal send: our current ID, flags clear.
        let (id0, f0) = d.tx_id();
        assert_eq!(f0, 0);

        // Two transmitters under one ID (id 42) at very different RSSI within the window → an alias is
        // detected and a DAR hint is queued.
        assert!(!d.rx(42, 0, Some(-40), 1_000));
        assert!(!d.rx(42, 0, Some(-80), 1_050));
        // Our next TX piggybacks the hint: addr3[4] = the conflicted ID (42), flag set.
        let (hid, hf) = d.tx_id();
        assert_eq!(hid, 42);
        assert_eq!(hf & FLAG_ID_COLLISION, FLAG_ID_COLLISION);
        // The hint is one-shot — the following TX is back to our own ID.
        let (id2, f2) = d.tx_id();
        assert_eq!(f2, 0);
        assert_eq!(id2, id0, "our own ID is unchanged by sending a hint about someone else");

        // Receiving a hint that names OUR id rotates us; the return is `true` (a hint, not a neighbour).
        let mine = d.current();
        assert!(d.rx(mine, FLAG_ID_COLLISION, Some(-50), 2_000));
        assert_ne!(d.current(), mine, "a collision hint for our ID must rotate us");
        // A hint for someone else's ID leaves us put.
        let now = d.current();
        let other = now.wrapping_add(7);
        assert!(d.rx(other, FLAG_ID_COLLISION, Some(-50), 2_100));
        assert_eq!(d.current(), now, "a hint for another ID must not move us");
    }

    #[test]
    fn detector_flags_two_contents_on_one_id_but_not_a_single_stream() {
        let mut d = AliasDetector::new(500);
        // One sender, one ID, evolving content over time — NOT an alias (spaced beyond the window).
        assert!(!d.observe(42, 0x1111, 1_000));
        assert!(!d.observe(42, 0x2222, 2_000), "same id, later content, outside window = not an alias");
        // Two senders on ID 42 within the window, different fingerprints → alias.
        assert!(!d.observe(42, 0xAAAA, 3_000));
        assert!(d.observe(42, 0xBBBB, 3_100), "same id, different content, within window = alias");
        // Same content within the window (a retransmit) is NOT an alias.
        assert!(!d.observe(7, 0xCAFE, 4_000));
        assert!(!d.observe(7, 0xCAFE, 4_050), "same content = one sender, not an alias");
    }
}
