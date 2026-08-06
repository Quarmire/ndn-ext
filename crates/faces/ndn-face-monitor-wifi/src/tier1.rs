//! **Tier-1: receiver-side BF-FIB / BF-PIT / BF-CS** (#92) — NDN-NIC's design, minus Active CS.
//!
//! Tier-0 ([`crate::tier0`]) answers direction **(a)**: *is the frame's name under a prefix I
//! registered?* It does that with no parse, from 12 bytes in the frame. It cannot answer direction
//! **(b)** — *is the frame's name a prefix of something I hold?* — because that needs **my** names,
//! which the frame does not carry. A prefix-seeking Interest (`CanBePrefix`) for `/a/b` matching a
//! cached Data `/a/b/c/d` is exactly that case, and it is invisible to Tier-0 by construction.
//!
//! So Tier-1 runs *after* Tier-0 admits a frame, on the parsed name, against three tables:
//!
//! | table | holds | answers |
//! |---|---|---|
//! | **BF-FIB** | registered prefixes | is this name under something I serve? (direction a, at scale) |
//! | **BF-PIT** | outstanding Interest names | does this Data satisfy an Interest I sent? |
//! | **BF-CS** | *every prefix of* every cached name | is this Interest a prefix of something I cache? (direction **b**) |
//!
//! ## Why this is not "just a bigger Tier-0"
//!
//! #101 measured Tier-0's limit: because a 94-bit in-frame filter is tested against E registered
//! masks, **each extra mask is another chance to false-positive**, so FP climbs with E — 0.6% at
//! E=2, 19.7% at E=32, 36.2% at E=128 — and past ~8–32 prefixes the filter stops paying for its
//! 12 bytes of permanent airtime. Tier-1 inverts the geometry: one table sized to the node's tables,
//! queried O(name depth) times regardless of how many entries it holds. A relay wants this; an
//! endpoint with a handful of interests does not need it.
//!
//! ## The part that is easy to get wrong: update ordering
//!
//! The fast filters are plain Bloom filters — no deletion. So each is **mirrored from a counting
//! Bloom filter** held in software, which does support removal, and the mirror is refreshed after a
//! batch of changes. Refreshing naively (recompute the mirror, write it out) opens a window in which
//! a bit that is still needed reads 0, i.e. **a false negative** — a wanted packet dropped. On a
//! radio that is not a lost cache hit, it is a retransmission and a round trip.
//!
//! The rule, from the paper, is **0→1 before 1→0**: apply every bit that must be *set* first, then
//! the bits that must be *cleared*. At every instant the mirror is a superset of the truth, so it
//! can over-accept but can never miss. [`Table::sync`] implements exactly that, and
//! [`tests::sync_never_opens_a_false_negative_window`] checks the invariant after each individual
//! bit write, not merely at the end.

use crate::tier0::{for_each_prefix, name_hash};

/// Counter width for the software CBF. 8 bits is far more than the paper needs (it uses 4) and costs
/// nothing here — this side is not gate-limited, and saturation would silently break removal.
type Counter = u8;

/// A counting Bloom filter and the plain-Bloom mirror the fast path reads.
///
/// The split is the whole point: the CBF supports removal but is too big and too slow for the fast
/// path; the mirror is a bit array the fast path can test with a couple of word ops.
#[derive(Clone)]
pub struct Table {
    counts: Vec<Counter>,
    /// The mirror the query path reads. Kept a superset of `counts != 0` at all times.
    mirror: Vec<u8>,
    k: u32,
    key: [u8; 16],
    saturated: u32,
}

impl Table {
    /// A table of `bits` bits with `k` probes per key.
    pub fn new(key: &[u8; 16], bits: usize, k: u32) -> Self {
        let bits = bits.max(8);
        Self {
            counts: vec![0; bits],
            mirror: vec![0u8; bits.div_ceil(8)],
            k,
            key: *key,
            saturated: 0,
        }
    }

    fn positions(&self, name: &[u8]) -> impl Iterator<Item = usize> + '_ {
        let m = self.counts.len() as u64;
        let h1 = name_hash(&self.key, name);
        let mut key2 = self.key;
        key2[0] ^= 0x5a;
        let h2 = name_hash(&key2, name) | 1;
        (0..self.k).map(move |i| (h1.wrapping_add((i as u64).wrapping_mul(h2)) % m) as usize)
    }

    /// Add one key to the counting filter. Does **not** touch the mirror — call [`sync`](Self::sync).
    pub fn insert(&mut self, name: &[u8]) {
        for p in self.positions(name).collect::<Vec<_>>() {
            match self.counts[p].checked_add(1) {
                Some(v) => self.counts[p] = v,
                // A saturated counter can never be decremented back to 0, so the bit would be stuck
                // set forever — a permanent false-positive source. Counted rather than silently
                // clamped, so it is visible instead of becoming a slow leak.
                None => self.saturated += 1,
            }
        }
    }

    /// Remove one key. Removing a key that was never inserted corrupts the filter, so this is
    /// deliberately tolerant of underflow only in the sense of not panicking — it counts it.
    pub fn remove(&mut self, name: &[u8]) {
        for p in self.positions(name).collect::<Vec<_>>() {
            match self.counts[p].checked_sub(1) {
                Some(v) => self.counts[p] = v,
                None => self.saturated += 1,
            }
        }
    }

    /// **Refresh the mirror, 0→1 before 1→0.**
    ///
    /// Two passes on purpose. Pass 1 sets every bit the new state requires; pass 2 clears the bits it
    /// no longer requires. Between them the mirror is a strict superset of both the old and the new
    /// truth, so a concurrent reader can over-accept but **cannot** get a false negative. Doing it in
    /// one pass — or clearing first — opens exactly that window.
    ///
    /// `on_write` is called after every individual bit change, so a test can assert the invariant at
    /// each intermediate state rather than only at the end.
    pub fn sync_observed(&mut self, mut on_write: impl FnMut(&[u8])) {
        // Pass 1: 0 -> 1.
        for (i, &c) in self.counts.iter().enumerate() {
            if c != 0 && self.mirror[i / 8] & (1 << (i % 8)) == 0 {
                self.mirror[i / 8] |= 1 << (i % 8);
                on_write(&self.mirror);
            }
        }
        // Pass 2: 1 -> 0.
        for (i, &c) in self.counts.iter().enumerate() {
            if c == 0 && self.mirror[i / 8] & (1 << (i % 8)) != 0 {
                self.mirror[i / 8] &= !(1 << (i % 8));
                on_write(&self.mirror);
            }
        }
    }

    /// [`sync_observed`](Self::sync_observed) without the observer.
    pub fn sync(&mut self) {
        self.sync_observed(|_| {});
    }

    /// The fast-path test: is `name` possibly present? Reads the mirror only.
    pub fn may_contain(&self, name: &[u8]) -> bool {
        self.positions(name).all(|p| self.mirror[p / 8] & (1 << (p % 8)) != 0)
    }

    /// Bits set in the mirror — occupancy, which drives the false-positive rate.
    pub fn popcount(&self) -> u32 {
        self.mirror.iter().map(|b| b.count_ones()).sum()
    }

    /// Counter saturation / underflow events. **Non-zero means the table is degraded** and needs
    /// resizing or a rebuild; it is not self-healing.
    pub fn anomalies(&self) -> u32 {
        self.saturated
    }
}

/// What a Tier-1 lookup concluded, and therefore what the forwarder should do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verdict {
    /// Some registered prefix may cover this name — a forwarding candidate.
    pub fib: bool,
    /// Some outstanding Interest may match — this Data may be wanted.
    pub pit: bool,
    /// Something cached may be under this name — we may be able to answer it.
    pub cs: bool,
}

impl Verdict {
    /// Nothing matched: the frame is of no interest to this node and Tier-2 need not run.
    pub fn is_miss(&self) -> bool {
        !self.fib && !self.pit && !self.cs
    }
}

/// The three tables, plus the Basic CS rule.
pub struct Tier1 {
    pub fib: Table,
    pub pit: Table,
    pub cs: Table,
    /// Basic CS: a cached name already covered by a FIB prefix is not inserted into BF-CS, because a
    /// FIB hit already admits the frame. The paper's cheap win — taken; Active CS is not, because it
    /// trades exact-match false positives for prefix-match ones, and on a radio a false positive
    /// costs a wakeup, a decode and possibly an on-air relay rather than a PCIe transfer.
    pub basic_cs: bool,
    cs_skipped: u32,
}

impl Tier1 {
    pub fn new(key: &[u8; 16], bits_each: usize, k: u32) -> Self {
        Self {
            fib: Table::new(key, bits_each, k),
            pit: Table::new(key, bits_each, k),
            cs: Table::new(key, bits_each, k),
            basic_cs: true,
            cs_skipped: 0,
        }
    }

    /// Register a FIB prefix. Direction (a): queried by testing the packet name's prefixes.
    pub fn register_prefix(&mut self, prefix: &[u8]) {
        self.fib.insert(prefix);
    }

    /// Record an outstanding Interest.
    pub fn add_pit(&mut self, name: &[u8]) {
        self.pit.insert(name);
    }

    pub fn remove_pit(&mut self, name: &[u8]) {
        self.pit.remove(name);
    }

    /// Cache a Data name. **Every prefix is inserted**, which is what makes direction (b) work: a
    /// prefix-seeking Interest `/a/b` can then hit a cached `/a/b/c/d`.
    pub fn cache(&mut self, name: &[u8]) {
        if self.basic_cs && self.fib_covers(name) {
            // Already admitted by a FIB hit — inserting it would only add occupancy, and occupancy
            // is what the false-positive rate is made of.
            self.cs_skipped += 1;
            return;
        }
        for_each_prefix(name, |pfx| self.cs.insert(pfx));
    }

    fn fib_covers(&self, name: &[u8]) -> bool {
        let mut hit = false;
        for_each_prefix(name, |pfx| {
            if !hit && self.fib.may_contain(pfx) {
                hit = true;
            }
        });
        hit
    }

    /// Publish all three mirrors, each 0→1 before 1→0.
    pub fn sync(&mut self) {
        self.fib.sync();
        self.pit.sync();
        self.cs.sync();
    }

    /// **The Tier-1 query.** Runs on the parsed name, after Tier-0 has admitted the frame.
    pub fn lookup(&self, name: &[u8]) -> Verdict {
        Verdict {
            // (a) is the name under a registered prefix — test the name's prefixes.
            fib: self.fib_covers(name),
            // does an outstanding Interest cover this Data — the PIT holds full names, and a Data
            // name may extend it (implicit digest), so test the name's prefixes too.
            pit: {
                let mut hit = false;
                for_each_prefix(name, |pfx| {
                    if !hit && self.pit.may_contain(pfx) {
                        hit = true;
                    }
                });
                hit
            },
            // (b) is the name a PREFIX of something cached — one direct probe, because `cache`
            // inserted every prefix of the cached name.
            cs: self.cs.may_contain(name),
        }
    }

    /// Cached names skipped by the Basic CS rule.
    pub fn cs_skipped(&self) -> u32 {
        self.cs_skipped
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 16] = *b"ndn/tier1-testk!";
    const BITS: usize = 4096;
    const K: u32 = 4;

    fn t1() -> Tier1 {
        Tier1::new(&KEY, BITS, K)
    }

    /// **Direction (b) — the case Tier-0 cannot answer at all.**
    ///
    /// A prefix-seeking Interest for `/a/b` must find cached Data `/a/b/c/d`. Tier-0's in-frame
    /// filter carries prefixes of the *frame's* name, and the receiver's masks are its *registered*
    /// prefixes, so it can only decide "is the frame under my prefix". This is the other direction,
    /// and it is the reason Tier-1 exists rather than being a scaled-up Tier-0.
    #[test]
    fn cs_answers_the_direction_tier0_cannot() {
        let mut t = t1();
        t.cache(b"/a/b/c/d");
        t.sync();
        assert!(t.lookup(b"/a/b").cs, "prefix-seeking Interest missed a cached descendant");
        assert!(t.lookup(b"/a/b/c/d").cs, "exact cached name missed");
        assert!(!t.lookup(b"/z/z").cs, "unrelated name hit the CS");
    }

    /// FIB is direction (a) at scale — the same question Tier-0 answers, but O(name depth) instead
    /// of O(E), which is the whole point of #101's finding.
    #[test]
    fn fib_matches_under_a_registered_prefix() {
        let mut t = t1();
        for i in 0..500u32 {
            t.register_prefix(format!("/ns{i:04x}").as_bytes());
        }
        t.sync();
        assert!(t.lookup(b"/ns0007/x/y").fib, "name under a registered prefix missed");
        assert!(!t.lookup(b"/other/x").fib, "unregistered namespace hit");
    }

    /// **The invariant that matters: no false negative at ANY point during a mirror refresh.**
    ///
    /// Checked after every individual bit write, not just at the end — a one-pass or clear-first
    /// sync passes an end-state check and still drops packets mid-update. Entries present both
    /// before and after must remain findable throughout.
    #[test]
    fn sync_never_opens_a_false_negative_window() {
        let mut t = Table::new(&KEY, BITS, K);
        let keep: Vec<Vec<u8>> = (0..40u32).map(|i| format!("/keep{i:03}").into_bytes()).collect();
        let drop: Vec<Vec<u8>> = (0..40u32).map(|i| format!("/drop{i:03}").into_bytes()).collect();
        for n in keep.iter().chain(drop.iter()) {
            t.insert(n);
        }
        t.sync();
        for n in &keep {
            assert!(t.may_contain(n), "setup: keeper not present");
        }

        // Now remove half the entries and refresh. `keep` must stay findable at every instant.
        for n in &drop {
            t.remove(n);
        }
        let probe: Vec<Vec<usize>> =
            keep.iter().map(|n| t.positions(n).collect::<Vec<_>>()).collect();
        let mut writes = 0u32;
        let mut violations = 0u32;
        t.sync_observed(|mirror| {
            writes += 1;
            for pos in &probe {
                if !pos.iter().all(|p| mirror[p / 8] & (1 << (p % 8)) != 0) {
                    violations += 1;
                }
            }
        });
        assert!(writes > 0, "sync did nothing — the test would be vacuous");
        assert_eq!(violations, 0, "a keeper became unfindable mid-sync: false-negative window");
        for n in &keep {
            assert!(t.may_contain(n), "keeper lost after sync");
        }
    }

    /// Clear-first is the natural implementation and it is WRONG — this pins that, so nobody
    /// "simplifies" `sync` into it later. Demonstrated on the same data the correct order survives.
    #[test]
    fn clear_first_would_open_the_window_that_sync_avoids() {
        let mut t = Table::new(&KEY, BITS, K);
        let keep: Vec<Vec<u8>> = (0..40u32).map(|i| format!("/keep{i:03}").into_bytes()).collect();
        let drop: Vec<Vec<u8>> = (0..40u32).map(|i| format!("/drop{i:03}").into_bytes()).collect();
        for n in keep.iter().chain(drop.iter()) {
            t.insert(n);
        }
        t.sync();
        for n in &drop {
            t.remove(n);
        }

        // Simulate the wrong order: clear every bit whose count is now 0, watching for a keeper
        // that becomes unfindable. Bits shared between a keeper and a dropped entry are exactly
        // where this bites — the count is non-zero, but a naive "recompute from scratch, write in
        // index order" pass would clear before re-setting.
        let mut naive = vec![0u8; BITS.div_ceil(8)];
        let mut lost = 0u32;
        for (i, &c) in t.counts.iter().enumerate() {
            if c != 0 {
                naive[i / 8] |= 1 << (i % 8);
            }
            // Mid-rebuild: a keeper whose bits are not all written yet reads as absent.
            if i == BITS / 2 {
                for n in &keep {
                    if !t.positions(n).all(|p| naive[p / 8] & (1 << (p % 8)) != 0) {
                        lost += 1;
                    }
                }
            }
        }
        assert!(
            lost > 0,
            "the naive rebuild did not lose anyone — the ordering test above proves nothing"
        );
    }

    /// Basic CS: a cached name already covered by a FIB prefix is not inserted, because a FIB hit
    /// already admits the frame. Taken from the paper; the saving is pure occupancy, and occupancy
    /// is what the false-positive rate is made of.
    #[test]
    fn basic_cs_skips_names_a_fib_prefix_already_covers() {
        let mut t = t1();
        t.register_prefix(b"/served");
        t.sync();
        t.cache(b"/served/a/b");
        t.cache(b"/elsewhere/a/b");
        t.sync();
        assert_eq!(t.cs_skipped(), 1, "a FIB-covered name was still inserted into BF-CS");
        // Still reachable — via the FIB, which is the point of the optimisation.
        assert!(t.lookup(b"/served/a/b").fib);
        assert!(t.lookup(b"/elsewhere").cs, "the non-covered name should be in BF-CS");
    }

    /// A clean miss must be a miss on all three, so the forwarder can skip Tier-2 entirely.
    #[test]
    fn a_total_miss_is_reported_as_one() {
        let mut t = t1();
        t.register_prefix(b"/served");
        t.add_pit(b"/asked/for/this");
        t.cache(b"/cached/thing");
        t.sync();
        assert!(t.lookup(b"/nothing/here").is_miss());
        assert!(!t.lookup(b"/served/x").is_miss());
        assert!(!t.lookup(b"/asked/for/this").is_miss());
        assert!(!t.lookup(b"/cached").is_miss());
    }

    /// Removal must actually remove — the property a plain Bloom filter cannot provide and the
    /// entire reason for the counting mirror.
    #[test]
    fn pit_entries_disappear_when_satisfied() {
        let mut t = t1();
        t.add_pit(b"/i/want/this");
        t.sync();
        assert!(t.lookup(b"/i/want/this").pit);
        t.remove_pit(b"/i/want/this");
        t.sync();
        assert!(!t.lookup(b"/i/want/this").pit, "satisfied PIT entry still matches");
        assert_eq!(t.pit.anomalies(), 0, "counter under/overflow during a legal cycle");
    }
}
