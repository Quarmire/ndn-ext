//! **Tier-0: the in-frame prefix-set Bloom filter** (#91) — zero-parse name matching.
//!
//! Ported from the firmware reference implementation
//! (`ndn-radio-drivers/firmware/lr2021-nrf54l15-rs/src/tier0.rs`), which is dependency-free integer
//! code and compiles for RISC-V unchanged.
//!
//! **All three copies hash `siphash24`** (doctrine §8 unforgeability — see [`name_hash`]): this one,
//! the LR2021 firmware `tier0.rs`, and the ath9k-htc C `ndr_tier0.c`. An earlier version of this
//! header warned that the firmware "still uses keyed FNV-1a-64"; that was true once, was fixed in
//! the firmware, and the warning here was not — **it then misled a review into re-planning work that
//! was already done**, which is the exact cost of a stale comment about another file.
//!
//! They agree today *by having been edited in sync*, which is not a guarantee. `golden/tier0/`
//! carries the shared vectors ([`golden_vectors`]) and every implementation asserts them, so drift
//! is a red test rather than a silent false negative on air — the forbidden failure. The algorithm,
//! the sizing, and the `k = 4` constant were
//! **measured on hardware** there (`m7_filter_test`, 20 000 trials/point on an nRF54L15); the tests at
//! the bottom of this file re-assert the two properties that matter — zero false negatives, and the
//! measured false-positive curve — so the port cannot silently drift from the validated original.
//!
//! The design lives in `docs/named-filter-mac-redesign.md` §3. In short: an in-frame *hash* of the
//! name cannot express prefix matching, and a prefix is the normal FIB entry in NDN. A hash destroys
//! hierarchy; NDN names **are** hierarchy. The fix is to carry the name's **prefix set** rather than
//! the name:
//!
//! ```text
//!   sender:    /A/b/c → { /, /A, /A/b, /A/b/c } → K bits set per prefix in an M-bit filter
//!   receiver:  for each registered prefix P (mask precomputed once):
//!                  (frame & mask[P]) == mask[P]  ⇒ maybe under P → accept, parse
//!              else                              ⇒ DEFINITELY not under P → drop, never parse
//! ```
//!
//! The negative answer is **exact**: if the name really were under `P`, the sender would have set
//! precisely those bits. False positives cost a parse; false negatives cannot occur. That asymmetry
//! is what makes an aggressive MAC-layer filter safe to be wrong.
//!
//! ## Sizing, and why the source paper's k does not transfer
//!
//! NDN-NIC uses k=2, optimal for *its* regime (~10⁵ keys in 65536 bits). Ours is the opposite:
//! **n ≈ name depth (4–8) in [`M_BITS`] = 94 bits**. The textbook optimum `(M/n)·ln2` predicts ~7,
//! but that formula assumes a query's k positions are independent — with only 94 bits they are not
//! (k=6 positions collide with each other ~15 % of the time), so the true optimum sits *below* the
//! prediction. Measured optimum is [`K`] = 4. See the doc §9.
//!
//! ## Why 94 and not 96
//!
//! The filter rides in the two 48-bit address fields of the frame. The **I/G and U/L bits of the
//! first octet must keep their locally-administered/group meaning**, or we begin emitting frames that
//! look like real devices' unicast traffic — a doctrine violation (see `mac-addressing-doctrine.md`
//! §6.1).
//!
//! ## Hashing
//!
//! One keyed 64-bit name hash per prefix, expanded to [`K`] bit positions by double hashing
//! (Kirsch–Mitzenmacher): `h_i = (h1 + i·h2) mod M`, with `h1` and `h2` two **independent** keyed
//! FNV-1a passes (splitting one output measured 1.3–3.4× worse — FNV's high half is weak). Keeps the
//! project to **one name-hash keyspace** shared by the filter, the FIB, and the data plane (#44).
//! Keyed so a private group's filter is unlinkable by an observer without the key.

/// Usable filter bits. 96 (two address fields) minus the two reserved bits of octet 0.
use ndn_frame_io::siphash24;

pub const M_BITS: u32 = 126;

/// **Hashes per prefix — k = 4.**
///
/// Chosen on the largest-sample measurement available, not on a claimed optimum. The history matters
/// because this constant has now been wrong in both directions:
///
/// 1. Originally k=4, justified by an on-device sweep that "disproved" the closed-form prediction of
///    ~6. That sweep's false-positive queries came from `make_name(d, 0x10000 + t)`, and the helper
///    formats the salt as four hex digits — the 0x10000 truncated away, so the "disjoint" queries
///    shared leading components with the registered name and genuine ancestors were counted as false
///    positives.
/// 2. With the generator fixed, the same device sweep inverted and showed k=6 far ahead. That was
///    12 names and 54 events — one harness, small sample, exactly the weakness that produced (1).
/// 3. An independent host replication at **200 names / 400 000 trials** (`ksweep_host_replication`),
///    with +/-1σ error bars, disagrees with the device beyond both their error bars:
///
/// | k | bits set | FP @ depth 8, host (±1σ) | FP @ depth 8, device |
/// |---|---|---|---|
/// | 3 | 23/94 | 1.043% ± 0.016 | 1.02% |
/// | **4** | **28/94** | **0.586% ± 0.012** | 0.91% |
/// | 5 | 34/94 | 0.671% ± 0.013 | 0.46% |
/// | 6 | 38/94 | 0.665% ± 0.013 | 0.27% |
/// | 8 | 48/94 | 0.670% ± 0.013 | 0.67% |
///
/// **The honest reading: the optimum is not determined by these measurements.** Two independently
/// written harnesses rank k=4..8 differently by more than their error bars, which means the *name
/// distribution* dominates, not k. Only k=3 is consistently bad. Everything else is inside the
/// sub-1.5% regime the design needs.
///
/// So k=4 on the tiebreakers: it wins the one measurement with tight error bars, sets the fewest
/// bits (28/94, leaving headroom before saturation), costs the fewest hashes per frame, and is what
/// the on-air shadow-mode result (#106: 87.1% reject, 0.46% FP) was measured at.
///
/// **Do not "improve" this from a single sweep.** That is what went wrong twice.
pub const K: u32 = 4;

/// Deepest prefix inserted. Beyond this the filter saturates and degrades *for every user of the
/// frame*, so the tail is bounded here and deeper matching is left to the software tier.
pub const MAX_DEPTH: usize = 8;

/// **Admission fill cap** — the maximum number of set bits a *received* filter may carry and still
/// be tested against any local mask.
///
/// Without it, [`PrefixFilter::may_match`] is a pure AND: a frame with all 94 bits set matches every
/// registered mask at every node, for free, computed once. That is a one-frame universal wake — and
/// once the scheduler keys on this field it becomes worse than a wake, because the same frame
/// matches every slot owner's mask: every slot reads busy, presence is forged for every owner
/// including departed ones, and claims are suppressed network-wide for a full presence window per
/// frame.
///
/// **Sizing.** A legitimate filter at the depth cap sets 30 bits (measured, `MAX_DEPTH` = 8,
/// `K` = 4 — see the depth/popcount table in the tests). 48 leaves headroom for future class tokens
/// while bounding a just-under-cap adversary to roughly `(48/94)^4` ≈ 7% per targeted prefix rather
/// than 100%.
///
/// **Scope, honestly.** This removes the *amplified* attack — one frame forging presence for every
/// group at once. It does not stop an adversary forging presence for a single group it knows the
/// name of; that is inherent to unauthenticated MAC-level evidence and is not a property any
/// arrangement of these 94 bits can provide.
///
/// Coupled to `MAX_DEPTH`, `K` and any future class tokens, so it is a **shared wire parameter**:
/// every implementation must use the same value or they disagree about which frames are admissible.
pub const FILL_CAP: u32 = 64;


/// The two bits of octet 0 that must not be used by the filter (I/G and U/L).
const RESERVED_MASK0: u8 = 0b0000_0011;

/// A 96-bit in-frame filter: 94 usable bits plus the two reserved address bits.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PrefixFilter(pub [u8; 16]);

impl Default for PrefixFilter {
    fn default() -> Self {
        Self::new()
    }
}

/// **SipHash-2-4 under the full 16-byte [`GroupKey`]** — a keyed PRF, not a keyed checksum.
///
/// This was keyed FNV-1a-64 (the group key XORed into the FNV init state). FNV is not a PRF and that
/// keying is trivially invertible from observed output, so an outsider who saw a few frames could
/// recover the key and then compute — or deliberately collide with — a private group's pre-parse
/// filter. That is precisely the property doctrine §8 claims the group key provides, and §8's own
/// history records FNV-1a being *replaced by* SipHash-2-4 for this exact reason. Going back to FNV
/// silently un-did it: the filter still varied with the key, so every test still passed, while the
/// adversarial guarantee was gone.
///
/// The shared-keyspace goal from #44 is unaffected — `siphash24` is what `EphemeralSource` already
/// uses, so this consolidates onto ONE keyed-hash primitive rather than adding a second family.
pub fn name_hash(key: &[u8; 16], name: &[u8]) -> u64 {
    siphash24(key, name)
}

/// Domain separator for the second hash, so `h1` and `h2` are two independent PRF evaluations under
/// *different keys* rather than two halves of one output. (Under FNV this had to be a golden-ratio
/// key mix because splitting one FNV output measured 1.3-3.4x worse — FNV's high bits are its weak
/// half. SipHash has no weak half, but two keys remain the clean construction.)
const KEY2_DOMAIN: [u8; 16] = *b"ndn/tier0-h2\0\0\0\0";

/// The [`K`] bit positions one prefix occupies.
///
/// `h1` and `h2` are two **independent** keyed hashes, not the two halves of one. Splitting a single
/// FNV-1a output measured 1.3–3.4× worse at depths 4–8 — FNV's high bits are its weak half, so using
/// them as the double-hashing stride correlates the K positions.
pub fn positions(key: &[u8; 16], prefix: &[u8]) -> [u8; K as usize] {
    let mut key2 = *key;
    for (b, d) in key2.iter_mut().zip(KEY2_DOMAIN.iter()) {
        *b ^= *d;
    }
    let h1 = name_hash(key, prefix) as u32;
    // `| 1` keeps the stride odd, so the K positions cannot collapse onto one bit.
    let h2 = (name_hash(&key2, prefix) as u32) | 1;
    let mut out = [0u8; K as usize];
    for (i, o) in out.iter_mut().enumerate() {
        *o = (h1.wrapping_add((i as u32).wrapping_mul(h2)) % M_BITS) as u8;
    }
    out
}

/// Iterate the prefixes of a `/`-separated name, root first, capped at [`MAX_DEPTH`].
///
/// `/A/b/c` yields `/`, `/A`, `/A/b`, `/A/b/c`.
pub fn for_each_prefix<F: FnMut(&[u8])>(name: &[u8], mut f: F) {
    f(b"/");
    let mut depth = 0;
    for (i, &b) in name.iter().enumerate() {
        if i > 0 && b == b'/' {
            depth += 1;
            if depth >= MAX_DEPTH {
                return;
            }
            f(&name[..i]);
        }
    }
    if !name.is_empty() && depth < MAX_DEPTH {
        f(name);
    }
}

/// Truncate a *registered* prefix to the deepest form a sender would actually have inserted.
///
/// ★ Load-bearing. Without it the depth cap produces **true false negatives** — the one failure the
/// design forbids.
///
/// [`for_each_prefix`] stops at the cap, so a sender transmitting `/a/b/c/d/e/f/g/h/i` inserts at
/// deepest `/a/b/c/d/e/f/g` — **seven** components, not eight. A receiver registered on
/// `/a/b/c/d/e/f/g/h` would otherwise build a mask over bits the sender never set and drop a frame
/// that genuinely is under its prefix. Clamping the registration to its 7-component ancestor restores
/// zero false negatives (at the cost of extra false positives), and Tier 1/2 does the exact match.
///
/// Found by cross-checking the C port for the AR9271 firmware against this implementation.
pub fn clamp_prefix(prefix: &[u8]) -> usize {
    let mut comps = 0;
    for i in 1..prefix.len() {
        if prefix[i] == b'/' {
            comps += 1;
            // `comps` components precede this slash; the cap admits MAX_DEPTH - 1 of them.
            if comps >= MAX_DEPTH - 1 {
                return i;
            }
        }
    }
    prefix.len()
}

impl PrefixFilter {
    /// An empty filter (all usable bits clear).
    pub const fn new() -> Self {
        Self([0; 16])
    }

    /// Set one bit, skipping the two reserved positions by construction.
    fn set_bit(&mut self, pos: u8) {
        // Bit p of the usable space maps to physical bit p+2, so 0 and 1 of octet 0 stay free.
        let p = pos as usize + 2;
        self.0[p / 8] |= 1 << (p % 8);
    }

    fn get_bit(&self, pos: u8) -> bool {
        let p = pos as usize + 2;
        self.0[p / 8] & (1 << (p % 8)) != 0
    }

    /// Insert every prefix of `name`.
    pub fn insert_name(&mut self, key: &[u8; 16], name: &[u8]) {
        let mut tmp = *self;
        for_each_prefix(name, |pfx| {
            for &p in positions(key, pfx).iter() {
                tmp.set_bit(p);
            }
        });
        *self = tmp;
    }

    /// The mask a receiver precomputes once per registered prefix.
    ///
    /// The prefix is clamped by [`clamp_prefix`] first — without that, a registration deeper than the
    /// cap produces a **true false negative**.
    pub fn mask_for(key: &[u8; 16], prefix: &[u8]) -> Self {
        let prefix = &prefix[..clamp_prefix(prefix)];
        let mut m = Self::new();
        for &p in positions(key, prefix).iter() {
            m.set_bit(p);
        }
        m
    }

    /// Could this frame's name be under the prefix `mask` was built from?
    ///
    /// `false` is **exact** — the name is definitely not under it. `true` means *probably*, and the
    /// software tier decides.
    pub fn may_match(&self, mask: &Self) -> bool {
        // **Fill cap first** — before any mask test, because the mask test is a pure AND and an
        // over-full filter passes every one of them. See [`FILL_CAP`].
        if self.popcount() > FILL_CAP {
            return false;
        }
        for i in 0..16 {
            let want = mask.0[i] & !if i == 0 { RESERVED_MASK0 } else { 0 };
            if self.0[i] & want != want {
                return false;
            }
        }
        true
    }

    /// Count of usable bits set — the saturation the false-positive rate follows.
    pub fn popcount(&self) -> u32 {
        let mut n = 0;
        for p in 0..M_BITS as u8 {
            if self.get_bit(p) {
                n += 1;
            }
        }
        n
    }

    /// The 12 wire bytes (addr1 ‖ addr2), with the reserved bits forced to locally-administered group.
    ///
    /// Applied at the boundary rather than trusted from the caller: a filter whose bit pattern happens
    /// to clear these would put a globally-unique unicast address on the air.
    pub fn to_wire(&self) -> [u8; 16] {
        let mut w = self.0;
        w[0] = (w[0] & !RESERVED_MASK0) | 0b0000_0011; // I/G = group, U/L = local
        w
    }

    /// Reconstruct a filter from the 12 on-air address bytes (addr1 ‖ addr2).
    ///
    /// The reserved bits are ignored on the way in: [`may_match`] already excludes them, so a
    /// round-trip through [`to_wire`] is exact for matching purposes.
    pub fn from_wire(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Group key for the tests; any fixed value. The filter is keyed so a private group is unlinkable.
    const KEY: [u8; 16] = *b"ndn/tier0-testk!";

    /// `/p0/p1/.../p{depth-1}` with a varying 4-hex-digit leaf, so component length is constant and
    /// depth is the only variable — mirrors the on-device `m7_filter_test::make_name`. Non-leaf
    /// components are `0,1,2,…` (a fixed low-range namespace).
    fn make_name(depth: usize, salt: u32) -> Vec<u8> {
        let mut v = Vec::new();
        for c in 0..depth {
            v.push(b'/');
            let val = if c + 1 == depth { salt } else { c as u32 };
            for shift in [12, 8, 4, 0] {
                let d = ((val >> shift) & 0xf) as u8;
                v.push(if d < 10 { b'0' + d } else { b'a' + d - 10 });
            }
        }
        v
    }

    /// Like [`make_name`] but every component (not just the leaf) is in a high, disjoint range, so no
    /// prefix of one of these names can ever coincide with a prefix of a [`make_name`] filter name.
    ///
    /// ★ This matters *because* of [`clamp_prefix`]: a query of depth ≥ MAX_DEPTH that shares the
    /// filter's first `MAX_DEPTH-1` components clamps onto the filter's genuine deep ancestor and
    /// matches — correctly, not a false positive. Measuring the FP rate against non-ancestors
    /// therefore requires a query namespace that is disjoint at *every* prefix depth, not just at the
    /// leaf. (The on-device `m7_filter_test` predated `clamp_prefix` and used overlapping non-leaf
    /// components, which was harmless only until clamping existed.)
    fn make_disjoint_name(depth: usize, salt: u32) -> Vec<u8> {
        let mut v = Vec::new();
        for c in 0..depth {
            v.push(b'/');
            let val = 0x8000 + (c as u32) * 0x100 + if c + 1 == depth { salt & 0xff } else { 0 };
            for shift in [12, 8, 4, 0] {
                let d = ((val >> shift) & 0xf) as u8;
                v.push(if d < 10 { b'0' + d } else { b'a' + d - 10 });
            }
        }
        v
    }

    #[test]
    fn prefixes_root_first_and_capped() {
        let mut seen: Vec<Vec<u8>> = Vec::new();
        for_each_prefix(b"/A/b/c", |p| seen.push(p.to_vec()));
        assert_eq!(
            seen,
            vec![
                b"/".to_vec(),
                b"/A".to_vec(),
                b"/A/b".to_vec(),
                b"/A/b/c".to_vec()
            ]
        );

        // A name deeper than the cap stops inserting at MAX_DEPTH - 1 slashes.
        let deep = b"/a/b/c/d/e/f/g/h/i/j";
        let mut count = 0;
        let mut deepest = Vec::new();
        for_each_prefix(deep, |p| {
            count += 1;
            deepest = p.to_vec();
        });
        // root + (MAX_DEPTH - 1) interior prefixes.
        assert_eq!(count, MAX_DEPTH);
        assert_eq!(deepest, b"/a/b/c/d/e/f/g".to_vec());
    }

    #[test]
    fn no_false_negatives_every_genuine_ancestor_matches() {
        // The property the whole design rests on: for a name inserted into the filter, every one of
        // its genuine prefixes must match. Checked exhaustively across many names and depths.
        for depth in 1..=12usize {
            for salt in 0..500u32 {
                let name = make_name(depth, 0xABCD ^ salt);
                let mut f = PrefixFilter::new();
                f.insert_name(&KEY, &name);
                for_each_prefix(&name, |pfx| {
                    let mask = PrefixFilter::mask_for(&KEY, pfx);
                    assert!(
                        f.may_match(&mask),
                        "false negative at depth {depth} salt {salt} prefix {:?}",
                        std::str::from_utf8(pfx).unwrap_or("<bin>")
                    );
                });
            }
        }
    }

    #[test]
    fn deep_registration_clamps_no_false_negative() {
        // A registration DEEPER than the cap must still match a frame genuinely under it. This is the
        // clamp_prefix guarantee — the case the on-device measurement could not see.
        let name = b"/a/b/c/d/e/f/g/h/i/j/k";
        let mut f = PrefixFilter::new();
        f.insert_name(&KEY, name);
        // Register on an 10-component prefix (past the 8 cap); must not drop the frame.
        let reg = b"/a/b/c/d/e/f/g/h/i/j";
        let mask = PrefixFilter::mask_for(&KEY, reg);
        assert!(f.may_match(&mask), "clamp failed → false negative");
    }

    #[test]
    fn false_positive_rate_matches_measured_curve() {
        // Two guards in one: (1) the exact bits-set counts, which pin the insertion path; (2) the FP
        // rate stays in the sub-1.5 % regime the k=4 design promises. FP queries come from a namespace
        // disjoint at every prefix depth (see make_disjoint_name) so clamp_prefix cannot turn a deep
        // query into a genuine ancestor.
        //
        // **Re-baselined when the hash moved from keyed FNV-1a-64 to SipHash-2-4** (see `name_hash`).
        // Different hash, different bit positions — so the popcounts shifted at depths 6 and 8. What
        // did NOT shift is the regime, which is the property that matters:
        //
        //   depth   popcount (FNV -> SipHash)   FP (FNV -> SipHash)
        //     2         12 -> 12                 0.095% -> 0.000%
        //     4         19 -> 19                 0.24%  -> 0.390%
        //     6         27 -> 23                 0.80%  -> 0.910%
        //     8         29 -> 30                 0.94%  -> 0.780%
        //
        // Both sit inside the k=4 band, which is exactly what the original sizing work predicted:
        // at m=94 the FP rate is dominated by small-m collisions between the K positions, not by
        // hash quality — measured then by swapping in two independent keyed hashes and seeing no
        // improvement. Changing the hash for its *cryptographic* property therefore costs nothing
        // in filter performance.
        // **Averaged over R registered names per depth, not one.** A single draw is exactly how the
        // k=4 artefact survived for as long as it did: one name, one key, and a number that looked
        // authoritative. Matching the on-device methodology (`m7_filter_test`) so the two are
        // comparable rather than merely both plausible.
        const TRIALS: u32 = 20_000;
        const R: u32 = 12;
        for &(depth, exp_bits) in &[(2usize, 12u32), (4, 20), (6, 26), (8, 34)] {
            let mut fp = 0u32;
            let mut trials = 0u32;
            for r in 0..R {
                let name = make_name(depth, 0x1000 + r * 0x111);
                let mut f = PrefixFilter::new();
                f.insert_name(&KEY, &name);
                if r == 0 {
                    assert_eq!(f.popcount(), exp_bits, "bits set drifted at depth {depth}");
                }
                let per = TRIALS / R;
                for t in 0..per {
                    let other = make_disjoint_name(1 + (t as usize % depth.max(1)), r * TRIALS + t);
                    if f.may_match(&PrefixFilter::mask_for(&KEY, &other)) {
                        fp += 1;
                    }
                }
                trials += per;
            }
            let ppm = (fp as u64) * 1_000_000 / trials as u64;
            // 1.5 % ceiling: a regression guard, not the measurement. Measured at k=4, averaged over
            // 12 names: 0.00 / 0.53 / 0.70 / 0.56 % at depths 2/4/6/8.
            assert!(
                ppm <= 15_000,
                "FP at depth {depth} = {ppm} ppm exceeds the k=6 regime"
            );
        }
    }

    #[test]
    fn keying_hides_a_private_group() {
        // **This test used to check ONE wrong key and assert it did not match.** That is
        // key-sensitivity, which even a keyed checksum satisfies — and it read like a guard on
        // doctrine §8's *unforgeability* claim while guarding nothing of the sort. It passed happily
        // while the filter was keyed with FNV-1a, whose keying an outsider can invert from observed
        // output.
        //
        // What §8 actually claims is that an outsider without the key cannot match (or deliberately
        // collide with) a private group's frames. The observable consequence: under a wrong key, the
        // match rate must fall to the filter's own false-positive floor — no better than guessing.
        // A hash with structure the key fails to hide would show a match rate well above it.
        let name = make_name(6, 0x1234);
        let mut f = PrefixFilter::new();
        f.insert_name(&KEY, &name);

        const TRIALS: u32 = 20_000;
        let mut matched = 0u32;
        for t in 0..TRIALS {
            // A different wrong key each time, so this samples the key space rather than one point.
            let mut wrong = KEY;
            wrong[0] ^= (t & 0xff) as u8;
            wrong[1] ^= ((t >> 8) & 0xff) as u8;
            wrong[2] ^= 0xA5;
            if f.may_match(&PrefixFilter::mask_for(&wrong, &name)) {
                matched += 1;
            }
        }
        let ppm = (matched as u64) * 1_000_000 / TRIALS as u64;
        // The depth-6 FP floor measured just above is ~9100 ppm; allow headroom but stay far below
        // anything that would indicate the key is not hiding the name's structure.
        assert!(
            ppm <= 20_000,
            "wrong-key match rate {ppm} ppm is above the FP floor — keying is not hiding the group"
        );
    }

    #[test]
    fn wire_round_trip_sets_reserved_bits() {
        let name = make_name(4, 7);
        let mut f = PrefixFilter::new();
        f.insert_name(&KEY, &name);
        let wire = f.to_wire();
        assert_eq!(wire[0] & RESERVED_MASK0, 0b0000_0011, "I/G+U/L not local-group");
        // The reconstructed filter still matches every genuine prefix (reserved bits excluded).
        let back = PrefixFilter::from_wire(wire);
        for_each_prefix(&name, |pfx| {
            assert!(back.may_match(&PrefixFilter::mask_for(&KEY, pfx)));
        });
    }

    /// **One-shot k sweep on the host** — an independent replication of the on-device measurement
    /// that chose k. Run with `TIER0_KSWEEP=1 cargo test -p ndn-face-monitor-wifi ksweep -- --nocapture`.
    ///
    /// Uses this module's own name generators (different from the firmware's), the same 12-name
    /// averaging, and a k-parameterised probe so every k is measured identically. Two independent
    /// harnesses agreeing on the ordering is what makes the k choice trustworthy; the previous k=4
    /// rested on one harness, one name, and a generator that was quietly broken.
    #[test]
    fn ksweep_host_replication() {
        if std::env::var("TIER0_KSWEEP").is_err() {
            return;
        }
        fn set_bits(bits: &mut [u8; 16], key: &[u8; 16], prefix: &[u8], k: u32) {
            let mut key2 = *key;
            for (b, d) in key2.iter_mut().zip(KEY2_DOMAIN.iter()) {
                *b ^= *d;
            }
            let h1 = name_hash(key, prefix) as u32;
            let h2 = (name_hash(&key2, prefix) as u32) | 1;
            for i in 0..k {
                let pos = (h1.wrapping_add(i.wrapping_mul(h2)) % M_BITS) as usize + 2;
                bits[pos / 8] |= 1 << (pos % 8);
            }
        }
        fn contains(bits: &[u8; 16], key: &[u8; 16], prefix: &[u8], k: u32) -> bool {
            let mut probe = [0u8; 16];
            set_bits(&mut probe, key, prefix, k);
            (0..16).all(|i| probe[i] & !bits[i] & if i == 0 { !0b11 } else { 0xff } == 0)
        }
        // Large sample: the 12-name / 20k-trial version put the two harnesses in disagreement about
        // the ordering, which means the NAME SET was dominating, not k. Widen until the error bars
        // are small enough for the question to have an answer.
        const TRIALS: u32 = 400_000;
        const R: u32 = 200;
        println!("host k sweep at depth {MAX_DEPTH} ({R} names, {TRIALS} trials):");
        for k in [3u32, 4, 5, 6, 8] {
            let (mut fp, mut trials, mut bits_tot, mut fneg) = (0u32, 0u32, 0u32, 0u32);
            for r in 0..R {
                let name = make_name(MAX_DEPTH, 0x1000 + r * 0x111);
                let mut bits = [0u8; 16];
                for_each_prefix(&name, |pfx| set_bits(&mut bits, &KEY, pfx, k));
                bits_tot += bits.iter().map(|b| b.count_ones()).sum::<u32>();
                for_each_prefix(&name, |pfx| {
                    if !contains(&bits, &KEY, pfx, k) {
                        fneg += 1;
                    }
                });
                let per = TRIALS / R;
                for t in 0..per {
                    let other = make_disjoint_name(1 + (t as usize % MAX_DEPTH), r * TRIALS + t);
                    if contains(&bits, &KEY, &other, k) {
                        fp += 1;
                    }
                }
                trials += per;
            }
            // +/- 1 sigma on a Poisson count, carried through to ppm, so the numbers can be
            // compared instead of merely ranked.
            let ppm = (fp as u64) * 1_000_000 / trials as u64;
            let sigma_ppm = ((fp as f64).sqrt() * 1_000_000.0 / trials as f64) as u64;
            println!(
                "  k={k}: bits(avg) {}/94  FP {fp}/{trials} = {ppm} +/- {sigma_ppm} ppm  false negatives {fneg}",
                bits_tot / R
            );
        }
    }
}

/// **The admission fill cap** (F1) — the amplified-wake hole and its boundary.
#[cfg(test)]
mod fill_cap_tests {
    use super::*;

    /// **An over-full filter must match nothing**, and this is the whole point: `may_match` is a
    /// pure AND, so before the cap an all-ones frame matched *every* registered mask at *every*
    /// node. One frame, computed for free, woke the entire network — and once the scheduler keys on
    /// this field it forges presence for every slot owner at once, suppressing all claims for a
    /// presence window.
    #[test]
    fn an_all_ones_filter_matches_nothing() {
        let key = [7u8; 16];
        let mut mask = PrefixFilter::default();
        mask.insert_name(&key, b"/ndn/alarm");
        assert!(mask.popcount() > 0, "fixture: the mask has bits to match");

        let mut all_ones = PrefixFilter::default();
        for p in 0..M_BITS as u8 {
            all_ones.set_bit(p);
        }
        assert!(all_ones.popcount() > FILL_CAP);
        assert!(
            !all_ones.may_match(&mask),
            "a saturated filter must be inert; without the cap it matched every mask on the network"
        );
    }

    /// A legitimate filter at the depth cap must still be admitted — the cap must not cost us the
    /// deepest names we actually send. Measured fill at MAX_DEPTH is 30 bits against a cap of 48.
    #[test]
    fn a_legitimate_deep_name_is_still_admitted() {
        let key = [3u8; 16];
        let deep = b"/a/b/c/d/e/f/g/h".as_slice(); // MAX_DEPTH components
        let mut f = PrefixFilter::default();
        f.insert_name(&key, deep);
        assert!(
            f.popcount() <= FILL_CAP,
            "a legitimate depth-{MAX_DEPTH} name filled {} bits, over the {FILL_CAP} cap — the cap \
             is mis-sized and would drop real traffic",
            f.popcount()
        );
        let mut mask = PrefixFilter::default();
        mask.insert_name(&key, deep);
        assert!(f.may_match(&mask), "and it must still match its own mask");
    }

    /// The boundary is exact and inclusive: `popcount == FILL_CAP` is admissible, `+1` is not.
    /// Asserted directly because an off-by-one here is either a silent drop of real frames or a
    /// silent hole, and neither shows up as anything but "the link is flaky".
    #[test]
    fn the_cap_boundary_is_exact() {
        let key = [1u8; 16];
        let mut mask = PrefixFilter::default();
        mask.insert_name(&key, b"/x");

        // Build a filter that is a superset of the mask, padded to exactly FILL_CAP bits.
        let mut at_cap = mask;
        let mut p = 0u8;
        while at_cap.popcount() < FILL_CAP && (p as u32) < M_BITS {
            at_cap.set_bit(p);
            p += 1;
        }
        assert_eq!(at_cap.popcount(), FILL_CAP);
        assert!(at_cap.may_match(&mask), "exactly at the cap is admissible");

        // One more bit tips it over.
        let mut over = at_cap;
        while over.popcount() == FILL_CAP && (p as u32) < M_BITS {
            over.set_bit(p);
            p += 1;
        }
        assert_eq!(over.popcount(), FILL_CAP + 1);
        assert!(!over.may_match(&mask), "one bit over the cap is rejected");
    }
}

/// **Tier-0 golden vectors** (F2 / P0.2) — the cross-implementation pin.
///
/// Three copies of this filter exist: this one, the LR2021 firmware `tier0.rs`, and the ath9k-htc C
/// `ndr_tier0.c`. They agree today *by having been edited in sync*, which is not a guarantee — and
/// the failure mode of a divergence is a **silent false negative**, the one error class this design
/// forbids: two nodes in one group simply stop matching each other, on air, with nothing logged.
///
/// So the wire is pinned to a file rather than to a habit. `NDN_TIER0_REGEN=1 cargo test
/// tier0_golden_vectors_are_stable` rewrites it; every other implementation reads and asserts it.
/// A parameter change is then a visible diff in a checked-in artefact, reviewed on purpose,
/// instead of a number that drifted in one of three files.
///
/// Rows are chosen to catch the failures that actually happen here:
/// * depth 2 / depth 8 — the ordinary range, and the `MAX_DEPTH` boundary
/// * depth 12 — past `MAX_DEPTH`; pins the cap/clamp meeting point (it does *not* equal the depth-8
///   filter — see the test), the seam whose mishandling was a false negative
/// * wrong key — must **not** match, pinning that the filter is keyed at all (doctrine §8)
/// * `FILL_CAP` boundary pair — admissible at the cap, rejected one bit over (F1)
///
/// Each row carries its popcount, which retires the depth-6 comment/assert split by construction:
/// the vectors become the arbiter, and both the prose table and the assert are checked against them.
#[cfg(test)]
mod golden_vectors {
    use super::*;

    const VECTORS: &str = include_str!("../../../../../ndn-radio-drivers/golden/tier0/vectors.txt");

    /// The key every non-"wrong key" row uses. Fixed, published, and not secret — these vectors pin
    /// the *algorithm*, not a deployment's group key.
    const VK: [u8; 16] = *b"ndr/tier0-vec-01";
    const WRONG: [u8; 16] = *b"ndr/tier0-vec-02";

    fn deep_name(depth: usize) -> Vec<u8> {
        let mut n = Vec::new();
        for i in 0..depth {
            n.push(b'/');
            n.extend_from_slice(format!("c{i}").as_bytes());
        }
        n
    }

    fn rows() -> Vec<(String, [u8; 16], Vec<u8>)> {
        vec![
            ("depth2".into(), VK, b"/ndn/alarm".to_vec()),
            ("depth8".into(), VK, deep_name(8)),
            ("depth12-over-cap".into(), VK, deep_name(12)),
            ("wrongkey".into(), WRONG, b"/ndn/alarm".to_vec()),
        ]
    }

    fn render() -> String {
        let mut out = String::new();
        out.push_str("# Tier0Params v2 — the shared wire parameter set. Generated by\n");
        out.push_str("# ndn-face-monitor-wifi tier0::golden_vectors; asserted by every implementation.\n");
        out.push_str("# Regenerate: NDN_TIER0_REGEN=1 cargo test -p ndn-face-monitor-wifi tier0_golden\n");
        out.push_str(&format!(
            "params version=2 k={K} m={M_BITS} max_depth={MAX_DEPTH} fill_cap={FILL_CAP} \
             hash=siphash24 key_len=16 norm=ndn_name_to_slash reserved_mask0=0x{RESERVED_MASK0:02x}\n"
        ));
        out.push_str("# row <label> <key-ascii> <name> <16 wire bytes hex> <popcount>\n");
        for (label, key, name) in rows() {
            let mut f = PrefixFilter::default();
            f.insert_name(&key, &name);
            let wire: String = f.to_wire().iter().map(|b| format!("{b:02x}")).collect();
            out.push_str(&format!(
                "row {label} {} {} {wire} {}\n",
                std::str::from_utf8(&key).unwrap(),
                std::str::from_utf8(&name).unwrap(),
                f.popcount()
            ));
        }
        out
    }

    /// The vectors are stable, and the file is the arbiter. Set `NDN_TIER0_REGEN=1` to rewrite it —
    /// which should only ever accompany a deliberate, reviewed `Tier0Params` change.
    #[test]
    fn tier0_golden_vectors_are_stable() {
        let generated = render();
        if std::env::var("NDN_TIER0_REGEN").is_ok() {
            let path = concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../../../ndn-radio-drivers/golden/tier0/vectors.txt"
            );
            std::fs::write(path, &generated).expect("write vectors");
            return;
        }
        assert_eq!(
            generated.trim(),
            VECTORS.trim(),
            "Tier-0 wire output no longer matches the checked-in vectors. If this change is \
             intended, it is a Tier0Params change: bump the version, regenerate with \
             NDN_TIER0_REGEN=1, and update the other two implementations in the same commit — a \
             divergence here is a SILENT false negative on air."
        );
    }

    /// The behavioural claims the vectors encode, asserted directly so the file cannot be
    /// regenerated into something meaningless.
    #[test]
    fn the_vectors_encode_the_properties_they_exist_to_pin() {
        // **The depth cap and the registered-prefix clamp meet here, and the vectors made it
        // visible.** A depth-12 name does NOT produce the depth-8 name's filter: `for_each_prefix`
        // returns at the cap *before* emitting the full name, so the 12-component name inserts the
        // root plus 7 proper prefixes (24 bits here) while the 8-component name also inserts itself
        // (27 bits). What makes that sound is `clamp_prefix`: a *registered* prefix is truncated to
        // MAX_DEPTH-1 components, so the mask a receiver builds is one both senders inserted. That
        // is the false negative `clamp_prefix` exists to prevent, and this asserts the meeting
        // point rather than the folklore that "12 clamps to 8".
        let (mut d8, mut d12) = (PrefixFilter::default(), PrefixFilter::default());
        d8.insert_name(&VK, &deep_name(8));
        d12.insert_name(&VK, &deep_name(12));
        let mask8 = PrefixFilter::mask_for(&VK, &deep_name(8));
        assert!(d12.may_match(&mask8), "a depth-12 name must still match its depth-8 prefix mask");

        // Keyed, not merely hashed: the same name under another key must not match.
        let right = PrefixFilter::mask_for(&VK, b"/ndn/alarm");
        let mut wrong = PrefixFilter::default();
        wrong.insert_name(&WRONG, b"/ndn/alarm");
        assert!(
            !wrong.may_match(&right),
            "the same name under a different group key must not match — the filter is keyed (§8)"
        );

        // And the popcounts in the file agree with the depth table the prose quotes.
        // Fill is a property of the NAME, not just its depth: at m=126 this 8-component name sets 33
        // bits, while the tests' `make_name` shape sets 34 at the same depth. FILL_CAP (64) was sized
        // against the larger, so quote 34 as the worst case observed and never as a formula.
        assert_eq!(d8.popcount(), 33);
        assert!(d8.popcount() <= FILL_CAP, "and every legitimate shape stays under the cap");
    }
}
