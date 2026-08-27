//! **The NDN-NIC baseline** (#101) — receiver-side Bloom filtering over registered prefixes.
//!
//! Shi, Liang, Wu, Liu & Zhang, *NDN-NIC: Name-based Filtering on Network Interface Card* (ICN'16).
//! Their NIC holds BF-FIB / BF-PIT / BF-CS totalling 16 KB, **parses the incoming name**, and tests
//! it against those filters, dropping 96.30% of received packets.
//!
//! This module implements the BF-FIB half — the part that answers "is this name under something I
//! serve?" — so Tier-0 can be measured *against* it on identical traffic instead of against a number
//! quoted from a paper. It is a baseline, not a candidate: nothing selects it in production.
//!
//! ## The two are not the same measurement, and the comparison must say so
//!
//! `named-filter-mac-redesign.md` §8.1 is explicit that "99.6% in 12 bytes vs 96.30% in 16 KB" is
//! rhetorically neat and misleading:
//!
//! | | NDN-NIC (this module) | Tier-0 ([`crate::tier0`]) |
//! |---|---|---|
//! | what is compressed | **the receiver's wants** — 10⁵⁺ names into 16 KB | **the frame's name** — one prefix set into 12 bytes |
//! | where it lives | receiver-side table | on the air, every frame, forever |
//! | needs the name parsed? | **yes** | **no** |
//! | per-frame work | O(name depth) BF probes | O(E) mask ANDs, E = registered prefixes |
//! | wire cost | 0 bytes | 12 bytes/frame |
//! | receiver state | 16 KB | 12 bytes × E |
//!
//! So Tier-0 is not "the same result with a thousand times less memory" — it is **the same job moved
//! earlier in the pipeline**, paid for in permanent airtime. A comparison that reports only rejection
//! rates hides exactly the axis where they differ, which is why [`Comparison`] carries the costs.
//!
//! ## Deliberate deviations from the paper
//!
//! - **`siphash24`, not H3.** The paper uses two H3 hashes (cheap in NIC gate logic). Using our one
//!   keyed hash keeps the A/B about the *architecture* rather than about hash choice, and H3 is
//!   rejected for our use on security grounds anyway (§3.1 — universal, not a PRF).
//! - **BF-FIB only.** BF-PIT and BF-CS are Tier-1's business (#92) and answer a different question;
//!   including them here would compare a two-tier design against a one-tier one.
//! - **No Active CS.** Rejected on cost-model grounds in §2: it trades exact-match false positives
//!   for prefix-match ones, and on a radio a false positive costs a wakeup, a decode and possibly an
//!   on-air relay — not a PCIe transfer.
//!
//! ## ⚠ These numbers are NOT comparable to the paper's 96.30%
//!
//! Three reasons, any one of which is disqualifying:
//!
//! 1. **Different traffic.** The paper's 96.30% is over their trace. A rejection rate is mostly a
//!    property of *how much of the traffic the receiver actually wants*, not of the filter. Our
//!    synthetic mix has a different wanted-fraction, so the numbers cannot be laid side by side.
//! 2. **BF-FIB only.** Their 96.30% is BF-FIB **+ BF-PIT + BF-CS** together. We implement one of the
//!    three, because the other two answer Tier-1's question (#92). A like-for-like drop rate is not
//!    available from this module at all.
//! 3. **Utterly different loading.** Paper: n ≈ 10⁵ names in 16 KB. Here: E = 2..128 prefixes in
//!    24..1536 B. Bloom-filter behaviour is a function of bits-per-key; these are different regimes.
//!
//! **Raw reject is also not comparable across rows of our own sweep**, which the first version of
//! this A/B got wrong: registering more prefixes makes more of the traffic genuinely wanted, so a
//! *perfect* filter's reject rate falls (99.2% at E=2 down to 49.6% at E=128). Reporting raw reject
//! alone turned a moving ceiling into what looked like filter degradation. The comparable figures are
//! **achieved fraction of that ceiling** and **FP over irrelevant frames** — both are in the output.

use crate::tier0::{for_each_prefix, name_hash};

/// The paper's BF-FIB/PIT/CS budget, for a like-for-like default.
pub const PAPER_TABLE_BYTES: usize = 16 * 1024;

/// The paper's k. Their regime (n ≈ 10⁵ keys, m = 65536 bits) makes k=2 optimal; ours does not, which
/// is precisely the sort of parameter that must not be copied across regimes without re-deriving —
/// see the `K` doc in [`crate::tier0`] for how expensive that lesson was.
pub const PAPER_K: u32 = 2;

/// A receiver-side Bloom filter over the prefixes this node serves — the paper's BF-FIB.
///
/// Queried with a **parsed** name: every prefix of the name is probed, and any hit admits the packet.
/// That is longest-prefix-match semantics done probabilistically, and like Tier-0 it has no false
/// negatives — a registered prefix's bits are always set, so a genuine match can never be missed.
#[derive(Clone)]
pub struct NdnNicFilter {
    bits: Vec<u8>,
    k: u32,
    key: [u8; 16],
    /// Prefixes inserted — recorded so [`Comparison`] can report table occupancy honestly.
    inserted: usize,
}

impl NdnNicFilter {
    /// Build a BF-FIB of `table_bytes` over `prefixes`, with `k` probes per prefix.
    pub fn new(key: &[u8; 16], prefixes: &[impl AsRef<[u8]>], table_bytes: usize, k: u32) -> Self {
        let mut f = Self {
            bits: vec![0u8; table_bytes.max(1)],
            k,
            key: *key,
            inserted: prefixes.len(),
        };
        for p in prefixes {
            f.insert(p.as_ref());
        }
        f
    }

    /// The paper's configuration: 16 KB, k = 2.
    pub fn paper_default(key: &[u8; 16], prefixes: &[impl AsRef<[u8]>]) -> Self {
        Self::new(key, prefixes, PAPER_TABLE_BYTES, PAPER_K)
    }

    fn positions(&self, prefix: &[u8]) -> impl Iterator<Item = usize> + '_ {
        let m = (self.bits.len() * 8) as u64;
        let h1 = name_hash(&self.key, prefix);
        let mut key2 = self.key;
        key2[0] ^= 0x5a;
        let h2 = name_hash(&key2, prefix) | 1;
        (0..self.k).map(move |i| (h1.wrapping_add((i as u64).wrapping_mul(h2)) % m) as usize)
    }

    fn insert(&mut self, prefix: &[u8]) {
        for pos in self.positions(prefix).collect::<Vec<_>>() {
            self.bits[pos / 8] |= 1 << (pos % 8);
        }
    }

    fn contains(&self, prefix: &[u8]) -> bool {
        self.positions(prefix)
            .all(|pos| self.bits[pos / 8] & (1 << (pos % 8)) != 0)
    }

    /// **The query — requires the name, i.e. requires a parse.**
    ///
    /// Probes every prefix of `name` root-first and admits on the first hit. This is where the
    /// architectural cost sits: reaching this function at all means the frame has already been
    /// received, reassembled and TLV-decoded far enough to extract the Name.
    pub fn may_serve(&self, name: &[u8]) -> bool {
        let mut hit = false;
        for_each_prefix(name, |pfx| {
            if !hit && self.contains(pfx) {
                hit = true;
            }
        });
        hit
    }

    /// Bits currently set — table occupancy, which drives the false-positive rate.
    pub fn popcount(&self) -> u32 {
        self.bits.iter().map(|b| b.count_ones()).sum()
    }

    /// Receiver-side bytes this filter costs.
    pub fn table_bytes(&self) -> usize {
        self.bits.len()
    }

    /// Registered prefixes summarised.
    pub fn inserted(&self) -> usize {
        self.inserted
    }
}

/// One filter's score over a traffic sample, plus the costs that make the comparison honest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Score {
    pub seen: u32,
    pub accepted: u32,
    pub wanted: u32,
    pub false_pos: u32,
    /// **Must be 0.** A filter that drops a wanted frame is not a filter, it is a bug.
    pub false_neg: u32,
    /// Bytes added to every frame on the air.
    pub wire_bytes_per_frame: usize,
    /// Receiver-side table bytes.
    pub table_bytes: usize,
    /// Does admitting a frame require parsing its name first?
    pub needs_parse: bool,
}

impl Score {
    /// Frames rejected without further work, in ppm of all frames seen.
    pub fn reject_ppm(&self) -> u64 {
        ((self.seen - self.accepted) as u64) * 1_000_000 / self.seen.max(1) as u64
    }

    /// **The filter's true false-positive rate**: of the frames that were genuinely irrelevant, the
    /// share admitted anyway. The only figure comparable across designs — see the note in
    /// `named-filter-mac-redesign.md` about not quoting FP-over-accepted alone.
    pub fn fp_ppm_of_irrelevant(&self) -> u64 {
        let irrelevant = self.seen - self.wanted;
        (self.false_pos as u64) * 1_000_000 / irrelevant.max(1) as u64
    }
}

/// A side-by-side of Tier-0 and the NDN-NIC baseline over one traffic sample.
#[derive(Debug, Clone, Copy)]
pub struct Comparison {
    pub tier0: Score,
    pub ndn_nic: Score,
}

impl Comparison {
    /// A human-readable table, cost axes included. Deliberately not a single "winner" — the two
    /// designs buy different things and a scalar verdict would misrepresent both.
    pub fn report(&self) -> String {
        let row = |n: &str, s: &Score| {
            format!(
                "{n:<10} reject {:>7.3}%  FP(of irrelevant) {:>7.3}%  FN {:>3}  wire {:>3} B/frame  table {:>6} B  parse {}\n",
                s.reject_ppm() as f64 / 10_000.0,
                s.fp_ppm_of_irrelevant() as f64 / 10_000.0,
                s.false_neg,
                s.wire_bytes_per_frame,
                s.table_bytes,
                if s.needs_parse { "REQUIRED" } else { "none" },
            )
        };
        format!(
            "over {} frames ({} genuinely wanted)\n{}{}",
            self.tier0.seen,
            self.tier0.wanted,
            row("tier0", &self.tier0),
            row("ndn-nic", &self.ndn_nic),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tier0::PrefixFilter;

    const KEY: [u8; 16] = *b"ndn/tier0-testk!";

    /// Traffic mix: `NS` top-level namespaces at depth 2..6, of which the receiver registers 2 — the
    /// same shape as the on-air #106 run, so the numbers are comparable to it.
    const NS: u32 = 16;

    fn make_name(ns: u32, seq: u32) -> Vec<u8> {
        let depth = 2 + (seq % 5) as usize;
        let mut out = Vec::new();
        for c in 0..depth {
            out.push(b'/');
            let v = if c == 0 {
                ns
            } else {
                seq.wrapping_add(c as u32 * 7)
            };
            for shift in [12, 8, 4, 0] {
                let d = ((v >> shift) & 0xf) as u8;
                out.push(if d < 10 { b'0' + d } else { b'a' + d - 10 });
            }
        }
        out
    }

    fn registered() -> Vec<Vec<u8>> {
        vec![b"/0003".to_vec(), b"/000a".to_vec()]
    }

    /// **#101 — Tier-0 vs the NDN-NIC baseline on identical traffic.**
    ///
    /// Both must show zero false negatives; the interesting output is the cost matrix, which is the
    /// part a rejection-rate-only comparison hides. Print it with
    /// `cargo test -p ndn-phy-wifi ab_ -- --nocapture`.
    #[test]
    fn ab_tier0_versus_ndn_nic_baseline() {
        const FRAMES: u32 = 20_000;
        let reg = registered();
        let masks: Vec<PrefixFilter> = reg
            .iter()
            .map(|p| PrefixFilter::mask_for(&KEY, p))
            .collect();
        let bf = NdnNicFilter::paper_default(&KEY, &reg);

        let mut t0 = Score {
            seen: 0,
            accepted: 0,
            wanted: 0,
            false_pos: 0,
            false_neg: 0,
            wire_bytes_per_frame: 12,
            table_bytes: masks.len() * 12,
            needs_parse: false,
        };
        let mut nn = Score {
            seen: 0,
            accepted: 0,
            wanted: 0,
            false_pos: 0,
            false_neg: 0,
            wire_bytes_per_frame: 0,
            table_bytes: bf.table_bytes(),
            needs_parse: true,
        };

        for seq in 0..FRAMES {
            let name = make_name(seq % NS, seq);
            // Ground truth: a real prefix match on the name.
            let truth = reg
                .iter()
                .any(|p| name.len() >= p.len() && &name[..p.len()] == &p[..]);

            // Tier-0: the frame carries the filter; the receiver never sees the name.
            let mut frame_bf = PrefixFilter::new();
            frame_bf.insert_name(&KEY, &name);
            let t0_accept = masks.iter().any(|m| frame_bf.may_match(m));

            // NDN-NIC: the receiver must parse the name to ask the question at all.
            let nn_accept = bf.may_serve(&name);

            for (s, accept) in [(&mut t0, t0_accept), (&mut nn, nn_accept)] {
                s.seen += 1;
                s.wanted += truth as u32;
                s.accepted += accept as u32;
                match (accept, truth) {
                    (true, false) => s.false_pos += 1,
                    (false, true) => s.false_neg += 1,
                    _ => {}
                }
            }
        }

        let cmp = Comparison {
            tier0: t0,
            ndn_nic: nn,
        };
        println!("\n#101 A/B — Tier-0 vs NDN-NIC BF-FIB\n{}", cmp.report());

        // The one hard invariant both designs must hold.
        assert_eq!(t0.false_neg, 0, "Tier-0 dropped a wanted frame");
        assert_eq!(nn.false_neg, 0, "NDN-NIC baseline dropped a wanted frame");
        // Both must actually reject the bulk of irrelevant traffic, or the comparison is vacuous.
        assert!(t0.reject_ppm() > 800_000, "Tier-0 reject collapsed");
        assert!(nn.reject_ppm() > 800_000, "NDN-NIC reject collapsed");
    }

    /// **The A/B that actually informs: EQUAL RECEIVER STATE, swept over registered-prefix count.**
    ///
    /// The default comparison above gives NDN-NIC 16 KB to hold 2 prefixes — the paper's table, sized
    /// for 10⁵ names, applied to two. It scores a perfect 87.5% / 0% FP, and that says nothing except
    /// that a filter 5000x over-provisioned does not collide. Reporting it as a win either way would
    /// be rigging the result.
    ///
    /// Held at equal state (NDN-NIC gets exactly the bytes Tier-0's masks occupy, 12 B per registered
    /// prefix) the designs separate on their real axes: Tier-0's receiver work is O(E) and its table
    /// grows with E, while NDN-NIC's work is O(name depth) regardless of E but its FP climbs as the
    /// fixed table fills.
    #[test]
    fn ab_at_equal_receiver_state() {
        const FRAMES: u32 = 8_000;
        println!("\n#101 A/B at EQUAL receiver state (NDN-NIC table = 12 B x registered prefixes)");
        println!("  NOT comparable to the paper's 96.30% — see the module docs. Raw reject is NOT");
        println!(
            "  comparable ACROSS ROWS either: registering more prefixes means more traffic is"
        );
        println!(
            "  genuinely wanted, so the ceiling falls. 'of max' is the filter-quality figure."
        );
        println!(
            "  E     state   wanted   max_rej   tier0 rej (of max) / FP     nic rej (of max) / FP"
        );
        for e in [2usize, 8, 32, 128] {
            // E registered prefixes drawn from the same namespace the traffic uses.
            let reg: Vec<Vec<u8>> = (0..e)
                .map(|i| {
                    let mut v = vec![b'/'];
                    for shift in [12, 8, 4, 0] {
                        let d = (((i as u32) >> shift) & 0xf) as u8;
                        v.push(if d < 10 { b'0' + d } else { b'a' + d - 10 });
                    }
                    v
                })
                .collect();
            let state = reg.len() * 12;
            let masks: Vec<PrefixFilter> = reg
                .iter()
                .map(|p| PrefixFilter::mask_for(&KEY, p))
                .collect();
            let bf = NdnNicFilter::new(&KEY, &reg, state, PAPER_K);

            let (mut t_acc, mut n_acc, mut want, mut t_fp, mut n_fp, mut t_fn, mut n_fn) =
                (0u32, 0u32, 0u32, 0u32, 0u32, 0u32, 0u32);
            for seq in 0..FRAMES {
                let name = make_name(seq % 256, seq);
                let truth = reg
                    .iter()
                    .any(|p| name.len() >= p.len() && &name[..p.len()] == &p[..]);
                let mut fbf = PrefixFilter::new();
                fbf.insert_name(&KEY, &name);
                let ta = masks.iter().any(|m| fbf.may_match(m));
                let na = bf.may_serve(&name);
                want += truth as u32;
                t_acc += ta as u32;
                n_acc += na as u32;
                if ta && !truth {
                    t_fp += 1
                }
                if na && !truth {
                    n_fp += 1
                }
                if !ta && truth {
                    t_fn += 1
                }
                if !na && truth {
                    n_fn += 1
                }
            }
            let irr = (FRAMES - want).max(1);
            // **The ceiling moves with E.** Registering more prefixes makes more of the traffic
            // genuinely wanted, so a PERFECT filter's reject rate falls. Reporting raw reject alone
            // made a moving ceiling look like filter degradation — it is the achieved fraction of
            // the ceiling, and the FP rate, that measure the filter.
            let max_rej = irr as f64 * 100.0 / FRAMES as f64;
            let t_rej = (FRAMES - t_acc) as f64 * 100.0 / FRAMES as f64;
            let n_rej = (FRAMES - n_acc) as f64 * 100.0 / FRAMES as f64;
            println!(
                "  {e:<4}  {state:>5} B  {:>5.1}%  {max_rej:>6.2}%   {t_rej:>6.2}% ({:>5.1}%) / {:>6.3}%   {n_rej:>6.2}% ({:>5.1}%) / {:>6.3}%",
                want as f64 * 100.0 / FRAMES as f64,
                t_rej * 100.0 / max_rej,
                t_fp as f64 * 100.0 / irr as f64,
                n_rej * 100.0 / max_rej,
                n_fp as f64 * 100.0 / irr as f64,
            );
            // The invariant holds at every operating point, for both designs.
            assert_eq!(t_fn, 0, "Tier-0 false negative at E={e}");
            assert_eq!(n_fn, 0, "NDN-NIC false negative at E={e}");
        }
    }

    /// The baseline's false-positive rate must track its table size — the axis the paper spends
    /// 16 KB on. If this is flat, the filter is not doing what the paper's is and the A/B is not
    /// measuring what it claims.
    #[test]
    fn baseline_fp_falls_as_the_table_grows() {
        let reg: Vec<Vec<u8>> = (0..200u32).map(|i| make_name(i, i)).collect();
        let mut prev = u64::MAX;
        for bytes in [64usize, 256, 1024, 16384] {
            let bf = NdnNicFilter::new(&KEY, &reg, bytes, PAPER_K);
            let mut fp = 0u32;
            const T: u32 = 4_000;
            for t in 0..T {
                let other = make_name(0xf000 + t, t);
                if bf.may_serve(&other) {
                    fp += 1;
                }
            }
            let ppm = (fp as u64) * 1_000_000 / T as u64;
            println!(
                "  table {bytes:>6} B: popcount {:>6}  FP {ppm} ppm",
                bf.popcount()
            );
            assert!(
                ppm <= prev,
                "FP rose from {prev} to {ppm} ppm as the table grew"
            );
            prev = ppm;
        }
    }
}
