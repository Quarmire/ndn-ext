//! **GCS-in-frame** — the Golomb-Coded Set prefix-set filter for bit-starved, sequential-decode
//! bearers (LoRa / FLRC), where the filter rides the frame **body**, not the 802.11 address fields.
//!
//! Same keyed-SipHash keyspace as the address Blur (#44) and the same **zero-false-negative** guarantee
//! — only the *structure* differs. GCS packs ~`log2(1/ε)` bits per prefix against Bloom's
//! ~`1.44·log2(1/ε)` (the ~30% "decimal bits" win, measured in `gcs_fp.rs`), at the cost of
//! **sequential** (not random-access) decode. Sequential is free in a body field and forbidden in an
//! address field — which is exactly why Bloom stays the address floor and GCS is the body tier
//! (`wire-format-spec.md` §2a). On an 802.11 monitor bearer there is nothing to gain (the 12+ address
//! bytes are already paid for); on a LoRa frame every byte is airtime, so the ~30% is real.
//!
//! ## Wire format
//!
//! ```text
//!   [ n : u8 ] [ Rice-coded sorted gaps, MSB-first ]
//! ```
//!
//! `n` is the prefix count — it fixes the hash range `U = n · 2^P`, which both encoder and receiver
//! need to map a name into the same value space (BIP158 does the same). The Rice parameter `P` sets the
//! false-positive rate `ε ≈ 2^-P`. Each gap is `q` ones + a terminating `0` (the quotient, unary) then
//! `P` remainder bits.

use crate::tier0::{MAX_DEPTH, clamp_prefix, for_each_prefix, name_hash};

/// Rice/Golomb parameter: `M = 2^P`, so `ε ≈ 2^-P`. `8` → ~0.39%, comparable to the 126-bit address
/// Blur at the depth cap — a shared wire parameter, like the Blur's `k`/`m` (every implementation must
/// agree or they disagree about which frames match).
pub const GCS_P: u32 = 8;

/// Max prefixes in one name's set (root + the depth cap).
const MAX_PREFIXES: usize = MAX_DEPTH + 1;

/// Body-field capacity — `MAX_PREFIXES` gaps at `P` bits + unary overhead, rounded up with headroom.
pub const GCS_MAX_BYTES: usize = 24;

/// A prefix-set as a Golomb-Coded Set. Fixed-buffer + bit length ⇒ no heap, no_std-portable to the
/// firmware exactly as `PrefixFilter` is.
#[derive(Clone, Copy, Debug)]
pub struct GcsFilter {
    /// Prefix count — fixes the hash range and rides the wire.
    n: u8,
    /// Bits used in `bytes`.
    bit_len: u16,
    bytes: [u8; GCS_MAX_BYTES],
}

/// MSB-first bit writer over a fixed buffer.
struct BitW<'a> {
    buf: &'a mut [u8],
    pos: usize,
}
impl BitW<'_> {
    fn bit(&mut self, b: u32) {
        if b & 1 != 0 && self.pos / 8 < self.buf.len() {
            self.buf[self.pos / 8] |= 1 << (7 - self.pos % 8);
        }
        self.pos += 1;
    }
    fn bits(&mut self, v: u64, n: u32) {
        for i in (0..n).rev() {
            self.bit(((v >> i) & 1) as u32);
        }
    }
    /// Rice code: `q` ones + a `0`, then `P` remainder bits.
    fn rice(&mut self, gap: u64, p: u32) {
        for _ in 0..(gap >> p) {
            self.bit(1);
        }
        self.bit(0);
        self.bits(gap & ((1 << p) - 1), p);
    }
}

/// MSB-first bit reader bounded by `len` bits.
struct BitR<'a> {
    buf: &'a [u8],
    pos: usize,
    len: usize,
}
impl BitR<'_> {
    fn bit(&mut self) -> Option<u32> {
        if self.pos >= self.len {
            return None;
        }
        let b = (self.buf[self.pos / 8] >> (7 - self.pos % 8)) & 1;
        self.pos += 1;
        Some(b as u32)
    }
    fn bits(&mut self, n: u32) -> Option<u64> {
        let mut v = 0u64;
        for _ in 0..n {
            v = (v << 1) | self.bit()? as u64;
        }
        Some(v)
    }
    fn rice(&mut self, p: u32) -> Option<u64> {
        let mut q = 0u64;
        while self.bit()? == 1 {
            q += 1;
        }
        Some((q << p) | self.bits(p)?)
    }
}

impl GcsFilter {
    /// Encode every prefix of `name` (root-first, capped at `MAX_DEPTH`) as a GCS.
    pub fn from_name(key: &[u8; 16], name: &[u8]) -> Self {
        let mut vals = [0u64; MAX_PREFIXES];
        let mut n = 0usize;
        for_each_prefix(name, |pfx| {
            if n < MAX_PREFIXES {
                vals[n] = name_hash(key, pfx);
                n += 1;
            }
        });
        let m = (n as u64) << GCS_P; // U = n · 2^P
        let vs = &mut vals[..n];
        for v in vs.iter_mut() {
            *v = if m > 0 { *v % m } else { 0 };
        }
        vs.sort_unstable();

        let mut bytes = [0u8; GCS_MAX_BYTES];
        let mut w = BitW { buf: &mut bytes, pos: 0 };
        let mut prev = 0u64;
        let mut first = true;
        for &v in vs.iter() {
            if !first && v == prev {
                continue; // dedup: a collision after `% m` is one value, not two
            }
            w.rice(v - prev, GCS_P);
            prev = v;
            first = false;
        }
        Self { n: n as u8, bit_len: w.pos as u16, bytes }
    }

    /// Could a name carrying this filter be under `prefix`? `false` is **exact** (zero false negatives);
    /// `true` may be a false positive costing a parse — the same contract as the address Blur.
    pub fn may_match(&self, key: &[u8; 16], prefix: &[u8]) -> bool {
        let prefix = &prefix[..clamp_prefix(prefix)];
        let m = (self.n as u64) << GCS_P;
        if m == 0 {
            return false;
        }
        let qv = name_hash(key, prefix) % m;
        let mut r = BitR { buf: &self.bytes, pos: 0, len: self.bit_len as usize };
        let mut acc = 0u64;
        while let Some(gap) = r.rice(GCS_P) {
            acc += gap;
            if acc == qv {
                return true;
            }
            if acc > qv {
                return false; // the set is sorted — we have passed where qv would be
            }
        }
        false
    }

    /// Serialize to `out` (`[n][gap bytes]`); returns the byte count written. The whole point of GCS:
    /// this is **variable-length and small**, unlike the address Blur's fixed 16 bytes.
    pub fn to_wire(&self, out: &mut [u8]) -> usize {
        let nbytes = (self.bit_len as usize).div_ceil(8);
        out[0] = self.n;
        out[1..1 + nbytes].copy_from_slice(&self.bytes[..nbytes]);
        1 + nbytes
    }

    /// The wire size (`[n] + gap bytes`) this filter would occupy.
    pub fn wire_len(&self) -> usize {
        1 + (self.bit_len as usize).div_ceil(8)
    }

    /// Reconstruct from the on-wire bytes. Trailing pad bits decode as zero-gaps and cannot create a
    /// match (they never advance `acc`), so the exact bit length need not ride the wire.
    pub fn from_wire(wire: &[u8]) -> Self {
        let n = wire.first().copied().unwrap_or(0);
        let body = wire.get(1..).unwrap_or(&[]);
        let nb = body.len().min(GCS_MAX_BYTES);
        let mut bytes = [0u8; GCS_MAX_BYTES];
        bytes[..nb].copy_from_slice(&body[..nb]);
        Self { n, bit_len: (nb * 8) as u16, bytes }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tier0::PrefixFilter;

    const KEY: [u8; 16] = *b"ndn/gcs-test-key";

    fn deep(depth: usize) -> Vec<u8> {
        let mut v = Vec::new();
        for i in 0..depth {
            v.push(b'/');
            v.extend_from_slice(format!("c{i}").as_bytes());
        }
        v
    }

    /// **The property that governs the whole design: never a false negative.** Every prefix a sender
    /// would have inserted for a name must match — through a wire round-trip, at every depth.
    #[test]
    fn gcs_has_zero_false_negatives() {
        for depth in 1..=10usize {
            let name = deep(depth);
            let f = GcsFilter::from_name(&KEY, &name);
            let mut wire = [0u8; GCS_MAX_BYTES + 1];
            let len = f.to_wire(&mut wire);
            let back = GcsFilter::from_wire(&wire[..len]);
            // Every genuine prefix of the name (clamped like a registration) must be admitted.
            for d in 1..=depth.min(MAX_DEPTH - 1) {
                let pfx = deep(d);
                assert!(
                    back.may_match(&KEY, &pfx),
                    "FALSE NEGATIVE: name depth {depth}, prefix depth {d}"
                );
            }
            // And the root always matches.
            assert!(back.may_match(&KEY, b"/"), "root must match at depth {depth}");
        }
    }

    /// GCS must be **smaller on the wire** than the fixed 16-byte address Blur for a realistic name —
    /// that byte saving is the entire reason to carry it on a bit-starved bearer.
    #[test]
    fn gcs_is_smaller_than_the_address_bloom() {
        for depth in [4usize, 6, 8] {
            let name = deep(depth);
            let gcs = GcsFilter::from_name(&KEY, &name).wire_len();
            let bloom = 16; // PrefixFilter::to_wire() is always 16 bytes
            assert!(
                gcs < bloom,
                "GCS ({gcs} B) should undercut the 16 B Bloom at depth {depth}"
            );
        }
    }

    /// False positives are allowed but must stay near the target ε ≈ 2^-P. Measured over many
    /// disjoint queries against one deep name — the same methodology as the Blur's FP test.
    #[test]
    fn gcs_false_positive_rate_is_near_target() {
        let name = deep(8);
        let f = GcsFilter::from_name(&KEY, &name);
        let (mut fp, trials) = (0u32, 20_000u32);
        for t in 0..trials {
            // A disjoint query namespace so a hit is a genuine false positive, not a real ancestor.
            let q = format!("/zzz/{t:x}");
            if f.may_match(&KEY, q.as_bytes()) {
                fp += 1;
            }
        }
        let ppm = fp as u64 * 1_000_000 / trials as u64;
        // ε ≈ 2^-8 ≈ 3900 ppm; allow generous slack for the small set + hash variance.
        assert!(ppm < 12_000, "FP {ppm} ppm is far above the ~3900 ppm target");
    }

    /// Cross-check the shared keyspace: the SAME name under the SAME key admits the same prefixes in
    /// both structures (GCS and the address Blur), so a deployment can pick per bearer with no
    /// re-registration — only the encoding differs, never which names match.
    #[test]
    fn gcs_and_bloom_agree_on_membership() {
        let name = deep(6);
        let gcs = GcsFilter::from_name(&KEY, &name);
        let mut bloom = PrefixFilter::new();
        bloom.insert_name(&KEY, &name);
        for d in 1..=5usize {
            let pfx = deep(d);
            let mask = PrefixFilter::mask_for(&KEY, &pfx);
            assert_eq!(
                gcs.may_match(&KEY, &pfx),
                bloom.may_match(&mask),
                "GCS and Bloom disagree on prefix depth {d} (both should admit a true prefix)"
            );
        }
    }
}
