//! FEC repair groups over `ndn-coding`'s systematic K-of-N MDS codec.
//!
//! Stream seqs are grouped `K` at a time (group `g` covers seqs
//! `[g·K, g·K + K)`); the producer emits `R` parity items per complete group,
//! and a consumer holding **any K of the K+R items** recovers the rest —
//! strictly stronger than fixed XOR-one/GF256-two parity at the same overhead
//! (any-R-losses per group, not specific patterns).
//!
//! Stream items vary in length while the codec needs equal-length segments, so
//! each source item is framed `u32-be length ‖ payload` and zero-padded to the
//! group's widest frame; parity rows inherit that width and recovery strips
//! the framing. The codec itself is `ndn_coding::fec` (Vandermonde GF(2⁸)) —
//! this module only does the group bookkeeping.

use std::collections::{BTreeMap, HashMap};

use bytes::{BufMut, Bytes, BytesMut};
use ndn_coding::fec::{Decoder, Encoder};

/// Which repair group a seq belongs to, for group size `k`.
pub fn group_of(seq: u64, k: u16) -> u64 {
    seq / u64::from(k.max(1))
}

/// FEC shape: `k` source items per group, `r` parity items on top.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FecConfig {
    /// Source items per group.
    pub k: u16,
    /// Parity items per group (any `r` losses per group are recoverable).
    pub r: u16,
}

/// A parity item the producer must publish.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParityItem {
    /// The repair group.
    pub group: u64,
    /// Parity index within the group (`0..r`).
    pub index: u16,
    /// The parity bytes (opaque to the transport).
    pub payload: Bytes,
}

fn frame(payload: &Bytes, width: usize) -> Bytes {
    let mut b = BytesMut::with_capacity(width);
    b.put_u32(payload.len() as u32);
    b.extend_from_slice(payload);
    b.resize(width, 0);
    b.freeze()
}

fn unframe(row: &Bytes) -> Option<Bytes> {
    if row.len() < 4 {
        return None;
    }
    let len = u32::from_be_bytes([row[0], row[1], row[2], row[3]]) as usize;
    if 4 + len > row.len() {
        return None;
    }
    Some(row.slice(4..4 + len))
}

/// Producer-side parity generation: feed source items in seq order; every
/// complete group yields its parity items. An incomplete trailing group emits
/// nothing (parity spans exactly `k` sources — end a stream on a group
/// boundary if the tail must be protected).
#[derive(Debug)]
pub struct GroupEncoder {
    cfg: FecConfig,
    current: Vec<Bytes>,
    next_seq: u64,
}

impl GroupEncoder {
    /// An encoder for streams whose first seq is `first_seq`.
    pub fn new(first_seq: u64, cfg: FecConfig) -> Self {
        Self {
            cfg,
            current: Vec::new(),
            next_seq: first_seq,
        }
    }

    /// The seq the next pushed item must carry (items feed strictly in order).
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Feed the item at the next seq. Returns the group's parity items when
    /// this item completes a group. Panics never; a `r = 0` config simply
    /// yields no parity.
    pub fn push(&mut self, payload: Bytes) -> Vec<ParityItem> {
        let seq = self.next_seq;
        self.next_seq += 1;
        self.current.push(payload);
        if self.current.len() < usize::from(self.cfg.k.max(1)) {
            return Vec::new();
        }
        let group = group_of(seq, self.cfg.k);
        let items = self.emit(group);
        self.current.clear();
        items
    }

    fn emit(&self, group: u64) -> Vec<ParityItem> {
        if self.cfg.r == 0 {
            return Vec::new();
        }
        let width = self.current.iter().map(|p| 4 + p.len()).max().unwrap_or(4);
        let n = self.cfg.k + self.cfg.r;
        let Ok(mut enc) = Encoder::new(self.cfg.k, n) else {
            tracing::warn!(k = self.cfg.k, n, "invalid FEC shape — emitting no parity");
            return Vec::new();
        };
        for p in &self.current {
            if enc.feed(frame(p, width)).is_err() {
                return Vec::new();
            }
        }
        (0..self.cfg.r)
            .filter_map(|i| {
                enc.parity(self.cfg.k + i).ok().map(|payload| ParityItem {
                    group,
                    index: i,
                    payload,
                })
            })
            .collect()
    }
}

#[derive(Default)]
struct GroupState {
    /// In-group index (0..k) → raw source payload.
    sources: BTreeMap<u16, Bytes>,
    /// Parity index (0..r) → parity row.
    parities: BTreeMap<u16, Bytes>,
    recovered: bool,
}

/// Consumer-side recovery: collect a group's sources and parities; once any
/// `k` of its `k+r` items are present, the missing sources are reconstructed.
pub struct GroupDecoder {
    cfg: FecConfig,
    groups: HashMap<u64, GroupState>,
}

impl GroupDecoder {
    /// A decoder for the given shape.
    pub fn new(cfg: FecConfig) -> Self {
        Self {
            cfg,
            groups: HashMap::new(),
        }
    }

    /// Offer a received source item, then try recovery for its group.
    /// Returns any sources newly reconstructed (never includes `seq` itself).
    pub fn add_source(&mut self, seq: u64, payload: Bytes) -> Vec<(u64, Bytes)> {
        let group = group_of(seq, self.cfg.k);
        let idx = (seq % u64::from(self.cfg.k.max(1))) as u16;
        let state = self.groups.entry(group).or_default();
        state.sources.entry(idx).or_insert(payload);
        self.try_recover(group)
    }

    /// Offer a received parity item, then try recovery for its group.
    pub fn add_parity(&mut self, item: ParityItem) -> Vec<(u64, Bytes)> {
        if item.index >= self.cfg.r {
            return Vec::new();
        }
        let state = self.groups.entry(item.group).or_default();
        state.parities.entry(item.index).or_insert(item.payload);
        self.try_recover(item.group)
    }

    /// Drop state for groups entirely below `seq` (the delivery cursor) —
    /// bounded memory; call as the stream advances.
    pub fn evict_below(&mut self, seq: u64) {
        let keep_from = group_of(seq, self.cfg.k);
        self.groups.retain(|&g, _| g >= keep_from);
    }

    /// Tracked group count (bounded by eviction).
    pub fn tracked_groups(&self) -> usize {
        self.groups.len()
    }

    fn try_recover(&mut self, group: u64) -> Vec<(u64, Bytes)> {
        let k = usize::from(self.cfg.k.max(1));
        let Some(state) = self.groups.get_mut(&group) else {
            return Vec::new();
        };
        if state.recovered
            || state.sources.len() >= k
            || state.parities.is_empty()
            || state.sources.len() + state.parities.len() < k
        {
            return Vec::new();
        }
        // Row width comes from the parity rows (sources arrive unframed).
        let width = state.parities.values().map(Bytes::len).max().unwrap_or(0);
        if state.parities.values().any(|p| p.len() != width)
            || state.sources.values().any(|s| 4 + s.len() > width)
        {
            tracing::warn!(group, "inconsistent FEC row widths — refusing recovery");
            return Vec::new();
        }
        let n = self.cfg.k + self.cfg.r;
        let Ok(mut dec) = Decoder::new(self.cfg.k, n) else {
            return Vec::new();
        };
        for (&idx, payload) in &state.sources {
            let _ = dec.absorb(idx, frame(payload, width));
        }
        for (&idx, row) in &state.parities {
            let _ = dec.absorb(self.cfg.k + idx, row.clone());
        }
        if !dec.is_complete() {
            return Vec::new();
        }
        let Ok(rows) = dec.recover() else {
            return Vec::new();
        };
        let missing: Vec<u16> = (0..self.cfg.k)
            .filter(|i| !state.sources.contains_key(i))
            .collect();
        let mut out = Vec::new();
        for idx in missing {
            let Some(payload) = unframe(&rows[usize::from(idx)]) else {
                tracing::warn!(group, idx, "recovered row failed to unframe");
                continue;
            };
            state.sources.insert(idx, payload.clone());
            out.push((group * u64::from(self.cfg.k) + u64::from(idx), payload));
        }
        state.recovered = true;
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b(s: &str) -> Bytes {
        Bytes::copy_from_slice(s.as_bytes())
    }

    fn shape(k: u16, r: u16) -> FecConfig {
        FecConfig { k, r }
    }

    #[test]
    fn parity_emits_per_complete_group() {
        let mut enc = GroupEncoder::new(0, shape(3, 2));
        assert!(enc.push(b("a")).is_empty());
        assert!(enc.push(b("bb")).is_empty());
        let parity = enc.push(b("ccc"));
        assert_eq!(parity.len(), 2);
        assert_eq!(parity[0].group, 0);
        // Next group starts clean.
        assert!(enc.push(b("d")).is_empty());
        assert_eq!(enc.next_seq(), 4);
    }

    #[test]
    fn one_loss_recovers_from_one_parity() {
        let mut enc = GroupEncoder::new(0, shape(3, 1));
        enc.push(b("alpha"));
        enc.push(b("bee"));
        let parity = enc.push(b("c"));

        let mut dec = GroupDecoder::new(shape(3, 1));
        // seq 1 ("bee") is lost.
        assert!(dec.add_source(0, b("alpha")).is_empty());
        assert!(dec.add_source(2, b("c")).is_empty());
        let recovered = dec.add_parity(parity[0].clone());
        assert_eq!(recovered, vec![(1, b("bee"))]);
    }

    #[test]
    fn r_losses_recover_from_r_parities_any_pattern() {
        // The MDS property upstream's XOR-one can't offer: TWO losses in one
        // group, recovered from the two parity items.
        let mut enc = GroupEncoder::new(0, shape(4, 2));
        enc.push(b("s0"));
        enc.push(b("s1-long-payload"));
        enc.push(b("s2"));
        let parity = enc.push(b("s3"));
        assert_eq!(parity.len(), 2);
        let mut dec = GroupDecoder::new(shape(4, 2));
        dec.add_source(0, b("s0"));
        dec.add_source(3, b("s3"));
        dec.add_parity(parity[0].clone());
        let recovered = dec.add_parity(parity[1].clone());
        let mut got: Vec<(u64, Bytes)> = recovered;
        got.sort_by_key(|(s, _)| *s);
        assert_eq!(got, vec![(1, b("s1-long-payload")), (2, b("s2"))]);
    }

    #[test]
    fn no_recovery_below_k_items() {
        let mut enc = GroupEncoder::new(0, shape(3, 1));
        enc.push(b("a"));
        enc.push(b("b"));
        let parity = enc.push(b("c"));
        let mut dec = GroupDecoder::new(shape(3, 1));
        dec.add_source(0, b("a"));
        // Only 2 of 3 needed items: nothing recovers.
        assert!(dec.add_parity(parity[0].clone()).is_empty());
    }

    #[test]
    fn recovery_fires_once_per_group() {
        let mut enc = GroupEncoder::new(0, shape(2, 1));
        enc.push(b("x"));
        let parity = enc.push(b("y"));
        let mut dec = GroupDecoder::new(shape(2, 1));
        dec.add_source(0, b("x"));
        assert_eq!(dec.add_parity(parity[0].clone()), vec![(1, b("y"))]);
        // The late real item changes nothing and re-recovers nothing.
        assert!(dec.add_source(1, b("y")).is_empty());
    }

    #[test]
    fn eviction_bounds_group_state() {
        let mut dec = GroupDecoder::new(shape(2, 1));
        for seq in 0..20 {
            dec.add_source(seq, b("s"));
        }
        assert_eq!(dec.tracked_groups(), 10);
        dec.evict_below(16);
        assert_eq!(dec.tracked_groups(), 2);
    }

    #[test]
    fn seq_grouping_is_stable() {
        assert_eq!(group_of(0, 4), 0);
        assert_eq!(group_of(3, 4), 0);
        assert_eq!(group_of(4, 4), 1);
        assert_eq!(group_of(11, 4), 2);
    }
}
