//! Reception reports — the cooperative, named-data channel that turns N
//! locally-sensing radios into one shared view.
//!
//! Each node periodically broadcasts what it observes: which **neighbors it hears
//! and at what RSSI**, which **prefixes it holds** (receiver multiplicity / COPE
//! side-info), and its **per-channel spectrum view** (cooperative spectrum
//! sensing). Reports travel as named, signed, cacheable Data on a hop-local
//! namespace (e.g. `/localhop/radio/report/<node>`); this module defines the
//! report **value** (the content bytes) — the NDN-Data wrapping is the
//! integration's job, keeping this crate packet-free.
//!
//! The headline use: a neighbor's report that says *"I hear node X at −55 dBm"*
//! gives node X its **measured outbound** link quality to that neighbor — better
//! than the reciprocity guess, and the thing that closes the on-air rate/power
//! loop without a custom handshake.
//!
//! Encoding is compact, versioned, and **bounded** (≤ [`MAX_ENTRIES`] per list) so
//! a malicious or buggy peer can't blow up frame size or memory.

/// Reception-report content magic (first byte).
pub const REPORT_MAGIC: u8 = 0xCD;
/// Report wire version.
pub const REPORT_VERSION: u8 = 1;
/// Max entries encoded/accepted per list (bounded state).
pub const MAX_ENTRIES: usize = 32;

/// A node's snapshot of what it observes, shared with neighbors.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ReceptionReport {
    /// The reporting node's id.
    pub node_id: u64,
    /// Monotonic report sequence (anti-rollback / freshness).
    pub seq: u32,
    /// Reporter's timestamp (ms); receivers re-stamp with their own clock.
    pub ts_ms: u64,
    /// Neighbors the reporter hears, and at what RSSI (dBm). The entry where the
    /// neighbour id == *your* node id is your measured outbound link to the reporter.
    pub heard_neighbors: Vec<(u64, i8)>,
    /// Prefix-hashes the reporter recently heard / holds.
    pub heard_prefixes: Vec<u64>,
    /// The reporter's per-channel busy% view: `(channel, busy_pct)`.
    pub spectrum: Vec<(u8, u8)>,
}

/// Encode a report to its content bytes (lists truncated to [`MAX_ENTRIES`]).
pub fn encode_report(r: &ReceptionReport) -> Vec<u8> {
    let mut b = Vec::with_capacity(32);
    b.push(REPORT_MAGIC);
    b.push(REPORT_VERSION);
    b.extend_from_slice(&r.node_id.to_le_bytes());
    b.extend_from_slice(&r.seq.to_le_bytes());
    b.extend_from_slice(&r.ts_ms.to_le_bytes());

    let nn = r.heard_neighbors.len().min(MAX_ENTRIES);
    b.push(nn as u8);
    for (id, rssi) in r.heard_neighbors.iter().take(nn) {
        b.extend_from_slice(&id.to_le_bytes());
        b.push(*rssi as u8);
    }
    let np = r.heard_prefixes.len().min(MAX_ENTRIES);
    b.push(np as u8);
    for p in r.heard_prefixes.iter().take(np) {
        b.extend_from_slice(&p.to_le_bytes());
    }
    let ns = r.spectrum.len().min(MAX_ENTRIES);
    b.push(ns as u8);
    for (c, busy) in r.spectrum.iter().take(ns) {
        b.push(*c);
        b.push(*busy);
    }
    b
}

/// Cursor with bounds checks for safe decoding of untrusted peer bytes.
struct Reader<'a> {
    b: &'a [u8],
    i: usize,
}
impl<'a> Reader<'a> {
    fn u8(&mut self) -> Option<u8> {
        let v = *self.b.get(self.i)?;
        self.i += 1;
        Some(v)
    }
    fn arr<const N: usize>(&mut self) -> Option<[u8; N]> {
        let s = self.b.get(self.i..self.i + N)?;
        self.i += N;
        Some(s.try_into().unwrap())
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.arr()?))
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.arr()?))
    }
}

/// Decode a report from (untrusted) content bytes. Returns `None` on bad magic /
/// version / truncation. Entry counts are capped at [`MAX_ENTRIES`].
pub fn decode_report(bytes: &[u8]) -> Option<ReceptionReport> {
    let mut r = Reader { b: bytes, i: 0 };
    if r.u8()? != REPORT_MAGIC || r.u8()? != REPORT_VERSION {
        return None;
    }
    let node_id = r.u64()?;
    let seq = r.u32()?;
    let ts_ms = r.u64()?;

    let nn = (r.u8()? as usize).min(MAX_ENTRIES);
    let mut heard_neighbors = Vec::with_capacity(nn);
    for _ in 0..nn {
        let id = r.u64()?;
        let rssi = r.u8()? as i8;
        heard_neighbors.push((id, rssi));
    }
    let np = (r.u8()? as usize).min(MAX_ENTRIES);
    let mut heard_prefixes = Vec::with_capacity(np);
    for _ in 0..np {
        heard_prefixes.push(r.u64()?);
    }
    let ns = (r.u8()? as usize).min(MAX_ENTRIES);
    let mut spectrum = Vec::with_capacity(ns);
    for _ in 0..ns {
        let c = r.u8()?;
        let busy = r.u8()?;
        spectrum.push((c, busy));
    }
    Some(ReceptionReport {
        node_id,
        seq,
        ts_ms,
        heard_neighbors,
        heard_prefixes,
        spectrum,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ReceptionReport {
        ReceptionReport {
            node_id: 0xABCD,
            seq: 7,
            ts_ms: 12345,
            heard_neighbors: vec![(1, -55), (2, -80)],
            heard_prefixes: vec![0x11, 0x22, 0x33],
            spectrum: vec![(149, 40), (165, 5)],
        }
    }

    #[test]
    fn roundtrip() {
        let r = sample();
        assert_eq!(decode_report(&encode_report(&r)), Some(r));
    }

    #[test]
    fn rejects_garbage_and_truncation() {
        assert_eq!(decode_report(&[]), None);
        assert_eq!(decode_report(&[0x00, 0x01]), None); // bad magic
        let enc = encode_report(&sample());
        assert_eq!(decode_report(&enc[..enc.len() - 3]), None); // truncated tail
    }

    #[test]
    fn lists_are_bounded() {
        let mut r = sample();
        r.heard_prefixes = (0..1000).collect();
        let dec = decode_report(&encode_report(&r)).unwrap();
        assert_eq!(dec.heard_prefixes.len(), MAX_ENTRIES, "encode caps at MAX_ENTRIES");
    }

    #[test]
    fn negative_rssi_survives() {
        let dec = decode_report(&encode_report(&sample())).unwrap();
        assert_eq!(dec.heard_neighbors, vec![(1, -55), (2, -80)]);
    }
}
