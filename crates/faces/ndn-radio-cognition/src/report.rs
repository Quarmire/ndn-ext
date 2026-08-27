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
/// Report wire version. v2 appends `max_rx_mcs` after `ts_ms` (v1 reports decode with
/// `max_rx_mcs = FULL_RX_MCS`, i.e. assume a fully-capable receiver).
pub const REPORT_VERSION: u8 = 2;
/// Max entries encoded/accepted per list (bounded state).
pub const MAX_ENTRIES: usize = 32;
/// `max_rx_mcs` value meaning "decodes any HT/VHT MCS" — the fully-capable default.
pub const FULL_RX_MCS: u8 = 9;
/// `max_rx_mcs` value meaning "decodes legacy OFDM only, no HT/VHT" — e.g. the 8812au on
/// 5 GHz (measured 2026-07-24). A transmitter reaching such a neighbour must use a legacy
/// basic rate for the whole content group (the doctrine's worst-overheard-receiver rate).
pub const LEGACY_ONLY_RX: u8 = 0;
/// `max_rx_mcs` value for a **single-RX-chain** receiver: decodes single-stream HT (MCS 0–7) and
/// legacy, but **no** 2-stream frame at any index. The userspace RTL8812EU (88xx backend) brings up
/// one RX chain, so it advertises this (field-measured 2026-08-13: MCS 0–7 decode, 8–15 do not). A
/// transmitter reaching such a neighbour caps its data rate at MCS 7 **and one spatial stream** — a
/// 2-stream frame is undecodable by a 1-chain radio regardless of per-stream MCS. This is why
/// [`FULL_RX_MCS`] here means "2-stream capable", and any `1..=7` means "single stream, ≤ that MCS".
pub const SINGLE_STREAM_HT_RX_MCS: u8 = 7;

/// A node's snapshot of what it observes, shared with neighbors.
#[derive(Clone, Debug, PartialEq)]
pub struct ReceptionReport {
    /// The reporting node's id.
    pub node_id: u64,
    /// Monotonic report sequence (anti-rollback / freshness).
    pub seq: u32,
    /// Reporter's timestamp (ms); receivers re-stamp with their own clock.
    pub ts_ms: u64,
    /// The highest HT/VHT MCS the reporter's **best** radio can *decode*, or
    /// [`LEGACY_ONLY_RX`] (0) if it can only decode legacy OFDM. Advertised so a peer
    /// caps the *data* rate for any group reaching this node — a legacy-only receiver
    /// cannot decode HT at any index, so the group drops to a legacy basic rate.
    pub max_rx_mcs: u8,
    /// Neighbors the reporter hears, and at what RSSI (dBm). The entry where the
    /// neighbour id == *your* node id is your measured outbound link to the reporter.
    pub heard_neighbors: Vec<(u64, i8)>,
    /// Prefix-hashes the reporter recently heard / holds.
    pub heard_prefixes: Vec<u64>,
    /// The reporter's per-channel busy% view: `(channel, busy_pct)`.
    pub spectrum: Vec<(u8, u8)>,
    /// Per-neighbour **SNR in dB** as the reporter heard them: `(neighbour_id, snr_db)`.
    ///
    /// The companion to [`heard_neighbors`](Self::heard_neighbors) and the reason it exists: RSSI
    /// tells a transmitter how LOUD it arrives at a peer, SNR how CLEAN, and only the second
    /// predicts whether a rate demodulates there. Finding our own id here is how we learn the
    /// quality of the OUTBOUND link — the input the worst-receiver rate cap actually wants.
    ///
    /// Empty when the reporter's radio cannot measure SNR, which must cost it nothing.
    pub heard_snr: Vec<(u64, i8)>,
}

impl Default for ReceptionReport {
    fn default() -> Self {
        Self {
            node_id: 0,
            seq: 0,
            ts_ms: 0,
            max_rx_mcs: FULL_RX_MCS,
            heard_neighbors: Vec::new(),
            heard_prefixes: Vec::new(),
            spectrum: Vec::new(),
            heard_snr: Vec::new(),
        }
    }
}

/// Encode a report to its content bytes (lists truncated to [`MAX_ENTRIES`]).
pub fn encode_report(r: &ReceptionReport) -> Vec<u8> {
    let mut b = Vec::with_capacity(32);
    b.push(REPORT_MAGIC);
    b.push(REPORT_VERSION);
    b.extend_from_slice(&r.node_id.to_le_bytes());
    b.extend_from_slice(&r.seq.to_le_bytes());
    b.extend_from_slice(&r.ts_ms.to_le_bytes());
    b.push(r.max_rx_mcs); // v2

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
    // --- appended section: per-neighbour SNR ---
    //
    // Appended rather than folded into `heard_neighbors`, and WITHOUT bumping REPORT_VERSION, on
    // purpose. This is a broadcast protocol with no version negotiation, and the decoder rejects a
    // version it does not know outright — so a bump is a flag day in which un-upgraded nodes
    // discard an upgraded peer's ENTIRE report to avoid one optional field. That is a bad trade.
    // Appending is compatible in both directions: an older decoder stops after `spectrum` and
    // ignores these bytes, a newer one reads them when present and treats absence as "no SNR".
    let nq = r.heard_snr.len().min(MAX_ENTRIES);
    b.push(nq as u8);
    for (id, snr) in r.heard_snr.iter().take(nq) {
        b.extend_from_slice(&id.to_le_bytes());
        b.push(*snr as u8);
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
    if r.u8()? != REPORT_MAGIC {
        return None;
    }
    // Accept v1 (no max_rx_mcs → assume fully capable) and v2 (reads the byte).
    let version = r.u8()?;
    if version != 1 && version != REPORT_VERSION {
        return None;
    }
    let node_id = r.u64()?;
    let seq = r.u32()?;
    let ts_ms = r.u64()?;
    let max_rx_mcs = if version >= 2 { r.u8()? } else { FULL_RX_MCS };

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
    // Appended SNR section: absent in reports from un-upgraded peers, so a failed read is "none",
    // never a decode failure — rejecting a whole report over an optional field is the flag day
    // this format is shaped to avoid.
    // ⚠ ABSENT and TRUNCATED are different things, and conflating them costs a real guarantee.
    // No bytes at all after `spectrum` = a report from an un-upgraded peer: fine, no SNR. But once
    // the count byte is present the entries it promises MUST all be there — a short list is
    // malformed input, and this decoder's contract (untrusted bytes in) is to reject that. A first
    // version of this tolerated both and silently weakened `rejects_garbage_and_truncation`.
    let mut heard_snr = Vec::new();
    if let Some(nq) = r.u8() {
        for _ in 0..(nq as usize).min(MAX_ENTRIES) {
            let id = r.u64()?;
            let v = r.u8()?;
            heard_snr.push((id, v as i8));
        }
    }
    Some(ReceptionReport {
        node_id,
        seq,
        ts_ms,
        max_rx_mcs,
        heard_neighbors,
        heard_prefixes,
        spectrum,
        heard_snr,
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
            max_rx_mcs: LEGACY_ONLY_RX,
            heard_neighbors: vec![(1, -55), (2, -80)],
            heard_prefixes: vec![0x11, 0x22, 0x33],
            spectrum: vec![(149, 40), (165, 5)],
            heard_snr: vec![(1, 21), (2, 6)],
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
        assert_eq!(
            dec.heard_prefixes.len(),
            MAX_ENTRIES,
            "encode caps at MAX_ENTRIES"
        );
    }

    #[test]
    fn negative_rssi_survives() {
        let dec = decode_report(&encode_report(&sample())).unwrap();
        assert_eq!(dec.heard_neighbors, vec![(1, -55), (2, -80)]);
    }

    #[test]
    fn max_rx_mcs_round_trips() {
        let dec = decode_report(&encode_report(&sample())).unwrap();
        assert_eq!(
            dec.max_rx_mcs, LEGACY_ONLY_RX,
            "legacy-only advert survives"
        );
        let mut hi = sample();
        hi.max_rx_mcs = FULL_RX_MCS;
        assert_eq!(
            decode_report(&encode_report(&hi)).unwrap().max_rx_mcs,
            FULL_RX_MCS
        );
    }

    #[test]
    fn v1_report_decodes_as_fully_capable() {
        // A legacy v1 report (no max_rx_mcs byte) must decode with the fully-capable
        // default so old peers are never mistaken for legacy-only receivers.
        let r = sample();
        let mut v1 = Vec::new();
        v1.push(REPORT_MAGIC);
        v1.push(1); // version 1
        v1.extend_from_slice(&r.node_id.to_le_bytes());
        v1.extend_from_slice(&r.seq.to_le_bytes());
        v1.extend_from_slice(&r.ts_ms.to_le_bytes());
        v1.push(0); // 0 heard_neighbors
        v1.push(0); // 0 heard_prefixes
        v1.push(0); // 0 spectrum
        let dec = decode_report(&v1).expect("v1 decodes");
        assert_eq!(dec.max_rx_mcs, FULL_RX_MCS);
        assert_eq!(dec.node_id, r.node_id);
    }
}

#[cfg(test)]
mod snr_section_tests {
    use super::*;

    #[test]
    fn snr_section_round_trips() {
        let mut r = ReceptionReport::default();
        r.node_id = 0xAA;
        r.heard_neighbors = vec![(1, -50), (2, -70)];
        r.heard_snr = vec![(1, 22), (2, 7)];
        let d = decode_report(&encode_report(&r)).expect("decode");
        assert_eq!(d.heard_snr, vec![(1, 22), (2, 7)]);
        assert_eq!(d.heard_neighbors, vec![(1, -50), (2, -70)]);
    }

    /// A report from an un-upgraded peer simply stops after `spectrum`. It must decode fine with
    /// no SNR — never be rejected, which is the flag-day failure this shape avoids.
    #[test]
    fn report_without_the_snr_section_still_decodes() {
        let mut r = ReceptionReport::default();
        r.node_id = 0xBB;
        r.heard_neighbors = vec![(9, -60)];
        let mut bytes = encode_report(&r);
        bytes.pop(); // drop the appended zero-length SNR section = an older encoder's output
        let d = decode_report(&bytes).expect("older report must still decode");
        assert_eq!(d.node_id, 0xBB);
        assert_eq!(d.heard_neighbors, vec![(9, -60)]);
        assert!(d.heard_snr.is_empty());
    }

    /// A section that ANNOUNCES entries and then stops short is malformed, not old — it must be
    /// rejected like any other truncation. Only a wholly ABSENT section means "older peer".
    #[test]
    fn truncated_snr_section_is_rejected() {
        let mut r = ReceptionReport::default();
        r.node_id = 0xCC;
        r.heard_neighbors = vec![(3, -55)];
        r.heard_snr = vec![(3, 18), (4, 20)];
        let full = encode_report(&r);
        assert_eq!(
            decode_report(&full[..full.len() - 5]),
            None,
            "a short SNR list is malformed input and must not decode"
        );
    }

    #[test]
    fn negative_snr_survives() {
        let mut r = ReceptionReport::default();
        r.heard_snr = vec![(7, -5)];
        let d = decode_report(&encode_report(&r)).unwrap();
        assert_eq!(d.heard_snr, vec![(7, -5)]);
    }
}
