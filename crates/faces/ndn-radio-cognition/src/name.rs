//! **Name → filter-input derivation** — the named-data radio's one canonical path from an on-air
//! frame to the `/`-joined normalized name that every in-frame name filter is computed over.
//!
//! This is a #44 keyspace primitive, peer to [`prefix_hash`](crate::prefix_hash) and the filter
//! codecs ([`gcs`](crate::gcs), the address Blur): a producer compiling its name into a filter and a
//! receiver registering a `/`-string prefix **must** derive their bytes here so the two agree. It
//! lives in the shared control-plane crate — not in any one bearer's face — precisely so no bearer
//! grows a private copy that can drift (the failure the golden-vector oracle exists to catch). Every
//! bearer (Wi-Fi address Blur, LoRa body GCS, …) calls the same [`inner_name`] + [`ndn_name_to_slash`].
//!
//! Pure: TLV/LP parsing over borrowed bytes, no IO — consistent with the crate's sans-IO contract.

/// Extract the NDN **Name** TLV bytes from an LP-framed wire frame's inner packet. Returns `None`
/// for a non-first fragment (the name is only in fragment 0) or a parse miss. The one bounded
/// NDN-structure peek a bearer needs to compile its own Data's name into an in-frame filter.
pub fn inner_name(wire: &[u8]) -> Option<&[u8]> {
    // The network packet bytes: the LP `Fragment` (0x50) value. A multi-fragment
    // frame exposes it via extract_fragment (only fragment 0 has the name); a
    // single LP packet we scan for the 0x50 TLV; a bare packet is used as-is.
    let pkt: &[u8] = if let Some(h) = ndn_packet::lp::extract_fragment(wire) {
        if h.frag_index != 0 {
            return None;
        }
        wire.get(h.frag_start..h.frag_end)?
    } else if wire.first() == Some(&0x64) {
        lp_fragment_value(wire)?
    } else {
        wire
    };
    // pkt = Interest(0x05) | Data(0x06) { Name(0x07){…}, … } — return the Name TLV.
    named_tlv(pkt, 0x07)
}

/// Render an NDN **Name** TLV (`0x07 { 0x08 len comp … }`) to the `/`-joined byte form the in-frame
/// name filters iterate (`/x/y`), so a producer compiling the wire name and a receiver registering a
/// `/`-string prefix compute filter positions over identical bytes.
///
/// Component values are used verbatim. A raw `/` inside a component would create a false
/// prefix boundary — rare for `GenericNameComponent`s, and harmless in the safe direction
/// (an extra false positive; the receiver's exact table does the exact match). Falls back to the raw
/// TLV bytes if it won't parse, so the filter is still deterministic rather than panicking.
pub fn ndn_name_to_slash(name_tlv: &[u8]) -> Vec<u8> {
    fn parse(name_tlv: &[u8]) -> Option<Vec<u8>> {
        let (t, tn) = ndn_tlv::read_varu64(name_tlv).ok()?;
        if t != 0x07 {
            return None;
        }
        let (len, ln) = ndn_tlv::read_varu64(name_tlv.get(tn..)?).ok()?;
        let body = name_tlv.get(tn + ln..tn + ln + len as usize)?;
        let mut out = Vec::new();
        let mut pos = 0;
        while pos < body.len() {
            let (_ct, a) = ndn_tlv::read_varu64(body.get(pos..)?).ok()?;
            pos += a;
            let (cl, b) = ndn_tlv::read_varu64(body.get(pos..)?).ok()?;
            pos += b;
            let val = body.get(pos..pos + cl as usize)?;
            pos += cl as usize;
            out.push(b'/');
            out.extend_from_slice(val);
        }
        if out.is_empty() {
            out.push(b'/'); // the root name
        }
        Some(out)
    }
    parse(name_tlv).unwrap_or_else(|| name_tlv.to_vec())
}

/// Convenience: the full frame → `/`-joined name in one call. `None` for a nameless/continuation
/// frame. Bearers that want the name in one step (the LoRa body-GCS path) use this.
pub fn wire_to_name_slash(wire: &[u8]) -> Option<Vec<u8>> {
    Some(ndn_name_to_slash(inner_name(wire)?))
}

/// The value bytes of the LP `Fragment` (0x50) TLV inside a single LP packet (0x64).
fn lp_fragment_value(lp: &[u8]) -> Option<&[u8]> {
    let (_, tn) = ndn_tlv::read_varu64(lp).ok()?;
    let (outer_len, ln) = ndn_tlv::read_varu64(lp.get(tn..)?).ok()?;
    let body = lp.get(tn + ln..tn + ln + outer_len as usize)?;
    named_tlv_value(body, 0x50)
}

/// Find the first sub-TLV of type `want` inside `parent`'s value and return it
/// **including** its type+length header (the hash input for a name is the whole
/// Name TLV). `parent` starts with an outer type+len wrapping the sub-TLVs.
fn named_tlv(parent: &[u8], want: u64) -> Option<&[u8]> {
    let (_, tn) = ndn_tlv::read_varu64(parent).ok()?;
    let (len, ln) = ndn_tlv::read_varu64(parent.get(tn..)?).ok()?;
    let body = parent.get(tn + ln..tn + ln + len as usize)?;
    let mut pos = 0;
    while pos < body.len() {
        let start = pos;
        let (t, a) = ndn_tlv::read_varu64(body.get(pos..)?).ok()?;
        pos += a;
        let (l, b) = ndn_tlv::read_varu64(body.get(pos..)?).ok()?;
        pos += b + l as usize;
        if t == want {
            return body.get(start..pos);
        }
    }
    None
}

/// Like [`named_tlv`] but returns the sub-TLV's **value** (no header).
fn named_tlv_value(parent: &[u8], want: u64) -> Option<&[u8]> {
    let (_, tn) = ndn_tlv::read_varu64(parent).ok()?;
    let (len, ln) = ndn_tlv::read_varu64(parent.get(tn..)?).ok()?;
    let body = parent.get(tn + ln..tn + ln + len as usize)?;
    let mut pos = 0;
    while pos < body.len() {
        let (t, a) = ndn_tlv::read_varu64(body.get(pos..)?).ok()?;
        pos += a;
        let (l, b) = ndn_tlv::read_varu64(body.get(pos..)?).ok()?;
        pos += b;
        if t == want {
            return body.get(pos..pos + l as usize);
        }
        pos += l as usize;
    }
    None
}
