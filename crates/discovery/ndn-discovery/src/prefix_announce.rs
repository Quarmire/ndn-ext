//! Service record encode/decode (NDNSD §3.1).
//!
//! Name:    `/ndn/local/sd/services/<prefix-hash>/<node-name>/v=<ts-ms>`
//! Content: `ANNOUNCED-PREFIX NODE-NAME FRESHNESS-MS? CAPABILITIES?`
//! TLV:     `0xD0`-`0xD3` (experimental range).

use std::time::Duration;

use bytes::Bytes;
use ndn_packet::encode::DataBuilder;
use ndn_packet::{Name, NameComponent, SignatureType, tlv_type};
use ndn_tlv::TlvWriter;

use crate::scope::{sd_root, sd_services_under};
use crate::service_discovery::auth::{DigestSigner, RecordSigner};
use crate::wire::{encode_name_tlv, parse_raw_data, write_name_tlv, write_nni};

const T_ANNOUNCED_PREFIX: u32 = 0xD0;
const T_SD_NODE_NAME: u32 = 0xD1;
const T_FRESHNESS_MS: u32 = 0xD2;
const T_SD_CAPABILITIES: u32 = 0xD3;
/// Monotonic version (publish timestamp, ms) — signature-protected
/// anti-rollback (audit #4).
const T_VERSION: u32 = 0xD4;

#[derive(Clone, Debug, PartialEq)]
pub struct ServiceRecord {
    pub announced_prefix: Name,
    pub node_name: Name,
    /// `0` = rely on NDN FreshnessPeriod only.
    pub freshness_ms: u64,
    pub capabilities: u8,
    /// Monotonic version (publish timestamp, ms). `0` = unset (legacy).
    pub version: u64,
}

impl ServiceRecord {
    pub fn new(announced_prefix: Name, node_name: Name) -> Self {
        Self {
            announced_prefix,
            node_name,
            freshness_ms: 30_000,
            capabilities: 0,
            version: 0,
        }
    }

    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        let prefix_bytes = encode_name_raw(&self.announced_prefix);
        w.write_tlv(T_ANNOUNCED_PREFIX.into(), &prefix_bytes);
        let node_bytes = encode_name_raw(&self.node_name);
        w.write_tlv(T_SD_NODE_NAME.into(), &node_bytes);
        if self.freshness_ms > 0 {
            write_nni_to_writer(&mut w, T_FRESHNESS_MS, self.freshness_ms);
        }
        if self.capabilities != 0 {
            w.write_tlv(T_SD_CAPABILITIES.into(), &[self.capabilities]);
        }
        if self.version > 0 {
            write_nni_to_writer(&mut w, T_VERSION, self.version);
        }
        w.finish()
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        let mut pos = 0;
        let mut announced_prefix: Option<Name> = None;
        let mut node_name: Option<Name> = None;
        let mut freshness_ms = 0u64;
        let mut capabilities = 0u8;
        let mut version = 0u64;

        while pos < b.len() {
            let (typ, len, header_len) = read_tlv_header(b, pos)?;
            let val_start = pos + header_len;
            let val_end = val_start + len;
            if val_end > b.len() {
                return None;
            }
            let val = &b[val_start..val_end];
            match typ {
                T_ANNOUNCED_PREFIX => {
                    announced_prefix = Some(decode_name_raw(val)?);
                }
                T_SD_NODE_NAME => {
                    node_name = Some(decode_name_raw(val)?);
                }
                T_FRESHNESS_MS => {
                    freshness_ms = read_nni(val)?;
                }
                T_SD_CAPABILITIES => {
                    capabilities = *val.first()?;
                }
                T_VERSION => {
                    version = read_nni(val)?;
                }
                _ => {}
            }
            pos = val_end;
        }

        Some(Self {
            announced_prefix: announced_prefix?,
            node_name: node_name?,
            freshness_ms,
            capabilities,
            version,
        })
    }

    pub fn make_name(&self, timestamp_ms: u64) -> Name {
        make_record_name(&self.announced_prefix, &self.node_name, timestamp_ms)
    }

    /// Self-signed with [`DigestSigner`] (DigestSha256 integrity). For
    /// authenticated announcements use
    /// [`build_data_signed`](Self::build_data_signed).
    pub fn build_data(&self, timestamp_ms: u64) -> Bytes {
        self.build_data_signed(timestamp_ms, &DigestSigner)
    }

    /// Build and sign the rendezvous Data with `signer`. Replaces the
    /// former all-zero stub signature (audit #1).
    pub fn build_data_signed(&self, timestamp_ms: u64, signer: &dyn RecordSigner) -> Bytes {
        let name = self.make_name(timestamp_ms);
        let content = self.encode();
        let freshness_period = if self.freshness_ms > 0 {
            self.freshness_ms
        } else {
            30_000
        };
        let (sig_code, key_locator) = signer.signing_info();
        DataBuilder::new(name, content.as_ref())
            .freshness(Duration::from_millis(freshness_period))
            .sign_sync(
                SignatureType::from_code(sig_code),
                key_locator.as_ref(),
                |region| signer.sign(region).unwrap_or_default(),
            )
    }

    pub fn from_data_packet(raw: &Bytes) -> Option<Self> {
        Self::from_data_packet_under(sd_root(), raw)
    }

    pub fn from_data_packet_under(root: &Name, raw: &Bytes) -> Option<Self> {
        let parsed = parse_raw_data(raw)?;
        let services = sd_services_under(root);
        if !parsed.name.has_prefix(&services) {
            return None;
        }
        let content = parsed.content?;
        Self::decode(&content)
    }
}

pub fn make_record_name(announced_prefix: &Name, node_name: &Name, timestamp_ms: u64) -> Name {
    make_record_name_under(sd_root(), announced_prefix, node_name, timestamp_ms)
}

/// Build a rendezvous name under an injectable root prefix.
pub fn make_record_name_under(
    root: &Name,
    announced_prefix: &Name,
    node_name: &Name,
    timestamp_ms: u64,
) -> Name {
    let hash_hex = prefix_hash_hex(announced_prefix);

    let mut comps: Vec<NameComponent> = sd_services_under(root).components().to_vec();
    comps.push(NameComponent {
        typ: tlv_type::NAME_COMPONENT,
        value: hash_hex.as_bytes().to_vec().into(),
    });

    comps.extend(node_name.components().iter().cloned());

    // VersionNameComponent: type 0x0D, value = big-endian u64.
    comps.push(NameComponent {
        typ: 0x0D,
        value: timestamp_ms.to_be_bytes().to_vec().into(),
    });

    Name::from_components(comps)
}

/// Swap `services` -> `service-info` in a rendezvous name. The two share
/// `(prefix-hash, node, v=<ts>)`.
pub fn make_body_name(rendezvous_name: &Name, root: &Name) -> Name {
    let root_len = root.components().len();
    let comps = rendezvous_name.components();
    let mut new_comps: Vec<NameComponent> = comps[..root_len].to_vec();
    new_comps.push(NameComponent {
        typ: tlv_type::NAME_COMPONENT,
        value: b"service-info".to_vec().into(),
    });
    if comps.len() > root_len + 1 {
        new_comps.extend_from_slice(&comps[root_len + 1..]);
    }
    Name::from_components(new_comps)
}

pub fn build_browse_interest() -> Bytes {
    build_browse_interest_under(sd_root())
}

pub fn build_browse_interest_under(root: &Name) -> Bytes {
    let prefix = sd_services_under(root);
    let mut w = TlvWriter::new();
    w.write_nested(tlv_type::INTEREST, |w: &mut TlvWriter| {
        write_name_tlv(w, &prefix);
        w.write_tlv(0x21, &[]); // CanBePrefix
        w.write_tlv(tlv_type::MUST_BE_FRESH, &[]);
        write_nni(w, tlv_type::INTEREST_LIFETIME, 4000);
    });
    w.finish()
}

/// Collision-resistant prefix identifier used as the `<prefix-hash>` name
/// component in rendezvous/body names (audit #7, replaces FNV-1a). First
/// 8 bytes of SHA-256 over the **canonical Name wire** (not the URI), as
/// 16 hex chars. The full prefix still travels in the record content; this
/// is only the in-name index, so 64 bits of collision resistance suffices.
pub(crate) fn prefix_hash_hex(name: &Name) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, &encode_name_tlv(name));
    let bytes = &digest.as_ref()[..8];
    let mut s = String::with_capacity(16);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn encode_name_raw(name: &Name) -> Bytes {
    let mut w = TlvWriter::new();
    write_name_tlv(&mut w, name);
    w.finish()
}

fn decode_name_raw(b: &[u8]) -> Option<Name> {
    if b.is_empty() || b[0] != 0x07 {
        return None;
    }
    use std::str::FromStr;
    let (_, len, hl) = read_tlv_header(b, 0)?;
    let comps_bytes = &b[hl..hl + len];
    let mut comps = Vec::new();
    let mut pos = 0;
    while pos < comps_bytes.len() {
        let (typ, clen, chl) = read_tlv_header(comps_bytes, pos)?;
        let val = comps_bytes[pos + chl..pos + chl + clen].to_vec();
        comps.push(NameComponent {
            typ: typ as u64,
            value: val.into(),
        });
        pos += chl + clen;
    }
    if comps.is_empty() {
        return Some(Name::root());
    }
    let uri = {
        let mut s = String::new();
        for comp in &comps {
            s.push('/');
            for b in comp.value.iter() {
                if b.is_ascii_alphanumeric() || b"-.~_".contains(b) {
                    s.push(*b as char);
                } else {
                    s.push_str(&format!("%{:02X}", b));
                }
            }
        }
        if s.is_empty() { "/".to_string() } else { s }
    };
    Name::from_str(&uri).ok()
}

fn write_nni_to_writer(w: &mut TlvWriter, typ: u32, val: u64) {
    let bytes = nni_bytes(val);
    w.write_tlv(typ.into(), &bytes);
}

fn nni_bytes(val: u64) -> Vec<u8> {
    if val <= 0xFF {
        vec![val as u8]
    } else if val <= 0xFFFF {
        (val as u16).to_be_bytes().to_vec()
    } else if val <= 0xFFFF_FFFF {
        (val as u32).to_be_bytes().to_vec()
    } else {
        val.to_be_bytes().to_vec()
    }
}

fn read_nni(b: &[u8]) -> Option<u64> {
    match b.len() {
        1 => Some(b[0] as u64),
        2 => Some(u16::from_be_bytes(b.try_into().ok()?) as u64),
        4 => Some(u32::from_be_bytes(b.try_into().ok()?) as u64),
        8 => Some(u64::from_be_bytes(b.try_into().ok()?)),
        _ => None,
    }
}

fn read_tlv_header(b: &[u8], pos: usize) -> Option<(u32, usize, usize)> {
    if pos >= b.len() {
        return None;
    }
    let (typ, t_len) = read_varnumber(b, pos)?;
    let (len, l_len) = read_varnumber(b, pos + t_len)?;
    Some((typ as u32, len as usize, t_len + l_len))
}

fn read_varnumber(b: &[u8], pos: usize) -> Option<(u64, usize)> {
    let first = *b.get(pos)?;
    match first {
        0xFD => {
            let hi = *b.get(pos + 1)? as u64;
            let lo = *b.get(pos + 2)? as u64;
            Some(((hi << 8) | lo, 3))
        }
        0xFE => {
            let v = u32::from_be_bytes(b[pos + 1..pos + 5].try_into().ok()?);
            Some((v as u64, 5))
        }
        0xFF => {
            let v = u64::from_be_bytes(b[pos + 1..pos + 9].try_into().ok()?);
            Some((v, 9))
        }
        _ => Some((first as u64, 1)),
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::scope::{sd_root, sd_service_info_under, sd_services, sd_services_under};

    fn n(s: &str) -> Name {
        Name::from_str(s).unwrap()
    }

    #[test]
    fn record_encode_decode_roundtrip() {
        let rec = ServiceRecord {
            announced_prefix: n("/ndn/sensor/temp"),
            node_name: n("/ndn/site/router1"),
            freshness_ms: 60_000,
            capabilities: 0x03,
            version: 1_700_000_000_000,
        };
        let encoded = rec.encode();
        let decoded = ServiceRecord::decode(&encoded).unwrap();
        assert_eq!(decoded.announced_prefix, rec.announced_prefix);
        assert_eq!(decoded.node_name, rec.node_name);
        assert_eq!(decoded.freshness_ms, rec.freshness_ms);
        assert_eq!(decoded.capabilities, rec.capabilities);
        assert_eq!(decoded.version, rec.version);
    }

    #[test]
    fn make_name_under_sd_services() {
        let rec = ServiceRecord::new(n("/ndn/sensor/temp"), n("/ndn/site/router1"));
        let name = rec.make_name(1_700_000_000_000);
        assert!(
            name.has_prefix(sd_services()),
            "name should be under sd/services"
        );
    }

    #[test]
    fn data_packet_roundtrip() {
        let rec = ServiceRecord::new(n("/ndn/edu/ucla/cs"), n("/ndn/site/node42"));
        let pkt = rec.build_data(42_000);
        let decoded = ServiceRecord::from_data_packet(&pkt).unwrap();
        assert_eq!(decoded.announced_prefix, rec.announced_prefix);
        assert_eq!(decoded.node_name, rec.node_name);
    }

    #[test]
    fn prefix_hash_is_deterministic_16_hex() {
        let h1 = prefix_hash_hex(&n("/ndn/sensor/temp"));
        let h2 = prefix_hash_hex(&n("/ndn/sensor/temp"));
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 16);
        assert!(h1.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn different_prefixes_different_hashes() {
        let h1 = prefix_hash_hex(&n("/ndn/sensor/temp"));
        let h2 = prefix_hash_hex(&n("/ndn/sensor/pressure"));
        assert_ne!(h1, h2);
    }

    #[test]
    fn browse_interest_has_sd_prefix() {
        use crate::wire::parse_raw_interest;
        let pkt = build_browse_interest();
        let parsed = parse_raw_interest(&pkt).unwrap();
        assert!(parsed.name.has_prefix(sd_services()));
    }

    #[test]
    fn make_record_name_under_custom_root() {
        let rec = ServiceRecord::new(n("/ndn/sensor/temp"), n("/ndn/site/router1"));
        let default_name = rec.make_name(1_000);
        let custom_root = n("/zone/x/sd");
        let custom_name =
            make_record_name_under(&custom_root, &rec.announced_prefix, &rec.node_name, 1_000);
        assert_ne!(default_name, custom_name);
        assert!(custom_name.has_prefix(&sd_services_under(&custom_root)));
        assert!(!custom_name.has_prefix(sd_services()));
        assert!(default_name.has_prefix(sd_services()));
    }

    #[test]
    fn make_body_name_swaps_services_to_service_info() {
        let root = sd_root();
        let rec = ServiceRecord::new(n("/ndn/sensor/temp"), n("/ndn/site/router1"));
        let rendezvous = rec.make_name(9_000);
        let body = make_body_name(&rendezvous, root);
        assert!(body.has_prefix(&sd_service_info_under(root)));
        assert!(!body.has_prefix(sd_services()));
        let rv_comps = rendezvous.components();
        let bd_comps = body.components();
        assert_eq!(rv_comps.len(), bd_comps.len());
        assert_eq!(rv_comps.last(), bd_comps.last());
    }

    #[test]
    fn make_body_name_custom_root() {
        let root = n("/zone/y/sd");
        let rec = ServiceRecord::new(n("/ndn/svc/alpha"), n("/ndn/site/node1"));
        let rendezvous = make_record_name_under(&root, &rec.announced_prefix, &rec.node_name, 42);
        let body = make_body_name(&rendezvous, &root);
        assert!(body.has_prefix(&sd_service_info_under(&root)));
        assert_eq!(rendezvous.components().len(), body.components().len());
    }
}
