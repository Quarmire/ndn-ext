//! 802.11 framing for NAN: the management header and the two NAN carriers.
//!
//! A NAN node injects **management** frames (not data frames): a **beacon**
//! (sync or discovery) carries NAN attributes in a vendor-specific information
//! element; a **Service Discovery Frame** (SDF) is a public action frame whose
//! attributes follow the OUI/type directly. Both share the 24-byte 802.11
//! management header.
//!
//! These builders produce the bytes *from the 802.11 header onward* — the
//! radiotap TX header is prepended by the radio backend (the desktop monitor
//! `FrameIo`), exactly as for every other injected frame in the stack. Decoders
//! are bounds-checked and never panic on malformed input.

use alloc::vec::Vec;

use crate::attr::{Attribute, Attributes};
use crate::wire::{Reader, WireError, WriteExt};
use crate::{NAN_OUI, NAN_OUI_TYPE, NAN_OUI_TYPE_ACTION};

/// 802.11 frame-control value for a **beacon** management frame
/// (type=management, subtype=beacon). On the wire (LE) this is bytes `80 00`.
pub const FC_BEACON: u16 = 0x0080;

/// 802.11 frame-control value for an **action** management frame
/// (type=management, subtype=action). On the wire (LE) this is bytes `D0 00`.
pub const FC_ACTION: u16 = 0x00D0;

/// Public Action frame category (`0x04`).
pub const ACTION_CATEGORY_PUBLIC: u8 = 0x04;

/// Vendor-Specific Public Action value (`0x09`) — the action byte of a NAN SDF.
pub const ACTION_PUBLIC_VENDOR_SPECIFIC: u8 = 0x09;

/// The 802.11 vendor-specific information-element id (`0xDD`), wrapping NAN
/// attributes inside a beacon.
pub const ELEMENT_ID_VENDOR_SPECIFIC: u8 = 0xDD;

/// The default beacon capability-information field opennan emits (`0x0420`).
pub const DEFAULT_BEACON_CAPABILITY: u16 = 0x0420;

/// The 802.11 management header (24 bytes), parsed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dot11Header {
    pub frame_control: u16,
    pub duration_id: u16,
    /// addr1 — destination (broadcast / NAN network id for SDFs).
    pub addr1: [u8; 6],
    /// addr2 — source (this node's NAN management-interface MAC).
    pub addr2: [u8; 6],
    /// addr3 — BSSID (the NAN cluster id).
    pub addr3: [u8; 6],
    /// Sequence-control field (`seq << 4 | frag`); NAN sets `frag = 0`.
    pub seq_ctrl: u16,
}

impl Dot11Header {
    /// A management header with `duration_id = 0` and `seq_ctrl = seq << 4`.
    pub fn new(
        frame_control: u16,
        addr1: [u8; 6],
        addr2: [u8; 6],
        addr3: [u8; 6],
        seq: u16,
    ) -> Self {
        Self {
            frame_control,
            duration_id: 0,
            addr1,
            addr2,
            addr3,
            seq_ctrl: seq << 4,
        }
    }

    /// Append the 24-byte header to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.put_le16(self.frame_control);
        out.put_le16(self.duration_id);
        out.put_bytes(&self.addr1);
        out.put_bytes(&self.addr2);
        out.put_bytes(&self.addr3);
        out.put_le16(self.seq_ctrl);
    }

    /// Decode the 24-byte header, returning it and a reader at the body.
    fn decode<'a>(buf: &'a [u8]) -> Result<(Self, Reader<'a>), WireError> {
        let mut r = Reader::new(buf);
        let frame_control = r.le16()?;
        let duration_id = r.le16()?;
        let addr1 = r.take_array()?;
        let addr2 = r.take_array()?;
        let addr3 = r.take_array()?;
        let seq_ctrl = r.le16()?;
        Ok((
            Self {
                frame_control,
                duration_id,
                addr1,
                addr2,
                addr3,
                seq_ctrl,
            },
            r,
        ))
    }

    /// The sequence number (the high 12 bits of `seq_ctrl`).
    pub fn seq(&self) -> u16 {
        self.seq_ctrl >> 4
    }
}

/// What kind of frame a captured buffer is, by frame-control subtype.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameType {
    Beacon,
    /// A Service Discovery Frame (action OUI type `0x13`).
    Action,
    /// A NAN Action Frame (action OUI type `0x18`) — data path, ranging, or
    /// schedule. Carries the raw subtype byte; [`NafSubtype::from_byte`] names it.
    Naf { subtype: u8 },
    Other,
}

/// A captured NAN frame: its 802.11 header plus the NAN attribute bytes carried
/// inside it (the vendor-IE body for a beacon, the post-OUI bytes for an SDF).
#[derive(Clone, Debug)]
pub struct Dot11Frame<'a> {
    pub header: Dot11Header,
    pub kind: FrameType,
    /// The packed NAN attribute TLVs, ready to feed to [`Attributes::new`].
    pub attributes: &'a [u8],
}

impl<'a> Dot11Frame<'a> {
    /// Iterate the NAN attributes carried in this frame.
    pub fn attrs(&self) -> Attributes<'a> {
        Attributes::new(self.attributes)
    }

    /// Find one attribute by id.
    pub fn find(&self, which: crate::attr::AttributeId) -> Option<Attribute<'a>> {
        Attributes::find(self.attributes, which)
    }
}

/// A NAN beacon (sync or discovery) — the cluster's heartbeat.
///
/// Layout after the 802.11 header: `timestamp(u64 LE) | beacon_interval(u16 LE)
/// | capability(u16 LE) | 0xDD | ie_len(u8) | OUI(3) | 0x13 | attributes`.
#[derive(Clone, Debug)]
pub struct NanBeacon {
    pub header: Dot11Header,
    /// The transmitter's synchronized TSF (software TSF in our userspace stack).
    pub timestamp: u64,
    /// 512 TU for a sync beacon, 100 TU for a discovery beacon.
    pub beacon_interval: u16,
    pub capability: u16,
}

impl NanBeacon {
    /// A beacon header bound for the cluster. `dst` is typically broadcast.
    pub fn new(
        dst: [u8; 6],
        src: [u8; 6],
        cluster_id: [u8; 6],
        seq: u16,
        timestamp: u64,
        beacon_interval: u16,
    ) -> Self {
        Self {
            header: Dot11Header::new(FC_BEACON, dst, src, cluster_id, seq),
            timestamp,
            beacon_interval,
            capability: DEFAULT_BEACON_CAPABILITY,
        }
    }

    /// Serialize the full beacon (802.11 header → fixed fields → NAN vendor IE
    /// wrapping `attributes`). `attributes` is the pre-encoded TLV bytes; it must
    /// be ≤ 251 bytes so the OUI(3)+type(1)+attrs fit one IE length octet (true
    /// for sync/discovery beacons, which carry only Master Indication + Cluster).
    pub fn encode(&self, attributes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        self.header.encode(&mut out);
        out.put_le64(self.timestamp);
        out.put_le16(self.beacon_interval);
        out.put_le16(self.capability);
        out.put_u8(ELEMENT_ID_VENDOR_SPECIFIC);
        // IE length = OUI(3) + oui_type(1) + attributes.
        out.put_u8((NAN_OUI.len() + 1 + attributes.len()) as u8);
        out.put_bytes(&NAN_OUI);
        out.put_u8(NAN_OUI_TYPE);
        out.put_bytes(attributes);
        out
    }

    /// Parse a captured beacon, returning the fixed fields and the carried NAN
    /// attribute bytes. Rejects non-beacon frames and non-NAN vendor IEs.
    pub fn parse(buf: &[u8]) -> Result<(Self, &[u8]), WireError> {
        let (header, mut r) = Dot11Header::decode(buf)?;
        if header.frame_control != FC_BEACON {
            return Err(WireError::Invalid);
        }
        let timestamp = r.le64()?;
        let beacon_interval = r.le16()?;
        let capability = r.le16()?;
        // Walk information elements to find the NAN vendor IE (id 0xDD, our OUI,
        // oui_type 0x13). Other IEs (if any precede it) are skipped by length.
        let attributes = find_nan_vendor_ie(&mut r)?;
        Ok((
            Self {
                header,
                timestamp,
                beacon_interval,
                capability,
            },
            attributes,
        ))
    }
}

/// A NAN Service Discovery Frame — a public action frame carrying SDAs.
///
/// Layout after the 802.11 header: `category(0x04) | action(0x09) | OUI(3) |
/// 0x13 | attributes`.
#[derive(Clone, Debug)]
pub struct ServiceDiscoveryFrame {
    pub header: Dot11Header,
}

impl ServiceDiscoveryFrame {
    /// An SDF header. `dst` is the matched peer (unicast) or the NAN network id
    /// (broadcast).
    pub fn new(dst: [u8; 6], src: [u8; 6], cluster_id: [u8; 6], seq: u16) -> Self {
        Self {
            header: Dot11Header::new(FC_ACTION, dst, src, cluster_id, seq),
        }
    }

    /// Serialize the full SDF wrapping `attributes` (pre-encoded TLV bytes).
    pub fn encode(&self, attributes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        self.header.encode(&mut out);
        out.put_u8(ACTION_CATEGORY_PUBLIC);
        out.put_u8(ACTION_PUBLIC_VENDOR_SPECIFIC);
        out.put_bytes(&NAN_OUI);
        out.put_u8(NAN_OUI_TYPE);
        out.put_bytes(attributes);
        out
    }

    /// Parse a captured SDF, returning the header and the carried NAN attribute
    /// bytes. Rejects non-action frames and non-NAN action OUIs.
    pub fn parse(buf: &[u8]) -> Result<(Self, &[u8]), WireError> {
        let (header, mut r) = Dot11Header::decode(buf)?;
        if header.frame_control != FC_ACTION {
            return Err(WireError::Invalid);
        }
        if r.u8()? != ACTION_CATEGORY_PUBLIC || r.u8()? != ACTION_PUBLIC_VENDOR_SPECIFIC {
            return Err(WireError::Invalid);
        }
        if r.take(3)? != NAN_OUI || r.u8()? != NAN_OUI_TYPE {
            return Err(WireError::Invalid);
        }
        Ok((Self { header }, r.rest()))
    }
}

/// NAN Action Frame subtypes (the byte after the action OUI type).
///
/// Same public-action envelope as an SDF, but OUI type [`NAN_OUI_TYPE_ACTION`]
/// (`0x18`) rather than [`NAN_OUI_TYPE`] (`0x13`) — this is the frame that
/// carries data-path setup, ranging, and schedule negotiation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
#[repr(u8)]
pub enum NafSubtype {
    RangingRequest = 1,
    RangingResponse = 2,
    RangingTermination = 3,
    RangingReport = 4,
    /// NDP M1 — the initiator asks for a data path.
    DataPathRequest = 5,
    /// NDP M2 — the responder accepts / rejects / continues.
    DataPathResponse = 6,
    /// NDP M3 — the initiator confirms the accepted path.
    DataPathConfirm = 7,
    /// NDP M4 — key installment (security-enabled paths only).
    DataPathKeyInstallment = 8,
    DataPathTermination = 9,
    ScheduleRequest = 10,
    ScheduleResponse = 11,
    ScheduleConfirm = 12,
    ScheduleUpdateNotification = 13,
}

impl NafSubtype {
    /// Map the on-air subtype byte. Unknown/reserved values are `None` rather
    /// than an error: an unrecognised NAF is a frame to ignore, not a malformed
    /// one.
    pub fn from_byte(b: u8) -> Option<Self> {
        Some(match b {
            1 => Self::RangingRequest,
            2 => Self::RangingResponse,
            3 => Self::RangingTermination,
            4 => Self::RangingReport,
            5 => Self::DataPathRequest,
            6 => Self::DataPathResponse,
            7 => Self::DataPathConfirm,
            8 => Self::DataPathKeyInstallment,
            9 => Self::DataPathTermination,
            10 => Self::ScheduleRequest,
            11 => Self::ScheduleResponse,
            12 => Self::ScheduleConfirm,
            13 => Self::ScheduleUpdateNotification,
            _ => return None,
        })
    }
}

/// A NAN Action Frame (NAF): the data-path / ranging / schedule carrier.
///
/// Wire shape — a public action frame, like an SDF, diverging at the OUI type:
///
/// ```text
/// dot11 hdr | 0x04 | 0x09 | 50:6F:9A | 0x18 | subtype | attributes...
///             cat    vend    OUI       type
/// ```
pub struct NanActionFrame {
    pub header: Dot11Header,
    pub subtype: u8,
}

impl NanActionFrame {
    /// A NAF to `dst` (a peer's NMI — data-path setup is unicast).
    pub fn new(subtype: NafSubtype, dst: [u8; 6], src: [u8; 6], cluster_id: [u8; 6], seq: u16) -> Self {
        Self {
            header: Dot11Header::new(FC_ACTION, dst, src, cluster_id, seq),
            subtype: subtype as u8,
        }
    }

    /// Serialize the full NAF wrapping `attributes` (pre-encoded TLV bytes).
    pub fn encode(&self, attributes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        self.header.encode(&mut out);
        out.put_u8(ACTION_CATEGORY_PUBLIC);
        out.put_u8(ACTION_PUBLIC_VENDOR_SPECIFIC);
        out.put_bytes(&NAN_OUI);
        out.put_u8(NAN_OUI_TYPE_ACTION);
        out.put_u8(self.subtype);
        out.put_bytes(attributes);
        out
    }

    /// Parse a captured NAF, returning the header + subtype and the carried NAN
    /// attribute bytes.
    pub fn parse(buf: &[u8]) -> Result<(Self, &[u8]), WireError> {
        let (header, mut r) = Dot11Header::decode(buf)?;
        if header.frame_control != FC_ACTION {
            return Err(WireError::Invalid);
        }
        if r.u8()? != ACTION_CATEGORY_PUBLIC || r.u8()? != ACTION_PUBLIC_VENDOR_SPECIFIC {
            return Err(WireError::Invalid);
        }
        if r.take(3)? != NAN_OUI || r.u8()? != NAN_OUI_TYPE_ACTION {
            return Err(WireError::Invalid);
        }
        let subtype = r.u8()?;
        Ok((Self { header, subtype }, r.rest()))
    }
}

/// Classify a captured frame buffer and, when it's a NAN beacon, SDF, or NAF,
/// surface its attribute bytes — the single entry point a receive loop calls.
pub fn classify(buf: &[u8]) -> Result<Dot11Frame<'_>, WireError> {
    let (header, _) = Dot11Header::decode(buf)?;
    match header.frame_control {
        FC_BEACON => {
            let (b, attributes) = NanBeacon::parse(buf)?;
            Ok(Dot11Frame {
                header: b.header,
                kind: FrameType::Beacon,
                attributes,
            })
        }
        // An action frame is an SDF or a NAF depending on its OUI type, so try
        // the SDF shape and fall back — treating every action frame as an SDF
        // would reject NAFs outright and lose the whole data-path channel.
        FC_ACTION => match ServiceDiscoveryFrame::parse(buf) {
            Ok((s, attributes)) => Ok(Dot11Frame {
                header: s.header,
                kind: FrameType::Action,
                attributes,
            }),
            Err(_) => {
                let (n, attributes) = NanActionFrame::parse(buf)?;
                Ok(Dot11Frame {
                    header: n.header,
                    kind: FrameType::Naf {
                        subtype: n.subtype,
                    },
                    attributes,
                })
            }
        },
        _ => Ok(Dot11Frame {
            header,
            kind: FrameType::Other,
            attributes: &[],
        }),
    }
}

/// Walk information elements from `r`'s current position, returning the NAN
/// vendor IE's attribute bytes (the body after OUI + oui_type). Skips any
/// non-matching IEs by their length field.
fn find_nan_vendor_ie<'a>(r: &mut Reader<'a>) -> Result<&'a [u8], WireError> {
    while r.remaining() >= 2 {
        let id = r.u8()?;
        let len = r.u8()? as usize;
        let body = r.take(len)?;
        if id == ELEMENT_ID_VENDOR_SPECIFIC
            && body.len() >= 4
            && body[..3] == NAN_OUI[..]
            && body[3] == NAN_OUI_TYPE
        {
            return Ok(&body[4..]);
        }
    }
    Err(WireError::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attr::{Cluster, MasterIndication, ServiceControlType, ServiceDescriptor};
    use crate::{BROADCAST, NAN_CLUSTER_ID_BASE, NAN_NETWORK_ID};

    const SRC: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];

    fn beacon_attrs() -> Vec<u8> {
        let mut a = Vec::new();
        MasterIndication {
            master_preference: 200,
            random_factor: 17,
        }
        .encode(&mut a);
        Cluster {
            anchor_master_rank: 0x00C8_0000_0000_0000,
            hop_count: 0,
            ambtt: 0x1234_5678,
        }
        .encode(&mut a);
        a
    }

    #[test]
    fn beacon_header_and_fixed_fields_are_byte_exact() {
        let attrs = beacon_attrs();
        let beacon = NanBeacon::new(BROADCAST, SRC, NAN_CLUSTER_ID_BASE, 5, 0xABCD, 512);
        let wire = beacon.encode(&attrs);

        // Frame control (LE) = 80 00 (beacon).
        assert_eq!(&wire[0..2], &[0x80, 0x00]);
        // duration = 0
        assert_eq!(&wire[2..4], &[0x00, 0x00]);
        // addr1 broadcast, addr2 src, addr3 cluster id base
        assert_eq!(&wire[4..10], &BROADCAST);
        assert_eq!(&wire[10..16], &SRC);
        assert_eq!(&wire[16..22], &NAN_CLUSTER_ID_BASE);
        // seq_ctrl = 5 << 4 = 0x0050 LE
        assert_eq!(&wire[22..24], &[0x50, 0x00]);
        // timestamp 0xABCD LE (8 bytes)
        assert_eq!(&wire[24..32], &[0xCD, 0xAB, 0, 0, 0, 0, 0, 0]);
        // beacon_interval 512 LE
        assert_eq!(&wire[32..34], &[0x00, 0x02]);
        // capability 0x0420 LE
        assert_eq!(&wire[34..36], &[0x20, 0x04]);
        // vendor IE: 0xDD, len, OUI, oui_type
        assert_eq!(wire[36], 0xDD);
        assert_eq!(wire[37] as usize, NAN_OUI.len() + 1 + attrs.len());
        assert_eq!(&wire[38..41], &NAN_OUI);
        assert_eq!(wire[41], NAN_OUI_TYPE);
    }

    #[test]
    fn beacon_roundtrips_through_classify() {
        let attrs = beacon_attrs();
        let beacon = NanBeacon::new(BROADCAST, SRC, NAN_CLUSTER_ID_BASE, 1, 0x0102_0304, 512);
        let wire = beacon.encode(&attrs);

        let frame = classify(&wire).unwrap();
        assert_eq!(frame.kind, FrameType::Beacon);
        assert_eq!(frame.header.addr2, SRC);
        assert_eq!(frame.attributes, &attrs[..]);

        let (parsed, body) = NanBeacon::parse(&wire).unwrap();
        assert_eq!(parsed.timestamp, 0x0102_0304);
        assert_eq!(parsed.beacon_interval, 512);
        let mi = MasterIndication::decode(
            Attributes::find(body, crate::attr::AttributeId::MasterIndication)
                .unwrap()
                .body,
        )
        .unwrap();
        assert_eq!(mi.master_preference, 200);
    }

    #[test]
    fn sdf_roundtrips_through_classify() {
        let sid = crate::service::service_id("org.ndn.test");
        let mut attrs = Vec::new();
        ServiceDescriptor::new(sid, 7, ServiceControlType::Publish)
            .with_service_info(b"ndn".to_vec())
            .encode(&mut attrs);

        let sdf = ServiceDiscoveryFrame::new(NAN_NETWORK_ID, SRC, NAN_CLUSTER_ID_BASE, 3);
        let wire = sdf.encode(&attrs);

        // category/action/oui/type land right after the 24-byte header.
        assert_eq!(wire[24], ACTION_CATEGORY_PUBLIC);
        assert_eq!(wire[25], ACTION_PUBLIC_VENDOR_SPECIFIC);
        assert_eq!(&wire[26..29], &NAN_OUI);
        assert_eq!(wire[29], NAN_OUI_TYPE);

        let frame = classify(&wire).unwrap();
        assert_eq!(frame.kind, FrameType::Action);
        let sda = ServiceDescriptor::decode(
            frame
                .find(crate::attr::AttributeId::ServiceDescriptor)
                .unwrap()
                .body,
        )
        .unwrap();
        assert_eq!(sda.service_id, sid);
        assert_eq!(sda.service_info, b"ndn");
    }

    #[test]
    fn malformed_frames_error_cleanly() {
        // Beacon FC but only 2 bytes: the 24-byte header decode is truncated.
        assert_eq!(classify(&[0x80, 0x00]).err(), Some(WireError::Truncated));
        assert!(classify(&[]).is_err());
        // An action frame with a non-NAN OUI is rejected.
        let mut bad = Vec::new();
        Dot11Header::new(FC_ACTION, BROADCAST, SRC, NAN_CLUSTER_ID_BASE, 0).encode(&mut bad);
        bad.put_u8(ACTION_CATEGORY_PUBLIC);
        bad.put_u8(ACTION_PUBLIC_VENDOR_SPECIFIC);
        bad.put_bytes(&[0x00, 0x11, 0x22]); // wrong OUI
        bad.put_u8(NAN_OUI_TYPE);
        assert_eq!(
            ServiceDiscoveryFrame::parse(&bad).err(),
            Some(WireError::Invalid)
        );
    }

    #[test]
    fn naf_roundtrips_and_carries_its_subtype() {
        const PEER: [u8; 6] = [0x02, 0x26, 0x23, 0xef, 0xbe, 0x2f];
        let naf = NanActionFrame::new(
            NafSubtype::DataPathRequest,
            PEER,
            SRC,
            NAN_CLUSTER_ID_BASE,
            7,
        );
        let wire = naf.encode(&[0xAA, 0xBB]);

        // The envelope diverges from an SDF only at the OUI type, then a subtype.
        assert_eq!(wire[24], ACTION_CATEGORY_PUBLIC);
        assert_eq!(wire[25], ACTION_PUBLIC_VENDOR_SPECIFIC);
        assert_eq!(&wire[26..29], &NAN_OUI);
        assert_eq!(wire[29], NAN_OUI_TYPE_ACTION);
        assert_eq!(wire[30], NafSubtype::DataPathRequest as u8);

        let (parsed, attrs) = NanActionFrame::parse(&wire).unwrap();
        assert_eq!(parsed.header.addr1, PEER, "data-path setup is unicast");
        assert_eq!(parsed.subtype, 5);
        assert_eq!(NafSubtype::from_byte(parsed.subtype), Some(NafSubtype::DataPathRequest));
        assert_eq!(attrs, &[0xAA, 0xBB]);
    }

    /// An SDF and a NAF are both public action frames; only the OUI type tells
    /// them apart. Classifying every action frame as an SDF would reject NAFs and
    /// silently lose the entire data-path channel.
    #[test]
    fn classify_separates_sdf_from_naf() {
        let sdf = ServiceDiscoveryFrame::new(NAN_NETWORK_ID, SRC, NAN_CLUSTER_ID_BASE, 1)
            .encode(&[]);
        assert_eq!(classify(&sdf).unwrap().kind, FrameType::Action);

        let naf = NanActionFrame::new(
            NafSubtype::DataPathResponse,
            SRC,
            SRC,
            NAN_CLUSTER_ID_BASE,
            1,
        )
        .encode(&[]);
        assert_eq!(classify(&naf).unwrap().kind, FrameType::Naf { subtype: 6 });
    }

    #[test]
    fn unknown_naf_subtype_is_none_not_an_error() {
        assert_eq!(NafSubtype::from_byte(0), None);
        assert_eq!(NafSubtype::from_byte(200), None);
        assert_eq!(NafSubtype::from_byte(9), Some(NafSubtype::DataPathTermination));
    }
}
