//! NAN attribute TLVs.
//!
//! Every NAN attribute is `id(u8) | length(u16 LE) | body[length]` — the
//! `length` counts only the body, not the 3-byte header. Beacons and Service
//! Discovery Frames carry a sequence of these. [`Attribute`] is a borrowed view
//! of one TLV; [`Attributes`] iterates a buffer of them; and the typed structs
//! ([`MasterIndication`], [`Cluster`], [`ServiceDescriptor`]) encode/decode the
//! sync- and discovery-critical bodies.
//!
//! The numeric IDs are the full Wi-Fi Aware set (see [`AttributeId`]); Phase 0
//! models the load-bearing ones and treats the rest as opaque bodies, so a
//! decoder round-trips frames containing attributes it doesn't yet interpret.

use alloc::vec::Vec;

use crate::ServiceId;
use crate::wire::{Reader, WireError, WriteExt};

/// NAN attribute IDs (from the Wi-Fi Aware spec / Wireshark `wifi_nan`
/// dissector). The full catalog is listed for reference; only a subset is typed
/// in Phase 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
#[repr(u8)]
pub enum AttributeId {
    MasterIndication = 0x00,
    Cluster = 0x01,
    ServiceIdList = 0x02,
    ServiceDescriptor = 0x03,
    ConnectionCapability = 0x04,
    WlanInfra = 0x05,
    P2pOperation = 0x06,
    Ibss = 0x07,
    Mesh = 0x08,
    FurtherNanServiceDiscovery = 0x09,
    FurtherAvailabilityMap = 0x0A,
    CountryCode = 0x0B,
    Ranging = 0x0C,
    ClusterDiscovery = 0x0D,
    ServiceDescriptorExtension = 0x0E,
    DeviceCapability = 0x0F,
    Ndp = 0x10,
    NanAvailability = 0x12,
    Ndc = 0x13,
    Ndl = 0x14,
    NdlQos = 0x15,
    UnalignedSchedule = 0x17,
    RangingInformation = 0x1A,
    RangingSetup = 0x1B,
    FtmRangeReport = 0x1C,
    ElementContainer = 0x1D,
    CipherSuiteInfo = 0x22,
    SecurityContextInfo = 0x23,
    SharedKeyDescriptor = 0x24,
    PublicAvailability = 0x27,
    SubscribeServiceIdList = 0x28,
    NdpExtension = 0x29,
    DeviceCapabilityExtension = 0x2A,
    NanIdentityResolution = 0x2B,
    NanPairingBootstrapping = 0x2C,
    VendorSpecific = 0xDD,
}

/// A borrowed view of one attribute TLV: its `id` byte and its body slice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attribute<'a> {
    pub id: u8,
    pub body: &'a [u8],
}

impl<'a> Attribute<'a> {
    /// Append this attribute (header + body) to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(self.id);
        out.put_le16(self.body.len() as u16);
        out.put_bytes(self.body);
    }

    /// True if this attribute's id matches `which`.
    pub fn is(&self, which: AttributeId) -> bool {
        self.id == which as u8
    }
}

/// An iterator over a buffer of attribute TLVs. Stops (yielding `Err`) on a
/// truncated or over-long TLV so a malformed tail can't be silently dropped.
pub struct Attributes<'a> {
    reader: Reader<'a>,
}

impl<'a> Attributes<'a> {
    /// Iterate the attribute TLVs packed in `buf`.
    pub fn new(buf: &'a [u8]) -> Self {
        Self {
            reader: Reader::new(buf),
        }
    }

    /// Find the first attribute with id `which`, if present.
    pub fn find(buf: &'a [u8], which: AttributeId) -> Option<Attribute<'a>> {
        Attributes::new(buf).flatten().find(|a| a.is(which))
    }
}

impl<'a> Iterator for Attributes<'a> {
    type Item = Result<Attribute<'a>, WireError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.reader.is_empty() {
            return None;
        }
        Some((|| {
            let id = self.reader.u8()?;
            let len = self.reader.le16()? as usize;
            let body = self.reader.take(len)?;
            Ok(Attribute { id, body })
        })())
    }
}

/// Master Indication attribute (`0x00`): the local node's election inputs.
///
/// Body = `master_preference(u8) | random_factor(u8)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MasterIndication {
    pub master_preference: u8,
    pub random_factor: u8,
}

impl MasterIndication {
    /// Append this attribute (TLV header + 2-byte body) to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(AttributeId::MasterIndication as u8);
        out.put_le16(2);
        out.put_u8(self.master_preference);
        out.put_u8(self.random_factor);
    }

    /// Decode from an attribute body.
    pub fn decode(body: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(body);
        Ok(Self {
            master_preference: r.u8()?,
            random_factor: r.u8()?,
        })
    }
}

/// Cluster attribute (`0x01`): the cluster's anchor-master state.
///
/// Body = `anchor_master_rank(u64 LE) | hop_count(u8) | ambtt(u32 LE)`, where
/// `ambtt` is the lower 32 bits of the anchor master's beacon TX time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cluster {
    pub anchor_master_rank: u64,
    pub hop_count: u8,
    pub ambtt: u32,
}

impl Cluster {
    /// Append this attribute (TLV header + 13-byte body) to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(AttributeId::Cluster as u8);
        out.put_le16(13);
        out.put_le64(self.anchor_master_rank);
        out.put_u8(self.hop_count);
        out.put_le32(self.ambtt);
    }

    /// Decode from an attribute body.
    pub fn decode(body: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(body);
        Ok(Self {
            anchor_master_rank: r.le64()?,
            hop_count: r.u8()?,
            ambtt: r.le32()?,
        })
    }
}

/// The Service Control type — the low 2 bits of an SDA's control byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceControlType {
    Publish = 0,
    Subscribe = 1,
    FollowUp = 2,
}

/// The Service Control byte of a Service Descriptor Attribute. The low 2 bits
/// select the [`ServiceControlType`]; the upper bits flag which optional fields
/// follow the fixed header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServiceControl {
    pub control_type: ServiceControlType,
    pub matching_filter_present: bool,
    pub service_response_filter_present: bool,
    pub service_info_present: bool,
    pub discovery_range_limited: bool,
    pub binding_bitmap_present: bool,
}

impl ServiceControl {
    /// A publish/subscribe/follow-up control with all optional-field flags clear.
    pub fn new(control_type: ServiceControlType) -> Self {
        Self {
            control_type,
            matching_filter_present: false,
            service_response_filter_present: false,
            service_info_present: false,
            discovery_range_limited: false,
            binding_bitmap_present: false,
        }
    }

    /// Pack to the on-air control byte.
    pub fn to_byte(self) -> u8 {
        let mut b = self.control_type as u8; // bits 0-1
        if self.matching_filter_present {
            b |= 0x04;
        }
        if self.service_response_filter_present {
            b |= 0x08;
        }
        if self.service_info_present {
            b |= 0x10;
        }
        if self.discovery_range_limited {
            b |= 0x20;
        }
        if self.binding_bitmap_present {
            b |= 0x40;
        }
        b
    }

    /// Unpack from the on-air control byte. Unknown type bits (3) decode as
    /// [`WireError::Invalid`].
    pub fn from_byte(b: u8) -> Result<Self, WireError> {
        let control_type = match b & 0x03 {
            0 => ServiceControlType::Publish,
            1 => ServiceControlType::Subscribe,
            2 => ServiceControlType::FollowUp,
            _ => return Err(WireError::Invalid),
        };
        Ok(Self {
            control_type,
            matching_filter_present: b & 0x04 != 0,
            service_response_filter_present: b & 0x08 != 0,
            service_info_present: b & 0x10 != 0,
            discovery_range_limited: b & 0x20 != 0,
            binding_bitmap_present: b & 0x40 != 0,
        })
    }
}

/// Service Descriptor Attribute (SDA, `0x03`) — the core publish/subscribe/
/// follow-up descriptor.
///
/// Fixed header = `service_id(6) | instance_id(1) | requestor_instance_id(1) |
/// service_control(1)`, then optional fields gated by the control byte. Phase 0
/// models the fixed header plus the **matching filter** and **service-specific
/// info** optional fields (the two that carry discovery semantics); the SRF and
/// binding-bitmap fields are left for Phase 1 and rejected here if a peer sets
/// their flags (so we never silently mis-parse).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceDescriptor {
    pub service_id: ServiceId,
    /// The local function's instance id (publisher/subscriber handle).
    pub instance_id: u8,
    /// The peer function's instance id this descriptor responds to (0 if none).
    pub requestor_instance_id: u8,
    pub control: ServiceControl,
    /// Matching filter bytes (LV-encoded), present iff
    /// `control.matching_filter_present`.
    pub matching_filter: Vec<u8>,
    /// Service-specific info, present iff `control.service_info_present`.
    pub service_info: Vec<u8>,
}

impl ServiceDescriptor {
    /// A minimal descriptor (no optional fields) of the given control type.
    pub fn new(service_id: ServiceId, instance_id: u8, control_type: ServiceControlType) -> Self {
        Self {
            service_id,
            instance_id,
            requestor_instance_id: 0,
            control: ServiceControl::new(control_type),
            matching_filter: Vec::new(),
            service_info: Vec::new(),
        }
    }

    /// Attach service-specific info (sets the control flag).
    pub fn with_service_info(mut self, ssi: impl Into<Vec<u8>>) -> Self {
        self.service_info = ssi.into();
        self.control.service_info_present = !self.service_info.is_empty();
        self
    }

    /// Attach a matching filter (sets the control flag).
    pub fn with_matching_filter(mut self, filter: impl Into<Vec<u8>>) -> Self {
        self.matching_filter = filter.into();
        self.control.matching_filter_present = !self.matching_filter.is_empty();
        self
    }

    /// Append the full SDA TLV (header + length + body) to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        // Build the body first so we can prefix its true length.
        let mut body = Vec::new();
        body.put_bytes(&self.service_id);
        body.put_u8(self.instance_id);
        body.put_u8(self.requestor_instance_id);
        body.put_u8(self.control.to_byte());
        // Optional fields, in spec order (matching filter before service info).
        if self.control.matching_filter_present {
            body.put_u8(self.matching_filter.len() as u8);
            body.put_bytes(&self.matching_filter);
        }
        if self.control.service_info_present {
            body.put_u8(self.service_info.len() as u8);
            body.put_bytes(&self.service_info);
        }
        out.put_u8(AttributeId::ServiceDescriptor as u8);
        out.put_le16(body.len() as u16);
        out.put_bytes(&body);
    }

    /// Decode from an attribute body (the bytes after the TLV length).
    pub fn decode(body: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(body);
        let service_id: ServiceId = r.take_array()?;
        let instance_id = r.u8()?;
        let requestor_instance_id = r.u8()?;
        let control = ServiceControl::from_byte(r.u8()?)?;
        // Optional fields not yet modeled would desync the cursor — refuse them
        // explicitly rather than mis-parse.
        if control.service_response_filter_present || control.binding_bitmap_present {
            return Err(WireError::Invalid);
        }
        let mut matching_filter = Vec::new();
        if control.matching_filter_present {
            let len = r.u8()? as usize;
            matching_filter.extend_from_slice(r.take(len)?);
        }
        let mut service_info = Vec::new();
        if control.service_info_present {
            let len = r.u8()? as usize;
            service_info.extend_from_slice(r.take(len)?);
        }
        Ok(Self {
            service_id,
            instance_id,
            requestor_instance_id,
            control,
            matching_filter,
            service_info,
        })
    }
}

/// Service ID List (`0x02`) / Subscribe Service ID List (`0x28`) — a plain
/// concatenation of the 6-byte service IDs a node publishes / subscribes. A
/// stock device (e.g. an S23) advertises both in its beacons; including them
/// lets a peer learn what we offer without waiting for a Service Discovery Frame.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ServiceIdList {
    pub ids: Vec<ServiceId>,
}

impl ServiceIdList {
    /// A list of the given service IDs.
    pub fn new(ids: Vec<ServiceId>) -> Self {
        Self { ids }
    }

    fn encode_with(&self, attr_id: u8, out: &mut Vec<u8>) {
        out.put_u8(attr_id);
        out.put_le16((self.ids.len() * 6) as u16);
        for id in &self.ids {
            out.put_bytes(id);
        }
    }

    /// Append as a **Service ID List** (`0x02`) — services we publish.
    pub fn encode_publish(&self, out: &mut Vec<u8>) {
        self.encode_with(AttributeId::ServiceIdList as u8, out);
    }

    /// Append as a **Subscribe Service ID List** (`0x28`) — services we subscribe.
    pub fn encode_subscribe(&self, out: &mut Vec<u8>) {
        self.encode_with(AttributeId::SubscribeServiceIdList as u8, out);
    }

    /// Decode a list of 6-byte service IDs from an attribute body.
    pub fn decode(body: &[u8]) -> Result<Self, WireError> {
        if !body.len().is_multiple_of(6) {
            return Err(WireError::Invalid);
        }
        let mut r = Reader::new(body);
        let mut ids = Vec::new();
        while !r.is_empty() {
            ids.push(r.take_array()?);
        }
        Ok(Self { ids })
    }
}

/// Device Capability attribute (`0x0f`) — a node's band/DW/antenna capabilities.
/// A 9-byte fixed body. The defaults in [`basic`](Self::basic) mirror the values
/// a Samsung S23 emits (captured on-air) so a stock device accepts us as a
/// compatible cluster peer; tune them once our radio's real capabilities differ.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceCapability {
    pub map_id: u8,
    /// Committed DW info (which Discovery Windows we're awake for). `0x0489` is
    /// the S23-observed 2.4 GHz value.
    pub committed_dw_info: u16,
    /// Supported Bands bitmap (`0x14` = 2.4 GHz + 5 GHz, as the S23 advertises).
    pub supported_bands: u8,
    pub operation_mode: u8,
    /// Antennas: low nibble = TX, high nibble = RX.
    pub num_antennas: u8,
    /// Max channel-switch time (µs, LE).
    pub max_channel_switch_time: u16,
    pub capabilities: u8,
}

impl DeviceCapability {
    /// A plausible 2.4 GHz device capability, byte-compatible with the S23 in the
    /// fields that gate peer acceptance (DW info / bands / operation mode).
    pub fn basic() -> Self {
        Self {
            map_id: 0,
            committed_dw_info: 0x0489,
            supported_bands: 0x14,
            operation_mode: 0x15,
            num_antennas: 0x11,
            max_channel_switch_time: 0,
            capabilities: 0,
        }
    }

    /// Append the full Device Capability TLV (3-byte header + 9-byte body).
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(AttributeId::DeviceCapability as u8);
        out.put_le16(9);
        out.put_u8(self.map_id);
        out.put_le16(self.committed_dw_info);
        out.put_u8(self.supported_bands);
        out.put_u8(self.operation_mode);
        out.put_u8(self.num_antennas);
        out.put_le16(self.max_channel_switch_time);
        out.put_u8(self.capabilities);
    }

    /// Decode from a 9-byte attribute body.
    pub fn decode(body: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(body);
        Ok(Self {
            map_id: r.u8()?,
            committed_dw_info: r.le16()?,
            supported_bands: r.u8()?,
            operation_mode: r.u8()?,
            num_antennas: r.u8()?,
            max_channel_switch_time: r.le16()?,
            capabilities: r.u8()?,
        })
    }
}

/// Append NAN Availability attribute(s) (`0x12`) advertising our availability
/// schedule. A stock NAN-2.0 subscriber (e.g. a Samsung S23's ndn-ripple) will
/// not surface a discovered publisher whose SDF carries no Availability — it
/// needs to know when/where the publisher is reachable.
///
/// These are byte-for-byte the two Availability attributes a real S23 emits in
/// its own publish SDF: a known-valid NAN-2.0 schedule on 2.4 GHz (operating
/// class 81, channels 1–11) across the cluster's time-bitmap slots. We are
/// TSF-merged into that cluster, so the same schedule applies to us. (A
/// from-scratch encoder can replace this once the entry / band-channel layout is
/// validated across more devices.)
pub fn encode_availability(out: &mut Vec<u8>) {
    const AVAIL_A: [u8; 35] = [
        0x8c, 0x02, 0x00, 0x0e, 0x00, 0x0a, 0x10, 0x18, 0x00, 0x04, 0xfc, 0xff, 0xff, 0x3f, 0x11,
        0x51, 0xff, 0x07, 0x00, 0x0e, 0x00, 0x0a, 0x10, 0x18, 0x00, 0x04, 0xfe, 0xff, 0xff, 0xff,
        0x11, 0x51, 0x20, 0x00, 0x00,
    ];
    const AVAIL_B: [u8; 55] = [
        0x8c, 0x01, 0x00, 0x0e, 0x00, 0x1a, 0x10, 0x18, 0x00, 0x04, 0xff, 0x00, 0xff, 0x00, 0x11,
        0x80, 0x01, 0x00, 0x02, 0x0e, 0x00, 0x0a, 0x10, 0x18, 0x00, 0x04, 0x00, 0xf0, 0x00, 0xff,
        0x11, 0x80, 0x20, 0x00, 0x01, 0x12, 0x00, 0x0a, 0x10, 0x18, 0x00, 0x04, 0x00, 0x0f, 0x00,
        0x00, 0x21, 0x80, 0x20, 0x00, 0x0f, 0x80, 0x01, 0x00, 0x0f,
    ];
    for body in [AVAIL_A.as_slice(), AVAIL_B.as_slice()] {
        out.put_u8(AttributeId::NanAvailability as u8);
        out.put_le16(body.len() as u16);
        out.extend_from_slice(body);
    }
}

/// Service Descriptor Extension attribute (SDEA, `0x0e`) — per-service control
/// bits (data-path/ranging/security/QoS required, etc.) keyed to an SDA's
/// instance id. Our publishes need none of those, so [`plain`](Self::plain)
/// emits the S23-observed 3-byte body (instance id + control `0x0000`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sdea {
    pub instance_id: u8,
    pub control: u16,
}

impl Sdea {
    /// A no-op SDEA for `instance_id` (control `0x0000` — no data path / security).
    pub fn plain(instance_id: u8) -> Self {
        Self {
            instance_id,
            control: 0,
        }
    }

    /// Append the SDEA TLV (3-byte header + 3-byte body).
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(AttributeId::ServiceDescriptorExtension as u8);
        out.put_le16(3);
        out.put_u8(self.instance_id);
        out.put_le16(self.control);
    }

    /// Decode from a 3-byte attribute body.
    pub fn decode(body: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(body);
        Ok(Self {
            instance_id: r.u8()?,
            control: r.le16()?,
        })
    }
}

/// NAN Availability attribute (`0x12`) — when/where a node is available. This
/// encodes a single **committed** entry advertising availability across a 2.4
/// GHz channel's Discovery Windows, matching the on-air time-bitmap geometry the
/// S23 uses (16 TU bit duration, 512 TU period).
///
/// Body layout, as verified against a real S23's on-air bytes (see
/// `s23_availability_bytes_decode_with_our_layout`):
///
/// ```text
/// 8c | 02 00 | 0e 00 | 0a 10 | 18 00 | 04 | fc ff ff 3f | 11 51 ff 07 00
/// ^^   ^^^^^   ^^^^^   ^^^^^   ^^^^^   ^^   ^^^^^^^^^^^   ^^^^^^^^^^^^^^
/// seq  ctrl    length  entry   bitmap  len  time bitmap   band/channel
///                      ctrl    ctrl
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedAvailability {
    /// Bumped whenever the advertised schedule changes; peers use it to notice a
    /// stale cached availability.
    pub sequence_id: u8,
    pub map_id: u8,
    /// Operating class (`81` = 2.4 GHz 20 MHz) and the channel within it.
    pub operating_class: u8,
    pub channel: u8,
}

impl CommittedAvailability {
    /// Committed availability on a 2.4 GHz `channel` (operating class 81).
    pub fn ch_2ghz(map_id: u8, channel: u8) -> Self {
        Self {
            sequence_id: 0,
            map_id,
            operating_class: 81,
            channel,
        }
    }

    /// Append the NAN Availability TLV with one committed entry that is available
    /// across the whole 512 TU period (all 32 of the 16 TU slots) on `channel`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        // Build the body first so we can length-prefix it.
        let mut body = Vec::new();
        // Sequence ID precedes Attribute Control. Omitting it shifts every field
        // that follows by one byte, which is what made a real dissector read this
        // attribute as Malformed.
        body.put_u8(self.sequence_id);
        // Attribute Control: Map ID in bits[3:0], Committed-Changed bit 4.
        body.put_le16((self.map_id as u16 & 0x0f) | 0x0010);
        // --- one Availability Entry ---
        let mut entry = Vec::new();
        // Entry Control: Availability Type = Committed (bits[2:0]=1),
        // Time Bitmap Present (bit 12).
        entry.put_le16(0x1001);
        // Time Bitmap Control: Bit Duration 16 TU (0), Period 512 TU (3<<3),
        // Start Offset 0 → 0x0018.
        entry.put_le16(0x0018);
        // Time Bitmap: 4 bytes, all 32 slots available.
        entry.put_u8(4);
        entry.put_bytes(&[0xff, 0xff, 0xff, 0xff]);
        // Band/Channel entries: one operating-class + channel entry.
        // Control byte: bit0 = 1 (operating classes & channels), bits[7:4] = #entries.
        entry.put_u8(0x01 | (1 << 4));
        entry.put_u8(self.operating_class);
        // Channel bitmap (2 bytes LE): the bit for `channel` within the class
        // (ch N → bit N-1 for the 2.4 GHz class).
        let bit = self.channel.saturating_sub(1);
        let mask: u16 = 1u16 << (bit % 16);
        entry.put_le16(mask);
        // Primary channel bitmap (1 byte).
        entry.put_u8(0x00);
        // Entry Length prefixes the entry body.
        body.put_le16(entry.len() as u16);
        body.put_bytes(&entry);

        out.put_u8(AttributeId::NanAvailability as u8);
        out.put_le16(body.len() as u16);
        out.put_bytes(&body);
    }
}

/// NDP message type — which of the M1–M4 data-path exchange this attribute is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NdpType {
    /// M1: the initiator asks for a data path.
    Request = 0,
    /// M2: the responder answers (see [`NdpStatus`]).
    Response = 1,
    /// M3: the initiator confirms.
    Confirm = 2,
    /// M4: key installment (security-enabled paths).
    SecurityInstall = 3,
    Terminate = 4,
}

impl NdpType {
    pub fn from_bits(b: u8) -> Option<Self> {
        Some(match b & 0x0f {
            0 => Self::Request,
            1 => Self::Response,
            2 => Self::Confirm,
            3 => Self::SecurityInstall,
            4 => Self::Terminate,
            _ => return None,
        })
    }
}

/// The responder's verdict, in the high nibble of the type/status byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NdpStatus {
    Continue = 0,
    Accepted = 1,
    Rejected = 2,
}

impl NdpStatus {
    pub fn from_bits(b: u8) -> Option<Self> {
        Some(match (b >> 4) & 0x0f {
            0 => Self::Continue,
            1 => Self::Accepted,
            2 => Self::Rejected,
            _ => return None,
        })
    }
}

/// NDPE Control bits (one byte).
pub mod ndpe_control {
    pub const CONFIRM_REQUIRED: u8 = 0x01;
    pub const SECURITY_PRESENT: u8 = 0x04;
    pub const PUBLISH_ID_PRESENT: u8 = 0x08;
    pub const RESPONDER_NDI_PRESENT: u8 = 0x10;
    pub const GTK_REQUIRED: u8 = 0x20;
}

/// An NDPE TLV — the payload list at the end of the attribute.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NdpeTlv {
    /// Type 0: the 8-byte IPv6 interface identifier of the sender's NDI. This is
    /// the whole point of NDPE — it carries the address the data path will use,
    /// so a peer can form `fe80::<iid>` without any out-of-band exchange.
    Ipv6LinkLocal([u8; 8]),
    /// Type 1: Service Info — a 3-byte OUI plus a vendor-defined body (where a
    /// transport port/protocol descriptor rides).
    ServiceInfo { oui: [u8; 3], body: Vec<u8> },
    /// Anything else, kept verbatim so an unknown TLV round-trips.
    Unknown { tlv_type: u8, body: Vec<u8> },
}

impl NdpeTlv {
    fn tlv_type(&self) -> u8 {
        match self {
            Self::Ipv6LinkLocal(_) => 0,
            Self::ServiceInfo { .. } => 1,
            Self::Unknown { tlv_type, .. } => *tlv_type,
        }
    }

    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(self.tlv_type());
        match self {
            Self::Ipv6LinkLocal(iid) => {
                out.put_le16(8);
                out.put_bytes(iid);
            }
            Self::ServiceInfo { oui, body } => {
                out.put_le16((3 + body.len()) as u16);
                out.put_bytes(oui);
                out.put_bytes(body);
            }
            Self::Unknown { body, .. } => {
                out.put_le16(body.len() as u16);
                out.put_bytes(body);
            }
        }
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, WireError> {
        let tlv_type = r.u8()?;
        let len = r.le16()? as usize;
        let body = r.take(len)?;
        Ok(match tlv_type {
            0 => {
                if body.len() != 8 {
                    return Err(WireError::Invalid);
                }
                let mut iid = [0u8; 8];
                iid.copy_from_slice(body);
                Self::Ipv6LinkLocal(iid)
            }
            1 => {
                if body.len() < 3 {
                    return Err(WireError::Invalid);
                }
                let mut oui = [0u8; 3];
                oui.copy_from_slice(&body[..3]);
                Self::ServiceInfo {
                    oui,
                    body: body[3..].to_vec(),
                }
            }
            other => Self::Unknown {
                tlv_type: other,
                body: body.to_vec(),
            },
        })
    }
}

/// NAN Data Path Extension attribute (NDPE, `0x29`) — the M1–M4 data-path
/// negotiation, carrying each side's NDI and IPv6 interface identifier.
///
/// Body layout (from the Wi-Fi Aware NAN dissector, whose field offsets and bit
/// masks this mirrors — the design doc flagged these codepoints as needing
/// verification before Phase 2 could be byte-compatible):
///
/// ```text
/// dialog(1) | type:status(1) | reason(1) | initiator_ndi(6) | ndp_id(1) | control(1)
///   [ publish_id(1)    if control & PUBLISH_ID_PRESENT and type == Request ]
///   [ responder_ndi(6) if type == Response and status in {Continue, Accepted} ]
///   TLV*   where TLV = type(1) | length(2 LE) | value
/// ```
///
/// The type/status byte packs `type` in the low nibble and `status` in the high
/// nibble. Minimum body is 11 bytes (through `control`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ndpe {
    pub dialog_token: u8,
    pub ndp_type: NdpType,
    pub status: NdpStatus,
    pub reason_code: u8,
    /// The **initiator's** NDI (data-interface MAC), always present — even in a
    /// response, this names the initiator, not the sender.
    pub initiator_ndi: [u8; 6],
    pub ndp_id: u8,
    pub control: u8,
    /// Present on a Request that references a publish session.
    pub publish_id: Option<u8>,
    /// The responder's NDI — only on an accepted/continuing Response.
    pub responder_ndi: Option<[u8; 6]>,
    pub tlvs: Vec<NdpeTlv>,
}

impl Ndpe {
    /// An M1 Data Path Request from `initiator_ndi`, advertising our NDI's IPv6
    /// interface identifier so the responder can address us.
    pub fn request(dialog_token: u8, ndp_id: u8, initiator_ndi: [u8; 6], iid: [u8; 8]) -> Self {
        Self {
            dialog_token,
            ndp_type: NdpType::Request,
            status: NdpStatus::Continue,
            reason_code: 0,
            initiator_ndi,
            ndp_id,
            control: ndpe_control::CONFIRM_REQUIRED,
            publish_id: None,
            responder_ndi: None,
            tlvs: alloc::vec![NdpeTlv::Ipv6LinkLocal(iid)],
        }
    }

    /// An M2 Response accepting `initiator_ndi`'s request, carrying our own NDI
    /// and interface identifier.
    pub fn accept(
        dialog_token: u8,
        ndp_id: u8,
        initiator_ndi: [u8; 6],
        responder_ndi: [u8; 6],
        iid: [u8; 8],
    ) -> Self {
        Self {
            dialog_token,
            ndp_type: NdpType::Response,
            status: NdpStatus::Accepted,
            reason_code: 0,
            initiator_ndi,
            ndp_id,
            control: ndpe_control::RESPONDER_NDI_PRESENT,
            publish_id: None,
            responder_ndi: Some(responder_ndi),
            tlvs: alloc::vec![NdpeTlv::Ipv6LinkLocal(iid)],
        }
    }

    /// An M3 Confirm closing the handshake.
    pub fn confirm(dialog_token: u8, ndp_id: u8, initiator_ndi: [u8; 6]) -> Self {
        Self {
            dialog_token,
            ndp_type: NdpType::Confirm,
            status: NdpStatus::Accepted,
            reason_code: 0,
            initiator_ndi,
            ndp_id,
            control: 0,
            publish_id: None,
            responder_ndi: None,
            tlvs: Vec::new(),
        }
    }

    /// The IPv6 interface identifier the peer advertised, if any.
    pub fn ipv6_iid(&self) -> Option<[u8; 8]> {
        self.tlvs.iter().find_map(|t| match t {
            NdpeTlv::Ipv6LinkLocal(iid) => Some(*iid),
            _ => None,
        })
    }

    /// Append the NDPE TLV (3-byte header + body).
    pub fn encode(&self, out: &mut Vec<u8>) {
        let mut body = Vec::new();
        body.put_u8(self.dialog_token);
        body.put_u8((self.ndp_type as u8 & 0x0f) | ((self.status as u8 & 0x0f) << 4));
        body.put_u8(self.reason_code);
        body.put_bytes(&self.initiator_ndi);
        body.put_u8(self.ndp_id);
        // Keep the control byte's presence bits honest about what we actually
        // append below, rather than trusting the caller to have set them.
        let mut control = self.control;
        if self.publish_id.is_some() {
            control |= ndpe_control::PUBLISH_ID_PRESENT;
        } else {
            control &= !ndpe_control::PUBLISH_ID_PRESENT;
        }
        if self.responder_ndi.is_some() {
            control |= ndpe_control::RESPONDER_NDI_PRESENT;
        } else {
            control &= !ndpe_control::RESPONDER_NDI_PRESENT;
        }
        body.put_u8(control);
        if let Some(id) = self.publish_id
            && self.ndp_type == NdpType::Request
        {
            body.put_u8(id);
        }
        if let Some(ndi) = self.responder_ndi
            && self.ndp_type == NdpType::Response
            && matches!(self.status, NdpStatus::Continue | NdpStatus::Accepted)
        {
            body.put_bytes(&ndi);
        }
        for tlv in &self.tlvs {
            tlv.encode(&mut body);
        }

        out.put_u8(AttributeId::NdpExtension as u8);
        out.put_le16(body.len() as u16);
        out.put_bytes(&body);
    }

    /// Decode from an NDPE attribute body.
    pub fn decode(body: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(body);
        let dialog_token = r.u8()?;
        let type_status = r.u8()?;
        let ndp_type = NdpType::from_bits(type_status).ok_or(WireError::Invalid)?;
        let status = NdpStatus::from_bits(type_status).ok_or(WireError::Invalid)?;
        let reason_code = r.u8()?;
        let initiator_ndi = r.take_array::<6>()?;
        let ndp_id = r.u8()?;
        let control = r.u8()?;

        let publish_id = (control & ndpe_control::PUBLISH_ID_PRESENT != 0
            && ndp_type == NdpType::Request)
            .then(|| r.u8())
            .transpose()?;
        let responder_ndi = (ndp_type == NdpType::Response
            && matches!(status, NdpStatus::Continue | NdpStatus::Accepted))
        .then(|| r.take_array::<6>())
        .transpose()?;

        let mut tlvs = Vec::new();
        while !r.is_empty() {
            tlvs.push(NdpeTlv::decode(&mut r)?);
        }
        Ok(Self {
            dialog_token,
            ndp_type,
            status,
            reason_code,
            initiator_ndi,
            ndp_id,
            control,
            publish_id,
            responder_ndi,
            tlvs,
        })
    }
}

/// The header + first entry of a NAN Availability attribute body.
///
/// Exists to *prove* the encoder's layout: the same reader parses our bytes and a
/// real S23's, so a field-order mistake shows up as a failing test instead of a
/// Malformed frame on air. Discovery does not need a peer's availability, so this
/// deliberately stops after the first entry's fixed fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AvailabilityHeader {
    pub sequence_id: u8,
    pub attribute_control: u16,
    pub map_id: u8,
    /// First Availability Entry: its declared length, control word, and time-bitmap
    /// geometry.
    pub entry_length: u16,
    pub entry_control: u16,
    pub time_bitmap_control: u16,
    pub time_bitmap: Vec<u8>,
    /// Band/channel entry: control byte, operating class, channel bitmap.
    pub band_channel_control: u8,
    pub operating_class: u8,
    pub channel_bitmap: u16,
}

impl AvailabilityHeader {
    /// Decode from a NAN Availability attribute body (the bytes after id + length).
    pub fn decode(body: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(body);
        let sequence_id = r.u8()?;
        let attribute_control = r.le16()?;
        let entry_length = r.le16()?;
        let entry_control = r.le16()?;
        let time_bitmap_control = r.le16()?;
        let tb_len = r.u8()? as usize;
        let time_bitmap = r.take(tb_len)?.to_vec();
        let band_channel_control = r.u8()?;
        let operating_class = r.u8()?;
        let channel_bitmap = r.le16()?;
        Ok(Self {
            sequence_id,
            attribute_control,
            map_id: (attribute_control & 0x0f) as u8,
            entry_length,
            entry_control,
            time_bitmap_control,
            time_bitmap,
            band_channel_control,
            operating_class,
            channel_bitmap,
        })
    }

    /// Is the first entry's Time Bitmap Present bit set?
    pub fn time_bitmap_present(&self) -> bool {
        self.entry_control & (1 << 12) != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn master_indication_layout() {
        let mi = MasterIndication {
            master_preference: 200,
            random_factor: 17,
        };
        let mut buf = Vec::new();
        mi.encode(&mut buf);
        // id=0x00, len=0x0002 LE, body=[200, 17]
        assert_eq!(buf, [0x00, 0x02, 0x00, 200, 17]);
        let attr = Attributes::find(&buf, AttributeId::MasterIndication).unwrap();
        assert_eq!(MasterIndication::decode(attr.body).unwrap(), mi);
    }

    #[test]
    fn cluster_layout_is_13_bytes() {
        let c = Cluster {
            anchor_master_rank: 0x00C8_0000_0000_0000, // pref 200 in MSB
            hop_count: 0,
            ambtt: 0xDEAD_BEEF,
        };
        let mut buf = Vec::new();
        c.encode(&mut buf);
        assert_eq!(buf[0], AttributeId::Cluster as u8);
        assert_eq!(u16::from_le_bytes([buf[1], buf[2]]), 13);
        assert_eq!(buf.len(), 3 + 13);
        let attr = Attributes::find(&buf, AttributeId::Cluster).unwrap();
        assert_eq!(Cluster::decode(attr.body).unwrap(), c);
    }

    #[test]
    fn service_control_byte_roundtrips() {
        let mut sc = ServiceControl::new(ServiceControlType::Subscribe);
        sc.service_info_present = true;
        sc.discovery_range_limited = true;
        let b = sc.to_byte();
        assert_eq!(b & 0x03, 1); // subscribe
        assert_eq!(b & 0x10, 0x10);
        assert_eq!(b & 0x20, 0x20);
        assert_eq!(ServiceControl::from_byte(b).unwrap(), sc);
    }

    #[test]
    fn sda_publish_with_ssi_roundtrips() {
        let sid = crate::service::service_id("org.ndn.test");
        let sda = ServiceDescriptor::new(sid, 7, ServiceControlType::Publish)
            .with_service_info(b"hello".to_vec());
        let mut buf = Vec::new();
        sda.encode(&mut buf);

        let attr = Attributes::find(&buf, AttributeId::ServiceDescriptor).unwrap();
        let decoded = ServiceDescriptor::decode(attr.body).unwrap();
        assert_eq!(decoded, sda);
        assert_eq!(decoded.service_id, sid);
        assert_eq!(decoded.service_info, b"hello");
        assert!(decoded.control.service_info_present);
    }

    #[test]
    fn unmodeled_optional_fields_are_rejected_not_misparsed() {
        // Hand-build an SDA body with the SRF-present bit set but no SRF data:
        // the decoder must refuse rather than read garbage.
        let mut body = Vec::new();
        body.put_bytes(&[0u8; 6]); // service id
        body.put_u8(1); // instance
        body.put_u8(0); // requestor
        body.put_u8(0x08); // control: publish + SRF-present
        assert_eq!(ServiceDescriptor::decode(&body), Err(WireError::Invalid));
    }

    #[test]
    fn attributes_iterate_and_preserve_unknown() {
        // Two attributes: a known Master Indication and an unmodeled id 0x99.
        let mut buf = Vec::new();
        MasterIndication {
            master_preference: 1,
            random_factor: 2,
        }
        .encode(&mut buf);
        Attribute {
            id: 0x99,
            body: &[0xAA, 0xBB],
        }
        .encode(&mut buf);

        let got: Vec<_> = Attributes::new(&buf).map(|a| a.unwrap()).collect();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].id, 0x00);
        assert_eq!(got[1].id, 0x99);
        assert_eq!(got[1].body, &[0xAA, 0xBB]);
    }

    #[test]
    fn service_id_list_publish_and_subscribe_round_trip() {
        let a = crate::service::service_id("ndn");
        let list = ServiceIdList::new(vec![a]);
        let mut buf = Vec::new();
        list.encode_publish(&mut buf);
        list.encode_subscribe(&mut buf);
        // Publish list id 0x02, subscribe list id 0x28, each a 6-byte id.
        assert_eq!(buf[0], 0x02);
        assert_eq!(u16::from_le_bytes([buf[1], buf[2]]), 6);
        let pub_attr = Attributes::find(&buf, AttributeId::ServiceIdList).unwrap();
        let sub_attr = Attributes::find(&buf, AttributeId::SubscribeServiceIdList).unwrap();
        assert_eq!(ServiceIdList::decode(pub_attr.body).unwrap(), list);
        assert_eq!(ServiceIdList::decode(sub_attr.body).unwrap(), list);
        assert_eq!(ServiceIdList::decode(pub_attr.body).unwrap().ids[0], a);
    }

    #[test]
    fn device_capability_is_9_bytes_and_round_trips() {
        let dc = DeviceCapability::basic();
        let mut buf = Vec::new();
        dc.encode(&mut buf);
        assert_eq!(buf[0], AttributeId::DeviceCapability as u8);
        assert_eq!(u16::from_le_bytes([buf[1], buf[2]]), 9);
        assert_eq!(buf.len(), 3 + 9);
        // Committed DW info is little-endian 0x0489 (S23-observed).
        assert_eq!(&buf[4..6], &[0x89, 0x04]);
        let attr = Attributes::find(&buf, AttributeId::DeviceCapability).unwrap();
        assert_eq!(DeviceCapability::decode(attr.body).unwrap(), dc);
    }

    #[test]
    fn sdea_plain_is_3_bytes_and_round_trips() {
        let s = Sdea::plain(7);
        let mut buf = Vec::new();
        s.encode(&mut buf);
        assert_eq!(buf[0], AttributeId::ServiceDescriptorExtension as u8);
        assert_eq!(u16::from_le_bytes([buf[1], buf[2]]), 3);
        let attr = Attributes::find(&buf, AttributeId::ServiceDescriptorExtension).unwrap();
        assert_eq!(Sdea::decode(attr.body).unwrap(), s);
    }

    /// The M1→M2→M3 exchange, in the bytes each side would actually put on air.
    /// Field order and the type/status nibble packing follow the NAN dissector.
    #[test]
    fn ndpe_handshake_round_trips() {
        const INIT_NDI: [u8; 6] = [0x02, 0x4e, 0x41, 0x4e, 0x00, 0x31];
        const RESP_NDI: [u8; 6] = [0x02, 0x26, 0x23, 0xef, 0xbe, 0x2f];
        const INIT_IID: [u8; 8] = [0x00, 0x4e, 0x41, 0xff, 0xfe, 0x4e, 0x00, 0x31];
        const RESP_IID: [u8; 8] = [0x00, 0x26, 0x23, 0xff, 0xfe, 0xef, 0xbe, 0x2f];

        // --- M1: request ---
        let m1 = Ndpe::request(0x42, 7, INIT_NDI, INIT_IID);
        let mut buf = Vec::new();
        m1.encode(&mut buf);
        assert_eq!(buf[0], AttributeId::NdpExtension as u8);
        let body = Attributes::find(&buf, AttributeId::NdpExtension)
            .unwrap()
            .body;
        // Minimum body is 11 bytes through the control byte; ours adds the IID TLV.
        assert!(body.len() >= 11);
        // type in the low nibble, status in the high nibble, of one byte.
        assert_eq!(body[1] & 0x0f, NdpType::Request as u8);
        let back = Ndpe::decode(body).unwrap();
        assert_eq!(back, m1);
        assert_eq!(
            back.ipv6_iid(),
            Some(INIT_IID),
            "M1 advertises our NDI's IID"
        );
        assert_eq!(back.responder_ndi, None, "a request has no responder NDI");

        // --- M2: accept ---
        let m2 = Ndpe::accept(0x42, 7, INIT_NDI, RESP_NDI, RESP_IID);
        let mut buf = Vec::new();
        m2.encode(&mut buf);
        let body = Attributes::find(&buf, AttributeId::NdpExtension)
            .unwrap()
            .body;
        assert_eq!(body[1] & 0x0f, NdpType::Response as u8);
        assert_eq!((body[1] >> 4) & 0x0f, NdpStatus::Accepted as u8);
        let back = Ndpe::decode(body).unwrap();
        assert_eq!(back, m2);
        // The initiator's NDI still names the initiator, even in the response.
        assert_eq!(back.initiator_ndi, INIT_NDI);
        assert_eq!(back.responder_ndi, Some(RESP_NDI));
        assert_eq!(back.ipv6_iid(), Some(RESP_IID));
        assert_eq!(back.ndp_id, 7, "the NDP id ties the exchange together");

        // --- M3: confirm ---
        let m3 = Ndpe::confirm(0x42, 7, INIT_NDI);
        let mut buf = Vec::new();
        m3.encode(&mut buf);
        let body = Attributes::find(&buf, AttributeId::NdpExtension)
            .unwrap()
            .body;
        assert_eq!(Ndpe::decode(body).unwrap(), m3);
    }

    /// The control byte must describe what actually follows it. If it claims a
    /// responder NDI that was never appended, a peer reads 6 bytes of the next
    /// field as a MAC and the rest of the attribute shears — the same class of
    /// bug the Availability Sequence ID caused.
    #[test]
    fn ndpe_control_bits_track_the_optional_fields() {
        const NDI: [u8; 6] = [1, 2, 3, 4, 5, 6];
        // Claim both optional fields are present without supplying either.
        let mut lying = Ndpe::confirm(1, 1, NDI);
        lying.control = ndpe_control::PUBLISH_ID_PRESENT | ndpe_control::RESPONDER_NDI_PRESENT;
        let mut buf = Vec::new();
        lying.encode(&mut buf);
        let body = Attributes::find(&buf, AttributeId::NdpExtension)
            .unwrap()
            .body;
        // The encoder corrects the claim rather than emitting an unreadable body.
        assert_eq!(body[10] & ndpe_control::PUBLISH_ID_PRESENT, 0);
        assert_eq!(body[10] & ndpe_control::RESPONDER_NDI_PRESENT, 0);
        let back = Ndpe::decode(body).unwrap();
        assert_eq!(back.publish_id, None);
        assert_eq!(back.responder_ndi, None);

        // And when a publish id IS set on a request, the bit appears with it.
        let mut req = Ndpe::request(1, 1, NDI, [0; 8]);
        req.publish_id = Some(0x09);
        let mut buf = Vec::new();
        req.encode(&mut buf);
        let body = Attributes::find(&buf, AttributeId::NdpExtension)
            .unwrap()
            .body;
        assert_eq!(
            body[10] & ndpe_control::PUBLISH_ID_PRESENT,
            ndpe_control::PUBLISH_ID_PRESENT
        );
        assert_eq!(Ndpe::decode(body).unwrap().publish_id, Some(0x09));
    }

    #[test]
    fn ndpe_keeps_unknown_tlvs_and_service_info() {
        const NDI: [u8; 6] = [1, 2, 3, 4, 5, 6];
        let mut m = Ndpe::request(1, 1, NDI, [9; 8]);
        m.tlvs.push(NdpeTlv::ServiceInfo {
            oui: [0x50, 0x6f, 0x9a],
            body: alloc::vec![0xde, 0xad],
        });
        m.tlvs.push(NdpeTlv::Unknown {
            tlv_type: 0x77,
            body: alloc::vec![0x01, 0x02, 0x03],
        });
        let mut buf = Vec::new();
        m.encode(&mut buf);
        let body = Attributes::find(&buf, AttributeId::NdpExtension)
            .unwrap()
            .body;
        // An unknown TLV survives a decode/encode cycle unchanged.
        assert_eq!(Ndpe::decode(body).unwrap(), m);
    }

    #[test]
    fn ndpe_rejects_truncated_and_reserved_values() {
        assert!(
            Ndpe::decode(&[0u8; 10]).is_err(),
            "shorter than the 11-byte minimum"
        );
        // Reserved NDP type (5..=15).
        let mut body = [0u8; 11];
        body[1] = 0x05;
        assert!(Ndpe::decode(&body).is_err());
        // Reserved status (3..=15).
        let mut body = [0u8; 11];
        body[1] = 0x30;
        assert!(Ndpe::decode(&body).is_err());
    }

    /// The layout proof: the *same* reader that parses our encoder's output must
    /// parse a real S23's Availability bytes into the values a dissector reported
    /// for that capture. If the field order is wrong, this fails — which is how the
    /// missing Sequence ID byte hid for so long (the old test only checked that the
    /// TLV length matched its body, which a misaligned body satisfies happily).
    #[test]
    fn s23_availability_bytes_decode_with_our_layout() {
        // The first Availability attribute a real S23 emits in its publish SDF.
        const S23_AVAIL_A: [u8; 35] = [
            0x8c, 0x02, 0x00, 0x0e, 0x00, 0x0a, 0x10, 0x18, 0x00, 0x04, 0xfc, 0xff, 0xff, 0x3f,
            0x11, 0x51, 0xff, 0x07, 0x00, 0x0e, 0x00, 0x0a, 0x10, 0x18, 0x00, 0x04, 0xfe, 0xff,
            0xff, 0xff, 0x11, 0x51, 0x20, 0x00, 0x00,
        ];
        let h = AvailabilityHeader::decode(&S23_AVAIL_A).expect("S23 bytes parse");
        assert_eq!(h.sequence_id, 0x8c);
        assert_eq!(h.attribute_control, 0x0002, "Map ID 2, as captured");
        assert_eq!(h.map_id, 2);
        assert_eq!(h.entry_length, 14);
        assert_eq!(h.entry_control, 0x100a);
        assert!(h.time_bitmap_present());
        // Bit Duration 16 TU, Period 512 TU — the geometry our DW clock assumes.
        assert_eq!(h.time_bitmap_control, 0x0018);
        assert_eq!(h.time_bitmap, [0xfc, 0xff, 0xff, 0x3f]);
        // Band/channel: one operating-class entry, class 81 (2.4 GHz), ch 1–11.
        assert_eq!(h.band_channel_control, 0x11);
        assert_eq!(h.operating_class, 81);
        assert_eq!(h.channel_bitmap, 0x07ff);
    }

    #[test]
    fn committed_availability_round_trips_for_ch6() {
        let av = CommittedAvailability::ch_2ghz(0, 6);
        let mut buf = Vec::new();
        av.encode(&mut buf);
        assert_eq!(buf[0], AttributeId::NanAvailability as u8);
        let len = u16::from_le_bytes([buf[1], buf[2]]) as usize;
        assert_eq!(buf.len(), 3 + len);
        assert_eq!(Attributes::new(&buf).flatten().count(), 1);

        let attr = Attributes::find(&buf, AttributeId::NanAvailability).unwrap();
        let h = AvailabilityHeader::decode(attr.body).expect("our own bytes parse");
        assert_eq!(h.sequence_id, 0);
        assert_eq!(h.map_id, 0);
        assert_eq!(h.attribute_control & 0x10, 0x10, "committed-changed set");
        // Committed (bit 0), with a time bitmap — and the S23's 16 TU / 512 TU
        // geometry, so our schedule is expressed in the same terms as the peer's.
        assert_eq!(h.entry_control, 0x1001);
        assert!(h.time_bitmap_present());
        assert_eq!(h.time_bitmap_control, 0x0018);
        assert_eq!(h.operating_class, 81);
        // ch 6 → bit 5.
        assert_eq!(h.channel_bitmap, 1 << 5);
        // The entry's declared length must match what actually follows it.
        assert_eq!(h.entry_length as usize, attr.body.len() - 5);
    }
}
