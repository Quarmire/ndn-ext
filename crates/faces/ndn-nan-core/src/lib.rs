//! Byte-exact, **sans-I/O** Wi-Fi Aware (NAN) protocol core.
//!
//! This crate is the interop-critical heart of the userspace NAN stack: it
//! encodes and decodes NAN frames *exactly* as a stock Wi-Fi Aware device (e.g.
//! an Android phone) puts them on the air, with **no I/O, no async, and no
//! clock of its own**. Platform drivers (the desktop `ndn-nan` crate over
//! `FrameIo`, or an embedded driver over an open-MAC radio) feed it time +
//! inbound frames and transmit its outbound frames.
//!
//! It is `#![no_std]` (with `alloc`) so the *same* byte-for-byte codec runs on a
//! laptop and on an ESP32. See the design doc
//! (`ndn-face-wifi-aware/docs/NAMED_RADIO_EXPANSION_DESIGN.md`).
//!
//! ## Scope (this module set)
//!
//! The wire layer:
//! - [`wire`] — little-endian read/write primitives over byte buffers.
//! - [`attr`] — the NAN attribute TLV format (`id | len_le16 | body`) and the
//!   sync/discovery-critical typed attributes (Master Indication, Cluster,
//!   Service Descriptor).
//! - [`frame`] — the 802.11 management header and the two NAN frame carriers: a
//!   NAN **beacon** (sync/discovery) and a NAN **Service Discovery Frame** (a
//!   public action frame).
//! - [`service`] — the NAN service-ID hash (first 6 bytes of SHA-256 of the
//!   lowercased service name), byte-identical to Android `WifiAwareManager`.
//!
//! And the state machine that sits on top of it:
//! - [`engine`] — the sans-I/O sync/discovery/data-path state machine. Discovery
//!   and coordination against a stock Wi-Fi Aware device are shipped (proven on
//!   air, mutually, against a Samsung S23), as is the M1-M4 NDP handshake that
//!   settles a data path's addresses. Full master/anchor election role
//!   transitions and multi-channel Discovery Windows are not yet built.
//! - [`rendezvous`] — the pluggable rendezvous strategy the engine schedules
//!   against ([`rendezvous::DiscoveryWindow`] for NAN's 512/16-TU clock,
//!   [`rendezvous::AlwaysOn`] for radios that never sleep). Lifted out of the
//!   engine so the DW clock is a choice rather than a hardcoded assumption.
//!
//! Note that the NDP data path the engine negotiates is an **interop bearer**,
//! not this stack's own data path — see
//! `ndn-face-wifi-aware/docs/NAMED_RADIO_COURSE_CORRECTION.md`.
//!
//! ## Wire facts (interop-critical; verified against opennan + the Wireshark
//! `wifi_nan` dissector)
//!
//! - All multi-byte integers are **little-endian**.
//! - Wi-Fi Alliance **OUI** `50:6F:9A`; NAN OUI type `0x13`.
//! - A NAN beacon's NAN data rides in a vendor-specific information element
//!   (element id `0xDD`); a Service Discovery Frame is a **public action** frame
//!   (`category 0x04`, `action 0x09`) whose attributes follow the OUI/type
//!   directly (no `0xDD` IE wrapper).
//! - Cluster ID base `50:6F:9A:01:xx:xx`; the broadcast/network address
//!   `51:6F:9A:01:00:00`.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod attr;
pub mod engine;
pub mod frame;
pub mod rendezvous;
pub mod service;
pub mod wire;

pub use attr::{
    Attribute, AttributeId, Attributes, Cluster, CommittedAvailability, DeviceCapability,
    MasterIndication, Sdea, ServiceControl, ServiceControlType, ServiceDescriptor, ServiceIdList,
};
pub use engine::{
    NDP_MAX_ATTEMPTS, NDP_RETRY_USEC, NanConfig, NanEngine, NanEvent, NdpFailure, NdpRole, RxFrame,
    Step, TxFrame, Usec, eui64_iid, master_rank,
};
pub use frame::{Dot11Frame, Dot11Header, FrameType, NanBeacon, ServiceDiscoveryFrame, classify};
pub use rendezvous::{AlwaysOn, DiscoveryWindow, Rendezvous};
pub use service::service_id;
pub use wire::{Reader, WireError, WriteExt};

/// The Wi-Fi Alliance OUI used by all NAN frames (`50:6F:9A`).
pub const NAN_OUI: [u8; 3] = [0x50, 0x6F, 0x9A];

/// The OUI type identifying NAN within the OUI (`0x13`), used in both the beacon
/// vendor IE and the Service Discovery Frame.
pub const NAN_OUI_TYPE: u8 = 0x13;

/// The OUI type for NAN **action** frames (data path / ranging / schedule) —
/// distinct from the service-discovery `0x13`. Reserved for Phase 2 (NDP).
pub const NAN_OUI_TYPE_ACTION: u8 = 0x18;

/// Cluster ID base: a NAN cluster's BSSID is `50:6F:9A:01:xx:xx`, the last two
/// octets randomized per cluster.
pub const NAN_CLUSTER_ID_BASE: [u8; 6] = [0x50, 0x6F, 0x9A, 0x01, 0x00, 0x00];

/// The NAN network ID — the destination (addr1) of broadcast Service Discovery
/// Frames (`51:6F:9A:01:00:00`).
pub const NAN_NETWORK_ID: [u8; 6] = [0x51, 0x6F, 0x9A, 0x01, 0x00, 0x00];

/// The 802.11 broadcast address.
pub const BROADCAST: [u8; 6] = [0xFF; 6];

/// A NAN service ID — the 6-byte truncated hash of a service name that keys
/// publish/subscribe matching. See [`service::service_id`].
pub type ServiceId = [u8; 6];

/// One Time Unit (TU) = 1024 microseconds, the NAN/802.11 timing quantum.
pub const USEC_PER_TU: u64 = 1024;

/// Discovery Window interval: a DW recurs every **512 TU** (~524 ms).
pub const DW_INTERVAL_TU: u64 = 512;

/// Discovery Window length: **16 TU** (~16.4 ms) of the 512 TU period.
pub const DW_LENGTH_TU: u64 = 16;

/// Sync-beacon cadence: one per Discovery Window (every 512 TU).
pub const SYNC_BEACON_INTERVAL_TU: u64 = 512;

/// Discovery-beacon cadence: every 100 TU, transmitted outside the DW by a
/// master.
pub const DISCOVERY_BEACON_INTERVAL_TU: u64 = 100;
