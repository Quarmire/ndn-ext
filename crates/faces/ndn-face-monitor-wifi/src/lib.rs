//! Connectionless **802.11 monitor-mode** face — a named-radio bearer over raw
//! WiFi injection.
//!
//! **Architecture & concepts: see `docs/RADIO_SUBSYSTEM.md`** — the two seams
//! ([`FrameIo`] data plane / [`RadioKnobs`] control plane), how a radio is a
//! *pool of capability* rather than an IP interface, how this binds to `ndn-rs`,
//! the per-chip device details, and the recipe for adding a backend. (That file
//! is a local staging note and is gitignored — it is not in a clone.)
//!
//! **Doctrine: see `docs/named-radio.md`** (tracked), with the frontier ideas in
//! `docs/named-radio-vision-frontier.md` and the authoritative correction in
//! `../ndn-face-wifi-aware/docs/NAMED_RADIO_COURSE_CORRECTION.md`. Those three
//! carry the rules this crate exists to honour: the NDN *name* is the addressing,
//! you do not join a network, and a peer publishes capability as named signed
//! Data (`/can-serve/…`) — never "I am device X." Read them before adding a
//! bearer. A design that reintroduces host addressing (MAC/EUI-64/IP/ports) is
//! legitimate only as an **interop** bearer for peers we do not control, and must
//! say so; our own traffic rides [`FrameFormat::RawNdn`]. This doctrine was
//! gitignored until 2026-07-16, which is exactly how an in-tree, reviewed design
//! came to contradict it unremarked.
//!
//! This is the data-centric reframing of wfb-ng: monitor mode + raw frame
//! injection, with the host-centric parts (association, MAC addressing, ARQ)
//! discarded. There is no destination address — the NDN *name* is the
//! addressing. Every monitor-mode receiver in range hears every injected frame
//! and evaluates it against its own PIT/FIB/CS.
//!
//! ## Why this beats the "broadcast is stuck at legacy rates" wall
//!
//! That wall is a property of the **managed-mode** MAC: an AP sends
//! group-addressed frames at a *basic rate* because there is no per-receiver
//! ACK to rate-adapt against. It is **not** a property of the radio. When we
//! *inject* in monitor mode we prepend a [`radiotap`] TX header that names the
//! MCS per frame — so we transmit at near link rate, with no AP basic-rate
//! floor. What injection gives up is link-layer ARQ and rate-adaptation
//! feedback, and the architecture already replaces both: loss is handled by
//! FEC/RLNC (`ndn-coding`) instead of retransmits, and rate feedback rides the
//! cross-layer signal store (per-frame RSSI → adaptive MCS, see
//! [`mcs_for_rssi`]) instead of a MAC back-channel.
//!
//! ## How it slots into the engine
//!
//! - **`link_type() == AdHoc`** — one undifferentiated broadcast domain. The
//!   engine's Data path re-radiates Data back onto an ad-hoc face so the nodes a
//!   relay serves can hear it. Mirrors [`ndn-face-ble-adv`](https://docs.rs).
//! - **`send_mtu()` set** — an injected 802.11 frame carries ~1500 bytes, so the
//!   paired `LpLinkService` fragments larger NDN packets across frames
//!   automatically (NDNLPv2). No custom chunking in the face.
//! - **RSSI → `SignalStore`** — every captured frame's radiotap RSSI is
//!   published as `LinkSignals` for this face, feeding measured/CCLF strategies
//!   *and* this face's own adaptive-MCS picker.
//!
//! ## Structure
//!
//! The radio is abstracted behind [`FrameIo`]: how raw frames reach the air
//! is a backend choice, exactly the `AdvBackend`/`RadioBackend`/`NanBackend`
//! pattern used elsewhere in the stack.
//!
//! - `AfPacketBackend` (Linux, `cfg(target_os = "linux")`) — `AF_PACKET`
//!   `SOCK_RAW` on a monitor-mode interface; builds radiotap TX + the 802.11
//!   frame per [`FrameFormat`], parses radiotap RX. Requires `CAP_NET_RAW`.
//! - [`LoopbackMonitorBus`] — a hardware-free shared medium for CI and
//!   simulation; carries the NDN payload plus a simulated RSSI/MCS so the whole
//!   face, NDNLPv2 fragmentation, and RSSI plumbing run through a real engine
//!   without a radio.
//!
//! - `LibUsbRtl88xxBackend` (`libusb-backend` feature) — a **working**
//!   userspace driver for the RTL8812EU (halmac 8822E) over libusb, for hosts
//!   without an `AF_PACKET` monitor interface (macOS / non-`rtl8812au` Linux).
//!   Full 5 GHz monitor-mode bring-up (power, firmware, MAC/BB/RF, the
//!   IQK/LCK/DACK/TXGAPK/kfree calibrations, the BT-coex grant that ungates TX
//!   power, and the regulatory-limited per-rate power-by-rate) plus HT and VHT
//!   (802.11ac) inject and RX. Verified on-air to the full 11n single-stream
//!   range and VHT 256-QAM at kernel-level power. **Not yet ported:** the
//!   periodic phydm watchdog (runtime thermal TX-power tracking / DIG / CFO),
//!   40/80 MHz and narrowband bandwidths, and the 2.4 GHz band. See
//!   the crate docs (`docs/named-radio.md`).

// OS-I/O leaf crate: it owns the raw syscall / mmap / FFI boundary, so
// unsafe is inherent here. Denied workspace-wide, allowed in this crate.
#![allow(unsafe_code)]

use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::{AtomicI8, Ordering};
use std::time::Duration;

use bytes::Bytes;
use ndn_coding::link_fec_bridge::{GenerationSink, LinkFecBridge};
use ndn_radio_cognition::TxParams;
use ndn_signals_core::{LinkSignals, SignalStore};
use ndn_transport::{
    Face, FaceAddr, FaceKind, FacePersistency, LinkType, MtuError, PersistencyError, Transport,
};
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

// The frame-I/O substrate — the `FrameIo` trait, the inject/capture frame
// types, the on-air framing (`frame`/`radiotap`), and the reusable AF_PACKET +
// loopback backends — moved to `ndn-frame-io`. Re-exported here so existing
// `ndn_face_monitor_wifi::` paths (and this crate's own modules, which still
// reference `crate::frame::…`, `crate::McsDescriptor`, `crate::FrameIo`) keep
// working unchanged.
#[cfg(target_os = "linux")]
pub use ndn_frame_io::AfPacketBackend;
pub use ndn_frame_io::{
    BROADCAST, CapturedFrame, DEFAULT_SRC, EphemeralSource, ESPNOW_MAX_BODY, ESPNOW_OUI, FaceError, FaceId,
    FrameFormat, FrameIo, GroupKey, InjectFrame, LEGACY_ETHER_MTU, LoopbackEndpoint,
    LoopbackMonitorBus, MAX_RELIABLE_MCS, MONITOR_MTU, McsDescriptor, McsPolicy, OPEN_GROUP_KEY,
    RadioCapability, Reach, Reliability, TxIntent, WifiRadio, frame, mcs_for_rssi, mcs_phy_rate_bps,
    radiotap,
};

// The four userspace USB Wi-Fi driver backends (RTL8812EU/8822E, RTL8821CU,
// MT7612U, RTL8812AU) were lifted into the standalone `ndn-radio-drivers` crate
// so drivers have a dedicated home. Re-exported here so existing
// `ndn_face_monitor_wifi::` paths (and this crate's `crate::LibUsbRtl88xxBackend`
// etc. references in `control.rs`/`lib.rs`) keep working unchanged.
#[cfg(feature = "libusb-backend")]
pub use ndn_radio_drivers::{
    CHIP_ID_8822E, ChannelBw, ChipInfo, FwVersion, IqkResult, LibUsbRtl88xxBackend, MT7612U_PIDS,
    Mt7612uBackend, REALTEK_VID, REG_SYS_CFG, RTL88XX_PIDS, RTL8733B_PIDS, RTL8812AU_PIDS,
    RTL8821CU_PIDS, RfPath, Rtl8733buBackend, Rtl8812auBackend, Rtl8821cuBackend,
};

// The BW16 (RTL8720DN) serial-bridged backend — a dual-band 802.11 node driven
// over USB-serial, usable under a MonitorWifiFace exactly like the USB backends.
#[cfg(feature = "bw16")]
pub use ndn_radio_drivers::Bw16SerialBackend;

mod control;

/// Absolute dBm TX-power control for Linux mac80211 radios (driver-agnostic).
/// Portable code — it compiles anywhere, but discovery only finds anything on a
/// Linux host with debugfs/nl80211, and is inert elsewhere.
pub mod dbm_power;
#[cfg(feature = "libusb-backend")]
pub use control::LibUsbActuator;
pub use control::RadioControl;
pub use control::{activity_rate, spawn_occupancy_sampler};
/// Advertised RX-capability sentinels for the worst-overheard-receiver rate cap.
pub use ndn_radio_cognition::{FULL_RX_MCS, LEGACY_ONLY_RX};

// "The medium is the face": one NDN face over N radio *capabilities* (RX union +
// TX fan-out), the data plane matching the already-medium-shaped `RadioControl`.
mod medium;
pub use medium::{
    ContextSource, LinkSignalStore, LossMeter, MediumActuator, RadioBearer, RadioId,
    RadioMediumFace, RunningMedium, StaticContexts, spawn_control_loop,
};

// The `FaceFactory` for the medium: stand the radio face up from `FaceParams` data,
// so a connectivity resolver / config row can `add_face_of_kind(Wfb, ..)` it.
mod factory;
pub use factory::RadioMediumFaceFactory;

pub mod radio;
pub use radio::{Bandwidth, DbmRange, OpenRadio, RadioKnobs, RadioProfile, RadioTime};

// The data-centric time-slice (#61) + FHSS (#40) transmit scheduler, actuated at the TX path.
mod sched;
pub use sched::{FaceScheduler, TIME_BEACON_MAGIC, TimeStatus};

pub mod measure;

// #91 Tier-0: the in-frame prefix-set Bloom filter (addr1 ‖ addr2). Zero-parse name matching that
// replaces the name-group hash; ported from the measured firmware reference. See the module docs.
pub mod name_gate;
pub mod ndn_nic;
pub mod tier0;
pub mod tier1;
pub use tier0::PrefixFilter;

// nl80211 Wi-Fi channel control (Linux), folded in from the former ndn-research
// draft crate — it belongs with the Wi-Fi monitor face.
#[cfg(target_os = "linux")]
pub mod channel_manager;
#[cfg(target_os = "linux")]
pub use channel_manager::ChannelManager;

/// MTU for an **ESP-NOW** face: the ESP-NOW vendor-element body cap (250 B, see
/// [`ESPNOW_MAX_BODY`]). The paired `LpLinkService` fragments NDN packets to
/// this so every NDNLPv2 fragment rides one ESP-NOW frame a stock `esp-wifi`
/// peer (e.g. an ESP32-C5) can parse. Built by [`MonitorWifiFace::espnow`].
pub const ESPNOW_MTU: usize = ESPNOW_MAX_BODY;

/// A connectionless 802.11 monitor-mode injection face. Build a [`Face`] with
/// [`into_face`](Self::into_face), which pairs the `LpLinkService` so the engine
/// fragments/reassembles NDN packets across injected frames.
/// Coalesces queued outbound frames into **A-MSDU bursts** — the face-level
/// realization of radio-layer bundling. [`submit`](Self::submit) is non-blocking;
/// a background task drains up to `max_msdus` frames within a latency `window`
/// and hands them to [`FrameIo::inject_batch_at`](ndn_radio_hal::FrameIo::inject_batch_at), which
/// the AF_PACKET backend overrides with real aggregation (one A-MSDU per same-RA run, greedily
/// packed). Each MSDU stays an independent NDN packet (the receiver de-aggregates),
/// so only airtime is shared — the throughput↔latency knob, not NDN-layer Interest
/// bundling. Started by [`MonitorWifiFace::with_amsdu_batching`]. Each queued frame
/// carries its resolved MCS, so the exact rate rides the batch, not the seam.
///
/// The aggregation is **the backend's**, and is reached only by calling `inject_batch_at` on the
/// trait object. #82 part 1 briefly routed this through a local free function holding a copy of the
/// trait's *default* body, which dispatches to no override and quietly turned every batch back into
/// individual MPDUs — no error, no log, just the airtime saving gone. Part 2 restored the virtual
/// call and moved the method onto `FrameIo` so the seam a face holds is the seam that aggregates.
struct TxBatcher {
    tx: tokio::sync::mpsc::UnboundedSender<(InjectFrame, McsDescriptor)>,
}

impl TxBatcher {
    fn spawn(backend: Arc<dyn FrameIo>, max_msdus: usize, window: Duration) -> Self {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<(InjectFrame, McsDescriptor)>();
        tokio::spawn(async move {
            while let Some(first) = rx.recv().await {
                let mut batch = vec![first];
                let deadline = tokio::time::Instant::now() + window;
                while batch.len() < max_msdus {
                    match tokio::time::timeout_at(deadline, rx.recv()).await {
                        Ok(Some(f)) => batch.push(f),
                        _ => break, // window elapsed, or the face was dropped
                    }
                }
                let _ = backend.inject_batch_at(batch).await;
            }
        });
        TxBatcher { tx }
    }

    fn submit(&self, frame: InjectFrame, mcs: McsDescriptor) -> Result<(), FaceError> {
        self.tx.send((frame, mcs)).map_err(|_| FaceError::Closed)
    }
}

/// **What a coded generation pins to the frame that opened it: its whole on-air identity.**
///
/// One sink serves both faces (#82). Before this, each had its own: `MonitorWifiFace` pinned
/// `(mcs, dst)` and `RadioMediumFace` used `ndn-coding`'s generic `FrameIoSink` with no pin at all,
/// so each reconstructed the addressing its direct send path had already computed — badly, and
/// differently. Both dropped things:
///
/// * **Tier-0 addressing.** Under [`TxAddr::PrefixBloom`] the object's 12-byte prefix-set filter is
///   split across *both* address fields (addr1 = hi, addr2 = lo) and the receiver reassembles
///   `addr1 ‖ addr2` before testing it. Pinning only `dst` left the sender's fixed source in addr2,
///   so a receiver registered on that very prefix reconstructed half a filter and dropped the
///   frame — a false negative, not a lost optimisation. `tier0_addressing_survives_link_fec` is
///   the regression test; it failed with `addr2 = 02 4e 44 4e 00 01` (`DEFAULT_SRC`).
/// * **The doctrine §2 rotating nonce.** The face pinned no `addr3` at all; the medium snapshotted
///   one nonce for the bridge's whole lifetime. Either way the rotation that bounds linkability
///   stopped happening the moment FEC was enabled.
/// * **The legacy-rate gate** on the medium, which hardcoded `CONSERVATIVE` and so ignored the
///   worst-overheard-receiver cap for coded traffic.
///
/// The cause was the same each time: the pin carried *less* than an [`InjectFrame`] needs, so the
/// sink had to invent the rest. It now carries exactly what the direct path computes, and both
/// faces build it from that same code — there is nothing left for a sink to guess.
///
/// The pin is per-*generation*, snapshotted from the opening frame, and that is deliberate: all
/// k + R frames of a generation share one address, so a receiver that admits the object also admits
/// its parity. Addressing parity independently would fail — a parity frame carries no NDN name to
/// derive a filter from.
#[derive(Clone, Copy)]
pub(crate) struct RadioFecPin {
    /// addr1 — the broadcast address, a split per-Data-name address, or the filter's high half.
    pub dst: [u8; 6],
    /// addr2 — the ephemeral source nonce, or the filter's low half under Tier-0.
    pub src: [u8; 6],
    /// addr3 — the doctrine §2 nonce when Tier-0 displaced it out of addr2.
    pub addr3: Option<[u8; 6]>,
    /// The transmit intent (so the medium's legacy-rate gate reaches coded frames too).
    pub intent: TxIntent,
    /// The exact rate, when the bearer takes one per frame (`MonitorWifiFace`). `None` where rate is
    /// bearer state held in the driver (`RadioMediumFace`), which then injects at whatever is set.
    pub mcs: Option<McsDescriptor>,
}

/// The radio side of link FEC, shared by both faces: inject each coded frame of a generation as its
/// **own** MPDU — never one generation per aggregate, where a single FCS failure would erase all of
/// it — carrying the generation's pinned address, intent and rate.
pub(crate) struct RadioFecSink {
    pub radio: Arc<dyn FrameIo>,
}

impl GenerationSink for RadioFecSink {
    type Pin = RadioFecPin;

    async fn emit(&self, coded: Vec<Bytes>, pin: &RadioFecPin) {
        for f in coded {
            let frame = InjectFrame {
                payload: f,
                tx: pin.intent,
                dst: pin.dst,
                src: pin.src,
                addr3: pin.addr3,
            };
            let _ = match pin.mcs {
                Some(mcs) => self.radio.inject_at(frame, mcs).await,
                None => self.radio.inject(frame).await,
            };
        }
    }
}

struct FaceFec {
    /// Batching + plan-R actuation over the radio; the pin is the generation's whole on-air
    /// identity — see [`RadioFecPin`].
    bridge: LinkFecBridge<RadioFecPin>,
    /// Payloads recovered/delivered by the decoder, awaiting `recv_bytes`.
    pending: std::sync::Mutex<VecDeque<(Bytes, Option<FaceAddr>)>>,
}

impl FaceFec {
    fn spawn(backend: Arc<dyn FrameIo>, k: usize, redundancy: u16, window: Duration) -> Self {
        // The generation loop, the window flush, and the plan-driven R actuation are all in the
        // bearer-agnostic bridge (task #33); the radio specifics are in the shared
        // [`RadioFecSink`], which both faces use (#82). Everything on-air-visible rides the
        // per-generation pin, so per-Data-name addressing and the §2 nonce compose with coding
        // instead of being reinvented by the sink.
        let bridge = LinkFecBridge::spawn(RadioFecSink { radio: backend }, k, redundancy, window);
        FaceFec {
            bridge,
            pending: std::sync::Mutex::new(VecDeque::new()),
        }
    }
}

/// **How outgoing frames get their addr1** — a composable, configurable capability
/// (set independently of the RX filter, the FEC bridge, the MCS policy, the trust
/// key). See `docs/mac-addressing-doctrine.md` §8.
#[derive(Clone)]
pub enum TxAddr {
    /// No name addressing: broadcast — every receiver in range hears it.
    Broadcast,
    /// **Tier-0 prefix-set Bloom filter** (#91): every prefix of the object's inner NDN
    /// name is inserted into a 94-bit filter carried in `addr1 ‖ addr2` (all fragments of
    /// one object share it), with the ephemeral source nonce in `addr3`. This ships *all*
    /// name granularities at once, so a receiver matches at *its own* registered prefix —
    /// longest-prefix match becomes a receiver-local decision and the out-of-band granularity
    /// agreement the old name-group hash needed disappears. See `tier0` and the redesign §3.
    PrefixBloom {
        /// Trust context; keys the filter so a private group is unlinkable.
        key: GroupKey,
    },
}

// `RxFilter` moved to `name_gate` (#82) — the gate is now one implementation shared by both
// faces, instead of this enum being matched separately in each.
pub use name_gate::{NameGate, RxFilter};


/// Extract the NDN **Name** TLV bytes from an LP-framed wire frame's inner packet,
/// for [`TxAddr::PrefixBloom`]. Returns `None` for a non-first fragment (the name is
/// only in fragment 0) or a parse miss. The face's one bounded NDN-structure peek —
/// a producer compiling its own Data's name into the address, as V-MAC does.
pub(crate) fn inner_name(wire: &[u8]) -> Option<&[u8]> {
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

/// Render an NDN **Name** TLV (`0x07 { 0x08 len comp … }`) to the `/`-joined byte form the
/// Tier-0 filter iterates (`/x/y`), so a producer compiling the wire name and a receiver
/// registering a `/`-string prefix compute [`PrefixFilter`] positions over identical bytes.
///
/// Component values are used verbatim. A raw `/` inside a component would create a false
/// prefix boundary — rare for `GenericNameComponent`s, and harmless in the safe direction
/// (an extra false positive; Tier 1/2 does the exact match). Falls back to the raw TLV bytes
/// if it won't parse, so the filter is still deterministic rather than panicking.
pub(crate) fn ndn_name_to_slash(name_tlv: &[u8]) -> Vec<u8> {
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

/// The 64-bit Tier-0 filter key from a [`GroupKey`] (first 8 bytes) — [`OPEN_GROUP_KEY`] a public
/// keyspace, a shared secret a private one. Shared by the single-radio face and the multi-radio medium.
/// The Tier-0 filter key **is** the whole [`GroupKey`].
///
/// This used to truncate to the low 8 bytes, because the FNV keying took a `u64`. SipHash-2-4 takes
/// the full 128-bit key, so a private group's key now contributes all of its entropy instead of half.
pub(crate) fn bloom_key64(key: &GroupKey) -> &[u8; 16] {
    &key.0
}

/// The 12 wire bytes (`addr1 ‖ addr2`) of the Tier-0 filter for the NDN name inside an LP wire frame
/// (first fragment / bare packet). `None` when the wire carries no name (a non-first fragment) — the
/// caller falls back to broadcast, which every receiver's filter admits (a safe over-accept).
pub(crate) fn bloom_wire_for_wire(key: &GroupKey, wire: &[u8]) -> Option<[u8; 12]> {
    let name = inner_name(wire)?;
    let mut f = PrefixFilter::new();
    f.insert_name(bloom_key64(key), &ndn_name_to_slash(name));
    Some(f.to_wire())
}

/// Precompute one [`PrefixFilter::mask_for`] per registered `/`-string prefix — a receiver's
/// [`RxFilter::Bloom`] mask set, reusable by the medium's RX reader.
pub(crate) fn bloom_masks_for(key: &GroupKey, prefixes: &[impl AsRef<[u8]>]) -> std::sync::Arc<[PrefixFilter]> {
    let k = bloom_key64(key);
    prefixes.iter().map(|p| PrefixFilter::mask_for(k, p.as_ref())).collect()
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


// `inject_at` / `inject_batch_at` are called straight on `FrameIo` — there are no local helpers.
//
// #82 part 1 moved this face from `Arc<dyn WifiRadio>` to `Arc<dyn FrameIo>`. That was the right
// change (only 2 of 7 backends implement `WifiRadio`, so the face could not accept most of the
// radios in the tree), but the two rate-carrying methods lived on `WifiRadio`, out of reach of a
// `dyn FrameIo`. So it grew private `inject_at_rate` / `inject_batch_at_rate` free functions that
// reproduced the traits' *default* bodies — reasoning, wrongly, that both were purely derived from
// `set_rate` + `inject` and therefore safe to inline.
//
// `inject_batch_at` is **overridden**: `AfPacketBackend` implements it as real A-MSDU aggregation
// (one QoS-Data MPDU per RA, greedily packed — the big airtime lever at S1G). A free function
// copying the default body cannot dispatch to an override, so the A-MSDU batcher silently went back
// to one MPDU per frame. Nothing failed; the frames still went out; only the aggregation vanished.
//
// Part 2 fixes the cause instead of the call site: `inject_at` and `inject_batch_at` now live on
// `FrameIo` (see the note on `WifiRadio` in ndn-radio-hal), so the object-safe seam a face actually
// holds is the one carrying the overridable behaviour, and the helpers are gone.

pub struct MonitorWifiFace {
    id: FaceId,
    backend: Arc<dyn FrameIo>,
    mtu: usize,
    policy: McsPolicy,
    signal_sink: Option<Arc<dyn SignalStore<FaceId> + Send + Sync>>,
    /// Most-recently-observed RSSI, fed by every captured frame; the input to
    /// [`McsPolicy::Adaptive`]. Initialised to the conservative-default RSSI.
    last_rssi: AtomicI8,
    /// TX name-addressing capability (how outgoing `addr1` is chosen).
    tx_addr: TxAddr,
    /// Name filtering (Tier-0 + optional Tier-1), shared with `RadioMediumFace` (#82).
    gate: NameGate,
    /// **Tier-1** (#92), when this node runs one: BF-FIB / BF-PIT / BF-CS consulted on the parsed
    /// name *after* Tier-0 admits a frame. `None` on an endpoint, where Tier-0 alone is the right
    /// trade (#101: Tier-0's FP climbs with registered-prefix count, so it suits small E and a relay
    /// wants this instead).
    ///
    /// `RwLock` because the read is the per-frame fast path and the writes are comparatively rare
    /// forwarder events (a PIT entry added, a Data cached). No `await` is held across the guard.
    tier1: Option<Arc<std::sync::RwLock<crate::tier1::Tier1>>>,
    /// Frames Tier-1 rejected — kept so the tier's contribution is observable rather than assumed.
    /// A filter nobody can measure is indistinguishable from one that does nothing.
    tier1_dropped: Arc<std::sync::atomic::AtomicU64>,
    /// For [`TxAddr::PrefixBloom`]: the per-object 12-byte filter (`addr1 ‖ addr2`) cached
    /// by LP base-sequence, so every fragment of one object carries the same filter.
    bloom_cache: Mutex<HashMap<u64, [u8; 12]>>,
    /// This face's ephemeral rotating source nonce (mac-addressing-doctrine §2). Stamped into
    /// `addr3` on the Tier-0 ([`TxAddr::PrefixBloom`]) TX path, where `addr1 ‖ addr2` is the filter
    /// and so cannot also carry the source — preserving per-transmitter RSSI keying at the receiver.
    source: EphemeralSource,
    /// Optional A-MSDU batcher ([`with_amsdu_batching`]). When set, `send_bytes`
    /// enqueues outbound frames here and they are coalesced into A-MSDU bursts
    /// instead of injected one at a time.
    ///
    /// [`with_amsdu_batching`]: MonitorWifiFace::with_amsdu_batching
    batcher: Option<TxBatcher>,
    /// Optional link-layer FEC ([`with_link_fec`]). Mutually exclusive with the
    /// A-MSDU batcher (FEC interleaves one MPDU per frame; batching bundles).
    ///
    /// [`with_link_fec`]: MonitorWifiFace::with_link_fec
    fec: Option<FaceFec>,
    /// Optional control-plane override of the per-frame [`TxParams`]
    /// ([`with_planned_params`]). When the cognitive control plane
    /// ([`RadioControl`]) decides a [`RadioPlan`], its actuator writes the chosen
    /// `TxParams` into this shared cell; `select_mcs` reads it so the *decided*
    /// rate/coding actually changes what we transmit. `None`/empty ⇒ fall back to
    /// the static [`McsPolicy`]. This is the ACT half of the closed loop.
    ///
    /// [`with_planned_params`]: MonitorWifiFace::with_planned_params
    /// [`RadioControl`]: crate::RadioControl
    /// [`RadioPlan`]: ndn_radio_cognition::RadioPlan
    planned: Option<Arc<RwLock<Option<TxParams>>>>,
}

impl MonitorWifiFace {
    /// New monitor-mode face over `backend`, sized for fragmented NDN traffic
    /// (`MONITOR_MTU`) and injecting at the conservative default rate.
    pub fn new(id: FaceId, backend: Arc<dyn FrameIo>) -> Self {
        Self {
            id,
            backend,
            mtu: MONITOR_MTU,
            policy: McsPolicy::default(),
            signal_sink: None,
            last_rssi: AtomicI8::new(-70),
            tx_addr: TxAddr::Broadcast,
            gate: NameGate::open(),
            tier1: None,
            tier1_dropped: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            bloom_cache: Mutex::new(HashMap::new()),
            source: EphemeralSource::new(
                {
                    // Per-boot entropy ⊕ face id, so co-located faces get distinct nonces. The nonce
                    // only appears on the Tier-0 TX path; a stronger RNG drops in unchanged.
                    let nanos = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_nanos() as u64)
                        .unwrap_or(0);
                    nanos ^ (id.0 as u64).wrapping_mul(0x9E37_79B9)
                },
                5 * 60 * 1000,
            ),
            batcher: None,
            fec: None,
            planned: None,
        }
    }

    /// Build an **ESP-NOW** face over `backend` — the first-class
    /// NDN-over-ESP-NOW path. `backend` must be in [`FrameFormat::EspNow`] mode
    /// (e.g. `AfPacketBackend::new(iface, FrameFormat::EspNow { oui: ESPNOW_OUI })`
    /// on Linux, or use `open_libusb_espnow` on a
    /// host without a kernel monitor driver). The face is sized to the 250-B
    /// ESP-NOW body ([`ESPNOW_MTU`]) so the paired `LpLinkService` fragments NDN
    /// packets into vendor-action frames a stock `esp-wifi` ESP-NOW peer hears;
    /// the broadcast addressing ESP-NOW requires is the default (no name-group).
    /// Chainable with [`with_signal_sink`](Self::with_signal_sink),
    /// [`with_link_fec`](Self::with_link_fec), etc.
    pub fn espnow(id: FaceId, backend: Arc<dyn FrameIo>) -> Self {
        Self::new(id, backend).with_mtu(ESPNOW_MTU)
    }

    /// Open a **Wi-Fi HaLow (802.11ah / S1G)** monitor face on the kernel monitor
    /// interface `iface` — e.g. `"halow0"` (Newracom NRC7292) or `"mon0"` (Morse
    /// Micro MM6108). Drives **both** HaLow chips uniformly; the driver-side
    /// differences are invisible here.
    ///
    /// This pools the HaLow radio uniformly with the 2.4/5 GHz monitor faces:
    /// same [`FrameIo`] data plane, same [`MonitorWifiFace`], same engine. It
    /// sets [`FrameFormat::RawNdnS1g`], so injected frames carry the S1G radiotap
    /// header that names *no* 11n/ac MCS — the chip's own MAC picks the sub-GHz
    /// rate, so the same minimal radiotap suits both chips.
    ///
    /// Verified on-air, including cross-vendor: an NRC7292 received frames a
    /// second NRC7292 injected, and a Morse MM6108 injected NDN-over-HaLow frames
    /// that an NRC7292 decoded on 904.5 MHz. Each chip needs a driver patch for
    /// monitor injection (see the minidronesys configs): NRC7292 forwards
    /// `IEEE80211_TX_CTL_INJECTED`; the MM6108 driver routes vif-less injected
    /// frames through its firmware monitor vif with a fixed S1G rate.
    ///
    /// The interface must already be in monitor mode on an S1G channel
    /// (`iw dev <iface> set type monitor; iw dev <iface> set channel 161`; for the
    /// MM6108 add the vif with `iw phy <phy> interface add mon0 type monitor`,
    /// per its NixOS `services.morseMonitor`) and the process needs `CAP_NET_RAW`.
    /// `channels` are the driver's fake channel numbers for the advertised
    /// capability (they differ per vendor; align on real frequency for interop).
    #[cfg(target_os = "linux")]
    pub fn halow(id: FaceId, iface: &str, channels: Vec<u8>) -> Result<Self, FaceError> {
        // 0x8624 = the NDN-over-Ethernet ethertype used across the stack; both
        // ends must agree on it (the RX parse validates the LLC/SNAP ethertype).
        // Advertise absolute dBm power control when this interface actually has it
        // (Morse and Newracom S1G parts both expose a dBm knob), so a control plane
        // registering this capability decides power in link budget rather than in
        // chip index units. Absent on a radio where nothing was found.
        let mut cap = RadioCapability::wifi_halow_s1g(channels);
        if let Some(r) = crate::dbm_power::Mac80211Knobs::discover(iface).tx_power_range() {
            cap = cap.with_tx_power_dbm(r);
        }
        let backend = AfPacketBackend::new(iface, FrameFormat::RawNdnS1g { ethertype: 0x8624 })
            .map_err(FaceError::Io)?
            .with_capability(cap);
        Ok(Self::new(id, Arc::new(backend)))
    }

    /// Open the RTL8812EU USB dongle in 5 GHz monitor mode on `channel` and
    /// build an **ESP-NOW** face over it — the host side of NDN-over-ESP-NOW
    /// interop with an ESP32 on a host without a kernel monitor driver (macOS,
    /// etc.). Sets [`FrameFormat::EspNow`] (Espressif OUI) and the 250-B
    /// [`ESPNOW_MTU`]. For a **dual-band ESP32-C5** the dongle injects on a 5 GHz
    /// channel (e.g. 36 or 161) and the C5 listens there in `BandMode::_5G` —
    /// the path the 2.4 GHz-only ESP32-S3 could never close, since these wfb
    /// dongles only inject on 5 GHz. Inject at a basic rate the peer decodes:
    /// 6 Mbps OFDM on 5 GHz (`NDN_RADIO_TX_RATE=4`; 1 Mbps DSSS does not exist
    /// on 5 GHz).
    #[cfg(feature = "libusb-backend")]
    pub fn open_libusb_espnow(id: FaceId, channel: u8) -> Result<Self, FaceError> {
        let backend = crate::LibUsbRtl88xxBackend::open_monitor(channel)?
            .with_format(FrameFormat::EspNow { oui: ESPNOW_OUI });
        Ok(Self::espnow(id, Arc::new(backend)))
    }

    /// Enable **link-layer FEC**: outbound frames are grouped into generations of
    /// up to `k` (or a `window`), sent as `k + redundancy` coded frames — each its
    /// own MPDU (interleaved) — and the receiver recovers up to `redundancy`
    /// losses per generation with no ARQ. The broadcast reliability lever; reuses
    /// `ndn_coding`'s systematic codec. Mutually exclusive with A-MSDU batching
    /// (FEC wants one MPDU per frame so a lost MPDU costs ≤ `redundancy` of a
    /// generation; batching would bundle a whole generation into one MPDU).
    /// Both ends must enable FEC. Call before mounting (spawns the flush task).
    pub fn with_link_fec(mut self, k: usize, redundancy: u16, window: Duration) -> Self {
        // No address is snapshotted here: the whole on-air identity (dst, src, addr3, intent) is
        // resolved per generation from the frame that opens it and rides the pin, so coded frames
        // are addressed exactly as uncoded ones are.
        self.fec = Some(FaceFec::spawn(
            self.backend.clone(),
            k.max(1),
            redundancy,
            window,
        ));
        self
    }

    /// Enable **link-layer A-MSDU bundling** on the send path: outbound frames
    /// are coalesced into one A-MSDU per up-to-`max_msdus` frames or `window`
    /// elapsed, whichever first — one PHY preamble for many NDN packets. Trades a
    /// little latency for airtime efficiency on the broadcast medium; each MSDU
    /// stays an independent NDN packet the receiver de-aggregates, so PIT/FIB
    /// semantics are untouched. Call before mounting (it spawns the flush task on
    /// the current runtime). A `window` of a few milliseconds and `max_msdus`
    /// ~8–16 is a sane default.
    ///
    /// The aggregation happens in the backend's
    /// [`inject_batch_at`](ndn_radio_hal::FrameIo::inject_batch_at) override, so how much it buys is
    /// backend-specific: AF_PACKET aggregates for real, and a backend that does not override it
    /// falls back to individual injection with no airtime change and no error. Check the backend
    /// before quoting a speedup — the figure that used to sit here was never measured on one.
    pub fn with_amsdu_batching(mut self, max_msdus: usize, window: Duration) -> Self {
        self.batcher = Some(TxBatcher::spawn(self.backend.clone(), max_msdus, window));
        self
    }

    /// Open the RTL8812EU USB dongle, bring it up in 5 GHz monitor mode on
    /// `channel` (20 MHz), and build a named-radio face over it — the one-call
    /// path from a plugged-in dongle to a working `MonitorWifiFace` on a host
    /// without a kernel monitor driver (macOS, etc.). Pair with
    /// [`into_face`](Self::into_face) to mount it on the engine.
    #[cfg(feature = "libusb-backend")]
    pub fn open_libusb(id: FaceId, channel: u8) -> Result<Self, FaceError> {
        let backend = crate::LibUsbRtl88xxBackend::open_monitor(channel)?;
        Ok(Self::new(id, Arc::new(backend)))
    }

    /// Set the TX name-addressing capability directly (compose with [`with_rx_filter`]).
    pub fn with_tx_addr(mut self, tx: TxAddr) -> Self {
        self.tx_addr = tx;
        self
    }

    /// Set the RX name-filtering capability directly (compose with [`with_tx_addr`]).
    pub fn with_rx_filter(mut self, rx: RxFilter) -> Self {
        self.gate = NameGate::new(rx, self.gate.tier1());
        self
    }

    /// **Enable Tier-1** (#92) with `bits_each` bits per table, seeding BF-FIB from `prefixes`.
    ///
    /// Sized by the caller because the right size is a property of the node's tables, not of the
    /// face: a relay with a large FIB and a real CS wants far more than a gateway with three
    /// prefixes. Returns the handle so the forwarder can feed PIT/CS — see [`tier1_handle`].
    pub fn with_tier1(
        mut self,
        key: &GroupKey,
        prefixes: &[impl AsRef<[u8]>],
        bits_each: usize,
        k: u32,
    ) -> Self {
        let mut t = crate::tier1::Tier1::new(Self::bloom_key(key), bits_each, k);
        for p in prefixes {
            t.register_prefix(p.as_ref());
        }
        t.sync();
        self.gate = NameGate::new(self.gate.filter(), Some(Arc::new(std::sync::RwLock::new(t))));
        self
    }

    /// The live Tier-1 handle, for the forwarder to drive **from its real tables**.
    ///
    /// This is the half that makes the tier real rather than decorative: BF-PIT must be fed by the
    /// actual PIT (`add_pit` on send, `remove_pit` on satisfy) and BF-CS by the actual CS (`cache`),
    /// then `sync()` published. A Tier-1 whose tables drift from the forwarder's does not merely
    /// lose efficiency — a stale BF-PIT **drops Data the node is waiting for**, which is a false
    /// negative and the one failure mode this design must not have.
    pub fn tier1_handle(&self) -> Option<Arc<std::sync::RwLock<crate::tier1::Tier1>>> {
        self.gate.tier1()
    }

    /// Frames rejected by Tier-1 since start.
    pub fn tier1_dropped(&self) -> u64 {
        self.gate.dropped_tier1()
    }

    /// Build a [`RxFilter::Bloom`] over `prefixes` under `key`: one precomputed
    /// [`PrefixFilter::mask_for`] per registered prefix. A relay passes many; a consumer one.
    fn bloom_masks(key: &GroupKey, prefixes: &[impl AsRef<[u8]>]) -> RxFilter {
        let k = Self::bloom_key(key);
        let masks: std::sync::Arc<[PrefixFilter]> = prefixes
            .iter()
            .map(|p| PrefixFilter::mask_for(k, p.as_ref()))
            .collect();
        RxFilter::Bloom(masks)
    }

    /// **Tier-0 producer** (#91): each object is addressed by the prefix-set Bloom filter of
    /// its inner name (`addr1 ‖ addr2`), so every receiver matches at its *own* registered
    /// prefix. RX keeps the object's own name family (overhearing). This is the prefix-set
    /// replacement for the retired flat/split name-group addressing.
    pub fn with_bloom_producer(self, key: &GroupKey, routable_prefix: impl AsRef<[u8]>) -> Self {
        let rx = Self::bloom_masks(key, &[routable_prefix.as_ref()]);
        self.with_tx_addr(TxAddr::PrefixBloom { key: *key })
            .with_rx_filter(rx)
    }

    /// **Tier-0 relay** (#91): RX keeps any frame whose in-frame filter could be under one of
    /// `prefixes` — the aggregation win, now expressed as longest-prefix match rather than a
    /// single fixed-granularity hash. TX is left as configured.
    pub fn with_bloom_relay(self, key: &GroupKey, prefixes: &[impl AsRef<[u8]>]) -> Self {
        let rx = Self::bloom_masks(key, prefixes);
        self.with_rx_filter(rx)
    }

    /// **Tier-0 consumer** (#91): RX keeps frames under this one registered prefix. Because the
    /// sender ships *all* name granularities, this matches whether the sender chose `/x` or
    /// `/x/y/z` — the out-of-band granularity agreement `name_group` required is gone.
    pub fn with_bloom_consumer(self, key: &GroupKey, prefix: impl AsRef<[u8]>) -> Self {
        let rx = Self::bloom_masks(key, &[prefix.as_ref()]);
        self.with_tx_addr(TxAddr::PrefixBloom { key: *key })
            .with_rx_filter(rx)
    }

    /// Inject every frame at a fixed MCS (e.g. for a known-good link or a bench).
    pub fn with_fixed_mcs(mut self, mcs: McsDescriptor) -> Self {
        self.policy = McsPolicy::Fixed(mcs);
        self
    }

    /// Pick the injection MCS from observed RSSI ([`McsPolicy::Adaptive`]).
    pub fn with_adaptive_mcs(mut self) -> Self {
        self.policy = McsPolicy::Adaptive;
        self
    }

    /// Override the injected-frame payload budget (custom PHY / MTU).
    pub fn with_mtu(mut self, mtu: usize) -> Self {
        self.mtu = mtu.max(1);
        self
    }

    /// Publish per-frame RSSI into `sink` keyed by this face's id, feeding
    /// measured strategies via [`ndn_signals_core::SignalView`].
    pub fn with_signal_sink(mut self, sink: Arc<dyn SignalStore<FaceId> + Send + Sync>) -> Self {
        self.signal_sink = Some(sink);
        self
    }

    /// Let the cognitive control plane drive the per-frame [`TxParams`] via a
    /// shared cell. The [`RadioControl`] actuator writes the decided params here;
    /// `select_mcs` reads them so a *decision* actually changes the transmitted
    /// rate/coding. This is the ACT half of the sense→decide→act loop. Pass the
    /// same `Arc` to `RadioControl::libusb_actuator` so both ends share it.
    ///
    /// [`RadioControl`]: crate::RadioControl
    pub fn with_planned_params(mut self, cell: Arc<RwLock<Option<TxParams>>>) -> Self {
        self.planned = Some(cell);
        self
    }

    /// Build a [`Face`] pairing this transport with the `LpLinkService`, so the
    /// engine fragments/reassembles NDN packets across injected frames.
    pub fn into_face(self) -> Face {
        Face::from_transport(self)
    }

    /// Parity frames the plan wants on the next generation, if a control plane has
    /// decided one. `None` leaves the link-FEC feature at its configured `R`.
    ///
    /// This is the actuator for [`TxParams::link_fec_redundancy`], which until
    /// 2026-07-17 was decided by `RadioPolicy::fec_redundancy`, carried all the way
    /// into this face's `planned` cell — and then read by nobody, so the redundancy
    /// budget was fixed at `with_link_fec` construction time and no name ever moved
    /// it (task #32). A knob reaching the face is not a knob reaching the air.
    ///
    /// [`TxParams::link_fec_redundancy`]: ndn_radio_cognition::TxParams::link_fec_redundancy
    fn planned_redundancy(&self) -> Option<u16> {
        self.planned
            .as_ref()
            .and_then(|cell| cell.read().ok().and_then(|g| *g))
            .and_then(|tp| tp.link_fec_redundancy)
    }

    /// The face's fallback `(dst, src)` when no per-object filter applies (broadcast, or a
    /// non-first fragment on a cache miss). Broadcast passes every receiver's filter — the safe
    /// over-accept direction; Tier 1/2 does the exact match, and a false negative is forbidden.
    fn static_addr(&self) -> ([u8; 6], [u8; 6]) {
        (BROADCAST, DEFAULT_SRC)
    }

    /// The 64-bit filter key derived from a [`GroupKey`] — the first 8 bytes, so the
    /// well-known [`OPEN_GROUP_KEY`] is a public keyspace and a shared secret is private.
    /// The Tier-0 filter key is the whole [`GroupKey`] — see [`crate::bloom_key64`].
    fn bloom_key(key: &GroupKey) -> &[u8; 16] {
        &key.0
    }

    /// Build the 12 wire bytes (`addr1 ‖ addr2`) of the Tier-0 filter for a wire NDN Name
    /// TLV under `key` — every prefix of the name inserted into the 94-bit filter.
    fn bloom_wire(key: &GroupKey, name_tlv: &[u8]) -> [u8; 12] {
        let slash = ndn_name_to_slash(name_tlv);
        let mut f = PrefixFilter::new();
        f.insert_name(Self::bloom_key(key), &slash);
        f.to_wire()
    }

    /// The source nonce to stamp into `addr3`, or `None` to keep the legacy `addr3 = dst`. Only the
    /// Tier-0 ([`TxAddr::PrefixBloom`]) path needs it — there `addr2` is the filter's low half, so the
    /// per-transmitter source moves to `addr3` (doctrine §2, per-neighbour RSSI keying).
    fn tx_nonce(&self) -> Option<[u8; 6]> {
        matches!(self.tx_addr, TxAddr::PrefixBloom { .. })
            .then(|| self.source.current(now_ms() as u64))
    }

    /// Resolve the `(dst, src)` = `addr1 ‖ addr2` for one outgoing wire frame under
    /// [`TxAddr::PrefixBloom`]: the object's name → its prefix-set filter, cached by LP base
    /// sequence so every fragment of one object carries the same filter (only the first has the
    /// name). Non-Bloom / no-name → broadcast, a safe over-accept.
    fn resolve_addr(&self, wire: &[u8]) -> ([u8; 6], [u8; 6]) {
        let TxAddr::PrefixBloom { key } = &self.tx_addr else {
            return self.static_addr();
        };
        let split = |w: [u8; 12]| -> ([u8; 6], [u8; 6]) {
            (w[..6].try_into().unwrap(), w[6..].try_into().unwrap())
        };
        if let Some(h) = ndn_packet::lp::extract_fragment(wire) {
            let base = h.sequence.wrapping_sub(h.frag_index);
            if h.frag_index == 0 {
                let w = match inner_name(wire) {
                    Some(name) => Self::bloom_wire(key, name),
                    None => return self.static_addr(), // no name → broadcast
                };
                self.bloom_cache.lock().unwrap().insert(base, w);
                return split(w);
            }
            if let Some(w) = self.bloom_cache.lock().unwrap().get(&base).copied() {
                return split(w);
            }
            return self.static_addr(); // cache miss → broadcast (over-accept, never a FN)
        }
        match inner_name(wire) {
            Some(name) => split(Self::bloom_wire(key, name)),
            None => self.static_addr(),
        }
    }

    /// Does a captured frame pass this face's name filtering? Delegates to the shared
    /// [`NameGate`] (#82) — the same decision `RadioMediumFace` makes, from the same code.
    fn rx_accepts(&self, addr1: Option<[u8; 6]>, addr2: Option<[u8; 6]>, wire: &[u8]) -> bool {
        self.gate.admits(addr1, addr2, wire)
    }

    /// The rate to inject the next frame at. A control-plane plan
    /// ([`with_planned_params`]) wins when present; otherwise the static policy.
    fn select_mcs(&self) -> McsDescriptor {
        if let Some(cell) = &self.planned
            && let Ok(guard) = cell.read()
            && let Some(tp) = *guard
            && let Some(index) = tp.mcs()
        {
            return McsDescriptor {
                index,
                short_gi: tp.short_gi(),
                vht: tp.vht(),
                nss: tp.nss().unwrap_or(1),
                stbc: tp.stbc(),
                ldpc: tp.ldpc(),
            };
        }
        match self.policy {
            McsPolicy::Fixed(d) => d,
            McsPolicy::Adaptive => {
                McsDescriptor::ht(mcs_for_rssi(self.last_rssi.load(Ordering::Relaxed)))
            }
        }
    }

    /// Receive one captured frame for this face, recording its RSSI for adaptive
    /// MCS and publishing it to the signal sink. When bound to a name-group,
    /// frames for other groups are dropped here (a name pre-filter *before* NDN
    /// decode); our group and broadcast are kept.
    async fn recv_inner(&self) -> Result<CapturedFrame, FaceError> {
        loop {
            let f = self.backend.recv_frame().await?;
            if !self.rx_accepts(f.group, f.addr, &f.payload) {
                continue; // a different name-group — drop before decoding
            }
            // **Tier-1** (#92), when enabled: Tier-0 has admitted the frame on 12 bytes with no
            // parse; this is the second gate, on the parsed name, against BF-FIB / BF-PIT / BF-CS.
            // It catches what Tier-0 structurally cannot — notably direction (b), a prefix-seeking
            // Interest that is an ancestor of something we cache — and it is where a node with many
            // registered prefixes gets its selectivity back (#101).
            //
            // A frame with no name (a non-first fragment) is passed: reassembly needs it, and the
            // first fragment already faced both gates. Same safe over-accept the TX path makes.
            if let Some(t1) = self.tier1.as_ref()
                && let Some(name) = inner_name(&f.payload)
            {
                let slash = ndn_name_to_slash(name);
                let miss = match t1.read() {
                    Ok(g) => g.lookup(&slash).is_miss(),
                    // A poisoned lock must not silently start dropping traffic: fail open. The
                    // filter is an optimisation; the forwarder behind it is the correctness layer.
                    Err(_) => false,
                };
                if miss {
                    self.tier1_dropped.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            }
            if let Some(rssi) = f.rssi_dbm {
                self.last_rssi.store(rssi, Ordering::Relaxed);
            }
            // Publish the per-frame radio signals (RSSI + the rate the frame
            // arrived at) for this face, so measured/CCLF strategies can rank
            // this neighbour by live link quality. Publish whenever either
            // reading is present.
            if (f.rssi_dbm.is_some() || f.mcs_index.is_some())
                && let Some(sink) = self.signal_sink.as_ref()
            {
                let mut ls = LinkSignals {
                    rssi_dbm: f.rssi_dbm,
                    observed_tput_bps: f.mcs_index.map(mcs_phy_rate_bps),
                    updated_ms: now_ms(),
                    ..LinkSignals::default()
                };
                // Publish the raw 802.11 MCS index as a cross-layer ext signal:
                // the common vocab has no MCS field, and `observed_tput_bps`
                // above is only the *derived* PHY rate. Measured/CCLF strategies
                // and the cognitive plane read it via `ext_get("mcs")`.
                if let Some(mcs) = f.mcs_index {
                    ls.ext_set("mcs", mcs as f32);
                }
                sink.set_link(self.id, ls);
            }
            return Ok(f);
        }
    }
}

impl Transport for MonitorWifiFace {
    fn id(&self) -> FaceId {
        self.id
    }

    fn kind(&self) -> FaceKind {
        // The Wfb kind: a wire kind (LP framing on), NonLocal scope.
        // `link_type() == AdHoc` distinguishes the connectionless injection
        // bearer.
        FaceKind::Wfb
    }

    fn remote_uri(&self) -> Option<String> {
        Some("monitor-wifi://broadcast".to_string())
    }

    fn link_type(&self) -> LinkType {
        LinkType::AdHoc
    }

    fn send_mtu(&self) -> Option<usize> {
        Some(self.mtu)
    }

    async fn send_bytes(&self, wire: Bytes) -> Result<(), FaceError> {
        // The LpLinkService already framed/fragmented; each call is one frame.
        // Address it per the TX capability (broadcast / flat group / per-Data-name
        // split) — never a host MAC.
        let (dst, src) = self.resolve_addr(&wire);
        let mcs = self.select_mcs();
        // Link-FEC: enqueue the wire frame; the flush task groups a generation,
        // emits K+R coded frames (one MPDU each, interleaved), recovers losses. The
        // per-object split `dst` rides in the pin, so the generation is addressed to
        // the object that opened it — split addressing composes with coding. (K should
        // align with an object's fragments; a generation spanning objects takes the
        // opening object's address, same as it takes the opening frame's MCS.)
        if let Some(fec) = &self.fec {
            return fec.bridge.send(
                wire,
                RadioFecPin {
                    dst,
                    src,
                    addr3: self.tx_nonce(),
                    intent: TxIntent::CONSERVATIVE,
                    mcs: Some(mcs),
                },
                self.planned_redundancy(),
            );
        }
        // The exact resolved rate travels alongside the frame (via inject_at /
        // the batcher), not on the intent — the frame's tx is a placeholder.
        let frame = InjectFrame {
            payload: wire,
            tx: TxIntent::CONSERVATIVE,
            dst,
            src,
            // Tier-0 (#91d): stamp the ephemeral nonce into addr3 (addr1‖addr2 is the filter). `None`
            // off the Bloom path keeps the legacy addr3=dst.
            addr3: self.tx_nonce(),
        };
        // With A-MSDU batching the frame is enqueued (non-blocking) and bundled
        // by the flush task; otherwise it is injected immediately.
        match &self.batcher {
            Some(b) => b.submit(frame, mcs),
            None => self.backend.inject_at(frame, mcs).await,
        }
    }

    async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
        self.recv_bytes_with_addr().await.map(|(b, _)| b)
    }

    async fn recv_bytes_with_addr(&self) -> Result<(Bytes, Option<FaceAddr>), FaceError> {
        // Link-FEC: feed each captured frame to the decoder. Source frames are
        // delivered immediately; parity recovers missing ones. A captured frame
        // can yield 0 (parity, not yet complete), 1, or several payloads — buffer
        // the extras and drain them across calls. Non-FEC frames pass through.
        if let Some(fec) = &self.fec {
            loop {
                if let Some(p) = fec.pending.lock().unwrap().pop_front() {
                    return Ok(p);
                }
                let f = self.recv_inner().await?;
                let addr = f.addr.map(FaceAddr::Ether);
                // The feature delivers a plain frame as-is, a source frame immediately,
                // and recovered sources when parity completes a generation (0, 1, or many).
                let delivered = fec.bridge.decode(f.payload);
                if delivered.is_empty() {
                    continue; // parity that didn't complete a generation yet
                }
                let mut q = fec.pending.lock().unwrap();
                for d in delivered {
                    q.push_back((d, addr.clone()));
                }
                if let Some(p) = q.pop_front() {
                    return Ok(p);
                }
            }
        }
        let f = self.recv_inner().await?;
        Ok((f.payload, f.addr.map(FaceAddr::Ether)))
    }

    /// Injected-frame budget is fixed at construction.
    fn set_send_mtu(&self, _mtu: Option<u64>) -> Result<Option<u64>, MtuError> {
        Err(MtuError::Immutable)
    }

    /// A broadcast medium has no per-peer connection to keep alive.
    fn set_persistency(&self, _persistency: FacePersistency) -> Result<(), PersistencyError> {
        Err(PersistencyError::Immutable)
    }
}

fn now_ms() -> u32 {
    use std::sync::OnceLock;
    use std::time::Instant;
    static BASE: OnceLock<Instant> = OnceLock::new();
    BASE.get_or_init(Instant::now).elapsed().as_millis() as u32
}

#[cfg(test)]
mod tests {

    /// **#92 integration — Tier-1 actually gates the RX path.**
    ///
    /// Not "the module compiles and has unit tests": a frame whose name misses all three tables must
    /// be dropped by the face, and the counter must say so. Without this the tier is decided and
    /// unactuated, which is this codebase's characteristic defect.
    #[tokio::test]
    async fn tier1_gates_the_rx_path_and_counts_what_it_drops() {
        let key = OPEN_GROUP_KEY;
        let bus = LoopbackMonitorBus::new();
        // Tier-0 open so this test isolates Tier-1: whatever is dropped, Tier-1 dropped it.
        let rx = MonitorWifiFace::new(FaceId(1), Arc::new(bus.endpoint(1, -50)))
            .with_tier1(&key, &["/served"], 8192, 4);
        let tx = MonitorWifiFace::new(FaceId(2), Arc::new(bus.endpoint(2, -50)));

        // A name under the registered prefix must pass; one outside must be dropped by Tier-1.
        for (comps, expect_pass) in [
            (vec![b"served".as_slice(), b"thing".as_slice()], true),
            (vec![b"elsewhere".as_slice(), b"thing".as_slice()], false),
        ] {
            tx.send_bytes(data_pkt(&name_tlv(&comps))).await.unwrap();
            let got = tokio::time::timeout(std::time::Duration::from_millis(150), rx.recv_bytes()).await;
            assert_eq!(got.is_ok(), expect_pass, "Tier-1 disagreed on pass={expect_pass}");
        }
        assert_eq!(rx.tier1_dropped(), 1, "the drop was not counted");
    }

    /// **The failure mode that matters: a stale BF-PIT drops Data we are waiting for.**
    ///
    /// Tier-1's tables must be fed from the forwarder's real ones. This shows the consequence of
    /// *not* doing that — Data for an outstanding Interest is dropped until the PIT entry is
    /// published — so the requirement in `tier1_handle`'s doc is a demonstrated hazard, not advice.
    #[tokio::test]
    async fn an_unfed_bf_pit_drops_data_we_asked_for() {
        let key = OPEN_GROUP_KEY;
        let bus = LoopbackMonitorBus::new();
        let rx = MonitorWifiFace::new(FaceId(1), Arc::new(bus.endpoint(1, -50)))
            .with_tier1(&key, &["/served"], 8192, 4);
        let tx = MonitorWifiFace::new(FaceId(2), Arc::new(bus.endpoint(2, -50)));
        let comps: Vec<&[u8]> = vec![b"asked", b"for", b"this"];
        let pkt = data_pkt(&name_tlv(&comps));

        // PIT not yet published: Tier-1 has no reason to want it, so it drops.
        tx.send_bytes(pkt.clone()).await.unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(150), rx.recv_bytes()).await.is_err(),
            "expected the drop that an unfed BF-PIT causes"
        );

        // Feed the PIT the way a forwarder must, then the same frame passes.
        {
            let h = rx.tier1_handle().expect("tier1 enabled");
            let mut g = h.write().unwrap();
            g.add_pit(b"/asked/for/this");
            g.sync();
        }
        tx.send_bytes(pkt).await.unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(150), rx.recv_bytes()).await.is_ok(),
            "Data for a published PIT entry was still dropped"
        );
    }
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::time::Duration;

    use ndn_signals_core::{NodeSignals, SignalView};

    const ADDR_A: [u8; 6] = [0xA0; 6];
    const ADDR_B: [u8; 6] = [0xB0; 6];

    /// Link-FEC wired into the face: a generation sent through `send_bytes` on a
    /// FEC face is encoded, carried over the (lossless) bus, and de-coded back to
    /// the original frames by the peer's `recv_bytes` — proving the TX-encode /
    /// RX-decode plumbing end to end (erasure *recovery* is covered by the
    /// `ndn_coding::link_fec` unit tests).
    #[tokio::test]
    async fn link_fec_face_roundtrip() {
        use ndn_transport::Transport;
        let bus = LoopbackMonitorBus::new();
        let tx = MonitorWifiFace::new(FaceId(1), Arc::new(bus.endpoint(1, -50))).with_link_fec(
            3,
            2,
            Duration::from_millis(20),
        );
        let rx = MonitorWifiFace::new(FaceId(2), Arc::new(bus.endpoint(2, -60))).with_link_fec(
            3,
            2,
            Duration::from_millis(20),
        );

        let sent: Vec<Bytes> = (0..3u8).map(|i| Bytes::from(vec![i; 12])).collect();
        for w in &sent {
            tx.send_bytes(w.clone()).await.unwrap();
        }
        let mut got = Vec::new();
        for _ in 0..3 {
            let (b, _) = tokio::time::timeout(Duration::from_secs(2), rx.recv_bytes_with_addr())
                .await
                .expect("FEC face should deliver the generation")
                .unwrap();
            got.push(b);
        }
        got.sort();
        let mut want = sent;
        want.sort();
        assert_eq!(got, want, "FEC face round-trips the generation");
    }

    /// The plan's `link_fec_redundancy` must change **what hits the air**, not just
    /// what the policy decided. This is the regression test for task #32: the knob
    /// was decided, logged, and carried into the face's `planned` cell, and then no
    /// send-path code read it, so R stayed frozen at `with_link_fec` construction.
    ///
    /// Asserting the decision (as the policy's own tests do) would have passed the
    /// whole time. So this asserts the **effect**: a passive third radio counts the
    /// frames actually on the bus. A K=2 generation with the plan forcing R=5 must
    /// put 7 frames on air; the same face with an empty plan cell must put K+R_ctor.
    #[tokio::test]
    async fn planned_redundancy_changes_frames_on_air() {
        use ndn_frame_io::FrameIo;
        use ndn_transport::Transport;

        const K: usize = 2;
        const R_CTOR: u16 = 1;

        // Send one K-frame generation through `face` and count the frames a passive
        // third radio hears — i.e. what actually hit the air, K + R.
        async fn frames_on_air(bus: &LoopbackMonitorBus, face: &MonitorWifiFace) -> usize {
            let sniffer = Arc::new(bus.endpoint(99, -70));
            let counter = tokio::spawn(async move {
                let mut n = 0usize;
                while tokio::time::timeout(Duration::from_millis(150), sniffer.recv_frame())
                    .await
                    .is_ok()
                {
                    n += 1;
                }
                n
            });
            tokio::time::sleep(Duration::from_millis(10)).await; // let the sniffer subscribe
            for i in 0..K as u8 {
                face.send_bytes(Bytes::from(vec![i; 12])).await.unwrap();
            }
            counter.await.unwrap()
        }

        // Baseline: no plan cell, so R stays at the constructed value → K + R_CTOR.
        let bus = LoopbackMonitorBus::new();
        let base = MonitorWifiFace::new(FaceId(1), Arc::new(bus.endpoint(1, -50)))
            .with_link_fec(K, R_CTOR, Duration::from_millis(20));
        assert_eq!(
            frames_on_air(&bus, &base).await,
            K + R_CTOR as usize,
            "baseline generation is K + constructed R"
        );

        // Same construction, but the plan forces R=5. If the knob reaches the air,
        // the generation grows to K + 5; if it is still decorative, it stays K + 1.
        let bus = LoopbackMonitorBus::new();
        let cell = Arc::new(RwLock::new(Some(TxParams {
            link_fec_redundancy: Some(5),
            ..Default::default()
        })));
        let planned = MonitorWifiFace::new(FaceId(2), Arc::new(bus.endpoint(2, -50)))
            .with_link_fec(K, R_CTOR, Duration::from_millis(20))
            .with_planned_params(cell);
        assert_eq!(
            frames_on_air(&bus, &planned).await,
            K + 5,
            "the plan's link_fec_redundancy must change frames on air, not just the decision"
        );
    }

    #[derive(Default)]
    struct TestSink {
        links: Mutex<HashMap<u64, LinkSignals>>,
    }
    impl SignalView<FaceId> for TestSink {
        fn link(&self, face: FaceId) -> Option<LinkSignals> {
            self.links.lock().unwrap().get(&face.0).copied()
        }
        fn node(&self) -> NodeSignals {
            NodeSignals::default()
        }
        fn neighbor(&self, _face: FaceId) -> Option<NodeSignals> {
            None
        }
    }
    impl SignalStore<FaceId> for TestSink {
        fn set_link(&self, face: FaceId, signals: LinkSignals) {
            self.links.lock().unwrap().insert(face.0, signals);
        }
        fn set_node(&self, _signals: NodeSignals) {}
        fn set_neighbor(&self, _face: FaceId, _signals: NodeSignals) {}
    }

    #[test]
    fn mcs_for_rssi_is_monotone() {
        // Stronger signal never yields a lower MCS.
        let mut prev = 0u8;
        for rssi in -100..=-40 {
            let mcs = mcs_for_rssi(rssi as i8);
            assert!(mcs >= prev, "rssi {rssi} gave {mcs} < {prev}");
            prev = mcs;
        }
        assert_eq!(
            mcs_for_rssi(-50),
            MAX_RELIABLE_MCS,
            "strong link → the verified-reliable ceiling, not the 11n max"
        );
        assert_eq!(mcs_for_rssi(-95), 0, "weak link → most robust MCS");
    }

    /// The first-class ESP-NOW face is sized to the 250-B ESP-NOW body and
    /// round-trips an NDN payload through the face plumbing (the ESP-NOW *wire*
    /// layout is locked by `ndn_frame_io::frame`'s round-trip tests; the
    /// loopback bus is format-agnostic, so this proves the face/MTU wiring).
    #[tokio::test]
    async fn espnow_face_is_250b_and_round_trips() {
        use ndn_transport::Transport;
        let bus = LoopbackMonitorBus::new();
        let tx = MonitorWifiFace::espnow(FaceId(1), Arc::new(bus.endpoint(1, -40)));
        let rx = MonitorWifiFace::espnow(FaceId(2), Arc::new(bus.endpoint(2, -50)));
        assert_eq!(ESPNOW_MTU, 250);
        assert_eq!(tx.send_mtu(), Some(ESPNOW_MTU));

        tx.send_bytes(Bytes::from_static(b"\x05\x03ndn"))
            .await
            .unwrap();
        let (got, addr) =
            tokio::time::timeout(Duration::from_millis(200), rx.recv_bytes_with_addr())
                .await
                .expect("espnow face should deliver")
                .unwrap();
        assert_eq!(got, Bytes::from_static(b"\x05\x03ndn"));
        assert!(matches!(addr, Some(FaceAddr::Ether(_))));
    }

    #[test]
    fn face_is_ad_hoc_wfb_with_fragmenting_mtu() {
        let bus = LoopbackMonitorBus::new();
        let face = MonitorWifiFace::new(FaceId(1), Arc::new(bus.endpoint(1, -50)));
        assert_eq!(face.kind(), FaceKind::Wfb);
        assert_eq!(face.link_type(), LinkType::AdHoc);
        assert_eq!(face.send_mtu(), Some(MONITOR_MTU));
    }

    #[tokio::test]
    async fn inject_reaches_peer_not_self() {
        let bus = LoopbackMonitorBus::new();
        let a = Arc::new(bus.endpoint(1, -50));
        let b = Arc::new(bus.endpoint(2, -60));

        a.inject(InjectFrame {
            payload: Bytes::from_static(b"hello"),
            tx: TxIntent::CONSERVATIVE,
            dst: BROADCAST,
            src: ADDR_A,
            addr3: None,
        })
        .await
        .unwrap();

        let got = tokio::time::timeout(Duration::from_millis(200), b.recv_frame())
            .await
            .expect("B should hear A")
            .unwrap();
        assert_eq!(got.payload, Bytes::from_static(b"hello"));
        assert_eq!(got.addr, Some(ADDR_A));
        assert_eq!(got.rssi_dbm, Some(-60));

        let self_heard = tokio::time::timeout(Duration::from_millis(100), a.recv_frame()).await;
        assert!(
            self_heard.is_err(),
            "a node must not hear its own injection"
        );
    }

    #[tokio::test]
    async fn recv_publishes_rssi_and_drives_adaptive_mcs() {
        let bus = LoopbackMonitorBus::new();
        let sink = Arc::new(TestSink::default());
        // Endpoint observes a strong -50 dBm on every frame it hears.
        let face = MonitorWifiFace::new(FaceId(7), Arc::new(bus.endpoint(7, -50)))
            .with_adaptive_mcs()
            .with_signal_sink(sink.clone());
        let peer = Arc::new(bus.endpoint(8, -50));

        peer.inject(InjectFrame {
            payload: Bytes::from_static(b"x"),
            tx: TxIntent::CONSERVATIVE,
            dst: BROADCAST,
            src: ADDR_B,
            addr3: None,
        })
        .await
        .unwrap();

        let (payload, addr) =
            tokio::time::timeout(Duration::from_millis(200), face.recv_bytes_with_addr())
                .await
                .expect("face should hear peer")
                .unwrap();
        assert_eq!(payload, Bytes::from_static(b"x"));
        assert!(matches!(addr, Some(FaceAddr::Ether(a)) if a == ADDR_B));
        let published = sink
            .link(FaceId(7))
            .expect("a link reading must be published");
        assert_eq!(
            published.rssi_dbm,
            Some(-50),
            "captured RSSI must reach the signal sink"
        );
        // The rate the frame arrived at (peer injected MCS1) is surfaced as the
        // link's achievable PHY throughput, so measured strategies see rate too.
        assert_eq!(
            published.observed_tput_bps,
            Some(mcs_phy_rate_bps(1)),
            "captured rate must reach the signal sink"
        );
        // Having heard a strong -50, adaptive policy picks the highest validated
        // rate (capped at MAX_RELIABLE_MCS until higher MCS are confirmed on-air).
        assert_eq!(face.select_mcs().index, MAX_RELIABLE_MCS);
    }

    /// A name-grouped face drops frames for other groups before NDN decode, but
    /// One NDN Name TLV (`0x07 { 0x08 comp … }`) and a minimal Data packet wrapping it.
    fn name_tlv(comps: &[&[u8]]) -> Vec<u8> {
        let mut inner = Vec::new();
        for c in comps {
            inner.push(0x08);
            inner.push(c.len() as u8);
            inner.extend_from_slice(c);
        }
        let mut t = vec![0x07, inner.len() as u8];
        t.extend_from_slice(&inner);
        t
    }
    fn data_pkt(name: &[u8]) -> Bytes {
        let mut d = vec![0x06, name.len() as u8];
        d.extend_from_slice(name);
        Bytes::from(d)
    }

    /// **Tier-0 prefix-set Bloom filter, end to end** (#91). A producer addresses each
    /// object by the 94-bit prefix-set filter of its inner name (`addr1 ‖ addr2`), on the
    /// real loopback medium through `build_dot11`/`parse_dot11`. It proves the two things the
    /// filter buys over `name_group`:
    ///
    /// - a **relay** registered on the coarse `/x` hears BOTH `/x/y` and `/x/z` (prefix match);
    /// - a **consumer** registered on the *finer* `/x/y/z` — a granularity the producer never
    ///   "chose" — still hears the producer's `/x/y/z` object, because the sender ships every
    ///   granularity at once. That receiver-local longest-prefix match is exactly what a name
    ///   hash cannot express, and it needs no out-of-band agreement.
    #[tokio::test]
    async fn bloom_addressing_prefix_and_granularity_decoupling() {
        let key = OPEN_GROUP_KEY;
        let bus = LoopbackMonitorBus::new();
        let xy = name_tlv(&[b"x", b"y"]);
        let xz = name_tlv(&[b"x", b"z"]);
        let xyz = name_tlv(&[b"x", b"y", b"z"]);

        let producer =
            MonitorWifiFace::new(FaceId(1), Arc::new(bus.endpoint(1, -50))).with_bloom_producer(&key, "/x");
        // Relay on the coarse family /x.
        let relay =
            MonitorWifiFace::new(FaceId(2), Arc::new(bus.endpoint(2, -50))).with_bloom_relay(&key, &["/x"]);
        // Consumer on a FINER prefix than any single granularity the producer commits to.
        let deep =
            MonitorWifiFace::new(FaceId(3), Arc::new(bus.endpoint(3, -50))).with_bloom_consumer(&key, "/x/y/z");
        // Consumer on an unrelated prefix hears nothing.
        let other =
            MonitorWifiFace::new(FaceId(4), Arc::new(bus.endpoint(4, -50))).with_bloom_consumer(&key, "/w");

        producer.send_bytes(data_pkt(&xy)).await.unwrap();
        producer.send_bytes(data_pkt(&xz)).await.unwrap();
        producer.send_bytes(data_pkt(&xyz)).await.unwrap();

        // Relay prefix-matches the whole /x family (all three).
        let mut relayed = Vec::new();
        for _ in 0..3 {
            let (b, _) = tokio::time::timeout(Duration::from_millis(300), relay.recv_bytes_with_addr())
                .await
                .expect("relay hears the /x family")
                .unwrap();
            relayed.push(b);
        }
        relayed.sort();
        let mut want = vec![data_pkt(&xy), data_pkt(&xz), data_pkt(&xyz)];
        want.sort();
        assert_eq!(relayed, want, "relay prefix-matches every name under /x");

        // The /x/y/z consumer hears the /x/y/z object — the granularity-decoupling win.
        let (got, _) = tokio::time::timeout(Duration::from_millis(300), deep.recv_bytes_with_addr())
            .await
            .expect("deep consumer hears /x/y/z at its own registered granularity")
            .unwrap();
        assert_eq!(got, data_pkt(&xyz));

        // The /w consumer hears none of them (exact negative — no false accept expected here).
        let none = tokio::time::timeout(Duration::from_millis(150), other.recv_bytes_with_addr()).await;
        assert!(none.is_err(), "an unrelated prefix must not match the /x family");
    }

    /// **The A-MSDU batcher must reach the backend's `inject_batch_at` override.**
    ///
    /// This is the regression test for the defect #82 part 2 found: part 1 replaced
    /// `backend.inject_batch_at(batch)` with a free function holding a copy of the trait's default
    /// body. Every existing test still passed — the frames went out, the payloads were right, the
    /// counts were right. The only casualty was dynamic dispatch, so `AfPacketBackend`'s real
    /// A-MSDU aggregation stopped being called and the batcher quietly became a no-op that costs
    /// latency.
    ///
    /// Nothing in the suite observed *which* method the batcher called, which is why a silent
    /// airtime regression could ship. So this test asserts on the seam itself: a backend that
    /// overrides `inject_batch_at` must see the batch arrive there, not as N separate `inject`s.
    #[tokio::test]
    async fn amsdu_batching_dispatches_to_the_backend_override() {
        /// A backend that aggregates the way AF_PACKET does — it overrides `inject_batch_at` and
        /// records that the override ran, plus how many frames it was handed at once.
        struct AggregatingBackend {
            batches: std::sync::Mutex<Vec<usize>>,
            singles: std::sync::atomic::AtomicU64,
        }

        #[async_trait::async_trait]
        impl FrameIo for AggregatingBackend {
            async fn inject(&self, _frame: InjectFrame) -> Result<(), FaceError> {
                self.singles.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            async fn inject_batch_at(
                &self,
                frames: Vec<(InjectFrame, McsDescriptor)>,
            ) -> Result<(), FaceError> {
                self.batches.lock().unwrap().push(frames.len());
                Ok(())
            }
            async fn recv_frame(&self) -> Result<CapturedFrame, FaceError> {
                std::future::pending().await
            }
        }

        let backend = Arc::new(AggregatingBackend {
            batches: std::sync::Mutex::new(Vec::new()),
            singles: std::sync::atomic::AtomicU64::new(0),
        });
        let face = MonitorWifiFace::new(FaceId(1), backend.clone())
            .with_amsdu_batching(8, Duration::from_millis(5));

        for i in 0..4u8 {
            face.send_bytes(Bytes::from(vec![i; 16])).await.unwrap();
        }
        // One flush window plus slack, so the batcher's timer fires.
        tokio::time::sleep(Duration::from_millis(60)).await;

        let batches = backend.batches.lock().unwrap().clone();
        let total: usize = batches.iter().sum();
        assert!(
            !batches.is_empty(),
            "the batcher must call inject_batch_at — the backend's aggregation lives there; \
             seeing zero batches is exactly the #82-part-1 regression (singles={})",
            backend.singles.load(Ordering::Relaxed)
        );
        assert_eq!(total, 4, "every submitted frame must reach the override: {batches:?}");
        assert_eq!(
            backend.singles.load(Ordering::Relaxed),
            0,
            "with batching on, nothing may bypass the batch seam and inject individually"
        );
    }

    /// **Tier-0 addressing must survive link-FEC.** Composing the two is offered by construction
    /// (`with_bloom_producer` + `with_link_fec` are independent builders), so it has to work.
    ///
    /// Under `TxAddr::PrefixBloom` the object's 12-byte prefix-set filter is split across *both*
    /// address fields — `resolve_addr` returns `(w[..6], w[6..])`, addr1 = filter-hi and
    /// addr2 = filter-lo — and the receiver's `NameGate` reassembles `addr1 ‖ addr2` before testing
    /// it. So a send path that pins only `dst` puts the face's own source in addr2, the receiver
    /// reconstructs half a filter, and the Bloom test fails: not a lost optimisation but a **false
    /// negative**, data dropped for a name the receiver registered.
    ///
    /// This asserts on the frames actually on the bus rather than on end-to-end delivery, so it
    /// isolates the addressing from FEC decode.
    #[tokio::test]
    async fn tier0_addressing_survives_link_fec() {
        use ndn_frame_io::FrameIo;
        use ndn_transport::Transport;

        const K: usize = 2;
        let key = OPEN_GROUP_KEY;
        let masks = crate::bloom_masks_for(&key, &[b"/x".as_slice()]);

        let bus = LoopbackMonitorBus::new();
        let sniffer = Arc::new(bus.endpoint(99, -70));
        let producer = MonitorWifiFace::new(FaceId(1), Arc::new(bus.endpoint(1, -50)))
            .with_bloom_producer(&key, b"/x/y")
            .with_link_fec(K, 1, Duration::from_millis(20));

        let collector = tokio::spawn(async move {
            let mut seen = Vec::new();
            while let Ok(Ok(f)) =
                tokio::time::timeout(Duration::from_millis(150), sniffer.recv_frame()).await
            {
                seen.push((f.group, f.addr));
            }
            seen
        });
        tokio::time::sleep(Duration::from_millis(10)).await;

        let wire = data_pkt(&name_tlv(&[b"x", b"y"]));
        for _ in 0..K {
            producer.send_bytes(wire.clone()).await.unwrap();
        }
        let frames = collector.await.unwrap();

        assert!(!frames.is_empty(), "the coded generation must reach the bus");
        for (i, (a1, a2)) in frames.iter().enumerate() {
            let (Some(a1), Some(a2)) = (a1, a2) else {
                panic!("frame {i} carries no address pair");
            };
            let mut w = [0u8; 12];
            w[..6].copy_from_slice(a1);
            w[6..].copy_from_slice(a2);
            let f = crate::PrefixFilter::from_wire(w);
            assert!(
                masks.iter().any(|m| f.may_match(m)),
                "coded frame {i} must still be addressed under /x — a receiver registered on /x \
                 reassembles addr1‖addr2 and drops it otherwise (addr1={a1:02x?} addr2={a2:02x?})"
            );
        }
    }
}
