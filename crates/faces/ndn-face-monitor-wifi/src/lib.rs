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
    name_group, name_group_mac, name_group_uni, prefix_key, radiotap,
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
pub use radio::{Bandwidth, DbmRange, RadioKnobs};

// The data-centric time-slice (#61) + FHSS (#40) transmit scheduler, actuated at the TX path.
mod sched;
pub use sched::FaceScheduler;

pub mod measure;

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
/// and hands them to [`WifiRadio::inject_batch_at`] (one A-MSDU per same-dst/src/mcs
/// run). Each MSDU stays an independent NDN packet (the receiver de-aggregates),
/// so only airtime is shared — the throughput↔latency knob, not NDN-layer Interest
/// bundling. Started by [`MonitorWifiFace::with_amsdu_batching`]. Each queued frame
/// carries its resolved MCS, so the exact rate rides the batch, not the seam.
struct TxBatcher {
    tx: tokio::sync::mpsc::UnboundedSender<(InjectFrame, McsDescriptor)>,
}

impl TxBatcher {
    fn spawn(backend: Arc<dyn WifiRadio>, max_msdus: usize, window: Duration) -> Self {
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

/// The Wi-Fi radio specifics of link FEC — the one part the bearer-agnostic
/// [`LinkFecBridge`] delegates: inject each coded frame of a generation as its
/// **own** MPDU (interleaved — never one generation per A-MSDU), at the MCS pinned
/// to the frame that opened the generation.
/// What a coded generation pins to the frame that opened it: the MCS **and** the
/// per-Data-name destination. So a generation carrying object `/x/y` is addressed to
/// `/x/y`'s split address — relays prefix-match it, the consumer exact-matches it —
/// exactly as an uncoded object is (composing split addressing with the coded path).
#[derive(Clone, Copy)]
struct WifiPin {
    mcs: McsDescriptor,
    dst: [u8; 6],
}

struct WifiFecSink {
    backend: Arc<dyn WifiRadio>,
    /// The source (name-derived, fixed for the face); the dst is pinned per generation.
    src: [u8; 6],
}

impl GenerationSink for WifiFecSink {
    type Pin = WifiPin;

    async fn emit(&self, coded: Vec<Bytes>, pin: &WifiPin) {
        inject_coded(&self.backend, &coded, Some(pin.mcs), pin.dst, self.src).await;
    }
}

/// Link-layer FEC over the radio (see [`MonitorWifiFace::with_link_fec`]). The codec,
/// generation batching, and the plan-driven redundancy actuation live in
/// `ndn_coding`'s reusable [`LinkFecBridge`]; this face supplies only the Wi-Fi
/// [`GenerationSink`] (MCS-pinned per-MPDU injection). The RX side feeds captured
/// frames through the bridge's decoder, recovering up to R losses per generation
/// without ARQ.
struct FaceFec {
    /// Batching + plan-R actuation over the radio; the pin is the per-generation
    /// (MCS, split dst) — see [`WifiPin`].
    bridge: LinkFecBridge<WifiPin>,
    /// Payloads recovered/delivered by the decoder, awaiting `recv_bytes`.
    pending: std::sync::Mutex<VecDeque<(Bytes, Option<FaceAddr>)>>,
}

impl FaceFec {
    fn spawn(
        backend: Arc<dyn WifiRadio>,
        src: [u8; 6],
        k: usize,
        redundancy: u16,
        window: Duration,
    ) -> Self {
        // The generation loop, the window flush, and the plan-driven R actuation
        // are all in the bearer-agnostic bridge (task #33); this face supplies only
        // the Wi-Fi injection (MCS + split dst pinned per generation). The dst rides
        // in the per-frame pin so per-Data-name addressing composes with coding.
        let bridge = LinkFecBridge::spawn(WifiFecSink { backend, src }, k, redundancy, window);
        FaceFec {
            bridge,
            pending: std::sync::Mutex::new(VecDeque::new()),
        }
    }
}

/// Inject each coded frame of a generation as its own MPDU, on the generation's MCS.
async fn inject_coded(
    backend: &Arc<dyn WifiRadio>,
    coded: &[Bytes],
    mcs: Option<McsDescriptor>,
    dst: [u8; 6],
    src: [u8; 6],
) {
    let Some(mcs) = mcs else { return };
    for f in coded {
        let _ = backend
            .inject_at(
                InjectFrame {
                    payload: f.clone(),
                    tx: TxIntent::CONSERVATIVE,
                    dst,
                    src,
                },
                mcs,
            )
            .await;
    }
}

/// **How outgoing frames get their addr1** — a composable, configurable capability
/// (set independently of the RX filter, the FEC bridge, the MCS policy, the trust
/// key). See `docs/mac-addressing-doctrine.md` §8.
#[derive(Clone)]
pub enum TxAddr {
    /// No name addressing: broadcast — every receiver in range hears it.
    Broadcast,
    /// One flat prefix-group address for all traffic (coarse — every frame shares it).
    Group([u8; 6], [u8; 6]),
    /// Per-Data-name **split**: derive `addr1 = H(prefix)‖H(name)` from each object's
    /// inner NDN name (all fragments of one object share it), so relays prefix-match
    /// by masking and consumers exact-match the full width.
    SplitByName {
        /// Trust context.
        key: GroupKey,
        /// The routable prefix (its hash is the high, aggregatable half).
        prefix: Vec<u8>,
    },
}

/// **Which received frames pass the pre-decode filter** — the RX-side capability,
/// independent of [`TxAddr`]. A consumer sets `Exact`, a relay `Prefix`, a
/// promiscuous/broadcast node `Open`. Broadcast frames always pass.
#[derive(Clone, Copy)]
pub enum RxFilter {
    /// Keep every frame (promiscuous / broadcast join).
    Open,
    /// Consumer: keep only this exact `addr1` (+ broadcast).
    Exact([u8; 6]),
    /// Relay: keep any frame whose prefix bytes ([`prefix_key`]) match this (+ broadcast).
    Prefix([u8; 6]),
}

/// The coarse prefix-match key for `routable_prefix` under `key` — what a relay's
/// [`RxFilter::Prefix`] holds, and what `prefix_key` of any split frame under that
/// prefix reduces to (the high, aggregatable half).
pub fn group_prefix_key(key: &GroupKey, routable_prefix: &[u8]) -> [u8; 6] {
    prefix_key(name_group(key, routable_prefix, routable_prefix, true))
}

/// Extract the NDN **Name** TLV bytes from an LP-framed wire frame's inner packet,
/// for [`TxAddr::SplitByName`]. Returns `None` for a non-first fragment (the name is
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

pub struct MonitorWifiFace {
    id: FaceId,
    backend: Arc<dyn WifiRadio>,
    mtu: usize,
    policy: McsPolicy,
    signal_sink: Option<Arc<dyn SignalStore<FaceId> + Send + Sync>>,
    /// Most-recently-observed RSSI, fed by every captured frame; the input to
    /// [`McsPolicy::Adaptive`]. Initialised to the conservative-default RSSI.
    last_rssi: AtomicI8,
    /// TX name-addressing capability (how outgoing `addr1` is chosen).
    tx_addr: TxAddr,
    /// RX name-filtering capability (which frames pass before decode).
    rx_filter: RxFilter,
    /// For [`TxAddr::SplitByName`]: the per-object `addr1` cached by LP base-sequence,
    /// so every fragment of one object (only the first carries the name) shares it.
    split_cache: Mutex<HashMap<u64, [u8; 6]>>,
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
    pub fn new(id: FaceId, backend: Arc<dyn WifiRadio>) -> Self {
        Self {
            id,
            backend,
            mtu: MONITOR_MTU,
            policy: McsPolicy::default(),
            signal_sink: None,
            last_rssi: AtomicI8::new(-70),
            tx_addr: TxAddr::Broadcast,
            rx_filter: RxFilter::Open,
            split_cache: Mutex::new(HashMap::new()),
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
    pub fn espnow(id: FaceId, backend: Arc<dyn WifiRadio>) -> Self {
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
        // The source is the face's fixed name-derived identity; the per-generation
        // destination rides the pin (composes split addressing with the coded path).
        let (_dst, src) = self.static_addr();
        self.fec = Some(FaceFec::spawn(
            self.backend.clone(),
            src,
            k.max(1),
            redundancy,
            window,
        ));
        self
    }

    /// Enable **link-layer A-MSDU bundling** on the send path: outbound frames
    /// are coalesced into one A-MSDU per up-to-`max_msdus` frames or `window`
    /// elapsed, whichever first — one PHY preamble for many NDN packets. Trades a
    /// little latency for ~3–4× airtime efficiency on the broadcast medium
    /// (`inject_amsdu`); each MSDU stays an independent NDN packet the receiver
    /// de-aggregates, so PIT/FIB semantics are untouched. Call before mounting
    /// (it spawns the flush task on the current runtime). A `window` of a few
    /// milliseconds and `max_msdus` ~8–16 is a sane default.
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

    /// Bind this face to a **name-group** under the **open** trust context: TX frames
    /// are addressed to/from the name-derived group MAC instead of broadcast, and RX
    /// drops frames for other groups (a name pre-filter before NDN decode). *"The
    /// routable prefix is the group address."* Open receiver set — anyone can compute
    /// the group and join. For a private trust domain, use
    /// [`with_name_group_keyed`](Self::with_name_group_keyed).
    pub fn with_name_group(self, routable_prefix: impl AsRef<[u8]>) -> Self {
        self.with_name_group_keyed(&OPEN_GROUP_KEY, routable_prefix)
    }

    /// Bind this face to a name-group under an explicit **trust context** ([`GroupKey`]):
    /// the group MAC is `siphash(key, routable_prefix)`, so under a shared-secret key
    /// the group is unforgeable/unlinkable to outsiders (they cannot compute it to
    /// target the pre-parse filter), and under [`OPEN_GROUP_KEY`] it is a public open
    /// receiver set. Verify-on-decode stays authoritative — the group MAC is a fast
    /// hint, not a security boundary.
    ///
    /// `routable_prefix` is the prefix this face serves/consumes; every frame shares
    /// this one flat prefix-group address. For per-Data-name addressing (relays
    /// prefix-match, consumers exact-match), see [`with_split_producer`],
    /// [`with_prefix_relay`], [`with_exact_consumer`] — or compose [`with_tx_addr`] +
    /// [`with_rx_filter`] directly.
    ///
    /// [`with_split_producer`]: Self::with_split_producer
    /// [`with_prefix_relay`]: Self::with_prefix_relay
    /// [`with_exact_consumer`]: Self::with_exact_consumer
    /// [`with_tx_addr`]: Self::with_tx_addr
    /// [`with_rx_filter`]: Self::with_rx_filter
    pub fn with_name_group_keyed(
        self,
        key: &GroupKey,
        routable_prefix: impl AsRef<[u8]>,
    ) -> Self {
        let p = routable_prefix.as_ref();
        self.with_tx_addr(TxAddr::Group(name_group_mac(key, p), name_group_uni(key, p)))
            .with_rx_filter(RxFilter::Exact(name_group_mac(key, p)))
    }

    /// Set the TX name-addressing capability directly (compose with [`with_rx_filter`]).
    pub fn with_tx_addr(mut self, tx: TxAddr) -> Self {
        self.tx_addr = tx;
        self
    }

    /// Set the RX name-filtering capability directly (compose with [`with_tx_addr`]).
    pub fn with_rx_filter(mut self, rx: RxFilter) -> Self {
        self.rx_filter = rx;
        self
    }

    /// **Producer** with per-Data-name split addressing: each object is sent to
    /// `H(prefix)‖H(name)` so relays prefix-match and consumers exact-match. RX keeps
    /// its own prefix family (overhearing). Convenience = `with_tx_addr(SplitByName) +
    /// with_rx_filter(Prefix)`.
    pub fn with_split_producer(self, key: &GroupKey, routable_prefix: impl AsRef<[u8]>) -> Self {
        let p = routable_prefix.as_ref().to_vec();
        let pk = group_prefix_key(key, &p);
        self.with_tx_addr(TxAddr::SplitByName { key: *key, prefix: p })
            .with_rx_filter(RxFilter::Prefix(pk))
    }

    /// **Relay** for a prefix family: RX keeps every frame whose prefix bytes match,
    /// so it hears all names under `routable_prefix` from a split producer with one
    /// filter entry (the aggregation win). TX is left as configured (a relay
    /// re-radiates whatever it forwards).
    pub fn with_prefix_relay(self, key: &GroupKey, routable_prefix: impl AsRef<[u8]>) -> Self {
        let pk = group_prefix_key(key, routable_prefix.as_ref());
        self.with_rx_filter(RxFilter::Prefix(pk))
    }

    /// **Consumer** for one exact name: RX keeps only the split address of
    /// `full_name` under `routable_prefix` — it hears `/x/y` from a split producer but
    /// not its sibling `/x/z`.
    pub fn with_exact_consumer(
        self,
        key: &GroupKey,
        routable_prefix: impl AsRef<[u8]>,
        full_name: impl AsRef<[u8]>,
    ) -> Self {
        let addr = name_group(key, routable_prefix.as_ref(), full_name.as_ref(), true);
        self.with_rx_filter(RxFilter::Exact(addr))
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

    /// The face's fixed group `(dst, src)` — for broadcast, the flat group, or (as a
    /// fallback where per-object split isn't applied, e.g. the FEC path) a split
    /// producer's flat prefix group.
    fn static_addr(&self) -> ([u8; 6], [u8; 6]) {
        match &self.tx_addr {
            TxAddr::Broadcast => (BROADCAST, DEFAULT_SRC),
            TxAddr::Group(d, s) => (*d, *s),
            TxAddr::SplitByName { key, prefix } => {
                (name_group_mac(key, prefix), name_group_uni(key, prefix))
            }
        }
    }

    /// Resolve the `(dst, src)` for one outgoing wire frame, applying
    /// [`TxAddr::SplitByName`] per Data object: the first fragment carries the name,
    /// from which `addr1 = H(prefix)‖H(name)` is derived and cached by LP
    /// base-sequence so the object's other fragments share it.
    fn resolve_addr(&self, wire: &[u8]) -> ([u8; 6], [u8; 6]) {
        let TxAddr::SplitByName { key, prefix } = &self.tx_addr else {
            return self.static_addr();
        };
        let src = name_group_uni(key, prefix);
        // Fragmented: key the per-object addr by the LP base sequence.
        if let Some(h) = ndn_packet::lp::extract_fragment(wire) {
            let base = h.sequence.wrapping_sub(h.frag_index);
            if h.frag_index == 0 {
                let dst = match inner_name(wire) {
                    Some(name) => name_group(key, prefix, name, true),
                    None => name_group_mac(key, prefix), // no name → flat prefix group
                };
                self.split_cache.lock().unwrap().insert(base, dst);
                return (dst, src);
            }
            if let Some(dst) = self.split_cache.lock().unwrap().get(&base).copied() {
                return (dst, src);
            }
            return (name_group_mac(key, prefix), src); // cache miss → flat prefix
        }
        // Single (unfragmented) packet: derive directly from its name.
        let dst = match inner_name(wire) {
            Some(name) => name_group(key, prefix, name, true),
            None => name_group_mac(key, prefix),
        };
        (dst, src)
    }

    /// Does a captured frame's `addr1` (`f.group`) pass this face's [`RxFilter`]?
    /// Broadcast always passes.
    fn rx_accepts(&self, addr1: Option<[u8; 6]>) -> bool {
        let Some(a) = addr1 else { return true };
        if a == BROADCAST {
            return true;
        }
        match self.rx_filter {
            RxFilter::Open => true,
            RxFilter::Exact(g) => a == g,
            RxFilter::Prefix(pk) => prefix_key(a) == pk,
        }
    }

    /// The rate to inject the next frame at. A control-plane plan
    /// ([`with_planned_params`]) wins when present; otherwise the static policy.
    ///
    /// [`with_planned_params`]: MonitorWifiFace::with_planned_params
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
            if !self.rx_accepts(f.group) {
                continue; // a different name-group — drop before decoding
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
            return fec
                .bridge
                .send(wire, WifiPin { mcs, dst }, self.planned_redundancy());
        }
        // The exact resolved rate travels alongside the frame (via inject_at /
        // the batcher), not on the intent — the frame's tx is a placeholder.
        let frame = InjectFrame {
            payload: wire,
            tx: TxIntent::CONSERVATIVE,
            dst,
            src,
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
    /// keeps its own group and broadcast.
    #[tokio::test]
    async fn name_group_face_filters_other_groups() {
        let bus = LoopbackMonitorBus::new();
        let face = MonitorWifiFace::new(FaceId(1), Arc::new(bus.endpoint(1, -50)))
            .with_name_group("/sensors/temp");
        let peer = Arc::new(bus.endpoint(2, -50));
        let tx = TxIntent::CONSERVATIVE;

        // Frame for a *different* group → filtered out (recv times out).
        peer.inject(InjectFrame {
            payload: Bytes::from_static(b"x"),
            tx,
            dst: name_group_mac(&OPEN_GROUP_KEY, b"/other/feed"),
            src: name_group_uni(&OPEN_GROUP_KEY, b"/other/feed"),
        })
        .await
        .unwrap();
        let got = tokio::time::timeout(Duration::from_millis(120), face.recv_bytes()).await;
        assert!(got.is_err(), "frame for another group must be dropped");

        // Frame for our group → delivered.
        peer.inject(InjectFrame {
            payload: Bytes::from_static(b"mine"),
            tx,
            dst: name_group_mac(&OPEN_GROUP_KEY, b"/sensors/temp"),
            src: name_group_uni(&OPEN_GROUP_KEY, b"/sensors/temp"),
        })
        .await
        .unwrap();
        let got = tokio::time::timeout(Duration::from_millis(200), face.recv_bytes())
            .await
            .expect("our-group frame should arrive")
            .unwrap();
        assert_eq!(got, Bytes::from_static(b"mine"));

        // Broadcast frame → also delivered (joins every group).
        peer.inject(InjectFrame::broadcast(Bytes::from_static(b"bcast"), tx))
            .await
            .unwrap();
        let got = tokio::time::timeout(Duration::from_millis(200), face.recv_bytes())
            .await
            .expect("broadcast frame should arrive")
            .unwrap();
        assert_eq!(got, Bytes::from_static(b"bcast"));
    }

    /// Trust-context isolation: a face keyed to a private domain does NOT match a
    /// frame for the SAME routable prefix under the open key — an outsider who knows
    /// the (public) name cannot address the private group's pre-parse filter.
    #[tokio::test]
    async fn keyed_name_group_isolates_trust_domains() {
        let secret = GroupKey(*b"trust-domain-42!");
        let bus = LoopbackMonitorBus::new();
        let face = MonitorWifiFace::new(FaceId(1), Arc::new(bus.endpoint(1, -50)))
            .with_name_group_keyed(&secret, "/sensors/temp");
        let peer = Arc::new(bus.endpoint(2, -50));
        let tx = TxIntent::CONSERVATIVE;

        // Same prefix, but the OPEN key → a different group hash → dropped.
        peer.inject(InjectFrame {
            payload: Bytes::from_static(b"outsider"),
            tx,
            dst: name_group_mac(&OPEN_GROUP_KEY, b"/sensors/temp"),
            src: name_group_uni(&OPEN_GROUP_KEY, b"/sensors/temp"),
        })
        .await
        .unwrap();
        let got = tokio::time::timeout(Duration::from_millis(120), face.recv_bytes()).await;
        assert!(got.is_err(), "same prefix under the open key must not match the private group");

        // Same prefix under the SAME secret key → delivered.
        peer.inject(InjectFrame {
            payload: Bytes::from_static(b"insider"),
            tx,
            dst: name_group_mac(&secret, b"/sensors/temp"),
            src: name_group_uni(&secret, b"/sensors/temp"),
        })
        .await
        .unwrap();
        let got = tokio::time::timeout(Duration::from_millis(200), face.recv_bytes())
            .await
            .expect("same-key frame should arrive")
            .unwrap();
        assert_eq!(got, Bytes::from_static(b"insider"));
    }

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

    /// Per-Data-name split addressing, end to end: a split **producer** sends `/x/y`
    /// and `/x/z`; a **relay** filtering on the prefix `/x` hears BOTH (one filter
    /// entry, the family) while a **consumer** for exactly `/x/y` hears only `/x/y`.
    /// This is the payoff of the split — coarse for relays, fine for consumers, from
    /// the same address the producer compiles from each object's name.
    #[tokio::test]
    async fn split_addressing_relay_prefix_matches_consumer_exact_matches() {
        let key = OPEN_GROUP_KEY;
        let bus = LoopbackMonitorBus::new();
        let xy = name_tlv(&[b"x", b"y"]);
        let xz = name_tlv(&[b"x", b"z"]);

        let producer = MonitorWifiFace::new(FaceId(1), Arc::new(bus.endpoint(1, -50)))
            .with_split_producer(&key, "/x");
        let relay = MonitorWifiFace::new(FaceId(2), Arc::new(bus.endpoint(2, -50)))
            .with_prefix_relay(&key, "/x");
        let consumer = MonitorWifiFace::new(FaceId(3), Arc::new(bus.endpoint(3, -50)))
            .with_exact_consumer(&key, "/x", &xy);

        producer.send_bytes(data_pkt(&xy)).await.unwrap();
        producer.send_bytes(data_pkt(&xz)).await.unwrap();

        // The relay hears BOTH /x/y and /x/z (prefix aggregation).
        let mut relayed = Vec::new();
        for _ in 0..2 {
            let (b, _) = tokio::time::timeout(Duration::from_millis(300), relay.recv_bytes_with_addr())
                .await
                .expect("relay should hear both names under /x")
                .unwrap();
            relayed.push(b);
        }
        relayed.sort();
        let mut want = vec![data_pkt(&xy), data_pkt(&xz)];
        want.sort();
        assert_eq!(relayed, want, "relay prefix-matches the whole /x family");

        // The consumer hears /x/y (its exact name) …
        let (got, _) = tokio::time::timeout(Duration::from_millis(300), consumer.recv_bytes_with_addr())
            .await
            .expect("consumer should hear its exact name")
            .unwrap();
        assert_eq!(got, data_pkt(&xy));
        // … but NOT the sibling /x/z (different full address).
        let none = tokio::time::timeout(Duration::from_millis(150), consumer.recv_bytes_with_addr()).await;
        assert!(none.is_err(), "consumer must NOT hear the sibling /x/z");
    }

    /// Split addressing composed with **link FEC**: each object is a coded generation
    /// addressed to its own split address (pinned to the generation, like the MCS), so
    /// the relay prefix-matches and decodes the whole `/x` family while the `/x/y`
    /// consumer decodes only `/x/y`. This is the coded path no longer using a static
    /// group address.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn split_addressing_composes_with_link_fec() {
        let key = OPEN_GROUP_KEY;
        let win = Duration::from_millis(50);
        let bus = LoopbackMonitorBus::new();
        let xy = name_tlv(&[b"x", b"y"]);
        let xz = name_tlv(&[b"x", b"z"]);

        // k=1 so each object is its own generation → its own split address.
        let producer = MonitorWifiFace::new(FaceId(1), Arc::new(bus.endpoint(1, -50)))
            .with_split_producer(&key, "/x")
            .with_link_fec(1, 1, win);
        let relay = MonitorWifiFace::new(FaceId(2), Arc::new(bus.endpoint(2, -50)))
            .with_prefix_relay(&key, "/x")
            .with_link_fec(1, 1, win);
        let consumer = MonitorWifiFace::new(FaceId(3), Arc::new(bus.endpoint(3, -50)))
            .with_exact_consumer(&key, "/x", &xy)
            .with_link_fec(1, 1, win);

        producer.send_bytes(data_pkt(&xy)).await.unwrap();
        producer.send_bytes(data_pkt(&xz)).await.unwrap();

        let mut relayed = Vec::new();
        for _ in 0..2 {
            let b = tokio::time::timeout(Duration::from_secs(2), relay.recv_bytes())
                .await
                .expect("relay decodes both coded objects under /x")
                .unwrap();
            relayed.push(b);
        }
        relayed.sort();
        let mut want = vec![data_pkt(&xy), data_pkt(&xz)];
        want.sort();
        assert_eq!(relayed, want, "relay prefix-matches + decodes the whole coded family");

        let got = tokio::time::timeout(Duration::from_secs(2), consumer.recv_bytes())
            .await
            .expect("consumer decodes its exact coded object")
            .unwrap();
        assert_eq!(got, data_pkt(&xy));
        let none = tokio::time::timeout(Duration::from_millis(200), consumer.recv_bytes()).await;
        assert!(none.is_err(), "consumer must not decode the sibling /x/z");
    }
}
