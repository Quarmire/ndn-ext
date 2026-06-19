//! Connectionless **802.11 monitor-mode** face — a named-radio bearer over raw
//! WiFi injection.
//!
//! **Architecture & concepts: see [`docs/RADIO_SUBSYSTEM.md`](../docs/RADIO_SUBSYSTEM.md)** —
//! the two seams ([`FrameIo`] data plane / [`RadioKnobs`] control plane), how a
//! radio is a *pool of capability* rather than an IP interface, how this binds to
//! `ndn-rs`, the per-chip device details, and the recipe for adding a backend.
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
//! is a backend choice, exactly the [`AdvBackend`]/`RadioBackend`/`NanBackend`
//! pattern used elsewhere in the stack.
//!
//! - [`AfPacketBackend`] (Linux, `cfg(target_os = "linux")`) — `AF_PACKET`
//!   `SOCK_RAW` on a monitor-mode interface; builds radiotap TX + the 802.11
//!   frame per [`FrameFormat`], parses radiotap RX. Requires `CAP_NET_RAW`.
//! - [`LoopbackMonitorBus`] — a hardware-free shared medium for CI and
//!   simulation; carries the NDN payload plus a simulated RSSI/MCS so the whole
//!   face, NDNLPv2 fragmentation, and RSSI plumbing run through a real engine
//!   without a radio.
//!
//! - [`LibUsbRtl88xxBackend`] (`libusb-backend` feature) — a **working**
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

use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::{AtomicI8, Ordering};
use std::time::Duration;

use bytes::Bytes;
use ndn_radio_cognition::TxParams;
use ndn_coding::{LinkFecRx, LinkFecTx};
use ndn_signals_core::{LinkSignals, SignalStore};
use std::collections::VecDeque;
use ndn_transport::{
    Face, FaceAddr, FaceKind, FacePersistency, LinkType, MtuError, PersistencyError, Transport,
};

// The frame-I/O substrate — the `FrameIo` trait, the inject/capture frame
// types, the on-air framing (`frame`/`radiotap`), and the reusable AF_PACKET +
// loopback backends — moved to `ndn-frame-io`. Re-exported here so existing
// `ndn_face_monitor_wifi::` paths (and this crate's own modules, which still
// reference `crate::frame::…`, `crate::McsDescriptor`, `crate::FrameIo`) keep
// working unchanged.
pub use ndn_frame_io::{
    BROADCAST, CapturedFrame, DEFAULT_SRC, ESPNOW_MAX_BODY, ESPNOW_OUI, FaceError, FaceId,
    FrameFormat, FrameIo, InjectFrame, LEGACY_ETHER_MTU, LoopbackEndpoint, LoopbackMonitorBus,
    MAX_RELIABLE_MCS, MONITOR_MTU, McsDescriptor, McsPolicy, frame, mcs_for_rssi, mcs_phy_rate_bps,
    name_group_mac, name_group_uni, radiotap,
};
#[cfg(target_os = "linux")]
pub use ndn_frame_io::AfPacketBackend;

#[cfg(feature = "libusb-backend")]
mod libusb_rtl88xx;
#[cfg(feature = "libusb-backend")]
pub use libusb_rtl88xx::{
    CHIP_ID_8822E, ChannelBw, FwVersion, LibUsbRtl88xxBackend, REALTEK_VID, REG_SYS_CFG,
    RTL88XX_PIDS, RfPath,
};

// Userspace RTL8821CU/8811CU backend (rtw88-derived). Separate module from the
// 8822E backend above: different HAL generation, power sequence, firmware-download
// path, and descriptors. See `docs/rtl8821cu-port-reference.md`.
#[cfg(feature = "libusb-backend")]
mod rtl8821c;
#[cfg(feature = "libusb-backend")]
pub use rtl8821c::{RTL8821CU_PIDS, Rtl8821cuBackend};

#[cfg(feature = "libusb-backend")]
mod mt7612;
#[cfg(feature = "libusb-backend")]
pub use mt7612::{MT7612U_PIDS, Mt7612uBackend};

mod control;
pub use control::RadioControl;
#[cfg(feature = "libusb-backend")]
pub use control::LibUsbActuator;

pub mod radio;
pub use radio::{Bandwidth, RadioKnobs};

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
/// and hands them to [`FrameIo::inject_batch`] (one A-MSDU per same-dst/src/mcs
/// run). Each MSDU stays an independent NDN packet (the receiver de-aggregates),
/// so only airtime is shared — the throughput↔latency knob, not NDN-layer Interest
/// bundling. Started by [`MonitorWifiFace::with_amsdu_batching`].
struct TxBatcher {
    tx: tokio::sync::mpsc::UnboundedSender<InjectFrame>,
}

impl TxBatcher {
    fn spawn(backend: Arc<dyn FrameIo>, max_msdus: usize, window: Duration) -> Self {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<InjectFrame>();
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
                let _ = backend.inject_batch(batch).await;
            }
        });
        TxBatcher { tx }
    }

    fn submit(&self, frame: InjectFrame) -> Result<(), FaceError> {
        self.tx.send(frame).map_err(|_| FaceError::Closed)
    }
}

/// Link-layer FEC over the radio (see [`MonitorWifiFace::with_link_fec`]). The
/// TX side accumulates up to K outbound frames (or a latency window) and emits
/// K+R coded frames, each as its **own** MPDU (interleaved — never one
/// generation per A-MSDU); the RX side de-codes, recovering up to R losses per
/// generation without ARQ. Reuses `ndn_coding`'s systematic K-of-N codec.
struct FaceFec {
    /// Outbound wire frames + the MCS for the generation.
    tx: tokio::sync::mpsc::UnboundedSender<(Bytes, McsDescriptor)>,
    rx: std::sync::Mutex<LinkFecRx>,
    /// Payloads recovered/delivered by the decoder, awaiting `recv_bytes`.
    pending: std::sync::Mutex<VecDeque<(Bytes, Option<FaceAddr>)>>,
}

impl FaceFec {
    fn spawn(
        backend: Arc<dyn FrameIo>,
        dst: [u8; 6],
        src: [u8; 6],
        k: usize,
        redundancy: u16,
        window: Duration,
    ) -> Self {
        let (tx, mut rx_ch) = tokio::sync::mpsc::unbounded_channel::<(Bytes, McsDescriptor)>();
        tokio::spawn(async move {
            let mut enc = LinkFecTx::new(redundancy);
            while let Some((first, mcs)) = rx_ch.recv().await {
                // The whole generation uses the first frame's MCS (parity must match).
                let mut accum = vec![first];
                let deadline = tokio::time::Instant::now() + window;
                while accum.len() < k {
                    match tokio::time::timeout_at(deadline, rx_ch.recv()).await {
                        Ok(Some((w, _))) => accum.push(w),
                        _ => break, // window elapsed (tail flush) or sender dropped
                    }
                }
                if let Ok(coded) = enc.encode(accum) {
                    // Each coded frame as its own MPDU → interleaved on air.
                    for f in coded {
                        let _ = backend
                            .inject(InjectFrame {
                                payload: f,
                                mcs,
                                dst,
                                src,
                            })
                            .await;
                    }
                }
            }
        });
        FaceFec {
            tx,
            rx: std::sync::Mutex::new(LinkFecRx::new()),
            pending: std::sync::Mutex::new(VecDeque::new()),
        }
    }
}

pub struct MonitorWifiFace {
    id: FaceId,
    backend: Arc<dyn FrameIo>,
    mtu: usize,
    policy: McsPolicy,
    signal_sink: Option<Arc<dyn SignalStore<FaceId> + Send + Sync>>,
    /// Most-recently-observed RSSI, fed by every captured frame; the input to
    /// [`McsPolicy::Adaptive`]. Initialised to the conservative-default RSSI.
    last_rssi: AtomicI8,
    /// Name-group binding `(group_mac, group_uni)` from [`with_name_group`].
    /// When set, frames are addressed to/from the name-derived group and the
    /// receive path drops frames for other groups. `None` = broadcast.
    ///
    /// [`with_name_group`]: MonitorWifiFace::with_name_group
    group: Option<([u8; 6], [u8; 6])>,
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
            group: None,
            batcher: None,
            fec: None,
            planned: None,
        }
    }

    /// Build an **ESP-NOW** face over `backend` — the first-class
    /// NDN-over-ESP-NOW path. `backend` must be in [`FrameFormat::EspNow`] mode
    /// (e.g. `AfPacketBackend::new(iface, FrameFormat::EspNow { oui: ESPNOW_OUI })`
    /// on Linux, or use [`open_libusb_espnow`](Self::open_libusb_espnow) on a
    /// host without a kernel monitor driver). The face is sized to the 250-B
    /// ESP-NOW body ([`ESPNOW_MTU`]) so the paired `LpLinkService` fragments NDN
    /// packets into vendor-action frames a stock `esp-wifi` ESP-NOW peer hears;
    /// the broadcast addressing ESP-NOW requires is the default (no name-group).
    /// Chainable with [`with_signal_sink`](Self::with_signal_sink),
    /// [`with_link_fec`](Self::with_link_fec), etc.
    pub fn espnow(id: FaceId, backend: Arc<dyn FrameIo>) -> Self {
        Self::new(id, backend).with_mtu(ESPNOW_MTU)
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
        let (dst, src) = match self.group {
            Some((mac, uni)) => (mac, uni),
            None => (BROADCAST, DEFAULT_SRC),
        };
        self.fec = Some(FaceFec::spawn(
            self.backend.clone(),
            dst,
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
    /// ([`inject_amsdu`]); each MSDU stays an independent NDN packet the receiver
    /// de-aggregates, so PIT/FIB semantics are untouched. Call before mounting
    /// (it spawns the flush task on the current runtime). A `window` of a few
    /// milliseconds and `max_msdus` ~8–16 is a sane default.
    ///
    /// [`inject_amsdu`]: crate::LibUsbRtl88xxBackend::inject_amsdu
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

    /// Bind this face to a **name-group**: TX frames are addressed to/from the
    /// name-derived group MAC (`name_group_mac`/`name_group_uni`) instead of
    /// broadcast, and RX drops frames for other groups (a name pre-filter before
    /// NDN decode). *"The prefix is the group address."* Verify-on-decode stays
    /// authoritative — the group MAC is a fast hint, not a security boundary.
    pub fn with_name_group(mut self, prefix: impl AsRef<[u8]>) -> Self {
        let p = prefix.as_ref();
        self.group = Some((name_group_mac(p), name_group_uni(p)));
        self
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
    /// same `Arc` to [`RadioControl::libusb_actuator`] so both ends share it.
    ///
    /// [`RadioControl`]: crate::RadioControl
    /// [`RadioControl::libusb_actuator`]: crate::RadioControl::libusb_actuator
    pub fn with_planned_params(mut self, cell: Arc<RwLock<Option<TxParams>>>) -> Self {
        self.planned = Some(cell);
        self
    }

    /// Build a [`Face`] pairing this transport with the `LpLinkService`, so the
    /// engine fragments/reassembles NDN packets across injected frames.
    pub fn into_face(self) -> Face {
        Face::from_transport(self)
    }

    /// The rate to inject the next frame at. A control-plane plan
    /// ([`with_planned_params`]) wins when present; otherwise the static policy.
    ///
    /// [`with_planned_params`]: MonitorWifiFace::with_planned_params
    fn select_mcs(&self) -> McsDescriptor {
        if let Some(cell) = &self.planned
            && let Ok(guard) = cell.read()
            && let Some(tp) = *guard
            && let Some(index) = tp.mcs
        {
            return McsDescriptor {
                index,
                short_gi: tp.short_gi,
                vht: tp.vht,
                nss: tp.nss.unwrap_or(1),
                stbc: tp.stbc,
                ldpc: tp.ldpc,
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
            if let (Some((mac, _)), Some(g)) = (self.group, f.group)
                && g != mac
                && g != BROADCAST
            {
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
        // Address it to the name-group (or broadcast) — never a host MAC.
        let (dst, src) = match self.group {
            Some((mac, uni)) => (mac, uni),
            None => (BROADCAST, DEFAULT_SRC),
        };
        let mcs = self.select_mcs();
        // Link-FEC: enqueue the wire frame; the flush task groups a generation,
        // emits K+R coded frames (one MPDU each, interleaved), recovers losses.
        if let Some(fec) = &self.fec {
            return fec.tx.send((wire, mcs)).map_err(|_| FaceError::Closed);
        }
        let frame = InjectFrame {
            payload: wire,
            mcs,
            dst,
            src,
        };
        // With A-MSDU batching the frame is enqueued (non-blocking) and bundled
        // by the flush task; otherwise it is injected immediately.
        match &self.batcher {
            Some(b) => b.submit(frame),
            None => self.backend.inject(frame).await,
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
                if !LinkFecRx::is_fec(&f.payload) {
                    return Ok((f.payload, addr)); // not a FEC frame — deliver as-is
                }
                let delivered = fec
                    .rx
                    .lock()
                    .unwrap()
                    .absorb(f.payload)
                    .unwrap_or_default();
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
        let tx = MonitorWifiFace::new(FaceId(1), Arc::new(bus.endpoint(1, -50)))
            .with_link_fec(3, 2, Duration::from_millis(20));
        let rx = MonitorWifiFace::new(FaceId(2), Arc::new(bus.endpoint(2, -60)))
            .with_link_fec(3, 2, Duration::from_millis(20));

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

        tx.send_bytes(Bytes::from_static(b"\x05\x03ndn")).await.unwrap();
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
            mcs: McsDescriptor::CONSERVATIVE,
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
            mcs: McsDescriptor::CONSERVATIVE,
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
        let mcs = McsDescriptor::CONSERVATIVE;

        // Frame for a *different* group → filtered out (recv times out).
        peer.inject(InjectFrame {
            payload: Bytes::from_static(b"x"),
            mcs,
            dst: name_group_mac(b"/other/feed"),
            src: name_group_uni(b"/other/feed"),
        })
        .await
        .unwrap();
        let got = tokio::time::timeout(Duration::from_millis(120), face.recv_bytes()).await;
        assert!(got.is_err(), "frame for another group must be dropped");

        // Frame for our group → delivered.
        peer.inject(InjectFrame {
            payload: Bytes::from_static(b"mine"),
            mcs,
            dst: name_group_mac(b"/sensors/temp"),
            src: name_group_uni(b"/sensors/temp"),
        })
        .await
        .unwrap();
        let got = tokio::time::timeout(Duration::from_millis(200), face.recv_bytes())
            .await
            .expect("our-group frame should arrive")
            .unwrap();
        assert_eq!(got, Bytes::from_static(b"mine"));

        // Broadcast frame → also delivered (joins every group).
        peer.inject(InjectFrame::broadcast(Bytes::from_static(b"bcast"), mcs))
            .await
            .unwrap();
        let got = tokio::time::timeout(Duration::from_millis(200), face.recv_bytes())
            .await
            .expect("broadcast frame should arrive")
            .unwrap();
        assert_eq!(got, Bytes::from_static(b"bcast"));
    }
}
