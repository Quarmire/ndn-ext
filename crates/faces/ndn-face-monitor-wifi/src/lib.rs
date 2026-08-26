//! Connectionless **802.11 monitor-mode** face — a named-radio bearer over raw
//! WiFi injection.
//!
//! **Architecture & concepts: see `docs/RADIO_SUBSYSTEM.md`** — the two seams
//! ([`FrameIo`] data plane / [`RadioKnobs`] control plane), how a radio is a
//! *pool of capability* rather than an IP interface, how this binds to `ndn-rs`,
//! the per-chip device details, and the recipe for adding a backend. (That file
//! is tracked in-tree; `docs/INDEX.md` maps this directory's docs and their
//! reading order.)
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
use ndn_coding::link_fec_bridge::GenerationSink;
use ndn_radio_cognition::TxParams;
use ndn_signals_core::SignalStore;
use ndn_transport::{
    Face, FaceAddr, FaceKind, FacePersistency, LinkType, MtuError, PersistencyError, Transport,
};
use std::collections::HashMap;
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
    RadioCapability, Reach, Reliability, TxIntent, frame, mcs_for_rssi, mcs_phy_rate_bps,
    radiotap,
};

// The four userspace USB Wi-Fi driver backends (RTL8812EU/8822E, RTL8821CU,
// MT7612U, RTL8812AU) were lifted into the standalone `ndn-radio-drivers` crate
// so drivers have a dedicated home. Re-exported here so existing
// `ndn_face_monitor_wifi::` paths (and this crate's `crate::LibUsbRtl88xxBackend`
// etc. references in `control.rs`/`lib.rs`) keep working unchanged.
#[cfg(feature = "libusb-backend")]
pub use ndn_radio_drivers::{
    Ath9kHtcBackend, CHIP_ID_8822E, ChannelBw, ChipInfo, DeviceSelect, FwVersion, IqkResult,
    LegacyRate, LibUsbRtl88xxBackend, MT7612U_PIDS, Mt7612uBackend, REALTEK_VID, REG_SYS_CFG,
    RTL88XX_PIDS, RTL8733B_PIDS, RTL8812AU_PIDS, RTL8821CU_PIDS, RfPath, Rtl8733buBackend,
    Rtl8812auBackend, Rtl8821cuBackend, open_ath9k, open_named_radio,
};

// The serial-bridged 802.11 backend (BW16 / ESP32-C5) — a raw 802.11 node driven
// over USB-serial, usable under a MonitorWifiFace exactly like the USB backends.
#[cfg(feature = "serial-radio")]
pub use ndn_radio_drivers::{SerialRadioBackend, Esp32SerialBackend};

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
pub use ndn_radio_cognition::{FULL_RX_MCS, LEGACY_ONLY_RX, SINGLE_STREAM_HT_RX_MCS};

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
pub use sched::{FaceScheduler, GroupTable, TIME_BEACON_MAGIC, TimeStatus};

pub mod measure;

// #91 Tier-0: the in-frame prefix-set Bloom filter (addr1 ‖ addr2). Zero-parse name matching that
// replaces the name-group hash; ported from the measured firmware reference. See the module docs.
pub mod name_gate;
pub mod ndn_nic;
pub mod gcs;
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


/// The frame → Name-TLV → `/`-joined-name derivation is a **named-data-radio primitive**, not this
/// face's private helper: it lives in `ndn_radio_cognition::name` so every bearer (this face's
/// address Blur, the LoRa body GCS, …) computes filter input over identical bytes (#44). Re-exported
/// here so the many `crate::inner_name` / `crate::ndn_name_to_slash` call sites resolve unchanged,
/// against the one shared implementation.
pub(crate) use ndn_radio_cognition::name::{inner_name, ndn_name_to_slash};

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
pub(crate) fn bloom_wire_for_wire(key: &GroupKey, wire: &[u8]) -> Option<[u8; 16]> {
    let name = inner_name(wire)?;
    let mut f = PrefixFilter::new();
    f.insert_name(bloom_key64(key), &ndn_name_to_slash(name));
    Some(f.to_wire())
}

/// **How the next frame's exact rate is chosen** — shared by both faces (#82).
///
/// Three inputs, in priority order:
///
/// 1. the cognitive control plane's decided [`TxParams`], when a plan cell is bound — the ACT half
///    of the closed loop, and the reason this is not just a constant;
/// 2. otherwise [`McsPolicy::Adaptive`], from the most recently observed RSSI;
/// 3. otherwise the static [`McsPolicy::Fixed`] rate.
///
/// This was `MonitorWifiFace`-only: `RadioMediumFace` models rate as bearer state set out-of-band,
/// so a medium face had no way to act on a decided MCS at all. It is the last of the four features
/// #82 found on one side only (after the name gate, link-FEC and A-MSDU), and the least visible —
/// a plan that decides a rate nothing applies looks exactly like a plan that decided the rate you
/// were already using.
///
/// Shared behind an `Arc` because the RX path writes `last_rssi` while the TX path reads it, and on
/// the medium those are different tasks on different bearers observing one link.
pub struct RatePolicy {
    policy: McsPolicy,
    /// Most-recently-observed RSSI, fed by every captured frame; the input to
    /// [`McsPolicy::Adaptive`]. Initialised to the conservative-default RSSI.
    last_rssi: AtomicI8,
    /// The control plane's decided [`TxParams`], when bound. Wins over the static policy.
    planned: Option<Arc<RwLock<Option<TxParams>>>>,
}

impl RatePolicy {
    pub fn new(policy: McsPolicy) -> Self {
        Self {
            policy,
            last_rssi: AtomicI8::new(-70),
            planned: None,
        }
    }

    pub fn with_planned(mut self, cell: Arc<RwLock<Option<TxParams>>>) -> Self {
        self.planned = Some(cell);
        self
    }

    /// Record a captured frame's RSSI — the feedback that makes `Adaptive` adaptive.
    pub fn observe_rssi(&self, dbm: i8) {
        self.last_rssi.store(dbm, Ordering::Relaxed);
    }

    /// The rate to inject the next frame at.
    pub fn select(&self) -> McsDescriptor {
        if let Some(cell) = &self.planned
            && let Ok(guard) = cell.read()
            && let Some(tp) = *guard
            && let Some(mcs) = tp.wifi_mcs()
        {
            return mcs; // the write-once TxParams->McsDescriptor mapping (see TxParams::wifi_mcs)
        }
        match self.policy {
            McsPolicy::Fixed(d) => d,
            McsPolicy::Adaptive => {
                McsDescriptor::ht(mcs_for_rssi(self.last_rssi.load(Ordering::Relaxed)))
            }
        }
    }

    /// The plan's decided **A-MSDU target**, in MSDUs, when the cell carries one.
    ///
    /// `Some(0)` is meaningful and distinct from `None`: the cognition plane spelling "do not
    /// aggregate" (a latency-sensitive class, or a medium where a long MPDU is a bad bet), versus
    /// "no opinion — keep the face's configured cap".
    ///
    /// Wired late. `TxParams::amsdu_msdus` had an accessor and **zero callers** — the plane decided
    /// an aggregation target that reached no actuator, exactly the defect this crate keeps
    /// producing, and it survived the session that *built* the A-MSDU batcher because that batcher
    /// took a static bound from its builder and never asked the plan.
    pub fn planned_amsdu_msdus(&self) -> Option<u16> {
        self.planned
            .as_ref()?
            .read()
            .ok()
            .and_then(|g| *g)
            .and_then(|tp| tp.amsdu_msdus())
    }

    /// The plan's decided link-FEC redundancy, when the cell carries one.
    pub fn planned_redundancy(&self) -> Option<u16> {
        self.planned
            .as_ref()?
            .read()
            .ok()
            .and_then(|g| *g)
            .and_then(|tp| tp.link_fec_redundancy)
    }
}

/// **Tier-0 TX addressing for a whole object, fragments included** — shared by both faces (#82).
///
/// Only fragment 0 of an LP-fragmented object carries the Name TLV, so the object's prefix-set
/// filter can be derived exactly once. This caches it by **LP base sequence** (`sequence -
/// frag_index`) so fragments 1..n are addressed to the same filter as the fragment that opened the
/// object, and a receiver registered on that prefix admits all of them.
///
/// `MonitorWifiFace` had this; `RadioMediumFace` did not — its `bloom_wire_for_wire` asked
/// `inner_name` per frame, got `None` for every continuation fragment and fell back to broadcast.
/// That loses no data (broadcast is admitted by everyone) but surrenders the filtering on all but
/// the first frame of every fragmented object — nearly all traffic at a fragmenting MTU, and
/// enough to have quietly invalidated #106's measured 87.32% reject had the faces been collapsed
/// onto the uncached path. `medium_addresses_every_fragment_of_an_object_under_its_prefix` is the
/// regression test.
///
/// Unlike the original, the cache is **bounded**. The face's was a `HashMap` that only ever grew:
/// one entry per fragmented object, inserted and never removed — a slow leak on a long-running
/// relay. Entries are dropped when the object's last fragment goes out, and a hard cap covers the
/// case where that fragment never arrives (a torn-down peer, a reordered tail). Evicting early is
/// safe: a miss falls back to broadcast, which over-accepts rather than dropping.
pub(crate) struct Tier0Addresser {
    key: GroupKey,
    cache: Mutex<HashMap<u64, [u8; 16]>>,
}

/// Cap on in-flight fragmented objects tracked at once. Generous next to any real fragment window;
/// it exists so a peer that vanishes mid-object cannot grow the map without bound.
const TIER0_CACHE_CAP: usize = 4096;

impl Tier0Addresser {
    pub(crate) fn new(key: GroupKey) -> Self {
        Self {
            key,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// How many in-flight objects are currently tracked — the bound this type exists to keep.
    #[cfg(test)]
    pub(crate) fn tracked(&self) -> usize {
        self.cache.lock().unwrap().len()
    }

    /// The 12-byte filter (`addr1 ‖ addr2`) for this outgoing wire, or `None` to address it
    /// broadcast — no name and no cached object, a safe over-accept.
    pub(crate) fn wire_for(&self, wire: &[u8]) -> Option<[u8; 16]> {
        let Some(h) = ndn_packet::lp::extract_fragment(wire) else {
            // Unfragmented: the name is right here, nothing to remember.
            return bloom_wire_for_wire(&self.key, wire);
        };
        let base = h.sequence.wrapping_sub(h.frag_index);
        let last = h.frag_index + 1 >= h.frag_count;
        if h.frag_index == 0 {
            let w = bloom_wire_for_wire(&self.key, wire)?;
            if !last {
                let mut c = self.cache.lock().unwrap();
                if c.len() >= TIER0_CACHE_CAP
                    && let Some(&victim) = c.keys().next()
                {
                    c.remove(&victim);
                }
                c.insert(base, w);
            }
            return Some(w);
        }
        let mut c = self.cache.lock().unwrap();
        if last { c.remove(&base) } else { c.get(&base).copied() }
    }
}

/// Precompute one [`PrefixFilter::mask_for`] per registered `/`-string prefix — a receiver's
/// [`RxFilter::Bloom`] mask set, reusable by the medium's RX reader.
pub(crate) fn bloom_masks_for(key: &GroupKey, prefixes: &[impl AsRef<[u8]>]) -> std::sync::Arc<[PrefixFilter]> {
    let k = bloom_key64(key);
    prefixes.iter().map(|p| PrefixFilter::mask_for(k, p.as_ref())).collect()
}



// `inject_at` / `inject_batch_at` are called straight on `FrameIo` — there are no local helpers.
//
// #82 part 1 moved this face from `Arc<dyn FrameIo>` to `Arc<dyn FrameIo>`. That was the right
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

/// **A single-radio monitor-mode face — a one-bearer [`RadioMediumFace`]** (#82).
///
/// This is now a *builder*, not a second data plane. Every frame it sends and receives goes through
/// the medium's `TxBearer` / reader task; nothing about addressing, filtering, coding, batching or
/// rate lives here any more. What remains is the ergonomics that made this type worth keeping: the
/// one-call constructors for a single radio ([`espnow`](Self::espnow), [`halow`](Self::halow),
/// [`open_libusb`](Self::open_libusb)) and a builder chain that reads in single-radio terms.
///
/// #82 called for collapsing the two faces because "the right model has the fewer features", and
/// that is what happened — but only after the features were reconciled one at a time, because each
/// pass found the copies had diverged, not merely duplicated:
///
/// | feature | what the split had done |
/// |---|---|
/// | name gate | Tier-1 and the NDN-NIC baseline existed on one side only (part 1) |
/// | A-MSDU | reached the backend's override from one side only; a helper silently disabled it |
/// | link-FEC | two sinks, each pinning too little; coded frames lost Tier-0 addressing |
/// | Tier-0 fragments | the medium had no fragment cache; the face's leaked |
/// | rate policy | a decided MCS reached the air from one side only |
///
/// The collapse also fixes one thing on its own, with no code written for it: this face used to
/// address non-Tier-0 frames `(BROADCAST, DEFAULT_SRC)` — a fixed host tag in the source field,
/// which is exactly what `docs/mac-addressing-doctrine.md` §2 forbids. The medium has always
/// stamped the per-boot ephemeral rotating nonce there. Routing this face through it makes the
/// doctrine hold on both paths, which is the argument for collapsing rather than syncing: a
/// behaviour that exists once cannot drift.
pub struct MonitorWifiFace {
    id: FaceId,
    /// Mirrored so [`Transport::send_mtu`] can answer without materialising the medium.
    mtu: std::sync::atomic::AtomicUsize,
    /// The medium being configured. `take`n when the face is first used or mounted.
    cfg: Mutex<Option<RadioMediumFace>>,
    /// The running medium, materialised on first use. Built lazily so the builder chain stays a
    /// plain `mut self -> Self` and no reader task is spawned for a face that is only configured.
    running: tokio::sync::OnceCell<crate::medium::RunningMedium>,
    /// The very gate the medium's reader uses — held here so `tier1_handle` / `tier1_dropped`
    /// answer about the live filter rather than a copy of its configuration.
    gate: Arc<NameGate>,
    /// The very rate policy the medium's bearer uses, for `select_mcs`.
    rate: Arc<RatePolicy>,
}

impl MonitorWifiFace {
    /// New monitor-mode face over `backend`, sized for fragmented NDN traffic
    /// (`MONITOR_MTU`) and injecting at the conservative default rate.
    pub fn new(id: FaceId, backend: Arc<dyn FrameIo>) -> Self {
        Self::over(
            id,
            backend,
            RadioCapability::wifi_monitor_5ghz(Vec::new()),
        )
    }

    /// **A face from the standardized opener** (#78/#83) — the capability-complete single-radio path.
    ///
    /// [`new`](Self::new) takes a bare `Arc<dyn FrameIo>`, which cannot be asked what it is, so it
    /// must invent a placeholder capability and drops the radio's knobs, clock and profile on the
    /// floor. That silently costs the scheduler its channel knob (`FaceScheduler` is built from
    /// `bearer.knobs`) and leaves the declared capability a guess. `open_named_radio` already
    /// returns all four handles; this carries them through.
    ///
    /// Capability is **discovered**, not asserted: it comes from the radio's own `RadioProfile` when
    /// it has one, falling back to `cap` otherwise. See [`RadioBearer::effective_cap`].
    pub fn from_open(id: FaceId, r: OpenRadio, cap: RadioCapability) -> Self {
        let rate = Arc::new(RatePolicy::new(McsPolicy::default()));
        let medium = RadioMediumFace::new(id, vec![RadioBearer::from_open(RadioId(0), r, cap)])
            .with_rate_policy(rate.clone());
        Self::wrap(id, medium, rate)
    }

    /// New face over `backend` declaring `cap` — what the one-radio constructors use when they know
    /// the radio's real profile (S1G channel list, dBm range) rather than a placeholder.
    fn over(id: FaceId, backend: Arc<dyn FrameIo>, cap: RadioCapability) -> Self {
        // A rate policy is installed from the start, unlike on a bare `RadioMediumFace`: this face's
        // contract has always been "inject at the conservative default rate", i.e. it *names* a rate
        // per frame rather than leaving whatever the driver holds. Handing the policy over at
        // construction is what preserves that through the collapse — without it the medium would
        // fall back to bearer-state rate and the face would silently stop naming one.
        let rate = Arc::new(RatePolicy::new(McsPolicy::default()));
        let medium = RadioMediumFace::new(id, vec![RadioBearer::new(RadioId(0), backend, cap)])
            .with_rate_policy(rate.clone());
        Self::wrap(id, medium, rate)
    }

    /// The common tail of every constructor: wrap a configured one-bearer medium.
    fn wrap(id: FaceId, medium: RadioMediumFace, rate: Arc<RatePolicy>) -> Self {
        Self {
            id,
            mtu: std::sync::atomic::AtomicUsize::new(MONITOR_MTU),
            cfg: Mutex::new(Some(medium)),
            running: tokio::sync::OnceCell::new(),
            gate: Arc::new(NameGate::open()),
            rate,
        }
    }

    /// Reconfigure the medium under construction. Panics if the face has already been used or
    /// mounted — a builder call after the reader task is running would silently do nothing, which is
    /// the class of quiet no-op this whole task has been about.
    fn map(self, f: impl FnOnce(RadioMediumFace) -> RadioMediumFace) -> Self {
        {
            let mut g = self.cfg.lock().unwrap();
            let cfg = g
                .take()
                .expect("MonitorWifiFace builder called after the face was used or mounted");
            *g = Some(f(cfg));
        }
        self
    }

    /// The running medium, built on first use.
    async fn running(&self) -> &crate::medium::RunningMedium {
        self.running
            .get_or_init(|| async {
                let cfg = self
                    .cfg
                    .lock()
                    .unwrap()
                    .take()
                    .expect("MonitorWifiFace used after being mounted");
                cfg.build()
            })
            .await
    }

    /// Build an **ESP-NOW** face over `backend` — the first-class NDN-over-ESP-NOW path. `backend`
    /// must be in [`FrameFormat::EspNow`] mode (e.g.
    /// `AfPacketBackend::new(iface, FrameFormat::EspNow { oui: ESPNOW_OUI })` on Linux, or use
    /// `open_libusb_espnow` on a host without a kernel monitor driver). Sized to the 250-B ESP-NOW
    /// body ([`ESPNOW_MTU`]) so the paired `LpLinkService` fragments NDN packets into vendor-action
    /// frames a stock `esp-wifi` peer hears; the broadcast addressing ESP-NOW requires is the
    /// default. Chainable with [`with_signal_sink`](Self::with_signal_sink),
    /// [`with_link_fec`](Self::with_link_fec), etc.
    pub fn espnow(id: FaceId, backend: Arc<dyn FrameIo>) -> Self {
        Self::new(id, backend).with_mtu(ESPNOW_MTU)
    }

    /// Open a **Wi-Fi HaLow (802.11ah / S1G)** monitor face on the kernel monitor interface `iface`
    /// — e.g. `"halow0"` (Newracom NRC7292) or `"mon0"` (Morse Micro MM6108). Drives **both** HaLow
    /// chips uniformly; the driver-side differences are invisible here.
    ///
    /// Sets [`FrameFormat::RawNdnS1g`], so injected frames carry the S1G radiotap header that names
    /// *no* 11n/ac MCS — the chip's own MAC picks the sub-GHz rate, so the same minimal radiotap
    /// suits both chips. Verified on-air, including cross-vendor: an NRC7292 received frames a
    /// second NRC7292 injected, and a Morse MM6108 injected NDN-over-HaLow frames that an NRC7292
    /// decoded on 904.5 MHz. Each chip needs a driver patch for monitor injection (see the
    /// minidronesys configs): NRC7292 forwards `IEEE80211_TX_CTL_INJECTED`; the MM6108 driver routes
    /// vif-less injected frames through its firmware monitor vif with a fixed S1G rate.
    ///
    /// The interface must already be in monitor mode on an S1G channel
    /// (`iw dev <iface> set type monitor; iw dev <iface> set channel 161`; for the MM6108 add the
    /// vif with `iw phy <phy> interface add mon0 type monitor`, per its NixOS
    /// `services.morseMonitor`) and the process needs `CAP_NET_RAW`. `channels` are the driver's
    /// fake channel numbers for the advertised capability (they differ per vendor; align on real
    /// frequency for interop).
    #[cfg(target_os = "linux")]
    pub fn halow(id: FaceId, iface: &str, channels: Vec<u8>) -> Result<Self, FaceError> {
        // 0x8624 = the NDN-over-Ethernet ethertype used across the stack; both ends must agree on it
        // (the RX parse validates the LLC/SNAP ethertype). Advertise absolute dBm power control when
        // this interface actually has it (Morse and Newracom S1G parts both expose a dBm knob), so a
        // control plane registering this capability decides power in link budget rather than in chip
        // index units. Absent on a radio where nothing was found.
        let mut cap = RadioCapability::wifi_halow_s1g(channels);
        if let Some(r) = crate::dbm_power::Mac80211Knobs::discover(iface).tx_power_range() {
            cap = cap.with_tx_power_dbm(r);
        }
        let backend = AfPacketBackend::new(iface, FrameFormat::RawNdnS1g { ethertype: 0x8624 })
            .map_err(FaceError::Io)?
            .with_capability(cap.clone());
        Ok(Self::over(id, Arc::new(backend), cap))
    }

    /// Open the RTL8812EU USB dongle, bring it up in 5 GHz monitor mode on `channel` (20 MHz), and
    /// build a named-radio face over it — the one-call path from a plugged-in dongle to a working
    /// face on a host without a kernel monitor driver (macOS, etc.). Pair with
    /// [`into_face`](Self::into_face) to mount it on the engine.
    #[cfg(feature = "libusb-backend")]
    pub fn open_libusb(id: FaceId, channel: u8) -> Result<Self, FaceError> {
        let backend = crate::LibUsbRtl88xxBackend::open_monitor(channel)?;
        Ok(Self::new(id, Arc::new(backend)))
    }

    /// Open the RTL8812EU USB dongle in 5 GHz monitor mode on `channel` and build an **ESP-NOW**
    /// face over it — the host side of NDN-over-ESP-NOW interop with an ESP32 on a host without a
    /// kernel monitor driver (macOS, etc.). Sets [`FrameFormat::EspNow`] (Espressif OUI) and the
    /// 250-B [`ESPNOW_MTU`]. For a **dual-band ESP32-C5** the dongle injects on a 5 GHz channel
    /// (e.g. 36 or 161) and the C5 listens there in `BandMode::_5G` — the path the 2.4 GHz-only
    /// ESP32-S3 could never close, since these wfb dongles only inject on 5 GHz. Inject at a basic
    /// rate the peer decodes: 6 Mbps OFDM on 5 GHz (`NDN_RADIO_TX_RATE=4`; 1 Mbps DSSS does not
    /// exist on 5 GHz).
    #[cfg(feature = "libusb-backend")]
    pub fn open_libusb_espnow(id: FaceId, channel: u8) -> Result<Self, FaceError> {
        let backend = crate::LibUsbRtl88xxBackend::open_monitor(channel)?
            .with_format(FrameFormat::EspNow { oui: ESPNOW_OUI });
        Ok(Self::espnow(id, Arc::new(backend)))
    }

    /// Enable **link-layer FEC**: outbound frames are grouped into generations of up to `k` (or a
    /// `window`), sent as `k + redundancy` coded frames — each its own MPDU (interleaved) — and the
    /// receiver recovers up to `redundancy` losses per generation with no ARQ. The broadcast
    /// reliability lever; reuses `ndn_coding`'s systematic codec. Mutually exclusive with A-MSDU
    /// batching (FEC wants one MPDU per frame so a lost MPDU costs ≤ `redundancy` of a generation;
    /// batching would bundle a whole generation into one MPDU). Both ends must enable FEC.
    pub fn with_link_fec(self, k: usize, redundancy: u16, window: Duration) -> Self {
        self.map(|m| {
            m.with_link_fec(
                k,
                window,
                Arc::new(std::sync::atomic::AtomicU16::new(redundancy)),
                Arc::new(crate::medium::LossMeter::default()),
            )
        })
    }

    /// Enable **link-layer A-MSDU bundling** on the send path — see
    /// [`RadioMediumFace::with_amsdu_batching`], which this now is.
    pub fn with_amsdu_batching(self, max_msdus: usize, window: Duration) -> Self {
        self.map(|m| m.with_amsdu_batching(max_msdus, window))
    }

    /// Set the TX name-addressing capability directly (compose with [`with_rx_filter`]).
    pub fn with_tx_addr(self, tx: TxAddr) -> Self {
        match tx {
            TxAddr::PrefixBloom { key } => self.map(|m| m.with_tx_bloom(key)),
            // Broadcast addressing with the doctrine §2 rotating nonce in the source field is the
            // medium's default, so there is nothing to configure.
            TxAddr::Broadcast => self,
        }
    }

    /// Set the RX name-filtering capability directly (compose with [`with_tx_addr`]).
    pub fn with_rx_filter(mut self, rx: RxFilter) -> Self {
        self.gate = Arc::new(NameGate::new(rx, self.gate.tier1()));
        let g = self.gate.clone();
        self.map(|m| m.with_rx_gate(g))
    }

    /// Mount a **Tier-1** table (#92) behind the Tier-0 gate: BF-FIB / BF-PIT / BF-CS consulted on
    /// the parsed name once Tier-0 admits a frame, registered on `prefixes` with `bits_each` bits
    /// per table and `k` hashes. Use [`tier1_handle`](Self::tier1_handle) to drive it from the
    /// forwarder's real PIT/CS — a Tier-1 whose tables drift from the forwarder's does not merely
    /// lose efficiency, a stale BF-PIT drops Data the node is waiting for.
    pub fn with_tier1(
        mut self,
        key: &GroupKey,
        prefixes: &[impl AsRef<[u8]>],
        bits_each: usize,
        k: u32,
    ) -> Self {
        let mut t = crate::tier1::Tier1::new(&key.0, bits_each, k);
        for p in prefixes {
            t.register_prefix(p.as_ref());
        }
        t.sync();
        self.gate = Arc::new(NameGate::new(
            self.gate.filter(),
            Some(Arc::new(std::sync::RwLock::new(t))),
        ));
        let g = self.gate.clone();
        self.map(|m| m.with_rx_gate(g))
    }

    /// The live Tier-1 handle, for the forwarder to drive from its real PIT/CS.
    pub fn tier1_handle(&self) -> Option<Arc<std::sync::RwLock<crate::tier1::Tier1>>> {
        self.gate.tier1()
    }

    /// Frames Tier-1 rejected — the tier's contribution, observable rather than assumed.
    pub fn tier1_dropped(&self) -> u64 {
        self.gate.dropped_tier1()
    }

    /// The rate the next frame would be injected at.
    #[cfg(test)]
    fn select_mcs(&self) -> McsDescriptor {
        self.rate.select()
    }

    /// Precompute the receiver's Tier-0 mask set for `prefixes`.
    fn bloom_masks(key: &GroupKey, prefixes: &[impl AsRef<[u8]>]) -> RxFilter {
        RxFilter::Bloom(crate::bloom_masks_for(key, prefixes))
    }

    /// **Tier-0 producer** (#91): address every outgoing object by its name's prefix-set filter, and
    /// accept inbound frames whose filter could be under `routable_prefix`.
    pub fn with_bloom_producer(self, key: &GroupKey, routable_prefix: impl AsRef<[u8]>) -> Self {
        let rx = Self::bloom_masks(key, &[routable_prefix.as_ref()]);
        self.with_tx_addr(TxAddr::PrefixBloom { key: *key })
            .with_rx_filter(rx)
    }

    /// **Tier-0 relay** (#91): RX keeps any frame whose in-frame filter could be under one of
    /// `prefixes` — the aggregation win, expressed as longest-prefix match rather than a single
    /// fixed-granularity hash. TX is left as configured.
    pub fn with_bloom_relay(self, key: &GroupKey, prefixes: &[impl AsRef<[u8]>]) -> Self {
        let rx = Self::bloom_masks(key, prefixes);
        self.with_rx_filter(rx)
    }

    /// **Tier-0 consumer** (#91): accept only frames whose filter could be under `prefix`.
    pub fn with_bloom_consumer(self, key: &GroupKey, prefix: impl AsRef<[u8]>) -> Self {
        let rx = Self::bloom_masks(key, &[prefix.as_ref()]);
        self.with_rx_filter(rx)
    }

    /// Inject at a fixed rate.
    pub fn with_fixed_mcs(mut self, mcs: McsDescriptor) -> Self {
        self.rate = Arc::new(RatePolicy::new(McsPolicy::Fixed(mcs)));
        let r = self.rate.clone();
        self.map(|m| m.with_rate_policy(r))
    }

    /// Pick the rate from the most recently observed RSSI.
    pub fn with_adaptive_mcs(mut self) -> Self {
        self.rate = Arc::new(RatePolicy::new(McsPolicy::Adaptive));
        let r = self.rate.clone();
        self.map(|m| m.with_rate_policy(r))
    }

    /// Override the injected-frame payload budget (defaults to [`MONITOR_MTU`]).
    pub fn with_mtu(self, mtu: usize) -> Self {
        self.mtu.store(mtu, Ordering::Relaxed);
        self.map(|m| m.with_mtu(mtu))
    }

    /// Publish each captured frame's RSSI/rate to `sink`, keyed by this face id, so the cognitive
    /// control loop's `SignalView` sees live per-radio link quality.
    pub fn with_signal_sink(self, sink: Arc<dyn SignalStore<FaceId> + Send + Sync>) -> Self {
        self.map(|m| m.with_signal_sink(sink))
    }

    /// Bind the control plane's decided [`TxParams`] — the ACT half of the closed loop. `select_mcs`
    /// reads the cell, so the decided rate/coding actually changes what we transmit.
    pub fn with_planned_params(mut self, cell: Arc<RwLock<Option<TxParams>>>) -> Self {
        self.rate = Arc::new(RatePolicy::new(McsPolicy::default()).with_planned(cell));
        let r = self.rate.clone();
        self.map(|m| m.with_rate_policy(r))
    }

    /// Build a [`Face`] pairing this face's transport with the engine's `LpLinkService`, so NDN
    /// packets fragment/reassemble across injected frames.
    pub fn into_face(self) -> Face {
        let cfg = self
            .cfg
            .lock()
            .unwrap()
            .take()
            .expect("MonitorWifiFace mounted twice");
        cfg.into_face()
    }
}

impl Transport for MonitorWifiFace {
    fn id(&self) -> FaceId {
        self.id
    }

    fn kind(&self) -> FaceKind {
        // The Wfb kind: a wire kind (LP framing on), NonLocal scope.
        // `link_type() == AdHoc` distinguishes the connectionless injection bearer.
        FaceKind::Wfb
    }

    fn remote_uri(&self) -> Option<String> {
        Some("radio://broadcast".into())
    }

    fn link_type(&self) -> LinkType {
        LinkType::AdHoc
    }

    fn send_mtu(&self) -> Option<usize> {
        Some(self.mtu.load(Ordering::Relaxed))
    }

    async fn send_bytes(&self, wire: Bytes) -> Result<(), FaceError> {
        self.running().await.send_bytes(wire).await
    }

    async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
        self.running().await.recv_bytes().await
    }

    async fn recv_bytes_with_addr(&self) -> Result<(Bytes, Option<FaceAddr>), FaceError> {
        self.running().await.recv_bytes_with_addr().await
    }

    fn set_send_mtu(&self, _mtu: Option<u64>) -> Result<Option<u64>, MtuError> {
        Err(MtuError::NotSupported)
    }

    fn set_persistency(&self, _persistency: FacePersistency) -> Result<(), PersistencyError> {
        Err(PersistencyError::NotSupported)
    }
}

/// Milliseconds since first call — a cheap monotonic clock for nonce rotation and signal
/// timestamps, with no wall-clock dependency.
fn now_ms() -> u32 {
    use std::sync::OnceLock;
    use std::time::Instant;
    static BASE: OnceLock<Instant> = OnceLock::new();
    BASE.get_or_init(Instant::now).elapsed().as_millis() as u32
}

#[cfg(test)]
mod tests {
    use ndn_signals_core::LinkSignals;

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
            singles: portable_atomic::AtomicU64,
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
            singles: portable_atomic::AtomicU64::new(0),
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
            let mut w = [0u8; 16];
            w[..6].copy_from_slice(a1);
            w[6..12].copy_from_slice(a2);
            let f = crate::PrefixFilter::from_wire(w);
            assert!(
                masks.iter().any(|m| f.may_match(m)),
                "coded frame {i} must still be addressed under /x — a receiver registered on /x \
                 reassembles addr1‖addr2 and drops it otherwise (addr1={a1:02x?} addr2={a2:02x?})"
            );
        }
    }

    /// **The Tier-0 fragment cache must not grow without bound.** The original was a `HashMap` that
    /// only ever gained entries — one per fragmented object, never removed. A relay forwarding
    /// fragmented objects indefinitely leaked one entry per object, quietly and forever.
    ///
    /// Completing an object releases its entry, and a peer that vanishes mid-object cannot push the
    /// map past its cap. Both matter: the first is the common path, the second is the one an
    /// adversary or a flaky link would otherwise exploit.
    #[test]
    fn tier0_fragment_cache_is_bounded() {
        fn tlv(t: u8, v: &[u8]) -> Vec<u8> {
            let mut o = vec![t, v.len() as u8];
            o.extend_from_slice(v);
            o
        }
        fn frag(seq: u64, index: u64, count: u64, payload: &[u8]) -> Vec<u8> {
            let mut inner = Vec::new();
            inner.extend(tlv(0x51, &seq.to_be_bytes()));
            inner.extend(tlv(0x52, &index.to_be_bytes()));
            inner.extend(tlv(0x53, &count.to_be_bytes()));
            inner.extend(tlv(0x50, payload));
            let mut out = vec![0x64, inner.len() as u8];
            out.extend_from_slice(&inner);
            out
        }

        let a = Tier0Addresser::new(OPEN_GROUP_KEY);
        let named = data_pkt(&name_tlv(&[b"x", b"y"]));

        // A complete 3-fragment object: tracked while in flight, released on the last fragment.
        let opening = a.wire_for(&frag(10, 0, 3, &named));
        assert!(opening.is_some(), "the opening fragment carries the name");
        assert_eq!(a.tracked(), 1, "the object is tracked while its tail is outstanding");
        assert_eq!(a.wire_for(&frag(11, 1, 3, b"mid")), opening, "mid fragment reuses the filter");
        assert_eq!(a.wire_for(&frag(12, 2, 3, b"end")), opening, "last fragment reuses it too");
        assert_eq!(a.tracked(), 0, "completing the object must release its entry");

        // Objects whose tails never arrive: bounded by the cap, not by the peer's good behaviour.
        for i in 0..(TIER0_CACHE_CAP + 500) {
            let seq = 1_000_000 + (i as u64) * 10;
            let _ = a.wire_for(&frag(seq, 0, 9, &named));
        }
        assert!(
            a.tracked() <= TIER0_CACHE_CAP,
            "abandoned objects must stay under the cap, got {}",
            a.tracked()
        );
    }
}
