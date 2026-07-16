//! The sans-I/O NAN state machine (Phase 1 MVP).
//!
//! [`NanEngine`] is a pure function of (time, inbound frames) → (outbound
//! frames, channel, events, next-wake). It owns **no** sockets, async, or clock:
//! a platform driver (`ndn-nan` over `FrameIo` + tokio on desktop; embassy on an
//! MCU) calls [`poll`](NanEngine::poll) on a timer and whenever a frame is
//! captured, injects the returned frames, and re-arms its timer at `wake_at`.
//! That keeps the timing-critical, interop-critical logic deterministically
//! testable (fake clock + synthetic frames → exact output bytes).
//!
//! ## Scope
//!
//! Discovery + coordination with a stock Wi-Fi Aware device: a 512/16-TU
//! Discovery-Window clock; software-TSF sync to received beacons (one-shot jam to
//! a higher-ranked cluster); per-DW emission of a sync beacon (Master Indication +
//! Cluster) plus a Service Discovery Frame carrying our active publish/subscribe
//! Service Descriptors; service-ID matching of received SDAs; and unicast
//! follow-up send/receive.
//!
//! Plus the **data path**: the M1-M4 NDP handshake ([`NanEngine::request_ndp`] ->
//! [`NanEvent::NdpEstablished`]), which negotiates each side's NAN Data Interface
//! and IPv6 interface identifier over NAFs. The engine settles *which* addresses a
//! data path uses; binding a socket to them is the driver's job (and needs an NDI
//! virtual interface, which does not exist yet).
//!
//! Full master/anchor election role transitions and multi-channel DWs land in a
//! later phase - the structure here grows into them.

use alloc::boxed::Box;
use alloc::collections::{BTreeSet, VecDeque};
use alloc::vec::Vec;

use crate::attr::{
    AttributeId, Cluster, DeviceCapability, MasterIndication, Ndpe, NdpStatus, NdpType, Sdea,
    ServiceControlType, ServiceDescriptor, ServiceIdList,
};
use crate::frame::{FrameType, NafSubtype, NanActionFrame, NanBeacon, ServiceDiscoveryFrame, classify};
use crate::rendezvous::{DiscoveryWindow, Rendezvous};
use crate::service::service_id;
use crate::{BROADCAST, NAN_CLUSTER_ID_BASE, NAN_NETWORK_ID, SYNC_BEACON_INTERVAL_TU, ServiceId};

/// Microseconds — the engine's time unit (a free-running monotonic clock the
/// driver supplies; only differences matter).
pub type Usec = u64;

/// Static configuration for a NAN node.
#[derive(Clone, Debug)]
pub struct NanConfig {
    /// Our NAN management-interface MAC (the addr2 of every frame we send). NMIs
    /// rotate for privacy in a full stack; here it's a stable local identifier.
    pub nmi: [u8; 6],
    /// Master preference (0–255). Higher wins election; the MVP advertises this
    /// but does not run role transitions.
    pub master_preference: u8,
    /// Random factor (0–255), the election tiebreak below preference.
    pub random_factor: u8,
    /// The 2.4/5 GHz discovery channel to park on (MVP: a single channel, e.g. 6).
    pub channel: u8,
    /// Our NAN Data Interface MAC — the address the **data path** uses, as
    /// opposed to the NMI that carries discovery. A real stack gives the NDI its
    /// own MAC (and rotates it); [`new`](Self::new) defaults it to the NMI, which
    /// is honest for a single-interface node. Its EUI-64 becomes the IPv6
    /// interface identifier we advertise in NDPE — see [`eui64_iid`].
    pub ndi: [u8; 6],
    /// Accept incoming data-path requests automatically (open NDP). Set false to
    /// reject every request — a node that publishes but serves no data path.
    pub ndp_auto_accept: bool,
}

impl NanConfig {
    /// A node on `channel` identified by `nmi`, advertising master preference
    /// `pref`.
    pub fn new(nmi: [u8; 6], channel: u8, pref: u8) -> Self {
        Self {
            nmi,
            master_preference: pref,
            random_factor: 0,
            channel,
            ndi: nmi,
            ndp_auto_accept: true,
        }
    }

    /// Give the data path its own interface MAC, distinct from the NMI.
    pub fn with_ndi(mut self, ndi: [u8; 6]) -> Self {
        self.ndi = ndi;
        self
    }
}

/// The modified EUI-64 interface identifier of a MAC — the low 64 bits of the
/// IPv6 link-local address `fe80::<iid>` that a NAN data interface answers on.
///
/// Insert `ff:fe` in the middle and flip the universal/local bit, per RFC 4291.
/// This is what makes NDPE self-sufficient: the peer derives our address from
/// the identifier we advertise, with no out-of-band exchange.
pub fn eui64_iid(mac: [u8; 6]) -> [u8; 8] {
    [
        mac[0] ^ 0x02,
        mac[1],
        mac[2],
        0xff,
        0xfe,
        mac[3],
        mac[4],
        mac[5],
    ]
}

/// One captured frame handed to [`poll`](NanEngine::poll).
#[derive(Clone, Copy, Debug)]
pub struct RxFrame<'a> {
    /// The full 802.11 frame (from the management header onward), as recovered
    /// by the radio backend.
    pub bytes: &'a [u8],
    /// Per-frame RSSI, if the backend measured it.
    pub rssi_dbm: Option<i8>,
    /// The driver's capture timestamp (same clock domain as `poll`'s `now`).
    pub now_usec: Usec,
}

/// One frame the driver must inject (the complete 802.11 frame; the backend
/// prepends radiotap / its TX descriptor).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxFrame {
    pub bytes: Vec<u8>,
}

/// Something the engine surfaces to the driver / NDN layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NanEvent {
    /// A peer was seen advertising a service we publish or subscribe.
    Discovered {
        service: ServiceId,
        peer: [u8; 6],
        /// The peer's service-specific info, if any.
        ssi: Vec<u8>,
        rssi_dbm: Option<i8>,
    },
    /// A follow-up message addressed to us arrived (the coordination receive).
    Followup {
        peer: [u8; 6],
        ssi: Vec<u8>,
        rssi_dbm: Option<i8>,
    },
    /// A data path is up: the M1–M4 exchange completed. The driver can now bind a
    /// socket to our NDI and reach the peer at `fe80::<peer_iid>` — everything
    /// needed to carry bulk traffic is here, with no out-of-band exchange.
    NdpEstablished {
        /// The peer's NMI (the discovery identity that negotiated the path).
        peer: [u8; 6],
        ndp_id: u8,
        role: NdpRole,
        /// The peer's data-interface MAC.
        peer_ndi: [u8; 6],
        /// The peer's IPv6 interface identifier — `fe80::<peer_iid>` addresses it.
        peer_iid: [u8; 8],
    },
    /// A data path could not be set up: rejected by the peer, or unanswered.
    NdpFailed {
        peer: [u8; 6],
        ndp_id: u8,
        reason: NdpFailure,
    },
    /// An established data path was torn down.
    NdpTerminated { peer: [u8; 6], ndp_id: u8 },
}

/// Why a data path did not come up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NdpFailure {
    /// The peer answered with status Rejected.
    Rejected { reason_code: u8 },
    /// The peer never answered within [`NDP_MAX_ATTEMPTS`] requests.
    TimedOut,
}

/// Which side of a data-path exchange we are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NdpRole {
    /// We sent M1 — we asked for the path.
    Initiator,
    /// We answered someone else's M1.
    Responder,
}

/// How far along a data-path handshake is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NdpState {
    /// Initiator: M1 sent, waiting for M2.
    AwaitingResponse,
    /// Responder: M2 sent, waiting for M3.
    AwaitingConfirm,
    /// The path is up.
    Established,
}

/// How long to wait for a data-path reply before re-sending. Two Discovery
/// Windows: a peer only listens during its DW, so a shorter timer would just
/// retransmit into a sleeping radio.
pub const NDP_RETRY_USEC: Usec = 2 * 512 * 1024;

/// How many times the initiator sends M1 before giving up.
pub const NDP_MAX_ATTEMPTS: u8 = 4;

/// One in-flight or established data path.
#[derive(Clone, Debug)]
struct NdpSession {
    /// The peer's NMI — data-path NAFs are addressed to the discovery identity,
    /// while the NDIs inside the NDPE name the data interfaces.
    peer: [u8; 6],
    ndp_id: u8,
    dialog_token: u8,
    role: NdpRole,
    state: NdpState,
    peer_ndi: Option<[u8; 6]>,
    peer_iid: Option<[u8; 8]>,
    /// The NAF subtype we owe the peer on the next transmit window, if any.
    pending_tx: Option<NafSubtype>,
    /// M1 sends so far (initiator only).
    attempts: u8,
    /// When to re-send M1 if M2 hasn't arrived.
    retry_at_usec: Usec,
}

/// The result of one [`poll`](NanEngine::poll): frames to send, an optional
/// channel change, events to surface, and when to wake next.
#[derive(Clone, Debug, Default)]
pub struct Step {
    pub tx: Vec<TxFrame>,
    pub set_channel: Option<u8>,
    pub events: Vec<NanEvent>,
    /// Absolute time (same clock as `now`) at which the driver should next call
    /// `poll` even if no frame arrives.
    pub wake_at_usec: Usec,
}

/// What a registered service function is (the local half of a publish/subscribe).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FunctionKind {
    Publish,
    Subscribe,
}

#[derive(Clone, Debug)]
struct Function {
    service_id: ServiceId,
    instance_id: u8,
    kind: FunctionKind,
    ssi: Vec<u8>,
    /// Subscribe: active (transmits a subscribe SDF) vs passive (listen-only).
    /// Publish: ignored.
    active: bool,
}

/// A queued outbound follow-up (a connectionless coordination message).
#[derive(Clone, Debug)]
struct Followup {
    dest: [u8; 6],
    /// Our function instance the follow-up originates from.
    instance_id: u8,
    /// The peer function instance it is directed at (0 if unknown).
    requestor_instance_id: u8,
    service_id: ServiceId,
    ssi: Vec<u8>,
}

/// Compute the 64-bit NAN master rank exactly as opennan packs it (a
/// little-endian union of `{ mac[6], random_factor, master_preference }`): as a
/// `u64`, preference is the most-significant byte, then the random factor, then
/// the MAC with `mac[0]` least-significant. `>` therefore orders by preference,
/// then random factor, then MAC — the spec ordering.
pub fn master_rank(master_preference: u8, random_factor: u8, mac: [u8; 6]) -> u64 {
    let mut v = 0u64;
    for (i, &b) in mac.iter().enumerate() {
        v |= (b as u64) << (8 * i);
    }
    v |= (random_factor as u64) << 48;
    v |= (master_preference as u64) << 56;
    v
}

/// The sans-I/O NAN protocol engine.
pub struct NanEngine {
    cfg: NanConfig,
    cluster_id: [u8; 6],
    /// Software-TSF origin: `synced_time = now - base_time_usec`.
    base_time_usec: Usec,
    /// True once we've synced our clock to a (higher-ranked) cluster beacon.
    synced: bool,
    /// 802.11 sequence-number counter.
    seq: u16,
    next_instance_id: u8,
    functions: Vec<Function>,
    /// Discovered (peer, service) pairs already surfaced, so each fires once.
    discovered: BTreeSet<([u8; 6], ServiceId)>,
    /// Peers we may follow-up to (learned from any matched SDA): peer → their
    /// advertised instance id for the matched service.
    peers: Vec<([u8; 6], u8)>,
    followups: VecDeque<Followup>,
    /// The DW index we last emitted a beacon/SDF in (one burst per DW).
    last_burst_dw: Option<u64>,
    /// Whether the driver has been told to tune the channel yet.
    channel_set: bool,
    base_initialized: bool,
    /// Anchor-master rank of the cluster we currently follow — our DW timeline is
    /// aligned to this anchor. Starts as our own rank (we're our own anchor) and
    /// rises when we join a higher-graded cluster (NAN cluster merge: the cluster
    /// with the greater anchor-master rank wins; lower-graded members adopt its id
    /// + TSF). This is what makes our SDFs land in a peer's Discovery Window.
    cluster_amr: u64,
    /// The wake / transmit schedule (medium-access mode). Defaults to the NAN
    /// [`DiscoveryWindow`]; swap it for an always-on or TSCH schedule via
    /// [`with_rendezvous`](NanEngine::with_rendezvous). The engine's timing is
    /// neutral — this strategy owns "when."
    rendezvous: Box<dyn Rendezvous>,
    /// In-flight and established data paths, keyed by (peer NMI, ndp id).
    ndps: Vec<NdpSession>,
    /// Next data-path id to hand out (ids are per-initiator, so ours need only be
    /// unique among the paths *we* start).
    next_ndp_id: u8,
    next_dialog_token: u8,
}

impl NanEngine {
    /// A new engine in its own cluster (until it merges into a higher-graded one).
    pub fn new(cfg: NanConfig) -> Self {
        let own_rank = master_rank(cfg.master_preference, cfg.random_factor, cfg.nmi);
        Self {
            cfg,
            cluster_id: NAN_CLUSTER_ID_BASE,
            base_time_usec: 0,
            synced: false,
            seq: 0,
            next_instance_id: 1,
            functions: Vec::new(),
            discovered: BTreeSet::new(),
            peers: Vec::new(),
            followups: VecDeque::new(),
            last_burst_dw: None,
            channel_set: false,
            base_initialized: false,
            cluster_amr: own_rank,
            rendezvous: Box::new(DiscoveryWindow),
            ndps: Vec::new(),
            next_ndp_id: 1,
            next_dialog_token: 1,
        }
    }

    /// A new engine using an explicit rendezvous (medium-access) schedule instead
    /// of the default [`DiscoveryWindow`] — e.g. [`AlwaysOn`](crate::AlwaysOn) for
    /// a mains-powered / SDR relay that never sleeps.
    pub fn with_rendezvous(cfg: NanConfig, rendezvous: Box<dyn Rendezvous>) -> Self {
        let mut engine = Self::new(cfg);
        engine.rendezvous = rendezvous;
        engine
    }

    /// Our NMI.
    pub fn nmi(&self) -> [u8; 6] {
        self.cfg.nmi
    }

    /// Our current master rank (preference, random factor, NMI).
    pub fn rank(&self) -> u64 {
        master_rank(
            self.cfg.master_preference,
            self.cfg.random_factor,
            self.cfg.nmi,
        )
    }

    /// Publish a service by name. Returns the assigned instance id.
    pub fn publish(&mut self, name: &str, ssi: impl Into<Vec<u8>>) -> u8 {
        self.add_function(service_id(name), FunctionKind::Publish, ssi.into(), false)
    }

    /// Subscribe to a service by name (`active` transmits a subscribe SDF;
    /// passive listens only). Returns the assigned instance id.
    pub fn subscribe(&mut self, name: &str, active: bool) -> u8 {
        self.add_function(
            service_id(name),
            FunctionKind::Subscribe,
            Vec::new(),
            active,
        )
    }

    fn add_function(
        &mut self,
        service_id: ServiceId,
        kind: FunctionKind,
        ssi: Vec<u8>,
        active: bool,
    ) -> u8 {
        let instance_id = self.next_instance_id;
        self.next_instance_id = self.next_instance_id.wrapping_add(1).max(1);
        self.functions.push(Function {
            service_id,
            instance_id,
            kind,
            ssi,
            active,
        });
        // Re-burst in the current Discovery Window so a freshly registered
        // function is advertised on the next poll, not a full DW (~524 ms) later.
        self.last_burst_dw = None;
        instance_id
    }

    /// Queue a follow-up message carrying `ssi` to every currently-matched peer
    /// — the connectionless coordination "broadcast". Returns how many peers it
    /// was queued for (0 if none are matched yet).
    pub fn broadcast_followup(&mut self, ssi: impl Into<Vec<u8>>) -> usize {
        let ssi = ssi.into();
        // Originate from our first function (the coordination service handle).
        let instance_id = self.functions.first().map(|f| f.instance_id).unwrap_or(0);
        let service = self
            .functions
            .first()
            .map(|f| f.service_id)
            .unwrap_or([0; 6]);
        let peers: Vec<_> = self.peers.clone();
        for (peer, their_inst) in &peers {
            self.followups.push_back(Followup {
                dest: *peer,
                instance_id,
                requestor_instance_id: *their_inst,
                service_id: service,
                ssi: ssi.clone(),
            });
        }
        peers.len()
    }

    /// Ask `peer` (by NMI) for a data path — the M1 of the M1–M4 exchange.
    ///
    /// Returns the data-path id identifying this exchange; the outcome arrives as
    /// [`NanEvent::NdpEstablished`] or [`NanEvent::NdpFailed`]. The request rides
    /// the next transmit window, because that is when the peer is listening.
    ///
    /// A second request to a peer we already have a path to returns the existing
    /// id rather than starting a duplicate negotiation.
    pub fn request_ndp(&mut self, peer: [u8; 6]) -> u8 {
        if let Some(s) = self
            .ndps
            .iter()
            .find(|s| s.peer == peer && s.role == NdpRole::Initiator)
        {
            return s.ndp_id;
        }
        let ndp_id = self.next_ndp_id;
        self.next_ndp_id = self.next_ndp_id.wrapping_add(1).max(1);
        let dialog_token = self.next_dialog_token;
        self.next_dialog_token = self.next_dialog_token.wrapping_add(1).max(1);
        self.ndps.push(NdpSession {
            peer,
            ndp_id,
            dialog_token,
            role: NdpRole::Initiator,
            state: NdpState::AwaitingResponse,
            peer_ndi: None,
            peer_iid: None,
            pending_tx: Some(NafSubtype::DataPathRequest),
            attempts: 0,
            retry_at_usec: 0,
        });
        ndp_id
    }

    /// Tear down a data path, telling the peer.
    pub fn terminate_ndp(&mut self, peer: [u8; 6], ndp_id: u8) {
        if let Some(s) = self
            .ndps
            .iter_mut()
            .find(|s| s.peer == peer && s.ndp_id == ndp_id)
        {
            s.pending_tx = Some(NafSubtype::DataPathTermination);
            s.state = NdpState::Established; // stop retrying; the frame still goes out
        }
    }

    /// The cluster we are currently a member of. A data path's frames carry this
    /// as their BSSID: the path lives inside the cluster whose timeline it was
    /// negotiated on, and a merge moves it.
    pub fn cluster_id(&self) -> [u8; 6] {
        self.cluster_id
    }

    /// Our data-interface MAC and its IPv6 interface identifier — what a peer
    /// will address us by once a path is up.
    pub fn local_ndp_identity(&self) -> ([u8; 6], [u8; 8]) {
        (self.cfg.ndi, eui64_iid(self.cfg.ndi))
    }

    /// Number of data paths currently established.
    pub fn established_ndps(&self) -> usize {
        self.ndps
            .iter()
            .filter(|s| s.state == NdpState::Established)
            .count()
    }

    /// Synced software TSF (microseconds since this cluster's epoch).
    fn synced_usec(&self, now: Usec) -> Usec {
        now.wrapping_sub(self.base_time_usec)
    }

    /// The current transmit-window index — one burst per window. Delegates to the
    /// [`rendezvous`](crate::rendezvous) schedule (a Discovery-Window index by
    /// default) over the synced clock.
    fn dw_index(&self, now: Usec) -> u64 {
        self.rendezvous.window_index(self.synced_usec(now))
    }

    /// Whether `now` falls within a transmit / listen window (a Discovery Window
    /// by default), per the rendezvous schedule.
    fn in_dw(&self, now: Usec) -> bool {
        self.rendezvous.in_window(self.synced_usec(now))
    }

    /// Absolute (now-domain) usec of the next window start after `now`. The
    /// rendezvous returns the next start in the synced domain; adding
    /// `base_time_usec` maps it back to `now`'s domain. All arithmetic is modular
    /// (mod 2^64), like the 802.11 TSF it tracks: after a cluster merge
    /// `base_time_usec` is `now - anchor_tsf`, so the wrapping is correct and the
    /// result lands back in `now`'s domain.
    fn next_dw_start_usec(&self, now: Usec) -> Usec {
        self.base_time_usec
            .wrapping_add(self.rendezvous.next_window_start(self.synced_usec(now)))
    }

    /// The main entry point. See the module docs.
    pub fn poll(&mut self, now: Usec, inbound: &[RxFrame]) -> Step {
        if !self.base_initialized {
            // Form our own cluster anchored at the first observation.
            self.base_time_usec = now;
            self.base_initialized = true;
        }
        let mut step = Step::default();
        if !self.channel_set {
            step.set_channel = Some(self.cfg.channel);
            self.channel_set = true;
        }

        for rx in inbound {
            self.handle_rx(*rx, &mut step);
        }

        // One transmit burst per Discovery Window: a sync beacon + an SDF
        // carrying our active functions, then any queued follow-ups.
        if self.in_dw(now) {
            let dw = self.dw_index(now);
            if self.last_burst_dw != Some(dw) {
                self.last_burst_dw = Some(dw);
                self.emit_beacon(now, &mut step);
                self.emit_discovery(&mut step);
            }
            // Follow-ups also ride the DW (the peer is only listening then).
            self.emit_followups(&mut step);
            // Data-path setup likewise: an M2 answering an M1 that arrived in this
            // same window goes out while the initiator is still awake.
            self.emit_ndp(now, &mut step);
        }

        step.wake_at_usec = self.next_dw_start_usec(now);
        step
    }

    fn handle_rx(&mut self, rx: RxFrame, step: &mut Step) {
        let Ok(frame) = classify(rx.bytes) else {
            return;
        };
        // Never react to our own transmissions (a real radio is half-duplex;
        // loopback echoes, so guard here too).
        if frame.header.addr2 == self.cfg.nmi {
            return;
        }
        match frame.kind {
            FrameType::Beacon => self.handle_beacon(rx),
            FrameType::Action => self.handle_sdf(rx, frame.attributes, step),
            FrameType::Naf { subtype } => {
                self.handle_naf(rx, subtype, frame.attributes, step);
            }
            FrameType::Other => {}
        }
    }

    fn handle_beacon(&mut self, rx: RxFrame) {
        let Ok((beacon, attrs)) = NanBeacon::parse(rx.bytes) else {
            return;
        };
        // The cluster's anchor-master rank: prefer the Cluster attribute's
        // `anchor_master_rank` (what the whole cluster is graded by); fall back to
        // the transmitter's own Master Indication when absent.
        let beacon_amr = crate::attr::Attributes::find(attrs, AttributeId::Cluster)
            .and_then(|a| Cluster::decode(a.body).ok())
            .map(|c| c.anchor_master_rank)
            .or_else(|| {
                crate::attr::Attributes::find(attrs, AttributeId::MasterIndication)
                    .and_then(|a| MasterIndication::decode(a.body).ok())
                    .map(|mi| {
                        master_rank(mi.master_preference, mi.random_factor, beacon.header.addr2)
                    })
            });
        let Some(beacon_amr) = beacon_amr else {
            return;
        };
        // NAN cluster merge: if the heard cluster outgrades the one we follow,
        // join it — adopt its cluster id and align our software TSF so our synced
        // clock reads the anchor's beacon timestamp now (one-shot jam). This is
        // what aligns our Discovery Windows to a higher-graded peer (e.g. a phone
        // we want to reach) so our SDFs land in *its* DW.
        if beacon_amr > self.cluster_amr {
            self.cluster_id = beacon.header.addr3;
            self.base_time_usec = rx.now_usec.wrapping_sub(beacon.timestamp);
            self.cluster_amr = beacon_amr;
            self.synced = true;
            self.last_burst_dw = None; // re-burst in the now-aligned DW
        } else if beacon.header.addr3 == self.cluster_id && beacon_amr == self.cluster_amr {
            // Same cluster, same anchor — re-sync TSF to track drift.
            self.base_time_usec = rx.now_usec.wrapping_sub(beacon.timestamp);
        }
    }

    fn handle_sdf(&mut self, rx: RxFrame, attrs: &[u8], step: &mut Step) {
        let to_us = rx_addr1(rx.bytes) == Some(self.cfg.nmi);
        for attr in crate::attr::Attributes::new(attrs).flatten() {
            if !attr.is(AttributeId::ServiceDescriptor) {
                continue;
            }
            let Ok(sda) = ServiceDescriptor::decode(attr.body) else {
                continue;
            };
            let peer = rx_addr2(rx.bytes);
            match sda.control.control_type {
                // A peer advertising a service. If we have a function for that
                // service, record the peer and surface a discovery.
                ServiceControlType::Publish | ServiceControlType::Subscribe => {
                    if self.has_function_for(sda.service_id) {
                        self.note_peer(peer, sda.instance_id);
                        if self.discovered.insert((peer, sda.service_id)) {
                            step.events.push(NanEvent::Discovered {
                                service: sda.service_id,
                                peer,
                                ssi: sda.service_info.clone(),
                                rssi_dbm: rx.rssi_dbm,
                            });
                        }
                    }
                }
                // A follow-up directed at us → deliver it.
                ServiceControlType::FollowUp => {
                    if to_us && self.has_function_for(sda.service_id) {
                        step.events.push(NanEvent::Followup {
                            peer,
                            ssi: sda.service_info.clone(),
                            rssi_dbm: rx.rssi_dbm,
                        });
                    }
                }
            }
        }
    }

    fn has_function_for(&self, sid: ServiceId) -> bool {
        self.functions.iter().any(|f| f.service_id == sid)
    }

    fn note_peer(&mut self, peer: [u8; 6], their_instance: u8) {
        if let Some(e) = self.peers.iter_mut().find(|(p, _)| *p == peer) {
            e.1 = their_instance;
        } else {
            self.peers.push((peer, their_instance));
        }
    }

    fn next_seq(&mut self) -> u16 {
        let s = self.seq;
        self.seq = self.seq.wrapping_add(1) & 0x0FFF;
        s
    }

    fn emit_beacon(&mut self, now: Usec, step: &mut Step) {
        let timestamp = self.synced_usec(now);
        let seq = self.next_seq();
        let beacon = NanBeacon::new(
            BROADCAST,
            self.cfg.nmi,
            self.cluster_id,
            seq,
            timestamp,
            SYNC_BEACON_INTERVAL_TU as u16,
        );
        let mut attrs = Vec::new();
        MasterIndication {
            master_preference: self.cfg.master_preference,
            random_factor: self.cfg.random_factor,
        }
        .encode(&mut attrs);
        Cluster {
            // Propagate the rank of the anchor master we follow (ourselves until
            // we merge into a higher-graded cluster), so peers grade our cluster
            // consistently and converge on one timeline.
            anchor_master_rank: self.cluster_amr,
            hop_count: 0,
            ambtt: timestamp as u32,
        }
        .encode(&mut attrs);
        // Advertise what we publish / subscribe, as a stock device does in its
        // beacons, so a peer learns our services without first hearing an SDF.
        let pub_ids: Vec<_> = self
            .functions
            .iter()
            .filter(|f| f.kind == FunctionKind::Publish)
            .map(|f| f.service_id)
            .collect();
        let sub_ids: Vec<_> = self
            .functions
            .iter()
            .filter(|f| f.kind == FunctionKind::Subscribe)
            .map(|f| f.service_id)
            .collect();
        if !pub_ids.is_empty() {
            ServiceIdList::new(pub_ids).encode_publish(&mut attrs);
        }
        if !sub_ids.is_empty() {
            ServiceIdList::new(sub_ids).encode_subscribe(&mut attrs);
        }
        step.tx.push(TxFrame {
            bytes: beacon.encode(&attrs),
        });
    }

    fn emit_discovery(&mut self, step: &mut Step) {
        // First decide whether there's anything to advertise, so an empty node
        // emits no SDF (and we don't prepend Device Capability for nothing).
        let advertises = self
            .functions
            .iter()
            .any(|f| f.kind == FunctionKind::Publish || f.active);
        if !advertises {
            return;
        }

        // SDF attribute order mirrors a stock device's: Device Capability + NAN
        // Availability describe our scheduling, then a Service Descriptor (+SDEA)
        // per advertised function — what makes a strict firmware accept the SDF.
        let mut attrs = Vec::new();
        DeviceCapability::basic().encode(&mut attrs);
        // NAN Availability — a stock NAN-2.0 subscriber (S23 ndn-ripple) won't
        // surface a publisher whose SDF advertises no availability schedule.
        crate::attr::encode_availability(&mut attrs);
        for f in &self.functions {
            let control_type = match f.kind {
                FunctionKind::Publish => ServiceControlType::Publish,
                FunctionKind::Subscribe => {
                    if !f.active {
                        continue; // passive subscribe transmits nothing
                    }
                    ServiceControlType::Subscribe
                }
            };
            let mut sda = ServiceDescriptor::new(f.service_id, f.instance_id, control_type);
            if !f.ssi.is_empty() {
                sda = sda.with_service_info(f.ssi.clone());
            }
            sda.encode(&mut attrs);
            Sdea::plain(f.instance_id).encode(&mut attrs);
        }
        let seq = self.next_seq();
        let sdf = ServiceDiscoveryFrame::new(NAN_NETWORK_ID, self.cfg.nmi, self.cluster_id, seq);
        step.tx.push(TxFrame {
            bytes: sdf.encode(&attrs),
        });
    }

    /// The M1–M4 receive half. Data-path setup is unicast, so a NAF not addressed
    /// to us is someone else's negotiation — reacting to it would answer a request
    /// that was never made of us.
    fn handle_naf(&mut self, rx: RxFrame, subtype: u8, attrs: &[u8], step: &mut Step) {
        if rx_addr1(rx.bytes) != Some(self.cfg.nmi) {
            return;
        }
        let Some(sub) = NafSubtype::from_byte(subtype) else {
            return;
        };
        let Some(attr) = crate::attr::Attributes::find(attrs, AttributeId::NdpExtension) else {
            return;
        };
        let Ok(ndpe) = Ndpe::decode(attr.body) else {
            return;
        };
        let peer = rx_addr2(rx.bytes);

        match sub {
            NafSubtype::DataPathRequest => self.on_ndp_request(peer, &ndpe),
            NafSubtype::DataPathResponse => self.on_ndp_response(peer, &ndpe, step),
            NafSubtype::DataPathConfirm => self.on_ndp_confirm(peer, &ndpe, step),
            NafSubtype::DataPathTermination => {
                if let Some(i) = self.ndp_index(peer, ndpe.ndp_id) {
                    let s = self.ndps.remove(i);
                    step.events.push(NanEvent::NdpTerminated {
                        peer,
                        ndp_id: s.ndp_id,
                    });
                }
            }
            // Ranging, schedule negotiation, and key installment are out of scope
            // for an open data path.
            _ => {}
        }
    }

    fn ndp_index(&self, peer: [u8; 6], ndp_id: u8) -> Option<usize> {
        self.ndps
            .iter()
            .position(|s| s.peer == peer && s.ndp_id == ndp_id)
    }

    /// M1 in: become the responder for a path this peer wants.
    fn on_ndp_request(&mut self, peer: [u8; 6], ndpe: &Ndpe) {
        if ndpe.ndp_type != NdpType::Request {
            return;
        }
        // A repeat of an M1 we already answered means our M2 was lost — re-send
        // it rather than starting a second session for the same path.
        if let Some(i) = self.ndp_index(peer, ndpe.ndp_id) {
            if self.ndps[i].role == NdpRole::Responder
                && self.ndps[i].state == NdpState::AwaitingConfirm
            {
                self.ndps[i].pending_tx = Some(NafSubtype::DataPathResponse);
            }
            return;
        }
        self.ndps.push(NdpSession {
            peer,
            ndp_id: ndpe.ndp_id,
            dialog_token: ndpe.dialog_token,
            role: NdpRole::Responder,
            // A rejection still needs the session to carry the outbound M2; it is
            // dropped once sent.
            state: NdpState::AwaitingConfirm,
            peer_ndi: Some(ndpe.initiator_ndi),
            peer_iid: ndpe.ipv6_iid(),
            pending_tx: Some(NafSubtype::DataPathResponse),
            attempts: 0,
            retry_at_usec: 0,
        });
    }

    /// M2 in: the peer answered our request.
    fn on_ndp_response(&mut self, peer: [u8; 6], ndpe: &Ndpe, step: &mut Step) {
        let Some(i) = self.ndp_index(peer, ndpe.ndp_id) else {
            return;
        };
        if self.ndps[i].role != NdpRole::Initiator || self.ndps[i].state != NdpState::AwaitingResponse
        {
            return;
        }
        match ndpe.status {
            NdpStatus::Rejected => {
                let s = self.ndps.remove(i);
                step.events.push(NanEvent::NdpFailed {
                    peer,
                    ndp_id: s.ndp_id,
                    reason: NdpFailure::Rejected {
                        reason_code: ndpe.reason_code,
                    },
                });
            }
            NdpStatus::Accepted => {
                // The responder's NDI + IID are the whole payoff: they are what we
                // address the data path to.
                let (Some(ndi), Some(iid)) = (ndpe.responder_ndi, ndpe.ipv6_iid()) else {
                    // Accepted but unusable — without both we cannot address the
                    // peer, so treat it as a rejection rather than report a path
                    // that can't carry anything.
                    let s = self.ndps.remove(i);
                    step.events.push(NanEvent::NdpFailed {
                        peer,
                        ndp_id: s.ndp_id,
                        reason: NdpFailure::Rejected { reason_code: 0 },
                    });
                    return;
                };
                let s = &mut self.ndps[i];
                s.peer_ndi = Some(ndi);
                s.peer_iid = Some(iid);
                s.state = NdpState::Established;
                s.pending_tx = Some(NafSubtype::DataPathConfirm);
                let (ndp_id, role) = (s.ndp_id, s.role);
                step.events.push(NanEvent::NdpEstablished {
                    peer,
                    ndp_id,
                    role,
                    peer_ndi: ndi,
                    peer_iid: iid,
                });
            }
            // Continue = "still deciding": keep waiting for a terminal answer.
            NdpStatus::Continue => {}
        }
    }

    /// M3 in: the initiator confirmed the path we accepted.
    fn on_ndp_confirm(&mut self, peer: [u8; 6], ndpe: &Ndpe, step: &mut Step) {
        let Some(i) = self.ndp_index(peer, ndpe.ndp_id) else {
            return;
        };
        let s = &mut self.ndps[i];
        if s.role != NdpRole::Responder || s.state != NdpState::AwaitingConfirm {
            return;
        }
        s.state = NdpState::Established;
        let (Some(ndi), Some(iid)) = (s.peer_ndi, s.peer_iid) else {
            // The initiator never told us how to address it (no IID in M1).
            let s = self.ndps.remove(i);
            step.events.push(NanEvent::NdpFailed {
                peer,
                ndp_id: s.ndp_id,
                reason: NdpFailure::Rejected { reason_code: 0 },
            });
            return;
        };
        let (ndp_id, role) = (s.ndp_id, s.role);
        step.events.push(NanEvent::NdpEstablished {
            peer,
            ndp_id,
            role,
            peer_ndi: ndi,
            peer_iid: iid,
        });
    }

    /// The M1–M4 transmit half: send whatever each session owes, and re-send an
    /// unanswered M1 until the attempt budget runs out.
    fn emit_ndp(&mut self, now: Usec, step: &mut Step) {
        let (our_ndi, our_iid) = (self.cfg.ndi, eui64_iid(self.cfg.ndi));
        let auto_accept = self.cfg.ndp_auto_accept;
        let mut timed_out: Vec<([u8; 6], u8)> = Vec::new();
        let mut frames: Vec<([u8; 6], NafSubtype, Vec<u8>)> = Vec::new();

        for s in &mut self.ndps {
            // Re-arm an unanswered request.
            if s.pending_tx.is_none()
                && s.role == NdpRole::Initiator
                && s.state == NdpState::AwaitingResponse
                && now >= s.retry_at_usec
            {
                if s.attempts >= NDP_MAX_ATTEMPTS {
                    timed_out.push((s.peer, s.ndp_id));
                    continue;
                }
                s.pending_tx = Some(NafSubtype::DataPathRequest);
            }
            let Some(sub) = s.pending_tx.take() else {
                continue;
            };

            let mut attrs = Vec::new();
            match sub {
                NafSubtype::DataPathRequest => {
                    Ndpe::request(s.dialog_token, s.ndp_id, our_ndi, our_iid).encode(&mut attrs);
                    s.attempts = s.attempts.saturating_add(1);
                    s.retry_at_usec = now.wrapping_add(NDP_RETRY_USEC);
                }
                NafSubtype::DataPathResponse => {
                    // The initiator's NDI, not ours: it names who asked.
                    let init_ndi = s.peer_ndi.unwrap_or(s.peer);
                    let mut m2 = if auto_accept {
                        Ndpe::accept(s.dialog_token, s.ndp_id, init_ndi, our_ndi, our_iid)
                    } else {
                        let mut r = Ndpe::confirm(s.dialog_token, s.ndp_id, init_ndi);
                        r.ndp_type = NdpType::Response;
                        r.status = NdpStatus::Rejected;
                        r
                    };
                    if !auto_accept {
                        m2.responder_ndi = None;
                        m2.tlvs.clear();
                    }
                    m2.encode(&mut attrs);
                }
                NafSubtype::DataPathConfirm => {
                    Ndpe::confirm(s.dialog_token, s.ndp_id, our_ndi).encode(&mut attrs);
                }
                NafSubtype::DataPathTermination => {
                    let mut t = Ndpe::confirm(s.dialog_token, s.ndp_id, our_ndi);
                    t.ndp_type = NdpType::Terminate;
                    t.encode(&mut attrs);
                }
                _ => continue,
            }
            frames.push((s.peer, sub, attrs));
            // A rejected request leaves no session behind.
            if matches!(sub, NafSubtype::DataPathResponse) && !auto_accept {
                timed_out.push((s.peer, s.ndp_id));
            }
        }

        for (peer, sub, attrs) in frames {
            let seq = self.next_seq();
            let naf = NanActionFrame::new(sub, peer, self.cfg.nmi, self.cluster_id, seq);
            step.tx.push(TxFrame {
                bytes: naf.encode(&attrs),
            });
        }

        for (peer, ndp_id) in timed_out {
            if let Some(i) = self.ndp_index(peer, ndp_id) {
                let s = self.ndps.remove(i);
                if s.role == NdpRole::Initiator {
                    step.events.push(NanEvent::NdpFailed {
                        peer,
                        ndp_id,
                        reason: NdpFailure::TimedOut,
                    });
                }
            }
        }
    }

    fn emit_followups(&mut self, step: &mut Step) {
        while let Some(fu) = self.followups.pop_front() {
            let mut attrs = Vec::new();
            let mut sda =
                ServiceDescriptor::new(fu.service_id, fu.instance_id, ServiceControlType::FollowUp);
            sda.requestor_instance_id = fu.requestor_instance_id;
            if !fu.ssi.is_empty() {
                sda = sda.with_service_info(fu.ssi);
            }
            sda.encode(&mut attrs);
            let seq = self.next_seq();
            let sdf = ServiceDiscoveryFrame::new(fu.dest, self.cfg.nmi, self.cluster_id, seq);
            step.tx.push(TxFrame {
                bytes: sdf.encode(&attrs),
            });
        }
    }
}

/// addr1 (destination) of a captured frame, if the 24-byte header is present.
fn rx_addr1(buf: &[u8]) -> Option<[u8; 6]> {
    buf.get(4..10).map(|s| {
        let mut a = [0u8; 6];
        a.copy_from_slice(s);
        a
    })
}

/// addr2 (source / NMI) of a captured frame.
fn rx_addr2(buf: &[u8]) -> [u8; 6] {
    let mut a = [0u8; 6];
    if let Some(s) = buf.get(10..16) {
        a.copy_from_slice(s);
    }
    a
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::USEC_PER_TU;

    const A: [u8; 6] = [0x02, 0, 0, 0, 0, 0xAA];
    const B: [u8; 6] = [0x02, 0, 0, 0, 0, 0xBB];

    /// Drive two engines through a synchronous in-memory medium: everything one
    /// emits in a `poll` is delivered to the other on its next `poll`. Returns
    /// the events each surfaced.
    struct Medium {
        a: NanEngine,
        b: NanEngine,
        a_inbox: Vec<TxFrame>,
        b_inbox: Vec<TxFrame>,
        now: Usec,
    }

    impl Medium {
        fn new(a: NanEngine, b: NanEngine) -> Self {
            Self {
                a,
                b,
                a_inbox: Vec::new(),
                b_inbox: Vec::new(),
                now: 1_000_000,
            }
        }

        /// Advance `now`, poll both engines, and cross-deliver their TX. Returns
        /// (a_events, b_events) from this tick.
        fn tick(&mut self, dt: Usec) -> (Vec<NanEvent>, Vec<NanEvent>) {
            self.now += dt;
            let a_in: Vec<RxFrame> = self
                .a_inbox
                .iter()
                .map(|f| RxFrame {
                    bytes: &f.bytes,
                    rssi_dbm: Some(-50),
                    now_usec: self.now,
                })
                .collect();
            let a_step = self.a.poll(self.now, &a_in);
            self.a_inbox.clear();

            let b_in: Vec<RxFrame> = self
                .b_inbox
                .iter()
                .map(|f| RxFrame {
                    bytes: &f.bytes,
                    rssi_dbm: Some(-55),
                    now_usec: self.now,
                })
                .collect();
            let b_step = self.b.poll(self.now, &b_in);
            self.b_inbox.clear();

            // Cross-deliver (a half-duplex node never hears itself; the engine
            // also guards on addr2).
            self.b_inbox.extend(a_step.tx.iter().cloned());
            self.a_inbox.extend(b_step.tx.iter().cloned());
            (a_step.events, b_step.events)
        }
    }

    #[test]
    fn master_rank_orders_by_preference_then_factor_then_mac() {
        // Preference dominates.
        assert!(master_rank(200, 0, A) > master_rank(199, 255, A));
        // Then random factor.
        assert!(master_rank(200, 10, A) > master_rank(200, 9, B));
        // Then MAC (mac[5] is most significant among address bytes).
        assert!(master_rank(200, 0, B) > master_rank(200, 0, A));
    }

    #[test]
    fn two_nodes_discover_each_other_over_a_dw() {
        // Both publish AND subscribe the same coordination service → mutual
        // discovery (the NanCoordFace model). A outranks B.
        let mut a = NanEngine::new(NanConfig::new(A, 6, 200));
        a.publish("org.ndn.coord", b"a".to_vec());
        a.subscribe("org.ndn.coord", true);
        let mut b = NanEngine::new(NanConfig::new(B, 6, 180));
        b.publish("org.ndn.coord", b"b".to_vec());
        b.subscribe("org.ndn.coord", true);

        let mut m = Medium::new(a, b);
        let mut a_found = false;
        let mut b_found = false;
        // Step in fine 8-TU increments so samples reliably fall inside the
        // 16-TU Discovery Window of each 512-TU period (a real driver instead
        // polls exactly at the DW boundaries `wake_at` reports).
        for _ in 0..200 {
            let (ae, be) = m.tick(8 * USEC_PER_TU);
            if ae
                .iter()
                .any(|e| matches!(e, NanEvent::Discovered { peer, .. } if *peer == B))
            {
                a_found = true;
            }
            if be
                .iter()
                .any(|e| matches!(e, NanEvent::Discovered { peer, .. } if *peer == A))
            {
                b_found = true;
            }
        }
        assert!(a_found, "A should discover B");
        assert!(b_found, "B should discover A");
    }

    /// The whole point: two engines negotiate a path over the medium and BOTH
    /// end up knowing how to address the other, with no out-of-band exchange.
    #[test]
    fn two_nodes_establish_a_data_path() {
        const A_NDI: [u8; 6] = [0x02, 0xaa, 0xaa, 0x00, 0x00, 0x01];
        const B_NDI: [u8; 6] = [0x02, 0xbb, 0xbb, 0x00, 0x00, 0x02];
        let a = NanEngine::new(NanConfig::new(A, 6, 200).with_ndi(A_NDI));
        let b = NanEngine::new(NanConfig::new(B, 6, 180).with_ndi(B_NDI));
        let mut m = Medium::new(a, b);

        let ndp_id = m.a.request_ndp(B);
        let (mut a_up, mut b_up) = (None, None);
        for _ in 0..200 {
            let (ae, be) = m.tick(8 * USEC_PER_TU);
            for e in ae {
                if let NanEvent::NdpEstablished { .. } = e {
                    a_up = Some(e);
                }
            }
            for e in be {
                if let NanEvent::NdpEstablished { .. } = e {
                    b_up = Some(e);
                }
            }
        }

        // The initiator learns the responder's data interface + address.
        assert_eq!(
            a_up.expect("A should establish the path it asked for"),
            NanEvent::NdpEstablished {
                peer: B,
                ndp_id,
                role: NdpRole::Initiator,
                peer_ndi: B_NDI,
                peer_iid: eui64_iid(B_NDI),
            }
        );
        // And the responder learns the initiator's, from M1's NDPE.
        assert_eq!(
            b_up.expect("B should accept and confirm"),
            NanEvent::NdpEstablished {
                peer: A,
                ndp_id,
                role: NdpRole::Responder,
                peer_ndi: A_NDI,
                peer_iid: eui64_iid(A_NDI),
            }
        );
        assert_eq!(m.a.established_ndps(), 1);
        assert_eq!(m.b.established_ndps(), 1);
    }

    /// The IID a peer derives our address from must be the modified EUI-64 of our
    /// NDI: `ff:fe` inserted and the universal/local bit flipped (RFC 4291). Get
    /// this wrong and the handshake still "succeeds" while the data path
    /// addresses a host that does not exist.
    #[test]
    fn eui64_matches_the_rfc_4291_construction() {
        assert_eq!(
            eui64_iid([0x02, 0x26, 0x23, 0xef, 0xbe, 0x2f]),
            [0x00, 0x26, 0x23, 0xff, 0xfe, 0xef, 0xbe, 0x2f]
        );
        // The bit flips both ways: a universally-administered MAC gains it.
        assert_eq!(eui64_iid([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])[0], 0x02);
        let e = NanEngine::new(NanConfig::new(A, 6, 200).with_ndi([0x02, 1, 2, 3, 4, 5]));
        assert_eq!(
            e.local_ndp_identity(),
            ([0x02, 1, 2, 3, 4, 5], eui64_iid([0x02, 1, 2, 3, 4, 5]))
        );
    }

    #[test]
    fn a_rejecting_peer_fails_the_path_rather_than_hanging() {
        let a = NanEngine::new(NanConfig::new(A, 6, 200));
        let mut cfg = NanConfig::new(B, 6, 180);
        cfg.ndp_auto_accept = false; // publishes, but serves no data path
        let b = NanEngine::new(cfg);
        let mut m = Medium::new(a, b);

        let ndp_id = m.a.request_ndp(B);
        let mut failed = None;
        for _ in 0..200 {
            let (ae, _) = m.tick(8 * USEC_PER_TU);
            for e in ae {
                if let NanEvent::NdpFailed { .. } = e {
                    failed = Some(e);
                }
            }
        }
        assert_eq!(
            failed.expect("A should be told the path was refused"),
            NanEvent::NdpFailed {
                peer: B,
                ndp_id,
                reason: NdpFailure::Rejected { reason_code: 0 },
            }
        );
        assert_eq!(m.a.established_ndps(), 0);
        assert_eq!(m.b.established_ndps(), 0, "a refused path leaves no session");
    }

    /// An unanswered request must give up, not retry forever — and must say so.
    #[test]
    fn an_unanswered_request_times_out_after_a_bounded_number_of_attempts() {
        let mut a = NanEngine::new(NanConfig::new(A, 6, 200));
        const ABSENT: [u8; 6] = [0x02, 0x00, 0x00, 0xde, 0xad, 0x00];
        let ndp_id = a.request_ndp(ABSENT);

        let mut now = 1_000_000u64;
        let mut m1_count = 0;
        let mut failed = None;
        // Long enough to cover NDP_MAX_ATTEMPTS retries at NDP_RETRY_USEC apart
        // (~1.05 s each) plus the final timeout.
        for _ in 0..800 {
            now += 8 * USEC_PER_TU;
            let step = a.poll(now, &[]);
            m1_count += step
                .tx
                .iter()
                .filter(|f| {
                    crate::frame::NanActionFrame::parse(&f.bytes)
                        .map(|(n, _)| n.subtype == NafSubtype::DataPathRequest as u8)
                        .unwrap_or(false)
                })
                .count();
            for e in step.events {
                if let NanEvent::NdpFailed { .. } = e {
                    failed = Some(e);
                }
            }
        }
        assert_eq!(
            failed.expect("an unanswered request must fail, not hang"),
            NanEvent::NdpFailed {
                peer: ABSENT,
                ndp_id,
                reason: NdpFailure::TimedOut,
            }
        );
        assert_eq!(
            m1_count, NDP_MAX_ATTEMPTS as usize,
            "exactly the attempt budget, then stop"
        );
        assert_eq!(a.established_ndps(), 0);
    }

    /// Data-path setup is unicast. Answering an M1 aimed at another node would
    /// mean accepting a request nobody made of us.
    #[test]
    fn a_request_addressed_elsewhere_is_ignored() {
        const OTHER: [u8; 6] = [0x02, 0x00, 0x00, 0x11, 0x22, 0x33];
        let mut attrs = Vec::new();
        Ndpe::request(1, 1, A, eui64_iid(A)).encode(&mut attrs);
        // Addressed to OTHER, sent by A; B merely overhears it.
        let naf =
            NanActionFrame::new(NafSubtype::DataPathRequest, OTHER, A, NAN_CLUSTER_ID_BASE, 1)
                .encode(&attrs);

        let mut b = NanEngine::new(NanConfig::new(B, 6, 180));
        let step = b.poll(
            1_000_000,
            &[RxFrame {
                bytes: &naf,
                rssi_dbm: Some(-50),
                now_usec: 1_000_000,
            }],
        );
        assert!(step.tx.iter().all(|f| {
            crate::frame::NanActionFrame::parse(&f.bytes).is_err() // beacons/SDFs only
        }));
        assert_eq!(b.established_ndps(), 0);
    }

    /// A lost M2 must not spawn a second session for the same path.
    #[test]
    fn a_repeated_request_re_sends_the_response_without_duplicating_state() {
        let mut b = NanEngine::new(NanConfig::new(B, 6, 180));
        let mut attrs = Vec::new();
        Ndpe::request(1, 7, A, eui64_iid(A)).encode(&mut attrs);
        let naf = NanActionFrame::new(NafSubtype::DataPathRequest, B, A, NAN_CLUSTER_ID_BASE, 1)
            .encode(&attrs);
        let rx = |t| RxFrame {
            bytes: &naf,
            rssi_dbm: Some(-50),
            now_usec: t,
        };

        let count_m2 = |step: &Step| {
            step.tx
                .iter()
                .filter(|f| {
                    crate::frame::NanActionFrame::parse(&f.bytes)
                        .map(|(n, _)| n.subtype == NafSubtype::DataPathResponse as u8)
                        .unwrap_or(false)
                })
                .count()
        };
        let s1 = b.poll(1_000_000, &[rx(1_000_000)]);
        assert_eq!(count_m2(&s1), 1, "M1 → one M2");
        let s2 = b.poll(1_000_100, &[rx(1_000_100)]);
        assert_eq!(count_m2(&s2), 1, "a repeated M1 re-sends M2");
        assert_eq!(b.ndps.len(), 1, "still one session, not two");
    }

    #[test]
    fn discovered_event_carries_peer_ssi() {
        let mut a = NanEngine::new(NanConfig::new(A, 6, 200));
        a.publish("svc", b"hello-from-a".to_vec());
        let mut b = NanEngine::new(NanConfig::new(B, 6, 180));
        b.subscribe("svc", true); // active so it also beacons/sdf's

        let mut m = Medium::new(a, b);
        let mut got: Option<Vec<u8>> = None;
        for _ in 0..200 {
            let (_ae, be) = m.tick(8 * USEC_PER_TU);
            for e in be {
                if let NanEvent::Discovered { ssi, peer, .. } = e
                    && peer == A
                {
                    got = Some(ssi);
                }
            }
        }
        assert_eq!(got.as_deref(), Some(&b"hello-from-a"[..]));
    }

    #[test]
    fn follow_up_reaches_a_matched_peer() {
        let mut a = NanEngine::new(NanConfig::new(A, 6, 200));
        a.publish("org.ndn.coord", Vec::new());
        a.subscribe("org.ndn.coord", true);
        let mut b = NanEngine::new(NanConfig::new(B, 6, 180));
        b.publish("org.ndn.coord", Vec::new());
        b.subscribe("org.ndn.coord", true);

        let mut m = Medium::new(a, b);
        // Run until mutual discovery so both have the other as a matched peer.
        for _ in 0..200 {
            m.tick(8 * USEC_PER_TU);
        }
        // A sends a follow-up; B should surface it.
        let n = m.a.broadcast_followup(b"ping".to_vec());
        assert!(n >= 1, "A must have B as a matched peer");

        let mut delivered = None;
        for _ in 0..200 {
            let (_ae, be) = m.tick(8 * USEC_PER_TU);
            for e in be {
                if let NanEvent::Followup { peer, ssi, .. } = e
                    && peer == A
                {
                    delivered = Some(ssi);
                }
            }
        }
        assert_eq!(delivered.as_deref(), Some(&b"ping"[..]));
    }

    /// Cluster merge: the lower-graded node adopts the higher-graded node's
    /// cluster id and TSF timeline (so their Discovery Windows align). A (pref
    /// 200) outgrades B (pref 50); B must end up on A's cluster + clock.
    #[test]
    fn lower_graded_node_merges_into_higher_cluster() {
        let mut a = NanEngine::new(NanConfig::new(A, 6, 200));
        a.publish("org.ndn.coord", Vec::new());
        let mut b = NanEngine::new(NanConfig::new(B, 6, 50));
        b.publish("org.ndn.coord", Vec::new());
        let a_rank = a.rank();

        let mut m = Medium::new(a, b);
        for _ in 0..60 {
            m.tick(8 * USEC_PER_TU);
        }
        // B joined A's cluster (A's amr) and A stayed its own anchor.
        assert_eq!(m.b.cluster_amr, a_rank, "B adopts A's anchor-master rank");
        assert_eq!(m.a.cluster_amr, a_rank, "A remains its own anchor");
        assert_eq!(m.b.cluster_id, m.a.cluster_id, "B joins A's cluster id");
        // Their synced DW timelines now agree at a common instant.
        let t = 999_999u64;
        assert_eq!(
            m.a.dw_index(t),
            m.b.dw_index(t),
            "aligned timelines ⇒ same DW index"
        );
    }

    #[test]
    fn first_poll_requests_channel_then_doesnt_repeat() {
        let mut a = NanEngine::new(NanConfig::new(A, 44, 200));
        let s0 = a.poll(0, &[]);
        assert_eq!(s0.set_channel, Some(44));
        let s1 = a.poll(1000, &[]);
        assert_eq!(s1.set_channel, None);
    }
}
