//! Connectionless **Wi-Fi Aware (NAN)** coordination face for ndn-rs.
//!
//! Wi-Fi Aware / Neighbor Awareness Networking is AP-less, association-less, and
//! its native primitive is publish/subscribe by service *name* — NDN's model in
//! silicon. NAN exposes three primitives that map to three different NDN seams
//! (see `.claude/notes/named-radio/wifi-aware-face-design-2026-05-23.md`):
//!
//! 1. **service publish/subscribe** → an NDN `DiscoveryProtocol` (later phase);
//! 2. **follow-up messages** (small, connectionless) → *this* face, the
//!    name-native **coordination** channel carrying Interests + small Data;
//! 3. **NDP** (NAN data path, IPv6 link-local) → a plain `UdpFace` for **bulk**
//!    (later phase; no new transport code — reuses `ndn-face-native`).
//!
//! This crate provides the coordination face. Like
//! [`ndn-face-ble-adv`](https://docs.rs/ndn-face-ble-adv), it is a
//! **`LinkType::AdHoc`** broadcast bearer — the engine forwards on the *name*
//! inside each frame, broadcast/self-learning strategy does the rest. The radio
//! lives behind the [`NanBackend`] trait, supplied by the platform (Android
//! `WifiAwareManager` via JNI; Linux nl80211 later). A hardware-free
//! [`LoopbackNanBus`] exercises the face in tests.
//!
//! Faces report [`FaceKind::WifiAware`] (NonLocal scope, LP-framed) with
//! `link_type() == AdHoc` marking the connectionless cluster medium.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use ndn_signals_core::{LinkSignals, SignalStore};
use ndn_transport::{
    Face, FaceAddr, FaceId, FaceKind, FacePersistency, LinkType, MtuError, PersistencyError,
    Transport,
};
// Part of the public `NanBackend` surface (its methods return it), so external
// backend implementors (e.g. the boltffi FFI adapter) can name it.
pub use ndn_transport::FaceError;

/// Usable payload for a NAN **follow-up message**. Well above the NDNLPv2
/// fragmentation floor (`ndn_packet::fragment::FRAG_OVERHEAD` ≈ 50 B), so this
/// bearer can carry LP-fragmented NDN — unlike a legacy BLE advertisement.
///
/// Verified against the platform: Android `WifiAwareManager` caps a follow-up
/// message at `Characteristics.getMaxServiceSpecificInfoLength()`, and on real
/// hardware (e.g. Samsung S23) that ceiling is **below 255** — sending a
/// 255-byte LP fragment fails with *"Message length longer than supported by
/// device characteristics"*, so the packet never leaves the radio. Stay well
/// under the smallest observed ceiling (with headroom for the follow-up's own
/// framing); a face can still raise it per-device via [`NanCoordFace::with_mtu`]
/// once it has queried the real characteristic. Treat bulk transfers as Tier-2
/// NDP traffic (a `UdpFace`), not something to LP-fragment across follow-ups.
pub const FOLLOWUP_MTU: usize = 200;

/// One follow-up message heard from a cluster peer: the carried bytes plus what
/// the link layer knows about it. The NDN layer forwards on the *name* inside
/// `frame`; `peer`/`rssi_dbm` are link-layer hints (dedup, per-neighbour
/// measurement), never the addressing.
#[derive(Clone, Debug)]
pub struct FollowupFrame {
    /// The follow-up payload — a (possibly LP-fragmented) NDN packet.
    pub frame: Bytes,
    /// The sender's NAN management-interface MAC (NMI), if surfaced. NMIs
    /// rotate for privacy; this is a reassembly *stream key*, not a host id.
    pub peer: Option<[u8; 6]>,
    /// Received signal strength in dBm, if measured.
    pub rssi_dbm: Option<i8>,
}

/// A NAN service name — a short UTF-8 label the radio hashes to a service ID.
/// Maps to an NDN **coordination prefix**, not a per-content name (a full NDN
/// name does not fit; content names ride inside the follow-up/NDP payload).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NanServiceName(pub String);

impl NanServiceName {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

impl From<&str> for NanServiceName {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

/// A discovered peer advertising one of our subscribed services — the NAN
/// publish/subscribe match event that drives prefix discovery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NanMatch {
    /// The subscribed service the peer was found advertising.
    pub service: NanServiceName,
    /// The matched peer's NAN management-interface MAC (NMI).
    pub peer: [u8; 6],
}

/// An established NAN **data path** (NDP) to a peer — the Tier-2 bulk channel.
/// NAN sets up an IPv6 link-local L2 link; this carries the resulting bound UDP
/// socket and the peer's resolved address. Wrap it in an `ndn-face-native`
/// `UdpFace` (`UdpFace::from_socket(id, link.socket, link.peer_addr)`) and add
/// that to the engine — no new transport code, full NDNLPv2 / reliability /
/// congestion. Use the coordination face ([`NanCoordFace`]) for small traffic
/// and request an NDP only for sustained/bulk transfers.
pub struct NdpLink {
    /// Bound local UDP socket over the NDP interface (IPv6 link-local in a real
    /// NDP; loopback in tests).
    pub socket: tokio::net::UdpSocket,
    /// The peer's address on the NDP interface.
    pub peer_addr: std::net::SocketAddr,
}

/// The radio behind a [`NanCoordFace`] (and, optionally, [`NanDiscovery`]). The
/// follow-up methods (`broadcast`/`next_followup`) carry the coordination
/// channel; the service methods (`publish`/`subscribe`/`drain_matches`) drive
/// NAN service discovery and default to no-ops so a coordination-only backend
/// need not implement them.
///
/// `next_followup` has a single consumer (the face's reader task); `broadcast`
/// may be called concurrently and must synchronise internally.
#[async_trait]
pub trait NanBackend: Send + Sync + 'static {
    /// Send `frame` as a follow-up message to every currently-matched peer in
    /// the NAN cluster — the connectionless coordination "broadcast".
    /// Fire-and-forget, unacknowledged.
    async fn broadcast(&self, frame: Bytes) -> Result<(), FaceError>;

    /// Await the next follow-up message heard from any cluster peer. A node
    /// never hears its own transmissions (radios are half-duplex); the backend
    /// filters those.
    async fn next_followup(&self) -> Result<FollowupFrame, FaceError>;

    /// Advertise NDN service `service` so subscribing peers discover this node.
    async fn publish(&self, service: &NanServiceName) -> Result<(), FaceError> {
        let _ = service;
        Ok(())
    }

    /// Subscribe to discover peers advertising NDN service `service`.
    async fn subscribe(&self, service: &NanServiceName) -> Result<(), FaceError> {
        let _ = service;
        Ok(())
    }

    /// Drain match events observed since the last call (non-blocking) — each is
    /// a peer seen advertising one of our subscribed services. Drained from
    /// [`NanDiscovery::on_tick`](ndn_discovery_core::DiscoveryProtocol::on_tick).
    fn drain_matches(&self) -> Vec<NanMatch> {
        Vec::new()
    }

    /// Establish a NAN data path (NDP) to `peer` for bulk transfer, returning
    /// the bound UDP socket + peer address to wrap in a `UdpFace`. Defaults to
    /// `Unsupported` — a coordination-only backend need not implement NDP.
    async fn request_ndp(&self, peer: [u8; 6]) -> Result<NdpLink, FaceError> {
        let _ = peer;
        Err(FaceError::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "NDP not supported by this NAN backend",
        )))
    }
}

/// A connectionless Wi-Fi Aware coordination face over NAN follow-up messages.
/// Build a [`Face`] with [`into_face`](Self::into_face); the engine treats it as
/// an ad-hoc broadcast bearer and frames it with NDNLPv2 (the LP link service
/// fragments/reassembles — follow-up MTU is above the fragmentation floor).
pub struct NanCoordFace {
    id: FaceId,
    backend: Arc<dyn NanBackend>,
    mtu: usize,
    /// Optional sink for per-frame RSSI. When set, every received follow-up
    /// publishes `LinkSignals` for this face id (feeds measured strategies).
    signal_sink: Option<Arc<dyn SignalStore<FaceId> + Send + Sync>>,
}

impl NanCoordFace {
    /// New coordination face over `backend`, sized for a NAN follow-up message.
    pub fn new(id: FaceId, backend: Arc<dyn NanBackend>) -> Self {
        Self {
            id,
            backend,
            mtu: FOLLOWUP_MTU,
            signal_sink: None,
        }
    }

    /// Override the follow-up payload budget (e.g. a platform with a different
    /// `ServiceSpecificInfo` cap).
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

    /// Build a [`Face`], pairing this transport with the engine's NDNLPv2 link
    /// service (so the engine fragments/reassembles). Add the result to the
    /// engine via the face-table's pre-built-face path.
    pub fn into_face(self) -> Face {
        Face::from_transport(self)
    }

    /// Receive one follow-up message, publishing its RSSI to the sink if wired.
    async fn recv_inner(&self) -> Result<FollowupFrame, FaceError> {
        let msg = self.backend.next_followup().await?;
        if let (Some(sink), Some(rssi)) = (self.signal_sink.as_ref(), msg.rssi_dbm) {
            sink.set_link(
                self.id,
                LinkSignals {
                    rssi_dbm: Some(rssi),
                    updated_ms: now_ms(),
                    ..LinkSignals::default()
                },
            );
        }
        Ok(msg)
    }
}

impl Transport for NanCoordFace {
    fn id(&self) -> FaceId {
        self.id
    }

    fn kind(&self) -> FaceKind {
        // A connectionless Wi-Fi wire bearer (LP framing on, NonLocal scope);
        // `link_type() == AdHoc` marks the connectionless cluster medium.
        FaceKind::WifiAware
    }

    fn remote_uri(&self) -> Option<String> {
        Some("wifi-aware://cluster".to_string())
    }

    fn link_type(&self) -> LinkType {
        LinkType::AdHoc
    }

    fn send_mtu(&self) -> Option<usize> {
        Some(self.mtu)
    }

    async fn send_bytes(&self, wire: Bytes) -> Result<(), FaceError> {
        // The LpLinkService already framed/fragmented to `mtu`; each call is one
        // follow-up message fanned to the matched cluster.
        self.backend.broadcast(wire).await
    }

    async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
        self.recv_bytes_with_addr().await.map(|(b, _)| b)
    }

    async fn recv_bytes_with_addr(&self) -> Result<(Bytes, Option<FaceAddr>), FaceError> {
        let msg = self.recv_inner().await?;
        Ok((msg.frame, msg.peer.map(FaceAddr::Ether)))
    }

    /// Follow-up payload size is fixed at construction.
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

// NAN service discovery → NDN routes
mod discovery;
pub use discovery::NanDiscovery;

// Hardware-free loopback NAN cluster (tests + simulation)
mod loopback;
pub use loopback::{LoopbackNanBus, LoopbackNanEndpoint};

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::time::Duration;

    use ndn_signals_core::{NodeSignals, SignalView};

    const NMI_A: [u8; 6] = [0xA0; 6];
    const NMI_B: [u8; 6] = [0xB0; 6];

    /// Minimal in-memory `SignalStore` for asserting RSSI plumbing.
    #[derive(Default)]
    struct TestSink {
        links: Mutex<std::collections::HashMap<u64, LinkSignals>>,
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

    #[tokio::test]
    async fn followup_reaches_peer_not_self() {
        let bus = LoopbackNanBus::new();
        let a = Arc::new(bus.endpoint(1, NMI_A, -50));
        let b = Arc::new(bus.endpoint(2, NMI_B, -60));

        a.broadcast(Bytes::from_static(b"hello")).await.unwrap();

        // B hears A's follow-up, with A's NMI and B's observed RSSI.
        let got = tokio::time::timeout(Duration::from_millis(200), b.next_followup())
            .await
            .expect("B should hear A")
            .unwrap();
        assert_eq!(got.frame, Bytes::from_static(b"hello"));
        assert_eq!(got.peer, Some(NMI_A));
        assert_eq!(got.rssi_dbm, Some(-60));

        // A does NOT hear its own transmission (half-duplex radio).
        let self_heard = tokio::time::timeout(Duration::from_millis(100), a.next_followup()).await;
        assert!(
            self_heard.is_err(),
            "a node must not hear its own follow-up"
        );
    }

    #[tokio::test]
    async fn recv_publishes_rssi_to_sink() {
        let bus = LoopbackNanBus::new();
        let sink = Arc::new(TestSink::default());
        let face = NanCoordFace::new(FaceId(7), Arc::new(bus.endpoint(7, NMI_A, -42)))
            .with_signal_sink(sink.clone());
        let peer = Arc::new(bus.endpoint(8, NMI_B, -42));

        peer.broadcast(Bytes::from_static(b"x")).await.unwrap();

        let (frame, addr) =
            tokio::time::timeout(Duration::from_millis(200), face.recv_bytes_with_addr())
                .await
                .expect("face should hear peer")
                .unwrap();
        assert_eq!(frame, Bytes::from_static(b"x"));
        assert!(
            matches!(addr, Some(FaceAddr::Ether(a)) if a == NMI_B),
            "follow-up must carry the sender NMI as a stream key"
        );
        assert_eq!(
            sink.link(FaceId(7)).and_then(|s| s.rssi_dbm),
            Some(-42),
            "received RSSI must be published to the signal sink for this face"
        );
    }

    #[test]
    fn face_is_ad_hoc() {
        let bus = LoopbackNanBus::new();
        let face = NanCoordFace::new(FaceId(1), Arc::new(bus.endpoint(1, NMI_A, -50)));
        assert_eq!(face.link_type(), LinkType::AdHoc);
        assert_eq!(face.kind(), FaceKind::WifiAware);
        assert_eq!(face.send_mtu(), Some(FOLLOWUP_MTU));
    }
}
