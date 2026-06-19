//! Connectionless **BLE advertising** face — a named-radio bearer.
//!
//! Unlike the GATT-based Bluetooth faces (`ndn-face-native`, `ndn-face-webble`),
//! this face carries NDN packets in BLE **advertisements**: connectionless,
//! pairless, association-less broadcast. There is no destination address — the
//! NDN *name* is the addressing. Every scanning peer in range hears every
//! frame and evaluates it against its own PIT/FIB/CS. Meshing is the
//! forwarder's job (a broadcast/self-learning strategy relaying across faces),
//! not the face's.
//!
//! ## How it slots into the engine
//!
//! - **`link_type() == AdHoc`** — the shared medium is one undifferentiated
//!   broadcast domain. The engine's Data path re-radiates Data back onto an
//!   ad-hoc face (the `forwarder.cpp:383` carve-out) so the nodes a relay
//!   serves can hear it.
//! - **Small `send_mtu`** — a BLE advertisement carries only a few dozen bytes.
//!   Returning `Some(small)` makes the paired `LpLinkService` fragment NDN
//!   packets across advertisements automatically (NDNLPv2 fragmentation); the
//!   receiver's `ReassemblyFeature` puts them back together. No custom chunking.
//! - **RSSI → `SignalStore`** — every scanned advertisement carries an RSSI.
//!   When a signal sink is wired, each received frame publishes `LinkSignals`
//!   for this face, feeding measured/CCLF strategies. BLE advertising is one of
//!   the cleanest per-packet RSSI sources in the stack.
//!
//! - **Framing** — two choices via [`BleFraming`]. `Ndnlpv2` (default) rides
//!   the engine's `LpLinkService`; its ~50-byte per-fragment overhead needs
//!   *extended* advertising and interoperates with NFD/ndnd. `Ndnts`
//!   ([`BleAdvFace::ndnts_framing`]) uses the esp8266ndn/NDNts 1-byte header so
//!   it fits a *legacy* advertisement, doing fragmentation and **per-sender**
//!   reassembly in the face itself (the 1-byte header has no sender id, so
//!   reassembly is keyed by the scanned BD_ADDR). Use
//!   [`BleAdvFace::into_face`] — it pairs the correct link service per framing.
//!
//! The radio itself is abstracted behind [`AdvBackend`]: implement it over
//! BlueZ/`bluer` (Linux), an HCI socket, or an embedded controller. A
//! hardware-free [`LoopbackAdvBus`] is provided for tests and simulation.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::Bytes;
use ndn_ble_framing::{BleFraming, PerSenderReassembler};
use ndn_signals_core::{LinkSignals, SignalStore};
use ndn_transport::{
    Face, FaceAddr, FaceId, FaceKind, FacePersistency, LinkType, MtuError, PassthroughLinkService,
    PersistencyError, Transport,
};
// Part of the public `AdvBackend` surface (its methods return it), so external
// backend implementors (e.g. the boltffi FFI adapter) can name it.
pub use ndn_transport::FaceError;

/// Usable advertising-payload budget for **legacy** advertising (31-byte AD
/// minus AD-structure + manufacturer/service-data overhead).
///
/// **Caveat:** this is *smaller than NDNLPv2's per-fragment overhead*
/// (`ndn_packet::fragment::FRAG_OVERHEAD` ≈ 50 bytes), so legacy advertising
/// **cannot carry LP-fragmented NDN** — a fragmenting send would have no room
/// for payload. Legacy mode is only viable for NDN packets that fit whole in
/// one advert (tiny names, no fragmentation). For real traffic use
/// [`BleAdvFace::new`]'s default (extended advertising). The same limit bites
/// other tiny-frame bearers (LoRa low spreading factors).
pub const LEGACY_ADV_MTU: usize = 26;

/// Usable payload for BLE 5 **extended** advertising (up to ~255 bytes minus
/// overhead). Offloads the bulk onto secondary channels via the AUX pointer.
/// Above the NDNLPv2 fragmentation floor, so this is the bearer that actually
/// carries fragmented NDN — hence the [`BleAdvFace`] default.
pub const EXTENDED_ADV_MTU: usize = 245;

/// One advertisement observed by the radio: the carried bytes plus what the
/// link layer knows about it (sender address, RSSI). The NDN layer forwards on
/// the *name* inside `frame`; `addr`/`rssi` are link-layer hints (dedup,
/// per-neighbour measurement), never the addressing.
#[derive(Clone, Debug)]
pub struct ScannedFrame {
    /// The advertised payload — a (possibly LP-fragmented) NDN packet.
    pub frame: Bytes,
    /// Sender BD_ADDR, if the controller surfaced it.
    pub addr: Option<[u8; 6]>,
    /// Received signal strength in dBm, if measured.
    pub rssi_dbm: Option<i8>,
}

/// The radio behind a [`BleAdvFace`]: broadcast a frame, and yield scanned
/// frames. `next_scanned` has a single consumer (the face's reader task);
/// `broadcast` may be called concurrently and must synchronise internally.
#[async_trait]
pub trait AdvBackend: Send + Sync + 'static {
    /// Transmit `frame` as a BLE advertisement on the medium. Fire-and-forget,
    /// unacknowledged — like all broadcast.
    async fn broadcast(&self, frame: Bytes) -> Result<(), FaceError>;

    /// Await the next advertisement heard on the medium. A node never hears its
    /// own transmissions (radios are half-duplex); the backend filters those.
    async fn next_scanned(&self) -> Result<ScannedFrame, FaceError>;
}

/// A connectionless BLE advertising face. Build a [`Face`] from it with
/// [`into_face`](Self::into_face) (which pairs the right link service for the
/// chosen framing); the engine treats it as an ad-hoc broadcast bearer.
pub struct BleAdvFace {
    id: FaceId,
    backend: Arc<dyn AdvBackend>,
    mtu: usize,
    /// Wire framing. `Ndnlpv2` (default) rides the engine's `LpLinkService`
    /// (needs extended adverts; NFD/ndnd interop). `Ndnts` does its own 1-byte
    /// fragmentation + per-sender reassembly here (fits legacy adverts;
    /// esp8266ndn/NDNts interop).
    framing: BleFraming,
    /// Optional sink for per-frame RSSI. When set, every scanned frame
    /// publishes `LinkSignals` for this face id.
    signal_sink: Option<Arc<dyn SignalStore<FaceId> + Send + Sync>>,
    /// Broadcast NDNts reassembly, keyed by sender BD_ADDR (the 1-byte header
    /// carries no sender id). Unused in `Ndnlpv2` framing.
    reasm: Mutex<PerSenderReassembler<[u8; 6]>>,
}

impl BleAdvFace {
    /// New advertising face over `backend`, sized for BLE 5 **extended**
    /// advertising — the mode large enough for NDNLPv2 fragmentation to apply
    /// (see [`LEGACY_ADV_MTU`] for why legacy can't fragment under NDNLPv2).
    pub fn new(id: FaceId, backend: Arc<dyn AdvBackend>) -> Self {
        Self {
            id,
            backend,
            mtu: EXTENDED_ADV_MTU,
            framing: BleFraming::Ndnlpv2,
            signal_sink: None,
            reasm: Mutex::new(PerSenderReassembler::new()),
        }
    }

    /// Use the **NDNts / esp8266ndn** 1-byte fragmentation header instead of
    /// NDNLPv2. Per-fragment overhead drops from ~50 B to ~1 B, so it fits a
    /// legacy advertisement (where NDNLPv2 cannot fragment) and interoperates
    /// with stock NDNts / esp8266ndn peers — at the cost of the NDNLPv2 feature
    /// set (Nack, PitToken, reliability). The face owns framing and
    /// **per-sender** reassembly; [`into_face`](Self::into_face) pairs it with a
    /// passthrough link service accordingly.
    pub fn ndnts_framing(mut self) -> Self {
        self.framing = BleFraming::Ndnts;
        self
    }

    /// Opt into **legacy** advertising sizing (≈26 B). Pair with
    /// [`ndnts_framing`](Self::ndnts_framing): under NDNLPv2, legacy is below
    /// the fragmentation floor. See [`LEGACY_ADV_MTU`].
    pub fn legacy(mut self) -> Self {
        self.mtu = LEGACY_ADV_MTU;
        self
    }

    /// Build a [`Face`] pairing this transport with the link service its
    /// framing needs: `LpLinkService` for NDNLPv2 (the engine fragments and
    /// reassembles), or `PassthroughLinkService` for NDNts (this face owns
    /// framing + per-sender reassembly). Add the result to the engine via the
    /// face-table's pre-built-face path.
    pub fn into_face(self) -> Face {
        match self.framing {
            BleFraming::Ndnlpv2 => Face::from_transport(self),
            BleFraming::Ndnts => Face::new(Arc::new(self), Arc::new(PassthroughLinkService)),
        }
    }

    /// Override the advertising payload budget explicitly (e.g. for a custom
    /// PHY or a controller with a different usable size).
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

    /// Receive one scanned frame, publishing its RSSI to the sink if wired.
    async fn recv_inner(&self) -> Result<ScannedFrame, FaceError> {
        let scanned = self.backend.next_scanned().await?;
        if let (Some(sink), Some(rssi)) = (self.signal_sink.as_ref(), scanned.rssi_dbm) {
            sink.set_link(
                self.id,
                LinkSignals {
                    rssi_dbm: Some(rssi),
                    updated_ms: now_ms(),
                    ..LinkSignals::default()
                },
            );
        }
        Ok(scanned)
    }
}

impl Transport for BleAdvFace {
    fn id(&self) -> FaceId {
        self.id
    }

    fn kind(&self) -> FaceKind {
        // Reuse the Bluetooth kind: a wire kind (LP framing on), NonLocal
        // scope. `link_type() == AdHoc` is what distinguishes the connectionless
        // advertising bearer from the GATT faces.
        FaceKind::Bluetooth
    }

    fn remote_uri(&self) -> Option<String> {
        Some("ble-adv://broadcast".to_string())
    }

    fn link_type(&self) -> LinkType {
        LinkType::AdHoc
    }

    fn send_mtu(&self) -> Option<usize> {
        Some(self.mtu)
    }

    async fn send_bytes(&self, wire: Bytes) -> Result<(), FaceError> {
        match self.framing {
            // NDNLPv2: the LpLinkService already framed/fragmented; each call is
            // one advert.
            BleFraming::Ndnlpv2 => self.backend.broadcast(wire).await,
            // NDNts: this face fragments the whole packet into 1-byte-header
            // adverts (paired with a passthrough link service).
            BleFraming::Ndnts => {
                for frag in BleFraming::Ndnts.frame(&wire, self.mtu, &mut 0) {
                    self.backend.broadcast(frag).await?;
                }
                Ok(())
            }
        }
    }

    async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
        self.recv_bytes_with_addr().await.map(|(b, _)| b)
    }

    async fn recv_bytes_with_addr(&self) -> Result<(Bytes, Option<FaceAddr>), FaceError> {
        match self.framing {
            BleFraming::Ndnlpv2 => {
                let s = self.recv_inner().await?;
                Ok((s.frame, s.addr.map(FaceAddr::Ether)))
            }
            // NDNts: feed each scanned advert into the per-sender reassembler
            // (keyed by BD_ADDR) and surface only complete packets.
            BleFraming::Ndnts => loop {
                let s = self.recv_inner().await?;
                let key = s.addr.unwrap_or([0u8; 6]);
                let whole = self.reasm.lock().unwrap().feed(key, &s.frame);
                if let Some(pkt) = whole {
                    return Ok((pkt, s.addr.map(FaceAddr::Ether)));
                }
            },
        }
    }

    /// Advertising payload size is fixed at construction (legacy vs extended).
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

// Hardware-free loopback bus (tests + simulation)
mod loopback;
pub use loopback::{LoopbackAdvBus, LoopbackEndpoint};

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::time::Duration;

    use ndn_signals_core::{NodeSignals, SignalView};

    const ADDR_A: [u8; 6] = [0xA0; 6];
    const ADDR_B: [u8; 6] = [0xB0; 6];

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
    async fn broadcast_reaches_peer_not_self() {
        let bus = LoopbackAdvBus::new();
        let a = Arc::new(bus.endpoint(1, ADDR_A, -50));
        let b = Arc::new(bus.endpoint(2, ADDR_B, -60));

        a.broadcast(Bytes::from_static(b"hello")).await.unwrap();

        // B hears A's advertisement, with A's address and B's observed RSSI.
        let got = tokio::time::timeout(Duration::from_millis(200), b.next_scanned())
            .await
            .expect("B should hear A")
            .unwrap();
        assert_eq!(got.frame, Bytes::from_static(b"hello"));
        assert_eq!(got.addr, Some(ADDR_A));
        assert_eq!(got.rssi_dbm, Some(-60));

        // A does NOT hear its own transmission (half-duplex radio).
        let self_heard = tokio::time::timeout(Duration::from_millis(100), a.next_scanned()).await;
        assert!(self_heard.is_err(), "a node must not hear its own advert");
    }

    #[tokio::test]
    async fn recv_publishes_rssi_to_sink() {
        let bus = LoopbackAdvBus::new();
        let sink = Arc::new(TestSink::default());
        let face = BleAdvFace::new(FaceId(7), Arc::new(bus.endpoint(7, ADDR_A, -42)))
            .with_signal_sink(sink.clone());
        let peer = Arc::new(bus.endpoint(8, ADDR_B, -42));

        peer.broadcast(Bytes::from_static(b"x")).await.unwrap();

        let (frame, addr) =
            tokio::time::timeout(Duration::from_millis(200), face.recv_bytes_with_addr())
                .await
                .expect("face should hear peer")
                .unwrap();
        assert_eq!(frame, Bytes::from_static(b"x"));
        assert!(
            matches!(addr, Some(FaceAddr::Ether(a)) if a == ADDR_B),
            "scanned frame must carry the sender BD_ADDR"
        );
        assert_eq!(
            sink.link(FaceId(7)).and_then(|s| s.rssi_dbm),
            Some(-42),
            "scanned RSSI must be published to the signal sink for this face"
        );
    }

    #[test]
    fn face_is_ad_hoc_with_small_mtu() {
        let bus = LoopbackAdvBus::new();
        let face = BleAdvFace::new(FaceId(1), Arc::new(bus.endpoint(1, ADDR_A, -50)));
        assert_eq!(face.link_type(), LinkType::AdHoc);
        assert_eq!(face.send_mtu(), Some(EXTENDED_ADV_MTU));
        assert_eq!(face.kind(), FaceKind::Bluetooth);
        let legacy = BleAdvFace::new(FaceId(1), Arc::new(bus.endpoint(1, ADDR_A, -50))).legacy();
        assert_eq!(legacy.send_mtu(), Some(LEGACY_ADV_MTU));
    }

    /// NDNts framing fits a legacy-advert MTU (where NDNLPv2 can't fragment):
    /// a 300-byte packet sent over 26-byte adverts is reassembled per-sender on
    /// the receiving face.
    #[tokio::test]
    async fn ndnts_legacy_round_trip_between_faces() {
        let bus = LoopbackAdvBus::new();
        let tx = BleAdvFace::new(FaceId(1), Arc::new(bus.endpoint(1, ADDR_A, -50)))
            .legacy()
            .ndnts_framing();
        let rx = BleAdvFace::new(FaceId(2), Arc::new(bus.endpoint(2, ADDR_B, -55)))
            .legacy()
            .ndnts_framing();

        // Valid Data TLV (0x06, 3-byte length 300) so reassembly can find the end.
        let pkt = {
            let mut v = vec![0x06u8, 253, 0x01, 0x2C];
            v.extend((0..300u32).map(|i| (i % 251) as u8));
            Bytes::from(v)
        };

        tx.send_bytes(pkt.clone()).await.unwrap();

        let (got, _addr) =
            tokio::time::timeout(Duration::from_millis(300), rx.recv_bytes_with_addr())
                .await
                .expect("rx should reassemble")
                .unwrap();
        assert_eq!(
            got, pkt,
            "NDNts framing must reassemble a large packet across legacy-sized adverts"
        );
    }
}
