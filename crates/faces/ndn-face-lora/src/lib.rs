//! Connectionless **LoRa** face for ndn-rs — a named-radio bearer over a
//! serial-bridged SX126x radio (`ndn_radio_drivers::LoraSerialBackend`, or any
//! [`FrameIo`]), with **plan-driven link FEC**.
//!
//! LoRa is the bearer where redundancy matters *most*: half-duplex, no ARQ, and
//! airtime measured in the hundreds of milliseconds per frame, so a lost frame is
//! expensive to notice and expensive to re-request. It also has no per-frame rate
//! knob — spreading factor / coding rate are set out-of-band via
//! [`RadioKnobs`](ndn_radio_hal) — which makes it the textbook case for the
//! bearer-agnostic [`LinkFecBridge`](ndn_coding::link_fec_bridge): the face mounts
//! the bridge with a plain-inject sink (no per-generation pin) and the cognitive
//! plane's [`TxParams::link_fec_redundancy`] actuates the parity count per name,
//! exactly as it does on Wi-Fi (tasks #32-#34), with none of the MCS machinery.
//!
//! Like [`ndn-face-ble-adv`] and the Wi-Fi monitor face, this is an
//! `AdHoc` broadcast bearer: the NDN *name* is the addressing, there is no
//! association, and every LoRa receiver in range hears every frame and evaluates
//! it against its own PIT/FIB/CS. Pair it with the engine's `LpLinkService` via
//! [`into_face`](LoraFace::into_face) so NDN packets larger than one LoRa frame
//! fragment across frames (NDNLPv2) — and, when FEC is on, ride generations.
//!
//! [`TxParams::link_fec_redundancy`]: ndn_radio_cognition::TxParams::link_fec_redundancy
//! [`ndn-face-ble-adv`]: https://docs.rs/ndn-face-ble-adv

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use bytes::Bytes;
use ndn_coding::link_fec_bridge::{GenerationSink, LinkFecBridge};
use ndn_radio_cognition::TxParams;
use ndn_radio_hal::{FaceError, FrameIo, InjectFrame, TxIntent};
use ndn_transport::{
    Face, FaceAddr, FaceId, FaceKind, FacePersistency, LinkType, MtuError, PersistencyError,
    Transport,
};

/// A single LoRa frame's payload ceiling. The paired `LpLinkService` fragments
/// larger NDN packets to this. Kept conservative — the SX126x + our serial framing
/// cap a frame well under 255 B, and the driver rejects an oversize `inject`.
pub const LORA_MTU: usize = 200;

/// Source frames per FEC generation (K). Deliberately small for LoRa: at high
/// spreading factors one frame is hundreds of ms of airtime, so a large K would
/// make a generation span many seconds and stall everything behind it. K=2 keeps
/// the generation short while still letting one lost frame be recovered (with R≥1).
const LORA_FEC_K: usize = 2;

/// How long a partial generation waits before a tail-flush. Generous for LoRa —
/// a frame can take ~1 s at SF12, so a tight window would flush half-empty
/// generations constantly. The face's caller can override via [`with_link_fec`].
const LORA_FEC_WINDOW: Duration = Duration::from_secs(3);

/// The LoRa injection specifics the bearer-agnostic [`LinkFecBridge`] delegates:
/// put each coded frame of a generation on the air via the serial radio. LoRa has
/// no per-generation pin (its SF/CR are set out-of-band), so `Pin = ()` — this is
/// the plain-inject case, sharing the same [`FrameIo`] handle the face uses for RX.
struct LoraFecSink {
    radio: Arc<dyn FrameIo>,
}

impl GenerationSink for LoraFecSink {
    type Pin = ();

    async fn emit(&self, coded: Vec<Bytes>, _pin: &()) {
        for f in coded {
            // Broadcast: LoRa carries no link addressing here (the name is the
            // addressing), so dst/src are advisory and the driver ignores them.
            let _ = self
                .radio
                .inject(InjectFrame {
                    payload: f,
                    tx: TxIntent::CONSERVATIVE,
                    dst: [0xff; 6],
                    src: [0x02, b'l', b'o', b'r', b'a', 0x00],
                })
                .await;
        }
    }
}

enum Egress {
    /// Plain: each `send_bytes` is one LoRa frame (the `LpLinkService` already
    /// fragmented). No redundancy.
    Direct,
    /// Link FEC: frames batch into generations; the plan's parity count actuates
    /// per generation. The bridge owns the batching/decode; this face reads the
    /// plan and feeds it in.
    Fec(LinkFecBridge<()>),
}

/// A connectionless LoRa broadcast face. Build a [`Face`] with
/// [`into_face`](Self::into_face); the engine treats it as an ad-hoc bearer.
pub struct LoraFace {
    id: FaceId,
    radio: Arc<dyn FrameIo>,
    egress: Egress,
    /// Recovered payloads awaiting `recv_bytes` (FEC decode can yield 0/1/many).
    pending: Mutex<VecDeque<Bytes>>,
    /// Control-plane [`TxParams`] cell — `link_fec_redundancy` is the only field
    /// this bearer reads (no MCS). Written by the cognitive actuator, read per send.
    planned: Option<Arc<RwLock<Option<TxParams>>>>,
}

impl LoraFace {
    /// A plain LoRa face over `radio` (no link FEC). Every `send_bytes` is one
    /// frame; the paired `LpLinkService` fragments larger packets.
    pub fn new(id: FaceId, radio: Arc<dyn FrameIo>) -> Self {
        Self {
            id,
            radio,
            egress: Egress::Direct,
            pending: Mutex::new(VecDeque::new()),
            planned: None,
        }
    }

    /// Enable **plan-driven link FEC**: source frames batch into generations of `k`
    /// (or [`LORA_FEC_K`]), transmitted as `k + R` coded frames where `R` is the
    /// plan's [`link_fec_redundancy`], recoverable from any `k` of the `n`. `window`
    /// bounds a partial generation's tail-flush (default [`LORA_FEC_WINDOW`]).
    ///
    /// The initial `R` is 0 — the real value comes from the plan per frame, so a
    /// face with no plan cell transmits plain (no parity) until one is attached.
    ///
    /// [`link_fec_redundancy`]: ndn_radio_cognition::TxParams::link_fec_redundancy
    pub fn with_link_fec(mut self, k: Option<usize>, window: Option<Duration>) -> Self {
        let sink = LoraFecSink { radio: Arc::clone(&self.radio) };
        let bridge = LinkFecBridge::spawn(
            sink,
            k.unwrap_or(LORA_FEC_K),
            0,
            window.unwrap_or(LORA_FEC_WINDOW),
        );
        self.egress = Egress::Fec(bridge);
        self
    }

    /// Let the cognitive control plane drive per-name link FEC: its actuator writes
    /// the decided [`TxParams`] into `cell`, and this face reads
    /// `link_fec_redundancy` from it on each send. No effect without
    /// [`with_link_fec`](Self::with_link_fec).
    pub fn with_planned_params(mut self, cell: Arc<RwLock<Option<TxParams>>>) -> Self {
        self.planned = Some(cell);
        self
    }

    /// Build a [`Face`] pairing this transport with the engine's `LpLinkService`,
    /// so NDN packets fragment/reassemble across LoRa frames (and, under FEC, ride
    /// generations).
    pub fn into_face(self) -> Face {
        Face::from_transport(self)
    }

    /// Parity the plan wants on the next generation (`None` = leave the bridge's
    /// current R). The actuator for [`TxParams::link_fec_redundancy`] on LoRa.
    fn planned_redundancy(&self) -> Option<u16> {
        self.planned
            .as_ref()
            .and_then(|c| c.read().ok().and_then(|g| *g))
            .and_then(|tp| tp.link_fec_redundancy)
    }
}

impl Transport for LoraFace {
    fn id(&self) -> FaceId {
        self.id
    }

    fn kind(&self) -> FaceKind {
        // A wire kind (LP framing on), NonLocal scope; `link_type() == AdHoc`
        // marks the connectionless broadcast bearer, as for BLE-adv / monitor-wifi.
        FaceKind::Wfb
    }

    fn remote_uri(&self) -> Option<String> {
        Some("lora://broadcast".to_string())
    }

    fn link_type(&self) -> LinkType {
        LinkType::AdHoc
    }

    fn send_mtu(&self) -> Option<usize> {
        Some(LORA_MTU)
    }

    async fn send_bytes(&self, wire: Bytes) -> Result<(), FaceError> {
        match &self.egress {
            Egress::Direct => {
                self.radio
                    .inject(InjectFrame {
                        payload: wire,
                        tx: TxIntent::CONSERVATIVE,
                        dst: [0xff; 6],
                        src: [0x02, b'l', b'o', b'r', b'a', 0x00],
                    })
                    .await
            }
            // The plan's redundancy rides in with the frame (same pattern as the
            // Wi-Fi face's MCS): the bridge applies it at the next generation
            // boundary, because R is a whole-generation property.
            Egress::Fec(bridge) => bridge.send(wire, (), self.planned_redundancy()),
        }
    }

    async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
        self.recv_bytes_with_addr().await.map(|(b, _)| b)
    }

    async fn recv_bytes_with_addr(&self) -> Result<(Bytes, Option<FaceAddr>), FaceError> {
        match &self.egress {
            Egress::Direct => {
                let cf = self.radio.recv_frame().await?;
                Ok((cf.payload, cf.addr.map(FaceAddr::Ether)))
            }
            // Feed each captured frame through the FEC decoder; source frames come
            // back immediately, parity recovers missing ones (0/1/many per frame).
            // Buffer the extras and drain across calls.
            Egress::Fec(bridge) => loop {
                if let Some(p) = self.pending.lock().unwrap().pop_front() {
                    return Ok((p, None));
                }
                let cf = self.radio.recv_frame().await?;
                let addr = cf.addr;
                let delivered = bridge.decode(cf.payload);
                if delivered.is_empty() {
                    continue;
                }
                let mut q = self.pending.lock().unwrap();
                q.extend(delivered);
                if let Some(p) = q.pop_front() {
                    return Ok((p, addr.map(FaceAddr::Ether)));
                }
            },
        }
    }

    /// The LoRa frame size is fixed by the radio + serial framing.
    fn set_send_mtu(&self, _mtu: Option<u64>) -> Result<Option<u64>, MtuError> {
        Err(MtuError::Immutable)
    }

    /// A broadcast medium has no per-peer connection to keep alive.
    fn set_persistency(&self, _p: FacePersistency) -> Result<(), PersistencyError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_frame_io::LoopbackMonitorBus;
    use ndn_transport::Transport;

    /// A K=2 generation with the plan forcing R=2 must put 4 frames on air, and the
    /// peer's FEC face must decode the 2 source frames back out — proving the
    /// plan-driven link-FEC path end to end over a `FrameIo` bearer (the LoRa case,
    /// on the loopback bus since real LoRa needs a serial dongle). Mirrors the
    /// Wi-Fi face's regression test; erasure recovery itself is covered by
    /// `ndn_coding::link_fec` unit tests.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn plan_driven_fec_round_trips_over_a_frameio_bearer() {
        let bus = LoopbackMonitorBus::new();
        let cell = Arc::new(RwLock::new(Some(TxParams {
            link_fec_redundancy: Some(2),
            ..Default::default()
        })));
        let tx = LoraFace::new(FaceId(1), Arc::new(bus.endpoint(1, -60)))
            .with_link_fec(Some(2), Some(Duration::from_millis(50)))
            .with_planned_params(cell);
        let rx = LoraFace::new(FaceId(2), Arc::new(bus.endpoint(2, -60)))
            .with_link_fec(Some(2), Some(Duration::from_millis(50)));

        let sent: Vec<Bytes> = (0..2u8).map(|i| Bytes::from(vec![i; 16])).collect();
        for w in &sent {
            tx.send_bytes(w.clone()).await.unwrap();
        }
        let mut got = Vec::new();
        for _ in 0..2 {
            let (b, _) = tokio::time::timeout(Duration::from_secs(2), rx.recv_bytes_with_addr())
                .await
                .expect("FEC face should deliver the generation")
                .unwrap();
            got.push(b);
        }
        got.sort();
        let mut want = sent;
        want.sort();
        assert_eq!(got, want, "plan-driven LoRa FEC face round-trips the generation");
    }

    /// A plain (no-FEC) face is a straight passthrough: one send, one frame, one
    /// recv — the fragmentation-only path when the plan asks for no redundancy.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn plain_face_passes_frames_through() {
        let bus = LoopbackMonitorBus::new();
        let tx = LoraFace::new(FaceId(1), Arc::new(bus.endpoint(1, -60)));
        let rx = LoraFace::new(FaceId(2), Arc::new(bus.endpoint(2, -60)));
        tx.send_bytes(Bytes::from_static(b"hello-lora")).await.unwrap();
        let (b, _) = tokio::time::timeout(Duration::from_secs(2), rx.recv_bytes_with_addr())
            .await
            .expect("plain face delivers")
            .unwrap();
        assert_eq!(&b[..], b"hello-lora");
    }
}
