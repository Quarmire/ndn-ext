//! Desktop driver for userspace **Wi-Fi Aware (NAN)**.
//!
//! This crate is the I/O half of the NAN stack: it drives the sans-I/O
//! [`ndn_nan_core::NanEngine`] from a [`FrameIo`] monitor radio + a tokio timer,
//! and presents the [`NanBackend`] that
//! `ndn-face-wifi-aware`'s `NanCoordFace` / `NanDiscovery` already consume. So a
//! commodity monitor-mode Wi-Fi adapter becomes a real NAN radio with no kernel
//! NAN support — the cluster sync, Discovery-Window scheduling, service matching,
//! and follow-up coordination all run in userspace over raw 802.11 inject/capture
//! (see `ndn-face-wifi-aware/docs/NAMED_RADIO_EXPANSION_DESIGN.md`).
//!
//! ```ignore
//! let bus = ndn_frame_io::LoopbackMonitorBus::new();          // or a real FrameIo backend
//! let radio: Arc<dyn FrameIo> = Arc::new(bus.endpoint(1, -50));
//! let backend = ndn_nan::spawn(radio, NanConfig::new(nmi, 6, 200), None);
//! // `backend: Arc<NanDriver>` is a NanBackend — hand it to NanCoordFace::new(..).
//! ```
//!
//! ## Architecture
//!
//! A single **engine task** owns the (non-`Sync`) [`NanEngine`] and is the only
//! thing that touches it. The [`NanBackend`] methods are thin shims that send
//! commands to that task over a channel and receive results back:
//!
//! - `publish`/`subscribe` → register a service function (the task also records
//!   the service-name ↔ service-ID mapping so [`drain_matches`] can name peers).
//! - `broadcast` → queue a follow-up to every matched peer.
//! - `next_followup` → await the next follow-up the task delivered.
//! - `drain_matches` → take the discovered peers the task accumulated.
//! - `request_ndp` → run the M1-M4 NDP handshake to a peer and return an
//!   [`NdpLink`] whose socket is **already bound** to our end of the link-local
//!   pair the handshake settled. Wrap it in a `UdpFace` to reach a stock Wi-Fi
//!   Aware peer, which speaks IPv6/UDP and nothing else. This is an interop
//!   bearer, not this stack's data path — our own traffic rides
//!   `FrameFormat::RawNdn`, where the name is the addressing.
//!
//! A separate reader task forwards captured frames into the engine task, so the
//! engine loop's `select!` never has to cancel a half-completed `recv_frame`.
//!
//! ## The data path (NDP / NDI)
//!
//! [`spawn_with`] takes an optional [`ndi::DataInterface`] — a TAP device whose
//! MAC *is* our NAN Data Interface, so the kernel gives it exactly the `fe80::`
//! address the handshake advertised. The engine task bridges it both ways:
//! Ethernet frames the kernel writes to the interface go on the air as 802.11
//! data frames addressed to the peer's NDI, and data frames off the air addressed
//! to ours are handed back up. That conversion is what a kernel/firmware NAN stack
//! does inside the device; a userspace monitor-mode stack does it in [`ndi`].
//! Without an NDI the engine still negotiates paths — they just have nothing to
//! carry traffic over, and `request_ndp` is refused.
//!
//! **NDP is an interop bearer, not our data path.** It addresses by host (NDI MAC,
//! `fe80::`, UDP port); our own traffic rides `FrameFormat::RawNdn`, where the NDN
//! name is the addressing. See
//! `ndn-face-wifi-aware/docs/NAMED_RADIO_COURSE_CORRECTION.md`.
//!
//! [`drain_matches`]: ndn_face_wifi_aware::NanBackend::drain_matches

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use ndn_face_wifi_aware::{
    FaceError, FollowupFrame, NanBackend, NanMatch, NanServiceName, NdpLink,
};
use ndn_frame_io::{BROADCAST, CapturedFrame, FrameIo, InjectFrame, TxIntent};
use ndn_nan_core::{NanConfig, NanEngine, NanEvent, RxFrame, ServiceId, service_id};
use ndn_radio_hal::{Bandwidth, RadioKnobs};
use ndn_time::RadioHwClock;

use crate::ndi::{DataInterface, DuplicateFilter, MAX_ETHERNET_FRAME, dot11_to_eth, eth_to_dot11};
use tokio::sync::mpsc;

pub mod ndi;

pub use ndn_nan_core::NanConfig as Config;

/// The slow control-plane knob the engine needs: tune the radio to a channel.
///
/// A tiny trait of its own because the engine wants *only* this one verb — but
/// any radio exposing the HAL's [`RadioKnobs`] control plane satisfies it via
/// [`knobs_channel`], so a real device needs no bespoke adapter.
pub trait RadioChannel: Send + Sync + 'static {
    fn set_channel(&self, channel: u8) -> Result<(), FaceError>;
}

/// Adapts the HAL's control-plane contract to the one verb the engine needs.
///
/// NAN discovery is a 20 MHz affair (operating class 81 on 2.4 GHz, and the
/// 5 GHz discovery channels likewise), so the width is pinned rather than
/// plumbed: a caller who needs a different width is not doing NAN discovery.
struct KnobsChannel<K>(Arc<K>);

impl<K: RadioKnobs + 'static> RadioChannel for KnobsChannel<K> {
    fn set_channel(&self, channel: u8) -> Result<(), FaceError> {
        self.0.set_channel(channel, Bandwidth::Bw20)
    }
}

/// Drive the engine's channel through any radio's [`RadioKnobs`].
///
/// Pass the result as [`spawn`]'s `channel` argument. This is what lets the
/// sans-I/O engine retune a real device — a USB monitor dongle, an AF_PACKET
/// port — without `ndn-nan` depending on any particular driver.
///
/// ```ignore
/// let radio = Arc::new(Rtl8812auBackend::open()?);
/// let nan = ndn_nan::spawn(radio.clone(), cfg, Some(knobs_channel(radio)));
/// ```
pub fn knobs_channel<K: RadioKnobs + 'static>(knobs: Arc<K>) -> Arc<dyn RadioChannel> {
    Arc::new(KnobsChannel(knobs))
}

/// The UDP port a data path's traffic uses.
///
/// A well-known port rather than a negotiated one. NDPE *does* carry a transport
/// port — in its Service Info TLV — but the Wi-Fi Aware sub-TLV layout for that
/// body is not in the open dissector (it is the paywalled part), and inventing
/// bytes there would put a fabricated claim of WFA semantics on the air. A fixed
/// port needs no wire format at all.
///
/// The cost is one data path per node: the socket is bound to *this* port on our
/// NDI, so a second concurrent path would collide. Multiple peers need the real
/// per-path port exchange.
pub const NDP_PORT: u16 = 6363;

/// Who to hand a negotiated data path back to.
type NdpReply = tokio::sync::oneshot::Sender<Result<NdpLink, FaceError>>;

/// A command from a [`NanBackend`] method to the engine task.
enum Command {
    Publish(String, Vec<u8>),
    Subscribe(String, bool),
    Broadcast(Bytes),
    /// Ask for a data path to a peer; the reply carries the bound socket.
    RequestNdp([u8; 6], NdpReply),
}

/// State shared between the engine task (writer) and the [`NanDriver`] handle
/// (reader): the service-name table and the discovered-peer queue.
#[derive(Default)]
struct Shared {
    /// service ID → the name that produced it (to name matches; the hash can't
    /// be reversed).
    name_by_id: Mutex<HashMap<ServiceId, NanServiceName>>,
    /// Discovered peers awaiting `drain_matches`.
    matches: Mutex<Vec<NanMatch>>,
}

/// A NAN radio backend over a userspace monitor-mode engine. Construct with
/// [`spawn`]; it implements [`NanBackend`], so it drops into
/// `NanCoordFace::new(id, backend)` / `NanDiscovery::new(backend, ..)`.
pub struct NanDriver {
    cmd_tx: mpsc::UnboundedSender<Command>,
    followups: tokio::sync::Mutex<mpsc::UnboundedReceiver<FollowupFrame>>,
    shared: Arc<Shared>,
}

/// Start a userspace NAN engine over `frame_io`, returning a [`NanBackend`].
///
/// `cfg` carries the node's NMI, master preference, and discovery channel.
/// `channel` tunes a real radio on start-up (pass `None` for loopback or a radio
/// already parked on the discovery channel). Must be called from within a tokio
/// runtime (it spawns the engine + reader tasks).
pub fn spawn(
    frame_io: Arc<dyn FrameIo>,
    cfg: NanConfig,
    channel: Option<Arc<dyn RadioChannel>>,
) -> Arc<NanDriver> {
    spawn_with(frame_io, cfg, channel, None)
}

/// Like [`spawn`], but also **bridges a NAN Data Interface** to the radio.
///
/// With an `ndi`, a negotiated data path carries real traffic: Ethernet frames
/// the kernel writes to the interface go out as 802.11 data frames addressed to
/// the peer's NDI, and data frames off the air addressed to ours are handed back
/// up. Without one, the engine still negotiates paths — they just have nothing to
/// carry traffic over.
pub fn spawn_with(
    frame_io: Arc<dyn FrameIo>,
    cfg: NanConfig,
    channel: Option<Arc<dyn RadioChannel>>,
    ndi: Option<Arc<dyn DataInterface>>,
) -> Arc<NanDriver> {
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let (fu_tx, fu_rx) = mpsc::unbounded_channel();
    let shared = Arc::new(Shared::default());
    let task = EngineTask {
        nmi: cfg.nmi,
        engine: NanEngine::new(cfg),
        frame_io,
        channel,
        ndi,
        ndi_seq: 0,
        ndi_dupes: DuplicateFilter::new(),
        cmd_rx,
        fu_tx,
        shared: Arc::clone(&shared),
        ndp_waiters: HashMap::new(),
        hw_clock: RadioHwClock::realtek(),
    };
    tokio::spawn(task.run());
    Arc::new(NanDriver {
        cmd_tx,
        followups: tokio::sync::Mutex::new(fu_rx),
        shared,
    })
}

impl NanDriver {
    /// Publish `service` with `service_info` (the SDA's service-specific info) —
    /// what a stock subscriber surfaces / parses to describe the peer (e.g.
    /// ndn-ripple expects a `Presence` descriptor here). The plain
    /// [`NanBackend::publish`] sends empty info.
    pub fn publish_with_info(&self, service: &str, service_info: Vec<u8>) -> Result<(), FaceError> {
        self.cmd_tx
            .send(Command::Publish(service.to_string(), service_info))
            .map_err(|_| FaceError::Closed)
    }
}

#[async_trait]
impl NanBackend for NanDriver {
    async fn broadcast(&self, frame: Bytes) -> Result<(), FaceError> {
        self.cmd_tx
            .send(Command::Broadcast(frame))
            .map_err(|_| FaceError::Closed)
    }

    async fn next_followup(&self) -> Result<FollowupFrame, FaceError> {
        self.followups
            .lock()
            .await
            .recv()
            .await
            .ok_or(FaceError::Closed)
    }

    async fn publish(&self, service: &NanServiceName) -> Result<(), FaceError> {
        self.cmd_tx
            .send(Command::Publish(service.0.clone(), Vec::new()))
            .map_err(|_| FaceError::Closed)
    }

    async fn subscribe(&self, service: &NanServiceName) -> Result<(), FaceError> {
        // Active subscribe — we transmit a Subscribe SDF so peers can discover us
        // (the symmetric coordination model NanCoordFace expects).
        self.cmd_tx
            .send(Command::Subscribe(service.0.clone(), true))
            .map_err(|_| FaceError::Closed)
    }

    /// Negotiate a NAN data path to `peer` and return a socket bound over the NDI.
    ///
    /// Runs the M1-M4 exchange, then binds our end of the link-local pair the
    /// handshake settled. Wrap the result in a `UdpFace` for bulk transfer.
    ///
    /// Requires an NDI (see [`spawn_with`]) — without one there is nothing to bind
    /// a socket to. Errors if the peer refuses or never answers.
    async fn request_ndp(&self, peer: [u8; 6]) -> Result<NdpLink, FaceError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.cmd_tx
            .send(Command::RequestNdp(peer, tx))
            .map_err(|_| FaceError::Closed)?;
        // The engine task answers when the handshake settles — or when it gives
        // up, which it always eventually does (the initiator's request has a
        // bounded attempt budget), so this cannot wait forever.
        rx.await.map_err(|_| FaceError::Closed)?
    }

    fn drain_matches(&self) -> Vec<NanMatch> {
        std::mem::take(&mut self.shared.matches.lock().unwrap())
    }
}

/// The sole owner of the [`NanEngine`]; runs the poll loop.
struct EngineTask {
    nmi: [u8; 6],
    engine: NanEngine,
    frame_io: Arc<dyn FrameIo>,
    channel: Option<Arc<dyn RadioChannel>>,
    /// The data interface a negotiated path carries traffic over, if bridged.
    ndi: Option<Arc<dyn DataInterface>>,
    /// Sequence counter for the data frames we put on air (the engine owns its
    /// own for management frames).
    ndi_seq: u16,
    /// Drops 802.11 retransmissions before they reach the kernel twice.
    ndi_dupes: DuplicateFilter,
    cmd_rx: mpsc::UnboundedReceiver<Command>,
    fu_tx: mpsc::UnboundedSender<FollowupFrame>,
    shared: Arc<Shared>,
    /// Callers blocked in `request_ndp`, keyed by the path they asked for.
    ndp_waiters: HashMap<([u8; 6], u8), NdpReply>,
    /// Disciplines the engine's clock onto the hardware RX TSF (#41), so the TSF / Discovery-Window
    /// slots anchor on sub-µs hardware time instead of the ~55-µs-jittery userspace clock.
    hw_clock: RadioHwClock,
}

// The disciplined hardware clock is the shared `ndn_time::RadioHwClock` (#41). It used to be a private
// `HwClock` here, but the disciplined hardware clock is a *shared substrate* — the named-radio
// time-slice/FHSS scheduler, cognition, and the cross-node common-view pool are the other consumers —
// so it now lives in `ndn-time` next to `LinkStamp`/`Discipline`, and the nan runtime is one consumer
// of it. See the "why nan only" note in hardware-tsf-common-view.

impl EngineTask {
    async fn run(mut self) {
        let base = Instant::now();

        // Reader task: forward captured frames in (decouples `recv_frame`
        // cancel-safety from the select loop below).
        let (rx_tx, mut rx_rx) = mpsc::unbounded_channel::<CapturedFrame>();
        {
            let fio = Arc::clone(&self.frame_io);
            tokio::spawn(async move {
                while let Ok(cf) = fio.recv_frame().await {
                    if rx_tx.send(cf).is_err() {
                        break; // engine task gone
                    }
                }
            });
        }

        // NDI pump: the kernel's Ethernet frames, off the interface's blocking fd
        // on its own thread, into the loop below.
        let (mut ndi_rx, _pump) = match &self.ndi {
            Some(ndi) => {
                let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
                let ndi = Arc::clone(ndi);
                let h = std::thread::spawn(move || {
                    let mut buf = [0u8; MAX_ETHERNET_FRAME];
                    loop {
                        match ndi.read_frame(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => {
                                if tx.send(buf[..n].to_vec()).is_err() {
                                    break; // engine task gone
                                }
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                            Err(e) => {
                                tracing::warn!(error = %e, "NDI read failed; bridge stopping");
                                break;
                            }
                        }
                    }
                });
                (Some(rx), Some(h))
            }
            None => (None, None),
        };

        // Prime: set the channel and schedule the first Discovery Window.
        let mut next_wake = self.poll(base, None).await;

        loop {
            let sleep = tokio::time::sleep_until(tokio::time::Instant::from_std(next_wake));
            tokio::select! {
                biased;
                cmd = self.cmd_rx.recv() => match cmd {
                    Some(c) => {
                        self.apply(c);
                        next_wake = self.poll(base, None).await;
                    }
                    None => break, // all NanDriver handles dropped
                },
                rx = rx_rx.recv() => match rx {
                    Some(cf) => next_wake = self.poll(base, Some(cf)).await,
                    None => break, // reader ended (radio closed)
                },
                // `recv()` on an Option<Receiver>: with no NDI this branch is
                // disabled rather than resolving instantly and spinning the loop.
                eth = async { ndi_rx.as_mut().unwrap().recv().await }, if ndi_rx.is_some() => {
                    match eth {
                        Some(frame) => self.send_ndi_frame(&frame).await,
                        None => { ndi_rx = None; } // pump thread ended
                    }
                }
                _ = sleep => {
                    next_wake = self.poll(base, None).await;
                }
            }
        }
    }

    /// An Ethernet frame the kernel wrote to the NDI → the air.
    ///
    /// Data-path traffic is *not* gated on the Discovery Window: a DW is the
    /// discovery rendezvous, while a negotiated path has its own schedule and the
    /// peer's NDI is listening. Holding bulk traffic for the next DW would cap it
    /// at one burst per 512 TU.
    async fn send_ndi_frame(&mut self, eth: &[u8]) {
        let cluster = self.engine.cluster_id();
        self.ndi_seq = self.ndi_seq.wrapping_add(1);
        let Some(bytes) = eth_to_dot11(eth, cluster, self.ndi_seq) else {
            return; // not a frame we can carry
        };
        let src = self.ndi.as_ref().map(|n| n.mac()).unwrap_or(self.nmi);
        let frame = InjectFrame {
            payload: Bytes::from(bytes),
            // Bulk over a negotiated path: let the radio pick its rate rather
            // than pinning the most-robust one discovery uses.
            tx: TxIntent::CONSERVATIVE,
            dst: BROADCAST,
            src,
            addr3: None,
        };
        if let Err(e) = self.frame_io.inject(frame).await {
            tracing::debug!(error = %e, "NDI: inject failed");
        }
    }

    /// Hand a captured frame to the NDI if it is data-path traffic for us.
    ///
    /// Returns true when the frame was the NDI's, so the caller does not also feed
    /// it to the engine — one radio, one reader, demuxed by what the frame is.
    fn deliver_to_ndi(&mut self, cf: &CapturedFrame) -> bool {
        let Some(ndi) = &self.ndi else {
            return false;
        };
        let Some(eth) = dot11_to_eth(&cf.payload, ndi.mac()) else {
            return false;
        };
        // A retransmission is still ours — claim it so it never reaches the
        // engine, but do not hand the kernel the same packet twice.
        if self.ndi_dupes.is_duplicate(&cf.payload) {
            return true;
        }
        if let Err(e) = ndi.write_frame(&eth) {
            tracing::warn!(error = %e, "NDI: write failed");
        }
        true
    }

    /// Run one engine `poll`: feed time + an optional captured frame, inject the
    /// resulting frames, apply a channel change, route events, and return the
    /// next wake instant.
    async fn poll(&mut self, base: Instant, inbound: Option<CapturedFrame>) -> Instant {
        let host_now = base.elapsed().as_micros() as u64;
        // #41: discipline the engine's clock onto the hardware RX TSF. Do it from ANY captured frame's
        // stamp (before the NDI demux drops data frames) — every frame is a fresh sub-µs time fix — so
        // the TSF anchor and Discovery-Window slots ride hardware time, not the userspace clock.
        if let Some(stamp) = inbound.as_ref().and_then(|cf| cf.stamp) {
            self.hw_clock.on_stamp(&stamp, host_now);
        }
        let now = self.hw_clock.now(host_now);
        // Demux: a data frame for our NDI is the data path's, not the engine's. The engine would ignore
        // it anyway, but the NDI would never see it — the radio has one reader.
        let inbound = match inbound {
            Some(cf) if self.deliver_to_ndi(&cf) => None,
            other => other,
        };
        let rx_vec: Vec<RxFrame> = match &inbound {
            Some(cf) => vec![RxFrame {
                bytes: &cf.payload,
                rssi_dbm: cf.rssi_dbm,
                // The frame's hardware capture time (≈ its RXTSFL) in the engine's clock domain; equals
                // `now` since it just arrived. Falls back to the software clock when unstamped.
                now_usec: now,
            }],
            None => Vec::new(),
        };
        let step = self.engine.poll(now, &rx_vec);

        if let (Some(ch), Some(ctl)) = (step.set_channel, self.channel.as_ref())
            && let Err(e) = ctl.set_channel(ch)
        {
            tracing::warn!(channel = ch, error = %e, "NAN: set_channel failed");
        }
        for tx in step.tx {
            let frame = InjectFrame {
                payload: Bytes::from(tx.bytes),
                // NAN beacons/SDFs are legacy-rate management frames: maximum
                // robustness, broadcast. The backend maps this to its PHY (the
                // 8812AU NAN backend forces legacy 6 Mbps OFDM regardless).
                tx: TxIntent::ROBUST,
                dst: BROADCAST,
                src: self.nmi,
                addr3: None,
            };
            if let Err(e) = self.frame_io.inject(frame).await {
                tracing::debug!(error = %e, "NAN: inject failed (lossy medium)");
            }
        }
        for ev in step.events {
            self.settle_ndp(&ev).await;
            self.route_event(ev);
        }
        // `wake_at_usec` is in the engine's (hardware) domain; map it back to host-elapsed for the sleep.
        base + Duration::from_micros(self.hw_clock.to_host(step.wake_at_usec))
    }

    fn apply(&mut self, cmd: Command) {
        match cmd {
            Command::Publish(name, ssi) => {
                self.remember(&name);
                self.engine.publish(&name, ssi);
            }
            Command::Subscribe(name, active) => {
                self.remember(&name);
                self.engine.subscribe(&name, active);
            }
            Command::Broadcast(frame) => {
                self.engine.broadcast_followup(frame.to_vec());
            }
            Command::RequestNdp(peer, reply) => {
                if self.ndi.is_none() {
                    let _ = reply.send(Err(FaceError::Io(std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        "no NAN Data Interface bridged — a path would have nothing to carry \
                         traffic over (see ndn_nan::spawn_with)",
                    ))));
                    return;
                }
                let ndp_id = self.engine.request_ndp(peer);
                // Keyed by the path, so a second request for a peer we already
                // have in flight joins the same negotiation.
                self.ndp_waiters.insert((peer, ndp_id), reply);
            }
        }
    }

    /// Turn an established path into something an application can send over.
    ///
    /// The engine settled the addresses; this binds our end and names the peer's.
    /// A link-local address means nothing without its interface, so both ends
    /// carry the NDI's scope id.
    ///
    /// Takes the interface by value rather than borrowing `self`: the engine's
    /// rendezvous strategy is `Send` but not `Sync`, so holding a shared borrow of
    /// the task across this `await` would make the whole engine future non-`Send`.
    async fn ndp_link(
        ndi: Arc<dyn DataInterface>,
        peer_iid: [u8; 8],
    ) -> Result<NdpLink, FaceError> {
        let scope = ndi.index();
        let local = std::net::SocketAddrV6::new(
            ndi::link_local_addr(ndn_nan_core::eui64_iid(ndi.mac())),
            NDP_PORT,
            0,
            scope,
        );
        let socket = tokio::net::UdpSocket::bind(local).await.map_err(|e| {
            FaceError::Io(std::io::Error::new(
                e.kind(),
                format!("bind {local} on the NDI: {e}"),
            ))
        })?;
        let peer_addr =
            std::net::SocketAddrV6::new(ndi::link_local_addr(peer_iid), NDP_PORT, 0, scope);
        Ok(NdpLink {
            socket,
            peer_addr: peer_addr.into(),
        })
    }

    /// Resolve whoever is blocked in `request_ndp` for this path.
    async fn settle_ndp(&mut self, ev: &NanEvent) {
        match ev {
            NanEvent::NdpEstablished {
                peer,
                ndp_id,
                peer_iid,
                ..
            } => {
                if let Some(reply) = self.ndp_waiters.remove(&(*peer, *ndp_id)) {
                    let link = match self.ndi.as_ref().map(Arc::clone) {
                        Some(ndi) => Self::ndp_link(ndi, *peer_iid).await,
                        None => Err(FaceError::Io(std::io::Error::new(
                            std::io::ErrorKind::Unsupported,
                            "no NAN Data Interface",
                        ))),
                    };
                    let _ = reply.send(link);
                }
            }
            NanEvent::NdpFailed {
                peer,
                ndp_id,
                reason,
            } => {
                if let Some(reply) = self.ndp_waiters.remove(&(*peer, *ndp_id)) {
                    let _ = reply.send(Err(FaceError::Io(std::io::Error::other(format!(
                        "NAN data path to {peer:02x?} failed: {reason:?}"
                    )))));
                }
            }
            _ => {}
        }
    }

    /// Record the service-name ↔ service-ID mapping so discovered peers can be
    /// reported by name (the 6-byte hash isn't reversible).
    fn remember(&self, name: &str) {
        self.shared
            .name_by_id
            .lock()
            .unwrap()
            .insert(service_id(name), NanServiceName(name.to_string()));
    }

    fn route_event(&self, ev: NanEvent) {
        match ev {
            NanEvent::Discovered { service, peer, .. } => {
                if let Some(name) = self
                    .shared
                    .name_by_id
                    .lock()
                    .unwrap()
                    .get(&service)
                    .cloned()
                {
                    self.shared.matches.lock().unwrap().push(NanMatch {
                        service: name,
                        peer,
                    });
                }
            }
            NanEvent::Followup {
                peer,
                ssi,
                rssi_dbm,
            } => {
                let _ = self.fu_tx.send(FollowupFrame {
                    frame: Bytes::from(ssi),
                    peer: Some(peer),
                    rssi_dbm,
                });
            }
            // `request_ndp` resolves these into a bound socket (see `ndp_link`);
            // this arm reports paths nobody is waiting on — e.g. one a peer
            // initiated, which we answered but never asked for.
            NanEvent::NdpEstablished {
                peer,
                ndp_id,
                role,
                peer_ndi,
                peer_iid,
            } => {
                tracing::info!(
                    ?role,
                    ndp_id,
                    peer = ?peer,
                    peer_ndi = ?peer_ndi,
                    peer_iid = ?peer_iid,
                    "NAN data path established (no NDI to bind it to yet)"
                );
            }
            NanEvent::NdpFailed {
                peer,
                ndp_id,
                reason,
            } => {
                tracing::warn!(ndp_id, peer = ?peer, ?reason, "NAN data path failed");
            }
            NanEvent::NdpTerminated { peer, ndp_id } => {
                tracing::info!(ndp_id, peer = ?peer, "NAN data path terminated");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_frame_io::LoopbackMonitorBus;
    use std::time::Duration;
    use tokio::time::timeout;

    const NMI_A: [u8; 6] = [0x02, 0, 0, 0, 0, 0xAA];
    const NMI_B: [u8; 6] = [0x02, 0, 0, 0, 0, 0xBB];

    /// Two userspace NAN drivers over a loopback monitor medium: each publishes
    /// and subscribes a coordination service, mutually discovers the other (a
    /// real `NanMatch` via `drain_matches`), then A's `broadcast` follow-up is
    /// delivered to B's `next_followup`. End-to-end through the *real* engine,
    /// `FrameIo`, and `NanBackend` — only the radio is simulated.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn drivers_discover_and_followup_over_loopback() {
        let bus = LoopbackMonitorBus::new();
        let a = spawn(
            Arc::new(bus.endpoint(1, -50)),
            NanConfig::new(NMI_A, 6, 200),
            None,
        );
        let b = spawn(
            Arc::new(bus.endpoint(2, -55)),
            NanConfig::new(NMI_B, 6, 180),
            None,
        );

        let svc = NanServiceName("org.ndn.coord".into());
        a.publish(&svc).await.unwrap();
        a.subscribe(&svc).await.unwrap();
        b.publish(&svc).await.unwrap();
        b.subscribe(&svc).await.unwrap();

        // Mutual discovery (within a couple of Discovery Windows).
        let discover = async {
            let (mut a_saw_b, mut b_saw_a) = (false, false);
            while !(a_saw_b && b_saw_a) {
                for m in a.drain_matches() {
                    if m.peer == NMI_B && m.service == svc {
                        a_saw_b = true;
                    }
                }
                for m in b.drain_matches() {
                    if m.peer == NMI_A && m.service == svc {
                        b_saw_a = true;
                    }
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        };
        timeout(Duration::from_secs(5), discover)
            .await
            .expect("A and B should mutually discover over NAN");

        // A → B follow-up (the connectionless coordination channel).
        a.broadcast(Bytes::from_static(b"interest-wire"))
            .await
            .unwrap();
        let got = timeout(Duration::from_secs(3), b.next_followup())
            .await
            .expect("B should receive A's follow-up in time")
            .expect("follow-up channel open");
        assert_eq!(got.frame, Bytes::from_static(b"interest-wire"));
        assert_eq!(got.peer, Some(NMI_A));
    }

    /// A stand-in NDI: no kernel, no root — just the two ends of the bridge.
    struct FakeNdi {
        mac: [u8; 6],
        /// Frames the kernel would be writing out (fed to `read_frame`).
        outbound: Mutex<std::collections::VecDeque<Vec<u8>>>,
        /// Frames the bridge handed up to the kernel.
        delivered: Mutex<Vec<Vec<u8>>>,
    }

    impl FakeNdi {
        fn new(mac: [u8; 6]) -> Self {
            Self {
                mac,
                outbound: Mutex::new(std::collections::VecDeque::new()),
                delivered: Mutex::new(Vec::new()),
            }
        }
    }

    impl DataInterface for FakeNdi {
        fn mac(&self) -> [u8; 6] {
            self.mac
        }
        fn index(&self) -> u32 {
            0 // no kernel interface behind this one
        }
        fn read_frame(&self, buf: &mut [u8]) -> std::io::Result<usize> {
            // Block like a real fd would, instead of spinning the pump thread.
            loop {
                if let Some(f) = self.outbound.lock().unwrap().pop_front() {
                    buf[..f.len()].copy_from_slice(&f);
                    return Ok(f.len());
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        fn write_frame(&self, eth: &[u8]) -> std::io::Result<usize> {
            self.delivered.lock().unwrap().push(eth.to_vec());
            Ok(eth.len())
        }
    }

    /// The bridge's whole purpose: a frame the kernel writes to one node's NDI
    /// comes out of the other node's NDI, unchanged, over the radio.
    #[tokio::test]
    async fn a_frame_written_to_one_ndi_arrives_at_the_peers_ndi() {
        const A_NDI: [u8; 6] = [0x02, 0xaa, 0xaa, 0x00, 0x00, 0x01];
        const B_NDI: [u8; 6] = [0x02, 0xbb, 0xbb, 0x00, 0x00, 0x02];

        let bus = LoopbackMonitorBus::new();
        let a_ndi = Arc::new(FakeNdi::new(A_NDI));
        let b_ndi = Arc::new(FakeNdi::new(B_NDI));
        let _a = spawn_with(
            Arc::new(bus.endpoint(1, -50)),
            Config::new(NMI_A, 6, 200).with_ndi(A_NDI),
            None,
            Some(a_ndi.clone() as Arc<dyn DataInterface>),
        );
        let _b = spawn_with(
            Arc::new(bus.endpoint(2, -50)),
            Config::new(NMI_B, 6, 180).with_ndi(B_NDI),
            None,
            Some(b_ndi.clone() as Arc<dyn DataInterface>),
        );

        // The kernel on A sends an IPv6 packet to B's NDI.
        let mut eth = Vec::new();
        eth.extend_from_slice(&B_NDI);
        eth.extend_from_slice(&A_NDI);
        eth.extend_from_slice(&[0x86, 0xdd]);
        eth.extend_from_slice(b"an ipv6 packet");
        a_ndi.outbound.lock().unwrap().push_back(eth.clone());

        let got = timeout(Duration::from_secs(3), async {
            loop {
                if let Some(f) = b_ndi.delivered.lock().unwrap().first().cloned() {
                    return f;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("B's NDI should receive what A's NDI sent");
        assert_eq!(got, eth, "the frame arrives byte-identical");

        // And A must not be handed back its own transmission.
        assert!(
            a_ndi.delivered.lock().unwrap().is_empty(),
            "a node's own frames must not come back up its NDI"
        );
    }

    /// The radio has one reader. A data frame belongs to the NDI; a management
    /// frame to the engine. Mixing them would either starve the NDI or feed the
    /// kernel someone's beacons.
    #[tokio::test]
    async fn the_ndi_does_not_swallow_discovery_frames() {
        const A_NDI: [u8; 6] = [0x02, 0xaa, 0xaa, 0x00, 0x00, 0x01];
        const B_NDI: [u8; 6] = [0x02, 0xbb, 0xbb, 0x00, 0x00, 0x02];
        let bus = LoopbackMonitorBus::new();
        let a_ndi = Arc::new(FakeNdi::new(A_NDI));
        let b_ndi = Arc::new(FakeNdi::new(B_NDI));
        let svc = NanServiceName("org.ndn.coord".into());

        let a = spawn_with(
            Arc::new(bus.endpoint(1, -50)),
            Config::new(NMI_A, 6, 200).with_ndi(A_NDI),
            None,
            Some(a_ndi.clone() as Arc<dyn DataInterface>),
        );
        let b = spawn_with(
            Arc::new(bus.endpoint(2, -50)),
            Config::new(NMI_B, 6, 180).with_ndi(B_NDI),
            None,
            Some(b_ndi.clone() as Arc<dyn DataInterface>),
        );
        a.publish(&svc).await.unwrap();
        a.subscribe(&svc).await.unwrap();
        b.publish(&svc).await.unwrap();
        b.subscribe(&svc).await.unwrap();

        // Discovery still works with the bridge in the path...
        timeout(Duration::from_secs(5), async {
            loop {
                if b.drain_matches().iter().any(|m| m.peer == NMI_A) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("discovery must survive the NDI demux");

        // ...and no beacon/SDF was mistaken for data-path traffic.
        assert!(b_ndi.delivered.lock().unwrap().is_empty());
        assert!(a_ndi.delivered.lock().unwrap().is_empty());
    }

    /// Without an NDI a "path" would have nothing to carry traffic over, so the
    /// request must fail loudly rather than hand back a link that cannot work.
    #[tokio::test]
    async fn request_ndp_without_an_ndi_is_refused() {
        let bus = LoopbackMonitorBus::new();
        let a = spawn(
            Arc::new(bus.endpoint(1, -50)),
            Config::new(NMI_A, 6, 200),
            None,
        );
        let err = a.request_ndp(NMI_B).await.err().expect("no NDI → no link");
        assert!(
            format!("{err}").contains("Data Interface"),
            "the error should say what is missing, got: {err}"
        );
    }

    /// A peer that refuses must surface as an error on the caller's `request_ndp`,
    /// not as a hang.
    #[tokio::test]
    async fn request_ndp_reports_a_refusing_peer() {
        const A_NDI: [u8; 6] = [0x02, 0xaa, 0xaa, 0x00, 0x00, 0x01];
        const B_NDI: [u8; 6] = [0x02, 0xbb, 0xbb, 0x00, 0x00, 0x02];
        let bus = LoopbackMonitorBus::new();
        let a_ndi = Arc::new(FakeNdi::new(A_NDI));
        let b_ndi = Arc::new(FakeNdi::new(B_NDI));

        let a = spawn_with(
            Arc::new(bus.endpoint(1, -50)),
            Config::new(NMI_A, 6, 200).with_ndi(A_NDI),
            None,
            Some(a_ndi as Arc<dyn DataInterface>),
        );
        let mut b_cfg = Config::new(NMI_B, 6, 180).with_ndi(B_NDI);
        b_cfg.ndp_auto_accept = false;
        let _b = spawn_with(
            Arc::new(bus.endpoint(2, -50)),
            b_cfg,
            None,
            Some(b_ndi as Arc<dyn DataInterface>),
        );

        let err = timeout(Duration::from_secs(10), a.request_ndp(NMI_B))
            .await
            .expect("request_ndp must not hang on a refusal")
            .err()
            .expect("B refuses data paths");
        assert!(format!("{err}").contains("failed"), "got: {err}");
    }

    /// A radio whose only job is to record what it was tuned to.
    struct SpyKnobs(Mutex<Vec<(u8, Bandwidth)>>);

    impl RadioKnobs for SpyKnobs {
        fn set_channel(&self, channel: u8, bw: Bandwidth) -> Result<(), FaceError> {
            self.0.lock().unwrap().push((channel, bw));
            Ok(())
        }
    }

    /// The engine's `set_channel` has to actually reach the radio. Before the
    /// adapter existed nothing implemented `RadioChannel`, so every caller passed
    /// `None` and the engine's tuning request went nowhere — a real device only
    /// worked because it happened to be parked on the right channel already.
    #[tokio::test]
    async fn knobs_channel_tunes_the_radio_the_engine_asked_for() {
        let spy = Arc::new(SpyKnobs(Mutex::new(Vec::new())));
        let bus = LoopbackMonitorBus::new();
        let radio: Arc<dyn FrameIo> = Arc::new(bus.endpoint(1, -50));
        let _driver = spawn(
            radio,
            Config::new(NMI_A, 6, 200),
            Some(knobs_channel(Arc::clone(&spy))),
        );

        // The engine tunes on start-up; give the task a moment to run.
        let tuned = timeout(Duration::from_secs(2), async {
            loop {
                if let Some(&first) = spy.0.lock().unwrap().first() {
                    return first;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the engine should tune the radio through the adapter");

        // Channel 6 is what the config asked for, at NAN's 20 MHz discovery width.
        assert_eq!(tuned, (6, Bandwidth::Bw20));
    }
}
