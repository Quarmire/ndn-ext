//! Desktop driver for userspace **Wi-Fi Aware (NAN)**.
//!
//! This crate is the I/O half of the NAN stack: it drives the sans-I/O
//! [`ndn_nan_core::NanEngine`] from a [`FrameIo`] monitor radio + a tokio timer,
//! and presents the [`NanBackend`](ndn_face_wifi_aware::NanBackend) that
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
//!
//! A separate reader task forwards captured frames into the engine task, so the
//! engine loop's `select!` never has to cancel a half-completed `recv_frame`.
//!
//! [`drain_matches`]: ndn_face_wifi_aware::NanBackend::drain_matches

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use ndn_face_wifi_aware::{FaceError, FollowupFrame, NanBackend, NanMatch, NanServiceName};
use ndn_frame_io::{BROADCAST, CapturedFrame, FrameIo, InjectFrame, TxIntent};
use ndn_nan_core::{NanConfig, NanEngine, NanEvent, RxFrame, ServiceId, service_id};
use tokio::sync::mpsc;

pub use ndn_nan_core::NanConfig as Config;

/// The slow control-plane knob the engine needs: tune the radio to a channel.
/// Kept as a tiny local trait so this driver doesn't pull in a specific radio
/// crate; a monitor backend's `RadioKnobs` is adapted to it (or pass `None` for
/// a loopback / fixed-channel radio).
pub trait RadioChannel: Send + Sync + 'static {
    fn set_channel(&self, channel: u8) -> Result<(), FaceError>;
}

/// A command from a [`NanBackend`] method to the engine task.
enum Command {
    Publish(String, Vec<u8>),
    Subscribe(String, bool),
    Broadcast(Bytes),
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
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let (fu_tx, fu_rx) = mpsc::unbounded_channel();
    let shared = Arc::new(Shared::default());
    let task = EngineTask {
        nmi: cfg.nmi,
        engine: NanEngine::new(cfg),
        frame_io,
        channel,
        cmd_rx,
        fu_tx,
        shared: Arc::clone(&shared),
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
    cmd_rx: mpsc::UnboundedReceiver<Command>,
    fu_tx: mpsc::UnboundedSender<FollowupFrame>,
    shared: Arc<Shared>,
}

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
                _ = sleep => {
                    next_wake = self.poll(base, None).await;
                }
            }
        }
    }

    /// Run one engine `poll`: feed time + an optional captured frame, inject the
    /// resulting frames, apply a channel change, route events, and return the
    /// next wake instant.
    async fn poll(&mut self, base: Instant, inbound: Option<CapturedFrame>) -> Instant {
        let now = base.elapsed().as_micros() as u64;
        let rx_vec: Vec<RxFrame> = match &inbound {
            Some(cf) => vec![RxFrame {
                bytes: &cf.payload,
                rssi_dbm: cf.rssi_dbm,
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
            };
            if let Err(e) = self.frame_io.inject(frame).await {
                tracing::debug!(error = %e, "NAN: inject failed (lossy medium)");
            }
        }
        for ev in step.events {
            self.route_event(ev);
        }
        base + Duration::from_micros(step.wake_at_usec)
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
}
