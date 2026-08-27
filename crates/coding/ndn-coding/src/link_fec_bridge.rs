//! Bearer-agnostic link-FEC bridge: generation batching + plan-driven redundancy
//! actuation over any [`FrameIo`], so a face gets plan-driven link FEC without
//! re-hand-rolling the batching task per bearer.
//!
//! This is the reusable core lifted out of `ndn-face-monitor-wifi` (task #33). The
//! Wi-Fi face had a working FEC task, but it was welded to that crate — LoRa, BLE,
//! and every future bearer would have re-implemented the same generation loop to
//! get the actuator #32 added. The loop itself is bearer-neutral; only *how a
//! generation's coded frames reach the air* differs (Wi-Fi pins a per-generation
//! MCS via `inject_at`; LoRa just `inject`s). That difference is the one thing this
//! bridge does not own — it delegates it to a [`GenerationSink`].
//!
//! What the bridge owns, once, for everyone:
//!  - **Generation batching.** Source frames are buffered into generations of K;
//!    a generation flushes at K or on a `window` tail-flush.
//!  - **Plan-driven redundancy.** The parity count R is snapshotted from the frame
//!    that *opens* a generation and applied for that whole generation — because a
//!    receiver recovers K from any K of N, so N (hence R) is a property of the
//!    generation, not of a frame. Mid-generation R changes are deliberately
//!    ignored, exactly as a mid-generation MCS change would be.
//!  - **Decode.** Captured frames are fed through the codec; recovered source
//!    frames come back out.
//!
//! The redundancy value is the actuator for `TxParams::link_fec_redundancy`: a face
//! reads the plan and passes the decided R with each [`send`](LinkFecBridge::send).

use core::future::Future;
use core::time::Duration;
use std::sync::Arc;

use bytes::Bytes;
use ndn_frame_io::{FaceError, FrameIo, InjectFrame, TxIntent};
use tokio::sync::mpsc;

use crate::link_fec_feature::LinkFecFeature;

/// How a bearer puts one generation's coded frames on the air.
///
/// The bridge owns batching, redundancy actuation, and decode; the bearer owns
/// only the on-air specifics. Implementations are cheap adapters over a radio
/// handle — see [`FrameIoSink`] for the plain-inject default, and
/// `ndn-face-monitor-wifi`'s MCS-pinning sink for the Wi-Fi case.
pub trait GenerationSink: Send + Sync + 'static {
    /// Per-frame side channel the sender attaches — snapshotted from the frame that
    /// opens a generation and handed back with that generation's coded frames.
    /// `()` for a bearer with no per-generation pin (e.g. LoRa); the resolved
    /// `McsDescriptor` for Wi-Fi.
    type Pin: Send + 'static;

    /// Emit `coded` (the K+R frames of one generation), each as its own link-layer
    /// unit, using `pin` from the generation's opening frame. Never bundle a whole
    /// generation into one aggregate — a single FCS failure would erase all of it.
    fn emit(&self, coded: Vec<Bytes>, pin: &Self::Pin) -> impl Future<Output = ()> + Send;
}

/// The default sink: inject each coded frame as a plain broadcast frame over a
/// [`FrameIo`], with no per-generation pin. This is the LoRa/any-bearer path — a
/// bearer whose rate/robustness is set out-of-band (LoRa's SF/CR via `RadioKnobs`)
/// rather than per frame needs nothing more than this.
pub struct FrameIoSink<R: FrameIo> {
    radio: R,
    dst: [u8; 6],
    src: [u8; 6],
    intent: TxIntent,
}

impl<R: FrameIo> FrameIoSink<R> {
    pub fn new(radio: R, dst: [u8; 6], src: [u8; 6], intent: TxIntent) -> Self {
        Self {
            radio,
            dst,
            src,
            intent,
        }
    }
}

impl<R: FrameIo + Send + Sync + 'static> GenerationSink for FrameIoSink<R> {
    type Pin = ();

    async fn emit(&self, coded: Vec<Bytes>, _pin: &()) {
        for f in coded {
            let _ = self
                .radio
                .inject(InjectFrame {
                    payload: f,
                    tx: self.intent,
                    dst: self.dst,
                    src: self.src,
                    addr3: None,
                })
                .await;
        }
    }
}

/// Bearer-agnostic link-FEC bridge. `P` is the sink's per-generation pin type.
pub struct LinkFecBridge<P: Send + 'static> {
    tx: mpsc::UnboundedSender<(Bytes, P, Option<u16>)>,
    feature: Arc<LinkFecFeature>,
}

impl<P: Send + 'static> LinkFecBridge<P> {
    /// Spawn the batching task and return the bridge. `k` source frames per
    /// generation; `redundancy` the initial parity count (usually 0, with the real
    /// value coming from the plan per [`send`](Self::send)); `window` the tail-flush
    /// deadline for a partial generation.
    pub fn spawn<S>(sink: S, k: usize, redundancy: u16, window: Duration) -> Self
    where
        S: GenerationSink<Pin = P>,
    {
        let feature = Arc::new(LinkFecFeature::new(k, redundancy, window));
        feature.set_enabled(true);
        let (tx, mut rx_ch) = mpsc::unbounded_channel::<(Bytes, P, Option<u16>)>();
        let tx_feature = feature.clone();
        tokio::spawn(async move {
            // The generation rides the pin of the frame that opened it, and R is
            // snapshotted there too; the window is anchored at that frame, not
            // reset per arrival.
            let mut gen_pin: Option<P> = None;
            let mut gen_deadline: Option<tokio::time::Instant> = None;
            loop {
                let coded = match gen_deadline {
                    None => match rx_ch.recv().await {
                        Some((w, pin, parity)) => {
                            gen_pin = Some(pin);
                            gen_deadline = Some(tokio::time::Instant::now() + window);
                            if let Some(r) = parity {
                                tx_feature.set_redundancy(r);
                            }
                            tx_feature.on_send(w)
                        }
                        None => break, // sender dropped
                    },
                    Some(deadline) => match tokio::time::timeout_at(deadline, rx_ch.recv()).await {
                        Ok(Some((w, _, _))) => tx_feature.on_send(w),
                        Ok(None) => {
                            // Sender dropped mid-generation — flush and exit.
                            let last = tx_feature.flush();
                            if let Some(pin) = &gen_pin {
                                sink.emit(last, pin).await;
                            }
                            break;
                        }
                        Err(_) => tx_feature.flush(), // window elapsed → tail flush
                    },
                };
                if !coded.is_empty()
                    && let Some(pin) = &gen_pin
                {
                    sink.emit(coded, pin).await;
                }
                // A completed/flushed generation empties the buffer → start fresh.
                gen_deadline = (tx_feature.pending_len() > 0)
                    .then(|| gen_deadline.unwrap_or_else(|| tokio::time::Instant::now() + window));
            }
        });
        Self { tx, feature }
    }

    /// Enqueue one source frame with its per-generation `pin` and the plan's decided
    /// parity `redundancy` (`None` leaves R unchanged). The batching task groups it
    /// into a generation and emits K+R coded frames via the sink.
    pub fn send(&self, frame: Bytes, pin: P, redundancy: Option<u16>) -> Result<(), FaceError> {
        self.tx
            .send((frame, pin, redundancy))
            .map_err(|_| FaceError::Closed)
    }

    /// Feed one captured frame to the decoder; returns recovered source frames (0
    /// for a parity frame that did not complete a generation, 1 for a source frame,
    /// several when parity completes a generation). The caller owns queueing — a
    /// face typically re-attaches the source address before buffering.
    pub fn decode(&self, captured: Bytes) -> Vec<Bytes> {
        self.feature.on_recv(captured)
    }

    /// The parity count currently in force (for diagnostics/tests).
    pub fn redundancy(&self) -> u16 {
        self.feature.redundancy()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A sink that records the coded frames it was asked to emit — the on-air proxy
    /// for a test with no radio.
    #[derive(Default, Clone)]
    struct RecordingSink(Arc<Mutex<Vec<Vec<Bytes>>>>);

    impl GenerationSink for RecordingSink {
        type Pin = u8;
        async fn emit(&self, coded: Vec<Bytes>, _pin: &u8) {
            self.0.lock().unwrap().push(coded);
        }
    }

    fn frame_total(gens: &[Vec<Bytes>]) -> usize {
        gens.iter().map(|g| g.len()).sum()
    }

    #[tokio::test]
    async fn plan_redundancy_sizes_the_generation() {
        let rec = RecordingSink::default();
        let bridge = LinkFecBridge::spawn(rec.clone(), 3, 0, Duration::from_millis(50));

        // A K=3 generation with the plan forcing R=4 must emit 3 + 4 = 7 frames.
        for i in 0..3u8 {
            bridge.send(Bytes::from(vec![i; 8]), 0, Some(4)).unwrap();
        }
        // Give the task a moment to flush the completed generation.
        tokio::time::sleep(Duration::from_millis(20)).await;
        let gens = rec.0.lock().unwrap().clone();
        assert_eq!(frame_total(&gens), 7, "K=3 + plan R=4 = 7 frames on air");
        assert_eq!(
            bridge.redundancy(),
            4,
            "R was actuated, not left at the constructed 0"
        );
    }

    #[tokio::test]
    async fn round_trips_a_generation_through_decode() {
        let rec = RecordingSink::default();
        let bridge = LinkFecBridge::spawn(rec.clone(), 3, 2, Duration::from_millis(50));
        let sent: Vec<Bytes> = (0..3u8).map(|i| Bytes::from(vec![i; 8])).collect();
        for s in &sent {
            bridge.send(s.clone(), 0, None).unwrap();
        }
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Feed every coded frame back through the decoder; recover the 3 sources.
        let coded: Vec<Bytes> = rec.0.lock().unwrap().iter().flatten().cloned().collect();
        assert_eq!(coded.len(), 5, "K=3 + R=2");
        let rx = LinkFecBridge::spawn(RecordingSink::default(), 3, 0, Duration::from_millis(50));
        let mut got = Vec::new();
        for c in coded {
            got.extend(rx.decode(c));
        }
        got.sort();
        let mut want = sent;
        want.sort();
        assert_eq!(got, want, "decoder recovers the generation's source frames");
    }
}
