//! Link-FEC as a composable [`LinkServiceFeature`] (G7).
//!
//! Wraps the [`link_fec`](crate::link_fec) codec so a lossy broadcast/radio face can
//! enable FEC alongside reliability + congestion-marking in one feature set — instead of
//! every such face hand-rolling generation batching. Like the reliability feature, the
//! real *multi-frame* transform rides bespoke handle methods ([`on_send`](LinkFecFeature::on_send)
//! / [`flush`](LinkFecFeature::flush) / [`on_recv`](LinkFecFeature::on_recv)): FEC turns
//! K frames into K+R and recovers K from any K of N, so it cannot use the one-in-one-out
//! `on_egress`/`on_ingress` hooks. The trait impl gives it the uniform name / enable /
//! status surface the rest of the feature model has.
//!
//! Feature-gated (`link-fec-feature`) so the codec core stays dependency-free.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::time::Duration;
use std::sync::Mutex;

use bytes::Bytes;

use ndn_transport::link_service::{LinkServiceFeature, TickCtx};

use crate::link_fec::{LinkFecRx, LinkFecTx};

/// Maximum total frames per generation `N = K + R` the systematic codec supports (a coded
/// frame's index is a single byte). Configurations are clamped to keep `K + R ≤ MAX_N`.
const MAX_N: u16 = 255;

/// Link-FEC behind the [`LinkServiceFeature`] seam. A *generation* of K source frames is
/// transmitted as K+R coded frames; a receiver recovers all K from any K of the N.
///
/// Egress batches sources into generations (flush at K, or a partial tail-flush on the
/// face's window tick); ingress absorbs coded frames and emits the recovered sources.
/// Constructed disabled — enable per face. Each coded frame **must** be transmitted as
/// its own link-layer unit (never a whole generation in one aggregate), or a single FCS
/// failure erases the generation; see [`crate::link_fec`].
pub struct LinkFecFeature {
    enabled: AtomicBool,
    /// Source frames per generation (K).
    k: usize,
    /// Max time a partial generation waits before a tail flush (face-driven).
    window: Duration,
    tx: Mutex<LinkFecTx>,
    rx: Mutex<LinkFecRx>,
    pending: Mutex<Vec<Bytes>>,
    gens_encoded: AtomicU64,
    frames_delivered: AtomicU64,
}

impl LinkFecFeature {
    /// `k` source frames per generation, `redundancy` parity frames (losses tolerated per
    /// generation), `window` = how long a partial generation waits before a tail flush.
    /// Constructed disabled.
    ///
    /// The systematic codec requires `N = K + R ≤ 255`. A configuration that would exceed
    /// that makes **every** generation fail to encode — i.e. silently dropped traffic — so
    /// the parameters are **clamped into range here** (rather than failing later, per
    /// generation): `redundancy` to ≤ `MAX_N - 1` and `k` to `1..=(MAX_N - redundancy)`.
    /// With in-range parameters [`encode`](Self::encode) cannot fail on N, so a valid
    /// generation is never dropped.
    pub fn new(k: usize, redundancy: u16, window: Duration) -> Self {
        // Clamp so K + R ≤ MAX_N (leaving room for at least one source frame).
        let redundancy = redundancy.min(MAX_N - 1);
        let k = k.clamp(1, (MAX_N - redundancy) as usize);
        Self {
            enabled: AtomicBool::new(false),
            k,
            window,
            tx: Mutex::new(LinkFecTx::new(redundancy)),
            rx: Mutex::new(LinkFecRx::new()),
            pending: Mutex::new(Vec::new()),
            gens_encoded: AtomicU64::new(0),
            frames_delivered: AtomicU64::new(0),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Release);
    }
    /// Generations encoded on egress.
    pub fn generations_encoded(&self) -> u64 {
        self.gens_encoded.load(Ordering::Relaxed)
    }
    /// Source payloads delivered by the decoder (arrived sources + parity-recovered ones).
    pub fn frames_delivered(&self) -> u64 {
        self.frames_delivered.load(Ordering::Relaxed)
    }
    /// Source frames per generation (K).
    pub fn generation_size(&self) -> usize {
        self.k
    }
    /// Window before a partial generation is tail-flushed.
    pub fn window(&self) -> Duration {
        self.window
    }
    /// Source frames buffered in the not-yet-flushed current generation. A face uses this
    /// to know when a fresh generation is starting (e.g. to pin its per-generation side
    /// channel, such as the radio MCS, to the first frame).
    pub fn pending_len(&self) -> usize {
        self.pending.lock().unwrap().len()
    }

    /// Egress: buffer `frame` into the current generation. Returns the coded frames to
    /// transmit **now** — empty while the generation is still filling (held for batching),
    /// or the K+R coded frames once it reaches K. When disabled, passes the frame straight
    /// through (`[frame]`). Transmit each returned frame as its own link-layer unit.
    ///
    /// `#[must_use]`: the returned frames are the *only* copy of the buffered generation —
    /// dropping them strands those source frames (they are not re-buffered). This makes the
    /// transmit step impossible to forget at a call site.
    ///
    /// **Concurrency (G7.4):** the `pending` mutex keeps this memory-safe under concurrent
    /// callers, but generation *membership* then depends on lock-acquisition order — which K
    /// frames land in one generation becomes non-deterministic. Drive `on_send` from a
    /// **single egress task** (the intended use — a face's tx loop) for deterministic
    /// generation grouping; concurrent callers get safe-but-arbitrary grouping.
    #[must_use = "these coded frames must be transmitted, or the generation is lost"]
    pub fn on_send(&self, frame: Bytes) -> Vec<Bytes> {
        if !self.is_enabled() {
            return vec![frame];
        }
        let mut pending = self.pending.lock().unwrap();
        pending.push(frame);
        if pending.len() >= self.k {
            let generation = std::mem::take(&mut *pending);
            drop(pending);
            self.encode(generation)
        } else {
            Vec::new()
        }
    }

    /// Egress tail-flush: encode whatever partial generation is buffered (≥1 source) into
    /// its coded frames. Empty when nothing is buffered or the feature is disabled.
    ///
    /// **Wiring contract (do not skip):** a face that enables this feature MUST drive
    /// `flush()` from its tick at the [`window`](Self::window) cadence — [`tick`](#impl-LinkServiceFeature)
    /// returns exactly that interval while enabled. Without it, a generation that never
    /// reaches K (the common tail case) is buffered forever and those frames are never
    /// sent. The `#[must_use]` return makes a dropped flush a compile warning, but the
    /// *scheduling* of flush is the integrator's responsibility.
    #[must_use = "these coded frames must be transmitted, or the tail generation is lost"]
    pub fn flush(&self) -> Vec<Bytes> {
        if !self.is_enabled() {
            return Vec::new();
        }
        let generation = {
            let mut pending = self.pending.lock().unwrap();
            if pending.is_empty() {
                return Vec::new();
            }
            std::mem::take(&mut *pending)
        };
        self.encode(generation)
    }

    fn encode(&self, generation: Vec<Bytes>) -> Vec<Bytes> {
        match self.tx.lock().unwrap().encode(generation) {
            Ok(coded) => {
                self.gens_encoded.fetch_add(1, Ordering::Relaxed);
                coded
            }
            // Unreachable for an in-range config: `new` clamps K + R ≤ MAX_N, so the codec
            // cannot reject on N here. Kept as a defensive drop (never send un-coded).
            Err(_) => Vec::new(),
        }
    }

    /// Ingress: absorb `frame`. A plain (non-FEC) frame passes straight through
    /// (`[frame]`); a FEC frame returns the source payload(s) to deliver now — the source
    /// as it arrives, plus any sources recovered when parity completes a generation.
    pub fn on_recv(&self, frame: Bytes) -> Vec<Bytes> {
        if !self.is_enabled() || !LinkFecRx::is_fec(&frame) {
            return vec![frame];
        }
        match self.rx.lock().unwrap().absorb(frame) {
            Ok(payloads) => {
                self.frames_delivered
                    .fetch_add(payloads.len() as u64, Ordering::Relaxed);
                payloads
            }
            Err(_) => Vec::new(),
        }
    }
}

impl LinkServiceFeature for LinkFecFeature {
    fn name(&self) -> &'static str {
        "link-fec"
    }

    // FEC is a K→K+R / K-of-N transform, so — like reliability — the real work rides the
    // bespoke handle methods, not the one-in-one-out per-frame hooks (left as no-ops). The
    // face drives `flush()` at this cadence to tail-flush partial generations.
    fn tick(&self, _ctx: &TickCtx) -> Option<Duration> {
        self.is_enabled().then_some(self.window)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b(s: &str) -> Bytes {
        Bytes::from(s.to_owned())
    }

    #[test]
    fn out_of_range_config_is_clamped_not_silently_dropping() {
        // K + R > 255 would make every generation fail to encode (silent drop). `new` must
        // clamp into range so a real generation still encodes + delivers.
        let f = LinkFecFeature::new(usize::MAX, 1000, Duration::from_millis(20));
        f.set_enabled(true);
        assert!(f.generation_size() >= 1, "K clamped to at least 1");
        assert!(
            f.generation_size() + 1 <= MAX_N as usize,
            "K + R kept within the codec's N bound"
        );
        // A full generation actually produces coded frames (not an empty silent drop).
        let mut produced = 0usize;
        for i in 0..f.generation_size() {
            produced += f.on_send(b(&format!("f{i}"))).len();
        }
        produced += f.flush().len();
        assert!(produced > 0, "a clamped config still encodes + emits a generation");
        assert!(f.generations_encoded() >= 1);
    }

    #[test]
    fn disabled_is_passthrough() {
        let f = LinkFecFeature::new(4, 2, Duration::from_millis(20));
        assert_eq!(f.on_send(b("hi")), vec![b("hi")], "egress passthrough when off");
        assert_eq!(f.on_recv(b("hi")), vec![b("hi")], "ingress passthrough when off");
        assert!(f.flush().is_empty());
        assert_eq!(f.generations_encoded(), 0);
    }

    #[test]
    fn batches_at_k_then_round_trips_with_loss() {
        let tx = LinkFecFeature::new(4, 2, Duration::from_millis(20));
        tx.set_enabled(true);
        let sources = [b("alpha"), b("bb"), b("gamma-is-longer"), b("d")];

        // First three are held (generation filling); the fourth flushes K+R = 6 frames.
        let mut coded = Vec::new();
        for (i, s) in sources.iter().enumerate() {
            let out = tx.on_send(s.clone());
            if i < 3 {
                assert!(out.is_empty(), "frame {i} held while the generation fills");
            } else {
                coded = out;
            }
        }
        assert_eq!(coded.len(), 6, "K=4 + R=2 coded frames");
        assert_eq!(tx.generations_encoded(), 1);

        // Receiver: drop two source frames; the rest recover the whole generation.
        let rx = LinkFecFeature::new(4, 2, Duration::from_millis(20));
        rx.set_enabled(true);
        let kept = coded
            .into_iter()
            .enumerate()
            .filter(|(i, _)| *i != 0 && *i != 2)
            .map(|(_, f)| f);
        let mut got: Vec<Bytes> = kept.flat_map(|f| rx.on_recv(f)).collect();
        got.sort();
        let mut want: Vec<Bytes> = sources.to_vec();
        want.sort();
        assert_eq!(got, want, "recovered the full generation despite two losses");
    }

    #[test]
    fn window_flush_emits_partial_generation() {
        let f = LinkFecFeature::new(8, 2, Duration::from_millis(20));
        f.set_enabled(true);
        assert!(f.on_send(b("only-one")).is_empty(), "held below K");
        assert_eq!(f.pending_len(), 1);
        let coded = f.flush();
        assert_eq!(coded.len(), 3, "K'=1 + R=2 for the partial generation");
        assert_eq!(f.pending_len(), 0, "flush drains the buffer");
        assert!(f.flush().is_empty(), "nothing left to flush");
    }

    #[test]
    fn plain_frame_passes_through_on_ingress() {
        let f = LinkFecFeature::new(4, 2, Duration::from_millis(20));
        f.set_enabled(true);
        // A non-FEC frame is delivered as-is (mixed plain/coded stream).
        assert_eq!(f.on_recv(b("\x01not-fec")), vec![b("\x01not-fec")]);
    }

    #[test]
    fn composes_in_a_feature_pipeline_with_reliability_and_marking() {
        use ndn_transport::link_service::{
            CongestionMarkingFeature, LinkServiceFeature, ReliabilityFeature,
        };
        use std::sync::Arc;
        // FEC sits in the same trait-erased pipeline as the core features — the G7 point.
        let features: Vec<Arc<dyn LinkServiceFeature>> = vec![
            Arc::new(LinkFecFeature::new(4, 2, Duration::from_millis(20))),
            Arc::new(ReliabilityFeature::new()),
            Arc::new(CongestionMarkingFeature::new()),
        ];
        let names: Vec<&str> = features.iter().map(|f| f.name()).collect();
        assert_eq!(names, vec!["link-fec", "reliability", "congestion-marking"]);
    }
}
