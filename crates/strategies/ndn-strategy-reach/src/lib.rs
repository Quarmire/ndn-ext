//! **Soft prefix-reach** — a mobility-first named-radio forwarding strategy, the base candidate from
//! `ndn-ext/crates/faces/ndn-face-monitor-wifi/docs/wireless-forwarding-under-flux.md` §5. Two variants, both
//! keyed on a decaying, **name-prefix reachability prior** (the MAC's one legal soft-state memory; §7): the
//! prior is reinforced `+g` on Data-return (`after_receive_data`) and decays `w·e^(−Δt/τ)` on read, keyed on
//! the name only (no host identity). What the prior *drives* is the axis being A/B'd:
//!
//! - **`soft-prefix-reach`** (v1, probabilistic gate) — a relay re-broadcasts with probability
//!   `p = floor + (1−floor)·min(w/wmax,1)`. Cheap, but it moves *along* the delivery/airtime curve: a
//!   suppressed re-broadcast can kill a path, so airtime *and* delivery drop together.
//!
//! - **`soft-prefix-reach-defer`** (v2, defer + overhear-cancel — LFBL/CCLF) — a relay does NOT drop; it
//!   **defers** the re-broadcast by a delay the prior sets (high reach → short delay → fires first), emitting
//!   [`ForwardingAction::ForwardAfter`]. The engine's overhear-cancel then suppresses the *redundant* copies:
//!   when a better-positioned neighbor re-broadcasts first, the duplicate nonce sets the PIT entry's
//!   `forward_cancelled` and the pending timer skips. So only ~one relay per hop transmits (the best), which
//!   cuts airtime *without* dropping delivery — it *shifts* the curve. This is the intended Pareto win.
//!
//! Only the re-broadcast on the arrival face is gated/deferred (the floodable part); a genuine hop — a
//! consumer's own Interest heading out, or an Interest reaching a local producer — always forwards immediately.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ndn_packet::{Name, NameComponent};
use ndn_strategy::{register_strategy, ErasedStrategy, Strategy, StrategyContext};
use ndn_transport::{FaceId, ForwardingAction, NackReason};
use smallvec::{smallvec, SmallVec};

register_strategy!(SOFT_PREFIX_REACH_REG, b"soft-prefix-reach", 1, || Arc::new(
    SoftPrefixReachStrategy::new(Mode::Probabilistic)
) as Arc<dyn ErasedStrategy>,);
register_strategy!(SOFT_PREFIX_REACH_DEFER_REG, b"soft-prefix-reach-defer", 1, || Arc::new(
    SoftPrefixReachStrategy::new(Mode::Defer)
) as Arc<dyn ErasedStrategy>,);

// --- tunables (wireless-forwarding-under-flux.md §8; A/B these in the sim) ---
const P_FLOOR: f64 = 0.2; // v1 exploration floor (env `NDR_PFLOOR`)
const REINFORCE: f64 = 1.0; // weight added on each Data-return for the prefix
const W_MAX: f64 = 4.0; // reach-weight cap (p / priority saturate here)
const TAU_MS: f64 = 4000.0; // reach-prior decay time constant
const DEFER_MIN_MS: f64 = 2.0; // v2 shortest defer (a fully-warm relay)
const DEFER_MAX_MS: f64 = 40.0; // v2 longest defer (a cold relay) — keep ·hops < Interest lifetime

#[derive(Clone, Copy)]
enum Mode {
    /// v1: re-broadcast with probability `p(reach)`; else suppress.
    Probabilistic,
    /// v2: defer the re-broadcast by `delay(reach)`; the engine overhear-cancels the redundant ones.
    Defer,
}

struct Reach {
    weight: f64,
    last_ms: u64,
}

/// A decaying per-prefix reachability prior driving either a probabilistic gate (v1) or a prior-ordered
/// deferred re-broadcast with overhear-cancel (v2). One instance per node (the registry factory builds a
/// fresh one), so its `Mutex` state is that node's private soft state.
pub struct SoftPrefixReachStrategy {
    name: Name,
    mode: Mode,
    prior: Mutex<HashMap<u64, Reach>>,
    rng: Mutex<u32>, // xorshift32 — deterministic per-node stream
    p_floor: f64, // v1 exploration floor (env `NDR_PFLOOR`)
}

impl SoftPrefixReachStrategy {
    pub fn new(mode: Mode) -> Self {
        let leaf: &'static [u8] = match mode {
            Mode::Probabilistic => b"soft-prefix-reach",
            Mode::Defer => b"soft-prefix-reach-defer",
        };
        Self {
            name: Name::from_components([
                NameComponent::generic(bytes_static(b"localhost")),
                NameComponent::generic(bytes_static(b"nfd")),
                NameComponent::generic(bytes_static(b"strategy")),
                NameComponent::generic(bytes_static(leaf)),
            ]),
            mode,
            prior: Mutex::new(HashMap::new()),
            rng: Mutex::new(0x2545_F491),
            p_floor: std::env::var("NDR_PFLOOR").ok().and_then(|v| v.parse().ok()).unwrap_or(P_FLOOR),
        }
    }

    /// FNV-1a of the name's first component — the registered-prefix granularity the reach prior keys on.
    fn prefix_key(ctx: &StrategyContext<'_>) -> u64 {
        let mut h = 0xcbf2_9ce4_8422_2325u64;
        if let Some(first) = ctx.name.components().first() {
            for b in first.value.as_ref() {
                h ^= *b as u64;
                h = h.wrapping_mul(0x0100_0000_01b3);
            }
        }
        h
    }

    fn now_ms(ctx: &StrategyContext<'_>) -> u64 {
        ctx.runtime.unix_nanos() / 1_000_000
    }

    /// Decayed reach weight for `key` at `now_ms` (geometric decay since last reinforcement).
    fn weight(&self, key: u64, now_ms: u64) -> f64 {
        let map = self.prior.lock().unwrap();
        match map.get(&key) {
            Some(r) => {
                let dt = now_ms.saturating_sub(r.last_ms) as f64;
                r.weight * (-dt / TAU_MS).exp()
            }
            None => 0.0,
        }
    }

    /// A deterministic pseudo-random draw in `[0, 1)` from this node's xorshift stream.
    fn draw(&self) -> f64 {
        let mut s = self.rng.lock().unwrap();
        let mut x = *s;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        *s = x;
        (x as f64) / (u32::MAX as f64)
    }

    /// v2 defer: warm relays fire first (short delay), cold relays last; a random term spreads ties so a
    /// single winner emerges per hop and the engine's overhear-cancel suppresses the rest.
    fn defer_delay(&self, reach_norm: f64) -> Duration {
        let priority = 1.0 - reach_norm; // 0 = warm (fast), 1 = cold (slow)
        let frac = (0.5 * priority + 0.5 * self.draw()).clamp(0.0, 1.0);
        let ms = DEFER_MIN_MS + (DEFER_MAX_MS - DEFER_MIN_MS) * frac;
        Duration::from_micros((ms * 1000.0) as u64)
    }
}

impl Strategy for SoftPrefixReachStrategy {
    fn name(&self) -> &Name {
        &self.name
    }

    fn after_receive_interest(&self, ctx: &StrategyContext<'_>) -> SmallVec<[ForwardingAction; 2]> {
        let Some(fib) = ctx.fib_entry else {
            return smallvec![ForwardingAction::Nack(NackReason::NoRoute)];
        };
        let faces: SmallVec<[FaceId; 4]> = fib.nexthops.iter().map(|n| n.face_id).collect();
        if faces.is_empty() {
            return smallvec![ForwardingAction::Nack(NackReason::NoRoute)];
        }

        // Genuine hops (a nexthop != the arrival face) always forward immediately — a consumer's own Interest
        // heading out, or an Interest reaching a local producer. Only a pure re-broadcast on the arrival face
        // (the flood) is gated/deferred.
        let other: SmallVec<[FaceId; 4]> = faces.iter().copied().filter(|&f| f != ctx.in_face).collect();
        if !other.is_empty() {
            return smallvec![ForwardingAction::Forward(other)];
        }

        // Pure re-broadcast on the arrival face.
        let key = Self::prefix_key(ctx);
        let w = self.weight(key, Self::now_ms(ctx));
        let reach_norm = (w / W_MAX).clamp(0.0, 1.0);
        match self.mode {
            Mode::Probabilistic => {
                let p = self.p_floor + (1.0 - self.p_floor) * reach_norm;
                if self.draw() < p {
                    smallvec![ForwardingAction::Forward(faces)]
                } else {
                    smallvec![ForwardingAction::Suppress]
                }
            }
            Mode::Defer => {
                // Never drop — defer, and let the engine's overhear-cancel suppress the redundant copies.
                smallvec![ForwardingAction::ForwardAfter { faces, delay: self.defer_delay(reach_norm) }]
            }
        }
    }

    fn after_receive_data(&self, ctx: &StrategyContext<'_>) -> SmallVec<[ForwardingAction; 2]> {
        // Data came back for this prefix through this node → reinforce the reach prior (pheromone/KITE).
        let key = Self::prefix_key(ctx);
        let now = Self::now_ms(ctx);
        let mut map = self.prior.lock().unwrap();
        let r = map.entry(key).or_insert(Reach { weight: 0.0, last_ms: now });
        let dt = now.saturating_sub(r.last_ms) as f64;
        r.weight = (r.weight * (-dt / TAU_MS).exp() + REINFORCE).min(W_MAX);
        r.last_ms = now;
        SmallVec::new()
    }
}

/// `Bytes` from a static slice — small helper so the strategy name can be a const-ish literal.
fn bytes_static(b: &'static [u8]) -> bytes::Bytes {
    bytes::Bytes::from_static(b)
}
