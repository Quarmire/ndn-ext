//! **Soft prefix-reach** — a mobility-first named-radio forwarding strategy, the base candidate from
//! `ndn-ext/crates/faces/ndn-face-monitor-wifi/docs/wireless-forwarding-under-flux.md` §5, in its simplest
//! (probabilistic-gate) form.
//!
//! On a broadcast named-data radio the honest baseline is **flooding** (`broadcast`: every relay re-broadcasts
//! every Interest). This strategy holds the MAC's one legal memory — a **decaying, name-prefix-keyed
//! reachability prior** — and uses it to *scope the flood*: a relay re-broadcasts an Interest with a
//! probability that rises with how recently Data for that prefix came back through it. Cold/unknown prefixes
//! still re-broadcast at a floor probability (exploration), so a cold or wrong prior only ever *widens* the
//! flood — it can never blackhole (the §7 soft-state invariant: loss of the prior costs airtime, never
//! delivery). Every design axis here is the simplest legal choice, meant to be A/B'd and swapped one at a time
//! (`ndn-sim`'s `ndr_mobility_sweep`):
//!
//! - **memory** — `name-prefix → decaying reach weight` (a scalar per registered prefix; the counting-Bloom
//!   form is a later axis swap).
//! - **decay** — geometric/EWMA `w·e^(−Δt/τ)` on read, reinforced `+g` on Data-return (pheromone/KITE).
//! - **decision** — threshold→flood-fallback via a probabilistic gate `p = floor + (1−floor)·min(w/wmax,1)`
//!   (the discounted-bandit gate is a later axis swap).
//! - **exploration** — the `floor` probability keeps a cold prefix flooding (degrades to epidemic).
//! - **feedback** — `after_receive_data` reinforces; keyed on the name only (no host identity).
//!
//! Only the *re-broadcast on the arrival face* is gated (the floodable part); a genuine hop — a consumer's own
//! Interest heading out, or an Interest reaching a local producer — is never gated.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ndn_packet::{Name, NameComponent};
use ndn_strategy::{register_strategy, ErasedStrategy, Strategy, StrategyContext};
use ndn_transport::{FaceId, ForwardingAction, NackReason};
use smallvec::{smallvec, SmallVec};

register_strategy!(SOFT_PREFIX_REACH_REG, b"soft-prefix-reach", 1, || Arc::new(
    SoftPrefixReachStrategy::new()
) as Arc<dyn ErasedStrategy>,);

// --- tunables (wireless-forwarding-under-flux.md §8; A/B these in the sim) ---
const P_FLOOR: f64 = 0.2; // cold-prior re-broadcast probability (exploration floor)
const REINFORCE: f64 = 1.0; // weight added on each Data-return for the prefix
const W_MAX: f64 = 4.0; // reach-weight cap (p saturates to 1 here)
const TAU_MS: f64 = 4000.0; // reach-prior decay time constant

struct Reach {
    weight: f64,
    last_ms: u64,
}

/// The strategy: a decaying per-prefix reachability prior + a probabilistic re-broadcast gate. One instance
/// per node (the registry factory builds a fresh one), so its `Mutex` state is that node's private soft state.
pub struct SoftPrefixReachStrategy {
    name: Name,
    prior: Mutex<HashMap<u64, Reach>>,
    rng: Mutex<u32>, // xorshift32 — deterministic per-node stream
    p_floor: f64, // exploration floor — the key delivery/airtime knob (env `NDR_PFLOOR`, for §8 tuning)
}

impl SoftPrefixReachStrategy {
    pub fn new() -> Self {
        Self {
            name: Name::from_components([NameComponent::generic(bytes_static(b"localhost")), NameComponent::generic(bytes_static(b"nfd")), NameComponent::generic(bytes_static(b"strategy")), NameComponent::generic(bytes_static(b"soft-prefix-reach"))]),
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
}

impl Default for SoftPrefixReachStrategy {
    fn default() -> Self {
        Self::new()
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

        // Genuine hops (a nexthop != the arrival face) always forward — a consumer's own Interest heading out,
        // or an Interest reaching a local producer. Only the re-broadcast on the arrival face is floodable.
        let mut out: SmallVec<[FaceId; 4]> = faces.iter().copied().filter(|&f| f != ctx.in_face).collect();
        let is_rebroadcast = faces.iter().any(|&f| f == ctx.in_face);

        if is_rebroadcast {
            let key = Self::prefix_key(ctx);
            let w = self.weight(key, Self::now_ms(ctx));
            let p = self.p_floor + (1.0 - self.p_floor) * (w / W_MAX).clamp(0.0, 1.0);
            if self.draw() < p {
                out.push(ctx.in_face); // re-broadcast (scoped flood)
            }
        }

        if out.is_empty() {
            smallvec![ForwardingAction::Suppress]
        } else {
            smallvec![ForwardingAction::Forward(out)]
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
