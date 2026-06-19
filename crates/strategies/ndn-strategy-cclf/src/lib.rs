//! Layer: extension — **CCLF**, a cross-layer, link-quality-aware forwarding
//! strategy. Research-derived (not canonical NDN), so it lives as an extension
//! crate and plugs into the `Strategy` seam — it never forks the forwarder.
//!
//! The decision is a single **pure kernel**, [`cclf_decide`], shared verbatim by
//! two thin adapters:
//!
//! - the **embedded** adapter ([`Cclf`]) — implements the sans-IO
//!   [`ndn_fwd_core::strategy::Strategy`] and delegates straight to the kernel;
//! - the **native** adapter ([`native::CclfStrategy`], feature `native`) —
//!   implements the async [`ndn_strategy::Strategy`], building a [`SignalView`]
//!   from the engine's `StrategyContext` and calling the same kernel.
//!
//! One algorithm, two platforms — the conformance-pinning pattern of
//! `ndn-fwd-core` / `ndn-crypto-core` applied to strategy logic.
//!
//! ## The algorithm (Chowdhury, Khan & Wang, ICN '20)
//!
//! CCLF is a content-aware election for broadcast wireless, not a unicast
//! best-nexthop pick. For each Interest a node computes:
//!
//! - a **Content Connectivity Score** (CCS) for the prefix — how well this node
//!   has historically returned content under it ([`cltree`]);
//! - an optional **Location Score** (LS) rewarding geographic progress toward
//!   the destination ([`geo`]);
//! - a **weight** `w = β·CCS + (1-β)·LS` and a jittered **election timer**
//!   `t = T/w` — higher quality forwards first, others overhear and cancel;
//! - a **density suppression** coin `p = min(K·n, 1)` over the network-layer
//!   named-neighbor count ([`neighbors`]) so dense neighborhoods thin their
//!   forwarders.
//!
//! The election math lives in [`election`]; state (C-L tree, neighbor table)
//! and I/O (scheduling, overhear-cancel) live in the adapters and engine.
//! See `.claude/notes/signals/cross-layer-signals-design-2026-05-23.md` and the
//! NDN-Pipes reconciliation note.
//!
//! ### A note on the legacy [`cclf_decide`] kernel
//!
//! The original RSSI-only [`cclf_decide`] is retained for now as a simple
//! link-quality fallback; the full CCLF election above supersedes it and is
//! wired through the strategy adapters.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod cltree;
pub mod election;
pub mod geo;
pub mod neighbors;
pub mod rng;

pub use cltree::{ClTree, Prefix, prefix_of};
pub use election::{CclfDecision, CclfParams, cclf_elect};
pub use geo::location_score;
pub use neighbors::{NamedNeighborTable, NodeName};
pub use rng::XorShift32;

use core::cell::RefCell;
use ndn_fwd_core::pipeline::ForwardAction;
use ndn_fwd_core::strategy::DecideCtx;
use ndn_signals_core::{CongestionLevel, SignalView};

/// Backoff applied (ms) when the best nexthop's link is congested.
pub const CONGESTION_BACKOFF_MS: u32 = 50;

/// RSSI (dBm) assumed for a nexthop whose link signal is unknown — mediocre, so
/// a link with *known* good RSSI is preferred but an unmeasured link still
/// beats a known-bad one.
const UNKNOWN_RSSI_DBM: i16 = -100;

/// The pure CCLF decision. Chooses the best-link nexthop (excluding `incoming`)
/// from `view` and emits exactly one [`ForwardAction`]: `Now` normally, or
/// `After` when the chosen link is congested. Emits nothing if no nexthop is
/// eligible (split-horizon / empty FIB). Allocation-free.
pub fn cclf_decide<F: Copy + Eq>(
    view: &dyn SignalView<F>,
    nexthops: &[F],
    incoming: F,
    emit: &mut dyn FnMut(ForwardAction<F>),
) {
    let mut best: Option<(F, i16)> = None;
    for &face in nexthops.iter().filter(|&&f| f != incoming) {
        let rssi = view
            .link(face)
            .and_then(|l| l.rssi_dbm)
            .map(i16::from)
            .unwrap_or(UNKNOWN_RSSI_DBM);
        if best.is_none_or(|(_, best_rssi)| rssi > best_rssi) {
            best = Some((face, rssi));
        }
    }

    if let Some((face, _)) = best {
        let congested = view
            .link(face)
            .and_then(|l| l.congestion)
            .is_some_and(|c| c == CongestionLevel::High);
        if congested {
            emit(ForwardAction::After(face, CONGESTION_BACKOFF_MS));
        } else {
            emit(ForwardAction::Now(face));
        }
    }
}

/// Build an owned [`Prefix`]/[`NodeName`] from borrowed component slices.
fn to_prefix(components: &[&[u8]]) -> Prefix {
    components.iter().map(|c| c.to_vec()).collect()
}

/// Embedded (sans-IO) **CCLF** adapter, implementing the full election.
///
/// Owns the [`ClTree`] (CCS), the network-layer [`NamedNeighborTable`]
/// (density), and a [`XorShift32`] behind `RefCell` — the constrained forwarder
/// is single-threaded, so interior mutability needs no lock. For each Interest
/// it observes the name into the C-L tree, computes CCS, and runs
/// [`cclf_elect`] **per egress radio** (the candidate nexthops, split-horizon
/// excluded), emitting a jittered [`ForwardAction::After`] or nothing
/// (suppressed). The tick loop enacts the scheduled forward; the engine's
/// overhear-cancel skips it if a neighbor forwards first.
///
/// Location Score is `None` here (the sans-IO seam carries no position fix), so
/// the embedded election is CCS-only — the paper's documented graceful
/// degradation. The shell feeds [`Strategy::observe_data`] and
/// [`Strategy::observe_neighbor`] from the Data and beacon/adornment paths.
pub struct Cclf<F: Copy + Ord> {
    cltree: RefCell<ClTree>,
    neighbors: RefCell<NamedNeighborTable<F>>,
    rng: RefCell<XorShift32>,
    params: CclfParams,
}

impl<F: Copy + Ord> Cclf<F> {
    /// New CCLF with default parameters, `seed` for the jitter/suppression PRNG.
    pub fn new(seed: u32) -> Self {
        Self::with_params(seed, CclfParams::default())
    }

    /// New CCLF with explicit [`CclfParams`].
    pub fn with_params(seed: u32, params: CclfParams) -> Self {
        Self {
            cltree: RefCell::new(ClTree::new()),
            neighbors: RefCell::new(NamedNeighborTable::new()),
            rng: RefCell::new(XorShift32::new(seed)),
            params,
        }
    }
}

impl<F: Copy + Ord> ndn_fwd_core::strategy::Strategy<F> for Cclf<F> {
    fn decide(&self, ctx: &DecideCtx<'_, F>, emit: &mut dyn FnMut(ForwardAction<F>)) {
        let now = ctx.now_ms as u64;
        let prefix = to_prefix(ctx.components);
        let ccs = {
            let mut tree = self.cltree.borrow_mut();
            tree.observe_interest(prefix.clone(), now);
            tree.ccs(&prefix, now)
        };
        let mut neighbors = self.neighbors.borrow_mut();
        let mut rng = self.rng.borrow_mut();
        for &face in ctx.nexthops.iter().filter(|&&f| f != ctx.incoming) {
            let n = neighbors.count(face, now);
            // Location Score is unavailable on the sans-IO seam → CCS-only.
            match cclf_elect(ccs, None, n, &self.params, &mut rng) {
                CclfDecision::ForwardAfter { delay_us } => {
                    emit(ForwardAction::After(face, (delay_us / 1000).max(1)));
                }
                CclfDecision::Suppress => {}
            }
        }
    }

    fn observe_data(&self, components: &[&[u8]], now_ms: u32) {
        self.cltree
            .borrow_mut()
            .observe_data(to_prefix(components), now_ms as u64);
    }

    fn observe_neighbor(&self, face: F, name: &[&[u8]], now_ms: u32) {
        self.neighbors
            .borrow_mut()
            .observe(face, to_prefix(name), now_ms as u64);
    }
}

#[cfg(feature = "native")]
pub mod native {
    //! Native async adapter, registry-wired for `/localhost/nfd/strategy-choice`.

    use super::{CclfDecision, CclfParams, ClTree, NamedNeighborTable, XorShift32, cclf_elect};
    use bytes::Bytes;
    use ndn_packet::{Name, NameComponent};
    use ndn_strategy::{ErasedStrategy, Strategy, StrategyContext, register_strategy};
    use ndn_transport::{FaceId, ForwardingAction, NackReason};
    use smallvec::{SmallVec, smallvec};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    register_strategy!(CCLF_REG, b"cclf", 1, || Arc::new(CclfStrategy::new())
        as Arc<dyn ErasedStrategy>,);

    /// CCLF as a native strategy. Owns the full election state — the C-L tree
    /// (CCS), the network-layer named-neighbor table (density, keyed by the
    /// `u64` face id since [`FaceId`] is not `Ord`), and a PRNG — behind
    /// `Mutex` (the strategy is shared `Send + Sync`). It observes Interests and
    /// Data for CCS, counts named neighbors per egress radio, and emits a single
    /// jittered `ForwardAfter` over the egress set (the engine's overhear-cancel
    /// seam cancels it if a neighbor forwards first) or `Suppress` (density
    /// thinning). Location Score is wired by the A-LAL layer; CCS-only until then.
    pub struct CclfStrategy {
        name: Name,
        cltree: Mutex<ClTree>,
        /// `Arc` so the A-LAL ingress sink (installed in `new`) and the decision
        /// path share one table. Keyed by `u64` (FaceId is not `Ord`).
        neighbors: Arc<Mutex<NamedNeighborTable<u64>>>,
        rng: Mutex<XorShift32>,
        params: CclfParams,
        start: Instant,
    }

    impl CclfStrategy {
        /// `/localhost/nfd/strategy/cclf/v=1`.
        pub fn strategy_name() -> Name {
            Name::from_components([
                NameComponent::generic(Bytes::from_static(b"localhost")),
                NameComponent::generic(Bytes::from_static(b"nfd")),
                NameComponent::generic(Bytes::from_static(b"strategy")),
                NameComponent::generic(Bytes::from_static(b"cclf")),
            ])
            .append_version(1)
        }

        pub fn new() -> Self {
            // Per-process entropy so different nodes draw different jitter and
            // ties break (not security-sensitive).
            let seed = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0x1234_5678)
                | 1;
            let neighbors = Arc::new(Mutex::new(NamedNeighborTable::new()));
            let start = Instant::now();

            // Wire the A-LAL ingress (transport layer) → this strategy's
            // neighbor table via the process-global presence sink, mirroring the
            // trace-context global pattern. No downcast / engine seam needed; the
            // app supplies the egress presence via `advertise_presence`. The
            // app remains responsible for trust-schema validation of the name.
            {
                let nb = Arc::clone(&neighbors);
                ndn_transport::link_service::features::install_global_presence_sink(Arc::new(
                    move |face: FaceId, name_wire: bytes::Bytes| {
                        let now = start.elapsed().as_millis() as u64;
                        let Ok(name) = ndn_packet::Name::decode_from_tlv(name_wire) else {
                            return;
                        };
                        let comps: alloc::vec::Vec<alloc::vec::Vec<u8>> =
                            name.components().iter().map(|c| c.value.to_vec()).collect();
                        if let Ok(mut t) = nb.lock() {
                            t.observe(face.0, comps, now);
                        }
                    },
                ));
            }

            Self {
                name: Self::strategy_name(),
                cltree: Mutex::new(ClTree::new()),
                neighbors,
                rng: Mutex::new(XorShift32::new(seed)),
                params: CclfParams::default(),
                start,
            }
        }

        /// Advertise this node's presence so neighbors count it (A-LAL egress).
        /// Installs the process-global presence source with `name`'s encoded
        /// wire; the app calls this once with the forwarder's identity/prefix.
        pub fn advertise_presence(name: &Name) {
            let wire = name.encode_to_tlv();
            ndn_transport::link_service::features::install_global_presence_source(Arc::new(
                move || Some(wire.clone()),
            ));
        }

        /// Distinct named neighbors currently counted on `face` (observability /
        /// witness; this is the density `n` the election uses).
        pub fn neighbor_count_now(&self, face: FaceId) -> u32 {
            let now = self.now_ms();
            self.neighbors.lock().unwrap().count(face.0, now)
        }

        fn now_ms(&self) -> u64 {
            self.start.elapsed().as_millis() as u64
        }

        /// A [`Name`] as component byte-vectors (the C-L tree / neighbor key).
        fn name_prefix(name: &Name) -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
            name.components().iter().map(|c| c.value.to_vec()).collect()
        }

        /// Record a named neighbor heard at the network layer on `face` (fed by
        /// the A-LAL presence/announcement path). `name` is component slices.
        pub fn observe_neighbor(&self, face: FaceId, name: &[&[u8]], now_ms: u64) {
            let prefix = name.iter().map(|c| c.to_vec()).collect();
            self.neighbors
                .lock()
                .unwrap()
                .observe(face.0, prefix, now_ms);
        }

        fn decide_sync(&self, ctx: &StrategyContext<'_>) -> SmallVec<[ForwardingAction; 2]> {
            let Some(fib) = ctx.fib_entry else {
                return smallvec![ForwardingAction::Nack(NackReason::NoRoute)];
            };
            // Egress radios = candidate nexthops minus the incoming face.
            let faces: SmallVec<[FaceId; 4]> = fib
                .nexthops
                .iter()
                .map(|n| n.face_id)
                .filter(|f| *f != ctx.in_face)
                .collect();
            if faces.is_empty() {
                return smallvec![ForwardingAction::Nack(NackReason::NoRoute)];
            }

            let now = self.now_ms();
            let prefix = Self::name_prefix(ctx.name);
            // CCS: observe this Interest, then read the prefix's connectivity.
            let ccs = {
                let mut tree = self.cltree.lock().unwrap();
                tree.observe_interest(prefix.clone(), now);
                tree.ccs(&prefix, now)
            };
            // Density: worst-case named-neighbor count across egress radios.
            let n = {
                let mut nb = self.neighbors.lock().unwrap();
                faces.iter().map(|f| nb.count(f.0, now)).max().unwrap_or(0)
            };
            // Location Score: computed only when this node's position (signals),
            // the previous hop's (A-LAL PL), and the destination's (A-LAL DL) are
            // all known; otherwise `None` ⇒ CCS-only (β collapses to 1).
            let ls = {
                let self_pos = ctx.signals.node().position;
                let prev = ctx
                    .extensions
                    .get::<ndn_strategy::PrevHopLocation>()
                    .map(|p| p.0);
                let dest = ctx
                    .extensions
                    .get::<ndn_strategy::DataLocation>()
                    .map(|d| d.0);
                match (self_pos, prev, dest) {
                    (Some(n_pos), Some(p_pos), Some(d_pos)) => {
                        Some(super::location_score(n_pos, p_pos, d_pos))
                    }
                    _ => None,
                }
            };
            // With a position fix, weight CCS and LS equally; else CCS-only.
            let params = if ls.is_some() {
                CclfParams {
                    beta: 0.5,
                    ..self.params
                }
            } else {
                self.params
            };
            let decision = {
                let mut rng = self.rng.lock().unwrap();
                cclf_elect(ccs, ls, n, &params, &mut rng)
            };
            match decision {
                CclfDecision::ForwardAfter { delay_us } => {
                    smallvec![ForwardingAction::ForwardAfter {
                        faces,
                        delay: Duration::from_micros(u64::from(delay_us)),
                    }]
                }
                CclfDecision::Suppress => smallvec![ForwardingAction::Suppress],
            }
        }
    }

    impl Default for CclfStrategy {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Strategy for CclfStrategy {
        fn name(&self) -> &Name {
            &self.name
        }

        fn decide(&self, ctx: &StrategyContext<'_>) -> Option<SmallVec<[ForwardingAction; 2]>> {
            Some(self.decide_sync(ctx))
        }

        fn after_receive_interest(
            &self,
            ctx: &StrategyContext<'_>,
        ) -> SmallVec<[ForwardingAction; 2]> {
            self.decide_sync(ctx)
        }

        fn after_receive_data(
            &self,
            ctx: &StrategyContext<'_>,
        ) -> SmallVec<[ForwardingAction; 2]> {
            // CCS: returning Data lifts this node's content connectivity.
            let now = self.now_ms();
            let prefix = Self::name_prefix(ctx.name);
            self.cltree.lock().unwrap().observe_data(prefix, now);
            SmallVec::new()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use ndn_transport::link_service::features::AlalFeature;
        use ndn_transport::link_service::{
            EgressCtx, InboundLpFrame, IngressCtx, LinkServiceFeature, OutboundLpFrame,
        };

        fn lp_wire() -> Bytes {
            // Wrap a minimal bare Interest in an LpPacket.
            ndn_packet::lp::encode_lp_packet(b"\x05\x02\x00\x00")
        }

        /// End-to-end native density path through the real `AlalFeature`: a
        /// peer's presence is spliced on egress, extracted on ingress, decoded,
        /// and observed into the strategy's neighbor table — so the election's
        /// density input `n` is fed at the network layer (no MAC/host id). Uses
        /// the per-face sink for test isolation (the production path is the
        /// `OnceLock` global sink installed in `new`, identical otherwise).
        #[test]
        fn alal_presence_feeds_strategy_neighbor_count() {
            let strat = Arc::new(CclfStrategy::new());
            let peer = Name::from_components([
                NameComponent::generic(Bytes::from_static(b"ndn")),
                NameComponent::generic(Bytes::from_static(b"peer-X")),
            ]);

            let feat = AlalFeature::new();
            feat.set_presence(Some(peer.encode_to_tlv()));
            let s2 = Arc::clone(&strat);
            feat.set_sink(Some(Arc::new(move |face: FaceId, name_wire: Bytes| {
                let Ok(name) = Name::decode_from_tlv(name_wire) else {
                    return;
                };
                let comps: Vec<&[u8]> =
                    name.components().iter().map(|c| c.value.as_ref()).collect();
                s2.observe_neighbor(face, &comps, 0);
            })));

            // Egress splices presence; the same wire is then received on face 2.
            let mut frame = OutboundLpFrame::new(lp_wire(), true);
            feat.on_egress(&mut frame, &EgressCtx::new(FaceId(2), None));
            feat.on_ingress(
                &InboundLpFrame::bare(frame.wire),
                &IngressCtx::new(FaceId(2)),
            );

            assert_eq!(
                strat.neighbor_count_now(FaceId(2)),
                1,
                "A-LAL presence must reach the strategy's per-radio neighbor count",
            );
            // A different radio saw nothing.
            assert_eq!(strat.neighbor_count_now(FaceId(3)), 0);
        }

        #[test]
        fn advertise_presence_installs_global_source() {
            // Smoke: advertising sets a global source that yields the name wire.
            let n = Name::from_components([NameComponent::generic(Bytes::from_static(b"node"))]);
            CclfStrategy::advertise_presence(&n);
            let feat = AlalFeature::new();
            let mut frame = OutboundLpFrame::new(lp_wire(), true);
            feat.on_egress(&mut frame, &EgressCtx::new(FaceId(1), None));
            // Presence (global source) was spliced even with no per-face override.
            assert!(
                ndn_packet::lp::extract_lp_header(&frame.wire, ndn_packet::lp::TLV_AL_PRESENCE)
                    .is_some(),
                "global presence source must drive egress splice",
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_fwd_core::strategy::Strategy as _;
    use ndn_signals_core::LinkSignals;

    /// Fixed-array test view (no collections, no_std-safe).
    struct TestView<'a>(&'a [(u8, LinkSignals)]);
    impl SignalView<u8> for TestView<'_> {
        fn link(&self, f: u8) -> Option<LinkSignals> {
            self.0.iter().find(|(k, _)| *k == f).map(|(_, v)| *v)
        }
        fn node(&self) -> ndn_signals_core::NodeSignals {
            ndn_signals_core::NodeSignals::default()
        }
        fn neighbor(&self, _f: u8) -> Option<ndn_signals_core::NodeSignals> {
            None
        }
    }

    fn collect(view: &dyn SignalView<u8>, nh: &[u8], incoming: u8) -> Option<ForwardAction<u8>> {
        let mut out = None;
        cclf_decide(view, nh, incoming, &mut |a| out = Some(a));
        out
    }

    #[test]
    fn picks_best_rssi_nexthop() {
        let view = TestView(&[
            (
                2,
                LinkSignals {
                    rssi_dbm: Some(-80),
                    ..Default::default()
                },
            ),
            (
                3,
                LinkSignals {
                    rssi_dbm: Some(-55),
                    ..Default::default()
                },
            ),
        ]);
        assert_eq!(collect(&view, &[2, 3], 1), Some(ForwardAction::Now(3)));
    }

    #[test]
    fn defers_when_chosen_link_congested() {
        let view = TestView(&[(
            3,
            LinkSignals {
                rssi_dbm: Some(-50),
                congestion: Some(CongestionLevel::High),
                ..Default::default()
            },
        )]);
        assert_eq!(
            collect(&view, &[3], 1),
            Some(ForwardAction::After(3, CONGESTION_BACKOFF_MS))
        );
    }

    #[test]
    fn split_horizon_excludes_incoming() {
        let view = TestView(&[]);
        assert_eq!(collect(&view, &[1], 1), None);
    }

    fn ctx<'a>(
        components: &'a [&'a [u8]],
        nexthops: &'a [u8],
        incoming: u8,
        now_ms: u32,
        view: &'a dyn SignalView<u8>,
    ) -> DecideCtx<'a, u8> {
        DecideCtx {
            components,
            nexthops,
            incoming,
            now_ms,
            signals: view,
        }
    }

    #[test]
    fn cclf_embedded_emits_after_for_egress_radio() {
        // No neighbors → never suppressed; emits a jittered `After` for the
        // egress face and nothing for the split-horizon (incoming) face.
        let cclf = Cclf::<u8>::new(7);
        let view = TestView(&[]);
        let name: [&[u8]; 2] = [b"sensors", b"temp"];
        let mut out = None;
        cclf.decide(&ctx(&name, &[2], 1, 100, &view), &mut |a| out = Some(a));
        assert!(
            matches!(out, Some(ForwardAction::After(2, _))),
            "got {out:?}"
        );

        // Only nexthop is the incoming face → split horizon → nothing emitted.
        let mut emitted = false;
        cclf.decide(&ctx(&name, &[1], 1, 100, &view), &mut |_| emitted = true);
        assert!(!emitted, "split horizon must emit nothing");
    }

    #[test]
    fn cclf_embedded_dense_neighborhood_suppresses() {
        // Per egress radio: with ~8 named neighbors heard on face 2, density
        // suppression (p≈0.96) drops most forwards. Fresh instance per seed so
        // the jitter/coin stream varies.
        let name: [&[u8]; 1] = [b"a"];
        let view = TestView(&[]);
        let mut suppressed = 0;
        for seed in 1u32..=400 {
            let cclf = Cclf::<u8>::new(seed);
            for j in 0..8u8 {
                let nb: [&[u8]; 2] = [b"ndn", core::slice::from_ref(&b"abcdefgh"[j as usize])];
                cclf.observe_neighbor(2, &nb, 0);
            }
            let mut emitted = false;
            cclf.decide(&ctx(&name, &[2], 1, 0, &view), &mut |_| emitted = true);
            if !emitted {
                suppressed += 1;
            }
        }
        assert!(
            suppressed > 300,
            "dense neighborhood should suppress most: {suppressed}/400"
        );
    }

    #[test]
    fn cclf_embedded_observe_data_is_tracked() {
        // observe_data must feed the C-L tree (CCS): after observing Data under
        // a prefix, the strategy still produces a valid forward decision (no
        // panic, borrow conflicts, etc.) and the tree is non-empty via decide's
        // own interest observation.
        let cclf = Cclf::<u8>::new(3);
        let name: [&[u8]; 2] = [b"a", b"b"];
        cclf.observe_data(&name, 10);
        cclf.observe_data(&name, 20);
        let view = TestView(&[]);
        let mut out = None;
        cclf.decide(&ctx(&name, &[2], 1, 30, &view), &mut |a| out = Some(a));
        assert!(matches!(out, Some(ForwardAction::After(2, _))));
    }
}
