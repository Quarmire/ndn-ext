//! **One name-filtering gate, shared by both faces** (#82).
//!
//! Before this, the same decision was implemented twice and differently:
//!
//! | | `MonitorWifiFace::rx_accepts` | `RadioMediumFace`'s RX loop |
//! |---|---|---|
//! | Tier-0 prefix-set filter | yes | yes, open-coded inline |
//! | Tier-1 (BF-FIB/PIT/CS) | yes | **no** |
//! | NDN-NIC baseline (#101) | yes | **no** |
//! | drop accounting | yes | **no** |
//!
//! Two faces doing one job, with the features on opposite sides — which is the whole of #82. The
//! copies had already begun to drift: every filtering feature added recently landed only in
//! `MonitorWifiFace`, the face #82 says should *disappear* into `RadioMediumFace`. Extracting the
//! gate is the step that stops the drift; the remaining collapse can then happen without carrying two
//! divergent filter paths through it.
//!
//! The gate is deliberately **one type with one `admits`**, not a trait: there is exactly one policy
//! here and a trait would invite a second implementation, which is the situation being fixed.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::tier0::PrefixFilter;
use crate::{BROADCAST, inner_name, ndn_name_to_slash};

/// Which frames pass, before any NDN decode.
#[derive(Clone)]
pub enum RxFilter {
    /// Keep every frame (promiscuous / broadcast join).
    Open,
    /// **Tier-0** (#91): keep any frame whose in-frame prefix-set filter (`addr1 ‖ addr2`) could be
    /// under one of these registered-prefix masks. Exact on the negative (definitely-not-under →
    /// drop, never parse), over-accepts on the positive.
    Bloom(Arc<[PrefixFilter]>),
    /// **The NDN-NIC baseline** (#101) — receiver-side BF-FIB over registered prefixes, queried with
    /// the *parsed* name. For A/B measurement, not production: it needs the parse Tier-0 exists to
    /// avoid, so selecting it forfeits the point.
    NdnNic(Arc<crate::ndn_nic::NdnNicFilter>),
}

/// Tier-0 (+ optional Tier-1) admission for one face.
pub struct NameGate {
    filter: RxFilter,
    /// **Tier-1** (#92), when this node runs one. `None` on an endpoint, where Tier-0 alone is the
    /// right trade — #101 measured Tier-0's false-positive rate climbing with registered-prefix
    /// count, so it suits small E and a relay wants Tier-1 instead.
    tier1: Option<Arc<std::sync::RwLock<crate::tier1::Tier1>>>,
    dropped_tier0: AtomicU64,
    dropped_tier1: AtomicU64,
}

impl NameGate {
    /// A gate that admits everything — the default, and what a face without name filtering uses.
    pub fn open() -> Self {
        Self::new(RxFilter::Open, None)
    }

    pub fn new(
        filter: RxFilter,
        tier1: Option<Arc<std::sync::RwLock<crate::tier1::Tier1>>>,
    ) -> Self {
        Self {
            filter,
            tier1,
            dropped_tier0: AtomicU64::new(0),
            dropped_tier1: AtomicU64::new(0),
        }
    }

    /// The current Tier-0 filter, so a builder can replace the Tier-1 half without discarding it
    /// (and vice versa). Cheap — `RxFilter` is `Arc`s.
    pub fn filter(&self) -> RxFilter {
        self.filter.clone()
    }

    /// The live Tier-1 handle, for the forwarder to drive from its real PIT/CS.
    pub fn tier1(&self) -> Option<Arc<std::sync::RwLock<crate::tier1::Tier1>>> {
        self.tier1.clone()
    }

    pub fn dropped_tier0(&self) -> u64 {
        self.dropped_tier0.load(Ordering::Relaxed)
    }

    pub fn dropped_tier1(&self) -> u64 {
        self.dropped_tier1.load(Ordering::Relaxed)
    }

    /// **Does this frame pass?** `addr1 ‖ addr2` carry the Tier-0 filter; `wire` is the payload,
    /// needed only by the tiers that parse.
    ///
    /// Broadcast always passes: a frame with no group is addressed to everyone, and dropping it here
    /// would silently break discovery and the time beacons.
    pub fn admits(
        &self,
        addr1: Option<[u8; 6]>,
        addr2: Option<[u8; 6]>,
        addr3: Option<[u8; 6]>,
        wire: &[u8],
    ) -> bool {
        // **Broadcast skips TIER-0 ONLY, never Tier-1.**
        //
        // Tier-0 reads the filter out of `addr1 ‖ addr2`, so a frame with no group address carries no
        // filter to test and must pass. Tier-1 is a different question — "do I want this name?" — and
        // on a broadcast medium *every* frame is broadcast, so returning early here would disable
        // Tier-1 entirely. Consolidating the two gates, I first wrote a single early return and two
        // Tier-1 tests failed immediately; without them this would have shipped as a filter that
        // quietly does nothing on exactly the medium it was built for.
        let tier0_ok = match (addr1, &self.filter) {
            (None, _) => true,
            (Some(a1), _) if a1 == BROADCAST => true,
            (Some(_), RxFilter::Open) => true,
            (Some(a1), RxFilter::Bloom(masks)) => {
                let Some(a2) = addr2 else { return true };
                // The 126-bit Blur spans addr1‖addr2‖addr3[0..4] (wire-format-spec §5.3). addr3's
                // last two bytes are the ephemeral ID + flags, not filter — a legacy frame with no
                // addr3 leaves those four bytes clear, which only *loosens* the match (over-accept),
                // never a false negative.
                let mut w = [0u8; 16];
                w[..6].copy_from_slice(&a1);
                w[6..12].copy_from_slice(&a2);
                if let Some(a3) = addr3 {
                    w[12..16].copy_from_slice(&a3[..4]);
                }
                let frame = PrefixFilter::from_wire(w);
                masks.iter().any(|m| frame.may_match(m))
            }
            // The baseline's cost is visible here: it cannot answer without decoding far enough to
            // find the Name TLV. The Tier-0 arm above never touches `wire`.
            (Some(_), RxFilter::NdnNic(bf)) => match inner_name(wire) {
                Some(name) => bf.may_serve(&ndn_name_to_slash(name)),
                None => true,
            },
        };
        if !tier0_ok {
            self.dropped_tier0.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        // ── Tier-1: on the parsed name, after Tier-0 admits ──────────────────────────────────
        // A frame with no name (a non-first fragment) passes: reassembly needs it, and the first
        // fragment already faced both gates.
        if let Some(t1) = self.tier1.as_ref()
            && let Some(name) = inner_name(wire)
        {
            let slash = ndn_name_to_slash(name);
            let miss = match t1.read() {
                Ok(g) => g.lookup(&slash).is_miss(),
                // A poisoned lock must not silently start dropping traffic: fail open. The filter is
                // an optimisation; the forwarder behind it is the correctness layer.
                Err(_) => false,
            };
            if miss {
                self.dropped_tier1.fetch_add(1, Ordering::Relaxed);
                return false;
            }
        }
        true
    }
}

impl Default for NameGate {
    fn default() -> Self {
        Self::open()
    }
}
