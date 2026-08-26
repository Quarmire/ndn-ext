//! **The unified `WirelessFace`** — ONE `ndn_transport::Transport` the forwarder sees, over **N named-radio
//! bearers** (Wi-Fi / BLE / LoRa …). This is the "one wireless face" the NDR MAC presents upward
//! (`../ndn-face-monitor-wifi/docs/bearer-face-radio-coex.md`): the forwarder does `name → face` + PIT, and
//! *everything that makes wireless hard lives below this face* — which bearer, fragmentation, coex, RX merge.
//!
//! The design is exactly what the forwarding-under-flux testing taught
//! (`../ndn-face-monitor-wifi/docs/wireless-forwarding-under-flux.md` §10):
//!
//! - **Bearer selection is the reach lever** ([`BearerPolicy`]). In a *single* broadcast medium the reach
//!   prior's accuracy was delivery-neutral (defer+overhear-cancel does the work); its fidelity only pays off
//!   when it **selects among options** — which is *this* seam. Long-reach/robust class → the highest
//!   `range_rank` bearer (BLE-coded / LoRa); throughput class → the highest-MTU bearer (Wi-Fi); default →
//!   *all* bearers (macrodiversity — the engine's PIT and this face's RX dedup absorb the duplicate).
//! - **Fragmentation is bearer-native** — there is **no single face MTU** ([`send_mtu`](WirelessFace) returns
//!   `None`); each [`WirelessBearer`] fragments a whole packet to its *own* airtime-optimal ceiling internally.
//! - **RX merges + dedups across bearers** — a per-bearer pump feeds one queue; the same Data arriving via two
//!   bearers (macrodiversity) is delivered to the forwarder **once**, keyed on the whole-object bytes (no host
//!   identity).
//! - **Coex lives below** — bearers that share one radio front-end time-share it via the demand-driven split
//!   on the shared mux (`ndn_radio_drivers::SerialRadioBackend`); the face never sees it.

use std::collections::{HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::Bytes;
use ndn_transport::{FaceError, FaceId, FaceKind, LinkType, Transport};
use smallvec::SmallVec;
use tokio::sync::{mpsc, Mutex as AsyncMutex};

/// The PHY family of a bearer — a tag for the [`BearerPolicy`] and telemetry (not an on-air identity).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BearerKind {
    Wifi,
    Ble,
    LoRa,
    Other,
}

/// A named-radio **bearer** the [`WirelessFace`] multiplexes: a medium with its own airtime-optimal MTU and
/// reach, that fragments/reassembles *internally* (bearer-native framing, below the face). Real backends adapt
/// to this — a BLE `AdvBackend`, a Wi-Fi `FrameIo`, a LoRa dongle — each already owning its own framing.
#[async_trait]
pub trait WirelessBearer: Send + Sync + 'static {
    fn kind(&self) -> BearerKind;
    /// Bearer-native MTU ceiling (bytes) — the airtime-optimal frame size. Fragmentation to this is internal.
    fn mtu(&self) -> usize;
    /// Reach rank: higher = longer range / more robust (LoRa, BLE-coded > Wi-Fi). The reach lever's input.
    fn range_rank(&self) -> u8;
    /// Send a whole network packet; the bearer fragments it to its own MTU and frames it on air.
    async fn send(&self, wire: Bytes) -> Result<(), FaceError>;
    /// Receive the next fully-reassembled network packet from this bearer.
    async fn recv(&self) -> Result<Bytes, FaceError>;
}

/// Which bearer(s) an outbound packet egresses on — **the reach lever**, name/class-seeded. This is the seam
/// where a reach prior's accuracy matters (multi-medium selection); a single-bearer node degenerates to "the
/// one bearer". Returns indices into the face's bearer list; empty ⇒ drop; multiple ⇒ macrodiversity.
pub trait BearerPolicy: Send + Sync + 'static {
    fn select(&self, wire: &[u8], bearers: &[Arc<dyn WirelessBearer>]) -> SmallVec<[usize; 2]>;
}

/// Default: transmit on **all** bearers (macrodiversity — the robust default). PIT + RX-dedup absorb the copies.
pub struct BroadcastAllBearers;
impl BearerPolicy for BroadcastAllBearers {
    fn select(&self, _wire: &[u8], bearers: &[Arc<dyn WirelessBearer>]) -> SmallVec<[usize; 2]> {
        (0..bearers.len()).collect()
    }
}

/// The reach class a name asks for — in a real deployment this is *name-computed* (the HOW-WELL facet). Here
/// it's supplied by a classifier closure so the seam is exercised without pinning a naming convention.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReachClass {
    /// Get it far / robustly — pick the longest-reach bearer (LoRa/BLE-coded).
    Robust,
    /// Get it fast — pick the highest-MTU/throughput bearer (Wi-Fi).
    Throughput,
    /// Reliability-critical — emit on *all* bearers (macrodiversity).
    Redundant,
}

/// A reach-class bearer policy: `classify(wire)` → [`ReachClass`] → the bearer(s) that class wants. The
/// concrete realization of "bearer selection is a HOW-WELL/WHERE cognition lever".
pub struct ReachClassPolicy<F: Fn(&[u8]) -> ReachClass + Send + Sync + 'static> {
    pub classify: F,
}

impl<F: Fn(&[u8]) -> ReachClass + Send + Sync + 'static> BearerPolicy for ReachClassPolicy<F> {
    fn select(&self, wire: &[u8], bearers: &[Arc<dyn WirelessBearer>]) -> SmallVec<[usize; 2]> {
        if bearers.is_empty() {
            return SmallVec::new();
        }
        match (self.classify)(wire) {
            ReachClass::Redundant => (0..bearers.len()).collect(),
            ReachClass::Robust => {
                let i = (0..bearers.len()).max_by_key(|&i| bearers[i].range_rank()).unwrap();
                SmallVec::from_slice(&[i])
            }
            ReachClass::Throughput => {
                let i = (0..bearers.len()).max_by_key(|&i| bearers[i].mtu()).unwrap();
                SmallVec::from_slice(&[i])
            }
        }
    }
}

/// Bounded whole-object dedup ring — the cross-bearer RX filter. Keyed on the packet bytes (no host identity);
/// loss of the ring only re-admits a duplicate (a performance cost, never a correctness one — §7 soft-state).
struct Dedup {
    seen: HashSet<u64>,
    order: VecDeque<u64>,
    cap: usize,
}

impl Dedup {
    fn new(cap: usize) -> Self {
        Self { seen: HashSet::new(), order: VecDeque::new(), cap }
    }
    /// Returns `true` if `wire` is a duplicate of a recently-seen object.
    fn is_dup(&mut self, wire: &[u8]) -> bool {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        wire.hash(&mut h);
        let key = h.finish();
        if !self.seen.insert(key) {
            return true;
        }
        self.order.push_back(key);
        if self.order.len() > self.cap {
            if let Some(old) = self.order.pop_front() {
                self.seen.remove(&old);
            }
        }
        false
    }
}

const DEDUP_CAP: usize = 4096;

/// One `Transport` over N bearers. See the module docs.
pub struct WirelessFace {
    id: FaceId,
    bearers: Vec<Arc<dyn WirelessBearer>>,
    policy: Arc<dyn BearerPolicy>,
    /// Merged RX from every bearer's pump.
    rx: AsyncMutex<mpsc::UnboundedReceiver<Bytes>>,
    dedup: Mutex<Dedup>,
}

impl WirelessFace {
    /// Build a wireless face over `bearers` with the given selection `policy`. Spawns one RX pump per bearer
    /// (needs a Tokio runtime — the host driving real radios has one).
    pub fn new(id: FaceId, bearers: Vec<Arc<dyn WirelessBearer>>, policy: Arc<dyn BearerPolicy>) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        for bearer in &bearers {
            let bearer = Arc::clone(bearer);
            let tx = tx.clone();
            tokio::spawn(async move {
                while let Ok(wire) = bearer.recv().await {
                    if tx.send(wire).is_err() {
                        break; // face dropped
                    }
                }
            });
        }
        Self { id, bearers, policy, rx: AsyncMutex::new(rx), dedup: Mutex::new(Dedup::new(DEDUP_CAP)) }
    }

    /// Convenience: all-bearer macrodiversity.
    pub fn broadcast(id: FaceId, bearers: Vec<Arc<dyn WirelessBearer>>) -> Self {
        Self::new(id, bearers, Arc::new(BroadcastAllBearers))
    }

    /// The bearers, for coex/telemetry wiring below the face.
    pub fn bearers(&self) -> &[Arc<dyn WirelessBearer>] {
        &self.bearers
    }
}

impl Transport for WirelessFace {
    fn id(&self) -> FaceId {
        self.id
    }

    fn kind(&self) -> FaceKind {
        // A shared, connectionless broadcast bearer — the same face kind the monitor-wifi named radio uses.
        FaceKind::Wfb
    }

    fn remote_uri(&self) -> Option<String> {
        Some("wireless://multi-bearer".into())
    }

    fn link_type(&self) -> LinkType {
        LinkType::AdHoc
    }

    /// **No single face MTU** — fragmentation is bearer-native, below bearer selection.
    fn send_mtu(&self) -> Option<usize> {
        None
    }

    async fn send_bytes(&self, wire: Bytes) -> Result<(), FaceError> {
        let sel = self.policy.select(&wire, &self.bearers);
        if sel.is_empty() {
            return Ok(()); // policy dropped it (no eligible bearer)
        }
        // Each selected bearer fragments `wire` to its own MTU internally (bearer-native).
        let mut last_err = None;
        for i in sel {
            if let Some(bearer) = self.bearers.get(i) {
                if let Err(e) = bearer.send(wire.clone()).await {
                    last_err = Some(e);
                }
            }
        }
        match last_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
        // Merge every bearer's reassembled objects; deliver each distinct object once (cross-bearer dedup).
        let mut rx = self.rx.lock().await;
        loop {
            let wire = rx.recv().await.ok_or(FaceError::Closed)?;
            let dup = self.dedup.lock().unwrap().is_dup(&wire);
            if !dup {
                return Ok(wire);
            }
        }
    }
}

#[cfg(test)]
mod tests;
