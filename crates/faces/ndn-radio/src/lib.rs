//! **The unified `Radio`** — ONE `ndn_transport::Transport` the forwarder sees, over **N named-radio
//! phys** (Wi-Fi / BLE / LoRa …). This is the "one wireless face" the NDR MAC presents upward
//! (`../ndn-phy-wifi/docs/phy-face-radio-coex.md`): the forwarder does `name → face` + PIT, and
//! *everything that makes wireless hard lives below this face* — which phy, fragmentation, coex, RX merge.
//!
//! The design is exactly what the forwarding-under-flux testing taught
//! (`../ndn-phy-wifi/docs/wireless-forwarding-under-flux.md` §10):
//!
//! - **Phy selection is the reach lever** ([`PhyPolicy`]). In a *single* broadcast medium the reach
//!   prior's accuracy was delivery-neutral (defer+overhear-cancel does the work); its fidelity only pays off
//!   when it **selects among options** — which is *this* seam. Long-reach/robust class → the highest
//!   `range_rank` phy (BLE-coded / LoRa); throughput class → the highest-MTU phy (Wi-Fi); default →
//!   *all* phys (macrodiversity — the engine's PIT and this face's RX dedup absorb the duplicate).
//! - **Fragmentation is phy-native** — there is **no single face MTU** ([`send_mtu`](Radio) returns
//!   `None`); each [`WirelessPhy`] fragments a whole packet to its *own* airtime-optimal ceiling internally.
//! - **RX merges + dedups across phys** — a per-phy pump feeds one queue; the same Data arriving via two
//!   phys (macrodiversity) is delivered to the forwarder **once**, keyed on the whole-object bytes (no host
//!   identity).
//! - **Coex lives below** — phys that share one radio front-end time-share it via the demand-driven split
//!   on the shared mux (`ndn_radio_drivers::SerialRadioBackend`); the face never sees it.

use std::collections::{HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use ndn_transport::{FaceError, FaceId, FaceKind, LinkType, Transport};
use smallvec::SmallVec;
use tokio::sync::{Mutex as AsyncMutex, mpsc};

/// The PHY family of a phy — a tag for the [`PhyPolicy`] and telemetry (not an on-air identity).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PhyKind {
    Wifi,
    Ble,
    LoRa,
    Other,
}

/// A named-radio **phy** the [`Radio`] multiplexes: a medium with its own airtime-optimal MTU and
/// reach, that fragments/reassembles *internally* (phy-native framing, below the face). Real backends adapt
/// to this — a BLE `AdvBackend`, a Wi-Fi `FrameIo`, a LoRa dongle — each already owning its own framing.
#[async_trait]
pub trait WirelessPhy: Send + Sync + 'static {
    fn kind(&self) -> PhyKind;
    /// Phy-native MTU ceiling (bytes) — the airtime-optimal frame size. Fragmentation to this is internal.
    fn mtu(&self) -> usize;
    /// Reach rank: higher = longer range / more robust (LoRa, BLE-coded > Wi-Fi). The reach lever's input.
    fn range_rank(&self) -> u8;
    /// Send a whole network packet; the phy fragments it to its own MTU and frames it on air.
    async fn send(&self, wire: Bytes) -> Result<(), FaceError>;
    /// Receive the next fully-reassembled network packet from this phy.
    async fn recv(&self) -> Result<Bytes, FaceError>;
}

/// Which phy(s) an outbound packet egresses on — **the reach lever**, name/class-seeded. This is the seam
/// where a reach prior's accuracy matters (multi-medium selection); a single-phy node degenerates to "the
/// one phy". Returns indices into the face's phy list; empty ⇒ drop; multiple ⇒ macrodiversity.
pub trait PhyPolicy: Send + Sync + 'static {
    fn select(&self, wire: &[u8], phys: &[Arc<dyn WirelessPhy>]) -> SmallVec<[usize; 2]>;

    /// RX feedback: the face calls this when a (deduped) object arrives on `phy` — evidence that phy
    /// currently reaches the name's producer/region. A learning policy reinforces a per-prefix reach prior
    /// here (the reach prior *selecting among phys* — the seam the forwarding-under-flux testing found is
    /// where prior accuracy matters). Default: stateless policies ignore it.
    fn observe_delivery(&self, _wire: &[u8], _bearer: usize) {}
}

/// Default: transmit on **all** phys (macrodiversity — the robust default). PIT + RX-dedup absorb the copies.
pub struct BroadcastAllPhys;
impl PhyPolicy for BroadcastAllPhys {
    fn select(&self, _wire: &[u8], phys: &[Arc<dyn WirelessPhy>]) -> SmallVec<[usize; 2]> {
        (0..phys.len()).collect()
    }
}

/// The reach class a name asks for — in a real deployment this is *name-computed* (the HOW-WELL facet). Here
/// it's supplied by a classifier closure so the seam is exercised without pinning a naming convention.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReachClass {
    /// Get it far / robustly — pick the longest-reach phy (LoRa/BLE-coded).
    Robust,
    /// Get it fast — pick the highest-MTU/throughput phy (Wi-Fi).
    Throughput,
    /// Reliability-critical — emit on *all* phys (macrodiversity).
    Redundant,
}

/// A reach-class phy policy: `classify(wire)` → [`ReachClass`] → the phy(s) that class wants. The
/// concrete realization of "phy selection is a HOW-WELL/WHERE cognition lever".
pub struct ReachClassPolicy<F: Fn(&[u8]) -> ReachClass + Send + Sync + 'static> {
    pub classify: F,
}

impl<F: Fn(&[u8]) -> ReachClass + Send + Sync + 'static> PhyPolicy for ReachClassPolicy<F> {
    fn select(&self, wire: &[u8], phys: &[Arc<dyn WirelessPhy>]) -> SmallVec<[usize; 2]> {
        if phys.is_empty() {
            return SmallVec::new();
        }
        match (self.classify)(wire) {
            ReachClass::Redundant => (0..phys.len()).collect(),
            ReachClass::Robust => {
                let i = (0..phys.len())
                    .max_by_key(|&i| phys[i].range_rank())
                    .unwrap();
                SmallVec::from_slice(&[i])
            }
            ReachClass::Throughput => {
                let i = (0..phys.len()).max_by_key(|&i| phys[i].mtu()).unwrap();
                SmallVec::from_slice(&[i])
            }
        }
    }
}

/// Adapt **any** `ndn_transport::Transport` — a BLE `AdvBackend`-backed face, a Wi-Fi face, the shared mux —
/// into a [`WirelessPhy`]. The Transport already sends/receives *whole packets with its own phy-native
/// framing*; this just attaches the `(kind, mtu, range_rank)` metadata the reach lever needs. Generic because
/// `Transport` uses native `async fn` (not object-safe) — build one per concrete backend; it erases to
/// `Arc<dyn WirelessPhy>` at the face boundary.
pub struct TransportPhy<T: Transport + Send + Sync + 'static> {
    inner: T,
    kind: PhyKind,
    mtu: usize,
    range_rank: u8,
}

impl<T: Transport + Send + Sync + 'static> TransportPhy<T> {
    /// Wrap `inner`; the MTU is its `send_mtu()` (or unbounded if it reports none — override with
    /// [`with_mtu`](Self::with_mtu) to the phy's true airtime-optimal ceiling).
    pub fn new(inner: T, kind: PhyKind, range_rank: u8) -> Self {
        let mtu = inner.send_mtu().unwrap_or(usize::MAX);
        Self {
            inner,
            kind,
            mtu,
            range_rank,
        }
    }
    /// Override the advertised MTU (the reach lever's throughput signal).
    pub fn with_mtu(mut self, mtu: usize) -> Self {
        self.mtu = mtu;
        self
    }
}

#[async_trait]
impl<T: Transport + Send + Sync + 'static> WirelessPhy for TransportPhy<T> {
    fn kind(&self) -> PhyKind {
        self.kind
    }
    fn mtu(&self) -> usize {
        self.mtu
    }
    fn range_rank(&self) -> u8 {
        self.range_rank
    }
    async fn send(&self, wire: Bytes) -> Result<(), FaceError> {
        self.inner.send_bytes(wire).await
    }
    async fn recv(&self) -> Result<Bytes, FaceError> {
        self.inner.recv_bytes().await
    }
}

/// A **name-computed** [`PhyPolicy`] (the HOW-WELL facet made concrete): extract the packet's NDN name and
/// map it to a [`ReachClass`] by longest-prefix rule, then select the phy that class wants. Unwraps an LP
/// frame to reach the Interest/Data name; an unparseable wire falls to `default`.
pub struct NameReachClassifier {
    rules: Vec<(ndn_packet::Name, ReachClass)>,
    default: ReachClass,
}

impl NameReachClassifier {
    pub fn new(default: ReachClass) -> Self {
        Self {
            rules: Vec::new(),
            default,
        }
    }
    /// Names under `prefix` get `class` (longest matching prefix wins).
    pub fn rule(mut self, prefix: impl Into<ndn_packet::Name>, class: ReachClass) -> Self {
        self.rules.push((prefix.into(), class));
        self
    }
    /// The reach class of a wire (best-effort name extraction).
    pub fn classify(&self, wire: &[u8]) -> ReachClass {
        let Some(name) = wire_name(wire) else {
            return self.default;
        };
        self.rules
            .iter()
            .filter(|(p, _)| name.has_prefix(p))
            .max_by_key(|(p, _)| p.components().len())
            .map(|(_, c)| *c)
            .unwrap_or(self.default)
    }
}

impl PhyPolicy for NameReachClassifier {
    fn select(&self, wire: &[u8], phys: &[Arc<dyn WirelessPhy>]) -> SmallVec<[usize; 2]> {
        if phys.is_empty() {
            return SmallVec::new();
        }
        match self.classify(wire) {
            ReachClass::Redundant => (0..phys.len()).collect(),
            ReachClass::Robust => SmallVec::from_slice(&[(0..phys.len())
                .max_by_key(|&i| phys[i].range_rank())
                .unwrap()]),
            ReachClass::Throughput => {
                SmallVec::from_slice(&[(0..phys.len()).max_by_key(|&i| phys[i].mtu()).unwrap()])
            }
        }
    }
}

/// Best-effort NDN name from a wire: unwrap an LP frame if present, then decode as Interest or Data.
fn wire_name(wire: &[u8]) -> Option<ndn_packet::Name> {
    let raw = Bytes::copy_from_slice(wire);
    let inner = if ndn_packet::lp::is_lp_packet(wire) {
        ndn_packet::lp::LpPacket::decode(raw).ok()?.fragment?
    } else {
        raw
    };
    if let Ok(i) = ndn_packet::Interest::decode(inner.clone()) {
        return Some((*i.name).clone());
    }
    if let Ok(d) = ndn_packet::Data::decode(inner) {
        return Some((*d.name).clone());
    }
    None
}

/// A **learning** [`PhyPolicy`] — the soft-prefix-reach prior applied to *phy selection*. It holds a
/// decaying per-`(prefix, phy)` reach weight, reinforced from RX ([`observe_delivery`](PhyPolicy::
/// observe_delivery)) — "Data for this prefix came back on that phy" — and on TX it sends the name out the
/// **highest-reach phy** once one is trusted, or **all** phys while the prefix is cold (exploration).
/// Decay lets a producer that moves to another phy be re-discovered (the warm phy fades → re-explore).
/// This is the culmination: in a *single* medium the prior's accuracy was delivery-neutral (defer+cancel did
/// the work), so its payoff is *here*, choosing among phys — exactly what the multi-producer test predicted.
pub struct LearnedPhyPolicy {
    prior: Mutex<std::collections::HashMap<u64, LearnedReach>>,
    reinforce: f64,
    tau: Duration,
    /// Min reach weight to *trust* a phy (below this the prefix is "cold" ⇒ explore all phys).
    threshold: f64,
    prefix_depth: usize,
}

struct LearnedReach {
    weights: Vec<f64>,
    last: std::time::Instant,
}

impl LearnedPhyPolicy {
    /// Defaults: `reinforce = 1.0`, `τ = 30 s`, `threshold = 0.5`, prefix depth 1.
    pub fn new() -> Self {
        Self {
            prior: Mutex::new(std::collections::HashMap::new()),
            reinforce: 1.0,
            tau: Duration::from_secs(30),
            threshold: 0.5,
            prefix_depth: 1,
        }
    }
    pub fn with_params(reinforce: f64, tau: Duration, threshold: f64, prefix_depth: usize) -> Self {
        Self {
            prior: Mutex::new(std::collections::HashMap::new()),
            reinforce,
            tau,
            threshold,
            prefix_depth: prefix_depth.max(1),
        }
    }

    fn key(&self, wire: &[u8]) -> Option<u64> {
        let name = wire_name(wire)?;
        let mut h = 0xcbf2_9ce4_8422_2325u64;
        for comp in name.components().iter().take(self.prefix_depth) {
            for b in comp.value.as_ref() {
                h ^= *b as u64;
                h = h.wrapping_mul(0x0100_0000_01b3);
            }
            h ^= 0x2f;
        }
        Some(h)
    }

    fn decay(&self, r: &mut LearnedReach) {
        let dt = r.last.elapsed().as_secs_f64();
        if dt > 0.0 {
            let f = (-dt / self.tau.as_secs_f64()).exp();
            for w in &mut r.weights {
                *w *= f;
            }
            r.last = std::time::Instant::now();
        }
    }
}

impl Default for LearnedPhyPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl PhyPolicy for LearnedPhyPolicy {
    fn select(&self, wire: &[u8], phys: &[Arc<dyn WirelessPhy>]) -> SmallVec<[usize; 2]> {
        let all = || (0..phys.len()).collect::<SmallVec<[usize; 2]>>();
        if phys.len() <= 1 {
            return all();
        }
        let Some(key) = self.key(wire) else {
            return all();
        };
        let mut map = self.prior.lock().unwrap();
        let Some(r) = map.get_mut(&key) else {
            return all();
        };
        self.decay(r);
        let n = r.weights.len().min(phys.len());
        match (0..n).max_by(|&a, &b| r.weights[a].total_cmp(&r.weights[b])) {
            Some(best) if r.weights[best] >= self.threshold => SmallVec::from_slice(&[best]),
            _ => all(), // cold / faded ⇒ explore every phy
        }
    }

    fn observe_delivery(&self, wire: &[u8], phy: usize) {
        let Some(key) = self.key(wire) else { return };
        let mut map = self.prior.lock().unwrap();
        let r = map.entry(key).or_insert_with(|| LearnedReach {
            weights: Vec::new(),
            last: std::time::Instant::now(),
        });
        self.decay(r);
        if r.weights.len() <= phy {
            r.weights.resize(phy + 1, 0.0);
        }
        r.weights[phy] += self.reinforce;
        r.last = std::time::Instant::now();
    }
}

/// Bounded whole-object dedup ring — the cross-phy RX filter. Keyed on the packet bytes (no host identity);
/// loss of the ring only re-admits a duplicate (a performance cost, never a correctness one — §7 soft-state).
struct Dedup {
    seen: HashSet<u64>,
    order: VecDeque<u64>,
    cap: usize,
}

impl Dedup {
    fn new(cap: usize) -> Self {
        Self {
            seen: HashSet::new(),
            order: VecDeque::new(),
            cap,
        }
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

/// One `Transport` over N phys. See the module docs.
pub struct Radio {
    id: FaceId,
    phys: Vec<Arc<dyn WirelessPhy>>,
    policy: Arc<dyn PhyPolicy>,
    /// Merged RX from every phy's pump, each object tagged with the phy index it arrived on.
    rx: AsyncMutex<mpsc::UnboundedReceiver<(usize, Bytes)>>,
    dedup: Mutex<Dedup>,
    /// Count of outbound `send_bytes` calls (each a forward/re-broadcast) — for measuring, e.g., how many
    /// re-broadcasts a relay's strategy suppressed via defer + overhear-cancel.
    tx_count: Arc<std::sync::atomic::AtomicU64>,
}

impl Radio {
    /// Build a wireless face over `phys` with the given selection `policy`. Spawns one RX pump per phy
    /// (needs a Tokio runtime — the host driving real radios has one).
    pub fn new(id: FaceId, phys: Vec<Arc<dyn WirelessPhy>>, policy: Arc<dyn PhyPolicy>) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        for (idx, phy) in phys.iter().enumerate() {
            let phy = Arc::clone(phy);
            let tx = tx.clone();
            tokio::spawn(async move {
                while let Ok(wire) = phy.recv().await {
                    if tx.send((idx, wire)).is_err() {
                        break; // face dropped
                    }
                }
            });
        }
        Self {
            id,
            phys,
            policy,
            rx: AsyncMutex::new(rx),
            dedup: Mutex::new(Dedup::new(DEDUP_CAP)),
            tx_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// A shared handle to the outbound-send counter — grab it before moving the face into an engine, then read
    /// how many forwards/re-broadcasts the face actually emitted (defer + overhear-cancel suppress relay ones).
    pub fn tx_counter(&self) -> Arc<std::sync::atomic::AtomicU64> {
        self.tx_count.clone()
    }

    /// Convenience: all-phy macrodiversity.
    pub fn broadcast(id: FaceId, phys: Vec<Arc<dyn WirelessPhy>>) -> Self {
        Self::new(id, phys, Arc::new(BroadcastAllPhys))
    }

    /// The phys, for coex/telemetry wiring below the face.
    pub fn phys(&self) -> &[Arc<dyn WirelessPhy>] {
        &self.phys
    }
}

impl Transport for Radio {
    fn id(&self) -> FaceId {
        self.id
    }

    fn kind(&self) -> FaceKind {
        // A shared, connectionless broadcast phy — the same face kind the monitor-wifi named radio uses.
        FaceKind::Wfb
    }

    fn remote_uri(&self) -> Option<String> {
        Some("wireless://multi-phy".into())
    }

    fn link_type(&self) -> LinkType {
        LinkType::AdHoc
    }

    /// **No single face MTU** — fragmentation is phy-native, below phy selection.
    fn send_mtu(&self) -> Option<usize> {
        None
    }

    async fn send_bytes(&self, wire: Bytes) -> Result<(), FaceError> {
        let sel = self.policy.select(&wire, &self.phys);
        if sel.is_empty() {
            return Ok(()); // policy dropped it (no eligible phy)
        }
        self.tx_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // Each selected phy fragments `wire` to its own MTU internally (phy-native).
        let mut last_err = None;
        for i in sel {
            if let Some(phy) = self.phys.get(i) {
                if let Err(e) = phy.send(wire.clone()).await {
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
        // Merge every phy's reassembled objects; deliver each distinct object once (cross-phy dedup).
        let mut rx = self.rx.lock().await;
        loop {
            let (phy, wire) = rx.recv().await.ok_or(FaceError::Closed)?;
            let dup = self.dedup.lock().unwrap().is_dup(&wire);
            if !dup {
                // Feedback to the (learning) policy: this phy is the one that delivered the object first.
                self.policy.observe_delivery(&wire, phy);
                return Ok(wire);
            }
        }
    }
}

#[cfg(test)]
mod tests;
