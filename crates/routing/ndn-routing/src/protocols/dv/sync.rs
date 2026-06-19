//! ndn-dv Advertisement Sync — wire layer + face/active tracking.
//!
//! Wraps [`SvsLocal`] (from `ndn-sync`) with:
//! - SPEC-compliant name builders for the four `/localhop` prefixes
//!   per `ndnd/dv/SPEC.md` §2.
//! - Sync Interest construction: the Interest carries a Data packet in
//!   `ApplicationParameters`, mirroring ndnd's
//!   `advert_sync.go::sendSyncInterestImpl`. Inner Data content is the
//!   SVS v3 state vector.
//! - Per-neighbour face tracking with active-wins-over-passive precedence
//!   per `ndnd/dv/table/neighbor_table.go::RecvPing`.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use bytes::Bytes;
use ndn_packet::{Data, Interest, Name, NameComponent, encode::InterestBuilder};
use ndn_sync::{NeighborAdvance, SvsLocal, SvsLocalError, decode_svs_data};
use ndn_transport::FaceId;

const KW_DV: &[u8] = b"DV";
const KW_ADS: &[u8] = b"ADS";
const KW_ACT: &[u8] = b"ACT";
const KW_PSV: &[u8] = b"PSV";
const KW_ADV: &[u8] = b"ADV";
const KW_SYNC: &[u8] = b"SYNC";
const LOCALHOP: &[u8] = b"localhop";

/// `Active` Sync Interests are sent to an explicitly configured
/// neighbour, FIB-routed via the active prefix. `Passive` are sent on
/// the incoming face of a prior sync, FIB-routed via the passive prefix.
/// Per SPEC.md §4 *Advertisement Broadcast*, active wins over passive
/// for face-routing purposes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncKind {
    Active,
    Passive,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DvSyncError {
    InterestDecode,
    /// ndn-dv sync always carries a Data packet in AppParam (SPEC.md §4).
    MissingAppParam,
    DataDecode,
    Svs(SvsLocalError),
}

impl From<SvsLocalError> for DvSyncError {
    fn from(err: SvsLocalError) -> Self {
        DvSyncError::Svs(err)
    }
}

impl std::fmt::Display for DvSyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DvSyncError::InterestDecode => write!(f, "sync Interest decode failed"),
            DvSyncError::MissingAppParam => {
                write!(
                    f,
                    "sync Interest missing AppParam (Data-in-AppParam required)"
                )
            }
            DvSyncError::DataDecode => write!(f, "sync Interest AppParam is not a valid Data"),
            DvSyncError::Svs(e) => write!(f, "sync state-vector codec: {e}"),
        }
    }
}

impl std::error::Error for DvSyncError {}

/// A neighbour whose tracked face just changed. Stage 3 will translate
/// this into FIB updates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaceChange {
    pub neighbor: Name,
    pub old_face: Option<FaceId>,
    pub new_face: FaceId,
    /// Whether the new face is `active` (true) or `passive` (false).
    /// Once a face is bound as active, subsequent passive syncs from
    /// the same neighbour are ignored for face-update purposes.
    pub now_active: bool,
}

/// Outcome of processing one incoming Sync Interest.
#[derive(Clone, Debug, Default)]
pub struct SyncReceipt {
    /// Neighbours whose `(boot, seq)` advanced — caller should fetch
    /// `/localhop/<neighbor>/32=DV/32=ADV/t=<boot>/v=<seq>`.
    pub advances: Vec<NeighborAdvance>,
    /// Neighbours whose face binding changed — caller may need to
    /// update FIB.
    pub face_changes: Vec<FaceChange>,
}

/// Mirrors ndnd's `NeighborState` (`dv/table/neighbor_table.go`).
#[derive(Clone, Debug)]
struct FaceBinding {
    face_id: FaceId,
    is_active: bool,
    /// Updated by [`DvSync::update_face`] on every receipt; drives
    /// dead-neighbour detection.
    last_seen: Instant,
}

/// Owned by a router. Combines [`SvsLocal`] (self + neighbour
/// `(boot, seq)` tracking) with face/active state. Pure state +
/// codec; no I/O.
pub struct DvSync {
    network: Name,
    router: Name,
    svs: SvsLocal,
    faces: RwLock<HashMap<Name, FaceBinding>>,
    /// Defaults to [`crate::protocols::dv::signing::InsecureTrust`]
    /// (`DigestSha256` outgoing, accepts every incoming packet —
    /// matches ndnd's `KeyChainUri = "insecure"`).
    trust: crate::protocols::dv::signing::DvTrustHandle,
}

impl DvSync {
    /// Uses [`crate::protocols::dv::signing::InsecureTrust`]; call
    /// [`with_trust`] to install
    /// [`crate::protocols::dv::signing::StaticTrust`] or
    /// [`crate::protocols::dv::signing::LvsTrust`].
    pub fn new(network: Name, router: Name, boot: u64) -> Self {
        Self::with_trust(
            network,
            router,
            boot,
            crate::protocols::dv::signing::InsecureTrust::handle(),
        )
    }

    pub fn with_trust(
        network: Name,
        router: Name,
        boot: u64,
        trust: crate::protocols::dv::signing::DvTrustHandle,
    ) -> Self {
        Self {
            network,
            router: router.clone(),
            svs: SvsLocal::new(router, boot),
            faces: RwLock::new(HashMap::new()),
            trust,
        }
    }

    pub fn trust(&self) -> &crate::protocols::dv::signing::DvTrustHandle {
        &self.trust
    }

    /// `/localhop/<network>/32=DV/32=ADS/32=ACT` — the FIB-routed
    /// prefix for active Sync Interests.
    pub fn active_sync_prefix(&self) -> Name {
        let mut name = localhop().append_components(self.network.components());
        name = name
            .append_component(NameComponent::keyword(Bytes::from_static(KW_DV)))
            .append_component(NameComponent::keyword(Bytes::from_static(KW_ADS)))
            .append_component(NameComponent::keyword(Bytes::from_static(KW_ACT)));
        name
    }

    /// `/localhop/<network>/32=DV/32=ADS/32=PSV` — the FIB-routed
    /// prefix for passive Sync Interests.
    pub fn passive_sync_prefix(&self) -> Name {
        let mut name = localhop().append_components(self.network.components());
        name = name
            .append_component(NameComponent::keyword(Bytes::from_static(KW_DV)))
            .append_component(NameComponent::keyword(Bytes::from_static(KW_ADS)))
            .append_component(NameComponent::keyword(Bytes::from_static(KW_PSV)));
        name
    }

    /// `/localhop/<router>/32=DV/32=ADV/32=SYNC` — the name of the
    /// Data packet carried inside an outgoing Sync Interest's
    /// AppParam (per ndnd's `advert_sync.go`).
    pub fn sync_data_name(&self) -> Name {
        let mut name = localhop().append_components(self.router.components());
        name = name
            .append_component(NameComponent::keyword(Bytes::from_static(KW_DV)))
            .append_component(NameComponent::keyword(Bytes::from_static(KW_ADV)))
            .append_component(NameComponent::keyword(Bytes::from_static(KW_SYNC)));
        name
    }

    /// `/localhop/<router>/32=DV/32=ADV/t=<boot>/v=<seq>` — name of
    /// an Advertisement Data packet (fetch target).
    pub fn advertisement_data_name(&self, boot: u64, seq: u64) -> Name {
        Self::peer_advertisement_data_name(&self.router, boot, seq)
    }

    /// `/localhop/<router>/32=DV/32=ADV` — the prefix under which
    /// every Advertisement Data variant for this router lives.
    /// A FIB entry under this prefix routes peer fetches to the
    /// producer face.
    pub fn advertisement_data_prefix(&self) -> Name {
        let mut name = localhop().append_components(self.router.components());
        name = name
            .append_component(NameComponent::keyword(Bytes::from_static(KW_DV)))
            .append_component(NameComponent::keyword(Bytes::from_static(KW_ADV)));
        name
    }

    /// Same shape as [`advertisement_data_name`] but for an
    /// arbitrary peer.
    pub fn peer_advertisement_data_name(peer: &Name, boot: u64, seq: u64) -> Name {
        let mut name = Self::peer_advertisement_data_prefix(peer);
        name = name
            .append_component(NameComponent::timestamp(boot))
            .append_component(NameComponent::version(seq));
        name
    }

    /// `/localhop/<peer>/32=DV/32=ADV` — peer-published Adv Data
    /// prefix. `DvProtocol::on_inbound` installs a bootstrap FIB
    /// entry under this so the follow-up Adv Data fetch reaches the
    /// peer on first contact.
    pub fn peer_advertisement_data_prefix(peer: &Name) -> Name {
        let mut name = localhop().append_components(peer.components());
        name = name
            .append_component(NameComponent::keyword(Bytes::from_static(KW_DV)))
            .append_component(NameComponent::keyword(Bytes::from_static(KW_ADV)));
        name
    }

    pub fn router_name(&self) -> &Name {
        &self.router
    }
    pub fn network(&self) -> &Name {
        &self.network
    }
    pub fn boot(&self) -> u64 {
        self.svs.boot()
    }
    pub fn current_seq(&self) -> u64 {
        self.svs.current_seq()
    }

    /// Call when the router's published advertisement changes.
    pub fn advance_seq(&self) -> u64 {
        self.svs.advance_seq()
    }

    pub fn neighbor_seq(&self, name: &Name) -> Option<(u64, u64)> {
        self.svs.neighbor(name).map(|s| (s.boot, s.seq))
    }

    pub fn tracked_neighbor_count(&self) -> usize {
        self.svs.neighbors().len()
    }

    pub fn neighbor_face(&self, name: &Name) -> Option<(FaceId, bool)> {
        let faces = self.faces.read().expect("DvSync::faces poisoned");
        faces.get(name).map(|b| (b.face_id, b.is_active))
    }

    /// Both `Active` and `Passive` carry the same payload (a self-only
    /// state vector wrapped in a Data packet); the receiver
    /// distinguishes by which prefix the Interest matched on the FIB.
    pub fn build_sync_interest(&self, kind: SyncKind) -> Bytes {
        let sv_bytes = self.svs.encode_self_state_vector();
        let inner_data = crate::protocols::dv::signing::encode_inner_data(
            &self.sync_data_name(),
            &sv_bytes,
            self.trust.as_ref(),
        );

        let interest_name = match kind {
            SyncKind::Active => self.active_sync_prefix(),
            SyncKind::Passive => self.passive_sync_prefix(),
        };
        InterestBuilder::new(interest_name)
            .lifetime(Duration::from_millis(1000))
            .hop_limit(2) // SPEC.md §4: HopLimit of 2, localhop
            .app_parameters(inner_data.to_vec())
            .build()
    }

    /// Per SPEC.md §4 step 6, the incoming face of a Sync Interest is
    /// used to set up data routes to that neighbour. Per step 3, an
    /// active sync wins over a passive sync for face routing when both
    /// apply.
    pub fn process_sync_interest(
        &self,
        interest_bytes: &Bytes,
        incoming_face: FaceId,
        kind: SyncKind,
    ) -> Result<SyncReceipt, DvSyncError> {
        let interest =
            Interest::decode(interest_bytes.clone()).map_err(|_| DvSyncError::InterestDecode)?;
        let app_param = interest
            .app_parameters()
            .cloned()
            .ok_or(DvSyncError::MissingAppParam)?;

        // Untrusted/forged Data is silently dropped — the receipt is
        // empty so no face binding moves and no advance is queued.
        // Insecure deployments fall through `validate`'s default impl
        // which accepts everything.
        let data = Data::decode(app_param).map_err(|_| DvSyncError::DataDecode)?;
        if !crate::protocols::dv::signing::validate_inner_data(&data, self.trust.as_ref()) {
            return Ok(SyncReceipt::default());
        }
        let content = data.content().cloned().unwrap_or_default();
        let entries = decode_svs_data(&content)?;

        let mut receipt = SyncReceipt::default();
        let is_active = kind == SyncKind::Active;
        for entry in &entries {
            if let Some(change) = self.update_face(&entry.name, incoming_face, is_active) {
                receipt.face_changes.push(change);
            }
            if let Some(adv) = self.svs.apply_entry(entry) {
                receipt.advances.push(adv);
            }
        }
        Ok(receipt)
    }

    /// Mirrors `ndnd/dv/table/neighbor_table.go::RecvPing`. Returns a
    /// [`FaceChange`] if the binding moved or `None` if unchanged (or
    /// skipped because an active binding shadows a passive sync).
    fn update_face(&self, neighbor: &Name, face_id: FaceId, is_active: bool) -> Option<FaceChange> {
        if neighbor == &self.router {
            return None;
        }
        let mut faces = self.faces.write().expect("DvSync::faces poisoned");
        match faces.get_mut(neighbor) {
            Some(binding) => {
                // Active binding shadows passive pings entirely
                // (no face update, no freshness bump).
                if binding.is_active && !is_active {
                    return None;
                }
                let now = Instant::now();
                binding.last_seen = now;
                if binding.face_id != face_id || binding.is_active != is_active {
                    let old_face = Some(binding.face_id);
                    binding.face_id = face_id;
                    binding.is_active = is_active;
                    Some(FaceChange {
                        neighbor: neighbor.clone(),
                        old_face,
                        new_face: face_id,
                        now_active: is_active,
                    })
                } else {
                    None
                }
            }
            None => {
                faces.insert(
                    neighbor.clone(),
                    FaceBinding {
                        face_id,
                        is_active,
                        last_seen: Instant::now(),
                    },
                );
                Some(FaceChange {
                    neighbor: neighbor.clone(),
                    old_face: None,
                    new_face: face_id,
                    now_active: is_active,
                })
            }
        }
    }

    /// Names of neighbours whose `last_seen` is older than
    /// `now - dead_interval`. Caller drops the face binding via
    /// [`forget_neighbor`] and clears RIB routes through them.
    pub fn dead_neighbors(&self, now: Instant, dead_interval: Duration) -> Vec<Name> {
        let faces = self.faces.read().expect("DvSync::faces poisoned");
        faces
            .iter()
            .filter(|(_, b)| now.duration_since(b.last_seen) >= dead_interval)
            .map(|(n, _)| n.clone())
            .collect()
    }

    /// Drop the face binding for `neighbor`. The underlying SVS state
    /// is intentionally preserved: on rejoin, the SVS skip-rule
    /// handles a new boot timestamp, and a same-boot higher-seq
    /// rejoin picks up where we left off.
    pub fn forget_neighbor(&self, neighbor: &Name) {
        let mut faces = self.faces.write().expect("DvSync::faces poisoned");
        faces.remove(neighbor);
    }
}

fn localhop() -> Name {
    Name::root().append_component(NameComponent::generic(Bytes::from_static(LOCALHOP)))
}

trait NameAppendExt {
    fn append_components(self, comps: &[NameComponent]) -> Self;
}

impl NameAppendExt for Name {
    fn append_components(mut self, comps: &[NameComponent]) -> Self {
        for c in comps {
            self = self.append_component(c.clone());
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn name(s: &str) -> Name {
        Name::from_str(s).expect("valid name")
    }

    fn fresh(router: &str, boot: u64) -> DvSync {
        DvSync::new(name("/ndn"), name(router), boot)
    }

    #[test]
    fn active_prefix_matches_spec() {
        let dv = fresh("/r1", 100);
        let p = dv.active_sync_prefix();
        assert_eq!(p.len(), 5); // localhop + ndn + DV + ADS + ACT
        assert_eq!(p.components()[0].value.as_ref(), b"localhop");
        assert_eq!(p.components()[1].value.as_ref(), b"ndn");
        assert_eq!(p.components()[2].value.as_ref(), b"DV");
        assert_eq!(p.components()[3].value.as_ref(), b"ADS");
        assert_eq!(p.components()[4].value.as_ref(), b"ACT");
        // The keyword components use type 0x20 per NDN naming conventions.
        for &i in &[2, 3, 4] {
            assert_eq!(p.components()[i].typ, 0x20);
        }
    }

    #[test]
    fn passive_prefix_matches_spec() {
        let dv = fresh("/r1", 100);
        let p = dv.passive_sync_prefix();
        assert_eq!(p.components()[4].value.as_ref(), b"PSV");
    }

    #[test]
    fn sync_data_name_matches_spec() {
        let dv = fresh("/r1", 100);
        let p = dv.sync_data_name();
        // /localhop/r1/32=DV/32=ADV/32=SYNC
        assert_eq!(p.len(), 5);
        assert_eq!(p.components()[0].value.as_ref(), b"localhop");
        assert_eq!(p.components()[1].value.as_ref(), b"r1");
        assert_eq!(p.components()[2].value.as_ref(), b"DV");
        assert_eq!(p.components()[3].value.as_ref(), b"ADV");
        assert_eq!(p.components()[4].value.as_ref(), b"SYNC");
    }

    #[test]
    fn advertisement_data_name_matches_spec() {
        let dv = fresh("/r1", 100);
        let p = dv.advertisement_data_name(12345, 7);
        // /localhop/r1/32=DV/32=ADV/t=12345/v=7
        assert_eq!(p.len(), 6);
        let comps = p.components();
        assert_eq!(comps[2].value.as_ref(), b"DV");
        assert_eq!(comps[3].value.as_ref(), b"ADV");
        // Timestamp component type = 0x38 (NDN naming conventions).
        assert_eq!(comps[4].typ, 0x38);
        // Version component type = 0x36.
        assert_eq!(comps[5].typ, 0x36);
    }

    #[test]
    fn build_sync_interest_active_is_valid_interest() {
        let dv = fresh("/r1", 100);
        dv.advance_seq();
        let wire = dv.build_sync_interest(SyncKind::Active);
        let interest = Interest::decode(wire).expect("Sync Interest must be valid");
        // Name should be the active sync prefix (with a trailing
        // ParametersSha256DigestComponent appended by InterestBuilder).
        let comps = interest.name.components();
        // 5 spec-defined components + 1 PSDC = 6
        assert_eq!(comps.len(), 6);
        assert_eq!(comps[4].value.as_ref(), b"ACT");
        // HopLimit must be 2 per SPEC.md §4.
        assert_eq!(interest.hop_limit(), Some(2));
        assert!(interest.app_parameters().is_some());
    }

    #[test]
    fn build_passive_interest_uses_passive_prefix() {
        let dv = fresh("/r1", 100);
        let wire = dv.build_sync_interest(SyncKind::Passive);
        let interest = Interest::decode(wire).unwrap();
        assert_eq!(interest.name.components()[4].value.as_ref(), b"PSV");
    }

    #[test]
    fn two_routers_converge_via_active_sync() {
        let r1 = fresh("/r1", 100);
        let r2 = fresh("/r2", 200);

        // r1 publishes an advertisement (seq -> 1) and sends an active sync.
        r1.advance_seq();
        let wire = r1.build_sync_interest(SyncKind::Active);

        // r2 receives it on face 7 as an active sync.
        let receipt = r2
            .process_sync_interest(&wire, FaceId(7), SyncKind::Active)
            .unwrap();
        assert_eq!(receipt.advances.len(), 1);
        assert_eq!(receipt.advances[0].name, name("/r1"));
        assert_eq!(receipt.advances[0].boot, 100);
        assert_eq!(receipt.advances[0].seq, 1);
        assert_eq!(receipt.face_changes.len(), 1);
        assert_eq!(receipt.face_changes[0].neighbor, name("/r1"));
        assert_eq!(receipt.face_changes[0].new_face, FaceId(7));
        assert!(receipt.face_changes[0].now_active);

        // Symmetric: r2 sends, r1 receives on face 8.
        r2.advance_seq();
        r2.advance_seq();
        let wire = r2.build_sync_interest(SyncKind::Active);
        let receipt = r1
            .process_sync_interest(&wire, FaceId(8), SyncKind::Active)
            .unwrap();
        assert_eq!(receipt.advances[0].seq, 2);

        // Both routers now have the other's (boot, seq) tracked.
        assert_eq!(r1.neighbor_seq(&name("/r2")), Some((200, 2)));
        assert_eq!(r2.neighbor_seq(&name("/r1")), Some((100, 1)));
    }

    #[test]
    fn duplicate_sync_does_not_re_advance() {
        let r1 = fresh("/r1", 100);
        let r2 = fresh("/r2", 200);
        r1.advance_seq();
        let wire = r1.build_sync_interest(SyncKind::Active);

        let first = r2
            .process_sync_interest(&wire, FaceId(7), SyncKind::Active)
            .unwrap();
        let second = r2
            .process_sync_interest(&wire, FaceId(7), SyncKind::Active)
            .unwrap();

        assert_eq!(first.advances.len(), 1);
        assert!(
            second.advances.is_empty(),
            "same (boot, seq) must not re-advance",
        );
        // Face binding stable across identical syncs.
        assert!(second.face_changes.is_empty());
    }

    #[test]
    fn passive_does_not_overwrite_active() {
        let r2 = fresh("/r2", 200);
        let r1 = fresh("/r1", 100);
        r1.advance_seq();
        let active_wire = r1.build_sync_interest(SyncKind::Active);
        let passive_wire = r1.build_sync_interest(SyncKind::Passive);

        // Active sync from r1 on face 7 — r2 binds r1 to face 7 (active).
        let _ = r2
            .process_sync_interest(&active_wire, FaceId(7), SyncKind::Active)
            .unwrap();
        assert_eq!(r2.neighbor_face(&name("/r1")), Some((FaceId(7), true)));

        // Passive sync from r1 on face 9 — should NOT overwrite, per
        // SPEC.md §4 (active wins over passive). r2's binding stays
        // at (face 7, active).
        let receipt = r2
            .process_sync_interest(&passive_wire, FaceId(9), SyncKind::Passive)
            .unwrap();
        assert!(
            receipt.face_changes.is_empty(),
            "passive must not displace active",
        );
        assert_eq!(r2.neighbor_face(&name("/r1")), Some((FaceId(7), true)));
    }

    #[test]
    fn active_overwrites_passive() {
        let r2 = fresh("/r2", 200);
        let r1 = fresh("/r1", 100);
        r1.advance_seq();
        let passive_wire = r1.build_sync_interest(SyncKind::Passive);
        let active_wire = r1.build_sync_interest(SyncKind::Active);

        // First, passive bind on face 9.
        let _ = r2
            .process_sync_interest(&passive_wire, FaceId(9), SyncKind::Passive)
            .unwrap();
        assert_eq!(r2.neighbor_face(&name("/r1")), Some((FaceId(9), false)));

        // Now an active sync on face 7 — should win.
        let receipt = r2
            .process_sync_interest(&active_wire, FaceId(7), SyncKind::Active)
            .unwrap();
        assert_eq!(receipt.face_changes.len(), 1);
        assert_eq!(receipt.face_changes[0].old_face, Some(FaceId(9)));
        assert_eq!(receipt.face_changes[0].new_face, FaceId(7));
        assert!(receipt.face_changes[0].now_active);
        assert_eq!(r2.neighbor_face(&name("/r1")), Some((FaceId(7), true)));
    }

    #[test]
    fn passive_face_change_tracked() {
        let r2 = fresh("/r2", 200);
        let r1 = fresh("/r1", 100);
        r1.advance_seq();
        let passive_wire = r1.build_sync_interest(SyncKind::Passive);

        let _ = r2
            .process_sync_interest(&passive_wire, FaceId(9), SyncKind::Passive)
            .unwrap();
        // Same neighbour, different passive face — face_change emitted.
        let receipt = r2
            .process_sync_interest(&passive_wire, FaceId(10), SyncKind::Passive)
            .unwrap();
        assert_eq!(receipt.face_changes.len(), 1);
        assert_eq!(receipt.face_changes[0].old_face, Some(FaceId(9)));
        assert_eq!(receipt.face_changes[0].new_face, FaceId(10));
        assert!(!receipt.face_changes[0].now_active);
    }

    #[test]
    fn dead_neighbors_empty_with_no_bindings() {
        let s = fresh("/me", 100);
        assert!(
            s.dead_neighbors(Instant::now(), Duration::from_secs(60))
                .is_empty()
        );
    }

    #[test]
    fn dead_neighbors_excludes_recently_seen() {
        // After receiving a sync, the neighbour is bound with last_seen
        // ≈ now. With a 60s dead-interval, it should NOT be reported as dead.
        let s = fresh("/me", 100);
        let peer = fresh("/r2", 200);
        peer.advance_seq();
        let wire = peer.build_sync_interest(SyncKind::Active);
        s.process_sync_interest(&wire, FaceId(7), SyncKind::Active)
            .unwrap();
        let now = Instant::now();
        let dead = s.dead_neighbors(now, Duration::from_secs(60));
        assert!(dead.is_empty(), "freshly-seen neighbour must not be dead");
    }

    #[test]
    fn dead_neighbors_reports_stale_bindings() {
        // Use a near-zero dead_interval so the bound neighbour is
        // immediately considered dead.
        let s = fresh("/me", 100);
        let peer = fresh("/r2", 200);
        peer.advance_seq();
        let wire = peer.build_sync_interest(SyncKind::Active);
        s.process_sync_interest(&wire, FaceId(7), SyncKind::Active)
            .unwrap();
        // Advance "now" beyond the dead interval (use a duration
        // smaller than the time since the bind, then check "future"
        // now).
        std::thread::sleep(Duration::from_millis(5));
        let now = Instant::now();
        let dead = s.dead_neighbors(now, Duration::from_millis(1));
        assert_eq!(dead, vec![name("/r2")]);
    }

    #[test]
    fn forget_neighbor_drops_face_binding() {
        let s = fresh("/me", 100);
        let peer = fresh("/r2", 200);
        peer.advance_seq();
        let wire = peer.build_sync_interest(SyncKind::Active);
        s.process_sync_interest(&wire, FaceId(7), SyncKind::Active)
            .unwrap();
        assert_eq!(s.neighbor_face(&name("/r2")), Some((FaceId(7), true)));

        s.forget_neighbor(&name("/r2"));
        assert_eq!(s.neighbor_face(&name("/r2")), None);
        // SVS state intact — a fresh sync with same (boot, seq) is
        // therefore stale; with a higher seq, it advances.
        assert_eq!(s.neighbor_seq(&name("/r2")), Some((200, 1)));
    }

    #[test]
    fn rebinding_face_resets_last_seen() {
        // Two syncs from the same neighbour separated in time —
        // dead_neighbors using the LATER bind time should not flag
        // them, because update_face refreshes last_seen.
        let s = fresh("/me", 100);
        let peer = fresh("/r2", 200);
        peer.advance_seq();
        let wire1 = peer.build_sync_interest(SyncKind::Active);
        s.process_sync_interest(&wire1, FaceId(7), SyncKind::Active)
            .unwrap();
        std::thread::sleep(Duration::from_millis(3));
        // Same neighbour, same face, no seq change (treated as keepalive).
        s.process_sync_interest(&wire1, FaceId(7), SyncKind::Active)
            .unwrap();
        // 1ms dead-interval from now should still exclude the
        // neighbour because last_seen was just refreshed.
        let dead = s.dead_neighbors(Instant::now(), Duration::from_millis(50));
        assert!(dead.is_empty(), "keepalive must reset last_seen");
    }

    #[test]
    fn rejects_interest_without_app_param() {
        let r2 = fresh("/r2", 200);
        // Build a bare Interest with no AppParam.
        let interest_wire = InterestBuilder::new(name("/ndn/x")).build();
        let err = r2
            .process_sync_interest(&interest_wire, FaceId(1), SyncKind::Active)
            .unwrap_err();
        assert_eq!(err, DvSyncError::MissingAppParam);
    }

    #[test]
    fn rejects_malformed_app_param_data() {
        let r2 = fresh("/r2", 200);
        // Interest with AppParam that's NOT a valid Data packet.
        let interest_wire = InterestBuilder::new(name("/ndn/x"))
            .app_parameters(vec![0x00, 0x01, 0x02])
            .build();
        let err = r2
            .process_sync_interest(&interest_wire, FaceId(1), SyncKind::Active)
            .unwrap_err();
        assert_eq!(err, DvSyncError::DataDecode);
    }

    #[test]
    fn self_reflection_is_ignored_for_face_tracking() {
        let r1 = fresh("/r1", 100);
        r1.advance_seq();
        // r1 receives its own sync (could happen with a multicast loop
        // mis-configuration). Should NOT bind a face for self.
        let wire = r1.build_sync_interest(SyncKind::Active);
        let receipt = r1
            .process_sync_interest(&wire, FaceId(5), SyncKind::Active)
            .unwrap();
        assert!(receipt.advances.is_empty(), "self-bounce must not advance");
        assert!(
            receipt.face_changes.is_empty(),
            "self-bounce must not bind face",
        );
    }
}
