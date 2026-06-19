//! ndn-dv Prefix Sync wire layer — canonical SVS over the global
//! Prefix Sync group, per SPEC.md §2 and §4 *Prefix Sync*.
//!
//! Differs from [`super::sync::DvSync`] (local-variant Advertisement
//! Sync) in two ways: outgoing state vectors are canonical
//! (self + every tracked neighbour, not self-only), and names live
//! under `/<network>/32=DV/32=PFS/...` instead of `/localhop`.
//!
//! Names (SPEC.md §2):
//!
//! ```text
//! Sync group prefix  = /<network>/32=DV/32=PFS/32=svs
//! Prefix Data prefix = /<network>/32=DV/32=PFS/<router>
//! Prefix Data name   = /<network>/32=DV/32=PFS/<router>/t=<boot>/seq=<seq>/v=0
//! ```
//!
//! Pure wire layer. I/O lives in [`super::protocol`]; PrefixOpList
//! codec in [`super::tlv`]; table state in [`super::prefix`].

use std::time::Duration;

use bytes::Bytes;
use ndn_packet::encode::InterestBuilder;
use ndn_packet::{Data, Interest, Name, NameComponent};
use ndn_sync::{NeighborAdvance, SvsLocal, SvsLocalError, decode_svs_data};

const KW_DV: &[u8] = b"DV";
const KW_PFS: &[u8] = b"PFS";
const KW_SVS: &[u8] = b"svs";
const KW_SYNC: &[u8] = b"SYNC";

#[derive(Debug, PartialEq, Eq)]
pub enum DvPfxSyncError {
    InterestDecode,
    /// ndn-dv Pfx Sync always carries a Data packet in AppParam
    /// (matches `DvSync`'s pattern).
    MissingAppParam,
    DataDecode,
    Svs(SvsLocalError),
}

impl From<SvsLocalError> for DvPfxSyncError {
    fn from(err: SvsLocalError) -> Self {
        DvPfxSyncError::Svs(err)
    }
}

impl std::fmt::Display for DvPfxSyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DvPfxSyncError::InterestDecode => write!(f, "Pfx Sync Interest decode failed"),
            DvPfxSyncError::MissingAppParam => {
                write!(
                    f,
                    "Pfx Sync Interest missing AppParam (Data-in-AppParam required)"
                )
            }
            DvPfxSyncError::DataDecode => {
                write!(f, "Pfx Sync Interest AppParam is not a valid Data")
            }
            DvPfxSyncError::Svs(e) => write!(f, "Pfx Sync state-vector codec: {e}"),
        }
    }
}

impl std::error::Error for DvPfxSyncError {}

/// Owns an [`SvsLocal`] in canonical mode (multi-peer state vector)
/// and provides name builders. Pure state + codec; no I/O.
pub struct DvPfxSync {
    network: Name,
    router: Name,
    svs: SvsLocal,
    trust: crate::protocols::dv::signing::DvTrustHandle,
}

impl DvPfxSync {
    /// Uses [`crate::protocols::dv::signing::InsecureTrust`]; call
    /// [`with_trust`] for key-based signing or LVS validation.
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
            trust,
        }
    }

    /// Pluggable trust policy.
    pub fn trust(&self) -> &crate::protocols::dv::signing::DvTrustHandle {
        &self.trust
    }

    /// This router's name.
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

    /// Call when the local prefix table changes (via
    /// `PrefixTable::announce_local` / `withdraw_local`).
    pub fn advance_seq(&self) -> u64 {
        self.svs.advance_seq()
    }

    pub fn neighbor_seq(&self, name: &Name) -> Option<(u64, u64)> {
        self.svs.neighbor(name).map(|s| (s.boot, s.seq))
    }

    /// `/<network>/32=DV/32=PFS/32=svs` — canonical-SVS Sync Interest
    /// target; FIB routing fans Interests out network-wide.
    pub fn sync_group_prefix(&self) -> Name {
        let mut name = self.network.clone();
        name = name
            .append_component(NameComponent::keyword(Bytes::from_static(KW_DV)))
            .append_component(NameComponent::keyword(Bytes::from_static(KW_PFS)))
            .append_component(NameComponent::keyword(Bytes::from_static(KW_SVS)));
        name
    }

    /// `/<network>/32=DV/32=PFS/<router>` — FIB-registration prefix
    /// for our Prefix Data; peer fetches of any
    /// `t=<boot>/seq=<seq>/v=0` variant arrive at our producer.
    pub fn prefix_data_prefix(&self) -> Name {
        Self::peer_prefix_data_prefix(&self.network, &self.router)
    }

    pub fn peer_prefix_data_prefix(network: &Name, peer: &Name) -> Name {
        let mut name = network.clone();
        name = name
            .append_component(NameComponent::keyword(Bytes::from_static(KW_DV)))
            .append_component(NameComponent::keyword(Bytes::from_static(KW_PFS)));
        for c in peer.components() {
            name = name.append_component(c.clone());
        }
        name
    }

    /// `/<network>/32=DV/32=PFS/<router>/t=<boot>/seq=<seq>/v=0`.
    pub fn prefix_data_name(&self, boot: u64, seq: u64) -> Name {
        Self::peer_prefix_data_name(&self.network, &self.router, boot, seq)
    }

    pub fn peer_prefix_data_name(network: &Name, peer: &Name, boot: u64, seq: u64) -> Name {
        let mut name = Self::peer_prefix_data_prefix(network, peer);
        name = name
            .append_component(NameComponent::timestamp(boot))
            .append_component(NameComponent::sequence_num(seq))
            .append_component(NameComponent::version(0));
        name
    }

    /// `/<network>/32=DV/32=PFS/<router>/32=SYNC` — inner Data name
    /// carried inside an outgoing Pfx Sync Interest's AppParam.
    fn sync_data_name(&self) -> Name {
        let mut name = self.prefix_data_prefix();
        name = name.append_component(NameComponent::keyword(Bytes::from_static(KW_SYNC)));
        name
    }

    /// Carries the full canonical state vector (self + every tracked
    /// neighbour). Caller sends fire-and-forget; SVS expects no Data
    /// reply.
    pub fn build_sync_interest(&self) -> Bytes {
        let sv_bytes = self.svs.encode_full_state_vector();
        let inner_data = crate::protocols::dv::signing::encode_inner_data(
            &self.sync_data_name(),
            &sv_bytes,
            self.trust.as_ref(),
        );

        InterestBuilder::new(self.sync_group_prefix())
            .lifetime(Duration::from_millis(1000))
            // Pfx Sync is network-wide; no HopLimit (Adv Sync's
            // one-hop scope sets HopLimit=2).
            .app_parameters(inner_data.to_vec())
            .build()
    }

    /// Parse an incoming Pfx Sync Interest from raw wire bytes,
    /// update our view of every peer mentioned in the state vector,
    /// and return the peers whose `(boot, seq)` advanced.
    pub fn process_sync_interest(
        &self,
        interest_bytes: &Bytes,
    ) -> Result<Vec<NeighborAdvance>, DvPfxSyncError> {
        let interest =
            Interest::decode(interest_bytes.clone()).map_err(|_| DvPfxSyncError::InterestDecode)?;
        let app_param = interest
            .app_parameters()
            .cloned()
            .ok_or(DvPfxSyncError::MissingAppParam)?;
        self.process_sync_app_param(&app_param)
    }

    /// Like [`process_sync_interest`] but takes AppParam bytes
    /// directly — useful when the caller already holds the parsed
    /// Interest.
    pub fn process_sync_app_param(
        &self,
        app_param: &Bytes,
    ) -> Result<Vec<NeighborAdvance>, DvPfxSyncError> {
        let data = Data::decode(app_param.clone()).map_err(|_| DvPfxSyncError::DataDecode)?;
        let content = data.content().cloned().unwrap_or_default();
        let entries = decode_svs_data(&content)?;
        let mut advances = Vec::new();
        for entry in &entries {
            if let Some(adv) = self.svs.apply_entry(entry) {
                advances.push(adv);
            }
        }
        Ok(advances)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_packet::tlv_type;
    use std::str::FromStr;

    fn name(s: &str) -> Name {
        Name::from_str(s).expect("valid name")
    }

    fn fresh(router: &str, boot: u64) -> DvPfxSync {
        DvPfxSync::new(name("/ndn"), name(router), boot)
    }

    #[test]
    fn sync_group_prefix_matches_spec() {
        let pfx = fresh("/r1", 100);
        let p = pfx.sync_group_prefix();
        // /ndn/32=DV/32=PFS/32=svs
        assert_eq!(p.len(), 4);
        assert_eq!(p.components()[0].value.as_ref(), b"ndn");
        assert_eq!(p.components()[1].value.as_ref(), b"DV");
        assert_eq!(p.components()[2].value.as_ref(), b"PFS");
        assert_eq!(p.components()[3].value.as_ref(), b"svs");
        for &i in &[1, 2, 3] {
            assert_eq!(
                p.components()[i].typ,
                0x20,
                "components 1-3 must be keyword type 0x20",
            );
        }
    }

    #[test]
    fn prefix_data_prefix_matches_spec() {
        let pfx = fresh("/r1", 100);
        let p = pfx.prefix_data_prefix();
        // /ndn/32=DV/32=PFS/r1
        assert_eq!(p.len(), 4);
        assert_eq!(p.components()[0].value.as_ref(), b"ndn");
        assert_eq!(p.components()[1].value.as_ref(), b"DV");
        assert_eq!(p.components()[2].value.as_ref(), b"PFS");
        assert_eq!(p.components()[3].value.as_ref(), b"r1");
        assert_eq!(p.components()[3].typ, tlv_type::NAME_COMPONENT);
    }

    #[test]
    fn prefix_data_name_matches_spec() {
        let pfx = fresh("/r1", 100);
        let n = pfx.prefix_data_name(12345, 7);
        // /ndn/32=DV/32=PFS/r1/t=12345/seq=7/v=0
        assert_eq!(n.len(), 7);
        let comps = n.components();
        assert_eq!(comps[3].value.as_ref(), b"r1");
        // Timestamp = type 0x38, Sequence = type 0x3A, Version = type 0x36.
        assert_eq!(comps[4].typ, 0x38);
        assert_eq!(comps[5].typ, 0x3A);
        assert_eq!(comps[6].typ, 0x36);
        // Version component value is 0.
        let v = &comps[6].value;
        assert!(v.iter().all(|&b| b == 0), "version=0 expected, got {v:?}");
    }

    #[test]
    fn peer_prefix_data_name_uses_supplied_peer() {
        let n = DvPfxSync::peer_prefix_data_name(&name("/ndn"), &name("/other"), 1, 2);
        assert_eq!(n.components()[3].value.as_ref(), b"other");
    }

    #[test]
    fn build_sync_interest_is_valid_with_no_hop_limit() {
        let pfx = fresh("/r1", 100);
        pfx.advance_seq();
        let wire = pfx.build_sync_interest();
        let interest = Interest::decode(wire).expect("valid Interest");
        // Sync group prefix + ParametersSha256DigestComponent appended.
        let comps = interest.name.components();
        assert_eq!(comps.len(), 5);
        assert_eq!(comps[3].value.as_ref(), b"svs");
        // Pfx Sync has no HopLimit (network-wide propagation).
        assert_eq!(interest.hop_limit(), None);
        assert!(interest.app_parameters().is_some());
    }

    #[test]
    fn build_sync_interest_carries_full_state_vector() {
        // Self + two known peers should all appear in the state
        // vector inside the AppParam Data.
        let pfx = fresh("/r1", 100);
        pfx.advance_seq();
        // Make /r1 learn two peers by processing inbound state vectors.
        let peer_a = fresh("/peer-a", 200);
        peer_a.advance_seq();
        let _ = pfx
            .process_sync_interest(&peer_a.build_sync_interest())
            .unwrap();
        let peer_b = fresh("/peer-b", 300);
        peer_b.advance_seq();
        peer_b.advance_seq();
        let _ = pfx
            .process_sync_interest(&peer_b.build_sync_interest())
            .unwrap();

        let wire = pfx.build_sync_interest();
        let interest = Interest::decode(wire).unwrap();
        let app_param = interest.app_parameters().unwrap().clone();
        let data = Data::decode(app_param).unwrap();
        let content = data.content().cloned().unwrap_or_default();
        let entries = decode_svs_data(&content).unwrap();
        // Self + 2 peers = 3 entries.
        assert_eq!(entries.len(), 3);
        let names: Vec<&Name> = entries.iter().map(|e| &e.name).collect();
        assert!(names.iter().any(|n| **n == name("/r1")));
        assert!(names.iter().any(|n| **n == name("/peer-a")));
        assert!(names.iter().any(|n| **n == name("/peer-b")));
    }

    #[test]
    fn two_routers_converge_on_each_other_seq() {
        let r1 = fresh("/r1", 100);
        let r2 = fresh("/r2", 200);
        r1.advance_seq();
        let advances = r2.process_sync_interest(&r1.build_sync_interest()).unwrap();
        assert_eq!(advances.len(), 1);
        assert_eq!(advances[0].name, name("/r1"));
        assert_eq!(advances[0].boot, 100);
        assert_eq!(advances[0].seq, 1);
        assert_eq!(r2.neighbor_seq(&name("/r1")), Some((100, 1)));
    }

    #[test]
    fn duplicate_state_vector_does_not_re_advance() {
        let r1 = fresh("/r1", 100);
        let r2 = fresh("/r2", 200);
        r1.advance_seq();
        let wire = r1.build_sync_interest();
        let first = r2.process_sync_interest(&wire).unwrap();
        let second = r2.process_sync_interest(&wire).unwrap();
        assert_eq!(first.len(), 1);
        assert!(second.is_empty(), "same (boot, seq) must not re-advance");
    }

    #[test]
    fn rejects_interest_without_app_param() {
        let pfx = fresh("/r2", 200);
        let interest_wire = InterestBuilder::new(name("/ndn/x")).build();
        let err = pfx.process_sync_interest(&interest_wire).unwrap_err();
        assert_eq!(err, DvPfxSyncError::MissingAppParam);
    }

    #[test]
    fn rejects_malformed_app_param() {
        let pfx = fresh("/r2", 200);
        let interest_wire = InterestBuilder::new(name("/ndn/x"))
            .app_parameters(vec![0x00, 0x01, 0x02])
            .build();
        let err = pfx.process_sync_interest(&interest_wire).unwrap_err();
        assert_eq!(err, DvPfxSyncError::DataDecode);
    }
}
