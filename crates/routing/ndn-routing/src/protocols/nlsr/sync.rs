//! PSync adapter for LSA flooding.
//!
//! Maps NLSR's three LSA namespaces (NAME, ADJACENCY, COORDINATE) onto
//! a generic sync protocol. User prefixes follow:
//!
//! ```text
//! <lsa_prefix>/<router_components…>/<LSA_TYPE>/<seq_no>
//! ```
//!
//! `NlsrSync` subscribes to LSDB events and:
//! - on own-LSA install/update, publishes user prefix + seq_no to PSync
//!   with the wire-encoded LSA as mapping bytes;
//! - on PSync `SyncUpdate` carrying mapping bytes, decodes and installs
//!   (`Stale`/`Duplicate` silently dropped, `Invalid` counter-bumped).
//!
//! C++ ref: `NLSR/src/communication/sync-{logic-handler,protocol-adapter}.{hpp,cpp}`.

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use ndn_engine::observability::targets as t;
use ndn_packet::Name;
use ndn_sync::SyncHandle;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::protocols::nlsr::lsa::LsaType;
use crate::protocols::nlsr::lsdb::{InstallResult, Lsdb, LsdbUpdate};

pub struct SeqUpdate {
    pub origin_router: Name,
    pub lsa_type: LsaType,
    pub seq_no: u64,
    /// Face the sync update arrived on (for localhop scoping).
    pub incoming_face_id: Option<u64>,
}

pub struct NlsrSync {
    own_router: Name,
    /// C++ NLSR excludes the network component from the IBLT user
    /// prefix but includes it in origin router names stored in the
    /// LSDB (`ConfParameter::getNetwork()`, NLSR/src/conf-parameter.hpp:115).
    network: Name,
    lsa_prefix: Name,
    lsdb: Arc<Lsdb>,
    route_notify: Arc<tokio::sync::Notify>,
    /// Receives `(origin_router, lsa_type, seq_no)` when a PSync
    /// update arrives without inline mapping bytes (C++ NLSR path).
    lsa_fetch_tx: mpsc::Sender<(Name, LsaType, u64)>,
    pub invalid_counter: Arc<AtomicU64>,
}

impl NlsrSync {
    /// Returns the sync object and an `Arc<Notify>` that fires after
    /// each LSDB adjacency or name LSA change — callers await it to
    /// trigger Dijkstra recomputation.
    pub fn new(
        own_router: Name,
        network: Name,
        lsa_prefix: Name,
        lsdb: Arc<Lsdb>,
        lsa_fetch_tx: mpsc::Sender<(Name, LsaType, u64)>,
    ) -> (Self, Arc<tokio::sync::Notify>) {
        let notify = Arc::new(tokio::sync::Notify::new());
        let counter = Arc::new(AtomicU64::new(0));
        (
            Self {
                own_router,
                network,
                lsa_prefix,
                lsdb,
                route_notify: notify.clone(),
                lsa_fetch_tx,
                invalid_counter: counter,
            },
            notify,
        )
    }

    /// `<lsa_prefix>/<router_suffix>/<LSA_TYPE>` where `router_suffix`
    /// is `own_router` with leading network components stripped — C++
    /// NLSR stores only `siteName + routerName` in the IBLT
    /// (`makeLsaUserPrefix`, NLSR/src/communication/sync-logic-handler.hpp:47).
    pub fn user_prefix_for(&self, lsa_type: LsaType) -> Name {
        let type_str: &[u8] = match lsa_type {
            LsaType::Adjacency => b"ADJACENCY",
            LsaType::Name => b"NAME",
            LsaType::Coordinate => b"COORDINATE",
        };
        let network_len = self.network.components().len();
        let mut name = self.lsa_prefix.clone();
        for comp in self.own_router.components().iter().skip(network_len) {
            name = name.append_component(comp.clone());
        }
        name.append(type_str)
    }

    /// Parses `<lsa_prefix>/<router_components…>/<LSA_TYPE>/<seq_no>`.
    /// C++: `SyncLogicHandler::processUpdate`
    /// (NLSR/src/communication/sync-logic-handler.cpp:55).
    pub fn parse_update_name(&self, update_name: &Name) -> Option<(Name, LsaType, u64)> {
        let comps = update_name.components();
        let prefix_len = self.lsa_prefix.components().len();

        if comps.len() < prefix_len + 3 {
            return None;
        }

        for (a, b) in comps[..prefix_len].iter().zip(self.lsa_prefix.components()) {
            if a != b {
                return None;
            }
        }

        let seq_comp = comps.last()?;
        let seq_no = seq_comp
            .as_sequence_num()
            .or_else(|| parse_u64_component(&seq_comp.value))?;

        let type_comp = &comps[comps.len() - 2];
        let lsa_type = match type_comp.value.as_ref() {
            b"NAME" => LsaType::Name,
            b"ADJACENCY" => LsaType::Adjacency,
            b"COORDINATE" => LsaType::Coordinate,
            _ => return None,
        };

        // Prepend `network` to reconstruct the full origin router
        // name stored in the LSDB (C++ NLSR/src/lsdb.cpp:241).
        let router_comps = &comps[prefix_len..comps.len() - 2];
        if router_comps.is_empty() {
            return None;
        }
        let origin_router = Name::from_components(
            self.network
                .components()
                .iter()
                .chain(router_comps.iter())
                .cloned(),
        );

        Some((origin_router, lsa_type, seq_no))
    }

    /// Background task: own-LSA installs/updates publish user-prefix + seq_no
    /// to PSync with the wire-encoded LSA as mapping bytes; inbound PSync
    /// updates with mapping bytes install into LSDB; any AdjLSA / NameLSA
    /// change fires `route_notify`.
    pub async fn run(self: Arc<Self>, mut sync_handle: SyncHandle, cancel: CancellationToken) {
        let mut events = self.lsdb.event_stream();

        // Bootstrap: publish own LSAs that pre-existed before this task
        // subscribed (e.g. `lsdb.build_own_name_lsa()` runs at NLSR
        // startup), or peers never see our state and reconciliation
        // gets stuck at `we_have=0, they_have=0`.
        let snap = self.lsdb.snapshot();
        for lsa in snap
            .adjacency
            .iter()
            .chain(snap.name.iter())
            .chain(snap.coordinate.iter())
        {
            if lsa.origin_router() == &self.own_router {
                let seq_bytes = encode_nni_minimal(lsa.seq_no());
                let user_prefix = self
                    .user_prefix_for(lsa.lsa_type())
                    .append_component(ndn_packet::NameComponent::generic(seq_bytes));
                let lsa_bytes = lsa.wire_encode();
                let _ = sync_handle
                    .publish_with_mapping(user_prefix, lsa_bytes)
                    .await;
            }
        }

        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,

                Ok(event) = events.recv() => {
                    if event.lsa.origin_router() == &self.own_router
                        && matches!(event.update, LsdbUpdate::Installed | LsdbUpdate::Updated)
                    {
                        // Seq must be a GenericNameComponent (0x08)
                        // with minimal NNI encoding (matches C++
                        // NLSR `appendNumber()`,
                        // NLSR/src/communication/sync-logic-handler.cpp:49).
                        // `append_sequence_num()` (0x3A) would produce
                        // a different IBLT hash and break reconciliation.
                        let seq_bytes = encode_nni_minimal(event.lsa.seq_no());
                        let user_prefix = self
                            .user_prefix_for(event.lsa.lsa_type())
                            .append_component(ndn_packet::NameComponent::generic(seq_bytes));
                        let lsa_bytes = event.lsa.wire_encode();
                        let _ = sync_handle.publish_with_mapping(user_prefix, lsa_bytes).await;
                    }

                    if matches!(event.lsa.lsa_type(), LsaType::Adjacency | LsaType::Name) {
                        self.route_notify.notify_one();
                    }
                }

                Some(update) = sync_handle.recv() => {
                    if let Some(lsa_bytes) = update.mapping {
                        // Inline mapping bytes (in-process peers).
                        if let Some((_, lsa_type, _)) = self.parse_update_name(&update.name) {
                            match crate::protocols::nlsr::lsa::Lsa::wire_decode(lsa_type, lsa_bytes) {
                                Ok(lsa) => {
                                    match self.lsdb.install(lsa) {
                                        InstallResult::Newer => {}
                                        InstallResult::Stale | InstallResult::Duplicate => {}
                                        InstallResult::Invalid => {
                                            warn!(target: t::ROUTING_NLSR, "NlsrSync: received invalid LSA from sync");
                                            self.invalid_counter.fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!(target: t::ROUTING_NLSR, "NlsrSync: failed to decode LSA: {e}");
                                }
                            }
                        }
                    } else {
                        // C++ NLSR path: no inline bytes — fetch the
                        // LSA via Interest/Data (NLSR/src/lsdb.cpp:137,
                        // `processUpdateFromSync` →
                        // `expressInterest(lsaInterest.appendNumber(seqNo))`).
                        match self.parse_update_name(&update.name) {
                            None => {
                                warn!(
                                    target: t::ROUTING_NLSR,
                                    name = %update.name,
                                    "NlsrSync: malformed sync update name, skipping"
                                );
                            }
                            Some((origin_router, lsa_type, seq_no)) => {
                                if origin_router == self.own_router {
                                    // Avoid self-fetch.
                                } else {
                                    tracing::trace!(
                                        target: t::ROUTING_NLSR,
                                        %origin_router, ?lsa_type, seq_no,
                                        "PSync update without mapping — queuing LSA fetch"
                                    );
                                    let _ = self.lsa_fetch_tx
                                        .send((origin_router, lsa_type, seq_no))
                                        .await;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Matches C++ `appendNumber()` output
/// (NLSR/src/communication/sync-logic-handler.cpp:49).
fn encode_nni_minimal(n: u64) -> bytes::Bytes {
    let b = n.to_be_bytes();
    bytes::Bytes::copy_from_slice(match n {
        0..=0xFF => &b[7..],
        0x100..=0xFFFF => &b[6..],
        0x10000..=0xFFFF_FFFF => &b[4..],
        _ => &b,
    })
}

fn parse_u64_component(value: &[u8]) -> Option<u64> {
    match value.len() {
        1 => Some(value[0] as u64),
        2 => Some(u16::from_be_bytes([value[0], value[1]]) as u64),
        4 => Some(u32::from_be_bytes([value[0], value[1], value[2], value[3]]) as u64),
        8 => Some(u64::from_be_bytes(value.try_into().ok()?)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use ndn_packet::Name;

    use super::*;
    use crate::protocols::nlsr::lsa::{
        Lsa, LsaType,
        name::{NameLsa, PrefixInfo},
    };
    use crate::protocols::nlsr::lsdb::{InstallResult, Lsdb};

    fn name(s: &str) -> Name {
        s.parse().unwrap()
    }

    fn future_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
            + 300_000
    }

    fn make_sync(own_router: &str, network: &str) -> NlsrSync {
        let (tx, _rx) = mpsc::channel(1);
        let lsdb = Arc::new(Lsdb::new(name(own_router)));
        let (sync, _) = NlsrSync::new(
            name(own_router),
            name(network),
            name("/ndn/nlsr/LSA"),
            lsdb,
            tx,
        );
        sync
    }

    #[test]
    fn user_prefix_for_name_lsa() {
        // network=/ndn (1 component) — router suffix = /site/routerA (skip /ndn)
        let sync = make_sync("/ndn/site/routerA", "/ndn");
        let prefix = sync.user_prefix_for(LsaType::Name);
        assert_eq!(prefix.to_string(), "/ndn/nlsr/LSA/site/routerA/NAME");
    }

    #[test]
    fn user_prefix_for_adjacency_lsa() {
        let sync = make_sync("/ndn/site/routerA", "/ndn");
        let prefix = sync.user_prefix_for(LsaType::Adjacency);
        assert_eq!(prefix.to_string(), "/ndn/nlsr/LSA/site/routerA/ADJACENCY");
    }

    #[test]
    fn parse_update_name_roundtrip() {
        let sync = make_sync("/ndn/site/routerA", "/ndn");

        // PSync update name from routerB: lsa_prefix/routerB_suffix/NAME/seq=5
        // routerB suffix = /site/routerB (without network /ndn)
        let update_name = name("/ndn/nlsr/LSA/site/routerB/NAME").append_sequence_num(5);

        let (origin, lsa_type, seq_no) = sync
            .parse_update_name(&update_name)
            .expect("valid update name must parse");

        // origin_router should include the network prefix prepended back.
        assert_eq!(origin.to_string(), "/ndn/site/routerB");
        assert_eq!(lsa_type, LsaType::Name);
        assert_eq!(seq_no, 5);
    }

    /// G.04 sync loop — three-node LSDB convergence.
    ///
    /// Simulates one sync round: each node wire-encodes its own NameLSA and
    /// installs it directly into the other two nodes' LSDBs.  Verifies that
    /// all three LSDBs converge to holding three NameLSAs each.
    ///
    /// In a real deployment the PSync protocol drives this exchange; here we
    /// use direct wire-byte installation to isolate the LSDB logic from the
    /// network layer.  The PSync end-to-end path is tested in phase 6.
    #[test]
    fn sync_loop_three_node_convergence() {
        let router_a = name("/ndn/site/A");
        let router_b = name("/ndn/site/B");
        let router_c = name("/ndn/site/C");

        let lsdb_a = Lsdb::new(router_a.clone());
        let lsdb_b = Lsdb::new(router_b.clone());
        let lsdb_c = Lsdb::new(router_c.clone());

        let exp = future_ms();

        // Each node builds and installs its own NameLSA.
        let lsa_a = Lsa::Name(NameLsa {
            origin_router: router_a.clone(),
            seq_no: 1,
            expiration_ms: exp,
            prefixes: vec![PrefixInfo {
                name: name("/ndn/site/A/prefix"),
                cost: 0.0,
            }],
        });
        let lsa_b = Lsa::Name(NameLsa {
            origin_router: router_b.clone(),
            seq_no: 1,
            expiration_ms: exp,
            prefixes: vec![PrefixInfo {
                name: name("/ndn/site/B/prefix"),
                cost: 0.0,
            }],
        });
        let lsa_c = Lsa::Name(NameLsa {
            origin_router: router_c.clone(),
            seq_no: 1,
            expiration_ms: exp,
            prefixes: vec![PrefixInfo {
                name: name("/ndn/site/C/prefix"),
                cost: 0.0,
            }],
        });

        lsdb_a.install(lsa_a.clone());
        lsdb_b.install(lsa_b.clone());
        lsdb_c.install(lsa_c.clone());

        // Sync round: wire-encode each LSA and install into the other nodes' LSDBs.
        let wire_a = lsa_a.wire_encode();
        let wire_b = lsa_b.wire_encode();
        let wire_c = lsa_c.wire_encode();

        let decode_name = |bytes: bytes::Bytes| {
            Lsa::wire_decode(LsaType::Name, bytes).expect("valid NameLSA wire bytes")
        };

        assert_eq!(
            lsdb_b.install(decode_name(wire_a.clone())),
            InstallResult::Newer
        );
        assert_eq!(lsdb_c.install(decode_name(wire_a)), InstallResult::Newer);
        assert_eq!(
            lsdb_a.install(decode_name(wire_b.clone())),
            InstallResult::Newer
        );
        assert_eq!(lsdb_c.install(decode_name(wire_b)), InstallResult::Newer);
        assert_eq!(
            lsdb_a.install(decode_name(wire_c.clone())),
            InstallResult::Newer
        );
        assert_eq!(lsdb_b.install(decode_name(wire_c)), InstallResult::Newer);

        // After one sync round, all three LSDBs hold all three NameLSAs.
        let count_a = lsdb_a.iter_by_type(LsaType::Name).count();
        let count_b = lsdb_b.iter_by_type(LsaType::Name).count();
        let count_c = lsdb_c.iter_by_type(LsaType::Name).count();
        assert_eq!(count_a, 3, "LSDB_A: expected 3 NameLSAs, got {count_a}");
        assert_eq!(count_b, 3, "LSDB_B: expected 3 NameLSAs, got {count_b}");
        assert_eq!(count_c, 3, "LSDB_C: expected 3 NameLSAs, got {count_c}");
    }
}
