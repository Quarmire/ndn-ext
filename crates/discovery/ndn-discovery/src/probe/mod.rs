//! Per-neighbor liveness probe via Interest exchange.
//!
//! Wire: `/ndn/local/nd/probe/ping/<neighbor_name>/<nonce>` Interest;
//! Data at the same name with `DigestSha256` and `FreshnessPeriod=0`.
//! Three consecutive misses move the neighbor to `Stale`.
//!
//! The single claimed prefix covers both incoming probes addressed to
//! this node and replies for outgoing probes, so it composes cleanly
//! under [`CompositeDiscovery`](crate::CompositeDiscovery).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use bytes::Bytes;
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_packet::{Name, NameComponent};
use ndn_transport::FaceId;
use tracing::{debug, info};

use crate::context::DiscoveryContext;
use crate::neighbor::{NeighborState, NeighborUpdate};
use crate::protocol::{DiscoveryProtocol, InboundMeta, ProtocolId};
use crate::scope::probe_ping;
use crate::wire::{parse_raw_data, parse_raw_interest};

const PROTOCOL: ProtocolId = ProtocolId("neighbor-probe");

const PROBE_LIFETIME: Duration = Duration::from_secs(4);
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

struct ProbeEntry {
    last_probe: Instant,
    pending_nonce: Option<(u32, Instant)>,
    miss_count: u8,
}

struct State {
    nonce_counter: u32,
    entries: HashMap<Name, ProbeEntry>,
}

impl State {
    fn next_nonce(&mut self) -> u32 {
        self.nonce_counter = self.nonce_counter.wrapping_add(1);
        self.nonce_counter
    }
}

pub struct NeighborProbeProtocol {
    local_name: Name,
    claimed: Vec<Name>,
    probe_interval: Duration,
    miss_limit: u8,
    state: Mutex<State>,
}

impl NeighborProbeProtocol {
    pub fn new(local_name: Name, probe_interval: Duration, miss_limit: u8) -> Self {
        let claimed = vec![probe_ping().clone()];
        Self {
            local_name,
            claimed,
            probe_interval,
            miss_limit,
            state: Mutex::new(State {
                nonce_counter: rand_seed(),
                entries: HashMap::new(),
            }),
        }
    }

    fn send_probe(&self, neighbor: &Name, face_id: FaceId, ctx: &dyn DiscoveryContext) -> u32 {
        let nonce = self.state.lock().unwrap().next_nonce();
        let interest = build_probe_interest(neighbor, nonce);
        ctx.send_on(face_id, interest);
        nonce
    }

    fn handle_probe_interest(
        &self,
        name: &Name,
        incoming_face: FaceId,
        ctx: &dyn DiscoveryContext,
    ) {
        // Expected: probe_ping() / local_name / nonce.
        let ping_depth = probe_ping().len();
        let local_depth = self.local_name.len();
        let expected_depth = ping_depth + local_depth + 1;

        if name.len() != expected_depth {
            return;
        }
        let name_slice = &name.components()[ping_depth..ping_depth + local_depth];
        if name_slice != self.local_name.components() {
            return;
        }
        let data = DataBuilder::new(name.clone(), &[])
            .freshness(Duration::ZERO)
            .sign_digest_sha256();
        ctx.send_on(incoming_face, data);
        debug!(?incoming_face, "neighbor-probe: replied to probe from face");
    }

    fn handle_probe_data(&self, name: &Name, ctx: &dyn DiscoveryContext) {
        let ping_depth = probe_ping().len();
        if name.len() <= ping_depth + 1 {
            return;
        }
        let nonce_comp = &name.components()[name.len() - 1];
        if nonce_comp.value.len() != 4 {
            return;
        }
        let nonce = u32::from_be_bytes(nonce_comp.value[..4].try_into().unwrap());

        let neighbor_comps = &name.components()[ping_depth..name.len() - 1];
        let neighbor = Name::from_components(neighbor_comps.iter().cloned());

        let mut st = self.state.lock().unwrap();
        let entry = match st.entries.get_mut(&neighbor) {
            Some(e) => e,
            None => return,
        };
        match entry.pending_nonce {
            Some((pending, _)) if pending == nonce => {
                entry.pending_nonce = None;
                entry.miss_count = 0;
                drop(st);
                ctx.update_neighbor(NeighborUpdate::SetState {
                    name: neighbor.clone(),
                    state: NeighborState::Established {
                        last_seen: Instant::now(),
                    },
                });
                debug!(peer = %neighbor, "neighbor-probe: Active");
            }
            _ => {}
        }
    }
}

impl DiscoveryProtocol for NeighborProbeProtocol {
    fn protocol_id(&self) -> ProtocolId {
        PROTOCOL
    }

    fn claimed_prefixes(&self) -> &[Name] {
        &self.claimed
    }

    fn on_face_up(&self, _face_id: FaceId, _ctx: &dyn DiscoveryContext) {}

    fn on_face_down(&self, face_id: FaceId, ctx: &dyn DiscoveryContext) {
        let neighbors: Vec<_> = ctx.neighbors().all();
        for entry in neighbors {
            if entry.faces.iter().any(|(fid, _, _)| *fid == face_id) {
                ctx.update_neighbor(NeighborUpdate::SetState {
                    name: entry.node_name.clone(),
                    state: NeighborState::Stale {
                        miss_count: 1,
                        last_seen: Instant::now(),
                    },
                });
            }
        }
    }

    fn on_inbound(
        &self,
        raw: &Bytes,
        incoming_face: FaceId,
        _meta: &InboundMeta,
        ctx: &dyn DiscoveryContext,
    ) -> bool {
        match raw.first() {
            Some(&0x05) => {
                let parsed = match parse_raw_interest(raw) {
                    Some(p) => p,
                    None => return false,
                };
                if !parsed.name.has_prefix(probe_ping()) {
                    return false;
                }
                self.handle_probe_interest(&parsed.name, incoming_face, ctx);
                true
            }
            Some(&0x06) => {
                let parsed = match parse_raw_data(raw) {
                    Some(d) => d,
                    None => return false,
                };
                if !parsed.name.has_prefix(probe_ping()) {
                    return false;
                }
                self.handle_probe_data(&parsed.name, ctx);
                true
            }
            _ => false,
        }
    }

    fn on_tick(&self, now: Instant, ctx: &dyn DiscoveryContext) {
        let all_neighbors = ctx.neighbors().all();

        for entry in &all_neighbors {
            let face_id = match entry.faces.first().map(|(f, _, _)| *f) {
                Some(f) => f,
                None => continue,
            };

            let mut st = self.state.lock().unwrap();
            let probe_entry = st
                .entries
                .entry(entry.node_name.clone())
                .or_insert_with(|| ProbeEntry {
                    last_probe: now - self.probe_interval,
                    pending_nonce: None,
                    miss_count: 0,
                });

            let probe_timed_out = probe_entry
                .pending_nonce
                .is_some_and(|(_, sent)| now.duration_since(sent) >= PROBE_TIMEOUT);
            if probe_timed_out {
                probe_entry.pending_nonce = None;
                probe_entry.miss_count = probe_entry.miss_count.saturating_add(1);
                let miss = probe_entry.miss_count;
                let miss_limit = self.miss_limit;
                drop(st);

                if miss >= miss_limit {
                    info!(peer = %entry.node_name, miss_count = miss,
                        "neighbor-probe: peer unreachable, marking Stale");
                    ctx.update_neighbor(NeighborUpdate::SetState {
                        name: entry.node_name.clone(),
                        state: NeighborState::Stale {
                            miss_count: miss,
                            last_seen: now,
                        },
                    });
                }
                continue;
            }

            let should_probe = probe_entry.pending_nonce.is_none()
                && now.duration_since(probe_entry.last_probe) >= self.probe_interval;

            if should_probe {
                probe_entry.last_probe = now;
                drop(st);

                let nonce = self.send_probe(&entry.node_name, face_id, ctx);
                if let Some(e) = self.state.lock().unwrap().entries.get_mut(&entry.node_name) {
                    e.pending_nonce = Some((nonce, now));
                }

                debug!(peer = %entry.node_name, nonce, "neighbor-probe: sent probe");
            }
        }
    }

    fn tick_interval(&self) -> Duration {
        Duration::from_millis(500)
    }
}

/// `/ndn/local/nd/probe/ping/<name>`.
pub fn probe_name_prefix(name: &Name) -> Name {
    Name::from_components(
        probe_ping()
            .components()
            .iter()
            .cloned()
            .chain(name.components().iter().cloned()),
    )
}

/// Name: `/ndn/local/nd/probe/ping/<neighbor>/<nonce_be_u32>`.
pub fn build_probe_interest(neighbor: &Name, nonce: u32) -> Bytes {
    let nonce_comp = NameComponent::generic(Bytes::copy_from_slice(&nonce.to_be_bytes()));
    let name = Name::from_components(
        probe_ping()
            .components()
            .iter()
            .cloned()
            .chain(neighbor.components().iter().cloned())
            .chain(std::iter::once(nonce_comp)),
    );
    InterestBuilder::new(name).lifetime(PROBE_LIFETIME).build()
}

fn rand_seed() -> u32 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .hash(&mut h);
    h.finish() as u32
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::sync::Arc;

    use super::*;
    use crate::context::NeighborTableView;
    use crate::neighbor::{NeighborEntry, NeighborTable};
    use crate::{MacAddr, ProtocolId};

    fn name(s: &str) -> Name {
        Name::from_str(s).unwrap()
    }

    struct TrackCtx {
        table: Arc<NeighborTable>,
        sent: Mutex<Vec<(FaceId, Bytes)>>,
    }

    impl TrackCtx {
        fn new() -> Self {
            Self {
                table: NeighborTable::new(),
                sent: Mutex::new(Vec::new()),
            }
        }
    }

    impl ndn_discovery_core::FaceLifecycleContext for TrackCtx {
        fn alloc_face_id(&self) -> FaceId {
            FaceId(0)
        }
        fn add_face(&self, _: Arc<ndn_transport::Face>) -> FaceId {
            FaceId(0)
        }
        fn remove_face(&self, _: FaceId) {}
    }
    impl ndn_discovery_core::RoutingTableContext for TrackCtx {
        fn add_fib_entry(&self, _: &Name, _: FaceId, _: u32, _: ProtocolId) {}
        fn remove_fib_entry(&self, _: &Name, _: FaceId, _: ProtocolId) {}
        fn remove_fib_entries_by_owner(&self, _: ProtocolId) {}
    }
    impl ndn_discovery_core::NeighborContext for TrackCtx {
        fn neighbors(&self) -> Arc<dyn NeighborTableView> {
            self.table.clone()
        }
        fn update_neighbor(&self, update: NeighborUpdate) {
            self.table.apply(update);
        }
    }
    impl DiscoveryContext for TrackCtx {
        fn send_on(&self, face_id: FaceId, pkt: Bytes) {
            self.sent.lock().unwrap().push((face_id, pkt));
        }
        fn now(&self) -> Instant {
            Instant::now()
        }
    }

    #[test]
    fn probe_interest_has_correct_prefix() {
        let neighbor = name("/ndn/test/B");
        let pkt = build_probe_interest(&neighbor, 0xDEAD_BEEF);
        let parsed = parse_raw_interest(&pkt).expect("parse interest");
        assert!(parsed.name.has_prefix(probe_ping()));
        let last_comp = parsed.name.components().last().unwrap();
        assert_eq!(
            last_comp.value.as_ref(),
            0xDEAD_BEEFu32.to_be_bytes().as_ref()
        );
    }

    #[test]
    fn probe_protocol_replies_to_incoming_probe_interest() {
        let local = name("/ndn/test/A");
        let neighbor = name("/ndn/test/B");
        let probe = NeighborProbeProtocol::new(local.clone(), Duration::from_secs(10), 3);
        let ctx = TrackCtx::new();

        // Build an Interest addressed to node A.
        let nonce = 0xCAFE_BABEu32;
        let interest = build_probe_interest(&local, nonce);

        let consumed = probe.on_inbound(&interest, FaceId(42), &InboundMeta::none(), &ctx);
        assert!(consumed);

        let sent = ctx.sent.lock().unwrap();
        assert_eq!(sent.len(), 1, "should have sent one probe reply Data");
        let (face, pkt) = &sent[0];
        assert_eq!(*face, FaceId(42));
        let data = parse_raw_data(pkt).expect("reply should be parseable Data");
        assert!(
            data.name.has_prefix(probe_ping()),
            "reply name under probe/ping"
        );
        drop(sent);
        let _ = neighbor;
    }

    #[test]
    fn probe_protocol_sends_probe_on_tick() {
        let local = name("/ndn/test/A");
        let neighbor = name("/ndn/test/B");
        let probe = NeighborProbeProtocol::new(local.clone(), Duration::from_millis(1), 3);
        let ctx = TrackCtx::new();

        let mac = MacAddr::new([0u8; 6]);
        ctx.table.apply(NeighborUpdate::Upsert(NeighborEntry {
            node_name: neighbor.clone(),
            state: NeighborState::Established {
                last_seen: Instant::now(),
            },
            faces: vec![(FaceId(7), mac, "lo".into())],
            rtt_us: None,
            pending_nonce: None,
        }));

        std::thread::sleep(Duration::from_millis(5));
        probe.on_tick(Instant::now(), &ctx);

        let sent = ctx.sent.lock().unwrap();
        assert_eq!(sent.len(), 1, "should send probe Interest on tick");
        let (face, pkt) = &sent[0];
        assert_eq!(*face, FaceId(7));
        let interest = parse_raw_interest(pkt).expect("should be parseable Interest");
        assert!(interest.name.has_prefix(probe_ping()));
    }
}
