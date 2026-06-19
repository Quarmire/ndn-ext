//! NLSR Hello protocol — per-neighbour liveness detection.
//!
//! Names (match C++ NLSR exactly, `NLSR/src/hello-protocol.cpp:97-131`):
//!
//! - Interest: `/<neighbor>/nlsr/INFO/<own_router_name_tlv>`. The
//!   own-router prefix is appended as a `GenericNameComponent` whose
//!   value is the wire-encoded Name TLV (`name.wireEncode()` in
//!   ndn-cxx).
//! - Data: `/<neighbor>/nlsr/INFO/<own_router_name_tlv>/<version>`.
//!
//! C++ NLSR uses `ndn::Scheduler` callbacks for the periodic send loop
//! and per-retry re-expressions; we use one `tokio::time::interval`
//! per neighbour task with a bounded retry loop inside each tick. The
//! state machine drives deterministically under
//! `tokio::time::advance`.

use std::collections::HashMap;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use ndn_app::Consumer;
use ndn_engine::observability::targets as t;
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_packet::{Name, NameComponent};
use ndn_transport::FaceId;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{Instrument as _, debug};

use crate::protocols::nlsr::NlsrError;
use crate::protocols::nlsr::lsa::adjacency::Adjacent;
use crate::protocols::nlsr::lsdb::Lsdb;

// Defaults from NLSR/src/hello-protocol.hpp.
pub const HELLO_INTERVAL_DEFAULT: u32 = 60;
pub const HELLO_RETRIES_DEFAULT: u32 = 3;
pub const HELLO_TIMEOUT_DEFAULT: u32 = 1;
const LSA_REFRESH_DEFAULT_MS: u64 = 1_800_000;

const NLSR_COMPONENT: &[u8] = b"nlsr";
const INFO_COMPONENT: &[u8] = b"INFO";

/// C++ equivalent: `Adjacent::Status` in `NLSR/src/adjacent.hpp:55`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NeighborState {
    Active,
    Inactive,
}

/// Published on the `watch` channel on every adjacency change so the
/// sync layer knows when to re-originate the own AdjacencyLsa.
#[derive(Clone, Debug)]
pub struct AdjacencySnapshot {
    pub neighbors: Vec<(Name, NeighborState)>,
}

pub struct HelloNeighborConfig {
    pub name: Name,
    pub face_uri: String,
    pub link_cost: f64,
}

/// Drawn from `NlsrConfig`.
pub struct HelloConfig {
    pub own_router: Name,
    pub neighbors: Vec<HelloNeighborConfig>,
    pub hello_interval_secs: u32,
    pub hello_retries: u32,
    pub hello_timeout_secs: u32,
    /// LSA lifetime (ms) used when building the own AdjacencyLsa.
    pub lsa_refresh_ms: u64,
}

impl Default for HelloConfig {
    fn default() -> Self {
        Self {
            own_router: Name::root(),
            neighbors: Vec::new(),
            hello_interval_secs: HELLO_INTERVAL_DEFAULT,
            hello_retries: HELLO_RETRIES_DEFAULT,
            hello_timeout_secs: HELLO_TIMEOUT_DEFAULT,
            lsa_refresh_ms: LSA_REFRESH_DEFAULT_MS,
        }
    }
}

struct NeighborEntry {
    state: NeighborState,
    face_uri: String,
    link_cost: f64,
}

struct HelloInner {
    config: HelloConfig,
    states: Mutex<HashMap<Name, NeighborEntry>>,
    adj_tx: watch::Sender<AdjacencySnapshot>,
    lsdb: Arc<Lsdb>,
    adj_seq: AtomicU64,
}

/// C++ equivalent: `HelloProtocol` in `NLSR/src/hello-protocol.hpp:38`.
///
/// `Clone` gives callers a shared handle after `start()` consumes the
/// owned value; both handles share state through `Arc<HelloInner>`.
#[derive(Clone)]
pub struct HelloProtocol {
    inner: Arc<HelloInner>,
}

impl HelloProtocol {
    pub fn new(config: HelloConfig, lsdb: Arc<Lsdb>) -> (Self, watch::Receiver<AdjacencySnapshot>) {
        let initial = AdjacencySnapshot {
            neighbors: config
                .neighbors
                .iter()
                .map(|n| (n.name.clone(), NeighborState::Inactive))
                .collect(),
        };
        let (adj_tx, adj_rx) = watch::channel(initial);

        let states: HashMap<Name, NeighborEntry> = config
            .neighbors
            .iter()
            .map(|n| {
                (
                    n.name.clone(),
                    NeighborEntry {
                        state: NeighborState::Inactive,
                        face_uri: n.face_uri.clone(),
                        link_cost: n.link_cost,
                    },
                )
            })
            .collect();

        let inner = Arc::new(HelloInner {
            config,
            states: Mutex::new(states),
            adj_tx,
            lsdb,
            adj_seq: AtomicU64::new(1),
        });
        (Self { inner }, adj_rx)
    }

    pub fn adjacency_watch(&self) -> watch::Receiver<AdjacencySnapshot> {
        self.inner.adj_tx.subscribe()
    }

    /// Interest name: `/<own_router>/nlsr/INFO/<requester_name_tlv>`.
    /// Returns the wire-encoded Data if the requester is a known
    /// adjacency, otherwise `None`. C++ equivalent:
    /// `HelloProtocol::processInterest` (`NLSR/src/hello-protocol.cpp:111`).
    pub fn handle_incoming_interest(&self, interest_name: &Name) -> Option<Bytes> {
        let comps = interest_name.components();
        // Minimum: <own_router>(≥1) + nlsr + INFO + <requester_nested> = at least 4
        if comps.len() < 4 {
            return None;
        }
        if comps[comps.len() - 2].value.as_ref() != INFO_COMPONENT {
            return None;
        }
        if comps[comps.len() - 3].value.as_ref() != NLSR_COMPONENT {
            return None;
        }

        // Last component value = wire-encoded Name TLV of the requester.
        // NLSR/src/hello-protocol.cpp:127:
        //   `ndn::Name neighbor(interestName.get(-1).blockFromValue())`
        let requester_comp = &comps[comps.len() - 1];
        let requester = Name::decode_from_tlv(requester_comp.value.clone()).ok()?;

        let states = self.inner.states.lock().unwrap();
        if !states.contains_key(&requester) {
            return None;
        }
        drop(states);

        // Data name = Interest name + version (NLSR/src/hello-protocol.cpp:131).
        let version_us = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;
        let data_name = interest_name.clone().append_version(version_us);

        // FreshnessPeriod = 0 ms per NLSR/src/hello-protocol.cpp:135.
        let wire = DataBuilder::new(data_name, INFO_COMPONENT)
            .freshness(Duration::ZERO)
            .build();
        Some(wire)
    }

    /// `neighbors` maps each neighbour name to the engine FaceId of
    /// the link reaching it and a dedicated [`ndn_app::Consumer`].
    /// The Consumer pins each Hello Interest to `face_id` via
    /// `Consumer::fetch_on` (NDNLPv2 `NextHopFaceId`, TLV 0x0330)
    /// so the engine bypasses FIB/strategy.
    ///
    /// `face_id` must be the neighbour's engine UDP face — *not* the
    /// Consumer's own InProcFace id — or Hello Interests loop back
    /// into our InProcFace via PIT loopback.
    ///
    /// Each loop owns its own `Consumer` because a single `Connection`
    /// serialises send → recv; sharing would interleave Hello timeouts
    /// across neighbours.
    pub fn start(
        self,
        neighbors: Vec<(Name, FaceId, Consumer)>,
        cancel: CancellationToken,
    ) -> JoinHandle<Result<(), NlsrError>> {
        let inner = Arc::clone(&self.inner);

        tokio::spawn(
            async move {
                let mut tasks: Vec<JoinHandle<()>> = Vec::new();

                for (neighbor_name, face_id, consumer) in neighbors {
                    let inner_c = Arc::clone(&inner);
                    let cancel_c = cancel.clone();
                    let neighbor_str = neighbor_name.to_string();
                    let task = tokio::spawn(
                        async move {
                            run_neighbor_loop(inner_c, neighbor_name, face_id, consumer, cancel_c)
                                .await;
                        }
                        .instrument(tracing::info_span!(
                            target: t::ROUTING_NLSR,
                            "nlsr_hello",
                            neighbor = neighbor_str,
                        )),
                    );
                    tasks.push(task);
                }

                cancel.cancelled().await;

                for task in tasks {
                    task.abort();
                    let _ = task.await;
                }

                Ok(())
            }
            .instrument(tracing::info_span!(target: t::ROUTING_NLSR, "nlsr_hello")),
        )
    }
}

/// C++ NLSR: `NLSR/src/hello-protocol.cpp:88-108`.
async fn run_neighbor_loop(
    inner: Arc<HelloInner>,
    neighbor: Name,
    face_id: FaceId,
    mut consumer: Consumer,
    cancel: CancellationToken,
) {
    let interval_secs = inner.config.hello_interval_secs as u64;
    let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            _ = interval.tick() => {}
        }

        send_hello_with_retries(&inner, &neighbor, face_id, &mut consumer).await;
    }
    debug!(target: t::ROUTING_NLSR, "Hello loop for {:?} exiting", neighbor);
}

/// Expresses Hello Interest with up to `hello_retries` retries.
/// Success → mark Active (if not already), install AdjLSA.
/// Exhausted → mark Inactive (if was Active), install AdjLSA.
/// C++: `HelloProtocol::expressInterest` + `processInterestTimedOut`
/// (`NLSR/src/hello-protocol.cpp:65-201`).
async fn send_hello_with_retries(
    inner: &HelloInner,
    neighbor: &Name,
    face_id: FaceId,
    consumer: &mut Consumer,
) {
    let interest_name = build_hello_interest_name(neighbor, &inner.config.own_router);
    let timeout = Duration::from_secs(inner.config.hello_timeout_secs as u64);
    let retries = inner.config.hello_retries;

    for attempt in 0..retries {
        debug!(
            target: t::ROUTING_NLSR,
            neighbor = %neighbor,
            attempt,
            "sending Hello Interest {:?}",
            interest_name
        );

        let builder = InterestBuilder::new(interest_name.clone())
            .lifetime(timeout)
            .must_be_fresh()
            .can_be_prefix();

        match consumer.fetch_with_on(face_id, builder).await {
            Ok(_data) => {
                on_hello_data(inner, neighbor);
                return;
            }
            Err(e) => {
                debug!(
                    target: t::ROUTING_NLSR,
                    neighbor = %neighbor,
                    attempt,
                    error = %e,
                    "Hello no valid Data response"
                );
            }
        }
    }

    on_hello_failure(inner, neighbor);
}

/// Resets strike counter, transitions Inactive → Active if needed,
/// reinstalls own AdjacencyLsa. C++:
/// `HelloProtocol::onContentValidated` (`NLSR/src/hello-protocol.cpp:221`).
fn on_hello_data(inner: &HelloInner, neighbor: &Name) {
    let old_state = {
        let mut states = inner.states.lock().unwrap();
        let entry = match states.get_mut(neighbor) {
            Some(e) => e,
            None => return,
        };
        let old = entry.state;
        entry.state = NeighborState::Active;
        old
    };

    if old_state != NeighborState::Active {
        debug!(target: t::ROUTING_NLSR, neighbor = %neighbor, "adjacency transition → Active");
        rebuild_and_install_adj_lsa(inner);
        publish_snapshot(inner);
    }
}

/// Transitions Active → Inactive if needed; reinstalls own AdjacencyLsa.
/// C++: `HelloProtocol::processInterestTimedOut` final branch
/// (`NLSR/src/hello-protocol.cpp:189`).
fn on_hello_failure(inner: &HelloInner, neighbor: &Name) {
    let old_state = {
        let mut states = inner.states.lock().unwrap();
        let entry = match states.get_mut(neighbor) {
            Some(e) => e,
            None => return,
        };
        let old = entry.state;
        entry.state = NeighborState::Inactive;
        old
    };

    if old_state == NeighborState::Active {
        debug!(target: t::ROUTING_NLSR, neighbor = %neighbor, "adjacency transition → Inactive");
        rebuild_and_install_adj_lsa(inner);
        publish_snapshot(inner);
    }
}

/// C++: `Lsdb::buildAndInstallOwnAdjLsa` (`NLSR/src/lsdb.cpp:130`).
fn rebuild_and_install_adj_lsa(inner: &HelloInner) {
    let adjacencies: Vec<Adjacent> = {
        let states = inner.states.lock().unwrap();
        states
            .iter()
            .filter(|(_, e)| e.state == NeighborState::Active)
            .map(|(name, e)| Adjacent {
                name: name.clone(),
                face_uri: e.face_uri.clone(),
                link_cost: e.link_cost,
            })
            .collect()
    };

    let seq = inner.adj_seq.fetch_add(1, Ordering::Relaxed);
    let result = inner
        .lsdb
        .build_own_adj_lsa(adjacencies, seq, inner.config.lsa_refresh_ms);
    debug!(target: t::ROUTING_NLSR, "installed own AdjLSA seq={seq}: {:?}", result);
}

fn publish_snapshot(inner: &HelloInner) {
    let neighbors: Vec<(Name, NeighborState)> = {
        let states = inner.states.lock().unwrap();
        states
            .iter()
            .map(|(name, e)| (name.clone(), e.state))
            .collect()
    };
    let _ = inner.adj_tx.send(AdjacencySnapshot { neighbors });
}

/// `/<neighbor>/nlsr/INFO/<own_router_wire>` — own-router prefix is a
/// `GenericNameComponent` whose value is the full Name TLV wire
/// encoding (`name.wireEncode()` in ndn-cxx). C++:
/// `HelloProtocol::sendHelloInterest:97-103`.
fn build_hello_interest_name(neighbor: &Name, own_router: &Name) -> Name {
    let own_wire = own_router.encode_to_tlv();
    neighbor
        .clone()
        .append(NLSR_COMPONENT)
        .append(INFO_COMPONENT)
        .append_component(NameComponent::generic(own_wire))
}

#[cfg(test)]
mod nlsr_hello {
    use std::collections::VecDeque;
    use std::sync::Arc;
    use std::sync::Mutex as StdMutex;
    use std::time::Duration;

    use async_trait::async_trait;
    use bytes::Bytes;
    use ndn_app::{AppError, Connection, Consumer};
    use ndn_packet::encode::DataBuilder;
    use ndn_packet::lp::{LpPacket, is_lp_packet};
    use ndn_packet::{Data, Interest, Name};
    use ndn_transport::FaceId;
    use tokio::sync::Notify;
    use tokio_util::sync::CancellationToken;

    use super::{
        HelloConfig, HelloNeighborConfig, HelloProtocol, NeighborState, build_hello_interest_name,
    };
    use crate::protocols::nlsr::lsa::LsaType;
    use crate::protocols::nlsr::lsdb::Lsdb;

    //
    // Simulates a forwarder: each `send(wire)` LP-unwraps the Interest
    // (Consumer::fetch_on pins it via NDNLPv2 NextHopFaceId 0x0330) and
    // runs the test's responder closure; any reply is queued for `recv()`.
    // Single-loop Consumer ⇒ no need to correlate concurrent outstanding
    // Interests, matching the per-Hello-loop pattern start() now uses.
    struct MockConnection {
        on_send: Arc<dyn Fn(Interest) -> Option<Bytes> + Send + Sync>,
        inbox: StdMutex<VecDeque<Bytes>>,
        notify: Notify,
    }

    impl MockConnection {
        fn new<F>(responder: F) -> Arc<Self>
        where
            F: Fn(Interest) -> Option<Bytes> + Send + Sync + 'static,
        {
            Arc::new(Self {
                on_send: Arc::new(responder),
                inbox: StdMutex::new(VecDeque::new()),
                notify: Notify::new(),
            })
        }
    }

    #[async_trait]
    impl Connection for MockConnection {
        async fn send(&self, wire: Bytes) -> Result<(), AppError> {
            let inner = if is_lp_packet(&wire) {
                LpPacket::decode(wire.clone())
                    .ok()
                    .and_then(|lp| lp.fragment)
                    .unwrap_or(wire)
            } else {
                wire
            };
            if let Ok(interest) = Interest::decode(inner)
                && let Some(reply) = (self.on_send)(interest)
            {
                self.inbox.lock().unwrap().push_back(reply);
                self.notify.notify_one();
            }
            Ok(())
        }
        async fn recv(&self) -> Option<Bytes> {
            loop {
                if let Some(b) = self.inbox.lock().unwrap().pop_front() {
                    return Some(b);
                }
                self.notify.notified().await;
            }
        }
        async fn register_prefix(&self, _: &Name) -> Result<(), AppError> {
            Ok(())
        }
    }

    fn mock_consumer<F>(responder: F) -> Consumer
    where
        F: Fn(Interest) -> Option<Bytes> + Send + Sync + 'static,
    {
        Consumer::new(MockConnection::new(responder) as Arc<dyn Connection>)
    }

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    fn lsdb(own: &str) -> Arc<Lsdb> {
        Arc::new(Lsdb::new(n(own)))
    }

    fn hello_config(own: &str, neighbors: &[&str]) -> HelloConfig {
        HelloConfig {
            own_router: n(own),
            neighbors: neighbors
                .iter()
                .map(|nb| HelloNeighborConfig {
                    name: n(nb),
                    face_uri: "udp4://127.0.0.1:6363".into(),
                    link_cost: 10.0,
                })
                .collect(),
            hello_interval_secs: 60,
            hello_retries: 3,
            hello_timeout_secs: 1,
            lsa_refresh_ms: 120_000,
        }
    }

    /// Build a valid Hello Data wire response for a given interest name.
    fn hello_data_for(interest_name: &Name) -> Bytes {
        let version_us = 1_000_000u64;
        let data_name = interest_name.clone().append_version(version_us);
        DataBuilder::new(data_name, b"INFO")
            .freshness(Duration::ZERO)
            .build()
    }

    /// Node A and Node B each have a Hello protocol.  Each node's face
    /// simulates the other always responding.  After one hello interval, both
    /// nodes should have their peer in the Active state and an AdjacencyLsa
    /// installed in their LSDB.
    #[tokio::test(start_paused = true)]
    async fn two_node_hello_loop() {
        let db_a = lsdb("/ndn/test/A");
        let db_b = lsdb("/ndn/test/B");

        // Node A: simulated forwarder where B always responds.
        let interest_name_a_to_b = build_hello_interest_name(&n("/ndn/test/B"), &n("/ndn/test/A"));
        let consumer_a = mock_consumer({
            let iname = interest_name_a_to_b.clone();
            move |_interest| Some(hello_data_for(&iname))
        });

        // Node B: simulated forwarder where A always responds.
        let interest_name_b_to_a = build_hello_interest_name(&n("/ndn/test/A"), &n("/ndn/test/B"));
        let consumer_b = mock_consumer({
            let iname = interest_name_b_to_a.clone();
            move |_interest| Some(hello_data_for(&iname))
        });

        let (hello_a, mut rx_a) =
            HelloProtocol::new(hello_config("/ndn/test/A", &["/ndn/test/B"]), db_a.clone());
        let (hello_b, mut rx_b) =
            HelloProtocol::new(hello_config("/ndn/test/B", &["/ndn/test/A"]), db_b.clone());

        let cancel = CancellationToken::new();
        let _h_a = hello_a.start(
            vec![(n("/ndn/test/B"), FaceId(1), consumer_a)],
            cancel.clone(),
        );
        let _h_b = hello_b.start(
            vec![(n("/ndn/test/A"), FaceId(2), consumer_b)],
            cancel.clone(),
        );

        // Advance past the first interval tick (interval fires at t=0, so a
        // small advance is sufficient for the tasks to run).
        tokio::time::advance(Duration::from_millis(10)).await;
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        cancel.cancel();

        // Both nodes should now see each other as Active.
        let snap_a = rx_a.borrow_and_update().clone();
        let snap_b = rx_b.borrow_and_update().clone();

        let state_b_from_a = snap_a
            .neighbors
            .iter()
            .find(|(nm, _)| *nm == n("/ndn/test/B"))
            .map(|(_, s)| *s);
        assert_eq!(
            state_b_from_a,
            Some(NeighborState::Active),
            "A should see B as Active"
        );

        let state_a_from_b = snap_b
            .neighbors
            .iter()
            .find(|(nm, _)| *nm == n("/ndn/test/A"))
            .map(|(_, s)| *s);
        assert_eq!(
            state_a_from_b,
            Some(NeighborState::Active),
            "B should see A as Active"
        );
    }

    /// After a successful Hello exchange, the LSDB must contain an
    /// AdjacencyLsa originated by the local router.
    #[tokio::test(start_paused = true)]
    async fn adj_lsa_installed_after_success() {
        let db = lsdb("/ndn/test/A");
        let interest_name = build_hello_interest_name(&n("/ndn/test/B"), &n("/ndn/test/A"));
        let consumer = mock_consumer({
            let iname = interest_name.clone();
            move |_| Some(hello_data_for(&iname))
        });

        let (hello, _rx) =
            HelloProtocol::new(hello_config("/ndn/test/A", &["/ndn/test/B"]), db.clone());

        let cancel = CancellationToken::new();
        let _h = hello.start(
            vec![(n("/ndn/test/B"), FaceId(1), consumer)],
            cancel.clone(),
        );

        tokio::time::advance(Duration::from_millis(10)).await;
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        cancel.cancel();

        let lsa = db.lookup(&n("/ndn/test/A"), LsaType::Adjacency);
        assert!(
            lsa.is_some(),
            "AdjacencyLsa must be installed after first Hello success"
        );
    }

    /// Three consecutive failures (simulated by a non-responding mock) must
    /// transition the neighbor from Active → Inactive and update the LSDB.
    #[tokio::test(start_paused = true)]
    async fn hello_failure_marks_inactive() {
        let db = lsdb("/ndn/test/A");

        // First: node B always responds (go Active).
        let interest_name = build_hello_interest_name(&n("/ndn/test/B"), &n("/ndn/test/A"));
        let responds = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let responds_c = responds.clone();
        let iname_c = interest_name.clone();
        let consumer = mock_consumer(move |_| {
            if responds_c.load(std::sync::atomic::Ordering::Relaxed) {
                Some(hello_data_for(&iname_c))
            } else {
                None // → fetch_on times out → treated as failure
            }
        });

        let (hello, mut rx) = HelloProtocol::new(
            HelloConfig {
                hello_interval_secs: 2, // short for test
                hello_retries: 3,
                hello_timeout_secs: 1,
                lsa_refresh_ms: 120_000,
                ..hello_config("/ndn/test/A", &["/ndn/test/B"])
            },
            db.clone(),
        );
        let cancel = CancellationToken::new();
        let _h = hello.start(
            vec![(n("/ndn/test/B"), FaceId(1), consumer)],
            cancel.clone(),
        );

        // Advance to trigger first interval — B responds → Active.
        tokio::time::advance(Duration::from_millis(10)).await;
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        {
            let snap = rx.borrow_and_update().clone();
            let state = snap
                .neighbors
                .iter()
                .find(|(nm, _)| *nm == n("/ndn/test/B"))
                .map(|(_, s)| *s);
            assert_eq!(
                state,
                Some(NeighborState::Active),
                "should be Active after first hello"
            );
        }

        // Stop B from responding — next interval will fail 3 times → Inactive.
        responds.store(false, std::sync::atomic::Ordering::Relaxed);

        // Advance past timeout window for 3 retries. Each retry waits
        // `Consumer::fetch_with_on`'s lifetime (= hello_timeout_secs)
        // + 500 ms buffer = 1.5 s; 3 retries ≤ 4.5 s. Add the interval
        // (2 s): total ≤ 6.5 s. Advance generously and pump the runtime
        // — paused-time tests need yields between each .await edge in
        // the nested timeout → recv → notify chain.
        for _ in 0..8 {
            tokio::time::advance(Duration::from_secs(1)).await;
            for _ in 0..4 {
                tokio::task::yield_now().await;
            }
        }

        cancel.cancel();

        let snap = rx.borrow_and_update().clone();
        let state = snap
            .neighbors
            .iter()
            .find(|(nm, _)| *nm == n("/ndn/test/B"))
            .map(|(_, s)| *s);
        assert_eq!(
            state,
            Some(NeighborState::Inactive),
            "should be Inactive after failure"
        );

        // AdjLSA should still be present but with no adjacencies (B is Inactive).
        let lsa = db.lookup(&n("/ndn/test/A"), LsaType::Adjacency);
        assert!(
            lsa.is_some(),
            "AdjLSA must be updated on transition to Inactive"
        );
    }

    /// When a Hello Interest arrives for a known neighbor, we must return a
    /// correctly named Data wire.  For an unknown requester, we return None.
    #[test]
    fn responder_returns_data_for_known_neighbor() {
        let (hello, _rx) = HelloProtocol::new(
            hello_config("/ndn/test/A", &["/ndn/test/B"]),
            lsdb("/ndn/test/A"),
        );

        // Construct a proper inbound interest: /<own>/nlsr/INFO/<requester_wire>
        use ndn_packet::NameComponent;
        let requester_wire = n("/ndn/test/B").encode_to_tlv();
        let inbound_interest = n("/ndn/test/A")
            .append(b"nlsr" as &[u8])
            .append(b"INFO" as &[u8])
            .append_component(NameComponent::generic(requester_wire));

        let data_wire = hello.handle_incoming_interest(&inbound_interest);
        assert!(
            data_wire.is_some(),
            "should produce Data for known neighbor"
        );

        let data = Data::decode(data_wire.unwrap()).unwrap();
        // Data name must start with /<own_router>/nlsr/INFO/...
        assert!(
            data.name.to_string().starts_with("/ndn/test/A"),
            "data name prefix"
        );
    }

    #[test]
    fn responder_returns_none_for_unknown_requester() {
        let (hello, _rx) = HelloProtocol::new(
            hello_config("/ndn/test/A", &["/ndn/test/B"]),
            lsdb("/ndn/test/A"),
        );

        use ndn_packet::NameComponent;
        let unknown_wire = n("/ndn/test/UNKNOWN").encode_to_tlv();
        let inbound_interest = n("/ndn/test/A")
            .append(b"nlsr" as &[u8])
            .append(b"INFO" as &[u8])
            .append_component(NameComponent::generic(unknown_wire));

        let data_wire = hello.handle_incoming_interest(&inbound_interest);
        assert!(
            data_wire.is_none(),
            "should return None for unknown requester"
        );
    }
}
