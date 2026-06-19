//! A hardware-free NAN cluster: every endpoint's follow-up "broadcast" is heard
//! by every *other* endpoint on the same bus, with a configurable observed
//! RSSI. Models the connectionless, half-duplex (no self-hearing),
//! fire-and-forget semantics of NAN follow-up messages — enough to exercise the
//! face, NDNLPv2 fragmentation/reassembly, RSSI plumbing, and service
//! publish/subscribe discovery through a real engine without a radio.

use std::collections::{HashMap, HashSet};
use std::net::{SocketAddr, UdpSocket as StdUdpSocket};
use std::sync::{Arc, Mutex as StdMutex};

use async_trait::async_trait;
use bytes::Bytes;
use ndn_transport::FaceError;
use tokio::sync::{Mutex, broadcast};

use crate::{FollowupFrame, NanBackend, NanMatch, NanServiceName, NdpLink};

#[derive(Clone)]
struct Followup {
    sender: u64,
    nmi: [u8; 6],
    frame: Bytes,
}

/// Cluster-wide service publication registry: service name → advertising NMIs.
type Publications = Arc<StdMutex<HashMap<String, Vec<[u8; 6]>>>>;
/// Cluster-wide NDP address book: NMI → its data-path UDP address.
type NdpAddrs = Arc<StdMutex<HashMap<[u8; 6], SocketAddr>>>;

/// A shared NAN cluster medium. Hand out [`LoopbackNanEndpoint`]s with
/// [`endpoint`](Self::endpoint).
pub struct LoopbackNanBus {
    tx: broadcast::Sender<Arc<Followup>>,
    pubs: Publications,
    ndp_addrs: NdpAddrs,
}

impl LoopbackNanBus {
    pub fn new() -> Self {
        let (tx, _rx) = broadcast::channel(1024);
        Self {
            tx,
            pubs: Arc::new(StdMutex::new(HashMap::new())),
            ndp_addrs: Arc::new(StdMutex::new(HashMap::new())),
        }
    }

    /// Attach an endpoint identified by `node_id` (used to suppress
    /// self-hearing), with management-interface MAC `nmi`, observing
    /// `observed_rssi_dbm` on every follow-up it receives.
    ///
    /// Eagerly binds a loopback UDP socket to stand in for the endpoint's NDP
    /// data-path interface and registers its address, so [`request_ndp`] is a
    /// simple lookup (a real radio negotiates the NDP on demand).
    ///
    /// [`request_ndp`]: NanBackend::request_ndp
    pub fn endpoint(
        &self,
        node_id: u64,
        nmi: [u8; 6],
        observed_rssi_dbm: i8,
    ) -> LoopbackNanEndpoint {
        let ndp = StdUdpSocket::bind("127.0.0.1:0").expect("bind loopback NDP socket");
        ndp.set_nonblocking(true)
            .expect("set NDP socket nonblocking");
        let ndp_addr = ndp.local_addr().expect("NDP local addr");
        self.ndp_addrs.lock().unwrap().insert(nmi, ndp_addr);
        LoopbackNanEndpoint {
            node_id,
            nmi,
            observed_rssi_dbm,
            tx: self.tx.clone(),
            rx: Mutex::new(self.tx.subscribe()),
            pubs: Arc::clone(&self.pubs),
            subs: StdMutex::new(HashSet::new()),
            seen: StdMutex::new(HashSet::new()),
            ndp_addrs: Arc::clone(&self.ndp_addrs),
            ndp_socket: StdMutex::new(Some(ndp)),
        }
    }
}

impl Default for LoopbackNanBus {
    fn default() -> Self {
        Self::new()
    }
}

/// One node on a [`LoopbackNanBus`]. Implements [`NanBackend`] — both the
/// follow-up coordination channel and service publish/subscribe discovery.
pub struct LoopbackNanEndpoint {
    node_id: u64,
    nmi: [u8; 6],
    observed_rssi_dbm: i8,
    tx: broadcast::Sender<Arc<Followup>>,
    rx: Mutex<broadcast::Receiver<Arc<Followup>>>,
    /// Cluster-wide publications (shared with the bus and every endpoint).
    pubs: Publications,
    /// Services this endpoint subscribes to.
    subs: StdMutex<HashSet<String>>,
    /// Matches already returned by `drain_matches` (so each is reported once).
    seen: StdMutex<HashSet<(String, [u8; 6])>>,
    /// Cluster NDP address book (shared with the bus).
    ndp_addrs: NdpAddrs,
    /// This endpoint's pre-bound NDP socket, taken on first `request_ndp`.
    ndp_socket: StdMutex<Option<StdUdpSocket>>,
}

#[async_trait]
impl NanBackend for LoopbackNanEndpoint {
    async fn broadcast(&self, frame: Bytes) -> Result<(), FaceError> {
        // No subscribers is not an error on a connectionless medium (nobody is
        // matched — the follow-up is simply lost, like a real cluster).
        let _ = self.tx.send(Arc::new(Followup {
            sender: self.node_id,
            nmi: self.nmi,
            frame,
        }));
        Ok(())
    }

    async fn next_followup(&self) -> Result<FollowupFrame, FaceError> {
        let mut rx = self.rx.lock().await;
        loop {
            match rx.recv().await {
                Ok(f) if f.sender != self.node_id => {
                    return Ok(FollowupFrame {
                        frame: f.frame.clone(),
                        peer: Some(f.nmi),
                        rssi_dbm: Some(self.observed_rssi_dbm),
                    });
                }
                // Own transmission — a radio does not hear itself.
                Ok(_) => continue,
                // Slow consumer dropped frames; keep going (lossy medium).
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return Err(FaceError::Closed),
            }
        }
    }

    async fn publish(&self, service: &NanServiceName) -> Result<(), FaceError> {
        self.pubs
            .lock()
            .unwrap()
            .entry(service.0.clone())
            .or_default()
            .push(self.nmi);
        Ok(())
    }

    async fn subscribe(&self, service: &NanServiceName) -> Result<(), FaceError> {
        self.subs.lock().unwrap().insert(service.0.clone());
        Ok(())
    }

    fn drain_matches(&self) -> Vec<NanMatch> {
        let subs = self.subs.lock().unwrap().clone();
        let pubs = self.pubs.lock().unwrap();
        let mut seen = self.seen.lock().unwrap();
        let mut out = Vec::new();
        for service in &subs {
            let Some(peers) = pubs.get(service) else {
                continue;
            };
            for &peer in peers {
                // Don't match our own advertisement, and report each peer once.
                if peer != self.nmi && seen.insert((service.clone(), peer)) {
                    out.push(NanMatch {
                        service: NanServiceName(service.clone()),
                        peer,
                    });
                }
            }
        }
        out
    }

    async fn request_ndp(&self, peer: [u8; 6]) -> Result<NdpLink, FaceError> {
        let peer_addr = self
            .ndp_addrs
            .lock()
            .unwrap()
            .get(&peer)
            .copied()
            .ok_or_else(|| {
                FaceError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "peer has no NDP address registered",
                ))
            })?;
        let std_socket = self.ndp_socket.lock().unwrap().take().ok_or_else(|| {
            FaceError::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "NDP already established on this endpoint",
            ))
        })?;
        let socket = tokio::net::UdpSocket::from_std(std_socket)?;
        Ok(NdpLink { socket, peer_addr })
    }
}
