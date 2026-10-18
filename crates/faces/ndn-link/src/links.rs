//! Running the links: accepting, dialling, establishing, and keeping them.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Weak};
use std::time::Duration;

use parking_lot::Mutex;

use ndn_face_quic::{
    CloseReason, Handshaken, Incoming, KeyFingerprint, LinkEndpoint, LinkError, LinkHandle, LinkHello,
    LinkKeySource, LinkTransportConfig,
};
use ndn_packet::Name;
use ndn_transport::reliability::ReliabilityConfig;
use ndn_transport::{Face, FaceId, LpLinkService};
use tokio_util::sync::CancellationToken;

use crate::admission::{Admitted, Enrollment, Judge, list};
use crate::host::{FaceSink, LinkHints, LinkTrust, PathCandidate, PathSource};
use crate::peer::{PeerId, PeerSpec, Peers};
use crate::policy::{Backoff, ENROLLMENT_IDLE, MESSAGE_DEADLINE};
use crate::routes::routes_for;
use crate::slots::EnrollmentSlots;
use crate::table::{LinkPath, LinkTable, Registration};

/// What a host gives [`Links::start`].
pub struct LinkSetup {
    /// The devices this one links with; a peer's [`PeerId`] is its index
    /// here.
    pub peers: Vec<PeerSpec>,
    /// The key this device links with now.
    pub key: Arc<dyn LinkKeySource>,
    pub trust: Arc<dyn LinkTrust>,
    pub faces: Arc<dyn FaceSink>,
    pub paths: Arc<dyn PathSource>,
    /// The host's link socket, bound with the same `key` and `transport`:
    /// links are accepted on it when it listens, and dialled from it for
    /// its address family (so other devices see one address for this one).
    /// Dials of the other family, or all dials without it, use a dial-only
    /// socket on an address the system picks.
    pub socket: Option<Arc<LinkEndpoint>>,
    pub transport: LinkTransportConfig,
    pub hints: LinkHints,
}

/// This device's links.
pub struct Links {
    key: Arc<dyn LinkKeySource>,
    trust: Arc<dyn LinkTrust>,
    faces: Arc<dyn FaceSink>,
    paths: Arc<dyn PathSource>,
    peers: Peers,
    hints: LinkHints,
    transport: LinkTransportConfig,
    socket: Option<Arc<LinkEndpoint>>,
    /// Dial-only sockets, by address family (`true`: IPv4).
    dialers: Mutex<HashMap<bool, Arc<LinkEndpoint>>>,
    table: LinkTable,
    enrollment_slots: EnrollmentSlots,
    cancel: CancellationToken,
}

impl Links {
    /// Start: accept links on the socket when it listens, dial each peer
    /// that has a path, and close links a newly adopted trust context
    /// revokes. Everything stops at `cancel`.
    pub fn start(setup: LinkSetup, cancel: CancellationToken) -> Arc<Self> {
        let links = Arc::new(Self {
            key: setup.key,
            trust: setup.trust,
            faces: setup.faces,
            paths: setup.paths,
            peers: Peers::new(setup.peers),
            hints: setup.hints,
            transport: setup.transport,
            socket: setup.socket,
            dialers: Mutex::new(HashMap::new()),
            table: LinkTable::default(),
            enrollment_slots: EnrollmentSlots::default(),
            cancel,
        });

        let weak = Arc::downgrade(&links);
        links.trust.keyring().on_revocation(move |ctx, _| {
            if let Some(links) = weak.upgrade() {
                links.table.close_revoked(ctx);
            }
        });
        if let Some(socket) = links.socket.as_ref().filter(|s| s.is_listening()) {
            tokio::spawn(accept_loop(Arc::downgrade(&links), Arc::clone(socket)));
        }
        for (id, peer) in links.peers.iter() {
            if !links.paths.candidates(id, peer).is_empty() {
                tokio::spawn(dial_loop(Arc::downgrade(&links), id));
            }
        }
        links
    }

    /// Tell every linked device that this one is shutting down.
    pub async fn shutdown(&self) {
        let text = "the device is shutting down; it links again when it is back";
        let grace = Duration::from_secs(1);
        let dialers: Vec<_> = self
            .dialers
            .lock()
            .values()
            .cloned()
            .collect();
        for endpoint in self.socket.iter().chain(dialers.iter()) {
            endpoint.close(CloseReason::Shutdown, text, grace).await;
        }
    }

    /// This device switched to another key (it enrolled): close each
    /// enrollment link for a namespace that key is certified in, and dial it
    /// again, now as an enrolled device.
    pub fn key_switched(&self) {
        if let Some(cert) = self.judge().own_certificate() {
            self.table.relink_enrolled(&cert.name);
        }
    }

    fn judge(&self) -> Judge<'_> {
        Judge {
            trust: self.trust.as_ref(),
            peers: &self.peers,
            hints: &self.hints,
        }
    }

    /// The endpoint to dial `addr` from: the host's link socket when it has
    /// that address family (so the other device sees one address for this
    /// one, the one the host bound), else a dial-only socket per family on
    /// an address the system picks.
    fn endpoint_for(&self, addr: SocketAddr) -> Result<Arc<LinkEndpoint>, LinkError> {
        if let Some(socket) = &self.socket
            && socket.local_addr().is_ok_and(|l| l.is_ipv4() == addr.is_ipv4())
        {
            return Ok(Arc::clone(socket));
        }
        let mut dialers = self.dialers.lock();
        if let Some(endpoint) = dialers.get(&addr.is_ipv4()) {
            return Ok(Arc::clone(endpoint));
        }
        let bind: SocketAddr = if addr.is_ipv4() {
            SocketAddr::from(([0, 0, 0, 0], 0))
        } else {
            SocketAddr::from(([0u16; 8], 0))
        };
        let endpoint = Arc::new(LinkEndpoint::bind(bind, Arc::clone(&self.key), &self.transport, false)?);
        dialers.insert(addr.is_ipv4(), Arc::clone(&endpoint));
        Ok(endpoint)
    }

    fn my_fingerprint(&self) -> Option<KeyFingerprint> {
        self.key.current().ok().map(|k| k.fingerprint())
    }

    /// Run a handshaken connection to its end: exchange hellos, decide,
    /// admit (or refuse), and register the link. Returns the link's handle
    /// once it is up.
    async fn establish(self: &Arc<Self>, mut hs: Handshaken, dialed: Option<PeerId>) -> Result<LinkHandle, LinkError> {
        let remote = hs.remote_address();
        let ours = LinkHello {
            certificates: self.trust.own_chain(),
        };
        let theirs = hs.exchange_hello(&ours, MESSAGE_DEADLINE).await?;
        let judge = self.judge();
        let admitted = match judge.decide(hs.peer_key(), &theirs, dialed).await {
            Ok(a) => a,
            Err(refusal) => {
                tracing::warn!(
                    target: "face.quic",
                    %remote,
                    key = %hs.peer_key().fingerprint(),
                    reason = ?refusal.reason,
                    "refused a link: {}",
                    refusal.text
                );
                hs.refuse(refusal.reason, &refusal.text);
                return Err(LinkError::RefusedHere {
                    reason: refusal.reason,
                    text: refusal.text,
                });
            }
        };
        let slot = match &admitted.enrollment {
            Some(Enrollment::Relay(_)) => match self.enrollment_slots.reserve(remote.ip()) {
                Ok(slot) => Some(slot),
                Err(refusal) => {
                    tracing::warn!(
                        target: "face.quic",
                        %remote,
                        key = %hs.peer_key().fingerprint(),
                        "refused an enrollment link: {}",
                        refusal.text
                    );
                    hs.refuse(refusal.reason, &refusal.text);
                    return Err(LinkError::RefusedHere {
                        reason: refusal.reason,
                        text: refusal.text,
                    });
                }
            },
            _ => None,
        };
        let direction = hs.direction();
        let face_id = self.faces.alloc_face_id();
        let link = hs
            .admit(face_id, MESSAGE_DEADLINE, judge.admission_for(&admitted))
            .await?;
        let reliability = admitted.peer.is_some_and(|i| self.peers.get(i).reliability);
        let link_service: Arc<dyn ndn_transport::LinkService> = if reliability {
            Arc::new(LpLinkService::with_reliability(ReliabilityConfig::ethernet()))
        } else {
            ndn_transport::default_link_service_for_kind(ndn_transport::FaceKind::Quic)
        };
        let face = Face::from_parts(Arc::new(link.face), link_service);
        let handle = link.handle;
        let peer_enrollment = link.peer_verdict.enrollment_link.unwrap_or_default();
        let mut enrolling = peer_enrollment.clone();
        if let Some(Enrollment::Device(ns)) = &admitted.enrollment
            && !enrolling.contains(ns)
        {
            enrolling.push(ns.clone());
        }
        let registration = Registration {
            fingerprint: admitted.fingerprint,
            peer: admitted.peer,
            identity: admitted.identity.clone(),
            enrolling,
            path: LinkPath {
                face: face_id,
                handle: handle.clone(),
                direction,
            },
        };
        let Some(generation) = self.table.register(registration, self.my_fingerprint()) else {
            return Err(LinkError::RefusedHere {
                reason: CloseReason::Replaced,
                text: "a link between these two devices already exists".into(),
            });
        };
        self.faces.add_face(face, self.cancel.child_token());
        // The namespace route goes to a relay this device dials, whichever
        // side's dial this link came from (when both dial, one link stays).
        let dials = admitted
            .peer
            .is_some_and(|i| !self.paths.candidates(i, self.peers.get(i)).is_empty());
        let routes = routes_for(&self.peers, &admitted, dials);
        self.faces.add_routes(face_id, &routes);
        tracing::info!(
            target: "face.quic",
            face = face_id.0,
            %remote,
            peer = %admitted.describe(),
            direction = ?direction,
            routes = ?routes.iter().map(|r| format!("{} cost {}", r.prefix, r.cost)).collect::<Vec<_>>(),
            "link up"
        );
        self.explain_enrollment(&admitted, &peer_enrollment, face_id);
        let weak = Arc::downgrade(self);
        let watched = handle.clone();
        let fingerprint = admitted.fingerprint;
        let describe = admitted.describe();
        tokio::spawn(async move {
            let why = match slot {
                // An enrollment link that carries nothing for its idle
                // lifetime is closed; the device dials again if it still
                // needs it.
                Some(slot) => {
                    let why = loop {
                        tokio::select! {
                            why = watched.closed() => break why,
                            () = tokio::time::sleep(ENROLLMENT_IDLE / 4) => {}
                        }
                        if watched.scope_idle_for().is_some_and(|idle| idle >= ENROLLMENT_IDLE) {
                            watched.close(
                                CloseReason::Idle,
                                &format!(
                                    "this enrollment link carried nothing for {} s and is closed; \
                                     your device dials again by itself while it enrolls",
                                    ENROLLMENT_IDLE.as_secs()
                                ),
                            );
                        }
                    };
                    drop(slot);
                    why
                }
                None => watched.closed().await,
            };
            tracing::info!(
                target: "face.quic",
                face = face_id.0,
                peer = %describe,
                "link down: {why}"
            );
            if let Some(links) = weak.upgrade() {
                links.table.unregister(fingerprint, generation);
                links.faces.remove_face(face_id);
            }
        });
        Ok(handle)
    }

    /// Say, once a link is up, what an enrollment link on either side
    /// carries and what makes it a full link.
    fn explain_enrollment(&self, admitted: &Admitted, peer_enrollment: &[Name], face: FaceId) {
        let judge = self.judge();
        let peer = judge.label(admitted);
        let enroll = &self.hints.enroll;
        match &admitted.enrollment {
            Some(Enrollment::Relay(namespaces)) => tracing::info!(
                target: "face.quic",
                face = face.0,
                "admitted {peer} on an enrollment link: it carries only that device's enrollment \
                 in {} (Interests for its CA, trust context and certificates, and their answers); \
                 the device links as an enrolled device once it holds a certificate",
                list(namespaces)
            ),
            Some(Enrollment::Device(ns)) => tracing::info!(
                target: "face.quic",
                face = face.0,
                "linked to {peer} for this device's enrollment in {ns} only: it holds no \
                 certificate in {ns}, so it cannot confirm the device there yet. Enroll it \
                 ({enroll}); the link is made again as a full link then"
            ),
            None => {}
        }
        if peer_enrollment.is_empty() {
            return;
        }
        let enrolled: Vec<&Name> = peer_enrollment
            .iter()
            .filter(|ns| judge.own_role_in(ns).is_some())
            .collect();
        if enrolled.is_empty() {
            tracing::info!(
                target: "face.quic",
                face = face.0,
                "{peer} admitted this device on an enrollment link: it carries only this device's \
                 enrollment in {} until it enrolls ({enroll}); the link is made again as a full \
                 link then",
                list(peer_enrollment)
            );
        } else {
            tracing::warn!(
                target: "face.quic",
                face = face.0,
                "{peer} admitted this device only on an enrollment link, although it holds a \
                 certificate in {}: that device cannot validate it — it may hold an older version \
                 of the trust context ({} there) or lack the issuer chain. This device's key: {}",
                enrolled.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(", "),
                self.hints.refresh,
                admitted.fingerprint
            );
        }
    }

    /// One attempt over every path of `peer`; the first that links wins,
    /// else the last failure.
    async fn dial_once(self: &Arc<Self>, id: PeerId) -> Result<LinkHandle, LinkError> {
        let peer = self.peers.get(id);
        let mut last = LinkError::Connect(format!("{} has no endpoint", peer.label));
        for candidate in self.paths.candidates(id, peer) {
            let addrs: Vec<SocketAddr> = match candidate {
                PathCandidate::Address(addr) => vec![addr],
                PathCandidate::Endpoint(endpoint) => match tokio::net::lookup_host(endpoint.as_str()).await {
                    Ok(addrs) => addrs.collect(),
                    Err(e) => {
                        last = LinkError::Connect(format!("cannot resolve {endpoint}: {e}"));
                        continue;
                    }
                },
            };
            for addr in addrs {
                let socket = match self.endpoint_for(addr) {
                    Ok(s) => s,
                    Err(e) => {
                        last = LinkError::Connect(format!("no socket to dial {addr} from: {e}"));
                        continue;
                    }
                };
                let attempt = async {
                    let hs = socket.connect(addr, peer.key).await?;
                    self.establish(hs, Some(id)).await
                };
                match attempt.await {
                    Ok(handle) => return Ok(handle),
                    Err(e) => last = e,
                }
            }
        }
        Err(last)
    }
}

async fn accept_loop(links: Weak<Links>, listener: Arc<LinkEndpoint>) {
    loop {
        let Some(cancel) = links.upgrade().map(|l| l.cancel.clone()) else {
            return;
        };
        let incoming = tokio::select! {
            () = cancel.cancelled() => return,
            incoming = listener.accept() => incoming,
        };
        let Some(incoming) = incoming else { return };
        let Some(links) = links.upgrade() else { return };
        tokio::spawn(inbound(links, incoming));
    }
}

async fn inbound(links: Arc<Links>, incoming: Incoming) {
    let remote = incoming.remote_address();
    let hs = match incoming.handshake().await {
        Ok(hs) => hs,
        Err(e) => {
            tracing::info!(target: "face.quic", %remote, "inbound link handshake failed: {e}");
            return;
        }
    };
    // A refusal here was logged with its reason where it was decided.
    if let Err(e) = links.establish(hs, None).await
        && !matches!(e, LinkError::RefusedHere { .. })
    {
        tracing::info!(target: "face.quic", %remote, "inbound link did not come up: {e}");
    }
}

/// Keep `peer` linked: dial its paths in order, and again with backoff
/// whenever the link drops (once, unless persistent).
async fn dial_loop(links: Weak<Links>, id: PeerId) {
    let mut backoff = Backoff::default();
    loop {
        let Some(this) = links.upgrade() else { return };
        let cancel = this.cancel.clone();
        let peer = this.peers.get(id);
        let persistent = peer.persistent;
        let label = peer.label.clone();

        // Already linked (the other device dialled this one): wait for that
        // link to end.
        if let Some(handle) = this.table.link_to(id) {
            drop(this);
            tokio::select! {
                () = cancel.cancelled() => return,
                _ = handle.closed() => {}
            }
            if !relink_once(&links, id) && !persistent {
                return;
            }
            continue;
        }

        let attempt = this.dial_once(id).await;
        drop(this);
        let wait = match attempt {
            Ok(handle) => {
                backoff.reset();
                tokio::select! {
                    () = cancel.cancelled() => return,
                    _ = handle.closed() => {}
                }
                if !relink_once(&links, id) && !persistent {
                    return;
                }
                backoff.after_drop()
            }
            Err(e) => {
                let refused = !e.is_transient();
                let wait = backoff.after_failure(refused);
                tracing::warn!(
                    target: "face.quic",
                    peer = %label,
                    retry_in_secs = wait.as_secs_f32(),
                    "link to {label} failed: {e}"
                );
                if !persistent {
                    return;
                }
                wait
            }
        };
        tokio::select! {
            () = cancel.cancelled() => return,
            () = tokio::time::sleep(wait) => {}
        }
    }
}

/// Whether `peer` is to be dialled again once, its enrollment link having
/// been closed because this device enrolled.
fn relink_once(links: &Weak<Links>, id: PeerId) -> bool {
    links.upgrade().is_some_and(|l| l.table.take_relink(id))
}
