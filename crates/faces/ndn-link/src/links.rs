//! Running the links: accepting, dialling, establishing, and keeping them,
//! and their direct paths.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, OnceLock, Weak};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use ndn_face_quic::{
    CloseReason, Handshaken, Incoming, KeyFingerprint, LinkEndpoint, LinkError, LinkHandle, LinkHello,
    LinkKeySource, LinkTransportConfig, PathSession,
};
use ndn_packet::Name;
use ndn_transport::reliability::ReliabilityConfig;
use ndn_transport::{Face, FaceId, LpLinkService};
use tokio_util::sync::CancellationToken;

use crate::admission::{Admitted, Enrollment, Judge, device_of, hello_chain, list, own_memberships};
use crate::asleep::{RelayService, Sleepers};
use crate::candidates::CandidateSource;
use crate::control::{PeerCtl, idle_check, release};
use crate::direct::{Direct, Whom};
use crate::host::{FaceSink, LinkHints, LinkTrust, PathCandidate, PathSource};
use crate::peer::{LinkMode, PeerId, PeerSpec, Peers};
use crate::policy::{Backoff, ENROLLMENT_IDLE, MESSAGE_DEADLINE};
use crate::presence::{DirectOptions, MemberEntry};
use crate::relays::RelayOptions;
use crate::routes::{RelayRoutes, routes_for};
use crate::serving::QuotaState;
use crate::signal::Signal;
use crate::slots::EnrollmentSlots;
use crate::status::{DirectState, DirectStatus, LinkReport, LinkStatus, PathKind, PathStatus};
use crate::table::{LinkPath, LinkTable, Registration};
use crate::waiting::{WaitFor, Waiting};

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
    /// Where this device's own direct-path candidates come from, besides
    /// the reflexive addresses its links report: its interfaces
    /// ([`HostCandidates`](crate::HostCandidates)), configured addresses
    /// ([`AdvertisedCandidates`](crate::AdvertisedCandidates)), a port
    /// mapping.
    pub candidates: Vec<Arc<dyn CandidateSource>>,
    /// The host's link socket, bound with the same `key` and `transport`:
    /// links are accepted on it when it listens, and dialled from it for
    /// its address family (so other devices see one address for this one).
    /// Dials of the other family, or all dials without it, use a dial-only
    /// socket on an address the system picks.
    pub socket: Option<Arc<LinkEndpoint>>,
    pub transport: LinkTransportConfig,
    pub hints: LinkHints,
    /// Which relays this device uses.
    pub relays: RelayOptions,
    /// What this device offers as a relay: whom it serves, and whether it
    /// holds Interests for and wakes devices asleep here.
    pub service: RelayService,
    /// Direct paths by membership.
    pub direct: DirectOptions,
}

/// How a connection came to be, for [`Links::establish`].
#[derive(Clone, Copy, Debug)]
pub(crate) enum Origin {
    /// This device dialled the peer.
    Dialed(PeerId),
    /// Another device dialled this one.
    Accepted,
    /// This device dialled the direct path of a punch.
    Direct(PathSession),
}

/// This device's links.
pub struct Links {
    pub(crate) key: Arc<dyn LinkKeySource>,
    pub(crate) trust: Arc<dyn LinkTrust>,
    faces: Arc<dyn FaceSink>,
    pub(crate) paths: Arc<dyn PathSource>,
    pub(crate) candidates: Vec<Arc<dyn CandidateSource>>,
    pub(crate) peers: Peers,
    pub(crate) hints: LinkHints,
    transport: LinkTransportConfig,
    pub(crate) socket: Option<Arc<LinkEndpoint>>,
    /// Dial-only sockets, by address family (`true`: IPv4).
    pub(crate) dialers: Mutex<HashMap<bool, Arc<LinkEndpoint>>>,
    pub(crate) table: LinkTable,
    enrollment_slots: EnrollmentSlots,
    pub(crate) direct: Direct,
    signal: OnceLock<Arc<Signal>>,
    pub(crate) waiting: OnceLock<Arc<Waiting>>,
    pub(crate) relay_options: RelayOptions,
    pub(crate) service: RelayService,
    pub(crate) quotas: QuotaState,
    pub(crate) direct_options: DirectOptions,
    pub(crate) ctls: Mutex<HashMap<PeerId, Arc<PeerCtl>>>,
    pub(crate) active: AtomicBool,
    /// Namespace relays the host removed: not added again.
    pub(crate) dismissed: Mutex<HashSet<String>>,
    pub(crate) sleepers: Sleepers,
    /// Members this device punches by presence, by key.
    pub(crate) members: Mutex<HashMap<KeyFingerprint, MemberEntry>>,
    pub(crate) cancel: CancellationToken,
}

impl Links {
    /// Start: accept links on the socket when it listens, dial each peer
    /// that has a path (as its mode says), use the relays the namespaces
    /// advertise, punch direct paths to the peers reached through a relay
    /// and to members met at one, take the punches of others, hold
    /// Interests for on-demand links and sleeping devices, and close links
    /// a newly adopted trust context revokes. Everything stops at `cancel`.
    pub fn start(setup: LinkSetup, cancel: CancellationToken) -> Arc<Self> {
        let links = Arc::new(Self {
            key: setup.key,
            trust: setup.trust,
            faces: setup.faces,
            paths: setup.paths,
            candidates: setup.candidates,
            peers: Peers::new(setup.peers),
            hints: setup.hints,
            transport: setup.transport,
            socket: setup.socket,
            dialers: Mutex::new(HashMap::new()),
            table: LinkTable::default(),
            enrollment_slots: EnrollmentSlots::default(),
            direct: Direct::default(),
            signal: OnceLock::new(),
            waiting: OnceLock::new(),
            relay_options: setup.relays,
            service: setup.service,
            quotas: QuotaState::default(),
            direct_options: setup.direct,
            ctls: Mutex::new(HashMap::new()),
            active: AtomicBool::new(false),
            dismissed: Mutex::new(HashSet::new()),
            sleepers: Sleepers::default(),
            members: Mutex::new(HashMap::new()),
            cancel,
        });
        let _ = links.signal.set(Signal::start(&links));
        let _ = links.waiting.set(Waiting::start(&links));
        links.take_punches();

        let weak = Arc::downgrade(&links);
        links.trust.keyring().on_revocation(move |ctx, _| {
            if let Some(links) = weak.upgrade() {
                links.revoked(ctx);
            }
        });
        // A new version may advertise other relays or pair other roles. The
        // keyring may adopt on any thread: the work goes to this runtime.
        let weak = Arc::downgrade(&links);
        let runtime = tokio::runtime::Handle::current();
        links.trust.keyring().on_adoption(move |_| {
            if let Some(links) = weak.upgrade() {
                runtime.spawn(async move {
                    links.sync_namespace_relays();
                    links.announce_all();
                });
            }
        });
        // Every socket accepts: a listening one any link, a dial-only one
        // the direct paths of its punches.
        if let Some(socket) = &links.socket {
            tokio::spawn(accept_loop(Arc::downgrade(&links), Arc::clone(socket)));
        }
        for (id, peer) in links.peers.iter() {
            links.run_peer(id, &peer);
        }
        links.sync_namespace_relays();
        links
    }

    /// Tell every linked device that this one is shutting down.
    pub async fn shutdown(&self) {
        let text = "the device is shutting down; it links again when it is back";
        let grace = Duration::from_secs(1);
        let dialers: Vec<_> = self.dialers.lock().values().cloned().collect();
        for endpoint in self.socket.iter().chain(dialers.iter()) {
            endpoint.close(CloseReason::Shutdown, text, grace).await;
        }
    }

    /// This device's link key or its memberships changed (it enrolled in a
    /// namespace, a membership ended, or it links with another key now):
    /// close each enrollment link for a namespace it now holds a
    /// certificate in, and each full link whose hello showed other
    /// namespaces than it holds now, and dial them again (a link the other
    /// device dialled, it dials again); take punches under each of its
    /// names; use the relays its namespaces advertise.
    pub fn identities_changed(self: &Arc<Self>) {
        let certificates: Vec<Name> = self
            .judge()
            .own_certificates()
            .into_iter()
            .map(|(cert, _)| (*cert.name).clone())
            .collect();
        self.table.relink_enrolled(&certificates);
        self.table.relink_changed(&self.shown_namespaces());
        self.take_punches();
        self.sync_namespace_relays();
        for (id, _) in self.peers.iter() {
            self.route_demand(id);
        }
    }

    /// The namespaces this device shows in a hello: the one of its link
    /// key's certificate and each of its memberships', sorted.
    pub(crate) fn shown_namespaces(&self) -> Vec<Name> {
        let judge = self.judge();
        let mut shown: Vec<Name> = judge
            .own_certificates()
            .into_iter()
            .filter_map(|(cert, m)| match m {
                Some(m) => Some(m.namespace),
                None => device_of(&cert.name).map(|d| judge.namespace_of(&d)),
            })
            .collect();
        shown.sort();
        shown.dedup();
        shown
    }

    /// A newly adopted trust context revokes certificates: close the links
    /// it leaves with no identity; a link another membership still admits
    /// loses that membership's routes and presence.
    fn revoked(&self, ctx: &Arc<ndn_security::SignedTrustContext>) {
        for dropped in self.table.close_revoked(ctx) {
            for (face, prefixes) in &dropped.routes {
                self.faces.remove_routes(*face, prefixes);
            }
            if let Some(handle) = &dropped.handle {
                handle.send_presence(&ndn_face_quic::Presence {
                    namespace: dropped.namespace.clone(),
                    devices: Vec::new(),
                });
            }
            self.announce_presence(&dropped.namespace);
        }
    }

    /// This device's links now: each device, its paths, and its direct
    /// path's state.
    pub fn report(&self) -> LinkReport {
        let views = self.table.views();
        let entries = self.direct.entries();
        let mut used = vec![false; views.len()];
        let mut links = Vec::new();
        let direct_status = |whom: Whom, paths: &[PathStatus]| -> DirectStatus {
            let mut status = entries.get(&whom).map(|e| e.status()).unwrap_or_default();
            if let Some(p) = paths.iter().find(|p| p.kind == PathKind::Direct) {
                status = DirectStatus {
                    state: DirectState::Up,
                    text: format!("direct path to {}", p.remote.map(|a| a.to_string()).unwrap_or_default()),
                    retry_in: None,
                };
            }
            status
        };
        for (id, peer) in self.peers.iter() {
            let learned = entries.get(&Whom::Peer(id)).and_then(|e| e.key).or(peer.key);
            let at = views
                .iter()
                .position(|v| v.peer == Some(id) || Some(v.fingerprint) == learned);
            let mut paths = Vec::new();
            let mut key = learned;
            let mut device = peer.device.clone();
            if let Some(i) = at {
                used[i] = true;
                paths.extend(views[i].paths.iter().cloned());
                key = Some(views[i].fingerprint);
                device = views[i].device.clone().or(device);
            }
            if let Some(relay) = peer.relay
                && let Some(v) = views.iter().find(|v| v.peer == Some(relay))
                && let Some(p) = v.paths.iter().find(|p| p.kind == PathKind::Link)
            {
                paths.push(PathStatus {
                    kind: PathKind::Relay,
                    via: Some(self.peers.label(relay)),
                    ..p.clone()
                });
            }
            let direct = direct_status(Whom::Peer(id), &paths);
            links.push(LinkStatus {
                label: peer.label.clone(),
                key,
                device,
                paths,
                direct,
                peer: Some(id),
                mode: Some(peer.mode),
                relay: self.relay_status(id, &peer),
                down: self.why_down(id, &peer),
                asleep: key.and_then(|k| self.asleep_status(&k)),
            });
        }
        for (i, v) in views.iter().enumerate() {
            if used[i] {
                continue;
            }
            links.push(LinkStatus {
                label: v
                    .device
                    .as_ref()
                    .map_or_else(|| format!("key {}", v.fingerprint), ToString::to_string),
                key: Some(v.fingerprint),
                device: v.device.clone(),
                paths: v.paths.clone(),
                direct: direct_status(Whom::Key(v.fingerprint), &v.paths),
                peer: None,
                mode: None,
                relay: None,
                down: None,
                asleep: None,
            });
        }
        for (whom, entry) in &entries {
            let Whom::Key(fp) = whom else { continue };
            if links.iter().any(|l| l.key == Some(*fp)) {
                continue;
            }
            links.push(LinkStatus {
                label: entry.label.clone(),
                key: Some(*fp),
                device: entry.device.clone(),
                paths: Vec::new(),
                direct: entry.status(),
                peer: None,
                mode: None,
                relay: None,
                down: None,
                asleep: self.asleep_status(fp),
            });
        }
        for (fp, device) in self.sleepers() {
            if links.iter().any(|l| l.key == Some(fp)) {
                continue;
            }
            links.push(LinkStatus {
                label: device
                    .as_ref()
                    .map_or_else(|| format!("key {fp}"), ToString::to_string),
                key: Some(fp),
                device,
                paths: Vec::new(),
                direct: DirectStatus::default(),
                peer: None,
                mode: None,
                relay: None,
                down: None,
                asleep: self.asleep_status(&fp),
            });
        }
        LinkReport {
            key: self.my_fingerprint(),
            probes_sent: self.direct.probes_sent.load(std::sync::atomic::Ordering::Relaxed),
            punches_refused: self.direct.refused.load(std::sync::atomic::Ordering::Relaxed),
            serve: self.service.serve.describe(),
            held_total: self.waiting.get().map_or(0, |w| w.total(true)),
            wakes_sent: self.sleepers.wakes_sent.load(std::sync::atomic::Ordering::Relaxed),
            links,
        }
    }

    pub(crate) fn faces(&self) -> &Arc<dyn FaceSink> {
        &self.faces
    }

    pub(crate) fn cancel_token(&self) -> &CancellationToken {
        &self.cancel
    }

    pub(crate) fn signal(&self) -> &Arc<Signal> {
        self.signal.get().expect("the signalling face starts with the links")
    }

    pub(crate) fn waiting(&self) -> &Arc<Waiting> {
        self.waiting.get().expect("the waiting face starts with the links")
    }

    /// This device's names, one per certificate it holds (its link key's
    /// first).
    pub(crate) fn own_devices(&self) -> Vec<Name> {
        self.judge().own_devices()
    }

    /// Route the punches to each of this device's names to the signalling
    /// face.
    fn take_punches(&self) {
        let Some(signal) = self.signal.get() else { return };
        for device in self.own_devices() {
            signal.take_punches_for(self, &device);
        }
    }

    pub(crate) fn judge(&self) -> Judge<'_> {
        Judge {
            trust: self.trust.as_ref(),
            peers: &self.peers,
            hints: &self.hints,
            serve: &self.service.serve,
            quotas: &self.quotas,
        }
    }

    /// The endpoint to dial `addr` from: the host's link socket when it has
    /// that address family (so the other device sees one address for this
    /// one, the one the host bound), else a dial-only socket per family on
    /// an address the system picks (which accepts only the direct paths of
    /// its punches).
    pub(crate) fn endpoint_for(self: &Arc<Self>, addr: SocketAddr) -> Result<Arc<LinkEndpoint>, LinkError> {
        let v4 = addr.ip().to_canonical().is_ipv4();
        if let Some(socket) = &self.socket
            && socket.local_addr().is_ok_and(|l| l.is_ipv4() == v4 || l.ip().is_unspecified() && l.is_ipv6())
        {
            return Ok(Arc::clone(socket));
        }
        let mut dialers = self.dialers.lock();
        if let Some(endpoint) = dialers.get(&v4) {
            return Ok(Arc::clone(endpoint));
        }
        let bind: SocketAddr = if v4 {
            SocketAddr::from(([0, 0, 0, 0], 0))
        } else {
            SocketAddr::from(([0u16; 8], 0))
        };
        let endpoint = Arc::new(LinkEndpoint::bind(bind, Arc::clone(&self.key), &self.transport, false)?);
        dialers.insert(v4, Arc::clone(&endpoint));
        tokio::spawn(accept_loop(Arc::downgrade(self), Arc::clone(&endpoint)));
        Ok(endpoint)
    }

    pub(crate) fn my_fingerprint(&self) -> Option<KeyFingerprint> {
        self.key.current().ok().map(|k| k.fingerprint())
    }

    /// Run a handshaken connection to its end: exchange hellos, decide,
    /// admit (or refuse), and register the link or its direct path.
    /// Returns the path's handle once it is up.
    pub(crate) async fn establish(self: &Arc<Self>, mut hs: Handshaken, origin: Origin) -> Result<LinkHandle, LinkError> {
        let remote = hs.remote_address();
        let peer_fp = hs.peer_key().fingerprint();
        // A direct path is named by both hellos: the dialer's punch session,
        // and the session the listener punches with that key.
        let session = match origin {
            Origin::Direct(session) => Some(session),
            Origin::Accepted => self.direct.session_with(peer_fp),
            Origin::Dialed(_) => None,
        };
        // Dialling a relay of a namespace this device is not in (it names
        // the relay's device, not its key), this device links for its
        // enrollment only and sends no certificate: one of another namespace
        // would have the relay refuse it as a device it does not serve.
        let enrolling = match origin {
            Origin::Dialed(id) => self.peers.get(id).is_some_and(|p| {
                let judge = self.judge();
                p.key.is_none() && p.device.as_ref().is_some_and(|d| judge.own_role_in(&judge.namespace_of(d)).is_none())
            }),
            _ => false,
        };
        let channel = match hs.channel_binding() {
            Ok(channel) => channel,
            Err(e) => {
                let text = format!("this device cannot bind its memberships to the link: {e}");
                hs.refuse(CloseReason::Protocol, &text);
                return Err(LinkError::RefusedHere {
                    reason: CloseReason::Protocol,
                    text,
                });
            }
        };
        let (ours, shown) = if enrolling {
            (
                LinkHello {
                    direct_path: session,
                    ..LinkHello::default()
                },
                Vec::new(),
            )
        } else {
            // Bound to the key this connection's handshake presented, not
            // one the device switched to since.
            let memberships = own_memberships(self.trust.as_ref(), hs.local_key(), &channel, None).await;
            (
                LinkHello {
                    certificates: hello_chain(self.trust.as_ref()),
                    memberships,
                    direct_path: session,
                },
                self.shown_namespaces(),
            )
        };
        let theirs = hs.exchange_hello(&ours, MESSAGE_DEADLINE).await?;
        let refuse = |hs: Handshaken, reason: CloseReason, text: String| {
            tracing::warn!(
                target: "face.quic",
                %remote,
                key = %peer_fp,
                reason = ?reason,
                "refused a link: {text}"
            );
            hs.refuse(reason, &text);
            Err(LinkError::RefusedHere { reason, text })
        };
        let direct = match (origin, theirs.direct_path) {
            (Origin::Direct(s), Some(t)) if s == t => Some(s),
            (Origin::Direct(s), _) => {
                let text = format!(
                    "this device dialled the direct path of punch {} and your device did not take it as one",
                    hex(&s)
                );
                return refuse(hs, CloseReason::PathExpired, text);
            }
            (_, Some(t)) if session == Some(t) => Some(t),
            (_, Some(t)) => {
                let text = format!(
                    "this device runs no punch {} with your key (it ended); your device punches again",
                    hex(&t)
                );
                return refuse(hs, CloseReason::PathExpired, text);
            }
            (_, None) => None,
        };
        let dialed = match origin {
            Origin::Dialed(id) => Some(id),
            _ => None,
        };
        let judge = self.judge();
        let mut admitted = match judge.decide(hs.peer_key(), &theirs, &channel, dialed).await {
            Ok(a) => a,
            Err(refusal) => return refuse(hs, refusal.reason, refusal.text),
        };
        if let Some(session) = direct {
            if admitted.enrollment.is_some() {
                let text = "a direct path carries a full link only, and this device admits you only on an \
                            enrollment link"
                    .to_string();
                return refuse(hs, CloseReason::Unrecognized, text);
            }
            if let Some(why) = self.direct_off(&admitted) {
                return refuse(hs, CloseReason::DirectPathsOff, why);
            }
            if !self.direct.claim(&session, peer_fp) {
                let text = format!("another path of punch {} came up first", hex(&session));
                return refuse(hs, CloseReason::Replaced, text);
            }
        }
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
        // What the link carries is decided before the quota slots move to
        // the link's task: the deciding identity's limits bound it.
        let admission = judge.admission_for(&admitted);
        let quota = (admitted.quota.take(), std::mem::take(&mut admitted.quotas));
        let direction = hs.direction();
        let gone = CancellationToken::new();
        let kind = if direct.is_some() {
            PathKind::Direct
        } else {
            PathKind::Link
        };
        let peer = admitted.peer.and_then(|i| self.peers.get(i));
        let face_id = self.faces.alloc_face_id();
        let link = hs.admit(face_id, MESSAGE_DEADLINE, admission).await?;
        let reliability = peer.as_ref().is_some_and(|p| p.reliability);
        let link_service: Arc<dyn ndn_transport::LinkService> = if reliability {
            Arc::new(LpLinkService::with_reliability(ReliabilityConfig::ethernet()))
        } else {
            ndn_transport::default_link_service_for_kind(ndn_transport::FaceKind::Quic)
        };
        let transport: Arc<dyn ndn_transport::ErasedTransport> = Arc::new(link.face);
        let face = Face::from_parts(Arc::clone(&transport), Arc::clone(&link_service));
        let sender = Arc::new(Face::from_parts(transport, link_service));
        let handle = link.handle;
        let peer_enrollment = link.peer_verdict.enrollment_link.unwrap_or_default();
        let mut enrolling = peer_enrollment.clone();
        if let Some(Enrollment::Device(ns)) = &admitted.enrollment
            && !enrolling.contains(ns)
        {
            enrolling.push(ns.clone());
        }
        // The namespace route goes to a relay this device dials, whichever
        // side's dial this link came from (when both dial, one link stays);
        // a relay this device uses routes its namespaces at the relay's
        // rank.
        let dials = admitted
            .peer
            .zip(peer.as_ref())
            .is_some_and(|(i, p)| !self.paths.candidates(i, p).is_empty());
        let relay_routes = match (admitted.peer, &peer) {
            (Some(i), Some(p)) if p.relay_use.is_some() && kind == PathKind::Link => Some(RelayRoutes {
                namespaces: self.relay_namespaces(p),
                cost: self.relay_cost(i),
            }),
            _ => None,
        };
        let routes = routes_for(&self.peers, &admitted, dials, relay_routes);
        let registration = Registration {
            fingerprint: admitted.fingerprint,
            peer: admitted.peer,
            identities: admitted.identities.clone(),
            shown,
            enrolling: enrolling.clone(),
            path: LinkPath {
                face: face_id,
                handle: handle.clone(),
                direction,
                kind,
                gone: gone.clone(),
                since: Instant::now(),
                sender,
                routes: routes.clone(),
            },
        };
        let Some(generation) = self.table.register(registration, self.my_fingerprint()) else {
            return Err(LinkError::RefusedHere {
                reason: CloseReason::Replaced,
                text: "a link between these two devices already exists".into(),
            });
        };
        self.faces.add_face(face, self.cancel.child_token());
        self.faces.add_routes(face_id, &routes);
        // A served device of a namespace not held here: its Data crosses this
        // forwarder unvalidated while it is linked.
        let transit: Vec<Name> = admitted
            .identities
            .iter()
            .filter(|id| id.served.is_some())
            .map(|id| id.namespace.clone())
            .collect();
        for ns in &transit {
            self.faces.transit(ns, true);
        }
        tracing::info!(
            target: "face.quic",
            face = face_id.0,
            %remote,
            peer = %admitted.describe(),
            direction = ?direction,
            routes = ?routes.iter().map(|r| format!("{} cost {}", r.prefix, r.cost)).collect::<Vec<_>>(),
            "{} up",
            if direct.is_some() { "direct path" } else { "link" }
        );
        if let Some(session) = direct {
            self.direct.path_up(&session, &handle);
        }
        self.explain_enrollment(&admitted, &peer_enrollment, face_id);
        if kind == PathKind::Link && enrolling.is_empty() {
            self.link_up(&admitted, peer.as_deref(), &handle).await;
        }
        let weak = Arc::downgrade(self);
        let watched = handle.clone();
        let fingerprint = admitted.fingerprint;
        let describe = admitted.describe();
        let what = kind.as_str();
        tokio::spawn(async move {
            // Cancelled once this task removed the path's face and routes.
            let _gone = gone.drop_guard();
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
            drop(quota);
            tracing::info!(
                target: "face.quic",
                face = face_id.0,
                peer = %describe,
                path = what,
                "link down: {why}"
            );
            if let Some(links) = weak.upgrade() {
                for ns in &transit {
                    links.faces.transit(ns, false);
                }
                let ended = links.table.unregister(fingerprint, generation);
                links.faces.remove_face(face_id);
                if let Some(ended) = ended {
                    if ended.kind == PathKind::Direct && watched.datagrams() > 0 {
                        links.direct.carried(fingerprint);
                    }
                    links.maybe_asleep(fingerprint, &ended, watched.peer_reachability(), &why);
                    if ended.last {
                        for id in &ended.identities {
                            links.announce_presence(&id.namespace);
                        }
                    }
                    if ended.peer.is_some_and(|p| links.peers.is_relay(p)) {
                        links.reselect_relays();
                    }
                }
            }
        });
        Ok(handle)
    }

    /// A full link is up: the device is awake if it slept here, what waited
    /// for the link goes over it, this device tells it how to reach it
    /// while asleep, follows its presence list when it is a relay, and tells
    /// the members of each namespace the device was admitted in, linked
    /// here.
    async fn link_up(self: &Arc<Self>, admitted: &Admitted, peer: Option<&PeerSpec>, handle: &LinkHandle) {
        self.awake(admitted.fingerprint).await;
        if let (Some(id), Some(peer)) = (admitted.peer, peer) {
            let ctl = self.ctl(id);
            ctl.dialled(None);
            self.flush_if_linked(&WaitFor::Peer(id)).await;
            ctl.clear_demand();
            let reach = self.reachability_for(id, peer);
            if reach.hold || reach.wake_token.is_some() {
                handle.send_reachability(&reach);
            }
            // Presence from a relay this device uses, or from any device
            // whose role one of its namespaces lets relay (a plain peer
            // entry for the namespace's relay).
            let relay_role = admitted.identities.iter().any(|i| {
                self.trust
                    .keyring()
                    .context_for(&i.device)
                    .link_policy()
                    .allows_relay(i.role.as_str())
            });
            if self.peers.is_relay(id) || relay_role {
                self.follow_presence(id, handle.clone());
            }
            if self.peers.is_relay(id) {
                self.reselect_relays();
            }
        }
        for id in &admitted.identities {
            self.announce_presence(&id.namespace);
        }
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
    async fn dial_once(self: &Arc<Self>, id: PeerId, peer: &PeerSpec) -> Result<LinkHandle, LinkError> {
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
                    self.establish(hs, Origin::Dialed(id)).await
                };
                match attempt.await {
                    Ok(handle) => return Ok(handle),
                    Err(e) => last = e,
                }
            }
        }
        Err(last)
    }

    /// Whether peer `id`'s link is to be made now: it has a path, it is a
    /// chosen relay (when it is one), and its mode says so.
    fn wants_link(&self, id: PeerId, peer: &PeerSpec, ctl: &PeerCtl) -> bool {
        if peer.relay_use.is_some() && !self.relay_wanted(id) {
            return false;
        }
        match peer.mode {
            LinkMode::Always => true,
            LinkMode::Off => ctl.asked(),
            LinkMode::OnDemand { .. } => ctl.asked() || self.is_active() || ctl.demand(),
        }
    }

    /// Keep the link `handle` to peer `id` while it is wanted: closes it
    /// (as asleep, or released) once it is not — an on-demand link idle
    /// for its idle time while the host is not active, an off link the host
    /// no longer asks for, a relay no longer chosen, a removed peer.
    /// Returns once the link ended, with whether this device closed it.
    async fn keep(&self, id: PeerId, ctl: &PeerCtl, handle: &LinkHandle) -> bool {
        let mut seen = handle.datagrams();
        let mut quiet_since = Instant::now();
        loop {
            // Traffic is looked for every idle_check; once none came, sleep
            // to the idle deadline itself rather than to the next check.
            let check = match self.peers.get(id).map(|p| p.mode) {
                Some(LinkMode::OnDemand { idle }) => match idle.saturating_sub(quiet_since.elapsed()) {
                    left if left.is_zero() => idle_check(idle),
                    left => left.min(idle_check(idle)),
                },
                _ => Duration::from_secs(60),
            };
            tokio::select! {
                () = self.cancel.cancelled() => return true,
                _ = handle.closed() => return false,
                () = ctl.changed() => {}
                () = tokio::time::sleep(check) => {}
            }
            let now = handle.datagrams();
            if now != seen {
                seen = now;
                quiet_since = Instant::now();
            }
            let Some(peer) = self.peers.get(id) else {
                release(handle, false, "this device no longer uses this link (the host removed it)");
                return true;
            };
            if peer.relay_use.is_some() && !self.relay_wanted(id) {
                let text = "this device links to a more preferred relay now; it uses this one again if that \
                            one is lost";
                tracing::info!(target: "face.quic", peer = %peer.label, "releasing relay {}: {text}", peer.label);
                release(handle, false, text);
                return true;
            }
            match peer.mode {
                LinkMode::Off if !ctl.asked() => {
                    release(handle, true, "this device turned its link off; it links again when asked");
                    return true;
                }
                LinkMode::OnDemand { idle }
                    if !ctl.asked() && !self.is_active() && quiet_since.elapsed() >= idle =>
                {
                    let text = format!(
                        "this device's on-demand link carried nothing for {} s and sleeps; it links again \
                         when it has traffic",
                        idle.as_secs()
                    );
                    tracing::info!(target: "face.quic", peer = %peer.label, "closing the link to {}: {text}", peer.label);
                    release(handle, true, &text);
                    return true;
                }
                _ => {}
            }
        }
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
    if let Err(e) = links.establish(hs, Origin::Accepted).await
        && !matches!(e, LinkError::RefusedHere { .. })
    {
        tracing::info!(target: "face.quic", %remote, "inbound link did not come up: {e}");
    }
}

/// A punch session as logs and refusals show it.
fn hex(session: &PathSession) -> String {
    session.iter().map(|b| format!("{b:02x}")).collect()
}

/// Keep peer `id` linked as its mode and the relay choice say: dial its
/// paths in order when its link is wanted, again with backoff whenever it
/// drops (once, for a peer that is not persistent and links always), and
/// close it when it is no longer wanted. Ends when the peer is removed.
pub(crate) async fn dial_loop(links: Weak<Links>, id: PeerId, ctl: Arc<PeerCtl>) {
    let mut backoff = Backoff::default();
    loop {
        let Some(this) = links.upgrade() else { return };
        let cancel = this.cancel.clone();
        let Some(peer) = this.peers.get(id) else {
            if let Some(handle) = this.table.link_to(id) {
                release(&handle, false, "this device no longer uses this link (the host removed it)");
            }
            return;
        };
        let one_shot = !peer.persistent && peer.mode == LinkMode::Always;

        // Linked (dialled, or the other device dialled this one): keep it
        // while it is wanted.
        if let Some(handle) = this.table.link_to(id) {
            backoff.reset();
            let closed_here = this.keep(id, &ctl, &handle).await;
            // A relay that closed its link saying it shuts down is not
            // there to redial: it counts as failed now, so the next relay
            // stands in at once while this one is dialled again with
            // backoff.
            if !closed_here
                && peer.relay_use.is_some()
                && let LinkError::Refused { reason: Some(CloseReason::Shutdown), .. } = handle.closed().await
            {
                ctl.dialled(Some("it closed its link: it is shutting down".into()));
                this.reselect_relays();
            }
            drop(this);
            if cancel.is_cancelled() {
                return;
            }
            if !closed_here && !relink_once(&links, id) && one_shot {
                return;
            }
            if !closed_here {
                // Dropped: dial again after the first backoff (the other
                // device may be restarting).
                tokio::select! {
                    () = cancel.cancelled() => return,
                    () = tokio::time::sleep(backoff.after_drop()) => {}
                }
            }
            continue;
        }

        if !this.wants_link(id, &peer, &ctl) {
            drop(this);
            tokio::select! {
                () = cancel.cancelled() => return,
                () = ctl.changed() => {}
            }
            continue;
        }

        let attempt = this.dial_once(id, &peer).await;
        let wait = match attempt {
            Ok(_) => {
                ctl.dialled(None);
                continue;
            }
            Err(e) => {
                let refused = !e.is_transient();
                let wait = backoff.after_failure(refused);
                tracing::warn!(
                    target: "face.quic",
                    peer = %peer.label,
                    retry_in_secs = wait.as_secs_f32(),
                    "link to {} failed: {e}",
                    peer.label
                );
                ctl.dialled(Some(format!("its last dial failed: {e}; retried after {:.1} s", wait.as_secs_f32())));
                if peer.relay_use.is_some() {
                    this.reselect_relays();
                }
                // What waits for an on-demand link that cannot be made is
                // answered now rather than at its lifetime's end.
                if matches!(peer.mode, LinkMode::OnDemand { .. }) && ctl.demand() {
                    ctl.clear_demand();
                    this.waiting()
                        .drop_all(&WaitFor::Peer(id), ndn_packet::nack::NackReason::NoRoute)
                        .await;
                }
                if one_shot {
                    return;
                }
                wait
            }
        };
        drop(this);
        let until = tokio::time::Instant::now() + wait;
        loop {
            tokio::select! {
                () = cancel.cancelled() => return,
                () = tokio::time::sleep_until(until) => break,
                () = ctl.changed() => if ctl.take_kick() { break },
            }
        }
    }
}

/// Whether `peer` is to be dialled again once, its enrollment link having
/// been closed because this device enrolled.
fn relink_once(links: &Weak<Links>, id: PeerId) -> bool {
    links.upgrade().is_some_and(|l| l.table.take_relink(id))
}
