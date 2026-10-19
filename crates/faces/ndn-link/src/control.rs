//! What the host asks of each link while links run: peers added and
//! removed, a link's mode, connect and disconnect, whether the host is
//! active, its wake token, a change of network — and the on-demand links'
//! side of the waiting face.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bytes::Bytes;
use parking_lot::Mutex;
use tokio::sync::Notify;

use ndn_face_quic::{CloseReason, Reachability};
use ndn_packet::Name;
use ndn_packet::nack::NackReason;

use crate::direct::direct_loop;
use crate::links::{Links, dial_loop};
use crate::peer::{LinkMode, PeerId, PeerSpec};
use crate::routes::predicted_routes;
use crate::waiting::{DEMAND_PER_PEER, DEMAND_TOTAL, Verdict, WaitFor};

/// One peer's controls, shared between the host's calls and its dial loop.
#[derive(Default)]
pub(crate) struct PeerCtl {
    /// Something changed that the dial loop looks at.
    changed: Notify,
    /// The host asked for the link ([`Links::connect`]).
    asked: AtomicBool,
    /// An Interest waits for the link.
    demand: AtomicBool,
    /// The last dial failed.
    failing: AtomicBool,
    /// Skip the rest of the current backoff: the host asked, or the network
    /// changed.
    kick: AtomicBool,
    last_error: Mutex<Option<String>>,
    wake_token: Mutex<Option<Bytes>>,
}

impl PeerCtl {
    pub(crate) fn poke(&self) {
        self.changed.notify_one();
    }

    /// Poke, and skip the rest of the current backoff.
    pub(crate) fn kick(&self) {
        self.kick.store(true, Ordering::SeqCst);
        self.changed.notify_one();
    }

    pub(crate) fn take_kick(&self) -> bool {
        self.kick.swap(false, Ordering::SeqCst)
    }

    pub(crate) async fn changed(&self) {
        self.changed.notified().await;
    }

    pub(crate) fn asked(&self) -> bool {
        self.asked.load(Ordering::SeqCst)
    }

    pub(crate) fn demand(&self) -> bool {
        self.demand.load(Ordering::SeqCst)
    }

    pub(crate) fn clear_demand(&self) {
        self.demand.store(false, Ordering::SeqCst);
    }

    pub(crate) fn failing(&self) -> bool {
        self.failing.load(Ordering::SeqCst)
    }

    pub(crate) fn last_error(&self) -> Option<String> {
        self.last_error.lock().clone()
    }

    /// Record a dial's outcome: `None` when it linked.
    pub(crate) fn dialled(&self, error: Option<String>) {
        self.failing.store(error.is_some(), Ordering::SeqCst);
        *self.last_error.lock() = error;
    }

    pub(crate) fn wake_token(&self) -> Option<Bytes> {
        self.wake_token.lock().clone()
    }
}

impl Links {
    pub(crate) fn ctl(&self, id: PeerId) -> Arc<PeerCtl> {
        Arc::clone(self.ctls.lock().entry(id).or_default())
    }

    /// Start keeping peer `id`: its dial loop when it has paths, its direct
    /// path loop when it is reached through a relay, and its waiting routes
    /// when it links on demand.
    pub(crate) fn run_peer(self: &Arc<Self>, id: PeerId, peer: &PeerSpec) {
        let ctl = self.ctl(id);
        if !self.paths.candidates(id, peer).is_empty() {
            tokio::spawn(dial_loop(Arc::downgrade(self), id, ctl));
        }
        if peer.relay.is_some() && peer.device.is_some() {
            tokio::spawn(direct_loop(Arc::downgrade(self), id));
        }
        self.route_demand(id);
    }

    /// Add a peer while links run, and start keeping it.
    pub fn add_peer(self: &Arc<Self>, spec: PeerSpec) -> PeerId {
        let id = self.peers.add(spec);
        if let Some(peer) = self.peers.get(id) {
            self.run_peer(id, &peer);
        }
        self.reselect_relays();
        id
    }

    /// Stop linking with peer `id`: its link is closed
    /// ([`CloseReason::Released`]) and its routes go with its face. A relay
    /// of the namespace removed this way is not used again while these
    /// links run (a newer version of the trust context does not bring it
    /// back).
    pub fn remove_peer(&self, id: PeerId) {
        if let Some(peer) = self.peers.get(id)
            && peer.relay_use.is_some()
        {
            self.dismissed.lock().insert(peer.label.clone());
        }
        self.drop_peer(id, "this device no longer uses this link (the host removed it)");
    }

    /// Change when peer `id`'s link is up.
    pub fn set_mode(&self, id: PeerId, mode: LinkMode) {
        if !self.peers.update(id, |p| p.mode = mode) {
            return;
        }
        self.route_demand(id);
        self.ctl(id).kick();
        self.reselect_relays();
    }

    /// The host asks for peer `id`'s link now (whatever its mode): it is
    /// dialled at once and kept until [`disconnect`](Self::disconnect).
    pub fn connect(&self, id: PeerId) {
        let ctl = self.ctl(id);
        ctl.asked.store(true, Ordering::SeqCst);
        ctl.failing.store(false, Ordering::SeqCst);
        ctl.kick();
        self.reselect_relays();
    }

    /// The host no longer asks for peer `id`'s link: an `off` link closes
    /// now, an on-demand one once idle; an `always` link stays (set its
    /// mode to `off` to close it).
    pub fn disconnect(&self, id: PeerId) {
        let ctl = self.ctl(id);
        ctl.asked.store(false, Ordering::SeqCst);
        ctl.poke();
        self.reselect_relays();
    }

    /// Whether the host is active (an app in the foreground): while it is,
    /// on-demand links are up; while it is not, each closes after its idle
    /// time without traffic.
    pub fn set_active(&self, active: bool) {
        let was = self.active.swap(active, Ordering::SeqCst);
        if was == active {
            return;
        }
        for (id, p) in self.peers.iter() {
            if matches!(p.mode, LinkMode::OnDemand { .. }) {
                if active {
                    self.ctl(id).kick();
                } else {
                    self.ctl(id).poke();
                }
            }
        }
    }

    pub(crate) fn is_active(&self) -> bool {
        self.active.load(Ordering::SeqCst)
    }

    /// Register (or clear) the wake token this device gives peer `id` (a
    /// relay): the relay invokes its wake notifier with it when an Interest
    /// arrives for this device while it is asleep there. Sent at once when
    /// linked, and on every new link.
    pub fn set_wake_token(&self, id: PeerId, token: Option<Bytes>) {
        *self.ctl(id).wake_token.lock() = token;
        if let (Some(peer), Some(handle)) = (self.peers.get(id), self.table.link_to(id)) {
            handle.send_reachability(&self.reachability_for(id, &peer));
        }
    }

    /// What this device asks peer `id` to do while it is asleep.
    pub(crate) fn reachability_for(&self, id: PeerId, peer: &PeerSpec) -> Reachability {
        Reachability {
            hold: peer.hold,
            wake_token: self.ctl(id).wake_token(),
        }
    }

    /// The network changed (Wi-Fi to cellular, a new address): move the
    /// host's link socket to `socket` when given (its links migrate), the
    /// dial-only sockets to new ones, dial again now, and punch again now:
    /// the devices whose punch waits out its backoff, and every device a
    /// direct path goes to (that path is closed; the new punch's takes its
    /// place).
    pub fn network_changed(self: &Arc<Self>, socket: Option<std::net::UdpSocket>) {
        if let (Some(socket), Some(endpoint)) = (socket, &self.socket)
            && let Err(e) = endpoint.rebind(socket)
        {
            tracing::warn!(target: "face.quic", "cannot move the link socket to the new network: {e}");
        }
        let dialers: Vec<_> = self.dialers.lock().iter().map(|(v4, e)| (*v4, Arc::clone(e))).collect();
        for (v4, endpoint) in dialers {
            let bind: std::net::SocketAddr = if v4 {
                std::net::SocketAddr::from(([0, 0, 0, 0], 0))
            } else {
                std::net::SocketAddr::from(([0u16; 8], 0))
            };
            match std::net::UdpSocket::bind(bind).and_then(|s| endpoint.rebind(s)) {
                Ok(()) => {}
                Err(e) => tracing::warn!(target: "face.quic", "cannot move a dial socket to the new network: {e}"),
            }
        }
        for (id, _) in self.peers.iter() {
            let ctl = self.ctl(id);
            ctl.failing.store(false, Ordering::SeqCst);
            ctl.kick();
        }
        self.direct.kick();
        self.punch_again_all();
        tracing::info!(target: "face.quic", "the network changed: links are dialled and punched again now");
    }

    /// Route what peer `id`'s link would carry to the waiting face while it
    /// links on demand; take those routes away otherwise.
    pub(crate) fn route_demand(&self, id: PeerId) {
        let Some(waiting) = self.waiting.get() else { return };
        let target = WaitFor::Peer(id);
        match self.peers.get(id) {
            Some(p) if matches!(p.mode, LinkMode::OnDemand { .. }) && !self.paths.candidates(id, &p).is_empty() => {
                let prefixes = predicted_routes(&p, &self.relay_namespaces(&p));
                waiting.route(self, target, prefixes);
            }
            _ => waiting.unroute(self, &target),
        }
    }

    pub(crate) fn unroute_demand(&self, id: PeerId) {
        if let Some(waiting) = self.waiting.get() {
            waiting.unroute(self, &WaitFor::Peer(id));
        }
    }

    /// What to do with an Interest that reached the waiting face for
    /// `target`.
    pub(crate) fn on_waiting(&self, target: &WaitFor, name: &Name) -> Verdict {
        match target {
            WaitFor::Asleep(fp) => self.asleep_interest(*fp, name),
            WaitFor::Peer(id) => {
                let Some(peer) = self.peers.get(*id) else {
                    return Verdict::Nack(NackReason::NoRoute, "its peer was removed".into());
                };
                if self.table.link_to(*id).is_some() {
                    // Up already: it goes out over the link below.
                    return Verdict::Hold {
                        per_target: DEMAND_PER_PEER,
                        total: DEMAND_TOTAL,
                        max_hold: None,
                    };
                }
                if !matches!(peer.mode, LinkMode::OnDemand { .. }) {
                    return Verdict::Drop;
                }
                if peer.relay_use.is_some() && !self.relay_wanted(*id) {
                    return Verdict::Nack(
                        NackReason::NoRoute,
                        format!("{} is not among the relays chosen now", peer.label),
                    );
                }
                let ctl = self.ctl(*id);
                if !ctl.demand.swap(true, Ordering::SeqCst) {
                    tracing::info!(
                        target: "face.quic",
                        peer = %peer.label,
                        "linking to {} on demand: an Interest for {name} waits for it",
                        peer.label
                    );
                }
                ctl.poke();
                Verdict::Hold {
                    per_target: DEMAND_PER_PEER,
                    total: DEMAND_TOTAL,
                    max_hold: None,
                }
            }
        }
    }

    /// If what `target` waits for is linked, send it its waiting Interests
    /// over the link.
    pub(crate) async fn flush_if_linked(&self, target: &WaitFor) {
        let Some(waiting) = self.waiting.get() else { return };
        let sender = match target {
            WaitFor::Peer(id) => self.table.peer_sender(*id).map(|(_, s)| s),
            WaitFor::Asleep(fp) => self.table.sender_to(fp),
        };
        let Some(sender) = sender else { return };
        let held = waiting.take(target);
        if held.is_empty() {
            return;
        }
        tracing::info!(
            target: "face.quic",
            face = sender.id().0,
            "sending {} Interest(s) that waited for this link",
            held.len()
        );
        for wire in held {
            if let Err(e) = sender.send_bytes(wire).await {
                tracing::info!(target: "face.quic", face = sender.id().0, "an Interest that waited was not sent: {e}");
                return;
            }
        }
    }

    /// Why peer `id` is not linked now, for status.
    pub(crate) fn why_down(&self, id: PeerId, peer: &PeerSpec) -> Option<String> {
        if self.table.link_to(id).is_some() {
            return None;
        }
        let ctl = self.ctl(id);
        if self.paths.candidates(id, peer).is_empty() {
            return Some("it links in to this device (no endpoint to dial)".into());
        }
        if peer.relay_use.is_some()
            && !self.relay_wanted(id)
            && !(peer.mode == LinkMode::Off && !ctl.asked())
        {
            return Some("a standby relay: not needed now".into());
        }
        let why = match peer.mode {
            LinkMode::Off if !ctl.asked() => "its mode is off: it links when asked".to_string(),
            LinkMode::OnDemand { idle } if !ctl.asked() && !self.is_active() && !ctl.demand() => format!(
                "on demand: closed (after {} s idle, or not needed yet); it links on traffic or when the host is active",
                idle.as_secs()
            ),
            _ => match ctl.last_error() {
                Some(e) => e,
                None => "dialling".to_string(),
            },
        };
        Some(why)
    }
}

/// How often a linked on-demand link checks whether it has been idle.
pub(crate) fn idle_check(idle: Duration) -> Duration {
    (idle / 4).clamp(Duration::from_millis(250), Duration::from_secs(30))
}

/// The close of a link this device no longer wants: to sleep, or released.
pub(crate) fn release(handle: &ndn_face_quic::LinkHandle, asleep: bool, text: &str) {
    let reason = if asleep { CloseReason::Asleep } else { CloseReason::Released };
    handle.close(reason, text);
}
