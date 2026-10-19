//! Interests that wait for a link: the library's waiting face.
//!
//! Two kinds of route lead to it, each at [`WAITING_COST`] so that a live
//! link's routes win:
//!
//! - on a device, the routes an **on-demand** link to a peer would get,
//!   while that link is down: an Interest arriving here makes the link dial
//!   and waits for it;
//! - on a relay, the routes a device **asleep** here had: its Interests are
//!   held for it (when it asked and this relay holds Interests) and its
//!   wake notifier is invoked (when it registered a wake token).
//!
//! When the link comes up, the Interests still within their lifetime are
//! sent over it directly (past the forwarder, whose pending entry for each
//! is still there); the Data the other device answers with comes back over
//! the link and satisfies that entry by name. An Interest that cannot wait
//! (the queue is full, or nothing will link) is Nacked at once, and the
//! reason is logged.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use bytes::Bytes;
use parking_lot::Mutex;

use ndn_face_local::{InProcFace, InProcHandle};
use ndn_face_quic::KeyFingerprint;
use ndn_packet::lp::{LpPacket, encode_lp_nack, is_lp_packet};
use ndn_packet::nack::NackReason;
use ndn_packet::{Interest, Name};
use ndn_transport::{Face, FaceId};

use crate::host::Route;
use crate::links::Links;
use crate::peer::PeerId;

/// Cost of a route to the waiting face: above any link's.
pub const WAITING_COST: u32 = 1000;
/// Interests that wait for one on-demand link at most…
pub const DEMAND_PER_PEER: usize = 64;
/// …and for all of them.
pub const DEMAND_TOTAL: usize = 1024;
/// An Interest without an InterestLifetime waits this long (its default
/// lifetime).
const DEFAULT_LIFETIME: Duration = Duration::from_secs(4);
/// Packets queued between the face and the forwarder.
const QUEUE: usize = 256;

/// What an Interest waits for.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum WaitFor {
    /// The on-demand link to a peer.
    Peer(PeerId),
    /// A device asleep at this relay, by its key.
    Asleep(KeyFingerprint),
}

/// An Interest that waits, as a bare Interest, until `until`.
struct Held {
    wire: Bytes,
    until: Instant,
}

pub(crate) struct Waiting {
    handle: InProcHandle,
    face: FaceId,
    routes: Mutex<Vec<(Name, WaitFor)>>,
    queues: Mutex<HashMap<WaitFor, VecDeque<Held>>>,
}

/// What a waiting Interest's owner decided.
pub(crate) enum Verdict {
    /// Queue it, within these bounds (per target, all targets of its kind).
    Hold {
        per_target: usize,
        total: usize,
        max_hold: Option<Duration>,
    },
    /// Answer it with a Nack now; the text is logged.
    Nack(NackReason, String),
    /// Drop it silently (another path carries it).
    Drop,
}

impl Waiting {
    /// The face, added to the host's forwarder; it lives until `links` is
    /// cancelled.
    pub(crate) fn start(links: &Arc<Links>) -> Arc<Self> {
        let faces = links.faces();
        let id = faces.alloc_face_id();
        let (face, handle) = InProcFace::new(id, QUEUE);
        let kind = ndn_transport::Transport::kind(&face);
        faces.add_face(
            Face::from_parts(
                Arc::new(face),
                ndn_transport::default_link_service_for_kind(kind),
            ),
            links.cancel_token().child_token(),
        );
        let waiting = Arc::new(Self {
            handle,
            face: id,
            routes: Mutex::new(Vec::new()),
            queues: Mutex::new(HashMap::new()),
        });
        tokio::spawn(receive(Arc::downgrade(links), Arc::clone(&waiting)));
        waiting
    }

    /// Route `prefixes` to this face for `target` (replacing its earlier
    /// routes).
    pub(crate) fn route(&self, links: &Links, target: WaitFor, prefixes: Vec<Name>) {
        let (stale, fresh) = {
            let mut routes = self.routes.lock();
            let stale: Vec<Name> = routes
                .iter()
                .filter(|(p, t)| *t == target && !prefixes.contains(p))
                .map(|(p, _)| p.clone())
                .collect();
            routes.retain(|(_, t)| *t != target);
            let fresh: Vec<Name> = prefixes
                .iter()
                .filter(|p| !routes.iter().any(|(q, _)| q == *p))
                .cloned()
                .collect();
            routes.extend(prefixes.into_iter().map(|p| (p, target.clone())));
            (stale, fresh)
        };
        let still_routed = |p: &Name| self.routes.lock().iter().any(|(q, _)| q == p);
        let stale: Vec<Name> = stale.into_iter().filter(|p| !still_routed(p)).collect();
        if !stale.is_empty() {
            links.faces().remove_routes(self.face, &stale);
        }
        if !fresh.is_empty() {
            let routes: Vec<Route> = fresh
                .into_iter()
                .map(|prefix| Route {
                    prefix,
                    cost: WAITING_COST,
                })
                .collect();
            links.faces().add_routes(self.face, &routes);
        }
    }

    /// Take `target`'s routes from this face; its waiting Interests stay
    /// until [`take`](Self::take) or [`drop_all`](Self::drop_all).
    pub(crate) fn unroute(&self, links: &Links, target: &WaitFor) {
        self.route(links, target.clone(), Vec::new());
    }

    /// The Interests waiting for `target` that are still within their
    /// lifetime, oldest first; the queue is emptied.
    pub(crate) fn take(&self, target: &WaitFor) -> Vec<Bytes> {
        let now = Instant::now();
        self.queues
            .lock()
            .remove(target)
            .map(|q| {
                q.into_iter()
                    .filter(|h| h.until > now)
                    .map(|h| h.wire)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Forget what waits for `target`, Nacking each Interest still within
    /// its lifetime with `reason`.
    pub(crate) async fn drop_all(&self, target: &WaitFor, reason: NackReason) {
        for wire in self.take(target) {
            let _ = self.handle.send(encode_lp_nack(reason, &wire)).await;
        }
    }

    /// Interests waiting for `target` now (within their lifetime).
    pub(crate) fn count(&self, target: &WaitFor) -> usize {
        let now = Instant::now();
        self.queues
            .lock()
            .get(target)
            .map_or(0, |q| q.iter().filter(|h| h.until > now).count())
    }

    /// Interests waiting for every target of `kind` (asleep, or demand)
    /// now.
    pub(crate) fn total(&self, asleep: bool) -> usize {
        let now = Instant::now();
        self.queues
            .lock()
            .iter()
            .filter(|(t, _)| matches!(t, WaitFor::Asleep(_)) == asleep)
            .map(|(_, q)| q.iter().filter(|h| h.until > now).count())
            .sum()
    }

    /// The target whose route covers `name` the longest.
    fn target_of(&self, name: &Name) -> Option<WaitFor> {
        self.routes
            .lock()
            .iter()
            .filter(|(p, _)| name.has_prefix(p))
            .max_by_key(|(p, _)| p.len())
            .map(|(_, t)| t.clone())
    }

    /// Queue `wire` for `target` within `verdict`'s bounds; the Nack reason
    /// and why when it does not fit.
    fn hold(
        &self,
        target: &WaitFor,
        wire: Bytes,
        lifetime: Duration,
        per_target: usize,
        total: usize,
        max_hold: Option<Duration>,
    ) -> Result<(), String> {
        let now = Instant::now();
        let asleep = matches!(target, WaitFor::Asleep(_));
        let mut queues = self.queues.lock();
        for q in queues.values_mut() {
            q.retain(|h| h.until > now);
        }
        queues.retain(|_, q| !q.is_empty());
        let held: usize = queues
            .iter()
            .filter(|(t, _)| matches!(t, WaitFor::Asleep(_)) == asleep)
            .map(|(_, q)| q.len())
            .sum();
        if held >= total {
            return Err(format!(
                "{held} Interests wait here already (at most {total})"
            ));
        }
        let queue = queues.entry(target.clone()).or_default();
        if queue.len() >= per_target {
            return Err(format!(
                "{} Interests wait for it already (at most {per_target})",
                queue.len()
            ));
        }
        let wait = max_hold.map_or(lifetime, |max| lifetime.min(max));
        queue.push_back(Held {
            wire,
            until: now + wait,
        });
        Ok(())
    }
}

/// Take what the forwarder hands the face: Interests that wait.
async fn receive(links: Weak<Links>, waiting: Arc<Waiting>) {
    while let Some(wire) = waiting.handle.recv().await {
        let (wire, nacked) = if is_lp_packet(&wire) {
            match LpPacket::decode(wire) {
                Ok(LpPacket {
                    fragment: Some(fragment),
                    nack,
                    ..
                }) => (fragment, nack.is_some()),
                _ => continue,
            }
        } else {
            (wire, false)
        };
        if nacked || wire.first() != Some(&0x05) {
            continue;
        }
        let Ok(interest) = Interest::decode(wire.clone()) else {
            continue;
        };
        let Some(target) = waiting.target_of(&interest.name) else {
            continue;
        };
        let Some(links) = links.upgrade() else { return };
        let lifetime = interest.lifetime().unwrap_or(DEFAULT_LIFETIME);
        let verdict = links.on_waiting(&target, &interest.name);
        let refusal = match verdict {
            Verdict::Hold {
                per_target,
                total,
                max_hold,
            } => match waiting.hold(&target, wire.clone(), lifetime, per_target, total, max_hold) {
                Ok(()) => {
                    // The link may have come up while this Interest was on
                    // its way here.
                    links.flush_if_linked(&target).await;
                    None
                }
                Err(why) => Some((NackReason::Congestion, why)),
            },
            Verdict::Nack(reason, why) => Some((reason, why)),
            Verdict::Drop => None,
        };
        if let Some((reason, why)) = refusal {
            tracing::info!(
                target: "face.quic",
                name = %interest.name,
                "an Interest waiting for a link is answered with a Nack ({reason:?}): {why}"
            );
            let _ = waiting.handle.send(encode_lp_nack(reason, &wire)).await;
        }
    }
}
