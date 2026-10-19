//! Which relays this device uses: the ones its namespace advertises (in its
//! trust context), the ones the person at it added, or none — merged by
//! preference, the `count` most preferred reachable ones linked at once,
//! failing over to the next when one is lost and back when it returns.
//!
//! A relay is a peer with [`PeerSpec::relay_use`]. Its link routes this
//! device's namespace (the one its current certificate is in) at a cost by
//! rank — the most preferred relay 0, the next 1, … — so traffic takes the
//! most preferred linked relay and moves to the next when it is lost.
//! Choosing walks the relays by preference (of equal preference, a user's
//! before the namespace's): a relay is chosen when it is linked or its last
//! dial did not fail, until `count` are chosen; a more preferred relay
//! whose dial failed, or that closed its link saying it shuts down, is
//! dialled again with backoff while a less preferred one stands in, and
//! once it links again the stand-in is released
//! ([`CloseReason::Released`]). Relays beyond the chosen ones stand by,
//! undialled.

use std::sync::Arc;

use ndn_face_quic::{CloseReason, KeyFingerprint};
use ndn_packet::Name;

use crate::links::Links;
use crate::peer::{LinkMode, PeerId, PeerSpec, RelaySource, RelayUse};
use crate::status::{RelayState, RelayStatus};

/// How this device chooses its relays.
#[derive(Clone, Debug)]
pub struct RelayOptions {
    /// Relays linked at once.
    pub count: usize,
    /// Use the relays the namespaces this device is enrolled in advertise.
    pub use_namespace: bool,
    /// The mode of a namespace's relays.
    pub namespace_mode: LinkMode,
    /// Ask a namespace's relays to hold Interests while this device sleeps.
    pub namespace_hold: bool,
}

impl Default for RelayOptions {
    fn default() -> Self {
        Self {
            count: 1,
            use_namespace: true,
            namespace_mode: LinkMode::Always,
            namespace_hold: false,
        }
    }
}

/// The relays chosen now.
pub(crate) struct Choice {
    /// Linked, or to be linked.
    pub(crate) chosen: Vec<PeerId>,
    /// More preferred than a chosen one, but their last dial failed: dialled
    /// again with backoff.
    pub(crate) retrying: Vec<PeerId>,
}

impl Links {
    /// The relays, most preferred first.
    pub(crate) fn relay_order(&self) -> Vec<(PeerId, Arc<PeerSpec>)> {
        let mut relays: Vec<_> = self
            .peers
            .iter()
            .into_iter()
            .filter(|(_, p)| p.relay_use.is_some())
            .collect();
        relays.sort_by_key(|(id, p)| {
            let used = p.relay_use.as_ref().expect("filtered");
            (used.preference, matches!(used.source, RelaySource::Namespace(_)), *id)
        });
        relays
    }

    pub(crate) fn relay_choice(&self) -> Choice {
        let mut choice = Choice {
            chosen: Vec::new(),
            retrying: Vec::new(),
        };
        for (id, p) in self.relay_order() {
            if choice.chosen.len() >= self.relay_options.count {
                break;
            }
            let ctl = self.ctl(id);
            let linked = self.table.link_to(id).is_some();
            if p.mode == LinkMode::Off && !ctl.asked() && !linked {
                continue;
            }
            if linked || !ctl.failing() {
                choice.chosen.push(id);
            } else {
                choice.retrying.push(id);
            }
        }
        choice
    }

    /// Whether relay `id` is to be linked now (chosen, or retried).
    pub(crate) fn relay_wanted(&self, id: PeerId) -> bool {
        let choice = self.relay_choice();
        choice.chosen.contains(&id) || choice.retrying.contains(&id)
    }

    /// The route cost of relay `id`: its rank among the relays.
    pub(crate) fn relay_cost(&self, id: PeerId) -> u32 {
        self.relay_order()
            .iter()
            .position(|(r, _)| *r == id)
            .map_or(0, |rank| u32::try_from(rank).unwrap_or(u32::MAX))
    }

    /// Tell every relay's dial loop to look at the choice again.
    pub(crate) fn reselect_relays(&self) {
        for (id, _) in self.relay_order() {
            self.ctl(id).poke();
        }
    }

    /// The namespaces this device's traffic goes to its relays for: the
    /// namespace of the certificate it links with now.
    pub(crate) fn own_namespaces(&self) -> Vec<Name> {
        let Some(device) = self.own_device() else {
            return Vec::new();
        };
        let ctx = self.trust.keyring().context_for(&device);
        if ctx.namespace().is_empty() {
            return Vec::new();
        }
        vec![ctx.namespace().clone()]
    }

    /// Relay `id`'s place in the choice, for status.
    pub(crate) fn relay_status(&self, id: PeerId, peer: &PeerSpec) -> Option<RelayStatus> {
        let used = peer.relay_use.clone()?;
        let choice = self.relay_choice();
        let ctl = self.ctl(id);
        let (state, text) = if self.table.link_to(id).is_some() {
            (RelayState::Linked, format!("route cost {}", self.relay_cost(id)))
        } else if peer.mode == LinkMode::Off && !ctl.asked() {
            (RelayState::Off, "its mode is off; it links when asked".to_string())
        } else if choice.retrying.contains(&id) {
            let standing_in: Vec<String> = choice.chosen.iter().map(|c| self.peers.label(*c)).collect();
            let meanwhile = if standing_in.is_empty() {
                "no other relay stands in, so this device is reached through no relay meanwhile".to_string()
            } else {
                format!("{} stands in", standing_in.join(", "))
            };
            (
                RelayState::Down,
                format!(
                    "{}; dialled again with backoff; {meanwhile}",
                    ctl.last_error().unwrap_or_default()
                ),
            )
        } else if choice.chosen.contains(&id) {
            match peer.mode {
                LinkMode::OnDemand { .. } => (
                    RelayState::Trying,
                    "chosen; on demand, it links on traffic or when the host is active".to_string(),
                ),
                _ => (RelayState::Trying, "chosen; dialling".to_string()),
            }
        } else if ctl.failing() {
            (
                RelayState::Down,
                format!(
                    "{}; not needed while {} more preferred relay(s) are chosen",
                    ctl.last_error().unwrap_or_default(),
                    choice.chosen.len()
                ),
            )
        } else {
            (
                RelayState::Standby,
                format!(
                    "not needed: {} more preferred relay(s) are chosen (count = {})",
                    choice.chosen.len(),
                    self.relay_options.count
                ),
            )
        };
        Some(RelayStatus {
            source: used.source,
            preference: used.preference,
            state,
            text,
        })
    }

    /// Bring the relays the namespaces advertise up to date: add the ones
    /// newly advertised (unless the host removed them, or a peer of the
    /// host's names the same device or key), update the ones whose
    /// endpoints, key or preference changed, and remove the ones no longer
    /// advertised.
    pub(crate) fn sync_namespace_relays(self: &Arc<Self>) {
        let mine = self.my_fingerprint();
        let own_device = self.own_device();
        let mut advertised: Vec<PeerSpec> = Vec::new();
        if self.relay_options.use_namespace {
            let judge = self.judge();
            for ctx in self.trust.keyring().contexts() {
                let ns = ctx.namespace().clone();
                if ns.is_empty() || judge.own_role_in(&ns).is_none() {
                    continue;
                }
                for relay in ctx.relays() {
                    let key = relay.key.map(KeyFingerprint);
                    if own_device.as_ref() == Some(&relay.device) || (key.is_some() && key == mine) {
                        continue;
                    }
                    advertised.push(PeerSpec {
                        label: relay.device.to_string(),
                        key,
                        device: Some(relay.device.clone()),
                        endpoints: relay.endpoints.clone(),
                        mode: self.relay_options.namespace_mode,
                        hold: self.relay_options.namespace_hold,
                        relay_use: Some(RelayUse {
                            source: RelaySource::Namespace(ns.clone()),
                            preference: relay.preference,
                        }),
                        ..PeerSpec::default()
                    });
                }
            }
        }
        let same = |a: &PeerSpec, b: &PeerSpec| {
            (a.device.is_some() && a.device == b.device) || (a.key.is_some() && a.key == b.key)
        };
        let current = self.peers.iter();
        for (id, p) in &current {
            let Some(RelayUse {
                source: RelaySource::Namespace(ns),
                ..
            }) = &p.relay_use
            else {
                continue;
            };
            match advertised.iter().find(|a| same(a, p)) {
                None => {
                    tracing::info!(
                        target: "face.quic",
                        peer = %p.label,
                        "{ns} no longer advertises relay {}; this device stops using it",
                        p.label
                    );
                    self.drop_peer(*id, "the namespace no longer advertises this relay");
                }
                Some(a) if a.endpoints != p.endpoints || a.key != p.key || a.relay_use != p.relay_use => {
                    self.peers.update(*id, |spec| {
                        spec.endpoints = a.endpoints.clone();
                        spec.key = a.key;
                        spec.relay_use = a.relay_use.clone();
                    });
                    tracing::info!(
                        target: "face.quic",
                        peer = %p.label,
                        "{ns} changed its relay {} (endpoints {:?}, preference {})",
                        p.label,
                        a.endpoints,
                        a.relay_use.as_ref().map_or(0, |u| u.preference)
                    );
                    self.ctl(*id).kick();
                    self.reselect_relays();
                }
                Some(_) => {}
            }
        }
        for a in advertised {
            if current.iter().any(|(_, p)| same(p, &a)) || self.dismissed.lock().contains(&a.label) {
                continue;
            }
            let Some(RelaySource::Namespace(ns)) = a.relay_use.as_ref().map(|u| u.source.clone()) else {
                continue;
            };
            tracing::info!(
                target: "face.quic",
                peer = %a.label,
                "{ns} advertises relay {} (endpoints {:?}); this device uses it",
                a.label,
                a.endpoints
            );
            self.add_peer(a);
        }
    }

    /// Stop using peer `id` for `why`, as [`Links::remove_peer`] does,
    /// without marking it dismissed.
    pub(crate) fn drop_peer(&self, id: PeerId, why: &str) {
        if self.peers.remove(id).is_none() {
            return;
        }
        if let Some(handle) = self.table.link_to(id) {
            handle.close(CloseReason::Released, why);
        }
        self.unroute_demand(id);
        self.ctl(id).poke();
        self.reselect_relays();
    }
}
