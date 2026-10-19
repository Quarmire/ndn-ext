//! Presence: which devices of a namespace are linked to a common relay, so
//! that members meet there and make direct paths by membership, with no
//! peer entry for each other.
//!
//! A relay that holds a namespace's trust context tells each device of that
//! namespace linked to it over a full link which other devices of the
//! namespace are linked to it now — only those the namespace's direct-path
//! role matrix ([`LinkPolicy::allows_direct_path`]) pairs with the
//! receiver's role — in a `Presence` message on the link's control stream,
//! at once and whenever the list changes. The control stream is the link's:
//! both keys were proven in its handshake and certified in the namespace at
//! admission, so a presence list is as authentic as a signed record would be,
//! reaches only devices the relay admitted as members, and costs no
//! signature or polling. A presence entry is a device name and its key
//! fingerprint, never an address: addresses travel only in the signed punch
//! messages, to a device whose punch the other admitted under the same
//! role matrix. A relay that does not hold the namespace's trust context
//! (it serves the namespace by its root fingerprint, or is open) sends no
//! presence for it: it could not apply the namespace's policy.
//!
//! A device takes presence from the relays it uses. For each device listed
//! whose key fingerprint is larger than its own (one side punches; the
//! other answers), that the role matrix pairs with it, and that no peer
//! entry of its names, it punches a direct path through that relay, within
//! [`DirectOptions::max_paths`].
//!
//! [`LinkPolicy::allows_direct_path`]: ndn_security::LinkPolicy::allows_direct_path

use std::sync::Arc;

use ndn_face_quic::{KeyFingerprint, LinkHandle, Presence, PresentDevice};
use ndn_packet::Name;
use tokio_util::sync::CancellationToken;

use crate::direct::{Target, Whom, member_loop};
use crate::host::Route;
use crate::links::Links;
use crate::peer::PeerId;
use crate::policy::VIA_RELAY_COST;

/// Devices a presence message lists at most.
pub const PRESENCE_MAX: usize = 256;

/// Direct paths this device makes by membership.
#[derive(Clone, Copy, Debug)]
pub struct DirectOptions {
    /// Punch direct paths to the devices of its namespace its relays list
    /// (as the namespace's role matrix allows); `false`: only to peer
    /// entries.
    pub membership: bool,
    /// Direct paths up at once, at most (this device's punches and the
    /// ones it answers).
    pub max_paths: usize,
}

impl Default for DirectOptions {
    fn default() -> Self {
        Self {
            membership: true,
            max_paths: 8,
        }
    }
}

/// A member this device punches by presence.
pub(crate) struct MemberEntry {
    relay: PeerId,
    device: Name,
    cancel: CancellationToken,
}

impl Links {
    /// Tell each device of `namespace` linked here which others are (as
    /// its role pairs it).
    pub(crate) fn announce_presence(&self, namespace: &Name) {
        let Some(ctx) = self
            .trust
            .keyring()
            .contexts()
            .into_iter()
            .find(|c| c.namespace() == namespace)
        else {
            return;
        };
        let policy = ctx.link_policy();
        let members: Vec<_> = self
            .table
            .members(namespace)
            .into_iter()
            .filter(|m| m.identity.served.is_none())
            .collect();
        for to in &members {
            let devices: Vec<PresentDevice> = members
                .iter()
                .filter(|o| o.fingerprint != to.fingerprint)
                .filter(|o| policy.allows_direct_path(to.identity.role.as_str(), o.identity.role.as_str()))
                .take(PRESENCE_MAX)
                .map(|o| PresentDevice {
                    device: o.identity.device.clone(),
                    key: o.fingerprint,
                })
                .collect();
            to.handle.send_presence(&Presence {
                namespace: namespace.clone(),
                devices,
            });
        }
    }

    /// Announce presence for every namespace held (a new version may
    /// change the role matrix).
    pub(crate) fn announce_all(&self) {
        for ctx in self.trust.keyring().contexts() {
            if !ctx.namespace().is_empty() {
                self.announce_presence(ctx.namespace());
            }
        }
    }

    /// Follow the presence relay `relay` sends on its link `handle` until
    /// the link ends.
    pub(crate) fn follow_presence(self: &Arc<Self>, relay: PeerId, handle: LinkHandle) {
        let weak = Arc::downgrade(self);
        let cancel = self.cancel.clone();
        tokio::spawn(async move {
            let mut rx = handle.presence();
            loop {
                let list = rx.borrow_and_update().clone();
                if let Some(links) = weak.upgrade() {
                    links.take_presence(relay, &list);
                }
                tokio::select! {
                    () = cancel.cancelled() => return,
                    _ = handle.closed() => break,
                    changed = rx.changed() => if changed.is_err() { break },
                }
            }
            if let Some(links) = weak.upgrade() {
                links.take_presence(relay, &[]);
            }
        });
    }

    /// Relay `relay` lists `list` now: punch the members it newly lists,
    /// stop punching the ones it no longer does.
    fn take_presence(self: &Arc<Self>, relay: PeerId, list: &[Presence]) {
        let mine = self.my_fingerprint();
        let own_device = self.own_device();
        let judge = self.judge();
        let mut wanted: Vec<(KeyFingerprint, Name)> = Vec::new();
        if self.direct_options.membership
            && let Some(mine) = mine
        {
            for p in list {
                if judge.own_role_in(&p.namespace).is_none() {
                    continue;
                }
                for d in &p.devices {
                    if d.key == mine
                        || own_device.as_ref() == Some(&d.device)
                        || mine > d.key
                        || !d.device.has_prefix(&p.namespace)
                        || self.peers.find(d.key, Some(&d.device)).is_some()
                        || self.pair_off(&d.device).is_some()
                    {
                        continue;
                    }
                    wanted.push((d.key, d.device.clone()));
                }
            }
        }
        let relay_face = self.table.link_face(relay);
        let mut members = self.members.lock();
        let gone: Vec<KeyFingerprint> = members
            .iter()
            .filter(|(fp, m)| m.relay == relay && !wanted.iter().any(|(w, _)| w == *fp))
            .map(|(fp, _)| *fp)
            .collect();
        for fp in gone {
            if let Some(m) = members.remove(&fp) {
                m.cancel.cancel();
                if let Some(face) = relay_face {
                    self.faces().remove_routes(face, std::slice::from_ref(&m.device));
                }
                tracing::info!(
                    target: "face.quic",
                    peer = %m.device,
                    "{} is no longer linked to {}; no more punches to it by membership",
                    m.device,
                    self.peers.label(relay)
                );
            }
        }
        for (fp, device) in wanted {
            if members.contains_key(&fp) {
                continue;
            }
            let cancel = self.cancel.child_token();
            if let Some(face) = relay_face {
                self.faces().add_routes(
                    face,
                    &[Route {
                        prefix: device.clone(),
                        cost: VIA_RELAY_COST,
                    }],
                );
            }
            tracing::info!(
                target: "face.quic",
                peer = %device,
                "{device} of this device's namespace is linked to {} too: punching a direct path by membership",
                self.peers.label(relay)
            );
            let target = Target {
                whom: Whom::Key(fp),
                label: device.to_string(),
                device: device.clone(),
                key: Some(fp),
                peer: None,
            };
            tokio::spawn(member_loop(Arc::downgrade(self), target, relay, cancel.clone()));
            members.insert(fp, MemberEntry { relay, device, cancel });
        }
    }
}
