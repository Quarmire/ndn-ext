//! Introductions over links: a stranger's link that carries only an
//! introduction, and dialling a device by its key from a code's link hint
//! (`ndn-rs/docs/specs/ndn-link.md` §14, data-layer.md §19).
//!
//! An inviter's host names the prefixes its introductions travel under
//! ([`Links::set_introductions`]); a device it knows nothing of — no
//! certificate of a namespace it holds, no peer entry expecting its key — is
//! then admitted on an **introduction link** instead of being refused: a link
//! that carries Interests under those prefixes and their answers, nothing
//! else, rate-limited and held in the same slots as enrollment links.
//!
//! A joiner dials the inviter by the key and addresses its code carries
//! ([`Links::dial_by_key`]): every address is tried at once, the handshake
//! succeeds only with the device holding the key, and the first that does
//! becomes the link. Once the joiner's host holds the inviter's namespace the
//! link is made again, so the inviter admits it by its certificate (a full
//! link); until then it carries the introduction alone.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ndn_face_quic::{CloseReason, KeyFingerprint, LinkHandle};
use ndn_mgmt_wire::{LinkDetail, link_code as code};
use ndn_packet::Name;
use tokio::task::JoinSet;

use crate::admission::{Admitted, Enrollment, Refusal};
use crate::candidates::Candidate;
use crate::host::PathCandidate;
use crate::links::{Links, Origin, dial_loop};
use crate::peer::{PeerId, PeerSpec};
use crate::policy::CANDIDATES_MAX;

impl Links {
    /// This device takes introduction links from devices it does not know:
    /// links that carry Interests under `prefixes` and their answers, and
    /// nothing else (the names of the introductions it answers — for a data
    /// layer device `<device>/32=held` and `<device>/32=intro`). Empty
    /// stops taking them (links already up stay until they end).
    pub fn set_introductions(&self, prefixes: Vec<Name>) {
        *self.introductions.lock() = prefixes;
    }

    /// The fingerprint of the key this device links with now: what a link
    /// hint of this device names.
    pub fn key_fingerprint(&self) -> Option<KeyFingerprint> {
        self.my_fingerprint()
    }

    /// The candidate addresses of this device's listening link socket now,
    /// most promising first, at most [`CANDIDATES_MAX`]: the addresses a
    /// link hint offers. None when this device does not listen.
    pub fn hint_candidates(&self) -> Vec<Candidate> {
        match &self.socket {
            Some(socket) if socket.is_listening() => self.gather(socket),
            _ => Vec::new(),
        }
    }

    /// An introduction link for a device the decision `refusal` turned away,
    /// if this device takes them: only a device that dialled in (no peer
    /// entry expected it) whose key or certificates no namespace held here
    /// vouches for — a device the policy, a revocation or a role refused
    /// stays refused.
    pub(crate) fn introduction_link(
        &self,
        refusal: &Refusal,
        fingerprint: KeyFingerprint,
        origin: Origin,
    ) -> Option<Admitted> {
        if !matches!(origin, Origin::Accepted)
            || !matches!(
                refusal.reason,
                CloseReason::Unrecognized | CloseReason::NotServed
            )
        {
            return None;
        }
        let prefixes = self.introductions.lock().clone();
        if prefixes.is_empty() {
            return None;
        }
        Some(Admitted {
            fingerprint,
            identities: Vec::new(),
            peer: None,
            enrollment: Some(Enrollment::Introduction(prefixes)),
            quota: None,
            quotas: Vec::new(),
        })
    }

    /// Where to dial peer `id`: the host's paths, else the addresses it was
    /// dialled at from a link hint.
    pub(crate) fn path_candidates(&self, id: PeerId, peer: &PeerSpec) -> Vec<PathCandidate> {
        if let Some(addrs) = self.introduced.lock().get(&id) {
            return addrs.iter().copied().map(PathCandidate::Address).collect();
        }
        self.paths.candidates(id, peer)
    }

    /// Whether peer `id` has a path to dial.
    pub(crate) fn has_path(&self, id: PeerId, peer: &PeerSpec) -> bool {
        !self.path_candidates(id, peer).is_empty()
    }

    /// A trust context was adopted: a link to a device dialled by its key
    /// alone, whose namespace this device holds now, is made again so the
    /// device is identified in it.
    pub(crate) fn relink_identified(&self) {
        let keyring = self.trust.keyring();
        self.table.relink_identified(|peer| {
            self.peers
                .get(peer)
                .and_then(|p| p.device.clone())
                .is_some_and(|device| keyring.held_for(&device).is_some())
        });
    }

    /// Dial the device `device` by the key `key` at `addrs` (at most
    /// [`CANDIDATES_MAX`], in order of preference), all at once, within
    /// `within` for the handshakes. `Ok` once a link to the device holding
    /// `key` is up and routes `device`'s names; the link is then kept like a
    /// peer's that is not persistent: made again once when this device comes
    /// to hold `device`'s namespace, and not otherwise. An address whose
    /// device presents another key is no link; the error says which
    /// addresses failed and how.
    pub async fn dial_by_key(
        self: &Arc<Self>,
        key: KeyFingerprint,
        device: Name,
        addrs: Vec<SocketAddr>,
        within: Duration,
    ) -> Result<(), LinkDetail> {
        let mut addrs = addrs;
        addrs.truncate(CANDIDATES_MAX);
        if addrs.is_empty() {
            return Err(LinkDetail::new(
                code::DIAL_FAILED,
                format!("no address to dial {device} at: the hint names none this device can use"),
            ));
        }
        if self.my_fingerprint() == Some(key) {
            return Err(LinkDetail::new(
                code::DIAL_FAILED,
                format!("the key of {device} is this device's own: it dials itself by no hint"),
            ));
        }
        // Already linked to that key (an earlier dial, or the device dialled
        // this one): nothing to dial; a join asked again finds its path.
        if self.table.is_linked(&key) {
            return Ok(());
        }
        let id = self.peers.add(PeerSpec {
            label: device.to_string(),
            key: Some(key),
            device: Some(device.clone()),
            persistent: false,
            direct: false,
            ..PeerSpec::default()
        });
        self.introduced.lock().insert(id, addrs.clone());
        match self.dial_race(id, key, &addrs, within).await {
            Ok(_handle) => {
                let ctl = self.ctl(id);
                let weak = Arc::downgrade(self);
                tokio::spawn(async move {
                    dial_loop(weak.clone(), id, ctl).await;
                    if let Some(links) = weak.upgrade() {
                        links.forget_dialled(id);
                    }
                });
                Ok(())
            }
            Err(e) => {
                self.forget_dialled(id);
                Err(e)
            }
        }
    }

    /// Peer `id`, added by [`dial_by_key`](Self::dial_by_key), is over.
    fn forget_dialled(&self, id: PeerId) {
        self.introduced.lock().remove(&id);
        self.ctls.lock().remove(&id);
        self.peers.remove(id);
    }

    /// The handshakes to every address at once, the first to succeed
    /// established as peer `id`'s link; the others dropped.
    async fn dial_race(
        self: &Arc<Self>,
        id: PeerId,
        key: KeyFingerprint,
        addrs: &[SocketAddr],
        within: Duration,
    ) -> Result<LinkHandle, LinkDetail> {
        let mut failed: Vec<String> = Vec::new();
        let mut attempts = JoinSet::new();
        for &addr in addrs {
            match self.endpoint_for(addr) {
                Ok(socket) => {
                    attempts.spawn(async move {
                        (
                            addr,
                            socket
                                .connect(addr, Some(key))
                                .await
                                .map_err(|e| e.to_string()),
                        )
                    });
                }
                Err(e) => failed.push(format!("{addr}: no socket to dial from ({e})")),
            }
        }
        let handshake = async {
            while let Some(done) = attempts.join_next().await {
                match done {
                    Ok((_, Ok(hs))) => return Some(hs),
                    Ok((addr, Err(e))) => failed.push(format!("{addr}: {e}")),
                    Err(e) => failed.push(format!("a dial ended abnormally: {e}")),
                }
            }
            None
        };
        let outcome = tokio::time::timeout(within, handshake).await;
        attempts.abort_all();
        let hs = match outcome {
            Ok(Some(hs)) => hs,
            Ok(None) => {
                return Err(LinkDetail::new(
                    code::DIAL_FAILED,
                    format!(
                        "no address linked to the device with key {key}: {}",
                        failed.join("; ")
                    ),
                ));
            }
            Err(_) => {
                let answered = if failed.is_empty() {
                    String::new()
                } else {
                    format!(": {}; the others did not answer", failed.join("; "))
                };
                return Err(LinkDetail::new(
                    code::DIAL_FAILED,
                    format!(
                        "no address linked to the device with key {key} within {} s ({} tried){answered}",
                        within.as_secs_f32(),
                        addrs.len()
                    ),
                ));
            }
        };
        self.establish(hs, Origin::Dialed(id))
            .await
            .map_err(|e| e.detail)
    }
}
