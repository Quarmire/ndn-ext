//! Introductions over links: a stranger's link that carries only an
//! introduction, and dialling a device by its key from a code's link hint
//! (`ndn-rs/docs/specs/ndn-link.md` §14, invite.md).
//!
//! An inviter's host gives its links what its introductions serve
//! ([`Links::set_introductions`], an [`Introductions`]); a device it knows
//! nothing of — no certificate of a namespace it holds, no peer entry
//! expecting its key — is then admitted on an **introduction link** instead
//! of being refused, but only while an offer is open: a link that carries
//! the Interests of the one exchange (the offer's record and the ask) and
//! their answers, nothing else, rate-limited and held in the same slots as
//! enrollment links.
//!
//! A joiner dials the inviter by the key and addresses its code carries
//! ([`Links::dial_by_key`]): every address is tried at once, the handshake
//! succeeds only with the device holding the key, and the first that does
//! becomes the link. Until the joiner's host holds the inviter's namespace
//! the link carries only the routes it was dialled for (an introduction's
//! prefixes), never the names the code claims for the device; once it does
//! the link is made again, so the inviter admits it by its certificate (a
//! full link) and it gets the routes of the identity it proved.
//!
//! A short code carries no key: its first contact is one address, dialled by
//! [`Links::dial_first`] with no key to expect. Whoever answers there is
//! linked by the key it proves, on the same terms (only the routes it was
//! dialled for, until it shows a certificate this device holds), but is sent
//! an empty hello: no certificate and no membership. The key is returned for
//! the join to name the link by.
//!
//! What a link dialled from a code carries while its party has shown no
//! certificate is bounded in both directions ([`Links::dial_by_key`],
//! `dial_first`): answers under the routes it was dialled for and Interests
//! only for this device's own names come in, nothing else. A party that still
//! shows no certificate once this device holds the namespace of the device
//! the code claimed is refused, not admitted again.

use std::fmt;
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

/// What a device's introductions serve over a link a stranger dialled
/// (ndn-link §8.6): the host gives it to [`Links::set_introductions`]. For a
/// device with `ndn-invite` it is `ndn_invite::Surface`.
pub trait Introductions: Send + Sync {
    /// Whether an offer is open: a stranger's introduction link is worth
    /// taking now. With none, a stranger is refused as any other.
    fn open(&self) -> bool;

    /// Whether an Interest for `name` may cross an introduction link: the
    /// names of the one exchange an open offer needs, no other name the
    /// device serves.
    fn carries(&self, name: &Name) -> bool;

    /// Whether a packet named `name` may cross the link of a person a grant
    /// admitted to `folder` ([`Grant::folder`](crate::Grant::folder)): the
    /// names of the folder's collections, as the layer above names them, and
    /// the few of its own that reach them, among them the roots of the other
    /// writers the folder's members record lists. It is asked **at every
    /// packet** and answers from the record in force then: a writer the
    /// record dropped is not carried from the next packet. The link layer
    /// adds the person's own devices, the namespaces' certificates and sync
    /// groups, and this surface's [`carries`](Introductions::carries); it
    /// carries no other name this device serves, so an unsealed collection
    /// outside the folder is not answered over a grant link. For a
    /// device with `ndn-invite` it is `Surface::grant_carries`.
    fn grant_carries(&self, folder: &Name, name: &Name) -> bool;

    /// Whether a packet named `name` may cross the departure link of a
    /// person let go by the members record whose log entry is `record`
    /// (ndn-link §8.8): the entry, its pieces and its cut manifests and
    /// nothing else. For a device with `ndn-invite` it is
    /// `Surface::departure_carries`.
    fn departure_carries(&self, record: &Name, name: &Name) -> bool;

    /// The namespaces of the other writers the members record in force for
    /// `folder` lists (the folder's own excluded): whose sync groups a grant
    /// link to a person admitted to `folder` routes (§8.7), so the person's
    /// device hears them through this one, and whose public names the link
    /// carries (§8.7), as the folder's own namespace's does. Read live, at
    /// every look. A device with no data layer lists none. For a device with
    /// `ndn-invite` it is `Surface::writer_namespaces`.
    fn writer_namespaces(&self, folder: &Name) -> Vec<Name> {
        let _ = folder;
        Vec::new()
    }

    /// The sync group the data layer gives the space `folder` (the name its
    /// nodes announce and hear that space's notices under): a grant link to a
    /// person admitted to `folder` routes exactly this group over the link and
    /// carries exactly the names under it ([`Grant::folder`](crate::Grant::folder)),
    /// not the owner's other groups. `None` for a name that is no space of the
    /// data layer, and for a device with no data layer (the default): then no
    /// group of the folder is routed or carried beyond the namespaces' own.
    /// For a device with `ndn-invite` it is the group of `ndn-heap`
    /// (`ndn_heap::wire::sync_group_of`).
    fn sync_group(&self, folder: &Name) -> Option<Name> {
        let _ = folder;
        None
    }
}

/// What the introduction links of [`Enrollment::Introduction`] carry.
#[derive(Clone)]
pub(crate) struct Surface(pub(crate) Arc<dyn Introductions>);

impl fmt::Debug for Surface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("introductions")
    }
}

impl PartialEq for Surface {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for Surface {}

impl Links {
    /// This device takes introduction links from devices it does not know,
    /// while `surface` says an offer is open ([`Introductions::open`]): links
    /// that carry the Interests `surface` carries
    /// ([`Introductions::carries`]) and their answers, nothing else. Once no
    /// offer is open a stranger is refused as any other, with no timer of
    /// this device's; links already up stay until they end. Call it once, on
    /// the device that makes offers.
    pub fn set_introductions(&self, surface: Arc<dyn Introductions>) {
        *self.introductions.lock() = Some(surface);
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
        let surface = self.introductions.lock().clone()?;
        if !surface.open() {
            return None;
        }
        Some(Admitted {
            fingerprint,
            identities: Vec::new(),
            peer: None,
            enrollment: Some(Enrollment::Introduction(Surface(surface))),
            quota: None,
            quotas: Vec::new(),
            grant: None,
            follows: Vec::new(),
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

    /// Whether the link just admitted frames NDNLPv2 reliability
    /// ([`LinkReliability`](crate::LinkReliability)): when its peer entry
    /// asks for it, or when the option of the kind that made it is on. A
    /// grant link is the grant's kind, an introduction link a stranger
    /// dialled the introduction kind, and a link this device dialled is the
    /// kind of the entry it was dialled as: a first contact, a remembered
    /// peer, or a dial by key.
    pub(crate) fn reliable(&self, admitted: &Admitted, peer: Option<&PeerSpec>) -> bool {
        let kinds = &self.reliability;
        if peer.is_some_and(|p| p.reliability) {
            return true;
        }
        if kinds.granted && admitted.grant.is_some() {
            return true;
        }
        if kinds.introduced
            && matches!(
                admitted.enrollment,
                Some(Enrollment::Introduction(_) | Enrollment::Relay(_, Some(_)))
            )
        {
            return true;
        }
        let Some((id, peer)) = admitted.peer.zip(peer) else {
            return false;
        };
        // A first contact is its own kind until the link is made again (then it is
        // the dial by key it became).
        if self.first_contacts.lock().contains(&id) {
            return kinds.first_contact;
        }
        (kinds.remembered && peer.remembered)
            || (kinds.introduced && !peer.remembered && self.introduced.lock().contains_key(&id))
    }

    /// A trust context was adopted: a link to a device dialled by its key
    /// alone, whose namespace this device holds now, is made again so the
    /// device is identified in it (and gets the routes of its identity). The
    /// link made again of a first contact sends this device's full hello:
    /// the party it reaches was judged by the join (its key is the hint
    /// record's), and the hello is what lets it identify this device.
    pub(crate) fn relink_identified(&self) {
        let keyring = self.trust.keyring();
        self.table.relink_identified(
            |peer| {
                let held = self
                    .peers
                    .get(peer)
                    .and_then(|p| p.device.clone())
                    .is_some_and(|device| keyring.held_for(&device).is_some());
                // Before the link closes, so the dial that follows sends it.
                if held {
                    self.first_contacts.lock().remove(&peer);
                    self.relinked.lock().insert(peer);
                }
                held
            },
            |peer| self.introduced.lock().contains_key(&peer),
        );
    }

    /// Dial the device `device` by the key `key` at `addrs` (at most
    /// [`CANDIDATES_MAX`], in order of preference), all at once, within
    /// `within` for the handshakes. `Ok` once a link to the device holding
    /// `key` is up; the link is then kept like a peer's that is not
    /// persistent: made again once when this device comes to hold
    /// `device`'s namespace, and not otherwise. An address whose device
    /// presents another key is no link; the error says which addresses
    /// failed and how.
    ///
    /// `device` is only what a code claimed: the device at that key has
    /// shown no certificate. Until it does (the link made again after this
    /// device holds its namespace) the link routes `routes` — for an
    /// introduction, its introduction prefixes — and not `device`'s names,
    /// so a code naming a device of a namespace this device already
    /// holds does not steer that namespace's Interests to whoever holds the
    /// key.
    pub async fn dial_by_key(
        self: &Arc<Self>,
        key: KeyFingerprint,
        device: Name,
        addrs: Vec<SocketAddr>,
        within: Duration,
        routes: Vec<Name>,
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
            unidentified_routes: Some(routes),
            ..PeerSpec::default()
        });
        self.introduced.lock().insert(id, addrs.clone());
        match self.dial_race(id, key, &addrs, within).await {
            Ok(_handle) => {
                self.keep_dialled(id);
                Ok(())
            }
            Err(e) => {
                self.watch_failed(id, Some(key), &e, crate::watch::Next::Gone);
                self.forget_dialled(id);
                Err(e)
            }
        }
    }

    /// Dial the device `device` at the one address `addr` with **no key to
    /// expect**, within `within` for the handshake: the key is not in the
    /// code, the hint record fetched over this link names it. `Ok(key)` once
    /// a link to whoever answers is up, `key` being the fingerprint of the
    /// key its handshake proved. The link is kept as
    /// [`dial_by_key`](Self::dial_by_key) keeps its own: not persistent,
    /// made again once when this device comes to hold `device`'s namespace
    /// (and the key then shows a certificate there), not otherwise, and
    /// taken down by [`undial_by_key`](Self::undial_by_key) with the key
    /// returned.
    ///
    /// `addr` is only where to try, and whoever answers there is a stranger:
    /// the key it proved is no more than a name for its link. Until it
    /// shows a certificate this device holds the link routes `routes` — for
    /// an introduction, its introduction prefixes — and nothing else, not
    /// the names the code claims for `device`, whatever key answered, and
    /// sends this device's Interests under `routes` only. **The hello is
    /// empty**: no certificate and no membership is shown to a party nothing
    /// vouches for; the full hello goes on the link made again once this
    /// device holds `device`'s namespace. The dial is judged as
    /// `dial_by_key`'s is once the key is proved: the peer is added with that
    /// key, so the party is admitted as a stranger or refused as it would be
    /// had the code named its key, and a failure leaves no peer, route or
    /// link behind.
    ///
    /// One address only, so no race: [`CANDIDATES_MAX`] bounds a hint's
    /// addresses and a short code's first contact is one. A key this device
    /// already links with is returned, no second link made; this device's
    /// own key is refused.
    pub async fn dial_first(
        self: &Arc<Self>,
        device: Name,
        addr: SocketAddr,
        within: Duration,
        routes: Vec<Name>,
    ) -> Result<KeyFingerprint, LinkDetail> {
        if !self.is_online() {
            return Err(crate::online::offline_detail());
        }
        let socket = self.endpoint_for(addr).map_err(|e| {
            LinkDetail::new(
                code::DIAL_FAILED,
                format!("{addr}: no socket to dial the first contact of {device} from ({e})"),
            )
        })?;
        let hs = match tokio::time::timeout(within, socket.connect(addr, None)).await {
            Ok(Ok(hs)) => hs,
            Ok(Err(e)) => {
                return Err(LinkDetail::new(
                    code::DIAL_FAILED,
                    format!("the first contact {addr} of {device} did not link: {e}"),
                ));
            }
            Err(_) => {
                return Err(LinkDetail::new(
                    code::DIAL_FAILED,
                    format!(
                        "the first contact {addr} of {device} did not answer within {} s",
                        within.as_secs_f32()
                    ),
                ));
            }
        };
        let key = hs.peer_key().fingerprint();
        if self.my_fingerprint() == Some(key) {
            let text = format!(
                "the first contact {addr} of {device} answered with this device's own key: \
                 a device dials itself by no code"
            );
            hs.refuse(CloseReason::NotTheExpectedDevice, &text);
            return Err(LinkDetail::new(code::DIAL_FAILED, text));
        }
        // Already linked to that key: this connection is the second of a
        // pair, and the first stays.
        if self.table.is_linked(&key) {
            hs.refuse(
                CloseReason::Replaced,
                "a link between these two devices already exists",
            );
            return Ok(key);
        }
        let id = self.peers.add(PeerSpec {
            label: device.to_string(),
            key: Some(key),
            device: Some(device),
            persistent: false,
            direct: false,
            unidentified_routes: Some(routes),
            ..PeerSpec::default()
        });
        self.introduced.lock().insert(id, vec![addr]);
        self.first_contacts.lock().insert(id);
        match self.establish(hs, Origin::Dialed(id)).await {
            Ok(_handle) => {
                self.keep_dialled(id);
                Ok(key)
            }
            Err(e) => {
                self.watch_failed(id, Some(key), &e.detail, crate::watch::Next::Gone);
                self.forget_dialled(id);
                Err(e.detail)
            }
        }
    }

    /// Peer `id`, added by a dial by key, has its link: keep it as a peer
    /// that is not persistent, dialled again by its key at the address it
    /// was dialled at while the link drops, until that ends.
    fn keep_dialled(self: &Arc<Self>, id: PeerId) {
        let ctl = self.ctl(id);
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            dial_loop(weak.clone(), id, ctl).await;
            if let Some(links) = weak.upgrade() {
                links.forget_dialled(id);
            }
        });
    }

    /// Peer `id`, added by [`dial_by_key`](Self::dial_by_key), is over.
    pub(crate) fn forget_dialled(&self, id: PeerId) {
        self.introduced.lock().remove(&id);
        self.first_contacts.lock().remove(&id);
        self.relinked.lock().remove(&id);
        self.ctls.lock().remove(&id);
        self.peers.remove(id);
        self.watch_forget(id);
    }

    /// Take down the link [`dial_by_key`](Self::dial_by_key) made to the
    /// device with key `key`, for `why`, if it is still what that dial made:
    /// a peer the dial added whose link has shown no certificate this device
    /// holds (whatever enrollment the party told this device it is on: that
    /// is the party's word). A link that was up before the dial, or that has
    /// been identified since (the join went on and this device holds the
    /// device's namespace), is kept. The join that dialled it failed, or its
    /// record named another key, so what answered at that key proved nothing
    /// and keeps no route.
    pub fn undial_by_key(&self, key: KeyFingerprint, why: &str) {
        let ids: Vec<PeerId> = self.introduced.lock().keys().copied().collect();
        for id in ids {
            if self.peers.get(id).and_then(|p| p.key) != Some(key) {
                continue;
            }
            if self.table.is_identified(&key) {
                continue;
            }
            self.drop_peer(id, why);
            self.forget_dialled(id);
        }
    }

    /// The handshakes to every address at once, the first to succeed
    /// established as peer `id`'s link; the others dropped.
    pub(crate) async fn dial_race(
        self: &Arc<Self>,
        id: PeerId,
        key: KeyFingerprint,
        addrs: &[SocketAddr],
        within: Duration,
    ) -> Result<LinkHandle, LinkDetail> {
        if !self.is_online() {
            return Err(crate::online::offline_detail());
        }
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

#[cfg(test)]
mod tests {
    //! [`Links::dial_first`] on real QUIC between two [`Links`] over loopback:
    //! the party at an address is linked by whatever key its handshake
    //! proves, and the link routes only what it was dialled for.

    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Instant;

    use bytes::Bytes;
    use ndn_face_quic::{LinkEndpoint, LinkKey, LinkKeySource, LinkTransportConfig};
    use ndn_security::{Certificate, Ed25519Signer, Keyring};
    use ndn_transport::{Face, FaceId, FaceKind};
    use parking_lot::Mutex;
    use tokio_util::sync::CancellationToken;

    use super::*;
    use crate::{ConfiguredEndpoints, FaceSink, LinkSetup, LinkTrust, RelayService, Route};

    fn key(seed: u8) -> LinkKey {
        LinkKey::from_signer(Arc::new(Ed25519Signer::from_seed(
            &[seed; 32],
            format!("/ns/member/d{seed}/KEY/k").parse().unwrap(),
        )))
        .unwrap()
    }

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    /// No namespace held and no certificate: the devices are strangers.
    struct NoTrust(Arc<Keyring>);

    impl LinkTrust for NoTrust {
        fn keyring(&self) -> &Arc<Keyring> {
            &self.0
        }
        fn own_chain(&self) -> Vec<Bytes> {
            Vec::new()
        }
        fn known_certificate(&self, _: &Name) -> Option<Certificate> {
            None
        }
        fn known_certificate_of_key(&self, _: &KeyFingerprint) -> Option<Certificate> {
            None
        }
    }

    /// A listener's introductions: an offer open or not, and no name carried
    /// (these cases look at the dialler's side).
    struct Offers(bool);

    impl Introductions for Offers {
        fn open(&self) -> bool {
            self.0
        }
        fn carries(&self, _: &Name) -> bool {
            false
        }
        fn grant_carries(&self, _: &Name, _: &Name) -> bool {
            false
        }
        fn departure_carries(&self, _: &Name, _: &Name) -> bool {
            false
        }
    }

    /// The forwarder's side, remembering the link faces and the routes the
    /// links gave them.
    #[derive(Default)]
    struct Faces {
        next: AtomicU64,
        live: Mutex<Vec<FaceId>>,
        routes: Mutex<Vec<(FaceId, Route)>>,
    }

    impl Faces {
        /// The prefixes routed over link faces now, sorted.
        fn prefixes(&self) -> Vec<Name> {
            let mut out: Vec<Name> = self
                .routes
                .lock()
                .iter()
                .map(|(_, r)| r.prefix.clone())
                .collect();
            out.sort();
            out
        }
    }

    impl FaceSink for Faces {
        fn alloc_face_id(&self) -> FaceId {
            FaceId(self.next.fetch_add(1, Ordering::SeqCst) + 1)
        }
        fn add_face(&self, face: Face, _: CancellationToken) {
            if face.kind() == FaceKind::Quic {
                self.live.lock().push(face.id());
            }
        }
        fn remove_face(&self, face: FaceId) {
            self.live.lock().retain(|f| *f != face);
            self.routes.lock().retain(|(f, _)| *f != face);
        }
        fn add_routes(&self, face: FaceId, routes: &[Route]) {
            if self.live.lock().contains(&face) {
                self.routes
                    .lock()
                    .extend(routes.iter().map(|r| (face, r.clone())));
            }
        }
        fn remove_routes(&self, face: FaceId, prefixes: &[Name]) {
            self.routes
                .lock()
                .retain(|(f, r)| *f != face || !prefixes.contains(&r.prefix));
        }
        fn routes_to(&self, face: FaceId) -> bool {
            self.routes.lock().iter().any(|(f, _)| *f == face)
        }
        fn transit(&self, _: &Name, _: bool) {}
    }

    /// One device: its links, what its forwarder was given, the address it
    /// listens at (when it does) and its key.
    struct Party {
        links: Arc<Links>,
        faces: Arc<Faces>,
        addr: Option<SocketAddr>,
        key: KeyFingerprint,
    }

    /// A device with key seed `seed`. `listen`: a loopback socket, taking an
    /// introduction link from a stranger while `offer_open`.
    fn party(seed: u8, listen: bool, offer_open: bool, cancel: &CancellationToken) -> Party {
        let key = key(seed);
        let fingerprint = key.fingerprint();
        let key: Arc<dyn LinkKeySource> = Arc::new(key);
        let transport = LinkTransportConfig::default();
        let socket = listen.then(|| {
            Arc::new(
                LinkEndpoint::bind(
                    "127.0.0.1:0".parse().unwrap(),
                    Arc::clone(&key),
                    &transport,
                    true,
                )
                .unwrap(),
            )
        });
        let addr = socket.as_ref().map(|s| s.local_addr().unwrap());
        let faces = Arc::new(Faces::default());
        let links = Links::start(
            LinkSetup {
                peers: Vec::new(),
                key,
                trust: Arc::new(NoTrust(Arc::new(Keyring::new()))),
                faces: Arc::clone(&faces) as Arc<dyn FaceSink>,
                paths: Arc::new(ConfiguredEndpoints),
                candidates: Vec::new(),
                socket,
                transport,
                relays: Default::default(),
                service: RelayService::default(),
                direct: Default::default(),
                reliability: Default::default(),
            },
            cancel.child_token(),
        );
        if listen {
            links.set_introductions(Arc::new(Offers(offer_open)));
        }
        Party {
            links,
            faces,
            addr,
            key: fingerprint,
        }
    }

    /// The routes a first contact is dialled for.
    fn routes() -> Vec<Name> {
        vec![
            n("/alice/member/laptop/32=held"),
            n("/alice/member/laptop/32=intro"),
        ]
    }

    fn sorted(mut names: Vec<Name>) -> Vec<Name> {
        names.sort();
        names
    }

    async fn until(what: &str, mut done: impl FnMut() -> bool) {
        let start = Instant::now();
        while !done() {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "not within 10 s: {what}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_party_at_the_address_is_linked_by_the_key_it_proves_and_only_the_routes_are_made()
    {
        let cancel = CancellationToken::new();
        let listener = party(1, true, true, &cancel);
        let joiner = party(2, false, false, &cancel);
        let device = n("/alice/member/laptop");

        let proved = joiner
            .links
            .dial_first(
                device.clone(),
                listener.addr.unwrap(),
                Duration::from_secs(10),
                routes(),
            )
            .await
            .unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(proved, listener.key, "the key the handshake proved");
        assert_eq!(
            joiner.faces.prefixes(),
            sorted(routes()),
            "the link routes what it was dialled for and no name of the claimed device"
        );
        // The link is the key's, a peer the dial added: not persistent, no
        // certificate shown.
        let report = joiner.links.report();
        let link = report
            .links
            .iter()
            .find(|l| l.key == Some(listener.key))
            .unwrap_or_else(|| panic!("{report:#?}"));
        assert!(!link.paths.is_empty(), "{link:#?}");

        // The dial that made it takes it down again.
        joiner
            .links
            .undial_by_key(proved, "the join that dialled it failed");
        until("the link and its routes are gone", || {
            joiner.links.report().links.is_empty() && joiner.faces.prefixes().is_empty()
        })
        .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_key_already_linked_is_returned_and_no_second_link_is_made() {
        let cancel = CancellationToken::new();
        let listener = party(3, true, true, &cancel);
        let joiner = party(4, false, false, &cancel);
        let dial = || {
            joiner.links.dial_first(
                n("/alice/member/laptop"),
                listener.addr.unwrap(),
                Duration::from_secs(10),
                routes(),
            )
        };
        let first = dial().await.unwrap_or_else(|e| panic!("{e:?}"));
        let second = dial().await.unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(first, second);
        assert_eq!(first, listener.key);
        assert_eq!(joiner.links.report().links.len(), 1);
        assert_eq!(joiner.faces.live.lock().len(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_device_does_not_dial_itself_by_a_first_contact() {
        let cancel = CancellationToken::new();
        let myself = party(5, true, true, &cancel);
        let refused = myself
            .links
            .dial_first(
                n("/alice/member/laptop"),
                myself.addr.unwrap(),
                Duration::from_secs(10),
                routes(),
            )
            .await
            .expect_err("a device is not its own first contact");
        assert_eq!(refused.code, code::DIAL_FAILED);
        assert!(refused.text.contains("own"), "{}", refused.text);
        assert!(myself.faces.prefixes().is_empty());
        assert!(
            !myself
                .links
                .report()
                .links
                .iter()
                .any(|l| l.key == Some(myself.key)),
            "{:#?}",
            myself.links.report()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_address_nothing_answers_at_fails_within_the_time_given_and_leaves_nothing() {
        let cancel = CancellationToken::new();
        let joiner = party(6, false, false, &cancel);
        let dead = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let at = dead.local_addr().unwrap();

        let started = Instant::now();
        let failed = joiner
            .links
            .dial_first(
                n("/alice/member/laptop"),
                at,
                Duration::from_secs(2),
                routes(),
            )
            .await
            .expect_err("nothing answers");
        assert!(
            started.elapsed() < Duration::from_secs(8),
            "the dial is bounded"
        );
        assert_eq!(failed.code, code::DIAL_FAILED);
        assert!(failed.text.contains(&at.to_string()), "{}", failed.text);
        assert!(joiner.links.report().links.is_empty());
        assert!(joiner.faces.prefixes().is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_party_that_takes_no_introduction_link_leaves_no_peer_and_no_route() {
        let cancel = CancellationToken::new();
        // No offer is open: the party refuses a stranger as any other.
        let listener = party(7, true, false, &cancel);
        let joiner = party(8, false, false, &cancel);
        let failed = joiner
            .links
            .dial_first(
                n("/alice/member/laptop"),
                listener.addr.unwrap(),
                Duration::from_secs(10),
                routes(),
            )
            .await
            .expect_err("a stranger is refused while no offer is open");
        assert!(!failed.text.is_empty(), "{failed:?}");
        assert!(joiner.links.report().links.is_empty());
        assert!(joiner.faces.prefixes().is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_offline_device_dials_nobody() {
        let cancel = CancellationToken::new();
        let listener = party(9, true, true, &cancel);
        let joiner = party(10, false, false, &cancel);
        joiner.links.set_online(false);
        let failed = joiner
            .links
            .dial_first(
                n("/alice/member/laptop"),
                listener.addr.unwrap(),
                Duration::from_secs(5),
                routes(),
            )
            .await
            .expect_err("offline");
        assert_eq!(failed.code, code::OFFLINE, "{failed:?}");
        assert!(joiner.links.report().links.is_empty());
    }
}
