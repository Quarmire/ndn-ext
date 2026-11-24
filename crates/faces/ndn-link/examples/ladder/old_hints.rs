//! The old layer's half of the link machinery: what `ndn_link::LinkHints` was for an
//! `ndn_data::Device` before the introductions moved to `ndn-invite` (it now speaks
//! `ndn_invite` types only). The ladder keeps the old layer until stage 9 so that its
//! numbers can be had before and after the move; this is that glue, as it was, over the
//! same `Links` calls, so both layers measure the same link stack.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ndn_data::intro::{
    Dialing, FirstDialing, HintCandidate, HintKind, JoinedFolder, LinkHint, introduction_prefixes,
};
use ndn_data::version::Timestamp;
use ndn_data::{Device, IntroductionSurface, NextStep, Role};
use ndn_face_quic::KeyFingerprint;
use ndn_link::{
    Departure, DepartureSink, DepartureTaking, Grant, GrantRole, Introductions, JoinedRoutes,
    Links, NotTaken,
};
use ndn_packet::Name;
use tokio_util::sync::CancellationToken;

/// The device's introductions as the links take them (a newtype: both the trait and the
/// surface are foreign to this crate).
struct Surface(IntroductionSurface);

impl Introductions for Surface {
    fn open(&self) -> bool {
        self.0.open()
    }

    fn carries(&self, name: &Name) -> bool {
        self.0.carries(name)
    }

    fn grant_carries(&self, folder: &Name, name: &Name) -> bool {
        self.0.grant_carries(folder, name)
    }

    fn departure_carries(&self, record: &Name, name: &Name) -> bool {
        self.0.departure_carries(record, name)
    }

    fn writer_namespaces(&self, folder: &Name) -> Vec<Name> {
        self.0.writer_namespaces(folder)
    }
}

impl DepartureSink for Surface {
    fn departure<'a>(
        &'a self,
        from: &'a Name,
        folder: &'a Name,
        record: &'a Name,
    ) -> DepartureTaking<'a> {
        Box::pin(async move {
            self.0
                .take_departure(from, folder, record)
                .await
                .map_err(|e| {
                    // What `NotReady` and `Unavailable` say to do: ask again.
                    if e.next() == NextStep::RetryLater {
                        NotTaken::not_yet(e.to_string())
                    } else {
                        NotTaken::refused(e.to_string())
                    }
                })
        })
    }
}

/// What an `ndn_data::Device` does over its [`Links`] for an introduction code's link hint.
pub struct OldHints {
    links: Arc<Links>,
}

impl OldHints {
    pub fn new(links: Arc<Links>) -> Self {
        Self { links }
    }

    /// The inviter's half (its introductions' surface, its grants and departure marks in
    /// force) and the joiner's (the folders it joined, routed over the links now and at
    /// every change the device signals, by one task that ends with `stop`).
    pub fn serve(&self, device: &Device, stop: CancellationToken) {
        self.links
            .set_introductions(Arc::new(Surface(device.introductions())));
        self.links
            .set_departure_sink(Arc::new(Surface(device.introductions())));
        for departure in device.departures() {
            self.depart(&departure);
        }
        for grant in device.grants() {
            self.grant(&grant);
        }
        let surface = device.introductions();
        let mut changes = surface.joined_changes();
        set_joined(&self.links, &surface);
        let links = Arc::downgrade(&self.links);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    () = stop.cancelled() => break,
                    changed = changes.changed() => {
                        if changed.is_err() {
                            break;
                        }
                        let Some(links) = links.upgrade() else { break };
                        set_joined(&links, &surface);
                    }
                }
            }
        });
    }

    pub fn grant(&self, grant: &ndn_data::intro::Grant) {
        self.links.grant(link_grant(grant));
    }

    pub fn revoke_grant(&self, key: &[u8; 32], folder: &Name) {
        self.links.revoke_grant(&KeyFingerprint(*key), folder);
    }

    pub fn depart(&self, departure: &ndn_data::intro::Departure) {
        self.links.depart(link_departure(departure));
    }

    /// The hint to put into an offer's code: this device's link key and the candidate
    /// addresses of its listening socket, most promising first.
    pub fn hint(&self) -> Option<LinkHint> {
        let key = self.links.key_fingerprint()?;
        let candidates: Vec<HintCandidate> = self
            .links
            .hint_candidates()
            .into_iter()
            .filter_map(|c| {
                Some(HintCandidate {
                    kind: HintKind::from_code(c.kind.code())?,
                    addr: c.addr,
                })
            })
            .collect();
        (!candidates.is_empty()).then_some(LinkHint {
            key: key.0,
            candidates,
        })
    }

    /// Dial `inviter` by `hint`, every candidate at once, within `within`.
    pub fn dial<'a>(
        &'a self,
        hint: &'a LinkHint,
        inviter: &'a Name,
        within: Duration,
    ) -> Dialing<'a> {
        Box::pin(async move {
            let addrs = hint.candidates.iter().map(|c| c.addr).collect();
            self.links
                .dial_by_key(
                    KeyFingerprint(hint.key),
                    inviter.clone(),
                    addrs,
                    within,
                    introduction_prefixes(inviter).into(),
                )
                .await
                .map_err(|detail| detail.text)
        })
    }

    /// Dial `inviter` at the one address `addr` of a short code, with no key to expect.
    pub fn dial_first<'a>(
        &'a self,
        inviter: &'a Name,
        addr: SocketAddr,
        within: Duration,
    ) -> FirstDialing<'a> {
        Box::pin(async move {
            self.links
                .dial_first(
                    inviter.clone(),
                    addr,
                    within,
                    introduction_prefixes(inviter).into(),
                )
                .await
                .map(|key| key.0)
                .map_err(|detail| detail.text)
        })
    }

    pub fn undial(&self, hint: &LinkHint, inviter: &Name) {
        self.links.undial_by_key(
            KeyFingerprint(hint.key),
            &format!(
                "the link made by dialling {inviter} from its code is taken down: the join failed, \
                 or this party's key is not the one the code's verified hint names"
            ),
        );
    }
}

/// `ms` milliseconds after the Unix epoch, `None` where the platform's clock cannot count
/// that far.
fn epoch_plus(ms: u64) -> Option<SystemTime> {
    UNIX_EPOCH.checked_add(Duration::from_millis(ms))
}

/// The joined folders `surface` lists now, given to `links` as routes.
fn set_joined(links: &Links, surface: &IntroductionSurface) {
    links.set_joined_routes(joined_routes(&surface.joined_folders()));
}

fn joined_routes(folders: &[JoinedFolder]) -> Vec<JoinedRoutes> {
    folders
        .iter()
        .map(|f| JoinedRoutes {
            inviter: KeyFingerprint(f.inviter),
            owner: f.owner.clone(),
            namespaces: f.writers.clone(),
            push: f.role == Role::Writer,
        })
        .collect()
}

fn link_grant(grant: &ndn_data::intro::Grant) -> Grant {
    let until = grant
        .until
        .map(|Timestamp(ms)| epoch_plus(ms).unwrap_or(UNIX_EPOCH));
    Grant {
        key: KeyFingerprint(grant.key),
        namespaces: grant.namespaces.clone(),
        folder: grant.folder.clone(),
        role: match grant.role {
            Role::Reader => GrantRole::Reader,
            Role::Writer => GrantRole::Writer,
        },
        until,
    }
}

fn link_departure(departure: &ndn_data::intro::Departure) -> Departure {
    let Timestamp(until) = departure.until;
    Departure {
        key: KeyFingerprint(departure.key),
        namespaces: departure.namespaces.clone(),
        folder: departure.folder.clone(),
        record: departure.record.clone(),
        until: epoch_plus(until).unwrap_or(UNIX_EPOCH),
    }
}
