//! A data-layer device's link hint and dial over [`Links`] (feature
//! `introductions`; ndn-rs data-layer.md §19.2, §19.3).
//!
//! The data layer cannot depend on this crate, so a host gives its
//! `ndn_data::Introducer` the three halves it asks of it —
//! `link_hint`, `dial` and `undial` — by forwarding to a [`LinkHints`].

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ndn_data::intro::{
    Dialing, HintCandidate, HintKind, JoinedFolder, LinkHint, introduction_prefixes,
};
use ndn_data::version::Timestamp;
use ndn_data::{DataError, Device, IntroductionSurface, NextStep, Role};
use ndn_face_quic::KeyFingerprint;
use ndn_packet::Name;

use crate::departures::{Departure, DepartureSink, DepartureTaking, NotTaken};
use crate::grants::{Grant, GrantRole};
use crate::introduce::Introductions;
use crate::joined::JoinedRoutes;
use crate::links::Links;

impl Introductions for IntroductionSurface {
    fn open(&self) -> bool {
        IntroductionSurface::open(self)
    }

    fn carries(&self, name: &Name) -> bool {
        IntroductionSurface::carries(self, name)
    }

    fn grant_carries(&self, folder: &Name, name: &Name) -> bool {
        IntroductionSurface::grant_carries(self, folder, name)
    }

    fn departure_carries(&self, record: &Name, name: &Name) -> bool {
        IntroductionSurface::departure_carries(self, record, name)
    }

    fn writer_namespaces(&self, folder: &Name) -> Vec<Name> {
        IntroductionSurface::writer_namespaces(self, folder)
    }
}

impl DepartureSink for IntroductionSurface {
    fn departure<'a>(
        &'a self,
        from: &'a Name,
        folder: &'a Name,
        record: &'a Name,
    ) -> DepartureTaking<'a> {
        Box::pin(async move {
            self.take_departure(from, folder, record)
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

/// What a data-layer device does over its [`Links`] for an introduction
/// code's link hint.
#[derive(Clone)]
pub struct LinkHints {
    links: Arc<Links>,
}

impl LinkHints {
    pub fn new(links: Arc<Links>) -> Self {
        Self { links }
    }

    /// The inviter's half: take introduction links for the device's
    /// introductions (its offer fetches and asks), from devices this one
    /// does not know, while one of its offers is open and carrying only what
    /// the device's [`introductions`](ndn_data::Device::introductions)
    /// surface carries; and install the grants in force
    /// ([`Device::grants`]), so a person this device admitted before a
    /// restart links again with no list kept here. Call it once, on the
    /// device that makes offers, and forward its introducer's
    /// [`grant`](ndn_data::intro::Introducer::grant) and
    /// [`revoke_grant`](ndn_data::intro::Introducer::revoke_grant) to
    /// [`LinkHints::grant`] and [`LinkHints::revoke_grant`]: the device is the
    /// single source of grants, and ndn-link keeps none of its own across
    /// restarts.
    ///
    /// It is also the joiner's half: the folders this device joined
    /// ([`Device::joined_folders`]) are given to the links now
    /// ([`Links::set_joined_routes`]), and again at every change the device
    /// signals ([`Device::joined_changes`]), by **one** task that ends when the
    /// device is gone or the links stop. A second call stops the task the first
    /// started and starts its own: there is never more than one for these
    /// links, so calling it twice does not follow the device twice. The host
    /// has no route to make.
    pub fn serve(&self, device: &Device) {
        self.links
            .set_introductions(Arc::new(device.introductions()));
        self.links
            .set_departure_sink(Arc::new(device.introductions()));
        for departure in device.departures() {
            self.depart(&departure);
        }
        for grant in device.grants() {
            self.grant(&grant);
        }
        self.follow_joined(device.introductions());
    }

    /// Give the links the joined folders of `surface` now and at every change
    /// of its `joined_changes`, by one task for these links: the one a former
    /// call started is stopped, and the task ends when the device is gone.
    fn follow_joined(&self, surface: IntroductionSurface) {
        let stop = {
            let mut running = self.links.joined_follow.lock();
            if let Some(former) = running.take() {
                former.cancel();
            }
            let stop = self.links.cancel_token().child_token();
            *running = Some(stop.clone());
            stop
        };
        // Subscribed before the first read: a change between the two is seen
        // as one more, which changes nothing.
        let mut changes = surface.joined_changes();
        set_joined(&self.links, &surface);
        let links = Arc::downgrade(&self.links);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = stop.cancelled() => break,
                    changed = changes.changed() => {
                        // The device dropped its end: it is gone.
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

    /// An offer of the device admitted a person (or a held record changed
    /// the role it admits them in): this device links with its key as a
    /// person of the grant's namespaces, in the folder's scope and the
    /// role's, until it ends ([`Links::grant`]); the grant is one entry of
    /// the key's set, the entry of its folder. Forward
    /// [`Introducer::grant`](ndn_data::intro::Introducer::grant) here.
    pub fn grant(&self, grant: &ndn_data::intro::Grant) {
        self.links.grant(link_grant(grant));
    }

    /// The grant of `key` for `folder` ended before its time (a held members
    /// record leaves the person out of that folder): the links the key's
    /// entries admitted close when this was the last entry
    /// ([`Links::revoke_grant`]), or narrow to the departure when
    /// [`LinkHints::depart`] was told of this folder first. Forward
    /// [`Introducer::revoke_grant`](ndn_data::intro::Introducer::revoke_grant)
    /// here. It is **in memory only**: the device calls it before it records
    /// the end durably, itself. A host that ends a grant of its own accord
    /// (a person who stays a member) calls [`LinkHints::end_grant_in`] or
    /// [`LinkHints::end_grant`], which also make it durable, so that a
    /// restart does not bring it back.
    pub fn revoke_grant(&self, key: &[u8; 32], folder: &Name) {
        self.links.revoke_grant(&KeyFingerprint(*key), folder);
    }

    /// A held members record left the person out of a folder: the departure
    /// mark ([`Links::depart`]) that makes the link narrow to the record, or
    /// admit a returning device on a narrow link for it. Forward
    /// [`Introducer::departure`](ndn_data::intro::Introducer::departure)
    /// here; the device calls it before
    /// [`revoke_grant`](LinkHints::revoke_grant) for the same end.
    pub fn depart(&self, departure: &ndn_data::intro::Departure) {
        self.links.depart(link_departure(departure));
    }

    /// The host ends every grant of `key` for good: the links they alone
    /// admitted close now ([`Links::revoke_grants`], in memory, first), then
    /// the device records the end ([`Device::end_grant`]) behind its store
    /// barrier. No departure is told: the person was not let go by a record.
    /// The person stays a member of the folders, which a members record
    /// changes, not this. `Ok(true)` when a grant was in force in either
    /// layer.
    ///
    /// `device` is the one given to [`LinkHints::serve`]; it is a parameter
    /// and not kept here because the device's introducer holds these hints.
    ///
    /// # Errors
    /// [`DataError::Local`] when the device stopped before the end was
    /// durable: the links are closed already, call it again once the device
    /// runs.
    pub async fn end_grant(&self, device: &Device, key: &[u8; 32]) -> Result<bool, DataError> {
        let linked = self.links.revoke_grants(&KeyFingerprint(*key));
        let recorded = device.end_grant(key).await?;
        Ok(linked || recorded)
    }

    /// The host ends the grant of `key` for `folder` only, for good
    /// ([`Links::revoke_grant`], then [`Device::end_grant_in`]): the key's
    /// other entries stand, and the links close only when this was the last.
    /// `Ok(true)` when an entry was in force in either layer.
    ///
    /// # Errors
    /// As [`LinkHints::end_grant`].
    pub async fn end_grant_in(
        &self,
        device: &Device,
        key: &[u8; 32],
        folder: &Name,
    ) -> Result<bool, DataError> {
        let linked = self.links.revoke_grant(&KeyFingerprint(*key), folder);
        let recorded = device.end_grant_in(key, folder).await?;
        Ok(linked || recorded)
    }

    /// The host renews the grant of `key` (`until`: a later date, or `None`
    /// for no date): the device records it durably ([`Device::renew_grant`],
    /// only while a held members record still admits the person), then this
    /// device's links hold it as it now stands ([`LinkHints::grant`]), so a
    /// restart keeps it. Returns the grant as it stands, `None` when no grant
    /// of `key` is live or no held record admits the person.
    ///
    /// # Errors
    /// [`DataError::BadRequest`] for a date not after the device's clock,
    /// [`DataError::Local`] when the device stopped before the change was
    /// durable.
    pub async fn renew_grant(
        &self,
        device: &Device,
        key: &[u8; 32],
        until: Option<Timestamp>,
    ) -> Result<Option<ndn_data::intro::Grant>, DataError> {
        let renewed = device.renew_grant(key, until).await?;
        if let Some(grant) = &renewed {
            self.grant(grant);
        }
        Ok(renewed)
    }

    /// The hint to put into an offer's code: this device's link key and the
    /// candidate addresses of its listening socket, most promising first.
    /// `None` when it does not listen or has no usable key.
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

    /// The joiner's half: dial `inviter` by `hint`, every candidate at once,
    /// within `within` ([`Links::dial_by_key`]). `Ok` once the link to the
    /// device holding the hint's key is up; until that device is identified
    /// the link routes only `inviter`'s introduction prefixes, not the
    /// names the code claims for it.
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

    /// The join that dialled `hint` failed: take down the link it made, if
    /// it is still one that carries only the introduction
    /// ([`Links::undial_by_key`]).
    pub fn undial(&self, hint: &LinkHint, inviter: &Name) {
        self.links.undial_by_key(
            KeyFingerprint(hint.key),
            &format!("the join that dialled {inviter} by its code's hint failed"),
        );
    }
}

/// `ms` milliseconds after the Unix epoch, `None` where the platform's clock
/// cannot count that far (a date a store holds is not trusted to fit).
fn epoch_plus(ms: u64) -> Option<SystemTime> {
    add_ms(UNIX_EPOCH, ms)
}

fn add_ms(base: SystemTime, ms: u64) -> Option<SystemTime> {
    base.checked_add(Duration::from_millis(ms))
}

/// The joined folders `surface` lists now, given to `links` as routes, and
/// said at info with the folders and prefixes.
fn set_joined(links: &Links, surface: &IntroductionSurface) {
    let folders = surface.joined_folders();
    tracing::info!(
        target: "face.quic",
        folders = ?folders.iter().map(|f| format!(
            "{} (inviter {}): {}",
            f.folder,
            KeyFingerprint(f.inviter),
            f.writers.iter().map(ToString::to_string).collect::<Vec<_>>().join(" ")
        )).collect::<Vec<_>>(),
        "the folders this device joined changed: the writers' namespaces are routed over each inviter's link"
    );
    links.set_joined_routes(joined_routes(&folders));
}

/// The data layer's joined folders as ndn-link routes them: the inviter's
/// digest is its link key (a host whose link key is not its device key calls
/// [`Links::set_joined_routes`] with its own mapping), the owner and the
/// writers' namespaces as the device derived them.
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

/// The data layer's grant as ndn-link holds it. A date no platform clock can
/// count to is a date long past for the grant's purposes: the grant is made
/// already over, never trusted to be unending and never a panic.
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

/// The data layer's departure mark as ndn-link holds it. A date no platform
/// clock can count to is a date long past: the mark is already over.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The latest instant the platform's clock holds: a date past it cannot
    /// be added to without overflow.
    fn latest() -> SystemTime {
        let mut t = UNIX_EPOCH;
        for step in [1u64 << 62, 1 << 40, 1 << 20, 1 << 10, 1] {
            while let Some(next) = t.checked_add(Duration::from_secs(step)) {
                t = next;
            }
        }
        t
    }

    #[test]
    fn a_date_the_clock_cannot_count_is_not_added_to_and_makes_a_grant_already_over() {
        // No panic, and a result that says so, where the sum overflows.
        assert_eq!(add_ms(latest(), 5_000), None);
        assert_eq!(
            add_ms(UNIX_EPOCH, 1_500),
            Some(UNIX_EPOCH + Duration::from_millis(1_500))
        );

        // A grant the data layer made with a date: the link layer's `until`
        // is that instant; with none, none.
        let make = |until| ndn_data::intro::Grant {
            key: [7; 32],
            namespaces: vec!["/bob".parse().unwrap()],
            folder: "/alice/32=data/notebook".parse().unwrap(),
            role: Role::Reader,
            until,
        };
        let dated = link_grant(&make(Some(Timestamp(2_000))));
        assert_eq!(dated.until, Some(UNIX_EPOCH + Duration::from_millis(2_000)));
        assert_eq!(dated.role, GrantRole::Reader);
        assert_eq!(dated.folder, "/alice/32=data/notebook".parse().unwrap());
        assert_eq!(link_grant(&make(None)).until, None);
    }
}
