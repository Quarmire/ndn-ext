//! Grants: the people an introduction admitted links here, under the
//! default serving policy (`ndn-rs/docs/specs/ndn-link.md` §8.7).
//!
//! A [`Grant`] says: the device holding link key `key` may link here, as a
//! person of the `namespaces`, in the offered `folder`'s scope, until `until`
//! (or with no date at all, while the members record of the folder keeps
//! admitting the person). The serving policy `own` serves the namespaces this
//! device holds a certificate in and no others, so the person an inviter just
//! admitted — of another namespace, whose context it now holds — would be
//! refused; the grant serves exactly that key in exactly those namespaces,
//! and nothing else. It is host-supplied authority to *link*, and a link
//! under a grant carries only the names of the folder, of the person's own
//! devices, of the introduction (`Introductions::grant_carries`), the public
//! names of the namespaces of the folder's writers: not everything this
//! device serves by name.
//!
//! A key holds a **set of entries**, one per folder (a person invited into
//! two folders has two). The link a grant admits is tagged with the key and
//! stands while any entry of the key is live; what it carries and what the
//! peer may push are judged at every packet against the entries live then,
//! so a role change or an entry's end takes effect at the next packet, with
//! no close. When the last entry ends by a members record that left the
//! person out, the link narrows in place to the departure
//! (`departures.rs`, §8.8); otherwise it closes.
//!
//! The grants are a live table in memory by key; the host owns them (the
//! data layer's device re-derives them at start from signed, durable data
//! — `LinkHints::serve`). Expiry is judged on every admission and by one
//! task that sleeps until the earliest `until`, at most a minute at a time
//! so that a suspend or a clock step is seen within a minute; a grant that
//! ended closes the links it alone admitted and is named in the refusal of
//! the next dial of its key. A link is checked against the table again once
//! it is registered, so a grant that ended while its handshake was in flight
//! closes it too.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ndn_cert::onboarding::rdr_prefix;
use ndn_face_quic::{CloseReason, KeyFingerprint, NameFilter};
use ndn_mgmt_wire::{LinkDetail, link_code as code};
use ndn_packet::{Name, NameComponent};
use ndn_security::sync_group;
use parking_lot::Mutex;
use tokio::sync::Notify;

use crate::admission::{Identity, Judge, Refusal, is_key_or_certificate_name, list as list_of};
use crate::departures::Departure;
use crate::introduce::Introductions;
use crate::links::Links;
use crate::serving::{QuotaSlot, Quotas, ServePolicy, Serving};

/// What a link under a grant carries: the role the offer admitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantRole {
    /// The person only reads: what it sends toward this device is Interests
    /// (Data it pushes is dropped at the link); what this device sends is
    /// everything.
    Reader,
    /// A full link within the quotas.
    Writer,
}

impl GrantRole {
    fn as_str(self) -> &'static str {
        match self {
            Self::Reader => "reader",
            Self::Writer => "writer",
        }
    }
}

/// The device holding link key `key` may link here as a person of
/// `namespaces`, in the scope of `folder`, until `until`. One entry of the
/// key's set: it is identified by `(key, folder)`, and granting the same key
/// and folder again replaces it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    /// The link key the person's device proves in the handshake.
    pub key: KeyFingerprint,
    /// The namespaces the person may be identified in: the link is admitted
    /// by those of its certificates and memberships that validate in one of
    /// these, and by no other.
    pub namespaces: Vec<Name>,
    /// The folder the offer admitted the person to (`<O>/32=data/<path>`):
    /// the link carries the names of its collections, nothing else this
    /// device serves by name besides the person's own devices and the
    /// introduction ([`Introductions::grant_carries`]).
    pub folder: Name,
    /// The role in this folder: what the person may push toward this device
    /// under this folder's names, judged at every packet.
    pub role: GrantRole,
    /// `Some`: the grant ends then. `None`: it has no date of its own; it
    /// follows the members record of the folder, and its host ends it
    /// ([`Links::revoke_grant`]) when a record leaves the person out.
    pub until: Option<SystemTime>,
}

impl Grant {
    /// The grant in words: `granted until 2026-11-18 14:03:22 UTC as a
    /// writer in /bob`, or `granted with no end date (it follows the
    /// folder's members record) as a writer in /bob`.
    pub fn describe(&self) -> String {
        let when = match self.until {
            Some(until) => format!("until {}", utc(until)),
            None => "with no end date (it follows the folder's members record)".to_string(),
        };
        format!(
            "granted {when} as a {} in {}",
            self.role.as_str(),
            list_of(&self.namespaces)
        )
    }

    /// Whether the grant has run out by `now`.
    fn over(&self, now: SystemTime) -> bool {
        self.until.is_some_and(|until| until <= now)
    }

    /// Whether this entry's namespaces include one of `identities`'.
    fn admits_any(&self, identities: &[Identity]) -> bool {
        identities
            .iter()
            .any(|id| self.namespaces.contains(&id.namespace))
    }
}

/// How a grant ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum How {
    Expired,
    Revoked,
    /// Replaced by a grant of other namespaces.
    Replaced,
}

impl How {
    fn as_str(self) -> &'static str {
        match self {
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::Replaced => "replaced",
        }
    }

    /// What ended it, for a person reading why.
    fn words(self) -> &'static str {
        match self {
            Self::Expired => "it expired",
            Self::Revoked => {
                "it was revoked: this device withdrew it, as it does when the members record of the \
                 folder no longer lists you"
            }
            Self::Replaced => "it was replaced by a grant of other namespaces",
        }
    }

    fn ended(self, grant: &Grant) -> EndedGrant {
        EndedGrant {
            key: grant.key,
            namespaces: grant.namespaces.clone(),
            folder: grant.folder.clone(),
            until: grant.until,
            how: self,
        }
    }
}

/// A grant entry that ended: what is left of it to name in a refusal.
#[derive(Clone, Debug)]
pub(crate) struct EndedGrant {
    key: KeyFingerprint,
    namespaces: Vec<Name>,
    folder: Name,
    until: Option<SystemTime>,
    how: How,
}

impl EndedGrant {
    pub(crate) fn detail(&self) -> LinkDetail {
        let until = match self.until {
            Some(until) => format!("until {}", utc(until)),
            None => "with no end date".to_string(),
        };
        LinkDetail::new(
            code::GRANT_ENDED,
            format!(
                "your key {} was granted a link here as a person of {}, {until}, in the folder {}, \
                 and the grant ended: {}. Ask the person who invited you to invite you again",
                self.key,
                list_of(&self.namespaces),
                self.folder,
                self.how.words()
            ),
        )
        .with("key", self.key)
        .with("namespaces", list_of(&self.namespaces))
        .with("folder", &self.folder)
        .with("until", self.until.map_or_else(|| "none".to_string(), utc))
        .with("ended", self.how.as_str())
    }
}

/// How many ended grant entries are remembered to name in refusals: the
/// oldest are forgotten.
const ENDED_MAX: usize = 64;

/// The longest the expiry task sleeps at once. The sleep runs on the monotonic
/// clock, which stands still while a machine is suspended, and the grants'
/// dates are on the wall clock, which may be set: so the task looks at the
/// wall clock again at least this often while a dated grant is in force, and a
/// suspend or a step is seen within it.
const SLEEP_MAX: Duration = Duration::from_secs(60);

#[derive(Default)]
struct State {
    /// Each key's entries, sorted by folder. A key with none has no entry
    /// here. Replaced whole on every change, so a reader holds a snapshot
    /// with no lock.
    live: HashMap<KeyFingerprint, Arc<[Grant]>>,
    /// The entries that ended, oldest first.
    ended: VecDeque<EndedGrant>,
}

impl State {
    fn end(&mut self, grant: &Grant, how: How) {
        self.ended
            .retain(|e| !(e.key == grant.key && e.folder == grant.folder));
        if self.ended.len() == ENDED_MAX {
            self.ended.pop_front();
        }
        self.ended.push_back(how.ended(grant));
    }

    /// Adds `grant` or replaces the entry of its key and folder; the entry
    /// it replaced.
    fn put(&mut self, grant: Grant) -> Option<Grant> {
        self.ended
            .retain(|e| !(e.key == grant.key && e.folder == grant.folder));
        let mut entries: Vec<Grant> = self
            .live
            .remove(&grant.key)
            .map(|e| e.to_vec())
            .unwrap_or_default();
        let previous = match entries.iter().position(|g| g.folder == grant.folder) {
            Some(at) => Some(std::mem::replace(&mut entries[at], grant.clone())),
            None => {
                entries.push(grant.clone());
                None
            }
        };
        entries.sort_by(|a, b| a.folder.cmp(&b.folder));
        self.live.insert(grant.key, entries.into());
        previous
    }

    /// Removes the entry of `key` for `folder`; the entry removed.
    fn remove(&mut self, key: &KeyFingerprint, folder: &Name) -> Option<Grant> {
        let entries = self.live.remove(key)?;
        let removed = entries.iter().find(|g| g.folder == *folder).cloned();
        let kept: Vec<Grant> = entries
            .iter()
            .filter(|g| g.folder != *folder)
            .cloned()
            .collect();
        if !kept.is_empty() {
            self.live.insert(*key, kept.into());
        }
        removed
    }
}

#[derive(Default)]
struct Inner {
    state: Mutex<State>,
    /// Wakes the expiry task when the earliest `until` may have changed.
    wake: Notify,
}

/// The live grants of a [`Links`], and the memory of the ones that ended.
#[derive(Clone, Default)]
pub(crate) struct Grants {
    inner: Arc<Inner>,
}

/// What the table says of a key.
pub(crate) enum Lookup {
    /// The entries in force, never empty, sorted by folder.
    Live(Arc<[Grant]>),
    Ended(LinkDetail),
    None,
}

impl Grants {
    /// An entry in force, for the judge's tests (the table without a
    /// `Links`).
    #[cfg(test)]
    pub(crate) fn put(&self, grant: Grant) {
        self.inner.state.lock().put(grant);
    }

    /// Ends the entry of `key` for `folder` as a revoke does, for the judge's
    /// tests; the entry ended.
    #[cfg(test)]
    pub(crate) fn take(&self, key: &KeyFingerprint, folder: &Name) -> Option<Grant> {
        let mut state = self.inner.state.lock();
        let grant = state.remove(key, folder)?;
        state.end(&grant, How::Revoked);
        Some(grant)
    }

    /// The entries of `key` now: live while they have not run out (the expiry
    /// task may not have swept them yet), else what is known of the end of
    /// the one that ended last.
    pub(crate) fn lookup(&self, key: &KeyFingerprint, now: SystemTime) -> Lookup {
        let state = self.inner.state.lock();
        if let Some(entries) = state.live.get(key) {
            let live = entries.iter().filter(|g| !g.over(now)).count();
            if live == entries.len() {
                return Lookup::Live(Arc::clone(entries));
            }
            if live > 0 {
                let kept: Vec<Grant> = entries.iter().filter(|g| !g.over(now)).cloned().collect();
                return Lookup::Live(kept.into());
            }
            let last = entries.iter().max_by_key(|g| g.until).expect("entries");
            return Lookup::Ended(How::Expired.ended(last).detail());
        }
        match state.ended.iter().rev().find(|e| e.key == *key) {
            Some(e) => Lookup::Ended(e.detail()),
            None => Lookup::None,
        }
    }

    /// The entries of `key` in force at `now`: a snapshot, empty when there
    /// are none. It takes no copy of the entries when none ran out, so the
    /// names a grant link carries can be judged with it at every packet.
    pub(crate) fn live_entries(&self, key: &KeyFingerprint, now: SystemTime) -> Arc<[Grant]> {
        match self.lookup(key, now) {
            Lookup::Live(entries) => entries,
            _ => Arc::from([]),
        }
    }

    /// Whether `key` has an entry in force now.
    pub(crate) fn has_live(&self, key: &KeyFingerprint, now: SystemTime) -> bool {
        matches!(self.lookup(key, now), Lookup::Live(_))
    }

    /// `None` while the table still holds an entry of `admitted`'s key that
    /// admits one of the link's `identities`; else what ended it, to say to
    /// the person whose link it was.
    pub(crate) fn ended_since(
        &self,
        admitted: &Grant,
        identities: &[Identity],
    ) -> Option<LinkDetail> {
        let now = SystemTime::now();
        match self.lookup(&admitted.key, now) {
            Lookup::Live(entries) if entries.iter().any(|g| g.admits_any(identities)) => None,
            Lookup::Live(_) => Some(How::Replaced.ended(admitted).detail()),
            Lookup::Ended(detail) => Some(detail),
            Lookup::None => Some(How::Revoked.ended(admitted).detail()),
        }
    }

    /// The entries in force now, sorted by key then folder.
    fn list(&self) -> Vec<Grant> {
        let now = SystemTime::now();
        let state = self.inner.state.lock();
        let mut grants: Vec<Grant> = state
            .live
            .values()
            .flat_map(|entries| entries.iter())
            .filter(|g| !g.over(now))
            .cloned()
            .collect();
        grants.sort_by(|a, b| (a.key, &a.folder).cmp(&(b.key, &b.folder)));
        grants
    }

    /// The earliest `until` of the live entries that have one.
    fn next_until(&self) -> Option<SystemTime> {
        self.inner
            .state
            .lock()
            .live
            .values()
            .flat_map(|entries| entries.iter())
            .filter_map(|g| g.until)
            .min()
    }

    /// The entries that ran out by `now`, ended: each with whether it was
    /// the last entry of its key (the key has none left).
    fn take_due(&self, now: SystemTime) -> Vec<(Grant, bool)> {
        let mut state = self.inner.state.lock();
        let due: Vec<Grant> = state
            .live
            .values()
            .flat_map(|entries| entries.iter())
            .filter(|g| g.over(now))
            .cloned()
            .collect();
        let mut taken = Vec::with_capacity(due.len());
        for grant in due {
            if state.remove(&grant.key, &grant.folder).is_some() {
                state.end(&grant, How::Expired);
                let last = !state.live.contains_key(&grant.key);
                taken.push((grant, last));
            }
        }
        taken
    }
}

/// How long the expiry task sleeps before it looks at the wall clock again,
/// given the earliest `until` of the grants in force (`None`: no grant has a
/// date, the task waits to be woken): until then, but never more than
/// [`SLEEP_MAX`].
pub(crate) fn sleep_for(next: Option<SystemTime>, now: SystemTime) -> Option<Duration> {
    next.map(|at| at.duration_since(now).unwrap_or_default().min(SLEEP_MAX))
}

impl Links {
    /// Starts the one task that ends grants when they run out: it sleeps
    /// until the earliest `until`, a minute at most at a time (the wall clock
    /// is read again at each wake: [`SLEEP_MAX`]), and wakes when a grant is
    /// made or ended. A grant with no `until` needs no wake.
    pub(crate) fn spawn_grant_expiry(self: &Arc<Self>) {
        let grants = self.grants.clone();
        let weak = Arc::downgrade(self);
        let cancel = self.cancel_token().clone();
        tokio::spawn(async move {
            loop {
                let next = grants.next_until();
                let sleep = async {
                    match sleep_for(next, SystemTime::now()) {
                        Some(wait) => tokio::time::sleep(wait).await,
                        None => std::future::pending::<()>().await,
                    }
                };
                tokio::select! {
                    biased;
                    () = cancel.cancelled() => return,
                    () = grants.inner.wake.notified() => continue,
                    () = sleep => {}
                }
                let Some(links) = weak.upgrade() else { return };
                for (grant, last) in links.grants.take_due(SystemTime::now()) {
                    if last {
                        links.grant_ended_last(&grant.key, How::Expired.ended(&grant), false);
                    }
                }
            }
        });
    }

    /// Adds the entry for `grant.folder` to the grants of `grant.key`, or
    /// replaces the entry of the same key and folder: the device holding the
    /// key may link here as a person of `grant.namespaces`, in the scope of
    /// `grant.folder`, in `grant.role`, until `grant.until`. A grant never
    /// serves what the serving policy's quotas, the namespace's link policy
    /// or a revocation refuse, and under `serve = open` it adds nothing. It
    /// closes no link while another entry of the key stands: a link the key's
    /// entries admitted stays, whatever the entry replaced listed, until no
    /// entry admits any identity it was admitted by (the device dials again
    /// and is judged by the entries then).
    pub fn grant(&self, grant: Grant) {
        let key = grant.key;
        let now = SystemTime::now();
        let replaced = {
            let mut state = self.grants.inner.state.lock();
            state
                .ended
                .retain(|e| !(e.key == key && e.folder == grant.folder));
            if grant.over(now) {
                // Granted already over: it ends what it replaces.
                let previous = state.remove(&key, &grant.folder);
                state.end(&grant, How::Expired);
                previous.map(|p| (p, How::Expired, !state.live.contains_key(&key)))
            } else {
                let previous = state.put(grant.clone());
                previous
                    .filter(|p| p.namespaces != grant.namespaces)
                    .map(|p| (p, How::Replaced, false))
            }
        };
        self.grants.inner.wake.notify_one();
        if !grant.over(now) {
            // The person is invited into the folder again: the departure of
            // an earlier record no longer describes them.
            self.departures.remove(&key, &grant.folder);
            self.route_grant_groups(&key);
        }
        match replaced {
            Some((previous, How::Expired, true)) => {
                self.grant_ended_last(&key, How::Expired.ended(&previous), false);
            }
            Some((previous, How::Replaced, _)) => {
                let entries = self.grants.live_entries(&key, now);
                self.close_granted_where(&key, &How::Replaced.ended(&previous), |ids| {
                    !entries.iter().any(|e| e.admits_any(ids))
                });
            }
            _ => {}
        }
    }

    /// Ends the entry of `key` for `folder` now. The links the key's entries
    /// admitted close when this was its last entry
    /// ([`CloseReason::NotServed`], saying what ended and what to do), or
    /// narrow in place to the departure when a mark of this folder is held
    /// ([`Links::depart`], §8.8). `true` when an entry was in force.
    pub fn revoke_grant(&self, key: &KeyFingerprint, folder: &Name) -> bool {
        let (grant, last) = {
            let mut state = self.grants.inner.state.lock();
            let Some(grant) = state.remove(key, folder) else {
                return false;
            };
            state.end(&grant, How::Revoked);
            let last = !state.live.contains_key(key);
            (grant, last)
        };
        self.grants.inner.wake.notify_one();
        let departing = self
            .departures
            .has_mark(key, &grant.folder, SystemTime::now());
        if last {
            self.grant_ended_last(key, How::Revoked.ended(&grant), departing);
        } else if departing {
            // Other entries keep the link: it does not narrow, but the person
            // is told which record lets them go of this folder, which the
            // link carries beside what the other entries do (§8.8).
            self.tell_ended_entry(key, &grant.folder);
        }
        true
    }

    /// Ends every entry of `key` now (the host ends the person: no departure
    /// is told, the person was not let go by a record). The links the entries
    /// admitted close. `true` when an entry was in force.
    pub fn revoke_grants(&self, key: &KeyFingerprint) -> bool {
        let ended = {
            let mut state = self.grants.inner.state.lock();
            let Some(entries) = state.live.remove(key) else {
                return false;
            };
            for grant in entries.iter() {
                state.end(grant, How::Revoked);
            }
            entries.last().map(|g| How::Revoked.ended(g))
        };
        self.grants.inner.wake.notify_one();
        if let Some(ended) = ended {
            self.grant_ended_last(key, ended, false);
        }
        true
    }

    /// The grant entries in force now, sorted by key then folder.
    pub fn grants(&self) -> Vec<Grant> {
        self.grants.list()
    }

    /// The first entry of the grants that admitted the link of `key`, as it
    /// stands now (the live entry, else the one the link was admitted by),
    /// for the report.
    pub(crate) fn grant_of_link(&self, admitted_by: &Grant) -> Grant {
        self.grants
            .live_entries(&admitted_by.key, SystemTime::now())
            .first()
            .cloned()
            .unwrap_or_else(|| admitted_by.clone())
    }

    /// The last entry of `key` ended (`ended` is the one ended last): the
    /// links it admitted narrow to the departure when `departing` (a held
    /// record left the person out and a mark of the folder is held) and
    /// there is one to tell, else they close.
    pub(crate) fn grant_ended_last(
        &self,
        key: &KeyFingerprint,
        ended: EndedGrant,
        departing: bool,
    ) {
        if departing && self.narrow_granted(key) {
            return;
        }
        self.close_granted_where(key, &ended, |_| true);
    }

    /// Closes the links of `key` that only a grant admitted and `closes`
    /// says no entry admits any more.
    fn close_granted_where(
        &self,
        key: &KeyFingerprint,
        ended: &EndedGrant,
        closes: impl Fn(&[Identity]) -> bool,
    ) {
        let detail = ended.detail();
        let closed = self
            .table
            .close_granted(key, CloseReason::NotServed, &detail.text, closes);
        if closed {
            tracing::warn!(
                target: "face.quic",
                key = %key,
                "closed the link of a grant that ended: {}",
                detail.text
            );
        }
    }
}

/// What the grants make of a link the serving policy declined.
pub(crate) enum GrantOutcome {
    /// Admitted: the identities the entries admit, each with its quota slot,
    /// and the first entry that admits one.
    Admitted(Vec<(Identity, QuotaSlot)>, Grant),
    /// No entry stands, but marks of the key do: admitted as a departure
    /// link, telling the person of these.
    Departing(Vec<Departure>),
    /// The grant matched and the quotas (or a name collision) refuse.
    Refused(Refusal),
    /// No grant admits it; what is worth telling the refused device about
    /// grants, if anything.
    No(Option<LinkDetail>),
}

impl Judge<'_> {
    /// Consulted where the serving policy served none of the identities of
    /// `fingerprint` (`declined`: those its policy declined — not the ones
    /// refused for quotas or a name collision): the live entries of the key
    /// admit the identities in the namespaces they list, if they validate in
    /// a namespace this device holds (never one served by a root it does not
    /// hold). With no live entry the marks of the key (§8.8) may admit it on
    /// a departure link. Under `open` it adds nothing.
    pub(crate) fn grant_for(
        &self,
        fingerprint: KeyFingerprint,
        declined: &[Identity],
    ) -> GrantOutcome {
        if matches!(self.serve, ServePolicy::Open { .. }) {
            return GrantOutcome::No(None);
        }
        let now = SystemTime::now();
        let entries = match self.grants.lookup(&fingerprint, now) {
            Lookup::Live(entries) => entries,
            other => {
                // Not live. A mark of the key may admit its held identities
                // on the narrow link; failing that the refusal is the one a
                // key whose grant ended with no mark gets.
                let namespaces: Vec<Name> = declined
                    .iter()
                    .filter(|id| id.served.is_none())
                    .map(|id| id.namespace.clone())
                    .collect();
                if let Some(marks) = self.departures.admit(&fingerprint, &namespaces, now) {
                    return GrantOutcome::Departing(marks);
                }
                return match other {
                    Lookup::Ended(detail) => GrantOutcome::No(Some(detail)),
                    _ => GrantOutcome::No(None),
                };
            }
        };
        let matching: Vec<&Identity> = declined
            .iter()
            .filter(|id| {
                id.served.is_none() && entries.iter().any(|e| e.namespaces.contains(&id.namespace))
            })
            .collect();
        if matching.is_empty() {
            let shown: Vec<Name> = declined.iter().map(|id| id.namespace.clone()).collect();
            let mut listed: Vec<Name> = entries
                .iter()
                .flat_map(|e| e.namespaces.iter().cloned())
                .collect();
            listed.sort();
            listed.dedup();
            return GrantOutcome::No(Some(
                LinkDetail::new(
                    code::GRANT_UNMATCHED,
                    format!(
                        "your key {fingerprint} is granted a link here as a person of {}, and the \
                         certificates you showed are of {}: link with the certificate of one the \
                         grant lists",
                        list_of(&listed),
                        if shown.is_empty() {
                            "no namespace this device holds".to_string()
                        } else {
                            list_of(&shown)
                        }
                    ),
                )
                .with("key", fingerprint)
                .with("namespaces", list_of(&listed))
                .with("shown", list_of(&shown)),
            ));
        }
        // The quotas bound how many grant links there are; the rates a grant
        // link takes are the grant link's own, not the strangers'
        // (`policy::GRANT_FRAMES`).
        let quotas = match self.serve {
            ServePolicy::Listed {
                quotas: Some(quotas),
                ..
            } => *quotas,
            _ => Quotas::default(),
        };
        let tag = entries
            .iter()
            .find(|e| e.admits_any(std::slice::from_ref(matching[0])))
            .expect("an entry admits the first matching identity")
            .clone();
        let mut admitted = Vec::with_capacity(matching.len());
        for id in matching {
            // The held context's first anchor (by fingerprint order), as an
            // open policy binds a held namespace.
            let Some(root) = self.held_roots(&id.namespace).into_iter().min() else {
                continue;
            };
            match self
                .quotas
                .take(&id.namespace, root, Some(&quotas), Serving::Granted)
            {
                Ok(slot) => admitted.push((id.clone(), slot)),
                Err(refusal) => return GrantOutcome::Refused(refusal),
            }
        }
        if admitted.is_empty() {
            return GrantOutcome::No(None);
        }
        GrantOutcome::Admitted(admitted, tag)
    }
}

/// Whether `entry` carries `name` (§8.7 rule 5): the sync groups, trust
/// contexts and key and certificate names of its namespaces (public by
/// design: a hello already carries the chain, and the group carries no
/// data); the trust context and key and certificate names of its folder's
/// namespace, and the Sync Interests (`<group>/v=N`) of the one sync group the
/// data layer gives the folder ([`Introductions::sync_group`]: that space's
/// exactly, not the owner's others nor a space nested in the folder);
/// the sync groups and the same names of the other writers' namespaces its
/// folder's record lists; what this device's introductions serve
/// ([`Introductions::carries`]: a person may ask again); the names of the
/// folder's collections as the data layer names them
/// ([`Introductions::grant_carries`]); and the asks of a channel to a device
/// of the folder's owner namespace and their answers (`<device>/32=chan/…`,
/// [`is_chan_name_of`]). A device with no data layer carries the first kind
/// and the channel names only.
fn entry_carries(surface: Option<&Arc<dyn Introductions>>, entry: &Grant, name: &Name) -> bool {
    entry
        .namespaces
        .iter()
        .any(|ns| public_name(ns, name))
        || folder_namespace(&entry.folder).is_some_and(|ns| {
            !entry.namespaces.contains(&ns) && public_name_outside_group(&ns, name)
        })
        || folder_namespace(&entry.folder).is_some_and(|ns| is_chan_name_of(&ns, name))
        || surface.is_some_and(|s| {
            s.sync_group(&entry.folder)
                .is_some_and(|group| is_sync_name_of(&group, name))
        })
        || surface.is_some_and(|s| s.carries(name) || s.grant_carries(&entry.folder, name))
        // The sync groups, trust contexts and key and certificate names of
        // the other writers' namespaces the record in force lists, so the
        // person's device can validate what those writers wrote (live, per
        // packet: a writer the record drops is out at the next).
        || surface.is_some_and(|s| {
            s.writer_namespaces(&entry.folder)
                .iter()
                .any(|w| public_name(w, name))
        })
}

/// Whether `name` is an **ask of the data layer** to a device: its first keyword is
/// `32=grant` (the grant of a folder's epoch key), after plain components only (a
/// device's name), as the data layer routes a served name (`served_kind`: the first
/// component that is no plain one decides). The shape after the keyword is not judged
/// here: a name that is not an ask is refused by the data layer, and a link that rates
/// more names than the asks only rates what the data layer would refuse anyway. These
/// are what a link rates apart ([`crate::policy::DATA_ASKS`]).
pub(crate) fn is_data_ask(name: &Name) -> bool {
    use ndn_packet::tlv_type::{IMPLICIT_SHA256, KEYWORD, PARAMETERS_SHA256};
    let comps = name.components();
    let plain = |c: &NameComponent| !matches!(c.typ, KEYWORD | IMPLICIT_SHA256 | PARAMETERS_SHA256);
    comps.iter().position(|c| !plain(c)).is_some_and(|at| {
        at > 0 && comps[at].typ == KEYWORD && comps[at].value.as_ref() == b"grant"
    })
}

/// Whether `name` is `<device>/32=chan[/…]` for a device of `ns`: the ask of a
/// channel to that device (the channel layer names its setup under the
/// sender's device name) or the session answered under
/// it. The device's name is plain components under `ns` (the first component
/// that is no plain one decides, as for [`is_data_ask`]), and the keyword is
/// `chan`; what follows the keyword is the channel layer's to judge.
fn is_chan_name_of(ns: &Name, name: &Name) -> bool {
    use ndn_packet::tlv_type::{IMPLICIT_SHA256, KEYWORD, PARAMETERS_SHA256};
    let comps = name.components();
    let plain = |c: &NameComponent| !matches!(c.typ, KEYWORD | IMPLICIT_SHA256 | PARAMETERS_SHA256);
    name.has_prefix(ns)
        && comps.iter().position(|c| !plain(c)).is_some_and(|at| {
            at > ns.len() && comps[at].typ == KEYWORD && comps[at].value.as_ref() == b"chan"
        })
}

impl Judge<'_> {
    /// The names the link of the person holding `key` carries, judged at
    /// every packet in both directions (§8.7 rule 5) against the entries
    /// live then: only
    ///
    /// - the names under the person's own devices (`own`);
    /// - what any live entry carries ([`entry_carries`]): the public names of
    ///   its namespaces and its folder's, the introduction, and its folder's
    ///   collections.
    ///
    /// Nothing else this device serves by name crosses, so an unsealed
    /// collection outside the folders is not answered. The record of a mark
    /// of the key (a folder the person was let go of while other entries
    /// stand) is carried beside them; with **no** entry live a link the
    /// key's entries admitted carries the departure only
    /// (`Departures::carried_by`, §8.8) whether or not it has been narrowed
    /// or closed yet: a grant that ended carries nothing else from that
    /// instant.
    pub(crate) fn grant_names(&self, key: KeyFingerprint, own: Vec<Name>) -> NameFilter {
        let table = self.grants.clone();
        let departures = self.departures.clone();
        let surface = self.introductions.clone();
        Box::new(move |name: &Name| {
            let now = SystemTime::now();
            let entries = table.live_entries(&key, now);
            if entries.is_empty() {
                return departures.carried_by(&key, name, surface.as_ref(), now);
            }
            own.iter().any(|d| name.has_prefix(d))
                || entries
                    .iter()
                    .any(|e| entry_carries(surface.as_ref(), e, name))
                // The record that lets the person go of a folder whose entry
                // ended while another stands (§8.8): the person is told which
                // to fetch.
                || departures.carried_by(&key, name, surface.as_ref(), now)
        })
    }

    /// What the person holding `key` may push toward this device: Data under
    /// its own devices, or under the carried names of a live entry whose
    /// role is [`GrantRole::Writer`], judged at every packet. A reader entry
    /// widens nothing; a person who writes in one folder and reads in
    /// another pushes under the first folder's names only.
    pub(crate) fn grant_pushes(&self, key: KeyFingerprint, own: Vec<Name>) -> NameFilter {
        let table = self.grants.clone();
        let surface = self.introductions.clone();
        Box::new(move |name: &Name| {
            own.iter().any(|d| name.has_prefix(d))
                || table.live_entries(&key, SystemTime::now()).iter().any(|e| {
                    e.role == GrantRole::Writer && entry_carries(surface.as_ref(), e, name)
                })
        })
    }
}

/// The namespace of a folder name `<O>/32=data[/<path>]`: the components
/// before its `32=data` marker (heap.md §2.5); `None` for a name with
/// none or nothing before it.
pub(crate) fn folder_namespace(folder: &Name) -> Option<Name> {
    let at = folder
        .components()
        .iter()
        .position(|c| c.typ == ndn_packet::tlv_type::KEYWORD && c.value.as_ref() == b"data")?;
    (at > 0).then(|| Name::from_components(folder.components()[..at].iter().cloned()))
}

/// Whether `name` is of the sync group `group` and of no other group below it:
/// the sync protocol names a Sync Interest `<group>/v=N` (the version
/// component, then what the protocol appends), while a space nested in the
/// space (`<O>/32=data/n/f1` under `n`) has a group whose name extends the
/// group's with a generic component, which is never a version.
fn is_sync_name_of(group: &Name, name: &Name) -> bool {
    name.has_prefix(group)
        && name
            .components()
            .get(group.len())
            .is_some_and(|c| c.as_version().is_some())
}

/// A name of `ns` that is public by design: its sync group, its trust
/// context, a key or certificate name.
fn public_name(ns: &Name, name: &Name) -> bool {
    name.has_prefix(&sync_group(ns)) || public_name_outside_group(ns, name)
}

/// [`public_name`] but for the namespace's sync group: its trust context, a
/// key or certificate name.
fn public_name_outside_group(ns: &Name, name: &Name) -> bool {
    name.has_prefix(&rdr_prefix(ns))
        || (name.has_prefix(ns) && is_key_or_certificate_name(&name.components()[ns.len()..]))
}

/// `t` as `2026-11-18 14:03:22 UTC`.
pub(crate) fn utc(t: SystemTime) -> String {
    let secs = t
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_else(|e| -(e.duration().as_secs() as i64));
    let days = secs.div_euclid(86_400);
    let rest = secs.rem_euclid(86_400);
    // Civil date from days since 1970-01-01 (proleptic Gregorian).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} UTC",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_names_a_time_in_words() {
        assert_eq!(utc(UNIX_EPOCH), "1970-01-01 00:00:00 UTC");
        assert_eq!(
            utc(UNIX_EPOCH + Duration::from_secs(1_700_000_000)),
            "2023-11-14 22:13:20 UTC"
        );
        assert_eq!(
            utc(UNIX_EPOCH + Duration::from_secs(1_709_164_800)),
            "2024-02-29 00:00:00 UTC"
        );
    }

    fn grant(until: Option<SystemTime>) -> Grant {
        Grant {
            key: KeyFingerprint([5; 32]),
            namespaces: vec!["/bob".parse().unwrap()],
            folder: "/alice/32=data/notes".parse().unwrap(),
            role: GrantRole::Writer,
            until,
        }
    }

    /// A grant with no date follows the members record, which its host ends:
    /// the table never finds it due and never wakes the expiry task for it,
    /// and it is in force however long it has stood; a dated one is due at
    /// its date.
    #[test]
    fn a_grant_with_no_date_is_never_due_and_one_with_a_date_is() {
        let table = Grants::default();
        let now = SystemTime::now();
        table.put(grant(None));
        assert_eq!(table.next_until(), None);
        let far = now + Duration::from_secs(100 * 365 * 24 * 3600);
        assert!(table.take_due(far).is_empty());
        assert!(matches!(
            table.lookup(&KeyFingerprint([5; 32]), far),
            Lookup::Live(_)
        ));
        assert_eq!(
            grant(None).describe(),
            "granted with no end date (it follows the folder's members record) as a writer in /bob"
        );

        let table = Grants::default();
        let at = now + Duration::from_secs(10);
        table.put(grant(Some(at)));
        assert_eq!(table.next_until(), Some(at));
        assert!(table.take_due(now).is_empty());
        assert_eq!(table.take_due(at).len(), 1);
        assert!(table.take_due(at).is_empty(), "a grant ended twice");
    }

    /// The table holds entries per (key, folder): adding another folder keeps
    /// the first, and the same folder again replaces its entry only.
    #[test]
    fn a_key_holds_one_entry_per_folder() {
        let table = Grants::default();
        table.put(grant(None));
        let mut other = grant(None);
        other.folder = "/alice/32=data/diary".parse().unwrap();
        other.role = GrantRole::Reader;
        table.put(other.clone());
        assert_eq!(table.list().len(), 2);
        let mut changed = grant(None);
        changed.role = GrantRole::Reader;
        table.put(changed.clone());
        let listed = table.list();
        assert_eq!(listed.len(), 2, "replaced in place, not added");
        assert!(listed.contains(&changed) && listed.contains(&other));
        // Sorted by key then folder.
        assert!(listed[0].folder < listed[1].folder);
    }

    /// The identity of a device of `ns`, as a link a grant admitted holds it.
    fn identity(ns: &str) -> Identity {
        Identity {
            namespace: ns.parse().unwrap(),
            version: 1,
            device: format!("{ns}/member/phone").parse().unwrap(),
            role: ndn_cert::roles::Role::Member,
            certificates: Vec::new(),
            served: None,
            lapses: None,
        }
    }

    /// A link is checked against the entries of its key: it stands while one
    /// of them admits an identity it was admitted by, and says what ended
    /// it when none does.
    #[test]
    fn a_link_stands_while_an_entry_of_its_key_does_and_says_what_ended_it() {
        let table = Grants::default();
        let ids = [identity("/bob")];
        let admitted = grant(Some(SystemTime::now() + Duration::from_secs(3600)));
        table.put(admitted.clone());
        assert!(table.has_live(&admitted.key, SystemTime::now()));
        assert!(table.ended_since(&admitted, &ids).is_none());

        // Another folder is another entry: the first still stands, and the
        // link it admitted stays.
        let mut other = admitted.clone();
        other.folder = "/alice/32=data/diary".parse().unwrap();
        table.put(other.clone());
        assert_eq!(
            table.live_entries(&admitted.key, SystemTime::now()).len(),
            2
        );
        assert!(table.ended_since(&admitted, &ids).is_none());

        // The same folder with namespaces the link was not admitted in: no
        // entry admits it any more.
        let mut elsewhere = other.clone();
        elsewhere.namespaces = vec!["/carol".parse().unwrap()];
        assert!(table.take(&admitted.key, &admitted.folder).is_some());
        table.put(elsewhere);
        let why = table.ended_since(&admitted, &ids).expect("replaced");
        assert!(why.text.contains("replaced"), "{}", why.text);

        // Past its date: expired, whether or not the task has swept it.
        let table = Grants::default();
        table.put(grant(Some(SystemTime::now() - Duration::from_secs(1))));
        assert!(!table.has_live(&admitted.key, SystemTime::now()));
        let why = table.ended_since(&admitted, &ids).expect("expired");
        assert!(why.text.contains("it expired"), "{}", why.text);

        // Gone from the table with nothing remembered: revoked.
        let empty = Grants::default();
        let why = empty.ended_since(&admitted, &ids).expect("revoked");
        assert!(why.text.contains("revoked"), "{}", why.text);
    }

    /// Entries of one key end one by one: the refusal of the key names the
    /// entry that ended last, the table remembers the last 64, and an entry
    /// ending while another stands leaves the key live.
    #[test]
    fn entries_end_one_by_one_and_the_refusal_names_the_one_ended_last() {
        let table = Grants::default();
        let key = KeyFingerprint([5; 32]);
        let notes: Name = "/alice/32=data/notes".parse().unwrap();
        let diary: Name = "/alice/32=data/diary".parse().unwrap();
        let hour = Some(SystemTime::now() + Duration::from_secs(3600));
        table.put(grant(hour));
        let mut second = grant(hour);
        second.folder = diary.clone();
        table.put(second);

        assert!(table.take(&key, &notes).is_some());
        assert!(
            table.has_live(&key, SystemTime::now()),
            "the diary entry stands"
        );
        assert!(table.take(&key, &diary).is_some());
        let Lookup::Ended(detail) = table.lookup(&key, SystemTime::now()) else {
            panic!("no entry stands")
        };
        assert_eq!(
            detail.param("folder"),
            Some(diary.to_string().as_str()),
            "the entry ended last is named: {detail:?}"
        );
        assert_eq!(detail.param("ended"), Some("revoked"));
        assert!(table.take(&key, &diary).is_none(), "ended twice");

        // Granting a folder again drops its memory; the other stays.
        table.put(grant(hour));
        assert_eq!(table.list().len(), 1);

        // The last 64 ended entries are remembered, per (key, folder).
        let table = Grants::default();
        for i in 0..70u8 {
            let mut g = grant(hour);
            g.key = KeyFingerprint([i; 32]);
            table.put(g.clone());
            table.take(&g.key, &g.folder);
        }
        let ended = table.inner.state.lock().ended.len();
        assert_eq!(ended, ENDED_MAX);
        assert!(matches!(
            table.lookup(&KeyFingerprint([0; 32]), SystemTime::now()),
            Lookup::None
        ));
        assert!(matches!(
            table.lookup(&KeyFingerprint([69; 32]), SystemTime::now()),
            Lookup::Ended(_)
        ));
    }

    /// Entries run out one by one at their own dates, and the expiry task
    /// treats the key's last as the end of the person.
    #[test]
    fn due_entries_are_taken_each_and_the_last_of_a_key_is_marked() {
        let table = Grants::default();
        let now = SystemTime::now();
        let soon = now + Duration::from_secs(10);
        let later = now + Duration::from_secs(20);
        table.put(grant(Some(soon)));
        let mut second = grant(Some(later));
        second.folder = "/alice/32=data/diary".parse().unwrap();
        table.put(second);
        assert_eq!(table.next_until(), Some(soon));
        let first = table.take_due(soon);
        assert_eq!(first.len(), 1);
        assert!(!first[0].1, "an entry of the key still stands");
        assert_eq!(table.next_until(), Some(later));
        let last = table.take_due(later);
        assert_eq!(last.len(), 1);
        assert!(last[0].1, "the key's last entry ran out");
    }

    /// The wall clock is read again within a minute whatever the next date
    /// is: the sleep runs on the monotonic clock, which stands still while a
    /// machine is suspended and does not follow a step of the wall clock.
    #[test]
    fn the_expiry_task_reads_the_wall_clock_at_least_once_a_minute() {
        let now = SystemTime::now();
        let hour = now + Duration::from_secs(3600);
        assert_eq!(sleep_for(Some(hour), now), Some(Duration::from_secs(60)));
        assert_eq!(
            sleep_for(Some(now + Duration::from_secs(5)), now),
            Some(Duration::from_secs(5))
        );
        assert_eq!(
            sleep_for(Some(now - Duration::from_secs(5)), now),
            Some(Duration::ZERO)
        );
        assert_eq!(
            sleep_for(None, now),
            None,
            "no dated grant: wait to be woken"
        );
    }

    /// What a data layer lists as writers, changing under the link.
    struct Writers(parking_lot::Mutex<Vec<Name>>);

    impl Introductions for Writers {
        fn open(&self) -> bool {
            false
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
        fn writer_namespaces(&self, _: &Name) -> Vec<Name> {
            self.0.lock().clone()
        }
    }

    /// The sync group, trust context and key and certificate names of a
    /// namespace the record lists as a writer's are carried by the entry, at
    /// the next packet after the record lists it and not after it stops;
    /// nothing else of that namespace is (a collection of the writer's own
    /// outside the folder), whether it is listed or not.
    #[test]
    fn the_public_names_of_a_listed_writer_are_carried_live_and_nothing_else_of_hers() {
        let n = |s: &str| -> Name { s.parse().unwrap() };
        let writers = Arc::new(Writers(parking_lot::Mutex::new(Vec::new())));
        let surface: Arc<dyn Introductions> = writers.clone();
        let entry = grant(None);
        let carried = |name: &str| entry_carries(Some(&surface), &entry, &n(name));
        let public = [
            "/carol/32=sync/x",
            "/carol/KEY/k1",
            "/carol/member/phone/KEY/k1/self/v=1",
        ];
        let diary = "/carol/member/phone/32=log/carol/32=data/diary/seq=1";
        for name in public {
            assert!(
                !carried(name),
                "{name} carried before the record lists Carol"
            );
        }
        *writers.0.lock() = vec![n("/carol")];
        for name in public {
            assert!(
                carried(name),
                "{name} not carried while the record lists Carol"
            );
        }
        // Nor is an entry of a collection of hers whose path has a literal
        // `KEY` component taken for a key or certificate name.
        for lookalike in [
            "/carol/member/phone/32=log/carol/32=data/diary/KEY/x/seq=3",
            "/carol/32=data/KEY/x",
        ] {
            assert!(!carried(lookalike), "{lookalike} taken for a key name");
        }
        assert!(
            !carried(diary),
            "a collection of hers outside the folder is carried"
        );
        writers.0.lock().clear();
        for name in public {
            assert!(
                !carried(name),
                "{name} still carried after the record dropped Carol"
            );
        }
        assert!(!carried(diary));
    }

    fn nm(s: &str) -> Name {
        s.parse().unwrap()
    }

    fn keyword(word: &'static str) -> NameComponent {
        NameComponent::keyword(bytes::Bytes::from_static(word.as_bytes()))
    }

    /// A component of `typ` holding 32 octets.
    fn octets(typ: u64) -> NameComponent {
        NameComponent::new(typ, bytes::Bytes::from_static(&[7; 32]))
    }

    fn then(name: &str, tail: Vec<NameComponent>) -> Name {
        tail.into_iter().fold(nm(name), Name::append_component)
    }

    const GENERIC: u64 = ndn_packet::tlv_type::NAME_COMPONENT;
    const PARAMETERS: u64 = ndn_packet::tlv_type::PARAMETERS_SHA256;

    /// R12 H1: the data layer's asks of a device (`32=grant` right after its name) are what
    /// a link rates apart for them, by the first keyword as the data layer routes a name;
    /// nothing else is.
    #[test]
    fn the_data_layers_asks_are_rated_by_their_first_keyword() {
        let device = "/alice/member/laptop";
        let name = then(device, vec![keyword("grant"), octets(GENERIC)]);
        assert!(is_data_ask(&name), "32=grant after a device name");
        // A device name of any depth, and a name with a tail the data layer would refuse.
        assert!(is_data_ask(&then(
            "/alice/laptop",
            vec![keyword("grant"), octets(GENERIC)]
        )));
        assert!(is_data_ask(&then(
            "/a/b/c/d/e",
            vec![keyword("grant"), octets(GENERIC)]
        )));
        assert!(
            is_data_ask(&name.clone().append_component(octets(GENERIC))),
            "a longer name is rated too: nothing slips by the shape"
        );
        assert!(
            !is_data_ask(&nm("/alice/member/laptop/grant/x")),
            "a plain component is no keyword"
        );
        // The first non-plain component decides, as `served_kind` does.
        assert!(!is_data_ask(&then(
            device,
            vec![keyword("log"), keyword("grant"), octets(GENERIC)]
        )));
        assert!(!is_data_ask(&then(
            device,
            vec![octets(PARAMETERS), keyword("grant")]
        )));
        // No device name before the keyword: not a served name.
        assert!(!is_data_ask(&Name::from_components([
            keyword("grant"),
            octets(GENERIC)
        ])));
        // Other served kinds and fetches are not asks of this class.
        for other in ["held", "seal", "intro", "hint", "log"] {
            assert!(
                !is_data_ask(&then(device, vec![keyword(other), octets(GENERIC)])),
                "{other}"
            );
        }
    }
}
