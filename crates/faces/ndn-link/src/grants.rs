//! Grants: the one person an introduction admitted links here, under the
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
//! devices and of the introduction (`Introductions::grant_carries`): not
//! everything this device serves by name.
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
use ndn_packet::Name;
use ndn_security::sync_group;
use parking_lot::Mutex;
use tokio::sync::Notify;

use crate::admission::{Identity, Judge, Refusal, is_key_or_certificate_name, list as list_of};
use crate::links::Links;
use crate::serving::{QuotaSlot, Quotas, ServePolicy};

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
/// `namespaces`, in the scope of `folder`, until `until`.
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

    /// Whether `other` admits the same links: the same namespaces, folder
    /// and role (its `until` may differ).
    fn same_scope(&self, other: &Grant) -> bool {
        self.role == other.role
            && self.namespaces == other.namespaces
            && self.folder == other.folder
    }

    /// Whether the grant has run out by `now`.
    fn over(&self, now: SystemTime) -> bool {
        self.until.is_some_and(|until| until <= now)
    }
}

/// How a grant ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum How {
    Expired,
    Revoked,
    /// Replaced by a grant of other namespaces or another role.
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
            Self::Replaced => "it was replaced by a grant of other namespaces or another role",
        }
    }
}

/// A grant that ended: what is left of it to name in a refusal.
#[derive(Clone, Debug)]
struct EndedGrant {
    key: KeyFingerprint,
    namespaces: Vec<Name>,
    until: Option<SystemTime>,
    how: How,
}

impl EndedGrant {
    fn detail(&self) -> LinkDetail {
        let until = match self.until {
            Some(until) => format!("until {}", utc(until)),
            None => "with no end date".to_string(),
        };
        LinkDetail::new(
            code::GRANT_ENDED,
            format!(
                "your key {} was granted a link here as a person of {}, {until}, and the grant ended: \
                 {}. Ask the person who invited you to invite you again",
                self.key,
                list_of(&self.namespaces),
                self.how.words()
            ),
        )
        .with("key", self.key)
        .with("namespaces", list_of(&self.namespaces))
        .with("until", self.until.map_or_else(|| "none".to_string(), utc))
        .with("ended", self.how.as_str())
    }
}

/// How many ended grants are remembered to name in refusals: the oldest are
/// forgotten.
const ENDED_MAX: usize = 64;

/// The longest the expiry task sleeps at once. The sleep runs on the monotonic
/// clock, which stands still while a machine is suspended, and the grants'
/// dates are on the wall clock, which may be set: so the task looks at the
/// wall clock again at least this often while a dated grant is in force, and a
/// suspend or a step is seen within it.
const SLEEP_MAX: Duration = Duration::from_secs(60);

#[derive(Default)]
struct State {
    live: HashMap<KeyFingerprint, Grant>,
    ended: VecDeque<EndedGrant>,
}

impl State {
    fn end(&mut self, grant: &Grant, how: How) {
        self.ended.retain(|e| e.key != grant.key);
        if self.ended.len() == ENDED_MAX {
            self.ended.pop_front();
        }
        self.ended.push_back(EndedGrant {
            key: grant.key,
            namespaces: grant.namespaces.clone(),
            until: grant.until,
            how,
        });
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
    Live(Grant),
    Ended(LinkDetail),
    None,
}

impl Grants {
    /// A grant in force, for the judge's tests (the table without a `Links`).
    #[cfg(test)]
    pub(crate) fn put(&self, grant: Grant) {
        self.inner.state.lock().live.insert(grant.key, grant);
    }

    /// The grant of `key` now: live while it has not run out (the expiry
    /// task may not have swept it yet), else what is known of its end.
    pub(crate) fn lookup(&self, key: &KeyFingerprint, now: SystemTime) -> Lookup {
        let state = self.inner.state.lock();
        if let Some(grant) = state.live.get(key) {
            if !grant.over(now) {
                return Lookup::Live(grant.clone());
            }
            return Lookup::Ended(How::Expired.ended(grant).detail());
        }
        match state.ended.iter().find(|e| e.key == *key) {
            Some(e) => Lookup::Ended(e.detail()),
            None => Lookup::None,
        }
    }

    /// The live grant of `key`, if it has not run out.
    pub(crate) fn live(&self, key: &KeyFingerprint) -> Option<Grant> {
        match self.lookup(key, SystemTime::now()) {
            Lookup::Live(g) => Some(g),
            _ => None,
        }
    }

    /// Whether the table still holds `admitted` as it was when a link was
    /// admitted by it: live now, with the same namespaces, folder and role.
    /// Judged on the wall clock at each call, so it never lags the expiry
    /// task. It copies nothing: the names a grant link carries are judged
    /// with it at every packet.
    pub(crate) fn stands(&self, admitted: &Grant) -> bool {
        let now = SystemTime::now();
        self.inner
            .state
            .lock()
            .live
            .get(&admitted.key)
            .is_some_and(|g| !g.over(now) && g.same_scope(admitted))
    }

    /// `None` while the table still holds `admitted` ([`Self::stands`]);
    /// else what ended it, to say to the person whose link it was.
    pub(crate) fn ended_since(&self, admitted: &Grant) -> Option<LinkDetail> {
        let now = SystemTime::now();
        match self.lookup(&admitted.key, now) {
            Lookup::Live(g) if g.same_scope(admitted) => None,
            Lookup::Live(_) => Some(How::Replaced.ended(admitted).detail()),
            Lookup::Ended(detail) => Some(detail),
            Lookup::None => Some(How::Revoked.ended(admitted).detail()),
        }
    }

    /// The grants in force now.
    fn list(&self) -> Vec<Grant> {
        let now = SystemTime::now();
        let state = self.inner.state.lock();
        let mut grants: Vec<Grant> = state
            .live
            .values()
            .filter(|g| !g.over(now))
            .cloned()
            .collect();
        grants.sort_by_key(|g| g.key);
        grants
    }

    /// The earliest `until` of the live grants that have one.
    fn next_until(&self) -> Option<SystemTime> {
        self.inner
            .state
            .lock()
            .live
            .values()
            .filter_map(|g| g.until)
            .min()
    }

    /// The grants that ran out by `now`, ended.
    fn take_due(&self, now: SystemTime) -> Vec<Grant> {
        let mut state = self.inner.state.lock();
        let due: Vec<KeyFingerprint> = state
            .live
            .values()
            .filter(|g| g.over(now))
            .map(|g| g.key)
            .collect();
        due.into_iter()
            .filter_map(|key| {
                let grant = state.live.remove(&key)?;
                state.end(&grant, How::Expired);
                Some(grant)
            })
            .collect()
    }
}

/// How long the expiry task sleeps before it looks at the wall clock again,
/// given the earliest `until` of the grants in force (`None`: no grant has a
/// date, the task waits to be woken): until then, but never more than
/// [`SLEEP_MAX`].
fn sleep_for(next: Option<SystemTime>, now: SystemTime) -> Option<Duration> {
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
                    () = cancel.cancelled() => return,
                    () = grants.inner.wake.notified() => continue,
                    () = sleep => {}
                }
                let Some(links) = weak.upgrade() else { return };
                for grant in links.grants.take_due(SystemTime::now()) {
                    links.close_granted(&grant.key, How::Expired.ended(&grant));
                }
            }
        });
    }

    /// Grants the device holding `grant.key` a link here as a person of
    /// `grant.namespaces`, in the scope of `grant.folder`, until
    /// `grant.until` (replacing an earlier grant of the same key). A grant
    /// never serves what the serving policy's quotas, the namespace's link
    /// policy or a revocation refuse, and under `serve = open` it adds
    /// nothing. A link the earlier grant admitted stays when only `until`
    /// changed; with other namespaces, folder or role it is closed (the
    /// device dials again and is judged by the new one).
    pub fn grant(&self, grant: Grant) {
        let key = grant.key;
        let now = SystemTime::now();
        let previous = {
            let mut state = self.grants.inner.state.lock();
            state.ended.retain(|e| e.key != key);
            if grant.over(now) {
                // Granted already over: it ends what it replaces.
                let previous = state.live.remove(&key);
                state.end(&grant, How::Expired);
                previous.map(|p| (p, How::Expired))
            } else {
                let previous = state.live.insert(key, grant.clone());
                previous
                    .filter(|p| !p.same_scope(&grant))
                    .map(|p| (p, How::Replaced))
            }
        };
        self.grants.inner.wake.notify_one();
        if let Some((previous, how)) = previous {
            self.close_granted(&key, how.ended(&previous));
        }
    }

    /// Ends the grant of `key` now, and closes the links it alone admitted
    /// ([`CloseReason::NotServed`], saying what ended and what to do).
    /// `true` when one was in force.
    pub fn revoke_grant(&self, key: &KeyFingerprint) -> bool {
        let grant = {
            let mut state = self.grants.inner.state.lock();
            let Some(grant) = state.live.remove(key) else {
                return false;
            };
            state.end(&grant, How::Revoked);
            grant
        };
        self.grants.inner.wake.notify_one();
        self.close_granted(key, How::Revoked.ended(&grant));
        true
    }

    /// The grants in force now.
    pub fn grants(&self) -> Vec<Grant> {
        self.grants.list()
    }

    /// The grant that admitted the link of `key`, as it stands now (the live
    /// grant, else the one the link was admitted by), for the report.
    pub(crate) fn grant_of_link(&self, admitted_by: &Grant) -> Grant {
        self.grants
            .live(&admitted_by.key)
            .unwrap_or_else(|| admitted_by.clone())
    }

    /// Closes the links of `key` that only a grant admitted.
    fn close_granted(&self, key: &KeyFingerprint, ended: EndedGrant) {
        let detail = ended.detail();
        let closed = self
            .table
            .close_granted(key, CloseReason::NotServed, &detail.text);
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

impl How {
    fn ended(self, grant: &Grant) -> EndedGrant {
        EndedGrant {
            key: grant.key,
            namespaces: grant.namespaces.clone(),
            until: grant.until,
            how: self,
        }
    }
}

/// What the grants make of a link the serving policy declined.
pub(crate) enum GrantOutcome {
    /// Admitted: the identities the grant admits, each with its quota slot,
    /// and the grant.
    Admitted(Vec<(Identity, QuotaSlot)>, Grant),
    /// The grant matched and the quotas (or a name collision) refuse.
    Refused(Refusal),
    /// No grant admits it; what is worth telling the refused device about
    /// grants, if anything.
    No(Option<LinkDetail>),
}

impl Judge<'_> {
    /// Consulted where the serving policy served none of the identities of
    /// `fingerprint` (`declined`: those its policy declined — not the ones
    /// refused for quotas or a name collision): a live grant of the key
    /// admits the identities in the namespaces it lists, if they validate in
    /// a namespace this device holds (never one served by a root it does not
    /// hold). Under `open` it adds nothing.
    pub(crate) fn grant_for(
        &self,
        fingerprint: KeyFingerprint,
        declined: &[Identity],
    ) -> GrantOutcome {
        if matches!(self.serve, ServePolicy::Open { .. }) {
            return GrantOutcome::No(None);
        }
        let grant = match self.grants.lookup(&fingerprint, SystemTime::now()) {
            Lookup::None => return GrantOutcome::No(None),
            Lookup::Ended(detail) => return GrantOutcome::No(Some(detail)),
            Lookup::Live(grant) => grant,
        };
        let matching: Vec<&Identity> = declined
            .iter()
            .filter(|id| id.served.is_none() && grant.namespaces.contains(&id.namespace))
            .collect();
        if matching.is_empty() {
            let shown: Vec<Name> = declined.iter().map(|id| id.namespace.clone()).collect();
            return GrantOutcome::No(Some(
                LinkDetail::new(
                    code::GRANT_UNMATCHED,
                    format!(
                        "your key {fingerprint} is granted a link here as a person of {}, and the \
                         certificates you showed are of {}: link with the certificate of one the \
                         grant lists",
                        list_of(&grant.namespaces),
                        if shown.is_empty() {
                            "no namespace this device holds".to_string()
                        } else {
                            list_of(&shown)
                        }
                    ),
                )
                .with("key", fingerprint)
                .with("namespaces", list_of(&grant.namespaces))
                .with("shown", list_of(&shown)),
            ));
        }
        let quotas = match self.serve {
            ServePolicy::Listed {
                quotas: Some(quotas),
                ..
            } => *quotas,
            _ => Quotas::default(),
        };
        let mut admitted = Vec::with_capacity(matching.len());
        for id in matching {
            // The held context's first anchor (by fingerprint order), as an
            // open policy binds a held namespace.
            let Some(root) = self.held_roots(&id.namespace).into_iter().min() else {
                continue;
            };
            match self.quotas.take(&id.namespace, root, Some(&quotas)) {
                Ok(slot) => admitted.push((id.clone(), slot)),
                Err(refusal) => return GrantOutcome::Refused(refusal),
            }
        }
        if admitted.is_empty() {
            return GrantOutcome::No(None);
        }
        GrantOutcome::Admitted(admitted, grant)
    }
}

impl Judge<'_> {
    /// The names the link of `grant` carries, judged at every packet in both
    /// directions (§8.7 rule 5): only
    ///
    /// - the names under the person's own devices (`own`);
    /// - the sync groups, trust contexts and key and certificate names of
    ///   the grant's namespaces and of the folder's (public by design: a
    ///   hello already carries the chain, and the group carries no data);
    /// - what this device's introductions serve
    ///   ([`Introductions::carries`](crate::Introductions::carries): a
    ///   person may ask again); and
    /// - the names of the folder's collections as the data layer names them
    ///   ([`Introductions::grant_carries`](crate::Introductions::grant_carries)).
    ///
    /// Nothing else this device serves by name crosses, so an unsealed
    /// collection outside the folder is not answered. Judged against the
    /// live table at each packet, a grant that ended carries nothing from
    /// that instant, whether or not its link has been closed yet. A device
    /// with no data layer (no [`Introductions`](crate::Introductions) given)
    /// carries the first three kinds and no folder.
    pub(crate) fn grant_names(&self, grant: &Grant, own: Vec<Name>) -> NameFilter {
        let table = self.grants.clone();
        let admitted = grant.clone();
        let surface = self.introductions.clone();
        let mut namespaces = grant.namespaces.clone();
        if let Some(ns) = folder_namespace(&grant.folder)
            && !namespaces.contains(&ns)
        {
            namespaces.push(ns);
        }
        Box::new(move |name: &Name| {
            table.stands(&admitted)
                && (own.iter().any(|d| name.has_prefix(d))
                    || namespaces.iter().any(|ns| public_name(ns, name))
                    || surface.as_ref().is_some_and(|s| {
                        s.carries(name) || s.grant_carries(&admitted.folder, name)
                    }))
        })
    }
}

/// The namespace of a folder name `<O>/32=data[/<path>]`: the components
/// before its `32=data` marker (data-layer.md §3); `None` for a name with
/// none or nothing before it.
fn folder_namespace(folder: &Name) -> Option<Name> {
    let at = folder
        .components()
        .iter()
        .position(|c| c.typ == ndn_packet::tlv_type::KEYWORD && c.value.as_ref() == b"data")?;
    (at > 0).then(|| Name::from_components(folder.components()[..at].iter().cloned()))
}

/// A name of `ns` that is public by design: its sync group, its trust
/// context, a key or certificate name.
fn public_name(ns: &Name, name: &Name) -> bool {
    name.has_prefix(&sync_group(ns))
        || name.has_prefix(&rdr_prefix(ns))
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

    /// A link is checked against the grant that admitted it: still the same
    /// scope, or what ended it.
    #[test]
    fn a_link_stands_while_its_grant_does_and_says_what_ended_it() {
        let table = Grants::default();
        let admitted = grant(Some(SystemTime::now() + Duration::from_secs(3600)));
        table.put(admitted.clone());
        assert!(table.stands(&admitted));
        assert!(table.ended_since(&admitted).is_none());

        // Replaced by another folder: not the grant the link was admitted by.
        let mut other = admitted.clone();
        other.folder = "/alice/32=data/diary".parse().unwrap();
        table.put(other);
        assert!(!table.stands(&admitted));
        let why = table.ended_since(&admitted).expect("replaced");
        assert!(why.text.contains("replaced"), "{}", why.text);

        // Past its date: expired, whether or not the task has swept it.
        table.put(grant(Some(SystemTime::now() - Duration::from_secs(1))));
        assert!(!table.stands(&admitted));
        let why = table.ended_since(&admitted).expect("expired");
        assert!(why.text.contains("it expired"), "{}", why.text);

        // Gone from the table with nothing remembered: revoked.
        let empty = Grants::default();
        let why = empty.ended_since(&admitted).expect("revoked");
        assert!(why.text.contains("revoked"), "{}", why.text);
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
}
