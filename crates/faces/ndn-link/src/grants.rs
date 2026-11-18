//! Grants: the one person an introduction admitted links here, under the
//! default serving policy (`ndn-rs/docs/specs/ndn-link.md` §8.7).
//!
//! A [`Grant`] says: the device holding link key `key` may link here, as a
//! person of the `namespaces`, until `until`. The serving policy `own` serves
//! the namespaces this device holds a certificate in and no others, so the
//! person an inviter just admitted — of another namespace, whose context it
//! now holds — would be refused; the grant serves exactly that key in exactly
//! those namespaces, and nothing else. It is host-supplied authority to
//! *link*, not to read: what the link carries is what the layer above serves
//! it.
//!
//! The grants are a live table in memory by key; the host owns them (the
//! data layer's device re-derives them at start from signed, durable data
//! — `LinkHints::serve`). Expiry is judged on every admission and by one
//! task that sleeps until the earliest `until`; a grant that ended closes
//! the links it alone admitted and is named in the refusal of the next dial
//! of its key.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ndn_face_quic::{CloseReason, KeyFingerprint};
use ndn_mgmt_wire::{LinkDetail, link_code as code};
use ndn_packet::Name;
use parking_lot::Mutex;
use tokio::sync::Notify;

use crate::admission::{Identity, Judge, Refusal, list as list_of};
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
/// `namespaces`, until `until`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    /// The link key the person's device proves in the handshake.
    pub key: KeyFingerprint,
    /// The namespaces the person may be identified in: the link is admitted
    /// by those of its certificates and memberships that validate in one of
    /// these, and by no other.
    pub namespaces: Vec<Name>,
    pub role: GrantRole,
    pub until: SystemTime,
}

impl Grant {
    /// The grant in words: `granted until 2026-11-18 14:03:22 UTC as a
    /// writer in /bob`.
    pub fn describe(&self) -> String {
        format!(
            "granted until {} as a {} in {}",
            utc(self.until),
            self.role.as_str(),
            list_of(&self.namespaces)
        )
    }

    /// Whether `other` admits the same links: the same namespaces and role
    /// (its `until` may differ).
    fn same_scope(&self, other: &Grant) -> bool {
        self.role == other.role && self.namespaces == other.namespaces
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
    until: SystemTime,
    how: How,
}

impl EndedGrant {
    fn detail(&self) -> LinkDetail {
        LinkDetail::new(
            code::GRANT_ENDED,
            format!(
                "your key {} was granted a link here as a person of {}, until {}, and the grant ended: \
                 {}. Ask the person who invited you to invite you again",
                self.key,
                list_of(&self.namespaces),
                utc(self.until),
                self.how.words()
            ),
        )
        .with("key", self.key)
        .with("namespaces", list_of(&self.namespaces))
        .with("until", utc(self.until))
        .with("ended", self.how.as_str())
    }
}

/// How many ended grants are remembered to name in refusals: the oldest are
/// forgotten.
const ENDED_MAX: usize = 64;

/// The longest the expiry task sleeps at once (a wall clock may be set).
const SLEEP_MAX: Duration = Duration::from_secs(3600);

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

    /// The grant of `key` now: live while its `until` is in the future (the
    /// expiry task may not have swept it yet), else what is known of its
    /// end.
    pub(crate) fn lookup(&self, key: &KeyFingerprint, now: SystemTime) -> Lookup {
        let state = self.inner.state.lock();
        if let Some(grant) = state.live.get(key) {
            if grant.until > now {
                return Lookup::Live(grant.clone());
            }
            return Lookup::Ended(
                EndedGrant {
                    key: grant.key,
                    namespaces: grant.namespaces.clone(),
                    until: grant.until,
                    how: How::Expired,
                }
                .detail(),
            );
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

    /// The grants in force now.
    fn list(&self) -> Vec<Grant> {
        let now = SystemTime::now();
        let state = self.inner.state.lock();
        let mut grants: Vec<Grant> = state
            .live
            .values()
            .filter(|g| g.until > now)
            .cloned()
            .collect();
        grants.sort_by_key(|g| g.key);
        grants
    }

    /// The earliest `until` of the live grants.
    fn next_until(&self) -> Option<SystemTime> {
        self.inner.state.lock().live.values().map(|g| g.until).min()
    }

    /// The grants that ran out by `now`, ended.
    fn take_due(&self, now: SystemTime) -> Vec<Grant> {
        let mut state = self.inner.state.lock();
        let due: Vec<KeyFingerprint> = state
            .live
            .values()
            .filter(|g| g.until <= now)
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

impl Links {
    /// Starts the one task that ends grants when they run out: it sleeps
    /// until the earliest `until` and wakes when a grant is made or ended.
    pub(crate) fn spawn_grant_expiry(self: &Arc<Self>) {
        let grants = self.grants.clone();
        let weak = Arc::downgrade(self);
        let cancel = self.cancel_token().clone();
        tokio::spawn(async move {
            loop {
                let next = grants.next_until();
                let sleep = async {
                    match next {
                        Some(at) => {
                            let wait = at
                                .duration_since(SystemTime::now())
                                .unwrap_or_default()
                                .min(SLEEP_MAX);
                            tokio::time::sleep(wait).await;
                        }
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
    /// `grant.namespaces`, until `grant.until` (replacing an earlier grant of
    /// the same key). A grant never serves what the serving policy's
    /// quotas, the namespace's link policy or a revocation refuse, and under
    /// `serve = open` it adds nothing. A link the earlier grant admitted
    /// stays when only `until` changed; with other namespaces or another
    /// role it is closed (the device dials again and is judged by the new
    /// one).
    pub fn grant(&self, grant: Grant) {
        let key = grant.key;
        let now = SystemTime::now();
        let previous = {
            let mut state = self.grants.inner.state.lock();
            state.ended.retain(|e| e.key != key);
            if grant.until <= now {
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
}
