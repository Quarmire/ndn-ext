//! A person let go is told (`ndn-rs/docs/specs/ndn-link.md` §8.8).
//!
//! When a held members record leaves a granted person out of a folder, the
//! data layer ends the grant entry and installs a **departure mark**
//! ([`Links::depart`]): the key, the folder, the log entry name of the record
//! that leaves the person out and the date after which the mark is no longer
//! served. The link the entry admitted does not just close:
//!
//! - **online**, when the last entry of the key ends the link **narrows in
//!   place** (the scope's [`Narrowing`](ndn_face_quic::Narrowing)): Interests
//!   only toward this device, answers only toward the peer, and a name filter
//!   judged at every packet that carries the record, its pieces, its cut
//!   manifests and the key and certificate names of the folder's namespace,
//!   nothing else. The inviter sends the person one `Departure` message
//!   naming the folder and the record, which the person's `Links` hands to a
//!   [`DepartureSink`];
//! - **offline**, a device whose key has no live entry and a mark is admitted
//!   on a **departure link** of the same shape, in the enrollment slots, at
//!   most [`DepartureOptions::attempts`] times per key per mark, and only for
//!   a key whose grant note (MAC'd) made the mark: a key that never held a
//!   grant has no mark.
//!
//! The link closes when the record's entry has been carried and
//! [`DepartureOptions::settle`] has passed (so its cut manifests follow), or
//! after [`DepartureOptions::hold`], or at the idle close, with the
//! `let-go` detail naming the folder and the record. Nothing here grants a
//! route, presence, a sync group or a quota slot.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use ndn_face_quic::{CloseReason, Departure as Told, KeyFingerprint, LinkHandle, NameFilter};
use ndn_mgmt_wire::{LinkDetail, link_code as code};
use ndn_packet::Name;
use ndn_packet::tlv_type::IMPLICIT_SHA256;
use parking_lot::Mutex;
use tokio::sync::watch;

use crate::admission::{Admitted, Enrollment, Judge, is_key_or_certificate_name};
use crate::grants::folder_namespace;
use crate::introduce::Introductions;
use crate::links::Links;

/// A person let go of a folder: the key of the person's device (the grant's),
/// the namespaces the grant admitted it in, the folder, the log entry name of
/// the held members record that leaves it out and the date after which the
/// mark is no longer served.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Departure {
    pub key: KeyFingerprint,
    pub namespaces: Vec<Name>,
    pub folder: Name,
    /// `<signer device>/32=log/<folder>/seq=<n>`: its pieces and its cut
    /// manifests are named by it and carried with it.
    pub record: Name,
    /// By this device's clock: the mark is no longer served after it.
    pub until: SystemTime,
}

/// How a departure is served ([`Links::set_departure_options`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DepartureOptions {
    /// The longest a departure link lasts from its admission, or from the
    /// narrowing of a link. Default 30 s.
    pub hold: Duration,
    /// How long after the record's entry crossed the link stays, so the
    /// record's cut manifests follow. Default 2 s.
    pub settle: Duration,
    /// How many departure links one mark admits (per key per mark), counted
    /// in memory and not reset by a new link. Default 3.
    pub attempts: u32,
    /// How many marks are kept: past it the oldest are forgotten. Default 256.
    pub marks_max: usize,
}

impl Default for DepartureOptions {
    fn default() -> Self {
        Self {
            hold: Duration::from_secs(30),
            settle: Duration::from_secs(2),
            attempts: 3,
            marks_max: 256,
        }
    }
}

/// What a departure sink takes: a future of the result.
pub type DepartureTaking<'a> = Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;

/// The person's half: what to do with the members record the inviter named.
/// For a data-layer device it fetches and takes the record
/// (`Device::take_departure`); [`LinkHints::serve`](crate::LinkHints::serve)
/// registers the device's.
pub trait DepartureSink: Send + Sync {
    /// The inviter that let this device go told it that the members record
    /// named `record` of `folder` leaves it out (a hint, with no authority:
    /// the sink fetches the record and takes it only as it validates, for a
    /// folder it is a member of). `Err` is why it was not taken, in words.
    fn departure<'a>(&'a self, folder: &'a Name, record: &'a Name) -> DepartureTaking<'a>;
}

/// The most departures a link's sink takes, however often the inviter tells.
const TAKEN_PER_LINK_MAX: usize = 32;

struct Mark {
    departure: Departure,
    /// Departure links this mark admitted.
    admissions: u32,
    /// Times the record's entry crossed the link (Interest in, answer out).
    sightings: u32,
}

#[derive(Default)]
struct State {
    /// The marks, oldest first.
    marks: Vec<Mark>,
    options: DepartureOptions,
    /// Why a link of a key closed, until its `Down` is reported.
    let_go: HashMap<KeyFingerprint, LinkDetail>,
    sink: Option<Arc<dyn DepartureSink>>,
}

struct Inner {
    state: Mutex<State>,
    /// Counts each time a record's entry crossed a departure link.
    sighted: watch::Sender<u64>,
}

/// The departure marks of a [`Links`], the memory of what each admitted, and
/// the sink that takes a departure told to this device.
#[derive(Clone)]
pub(crate) struct Departures {
    inner: Arc<Inner>,
}

impl Default for Departures {
    fn default() -> Self {
        Self {
            inner: Arc::new(Inner {
                state: Mutex::new(State::default()),
                sighted: watch::channel(0).0,
            }),
        }
    }
}

impl State {
    fn forget_expired(&mut self, now: SystemTime) {
        self.marks.retain(|m| m.departure.until > now);
    }

    fn live<'a>(
        &'a self,
        key: &'a KeyFingerprint,
        now: SystemTime,
    ) -> impl Iterator<Item = &'a Mark> {
        self.marks
            .iter()
            .filter(move |m| m.departure.key == *key && m.departure.until > now)
    }
}

impl Departures {
    /// Installs `d`: it replaces the mark of the same key and folder. The
    /// admissions already counted stay with a mark that is the same (same
    /// record, same date); a new record is a new mark.
    pub(crate) fn put(&self, d: Departure, now: SystemTime) {
        let mut state = self.inner.state.lock();
        state.forget_expired(now);
        if d.until <= now {
            return;
        }
        let at = state
            .marks
            .iter()
            .position(|m| m.departure.key == d.key && m.departure.folder == d.folder);
        let admissions = match at {
            Some(i) => {
                let old = state.marks.remove(i);
                if old.departure.record == d.record && old.departure.until == d.until {
                    old.admissions
                } else {
                    0
                }
            }
            None => 0,
        };
        state.marks.push(Mark {
            departure: d,
            admissions,
            sightings: 0,
        });
        let max = state.options.marks_max.max(1);
        let over = state.marks.len().saturating_sub(max);
        state.marks.drain(..over);
    }

    /// Forgets the mark of `key` for `folder` (the person was invited again).
    pub(crate) fn remove(&self, key: &KeyFingerprint, folder: &Name) {
        self.inner
            .state
            .lock()
            .marks
            .retain(|m| !(m.departure.key == *key && m.departure.folder == *folder));
    }

    pub(crate) fn set_options(&self, options: DepartureOptions) {
        let mut state = self.inner.state.lock();
        state.options = options;
        let over = state.marks.len().saturating_sub(options.marks_max.max(1));
        state.marks.drain(..over);
    }

    pub(crate) fn options(&self) -> DepartureOptions {
        self.inner.state.lock().options
    }

    /// The marks in force at `now`, oldest first.
    pub(crate) fn list(&self, now: SystemTime) -> Vec<Departure> {
        let state = self.inner.state.lock();
        state
            .marks
            .iter()
            .filter(|m| m.departure.until > now)
            .map(|m| m.departure.clone())
            .collect()
    }

    /// The marks of `key` in force at `now`.
    pub(crate) fn marks_of(&self, key: &KeyFingerprint, now: SystemTime) -> Vec<Departure> {
        let state = self.inner.state.lock();
        state.live(key, now).map(|m| m.departure.clone()).collect()
    }

    /// Whether `key` has a mark of `folder` in force.
    pub(crate) fn has_mark(&self, key: &KeyFingerprint, folder: &Name, now: SystemTime) -> bool {
        let state = self.inner.state.lock();
        state.live(key, now).any(|m| m.departure.folder == *folder)
    }

    /// Admission of a departure link for `key`, whose handshake showed
    /// identities in `namespaces` (validated in held namespaces): the marks of
    /// the key in force whose namespaces include one of them and that still
    /// have attempts left, each counted once more. `None` when there is none:
    /// a key with no mark (it never held a grant), an expired or used-up
    /// mark, or identities of other namespaces.
    pub(crate) fn admit(
        &self,
        key: &KeyFingerprint,
        namespaces: &[Name],
        now: SystemTime,
    ) -> Option<Vec<Departure>> {
        let mut state = self.inner.state.lock();
        state.forget_expired(now);
        let attempts = state.options.attempts;
        let mut admitted = Vec::new();
        for mark in state.marks.iter_mut().filter(|m| {
            m.departure.key == *key
                && m.admissions < attempts
                && m.departure
                    .namespaces
                    .iter()
                    .any(|ns| namespaces.contains(ns))
        }) {
            mark.admissions += 1;
            mark.sightings = 0;
            admitted.push(mark.departure.clone());
        }
        (!admitted.is_empty()).then_some(admitted)
    }

    /// A link of `key` narrows or is admitted now: what crossed it before is
    /// forgotten.
    fn begin(&self, key: &KeyFingerprint, now: SystemTime) {
        let mut state = self.inner.state.lock();
        for mark in state
            .marks
            .iter_mut()
            .filter(|m| m.departure.key == *key && m.departure.until > now)
        {
            mark.sightings = 0;
        }
    }

    /// Whether a packet named `name` may cross a link of `key` that carries a
    /// departure only: for each mark of the key in force, the record's entry,
    /// its pieces and its cut manifests (`departure_carries` of the data
    /// layer, `surface`), and the key and certificate names of the folder's
    /// namespace and of the record's signer (so the record can be
    /// validated). Nothing else. Counts the times the record's entry itself
    /// crosses, which is how the link knows it was carried.
    pub(crate) fn carried_by(
        &self,
        key: &KeyFingerprint,
        name: &Name,
        surface: Option<&Arc<dyn Introductions>>,
        now: SystemTime,
    ) -> bool {
        let mut sighted = false;
        let carried = {
            let mut state = self.inner.state.lock();
            let mut carried = false;
            for mark in state
                .marks
                .iter_mut()
                .filter(|m| m.departure.key == *key && m.departure.until > now)
            {
                let d = &mark.departure;
                if surface.is_some_and(|s| s.departure_carries(&d.record, name))
                    || names_a_key_of(&folder_namespace(&d.folder), name)
                    || names_a_key_of(&signer_device(&d.record), name)
                {
                    carried = true;
                    if undigested(name) == undigested(&d.record) {
                        mark.sightings = mark.sightings.saturating_add(1);
                        sighted = true;
                    }
                }
            }
            carried
        };
        if sighted {
            self.inner.sighted.send_modify(|n| *n += 1);
        }
        carried
    }

    /// Whether the record of every mark of `key` in force has crossed the
    /// link (an Interest for it and its answer), or there is none.
    fn all_carried(&self, key: &KeyFingerprint, now: SystemTime) -> bool {
        let state = self.inner.state.lock();
        state.live(key, now).all(|m| m.sightings >= 2)
    }

    fn subscribe(&self) -> watch::Receiver<u64> {
        self.inner.sighted.subscribe()
    }

    /// Remember why the link of `key` is closing, for its `Down`.
    pub(crate) fn note_let_go(&self, key: KeyFingerprint, detail: LinkDetail) {
        self.inner.state.lock().let_go.insert(key, detail);
    }

    /// The let-go of the link of `key` that just ended, if it was one.
    pub(crate) fn take_let_go(&self, key: &KeyFingerprint) -> Option<LinkDetail> {
        self.inner.state.lock().let_go.remove(key)
    }

    pub(crate) fn set_sink(&self, sink: Arc<dyn DepartureSink>) {
        self.inner.state.lock().sink = Some(sink);
    }

    fn sink(&self) -> Option<Arc<dyn DepartureSink>> {
        self.inner.state.lock().sink.clone()
    }
}

/// `name` without a trailing implicit digest.
fn undigested(name: &Name) -> Name {
    match name.components().split_last() {
        Some((last, rest)) if last.typ == IMPLICIT_SHA256 => {
            Name::from_components(rest.iter().cloned())
        }
        _ => name.clone(),
    }
}

/// Whether `name` is a key or certificate name under `ns`.
fn names_a_key_of(ns: &Option<Name>, name: &Name) -> bool {
    ns.as_ref().is_some_and(|ns| {
        name.has_prefix(ns) && is_key_or_certificate_name(&name.components()[ns.len()..])
    })
}

/// The device that signed the log entry `record`: the components before its
/// `32=log` marker.
fn signer_device(record: &Name) -> Option<Name> {
    let at = record
        .components()
        .iter()
        .position(|c| c.typ == ndn_packet::tlv_type::KEYWORD && c.value.as_ref() == b"log")?;
    (at > 0).then(|| Name::from_components(record.components()[..at].iter().cloned()))
}

/// The `let-go` detail for the marks `of` a person was let go by.
pub(crate) fn let_go_detail(of: &[Departure]) -> LinkDetail {
    let folders = crate::admission::list(&of.iter().map(|d| d.folder.clone()).collect::<Vec<_>>());
    let records = crate::admission::list(&of.iter().map(|d| d.record.clone()).collect::<Vec<_>>());
    let ended = match of {
        [only] => format!(
            "you were let go of {}: the members record {} leaves you out",
            only.folder, only.record
        ),
        _ => format!("you were let go of {folders}: the members records {records} leave you out"),
    };
    LinkDetail::new(
        code::LET_GO,
        format!(
            "{ended}; this device carried {} to you and closed the link; ask the person who \
             invited you to invite you again",
            if of.len() == 1 { "it" } else { "them" }
        ),
    )
    .with("folder", folders)
    .with("record", records)
}

/// The `let-go` detail as the person's device words it, from the message.
fn told_detail(told: &[Told]) -> LinkDetail {
    let folders =
        crate::admission::list(&told.iter().map(|d| d.folder.clone()).collect::<Vec<_>>());
    let records =
        crate::admission::list(&told.iter().map(|d| d.record.clone()).collect::<Vec<_>>());
    LinkDetail::new(
        code::LET_GO,
        format!(
            "you were let go of {folders}: the members record {records} leaves you out; the \
             device that let you go carried it to you and closed the link; ask the person who \
             invited you to invite you again"
        ),
    )
    .with("folder", folders)
    .with("record", records)
}

impl Judge<'_> {
    /// The names a departure link of `key` carries ([`Departures::carried_by`]),
    /// judged at every packet in both directions.
    pub(crate) fn departure_names(&self, key: KeyFingerprint) -> NameFilter {
        let departures = self.departures.clone();
        let surface = self.introductions.clone();
        Box::new(move |name: &Name| {
            departures.carried_by(&key, name, surface.as_ref(), SystemTime::now())
        })
    }
}

impl Links {
    /// A person was let go of `d.folder` by the held members record
    /// `d.record`: from now until `d.until`, a link of `d.key` that has no
    /// live grant entry is told so and carries that record
    /// ([`Links::revoke_grant`] narrows a link standing, a departure link
    /// admits a returning device). Replaces the mark of the same key and
    /// folder; at most [`DepartureOptions::marks_max`] are kept, the oldest
    /// forgotten. A host with a data-layer device calls it by
    /// [`LinkHints::serve`](crate::LinkHints::serve).
    pub fn depart(&self, d: Departure) {
        self.departures.put(d, SystemTime::now());
    }

    /// The departure marks in force now, oldest first.
    pub fn departures(&self) -> Vec<Departure> {
        self.departures.list(SystemTime::now())
    }

    /// How departures are served ([`DepartureOptions`]).
    pub fn set_departure_options(&self, options: DepartureOptions) {
        self.departures.set_options(options);
    }

    /// The person's half: what takes a departure an inviter told this
    /// device ([`DepartureSink`]). Call it once.
    pub fn set_departure_sink(&self, sink: Arc<dyn DepartureSink>) {
        self.departures.set_sink(sink);
    }

    /// The last entry of `key` ended by a record: narrow its links in place
    /// to the departure, tell the person, and close them when the record has
    /// been carried or `hold` has passed. `false` when no link of the key was
    /// admitted by a grant (the caller closes nothing either: a later dial is
    /// admitted on a departure link) or there is no mark to tell.
    pub(crate) fn narrow_granted(&self, key: &KeyFingerprint) -> bool {
        let now = SystemTime::now();
        let marks = self.departures.marks_of(key, now);
        if marks.is_empty() {
            return false;
        }
        let handles = self.table.granted_handles(key);
        self.departures.begin(key, now);
        for handle in &handles {
            self.tell_departures(handle, &marks);
            self.spawn_finish(*key, handle.clone());
        }
        true
    }

    /// An entry of `key` for `folder` ended by a record while others of the
    /// key stand: the links stay (and carry that record beside the entries'
    /// names), and the person is told which record of `folder` leaves them
    /// out, as a narrowed link tells it. Without it the person would keep
    /// walking the folder the inviter no longer serves.
    pub(crate) fn tell_ended_entry(&self, key: &KeyFingerprint, folder: &Name) {
        let marks: Vec<Departure> = self
            .departures
            .marks_of(key, SystemTime::now())
            .into_iter()
            .filter(|m| m.folder == *folder)
            .collect();
        if marks.is_empty() {
            return;
        }
        for handle in self.table.granted_handles(key) {
            self.tell_departures(&handle, &marks);
        }
    }

    /// A departure link was registered: tell the person, and see it to its end.
    pub(crate) fn departure_link_up(&self, admitted: &Admitted, handle: &LinkHandle) {
        let Some(Enrollment::Departure(marks)) = &admitted.enrollment else {
            return;
        };
        self.departures
            .begin(&admitted.fingerprint, SystemTime::now());
        self.tell_departures(handle, marks);
        self.spawn_finish(admitted.fingerprint, handle.clone());
    }

    fn tell_departures(&self, handle: &LinkHandle, marks: &[Departure]) {
        for mark in marks {
            handle.send_departure(&Told {
                folder: mark.folder.clone(),
                record: mark.record.clone(),
            });
        }
    }

    /// Sees a narrowed or departure link of `key` to its end: closed with the
    /// `let-go` detail once every record has crossed it and `settle` has
    /// passed, or after `hold`, whichever first; left alone once an entry of
    /// the key is live again (it widened back).
    fn spawn_finish(&self, key: KeyFingerprint, handle: LinkHandle) {
        let grants = self.grants.clone();
        let departures = self.departures.clone();
        let cancel = self.cancel_token().clone();
        tokio::spawn(async move {
            let options = departures.options();
            let started = Instant::now();
            let mut complete_at: Option<Instant> = None;
            let mut sighted = departures.subscribe();
            loop {
                let now = SystemTime::now();
                if grants.has_live(&key, now) {
                    return;
                }
                let marks = departures.marks_of(&key, now);
                if marks.is_empty() {
                    // The mark ran out under the link: nothing is carried any
                    // more, and the person was told what it needed to be.
                    handle.close(
                        CloseReason::NotServed,
                        "the departure this link carried has expired; ask the person who \
                         invited you to invite you again",
                    );
                    return;
                }
                if complete_at.is_none() && departures.all_carried(&key, now) {
                    complete_at = Some(Instant::now() + options.settle);
                }
                let deadline =
                    (started + options.hold).min(complete_at.unwrap_or(started + options.hold));
                if Instant::now() >= deadline {
                    let detail = let_go_detail(&marks);
                    departures.note_let_go(key, detail.clone());
                    tracing::info!(
                        target: "face.quic",
                        key = %key,
                        "closing the departure link: {}",
                        detail.text
                    );
                    handle.close(CloseReason::NotServed, &detail.text);
                    return;
                }
                tokio::select! {
                    () = cancel.cancelled() => return,
                    _ = handle.closed() => return,
                    _ = sighted.changed() => {}
                    () = tokio::time::sleep_until(deadline.into()) => {}
                }
            }
        });
    }

    /// The person's half, for the link of `key` just registered: what the
    /// inviter says on its control stream goes to the sink, one at a time (so
    /// one fetch in flight per link, hence per folder), at most
    /// [`TAKEN_PER_LINK_MAX`] over the link's life; and the link's `Down`
    /// names what it was told.
    pub(crate) fn hear_departures(&self, key: KeyFingerprint, handle: &LinkHandle) {
        let Some(sink) = self.departures.sink() else {
            return;
        };
        let departures = self.departures.clone();
        let mut heard = handle.departures();
        let handle = handle.clone();
        let cancel = self.cancel_token().clone();
        tokio::spawn(async move {
            let mut seen: Vec<Told> = Vec::new();
            loop {
                tokio::select! {
                    () = cancel.cancelled() => return,
                    _ = handle.closed() => return,
                    changed = heard.changed() => if changed.is_err() { return },
                }
                let now: Vec<Told> = heard.borrow_and_update().clone();
                departures.note_let_go(key, told_detail(&now));
                for told in now {
                    if seen.contains(&told) {
                        continue;
                    }
                    if seen.len() >= TAKEN_PER_LINK_MAX {
                        tracing::warn!(
                            target: "face.quic",
                            key = %key,
                            "not taking the departure of {}: this link already told this device of \
                             {TAKEN_PER_LINK_MAX} departures",
                            told.folder
                        );
                        continue;
                    }
                    seen.push(told.clone());
                    match sink.departure(&told.folder, &told.record).await {
                        Ok(()) => tracing::info!(
                            target: "face.quic",
                            key = %key,
                            "took the members record {} that lets this device go of {}",
                            told.record,
                            told.folder
                        ),
                        Err(why) => tracing::warn!(
                            target: "face.quic",
                            key = %key,
                            "did not take the members record {} named for {}: {why}",
                            told.record,
                            told.folder
                        ),
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    fn key(b: u8) -> KeyFingerprint {
        KeyFingerprint([b; 32])
    }

    fn mark(b: u8, folder: &str, seq: u32, until: SystemTime) -> Departure {
        Departure {
            key: key(b),
            namespaces: vec![n("/bob")],
            folder: n(folder),
            record: n(&format!("/alice/member/laptop/32=log{folder}/seq={seq}")),
            until,
        }
    }

    /// What the data layer carries of a record, for these tests: the entry
    /// itself.
    struct Entry;

    impl Introductions for Entry {
        fn open(&self) -> bool {
            false
        }
        fn carries(&self, _: &Name) -> bool {
            false
        }
        fn grant_carries(&self, _: &Name, _: &Name) -> bool {
            false
        }
        fn departure_carries(&self, record: &Name, name: &Name) -> bool {
            undigested(name) == undigested(record)
        }
    }

    #[test]
    fn a_mark_admits_only_its_key_in_its_namespaces_and_only_so_many_times() {
        let table = Departures::default();
        let now = SystemTime::now();
        let hour = now + Duration::from_secs(3600);
        table.put(mark(1, "/alice/32=data/a", 5, hour), now);
        let bob = [n("/bob")];
        assert!(table.admit(&key(2), &bob, now).is_none(), "another key");
        assert!(
            table.admit(&key(1), &[n("/carol")], now).is_none(),
            "a namespace the mark does not list"
        );
        for _ in 0..3 {
            assert_eq!(table.admit(&key(1), &bob, now).unwrap().len(), 1);
        }
        assert!(
            table.admit(&key(1), &bob, now).is_none(),
            "a fourth admission is refused"
        );
        // The same mark installed again keeps its count; a new record is a
        // new mark with its own attempts.
        table.put(mark(1, "/alice/32=data/a", 5, hour), now);
        assert!(table.admit(&key(1), &bob, now).is_none());
        table.put(mark(1, "/alice/32=data/a", 6, hour), now);
        assert!(table.admit(&key(1), &bob, now).is_some());
    }

    #[test]
    fn a_mark_is_not_served_after_its_date_and_the_oldest_go_first() {
        let table = Departures::default();
        let now = SystemTime::now();
        let soon = now + Duration::from_secs(10);
        table.put(mark(1, "/alice/32=data/a", 5, soon), now);
        assert!(table.admit(&key(1), &[n("/bob")], now).is_some());
        let later = now + Duration::from_secs(11);
        assert!(table.admit(&key(1), &[n("/bob")], later).is_none());
        assert!(table.list(later).is_empty());
        assert!(!table.has_mark(&key(1), &n("/alice/32=data/a"), later));

        table.set_options(DepartureOptions {
            marks_max: 2,
            ..DepartureOptions::default()
        });
        let hour = now + Duration::from_secs(3600);
        for b in 1..=3 {
            table.put(mark(b, "/alice/32=data/a", 5, hour), now);
        }
        let kept: Vec<_> = table.list(now).iter().map(|d| d.key).collect();
        assert_eq!(kept, vec![key(2), key(3)], "the oldest was forgotten");
    }

    /// Only the record's entry (with or without its digest), and the key and
    /// certificate names of the folder's namespace and of the signer, cross;
    /// the record's carrying is counted, and a name of another key not at all.
    #[test]
    fn a_departure_link_carries_the_record_and_the_keys_that_validate_it_and_counts_it() {
        let table = Departures::default();
        let now = SystemTime::now();
        let hour = now + Duration::from_secs(3600);
        let d = mark(1, "/alice/32=data/a", 5, hour);
        table.put(d.clone(), now);
        let surface: Arc<dyn Introductions> = Arc::new(Entry);
        let carried =
            |name: &str, key_: u8| table.carried_by(&key(key_), &n(name), Some(&surface), now);
        assert!(carried(&d.record.to_string(), 1));
        assert!(
            carried("/alice/KEY/k1", 1),
            "a key name of the folder's namespace"
        );
        assert!(carried("/alice/member/laptop/KEY/k1/self/v=1", 1));
        assert!(
            !carried("/alice/32=data/a/cover", 1),
            "another name of the folder"
        );
        assert!(!carried(
            "/alice/member/laptop/32=log/alice/32=data/a/seq=6",
            1
        ));
        assert!(!carried(&d.record.to_string(), 2), "another key");
        assert!(!table.all_carried(&key(1), now), "the entry crossed once");
        assert!(carried(&d.record.to_string(), 1));
        assert!(
            table.all_carried(&key(1), now),
            "an Interest and its answer"
        );
        // Nothing of the record is carried without a data layer.
        assert!(!table.carried_by(&key(1), &d.record, None, now));
        assert!(table.carried_by(&key(1), &n("/alice/KEY/k1"), None, now));
    }
}
