//! A person let go is told, on real QUIC links between real data-layer
//! devices (ndn-rs `ndn-link.md` §8.8, `data-layer.md` §19.8).
//!
//! Ann invites Bob into a folder; her members record then leaves him out. The
//! grant entry ends and Ann's device leaves a **departure mark** (the record's
//! name, a date). Online, Bob's link narrows in place to that record and tells
//! him which record to fetch; offline, his device returns later and is
//! admitted on a narrow link for the record alone. Either way his device
//! takes the record (it says it was let go), nothing else crosses, and the
//! link closes naming the folder and the record on both sides. The mark is
//! bounded: it expires, admits a few times, belongs only to a key whose
//! grant note (with its MAC) made it, and a note changed in the store makes
//! none.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use common::*;
use ndn_data::{DataLayer, Role};
use ndn_link::{DepartureOptions, LinkState};
use ndn_packet::{Name, NameComponent};
use ndn_sync::DataStore;

/// Ann's record for the notebook without Bob.
async fn lets_go(ann: &Embedded) {
    reshare(ann, &n(FOLDER), &[n("/alice")]).await;
}

/// Whether `on`'s device lists the namespace of `who` among the writers of
/// `folder` by the members record it holds.
async fn lists(on: &Embedded, folder: &Name, who: &Name) -> bool {
    on.device
        .members(folder)
        .await
        .is_ok_and(|share| share.writers.iter().any(|w| who.has_prefix(w)))
}

/// What `on` says of why its link to `key` is down, when it is.
fn down_says(on: &Embedded, key: ndn_face_quic::KeyFingerprint) -> Option<String> {
    on.links
        .watch()
        .current()
        .into_iter()
        .find(|p| p.key == key)
        .and_then(|p| match p.state {
            LinkState::Down { why, .. } => Some(said(&why)),
            LinkState::Up { .. } => None,
        })
}

/// The `let-go` words name the folder and the record.
fn names_folder_and_record(words: &str, folder: &Name, record: &Name) -> bool {
    words.contains("you were let go of")
        && words.contains(&folder.to_string())
        && words.contains(&record.to_string())
}

/// Ann's device's mark for `key`: the record that lets that person go.
fn record_of(ann: &Embedded, key: ndn_face_quic::KeyFingerprint) -> Name {
    let marks: Vec<_> = ann
        .links
        .departures()
        .into_iter()
        .filter(|d| d.key == key)
        .collect();
    assert_eq!(marks.len(), 1, "{:#?}", ann.links.departures());
    marks[0].record.clone()
}

/// What a device that is not let go would be answered over its link, and a
/// narrow link must not answer: Ann's folder entry, her summary root, her
/// sync group.
struct Names {
    entry: Name,
    root: Name,
    probe: Name,
}

/// Ann writes into the notebook; the names a let-go person is refused.
async fn names_of(ann: &Embedded) -> Names {
    answers_probes(ann);
    let later = n(FOLDER).append("later");
    puts(&ann.device, &later, text("before"), LONG).await;
    Names {
        entry: newest_entry(ann, ANN, &later).await,
        root: ndn_data::wire::root_prefix(&n(ANN), &ann.ns),
        probe: probe_prefix(ann).append("departed"),
    }
}

/// Every name of `names` is answered over `from`'s link to `to`, or none is.
async fn all_asked(from: &Embedded, to: &Embedded, names: &Names, answered: bool) {
    for (what, name, prefix) in [
        ("a folder entry", &names.entry, false),
        ("a summary root", &names.root, true),
        ("the sync group", &names.probe, false),
    ] {
        assert_eq!(
            asks(from, to.key, name, prefix).await,
            answered,
            "{what} ({name}) was {}answered over the link",
            if answered { "not " } else { "" }
        );
    }
}

/// Bob, invited into the notebook, linked to Ann, goes offline; Ann lets him
/// go. Nothing has told him.
async fn let_go_offline(ann: &Embedded, bob: &Embedded) {
    until("ann is linked to bob", LONG, async || {
        linked(ann, bob.key) && linked(bob, ann.key)
    })
    .await;
    bob.links.set_online(false);
    until("the link to bob ends", LONG, async || !linked(ann, bob.key)).await;
    lets_go(ann).await;
    until("ann holds the departure", LONG, async || {
        ann.links.departures().iter().any(|d| d.key == bob.key)
    })
    .await;
    assert!(
        lists(bob, &n(FOLDER), &bob.ns).await,
        "bob's device heard of the record while offline"
    );
    bob.links.set_online(true);
}

/// Let go while **online**: the link narrows in place and tells Bob which
/// record to fetch; his device takes it and says it was let go; every other
/// name is refused over the narrowed link; then the link closes, and both
/// sides' `Down` name the folder and the record.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn let_go_while_online_the_person_is_told_takes_the_record_and_the_link_closes() {
    let alice = Person::new("/alice").await;
    let bobs = Person::new("/bob").await;
    let ann = embedded(&alice, ANN, Setup::inviter()).await;
    let bob = embedded(&bobs, "/bob/member/phone", Setup::dialer()).await;
    let folder = n(FOLDER);
    invited(&ann, &bob, Role::Writer).await;
    until("ann is linked to bob", LONG, async || {
        linked(&ann, bob.key) && linked(&bob, ann.key)
    })
    .await;
    let names = names_of(&ann).await;
    until("bob reads what ann wrote", LONG, async || {
        reads(&bob.device, &folder.clone().append("later"), "before").await
    })
    .await;
    // The link stays narrow long enough to ask over it.
    ann.links.set_departure_options(DepartureOptions {
        settle: Duration::from_secs(8),
        ..DepartureOptions::default()
    });
    // Control: a member is answered all of it.
    all_asked(&bob, &ann, &names, true).await;
    assert!(lists(&bob, &folder, &bob.ns).await);

    lets_go(&ann).await;
    // Told: his device took the record and its folder no longer lists him.
    until("bob's device says it was let go", LONG, async || {
        !lists(&bob, &folder, &bob.ns).await
    })
    .await;
    let record = record_of(&ann, bob.key);
    assert!(ann.device.grants().is_empty());
    // The record is the one of Ann's line that leaves him out, a log entry of
    // the folder.
    assert!(
        record.to_string().contains("/alice/member/laptop"),
        "{record}"
    );
    // Nothing else crosses the narrowed link, whichever way he asks.
    all_asked(&bob, &ann, &names, false).await;
    assert!(
        linked(&ann, bob.key),
        "the link closed before it could be asked over"
    );

    until("the link closes", LONG, async || {
        !linked(&ann, bob.key) && !linked(&bob, ann.key)
    })
    .await;
    for (who, other, side) in [(&ann, &bob, "ann"), (&bob, &ann, "bob")] {
        until(&format!("{side} says why"), LONG, async || {
            down_says(who, other.key).is_some()
        })
        .await;
        let words = down_says(who, other.key).unwrap();
        assert!(
            names_folder_and_record(&words, &folder, &record),
            "{side}'s Down does not name the folder and the record: {words}"
        );
    }
}

/// Let go while **offline**: Ann's link to Bob is gone when the record is
/// made; the device returns later and is admitted on a narrow link for the
/// record alone; his device takes it, nothing else crosses, then the link
/// closes saying the same.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn let_go_while_offline_the_mark_admits_a_narrow_link_for_the_record_alone() {
    let alice = Person::new("/alice").await;
    let bobs = Person::new("/bob").await;
    let ann = embedded(&alice, ANN, Setup::inviter()).await;
    let bob = embedded(&bobs, "/bob/member/phone", Setup::dialer()).await;
    let folder = n(FOLDER);
    invited(&ann, &bob, Role::Writer).await;
    let names = names_of(&ann).await;
    ann.links.set_departure_options(DepartureOptions {
        settle: Duration::from_secs(8),
        ..DepartureOptions::default()
    });
    let_go_offline(&ann, &bob).await;
    let record = record_of(&ann, bob.key);
    // A stranger's introduction link is not what takes the place of the
    // grant: Ann's offer is spent.
    ann.offers_run_out();

    dials(&bob, &ann)
        .await
        .expect("the mark did not admit the returning device");
    until("bob's device says it was let go", LONG, async || {
        !lists(&bob, &folder, &bob.ns).await
    })
    .await;
    all_asked(&bob, &ann, &names, false).await;
    // Neither the grant nor any route came with the link.
    assert!(ann.links.grants().is_empty());
    assert!(
        routed_over(&ann, bob.key).is_empty(),
        "the departure link routed {:?}",
        routed_over(&ann, bob.key)
    );

    until("the link closes", LONG, async || {
        !linked(&ann, bob.key) && !linked(&bob, ann.key)
    })
    .await;
    for (who, other, side) in [(&ann, &bob, "ann"), (&bob, &ann, "bob")] {
        until(&format!("{side} says why"), LONG, async || {
            down_says(who, other.key).is_some_and(|w| w.contains("you were let go of"))
        })
        .await;
        let words = down_says(who, other.key).unwrap();
        assert!(
            names_folder_and_record(&words, &folder, &record),
            "{side}'s Down does not name the folder and the record: {words}"
        );
    }
}

/// The departed person gets nothing but the record: not another record of
/// the folder — Carol's, the one that let her go before — nor a cut manifest
/// of it, and the record's own name, with a cut manifest, is carried.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_departed_gets_nothing_but_the_record_not_another_persons_cut() {
    let alice = Person::new("/alice").await;
    let bobs = Person::new("/bob").await;
    let carols = Person::new("/carol").await;
    let ann = embedded(&alice, ANN, Setup::inviter()).await;
    let bob = embedded(&bobs, "/bob/member/phone", Setup::dialer()).await;
    let carol = embedded(&carols, "/carol/member/phone", Setup::dialer()).await;
    let folder = n(FOLDER);
    invited(&ann, &bob, Role::Writer).await;
    invited_in(&ann, &carol, &folder, Role::Writer).await;
    until("ann is linked to both", LONG, async || {
        linked(&ann, bob.key) && linked(&ann, carol.key)
    })
    .await;
    // Carol is let go first, by a record that keeps Bob.
    reshare(&ann, &folder, &[alice.ns.clone(), bobs.ns.clone()]).await;
    until("carol's departure is held", LONG, async || {
        ann.links.departures().iter().any(|d| d.key == carol.key)
    })
    .await;
    let carols_record = record_of(&ann, carol.key);
    // Then Bob, while his device is away.
    ann.links.set_departure_options(DepartureOptions {
        settle: Duration::from_secs(8),
        ..DepartureOptions::default()
    });
    let_go_offline_after_carol(&ann, &bob).await;
    let bobs_record = record_of(&ann, bob.key);
    assert_ne!(carols_record, bobs_record, "one record let both go");
    ann.offers_run_out();

    dials(&bob, &ann).await.expect("the mark admitted nothing");
    until("bob's device says it was let go", LONG, async || {
        !lists(&bob, &folder, &bob.ns).await
    })
    .await;
    let cut_of = |record: &Name| {
        record
            .clone()
            .append_component(NameComponent::keyword(Bytes::from_static(b"cut")))
            .append_segment(0)
    };
    for (what, name) in [
        ("Carol's record", carols_record.clone()),
        ("a cut manifest of Carol's record", cut_of(&carols_record)),
    ] {
        assert!(
            !asks(&bob, ann.key, &name, false).await,
            "{what} ({name}), another person's, crossed Bob's departure link"
        );
    }
    // Control: the link is Bob's departure link, which does carry his own
    // record.
    assert!(
        asks(&bob, ann.key, &bobs_record, false).await,
        "{bobs_record}, Bob's own record, was refused on his departure link"
    );
}

/// Carol's departure is held; Bob goes offline and Ann lets him go.
async fn let_go_offline_after_carol(ann: &Embedded, bob: &Embedded) {
    until("ann is linked to bob", LONG, async || {
        linked(ann, bob.key) && linked(bob, ann.key)
    })
    .await;
    bob.links.set_online(false);
    until("the link to bob ends", LONG, async || !linked(ann, bob.key)).await;
    lets_go(ann).await;
    until("ann holds bob's departure", LONG, async || {
        ann.links.departures().iter().any(|d| d.key == bob.key)
    })
    .await;
    bob.links.set_online(true);
}

/// The mark expires: a device that returns before is admitted on the narrow
/// link; one that returns after is refused with the plain grant-ended
/// refusal, which says what ended and what to do.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_mark_expires_admitted_before_refused_after_with_the_grant_ended_text() {
    let alice = Person::new("/alice").await;
    let bobs = Person::new("/bob").await;
    let ann = embedded(
        &alice,
        ANN,
        Setup {
            departure_for: Duration::from_secs(10),
            ..Setup::inviter()
        },
    )
    .await;
    let bob = embedded(&bobs, "/bob/member/phone", Setup::dialer()).await;
    invited(&ann, &bob, Role::Writer).await;
    ann.links.set_departure_options(DepartureOptions {
        settle: Duration::ZERO,
        hold: Duration::from_secs(1),
        ..DepartureOptions::default()
    });
    let_go_offline(&ann, &bob).await;
    ann.offers_run_out();

    dials(&bob, &ann)
        .await
        .expect("the mark had not expired, yet the device was refused");
    until("the link closes", LONG, async || {
        !linked(&ann, bob.key) && !linked(&bob, ann.key)
    })
    .await;

    until("the mark runs out", LONG, async || {
        ann.links.departures().is_empty()
    })
    .await;
    let refused = dials(&bob, &ann)
        .await
        .expect_err("the mark had expired, yet the device was admitted");
    let words = said(&refused);
    assert!(
        words.contains("the grant ended") && words.contains("members record"),
        "the refusal after the mark does not say the grant ended: {words}"
    );
    assert!(!linked(&ann, bob.key));
}

/// A mark admits `attempts` links and no more, however often the device
/// dials (and whether it is Bob's dial or the one his join left running):
/// counted at Ann's end, three links stand and fall, and every dial after is
/// refused with the grant-ended refusal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_attempts_are_bounded_a_fourth_admission_is_refused() {
    let alice = Person::new("/alice").await;
    let bobs = Person::new("/bob").await;
    let ann = embedded(&alice, ANN, Setup::inviter()).await;
    let bob = embedded(&bobs, "/bob/member/phone", Setup::dialer()).await;
    invited(&ann, &bob, Role::Writer).await;
    ann.links.set_departure_options(DepartureOptions {
        settle: Duration::ZERO,
        hold: Duration::from_secs(1),
        attempts: 3,
        ..DepartureOptions::default()
    });
    // Ann's end counts the times Bob's link comes up.
    let ups = Arc::new(AtomicUsize::new(0));
    {
        let ups = Arc::clone(&ups);
        let mut watch = ann.links.watch();
        let key = bob.key;
        tokio::spawn(async move {
            let mut was_up = false;
            while let Some(peers) = watch.changed().await {
                let up = peers
                    .iter()
                    .any(|p| p.key == key && matches!(p.state, LinkState::Up { .. }));
                if up && !was_up {
                    ups.fetch_add(1, Ordering::SeqCst);
                }
                was_up = up;
            }
        });
    }
    until("ann is linked to bob", LONG, async || {
        linked(&ann, bob.key) && linked(&bob, ann.key)
    })
    .await;
    bob.links.set_online(false);
    until("the link to bob ends", LONG, async || {
        !linked(&ann, bob.key)
    })
    .await;
    lets_go(&ann).await;
    until("ann holds the departure", LONG, async || {
        ann.links.departures().iter().any(|d| d.key == bob.key)
    })
    .await;
    ann.offers_run_out();
    let before = ups.load(Ordering::SeqCst);
    bob.links.set_online(true);

    let mut refused = None;
    for _ in 0..10 {
        match dials(&bob, &ann).await {
            Ok(()) => {
                until("the link closes", LONG, async || {
                    !linked(&ann, bob.key) && !linked(&bob, ann.key)
                })
                .await;
            }
            Err(e) => {
                refused = Some(e);
                break;
            }
        }
    }
    let words = said(&refused.expect("ten dials were all admitted: the mark is no bound"));
    assert!(
        words.contains("the grant ended") && words.contains("members record"),
        "the refusal after the attempts does not say the grant ended: {words}"
    );
    // Nothing brings a fourth link, however long it is waited for. (Counted
    // at Ann's end by the links that came up: a handshake the mark admitted
    // that lost the race with another of the same key is admitted and never
    // up, so the count is at most the attempts, and at least one.)
    tokio::time::sleep(Duration::from_secs(3)).await;
    let admitted = ups.load(Ordering::SeqCst) - before;
    assert!(
        (1..=3).contains(&admitted),
        "the mark admitted {admitted} links, not at most the 3 attempts it allows"
    );
    assert!(!linked(&ann, bob.key));
}

/// A key that never held a grant gets no departure link, whoever else was
/// let go: it is refused as before, with the same words.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_key_with_no_grant_note_gets_no_departure_link_and_the_same_refusal_as_before() {
    let alice = Person::new("/alice").await;
    let bobs = Person::new("/bob").await;
    let ann = embedded(&alice, ANN, Setup::inviter()).await;
    let bob = embedded(&bobs, "/bob/member/phone", Setup::dialer()).await;
    // Another device of Bob's namespace, with a certificate of it: no grant.
    let tablet = embedded(&bobs, "/bob/member/tablet", Setup::dialer()).await;
    invited(&ann, &bob, Role::Writer).await;
    ann.offers_run_out();
    let before = said(
        &dials(&tablet, &ann)
            .await
            .expect_err("the tablet was linked with no grant"),
    );
    assert!(before.contains("holds no certificate in"), "{before}");

    let_go_offline(&ann, &bob).await;
    assert!(ann.links.departures().iter().all(|d| d.key != tablet.key));
    let after = said(
        &dials(&tablet, &ann)
            .await
            .expect_err("a mark of Bob's admitted the tablet"),
    );
    assert_eq!(
        before, after,
        "a key that never held a grant is refused differently once another was let go"
    );
    assert!(!linked(&ann, tablet.key));
    // Bob, who held one, is admitted: the mark is his.
    dials(&bob, &ann)
        .await
        .expect("bob's mark admitted nothing");
}

/// What Ann's device derives from its store at a start (`LinkHints::serve`
/// installs it): a mark whose note was changed in the store — cleared,
/// moved, or added — is ignored, so the person it names is refused as a
/// person with no grant is; the same store unchanged admits them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_note_changed_in_the_store_leaves_no_mark_at_the_next_start() {
    // The flag byte of a note and the bit that says it keeps a mark; the
    // byte that ends the note's body, before its MAC.
    const FLAGS: usize = 1;
    const MARKED: u8 = 4;
    const MAC: usize = 32;
    type Tamper = fn(Vec<u8>) -> Vec<u8>;
    let variants: [(&str, Option<Tamper>); 4] = [
        ("unchanged", None),
        (
            "a mark cleared",
            Some(|mut note| {
                note[FLAGS] &= !MARKED;
                note
            }),
        ),
        (
            "a mark moved",
            Some(|mut note| {
                // The last octet of the mark's record name.
                let at = note.len() - MAC - 1;
                note[at] ^= 0x01;
                note
            }),
        ),
        (
            "a mark added to a note that had none",
            Some(|mut note| {
                // A note with no mark that now says it has one: the flag is
                // set, the mark's octets appended, the MAC kept.
                note[FLAGS] |= MARKED | 1;
                let mac = note.split_off(note.len() - MAC);
                note.extend_from_slice(&[0u8; 8]);
                note.extend_from_slice(&mac);
                note
            }),
        ),
    ];
    for (what, tamper) in variants {
        let alice = Person::new("/alice").await;
        let bobs = Person::new("/bob").await;
        let ann = embedded(&alice, ANN, Setup::inviter()).await;
        let bob = embedded(&bobs, "/bob/member/phone", Setup::dialer()).await;
        invited(&ann, &bob, Role::Writer).await;
        let_go_offline(&ann, &bob).await;
        let notes = ann
            .store()
            .scan_under(&n("/localhost/ndn-data/intro/grant"), 0);
        assert_eq!(notes.len(), 1, "{what}: the notes of Ann's store");
        if let Some(tamper) = tamper {
            let (name, value) = notes.into_iter().next().unwrap();
            ann.store()
                .insert(name, Bytes::from(tamper(value.to_vec())));
        }
        let store = std::sync::Arc::clone(ann.store());

        // Ann starts again over the store.
        let ann = ann.restart(Setup::inviter()).await;
        assert!(std::sync::Arc::ptr_eq(&store, ann.store()));
        ann.offers_run_out();
        let marked = tamper.is_none();
        assert_eq!(
            ann.device.departures().len(),
            usize::from(marked),
            "{what}: the marks Ann's device derives"
        );
        assert_eq!(
            ann.links.departures().len(),
            usize::from(marked),
            "{what}: the marks her links installed"
        );
        let result = dials(&bob, &ann).await;
        if marked {
            result.unwrap_or_else(|e| panic!("{what}: the mark was refused: {}", said(&e)));
        } else {
            let words = said(&result.expect_err(&format!("{what}: a changed note admitted Bob")));
            assert!(
                words.contains("holds no certificate in"),
                "{what}: the refusal is not the one a key with no grant gets: {words}"
            );
            assert!(!linked(&ann, bob.key), "{what}");
        }
    }
}
