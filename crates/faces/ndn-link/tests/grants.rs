//! The per-introduction grant on real QUIC links, real forwarders and real
//! data-layer devices (ndn-rs `ndn-link.md` §8.7, `data-layer.md` §19.8).
//!
//! Ann keeps the default serving policy `own`: she serves the devices of
//! namespaces she holds a certificate in, and a person she invites is of
//! another namespace, whose context she holds from the join but in which she
//! has no certificate. The grant her device made when it admitted Bob is what
//! links him — his key, in his namespace, until it ends — and links nobody
//! else, Carol (another device of Bob's namespace) included. The cases:
//! Bob syncs a note both ways with Ann; Carol gets no link and the refusal
//! says why; an expired, a revoked and a removed member's grant each close
//! Bob's link and name what ended in the refusal of his next dial; under
//! `serve = open` the grant changes nothing; a reader's link carries what a
//! reader sends as Interests only.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use common::*;
use ndn_app::EngineAppExt;
use ndn_data::{Audience, DataLayer, Role, Rule, Share, Sharing, Timestamp};
use ndn_link::{Grant, GrantRole};
use ndn_packet::{Name, NameComponent};

/// Ann invites Bob, who joins and syncs a note both ways with her, under the
/// default `own` policy: his link is the grant's, in his namespace only, and
/// carries what a writer's does. Carol, another device of Bob's namespace
/// with a valid certificate of it, gets no link, and the refusal says why.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ann_invites_bob_who_syncs_both_ways_and_carol_gets_no_link() {
    let alice = Person::new("/alice").await;
    let bobs = Person::new("/bob").await;
    let ann = embedded(&alice, ANN, Setup::inviter()).await;
    let bob = embedded(&bobs, "/bob/member/phone", Setup::dialer()).await;
    let carol = embedded(&bobs, "/bob/member/tablet", Setup::dialer()).await;
    answers_probes(&ann);
    answers_probes(&bob);

    invited(&ann, &bob, Role::Writer).await;

    // The grant the device made is in the links: Bob's key, his namespace,
    // the offer's role.
    let grants = ann.links.grants();
    assert_eq!(grants.len(), 1, "{grants:#?}");
    assert_eq!(grants[0].key, bob.key);
    assert_eq!(grants[0].namespaces, vec![n("/bob")]);
    assert_eq!(grants[0].role, GrantRole::Writer);

    // Both ways: Bob reads Ann's cover, and each reads what the other writes.
    let folder = n(FOLDER);
    let cover = folder.clone().append("cover");
    until("bob reads ann's cover", LONG, async || {
        reads(&bob.device, &cover, "cover by ann").await
    })
    .await;
    let from_bob = folder.clone().append("from-bob");
    bob.device
        .put(&from_bob, text("hello from bob"), note())
        .await
        .unwrap();
    until("ann reads bob's note", LONG, async || {
        reads(&ann.device, &from_bob, "hello from bob").await
    })
    .await;
    let from_ann = folder.append("from-ann");
    ann.device
        .put(&from_ann, text("hello from ann"), note())
        .await
        .unwrap();
    until("bob reads ann's note", LONG, async || {
        reads(&bob.device, &from_ann, "hello from ann").await
    })
    .await;

    // Ann's link to Bob is the grant's: the report says so, and her forwarder
    // routes Bob's device and his namespace's sync group over it.
    let report = ann.links.report();
    let link = report
        .links
        .iter()
        .find(|l| l.key == Some(bob.key))
        .expect("ann is linked to bob");
    let granted = link.granted.as_ref().expect("the link says it is granted");
    assert!(
        granted
            .describe()
            .starts_with("granted with no end date (it follows the folder's members record) as a "),
        "{}",
        granted.describe()
    );
    assert_eq!(report.grants, grants);
    let routed = routed_over(&ann, bob.key);
    assert!(
        routed.iter().all(|p| p.starts_with("/bob")),
        "ann routes only bob's namespace over his link: {routed:?}"
    );
    // A writer's link is a full link: his Data reaches Ann, hers reaches him.
    assert!(probes(&ann, &bob, "1").await, "a writer's Data was dropped");
    assert!(probes(&bob, &ann, "1").await);

    // Ann's offer is spent and has run out: a stranger gets no introduction
    // link on her, so what the policy and the grants say is what it hears.
    ann.offers_run_out();
    // Carol: another key of Bob's namespace, a valid certificate of it, which
    // Ann holds a context of — and no grant. No link; the refusal says why.
    let refused = dials(&carol, &ann).await.expect_err("carol was linked");
    let why = said(&refused);
    assert!(
        why.contains("/bob/member/tablet") && why.contains("holds no certificate in"),
        "the refusal does not say who was refused and why: {why}"
    );
    assert!(
        why.contains("inviting you"),
        "the refusal does not say that an invitation grants a link: {why}"
    );
    assert!(
        !linked(&ann, carol.key),
        "ann linked carol: {:#?}",
        ann.links.report()
    );
    assert!(
        routed_over(&ann, carol.key).is_empty(),
        "ann routes carol's device"
    );
    // Bob's link is unaffected.
    assert!(linked(&ann, bob.key));
}

/// A grant links a person; it does not hand them everything the device
/// answers by name. Over Bob's grant link Ann answers the names of the
/// offered folder, and Bob's own device is reachable, but an **unsealed**
/// collection of her namespace outside the folder (the data layer answers
/// those to anyone who asks by name) is not answered: the link does not
/// carry its names.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_grant_link_answers_the_folders_names_and_not_an_unsealed_collection_outside_it() {
    let alice = Person::new("/alice").await;
    let bobs = Person::new("/bob").await;
    let ann = embedded(&alice, ANN, Setup::inviter()).await;
    let bob = embedded(&bobs, "/bob/member/phone", Setup::dialer()).await;
    invited(&ann, &bob, Role::Writer).await;
    until("ann is linked to bob", LONG, async || linked(&ann, bob.key)).await;
    until("bob routes ann's device", LONG, async || {
        routed_over(&bob, ann.key).contains(&ANN.to_string())
    })
    .await;

    // Ann writes into a collection outside the offered folder; no members
    // record gives it readers, so the layer answers it to whoever asks.
    let diary = n("/alice/32=data/diary");
    ann.device
        .put_op(&diary, Bytes::from_static(b"ann's diary"), note())
        .await
        .unwrap();
    let diary_entry = newest_entry(&ann, ANN, &diary).await;
    // A note in the folder, which Bob's device fetches by itself.
    let folder = n(FOLDER);
    let shared = folder.clone().append("later");
    ann.device
        .put(&shared, text("for bob"), note())
        .await
        .unwrap();
    let shared_entry = newest_entry(&ann, ANN, &shared).await;
    until("bob reads the folder's note", LONG, async || {
        reads(&bob.device, &shared, "for bob").await
    })
    .await;

    // The folder's entry is answered over the link; the diary's is not,
    // however Bob asks.
    let mut at_bob = bob.engine.app_consumer(bob.cancel.child_token());
    assert!(
        at_bob.fetch(shared_entry.clone()).await.is_ok(),
        "{shared_entry} of the offered folder was not answered over the grant link"
    );
    assert!(
        at_bob.fetch(diary_entry.clone()).await.is_err(),
        "{diary_entry}, an unsealed collection outside the offered folder, was answered over \
         the grant link"
    );

    // Bob's own device is reachable: Ann fetches what he wrote.
    let from_bob = folder.append("from-bob");
    bob.device
        .put(&from_bob, text("hello from bob"), note())
        .await
        .unwrap();
    let bobs_entry = newest_entry(&bob, "/bob/member/phone", &from_bob).await;
    let mut at_ann = ann.engine.app_consumer(ann.cancel.child_token());
    until(
        "ann fetches bob's entry from his device",
        LONG,
        async || at_ann.fetch(bobs_entry.clone()).await.is_ok(),
    )
    .await;
}

/// A host that ends the grant of a person who stays a member (it kicks
/// them from its links, not from the folder) ends it durably: the links
/// close, and a restart — which installs what the device derives
/// (`LinkHints::serve`) — does not bring the grant back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_grant_the_host_ended_does_not_come_back_at_the_restart() {
    let alice = Person::new("/alice").await;
    let bobs = Person::new("/bob").await;
    let ann = embedded(&alice, ANN, Setup::inviter()).await;
    let bob = embedded(&bobs, "/bob/member/phone", Setup::dialer()).await;
    invited(&ann, &bob, Role::Writer).await;
    until("ann is linked to bob", LONG, async || linked(&ann, bob.key)).await;

    assert!(
        ann.hints
            .end_grant(&ann.device, &bob.key.0)
            .await
            .expect("the device made the end durable"),
        "no grant was in force"
    );
    until("the link closes", LONG, async || {
        !linked(&ann, bob.key) && !linked(&bob, ann.key)
    })
    .await;
    assert!(ann.links.grants().is_empty());

    // The restart: the device's grants are installed again.
    ann.hints.serve(&ann.device);
    assert!(
        ann.device.grants().is_empty(),
        "the device still lists a grant the host ended: {:#?}",
        ann.device.grants()
    );
    assert!(
        ann.links.grants().is_empty(),
        "a grant the host ended came back at the restart: {:#?}",
        ann.links.grants()
    );
    ann.offers_run_out();
    let refused = dials(&bob, &ann)
        .await
        .expect_err("the grant the host ended linked again");
    assert!(
        said(&refused).contains("the grant ended"),
        "{}",
        said(&refused)
    );
}

/// A host's renewal of a grant — a later date, then none — is durable: the
/// grant as the device now derives it is what the links hold, and what a
/// restart installs again, not the date the offer's admission gave it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hosts_renewal_of_a_grant_survives_the_restart() {
    let alice = Person::new("/alice").await;
    let bobs = Person::new("/bob").await;
    let ann = embedded(
        &alice,
        ANN,
        Setup {
            grant_for: Some(Duration::from_secs(3600)),
            ..Setup::inviter()
        },
    )
    .await;
    let bob = embedded(&bobs, "/bob/member/phone", Setup::dialer()).await;
    invited(&ann, &bob, Role::Writer).await;
    until("ann is linked to bob", LONG, async || linked(&ann, bob.key)).await;
    let first = ann.links.grants()[0].until;
    assert!(first.is_some(), "the device made a dated grant");

    let in_two_days = Timestamp(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
            + 2 * 24 * 3_600_000,
    );
    let at = SystemTime::UNIX_EPOCH + Duration::from_millis(in_two_days.0);
    let renewed = ann
        .hints
        .renew_grant(&ann.device, &bob.key.0, Some(in_two_days))
        .await
        .expect("the device made the renewal durable")
        .expect("a grant a held record admits was live");
    assert_eq!(renewed.until, Some(in_two_days));
    assert_eq!(ann.links.grants()[0].until, Some(at));
    assert!(linked(&ann, bob.key), "a renewal closed the link");
    ann.hints.serve(&ann.device);
    assert_eq!(
        ann.links.grants()[0].until,
        Some(at),
        "the restart installed the date the offer's admission gave, not the renewed one"
    );

    // No date at all: it follows the members record.
    ann.hints
        .renew_grant(&ann.device, &bob.key.0, None)
        .await
        .expect("the device made the renewal durable")
        .expect("a grant a held record admits was live");
    assert_eq!(ann.links.grants()[0].until, None);
    ann.hints.serve(&ann.device);
    assert_eq!(ann.links.grants()[0].until, None);
    assert!(linked(&ann, bob.key));
}

/// A grant that ran out closes the link at `until`, and the next dial of the
/// key is refused naming the expiry. The device's grant has no date; the
/// host dates it through `Links::grant`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_expired_grant_closes_the_link_at_until_and_the_next_dial_names_it() {
    let alice = Person::new("/alice").await;
    let bobs = Person::new("/bob").await;
    let ann = embedded(&alice, ANN, Setup::inviter()).await;
    let bob = embedded(&bobs, "/bob/member/phone", Setup::dialer()).await;
    invited(&ann, &bob, Role::Writer).await;
    until("ann is linked to bob", LONG, async || linked(&ann, bob.key)).await;

    let started = Instant::now();
    let until_at = SystemTime::now() + Duration::from_secs(4);
    let mut shortened = ann.links.grants().remove(0);
    shortened.until = Some(until_at);
    ann.links.grant(shortened);
    // The same scope: the link stays up until the grant runs out.
    assert!(linked(&ann, bob.key), "a later `until` closed the link");

    until("the link closes at until", LONG, async || {
        !linked(&ann, bob.key) && !linked(&bob, ann.key)
    })
    .await;
    assert!(
        started.elapsed() >= Duration::from_secs(3),
        "the link closed {:?} after the grant was shortened to 4 s",
        started.elapsed()
    );
    assert!(SystemTime::now() >= until_at - Duration::from_millis(500));
    assert_eq!(ann.links.grants(), Vec::new(), "an expired grant is live");
    assert!(ann.links.report().grants.is_empty());

    ann.offers_run_out();
    let refused = dials(&bob, &ann)
        .await
        .expect_err("an expired grant linked");
    let why = said(&refused);
    assert!(
        why.contains("the grant ended") && why.contains("it expired") && why.contains("until "),
        "the refusal does not name the expiry: {why}"
    );
    assert!(!linked(&ann, bob.key));
}

/// A revoked grant closes the link, saying what ended and what to do, and the
/// redial is refused naming the revocation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revoked_grant_closes_the_link_and_the_redial_is_refused() {
    let alice = Person::new("/alice").await;
    let bobs = Person::new("/bob").await;
    let ann = embedded(&alice, ANN, Setup::inviter()).await;
    let bob = embedded(&bobs, "/bob/member/phone", Setup::dialer()).await;
    invited(&ann, &bob, Role::Writer).await;
    until("ann is linked to bob", LONG, async || linked(&ann, bob.key)).await;

    assert!(ann.links.revoke_grants(&bob.key), "no grant was in force");
    assert!(!ann.links.revoke_grants(&bob.key), "revoked twice");
    until("the link closes", LONG, async || {
        !linked(&ann, bob.key) && !linked(&bob, ann.key)
    })
    .await;
    ann.offers_run_out();
    let refused = dials(&bob, &ann).await.expect_err("a revoked grant linked");
    let why = said(&refused);
    assert!(
        why.contains("the grant ended")
            && why.contains("revoked")
            && why.contains("invite you again"),
        "the refusal does not name the revocation and what to do: {why}"
    );
}

/// A removed member's link closes: Ann's members record drops Bob, her
/// device revokes the grant, and the link ends. Ann's device keeps no
/// departure mark here (`departure_for` zero: round 7's way to say a person
/// let go is not told), so this is the plain close and the plain refusal;
/// what a mark changes is `tests/departures.rs`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_removed_members_link_closes_when_the_record_drops_him() {
    let alice = Person::new("/alice").await;
    let bobs = Person::new("/bob").await;
    let ann = embedded(
        &alice,
        ANN,
        Setup {
            departure_for: Duration::ZERO,
            ..Setup::inviter()
        },
    )
    .await;
    let bob = embedded(&bobs, "/bob/member/phone", Setup::dialer()).await;
    invited(&ann, &bob, Role::Writer).await;
    until("ann is linked to bob", LONG, async || linked(&ann, bob.key)).await;
    assert_eq!(ann.links.grants().len(), 1);

    ann.device
        .share_folder(
            &n(FOLDER),
            Sharing::Whole(Share {
                rule: Rule::Log,
                writers: vec![n("/alice")],
                readers: vec![Audience::Person(n("/alice"))],
            }),
        )
        .await
        .unwrap();
    until("the link closes", LONG, async || {
        !linked(&ann, bob.key) && !linked(&bob, ann.key)
    })
    .await;
    assert!(ann.links.grants().is_empty());
    ann.offers_run_out();
    let refused = dials(&bob, &ann)
        .await
        .expect_err("a removed member linked");
    let why = said(&refused);
    assert!(
        why.contains("the grant ended") && why.contains("members record"),
        "the refusal does not say the record left him out: {why}"
    );
}

/// Under `serve = open` the grant changes nothing: the policy serves Bob (as
/// it would anyone of a held namespace), his link is no grant's, a reader's
/// grant narrows nothing of it, and ending the grant does not close it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn under_open_a_grant_changes_nothing() {
    let alice = Person::new("/alice").await;
    let bobs = Person::new("/bob").await;
    let ann = embedded(&alice, ANN, Setup::open()).await;
    let bob = embedded(&bobs, "/bob/member/phone", Setup::dialer()).await;
    invited(&ann, &bob, Role::Reader).await;
    until("ann is linked to bob", LONG, async || linked(&ann, bob.key)).await;
    let report = ann.links.report();
    let link = report
        .links
        .iter()
        .find(|l| l.key == Some(bob.key))
        .expect("linked");
    assert!(
        link.granted.is_none(),
        "open served him; the link is not the grant's: {:?}",
        link.granted
    );
    // A reader's grant narrows nothing under open: the link is open's own,
    // so what Bob sends is not held to Interests.
    answers_probes(&bob);
    answers_probes(&ann);
    assert!(probes(&ann, &bob, "open").await, "open's link dropped Data");
    assert!(ann.links.revoke_grants(&bob.key));
    // The link is open's: it carries as it did.
    assert!(
        probes(&ann, &bob, "after").await && probes(&bob, &ann, "after").await,
        "ending a grant closed or narrowed an open link"
    );
}

/// A reader's grant: what Bob sends toward Ann is Interests only (the Data
/// he pushes is dropped at the link); what Ann sends him is everything, so
/// what he fetches works.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_readers_grant_drops_the_data_a_reader_pushes_and_what_it_fetches_works() {
    let alice = Person::new("/alice").await;
    let bobs = Person::new("/bob").await;
    let ann = embedded(&alice, ANN, Setup::inviter()).await;
    let bob = embedded(&bobs, "/bob/member/phone", Setup::dialer()).await;
    answers_probes(&ann);
    answers_probes(&bob);
    invited(&ann, &bob, Role::Reader).await;
    assert_eq!(ann.links.grants()[0].role, GrantRole::Reader);
    let folder = n(FOLDER);
    let cover = folder.clone().append("cover");
    until("bob reads ann's cover", LONG, async || {
        reads(&bob.device, &cover, "cover by ann").await
    })
    .await;
    let note_name = folder.append("later");
    ann.device
        .put(&note_name, text("a later note"), note())
        .await
        .unwrap();
    until("bob reads what ann writes later", LONG, async || {
        reads(&bob.device, &note_name, "a later note").await
    })
    .await;
    // His Interests reach her and her Data reaches him ...
    assert!(
        probes(&bob, &ann, "r").await,
        "a reader's Interest was dropped"
    );
    // ... and the Data he answers with is dropped at her end of the link.
    assert!(
        !probes(&ann, &bob, "r").await,
        "the Data a reader pushed crossed the link"
    );
    let report = ann.links.report();
    let link = report
        .links
        .iter()
        .find(|l| l.key == Some(bob.key))
        .expect("linked");
    assert_eq!(
        link.granted.as_ref().map(|g| g.role),
        Some(GrantRole::Reader)
    );
}

/// Under `own` with no grant a person Ann holds the namespace of is refused,
/// saying why and what Ann can do; the grant Ann's host makes by hand
/// (`Links::grant`, for a link key of another kind than the Device's) links
/// that key and no other, Carol, a second device of Bob's namespace, included.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn own_refuses_without_a_grant_and_a_hosts_grant_links_its_key_only() {
    let alice = Person::new("/alice").await;
    let bobs = Person::new("/bob").await;
    let ann = embedded(&alice, ANN, Setup::inviter()).await;
    let bob = embedded(&bobs, "/bob/member/phone", Setup::dialer()).await;
    let carol = embedded(&bobs, "/bob/member/tablet", Setup::dialer()).await;
    // Ann holds Bob's namespace (as the join would have her adopt it), has
    // made no offer, and has granted nobody.
    ann.validator.adopt_context(Arc::clone(&bobs.ctx)).unwrap();
    assert!(ann.links.grants().is_empty());

    for (who, name) in [(&bob, "/bob/member/phone"), (&carol, "/bob/member/tablet")] {
        let refused = dials(who, &ann)
            .await
            .expect_err("own served a device with no grant");
        let why = said(&refused);
        assert!(
            why.contains(name)
                && why.contains("holds no certificate in")
                && why.contains("inviting you"),
            "the refusal does not say who, why and what to do: {why}"
        );
    }

    ann.links.grant(Grant {
        key: bob.key,
        namespaces: vec![n("/bob")],
        role: GrantRole::Writer,
        folder: n(FOLDER),
        until: Some(SystemTime::now() + Duration::from_secs(3600)),
    });
    dials(&bob, &ann)
        .await
        .expect("the granted key was refused");
    until("ann is linked to bob", LONG, async || linked(&ann, bob.key)).await;
    let report = ann.links.report();
    let link = report
        .links
        .iter()
        .find(|l| l.key == Some(bob.key))
        .expect("linked");
    assert!(link.granted.is_some(), "{link:#?}");
    assert_eq!(link.device, Some(n("/bob/member/phone")));
    // Another key of the same namespace gets nothing from it.
    let refused = dials(&carol, &ann)
        .await
        .expect_err("a grant of Bob's key linked Carol");
    assert!(
        said(&refused).contains("holds no certificate in"),
        "{}",
        said(&refused)
    );
    assert!(!linked(&ann, carol.key));
}

/// SHAPES-R7 A: Ann invites Bob into two folders with two notes, and he is
/// let into both; both sync; a members record that leaves him out of the
/// first alone ends the first's entry and leaves the second synced, on the
/// same link, with no close. What the ended entry carried is no longer
/// carried, what the standing one carries still is.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_notes_bob_let_into_both_both_sync_and_letting_him_go_of_one_leaves_the_other() {
    let alice = Person::new("/alice").await;
    let bobs = Person::new("/bob").await;
    let ann = embedded(&alice, ANN, Setup::inviter()).await;
    let bob = embedded(&bobs, "/bob/member/phone", Setup::dialer()).await;
    let (first, second) = (n(FOLDER), n(SECOND));

    invited(&ann, &bob, Role::Writer).await;
    shared(&ann, &second).await;
    invited_in(&ann, &bob, &second, Role::Writer).await;

    // Two entries of one key, one link.
    let grants = ann.links.grants();
    assert_eq!(grants.len(), 2, "{grants:#?}");
    assert!(grants.iter().all(|g| g.key == bob.key));
    // Sorted by key, then folder (by the names' canonical order).
    let mut folders = vec![first.clone(), second.clone()];
    folders.sort();
    assert_eq!(
        grants.iter().map(|g| g.folder.clone()).collect::<Vec<_>>(),
        folders
    );
    until("ann is linked to bob", LONG, async || {
        linked(&ann, bob.key) && linked(&bob, ann.key)
    })
    .await;

    // Both folders sync both ways.
    for folder in [&first, &second] {
        let cover = folder.clone().append("cover");
        until("bob reads ann's cover", LONG, async || {
            reads(&bob.device, &cover, "cover by ann").await
        })
        .await;
        let from_bob = folder.clone().append("from-bob");
        puts(&bob.device, &from_bob, text("bob was here"), LONG).await;
        until("ann reads bob's note", LONG, async || {
            reads(&ann.device, &from_bob, "bob was here").await
        })
        .await;
    }

    // A record that leaves Bob out of the first folder only.
    reshare(&ann, &first, &[n("/alice")]).await;
    until("the first folder's entry ends", LONG, async || {
        let grants = ann.links.grants();
        grants.len() == 1 && grants[0].folder == second
    })
    .await;
    let grants = ann.links.grants();
    assert_eq!(grants[0].key, bob.key);
    assert_eq!(grants[0].role, GrantRole::Writer);

    // The link stands: it was never closed, and the second folder still
    // syncs both ways, with notes written after the first ended.
    let after_ann = second.clone().append("after-ann");
    ann.device
        .put(&after_ann, text("still here"), note())
        .await
        .unwrap();
    until("bob reads what ann writes after", LONG, async || {
        reads(&bob.device, &after_ann, "still here").await
    })
    .await;
    let after_bob = second.clone().append("after-bob");
    puts(&bob.device, &after_bob, text("and me"), LONG).await;
    until("ann reads what bob writes after", LONG, async || {
        reads(&ann.device, &after_bob, "and me").await
    })
    .await;
    assert!(
        linked(&ann, bob.key) && linked(&bob, ann.key),
        "letting Bob go of one folder closed the link of the other: {:#?}",
        ann.links.report()
    );

    // What the ended entry carried is not carried now: an entry Ann writes
    // into the first folder is not answered to Bob; the second's is.
    let left = first.clone().append("after-ann");
    ann.device
        .put(&left, text("not for bob"), note())
        .await
        .unwrap();
    let left_entry = newest_entry(&ann, ANN, &left).await;
    let kept_entry = newest_entry(&ann, ANN, &after_ann).await;
    assert!(
        asks(&bob, ann.key, &kept_entry, false).await,
        "{kept_entry} of the folder Bob stays in was not answered"
    );
    assert!(
        !asks(&bob, ann.key, &left_entry, false).await,
        "{left_entry} of the folder Bob was let go of was answered over his link"
    );
}

/// Three people, each invited separately: Bob and Carol never met, and Ann's
/// grant links to each carry the summary root of the other's namespace (the
/// writers the members record lists), so all three read everything the
/// others wrote (REPLY-17's G11).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_member_reads_another_member_let_in_by_another_invitation() {
    let alice = Person::new("/alice").await;
    let bobs = Person::self_certifying([0xb2; 32]).await;
    let carols = Person::self_certifying([0xc2; 32]).await;
    let ann = embedded(&alice, ANN, Setup::inviter()).await;
    let bob = embedded(&bobs, &bobs.device("phone"), Setup::dialer()).await;
    let carol = embedded(&carols, &carols.device("phone"), Setup::dialer()).await;
    let folder = n(FOLDER);

    invited(&ann, &bob, Role::Writer).await;
    invited_in(&ann, &carol, &folder, Role::Writer).await;
    until("ann is linked to both", LONG, async || {
        linked(&ann, bob.key) && linked(&ann, carol.key)
    })
    .await;

    // Each writes a note of its own.
    let people = [
        (&ann, "from-ann", "ann writes"),
        (&bob, "from-bob", "bob writes"),
        (&carol, "from-carol", "carol writes"),
    ];
    for (who, name, words) in people {
        puts(&who.device, &folder.clone().append(name), text(words), LONG).await;
    }
    // All three read everything.
    for (reader, who) in [(&ann, "ann"), (&bob, "bob"), (&carol, "carol")] {
        for (_, name, words) in people {
            let collection = folder.clone().append(name);
            until(&format!("{who} reads {name}"), LONG, async || {
                reads(&reader.device, &collection, words).await
            })
            .await;
        }
    }
}

/// SHAPES-R7 C: the names a grant carries for the other writers are derived
/// from the members record in force at every packet. A writer the record
/// drops stops being carried: her summary root is refused at the next
/// packet, while her entries of the folder are still carried as the
/// collection's; and a name of hers outside the folder is refused all along.
/// Ann's forwarder also relays Bob's Interest for Carol's entry to Carol's
/// link while her entry stands (Bob's forwarder routing her device name
/// over his link), and no longer once it has ended.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_removed_writers_names_stop_being_carried_and_a_name_outside_the_folder_never_was() {
    let alice = Person::new("/alice").await;
    let bobs = Person::self_certifying([0xb2; 32]).await;
    let carols = Person::self_certifying([0xc2; 32]).await;
    let ann = embedded(&alice, ANN, Setup::inviter()).await;
    let bob = embedded(&bobs, &bobs.device("phone"), Setup::dialer()).await;
    let carol = embedded(&carols, &carols.device("phone"), Setup::dialer()).await;
    let folder = n(FOLDER);

    invited(&ann, &bob, Role::Writer).await;
    invited_in(&ann, &carol, &folder, Role::Writer).await;
    until("ann is linked to both", LONG, async || {
        linked(&ann, bob.key) && linked(&ann, carol.key)
    })
    .await;
    // Carol writes into the folder and, beside it, into a collection of her
    // own namespace that no record gives readers.
    let written = folder.clone().append("from-carol");
    puts(&carol.device, &written, text("carol writes"), LONG).await;
    let diary = carols
        .ns
        .clone()
        .append_component(NameComponent::keyword(Bytes::from_static(b"data")))
        .append("diary");
    puts_op(&carol.device, &diary, b"carol's diary", LONG).await;
    until("ann reads carol's note", LONG, async || {
        reads(&ann.device, &written, "carol writes").await
    })
    .await;
    until("bob reads carol's note", LONG, async || {
        reads(&bob.device, &written, "carol writes").await
    })
    .await;
    // Bob asks for what Carol wrote as the walk does: of Ann, a device that
    // holds it, by the name `<Ann>/32=held/<name>` (spec §13.5), so what
    // Ann's own device holds answers: her copy of Carol's entry of the
    // folder, and (to show the answer is not "everything") her copy of
    // nothing of Carol's diary. The names' derivation from the record at
    // each packet — a listed writer's public names carried, a dropped one's
    // not, her collections outside the folder never — is the unit case
    // `grants::tests::the_public_names_of_a_listed_writer_...`.
    let held = |name: &Name| ndn_data::wire::held_name(&n(ANN), name);
    let carols_entry = held(&newest_entry(&ann, &carols.device("phone"), &written).await);
    let carols_diary = held(&newest_entry(&carol, &carols.device("phone"), &diary).await);

    // While the record lists Carol her entry of the folder crosses Bob's
    // link; her diary, outside the folder, is not answered.
    assert!(
        asks(&bob, ann.key, &carols_entry, false).await,
        "{carols_entry}: the record lists Carol, yet her entry was not answered"
    );
    assert!(
        !asks(&bob, ann.key, &carols_diary, false).await,
        "{carols_diary}, outside the folder, was answered over Bob's link"
    );
    // Ann does relay, bounded, between two grant links: her forwarder has a
    // route for Carol's device name over Carol's link (Carol's identity is
    // admitted by her grant), and Bob's link carries Carol's entries of the
    // folder (`folder_carries`, whoever wrote them). So when Bob's
    // forwarder routes Carol's device name over his link to Ann (as a host's
    // `[[peer]]` entry for Carol through relay Ann does), Bob's Interest
    // for Carol's entry passes his link's filter, Ann's forwarder sends it
    // over Carol's link, which carries it (her own device's name), and the
    // Data returns the same way. What Bob cannot ask Ann to fetch is
    // judged per packet at Bob's link: Carol's diary, outside the folder, is
    // not carried.
    let carols_entry_direct = newest_entry(&ann, &carols.device("phone"), &written).await;
    let carols_diary_direct = newest_entry(&carol, &carols.device("phone"), &diary).await;
    let bobs_face_to_ann = bob
        .links
        .report()
        .links
        .iter()
        .filter(|l| l.key == Some(ann.key))
        .flat_map(|l| l.paths.iter().map(|p| p.face))
        .next()
        .expect("bob's link to ann");
    bob.engine
        .fib()
        .add_nexthop(&n(&carols.device("phone")), bobs_face_to_ann, 10);
    let before_relay = interests_at(&carol, ann.key);
    assert!(
        asks(&bob, ann.key, &carols_entry_direct, false).await,
        "{carols_entry_direct}, Carol's entry of the folder, was not relayed by Ann to Carol's link"
    );
    let carol_was_asked = interests_at(&carol, ann.key) - before_relay;
    // What Carol's side of the link was asked: the counter measures the
    // relay (it rises for the ask above, which Ann relays to Carol).
    assert!(
        carol_was_asked > 0,
        "{carols_entry_direct}: Carol's link carried no Interest of the relay above"
    );
    assert!(
        !asks(&bob, ann.key, &carols_diary_direct, false).await,
        "{carols_diary_direct}, outside the folder, was relayed for Bob"
    );

    // A record without Carol: her entry ends; Bob's link and his reading of
    // what she wrote stand (the entries are the collection's, carried
    // whoever wrote them); her diary is still not answered.
    reshare(&ann, &folder, &[alice.ns.clone(), bobs.ns.clone()]).await;
    until("carol's entry ends", LONG, async || {
        ann.links.grants().iter().all(|g| g.key != carol.key)
    })
    .await;
    assert!(
        asks(&bob, ann.key, &carols_entry, false).await,
        "{carols_entry}, an entry of the folder, stopped being carried with its writer"
    );
    assert!(
        !asks(&bob, ann.key, &carols_diary, false).await,
        "{carols_diary}, outside the folder, was answered over Bob's link"
    );
    assert!(linked(&ann, bob.key), "Bob's link closed with Carol's");
    // Carol's link is gone, and with it Ann's route to her device name: the
    // relay ended with her entry, whatever Bob's forwarder sends. Ann's copy of
    // Carol's entry (her content store) may answer Bob, who may read it: what
    // must not happen is that the Interest reaches Carol, so what Carol's side
    // of the link is asked is what is counted.
    let before_ask = interests_at(&carol, ann.key);
    let _answered_from_ann_s_copy = asks(&bob, ann.key, &carols_entry_direct, false).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        interests_at(&carol, ann.key),
        before_ask,
        "{carols_entry_direct} was relayed to a writer whose link had ended"
    );
}

/// SHAPES-R7 C: a grant's role is per entry and judged at every packet. Bob
/// is a reader of one folder: the Data he answers with under a name only a
/// writer's entry carries (his namespace's sync group) is dropped at Ann's
/// end, as a reader's push always was. By a second invitation he is a writer
/// of another folder: the same answer then passes, on the same link. When
/// the writer entry ends (a record without him), the reader's entry alone
/// stands and the answer is dropped again, again with no close. (The names
/// of one folder against another's are in `tests/grant_rules.rs`: Ann's
/// forwarder routes only Bob's names over his link, so a real Interest for a
/// folder's names under another device's name cannot be asked of him.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reader_role_grant_gains_no_push_scope_and_a_writer_entry_of_another_folder_passes() {
    let alice = Person::new("/alice").await;
    let bobs = Person::new("/bob").await;
    let ann = embedded(&alice, ANN, Setup::inviter()).await;
    let bob = embedded(&bobs, "/bob/member/phone", Setup::dialer()).await;
    let second = n(SECOND);
    answers_probes(&bob);

    invited(&ann, &bob, Role::Reader).await;
    until("ann is linked to bob", LONG, async || {
        linked(&ann, bob.key) && linked(&bob, ann.key)
    })
    .await;
    assert!(
        !probes(&ann, &bob, "reader").await,
        "the Data a reader pushed crossed Ann's end of the link"
    );

    // A writer of the second folder as well: what a writer's entry carries
    // passes.
    shared(&ann, &second).await;
    invited_in(&ann, &bob, &second, Role::Writer).await;
    let roles: Vec<_> = ann.links.grants().iter().map(|g| g.role).collect();
    assert_eq!(roles.len(), 2, "{roles:?}");
    assert!(roles.contains(&GrantRole::Reader) && roles.contains(&GrantRole::Writer));
    assert!(
        probes(&ann, &bob, "writer").await,
        "the Data a writer of the second folder pushed was dropped"
    );

    // The writer entry ends: the reader's entry alone stands.
    reshare(&ann, &second, &[n("/alice")]).await;
    until("the second folder's entry ends", LONG, async || {
        ann.links.grants().len() == 1
    })
    .await;
    assert_eq!(ann.links.grants()[0].role, GrantRole::Reader);
    assert!(
        !probes(&ann, &bob, "reader-again").await,
        "a Data crossed Ann's end of the link after the only writer entry ended"
    );
    assert!(
        linked(&ann, bob.key) && linked(&bob, ann.key),
        "an entry ending closed the link a reader's entry still holds"
    );
}
