//! A commit made while no link was up is shared at once when the link comes
//! up, on real QUIC links between real data-layer devices (ndn-rs
//! `heap.md`, a group announced when a face comes up).
//!
//! Ann and Bob share a folder and are linked; Bob's link goes down, Ann
//! commits a version (her announcement of it reaches no one), and the link
//! comes up again. The devices run with the **default** sync configuration
//! (an announcement every 30 s): Bob reads the version within seconds, from
//! the announcement the link's routes bring about, not from the periodic one.

mod common;

use std::time::{Duration, Instant};

use common::*;
use ndn_invite::Role;

/// How long after the link comes up Bob has to read what Ann committed with
/// no link: far under the group's period (30 s), so only an announcement
/// made because the link came up can meet it.
const WITHIN: Duration = Duration::from_secs(10);

/// Take Bob's link down, Ann commits `what` as `name`, and Bob's link comes
/// up again: how long Bob took to read it, counted from the link coming up.
async fn commits_offline_then_links(
    ann: &Embedded,
    bob: &Embedded,
    name: &ndn_packet::Name,
    what: &str,
) -> Duration {
    until("ann and bob are linked", LONG, async || {
        linked(ann, bob.key) && linked(bob, ann.key)
    })
    .await;
    bob.links.set_online(false);
    until("the link ends on both sides", LONG, async || {
        !linked(ann, bob.key) && !linked(bob, ann.key)
    })
    .await;
    puts(ann, name, text(what), LONG).await;
    assert!(reads(ann, name, what).await, "ann reads her own commit");
    // No link: nothing of it reaches Bob.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!reads(bob, name, what).await, "bob read it with no link up");

    let up = Instant::now();
    bob.links.set_online(true);
    while !reads(bob, name, what).await {
        assert!(
            up.elapsed() < WITHIN,
            "Bob did not read it within {WITHIN:?} of the link coming up \
             (linked: ann {}, bob {})",
            linked(ann, bob.key),
            linked(bob, ann.key)
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    up.elapsed()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_commit_made_while_no_link_was_up_is_read_within_seconds_of_the_link_coming_up() {
    let alice = Person::new("/alice").await;
    let bobs = Person::new("/bob").await;
    let ann = embedded(&alice, ANN, Setup::inviter()).await;
    // Bob's device never announces because a face came up: only Ann's
    // announcement can bring him her version before the period.
    let bob = embedded(
        &bobs,
        "/bob/member/phone",
        Setup {
            sync_tells_no_routes: true,
            ..Setup::dialer()
        },
    )
    .await;
    invited(&ann, &bob, Role::Writer).await;
    let folder = n(FOLDER);
    let cover = folder.clone().append("cover");
    until("bob reads ann's cover", LONG, async || {
        reads(&bob, &cover, "cover by ann").await
    })
    .await;

    let offline = folder.append("written-offline");
    let took = commits_offline_then_links(&ann, &bob, &offline, "written with no link").await;
    eprintln!("connect to read: {took:?}");
}
