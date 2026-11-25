//! A relay routes the sync groups of the spaces its device follows, and only
//! those (ndn-rs `ndn-link.md` §5.10, §10, §13.6, Decision 42), on real QUIC
//! links between real devices on forwarders of their own.
//!
//! Alice (`/sa`) and Bob (`/sb`) reach each other through an open relay (`/sr`)
//! that holds no context of either. Alice has two spaces, `doc` and `chat`
//! (groups `/sa/32=sync/doc` and `/sa/32=sync/chat`); Bob follows `doc` only:
//! his host gives his links that exact group ([`Links::set_followed_groups`]).
//! Alice's Sync Interests of her group `doc` leave her forwarder over her
//! relay face and reach Bob only when the relay routes that group over Bob's
//! link, which it does because Bob's hello told it he follows it; the group of
//! `chat`, another space of the same namespace, is not routed to him.

mod common;

use std::time::Duration;

use bytes::Bytes;
use common::*;
use ndn_app::EngineAppExt;
use ndn_link::{FollowedGroupsError, PeerSpec, RelaySource, RelayUse};
use ndn_packet::Name;

/// The relay `relay` as a peer entry of a device that uses it.
fn relay_entry(relay: &Embedded) -> PeerSpec {
    PeerSpec {
        label: "relay".into(),
        key: Some(relay.key),
        endpoints: vec![relay.addr.expect("the relay listens").to_string()],
        persistent: true,
        relay_use: Some(RelayUse {
            source: RelaySource::User,
            preference: 0,
        }),
        ..PeerSpec::default()
    }
}

/// The sync group of the space `space` of `owner`, as the data layer names it.
fn group_of(owner: &Name, space: &str) -> Name {
    format!("{owner}/32=sync/{space}").parse().unwrap()
}

/// Where the group `group` is probed.
fn probe_in(group: &Name) -> Name {
    group.clone().append("probe")
}

/// `on` answers every Interest under `prefix` with a Data.
fn answers_under(on: &Embedded, prefix: Name) {
    let producer = on.engine.register_producer(prefix, on.cancel.child_token());
    tokio::spawn(async move {
        let _ = producer
            .serve(|interest, responder| async move {
                let _ = responder
                    .respond((*interest.name).clone(), Bytes::from_static(b"probe"))
                    .await;
            })
            .await;
    });
}

/// Whether `from` fetches `<prefix>/<tag>`.
async fn fetches(from: &Embedded, prefix: &Name, tag: &str) -> bool {
    let mut consumer = from.engine.app_consumer(from.cancel.child_token());
    consumer.fetch(prefix.clone().append(tag)).await.is_ok()
}

struct World {
    sa: Person,
    relay: Embedded,
    alice: Embedded,
    bob: Embedded,
}

impl World {
    /// The relay routes `group` over Bob's link.
    fn routes_to_bob(&self, group: &Name) -> bool {
        routed_over(&self.relay, self.bob.key).contains(&group.to_string())
    }
}

/// Alice and Bob, each linked to the relay they use. Bob follows the `doc`
/// group of `/sa` from the start when `follows`.
async fn world(follows: bool) -> World {
    let (sa, sb, sr) = (
        Person::with_ca("/sa").await,
        Person::with_ca("/sb").await,
        Person::new("/sr").await,
    );
    let relay = embedded(&sr, &sr.device("relay"), Setup::open()).await;
    let alice = embedded(&sa, &sa.device("laptop"), Setup::dialer()).await;
    let bob = embedded(&sb, &sb.device("phone"), Setup::dialer()).await;
    if follows {
        bob.links
            .set_followed_groups([group_of(&sa.ns, "doc")])
            .unwrap();
    }
    alice.links.add_peer(relay_entry(&relay));
    bob.links.add_peer(relay_entry(&relay));
    until("alice and bob link to the relay", LONG, async || {
        linked(&alice, relay.key) && linked(&bob, relay.key)
    })
    .await;
    World {
        sa,
        relay,
        alice,
        bob,
    }
}

/// Bob follows the `doc` space of `/sa`: the relay routes `/sa/32=sync/doc`
/// over his link, beside his own namespace's group, and over no other link
/// that did not claim it (Alice's carries `/sa/32=sync` because she is served
/// for `/sa`; a third device of `/sc` that follows nothing gets neither). The
/// route is that one group's alone: neither the owner's whole group nor
/// another space of `/sa` (`chat`) is routed to Bob, and no other name of
/// `/sa`. Alice's Sync Interest under the `doc` group, from her side of the
/// relay, reaches Bob's forwarder and his Data comes back; her Sync Interest
/// under the `chat` group does not reach him, though Bob's forwarder would
/// answer it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relay_routes_the_group_of_the_space_its_device_follows_and_no_other_space_of_the_namespace()
 {
    let w = world(true).await;
    let carol_person = Person::with_ca("/sc").await;
    let carol = embedded(&carol_person, &carol_person.device("tab"), Setup::dialer()).await;
    carol.links.add_peer(relay_entry(&w.relay));
    until("carol links to the relay", LONG, async || {
        linked(&carol, w.relay.key)
    })
    .await;

    let doc = group_of(&w.sa.ns, "doc");
    let chat = group_of(&w.sa.ns, "chat");
    let whole = ndn_security::sync_group(&w.sa.ns);
    let at_bob = routed_over(&w.relay, w.bob.key);
    assert!(
        at_bob.contains(&doc.to_string()),
        "the relay's routes over Bob's link: {at_bob:?}"
    );
    assert!(
        at_bob.contains(&ndn_security::sync_group(&n("/sb")).to_string()),
        "his own group is routed still: {at_bob:?}"
    );
    assert!(
        at_bob
            .iter()
            .all(|p| *p == doc.to_string() || !p.starts_with("/sa")),
        "a claim of following routed more than the one group: {at_bob:?}"
    );
    assert!(
        !at_bob.contains(&whole.to_string()) && !at_bob.contains(&chat.to_string()),
        "the owner's whole group or another space of it is routed to Bob: {at_bob:?}"
    );
    let at_carol = routed_over(&w.relay, carol.key);
    assert!(
        !at_carol.iter().any(|p| p.starts_with("/sa")),
        "a device that follows nothing was routed /sa: {at_carol:?}"
    );

    // Bob's forwarder would answer under both groups: only one is routed to him.
    answers_under(&w.bob, probe_in(&doc));
    answers_under(&w.bob, probe_in(&chat));
    let prefix = probe_in(&doc);
    until(
        "Alice's Sync Interest of the followed space reaches Bob through the relay",
        Duration::from_secs(20),
        async || fetches(&w.alice, &prefix, "1").await,
    )
    .await;
    assert!(
        !fetches(&w.alice, &probe_in(&chat), "1").await,
        "Alice's Sync Interest of a space Bob does not follow reached him"
    );
}

/// A space Bob follows after his link to the relay is up reaches the relay on
/// a link made again (his hello tells the relay what he follows): the route
/// appears over the new link, and not before.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_space_followed_later_is_routed_by_the_relay_once_the_link_is_made_again() {
    let w = world(false).await;
    let doc = group_of(&w.sa.ns, "doc");
    assert!(
        !w.routes_to_bob(&doc),
        "Bob followed nothing yet: {:?}",
        routed_over(&w.relay, w.bob.key)
    );

    w.bob.links.set_followed_groups([doc.clone()]).unwrap();
    until(
        "the relay routes the group of the space over Bob's link",
        Duration::from_secs(30),
        async || linked(&w.bob, w.relay.key) && w.routes_to_bob(&doc),
    )
    .await;

    answers_under(&w.bob, probe_in(&doc));
    let prefix = probe_in(&doc);
    until(
        "Alice's Sync Interest reaches Bob through the relay",
        Duration::from_secs(20),
        async || fetches(&w.alice, &prefix, "2").await,
    )
    .await;
}

/// A space Bob stops following is no longer told: his link is made again and
/// the relay's route over it goes; the one he still follows stays.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_space_no_longer_followed_loses_the_relays_route_when_the_link_is_made_again() {
    let w = world(false).await;
    let (doc, chat) = (group_of(&w.sa.ns, "doc"), group_of(&w.sa.ns, "chat"));
    w.bob
        .links
        .set_followed_groups([chat.clone(), doc.clone()])
        .unwrap();
    until(
        "the relay routes both groups over Bob's link",
        Duration::from_secs(30),
        async || linked(&w.bob, w.relay.key) && w.routes_to_bob(&doc) && w.routes_to_bob(&chat),
    )
    .await;

    w.bob.links.set_followed_groups([doc.clone()]).unwrap();
    until(
        "the relay's route of the group Bob left goes",
        Duration::from_secs(30),
        async || linked(&w.bob, w.relay.key) && !w.routes_to_bob(&chat) && w.routes_to_bob(&doc),
    )
    .await;
}

/// The host's set is all or nothing, and names space groups only: a
/// namespace and an owner's whole group (the prefix of every space of the
/// owner) are refused, saying why, as is a set of more groups than a hello
/// names; the set given before stays, and the same set again changes nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_hosts_followed_groups_name_exact_spaces_or_are_refused_whole() {
    let w = world(false).await;
    let doc = group_of(&w.sa.ns, "doc");
    let links = &w.bob.links;
    links.set_followed_groups([doc.clone()]).unwrap();

    for (bad, word) in [
        (w.sa.ns.clone(), "32=sync"),
        (ndn_security::sync_group(&w.sa.ns), "whole group"),
    ] {
        let refused = links
            .set_followed_groups([group_of(&w.sa.ns, "chat"), bad.clone()])
            .unwrap_err();
        assert!(
            matches!(&refused, FollowedGroupsError::NotAGroup { group, .. } if *group == bad),
            "{refused:?}"
        );
        assert!(refused.to_string().contains(word), "{refused}");
        assert_eq!(
            links.followed_groups(),
            std::slice::from_ref(&doc),
            "a refusal changed the set"
        );
    }

    let max = ndn_face_quic::FOLLOWS_MAX;
    let many: Vec<Name> = (0..=max)
        .map(|i| group_of(&w.sa.ns, &format!("s{i}")))
        .collect();
    let refused = links.set_followed_groups(many.clone()).unwrap_err();
    assert_eq!(refused, FollowedGroupsError::TooMany { given: many.len() });
    assert!(refused.to_string().contains("at most"), "{refused}");
    assert_eq!(links.followed_groups(), std::slice::from_ref(&doc));

    // The limit itself is fine; a group named twice counts once.
    let mut at_limit = many[..max].to_vec();
    at_limit.push(many[0].clone());
    links.set_followed_groups(at_limit).unwrap();
    assert_eq!(links.followed_groups().len(), max);
    links.set_followed_groups(Vec::new()).unwrap();
    assert!(links.followed_groups().is_empty());
}
