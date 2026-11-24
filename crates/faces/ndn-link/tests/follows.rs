//! A relay routes the sync group of a space its device follows (ndn-rs
//! `ndn-link.md` §10, Decision 34), on real QUIC links between real devices on
//! forwarders of their own.
//!
//! Alice (`/sa`) and Bob (`/sb`) reach each other through an open relay (`/sr`)
//! that holds no context of either. Bob follows `/sa` (holds its trust context,
//! no certificate in it); Alice's Sync Interests of her group `/sa/32=sync`
//! leave her forwarder over her relay face and reach Bob only when the relay
//! routes that group over Bob's link, which it does because Bob's hello told
//! it he follows `/sa`.

mod common;

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use common::*;
use ndn_app::EngineAppExt;
use ndn_link::{PeerSpec, RelaySource, RelayUse};
use ndn_packet::Name;
use ndn_security::sync_group;

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

/// Where the group of `ns` is probed.
fn probe_in(ns: &Name) -> Name {
    sync_group(ns).append("probe")
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

/// The sync group of `ns`, as the relay's route table shows it.
fn group(ns: &Name) -> String {
    sync_group(ns).to_string()
}

impl World {
    /// The relay routes the group of Alice's namespace over Bob's link.
    fn sa_group_at_bob(&self) -> bool {
        routed_over(&self.relay, self.bob.key).contains(&group(&self.sa.ns))
    }
}

/// Alice and Bob, each linked to the relay they use. Bob follows `/sa` from
/// the start when `follows`.
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
        bob.validator.adopt_context(Arc::clone(&sa.ctx)).unwrap();
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

/// Bob follows `/sa`: the relay routes `/sa/32=sync` over his link, beside
/// his own namespace's group, and over no other link that did not claim it
/// (Alice's carries the group because she is served for `/sa`; a third device
/// of `/sc` that follows nothing gets neither). The route is the group's
/// alone: no other name of `/sa` is routed to Bob. Alice's Sync Interest
/// under the group, from her side of the relay, reaches Bob's forwarder and
/// his Data comes back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relay_routes_the_group_of_a_space_its_device_follows_and_alices_sync_interest_reaches_bob()
 {
    let w = world(true).await;
    let carol_person = Person::with_ca("/sc").await;
    let carol = embedded(&carol_person, &carol_person.device("tab"), Setup::dialer()).await;
    carol.links.add_peer(relay_entry(&w.relay));
    until("carol links to the relay", LONG, async || {
        linked(&carol, w.relay.key)
    })
    .await;

    let group_a = group(&w.sa.ns);
    let at_bob = routed_over(&w.relay, w.bob.key);
    assert!(
        at_bob.contains(&group_a),
        "the relay's routes over Bob's link: {at_bob:?}"
    );
    assert!(
        at_bob.contains(&group(&n("/sb"))),
        "his own group is routed still: {at_bob:?}"
    );
    assert!(
        at_bob
            .iter()
            .all(|p| *p == group_a || !p.starts_with("/sa")),
        "a claim of following routed more than the group: {at_bob:?}"
    );
    let at_carol = routed_over(&w.relay, carol.key);
    assert!(
        !at_carol.iter().any(|p| p.starts_with("/sa")),
        "a device that follows nothing was routed /sa: {at_carol:?}"
    );

    // The probe is Bob's answer under Alice's group, asked from Alice.
    answers_under(&w.bob, probe_in(&w.sa.ns));
    let prefix = probe_in(&w.sa.ns);
    until(
        "Alice's Sync Interest reaches Bob through the relay",
        Duration::from_secs(20),
        async || fetches(&w.alice, &prefix, "1").await,
    )
    .await;
}

/// A namespace Bob follows after his link to the relay is up reaches the relay
/// on a link made again (his hello tells the relay what he follows): the
/// route appears over the new link, and not before.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_namespace_followed_later_is_routed_by_the_relay_once_the_link_is_made_again() {
    let w = world(false).await;
    assert!(
        !w.sa_group_at_bob(),
        "Bob followed nothing yet: {:?}",
        routed_over(&w.relay, w.bob.key)
    );

    w.bob
        .validator
        .adopt_context(Arc::clone(&w.sa.ctx))
        .unwrap();
    w.bob.links.followed_changed();
    until(
        "the relay routes the group of /sa over Bob's link",
        Duration::from_secs(30),
        async || linked(&w.bob, w.relay.key) && w.sa_group_at_bob(),
    )
    .await;

    answers_under(&w.bob, probe_in(&w.sa.ns));
    let prefix = probe_in(&w.sa.ns);
    until(
        "Alice's Sync Interest reaches Bob through the relay",
        Duration::from_secs(20),
        async || fetches(&w.alice, &prefix, "2").await,
    )
    .await;
}

/// A namespace Bob stops following is no longer told: his link is made again
/// and the relay's route over it goes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_namespace_no_longer_followed_loses_the_relays_route_when_the_link_is_made_again() {
    let w = world(true).await;
    until(
        "the relay routes the group of /sa over Bob's link",
        Duration::from_secs(30),
        async || w.sa_group_at_bob(),
    )
    .await;

    w.bob.validator.keyring().forget(&w.sa.ns);
    w.bob.links.followed_changed();
    until(
        "the relay's route over Bob's link goes",
        Duration::from_secs(30),
        async || linked(&w.bob, w.relay.key) && !w.sa_group_at_bob(),
    )
    .await;
}
