//! The ask exchange over a grant link has a small rate of its own (ndn-rs
//! `ndn-link.md` §8.7 rule 20): a peer may send `ASK_INTERESTS` (10 at once,
//! then 1 a second) Interests `<W>/<role>/<device>/32=ask-answer/<digest>` over
//! its link, beside the link's quota of 100/s, so that a person who floods a
//! signer with asks it would have to open, verify and answer is held to a
//! trickle at the link, before the signer's Device sees them. An honest asker
//! (nine Interests of one question to one signer: `ASK_ATTEMPTS` 3 × `ASK_SENDS`
//! 3, one ask in flight) never meets it, and the plain fetch of a seal key is
//! not rated.
//!
//! Real QUIC, real forwarders: Ann invites Bob; a device of Ann's namespace on
//! her forwarder counts what reaches it and answers everything, so what is
//! counted is what the link let through.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use common::{ANN, Embedded, LONG, Person, Setup, embedded, invited, linked, n, until};
use ndn_app::{EngineAppExt, FaceId};
use ndn_data::Role;
use ndn_face_quic::KeyFingerprint;
use ndn_packet::{Name, NameComponent};

/// The signer of the test: a device of Ann's namespace.
const SIGNER: &str = "/alice/member/lamp";
/// `ASK_ATTEMPTS` × `ASK_SENDS` of ndn-data: what an honest asker sends to one
/// signer for one question.
const HONEST_ASK: usize = 9;
/// What the link allows at once.
const BURST: usize = 10;

fn keyword(name: Name, word: &'static [u8]) -> Name {
    name.append_component(NameComponent::keyword(Bytes::from_static(word)))
}

/// A device at [`SIGNER`] on Ann's forwarder that answers whatever it is asked
/// and counts the Interests it sees, and Bob's route to it over his link to Ann
/// (the test's: what is judged is the link).
fn signer(ann: &Embedded, bob: &Embedded) -> (Arc<AtomicUsize>, FaceId) {
    let seen = Arc::new(AtomicUsize::new(0));
    let producer = ann
        .engine
        .register_producer(n(SIGNER), ann.cancel.child_token());
    let counted = Arc::clone(&seen);
    tokio::spawn(async move {
        let _ = producer
            .serve(move |interest, responder| {
                let counted = Arc::clone(&counted);
                async move {
                    counted.fetch_add(1, Ordering::SeqCst);
                    let _ = responder
                        .respond((*interest.name).clone(), Bytes::from_static(b"here"))
                        .await;
                }
            })
            .await;
    });
    let face = bob
        .links
        .report()
        .links
        .iter()
        .filter(|l| l.key == Some(ann.key))
        .flat_map(|l| l.paths.iter().map(|p| p.face))
        .next()
        .expect("bob is linked to ann");
    bob.engine.fib().add_nexthop(&n(SIGNER), face, 0);
    (seen, face)
}

/// `count` asks `<signer>/32=ask-answer/<digest>`, each with parameters of its
/// own, sent at once over `face`: how many were answered.
async fn asks(bob: &Embedded, face: FaceId, count: usize, tag: u8) -> usize {
    let prefix = keyword(n(SIGNER), b"ask-answer");
    let mut sent = tokio::task::JoinSet::new();
    for i in 0..count {
        let mut consumer = bob.engine.app_consumer(bob.cancel.child_token());
        let interest = ndn_packet::encode::InterestBuilder::new(prefix.clone())
            .lifetime(Duration::from_secs(2))
            .app_parameters(vec![tag, (i % 251) as u8, (i / 251) as u8]);
        sent.spawn(async move { consumer.fetch_with_on(face, interest).await.is_ok() });
    }
    let mut answered = 0;
    while let Some(done) = sent.join_next().await {
        answered += usize::from(done.unwrap());
    }
    answered
}

/// Whether Bob is answered the plain fetch of a seal key of the signer.
async fn seal_crosses(bob: &Embedded, key: KeyFingerprint) -> bool {
    let name = keyword(n(SIGNER), b"seal")
        .append_component(NameComponent::generic(Bytes::from_static(&[7; 32])));
    common::asks(bob, key, &name, false).await
}

async fn linked_pair() -> (Embedded, Embedded) {
    let (alice, bobs) = (Person::new("/alice").await, Person::new("/bob").await);
    let ann = embedded(&alice, ANN, Setup::inviter()).await;
    let bob = embedded(&bobs, "/bob/member/phone", Setup::dialer()).await;
    invited(&ann, &bob, Role::Writer).await;
    until("ann is linked to bob", LONG, async || linked(&ann, bob.key)).await;
    (ann, bob)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_flood_of_asks_over_a_grant_link_is_held_to_its_rate_at_the_link() {
    let (ann, bob) = linked_pair().await;
    let (seen, face) = signer(&ann, &bob);
    let started = Instant::now();
    let answered = asks(&bob, face, 100, 1).await;
    let allowed = BURST + started.elapsed().as_secs() as usize + 1;
    let reached = seen.load(Ordering::SeqCst);
    assert!(
        reached <= allowed,
        "the signer's Device saw {reached} of 100 asks in {:?}: the link lets at most {allowed} \
         through (burst {BURST}, then 1 a second)",
        started.elapsed()
    );
    assert!(
        reached >= HONEST_ASK,
        "the link let only {reached} asks through: an honest question's {HONEST_ASK} must pass"
    );
    assert_eq!(answered, reached, "every ask that crossed was answered");
    // The seal key is fetched, not asked: the drained bucket does not hold it.
    assert!(
        seal_crosses(&bob, ann.key).await,
        "the fetch of a seal key was refused after a flood of asks"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_honest_ask_of_nine_sends_in_a_burst_passes() {
    let (ann, bob) = linked_pair().await;
    let (seen, face) = signer(&ann, &bob);
    // One question to one signer: nine Interests at once, as the data layer's
    // three attempts of three sends are at the worst.
    let answered = asks(&bob, face, HONEST_ASK, 2).await;
    assert_eq!(
        (answered, seen.load(Ordering::SeqCst)),
        (HONEST_ASK, HONEST_ASK),
        "an honest ask's {HONEST_ASK} Interests did not all cross the grant link"
    );
}
