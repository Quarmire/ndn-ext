//! NDNLPv2 reliability on the links a device makes by introduction, by grant, by
//! memory redial and by first contact (ndn-rs `ndn-link.md` §9 item 3, round 12): a link
//! made any of those ways reports it at both its ends, a host can turn a kind off,
//! and over a lossy link a transfer over one of them needs no re-expression where the
//! same link without it does.
//!
//! Real data-layer devices on real forwarders over real QUIC (the harness of
//! `tests/common`); a link's status says whether its link service frames
//! reliability ([`PathStatus::reliability`]).

mod common;

use std::time::Duration;

use common::{
    ANN, Embedded, LONG, Person, Setup, dials, embedded, invited, linked, n, offered, until,
};
use ndn_face_quic::KeyFingerprint;
use ndn_invite::{Role, introduction_prefixes};
use ndn_link::{LinkReliability, PeerSpec};

/// Whether each path `on` has to the device with `key` frames reliability; empty when it
/// has none.
fn reliable(on: &Embedded, key: KeyFingerprint) -> Vec<bool> {
    on.links
        .report()
        .links
        .iter()
        .filter(|l| l.key == Some(key))
        .flat_map(|l| l.paths.iter().map(|p| p.reliability))
        .collect()
}

/// `on` has at least one path to `key` and all of them frame reliability.
fn all_reliable(on: &Embedded, key: KeyFingerprint) -> bool {
    let paths = reliable(on, key);
    !paths.is_empty() && paths.iter().all(|r| *r)
}

/// No path `on` has to `key` frames reliability, and it has one.
fn none_reliable(on: &Embedded, key: KeyFingerprint) -> bool {
    let paths = reliable(on, key);
    !paths.is_empty() && paths.iter().all(|r| !*r)
}

/// A device dialled by the key a code names, and the introduction link the inviter
/// took from the stranger: both ends of the link frame reliability.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_link_dialled_by_key_and_the_introduction_link_it_makes_have_reliability() {
    let (alice, bobs) = (Person::new("/alice").await, Person::new("/bob").await);
    let ann = embedded(&alice, ANN, Setup::inviter()).await;
    let bob = embedded(&bobs, &bobs.device("phone"), Setup::dialer()).await;
    let _code = offered(&ann, Role::Writer).await;

    dials(&bob, &ann).await.unwrap_or_else(|e| panic!("{e:?}"));
    until("the inviter reports the link", LONG, async || {
        linked(&ann, bob.key)
    })
    .await;

    assert!(
        all_reliable(&bob, ann.key),
        "the link bob dialled by key: {:#?}",
        bob.links.report()
    );
    assert!(
        all_reliable(&ann, bob.key),
        "the introduction link ann took from a stranger: {:#?}",
        ann.links.report()
    );
}

/// A first contact (no key to expect), and the introduction link the inviter took.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_first_contact_link_has_reliability_at_both_ends() {
    let (alice, bobs) = (Person::new("/alice").await, Person::new("/bob").await);
    let ann = embedded(&alice, ANN, Setup::inviter()).await;
    let bob = embedded(&bobs, &bobs.device("phone"), Setup::dialer()).await;
    let _code = offered(&ann, Role::Writer).await;
    let device = n(ANN);

    let proved = bob
        .links
        .dial_first(
            device.clone(),
            ann.addr.unwrap(),
            Duration::from_secs(10),
            introduction_prefixes(&device).into(),
        )
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(proved, ann.key);
    until("the inviter reports the link", LONG, async || {
        linked(&ann, bob.key)
    })
    .await;

    assert!(
        all_reliable(&bob, ann.key),
        "the first-contact link bob dialled: {:#?}",
        bob.links.report()
    );
    assert!(
        all_reliable(&ann, bob.key),
        "the introduction link ann took: {:#?}",
        ann.links.report()
    );
}

/// The link of a person an invitation admitted: the inviter's end is the grant's, the
/// joiner's the one it dialled and made again once it held the inviter's namespace.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_grant_link_has_reliability_at_both_ends() {
    let (alice, bobs) = (Person::new("/alice").await, Person::new("/bob").await);
    let ann = embedded(&alice, ANN, Setup::inviter()).await;
    let bob = embedded(&bobs, &bobs.device("phone"), Setup::dialer()).await;
    invited(&ann, &bob, Role::Writer).await;

    until("ann's link is the grant's", LONG, async || {
        ann.links
            .report()
            .links
            .iter()
            .any(|l| l.key == Some(bob.key) && l.granted.is_some() && !l.paths.is_empty())
    })
    .await;
    until("bob's link is the one made again", LONG, async || {
        bob.links
            .report()
            .links
            .iter()
            .any(|l| l.key == Some(ann.key) && l.device == Some(n(ANN)) && !l.paths.is_empty())
    })
    .await;

    assert!(
        all_reliable(&ann, bob.key),
        "the grant link at ann: {:#?}",
        ann.links.report()
    );
    assert!(
        all_reliable(&bob, ann.key),
        "the link at bob: {:#?}",
        bob.links.report()
    );
}

/// Both devices of a case, with `reliability` for each.
async fn pair(reliability: LinkReliability) -> (Embedded, Embedded) {
    let (alice, bobs) = (Person::new("/alice").await, Person::new("/bob").await);
    let ann = embedded(
        &alice,
        ANN,
        Setup {
            reliability,
            ..Setup::inviter()
        },
    )
    .await;
    let bob = embedded(
        &bobs,
        &bobs.device("phone"),
        Setup {
            reliability,
            ..Setup::dialer()
        },
    )
    .await;
    (ann, bob)
}

/// A host turns the introduction kind off: neither the link bob dialled by key nor the
/// introduction link ann took has reliability.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_can_turn_the_introduction_kind_off() {
    let (ann, bob) = pair(LinkReliability {
        introduced: false,
        ..LinkReliability::default()
    })
    .await;
    let _code = offered(&ann, Role::Writer).await;
    dials(&bob, &ann).await.unwrap_or_else(|e| panic!("{e:?}"));
    until("the inviter reports the link", LONG, async || {
        linked(&ann, bob.key)
    })
    .await;

    assert!(
        none_reliable(&bob, ann.key),
        "bob's link: {:#?}",
        bob.links.report()
    );
    assert!(
        none_reliable(&ann, bob.key),
        "ann's link: {:#?}",
        ann.links.report()
    );
}

/// A host turns the first-contact kind off: the link bob dialled has none, and the
/// introduction link ann took (another kind, still on) has.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_can_turn_the_first_contact_kind_off() {
    let (ann, bob) = pair(LinkReliability {
        first_contact: false,
        ..LinkReliability::default()
    })
    .await;
    let _code = offered(&ann, Role::Writer).await;
    let device = n(ANN);
    bob.links
        .dial_first(
            device.clone(),
            ann.addr.unwrap(),
            Duration::from_secs(10),
            introduction_prefixes(&device).into(),
        )
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    until("the inviter reports the link", LONG, async || {
        linked(&ann, bob.key)
    })
    .await;

    assert!(
        none_reliable(&bob, ann.key),
        "bob's first contact: {:#?}",
        bob.links.report()
    );
    assert!(
        all_reliable(&ann, bob.key),
        "ann's introduction link: {:#?}",
        ann.links.report()
    );
}

/// A host turns the grant kind off: ann's end of the grant link has none, and bob's end
/// (the link he dialled, another kind, still on) has.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_can_turn_the_grant_kind_off() {
    let (ann, bob) = pair(LinkReliability {
        granted: false,
        ..LinkReliability::default()
    })
    .await;
    invited(&ann, &bob, Role::Writer).await;
    until("ann's link is the grant's", LONG, async || {
        ann.links
            .report()
            .links
            .iter()
            .any(|l| l.key == Some(bob.key) && l.granted.is_some() && !l.paths.is_empty())
    })
    .await;
    until("bob's link is the one made again", LONG, async || {
        bob.links
            .report()
            .links
            .iter()
            .any(|l| l.key == Some(ann.key) && l.device == Some(n(ANN)) && !l.paths.is_empty())
    })
    .await;

    assert!(
        none_reliable(&ann, bob.key),
        "ann's grant link: {:#?}",
        ann.links.report()
    );
    assert!(
        all_reliable(&bob, ann.key),
        "bob's link: {:#?}",
        bob.links.report()
    );
}

/// A link a host configured is what its entry says: no reliability unless the entry
/// asks for it (`PeerSpec::reliability`), whatever the options say of the kinds a device
/// makes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_configured_peer_has_reliability_only_when_its_entry_asks() {
    let alice = Person::new("/alice").await;
    let ann = embedded(&alice, ANN, Setup::inviter()).await;
    let plain = embedded(&alice, &alice.device("phone"), Setup::dialer()).await;
    let asking = embedded(&alice, &alice.device("tablet"), Setup::dialer()).await;
    for (device, reliability) in [(&plain, false), (&asking, true)] {
        device.links.add_peer(PeerSpec {
            label: "ann".into(),
            key: Some(ann.key),
            device: Some(n(ANN)),
            endpoints: vec![ann.addr.unwrap().to_string()],
            reliability,
            ..PeerSpec::default()
        });
    }
    for device in [&plain, &asking] {
        until("the configured peer links", LONG, async || {
            linked(device, ann.key)
        })
        .await;
    }

    assert!(
        none_reliable(&plain, ann.key),
        "an entry that does not ask: {:#?}",
        plain.links.report()
    );
    assert!(
        all_reliable(&asking, ann.key),
        "an entry that asks: {:#?}",
        asking.links.report()
    );
}

/// A transfer over a link that loses Interests, asked as ndn-heap asks one: 1 MiB in pieces of
/// `CHUNK` (4096) bytes, 32 in flight, a piece expressed again once if it has not come after
/// `GAP`. The loss is a fact, not a chance: the first Interest of every tenth piece is lost and
/// every later arrival of that Interest (the link's own retransmission, or the consumer's) is
/// delivered, so each run loses the same 26 Interests whatever the order frames arrive in.
/// What is counted is what the consumer sees: Interests expressed again because the gap passed
/// with the piece not come (a Congestion Nack's repeat is not one).
#[cfg(feature = "fault-injection")]
mod lossy {
    use std::sync::atomic::{AtomicU64, Ordering};

    use bytes::Bytes;
    use futures::StreamExt;
    use ndn_app::{Consumer, EngineAppExt};
    use ndn_link::{FaultKind, FaultPlan, FaultVerdict, Faults};
    use ndn_packet::Name;
    use ndn_packet::encode::InterestBuilder;

    use super::*;
    use common::probe_prefix;

    const CHUNK: usize = 4096;
    const SIZE: usize = 1 << 20;
    const PIECES: usize = SIZE / CHUNK;
    const WINDOW: usize = 32;
    /// The first Interest of every `LOST_EVERY`th piece (0, 10, 20, ...) is lost.
    const LOST_EVERY: usize = 10;
    /// How long a piece waits before the consumer expresses it again. Far longer than any
    /// repair the link makes (a retransmission after its timeout), so that what is expressed
    /// again is what the link did not repair, and no run depends on how fast the host is.
    const GAP: Duration = Duration::from_secs(5);
    const BUDGET: Duration = Duration::from_secs(30);

    /// What a transfer cost its consumer.
    #[derive(Debug)]
    pub struct Cost {
        /// The Interests expressed again because the gap passed with the piece not come,
        /// summed over the pieces.
        pub reexpressed: u64,
        /// Asks that failed outright (a Nack, the lifetime) and were asked again.
        pub failed: u64,
        /// What the fault layer did to the links of the device it was installed on.
        pub faults: Option<ndn_link::FaultReport>,
    }

    /// `producer` answers every Interest under `prefix` with a piece of `CHUNK` bytes.
    pub fn serves(producer: &Embedded, prefix: Name) {
        let served = producer
            .engine
            .register_producer(prefix, producer.cancel.child_token());
        let piece = Bytes::from(vec![0u8; CHUNK]);
        tokio::spawn(async move {
            let _ = served
                .serve(move |interest, responder| {
                    let piece = piece.clone();
                    async move {
                        let _ = responder.respond((*interest.name).clone(), piece).await;
                    }
                })
                .await;
        });
    }

    /// The pieces `producer` serves: under the probe prefix of its namespace, a name
    /// the other device's forwarder routes over the link.
    pub fn bulk(producer: &Embedded) -> Name {
        probe_prefix(producer).append("bulk")
    }

    /// The piece an Interest under `prefix` asks for (its last component, in digits).
    fn piece_of(prefix: &Name, name: &Name) -> Option<usize> {
        if !name.has_prefix(prefix) {
            return None;
        }
        let last = name.components().last()?;
        std::str::from_utf8(last.value.as_ref()).ok()?.parse().ok()
    }

    /// Lose the first Interest of every tenth piece under `prefix` that arrives on `at`'s
    /// links, and nothing else: no draw, no seed. (Every later arrival of the same Interest
    /// passes, so the loss is repaired, by the link or by the consumer, exactly once.)
    pub fn lossy(at: &Embedded, prefix: &Name) {
        let prefix = prefix.clone();
        let lost = std::sync::Mutex::new(std::collections::HashSet::new());
        at.links
            .inject_faults(FaultPlan::new(Faults::parse("drop=0").unwrap()).verdict(
                move |frame| {
                    let piece = (frame.kind == FaultKind::Interest)
                        .then_some(frame.name.as_ref())
                        .flatten()
                        .and_then(|name| piece_of(&prefix, name));
                    match piece {
                        Some(piece)
                            if piece % LOST_EVERY == 0 && lost.lock().unwrap().insert(piece) =>
                        {
                            FaultVerdict::Drop
                        }
                        _ => FaultVerdict::Pass,
                    }
                },
            ));
    }

    /// Ask the 1 MiB under `prefix` (run `run` of it) from `consumer`.
    pub async fn transfer(
        consumer: &Embedded,
        lossy_at: &Embedded,
        prefix: &Name,
        run: u32,
    ) -> Cost {
        let node = consumer.engine.app_node(consumer.cancel.child_token());
        let (reexpressed, failed) = (AtomicU64::new(0), AtomicU64::new(0));
        let (reexpressed_ref, failed_ref) = (&reexpressed, &failed);
        let node = &node;
        let got: usize = futures::stream::iter(0..PIECES)
            .map(|piece| async move {
                let name = prefix
                    .clone()
                    .append(run.to_string())
                    .append(piece.to_string());
                let mut tries = 0;
                loop {
                    let congested = AtomicU64::new(0);
                    match Consumer::new(node.connection())
                        .fetch_reexpressing_noting(
                            || InterestBuilder::new(name.clone()),
                            BUDGET,
                            Duration::from_millis(250),
                            [GAP],
                            || {
                                congested.fetch_add(1, Ordering::Relaxed);
                            },
                        )
                        .await
                    {
                        Ok((data, expressed)) => {
                            let again = u64::from(expressed - 1)
                                .saturating_sub(congested.load(Ordering::Relaxed));
                            reexpressed_ref.fetch_add(again, Ordering::Relaxed);
                            break data.content().map_or(0, |c| c.len());
                        }
                        Err(_) if tries < 3 => {
                            tries += 1;
                            failed_ref.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(e) => panic!("the piece {name} did not come in four asks: {e:?}"),
                    }
                }
            })
            .buffer_unordered(WINDOW)
            .fold(0, |a, b| async move { a + b })
            .await;
        assert_eq!(got, SIZE);
        Cost {
            reexpressed: reexpressed.load(Ordering::Relaxed),
            failed: failed.load(Ordering::Relaxed),
            faults: lossy_at.links.report().fault_injection,
        }
    }

    /// Ann (laptop) and Phone, devices of one person: Phone dialled Ann by the key and
    /// address a code names, Ann serves the pieces and Phone asks, the frames that
    /// arrive at Ann (Phone's Interests) lossy. Phone's end of the link it dialled
    /// repairs them, or does not.
    async fn dialled_by_key(reliability: LinkReliability) -> Cost {
        let alice = Person::new("/alice").await;
        let ann = embedded(
            &alice,
            ANN,
            Setup {
                reliability,
                ..Setup::inviter()
            },
        )
        .await;
        let phone = embedded(
            &alice,
            &alice.device("phone"),
            Setup {
                reliability,
                ..Setup::dialer()
            },
        )
        .await;
        dials(&phone, &ann)
            .await
            .unwrap_or_else(|e| panic!("{e:?}"));
        common::answers_probes(&ann);
        serves(&ann, bulk(&ann));
        until("a probe crosses the link", LONG, async || {
            common::probes(&phone, &ann, "warm").await
        })
        .await;

        lossy(&ann, &bulk(&ann));
        transfer(&phone, &ann, &bulk(&ann), 1).await
    }

    /// Ann invited Bob (another person) into her folder. Bob serves the pieces and Ann
    /// asks over the grant link, the frames that arrive at Bob (Ann's Interests) lossy.
    /// Ann's end of the grant link repairs them, or does not.
    async fn over_a_grant(reliability: LinkReliability) -> Cost {
        let (alice, bobs) = (Person::new("/alice").await, Person::new("/bob").await);
        let ann = embedded(
            &alice,
            ANN,
            Setup {
                reliability,
                ..Setup::inviter()
            },
        )
        .await;
        let bob = embedded(
            &bobs,
            &bobs.device("phone"),
            Setup {
                reliability,
                ..Setup::dialer()
            },
        )
        .await;
        invited(&ann, &bob, Role::Writer).await;
        common::answers_probes(&bob);
        serves(&bob, bulk(&bob));
        until("a probe crosses the grant link", LONG, async || {
            common::probes(&ann, &bob, "warm").await
        })
        .await;

        lossy(&bob, &bulk(&bob));
        transfer(&ann, &bob, &bulk(&bob), 1).await
    }

    /// With a kind's reliability on, a 1 MiB transfer over a link of that kind that loses 26
    /// Interests needs no re-expression and no second ask: the link repairs every one before
    /// the consumer's gap. With it off, the same transfer over the same link needs exactly one
    /// re-expression for each Interest lost.
    fn repaired(kind: &str, off: &Cost, on: &Cost) {
        println!("{kind}: off {off:?}\n{kind}: on  {on:?}");
        let lost = PIECES.div_ceil(LOST_EVERY) as u64;
        for (what, cost) in [("off", off), ("on", on)] {
            assert_eq!(
                cost.faults.as_ref().map(|f| f.dropped),
                Some(lost),
                "the fault layer did not lose the {lost} Interests the case plans, {kind}: {what} {cost:?}"
            );
        }
        assert_eq!(
            off.reexpressed, lost,
            "without reliability each lost Interest costs one re-expression, so the case shows nothing otherwise: {kind}: off {off:?}"
        );
        assert_eq!(
            (on.reexpressed, on.failed),
            (0, 0),
            "reliability on did not repair the loss of the {kind} before the consumer asked again: off {off:?}, on {on:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn reliability_repairs_the_loss_of_a_transfer_over_a_link_dialled_by_key() {
        let off = dialled_by_key(LinkReliability::none()).await;
        let on = dialled_by_key(LinkReliability::default()).await;
        repaired("link dialled by key", &off, &on);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn reliability_repairs_the_loss_of_a_transfer_over_a_grant_link() {
        let off = over_a_grant(LinkReliability::none()).await;
        let on = over_a_grant(LinkReliability::default()).await;
        repaired("grant link", &off, &on);
    }
}
