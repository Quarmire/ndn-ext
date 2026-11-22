//! What each kind of link takes from its peer (ndn-rs `ndn-link.md` §8.3 and
//! §8.7): a member's ordinary transfer never meets a quota, a stranger's flood
//! and an introduction link's are held at the link and answered with a Nack
//! (Congestion: the Interest was dropped for rate, ask again soon), and a link
//! of the device's own namespace is not limited.
//!
//! Real QUIC, real forwarders: the peer asks pinned to its link's face, so what
//! is judged is the link and never a route.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use common::{
    ANN, Embedded, LONG, Person, Setup, dials, embedded, invited, linked, n, offered, until,
};
use ndn_app::EngineAppExt;
use ndn_data::intro::{intro_prefix, introduction_prefixes};
use ndn_data::{Answer, Content, DataLayer, Got, Payload, Role};
use ndn_face_quic::KeyFingerprint;
use ndn_packet::{Name, NameComponent};
use tokio::sync::Semaphore;

/// `ndn_data::wire::CHUNK`: the size of a piece the data layer asks.
const PIECE: usize = 4096;
/// A transfer's pieces: 1 MiB.
const PIECES: usize = 256;
/// The data layer's window (`Config::new().window`): pieces in flight.
const WINDOW: usize = 32;

/// How one Interest ended.
#[derive(Debug, PartialEq, Eq)]
enum Ended {
    Data,
    Congestion,
    /// Any other Nack, or a timeout: the text of the error.
    Other(String),
}

/// What a flood came to.
struct Flood {
    ended: Vec<Ended>,
    /// How long after the first Interest the first Congestion Nack came back.
    first_nack: Option<Duration>,
    /// When the last Data or Nack came back: a bucket refills while a loaded
    /// receiver judges the frames, so what passed is bounded by the burst and
    /// this time's refill.
    replied: Duration,
    took: Duration,
}

impl Flood {
    fn count(&self, what: &Ended) -> usize {
        self.ended.iter().filter(|e| *e == what).count()
    }

    fn others(&self) -> Vec<&String> {
        self.ended
            .iter()
            .filter_map(|e| match e {
                Ended::Other(why) => Some(why),
                _ => None,
            })
            .collect()
    }
}

/// A device of Ann's namespace the grant link carries the names of (its seal
/// keys, `<device>/32=seal/<key>`), a name the sync groups'
/// multicast strategy does not hold Nacks back for.
const SIGNER: &str = "/alice/member/lamp";

/// `on` answers every Interest under [`SIGNER`] with a piece of [`PIECE`]
/// bytes.
fn serves_pieces(on: &Embedded) {
    let producer = on
        .engine
        .register_producer(n(SIGNER), on.cancel.child_token());
    tokio::spawn(async move {
        let _ = producer
            .serve(|interest, responder| async move {
                let _ = responder
                    .respond((*interest.name).clone(), Bytes::from(vec![7u8; PIECE]))
                    .await;
            })
            .await;
    });
}

/// The face of `from`'s link to the device with `key`.
fn face_to(from: &Embedded, key: KeyFingerprint) -> ndn_app::FaceId {
    from.links
        .report()
        .links
        .iter()
        .filter(|l| l.key == Some(key))
        .flat_map(|l| l.paths.iter().map(|p| p.face))
        .next()
        .expect("a link to that key")
}

/// `names`, each asked once (never asked again: a single send, a lifetime of
/// 3 s), `window` in flight, over `from`'s link to `key`.
async fn flood(from: &Embedded, key: KeyFingerprint, names: Vec<Name>, window: usize) -> Flood {
    let face = face_to(from, key);
    // The route the asker's forwarder has to the signer: the Interests are
    // pinned to the link's face besides.
    from.engine.fib().add_nexthop(&n(SIGNER), face, 0);
    let gate = Arc::new(Semaphore::new(window));
    let started = Instant::now();
    let mut asked = tokio::task::JoinSet::new();
    for (i, name) in names.into_iter().enumerate() {
        let permit = Arc::clone(&gate).acquire_owned().await.unwrap();
        let mut consumer = from.engine.app_consumer(from.cancel.child_token());
        asked.spawn(async move {
            let interest =
                ndn_packet::encode::InterestBuilder::new(name).lifetime(Duration::from_secs(3));
            let got = consumer.fetch_with_on(face, interest).await;
            drop(permit);
            let ended = match got {
                Ok(_) => Ended::Data,
                Err(e) if format!("{e:?}").contains("Congestion") => Ended::Congestion,
                Err(e) => Ended::Other(format!("{e:?}")),
            };
            (i, ended, started.elapsed())
        });
    }
    let mut ended: Vec<Option<Ended>> = Vec::new();
    let mut first_nack = None;
    let mut replied = Duration::ZERO;
    while let Some(done) = asked.join_next().await {
        let (i, what, at) = done.unwrap();
        if matches!(what, Ended::Data | Ended::Congestion) {
            replied = replied.max(at);
        }
        if what == Ended::Congestion && first_nack.is_none_or(|first| at < first) {
            first_nack = Some(at);
        }
        if ended.len() <= i {
            ended.resize_with(i + 1, || None);
        }
        ended[i] = Some(what);
    }
    Flood {
        ended: ended.into_iter().map(Option::unwrap).collect(),
        first_nack,
        replied,
        took: started.elapsed(),
    }
}

/// `count` names of seal keys of [`SIGNER`], each its own (`tag` and the number
/// are the key's first bytes).
fn pieces_of(count: usize, tag: u8) -> Vec<Name> {
    (0..count)
        .map(|i| {
            let mut key = [0u8; 32];
            key[0] = tag;
            key[1..5].copy_from_slice(&u32::try_from(i).unwrap().to_le_bytes());
            n(SIGNER)
                .append_component(NameComponent::keyword(Bytes::from_static(b"seal")))
                .append_component(NameComponent::generic(Bytes::copy_from_slice(&key)))
        })
        .collect()
}

async fn grant_linked() -> (Embedded, Embedded) {
    let (alice, bobs) = (Person::new("/alice").await, Person::new("/bob").await);
    let ann = embedded(&alice, ANN, Setup::inviter()).await;
    let bob = embedded(&bobs, "/bob/member/phone", Setup::dialer()).await;
    invited(&ann, &bob, Role::Writer).await;
    until("ann is linked to bob", LONG, async || linked(&ann, bob.key)).await;
    (ann, bob)
}

/// One 1 MiB transfer as the data layer asks it (256 piece Interests of 4096
/// bytes, 32 in flight, each sent once) over a grant link: every piece comes
/// back, none is dropped or Nacked at the link.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_members_1_mib_transfer_over_a_grant_link_meets_no_quota() {
    let (ann, bob) = grant_linked().await;
    serves_pieces(&ann);
    let got = flood(&bob, ann.key, pieces_of(PIECES, 1), WINDOW).await;
    assert_eq!(
        (
            got.count(&Ended::Data),
            got.count(&Ended::Congestion),
            got.others()
        ),
        (PIECES, 0, Vec::<&String>::new()),
        "a member's 1 MiB transfer over a grant link lost pieces ({} answered of {PIECES}, in {:?})",
        got.count(&Ended::Data),
        got.took
    );
    let (at_ann, at_bob) = (ann.links.report(), bob.links.report());
    assert_eq!(
        (
            at_ann.frames_over_rate,
            at_ann.congestion_nacks,
            at_bob.frames_over_rate
        ),
        (0, 0, 0),
        "a member's 1 MiB transfer met a rate at one end of its grant link"
    );
}

/// `count` distinct asks of the data layer's own devices a member sends the owner Ann
/// (`<ANN>/32=grant/<GrantAsk>` and `<ANN>/32=hold/<HoldAsk>`, the names the link carries
/// for a folder's collections), each its own: a seal key or a nonce that is nobody's.
fn data_asks(count: usize, tag: u8) -> Vec<Name> {
    use ndn_data::Seq;
    use ndn_data::wire::{GrantAsk, HoldAsk, grant_name, hold_ask_name, log_name};
    let collection = n(common::FOLDER).append("big");
    (0..count)
        .map(|i| {
            let mut random = [tag; 32];
            random[1..5].copy_from_slice(&u32::try_from(i).unwrap().to_le_bytes());
            if i % 2 == 0 {
                let seal = n("/bob/member/phone")
                    .append_component(NameComponent::keyword(Bytes::from_static(b"seal")))
                    .append_component(NameComponent::generic(Bytes::copy_from_slice(&random)));
                grant_name(
                    &n(ANN),
                    &GrantAsk {
                        seal_key: seal,
                        collection: collection.clone(),
                        epoch: ndn_data::Epoch {
                            creator: n(ANN),
                            seq: Seq(1),
                        },
                    },
                )
            } else {
                let mut nonce = [0u8; 16];
                nonce.copy_from_slice(&random[..16]);
                hold_ask_name(
                    &n(ANN),
                    &HoldAsk {
                        record: log_name(&n(ANN), Some(&collection), 1 + i as u64),
                        nonce,
                        asker: Bytes::from_static(&[0; 8]),
                    },
                )
            }
        })
        .collect()
}

/// R12 H1: the owner's grant asks and hold asks (the data layer's `32=grant` and `32=hold`
/// names, what a member's device asks the owner's) are rated apart on a grant link, in a
/// bucket of their own beside the link's frames: a member's flood of
/// distinct ones reaches the owner's device at most the burst and the refill of the time
/// it took (before this, 32,768 a second: each is a task, a fetch back to the member, and
/// a signature at the owner).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_flood_of_distinct_grant_asks_over_a_grant_link_is_bounded() {
    let (ann, bob) = grant_linked().await;
    let total = 1000;
    let got = flood(&bob, ann.key, data_asks(total, 3), total).await;
    let dropped = ann.links.report().frames_over_rate;
    let reached = total as u64 - dropped.min(total as u64);
    let allowed = u64::from(ndn_link::policy::DATA_ASKS.burst)
        + u64::from(ndn_link::policy::DATA_ASKS.per_sec) * got.took.as_secs()
        + 10;
    assert!(
        reached <= allowed,
        "{reached} of {total} distinct grant and hold asks reached the owner's device in {:?} \
         over a grant link: {dropped} were dropped for rate, the bucket allows {allowed}",
        got.took
    );
}

/// A stranger (served by `open`, under the quotas) that floods is limited at
/// the link, and the Interests it loses are answered with a Congestion Nack at
/// once, not left to time out.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_strangers_flood_is_limited_and_answered_with_congestion_nacks() {
    let (alice, bobs) = (Person::new("/alice").await, Person::new("/bob").await);
    let ann = embedded(&alice, ANN, Setup::open()).await;
    let bob = embedded(&bobs, "/bob/member/phone", Setup::dialer()).await;
    invited(&ann, &bob, Role::Writer).await;
    until("ann is linked to bob", LONG, async || linked(&ann, bob.key)).await;
    serves_pieces(&ann);
    let total = 600;
    let got = flood(&bob, ann.key, pieces_of(total, 2), total).await;
    let data = got.count(&Ended::Data);
    let nacked = got.count(&Ended::Congestion);
    // The default quotas: a burst of 200, then 100 a second while the flood is
    // being sent (and a few Interests of leeway).
    let allowed = 200 + (100.0_f64 * got.replied.as_secs_f64()).ceil() as usize + 10;
    assert!(
        data <= allowed,
        "the flood got {data} of {total} Interests through in {:?}: a stranger's quota allows {allowed}",
        got.took
    );
    assert!(
        nacked >= 100,
        "{nacked} Congestion Nacks for {} Interests dropped for rate (others: {:?}): the asker is \
         left to its timer",
        total - data,
        got.others().into_iter().take(3).collect::<Vec<_>>()
    );
    assert!(
        got.first_nack.is_some_and(|at| at < Duration::from_secs(1)),
        "the first Congestion Nack came after {:?}, not at once",
        got.first_nack
    );
    // A Nack is bounded too: past it the link drops without one.
    assert!(
        nacked < total - 200,
        "every dropped Interest was Nacked ({nacked}): a flood is answered without bound"
    );
    // What the link did is told: every Nack sent was for a dropped frame.
    let report = ann.links.report();
    assert!(
        report.congestion_nacks >= nacked as u64
            && report.frames_over_rate >= report.congestion_nacks,
        "the report counts {} frames over a rate and {} Nacks; the asker saw {nacked}",
        report.frames_over_rate,
        report.congestion_nacks
    );
}

/// A link of the device's own namespace is never limited.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_own_namespace_link_is_never_limited() {
    let alice = Person::new("/alice").await;
    let ann = embedded(&alice, ANN, Setup::inviter()).await;
    let phone = embedded(&alice, "/alice/member/phone", Setup::dialer()).await;
    dials(&phone, &ann).await.expect("the phone links to ann");
    until("ann is linked to the phone", LONG, async || {
        linked(&ann, phone.key)
    })
    .await;
    serves_pieces(&ann);
    let total = 1000;
    // A window as a host's transfer has.
    let got = flood(&phone, ann.key, pieces_of(total, 3), 64).await;
    assert_eq!(
        (
            got.count(&Ended::Data),
            got.count(&Ended::Congestion),
            got.others()
        ),
        (total, 0, Vec::<&String>::new()),
        "a link of the device's own namespace dropped Interests"
    );
    let report = ann.links.report();
    assert_eq!(
        (report.frames_over_rate, report.congestion_nacks),
        (0, 0),
        "an own-namespace link has no rate to meet"
    );
}

/// An introduction link (a stranger's, while an offer is open) keeps its tight
/// quota: a burst of 32, then 4 a second; what it loses is Nacked (Congestion).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_introduction_link_keeps_its_tight_quota() {
    let (alice, bobs) = (Person::new("/alice").await, Person::new("/bob").await);
    let ann = embedded(&alice, ANN, Setup::inviter()).await;
    let bob = embedded(&bobs, "/bob/member/phone", Setup::dialer()).await;
    // An open offer: a stranger is taken on an introduction link.
    let _code = offered(&ann, Role::Writer).await;
    let device = n(ANN);
    bob.links
        .dial_by_key(
            ann.key,
            device.clone(),
            vec![ann.addr.expect("ann listens")],
            Duration::from_secs(10),
            introduction_prefixes(&device).into(),
        )
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let total = 200;
    let asked: Vec<Name> = (0..total)
        .map(|i| intro_prefix(&device).append(i.to_string()))
        .collect();
    let got = flood(&bob, ann.key, asked, total).await;
    let nacked = got.count(&Ended::Congestion);
    let allowed = 32 + (4.0_f64 * got.replied.as_secs_f64()).ceil() as usize + 2;
    assert!(
        total - nacked <= allowed,
        "{} of {total} Interests were no Nack's: an introduction link lets {allowed} cross in {:?} \
         and Nacks the rest",
        total - nacked,
        got.took
    );
    assert!(
        nacked >= 100,
        "{nacked} Congestion Nacks of {total} Interests over an introduction link's burst of 32 \
         (others: {:?})",
        got.others().into_iter().take(3).collect::<Vec<_>>()
    );
    let report = ann.links.report();
    assert!(
        report.frames_over_rate >= 100 && report.congestion_nacks >= nacked as u64,
        "the report counts {} frames over a rate and {} Nacks for {nacked} Nacks seen",
        report.frames_over_rate,
        report.congestion_nacks
    );
}

/// The same with real data-layer devices: a 1 MiB note that Ann (the owner)
/// writes is read by Bob, a writer she invited, over his grant link, and no
/// frame was dropped for a rate at either end (the data layer asks each
/// piece again after 250 ms, doubling, when one is: 3 s for 1 MiB).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_members_1_mib_note_crosses_a_grant_link_with_nothing_dropped() {
    let (ann, bob) = grant_linked().await;
    let big = n(common::FOLDER).append("big");
    let blob = Content::new().with("blob", Bytes::from(vec![9u8; 1 << 20]));
    common::puts(&ann.device, &big, blob, LONG).await;
    until("bob reads the 1 MiB note", LONG, async || {
        matches!(
            bob.device.get(&big).await,
            Ok(Answer { got: Got::Version(v), .. })
                if matches!(&v.payload, Payload::Entry(c)
                    if c.get("blob").is_some_and(|b| b.len() == 1 << 20))
        )
    })
    .await;
    let (at_ann, at_bob) = (ann.links.report(), bob.links.report());
    assert_eq!(
        (
            at_ann.frames_over_rate,
            at_ann.congestion_nacks,
            at_bob.frames_over_rate
        ),
        (0, 0, 0),
        "a 1 MiB note met a rate at one end of a grant link"
    );
}
