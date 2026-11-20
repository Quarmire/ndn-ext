//! The ask exchange over a grant link (ndn-rs `ndn-link.md` §8.7 rule 19,
//! SHAPES-R11 §4): `<device>/32=seal` and `<device>/32=ask-answer/…` of the
//! inviter's devices and of the devices of the namespaces the folder's record
//! lists as writers cross a grant link in both directions, judged at every
//! packet against the record in force; nothing else under a device does.
//!
//! Real data-layer devices on real forwarders over real QUIC: Ann (the
//! inviter, who serves asks of her folder's members) is asked by Bob, who
//! joined by her code, through `Device::ask_answer` over his grant link, as a
//! writer and as a reader. Then, with devices on Ann's forwarder that answer
//! whatever they are asked, the names that cross and the names that do not:
//! the third party's devices only while the record lists her, the lookalikes
//! of a device never.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;

use common::{
    ANN, Embedded, LONG, Person, Setup, embedded, invited, invited_in, linked, n, puts, reshare,
    text, until,
};
use ndn_app::EngineAppExt;
use ndn_data::{
    AnswerAsk, AnswerConfig, AskServing, DataError, DataLayer, Definition, EvalError, Evaluator,
    Evaluators, Got, NextStep, Payload, PlanError, ReadView, Reads, Role,
};
use ndn_face_quic::KeyFingerprint;
use ndn_packet::{Name, NameComponent};

const ECHO: &str = "/conformance/eval/echo/v=1";

/// An evaluator both sides know: the answer to a definition is its `text`
/// field, read by nothing else.
struct Echo(Name);

#[async_trait::async_trait]
impl Evaluator for Echo {
    fn evaluator(&self) -> &Name {
        &self.0
    }

    async fn plan(&self, _: &Definition, _: &mut dyn Reads) -> Result<(), PlanError> {
        Ok(())
    }

    fn evaluate(&self, definition: &Definition, _: &dyn ReadView) -> Result<Bytes, EvalError> {
        let Got::Version(v) = &definition.got else {
            return Err(EvalError::Refused("the definition is a version".into()));
        };
        let Payload::Entry(content) = &v.payload else {
            return Err(EvalError::Refused("the definition is one entry".into()));
        };
        let text = content
            .get("text")
            .ok_or_else(|| EvalError::Refused("the definition has no field text".into()))?;
        Ok(Bytes::copy_from_slice(&text[..]))
    }
}

fn evaluators() -> Evaluators {
    Evaluators::none().with(Arc::new(Echo(n(ECHO))))
}

/// Ann answers the asks of her own devices and of the listed members of the
/// folders she shares.
fn ann_setup() -> Setup {
    Setup {
        answers: AnswerConfig {
            serve_asks: AskServing::OwnAndMembers,
            ..AnswerConfig::default()
        },
        evaluators: evaluators(),
        ..Setup::inviter()
    }
}

/// The joiner knows the evaluator too, so it needs nothing from the signer
/// but the answer.
fn joiner_setup() -> Setup {
    Setup {
        evaluators: evaluators(),
        ..Setup::dialer()
    }
}

/// A definition Ann puts in the folder and Bob holds, and the question that
/// asks for its answer.
async fn question(ann: &Embedded, bob: &Embedded, folder: &Name) -> Name {
    let definition = folder.clone().append("definition");
    puts(&ann.device, &definition, text("lamp is red"), LONG).await;
    until("bob holds the definition", LONG, async || {
        bob.device.get(&definition).await.is_ok()
    })
    .await;
    let (read, _) = ann.device.current_read(&definition).await.unwrap();
    AnswerAsk::pure(read, n(ECHO)).name(None).unwrap()
}

/// `ask_answer` of Ann's device as a host does what `RetryLater` says, until
/// `patience` has passed.
async fn asks_ann(
    bob: &Embedded,
    signer: &Name,
    question: &Name,
    patience: Duration,
) -> Result<Got, DataError> {
    let started = Instant::now();
    loop {
        match bob.device.ask_answer(signer, question).await {
            Err(e) if e.next() == NextStep::RetryLater && started.elapsed() < patience => {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            other => return other,
        }
    }
}

fn answered(got: Result<Got, DataError>, what: &str) {
    match got {
        Ok(Got::Answer(a)) => assert_eq!(
            a.result,
            Bytes::from_static(b"lamp is red"),
            "{what}: the answer is the definition's text"
        ),
        other => panic!("{what}: not answered: {other:?}"),
    }
}

/// Bob joins Ann's notebook as `role`, and both are linked.
async fn joined(ann: &Embedded, bob: &Embedded, role: Role) {
    invited(ann, bob, role).await;
    until("ann is linked to bob", LONG, async || linked(ann, bob.key)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_writer_asks_the_inviters_device_over_his_grant_link_and_is_answered() {
    let (alice, bobs) = (Person::new("/alice").await, Person::new("/bob").await);
    let ann = embedded(&alice, ANN, ann_setup()).await;
    let bob = embedded(&bobs, "/bob/member/phone", joiner_setup()).await;
    joined(&ann, &bob, Role::Writer).await;
    let q = question(&ann, &bob, &n(common::FOLDER)).await;
    answered(
        asks_ann(&bob, &n(ANN), &q, Duration::from_secs(20)).await,
        "a writer's ask",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reader_the_record_lists_asks_the_inviters_device_and_is_answered() {
    let (alice, bobs) = (Person::new("/alice").await, Person::new("/bob").await);
    let ann = embedded(&alice, ANN, ann_setup()).await;
    let bob = embedded(&bobs, "/bob/member/phone", joiner_setup()).await;
    joined(&ann, &bob, Role::Reader).await;
    let q = question(&ann, &bob, &n(common::FOLDER)).await;
    answered(
        asks_ann(&bob, &n(ANN), &q, Duration::from_secs(20)).await,
        "a listed reader's ask",
    );
}

/// The same between two people named by their keys, as ndf's peers are
/// (`/user/161=<digest>/member/<label>`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn people_named_by_their_keys_ask_each_other_over_the_grant_link() {
    let anns = Person::self_certifying([0xa2; 32]).await;
    let bobs = Person::self_certifying([0xb2; 32]).await;
    let ann_device = n(&anns.device("laptop"));
    let ann = embedded(&anns, &anns.device("laptop"), ann_setup()).await;
    let bob = embedded(&bobs, &bobs.device("phone"), joiner_setup()).await;
    let folder = n(&format!("{}/32=data/notebook", anns.ns));
    reshare(&ann, &folder, std::slice::from_ref(&anns.ns)).await;
    puts(
        &ann.device,
        &folder.clone().append("cover"),
        text("cover"),
        LONG,
    )
    .await;
    invited_in(&ann, &bob, &folder, Role::Writer).await;
    until("ann is linked to bob", LONG, async || linked(&ann, bob.key)).await;
    let q = question(&ann, &bob, &folder).await;
    answered(
        asks_ann(&bob, &ann_device, &q, Duration::from_secs(20)).await,
        "a key-named writer's ask",
    );
}

// ---- which names cross ------------------------------------------------------------------------

/// A device at `device` on Ann's forwarder that answers whatever it is asked
/// under its name, and Bob's route to it over his link to Ann (made by the
/// test, as the joiner's routes are the cases of `tests/joiner.rs`: what is
/// judged here is the link's filter, so every name has a route to cross).
fn ghost(ann: &Embedded, bob: &Embedded, device: &str) {
    let producer = ann
        .engine
        .register_producer(n(device), ann.cancel.child_token());
    tokio::spawn(async move {
        let _ = producer
            .serve(|interest, responder| async move {
                let _ = responder
                    .respond((*interest.name).clone(), Bytes::from_static(b"here"))
                    .await;
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
    bob.engine.fib().add_nexthop(&n(device), face, 0);
}

/// The seal key name of a device, as its owner's data layer names it, and the
/// prefix a fetch of it asks for.
fn seal(device: &str) -> Name {
    n(device).append_component(NameComponent::keyword(Bytes::from_static(b"seal")))
}

/// Whether Bob is answered for `name` over his link to Ann (by prefix).
async fn crosses(bob: &Embedded, ann_key: KeyFingerprint, name: &Name) -> bool {
    match common::ask(bob, ann_key, name, true).await {
        Ok(()) => true,
        Err(why) => {
            eprintln!("{name} did not cross: {why}");
            false
        }
    }
}

/// A folder of Ann's, shared with `writers` (and the same people as readers).
async fn listing(ann: &Embedded, writers: &[Name]) {
    reshare(ann, &n(common::FOLDER), writers).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_devices_of_a_third_party_cross_only_while_the_record_lists_her() {
    let (alice, bobs) = (Person::new("/alice").await, Person::new("/bob").await);
    let ann = embedded(&alice, ANN, ann_setup()).await;
    let bob = embedded(&bobs, "/bob/member/phone", joiner_setup()).await;
    joined(&ann, &bob, Role::Writer).await;
    ghost(&ann, &bob, "/carol/member/phone");
    let carols = seal("/carol/member/phone");
    assert!(
        !crosses(&bob, ann.key, &carols).await,
        "a device of a namespace the record does not list crossed"
    );
    let with_carol = [n("/alice"), n("/bob"), n("/carol")];
    listing(&ann, &with_carol).await;
    until("carol's device crosses once listed", LONG, async || {
        crosses(&bob, ann.key, &carols).await
    })
    .await;
    listing(&ann, &[n("/alice"), n("/bob")]).await;
    until("carol's device is blocked once dropped", LONG, async || {
        !crosses(&bob, ann.key, &carols).await
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn what_is_not_a_device_of_a_listed_namespace_stays_blocked() {
    let (alice, bobs) = (Person::new("/alice").await, Person::new("/bob").await);
    let ann = embedded(&alice, ANN, ann_setup()).await;
    let bob = embedded(&bobs, "/bob/member/phone", joiner_setup()).await;
    joined(&ann, &bob, Role::Writer).await;
    // The devices answer under their names, as a device that serves its seal
    // key or its asks does.
    for device in [
        "/alice/member/lamp",
        "/alice/member/lamp/nested",
        "/alice/stranger/lamp",
        "/dave/member/lamp",
        "/home/member/lamp",
        "/home/carol/member/lamp",
    ] {
        ghost(&ann, &bob, device);
    }
    // A writer that is itself a device of /home/carol.
    listing(
        &ann,
        &[n("/alice"), n("/bob"), n("/home/carol/member/other")],
    )
    .await;
    // The inviter's own device crosses, as the control: the link carries the
    // exchange where its shape is a device's, so the block below is the
    // filter's.
    until(
        "a device of the folder's namespace crosses",
        LONG,
        async || crosses(&bob, ann.key, &seal("/alice/member/lamp")).await,
    )
    .await;
    for blocked in [
        // Two components between the namespace and the keyword.
        seal("/alice/member/lamp/nested"),
        // A role the layout has none of.
        seal("/alice/stranger/lamp"),
        // A namespace the record does not list.
        seal("/dave/member/lamp"),
        // The broader namespace a listed writer's name merely starts with.
        seal("/home/member/lamp"),
        // A device of the writer's namespace's parent.
        seal("/home/carol/member/lamp"),
    ] {
        assert!(
            !crosses(&bob, ann.key, &blocked).await,
            "{blocked} crossed the grant link"
        );
    }
}

/// Every role is a writer's or a person's device of a namespace: the shape
/// is the layout's, not a policy: `<W>/<role>/<device>` for each role the
/// layout names.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_role_of_the_layout_crosses_and_a_look_alike_does_not() {
    let (alice, bobs) = (Person::new("/alice").await, Person::new("/bob").await);
    let ann = embedded(&alice, ANN, ann_setup()).await;
    let bob = embedded(&bobs, "/bob/member/phone", joiner_setup()).await;
    joined(&ann, &bob, Role::Writer).await;
    for role in ["admin", "member", "node", "guest", "Member", "owner"] {
        ghost(&ann, &bob, &format!("/alice/{role}/lamp"));
    }
    for role in ["admin", "member", "node", "guest"] {
        assert!(
            crosses(&bob, ann.key, &seal(&format!("/alice/{role}/lamp"))).await,
            "a {role} device's seal key did not cross"
        );
    }
    for role in ["Member", "owner"] {
        assert!(
            !crosses(&bob, ann.key, &seal(&format!("/alice/{role}/lamp"))).await,
            "a device under role {role}, which the layout does not name, crossed"
        );
    }
}

/// Two writers who never met: the seal key packet of Carol's device crosses
/// Ann's link to Bob, as Carol's namespace is the record's, with no route of
/// the test's (Bob's route for Carol's namespace is the joiner's, rule 18;
/// Ann's toward Carol's device is the link's, rule 10). Whether Bob's data
/// layer then holds Carol's namespace to verify that packet is its own
/// business (a namespace adopted for a folder judges that folder's packets
/// alone), not the link's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_seal_key_of_another_writers_real_device_crosses_the_inviters_link() {
    let alice = Person::new("/alice").await;
    let bobs = Person::self_certifying([0xb2; 32]).await;
    let carols = Person::self_certifying([0xc2; 32]).await;
    let by_name = Setup {
        scoped_by_name: true,
        ..joiner_setup()
    };
    let ann = embedded(&alice, ANN, ann_setup()).await;
    let bob = embedded(&bobs, &bobs.device("phone"), by_name.clone()).await;
    let carol = embedded(&carols, &carols.device("phone"), by_name).await;
    let folder = n(common::FOLDER);
    invited(&ann, &bob, Role::Writer).await;
    invited_in(&ann, &carol, &folder, Role::Writer).await;
    until("ann is linked to both", LONG, async || {
        linked(&ann, bob.key) && linked(&ann, carol.key)
    })
    .await;
    until("bob is routed carol's namespace", LONG, async || {
        !bob.sink.joined_now().is_empty()
    })
    .await;
    let carols_seal = seal(&carols.device("phone"));
    until("carol's seal key crosses", LONG, async || {
        crosses(&bob, ann.key, &carols_seal).await
    })
    .await;
}
