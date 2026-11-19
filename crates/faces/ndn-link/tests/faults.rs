#![cfg(feature = "fault-injection")]
//! The test-only fault layer on real QUIC links between two embedded forwarders
//! (ndn-rs `ndn-link.md` §17B): the conformance's `FAULTY` profile on a real link, the
//! same seed and the same faults, a forged Data still refused by the consumer, and a
//! verdict per packet (the profile on it, drop it or let it pass).
//!
//! Two devices of one namespace, each with a forwarder of its own and its links on a
//! loopback socket; `a` produces signed notes under its device name, `b` fetches them
//! across the link and validates them, as a data-layer consumer does. A device's layer
//! faults what *arrives* on its links: the Interests a note's fetch sends are faulted
//! at `a`, the Data that answers them at `b`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use ndn_app::{Consumer, EngineAppExt, Node};
use ndn_engine::{EngineBuilder, EngineConfig, ForwarderEngine, ShutdownHandle};
use ndn_face_quic::{
    Direction, KeyFingerprint, LinkEndpoint, LinkKey, LinkKeySource, LinkTransportConfig,
};
use ndn_link::{
    ConfiguredEndpoints, EngineFaces, FAULTY, FaultFrame, FaultKind, FaultPlan, FaultReport,
    FaultVerdict, Faults, HostCandidates, LinkSetup, LinkTrust, Links, PathKind, PeerSpec,
};
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_packet::{Data, Name};
use ndn_security::{
    Certificate, Ed25519Signer, Keyring, SecurityManager, SecurityProfile, SignedTrustContext,
    Signer, TrustSchema, Unverified, Validator, VerifyError,
};
use parking_lot::Mutex;
use tokio_util::sync::CancellationToken;

const NS: &str = "/home";

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

/// The namespace: its root key and signed trust context.
struct Home {
    root: SecurityManager,
    root_key: Name,
    context: Arc<SignedTrustContext>,
}

impl Home {
    fn new() -> Self {
        let root = SecurityManager::new();
        let root_key = n(&format!("{NS}/KEY/root"));
        root.generate_ed25519(root_key.clone()).unwrap();
        let signer = root.get_signer_sync(&root_key).unwrap();
        let anchor = root
            .issue_self_signed(&root_key, signer.public_key().unwrap(), u64::MAX)
            .unwrap();
        let context = SignedTrustContext::hierarchical(n(NS)).with_version(1);
        context.add_anchor(anchor);
        Self {
            root,
            root_key,
            context: Arc::new(context),
        }
    }

    async fn certify(&self, key_name: &Name, public_key: Bytes) -> Certificate {
        self.root
            .certify_as(
                key_name,
                public_key,
                &self.root_key,
                3_600_000,
                ndn_security::cert_name::NDNCERT_ISSUER,
                None,
            )
            .await
            .unwrap()
    }

    /// What a consumer of a note of `device` validates by: this namespace's context, and
    /// the device's certificate.
    fn validator(&self, cert: &Certificate) -> Validator {
        let validator = Validator::new(TrustSchema::hierarchical());
        validator.adopt_context(Arc::clone(&self.context)).unwrap();
        validator.cert_cache().insert(cert.clone());
        validator
    }
}

struct Trust {
    keyring: Arc<Keyring>,
    chain: Vec<Bytes>,
}

impl LinkTrust for Trust {
    fn keyring(&self) -> &Arc<Keyring> {
        &self.keyring
    }
    fn own_chain(&self) -> Vec<Bytes> {
        self.chain.clone()
    }
    fn known_certificate(&self, _: &Name) -> Option<Certificate> {
        None
    }
    fn known_certificate_of_key(&self, _: &KeyFingerprint) -> Option<Certificate> {
        None
    }
}

/// A device on a forwarder of its own, its links on a loopback socket.
struct Member {
    links: Arc<Links>,
    key: KeyFingerprint,
    addr: SocketAddr,
    signer: Arc<Ed25519Signer>,
    cert: Certificate,
    node: Node,
    cancel: CancellationToken,
    _engine: ForwarderEngine,
    _shutdown: ShutdownHandle,
}

impl Drop for Member {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// `/home/member/<name>`, with a fixed key (so its link key, and the ends of its links'
/// draws, are the same in every run), dialling `peers`.
async fn member(home: &Home, name: &str, seed: u8, peers: Vec<PeerSpec>) -> Member {
    let key_name = n(&format!("{NS}/member/{name}/KEY/k{seed}"));
    let signer = Arc::new(Ed25519Signer::from_seed(&[seed; 32], key_name.clone()));
    let cert = home.certify(&key_name, signer.public_key().unwrap()).await;
    let link_key = LinkKey::from_signer(Arc::clone(&signer) as Arc<dyn Signer>).unwrap();
    let key = link_key.fingerprint();
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .security_profile(SecurityProfile::Disabled)
        .build()
        .await
        .unwrap();
    let keyring = Arc::new(Keyring::new());
    keyring.adopt(Arc::clone(&home.context)).unwrap();
    let transport = LinkTransportConfig::default();
    let link_key: Arc<dyn LinkKeySource> = Arc::new(link_key);
    let socket = Arc::new(
        LinkEndpoint::bind(
            "127.0.0.1:0".parse().unwrap(),
            Arc::clone(&link_key),
            &transport,
            true,
        )
        .unwrap(),
    );
    let addr = socket.local_addr().unwrap();
    let cancel = CancellationToken::new();
    let links = Links::start(
        LinkSetup {
            peers,
            key: link_key,
            trust: Arc::new(Trust {
                keyring,
                chain: vec![cert.data_wire().unwrap()],
            }),
            faces: Arc::new(EngineFaces(engine.clone())),
            paths: Arc::new(ConfiguredEndpoints),
            candidates: vec![Arc::new(HostCandidates {
                include_local: true,
            })],
            socket: Some(socket),
            transport,
            relays: Default::default(),
            service: Default::default(),
            direct: Default::default(),
        },
        cancel.clone(),
    );
    let node = engine.app_node(cancel.child_token());
    Member {
        links,
        key,
        addr,
        signer,
        cert,
        node,
        cancel,
        _engine: engine,
        _shutdown: shutdown,
    }
}

/// The notes `a` produces: `/home/member/a/notes/<n>`.
fn notes() -> Name {
    n(&format!("{NS}/member/a/notes"))
}

fn note(i: usize) -> Name {
    notes().append(i.to_string())
}

/// A note, signed by `signer` as the data layer's devices sign: the bytes `a` answers with.
fn signed_note(signer: &Ed25519Signer, name: Name) -> Bytes {
    DataBuilder::new(name, b"a note".as_slice()).sign_sync(
        signer.sig_type(),
        Some(signer.key_name()),
        |region| signer.sign_sync(region).unwrap(),
    )
}

/// `a` answers every Interest under `/home/member/a/` with a signed Data of that name.
async fn produce(a: &Member) -> ndn_app::ServeGuard {
    let signer = Arc::clone(&a.signer);
    a.node
        .serve(n(&format!("{NS}/member/a")), move |interest, responder| {
            let signer = Arc::clone(&signer);
            async move {
                let wire = signed_note(&signer, (*interest.name).clone());
                let _ = responder.respond_bytes(wire).await;
            }
        })
        .await
        .unwrap()
}

/// `b`, dialling `a`.
async fn dialling(home: &Home, a: &Member) -> Member {
    let to_a = PeerSpec {
        label: "a".into(),
        device: Some(n(&format!("{NS}/member/a"))),
        endpoints: vec![a.addr.to_string()],
        persistent: true,
        ..Default::default()
    };
    member(home, "b", 2, vec![to_a]).await
}

async fn until(what: &str, limit: Duration, mut done: impl FnMut() -> bool) {
    let start = Instant::now();
    while !done() {
        assert!(start.elapsed() < limit, "not within {limit:?}: {what}");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// What one fetch of a note came to.
#[derive(Debug)]
enum Got {
    /// The Data arrived and its signature validates.
    Verified,
    /// The Data arrived and the consumer's validation refused it.
    Refused(VerifyError),
    /// Nothing arrived within the Interest's lifetime.
    Lost,
}

/// One fetch of `name`, validated by `validator`.
async fn attempt(
    consumer: &mut Consumer,
    validator: &Validator,
    name: &Name,
    lifetime: Duration,
) -> Got {
    match consumer
        .fetch_with(InterestBuilder::new(name.clone()).lifetime(lifetime))
        .await
    {
        Err(_) => Got::Lost,
        Ok(data) => match Unverified::new(data).verify(validator).await {
            Ok(_) => Got::Verified,
            Err(refusal) => Got::Refused(refusal),
        },
    }
}

/// Two members linked, `a` producing: `b` fetches an unfaulted probe until it gets one, so
/// the link and its routes are up before any case's own packets cross it.
async fn linked(home: &Home) -> (Member, Member, ndn_app::ServeGuard, Consumer, Validator) {
    let a = member(home, "a", 1, Vec::new()).await;
    let guard = produce(&a).await;
    let (b, consumer, validator) = join(home, &a).await;
    (a, b, guard, consumer, validator)
}

/// `b` dialling the producing `a`, and linked.
async fn join(home: &Home, a: &Member) -> (Member, Consumer, Validator) {
    let b = dialling(home, a).await;
    let mut consumer = Consumer::new(b.node.connection());
    let validator = home.validator(&a.cert);
    until("b links with a", Duration::from_secs(20), || {
        b.links
            .report()
            .links
            .iter()
            .any(|l| l.key == Some(a.key) && l.paths.iter().any(|p| p.kind == PathKind::Link))
    })
    .await;
    let probe = n(&format!("{NS}/member/a/probe"));
    let start = Instant::now();
    loop {
        if matches!(
            attempt(
                &mut consumer,
                &validator,
                &probe,
                Duration::from_millis(300)
            )
            .await,
            Got::Verified
        ) {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "no probe crossed the link"
        );
    }
    (b, consumer, validator)
}

/// What a recording verdict saw: the packets that met the profile.
#[derive(Clone, Default)]
struct Seen(Arc<Mutex<Vec<FaultFrame>>>);

impl Seen {
    fn all(&self) -> Vec<FaultFrame> {
        self.0.lock().clone()
    }
}

fn in_notes(f: &FaultFrame) -> bool {
    f.name.as_ref().is_some_and(|nm| nm.has_prefix(&notes()))
}

/// `profile` on the packets of the notes `matching` chooses, recording each it applied to.
fn plan(
    profile: Faults,
    seen: &Seen,
    matching: impl Fn(&FaultFrame) -> bool + Send + Sync + 'static,
) -> FaultPlan {
    let seen = seen.clone();
    FaultPlan::new(profile).verdict(move |f| {
        let chosen = in_notes(f) && matching(f);
        if chosen {
            seen.0.lock().push(f.clone());
            FaultVerdict::Profile
        } else {
            FaultVerdict::Pass
        }
    })
}

/// The fates of the shared stream for the packets `seen` recorded, as arrivals from `peer` at
/// `me`: the counters the layer must report. The ends of a link direction are the first
/// eight bytes (big-endian) of the sender's key's fingerprint and of the receiver's
/// (`ndn-link.md` §17B.3); an Interest, a Nack or other frame is told from a Data by kind alone.
fn replay(
    profile: &Faults,
    peer: &KeyFingerprint,
    me: &KeyFingerprint,
    seen: &[FaultFrame],
) -> FaultReport {
    let end = |k: &KeyFingerprint| u64::from_be_bytes(k.0[..8].try_into().unwrap());
    let mut stream = profile.stream(end(peer), end(me));
    let data = DataBuilder::new(n("/x"), b"c".as_slice()).sign_digest_sha256();
    let interest = InterestBuilder::new(n("/x")).build();
    let mut report = FaultReport {
        profile: Some(profile.to_string()),
        ..FaultReport::default()
    };
    for frame in seen {
        let wire = match frame.kind {
            FaultKind::Data => data.clone(),
            FaultKind::Interest => interest.clone(),
            FaultKind::Nack | FaultKind::Other => Bytes::from_static(&[0]),
        };
        let fate = stream.fate(wire.clone());
        report.met += 1;
        if fate.copies == 0 {
            report.dropped += 1;
            continue;
        }
        report.duplicated += u64::from(fate.copies > 1);
        report.forged += u64::from(fate.frame != wire);
        report.delayed += u64::from(!fate.delay.is_zero());
    }
    report
}

/// The layer's report of `links` and what its verdict saw, read together once nothing is
/// arriving between the two reads.
fn settled(links: &Links, seen: &Seen) -> (FaultReport, Vec<FaultFrame>) {
    for _ in 0..200 {
        let before = links.report().fault_injection.expect("the layer");
        let recorded = seen.all();
        let after = links.report().fault_injection.expect("the layer");
        if before == after && before.met as usize == recorded.len() {
            return (after, recorded);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("the layer never settled");
}

/// The counters the layer reports on `links` are the shared stream's fates for the packets it
/// met.
fn assert_fates_are_the_streams(
    what: &str,
    links: &Links,
    seen: &Seen,
    profile: &Faults,
    peer: &KeyFingerprint,
    me: &KeyFingerprint,
) -> FaultReport {
    let (report, recorded) = settled(links, seen);
    // `passed` counts the packets the verdict let pass (the probe, link traffic): they
    // draw nothing, so the stream says nothing of them.
    let want = FaultReport {
        passed: report.passed,
        ..replay(profile, peer, me, &recorded)
    };
    assert_eq!(
        report,
        want,
        "{what}: the fates drawn on the link are not the shared stream's for the same {} packets",
        recorded.len()
    );
    report
}

/// The conformance's `FAULTY` profile, on both devices of a real link: the notes still
/// arrive and validate (the consumer asks again), and what the layers did to the packets of
/// the exchange is what the shared stream draws for them.
#[tokio::test(flavor = "multi_thread")]
async fn the_conformance_profile_on_a_real_link() {
    let home = Home::new();
    let (a, b, _guard, mut consumer, validator) = linked(&home).await;
    let profile = Faults::parse(FAULTY).unwrap().with_seed(7);
    let (seen_a, seen_b) = (Seen::default(), Seen::default());
    // Interests are faulted as they arrive at `a`, the Data that answers them at `b`.
    a.links.inject_faults(plan(profile, &seen_a, |_| true));
    b.links.inject_faults(plan(profile, &seen_b, |_| true));

    let mut attempts = 0;
    let mut refused = 0;
    for i in 0..4 {
        let start = Instant::now();
        loop {
            attempts += 1;
            match attempt(
                &mut consumer,
                &validator,
                &note(i),
                Duration::from_millis(2500),
            )
            .await
            {
                Got::Verified => break,
                Got::Refused(_) => refused += 1,
                Got::Lost => {}
            }
            assert!(
                start.elapsed() < Duration::from_secs(90),
                "note {i} never arrived and validated in {attempts} attempts"
            );
        }
    }
    println!("{attempts} attempts for 4 notes, {refused} refused as forged");

    let at_a = assert_fates_are_the_streams("a", &a.links, &seen_a, &profile, &b.key, &a.key);
    let at_b = assert_fates_are_the_streams("b", &b.links, &seen_b, &profile, &a.key, &b.key);
    assert!(
        at_a.met >= 4 && at_b.met >= 4,
        "at least the four notes crossed: {at_a:?} {at_b:?}"
    );
    assert_eq!(
        at_b.forged, refused as u64,
        "every forged Data the layer made was refused by validation, and only those"
    );
}

/// What a run of `interests` serial Interests under `profile` came to at `a`, a link made
/// after the plan was installed (the plan is on `a` before `b` dials).
async fn interests_under(profile: Faults, interests: usize) -> FaultReport {
    let home = Home::new();
    let a = member(&home, "a", 1, Vec::new()).await;
    let _guard = produce(&a).await;
    let seen = Seen::default();
    a.links
        .inject_faults(plan(profile, &seen, |f| f.kind == FaultKind::Interest));
    let (b, mut consumer, validator) = join(&home, &a).await;
    // Only `a`'s arrivals of notes' Interests meet the profile: one per fetch, whatever
    // else crosses, so the packets of the run are the same in every run.
    for i in 0..interests {
        attempt(
            &mut consumer,
            &validator,
            &note(i),
            Duration::from_millis(150),
        )
        .await;
    }
    until(
        "the Interests have arrived at a",
        Duration::from_secs(20),
        || a.links.report().fault_injection.unwrap().met as usize >= interests,
    )
    .await;
    let report = assert_fates_are_the_streams("a", &a.links, &seen, &profile, &b.key, &a.key);
    assert_eq!(report.met as usize, interests, "one Interest per fetch");
    assert!(
        seen.all()
            .iter()
            .all(|f| f.direction == Direction::Accepted && f.peer == b.key),
        "the verdict is told which link, and that `a` accepted it"
    );
    report
}

/// The same seed gives the same faults, run after run, on a link made after the plan; another
/// seed gives others. (The Interests of a run are the same in every run, so the counters are
/// too; the shared stream says what they must be.)
#[tokio::test(flavor = "multi_thread")]
async fn the_same_seed_is_the_same_faults_and_another_seed_others() {
    let profile = |seed| Faults::parse("drop=0.3,dup=0.2").unwrap().with_seed(seed);
    let first = interests_under(profile(21), 30).await;
    let again = interests_under(profile(21), 30).await;
    assert_eq!(first, again, "the same seed, the same faults");
    assert!(
        first.dropped > 0 && first.duplicated > 0,
        "the profile did something: {first:?}"
    );
    let other = interests_under(profile(22), 30).await;
    assert_ne!(
        (first.dropped, first.duplicated),
        (other.dropped, other.duplicated),
        "another seed, other faults: {first:?} {other:?}"
    );
}

/// A Data the layer forged is refused by the consumer's validation, never delivered as
/// valid; the same Data unforged validates; and a consumer that does not validate takes the
/// forged one as it takes any (so the refusal is the validation's, not the layer's).
#[tokio::test(flavor = "multi_thread")]
async fn a_forged_data_is_still_refused_by_validation() {
    let home = Home::new();
    let (a, b, _guard, mut consumer, validator) = linked(&home).await;
    let lifetime = Duration::from_secs(3);

    // Control: with no plan the note validates.
    assert!(matches!(
        attempt(&mut consumer, &validator, &note(0), lifetime).await,
        Got::Verified
    ));

    let seen = Seen::default();
    b.links
        .inject_faults(plan(Faults::parse("forge=1").unwrap(), &seen, |f| {
            f.kind == FaultKind::Data
        }));
    let got = attempt(&mut consumer, &validator, &note(1), lifetime).await;
    assert!(
        matches!(got, Got::Refused(VerifyError::Invalid(_))),
        "a forged Data must be refused by validation, got {got:?}"
    );
    assert_eq!(b.links.report().fault_injection.unwrap().forged, 1);

    // The consumer that trusts without validating is handed the forged bytes, so the layer
    // did forge them: the refusal above is the validation's.
    let data: Data = consumer
        .fetch_with(InterestBuilder::new(note(2)).lifetime(lifetime))
        .await
        .expect("a consumer that does not validate takes what arrives");
    let genuine = signed_note(&a.signer, note(2));
    assert_ne!(
        data.raw(),
        &genuine,
        "what arrived is not what `a` signed: the layer forged it"
    );
    assert_eq!(data.raw().len(), genuine.len(), "one byte was flipped");
    assert!(
        matches!(
            Unverified::new(data).verify(&validator).await,
            Err(VerifyError::Invalid(_))
        ),
        "and validation refuses it"
    );
    assert_eq!(b.links.report().fault_injection.unwrap().forged, 2);

    // Without the plan the same note validates again.
    b.links.clear_faults();
    assert!(matches!(
        attempt(&mut consumer, &validator, &note(3), lifetime).await,
        Got::Verified
    ));
}

/// With a verdict only the packets it hands to the profile are touched, and it is told what
/// each is: its kind, its name, which side opened the link and whose key it came from.
#[tokio::test(flavor = "multi_thread")]
async fn only_the_packets_the_verdict_hands_to_the_profile_are_touched() {
    let home = Home::new();
    let a = member(&home, "a", 1, Vec::new()).await;
    let _guard = produce(&a).await;
    // Every Interest for `/notes/lost` is dropped at `a`; no other packet is touched.
    let lost = note(99);
    let asked: Arc<Mutex<Vec<FaultFrame>>> = Arc::default();
    let log = Arc::clone(&asked);
    let target = lost.clone();
    let plan = FaultPlan::new(Faults::parse("drop=1").unwrap()).verdict(move |f: &FaultFrame| {
        log.lock().push(f.clone());
        if f.kind == FaultKind::Interest && f.name.as_ref() == Some(&target) {
            FaultVerdict::Profile
        } else {
            FaultVerdict::Pass
        }
    });
    a.links.inject_faults(plan);
    let (b, mut consumer, validator) = join(&home, &a).await;
    // And `b` only looks: its verdict lets every packet pass.
    let at_b: Arc<Mutex<Vec<FaultFrame>>> = Arc::default();
    let log = Arc::clone(&at_b);
    b.links.inject_faults(
        FaultPlan::new(Faults::parse("drop=1").unwrap()).verdict(move |f| {
            log.lock().push(f.clone());
            FaultVerdict::Pass
        }),
    );

    let lifetime = Duration::from_millis(400);
    let kept = note(1);
    assert!(matches!(
        attempt(&mut consumer, &validator, &kept, lifetime).await,
        Got::Verified
    ));
    assert!(matches!(
        attempt(&mut consumer, &validator, &lost, lifetime).await,
        Got::Lost
    ));
    let report = a.links.report().fault_injection.unwrap();
    assert_eq!(
        (report.met, report.dropped),
        (1, 1),
        "only the Interest for the lost note met the profile: {report:?}"
    );
    assert!(
        report.passed >= 2,
        "the probe and the kept note passed untouched: {report:?}"
    );
    let asked = asked.lock();
    let interest_for = |name: &Name| {
        asked
            .iter()
            .find(|f| f.kind == FaultKind::Interest && f.name.as_ref() == Some(name))
            .cloned()
    };
    for name in [&kept, &lost] {
        let f = interest_for(name).unwrap_or_else(|| panic!("the verdict was not asked of {name}"));
        assert_eq!(f.direction, Direction::Accepted, "a accepted the link");
        assert_eq!(f.peer, b.key);
        assert!(f.len > 0);
    }
    // At `b` the verdict saw the Data that answered, and touched nothing.
    let report_b = b.links.report().fault_injection.unwrap();
    assert_eq!(report_b.met, 0);
    assert_eq!(report_b.passed as usize, at_b.lock().len());
    let at_b = at_b.lock();
    let answer = at_b
        .iter()
        .find(|f| f.kind == FaultKind::Data && f.name.as_ref() == Some(&kept))
        .expect("the verdict at b saw the Data of the kept note");
    assert_eq!(answer.direction, Direction::Dialed, "b dialled the link");
    assert_eq!(answer.peer, a.key);
}

/// The versions of another collection: `/home/member/a/other/<n>` (ndf's scenario K1 drops
/// a version of the other collection and keeps the faulty network for the rest).
fn other_collection() -> Name {
    n(&format!("{NS}/member/a/other"))
}

fn in_other(f: &FaultFrame) -> bool {
    f.name
        .as_ref()
        .is_some_and(|nm| nm.has_prefix(&other_collection()))
}

/// What one run of K1 came to.
struct K1 {
    report: FaultReport,
    /// Whether each note's fetch got its Data (one entry per note, in order).
    arrived: Vec<bool>,
    /// The packets that met the profile, in order.
    met: Vec<FaultFrame>,
    /// How many frames the verdict dropped.
    vetoed: usize,
    /// Whether every fetch of the other collection came to nothing.
    others_lost: bool,
}

/// `notes_n` serial fetches of notes, each preceded by `others` fetches of the other
/// collection's versions, at `a`, whose verdict drops the other collection's frames, hands
/// the notes' Interests to `profile`, and passes the rest.
async fn k1_run(profile: Faults, notes_n: usize, others: usize) -> K1 {
    let home = Home::new();
    let a = member(&home, "a", 1, Vec::new()).await;
    let _guard = produce(&a).await;
    let seen = Seen::default();
    let vetoed = Arc::new(AtomicUsize::new(0));
    let (log, count) = (seen.clone(), Arc::clone(&vetoed));
    a.links
        .inject_faults(FaultPlan::new(profile).verdict(move |f| {
            if in_other(f) {
                count.fetch_add(1, AtomicOrdering::SeqCst);
                FaultVerdict::Drop
            } else if in_notes(f) && f.kind == FaultKind::Interest {
                log.0.lock().push(f.clone());
                FaultVerdict::Profile
            } else {
                FaultVerdict::Pass
            }
        }));
    let (b, mut consumer, validator) = join(&home, &a).await;
    let mut arrived = Vec::new();
    let mut others_lost = true;
    for i in 0..notes_n {
        for j in 0..others {
            let name = other_collection().append((i * others + j).to_string());
            let got = attempt(&mut consumer, &validator, &name, Duration::from_millis(200)).await;
            others_lost &= matches!(got, Got::Lost);
        }
        let got = attempt(
            &mut consumer,
            &validator,
            &note(i),
            Duration::from_millis(600),
        )
        .await;
        arrived.push(matches!(got, Got::Verified));
    }
    until(
        "the notes' Interests have arrived at a",
        Duration::from_secs(20),
        || a.links.report().fault_injection.unwrap().met as usize >= notes_n,
    )
    .await;
    let (report, met) = settled(&a.links, &seen);
    // What the profile did to the frames that met it is the shared stream's draws for those
    // frames alone: the verdict's drops and passes drew nothing.
    let vetoed = vetoed.load(AtomicOrdering::SeqCst);
    let replayed = replay(&profile, &b.key, &a.key, &met);
    assert_eq!(
        report,
        FaultReport {
            passed: report.passed,
            dropped: replayed.dropped + vetoed as u64,
            ..replayed
        },
        "the counters are the stream's fates for the packets that met the profile, plus the \
         verdict's drops in `dropped`"
    );
    K1 {
        report,
        arrived,
        met,
        vetoed,
        others_lost,
    }
}

/// Case K1: the verdict drops a version of another collection, the faulty profile stays on
/// for the rest. Both are visible in the counters and in what arrives, and the same seed gives
/// the same fates twice, with or without the dropped frames between the others.
#[tokio::test(flavor = "multi_thread")]
async fn a_verdict_drops_one_collection_and_the_profile_stays_on_for_the_rest() {
    let profile = Faults {
        // Shortened so the delays fit the fetches' lifetimes; the draws are the same.
        delay_ms: 40,
        blocks_ms: 40,
        ..Faults::parse(FAULTY).unwrap().with_seed(5)
    };
    let notes_n = 20;
    let first = k1_run(profile, notes_n, 1).await;
    let again = k1_run(profile, notes_n, 1).await;
    let without = k1_run(profile, notes_n, 0).await;

    // The verdict's effect: every version of the other collection is lost, and counted.
    assert!(
        first.others_lost,
        "a dropped version of another collection arrived"
    );
    assert_eq!(
        first.vetoed, notes_n,
        "one Interest per fetch of the other collection"
    );
    assert_eq!(without.vetoed, 0);
    assert_eq!(
        first.report.dropped - without.report.dropped,
        notes_n as u64,
        "the verdict's drops are in `dropped`, beside the profile's"
    );

    // The profile's effect on the rest: some notes are lost, some are not, by its fates.
    let lost = first.arrived.iter().filter(|got| !**got).count();
    assert!(
        0 < lost && lost < notes_n,
        "the profile stayed on for the notes: {lost} of {notes_n} lost, {:?}",
        first.report
    );
    let by_profile = first.report.dropped - first.vetoed as u64;
    assert_eq!(
        lost as u64, by_profile,
        "a note is lost exactly when the profile dropped it"
    );
    assert_eq!(
        first.report.met as usize, notes_n,
        "only the notes met the profile"
    );

    // Same seed, same fates: twice, and with no frames dropped between the notes.
    let at_profile = |k: &K1| {
        let by_profile = k.report.dropped - k.vetoed as u64;
        (
            FaultReport {
                passed: 0,
                dropped: by_profile,
                ..k.report.clone()
            },
            k.arrived.clone(),
            k.met.len(),
        )
    };
    assert_eq!(
        at_profile(&first),
        at_profile(&again),
        "the same seed, the same fates"
    );
    assert_eq!(
        at_profile(&first),
        at_profile(&without),
        "what the profile does to the notes does not depend on the frames dropped between them"
    );
}
