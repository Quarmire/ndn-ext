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

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use ndn_app::EngineAppExt;
use ndn_data::intro::{Dialing, Grant as DataGrant, LinkHint};
use ndn_data::{
    Answer, Audience, Clock, Config, Content, DataLayer, Device, Got, IntroPolicy, Introducer,
    Joined, Keep, NextStep, Offer, Payload, PutOptions, Role, Rule, Share, Sharing, Timestamp,
    Transport, TypeId,
};
use ndn_engine::{EngineBuilder, EngineConfig, ForwarderEngine, ShutdownHandle};
use ndn_face_quic::{KeyFingerprint, LinkEndpoint, LinkKey, LinkKeySource, LinkTransportConfig};
use ndn_link::{
    ConfiguredEndpoints, EngineFaces, Grant, GrantRole, HostCandidates, LinkDetail, LinkHints,
    LinkSetup, LinkTrust, Links, Quotas, RelayService, ServePolicy,
};
use ndn_packet::{Data, Name};
use ndn_security::sync_group;
use ndn_security::{
    Certificate, Keyring, SecurityManager, SecurityProfile, SignedTrustContext, TrustSchema,
    Validator,
};
use ndn_sync::MemoryStore;
use ndn_trust_envelope::TrustEnvelope;
use tokio_util::sync::CancellationToken;

const VALIDITY_MS: u64 = 365 * 24 * 3600 * 1000;
const FOLDER: &str = "/alice/32=data/notebook";
const ANN: &str = "/alice/member/laptop";

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

/// A person: a namespace with its root key, trust context and anchor.
struct Person {
    ns: Name,
    authority: SecurityManager,
    issuer: Name,
    ctx: Arc<SignedTrustContext>,
    signed: Bytes,
}

impl Person {
    async fn new(ns: &str) -> Person {
        let ns = n(ns);
        let authority = SecurityManager::new();
        let issuer = authority
            .generate_ed25519(ns.clone().append("KEY").append("ns"))
            .unwrap();
        let signer = authority.get_signer_sync(&issuer).unwrap();
        let anchor = authority
            .issue_self_signed_async(&issuer, signer.public_key().unwrap(), VALIDITY_MS)
            .await
            .unwrap();
        let ctx = SignedTrustContext::hierarchical(ns.clone()).with_version(1);
        assert!(ctx.add_anchor(anchor));
        let signed = ctx.sign_into_data(signer.as_ref()).unwrap().raw().clone();
        Person {
            ns,
            authority,
            issuer,
            ctx: Arc::new(ctx),
            signed,
        }
    }
}

/// A device's keys, and its link socket when it listens.
struct Parts {
    name: Name,
    keys: Arc<SecurityManager>,
    key_name: Name,
    link_key: Arc<dyn LinkKeySource>,
    fingerprint: KeyFingerprint,
    public: Bytes,
    socket: Option<Arc<LinkEndpoint>>,
    addr: Option<SocketAddr>,
    transport: LinkTransportConfig,
}

impl Parts {
    fn new(device: &str, listen: bool) -> Parts {
        let name = n(device);
        let keys = Arc::new(SecurityManager::new());
        let key_name = keys
            .generate_ed25519(name.clone().append("KEY").append("1"))
            .unwrap();
        let signer = keys.get_signer_sync(&key_name).unwrap();
        let public = signer.public_key().unwrap();
        let link_key = LinkKey::from_signer(signer).unwrap();
        let fingerprint = link_key.fingerprint();
        let transport = LinkTransportConfig::default();
        let link_key: Arc<dyn LinkKeySource> = Arc::new(link_key);
        let socket = listen.then(|| {
            Arc::new(
                LinkEndpoint::bind(
                    "127.0.0.1:0".parse().unwrap(),
                    Arc::clone(&link_key),
                    &transport,
                    true,
                )
                .unwrap(),
            )
        });
        let addr = socket.as_ref().map(|s| s.local_addr().unwrap());
        Parts {
            name,
            keys,
            key_name,
            link_key,
            fingerprint,
            public,
            socket,
            addr,
            transport,
        }
    }

    /// The certificate `person` gives this device's key.
    async fn certified(&self, person: &Person) -> Certificate {
        let cert = person
            .authority
            .certify(
                &self.key_name,
                self.public.clone(),
                &person.issuer,
                VALIDITY_MS,
            )
            .await
            .unwrap();
        self.keys.cert_cache().insert(cert.clone());
        cert
    }
}

/// The host's trust data for the link library.
struct Trust {
    keyring: Arc<Keyring>,
    chain: Vec<Bytes>,
    validator: Arc<Validator>,
}

impl LinkTrust for Trust {
    fn keyring(&self) -> &Arc<Keyring> {
        &self.keyring
    }
    fn own_chain(&self) -> Vec<Bytes> {
        self.chain.clone()
    }
    fn known_certificate(&self, name: &Name) -> Option<Certificate> {
        self.validator.cert_cache().get_valid(name)
    }
    fn known_certificate_of_key(&self, _: &KeyFingerprint) -> Option<Certificate> {
        None
    }
}

fn trust(person: &Person, cert: &Certificate) -> (Arc<Validator>, Arc<Trust>) {
    let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
    validator.adopt_context(Arc::clone(&person.ctx)).unwrap();
    validator.cert_cache().insert(cert.clone());
    let trust = Arc::new(Trust {
        keyring: Arc::clone(validator.keyring()),
        chain: vec![cert.data_wire().unwrap()],
        validator: Arc::clone(&validator),
    });
    (validator, trust)
}

/// A host's introducer: its person's signed context, adoption into its
/// validator and forwarder, a link hint and a dial through its links, and
/// the grants its device makes and ends forwarded to them.
struct Host {
    anchor: Bytes,
    validator: Arc<Validator>,
    engine: ForwarderEngine,
    hints: OnceLock<LinkHints>,
}

impl Introducer for Host {
    fn anchor(&self) -> Option<Bytes> {
        Some(self.anchor.clone())
    }

    fn adopt<'a>(&'a self, link: &'a TrustEnvelope) -> ndn_data::intro::Adopting<'a> {
        Box::pin(async move {
            let TrustEnvelope::Anchor {
                namespace: Some(ns),
                context_data: Some(data),
                ..
            } = link
            else {
                return Err("not an inline anchor link".into());
            };
            let ns: Name = ns.parse().map_err(|_| "no name".to_string())?;
            let data = Data::decode(data.clone()).map_err(|e| format!("{e:?}"))?;
            let (ctx, _) = SignedTrustContext::open_received(&data)
                .await
                .map_err(|e| e.to_string())?;
            if self.validator.keyring().held(&ns).is_none() {
                self.validator
                    .adopt_context(Arc::new(ctx))
                    .map_err(|refused| refused.to_string())?;
            }
            ndn_namespace::sync_group::carry(&self.engine, &ns);
            Ok(())
        })
    }

    fn link_hint(&self) -> Option<LinkHint> {
        self.hints.get().and_then(LinkHints::hint)
    }

    fn dial<'a>(&'a self, hint: &'a LinkHint, inviter: &'a Name, within: Duration) -> Dialing<'a> {
        match self.hints.get() {
            Some(hints) => hints.dial(hint, inviter, within),
            None => Box::pin(async { Err("no links".to_string()) }),
        }
    }

    fn undial(&self, hint: &LinkHint, inviter: &Name) {
        if let Some(hints) = self.hints.get() {
            hints.undial(hint, inviter);
        }
    }

    fn grant(&self, grant: &DataGrant) {
        if let Some(hints) = self.hints.get() {
            hints.grant(grant);
        }
    }

    fn revoke_grant(&self, key: &[u8; 32]) {
        if let Some(hints) = self.hints.get() {
            hints.revoke_grant(key);
        }
    }
}

/// How a test's device is set up.
#[derive(Clone)]
struct Setup {
    /// It listens for links on a loopback socket and takes introductions.
    listen: bool,
    /// Whom it serves.
    serve: ServePolicy,
    /// How long a grant its device makes lasts.
    grant_for: Duration,
}

impl Setup {
    /// An inviter that keeps the default policy: `own`, and the grants its
    /// device makes.
    fn inviter() -> Setup {
        Setup {
            listen: true,
            serve: ServePolicy::Own,
            grant_for: Duration::from_secs(90 * 24 * 3600),
        }
    }

    fn open() -> Setup {
        Setup {
            serve: ServePolicy::Open {
                quotas: Quotas::default(),
            },
            ..Setup::inviter()
        }
    }

    /// A joiner: dial-only.
    fn dialer() -> Setup {
        Setup {
            listen: false,
            ..Setup::inviter()
        }
    }
}

/// A device of a person, alone on a forwarder of its own: its data layer, its
/// links.
struct Embedded {
    device: Device,
    links: Arc<Links>,
    key: KeyFingerprint,
    ns: Name,
    addr: Option<SocketAddr>,
    cancel: CancellationToken,
    engine: ForwarderEngine,
    _shutdown: ShutdownHandle,
    validator: Arc<Validator>,
    skew: Arc<AtomicU64>,
}

impl Drop for Embedded {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

impl Embedded {
    /// Every offer this device made has run out by its clock (moved two hours
    /// on): no stranger's introduction link is worth taking, so a device the
    /// policy does not serve is refused, with the reason.
    fn offers_run_out(&self) {
        self.skew.store(2 * 3_600_000, Ordering::SeqCst);
        assert!(
            !self.device.introductions().open(),
            "an offer is still open two hours on"
        );
    }
}

async fn embedded(person: &Person, device: &str, setup: Setup) -> Embedded {
    let parts = Parts::new(device, setup.listen);
    let cert = parts.certified(person).await;
    let (validator, trust) = trust(person, &cert);
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .security_profile(SecurityProfile::Disabled)
        .build()
        .await
        .unwrap();
    ndn_namespace::sync_group::carry(&engine, &person.ns);
    let cancel = CancellationToken::new();
    let skew = Arc::new(AtomicU64::new(0));
    let clock: Clock = {
        let by = Arc::clone(&skew);
        Arc::new(move || {
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_or(0, |d| d.as_millis() as u64);
            Timestamp(now + by.load(Ordering::SeqCst))
        })
    };
    let links = Links::start(
        LinkSetup {
            peers: Vec::new(),
            key: Arc::clone(&parts.link_key),
            trust,
            faces: Arc::new(EngineFaces(engine.clone())),
            paths: Arc::new(ConfiguredEndpoints),
            candidates: vec![Arc::new(HostCandidates {
                include_local: true,
            })],
            socket: parts.socket.clone(),
            transport: parts.transport.clone(),
            relays: Default::default(),
            service: RelayService {
                serve: setup.serve,
                ..RelayService::default()
            },
            direct: Default::default(),
        },
        cancel.clone(),
    );
    let hints = LinkHints::new(Arc::clone(&links));
    let host = Arc::new(Host {
        anchor: person.signed.clone(),
        validator: Arc::clone(&validator),
        engine: engine.clone(),
        hints: OnceLock::new(),
    });
    let _ = host.hints.set(hints.clone());
    let device = Device::start(
        Transport {
            node: engine.app_node(cancel.child_token()),
            sync: engine.app_face(cancel.child_token()),
        },
        parts.name.clone(),
        Arc::clone(&parts.keys),
        Arc::clone(&validator),
        Arc::new(MemoryStore::new()),
        Config {
            clock,
            first_look: Duration::from_secs(1),
            introducer: Some(host),
            intro: IntroPolicy {
                local_candidates: true,
                grant_for: setup.grant_for,
                ..IntroPolicy::new()
            },
            ..Config::new()
        },
    )
    .await
    .unwrap();
    if setup.listen {
        hints.serve(&device);
    }
    Embedded {
        device,
        links,
        key: parts.fingerprint,
        ns: person.ns.clone(),
        addr: parts.addr,
        cancel,
        engine,
        validator,
        skew,
        _shutdown: shutdown,
    }
}

fn note() -> PutOptions {
    PutOptions {
        type_id: TypeId {
            name: n("/types/note"),
            revision: 1,
        },
        keep: Keep::Forever,
        batch: None,
    }
}

fn text(s: &str) -> Content {
    Content::new().with("text", Bytes::copy_from_slice(s.as_bytes()))
}

/// Whether `layer` reads `s` as the newest note of `collection`.
async fn reads(layer: &Device, collection: &Name, s: &str) -> bool {
    match layer.get(collection).await {
        Ok(Answer {
            got: Got::Version(v),
            ..
        }) => {
            matches!(&v.payload, Payload::Entry(c) if c.get("text").is_some_and(|t| t[..] == *s.as_bytes()))
        }
        _ => false,
    }
}

async fn until(what: &str, limit: Duration, mut done: impl AsyncFnMut() -> bool) {
    let start = Instant::now();
    while !done().await {
        assert!(start.elapsed() < limit, "not within {limit:?}: {what}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

const LONG: Duration = Duration::from_secs(60);

/// Ann's notebook, shared with `/alice` alone and with a cover written into
/// it: an offer of it as `role` made by her laptop.
async fn offered(laptop: &Embedded, role: Role) -> ndn_data::Code {
    let folder = n(FOLDER);
    laptop
        .device
        .share_folder(
            &folder,
            Sharing::Whole(Share {
                rule: Rule::Log,
                writers: vec![n("/alice")],
                readers: vec![Audience::Person(n("/alice"))],
            }),
        )
        .await
        .unwrap();
    laptop
        .device
        .put(
            &folder.clone().append("cover"),
            text("cover by ann"),
            note(),
        )
        .await
        .unwrap();
    laptop
        .device
        .offer(
            &folder,
            Offer {
                role,
                until: Timestamp(
                    SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u64
                        + 3_600_000,
                ),
                tries: 3,
            },
        )
        .await
        .unwrap()
}

/// Join with `link` as a host does what `NotReady` says: again with the same
/// code until `limit` has passed.
async fn joins(
    phone: &Embedded,
    link: &str,
    limit: Duration,
) -> Result<Joined, ndn_data::DataError> {
    let started = Instant::now();
    loop {
        match phone.device.join(link).await {
            Err(e) if e.next() == NextStep::RetryLater && started.elapsed() < limit => {}
            other => return other,
        }
    }
}

/// What a refusal says: its sentence, its causes' and the other device's.
fn said(detail: &LinkDetail) -> String {
    let mut out = detail.text.clone();
    for (k, v) in &detail.params {
        out.push_str(&format!(" {k}={v}"));
    }
    for cause in &detail.causes {
        out.push(' ');
        out.push_str(&said(cause));
    }
    out
}

/// Ann is linked to the device with `key`.
fn linked(on: &Embedded, key: KeyFingerprint) -> bool {
    on.links
        .report()
        .links
        .iter()
        .any(|l| l.key == Some(key) && !l.paths.is_empty())
}

/// Dial Ann (by her key and address, as a joiner's code names them) from
/// `from`.
async fn dials(from: &Embedded, ann: &Embedded) -> Result<(), LinkDetail> {
    from.links
        .dial_by_key(
            ann.key,
            n(ANN),
            vec![ann.addr.expect("ann listens")],
            Duration::from_secs(10),
            Vec::new(),
        )
        .await
}

/// Invite `bob` as `role` and have him join; returns the link Ann's laptop
/// then has with him, up and made by the grant.
async fn invited(ann: &Embedded, bob: &Embedded, role: Role) {
    let code = offered(ann, role).await;
    let joined = joins(bob, &code.link, Duration::from_secs(90))
        .await
        .unwrap_or_else(|e| {
            panic!(
                "the join failed: {e} ({:?})\nbob: {:#?}\nann: {:#?}",
                e.next(),
                bob.links.report(),
                ann.links.report()
            )
        });
    assert_eq!(joined.role, role);
}

/// The prefixes (sorted, as text) `on`'s forwarder routes over its links to
/// the device with key `key`.
fn routed_over(on: &Embedded, key: KeyFingerprint) -> Vec<String> {
    let faces: Vec<_> = on
        .links
        .report()
        .links
        .iter()
        .filter(|l| l.key == Some(key))
        .flat_map(|l| l.paths.iter().map(|p| p.face))
        .collect();
    let mut out: Vec<String> = on
        .engine
        .fib()
        .dump()
        .into_iter()
        .filter(|(_, e)| e.nexthops.iter().any(|h| faces.contains(&h.face_id)))
        .map(|(prefix, _)| prefix.to_string())
        .collect();
    out.sort();
    out
}

/// Where a device answers probes: under its namespace's sync group, a name
/// the other device's forwarder routes over the link (the group's route), and
/// not under the device's own name.
fn probe_prefix(on: &Embedded) -> Name {
    sync_group(&on.ns).append("probe")
}

/// `on` answers probes with a Data: a Data a device sends on its own, toward
/// the other.
fn answers_probes(on: &Embedded) {
    let producer = on
        .engine
        .register_producer(probe_prefix(on), on.cancel.child_token());
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

/// Whether `from` fetches `/<to>/probe/<tag>` from `to` (it answers probes).
async fn probes(from: &Embedded, to: &Embedded, tag: &str) -> bool {
    let mut consumer = from.engine.app_consumer(from.cancel.child_token());
    consumer.fetch(probe_prefix(to).append(tag)).await.is_ok()
}

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
        granted.describe().starts_with("granted until "),
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

/// A grant that ran out closes the link at `until`, and the next dial of the
/// key is refused naming the expiry. The device's grant lasts 90 days; the
/// host shortens it through `Links::grant`.
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
    shortened.until = until_at;
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

    assert!(ann.links.revoke_grant(&bob.key), "no grant was in force");
    assert!(!ann.links.revoke_grant(&bob.key), "revoked twice");
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
/// device revokes the grant, and the link ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_removed_members_link_closes_when_the_record_drops_him() {
    let alice = Person::new("/alice").await;
    let bobs = Person::new("/bob").await;
    let ann = embedded(&alice, ANN, Setup::inviter()).await;
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
    assert!(ann.links.revoke_grant(&bob.key));
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
        until: SystemTime::now() + Duration::from_secs(3600),
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
