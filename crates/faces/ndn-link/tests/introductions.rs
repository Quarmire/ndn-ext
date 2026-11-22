//! Introductions by a code's link hint, on real forwarders and real data-layer
//! devices: an embedded joiner holding only a code — no daemon, no route, no
//! peer entry — dials the inviter by its key and joins, and the two devices
//! then sync the folder over the link made again between them.
//!
//! The inviter is daemonless too: one program, an in-process forwarder, its
//! links on a loopback UDP socket (QUIC, the device's key as the TLS identity).
//! The cases around it check what the hint's addresses and key may and may not
//! do (ndn-rs `data-layer.md` §19.3 step 0, §19.7; `ndn-link.md` §13.3): the
//! key is proved by the handshake, an address only says where to try, and a
//! code with a full hint is still one QR.

use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use ndn_app::{Consumer, EngineAppExt};
use ndn_data::intro::{
    Contact, Dialing, FirstDialing, HintCandidate, HintKind, HintRecord, LINK_HINT_CANDIDATES_MAX,
    LinkHint, ShortCode, hint_name, hint_prefix, hint_token, introduction_prefixes,
};
use ndn_data::{
    Answer, Audience, Config, Content, DataLayer, Device, Got, IntroPolicy, Introducer, Joined,
    Keep, NextStep, Offer, Payload, PutOptions, Role, Rule, Share, Sharing, Timestamp, Transport,
    TypeId,
};
use ndn_engine::{EngineBuilder, EngineConfig, ForwarderEngine, ShutdownHandle};
use ndn_face_quic::{
    Admission, CloseReason, KeyFingerprint, LinkEndpoint, LinkHello, LinkKey, LinkKeySource,
    LinkTransportConfig,
};
use ndn_link::{
    Candidate, CandidateKind, CandidateSource, ConfiguredEndpoints, EngineFaces, HostCandidates,
    Introductions, LinkHints, LinkSetup, LinkTrust, Links, PathKind, PeerSpec, Quotas,
    RelayService, RelaySource, RelayUse, ServePolicy,
};
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_packet::{Data, Name};
use ndn_security::{
    AdvertisedRelay, Certificate, Keyring, SecurityManager, SecurityProfile, SignedTrustContext,
    TrustSchema, Validator,
};
use ndn_sync::MemoryStore;
use ndn_transport::ErasedTransport;
use ndn_trust_envelope::TrustEnvelope;
use tokio_util::sync::CancellationToken;

const VALIDITY_MS: u64 = 365 * 24 * 3600 * 1000;
const FOLDER: &str = "/alice/32=data/notebook";

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
        Person::build(ns, Vec::new(), false).await
    }

    /// A person whose trust context names a CA to enroll at, so a device of
    /// the `node` role admits enrollment links.
    async fn enrolling(ns: &str) -> Person {
        Person::build(ns, Vec::new(), true).await
    }

    /// A person whose trust context advertises `relays`.
    async fn advertising(ns: &str, relays: Vec<AdvertisedRelay>) -> Person {
        Person::build(ns, relays, false).await
    }

    async fn build(ns: &str, relays: Vec<AdvertisedRelay>, ca: bool) -> Person {
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
        let mut ctx = SignedTrustContext::hierarchical(ns.clone())
            .with_version(1)
            .with_relays(relays);
        if ca {
            ctx = ctx.with_ca_endpoint(ns.clone().append("CA"));
        }
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

/// A device's keys, and its link socket when it listens: made before its
/// person certifies it, since a person's trust context may advertise the
/// address of a relay.
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
        Parts::bound(device, listen.then(|| "127.0.0.1:0".parse().unwrap()))
    }

    /// A device whose link socket listens at `at`, when it listens.
    fn bound(device: &str, at: Option<SocketAddr>) -> Parts {
        let name = n(device);
        let keys = Arc::new(SecurityManager::new());
        let key_name = keys
            .generate_ed25519(name.clone().append("KEY").append("1"))
            .unwrap();
        let signer = keys.get_signer_sync(&key_name).unwrap();
        let public = signer.public_key().unwrap();
        // Its links: the device's own key is the TLS identity.
        let link_key = LinkKey::from_signer(signer).unwrap();
        let fingerprint = link_key.fingerprint();
        let transport = LinkTransportConfig::default();
        let link_key: Arc<dyn LinkKeySource> = Arc::new(link_key);
        let socket = at.map(|at| {
            Arc::new(LinkEndpoint::bind(at, Arc::clone(&link_key), &transport, true).unwrap())
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

/// The host's trust data for the link library: the device's own certificate,
/// and the keyring its data layer's validator judges by (so a namespace the
/// layer adopts is a namespace the links admit).
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

/// A validator trusting `person`, holding the certificate `cert`, and the
/// link trust over it.
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

/// What link hint a host puts in its codes.
#[derive(Clone, Default)]
enum HintMode {
    /// Its links' own: the addresses of its listening socket.
    #[default]
    Links,
    /// None: the code carries no link hint.
    Nothing,
    /// Its links' own, after unreachable IPv6 addresses up to the most a code
    /// carries.
    Full,
    /// Its own key and these addresses.
    At(Vec<SocketAddr>),
}

/// A host's introducer: its person's signed context, adoption into its
/// validator and forwarder, and — through its links — a link hint and a dial.
struct Host {
    anchor: Bytes,
    validator: Arc<Validator>,
    engine: ForwarderEngine,
    key: KeyFingerprint,
    mode: HintMode,
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
            // As a host's forwarder does for a namespace it now holds.
            ndn_namespace::sync_group::carry(&self.engine, &ns);
            Ok(())
        })
    }

    fn link_hint(&self) -> Option<LinkHint> {
        let own = || self.hints.get().and_then(LinkHints::hint);
        match &self.mode {
            HintMode::Links => own(),
            HintMode::Nothing => None,
            HintMode::Full => {
                let real = own()?;
                let mut candidates: Vec<HintCandidate> = (0..LINK_HINT_CANDIDATES_MAX
                    - real.candidates.len())
                    .map(|i| HintCandidate {
                        kind: HintKind::Reflexive,
                        addr: SocketAddr::new(
                            format!("2001:db8:0:{:x}:ffff:ffff:ffff:ffff", i + 1)
                                .parse()
                                .unwrap(),
                            6363 + i as u16,
                        ),
                    })
                    .collect();
                candidates.extend(real.candidates);
                Some(LinkHint {
                    key: real.key,
                    candidates,
                })
            }
            HintMode::At(addrs) => Some(LinkHint {
                key: self.key.0,
                candidates: addrs
                    .iter()
                    .map(|&addr| HintCandidate {
                        kind: HintKind::Host,
                        addr,
                    })
                    .collect(),
            }),
        }
    }

    fn dial<'a>(&'a self, hint: &'a LinkHint, inviter: &'a Name, within: Duration) -> Dialing<'a> {
        match self.hints.get() {
            Some(hints) => hints.dial(hint, inviter, within),
            None => Box::pin(async { Err("no links".to_string()) }),
        }
    }

    fn dial_first<'a>(
        &'a self,
        inviter: &'a Name,
        addr: SocketAddr,
        within: Duration,
    ) -> FirstDialing<'a> {
        match self.hints.get() {
            Some(hints) => hints.dial_first(inviter, addr, within),
            None => Box::pin(async { Err("no links".to_string()) }),
        }
    }

    fn undial(&self, hint: &LinkHint, inviter: &Name) {
        if let Some(hints) = self.hints.get() {
            hints.undial(hint, inviter);
        }
    }
}

/// How a test's device is set up.
#[derive(Clone, Default)]
struct Setup {
    /// It listens for links on a loopback socket and takes introductions
    /// (and links with the people it introduced); otherwise it only dials.
    listen: bool,
    /// Peer entries: the relays it uses.
    peers: Vec<PeerSpec>,
    /// The link hint of its codes.
    hint: HintMode,
    /// Its policy refuses a loopback or link-local address from a code
    /// (`IntroPolicy::local_candidates` off).
    refuse_local: bool,
    /// Where it listens, when it does (default: a loopback port).
    bind: Option<SocketAddr>,
    /// Its sources of candidate addresses (default: `HostCandidates` with
    /// the loopback, devices on one machine).
    candidates: Option<Vec<Arc<dyn CandidateSource>>>,
    /// How many candidates of its hint its compact codes carry (`None`: the
    /// policy's default).
    code_candidates: Option<usize>,
}

impl Setup {
    fn listening() -> Setup {
        Setup {
            listen: true,
            ..Setup::default()
        }
    }
}

/// A device of a person, alone on a forwarder of its own: its data layer,
/// its links (listening on loopback or dial-only), nothing routed.
struct Embedded {
    device: Device,
    links: Arc<Links>,
    validator: Arc<Validator>,
    key: KeyFingerprint,
    addr: Option<SocketAddr>,
    cancel: CancellationToken,
    _engine: ForwarderEngine,
    _shutdown: ShutdownHandle,
}

impl Drop for Embedded {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

async fn forwarder(person: &Person) -> (ForwarderEngine, ShutdownHandle) {
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .security_profile(SecurityProfile::Disabled)
        .build()
        .await
        .unwrap();
    ndn_namespace::sync_group::carry(&engine, &person.ns);
    (engine, shutdown)
}

async fn embedded(person: &Person, device: &str, setup: Setup) -> Embedded {
    let parts = Parts::bound(
        device,
        setup
            .listen
            .then(|| setup.bind.unwrap_or_else(|| "127.0.0.1:0".parse().unwrap())),
    );
    embedded_of(person, parts, setup).await
}

async fn embedded_of(person: &Person, parts: Parts, setup: Setup) -> Embedded {
    let cert = parts.certified(person).await;
    let (validator, trust) = trust(person, &cert);
    let (engine, shutdown) = forwarder(person).await;
    let cancel = CancellationToken::new();

    let links = Links::start(
        LinkSetup {
            peers: setup.peers,
            key: Arc::clone(&parts.link_key),
            trust,
            faces: Arc::new(EngineFaces(engine.clone())),
            paths: Arc::new(ConfiguredEndpoints),
            // Devices on one machine: loopback host candidates.
            candidates: setup.candidates.unwrap_or_else(|| {
                vec![Arc::new(HostCandidates {
                    include_local: true,
                })]
            }),
            socket: parts.socket.clone(),
            transport: parts.transport.clone(),
            relays: Default::default(),
            // An inviter links with the people it invites, whom it knows of
            // only when they ask: it serves any namespace, within quotas
            // (the default `own` serves only its own).
            service: RelayService {
                serve: if setup.listen {
                    ServePolicy::Open {
                        quotas: Quotas::default(),
                    }
                } else {
                    ServePolicy::Own
                },
                ..RelayService::default()
            },
            direct: Default::default(),
            reliability: Default::default(),
        },
        cancel.clone(),
    );
    let hints = LinkHints::new(Arc::clone(&links));
    let host = Arc::new(Host {
        anchor: person.signed.clone(),
        validator: Arc::clone(&validator),
        engine: engine.clone(),
        key: parts.fingerprint,
        mode: setup.hint,
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
            first_look: Duration::from_secs(1),
            introducer: Some(host),
            // Devices on one machine: hints that name loopback addresses
            // (unless the case is about a device that refuses them).
            intro: IntroPolicy {
                local_candidates: !setup.refuse_local,
                code_candidates: setup
                    .code_candidates
                    .unwrap_or(IntroPolicy::new().code_candidates),
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
        validator,
        key: parts.fingerprint,
        addr: parts.addr,
        cancel,
        _engine: engine,
        _shutdown: shutdown,
    }
}

/// A relay: links on a loopback socket and a forwarder, serving the devices
/// of other namespaces.
struct Relay {
    key: KeyFingerprint,
    addr: SocketAddr,
    name: Name,
    cancel: CancellationToken,
    _engine: ForwarderEngine,
    _shutdown: ShutdownHandle,
    _links: Arc<Links>,
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// A relay of `person` that also holds the trust context of each person in
/// `followed`, so it checks their devices as its own operator would (their
/// revocations honoured) and serves them as its policy says.
async fn relay(person: &Person, followed: &[&Person], parts: Parts) -> Relay {
    let cert = parts.certified(person).await;
    let (validator, trust) = trust(person, &cert);
    for other in followed {
        validator.adopt_context(Arc::clone(&other.ctx)).unwrap();
    }
    let (engine, shutdown) = forwarder(person).await;
    for other in followed {
        ndn_namespace::sync_group::carry(&engine, &other.ns);
    }
    // A hint naming this relay has reached it: the Interest goes on by name.
    engine.network_region().add_own_name(parts.name.clone());
    let cancel = CancellationToken::new();
    let links = Links::start(
        LinkSetup {
            peers: Vec::new(),
            key: Arc::clone(&parts.link_key),
            trust,
            faces: Arc::new(EngineFaces(engine.clone())),
            paths: Arc::new(ConfiguredEndpoints),
            candidates: Vec::new(),
            socket: parts.socket.clone(),
            transport: parts.transport.clone(),
            relays: Default::default(),
            service: RelayService {
                serve: ServePolicy::Open {
                    quotas: Quotas::default(),
                },
                ..RelayService::default()
            },
            direct: Default::default(),
            reliability: Default::default(),
        },
        cancel.clone(),
    );
    Relay {
        key: parts.fingerprint,
        addr: parts.addr.expect("a relay listens"),
        name: parts.name,
        cancel,
        _engine: engine,
        _shutdown: shutdown,
        _links: links,
    }
}

fn note() -> PutOptions {
    PutOptions {
        type_id: TypeId {
            name: n("/types/note"),
            revision: 1,
        },
        keep: Keep::Forever,
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

/// Alice keeps a notebook and writes its cover; her laptop makes an offer
/// of it as a writer.
async fn offered(laptop: &Embedded) -> ndn_data::Code {
    offered_in(laptop, "/alice", FOLDER).await
}

/// `person`'s `folder`, shared with `person` alone and with a cover written
/// into it: an offer of it as a writer, made by `laptop`.
async fn offered_in(laptop: &Embedded, person: &str, folder: &str) -> ndn_data::Code {
    let folder = n(folder);
    laptop
        .device
        .share_folder(
            &folder,
            Sharing::Whole(Share {
                rule: Rule::Log,
                writers: vec![n(person)],
                readers: vec![Audience::Person(n(person))],
            }),
        )
        .await
        .unwrap();
    laptop
        .device
        .put(
            &folder.clone().append("cover"),
            text(&format!("cover by {}", person.trim_start_matches('/'))),
            note(),
        )
        .await
        .unwrap();
    laptop
        .device
        .offer(
            &folder,
            Offer {
                role: Role::Writer,
                until: Timestamp(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
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

/// The link hint `code` carries.
fn hint_of(code: &ndn_data::Code) -> Option<LinkHint> {
    let Ok(TrustEnvelope::Intro(intro)) = TrustEnvelope::from_uri(&code.link) else {
        panic!("an introduction link");
    };
    intro
        .link_hint
        .map(|bytes| LinkHint::decode(&bytes, true).unwrap())
}

/// `code`'s link with its hint replaced by `hint`.
fn with_hint(code: &ndn_data::Code, hint: &LinkHint) -> String {
    let Ok(TrustEnvelope::Intro(mut intro)) = TrustEnvelope::from_uri(&code.link) else {
        panic!("an introduction link");
    };
    intro.link_hint = Some(hint.encode());
    TrustEnvelope::Intro(intro).to_uri()
}

/// Join with `link` as a host does what `NotReady` says — joins again with
/// the same code — until `limit` has passed.
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

/// The keys `on` is linked to now.
fn linked_keys(on: &Links) -> Vec<KeyFingerprint> {
    on.report().links.iter().filter_map(|l| l.key).collect()
}

/// The prefixes (sorted, as text) `on`'s forwarder routes over its link to
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
        ._engine
        .fib()
        .dump()
        .into_iter()
        .filter(|(_, e)| e.nexthops.iter().any(|h| faces.contains(&h.face_id)))
        .map(|(prefix, _)| prefix.to_string())
        .collect();
    out.sort();
    out
}

/// The prefixes `on`'s forwarder routes over any link of `on.links`.
fn routed_over_any(on: &Embedded) -> Vec<String> {
    let mut out = Vec::new();
    for key in linked_keys(&on.links) {
        out.extend(routed_over(on, key));
    }
    out
}

/// An address nothing answers at: a socket bound and never read.
fn silent() -> (UdpSocket, SocketAddr) {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    (socket, addr)
}

/// An embedded joiner with only the code — no daemon, no route, no peer
/// entry — joins a daemonless inviter by dialling the key and addresses the
/// code carries, and reads what the inviter wrote. The two are devices of two
/// people: the inviter links with the one it introduced as the serving
/// policy it chose says (here: open, within quotas).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_embedded_joiner_with_only_the_code_dials_the_inviter_by_key_and_joins() {
    let alice = Person::new("/alice").await;
    let bob = Person::new("/bob").await;
    let laptop = embedded(&alice, "/alice/member/laptop", Setup::listening()).await;
    let phone = embedded(&bob, "/bob/member/phone", Setup::default()).await;
    let code = offered(&laptop).await;

    // The code carries the inviter's key and address, within one QR.
    assert!(code.link.len() <= ndn_trust_envelope::qr::MAX_TEXT_LEN);
    let hint = hint_of(&code).expect("the code carries a link hint");
    assert_eq!(hint.key, laptop.key.0);
    assert!(
        hint.candidates.iter().any(|c| Some(c.addr) == laptop.addr),
        "the hint offers the inviter's socket: {:?}",
        hint.candidates
    );

    // Bob's device knows no route to Alice's, and no peer. A host does what
    // `NotReady` says and joins again with the same code.
    let joined = joins(&phone, &code.link, Duration::from_secs(90))
        .await
        .unwrap_or_else(|e| {
            panic!(
                "the join failed: {e} ({:?})\nbob: {:#?}\nalice: {:#?}",
                e.next(),
                phone.links.report(),
                laptop.links.report()
            )
        });
    assert_eq!(
        joined,
        Joined {
            folder: n(FOLDER),
            role: Role::Writer,
            inviter: n("/alice"),
        }
    );

    // The link between them was made again as a full link: the folder syncs.
    let cover = n(&format!("{FOLDER}/cover"));
    until(
        "bob reads alice's cover",
        Duration::from_secs(60),
        async || reads(&phone.device, &cover, "cover by alice").await,
    )
    .await;
    let alice_knows_bob = laptop
        .links
        .report()
        .links
        .iter()
        .any(|l| l.key == Some(phone.key) && l.device.is_some());
    assert!(
        alice_knows_bob,
        "alice's link to bob's key is a full link, by his certificate: {:#?}",
        laptop.links.report()
    );
}

/// The compact link carries at most `IntroPolicy::code_candidates` candidates
/// of a host's hint: 3 by default, however many the host has, the most
/// promising first. (A short code names one first contact.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_code_carries_at_most_the_policys_candidates_of_a_hint() {
    let alice = Person::new("/alice").await;
    let laptop = embedded(
        &alice,
        "/alice/member/laptop",
        Setup {
            hint: HintMode::Full,
            ..Setup::listening()
        },
    )
    .await;
    let code = offered(&laptop).await;
    let hint = hint_of(&code).expect("a hint");
    assert_eq!(
        hint.candidates.len(),
        IntroPolicy::new().code_candidates,
        "{:?}",
        hint.candidates
    );
    assert_eq!(hint.key, laptop.key.0);
}

/// A code with a full hint — the most candidates, IPv6 (the longest) — is
/// still one QR, carries the hint whole, and joins: the candidates nothing
/// answers at are tried and left, the one that does is the link.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_code_with_a_full_hint_is_one_qr_and_joins_past_the_dead_candidates() {
    let max = ndn_trust_envelope::qr::MAX_TEXT_LEN;
    let alice = Person::new("/alice").await;
    let bob = Person::new("/bob").await;
    let bare = embedded(
        &alice,
        "/alice/member/laptop",
        Setup {
            hint: HintMode::Nothing,
            ..Setup::listening()
        },
    )
    .await;
    let without = offered(&bare).await.link.len();
    let plain = embedded(&alice, "/alice/member/desktop", Setup::listening()).await;
    let with_one = offered(&plain).await.link.len();
    drop((bare, plain));

    // The compact link carries at most `IntroPolicy::code_candidates` of the
    // hint (3 by default, SHAPES-R10 §5): this case is about a code with the
    // most a hint can hold, so the policy lifts the cap to it.
    let laptop = embedded(
        &alice,
        "/alice/member/tablet",
        Setup {
            hint: HintMode::Full,
            code_candidates: Some(LINK_HINT_CANDIDATES_MAX),
            ..Setup::listening()
        },
    )
    .await;
    let phone = embedded(&bob, "/bob/member/phone", Setup::default()).await;
    let code = offered(&laptop).await;
    let hint = hint_of(&code).expect("a hint");
    assert_eq!(hint.candidates.len(), LINK_HINT_CANDIDATES_MAX);
    assert!(
        hint.candidates.iter().any(|c| c.addr.is_ipv6())
            && hint.candidates.iter().any(|c| Some(c.addr) == laptop.addr),
        "the hint is full of IPv6 candidates and holds the real address: {:?}",
        hint.candidates
    );
    assert!(code.link.len() <= max, "{} octets", code.link.len());
    eprintln!(
        "code size: {without} characters without a link hint, {with_one} with the hint of one \
         loopback candidate, {} with a full hint of {} candidates (a QR holds {max})",
        code.link.len(),
        hint.candidates.len()
    );
    assert!(without < code.link.len());

    let joined = joins(&phone, &code.link, Duration::from_secs(90))
        .await
        .unwrap_or_else(|e| {
            panic!(
                "the join failed: {e}\nbob: {:#?}\nalice: {:#?}",
                phone.links.report(),
                laptop.links.report()
            )
        });
    assert_eq!(joined.folder, n(FOLDER));
}

/// The key a hint names is checked by the handshake, whatever answers at an
/// address: a device presenting another key is no link, and the dial goes on
/// to the address of the device that holds the key.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hint_address_answered_by_another_key_is_no_link_and_the_next_candidate_links() {
    let alice = Person::new("/alice").await;
    let bob = Person::new("/bob").await;
    let carol = Person::new("/carol").await;
    let laptop = embedded(&alice, "/alice/member/laptop", Setup::listening()).await;
    let impostor = embedded(&carol, "/carol/member/laptop", Setup::listening()).await;
    let phone = embedded(&bob, "/bob/member/phone", Setup::default()).await;
    let (_dead, dead) = silent();
    // An offer open: the inviter takes the stranger's introduction link.
    let _code = offered(&laptop).await;

    // The wrong party first, then an address nothing answers at, then the
    // inviter: the joiner keeps the one that proves the key.
    phone
        .links
        .dial_by_key(
            laptop.key,
            n("/alice/member/laptop"),
            vec![impostor.addr.unwrap(), dead, laptop.addr.unwrap()],
            Duration::from_secs(10),
            introduction_prefixes(&n("/alice/member/laptop")).into(),
        )
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
        linked_keys(&phone.links),
        [laptop.key],
        "bob is linked to the key the hint names, and to no other: {:#?}",
        phone.links.report()
    );
    assert!(
        !linked_keys(&impostor.links).contains(&phone.key),
        "the wrong party has no link from bob: {:#?}",
        impostor.links.report()
    );
}

/// An attacker who substitutes the addresses of a code can only make the dial
/// fail: the wrong parties at them fail the key check, no link is made, and
/// the dial says which address failed and how (within the time it was
/// given).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn substituted_addresses_make_the_dial_fail_and_nothing_else() {
    let alice = Person::new("/alice").await;
    let bob = Person::new("/bob").await;
    let carol = Person::new("/carol").await;
    let laptop = embedded(&alice, "/alice/member/laptop", Setup::listening()).await;
    let impostor = embedded(&carol, "/carol/member/laptop", Setup::listening()).await;
    let phone = embedded(&bob, "/bob/member/phone", Setup::default()).await;
    let (_dead, dead) = silent();

    let started = Instant::now();
    let refused = phone
        .links
        .dial_by_key(
            laptop.key,
            n("/alice/member/laptop"),
            vec![impostor.addr.unwrap(), dead],
            Duration::from_secs(3),
            introduction_prefixes(&n("/alice/member/laptop")).into(),
        )
        .await
        .expect_err("no address holds the key");
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "the dial is bounded"
    );
    assert!(
        refused.text.contains(&impostor.addr.unwrap().to_string()),
        "the failure names the address that answered with another key: {}",
        refused.text
    );
    assert!(
        linked_keys(&phone.links).is_empty(),
        "{:#?}",
        phone.links.report()
    );
    // The wrong party got a handshake it could not finish, and no link.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        linked_keys(&impostor.links).is_empty(),
        "{:#?}",
        impostor.links.report()
    );

    // The same through a join: substituted addresses and no relay hint leave
    // the join where it would be without a hint — unreachable, and not
    // forged: nothing is adopted, nothing answered.
    let code = offered(&laptop).await;
    let hint = hint_of(&code).unwrap();
    let altered = LinkHint {
        key: hint.key,
        candidates: vec![
            HintCandidate {
                kind: HintKind::Host,
                addr: impostor.addr.unwrap(),
            },
            HintCandidate {
                kind: HintKind::Host,
                addr: dead,
            },
        ],
    };
    let err = phone
        .device
        .join(&with_hint(&code, &altered))
        .await
        .expect_err("an address of nobody's reaches no one");
    assert_eq!(err.next(), NextStep::RetryLater, "{err}");
    assert!(
        phone.validator.keyring().held(&alice.ns).is_none(),
        "nothing of the inviter was adopted"
    );
    assert!(linked_keys(&phone.links).is_empty());
}

/// A code altered to name another key reaches that key's holder, which is no
/// inviter: the dial links to it (the key is the one the code now names), but
/// it answers nothing of the offer and the join proves nothing and adopts
/// nothing. No secret was sent: the ask, the only place it travels, is sent
/// after the offer is read. The join having failed, its dial is taken down:
/// bob keeps no link to the party that answered nothing, and no route over
/// one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_code_altered_to_name_another_key_reaches_a_party_that_answers_nothing() {
    let alice = Person::new("/alice").await;
    let bob = Person::new("/bob").await;
    let carol = Person::new("/carol").await;
    let laptop = embedded(&alice, "/alice/member/laptop", Setup::listening()).await;
    let impostor = embedded(&carol, "/carol/member/laptop", Setup::listening()).await;
    // The impostor has an offer of its own open, so it takes introduction
    // links from strangers.
    let _own = offered_in(&impostor, "/carol", "/carol/32=data/notebook").await;
    let phone = embedded(&bob, "/bob/member/phone", Setup::default()).await;
    let code = offered(&laptop).await;
    let altered = LinkHint {
        key: impostor.key.0,
        candidates: vec![HintCandidate {
            kind: HintKind::Host,
            addr: impostor.addr.unwrap(),
        }],
    };

    let err = phone
        .device
        .join(&with_hint(&code, &altered))
        .await
        .expect_err("the party holding the key cannot answer the offer");
    assert_eq!(err.next(), NextStep::RetryLater, "{err}");
    assert!(
        phone.validator.keyring().held(&alice.ns).is_none(),
        "nothing of the inviter was adopted"
    );
    // The join failed: its dial is taken down, and the party that answered
    // nothing keeps no link from bob, nor a route over one.
    until(
        "the failed join's link is taken down",
        Duration::from_secs(10),
        async || !linked_keys(&phone.links).contains(&impostor.key),
    )
    .await;
    assert!(
        routed_over_any(&phone).is_empty(),
        "no route is left over a link of the failed join: {:#?}",
        phone.links.report()
    );
    // The true inviter was never reached and saw nothing of this.
    assert!(
        !linked_keys(&laptop.links).contains(&phone.key),
        "{:#?}",
        laptop.links.report()
    );
}

/// A link dialled by key routes what it was dialled for, and `undial_by_key`
/// takes it down: the hint's device name is a claim, not a route, until the
/// device shows a certificate this device holds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_link_dialled_by_key_routes_only_what_it_was_dialled_for_and_is_taken_down() {
    let alice = Person::new("/alice").await;
    let bob = Person::new("/bob").await;
    let laptop = embedded(&alice, "/alice/member/laptop", Setup::listening()).await;
    let phone = embedded(&bob, "/bob/member/phone", Setup::default()).await;
    let _code = offered(&laptop).await;
    let device = n("/alice/member/laptop");

    phone
        .links
        .dial_by_key(
            laptop.key,
            device.clone(),
            vec![laptop.addr.unwrap()],
            Duration::from_secs(10),
            introduction_prefixes(&device).into(),
        )
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let mut introduction: Vec<String> = introduction_prefixes(&device)
        .iter()
        .map(ToString::to_string)
        .collect();
    introduction.sort();
    assert_eq!(
        routed_over(&phone, laptop.key),
        introduction,
        "{:#?}",
        phone.links.report()
    );
    // The inviter took it as a stranger: no identity. Its side of the link
    // is registered a moment after the dial returns.
    until(
        "the inviter reports the link",
        Duration::from_secs(10),
        async || {
            laptop
                .links
                .report()
                .links
                .iter()
                .any(|l| l.key == Some(phone.key))
        },
    )
    .await;
    let seen = laptop
        .links
        .report()
        .links
        .into_iter()
        .find(|l| l.key == Some(phone.key))
        .expect("the inviter was linked");
    assert!(seen.device.is_none(), "{seen:#?}");

    phone
        .links
        .undial_by_key(laptop.key, "the join that dialled it failed");
    until(
        "the link is taken down",
        Duration::from_secs(10),
        async || !linked_keys(&phone.links).contains(&laptop.key),
    )
    .await;
}

/// The prefixes (sorted, as text) a link dialled for `device`'s introduction
/// routes.
fn introduction_routes(device: &Name) -> Vec<String> {
    let mut out: Vec<String> = introduction_prefixes(device)
        .iter()
        .map(ToString::to_string)
        .collect();
    out.sort();
    out
}

/// Whether `on`'s forwarder routes `name` over a link face: some prefix of
/// the name has a nexthop that is one of its links' faces.
fn routes_over_a_link(on: &Embedded, name: &Name) -> bool {
    let faces: Vec<_> = on
        .links
        .report()
        .links
        .iter()
        .flat_map(|l| l.paths.iter().map(|p| p.face))
        .collect();
    on._engine.fib().dump().into_iter().any(|(prefix, e)| {
        name.has_prefix(&prefix) && e.nexthops.iter().any(|h| faces.contains(&h.face_id))
    })
}

/// Whether `node` fetches `name` within a few seconds.
async fn fetches(node: &ndn_app::Node, name: Name) -> bool {
    matches!(
        tokio::time::timeout(Duration::from_secs(6), node.fetch(name)).await,
        Ok(Ok(_))
    )
}

/// A first contact has no key to expect: the party at the address is linked
/// by whatever key its handshake proves, the key is returned, and the link
/// routes exactly the introduction's prefixes — the offer's record crosses,
/// a name of the device outside them has no route over it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_first_contact_dial_links_a_key_the_code_did_not_name_and_routes_only_the_introduction() {
    let alice = Person::new("/alice").await;
    let bob = Person::new("/bob").await;
    let laptop = embedded(&alice, "/alice/member/laptop", Setup::listening()).await;
    let phone = embedded(&bob, "/bob/member/phone", Setup::default()).await;
    let code = offered(&laptop).await;
    let device = n("/alice/member/laptop");

    let proved = phone
        .links
        .dial_first(
            device.clone(),
            laptop.addr.unwrap(),
            Duration::from_secs(10),
            introduction_prefixes(&device).into(),
        )
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(proved, laptop.key, "the key the handshake proved");
    assert_eq!(
        routed_over(&phone, laptop.key),
        introduction_routes(&device),
        "exactly the introduction's prefixes: {:#?}",
        phone.links.report()
    );
    assert_eq!(routed_over_any(&phone), introduction_routes(&device));
    // Three: the held pieces, the ask, and the hint record's family.
    assert_eq!(routed_over(&phone, laptop.key).len(), 3);
    assert!(
        routed_over(&phone, laptop.key)
            .contains(&ndn_data::intro::hint_prefix(&device).to_string())
    );

    // What the prefixes name crosses; any other name of the device, and any
    // name at all outside them, has no route and no answer.
    let node = phone._engine.app_node(phone.cancel.child_token());
    let held = ndn_data::wire::held_name(&device, &code.offer);
    assert!(
        fetches(&node, held).await,
        "the offer's record crosses the first-contact link: {:#?}",
        laptop.links.report()
    );
    for outside in [
        device.clone().append("private"),
        ndn_data::wire::log_name(&device, Some(&n(FOLDER)), 1),
        n("/alice/32=data/notebook/cover"),
        n("/alice"),
    ] {
        assert!(
            !routes_over_a_link(&phone, &outside),
            "{outside} is routed over the first-contact link"
        );
        assert!(
            !fetches(&node, outside.clone()).await,
            "{outside} crossed the first-contact link"
        );
    }

    // The inviter took the joiner as a stranger.
    until(
        "the inviter reports the link",
        Duration::from_secs(10),
        async || linked_keys(&laptop.links).contains(&phone.key),
    )
    .await;
    let seen = laptop
        .links
        .report()
        .links
        .into_iter()
        .find(|l| l.key == Some(phone.key))
        .expect("the inviter was linked");
    assert!(seen.device.is_none(), "{seen:#?}");

    // The join that made it ends it, by the key the dial returned.
    phone
        .links
        .undial_by_key(proved, "the join that dialled it failed");
    until(
        "the link and its routes are taken down",
        Duration::from_secs(10),
        async || !linked_keys(&phone.links).contains(&laptop.key),
    )
    .await;
    assert!(routed_over_any(&phone).is_empty());
}

/// Whoever answers at a first contact's address is a stranger: another key
/// gets the same link, whatever device name the code claims, and it
/// carries nothing beyond the introduction's prefixes — not the names the
/// code claims, not the stranger's own.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stranger_at_a_first_contact_address_gets_the_introduction_prefixes_and_nothing_else() {
    let alice = Person::new("/alice").await;
    let bob = Person::new("/bob").await;
    let carol = Person::new("/carol").await;
    let laptop = embedded(&alice, "/alice/member/laptop", Setup::listening()).await;
    let impostor = embedded(&carol, "/carol/member/laptop", Setup::listening()).await;
    // The party takes strangers while it has an offer open.
    let _own = offered_in(&impostor, "/carol", "/carol/32=data/notebook").await;
    let phone = embedded(&bob, "/bob/member/phone", Setup::default()).await;
    let _code = offered(&laptop).await;
    let device = n("/alice/member/laptop");

    let proved = phone
        .links
        .dial_first(
            device.clone(),
            impostor.addr.unwrap(),
            Duration::from_secs(10),
            introduction_prefixes(&device).into(),
        )
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(proved, impostor.key, "the key of whoever answered");
    assert_ne!(proved, laptop.key);
    assert_eq!(
        routed_over(&phone, impostor.key),
        introduction_routes(&device),
        "{:#?}",
        phone.links.report()
    );
    assert_eq!(routed_over_any(&phone), introduction_routes(&device));
    let node = phone._engine.app_node(phone.cancel.child_token());
    for outside in [
        device.clone().append("private"),
        n("/carol/member/laptop"),
        n("/carol/32=data/notebook/cover"),
        n("/carol"),
    ] {
        assert!(
            !routes_over_a_link(&phone, &outside),
            "{outside} is routed over the stranger's link"
        );
        assert!(
            !fetches(&node, outside.clone()).await,
            "{outside} crossed the stranger's link"
        );
    }
    // The true inviter was never reached.
    assert!(
        !linked_keys(&laptop.links).contains(&phone.key),
        "{:#?}",
        laptop.links.report()
    );

    // Taken down by the key returned: no link and no route is left.
    phone
        .links
        .undial_by_key(proved, "the join that dialled it failed");
    until(
        "the stranger's link is taken down",
        Duration::from_secs(10),
        async || !linked_keys(&phone.links).contains(&impostor.key),
    )
    .await;
    assert!(routed_over_any(&phone).is_empty());
}

/// A first contact claiming a device of a namespace the dialler already
/// holds steers none of that namespace's names to whoever answers: the link
/// routes the introduction's prefixes it was dialled for, and the held
/// namespace's own names have no route over it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_first_contact_claiming_a_held_namespace_routes_none_of_its_names() {
    let alice = Person::new("/alice").await;
    let bob = Person::new("/bob").await;
    let laptop = embedded(&alice, "/alice/member/laptop", Setup::listening()).await;
    let phone = embedded(&bob, "/bob/member/phone", Setup::default()).await;
    let _code = offered(&laptop).await;
    let claimed = n("/bob/member/tablet");

    let proved = phone
        .links
        .dial_first(
            claimed.clone(),
            laptop.addr.unwrap(),
            Duration::from_secs(10),
            introduction_prefixes(&claimed).into(),
        )
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(proved, laptop.key);
    assert_eq!(
        routed_over_any(&phone),
        introduction_routes(&claimed),
        "{:#?}",
        phone.links.report()
    );
    for held in [claimed.clone(), n("/bob/member/tablet/anything"), n("/bob")] {
        assert!(
            !routes_over_a_link(&phone, &held),
            "{held} of a held namespace is routed over a first-contact link"
        );
    }
}

/// With no offer open a stranger gets no introduction link: it is refused as
/// any device nobody knows. With one open it does, and the link answers the
/// offer's record and nothing else the device holds by name: another log
/// entry of the inviter's, though served to its own members, is not carried.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_introduction_link_is_taken_only_while_an_offer_is_open_and_carries_only_the_offer() {
    let alice = Person::new("/alice").await;
    let bob = Person::new("/bob").await;
    let laptop = embedded(&alice, "/alice/member/laptop", Setup::listening()).await;
    let phone = embedded(&bob, "/bob/member/phone", Setup::default()).await;
    let device = n("/alice/member/laptop");
    let dial = || {
        phone.links.dial_by_key(
            laptop.key,
            device.clone(),
            vec![laptop.addr.unwrap()],
            Duration::from_secs(5),
            introduction_prefixes(&device).into(),
        )
    };

    // No offer: the laptop shares its folder but has made none.
    laptop
        .device
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
    let refused = dial()
        .await
        .expect_err("no offer is open: no stranger's link");
    assert!(
        !linked_keys(&laptop.links).contains(&phone.key),
        "{refused:?}\n{:#?}",
        laptop.links.report()
    );

    // An offer open: the stranger is taken, on an introduction link.
    let code = offered(&laptop).await;
    dial().await.unwrap_or_else(|e| panic!("{e:?}"));
    let node = phone._engine.app_node(phone.cancel.child_token());
    let offer = code.offer.clone();
    let held = |piece: &Name| ndn_data::wire::held_name(&device, piece);
    let fetched = |name: Name| {
        let node = &node;
        async move {
            matches!(
                tokio::time::timeout(Duration::from_secs(6), node.fetch(name)).await,
                Ok(Ok(_))
            )
        }
    };
    assert!(
        fetched(held(&offer)).await,
        "the offer's record is answered over the introduction link: {:#?}",
        laptop.links.report()
    );
    // The first entry of the laptop's own log: the record sharing the folder.
    let other = ndn_data::wire::log_name(&device, Some(&n(FOLDER)), 1);
    assert_ne!(other, offer);
    assert!(
        !fetched(held(&other)).await,
        "a held piece that is no offer was answered over the introduction link"
    );
}

/// When the code's hint reaches no one — its candidates are dead — the join
/// goes on at once as it would without a hint: by the relay the code names,
/// which the joiner has a link to and the inviter's namespace advertises.
/// Both devices are dial-only; neither is linked to the other directly.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_join_whose_hint_reaches_no_one_goes_on_by_the_relay_the_code_names() {
    // The relay's address goes into alice's trust context, its certificate
    // comes from alice: its keys and socket first.
    let relay_parts = Parts::new("/alice/node/relay", true);
    let alice = Person::advertising(
        "/alice",
        vec![AdvertisedRelay {
            device: relay_parts.name.clone(),
            key: None,
            endpoints: vec![relay_parts.addr.unwrap().to_string()],
            preference: 0,
        }],
    )
    .await;
    let bob = Person::new("/bob").await;
    let relay = relay(&alice, &[&bob], relay_parts).await;
    let (_dead, dead) = silent();

    // Alice's laptop uses the relay its namespace advertises; its hint
    // offers an address nothing answers at.
    let laptop = embedded(
        &alice,
        "/alice/member/laptop",
        Setup {
            hint: HintMode::At(vec![dead]),
            ..Setup::default()
        },
    )
    .await;
    // Bob's phone uses the relay its person added.
    let phone = embedded(
        &bob,
        "/bob/member/phone",
        Setup {
            peers: vec![PeerSpec {
                label: "relay".into(),
                device: Some(relay.name.clone()),
                key: Some(relay.key),
                endpoints: vec![relay.addr.to_string()],
                persistent: true,
                relay_use: Some(RelayUse {
                    source: RelaySource::User,
                    preference: 0,
                }),
                ..PeerSpec::default()
            }],
            ..Setup::default()
        },
    )
    .await;
    let code = offered(&laptop).await;

    let hint = hint_of(&code).expect("the code carries a link hint");
    assert_eq!(hint.candidates.len(), 1);
    assert_eq!(hint.candidates[0].addr, dead);
    let Ok(TrustEnvelope::Intro(intro)) = TrustEnvelope::from_uri(&code.link) else {
        panic!("an introduction link");
    };
    assert_eq!(
        intro.relays,
        [relay.name.to_string()],
        "the code names the relay alice's namespace advertises"
    );

    let joined = joins(&phone, &code.link, Duration::from_secs(90))
        .await
        .unwrap_or_else(|e| {
            panic!(
                "the join failed: {e} ({:?})\nbob: {:#?}\nalice: {:#?}",
                e.next(),
                phone.links.report(),
                laptop.links.report()
            )
        });
    assert_eq!(joined.folder, n(FOLDER));
    assert!(
        !linked_keys(&phone.links).contains(&laptop.key),
        "the dead hint made no link: {:#?}",
        phone.links.report()
    );
    assert!(
        phone
            .links
            .report()
            .links
            .iter()
            .any(|l| l.key == Some(relay.key) && l.paths.iter().any(|p| p.kind == PathKind::Link)),
        "bob reached alice through the relay: {:#?}",
        phone.links.report()
    );
}

/// The short code of `code`: what `Device::offer` made for a host that gives a
/// first contact, or the reason it made none.
fn short_of(code: &ndn_data::Code) -> String {
    code.short.clone().unwrap_or_else(|| {
        panic!(
            "no short code was made: {}",
            code.short_why.as_deref().unwrap_or("no reason given")
        )
    })
}

/// G4, by an address: an embedded joiner holding only the short code — no
/// daemon, no route, no peer entry — against a daemonless inviter. The code
/// names an address and no key; the joiner dials it with none to expect,
/// fetches the hint record over that link, verifies it against the code, and
/// joins; the link is made again as a full link and the folder syncs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_short_code_over_a_direct_address_joins_an_embedded_joiner_with_no_route() {
    let alice = Person::new("/alice").await;
    let bob = Person::new("/bob").await;
    let laptop = embedded(&alice, "/alice/member/laptop", Setup::listening()).await;
    let phone = embedded(&bob, "/bob/member/phone", Setup::default()).await;
    let code = offered(&laptop).await;

    let short = short_of(&code);
    assert_eq!(code.share(), short, "a short code is what is shared");
    assert!(short.len() < code.link.len(), "{short}");
    assert!(
        short.contains(&laptop.addr.unwrap().to_string()),
        "the code names the inviter's address: {short}"
    );
    assert!(
        !short.contains(&format!("{}", laptop.key)),
        "the code names no key: {short}"
    );
    assert!(
        phone.links.report().links.is_empty() && routed_over_any(&phone).is_empty(),
        "bob starts with no link and no route"
    );

    let joined = joins(&phone, &short, Duration::from_secs(90))
        .await
        .unwrap_or_else(|e| {
            panic!(
                "the join failed: {e} ({:?})\nbob: {:#?}\nalice: {:#?}",
                e.next(),
                phone.links.report(),
                laptop.links.report()
            )
        });
    assert_eq!(
        joined,
        Joined {
            folder: n(FOLDER),
            role: Role::Writer,
            inviter: n("/alice"),
        }
    );
    let cover = n(&format!("{FOLDER}/cover"));
    until(
        "bob reads alice's cover",
        Duration::from_secs(60),
        async || reads(&phone.device, &cover, "cover by alice").await,
    )
    .await;
    assert!(
        laptop
            .links
            .report()
            .links
            .iter()
            .any(|l| l.key == Some(phone.key) && l.device.is_some()),
        "alice's link to bob's key is a full link, by his certificate: {:#?}",
        laptop.links.report()
    );
}

/// A relay of alice's namespace, which her namespace advertises, with her
/// dial-only laptop (no link hint: its code's first contact is that relay)
/// and bob's dial-only phone, which uses the relay: neither is linked to the
/// other.
struct Relayed {
    alice: Person,
    relay: Relay,
    laptop: Embedded,
    phone: Embedded,
}

async fn relayed() -> Relayed {
    relayed_with(HintMode::Nothing).await
}

/// [`relayed`], the inviter's codes carrying the link hint `hint`.
async fn relayed_with(hint: HintMode) -> Relayed {
    let relay_parts = Parts::new("/alice/node/relay", true);
    let alice = Person::advertising(
        "/alice",
        vec![AdvertisedRelay {
            device: relay_parts.name.clone(),
            key: None,
            endpoints: vec![relay_parts.addr.unwrap().to_string()],
            preference: 0,
        }],
    )
    .await;
    let bob = Person::new("/bob").await;
    let relay = relay(&alice, &[&bob], relay_parts).await;
    let laptop = embedded(
        &alice,
        "/alice/member/laptop",
        Setup {
            hint,
            ..Setup::default()
        },
    )
    .await;
    let phone = embedded(
        &bob,
        "/bob/member/phone",
        Setup {
            peers: vec![PeerSpec {
                label: "relay".into(),
                device: Some(relay.name.clone()),
                key: Some(relay.key),
                endpoints: vec![relay.addr.to_string()],
                persistent: true,
                relay_use: Some(RelayUse {
                    source: RelaySource::User,
                    preference: 0,
                }),
                ..PeerSpec::default()
            }],
            ..Setup::default()
        },
    )
    .await;
    Relayed {
        alice,
        relay,
        laptop,
        phone,
    }
}

/// G4, by a relay: the inviter is dial-only and its code carries a relay of
/// its namespace for a first contact (no address: its hint is empty). The
/// joiner has no link to the inviter and none by an address: the hint record
/// is fetched by name through the relay it uses, and the join goes on
/// through it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_short_code_over_a_relay_first_contact_joins_through_the_relay() {
    let Relayed {
        alice: _alice,
        relay,
        laptop,
        phone,
    } = relayed().await;
    let code = offered(&laptop).await;

    let short = short_of(&code);
    assert!(
        short.contains(&relay.name.to_string()),
        "the code names the relay alice's namespace advertises: {short}"
    );
    assert!(
        hint_of(&code).is_none(),
        "the inviter gives no link hint: nothing to dial"
    );

    let joined = joins(&phone, &short, Duration::from_secs(90))
        .await
        .unwrap_or_else(|e| {
            panic!(
                "the join failed: {e} ({:?})\nbob: {:#?}\nalice: {:#?}",
                e.next(),
                phone.links.report(),
                laptop.links.report()
            )
        });
    assert_eq!(joined.folder, n(FOLDER));
    assert!(
        !linked_keys(&phone.links).contains(&laptop.key),
        "no link to the inviter was made: {:#?}",
        phone.links.report()
    );
    assert!(
        phone
            .links
            .report()
            .links
            .iter()
            .any(|l| l.key == Some(relay.key) && l.paths.iter().any(|p| p.kind == PathKind::Link)),
        "bob reached alice through the relay: {:#?}",
        phone.links.report()
    );
}

/// A first-contact address that names this machine or its link is an address
/// a code must not make this device dial, unless its policy says
/// `local_candidates`: the join is refused before any dial, says so, and
/// nothing was dialled, adopted or sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_loopback_first_contact_is_refused_unless_the_policy_allows_local_candidates() {
    let alice = Person::new("/alice").await;
    let bob = Person::new("/bob").await;
    let laptop = embedded(&alice, "/alice/member/laptop", Setup::listening()).await;
    let refusing = embedded(
        &bob,
        "/bob/member/phone",
        Setup {
            refuse_local: true,
            ..Setup::default()
        },
    )
    .await;
    let accepting = embedded(&bob, "/bob/member/tablet", Setup::default()).await;
    let code = offered(&laptop).await;
    let short = short_of(&code);
    assert!(
        laptop.addr.is_some_and(|a| a.ip().is_loopback()) && short.contains("127.0.0.1"),
        "the first contact is a loopback address: {short}"
    );

    let err = refusing
        .device
        .join(&short)
        .await
        .expect_err("a loopback first contact is not dialled by this policy");
    assert_ne!(err.next(), NextStep::RetryLater, "{err}");
    assert!(
        err.to_string().contains("local_candidates"),
        "the refusal says which policy to change: {err}"
    );
    assert!(
        refusing.links.report().links.is_empty(),
        "nothing was dialled: {:#?}",
        refusing.links.report()
    );
    assert!(refusing.validator.keyring().held(&alice.ns).is_none());
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !linked_keys(&laptop.links).contains(&refusing.key),
        "{:#?}",
        laptop.links.report()
    );

    // The same code, to a device whose policy allows local candidates, joins:
    // it was the policy, not the code.
    let joined = joins(&accepting, &short, Duration::from_secs(90))
        .await
        .unwrap_or_else(|e| panic!("the join failed: {e} ({:?})", e.next()));
    assert_eq!(joined.folder, n(FOLDER));
}

/// A source that lists these addresses on the socket's port as host
/// candidates, in this order: what a host's interfaces give in the system's
/// order, the loopback first.
struct Listed(&'static [&'static str]);

impl CandidateSource for Listed {
    fn candidates(&self, local: SocketAddr) -> Vec<Candidate> {
        self.0
            .iter()
            .map(|ip| Candidate {
                kind: CandidateKind::Host,
                addr: SocketAddr::new(ip.parse().unwrap(), local.port()),
            })
            .collect()
    }
}

/// The short code carries the one address of the hint's order, so the order
/// of the host's candidates decides whether another computer can dial it:
/// the host's sources list the loopback before its LAN address, and the
/// hint, and so the code, still says the LAN address first, with
/// `local_candidates` on or off.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_short_code_names_an_address_another_computer_reaches_when_the_host_lists_the_loopback_first()
 {
    for refuse_local in [false, true] {
        let alice = Person::new("/alice").await;
        let laptop = embedded(
            &alice,
            "/alice/member/laptop",
            Setup {
                listen: true,
                refuse_local,
                candidates: Some(vec![Arc::new(Listed(&["127.0.0.1", "10.77.0.5"]))]),
                ..Setup::default()
            },
        )
        .await;
        let code = offered(&laptop).await;
        let port = laptop.addr.unwrap().port();
        let short = short_of(&code);
        assert!(
            short.contains(&format!("10.77.0.5:{port}")) && !short.contains("127.0.0.1"),
            "local_candidates {}: the code names the loopback: {short}",
            !refuse_local
        );
        let hint = hint_of(&code).expect("a hint");
        assert_eq!(
            hint.candidates
                .iter()
                .map(|c| c.addr.to_string())
                .collect::<Vec<_>>(),
            [format!("10.77.0.5:{port}"), format!("127.0.0.1:{port}")],
            "the hint lists the address another computer reaches first"
        );
    }
}

const CABLE_ROLE: &str = "NDN_LINK_CABLE_ROLE";
const CABLE_CODE: &str = "NDN_LINK_CABLE_CODE";
const CABLE_TEST: &str = "a_short_code_joins_across_two_network_namespaces_joined_by_a_cable";
const UNSHARE: [&str; 6] = [
    "--map-root-user",
    "--net",
    "--pid",
    "--fork",
    "--kill-child",
    "--mount-proc",
];

/// A child process, killed and reaped when this goes.
struct Kill(std::process::Child);

impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Run `argv` to its end; its failure is a panic that says what it said.
fn run(argv: &[String]) {
    let out = std::process::Command::new(&argv[0])
        .args(&argv[1..])
        .output()
        .unwrap_or_else(|e| panic!("{argv:?}: {e}"));
    assert!(
        out.status.success(),
        "{argv:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn words(argv: &[&str]) -> Vec<String> {
    argv.iter().map(|s| (*s).to_owned()).collect()
}

fn cable_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap()
}

/// The shape of ndf's scenario F4: Ann's laptop at 10.1.0.1 and Bob's at
/// 10.9.0.2 in two network namespaces joined by a cable (a veth pair), and
/// each with the loopback up as a host has it; Ann's also with a container
/// bridge, `docker0`, which the system lists before her LAN address. Ann
/// invites Bob, with `local_candidates` on, and he joins by the short code
/// alone: the code's one address is hers on the cable.
///
/// One test binary plays four parts, by `NDN_LINK_CABLE_ROLE`: the test
/// itself (re-run under `unshare`, a user, network and PID namespace of its
/// own so that nothing of the host's network is touched and no process
/// outlives it), the cable (builds the namespaces and runs the two hosts),
/// Ann and Bob. Skipped, saying why, where the machine has no unprivileged
/// user namespaces or lacks `ip` or `nsenter`.
#[test]
fn a_short_code_joins_across_two_network_namespaces_joined_by_a_cable() {
    match std::env::var(CABLE_ROLE).as_deref() {
        Ok("cable") => cable(),
        Ok("ann") => cable_runtime().block_on(cable_ann()),
        Ok("bob") => cable_runtime().block_on(cable_bob()),
        _ => cable_outside(),
    }
}

fn cable_outside() {
    let namespaces = std::process::Command::new("unshare")
        .args(UNSHARE)
        .arg("true")
        .output();
    if !namespaces.as_ref().is_ok_and(|o| o.status.success()) {
        eprintln!(
            "SKIPPED: `unshare {} true` does not work here ({namespaces:?}): the case needs \
             unprivileged user, network and PID namespaces",
            UNSHARE.join(" ")
        );
        return;
    }
    for tool in ["ip", "nsenter"] {
        if std::process::Command::new(tool).arg("-V").output().is_err() {
            eprintln!("SKIPPED: `{tool}` is not on PATH (iproute2 and util-linux are needed)");
            return;
        }
    }
    let exe = std::env::current_exe().unwrap();
    let out = std::process::Command::new("unshare")
        .args(UNSHARE)
        .arg("--")
        .arg(exe)
        .args(["--exact", CABLE_TEST, "--nocapture", "--test-threads=1"])
        .env(CABLE_ROLE, "cable")
        .stdin(std::process::Stdio::null())
        .output()
        .expect("unshare runs");
    // What the namespaces' side said (Ann's code, who joined): shown with
    // `--nocapture`, and the whole of it when the case fails.
    eprint!("{}", String::from_utf8_lossy(&out.stderr));
    assert!(
        out.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Inside the new namespaces: this one is Ann's, a held one is Bob's.
fn cable() {
    let exe = std::env::current_exe().unwrap();
    let holder = Kill(
        std::process::Command::new("unshare")
            .args(["--net", "--", "sleep", "infinity"])
            .spawn()
            .expect("a network namespace for Bob"),
    );
    let bob_ns = format!("/proc/{}/ns/net", holder.0.id());
    let ours = std::fs::read_link("/proc/self/ns/net").unwrap();
    let until = Instant::now() + Duration::from_secs(5);
    while std::fs::read_link(&bob_ns).map_or(true, |ns| ns == ours) {
        assert!(Instant::now() < until, "Bob's namespace did not appear");
        std::thread::sleep(Duration::from_millis(10));
    }
    let in_bob = |argv: &[&str]| {
        let mut all = words(&["nsenter", &format!("--net={bob_ns}"), "--"]);
        all.extend(words(argv));
        run(&all);
    };
    // Ann's host: the loopback, a container bridge (made first, so the
    // system lists it first), and her address on the cable.
    let bob_pid = holder.0.id().to_string();
    for argv in [
        &["ip", "link", "set", "lo", "up"][..],
        &["ip", "link", "add", "docker0", "type", "bridge"],
        &["ip", "addr", "add", "172.17.0.1/16", "dev", "docker0"],
        &["ip", "link", "set", "docker0", "up"],
        &[
            "ip", "link", "add", "name", "ann0", "type", "veth", "peer", "name", "bob0", "netns",
            &bob_pid,
        ],
        &["ip", "addr", "add", "10.1.0.1/24", "dev", "ann0"],
        &["ip", "link", "set", "ann0", "up"],
        &["ip", "route", "add", "10.9.0.0/24", "dev", "ann0"],
    ] {
        run(&words(argv));
    }
    for argv in [
        &["ip", "link", "set", "lo", "up"][..],
        &["ip", "addr", "add", "10.9.0.2/24", "dev", "bob0"],
        &["ip", "link", "set", "bob0", "up"],
        &["ip", "route", "add", "10.1.0.0/24", "dev", "bob0"],
    ] {
        in_bob(argv);
    }

    let mut ann = Kill(
        std::process::Command::new(&exe)
            .args(["--exact", CABLE_TEST, "--nocapture", "--test-threads=1"])
            .env(CABLE_ROLE, "ann")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("Ann starts"),
    );
    let stdout = ann.0.stdout.take().unwrap();
    let (lines, heard) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        use std::io::BufRead;
        for line in std::io::BufReader::new(stdout)
            .lines()
            .map_while(Result::ok)
        {
            if lines.send(line).is_err() {
                break;
            }
        }
    });
    let mut seen = Vec::new();
    let code = loop {
        match heard.recv_timeout(Duration::from_secs(60)) {
            Ok(line) => match line.strip_prefix("CODE ") {
                Some(code) => break code.to_owned(),
                None => seen.push(line),
            },
            Err(_) => panic!("Ann made no short code within 60 s, or ended: {seen:?}"),
        }
    };
    eprintln!("Ann's code: {code}");

    let mut bob = Kill(
        std::process::Command::new("nsenter")
            .arg(format!("--net={bob_ns}"))
            .arg("--")
            .arg(&exe)
            .args(["--exact", CABLE_TEST, "--nocapture", "--test-threads=1"])
            .env(CABLE_ROLE, "bob")
            .env(CABLE_CODE, &code)
            .stdin(std::process::Stdio::null())
            .spawn()
            .expect("Bob starts"),
    );
    let until = Instant::now() + Duration::from_secs(150);
    let status = loop {
        if let Some(status) = bob.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < until,
            "Bob did not end within 150 s (Ann's code: {code})"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    while let Ok(line) = heard.try_recv() {
        seen.push(line);
    }
    assert!(
        status.success(),
        "Bob did not join by the short code {code} ({status}); Ann said: {seen:?}"
    );
    assert!(
        code.contains("10.1.0.1:") && !code.contains("127.0.0.1") && !code.contains("172.17."),
        "the code names an address another computer cannot reach: {code}"
    );
}

/// Ann: her laptop listens on every address and offers the folder.
async fn cable_ann() {
    let alice = Person::new("/alice").await;
    let laptop = embedded(
        &alice,
        "/alice/member/laptop",
        Setup {
            listen: true,
            bind: Some("0.0.0.0:0".parse().unwrap()),
            ..Setup::default()
        },
    )
    .await;
    println!("CANDIDATES {:?}", laptop.links.hint_candidates());
    let code = offered(&laptop).await;
    println!("CODE {}", short_of(&code));
    std::future::pending::<()>().await;
}

/// Bob: a laptop that only dials, holding the short code.
async fn cable_bob() {
    let code = std::env::var(CABLE_CODE).expect("Ann's code");
    let bob = Person::new("/bob").await;
    let phone = embedded(&bob, "/bob/member/phone", Setup::default()).await;
    let joined = joins(&phone, &code, Duration::from_secs(45))
        .await
        .unwrap_or_else(|e| {
            panic!(
                "the join by {code} failed: {e} ({:?})\nbob: {:#?}",
                e.next(),
                phone.links.report()
            )
        });
    assert_eq!(
        joined,
        Joined {
            folder: n(FOLDER),
            role: Role::Writer,
            inviter: n("/alice"),
        }
    );
    let cover = n(&format!("{FOLDER}/cover"));
    until(
        "bob reads alice's cover",
        Duration::from_secs(60),
        async || reads(&phone.device, &cover, "cover by alice").await,
    )
    .await;
}

/// The short code of `code`, read: its device, its secret, and so the token
/// of its hint record.
fn read_short(code: &ndn_data::Code) -> ShortCode {
    ShortCode::parse(&short_of(code), true).unwrap_or_else(|e| panic!("{e}"))
}

/// Whether `node` fetches `name` within a few seconds, with the forwarding
/// hint `via` (none: by name).
async fn fetches_via(node: &ndn_app::Node, name: Name, via: &[Name]) -> Option<ndn_packet::Data> {
    let mut interest = InterestBuilder::new(name).lifetime(Duration::from_secs(4));
    if !via.is_empty() {
        interest = interest.forwarding_hint(via.to_vec());
    }
    tokio::time::timeout(
        Duration::from_secs(6),
        Consumer::new(node.connection()).fetch_with(interest),
    )
    .await
    .ok()?
    .ok()
}

/// The hint record's name crosses an introduction link only through the
/// surface's `carries`: the record of a token of one of the inviter's own
/// offers does, and answers with the record naming the inviter's key; the
/// family's prefix, an unknown token and a name under a known one do not
/// cross and get no answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_hint_record_crosses_an_introduction_link_only_for_a_token_of_an_own_offer() {
    let alice = Person::new("/alice").await;
    let bob = Person::new("/bob").await;
    let laptop = embedded(&alice, "/alice/member/laptop", Setup::listening()).await;
    let phone = embedded(&bob, "/bob/member/phone", Setup::default()).await;
    let code = offered(&laptop).await;
    let short = read_short(&code);
    let device = short.device.clone();
    let token = hint_token(&short.secret);

    phone
        .links
        .dial_first(
            device.clone(),
            laptop.addr.unwrap(),
            Duration::from_secs(10),
            introduction_prefixes(&device).into(),
        )
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let node = phone._engine.app_node(phone.cancel.child_token());

    let record = fetches_via(&node, hint_name(&device, &token), &[])
        .await
        .unwrap_or_else(|| panic!("the hint record crosses: {:#?}", laptop.links.report()));
    let content = record.content().expect("a hint record has content").clone();
    match HintRecord::decode(content, true).unwrap_or_else(|e| panic!("{e}")) {
        HintRecord::Offered { key, offer, .. } => {
            assert_eq!(key, laptop.key.0, "the record names the inviter's key");
            assert_eq!(offer, code.offer, "and the offer it is bound to");
        }
        other => panic!("an open offer's record, not {other:?}"),
    }

    for (what, name) in [
        ("an unknown token", hint_name(&device, &[7; 16])),
        ("the family's prefix", hint_prefix(&device)),
        (
            "a name under a known token",
            hint_name(&device, &token).append("more"),
        ),
    ] {
        assert!(
            fetches_via(&node, name.clone(), &[]).await.is_none(),
            "{what} ({name}) crossed the introduction link"
        );
    }
}

/// The hint record crosses a relay hop as the offer fetch does: an Interest
/// that names the relay as its forwarding hint reaches the dial-only
/// inviter through the relay, which has no link to the joiner for it; an
/// unknown token reaches no answer by the same way.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_hint_record_crosses_a_relay_hop_as_the_offer_fetch_does() {
    let Relayed {
        alice: _alice,
        relay,
        laptop,
        phone,
    } = relayed().await;
    let code = offered(&laptop).await;
    let short = read_short(&code);
    let device = short.device.clone();
    let node = phone._engine.app_node(phone.cancel.child_token());
    let via = [relay.name.clone()];

    // The offer's record, by the route the relay fallback uses today.
    let held = ndn_data::wire::held_name(&device, &code.offer);
    let until_up = Instant::now();
    let mut offer_record = None;
    while offer_record.is_none() && until_up.elapsed() < Duration::from_secs(60) {
        offer_record = fetches_via(&node, held.clone(), &via).await;
    }
    assert!(
        offer_record.is_some(),
        "the offer's record crosses the relay: {:#?}",
        phone.links.report()
    );

    let token = hint_token(&short.secret);
    let record = fetches_via(&node, hint_name(&device, &token), &via).await;
    assert!(
        record.is_some(),
        "the hint record crosses the relay hop: {:#?}",
        phone.links.report()
    );
    assert!(
        fetches_via(&node, hint_name(&device, &[7; 16]), &via)
            .await
            .is_none(),
        "an unknown token got an answer through the relay"
    );
}

/// A surface for a party that is no data-layer device: open, and carrying
/// every name asked of it, as a hostile program on the address would.
struct CarriesAll;

impl Introductions for CarriesAll {
    fn open(&self) -> bool {
        true
    }
    fn carries(&self, _: &Name) -> bool {
        true
    }
    fn grant_carries(&self, _: &Name, _: &Name) -> bool {
        false
    }
    fn departure_carries(&self, _: &Name, _: &Name) -> bool {
        false
    }
}

/// A short code's first contact is only a hint: a stranger at the address
/// serves a forged hint record — well formed, bound to the real offer, naming
/// its own key and address — and the join refuses it before any dial, ask
/// or adoption, whichever way it is forged: signed by a key of no namespace
/// the code names with no credentials, or with a real person's credentials
/// of another anchor.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stranger_at_the_first_contact_serving_a_forged_hint_record_is_refused_and_nothing_is_adopted()
 {
    let alice = Person::new("/alice").await;
    let bob = Person::new("/bob").await;
    let carol = Person::new("/carol").await;
    let laptop = embedded(&alice, "/alice/member/laptop", Setup::listening()).await;
    let code = offered(&laptop).await;
    let real = read_short(&code);
    let device = real.device.clone();
    let token = hint_token(&real.secret);

    for forged_with_credentials in [false, true] {
        // The stranger: its own keys, a real device of carol's, listening.
        let parts = Parts::new("/carol/member/laptop", true);
        let signer = parts.keys.get_signer_sync(&parts.key_name).unwrap();
        let cert = parts.certified(&carol).await;
        let (key, at) = (parts.fingerprint, parts.addr.unwrap());
        let stranger = embedded_of(&carol, parts, Setup::listening()).await;
        stranger.links.set_introductions(Arc::new(CarriesAll));
        let record = HintRecord::Offered {
            offer: code.offer.clone(),
            key: key.0,
            candidates: vec![HintCandidate {
                kind: HintKind::Host,
                addr: at,
            }],
            relays: Vec::new(),
            until: Timestamp(u64::MAX / 4),
            credentials: if forged_with_credentials {
                vec![carol.signed.clone(), cert.data_wire().unwrap()]
            } else {
                Vec::new()
            },
        }
        .encode();
        let node = stranger._engine.app_node(stranger.cancel.child_token());
        let name = hint_name(&device, &token);
        let _serving = node
            .serve(hint_prefix(&device), move |interest, responder| {
                let (record, signer) = (record.clone(), Arc::clone(&signer));
                async move {
                    let wire = DataBuilder::new((*interest.name).clone(), record.as_ref())
                        .sign_sync(signer.sig_type(), Some(signer.key_name()), |region| {
                            signer.sign_sync(region).unwrap()
                        });
                    let _ = responder.respond_bytes(wire).await;
                }
            })
            .await
            .unwrap();
        let phone = embedded(&bob, "/bob/member/phone", Setup::default()).await;

        // The code is the real one with its first contact replaced: the
        // checksum covers the address, so it is written again.
        let forged = ShortCode {
            contact: Some(Contact::Address(at)),
            ..real.clone()
        }
        .encode()
        .unwrap_or_else(|e| panic!("{e}"));
        let err = phone
            .device
            .join(&forged)
            .await
            .expect_err("a forged hint record must not be believed");
        let said = err.to_string();
        // No credentials: nothing proves the record, which a damaged packet
        // looks like (retry, and ask for a new code if it keeps failing).
        // A real person's credentials of another anchor: the record verifies
        // as that person's, and is not the inviter's — no damage in flight,
        // so no retry.
        let (proof, next) = if forged_with_credentials {
            ("not as the inviter this code names", NextStep::AskOwner)
        } else {
            ("does not prove it is the inviter's", NextStep::RetryLater)
        };
        assert!(
            said.contains(proof) && said.contains("new code") && err.next() == next,
            "(credentials {forged_with_credentials}) the refusal says why and what to do: {said} ({:?})",
            err.next()
        );
        assert!(
            phone.validator.keyring().held(&alice.ns).is_none()
                && phone.validator.keyring().held(&carol.ns).is_none(),
            "nothing was adopted"
        );
        // The record was asked for, so the stranger's link was made; the
        // refused join took it down and left no route.
        until(
            "the refused join's link is taken down",
            Duration::from_secs(10),
            async || !linked_keys(&phone.links).contains(&stranger.key),
        )
        .await;
        assert!(
            routed_over_any(&phone).is_empty(),
            "{name}: no route is left over the stranger's link: {:#?}",
            phone.links.report()
        );
        assert!(
            !linked_keys(&laptop.links).contains(&phone.key),
            "the true inviter was never reached: {:#?}",
            laptop.links.report()
        );
    }
}

// ---- a first contact: what it is shown, what it may send in, what outlives the join --------------

/// A party at an address that records the hello it is sent, then takes no one.
fn recording_party(parts: &Parts) -> tokio::task::JoinHandle<LinkHello> {
    let listener = Arc::clone(parts.socket.as_ref().expect("a party listens"));
    tokio::spawn(async move {
        let mut hs = listener.accept().await.unwrap().handshake().await.unwrap();
        let theirs = hs
            .exchange_hello(&LinkHello::default(), Duration::from_secs(10))
            .await
            .unwrap();
        hs.refuse(CloseReason::Unrecognized, "a test party that takes no one");
        theirs
    })
}

/// Whoever answers at a short code's address — a hostile code, an address
/// that was reassigned — is shown no certificate and no membership of the
/// joiner's: its hello is empty. A dial to a key it expected shows them (the
/// control: the same joiner, the same kind of party).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_first_contact_sends_the_party_at_the_address_no_certificate_and_no_membership() {
    let bob = Person::new("/bob").await;
    let phone = embedded(&bob, "/bob/member/phone", Setup::default()).await;
    let device = n("/alice/member/laptop");

    let parts = Parts::new("/carol/member/laptop", true);
    let party = recording_party(&parts);
    let _ = phone
        .links
        .dial_first(
            device.clone(),
            parts.addr.unwrap(),
            Duration::from_secs(10),
            introduction_prefixes(&device).into(),
        )
        .await;
    let theirs = party.await.unwrap();
    assert!(
        theirs.certificates.is_empty() && theirs.memberships.is_empty(),
        "the party at a first contact's address was sent the joiner's certificate or memberships: \
         {} certificates, {} memberships",
        theirs.certificates.len(),
        theirs.memberships.len()
    );

    let parts = Parts::new("/carol/member/tablet", true);
    let party = recording_party(&parts);
    let _ = phone
        .links
        .dial_by_key(
            parts.fingerprint,
            device.clone(),
            vec![parts.addr.unwrap()],
            Duration::from_secs(10),
            introduction_prefixes(&device).into(),
        )
        .await;
    let theirs = party.await.unwrap();
    assert!(
        !theirs.certificates.is_empty(),
        "a dial of a key the code names shows the joiner's certificate: the control sees none, so \
         the case above proves nothing"
    );
}

/// A joiner reaches an inviter that also admits enrollment links by a short
/// code's address: its hello is empty, which that inviter takes for an
/// enrollment link, and the link carries the open offer's introduction too, so
/// the join completes and the link made again is a full one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_short_code_joins_an_inviter_that_also_admits_enrollment_links() {
    let alice = Person::enrolling("/alice").await;
    let bob = Person::new("/bob").await;
    let laptop = embedded(&alice, "/alice/node/laptop", Setup::listening()).await;
    let phone = embedded(&bob, "/bob/member/phone", Setup::default()).await;
    let code = offered(&laptop).await;
    let short = short_of(&code);

    let joined = joins(&phone, &short, Duration::from_secs(90))
        .await
        .unwrap_or_else(|e| {
            panic!(
                "the join failed: {e} ({:?})\nbob: {:#?}\nalice: {:#?}",
                e.next(),
                phone.links.report(),
                laptop.links.report()
            )
        });
    assert_eq!(joined.folder, n(FOLDER));
    until(
        "alice's link to bob is a full link, by his certificate",
        Duration::from_secs(60),
        async || {
            laptop
                .links
                .report()
                .links
                .iter()
                .any(|l| l.key == Some(phone.key) && l.device.is_some())
        },
    )
    .await;
}

/// What the party at a first contact sends into the joiner: an Interest for a
/// name of the joiner's forwarder (another face serves it) is dropped, not
/// forwarded; one under the joiner's own device name is delivered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_party_at_a_first_contact_can_ask_the_joiner_for_its_own_names_only() {
    let bob = Person::new("/bob").await;
    let phone = embedded(&bob, "/bob/member/phone", Setup::default()).await;
    let device = n("/alice/member/laptop");
    let node = phone._engine.app_node(phone.cancel.child_token());
    let counting = |hits: &Arc<AtomicUsize>| {
        let hits = Arc::clone(hits);
        move |_interest, _responder| {
            let hits = Arc::clone(&hits);
            async move {
                hits.fetch_add(1, Ordering::SeqCst);
            }
        }
    };
    let (elsewhere, own) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let _elsewhere = node
        .serve(n("/carol/private"), counting(&elsewhere))
        .await
        .unwrap();
    let _own = node
        .serve(n("/bob/member/phone/32=probe"), counting(&own))
        .await
        .unwrap();

    let parts = Parts::new("/carol/member/laptop", true);
    let listener = Arc::clone(parts.socket.as_ref().unwrap());
    let party = tokio::spawn(async move {
        let mut hs = listener.accept().await.unwrap().handshake().await.unwrap();
        hs.exchange_hello(&LinkHello::default(), Duration::from_secs(10))
            .await
            .unwrap();
        hs.admit(
            ndn_transport::FaceId(9),
            Duration::from_secs(10),
            Admission::default(),
        )
        .await
        .unwrap()
    });
    phone
        .links
        .dial_first(
            device.clone(),
            parts.addr.unwrap(),
            Duration::from_secs(10),
            introduction_prefixes(&device).into(),
        )
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let link = party.await.unwrap();

    let lp = |wire: Bytes| ndn_packet::lp::encode_lp_packet(&wire);
    for name in ["/carol/private/x", "/bob/member/phone/32=probe/x"] {
        link.face
            .send_bytes(lp(InterestBuilder::new(n(name)).build()))
            .await
            .unwrap();
    }
    until(
        "the Interest for the joiner's own name is delivered",
        Duration::from_secs(10),
        async || own.load(Ordering::SeqCst) == 1,
    )
    .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        elsewhere.load(Ordering::SeqCst),
        0,
        "an Interest the party sent for another name reached another face of the joiner"
    );
}

/// A party at the address answers the first-contact dial with a key of its
/// own and relays the genuine hint record, which names the inviter's key; that
/// key's address is dead (blocked). The join goes on through the relay and
/// succeeds, and the party's link does not outlive it: no link and no route
/// to the party remain.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_first_contact_of_another_key_than_the_records_leaves_no_link_and_no_route_after_the_join()
 {
    let (_dead, dead) = silent();
    let Relayed {
        alice: _alice,
        relay,
        laptop,
        phone,
    } = relayed_with(HintMode::At(vec![dead])).await;
    let carol = Person::new("/carol").await;
    let code = offered(&laptop).await;
    let real = read_short(&code);
    let device = real.device.clone();

    // The genuine record, as the relay path gives it.
    let node = phone._engine.app_node(phone.cancel.child_token());
    let (name, via) = (
        hint_name(&device, &hint_token(&real.secret)),
        [relay.name.clone()],
    );
    let started = Instant::now();
    let mut record = None;
    while record.is_none() && started.elapsed() < Duration::from_secs(60) {
        record = fetches_via(&node, name.clone(), &via).await;
    }
    let wire = record
        .expect("the genuine record crosses the relay")
        .raw()
        .clone();

    // The party at the address: it serves exactly that record.
    let parts = Parts::new("/carol/member/laptop", true);
    let (key, at) = (parts.fingerprint, parts.addr.unwrap());
    let party = embedded_of(&carol, parts, Setup::listening()).await;
    party.links.set_introductions(Arc::new(CarriesAll));
    let party_node = party._engine.app_node(party.cancel.child_token());
    let _serving = party_node
        .serve(hint_prefix(&device), move |_interest, responder| {
            let wire = wire.clone();
            async move {
                let _ = responder.respond_bytes(wire).await;
            }
        })
        .await
        .unwrap();
    let dialled = ShortCode {
        contact: Some(Contact::Address(at)),
        ..real.clone()
    }
    .encode()
    .unwrap_or_else(|e| panic!("{e}"));

    let joined = joins(&phone, &dialled, Duration::from_secs(90))
        .await
        .unwrap_or_else(|e| {
            panic!(
                "the join failed: {e} ({:?})\nbob: {:#?}\nalice: {:#?}",
                e.next(),
                phone.links.report(),
                laptop.links.report()
            )
        });
    assert_eq!(joined.folder, n(FOLDER));
    // Time for the namespace's adoption to make the links again.
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        !linked_keys(&phone.links).contains(&key),
        "a link to the party at the address outlives the join: {:#?}",
        phone.links.report()
    );
    assert!(
        routed_over(&phone, key).is_empty(),
        "a route over the party's link outlives the join: {:?}",
        routed_over(&phone, key)
    );
}

/// A link made again to a party dialled from a code that still shows no
/// certificate of the device's namespace, once this device holds it, is taken
/// down with no route left, not admitted again as an unidentified stranger.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_link_made_again_to_a_party_that_shows_no_certificate_is_taken_down() {
    let alice = Person::new("/alice").await;
    let bob = Person::new("/bob").await;
    let carol = Person::new("/carol").await;
    let party = embedded(&carol, "/carol/member/laptop", Setup::listening()).await;
    let _own = offered_in(&party, "/carol", "/carol/32=data/notebook").await;
    let phone = embedded(&bob, "/bob/member/phone", Setup::default()).await;
    let device = n("/alice/member/laptop");

    let proved = phone
        .links
        .dial_first(
            device.clone(),
            party.addr.unwrap(),
            Duration::from_secs(10),
            introduction_prefixes(&device).into(),
        )
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(proved, party.key);
    assert!(linked_keys(&phone.links).contains(&party.key));

    // The joiner comes to hold the namespace the code claimed for the device.
    phone
        .validator
        .adopt_context(Arc::clone(&alice.ctx))
        .unwrap();
    until(
        "the party's link is taken down once the claimed namespace is held",
        Duration::from_secs(15),
        async || !linked_keys(&phone.links).contains(&party.key),
    )
    .await;
    assert!(
        routed_over_any(&phone).is_empty(),
        "a route is left over the party's link: {:#?}",
        phone.links.report()
    );
}
