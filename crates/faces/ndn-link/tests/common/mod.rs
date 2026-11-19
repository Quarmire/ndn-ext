//! Real QUIC links between real data-layer devices, each on a forwarder of its
//! own (the harness of `tests/grants.rs` and `tests/departures.rs`).
//!
//! Ann keeps the default serving policy `own`: she serves the devices of
//! namespaces she holds a certificate in, and a person she invites is of
//! another namespace, whose context she holds from the join but in which she
//! has no certificate. Every device runs `LinkHints::serve`, so each one also
//! installs the departure marks it derives and registers the sink that takes a
//! departure it is told of.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use ndn_app::EngineAppExt;
use ndn_data::intro::{Departure as DataDeparture, Dialing, Grant as DataGrant, LinkHint};
use ndn_data::{
    Answer, Audience, Clock, Config, Content, DataLayer, Device, Got, IntroPolicy, Introducer,
    Joined, Keep, NextStep, Offer, Payload, PutOptions, Role, Rule, Share, Sharing, Timestamp,
    Transport, TypeId,
};
use ndn_engine::{EngineBuilder, EngineConfig, ForwarderEngine, ShutdownHandle};
use ndn_face_quic::{KeyFingerprint, LinkEndpoint, LinkKey, LinkKeySource, LinkTransportConfig};
use ndn_link::{
    ConfiguredEndpoints, EngineFaces, FaceSink, HostCandidates, LinkDetail, LinkHints, LinkSetup,
    LinkTrust, Links, Quotas, RelayService, ServePolicy,
};
use ndn_packet::{Data, Name};
use ndn_security::self_certifying::Genesis;
use ndn_security::sync_group;
use ndn_security::{
    Certificate, Keyring, SecurityManager, SecurityProfile, SignedTrustContext, TrustSchema,
    Validator,
};
use ndn_sync::MemoryStore;
use ndn_trust_envelope::TrustEnvelope;
use tokio_util::sync::CancellationToken;

pub mod recording;
pub use recording::Recording;

/// The people of this test who are named by their key: their genesis and
/// their newest signed context, as the network would give them by name.
static DIRECTORY: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<Name, (Bytes, Bytes)>>,
> = std::sync::LazyLock::new(Default::default);

/// The device certificates of the test's people, by namespace.
static CERTIFICATES: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<Name, Vec<Certificate>>>,
> = std::sync::LazyLock::new(Default::default);

fn directory_entry(ns: &Name) -> Option<(Bytes, Bytes)> {
    DIRECTORY.lock().unwrap().get(ns).cloned()
}

pub const VALIDITY_MS: u64 = 365 * 24 * 3600 * 1000;
pub const FOLDER: &str = "/alice/32=data/notebook";
pub const ANN: &str = "/alice/member/laptop";

pub fn n(s: &str) -> Name {
    s.parse().unwrap()
}

/// A person: a namespace with its root key, trust context and anchor.
pub struct Person {
    pub ns: Name,
    pub authority: SecurityManager,
    pub issuer: Name,
    pub ctx: Arc<SignedTrustContext>,
    pub signed: Bytes,
    /// The genesis of a person named by their key.
    pub genesis: Option<Arc<Genesis>>,
}

impl Person {
    pub async fn new(ns: &str) -> Person {
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
            genesis: None,
        }
    }

    /// A person named by their key, `/user/<0xA1: SHA-256 of the key>`,
    /// whose root key is the Ed25519 secret `seed`: their genesis is what
    /// another person's device adopts them from, by name alone, and their
    /// context at version 2 follows from it.
    pub async fn self_certifying(seed: [u8; 32]) -> Person {
        let ns = ndn_cert::GenesisKey::from_seed(seed).namespace();
        let authority = SecurityManager::new();
        let issuer = authority
            .generate_ed25519_from_seed(ns.clone().append("KEY").append("ns"), &seed)
            .unwrap();
        let signer = authority.get_signer_sync(&issuer).unwrap();
        let first = ndn_cert::sign_genesis(signer.as_ref()).await.unwrap();
        let ctx = SignedTrustContext::hierarchical(ns.clone()).with_version(2);
        assert!(ctx.add_anchor(first.root().clone()));
        let signed = ctx.sign_into_data(signer.as_ref()).unwrap();
        DIRECTORY.lock().unwrap().insert(
            ns.clone(),
            (first.data().raw().clone(), signed.raw().clone()),
        );
        Person {
            ns,
            authority,
            issuer,
            ctx: Arc::new(ctx),
            signed: signed.raw().clone(),
            genesis: Some(Arc::new(first)),
        }
    }

    /// The name of this person's device `label`, as the text a device is
    /// started with.
    pub fn device(&self, label: &str) -> String {
        let name = self.ns.clone().append("member").append(label);
        assert_eq!(
            n(&name.to_string()),
            name,
            "a device name keeps its form as text"
        );
        name.to_string()
    }
}

/// A device's keys, and its link socket when it listens.
#[derive(Clone)]
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

    /// The same keys on a link socket of their own (when `listen`): what a
    /// device that restarts has, at an address of its own.
    fn rebound(&self, listen: bool) -> Parts {
        let socket = listen.then(|| {
            Arc::new(
                LinkEndpoint::bind(
                    "127.0.0.1:0".parse().unwrap(),
                    Arc::clone(&self.link_key),
                    &self.transport,
                    true,
                )
                .unwrap(),
            )
        });
        let addr = socket.as_ref().map(|s| s.local_addr().unwrap());
        Parts {
            socket,
            addr,
            ..self.clone()
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
        CERTIFICATES
            .lock()
            .unwrap()
            .entry(person.ns.clone())
            .or_default()
            .push(cert.clone());
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
    match &person.genesis {
        Some(first) => validator
            .keyring()
            .adopt_genesis(first, Arc::clone(&person.ctx))
            .unwrap(),
        None => validator.adopt_context(Arc::clone(&person.ctx)).unwrap(),
    }
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
/// the grants and departures its device makes and ends forwarded to them.
struct Host {
    anchor: Bytes,
    validator: Arc<Validator>,
    engine: ForwarderEngine,
    hints: OnceLock<LinkHints>,
    links: OnceLock<Arc<Links>>,
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
                match directory_entry(&ns) {
                    // A person named by their key enters a keyring from
                    // the genesis their name hashes.
                    Some((first, _)) => {
                        let first = Genesis::open_received(
                            &Data::decode(first).map_err(|e| format!("{e:?}"))?,
                        )
                        .await
                        .map_err(|e| e.to_string())?;
                        self.validator
                            .keyring()
                            .adopt_genesis(&first, Arc::new(ctx))
                            .map_err(|refused| refused.to_string())?;
                    }
                    None => self
                        .validator
                        .adopt_context(Arc::new(ctx))
                        .map_err(|refused| refused.to_string())?,
                }
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

    fn revoke_grant(&self, key: &[u8; 32], folder: &Name) {
        if let Some(hints) = self.hints.get() {
            hints.revoke_grant(key, folder);
        }
    }

    fn departure(&self, departure: &DataDeparture) {
        if let Some(hints) = self.hints.get() {
            hints.depart(departure);
        }
    }

    fn adopt_scoped<'a>(
        &'a self,
        namespace: &'a Name,
        held: Option<&'a ndn_security::ScopedContext>,
    ) -> ndn_data::intro::Scoping<'a> {
        let _ = held;
        Box::pin(async move {
            // The fetch of the genesis by name is the host's, over the
            // network; the harness's network is the directory of the test's
            // people. What the layer adopts is checked here as a fetched one
            // is: the genesis the name hashes, the newest from it, adopted
            // into no keyring.
            let (first, newest) = directory_entry(namespace)
                .ok_or_else(|| format!("{namespace} is no person of this test's directory"))?;
            let first = Genesis::open_received(&Data::decode(first).map_err(|e| format!("{e:?}"))?)
                .await
                .map_err(|e| e.to_string())?;
            let newest = Data::decode(newest).map_err(|e| format!("{e:?}"))?;
            let (context, _) = SignedTrustContext::open_received(&newest)
                .await
                .map_err(|e| e.to_string())?;
            let scoped = ndn_security::ScopedContext::new(first, Arc::new(context))
                .and_then(|scoped| scoped.with_data(&newest))
                .map_err(|e| e.to_string())?;
            // As the contract says, the host carries the namespace's sync
            // group and routes it over its links (to the inviter), where the
            // other writer's notices come from.
            ndn_namespace::sync_group::carry(&self.engine, namespace);
            // And the certificates of that person's devices, which a host
            // fetches by name for its validator (here: from the directory).
            for cert in CERTIFICATES
                .lock()
                .unwrap()
                .get(namespace)
                .cloned()
                .unwrap_or_default()
            {
                self.validator.cert_cache().insert(cert);
            }
            if let Some(links) = self.links.get() {
                let faces: Vec<_> = links
                    .report()
                    .links
                    .iter()
                    .flat_map(|l| l.paths.iter().map(|p| p.face))
                    .collect();
                for face in faces {
                    EngineFaces(self.engine.clone())
                        .add_routes(face, &ndn_link::group_routes([namespace], 0));
                }
            }
            Ok(scoped)
        })
    }
}

/// How a test's device is set up.
#[derive(Clone)]
pub struct Setup {
    /// It listens for links on a loopback socket and takes introductions.
    pub listen: bool,
    /// Whom it serves.
    pub serve: ServePolicy,
    /// How long a grant its device makes lasts: `None`, no date (it follows
    /// the members record).
    pub grant_for: Option<Duration>,
    /// How long a departure mark its device makes lasts: zero, no mark (a
    /// person let go is not told, as before round 7).
    pub departure_for: Duration,
}

impl Setup {
    /// An inviter that keeps the default policy: `own`, and the grants its
    /// device makes.
    pub fn inviter() -> Setup {
        Setup {
            listen: true,
            serve: ServePolicy::Own,
            grant_for: None,
            departure_for: IntroPolicy::new().departure_for,
        }
    }

    pub fn open() -> Setup {
        Setup {
            serve: ServePolicy::Open {
                quotas: Quotas::default(),
            },
            ..Setup::inviter()
        }
    }

    /// A joiner: dial-only.
    pub fn dialer() -> Setup {
        Setup {
            listen: false,
            ..Setup::inviter()
        }
    }
}

/// A device of a person, alone on a forwarder of its own: its data layer, its
/// links.
pub struct Embedded {
    pub device: Device,
    pub links: Arc<Links>,
    pub hints: LinkHints,
    pub key: KeyFingerprint,
    pub ns: Name,
    pub addr: Option<SocketAddr>,
    pub cancel: CancellationToken,
    pub engine: ForwarderEngine,
    /// What this device's links gave its forwarder (route and face removals,
    /// recorded).
    pub sink: Arc<Recording>,
    _shutdown: ShutdownHandle,
    pub validator: Arc<Validator>,
    kept: Kept,
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
    pub fn offers_run_out(&self) {
        self.skew.store(2 * 3_600_000, Ordering::SeqCst);
        assert!(
            !self.device.introductions().open(),
            "an offer is still open two hours on"
        );
    }
}

/// What a device keeps across its runs: its keys, trust, store and anchor.
#[derive(Clone)]
struct Kept {
    parts: Parts,
    trust: Arc<Trust>,
    validator: Arc<Validator>,
    store: Arc<MemoryStore>,
    anchor: Bytes,
    ns: Name,
}

pub async fn embedded(person: &Person, device: &str, setup: Setup) -> Embedded {
    log_to_file();
    let parts = Parts::new(device, setup.listen);
    let cert = parts.certified(person).await;
    let (validator, trust) = trust(person, &cert);
    boot(
        Kept {
            parts,
            trust,
            validator,
            store: Arc::new(MemoryStore::new()),
            anchor: person.signed.clone(),
            ns: person.ns.clone(),
        },
        setup,
    )
    .await
}

impl Embedded {
    /// The device's store: what it keeps across a restart.
    pub fn store(&self) -> &Arc<MemoryStore> {
        &self.kept.store
    }

    /// Stop this run and start the device again over what it kept: its keys,
    /// its trust and its store, on a link socket of its own (a new address
    /// when it listens).
    pub async fn restart(self, setup: Setup) -> Embedded {
        self.links.shutdown().await;
        self.device.shutdown();
        self.cancel.cancel();
        let mut kept = self.kept.clone();
        kept.parts = kept.parts.rebound(setup.listen);
        boot(kept, setup).await
    }
}

async fn boot(kept: Kept, setup: Setup) -> Embedded {
    let Kept {
        parts,
        trust,
        validator,
        store,
        anchor,
        ns,
    } = kept.clone();
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .security_profile(SecurityProfile::Disabled)
        .build()
        .await
        .unwrap();
    ndn_namespace::sync_group::carry(&engine, &ns);
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
    let sink = Arc::new(Recording::new(engine.clone()));
    let links = Links::start(
        LinkSetup {
            peers: Vec::new(),
            key: Arc::clone(&parts.link_key),
            trust,
            faces: Arc::clone(&sink) as Arc<dyn FaceSink>,
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
        anchor,
        validator: Arc::clone(&validator),
        engine: engine.clone(),
        hints: OnceLock::new(),
        links: OnceLock::new(),
    });
    let _ = host.hints.set(hints.clone());
    let _ = host.links.set(Arc::clone(&links));
    let device = Device::start(
        Transport {
            node: engine.app_node(cancel.child_token()),
            sync: engine.app_face(cancel.child_token()),
        },
        parts.name.clone(),
        Arc::clone(&parts.keys),
        Arc::clone(&validator),
        Arc::clone(&store) as Arc<dyn ndn_sync::DataStore>,
        Config {
            clock,
            first_look: Duration::from_secs(1),
            introducer: Some(host),
            intro: IntroPolicy {
                local_candidates: true,
                grant_for: setup.grant_for,
                departure_for: setup.departure_for,
                ..IntroPolicy::new()
            },
            ..Config::new()
        },
    )
    .await
    .unwrap();
    hints.serve(&device);
    Embedded {
        device,
        links,
        hints,
        key: parts.fingerprint,
        ns,
        addr: parts.addr,
        cancel,
        engine,
        sink,
        validator,
        kept,
        skew,
        _shutdown: shutdown,
    }
}

pub fn note() -> PutOptions {
    PutOptions {
        type_id: TypeId {
            name: n("/types/note"),
            revision: 1,
        },
        keep: Keep::Forever,
        batch: None,
    }
}

pub fn text(s: &str) -> Content {
    Content::new().with("text", Bytes::copy_from_slice(s.as_bytes()))
}

/// Whether `layer` reads `s` as the newest note of `collection`.
pub async fn reads(layer: &Device, collection: &Name, s: &str) -> bool {
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

/// `put` as a host does what `NotReady` says (the layer has not walked what
/// the new name's folder needs yet): again until `limit` has passed.
pub async fn puts(layer: &Device, name: &Name, content: Content, limit: Duration) {
    let started = Instant::now();
    loop {
        match layer.put(name, content.clone(), note()).await {
            Ok(_) => return,
            Err(e) if e.next() == NextStep::RetryLater && started.elapsed() < limit => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(e) => panic!("put of {name}: {e}"),
        }
    }
}

pub async fn until(what: &str, limit: Duration, mut done: impl AsyncFnMut() -> bool) {
    let start = Instant::now();
    while !done().await {
        assert!(start.elapsed() < limit, "not within {limit:?}: {what}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

pub const LONG: Duration = Duration::from_secs(60);

/// `folder` of Ann's, shared with `/alice` alone and with a cover written
/// into it. Once per folder: it makes the folder's members record.
pub async fn shared(laptop: &Embedded, folder: &Name) {
    laptop
        .device
        .share_folder(
            folder,
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
}

/// An offer of `folder` (already shared) as `role`, made by Ann's laptop.
pub async fn offer_of(laptop: &Embedded, folder: &Name, role: Role) -> ndn_data::Code {
    laptop
        .device
        .offer(
            folder,
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

/// Ann's notebook, shared with `/alice` alone and with a cover written into
/// it: an offer of it as `role` made by her laptop.
pub async fn offered(laptop: &Embedded, role: Role) -> ndn_data::Code {
    let folder = n(FOLDER);
    shared(laptop, &folder).await;
    offer_of(laptop, &folder, role).await
}

/// Join with `link` as a host does what `NotReady` says: again with the same
/// code until `limit` has passed.
pub async fn joins(
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
pub fn said(detail: &LinkDetail) -> String {
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
pub fn linked(on: &Embedded, key: KeyFingerprint) -> bool {
    on.links
        .report()
        .links
        .iter()
        .any(|l| l.key == Some(key) && !l.paths.is_empty())
}

/// Dial Ann (by her key and address, as a joiner's code names them) from
/// `from`.
pub async fn dials(from: &Embedded, ann: &Embedded) -> Result<(), LinkDetail> {
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

/// Invite `bob` as `role` into the notebook (shared with a cover) and have
/// him join.
pub async fn invited(ann: &Embedded, bob: &Embedded, role: Role) {
    let code = offered(ann, role).await;
    joined(ann, bob, &code, role).await;
}

/// Invite `bob` as `role` into `folder`, already shared, and have him join.
pub async fn invited_in(ann: &Embedded, bob: &Embedded, folder: &Name, role: Role) {
    let code = offer_of(ann, folder, role).await;
    joined(ann, bob, &code, role).await;
}

async fn joined(ann: &Embedded, bob: &Embedded, code: &ndn_data::Code, role: Role) {
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
pub fn routed_over(on: &Embedded, key: KeyFingerprint) -> Vec<String> {
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
pub fn probe_prefix(on: &Embedded) -> Name {
    sync_group(&on.ns).append("probe")
}

/// `on` answers probes with a Data: a Data a device sends on its own, toward
/// the other.
pub fn answers_probes(on: &Embedded) {
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
pub async fn probes(from: &Embedded, to: &Embedded, tag: &str) -> bool {
    let mut consumer = from.engine.app_consumer(from.cancel.child_token());
    consumer.fetch(probe_prefix(to).append(tag)).await.is_ok()
}

/// The name of the newest entry of `collection` that `device` (the name of
/// `on`'s device) wrote, as `on` holds it: a single version's own name, or,
/// for a merged collection, the log entry of the writer's highest seq.
pub async fn newest_entry(on: &Embedded, device: &str, collection: &Name) -> Name {
    match on.device.get(collection).await {
        Ok(Answer {
            got: Got::Version(v),
            ..
        }) => v.name,
        Ok(Answer {
            got: Got::State(state),
            ..
        }) => {
            let seq = state
                .at
                .iter()
                .map(|(_, seq)| seq.0)
                .max()
                .unwrap_or_else(|| panic!("{collection} has an empty state on {}", on.ns));
            ndn_data::wire::log_name(&n(device), Some(collection), seq)
        }
        other => panic!("{collection} has no entry on {}: {other:?}", on.ns),
    }
}

/// Whether `on` is answered a Data for `name` when it asks **over its link to
/// the device with `key`** (the Interest is pinned to that link's face, so a
/// missing route on `on`'s forwarder never stands in for a refusal at the
/// link), by prefix when `by_prefix`. `on`'s forwarder keeps no copy of what
/// it did not verify (the harness runs it with its validator off), so a Data
/// that arrives crossed the link.
pub async fn asks(on: &Embedded, key: KeyFingerprint, name: &Name, by_prefix: bool) -> bool {
    ask(on, key, name, by_prefix).await.is_ok()
}

/// [`asks`], with the reason when it is not answered: a Nack comes back at
/// once for an Interest a link's scope refused, a timeout for one nobody
/// answered.
pub async fn ask(
    on: &Embedded,
    key: KeyFingerprint,
    name: &Name,
    by_prefix: bool,
) -> Result<(), String> {
    let face = on
        .links
        .report()
        .links
        .iter()
        .filter(|l| l.key == Some(key))
        .flat_map(|l| l.paths.iter().map(|p| p.face))
        .next();
    let Some(face) = face else {
        return Err("no link to that key".into());
    };
    let mut builder =
        ndn_packet::encode::InterestBuilder::new(name.clone()).lifetime(Duration::from_secs(3));
    if by_prefix {
        builder = builder.can_be_prefix();
    }
    let mut consumer = on.engine.app_consumer(on.cancel.child_token());
    consumer
        .fetch_with_on(face, builder)
        .await
        .map(|_| ())
        .map_err(|e| format!("{e:?}"))
}

pub const SECOND: &str = "/alice/32=data/second";

/// Ann's members record for `folder` again, with `writers` (and the same
/// people as readers): whoever the record no longer lists is let go of the
/// folder.
pub async fn reshare(ann: &Embedded, folder: &Name, writers: &[Name]) {
    ann.device
        .share_folder(
            folder,
            Sharing::Whole(Share {
                rule: Rule::Log,
                writers: writers.to_vec(),
                readers: writers.iter().cloned().map(Audience::Person).collect(),
            }),
        )
        .await
        .unwrap();
}

/// With `NDN_LINK_TEST_LOG=<file>` (and `RUST_LOG`), the tracing of the run
/// goes to that file, once.
pub fn log_to_file() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        if let Ok(path) = std::env::var("NDN_LINK_TEST_LOG")
            && let Ok(file) = std::fs::File::create(path)
        {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
                .with_writer(std::sync::Mutex::new(file))
                .with_ansi(false)
                .try_init();
        }
    });
}
