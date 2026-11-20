//! Memory of linked peers across restarts on real QUIC links, real forwarders
//! and real data-layer devices (ndn-rs `ndn-link.md` §17C).
//!
//! The case SHAPES-R6 §2 names: Ann (the inviter, `own` plus the grant her
//! device made, listening) and Bob (dial-only) join by a code, both restart —
//! fresh links, engines and devices over the same stores and keyrings — and
//! link and sync again with no relay, no peer entry and no list the host keeps:
//! Bob redials Ann from the record his device kept, and Ann accepts him by the
//! grant her device re-derives. Further cases: a fresh record is dialled at
//! start; an expired one is not; `forget` ends the redial; a record whose
//! namespace is no longer held is not dialled until it is; an address another
//! key answers at costs a failed dial and no link; a peer with no address waits
//! and learns one when the peer dials in; a remembered peer whose grant ended
//! (revoked, or its record left him out) is refused and the inviter does not
//! dial it; the notes a store holds that are not records are dropped.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use ndn_app::EngineAppExt;
use ndn_data::intro::{Dialing, FirstDialing, Grant as DataGrant, LinkHint};
use ndn_data::{
    Answer, Audience, Clock, Config, Content, DataLayer, Device, Got, IntroPolicy, Introducer,
    Joined, Keep, NextStep, Offer, Payload, PutOptions, Role, Rule, Share, Sharing, Timestamp,
    Transport, TypeId,
};
use ndn_engine::{EngineBuilder, EngineConfig, ForwarderEngine, ShutdownHandle};
use ndn_face_quic::{KeyFingerprint, LinkEndpoint, LinkKey, LinkKeySource, LinkTransportConfig};
use ndn_link::{
    ConfiguredEndpoints, DeviceMemory, Direction, EngineFaces, Grant, GrantRole, HostCandidates,
    LinkDetail, LinkHints, LinkMemory, LinkSetup, LinkState, LinkTrust, Links, MemoryFuture,
    MemoryOptions, PeerRecord, RelayService, RememberedState, ServePolicy,
};
use ndn_packet::{Data, Name};
use ndn_security::{
    Certificate, Keyring, SecurityManager, SecurityProfile, SignedTrustContext, TrustSchema,
    Validator,
};
use ndn_sync::{DataStore, MemoryStore};
use ndn_trust_envelope::TrustEnvelope;
use parking_lot::Mutex;
use tokio_util::sync::CancellationToken;

const VALIDITY_MS: u64 = 365 * 24 * 3600 * 1000;
const FOLDER: &str = "/alice/32=data/notebook";
const ANN: &str = "/alice/member/laptop";
const BOB: &str = "/bob/member/phone";
const DAY: Duration = Duration::from_secs(24 * 3600);
const LONG: Duration = Duration::from_secs(60);

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

/// A device's keys: the same in every run of the device.
struct Parts {
    name: Name,
    keys: Arc<SecurityManager>,
    key_name: Name,
    link_key: Arc<dyn LinkKeySource>,
    fingerprint: KeyFingerprint,
    public: Bytes,
    transport: LinkTransportConfig,
}

impl Parts {
    fn new(device: &str) -> Parts {
        let name = n(device);
        let keys = Arc::new(SecurityManager::new());
        let key_name = keys
            .generate_ed25519(name.clone().append("KEY").append("1"))
            .unwrap();
        let signer = keys.get_signer_sync(&key_name).unwrap();
        let public = signer.public_key().unwrap();
        let link_key = LinkKey::from_signer(signer).unwrap();
        let fingerprint = link_key.fingerprint();
        Parts {
            name,
            keys,
            key_name,
            link_key: Arc::new(link_key),
            fingerprint,
            public,
            transport: LinkTransportConfig::default(),
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

/// A host's introducer: its person's signed context, adoption into its
/// validator and forwarder, a link hint and a dial through its links, and the
/// grants its device makes and ends forwarded to them.
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
}

/// How a test's device is set up.
#[derive(Clone)]
struct Setup {
    /// It listens for links on a loopback socket and takes introductions.
    listen: bool,
    /// Whom it serves.
    serve: ServePolicy,
    /// How long a departure mark its device makes lasts. Zero: no mark, so a
    /// member let go is refused as a stranger is (these cases are about what
    /// a device remembers; what a mark admits is `tests/departures.rs`).
    departure_for: Duration,
}

impl Setup {
    /// An inviter that keeps the default policy: `own`, and the grants its
    /// device makes.
    fn inviter() -> Setup {
        Setup {
            listen: true,
            serve: ServePolicy::Own,
            departure_for: Duration::ZERO,
        }
    }

    /// A joiner: dial-only.
    fn dialer() -> Setup {
        Setup {
            listen: false,
            serve: ServePolicy::Own,
            departure_for: Duration::ZERO,
        }
    }
}

/// What a device keeps across its runs: its keys, its keyring and trust, its
/// store, and the port it listens on.
struct Durable {
    parts: Parts,
    ns: Name,
    anchor: Bytes,
    validator: Arc<Validator>,
    trust: Arc<Trust>,
    store: Arc<MemoryStore>,
    port: Mutex<u16>,
    /// The host keeps no port: its socket is bound on a port the system picks at
    /// every start (the link memory keeps the port, ndn-link §17D.2).
    fresh_port: AtomicBool,
}

impl Durable {
    async fn new(person: &Person, device: &str) -> Arc<Durable> {
        let parts = Parts::new(device);
        let cert = parts.certified(person).await;
        let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
        validator.adopt_context(Arc::clone(&person.ctx)).unwrap();
        validator.cert_cache().insert(cert.clone());
        let trust = Arc::new(Trust {
            keyring: Arc::clone(validator.keyring()),
            chain: vec![cert.data_wire().unwrap()],
            validator: Arc::clone(&validator),
        });
        Arc::new(Durable {
            parts,
            ns: person.ns.clone(),
            anchor: person.signed.clone(),
            validator,
            trust,
            store: Arc::new(MemoryStore::new()),
            port: Mutex::new(0),
            fresh_port: AtomicBool::new(false),
        })
    }

    /// The listening socket: on a port the system picks the first time, on
    /// the same one at a restart (the old socket may take a moment to go).
    async fn bind(&self) -> Arc<LinkEndpoint> {
        let port = if self.fresh_port.load(Ordering::SeqCst) {
            0
        } else {
            *self.port.lock()
        };
        for _ in 0..100 {
            let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
            match LinkEndpoint::bind(
                addr,
                Arc::clone(&self.parts.link_key),
                &self.parts.transport,
                true,
            ) {
                Ok(socket) => {
                    *self.port.lock() = socket.local_addr().unwrap().port();
                    return Arc::new(socket);
                }
                Err(e) if port != 0 => {
                    let _ = e;
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(e) => panic!("cannot bind a link socket: {e}"),
            }
        }
        panic!("the listening port {port} is not free ten seconds after the device stopped");
    }
}

/// A device of a person, alone on a forwarder of its own: its data layer, its
/// links.
struct Embedded {
    device: Device,
    links: Arc<Links>,
    key: KeyFingerprint,
    addr: Option<SocketAddr>,
    endpoint: Option<Arc<LinkEndpoint>>,
    cancel: CancellationToken,
    _shutdown: ShutdownHandle,
    validator: Arc<Validator>,
    skew: Arc<AtomicU64>,
    durable: Arc<Durable>,
}

impl Drop for Embedded {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

impl Embedded {
    /// Every offer this device made has run out by its clock (moved two hours
    /// on): no stranger's introduction link is worth taking.
    fn offers_run_out(&self) {
        self.skew.store(2 * 3_600_000, Ordering::SeqCst);
        assert!(
            !self.device.introductions().open(),
            "an offer is still open two hours on"
        );
    }

    /// The device stops (its links tell the peers, and write what the memory
    /// owes the store) and starts again over what it kept.
    async fn restart(self, setup: Setup) -> Embedded {
        self.links.shutdown().await;
        self.device.shutdown();
        self.cancel.cancel();
        let durable = Arc::clone(&self.durable);
        drop(self);
        boot(&durable, setup).await
    }

    /// Give the links the memory a device keeps in its own store
    /// (`ndf`'s `links.remember(DeviceMemory::new(&device), …)`).
    fn remembers_in_the_device(&self) {
        self.links
            .remember(DeviceMemory::new(&self.device), on_this_machine());
    }

    /// The same with `options`.
    fn remembers_in_the_device_with(&self, options: MemoryOptions) {
        self.links
            .remember(DeviceMemory::new(&self.device), options);
    }
}

async fn embedded(person: &Person, device: &str, setup: Setup) -> Embedded {
    boot(&Durable::new(person, device).await, setup).await
}

/// Start the device of `durable`: a forwarder, links, a data layer over the
/// store it kept.
async fn boot(durable: &Arc<Durable>, setup: Setup) -> Embedded {
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .security_profile(SecurityProfile::Disabled)
        .build()
        .await
        .unwrap();
    ndn_namespace::sync_group::carry(&engine, &durable.ns);
    for ctx in durable.validator.keyring().contexts() {
        ndn_namespace::sync_group::carry(&engine, ctx.namespace());
    }
    let socket = if setup.listen {
        Some(durable.bind().await)
    } else {
        None
    };
    let addr = socket.as_ref().map(|s| s.local_addr().unwrap());
    let endpoint = socket.clone();
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
            key: Arc::clone(&durable.parts.link_key),
            trust: durable.trust.clone(),
            faces: Arc::new(EngineFaces(engine.clone())),
            paths: Arc::new(ConfiguredEndpoints),
            candidates: vec![Arc::new(HostCandidates {
                include_local: true,
            })],
            socket,
            transport: durable.parts.transport.clone(),
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
        anchor: durable.anchor.clone(),
        validator: Arc::clone(&durable.validator),
        engine: engine.clone(),
        hints: OnceLock::new(),
    });
    let _ = host.hints.set(hints.clone());
    let device = Device::start(
        Transport {
            node: engine.app_node(cancel.child_token()),
            sync: engine.app_face(cancel.child_token()),
        },
        durable.parts.name.clone(),
        Arc::clone(&durable.parts.keys),
        Arc::clone(&durable.validator),
        Arc::clone(&durable.store) as Arc<dyn DataStore>,
        Config {
            clock,
            first_look: Duration::from_secs(1),
            introducer: Some(host),
            intro: IntroPolicy {
                local_candidates: true,
                departure_for: setup.departure_for,
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
        key: durable.parts.fingerprint,
        addr,
        endpoint,
        cancel,
        validator: Arc::clone(&durable.validator),
        skew,
        durable: Arc::clone(durable),
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

/// `holds` stays true for `span`, checked as often as `until` looks: for what
/// must not happen, which no event announces.
async fn throughout(what: &str, span: Duration, mut holds: impl FnMut() -> bool) {
    let start = Instant::now();
    while start.elapsed() < span {
        assert!(holds(), "{what}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

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

/// Invite `bob` as `role` and have him join.
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

/// `on` is linked to the device with `key`.
fn linked(on: &Embedded, key: KeyFingerprint) -> bool {
    on.links
        .report()
        .links
        .iter()
        .any(|l| l.key == Some(key) && !l.paths.is_empty())
}

/// `on`'s memory of the peer with `key`: its record and what it does about it.
fn remembered(on: &Embedded, key: KeyFingerprint) -> Option<(PeerRecord, RememberedState)> {
    on.links
        .report()
        .memory
        .expect("the links keep a memory")
        .peers
        .into_iter()
        .find(|p| p.record.key == key)
        .map(|p| (p.record, p.state))
}

/// The devices of two people that know each other as an introduction leaves
/// them, without the join: Ann (listening, `own`) holds Bob's namespace and
/// has granted his key; Bob (dial-only) holds Ann's. Neither remembers anyone.
async fn acquainted(alice: &Person, bobs: &Person) -> (Embedded, Embedded) {
    let ann = embedded(alice, ANN, Setup::inviter()).await;
    let bob = embedded(bobs, BOB, Setup::dialer()).await;
    ann.validator.adopt_context(Arc::clone(&bobs.ctx)).unwrap();
    bob.validator.adopt_context(Arc::clone(&alice.ctx)).unwrap();
    ann.links.grant(grant_of(&bob));
    (ann, bob)
}

fn grant_of(bob: &Embedded) -> Grant {
    Grant {
        key: bob.key,
        namespaces: vec![n("/bob")],
        role: GrantRole::Writer,
        folder: n(FOLDER),
        until: Some(SystemTime::now() + Duration::from_secs(3600)),
    }
}

/// A link memory in a map, which a case can read and make fail.
#[derive(Default)]
struct Shelf {
    records: Mutex<HashMap<KeyFingerprint, PeerRecord>>,
    port: Mutex<Option<u16>>,
}

impl Shelf {
    fn with(records: Vec<PeerRecord>) -> Arc<Shelf> {
        let shelf = Shelf::default();
        shelf
            .records
            .lock()
            .extend(records.into_iter().map(|r| (r.key, r)));
        Arc::new(shelf)
    }

    fn get(&self, key: &KeyFingerprint) -> Option<PeerRecord> {
        self.records.lock().get(key).cloned()
    }
}

impl LinkMemory for Shelf {
    fn load(&self) -> Result<Vec<PeerRecord>, String> {
        Ok(self.records.lock().values().cloned().collect())
    }
    fn save<'a>(&'a self, record: &'a PeerRecord) -> MemoryFuture<'a, Result<(), String>> {
        Box::pin(async move {
            self.records.lock().insert(record.key, record.clone());
            Ok(())
        })
    }
    fn remove<'a>(&'a self, key: &'a KeyFingerprint) -> MemoryFuture<'a, Result<(), String>> {
        Box::pin(async move {
            self.records.lock().remove(key);
            Ok(())
        })
    }
    fn load_listen_port(&self) -> Result<Option<u16>, String> {
        Ok(*self.port.lock())
    }
    fn save_listen_port<'a>(&'a self, port: Option<u16>) -> MemoryFuture<'a, Result<(), String>> {
        Box::pin(async move {
            *self.port.lock() = port;
            Ok(())
        })
    }
}

/// What Bob's memory holds of Ann: where he reached her, `age` ago.
fn of_ann(ann: &Embedded, addresses: Vec<SocketAddr>, age: Duration) -> PeerRecord {
    PeerRecord {
        key: ann.key,
        device: n(ANN),
        addresses,
        last_contact: SystemTime::now() - age,
        origin: Direction::Dialed,
        port: None,
    }
}

/// The options of these cases: every device is on this machine, so the
/// loopback addresses they link at are kept (off by default).
fn on_this_machine() -> MemoryOptions {
    MemoryOptions {
        include_local: true,
        ..MemoryOptions::default()
    }
}

// ---- the cases ---------------------------------------------------------------------------------

/// SHAPES-R6 §2's case: two embedded hosts joined by a code restart over their
/// stores and keyrings and link and sync again with nothing but what their
/// devices kept.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_hosts_joined_by_a_code_restart_and_link_again_from_memory_alone() {
    let alice = Person::new("/alice").await;
    let bobs = Person::new("/bob").await;
    let ann = embedded(&alice, ANN, Setup::inviter()).await;
    let bob = embedded(&bobs, BOB, Setup::dialer()).await;
    ann.remembers_in_the_device();
    bob.remembers_in_the_device();

    invited(&ann, &bob, Role::Writer).await;
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

    // What each device learned of the other is written behind: the key, the
    // device and the address that worked.
    let (ann_notes, bob_notes) = (
        DeviceMemory::new(&ann.device),
        DeviceMemory::new(&bob.device),
    );
    until("both devices wrote what they learned", LONG, async || {
        ann_notes.load().is_ok_and(|r| r.len() == 1) && bob_notes.load().is_ok_and(|r| r.len() == 1)
    })
    .await;
    let kept_by_ann = ann_notes.load().unwrap().remove(0);
    assert_eq!(kept_by_ann.key, bob.key);
    assert_eq!(kept_by_ann.device, n(BOB));
    assert_eq!(kept_by_ann.origin, Direction::Accepted, "Bob dialled in");
    let kept_by_bob = bob_notes.load().unwrap().remove(0);
    assert_eq!(kept_by_bob.key, ann.key);
    assert_eq!(kept_by_bob.device, n(ANN));
    assert_eq!(kept_by_bob.origin, Direction::Dialed);
    assert!(
        kept_by_bob
            .addresses
            .iter()
            .any(|a| a.port() == ann.addr.unwrap().port()),
        "Bob kept the address that worked: {:?}",
        kept_by_bob.addresses
    );

    // Both stop and start again over what they kept: fresh links, engines and
    // devices; the same stores and keyrings. Nobody lists a peer.
    let ann = ann.restart(Setup::inviter()).await;
    let bob = bob.restart(Setup::dialer()).await;
    assert!(
        ann.links.report().links.iter().all(|l| l.paths.is_empty()),
        "a fresh Links is linked to no one"
    );
    assert_eq!(
        ann.links.grants().len(),
        1,
        "the device re-derives the grant: {:#?}",
        ann.links.grants()
    );
    ann.remembers_in_the_device();
    bob.remembers_in_the_device();

    until("bob and ann link from memory", LONG, async || {
        linked(&bob, ann.key) && linked(&ann, bob.key)
    })
    .await;
    let report = ann.links.report();
    let link = report
        .links
        .iter()
        .find(|l| l.key == Some(bob.key))
        .expect("linked");
    assert!(link.granted.is_some(), "Ann admitted Bob by the grant");
    assert_eq!(link.device, Some(n(BOB)));
    let (record, state) = remembered(&bob, ann.key).expect("Bob remembers Ann");
    assert_eq!(record.device, n(ANN));
    assert_eq!(state, RememberedState::Linked);

    // And they sync again: each writes after the restart, the other reads it.
    let after_bob = folder.clone().append("after-bob");
    bob.device
        .put(&after_bob, text("bob, restarted"), note())
        .await
        .unwrap();
    until(
        "ann reads what bob wrote after the restart",
        LONG,
        async || reads(&ann.device, &after_bob, "bob, restarted").await,
    )
    .await;
    let after_ann = folder.append("after-ann");
    ann.device
        .put(&after_ann, text("ann, restarted"), note())
        .await
        .unwrap();
    until(
        "bob reads what ann wrote after the restart",
        LONG,
        async || reads(&bob.device, &after_ann, "ann, restarted").await,
    )
    .await;
}

/// A record that is not old is dialled at start and linked as an identified
/// device: Ann admits Bob by the grant, Bob admits Ann by her certificate.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_remembered_peer_is_dialled_at_start_and_linked_as_an_identified_device() {
    let (alice, bobs) = (Person::new("/alice").await, Person::new("/bob").await);
    let (ann, bob) = acquainted(&alice, &bobs).await;
    let shelf = Shelf::with(vec![of_ann(&ann, vec![ann.addr.unwrap()], DAY)]);
    bob.links.remember(shelf.clone(), on_this_machine());

    until("bob dials ann from memory", LONG, async || {
        linked(&bob, ann.key) && linked(&ann, bob.key)
    })
    .await;
    let report = bob.links.report();
    let link = report
        .links
        .iter()
        .find(|l| l.key == Some(ann.key))
        .expect("linked");
    assert_eq!(link.device, Some(n(ANN)), "identified by her certificate");
    assert!(ann.links.report().links.iter().any(|l| l.granted.is_some()));
    let (record, state) = remembered(&bob, ann.key).unwrap();
    assert_eq!(state, RememberedState::Linked);
    assert!(
        record.last_contact > SystemTime::now() - DAY / 2,
        "the contact is noted: {record:?}"
    );
}

/// A record not in contact for `expires` is not dialled, and is removed from
/// the store at start; the same record a little younger is dialled.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_expired_record_is_not_dialled_and_is_removed_from_the_store() {
    let (alice, bobs) = (Person::new("/alice").await, Person::new("/bob").await);
    let (ann, bob) = acquainted(&alice, &bobs).await;
    let stale = Shelf::with(vec![of_ann(&ann, vec![ann.addr.unwrap()], 31 * DAY)]);
    bob.links.remember(stale.clone(), on_this_machine());
    until("the expired record is removed", LONG, async || {
        stale.get(&ann.key).is_none()
    })
    .await;
    assert!(remembered(&bob, ann.key).is_none());
    throughout(
        "an expired record was dialled",
        Duration::from_secs(2),
        || !linked(&bob, ann.key) && !linked(&ann, bob.key),
    )
    .await;

    // The control: the same record 29 days old, in a world that dials it.
    let (ann, bob) = acquainted(&alice, &bobs).await;
    let fresh = Shelf::with(vec![of_ann(&ann, vec![ann.addr.unwrap()], 29 * DAY)]);
    bob.links.remember(fresh, on_this_machine());
    until("a record 29 days old is dialled", LONG, async || {
        linked(&bob, ann.key)
    })
    .await;
}

/// `forget(key)` removes the record durably before it returns and ends the
/// redial: the link stays up, and when it ends it is not made again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forget_removes_the_record_and_ends_the_redial() {
    let (alice, bobs) = (Person::new("/alice").await, Person::new("/bob").await);
    let (ann, bob) = acquainted(&alice, &bobs).await;
    let shelf = Shelf::with(vec![of_ann(&ann, vec![ann.addr.unwrap()], DAY)]);
    bob.links.remember(shelf.clone(), on_this_machine());
    until("bob dials ann from memory", LONG, async || {
        linked(&bob, ann.key) && linked(&ann, bob.key)
    })
    .await;

    bob.links.forget(&ann.key).await;
    assert!(
        shelf.get(&ann.key).is_none(),
        "forget returned before the store held it no more"
    );
    assert!(remembered(&bob, ann.key).is_none());
    assert!(linked(&bob, ann.key), "a link already up stays up");

    // The link ends (Ann ends the grant, then grants again, so she would take
    // a redial): it is not made again.
    assert!(ann.links.revoke_grants(&bob.key));
    until("the link ends", LONG, async || {
        !linked(&bob, ann.key) && !linked(&ann, bob.key)
    })
    .await;
    ann.links.grant(grant_of(&bob));
    throughout(
        "bob dialled a peer he forgot",
        Duration::from_secs(3),
        || !linked(&bob, ann.key),
    )
    .await;
    // Ann does take him: nothing but the forgetting stood in the way.
    ann.links.grant(grant_of(&bob));
    bob.links
        .dial_by_key(
            ann.key,
            n(ANN),
            vec![ann.addr.unwrap()],
            Duration::from_secs(10),
            Vec::new(),
        )
        .await
        .expect("Ann admits Bob by the grant");
}

/// A record whose namespace this device does not hold is not dialled and not
/// admitted: it says why, and Ann sees no one. Once the namespace is held
/// again it is dialled.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_record_whose_namespace_is_not_held_is_not_dialled_until_it_is() {
    let (alice, bobs) = (Person::new("/alice").await, Person::new("/bob").await);
    let ann = embedded(&alice, ANN, Setup::inviter()).await;
    let bob = embedded(&bobs, BOB, Setup::dialer()).await;
    ann.validator.adopt_context(Arc::clone(&bobs.ctx)).unwrap();
    ann.links.grant(grant_of(&bob));
    // Bob holds `/bob` and not `/alice`.
    let shelf = Shelf::with(vec![of_ann(&ann, vec![ann.addr.unwrap()], DAY)]);
    bob.links.remember(shelf.clone(), on_this_machine());

    until("bob says why he does not dial", LONG, async || {
        matches!(
            remembered(&bob, ann.key),
            Some((_, RememberedState::NotDialled { .. }))
        )
    })
    .await;
    let Some((_, RememberedState::NotDialled { why })) = remembered(&bob, ann.key) else {
        unreachable!()
    };
    assert!(
        why.contains("/alice/member/laptop") && why.contains("does not hold"),
        "{why}"
    );
    throughout(
        "a namespace not held was dialled",
        Duration::from_secs(2),
        || !linked(&bob, ann.key) && !linked(&ann, bob.key),
    )
    .await;
    assert!(
        shelf.get(&ann.key).is_some(),
        "the record waits for expiry, it is not dropped"
    );

    // Bob adopts Ann's namespace: the record is dialled, at once.
    bob.validator.adopt_context(Arc::clone(&alice.ctx)).unwrap();
    until(
        "bob dials ann once he holds her namespace",
        LONG,
        async || linked(&bob, ann.key) && linked(&ann, bob.key),
    )
    .await;
}

/// An address that another key answers at is no link, and costs a failed dial:
/// a hostile address in the record links no one, and the record's other
/// address still links Ann.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_address_another_key_answers_at_costs_a_failed_dial_and_no_link() {
    let (alice, bobs) = (Person::new("/alice").await, Person::new("/bob").await);
    let (ann, bob) = acquainted(&alice, &bobs).await;
    // Mallory: another device of another person, listening, which would take
    // Bob's link if the address were all that decided.
    let mallory_person = Person::new("/mallory").await;
    let mallory = embedded(&mallory_person, "/mallory/member/laptop", Setup::inviter()).await;
    mallory
        .validator
        .adopt_context(Arc::clone(&bobs.ctx))
        .unwrap();
    mallory.links.grant(grant_of(&bob));

    let hostile = mallory.addr.unwrap();
    let shelf = Shelf::with(vec![of_ann(&ann, vec![hostile], DAY)]);
    bob.links.remember(shelf, on_this_machine());
    // The failed dial is reported: as a redial that comes, or (Bob and Ann
    // share no relay, §17D.2) as no path at all; either way no link.
    until("bob's dial fails", LONG, async || {
        matches!(
            remembered(&bob, ann.key),
            Some((
                _,
                RememberedState::Redialling { .. } | RememberedState::NoPath { .. }
            ))
        )
    })
    .await;
    assert!(
        !linked(&bob, mallory.key),
        "Bob linked the key at the address"
    );
    assert!(!linked(&bob, ann.key));
    assert!(
        !linked(&mallory, bob.key),
        "Mallory's side holds a link from Bob: {:#?}",
        mallory.links.report()
    );
    assert!(!linked(&ann, bob.key));
    // The state the watcher shows is the failure and the next dial.
    let watched = bob.links.watch().current();
    assert!(
        !watched
            .iter()
            .any(|p| p.key == mallory.key && matches!(p.state, LinkState::Up { .. })),
        "{watched:#?}"
    );

    // A record that lists the hostile address first and Ann's second: the dials
    // race, the handshake accepts only the holder of the key, Ann links.
    let (ann2, bob2) = acquainted(&alice, &bobs).await;
    let shelf = Shelf::with(vec![of_ann(&ann2, vec![hostile, ann2.addr.unwrap()], DAY)]);
    bob2.links.remember(shelf, on_this_machine());
    until("the right address links", LONG, async || {
        linked(&bob2, ann2.key) && linked(&ann2, bob2.key)
    })
    .await;
    assert!(!linked(&mallory, bob2.key));
}

/// A peer with no address waits for one and dials it as soon as it learns it:
/// the peer dials in.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_with_no_address_waits_and_learns_one_when_the_peer_dials_in() {
    let (alice, bobs) = (Person::new("/alice").await, Person::new("/bob").await);
    let (ann, bob) = acquainted(&alice, &bobs).await;
    // Ann remembers Bob (who dialled her once) with no address to dial.
    let shelf = Shelf::with(vec![PeerRecord {
        key: bob.key,
        device: n(BOB),
        addresses: Vec::new(),
        last_contact: SystemTime::now() - DAY,
        origin: Direction::Accepted,
        port: None,
    }]);
    ann.links.remember(shelf.clone(), on_this_machine());
    until("ann waits for an address", LONG, async || {
        matches!(
            remembered(&ann, bob.key),
            Some((_, RememberedState::WaitingForAddress))
        )
    })
    .await;
    assert!(!linked(&ann, bob.key));

    // Bob dials in: Ann learns where he came from, and the record is saved.
    bob.links
        .dial_by_key(
            ann.key,
            n(ANN),
            vec![ann.addr.unwrap()],
            Duration::from_secs(10),
            Vec::new(),
        )
        .await
        .expect("Ann admits Bob by the grant");
    until("ann learns an address", LONG, async || {
        shelf.get(&bob.key).is_some_and(|r| !r.addresses.is_empty())
    })
    .await;
    let record = shelf.get(&bob.key).unwrap();
    assert_eq!(record.origin, Direction::Accepted);
    // The record is saved on the contact and the report's state follows it
    // (two writers, one lock each): the state is read once it has caught up.
    until("ann reports bob linked", LONG, async || {
        remembered(&ann, bob.key).is_some_and(|(_, s)| s == RememberedState::Linked)
    })
    .await;
}

/// A remembered peer whose grant ended is refused, and the inviter does not
/// dial it: revoked by the host.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_remembered_peer_whose_grant_ended_is_refused_and_not_dialled_by_the_inviter() {
    let (alice, bobs) = (Person::new("/alice").await, Person::new("/bob").await);
    let (ann, bob) = acquainted(&alice, &bobs).await;
    let ann_shelf = Shelf::default();
    let ann_shelf = Arc::new(ann_shelf);
    ann.links.remember(ann_shelf.clone(), on_this_machine());
    let bob_shelf = Shelf::with(vec![of_ann(&ann, vec![ann.addr.unwrap()], DAY)]);
    bob.links.remember(bob_shelf, on_this_machine());
    until(
        "they link from memory, and Ann learns Bob",
        LONG,
        async || {
            linked(&bob, ann.key) && linked(&ann, bob.key) && ann_shelf.get(&bob.key).is_some()
        },
    )
    .await;
    assert_eq!(ann_shelf.get(&bob.key).unwrap().origin, Direction::Accepted);

    assert!(ann.links.revoke_grants(&bob.key));
    until("the link ends", LONG, async || {
        !linked(&bob, ann.key) && !linked(&ann, bob.key)
    })
    .await;
    // Ann's memory holds Bob and does not dial him: no live grant covers him.
    until("ann says she does not dial him", LONG, async || {
        matches!(
            remembered(&ann, bob.key),
            Some((_, RememberedState::NotDialled { .. }))
        )
    })
    .await;
    let Some((_, RememberedState::NotDialled { why })) = remembered(&ann, bob.key) else {
        unreachable!()
    };
    assert!(why.contains("no live grant"), "{why}");
    // Bob goes on redialling, and is refused saying what ended.
    until("bob's redial is refused", LONG, async || {
        bob.links.watch().current().iter().any(|p| {
            p.key == ann.key
                && matches!(&p.state, LinkState::Down { why, .. }
                    if said(why).contains("the grant ended") && said(why).contains("revoked"))
        })
    })
    .await;
    throughout(
        "a link came up with a grant that ended",
        Duration::from_secs(3),
        || !linked(&bob, ann.key) && !linked(&ann, bob.key),
    )
    .await;
}

/// A removed member's remembered key is refused: Ann's members record drops
/// Bob, her device ends the grant, his link closes, and neither his redial nor
/// anything Ann remembers of him links him again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_removed_members_remembered_key_is_refused() {
    let alice = Person::new("/alice").await;
    let bobs = Person::new("/bob").await;
    let ann = embedded(&alice, ANN, Setup::inviter()).await;
    let bob = embedded(&bobs, BOB, Setup::dialer()).await;
    ann.remembers_in_the_device();
    bob.remembers_in_the_device();
    invited(&ann, &bob, Role::Writer).await;
    let (ann_notes, bob_notes) = (
        DeviceMemory::new(&ann.device),
        DeviceMemory::new(&bob.device),
    );
    until("both devices wrote what they learned", LONG, async || {
        ann_notes.load().is_ok_and(|r| r.len() == 1) && bob_notes.load().is_ok_and(|r| r.len() == 1)
    })
    .await;
    until("they are linked", LONG, async || {
        linked(&ann, bob.key) && linked(&bob, ann.key)
    })
    .await;

    // Ann's offer is spent and has run out, so a device her policy does not
    // serve gets no introduction link to take the place of what ends.
    ann.offers_run_out();
    // Ann's record leaves Bob out.
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
    until("bob's redial is refused saying why", LONG, async || {
        bob.links.watch().current().iter().any(|p| {
            p.key == ann.key
                && matches!(&p.state, LinkState::Down { why, .. }
                    if said(why).contains("the grant ended") && said(why).contains("members record"))
        })
    })
    .await;
    throughout(
        "a removed member linked from memory",
        Duration::from_secs(3),
        || !linked(&bob, ann.key) && !linked(&ann, bob.key),
    )
    .await;
    // Bob's record is still his device's: only the rules refuse him.
    assert!(bob_notes.load().unwrap().iter().any(|r| r.key == ann.key));
    // And the removal stands after both restart.
    let ann = ann.restart(Setup::inviter()).await;
    ann.offers_run_out();
    let bob = bob.restart(Setup::dialer()).await;
    ann.remembers_in_the_device();
    bob.remembers_in_the_device();
    assert!(ann.links.grants().is_empty(), "{:#?}", ann.links.grants());
    throughout(
        "a removed member linked after a restart",
        Duration::from_secs(3),
        || !linked(&bob, ann.key) && !linked(&ann, bob.key),
    )
    .await;
}

/// The notes of a device's store that are not link records — garbage, or a
/// record under another key's name — are dropped; the record that is one is
/// kept and dialled.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn notes_that_are_not_records_are_dropped_and_the_good_one_is_kept() {
    let (alice, bobs) = (Person::new("/alice").await, Person::new("/bob").await);
    let (ann, bob) = acquainted(&alice, &bobs).await;
    let memory = DeviceMemory::new(&bob.device);
    // Bob's store holds a record of Ann the memory wrote ...
    memory
        .save(&of_ann(&ann, vec![ann.addr.unwrap()], DAY))
        .await
        .unwrap();
    // ... a note that decodes to nothing, and one that decodes to a record
    // named by another key.
    let notes = bob.device.local_notes("link-memory");
    notes.put("not-a-key", b"\x01garbage").await.unwrap();
    notes.put(&"ab".repeat(32), b"").await.unwrap();
    let named_wrong = notes.get(&ann.key.to_string()).unwrap().unwrap();
    notes.put(&"cd".repeat(32), &named_wrong).await.unwrap();
    assert_eq!(notes.list().unwrap().len(), 4);

    bob.links.remember(memory, on_this_machine());
    until(
        "the notes that are not records are removed",
        LONG,
        async || notes.list().unwrap().len() == 1,
    )
    .await;
    assert_eq!(notes.list().unwrap()[0].0, ann.key.to_string());
    until("the one record is dialled", LONG, async || {
        linked(&bob, ann.key) && linked(&ann, bob.key)
    })
    .await;
}

/// 64 peers of a store, each with four addresses of its own: 256 sockets on
/// this machine that count the datagrams they are sent.
struct Planted {
    sockets: Vec<std::net::UdpSocket>,
}

impl Planted {
    const PEERS: usize = 64;
    const EACH: usize = 4;

    fn new() -> Planted {
        let sockets = (0..Self::PEERS * Self::EACH)
            .map(|_| {
                let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
                socket.set_nonblocking(true).unwrap();
                socket
            })
            .collect();
        Planted { sockets }
    }

    /// The records a store could hold of them, in a namespace Bob holds.
    fn records(&self) -> Vec<PeerRecord> {
        (0..Self::PEERS)
            .map(|i| PeerRecord {
                key: KeyFingerprint([i as u8 + 1; 32]),
                device: n(&format!("/alice/member/planted{i}")),
                addresses: self.sockets[i * Self::EACH..(i + 1) * Self::EACH]
                    .iter()
                    .map(|s| s.local_addr().unwrap())
                    .collect(),
                last_contact: SystemTime::now() - Duration::from_secs(60),
                origin: Direction::Dialed,
                port: None,
            })
            .collect()
    }

    /// How many of the addresses were sent a datagram (a QUIC Initial).
    fn dialled(&self) -> usize {
        let mut buf = [0u8; 2048];
        self.sockets
            .iter()
            .filter(|s| s.recv_from(&mut buf).is_ok())
            .count()
    }
}

/// L6 (round 6): a store holding 64 peers with four addresses each does not
/// make a start-up send 256 QUIC Initials at once: the redials are staggered,
/// a few peers at a time.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_store_with_many_addresses_is_dialled_a_few_peers_at_a_time() {
    // The default: four peers at a time, each racing its four addresses.
    const AT_ONCE: usize = 4;
    let (alice, bobs) = (Person::new("/alice").await, Person::new("/bob").await);
    let (_ann, bob) = acquainted(&alice, &bobs).await;
    let planted = Planted::new();
    bob.links
        .remember(Shelf::with(planted.records()), on_this_machine());
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let dialled = planted.dialled();
    assert!(dialled > 0, "no remembered peer was dialled at all");
    assert!(
        dialled <= AT_ONCE * Planted::EACH,
        "{dialled} of 256 addresses were dialled within 1.5 s of the start: the start-up is not \
         staggered"
    );
}

/// L6 (round 6): an address in the store that is a loopback or link-local
/// one (a planted 169.254.169.254, say) is never dialled.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_store_cannot_make_this_device_dial_loopback_or_link_local_addresses() {
    let (alice, bobs) = (Person::new("/alice").await, Person::new("/bob").await);
    let (_ann, bob) = acquainted(&alice, &bobs).await;
    let planted = Planted::new();
    bob.links
        .remember(Shelf::with(planted.records()), MemoryOptions::default());
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(
        planted.dialled(),
        0,
        "addresses on this machine were dialled from a store"
    );
    let report = bob.links.report().memory.unwrap();
    assert!(
        report
            .peers
            .iter()
            .all(|p| p.record.addresses.is_empty() && p.state == RememberedState::WaitingForAddress),
        "the peers wait for an address they can use: {:?}",
        report.peers.first()
    );
}

/// The device stops and its port is free again (the old socket may take a
/// moment to go).
async fn stopped(ann: Embedded, port: u16) {
    ann.links.shutdown().await;
    ann.device.shutdown();
    ann.cancel.cancel();
    drop(ann);
    for _ in 0..100 {
        if std::net::UdpSocket::bind(("127.0.0.1", port)).is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("port {port} is not free ten seconds after the device stopped");
}

fn kept_port(ann: &Embedded) -> Option<u16> {
    ann.device
        .local_notes("link-memory")
        .get("listen-port")
        .unwrap()
        .map(|v| u16::from_be_bytes(<[u8; 2]>::try_from(v.as_ref()).expect("2 octets")))
}

/// SHAPES-R7 D, through a real device restarted over the same store: the
/// host keeps no port (its socket is bound on a port the system picks); the
/// device's notes keep the listening port (`link-memory/listen-port`, 2
/// octets), the next start's `remember` binds it again when it is free, and a
/// start with `persist_addresses = false` removes the note and moves nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_listening_port_survives_a_restart_in_the_devices_notes_and_goes_when_addresses_are_not_kept()
 {
    let alice = Person::new("/alice").await;
    let durable = Durable::new(&alice, ANN).await;
    durable.fresh_port.store(true, Ordering::SeqCst);

    // First run: the port the system picked is kept.
    let ann = boot(&durable, Setup::inviter()).await;
    let first = ann.addr.unwrap().port();
    ann.remembers_in_the_device();
    ann.links.shutdown().await;
    assert_eq!(kept_port(&ann), Some(first), "the note holds the port");
    stopped(ann, first).await;

    // Second run: the host binds another port; remember() binds the kept one.
    let ann = boot(&durable, Setup::inviter()).await;
    let picked = ann.addr.unwrap().port();
    assert_ne!(picked, first, "the system picked another port");
    ann.remembers_in_the_device();
    assert_eq!(
        ann.endpoint.as_ref().unwrap().local_addr().unwrap().port(),
        first,
        "the kept port is bound again"
    );
    ann.links.shutdown().await;
    assert_eq!(kept_port(&ann), Some(first), "and still kept");
    stopped(ann, first).await;

    // Third run, addresses not persisted: the note goes, the socket stays.
    let ann = boot(&durable, Setup::inviter()).await;
    let picked = ann.addr.unwrap().port();
    ann.remembers_in_the_device_with(MemoryOptions {
        persist_addresses: false,
        ..on_this_machine()
    });
    ann.links.shutdown().await;
    assert_eq!(
        ann.endpoint.as_ref().unwrap().local_addr().unwrap().port(),
        picked,
        "the kept port is not used when addresses are not kept"
    );
    assert_eq!(kept_port(&ann), None, "the note is removed");
}
