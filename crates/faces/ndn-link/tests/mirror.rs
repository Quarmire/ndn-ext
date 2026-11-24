//! The mirror grant and address freshness on real QUIC links, real forwarders and
//! real data-layer devices (ndn-rs `ndn-link.md` §8.7 rules 16–18, §17C;
//! `data-layer.md` §19.8; SHAPES-R9 B).
//!
//! A grant was built one-sided: the inviter's device admitted the joiner, and the
//! joiner's `own` policy held a grant for no one. Now the joiner's device keeps
//! the mirror of the inviter's grant, `Invites::grants()` lists it, and the link
//! the inviter dials is admitted by it as a grant link for that folder only.
//! With it, an identified peer that opens a link brings the address its record
//! holds up to date (the IP it came from, the port the record holds; the source
//! port is never recorded).
//!
//! Every device sits on a loopback address of its own (`127.0.0.2` …), so that a
//! device can move: the same keys, store and kept port at another address.
//!
//! * **F4, clean and faulty** (ndf-rs scenario F4): Ann (inviter, `own`, listening)
//!   at one address, Bob joined by her code. Ann moves; Bob restarts after the move;
//!   Ann redials Bob and Bob's `own` admits her by the mirror grant; Bob's memory
//!   learns her new IP with the port it holds; after another restart Bob dials it
//!   with nothing handed to him and words cross both ways.
//! * **F3** (the port changed) is `tests/online.rs` and `tests/memory.rs`; the unit
//!   cases of `Book::learn` are in `src/memory.rs`.
//! * Negatives: a key that is not remembered and holds no grant stays refused; a
//!   peer whose entry ended (a held record leaves Bob out, or the host's end) is
//!   refused and changes no record; a mirror grant of one folder carries no names of
//!   another; a link another key opened changes only that key's record; mutual
//!   invitations keep both entries of each device, and the link closes with the
//!   last.
//!
//! **The gate that keeps an unproven peer out of the memory**: `Memory::observe`
//! learns only from `LinkEvent::Up { identified: true, kind: Link }`, i.e. a key
//! proven by the handshake and an identity validated in a held namespace; a link
//! that is refused is no `Up` and learns nothing (the strangers below).

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use ndn_app::EngineAppExt;
use ndn_engine::{EngineBuilder, EngineConfig, ForwarderEngine, ShutdownHandle};
use ndn_face_quic::{KeyFingerprint, LinkEndpoint, LinkKey, LinkKeySource, LinkTransportConfig};
use ndn_heap::{
    Clock, Config, Heap, MembersChange, Node, PutOptions, Readers, Share, Timestamp, Transport,
};
use ndn_invite::{
    Adopting, Departure, Dialing, FirstDialing, Grant, Host as InviteHost, IntroPolicy,
    InviteConfig, InviteError, Invites, Joined, LinkHint, Offer, Role,
};
use ndn_link::{
    ConfiguredEndpoints, DeviceMemory, EngineFaces, HostCandidates, LinkDetail, LinkHints,
    LinkMemory, LinkSetup, LinkTrust, Links, MemoryOptions, PeerRecord, RelayService, ServePolicy,
};
#[cfg(feature = "fault-injection")]
use ndn_link::{FAULTY, FaultPlan, Faults};
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
/// Ann's folder: the one Bob is invited to.
const FOLDER: &str = "/alice/32=data/notebook";
/// Bob's folder: the one Ann is invited to in the mutual invitations, and a
/// folder of Bob's that Ann is never invited to.
const FOLDER_B: &str = "/bob/32=data/projects";
/// Bob's folder Carol joins.
const FOLDER_C: &str = "/bob/32=data/team";
const ANN: &str = "/alice/member/laptop";
const BOB: &str = "/bob/member/phone";
/// Another device of Ann's person: a key Bob holds nothing for.
const STRANGER: &str = "/alice/member/tablet";
const CAROL: &str = "/carol/member/tablet";
const LONG: Duration = Duration::from_secs(240);

const ANN_AT: &str = "127.0.0.2";
const ANN_MOVED_TO: &str = "127.0.0.3";
const BOB_AT: &str = "127.0.0.4";
const CAROL_AT: &str = "127.0.0.5";
const CAROL_MOVED_TO: &str = "127.0.0.6";
const STRANGER_AT: &str = "127.0.0.7";

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

fn ip(s: &str) -> IpAddr {
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
/// grants its device makes and ends (the mirror's included) forwarded to them.
struct Host {
    anchor: Bytes,
    validator: Arc<Validator>,
    engine: ForwarderEngine,
    hints: OnceLock<LinkHints>,
}

impl InviteHost for Host {
    fn anchor(&self) -> Option<Bytes> {
        Some(self.anchor.clone())
    }

    fn adopt<'a>(&'a self, link: &'a TrustEnvelope) -> Adopting<'a> {
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

    fn grant(&self, grant: &Grant) {
        if let Some(hints) = self.hints.get() {
            hints.grant(grant);
        }
    }

    fn departure(&self, departure: &Departure) {
        if let Some(hints) = self.hints.get() {
            hints.depart(departure);
        }
    }

    fn revoke_grant(&self, key: &[u8; 32], folder: &Name) {
        if let Some(hints) = self.hints.get() {
            hints.revoke_grant(key, folder);
        }
    }
}

/// What a device keeps across its runs: its keys, its keyring and trust, its
/// store, its address and the port it listens on.
struct Durable {
    parts: Parts,
    ns: Name,
    anchor: Bytes,
    validator: Arc<Validator>,
    trust: Arc<Trust>,
    store: Arc<MemoryStore>,
    /// Where the device's link socket is bound: the device moves by changing it.
    at: Mutex<IpAddr>,
    /// The port, picked the first time and bound again at every start.
    port: Mutex<u16>,
}

impl Durable {
    async fn new(person: &Person, device: &str, at: &str) -> Arc<Durable> {
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
            at: Mutex::new(ip(at)),
            port: Mutex::new(0),
        })
    }

    /// The listening socket: on a port the system picks the first time, on the
    /// same one at every restart, at the address the device is at now.
    async fn bind(&self) -> Arc<LinkEndpoint> {
        let port = *self.port.lock();
        let at = *self.at.lock();
        for _ in 0..100 {
            match LinkEndpoint::bind(
                SocketAddr::new(at, port),
                Arc::clone(&self.parts.link_key),
                &self.parts.transport,
                true,
            ) {
                Ok(socket) => {
                    *self.port.lock() = socket.local_addr().unwrap().port();
                    return Arc::new(socket);
                }
                Err(_) if port != 0 => tokio::time::sleep(Duration::from_millis(100)).await,
                Err(e) => panic!("cannot bind a link socket: {e}"),
            }
        }
        panic!("the listening port {port} is not free ten seconds after the device stopped");
    }
}

/// A device of a person, alone on a forwarder of its own: its data layer, its
/// links.
struct Embedded {
    node: Node,
    invites: Invites,
    links: Arc<Links>,
    hints: LinkHints,
    key: KeyFingerprint,
    addr: SocketAddr,
    cancel: CancellationToken,
    engine: ForwarderEngine,
    _shutdown: ShutdownHandle,
    durable: Arc<Durable>,
    faulty: bool,
}

impl Drop for Embedded {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

impl Embedded {
    /// The device stops (its links tell the peers, and write what the memory
    /// owes the store) and its port is free again.
    async fn stop(self) -> Arc<Durable> {
        self.links.shutdown().await;
        self.node.shutdown();
        self.cancel.cancel();
        let durable = Arc::clone(&self.durable);
        drop(self);
        let (at, port) = (*durable.at.lock(), *durable.port.lock());
        for _ in 0..100 {
            if std::net::UdpSocket::bind((at, port)).is_ok() {
                return durable;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("port {port} is not free ten seconds after the device stopped");
    }

    /// Stop and start again over what the device kept, where it is now.
    async fn restart(self) -> Embedded {
        let faulty = self.faulty;
        let durable = self.stop().await;
        boot(&durable, faulty).await
    }

    /// Stop, move to `to` (the port stays), and start again there.
    async fn moves_to(self, to: &str) -> Embedded {
        let faulty = self.faulty;
        let durable = self.stop().await;
        *durable.at.lock() = ip(to);
        boot(&durable, faulty).await
    }

    /// Give the links the memory a device keeps in its own store
    /// (`ndf`'s `links.remember(DeviceMemory::new(&device), …)`).
    fn remembers(&self) {
        self.links.remember(
            DeviceMemory::new(self.node.store().clone()),
            on_this_machine(),
        );
    }

    /// What the memory holds of the peer `key` right now (in memory).
    fn holds(&self, key: KeyFingerprint) -> Option<PeerRecord> {
        self.links
            .report()
            .memory
            .expect("the links keep a memory")
            .peers
            .into_iter()
            .find(|p| p.record.key == key)
            .map(|p| p.record)
    }

    /// What the store holds of the peer `key` (written behind).
    fn kept(&self, key: KeyFingerprint) -> Option<PeerRecord> {
        DeviceMemory::new(self.node.store().clone())
            .load()
            .unwrap()
            .into_iter()
            .find(|r| r.key == key)
    }

    /// The space `space` this device has open (made, joined or restored).
    fn heap(&self, space: &Name) -> Heap {
        self.node
            .space(space)
            .unwrap_or_else(|| panic!("{} has not opened {space}", self.durable.ns))
    }

    /// The open space `name` lies in (the longest one prefixing it) and the
    /// path of `name` inside it.
    fn locate(&self, name: &Name) -> Option<(Heap, Name)> {
        let space = self
            .node
            .spaces()
            .into_iter()
            .filter(|space| name.has_prefix(space))
            .max_by_key(Name::len)?;
        let path = Name::from_components(name.components()[space.len()..].iter().cloned());
        Some((self.node.space(&space)?, path))
    }
}

async fn embedded(person: &Person, device: &str, at: &str) -> Embedded {
    boot(&Durable::new(person, device, at).await, false).await
}

/// With `NDN_LINK_TEST_LOG=<file>` (and `RUST_LOG`), the tracing of the run
/// goes to that file, once.
fn log_to_file() {
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

/// Start the device of `durable`: a forwarder, links, a data layer over the
/// store it kept; it listens, under the default policy `own`. `faulty`: the
/// conformance's fault profile on every link of these links.
async fn boot(durable: &Arc<Durable>, faulty: bool) -> Embedded {
    log_to_file();
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .security_profile(SecurityProfile::Disabled)
        .build()
        .await
        .unwrap();
    ndn_namespace::sync_group::carry(&engine, &durable.ns);
    for ctx in durable.validator.keyring().contexts() {
        ndn_namespace::sync_group::carry(&engine, ctx.namespace());
    }
    let socket = durable.bind().await;
    let addr = socket.local_addr().unwrap();
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
            socket: Some(socket),
            transport: durable.parts.transport.clone(),
            relays: Default::default(),
            service: RelayService {
                serve: ServePolicy::Own,
                ..RelayService::default()
            },
            direct: Default::default(),
            reliability: Default::default(),
        },
        cancel.clone(),
    );
    #[cfg(feature = "fault-injection")]
    if faulty {
        links.inject_faults(FaultPlan::new(Faults::parse(FAULTY).unwrap().with_seed(9)));
    }
    #[cfg(not(feature = "fault-injection"))]
    assert!(!faulty, "the faulty cases need --features fault-injection");
    let hints = LinkHints::new(Arc::clone(&links));
    let host = Arc::new(Host {
        anchor: durable.anchor.clone(),
        validator: Arc::clone(&durable.validator),
        engine: engine.clone(),
        hints: OnceLock::new(),
    });
    let _ = host.hints.set(hints.clone());
    let node = Node::start(
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
            ..Config::new()
        },
    )
    .await
    .unwrap();
    let invites = Invites::start(
        &node,
        host,
        IntroPolicy {
            local_candidates: true,
            grant_for: None,
            ..IntroPolicy::new()
        },
        InviteConfig::new(),
    )
    .unwrap();
    hints.serve(&invites);
    Embedded {
        node,
        invites,
        links,
        hints,
        key: durable.parts.fingerprint,
        addr,
        cancel,
        engine,
        durable: Arc::clone(durable),
        faulty,
        _shutdown: shutdown,
    }
}

/// The options of these cases: every device is on this machine, so the
/// loopback addresses they link at are kept (off by default), and a record is
/// written as soon as it changes.
fn on_this_machine() -> MemoryOptions {
    MemoryOptions {
        include_local: true,
        save_interval: Duration::ZERO,
        ..MemoryOptions::default()
    }
}

fn note() -> PutOptions {
    PutOptions::default()
}

fn text(s: &str) -> Bytes {
    Bytes::copy_from_slice(s.as_bytes())
}

/// Whether `on` reads `s` as the value of `name` (a path under a space it has
/// open).
async fn reads(on: &Embedded, name: &Name, s: &str) -> bool {
    let Some((heap, path)) = on.locate(name) else {
        return false;
    };
    matches!(heap.get(&path).await, Ok(Some(item)) if item.bytes[..] == *s.as_bytes())
}

/// `put` as a host does what `NotReady` says (the layer has not seen yet what
/// the put needs: the space's creation, the epoch's key): again until `LONG`
/// has passed. `name` is a path under a space `on` has open.
async fn puts(on: &Embedded, name: &Name, bytes: Bytes) {
    let (heap, path) = on
        .locate(name)
        .unwrap_or_else(|| panic!("{} has opened no space {name} lies in", on.durable.ns));
    let started = Instant::now();
    loop {
        match heap.put(&path, bytes.clone(), note()).await {
            Ok(_) => return,
            Err(e) if e.retry() && started.elapsed() < LONG => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(e) => panic!("put of {name}: {e}"),
        }
    }
}

async fn until(what: &str, limit: Duration, mut done: impl AsyncFnMut() -> bool) {
    let start = Instant::now();
    while !done().await {
        assert!(start.elapsed() < limit, "not within {limit:?}: {what}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// `holds` stays true for `span`: for what must not happen, which no event
/// announces.
async fn throughout(what: &str, span: Duration, mut holds: impl FnMut() -> bool) {
    let start = Instant::now();
    while start.elapsed() < span {
        assert!(holds(), "{what}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// `from` writes a note into `folder` and `to` reads it: words crossed. A put is
/// refused as one to be asked again (`NotReady`) while its device has not seen
/// what it needs, so a put right after a link came up is asked again until it
/// goes through.
async fn words_cross(from: &Embedded, to: &Embedded, folder: &Name, tag: &str) {
    let name = folder.clone().append(tag);
    let words = format!("words {tag}");
    puts(from, &name, text(&words)).await;
    until(&format!("{tag} crosses"), LONG, async || {
        reads(to, &name, &words).await
    })
    .await;
}

/// Both ways, in `folder`.
async fn words_cross_both_ways(a: &Embedded, b: &Embedded, folder: &Name, tag: &str) {
    words_cross(a, b, folder, &format!("{tag}-from-a")).await;
    words_cross(b, a, folder, &format!("{tag}-from-b")).await;
}

/// `folder` of `laptop`'s person, shared with that person alone (once) and
/// with a cover written into it.
async fn shared(laptop: &Embedded, folder: &Name) {
    let heap = match laptop.node.space(folder) {
        Some(heap) => heap,
        None => laptop
            .node
            .create(
                folder,
                Share {
                    readers: Readers::Persons(Vec::new()),
                    writers: Vec::new(),
                },
            )
            .await
            .unwrap(),
    };
    heap.put(&n("/cover"), text("cover by the owner"), note())
        .await
        .unwrap();
}

/// Join with `link` as a host does what `NotReady` says: again with the same
/// code until `limit` has passed.
async fn joins(phone: &Embedded, link: &str, limit: Duration) -> Result<Joined, InviteError> {
    let started = Instant::now();
    loop {
        match phone.invites.join(link).await {
            Err(e) if e.retry() && started.elapsed() < limit => {}
            other => return other,
        }
    }
}

/// `inviter` shares `folder` (once) and invites `joiner` into it as `role`;
/// `joiner` joins.
async fn invites(inviter: &Embedded, joiner: &Embedded, folder: &Name, role: Role) {
    shared(inviter, folder).await;
    let code = inviter
        .invites
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
        .unwrap();
    let joined = joins(joiner, &code.link, Duration::from_secs(90))
        .await
        .unwrap_or_else(|e| {
            panic!(
                "the join failed: {e} ({:?})\njoiner: {:#?}\ninviter: {:#?}",
                e.next(),
                joiner.links.report(),
                inviter.links.report()
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

/// `from` dials `to` by its key and its address now, as a redial of it does.
async fn dials(from: &Embedded, to: &Embedded, device: &str) -> Result<(), LinkDetail> {
    from.links
        .dial_by_key(
            to.key,
            n(device),
            vec![to.addr],
            Duration::from_secs(10),
            Vec::new(),
        )
        .await
}

/// The name of the newest entry of `collection` that `device` (the name of
/// `on`'s device) wrote, as `on` holds it.
async fn newest_entry(on: &Embedded, device: &str, path: &Name) -> Name {
    let (heap, relative) = on
        .locate(path)
        .unwrap_or_else(|| panic!("{} has opened no space {path} lies in", on.durable.ns));
    match heap.get(&relative).await {
        Ok(Some(item)) => {
            assert_eq!(item.id.device, n(device), "{path} was written by {device}");
            ndn_heap::wire::log_name(&item.id.device, heap.name(), item.id.seq)
        }
        other => panic!("{path} has no entry on {device}: {other:?}"),
    }
}

/// Whether `on` is answered a Data for `name` when it asks **over its link to
/// the device with `key`** (the Interest is pinned to that link's face, so a
/// missing route never stands in for a refusal at the link).
async fn asks(on: &Embedded, key: KeyFingerprint, name: &Name) -> bool {
    let face = on
        .links
        .report()
        .links
        .iter()
        .filter(|l| l.key == Some(key))
        .flat_map(|l| l.paths.iter().map(|p| p.face))
        .next();
    let Some(face) = face else {
        return false;
    };
    let builder =
        ndn_packet::encode::InterestBuilder::new(name.clone()).lifetime(Duration::from_secs(3));
    let mut consumer = on.engine.app_consumer(on.cancel.child_token());
    consumer.fetch_with_on(face, builder).await.is_ok()
}

/// A record as the memory keeps it, without the clock: what must not change.
fn shape(record: &PeerRecord) -> (Name, Vec<SocketAddr>, Option<u16>) {
    (record.device.clone(), record.addresses.clone(), record.port)
}

/// Ann (at `ANN_AT`) invited Bob (at `BOB_AT`) into her notebook; both
/// remember; the link is up and Bob's memory holds Ann at the address she
/// joined from, and Ann's holds Bob. `faulty`: with the fault profile.
async fn ann_invited_bob(alice: &Person, bobs: &Person, faulty: bool) -> (Embedded, Embedded) {
    let ann = boot(&Durable::new(alice, ANN, ANN_AT).await, faulty).await;
    let bob = boot(&Durable::new(bobs, BOB, BOB_AT).await, faulty).await;
    ann.remembers();
    bob.remembers();
    invites(&ann, &bob, &n(FOLDER), Role::Writer).await;
    until("both devices wrote what they learned", LONG, async || {
        ann.kept(bob.key).is_some_and(|r| !r.addresses.is_empty())
            && bob.kept(ann.key).is_some_and(|r| !r.addresses.is_empty())
    })
    .await;
    let at_ann = SocketAddr::new(ip(ANN_AT), ann.addr.port());
    assert_eq!(
        bob.kept(ann.key).unwrap().addresses,
        vec![at_ann],
        "Bob kept the address that worked"
    );
    until("both are linked", LONG, async || {
        linked(&ann, bob.key) && linked(&bob, ann.key)
    })
    .await;
    (ann, bob)
}

// ---- F4 ----------------------------------------------------------------------------------------

/// SHAPES-R9 B, ndf-rs scenario F4: Ann's address changes, Bob restarts after
/// the move. Neither can start the link (Bob's memory holds her old address; her
/// redial of Bob is refused by Bob's `own` policy unless Bob holds the mirror of
/// her grant); with the mirror her redial is admitted as a grant link for her
/// folder only, Bob's memory learns her new IP with the port the record holds,
/// and after another restart Bob dials it with nothing handed to him.
async fn laptop_moves_and_the_joiner_restarts(faulty: bool) {
    let alice = Person::new("/alice").await;
    let bobs = Person::new("/bob").await;
    let (ann, bob) = ann_invited_bob(&alice, &bobs, faulty).await;
    let folder = n(FOLDER);
    let port = ann.addr.port();
    let before = bob.kept(ann.key).unwrap();
    assert_eq!(before.port, Some(port));
    words_cross_both_ways(&ann, &bob, &folder, "before").await;

    // Bob's device holds the mirror of Ann's grant, which is what admits her.
    let mirrored = bob.invites.grants();
    assert_eq!(mirrored.len(), 1, "{mirrored:#?}");
    assert_eq!(mirrored[0].key, ann.key.0);
    assert_eq!(mirrored[0].folder, folder);
    assert_eq!(mirrored[0].namespaces, vec![n("/alice")]);

    // The move: Ann stops and is at another address (the same port); Bob
    // restarts after it. Bob's record names the old address; he dials it and
    // nobody answers.
    let ann_key = ann.key;
    let ann_stopped = ann.stop().await;
    *ann_stopped.at.lock() = ip(ANN_MOVED_TO);
    let bob = bob.restart().await;
    bob.remembers();
    assert_eq!(
        shape(&bob.holds(ann_key).expect("Bob remembers Ann")).1,
        before.addresses,
        "nothing told Bob the new address yet"
    );
    let ann = boot(&ann_stopped, faulty).await;
    assert_eq!(ann.addr, SocketAddr::new(ip(ANN_MOVED_TO), port));
    ann.remembers();

    // Ann redials Bob from her memory; Bob's `own` admits her by the mirror.
    until("ann's redial is admitted", LONG, async || {
        linked(&ann, bob.key) && linked(&bob, ann.key)
    })
    .await;
    let report = bob.links.report();
    let link = report
        .links
        .iter()
        .find(|l| l.key == Some(ann.key))
        .expect("linked");
    let granted = link.granted.as_ref().expect("Ann's link is a grant link");
    assert_eq!(granted.folder, folder, "for her folder only");
    assert_eq!(granted.key, ann.key);

    // Bob's memory learns where she is now: her new IP with the port the record
    // holds, and the old address behind it. Her source port is nowhere.
    let moved = SocketAddr::new(ip(ANN_MOVED_TO), port);
    let old = SocketAddr::new(ip(ANN_AT), port);
    until("bob learns her new address", LONG, async || {
        bob.holds(ann.key)
            .is_some_and(|r| r.addresses.first() == Some(&moved))
            && bob
                .kept(ann.key)
                .is_some_and(|r| r.addresses.first() == Some(&moved))
    })
    .await;
    let kept = bob.kept(ann.key).unwrap();
    assert_eq!(
        kept.addresses,
        vec![moved, old],
        "the new address first, with the held port"
    );
    assert_eq!(
        kept.port,
        Some(port),
        "the held port is not the source port"
    );
    words_cross_both_ways(&ann, &bob, &folder, "after-ann-dialled").await;

    // Another restart of Bob, with nothing handed to him: Ann forgets Bob (so that
    // she does not redial) and Bob dials the address his memory holds.
    ann.links.forget(&bob.key).await;
    let bob = bob.restart().await;
    bob.remembers();
    until("bob dials her new address", LONG, async || {
        linked(&ann, bob.key) && linked(&bob, ann.key)
    })
    .await;
    let remote = bob
        .links
        .report()
        .links
        .iter()
        .find(|l| l.key == Some(ann.key))
        .and_then(|l| l.paths.first().and_then(|p| p.remote))
        .expect("Bob's path to Ann");
    assert_eq!(remote, moved, "Bob dialled where his memory holds her");
    words_cross_both_ways(&ann, &bob, &folder, "after-bob-dialled").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn after_the_laptop_moved_and_the_joiner_restarted_her_redial_is_admitted_and_his_memory_follows()
 {
    laptop_moves_and_the_joiner_restarts(false).await;
}

#[cfg(feature = "fault-injection")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn after_the_laptop_moved_and_the_joiner_restarted_the_same_on_a_faulty_network() {
    laptop_moves_and_the_joiner_restarts(true).await;
}

/// F3 and F4 together: Ann comes back at another address **and** on another
/// port, and dials Bob from her new socket. Her source port is her own choice:
/// Bob's record gets her new IP with the port it holds, and her source port is
/// nowhere in it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_source_port_of_a_link_the_peer_opened_is_never_recorded() {
    let alice = Person::new("/alice").await;
    let bobs = Person::new("/bob").await;
    let (ann, bob) = ann_invited_bob(&alice, &bobs, false).await;
    let port = ann.addr.port();
    let ann_key = ann.key;

    let ann_stopped = ann.stop().await;
    *ann_stopped.at.lock() = ip(ANN_MOVED_TO);
    *ann_stopped.port.lock() = 0;
    let bob = bob.restart().await;
    bob.remembers();
    // Ann does not remember here: her kept port would be bound again.
    let ann = boot(&ann_stopped, false).await;
    assert_ne!(ann.addr.port(), port, "Ann is on another port");
    dials(&ann, &bob, BOB)
        .await
        .expect("Bob's mirror admits Ann at her new address");

    let moved = SocketAddr::new(ip(ANN_MOVED_TO), port);
    until("bob learns her new IP", LONG, async || {
        bob.holds(ann_key)
            .is_some_and(|r| r.addresses.first() == Some(&moved))
    })
    .await;
    let held = bob.holds(ann_key).unwrap();
    assert_eq!(
        held.addresses,
        vec![moved, SocketAddr::new(ip(ANN_AT), port)],
        "the new IP with the held port"
    );
    assert_eq!(held.port, Some(port));
    assert!(
        held.addresses.iter().all(|a| a.port() != ann.addr.port()),
        "her source port was recorded: {:?}",
        held.addresses
    );
}

// ---- negatives ---------------------------------------------------------------------------------

/// Ann's members record for `folder` again, with `writers` (and the same
/// people as readers): whoever the record no longer lists is let go of it.
async fn reshare(ann: &Embedded, folder: &Name, writers: &[Name]) {
    let heap = ann.heap(folder);
    let members = heap.members();
    let readers = match &members.readers {
        Readers::Persons(persons) => persons.clone(),
        Readers::Anyone => Vec::new(),
    };
    let listed: std::collections::BTreeSet<&Name> =
        members.writers.iter().chain(&readers).collect();
    let remove = listed
        .into_iter()
        .filter(|p| **p != members.owner && !writers.contains(p))
        .cloned()
        .collect();
    let add = writers
        .iter()
        .filter(|w| **w != members.owner && !members.writers.contains(w))
        .cloned()
        .collect::<Vec<_>>();
    heap.change(MembersChange {
        add_writers: add.clone(),
        add_readers: add,
        remove,
    })
    .await
    .unwrap();
}

/// Ann invited Bob; Bob restarts and does not remember anyone (his links hold
/// what his device derives and no record), so no link of his is dialled: Ann
/// redials him from her memory, and it is a link Bob's `own` admits by the
/// mirror alone.
async fn ann_redials_bob(alice: &Person, bobs: &Person) -> (Embedded, Embedded) {
    let (ann, bob) = ann_invited_bob(alice, bobs, false).await;
    let bob = bob.restart().await;
    until("ann's redial is admitted by the mirror", LONG, async || {
        linked(&ann, bob.key) && linked(&bob, ann.key)
    })
    .await;
    let report = bob.links.report();
    let link = report
        .links
        .iter()
        .find(|l| l.key == Some(ann.key))
        .expect("linked");
    assert!(
        link.granted.is_some(),
        "Bob's link of Ann is the mirror's: {link:#?}"
    );
    (ann, bob)
}

/// A key that is not remembered and holds no grant stays refused: another device
/// of Ann's person (a valid certificate of a namespace Bob holds, and no entry)
/// is no one Bob's mirror admits, and it makes no record. Ann, whose key the
/// mirror lists, is admitted on the same device.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_key_that_is_not_remembered_and_holds_no_grant_stays_refused() {
    let alice = Person::new("/alice").await;
    let bobs = Person::new("/bob").await;
    let (ann, bob) = ann_invited_bob(&alice, &bobs, false).await;
    let bob = bob.restart().await;
    bob.remembers();
    until("ann is linked again", LONG, async || {
        linked(&ann, bob.key) && linked(&bob, ann.key)
    })
    .await;
    let stranger = boot(&Durable::new(&alice, STRANGER, STRANGER_AT).await, false).await;

    let refused = dials(&stranger, &bob, BOB)
        .await
        .expect_err("a key with no entry was linked");
    let why = said(&refused);
    assert!(
        why.contains(STRANGER) && why.contains("holds no certificate in"),
        "the refusal does not say who was refused and why: {why}"
    );
    assert!(
        why.contains("inviting you"),
        "the refusal does not say that an invitation grants a link: {why}"
    );
    assert!(!linked(&bob, stranger.key), "{:#?}", bob.links.report());
    // The gate: a refused link is no `Up` and learns nothing, so no record.
    throughout(
        "a refused key was remembered",
        Duration::from_secs(2),
        || bob.holds(stranger.key).is_none() && bob.kept(stranger.key).is_none(),
    )
    .await;
    // Ann is still the one the mirror admits.
    assert!(linked(&bob, ann.key));
}

/// A held record that leaves Bob out ends his mirror entry (the inviter tells
/// him): Ann, at another address now, is refused with the grant-ended words and
/// Bob's record of her does not change.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_whose_entry_ended_by_a_record_is_refused_and_changes_no_record() {
    let alice = Person::new("/alice").await;
    let bobs = Person::new("/bob").await;
    let (ann, bob) = ann_invited_bob(&alice, &bobs, false).await;
    let before = shape(&bob.holds(ann.key).expect("Bob remembers Ann"));

    reshare(&ann, &n(FOLDER), &[n("/alice")]).await;
    until("bob's device ends the mirror entry", LONG, async || {
        bob.invites.grants().is_empty()
    })
    .await;
    until("bob's links end the mirror entry", LONG, async || {
        bob.links.grants().is_empty()
    })
    .await;

    let ann = ann.moves_to(ANN_MOVED_TO).await;
    let refused = dials(&ann, &bob, BOB)
        .await
        .expect_err("an ended entry linked");
    let why = said(&refused);
    assert!(
        why.contains("the grant ended"),
        "the refusal does not say that the grant ended: {why}"
    );
    assert!(!linked(&bob, ann.key), "{:#?}", bob.links.report());
    throughout(
        "a refused link changed the record",
        Duration::from_secs(2),
        || {
            shape(&bob.holds(ann.key).unwrap()) == before
                && bob.kept(ann.key).is_some_and(|r| shape(&r) == before)
        },
    )
    .await;
}

/// The host's own end of the mirror (`end_grant`) is the same: Ann is refused
/// with the grant-ended words, and Bob's record of her does not change.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_whose_entry_the_host_ended_is_refused_and_changes_no_record() {
    let alice = Person::new("/alice").await;
    let bobs = Person::new("/bob").await;
    let (ann, bob) = ann_invited_bob(&alice, &bobs, false).await;
    let before = shape(&bob.holds(ann.key).expect("Bob remembers Ann"));

    assert!(
        bob.hints
            .end_grant(&bob.invites, &ann.key.0)
            .await
            .expect("the device made the end durable"),
        "no entry was in force"
    );
    assert!(
        bob.invites.grants().is_empty(),
        "{:#?}",
        bob.invites.grants()
    );
    assert!(bob.links.grants().is_empty());

    let ann = ann.moves_to(ANN_MOVED_TO).await;
    let refused = dials(&ann, &bob, BOB)
        .await
        .expect_err("an ended entry linked");
    let why = said(&refused);
    assert!(
        why.contains("the grant ended"),
        "the refusal does not say that the grant ended: {why}"
    );
    assert!(!linked(&bob, ann.key), "{:#?}", bob.links.report());
    throughout(
        "a refused link changed the record",
        Duration::from_secs(2),
        || {
            shape(&bob.holds(ann.key).unwrap()) == before
                && bob.kept(ann.key).is_some_and(|r| shape(&r) == before)
        },
    )
    .await;
}

/// A mirror grant of Ann's folder admits her for that folder's names only: over
/// the link she dialled Bob answers the folder's entry, and not an unsealed
/// collection of his own nor an entry of another folder of his.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_mirror_grant_of_one_folder_does_not_carry_the_names_of_another() {
    let alice = Person::new("/alice").await;
    let bobs = Person::new("/bob").await;
    let (ann, bob) = ann_redials_bob(&alice, &bobs).await;
    let (folder, other) = (n(FOLDER), n(FOLDER_B));

    // Bob's own things: a folder of his that Ann was never invited to, and an
    // unsealed collection of his namespace outside any folder.
    shared(&bob, &other).await;
    let diary = n("/bob/32=data/diary");
    let public = bob
        .node
        .create(
            &diary,
            Share {
                readers: Readers::Anyone,
                writers: Vec::new(),
            },
        )
        .await
        .unwrap();
    public
        .put(&n("/page"), Bytes::from_static(b"bob's diary"), note())
        .await
        .unwrap();
    let diary_entry = newest_entry(&bob, BOB, &diary.append("page")).await;
    let other_entry = newest_entry(&bob, BOB, &other.clone().append("cover")).await;
    let folder_entry = newest_entry(&bob, ANN, &folder.clone().append("cover")).await;

    until("ann is answered the folder's entry", LONG, async || {
        asks(&ann, bob.key, &folder_entry).await
    })
    .await;
    assert!(
        !asks(&ann, bob.key, &other_entry).await,
        "{other_entry}, an entry of a folder Ann is not in, was answered over the mirror link"
    );
    assert!(
        !asks(&ann, bob.key, &diary_entry).await,
        "{diary_entry}, an unsealed collection outside the folder, was answered over the mirror link"
    );
}

/// A link another key opened changes only that key's record: Carol (invited by
/// Bob to his team folder, her own record in Bob's memory) comes back from another
/// address and Bob's record of her moves; his record of Ann stays as it was.
/// (The record is keyed by the key the handshake proved; QUIC validates the path
/// before the handshake ends, so a forged source address never reaches `learn`.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_link_another_key_opened_changes_only_that_keys_record() {
    let alice = Person::new("/alice").await;
    let bobs = Person::new("/bob").await;
    let carols = Person::new("/carol").await;
    let (ann, bob) = ann_invited_bob(&alice, &bobs, false).await;
    let carol = boot(&Durable::new(&carols, CAROL, CAROL_AT).await, false).await;
    carol.remembers();
    invites(&bob, &carol, &n(FOLDER_C), Role::Writer).await;
    until("bob remembers carol and is linked", LONG, async || {
        bob.kept(carol.key).is_some_and(|r| !r.addresses.is_empty()) && linked(&bob, carol.key)
    })
    .await;
    let port = carol.addr.port();
    let ann_before = shape(&bob.holds(ann.key).unwrap());
    assert_eq!(
        bob.holds(carol.key).unwrap().addresses,
        vec![SocketAddr::new(ip(CAROL_AT), port)]
    );

    let carol = carol.moves_to(CAROL_MOVED_TO).await;
    carol.remembers();
    let moved = SocketAddr::new(ip(CAROL_MOVED_TO), port);
    until("bob learns carol's new address", LONG, async || {
        bob.holds(carol.key)
            .is_some_and(|r| r.addresses.first() == Some(&moved))
    })
    .await;
    assert_eq!(
        bob.holds(carol.key).unwrap().addresses,
        vec![moved, SocketAddr::new(ip(CAROL_AT), port)]
    );
    assert_eq!(
        shape(&bob.holds(ann.key).unwrap()),
        ann_before,
        "a link Carol opened changed Ann's record"
    );
    assert!(linked(&bob, ann.key));
}

// ---- mutual invitations -----------------------------------------------------------------------

/// Ann invited Bob to A and Bob invited Ann to B: each device holds an inviter
/// entry of one folder and a mirror entry of the other for the same peer key.
/// They are entries of different folders, so ending one leaves the other (and the
/// link) up, and the link closes when the last entry ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mutual_invitations_keep_both_entries_and_the_link_closes_with_the_last() {
    let alice = Person::new("/alice").await;
    let bobs = Person::new("/bob").await;
    let ann = embedded(&alice, ANN, ANN_AT).await;
    let bob = embedded(&bobs, BOB, BOB_AT).await;
    let (a, b) = (n(FOLDER), n(FOLDER_B));
    invites(&ann, &bob, &a, Role::Writer).await;
    invites(&bob, &ann, &b, Role::Writer).await;
    until("both are linked", LONG, async || {
        linked(&ann, bob.key) && linked(&bob, ann.key)
    })
    .await;

    // Both entries of each device, for the one peer key: the inviter's note of
    // one folder and the mirror of the other.
    let mut folders = vec![a.clone(), b.clone()];
    folders.sort();
    for (on, peer, who) in [(&ann, &bob, "ann"), (&bob, &ann, "bob")] {
        until(&format!("{who} holds both entries"), LONG, async || {
            on.links.grants().len() == 2
        })
        .await;
        assert_eq!(
            on.invites.grants().len(),
            2,
            "{who}: {:#?}",
            on.invites.grants()
        );
        assert_eq!(
            on.links.grants().len(),
            2,
            "{who}: {:#?}",
            on.links.grants()
        );
        assert!(on.invites.grants().iter().all(|g| g.key == peer.key.0));
        let listed: Vec<Name> = on.links.grants().iter().map(|g| g.folder.clone()).collect();
        assert_eq!(
            listed, folders,
            "{who}: the links hold them sorted by folder"
        );
    }
    words_cross_both_ways(&ann, &bob, &a, "a").await;
    words_cross_both_ways(&ann, &bob, &b, "b").await;

    // The host ends Bob's entry of A on Ann's side: her mirror entry of B stands,
    // so does the link, and B still carries words both ways.
    assert!(
        ann.hints
            .end_grant_in(&ann.invites, &bob.key.0, &a)
            .await
            .unwrap()
    );
    let left = ann.invites.grants();
    assert_eq!(left.len(), 1, "{left:#?}");
    assert_eq!(left[0].folder, b);
    assert_eq!(ann.links.grants().len(), 1);
    throughout(
        "ending one folder's entry closed the link of the other",
        Duration::from_secs(3),
        || linked(&ann, bob.key) && linked(&bob, ann.key),
    )
    .await;
    words_cross_both_ways(&ann, &bob, &b, "b-after").await;
    // Bob's entries are untouched: ending an entry of Ann's device is not a record.
    assert_eq!(bob.invites.grants().len(), 2);

    // The last entry of Ann's ends: the link closes.
    assert!(
        ann.hints
            .end_grant_in(&ann.invites, &bob.key.0, &b)
            .await
            .unwrap()
    );
    assert!(ann.invites.grants().is_empty());
    until("the link closes with the last entry", LONG, async || {
        !linked(&ann, bob.key) && !linked(&bob, ann.key)
    })
    .await;
}
