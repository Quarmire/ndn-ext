//! A person's device on a forwarder of its own, as a host assembles one: the identity (a
//! self-certifying person, `/user/<0xA1 hash of the key>`, and one device of theirs), the
//! embedded forwarder, the validator, a **disk** store (fjall, under a directory the caller
//! picks), the introductions, and the links (`ndn-link`, by an invitation's hint). The
//! ladder's rungs 5 and 6 run the data layer directly on two of these, one per process:
//! `ndn_heap::Node` and `ndn_invite::Invites`, the introductions the `ndn_invite::Host` (and
//! `ndn_heap::Adopter`) below over `ndn_link::LinkHints`, assembled from one identity, forwarder,
//! validator, trust and link socket.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use futures::Stream;
use ndn_app::EngineAppExt;
use ndn_engine::{EngineBuilder, EngineConfig, ForwarderEngine, ShutdownHandle};
use ndn_face_quic::{KeyFingerprint, LinkEndpoint, LinkKey, LinkKeySource, LinkTransportConfig};
use ndn_link::{
    ConfiguredEndpoints, DeviceMemory, EngineFaces, HostCandidates, LinkHints, LinkSetup,
    LinkTrust, Links, MemoryOptions, RelayService,
};
use ndn_namespace::{ContextStore, StoredContext, sync_group};
use ndn_packet::{Data, Name, NameComponent};
use ndn_security::cert_name::{DEFAULT_ISSUER, SELF_ISSUER, new_cert_name};
use ndn_security::self_certifying::Genesis;
use ndn_security::{
    Certificate, Keyring, ScopedContext, SecurityManager, SecurityProfile, SignedTrustContext,
    Validator, anchor_fingerprint, encode_cert_data,
};
use ndn_sync::DataStore;
use ndn_trust_envelope::TrustEnvelope;
use tokio_util::sync::CancellationToken;

/// The layer's crate, as the report names it.
pub const NAME: &str = "ndn-heap";

/// The piece size a value is asked in. `ndn_heap`'s `wire::pieces::CHUNK` (4096) is crate-private,
/// so its value is mirrored here, as the re-expression gaps are.
pub const CHUNK: usize = 4096;

/// How many pieces the layer has in flight at once (`Config::window`).
pub fn window() -> usize {
    ndn_heap::Config::new().window
}

/// The lifetime of the layer's Interests (`Config::lifetime`).
pub fn lifetime() -> Duration {
    ndn_heap::Config::new().lifetime
}

/// How long the person's anchor and the device's certificate last, and how long before now they
/// are valid from (so a peer whose clock stands behind accepts them), in milliseconds.
const VALIDITY_MS: u64 = 10 * 365 * 24 * 3600 * 1000;
const BEHIND_MS: u64 = 365 * 24 * 3600 * 1000;

fn validity() -> (u64, u64) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX));
    (
        now.saturating_sub(BEHIND_MS * 1_000_000),
        now.saturating_add(VALIDITY_MS * 1_000_000),
    )
}

/// What a host does for introductions, whichever layer asks: this person's trust context as
/// the anchor an offer carries, other people's adopted from an introduction (for the
/// process's life; the bench keeps nothing of them on disk), and a person adopted for one
/// space alone.
struct Core {
    anchor: Bytes,
    validator: Arc<Validator>,
    engine: ForwarderEngine,
    scoped: Mutex<HashSet<Name>>,
}

const NO_LINK: &str = "this device is not linked: it has no way to reach the inviter";

impl Core {
    /// Serve this person's trust context by name on the forwarder, until `cancel`: what another
    /// member's device fetches to adopt this person for the folders they share.
    fn publish(&self, cancel: CancellationToken) {
        let (face, publisher) = ndn_namespace::publish::prepare(
            &Own(self.anchor.clone()),
            self.engine.faces().alloc_id(),
        );
        self.engine.add_face(face, cancel);
        publisher.spawn(&self.engine);
    }

    async fn adopt(&self, link: &TrustEnvelope) -> Result<(), String> {
        let TrustEnvelope::Anchor {
            namespace: Some(ns),
            fingerprint: Some(fingerprint),
            ..
        } = link
        else {
            return Err("not an anchor link naming its namespace and fingerprint".into());
        };
        let ns: Name = ns
            .parse()
            .map_err(|_| format!("the anchor link names {ns}, which is no name"))?;
        let keyring = self.validator.keyring();
        match keyring
            .contexts()
            .into_iter()
            .find(|c| *c.namespace() == ns)
        {
            Some(held)
                if held
                    .anchors()
                    .iter()
                    .any(|a| anchor_fingerprint(a.value()) == *fingerprint) =>
            {
                Ok(())
            }
            Some(_) => Err(format!(
                "this device trusts {ns} under another anchor than the link's"
            )),
            None => {
                ndn_cert::adopt_anchor_envelope(keyring, link).map_err(|e| e.to_string())?;
                sync_group::carry(&self.engine, &ns);
                Ok(())
            }
        }
    }

    /// A member of a folder whose namespace this device holds no context of: fetched by name and
    /// adopted for that folder alone; its data and its sync group are carried until let go.
    async fn adopt_scoped(
        &self,
        namespace: &Name,
        held: Option<&ScopedContext>,
    ) -> Result<ScopedContext, String> {
        let scoped = ndn_identity::adopt_scoped_via_engine(&self.engine, namespace, held)
            .await
            .map_err(|e| e.to_string())?;
        if self
            .scoped
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(namespace.clone())
        {
            self.engine
                .transit()
                .add(namespace, || sync_group::carry(&self.engine, namespace));
        }
        Ok(scoped)
    }

    fn release_scoped(&self, namespace: &Name) {
        if self
            .scoped
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(namespace)
        {
            self.engine
                .transit()
                .remove(namespace, || sync_group::release(&self.engine, namespace));
        }
    }
}

/// What this device serves by name of its person's trust context: the one version it keeps.
struct Own(Bytes);

impl Own {
    fn stored(&self) -> Vec<StoredContext> {
        let read = Data::decode(self.0.clone())
            .map_err(|e| format!("{e:?}"))
            .and_then(|d| {
                ndn_cert::open_signed_context(&d)
                    .map(|(c, _)| (c, d))
                    .map_err(|e| e.to_string())
            });
        vec![StoredContext {
            location: "this person's trust context".into(),
            read,
        }]
    }
}

impl ContextStore for Own {
    fn location(&self) -> String {
        "this person's trust context".into()
    }
    fn persist(&self, ctx: &SignedTrustContext, _data: &Data) -> Result<String, String> {
        Err(format!(
            "{} version {} is not kept here: a device serves only its person's own trust context",
            ctx.namespace(),
            ctx.version()
        ))
    }
    fn stored_contexts(&self) -> Result<Vec<StoredContext>, String> {
        Ok(self.stored())
    }
    fn stored_versions(&self, namespace: &Name) -> Result<Vec<StoredContext>, String> {
        Ok(self
            .stored()
            .into_iter()
            .filter(|s| {
                s.read
                    .as_ref()
                    .is_ok_and(|(c, _)| c.namespace() == namespace)
            })
            .collect())
    }
    fn holds_root_key(&self, ctx: &SignedTrustContext) -> bool {
        self.stored().iter().any(|s| {
            s.read
                .as_ref()
                .is_ok_and(|(c, _)| c.namespace() == ctx.namespace())
        })
    }
    fn persist_cut_manifest(&self, namespace: &Name, _wire: &Bytes) -> Result<String, String> {
        Err(format!("{namespace} revokes nothing here: no cut is kept"))
    }
    fn stored_cut_manifests(&self, _namespace: &Name) -> Result<Vec<Bytes>, String> {
        Ok(Vec::new())
    }
}

// ---- the introductions ------------------------------------------------------------------------------------------------
/// The device's introductions: `ndn_invite::Host` and `ndn_heap::Adopter` over the common
/// core and `ndn_link::LinkHints`.
struct Intro {
    core: Core,
    hints: OnceLock<LinkHints>,
}

impl ndn_invite::Host for Intro {
    fn anchor(&self) -> Option<Bytes> {
        Some(self.core.anchor.clone())
    }

    fn adopt<'a>(&'a self, link: &'a TrustEnvelope) -> ndn_invite::Adopting<'a> {
        Box::pin(self.core.adopt(link))
    }

    fn link_hint(&self) -> Option<ndn_invite::LinkHint> {
        self.hints.get().and_then(LinkHints::hint)
    }

    fn dial<'a>(
        &'a self,
        hint: &'a ndn_invite::LinkHint,
        inviter: &'a Name,
        within: Duration,
    ) -> ndn_invite::Dialing<'a> {
        match self.hints.get() {
            Some(hints) => hints.dial(hint, inviter, within),
            None => Box::pin(async { Err(NO_LINK.to_owned()) }),
        }
    }

    fn dial_first<'a>(
        &'a self,
        inviter: &'a Name,
        addr: SocketAddr,
        within: Duration,
    ) -> ndn_invite::FirstDialing<'a> {
        match self.hints.get() {
            Some(hints) => hints.dial_first(inviter, addr, within),
            None => Box::pin(async { Err(NO_LINK.to_owned()) }),
        }
    }

    fn undial(&self, hint: &ndn_invite::LinkHint, inviter: &Name) {
        if let Some(hints) = self.hints.get() {
            hints.undial(hint, inviter);
        }
    }

    fn grant(&self, grant: &ndn_invite::Grant) {
        if let Some(hints) = self.hints.get() {
            hints.grant(grant);
        }
    }

    fn revoke_grant(&self, key: &[u8; 32], folder: &Name) {
        if let Some(hints) = self.hints.get() {
            hints.revoke_grant(key, folder);
        }
    }

    fn departure(&self, departure: &ndn_invite::Departure) {
        if let Some(hints) = self.hints.get() {
            hints.depart(departure);
        }
    }
}

impl ndn_heap::Adopter for Intro {
    fn adopt_scoped<'a>(
        &'a self,
        namespace: &'a Name,
        held: Option<&'a ScopedContext>,
    ) -> ndn_heap::Scoping<'a> {
        Box::pin(self.core.adopt_scoped(namespace, held))
    }

    fn release_scoped(&self, namespace: &Name) {
        self.core.release_scoped(namespace);
    }
}

/// What the link judges the others' certificates by: the device's keyring and validator.
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

// ---- the identity and forwarder ---------------------------------------------------------------------------------------
/// A person and one device of theirs on a forwarder: everything but the data layer and the links.
struct Base {
    ns: Name,
    device_name: Name,
    keys: Arc<SecurityManager>,
    validator: Arc<Validator>,
    engine: ForwarderEngine,
    shutdown: ShutdownHandle,
    cancel: CancellationToken,
    node: ndn_app::Node,
    sync: Arc<dyn ndn_app::Connection>,
    /// The person's signed trust context, whole.
    anchor: Bytes,
    /// The device's certificate, as the Data it was issued in.
    device_cert: Bytes,
}

impl Base {
    /// The person made from `seed` (their namespace follows from it) and their device `d<seed>`.
    async fn new(seed: u8) -> Base {
        let person_seed = [seed; 32];
        let device_seed = [seed.wrapping_add(1); 32];
        let ns = ndn_cert::GenesisKey::from_seed(person_seed).namespace();

        // The person's key signs the context and certifies the device; a device never signs as its
        // namespace.
        let ns_keys = SecurityManager::new();
        let ns_key = ns_keys
            .generate_ed25519_from_seed(ns.clone().append("KEY").append("1"), &person_seed)
            .unwrap();
        let root = ns_keys.get_signer_sync(&ns_key).unwrap();
        let public = root.public_key().unwrap();
        let (from, until) = validity();
        let anchor = encode_cert_data(
            &new_cert_name(&ns_key, SELF_ISSUER),
            &public,
            root.as_ref(),
            from,
            until,
        )
        .await
        .unwrap();
        let anchor = Certificate::decode(&Data::decode(anchor).unwrap()).unwrap();
        let ctx = SignedTrustContext::hierarchical(ns.clone()).with_version(1);
        assert!(ctx.add_anchor(anchor), "the person's anchor is valid now");
        let context_data = ctx.sign_into_data(root.as_ref()).unwrap().raw().clone();
        let (context, _) =
            SignedTrustContext::open_signed(&Data::decode(context_data.clone()).unwrap())
                .await
                .unwrap();

        let device_name = ns
            .clone()
            .append("member")
            .append(format!("d{seed}").as_str());
        let keys = Arc::new(SecurityManager::new());
        let key = keys
            .generate_ed25519_from_seed(device_name.clone().append("KEY").append("1"), &device_seed)
            .unwrap();
        let device_public = keys.get_signer_sync(&key).unwrap().public_key().unwrap();
        let cert_wire = encode_cert_data(
            &new_cert_name(&key, DEFAULT_ISSUER),
            &device_public,
            root.as_ref(),
            from,
            until,
        )
        .await
        .unwrap();
        let cert = Certificate::decode(&Data::decode(cert_wire).unwrap()).unwrap();
        let device_cert = cert
            .data_wire()
            .expect("the device's certificate has a Data to show");
        keys.cert_cache().insert(cert);

        // The forwarder the device and the links share: its security profile is off because the
        // device's own validator verifies every packet it takes.
        let (engine, shutdown) = EngineBuilder::new(EngineConfig {
            pipeline_threads: 1,
            ..EngineConfig::default()
        })
        .security_profile(SecurityProfile::Disabled)
        .build()
        .await
        .unwrap();
        let cancel = CancellationToken::new();
        let node = engine.app_node(cancel.child_token());
        let sync = engine.app_face(cancel.child_token());
        let cache = keys.cert_cache_arc();
        let fetcher = ndn_app::demux_cert_fetcher(node.demux(), cache.clone());
        let validator = Arc::new(Validator::with_keyring(
            keys.keyring().clone(),
            cache,
            Some(fetcher),
            5,
        ));
        // A person's namespace is self-certifying: trusted only from its genesis, its version 1.
        let genesis = Genesis::open_stored(&Data::decode(context_data.clone()).unwrap())
            .await
            .unwrap();
        validator
            .keyring()
            .adopt_genesis(&genesis, Arc::new(context))
            .unwrap();
        sync_group::carry(&engine, &ns);
        Base {
            ns,
            device_name,
            keys,
            validator,
            engine,
            shutdown,
            cancel,
            node,
            sync,
            anchor: context_data,
            device_cert,
        }
    }

    /// The introductions' common half, its person's trust context served by name.
    fn core(&self) -> Core {
        let core = Core {
            anchor: self.anchor.clone(),
            validator: self.validator.clone(),
            engine: self.engine.clone(),
            scoped: Mutex::default(),
        };
        core.publish(self.cancel.child_token());
        core
    }
}

/// The links: listen on a loopback port the system picks and take the introductions' links.
fn start_links(
    keys: &SecurityManager,
    device_name: &Name,
    validator: &Arc<Validator>,
    engine: &ForwarderEngine,
    device_cert: Bytes,
    cancel: &CancellationToken,
) -> Arc<Links> {
    let link_key: Arc<dyn LinkKeySource> = Arc::new(
        LinkKey::from_signer(
            keys.get_signer_sync(&device_name.clone().append("KEY").append("1"))
                .unwrap(),
        )
        .unwrap(),
    );
    let transport = LinkTransportConfig::default();
    let socket = LinkEndpoint::bind(
        SocketAddr::from(([0, 0, 0, 0], 0)),
        link_key.clone(),
        &transport,
        true,
    )
    .unwrap();
    Links::start(
        LinkSetup {
            peers: Vec::new(),
            key: link_key,
            trust: Arc::new(Trust {
                keyring: validator.keyring().clone(),
                chain: vec![device_cert],
                validator: validator.clone(),
            }),
            faces: Arc::new(EngineFaces(engine.clone())),
            paths: Arc::new(ConfiguredEndpoints),
            candidates: vec![Arc::new(HostCandidates {
                include_local: true,
            })],
            socket: Some(Arc::new(socket)),
            transport,
            relays: Default::default(),
            service: RelayService::default(),
            direct: Default::default(),
            reliability: Default::default(),
        },
        cancel.clone(),
    )
}

/// The link memory the device keeps in its store.
fn memory_options() -> MemoryOptions {
    MemoryOptions {
        include_local: true,
        ..MemoryOptions::default()
    }
}

/// `ms` from now, a day, as the date an offer lasts until.
fn a_day_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
        + 24 * 3_600_000
}

// ---- the device -----------------------------------------------------------------------------------------------------
/// One device of a person, running: `ndn_heap::Node` and `ndn_invite::Invites` on a forwarder
/// and links of its own.
pub struct Host {
    pub node: ndn_heap::Node,
    pub invites: ndn_invite::Invites,
    pub ns: Name,
    cancel: CancellationToken,
    _shutdown: ShutdownHandle,
    links: Arc<Links>,
}

impl Host {
    /// The person made from `seed` and their device `d<seed>`, the node's store a fjall database
    /// in `dir`.
    pub async fn open(dir: &Path, seed: u8) -> Host {
        let base = Base::new(seed).await;
        let intro = Arc::new(Intro {
            core: base.core(),
            hints: OnceLock::new(),
        });
        let store =
            Arc::new(ndn_sync::store::BackendStore::open_fjall(dir.join("device")).unwrap());
        let node = ndn_heap::Node::start(
            ndn_heap::Transport {
                node: base.node,
                sync: base.sync,
            },
            base.device_name.clone(),
            base.keys.clone(),
            base.validator.clone(),
            store as Arc<dyn DataStore>,
            ndn_heap::Config {
                adopter: Some(intro.clone() as Arc<dyn ndn_heap::Adopter>),
                ..ndn_heap::Config::new()
            },
        )
        .await
        .unwrap();
        let invites = ndn_invite::Invites::start(
            &node,
            intro.clone() as Arc<dyn ndn_invite::Host>,
            ndn_invite::IntroPolicy {
                local_candidates: true,
                ..ndn_invite::IntroPolicy::new()
            },
            ndn_invite::InviteConfig::new(),
        )
        .unwrap();

        let links = start_links(
            &base.keys,
            &base.device_name,
            &base.validator,
            &base.engine,
            base.device_cert,
            &base.cancel,
        );
        let hints = LinkHints::new(links.clone());
        hints.serve(&invites);
        let _ = intro.hints.set(hints);
        links.remember(DeviceMemory::new(node.store().clone()), memory_options());
        Host {
            node,
            invites,
            ns: base.ns,
            cancel: base.cancel,
            _shutdown: base.shutdown,
            links,
        }
    }

    /// A space of this person's `<ns>/32=data/<id>`, private to this person until an offer admits
    /// another.
    pub async fn share(&self, id: &str) -> Name {
        let space = self
            .ns
            .clone()
            .append_component(NameComponent::keyword(Bytes::from_static(b"data")))
            .append(id);
        self.node
            .create(
                &space,
                ndn_heap::Share {
                    readers: ndn_heap::Readers::Persons(Vec::new()),
                    writers: Vec::new(),
                },
            )
            .await
            .unwrap();
        space
    }

    /// What this device's links counted, in total: frames dropped for a rate and congestion
    /// Nacks sent for them.
    pub fn link_counters(&self) -> (u64, u64) {
        let r = self.links.report();
        (r.frames_over_rate, r.congestion_nacks)
    }

    /// An offer of `space` to write in it, the short code that carries it (a day, for one person).
    pub async fn offer(&self, space: &Name) -> String {
        self.invites
            .offer(
                space,
                ndn_invite::Offer {
                    role: ndn_invite::Role::Writer,
                    until: ndn_heap::Timestamp(a_day_ms()),
                    tries: 3,
                },
            )
            .await
            .unwrap()
            .share()
            .to_owned()
    }

    /// Join the space `code` invites to, again with the same code while the inviter is not
    /// reachable yet (what the layer's `RetryLater` says to do).
    pub async fn join(&self, code: &str) -> Name {
        let started = std::time::Instant::now();
        loop {
            match self.invites.join(code).await {
                Ok(joined) => return joined.space,
                Err(e) if e.retry() && started.elapsed() < Duration::from_secs(90) => {}
                Err(e) => panic!("the join failed: {e} ({:?})", e.next()),
            }
        }
    }

    /// Put `bytes` at `path` in `space`: signed and stored here when this returns (durable a
    /// flush later when a peer is known, which the node does before it announces). The put is
    /// asked again while the node says so (`RetryLater`).
    pub async fn put(&self, space: &Name, path: &str, bytes: &[u8]) {
        let heap = self
            .node
            .space(space)
            .unwrap_or_else(|| panic!("{} has not opened {space}", self.ns));
        let path = Name::root().append(path.as_bytes());
        let value = Bytes::copy_from_slice(bytes);
        let started = std::time::Instant::now();
        loop {
            match heap
                .put(&path, value.clone(), ndn_heap::PutOptions::default())
                .await
            {
                Ok(_) => return,
                Err(e) if e.retry() && started.elapsed() < Duration::from_secs(30) => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(e) => panic!("put of {path} in {space}: {e}"),
            }
        }
    }

    /// Every value put in `space`: what is held first, then each change as it comes.
    pub async fn watch(&self, space: &Name) -> impl Stream<Item = Bytes> + Send + use<> {
        let heap = self
            .node
            .space(space)
            .unwrap_or_else(|| panic!("{} has not opened {space}", self.ns));
        let changes = heap.watch(&ndn_heap::Frontier::new()).await.unwrap();
        futures::stream::unfold((changes, heap), |(mut changes, heap)| async move {
            loop {
                match changes.next().await? {
                    Ok(ndn_heap::Change::Put(item)) if item.bytes.len() >= 24 => {
                        return Some((item.bytes, (changes, heap)));
                    }
                    // Too many changes were left unread: list again from the start.
                    Ok(ndn_heap::Change::Lagged { .. }) => {
                        changes = heap.watch(&ndn_heap::Frontier::new()).await.ok()?
                    }
                    _ => {}
                }
            }
        })
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        self.node.shutdown();
        self.cancel.cancel();
    }
}
