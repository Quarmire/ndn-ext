//! A person's device on a forwarder of its own, as a host assembles one for ndn-data: the
//! identity (a self-certifying person, `/user/<0xA1 hash of the key>`, and one device of theirs),
//! the embedded forwarder, the validator, the data layer's **disk** store (fjall, under a
//! directory the caller picks), the introductions, and the links (`ndn-link`, by an invitation's
//! hint). The ladder's rungs 5 and 6 run `ndn_data::Device` directly on two of these, one per
//! process; ndf's own `open` does the same assembly behind its API, and this follows it step by
//! step so the two ladders measure the same stack.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use futures::{Stream, StreamExt};
use ndn_app::EngineAppExt;
use ndn_data::intro::{Adopting, Dialing, FirstDialing, Grant, LinkHint, Scoping};
use ndn_data::{
    Audience, Change, Config, DataLayer, Departure, Device, Frontier, Got, IntroPolicy, Introducer,
    Keep, MergeRules, Name, Offer, PutOptions, Role, Rule, Share, Sharing, Timestamp, Transport,
    TypeId,
};
use ndn_engine::{EngineBuilder, EngineConfig, ForwarderEngine, ShutdownHandle};
use ndn_face_quic::{KeyFingerprint, LinkEndpoint, LinkKey, LinkKeySource, LinkTransportConfig};
use ndn_link::{
    ConfiguredEndpoints, DeviceMemory, EngineFaces, HostCandidates, LinkHints, LinkSetup,
    LinkTrust, Links, MemoryOptions, RelayService,
};
use ndn_namespace::{ContextStore, StoredContext, sync_group};
use ndn_packet::{Data, NameComponent};
use ndn_security::cert_name::{DEFAULT_ISSUER, SELF_ISSUER, new_cert_name};
use ndn_security::self_certifying::Genesis;
use ndn_security::{
    Certificate, Keyring, ScopedContext, SecurityManager, SecurityProfile, SignedTrustContext,
    Validator, anchor_fingerprint, encode_cert_data,
};
use ndn_trust_envelope::TrustEnvelope;
use tokio_util::sync::CancellationToken;

use super::newest::{NEWEST, Newest};

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

/// The host's side of introductions: this person's trust context as the anchor an offer carries,
/// other people's adopted from an introduction (for the process's life; the bench keeps nothing
/// of them on disk), and the introductions' link steps handed to the link layer.
struct Intro {
    anchor: Bytes,
    validator: Arc<Validator>,
    engine: ForwarderEngine,
    hints: OnceLock<LinkHints>,
    scoped: Mutex<HashSet<Name>>,
}

const NO_LINK: &str = "this device is not linked: it has no way to reach the inviter";

impl Intro {
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

impl Introducer for Intro {
    fn anchor(&self) -> Option<Bytes> {
        Some(self.anchor.clone())
    }

    fn adopt<'a>(&'a self, link: &'a TrustEnvelope) -> Adopting<'a> {
        Box::pin(async move {
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
        })
    }

    /// A member of a folder whose namespace this device holds no context of: fetched by name and
    /// adopted for that folder alone; its data and its sync group are carried until let go.
    fn adopt_scoped<'a>(
        &'a self,
        namespace: &'a Name,
        held: Option<&'a ScopedContext>,
    ) -> Scoping<'a> {
        Box::pin(async move {
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
        })
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

    fn link_hint(&self) -> Option<LinkHint> {
        self.hints.get()?.hint()
    }

    fn dial<'a>(&'a self, hint: &'a LinkHint, inviter: &'a Name, within: Duration) -> Dialing<'a> {
        match self.hints.get() {
            Some(hints) => Box::pin(async move { hints.dial(hint, inviter, within).await }),
            None => Box::pin(async { Err(NO_LINK.to_owned()) }),
        }
    }

    fn dial_first<'a>(
        &'a self,
        inviter: &'a Name,
        addr: SocketAddr,
        within: Duration,
    ) -> FirstDialing<'a> {
        match self.hints.get() {
            Some(hints) => Box::pin(async move { hints.dial_first(inviter, addr, within).await }),
            None => Box::pin(async { Err(NO_LINK.to_owned()) }),
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

    fn revoke_grant(&self, key: &[u8; 32], folder: &Name) {
        if let Some(hints) = self.hints.get() {
            hints.revoke_grant(key, folder);
        }
    }

    fn departure(&self, d: &Departure) {
        if let Some(hints) = self.hints.get() {
            hints.depart(d);
        }
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

/// One device of a person, running: its data layer on a forwarder and links of its own.
pub struct Host {
    pub device: Device,
    pub ns: Name,
    cancel: CancellationToken,
    _shutdown: ShutdownHandle,
    _links: Arc<Links>,
}

/// What every put carries: kept for good, one version at a time (the options of ndf's `put`).
fn options() -> PutOptions {
    PutOptions {
        type_id: TypeId {
            name: Name::root().append("ndf").append("types").append("bytes"),
            revision: 1,
        },
        keep: Keep::Forever,
        batch: None,
    }
}

impl Host {
    /// The person made from `seed` (their namespace follows from it) and their device `d<seed>`,
    /// its data layer's store a fjall database in `dir`.
    pub async fn open(dir: &Path, seed: u8) -> Host {
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

        let intro = Arc::new(Intro {
            anchor: context_data,
            validator: validator.clone(),
            engine: engine.clone(),
            hints: OnceLock::new(),
            scoped: Mutex::default(),
        });
        intro.publish(cancel.child_token());
        let store = ndn_sync::store::BackendStore::open_fjall(dir.join("device")).unwrap();
        let config = Config {
            rules: MergeRules::standard().with(Arc::new(Newest::new())),
            introducer: Some(intro.clone()),
            intro: IntroPolicy {
                local_candidates: true,
                ..IntroPolicy::new()
            },
            ..Config::new()
        };
        let device = Device::start(
            Transport { node, sync },
            device_name.clone(),
            keys.clone(),
            validator.clone(),
            Arc::new(store),
            config,
        )
        .await
        .unwrap();

        // The links: listen on a loopback port the system picks and take the introductions' links.
        let link_key: Arc<dyn LinkKeySource> = Arc::new(
            LinkKey::from_signer(
                keys.get_signer_sync(&device_name.append("KEY").append("1"))
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
        let links = Links::start(
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
            },
            cancel.clone(),
        );
        let hints = LinkHints::new(links.clone());
        hints.serve(&device);
        let _ = intro.hints.set(hints);
        links.remember(
            DeviceMemory::new(&device),
            MemoryOptions {
                include_local: true,
                ..MemoryOptions::default()
            },
        );
        Host {
            device,
            ns,
            cancel,
            _shutdown: shutdown,
            _links: links,
        }
    }

    /// A folder of this person's `<ns>/32=data/s/<id>`, shared with this person alone, under the
    /// newest-wins rule.
    pub async fn share(&self, id: &str) -> Name {
        let folder = self
            .ns
            .clone()
            .append_component(NameComponent::keyword(Bytes::from_static(b"data")))
            .append("s")
            .append(id);
        let rule = Rule::Merge {
            function: NEWEST.parse().expect("the rule's name is an NDN name"),
        };
        let share = Share {
            rule,
            writers: vec![self.ns.clone()],
            readers: vec![Audience::Person(self.ns.clone())],
        };
        self.device
            .share_folder(&folder, Sharing::Whole(share))
            .await
            .unwrap();
        folder
    }

    /// An offer of `folder` to write in it, the short code that carries it (a day, for one person).
    pub async fn offer(&self, folder: &Name) -> String {
        let until = Timestamp(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_millis() as u64)
                + 24 * 3_600_000,
        );
        self.device
            .offer(
                folder,
                Offer {
                    role: Role::Writer,
                    until,
                    tries: 3,
                },
            )
            .await
            .unwrap()
            .share()
            .to_owned()
    }

    /// Join the folder `code` invites to, again with the same code while the inviter is not
    /// reachable yet (what the layer's `RetryLater` says to do).
    pub async fn join(&self, code: &str) -> Name {
        let started = std::time::Instant::now();
        loop {
            match self.device.join(code).await {
                Ok(joined) => return joined.folder,
                Err(e)
                    if e.next() == ndn_data::NextStep::RetryLater
                        && started.elapsed() < Duration::from_secs(90) => {}
                Err(e) => panic!("the join failed: {e} ({:?})", e.next()),
            }
        }
    }

    /// Put `bytes` at `path` under `folder`: signed and stored here when this returns (durable a
    /// flush later, which the data layer does before it announces).
    pub async fn put(&self, folder: &Name, path: &str, bytes: &[u8]) {
        let collection = folder.clone().append(path.as_bytes());
        self.device
            .put_op(&collection, Bytes::copy_from_slice(bytes), options())
            .await
            .unwrap();
    }

    /// Every change in `folder` as the newest bytes at the path it changed: what is held first, then
    /// each change as it comes (ndf's `watch`: a `get` of the collection a change names).
    pub async fn watch(&self, folder: &Name) -> impl Stream<Item = Bytes> + Send + use<> {
        let (device, folder) = (self.device.clone(), folder.clone());
        let changes = device.watch(&folder, &Frontier::new()).await.unwrap();
        futures::stream::unfold(
            (changes, device, folder),
            |(mut changes, device, folder)| async move {
                loop {
                    match changes.next().await? {
                        Ok(Change::Version(v)) => {
                            let got = match device.get(&v.collection).await {
                                Ok(answer) => answer.got,
                                Err(_) => continue,
                            };
                            if let Got::State(state) = got
                                && let Some(value) = state.value.bytes().filter(|v| v.len() >= 32)
                            {
                                return Some((value.slice(32..), (changes, device, folder)));
                            }
                        }
                        // Too many changes were left unread: list again from the start.
                        Ok(Change::Lagged { .. }) => {
                            changes = device.watch(&folder, &Frontier::new()).await.ok()?
                        }
                        _ => {}
                    }
                }
            },
        )
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        self.device.shutdown();
        self.cancel.cancel();
    }
}
