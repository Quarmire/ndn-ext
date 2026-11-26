//! The topology `tests/chan_relay.rs` and `examples/chan_relay.rs` share (SHAPES-CHANNEL.md §8,
//! §13 stage 4): a **sender** device, an optional **relay** and one to four **receivers**, each on
//! a forwarder of its own (`ndn-engine`, in this process), joined by real QUIC links on loopback
//! (`LinkFace`, which a forwarder takes as a face like any other). The sender and receivers run
//! the data layer (`ndn-heap` `Node`s over their forwarder's app faces, `attach_forwarder`); the
//! relay holds no identity, no trust and no data layer: its forwarder has FIB routes toward the
//! people's names and its `SideTable`, and nothing else.
//!
//! Everything reaches the receivers over the links: the space's sync, the signed ask
//! (`NodeHandle::ask_channel`: the Interest goes receiver -> relay -> sender, the session Data
//! returns over the reverse path with its `SideRoute` and installs a route at every hop) and the
//! frames (`Heap::emit` -> the sender's forwarder -> link -> the relay's table -> a link for each
//! receiver -> the receivers' forwarders -> `Heap::live`'s `Items`).

use std::sync::Arc;
use std::time::{Duration, Instant};

use ndn_app::EngineAppExt;
use ndn_engine::side::SideConfig;
use ndn_engine::{EngineBuilder, EngineConfig, ForwarderEngine};
use ndn_face_quic::{LinkEndpoint, LinkHandle, LinkTransportConfig};
use ndn_heap::{CHECKPOINT_DEFAULT, Config, Heap, Name, Node, Readers, Share, Transport};
use ndn_security::{
    Certificate, SecurityManager, SecurityProfile, SignedTrustContext, TrustSchema, Validator,
};
use ndn_sync::{DataStore, MemoryStore};
use ndn_transport::{Face, FaceId, FacePersistency};
use tokio::runtime::Handle;
use tokio_util::sync::CancellationToken;

use crate::pair::connect_ids;

/// The people: the sender's namespace, then the receivers' (a receiver is the owner of its own).
const PEOPLE: [&str; 5] = ["/bob", "/carol", "/dave", "/erin", "/frank"];
/// Their devices.
const DEVICES: [&str; 5] = [
    "/bob/phone",
    "/carol/tablet",
    "/dave/watch",
    "/erin/laptop",
    "/frank/phone",
];
/// The most receivers a mesh takes.
pub const MAX_RECEIVERS: usize = PEOPLE.len() - 1;

pub fn name(uri: &str) -> Name {
    uri.parse().expect("a valid name")
}

pub fn space() -> Name {
    name("/bob/32=data/bench")
}

fn config(checkpoint: Duration) -> Config {
    let mut c = Config::new();
    c.settle = Duration::from_secs(3);
    c.svs.jitter_ms = 20;
    c.svs.suppression_period = Duration::from_millis(30);
    c.svs.sync_interval = Duration::from_secs(1);
    c.channel.checkpoint = checkpoint;
    c
}

struct Dev {
    name: Name,
    keys: Arc<SecurityManager>,
    validator: Arc<Validator>,
}

/// Each device's key is certified by its namespace's root; every validator holds every anchor and
/// every certificate. A device's namespace is its first name component.
async fn world(devices: &[&str]) -> Vec<Dev> {
    let ns_of = |n: &Name| Name::from_components(n.components()[..1].iter().cloned());
    let mut roots: Vec<(Name, SecurityManager, Name, Certificate)> = Vec::new();
    for d in devices {
        let ns = ns_of(&name(d));
        if roots.iter().any(|(r, ..)| *r == ns) {
            continue;
        }
        let mgr = SecurityManager::new();
        let key = ns.clone().append("KEY").append("root");
        mgr.generate_ed25519(key.clone()).unwrap();
        let pk = mgr.get_signer_sync(&key).unwrap().public_key().unwrap();
        let anchor = mgr.issue_self_signed(&key, pk, u64::MAX).unwrap();
        roots.push((ns, mgr, key, anchor));
    }
    let mut made = Vec::new();
    for d in devices {
        let device = name(d);
        let ns = ns_of(&device);
        let (_, root, root_key, _) = roots.iter().find(|(r, ..)| *r == ns).unwrap();
        let keys = Arc::new(SecurityManager::new());
        let key = keys
            .generate_ed25519(device.clone().append("KEY").append("1"))
            .unwrap();
        let public = keys.get_signer_sync(&key).unwrap().public_key().unwrap();
        let cert = root
            .certify(&key, public, root_key, 365 * 24 * 3600 * 1000)
            .await
            .unwrap();
        made.push((device, keys, cert));
    }
    let validator = || {
        let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
        for (ns, _, _, anchor) in &roots {
            let ctx = SignedTrustContext::hierarchical(ns.clone());
            assert!(ctx.add_anchor(anchor.clone()));
            validator.adopt_context(Arc::new(ctx)).unwrap();
        }
        for (_, _, cert) in &made {
            validator.cert_cache().insert(cert.clone());
        }
        validator
    };
    made.iter()
        .map(|(device, keys, _)| Dev {
            name: device.clone(),
            keys: Arc::clone(keys),
            validator: validator(),
        })
        .collect()
}

/// Where each part runs: the runtimes the example pins to cores, or one runtime for a test.
#[derive(Clone)]
pub struct Runtimes {
    pub send: Handle,
    pub relay: Handle,
    pub recv: Vec<Handle>,
}

impl Runtimes {
    /// Every part on the runtime the caller is on.
    pub fn current() -> Self {
        let here = Handle::current();
        Self {
            send: here.clone(),
            relay: here.clone(),
            recv: vec![here; MAX_RECEIVERS],
        }
    }
}

/// A forwarder and the token that ends everything attached to it.
pub struct Site {
    pub engine: ForwarderEngine,
    cancel: CancellationToken,
}

impl Site {
    async fn start(rt: &Handle, side: SideConfig) -> Site {
        rt.spawn(async move {
            let (engine, shutdown) = EngineBuilder::new(EngineConfig {
                side,
                ..EngineConfig::default()
            })
            .security_profile(SecurityProfile::Disabled)
            .build()
            .await
            .expect("an engine");
            shutdown.detach();
            // The people's sync groups run with the multicast strategy here, as the link
            // library's host sets them for the namespaces a forwarder carries.
            for person in PEOPLE {
                ndn_namespace::sync_group::carry(&engine, &name(person));
            }
            Site {
                engine,
                cancel: CancellationToken::new(),
            }
        })
        .await
        .unwrap()
    }

    /// The names that go over `face`: the people it leads toward, and each one's sync group.
    fn route(&self, people: &[usize], face: FaceId) {
        let fib = self.engine.fib();
        for &p in people {
            let person = name(PEOPLE[p]);
            fib.add_nexthop(&person, face, 1);
            fib.add_nexthop(&ndn_security::sync_group(&person), face, 1);
        }
    }

    /// Every sync group goes over `face` as well, whoever is behind it (the multicast strategy
    /// sends a Sync Interest to every face its group is routed to, never back).
    fn route_sync(&self, people: &[usize], face: FaceId) {
        let fib = self.engine.fib();
        for &p in people {
            fib.add_nexthop(&ndn_security::sync_group(&name(PEOPLE[p])), face, 1);
        }
    }

    async fn node(&self, rt: &Handle, dev: Dev, checkpoint: Duration) -> Node {
        let (engine, cancel) = (self.engine.clone(), self.cancel.clone());
        rt.spawn(async move {
            let node = Node::start(
                Transport {
                    sync: engine.app_face(cancel.child_token()),
                    node: engine.app_node(cancel.child_token()),
                },
                dev.name.clone(),
                dev.keys,
                dev.validator,
                Arc::new(MemoryStore::new()) as Arc<dyn DataStore>,
                config(checkpoint),
            )
            .await
            .expect("the node starts");
            node.attach_forwarder()
                .expect("the engine's app face carries channel frames");
            node
        })
        .await
        .unwrap()
    }
}

impl Drop for Site {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// One link between two sites: `a` listens, `b` dials. The faces are in the sites' forwarders; the
/// handles stay for the link's counters.
pub struct Joined {
    pub a_face: FaceId,
    pub b_face: FaceId,
    pub a: LinkHandle,
    pub b: LinkHandle,
    _eps: [Arc<LinkEndpoint>; 2],
}

async fn join(a: (&Site, &Handle), b: (&Site, &Handle), transport: &LinkTransportConfig) -> Joined {
    let (id_a, id_b) = (a.0.engine.faces().alloc_id(), b.0.engine.faces().alloc_id());
    let (la, lb, eps) = connect_ids(transport, a.1, b.1, id_a, id_b).await;
    let (ha, hb) = (la.handle.clone(), lb.handle.clone());
    for (site, rt, link, expected) in [(a.0, a.1, la, id_a), (b.0, b.1, lb, id_b)] {
        // The face's reader task is spawned by whoever adds it: on the site's runtime.
        let (engine, cancel) = (site.engine.clone(), site.cancel.child_token());
        let id = rt
            .spawn(async move {
                engine.add_composed_face(
                    Face::from_transport(link.face),
                    cancel,
                    FacePersistency::Persistent,
                )
            })
            .await
            .unwrap();
        assert_eq!(
            id, expected,
            "the face took the id the link was admitted with"
        );
    }
    Joined {
        a_face: id_a,
        b_face: id_b,
        a: ha,
        b: hb,
        _eps: eps,
    }
}

/// What a participant of the data layer is: its device on its forwarder.
pub struct Party {
    pub node: Node,
    pub heap: Heap,
    pub site: Site,
    /// Its link toward the sender (the sender's: toward the relay or the one receiver; a
    /// receiver's: toward the relay or the sender).
    pub link: LinkHandle,
}

/// The sender, the optional relay and the receivers.
pub struct Mesh {
    pub sender: Party,
    /// `None`: the receiver is linked to the sender directly.
    pub relay: Option<Site>,
    /// The relay's links, to the sender first, then to each receiver.
    pub relay_links: Vec<LinkHandle>,
    pub receivers: Vec<Party>,
    _eps: Vec<Joined>,
}

/// How the relay's forwarder is built.
pub struct Build {
    pub transport: LinkTransportConfig,
    /// The relay's side table (a relay that cannot install a route is the relay of an older
    /// forwarder: its limits say so).
    pub relay_side: SideConfig,
    /// A public space or a sealed one.
    pub sealed: bool,
    /// The receivers write too (so that the sender can ask them for a channel back).
    pub receivers_write: bool,
    /// The checkpoint period of every node's channels.
    pub checkpoint: Duration,
}

impl Default for Build {
    fn default() -> Self {
        Self {
            transport: LinkTransportConfig::default(),
            relay_side: SideConfig::default(),
            sealed: true,
            receivers_write: false,
            checkpoint: CHECKPOINT_DEFAULT,
        }
    }
}

impl Mesh {
    /// `receivers` (1 to `MAX_RECEIVERS`) devices behind a relay (`relay`) or, for one, directly
    /// linked to the sender. The space is created by the sender, whose record each receiver holds
    /// before this returns.
    pub async fn new(rt: &Runtimes, receivers: usize, relay: bool, build: Build) -> Mesh {
        assert!((1..=MAX_RECEIVERS).contains(&receivers) && (relay || receivers == 1));
        let people = receivers + 1;
        let mut devs = world(&DEVICES[..people]).await;
        let sender_site = Site::start(&rt.send, SideConfig::default()).await;
        let relay_site = if relay {
            Some(Site::start(&rt.relay, build.relay_side).await)
        } else {
            None
        };
        let mut recv_sites = Vec::new();
        for i in 0..receivers {
            recv_sites.push(Site::start(&rt.recv[i], SideConfig::default()).await);
        }

        // The links, and the routes over them.
        let all: Vec<usize> = (0..people).collect();
        let mut joined = Vec::new();
        let sender_link;
        let mut relay_links = Vec::new();
        let mut recv_links = Vec::new();
        if let Some(relay_site) = &relay_site {
            let to_sender = join(
                (relay_site, &rt.relay),
                (&sender_site, &rt.send),
                &build.transport,
            )
            .await;
            // The relay: toward the sender it is /bob, toward each receiver that receiver.
            relay_site.route(&[0], to_sender.a_face);
            // Everyone else is behind the relay for the sender.
            let others: Vec<usize> = (1..people).collect();
            sender_site.route(&others, to_sender.b_face);
            sender_site.route_sync(&all, to_sender.b_face);
            relay_site.route_sync(&all, to_sender.a_face);
            relay_links.push(to_sender.a.clone());
            sender_link = to_sender.b.clone();
            joined.push(to_sender);
            for (i, site) in recv_sites.iter().enumerate() {
                let link = join(
                    (relay_site, &rt.relay),
                    (site, &rt.recv[i]),
                    &build.transport,
                )
                .await;
                relay_site.route(&[i + 1], link.a_face);
                relay_site.route_sync(&all, link.a_face);
                let behind: Vec<usize> = (0..people).filter(|p| *p != i + 1).collect();
                site.route(&behind, link.b_face);
                site.route_sync(&all, link.b_face);
                relay_links.push(link.a.clone());
                recv_links.push(link.b.clone());
                joined.push(link);
            }
        } else {
            let link = join(
                (&recv_sites[0], &rt.recv[0]),
                (&sender_site, &rt.send),
                &build.transport,
            )
            .await;
            sender_site.route(&[1], link.b_face);
            sender_site.route_sync(&all, link.b_face);
            recv_sites[0].route(&[0], link.a_face);
            recv_sites[0].route_sync(&all, link.a_face);
            sender_link = link.b.clone();
            recv_links.push(link.a.clone());
            joined.push(link);
        }

        // The data layer on the ends.
        let bob = sender_site
            .node(&rt.send, devs.remove(0), build.checkpoint)
            .await;
        let mut parties = Vec::new();
        for (i, (site, dev)) in recv_sites.into_iter().zip(devs).enumerate() {
            let node = site.node(&rt.recv[i], dev, build.checkpoint).await;
            parties.push((node, site));
        }
        let share = Share {
            readers: if build.sealed {
                Readers::Persons(PEOPLE[..people].iter().map(|p| name(p)).collect())
            } else {
                Readers::Anyone
            },
            writers: if build.receivers_write {
                PEOPLE[..people].iter().map(|p| name(p)).collect()
            } else {
                vec![name(PEOPLE[0])]
            },
        };
        // The space is made on the sender's runtime and opened on each receiver's: what they
        // start runs where the device runs.
        let (bob, bob_heap) = rt
            .send
            .spawn(async move {
                let heap = bob.create(&space(), share).await.unwrap();
                (bob, heap)
            })
            .await
            .unwrap();
        let mut receivers_out = Vec::new();
        for (i, ((node, site), link)) in parties.into_iter().zip(recv_links).enumerate() {
            let (node, heap) = rt.recv[i]
                .spawn(async move {
                    let heap = node.open(&space()).await.unwrap();
                    (node, heap)
                })
                .await
                .unwrap();
            receivers_out.push(Party {
                node,
                heap,
                site,
                link,
            });
        }
        Mesh {
            sender: Party {
                node: bob,
                heap: bob_heap,
                site: sender_site,
                link: sender_link,
            },
            relay: relay_site,
            relay_links,
            receivers: receivers_out,
            _eps: joined,
        }
    }

    /// `asker` asks `sender`'s device for its channel (on `rt`, the asker's runtime, so that the
    /// session's tasks run there) until it answers: the space's record takes a moment to reach
    /// the asker, over the links.
    pub async fn ask(rt: &Handle, asker: &Node, sender: &Node) -> ndn_heap::ChannelInfo {
        let (asker, sender) = (asker.handle(), sender.name().clone());
        rt.spawn(async move {
            let start = Instant::now();
            loop {
                match asker.ask_channel(&space(), &sender).await {
                    Ok(info) => return info,
                    Err(e) if start.elapsed() < Duration::from_secs(30) => {
                        let _ = e;
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                    Err(e) => panic!(
                        "{} asked {sender} for a channel: {e} (next: {:?})",
                        asker.name(),
                        e.next()
                    ),
                }
            }
        })
        .await
        .unwrap()
    }
}
