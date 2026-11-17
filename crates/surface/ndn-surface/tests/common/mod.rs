//! Real devices for the signal tests and bench: namespaces with an anchor, device
//! keys certified by it, `ndn_data::Device`s started on in-process engines, and a
//! `Signals` hub per device on a connection of its own, routed as a host routes it.

#![allow(dead_code)]

use std::collections::VecDeque;
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use futures::StreamExt;
use ndn_app::{Connection, EngineAppExt};
use ndn_data::{Audience, Config, DataLayer, Device, Frontier, Rule, Share, Sharing, Transport};
use ndn_engine::{EngineBuilder, EngineConfig, ForwarderEngine, ShutdownHandle};
use ndn_face::net::UdpFace;
use ndn_packet::Name;
use ndn_security::{
    Certificate, SecurityManager, SecurityProfile, SignedTrustContext, TrustSchema, Validator,
};
use ndn_surface::signal::{SignalError, SignalOptions, SignalSubscriber, Signals, wire};
use ndn_sync::MemoryStore;
use tokio_util::sync::CancellationToken;

/// The octets of `name`'s encoding as a Name TLV.
pub fn name_octets(name: &Name) -> usize {
    let tlv = |len: usize| 1 + if len < 253 { 1 } else { 3 } + len;
    tlv(name.components().iter().map(|c| tlv(c.value.len())).sum())
}

const VALIDITY_MS: u64 = 365 * 24 * 3600 * 1000;

pub fn n(s: &str) -> Name {
    s.parse().unwrap()
}

/// An in-process forwarder. It verifies nothing itself: the devices do.
pub struct Engine {
    pub engine: ForwarderEngine,
    _shutdown: ShutdownHandle,
}

pub async fn engine() -> Engine {
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .security_profile(SecurityProfile::Disabled)
        .build()
        .await
        .expect("an in-process engine");
    Engine {
        engine,
        _shutdown: shutdown,
    }
}

/// A namespace: its authority's key and anchor, and its devices' keys, each
/// certified by the authority.
pub struct World {
    ns: Name,
    authority: SecurityManager,
    issuer: Name,
    anchor: Certificate,
    devices: Vec<(Name, Arc<SecurityManager>, Certificate)>,
    /// Other namespaces whose trust contexts its devices hold: (namespace, anchor).
    trusted: Vec<(Name, Certificate)>,
    pub cancel: CancellationToken,
}

impl World {
    /// The namespace `ns` with the devices `devices`.
    pub async fn new(ns: &str, devices: &[&str]) -> World {
        let ns = n(ns);
        let authority = SecurityManager::new();
        let issuer = authority
            .generate_ed25519(ns.clone().append("KEY").append("ns"))
            .unwrap();
        let public = authority
            .get_signer_sync(&issuer)
            .unwrap()
            .public_key()
            .unwrap();
        let anchor = authority
            .issue_self_signed_async(&issuer, public, VALIDITY_MS)
            .await
            .unwrap();
        let mut world = World {
            ns,
            authority,
            issuer,
            anchor,
            devices: Vec::new(),
            trusted: Vec::new(),
            cancel: CancellationToken::new(),
        };
        for d in devices {
            let device = n(d);
            let keys = Arc::new(SecurityManager::new());
            let k = keys
                .generate_ed25519(device.clone().append("KEY").append("1"))
                .unwrap();
            let public = keys.get_signer_sync(&k).unwrap().public_key().unwrap();
            let cert = world
                .authority
                .certify(&k, public, &world.issuer, VALIDITY_MS)
                .await
                .unwrap();
            keys.cert_cache().insert(cert.clone());
            world.devices.push((device, keys, cert));
        }
        world
    }

    pub fn ns(&self) -> &Name {
        &self.ns
    }

    /// Its devices started from now on hold `other`'s trust context too, so a
    /// record naming `other`'s namespace counts its group.
    pub fn trust(&mut self, other: &World) {
        self.trusted.push((other.ns.clone(), other.anchor.clone()));
    }

    /// A validator as each device's host holds it: the namespace's trust context
    /// (its anchor), those it trusts, and its devices' certificates.
    fn validator(&self) -> Arc<Validator> {
        let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
        let own = [(self.ns.clone(), self.anchor.clone())];
        for (ns, anchor) in own.iter().chain(&self.trusted) {
            let ctx = SignedTrustContext::hierarchical(ns.clone()).with_version(1);
            assert!(ctx.add_anchor(anchor.clone()));
            validator.adopt_context(Arc::new(ctx)).unwrap();
        }
        for (_, _, cert) in &self.devices {
            validator.cert_cache().insert(cert.clone());
        }
        validator
    }

    /// Start `device` on `engine` and a `Signals` hub beside it, on a connection
    /// of its own. The engine runs the namespace's sync group with the multicast
    /// strategy, as a host does.
    pub async fn host(&self, engine: &Engine, device: &str, options: SignalOptions) -> Host {
        self.host_on(engine, device, options, Arc::new(MemoryStore::new()))
            .await
    }

    /// Like [`Self::host`], on `store`: a device started again on the store a
    /// stopped one left is that device restarted.
    pub async fn host_on(
        &self,
        engine: &Engine,
        device: &str,
        options: SignalOptions,
        store: Arc<MemoryStore>,
    ) -> Host {
        self.host_via(engine, device, options, store, |conn| conn)
            .await
    }

    /// Like [`Self::host_on`], with the `Signals` hub reading and pushing through what
    /// `wrap` makes of its connection: a test decides in which order its packets arrive.
    pub async fn host_via(
        &self,
        engine: &Engine,
        device: &str,
        options: SignalOptions,
        store: Arc<MemoryStore>,
        wrap: impl FnOnce(Arc<dyn Connection>) -> Arc<dyn Connection>,
    ) -> Host {
        let (name, keys, _) = self
            .devices
            .iter()
            .find(|(d, _, _)| *d == n(device))
            .expect("a device of the world");
        ndn_namespace::sync_group::carry(&engine.engine, &self.ns);
        let transport = Transport {
            node: engine.engine.app_node(self.cancel.child_token()),
            sync: engine.engine.app_face(self.cancel.child_token()),
        };
        let device = Device::start(
            transport,
            name.clone(),
            Arc::clone(keys),
            self.validator(),
            store,
            Config {
                first_look: Duration::from_millis(50),
                ..Config::new()
            },
        )
        .await
        .expect("the device starts");
        let signals = Signals::start(
            device.clone(),
            wrap(engine.engine.app_face(self.cancel.child_token())),
            options,
        )
        .await
        .expect("signals start");
        Host { device, signals }
    }
}

/// A device and its signals.
pub struct Host {
    pub device: Device,
    pub signals: Signals,
}

impl Host {
    /// Share `folder` with every device of the namespace writing; sealed to the
    /// namespace's person when `sealed`.
    pub async fn share(&self, folder: &Name, ns: &Name, sealed: bool) {
        let readers = if sealed {
            vec![Audience::Person(ns.clone())]
        } else {
            Vec::new()
        };
        self.device
            .share_folder(
                folder,
                Sharing::Whole(Share {
                    rule: Rule::Log,
                    writers: vec![ns.clone()],
                    readers,
                }),
            )
            .await
            .expect("the owner shares the folder");
    }

    /// Subscribe to `scope` once this device holds what it needs (the record,
    /// and sealed the epoch key), within `within`. The device follows the scope,
    /// as a host watching it does, so its owner's record arrives.
    pub async fn subscribe(&self, scope: &Name, within: Duration) -> SignalSubscriber {
        let mut changes = self
            .device
            .watch(scope, &Frontier::new())
            .await
            .expect("the device follows the scope");
        tokio::spawn(async move { while changes.next().await.is_some() {} });
        let deadline = Instant::now() + within;
        loop {
            match self.signals.subscribe(scope).await {
                Ok(s) => return s,
                Err(SignalError::NotReady { .. }) if Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(e) => panic!("{} cannot subscribe to {scope}: {e}", self.device.name()),
            }
        }
    }
}

/// Join `a` and `b` by a UDP face on 127.0.0.1 and route over it what a link
/// routes: the namespace's sync group both ways, and each side's devices.
pub async fn link(
    a: &Engine,
    b: &Engine,
    ns: &Name,
    a_devices: &[&str],
    b_devices: &[&str],
    cancel: &CancellationToken,
) {
    let sa = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sb = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (aa, ab) = (sa.local_addr().unwrap(), sb.local_addr().unwrap());
    let ida = a.engine.faces().alloc_id();
    a.engine
        .add_face(UdpFace::from_socket(ida, sa, ab), cancel.child_token());
    let idb = b.engine.faces().alloc_id();
    b.engine
        .add_face(UdpFace::from_socket(idb, sb, aa), cancel.child_token());
    let group = wire::sync_group(ns);
    a.engine.fib().add_nexthop(&group, ida, 0);
    b.engine.fib().add_nexthop(&group, idb, 0);
    for d in b_devices {
        a.engine.fib().add_nexthop(&n(d), ida, 0);
    }
    for d in a_devices {
        b.engine.fib().add_nexthop(&n(d), idb, 0);
    }
}

/// Options of a sender whose packets must cross the forwarder (every test
/// process is one host: a ring would carry them otherwise).
pub fn no_ring() -> SignalOptions {
    SignalOptions {
        local_ring: false,
        ..SignalOptions::default()
    }
}

/// `options` with a push budget no test reaches: an in-process engine, and a UDP
/// face between two, carry no relay quota (the default budget keeps a device
/// below one, ndn-link §15.3), so several runs at 60 Hz may push freely.
pub fn no_quota(options: SignalOptions) -> SignalOptions {
    SignalOptions {
        push_rate: NonZeroU32::new(10_000).unwrap(),
        push_burst: NonZeroU32::new(20_000).unwrap(),
        ..options
    }
}

/// What a [`Reordered`] connection does to the run headers on their way to a hub.
#[derive(Clone, Copy)]
pub enum Headers {
    /// A header-only packet is delivered after the packet of signals that follows it, as
    /// when the forwarder's parallel pipeline lets that packet overtake it (a forwarder
    /// promises no order between two Interests, nor does a network).
    Behind,
    /// Every packet that carries a header is lost on the way.
    Lost,
}

/// A hub's connection that decides in which order, and whether, the run headers
/// reach it. Unsealed packets only.
pub struct Reordered {
    inner: Arc<dyn Connection>,
    headers: Headers,
    state: Mutex<Overtaken>,
}

#[derive(Default)]
struct Overtaken {
    /// A packet of signals has been delivered already.
    signalled: bool,
    /// A header-only packet waiting for the packet of signals behind which it goes.
    held: Option<Bytes>,
    /// Packets to deliver before reading more.
    ready: VecDeque<Bytes>,
}

impl Reordered {
    pub fn wrap(headers: Headers) -> impl FnOnce(Arc<dyn Connection>) -> Arc<dyn Connection> {
        move |inner| {
            Arc::new(Reordered {
                inner,
                headers,
                state: Mutex::new(Overtaken::default()),
            })
        }
    }
}

/// The body of the unsealed signal packet `wire` pushes, if it is one.
fn unsealed_body(wire: &Bytes) -> Option<wire::Body> {
    let interest = ndn_packet::Interest::decode(wire.clone()).ok()?;
    match wire::decode_packet(wire::push_packet(&interest)?) {
        Ok(wire::Packet::Body(body)) => Some(body),
        _ => None,
    }
}

#[async_trait]
impl Connection for Reordered {
    async fn send(&self, wire: Bytes) -> Result<(), ndn_app::AppError> {
        self.inner.send(wire).await
    }

    async fn recv(&self) -> Option<Bytes> {
        loop {
            if let Some(ready) = self.state.lock().unwrap().ready.pop_front() {
                return Some(ready);
            }
            let wire = self.inner.recv().await?;
            let Some(body) = unsealed_body(&wire) else {
                return Some(wire);
            };
            match self.headers {
                Headers::Lost if body.header.is_some() => continue,
                Headers::Lost => return Some(wire),
                Headers::Behind => {
                    let mut st = self.state.lock().unwrap();
                    if body.header.is_some() && body.signals.is_empty() && !st.signalled {
                        st.held = Some(wire);
                        continue;
                    }
                    st.signalled |= !body.signals.is_empty();
                    if let Some(held) = st.held.take() {
                        st.ready.push_back(held);
                    }
                    return Some(wire);
                }
            }
        }
    }

    async fn register_prefix(&self, prefix: &Name) -> Result<(), ndn_app::AppError> {
        self.inner.register_prefix(prefix).await
    }

    fn replies(&self) -> Option<ndn_app::Replies> {
        self.inner.replies()
    }
}
