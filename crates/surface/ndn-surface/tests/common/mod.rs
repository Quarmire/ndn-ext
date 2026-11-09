//! Real devices for the signal tests and bench: namespaces with an anchor, device
//! keys certified by it, `ndn_data::Device`s started on in-process engines, and a
//! `Signals` hub per device on a connection of its own, routed as a host routes it.

#![allow(dead_code)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::StreamExt;
use ndn_app::EngineAppExt;
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

    /// A validator as each device's host holds it: the namespace's trust context
    /// (its anchor) and its devices' certificates.
    fn validator(&self) -> Arc<Validator> {
        let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
        let ctx = SignedTrustContext::hierarchical(self.ns.clone()).with_version(1);
        assert!(ctx.add_anchor(self.anchor.clone()));
        validator.adopt_context(Arc::new(ctx)).unwrap();
        for (_, _, cert) in &self.devices {
            validator.cert_cache().insert(cert.clone());
        }
        validator
    }

    /// Start `device` on `engine` and a `Signals` hub beside it, on a connection
    /// of its own. The engine runs the namespace's sync group with the multicast
    /// strategy, as a host does.
    pub async fn host(&self, engine: &Engine, device: &str, options: SignalOptions) -> Host {
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
            Arc::new(MemoryStore::new()),
            Config {
                first_look: Duration::from_millis(50),
                ..Config::new()
            },
        )
        .await
        .expect("the device starts");
        let signals = Signals::start(
            device.clone(),
            engine.engine.app_face(self.cancel.child_token()),
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
