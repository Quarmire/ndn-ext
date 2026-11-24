//! The certificate fetch budget of run headers (heap.md §11.3): what a header costs the network.
//!
//! The validator is real over each person's trust context, the headers are signed by real
//! Ed25519 keys, and certificates are fetched through a fetch function the case controls; the
//! node's own answers (who a header's signer is, the view) are the node's to test.

use std::future::pending;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_foundation_types::{Name, NameComponent};
use ndn_packet::encode::DataBuilder;
use ndn_security::{
    Certificate, FetchMiss, SecurityManager, SignedTrustContext, TrustSchema, Validator,
};

use super::*;

const VALIDITY_MS: u64 = 365 * 24 * 3600 * 1000;

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

/// The run id of every header here.
const RUN: [u8; 16] = [7; 16];

/// One person's authority: its key store, its key and its anchor.
struct Authority {
    ns: Name,
    keys: SecurityManager,
    issuer: Name,
}

/// The persons `/bob` and `/rita`, held by the one validator every case judges by.
struct World {
    validator: Arc<Validator>,
    people: Vec<Authority>,
}

/// A device with its key: what signs, and what the transport knows of it.
struct Dev {
    name: Name,
    key: Name,
    person: Name,
    keys: SecurityManager,
}

impl World {
    async fn new() -> World {
        let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
        let mut people = Vec::new();
        for ns in ["/bob", "/rita"] {
            let ns = n(ns);
            let keys = SecurityManager::new();
            let issuer = keys
                .generate_ed25519(ns.clone().append("KEY").append("ns"))
                .unwrap();
            let public = keys.get_signer_sync(&issuer).unwrap().public_key().unwrap();
            let anchor = keys
                .issue_self_signed_async(&issuer, public, VALIDITY_MS)
                .await
                .unwrap();
            let ctx = SignedTrustContext::hierarchical(ns.clone()).with_version(1);
            assert!(ctx.add_anchor(anchor));
            validator.adopt_context(Arc::new(ctx)).unwrap();
            people.push(Authority { ns, keys, issuer });
        }
        World { validator, people }
    }

    /// `device`'s key `KEY/<id>`, certified by its person's authority for `validity_ms` from
    /// now; the certificate is held by the validator only when `held`. The certificate is
    /// returned too, for a fetch to serve.
    async fn dev_key(
        &self,
        device: &str,
        id: &str,
        validity_ms: u64,
        held: bool,
    ) -> (Dev, Certificate) {
        let name = n(device);
        let a = self
            .people
            .iter()
            .find(|a| name.has_prefix(&a.ns))
            .expect("a device of a person of the world");
        let keys = SecurityManager::new();
        let key = keys
            .generate_ed25519(name.clone().append("KEY").append(id))
            .unwrap();
        let public = keys.get_signer_sync(&key).unwrap().public_key().unwrap();
        let cert = a
            .keys
            .certify(&key, public, &a.issuer, validity_ms)
            .await
            .unwrap();
        if held {
            self.validator.cert_cache().insert(cert.clone());
        }
        let dev = Dev {
            person: a.ns.clone(),
            keys,
            name,
            key,
        };
        (dev, cert)
    }

    /// A device whose certificate is held.
    async fn dev(&self, device: &str) -> Dev {
        self.dev_key(device, "1", VALIDITY_MS, true).await.0
    }
}

impl Dev {
    /// Its signed run header of the space `/alice/32=data/board`, and what the node would have
    /// answered of its signer.
    fn header(&self) -> (SignalSender, Data) {
        let mut comps = self.name.components().to_vec();
        comps.push(NameComponent::keyword(Bytes::from_static(b"signal")));
        comps.extend(n("/alice/32=data/board").components().iter().cloned());
        comps.push(NameComponent::keyword(Bytes::from_static(b"run")));
        comps.push(NameComponent::generic(Bytes::copy_from_slice(&RUN)));
        let signer = self.keys.get_signer_sync(&self.key).unwrap();
        let wire = DataBuilder::new(Name::from_components(comps), b"run").sign_sync(
            signer.sig_type(),
            Some(signer.key_name()),
            |region| signer.sign_sync(region).unwrap(),
        );
        let sender = SignalSender {
            key: self.key.clone(),
            device: self.name.clone(),
            namespace: self.person.clone(),
        };
        (sender, Data::decode(wire).unwrap())
    }
}

/// What the fetch was asked, in order.
type Asked = Arc<Mutex<Vec<Name>>>;

/// The validator fetches missing certificates through a fetch that notes every name asked,
/// never answers a name under `/bob/slow` or `/rita/slow`, answers a name `serve` holds a
/// certificate of with it, and answers every other that none is to be had.
fn fetching(world: &World, serve: Vec<Certificate>) -> Asked {
    let asked: Asked = Arc::default();
    let noted = Arc::clone(&asked);
    let serve: Vec<Bytes> = serve.iter().map(|c| c.data_wire().unwrap()).collect();
    let fetch: ndn_security::FetchFn = Arc::new(move |name: Name| {
        noted.lock().unwrap().push(name.clone());
        let served = serve
            .iter()
            .map(|w| Data::decode(w.clone()).unwrap())
            .find(|d| d.name.has_prefix(&name));
        Box::pin(async move {
            if name.has_prefix(&n("/bob/slow")) || name.has_prefix(&n("/rita/slow")) {
                pending::<()>().await;
            }
            served.ok_or(FetchMiss::Absent)
        })
    });
    let fetcher = ndn_security::CertFetcher::new(
        world.validator.cert_cache_arc(),
        fetch,
        Duration::from_secs(60),
    )
    .with_negative_ttl(Duration::ZERO);
    assert!(world.validator.set_cert_fetcher(Arc::new(fetcher)).is_ok());
    asked
}

/// A header signed by a key whose certificate is held verifies at once and asks for nothing; one
/// damaged on the way does not verify.
#[tokio::test]
async fn a_header_under_a_held_certificate_verifies_and_a_damaged_one_does_not() {
    let world = World::new().await;
    let asked = fetching(&world, Vec::new());
    let gate = Gate::default();
    let bob = world.dev("/bob/phone").await;
    let (sender, header) = bob.header();
    gate.verify(&world.validator, &sender, &header)
        .await
        .expect("a member's header under a held certificate");
    assert!(asked.lock().unwrap().is_empty(), "nothing was fetched");

    let mut damaged = header.raw().to_vec();
    *damaged.last_mut().unwrap() ^= 1;
    assert_eq!(
        gate.verify(
            &world.validator,
            &sender,
            &Data::decode(Bytes::from(damaged)).unwrap()
        )
        .await,
        Err(SignalRefusal::BadSignature {
            key: bob.key.clone()
        })
    );
}

/// Live data is admitted by the live rule: a header signed by a key whose certificate has
/// expired is refused though nothing revokes the key.
#[tokio::test]
async fn a_header_under_an_expired_certificate_is_refused() {
    let world = World::new().await;
    let (bob, _) = world.dev_key("/bob/phone", "2", 1, true).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    let (sender, header) = bob.header();
    match Gate::default()
        .verify(&world.validator, &sender, &header)
        .await
    {
        Err(r @ SignalRefusal::BadSignature { .. }) => {
            assert!(r.to_string().contains("expired"), "{r}")
        }
        other => panic!("a header under an expired certificate: {other:?}"),
    }
}

/// A member's header whose certificate is not held is admitted once the chain is fetched, by
/// asking for exactly the certificate its chain needs.
#[tokio::test]
async fn a_member_header_verifies_after_the_chain_fetch() {
    let world = World::new().await;
    let (bob, cert) = world.dev_key("/bob/phone", "3", VALIDITY_MS, false).await;
    let asked = fetching(&world, vec![cert.clone()]);
    let (sender, header) = bob.header();

    Gate::default()
        .verify(&world.validator, &sender, &header)
        .await
        .expect("verified after the fetch");
    let asked = asked.lock().unwrap().clone();
    assert_eq!(asked.len(), 1, "one certificate: {asked:?}");
    assert!(cert.name.has_prefix(&asked[0]), "the signer's: {asked:?}");
}

/// A header's certificates are fetched for a member only within its namespace's budget: 2
/// headers of one namespace wait for certificates at a time, the others are refused at once and
/// asked again; a member whose certificate is held is admitted meanwhile and another namespace
/// has a budget of its own. Time is tokio's, paused.
#[tokio::test]
async fn the_fetch_budget_bounds_waiting_headers() {
    let world = World::new().await;
    let gate = Arc::new(Gate::default());
    let asked = fetching(&world, Vec::new());
    let mut slow = Vec::new();
    for d in ["/bob/slow/1", "/bob/slow/2", "/bob/slow/3", "/bob/slow/4"] {
        slow.push(world.dev_key(d, "1", VALIDITY_MS, false).await.0.header());
    }
    let rita = world
        .dev_key("/rita/slow/1", "1", VALIDITY_MS, false)
        .await
        .0
        .header();
    let held = world.dev("/bob/phone").await;
    tokio::time::pause();

    let tasks: Vec<_> = slow
        .iter()
        .chain([&rita])
        .map(|(sender, header)| {
            let gate = Arc::clone(&gate);
            let validator = Arc::clone(&world.validator);
            let (sender, header) = (sender.clone(), Data::decode(header.raw().clone()).unwrap());
            tokio::spawn(async move { gate.verify(&validator, &sender, &header).await })
        })
        .collect();
    tokio::time::sleep(Duration::from_millis(200)).await;

    let fetching: Vec<Name> = asked.lock().unwrap().clone();
    let of = |ns: &str| fetching.iter().filter(|x| x.has_prefix(&n(ns))).count();
    assert_eq!(
        of("/bob"),
        2,
        "a namespace holds 2 fetches at once: {fetching:?}"
    );
    assert_eq!(of("/rita"), 1, "another namespace has its own budget");
    let refused: Vec<usize> = (0..slow.len())
        .filter(|i| tasks[*i].is_finished())
        .collect();
    assert_eq!(refused.len(), 2, "the others are refused at once");

    // A member whose certificate is held is not asked to wait.
    let (sender, header) = held.header();
    assert_eq!(
        gate.verify(&world.validator, &sender, &header).await,
        Ok(())
    );

    let mut waiting = Vec::new();
    for (i, task) in tasks.into_iter().enumerate() {
        if refused.contains(&i) {
            match task.await.unwrap() {
                Err(r @ SignalRefusal::Unverified { .. }) => {
                    let text = r.to_string();
                    assert!(
                        text.contains("2 run headers of /bob wait") && text.contains("again"),
                        "{text}"
                    );
                }
                other => panic!("over its namespace's fetches: {other:?}"),
            }
        } else {
            waiting.push(task);
        }
    }
    // The fetches that never answer end with the fetcher's own timeout and each refuses its
    // header: the slots are given back.
    for task in waiting {
        assert!(matches!(
            task.await.unwrap(),
            Err(SignalRefusal::Unverified { .. })
        ));
    }
    let slots = gate.waiting.0.lock().unwrap().len();
    assert_eq!(slots, 0, "every place is given back");
}

/// A device whose certificate could not be had is not fetched for again for 30 s, whatever key
/// id its next header names, and is fetched for again once they are over: a fresh key id per
/// header drives no fetch per header.
#[tokio::test]
async fn a_device_whose_certificate_could_not_be_had_is_not_asked_again_for_30_seconds() {
    let world = World::new().await;
    let gate = Gate::default();
    let asked = fetching(&world, Vec::new());
    let mut headers = Vec::new();
    for id in ["1", "2", "3", "4"] {
        let (dev, _) = world.dev_key("/bob/tablet", id, VALIDITY_MS, false).await;
        headers.push(dev.header());
    }
    tokio::time::pause();

    for (i, (sender, header)) in headers[..3].iter().enumerate() {
        match gate.verify(&world.validator, sender, header).await {
            Err(r @ SignalRefusal::Unverified { .. }) => {
                if i > 0 {
                    assert!(r.to_string().contains("30 s"), "{r}");
                }
            }
            other => panic!("no certificate of the key is to be had: {other:?}"),
        }
        assert_eq!(
            asked.lock().unwrap().len(),
            1,
            "header {i}: one fetch for the device, then none while it backs off"
        );
    }
    tokio::time::advance(Duration::from_secs(31)).await;
    let (sender, header) = &headers[3];
    assert!(gate.verify(&world.validator, sender, header).await.is_err());
    assert_eq!(asked.lock().unwrap().len(), 2, "asked again after 30 s");
}
