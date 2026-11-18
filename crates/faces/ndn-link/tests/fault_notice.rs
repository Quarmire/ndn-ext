//! The fault layer announces itself, and only a build that has it does: with the cargo
//! feature `fault-injection` (tests only), `Links::start` logs a warning and
//! `LinkReport::fault_injection` is `Some`; in every other build the field exists and
//! is `None`, and nothing is logged. This file runs in both builds
//! (`cargo test -p ndn-link` and `cargo test -p ndn-link --features fault-injection`).

use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use ndn_face_quic::{KeyFingerprint, LinkKey, LinkKeySource, LinkTransportConfig};
use ndn_link::{ConfiguredEndpoints, FaceSink, FaultReport, LinkSetup, LinkTrust, Links, Route};
use ndn_packet::Name;
use ndn_security::{Certificate, Ed25519Signer, Keyring};
use ndn_transport::{Face, FaceId};
use parking_lot::Mutex;
use tokio_util::sync::CancellationToken;
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Level, Metadata};

struct NoTrust(Arc<Keyring>);

impl LinkTrust for NoTrust {
    fn keyring(&self) -> &Arc<Keyring> {
        &self.0
    }
    fn own_chain(&self) -> Vec<Bytes> {
        Vec::new()
    }
    fn known_certificate(&self, _: &Name) -> Option<Certificate> {
        None
    }
    fn known_certificate_of_key(&self, _: &KeyFingerprint) -> Option<Certificate> {
        None
    }
}

/// A forwarder that takes nothing: no link is made here.
#[derive(Default)]
struct NoFaces(AtomicU64);

impl FaceSink for NoFaces {
    fn alloc_face_id(&self) -> FaceId {
        FaceId(self.0.fetch_add(1, Ordering::SeqCst) + 1)
    }
    fn add_face(&self, _: Face, _: CancellationToken) {}
    fn remove_face(&self, _: FaceId) {}
    fn add_routes(&self, _: FaceId, _: &[Route]) {}
    fn remove_routes(&self, _: FaceId, _: &[Name]) {}
    fn routes_to(&self, _: FaceId) -> bool {
        false
    }
    fn transit(&self, _: &Name, _: bool) {}
}

/// Collects the message of every warning logged on this thread.
struct Warnings(Arc<Mutex<Vec<String>>>);

struct Message(String);

impl Visit for Message {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(self.0, "{value:?}");
        }
    }
}

impl tracing::Subscriber for Warnings {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }
    fn record(&self, _: &Id, _: &Record<'_>) {}
    fn record_follows_from(&self, _: &Id, _: &Id) {}
    fn event(&self, event: &Event<'_>) {
        if *event.metadata().level() == Level::WARN {
            let mut message = Message(String::new());
            event.record(&mut message);
            self.0.lock().push(message.0);
        }
    }
    fn enter(&self, _: &Id) {}
    fn exit(&self, _: &Id) {}
}

#[tokio::test]
async fn a_build_with_the_fault_layer_says_so_and_no_other_does() {
    let warnings = Arc::new(Mutex::new(Vec::new()));
    let cancel = CancellationToken::new();
    let key = LinkKey::from_signer(Arc::new(Ed25519Signer::from_seed(
        &[9; 32],
        "/ns/member/d9/KEY/k".parse().unwrap(),
    )))
    .unwrap();
    let key: Arc<dyn LinkKeySource> = Arc::new(key);
    let guard = tracing::subscriber::set_default(Warnings(Arc::clone(&warnings)));
    let links = Links::start(
        LinkSetup {
            peers: Vec::new(),
            key,
            trust: Arc::new(NoTrust(Arc::new(Keyring::new()))),
            faces: Arc::new(NoFaces::default()),
            paths: Arc::new(ConfiguredEndpoints),
            candidates: Vec::new(),
            socket: None,
            transport: LinkTransportConfig::default(),
            relays: Default::default(),
            service: Default::default(),
            direct: Default::default(),
        },
        cancel.child_token(),
    );
    drop(guard);
    let report = links.report();
    let said: Vec<String> = warnings
        .lock()
        .iter()
        .filter(|w| w.contains("fault-injection"))
        .cloned()
        .collect();
    if cfg!(feature = "fault-injection") {
        assert_eq!(
            report.fault_injection,
            Some(FaultReport::default()),
            "a build with the layer reports it, even with no plan installed"
        );
        assert_eq!(said.len(), 1, "one notice at start: {said:?}");
        assert!(
            said[0].contains("can drop, duplicate, forge and delay packets")
                && said[0].contains("must not be in a production build"),
            "the notice says what it does and that it is for tests: {}",
            said[0]
        );
    } else {
        assert_eq!(
            report.fault_injection, None,
            "a build without the layer has none to report"
        );
        assert!(said.is_empty(), "and says nothing: {said:?}");
    }
    cancel.cancel();
}
