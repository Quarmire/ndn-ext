//! What a device of a self-certifying person serves on its own engine, as a
//! daemon does, so that another person's host can adopt the person **by name**
//! over the network (`ndn_identity::adopt_scoped_via_engine`): the namespace's
//! trust-context versions (RDR: the genesis, then the version the device
//! holds) and the device's own certificate. The same approach as the
//! conformance reference host's.

use std::sync::Arc;

use bytes::Bytes;
use ndn_engine::ForwarderEngine;
use ndn_namespace::publish::{OwnCertificates, PublishedContexts};
use ndn_namespace::{ContextStore, StoredContext};
use ndn_packet::{Data, Name};
use ndn_security::{SignedTrustContext, Validator};
use tokio_util::sync::CancellationToken;

/// What the device holds of its namespace's trust context when its publisher
/// starts: version 1, the genesis, as the root signed it. Later versions are
/// published as the device holds them.
struct FirstVersion {
    data: Data,
}

impl FirstVersion {
    fn stored(&self) -> Vec<StoredContext> {
        let read = Data::decode(self.data.raw().clone())
            .map_err(|e| format!("{e:?}"))
            .and_then(|data| {
                ndn_cert::open_signed_context(&data)
                    .map(|(ctx, _)| (ctx, data))
                    .map_err(|e| e.to_string())
            });
        vec![StoredContext {
            location: self.location(),
            read,
        }]
    }
}

impl ContextStore for FirstVersion {
    fn location(&self) -> String {
        format!("the test's memory of {}", self.data.name)
    }

    fn persist(&self, ctx: &SignedTrustContext, _data: &Data) -> Result<String, String> {
        Err(format!(
            "{} version {} is not kept here: the test publishes the versions it holds",
            ctx.namespace(),
            ctx.version()
        ))
    }

    fn stored_contexts(&self) -> Result<Vec<StoredContext>, String> {
        Ok(self.stored())
    }

    fn stored_versions(&self, namespace: &Name) -> Result<Vec<StoredContext>, String> {
        Ok(
            if self.data.name.has_prefix(&ndn_cert::rdr_prefix(namespace)) {
                self.stored()
            } else {
                Vec::new()
            },
        )
    }

    fn holds_root_key(&self, _ctx: &SignedTrustContext) -> bool {
        false
    }

    fn persist_cut_manifest(&self, namespace: &Name, _wire: &Bytes) -> Result<String, String> {
        Err(format!("a cut manifest of {namespace} is not kept here"))
    }

    fn stored_cut_manifests(&self, _namespace: &Name) -> Result<Vec<Bytes>, String> {
        Ok(Vec::new())
    }
}

/// What a device serves for its self-certifying namespace `ns`: `genesis` and
/// `newest` (the signed context it holds) by name, and its own certificate
/// `chain`. Alive as long as the returned handles.
pub struct Serving {
    _contexts: PublishedContexts,
    _certificates: Arc<OwnCertificates>,
}

pub fn serve_own_context(
    engine: &ForwarderEngine,
    validator: &Validator,
    cancel: &CancellationToken,
    genesis: Bytes,
    newest: Bytes,
    certificate: Vec<Bytes>,
) -> Serving {
    let genesis = Data::decode(genesis).expect("the genesis decodes");
    let newest = Data::decode(newest).expect("the newest context decodes");
    let first = FirstVersion { data: genesis };
    let (face, publisher) = ndn_namespace::publish::prepare(&first, engine.faces().alloc_id());
    engine.add_face(face, cancel.child_token());
    let contexts = publisher.spawn(engine);
    let held = validator
        .keyring()
        .contexts()
        .into_iter()
        .find(|c| newest.name.has_prefix(&ndn_cert::rdr_prefix(c.namespace())))
        .expect("the device holds its own namespace's context");
    contexts.publish(&held, &newest);
    let certificates = OwnCertificates::spawn(
        engine,
        certificate,
        &[],
        validator.keyring(),
        cancel.child_token(),
    );
    Serving {
        _contexts: contexts,
        _certificates: certificates,
    }
}
