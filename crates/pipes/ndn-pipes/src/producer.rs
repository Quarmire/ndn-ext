//! Producer side: answer the SEEK/JOIN/CHECK control handshake, and serve the
//! pipe's **coded bulk** — K-of-N FEC segments (`ndn-coding`) under the object
//! name, the no-ARQ loss story the thesis lacked.
//!
//! On SEEK the producer mints a random pipe id + pipe key and **seals them to the
//! consumer's public key** (from the SEEK app-params; see [`crate::crypto`]), so
//! only the consumer can recover the id and JOIN. The pipe key — never placed in
//! a name — authenticates TEARDOWN. With [`with_identity`](PipeProducer::with_identity)
//! the SEEK reply is also Ed25519-signed, so a consumer holding the matching
//! trust anchor authenticates the producer and a MITM cannot substitute its own
//! sealed handshake.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use ndn_app::{AppError, Consumer, Producer};
use ndn_coding::{FecPolicy, segment_payload};
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_packet::{Name, SignatureType};
use tokio::sync::Mutex as AsyncMutex;

use crate::crypto::{PIPE_ID_LEN, PIPE_KEY_LEN, ed25519_sign, random_bytes, seal};
use crate::message::{GHL, MessageKind, classify, encode_seek_reply, hop_index};
use crate::registry::PipeRegistry;

/// Default Promised Use Interval: a pipe with no liveness traffic for this long
/// is reclaimed. Mirrors [`PipeParams::default`](crate::PipeParams)'s PUI.
const DEFAULT_PUI: Duration = Duration::from_secs(10);

/// The producer's signing identity: an Ed25519 key + its key-locator name. When
/// set, the producer signs SEEK replies so a consumer holding the matching
/// trust anchor can authenticate the producer (and reject a MITM).
#[derive(Clone)]
struct ProducerIdentity {
    signing_key: [u8; 32],
    key_name: Name,
}

/// Serves the NDN-Pipes control messages plus the coded objects for one pipe.
pub struct PipeProducer {
    producer: Producer,
    /// Full coded-segment name (`<object>/<index>`) → segment content body.
    segments: HashMap<String, Bytes>,
    /// Promised Use Interval: how long a quiet pipe survives before teardown.
    pui: Duration,
    /// Live pipes (deadline + pipe key); shared with the PIPES mgmt module.
    registry: PipeRegistry,
    /// Optional signing identity; when present, SEEK replies are Ed25519-signed.
    identity: Option<ProducerIdentity>,
    /// Optional ndn-security signer (cert-bearing identity). Takes precedence
    /// over `identity`: SEEK replies are signed so a consumer's Validator can
    /// chain the producer to a CA, not just pin a raw key.
    signer: Option<Arc<dyn ndn_security::Signer>>,
    /// Coded segments to **push** to the consumer on JOIN (producer-initiated
    /// delivery over the reflexive reverse route). Empty = pull-only.
    push_segments: Vec<Bytes>,
}

impl PipeProducer {
    pub fn new(producer: Producer) -> Self {
        Self {
            producer,
            segments: HashMap::new(),
            pui: DEFAULT_PUI,
            registry: PipeRegistry::new(),
            identity: None,
            signer: None,
            push_segments: Vec::new(),
        }
    }

    /// Sign SEEK replies with an ndn-security [`Signer`](ndn_security::Signer)
    /// (a cert-bearing identity), so a consumer using a
    /// [`Validator`](ndn_security::Validator) can chain the producer to a trust
    /// anchor / CA — stronger than the pinned-key `with_identity` (TOFU). Takes
    /// precedence over [`with_identity`](Self::with_identity).
    pub fn with_signer(mut self, signer: Arc<dyn ndn_security::Signer>) -> Self {
        self.signer = Some(signer);
        self
    }

    /// Configure a payload to **push** on JOIN: seal it under `conf`, code the
    /// ciphertext (K-of-N), and stash the segments. With this set, drive the
    /// serve loop via [`serve_pushing`](Self::serve_pushing) — the producer then
    /// streams these segments to the consumer over the reflexive reverse route
    /// (server-initiated delivery) instead of waiting to be pulled.
    pub fn push_object(
        mut self,
        payload: &[u8],
        policy: &FecPolicy,
        generation_id: u64,
        conf: &crate::Confidentiality,
    ) -> Self {
        let sealed = conf.seal(payload);
        let segs = segment_payload(&sealed, policy, generation_id).expect("valid FEC policy");
        self.push_segments = segs.into_iter().map(|s| s.content).collect();
        self
    }

    /// Set the Promised Use Interval — a pipe idle (no CHECK) past this is torn
    /// down by inactivity, the thesis's coordinator-free reclaim.
    pub fn with_pui(mut self, pui: Duration) -> Self {
        self.pui = pui;
        self
    }

    /// Give the producer a signing identity (Ed25519 `signing_key`, advertised
    /// under `key_name`). SEEK replies are then signed, so a consumer with the
    /// matching trust anchor authenticates the producer — binding the sealed
    /// handshake to a real identity and closing the bare-ECDH MITM gap.
    pub fn with_identity(mut self, signing_key: [u8; 32], key_name: impl Into<Name>) -> Self {
        self.identity = Some(ProducerIdentity {
            signing_key,
            key_name: key_name.into(),
        });
        self
    }

    /// A shared handle to this producer's live-pipe table, for read-only
    /// introspection (e.g. building a [`PipesModule`](crate::PipesModule)).
    /// Grab it before [`serve`](Self::serve), which consumes the producer.
    pub fn registry(&self) -> PipeRegistry {
        self.registry.clone()
    }

    /// **Encrypt-then-code** an object: seal `payload` under `conf`, then encode
    /// the ciphertext into K-of-N coded segments for `object` and register them.
    /// The coded/relay layer only ever sees ciphertext. `lossy_skip` withholds
    /// segment indices to **simulate per-segment wire loss** — the consumer
    /// recovers from any K via parity, as it would over the no-ARQ radio.
    pub fn serve_object(
        mut self,
        object: &Name,
        payload: &[u8],
        policy: &FecPolicy,
        generation_id: u64,
        lossy_skip: &[u16],
        conf: &crate::Confidentiality,
    ) -> Self {
        let sealed = conf.seal(payload);
        let segs = segment_payload(&sealed, policy, generation_id)
            .expect("valid FEC policy + payload");
        for s in segs {
            if lossy_skip.contains(&s.index) {
                continue; // dropped "on the air"
            }
            let name = object.clone().append(s.index.to_string());
            self.segments.insert(name.to_string(), s.content);
        }
        self
    }

    /// Run the serve loop until the face closes (pull-only). Control messages get
    /// the handshake responses; any other name is looked up as a coded segment.
    pub async fn serve(self) -> Result<(), AppError> {
        self.serve_inner(None).await
    }

    /// Run the serve loop in **push** mode: on JOIN, stream the [`push_object`]
    /// segments to the consumer over the reflexive reverse route (the route the
    /// JOIN's reflexive name installs — now load-bearing), then ack the JOIN.
    /// `side` is a second app face on the same engine used to send the reverse
    /// push Interests while the serve face handles the forward JOIN.
    ///
    /// [`push_object`]: Self::push_object
    pub async fn serve_pushing(self, side: Consumer) -> Result<(), AppError> {
        self.serve_inner(Some(side)).await
    }

    async fn serve_inner(self, side: Option<Consumer>) -> Result<(), AppError> {
        let segments = Arc::new(self.segments);
        let registry = self.registry;
        let pui = self.pui;
        let identity = self.identity;
        let signer = self.signer;
        // Push state: the side consumer (for reverse Interests) + the segments.
        let push = side.map(|s| Arc::new((AsyncMutex::new(s), self.push_segments)));
        self.producer
            .serve(move |interest, responder| {
                let segments = Arc::clone(&segments);
                let registry = registry.clone();
                let identity = identity.clone();
                let signer = signer.clone();
                let push = push.clone();
                async move {
                    let name = (*interest.name).clone();
                    match classify(&name) {
                        Some(MessageKind::Seek) => {
                            // GHL hop accounting: the pipe length is how many
                            // hops the SEEK crossed to reach us, derived purely
                            // from the decremented HopLimit — no coordination.
                            let remaining = interest.hop_limit().unwrap_or(GHL);
                            let pipe_len = hop_index(GHL, remaining);
                            // The consumer's X25519 pubkey rides in the SEEK
                            // app-params; mint a random pipe id + pipe key and
                            // seal them to it, so only the consumer can JOIN.
                            match mint_and_seal(interest.app_parameters().map(|b| b.as_ref())) {
                                Some((pipe_id, pipe_key, sealed)) => {
                                    registry.insert(pipe_id, Instant::now() + pui, pipe_key);
                                    let body = encode_seek_reply(&sealed, pipe_len);
                                    let builder = DataBuilder::new(name, &body);
                                    // Prefer the ndn-security signer (cert-chain
                                    // trust); else the raw identity key (TOFU);
                                    // else a digest-signed reply.
                                    let d = if let Some(signer) = &signer {
                                        // KeyLocator = key name (as ndn-security's
                                        // KeyChain::sign_data does); the validator
                                        // resolves it to the producer's cert.
                                        builder.sign_sync(
                                            signer.sig_type(),
                                            Some(signer.key_name()),
                                            |region| signer.sign_sync(region).unwrap_or_default(),
                                        )
                                    } else if let Some(id) = &identity {
                                        builder.sign_sync(
                                            SignatureType::SignatureEd25519,
                                            Some(&id.key_name),
                                            |region| {
                                                Bytes::copy_from_slice(&ed25519_sign(
                                                    &id.signing_key,
                                                    region,
                                                ))
                                            },
                                        )
                                    } else {
                                        builder.build()
                                    };
                                    responder.respond_bytes(d).await.ok();
                                }
                                // No / malformed consumer key: can't form a pipe.
                                None => drop(responder),
                            }
                        }
                        Some(MessageKind::Join) => {
                            // In push mode, stream the configured segments to the
                            // consumer over the reverse route the JOIN installed,
                            // then ack. Each push is a reverse Interest carrying
                            // the coded segment in its app-params; the consumer
                            // absorbs it and answers with an ACK.
                            if let Some(push) = &push
                                && let Some(r) = interest.reflexive_name()
                            {
                                let r = (**r).clone();
                                let mut sc = push.0.lock().await;
                                for (i, seg) in push.1.iter().enumerate() {
                                    let push_name = r.clone().append("push").append(i.to_string());
                                    let wire = InterestBuilder::new(push_name)
                                        .app_parameters(seg.to_vec())
                                        .lifetime(Duration::from_secs(2))
                                        .build();
                                    sc.fetch_wire(wire, Duration::from_secs(2)).await.ok();
                                }
                            }
                            let d = DataBuilder::new(name, b"JOINED").build();
                            responder.respond_bytes(d).await.ok();
                        }
                        Some(MessageKind::Check) => {
                            // Liveness gate doubling as the PUI keep-alive: answer
                            // OK only while the pipe is held and unexpired, and
                            // renew the promise on the way through. Once torn down
                            // or lapsed, stay silent — the CHECK times out.
                            let alive = pid_at(&name, 0)
                                .map(|k| registry.refresh_if_live(&k, pui))
                                .unwrap_or(false);
                            if alive {
                                let d = DataBuilder::new(name, b"OK").build();
                                responder.respond_bytes(d).await.ok();
                            } else {
                                drop(responder);
                            }
                        }
                        Some(MessageKind::Teardown) => {
                            // Authenticated reclaim: the TEARDOWN must carry the
                            // pipe key (sealed to the consumer, never in a name)
                            // in its app-params. A relay that saw the JOIN knows
                            // the pipe id but not the key, so it cannot forge
                            // this. A teardown for an already-gone pipe is an
                            // idempotent no-op ack (the suppression floor).
                            let provided = interest.app_parameters().map(|b| b.to_vec());
                            let ok = pid_at(&name, 1)
                                .map(|k| registry.teardown_authorized(&k, provided.as_deref()))
                                .unwrap_or(false);
                            if ok {
                                let d = DataBuilder::new(name, b"BYE").build();
                                responder.respond_bytes(d).await.ok();
                            } else {
                                drop(responder);
                            }
                        }
                        _ => match segments.get(&name.to_string()) {
                            Some(content) => {
                                let d = DataBuilder::new(name, content.as_ref()).build();
                                responder.respond_bytes(d).await.ok();
                            }
                            // A segment we don't hold is "lost on the air": don't
                            // respond — the consumer's coded fetcher times out and
                            // over-fetches parity. (A Nack, by contrast, the
                            // fetcher treats as fatal — wrong model for wire loss.)
                            None => drop(responder),
                        },
                    }
                }
            })
            .await
    }
}

/// The pipe-id bytes at component `idx` of a control name (`0` for CHECK's
/// `/{pipe_id}/…`, `1` for TEARDOWN's `/COMMON/{pipe_id}/…`).
fn pid_at(name: &Name, idx: usize) -> Option<Vec<u8>> {
    name.components().get(idx).map(|c| c.value.to_vec())
}

/// Mint a random pipe id + pipe key and seal them to the consumer's X25519
/// public key (from the SEEK app-params). Returns `(pipe_id, pipe_key, sealed)`,
/// or `None` if no usable key was provided.
fn mint_and_seal(consumer_pub: Option<&[u8]>) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let pubk = consumer_pub?;
    let pipe_id = random_bytes(PIPE_ID_LEN)?;
    let pipe_key = random_bytes(PIPE_KEY_LEN)?;
    let mut bundle = Vec::with_capacity(PIPE_ID_LEN + PIPE_KEY_LEN);
    bundle.extend_from_slice(&pipe_id);
    bundle.extend_from_slice(&pipe_key);
    let sealed = seal(pubk, &bundle)?;
    Some((pipe_id, pipe_key, sealed))
}
