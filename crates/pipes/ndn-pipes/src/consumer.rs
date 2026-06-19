//! Consumer side: SEEK a producer, JOIN (installing the reverse route via the
//! pipe id as the reflexive name), and CHECK to confirm the pipe is live.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use ndn_app::{AppError, Consumer};
use ndn_coding::{CodedAssembler, CodedFetcher};
use ndn_crypto_core::verify_data_ed25519;
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_packet::{Interest, Name};

use crate::crypto::{ConsumerSession, PIPE_ID_LEN, PIPE_KEY_LEN};
use crate::message::{
    GHL, check_name, context_name, decode_seek_reply, join_name, seek_name, teardown_name,
};
use crate::{Pipe, PipeError, PipeId, PipeParams};

/// What a SEEK established: the recovered pipe id, the pipe key (for TEARDOWN),
/// and the GHL-derived pipe length.
struct Seeked {
    pipe_id: PipeId,
    teardown_secret: Bytes,
    pipe_len: u32,
}

/// Opens pipes by driving SEEK→JOIN→CHECK over an [`ndn_app::Consumer`].
pub struct PipeConsumer {
    consumer: Consumer,
    /// Producer's Ed25519 trust anchor; when set, the SEEK reply must verify
    /// against it before the sealed pipe id is trusted (authenticates producer).
    trust_anchor: Option<[u8; 32]>,
    /// Optional ndn-security validator (cert-chain trust). Takes precedence over
    /// `trust_anchor`: the SEEK reply must validate to a trusted anchor/CA.
    validator: Option<Arc<ndn_security::Validator>>,
}

impl PipeConsumer {
    pub fn new(consumer: Consumer) -> Self {
        Self {
            consumer,
            trust_anchor: None,
            validator: None,
        }
    }

    /// Validate the SEEK reply through an ndn-security
    /// [`Validator`](ndn_security::Validator): the producer's signature must
    /// chain to a trusted anchor / CA per the validator's trust schema —
    /// stronger than the pinned-key `with_trust_anchor` (TOFU). Takes precedence
    /// over [`with_trust_anchor`](Self::with_trust_anchor).
    pub fn with_validator(mut self, validator: Arc<ndn_security::Validator>) -> Self {
        self.validator = Some(validator);
        self
    }

    /// Pin the producer's Ed25519 public key as a trust anchor: [`open`] then
    /// rejects any SEEK reply not signed by it, so an on-path MITM cannot
    /// substitute its own ephemeral key + pipe id.
    ///
    /// [`open`]: Self::open
    pub fn with_trust_anchor(mut self, anchor: [u8; 32]) -> Self {
        self.trust_anchor = Some(anchor);
        self
    }

    /// **SEEK** the producer: advertise a fresh X25519 pubkey, authenticate the
    /// (optionally signed) reply against the trust anchor, and decrypt the sealed
    /// `pipe_id ‖ pipe_key`. Shared by [`open`](Self::open) and
    /// [`receive`](Self::receive).
    async fn seek(&mut self, ns: &Name) -> Result<Seeked, PipeError> {
        // A fresh per-handshake X25519 session; its public key rides in the SEEK
        // app-params so the producer can seal the pipe id + key back to us.
        let session = ConsumerSession::generate()
            .ok_or_else(|| PipeError::Crypto("handshake keygen failed".into()))?;

        // SEEK — multicast producer search on the common channel. Carry the GHL
        // so the producer can derive the pipe length from the decremented limit.
        let seek = InterestBuilder::new(seek_name(ns))
            .app_parameters(session.public.to_vec())
            .hop_limit(GHL)
            .must_be_fresh()
            .lifetime(Duration::from_secs(2));
        let reply = match self.consumer.fetch_with(seek).await {
            Ok(d) => d,
            Err(AppError::Timeout) => return Err(PipeError::NoProducer(ns.to_string())),
            Err(e) => return Err(PipeError::App(e)),
        };
        // Authenticate the producer before trusting anything it sealed. Prefer
        // the cert-chain validator; else the pinned-key check.
        if let Some(validator) = &self.validator {
            match validator.validate(&reply).await {
                ndn_security::ValidationResult::Valid(_) => {}
                _ => {
                    return Err(PipeError::Crypto(
                        "SEEK reply did not validate to a trusted producer".into(),
                    ));
                }
            }
        } else if let Some(anchor) = self.trust_anchor
            && !verify_data_ed25519(reply.raw(), &anchor)
        {
            return Err(PipeError::Crypto(
                "SEEK reply not signed by the trusted producer".into(),
            ));
        }
        // The reply is `pipe_len ‖ sealed(pipe_id ‖ pipe_key)`. Only we hold the
        // private half, so only we can recover the pipe id — and thus JOIN.
        let content = reply.content().cloned().unwrap_or_default();
        let (sealed, pipe_len_u8) = decode_seek_reply(&content)
            .ok_or_else(|| PipeError::Crypto("SEEK reply was malformed".into()))?;
        let bundle = session
            .open(&sealed)
            .ok_or_else(|| PipeError::Crypto("SEEK reply not sealed for us".into()))?;
        if bundle.len() != PIPE_ID_LEN + PIPE_KEY_LEN {
            return Err(PipeError::Crypto("handshake bundle malformed".into()));
        }
        Ok(Seeked {
            pipe_id: PipeId(Bytes::copy_from_slice(&bundle[..PIPE_ID_LEN])),
            teardown_secret: Bytes::copy_from_slice(&bundle[PIPE_ID_LEN..]),
            // Pipe length learned from GHL hop accounting (not assumed single-hop).
            pipe_len: pipe_len_u8 as u32,
        })
    }

    /// Open a pipe for `namespace`: **SEEK** the producer (and learn the
    /// producer-minted pipe id), **JOIN** carrying the pipe id as the reflexive
    /// name (the engine installs the `pipe_id → us` reverse route on the JOIN's
    /// forward pass), and **CHECK** to confirm liveness. Returns the [`Pipe`].
    pub async fn open(
        &mut self,
        namespace: impl Into<Name>,
        params: PipeParams,
    ) -> Result<Pipe, PipeError> {
        let ns = namespace.into();
        let Seeked {
            pipe_id,
            teardown_secret,
            pipe_len,
        } = self.seek(&ns).await?;

        // JOIN — only we (who hold the pipe id) can form this name. Carry it as
        // the reflexive name so the reverse route is installed in one pass.
        let join = InterestBuilder::new(join_name(&ns, pipe_id.as_bytes()))
            .reflexive_name(reflexive_name(&pipe_id))
            .hop_limit(GHL)
            .must_be_fresh()
            .lifetime(Duration::from_secs(2));
        self.consumer.fetch_with(join).await?;

        // CHECK — final liveness gate.
        let check = InterestBuilder::new(check_name(pipe_id.as_bytes(), pipe_len))
            .hop_limit(GHL)
            .lifetime(Duration::from_secs(2));
        let ok = self.consumer.fetch_with(check).await?;
        if ok.content().map(|c| c.as_ref()) != Some(b"OK".as_slice()) {
            return Err(PipeError::Crypto("CHECK was not OK".into()));
        }

        Ok(Pipe {
            namespace: ns,
            id: pipe_id,
            pipe_len,
            teardown_secret,
            params,
        })
    }

    /// **Receive a pushed object** (producer-initiated). SEEK the producer, then
    /// JOIN carrying the reflexive name and serve the producer's reverse pushes:
    /// each push is a reverse Interest carrying one coded segment in its
    /// app-params, which we absorb until K-of-N recovers the (sealed) bulk; we
    /// answer each with an ACK. The producer answers the JOIN once it has pushed,
    /// ending the session. Returns the decrypted payload.
    ///
    /// Pair with [`PipeProducer::serve_pushing`](crate::PipeProducer::serve_pushing).
    pub async fn receive(
        &mut self,
        namespace: impl Into<Name>,
        params: PipeParams,
    ) -> Result<Bytes, PipeError> {
        let ns = namespace.into();
        let Seeked { pipe_id, .. } = self.seek(&ns).await?;
        let r = reflexive_name(&pipe_id);

        // Reassemble the pushed coded segments; the recovered (sealed) bulk lands
        // here once K segments have been absorbed.
        let assembler = Arc::new(Mutex::new(CodedAssembler::new()));
        let recovered: Arc<Mutex<Option<Bytes>>> = Arc::new(Mutex::new(None));

        // The JOIN is the forward Interest of the reflexive session: it installs
        // the reverse route and keeps it alive while we serve the producer's
        // pushes, until the producer answers the JOIN.
        let join = InterestBuilder::new(join_name(&ns, pipe_id.as_bytes()))
            .reflexive_name(r.clone())
            .hop_limit(GHL)
            .must_be_fresh()
            .lifetime(Duration::from_secs(8));
        let a = Arc::clone(&assembler);
        let rec = Arc::clone(&recovered);
        self.consumer
            .fetch_reflexive(join, r, Duration::from_secs(8), move |reverse: Interest| {
                let a = Arc::clone(&a);
                let rec = Arc::clone(&rec);
                async move {
                    if let Some(seg) = reverse.app_parameters()
                        && let Ok(Some(payload)) = a.lock().unwrap().absorb_content(seg)
                    {
                        *rec.lock().unwrap() = Some(payload);
                    }
                    Ok(DataBuilder::new((*reverse.name).clone(), b"ACK").build())
                }
            })
            .await?;

        let sealed = recovered
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| PipeError::Coding("push ended before K segments arrived".into()))?;
        params
            .confidentiality
            .open(&sealed)
            .ok_or_else(|| PipeError::Crypto("pushed bulk decrypt/auth failed".into()))
    }

    /// Tear the pipe down: send a TEARDOWN carrying the pipe id as the capability
    /// (the real protocol signs it with the pipe private key). The producer (and
    /// any on-path relay) reclaims the pipe and acks `BYE`; teardown is
    /// idempotent, so a repeat is harmless.
    pub async fn close(&mut self, pipe: &Pipe) -> Result<(), PipeError> {
        let i = InterestBuilder::new(teardown_name(pipe.id.as_bytes()))
            .app_parameters(pipe.teardown_secret.to_vec())
            .hop_limit(GHL)
            .must_be_fresh()
            .lifetime(Duration::from_secs(2));
        self.consumer.fetch_with(i).await?;
        Ok(())
    }

    /// Re-CHECK the pipe: `true` while the producer still holds it (within the
    /// PUI), `false` once it has been torn down or the PUI lapsed. `must_be_fresh`
    /// forces a producer round-trip rather than a cached CHECK; a gone pipe stays
    /// silent, so the CHECK times out to `false`.
    pub async fn is_alive(&mut self, pipe: &Pipe) -> bool {
        let check = InterestBuilder::new(check_name(pipe.id.as_bytes(), pipe.pipe_len))
            .hop_limit(GHL)
            .must_be_fresh()
            .lifetime(Duration::from_millis(500));
        match self.consumer.fetch_with(check).await {
            Ok(d) => d.content().map(|c| c.as_ref()) == Some(b"OK".as_slice()),
            Err(_) => false,
        }
    }

    /// Probe the per-hop **CONTEXT** on the COMMON control band. `hop` is the
    /// consumer's addressing guess; the relay that answers reports the hop index
    /// it derived *for itself* from GHL − remaining HopLimit — coordinator-free
    /// addressing, the thesis's claim that no node is told its position.
    pub async fn context(&mut self, pipe: &Pipe, hop: u32) -> Result<u8, PipeError> {
        let i = InterestBuilder::new(context_name(pipe.id.as_bytes(), hop))
            .hop_limit(GHL)
            .must_be_fresh()
            .lifetime(Duration::from_secs(2));
        let d = self.consumer.fetch_with(i).await?;
        d.content()
            .and_then(|c| c.first().copied())
            .ok_or_else(|| PipeError::Crypto("CONTEXT reply was empty".into()))
    }

    /// Fetch `object` (a suffix under the pipe's namespace) over `pipe`. With a
    /// FEC policy, runs the K-of-N coded transfer (`ndn-coding`): pull source
    /// segments, over-fetch parity on loss, recover from any K — the no-ACK loss
    /// recovery the bearer needs. Without FEC, a single object fetch.
    pub async fn fetch(
        &mut self,
        pipe: &Pipe,
        object: impl Into<Name>,
    ) -> Result<Bytes, PipeError> {
        let name = extend(&pipe.namespace, &object.into());
        // Decode the (possibly coded) bulk, then decrypt — encrypt-then-code in
        // reverse. The recovered bytes are ciphertext when the pipe is sealed.
        let recovered = match &pipe.params.fec {
            Some(policy) => CodedFetcher::new()
                .fetch(&self.consumer, name, policy)
                .await
                .map_err(|e| PipeError::Coding(e.to_string()))?,
            None => self.consumer.fetch_object(name).await?,
        };
        pipe.params
            .confidentiality
            .open(&recovered)
            .ok_or_else(|| PipeError::Crypto("bulk decrypt/auth failed".into()))
    }
}

/// `prefix ++ suffix` (component-wise).
fn extend(prefix: &Name, suffix: &Name) -> Name {
    let mut n = prefix.clone();
    for c in suffix.components() {
        n = n.append_component(c.clone());
    }
    n
}

/// The reflexive (reverse-push) name for a pipe: `/rfx/{pipe_id}`. It MUST be
/// disjoint from the forward-fetch names (`/{pipe_id}/…/CHECK`, the bulk
/// namespace) — otherwise the reverse route `/rfx… → consumer` would shadow the
/// FIB and bounce the consumer's own forward Interests back to itself.
fn reflexive_name(pipe_id: &PipeId) -> Name {
    Name::from("/rfx").append(pipe_id.as_bytes())
}
