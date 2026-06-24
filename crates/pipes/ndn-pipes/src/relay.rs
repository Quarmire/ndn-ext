//! Relay side: a node *between* consumer and producer that participates in pipe
//! formation on the COMMON control band, while the engine forwards the data
//! plane toward the producer.
//!
//! Faithful to the thesis's coordinator-free addressing: the relay derives its
//! own hop index from `GHL − remaining HopLimit` — no configuration, no central
//! assignment — and answers CONTEXT/LINK/PIPE for its hop.
//!
//! **G3 slice 1 — relay pipe-key handoff.** A relay now obtains and holds the pipe
//! key (the teardown credential) via the PIPE exchange: [`learn_pipe_key`] fetches it
//! sealed from upstream into a [`RelayPipeStore`], and the relay's PIPE handler then
//! re-seals that stored key to *its* adjacent downstream node — propagating the key
//! down the path. Holding the key is the prerequisite for relay-side PUI teardown
//! (slices 2–3) and the PathControl migration (slice 4).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ndn_app::{AppError, Consumer, Producer};
use ndn_packet::Name;
use ndn_packet::encode::DataBuilder;

use crate::crypto::seal;
use crate::keyexchange::fetch_pipe_key;
use crate::message::{GHL, MessageKind, classify, encode_pipe_bundle, hop_index};

/// A relay's table of pipe keys it has learned (id → key + PUI), the teardown
/// credential for pipes passing through it. Cheaply cloneable (`Arc`): the learn path
/// inserts, the serve loop reads to re-seal, and (slice 3) the teardown path checks +
/// reaps. Mirrors the producer's `PipeRegistry`.
#[derive(Clone, Default)]
pub struct RelayPipeStore {
    inner: Arc<Mutex<HashMap<Vec<u8>, RelayEntry>>>,
}

struct RelayEntry {
    pipe_key: Vec<u8>,
    pui: Duration,
    deadline: Instant,
}

impl RelayPipeStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn insert(&self, id: Vec<u8>, pipe_key: Vec<u8>, pui: Duration) {
        self.inner.lock().unwrap().insert(
            id,
            RelayEntry {
                pipe_key,
                pui,
                deadline: Instant::now() + pui,
            },
        );
    }

    /// The `(pipe_key, pui)` for a live pipe — for re-sealing it downstream.
    pub fn bundle(&self, id: &[u8]) -> Option<(Vec<u8>, Duration)> {
        let m = self.inner.lock().unwrap();
        m.get(id)
            .filter(|e| Instant::now() <= e.deadline)
            .map(|e| (e.pipe_key.clone(), e.pui))
    }

    /// The pipe key for a live pipe (membership credential).
    pub fn pipe_key(&self, id: &[u8]) -> Option<Vec<u8>> {
        self.bundle(id).map(|(k, _)| k)
    }

    /// Authorize (and perform) a teardown of this relay's pipe state: the supplied
    /// secret must equal the stored pipe key (membership). Used by slice 3. An
    /// unknown/already-gone pipe is an idempotent success.
    pub fn teardown_authorized(&self, id: &[u8], secret: Option<&[u8]>) -> bool {
        let mut m = self.inner.lock().unwrap();
        match m.get(id) {
            Some(e) => {
                if secret == Some(e.pipe_key.as_slice()) {
                    m.remove(id);
                    true
                } else {
                    false
                }
            }
            None => true,
        }
    }
}

/// A pipe relay: serves the COMMON control channel for one node on the path.
/// Its [`Producer`] must be registered on the relay engine for [`COMMON_PREFIX`]
/// (`/COMMON`); non-control names are left to the engine to forward onward.
///
/// [`COMMON_PREFIX`]: crate::message::COMMON_PREFIX
pub struct PipeRelay {
    producer: Producer,
    store: RelayPipeStore,
}

impl PipeRelay {
    pub fn new(producer: Producer) -> Self {
        Self {
            producer,
            store: RelayPipeStore::new(),
        }
    }

    /// The shared pipe-key store (for tests / a PIPES introspection module).
    pub fn store(&self) -> RelayPipeStore {
        self.store.clone()
    }

    /// Learn the pipe key for `pipe_id` from the adjacent upstream node (`upstream_hop`
    /// = this relay's hop + 1) via the PIPE exchange, storing it. Call during pipe
    /// formation; returns whether a key was obtained.
    pub async fn learn_pipe_key(
        &self,
        upstream: &mut Consumer,
        pipe_id: &[u8],
        upstream_hop: u32,
        timeout: Duration,
    ) -> bool {
        match fetch_pipe_key(upstream, pipe_id, upstream_hop, timeout).await {
            Some((key, pui)) => {
                self.store.insert(pipe_id.to_vec(), key.to_vec(), pui);
                true
            }
            None => false,
        }
    }

    /// Serve the COMMON control band. On a PIPE request, if this relay holds the pipe
    /// key it re-seals it to the requester (propagating the credential downstream);
    /// otherwise — and for CONTEXT/LINK — it reports the locally-derived hop index
    /// (coordinator-free addressing). Anything else is left unanswered.
    pub async fn serve(self) -> Result<(), AppError> {
        let store = self.store.clone();
        self.producer
            .serve(move |interest, responder| {
                let store = store.clone();
                async move {
                    let name = (*interest.name).clone();
                    let remaining = interest.hop_limit().unwrap_or(GHL);
                    let hop = hop_index(GHL, remaining);
                    match classify(&name) {
                        Some(MessageKind::Pipe) => {
                            // Re-seal the stored pipe key to the downstream requester
                            // if we hold it (the key handoff); else fall back to the
                            // hop-index report used during formation.
                            let resealed = pid_at1(&name)
                                .and_then(|id| store.bundle(&id))
                                .zip(interest.app_parameters())
                                .and_then(|((key, pui), pubkey)| {
                                    seal(pubkey, &encode_pipe_bundle(&key, pui.as_millis() as u64))
                                });
                            let d = match resealed {
                                Some(sealed) => DataBuilder::new(name, &sealed).build(),
                                None => DataBuilder::new(name, &[hop]).build(),
                            };
                            responder.respond_bytes(d).await.ok();
                        }
                        Some(MessageKind::Context | MessageKind::Link) => {
                            let d = DataBuilder::new(name, &[hop]).build();
                            responder.respond_bytes(d).await.ok();
                        }
                        _ => drop(responder),
                    }
                }
            })
            .await
    }
}

/// The pipe-id bytes at component 1 of a `/COMMON/{pipe_id}/…` control name.
fn pid_at1(name: &Name) -> Option<Vec<u8>> {
    name.components().get(1).map(|c| c.value.to_vec())
}
