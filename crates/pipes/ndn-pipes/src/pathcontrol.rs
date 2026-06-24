//! G3 slice 4 — pipe teardown over the generic **PathControl** path-walk.
//!
//! Slices 1–3 gave relays real per-hop pipe state (the pipe key from the PIPE
//! exchange, an inactivity monitor, and a membership-authenticated teardown-receive
//! handler). This module migrates the *wire* + the *walk*: instead of a bespoke
//! `/COMMON/{id}/TEARDOWN` Interest hitting each node's serve loop, a single
//! [`PathControl`] `Teardown` named `<namespace>/32=PC/Teardown/<seq>` walks the pipe's
//! path, and the forwarder's PathControl hook reaps the pipe state at every hop it
//! crosses — producer *and* relays — in one sweep.
//!
//! The trust model is unchanged and faithful to the thesis (NDNPIPES.pdf pp. 41–46):
//! teardown is authorized by **pipe membership** — possession of the pipe key handed
//! out in the PIPE exchange — not by a prefix-namespace signature. So this rides
//! PathControl's *pluggable* [`PathAuthorizer`]: the pipe key carried in the message's
//! ApplicationParameters is the membership credential. (MAP-Me's `Redirect` keeps its
//! `Validator` authorizer; pipes never `Redirect` — they teardown-and-rebuild.)
//!
//! Feature-gated (`pathcontrol`) so the core stays forwarder-agnostic.

use bytes::Bytes;
use ndn_engine::{PathAuthorizer, PathControlObserver};
use ndn_packet::encode::InterestBuilder;
use ndn_packet::{Interest, Name};
use ndn_pathcontrol::{PathControl, PathOp};

use crate::registry::PipeRegistry;
use crate::relay::RelayPipeStore;

/// The membership view a node has of the pipes it holds — exactly what a PathControl
/// teardown needs to authorize and reap. Implemented by the producer's [`PipeRegistry`]
/// and a relay's [`RelayPipeStore`], so the *same* [`PipeTeardownControl`] adapter hosts
/// either on its engine.
pub trait PipeMembership: Send + Sync {
    /// The pipe key for `id`, if this node holds the pipe (the membership credential to
    /// compare against). `None` ⇒ not a member of this pipe.
    fn pipe_key(&self, id: &[u8]) -> Option<Vec<u8>>;

    /// Membership-reap: remove the pipe **iff** `key` matches the held pipe key. Returns
    /// the pipe's namespace when it was held *and* the key matched (so the caller can
    /// suppress sibling self-announcements); `None` otherwise (not held, or wrong key).
    fn reap(&self, id: &[u8], key: &[u8]) -> Option<Name>;

    /// Cancel this node's pending self-announcement for `namespace` on hearing a peer's
    /// teardown first (relay hop-order suppression). Default no-op (the producer is the
    /// path's root — it has no peer to defer to).
    fn suppress_namespace(&self, _namespace: &Name) {}
}

impl PipeMembership for RelayPipeStore {
    fn pipe_key(&self, id: &[u8]) -> Option<Vec<u8>> {
        RelayPipeStore::pipe_key(self, id)
    }

    fn reap(&self, id: &[u8], key: &[u8]) -> Option<Name> {
        // Not held ⇒ nothing to reap (and no namespace to suppress).
        let namespace = self.namespace_of(id)?;
        // `teardown_authorized` is the membership check + the reap (idempotent); it
        // returns false on a key mismatch, leaving the state intact.
        if self.teardown_authorized(id, Some(key)) {
            Some(namespace)
        } else {
            None
        }
    }

    fn suppress_namespace(&self, namespace: &Name) {
        self.suppress(namespace);
    }
}

impl PipeMembership for PipeRegistry {
    fn pipe_key(&self, id: &[u8]) -> Option<Vec<u8>> {
        PipeRegistry::pipe_key(self, id)
    }

    fn reap(&self, id: &[u8], key: &[u8]) -> Option<Name> {
        // The producer is the path root: it reaps on a key match but tracks no
        // per-pipe namespace and never suppresses (no peer to defer to).
        let _ = self.teardown_authorized(id, Some(key));
        None
    }
}

/// app-params codec for a pipe PathControl teardown: `id_len(u32 BE) ‖ id ‖ pipe_key`.
/// The pipe key trails the id and is the membership credential.
pub fn encode_pipe_teardown_params(id: &[u8], key: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + id.len() + key.len());
    v.extend_from_slice(&(id.len() as u32).to_be_bytes());
    v.extend_from_slice(id);
    v.extend_from_slice(key);
    v
}

/// Inverse of [`encode_pipe_teardown_params`]: `(pipe id, pipe key)`. `None` if the
/// blob is truncated or carries no key.
pub fn decode_pipe_teardown_params(p: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let len_bytes: [u8; 4] = p.get(..4)?.try_into().ok()?;
    let id_len = u32::from_be_bytes(len_bytes) as usize;
    let rest = p.get(4..)?;
    let id = rest.get(..id_len)?;
    let key = rest.get(id_len..)?;
    if key.is_empty() {
        return None;
    }
    Some((id.to_vec(), key.to_vec()))
}

/// Build an (unsigned) PathControl `Teardown` Interest for a pipe:
/// `<namespace>/32=PC/Teardown/<seq>` carrying `(id, key)` in ApplicationParameters.
/// Unsigned because the authorization is *membership* (the key in app-params), not a
/// namespace signature — see the module docs. `seq` is the PathControl loop/dedup guard;
/// use a per-emitter monotonic counter (collisions across emitters are benign — the
/// forwarder's `SeqStore` simply dedups them, which is the announcement suppression).
pub fn pipe_teardown_interest(namespace: &Name, id: &[u8], key: &[u8], seq: u64) -> Bytes {
    let name = PathControl::new(namespace.clone(), PathOp::Teardown, seq).to_name();
    InterestBuilder::new(name)
        .app_parameters(encode_pipe_teardown_params(id, key))
        .build()
}

/// Hosts pipe teardown on the forwarder's PathControl hook. Registered as **both** the
/// [`PathAuthorizer`] (membership check) and the [`PathControlObserver`] (reap) on a
/// node's engine, backed by that node's [`PipeMembership`] (a [`RelayPipeStore`] on a
/// relay, the [`PipeRegistry`] on the producer). A `Teardown` walking the path is then
/// authorized + reaped per hop by the forwarder — the app never sees it.
pub struct PipeTeardownControl<M> {
    membership: M,
}

impl<M: PipeMembership> PipeTeardownControl<M> {
    pub fn new(membership: M) -> Self {
        Self { membership }
    }
}

#[async_trait::async_trait]
impl<M: PipeMembership> PathAuthorizer for PipeTeardownControl<M> {
    async fn authorize(&self, pc: &PathControl, interest: &Interest) -> bool {
        // This authorizer governs *teardown* only; it deliberately rejects Redirect
        // (pipes teardown-and-rebuild, they don't re-anchor).
        if pc.op != PathOp::Teardown {
            return false;
        }
        let Some(params) = interest.app_parameters() else {
            return false;
        };
        let Some((id, key)) = decode_pipe_teardown_params(params) else {
            return false;
        };
        // Membership: the key in app-params must match the pipe key this node holds.
        self.membership.pipe_key(&id).as_deref() == Some(key.as_slice())
    }
}

impl<M: PipeMembership> PathControlObserver for PipeTeardownControl<M> {
    fn on_teardown(&self, pc: &PathControl, params: &[u8]) {
        if let Some((id, key)) = decode_pipe_teardown_params(params)
            && let Some(namespace) = self.membership.reap(&id, &key)
        {
            // We tore real state down — defer any pending self-announcement for it.
            self.membership.suppress_namespace(&namespace);
            debug_assert_eq!(&namespace, &pc.target);
        }
    }
}
