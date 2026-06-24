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
//! The trust model is faithful to the thesis (NDNPIPES.pdf pp. 41–46): teardown is
//! authorized by **pipe membership** — possession of the pipe key handed out in the
//! PIPE exchange — not by a prefix-namespace signature. So this rides PathControl's
//! *pluggable* [`PathAuthorizer`]. But the pipe key is a long-lived shared secret, so
//! it must **never travel on the wire**: a teardown Interest is broadcast along the
//! path, and a cleartext key in its ApplicationParameters would let any on-path observer
//! capture it and forge teardowns (or worse, impersonate membership) forever. Instead
//! the message carries a **possession proof** — a fixed-format MAC over the pipe key
//! bound to this exact teardown (`namespace ‖ op ‖ seq ‖ id`) — which proves the emitter
//! holds the key without revealing it, and is bound tightly enough that it can't be
//! lifted onto a different teardown. Each hop recomputes the MAC from the key it already
//! holds and compares it in constant time. (MAP-Me's `Redirect` keeps its `Validator`
//! authorizer; pipes never `Redirect` — they teardown-and-rebuild.)
//!
//! The teardown *wire* (the emit helper + codec + the [`PipeMembership`] view) is
//! unconditional. The in-engine adapter [`PipeTeardownControl`] — which plugs this into
//! a running forwarder's PathControl hook — is behind the `engine` feature, so the core
//! stays forwarder-agnostic.

use bytes::Bytes;
use ndn_packet::encode::InterestBuilder;
use ndn_packet::Name;
use ndn_pathcontrol::{PathControl, PathOp};

use crate::registry::PipeRegistry;
use crate::relay::RelayPipeStore;

/// Length of the teardown possession-proof MAC (SHA-256 output).
pub const TEARDOWN_MAC_LEN: usize = 32;

/// Possession proof for a teardown: a fixed-format MAC binding the pipe `key` to this
/// exact teardown (`namespace ‖ op ‖ seq ‖ id`). It proves the emitter holds the key
/// without putting the key on the wire, and the binding stops the proof being lifted
/// onto a different teardown. Fixed-format (every variable field is length-prefixed),
/// so `SHA-256(key ‖ …)` is a sound MAC here — length-extension can't forge a *different*
/// valid (namespace, op, seq, id) tuple. Mirrors the `auth_mac` construction in
/// `ndn-face-shm`.
pub fn teardown_mac(key: &[u8], namespace: &Name, op: PathOp, seq: u64, id: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"ndn-pipes/teardown-mac/v1");
    h.update((key.len() as u32).to_be_bytes());
    h.update(key);
    let ns = namespace.encode_to_tlv();
    h.update((ns.as_ref().len() as u32).to_be_bytes());
    h.update(ns.as_ref());
    h.update([op as u8]);
    h.update(seq.to_be_bytes());
    h.update((id.len() as u32).to_be_bytes());
    h.update(id);
    h.finalize().into()
}

/// Constant-time byte-slice equality — no early-out timing leak when comparing the MAC.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Verify a teardown possession proof against the key this node holds for `id`. Returns
/// false if we don't hold the pipe (no key to check against) or the MAC doesn't match.
/// Used by the in-engine adapter; the verification itself is forwarder-agnostic.
#[cfg(feature = "engine")]
fn verify_teardown<M: PipeMembership + ?Sized>(
    membership: &M,
    pc: &PathControl,
    id: &[u8],
    mac: &[u8],
) -> bool {
    let Some(key) = membership.pipe_key(id) else {
        return false;
    };
    let expected = teardown_mac(&key, &pc.target, pc.op, pc.seq, id);
    ct_eq(&expected, mac)
}

/// The membership view a node has of the pipes it holds — exactly what a PathControl
/// teardown needs to authorize and reap. Implemented by the producer's [`PipeRegistry`]
/// and a relay's [`RelayPipeStore`], so the *same* [`PipeTeardownControl`] adapter hosts
/// either on its engine.
pub trait PipeMembership: Send + Sync {
    /// The pipe key for `id`, if this node holds the pipe (the secret used to recompute
    /// the possession-proof MAC). `None` ⇒ not a member of this pipe. The key is used
    /// only locally — it is never serialized.
    fn pipe_key(&self, id: &[u8]) -> Option<Vec<u8>>;

    /// Remove the pipe state for `id` — called **only after** the possession proof has
    /// been verified by [`verify_teardown`] (the forwarder drops unauthorized control
    /// before observers fire). Returns the pipe's namespace when it was held (so the
    /// caller can suppress sibling self-announcements); `None` if it wasn't held.
    fn reap_authorized(&self, id: &[u8]) -> Option<Name>;

    /// Cancel this node's pending self-announcement for `namespace` on hearing a peer's
    /// teardown first (relay hop-order suppression). Default no-op (the producer is the
    /// path's root — it has no peer to defer to).
    fn suppress_namespace(&self, _namespace: &Name) {}
}

impl PipeMembership for RelayPipeStore {
    fn pipe_key(&self, id: &[u8]) -> Option<Vec<u8>> {
        RelayPipeStore::pipe_key(self, id)
    }

    fn reap_authorized(&self, id: &[u8]) -> Option<Name> {
        // Authorization already happened (MAC verified); remove and report the namespace.
        RelayPipeStore::reap_now(self, id)
    }

    fn suppress_namespace(&self, namespace: &Name) {
        self.suppress(namespace);
    }
}

impl PipeMembership for PipeRegistry {
    fn pipe_key(&self, id: &[u8]) -> Option<Vec<u8>> {
        PipeRegistry::pipe_key(self, id)
    }

    fn reap_authorized(&self, id: &[u8]) -> Option<Name> {
        // The producer is the path root: it reaps but tracks no per-pipe namespace and
        // never suppresses (no peer to defer to).
        PipeRegistry::reap_now(self, id);
        None
    }
}

/// app-params codec for a pipe PathControl teardown: `id_len(u32 BE) ‖ id ‖ mac`.
/// The trailing `mac` is the possession proof ([`teardown_mac`]) — **not** the pipe key,
/// which never travels on the wire.
pub fn encode_pipe_teardown_params(id: &[u8], mac: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + id.len() + mac.len());
    v.extend_from_slice(&(id.len() as u32).to_be_bytes());
    v.extend_from_slice(id);
    v.extend_from_slice(mac);
    v
}

/// Inverse of [`encode_pipe_teardown_params`]: `(pipe id, possession mac)`. `None` if the
/// blob is truncated or carries a wrong-length MAC.
pub fn decode_pipe_teardown_params(p: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let len_bytes: [u8; 4] = p.get(..4)?.try_into().ok()?;
    let id_len = u32::from_be_bytes(len_bytes) as usize;
    let rest = p.get(4..)?;
    let id = rest.get(..id_len)?;
    let mac = rest.get(id_len..)?;
    if mac.len() != TEARDOWN_MAC_LEN {
        return None;
    }
    Some((id.to_vec(), mac.to_vec()))
}

/// Build an (unsigned) PathControl `Teardown` Interest for a pipe:
/// `<namespace>/32=PC/Teardown/<seq>` carrying `(id, mac)` in ApplicationParameters,
/// where `mac` is the possession proof over `key` bound to this teardown. The key is
/// used here only to compute the MAC — it is never serialized. Unsigned because the
/// authorization is *membership* (the MAC), not a namespace signature — see the module
/// docs. `seq` is the PathControl loop/dedup guard *and* part of the MAC binding, so a
/// captured proof can't be replayed onto a different seq; use a per-emitter monotonic
/// counter (collisions across emitters are benign — the forwarder's `SeqStore` dedups).
pub fn pipe_teardown_interest(namespace: &Name, id: &[u8], key: &[u8], seq: u64) -> Bytes {
    let mac = teardown_mac(key, namespace, PathOp::Teardown, seq, id);
    let name = PathControl::new(namespace.clone(), PathOp::Teardown, seq).to_name();
    InterestBuilder::new(name)
        .app_parameters(encode_pipe_teardown_params(id, &mac))
        .build()
}

/// A monotonic PathControl sequence number for teardown emitters: wall-clock
/// milliseconds. Globally increasing across emitters and across namespace reuse (a new
/// pipe reusing a torn-down namespace gets a strictly-higher seq, so the forwarder's
/// `SeqStore` admits its teardown rather than treating it as a stale duplicate).
/// Two emitters firing in the same millisecond collide — benign, since the loser is
/// simply deduped, which is the announcement suppression.
pub fn now_seq() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Hosts pipe teardown on the forwarder's PathControl hook. Registered as **both** the
/// `PathAuthorizer` (membership check) and the `PathControlObserver` (reap) on a node's
/// engine, backed by that node's [`PipeMembership`] (a [`RelayPipeStore`] on a relay,
/// the [`PipeRegistry`] on the producer). A `Teardown` walking the path is then
/// authorized + reaped per hop by the forwarder — the app never sees it.
///
/// Behind the `engine` feature (it depends on `ndn-engine`).
#[cfg(feature = "engine")]
pub struct PipeTeardownControl<M> {
    membership: M,
}

#[cfg(feature = "engine")]
impl<M: PipeMembership> PipeTeardownControl<M> {
    pub fn new(membership: M) -> Self {
        Self { membership }
    }
}

#[cfg(feature = "engine")]
#[async_trait::async_trait]
impl<M: PipeMembership> ndn_engine::PathAuthorizer for PipeTeardownControl<M> {
    async fn authorize(&self, pc: &PathControl, interest: &ndn_packet::Interest) -> bool {
        // This authorizer governs *teardown* only; it deliberately rejects Redirect
        // (pipes teardown-and-rebuild, they don't re-anchor).
        if pc.op != PathOp::Teardown {
            return false;
        }
        let Some(params) = interest.app_parameters() else {
            return false;
        };
        let Some((id, mac)) = decode_pipe_teardown_params(params) else {
            return false;
        };
        // Membership: the possession proof must verify against the pipe key this node
        // holds (recomputed locally; constant-time compared). The key never crosses the
        // wire, so an on-path observer learns nothing it could replay or impersonate.
        verify_teardown(&self.membership, pc, &id, &mac)
    }
}

/// Feeds the forwarder's data-plane name-activity signal into a relay's PUI monitor: an
/// interest fetched under a held pipe's namespace renews that pipe, so an actively-used
/// pipe is never torn down. Register via
/// [`EngineBuilder::with_name_activity_observer`](ndn_engine::EngineBuilder::with_name_activity_observer).
///
/// Behind the `engine` feature (it depends on `ndn-engine`).
#[cfg(feature = "engine")]
pub struct RelayActivity {
    store: RelayPipeStore,
}

#[cfg(feature = "engine")]
impl RelayActivity {
    pub fn new(store: RelayPipeStore) -> Self {
        Self { store }
    }
}

#[cfg(feature = "engine")]
impl ndn_engine::NameActivityObserver for RelayActivity {
    fn on_activity(&self, name: &Name) {
        self.store.note_traffic(name);
    }
}

#[cfg(feature = "engine")]
impl<M: PipeMembership> ndn_engine::PathControlObserver for PipeTeardownControl<M> {
    fn on_teardown(&self, pc: &PathControl, params: &[u8]) {
        // Re-verify the possession proof here too (defense in depth — don't reap on a
        // bare decode), then remove the state.
        if let Some((id, mac)) = decode_pipe_teardown_params(params)
            && verify_teardown(&self.membership, pc, &id, &mac)
            && let Some(namespace) = self.membership.reap_authorized(&id)
        {
            // We tore real state down — defer any pending self-announcement for it.
            self.membership.suppress_namespace(&namespace);
            debug_assert_eq!(&namespace, &pc.target);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ns() -> Name {
        "/alice/pipe".parse().unwrap()
    }

    #[test]
    fn teardown_params_round_trip_and_reject_bad_mac() {
        let mac = teardown_mac(b"the-pipe-key", &ns(), PathOp::Teardown, 7, b"pipe-id");
        let wire = encode_pipe_teardown_params(b"pipe-id", &mac);
        let (id, got) = decode_pipe_teardown_params(&wire).expect("round-trips");
        assert_eq!(id, b"pipe-id");
        assert_eq!(got, mac);

        // A wrong-length trailer (e.g. a stray byte, or an old cleartext-key wire) is
        // rejected — the MAC is fixed-length.
        let mut short = encode_pipe_teardown_params(b"pipe-id", &mac);
        short.pop();
        assert!(decode_pipe_teardown_params(&short).is_none());
    }

    #[test]
    fn mac_binds_every_field() {
        let base = teardown_mac(b"key", &ns(), PathOp::Teardown, 7, b"id");
        // Deterministic for the same inputs.
        assert_eq!(base, teardown_mac(b"key", &ns(), PathOp::Teardown, 7, b"id"));
        // …and changes if *any* bound field changes (so a captured proof can't be lifted
        // onto a different teardown, key, or pipe).
        assert_ne!(base, teardown_mac(b"key2", &ns(), PathOp::Teardown, 7, b"id"));
        let other_ns: Name = "/bob/pipe".parse().unwrap();
        assert_ne!(base, teardown_mac(b"key", &other_ns, PathOp::Teardown, 7, b"id"));
        assert_ne!(base, teardown_mac(b"key", &ns(), PathOp::Refresh, 7, b"id"));
        assert_ne!(base, teardown_mac(b"key", &ns(), PathOp::Teardown, 8, b"id"));
        assert_ne!(base, teardown_mac(b"key", &ns(), PathOp::Teardown, 7, b"id2"));
    }

    #[test]
    fn ct_eq_matches_only_equal_slices() {
        assert!(ct_eq(b"abcd", b"abcd"));
        assert!(!ct_eq(b"abcd", b"abce"));
        assert!(!ct_eq(b"abc", b"abcd"));
    }

    #[cfg(feature = "engine")]
    #[test]
    fn verify_accepts_holder_proof_and_rejects_others() {
        use std::collections::HashMap;
        use std::sync::Mutex;

        struct Mock {
            keys: Mutex<HashMap<Vec<u8>, Vec<u8>>>,
        }
        impl PipeMembership for Mock {
            fn pipe_key(&self, id: &[u8]) -> Option<Vec<u8>> {
                self.keys.lock().unwrap().get(id).cloned()
            }
            fn reap_authorized(&self, id: &[u8]) -> Option<Name> {
                self.keys.lock().unwrap().remove(id).map(|_| ns())
            }
        }

        let m = Mock {
            keys: Mutex::new(HashMap::from([(b"id".to_vec(), b"secret-key".to_vec())])),
        };
        let pc = PathControl::new(ns(), PathOp::Teardown, 9);

        // A proof from the real key verifies.
        let good = teardown_mac(b"secret-key", &ns(), PathOp::Teardown, 9, b"id");
        assert!(verify_teardown(&m, &pc, b"id", &good));

        // A proof from the wrong key is rejected.
        let bad = teardown_mac(b"guessed-key", &ns(), PathOp::Teardown, 9, b"id");
        assert!(!verify_teardown(&m, &pc, b"id", &bad));

        // A valid proof for a *different* seq doesn't verify against this pc (replay onto
        // a new teardown is bound out).
        let replay = teardown_mac(b"secret-key", &ns(), PathOp::Teardown, 8, b"id");
        assert!(!verify_teardown(&m, &pc, b"id", &replay));

        // A pipe we don't hold can't be torn down (no key → no proof can verify).
        assert!(!verify_teardown(&m, &pc, b"unknown", &good));
    }
}
