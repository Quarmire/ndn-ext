//! Fail-closed **execution leases** for NDN services (sans-IO).
//!
//! A lease is a provider-local grant to *execute something later*: a requester
//! *prepares* a lease (reserving resources named by conflict keys), *commits*
//! it, *activates* it at execution time (validating the plan it committed to),
//! and *releases* it when done — or *aborts* along the way. The provider's
//! [`LeaseTable`] is the **only** authority over its own capacity: there is no
//! untracked-local fallback, and every failure path leaves the table unchanged
//! (fail closed).
//!
//! Ported *in mechanism* — not wire — from upstream NDNSF's
//! `ProviderExecutionLeaseTable` (spec 085, the mechanism its distributed-
//! inference workload forced into the core), redesigned tier-agnostic for the
//! ndn-rs service stack: nothing here knows about the four-phase, Tier-0, or
//! any transport. A carrier surfaces rejections however its protocol likes
//! (the NDNSF carrier maps them onto negative-ACK `LEASE_REJECTED` /
//! `LEASE_EXPIRED` reasons).
//!
//! ## The state machine
//!
//! ```text
//!            prepare              commit              activate            release
//!   (none) ────────▶ Prepared ────────▶ Committed ────────▶ Executing ────────▶ Released
//!                        │                  │                    │
//!                        │ abort            │ abort              │ (no abort: running
//!                        ▼                  ▼                    ▼  work must release)
//!                     Aborted            Aborted              Released
//!
//!   any non-terminal state ── TTL elapses ──▶ Expired (lazily, or via cleanup)
//! ```
//!
//! ## Properties
//!
//! * **Boot epochs** — the table is constructed with the provider instance's
//!   epoch; every issued lease carries it and every mutation revalidates it. A
//!   restarted provider (new epoch, empty table) gives holders of old leases a
//!   *typed* [`LeaseError::StaleEpoch`]/[`LeaseError::Unknown`] answer, never a
//!   silent grant. Lease state is memory-local by design (the NSF-T6 stance).
//! * **Conflict keys** — a prepare naming a conflict key held by any live
//!   (Prepared/Committed/Executing) lease is refused ([`LeaseError::Conflict`]).
//!   Terminal states free their keys.
//! * **Idempotency replay** — a prepare re-presenting a known idempotency key
//!   with the *same* plan digest returns the **same** lease (safe retry); with
//!   a *different* digest it is refused ([`LeaseError::IdempotencyConflict`]) —
//!   a retry must not smuggle in different work.
//! * **Holder binding** — every mutation names the holder; a lease can only be
//!   driven by the identity it was prepared for ([`LeaseError::WrongHolder`]).
//! * **Plan binding** — activation revalidates the plan digest committed at
//!   prepare time ([`LeaseError::PlanMismatch`]).
//! * **Clock-free** — the caller supplies monotonic seconds, so the machine is
//!   deterministic and directly testable (same discipline as `ndnsf-rs`'s
//!   token table).

#![deny(missing_docs)]

use std::collections::HashMap;

use ndn_packet::Name;
use rand_core::{OsRng, RngCore};

/// An opaque lease identifier (16 random bytes, hex) — unguessable, unique per
/// table instance.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LeaseId(String);

impl LeaseId {
    fn random() -> Self {
        let mut raw = [0u8; 16];
        OsRng.fill_bytes(&mut raw);
        let mut s = String::with_capacity(32);
        for b in raw {
            s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
            s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
        }
        Self(s)
    }

    /// The id string (as it travels in a protocol's lease field).
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Reconstruct an id from its wire string.
    pub fn from_wire(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

/// Where a lease is in its lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaseState {
    /// Reserved: conflict keys held, nothing running yet.
    Prepared,
    /// The holder has committed to executing; still not running.
    Committed,
    /// Execution is under way.
    Executing,
    /// Terminal: execution finished and the holder released.
    Released,
    /// Terminal: abandoned before execution.
    Aborted,
    /// Terminal: its TTL elapsed before completion.
    Expired,
}

impl LeaseState {
    /// A live lease holds its conflict keys; a terminal one does not.
    fn is_live(self) -> bool {
        matches!(
            self,
            LeaseState::Prepared | LeaseState::Committed | LeaseState::Executing
        )
    }
}

/// Why a lease operation was refused. Every refusal leaves the table unchanged
/// (fail closed).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum LeaseError {
    /// The presented boot epoch is not this provider instance's epoch — the
    /// lease (if any) belongs to a previous life of the provider.
    #[error("stale provider boot epoch")]
    StaleEpoch,
    /// No such lease (never issued, or this instance never issued it).
    #[error("unknown lease")]
    Unknown,
    /// The lease's TTL elapsed; it is now terminal `Expired`.
    #[error("lease expired")]
    Expired,
    /// The operation came from an identity other than the lease's holder.
    #[error("lease driven by the wrong holder")]
    WrongHolder,
    /// A conflict key in the prepare is held by a live lease.
    #[error("conflict key held by a live lease: {0}")]
    Conflict(String),
    /// The idempotency key is known but the plan digest differs — a retry must
    /// not change the work.
    #[error("idempotency key replayed with a different plan digest")]
    IdempotencyConflict,
    /// Activation presented a plan digest other than the one prepared.
    #[error("activation plan digest does not match the lease")]
    PlanMismatch,
    /// The operation is not legal from the lease's current state.
    #[error("invalid transition from {0:?}")]
    InvalidTransition(LeaseState),
    /// The table is at capacity (backstop against a prepare flood).
    #[error("lease table at capacity")]
    TableFull,
}

/// What a prepare asks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeaseRequest {
    /// The identity the lease binds to (every later step must present it).
    pub holder: Name,
    /// Exclusive resources this execution needs; any overlap with a live
    /// lease's keys refuses the prepare.
    pub conflict_keys: Vec<String>,
    /// Digest of the work to be executed; revalidated at activation.
    pub plan_digest: String,
    /// Optional safe-retry key: re-presenting it with the same `plan_digest`
    /// returns the same lease instead of double-reserving.
    pub idempotency_key: Option<String>,
    /// Seconds (from prepare) until an incomplete lease expires.
    pub ttl_secs: u64,
}

/// A granted lease, as returned to the holder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lease {
    /// The lease's id.
    pub id: LeaseId,
    /// The provider boot epoch it was issued under (present it back on every
    /// later step).
    pub boot_epoch: u64,
    /// Absolute (caller-clock) second at which it expires if not completed.
    pub expires_at_secs: u64,
}

struct LeaseEntry {
    holder: Name,
    state: LeaseState,
    conflict_keys: Vec<String>,
    plan_digest: String,
    idempotency_key: Option<String>,
    expires_at_secs: u64,
}

/// Observability counters (monotonic per table instance).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LeaseCounters {
    /// Successful prepares (including idempotent replays).
    pub prepared: u64,
    /// Prepares answered by idempotent replay.
    pub replayed: u64,
    /// Leases that reached `Released`.
    pub released: u64,
    /// Leases that reached `Aborted`.
    pub aborted: u64,
    /// Leases that reached `Expired`.
    pub expired: u64,
    /// Refusals of any kind (fail-closed events).
    pub refused: u64,
}

/// Backstop on outstanding leases — TTL reaping is the primary bound; this
/// stops the table growing without limit between reaps. Unlike the token
/// table, at capacity a prepare is **refused** (typed `TableFull`), never shed:
/// leases hold resources, so silently dropping one would break conflict-key
/// exclusivity.
const MAX_LEASES: usize = 8192;

/// The provider-local lease authority. One per provider instance (per boot).
pub struct LeaseTable {
    boot_epoch: u64,
    leases: HashMap<LeaseId, LeaseEntry>,
    /// idempotency key → (lease, plan digest) replay cache.
    idempotency: HashMap<String, (LeaseId, String)>,
    counters: LeaseCounters,
}

impl LeaseTable {
    /// A table for the provider instance whose boot epoch is `boot_epoch`
    /// (pick a fresh value each boot — e.g. random, or a boot timestamp; the
    /// table only ever compares it for equality).
    pub fn new(boot_epoch: u64) -> Self {
        Self {
            boot_epoch,
            leases: HashMap::new(),
            idempotency: HashMap::new(),
            counters: LeaseCounters::default(),
        }
    }

    /// This instance's boot epoch.
    pub fn boot_epoch(&self) -> u64 {
        self.boot_epoch
    }

    /// Observability counters.
    pub fn counters(&self) -> LeaseCounters {
        self.counters
    }

    /// Live (Prepared/Committed/Executing) lease count.
    pub fn live_count(&self) -> usize {
        self.leases.values().filter(|e| e.state.is_live()).count()
    }

    fn refuse<T>(&mut self, e: LeaseError) -> Result<T, LeaseError> {
        self.counters.refused += 1;
        tracing::debug!(error = %e, "lease operation refused — fail closed");
        Err(e)
    }

    /// Expire `id` in place if its TTL has elapsed. Returns true if it just
    /// became (or already was) `Expired`.
    fn lazily_expire(&mut self, id: &LeaseId, now_secs: u64) -> bool {
        let Some(entry) = self.leases.get_mut(id) else {
            return false;
        };
        if entry.state.is_live() && now_secs >= entry.expires_at_secs {
            entry.state = LeaseState::Expired;
            self.counters.expired += 1;
        }
        matches!(
            self.leases.get(id).map(|e| e.state),
            Some(LeaseState::Expired)
        )
    }

    /// Reserve a lease. Refused (nothing changes) on a held conflict key, an
    /// idempotency-key replay with a different plan digest, or a full table.
    /// An idempotency replay with the same digest returns the original lease.
    pub fn prepare(&mut self, now_secs: u64, req: &LeaseRequest) -> Result<Lease, LeaseError> {
        // Idempotency replay first: same key + same digest → same lease.
        if let Some(key) = &req.idempotency_key
            && let Some((id, digest)) = self.idempotency.get(key).cloned()
        {
            if digest != req.plan_digest {
                return self.refuse(LeaseError::IdempotencyConflict);
            }
            // Replay only while the original is still live and unexpired —
            // fail closed once it has completed/expired (the retry raced a
            // finished life; the caller must start over explicitly).
            if self.lazily_expire(&id, now_secs) {
                return self.refuse(LeaseError::Expired);
            }
            match self.leases.get(&id) {
                Some(entry) if entry.state.is_live() => {
                    self.counters.replayed += 1;
                    return Ok(Lease {
                        id,
                        boot_epoch: self.boot_epoch,
                        expires_at_secs: entry.expires_at_secs,
                    });
                }
                _ => return self.refuse(LeaseError::Unknown),
            }
        }

        if self.leases.len() >= MAX_LEASES {
            return self.refuse(LeaseError::TableFull);
        }

        // Conflict-key exclusivity against every live lease.
        for key in &req.conflict_keys {
            let held = self
                .leases
                .values()
                .any(|e| e.state.is_live() && e.conflict_keys.contains(key));
            if held {
                return self.refuse(LeaseError::Conflict(key.clone()));
            }
        }

        let id = LeaseId::random();
        let expires_at_secs = now_secs.saturating_add(req.ttl_secs);
        self.leases.insert(
            id.clone(),
            LeaseEntry {
                holder: req.holder.clone(),
                state: LeaseState::Prepared,
                conflict_keys: req.conflict_keys.clone(),
                plan_digest: req.plan_digest.clone(),
                idempotency_key: req.idempotency_key.clone(),
                expires_at_secs,
            },
        );
        if let Some(key) = &req.idempotency_key {
            self.idempotency
                .insert(key.clone(), (id.clone(), req.plan_digest.clone()));
        }
        self.counters.prepared += 1;
        Ok(Lease {
            id,
            boot_epoch: self.boot_epoch,
            expires_at_secs,
        })
    }

    /// Shared validation for every post-prepare step: epoch, existence,
    /// holder, expiry.
    fn checked_entry(
        &mut self,
        now_secs: u64,
        id: &LeaseId,
        holder: &Name,
        boot_epoch: u64,
    ) -> Result<(), LeaseError> {
        if boot_epoch != self.boot_epoch {
            return self.refuse(LeaseError::StaleEpoch);
        }
        if !self.leases.contains_key(id) {
            return self.refuse(LeaseError::Unknown);
        }
        // Holder binding BEFORE expiry: a wrong holder learns nothing about
        // the lease's lifecycle and burns nothing.
        if self.leases[id].holder != *holder {
            return self.refuse(LeaseError::WrongHolder);
        }
        if self.lazily_expire(id, now_secs) {
            return self.refuse(LeaseError::Expired);
        }
        Ok(())
    }

    fn transition(
        &mut self,
        now_secs: u64,
        id: &LeaseId,
        holder: &Name,
        boot_epoch: u64,
        from: &[LeaseState],
        to: LeaseState,
    ) -> Result<(), LeaseError> {
        self.checked_entry(now_secs, id, holder, boot_epoch)?;
        let state = self.leases[id].state;
        if !from.contains(&state) {
            return self.refuse(LeaseError::InvalidTransition(state));
        }
        self.leases.get_mut(id).expect("checked").state = to;
        match to {
            LeaseState::Released => self.counters.released += 1,
            LeaseState::Aborted => self.counters.aborted += 1,
            _ => {}
        }
        Ok(())
    }

    /// Prepared → Committed.
    pub fn commit(
        &mut self,
        now_secs: u64,
        id: &LeaseId,
        holder: &Name,
        boot_epoch: u64,
    ) -> Result<(), LeaseError> {
        self.transition(
            now_secs,
            id,
            holder,
            boot_epoch,
            &[LeaseState::Prepared],
            LeaseState::Committed,
        )
    }

    /// Committed → Executing, revalidating the plan: `plan_digest` must equal
    /// the digest prepared under this lease (upstream's `validateAndActivate`).
    pub fn activate(
        &mut self,
        now_secs: u64,
        id: &LeaseId,
        holder: &Name,
        boot_epoch: u64,
        plan_digest: &str,
    ) -> Result<(), LeaseError> {
        self.checked_entry(now_secs, id, holder, boot_epoch)?;
        if self.leases[id].plan_digest != plan_digest {
            return self.refuse(LeaseError::PlanMismatch);
        }
        self.transition(
            now_secs,
            id,
            holder,
            boot_epoch,
            &[LeaseState::Committed],
            LeaseState::Executing,
        )
    }

    /// Extend a live lease's TTL by `extend_secs` from `now_secs`.
    pub fn renew(
        &mut self,
        now_secs: u64,
        id: &LeaseId,
        holder: &Name,
        boot_epoch: u64,
        extend_secs: u64,
    ) -> Result<Lease, LeaseError> {
        self.checked_entry(now_secs, id, holder, boot_epoch)?;
        let entry = self.leases.get_mut(id).expect("checked");
        entry.expires_at_secs = now_secs.saturating_add(extend_secs);
        Ok(Lease {
            id: id.clone(),
            boot_epoch: self.boot_epoch,
            expires_at_secs: entry.expires_at_secs,
        })
    }

    /// Prepared|Committed → Aborted (frees the conflict keys). An Executing
    /// lease cannot abort — running work must [`release`](Self::release).
    pub fn abort(
        &mut self,
        now_secs: u64,
        id: &LeaseId,
        holder: &Name,
        boot_epoch: u64,
    ) -> Result<(), LeaseError> {
        self.transition(
            now_secs,
            id,
            holder,
            boot_epoch,
            &[LeaseState::Prepared, LeaseState::Committed],
            LeaseState::Aborted,
        )
    }

    /// Executing → Released (frees the conflict keys).
    pub fn release(
        &mut self,
        now_secs: u64,
        id: &LeaseId,
        holder: &Name,
        boot_epoch: u64,
    ) -> Result<(), LeaseError> {
        self.transition(
            now_secs,
            id,
            holder,
            boot_epoch,
            &[LeaseState::Executing],
            LeaseState::Released,
        )
    }

    /// The state of a lease, if this instance knows it (drives no transitions
    /// except lazy expiry).
    pub fn state(&mut self, now_secs: u64, id: &LeaseId) -> Option<LeaseState> {
        self.lazily_expire(id, now_secs);
        self.leases.get(id).map(|e| e.state)
    }

    /// Expire overdue live leases and drop terminal entries (and their
    /// idempotency-cache slots), returning how many entries were removed. Call
    /// periodically from the serve loop, like the token table's cleanup —
    /// otherwise terminal entries accumulate.
    pub fn cleanup(&mut self, now_secs: u64) -> usize {
        let ids: Vec<LeaseId> = self.leases.keys().cloned().collect();
        for id in &ids {
            self.lazily_expire(id, now_secs);
        }
        let before = self.leases.len();
        let dead: Vec<LeaseId> = self
            .leases
            .iter()
            .filter(|(_, e)| !e.state.is_live())
            .map(|(id, _)| id.clone())
            .collect();
        for id in dead {
            if let Some(entry) = self.leases.remove(&id)
                && let Some(key) = entry.idempotency_key
            {
                // Only drop the cache slot if it still points at this lease.
                if self.idempotency.get(&key).map(|(l, _)| l) == Some(&id) {
                    self.idempotency.remove(&key);
                }
            }
        }
        before - self.leases.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(s: &str) -> Name {
        s.parse().unwrap()
    }

    fn req(holder: &str, keys: &[&str], digest: &str, idem: Option<&str>) -> LeaseRequest {
        LeaseRequest {
            holder: name(holder),
            conflict_keys: keys.iter().map(|s| s.to_string()).collect(),
            plan_digest: digest.into(),
            idempotency_key: idem.map(str::to_string),
            ttl_secs: 60,
        }
    }

    #[test]
    fn full_lifecycle_prepare_commit_activate_release() {
        let mut t = LeaseTable::new(7);
        let alice = name("/muas/alice");
        let lease = t.prepare(0, &req("/muas/alice", &["gpu0"], "plan-a", None)).unwrap();
        assert_eq!(lease.boot_epoch, 7);
        assert_eq!(t.state(0, &lease.id), Some(LeaseState::Prepared));

        t.commit(1, &lease.id, &alice, 7).unwrap();
        assert_eq!(t.state(1, &lease.id), Some(LeaseState::Committed));

        t.activate(2, &lease.id, &alice, 7, "plan-a").unwrap();
        assert_eq!(t.state(2, &lease.id), Some(LeaseState::Executing));

        t.release(3, &lease.id, &alice, 7).unwrap();
        assert_eq!(t.state(3, &lease.id), Some(LeaseState::Released));
        assert_eq!(t.counters().released, 1);
        assert_eq!(t.live_count(), 0);
    }

    #[test]
    fn stale_epoch_fails_closed() {
        let mut t = LeaseTable::new(7);
        let alice = name("/muas/alice");
        let lease = t.prepare(0, &req("/muas/alice", &[], "p", None)).unwrap();
        // A lease from "another boot" (wrong epoch) drives nothing.
        assert_eq!(t.commit(1, &lease.id, &alice, 6), Err(LeaseError::StaleEpoch));
        assert_eq!(t.state(1, &lease.id), Some(LeaseState::Prepared));
    }

    #[test]
    fn restart_makes_old_leases_unknown() {
        // Boot 1 issues; boot 2 (fresh table, new epoch) knows nothing — the
        // holder gets a typed refusal, never a silent grant.
        let mut boot1 = LeaseTable::new(1);
        let lease = boot1.prepare(0, &req("/muas/alice", &["gpu0"], "p", None)).unwrap();
        let mut boot2 = LeaseTable::new(2);
        assert_eq!(
            boot2.commit(0, &lease.id, &name("/muas/alice"), lease.boot_epoch),
            Err(LeaseError::StaleEpoch)
        );
    }

    #[test]
    fn conflict_keys_are_exclusive_until_terminal() {
        let mut t = LeaseTable::new(7);
        let alice = name("/muas/alice");
        let a = t.prepare(0, &req("/muas/alice", &["gpu0", "model-q"], "p1", None)).unwrap();
        // Overlap on one key refuses the whole prepare.
        assert_eq!(
            t.prepare(0, &req("/muas/bob", &["net", "gpu0"], "p2", None)),
            Err(LeaseError::Conflict("gpu0".into()))
        );
        // Non-overlapping keys coexist.
        t.prepare(0, &req("/muas/bob", &["gpu1"], "p3", None)).unwrap();
        // Abort frees the keys.
        t.abort(1, &a.id, &alice, 7).unwrap();
        t.prepare(2, &req("/muas/bob", &["gpu0"], "p4", None)).unwrap();
    }

    #[test]
    fn idempotent_replay_returns_same_lease_conflicting_replay_refused() {
        let mut t = LeaseTable::new(7);
        let a = t.prepare(0, &req("/muas/alice", &["gpu0"], "plan-a", Some("job-1"))).unwrap();
        // Same key + same digest: the SAME lease, no double reservation.
        let b = t.prepare(1, &req("/muas/alice", &["gpu0"], "plan-a", Some("job-1"))).unwrap();
        assert_eq!(a.id, b.id);
        assert_eq!(t.counters().replayed, 1);
        assert_eq!(t.live_count(), 1);
        // Same key + different digest: refused (a retry must not change the work).
        assert_eq!(
            t.prepare(2, &req("/muas/alice", &["gpu0"], "plan-B", Some("job-1"))),
            Err(LeaseError::IdempotencyConflict)
        );
    }

    #[test]
    fn replay_after_completion_fails_closed() {
        let mut t = LeaseTable::new(7);
        let alice = name("/muas/alice");
        let a = t.prepare(0, &req("/muas/alice", &[], "p", Some("job-1"))).unwrap();
        t.commit(1, &a.id, &alice, 7).unwrap();
        t.activate(1, &a.id, &alice, 7, "p").unwrap();
        t.release(2, &a.id, &alice, 7).unwrap();
        // The finished life is not silently restarted by a late retry.
        assert_eq!(
            t.prepare(3, &req("/muas/alice", &[], "p", Some("job-1"))),
            Err(LeaseError::Unknown)
        );
    }

    #[test]
    fn wrong_holder_cannot_drive_and_burns_nothing() {
        let mut t = LeaseTable::new(7);
        let a = t.prepare(0, &req("/muas/alice", &["gpu0"], "p", None)).unwrap();
        for (op, err) in [
            (t.commit(1, &a.id, &name("/muas/mallory"), 7), LeaseError::WrongHolder),
            (t.abort(1, &a.id, &name("/muas/mallory"), 7), LeaseError::WrongHolder),
        ] {
            assert_eq!(op, Err(err));
        }
        assert_eq!(t.state(1, &a.id), Some(LeaseState::Prepared));
    }

    #[test]
    fn expiry_is_lazy_typed_and_frees_keys() {
        let mut t = LeaseTable::new(7);
        let alice = name("/muas/alice");
        let a = t.prepare(0, &req("/muas/alice", &["gpu0"], "p", None)).unwrap();
        // At the TTL the next touch expires it, with a typed reason.
        assert_eq!(t.commit(60, &a.id, &alice, 7), Err(LeaseError::Expired));
        assert_eq!(t.state(60, &a.id), Some(LeaseState::Expired));
        assert_eq!(t.counters().expired, 1);
        // The key is free again.
        t.prepare(61, &req("/muas/bob", &["gpu0"], "p2", None)).unwrap();
    }

    #[test]
    fn renew_extends_the_ttl() {
        let mut t = LeaseTable::new(7);
        let alice = name("/muas/alice");
        let a = t.prepare(0, &req("/muas/alice", &[], "p", None)).unwrap();
        assert_eq!(a.expires_at_secs, 60);
        let renewed = t.renew(50, &a.id, &alice, 7, 60).unwrap();
        assert_eq!(renewed.expires_at_secs, 110);
        // Alive past the original TTL.
        t.commit(100, &a.id, &alice, 7).unwrap();
    }

    #[test]
    fn activation_revalidates_the_plan() {
        let mut t = LeaseTable::new(7);
        let alice = name("/muas/alice");
        let a = t.prepare(0, &req("/muas/alice", &[], "plan-a", None)).unwrap();
        t.commit(1, &a.id, &alice, 7).unwrap();
        assert_eq!(
            t.activate(2, &a.id, &alice, 7, "plan-b"),
            Err(LeaseError::PlanMismatch)
        );
        assert_eq!(t.state(2, &a.id), Some(LeaseState::Committed), "unchanged");
        t.activate(3, &a.id, &alice, 7, "plan-a").unwrap();
    }

    #[test]
    fn illegal_transitions_are_typed_and_inert() {
        let mut t = LeaseTable::new(7);
        let alice = name("/muas/alice");
        let a = t.prepare(0, &req("/muas/alice", &[], "p", None)).unwrap();
        // Can't activate from Prepared (must commit first).
        assert_eq!(
            t.activate(1, &a.id, &alice, 7, "p"),
            Err(LeaseError::InvalidTransition(LeaseState::Prepared))
        );
        // Can't release what isn't executing.
        assert_eq!(
            t.release(1, &a.id, &alice, 7),
            Err(LeaseError::InvalidTransition(LeaseState::Prepared))
        );
        t.commit(1, &a.id, &alice, 7).unwrap();
        t.activate(1, &a.id, &alice, 7, "p").unwrap();
        // Running work can't abort — it must release.
        assert_eq!(
            t.abort(2, &a.id, &alice, 7),
            Err(LeaseError::InvalidTransition(LeaseState::Executing))
        );
    }

    #[test]
    fn unknown_lease_is_refused() {
        let mut t = LeaseTable::new(7);
        assert_eq!(
            t.commit(0, &LeaseId::from_wire("beef"), &name("/muas/alice"), 7),
            Err(LeaseError::Unknown)
        );
    }

    #[test]
    fn cleanup_reaps_terminal_and_expired() {
        let mut t = LeaseTable::new(7);
        let alice = name("/muas/alice");
        let a = t.prepare(0, &req("/muas/alice", &[], "p", Some("job-1"))).unwrap();
        t.abort(1, &a.id, &alice, 7).unwrap();
        let _b = t.prepare(0, &req("/muas/bob", &[], "p", None)).unwrap(); // will expire
        let c = t.prepare(70, &req("/muas/carol", &[], "p", None)).unwrap(); // stays live
        assert_eq!(t.cleanup(70), 2, "aborted + expired reaped");
        assert_eq!(t.state(70, &c.id), Some(LeaseState::Prepared));
        // The reaped idempotency slot is free for a fresh life.
        let a2 = t.prepare(71, &req("/muas/alice", &[], "p", Some("job-1"))).unwrap();
        assert_ne!(a2.id, a.id);
    }

    #[test]
    fn table_is_capped_with_typed_refusal() {
        let mut t = LeaseTable::new(7);
        for i in 0..MAX_LEASES {
            t.prepare(0, &req(&format!("/u/{i}"), &[], "p", None)).unwrap();
        }
        assert_eq!(
            t.prepare(0, &req("/u/last", &[], "p", None)),
            Err(LeaseError::TableFull)
        );
    }
}
