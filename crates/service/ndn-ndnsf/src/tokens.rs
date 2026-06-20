//! Provider-token lifecycle and pending-state machine — the faithful NDNSF
//! coordination guard, sans-IO.
//!
//! In NDNSF's four-phase flow, when a provider ACKs a request it creates a
//! pending **`ProviderToken`** keyed to that coordination; when the user's
//! `SELECTION` arrives carrying the token, the provider **consumes it once** and
//! executes. The token is single-use and expires after a pending TTL.
//!
//! This module is the state machine behind that, carrying the O4 token/state
//! invariants (`docs/specs/ndnsf-invariants.md`): NSF-T1/T3/T4/T5/T6 and
//! NSF-S1–S5. It is clock-free — the caller supplies a monotonic time in seconds
//! — so it is deterministic and testable, and `ProviderToken` is memory-local
//! (a restart drops unconsumed pending state, NSF-T6).

use std::collections::HashMap;

use ndn_packet::Name;
use rand_core::{OsRng, RngCore};

/// An opaque, single-use provider token (16 random bytes, hex). Equality +
/// hashing are over the token bytes; the value is unguessable.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProviderToken(String);

impl ProviderToken {
    fn random() -> Self {
        let mut raw = [0u8; 16];
        OsRng.fill_bytes(&mut raw);
        let mut s = String::with_capacity(32);
        for b in raw {
            // Hex without a per-byte `format!` allocation (SEC-34, the flood path).
            s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
            s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
        }
        Self(s)
    }

    /// The token string (as it travels in the SELECTION message).
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Reconstruct a token from its wire string (e.g. a received SELECTION).
    pub fn from_wire(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

/// The coordination state a consumed token unlocks: who asked, for what.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingCoordination {
    /// The requester's identity.
    pub requester: Name,
    /// The (unified) service name requested.
    pub service: Name,
    /// The one-time user token from the original request.
    pub user_token: String,
}

/// Why consuming a provider token failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TokenError {
    /// The token was never issued, or was already consumed (replay).
    #[error("unknown or already-consumed provider token")]
    Unknown,
    /// The token's pending TTL has elapsed.
    #[error("provider token has expired")]
    Expired,
    /// The redeeming SELECTION's verified requester is not the token's issuee — a
    /// stolen-token attempt on the broadcast medium (NSF-T / SEC-03).
    #[error("provider token redeemed by the wrong requester")]
    Unauthorized,
}

/// Hard cap on outstanding pending tokens — a memory backstop under a sustained
/// request/bootstrap flood (TTL reaping is the primary bound; this stops the table
/// growing without limit between reaps). At the cap, issuing sheds one entry
/// (red-team SEC-22).
const MAX_PENDING_TOKENS: usize = 8192;

/// A provider's pending-token table: issue on ACK, consume once on SELECTION,
/// expire/clean up by TTL.
pub struct PendingProviderTokens {
    entries: HashMap<ProviderToken, (PendingCoordination, u64)>, // token -> (state, created_at_secs)
    ttl_secs: u64,
}

impl PendingProviderTokens {
    /// A table whose tokens live for `ttl_secs` after issuance.
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            entries: HashMap::new(),
            ttl_secs,
        }
    }

    /// Issue a fresh single-use token for a coordination (called when ACKing).
    pub fn issue(
        &mut self,
        now_secs: u64,
        requester: Name,
        service: Name,
        user_token: String,
    ) -> ProviderToken {
        // Backstop the table size (SEC-22): shed an arbitrary entry at the cap so a
        // bootstrap/request flood can't grow it without bound between TTL reaps.
        if self.entries.len() >= MAX_PENDING_TOKENS
            && let Some(victim) = self.entries.keys().next().cloned()
        {
            self.entries.remove(&victim);
        }
        let token = ProviderToken::random();
        self.entries.insert(
            token.clone(),
            (
                PendingCoordination {
                    requester,
                    service,
                    user_token,
                },
                now_secs,
            ),
        );
        token
    }

    /// Whether `token` is still pending and unexpired at `now_secs`.
    fn is_expired(&self, created_at_secs: u64, now_secs: u64) -> bool {
        now_secs.saturating_sub(created_at_secs) >= self.ttl_secs
    }

    /// Consume `token` **once** (called when the SELECTION arrives), for the
    /// SELECTION's **verified** `requester`. Returns the unlocked coordination,
    /// removing the token so a replay fails. Rejected (without consuming) if the
    /// requester is not the token's issuee — so a participant who read the token off
    /// another's broadcast ACK cannot redeem it (SEC-03). Unknown/expired are
    /// likewise rejected.
    pub fn consume(
        &mut self,
        now_secs: u64,
        token: &ProviderToken,
        requester: &Name,
    ) -> Result<PendingCoordination, TokenError> {
        // Peek before removing: a mismatched (stolen-token) SELECTION must not burn
        // the legitimate issuee's pending token.
        match self.entries.get(token) {
            None => return Err(TokenError::Unknown),
            Some((coord, _)) if coord.requester != *requester => {
                return Err(TokenError::Unauthorized);
            }
            Some(_) => {}
        }
        let (coord, created) = self.entries.remove(token).expect("present per the peek above");
        if self.is_expired(created, now_secs) {
            return Err(TokenError::Expired);
        }
        Ok(coord)
    }

    /// Remove all tokens whose TTL has elapsed at `now_secs`; returns how many
    /// were reaped. Idempotent — a token already consumed or already reaped is
    /// simply absent.
    pub fn cleanup_expired(&mut self, now_secs: u64) -> usize {
        let ttl = self.ttl_secs; // capture so the retain closure doesn't borrow self
        let before = self.entries.len();
        self.entries
            .retain(|_, (_, created)| now_secs.saturating_sub(*created) < ttl);
        before - self.entries.len()
    }

    /// Number of tokens currently pending — bounded by issue/consume/cleanup.
    pub fn pending_count(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(s: &str) -> Name {
        s.parse().unwrap()
    }

    fn store() -> PendingProviderTokens {
        PendingProviderTokens::new(60)
    }

    fn issue(t: &mut PendingProviderTokens, now: u64) -> ProviderToken {
        t.issue(now, name("/muas/alice"), name("/svc/mavlink"), "utok".into())
    }

    /// SEC-22 — the pending-token table is hard-capped, so a flood of issuance
    /// (e.g. TargetedBootstrap minting batches) cannot grow it without bound.
    #[test]
    fn token_table_is_capped() {
        let mut t = store();
        for i in 0..(MAX_PENDING_TOKENS + 500) {
            t.issue(0, name(&format!("/muas/u{i}")), name("/svc/x"), String::new());
        }
        assert!(t.pending_count() <= MAX_PENDING_TOKENS);
    }

    #[test]
    fn stolen_token_by_wrong_requester_is_rejected_without_burning_it() {
        // SEC-03: a token issued to alice cannot be redeemed by mallory (who read it
        // off the broadcast ACK) — and the failed attempt does NOT consume it.
        let mut t = store();
        let tok = issue(&mut t, 0);
        assert_eq!(
            t.consume(0, &tok, &name("/muas/mallory")),
            Err(TokenError::Unauthorized)
        );
        assert!(t.consume(0, &tok, &name("/muas/alice")).is_ok(), "alice can still redeem it");
    }

    /// NSF-T1 / NSF-T3 — a token is single-use; consuming it again (replay,
    /// including after successful coordination) fails.
    #[test]
    fn nsf_t1_t3_token_is_single_use() {
        let mut t = store();
        let tok = issue(&mut t, 0);
        assert!(t.consume(10, &tok, &name("/muas/alice")).is_ok());
        assert_eq!(t.consume(10, &tok, &name("/muas/alice")), Err(TokenError::Unknown));
    }

    /// NSF-T4 — an expired token cannot coordinate.
    #[test]
    fn nsf_t4_expired_token_rejected() {
        let mut t = store();
        let tok = issue(&mut t, 0);
        assert_eq!(t.consume(60, &tok, &name("/muas/alice")), Err(TokenError::Expired));
    }

    /// NSF-T5 — an unknown/random token is rejected.
    #[test]
    fn nsf_t5_unknown_token_rejected() {
        let mut t = store();
        assert_eq!(
            t.consume(0, &ProviderToken::from_wire("deadbeef"), &name("/muas/alice")),
            Err(TokenError::Unknown)
        );
    }

    /// NSF-T6 — pending token state is memory-local: a fresh table (a "restart")
    /// holds nothing.
    #[test]
    fn nsf_t6_restart_drops_pending_state() {
        let mut t = store();
        let tok = issue(&mut t, 0);
        let fresh = store();
        assert_eq!(fresh.pending_count(), 0);
        assert_eq!(
            // the old token does not coordinate against a fresh table
            store().consume(10, &tok, &name("/muas/alice")),
            Err(TokenError::Unknown)
        );
    }

    /// NSF-S2 — successful coordination removes the pending state immediately.
    #[test]
    fn nsf_s2_success_removes_pending_immediately() {
        let mut t = store();
        let tok = issue(&mut t, 0);
        assert_eq!(t.pending_count(), 1);
        t.consume(10, &tok, &name("/muas/alice")).unwrap();
        assert_eq!(t.pending_count(), 0);
    }

    /// NSF-S3 — timeout cleanup does not remove an active (within-TTL) token
    /// before coordination can arrive.
    #[test]
    fn nsf_s3_cleanup_spares_active_tokens() {
        let mut t = store();
        let tok = issue(&mut t, 0);
        assert_eq!(t.cleanup_expired(59), 0); // still within TTL
        assert_eq!(t.pending_count(), 1);
        assert!(t.consume(59, &tok, &name("/muas/alice")).is_ok());
    }

    /// NSF-S1 — pending state is eventually cleaned by TTL.
    #[test]
    fn nsf_s1_cleanup_reaps_expired() {
        let mut t = store();
        issue(&mut t, 0);
        issue(&mut t, 0);
        assert_eq!(t.cleanup_expired(60), 2);
        assert_eq!(t.pending_count(), 0);
    }

    /// NSF-S4 / NSF-S5 — cleanup after completion is a no-op, and repeated
    /// cleanup cycles do not grow pending state.
    #[test]
    fn nsf_s4_s5_cleanup_idempotent_and_bounded() {
        let mut t = store();
        let tok = issue(&mut t, 0);
        t.consume(10, &tok, &name("/muas/alice")).unwrap(); // completed; pending now empty
        assert_eq!(t.cleanup_expired(10), 0); // no-op after completion
        assert_eq!(t.cleanup_expired(100), 0); // repeated cleanup: still no growth
        assert_eq!(t.pending_count(), 0);
    }
}
