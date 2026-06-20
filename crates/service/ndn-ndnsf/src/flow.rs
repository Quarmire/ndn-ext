//! Four-phase orchestration core (sans-IO).
//!
//! The provider's phase transitions, tying the [`crate::messages`] taxonomy to
//! the [`crate::tokens`] coordination guard:
//!
//! * **Phase 2** — on a `REQUEST`, [`ProviderEngine::on_request`] issues a
//!   single-use provider token and builds the `ACK`.
//! * **Phase 4** — on a `SELECTION`, [`ProviderEngine::on_selection`] **consumes
//!   the token once** (failing closed on a replayed/expired/forged token —
//!   NSF-T/F5), runs the handler, and builds the `RESPONSE`.
//!
//! This is the logic the async SVS pub/sub driver binds over a transport
//! (`SvsPubSub::publish`/`subscribe`); keeping it sans-IO makes the
//! coordination invariants directly testable. The user-side helpers
//! ([`make_request`]/[`make_selection`]) build the phase-1/3 messages.

use bytes::Bytes;
use ndn_packet::Name;
use rand_core::{OsRng, RngCore};
use tracing::instrument;

use crate::messages::{AckMessage, RequestMessage, ResponseMessage, SelectionMessage, Strategy};
use crate::tokens::{PendingCoordination, PendingProviderTokens, ProviderToken, TokenError};

/// A four-phase coordination failure on the provider side.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FlowError {
    /// The selection presented a token that was never issued, already consumed,
    /// or expired — no coordination occurs and no response is produced.
    #[error("selection presented an invalid provider token: {0}")]
    TokenRejected(TokenError),
}

/// The provider-side four-phase engine: issues tokens on ACK, consumes them on
/// SELECTION. Wraps the [`PendingProviderTokens`] state machine.
pub struct ProviderEngine {
    tokens: PendingProviderTokens,
}

impl ProviderEngine {
    /// A provider engine whose pending tokens live for `ttl_secs`.
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            tokens: PendingProviderTokens::new(ttl_secs),
        }
    }

    /// Issue a single-use provider token bound to a coordination, without
    /// building an ACK — used to pre-issue a Targeted-mode token batch.
    pub fn issue_token(
        &mut self,
        now_secs: u64,
        requester: Name,
        service: Name,
        user_token: String,
    ) -> crate::tokens::ProviderToken {
        self.tokens.issue(now_secs, requester, service, user_token)
    }

    /// Phase 2 — acknowledge a request, issuing a single-use provider token the
    /// user must present in its SELECTION.
    #[instrument(skip(self, req), fields(requester = %requester, service = %service, phase = "ack"))]
    pub fn on_request(
        &mut self,
        now_secs: u64,
        requester: Name,
        service: Name,
        req: &RequestMessage,
    ) -> AckMessage {
        let token = self.issue_token(now_secs, requester, service, req.user_token.clone());
        AckMessage {
            status: true,
            user_token: req.user_token.clone(),
            provider_token: token.as_str().to_string(),
            payload: Bytes::new(),
        }
    }

    /// Phase 4 — consume the selection's provider token (fails closed on an
    /// invalid one), run `handler` over the unlocked coordination, and build the
    /// RESPONSE. On rejection no response is produced (NSF-F5).
    #[instrument(skip(self, sel, handler), fields(phase = "response"))]
    pub fn on_selection<H>(
        &mut self,
        now_secs: u64,
        sel: &SelectionMessage,
        requester: &Name,
        handler: H,
    ) -> Result<ResponseMessage, FlowError>
    where
        H: FnOnce(&PendingCoordination) -> Bytes,
    {
        let coord = self.consume_selection(now_secs, sel, requester)?;
        let payload = handler(&coord);
        Ok(ResponseMessage {
            status: true,
            error_info: String::new(),
            payload,
        })
    }

    /// Validate and consume the selection's provider token for its **verified**
    /// `requester`, returning the coordination (fail-closed on an invalid/spent/
    /// stolen token — SEC-03). The caller runs the handler — sync via
    /// [`on_selection`](Self::on_selection), or async (e.g. a [`Carrier`](crate)
    /// dispatch) — and builds the [`ResponseMessage`]. Consuming the token here,
    /// before any handler runs, preserves NSF-T/F invariants.
    pub fn consume_selection(
        &mut self,
        now_secs: u64,
        sel: &SelectionMessage,
        requester: &Name,
    ) -> Result<PendingCoordination, FlowError> {
        let token = ProviderToken::from_wire(sel.provider_token.clone());
        self.tokens.consume(now_secs, &token, requester).map_err(|e| {
            tracing::warn!(error = %e, "selection rejected — fail closed (no response)");
            FlowError::TokenRejected(e)
        })
    }

    /// Pending (issued-but-unconsumed) token count.
    pub fn pending_count(&self) -> usize {
        self.tokens.pending_count()
    }

    /// Drop all tokens older than the TTL as of `now_secs`; returns how many were
    /// reaped. A serve loop MUST call this periodically with a real monotonic clock,
    /// or the token table grows unbounded (the TTL is otherwise inert).
    pub fn cleanup_expired(&mut self, now_secs: u64) -> usize {
        self.tokens.cleanup_expired(now_secs)
    }
}

/// User-side provider selection (Phase 3 decision): given the providers that
/// ACKed, pick which to SELECT per `strategy` — the first, a random one, or all.
/// Pure (modulo the RNG for `RandomSelection`); the driver applies it after its
/// ACK-collection window.
pub fn select_providers(
    strategy: Strategy,
    acks: &[(Name, AckMessage)],
) -> Vec<&(Name, AckMessage)> {
    match strategy {
        Strategy::FirstResponding => acks.first().into_iter().collect(),
        Strategy::AllSelected => acks.iter().collect(),
        Strategy::RandomSelection => {
            if acks.is_empty() {
                Vec::new()
            } else {
                vec![&acks[uniform_index(acks.len())]]
            }
        }
    }
}

/// A uniform index in `[0, n)` from the CSPRNG, **without modulo bias** (rejection
/// sampling — red-team SEC-31). `n` must be non-zero.
fn uniform_index(n: usize) -> usize {
    let n = n as u64;
    // Reject the incomplete final block so every index is equiprobable.
    let limit = (1u64 << 32) / n * n; // largest multiple of n within [0, 2^32)
    loop {
        let r = OsRng.next_u32() as u64;
        if r < limit {
            return (r % n) as usize;
        }
    }
}

/// Phase 1 — build a service request carrying a one-time user token.
pub fn make_request(request_id: &str, user_token: &str, payload: Bytes) -> RequestMessage {
    RequestMessage {
        request_id: request_id.to_string(),
        user_token: user_token.to_string(),
        payload,
        ..Default::default()
    }
}

/// Phase 3 — build the selection for a chosen provider's `ACK`, presenting its
/// provider token.
pub fn make_selection(ack: &AckMessage, request_id: &str) -> SelectionMessage {
    SelectionMessage {
        provider_token: ack.provider_token.clone(),
        request_id: request_id.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(s: &str) -> Name {
        s.parse().unwrap()
    }

    #[test]
    fn cleanup_expired_reaps_unselected_tokens() {
        // SEC-08 regression: a token issued at t=0 under a 10s TTL is reaped by a
        // later `cleanup_expired` even if its SELECTION never comes — the serve loop
        // now drives this with a real monotonic clock.
        let mut provider = ProviderEngine::new(10);
        let req = make_request("r1", "", Bytes::new());
        provider.on_request(0, name("/muas/alice"), name("/svc/x"), &req);
        assert_eq!(provider.pending_count(), 1);

        assert_eq!(provider.cleanup_expired(5), 0); // within TTL — nothing reaped
        assert_eq!(provider.pending_count(), 1);
        assert_eq!(provider.cleanup_expired(10), 1); // at TTL — reaped
        assert_eq!(provider.pending_count(), 0);
    }

    #[test]
    fn four_phase_happy_path() {
        let mut provider = ProviderEngine::new(60);

        // Phase 1: user requests.
        let req = make_request("r1", "utok", Bytes::from_static(b"compute this"));
        // Phase 2: provider ACKs, issuing a token.
        let ack = provider.on_request(0, name("/muas/alice"), name("/svc/x"), &req);
        assert!(ack.status && !ack.provider_token.is_empty());
        assert_eq!(provider.pending_count(), 1);

        // Phase 3: user selects this provider, echoing its token.
        let sel = make_selection(&ack, "r1");
        // Phase 4: provider consumes the token, runs the handler, responds.
        let resp = provider
            .on_selection(1, &sel, &name("/muas/alice"), |coord| {
                // the unlocked coordination carries the request context
                assert_eq!(coord.requester, name("/muas/alice"));
                assert_eq!(coord.user_token, "utok");
                Bytes::from_static(b"result")
            })
            .unwrap();
        assert!(resp.status);
        assert_eq!(resp.payload, Bytes::from_static(b"result"));
        // pending state cleared on success (NSF-S2).
        assert_eq!(provider.pending_count(), 0);
    }

    #[test]
    fn replayed_selection_fails_closed() {
        let mut provider = ProviderEngine::new(60);
        let req = make_request("r1", "utok", Bytes::new());
        let ack = provider.on_request(0, name("/muas/alice"), name("/svc/x"), &req);
        let sel = make_selection(&ack, "r1");

        assert!(provider.on_selection(0, &sel, &name("/muas/alice"), |_| Bytes::new()).is_ok());
        // A replayed SELECTION coordinates nothing (token already consumed).
        let mut ran = false;
        let result = provider.on_selection(0, &sel, &name("/muas/alice"), |_| {
            ran = true;
            Bytes::new()
        });
        assert_eq!(result, Err(FlowError::TokenRejected(TokenError::Unknown)));
        assert!(!ran, "handler must not run on a rejected selection (fail closed)");
    }

    #[test]
    fn forged_token_fails_closed() {
        let mut provider = ProviderEngine::new(60);
        let sel = SelectionMessage {
            provider_token: "forged".into(),
            request_id: "r1".into(),
        };
        let mut ran = false;
        let result = provider.on_selection(0, &sel, &name("/muas/alice"), |_| {
            ran = true;
            Bytes::new()
        });
        assert_eq!(result, Err(FlowError::TokenRejected(TokenError::Unknown)));
        assert!(!ran);
    }

    fn ack_from(provider: &str) -> (Name, AckMessage) {
        (
            name(provider),
            AckMessage {
                status: true,
                provider_token: format!("tok{provider}"),
                ..Default::default()
            },
        )
    }

    #[test]
    fn select_first_responding_picks_the_first() {
        let acks = vec![ack_from("/p/a"), ack_from("/p/b")];
        let sel = select_providers(Strategy::FirstResponding, &acks);
        assert_eq!(sel.len(), 1);
        assert_eq!(sel[0].0, name("/p/a"));
    }

    #[test]
    fn select_all_picks_every_provider() {
        let acks = vec![ack_from("/p/a"), ack_from("/p/b"), ack_from("/p/c")];
        assert_eq!(select_providers(Strategy::AllSelected, &acks).len(), 3);
    }

    #[test]
    fn select_random_picks_one_of_the_acks() {
        let acks = vec![ack_from("/p/a"), ack_from("/p/b")];
        let sel = select_providers(Strategy::RandomSelection, &acks);
        assert_eq!(sel.len(), 1);
        assert!(sel[0].0 == name("/p/a") || sel[0].0 == name("/p/b"));
    }

    #[test]
    fn select_from_no_acks_is_empty() {
        assert!(select_providers(Strategy::AllSelected, &[]).is_empty());
        assert!(select_providers(Strategy::RandomSelection, &[]).is_empty());
        assert!(select_providers(Strategy::FirstResponding, &[]).is_empty());
    }
}
