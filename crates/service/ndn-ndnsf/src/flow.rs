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
use tracing::instrument;

use crate::messages::{AckMessage, RequestMessage, ResponseMessage, SelectionMessage};
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
        let token = self
            .tokens
            .issue(now_secs, requester, service, req.user_token.clone());
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
        handler: H,
    ) -> Result<ResponseMessage, FlowError>
    where
        H: FnOnce(&PendingCoordination) -> Bytes,
    {
        let token = ProviderToken::from_wire(sel.provider_token.clone());
        let coord = self.tokens.consume(now_secs, &token).map_err(|e| {
            tracing::warn!(error = %e, "selection rejected — fail closed (no response)");
            FlowError::TokenRejected(e)
        })?;
        let payload = handler(&coord);
        Ok(ResponseMessage {
            status: true,
            error_info: String::new(),
            payload,
        })
    }

    /// Pending (issued-but-unconsumed) token count.
    pub fn pending_count(&self) -> usize {
        self.tokens.pending_count()
    }
}

/// Phase 1 — build a service request carrying a one-time user token.
pub fn make_request(request_id: &str, user_token: &str, payload: Bytes) -> RequestMessage {
    RequestMessage {
        request_id: request_id.to_string(),
        user_token: user_token.to_string(),
        payload,
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
            .on_selection(1, &sel, |coord| {
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

        assert!(provider.on_selection(0, &sel, |_| Bytes::new()).is_ok());
        // A replayed SELECTION coordinates nothing (token already consumed).
        let mut ran = false;
        let result = provider.on_selection(0, &sel, |_| {
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
        let result = provider.on_selection(0, &sel, |_| {
            ran = true;
            Bytes::new()
        });
        assert_eq!(result, Err(FlowError::TokenRejected(TokenError::Unknown)));
        assert!(!ran);
    }
}
