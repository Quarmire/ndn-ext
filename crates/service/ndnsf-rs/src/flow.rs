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

use crate::messages::{
    AckMessage, RequestMessage, ResponseMessage, SelectionMessage, SelectionProviderEntry,
    Strategy, selection_token_proof_hash,
};
use crate::tokens::{PendingCoordination, PendingProviderTokens, ProviderToken, TokenError};

/// A four-phase coordination failure on the provider side.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FlowError {
    /// The selection presented a token that was never issued, already consumed,
    /// or expired — no coordination occurs and no response is produced.
    #[error("selection presented an invalid provider token: {0}")]
    TokenRejected(TokenError),
    /// A compact selection named other providers but not this one — the message
    /// is well-formed, this provider was simply not selected. Not an attack:
    /// the driver ignores it silently (no response, no state change).
    #[error("compact selection carries no entry for this provider")]
    NotForUs,
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
            error_info: String::new(),
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
        self.tokens
            .consume(now_secs, &token, requester)
            .map_err(|e| {
                tracing::warn!(error = %e, "selection rejected — fail closed (no response)");
                FlowError::TokenRejected(e)
            })
    }

    /// Validate and consume a **compact** (unified V2) selection for this
    /// provider `node` serving `service`: find our [`SelectionProviderEntry`]
    /// (else [`FlowError::NotForUs`] — we were not selected), then consume the
    /// pending token whose [`selection_token_proof_hash`] matches the entry's
    /// hash, for the **verified** `requester`. The plaintext token never
    /// appears on the wire in this shape; possession is proven by the hash.
    /// Fails closed exactly like [`consume_selection`](Self::consume_selection):
    /// an unknown/expired/mismatched hash consumes nothing and produces no
    /// response. Returns the coordination and the entry's assignment payload.
    pub fn consume_selection_compact(
        &mut self,
        now_secs: u64,
        sel: &SelectionMessage,
        requester: &Name,
        node: &Name,
        service: &Name,
    ) -> Result<(PendingCoordination, bytes::Bytes), FlowError> {
        let Some(entry) = sel
            .provider_entries
            .iter()
            .find(|e| e.provider_name == *node)
        else {
            return Err(FlowError::NotForUs);
        };
        // An entry without a proof hash cannot prove token possession — reject
        // (fail closed; upstream's tokenless mode is out of scope for us).
        if entry.provider_token_hash.is_empty() {
            return Err(FlowError::TokenRejected(TokenError::Unknown));
        }
        let coord = self
            .tokens
            .consume_where(now_secs, requester, |token| {
                selection_token_proof_hash(requester, node, service, token)
                    == entry.provider_token_hash
            })
            .map_err(|e| {
                tracing::warn!(error = %e, "compact selection rejected — fail closed (no response)");
                FlowError::TokenRejected(e)
            })?;
        Ok((coord, entry.assignment_payload.clone()))
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

/// Phase 3 (legacy per-provider shape) — build the selection for a chosen
/// provider's `ACK`, presenting its plaintext provider token. Kept for inbound
/// compatibility tests; the driver **emits** [`make_compact_selection`].
pub fn make_selection(ack: &AckMessage, request_id: &str) -> SelectionMessage {
    SelectionMessage {
        provider_token: ack.provider_token.clone(),
        request_id: request_id.to_string(),
        ..SelectionMessage::default()
    }
}

/// Phase 3 (compact / unified V2 shape) — build **one** selection message naming
/// every selected provider, each entry carrying the token-**proof hash** over
/// that provider's ACKed token (never the plaintext token — upstream's
/// post-2026-06-07 security posture). Published once under
/// [`crate::names::compact_selection_name`].
pub fn make_compact_selection(
    requester: &Name,
    service: &Name,
    request_id: &str,
    selected: &[(Name, AckMessage)],
) -> SelectionMessage {
    SelectionMessage {
        request_id: request_id.to_string(),
        provider_entries: selected
            .iter()
            .map(|(provider, ack)| SelectionProviderEntry {
                provider_name: provider.clone(),
                provider_token_hash: selection_token_proof_hash(
                    requester,
                    provider,
                    service,
                    &ack.provider_token,
                ),
                assignment_payload: bytes::Bytes::new(),
            })
            .collect(),
        ..SelectionMessage::default()
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

        assert!(
            provider
                .on_selection(0, &sel, &name("/muas/alice"), |_| Bytes::new())
                .is_ok()
        );
        // A replayed SELECTION coordinates nothing (token already consumed).
        let mut ran = false;
        let result = provider.on_selection(0, &sel, &name("/muas/alice"), |_| {
            ran = true;
            Bytes::new()
        });
        assert_eq!(result, Err(FlowError::TokenRejected(TokenError::Unknown)));
        assert!(
            !ran,
            "handler must not run on a rejected selection (fail closed)"
        );
    }

    #[test]
    fn compact_selection_happy_path_and_replay() {
        // The full compact round: two providers ACK; the user builds ONE compact
        // selection naming only station A; A consumes by proof hash, B sees NotForUs.
        let mut a = ProviderEngine::new(60);
        let mut b = ProviderEngine::new(60);
        let requester = name("/muas/alice");
        let service = name("/svc/weather");
        let node_a = name("/met/stationA");
        let node_b = name("/met/stationB");

        let req = make_request("r1", "utok", Bytes::from_static(b"forecast"));
        let ack_a = a.on_request(0, requester.clone(), service.clone(), &req);
        let _ack_b = b.on_request(0, requester.clone(), service.clone(), &req);

        let sel = make_compact_selection(
            &requester,
            &service,
            "r1",
            &[(node_a.clone(), ack_a.clone())],
        );
        // The wire round-trip preserves the entries.
        let sel = crate::messages::SelectionMessage::decode(sel.encode()).unwrap();

        // Station B was not selected: NotForUs, token untouched.
        assert_eq!(
            b.consume_selection_compact(1, &sel, &requester, &node_b, &service)
                .unwrap_err(),
            FlowError::NotForUs
        );
        assert_eq!(b.pending_count(), 1);

        // Station A consumes by proof hash — no plaintext token on the wire.
        assert!(!sel.provider_entries[0].provider_token_hash.is_empty());
        assert_ne!(
            sel.provider_entries[0].provider_token_hash,
            ack_a.provider_token,
            "the compact shape must not carry the plaintext token"
        );
        let (coord, _assignment) = a
            .consume_selection_compact(1, &sel, &requester, &node_a, &service)
            .unwrap();
        assert_eq!(coord.requester, requester);
        assert_eq!(coord.user_token, "utok");
        assert_eq!(a.pending_count(), 0, "consumed once (NSF-T1/S2)");

        // Replay fails closed (NSF-T3).
        assert_eq!(
            a.consume_selection_compact(1, &sel, &requester, &node_a, &service)
                .unwrap_err(),
            FlowError::TokenRejected(TokenError::Unknown)
        );
    }

    #[test]
    fn compact_selection_wrong_requester_cannot_redeem() {
        // SEC-03 analog for the compact shape: mallory replays alice's compact
        // selection under her own (verified) identity — the proof hash binds the
        // requester, so no token of mallory's matches and nothing is consumed.
        let mut a = ProviderEngine::new(60);
        let requester = name("/muas/alice");
        let service = name("/svc/weather");
        let node_a = name("/met/stationA");
        let req = make_request("r1", "utok", Bytes::new());
        let ack_a = a.on_request(0, requester.clone(), service.clone(), &req);
        let sel = make_compact_selection(
            &requester,
            &service,
            "r1",
            &[(node_a.clone(), ack_a)],
        );
        assert_eq!(
            a.consume_selection_compact(1, &sel, &name("/muas/mallory"), &node_a, &service)
                .unwrap_err(),
            FlowError::TokenRejected(TokenError::Unknown)
        );
        assert_eq!(a.pending_count(), 1, "alice's pending token must survive");
    }

    #[test]
    fn compact_selection_empty_or_forged_hash_fails_closed() {
        let mut a = ProviderEngine::new(60);
        let requester = name("/muas/alice");
        let service = name("/svc/weather");
        let node_a = name("/met/stationA");
        let req = make_request("r1", "utok", Bytes::new());
        let _ack = a.on_request(0, requester.clone(), service.clone(), &req);

        // Forged hash: well-formed entry, wrong digest.
        let mut sel = make_compact_selection(&requester, &service, "r1", &[]);
        sel.provider_entries.push(crate::messages::SelectionProviderEntry {
            provider_name: node_a.clone(),
            provider_token_hash: "00".repeat(32),
            assignment_payload: Bytes::new(),
        });
        assert_eq!(
            a.consume_selection_compact(1, &sel, &requester, &node_a, &service)
                .unwrap_err(),
            FlowError::TokenRejected(TokenError::Unknown)
        );

        // Empty hash: rejected, not treated as tokenless-accept.
        sel.provider_entries[0].provider_token_hash = String::new();
        assert_eq!(
            a.consume_selection_compact(1, &sel, &requester, &node_a, &service)
                .unwrap_err(),
            FlowError::TokenRejected(TokenError::Unknown)
        );
        assert_eq!(a.pending_count(), 1, "nothing consumed on either rejection");
    }

    #[test]
    fn forged_token_fails_closed() {
        let mut provider = ProviderEngine::new(60);
        let sel = SelectionMessage {
            provider_token: "forged".into(),
            request_id: "r1".into(),
            ..SelectionMessage::default()
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
