//! The over-SVS four-phase driver (feature `driver`).
//!
//! Binds the sans-IO [`crate::flow`] orchestration to `ndn-sync`'s `SvsPubSub`:
//! a [`serve_provider`] loop runs the provider side (REQUEST→ACK,
//! SELECTION→RESPONSE) and [`call`] runs the user side (REQUEST→await ACK→
//! SELECTION→await RESPONSE) over a shared sync group. Participants subscribe to
//! a common group prefix and dispatch by the `NDNSF/<phase>` name marker.
//!
//! Routing is by token, not by name trust alone: only the provider whose
//! `ProviderEngine` issued a SELECTION's token consumes it, so in a multi-
//! provider group each provider serves only its own coordinations; an invalid
//! token fails closed (no RESPONSE). The phase spans flow into the OTLP-over-NDN
//! observability pipeline for per-leg latency.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use ndn_packet::{Name, NameComponent};
use ndn_ratelimit::{BucketOutcome, BucketSpec, TokenBucket};
use ndn_sync::SvsPubSub;
use tracing::instrument;

use std::time::{Duration, Instant};

use crate::flow::{ProviderEngine, make_compact_selection, make_request, select_providers};
use crate::messages::{
    AckMessage, RequestMessage, RequestMode, ResponseMessage, SelectionMessage, Strategy,
};
use crate::names;
use crate::policy::ProviderAuthorizer;
use crate::tokens::PendingCoordination;
use crate::trust::TrustCtx;

/// How many single-use tokens a TargetedBootstrap issues to a requester.
const TARGETED_BATCH: usize = 4;

/// Cap on a provider's in-flight unselected request payloads. A SELECTION may
/// never arrive, so without a ceiling (plus the TTL reap) the map grows unbounded
/// (red-team SEC-07). At the cap the provider sheds new requests.
const MAX_PENDING_PAYLOADS: usize = 1024;

/// Max wall-clock a single async handler may run before the provider gives up on
/// it and answers with an error — so one slow/hung handler neither blocks the
/// receive loop (it runs off-loop) nor leaves the client waiting forever (SEC-23).
const HANDLER_TIMEOUT: Duration = Duration::from_secs(30);

/// Per-requester admission control (red-team SEC-25): requests/sec and burst per
/// requester identity, and a cap on how many identities to track.
const RL_REQUESTS_PER_SEC: u32 = 50;
const RL_BURST: u32 = 100;
const RL_MAX_IDENTITIES: usize = 4096;

/// One token bucket per requester identity, in a bounded map. Bounds a single
/// (authenticated) requester's request rate on the four-phase REQUEST path. Under
/// the explicit `.insecure()` posture identities are spoofable, so this is
/// best-effort there — but the map cap still bounds memory, and the check runs
/// *before* the signature verify, so it also caps verify amplification.
struct RequesterLimiter {
    buckets: HashMap<Name, TokenBucket>,
}

impl RequesterLimiter {
    fn new() -> Self {
        Self {
            buckets: HashMap::new(),
        }
    }

    /// Admit one request from `who`; `false` ⇒ over the per-requester rate (drop).
    fn admit(&mut self, who: &Name) -> bool {
        if !self.buckets.contains_key(who) {
            if self.buckets.len() >= RL_MAX_IDENTITIES {
                // Evict an arbitrary entry to admit the newcomer — bounds memory
                // without letting an identity flood lock everyone else out.
                if let Some(victim) = self.buckets.keys().next().cloned() {
                    self.buckets.remove(&victim);
                }
            }
            match TokenBucket::from_spec(&BucketSpec::pps(RL_REQUESTS_PER_SEC, RL_BURST)) {
                Ok(bucket) => {
                    self.buckets.insert(who.clone(), bucket);
                }
                Err(_) => return true, // misconfigured limiter must not block traffic
            }
        }
        matches!(
            self.buckets.get(who).map(|b| b.try_consume(1, 0)),
            Some(BucketOutcome::Permit)
        )
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Request,
    Ack,
    Selection,
    Response,
}

fn comp(s: &str) -> NameComponent {
    NameComponent::generic(Bytes::copy_from_slice(s.as_bytes()))
}

/// The phase marker following the `NDNSF` component, if any.
fn phase_of(name: &Name) -> Option<Phase> {
    let comps = name.components();
    let idx = comps.iter().position(|c| *c == comp(names::NDNSF))?;
    let p = comps.get(idx + 1)?;
    if *p == comp(names::REQUEST) {
        Some(Phase::Request)
    } else if *p == comp(names::ACK) {
        Some(Phase::Ack)
    } else if *p == comp(names::SELECTION) {
        Some(Phase::Selection)
    } else if *p == comp(names::RESPONSE) {
        Some(Phase::Response)
    } else {
        None
    }
}

/// The publisher prefix before the `NDNSF` marker (the requester for REQUEST/
/// SELECTION, the provider for ACK/RESPONSE).
fn before_ndnsf(name: &Name) -> Name {
    let comps = name.components();
    let idx = comps
        .iter()
        .position(|c| *c == comp(names::NDNSF))
        .unwrap_or(comps.len());
    Name::from_components(comps[..idx].iter().cloned())
}

/// The request-id is the last component of every phase name.
fn request_id_of(name: &Name) -> Name {
    match name.components().last() {
        Some(c) => Name::from_components([c.clone()]),
        None => Name::from_components(core::iter::empty::<NameComponent>()),
    }
}

/// The `serviceName` path embedded in a REQUEST name (between the phase prefix
/// and the trailing single-component request id). `None` if the name is not a
/// REQUEST or is malformed. Used to route a publication to the provider serving
/// that service when several share one node/group.
fn service_of(name: &Name) -> Option<Name> {
    let comps = name.components();
    let idx = comps.iter().position(|c| *c == comp(names::NDNSF))?;
    if comps.get(idx + 1) != Some(&comp(names::REQUEST)) {
        return None;
    }
    let start = idx + 2;
    let end = comps.len().checked_sub(1)?; // drop the trailing request id
    if start > end {
        return None;
    }
    Some(Name::from_components(comps[start..end].iter().cloned()))
}

/// Whether a SELECTION name addresses `service`, in **either** accepted shape:
///
/// * compact:  `..NDNSF/SELECTION/<service...>/<reqid>` (what we and upstream emit)
/// * legacy:   `..NDNSF/SELECTION/<provider-uri>/<service...>/<reqid>` (inbound only)
///
/// A name that matches neither slice is for another service — ignore. The two
/// shapes can't false-positive against each other for the same `service`: the
/// slices differ in length. Routing here is only a *filter*; the message-level
/// entry/token check is what authorizes execution.
fn selection_matches_service(name: &Name, service: &Name) -> bool {
    let comps = name.components();
    let Some(idx) = comps.iter().position(|c| *c == comp(names::NDNSF)) else {
        return false;
    };
    if comps.get(idx + 1) != Some(&comp(names::SELECTION)) {
        return false;
    }
    let Some(end) = comps.len().checked_sub(1) else {
        return false;
    };
    let slice_eq = |start: usize| {
        start <= end && Name::from_components(comps[start..end].iter().cloned()) == *service
    };
    slice_eq(idx + 2) || slice_eq(idx + 3)
}

/// Run the provider side: serve `service` in `group`, ACKing requests and, on a
/// valid SELECTION, running `handler(coordination, request_payload)` and
/// publishing the RESPONSE. Loops until the subscription closes.
pub async fn serve_provider<H>(
    ps: &SvsPubSub,
    node: Name,
    service: Name,
    group_prefix: Name,
    ttl_secs: u64,
    trust: &TrustCtx,
    handler: H,
) where
    H: Fn(&PendingCoordination, &Bytes) -> Bytes,
{
    let mut engine = ProviderEngine::new(ttl_secs);
    // The provider holds each pending request's payload until its SELECTION, with
    // the insertion time so stale entries (whose SELECTION never comes) are reaped.
    let mut pending_payloads: HashMap<String, (Bytes, u64)> = HashMap::new();
    let mut limiter = RequesterLimiter::new();
    let mut rx = ps.subscribe(group_prefix).await;
    let start = Instant::now();

    while let Some(pubn) = rx.recv().await {
        // Monotonic clock for token/pending TTL — without this the expiry is inert
        // and both maps grow unbounded (red-team SEC-08).
        let now = start.elapsed().as_secs();
        engine.cleanup_expired(now);
        pending_payloads.retain(|_, (_, created)| now.saturating_sub(*created) < ttl_secs);

        match phase_of(&pubn.name) {
            Some(Phase::Request) => {
                // Route by service: ignore requests for a service we don't serve
                // (several providers may share one node/group).
                if service_of(&pubn.name).as_ref() != Some(&service) {
                    continue;
                }
                let requester = before_ndnsf(&pubn.name);
                // Admission control: cap requests per requester *before* the verify,
                // so a flood neither monopolizes the provider nor amplifies signature
                // work (red-team SEC-25).
                if !limiter.admit(&requester) {
                    continue;
                }
                // Trust gate: a REQUEST must be signed by its claimed requester.
                let Some(payload) = trust.unseal(pubn.payload, &requester, &pubn.name).await else {
                    continue;
                };
                let Ok(req) = RequestMessage::decode(payload) else {
                    continue;
                };
                let reqid = request_id_of(&pubn.name);
                match req.request_mode {
                    RequestMode::Normal => {
                        // At the cap: negative-ACK (spec 044, QUEUE_FULL) instead of a
                        // silent drop, so the user can stop/fail over early. No token
                        // is issued and nothing goes pending.
                        if pending_payloads.len() >= MAX_PENDING_PAYLOADS {
                            let nack = AckMessage::negative(
                                crate::messages::reason::QUEUE_FULL,
                                &req.user_token,
                            );
                            let name = names::ack_name(&node, &requester, &service, &reqid);
                            let _ = ps
                                .publish(name.clone(), trust.seal(name, nack.encode()).as_ref())
                                .await;
                            continue;
                        }
                        pending_payloads.insert(reqid.to_string(), (req.payload.clone(), now));
                        let ack = engine.on_request(now, requester.clone(), service.clone(), &req);
                        let name = names::ack_name(&node, &requester, &service, &reqid);
                        let _ = ps
                            .publish(name.clone(), trust.seal(name, ack.encode()).as_ref())
                            .await;
                    }
                    RequestMode::TargetedBootstrap => {
                        // Pre-issue a token batch and return it in the RESPONSE.
                        let toks: Vec<String> = (0..TARGETED_BATCH)
                            .map(|_| {
                                engine
                                    .issue_token(
                                        now,
                                        requester.clone(),
                                        service.clone(),
                                        req.user_token.clone(),
                                    )
                                    .as_str()
                                    .to_string()
                            })
                            .collect();
                        let resp = ResponseMessage {
                            status: true,
                            error_info: String::new(),
                            payload: Bytes::from(toks.join("\n").into_bytes()),
                        };
                        let name = names::response_name(&node, &requester, &service, &reqid);
                        let _ = ps
                            .publish(name.clone(), trust.seal(name, resp.encode()).as_ref())
                            .await;
                    }
                    RequestMode::Targeted => {
                        // Consume the pre-issued token and respond directly — no
                        // ACK/SELECTION. Fails closed on an invalid/spent token.
                        let sel = SelectionMessage {
                            provider_token: req.provider_token.clone(),
                            request_id: reqid.to_string(),
                            ..SelectionMessage::default()
                        };
                        if let Ok(resp) = engine.on_selection(now, &sel, &requester, |coord| {
                            handler(coord, &req.payload)
                        }) {
                            let name = names::response_name(&node, &requester, &service, &reqid);
                            let _ = ps
                                .publish(name.clone(), trust.seal(name, resp.encode()).as_ref())
                                .await;
                        }
                    }
                }
            }
            Some(Phase::Selection) => {
                if !selection_matches_service(&pubn.name, &service) {
                    continue;
                }
                let requester = before_ndnsf(&pubn.name);
                // Trust gate: a SELECTION must be signed by its claimed requester.
                let Some(payload) = trust.unseal(pubn.payload, &requester, &pubn.name).await else {
                    continue;
                };
                let Ok(sel) = SelectionMessage::decode(payload) else {
                    continue;
                };
                let reqid = request_id_of(&pubn.name);
                let payload = pending_payloads
                    .get(&reqid.to_string())
                    .map(|(p, _)| p.clone())
                    .unwrap_or_default();
                // Compact shape (entries present): consume our entry's token by
                // proof hash; NotForUs (another provider's selection) and any
                // token rejection alike produce no response (fail closed).
                // Legacy shape (no entries): plaintext-token consume, as before.
                let coord = if !sel.provider_entries.is_empty() {
                    engine
                        .consume_selection_compact(now, &sel, &requester, &node, &service)
                        .map(|(coord, _assignment)| coord)
                } else {
                    engine.consume_selection(now, &sel, &requester)
                };
                if let Ok(coord) = coord {
                    let resp = ResponseMessage {
                        status: true,
                        error_info: String::new(),
                        payload: handler(&coord, &payload),
                    };
                    pending_payloads.remove(&reqid.to_string());
                    let name = names::response_name(&node, &requester, &service, &reqid);
                    let _ = ps
                        .publish(name.clone(), trust.seal(name, resp.encode()).as_ref())
                        .await;
                }
            }
            _ => {} // ACK/RESPONSE: our own or others' — ignore
        }
    }
}

/// An async response producer for [`serve_provider_async`]: given the validated
/// coordination and the (owned) request payload, yield the response payload.
/// This is the seam a service `Carrier` plugs its async `Dispatch` into.
pub type AsyncResponder = Arc<
    dyn Fn(PendingCoordination, Bytes) -> Pin<Box<dyn Future<Output = Bytes> + Send>> + Send + Sync,
>;

/// Provider loop for the Normal four-phase path (REQUEST→ACK, SELECTION→RESPONSE)
/// with an **async** `responder` run at the selection step — the bridge for a
/// service `Carrier` whose `Dispatch` is async. Mirrors [`serve_provider`]'s
/// Normal path (service-name routing, trust gating, token coordination) but
/// awaits the responder; the token is consumed *before* the responder runs
/// (fail-closed, NSF-T/F invariants preserved). Targeted modes are not handled
/// here — the service carrier uses Normal/select only. Runs until the
/// subscription closes.
pub async fn serve_provider_async(
    ps: Arc<SvsPubSub>,
    node: Name,
    service: Name,
    group_prefix: Name,
    ttl_secs: u64,
    trust: &TrustCtx,
    responder: AsyncResponder,
) {
    let mut engine = ProviderEngine::new(ttl_secs);
    let mut pending_payloads: HashMap<String, (Bytes, u64)> = HashMap::new();
    let mut limiter = RequesterLimiter::new();
    let mut rx = ps.subscribe(group_prefix).await;
    let start = Instant::now();

    while let Some(pubn) = rx.recv().await {
        // Monotonic clock for token/pending TTL (red-team SEC-07/SEC-08).
        let now = start.elapsed().as_secs();
        engine.cleanup_expired(now);
        pending_payloads.retain(|_, (_, created)| now.saturating_sub(*created) < ttl_secs);

        match phase_of(&pubn.name) {
            Some(Phase::Request) => {
                if service_of(&pubn.name).as_ref() != Some(&service) {
                    continue;
                }
                let requester = before_ndnsf(&pubn.name);
                // Admission control before the verify (red-team SEC-25).
                if !limiter.admit(&requester) {
                    continue;
                }
                let Some(payload) = trust.unseal(pubn.payload, &requester, &pubn.name).await else {
                    continue;
                };
                let Ok(req) = RequestMessage::decode(payload) else {
                    continue;
                };
                if req.request_mode != RequestMode::Normal {
                    continue; // this serve path drives the Normal/select flow only
                }
                let reqid = request_id_of(&pubn.name);
                // At the cap: negative-ACK QUEUE_FULL (spec 044) instead of a
                // silent drop — no token issued, nothing pending.
                if pending_payloads.len() >= MAX_PENDING_PAYLOADS {
                    let nack =
                        AckMessage::negative(crate::messages::reason::QUEUE_FULL, &req.user_token);
                    let name = names::ack_name(&node, &requester, &service, &reqid);
                    let _ = ps
                        .publish(name.clone(), trust.seal(name, nack.encode()).as_ref())
                        .await;
                    continue;
                }
                pending_payloads.insert(reqid.to_string(), (req.payload.clone(), now));
                let ack = engine.on_request(now, requester.clone(), service.clone(), &req);
                let name = names::ack_name(&node, &requester, &service, &reqid);
                let _ = ps
                    .publish(name.clone(), trust.seal(name, ack.encode()).as_ref())
                    .await;
            }
            Some(Phase::Selection) => {
                if !selection_matches_service(&pubn.name, &service) {
                    continue;
                }
                let requester = before_ndnsf(&pubn.name);
                let Some(payload) = trust.unseal(pubn.payload, &requester, &pubn.name).await else {
                    continue;
                };
                let Ok(sel) = SelectionMessage::decode(payload) else {
                    continue;
                };
                let reqid = request_id_of(&pubn.name);
                let req_payload = pending_payloads
                    .get(&reqid.to_string())
                    .map(|(p, _)| p.clone())
                    .unwrap_or_default();
                // Consume the token (fail-closed) ON the loop — compact shape by
                // proof hash, legacy shape by plaintext — then run the handler
                // OFF the loop with a timeout, so a slow/hung responder neither blocks
                // other coordinations (head-of-line) nor strands the client (SEC-23).
                let coord = if !sel.provider_entries.is_empty() {
                    engine
                        .consume_selection_compact(now, &sel, &requester, &node, &service)
                        .map(|(coord, _assignment)| coord)
                } else {
                    engine.consume_selection(now, &sel, &requester)
                };
                if let Ok(coord) = coord {
                    pending_payloads.remove(&reqid.to_string());
                    let resp_name = names::response_name(&node, &requester, &service, &reqid);
                    let responder = responder.clone();
                    let ps = ps.clone();
                    let trust = trust.clone();
                    tokio::spawn(async move {
                        let resp = match tokio::time::timeout(
                            HANDLER_TIMEOUT,
                            responder(coord, req_payload),
                        )
                        .await
                        {
                            Ok(payload) => ResponseMessage {
                                status: true,
                                error_info: String::new(),
                                payload,
                            },
                            Err(_) => ResponseMessage {
                                status: false,
                                error_info: "handler timed out".into(),
                                payload: Bytes::new(),
                            },
                        };
                        let _ = ps
                            .publish(
                                resp_name.clone(),
                                trust.seal(resp_name, resp.encode()).as_ref(),
                            )
                            .await;
                    });
                }
            }
            _ => {}
        }
    }
}

/// Run the user side of one call to `provider` for `service`: publish the
/// REQUEST, await the provider's ACK, SELECT it, and return the RESPONSE
/// payload. `None` if the group/subscription closes before completion.
// Raw driver entry point; the ergonomic `ServiceUser`/`ServiceProvider` role
// wrappers (spec §11) bundle the stable fields and come with that phase.
#[allow(clippy::too_many_arguments)]
#[instrument(skip(ps, payload, trust), fields(requester = %requester, provider = %provider, service = %service))]
pub async fn call(
    ps: &SvsPubSub,
    requester: Name,
    provider: Name,
    service: Name,
    request_id: Name,
    group_prefix: Name,
    payload: Bytes,
    user_token: &str,
    trust: &TrustCtx,
) -> Option<Bytes> {
    let mut rx = ps.subscribe(group_prefix).await;

    // Phase 1: REQUEST (signed as the requester).
    let req = make_request(&request_id.to_string(), user_token, payload);
    let req_name = names::request_name(&requester, &service, &request_id);
    ps.publish(
        req_name.clone(),
        trust.seal(req_name, req.encode()).as_ref(),
    )
    .await
    .ok()?;

    // Await our provider's ACK (Phase 2), verified to come from `provider`.
    let ack = loop {
        let pubn = rx.recv().await?;
        if phase_of(&pubn.name) == Some(Phase::Ack) && request_id_of(&pubn.name) == request_id {
            let payload = trust.unseal(pubn.payload, &provider, &pubn.name).await?;
            break AckMessage::decode(payload).ok()?;
        }
    };
    // Negative ACK (spec 044): our single known provider declined — stop now
    // rather than waiting out a window that can't succeed (early-stop).
    if !ack.status {
        tracing::warn!(reason = %ack.error_info, provider = %provider, "negative ACK — early stop");
        return None;
    }

    // Phase 3: one compact SELECTION naming the provider, proving token
    // possession by hash (the plaintext token stays off the wire).
    let sel = make_compact_selection(
        &requester,
        &service,
        &request_id.to_string(),
        &[(provider.clone(), ack)],
    );
    let sel_name = names::compact_selection_name(&requester, &service, &request_id);
    ps.publish(
        sel_name.clone(),
        trust.seal(sel_name, sel.encode()).as_ref(),
    )
    .await
    .ok()?;

    // Await the RESPONSE (Phase 4), verified to come from `provider`.
    loop {
        let pubn = rx.recv().await?;
        if phase_of(&pubn.name) == Some(Phase::Response) && request_id_of(&pubn.name) == request_id
        {
            let payload = trust.unseal(pubn.payload, &provider, &pubn.name).await?;
            return ResponseMessage::decode(payload).ok().map(|r| r.payload);
        }
    }
}

/// Run the user side honoring a selection `strategy`: publish the REQUEST, gather
/// ACKs (`FirstResponding` stops at the first; `RandomSelection`/`AllSelected`
/// collect over `ack_window`), SELECT the chosen provider(s), and return each
/// selected provider's `(name, response)`. The empty vec means no provider
/// responded in time.
///
/// When `authorizer` is `Some`, an ACK from a provider **not authorized to serve
/// `service`** is dropped *before selection* — so a trusted-but-unlisted group
/// member can never be selected (per-service provider authorization, SEC-05).
/// `None` keeps the legacy behavior: any provider whose ACK verifies may serve.
#[allow(clippy::too_many_arguments)]
#[instrument(skip(ps, payload, trust, authorizer), fields(requester = %requester, service = %service, strategy = ?strategy))]
pub async fn select_and_call(
    ps: &SvsPubSub,
    requester: Name,
    service: Name,
    request_id: Name,
    group_prefix: Name,
    payload: Bytes,
    user_token: &str,
    strategy: Strategy,
    ack_window: Duration,
    trust: &TrustCtx,
    authorizer: Option<&ProviderAuthorizer>,
) -> Vec<(Name, Bytes)> {
    let mut rx = ps.subscribe(group_prefix).await;

    // Phase 1: REQUEST carrying the requested strategy (signed as the requester).
    let req = RequestMessage {
        request_id: request_id.to_string(),
        user_token: user_token.to_string(),
        payload,
        strategy,
        ..Default::default()
    };
    let req_name = names::request_name(&requester, &service, &request_id);
    if ps
        .publish(
            req_name.clone(),
            trust.seal(req_name, req.encode()).as_ref(),
        )
        .await
        .is_err()
    {
        return Vec::new();
    }

    // Phase 2: collect ACKs. FirstResponding stops at the first; the others
    // gather every ACK that arrives within `ack_window`.
    let mut acks: Vec<(Name, AckMessage)> = Vec::new();
    let deadline = tokio::time::Instant::now() + ack_window;
    loop {
        if strategy == Strategy::FirstResponding && !acks.is_empty() {
            break;
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(pubn)) => {
                let provider = before_ndnsf(&pubn.name);
                if phase_of(&pubn.name) == Some(Phase::Ack)
                    && request_id_of(&pubn.name) == request_id
                    // Per-service provider authorization: refuse an ACK from a
                    // provider the policy does not list for this service, before it
                    // can be selected (SEC-05). `None` ⇒ membership is authorization.
                    && authorizer.is_none_or(|a| a.allows(&service, &provider))
                    && let Some(payload) = trust.unseal(pubn.payload, &provider, &pubn.name).await
                    && let Ok(ack) = AckMessage::decode(payload)
                {
                    // A negative ACK (spec 044) is never a selection candidate;
                    // record its reason and keep collecting.
                    if !ack.status {
                        tracing::debug!(reason = %ack.error_info, provider = %provider,
                            "negative ACK recorded");
                        continue;
                    }
                    acks.push((provider, ack));
                }
            }
            _ => break, // window elapsed or group closed
        }
    }

    // Phase 3: SELECT the provider(s) per strategy and publish ONE compact
    // SELECTION naming them all — each entry proves possession of that
    // provider's token by hash (upstream's unified V2 shape; the plaintext
    // tokens stay off the wire).
    let selected: Vec<(Name, AckMessage)> = select_providers(strategy, &acks)
        .into_iter()
        .cloned()
        .collect();
    let want: Vec<Name> = selected.iter().map(|(p, _)| p.clone()).collect();
    if !selected.is_empty() {
        let sel = make_compact_selection(&requester, &service, &request_id.to_string(), &selected);
        let sel_name = names::compact_selection_name(&requester, &service, &request_id);
        let _ = ps
            .publish(
                sel_name.clone(),
                trust.seal(sel_name, sel.encode()).as_ref(),
            )
            .await;
    }

    // Phase 4: collect one RESPONSE per selected provider, within the window.
    let mut responses: Vec<(Name, Bytes)> = Vec::new();
    let deadline = tokio::time::Instant::now() + ack_window;
    while responses.len() < want.len() {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(pubn)) => {
                if phase_of(&pubn.name) == Some(Phase::Response)
                    && request_id_of(&pubn.name) == request_id
                {
                    let provider = before_ndnsf(&pubn.name);
                    if want.contains(&provider)
                        && !responses.iter().any(|(p, _)| *p == provider)
                        && let Some(payload) =
                            trust.unseal(pubn.payload, &provider, &pubn.name).await
                        && let Ok(resp) = ResponseMessage::decode(payload)
                    {
                        responses.push((provider, resp.payload));
                    }
                }
            }
            _ => break,
        }
    }
    responses
}

/// Targeted bootstrap (NDNSF `TargetedBootstrapRequest`): ask `provider` for a
/// batch of single-use tokens for `service`, returning the token pool. Empty on
/// failure/close.
#[allow(clippy::too_many_arguments)]
pub async fn bootstrap_targeted(
    ps: &SvsPubSub,
    requester: Name,
    provider: Name,
    service: Name,
    request_id: Name,
    group_prefix: Name,
    user_token: &str,
    trust: &TrustCtx,
) -> Vec<String> {
    let mut rx = ps.subscribe(group_prefix).await;
    let req = RequestMessage {
        request_id: request_id.to_string(),
        user_token: user_token.to_string(),
        request_mode: RequestMode::TargetedBootstrap,
        target_provider: Some(provider.clone()),
        ..Default::default()
    };
    let req_name = names::request_name(&requester, &service, &request_id);
    if ps
        .publish(
            req_name.clone(),
            trust.seal(req_name, req.encode()).as_ref(),
        )
        .await
        .is_err()
    {
        return Vec::new();
    }
    loop {
        let Some(pubn) = rx.recv().await else {
            return Vec::new();
        };
        if phase_of(&pubn.name) == Some(Phase::Response) && request_id_of(&pubn.name) == request_id
        {
            let Some(payload) = trust.unseal(pubn.payload, &provider, &pubn.name).await else {
                return Vec::new();
            };
            return match ResponseMessage::decode(payload) {
                Ok(resp) => String::from_utf8_lossy(&resp.payload)
                    .split('\n')
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect(),
                Err(_) => Vec::new(),
            };
        }
    }
}

/// Targeted call (NDNSF `TargetedRequest`): invoke `provider` directly with a
/// pre-issued `provider_token`, skipping ACK/SELECTION. `None` if no valid
/// response arrives (an invalid/spent token yields none — fail closed).
#[allow(clippy::too_many_arguments)]
pub async fn call_targeted(
    ps: &SvsPubSub,
    requester: Name,
    provider: Name,
    service: Name,
    request_id: Name,
    group_prefix: Name,
    payload: Bytes,
    user_token: &str,
    provider_token: &str,
    trust: &TrustCtx,
) -> Option<Bytes> {
    let mut rx = ps.subscribe(group_prefix).await;
    let req = RequestMessage {
        request_id: request_id.to_string(),
        user_token: user_token.to_string(),
        payload,
        request_mode: RequestMode::Targeted,
        target_provider: Some(provider.clone()),
        provider_token: provider_token.to_string(),
        ..Default::default()
    };
    let req_name = names::request_name(&requester, &service, &request_id);
    ps.publish(
        req_name.clone(),
        trust.seal(req_name, req.encode()).as_ref(),
    )
    .await
    .ok()?;
    loop {
        let pubn = rx.recv().await?;
        if phase_of(&pubn.name) == Some(Phase::Response) && request_id_of(&pubn.name) == request_id
        {
            let payload = trust.unseal(pubn.payload, &provider, &pubn.name).await?;
            return ResponseMessage::decode(payload).ok().map(|r| r.payload);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    #[test]
    fn rate_limiter_caps_a_flood_and_isolates_identities() {
        // SEC-25: a tight flood from one requester is rate-limited, while a distinct
        // requester keeps its own (undrained) bucket.
        let mut limiter = RequesterLimiter::new();
        let alice = n("/muas/alice");
        let permitted = (0..1000).filter(|_| limiter.admit(&alice)).count();
        assert!(
            permitted > 0,
            "the burst allowance must let an initial run through"
        );
        assert!(
            permitted < 1000,
            "a tight flood from one requester must be rate-limited"
        );

        let bob = n("/muas/bob");
        assert!(
            limiter.admit(&bob),
            "a distinct requester must not be starved by another's flood"
        );
    }

    #[test]
    fn rate_limiter_bounds_tracked_identities() {
        // The identity map is memory-bounded even under identity churn.
        let mut limiter = RequesterLimiter::new();
        for i in 0..(RL_MAX_IDENTITIES + 500) {
            limiter.admit(&n(&format!("/muas/u{i}")));
        }
        assert!(limiter.buckets.len() <= RL_MAX_IDENTITIES);
    }
}
