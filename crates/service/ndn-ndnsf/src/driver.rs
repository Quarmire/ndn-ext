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
use ndn_sync::SvsPubSub;
use tracing::instrument;

use std::time::Duration;

use crate::flow::{ProviderEngine, make_request, make_selection, select_providers};
use crate::messages::{
    AckMessage, RequestMessage, RequestMode, ResponseMessage, SelectionMessage, Strategy,
};
use crate::names;
use crate::tokens::PendingCoordination;
use crate::trust::TrustCtx;

/// How many single-use tokens a TargetedBootstrap issues to a requester.
const TARGETED_BATCH: usize = 4;

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

/// The `serviceName` path embedded in a REQUEST or SELECTION name (between the
/// phase prefix and the trailing single-component request id). `None` if the name
/// is not a REQUEST/SELECTION or is malformed. Used to route a publication to the
/// provider serving that service when several share one node/group.
fn service_of(name: &Name) -> Option<Name> {
    let comps = name.components();
    let idx = comps.iter().position(|c| *c == comp(names::NDNSF))?;
    let phase = comps.get(idx + 1)?;
    // REQUEST: `..NDNSF/REQUEST/<service...>/<reqid>`.
    // SELECTION: `..NDNSF/SELECTION/<provider-uri>/<service...>/<reqid>` (skip 1).
    let start = if *phase == comp(names::REQUEST) {
        idx + 2
    } else if *phase == comp(names::SELECTION) {
        idx + 3
    } else {
        return None;
    };
    let end = comps.len().checked_sub(1)?; // drop the trailing request id
    if start > end {
        return None;
    }
    Some(Name::from_components(comps[start..end].iter().cloned()))
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
    // The provider holds each pending request's payload until its SELECTION.
    let mut pending_payloads: HashMap<String, Bytes> = HashMap::new();
    let mut rx = ps.subscribe(group_prefix).await;

    while let Some(pubn) = rx.recv().await {
        match phase_of(&pubn.name) {
            Some(Phase::Request) => {
                // Route by service: ignore requests for a service we don't serve
                // (several providers may share one node/group).
                if service_of(&pubn.name).as_ref() != Some(&service) {
                    continue;
                }
                let requester = before_ndnsf(&pubn.name);
                // Trust gate: a REQUEST must be signed by its claimed requester.
                let Some(payload) = trust.unseal(pubn.payload, &requester).await else {
                    continue;
                };
                let Ok(req) = RequestMessage::decode(payload) else {
                    continue;
                };
                let reqid = request_id_of(&pubn.name);
                match req.request_mode {
                    RequestMode::Normal => {
                        pending_payloads.insert(reqid.to_string(), req.payload.clone());
                        let ack = engine.on_request(0, requester.clone(), service.clone(), &req);
                        let name = names::ack_name(&node, &requester, &service, &reqid);
                        let _ = ps.publish(name.clone(), trust.seal(name, ack.encode()).as_ref()).await;
                    }
                    RequestMode::TargetedBootstrap => {
                        // Pre-issue a token batch and return it in the RESPONSE.
                        let toks: Vec<String> = (0..TARGETED_BATCH)
                            .map(|_| {
                                engine
                                    .issue_token(
                                        0,
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
                        let _ = ps.publish(name.clone(), trust.seal(name, resp.encode()).as_ref()).await;
                    }
                    RequestMode::Targeted => {
                        // Consume the pre-issued token and respond directly — no
                        // ACK/SELECTION. Fails closed on an invalid/spent token.
                        let sel = SelectionMessage {
                            provider_token: req.provider_token.clone(),
                            request_id: reqid.to_string(),
                        };
                        if let Ok(resp) =
                            engine.on_selection(0, &sel, |coord| handler(coord, &req.payload))
                        {
                            let name = names::response_name(&node, &requester, &service, &reqid);
                            let _ = ps.publish(name.clone(), trust.seal(name, resp.encode()).as_ref()).await;
                        }
                    }
                }
            }
            Some(Phase::Selection) => {
                if service_of(&pubn.name).as_ref() != Some(&service) {
                    continue;
                }
                let requester = before_ndnsf(&pubn.name);
                // Trust gate: a SELECTION must be signed by its claimed requester.
                let Some(payload) = trust.unseal(pubn.payload, &requester).await else {
                    continue;
                };
                let Ok(sel) = SelectionMessage::decode(payload) else {
                    continue;
                };
                let reqid = request_id_of(&pubn.name);
                let payload = pending_payloads.get(&reqid.to_string()).cloned().unwrap_or_default();
                // on_selection fails closed for a token this provider did not issue.
                if let Ok(resp) = engine.on_selection(0, &sel, |coord| handler(coord, &payload)) {
                    pending_payloads.remove(&reqid.to_string());
                    let name = names::response_name(&node, &requester, &service, &reqid);
                    let _ = ps.publish(name.clone(), trust.seal(name, resp.encode()).as_ref()).await;
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
    dyn Fn(PendingCoordination, Bytes) -> Pin<Box<dyn Future<Output = Bytes> + Send>>
        + Send
        + Sync,
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
    ps: &SvsPubSub,
    node: Name,
    service: Name,
    group_prefix: Name,
    ttl_secs: u64,
    trust: &TrustCtx,
    responder: AsyncResponder,
) {
    let mut engine = ProviderEngine::new(ttl_secs);
    let mut pending_payloads: HashMap<String, Bytes> = HashMap::new();
    let mut rx = ps.subscribe(group_prefix).await;

    while let Some(pubn) = rx.recv().await {
        match phase_of(&pubn.name) {
            Some(Phase::Request) => {
                if service_of(&pubn.name).as_ref() != Some(&service) {
                    continue;
                }
                let requester = before_ndnsf(&pubn.name);
                let Some(payload) = trust.unseal(pubn.payload, &requester).await else {
                    continue;
                };
                let Ok(req) = RequestMessage::decode(payload) else {
                    continue;
                };
                if req.request_mode != RequestMode::Normal {
                    continue; // this serve path drives the Normal/select flow only
                }
                let reqid = request_id_of(&pubn.name);
                pending_payloads.insert(reqid.to_string(), req.payload.clone());
                let ack = engine.on_request(0, requester.clone(), service.clone(), &req);
                let name = names::ack_name(&node, &requester, &service, &reqid);
                let _ = ps.publish(name.clone(), trust.seal(name, ack.encode()).as_ref()).await;
            }
            Some(Phase::Selection) => {
                if service_of(&pubn.name).as_ref() != Some(&service) {
                    continue;
                }
                let requester = before_ndnsf(&pubn.name);
                let Some(payload) = trust.unseal(pubn.payload, &requester).await else {
                    continue;
                };
                let Ok(sel) = SelectionMessage::decode(payload) else {
                    continue;
                };
                let reqid = request_id_of(&pubn.name);
                let req_payload =
                    pending_payloads.get(&reqid.to_string()).cloned().unwrap_or_default();
                // Consume the token (fail-closed) before running the async responder.
                if let Ok(coord) = engine.consume_selection(0, &sel) {
                    pending_payloads.remove(&reqid.to_string());
                    let out = responder(coord, req_payload).await;
                    let resp = ResponseMessage {
                        status: true,
                        error_info: String::new(),
                        payload: out,
                    };
                    let name = names::response_name(&node, &requester, &service, &reqid);
                    let _ = ps.publish(name.clone(), trust.seal(name, resp.encode()).as_ref()).await;
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
    ps.publish(req_name.clone(), trust.seal(req_name, req.encode()).as_ref())
        .await
        .ok()?;

    // Await our provider's ACK (Phase 2), verified to come from `provider`.
    let ack = loop {
        let pubn = rx.recv().await?;
        if phase_of(&pubn.name) == Some(Phase::Ack) && request_id_of(&pubn.name) == request_id {
            let payload = trust.unseal(pubn.payload, &provider).await?;
            break AckMessage::decode(payload).ok()?;
        }
    };

    // Phase 3: SELECTION, echoing the provider token (signed as the requester).
    let sel = make_selection(&ack, &request_id.to_string());
    let sel_name = names::selection_name(&requester, &provider, &service, &request_id);
    ps.publish(sel_name.clone(), trust.seal(sel_name, sel.encode()).as_ref())
        .await
        .ok()?;

    // Await the RESPONSE (Phase 4), verified to come from `provider`.
    loop {
        let pubn = rx.recv().await?;
        if phase_of(&pubn.name) == Some(Phase::Response) && request_id_of(&pubn.name) == request_id {
            let payload = trust.unseal(pubn.payload, &provider).await?;
            return ResponseMessage::decode(payload).ok().map(|r| r.payload);
        }
    }
}

/// Run the user side honoring a selection `strategy`: publish the REQUEST, gather
/// ACKs (`FirstResponding` stops at the first; `RandomSelection`/`AllSelected`
/// collect over `ack_window`), SELECT the chosen provider(s), and return each
/// selected provider's `(name, response)`. The empty vec means no provider
/// responded in time.
#[allow(clippy::too_many_arguments)]
#[instrument(skip(ps, payload, trust), fields(requester = %requester, service = %service, strategy = ?strategy))]
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
        .publish(req_name.clone(), trust.seal(req_name, req.encode()).as_ref())
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
                    && let Some(payload) = trust.unseal(pubn.payload, &provider).await
                    && let Ok(ack) = AckMessage::decode(payload)
                {
                    acks.push((provider, ack));
                }
            }
            _ => break, // window elapsed or group closed
        }
    }

    // Phase 3: SELECT the provider(s) per strategy and send each a SELECTION.
    let selected: Vec<(Name, AckMessage)> =
        select_providers(strategy, &acks).into_iter().cloned().collect();
    let want: Vec<Name> = selected.iter().map(|(p, _)| p.clone()).collect();
    for (provider, ack) in &selected {
        let sel = make_selection(ack, &request_id.to_string());
        let sel_name = names::selection_name(&requester, provider, &service, &request_id);
        let _ = ps.publish(sel_name.clone(), trust.seal(sel_name, sel.encode()).as_ref()).await;
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
                        && let Some(payload) = trust.unseal(pubn.payload, &provider).await
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
        .publish(req_name.clone(), trust.seal(req_name, req.encode()).as_ref())
        .await
        .is_err()
    {
        return Vec::new();
    }
    loop {
        let Some(pubn) = rx.recv().await else {
            return Vec::new();
        };
        if phase_of(&pubn.name) == Some(Phase::Response) && request_id_of(&pubn.name) == request_id {
            let Some(payload) = trust.unseal(pubn.payload, &provider).await else {
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
    ps.publish(req_name.clone(), trust.seal(req_name, req.encode()).as_ref())
        .await
        .ok()?;
    loop {
        let pubn = rx.recv().await?;
        if phase_of(&pubn.name) == Some(Phase::Response) && request_id_of(&pubn.name) == request_id {
            let payload = trust.unseal(pubn.payload, &provider).await?;
            return ResponseMessage::decode(payload).ok().map(|r| r.payload);
        }
    }
}
