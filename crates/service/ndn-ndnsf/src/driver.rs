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

/// Run the provider side: serve `service` in `group`, ACKing requests and, on a
/// valid SELECTION, running `handler(coordination, request_payload)` and
/// publishing the RESPONSE. Loops until the subscription closes.
pub async fn serve_provider<H>(
    ps: &SvsPubSub,
    node: Name,
    service: Name,
    group_prefix: Name,
    ttl_secs: u64,
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
                let Ok(req) = RequestMessage::decode(pubn.payload) else {
                    continue;
                };
                let requester = before_ndnsf(&pubn.name);
                let reqid = request_id_of(&pubn.name);
                match req.request_mode {
                    RequestMode::Normal => {
                        pending_payloads.insert(reqid.to_string(), req.payload.clone());
                        let ack = engine.on_request(0, requester.clone(), service.clone(), &req);
                        let _ = ps
                            .publish(
                                names::ack_name(&node, &requester, &service, &reqid),
                                ack.encode().as_ref(),
                            )
                            .await;
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
                        let _ = ps
                            .publish(
                                names::response_name(&node, &requester, &service, &reqid),
                                resp.encode().as_ref(),
                            )
                            .await;
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
                            let _ = ps
                                .publish(
                                    names::response_name(&node, &requester, &service, &reqid),
                                    resp.encode().as_ref(),
                                )
                                .await;
                        }
                    }
                }
            }
            Some(Phase::Selection) => {
                let Ok(sel) = SelectionMessage::decode(pubn.payload) else {
                    continue;
                };
                let requester = before_ndnsf(&pubn.name);
                let reqid = request_id_of(&pubn.name);
                let payload = pending_payloads.get(&reqid.to_string()).cloned().unwrap_or_default();
                // on_selection fails closed for a token this provider did not issue.
                if let Ok(resp) = engine.on_selection(0, &sel, |coord| handler(coord, &payload)) {
                    pending_payloads.remove(&reqid.to_string());
                    let _ = ps
                        .publish(
                            names::response_name(&node, &requester, &service, &reqid),
                            resp.encode().as_ref(),
                        )
                        .await;
                }
            }
            _ => {} // ACK/RESPONSE: our own or others' — ignore
        }
    }
}

/// Run the user side of one call to `provider` for `service`: publish the
/// REQUEST, await the provider's ACK, SELECT it, and return the RESPONSE
/// payload. `None` if the group/subscription closes before completion.
// Raw driver entry point; the ergonomic `ServiceUser`/`ServiceProvider` role
// wrappers (spec §11) bundle the stable fields and come with that phase.
#[allow(clippy::too_many_arguments)]
#[instrument(skip(ps, payload), fields(requester = %requester, provider = %provider, service = %service))]
pub async fn call(
    ps: &SvsPubSub,
    requester: Name,
    provider: Name,
    service: Name,
    request_id: Name,
    group_prefix: Name,
    payload: Bytes,
    user_token: &str,
) -> Option<Bytes> {
    let mut rx = ps.subscribe(group_prefix).await;

    // Phase 1: REQUEST.
    let req = make_request(&request_id.to_string(), user_token, payload);
    ps.publish(names::request_name(&requester, &service, &request_id), req.encode().as_ref())
        .await
        .ok()?;

    // Await our provider's ACK (Phase 2).
    let ack = loop {
        let pubn = rx.recv().await?;
        if phase_of(&pubn.name) == Some(Phase::Ack) && request_id_of(&pubn.name) == request_id {
            break AckMessage::decode(pubn.payload).ok()?;
        }
    };

    // Phase 3: SELECTION, echoing the provider token.
    let sel = make_selection(&ack, &request_id.to_string());
    ps.publish(
        names::selection_name(&requester, &provider, &service, &request_id),
        sel.encode().as_ref(),
    )
    .await
    .ok()?;

    // Await the RESPONSE (Phase 4).
    loop {
        let pubn = rx.recv().await?;
        if phase_of(&pubn.name) == Some(Phase::Response) && request_id_of(&pubn.name) == request_id {
            return ResponseMessage::decode(pubn.payload).ok().map(|r| r.payload);
        }
    }
}

/// Run the user side honoring a selection `strategy`: publish the REQUEST, gather
/// ACKs (`FirstResponding` stops at the first; `RandomSelection`/`AllSelected`
/// collect over `ack_window`), SELECT the chosen provider(s), and return each
/// selected provider's `(name, response)`. The empty vec means no provider
/// responded in time.
#[allow(clippy::too_many_arguments)]
#[instrument(skip(ps, payload), fields(requester = %requester, service = %service, strategy = ?strategy))]
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
) -> Vec<(Name, Bytes)> {
    let mut rx = ps.subscribe(group_prefix).await;

    // Phase 1: REQUEST carrying the requested strategy.
    let req = RequestMessage {
        request_id: request_id.to_string(),
        user_token: user_token.to_string(),
        payload,
        strategy,
        ..Default::default()
    };
    if ps
        .publish(names::request_name(&requester, &service, &request_id), req.encode().as_ref())
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
                if phase_of(&pubn.name) == Some(Phase::Ack)
                    && request_id_of(&pubn.name) == request_id
                    && let Ok(ack) = AckMessage::decode(pubn.payload)
                {
                    acks.push((before_ndnsf(&pubn.name), ack));
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
        let _ = ps
            .publish(
                names::selection_name(&requester, provider, &service, &request_id),
                sel.encode().as_ref(),
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
                        && let Ok(resp) = ResponseMessage::decode(pubn.payload)
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
pub async fn bootstrap_targeted(
    ps: &SvsPubSub,
    requester: Name,
    provider: Name,
    service: Name,
    request_id: Name,
    group_prefix: Name,
    user_token: &str,
) -> Vec<String> {
    let mut rx = ps.subscribe(group_prefix).await;
    let req = RequestMessage {
        request_id: request_id.to_string(),
        user_token: user_token.to_string(),
        request_mode: RequestMode::TargetedBootstrap,
        target_provider: Some(provider),
        ..Default::default()
    };
    if ps
        .publish(names::request_name(&requester, &service, &request_id), req.encode().as_ref())
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
            return match ResponseMessage::decode(pubn.payload) {
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
) -> Option<Bytes> {
    let mut rx = ps.subscribe(group_prefix).await;
    let req = RequestMessage {
        request_id: request_id.to_string(),
        user_token: user_token.to_string(),
        payload,
        request_mode: RequestMode::Targeted,
        target_provider: Some(provider),
        provider_token: provider_token.to_string(),
        ..Default::default()
    };
    ps.publish(names::request_name(&requester, &service, &request_id), req.encode().as_ref())
        .await
        .ok()?;
    loop {
        let pubn = rx.recv().await?;
        if phase_of(&pubn.name) == Some(Phase::Response) && request_id_of(&pubn.name) == request_id {
            return ResponseMessage::decode(pubn.payload).ok().map(|r| r.payload);
        }
    }
}
