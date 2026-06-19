//! Ergonomic role wrappers (feature `driver`) — spec §11.2 mode 1 (closures).
//!
//! [`ServiceProvider`] and [`ServiceUser`] bundle the four-phase fields that are
//! *stable* for a participant (its `SvsPubSub`, identity, the `service` it speaks
//! and the sync `group`, its [`TrustCtx`]) so a call site supplies only what
//! *varies* per call (a target provider, a payload). This is the typed analogue
//! of NDNSF's `@provider.handler` decorator: the same protocol as [`crate::driver`],
//! without the long positional argument lists.
//!
//! ```no_run
//! # use ndn_ndnsf::roles::{ServiceProvider, ServiceUser};
//! # use ndn_sync::SvsPubSub;
//! # use ndn_packet::Name;
//! # use bytes::Bytes;
//! # async fn demo(provider_ps: SvsPubSub, user_ps: SvsPubSub) {
//! # let svc: Name = "/svc/echo".parse().unwrap();
//! # let group: Name = "/muas".parse().unwrap();
//! // Provider: one closure handles every coordination.
//! let provider = ServiceProvider::new(provider_ps, "/muas/bob".parse().unwrap(), svc.clone(), group.clone());
//! tokio::spawn(async move {
//!     provider.serve(|_coord, req| Bytes::copy_from_slice(req)).await; // echo
//! });
//!
//! // User: one method per call, request ids auto-assigned.
//! let user = ServiceUser::new(user_ps, "/muas/alice".parse().unwrap(), svc, group).token("utok");
//! let reply = user.call("/muas/bob".parse().unwrap(), Bytes::from_static(b"ping")).await;
//! # }
//! ```

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use ndn_packet::Name;
use ndn_security::{Signer, Validator};
use ndn_sync::SvsPubSub;

use crate::driver;
use crate::messages::Strategy;
use crate::tokens::PendingCoordination;
use crate::trust::TrustCtx;

/// Default provider pending-token TTL when [`ServiceProvider::ttl`] is not set.
const DEFAULT_TTL_SECS: u64 = 3600;

/// A four-phase provider bound to one `service` in one sync `group`. Construct
/// with [`new`](Self::new), optionally [`signed`](Self::signed) for NSF-A3 trust,
/// then [`serve`](Self::serve) a handler closure.
pub struct ServiceProvider {
    ps: SvsPubSub,
    node: Name,
    service: Name,
    group: Name,
    ttl_secs: u64,
    trust: TrustCtx,
}

impl ServiceProvider {
    /// A provider for `service` in `group`, identified by `node`. Unsigned and
    /// using the default token TTL until configured.
    pub fn new(ps: SvsPubSub, node: Name, service: Name, group: Name) -> Self {
        Self {
            ps,
            node,
            service,
            group,
            ttl_secs: DEFAULT_TTL_SECS,
            trust: TrustCtx::default(),
        }
    }

    /// Set the pending-token TTL (seconds).
    pub fn ttl(mut self, secs: u64) -> Self {
        self.ttl_secs = secs;
        self
    }

    /// Sign outbound messages with `signer` and verify inbound ones against
    /// `validator` (the trust half of NSF-A3). Without this, the provider runs
    /// the unsigned fast path.
    pub fn signed(mut self, signer: Arc<dyn Signer>, validator: Arc<Validator>) -> Self {
        self.trust = TrustCtx::new(signer, validator);
        self
    }

    /// Run the provider loop: ACK each request, and on a valid token-bearing
    /// SELECTION (or a Targeted request) run `handler(coordination, request)` and
    /// publish the response. Runs until the subscription closes.
    pub async fn serve<H>(&self, handler: H)
    where
        H: Fn(&PendingCoordination, &Bytes) -> Bytes,
    {
        driver::serve_provider(
            &self.ps,
            self.node.clone(),
            self.service.clone(),
            self.group.clone(),
            self.ttl_secs,
            &self.trust,
            handler,
        )
        .await
    }

    /// Borrow the underlying pub/sub (e.g. to publish or subscribe directly).
    pub fn pubsub(&self) -> &SvsPubSub {
        &self.ps
    }
}

/// A four-phase user bound to one `service` in one sync `group`. Construct with
/// [`new`](Self::new), optionally [`signed`](Self::signed) / [`token`](Self::token),
/// then call. Request ids are auto-assigned per call.
pub struct ServiceUser {
    ps: SvsPubSub,
    requester: Name,
    service: Name,
    group: Name,
    trust: TrustCtx,
    user_token: String,
    next_id: AtomicU64,
}

impl ServiceUser {
    /// A user of `service` in `group`, identified by `requester`. Unsigned, with
    /// an empty user token, until configured.
    pub fn new(ps: SvsPubSub, requester: Name, service: Name, group: Name) -> Self {
        Self {
            ps,
            requester,
            service,
            group,
            trust: TrustCtx::default(),
            user_token: String::new(),
            next_id: AtomicU64::new(1),
        }
    }

    /// Sign outbound messages with `signer` and verify inbound ones against
    /// `validator` (the trust half of NSF-A3).
    pub fn signed(mut self, signer: Arc<dyn Signer>, validator: Arc<Validator>) -> Self {
        self.trust = TrustCtx::new(signer, validator);
        self
    }

    /// Set the user capability token presented on each request.
    pub fn token(mut self, token: impl Into<String>) -> Self {
        self.user_token = token.into();
        self
    }

    /// The next monotonic request id (`/r1`, `/r2`, …).
    fn next_request_id(&self) -> Name {
        let n = self.next_id.fetch_add(1, Ordering::Relaxed);
        format!("/r{n}").parse().expect("request id is a valid name")
    }

    /// Call a specific `provider` (Normal four-phase: REQUEST→ACK→SELECTION→
    /// RESPONSE), returning the response payload (or `None` on timeout/close).
    pub async fn call(&self, provider: Name, payload: Bytes) -> Option<Bytes> {
        driver::call(
            &self.ps,
            self.requester.clone(),
            provider,
            self.service.clone(),
            self.next_request_id(),
            self.group.clone(),
            payload,
            &self.user_token,
            &self.trust,
        )
        .await
    }

    /// Strategy-driven multi-provider call: broadcast the request, gather ACKs
    /// over `ack_window`, select per `strategy`, and return each selected
    /// provider's `(name, response)`.
    pub async fn select_and_call(
        &self,
        payload: Bytes,
        strategy: Strategy,
        ack_window: Duration,
    ) -> Vec<(Name, Bytes)> {
        driver::select_and_call(
            &self.ps,
            self.requester.clone(),
            self.service.clone(),
            self.next_request_id(),
            self.group.clone(),
            payload,
            &self.user_token,
            strategy,
            ack_window,
            &self.trust,
        )
        .await
    }

    /// Targeted bootstrap: obtain a pool of single-use tokens from `provider`.
    pub async fn bootstrap_targeted(&self, provider: Name) -> Vec<String> {
        driver::bootstrap_targeted(
            &self.ps,
            self.requester.clone(),
            provider,
            self.service.clone(),
            self.next_request_id(),
            self.group.clone(),
            &self.user_token,
            &self.trust,
        )
        .await
    }

    /// Targeted call with a pre-issued `provider_token` (direct REQUEST→RESPONSE,
    /// no ACK/SELECTION). `None` if the token is invalid/spent (fail closed).
    pub async fn call_targeted(
        &self,
        provider: Name,
        payload: Bytes,
        provider_token: &str,
    ) -> Option<Bytes> {
        driver::call_targeted(
            &self.ps,
            self.requester.clone(),
            provider,
            self.service.clone(),
            self.next_request_id(),
            self.group.clone(),
            payload,
            &self.user_token,
            provider_token,
            &self.trust,
        )
        .await
    }

    /// Borrow the underlying pub/sub (e.g. to publish or subscribe directly).
    pub fn pubsub(&self) -> &SvsPubSub {
        &self.ps
    }
}
