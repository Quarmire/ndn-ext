//! `NdnsfCarrier` — the four-phase [`Carrier`] over the NDNSF `driver` (feature
//! `driver`).
//!
//! Proves the service seam (service-layer §12) is transport-independent: the same
//! `#[ndn_service]` definition that runs over Tier-0 `RpcCarrier` runs here over
//! the NDNSF four-phase (REQUEST→ACK→SELECTION→RESPONSE on SVS pub/sub), with no
//! change to the service. Because the four-phase reaches **many** providers and
//! selects among them, this carrier also implements [`SelectCarrier`].
//!
//! Op routing: the four-phase service name is the [`ServiceId`] prefix; the `OpId`
//! and request travel in the request payload envelope (the four-phase payload is
//! opaque, so unlike `RpcCarrier`'s name-component op this carrier frames it),
//! and the response payload carries a status byte so an unknown op / handler
//! error round-trips as a typed [`ServiceError`] rather than a timeout.
//!
//! Trust: built unsigned by default; `.signed(signer, validator)` enables the
//! NSF-A3 message trust the four-phase driver already enforces.

use portable_atomic::AtomicU64;
use std::sync::Mutex;
use std::sync::atomic::Ordering;
use std::time::Duration;

use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use ndn_packet::Name;
use ndn_security::{Signer, Validator};
use ndn_service_core::{
    Carrier, Dispatch, Invocation, Metadata, OpId, Response, SelectCarrier, ServiceError,
    ServiceId, Strategy as CoreStrategy, framing,
};
use ndn_sync::SvsPubSub;
use std::sync::Arc;
use tokio::task::JoinHandle;

use crate::driver::{self, AsyncResponder};
use crate::messages::Strategy as NdnsfStrategy;
use crate::policy::{ProviderAuthorizer, ServicePolicy};
use crate::trust::TrustCtx;

const DEFAULT_TTL_SECS: u64 = 3600;
const DEFAULT_ACK_WINDOW: Duration = Duration::from_secs(3);

// Response status bytes in the payload envelope.
const STATUS_OK: u8 = 0;
const STATUS_NOT_FOUND: u8 = 1;
const STATUS_ERROR: u8 = 2;

/// A four-phase service carrier: a node that invokes (broadcast → select → fetch)
/// and serves (REQUEST→ACK, SELECTION→RESPONSE) over one SVS group.
///
/// ## Provider authorization (red-team SEC-05)
///
/// With a validator configured, an inbound ACK/RESPONSE is verified to be **signed
/// by the provider that claims it** — a member cannot answer "as" another. But the
/// flow does **not** check whether that provider is *authorized to serve this
/// service*: any trusted group member can ACK, and the client may select it
/// (`FirstResponding` takes whoever ACKs first). In the current TrustContext model
/// **group membership is the provider authorization** — every member is a peer that
/// may serve. A finer per-service allow-list exists in `policy::ServicePolicy`
/// (its `providers` set) but is **not yet enforced** on the client's ACK-acceptance
/// path; wiring it there (reject an ACK whose signer isn't in the service's
/// allowed-providers set, before selecting) is the place to add per-service
/// provider authorization. Until then, do not run mutually-distrusting providers in
/// one group expecting service-level isolation.
pub struct NdnsfCarrier {
    ps: Arc<SvsPubSub>,
    node: Name,
    group: Name,
    ttl_secs: u64,
    ack_window: Duration,
    user_token: String,
    trust: TrustCtx,
    /// When set, refuse an ACK from a provider the policy does not authorize for
    /// the invoked service (per-service provider authorization). `None` ⇒ any
    /// group member whose ACK verifies may serve (the legacy posture).
    authorizer: Option<Arc<ProviderAuthorizer>>,
    next_id: AtomicU64,
    serving: Mutex<Vec<JoinHandle<()>>>,
}

impl NdnsfCarrier {
    /// A carrier for `node` on sync `group`, owning `ps`. Empty token, default TTL
    /// / ACK window until configured.
    ///
    /// **Secure by default:** until [`signed`](Self::signed) is called the carrier
    /// has no validator and *rejects* inbound four-phase messages (fail closed). To
    /// run an explicitly unauthenticated, public deployment, call
    /// [`insecure`](Self::insecure) (red-team SEC-02).
    pub fn new(ps: SvsPubSub, node: Name, group: Name) -> Self {
        Self {
            ps: Arc::new(ps),
            node,
            group,
            ttl_secs: DEFAULT_TTL_SECS,
            ack_window: DEFAULT_ACK_WINDOW,
            user_token: String::new(),
            trust: TrustCtx::default(),
            authorizer: None,
            next_id: AtomicU64::new(1),
            serving: Mutex::new(Vec::new()),
        }
    }

    /// Set the provider pending-token TTL (seconds).
    pub fn ttl(mut self, secs: u64) -> Self {
        self.ttl_secs = secs;
        self
    }

    /// Set the ACK/response collection window for invocations.
    pub fn ack_window(mut self, window: Duration) -> Self {
        self.ack_window = window;
        self
    }

    /// Set the user capability token presented on each request.
    pub fn token(mut self, token: impl Into<String>) -> Self {
        self.user_token = token.into();
        self
    }

    /// Sign outbound messages and verify inbound ones (NSF-A3 trust half).
    pub fn signed(mut self, signer: Arc<dyn Signer>, validator: Arc<Validator>) -> Self {
        self.trust = TrustCtx::new(signer, validator);
        self
    }

    /// **Explicitly** run unauthenticated: publish raw and accept inbound without
    /// verifying. Only for a genuinely public, unsigned deployment — any
    /// participant on the shared medium can then impersonate any requester
    /// (red-team SEC-02). Prefer [`signed`](Self::signed).
    pub fn insecure(mut self) -> Self {
        self.trust = TrustCtx::insecure();
        self
    }

    /// Enforce per-service **provider authorization** from `policy`: on invocation,
    /// an ACK from a provider the policy does not list for the invoked service is
    /// refused before it can be selected — so a trusted-but-unauthorized group
    /// member cannot serve (closes the SEC-05 gap where group membership was the
    /// only provider authorization). Pair with [`signed`](Self::signed) so provider
    /// identities are authenticated; under [`insecure`](Self::insecure) the names
    /// are spoofable and this check is best-effort. Shorthand for
    /// [`authorize`](Self::authorize) built from a [`ServicePolicy`](crate::policy::ServicePolicy).
    pub fn with_provider_policy(self, policy: &ServicePolicy) -> Self {
        self.authorize(ProviderAuthorizer::from_policy(policy))
    }

    /// Enforce provider authorization from a pre-compiled [`ProviderAuthorizer`]
    /// (e.g. one shared across carriers). See [`with_provider_policy`](Self::with_provider_policy).
    pub fn authorize(mut self, authorizer: ProviderAuthorizer) -> Self {
        self.authorizer = Some(Arc::new(authorizer));
        self
    }

    fn next_request_id(&self) -> Name {
        let n = self.next_id.fetch_add(1, Ordering::Relaxed);
        format!("/r{n}")
            .parse()
            .expect("request id is a valid name")
    }
}

impl Drop for NdnsfCarrier {
    fn drop(&mut self) {
        if let Ok(mut tasks) = self.serving.lock() {
            for handle in tasks.drain(..) {
                handle.abort();
            }
        }
    }
}

/// Frame `op` + `payload` into the four-phase request payload.
fn encode_request(op: &OpId, payload: &[u8]) -> Bytes {
    let op = op.as_str().as_bytes();
    let mut buf = BytesMut::with_capacity(4 + op.len() + payload.len());
    buf.put_u32_le(op.len() as u32);
    buf.put_slice(op);
    buf.put_slice(payload);
    buf.freeze()
}

/// Inverse of [`encode_request`]; `None` on a malformed envelope.
fn decode_request(bytes: &[u8]) -> Option<(OpId, Bytes)> {
    if bytes.len() < 4 {
        return None;
    }
    let n = u32::from_le_bytes(bytes[0..4].try_into().ok()?) as usize;
    if bytes.len() < 4 + n {
        return None;
    }
    let op = OpId::new(String::from_utf8_lossy(&bytes[4..4 + n]).into_owned());
    Some((op, Bytes::copy_from_slice(&bytes[4 + n..])))
}

/// Frame a response with its status byte.
fn encode_response(status: u8, payload: &[u8]) -> Bytes {
    let mut buf = BytesMut::with_capacity(1 + payload.len());
    buf.put_u8(status);
    buf.put_slice(payload);
    buf.freeze()
}

/// Decode a four-phase response payload into a [`Response`] (status `OK`) or the
/// corresponding [`ServiceError`].
fn decode_response(producer: Name, bytes: Bytes) -> Result<Response, ServiceError> {
    let Some((&status, payload)) = bytes.split_first() else {
        return Err(ServiceError::Transport("empty response payload".into()));
    };
    match status {
        STATUS_OK => {
            // The OK body is a metadata+payload envelope: recover the reflected slot.
            let (metadata, payload) = framing::decode_envelope(&bytes.slice(1..))?;
            Ok(Response {
                producer,
                payload,
                metadata,
            })
        }
        STATUS_NOT_FOUND => Err(ServiceError::NotFound),
        _ => Err(ServiceError::Handler(
            String::from_utf8_lossy(payload).into_owned(),
        )),
    }
}

/// Wrap a [`Dispatch`] as the four-phase async responder: decode the op envelope,
/// dispatch, and frame the reply with its status byte.
fn responder_for(dispatch: Arc<dyn Dispatch>) -> AsyncResponder {
    Arc::new(move |coord, payload: Bytes| {
        let dispatch = dispatch.clone();
        // The four-phase flow already verified the requester (the trust gate checks
        // the signer against the coordination's requester before the token is
        // consumed), so hand the handler that identity for its access decisions.
        // NOTE: meaningful only when the carrier has a validator configured; with a
        // default-open `TrustCtx` this identity is unauthenticated (red-team SEC-02).
        let requester = Some(coord.requester.clone());
        Box::pin(async move {
            let Some((op, body)) = decode_request(&payload) else {
                return encode_response(STATUS_ERROR, b"malformed request envelope");
            };
            // Recover the opaque metadata slot the client set (a trace context, etc.).
            let Ok((metadata, request)) = framing::decode_envelope(&body) else {
                return encode_response(STATUS_ERROR, b"malformed metadata envelope");
            };
            let inv = Invocation {
                op,
                request,
                requester,
                metadata: metadata.clone(),
            };
            match dispatch.dispatch(inv).await {
                // Reflect the request's slot onto the response beside the reply.
                Ok(reply) => {
                    encode_response(STATUS_OK, &framing::encode_envelope(&metadata, &reply))
                }
                Err(ServiceError::NotFound) => encode_response(STATUS_NOT_FOUND, b""),
                Err(e) => encode_response(STATUS_ERROR, e.to_string().as_bytes()),
            }
        })
    })
}

fn map_strategy(s: CoreStrategy) -> NdnsfStrategy {
    match s {
        CoreStrategy::FirstResponding => NdnsfStrategy::FirstResponding,
        CoreStrategy::Random => NdnsfStrategy::RandomSelection,
        CoreStrategy::All => NdnsfStrategy::AllSelected,
    }
}

#[async_trait]
impl Carrier for NdnsfCarrier {
    async fn invoke_meta(
        &self,
        svc: &ServiceId,
        op: &OpId,
        request: Bytes,
        metadata: Metadata,
    ) -> Result<Response, ServiceError> {
        // The opaque metadata slot rides beside the request inside the four-phase
        // op envelope, transported verbatim to the provider and reflected back.
        let payload = encode_request(op, &framing::encode_envelope(&metadata, &request));
        let raw = driver::select_and_call(
            self.ps.as_ref(),
            self.node.clone(),
            svc.name().clone(),
            self.next_request_id(),
            self.group.clone(),
            payload,
            &self.user_token,
            NdnsfStrategy::FirstResponding,
            self.ack_window,
            &self.trust,
            self.authorizer.as_deref(),
        )
        .await;
        match raw.into_iter().next() {
            Some((producer, bytes)) => decode_response(producer, bytes),
            None => Err(ServiceError::NotFound),
        }
    }

    async fn serve(
        &self,
        svc: &ServiceId,
        dispatch: Arc<dyn Dispatch>,
    ) -> Result<(), ServiceError> {
        let ps = self.ps.clone();
        let node = self.node.clone();
        let service = svc.name().clone();
        let group = self.group.clone();
        let ttl = self.ttl_secs;
        let trust = self.trust.clone();
        let responder = responder_for(dispatch);
        let handle = tokio::spawn(async move {
            driver::serve_provider_async(ps, node, service, group, ttl, &trust, responder).await;
        });
        self.serving.lock().expect("serve lock").push(handle);
        Ok(())
    }
}

#[async_trait]
impl SelectCarrier for NdnsfCarrier {
    async fn invoke_select_meta(
        &self,
        svc: &ServiceId,
        op: &OpId,
        request: Bytes,
        strategy: CoreStrategy,
        metadata: Metadata,
    ) -> Result<Vec<Response>, ServiceError> {
        let payload = encode_request(op, &framing::encode_envelope(&metadata, &request));
        let raw = driver::select_and_call(
            self.ps.as_ref(),
            self.node.clone(),
            svc.name().clone(),
            self.next_request_id(),
            self.group.clone(),
            payload,
            &self.user_token,
            map_strategy(strategy),
            self.ack_window,
            &self.trust,
            self.authorizer.as_deref(),
        )
        .await;
        // Keep the successful responses; a provider that can't serve the op
        // contributes an error envelope, which is dropped from the selection set.
        Ok(raw
            .into_iter()
            .filter_map(|(producer, bytes)| decode_response(producer, bytes).ok())
            .collect())
    }
}
