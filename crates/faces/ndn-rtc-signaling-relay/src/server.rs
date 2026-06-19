//! Axum-based rendezvous server. Sessions are keyed by an opaque string
//! (callers pick collision-free ids, e.g. UUIDs) and freed once both peers
//! have read the other's blob. Long-polls are capped at [`POLL_TIMEOUT`];
//! clients retry on 408.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::post;
use dashmap::DashMap;
use ndn_face_webrtc::{IceCandidate, SessionDescription};
use serde::Deserialize;
use tokio::sync::Notify;
use tracing::{debug, info};

use crate::Role;

const POLL_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("bind: {0}")]
    Bind(String),
    #[error("server: {0}")]
    Serve(String),
}

#[derive(Default)]
struct Session {
    inner: tokio::sync::Mutex<SessionInner>,
    notify: Notify,
}

#[derive(Default)]
struct SessionInner {
    offer: Option<SessionDescription>,
    answer: Option<SessionDescription>,
    offerer_cands: VecDeque<IceCandidate>,
    answerer_cands: VecDeque<IceCandidate>,
}

#[derive(Clone, Default)]
struct AppState {
    sessions: Arc<DashMap<String, Arc<Session>>>,
}

impl AppState {
    fn session(&self, id: &str) -> Arc<Session> {
        self.sessions
            .entry(id.to_string())
            .or_insert_with(|| Arc::new(Session::default()))
            .clone()
    }
}

pub struct RelayServer;

impl RelayServer {
    /// Bind and return `(bound_addr, driving_future)`; drop the future to stop.
    pub async fn serve(
        addr: SocketAddr,
    ) -> Result<
        (
            SocketAddr,
            impl std::future::Future<Output = Result<(), ServerError>>,
        ),
        ServerError,
    > {
        let state = AppState::default();
        let app = Router::new()
            .route("/rendezvous/{id}/offer", post(post_offer).get(get_offer))
            .route("/rendezvous/{id}/answer", post(post_answer).get(get_answer))
            .route(
                "/rendezvous/{id}/candidate",
                post(post_candidate).get(get_candidates),
            )
            .with_state(state);

        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| ServerError::Bind(e.to_string()))?;
        let bound = listener
            .local_addr()
            .map_err(|e| ServerError::Bind(e.to_string()))?;
        info!(target: "rtc.relay", %bound, "ndn-rtc-signaling-relay listening");
        let fut = async move {
            axum::serve(listener, app)
                .await
                .map_err(|e| ServerError::Serve(e.to_string()))
        };
        Ok((bound, fut))
    }
}

async fn post_offer(
    Path(id): Path<String>,
    State(state): State<AppState>,
    axum::Json(blob): axum::Json<SessionDescription>,
) -> impl IntoResponse {
    let session = state.session(&id);
    {
        let mut inner = session.inner.lock().await;
        inner.offer = Some(blob);
    }
    session.notify.notify_waiters();
    debug!(target: "rtc.relay", session=%id, "offer stored");
    StatusCode::OK
}

async fn get_offer(Path(id): Path<String>, State(state): State<AppState>) -> impl IntoResponse {
    let session = state.session(&id);
    poll_for(&session, |inner| inner.offer.clone()).await
}

async fn post_answer(
    Path(id): Path<String>,
    State(state): State<AppState>,
    axum::Json(blob): axum::Json<SessionDescription>,
) -> impl IntoResponse {
    let session = state.session(&id);
    {
        let mut inner = session.inner.lock().await;
        inner.answer = Some(blob);
    }
    session.notify.notify_waiters();
    debug!(target: "rtc.relay", session=%id, "answer stored");
    StatusCode::OK
}

async fn get_answer(Path(id): Path<String>, State(state): State<AppState>) -> impl IntoResponse {
    let session = state.session(&id);
    poll_for(&session, |inner| inner.answer.clone()).await
}

#[derive(Debug, Deserialize)]
struct CandidateQuery {
    role: Role,
}

async fn post_candidate(
    Path(id): Path<String>,
    Query(q): Query<CandidateQuery>,
    State(state): State<AppState>,
    axum::Json(cand): axum::Json<IceCandidate>,
) -> impl IntoResponse {
    let session = state.session(&id);
    {
        let mut inner = session.inner.lock().await;
        match q.role {
            Role::Offerer => inner.offerer_cands.push_back(cand),
            Role::Answerer => inner.answerer_cands.push_back(cand),
        }
    }
    session.notify.notify_waiters();
    StatusCode::OK
}

async fn get_candidates(
    Path(id): Path<String>,
    Query(q): Query<CandidateQuery>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let session = state.session(&id);
    poll_for(&session, |inner| {
        let q = match q.role {
            Role::Offerer => &mut inner.answerer_cands,
            Role::Answerer => &mut inner.offerer_cands,
        };
        if q.is_empty() {
            None
        } else {
            Some(q.drain(..).collect::<Vec<_>>())
        }
    })
    .await
}

/// Long-poll until `select` returns `Some`, bounded by [`POLL_TIMEOUT`].
async fn poll_for<T, F>(session: &Session, mut select: F) -> axum::response::Response
where
    T: serde::Serialize + Clone,
    F: FnMut(&mut SessionInner) -> Option<T>,
{
    let deadline = tokio::time::Instant::now() + POLL_TIMEOUT;
    loop {
        if let Some(v) = select(&mut *session.inner.lock().await) {
            return axum::Json(v).into_response();
        }
        let notified = session.notify.notified();
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return StatusCode::REQUEST_TIMEOUT.into_response();
        }
        if tokio::time::timeout(remaining, notified).await.is_err() {
            return StatusCode::REQUEST_TIMEOUT.into_response();
        }
    }
}
