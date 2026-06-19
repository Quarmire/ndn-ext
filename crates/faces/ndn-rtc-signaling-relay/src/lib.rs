//! HTTP signaling relay — one-shot SDP/ICE rendezvous for
//! `ndn-face-webrtc`. Anyone with the session id can read both blobs, so
//! treat SDPs as public; NDN signatures still cover the resulting
//! datachannel.
//!
//! ## Wire shape (per session-id `<id>`)
//!
//! - `POST /rendezvous/<id>/offer`   — body = JSON `SessionDescription`
//! - `GET  /rendezvous/<id>/offer`   — long-poll; 200 or 408
//! - `POST /rendezvous/<id>/answer`  — body = JSON `SessionDescription`
//! - `GET  /rendezvous/<id>/answer`  — long-poll; 200 or 408
//! - `POST /rendezvous/<id>/candidate?role=offerer|answerer`
//! - `GET  /rendezvous/<id>/candidate?role=offerer|answerer`
//!   drains queued candidates from the *other* role
//!
//! Sessions are created on first POST and dropped after both sides have
//! consumed each other's blobs; no persistence.

pub mod client;
pub mod listener;
pub mod server;

pub use client::{ClientError, RelayClient};
pub use listener::{ListenerError, WebRtcListener};
pub use server::{RelayServer, ServerError};

/// Disambiguates the two halves of a rendezvous for the trickle-candidate stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Offerer,
    Answerer,
}
