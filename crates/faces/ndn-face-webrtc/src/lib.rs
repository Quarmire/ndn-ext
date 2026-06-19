//! WebRTC datachannel face — peer-to-peer NDN transport.
//!
//! Each [`WebRtcFace`] owns one reliable, ordered SCTP datachannel over a
//! single `RTCPeerConnection` (native via `webrtc-rs`, wasm via `web_sys`).
//! The [`RtcChannel`] trait abstracts the platform split so the face
//! implementation is shared.
//!
//! Signaling helpers live in [`signaling`]. [`signaling::manual`] does
//! base64-encoded SDP+ICE blobs for manual paste-in rendezvous. An HTTP-relay
//! helper and NDN-native signaling (`/<peer>/rtc-offer` over an existing face)
//! are deferred — the latter assumes a discovery face exists, which is what
//! this transport itself bootstraps.
//!
//! WebRTC encrypts every datachannel via DTLS using an ephemeral self-signed
//! keypair. NDN-level trust is layered on top: every Data carries a signature
//! that chains to a configured trust anchor. This crate does not bind WebRTC's
//! DTLS fingerprint to NDN identity.

#![allow(missing_docs)]

use serde::{Deserialize, Serialize};

pub mod signaling;

#[cfg(not(target_arch = "wasm32"))]
mod native;
#[cfg(not(target_arch = "wasm32"))]
pub use native::{NativeRtcChannel, WebRtcConnector, WebRtcFace};

#[cfg(target_arch = "wasm32")]
mod wasm;
#[cfg(target_arch = "wasm32")]
pub use wasm::{PendingFace, WasmRtcChannel, WebRtcConnector, WebRtcFace};

/// Errors returned from a WebRTC face / connector.
#[derive(Debug, thiserror::Error)]
pub enum WebRtcError {
    #[error("signaling error: {0}")]
    Signaling(String),
    #[error("peer-connection error: {0}")]
    PeerConnection(String),
    #[error("datachannel error: {0}")]
    DataChannel(String),
    #[error("datachannel closed")]
    Closed,
    #[error("invalid SDP/ICE blob: {0}")]
    InvalidBlob(String),
}

/// One reliable, ordered SCTP/DTLS datachannel between two peers.
///
/// Native (`webrtc-rs`) impls are `Send + Sync`; wasm32 is single-threaded
/// and `web_sys` types are `!Send`, so bounds relax to `'static` only there.
#[cfg(not(target_arch = "wasm32"))]
#[async_trait::async_trait]
pub trait RtcChannel: Send + Sync + 'static {
    async fn send(&self, bytes: bytes::Bytes) -> Result<(), WebRtcError>;
    async fn recv(&self) -> Result<bytes::Bytes, WebRtcError>;
    fn is_open(&self) -> bool;
}

#[cfg(target_arch = "wasm32")]
#[async_trait::async_trait(?Send)]
pub trait RtcChannel: 'static {
    async fn send(&self, bytes: bytes::Bytes) -> Result<(), WebRtcError>;
    async fn recv(&self) -> Result<bytes::Bytes, WebRtcError>;
    fn is_open(&self) -> bool;
}

/// SDP offer or answer, transported as a serializable blob.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionDescription {
    /// SDP type (`"offer"` or `"answer"`).
    #[serde(rename = "type")]
    pub kind: String,
    pub sdp: String,
}

/// Trickle-ICE candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IceCandidate {
    pub candidate: String,
    #[serde(default)]
    pub sdp_mid: Option<String>,
    #[serde(default)]
    pub sdp_m_line_index: Option<u16>,
}

/// STUN / TURN configuration. TURN is opt-in (requires operator credentials).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IceServers {
    pub stun: Vec<String>,
    #[serde(default)]
    pub turn: Vec<TurnServer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TurnServer {
    pub url: String,
    pub username: String,
    pub credential: String,
}

impl Default for IceServers {
    fn default() -> Self {
        Self {
            stun: vec![
                "stun:stun.l.google.com:19302".into(),
                "stun:stun1.l.google.com:19302".into(),
            ],
            turn: Vec::new(),
        }
    }
}
