//! WebRTC binding for the remote-signer transport.
//!
//! Adapts an [`ndn-face-webrtc`](ndn_face_webrtc) datachannel into a
//! [`ChannelRemoteSigner`] (from [`ndn-custodian`](ndn_custodian)) and drives
//! the HTTP signaling relay to pair with a phone fob over the internet — the
//! concrete v1 transport for the dashboard's phone-as-signer second factor.
//!
//! **Native-only.** The relay client and the native `WebRtcConnector` are not
//! built for wasm32, and the wasm `RtcChannel` is `?Send` (it can't back a
//! `Send + Sync` `RemoteSignerTransport`). The wasm/PWA fob is a later phase.
//!
//! The byte-channel framing + sign-delegation loop is unit-tested in
//! `ndn-custodian` against an in-memory channel; here, [`WebRtcSignerChannel`]
//! and [`connect_fob_via_relay`] are **compile-verified** — the live
//! offer/answer/datachannel path needs a real phone peer and a running relay to
//! exercise. The handshake mirrors the proven `ndn-rtc-signaling-relay`
//! native-via-relay witness. Full design + security model:
//! `.claude/notes/remote-fob-design-2026-06-01.md`.

// `CustodianError` is intentionally large (carries a `Name`); it opts out of
// `large_enum_variant`, so fallible fns here opt out of the matching lint.
#![allow(clippy::result_large_err)]

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use ndn_security::custodian::{ChannelRemoteSigner, CustodianError, SignerChannel};
use ndn_face_webrtc::{IceServers, RtcChannel, WebRtcConnector, WebRtcError};
use ndn_rtc_signaling_relay::{ClientError, RelayClient};

/// Wraps an `ndn-face-webrtc` datachannel as a [`SignerChannel`], so the
/// transport-agnostic [`ChannelRemoteSigner`] can frame the remote-signer
/// protocol over it.
pub struct WebRtcSignerChannel {
    channel: Arc<dyn RtcChannel>,
}

impl WebRtcSignerChannel {
    pub fn new(channel: Arc<dyn RtcChannel>) -> Self {
        Self { channel }
    }
}

#[async_trait]
impl SignerChannel for WebRtcSignerChannel {
    async fn send(&self, frame: Bytes) -> Result<(), CustodianError> {
        self.channel
            .send(frame)
            .await
            .map_err(|e| CustodianError::SignFailed(format!("datachannel send: {e:?}")))
    }

    async fn recv(&self) -> Result<Bytes, CustodianError> {
        self.channel
            .recv()
            .await
            .map_err(|e| CustodianError::SignFailed(format!("datachannel recv: {e:?}")))
    }

    fn is_open(&self) -> bool {
        self.channel.is_open()
    }
}

/// Connect to a phone fob as the WebRTC **offerer**, signalling through the HTTP
/// relay at `relay_base_url`, and return a transport ready to delegate
/// signatures over the resulting datachannel.
///
/// The phone joins the same `session_id` on the relay as the answerer, pairs,
/// and thereafter gates each signature with on-device biometric. This drives
/// the offer/answer dance proven by the `ndn-rtc-signaling-relay` witness; it
/// is compile-verified here and needs a live phone peer to run end to end.
pub async fn connect_fob_via_relay(
    relay_base_url: impl Into<String>,
    session_id: impl Into<String>,
    ice: IceServers,
) -> Result<ChannelRemoteSigner<WebRtcSignerChannel>, CustodianError> {
    let connector = WebRtcConnector::new(ice).map_err(webrtc_err)?;
    let relay = RelayClient::new(relay_base_url, session_id);

    //   dashboard (offerer)              relay                    phone (answerer)
    //     │  POST /<id>/offer  ────────►                                  │
    //     │                              ◄──── GET /<id>/offer            │
    //     │                              ◄──── POST /<id>/answer          │
    //     │  GET /<id>/answer ─────────►                                  │
    //     │ ◄────────────  DTLS / SCTP datachannel  ────────────────────► │
    let (offer, pending) = connector.create_offer().await.map_err(webrtc_err)?;
    relay.post_offer(&offer).await.map_err(relay_err)?;
    let answer = relay.get_answer().await.map_err(relay_err)?;
    let face = connector
        .finalize_with_answer(pending, answer)
        .await
        .map_err(webrtc_err)?;

    let channel: Arc<dyn RtcChannel> = face.channel();
    Ok(ChannelRemoteSigner::new(WebRtcSignerChannel::new(channel)))
}

fn webrtc_err(e: WebRtcError) -> CustodianError {
    CustodianError::SignFailed(format!("webrtc: {e:?}"))
}

fn relay_err(e: ClientError) -> CustodianError {
    CustodianError::SignFailed(format!("relay: {e:?}"))
}
