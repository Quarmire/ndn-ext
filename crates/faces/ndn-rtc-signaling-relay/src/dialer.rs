//! Peer-side dialer: posts an SDP offer to the relay, long-polls for the
//! matching answer via [`WebRtcConnector`], and yields a [`WebRtcFace`].
//!
//! The symmetric counterpart to [`WebRtcListener`](crate::WebRtcListener):
//! `connect_one` is to the offerer what `accept_one` is to the answerer.

use std::time::Duration;

use ndn_face_webrtc::{IceServers, WebRtcConnector, WebRtcError, WebRtcFace};

use crate::{ClientError, RelayClient};

#[derive(Debug, thiserror::Error)]
pub enum DialerError {
    #[error("relay client: {0}")]
    Client(#[from] ClientError),
    #[error("connector: {0}")]
    Connector(WebRtcError),
}

impl From<WebRtcError> for DialerError {
    fn from(e: WebRtcError) -> Self {
        DialerError::Connector(e)
    }
}

/// Dialer; callers allocate session ids out of band (HTTP path, query
/// string, etc.) — discovery is intentionally not NDN-native here.
pub struct WebRtcDialer {
    base: String,
    servers: IceServers,
}

impl WebRtcDialer {
    pub fn new(base_url: impl Into<String>, servers: IceServers) -> Self {
        Self {
            base: base_url.into(),
            servers,
        }
    }

    /// Post an offer, long-poll for the answer, complete the SDP/ICE
    /// handshake, and return the live face once SCTP is up. Errors with
    /// `Timeout` after `wait`. Symmetric to
    /// [`WebRtcListener::accept_one`](crate::WebRtcListener::accept_one).
    pub async fn connect_one(
        &self,
        session_id: &str,
        wait: Duration,
    ) -> Result<WebRtcFace, DialerError> {
        let client = RelayClient::new(self.base.clone(), session_id.to_string());
        let connector = WebRtcConnector::new(self.servers.clone())?;

        // Build the peer connection + datachannel, generate the offer, and
        // publish it for the answerer to pick up.
        let (offer, pending) = connector.create_offer().await?;
        client.post_offer(&offer).await?;

        // Each GET caps at the server's 30s long-poll; retry until `wait`.
        let deadline = tokio::time::Instant::now() + wait;
        let answer = loop {
            match client.get_answer().await {
                Ok(a) => break a,
                Err(ClientError::Timeout) => {
                    if tokio::time::Instant::now() >= deadline {
                        return Err(DialerError::Client(ClientError::Timeout));
                    }
                    continue;
                }
                Err(e) => return Err(DialerError::Client(e)),
            }
        };

        let face = connector.finalize_with_answer(pending, answer).await?;
        Ok(face)
    }
}
