//! Forwarder-side listener: polls the relay for incoming SDP offers,
//! accepts them via [`WebRtcConnector`], and yields [`WebRtcFace`]s.

use std::time::Duration;

use ndn_face_webrtc::{IceServers, WebRtcConnector, WebRtcError, WebRtcFace};

use crate::{ClientError, RelayClient};

#[derive(Debug, thiserror::Error)]
pub enum ListenerError {
    #[error("relay client: {0}")]
    Client(#[from] ClientError),
    #[error("connector: {0}")]
    Connector(WebRtcError),
}

impl From<WebRtcError> for ListenerError {
    fn from(e: WebRtcError) -> Self {
        ListenerError::Connector(e)
    }
}

/// Listener; callers allocate session ids out of band (HTTP path, query
/// string, etc.) — discovery is intentionally not NDN-native here.
pub struct WebRtcListener {
    base: String,
    servers: IceServers,
}

impl WebRtcListener {
    pub fn new(base_url: impl Into<String>, servers: IceServers) -> Self {
        Self {
            base: base_url.into(),
            servers,
        }
    }

    /// Long-poll for an offer, complete the SDP/ICE handshake, and return
    /// the live face once SCTP is up. Errors with `Timeout` after `wait`.
    pub async fn accept_one(
        &self,
        session_id: &str,
        wait: Duration,
    ) -> Result<WebRtcFace, ListenerError> {
        let client = RelayClient::new(self.base.clone(), session_id.to_string());
        let connector = WebRtcConnector::new(self.servers.clone())?;

        // Each GET caps at the server's 30s long-poll; retry until `wait`.
        let deadline = tokio::time::Instant::now() + wait;
        let offer = loop {
            match client.get_offer().await {
                Ok(o) => break o,
                Err(ClientError::Timeout) => {
                    if tokio::time::Instant::now() >= deadline {
                        return Err(ListenerError::Client(ClientError::Timeout));
                    }
                    continue;
                }
                Err(e) => return Err(ListenerError::Client(e)),
            }
        };

        let (answer, pending) = connector.accept_offer(offer).await?;
        client.post_answer(&answer).await?;
        let face = connector.finalize_pending(pending).await?;
        Ok(face)
    }
}
