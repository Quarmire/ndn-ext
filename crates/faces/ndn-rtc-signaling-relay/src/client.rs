//! Reqwest-backed client for the rendezvous server.

use std::time::Duration;

use ndn_face_webrtc::{IceCandidate, SessionDescription};

use crate::Role;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("http: {0}")]
    Http(String),
    #[error("decode: {0}")]
    Decode(String),
    #[error("relay timeout / 408")]
    Timeout,
}

/// Client for [`RelayServer`](crate::RelayServer) over plain HTTP.
pub struct RelayClient {
    base: String,
    session: String,
    http: reqwest::Client,
}

impl RelayClient {
    pub fn new(base_url: impl Into<String>, session_id: impl Into<String>) -> Self {
        Self {
            base: base_url.into(),
            session: session_id.into(),
            // Covers the server's 30s long-poll with headroom.
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(60))
                .build()
                .expect("reqwest client"),
        }
    }

    pub async fn post_offer(&self, offer: &SessionDescription) -> Result<(), ClientError> {
        self.http
            .post(self.url("offer"))
            .json(offer)
            .send()
            .await
            .map_err(|e| ClientError::Http(e.to_string()))?
            .error_for_status()
            .map_err(|e| ClientError::Http(e.to_string()))?;
        Ok(())
    }

    pub async fn get_offer(&self) -> Result<SessionDescription, ClientError> {
        self.poll_json(self.url("offer")).await
    }

    pub async fn post_answer(&self, answer: &SessionDescription) -> Result<(), ClientError> {
        self.http
            .post(self.url("answer"))
            .json(answer)
            .send()
            .await
            .map_err(|e| ClientError::Http(e.to_string()))?
            .error_for_status()
            .map_err(|e| ClientError::Http(e.to_string()))?;
        Ok(())
    }

    pub async fn get_answer(&self) -> Result<SessionDescription, ClientError> {
        self.poll_json(self.url("answer")).await
    }

    pub async fn post_candidate(&self, role: Role, cand: &IceCandidate) -> Result<(), ClientError> {
        let role_s = match role {
            Role::Offerer => "offerer",
            Role::Answerer => "answerer",
        };
        let url = format!("{}?role={role_s}", self.url("candidate"));
        self.http
            .post(url)
            .json(cand)
            .send()
            .await
            .map_err(|e| ClientError::Http(e.to_string()))?
            .error_for_status()
            .map_err(|e| ClientError::Http(e.to_string()))?;
        Ok(())
    }

    pub async fn drain_candidates(&self, role: Role) -> Result<Vec<IceCandidate>, ClientError> {
        let role_s = match role {
            Role::Offerer => "offerer",
            Role::Answerer => "answerer",
        };
        let url = format!("{}?role={role_s}", self.url("candidate"));
        self.poll_json(url).await
    }

    fn url(&self, leaf: &str) -> String {
        format!("{}/rendezvous/{}/{leaf}", self.base, self.session)
    }

    async fn poll_json<T: serde::de::DeserializeOwned>(
        &self,
        url: String,
    ) -> Result<T, ClientError> {
        let resp = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|e| ClientError::Http(e.to_string()))?;
        if resp.status() == reqwest::StatusCode::REQUEST_TIMEOUT {
            return Err(ClientError::Timeout);
        }
        let resp = resp
            .error_for_status()
            .map_err(|e| ClientError::Http(e.to_string()))?;
        resp.json::<T>()
            .await
            .map_err(|e| ClientError::Decode(e.to_string()))
    }
}
