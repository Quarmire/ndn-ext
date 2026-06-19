//! `ManagementClient` — the UI-agnostic seam to an NFD-compatible forwarder.
//!
//! Everything a UI does to a forwarder is an NDN management command:
//! `/localhost/nfd/<module>/<verb>` carrying optional `ControlParameters`. This
//! trait is that one operation. Concrete impls ride a WebSocket (web), a
//! Unix-socket client (desktop), or a mobile IPC face — so a single
//! `DashboardEngine` can drive any forwarder over any transport.
//!
//! `?Send`: the browser transport's futures are `!Send` (the `gloo` WebSocket /
//! JS handles aren't `Send`); native impls are free to be `Send`. The engine
//! that drives this therefore runs on a `!Send`-tolerant executor (a `LocalSet`
//! / the Dioxus runtime), never bare `tokio::spawn`.

use async_trait::async_trait;
use bytes::Bytes;
use ndn_config::ControlParameters;

/// A management command/dataset response. For control verbs `status_code` /
/// `status_text` come from the `ControlResponse` envelope; for dataset verbs
/// the caller synthesises `status_code = 200` and the reassembled payload is in
/// `body`.
#[derive(Debug, Clone)]
pub struct MgmtResponse {
    pub status_code: u64,
    pub status_text: String,
    pub body: Bytes,
}

impl MgmtResponse {
    pub fn is_ok(&self) -> bool {
        (200..300).contains(&self.status_code)
    }
}

/// Send one `/localhost/nfd/<module>/<verb>` command (optionally with
/// `ControlParameters`) and return the response. The implementation owns
/// signing (the operator keyring) and transport details.
#[async_trait(?Send)]
pub trait ManagementClient {
    async fn send_cmd(
        &mut self,
        module: &str,
        verb: &str,
        params: Option<&ControlParameters>,
    ) -> Result<MgmtResponse, String>;
}
