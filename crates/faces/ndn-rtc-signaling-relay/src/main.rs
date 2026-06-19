//! `ndn-rtc-signaling-relay` — standalone HTTP rendezvous server
//! for `ndn-face-webrtc`.
//!
//! Usage:
//!
//! ```text
//! ndn-rtc-signaling-relay [--bind 0.0.0.0:8888]
//! ```
//!
//! See the crate-level docs (`lib.rs`) for the wire shape.

use std::net::SocketAddr;

use ndn_rtc_signaling_relay::RelayServer;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let bind = std::env::args()
        .nth(1)
        .map(|s| s.trim_start_matches("--bind=").to_string())
        .unwrap_or_else(|| "0.0.0.0:8888".to_string());
    let addr: SocketAddr = bind.parse().expect("invalid --bind address");

    let (bound, fut) = RelayServer::serve(addr).await?;
    tracing::info!(target: "rtc.relay", %bound, "ready — POST /rendezvous/<id>/{{offer,answer,candidate}}");

    fut.await?;
    Ok(())
}
