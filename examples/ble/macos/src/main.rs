//! macOS BLE peripheral test — verifies `BleFace` end-to-end.
//!
//! Starts a BLE GATT peripheral using the NDNts-compatible service UUID,
//! advertises, and responds to Interests under `/ndn/ble/test` with a
//! timestamped greeting.
//!
//! # Running
//!
//! ```sh
//! cargo run -p example-ble-macos
//! ```
//!
//! Then connect from an Android or iOS BLE test app, send an Interest for
//! `/ndn/ble/test`, and verify the Data response.

use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use ndn_app::EngineAppExt;
use ndn_engine::{EngineBuilder, EngineConfig};
use ndn_face_bluetooth::BleListener;
use ndn_packet::Name;
use ndn_packet::encode::DataBuilder;
use ndn_security::SecurityProfile;
use ndn_transport::FacePersistency;
use tokio_util::sync::CancellationToken;
use tracing::info;

const PREFIX: &str = "/ndn/ble/test";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("info".parse().unwrap()),
        )
        .init();

    let cancel = CancellationToken::new();

    // ── Build engine ─────────────────────────────────────────────────────
    let config = EngineConfig {
        pipeline_threads: 1,
        ..EngineConfig::default()
    };
    let builder = EngineBuilder::new(config).security_profile(SecurityProfile::Disabled);
    let (engine, _shutdown) = builder.build().await?;

    // ── Start BLE peripheral listener ────────────────────────────────────
    // Binds + advertises immediately; each connecting central becomes its own
    // face, registered by the accept loop below.
    let mut listener = BleListener::bind(None, None)
        .await
        .context("failed to bind BLE listener — is Bluetooth enabled?")?;
    info!("BLE peripheral advertising; waiting for centrals to connect …");
    {
        let engine = engine.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            loop {
                let id = engine.faces().alloc_id();
                match listener.accept(id).await {
                    Ok(face) => {
                        info!(face = id.0, "BLE central connected");
                        engine.add_face_with_persistency(
                            face,
                            cancel.child_token(),
                            FacePersistency::Permanent,
                        );
                    }
                    Err(e) => {
                        info!(error = %e, "BLE listener stopped");
                        break;
                    }
                }
            }
        });
    }

    // ── Register producer on /ndn/ble/test ───────────────────────────────
    // One call: allocates the in-process app face, installs the FIB route,
    // and returns the Producer — no face ids in app code.
    let prefix = Name::from_str(PREFIX).unwrap();
    let producer = engine.register_producer(prefix.clone(), cancel.child_token());
    info!(
        prefix = PREFIX,
        "producer registered; waiting for BLE client connections …"
    );

    let serve = tokio::spawn(async move {
        producer
            .serve(|interest, responder| async move {
                let ts = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis();
                let content = format!("Hello from macOS! t={ts}");
                info!(
                    name = %interest.name,
                    content = %content,
                    "Interest received, responding"
                );
                let data = DataBuilder::new((*interest.name).clone(), content.as_bytes()).build();
                responder.respond_bytes(data).await.ok();
            })
            .await
            .ok();
    });

    // ── Wait for Ctrl+C ──────────────────────────────────────────────────
    tokio::signal::ctrl_c().await?;
    info!("shutting down …");
    cancel.cancel();
    serve.abort();
    Ok(())
}
