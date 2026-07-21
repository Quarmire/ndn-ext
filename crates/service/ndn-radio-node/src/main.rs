//! A named-data radio node with **NDN-native observability**.
//!
//! Installs the OTLP span publisher + [`NdnObservabilityLayer`] as the tracing
//! subscriber, builds a forwarder engine, and mounts the publisher so completed
//! spans are served as **Interest-able Data** under an NDN prefix. It then runs
//! the cognitive radio control plane — each tick emits the sense → decide → act
//! timing tree plus a per-decision *why* span — and proves the loop end-to-end by
//! Interesting a just-emitted span back through the engine and decoding it as an
//! OTLP `Span` protobuf.
//!
//! No radio hardware required: this demonstrates the observability pipeline at the
//! radio/cognition layer. Point a real backend at the same `RadioControl`
//! (`libusb_actuator` + `start_occupancy_sampling`) to run it on-air.
//!
//!   cargo run -p ndn-radio-node            # 5 ticks, prove round-trip, exit
//!   env TICKS=20 RUST_LOG=named_radio=info cargo run -p ndn-radio-node

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_engine::{EngineBuilder, EngineConfig};
use ndn_face_local::InProcFace;
use ndn_face_monitor_wifi::{FaceId, RadioControl};
use ndn_observability::{
    NdnObservabilityLayer, SpanPublisher, SpanRetention, mount_observability, ratio_sampler,
};
use ndn_packet::encode::InterestBuilder;
use ndn_packet::{Data, Name, NameComponent};
use ndn_radio_cognition::{
    NameContext, RadioActuators, RadioAllocation, RadioCapability, RadioError, RadioId, RadioPolicy,
    prefix_hash,
};
use ndn_transport::FaceId as TransportFaceId;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::Layer;
use tracing_subscriber::layer::SubscriberExt;

const APP_FACE_ID: TransportFaceId = TransportFaceId(10_000);

fn obs_prefix() -> Name {
    Name::from_components([
        NameComponent::generic(Bytes::from_static(b"localhost")),
        NameComponent::generic(Bytes::from_static(b"named-radio")),
        NameComponent::generic(Bytes::from_static(b"observability")),
    ])
}

/// A no-op actuator so the ACT stage's `apply` span emits without real hardware.
struct NoopActuator(RadioId);
impl RadioActuators for NoopActuator {
    fn radio_id(&self) -> RadioId {
        self.0
    }
    fn apply(&self, _alloc: &RadioAllocation) -> Result<(), RadioError> {
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ticks: u32 = std::env::var("TICKS").ok().and_then(|v| v.parse().ok()).unwrap_or(5);

    // --- Observability: capture tracing spans → OTLP protobufs (published as
    //     Data), and mirror the human-readable events to the console. ---
    let publisher = SpanPublisher::new(obs_prefix(), SpanRetention::default());
    let obs = NdnObservabilityLayer::new(Arc::clone(&publisher), ratio_sampler(1.0));
    let console = tracing_subscriber::fmt::layer().with_filter(
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "named_radio=info".into()),
    );
    tracing::subscriber::set_global_default(tracing_subscriber::registry().with(obs).with(console))?;

    // --- Engine + app face; mount the publisher's Producer so spans are served
    //     as Data (Interest by trace-id/span-id; PIT/CS/NAC/signing all apply). ---
    let (app_face, app_handle) = InProcFace::new(APP_FACE_ID, 64);
    let (engine, _shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(app_face)
        .build()
        .await?;
    let cancel = CancellationToken::new();
    mount_observability(&engine, cancel.clone(), Arc::clone(&publisher));
    tokio::time::sleep(Duration::from_millis(20)).await; // let the producer register

    // --- Cognitive radio control plane: one wifi radio + a no-op actuator + an
    //     active object, so every tick emits the full sense→decide→act span tree. ---
    let radio = RadioId(0);
    let mut control = RadioControl::new(RadioPolicy::default());
    control.register_radio(
        radio,
        FaceId(0),
        RadioCapability::wifi_monitor_5ghz(vec![149, 161, 165]),
    );
    control.add_actuator(Arc::new(NoopActuator(radio)));
    control.set_active(vec![NameContext::new(prefix_hash(&[b"named-radio", b"demo"]))]);
    let control = Arc::new(control);

    println!("named-radio node up — observability prefix = {}", obs_prefix());
    println!("ticking the control plane {ticks}× (each tick emits the decision span tree)…");
    for _ in 0..ticks {
        control.tick_now(control.now_ms());
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    println!("published {} OTLP spans to the observability ring", publisher.len());

    // --- Prove end-to-end: take a just-emitted span's Data name, Interest it
    //     through the ENGINE, and decode the response as an OTLP Span protobuf. ---
    let latest = publisher.latest_wire().ok_or("no span was published")?;
    let name = (*Data::decode(latest)?.name).clone();
    println!("\nInteresting a published span by name: {name}");
    let interest = InterestBuilder::new(name.clone()).must_be_fresh().build();
    app_handle.send(interest).await?;
    let wire = tokio::time::timeout(Duration::from_millis(500), app_handle.recv())
        .await
        .map_err(|_| "no Data within 500ms")?
        .ok_or("app face closed")?;
    let data = Data::decode(wire)?;
    let content = data.content().cloned().ok_or("span Data had no content")?;
    // OTLP Span protobuf: field 1 (trace_id) = tag 0x0A, len 16.
    let is_otlp = content.first() == Some(&0x0A) && content.get(1) == Some(&16);
    println!(
        "  ← served by the engine as Data ({} bytes content); OTLP Span protobuf: {}",
        content.len(),
        if is_otlp { "yes ✓" } else { "NO" }
    );
    assert!(is_otlp, "round-tripped Data content was not an OTLP Span");
    assert_eq!(*data.name, name, "served name matched the Interest");
    println!("\nend-to-end verified: radio decision span → OTLP-in-Data → Interest-able.");

    cancel.cancel();
    Ok(())
}
