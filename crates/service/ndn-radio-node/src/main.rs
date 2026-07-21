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
use ndn_radio_cognition::{NameContext, RadioCapability, RadioId, RadioPolicy, prefix_hash};
#[cfg(not(feature = "libusb-backend"))]
use ndn_radio_cognition::{RadioActuators, RadioAllocation, RadioError};
use ndn_transport::FaceId as TransportFaceId;
use ndn_transport::link_service::features::{
    install_global_egress_source, install_global_ingress_sink,
};
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
#[cfg(not(feature = "libusb-backend"))]
struct NoopActuator(RadioId);
#[cfg(not(feature = "libusb-backend"))]
impl RadioActuators for NoopActuator {
    fn radio_id(&self) -> RadioId {
        self.0
    }
    fn apply(&self, _alloc: &RadioAllocation) -> Result<(), RadioError> {
        Ok(())
    }
}

fn env_u64(k: &str, d: u64) -> u64 {
    std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d)
}

/// Bind this node's observability layer to the process-global TraceContext hooks
/// (present on every network face's `LpLinkService` by default): outbound frames
/// carry this node's current trace context in the 0x520 LP TLV, and inbound frames
/// adopt the peer's trace-id (`set_inbound_trace_id`). So a frame that crosses the
/// radio hop carries its trace with it — one OTLP trace spans both nodes, and the
/// receiver's spans stitch under the sender's trace-id. No opentelemetry/tonic dep:
/// the TLV is the only wire artifact.
fn bind_global_trace_stitch(layer: &NdnObservabilityLayer) {
    let egress = layer.clone();
    install_global_egress_source(Arc::new(move || Some(egress.current_outbound_context())));
    let ingress = layer.clone();
    install_global_ingress_sink(Arc::new(move |tc| ingress.set_inbound_trace_id(tc.trace_id.0)));
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ticks = env_u64("TICKS", 5) as u32;
    let tick_ms = env_u64("NODE_TICK_MS", 200);

    // --- Observability: capture tracing spans → OTLP protobufs (published as
    //     Data), and mirror the human-readable events to the console. ---
    let publisher = SpanPublisher::new(obs_prefix(), SpanRetention::default());
    let layer = NdnObservabilityLayer::new(Arc::clone(&publisher), ratio_sampler(1.0));
    // Cross-node stitching: outbound frames carry our trace-id, inbound frames
    // adopt the peer's — one trace across the radio hop.
    bind_global_trace_stitch(&layer);
    let console = tracing_subscriber::fmt::layer().with_filter(
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "named_radio=info".into()),
    );
    tracing::subscriber::set_global_default(tracing_subscriber::registry().with(layer).with(console))?;

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

    // --- Cognitive radio control plane. On-air (feature `libusb-backend`) it binds
    //     a real RTL8822E as BOTH actuator and frame-free occupancy sensor; else a
    //     no-op actuator so the span tree still emits without hardware. Either way
    //     an active object makes every tick a real decision. ---
    let radio = RadioId(0);
    let ch = env_u64("NODE_CH", 149) as u8;
    let mut control = RadioControl::new(RadioPolicy::default());
    // Single operating channel so channel selection never tunes to an untested one.
    control.register_radio(radio, FaceId(0), RadioCapability::wifi_monitor_5ghz(vec![ch]));

    #[cfg(feature = "libusb-backend")]
    let backend = {
        use ndn_face_monitor_wifi::LibUsbRtl88xxBackend;
        let pid = env_u64("NODE_PID", 0xa81a) as u16;
        let b = Arc::new(LibUsbRtl88xxBackend::open_monitor_pid(pid, ch)?);
        control.libusb_actuator(radio, b.clone()); // ACT: real radio applies the plan
        println!("radio: RTL8822E 0bda:{pid:04x} bound as actuator + sensor on ch{ch}");
        b
    };
    #[cfg(not(feature = "libusb-backend"))]
    control.add_actuator(Arc::new(NoopActuator(radio)));

    control.set_active(vec![NameContext::new(prefix_hash(&[b"named-radio", b"demo"]))]);
    let control = Arc::new(control);

    // SENSE: on-air, spawn the frame-free occupancy sampler over the same handle.
    #[cfg(feature = "libusb-backend")]
    let _sampler =
        control.start_occupancy_sampling(radio, ch, backend, Duration::from_millis(500));

    println!("named-radio node up — observability prefix = {}", obs_prefix());
    println!("ticking the control plane {ticks}× (each tick emits the decision span tree)…");
    for _ in 0..ticks {
        control.tick_now(control.now_ms());
        tokio::time::sleep(Duration::from_millis(tick_ms)).await;
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

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_observability::{NdnObservabilityLayer, SpanPublisher, SpanRetention, ratio_sampler};
    use ndn_transport::link_service::{
        EgressCtx, IngressCtx, InboundLpFrame, LinkServiceFeature, OutboundLpFrame,
        TraceContextFeature,
    };

    fn a_node() -> NdnObservabilityLayer {
        NdnObservabilityLayer::new(
            SpanPublisher::new(obs_prefix(), SpanRetention::default()),
            ratio_sampler(1.0),
        )
    }

    /// A minimal well-formed LP wire (LP_PACKET wrapping an LP_FRAGMENT) to run the
    /// egress/ingress splice against.
    fn lp_wire() -> Bytes {
        use ndn_packet::tlv_type;
        let mut w = ndn_tlv::TlvWriter::new();
        w.write_nested(tlv_type::LP_PACKET, |w| {
            // A tiny inner NDN packet — content is irrelevant to the TraceContext TLV.
            w.write_tlv(tlv_type::LP_FRAGMENT, &[0x05, 0x02, 0x07, 0x00]);
        });
        w.finish()
    }

    #[test]
    fn one_trace_spans_two_nodes_across_a_hop() {
        // Two independent nodes, each with its own observability layer + the
        // trace-context feature its LpLinkService carries by default.
        let node_a = a_node();
        let node_b = a_node();
        // Put A on a known trace so the stitch is observable (both layers seed the
        // same process-wide root otherwise).
        node_a.set_inbound_trace_id([0xA1; 16]);
        let trace_a = node_a.current_outbound_context().trace_id;
        assert_eq!(trace_a.0, [0xA1; 16]);
        assert_ne!(
            node_b.current_outbound_context().trace_id,
            trace_a,
            "B starts on a different trace than A"
        );

        // Wire each node's feature to its layer — the same binding the node binary
        // installs process-globally, here per-feature so two nodes coexist in-process.
        let feat_a = TraceContextFeature::new();
        {
            let a = node_a.clone();
            feat_a.set_egress_source(Some(Arc::new(move || Some(a.current_outbound_context()))));
        }
        let feat_b = TraceContextFeature::new();
        {
            let b = node_b.clone();
            feat_b.set_ingress_sink(Some(Arc::new(move |tc| b.set_inbound_trace_id(tc.trace_id.0))));
        }

        // Node A transmits a frame: on_egress splices A's trace context (0x520 TLV).
        let mut out = OutboundLpFrame::new(lp_wire(), true);
        feat_a.on_egress(&mut out, &EgressCtx::new(APP_FACE_ID, None));

        // Node B receives it: on_ingress → sink → B adopts A's trace-id.
        feat_b.on_ingress(&InboundLpFrame::bare(out.wire), &IngressCtx::new(APP_FACE_ID));

        // B's subsequent spans now share A's trace-id — one trace, two nodes.
        assert_eq!(
            node_b.current_outbound_context().trace_id,
            trace_a,
            "the receiver stitched onto the sender's trace"
        );
    }
}
