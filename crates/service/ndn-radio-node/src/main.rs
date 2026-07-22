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
#[cfg(feature = "libusb-backend")]
use ndn_packet::{Interest, encode::encode_data_unsigned};
#[cfg(feature = "libusb-backend")]
use ndn_radio_cognition::{PolicyConfig, TxParams};
#[cfg(feature = "libusb-backend")]
use std::sync::RwLock;
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
/// The radio, when wired as an NDN face carrying LP traffic (not just an actuator).
#[cfg(feature = "libusb-backend")]
const RADIO_FACE_ID: TransportFaceId = TransportFaceId(1);

fn obs_prefix() -> Name {
    Name::from_components([
        NameComponent::generic(Bytes::from_static(b"localhost")),
        NameComponent::generic(Bytes::from_static(b"named-radio")),
        NameComponent::generic(Bytes::from_static(b"observability")),
    ])
}

/// The demo content prefix a consumer Interests and a producer serves over the radio.
#[cfg(feature = "libusb-backend")]
fn radio_demo_prefix() -> Name {
    Name::from_components([NameComponent::generic(Bytes::from_static(b"radio-demo"))])
}

/// `/radio-demo/<seq>/<rssi>/<ack>` — the consumer carries its measured link RSSI
/// AND whether it received the PREVIOUS Data (the real delivery reward) to the
/// producer in the Interest name, closing the loop over the radio itself.
#[cfg(feature = "libusb-backend")]
fn demo_name(seq: u64, rssi: i8, ack: u8) -> Name {
    Name::from_components([
        NameComponent::generic(Bytes::from_static(b"radio-demo")),
        NameComponent::generic(Bytes::copy_from_slice(seq.to_string().as_bytes())),
        NameComponent::generic(Bytes::copy_from_slice(rssi.to_string().as_bytes())),
        NameComponent::generic(Bytes::copy_from_slice(ack.to_string().as_bytes())),
    ])
}

#[cfg(feature = "libusb-backend")]
fn comp_i32(name: &Name, i: usize) -> Option<i32> {
    std::str::from_utf8(name.components().get(i)?.value.as_ref()).ok()?.parse().ok()
}
/// Reported RSSI = component [2]; delivery-ack of the previous frame = component [3].
#[cfg(feature = "libusb-backend")]
fn parse_rssi(name: &Name) -> Option<i8> {
    comp_i32(name, 2).map(|v| v.clamp(-110, -20) as i8)
}
#[cfg(feature = "libusb-backend")]
fn parse_ack(name: &Name) -> Option<bool> {
    comp_i32(name, 3).map(|v| v != 0)
}

/// A tiny signal store: the consumer's face pushes the per-frame RSSI it measures
/// on the a81a's RX descriptor here, and the consumer reads (and clears) it each
/// round — so the RSSI it reports is the REAL link it heard the producer at, and
/// a round where it heard nothing reads `None` (→ back off).
#[cfg(feature = "libusb-backend")]
#[derive(Default)]
struct RssiStore(std::sync::Mutex<std::collections::HashMap<FaceId, ndn_signals_core::LinkSignals>>);

#[cfg(feature = "libusb-backend")]
impl ndn_signals_core::SignalView<FaceId> for RssiStore {
    fn link(&self, f: FaceId) -> Option<ndn_signals_core::LinkSignals> {
        self.0.lock().unwrap().get(&f).copied()
    }
    fn node(&self) -> ndn_signals_core::NodeSignals {
        ndn_signals_core::NodeSignals::default()
    }
    fn neighbor(&self, _: FaceId) -> Option<ndn_signals_core::NodeSignals> {
        None
    }
}

#[cfg(feature = "libusb-backend")]
impl ndn_signals_core::SignalStore<FaceId> for RssiStore {
    fn set_link(&self, f: FaceId, s: ndn_signals_core::LinkSignals) {
        self.0.lock().unwrap().insert(f, s);
    }
    fn set_node(&self, _: ndn_signals_core::NodeSignals) {}
    fn set_neighbor(&self, _: FaceId, _: ndn_signals_core::NodeSignals) {}
}

#[cfg(feature = "libusb-backend")]
impl RssiStore {
    /// Take (read + clear) the RSSI heard since the last call; `None` if nothing.
    fn take_rssi(&self, f: FaceId) -> Option<i8> {
        self.0.lock().unwrap().remove(&f).and_then(|l| l.rssi_dbm)
    }
}

/// Low 8 bytes of a trace-id as hex — where the seed's entropy lives (the id is a
/// big-endian nanos timestamp), so this distinguishes two nodes' traces.
#[cfg(feature = "libusb-backend")]
fn trace8(id: [u8; 16]) -> String {
    id[8..].iter().map(|b| format!("{b:02x}")).collect()
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
    #[cfg(feature = "libusb-backend")]
    let trace_layer = layer.clone(); // read the current (possibly stitched) trace-id
    let console = tracing_subscriber::fmt::layer().with_filter(
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "named_radio=info".into()),
    );
    tracing::subscriber::set_global_default(tracing_subscriber::registry().with(layer).with(console))?;

    // --- Engine + app face (+ the radio as a real NDN Face when a role is set). ---
    let ch = env_u64("NODE_CH", 149) as u8;
    let (app_face, app_handle) = InProcFace::new(APP_FACE_ID, 64);
    #[allow(unused_mut)] // `builder` is reassigned only when the radio face is added
    let mut builder = EngineBuilder::new(EngineConfig::default()).face(app_face);

    // NODE_ROLE=consumer|producer wires the radio into the engine as an NDN face and
    // runs a real Interest/Data exchange over the air; unset = the control-plane demo.
    #[cfg(feature = "libusb-backend")]
    let role = std::env::var("NODE_ROLE").unwrap_or_default();
    // The producer's cognition writes its decided TX params here; the face reads the
    // cell per send. Actuating the cell directly (not via libusb_actuator) keeps the
    // control plane off the USB bus, so it never contends with the face's RX/TX.
    #[cfg(feature = "libusb-backend")]
    let planned_cell: Arc<RwLock<Option<TxParams>>> = Arc::new(RwLock::new(None));
    // The consumer's face pushes the RSSI it measures for each received producer
    // frame here; the consumer reads it to report the REAL link (self-running loop).
    #[cfg(feature = "libusb-backend")]
    let signal_store: Arc<RssiStore> = Arc::new(RssiStore::default());
    #[cfg(feature = "libusb-backend")]
    let radio_backend = if role == "consumer" || role == "producer" {
        use ndn_face_monitor_wifi::{FaceId, LibUsbRtl88xxBackend, MonitorWifiFace};
        let pid = env_u64("NODE_PID", 0xa81a) as u16;
        let backend = Arc::new(LibUsbRtl88xxBackend::open_monitor_pid(pid, ch)?);
        // NODE_TXPWR: lower the TXAGC to make the bench link marginal (induce real
        // loss) so the FEC A/B has something to recover. Unset = bring-up default.
        if let Ok(p) = std::env::var("NODE_TXPWR") {
            if let Ok(idx) = p.parse::<u32>() {
                backend.set_tx_power(idx)?;
                println!("tx power set to {idx:#04x}");
            }
        }
        // Broadcast/open by default — the paired LpLinkService fragments NDN packets
        // across injected frames and runs the per-frame feature pipeline (incl. the
        // TraceContextFeature that carries our stitch TLV).
        let mut mf = MonitorWifiFace::new(FaceId(RADIO_FACE_ID.0), backend.clone());
        // NODE_FEC=R: link-layer FEC (K=1 ⇒ repetition, R redundant frames) — the
        // broadcast reliability lever with no ARQ. Both ends must match. Encodes
        // below the LP features, so it wraps (and preserves) the stitch TLV. 0 = off.
        let fec_r = env_u64("NODE_FEC", 0) as u16;
        if fec_r > 0 {
            mf = mf.with_link_fec(1, fec_r, Duration::from_millis(50));
        }
        // The face sends at the cognition-decided MCS when the cell is populated
        // (producer), else its static policy (consumer); and it publishes the RSSI
        // it measures per RX frame to the signal store (consumer reads it).
        mf = mf.with_planned_params(planned_cell.clone());
        mf = mf.with_signal_sink(signal_store.clone());
        let radio_face = mf.into_face();
        builder = builder.face_composed(radio_face);
        println!(
            "radio: RTL8822E 0bda:{pid:04x} as NDN face {} on ch{ch}; link-FEC R={fec_r}",
            RADIO_FACE_ID.0
        );
        Some(backend)
    } else {
        None
    };

    let (engine, _shutdown) = builder.build().await?;
    let cancel = CancellationToken::new();
    mount_observability(&engine, cancel.clone(), Arc::clone(&publisher));
    tokio::time::sleep(Duration::from_millis(50)).await; // let producers register

    // --- Radio-face NDN exchange (the on-air cross-node path). ---
    #[cfg(feature = "libusb-backend")]
    if role == "consumer" || role == "producer" {
        let prefix = radio_demo_prefix();
        println!(
            "node up [{role}] — my trace = {}",
            trace8(trace_layer.current_outbound_context().trace_id.0)
        );
        if role == "consumer" {
            // Route the demo prefix out the radio face; express Interests over the air.
            engine.fib().add_nexthop(&prefix, RADIO_FACE_ID, 0);
            // Self-running loop: report the REAL RSSI the face measured for the last
            // producer frame; when nothing was heard (loss), report a conservative
            // floor so the producer backs off. NODE_RSSI_BIAS is an optional offset.
            let bias: i32 = std::env::var("NODE_RSSI_BIAS").ok().and_then(|v| v.parse().ok()).unwrap_or(0);
            let floor: i32 = std::env::var("NODE_RSSI_FLOOR").ok().and_then(|v| v.parse().ok()).unwrap_or(-90);
            // NODE_FIX_RSSI pins the report (ignoring measurement) so the policy stays
            // over-aggressive and the BANDIT must correct the rate from real reward.
            let fixed: Option<i32> = std::env::var("NODE_FIX_RSSI").ok().and_then(|v| v.parse().ok());
            let face_id = FaceId(RADIO_FACE_ID.0);
            println!("consumer: reporting {} link RSSI (floor {floor}, bias {bias})",
                if fixed.is_some() { "FIXED" } else { "MEASURED" });
            let mut got = 0u32;
            let mut got_prev = true; // ack of the previous Data (real bandit reward)
            for seq in 0..ticks as u64 {
                let measured = signal_store.take_rssi(face_id);
                let reported =
                    (fixed.unwrap_or_else(|| measured.map(i32::from).unwrap_or(floor)) + bias)
                        .clamp(-110, -20) as i8;
                let name = demo_name(seq, reported, got_prev as u8);
                app_handle
                    .send(InterestBuilder::new(name.clone()).must_be_fresh().build())
                    .await?;
                match tokio::time::timeout(Duration::from_millis(1500), app_handle.recv()).await {
                    Ok(Some(wire)) => {
                        got += 1;
                        got_prev = true;
                        let d = Data::decode(wire)?;
                        println!(
                            "  seq {seq}: reported {reported} (measured {measured:?}) → got ({} B)",
                            d.content().map(|c| c.len()).unwrap_or(0)
                        );
                    }
                    _ => {
                        got_prev = false;
                        println!("  seq {seq}: reported {reported} (measured {measured:?}) → LOST");
                    }
                }
                tokio::time::sleep(Duration::from_millis(tick_ms)).await;
            }
            println!("DELIVERY: {got}/{ticks} Interest→Data round-trips completed over the radio");
        } else {
            // PRODUCER: close the cognition loop — fold the consumer's REPORTED link
            // RSSI into the medium, let the policy decide, and write the decided TX
            // params so the next Data goes out at the adapted rate. Actuation is the
            // shared cell (no USB), so the plane never contends with the face.
            engine.fib().add_nexthop(&prefix, APP_FACE_ID, 0);
            let radio = RadioId(0);
            const CONSUMER_NODE: u64 = 0xC0;
            const FULL_PWR: u8 = 0x3f; // decide_power returns None = "keep full power"
            // NODE_BANDIT=1 → joint rate×power×FEC multi-arm bandit (the cooperative
            // dynamic-power learner from the 8812EU work); else the rule policy.
            let mut control = if env_u64("NODE_BANDIT", 0) == 1 {
                RadioControl::new_bandit(PolicyConfig::default(), 0.3)
            } else {
                RadioControl::new(RadioPolicy::default())
            };
            control.register_radio(radio, FaceId(0), RadioCapability::wifi_monitor_5ghz(vec![ch]));
            control.set_active(vec![NameContext::new(prefix_hash(&[b"radio-demo"]))]);
            let fake_reward = env_u64("NODE_FAKE_REWARD", 0) == 1;
            let run = Duration::from_secs(env_u64("NODE_SECS", 60));
            let start = tokio::time::Instant::now();
            let mut served = 0u32;
            let mut last: (Option<u8>, u8) = (None, 0); // (mcs, power)
            while start.elapsed() < run {
                match tokio::time::timeout(Duration::from_millis(500), app_handle.recv()).await {
                    Ok(Some(wire)) => {
                        let name = (*Interest::decode(wire)?.name).clone();
                        // REWARD FIRST: the ack is for the PREVIOUS Data, so feeding it
                        // before the tick attributes it to the arm that served it (the
                        // current last_arm) — correct delayed-feedback attribution.
                        // NODE_FAKE_REWARD=1 forces the old always-true reward (A/B).
                        if let Some(delivered) = parse_ack(&name) {
                            let reward = fake_reward || delivered;
                            control.observe_delivery(reward);
                        }
                        // SENSE (real reported link) → DECIDE → ACT: MCS via the planned
                        // cell (per-frame, no USB), TX power via the TXAGC (RadioKnobs).
                        if let Some(rssi) = parse_rssi(&name) {
                            let now = control.now_ms();
                            control.observe_rx(radio, CONSUMER_NODE, Some(rssi), now);
                            let plans = control.tick_now(now);
                            if let Some(a) = plans.first().and_then(|p| p.allocations.first()) {
                                *planned_cell.write().unwrap() = Some(a.params);
                                // NODE_FORCE_PWR overrides the decided power (stress test:
                                // force minimum to try to induce RF loss at close range).
                                let pwr = std::env::var("NODE_FORCE_PWR")
                                    .ok()
                                    .and_then(|v| v.parse::<u8>().ok())
                                    .unwrap_or_else(|| a.params.tx_power.unwrap_or(FULL_PWR));
                                if let Some(be) = &radio_backend {
                                    let _ = be.set_tx_power(pwr as u32);
                                }
                                let now_pair = (a.params.mcs(), pwr);
                                if now_pair != last {
                                    println!(
                                        "  reported RSSI {rssi} dBm → MCS {:?}, TX power {:#04x}",
                                        now_pair.0, pwr
                                    );
                                    last = now_pair;
                                }
                            }
                        }
                        let body = format!("hello from producer, {name}");
                        app_handle.send(encode_data_unsigned(&name, body.as_bytes())).await?;
                        served += 1;
                    }
                    _ => {}
                }
            }
            println!("producer served {served} Data over the radio");
        }
        println!("published {} OTLP spans (trace stitched across the hop)", publisher.len());
        cancel.cancel();
        return Ok(());
    }

    // --- Cognitive radio control plane. On-air (feature `libusb-backend`) it binds
    //     a real RTL8822E as BOTH actuator and frame-free occupancy sensor; else a
    //     no-op actuator so the span tree still emits without hardware. Either way
    //     an active object makes every tick a real decision. ---
    let radio = RadioId(0);
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
