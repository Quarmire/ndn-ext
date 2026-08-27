//! Gate: the carrier-uniform **metadata slot** rides intact through the Tier-0
//! carriers. A client sets an opaque slot (a W3C trace context) on the invocation;
//! it must (a) arrive at the **peer** on `Invocation::metadata` and (b) come back
//! **intact** on the returned `Response::metadata`. This is red-capable: a carrier
//! that dropped or mangled the slot would fail these assertions. The service (the
//! `Dispatch`) never sets the response slot — the carrier reflects it.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::Bytes;
use ndn_rpc::RpcCarrier;
use ndn_service_core::{Carrier, Dispatch, Invocation, Metadata, OpId, ServiceError, ServiceId};

fn n(s: &str) -> ndn_packet::Name {
    s.parse().unwrap()
}

/// A W3C-style trace context as an opaque two-entry slot.
fn trace_context() -> Metadata {
    let mut m = Metadata::new();
    m.insert(
        "traceparent".into(),
        Bytes::from_static(b"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
    );
    m.insert(
        "tracestate".into(),
        Bytes::from_static(b"congo=t61rcWkgMzE"),
    );
    m
}

/// Records the metadata the peer saw, and replies with a fixed payload. It never
/// touches the response slot — proving the carrier (not the service) reflects it.
struct CaptureDispatch(Arc<Mutex<Option<Metadata>>>);
#[async_trait]
impl Dispatch for CaptureDispatch {
    async fn dispatch(&self, inv: Invocation) -> Result<Bytes, ServiceError> {
        *self.0.lock().unwrap() = Some(inv.metadata.clone());
        Ok(Bytes::from_static(b"pong"))
    }
}

#[tokio::test]
async fn metadata_round_trips_over_rpc_carrier() {
    let carrier = RpcCarrier::new();
    let svc = ServiceId::new(n("/svc/trace"));
    let seen = Arc::new(Mutex::new(None));
    carrier
        .serve(&svc, Arc::new(CaptureDispatch(seen.clone())))
        .await
        .unwrap();

    let ctx = trace_context();
    let resp = carrier
        .invoke_meta(&svc, &OpId::new("op"), Bytes::new(), ctx.clone())
        .await
        .unwrap();

    assert_eq!(resp.payload, Bytes::from_static(b"pong"));
    // (a) the peer received the slot verbatim.
    assert_eq!(
        seen.lock().unwrap().as_ref(),
        Some(&ctx),
        "the trace context must arrive at the peer on Invocation::metadata"
    );
    // (b) it round-trips intact on the response.
    assert_eq!(
        resp.metadata, ctx,
        "the trace context must come back intact on Response::metadata"
    );
}

#[tokio::test]
async fn empty_slot_is_the_default() {
    // The no-metadata `invoke` shorthand carries an empty slot end to end.
    let carrier = RpcCarrier::new();
    let svc = ServiceId::new(n("/svc/trace"));
    let seen = Arc::new(Mutex::new(None));
    carrier
        .serve(&svc, Arc::new(CaptureDispatch(seen.clone())))
        .await
        .unwrap();

    let resp = carrier
        .invoke(&svc, &OpId::new("op"), Bytes::new())
        .await
        .unwrap();
    assert!(seen.lock().unwrap().as_ref().unwrap().is_empty());
    assert!(resp.metadata.is_empty());
}

// --- the same gate over the face-backed carrier (a real cross-face call) ---

#[cfg(feature = "engine")]
mod face {
    use super::*;
    use std::time::Duration;

    use ndn_app::{Consumer, EngineBuilder, Producer};
    use ndn_engine::EngineConfig;
    use ndn_face::local::InProcFace;
    use ndn_rpc::FaceRpcCarrier;
    use ndn_transport::FaceId;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn metadata_round_trips_over_face_carrier() {
        let svc_prefix = n("/svc/trace");
        let (c_face, c_handle) = InProcFace::new(FaceId(1), 64);
        let (p_face, p_handle) = InProcFace::new(FaceId(2), 64);
        let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
            .face(c_face)
            .face(p_face)
            .build()
            .await
            .unwrap();
        engine.fib().add_nexthop(&svc_prefix, FaceId(2), 0);

        let seen = Arc::new(Mutex::new(None));
        let seen_srv = seen.clone();
        let producer = Producer::from_handle(p_handle, svc_prefix.clone());
        let serve = tokio::spawn(async move {
            let server = FaceRpcCarrier::server(producer);
            let _ = server
                .serve(
                    &ServiceId::new(n("/svc/trace")),
                    Arc::new(CaptureDispatch(seen_srv)),
                )
                .await;
        });

        let ctx = trace_context();
        let client = FaceRpcCarrier::client(Consumer::from_handle(c_handle));
        let resp = tokio::time::timeout(
            Duration::from_secs(8),
            client.invoke_meta(
                &ServiceId::new(svc_prefix),
                &OpId::new("op"),
                Bytes::new(),
                ctx.clone(),
            ),
        )
        .await
        .expect("call timed out")
        .expect("call failed");

        assert_eq!(resp.payload, Bytes::from_static(b"pong"));
        assert_eq!(
            seen.lock().unwrap().as_ref(),
            Some(&ctx),
            "the trace context must survive the cross-face hop to the peer"
        );
        assert_eq!(
            resp.metadata, ctx,
            "the trace context must return intact through the PIT"
        );

        serve.abort();
        drop(engine);
        shutdown.shutdown().await;
    }
}
