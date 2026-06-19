#![cfg(feature = "engine")]
//! The face-backed carrier turns the proven seam into a **real** network service
//! call: a `#[ndn_service]` client invokes a provider that lives behind a
//! different face on the forwarder. The Interest is routed by the engine (FIB) to
//! the provider's face; the response Data flows back through the PIT — not a
//! shared in-process registry.

use std::sync::Arc;
use std::time::Duration;

use ndn_app::{Consumer, EngineBuilder, Producer};
use ndn_engine::EngineConfig;
use ndn_face::local::InProcFace;
use ndn_packet::Name;
use ndn_rpc::FaceRpcCarrier;
use ndn_service_core::{Carrier, ServiceId};
use ndn_service_macro::ndn_service;
use ndn_transport::FaceId;

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

#[ndn_service]
trait Echo {
    async fn echo(&self, msg: String) -> String;
}

struct EchoImpl;
impl Echo for EchoImpl {
    async fn echo(&self, msg: String) -> String {
        format!("echo:{msg}")
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn macro_client_calls_a_provider_over_the_engine() {
    let svc_prefix = n("/svc/echo");

    // One engine acting as the forwarder; a consumer face and a producer face.
    let (c_face, c_handle) = InProcFace::new(FaceId(1), 64);
    let (p_face, p_handle) = InProcFace::new(FaceId(2), 64);
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(c_face)
        .face(p_face)
        .build()
        .await
        .unwrap();
    // Route the service prefix to the provider's face.
    engine.fib().add_nexthop(&svc_prefix, FaceId(2), 0);

    // Provider: serve the macro dispatch over a Producer on its face.
    let producer = Producer::from_handle(p_handle, svc_prefix.clone());
    let serve = tokio::spawn(async move {
        let server = FaceRpcCarrier::server(producer);
        let svc = ServiceId::new(n("/svc/echo"));
        let _ = server.serve(&svc, Arc::new(EchoDispatch(Arc::new(EchoImpl)))).await;
    });

    // Client: a generated EchoClient over a face-backed carrier on its own face.
    let consumer = Consumer::from_handle(c_handle);
    let client = EchoClient::new(FaceRpcCarrier::client(consumer), ServiceId::new(svc_prefix));

    let reply = tokio::time::timeout(Duration::from_secs(8), client.echo("ping".into()))
        .await
        .expect("call timed out")
        .expect("echo failed");
    assert_eq!(reply, "echo:ping", "a real cross-face service call over the engine");

    serve.abort();
    drop(engine);
    shutdown.shutdown().await;
}
