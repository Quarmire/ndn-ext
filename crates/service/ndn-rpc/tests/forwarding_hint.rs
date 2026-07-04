//! `RpcCarrier` implements `HintedCarrier`: a forwarding hint passed to
//! `invoke_hinted` rides on the wire Interest (so a real forwarder can steer
//! toward the selected provider while the content name stays shared). A
//! capturing handler inspects the inbound Interest's forwarding hint.

use std::sync::{Arc, Mutex};

use ndn_packet::encode::DataBuilder;
use ndn_packet::{Data, Interest, Name};
use ndn_rpc::{RpcCarrier, RpcError, RpcHandler, RpcRegistry};
use ndn_service_core::{Carrier, HintedCarrier, OpId, ServiceId};

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

/// Records the forwarding hint of the most recent inbound Interest.
struct CaptureHint(Arc<Mutex<Option<Vec<String>>>>);
impl RpcHandler for CaptureHint {
    async fn handle(&self, interest: &Interest) -> Result<Data, RpcError> {
        let hints = interest
            .forwarding_hint()
            .map(|hs| hs.iter().map(|h| h.to_string()).collect::<Vec<_>>());
        *self.0.lock().unwrap() = hints;
        let wire = DataBuilder::new((*interest.name).clone(), b"ok").sign_digest_sha256();
        Data::decode(wire).map_err(|e| RpcError::HandlerFailed(e.to_string()))
    }
}

#[tokio::test]
async fn invoke_hinted_attaches_forwarding_hint() {
    let registry = Arc::new(RpcRegistry::new());
    let captured = Arc::new(Mutex::new(None));
    registry.register(&n("/svc/echo"), CaptureHint(captured.clone()));
    let carrier = RpcCarrier::with_registry(registry);
    let svc = ServiceId::new(n("/svc/echo"));

    // With a hint: the inbound Interest carries it (the forwarder would steer here).
    carrier
        .invoke_hinted(
            &svc,
            &OpId::new("echo"),
            bytes::Bytes::new(),
            Some(&n("/p1")),
        )
        .await
        .unwrap();
    assert_eq!(
        captured.lock().unwrap().clone(),
        Some(vec!["/p1".to_string()]),
        "the forwarding hint must ride on the Interest"
    );

    // Plain invoke: no hint on the wire.
    carrier
        .invoke(&svc, &OpId::new("echo"), bytes::Bytes::new())
        .await
        .unwrap();
    assert_eq!(
        captured.lock().unwrap().clone(),
        None,
        "a plain invoke carries no forwarding hint"
    );
}
