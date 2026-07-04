//! Proof of the service seam (service-layer §12) over the Tier-0 `RpcCarrier`.
//!
//! This is the shape the `#[ndn_service]` macro will emit, written by hand to
//! de-risk the macro and validate the `Carrier`/`Dispatch`/`Frame` contracts end
//! to end: a typed client generic over `C: Carrier`, a `Dispatch` that routes an
//! `OpId` to the typed service impl, and `Frame` request/response types. The same
//! definition would run over any carrier; here it runs over `RpcCarrier` (real
//! `Interest`/`Data`, real `RpcRegistry` dispatch).

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use ndn_packet::Name;
use ndn_rpc::RpcCarrier;
use ndn_service_core::{Carrier, Dispatch, Invocation, OpId, ServiceError, ServiceId};

fn name(s: &str) -> Name {
    s.parse().unwrap()
}

// --- messages (macro would derive `Frame` via TLV; these single-field messages
// use a trivial encoding — the seam, not the framing, is what's under test) ---

struct EchoReq {
    msg: String,
}
struct EchoResp {
    text: String,
}

impl ndn_service_core::Frame for EchoReq {
    fn encode(&self) -> Bytes {
        Bytes::copy_from_slice(self.msg.as_bytes())
    }
    fn decode(bytes: &[u8]) -> Result<Self, ServiceError> {
        let msg =
            String::from_utf8(bytes.to_vec()).map_err(|e| ServiceError::Decode(e.to_string()))?;
        Ok(EchoReq { msg })
    }
}
impl ndn_service_core::Frame for EchoResp {
    fn encode(&self) -> Bytes {
        Bytes::copy_from_slice(self.text.as_bytes())
    }
    fn decode(bytes: &[u8]) -> Result<Self, ServiceError> {
        let text =
            String::from_utf8(bytes.to_vec()).map_err(|e| ServiceError::Decode(e.to_string()))?;
        Ok(EchoResp { text })
    }
}

// --- the user's service definition (the IDL the macro consumes) ---

#[async_trait]
trait EchoService: Send + Sync + 'static {
    async fn echo(&self, msg: String) -> String;
    async fn shout(&self, msg: String) -> String;
}

struct EchoImpl;
#[async_trait]
impl EchoService for EchoImpl {
    async fn echo(&self, msg: String) -> String {
        msg
    }
    async fn shout(&self, msg: String) -> String {
        msg.to_uppercase()
    }
}

// --- macro-emitted server dispatch: route OpId -> typed handler ---

struct EchoDispatch<S: EchoService>(Arc<S>);
#[async_trait]
impl<S: EchoService> Dispatch for EchoDispatch<S> {
    async fn dispatch(&self, inv: Invocation) -> Result<Bytes, ServiceError> {
        use ndn_service_core::Frame;
        match inv.op.as_str() {
            "echo" => {
                let req = EchoReq::decode(&inv.request)?;
                Ok(EchoResp {
                    text: self.0.echo(req.msg).await,
                }
                .encode())
            }
            "shout" => {
                let req = EchoReq::decode(&inv.request)?;
                Ok(EchoResp {
                    text: self.0.shout(req.msg).await,
                }
                .encode())
            }
            _ => Err(ServiceError::NotFound),
        }
    }
}

// --- macro-emitted typed client, generic over any carrier ---

struct EchoClient<C: Carrier> {
    carrier: C,
    svc: ServiceId,
}
impl<C: Carrier> EchoClient<C> {
    async fn echo(&self, msg: String) -> Result<String, ServiceError> {
        use ndn_service_core::Frame;
        let resp = self
            .carrier
            .invoke(&self.svc, &OpId::new("echo"), EchoReq { msg }.encode())
            .await?;
        Ok(EchoResp::decode(&resp.payload)?.text)
    }
    async fn shout(&self, msg: String) -> Result<String, ServiceError> {
        use ndn_service_core::Frame;
        let resp = self
            .carrier
            .invoke(&self.svc, &OpId::new("shout"), EchoReq { msg }.encode())
            .await?;
        Ok(EchoResp::decode(&resp.payload)?.text)
    }
}

#[tokio::test]
async fn echo_service_round_trips_over_rpc_carrier() {
    let carrier = RpcCarrier::new();
    let svc = ServiceId::new(name("/svc/echo"));
    carrier
        .serve(&svc, Arc::new(EchoDispatch(Arc::new(EchoImpl))))
        .await
        .unwrap();

    let client = EchoClient { carrier, svc };
    // Two ops, routed by name: echo returns the payload, shout upper-cases it.
    assert_eq!(client.echo("hi there".into()).await.unwrap(), "hi there");
    assert_eq!(client.shout("hi there".into()).await.unwrap(), "HI THERE");
}

#[tokio::test]
async fn unknown_operation_fails_closed() {
    let carrier = RpcCarrier::new();
    let svc = ServiceId::new(name("/svc/echo"));
    carrier
        .serve(&svc, Arc::new(EchoDispatch(Arc::new(EchoImpl))))
        .await
        .unwrap();

    use ndn_service_core::Frame;
    let r = carrier
        .invoke(
            &svc,
            &OpId::new("nope"),
            EchoReq { msg: "x".into() }.encode(),
        )
        .await;
    assert!(
        matches!(r, Err(ServiceError::NotFound)),
        "an unknown op must fail closed"
    );
}

#[tokio::test]
async fn unknown_service_is_not_found() {
    let carrier = RpcCarrier::new();
    // Nothing mounted under /svc/ghost.
    use ndn_service_core::Frame;
    let r = carrier
        .invoke(
            &ServiceId::new(name("/svc/ghost")),
            &OpId::new("echo"),
            EchoReq { msg: "x".into() }.encode(),
        )
        .await;
    assert!(
        matches!(r, Err(ServiceError::NotFound)),
        "an unmounted service must be NotFound"
    );
}
