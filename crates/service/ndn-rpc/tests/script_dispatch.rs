//! The dynamic/scripting seam: an untyped `ScriptDispatch` (op → bytes→bytes
//! handlers) served over a carrier, invoked by op name. This is the exact path a
//! PyO3/boltffi binding wraps — a non-Rust callable becomes a `ScriptHandler`,
//! and the client calls ops with bytes (no `#[ndn_service]` macro, no typed Frame).

use std::sync::Arc;

use bytes::Bytes;
use ndn_packet::Name;
use ndn_rpc::RpcCarrier;
use ndn_service_core::{Carrier, OpId, ScriptDispatch, ScriptHandler, ServiceId};

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

#[tokio::test]
async fn untyped_script_service_round_trips_over_a_carrier() {
    // The "scripting layer" registers bytes->bytes handlers by op name.
    let mut dispatch = ScriptDispatch::new();
    let echo: ScriptHandler = Arc::new(|req: Bytes| Ok(req));
    let shout: ScriptHandler = Arc::new(|req: Bytes| {
        Ok(Bytes::from(String::from_utf8_lossy(&req).to_uppercase().into_bytes()))
    });
    dispatch.on("echo", echo);
    dispatch.on("shout", shout);

    let carrier = RpcCarrier::new();
    let svc = ServiceId::new(n("/svc/echo"));
    carrier.serve(&svc, Arc::new(dispatch)).await.unwrap();

    // The "scripting client" invokes ops by name — bytes in, bytes out.
    let r = carrier.invoke(&svc, &OpId::new("echo"), Bytes::from_static(b"hi")).await.unwrap();
    assert_eq!(r.payload.as_ref(), b"hi");
    let r = carrier.invoke(&svc, &OpId::new("shout"), Bytes::from_static(b"hi")).await.unwrap();
    assert_eq!(r.payload.as_ref(), b"HI");

    // An unknown op fails closed (ScriptDispatch returns NotFound).
    assert!(carrier.invoke(&svc, &OpId::new("nope"), Bytes::new()).await.is_err());
}

#[tokio::test]
async fn panicking_script_handler_is_isolated() {
    // SEC-24: a script handler that panics on attacker-supplied bytes must become an
    // error — not unwind the serving task — and other ops keep working afterward.
    let mut dispatch = ScriptDispatch::new();
    let boom: ScriptHandler = Arc::new(|_req: Bytes| panic!("handler blew up"));
    let echo: ScriptHandler = Arc::new(|req: Bytes| Ok(req));
    dispatch.on("boom", boom);
    dispatch.on("echo", echo);

    let carrier = RpcCarrier::new();
    let svc = ServiceId::new(n("/svc/x"));
    carrier.serve(&svc, Arc::new(dispatch)).await.unwrap();

    // The panicking op returns an error (caught by catch_unwind), not a crash.
    assert!(carrier.invoke(&svc, &OpId::new("boom"), Bytes::from_static(b"x")).await.is_err());
    // A subsequent op still works — the service survived the panic.
    let r = carrier.invoke(&svc, &OpId::new("echo"), Bytes::from_static(b"ok")).await.unwrap();
    assert_eq!(r.payload.as_ref(), b"ok");
}
