//! Proof that `#[ndn_service]` generates working code: the macro replaces the
//! hand-written `Frame`/`Dispatch`/client boilerplate of `carrier_proof.rs`, and
//! the generated service runs over `RpcCarrier`. The impl is a plain `async fn`
//! block — no `#[async_trait]` — because the macro rewrites the trait methods to
//! `-> impl Future + Send`.

use std::sync::Arc;

use ndn_rpc::RpcCarrier;
use ndn_service_core::{Carrier, ServiceId};
use ndn_service_macro::{Frame, ndn_service};

/// A structured response — `#[derive(Frame)]` makes typed "response with data"
/// ergonomic (the part a bare-`String` greeter left ambiguous).
#[derive(Frame, Debug, PartialEq, Eq)]
struct Stats {
    sum: u64,
    even: bool,
    label: String,
}

#[ndn_service]
trait Calc {
    async fn add(&self, a: u64, b: u64) -> u64;
    async fn echo(&self, msg: String) -> String;
    async fn ping(&self) -> u64;
    async fn summarize(&self, a: u64, b: u64) -> Stats;
}

struct CalcImpl;
impl Calc for CalcImpl {
    async fn add(&self, a: u64, b: u64) -> u64 {
        a + b
    }
    async fn echo(&self, msg: String) -> String {
        msg
    }
    async fn ping(&self) -> u64 {
        42
    }
    async fn summarize(&self, a: u64, b: u64) -> Stats {
        let sum = a + b;
        Stats {
            sum,
            even: sum.is_multiple_of(2),
            label: format!("{a}+{b}"),
        }
    }
}

#[tokio::test]
async fn macro_service_round_trips_over_rpc_carrier() {
    let carrier = RpcCarrier::new();
    let svc = ServiceId::new("/svc/calc".parse().unwrap());
    carrier
        .serve(&svc, Arc::new(CalcDispatch(Arc::new(CalcImpl))))
        .await
        .unwrap();

    let client = CalcClient::new(carrier, svc);
    // Multi-arg, single-arg, and no-arg ops all round-trip through the generated
    // Frame messages + dispatch.
    assert_eq!(client.add(2, 3).await.unwrap(), 5);
    assert_eq!(client.echo("hi there".into()).await.unwrap(), "hi there");
    assert_eq!(client.ping().await.unwrap(), 42);
    // A parameterized request returning a derived struct — the typed "response
    // with data" round-trips through the generated Frame codec.
    assert_eq!(
        client.summarize(2, 4).await.unwrap(),
        Stats {
            sum: 6,
            even: true,
            label: "2+4".into()
        }
    );
}

#[tokio::test]
async fn macro_service_unknown_service_fails_closed() {
    // A client whose service was never served gets NotFound, not a panic.
    let carrier = RpcCarrier::new();
    let client = CalcClient::new(carrier, ServiceId::new("/svc/ghost".parse().unwrap()));
    assert!(client.ping().await.is_err());
}
