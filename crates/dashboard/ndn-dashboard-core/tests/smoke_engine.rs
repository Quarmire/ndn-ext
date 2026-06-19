//! Live smoke test: drives `DashboardEngine` over a real `ndn_ipc::MgmtClient`
//! against a running forwarder. Ignored by default; run with the socket path:
//!
//! ```text
//! NDN_SMOKE_SOCKET=/tmp/ndn-smoke.sock cargo test -p ndn-dashboard-core \
//!     --features desktop --test smoke_engine -- --ignored --nocapture
//! ```
//!
//! This mirrors the dashboard's `NativeMgmtClient`, which is a pure newtype
//! delegating to `MgmtClient::send_cmd_raw` — so the adapter below is a
//! faithful proxy for the exact desktop poll/command path the engine drives.

#![cfg(feature = "desktop")]

use ndn_config::ControlParameters;
use ndn_dashboard_core::{DashboardEngine, ManagementClient, MgmtResponse, StateUpdate};
use ndn_ipc::MgmtClient;

struct NativeAdapter(MgmtClient);

#[async_trait::async_trait(?Send)]
impl ManagementClient for NativeAdapter {
    async fn send_cmd(
        &mut self,
        module: &str,
        verb: &str,
        params: Option<&ControlParameters>,
    ) -> Result<MgmtResponse, String> {
        let (status_code, status_text, body) = self
            .0
            .send_cmd_raw(module, verb, params)
            .await
            .map_err(|e| e.to_string())?;
        Ok(MgmtResponse {
            status_code,
            status_text,
            body,
        })
    }
}

#[tokio::test]
#[ignore = "requires a running forwarder; set NDN_SMOKE_SOCKET"]
async fn smoke_poll_and_command_against_live_forwarder() {
    let socket =
        std::env::var("NDN_SMOKE_SOCKET").expect("set NDN_SMOKE_SOCKET to the forwarder socket");

    let client = MgmtClient::connect(&socket)
        .await
        .expect("connect to forwarder socket");
    let mut engine = DashboardEngine::new(NativeAdapter(client));

    // 1) Poll the forwarding plane — the core of the cutover.
    let updates = engine.poll_forwarding().await;
    println!("\n=== poll updates: {updates:?} ===");
    let st = engine.state();
    println!("status:     {:?}", st.status);
    println!("faces:      {} entries", st.faces.len());
    for f in &st.faces {
        println!(
            "  face {:<4} remote={:?} local={:?} {} in_i={} out_d={}",
            f.face_id, f.remote_uri, f.local_uri, f.persistency, f.n_in_interests, f.n_out_data
        );
    }
    println!("routes:     {:?}", st.routes.iter().map(|r| &r.prefix).collect::<Vec<_>>());
    println!("strategies: {:?}", st.strategies.iter().map(|s| (&s.prefix, &s.strategy)).collect::<Vec<_>>());
    println!("cs:         {:?}", st.cs);

    // A healthy forwarder always returns its general status + face table.
    assert!(
        updates.contains(&StateUpdate::Status),
        "no status returned — forwarder unhealthy or wrong socket"
    );
    assert!(st.status.is_some(), "status didn't parse");
    assert!(
        updates.contains(&StateUpdate::Faces),
        "no faces dataset returned"
    );

    // 2) Exercise a command builder against real wire.
    println!("\n=== route_register /smoke/test ===");
    match engine.route_register("/smoke/test", 0, 100).await {
        Ok(resp) => {
            println!("route_register -> {} {}", resp.status_code, resp.status_text);
            if resp.is_ok() {
                // 3) Re-poll; RIB registration may propagate into the FIB.
                let _ = engine.poll_forwarding().await;
                let prefixes: Vec<_> = engine
                    .state()
                    .routes
                    .iter()
                    .map(|r| r.prefix.clone())
                    .collect();
                println!("routes after register: {prefixes:?}");
            }
        }
        // A fresh forwarder with no trust anchor may refuse signed commands;
        // that's a forwarder policy outcome, not a cutover failure — report it.
        Err(e) => println!("route_register rejected (forwarder policy): {e}"),
    }

    println!("\n=== smoke OK: engine drove a live forwarder ===");
}
