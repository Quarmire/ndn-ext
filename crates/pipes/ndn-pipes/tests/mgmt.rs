//! Slice-8 witness: the read-only PIPES introspection module. After a consumer
//! opens a pipe, `/localhost/nfd/pipes/list` (the `pipes` MgmtModule over the
//! producer's shared registry) reports it; once it is torn down, the dataset
//! drops it. Mirrors `compute/list`.

use ndn_app::{Consumer, EngineBuilder, Producer};
use ndn_config::{ControlParameters, ForwarderConfig, control_response::status, nfd_command::verb};
use ndn_engine::{EngineConfig, ForwarderEngine};
use ndn_face::local::InProcFace;
use ndn_mgmt::module::{MgmtContext, MgmtModule};
use ndn_mgmt::MgmtResponse;
use ndn_packet::Name;
use ndn_transport::FaceId;
use tokio_util::sync::CancellationToken;

use ndn_pipes::{Confidentiality, PipeConsumer, PipeParams, PipeProducer, PipesModule};

/// A minimal engine-backed `MgmtContext` (the PIPES module ignores it, but the
/// trait requires one — same shape as the other read-only module tests).
fn ctx<'a>(
    engine: &'a ForwarderEngine,
    cancel: &'a CancellationToken,
    config: &'a ForwarderConfig,
) -> MgmtContext<'a> {
    MgmtContext {
        engine,
        cancel,
        source_face: None,
        face_provisioners: &[],
        control_surfaces: &[],
        config,
        pib: None,
        security_is_ephemeral: false,
        log_inspector: None,
        coding_handler: None,
        rate_limit_handler: None,
        compute_handler: None,
        webtransport_status_handler: None,
        ble_handler: None,
        approval_handler: None,
        runtime_policy: None,
        face_events: None,
        route_events: None,
        strategy_events: None,
    }
}

fn list_text(resp: &MgmtResponse) -> &str {
    match resp {
        MgmtResponse::Control(cr) => &cr.status_text,
        _ => panic!("expected a Control response"),
    }
}

#[tokio::test]
async fn pipes_list_reports_live_pipes() {
    let (consumer_face, consumer_handle) = InProcFace::new(FaceId(1), 256);
    let (producer_face, producer_handle) = InProcFace::new(FaceId(2), 256);
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(consumer_face)
        .face(producer_face)
        .build()
        .await
        .expect("engine build");
    let root: Name = "/".parse().unwrap();
    engine.fib().add_nexthop(&root, FaceId(2), 0);

    let producer = PipeProducer::new(Producer::from_handle(producer_handle, root)).serve_object(
        &"/sensors/temp/v=42".parse().unwrap(),
        b"unused",
        &ndn_coding::FecPolicy::systematic(8, 12).unwrap(),
        1,
        &[],
        &Confidentiality::None,
    );
    // Share the producer's live-pipe table with the introspection module before
    // serve() consumes the producer.
    let module = PipesModule::new(producer.registry());
    let serve = tokio::spawn(async move { producer.serve().await });

    let cancel = CancellationToken::new();
    let config = ForwarderConfig::default();

    // Before any pipe: the dataset is empty.
    let before = module.dispatch(verb::LIST, ControlParameters::default(), &ctx(&engine, &cancel, &config)).await;
    assert!(list_text(&before).starts_with("0 pipes"), "no pipes yet");

    // Open a pipe, then list: it appears with a hex id and a remaining PUI.
    let mut pc = PipeConsumer::new(Consumer::from_handle(consumer_handle));
    let pipe = pc.open("/sensors/temp", PipeParams::default()).await.expect("pipe");
    let listed = module.dispatch(verb::LIST, ControlParameters::default(), &ctx(&engine, &cancel, &config)).await;
    let text = list_text(&listed);
    let id_hex: String = pipe.id.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
    assert!(text.starts_with("1 pipes"), "one live pipe, got: {text}");
    assert!(text.contains(&id_hex), "lists the pipe's id {id_hex}, got: {text}");
    assert!(text.contains("pui_remaining="), "shows the remaining PUI");

    // Tear it down; the dataset drops it.
    pc.close(&pipe).await.expect("teardown acked");
    let after = module.dispatch(verb::LIST, ControlParameters::default(), &ctx(&engine, &cancel, &config)).await;
    assert!(list_text(&after).starts_with("0 pipes"), "torn-down pipe is gone");

    // Unknown verb → NOT_FOUND.
    let bad = module.dispatch(b"bogus", ControlParameters::default(), &ctx(&engine, &cancel, &config)).await;
    match bad {
        MgmtResponse::Control(cr) => assert_eq!(cr.status_code, status::NOT_FOUND),
        _ => panic!("expected control response"),
    }

    drop(pc);
    drop(engine);
    shutdown.shutdown().await;
    let _ = serve.await;
}
