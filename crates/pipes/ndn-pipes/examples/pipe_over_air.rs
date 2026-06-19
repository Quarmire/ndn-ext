//! Run a real NDN-Pipes transfer over the **802.11 monitor-mode named-radio
//! bearer** between two machines — no AP, no association, no IP. One board
//! produces, the other fetches; the SEEK→JOIN→CHECK handshake and the
//! encrypt-then-code bulk cross the air, fragmented by `LpLinkService` and
//! recovered by K-of-N FEC.
//!
//! Prereqs on each board (Linux, `CAP_NET_RAW`), both on the same channel:
//!   sudo iw dev wlan0 set type monitor && sudo ip link set wlan0 up
//!   sudo iw dev wlan0 set channel 6
//!
//! Build (e.g. for the Orange Pi target) and run:
//!   cargo build --example pipe_over_air -p ndn-pipes --release
//!   # producer board:
//!   sudo ./target/release/examples/pipe_over_air wlan0 produce /sensors/temp /v=42 4000
//!   # consumer board:
//!   sudo ./target/release/examples/pipe_over_air wlan0 fetch   /sensors/temp /v=42
//!
//! The 32-byte AEAD content key is hard-coded here for the demo (pre-shared);
//! in a real deployment it comes from the trust layer (NAC/ABE).

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;

    use ndn_app::{Consumer, EngineBuilder, Producer};
    use ndn_coding::FecPolicy;
    use ndn_engine::EngineConfig;
    use ndn_face_monitor_wifi::{
        AfPacketBackend, FrameFormat, McsDescriptor, MonitorWifiFace, FrameIo,
    };
    use ndn_face::local::InProcFace;
    use ndn_packet::Name;
    use ndn_pipes::{Confidentiality, PipeConsumer, PipeParams, PipeProducer};
    use ndn_transport::FaceId;

    const KEY: [u8; 32] = [7u8; 32];

    let mut args = std::env::args().skip(1);
    let usage = || -> ! {
        eprintln!("usage: pipe_over_air <iface> produce <namespace> <object> [size] [k] [n] [mcs]");
        eprintln!("       pipe_over_air <iface> fetch   <namespace> <object> [k] [n] [mcs]");
        eprintln!("  k/n = K-of-N FEC (more parity = more loss tolerance over the air)");
        std::process::exit(2)
    };
    let iface = args.next().unwrap_or_else(|| usage());
    let mode = args.next().unwrap_or_else(|| usage());
    let namespace = args.next().unwrap_or_else(|| usage());
    let object = args.next().unwrap_or_else(|| usage());
    let rest: Vec<String> = args.collect();
    let nth = |i: usize| rest.get(i).and_then(|s| s.parse::<usize>().ok());

    let root: Name = "/".parse().unwrap();
    let backend: Arc<dyn FrameIo> =
        Arc::new(AfPacketBackend::new(&iface, FrameFormat::default())?);
    // The radio is bound to the namespace as its name-group (the coupling) and
    // injects at a fixed, robust MCS.
    let mk_radio = |mcs: u8| {
        MonitorWifiFace::new(FaceId(10), Arc::clone(&backend))
            .with_name_group(namespace.as_str())
            .with_fixed_mcs(McsDescriptor::ht(mcs))
            .into_face()
    };

    match mode.as_str() {
        "produce" => {
            let size = nth(0).unwrap_or(4000);
            let k = nth(1).unwrap_or(8) as u16;
            let n = nth(2).unwrap_or(32) as u16;
            let mcs = nth(3).unwrap_or(1) as u8;
            let policy = FecPolicy::systematic(k, n).expect("valid FEC shape");
            let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let (app, app_handle) = InProcFace::new(FaceId(2), 256);
            let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
                .face(app)
                .face_composed(mk_radio(mcs))
                .build()
                .await?;
            engine.fib().add_nexthop(&root, FaceId(2), 0);

            let object_name: Name = format!("{namespace}{object}").parse()?;
            let producer = PipeProducer::new(Producer::from_handle(app_handle, root)).serve_object(
                &object_name,
                &payload,
                &policy,
                1,
                &[],
                &Confidentiality::Aead(KEY),
            );
            println!(
                "producing {size} bytes under {object_name} on {iface} \
                 (k={k} n={n} mcs={mcs}, name-group {namespace}); ^C to stop"
            );
            producer.serve().await?;
            shutdown.shutdown().await;
        }
        "fetch" => {
            let k = nth(0).unwrap_or(8) as u16;
            let n = nth(1).unwrap_or(32) as u16;
            let mcs = nth(2).unwrap_or(1) as u8;
            let (app, app_handle) = InProcFace::new(FaceId(1), 256);
            let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
                .face(app)
                .face_composed(mk_radio(mcs))
                .build()
                .await?;
            engine.fib().add_nexthop(&root, FaceId(10), 0);

            let mut pc = PipeConsumer::new(Consumer::from_handle(app_handle));
            println!("opening pipe to {namespace} over {iface} (k={k} n={n} mcs={mcs}) …");
            let pipe = pc
                .open(
                    namespace.as_str(),
                    PipeParams::default().with_fec(k, n).with_aead_key(KEY),
                )
                .await?;
            println!("pipe up (len={}); fetching {object} …", pipe.pipe_len);
            let got = pc.fetch(&pipe, object.as_str()).await?;
            let sum: u64 = got.iter().map(|&b| b as u64).sum();
            println!("recovered {} bytes (checksum {sum}); tearing down", got.len());
            pc.close(&pipe).await.ok();
            drop(pc);
            drop(engine);
            shutdown.shutdown().await;
        }
        _ => usage(),
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("pipe_over_air requires Linux AF_PACKET monitor-mode injection (CAP_NET_RAW).");
    std::process::exit(1);
}
