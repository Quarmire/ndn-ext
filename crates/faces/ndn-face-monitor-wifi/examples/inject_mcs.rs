//! Phase-0 spike: prove that monitor-mode injection transmits at the MCS we
//! ask for — i.e. that the "broadcast is stuck at legacy rates" wall is a
//! managed-mode artifact, not a hardware one.
//!
//! Injects a burst of raw 802.11 frames at a chosen MCS on a monitor-mode
//! interface. Capture on a *second* monitor dongle and confirm the radiotap RX
//! rate matches the requested MCS (not a 1/6/24 Mbps legacy floor). The witness
//! `testbed/bench/wifi_inject_rate.sh` automates the capture+assert.
//!
//! Prereqs (Linux, `CAP_NET_RAW`):
//!   sudo iw dev wlan0 set type monitor && sudo ip link set wlan0 up
//!   sudo iw dev wlan0 set channel 6
//!
//! Usage:
//!   cargo build --example inject_mcs -p ndn-face-monitor-wifi --release
//!   sudo ./target/release/examples/inject_mcs <iface> [mcs=3] [count=1000] [size=800]

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;

    use bytes::Bytes;
    use ndn_face_monitor_wifi::{
        AfPacketBackend, FrameFormat, InjectFrame, McsDescriptor, FrameIo,
    };

    let mut args = std::env::args().skip(1);
    let iface = args.next().unwrap_or_else(|| {
        eprintln!("usage: inject_mcs <iface> [mcs] [count] [size]");
        std::process::exit(2);
    });
    let mcs: u8 = args.next().and_then(|s| s.parse().ok()).unwrap_or(3);
    let count: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(1000);
    let size: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(800);

    let backend = Arc::new(AfPacketBackend::new(&iface, FrameFormat::default())?);
    let payload = Bytes::from(vec![0xABu8; size]);

    println!("injecting {count} frames of {size} B at MCS{mcs} on {iface} …");
    for _ in 0..count {
        backend
            .inject(InjectFrame::broadcast(
                payload.clone(),
                McsDescriptor {
                    index: mcs,
                    short_gi: false,
                    vht: false,
                        nss: 1,
                        stbc: false,
                        ldpc: false,                },
            ))
            .await?;
    }
    println!(
        "done. capture on a second monitor dongle and confirm the radiotap RX \
         rate matches MCS{mcs} (not a legacy 1/6/24 Mbps floor)."
    );
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("inject_mcs requires Linux AF_PACKET monitor-mode injection (CAP_NET_RAW).");
    std::process::exit(1);
}
