//! Phase-3 ESP-NOW probe: inject / capture ESP-NOW vendor-action frames over a
//! monitor-mode dongle. Two uses:
//!   * dongle ↔ dongle — verify the on-air ESP-NOW byte layout (run `send` on
//!     one board, `recv` on another, same channel);
//!   * dongle ↔ ESP32 — the host side of the interop: an ESP32 running stock
//!     `esp-wifi` ESP-NOW receives `send`'s frames and its transmissions show
//!     up under `recv`.
//!
//! NB: a classic/-S3 ESP32 is **2.4 GHz only** — set the dongle to a 2.4 GHz
//! channel first (`iw dev <if> set channel 1`), not the 5 GHz wfb channel.
//!
//! Usage (Linux, CAP_NET_RAW):
//!   sudo ./espnow_probe <iface> send "<text>" [count=20] [mcs=0]
//!   sudo ./espnow_probe <iface> recv

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;

    use bytes::Bytes;
    use ndn_face_monitor_wifi::{
        AfPacketBackend, ESPNOW_OUI, FrameFormat, InjectFrame, McsDescriptor, FrameIo,
    };

    let mut args = std::env::args().skip(1);
    let iface = args.next().unwrap_or_else(|| {
        eprintln!("usage: espnow_probe <iface> send \"<text>\" [count] [mcs] | recv");
        std::process::exit(2);
    });
    let mode = args.next().unwrap_or_default();
    let backend = Arc::new(AfPacketBackend::new(
        &iface,
        FrameFormat::EspNow { oui: ESPNOW_OUI },
    )?);

    match mode.as_str() {
        "send" => {
            let text = args.next().unwrap_or_else(|| "ndn-lp-over-espnow".into());
            let count: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(20);
            let mcs: u8 = args.next().and_then(|s| s.parse().ok()).unwrap_or(0);
            println!(
                "injecting {count} ESP-NOW frames ({} B) on {iface} …",
                text.len()
            );
            for _ in 0..count {
                backend
                    .inject(InjectFrame::broadcast(
                        Bytes::from(text.clone().into_bytes()),
                        McsDescriptor {
                            index: mcs,
                            short_gi: false,
                            vht: false,
                        nss: 1,
                        stbc: false,
                        ldpc: false,                        },
                    ))
                    .await?;
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            println!("done.");
        }
        "recv" => {
            println!("capturing ESP-NOW frames on {iface} (ctrl-c to stop) …");
            loop {
                let f = backend.recv_frame().await?;
                let mac = f
                    .addr
                    .map(|a| {
                        a.iter()
                            .map(|b| format!("{b:02x}"))
                            .collect::<Vec<_>>()
                            .join(":")
                    })
                    .unwrap_or_else(|| "??".into());
                let text = String::from_utf8_lossy(&f.payload);
                println!(
                    "from {mac}  rssi={:?}  {} B  {:?}",
                    f.rssi_dbm,
                    f.payload.len(),
                    text
                );
            }
        }
        _ => {
            eprintln!("mode must be send|recv");
            std::process::exit(2);
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("espnow_probe requires Linux AF_PACKET monitor-mode injection.");
    std::process::exit(1);
}
