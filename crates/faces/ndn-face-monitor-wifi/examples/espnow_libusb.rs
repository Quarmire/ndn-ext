//! ESP-NOW probe over the **userspace RTL8812EU/8822E libusb backend** — the
//! macOS / no-kernel-monitor-driver counterpart to `espnow_probe` (which needs
//! Linux `AF_PACKET`). Injects / captures ESP-NOW vendor-action frames so a
//! plugged-in dongle can talk NDN-over-ESP-NOW to an ESP32.
//!
//! The compelling case is a **dual-band ESP32-C5**: these wfb dongles inject on
//! 5 GHz only, and the old 2.4 GHz-only ESP32-S3 could never hear them (the
//! documented "M2" gap). A C5 listening in `BandMode::_5G` on the same 5 GHz
//! channel closes it. On 5 GHz, inject at 6 Mbps OFDM (1 Mbps DSSS does not
//! exist there) — this probe defaults `NDN_RADIO_TX_RATE=4` for 5 GHz channels.
//!
//! Usage (build with the libusb backend; needs libusb-1.0 + dongle access):
//!   cargo run -p ndn-face-monitor-wifi --features libusb-backend \
//!       --example espnow_libusb -- <channel> send "<text>" [count=20]
//!   cargo run -p ndn-face-monitor-wifi --features libusb-backend \
//!       --example espnow_libusb -- <channel> recv
//! e.g. channel 36 or 161 for a 5 GHz ESP32-C5.

#[cfg(feature = "libusb-backend")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;

    use bytes::Bytes;
    use ndn_face_monitor_wifi::{
        ESPNOW_OUI, FrameFormat, FrameIo, InjectFrame, LibUsbRtl88xxBackend, McsDescriptor,
    };

    let mut args = std::env::args().skip(1);
    let channel: u8 = args
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| {
            eprintln!(
                "usage: espnow_libusb <channel> send \"<text>\" [count] | recv  (e.g. 36 for 5 GHz C5)"
            );
            std::process::exit(2);
        });
    let mode = args.next().unwrap_or_default();

    // On 5 GHz the lowest legacy rate is 6 Mbps OFDM (DESC_RATE 0x04); 1 Mbps
    // DSSS is 2.4 GHz-only. Default the TX-rate override so 5 GHz injects decode.
    if channel >= 36 && std::env::var_os("NDN_RADIO_TX_RATE").is_none() {
        // SAFETY: set before any radio thread is spawned (single-threaded here).
        unsafe { std::env::set_var("NDN_RADIO_TX_RATE", "4") };
        eprintln!("5 GHz channel {channel}: injecting at 6 Mbps OFDM (NDN_RADIO_TX_RATE=4)");
    }

    println!("opening RTL88xx in 5 GHz monitor mode on channel {channel} …");
    let backend = Arc::new(
        LibUsbRtl88xxBackend::open_monitor(channel)?
            .with_format(FrameFormat::EspNow { oui: ESPNOW_OUI }),
    );

    match mode.as_str() {
        "send" => {
            let text = args.next().unwrap_or_else(|| "ndn-lp-over-espnow".into());
            let count: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(20);
            println!("injecting {count} ESP-NOW frames ({} B) …", text.len());
            for _ in 0..count {
                backend
                    .inject(InjectFrame::broadcast(
                        Bytes::from(text.clone().into_bytes()),
                        McsDescriptor::CONSERVATIVE,
                    ))
                    .await?;
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            println!("done.");
        }
        "recv" => {
            println!("capturing ESP-NOW frames (ctrl-c to stop) …");
            loop {
                let f = backend.recv_frame().await?;
                let mac = f
                    .addr
                    .map(|a| a.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":"))
                    .unwrap_or_else(|| "??".into());
                println!(
                    "from {mac}  rssi={:?}  {} B  {:?}",
                    f.rssi_dbm,
                    f.payload.len(),
                    String::from_utf8_lossy(&f.payload)
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

#[cfg(not(feature = "libusb-backend"))]
fn main() {
    eprintln!("espnow_libusb requires `--features libusb-backend` (userspace RTL88xx driver).");
    std::process::exit(1);
}
