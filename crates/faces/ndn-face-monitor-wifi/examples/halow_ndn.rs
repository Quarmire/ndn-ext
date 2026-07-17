//! NDN-over-HaLow on-air test: inject / capture named-data frames on an
//! 802.11ah (S1G) monitor interface — a Newracom NRC7292 (`halow0`) — via the
//! kernel `AF_PACKET` path, the same seam the 2.4/5 GHz monitor faces use. This
//! is the HaLow radio taking its place in the named-radio pool.
//!
//! Prereqs (per board): the NRC7292 driver with the `inject_monitor` patch, and
//! the interface in monitor mode on a shared S1G channel:
//!   sudo iw dev halow0 set type monitor
//!   sudo ip link set halow0 up
//!   sudo iw reg set US
//!   sudo iw dev halow0 set channel 161   # 925 MHz
//!
//! Run (needs CAP_NET_RAW, i.e. sudo):
//!   RX board:  cargo run -p ndn-face-monitor-wifi --example halow_ndn -- rx
//!   TX board:  cargo run -p ndn-face-monitor-wifi --example halow_ndn -- tx
//! Optional 2nd arg = interface (default halow0), NDN_HALOW_COUNT env = TX frames.
//!
//! `rx` hearing `tx`'s marker frames proves the HaLow radio radiates
//! named-data frames on-air and a peer recovers the NDN payload — the same
//! `FrameFormat::RawNdnS1g` build/parse the engine uses through
//! `MonitorWifiFace::halow`.

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use bytes::Bytes;
    use ndn_face_monitor_wifi::{AfPacketBackend, FrameFormat, FrameIo, InjectFrame, TxIntent};
    use std::time::Duration;

    let role = std::env::args().nth(1).unwrap_or_else(|| "rx".into());
    let iface = std::env::args().nth(2).unwrap_or_else(|| "halow0".into());
    let count: u32 = std::env::var("NDN_HALOW_COUNT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(200);
    const MARKER: &[u8] = b"NDN-HALOW-onair";

    // Same format the pooled `MonitorWifiFace::halow` uses: an NDN data frame on
    // the S1G PHY (radiotap names no MCS — the NRC7292 MAC sets the sub-GHz rate).
    let backend = AfPacketBackend::new(&iface, FrameFormat::RawNdnS1g { ethertype: 0x8624 })?;
    println!("halow_ndn: role={role} iface={iface}");

    match role.as_str() {
        "tx" => {
            for i in 0..count {
                let mut p = MARKER.to_vec();
                p.extend_from_slice(&i.to_le_bytes());
                backend
                    .inject(InjectFrame::broadcast(Bytes::from(p), TxIntent::CONSERVATIVE))
                    .await?;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            println!("injected {count} NDN-over-HaLow frames on {iface}");
        }
        "rx" => {
            println!("listening on {iface} for NDN-over-HaLow frames (Ctrl-C to stop)…");
            let mut heard = 0u32;
            loop {
                match backend.recv_frame().await {
                    Ok(f) if f.payload.starts_with(MARKER) => {
                        heard += 1;
                        let seq = f
                            .payload
                            .get(MARKER.len()..MARKER.len() + 4)
                            .map(|b| u32::from_le_bytes(b.try_into().unwrap()));
                        println!(
                            "heard #{heard}: seq={seq:?} rssi={:?} dBm from {:02x?}",
                            f.rssi_dbm, f.addr
                        );
                    }
                    Ok(_) => {} // some other on-air frame; ignore
                    Err(e) => {
                        eprintln!("recv error: {e}");
                        break;
                    }
                }
            }
        }
        other => {
            eprintln!("unknown role {other:?}; use 'tx' or 'rx'");
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("halow_ndn requires Linux AF_PACKET (run it on the NRC7292 host, e.g. the ODROID-C4 / OPi 5 Pro)");
}
