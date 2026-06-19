//! Face-level A-MSDU batching demo: drive `MonitorWifiFace::send_bytes` rapidly
//! with batching on, and the outbound frames coalesce into A-MSDU bursts (far
//! fewer, larger on-air MPDUs). With batching off, each send is one MPDU.
//!
//! Usage: `face_batch [ch] [total] [mcs] [max_msdus] [psize]`  env BATCH_OFF=1
#[cfg(feature = "libusb-backend")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use bytes::Bytes;
    use ndn_face_monitor_wifi::{LibUsbRtl88xxBackend, McsDescriptor, MonitorWifiFace};
    use ndn_transport::{FaceId, Transport};
    use std::sync::Arc;
    use std::time::Duration;

    let mut a = std::env::args().skip(1);
    let ch: u8 = a.next().and_then(|s| s.parse().ok()).unwrap_or(149);
    let total: usize = a.next().and_then(|s| s.parse().ok()).unwrap_or(8000);
    let mcs: u8 = a.next().and_then(|s| s.parse().ok()).unwrap_or(7);
    let max_msdus: usize = a.next().and_then(|s| s.parse().ok()).unwrap_or(16);
    let psize: usize = a.next().and_then(|s| s.parse().ok()).unwrap_or(256);

    let backend = Arc::new(LibUsbRtl88xxBackend::open_monitor(ch)?);
    let off = std::env::var("BATCH_OFF").is_ok();
    let mut face = MonitorWifiFace::new(FaceId(1), backend).with_fixed_mcs(McsDescriptor::ht(mcs));
    if !off {
        face = face.with_amsdu_batching(max_msdus, Duration::from_millis(5));
    }
    println!(
        "sending {total} x {psize}B via the face, batching {}",
        if off { "OFF (1 MPDU/send)".into() } else { format!("ON ({max_msdus}/A-MSDU, 5ms)") }
    );

    let data = Bytes::from(vec![0x5au8; psize]);
    let t0 = std::time::Instant::now();
    for _ in 0..total {
        face.send_bytes(data.clone()).await?;
    }
    // Let the last batch's flush window elapse + the FIFO drain.
    tokio::time::sleep(Duration::from_millis(400)).await;
    let dt = t0.elapsed().as_secs_f64();
    println!("submitted {total} frames in {dt:.2}s — count MPDUs at the peer", );
    Ok(())
}

#[cfg(not(feature = "libusb-backend"))]
fn main() {
    eprintln!("rebuild with `--features libusb-backend` (needs an RTL8812EU dongle)");
}
