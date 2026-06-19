//! MT7612U high-throughput `FrameIo`/NDN integration. Demonstrates the production
//! path that bakes in the throughput findings:
//!   * `start_high_throughput()` — firmware → 5 GHz ch36 VHT80 → 2 spatial streams
//!     → background TX pump (pipelined) + RX pump (continuous capture).
//!   * a large send MTU (`MAX_MPDU_PAYLOAD` ≈ 5650 B) so the link service packs
//!     more NDN bytes per frame — plain DATA frames radiate intact to ~5700 B,
//!     giving ~142 Mb/s at VHT80 2×2 SGI (vs ~37 Mb/s at a 1500 B MTU).
//!   * inject at a VHT MCS9 2-stream short-GI rate.
//!
//! Verify radiation on a second monitor receiver (or the co-located MT7612) by
//! searching for the NDN source MAC (02:4e:44:4e:00:01) + ethertype 0x8624.
//! `cargo run -p ndn-face-monitor-wifi --features libusb-backend --example mt7612_frameio`
#[cfg(feature = "libusb-backend")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use bytes::Bytes;
    use ndn_face_monitor_wifi::{
        FaceId, FrameIo, InjectFrame, McsDescriptor, MonitorWifiFace, Mt7612uBackend,
    };
    use std::sync::Arc;
    use std::time::Instant;

    println!("opening MT7612U ...");
    let dev = Arc::new(Mt7612uBackend::open()?);
    // One call: firmware + 5 GHz VHT80 + 2 streams + TX/RX pumps.
    dev.start_high_throughput()?;
    println!(
        "chip 0x{:04x}  high-throughput path up (5 GHz ch36 VHT80, 2SS, MTU {})",
        dev.chip_id()?,
        Mt7612uBackend::MAX_MPDU_PAYLOAD
    );

    // The actual NDN face: wrap the backend, set the verified large MTU so the
    // LpLinkService fragments NDN packets into ~5650 B frames (not 2296 B). This
    // `Face` plugs into a forwarder; here we just build it to show the wiring.
    let _face = MonitorWifiFace::new(FaceId(1), dev.clone())
        .with_mtu(Mt7612uBackend::MAX_MPDU_PAYLOAD)
        .into_face();

    // Drive the FrameIo surface directly at the throughput rate + frame size.
    let mcs = McsDescriptor {
        short_gi: true,
        ..McsDescriptor::vht_2ss(9)
    };
    let payload = Bytes::from(vec![0xA5u8; 4000]); // big frame → amortise the ~300µs/MPDU
    let frame = InjectFrame::broadcast(payload, mcs);
    let n = 20_000u32;
    let t = Instant::now();
    let mut ok = 0u32;
    for _ in 0..n {
        if dev.inject(frame.clone()).await.is_ok() {
            ok += 1;
        }
    }
    let el = t.elapsed().as_secs_f64();
    let mbps = (ok as f64 * 4000.0 * 8.0) / el / 1e6;
    println!(
        "FrameIo inject (VHT80 MCS9 2SS SGI, 4000 B): {ok}/{n} in {el:.1}s ≈ {mbps:.0} Mb/s payload"
    );
    println!("verify: search a monitor RX for SA 02:4e:44:4e:00:01 / ethertype 86 24.");
    Ok(())
}
#[cfg(not(feature = "libusb-backend"))]
fn main() {}
