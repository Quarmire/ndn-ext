//! Bring up the dongle, optionally overwrite the BB registers that differ from
//! the golden (same-dongle, kernel-radiating) capture, then flood frames — to
//! test empirically whether the broken-vs-golden BB diff is the on-air TX gate.
//!
//! ```text
//! FORCE_GOLDEN=1 cargo run --example force_golden_flood -p ndn-face-monitor-wifi \
//!     --features libusb-backend -- [channel] [count]   # default ch161, 10000
//! ```

#[cfg(feature = "libusb-backend")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use bytes::Bytes;
    use ndn_face_monitor_wifi::{InjectFrame, LibUsbRtl88xxBackend, McsDescriptor, FrameIo};
    use std::sync::Arc;

    // The 31 BB registers where my bring-up differs from golden (golden values).
    const GOLDEN_BB: &[(u16, u32)] = &[
        (0x0820, 0x11111131),
        (0x0828, 0x30fb181c),
        (0x084c, 0xa8b05555),
        (0x1868, 0x000ff3fd),
        (0x18a0, 0x003b0002),
        (0x1a2c, 0x12baa000),
        (0x1a30, 0x02eb0800),
        (0x1a34, 0x02e93800),
        (0x1a48, 0x00080000),
        (0x1a4c, 0xb0000080),
        (0x1a50, 0x96080000),
        (0x1a54, 0x1000e30b),
        (0x1a58, 0x00005881),
        (0x1a60, 0xfefe0000),
        (0x1a68, 0x000000eb),
        (0x1a6c, 0x00000015),
        (0x1ac8, 0x00000807),
        (0x1b14, 0x40000000),
        (0x1d70, 0x20201c1c),
        (0x1e40, 0xfffeffff),
        (0x1e44, 0x2824201c),
        (0x1e48, 0x3834302c),
        (0x1e50, 0x2824201c),
        (0x1e54, 0x3834302c),
        (0x1e58, 0xfe44403c),
        (0x1e5c, 0xc53c00ff),
        (0x1e60, 0x4440412f),
        (0x1eb8, 0x00000b00),
        (0x4168, 0x000ffbff),
        (0x41a0, 0x003b0002),
        (0x41e8, 0x00010e00),
    ];

    let channel: u8 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(161);
    let count: usize = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(10000);
    let mcs_idx: u8 = std::env::args()
        .nth(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);

    let backend = Arc::new(LibUsbRtl88xxBackend::open_monitor(channel)?);
    println!("up on ch{channel}");

    if std::env::var("FORCE_GOLDEN").is_ok() {
        for &(a, v) in GOLDEN_BB {
            backend.write32(a, v)?;
        }
        println!("forced {} golden BB regs", GOLDEN_BB.len());
    }

    let data: Bytes = (0..1400u32).map(|i| (i & 0xff) as u8).collect();
    let mcs = McsDescriptor {
        index: mcs_idx,
        short_gi: false,
        vht: false,
                        nss: 1,
                        stbc: false,
                        ldpc: false,    };
    println!("flooding {count} frames at MCS{mcs_idx}…");
    for _ in 0..count {
        backend
            .inject(InjectFrame::broadcast(data.clone(), mcs))
            .await?;
    }
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    println!("done");
    Ok(())
}

#[cfg(not(feature = "libusb-backend"))]
fn main() {}
