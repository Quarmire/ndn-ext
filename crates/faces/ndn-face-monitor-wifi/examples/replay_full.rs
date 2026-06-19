//! Replay the working kernel driver's full captured register-init sequence
//! (golden usbmon `init_regseq.txt`, `addr width hexval`) on top of our
//! bring-up, then flood — the session-6d method that produced a radiating
//! state. Replays writes with `LO <= addr <= HI` (env, default 0x800..0xffff),
//! in capture order. If this radiates now and `bring_up` does not, binary-search
//! the LO/HI window to isolate the missing writes.
//!
//! ```text
//! [LO=0x1800] [HI=0x1fff] cargo run --example replay_full \
//!     -p ndn-face-monitor-wifi --features libusb-backend -- [channel] [count]
//! ```

#[cfg(feature = "libusb-backend")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use bytes::Bytes;
    use ndn_face_monitor_wifi::{InjectFrame, LibUsbRtl88xxBackend, McsDescriptor, FrameIo};
    use std::sync::Arc;

    const REGSEQ: &str = include_str!("../golden/opi-usbmon-2026-06-13/init_regseq.txt");
    let channel: u8 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(161);
    let count: usize = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(3000);
    let hex = |k: &str, d: u32| {
        std::env::var(k)
            .ok()
            .and_then(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).ok())
            .unwrap_or(d)
    };
    let (lo, hi) = (hex("LO", 0x800), hex("HI", 0xffff));
    let skip_bringup_bb = std::env::var("REPLAY_ONLY").is_ok();

    let b = LibUsbRtl88xxBackend::open()?;
    b.bring_up(channel)?;

    let mut n = 0u32;
    for line in REGSEQ.lines() {
        let mut it = line.split_whitespace();
        let (Some(a), Some(w), Some(v)) = (it.next(), it.next(), it.next()) else {
            continue;
        };
        let addr = u32::from_str_radix(a.trim_start_matches("0x"), 16).unwrap_or(0);
        let val = u32::from_str_radix(v.trim_start_matches("0x"), 16).unwrap_or(0);
        if !(lo..=hi).contains(&addr) {
            continue;
        }
        match w {
            "1" => b.write8(addr as u16, val as u8)?,
            "2" => b.write16(addr as u16, val as u16)?,
            _ => b.write32(addr as u16, val)?,
        }
        n += 1;
    }
    let _ = skip_bringup_bb;
    b.set_channel_bw20(channel)?;
    println!("replayed {n} writes in [{lo:#x},{hi:#x}] on ch{channel}");

    let backend = Arc::new(b);
    let data: Bytes = (0..1400u32).map(|i| (i & 0xff) as u8).collect();
    let mcs = McsDescriptor {
        index: 1,
        short_gi: false,
        vht: false,
                        nss: 1,
                        stbc: false,
                        ldpc: false,    };
    println!("flooding {count} frames at MCS1…");
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
