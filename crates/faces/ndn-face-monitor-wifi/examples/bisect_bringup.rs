//! Bisect what regressed the on-air TX between session-6d (worked) and now.
//! Composes the bring-up from the public steps; env flags add back the steps
//! that sessions 7–8 inserted into `bring_up` (`rx_path_init`,
//! `calibrate_tx_power`) one at a time, so we can see which kills TX.
//!
//! ```text
//! [ADD_RX=1] [ADD_CALTX=1] [SKIP_DPK=1] [SKIP_IQK=1] \
//! cargo run --example bisect_bringup -p ndn-face-monitor-wifi \
//!     --features libusb-backend -- [channel] [count]
//! ```

#[cfg(feature = "libusb-backend")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use bytes::Bytes;
    use ndn_face_monitor_wifi::{InjectFrame, LibUsbRtl88xxBackend, McsDescriptor, FrameIo};
    use std::sync::Arc;

    let channel: u8 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(161);
    let count: usize = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(3000);
    let env = |k: &str| std::env::var(k).is_ok();

    let b = LibUsbRtl88xxBackend::open()?;
    // Session-6d minimal bring-up.
    b.power_on()?;
    b.download_firmware(LibUsbRtl88xxBackend::firmware_nic())?;
    b.mac_init()?;
    b.monitor_cfg()?;
    b.send_general_info()?;
    b.phy_init()?;
    b.set_channel_bw20(channel)?;
    if !env("SKIP_IQK") {
        b.fw_iqk(false, false)?;
        print!("iqk ");
    }
    if !env("SKIP_DPK") {
        b.fw_dpk()?;
        print!("dpk ");
    }
    b.bb_tx_datapath_init()?;
    if env("ADD_RX") {
        b.rx_path_init()?;
        print!("rx_path ");
    }
    if env("ADD_CALTX") {
        let (a, c) = b.calibrate_tx_power(channel)?;
        print!("caltx(a={a:#x},b={c:#x}) ");
    }
    b.set_channel_bw20(channel)?;
    println!("\nbrought up on ch{channel}");

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
