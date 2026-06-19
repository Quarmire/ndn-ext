//! Verify thermal TX-power tracking: read the thermal meter, heat the PA with a
//! flood, then run thermal_track and report the compensation offset.
#[cfg(feature = "libusb-backend")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use bytes::Bytes;
    use ndn_face_monitor_wifi::{
        InjectFrame, LibUsbRtl88xxBackend, McsDescriptor, FrameIo, RfPath,
    };
    use std::sync::Arc;
    let b = Arc::new(LibUsbRtl88xxBackend::open_monitor(161)?);
    println!(
        "cal thermal (A/B) = {} / {}",
        b.read_thermal(RfPath::A)?,
        b.read_thermal(RfPath::B)?
    );
    let data: Bytes = (0..1400u32).map(|i| (i & 0xff) as u8).collect();
    let mcs = McsDescriptor::ht(1);
    for round in 0..4 {
        for _ in 0..15000 {
            b.inject(InjectFrame::broadcast(data.clone(), mcs)).await?;
        }
        let t = b.read_thermal(RfPath::A)?;
        let off = b.thermal_track()?;
        println!("round {round}: thermal={t}  track offset={off:+} TXAGC idx");
    }
    Ok(())
}
#[cfg(not(feature = "libusb-backend"))]
fn main() {}
