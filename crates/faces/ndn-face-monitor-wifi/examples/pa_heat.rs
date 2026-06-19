//! In-isolation TX-PA health test: read the die thermal sensor before, during,
//! and after a sustained full-power flood. A working PA emitting ~20 dBm warms
//! the die several counts over ~30 s; a dead/degraded PA (RX fine, TX FIFO
//! drains, but no RF out) stays cold.
#[cfg(feature = "libusb-backend")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use bytes::Bytes;
    use ndn_face_monitor_wifi::{InjectFrame, LibUsbRtl88xxBackend, McsDescriptor, FrameIo, RfPath};
    use std::sync::Arc;
    let b = Arc::new(LibUsbRtl88xxBackend::open_monitor(149)?);
    b.set_tx_power(0x3f)?;
    let data: Bytes = (0..1400u32).map(|i| (i & 0xff) as u8).collect();
    println!("thermal before: A={} B={}", b.read_thermal(RfPath::A)?, b.read_thermal(RfPath::B)?);
    for round in 0..6 {
        for _ in 0..3000 {
            b.inject(InjectFrame::broadcast(data.clone(), McsDescriptor::ht(0))).await?;
        }
        println!("round {round}: thermal A={} B={}", b.read_thermal(RfPath::A)?, b.read_thermal(RfPath::B)?);
    }
    Ok(())
}
#[cfg(not(feature = "libusb-backend"))]
fn main() {}
