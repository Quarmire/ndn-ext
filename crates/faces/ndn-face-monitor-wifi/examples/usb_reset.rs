//! Soft-replug: issue a libusb device reset to the RTL8812EU to clear a wedged
//! chip TX state (e.g. after a bad bandwidth switch) without a physical unplug,
//! then bring it up and flood to verify the TX path recovered.
#[cfg(feature = "libusb-backend")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use bytes::Bytes;
    use ndn_face_monitor_wifi::{
        InjectFrame, LibUsbRtl88xxBackend, McsDescriptor, FrameIo, RTL88XX_PIDS, REALTEK_VID,
    };
    use rusb::UsbContext;
    use std::sync::Arc;

    let ctx = rusb::Context::new()?;
    let mut n = 0;
    for dev in ctx.devices()?.iter() {
        let d = dev.device_descriptor()?;
        if d.vendor_id() == REALTEK_VID && RTL88XX_PIDS.contains(&d.product_id()) {
            let h = dev.open()?;
            match h.reset() {
                Ok(()) => println!("USB reset OK: {:04x}:{:04x}", d.vendor_id(), d.product_id()),
                Err(e) => println!("USB reset err ({e}) on {:04x}", d.product_id()),
            }
            n += 1;
        }
    }
    println!("{n} dongle(s) reset; waiting for re-enumeration");
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

    let b = Arc::new(LibUsbRtl88xxBackend::open_monitor(149)?);
    let data: Bytes = (0..1400u32).map(|i| (i & 0xff) as u8).collect();
    for _ in 0..4000 {
        b.inject(InjectFrame::broadcast(data.clone(), McsDescriptor::ht(1)))
            .await?;
    }
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    println!("reset + bring_up + 20MHz flood done");
    Ok(())
}
#[cfg(not(feature = "libusb-backend"))]
fn main() {}
