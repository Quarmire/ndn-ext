//! Minimal USB enumerator via the same rusb stack the userspace backends use —
//! shows every device's vid:pid/class and, for Realtek (0x0bda), its interfaces
//! and bulk endpoints. Use to identify a dongle (incl. CD-ROM "installer" mode).
//! `cargo run -p ndn-face-monitor-wifi --features libusb-backend --example usb_list`
#[cfg(feature = "libusb-backend")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use rusb::UsbContext;
    let ctx = rusb::Context::new()?;
    for dev in ctx.devices()?.iter() {
        let d = dev.device_descriptor()?;
        let realtek = d.vendor_id() == 0x0bda;
        println!(
            "bus {:03} addr {:03}  {:04x}:{:04x}  dev-class {:#04x}{}",
            dev.bus_number(),
            dev.address(),
            d.vendor_id(),
            d.product_id(),
            d.class_code(),
            if realtek { "   <-- Realtek" } else { "" }
        );
        if !realtek {
            continue;
        }
        if let Ok(cfg) = dev.active_config_descriptor() {
            for iface in cfg.interfaces() {
                for id in iface.descriptors() {
                    println!(
                        "    iface {} alt {}  class {:#04x} sub {:#04x}",
                        id.interface_number(),
                        id.setting_number(),
                        id.class_code(),
                        id.sub_class_code()
                    );
                    for ep in id.endpoint_descriptors() {
                        println!(
                            "        ep {:#04x}  {:?}  {:?}  max {}",
                            ep.address(),
                            ep.direction(),
                            ep.transfer_type(),
                            ep.max_packet_size()
                        );
                    }
                }
            }
        }
    }
    Ok(())
}
#[cfg(not(feature = "libusb-backend"))]
fn main() {}
