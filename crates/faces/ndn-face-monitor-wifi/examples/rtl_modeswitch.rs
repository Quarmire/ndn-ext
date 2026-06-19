//! Mode-switch a Realtek RTL88xxCU dongle out of its CD-ROM "driver installer"
//! mode (`0bda:1a2b`) into WiFi mode (`0bda:c811`/`c820`/...). Linux does this
//! via usb_modeswitch udev rules; macOS doesn't, so send the SCSI eject
//! (START STOP UNIT, LOEJ) directly over the mass-storage bulk-OUT endpoint.
//! `cargo run -p ndn-face-monitor-wifi --features libusb-backend --example rtl_modeswitch`
#[cfg(feature = "libusb-backend")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use rusb::{Context, Direction, TransferType, UsbContext};
    use std::time::{Duration, Instant};

    // SCSI START STOP UNIT with LOEJ=1 (eject) — the Realtek mode-switch trigger.
    let mut cbw = [0u8; 31];
    cbw[0..4].copy_from_slice(b"USBC");
    cbw[4..8].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    cbw[14] = 6; // CB length
    cbw[15] = 0x1b; // START STOP UNIT
    cbw[19] = 0x02; // LOEJ=1

    let secs: u64 = std::env::var("NDN_RADIO_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(45);
    println!("RACING the macOS mass-storage driver for ~{secs}s.");
    println!(">>> UNPLUG the dongle, wait 2s, then PLUG IT BACK IN now. <<<");
    println!("(I'll grab + eject it the instant it enumerates, before macOS claims it.)");

    let deadline = Instant::now() + Duration::from_secs(secs);
    let mut last_seen = false;
    let mut attempts = 0u64;
    while Instant::now() < deadline {
        let ctx = Context::new()?;
        let found = ctx.devices()?.iter().find(|d| {
            d.device_descriptor()
                .map(|x| x.vendor_id() == 0x0bda && x.product_id() == 0x1a2b)
                .unwrap_or(false)
        });
        match found {
            None => {
                if last_seen {
                    println!("dongle gone (replugging?) — ready to pounce ...");
                }
                last_seen = false;
            }
            Some(dev) => {
                last_seen = true;
                if let Ok(handle) = dev.open() {
                    let _ = handle.set_auto_detach_kernel_driver(true);
                    if let Ok(cfg) = dev.active_config_descriptor() {
                        let (mut iface_n, mut ep_out, mut ep_in) = (0u8, 0u8, 0u8);
                        for iface in cfg.interfaces() {
                            for d in iface.descriptors() {
                                for ep in d.endpoint_descriptors() {
                                    if ep.transfer_type() == TransferType::Bulk {
                                        match ep.direction() {
                                            Direction::Out => { iface_n = iface.number(); ep_out = ep.address(); }
                                            Direction::In => ep_in = ep.address(),
                                        }
                                    }
                                }
                            }
                        }
                        let _ = handle.detach_kernel_driver(iface_n);
                        if handle.claim_interface(iface_n).is_ok() {
                            println!("\n*** WON THE RACE (after {attempts} tries)! claimed iface {iface_n}, sending eject ... ***");
                            let _ = handle.write_bulk(ep_out, &cbw, Duration::from_millis(500));
                            let mut csw = [0u8; 13];
                            let _ = handle.read_bulk(ep_in, &mut csw, Duration::from_millis(300));
                            println!("eject sent — dongle should re-enumerate as WiFi mode (0bda:c811/c820).");
                            std::thread::sleep(Duration::from_secs(2));
                            return Ok(());
                        }
                    }
                }
                attempts += 1;
            }
        }
        // Spin fast to catch the post-enumeration / pre-kernel-attach window.
        std::thread::sleep(Duration::from_micros(200));
    }
    println!("\nTimed out after {attempts} claim attempts — macOS won every race (kernel driver");
    println!("attaches during enumeration, before user space can claim). This dongle can't be");
    println!("mode-switched on macOS.");
    Ok(())
}
#[cfg(not(feature = "libusb-backend"))]
fn main() {}
