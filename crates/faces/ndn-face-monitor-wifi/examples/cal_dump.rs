//! Bring up the RTL8812EU userspace driver and dump BB + RF registers in the
//! golden-dump layout, so the broken (no-on-air) state can be diffed against
//! `golden/opi0-2026-06-12/` — which was captured from the *same physical
//! dongle* (MAC 78:22:88:d9:93:e6) while it radiated on the kernel driver.
//!
//! ```text
//! cargo run --example cal_dump -p ndn-face-monitor-wifi \
//!     --features libusb-backend -- [channel]            # default 161 (golden)
//! ```

#[cfg(feature = "libusb-backend")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use ndn_face_monitor_wifi::{LibUsbRtl88xxBackend, RfPath};

    let channel: u8 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(161);

    let b = LibUsbRtl88xxBackend::open()?;
    b.bring_up(channel)?;
    eprintln!("# brought up on ch{channel}");

    println!("======= BB REG =======");
    // Path-A BB 0x0800-0x1ffc, then path-B window 0x4000-0x41fc (golden range).
    for &(lo, hi) in &[(0x0800u16, 0x1ffcu16), (0x4000, 0x41fc)] {
        let mut addr = lo;
        while addr <= hi {
            print!("0x{addr:04x} ");
            for _ in 0..4 {
                if addr <= hi {
                    print!("0x{:08x}  ", b.read32(addr)?);
                }
                addr = addr.wrapping_add(4);
            }
            println!();
        }
    }

    println!("======= RF REG =======");
    for (pi, path) in [RfPath::A, RfPath::B].into_iter().enumerate() {
        println!("RF_Path({pi})");
        let mut reg = 0u32;
        while reg <= 0xfc {
            print!("0x{reg:02x}  ");
            for _ in 0..4 {
                if reg <= 0xfc {
                    print!("0x{:08x}  ", b.rf_read(path, reg, 0xfffff)?);
                }
                reg += 1;
            }
            println!();
        }
    }
    Ok(())
}

#[cfg(not(feature = "libusb-backend"))]
fn main() {
    eprintln!("rebuild with `--features libusb-backend` (needs an RTL8812EU dongle)");
}
