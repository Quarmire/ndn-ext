//! First hardware milestone for the RTL8821CU userspace port: open the dongle
//! (`0bda:c820`), read its cut version + MAC, run the staged monitor bring-up,
//! and capture a few ambient frames. Run on the bring-up host with the dongle's
//! kernel driver unbound (the backend auto-detaches it on Linux):
//!
//! ```text
//! cargo run -p ndn-face-monitor-wifi --features libusb-backend --example whoami8821c
//! # diff the bring-up register writes against the golden usbmon trace:
//! NDN_RADIO_LOG_WRITES=1 cargo run ... --example whoami8821c 2> writes.txt
//! ```
#[cfg(feature = "libusb-backend")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use ndn_face_monitor_wifi::{FrameIo, Rtl8821cuBackend};
    use std::time::Duration;

    let channel: u8 = std::env::var("NDN_RADIO_CHANNEL")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(36);

    // Open + identify before the full bring-up.
    let dev = Rtl8821cuBackend::open()?;
    let sys_cfg1 = dev.read32(0x00f0)?;
    println!("REG_SYS_CFG1 (0x00f0) = {sys_cfg1:#010x}  cut={}", (sys_cfg1 >> 12) & 0xf);
    let mut mac = [0u8; 6];
    for (i, m) in mac.iter_mut().enumerate() {
        *m = dev.read8(0x0610 + i as u16)?;
    }
    println!(
        "MACID (0x0610) = {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    );

    println!("bringing up monitor on channel {channel} ...");
    dev.bring_up(channel)?;

    let (rfe, btg) = dev.rfe_profile();
    println!("RFE profile (efuse): rfe_option={rfe:#04x} btg={btg}{}",
        if rfe == 0xff { "  (efuse read FAILED — using defaults)" } else { "" });

    // Firmware liveness: REG_MCUFW_CTRL FW_INIT_RDY(bit15)/FW_DW_RDY(bit14) show
    // the fw booted; the H2C write/read pointers show whether the fw is actually
    // *consuming* the H2C queue (we sent general_info/phydm_info/iqk). If write
    // races ahead of read, the fw isn't processing H2C → DIG never runs → deaf RX.
    let mcufw = dev.read32(0x0080)?;
    println!(
        "FW: MCUFW_CTRL(0x80)={mcufw:#06x}  INIT_RDY={} DW_RDY={}",
        (mcufw >> 15) & 1,
        (mcufw >> 14) & 1
    );
    let h2c_w = dev.read32(0x10d4)? & 0x3ffff;
    let h2c_r = dev.read32(0x10d0)? & 0x3ffff;
    println!("FW: H2C_PKT write_addr(0x10d4)={h2c_w:#06x}  read_addr(0x10d0)={h2c_r:#06x}  {}",
        if h2c_w == h2c_r { "(fw consumed all H2C — alive)" } else { "(fw NOT consuming H2C — stuck/dead)" });
    // RF register dump: if these are all the same constant, RF *reads* are
    // broken; if varied, the read path works and a write/tune issue remains.
    for rf in [0x00u8, 0x18, 0x25, 0x42, 0xb8, 0xef] {
        println!("  RF_A {rf:#04x} = {:#07x}", dev.read_rf(rf, 0xfffff)?);
    }

    // Localize the RX bug: BB false-alarm counters (FA_CCK 0xa5c / FA_OFDM
    // 0xf48) climb if the RF/BB detects energy; RXPKT_NUM (0x284) climbs if the
    // MAC receives frames into the FIFO. Sample before/after the listen:
    //  - FA climbs + RXPKT climbs + bulk-IN zero  → MAC→USB DMA is broken.
    //  - FA climbs + RXPKT zero                    → MAC RX filter/enable issue.
    //  - FA zero                                   → RF/BB receiver is deaf.
    dev.debug_reset_rx_counters()?; // kick the BB counters so they accumulate
    let fa0 = (dev.read16(0x0a5c)?, dev.read16(0x0f48)?, dev.read32(0x0284)?);

    println!("listening 5s for ambient frames ...");
    // Start the background RX pump (concurrent bulk-IN reads) then drain.
    let dev = std::sync::Arc::new(dev);
    dev.spawn_rx_pump(4);
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut n = 0;
    while std::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(500), dev.recv_frame()).await {
            Ok(Ok(f)) => {
                n += 1;
                println!(
                    "  frame #{n}: {} bytes  rssi={:?}  mcs={:?}",
                    f.payload.len(),
                    f.rssi_dbm,
                    f.mcs_index
                );
            }
            _ => {}
        }
    }
    let fa1 = (dev.read16(0x0a5c)?, dev.read16(0x0f48)?, dev.read32(0x0284)?);
    // CRC counters (frames the BB actually demodulated): CCK 0xf04, OFDM 0xf14;
    // low16 = CRC-ok count, high16 = CRC-err count.
    let crc_cck = dev.read32(0x0f04)?;
    let crc_ofdm = dev.read32(0x0f14)?;
    println!(
        "BB RX counters (delta over listen): FA_CCK={} FA_OFDM={} RXPKT_NUM={}",
        fa1.0.wrapping_sub(fa0.0),
        fa1.1.wrapping_sub(fa0.1),
        fa1.2.wrapping_sub(fa0.2)
    );
    println!(
        "BB CRC counters: CCK ok={} err={} | OFDM ok={} err={}  (>0 ⇒ BB demodulating frames)",
        crc_cck & 0xffff, crc_cck >> 16, crc_ofdm & 0xffff, crc_ofdm >> 16
    );

    // The honest receiver test: raw 802.11 frames seen on air (ch1/2.4 GHz is
    // full of beacons, so >0 means RX works), independent of NDN payloads.
    println!(
        "RX RESULT: {} raw 802.11 frames captured on air; {n} of them were NDN-format",
        dev.raw_rx_count()
    );
    if dev.raw_rx_count() == 0 {
        println!("  (zero raw frames → receiver not delivering to USB yet)");
    }

    // TX liveness: inject a burst and watch REG_TXPKT_EMPTY (0x041A) — a per-queue
    // "empty" bitmap. If the queue drains back to empty, the chip keyed the frames
    // onto air; if a bit stays cleared, frames are stuck in the FIFO (PA gated /
    // not keying — the 8812EU failure mode). On-air confirmation still needs a
    // co-located receiver, but draining proves the MAC/PHY TX path runs.
    use ndn_face_monitor_wifi::{InjectFrame, McsDescriptor};
    let txempty_before = dev.read16(0x041a)?;
    let mut tx_ok = 0u32;
    for i in 0..100u32 {
        let payload = bytes::Bytes::from(format!("/ndn/tx-test/{i}").into_bytes());
        match dev.inject(InjectFrame::broadcast(payload, McsDescriptor::CONSERVATIVE)).await {
            Ok(()) => tx_ok += 1,
            Err(e) => {
                println!("TX: inject #{i} failed: {e}");
                break;
            }
        }
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let txempty_after = dev.read16(0x041a)?;
    println!(
        "TX: {tx_ok}/100 frames accepted by USB; TXPKT_EMPTY before={txempty_before:#06x} after={txempty_after:#06x} {}",
        if txempty_after == txempty_before { "(queues drained — TX path keying)" } else { "(queue stuck — frames not keyed)" }
    );
    Ok(())
}
#[cfg(not(feature = "libusb-backend"))]
fn main() {}
