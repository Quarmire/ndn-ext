//! TX liveness / firmware-state self-check after a (re)plug. The chip can't see
//! its own FEM output (no TSSI on 8822E), so on-air liveness must be read at a
//! peer RX. What we CAN read on-chip is whether the firmware finished its IQK
//! (0x2d9c==0xaa) — the recurring "fw cal didn't land" suspicion. Floods a
//! short burst so a peer monitor can confirm radiation.
#[cfg(feature = "libusb-backend")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use bytes::Bytes;
    use ndn_face_monitor_wifi::{InjectFrame, LibUsbRtl88xxBackend, McsDescriptor, FrameIo};
    use std::sync::Arc;
    let ch: u8 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(149);
    let nframes: u32 = std::env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(2000);
    let mcs: u8 = std::env::args().nth(3).and_then(|s| s.parse().ok()).unwrap_or(1);
    let b = Arc::new(LibUsbRtl88xxBackend::open_monitor(ch)?);
    // RADIO_BW=40|80|10|5 switches the channel bandwidth (default 20 MHz).
    if let Ok(s) = std::env::var("RADIO_BW") {
        use ndn_face_monitor_wifi::ChannelBw;
        let bw = match s.as_str() {
            "40" => ChannelBw::Bw40,
            "80" => ChannelBw::Bw80,
            "10" => ChannelBw::Nb10,
            "5" => ChannelBw::Nb5,
            _ => ChannelBw::Bw20,
        };
        b.set_channel(ch, bw)?;
        println!("bandwidth set to {s} MHz (primary ch{ch})");
    }
    let iqk = b.read8(0x2d9c)?;
    println!(
        "fw IQK done-flag 0x2d9c = {:#04x}  -> {}",
        iqk,
        if iqk == 0xaa { "COMPLETED" } else { "NOT raised (fw cal did not land)" }
    );
    // a few more firmware/TX-state regs for context
    println!("  REG_MCUFW_CTRL 0x80 = {:#06x} (fw alive = 0xc078)", b.read16(0x0080)?);
    println!("  TX activity 0x2d08 = {:#010x}", b.read32(0x2d08)?);
    let data: Bytes = (0..1400u32).map(|i| (i & 0xff) as u8).collect();
    // RADIO_VHT=1 uses 802.11ac VHT (required for 80 MHz; HT is 20/40 only).
    // RADIO_NSS=2 selects 2 spatial streams (VHT 2SS; for HT use index 8–15).
    let vht = std::env::var("RADIO_VHT").is_ok();
    let nss2 = std::env::var("RADIO_NSS").map(|s| s == "2").unwrap_or(false);
    let desc = match (vht, nss2) {
        (true, true) => McsDescriptor::vht_2ss(mcs),
        (true, false) => McsDescriptor::vht(mcs),
        (false, _) => McsDescriptor::ht(mcs),
    };
    let rate = if vht && nss2 { "VHT-2SS MCS" } else if vht { "VHT MCS" } else { "HT MCS" };
    println!("flooding {nframes} frames on ch{ch} at {rate}{mcs}…");
    for _ in 0..nframes {
        b.inject(InjectFrame::broadcast(data.clone(), desc)).await?;
    }
    let after = b.read32(0x2d08)?;
    println!("  TX activity 0x2d08 after flood = {after:#010x}");
    println!("flooded 2000 frames — confirm radiation at the peer RX (our 4e:44:4e MAC)");
    Ok(())
}
#[cfg(not(feature = "libusb-backend"))]
fn main() {}
