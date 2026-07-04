//! Open the RTL8812AU over libusb and read its chip-version registers — the
//! first bring-up checkpoint for our own userspace driver. Proves USB register
//! I/O works and identifies the silicon, without disturbing a co-resident
//! RTL8812EU (`wlu1`). Run on the OPi (after `modprobe -r rtw88_8812au`):
//!   sudo ./whoami8812au
#[cfg(feature = "libusb-backend")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use ndn_face_monitor_wifi::Rtl8812auBackend;
    let b = Rtl8812auBackend::open()?;
    let (ep_in, ep_out) = b.endpoints();
    println!(
        "opened RTL8812AU pid={:#06x}  bulk_in={:#04x} bulk_out={:#04x}",
        b.pid(),
        ep_in,
        ep_out
    );
    let info = b.chip_info()?;
    println!(
        "REG_SYS_CFG (0xF0) = {:#010x}\nREG_SYS_CFG1(0xFC) = {:#010x}\ncut = {} ({})  test_chip = {}",
        info.sys_cfg,
        info.sys_cfg1,
        info.cut,
        match info.cut {
            0 => "A-cut",
            1 => "B-cut",
            2 => "C-cut",
            _ => "?",
        },
        info.test_chip,
    );
    if !info.responsive() {
        println!("✗ registers read all-ones/zero — device wedged or not the AU");
        return Ok(());
    }
    println!("✓ chip responds to register reads — USB register I/O works");

    // Milestone 2: power-on + firmware download.
    println!("\npower-on (CARDEMU → ACT) …");
    b.power_on()?;
    println!("✓ MAC power domain up");

    // Enable MAC DMA blocks right after power-on (REG_CR = 0x063F).
    b.mac_enable_dma()?;
    println!(
        "✓ MAC DMA/scheduler/security blocks enabled (REG_CR={:#06x})",
        b.read_cr()?
    );

    // LLT page list (C order: before firmware).
    b.init_llt()?;
    println!("✓ LLT page chain programmed (polled OK — MAC buffer engine alive)");

    println!("firmware download …");
    let (ver, sub) = b.download_firmware()?;
    println!("✓ firmware {ver}.{sub} downloaded and ready (WINTINI_RDY)");

    println!("MAC init: register table (phydm conditional, USB/B-cut) …");
    b.mac_config()?;
    println!(
        "✓ MAC register table applied (0x010 = {:#04x})",
        b.read8(0x0010)?
    );

    println!("MAC init: queues / boundaries / RCR / enable …");
    b.mac_init_queues()?;
    let cr = b.read_cr()?;
    let txrx_on = cr & 0x00C0 == 0x00C0; // MACTXEN | MACRXEN
    println!(
        "✓ MAC init complete — REG_CR={cr:#06x} (MACTXEN|MACRXEN {})",
        if txrx_on { "SET ✓" } else { "NOT set ✗" }
    );

    // Milestone 4: baseband (BB/PHY) + AGC.
    println!("BB/PHY init: power on BB+RF, apply PHY_REG + AGC tables …");
    b.bb_config()?;
    println!(
        "✓ BB/PHY init complete — BB 0x800={:#010x}  0xC04={:#010x}",
        b.bb_read(0x0800)?,
        b.bb_read(0x0C04)?
    );

    // Milestone 5: RF (radio) register init, paths A + B.
    println!("RF init: apply radio-A + radio-B tables via BB LSSI …");
    b.rf_config()?;
    use ndn_face_monitor_wifi::RfPath;
    println!(
        "✓ RF init complete — RF_A 0x00={:#07x}  0x18={:#07x}  RF_B 0x00={:#07x}",
        b.rf_read(RfPath::A, 0x00)?,
        b.rf_read(RfPath::A, 0x18)?,
        b.rf_read(RfPath::B, 0x00)?,
    );

    // Milestone 7: tune to 2.4 GHz channel 6 (NAN social channel), 20 MHz.
    println!("set_channel(6) — 2.4 GHz band switch + channel + 20 MHz …");
    b.set_channel(6)?;
    let ch_a = b.rf_read(RfPath::A, 0x18)?;
    let ch_b = b.rf_read(RfPath::B, 0x18)?;
    println!(
        "✓ tuned — RF_A 0x18={ch_a:#07x} (ch={})  RF_B 0x18={ch_b:#07x} (ch={})",
        ch_a & 0xff,
        ch_b & 0xff
    );

    // Milestone 6: RF calibration — IQ imbalance (IQK) then VCO/PLL lock (LCK).
    println!("IQK — dual-path TX/RX IQ calibration …");
    let iqk = b.iq_calibrate()?;
    println!(
        "✓ IQK done — A:[TX {} {:?}  RX {} {:?}]  B:[TX {}  RX {}]  (ch preserved={})",
        if iqk.tx_a { "ok" } else { "default" },
        iqk.tx_a_xy,
        if iqk.rx_a { "ok" } else { "default" },
        iqk.rx_a_xy,
        if iqk.tx_b { "ok" } else { "default" },
        if iqk.rx_b { "ok" } else { "default" },
        b.rf_read(RfPath::A, 0x18)? & 0xff,
    );
    println!("LCK — VCO/PLL lock for the current channel …");
    b.lc_calibrate()?;
    let lck = b.rf_read(RfPath::A, 0x18)?;
    println!(
        "✓ LCK done — RF_A 0x18={lck:#07x} (ch={}, LC-begin bit15 cleared={})",
        lck & 0xff,
        lck & 0x8000 == 0
    );
    Ok(())
}

#[cfg(not(feature = "libusb-backend"))]
fn main() {
    eprintln!("build with --features libusb-backend");
}
