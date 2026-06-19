//! BT/WL coexistence init + the **WL antenna/RF grant** — ported from rtw88
//! coex.c / rtw8821c.c. See reference Part A.
//!
//! Why this matters even though the **RTL8811CU is WiFi-only** (no BT, unlike the
//! 8821CU): it's the same 8821C die, which powers up with the RF/antenna under
//! PTA (packet-traffic-arbiter) / hardware control. If WL is never granted the
//! antenna (GNT_WL), the receiver stays gated and demods nothing — the same
//! GNT_WL issue that ungated TX on the 8812EU. We take the `wifi_only` path:
//! force GNT_WL high, GNT_BT low, path owner = WL. Harmless on a BT-less chip,
//! and the prime suspect for the zero-RX symptom.

use std::time::Duration;

use ndn_transport::FaceError;

use super::Rtl8821cuBackend;

// LTE-coex indirect access (the 0x1700 strobe / 0x1704 wdata / 0x1708 rdata).
const LTECOEX_CTRL: u16 = 0x1700;
const LTECOEX_WDATA: u16 = 0x1704;
const LTECOEX_RDATA: u16 = 0x1708;
const LTECOEX_READY: u32 = 1 << 29;
const LTE_COEX_CTRL_OFF: u16 = 0x38; // indirect offset holding the GNT fields

// GNT states (coex.h): HW_PTA=0x0 (arbiter), SW_LOW=0x1, SW_HIGH=0x3.
const GNT_SW_LOW: u32 = 0x1;
const GNT_SW_HIGH: u32 = 0x3;

impl Rtl8821cuBackend {
    /// Grant WL the antenna and run the (BT-less-safe) coex HW init. Run after
    /// the PHY tables, before the channel set.
    pub(super) fn coex_init_wl_only(&self) -> Result<(), FaceError> {
        self.coex_power_on_setting()?;
        self.coex_cfg_init()?;
        self.coex_set_tables()?;
        self.coex_grant_wl()
    }

    /// `rtw_coex_power_on_setting` + `cfg_gnt_debug`: the "red-x" fix and freeing
    /// the GPIO/JTAG/SDIO mux off the GNT pins.
    fn coex_power_on_setting(&self) -> Result<(), FaceError> {
        self.write8(0xff1a, 0x00)?;
        self.clr32(0x0064, (1 << 20) | (1 << 24) | (1 << 15))?; // PAD_CTRL1: BTGP_SPI/JTAG, LED1DIS
        self.clr32(0x0040, 1 << 19)?; // GPIO_MUXCFG: FSPI_EN
        self.clr32(0x0070, (1 << 18) | (1 << 27))?; // SYS_SDIO_CTRL: SDIO_INT, DBG_GNT_WL_BT
        Ok(())
    }

    /// `rtw8821c_coex_cfg_init` (rtw8821c.c:811).
    fn coex_cfg_init(&self) -> Result<(), FaceError> {
        self.set8(0x0550, 1 << 3)?; // BCN_CTRL EN_BCN_FUNCTION
        self.write8_mask(0x0790, 0x3f, 0x05)?; // BT_TDMA_TIME sample rate
        self.write8(0x0778, 0x01)?; // BT_STAT_CTRL BT_CNT_ENABLE
        self.set32(0x0040, (1 << 5) | (1 << 9))?; // GPIO_MUXCFG BT_PTA_EN | PO_BT_PTA_PINS
        self.set8(0x04c6, 1 << 4)?; // QUEUE_CTRL PTA_WL_TX_EN
        self.clr8(0x04c6, 1 << 5)?; // QUEUE_CTRL clear PTA_EDCCA_EN
        let v = self.read16(0x0762)?;
        self.write16(0x0762, v | (1 << 12))?; // BT_COEX_V2 GNT_BT_POLARITY
        self.write8_mask(0x06cf, 1 << 3, 1 << 3)?; // BT_COEX_TABLE_H+3 BCN_QUEUE hi-pri
        Ok(())
    }

    /// `rtw_coex_set_table` (type=1, shared-antenna) + the WL-pri mask byte —
    /// matches the golden monitor trace exactly.
    fn coex_set_tables(&self) -> Result<(), FaceError> {
        self.write32(0x06c0, 0x5555_5555)?; // BT_COEX_TABLE0 (bt)
        self.write32(0x06c4, 0x5555_5555)?; // BT_COEX_TABLE1 (wl)
        self.write32(0x06c8, 0xf0ff_ffff)?; // BT_COEX_BRK_TABLE
        self.write8(0x06cc, 0x18)?; // BT_COEX_TABLE_H wl-pri
        Ok(())
    }

    /// Set the BT/WL grant to **HW PTA** (the hardware arbiter manages it), the
    /// path owner to WL, and the coex path owner bit. This matches the golden
    /// trace (GNT indirect-0x38 fields cleared → 0x0003), NOT a software-forced
    /// grant: forcing GNT_BT low disables the BTG LNA and kills 2.4 GHz RX, and
    /// the masks are single fields (0x3000 GNT_WL, 0xc000 GNT_BT) — my earlier
    /// extra 0x0300/0x0c00 writes were bugs. With no BT present (8811CU), the PTA
    /// arbiter simply grants WL. The per-band antenna switch is done in
    /// set_channel_rf; this only owns the grant + path.
    fn coex_grant_wl(&self) -> Result<(), FaceError> {
        // GNT_WL = SW_HIGH, GNT_BT = SW_LOW (force WL to own the antenna — the
        // WONLY state for a BT-less chip). Single fields: 0x3000 GNT_WL, 0xc000
        // GNT_BT (my earlier 0x0300/0x0c00 writes were bugs).
        self.ltecoex_write_field(LTE_COEX_CTRL_OFF, 0x3000, GNT_SW_HIGH)?;
        self.ltecoex_write_field(LTE_COEX_CTRL_OFF, 0xc000, GNT_SW_LOW)?;
        // path owner = WL: SYS_SDIO_CTRL byte3 bit2 (= BIT_LTE_MUX_CTRL_PATH>>24)
        self.set8(0x0073, 1 << 2)?;
        Ok(())
    }

    // ── LTE-coex indirect access (util.c:24-50) ──────────────────────────────

    fn ltecoex_wait_ready(&self) -> Result<(), FaceError> {
        self.poll32(LTECOEX_CTRL, LTECOEX_READY, LTECOEX_READY, 1000, Duration::from_micros(10))
    }

    fn ltecoex_read(&self, off: u16) -> Result<u32, FaceError> {
        self.ltecoex_wait_ready()?;
        self.write32(LTECOEX_CTRL, 0x800f_0000 | off as u32)?;
        self.read32(LTECOEX_RDATA)
    }

    fn ltecoex_write(&self, off: u16, val: u32) -> Result<(), FaceError> {
        self.ltecoex_wait_ready()?;
        self.write32(LTECOEX_WDATA, val)?;
        self.write32(LTECOEX_CTRL, 0xc00f_0000 | off as u32)
    }

    /// Read-modify-write a bitfield in an LTE-coex indirect register.
    fn ltecoex_write_field(&self, off: u16, mask: u32, val: u32) -> Result<(), FaceError> {
        let cur = self.ltecoex_read(off)?;
        let new = (cur & !mask) | ((val << mask.trailing_zeros()) & mask);
        self.ltecoex_write(off, new)
    }
}
