//! Power-sequence command vocabulary — a faithful port of rtw88's
//! `struct rtw_pwr_seq_cmd` and its parser opcodes (`main.h`).
//!
//! The 8821C power-on/off flows in [`tables`](super::tables) are arrays of
//! [`PwrCfg`]; [`super::Rtl8821cu::apply_pwr_flow`] walks them. Unlike the
//! 8822E flows in `libusb_rtl88xx.rs`, these carry an explicit address-`base`
//! (MAC/USB/PCIe/SDIO) field, because the rtw88 tables encode SDIO-local writes
//! we filter out by interface mask.

/// One entry of a power sequence: read/modify/write, poll, delay, or end.
/// Fields mirror `struct rtw_pwr_seq_cmd` exactly (offset, masks, base, cmd,
/// register mask, value).
pub struct PwrCfg {
    /// Register offset (relative to `base`'s address space).
    pub offset: u16,
    /// Cut-version mask: entry applies only if `(1 << (cut+1)) & cut_mask`.
    pub cut_mask: u8,
    /// Interface mask: entry applies only if `intf_bit & intf_mask`.
    pub intf_mask: u8,
    /// Address base: [`BASE_MAC`]/[`BASE_USB`]/[`BASE_PCIE`]/[`BASE_SDIO`].
    pub base: u8,
    /// Opcode: [`CMD_WRITE`]/[`CMD_POLLING`]/[`CMD_DELAY`]/[`CMD_END`]/`CMD_READ`.
    pub cmd: u8,
    /// Register bitmask the command acts on.
    pub mask: u8,
    /// Value (write: bits to set under `mask`; delay: the count; poll: target).
    pub value: u8,
}

// Opcodes — `RTW_PWR_CMD_*` (main.h:1080).
pub const CMD_READ: u8 = 0x00;
pub const CMD_WRITE: u8 = 0x01;
pub const CMD_POLLING: u8 = 0x02;
pub const CMD_DELAY: u8 = 0x03;
pub const CMD_END: u8 = 0x04;

// Address bases — `RTW_PWR_ADDR_*` (main.h:1087).
pub const BASE_MAC: u8 = 0x00;
pub const BASE_USB: u8 = 0x01;
pub const BASE_PCIE: u8 = 0x02;
pub const BASE_SDIO: u8 = 0x03;

// Interface masks — `RTW_PWR_INTF_*_MSK` (main.h:1092).
pub const INTF_SDIO: u8 = 1 << 0;
pub const INTF_USB: u8 = 1 << 1;
pub const INTF_PCI: u8 = 1 << 2;

// Delay units — `RTW_PWR_DELAY_*` (main.h:1107). `value` selects the unit;
// `offset` is the count.
pub const DELAY_US: u8 = 0;
pub const DELAY_MS: u8 = 1;

/// rtw88 polls a power-sequence condition every 50 µs up to this many times
/// (`RTW_PWR_POLLING_CNT`, main.h:1078).
pub const POLLING_CNT: u32 = 20_000;

/// `cut_version_to_mask` (mac.h:9): an entry's `cut_mask` is matched against
/// `1 << (cut_version + 1)`.
pub const fn cut_version_to_mask(cut_version: u8) -> u8 {
    1u8 << (cut_version + 1)
}
