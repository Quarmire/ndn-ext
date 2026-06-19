//! Userspace libusb backend for the **RTL8821CU** (`0bda:c820` and siblings) —
//! a 1×1 2.4/5 GHz 802.11ac dongle — modelled on [`crate::LibUsbRtl88xxBackend`]
//! (the RTL8812EU/8822E backend) but ported from **rtw88** (`rtw88_8821c`), the
//! kernel driver actually bound to this chip.
//!
//! Why a separate module: the 8821C is a different Realtek HAL generation
//! (rtw88, not the 8822E vendor halmac), with a different power sequence, a DDMA
//! firmware-download path, a 48-byte rtw88 TX descriptor / 24-byte RX
//! descriptor, and — crucially — **firmware-offloaded IQK** (no host
//! IQK/LCK/DPK/DACK at all). That last point makes it far simpler to radiate
//! than the 8822E, whose unported `halrf` calibration was the hard part.
//!
//! Bring-up is staged and verified against the golden usbmon trace in
//! `golden/c820-usbmon-2026-06-17/`; see `docs/rtl8821cu-port-reference.md` for
//! the full register/flow reference (every `file:line` here cites lwfinger/rtw88).
//!
//! Status: **complete bring-up path, pending on-hardware validation.** All
//! stages are ported from the reference: USB/reg (`0x4e0` quirk), RF access,
//! power sequence, DDMA firmware download ([`fw`]), MAC init ([`mac`]), PHY
//! table apply with the phy_cond branch evaluator, per-channel BB/RF/RX-DFIR +
//! TX-power-index write + firmware IQK ([`phy`]), the 48-byte txdesc / 24-byte
//! rxdesc, and promiscuous monitor RCR. Not yet validated on-air; bring up
//! against the golden trace (`NDN_RADIO_LOG_WRITES=1` and diff). Known
//! simplifications, each marked TODO(hw): the rest of `rtw_mac_pre_system_cfg`,
//! efuse-derived phy_cond (cut/rfe/pkg) and BB-swing, and the regulatory
//! power-by-rate pipeline (a uniform TX index is written instead — the
//! `bb_pg`/`txpwr_lmt` tables are generated and ready to wire in).

// This is a staged bring-up scaffold: several register/base constants are
// present for stages not yet wired (firmware download, the WLAN_* MAC-init
// group, TX power) and cited in the reference doc. Allow them until used.
#![allow(dead_code)]

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU16, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use rusb::{Context, Device, DeviceHandle, Direction, TransferType, UsbContext};

use ndn_transport::FaceError;

use crate::frame::{self, LLC_SNAP_PREFIX};
use crate::{CapturedFrame, FrameFormat, FrameIo, InjectFrame};

mod coex;
mod efuse;
mod fw;
mod mac;
mod phy;
mod pwrseq;
mod tables;

use pwrseq::PwrCfg;

// ── USB vendor request (rtw_usb, usb.h:15) ──────────────────────────────────
const VENDOR_REQ: u8 = 0x05;
const REQ_READ: u8 = 0xc0; // RTW_USB_CMD_READ  (device→host | vendor | device)
const REQ_WRITE: u8 = 0x40; // RTW_USB_CMD_WRITE (host→device | vendor | device)
const CTRL_TIMEOUT: Duration = Duration::from_millis(500);

pub const REALTEK_VID: u16 = 0x0bda;
/// RTL8821CU / RTL8811CU USB product IDs (rtw88_8821cu + out-of-tree variants).
pub const RTL8821CU_PIDS: &[u16] = &[
    0xc820, 0xc82a, 0xc821, 0xc82b, 0xb82b, 0xb820, 0xc811, 0x8811, 0xc814,
];

// ── Registers (rtw88 reg.h) ─────────────────────────────────────────────────
const REG_SYS_FUNC_EN: u16 = 0x0002;
const REG_RSV_CTRL: u16 = 0x001c;
const REG_RF_CTRL: u16 = 0x001f;
const REG_SYS_CFG1: u16 = 0x00f0; // cut version in bits [15:12]
const REG_CR: u16 = 0x0100;
const REG_MCUFW_CTRL: u16 = 0x0080;
const REG_RCR: u16 = 0x0608;
const REG_RXFLTMAP0: u16 = 0x06a0;
const REG_RXFLTMAP1: u16 = 0x06a2;
const REG_RXFLTMAP2: u16 = 0x06a4;
const REG_MAR_LO: u16 = 0x0620;
const REG_MAR_HI: u16 = 0x0624;

// RF (radio) indirect access — 8821C (rtw8821c.c:2019-2020).
const RF_BASE_ADDR_A: u16 = 0x2800;
const RF_SIPI_ADDR_A: u16 = 0x0c90;
const RFREG_MASK: u32 = 0xfffff;
const RF_CFGCH: u8 = 0x18; // channel/band/bandwidth
const RF_XTALX2: u8 = 0xb8; // PLL reload (BIT19)
const RF_LUTDBG: u8 = 0xdf;

// RCR bits (reg.h:505).
const BIT_APP_FCS: u32 = 1 << 31;
const BIT_APP_MIC: u32 = 1 << 30;
const BIT_APP_ICV: u32 = 1 << 29;
const BIT_APP_PHYSTS: u32 = 1 << 28;
const BIT_PKTCTL_DLEN: u32 = 1 << 20;
const BIT_HTC_LOC_CTRL: u32 = 1 << 14;
const BIT_AICV: u32 = 1 << 9;
const BIT_ACRC32: u32 = 1 << 8;
const BIT_CBSSID_BCN: u32 = 1 << 7;
const BIT_CBSSID_DATA: u32 = 1 << 6;
const BIT_AB: u32 = 1 << 3;
const BIT_AM: u32 = 1 << 2;
const BIT_APM: u32 = 1 << 1;
const BIT_AAP: u32 = 1 << 0;

/// Promiscuous monitor RCR: defaults + accept-all-addr1 + accept CRC/ICV-error
/// frames, with BSSID filtering off (see reference §11).
const RCR_MONITOR: u32 = BIT_APP_FCS
    | BIT_APP_MIC
    | BIT_APP_ICV
    | BIT_APP_PHYSTS
    | BIT_PKTCTL_DLEN
    | BIT_HTC_LOC_CTRL
    | BIT_AICV
    | BIT_ACRC32
    | BIT_AB
    | BIT_AM
    | BIT_APM
    | BIT_AAP;

// ── Descriptor sizes / rate codes (tx.h, main.h:398) ────────────────────────
const TX_DESC_SIZE: usize = 48;

/// Locally-administered BSSID for our ad-hoc (IBSS) cell when `NDN_RADIO_IBSS`
/// is set — used as REG_BSSID and as 802.11 addr3 on injected frames.
const IBSS_BSSID: [u8; 6] = [0x02, 0x4e, 0x44, 0x4e, 0xbe, 0xef];
const RX_DESC_SIZE: usize = 24;
const DESC_RATE_OFDM6M: u8 = 0x04;
const DESC_RATE_MCS0: u8 = 0x0c; // HT MCS0
const DESC_RATE_VHT1SS_MCS0: u8 = 0x2c;

// phy_cond bitfield (main.h struct rtw_phy_cond, little-endian).
const INTF_USB_PHY: u8 = 1 << 1; // INTF_USB = BIT(1) = 2

fn usb_err(e: rusb::Error) -> FaceError {
    FaceError::Io(io::Error::other(format!("rtl8821cu usb: {e}")))
}
fn init_err(what: String) -> FaceError {
    FaceError::Io(io::Error::other(what))
}

/// The driver-side phy condition the table branch directives are matched
/// against (rtw88 `check_positive`, phy.c). For 8821C only `cut`, `pkg`, `intf`,
/// `rfe` participate, and `rfe` must match exactly.
#[derive(Clone, Copy, Default)]
struct PhyCond {
    cut: u8,
    pkg: u8,
    intf: u8,
    rfe: u8,
}

pub struct Rtl8821cuBackend {
    handle: Arc<DeviceHandle<Context>>,
    bulk_out: u8,
    /// All bulk-OUT endpoint addresses on the WLAN interface, in descriptor
    /// order. rtw88 maps TX queues (MGMT/HIGH/data) to distinct OUT pipes; the
    /// radiating scan-probe path uses the MGMT pipe, not necessarily the first.
    bulk_outs: Vec<u8>,
    bulk_in: u8,
    format: FrameFormat,
    seq: AtomicU16,
    /// Monotonic H2C packet sequence (firmware echoes it; must increment).
    h2c_seq: AtomicU16,
    /// Round-robin HMEBOX index (0-3) for the H2C mailbox path.
    h2c_box: AtomicU8,
    cur_channel: AtomicU8,
    /// Channel bandwidth (`RTW_CHANNEL_WIDTH_*`: 0=20). Monitor is 20 MHz.
    cur_bw: AtomicU8,
    /// CCK TX-filter params snapshotted from 0xa24/0xa28/0xaac after the BB
    /// table load — replayed per 2.4 GHz channel (rtw8821c.c:196).
    ch_param: std::sync::Mutex<[u32; 3]>,
    /// Driver phy-condition for table selection, populated at bring-up.
    cond: std::sync::Mutex<PhyCond>,
    /// efuse `rfe_option & 0x1f` — the board's RFE profile (drives the 0xcb4
    /// front-end value, the agc-btg table, and antenna routing). 0xff = unread.
    rfe_option: AtomicU8,
    /// efuse-derived: antenna routes through the BTG front-end path.
    rfe_btg: std::sync::atomic::AtomicBool,
    rx_pending: std::sync::Mutex<std::collections::VecDeque<CapturedFrame>>,
    /// Set when a background RX pump is running (keeps several concurrent bulk-IN
    /// reads in flight — Realtek USB needs continuous outstanding IN requests for
    /// the RXDMA→USB engine to push frames; a single blocking read gets nothing).
    rx_pumped: std::sync::atomic::AtomicBool,
    rx_notify: tokio::sync::Notify,
    /// Count of every raw 802.11 RX unit seen on bulk-IN (before any NDN
    /// filtering) — the honest "is the receiver working at all" metric.
    rx_raw_count: std::sync::atomic::AtomicU64,
}

impl Rtl8821cuBackend {
    /// Find and open the first RTL8821CU dongle, claim the WLAN interface, and
    /// locate its bulk endpoints. (Bring-up is a separate call so the open path
    /// can be unit-exercised without a full radio init.)
    pub fn open() -> Result<Self, FaceError> {
        // Pass 1 — reset any matching dongle to a clean power-on state. This
        // re-enumerates the device (closest thing to a physical replug) and
        // recovers a chip wedged by a previous aborted bring-up. The handle is
        // discarded: after a reset the device comes back at a new address, so we
        // must re-scan and open it fresh (pass 2) rather than reuse this handle.
        {
            let context = Context::new().map_err(usb_err)?;
            for device in context.devices().map_err(usb_err)?.iter() {
                let desc = device.device_descriptor().map_err(usb_err)?;
                if desc.vendor_id() == REALTEK_VID && RTL8821CU_PIDS.contains(&desc.product_id())
                    && let Ok(h) = device.open()
                {
                    let _ = h.reset();
                }
            }
        }
        std::thread::sleep(Duration::from_millis(1500)); // let it re-enumerate

        // Pass 2 — open + claim the (re-enumerated) device.
        let context = Context::new().map_err(usb_err)?;
        for device in context.devices().map_err(usb_err)?.iter() {
            let desc = device.device_descriptor().map_err(usb_err)?;
            if desc.vendor_id() == REALTEK_VID && RTL8821CU_PIDS.contains(&desc.product_id()) {
                return Self::claim(device);
            }
        }
        Err(FaceError::Io(io::Error::new(
            io::ErrorKind::NotFound,
            "no RTL8821CU dongle found (Realtek 0bda:c811/c820/...)",
        )))
    }

    fn claim(device: Device<Context>) -> Result<Self, FaceError> {
        let handle = Arc::new(device.open().map_err(usb_err)?);
        let _ = handle.set_auto_detach_kernel_driver(true);
        let config = device.active_config_descriptor().map_err(usb_err)?;

        // The WLAN function is the interface that exposes the bulk endpoints
        // (the 8821C combo also has BT/isoc interfaces). Claim that one.
        let (mut wlan_iface, mut bulk_in, mut bulk_out) = (None, None, None);
        let mut bulk_outs: Vec<u8> = Vec::new();
        for iface in config.interfaces() {
            for d in iface.descriptors() {
                let mut has_in = None;
                let mut has_out = None;
                let mut outs: Vec<u8> = Vec::new();
                for ep in d.endpoint_descriptors() {
                    if ep.transfer_type() != TransferType::Bulk {
                        continue;
                    }
                    match ep.direction() {
                        Direction::In if has_in.is_none() => has_in = Some(ep.address()),
                        Direction::Out => {
                            if has_out.is_none() {
                                has_out = Some(ep.address());
                            }
                            outs.push(ep.address());
                        }
                        _ => {}
                    }
                }
                if let (Some(i), Some(o)) = (has_in, has_out) {
                    wlan_iface = Some(iface.number());
                    bulk_in = Some(i);
                    bulk_out = Some(o);
                    bulk_outs = outs;
                }
            }
        }
        if std::env::var("NDN_RADIO_EP_DEBUG").is_ok() {
            eprintln!(
                "8821cu WLAN bulk OUT endpoints: {}  (IN {:#04x})",
                bulk_outs.iter().map(|e| format!("{e:#04x}")).collect::<Vec<_>>().join(" "),
                bulk_in.unwrap_or(0)
            );
        }
        let iface = wlan_iface.ok_or_else(|| {
            FaceError::Io(io::Error::new(
                io::ErrorKind::NotFound,
                "RTL8821CU: no interface with bulk IN+OUT endpoints",
            ))
        })?;
        let _ = handle.set_auto_detach_kernel_driver(true);
        handle.claim_interface(iface).map_err(usb_err)?;

        Ok(Self {
            handle,
            bulk_out: bulk_out.unwrap(),
            bulk_outs,
            bulk_in: bulk_in.unwrap(),
            format: FrameFormat::default(),
            seq: AtomicU16::new(0),
            h2c_seq: AtomicU16::new(0),
            h2c_box: AtomicU8::new(0),
            cur_channel: AtomicU8::new(0),
            cur_bw: AtomicU8::new(0),
            ch_param: std::sync::Mutex::new([0; 3]),
            cond: std::sync::Mutex::new(PhyCond::default()),
            rfe_option: AtomicU8::new(0xff),
            rfe_btg: std::sync::atomic::AtomicBool::new(false),
            rx_pending: std::sync::Mutex::new(std::collections::VecDeque::new()),
            rx_pumped: std::sync::atomic::AtomicBool::new(false),
            rx_notify: tokio::sync::Notify::new(),
            rx_raw_count: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// Open the dongle and bring it up in monitor mode on `channel`.
    pub fn open_monitor(channel: u8) -> Result<Self, FaceError> {
        let dev = Self::open()?;
        dev.bring_up(channel)?;
        Ok(dev)
    }

    /// Start `depth` background threads each continuously reading the bulk-IN
    /// endpoint, parsing RX units into `rx_pending`. Keeps several concurrent
    /// reads in flight — required for the chip to DMA RX to USB. Call after
    /// bring-up, once the backend is in an `Arc`.
    pub fn spawn_rx_pump(self: &Arc<Self>, depth: usize) {
        self.rx_pumped.store(true, Ordering::Relaxed);
        for _ in 0..depth.max(1) {
            let weak = Arc::downgrade(self);
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 32768];
                loop {
                    let Some(dev) = weak.upgrade() else { break };
                    let r = dev.handle.read_bulk(dev.bulk_in, &mut buf, Duration::from_millis(200));
                    if std::env::var("NDN_RADIO_RX_DEBUG").is_ok() {
                        match &r {
                            Ok(n) => eprintln!("read_bulk(ep {:#04x}) -> Ok({n})", dev.bulk_in),
                            Err(rusb::Error::Timeout) => {}
                            Err(e) => eprintln!("read_bulk(ep {:#04x}) -> Err({e})", dev.bulk_in),
                        }
                    }
                    match r {
                        Ok(n) if n > 0 => {
                            let mut off = 0;
                            {
                                let mut q = dev.rx_pending.lock().unwrap();
                                while let Some((decoded, advance)) = dev.parse_rx_at(&buf[..n], off) {
                                    for f in decoded {
                                        q.push_back(f);
                                    }
                                    off += advance;
                                    if off + RX_DESC_SIZE > n {
                                        break;
                                    }
                                }
                            }
                            dev.rx_notify.notify_one();
                        }
                        _ => {} // timeout / error: re-submit
                    }
                }
            });
        }
    }

    /// Override the on-air frame format (e.g. ESP-NOW).
    pub fn with_format(mut self, format: FrameFormat) -> Self {
        self.format = format;
        self
    }

    // ── register access (usb.c:72-166) ──────────────────────────────────────

    fn read_reg(&self, addr: u16, buf: &mut [u8]) -> Result<(), FaceError> {
        let n = self
            .handle
            .read_control(REQ_READ, VENDOR_REQ, addr, 0, buf, CTRL_TIMEOUT)
            .map_err(usb_err)?;
        if n != buf.len() {
            return Err(init_err(format!("8821cu read_reg({addr:#06x}) short {n}")));
        }
        self.reg_sec(addr, buf);
        Ok(())
    }

    fn write_reg(&self, addr: u16, data: &[u8]) -> Result<(), FaceError> {
        log_write(addr, data);
        let n = self
            .handle
            .write_control(REQ_WRITE, VENDOR_REQ, addr, 0, data, CTRL_TIMEOUT)
            .map_err(usb_err)?;
        if n != data.len() {
            return Err(init_err(format!("8821cu write_reg({addr:#06x}) short {n}")));
        }
        self.reg_sec(addr, data);
        Ok(())
    }

    /// The 8821C `rtw_usb_reg_sec` quirk (usb.c:42-70): after any access to an
    /// "on" section register (`addr <= 0xff` or `0x1000..=0x10ff`), the kernel
    /// issues an extra 1-byte write to `0x4e0` with the same data. Replicated so
    /// our bring-up matches the golden trace byte-for-byte.
    fn reg_sec(&self, addr: u16, data: &[u8]) {
        let on_section = addr <= 0xff || (0x1000..=0x10ff).contains(&addr);
        if !on_section {
            return;
        }
        let byte = [*data.first().unwrap_or(&0)];
        let _ = self
            .handle
            .write_control(REQ_WRITE, VENDOR_REQ, 0x04e0, 0, &byte, CTRL_TIMEOUT);
    }

    /// Total raw 802.11 RX units seen on bulk-IN since open (before NDN
    /// filtering) — the "is the receiver working" metric.
    pub fn raw_rx_count(&self) -> u64 {
        self.rx_raw_count.load(Ordering::Relaxed)
    }

    /// Reset/kick the BB false-alarm + CRC counters (rtw8821c_false_alarm_statistics
    /// tail) so they accumulate from now — for the RX localization diagnostic.
    pub fn debug_reset_rx_counters(&self) -> Result<(), FaceError> {
        self.set32(0x09a4, 1 << 17)?; // REG_FAS BIT(17)
        self.clr32(0x09a4, 1 << 17)?;
        self.set32(0x0b58, 1 << 0)?; // REG_CNTRST BIT(0)
        self.clr32(0x0b58, 1 << 0)?;
        Ok(())
    }

    /// The board's RFE profile read from efuse: `(rfe_option_full, rfe_btg)`.
    /// `rfe_option_full == 0xff` means the efuse read failed (defaults in use).
    pub fn rfe_profile(&self) -> (u8, bool) {
        (
            self.rfe_option.load(Ordering::Relaxed),
            self.rfe_btg.load(Ordering::Relaxed),
        )
    }

    /// Read an 8-bit register (also exposed for diagnostics / examples).
    pub fn read8(&self, addr: u16) -> Result<u8, FaceError> {
        let mut b = [0u8; 1];
        self.read_reg(addr, &mut b)?;
        Ok(b[0])
    }
    /// Read a 16-bit register (also exposed for diagnostics / examples).
    pub fn read16(&self, addr: u16) -> Result<u16, FaceError> {
        let mut b = [0u8; 2];
        self.read_reg(addr, &mut b)?;
        Ok(u16::from_le_bytes(b))
    }
    /// Read a 32-bit register (also exposed for diagnostics / examples).
    pub fn read32(&self, addr: u16) -> Result<u32, FaceError> {
        let mut b = [0u8; 4];
        self.read_reg(addr, &mut b)?;
        Ok(u32::from_le_bytes(b))
    }
    fn write8(&self, addr: u16, v: u8) -> Result<(), FaceError> {
        self.write_reg(addr, &[v])
    }
    fn write16(&self, addr: u16, v: u16) -> Result<(), FaceError> {
        self.write_reg(addr, &v.to_le_bytes())
    }
    fn write32(&self, addr: u16, v: u32) -> Result<(), FaceError> {
        self.write_reg(addr, &v.to_le_bytes())
    }

    fn set8(&self, addr: u16, bits: u8) -> Result<(), FaceError> {
        let v = self.read8(addr)?;
        self.write8(addr, v | bits)
    }
    fn clr8(&self, addr: u16, bits: u8) -> Result<(), FaceError> {
        let v = self.read8(addr)?;
        self.write8(addr, v & !bits)
    }
    fn set32(&self, addr: u16, bits: u32) -> Result<(), FaceError> {
        let v = self.read32(addr)?;
        self.write32(addr, v | bits)
    }
    fn clr32(&self, addr: u16, bits: u32) -> Result<(), FaceError> {
        let v = self.read32(addr)?;
        self.write32(addr, v & !bits)
    }
    /// Read-modify-write a sub-field: clear `mask` bits, OR in `val` (already
    /// positioned within `mask`).
    fn write8_mask(&self, addr: u16, mask: u8, val: u8) -> Result<(), FaceError> {
        let v = self.read8(addr)?;
        self.write8(addr, (v & !mask) | (val & mask))
    }

    /// Poll `(read32(addr) & mask) == target`, up to `tries` × `delay`.
    fn poll32(&self, addr: u16, mask: u32, target: u32, tries: u32, delay: Duration) -> Result<(), FaceError> {
        for _ in 0..tries {
            if (self.read32(addr)? & mask) == target {
                return Ok(());
            }
            std::thread::sleep(delay);
        }
        Err(init_err(format!("8821cu poll timeout @{addr:#06x} mask={mask:#x}")))
    }

    /// Synchronous bulk-OUT write to the single WLAN endpoint.
    fn bulk_write(&self, buf: &[u8]) -> Result<(), FaceError> {
        let n = self
            .handle
            .write_bulk(self.bulk_out, buf, Duration::from_secs(1))
            .map_err(usb_err)?;
        if n != buf.len() {
            return Err(init_err(format!("8821cu bulk_write short {n}/{}", buf.len())));
        }
        Ok(())
    }

    // ── RF (radio) register access via BB indirect ports (phy.c:961-1071) ────

    /// Read RF register `addr` on path A: `read32_mask(0x2800 + addr*4, mask)`.
    pub fn read_rf(&self, addr: u8, mask: u32) -> Result<u32, FaceError> {
        let direct = RF_BASE_ADDR_A + ((addr as u16) << 2);
        let v = self.read32(direct)? & (mask & RFREG_MASK);
        Ok(v >> (mask & RFREG_MASK).trailing_zeros())
    }

    /// Write RF register `addr` on path A via SIPI: `write32(0xc90,
    /// (addr<<20)|data20)`. Partial masks read-modify-write first.
    fn write_rf(&self, addr: u8, mask: u32, data: u32) -> Result<(), FaceError> {
        let mask = mask & RFREG_MASK;
        let data = if mask != RFREG_MASK {
            let cur = self.read_rf(addr, RFREG_MASK)?;
            let shift = mask.trailing_zeros();
            (cur & !mask) | ((data << shift) & mask)
        } else {
            data & RFREG_MASK
        };
        let word = (((addr as u32) << 20) | data) & 0x0fff_ffff;
        self.write32(RF_SIPI_ADDR_A, word)?;
        std::thread::sleep(Duration::from_micros(13));
        Ok(())
    }

    // ── power sequence (mac.c:185-312) ──────────────────────────────────────

    /// Apply a power flow (a list of sub-sequences) for the USB interface and
    /// our cut version (rtw88 `rtw_pwr_seq_parser`).
    fn apply_pwr_flow(&self, flow: &[&[PwrCfg]], cut: u8) -> Result<(), FaceError> {
        let cut_mask = pwrseq::cut_version_to_mask(cut);
        for seq in flow {
            for c in *seq {
                if c.cmd == pwrseq::CMD_END {
                    break;
                }
                if (c.intf_mask & pwrseq::INTF_USB) == 0 || (c.cut_mask & cut_mask) == 0 {
                    continue;
                }
                // We only ever target the MAC base over USB; SDIO-base entries
                // are already filtered by the interface mask above.
                if c.base != pwrseq::BASE_MAC && c.base != pwrseq::BASE_USB {
                    continue;
                }
                match c.cmd {
                    pwrseq::CMD_WRITE => {
                        let v = self.read8(c.offset)?;
                        self.write8(c.offset, (v & !c.mask) | (c.value & c.mask))?;
                    }
                    pwrseq::CMD_POLLING => {
                        let mut ok = false;
                        for _ in 0..pwrseq::POLLING_CNT {
                            if (self.read8(c.offset)? & c.mask) == (c.value & c.mask) {
                                ok = true;
                                break;
                            }
                            std::thread::sleep(Duration::from_micros(50));
                        }
                        if !ok {
                            return Err(init_err(format!(
                                "8821cu pwrseq poll timeout @{:#06x}",
                                c.offset
                            )));
                        }
                    }
                    pwrseq::CMD_DELAY => {
                        let d = c.offset as u64;
                        if c.value == pwrseq::DELAY_US {
                            std::thread::sleep(Duration::from_micros(d));
                        } else {
                            std::thread::sleep(Duration::from_millis(d));
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    // ── PHY table application (phy.c:1199-1854) ──────────────────────────────

    /// Apply a flat phy_cond `{addr,data}` table, honouring the embedded
    /// IF/ELIF/ELSE/ENDIF branch directives and the per-op write width + delay
    /// sentinels. `do_cfg` is one of [`CfgKind`].
    fn apply_phy_table(&self, table: &[u32], kind: CfgKind) -> Result<(), FaceError> {
        let cond = *self.cond.lock().unwrap();
        let mut i = 0;
        let mut matched = true; // outside any branch → apply
        let mut skipped = false;
        while i + 1 < table.len() {
            let w0 = table[i];
            // A directive has pos or neg set in the top bits and consumes 2 words
            // (the condition) — or 4 for IF/ELIF (cond + the eval marker word).
            let pos = (w0 >> 31) & 1 != 0;
            let neg = (w0 >> 30) & 1 != 0;
            if pos {
                let branch = (w0 >> 28) & 0x3;
                match branch {
                    3 => {
                        // ENDIF
                        matched = true;
                        skipped = false;
                        i += 2;
                    }
                    2 => {
                        // ELSE
                        matched = !skipped;
                        i += 2;
                    }
                    _ => {
                        // IF / ELIF: stash condition, the next word (neg) evaluates it.
                        // (cond word, 0, eval-marker, 0) → 4 words.
                        let c = parse_phy_cond(w0);
                        let take = check_positive(c, cond);
                        if !skipped && take {
                            matched = true;
                            skipped = true;
                        } else {
                            matched = false;
                        }
                        i += 4;
                    }
                }
                continue;
            }
            if neg {
                // standalone eval marker without a leading pos — skip its 2 words
                i += 2;
                continue;
            }
            // Normal {addr, data} pair.
            let addr = w0;
            let data = table[i + 1];
            if matched {
                self.do_cfg(kind, addr, data)?;
            }
            i += 2;
        }
        Ok(())
    }

    fn do_cfg(&self, kind: CfgKind, addr: u32, data: u32) -> Result<(), FaceError> {
        match kind {
            CfgKind::Mac => self.write8(addr as u16, data as u8),
            CfgKind::Agc => self.write32(addr as u16, data),
            CfgKind::Bb => {
                // BB delay sentinels (phy.c:1823).
                match addr & 0xfff {
                    0xfe => std::thread::sleep(Duration::from_millis(50)),
                    0xfd => std::thread::sleep(Duration::from_millis(5)),
                    0xfc => std::thread::sleep(Duration::from_millis(1)),
                    0xfb => std::thread::sleep(Duration::from_micros(50)),
                    0xfa => std::thread::sleep(Duration::from_micros(5)),
                    0xf9 => std::thread::sleep(Duration::from_micros(1)),
                    _ => return self.write32(addr as u16, data),
                }
                Ok(())
            }
            CfgKind::Rf => {
                // RF delay sentinels (phy.c:1843).
                match addr & 0xfff {
                    0xffe => std::thread::sleep(Duration::from_millis(50)),
                    0xfe => std::thread::sleep(Duration::from_micros(100)),
                    _ => return self.write_rf(addr as u8, RFREG_MASK, data),
                }
                Ok(())
            }
        }
    }

    /// `rtw8821c_phy_set_param` (rtw8821c.c:159): re-enable the BB/RF domain that
    /// `pre_system_cfg` disabled, **before** loading the PHY tables. Without this
    /// the BB/RF stay powered off — RF registers read back garbage and the
    /// receiver never delivers frames. This was the bug that left RX dead.
    fn phy_set_param(&self) -> Result<(), FaceError> {
        // power on BB domain
        self.set8(0x0002, 1 << 6)?; // SYS_FUNC_EN |= FEN_PCIEA
        // toggle BB reset (set, clear, set)
        self.set8(0x0002, (1 << 0) | (1 << 1))?;
        self.clr8(0x0002, (1 << 0) | (1 << 1))?;
        self.set8(0x0002, (1 << 0) | (1 << 1))?;
        // enable RF
        self.write8(0x001f, (1 << 0) | (1 << 1) | (1 << 2))?; // RF_CTRL = EN|RSTB|SDM_RSTB
        std::thread::sleep(Duration::from_micros(10));
        self.write8(0x00ef, (1 << 0) | (1 << 1) | (1 << 2))?; // WLRF1+3 = EN|RSTB|SDM_RSTB
        std::thread::sleep(Duration::from_micros(10));
        self.clr32(0x0808, (1 << 28) | (1 << 29))?; // RXPSEL clr RX_PSEL_RST
        self.load_tables()
    }

    fn load_tables(&self) -> Result<(), FaceError> {
        self.apply_phy_table(tables::RTW8821C_MAC, CfgKind::Mac)?;
        self.apply_phy_table(tables::RTW8821C_BB, CfgKind::Bb)?;
        self.apply_phy_table(tables::RTW8821C_AGC, CfgKind::Agc)?;
        // BTG boards load the extra BTG AGC table (rfe_def->agc_btg_tbl).
        if self.rfe_btg.load(Ordering::Relaxed) {
            self.apply_phy_table(tables::RTW8821C_AGC_BTG_TYPE2, CfgKind::Agc)?;
        }
        // 8821C-specific REG_RFE_CTRL8 (0xcb4) between AGC and RF tables
        // (rtw_phy_load_tables, phy.c:1889), keyed on the board's rfe_option.
        let rfe = self.rfe_option.load(Ordering::Relaxed);
        let cb4 = if (0x28..=0x2f).contains(&rfe) {
            0x0000_0073
        } else if rfe == 4 {
            0x2000_0077
        } else {
            0x1000_0077
        };
        self.write32(0x0cb4, cb4)?;
        self.apply_phy_table(tables::RTW8821C_RF_A, CfgKind::Rf)?;
        // Snapshot the CCK TX-filter params the BB table left in place; they are
        // replayed per 2.4 GHz channel (rtw8821c.c:196).
        *self.ch_param.lock().unwrap() = [
            self.read32(0x0a24)?,
            self.read32(0x0a28)?,
            self.read32(0x0aac)?,
        ];
        Ok(())
    }

    // ── firmware download (DDMA path — see reference §2) ─────────────────────
    // TODO(hw): the DDMA reserved-page firmware download. Implemented as a
    // separate step because the WLAN function needs fw running only for the
    // (firmware-offloaded) IQK and for TX; monitor RX does not. Tracked against
    // the golden trace's BULK-OUT firmware chunks. See `fw.rs` (to add).

    // ── bring-up ─────────────────────────────────────────────────────────────

    /// Full monitor-mode bring-up on `channel`. Staged per the reference; each
    /// stage is diffable against the golden usbmon trace with `NDN_RADIO_LOG_WRITES=1`.
    pub fn bring_up(&self, channel: u8) -> Result<(), FaceError> {
        // 1) Cut version + efuse-derived phy condition (rfe/pkg) for table select.
        let cut = ((self.read32(REG_SYS_CFG1)? >> 12) & 0xf) as u8;
        *self.cond.lock().unwrap() = PhyCond {
            cut,
            pkg: 0,             // TODO(hw): efuse package type (rtw8821c.h pkg_type)
            intf: INTF_USB_PHY, // INTF_USB = 2
            rfe: 0,             // TODO(hw): efuse rfe_option_full >> 3
        };

        // 2) Power on. rtw_mac_pre_system_cfg configures the RF front-end pin mux
        //    (PAPE/LNAON routing) and disables BB/RF before the power flow — the
        //    front-end routing the receiver needs.
        self.pre_system_cfg()?;
        // Re-run safe: if the chip is already powered on (REG_CR != the 0xea
        // card-disabled signature), power it down first — running CARD_ENABLE on
        // an already-on chip wedges it (rtw88 power-cycles in the same case).
        // Best-effort: a stale-state poll timeout here must not abort bring-up.
        if self.read8(REG_CR)? != 0xea {
            let _ = self.apply_pwr_flow(tables::CARD_DISABLE_FLOW_8821C, cut);
            self.write8(REG_RSV_CTRL, 0)?;
        }
        self.apply_pwr_flow(tables::CARD_ENABLE_FLOW_8821C, cut)?;

        // 2b) Read the board's RFE profile from efuse — drives the 0xcb4
        //     front-end value, the agc-btg table, and antenna routing. Hardcoding
        //     another board's profile mis-tunes the receiver. Falls back to the
        //     prior assumptions on a read failure.
        match self.read_chip_info() {
            Ok(info) => {
                tracing::info!("8821cu efuse: rfe_option={:#04x} (full={:#04x}) pkg={} btg={}",
                    info.rfe_option, info.rfe_option_full, info.pkg_type, info.rfe_btg);
                self.rfe_option.store(info.rfe_option_full, Ordering::Relaxed);
                self.rfe_btg.store(info.rfe_btg, Ordering::Relaxed);
                let mut c = self.cond.lock().unwrap();
                c.rfe = info.rfe_option_full >> 3;
                c.pkg = info.pkg_type;
            }
            Err(e) => tracing::warn!("8821cu efuse read failed ({e}); using default RFE profile"),
        }

        // 3) Firmware download (DDMA) — required for IQK + TX (not strictly RX).
        self.download_firmware()?;

        // 4) MAC init: TRX FIFO/queue cfg + chip MAC register group + H2C ring.
        self.mac_init()?;

        // 5) Enable BB/RF then load the PHY tables (mac/bb/agc/rf).
        self.phy_set_param()?;

        // 5b) Firmware config H2C (rtw_power_on tail): general_info + phydm_info,
        //     so the firmware runs the dynamic RX gain (DIG). Best-effort.
        if let Err(e) = self.send_fw_info() {
            eprintln!("8821cu fw-info H2C failed: {e}");
        }

        // 5b.2) Emulate a connected station at MACID 0 (the MACID build_tx uses)
        //       so the firmware keys the PA for injected frames. rtw88 monitor
        //       injection skips this and doesn't radiate — suspected TX gate.
        //       `NDN_RADIO_NO_STA=1` skips it (A/B).
        // Firmware station-emulation (TX-radiate experiment). Off by default: it
        // had no measured effect on radiation and the clean monitor path is the
        // proven-good RX config. `NDN_RADIO_STA=1` re-enables for investigation.
        if std::env::var("NDN_RADIO_STA").is_ok() {
            if let Err(e) = self.media_status_report(0, true) {
                eprintln!("8821cu media-status(connect) failed: {e}");
            }
            // Rate table for MACID 0 (OFDM 6-54 + MCS0-7). Required for the
            // firmware RA to accept frames from this station when USE_RATE=0.
            if let Err(e) = self.ra_info(0, 6, 0x000f_fff0) {
                eprintln!("8821cu ra_info failed: {e}");
            }
        }

        // 5c) Grant WL the antenna/RF (coex WONLY path) + coex HW init. Even on a
        //     BT-less 8811CU the die powers up with the antenna under PTA control;
        //     ungating WL is the prime RX unblock. Best-effort.
        if let Err(e) = self.coex_init_wl_only() {
            eprintln!("8821cu coex/grant-WL failed: {e}");
        }

        // 6) Receive config: promiscuous monitor (overrides mac_init's RCR).
        self.set_monitor_rx()?;

        // 7) Channel (BB + RF + RX DFIR + TX-power index).
        self.set_channel(channel)?;

        // 7b) Enable the BB RX path. RX_PSEL_RST (REG_RXPSEL bit28|29) is pulsed
        //     clear during phy_set_param; the receiver only runs with bit29 SET
        //     (RX path selected). Without this the whole BB RX chain stays
        //     inactive — FA/CRC counters read 0 and no frames reach USB. THIS is
        //     what was killing monitor RX.
        self.set32(0x0808, 1 << 29)?;

        // 8) Firmware-offloaded IQK (the only calibration; needs fw running).
        //    Best-effort: a timeout shouldn't abort RX bring-up.
        if let Err(e) = self.do_iqk() {
            tracing::warn!("8821cu IQK skipped: {e}");
        }

        // 8b) Golden "finalize / function-enable" block the kernel emits after
        //     channel set, which I otherwise skip: SYS_FUNC_EN = all blocks
        //     (0x1f, vs my partial set) + the BB-TX-region 0x1c94=0xafffafff +
        //     0x042c/0x045f/0x06dc. Suspected TX-radiate gate (TX keys but emits
        //     no RF without it). `NDN_RADIO_NO_TXEN=1` skips it for A/B.
        if std::env::var("NDN_RADIO_NO_TXEN").is_err() {
            self.write32(0x042c, 0x4000_c000)?;
            self.write8(0x045f, 0x10)?;
            self.write32(0x06dc, 0x0484_0000)?;
            self.write32(0x1c94, 0xafff_afff)?;
            self.write8(0x0002, 0x1f)?; // SYS_FUNC_EN: enable all function blocks
        }

        // 8c) Station-identity registers the kernel writes before it transmits
        //     (decoded from scan_tx golden, absent in monitor): REG_MACID =
        //     our own MAC (= the A2 of frames we inject) and a few TX-control
        //     bytes. The TX engine keys the PA off REG_MACID; with it zeroed
        //     (monitor default) frames dequeue but never radiate. This is the
        //     prime TX-radiate hypothesis. `NDN_RADIO_NO_STAREGS=1` skips it.
        if std::env::var("NDN_RADIO_STAREGS").is_ok() {
            let mac = ndn_frame_io::frame::DEFAULT_SRC; // 02:4e:44:4e:00:01
            self.write32(0x0610, u32::from_le_bytes([mac[0], mac[1], mac[2], mac[3]]))?;
            self.write16(0x0614, u16::from_le_bytes([mac[4], mac[5]]))?;
            self.write8(0x0440, 0x5d)?; // TX control (scan golden)
            self.write8(0x0093, 0xd4)?;
            self.write8(0x0007, 0x20)?;
            self.write8(0x0550, 0x08)?;
        }

        // 8d) Ad-hoc (IBSS) operating mode — the TX-radiate path. Sets REG_CR
        //     network-type to ADHOC + EDCA + BSSID so the firmware keys injected
        //     TX (monitor's NO_LINK opmode gates it). `NDN_RADIO_IBSS=1`.
        if std::env::var("NDN_RADIO_IBSS").is_ok() {
            if let Err(e) = self.setup_ibss() {
                eprintln!("8821cu setup_ibss failed: {e}");
            }
        }

        // 9) USB RX burst + aggregation config — LAST (rtw_hci_start ordering),
        //    so the BB table load / channel set can't clobber REG_RXDMA_MODE.
        //    This is what makes the chip DMA received frames to bulk-IN.
        self.hci_usb_cfg()?;
        Ok(())
    }

    /// Send an 8-byte H2C command via the **HMEBOX mailbox** (rtw88
    /// `rtw_fw_send_h2c_command`): round-robin boxes 0-3, poll REG_HMETFR for the
    /// box to be free, write the ext word then the msg word. This is the path the
    /// kernel uses for media-status / RA — distinct from the qsel-19 packet path.
    fn send_h2c_mailbox(&self, w0: u32, w1: u32) -> Result<(), FaceError> {
        let box_n = self.h2c_box.fetch_add(1, Ordering::Relaxed) & 0x3;
        let (box_reg, ex_reg) = (0x01d0 + (box_n as u16) * 4, 0x01f0 + (box_n as u16) * 4);
        // REG_HMETFR (0x1cc): box busy when (state >> box) & 1.
        let mut free = false;
        for _ in 0..300 {
            if (self.read8(0x01cc)? >> box_n) & 1 == 0 {
                free = true;
                break;
            }
            std::thread::sleep(Duration::from_micros(100));
        }
        if !free {
            return Err(init_err(format!("8821cu H2C mailbox {box_n} busy")));
        }
        self.write32(ex_reg, w1)?;
        self.write32(box_reg, w0)?; // writing the msg word triggers the fw read
        Ok(())
    }

    /// `rtw_fw_media_status_report` (H2C_CMD_MEDIA_STATUS_RPT=0x01): tell the
    /// firmware a station at `macid` is connected/disconnected. On rtw88 the
    /// firmware gates PA-keying on this — without a "connected" station the chip
    /// dequeues TX frames but never radiates them. This is the suspected gate for
    /// host-injected TX (the kernel's monitor injection skips it and doesn't
    /// radiate either). w0 = cmd(0x01) | op_mode<<8 | macid<<16.
    fn media_status_report(&self, macid: u8, connect: bool) -> Result<(), FaceError> {
        let w0 = 0x01u32 | ((connect as u32) << 8) | ((macid as u32) << 16);
        self.send_h2c_mailbox(w0, 0)
    }

    /// Put the MAC into **ad-hoc (IBSS) operating mode** so the TX engine keys
    /// frames. Monitor mode leaves REG_CR network-type = NO_LINK, which gates all
    /// host TX (the chip dequeues + drains the FIFO but never keys the PA). The
    /// kernel's IBSS setup (golden_ibss.pcap) sets: REG_CR nettype=ADHOC, valid
    /// EDCA AC params, beacon control, own MAC + a BSSID. Replicated here without
    /// the reserved-page beacon download — the hypothesis being opmode+EDCA+BSSID
    /// alone ungates injected data TX.
    fn setup_ibss(&self) -> Result<(), FaceError> {
        let mac = ndn_frame_io::frame::DEFAULT_SRC; // 02:4e:44:4e:00:01
        // REG_CR (0x100): network type [17:16] = 01 (ADHOC).
        let cr = self.read32(0x0100)?;
        self.write32(0x0100, (cr & !0x0003_0000) | 0x0001_0000)?;
        // EDCA AC params (BE/BK/VI/VO) — valid TXOP/CW so the MAC can contend.
        for r in [0x0500u16, 0x0504, 0x0508, 0x050c] {
            self.write32(r, 0x0000_a432)?;
        }
        self.write8(0x0454, 0x05)?; // SIFS/ack timing (golden IBSS)
        self.write32(0x0420, 0x0070_1f80)?; // REG_FWHW_TXQ_CTRL: enable TX queues
        self.write8(0x0550, 0x18)?; // REG_BCN_CTRL: EN_BCN_FUNCTION | DIS_TSF_UDT
        // Own MAC + IBSS BSSID.
        self.write32(0x0610, u32::from_le_bytes([mac[0], mac[1], mac[2], mac[3]]))?;
        self.write16(0x0614, u16::from_le_bytes([mac[4], mac[5]]))?;
        let b = IBSS_BSSID;
        self.write32(0x0618, u32::from_le_bytes([b[0], b[1], b[2], b[3]]))?;
        self.write16(0x061c, u16::from_le_bytes([b[4], b[5]]))?;
        Ok(())
    }

    /// `rtw_fw_send_ra_info` (H2C_CMD_RA_INFO=0x40): install a rate-adaptation
    /// table entry for `macid` so the firmware knows what rates that station can
    /// use. Without it the firmware's RA has no entry for MACID 0 and silently
    /// drops injected frames (when USE_RATE=0). Fields per rtw88 fw.h:
    /// MACID=bits[15:8], RATE_ID=[20:16], INIT_RA_LVL=[22:21], SGI=BIT23,
    /// BW=[25:24], LDPC=BIT26, VHT=[29:28]; ext word = 32-bit rate bitmap
    /// (DESC_RATE index per bit: 0-3 CCK, 4-11 OFDM 6-54, 12-19 MCS0-7).
    fn ra_info(&self, macid: u8, rate_id: u8, ra_mask: u32) -> Result<(), FaceError> {
        let w0 = 0x40u32
            | ((macid as u32) << 8)
            | ((rate_id as u32 & 0x1f) << 16)
            | (1u32 << 22); // INIT_RA_LVL = highest, so it tries real rates immediately
        self.send_h2c_mailbox(w0, ra_mask)
    }

    /// `rtw_mac_pre_system_cfg` (mac.c:62) for USB: RF front-end pin mux +
    /// disable BB/RF, run before the card-enable power flow.
    fn pre_system_cfg(&self) -> Result<(), FaceError> {
        self.write8(REG_RSV_CTRL, 0)?;
        // PIN mux: route PAPE/LNAON to WL/BT, clear the LED-pin selects, enable
        // the WL RFE 4/5 pins.
        self.set32(0x0064, (1 << 29) | (1 << 28))?; // PAD_CTRL1 |= PAPE/LNAON_WLBT_SEL
        self.clr32(0x004c, (1 << 25) | (1 << 26))?; // LED_CFG &= ~(PAPE/LNAON_SEL_EN)
        self.set32(0x0040, 1 << 2)?; // GPIO_MUXCFG |= WLRFE_4_5_EN
        // disable BB/RF (re-enabled by the tables)
        self.clr8(0x0002, (1 << 0) | (1 << 1))?; // SYS_FUNC_EN &= ~(BB_RSTB|BB_GLB_RST)
        self.clr8(0x001f, (1 << 0) | (1 << 1) | (1 << 2))?; // RF_CTRL &= ~(RF_EN|RSTB|SDM_RSTB)
        self.clr32(0x00ec, (1 << 24) | (1 << 25) | (1 << 26))?; // WLRF1 &= ~BBRF_EN
        Ok(())
    }

    /// Configure monitor receive. Uses the exact RCR the kernel's `iw set
    /// monitor` produced in the golden trace (0xf410408e) plus all-ones RX filter
    /// maps, rather than a hand-rolled promiscuous value — this is the config
    /// proven to capture on this driver.
    fn set_monitor_rx(&self) -> Result<(), FaceError> {
        // The golden trace's *final* monitor RCR (0xf410400f): AAP set (accept
        // any addr1) and CBSSID_BCN/DATA clear (no BSSID filtering) = truly
        // promiscuous. The intermediate 0xf410408e has CBSSID_BCN set + AAP clear
        // and drops nearly everything — that was the RX-killer.
        self.write32(REG_RCR, 0xf410_400f)?;
        self.write16(REG_RXFLTMAP0, 0xffff)?;
        self.write16(REG_RXFLTMAP1, 0xffff)?;
        self.write16(REG_RXFLTMAP2, 0xffff)?;
        self.write32(REG_MAR_LO, 0xffff_ffff)?;
        self.write32(REG_MAR_HI, 0xffff_ffff)?;
        Ok(())
    }

    /// Set the operating channel (20 MHz monitor): per-channel BB band/BW + BB
    /// swing, the RF synthesiser (`RF 0x18`), RX DFIR, and the per-rate TX-power
    /// index write (the radiate gate). The BB/RF/power methods live in `phy.rs`.
    pub fn set_channel(&self, channel: u8) -> Result<(), FaceError> {
        self.set_channel_bb(channel)?;
        self.set_channel_bb_swing(channel)?;
        self.set_channel_rf(channel)?;
        self.set_channel_rxdfir()?;
        self.cur_channel.store(channel, Ordering::Relaxed);
        self.set_tx_power(channel)?;
        Ok(())
    }

    // ── TX/RX descriptors (tx.h / rx.h) ──────────────────────────────────────

    /// Build `[48-byte rtw88 TX descriptor][802.11 frame]` for `frame`, fixing
    /// the rate (USE_RATE + DISDATAFB + DATARATE) and routing to the MGMT queue.
    fn build_tx(&self, frame: &InjectFrame) -> Result<Vec<u8>, FaceError> {
        let body = self.build_80211(frame)?;
        let mut buf = vec![0u8; TX_DESC_SIZE + body.len()];

        txdesc_set(&mut buf, 0, 0, 16, body.len() as u32); // W0 TXPKTSIZE
        txdesc_set(&mut buf, 0, 16, 8, TX_DESC_SIZE as u32); // W0 OFFSET
        let bmc = frame.dst[0] & 0x01;
        txdesc_set(&mut buf, 0, 24, 1, bmc as u32); // W0 BMC
        txdesc_set(&mut buf, 0, 26, 1, 1); // W0 LS (last segment)

        // Match the kernel's golden monitor-injection TX descriptor (decoded
        // from a usbmon capture of rtw88 injecting): MACID=0, QSEL=HIGH(17),
        // RATE_ID=6, SPE_RPT. Crucially QSEL=HIGH maps to the same bulk-OUT
        // endpoint we send to; QSEL=MGMT(18) routes to a *different* endpoint on
        // this 3-OUT-pipe dongle, so the frame was dequeued (FIFO drained) but
        // never keyed — the "TX keys but doesn't radiate" symptom.
        txdesc_set(&mut buf, 1, 0, 8, 0); // W1 MACID = 0
        // QSEL: golden scan probe-reqs (which radiate, unassociated) use MGMT(18),
        // not HIGH(17). MGMT is not firmware-gated (probe/auth must work pre-assoc).
        // NDN_RADIO_QSEL overrides for sweeping; default 18 = MGMT.
        let qsel: u32 = std::env::var("NDN_RADIO_QSEL").ok().and_then(|s| s.parse().ok()).unwrap_or(17);
        txdesc_set(&mut buf, 1, 8, 5, qsel); // W1 QSEL
        txdesc_set(&mut buf, 1, 16, 5, 6); // W1 RATE_ID = 6
        txdesc_set(&mut buf, 2, 19, 1, 1); // W2 SPE_RPT

        let rate = rate_code(&frame.mcs);
        // The kernel injects with USE_RATE=0 (rate adaptation). Forcing a fixed
        // rate (USE_RATE+DISDATAFB) with no rate-table entry may be why TX didn't
        // key; default to the kernel style, `NDN_RADIO_FIXEDRATE=1` forces fixed.
        if std::env::var("NDN_RADIO_FIXEDRATE").is_ok() {
            txdesc_set(&mut buf, 3, 8, 1, 1); // W3 USE_RATE
            txdesc_set(&mut buf, 3, 10, 1, 1); // W3 DISDATAFB
        }
        txdesc_set(&mut buf, 4, 0, 7, rate as u32); // W4 DATARATE
        if frame.mcs.short_gi {
            txdesc_set(&mut buf, 5, 4, 1, 1); // W5 DATA_SHORT (SGI)
        }
        if frame.mcs.ldpc {
            txdesc_set(&mut buf, 5, 7, 1, 1); // W5 DATA_LDPC
        }
        let seq = self.seq.fetch_add(1, Ordering::Relaxed) & 0x0fff;
        txdesc_set(&mut buf, 8, 15, 1, 0); // W8 EN_HWSEQ off (we supply SEQ)
        txdesc_set(&mut buf, 9, 12, 12, seq as u32); // W9 SW_SEQ

        buf[TX_DESC_SIZE..].copy_from_slice(&body);
        txdesc_checksum(&mut buf);
        Ok(buf)
    }

    fn build_80211(&self, frame: &InjectFrame) -> Result<Vec<u8>, FaceError> {
        // TX-radiate investigation: rtw88/8821c firmware keys the PA for
        // *management* frames (probe/auth must work before association) but not
        // for host-injected *data* frames. NDN_RADIO_PROBE wraps the payload in a
        // probe-request with a vendor-specific IE so it rides the always-keyed
        // MGMT path. Mirrors the golden scan probe-req that we saw radiate.
        if std::env::var("NDN_RADIO_PROBE").is_ok() {
            return Ok(self.build_probe_req(frame));
        }
        let ethertype = match self.format {
            FrameFormat::RawNdn { ethertype } => ethertype,
            other => return frame::build_dot11(other, frame),
        };
        let seq = self.seq.fetch_add(1, Ordering::Relaxed) & 0x0fff;
        let mut out = Vec::with_capacity(24 + 8 + frame.payload.len());
        out.extend_from_slice(&[0x08, 0x00, 0x00, 0x00]); // FC data + duration
        out.extend_from_slice(&frame.dst); // addr1 = dst
        out.extend_from_slice(&frame.src); // addr2 = src
        // addr3: in IBSS, data frames carry the BSSID here (the firmware/peer
        // matches it); otherwise mirror dst (our prior monitor behaviour).
        if std::env::var("NDN_RADIO_IBSS").is_ok() {
            out.extend_from_slice(&IBSS_BSSID); // addr3 = BSSID
        } else {
            out.extend_from_slice(&frame.dst); // addr3
        }
        out.extend_from_slice(&(seq << 4).to_le_bytes());
        out.extend_from_slice(&LLC_SNAP_PREFIX);
        out.extend_from_slice(&ethertype.to_be_bytes());
        out.extend_from_slice(&frame.payload);
        Ok(out)
    }

    /// Build an 802.11 probe-request (mgmt, subtype 4) carrying `frame.payload`
    /// in a vendor-specific IE. Used to test/exploit the firmware's always-keyed
    /// MGMT TX path. Layout mirrors the golden radiating scan probe: broadcast
    /// addrs, wildcard SSID, supported-rates, DS-param(channel), then the vendor
    /// IE (0xdd, OUI = our DEFAULT_SRC[0..3]).
    fn build_probe_req(&self, frame: &InjectFrame) -> Vec<u8> {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed) & 0x0fff;
        let ch = self.cur_channel.load(Ordering::Relaxed);
        let mut out = Vec::with_capacity(40 + frame.payload.len());
        out.extend_from_slice(&[0x40, 0x00, 0x00, 0x00]); // FC=probe-req + duration
        out.extend_from_slice(&[0xff; 6]); // addr1 broadcast
        out.extend_from_slice(&frame.src); // addr2 = our MAC
        out.extend_from_slice(&[0xff; 6]); // addr3 broadcast (wildcard BSSID)
        out.extend_from_slice(&(seq << 4).to_le_bytes());
        // IEs:
        out.extend_from_slice(&[0x00, 0x00]); // SSID (wildcard, len 0)
        out.extend_from_slice(&[0x01, 0x08, 0x02, 0x04, 0x0b, 0x16, 0x0c, 0x12, 0x18, 0x24]); // rates
        out.extend_from_slice(&[0x03, 0x01, ch.max(1)]); // DS param: current channel
        // Vendor-specific IE carrying the NDN payload (chunked to <=255).
        let oui = [0x02u8, 0x4e, 0x44]; // DEFAULT_SRC[0..3]
        for chunk in frame.payload.chunks(252) {
            out.push(0xdd);
            out.push((chunk.len() + 3) as u8);
            out.extend_from_slice(&oui);
            out.extend_from_slice(chunk);
        }
        out
    }

    /// Parse one RX unit at `off`; returns the decoded frames (0 or 1) and the
    /// 8-byte-aligned stride to the next unit, or `None` if `off` is past the end.
    fn parse_rx_at(&self, buf: &[u8], off: usize) -> Option<(Vec<CapturedFrame>, usize)> {
        if off + RX_DESC_SIZE > buf.len() {
            return None;
        }
        let d = &buf[off..];
        let w0 = u32::from_le_bytes([d[0], d[1], d[2], d[3]]);
        let pkt_len = (w0 & 0x3fff) as usize;
        let crc_err = (w0 >> 14) & 1 != 0;
        let drv_info = ((w0 >> 16) & 0xf) as usize * 8;
        let shift = ((w0 >> 24) & 0x3) as usize;
        let physt = (w0 >> 26) & 1 != 0;
        let w2 = u32::from_le_bytes([d[8], d[9], d[10], d[11]]);
        let is_c2h = (w2 >> 28) & 1 != 0;
        let w3 = u32::from_le_bytes([d[12], d[13], d[14], d[15]]);
        let rate = (w3 & 0x7f) as u8;

        let hdr_off = RX_DESC_SIZE + drv_info + shift;
        let stride = (hdr_off + pkt_len).div_ceil(8) * 8;
        self.rx_raw_count.fetch_add(1, Ordering::Relaxed);

        // Raw RX diagnostic: every captured 802.11 unit, before NDN filtering.
        {
            use std::sync::OnceLock;
            static DBG: OnceLock<bool> = OnceLock::new();
            if *DBG.get_or_init(|| std::env::var("NDN_RADIO_RX_DEBUG").is_ok()) {
                eprintln!(
                    "RX unit @{off}: len={pkt_len} rate={rate:#04x} drv_info={drv_info} shift={shift} crc_err={crc_err} c2h={is_c2h} physt={physt}"
                );
            }
        }
        if pkt_len == 0 || off + hdr_off + pkt_len > buf.len() || is_c2h || crc_err {
            return Some((Vec::new(), stride.max(8)));
        }

        // RSSI from phy_status page 1 (OFDM/HT/VHT): PWDB_A(dword0[15:8]) - 110.
        let rssi = if physt && off + RX_DESC_SIZE + shift + 4 <= buf.len() {
            let ps = &buf[off + RX_DESC_SIZE + shift..];
            let page = ps[0] & 0xf;
            if page != 0 {
                let pwdb_a = ps[1]; // dword0 bits [15:8]
                Some((pwdb_a as i16 - 110).clamp(-120, 0) as i8)
            } else {
                None
            }
        } else {
            None
        };

        let body = &buf[off + hdr_off..off + hdr_off + pkt_len];
        // Strip the trailing FCS (4 bytes) that monitor RX appends.
        let body = if body.len() >= 4 { &body[..body.len() - 4] } else { body };
        let decoded = frame::parse_dot11(self.format, body, rssi, Some(rate))
            .into_iter()
            .collect();
        Some((decoded, stride.max(8)))
    }
}

// ── free helpers ─────────────────────────────────────────────────────────────

/// rtw88 rate enum (`DESC_RATE*`) for an [`McsDescriptor`].
fn rate_code(mcs: &crate::McsDescriptor) -> u8 {
    if let Ok(s) = std::env::var("NDN_RADIO_TX_RATE")
        && let Ok(v) = s.parse::<u8>()
    {
        return v;
    }
    if mcs.vht {
        DESC_RATE_VHT1SS_MCS0 + mcs.index
    } else if mcs.index == 0 && !mcs.vht {
        // default conservative: 6 Mbps OFDM rather than CCK
        DESC_RATE_MCS0 + mcs.index
    } else {
        DESC_RATE_MCS0 + mcs.index
    }
    .max(DESC_RATE_OFDM6M)
}

/// Set a big-endian-dword-relative bitfield in the little-endian descriptor:
/// `word` is the dword index, `bit`/`len` the field within that dword.
fn txdesc_set(desc: &mut [u8], word: usize, bit: u32, len: u32, value: u32) {
    let off = word * 4;
    let mut v = u32::from_le_bytes([desc[off], desc[off + 1], desc[off + 2], desc[off + 3]]);
    let mask = if len >= 32 { u32::MAX } else { ((1u32 << len) - 1) << bit };
    v = (v & !mask) | ((value << bit) & mask);
    desc[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// rtw88 TX-descriptor checksum (tx.h:124): zero W7[0:15], XOR the descriptor as
/// `__le16` words, store into W7[0:15].
fn txdesc_checksum(desc: &mut [u8]) {
    txdesc_set(desc, 7, 0, 16, 0);
    let mut sum: u16 = 0;
    let words = TX_DESC_SIZE / 2;
    for i in 0..words {
        sum ^= u16::from_le_bytes([desc[i * 2], desc[i * 2 + 1]]);
    }
    txdesc_set(desc, 7, 0, 16, sum as u32);
}

fn log_write(addr: u16, data: &[u8]) {
    use std::sync::OnceLock;
    static LOG: OnceLock<bool> = OnceLock::new();
    if *LOG.get_or_init(|| std::env::var("NDN_RADIO_LOG_WRITES").is_ok()) {
        let mut v = 0u32;
        for (i, b) in data.iter().enumerate().take(4) {
            v |= (*b as u32) << (i * 8);
        }
        eprintln!("W{}\t0x{:04x}\t0x{:0w$x}", data.len(), addr, v, w = data.len() * 2);
    }
}

/// Which write width / sentinel handling a phy_cond table uses.
#[derive(Clone, Copy)]
enum CfgKind {
    Mac,
    Agc,
    Bb,
    Rf,
}

/// Decode a phy_cond directive word (main.h struct rtw_phy_cond, little-endian).
fn parse_phy_cond(w: u32) -> PhyCond {
    PhyCond {
        rfe: (w & 0xff) as u8,
        intf: ((w >> 8) & 0xf) as u8,
        pkg: ((w >> 12) & 0xf) as u8,
        cut: ((w >> 24) & 0xf) as u8,
    }
}

/// rtw88 `check_positive` for 8821C (phy.c): cut/pkg/intf match if the directive
/// specifies them (nonzero); rfe must match exactly.
fn check_positive(cond: PhyCond, drv: PhyCond) -> bool {
    if cond.cut != 0 && cond.cut != drv.cut {
        return false;
    }
    if cond.pkg != 0 && cond.pkg != drv.pkg {
        return false;
    }
    if cond.intf != 0 && cond.intf != drv.intf {
        return false;
    }
    cond.rfe == drv.rfe
}

#[async_trait]
impl FrameIo for Rtl8821cuBackend {
    async fn inject(&self, frame: InjectFrame) -> Result<(), FaceError> {
        let buf = self.build_tx(&frame)?;
        let handle = self.handle.clone();
        // Endpoint selection for the TX-radiate investigation: NDN_RADIO_EP picks
        // an OUT pipe either by index (0,1,2…) or by raw address (e.g. 0x05).
        // Default: the MGMT pipe rtw88 uses for scan probes — the *last* OUT
        // endpoint on the 8821cu (high-priority/MGMT), which is the radiating one.
        let ep = match std::env::var("NDN_RADIO_EP").ok().and_then(|s| {
            s.strip_prefix("0x")
                .and_then(|h| u8::from_str_radix(h, 16).ok())
                .or_else(|| s.parse::<u8>().ok())
        }) {
            Some(v) if self.bulk_outs.contains(&v) => v,
            Some(idx) if (idx as usize) < self.bulk_outs.len() => self.bulk_outs[idx as usize],
            _ => self.bulk_out, // default: first OUT pipe (matches kernel injection)
        };
        tokio::task::spawn_blocking(move || {
            handle
                .write_bulk(ep, &buf, Duration::from_secs(1))
                .map_err(usb_err)
                .and_then(|n| {
                    (n == buf.len())
                        .then_some(())
                        .ok_or_else(|| init_err(format!("8821cu inject short {n}/{}", buf.len())))
                })
        })
        .await
        .map_err(|e| init_err(format!("8821cu inject join {e}")))?
    }

    async fn recv_frame(&self) -> Result<CapturedFrame, FaceError> {
        // Pumped mode: background threads fill rx_pending; just drain it.
        if self.rx_pumped.load(Ordering::Relaxed) {
            loop {
                let notified = self.rx_notify.notified();
                if let Some(f) = self.rx_pending.lock().unwrap().pop_front() {
                    return Ok(f);
                }
                let _ = tokio::time::timeout(Duration::from_millis(200), notified).await;
            }
        }
        loop {
            if let Some(f) = self.rx_pending.lock().unwrap().pop_front() {
                return Ok(f);
            }
            let handle = self.handle.clone();
            let ep = self.bulk_in;
            let buf = tokio::task::spawn_blocking(move || {
                let mut buf = vec![0u8; 32768];
                match handle.read_bulk(ep, &mut buf, Duration::from_millis(200)) {
                    Ok(n) => {
                        buf.truncate(n);
                        Ok(Some(buf))
                    }
                    Err(rusb::Error::Timeout) => Ok(None),
                    Err(e) => Err(usb_err(e)),
                }
            })
            .await
            .map_err(|e| init_err(format!("8821cu recv join {e}")))??;

            if let Some(buf) = buf {
                {
                    use std::sync::OnceLock;
                    static DBG: OnceLock<bool> = OnceLock::new();
                    if *DBG.get_or_init(|| std::env::var("NDN_RADIO_RX_DEBUG").is_ok()) {
                        eprintln!("bulk-IN transfer: {} bytes", buf.len());
                    }
                }
                let mut off = 0;
                let mut q = self.rx_pending.lock().unwrap();
                while let Some((decoded, advance)) = self.parse_rx_at(&buf, off) {
                    for f in decoded {
                        q.push_back(f);
                    }
                    off += advance;
                    if off + RX_DESC_SIZE > buf.len() {
                        break;
                    }
                }
            }
        }
    }
}
