//! Userspace **RTL8812AU** backend — our own libusb driver for the classic
//! 11ac monitor-injection chip (the aircrack-ng lineage).
//!
//! This is a fresh port, not a reuse of [`LibUsbRtl88xxBackend`](crate::LibUsbRtl88xxBackend):
//! the 8812**AU** is the *original* 2014-era 11ac silicon (the vendor
//! `rtl8812au` / kernel `rtw88_88xxa` family), a different HAL generation from
//! the 8812**EU**/8822E (halmac-8822) that backend drives. They share only the
//! Realtek USB register-I/O protocol, reproduced here. The morrownr/aircrack
//! `rtl8812au` C source and the kernel `rtw88_88xxa` driver are **reference
//! only** — on this OPi's Linux 7.0 kernel neither compiles (timer-API
//! removal), which is exactly why a userspace driver is the path.
//!
//! ## Why device-targeted open matters
//!
//! The test rig also carries an RTL8812**EU** (`0bda:a81a`, `wlu1`) driven by a
//! kernel module. [`open`](Rtl8812auBackend::open) therefore matches **only**
//! the 8812AU product ids ([`RTL8812AU_PIDS`]) — never `a81a` — and claims that
//! one device, so bringing up the AU never detaches the EU sniffer.
//!
//! ## Status: bring-up in progress
//!
//! Implemented: device-targeted USB open + the Realtek register-I/O protocol +
//! chip-version identification ([`chip_info`](Rtl8812auBackend::chip_info)). The
//! power-on sequence, firmware download, MAC/BB/RF init, and the `FrameIo`
//! inject/capture path are the next milestones (ported from the C reference).

use std::io;
use std::sync::Arc;
use std::time::Duration;

use std::collections::VecDeque;
use std::sync::Mutex;

use async_trait::async_trait;
use bytes::Bytes;
use rusb::{Context, Device, DeviceHandle, Direction, TransferType, UsbContext};

use ndn_frame_io::{CapturedFrame, FrameIo, InjectFrame};
use ndn_transport::FaceError;

// The RF-path enum is shared with the 8822E backend (an A/B selector).
use crate::RfPath;

/// Per-path convergence outcome of [`Rtl8812auBackend::iq_calibrate`]. A path
/// "converges" when two IQK measurements agree within ±4; otherwise an
/// identity-ish default is loaded and the flag is `false`.
#[derive(Debug, Clone, Copy, Default)]
pub struct IqkResult {
    /// Path A TX IQK converged; `tx_a_xy` holds the applied (X, Y) correction.
    pub tx_a: bool,
    /// Path A RX IQK converged; `rx_a_xy` holds the applied (X, Y) correction.
    pub rx_a: bool,
    /// Path B TX IQK converged.
    pub tx_b: bool,
    /// Path B RX IQK converged.
    pub rx_b: bool,
    /// Path A TX correction matrix (X, Y), 11-bit signed.
    pub tx_a_xy: (i32, i32),
    /// Path A RX correction matrix (X, Y), 11-bit signed.
    pub rx_a_xy: (i32, i32),
}

/// Realtek USB vendor request — identical to the 88xx path: `bRequest = 0x05`,
/// register address in `wValue`, `wIndex = 0`, little-endian data.
const VENDOR_REQ: u8 = 0x05;
const REQ_READ: u8 = 0xc0; // device-to-host | vendor | device
const REQ_WRITE: u8 = 0x40; // host-to-device | vendor | device
const CTRL_TIMEOUT: Duration = Duration::from_millis(500);

/// Realtek USB vendor id.
pub const REALTEK_VID: u16 = 0x0bda;

/// Known **RTL8812AU** USB product ids. Deliberately excludes `0xa81a` (the
/// 8812**EU**) so opening the AU never disturbs the EU monitor dongle on the
/// same host. `0x881a` is the RTL8812AU-VS on the test rig.
pub const RTL8812AU_PIDS: &[u16] = &[0x8812, 0x881a, 0x881b, 0x881c, 0x8813];

/// `REG_SYS_CFG` (`0x00F0`) — silicon configuration. For the 8812A the cut
/// version is bits `[15:12]`; the high bits carry vendor/RF-type straps. A read
/// of all-ones (`0xFFFFFFFF`) means the device is wedged / not responding.
pub const REG_SYS_CFG: u16 = 0x00F0;

/// `REG_SYS_CFG1` (`0x00FC`) — additional silicon config (vendor/RF straps).
pub const REG_SYS_CFG1: u16 = 0x00FC;

const REG_SYS_FUNC_EN: u16 = 0x0002;
const REG_RSV_CTRL: u16 = 0x001C;
/// RF enable control (`REG_RF_CTRL`); `0x07` = SDMRSTB|RSTB|EN (path A power-on).
const REG_RF_CTRL: u16 = 0x001F;
/// Path-B RF power-on control (`REG_OPT_CTRL_8812`; `+2` byte = `0x07`).
const REG_OPT_CTRL_8812: u16 = 0x0074;
/// `REG_SYS_FUNC_EN` baseband enables: BB reset, BB global reset-n, USB analog.
const FEN_BBRSTB: u8 = 1 << 0;
const FEN_BB_GLB_RSTN: u8 = 1 << 1;
const FEN_USBA: u8 = 1 << 2;
/// MCU firmware-download control register.
const REG_MCUFWDL: u16 = 0x0080;
/// Firmware RAM write window (the 4 KB page selected by `REG_MCUFWDL+2[2:0]`).
const FW_START_ADDRESS: u16 = 0x1000;
const MCUFWDL_RDY: u32 = 1 << 1;
const WINTINI_RDY: u32 = 1 << 6;
/// Firmware-download page size (4 KB) and the per-control-transfer write chunk.
const DLFW_PAGE_SIZE: usize = 4096;
const DLFW_BLOCK: usize = 196;

/// LLT (Link List Table) register — programs the TX packet-buffer page chain.
const REG_LLT_INIT: u16 = 0x01E0;
const LLT_NO_ACTIVE: u32 = 0x0;
const LLT_WRITE_ACCESS: u32 = 0x1;
const LLT_POLL_THRESHOLD: u32 = 20;
/// Last page of the 8812A TX packet buffer.
const LAST_TX_PKT_PAGE: u8 = 255;
/// TX-page boundary that separates the TX-queue page chain from the beacon /
/// loopback ring. `0xFF − BCNQ(7) − WoWLAN(0) − NDPA(0) − DBG(0) + 1` for our
/// non-WoWLAN / non-concurrent build (matches the vendor `TX_PAGE_BOUNDARY_8812`).
const TX_PAGE_BOUNDARY: u8 = 0xF9;

/// One entry of the halmac power sequence (`WLAN_PWR_CFG`), reduced to the fields
/// that matter for our single USB chip: a register op gated only by the command.
struct PwrCfg {
    offset: u16,
    cmd: u8,
    msk: u8,
    value: u8,
}
const PWR_WRITE: u8 = 1;
const PWR_POLLING: u8 = 2;

/// 8812A **card-enable** (`RTL8812_TRANS_CARDEMU_TO_ACT`) — bring the MAC power
/// domain up from card-emulation to active. Ported verbatim from the vendor
/// `Hal8812PwrSeq.h` (USB path; all entries apply to USB).
const CARDEMU_TO_ACT: &[PwrCfg] = &[
    // 0x04[10]=0: disable SW LPS.
    PwrCfg { offset: 0x0005, cmd: PWR_WRITE, msk: 0x04, value: 0x00 },
    // 0x04[17]=1: poll until power ready.
    PwrCfg { offset: 0x0006, cmd: PWR_POLLING, msk: 0x02, value: 0x02 },
    // 0x04[11]=0: disable WL suspend.
    PwrCfg { offset: 0x0005, cmd: PWR_WRITE, msk: 0x08, value: 0x00 },
    // 0x04[8]=1: APFM_ONMAC — turn on MAC via HW state machine.
    PwrCfg { offset: 0x0005, cmd: PWR_WRITE, msk: 0x01, value: 0x01 },
    // poll until 0x04[8]=0 (state machine done).
    PwrCfg { offset: 0x0005, cmd: PWR_POLLING, msk: 0x01, value: 0x00 },
    // 0x24[1]=0 / 0x28[3]=0: xosc buffer type.
    PwrCfg { offset: 0x0024, cmd: PWR_WRITE, msk: 0x02, value: 0x00 },
    PwrCfg { offset: 0x0028, cmd: PWR_WRITE, msk: 0x08, value: 0x00 },
];

/// 8812A **card-disable** (`RTL8812_TRANS_ACT_TO_CARDEMU`, USB entries) — bring
/// the MAC power domain down to card-emulation. Run before re-powering so a
/// repeated bring-up starts from a known state (`CARDEMU_TO_ACT` polls a
/// transition that never completes if the MAC is already active).
const ACT_TO_CARDEMU: &[PwrCfg] = &[
    // 0xc00/0xe00 = 4: turn off the BB 3-wire (path A/B).
    PwrCfg { offset: 0x0c00, cmd: PWR_WRITE, msk: 0xFF, value: 0x04 },
    PwrCfg { offset: 0x0e00, cmd: PWR_WRITE, msk: 0xFF, value: 0x04 },
    // 0x02[0] = 0: reset BB, close RF.
    PwrCfg { offset: 0x0002, cmd: PWR_WRITE, msk: 0x01, value: 0x00 },
    // 0x07 = 0x2A: SPS PWM mode.
    PwrCfg { offset: 0x0007, cmd: PWR_WRITE, msk: 0xFF, value: 0x2A },
    // 0x08[1] = 0: ANA clock 500 kHz.
    PwrCfg { offset: 0x0008, cmd: PWR_WRITE, msk: 0x02, value: 0x00 },
    // 0x04[9] = 1: turn off MAC via HW state machine, then poll until it clears.
    PwrCfg { offset: 0x0005, cmd: PWR_WRITE, msk: 0x02, value: 0x02 },
    PwrCfg { offset: 0x0005, cmd: PWR_POLLING, msk: 0x02, value: 0x00 },
];

/// The vendored 8812A **NIC** firmware (`array_mp_8812a_fw_nic`, v52.14,
/// signature `0x9501`) — extracted from the morrownr/aircrack `rtl8812au` C
/// source. A 32-byte header precedes the body that gets written to the MCU.
static FW_NIC: &[u8] = include_bytes!("../fw/rtl8812au/rtl8812au_fw_nic.bin");
const FW_HDR_LEN: usize = 32;

/// The 8812A MAC register table (`array_mp_8812a_mac_reg`), extracted from the
/// vendor phydm `halhwimg8812a_mac.c` as little-endian `u32` `(addr, value)`
/// pairs interleaved with phydm condition markers. Applied by [`mac_config`].
static MAC_REG: &[u8] = include_bytes!("../fw/rtl8812au/rtl8812au_mac_reg.bin");

/// 8812A baseband (PHY) register table (`array_mp_8812a_phy_reg`) and AGC table
/// (`array_mp_8812a_agc_tab`), extracted from the vendor phydm
/// `halhwimg8812a_bb.c`. Same phydm conditional format as [`MAC_REG`], applied as
/// 32-bit writes with delay opcodes (addr `0xfe..0xf9`). See [`bb_config`].
static PHY_REG: &[u8] = include_bytes!("../fw/rtl8812au/rtl8812au_phy_reg.bin");
static AGC_TAB: &[u8] = include_bytes!("../fw/rtl8812au/rtl8812au_agc_tab.bin");

/// 8812A RF register tables for path A (`array_mp_8812a_radioa`) and path B
/// (`array_mp_8812a_radiob`), from phydm `halhwimg8812a_rf.c`. Same conditional
/// format; each entry programs an RF register via the BB LSSI (see [`rf_config`]).
static RADIO_A: &[u8] = include_bytes!("../fw/rtl8812au/rtl8812au_radioa.bin");
static RADIO_B: &[u8] = include_bytes!("../fw/rtl8812au/rtl8812au_radiob.bin");

/// LSSI write registers (BB) per RF path — RF writes ride these (`rA/rB_LSSIWrite_Jaguar`).
const RF_LSSI_WRITE_A: u16 = 0x0C90;
const RF_LSSI_WRITE_B: u16 = 0x0E90;

/// The phydm `driver1` discriminant for **this** chip (`check_positive`): cut B
/// (`1<<24`) · package "don't-care" (`15<<12`) · interface USB (`ODM_ITRF_USB
/// = 2`, in `<<8`). Board-type is 0 (generic dongle), so `driver2`/`driver4` are
/// 0 and only the interface/cut nibbles of a condition can match.
const PHYDM_DRIVER1: u32 = (1 << 24) | (15 << 12) | (0x2 << 8);
const COND_ELSE: u8 = 2;
const COND_ENDIF: u8 = 3;

// MAC-init register map (hal_com_reg.h).
const REG_CR: u16 = 0x0100;
const REG_PBP: u16 = 0x0104;
const REG_TRXDMA_CTRL: u16 = 0x010C;
const REG_TRXFF_BNDY: u16 = 0x0114;
const REG_RQPN: u16 = 0x0200;
const REG_TDECTRL: u16 = 0x0208;
const REG_RQPN_NPQ: u16 = 0x0214;
const REG_BCNQ_BDNY: u16 = 0x0424;
const REG_MGQ_BDNY: u16 = 0x0425;
const REG_WMAC_LBK_BF_HD: u16 = 0x045D;
const REG_RCR: u16 = 0x0608;
const REG_RX_DRVINFO_SZ: u16 = 0x060F;
const REG_MAR: u16 = 0x0620;

/// `REG_CR` block-enable bits set right after power-on: HCI TX/RX DMA, MAC TX/RX
/// DMA, protocol, scheduler, security, and the 32k cal timer (= `0x063F`).
const CR_DMA_ENABLE: u16 = 0x063F;
/// MAC TX / RX enable (`REG_CR[7:6]`), set last.
const MACTXEN: u8 = 1 << 6;
const MACRXEN: u8 = 1 << 7;
/// `REG_RQPN`: HPQ 0x10 · LPQ 0x10 · PUBQ 0xD8 · `LD_RQPN` (load) — the
/// reserved-page split for a 3-bulk-OUT-endpoint device (NPQ 0, written to
/// `REG_RQPN_NPQ`). PUBQ = TX_TOTAL(0xF8) − HPQ − LPQ.
const RQPN_3EP: u32 = 0x10 | (0x10 << 8) | (0xD8 << 16) | (1 << 31);
/// `REG_TRXDMA_CTRL` queue→priority map for 3 OUT endpoints: VO/MGT/HI→HIGH,
/// VI→NORMAL, BE/BK→LOW (`0xF5B0`; low 3 bits preserved).
const TRXDMA_MAP_3EP: u16 = 0xF5B0;
/// RX-FIFO boundary (`RX_DMA_BOUNDARY_8812 = MAX_RX_DMA(0x3E80) − reserved(0) − 1`).
const RX_DMA_BOUNDARY: u16 = 0x3E7F;
/// `REG_PBP` transfer page size: TX 512 B (`_PSTX(PBP_512)` = `3<<4`).
const PBP_TX_512: u8 = 0x30;
/// `REG_CR` network-type field (`MASK_NETTYPE` / `_NETTYPE(NT_LINK_AP)`).
const MASK_NETTYPE: u32 = 0x30000;
const NETTYPE_AP: u32 = 0x2 << 16;
/// **Monitor** receive config: accept all unicast/phys-match/multicast/broadcast,
/// data + management frames, no BSSID filter, append PHY status (for RSSI), force
/// ACK off-path. `AAP|APM|AM|AB|ADF|AMF|HTC_LOC_CTRL|APP_PHYST_RXFF|FORCEACK`.
const MONITOR_RCR: u32 = 0x1 | 0x2 | 0x4 | 0x8 | (1 << 11) | (1 << 13) | (1 << 14) | (1 << 28) | (1 << 26);

// ── Milestone 8: frame injection / capture (TX/RX descriptors) ──────────────
/// 8812A TX descriptor size (`TXDESC_SIZE`): the WiFi-info header prepended to
/// every injected frame, and the `OFFSET` value (the 802.11 frame starts here).
const TXDESC_SIZE: usize = 40;
/// 8812A RX status-descriptor size (`RXDESC_SIZE`).
const RXDESC_SIZE: usize = 24;
/// Hardware rate code (`DESC_RATE6M`) for the `TX_RATE` field — legacy 6 Mbps
/// OFDM, the rate real NAN devices emit beacons/SDFs at.
const DESC_RATE_6M: u32 = 0x04;
/// Management-queue select (`QSLT_MGNT`) + its rate-adaptation group
/// (`RATEID_IDX_G`, the OFDM/11g table).
const QSLT_MGNT: u32 = 0x12;
const RATEID_IDX_G: u32 = 7;
/// Bulk-transfer timeouts (injection is fire-and-forget; capture polls).
const TX_TIMEOUT: Duration = Duration::from_millis(100);
const RX_TIMEOUT: Duration = Duration::from_millis(200);
/// Minimum plausible 802.11 management/data frame (24-byte header).
const DOT11_HDR_LEN: usize = 24;

/// Identified silicon details from [`Rtl8812auBackend::chip_info`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChipInfo {
    /// Raw `REG_SYS_CFG` (`0xF0`).
    pub sys_cfg: u32,
    /// Raw `REG_SYS_CFG1` (`0xFC`).
    pub sys_cfg1: u32,
    /// Cut/version, `REG_SYS_CFG[15:12]` (0 = A-cut, 1 = B-cut, …).
    pub cut: u8,
    /// True if this looks like a test chip (`REG_SYS_CFG` RTL-ID bit set).
    pub test_chip: bool,
}

impl ChipInfo {
    /// True when the registers read back as a live, sane device (not the wedged
    /// all-ones pattern).
    pub fn responsive(&self) -> bool {
        self.sys_cfg != 0xFFFF_FFFF && self.sys_cfg != 0
    }
}

fn usb_err(e: rusb::Error) -> FaceError {
    FaceError::Io(io::Error::other(format!("rtl8812au usb: {e}")))
}

fn init_err(what: impl Into<String>) -> FaceError {
    FaceError::Io(io::Error::other(what.into()))
}

/// A userspace RTL8812AU radio. Open with [`open`](Self::open); the handle keeps
/// interface 0 claimed for the backend's lifetime.
pub struct Rtl8812auBackend {
    handle: Arc<DeviceHandle<Context>>,
    /// Bulk OUT endpoint (frame injection).
    bulk_out: u8,
    /// Bulk IN endpoint (frame capture).
    bulk_in: u8,
    /// The product id we matched (diagnostics).
    pid: u16,
    /// RX frames de-aggregated from one bulk-IN URB (the 8812A stacks several
    /// 802.11 packets per USB transfer); drained one per `recv_frame` call.
    rx_pending: Mutex<VecDeque<CapturedFrame>>,
}

impl Rtl8812auBackend {
    /// Find and claim the RTL8812AU (a product id in [`RTL8812AU_PIDS`]), taking
    /// it from any kernel driver. Never matches the 8812EU (`0xa81a`), so a
    /// co-resident EU monitor dongle is left untouched.
    pub fn open() -> Result<Self, FaceError> {
        let context = Context::new().map_err(usb_err)?;
        for device in context.devices().map_err(usb_err)?.iter() {
            let desc = device.device_descriptor().map_err(usb_err)?;
            if desc.vendor_id() == REALTEK_VID && RTL8812AU_PIDS.contains(&desc.product_id()) {
                return Self::claim(device, desc.product_id());
            }
        }
        Err(FaceError::Io(io::Error::new(
            io::ErrorKind::NotFound,
            "no RTL8812AU found (Realtek 0bda:{8812,881a,881b,881c,8813})",
        )))
    }

    fn claim(device: Device<Context>, pid: u16) -> Result<Self, FaceError> {
        let handle = Arc::new(device.open().map_err(usb_err)?);
        // Detach only THIS device's kernel driver (Linux); leaves other adapters
        // (e.g. the 8812EU sniffer) bound to their drivers.
        let _ = handle.set_auto_detach_kernel_driver(true);
        // A USB port reset clears the device when the kernel driver's failed
        // probe / reset loop left its register interface unresponsive (vendor
        // reads time out otherwise). Best-effort: skip via `NDN_RADIO_NO_RESET=1`
        // (a stacked reset on a cold re-enumeration can re-wedge some devices).
        if std::env::var_os("NDN_RADIO_NO_RESET").is_none() {
            let _ = handle.reset();
        }
        handle.claim_interface(0).map_err(usb_err)?;

        let config = device.active_config_descriptor().map_err(usb_err)?;
        let (mut bulk_in, mut bulk_out) = (None, None);
        for iface in config.interfaces() {
            for desc in iface.descriptors() {
                for ep in desc.endpoint_descriptors() {
                    if ep.transfer_type() != TransferType::Bulk {
                        continue;
                    }
                    match ep.direction() {
                        // First bulk IN = RX (0x81); first bulk OUT = a TX queue.
                        Direction::In if bulk_in.is_none() => bulk_in = Some(ep.address()),
                        Direction::Out if bulk_out.is_none() => bulk_out = Some(ep.address()),
                        _ => {}
                    }
                }
            }
        }
        let no_ep = || init_err("RTL8812AU exposes no bulk IN/OUT endpoint");
        Ok(Self {
            handle,
            bulk_out: bulk_out.ok_or_else(no_ep)?,
            bulk_in: bulk_in.ok_or_else(no_ep)?,
            pid,
            rx_pending: Mutex::new(VecDeque::new()),
        })
    }

    /// The matched USB product id.
    pub fn pid(&self) -> u16 {
        self.pid
    }

    /// The discovered bulk endpoint addresses `(IN, OUT)`.
    pub fn endpoints(&self) -> (u8, u8) {
        (self.bulk_in, self.bulk_out)
    }

    // ── Realtek register I/O (the `usbctrl_vendorreq` path) ──────────────────

    fn read_reg(&self, addr: u16, buf: &mut [u8]) -> Result<(), FaceError> {
        let n = self
            .handle
            .read_control(REQ_READ, VENDOR_REQ, addr, 0, buf, CTRL_TIMEOUT)
            .map_err(usb_err)?;
        if n != buf.len() {
            return Err(init_err(format!(
                "rtl8812au read_reg({addr:#06x}): short {n}/{}",
                buf.len()
            )));
        }
        Ok(())
    }

    fn write_reg(&self, addr: u16, data: &[u8]) -> Result<(), FaceError> {
        let n = self
            .handle
            .write_control(REQ_WRITE, VENDOR_REQ, addr, 0, data, CTRL_TIMEOUT)
            .map_err(usb_err)?;
        if n != data.len() {
            return Err(init_err(format!(
                "rtl8812au write_reg({addr:#06x}): short {n}/{}",
                data.len()
            )));
        }
        Ok(())
    }

    /// Read an 8-bit register.
    pub fn read8(&self, addr: u16) -> Result<u8, FaceError> {
        let mut b = [0u8; 1];
        self.read_reg(addr, &mut b)?;
        Ok(b[0])
    }

    /// Read a 16-bit (little-endian) register.
    pub fn read16(&self, addr: u16) -> Result<u16, FaceError> {
        let mut b = [0u8; 2];
        self.read_reg(addr, &mut b)?;
        Ok(u16::from_le_bytes(b))
    }

    /// Read a 32-bit (little-endian) register.
    pub fn read32(&self, addr: u16) -> Result<u32, FaceError> {
        let mut b = [0u8; 4];
        self.read_reg(addr, &mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    /// Write an 8-bit register.
    pub fn write8(&self, addr: u16, val: u8) -> Result<(), FaceError> {
        self.write_reg(addr, &[val])
    }

    /// Write a 16-bit (little-endian) register.
    pub fn write16(&self, addr: u16, val: u16) -> Result<(), FaceError> {
        self.write_reg(addr, &val.to_le_bytes())
    }

    /// Write a 32-bit (little-endian) register.
    pub fn write32(&self, addr: u16, val: u32) -> Result<(), FaceError> {
        self.write_reg(addr, &val.to_le_bytes())
    }

    /// Read and decode the chip-version registers — the first bring-up
    /// checkpoint (proves USB register I/O works and identifies the silicon).
    pub fn chip_info(&self) -> Result<ChipInfo, FaceError> {
        let sys_cfg = self.read32(REG_SYS_CFG)?;
        let sys_cfg1 = self.read32(REG_SYS_CFG1)?;
        Ok(ChipInfo {
            sys_cfg,
            sys_cfg1,
            cut: ((sys_cfg >> 12) & 0xF) as u8,
            // RTL-ID / test-chip bit (BIT(23)) in REG_SYS_CFG.
            test_chip: sys_cfg & (1 << 23) != 0,
        })
    }

    // ── Milestone 2: power-on + firmware download ────────────────────────────

    /// Walk a halmac power sequence: `PWR_WRITE` is a masked read-modify-write,
    /// `PWR_POLLING` waits for the masked value (each read is a USB control
    /// transfer, so ~1000 tries is roughly a 1 s ceiling).
    fn run_pwr_seq(&self, seq: &[PwrCfg]) -> Result<(), FaceError> {
        for c in seq {
            match c.cmd {
                PWR_WRITE => {
                    let v = (self.read8(c.offset)? & !c.msk) | (c.value & c.msk);
                    self.write8(c.offset, v)?;
                }
                PWR_POLLING => {
                    let mut ready = false;
                    for _ in 0..1000 {
                        if self.read8(c.offset)? & c.msk == (c.value & c.msk) {
                            ready = true;
                            break;
                        }
                    }
                    if !ready {
                        return Err(init_err(format!(
                            "rtl8812au pwrseq: polling timeout @ {:#06x} msk {:#04x} want {:#04x}",
                            c.offset, c.msk, c.value
                        )));
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Bring the MAC power domain up (card-emulation → active) by running the
    /// 8812A [`CARDEMU_TO_ACT`] sequence. Run once after [`open`](Self::open),
    /// before [`download_firmware`](Self::download_firmware).
    pub fn power_on(&self) -> Result<(), FaceError> {
        // Release REG_RSV_CTRL so MCU-IO-wrapper register writes take effect.
        self.write8(REG_RSV_CTRL, 0)?;
        self.run_pwr_seq(CARDEMU_TO_ACT)
    }

    /// Bring the MAC power domain down to card-emulation ([`ACT_TO_CARDEMU`]).
    /// Call on a *brought-up* device before re-running [`power_on`](Self::power_on)
    /// so a repeated bring-up starts from a known state (the `CARDEMU_TO_ACT`
    /// poll never completes if the MAC is already active). Not auto-invoked by
    /// `power_on` — its BB-register writes fault on a freshly enumerated device
    /// whose MAC is not yet powered.
    pub fn power_off(&self) -> Result<(), FaceError> {
        self.write8(REG_RSV_CTRL, 0)?;
        self.run_pwr_seq(ACT_TO_CARDEMU)
    }

    /// Download the vendored 8812A NIC firmware to the MCU and wait for it to
    /// boot (`WINTINI_RDY`). Requires [`power_on`](Self::power_on) first. Returns
    /// the firmware `(version, subversion)` from its header.
    pub fn download_firmware(&self) -> Result<(u16, u8), FaceError> {
        let version = u16::from_le_bytes([FW_NIC[4], FW_NIC[5]]);
        let subversion = FW_NIC[6];
        let body = &FW_NIC[FW_HDR_LEN..];

        self.fw_dl_enable(true)?;
        self.write_fw(body)?;
        self.fw_dl_enable(false)?;
        self.fw_free_to_go()?;
        Ok((version, subversion))
    }

    /// `_FWDownloadEnable_8812`: gate the MCU firmware-download path and hold the
    /// 8051 in reset while writing (`enable`), or release it (`!enable`).
    fn fw_dl_enable(&self, enable: bool) -> Result<(), FaceError> {
        if enable {
            let t = self.read8(REG_MCUFWDL)?;
            self.write8(REG_MCUFWDL, t | 0x01)?; // MCUFWDL_EN
            let t = self.read8(REG_MCUFWDL + 2)?;
            self.write8(REG_MCUFWDL + 2, t & 0xf7)?; // hold 8051 reset
        } else {
            let t = self.read8(REG_MCUFWDL)?;
            self.write8(REG_MCUFWDL, t & 0xfe)?;
        }
        Ok(())
    }

    /// `_WriteFW_8812`: write the firmware body in 4 KB pages, selecting each
    /// page via `REG_MCUFWDL+2[2:0]` then block-writing it to the RAM window.
    fn write_fw(&self, body: &[u8]) -> Result<(), FaceError> {
        for (page, chunk) in body.chunks(DLFW_PAGE_SIZE).enumerate() {
            let v = (self.read8(REG_MCUFWDL + 2)? & 0xf8) | (page as u8 & 0x07);
            self.write8(REG_MCUFWDL + 2, v)?;
            self.block_write(chunk)?;
        }
        Ok(())
    }

    /// `_BlockWrite_8812` (USB): write a page's bytes to the firmware RAM window
    /// (`FW_START_ADDRESS`..) in ≤196-byte control transfers.
    fn block_write(&self, buf: &[u8]) -> Result<(), FaceError> {
        let mut off = 0;
        while off < buf.len() {
            let n = (buf.len() - off).min(DLFW_BLOCK);
            self.write_reg(FW_START_ADDRESS + off as u16, &buf[off..off + n])?;
            off += n;
        }
        Ok(())
    }

    /// `_FWFreeToGo8812`: mark download ready, reset the 8051, and poll until the
    /// firmware signals init done (`WINTINI_RDY`).
    fn fw_free_to_go(&self) -> Result<(), FaceError> {
        let mut v = self.read32(REG_MCUFWDL)?;
        v |= MCUFWDL_RDY;
        v &= !WINTINI_RDY;
        self.write32(REG_MCUFWDL, v)?;

        self.reset_8051()?;

        for _ in 0..1000 {
            if self.read32(REG_MCUFWDL)? & WINTINI_RDY != 0 {
                return Ok(());
            }
        }
        Err(init_err(
            "rtl8812au: firmware did not signal ready (WINTINI_RDY timeout)",
        ))
    }

    // ── Milestone 3 (first step): LLT packet-buffer page list ────────────────

    /// One LLT entry write: chain page `address` → page `data`, then poll the
    /// LLT engine back to idle (`_LLTWrite_8812A`).
    fn llt_write(&self, address: u8, data: u8) -> Result<(), FaceError> {
        let value = (data as u32) // _LLT_INIT_DATA: [7:0]
            | ((address as u32) << 8) // _LLT_INIT_ADDR: [15:8]
            | (LLT_WRITE_ACCESS << 30); // _LLT_OP: [31:30]
        self.write32(REG_LLT_INIT, value)?;
        for count in 0.. {
            if (self.read32(REG_LLT_INIT)? >> 30) & 0x3 == LLT_NO_ACTIVE {
                return Ok(());
            }
            if count > LLT_POLL_THRESHOLD {
                return Err(init_err(format!(
                    "rtl8812au: LLT write @page {address} timed out"
                )));
            }
        }
        unreachable!()
    }

    /// Initialize the LLT packet-buffer page chain (`InitLLTTable8812A`): pages
    /// `0..boundary-1` form a forward-linked TX-queue list ending in `0xFF`, and
    /// `boundary..255` form a ring (beacon / loopback buffer). Run after
    /// [`power_on`](Self::power_on); it's the first MAC-init step and each write
    /// polls, so success confirms the MAC's buffer engine is alive.
    pub fn init_llt(&self) -> Result<(), FaceError> {
        let boundary = TX_PAGE_BOUNDARY;
        // TX-queue list: each page points to the next.
        for i in 0..boundary - 1 {
            self.llt_write(i, i + 1)?;
        }
        // End of the TX-queue list.
        self.llt_write(boundary - 1, 0xFF)?;
        // Ring buffer over the remaining pages.
        for i in boundary..LAST_TX_PKT_PAGE {
            self.llt_write(i, i + 1)?;
        }
        // Last entry loops back to the ring start.
        self.llt_write(LAST_TX_PKT_PAGE, boundary)?;
        Ok(())
    }

    // ── Milestone 3: MAC register table (phydm conditional config) ───────────

    /// phydm `check_positive` for the MAC array, specialized to this chip.
    /// `cond1` is an IF condition word; returns whether it matches our cut /
    /// interface. Board-type is 0 here, so the `cond2`/`cond4` RF-path checks
    /// (which compare against `driver2`/`driver4 == 0`) only ever apply when a
    /// condition's board nibble is set — none do in the 8812A MAC table.
    fn check_positive(cond1: u32) -> bool {
        let driver1 = PHYDM_DRIVER1;
        // Value-defined checks: package [15:12], cut [27:24].
        if cond1 & 0x0000_F000 != 0 && cond1 & 0x0000_F000 != driver1 & 0x0000_F000 {
            return false;
        }
        if cond1 & 0x0F00_0000 != 0 && cond1 & 0x0F00_0000 != driver1 & 0x0F00_0000 {
            return false;
        }
        // Bit-defined check (interface/board nibble).
        let c = cond1 & 0x00FF_0FFF;
        let d = driver1 & 0x00FF_0FFF;
        if c & d != c {
            return false;
        }
        // Board-type DONTCARE (nibble 0) ⇒ matched on interface alone.
        c & 0x0F == 0
    }

    /// Walk a phydm conditional config table (`(addr, value)` `u32` pairs with
    /// IF/ELSE/ENDIF markers in the high bits), applying each matching entry for
    /// our cut/interface via `apply`. Shared by the MAC, BB, and AGC tables —
    /// they use the identical phydm condition format.
    fn config_table(
        &self,
        table: &[u8],
        mut apply: impl FnMut(&Self, u32, u32) -> Result<(), FaceError>,
    ) -> Result<(), FaceError> {
        let words: Vec<u32> = table
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect();

        let mut is_matched = true;
        let mut is_skipped = false;
        let mut pre = 0u32;
        let mut i = 0;
        while i + 1 < words.len() {
            let (v1, v2) = (words[i], words[i + 1]);
            if v1 & 0xC000_0000 != 0 {
                if v1 & 0x8000_0000 != 0 {
                    // Positive marker: IF / ELSE-IF (store), ELSE, or ENDIF.
                    let c_cond = ((v1 >> 28) & 0x3) as u8;
                    if c_cond == COND_ENDIF {
                        is_matched = true;
                        is_skipped = false;
                    } else if c_cond == COND_ELSE {
                        is_matched = !is_skipped;
                    } else {
                        pre = v1; // remember the IF condition for the negative entry
                    }
                } else if !is_skipped {
                    // Negative marker: evaluate the stored IF condition.
                    if Self::check_positive(pre) {
                        is_matched = true;
                        is_skipped = true;
                    } else {
                        is_matched = false;
                        is_skipped = false;
                    }
                } else {
                    is_matched = false;
                }
            } else if is_matched {
                apply(self, v1, v2)?;
            }
            i += 2;
        }
        Ok(())
    }

    /// Apply the MAC register table (`PHY_MACConfig8812`): byte writes, honoring
    /// the phydm condition blocks. Run after the firmware is ready.
    pub fn mac_config(&self) -> Result<(), FaceError> {
        self.config_table(MAC_REG, |s, addr, val| s.write8(addr as u16, val as u8))
    }

    // ── Milestone 4: baseband (BB/PHY) + AGC init ────────────────────────────

    /// Apply one BB register entry: a delay opcode (addr `0xfe..0xf9`) or a full
    /// dword write to the BB register space (`odm_config_bb_phy_8812a`).
    fn bb_write(&self, addr: u32, data: u32) -> Result<(), FaceError> {
        match addr {
            0xfe => std::thread::sleep(Duration::from_millis(50)),
            0xfd => std::thread::sleep(Duration::from_millis(5)),
            0xfc => std::thread::sleep(Duration::from_millis(1)),
            0xfb => std::thread::sleep(Duration::from_micros(50)),
            0xfa => std::thread::sleep(Duration::from_micros(5)),
            0xf9 => std::thread::sleep(Duration::from_micros(1)),
            _ => self.write32(addr as u16, data)?,
        }
        Ok(())
    }

    /// Configure the baseband (`PHY_BBConfig8812`): power on BB + both RF paths,
    /// then apply the BB PHY-register table and the AGC table. Run after
    /// [`mac_init_queues`](Self::mac_init_queues). Reuses the phydm condition
    /// evaluator (the BB/AGC tables share the MAC table's conditional format).
    pub fn bb_config(&self) -> Result<(), FaceError> {
        // Power on baseband + RF analog.
        let fen = self.read8(REG_SYS_FUNC_EN)?;
        self.write8(REG_SYS_FUNC_EN, fen | FEN_USBA)?;
        self.write8(
            REG_SYS_FUNC_EN,
            fen | FEN_USBA | FEN_BB_GLB_RSTN | FEN_BBRSTB,
        )?;
        self.write8(REG_RF_CTRL, 0x07)?; // path-A RF power on
        self.write8(REG_OPT_CTRL_8812 + 2, 0x07)?; // path-B RF power on

        // BB PHY register table, then the AGC table.
        self.config_table(PHY_REG, |s, a, d| s.bb_write(a, d))?;
        self.config_table(AGC_TAB, |s, a, d| s.bb_write(a, d))?;
        Ok(())
    }

    /// Read a baseband register (32-bit) — for verifying [`bb_config`].
    pub fn bb_read(&self, addr: u16) -> Result<u32, FaceError> {
        self.read32(addr)
    }

    /// Masked baseband write (`phy_set_bb_reg`): read-modify-write the `mask`
    /// bits of `addr` with `data` (shifted to the mask's position).
    fn bb_set(&self, addr: u16, mask: u32, data: u32) -> Result<(), FaceError> {
        if mask == 0xFFFF_FFFF {
            self.write32(addr, data)
        } else {
            let shift = mask.trailing_zeros();
            let v = (self.read32(addr)? & !mask) | ((data << shift) & mask);
            self.write32(addr, v)
        }
    }

    /// Masked baseband read (`phy_query_bb_reg`).
    fn bb_query(&self, addr: u16, mask: u32) -> Result<u32, FaceError> {
        Ok((self.read32(addr)? & mask) >> mask.trailing_zeros())
    }

    // ── Milestone 5: RF (radio) register init ────────────────────────────────

    /// RF serial write (`phy_RFSerialWrite`): `DataAndAddr =
    /// (rf_addr<<20 | data&0xFFFFF) & 0x0FFFFFFF` → the path's LSSI write register.
    fn rf_write(&self, path: RfPath, rf_addr: u32, data: u32) -> Result<(), FaceError> {
        let lssi = match path {
            RfPath::A => RF_LSSI_WRITE_A,
            RfPath::B => RF_LSSI_WRITE_B,
        };
        self.write32(lssi, ((rf_addr << 20) | (data & 0x000F_FFFF)) & 0x0FFF_FFFF)
    }

    /// One RF table entry: a delay opcode (addr `0xfe`/`0xffe`) or an RF write.
    fn rf_write_entry(&self, path: RfPath, addr: u32, data: u32) -> Result<(), FaceError> {
        if addr == 0xfe || addr == 0xffe {
            std::thread::sleep(Duration::from_millis(50));
            return Ok(());
        }
        self.rf_write(path, addr, data)
    }

    /// Masked RF write (`phy_set_rf_reg`): read-modify-write the `mask` bits of
    /// RF register `rf_addr` on `path`.
    fn rf_set(&self, path: RfPath, rf_addr: u32, mask: u32, data: u32) -> Result<(), FaceError> {
        if mask == 0x000F_FFFF {
            self.rf_write(path, rf_addr, data)
        } else {
            let shift = mask.trailing_zeros();
            let v = (self.rf_read(path, rf_addr)? & !mask) | ((data << shift) & mask);
            self.rf_write(path, rf_addr, v)
        }
    }

    // ── Milestone 7: channel / bandwidth selection (2.4 GHz, 20 MHz) ──────────

    /// Tune to a 2.4 GHz `channel` (1–14) at 20 MHz — the 5 GHz→2.4 GHz band
    /// switch (`PHY_SwitchWirelessBand8812`), the channel write to RF `0x18` on
    /// both paths, and the 20 MHz bandwidth set. Run after the PHY is configured
    /// ([`rf_config`](Self::rf_config)). Verify by reading RF `0x18` back (byte 0
    /// = channel).  Assumes `rfe_type == 0` (the common generic-dongle RFE).
    pub fn set_channel(&self, channel: u8) -> Result<(), FaceError> {
        // ── 2.4 GHz band switch (BB) ──
        self.bb_set(0x0808, 0x3000_0000, 0x03)?; // OFDM + CCK enable (0x808)
        self.bb_set(0x0834, 0x3, 0x1)?; // BW indication
        self.bb_set(0x0830, 0x3_E000, 0x17)?; // PD_TH 0x830[17:13]
        self.bb_set(0x0830, 0xE, 0x04)?; // 0x830[3:1] = 100 (2T)
        self.bb_set(0x082C, 0x3, 0x0)?; // AGC table select 2.4 G
        // RFE (rfe_type 0): pinmux 0x77777777, inv 0.
        self.write32(0x0CB0, 0x7777_7777)?;
        self.write32(0x0EB0, 0x7777_7777)?;
        self.bb_set(0x0CB4, 0x3FF0_0000, 0x000)?;
        self.bb_set(0x0EB4, 0x3FF0_0000, 0x000)?;
        // CCK FA / scan workaround + CCK check (clear 0x454[7] for 2.4 G).
        self.bb_set(0x080C, 0xF0, 0x1)?;
        self.bb_set(0x0A04, 0x0F00_0000, 0x1)?;
        let cck = self.read8(0x0454)?;
        self.write8(0x0454, cck & !0x80)?;

        // fc_area (channel < 36).
        self.bb_set(0x0860, 0x1FFE_0000, 0x96A)?;

        // ── RF channel + band/mode + bandwidth, both paths ──
        for path in [RfPath::A, RfPath::B] {
            // RF_MOD_AG: 2.4 G band/mode (bits 18,17,16,9,8 = 0).
            self.rf_set(path, 0x18, 0x7_0300, 0x000)?;
            // Bandwidth bits [11:10] = 20 MHz.
            self.rf_set(path, 0x18, 0xC00, 0x3)?;
            // Channel number (byte 0).
            self.rf_set(path, 0x18, 0xFF, channel as u32)?;
        }

        // ── 20 MHz bandwidth (BB + MAC) ──
        self.bb_set(0x08AC, 0x0030_03C3, 0x0030_0200)?; // rRFMOD 20 MHz
        self.bb_set(0x08AC, 0x300, 0x2)?; // spur workaround, ch ≤ 14
        let trx = self.read16(0x0668)?;
        self.write16(0x0668, trx & 0xFE7F)?; // WMAC TRXPTCL: 20 MHz (BIT7=BIT8=0)
        Ok(())
    }

    // ── Milestone 6: RF calibration (LCK; IQK) ───────────────────────────────

    /// LC (VCO/PLL) calibration (`_phy_lc_calibrate_8812a`): pause TX, enter LCK
    /// mode, trigger the LC cal on RF `0x18[15]`, poll until done, and restore.
    /// Locks the synthesizer for the current channel; run after
    /// [`set_channel`](Self::set_channel).
    pub fn lc_calibrate(&self) -> Result<(), FaceError> {
        const RF_LCK: u32 = 0xB4;
        const RF_CHNLBW: u32 = 0x18;
        const REG_TXPAUSE: u16 = 0x0522;

        // If a continuous-tone TX is active (0x914[18:16]), don't pause; else
        // pause packet TX during the cal.
        let cont_tx = self.read32(0x0914)? & 0x7_0000 != 0;
        if !cont_tx {
            self.write8(REG_TXPAUSE, 0xFF)?;
        }

        // Enter LCK mode.
        let lck = self.rf_read(RfPath::A, RF_LCK)?;
        self.rf_write(RfPath::A, RF_LCK, lck | (1 << 14))?;

        // Trigger LC cal (RF 0x18[15]) and poll until it self-clears.
        let lc_cal = self.rf_read(RfPath::A, RF_CHNLBW)?;
        self.rf_write(RfPath::A, RF_CHNLBW, lc_cal | 0x0_8000)?;
        std::thread::sleep(Duration::from_millis(150));
        for _ in 0..5 {
            if self.rf_read(RfPath::A, RF_CHNLBW)? & 0x8000 == 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        self.rf_write(RfPath::A, RF_CHNLBW, lc_cal)?; // restore RF 0x18

        // Leave LCK mode + un-pause TX.
        let lck = self.rf_read(RfPath::A, RF_LCK)?;
        self.rf_write(RfPath::A, RF_LCK, lck & !(1 << 14))?;
        if !cont_tx {
            self.write8(REG_TXPAUSE, 0x00)?;
        }
        Ok(())
    }

    /// Select BB page C (`c1=false`) or page C1 (`c1=true`) via `0x82c[31]`.
    /// The IQK reuses the same 0xc80–0xed4 addresses across two physical pages,
    /// so every page toggle in the vendor flow must be preserved exactly.
    fn page(&self, c1: bool) -> Result<(), FaceError> {
        self.bb_set(0x82c, 0x8000_0000, c1 as u32)
    }

    /// Read an 11-bit signed IQK result field (`[26:16]`) from `reg` (`0xd00`/
    /// `0xd40`) and sign-extend it — the vendor's `(val << 21) >> 21` idiom.
    fn iqk_result11(&self, reg: u16) -> Result<i32, FaceError> {
        let raw = self.bb_query(reg, 0x07ff_0000)? as i32;
        Ok((raw << 21) >> 21)
    }

    /// IQK MAC setup (`_iqk_configure_mac_8812a`): pause TX, RX antenna off,
    /// CCA off, CCK RX path off — quiesce the MAC so the loopback tone is clean.
    fn iqk_configure_mac(&self) -> Result<(), FaceError> {
        self.page(false)?;
        self.write8(0x522, 0x3f)?;
        self.bb_set(0x550, (1 << 11) | (1 << 3), 0x0)?;
        self.write8(0x808, 0x00)?; // RX ante off
        self.bb_set(0x838, 0xf, 0xc)?; // CCA off
        self.write8(0xa07, 0xf)?; // CCK RX path off
        Ok(())
    }

    /// Apply the measured TX IQ correction matrix (`_iqk_tx_fill_iqc_8812a`).
    /// `dpk_done == false` here, so the BIT(29) gates are always set.
    fn iqk_tx_fill_iqc(&self, path: RfPath, tx_x: i32, tx_y: i32) -> Result<(), FaceError> {
        let x = (tx_x & 0x7ff) as u32;
        let y = (tx_y & 0x7ff) as u32;
        self.page(true)?;
        match path {
            RfPath::A => {
                self.bb_set(0xc90, 1 << 7, 0x1)?;
                self.bb_set(0xcc4, 1 << 18, 0x1)?;
                self.bb_set(0xcc4, 1 << 29, 0x1)?;
                self.bb_set(0xcc8, 1 << 29, 0x1)?;
                self.bb_set(0xccc, 0x7ff, y)?;
                self.bb_set(0xcd4, 0x7ff, x)?;
            }
            RfPath::B => {
                self.bb_set(0xe90, 1 << 7, 0x1)?;
                self.bb_set(0xec4, 1 << 18, 0x1)?;
                self.bb_set(0xec4, 1 << 29, 0x1)?;
                self.bb_set(0xec8, 1 << 29, 0x1)?;
                self.bb_set(0xecc, 0x7ff, y)?;
                self.bb_set(0xed4, 0x7ff, x)?;
            }
        }
        Ok(())
    }

    /// Apply the measured RX IQ correction matrix (`_iqk_rx_fill_iqc_8812a`).
    /// `rx_x`/`rx_y` carry the sign-extended bit pattern (passed unsigned, as in
    /// the C); out-of-range corrections are clamped to the identity-ish default.
    fn iqk_rx_fill_iqc(&self, path: RfPath, rx_x: u32, rx_y: u32) -> Result<(), FaceError> {
        self.page(false)?;
        let reg: u16 = match path {
            RfPath::A => 0xc10,
            RfPath::B => 0xe10,
        };
        let xs = rx_x >> 1;
        let ys = rx_y >> 1;
        if xs >= 0x112 || (ys >= 0x12 && ys <= 0x3ee) {
            self.bb_set(reg, 0x0000_03ff, 0x100)?;
            self.bb_set(reg, 0x03ff_0000, 0)?;
        } else {
            self.bb_set(reg, 0x0000_03ff, xs)?;
            self.bb_set(reg, 0x03ff_0000, ys)?;
        }
        Ok(())
    }

    /// Restore the AFE registers and re-arm the IQ-compensation datapath after
    /// IQK (`_iqk_restore_afe_8812a`, `dpk_done == false` branch).
    fn iqk_restore_afe(&self, afe_bk: &[u32; 12], afe: &[u16; 12]) -> Result<(), FaceError> {
        self.page(false)?;
        for (i, &r) in afe.iter().enumerate() {
            self.write32(r, afe_bk[i])?;
        }
        self.page(true)?;
        self.write32(0xc80, 0x0)?;
        self.write32(0xc84, 0x0)?;
        self.write32(0xc88, 0x0)?;
        self.write32(0xc8c, 0x3c00_0000)?;
        self.bb_set(0xc90, 1 << 7, 0x1)?;
        self.bb_set(0xcc4, 1 << 18, 0x1)?;
        self.bb_set(0xcc4, 1 << 29, 0x1)?;
        self.bb_set(0xcc8, 1 << 29, 0x1)?;
        self.write32(0xe80, 0x0)?;
        self.write32(0xe84, 0x0)?;
        self.write32(0xe88, 0x0)?;
        self.write32(0xe8c, 0x3c00_0000)?;
        self.bb_set(0xe90, 1 << 7, 0x1)?;
        self.bb_set(0xec4, 1 << 18, 0x1)?;
        self.bb_set(0xec4, 1 << 29, 0x1)?;
        self.bb_set(0xec8, 1 << 29, 0x1)?;
        Ok(())
    }

    /// The dual-path (A+B) TX and RX IQ calibration core (`_iqk_tx_8812a`),
    /// specialised to 2.4 GHz / 20 MHz / USB / rfe_type 0 / no ext-PA / no DPK /
    /// VDF off. Injects a 16-tone loopback, polls the IQK engine, averages two
    /// agreeing results per path, then fills the correction matrices.
    fn iqk_tx(&self) -> Result<IqkResult, FaceError> {
        use std::thread::sleep;
        let mut tx_temp = [[0i32; 4]; 10];
        let mut rx_temp = [[0i32; 4]; 10];
        let mut tx_iqc = [0i32; 4];
        let mut rx_iqc = [0i32; 4];
        let (mut tx0_fin, mut tx1_fin) = (false, false);
        let (mut rx0_fin, mut rx1_fin) = (false, false);

        // ── path A+B AFE all on ──
        self.page(false)?;
        self.write32(0xc60, 0x7777_7777)?;
        self.write32(0xc64, 0x7777_7777)?;
        self.write32(0xe60, 0x7777_7777)?;
        self.write32(0xe64, 0x7777_7777)?;
        self.write32(0xc68, 0x1979_1979)?;
        self.write32(0xe68, 0x1979_1979)?;
        self.bb_set(0xc00, 0xf, 0x4)?; // 3-wire off
        self.bb_set(0xe00, 0xf, 0x4)?;
        self.bb_set(0xc5c, (1 << 26) | (1 << 25) | (1 << 24), 0x7)?; // 160 MHz
        self.bb_set(0xe5c, (1 << 26) | (1 << 25) | (1 << 24), 0x7)?;

        // ── TX IQK RF setting, both paths ──
        self.page(false)?;
        for p in [RfPath::A, RfPath::B] {
            self.rf_write(p, 0xef, 0x80002)?;
            self.rf_write(p, 0x30, 0x20000)?;
            self.rf_write(p, 0x31, 0x3fffd)?;
            self.rf_write(p, 0x32, 0xfe83f)?;
            self.rf_write(p, 0x65, 0x931d5)?;
            self.rf_write(p, 0x8f, 0x8a001)?;
        }
        self.write32(0x90c, 0x0000_8000)?;
        self.bb_set(0xc94, 1 << 0, 0x1)?;
        self.bb_set(0xe94, 1 << 0, 0x1)?;
        self.write32(0x978, 0x2900_2000)?;
        self.write32(0x97c, 0xa900_2000)?;
        self.write32(0x984, 0x0046_2910)?;
        self.page(true)?;
        self.write32(0xc88, 0x8214_03f1)?; // ext_pa_5g = 0
        self.write32(0xe88, 0x8214_03f1)?;
        self.write32(0xc8c, 0x2816_3e96)?; // band 2.4G
        self.write32(0xe8c, 0x2816_3e96)?;
        self.write32(0xc80, 0x1800_8c10)?; // TX tone idx = 16
        self.write32(0xc84, 0x3800_8c10)?;
        self.write32(0xce8, 0x0)?;
        self.write32(0xe80, 0x1800_8c10)?;
        self.write32(0xe84, 0x3800_8c10)?;
        self.write32(0xee8, 0x0)?;

        // ── TX IQK measurement loop (page stays C1) ──
        let (mut tx0_avg, mut tx1_avg) = (0usize, 0usize);
        let (mut cal0, mut cal1) = (0u8, 0u8);
        loop {
            // one shot
            self.write32(0xcb8, 0x0010_0000)?;
            self.write32(0xeb8, 0x0010_0000)?;
            self.write32(0x980, 0xfa00_0000)?;
            self.write32(0x980, 0xf800_0000)?;
            sleep(Duration::from_millis(10));
            self.write32(0xcb8, 0x0)?;
            self.write32(0xeb8, 0x0)?;

            let mut delay = 0;
            let (mut r0, mut r1) = (false, false);
            loop {
                if !tx0_fin {
                    r0 = self.bb_query(0xd00, 1 << 10)? != 0;
                }
                if !tx1_fin {
                    r1 = self.bb_query(0xd40, 1 << 10)? != 0;
                }
                if (r0 && r1) || delay > 20 {
                    break;
                }
                sleep(Duration::from_millis(1));
                delay += 1;
            }
            if delay < 20 {
                let tx0_fail = self.bb_query(0xd00, 1 << 12)? != 0;
                let tx1_fail = self.bb_query(0xd40, 1 << 12)? != 0;
                if !(tx0_fail || tx0_fin) {
                    self.write32(0xcb8, 0x0200_0000)?;
                    tx_temp[tx0_avg][0] = self.iqk_result11(0xd00)?;
                    self.write32(0xcb8, 0x0400_0000)?;
                    tx_temp[tx0_avg][1] = self.iqk_result11(0xd00)?;
                    tx0_avg += 1;
                } else {
                    cal0 += 1;
                    if cal0 == 10 {
                        break;
                    }
                }
                if !(tx1_fail || tx1_fin) {
                    self.write32(0xeb8, 0x0200_0000)?;
                    tx_temp[tx1_avg][2] = self.iqk_result11(0xd40)?;
                    self.write32(0xeb8, 0x0400_0000)?;
                    tx_temp[tx1_avg][3] = self.iqk_result11(0xd40)?;
                    tx1_avg += 1;
                } else {
                    cal1 += 1;
                    if cal1 == 10 {
                        break;
                    }
                }
            } else {
                cal0 += 1;
                cal1 += 1;
                if cal0 == 10 {
                    break;
                }
            }
            // accept a path once two measurements agree within ±4
            if tx0_avg >= 2 {
                for i in 0..tx0_avg {
                    for ii in (i + 1)..tx0_avg {
                        let dx = tx_temp[i][0] - tx_temp[ii][0];
                        let dy = tx_temp[i][1] - tx_temp[ii][1];
                        if dx > -4 && dx < 4 && dy > -4 && dy < 4 {
                            tx_iqc[0] = (tx_temp[i][0] + tx_temp[ii][0]) / 2;
                            tx_iqc[1] = (tx_temp[i][1] + tx_temp[ii][1]) / 2;
                            tx0_fin = true;
                        }
                    }
                }
            }
            if tx1_avg >= 2 {
                for i in 0..tx1_avg {
                    for ii in (i + 1)..tx1_avg {
                        let dx = tx_temp[i][2] - tx_temp[ii][2];
                        let dy = tx_temp[i][3] - tx_temp[ii][3];
                        if dx > -4 && dx < 4 && dy > -4 && dy < 4 {
                            tx_iqc[2] = (tx_temp[i][2] + tx_temp[ii][2]) / 2;
                            tx_iqc[3] = (tx_temp[i][3] + tx_temp[ii][3]) / 2;
                            tx1_fin = true;
                        }
                    }
                }
            }
            if tx0_fin && tx1_fin {
                break;
            }
            if (cal0 as usize + tx0_avg) >= 10 || (cal1 as usize + tx1_avg) >= 10 {
                break;
            }
        }

        // ── Load LOK (lo leakage cal result) into RF 0x58 ──
        self.page(false)?;
        let lok_a = (self.rf_read(RfPath::A, 0x08)? & 0xffc00) >> 10;
        self.rf_set(RfPath::A, 0x58, 0x7fe00, lok_a)?;
        let lok_b = (self.rf_read(RfPath::B, 0x08)? & 0xffc00) >> 10;
        self.rf_set(RfPath::B, 0x58, 0x7fe00, lok_b)?;
        self.page(true)?;

        // ── RX IQK setup ──
        self.page(false)?;
        if tx0_fin {
            self.rf_write(RfPath::A, 0xef, 0x80000)?;
            self.rf_write(RfPath::A, 0x30, 0x30000)?;
            self.rf_write(RfPath::A, 0x31, 0x3f7ff)?;
            self.rf_write(RfPath::A, 0x32, 0xfe7bf)?;
            self.rf_write(RfPath::A, 0x8f, 0x88001)?;
            self.rf_write(RfPath::A, 0x65, 0x931d1)?;
            self.rf_write(RfPath::A, 0xef, 0x00000)?;
        }
        if tx1_fin {
            self.rf_write(RfPath::B, 0xef, 0x80000)?;
            self.rf_write(RfPath::B, 0x30, 0x30000)?;
            self.rf_write(RfPath::B, 0x31, 0x3f7ff)?;
            self.rf_write(RfPath::B, 0x32, 0xfe7bf)?;
            self.rf_write(RfPath::B, 0x8f, 0x88001)?;
            self.rf_write(RfPath::B, 0x65, 0x931d1)?;
            self.rf_write(RfPath::B, 0xef, 0x00000)?;
        }
        self.bb_set(0x978, 1 << 31, 0x1)?;
        self.bb_set(0x97c, 1 << 31, 0x0)?;
        self.write32(0x90c, 0x0000_8000)?;
        self.write32(0x984, 0x0046_a890)?; // USB interface
        self.write32(0xcb0, 0x7777_7717)?; // rfe_type != 1
        self.write32(0xcb4, 0x0200_0077)?;
        self.write32(0xeb0, 0x7777_7717)?;
        self.write32(0xeb4, 0x0200_0077)?;
        self.page(true)?;
        if tx0_fin {
            self.write32(0xc80, 0x3800_8c10)?;
            self.write32(0xc84, 0x1800_8c10)?;
            self.write32(0xc88, 0x8214_0119)?;
        }
        if tx1_fin {
            self.write32(0xe80, 0x3800_8c10)?;
            self.write32(0xe84, 0x1800_8c10)?;
            self.write32(0xe88, 0x8214_0119)?;
        }

        // ── RX IQK measurement loop ──
        let (mut rx0_avg, mut rx1_avg) = (0usize, 0usize);
        cal0 = 0;
        cal1 = 0;
        loop {
            // re-apply the TX correction, then one-shot RX
            self.page(false)?;
            if tx0_fin {
                self.bb_set(0x978, 0x03ff_8000, (tx_iqc[0] & 0x7ff) as u32)?;
                self.bb_set(0x978, 0x0000_07ff, (tx_iqc[1] & 0x7ff) as u32)?;
                self.page(true)?;
                self.write32(0xc8c, 0x2816_0cc0)?; // rfe_type != 1
                self.write32(0xcb8, 0x0030_0000)?;
                self.write32(0xcb8, 0x0010_0000)?;
                sleep(Duration::from_millis(5));
                self.write32(0xc8c, 0x3c00_0000)?;
                self.write32(0xcb8, 0x0)?;
            }
            if tx1_fin {
                self.page(false)?;
                self.bb_set(0x978, 0x03ff_8000, (tx_iqc[2] & 0x7ff) as u32)?;
                self.bb_set(0x978, 0x0000_07ff, (tx_iqc[3] & 0x7ff) as u32)?;
                self.page(true)?;
                self.write32(0xe8c, 0x2816_0ca0)?; // rfe_type != 1
                self.write32(0xeb8, 0x0030_0000)?;
                self.write32(0xeb8, 0x0010_0000)?;
                sleep(Duration::from_millis(5));
                self.write32(0xe8c, 0x3c00_0000)?;
                self.write32(0xeb8, 0x0)?;
            }

            let mut delay = 0;
            let (mut r0, mut r1) = (false, false);
            loop {
                if !rx0_fin && tx0_fin {
                    r0 = self.bb_query(0xd00, 1 << 10)? != 0;
                }
                if !rx1_fin && tx1_fin {
                    r1 = self.bb_query(0xd40, 1 << 10)? != 0;
                }
                if (r0 && r1) || delay > 20 {
                    break;
                }
                sleep(Duration::from_millis(1));
                delay += 1;
            }
            if delay < 20 {
                let rx0_fail = self.bb_query(0xd00, 1 << 11)? != 0;
                let rx1_fail = self.bb_query(0xd40, 1 << 11)? != 0;
                if !(rx0_fail || rx0_fin) && tx0_fin {
                    self.write32(0xcb8, 0x0600_0000)?;
                    rx_temp[rx0_avg][0] = self.iqk_result11(0xd00)?;
                    self.write32(0xcb8, 0x0800_0000)?;
                    rx_temp[rx0_avg][1] = self.iqk_result11(0xd00)?;
                    rx0_avg += 1;
                } else {
                    cal0 += 1;
                    if cal0 == 10 {
                        break;
                    }
                }
                if !(rx1_fail || rx1_fin) && tx1_fin {
                    self.write32(0xeb8, 0x0600_0000)?;
                    rx_temp[rx1_avg][2] = self.iqk_result11(0xd40)?;
                    self.write32(0xeb8, 0x0800_0000)?;
                    rx_temp[rx1_avg][3] = self.iqk_result11(0xd40)?;
                    rx1_avg += 1;
                } else {
                    cal1 += 1;
                    if cal1 == 10 {
                        break;
                    }
                }
            } else {
                cal0 += 1;
                cal1 += 1;
                if cal0 == 10 {
                    break;
                }
            }
            if rx0_avg >= 2 {
                'a: for i in 0..rx0_avg {
                    for ii in (i + 1)..rx0_avg {
                        let dx = rx_temp[i][0] - rx_temp[ii][0];
                        let dy = rx_temp[i][1] - rx_temp[ii][1];
                        if dx > -4 && dx < 4 && dy > -4 && dy < 4 {
                            rx_iqc[0] = (rx_temp[i][0] + rx_temp[ii][0]) / 2;
                            rx_iqc[1] = (rx_temp[i][1] + rx_temp[ii][1]) / 2;
                            rx0_fin = true;
                            break 'a;
                        }
                    }
                }
            }
            if rx1_avg >= 2 {
                'b: for i in 0..rx1_avg {
                    for ii in (i + 1)..rx1_avg {
                        let dx = rx_temp[i][2] - rx_temp[ii][2];
                        let dy = rx_temp[i][3] - rx_temp[ii][3];
                        if dx > -4 && dx < 4 && dy > -4 && dy < 4 {
                            rx_iqc[2] = (rx_temp[i][2] + rx_temp[ii][2]) / 2;
                            rx_iqc[3] = (rx_temp[i][3] + rx_temp[ii][3]) / 2;
                            rx1_fin = true;
                            break 'b;
                        }
                    }
                }
            }
            if (rx0_fin || !tx0_fin) && (rx1_fin || !tx1_fin) {
                break;
            }
            if (cal0 as usize + rx0_avg) >= 10
                || (cal1 as usize + rx1_avg) >= 10
                || rx0_avg == 3
                || rx1_avg == 3
            {
                break;
            }
        }

        // ── fill the correction matrices (default = identity-ish 0x200/0x0) ──
        self.iqk_tx_fill_iqc(RfPath::A, if tx0_fin { tx_iqc[0] } else { 0x200 }, if tx0_fin { tx_iqc[1] } else { 0x0 })?;
        self.iqk_rx_fill_iqc(RfPath::A, if rx0_fin { rx_iqc[0] as u32 } else { 0x200 }, if rx0_fin { rx_iqc[1] as u32 } else { 0x0 })?;
        self.iqk_tx_fill_iqc(RfPath::B, if tx1_fin { tx_iqc[2] } else { 0x200 }, if tx1_fin { tx_iqc[3] } else { 0x0 })?;
        self.iqk_rx_fill_iqc(RfPath::B, if rx1_fin { rx_iqc[2] as u32 } else { 0x200 }, if rx1_fin { rx_iqc[3] as u32 } else { 0x0 })?;
        Ok(IqkResult {
            tx_a: tx0_fin,
            rx_a: rx0_fin,
            tx_b: tx1_fin,
            rx_b: rx1_fin,
            tx_a_xy: (tx_iqc[0], tx_iqc[1]),
            rx_a_xy: (rx_iqc[0], rx_iqc[1]),
        })
    }

    /// IQ calibration (`_phy_iq_calibrate_8812a`): back up the MAC/BB, AFE and RF
    /// registers it perturbs, run the dual-path TX/RX IQK, then restore. Run
    /// after [`set_channel`](Self::set_channel) (and typically before
    /// [`lc_calibrate`](Self::lc_calibrate)). Corrects TX/RX IQ imbalance —
    /// improves EVM and image rejection.
    pub fn iq_calibrate(&self) -> Result<IqkResult, FaceError> {
        const MACBB: [u16; 9] = [0x520, 0x550, 0x808, 0xa04, 0x90c, 0xc00, 0xe00, 0x838, 0x82c];
        const AFE: [u16; 12] =
            [0xc5c, 0xc60, 0xc64, 0xc68, 0xcb0, 0xcb4, 0xe5c, 0xe60, 0xe64, 0xe68, 0xeb0, 0xeb4];
        const RFREG: [u32; 3] = [0x65, 0x8f, 0x0];

        // back up MAC/BB (page C), the C1 one-shot regs, AFE (page C), RF A/B
        self.page(false)?;
        let mut macbb_bk = [0u32; 9];
        for (i, &r) in MACBB.iter().enumerate() {
            macbb_bk[i] = self.read32(r)?;
        }
        self.page(true)?;
        let reg_c1b8 = self.read32(0xcb8)?;
        let reg_e1b8 = self.read32(0xeb8)?;
        self.page(false)?;
        let mut afe_bk = [0u32; 12];
        for (i, &r) in AFE.iter().enumerate() {
            afe_bk[i] = self.read32(r)?;
        }
        let mut rfa_bk = [0u32; 3];
        let mut rfb_bk = [0u32; 3];
        for (i, &r) in RFREG.iter().enumerate() {
            rfa_bk[i] = self.rf_read(RfPath::A, r)?;
            rfb_bk[i] = self.rf_read(RfPath::B, r)?;
        }

        self.iqk_configure_mac()?;
        let result = self.iqk_tx()?;

        // restore RF (both paths), AFE, the C1 one-shot regs, and MAC/BB
        self.page(false)?;
        for (i, &r) in RFREG.iter().enumerate() {
            self.rf_write(RfPath::A, r, rfa_bk[i])?;
        }
        self.rf_write(RfPath::A, 0xef, 0x0)?;
        for (i, &r) in RFREG.iter().enumerate() {
            self.rf_write(RfPath::B, r, rfb_bk[i])?;
        }
        self.rf_write(RfPath::B, 0xef, 0x0)?;

        self.iqk_restore_afe(&afe_bk, &AFE)?;
        self.page(true)?;
        self.write32(0xcb8, reg_c1b8)?;
        self.write32(0xeb8, reg_e1b8)?;
        self.page(false)?;
        for (i, &r) in MACBB.iter().enumerate() {
            self.write32(r, macbb_bk[i])?;
        }
        Ok(result)
    }

    /// Configure both RF paths (`PHY_RFConfig8812` → RF6052): apply the radio-A
    /// and radio-B register tables via the BB LSSI. Run after
    /// [`bb_config`](Self::bb_config) (which powers on the RF analog).
    pub fn rf_config(&self) -> Result<(), FaceError> {
        self.config_table(RADIO_A, |s, addr, data| s.rf_write_entry(RfPath::A, addr, data))?;
        self.config_table(RADIO_B, |s, addr, data| s.rf_write_entry(RfPath::B, addr, data))?;
        Ok(())
    }

    /// Read an RF register via the BB serial interface (`phy_RFSerialRead`,
    /// jaguar): select PI/SI mode, latch the offset into the HSSI-read register,
    /// then read back the 20-bit value. Verifies the RF serial link round-trips.
    pub fn rf_read(&self, path: RfPath, offset: u32) -> Result<u32, FaceError> {
        // (PI-read reg, SI-read reg, PI-mode bit register).
        let (read_pi, read_si, mode_reg) = match path {
            RfPath::A => (0x0D04u16, 0x0D08u16, 0x0C00u16),
            RfPath::B => (0x0D44, 0x0D48, 0x0E00),
        };
        let offset = offset & 0xff;
        let pi_mode = self.bb_query(mode_reg, 0x4)? != 0;
        // Latch the read address into rHSSIRead_Jaguar (0x8B0), addr field 0xff.
        self.bb_set(0x08B0, 0xff, offset)?;
        let reg = if pi_mode { read_pi } else { read_si };
        // rRead_data_Jaguar = 20-bit data mask.
        self.bb_query(reg, 0x000F_FFFF)
    }

    /// Enable the MAC DMA / WMAC / scheduler / security blocks in `REG_CR`
    /// (`0x063F`). Run **right after** [`power_on`](Self::power_on), before LLT /
    /// firmware / MAC-table — the DMA engines must be on for those to take.
    pub fn mac_enable_dma(&self) -> Result<(), FaceError> {
        self.write16(REG_CR, 0)?;
        let cr = self.read16(REG_CR)?;
        self.write16(REG_CR, cr | CR_DMA_ENABLE)
    }

    /// Finish MAC init after the MAC register table: reserved-page split,
    /// TX/RX FIFO boundaries, the 3-endpoint queue→priority map, transfer page
    /// size, driver-info size, network type, the **monitor** receive config, and
    /// finally `REG_CR |= MACTXEN | MACRXEN`. After this the MAC is transmitting
    /// and receiving. Read `REG_CR` back to confirm the enable bits.
    pub fn mac_init_queues(&self) -> Result<(), FaceError> {
        // Reserved pages (RQPN): NPQ first, then the HPQ/LPQ/PUBQ load word.
        self.write8(REG_RQPN_NPQ, 0x00)?;
        self.write32(REG_RQPN, RQPN_3EP)?;

        // TX packet-buffer boundary across the queue/beacon/loopback registers.
        let bndy = TX_PAGE_BOUNDARY;
        self.write8(REG_BCNQ_BDNY, bndy)?;
        self.write8(REG_MGQ_BDNY, bndy)?;
        self.write8(REG_WMAC_LBK_BF_HD, bndy)?;
        self.write8(REG_TRXFF_BNDY, bndy)?;
        self.write8(REG_TDECTRL + 1, bndy)?;

        // RX-FIFO boundary.
        self.write16(REG_TRXFF_BNDY + 2, RX_DMA_BOUNDARY)?;

        // Map the AC queues to the 3 OUT endpoints (preserve the low 3 bits).
        let pri = (self.read16(REG_TRXDMA_CTRL)? & 0x7) | TRXDMA_MAP_3EP;
        self.write16(REG_TRXDMA_CTRL, pri)?;

        // Transfer page size + RX driver-info size.
        self.write8(REG_PBP, PBP_TX_512)?;
        self.write8(REG_RX_DRVINFO_SZ, 4)?; // DRVINFO_SZ (unit 8 B)

        // Network type (MSR) = AP, preserving the rest of REG_CR.
        let cr = self.read32(REG_CR)?;
        self.write32(REG_CR, (cr & !MASK_NETTYPE) | NETTYPE_AP)?;

        // Monitor receive config + accept-all multicast.
        self.write32(REG_RCR, MONITOR_RCR)?;
        self.write32(REG_MAR, 0xFFFF_FFFF)?;
        self.write32(REG_MAR + 4, 0xFFFF_FFFF)?;

        // Enable MAC TX/RX.
        let cr = self.read8(REG_CR)?;
        self.write8(REG_CR, cr | MACTXEN | MACRXEN)?;
        Ok(())
    }

    /// The current `REG_CR` value — read back after [`mac_init_queues`] to
    /// confirm the MAC TX/RX enable bits are set.
    pub fn read_cr(&self) -> Result<u16, FaceError> {
        self.read16(REG_CR)
    }

    /// `_8051Reset8812`: reset the MCU IO wrapper, pulse the 8051 enable
    /// (`REG_SYS_FUNC_EN+1[2]`), then re-enable the wrapper.
    fn reset_8051(&self) -> Result<(), FaceError> {
        // Reset MCU IO wrapper.
        let t = self.read8(REG_RSV_CTRL)?;
        self.write8(REG_RSV_CTRL, t & !0x02)?;
        let t = self.read8(REG_RSV_CTRL + 1)?;
        self.write8(REG_RSV_CTRL + 1, t & !0x08)?;
        // Pulse the 8051.
        let t = self.read8(REG_SYS_FUNC_EN + 1)?;
        self.write8(REG_SYS_FUNC_EN + 1, t & !0x04)?;
        // Re-enable MCU IO wrapper.
        let t = self.read8(REG_RSV_CTRL)?;
        self.write8(REG_RSV_CTRL, t & !0x02)?;
        let t = self.read8(REG_RSV_CTRL + 1)?;
        self.write8(REG_RSV_CTRL + 1, t | 0x08)?;
        let t = self.read8(REG_SYS_FUNC_EN + 1)?;
        self.write8(REG_SYS_FUNC_EN + 1, t | 0x04)?;
        Ok(())
    }

    // ── Milestone 8: frame injection / capture ───────────────────────────────

    /// Set a `len`-bit field at bit `shift` within the little-endian 32-bit word
    /// at byte `off` of a descriptor (the `SET_BITS_TO_LE_4BYTE` macro).
    fn set_desc_bits(desc: &mut [u8], off: usize, shift: u32, len: u32, val: u32) {
        let mask = if len >= 32 { u32::MAX } else { ((1u32 << len) - 1) << shift };
        let mut w = u32::from_le_bytes(desc[off..off + 4].try_into().unwrap());
        w = (w & !mask) | ((val << shift) & mask);
        desc[off..off + 4].copy_from_slice(&w.to_le_bytes());
    }

    /// Build the 40-byte 8812A TX descriptor for a `frame_len`-byte 802.11 frame
    /// at hardware rate `hw_rate` (`rtl8812a_fill_fake_txdesc` field set, with a
    /// forced legacy rate). The USB path drops frames whose descriptor checksum
    /// is wrong, so it is computed last over the first 32 bytes.
    fn build_txdesc(frame_len: usize, hw_rate: u32) -> [u8; TXDESC_SIZE] {
        let mut d = [0u8; TXDESC_SIZE];
        Self::set_desc_bits(&mut d, 0, 0, 16, frame_len as u32); // PKT_SIZE
        Self::set_desc_bits(&mut d, 0, 16, 8, TXDESC_SIZE as u32); // OFFSET
        Self::set_desc_bits(&mut d, 0, 26, 1, 1); // LAST_SEG
        Self::set_desc_bits(&mut d, 0, 27, 1, 1); // FIRST_SEG
        Self::set_desc_bits(&mut d, 0, 31, 1, 1); // OWN
        Self::set_desc_bits(&mut d, 4, 8, 5, QSLT_MGNT); // QUEUE_SEL
        Self::set_desc_bits(&mut d, 4, 16, 5, RATEID_IDX_G); // RATE_ID
        Self::set_desc_bits(&mut d, 12, 8, 1, 1); // USE_RATE (forced rate)
        Self::set_desc_bits(&mut d, 16, 0, 7, hw_rate); // TX_RATE
        Self::set_desc_bits(&mut d, 32, 15, 1, 1); // HWSEQ_EN (HW sequence #)
        let mut csum: u16 = 0;
        for i in 0..16 {
            csum ^= u16::from_le_bytes([d[i * 2], d[i * 2 + 1]]);
        }
        Self::set_desc_bits(&mut d, 28, 0, 16, csum as u32); // TX_DESC_CHECKSUM
        d
    }

    /// Frame an 802.11 `frame` for bulk-OUT: descriptor ++ frame, padded off the
    /// USB 512-byte boundary (Realtek drops a bulk-out of exactly N×512 bytes).
    fn tx_buffer(frame: &[u8], hw_rate: u32) -> Vec<u8> {
        let desc = Self::build_txdesc(frame.len(), hw_rate);
        let mut buf = Vec::with_capacity(TXDESC_SIZE + frame.len() + 8);
        buf.extend_from_slice(&desc);
        buf.extend_from_slice(frame);
        if buf.len() % 512 == 0 {
            buf.extend_from_slice(&[0u8; 8]);
        }
        buf
    }

    /// Inject a complete 802.11 `frame` (management header onward) at `hw_rate`
    /// — synchronous bulk-OUT to the MGNT-queue endpoint. Fire-and-forget.
    pub fn send_frame(&self, frame: &[u8], hw_rate: u32) -> Result<(), FaceError> {
        let buf = Self::tx_buffer(frame, hw_rate);
        self.handle
            .write_bulk(self.bulk_out, &buf, TX_TIMEOUT)
            .map_err(usb_err)?;
        Ok(())
    }

    /// Set a uniform TX power index (`idx`, 0–63) for every legacy and HT rate on
    /// both RF paths — the 8812A per-rate "power-by-rate" registers
    /// (`PHY_SetTxPowerIndex_8812A`). A pragmatic stand-in for the full EFUSE
    /// `PHY_SetTxPowerLevel8812` table (which we don't parse): without it these
    /// registers stay at reset and the PA emits nothing. Run after
    /// [`set_channel`](Self::set_channel) / calibration.
    pub fn set_tx_power(&self, idx: u8) -> Result<(), FaceError> {
        let w = u32::from_le_bytes([idx, idx, idx, idx]);
        // CCK, OFDM18-6, OFDM54-24, MCS3-0, MCS7-4 — paths A (0xC2x) and B (0xE2x).
        for reg in [
            0xc20u16, 0xc24, 0xc28, 0xc2c, 0xc30, 0xe20, 0xe24, 0xe28, 0xe2c, 0xe30,
        ] {
            self.write32(reg, w)?;
        }
        Ok(())
    }

    /// Release (resume) RX DMA by clearing `RW_RELEASE_EN` (`REG_RXPKT_NUM[18]`).
    /// After init the 8812AU leaves RX DMA paused (`RW_RELEASE_EN` set,
    /// `RXDMA_IDLE`), so no captured frame reaches the bulk-IN endpoint until it
    /// is released. **Call this as the final bring-up step** — IQ calibration
    /// re-pauses RX DMA, so releasing earlier has no lasting effect.
    pub fn start_rx_dma(&self) -> Result<(), FaceError> {
        // Minimise RX-DMA aggregation latency. The reset value
        // `REG_RXDMA_AGG_PG_TH = 0x2003` (timeout 0x20 ≈ 32 ms, 3-page threshold)
        // lets captured frames sit in the dongle's RX FIFO for tens of ms before
        // USB delivery — which lags our software TSF (jammed off a received
        // beacon) by the same amount, so NAN Discovery-Window-timed transmits
        // land *after* a peer's RX window closes. 1 page / ~1 ms flushes promptly.
        self.write16(0x0280, 0x0101)?;
        let v = self.read32(0x0284)?; // REG_RXPKT_NUM
        self.write32(0x0284, v & !(1 << 18))?;
        Ok(())
    }

    /// One raw bulk-IN read (diagnostic): returns the byte count without parsing
    /// (0 on timeout). Use to confirm RX DMA is delivering to the IN endpoint.
    pub fn rx_raw(&self, buf: &mut [u8]) -> Result<usize, FaceError> {
        match self.handle.read_bulk(self.bulk_in, buf, RX_TIMEOUT) {
            Ok(n) => Ok(n),
            Err(rusb::Error::Timeout) => Ok(0),
            Err(e) => Err(usb_err(e)),
        }
    }

    /// Inject on an explicit bulk-OUT endpoint address (diagnostic: the 8812AU
    /// has three OUT endpoints `0x02/0x03/0x04` mapped to TX priority queues).
    pub fn send_frame_ep(&self, ep: u8, frame: &[u8], hw_rate: u32) -> Result<(), FaceError> {
        let buf = Self::tx_buffer(frame, hw_rate);
        self.handle.write_bulk(ep, &buf, TX_TIMEOUT).map_err(usb_err)?;
        Ok(())
    }

    /// De-aggregate a bulk-IN buffer (`n` valid bytes) into whole 802.11 frames,
    /// queued on `rx_pending`. The 8812A stacks `RXDESC ++ drvinfo ++ shift ++
    /// frame` per packet, each 8-byte aligned (`recvbuf2recvframe`); CRC-error
    /// and firmware-report (C2H) packets are dropped.
    fn parse_rx_buffer(&self, buf: &[u8], n: usize) {
        let mut off = 0;
        let mut q = self.rx_pending.lock().unwrap();
        while off + RXDESC_SIZE <= n {
            let d = &buf[off..];
            let w0 = u32::from_le_bytes([d[0], d[1], d[2], d[3]]);
            let pkt_len = (w0 & 0x3FFF) as usize;
            let crc_err = (w0 >> 14) & 0x1 != 0;
            let drvinfo = ((w0 >> 16) & 0xF) as usize;
            let shift = ((w0 >> 24) & 0x3) as usize;
            let w2 = u32::from_le_bytes([d[8], d[9], d[10], d[11]]);
            let rpt_sel = (w2 >> 28) & 0x1 != 0; // firmware C2H report, not 802.11
            if pkt_len == 0 {
                break;
            }
            let start = RXDESC_SIZE + drvinfo * 8 + shift;
            let end = start + pkt_len;
            if end > n - off {
                break;
            }
            if !crc_err && !rpt_sel && pkt_len >= DOT11_HDR_LEN {
                let body = &d[start..end];
                let mut ta = [0u8; 6];
                ta.copy_from_slice(&body[10..16]);
                let mut group = [0u8; 6];
                group.copy_from_slice(&body[4..10]);
                q.push_back(CapturedFrame {
                    payload: Bytes::copy_from_slice(body),
                    addr: Some(ta),
                    group: Some(group),
                    rssi_dbm: None,
                    mcs_index: None,
                });
            }
            off += (start + pkt_len + 7) & !7; // next subframe, 8-byte aligned
        }
    }

    /// Synchronously poll for one captured 802.11 frame: drain the de-aggregation
    /// queue, else do one bulk-IN read (returns `None` on timeout / no frame).
    pub fn poll_frame(&self) -> Result<Option<CapturedFrame>, FaceError> {
        if let Some(f) = self.rx_pending.lock().unwrap().pop_front() {
            return Ok(Some(f));
        }
        let mut buf = vec![0u8; 16384];
        match self.handle.read_bulk(self.bulk_in, &mut buf, RX_TIMEOUT) {
            Ok(n) => self.parse_rx_buffer(&buf, n),
            Err(rusb::Error::Timeout) => return Ok(None),
            Err(e) => return Err(usb_err(e)),
        }
        Ok(self.rx_pending.lock().unwrap().pop_front())
    }
}

/// Async monitor radio: NAN injects management frames (`Raw80211` — the payload
/// is a complete 802.11 frame) and captures whatever is on the channel. Blocking
/// USB I/O runs on the blocking pool so the async reactor is never stalled.
#[async_trait]
impl FrameIo for Rtl8812auBackend {
    async fn inject(&self, frame: InjectFrame) -> Result<(), FaceError> {
        // `payload` is the whole 802.11 frame; inject verbatim at legacy 6 Mbps
        // OFDM (what real NAN devices emit). The HT/VHT `mcs` does not apply to a
        // legacy management frame, so it is intentionally ignored here.
        let handle = self.handle.clone();
        let ep = self.bulk_out;
        let buf = Self::tx_buffer(&frame.payload, DESC_RATE_6M);
        tokio::task::spawn_blocking(move || {
            handle
                .write_bulk(ep, &buf, TX_TIMEOUT)
                .map(|_| ())
                .map_err(usb_err)
        })
        .await
        .map_err(|e| init_err(format!("inject join: {e}")))?
    }

    async fn recv_frame(&self) -> Result<CapturedFrame, FaceError> {
        loop {
            if let Some(f) = self.rx_pending.lock().unwrap().pop_front() {
                return Ok(f);
            }
            let handle = self.handle.clone();
            let ep = self.bulk_in;
            let (buf, n) = tokio::task::spawn_blocking(move || {
                let mut buf = vec![0u8; 16384];
                match handle.read_bulk(ep, &mut buf, RX_TIMEOUT) {
                    Ok(n) => Ok((buf, n)),
                    Err(rusb::Error::Timeout) => Ok((buf, 0)),
                    Err(e) => Err(usb_err(e)),
                }
            })
            .await
            .map_err(|e| init_err(format!("recv join: {e}")))??;
            if n > 0 {
                self.parse_rx_buffer(&buf, n);
            }
        }
    }
}

#[async_trait]
impl crate::WifiRadio for Rtl8812auBackend {
    async fn inject_at(
        &self,
        frame: InjectFrame,
        _mcs: crate::McsDescriptor,
    ) -> Result<(), FaceError> {
        // Whole-frame legacy 6 Mbps injection (NAN management frames); the exact
        // HT/VHT rate does not apply, so it is ignored — same as `inject`.
        self.inject(frame).await
    }
}
