//! **Userspace RTL8812EU backend** — a [`FrameIo`] over the Realtek 8812EU
//! dongle driven directly from userspace via libusb, so the named-radio bearer
//! runs on hosts without an `AF_PACKET` monitor interface (macOS, and Linux
//! without the out-of-tree `rtl88x2eu` driver).
//!
//! **Status: bring-up complete through the PHY + TX/RX descriptors; on-air
//! radiation pending RF calibration.** Hardware-verified against the golden
//! kernel-driver state: power-on, the physical-EFUSE/MAC read, firmware
//! download (fw alive, `REG_MCUFW_CTRL = 0xC078`), MAC init (449/512 registers
//! match), and BB/RF init (`RF 0x18 = 0x531a1`, channel 161, 509/512 BB
//! registers match). [`inject`](FrameIo::inject) builds the 48-byte TX
//! descriptor + 802.11 frame and the chip accepts it on bulk-OUT;
//! [`recv_frame`](FrameIo::recv_frame) parses the 24-byte RX descriptor.
//!
//! **On-air TX works.** The long-hunted gate was the BB transmit datapath:
//! [`bb_tx_datapath_init`](Self::bb_tx_datapath_init) configures the
//! `0x1800-0x1fff` BB pages (TXAGC / TX-RX filter / OFDM-CCK datapath / DIG)
//! that our static phy_reg/agc tables and abbreviated init never set. Without
//! it the MAC accepts and queues frames but the BB never modulates them; with
//! it a peer RTL8812EU in monitor mode decodes every injected frame (verified
//! end-to-end at MCS1/20 MHz, ethertype 0x8624). Calibration was a red herring:
//! single-tone ([`single_tone`](Self::single_tone)) always radiated, and
//! skipping IQK/DPK still transmits — the datapath init is the gate. The 65
//! register values were captured from the working kernel driver via usbmon and
//! reduced from ~2000 calibration-churn writes (see
//! `golden/opi-usbmon-2026-06-13/`). TODO: a per-device calibration pass (the
//! captured TXAGC/cal values are the reference unit's; they radiate fine on
//! others but are not optimal).
//!
//! NOTE: `0x2DE0` is NOT a TX-OK counter (it stays 0 even on the working driver
//! mid-transmit) — don't use it to judge TX. Use a peer receiver in monitor
//! mode, which hears far below an SDR's noise floor.
//!
//! Gated behind the `libusb-backend` feature (pulls `rusb`/libusb-1.0).
//!
//! ## Chip note — `0bda:a81a` is an RTL8812EU, which halmac drives as **8822E**
//!
//! The reference driver (`svpcom/rtl8812eu`, the same `rtl88x2eu` module the
//! Orange Pi testbed runs) binds `0bda:a81a` to `RTL8822E`: the chip-specific
//! code lives in `hal/rtl8822e/` + `hal/halmac/halmac_88xx/halmac_8822e/`, and
//! the silicon self-identifies as `CHIP_ID_HW_DEF_8822E = 0x17` in
//! `REG_SYS_CFG2` (confirmed against the golden register dump from the working
//! kernel driver — see `golden/opi0-2026-06-12/`). Everything here is ported
//! from that driver's halmac, *not* from the older 8812AU stack (devourer),
//! whose power/EFUSE/BB sequences do not work on this silicon.

use std::io;
use std::time::Duration;

use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};

use async_trait::async_trait;
use bytes::Bytes;
use rusb::{Context, Device, DeviceHandle, Direction, TransferType, UsbContext};

use ndn_transport::FaceError;

use crate::McsDescriptor;
use crate::frame::LLC_SNAP_PREFIX;
use crate::{CapturedFrame, FrameFormat, InjectFrame, FrameIo};

/// Realtek USB vendor request: `bRequest` for register I/O, and the IN/OUT
/// `bmRequestType`s (vendor, device). The register address rides in `wValue`,
/// `wIndex = 0`; the data is little-endian. Same across the Realtek USB WLAN
/// family — this is the "usbctrl_vendorreq" path of the rtl88x2eu driver.
const VENDOR_REQ: u8 = 0x05;
const REQ_READ: u8 = 0xc0; // device-to-host | vendor | device
const REQ_WRITE: u8 = 0x40; // host-to-device | vendor | device
const CTRL_TIMEOUT: Duration = Duration::from_millis(500);

// ── Register map (halmac_reg2.h names/addresses) ────────────────────────────

const REG_SYS_ISO_CTRL: u16 = 0x0000;
const REG_SYS_FUNC_EN: u16 = 0x0002;
const REG_RSV_CTRL: u16 = 0x001c;
const REG_RF_CTRL: u16 = 0x001f;
const REG_EFUSE_CTRL: u16 = 0x0030;
const REG_GPIO_MUXCFG: u16 = 0x0040;
const REG_LED_CFG: u16 = 0x004c;
const REG_PAD_CTRL1: u16 = 0x0064;
const REG_MCUFW_CTRL: u16 = 0x0080;
const REG_EFUSE_CTRL_1: u16 = 0x00a4;
const REG_PMC_DBG_CTRL2: u16 = 0x00cc;
const REG_WLRF1: u16 = 0x00ec;
const REG_TXDMA_PQ_MAP: u16 = 0x010c;
const REG_FIFOPAGE_CTRL_2: u16 = 0x0204;
const REG_TXDMA_STATUS: u16 = 0x0210;
const REG_RQPN_CTRL_2: u16 = 0x022c;
const REG_FIFOPAGE_INFO_1: u16 = 0x0230;
const REG_FWHW_TXQ_CTRL: u16 = 0x0420;
const REG_BCN_CTRL: u16 = 0x0550;
const REG_RCR: u16 = 0x0608;
const REG_FW_DBG7: u16 = 0x10fc;
const REG_DDMA_CH0SA: u16 = 0x1200;
const REG_DDMA_CH0DA: u16 = 0x1204;
const REG_DDMA_CH0CTRL: u16 = 0x1208;
const REG_H2CQ_CSR: u16 = 0x1330;
const REG_LTECOEX_ACCESS_CTRL: u16 = 0x1700; // REG_WL2LTECOEX_INDIRECT_ACCESS_CTRL_V1
/// `REG_SYS_CFG1` — silicon config; byte 1 bits[7:4] = chip cut/version.
pub const REG_SYS_CFG: u16 = 0x00f0;
const REG_SYS_STATUS1: u16 = 0x00f4;
/// `REG_SYS_CFG2` — byte 0 is the hardware chip id (`0x17` = 8822E).
const REG_SYS_CFG2: u16 = 0x00fc;
const REG_CR: u16 = 0x0100;
const REG_MACID: u16 = 0x0610;
const REG_ANAPAR_MAC_0: u16 = 0x1018;
const REG_CPU_DMEM_CON: u16 = 0x1080;
const REG_CR_EXT: u16 = 0x1100;

/// `CHIP_ID_HW_DEF_8822E` — what `REG_SYS_CFG2[7:0]` reads on this silicon.
pub const CHIP_ID_8822E: u8 = 0x17;

/// RX-path init — see [`LibUsbRtl88xxBackend::rx_path_init`]. `(addr, value)` in
/// the working driver's first-touch order. Covers the path-B BB datapath
/// (`0x4000-0x41ff`, the path-A `0x1800` page's mirror) and the RF-over-BB
/// windows (path A `0x3c00 + reg<<2`, path B `0x4c00 + …`: LNA / RX gain / mixer).
/// The static radio tables leave the receive path unconfigured — without this
/// the chip demodulates nothing and delivers no frames on bulk-IN. The RF
/// channel registers (`0x3c60`/`0x4c60`, RF `0x18`) are re-tuned immediately by
/// `set_channel_bw20`, so their captured channel value does not stick.
const RX_PATH_INIT: &[(u16, u32)] = &[
    (0x410c, 0x97f00063),
    (0x4100, 0x00033312),
    (0x4140, 0x00200000),
    (0x4144, 0x00000030),
    (0x4130, 0x70fb0001),
    (0x4160, 0xf0041ff8),
    (0x4110, 0x62150684),
    (0x4168, 0x000ff006),
    (0x4118, 0x020194ff),
    (0x3e48, 0x0008b680),
    (0x3e4c, 0x0007377f),
    (0x4108, 0x0003351f),
    (0x4e48, 0x00062580),
    (0x4e4c, 0x0006b87f),
    (0x3d0c, 0x00015000),
    (0x4d0c, 0x00045000),
    (0x3fb8, 0x00000000),
    (0x3ccc, 0x0000000e),
    (0x3cfc, 0x00000002),
    (0x4fb8, 0x00000000),
    (0x4ccc, 0x0000000e),
    (0x4cfc, 0x00000004),
    (0x3d80, 0x00050000),
    (0x4d80, 0x00033000),
    (0x3c60, 0x000531a1),
    (0x3c68, 0x00040c00),
    (0x4c60, 0x000531a1),
    (0x4c68, 0x00000c00),
    (0x3f7c, 0x00000400),
    (0x41ac, 0x00008230),
    (0x4044, 0x00070bcb),
    (0x4040, 0xc1000000),
    (0x41a0, 0x00330000),
    (0x41e8, 0x00011200),
];

/// BB transmit-datapath init registers — see [`LibUsbRtl88xxBackend::bb_tx_datapath_init`].
/// `(addr, value)` in the working driver's first-touch order; BB pages
/// `0x1800-0x1fff` (TXAGC / TX-RX filter / OFDM-CCK datapath / DIG).
const BB_TX_DATAPATH_INIT: &[(u16, u32)] = &[
    (0x1d3c, 0xf8000000),
    (0x180c, 0x97f00063),
    (0x1c3c, 0x01051f43),
    (0x1cd0, 0x7f000000),
    (0x1e24, 0x80023000),
    (0x1a04, 0x81000008),
    (0x1a2c, 0x12ba8000),
    (0x1d30, 0x50209d00),
    (0x1e2c, 0xe4e40400),
    (0x1840, 0x00002000),
    (0x1844, 0x00003000),
    (0x1d70, 0x20202020),
    (0x1830, 0x70fb0001),
    (0x1860, 0xf0041ff8),
    (0x1810, 0x62150684),
    (0x1868, 0x00002801),
    (0x1818, 0x020184ff),
    (0x1e70, 0x00001000),
    (0x1808, 0x0003351f),
    (0x1b00, 0x0000000a),
    (0x1b9c, 0x00000088),
    (0x1b98, 0x000a4034),
    (0x1e80, 0x55005500),
    (0x1ac8, 0x00001107),
    (0x1ad0, 0xa33529f0),
    (0x1e60, 0x786e412f),
    (0x1e44, 0x36302a24),
    (0x1e48, 0x5a50463c),
    (0x1e5c, 0xc56400ff),
    (0x1e40, 0x57e457e4),
    (0x1e50, 0x2c282420),
    (0x1e54, 0x3c383430),
    (0x1e58, 0xfe484440),
    (0x1ee4, 0xf0000000),
    (0x1ed4, 0x800c0040),
    (0x1ed8, 0x8005000c),
    (0x1edc, 0x80020005),
    (0x1ee0, 0x80000002),
    (0x1e84, 0x00000000),
    (0x18ac, 0x00008230),
    (0x1a20, 0x52840000),
    (0x1a24, 0x3e18fec8),
    (0x1a28, 0x00150a88),
    (0x1a98, 0xacc4c040),
    (0x1a9c, 0x0006c8b2),
    (0x1aa0, 0x00faf0de),
    (0x1aac, 0x00122344),
    (0x1ab0, 0x0fffffff),
    (0x1a14, 0x111443a8),
    (0x1a80, 0x208e7532),
    (0x1c80, 0x2238e000),
    (0x1944, 0x00070bcb),
    (0x1940, 0xc1000000),
    (0x1ee8, 0x00000000),
    (0x1d94, 0x4038000a),
    (0x1abc, 0x82008080),
    (0x1ae8, 0xc2100002),
    (0x1aec, 0x000000f6),
    (0x1c90, 0x00e41708),
    (0x18a0, 0x00330000),
    (0x18e8, 0x00811800),
    (0x1eec, 0x0280a933),
    (0x1ef0, 0x30000a80),
    (0x1ef4, 0x40001266),
    (0x1ef8, 0x3b000100),
];

/// Realtek's USB vendor id.
pub const REALTEK_VID: u16 = 0x0bda;
/// Known product ids. `0xa81a` is the RTL8812EU dongle on the testbed; the
/// rest are 8812-family siblings kept for enumeration convenience.
pub const RTL88XX_PIDS: &[u16] = &[0x8812, 0x881a, 0x881c, 0xa811, 0xa81a, 0x8814];

fn usb_err(e: rusb::Error) -> FaceError {
    FaceError::Io(io::Error::other(format!("rtl88xx usb: {e}")))
}

fn init_err(what: String) -> FaceError {
    FaceError::Io(io::Error::other(what))
}

/// A userspace RTL8812EU radio. Open with [`open`](Self::open); the handle
/// keeps the interface claimed for the backend's lifetime.
pub struct LibUsbRtl88xxBackend {
    /// `Arc` so blocking USB transfers can be moved onto `spawn_blocking`.
    handle: Arc<DeviceHandle<Context>>,
    /// Bulk OUT endpoint address (frame injection) — the HIGH/MGT queue.
    bulk_out: u8,
    /// Bulk IN endpoint address (frame capture).
    bulk_in: u8,
    /// On-air frame format (defaults to [`FrameFormat::RawNdn`]).
    format: FrameFormat,
    /// Monotonic 802.11 sequence counter (12-bit field).
    seq: AtomicU16,
    /// TX-descriptor queue selector (default MGT 0x12; diagnostic override).
    tx_qsel: std::sync::atomic::AtomicU8,
    /// Monotonic H2C sequence number. The firmware echoes it in the C2H ack and
    /// (per `set_h2c_pkt_hdr_88xx`) the driver increments it for every H2C; a
    /// fixed seq can make the fw treat a repeat command as already-seen.
    h2c_seq: AtomicU16,
    /// Regulatory region for the TX-power limit table (`PW_LMT_REGU_*`; 0 = FCC).
    /// Caps per-rate TX power per channel; set with [`set_reg_region`](Self::set_reg_region).
    reg_region: std::sync::atomic::AtomicU8,
    /// Thermal-meter reading captured at bring-up (the calibration reference for
    /// [`thermal_track`](Self::thermal_track)), the operating channel, and the
    /// limit-computed TXAGC reference index that thermal tracking offsets from.
    cal_thermal: std::sync::atomic::AtomicU8,
    cur_channel: std::sync::atomic::AtomicU8,
    tx_ref_base: std::sync::atomic::AtomicU8,
    /// Current channel bandwidth (`ChannelBw as u8`); the TX descriptor's
    /// DATA_BW field follows it.
    cur_bw: std::sync::atomic::AtomicU8,
    /// Cyclic Shift Diversity for 1-stream OFDM frames. When set, the OFDM
    /// 1-stream TX path is routed to **both** antennas (`0x820[1:0]=AB`) instead
    /// of A-only, so a single stream is transmitted from both antennas with the
    /// standard per-antenna cyclic shift the BB applies — decorrelating them to
    /// avoid line-of-sight nulls. Pure TX diversity for feedback-free broadcast,
    /// with no throughput cost (unlike STBC) and no special receiver. Honoured by
    /// [`set_channel_bw20`](Self::set_channel_bw20) so it survives bandwidth
    /// changes. Mutually exclusive with per-frame STBC (both claim antenna B).
    tx_csd: std::sync::atomic::AtomicBool,
    /// Subscribed name-groups for multi-prefix DCNLA (software set-membership
    /// over the hardware multicast-narrowed RX stream). Empty ⇒ no SW filter.
    mcast_groups: std::sync::Mutex<Vec<[u8; 6]>>,
    /// Decoded frames pending from the last bulk-IN read. The chip aggregates
    /// several RX units into one USB transfer, so `recv_frame` parses the whole
    /// buffer and drains them one at a time. Single consumer (the face reader).
    rx_pending: std::sync::Mutex<std::collections::VecDeque<CapturedFrame>>,
    /// Set once an RX pump ([`spawn_rx_pump`](Self::spawn_rx_pump)) is running:
    /// background reader threads keep several bulk-IN transfers in flight and fill
    /// `rx_pending`, so `recv_frame` just drains the queue instead of doing its own
    /// blocking read (which left the RX FIFO unattended between calls).
    rx_pumped: std::sync::atomic::AtomicBool,
    /// Wakes `recv_frame` when a pump thread pushes into `rx_pending`.
    rx_notify: tokio::sync::Notify,
}

impl LibUsbRtl88xxBackend {
    /// Find the first RTL88xx dongle, open it, claim interface 0, and locate the
    /// bulk endpoints. Errors if no matching dongle is present or it can't be
    /// claimed (on Linux, any kernel driver is auto-detached first).
    pub fn open() -> Result<Self, FaceError> {
        let context = Context::new().map_err(usb_err)?;
        for device in context.devices().map_err(usb_err)?.iter() {
            let desc = device.device_descriptor().map_err(usb_err)?;
            if desc.vendor_id() == REALTEK_VID && RTL88XX_PIDS.contains(&desc.product_id()) {
                return Self::claim(device);
            }
        }
        Err(FaceError::Io(io::Error::new(
            io::ErrorKind::NotFound,
            "no RTL88xx dongle found (Realtek 0bda:88xx)",
        )))
    }

    fn claim(device: Device<Context>) -> Result<Self, FaceError> {
        let handle = Arc::new(device.open().map_err(usb_err)?);
        // Take the device from any kernel driver (Linux); harmless elsewhere.
        let _ = handle.set_auto_detach_kernel_driver(true);
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
                        Direction::In if bulk_in.is_none() => bulk_in = Some(ep.address()),
                        Direction::Out if bulk_out.is_none() => bulk_out = Some(ep.address()),
                        _ => {}
                    }
                }
            }
        }
        let no_ep = || {
            FaceError::Io(io::Error::new(
                io::ErrorKind::NotFound,
                "RTL88xx exposes no bulk IN/OUT endpoint",
            ))
        };
        Ok(Self {
            handle,
            bulk_out: bulk_out.ok_or_else(no_ep)?,
            bulk_in: bulk_in.ok_or_else(no_ep)?,
            format: FrameFormat::default(),
            seq: AtomicU16::new(0),
            tx_qsel: std::sync::atomic::AtomicU8::new(QSEL_MGT),
            h2c_seq: AtomicU16::new(0),
            reg_region: std::sync::atomic::AtomicU8::new(0), // FCC
            cal_thermal: std::sync::atomic::AtomicU8::new(0),
            cur_channel: std::sync::atomic::AtomicU8::new(0),
            tx_ref_base: std::sync::atomic::AtomicU8::new(0),
            cur_bw: std::sync::atomic::AtomicU8::new(ChannelBw::Bw20 as u8),
            tx_csd: std::sync::atomic::AtomicBool::new(false),
            mcast_groups: std::sync::Mutex::new(Vec::new()),
            rx_pending: std::sync::Mutex::new(std::collections::VecDeque::new()),
            rx_pumped: std::sync::atomic::AtomicBool::new(false),
            rx_notify: tokio::sync::Notify::new(),
        })
    }

    /// Open the first RTL88xx dongle and bring it up in 5 GHz monitor mode on
    /// `channel` (20 MHz) — a one-call path to a TX/RX-ready backend that can be
    /// dropped straight into a [`MonitorWifiFace`](crate::MonitorWifiFace). This
    /// is the constructor the named-radio bearer uses; [`open`](Self::open)
    /// without [`bring_up`](Self::bring_up) yields a device that is claimed but
    /// not yet transmitting.
    pub fn open_monitor(channel: u8) -> Result<Self, FaceError> {
        let backend = Self::open()?;
        backend.bring_up(channel)?;
        Ok(backend)
    }

    /// Spawn the **dynamic-mechanism watchdog** on a background thread: every
    /// ~2 s it runs [`watchdog_tick`](Self::watchdog_tick) (thermal TX-power
    /// tracking + RX DIG) for the life of the backend. The thread holds a
    /// [`Weak`](std::sync::Weak) reference and exits on its own once the
    /// `Arc<Self>` is dropped, so the returned [`JoinHandle`] can be ignored.
    /// Call once after [`open_monitor`](Self::open_monitor) for a self-
    /// maintaining link.
    pub fn spawn_watchdog(self: &Arc<Self>) -> std::thread::JoinHandle<()> {
        let weak = Arc::downgrade(self);
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(Duration::from_secs(2));
                let Some(dev) = weak.upgrade() else { break };
                if let Err(e) = dev.watchdog_tick() {
                    tracing::debug!(error = %e, "watchdog tick failed");
                }
            }
        })
    }

    /// Start `depth` background reader threads — **USB RX pipelining**. Each loops
    /// a blocking bulk-IN read, parses the transfer into `rx_pending`, and wakes
    /// `recv_frame`. With several reads always outstanding the chip always has a
    /// buffer to DMA into, so the RX FIFO doesn't overflow between `recv_frame`
    /// calls (the userspace-RX throughput ceiling). After this, `recv_frame` just
    /// drains the queue. Threads hold a `Weak<Self>` and exit when the backend is
    /// dropped (within one ~200 ms read timeout). `depth` 2–4 is plenty over USB.
    pub fn spawn_rx_pump(self: &Arc<Self>, depth: usize) -> Vec<std::thread::JoinHandle<()>> {
        self.rx_pumped
            .store(true, std::sync::atomic::Ordering::Relaxed);
        (0..depth.max(1))
            .map(|_| {
                let weak = Arc::downgrade(self);
                std::thread::spawn(move || {
                    let mut buf = vec![0u8; 16384];
                    loop {
                        let Some(dev) = weak.upgrade() else { break };
                        match dev.handle.read_bulk(
                            dev.bulk_in,
                            &mut buf,
                            Duration::from_millis(200),
                        ) {
                            Ok(n) if n > 0 => {
                                {
                                    let mut off = 0;
                                    let mut q = dev.rx_pending.lock().unwrap();
                                    while let Some((decoded, advance)) =
                                        dev.parse_rx_at(&buf[..n], off)
                                    {
                                        for f in decoded {
                                            q.push_back(f);
                                        }
                                        off += advance;
                                        if off + 24 > n {
                                            break;
                                        }
                                    }
                                }
                                dev.rx_notify.notify_one();
                            }
                            _ => {} // timeout / empty / error: re-submit the read
                        }
                    }
                })
            })
            .collect()
    }

    /// Run the full monitor-mode bring-up on an already-[`open`](Self::open)ed
    /// device: power on, download NIC firmware, init the MAC + monitor RCR, load
    /// the BB/RF tables and calibrate (DACK + FW IQK/DPK), tune to `channel`, and
    /// bring up the BB transmit datapath ([`bb_tx_datapath_init`] — the on-air
    /// gate). After this the backend transmits and receives. This is the library
    /// equivalent of the `usb_probe --inject` bring-up.
    ///
    /// [`bb_tx_datapath_init`]: Self::bb_tx_datapath_init
    pub fn bring_up(&self, channel: u8) -> Result<(), FaceError> {
        self.power_on()?;
        self.download_firmware(Self::firmware_nic())?;
        self.mac_init()?;
        self.monitor_cfg()?;
        self.send_general_info()?;
        // The kernel sends two register-based HMEBOX H2C commands at init that
        // our packet-H2C path never issues — documented prime suspect for the
        // firmware TX-state. NDN_RADIO_HMEBOX_H2C=1 replays them.
        if std::env::var("NDN_RADIO_HMEBOX_H2C").is_ok() {
            self.send_hmebox_h2c()?;
        }
        // NDN_RADIO_MINIMAL: skip our full direct BB/RF table load and let the
        // firmware configure+enable the PHY itself (the kernel's offload path).
        // Give the fw a settle window after general_info to apply its config.
        let minimal = std::env::var("NDN_RADIO_MINIMAL").is_ok();
        if minimal {
            std::thread::sleep(Duration::from_millis(200));
            eprintln!("NDN_RADIO_MINIMAL: skipping phy_init + cal, fw-configured PHY");
        } else {
            self.phy_init()?;
        }
        self.set_channel_bw20(channel)?;
        // NOTE: do NOT force the BT-coex grant before the cal chain. It was tried
        // (the theory: cals should run with GNT_WL=1 so TXGAPK fits against a
        // full-power chain) and it BROKE TX outright — empirically verified via the
        // OPi reciprocal link: grant-before-cal → 0 frames decoded; grant only at
        // the end (below) → ~850 frames. Forcing the BTC indirect grant before
        // calibration corrupts the cal/BB state. The grant stays at the END only,
        // exactly as in the S11–S13 working driver. (2026-06-14 bisection.)
        // FW + driver RF calibration (channel-dependent → after set_channel).
        // Not the on-air gate, but tunes TX power/EVM. NDN_RADIO_SKIP_CAL=1 bypasses it.
        if !minimal && std::env::var("NDN_RADIO_SKIP_CAL").is_err() {
            self.fw_iqk(false, false)?;
            // LO calibration (the kernel's `HAL_RF_LCK`).
            if let Err(e) = self.lck() {
                tracing::warn!(error = %e, "LCK calibration failed");
            }
            self.fw_dpk()?;
            // DPK is force-bypassed for our RFE type (21), matching the kernel.
            if let Err(e) = self.dpk_force_bypass() {
                tracing::warn!(error = %e, "DPK force-bypass failed");
            }
            // Factory power/thermal/PA-bias trim from EFUSE — must run before
            // TX Gain-K so the gain correction sits on the trimmed base.
            if let Err(e) = self.kfree() {
                tracing::warn!(error = %e, "kfree trim failed; TX power uncalibrated");
            }
            // TX Gain-K: rewrite the RF gain table so the modulated TX gain
            // tracks the target curve (the kernel's `HAL_RF_TXGAPK`).
            if let Err(e) = self.txgapk(channel) {
                tracing::warn!(error = %e, "TXGAPK calibration failed; TX gain uncalibrated");
            }
        } else {
            eprintln!("NDN_RADIO_SKIP_CAL: bypassing FW IQK/DPK + LCK/kfree/TXGAPK");
        }
        // External-FEM pinmux (GPIO_MUXCFG 0x40 + LED_CFG 0x4c + PAD_CTRL1 0x64):
        // route the FEM control signals (PA-enable / LNA / TX-RX switch) onto their
        // GPIO pins. The kernel does this for this board REGARDLESS of the phydm
        // rfe field (golden writes 0x40/0x4c/0x64 even though phydm_info reports
        // rfe=0) — it's board-level (the BL-M8812EU2 has external FEMs).
        // Skippable via NDN_RADIO_NO_EFEM for A/B.
        if RFE_TYPE == 21 && std::env::var("NDN_RADIO_NO_EFEM").is_err() {
            self.efem_pinmux_config()?;
        }
        // The on-air gate: configure the BB transmit datapath and the RF
        // receive path, then re-tune (the datapath init touches RF 0x18).
        self.bb_tx_datapath_init()?;
        self.rx_path_init()?;
        // Override the reference unit's captured TXAGC refs with this dongle's own
        // EFUSE power-by-rate base (per-device calibration).
        match self.calibrate_tx_power(channel) {
            Ok((a, b)) => tracing::debug!(base_a = a, base_b = b, "TX power calibrated from EFUSE"),
            Err(e) => {
                tracing::warn!(error = %e, "TX power calibration failed; using captured refs")
            }
        }
        self.set_channel_bw20(channel)?;
        // Re-assert the Wi-Fi grant after the post-cal RF re-tune (set_channel /
        // calibrate_tx_power touch RF state). It was already forced before the cal
        // chain; this keeps the steady-state grant pinned for TX.
        if let Err(e) = self.btc_grant_wl() {
            tracing::warn!(error = %e, "btc_grant_wl failed; TX power ~50 dB low");
        }
        // Capture the thermal reference for runtime power tracking.
        if let Ok(t) = self.read_thermal(RfPath::A) {
            self.cal_thermal.store(t, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Wait for the BTC indirect-register port to be ready (`0x1700[29]`
    /// clears), then masked-write the BT-coexistence indirect register `addr`
    /// via the `0x1700`/`0x1704` port (`_iqk_btc_write_indirect_reg_8822e`):
    /// the value goes in `0x1704`, then `0x1700` is strobed with
    /// `0xc00F0000 | addr`. A full-mask write skips the read-modify-write.
    fn btc_write_indirect(&self, addr: u16, mask: u32, val: u32) -> Result<(), FaceError> {
        let ready = |s: &Self| -> bool { s.bb_read(0x1700, 1 << 29).unwrap_or(0) == 0 };
        let data = if mask == 0xffff_ffff {
            val
        } else {
            // read-modify-write
            for _ in 0..10 {
                if ready(self) {
                    break;
                }
                std::thread::sleep(Duration::from_micros(100));
            }
            self.write32(0x1700, 0x800f_0000 | addr as u32)?;
            let orig = self.read32(0x1708)?;
            (orig & !mask) | ((val << mask.trailing_zeros()) & mask)
        };
        for _ in 0..10 {
            if ready(self) {
                break;
            }
            std::thread::sleep(Duration::from_micros(100));
        }
        self.write32(0x1704, data)?;
        self.write32(0x1700, 0xc00f_0000 | addr as u32)
    }

    /// **Force the BT-coexistence grant to Wi-Fi** (`btc_set_gnt_wl_bt`): set
    /// GNT_WL = 1, GNT_BT = 0 by writing BTC indirect register `0x38[15:8] =
    /// 0x77`. **This is the on-air TX-power gate.** Without it the BT-coex
    /// arbiter throttles the Wi-Fi TX — every static TXAGC/BB/RF register
    /// matched the kernel yet the modulated output sat ~50 dB low. The kernel
    /// forces this grant around every calibration; for a standalone Wi-Fi radio
    /// with no BT we force it permanently. Verified vs the OPi's calibrated
    /// receiver: −87 → −22 dBm (kernel-level full power).
    pub fn btc_grant_wl(&self) -> Result<(), FaceError> {
        // The kernel rtl88x2eu writes BTC 0x38 = 0xdd03 as a full 32-bit value
        // (golden usbmon 2026-06-14: read 0x800f0038, then 0x1704=0x0000dd03 /
        // strobe 0xc00f0038) — [15:8]=0xdd, [7:0]=0x03 — whereas we historically
        // forced only [15:8]=0x77. NDN_RADIO_BTC38=<hex> overrides for A/B
        // testing (e.g. 0xdd03 = kernel-faithful full write).
        if let Ok(s) = std::env::var("NDN_RADIO_BTC38")
            && let Ok(v) = u32::from_str_radix(s.trim_start_matches("0x"), 16)
        {
            return self.btc_write_indirect(0x38, 0xffff_ffff, v);
        }
        self.btc_write_indirect(0x38, 0x0000_ff00, 0x77)
    }

    /// Diagnostic: one raw bulk-IN read. Returns the unparsed buffer (RX
    /// descriptor + frame) the chip delivers, or `None` on timeout. Used to tell
    /// "chip delivers nothing" from "parse_rx rejects it".
    pub fn recv_raw(&self, timeout_ms: u64) -> Result<Option<Vec<u8>>, FaceError> {
        let mut buf = vec![0u8; 16384];
        match self
            .handle
            .read_bulk(self.bulk_in, &mut buf, Duration::from_millis(timeout_ms))
        {
            Ok(n) => {
                buf.truncate(n);
                Ok(Some(buf))
            }
            Err(rusb::Error::Timeout) => Ok(None),
            Err(e) => Err(usb_err(e)),
        }
    }

    /// Override the TX queue selector (diagnostic; default MGT 0x12).
    pub fn set_tx_qsel(&self, qsel: u8) {
        self.tx_qsel.store(qsel, Ordering::Relaxed);
    }

    /// Enable or disable Cyclic Shift Diversity for 1-stream OFDM frames (see
    /// [`tx_csd`](Self#structfield.tx_csd)). Stores the flag (so it survives a
    /// later [`set_channel_bw20`](Self::set_channel_bw20)) and applies it
    /// immediately by rewriting the OFDM 1-stream TX-path nibble `0x820[1:0]`
    /// (AB = both antennas when on, A-only when off). Call after bring-up /
    /// channel setup. **Do not combine with per-frame STBC** — both use antenna
    /// B and the kernel treats `tx_npath` and STBC_TX as mutually exclusive.
    pub fn set_tx_csd(&self, enable: bool) -> Result<(), FaceError> {
        self.tx_csd.store(enable, Ordering::Relaxed);
        // 0x820[1:0] = 1-stream OFDM TX path: AB (3) for CSD, A (1) otherwise.
        self.bb_write(0x820, 0x3, if enable { 0x3 } else { 0x1 })?;
        Ok(())
    }

    /// Set the EDCCA energy-detect thresholds (jaguar3), in dBm. EDCCA is the
    /// energy half of carrier sense: it holds off TX while in-air energy is
    /// above `l2h_dbm` (until it falls below `h2l_dbm`). On a congested channel
    /// the default thresholds make us defer to every other transmitter —
    /// host-centric, AP-style etiquette. Raising them lets a *data-centric*
    /// broadcast still put named data on the air under contention. Faithful to
    /// `phydm_set_edcca_threshold` (8822E): `0x84c` byte 2 = L2H, byte 3 = H2L,
    /// each encoded `(dBm + 110) + 0x80`. (`h2l` is conventionally `l2h − 8` =
    /// the kernel's default hysteresis.) See also [`set_edcca_ignore`].
    ///
    /// [`set_edcca_ignore`]: Self::set_edcca_ignore
    pub fn set_edcca_threshold(&self, l2h_dbm: i8, h2l_dbm: i8) -> Result<(), FaceError> {
        let enc = |dbm: i8| -> u32 { ((dbm as i32 + 110 + 0x80) & 0xff) as u32 };
        self.bb_write(0x84c, 0x00ff_0000, enc(l2h_dbm))?; // MASKBYTE2 = L2H
        self.bb_write(0x84c, 0xff00_0000, enc(h2l_dbm))?; // MASKBYTE3 = H2L
        Ok(())
    }

    /// Make the MAC **ignore EDCCA** entirely (`phydm_mac_edcca_state`,
    /// `PHYDM_IGNORE_EDCCA`): transmit regardless of detected in-air energy —
    /// the bluntest "transmit under contention" lever for a broadcast radio that
    /// treats named data as priority traffic. `0x520[15]` = ignore-EDCCA, and
    /// `0x524[11]` = 0 enables the EDCCA count-down (cleared here, set when not
    /// ignoring). Read-modify-write so the surrounding TXPAUSE/scheduler bytes
    /// in those dwords are preserved.
    pub fn set_edcca_ignore(&self, ignore: bool) -> Result<(), FaceError> {
        let mut r520 = self.read32(0x520)?;
        if ignore {
            r520 |= 1 << 15;
        } else {
            r520 &= !(1u32 << 15);
        }
        self.write32(0x520, r520)?;
        let mut r524 = self.read32(0x524)?;
        if ignore {
            r524 &= !(1u32 << 11);
        } else {
            r524 |= 1 << 11;
        }
        self.write32(0x524, r524)?;
        Ok(())
    }

    /// Measure the channel busy-ratio (CLM — Channel Load Measurement) over a
    /// window, in percent (0–100). The BB counts 4 µs samples in which the
    /// medium is busy (energy above the CCA threshold), so this senses **all**
    /// occupancy — including non-decodable interference that frame-counting
    /// misses — making it the spectrum-sensing primitive for frequency agility /
    /// cognitive radio. Faithful to `phydm_clm_*` (jaguar3): period
    /// `0x1e40[15:0]` in 4 µs units, trigger `0x1e60[0]` 0→1, ready `0x2d88[16]`,
    /// result `0x2d88[15:0]`; ratio = `(busy·100 + period/2) / period`.
    /// `window_us` is the measurement window (period clamped to 4 µs · 65535 ≈
    /// 262 ms). Blocking; call from a scan loop, not the inject hot path. NB the
    /// period count assumes a 20 MHz sample clock.
    pub fn measure_clm(&self, window_us: u32) -> Result<u8, FaceError> {
        let period = (window_us / 4).clamp(1, 0xffff);
        self.bb_write(0x1e40, 0xffff, period)?; // clm_period (4 µs samples)
        self.bb_write(0x1e60, 0x1, 0)?; // trigger low
        self.bb_write(0x1e60, 0x1, 1)?; // trigger: rising edge starts the count
        let budget_us = period * 4 + 10_000;
        let step_us = 2_000u32;
        let mut waited = 0u32;
        while self.bb_read(0x2d88, 1 << 16)? == 0 {
            if waited >= budget_us {
                return Err(init_err(
                    "rtl88xx CLM: measurement not ready (timeout)".to_string(),
                ));
            }
            std::thread::sleep(std::time::Duration::from_micros(step_us as u64));
            waited += step_us;
        }
        let busy = self.bb_read(0x2d88, 0xffff)?; // busy 4 µs-sample count
        Ok((((busy * 100 + period / 2) / period).min(100)) as u8)
    }

    /// CLM-driven channel selection: measure [`measure_clm`](Self::measure_clm)
    /// on each of `candidates` and return the clearest as `(channel, busy_%)`.
    /// The sensing→decision core of frequency agility — pick spectrum that is
    /// actually clear *from this node's vantage* instead of discovering
    /// congestion the hard way. `window_us` is the per-channel CLM window. The
    /// radio is re-tuned across candidates and **left on the winner** on return.
    /// A channel whose CLM read errors is treated as fully busy (skipped).
    pub fn pick_clear_channel(
        &self,
        candidates: &[u8],
        window_us: u32,
    ) -> Result<(u8, u8), FaceError> {
        let mut best: Option<(u8, u8)> = None;
        for (i, &ch) in candidates.iter().enumerate() {
            // First hop lays down the 20 MHz datapath; later hops use the fast
            // RF-only retune (~3x quicker) so the scan isn't switch-bound.
            if i == 0 {
                self.set_channel(ch, ChannelBw::Bw20)?;
            } else {
                self.set_channel_fast(ch)?;
            }
            std::thread::sleep(std::time::Duration::from_millis(15));
            let busy = self.measure_clm(window_us).unwrap_or(100);
            if best.is_none_or(|(_, b)| busy < b) {
                best = Some((ch, busy));
            }
        }
        let (ch, busy) =
            best.ok_or_else(|| init_err("pick_clear_channel: no candidates".to_string()))?;
        self.set_channel_fast(ch)?; // leave the radio on the winner
        Ok((ch, busy))
    }

    /// **DCNLA name-group hardware RX filter** — "the name is the address, in
    /// silicon." Program the MAC to accept only frames whose BSSID (addr3)
    /// equals `group_mac` (a name/namespace hash from [`frame::name_group_mac`],
    /// which our TX path also writes into addr1 *and* addr3). Frames for other
    /// name-groups are dropped **in hardware**, before they ever reach the host —
    /// content-centric filtering by the chip's address matcher, replacing
    /// host-side "hear everything, filter in software" promiscuous monitor.
    ///
    /// Mechanism (8822E): write `REG_BSSID` (0x618), then switch RCR out of
    /// accept-all-promiscuous (clear AAP, bit 0) into accept-multicast +
    /// check-BSSID-on-data (set AM bit 2 + CBSSID_DATA bit 6), clearing
    /// accept-broadcast (bit 3) so *only* the subscribed name-group passes;
    /// APP_PHYSTS (bit 28, per-frame RSSI) is preserved. `MAR` stays all-ones
    /// (all multicast buckets), so the exact filtering is the BSSID match.
    /// [`clear_name_group_filter`] restores promiscuous monitor.
    ///
    /// [`frame::name_group_mac`]: crate::frame::name_group_mac
    /// [`clear_name_group_filter`]: Self::clear_name_group_filter
    pub fn set_name_group_filter(&self, group_mac: [u8; 6]) -> Result<(), FaceError> {
        const REG_BSSID: u16 = 0x0618;
        let lo = u32::from_le_bytes([group_mac[0], group_mac[1], group_mac[2], group_mac[3]]);
        let hi = u16::from_le_bytes([group_mac[4], group_mac[5]]);
        // Program the name-group hash into the BSSID match register (addr3).
        self.write32(REG_BSSID, lo)?;
        self.write16(REG_BSSID + 4, hi)?;
        // Media status = AdHoc (`MSR` = REG_CR byte 0x102 bits[1:0], `_NETTYPE`).
        // Without AAP the MAC gates *data*-frame RX on a connected media status;
        // the monitor default (NoLink) drops them even when the address matches.
        let msr = (self.read8(0x0102)? & !0x03) | 0x01; // MSR_ADHOC
        self.write8(0x0102, msr)?;
        let mut rcr = self.read32(REG_RCR)?;
        rcr &= !(1 << 0); // AAP off — no longer accept every frame
        rcr |= 1 << 2; // AM — accept multicast (our group MAC is multicast)
        rcr &= !(1 << 3); // AB off — strict: only the name-group, not broadcast
        rcr |= 1 << 6; // CBSSID_DATA — drop data frames whose BSSID != REG_BSSID
        if std::env::var("NDN_DCNLA_NOCBSSID").is_ok() {
            rcr &= !(1 << 6); // AM-only (accept all multicast; no BSSID match)
        }
        self.write32(REG_RCR, rcr)?;
        Ok(())
    }

    /// Read back `(RCR, BSSID, MSR)` for verifying the name-group filter took.
    pub fn name_group_filter_state(&self) -> Result<(u32, [u8; 6], u8), FaceError> {
        let rcr = self.read32(REG_RCR)?;
        let lo = self.read32(0x0618)?.to_le_bytes();
        let hi = self.read16(0x061c)?.to_le_bytes();
        let bssid = [lo[0], lo[1], lo[2], lo[3], hi[0], hi[1]];
        let msr = self.read8(0x0102)? & 0x03;
        Ok((rcr, bssid, msr))
    }

    /// Restore promiscuous monitor RX (undo [`set_name_group_filter`]): RCR back
    /// to accept-all-physical + PHY-status (`rx_path_init`'s `RCR_MONITOR`).
    ///
    /// [`set_name_group_filter`]: Self::set_name_group_filter
    pub fn clear_name_group_filter(&self) -> Result<(), FaceError> {
        self.write32(REG_RCR, (1 << 31) | (1 << 28) | (1 << 0))?;
        let msr = self.read8(0x0102)? & !0x03; // MSR_NOLINK (monitor default)
        self.write8(0x0102, msr)?;
        Ok(())
    }

    /// **Multi-prefix DCNLA** — subscribe to several name-groups at once. Because
    /// our name-group MACs are *multicast* (group bit set), the hardware narrows
    /// to multicast in silicon (RCR **AM** on — drops every unicast frame and
    /// beacon, i.e. the bulk of ambient), and the exact per-group selection is a
    /// software set-membership check over that already-thinned stream
    /// ([`group_subscribed`]). This is how NICs filter multicast groups generally
    /// (imperfect HW narrow + SW confirm) and it scales past any fixed slot count.
    /// AAP/AB/CBSSID off, MSR=AdHoc (data-frame RX gate). [`clear_name_group_filter`]
    /// restores monitor.
    ///
    /// NB the chip's 8-entry **MBSSID CAM** (`RCR_ENMBID`) is an exact hardware
    /// multi-address matcher, but it matches addr1 for *unicast* (ACK) semantics
    /// and does not accept our *multicast* group MACs — it would only suit
    /// unicast-form name addresses (a ≤8-group, pure-HW variant; see notes).
    ///
    /// [`group_subscribed`]: Self::group_subscribed
    /// [`clear_name_group_filter`]: Self::clear_name_group_filter
    pub fn set_name_group_filter_multi(&self, groups: &[[u8; 6]]) -> Result<(), FaceError> {
        if groups.is_empty() {
            return Err(init_err("rtl88xx DCNLA: need ≥1 name-group".to_string()));
        }
        *self.mcast_groups.lock().unwrap() = groups.to_vec();
        let msr = (self.read8(0x0102)? & !0x03) | 0x01; // MSR_ADHOC
        self.write8(0x0102, msr)?;
        let mut rcr = self.read32(REG_RCR)?;
        rcr &= !(1 << 0); // AAP off — no longer promiscuous
        rcr |= 1 << 2; // AM on — accept multicast (HW narrows to it), drop unicast
        rcr &= !(1 << 3); // AB off
        rcr &= !(1 << 6); // CBSSID_DATA off
        self.write32(REG_RCR, rcr)?;
        Ok(())
    }

    /// Software side of multi-prefix DCNLA: is `group` (a frame's addr1) one of
    /// the subscribed name-groups set by [`set_name_group_filter_multi`]? Used by
    /// the RX path to drop the non-subscribed multicast the hardware AM filter
    /// still lets through. Empty subscription ⇒ accept all (no SW filter).
    ///
    /// [`set_name_group_filter_multi`]: Self::set_name_group_filter_multi
    pub fn group_subscribed(&self, group: &[u8; 6]) -> bool {
        let g = self.mcast_groups.lock().unwrap();
        g.is_empty() || g.contains(group)
    }

    /// The bulk-OUT endpoint addresses (HIGH 0x05, NORMAL 0x06, LOW 0x08) for
    /// diagnostic queue routing.
    pub fn bulk_out_ep(&self) -> u8 {
        self.bulk_out
    }
    /// Override the bulk-OUT endpoint used for injection (diagnostic).
    pub fn set_bulk_out(&mut self, ep: u8) {
        self.bulk_out = ep;
    }

    /// Set the on-air [`FrameFormat`] (defaults to `RawNdn` with ethertype
    /// 0x8624). Builder-style; returns `self`.
    pub fn with_format(mut self, format: FrameFormat) -> Self {
        self.format = format;
        self
    }

    // ── Control-path register I/O (the foundation every init step builds on) ──

    /// Read `buf.len()` (1/2/4) register bytes at `addr` over the vendor request.
    fn read_reg(&self, addr: u16, buf: &mut [u8]) -> Result<(), FaceError> {
        let n = self
            .handle
            .read_control(REQ_READ, VENDOR_REQ, addr, 0, buf, CTRL_TIMEOUT)
            .map_err(usb_err)?;
        if n != buf.len() {
            return Err(init_err(format!(
                "rtl88xx read_reg({addr:#06x}): short {n}/{}",
                buf.len()
            )));
        }
        Ok(())
    }

    /// Write 1/2/4 little-endian register bytes at `addr` over the vendor request.
    fn write_reg(&self, addr: u16, data: &[u8]) -> Result<(), FaceError> {
        // Instrumentation: with NDN_RADIO_LOG_WRITES set, emit every MMIO write
        // in the same `W<size>\t0x<addr>\t0x<value>` format as the decoded golden
        // usbmon trace (golden/.../init_regseq.txt) so the two can be diffed.
        {
            use std::sync::OnceLock;
            static LOG: OnceLock<bool> = OnceLock::new();
            if *LOG.get_or_init(|| std::env::var("NDN_RADIO_LOG_WRITES").is_ok()) {
                let mut v = 0u32;
                for (i, b) in data.iter().enumerate().take(4) {
                    v |= (*b as u32) << (i * 8);
                }
                eprintln!(
                    "W{}\t0x{:04x}\t0x{:0w$x}",
                    data.len(),
                    addr,
                    v,
                    w = data.len() * 2
                );
            }
        }
        let n = self
            .handle
            .write_control(REQ_WRITE, VENDOR_REQ, addr, 0, data, CTRL_TIMEOUT)
            .map_err(usb_err)?;
        if n != data.len() {
            return Err(init_err(format!(
                "rtl88xx write_reg({addr:#06x}): short {n}/{}",
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

    /// Set bits in an 8-bit register (read-modify-write).
    fn set8(&self, addr: u16, bits: u8) -> Result<(), FaceError> {
        let v = self.read8(addr)?;
        self.write8(addr, v | bits)
    }

    /// Clear bits in an 8-bit register (read-modify-write).
    fn clr8(&self, addr: u16, bits: u8) -> Result<(), FaceError> {
        let v = self.read8(addr)?;
        self.write8(addr, v & !bits)
    }

    // ── halmac 8822E power-on (rtw_halmac_poweron) ──────────────────────────
    //
    // The kernel flow is: halmac_pre_init_system_cfg → halmac_mac_power_switch
    // (the card-enable power sequence) → halmac_init_system_cfg. After this the
    // MAC power domain and the EFUSE/analog clocks are up — the physical EFUSE
    // read works, firmware download becomes possible.

    /// Full power-on: `pre_init_system_cfg_8822e` + `mac_pwr_switch_usb_8822e`
    /// (POWER_ON) + `init_system_cfg_8822e`. If the chip reports it is already
    /// powered, it is power-cycled first (the kernel's warm-reboot recovery
    /// path), so repeated runs land in the same state.
    pub fn power_on(&self) -> Result<(), FaceError> {
        let info = self.chip_info()?;
        if info.chip_id != CHIP_ID_8822E {
            return Err(init_err(format!(
                "rtl88xx: chip id {:#04x} is not 8822E ({CHIP_ID_8822E:#04x}); refusing to run \
                 the 8822E power sequence",
                info.chip_id
            )));
        }

        self.pre_init_system_cfg()?;

        self.leave_32k()?;
        if self.mac_power_is_on()? {
            // Warm state (e.g. a previous probe run) — cycle through power-off
            // so the enable sequence starts from CARDEMU like the kernel does.
            self.run_pwr_seq(CARD_DISABLE_FLOW_8822E, info.cut_msk())?;
        }
        self.run_pwr_seq(CARD_ENABLE_FLOW_8822E, info.cut_msk())?;
        // halmac clears the software power-off marker after a successful enable.
        self.clr8(REG_SYS_STATUS1 + 1, 1 << 0)?;

        self.init_system_cfg(&info)
    }

    /// Power the MAC off (`card_dis_flow_8822e`): ACT→CARDEMU→CARDDIS.
    pub fn power_off(&self) -> Result<(), FaceError> {
        let info = self.chip_info()?;
        self.run_pwr_seq(CARD_DISABLE_FLOW_8822E, info.cut_msk())
    }

    /// `pre_init_system_cfg_8822e` (USB branch): release `REG_RSV_CTRL`, apply
    /// the USB-PHY quirk, set pad/LED/GPIO pinmux, hold BB/RF disabled, and
    /// refuse to continue if the chip is strapped into test mode.
    fn pre_init_system_cfg(&self) -> Result<(), FaceError> {
        self.write8(REG_RSV_CTRL, 0)?;

        // USB: if REG_SYS_CFG2+3 reads 0x20 (USB3 PHY active), set 0xFE5B[4].
        if self.read8(REG_SYS_CFG2 + 3)? == 0x20 {
            self.set8(0xfe5b, 1 << 4)?;
        }

        let pad = self.read32(REG_PAD_CTRL1)?;
        self.write32(REG_PAD_CTRL1, pad | (1 << 28) | (1 << 29))?;
        let led = self.read32(REG_LED_CFG)?;
        self.write32(REG_LED_CFG, led & !((1 << 25) | (1 << 26)))?;
        let mux = self.read32(REG_GPIO_MUXCFG)?;
        self.write32(REG_GPIO_MUXCFG, mux | (1 << 2))?;

        self.enable_bb_rf(false)?;

        if self.read8(REG_SYS_CFG + 2)? & (1 << 4) != 0 {
            return Err(init_err("rtl88xx: chip strapped into test mode".into()));
        }
        Ok(())
    }

    /// `enable_bb_rf_88xx`: gate the BB (`REG_SYS_FUNC_EN[1:0]`), RF paths
    /// (`REG_RF_CTRL[2:0]`), and WLRF analog enables (`REG_WLRF1[26:24]`).
    /// Pre-init disables them; the BB/RF bring-up stage re-enables them.
    pub fn enable_bb_rf(&self, enable: bool) -> Result<(), FaceError> {
        let fen = self.read8(REG_SYS_FUNC_EN)?;
        let rf = self.read8(REG_RF_CTRL)?;
        let wlrf = self.read32(REG_WLRF1)?;
        if enable {
            self.write8(REG_SYS_FUNC_EN, fen | 0x03)?;
            self.write8(REG_RF_CTRL, rf | 0x07)?;
            self.write32(REG_WLRF1, wlrf | (0x07 << 24))?;
        } else {
            self.write8(REG_SYS_FUNC_EN, fen & !0x03)?;
            self.write8(REG_RF_CTRL, rf & !0x07)?;
            self.write32(REG_WLRF1, wlrf & !(0x07 << 24))?;
        }
        Ok(())
    }

    /// Power-state probe from `mac_pwr_switch_usb_8822e`: `REG_CR` reads `0xEA`
    /// when the MAC power domain is down; otherwise the software power-off
    /// marker `REG_SYS_STATUS1+1[0]` decides.
    fn mac_power_is_on(&self) -> Result<bool, FaceError> {
        if self.read8(REG_CR)? == 0xea {
            return Ok(false);
        }
        Ok(self.read8(REG_SYS_STATUS1 + 1)? & (1 << 0) == 0)
    }

    /// If downloaded firmware is alive (`REG_MCUFW_CTRL == 0xC078`), toggle the
    /// RPWM bit at `0xFE58` so it leaves 32K low-power state before the power
    /// sequence runs.
    fn leave_32k(&self) -> Result<(), FaceError> {
        let rpwm = self.read8(0xfe58)?;
        if self.read16(REG_MCUFW_CTRL)? == 0xc078 {
            self.write8(0xfe58, (rpwm ^ 0x80) & 0x80)?;
        }
        Ok(())
    }

    /// `init_system_cfg_8822e`: platform reset + descriptor-DMA enable, the
    /// `SYS_FUNC_EN` block enables, the MAC PHY-request delay, disable
    /// boot-from-flash so the host can download firmware, and the B-cut LDO
    /// voltage-select fix.
    fn init_system_cfg(&self, info: &ChipInfo) -> Result<(), FaceError> {
        const BIT_WL_PLATFORM_RST: u32 = 1 << 16;
        const BIT_DDMA_EN: u32 = 1 << 8;
        const SYS_FUNC_EN_8822E: u8 = 0xd8; // written to REG_SYS_FUNC_EN+1
        const WLAN_PHY_REQ_DELAY: u8 = 0x0c; // REG_CR_EXT+3 bits[3:0] (20 MHz BW)
        const BIT_BOOT_FSPI_EN: u32 = 1 << 20;
        const BIT_FSPI_EN: u32 = 1 << 19;
        const BITS_LDO_VSEL: u8 = 0x03;

        let dmem = self.read32(REG_CPU_DMEM_CON)?;
        self.write32(REG_CPU_DMEM_CON, dmem | BIT_WL_PLATFORM_RST | BIT_DDMA_EN)?;

        self.set8(REG_SYS_FUNC_EN + 1, SYS_FUNC_EN_8822E)?;

        let delay = (self.read8(REG_CR_EXT + 3)? & 0xf0) | WLAN_PHY_REQ_DELAY;
        self.write8(REG_CR_EXT + 3, delay)?;

        let mcufw = self.read32(REG_MCUFW_CTRL)?;
        if mcufw & BIT_BOOT_FSPI_EN != 0 {
            self.write32(REG_MCUFW_CTRL, mcufw & !BIT_BOOT_FSPI_EN)?;
            let mux = self.read32(REG_GPIO_MUXCFG)?;
            self.write32(REG_GPIO_MUXCFG, mux & !BIT_FSPI_EN)?;
        }

        if info.cut == 1 {
            // B-cut: clear the LDO voltage-select bits.
            self.clr8(REG_ANAPAR_MAC_0, BITS_LDO_VSEL)?;
        }
        Ok(())
    }

    /// Walk a halmac power sequence (`pwr_seq_parser_88xx`): each flow is a list
    /// of sub-sequences, each entry a register op gated by cut/interface masks.
    /// `Write` is read-modify-write; `Polling` waits for the masked value (each
    /// `read8` is a USB control transfer, so ~1000 tries ≈ a 1 s ceiling).
    fn run_pwr_seq(&self, flow: &[&[PwrCfg]], cut_msk: u8) -> Result<(), FaceError> {
        for seq in flow {
            for c in *seq {
                if c.cut_msk & cut_msk == 0 || c.intf_msk & INTF_USB == 0 {
                    continue;
                }
                match c.cmd {
                    PWR_CMD_WRITE => {
                        let v = (self.read8(c.offset)? & !c.msk) | (c.value & c.msk);
                        self.write8(c.offset, v)?;
                    }
                    PWR_CMD_POLLING => {
                        let mut ready = false;
                        for _ in 0..1000 {
                            if self.read8(c.offset)? & c.msk == (c.value & c.msk) {
                                ready = true;
                                break;
                            }
                        }
                        if !ready {
                            return Err(init_err(format!(
                                "rtl88xx pwrseq: polling timeout @ {:#06x} msk {:#04x} want {:#04x}",
                                c.offset, c.msk, c.value
                            )));
                        }
                    }
                    PWR_CMD_DELAY => {
                        // offset = amount, value = unit (0 = µs, 1 = ms).
                        let us = if c.value == 0 {
                            c.offset as u64
                        } else {
                            c.offset as u64 * 1000
                        };
                        std::thread::sleep(Duration::from_micros(us));
                    }
                    PWR_CMD_END => break,
                    _ => {}
                }
            }
        }
        Ok(())
    }

    // ── EFUSE (halmac_efuse_8822e — the 8822E overrides the generic 88xx path) ──

    /// Read `buf.len()` physical-EFUSE bytes starting at `offset` — a port of
    /// `read_hw_efuse_8822e`. The 8822E protocol differs from older chips:
    /// the read must be bracketed by the **EFUSE software power-cut enable**
    /// (PMC write-unmask + `PWC_EV2EF_S/B` power bits + releasing the
    /// `ISO_EB2CORE` isolation on `REG_SYS_ISO_CTRL` — without this the EFUSE
    /// block is isolated and never responds) and **OTP burst mode**
    /// (`REG_EFUSE_CTRL_1[19]`); the `REG_EFUSE_CTRL` field layout is the V1
    /// one — address in bits[26:16], ready flag at bit 29, data in [15:0].
    /// Requires [`power_on`](Self::power_on). Bank select is a no-op on 8822E.
    pub fn efuse_read(&self, offset: u16, buf: &mut [u8]) -> Result<(), FaceError> {
        const BIT_EF_RDY: u32 = 1 << 29;
        const MASK_EF_ADDR_V1: u32 = 0x7ff;
        const SHIFT_EF_ADDR_V1: u32 = 16;
        const BIT_EF_BURST: u32 = 1 << 19;

        self.efuse_sw_pwr_cut(true)?;

        let burst = self.read32(REG_EFUSE_CTRL_1)?;
        self.write32(REG_EFUSE_CTRL_1, burst | BIT_EF_BURST)?;

        let mut result = Ok(());
        'read: for (i, slot) in buf.iter_mut().enumerate() {
            let addr = offset as u32 + i as u32;
            // Address-only write with EF_RDY clear triggers the read.
            self.write32(REG_EFUSE_CTRL, (addr & MASK_EF_ADDR_V1) << SHIFT_EF_ADDR_V1)?;
            let mut done = false;
            for _ in 0..1000 {
                let t = self.read32(REG_EFUSE_CTRL)?;
                if t & BIT_EF_RDY != 0 {
                    *slot = (t & 0xff) as u8;
                    done = true;
                    break;
                }
            }
            if !done {
                result = Err(init_err(format!(
                    "rtl88xx efuse read timeout @ {addr:#06x}"
                )));
                break 'read;
            }
        }

        // Always undo burst mode + the power cut, even on a failed read.
        let burst = self.read32(REG_EFUSE_CTRL_1)?;
        self.write32(REG_EFUSE_CTRL_1, burst & !BIT_EF_BURST)?;
        self.efuse_sw_pwr_cut(false)?;
        result
    }

    /// Read one physical EFUSE byte (see [`efuse_read`](Self::efuse_read)).
    pub fn efuse_read_byte(&self, addr: u16) -> Result<u8, FaceError> {
        let mut b = [0u8; 1];
        self.efuse_read(addr, &mut b)?;
        Ok(b[0])
    }

    /// Dump the physical EFUSE. Reads `1536` bytes — the logical content is the
    /// first 1216, but the factory power-PG (`PPG_*`) trim cells the kfree
    /// calibration reads live in the raw `0x5xx` region above that.
    pub fn efuse_dump_physical(&self) -> Result<Vec<u8>, FaceError> {
        const EFUSE_SIZE_8822E: usize = 1536;
        let mut map = vec![0u8; EFUSE_SIZE_8822E];
        self.efuse_read(0, &mut map)?;
        Ok(map)
    }

    /// Decode a physical EFUSE map into the **logical** map (`EEPROM_SIZE_8822E`
    /// = 2048 bytes, unwritten cells `0xFF`) — a port of `eeprom_parser_8822e`
    /// (wifi flavour): content starts after the 4 security-control bytes; every
    /// entry has a 2-byte header (`blk_idx = hdr2[7:4] | hdr[3:0] << 4`,
    /// `word_en = hdr2[3:0]` active-low per 2-byte word), then the enabled
    /// words. A `0xFF` header terminates the map.
    pub fn efuse_decode_logical(physical: &[u8]) -> Result<Vec<u8>, FaceError> {
        const SEC_CTRL_EFUSE_SIZE: usize = 4;
        const EEPROM_SIZE_8822E: usize = 2048;
        let mut log = vec![0xffu8; EEPROM_SIZE_8822E];
        let mut idx = SEC_CTRL_EFUSE_SIZE;
        while let Some(&hdr) = physical.get(idx) {
            if hdr == 0xff {
                break;
            }
            idx += 1;
            let Some(&hdr2) = physical.get(idx) else {
                break;
            };
            if hdr2 == 0xff {
                break;
            }
            idx += 1;
            let blk_idx = ((hdr2 & 0xf0) >> 4) as usize | ((hdr & 0x0f) as usize) << 4;
            let word_en = hdr2 & 0x0f;
            for i in 0..4 {
                if (!(word_en >> i)) & 1 == 0 {
                    continue;
                }
                let eeprom_idx = (blk_idx << 3) + (i << 1);
                if eeprom_idx + 1 >= EEPROM_SIZE_8822E || idx + 1 >= physical.len() {
                    return Err(init_err(format!(
                        "rtl88xx efuse parse overflow (hdr {hdr:#04x} {hdr2:#04x} @ {idx:#x})"
                    )));
                }
                log[eeprom_idx] = physical[idx];
                log[eeprom_idx + 1] = physical[idx + 1];
                idx += 2;
            }
        }
        Ok(log)
    }

    /// The dongle's burned-in MAC address from the logical EFUSE
    /// (`EEPROM_MAC_ADDR_8822EU` = 0x157).
    pub fn efuse_mac(&self) -> Result<[u8; 6], FaceError> {
        const EEPROM_MAC_ADDR_8822EU: usize = 0x157;
        let physical = self.efuse_dump_physical()?;
        let logical = Self::efuse_decode_logical(&physical)?;
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&logical[EEPROM_MAC_ADDR_8822EU..EEPROM_MAC_ADDR_8822EU + 6]);
        Ok(mac)
    }

    /// `enable_efuse_sw_pwr_cut` / `disable_efuse_sw_pwr_cut` (read flavour,
    /// `is_write = 0`): unmask PMC register writes, power the EV2EF rails
    /// (small then big, with the reference driver's 1 ms settle), and release
    /// the EFUSE-block-to-core isolation — reversed in mirror order on disable.
    fn efuse_sw_pwr_cut(&self, enable: bool) -> Result<(), FaceError> {
        const BIT_SYSON_DIS_PMCREG_WRMSK: u8 = 1 << 2;
        const BIT_PWC_EV2EF_S: u16 = 1 << 14;
        const BIT_PWC_EV2EF_B: u16 = 1 << 15;
        const BIT_ISO_EB2CORE: u16 = 1 << 8;
        let iso = |v: u16| -> Result<(), FaceError> { self.write16(REG_SYS_ISO_CTRL, v) };

        if enable {
            self.set8(REG_PMC_DBG_CTRL2, BIT_SYSON_DIS_PMCREG_WRMSK)?;
            iso(self.read16(REG_SYS_ISO_CTRL)? | BIT_PWC_EV2EF_S)?;
            std::thread::sleep(Duration::from_millis(1));
            iso(self.read16(REG_SYS_ISO_CTRL)? | BIT_PWC_EV2EF_B)?;
            iso(self.read16(REG_SYS_ISO_CTRL)? & !BIT_ISO_EB2CORE)?;
        } else {
            iso(self.read16(REG_SYS_ISO_CTRL)? | BIT_ISO_EB2CORE)?;
            iso(self.read16(REG_SYS_ISO_CTRL)? & !BIT_PWC_EV2EF_B)?;
            std::thread::sleep(Duration::from_millis(1));
            iso(self.read16(REG_SYS_ISO_CTRL)? & !BIT_PWC_EV2EF_S)?;
            self.clr8(REG_PMC_DBG_CTRL2, BIT_SYSON_DIS_PMCREG_WRMSK)?;
        }
        Ok(())
    }

    // ── Firmware download (halmac_fw_88xx download_firmware_88xx) ───────────
    //
    // The WLAN CPU firmware is pushed through the TX path: each chunk is sent
    // as a reserved-page packet over bulk OUT (48-byte TX descriptor, beacon
    // queue), landing in the TX buffer; the on-chip DDMA channel 0 then copies
    // it from TXBUF into IMEM/DMEM/EMEM with a running checksum. Afterwards the
    // WLAN CPU is released and polled until `REG_MCUFW_CTRL` reads the fw-ready
    // magic 0xC078.

    /// The RTL8822E NIC firmware blob, extracted from the reference driver's
    /// `hal/rtl8822e/hal8822e_fw.c` (`array_mp_8822e_fw_nic`). Header reports
    /// v1.27, built 2024-09-04 — matching the golden `fw_info` ("FW VER -1.27").
    pub fn firmware_nic() -> &'static [u8] {
        include_bytes!("../fw/rtl8822e_fw_nic.bin")
    }

    /// Download `fw` to the WLAN CPU and wait until it boots (faithful port of
    /// `download_firmware_88xx`, USB interface). Requires
    /// [`power_on`](Self::power_on). On success the firmware is alive:
    /// `REG_MCUFW_CTRL == 0xC078` and the parsed [`FwVersion`] is returned.
    pub fn download_firmware(&self, fw: &[u8]) -> Result<FwVersion, FaceError> {
        let hdr = FwHeader::parse(fw)?;

        let lte_backup = self.ltecoex_read(0x38)?;
        self.wlan_cpu_en(false)?;

        // Backup the registers the download temporarily repurposes, then map
        // HIQ to high priority and leave only the TX DMA engines running.
        let bk_pq_map = self.read8(REG_TXDMA_PQ_MAP + 1)?;
        self.write8(REG_TXDMA_PQ_MAP + 1, DMA_MAPPING_HIGH << 6)?;
        let bk_cr = self.read8(REG_CR)?;
        let bk_h2cq_csr = 1u32 << 31;
        self.write8(REG_CR, 0x05)?; // BIT_HCI_TXDMA_EN | BIT_TXDMA_EN
        self.write32(REG_H2CQ_CSR, 1 << 31)?;
        let bk_fifo_info1 = self.read16(REG_FIFOPAGE_INFO_1)?;
        let bk_rqpn2 = self.read32(REG_RQPN_CTRL_2)? | (1 << 31);
        self.write16(REG_FIFOPAGE_INFO_1, 0x200)?;
        self.write32(REG_RQPN_CTRL_2, bk_rqpn2)?;
        let bk_bcn_ctrl = self.read8(REG_BCN_CTRL)?;
        self.write8(REG_BCN_CTRL, (bk_bcn_ctrl & !(1 << 3)) | (1 << 4))?;

        // pltfm_reset_88xx — pulse the platform reset (no 8822B/8821C quirk).
        self.clr8(REG_CPU_DMEM_CON + 2, 1 << 0)?;
        self.set8(REG_CPU_DMEM_CON + 2, 1 << 0)?;

        let dl_result = self.start_dlfw(fw, &hdr);

        // restore_mac_reg_88xx — always, even on a failed download.
        self.write8(REG_TXDMA_PQ_MAP + 1, bk_pq_map)?;
        self.write8(REG_CR, bk_cr)?;
        self.write32(REG_H2CQ_CSR, bk_h2cq_csr)?;
        self.write16(REG_FIFOPAGE_INFO_1, bk_fifo_info1)?;
        self.write32(REG_RQPN_CTRL_2, bk_rqpn2)?;
        self.write8(REG_BCN_CTRL, bk_bcn_ctrl)?;

        let end_result = dl_result.and_then(|()| self.dlfw_end_flow());
        if let Err(e) = end_result {
            // DLFW_FAIL: drop FWDL_EN, re-enable the CPU block, restore coex.
            self.clr8(REG_MCUFW_CTRL, 1 << 0)?;
            self.set8(REG_SYS_FUNC_EN + 1, 1 << 2)?;
            self.ltecoex_write(0x38, lte_backup)?;
            return Err(e);
        }

        self.ltecoex_write(0x38, lte_backup)?;
        Ok(hdr.version)
    }

    /// `start_dlfw_88xx`: enable FWDL, then stream the DMEM, IMEM, and (when
    /// present) EMEM sections to their OCP addresses.
    fn start_dlfw(&self, fw: &[u8], hdr: &FwHeader) -> Result<(), FaceError> {
        let ctrl = (self.read16(REG_MCUFW_CTRL)? & 0x3800) | 0x0001; // FWDL_EN
        self.write16(REG_MCUFW_CTRL, ctrl)?;

        let mut cur = WLAN_FW_HDR_SIZE;
        self.dlfw_to_mem(&fw[cur..cur + hdr.dmem_size], hdr.dmem_addr)?;
        cur += hdr.dmem_size;
        self.dlfw_to_mem(&fw[cur..cur + hdr.imem_size], hdr.imem_addr)?;
        cur += hdr.imem_size;
        if hdr.emem_size != 0 {
            self.dlfw_to_mem(&fw[cur..cur + hdr.emem_size], hdr.emem_addr)?;
        }
        Ok(())
    }

    /// `dlfw_to_mem_88xx`: send the section in ≤8 KB reserved-page packets and
    /// DDMA each from the TX buffer to `dest`, with a running checksum.
    fn dlfw_to_mem(&self, mut bin: &[u8], dest: u32) -> Result<(), FaceError> {
        const DLFW_PKT_MAX_SIZE: usize = 8192;
        const BIT_DDMACH0_RESET_CHKSUM_STS: u32 = 1 << 25;
        let v = self.read32(REG_DDMA_CH0CTRL)?;
        self.write32(REG_DDMA_CH0CTRL, v | BIT_DDMACH0_RESET_CHKSUM_STS)?;

        let mut mem_offset = 0u32;
        let mut first = true;
        while !bin.is_empty() {
            let pkt = &bin[..bin.len().min(DLFW_PKT_MAX_SIZE)];
            self.send_fwpkt(pkt)?;
            self.iddma_dlfw(
                OCPBASE_TXBUF + TX_DESC_SIZE as u32,
                dest + mem_offset,
                pkt.len() as u32,
                first,
            )?;
            first = false;
            mem_offset += pkt.len() as u32;
            bin = &bin[pkt.len()..];
        }

        self.check_fw_chksum(dest)
    }

    /// `send_fwpkt_88xx`: a USB total length (descriptor + payload) that is an
    /// exact multiple of 512 confuses the bulk pipe — append one dummy byte.
    fn send_fwpkt(&self, pkt: &[u8]) -> Result<(), FaceError> {
        if (pkt.len() + TX_DESC_SIZE).is_multiple_of(512) {
            let mut dup = Vec::with_capacity(pkt.len() + 1);
            dup.extend_from_slice(pkt);
            dup.push(0);
            self.dl_rsvd_page(0, &dup)
        } else {
            self.dl_rsvd_page(0, pkt)
        }
    }

    /// `dl_rsvd_page_88xx` + the USB platform send: point the beacon-queue head
    /// at `pg_addr`, enable SW beacon TX, push the packet (48-byte beacon-queue
    /// TX descriptor + payload) down bulk OUT 0, and poll BCN_VALID.
    fn dl_rsvd_page(&self, pg_addr: u16, buf: &[u8]) -> Result<(), FaceError> {
        self.write16(REG_FIFOPAGE_CTRL_2, (pg_addr & 0x0fff) | (1 << 15))?;
        let bk_cr1 = self.read8(REG_CR + 1)?;
        self.write8(REG_CR + 1, bk_cr1 | (1 << 0))?; // ENSWBCN
        let bk_txq = self.read8(REG_FWHW_TXQ_CTRL + 2)?;
        self.write8(REG_FWHW_TXQ_CTRL + 2, bk_txq & !(1 << 6))?;

        let mut result = self.send_beacon_queue_pkt(buf);
        if result.is_ok() {
            result = Err(init_err("rtl88xx dlfw: BCN_VALID poll timeout".into()));
            for _ in 0..1000 {
                if self.read8(REG_FIFOPAGE_CTRL_2 + 1)? & (1 << 7) != 0 {
                    result = Ok(());
                    break;
                }
            }
        }

        // Restore: beacon head back to the reserved boundary (0 pre-TRX-init).
        self.write16(REG_FIFOPAGE_CTRL_2, 1 << 15)?;
        self.write8(REG_FWHW_TXQ_CTRL + 2, bk_txq)?;
        self.write8(REG_CR + 1, bk_cr1)?;
        result
    }

    /// `usb_write_data_not_xmitframe` (beacon qsel): prepend the 48-byte TX
    /// descriptor (with the 512-boundary packet-offset workaround) and write it
    /// to bulk OUT id 0 (beacon/high queue → first bulk OUT endpoint).
    fn send_beacon_queue_pkt(&self, payload: &[u8]) -> Result<(), FaceError> {
        const USB_BULKOUT_SIZE: usize = 512;
        const PACKET_OFFSET_SZ: usize = 8;
        const QSEL_BEACON: u8 = 0x10;

        let mut offset = TX_DESC_SIZE;
        if (TX_DESC_SIZE + payload.len()).is_multiple_of(USB_BULKOUT_SIZE) {
            offset += PACKET_OFFSET_SZ;
        }
        let mut frame = vec![0u8; offset + payload.len()];
        frame[offset..].copy_from_slice(payload);

        txdesc_set(&mut frame, 0x00, 0, 16, payload.len() as u32); // TXPKTSIZE
        txdesc_set(&mut frame, 0x00, 16, 8, offset as u32); // OFFSET
        if offset != TX_DESC_SIZE {
            txdesc_set(&mut frame, 0x04, 24, 5, 1); // PKT_OFFSET
        }
        txdesc_set(&mut frame, 0x04, 8, 5, QSEL_BEACON as u32); // QSEL
        txdesc_checksum(&mut frame);

        let n = self
            .handle
            .write_bulk(self.bulk_out, &frame, Duration::from_secs(1))
            .map_err(usb_err)?;
        if n != frame.len() {
            return Err(init_err(format!(
                "rtl88xx dlfw: short bulk write {n}/{}",
                frame.len()
            )));
        }
        Ok(())
    }

    /// `iddma_dlfw_88xx` + `iddma_en_88xx`: drive DDMA channel 0 to copy `len`
    /// bytes from `src` (TX buffer OCP address) to `dest` (IMEM/DMEM/EMEM).
    fn iddma_dlfw(&self, src: u32, dest: u32, len: u32, first: bool) -> Result<(), FaceError> {
        const BIT_DDMACH0_OWN: u32 = 1 << 31;
        const BIT_DDMACH0_CHKSUM_EN: u32 = 1 << 29;
        const BIT_DDMACH0_CHKSUM_CONT: u32 = 1 << 24;
        const MASK_DDMACH0_DLEN: u32 = 0x3ffff;

        let mut ready = false;
        for _ in 0..1000 {
            if self.read32(REG_DDMA_CH0CTRL)? & BIT_DDMACH0_OWN == 0 {
                ready = true;
                break;
            }
        }
        if !ready {
            return Err(init_err("rtl88xx dlfw: DDMA ch0 busy".into()));
        }

        let mut ctrl = BIT_DDMACH0_CHKSUM_EN | BIT_DDMACH0_OWN | (len & MASK_DDMACH0_DLEN);
        if !first {
            ctrl |= BIT_DDMACH0_CHKSUM_CONT;
        }
        self.write32(REG_DDMA_CH0SA, src)?;
        self.write32(REG_DDMA_CH0DA, dest)?;
        self.write32(REG_DDMA_CH0CTRL, ctrl)?;
        for _ in 0..1000 {
            if self.read32(REG_DDMA_CH0CTRL)? & BIT_DDMACH0_OWN == 0 {
                return Ok(());
            }
        }
        Err(init_err("rtl88xx dlfw: DDMA ch0 transfer timeout".into()))
    }

    /// `check_fw_chksum_88xx`: report the DDMA running-checksum result into the
    /// IMEM/DMEM status bits of `REG_MCUFW_CTRL`.
    fn check_fw_chksum(&self, dest: u32) -> Result<(), FaceError> {
        const BIT_DDMACH0_CHKSUM_STS: u32 = 1 << 27;
        const BIT_IMEM_DW_OK: u8 = 1 << 3;
        const BIT_IMEM_CHKSUM_OK: u8 = 1 << 4;
        const BIT_DMEM_DW_OK: u8 = 1 << 5;
        const BIT_DMEM_CHKSUM_OK: u8 = 1 << 6;

        let fw_ctrl = self.read8(REG_MCUFW_CTRL)?;
        let failed = self.read32(REG_DDMA_CH0CTRL)? & BIT_DDMACH0_CHKSUM_STS != 0;
        let is_imem = dest < OCPBASE_DMEM; // IMEM and EMEM report via the IMEM bits
        let bits = if failed {
            if is_imem {
                (fw_ctrl | BIT_IMEM_DW_OK) & !BIT_IMEM_CHKSUM_OK
            } else {
                (fw_ctrl | BIT_DMEM_DW_OK) & !BIT_DMEM_CHKSUM_OK
            }
        } else if is_imem {
            fw_ctrl | BIT_IMEM_DW_OK | BIT_IMEM_CHKSUM_OK
        } else {
            fw_ctrl | BIT_DMEM_DW_OK | BIT_DMEM_CHKSUM_OK
        };
        self.write8(REG_MCUFW_CTRL, bits)?;
        if failed {
            return Err(init_err(format!(
                "rtl88xx dlfw: checksum failed for dest {dest:#x}"
            )));
        }
        Ok(())
    }

    /// `dlfw_end_flow_88xx`: confirm both section checksums, flag FW_DW_RDY,
    /// release the WLAN CPU, and poll for the 0xC078 fw-ready magic.
    fn dlfw_end_flow(&self) -> Result<(), FaceError> {
        const BIT_FW_DW_RDY: u16 = 1 << 14;
        const ILLEGAL_KEY_GROUP: u32 = 0xFAAAAA00;

        self.write32(REG_TXDMA_STATUS, 1 << 2)?;

        let fw_ctrl = self.read16(REG_MCUFW_CTRL)?;
        if fw_ctrl & 0x50 != 0x50 {
            return Err(init_err(format!(
                "rtl88xx dlfw: IMEM/DMEM checksum bits not ok (MCUFW_CTRL={fw_ctrl:#06x})"
            )));
        }
        self.write16(REG_MCUFW_CTRL, (fw_ctrl | BIT_FW_DW_RDY) & !0x0001)?;

        self.wlan_cpu_en(true)?;

        for _ in 0..2000 {
            if self.read16(REG_MCUFW_CTRL)? == 0xc078 {
                return Ok(());
            }
        }
        if self.read32(REG_FW_DBG7)? & 0xffffff00 == ILLEGAL_KEY_GROUP {
            return Err(init_err("rtl88xx dlfw: illegal key group".into()));
        }
        Err(init_err(
            "rtl88xx dlfw: fw-ready (0x80 == 0xC078) poll timeout".into(),
        ))
    }

    /// Send the **general-info** and **phydm-info** H2C packets to the
    /// firmware (`send_general_info_88xx`). These tell the on-chip CPU the
    /// TX-buffer boundary and the RF/antenna/cut configuration so its dynamic
    /// mechanisms and TX scheduling work. Sent in the kernel's init order
    /// (after MAC init, before BB/RF). Requires
    /// [`download_firmware`](Self::download_firmware) + [`mac_init`](Self::mac_init).
    pub fn send_general_info(&self) -> Result<(), FaceError> {
        const SUB_GENERAL_INFO: u16 = 0x0d;
        const SUB_PHYDM_INFO: u16 = 0x11;
        const RF_2T2R: u32 = 2;
        const ANT_AB: u32 = 0x3;
        let info = self.chip_info()?;

        // general_info: FW_TX_BOUNDARY at 0x08[16:23] = fw-txbuf − rsvd boundary.
        let mut gi = [0u8; 32];
        h2c_hdr(&mut gi, SUB_GENERAL_INFO, 4, 0);
        let fw_tx_boundary = (Self::RSVD_CSIBUF_ADDR - 4) - Self::RSVD_BOUNDARY; // rsvd_fw_txbuf_addr − boundary
        txdesc_set(&mut gi, 0x08, 16, 8, fw_tx_boundary as u32);
        self.send_h2c(&gi)?;

        // phydm_info: rfe/rf/cut/antenna so phydm's FW side matches the host.
        let mut pi = [0u8; 32];
        if std::env::var("NDN_RADIO_KERNEL_PHYDM").is_ok() {
            // Byte-exact kernel golden phydm_info (usbmon 2026-06-14): ack=0, content
            // 00 04 01 11 = rfe_type 0 / rf_type 1T1R(4) / cut 1 / rx_ant 1 /
            // tx_ant 1 / ext_pa 0 (layout from halmac_fw_offload_h2c_nic.h). Diagnostic
            // knob only — the default below (the host's own rfe/rf/antenna) is what
            // the working driver uses.
            h2c_hdr(&mut pi, SUB_PHYDM_INFO, 8, 0);
            pi[8] = 0x00;
            pi[9] = 0x04;
            pi[10] = 0x01;
            pi[11] = 0x11;
        } else {
            h2c_hdr(&mut pi, SUB_PHYDM_INFO, 8, 1);
            txdesc_set(&mut pi, 0x08, 0, 8, RFE_TYPE); // ref/rfe type
            txdesc_set(&mut pi, 0x08, 8, 8, RF_2T2R); // rf type
            txdesc_set(&mut pi, 0x08, 16, 8, info.cut as u32); // cut version
            txdesc_set(&mut pi, 0x08, 24, 4, ANT_AB); // rx ant status
            txdesc_set(&mut pi, 0x08, 28, 4, ANT_AB); // tx ant status
        }
        self.send_h2c(&pi)
    }

    /// Replay the kernel's two init **HMEBOX** H2C commands (register-based H2C
    /// via `REG_HMEBOX_0` 0x1d0 + ext box `REG_HMEBOX_EXT0` 0x1f0; write ext
    /// first, then the box to trigger). usbmon golden 2026-06-14:
    /// `0x1f0=0x11 / 0x1d0=0x0100004c`, then `0x1f4=0 / 0x1d4=0x000001c3`.
    fn send_hmebox_h2c(&self) -> Result<(), FaceError> {
        self.write32(0x01f0, 0x0000_0011)?;
        self.write32(0x01d0, 0x0100_004c)?;
        std::thread::sleep(Duration::from_millis(5));
        self.write32(0x01f4, 0x0000_0000)?;
        self.write32(0x01d4, 0x0000_01c3)?;
        std::thread::sleep(Duration::from_millis(5));
        Ok(())
    }

    /// Send one 32-byte H2C packet via the firmware TX path: prepend a TX
    /// descriptor with `QSEL = H2C_CMD`, write it to the bulk-OUT (the
    /// `usb_write_data_h2c` path). Used by [`send_general_info`](Self::send_general_info).
    fn send_h2c(&self, h2c: &[u8; 32]) -> Result<(), FaceError> {
        const QSEL_H2C: u8 = 0x13;
        let mut buf = vec![0u8; TX_DESC_SIZE + h2c.len()];
        txdesc_set(&mut buf, 0x00, 0, 16, h2c.len() as u32); // TXPKTSIZE
        txdesc_set(&mut buf, 0x00, 16, 8, TX_DESC_SIZE as u32); // OFFSET
        txdesc_set(&mut buf, 0x04, 8, 5, QSEL_H2C as u32); // QSEL = H2C
        txdesc_checksum(&mut buf);
        buf[TX_DESC_SIZE..].copy_from_slice(h2c);
        // Stamp the monotonic H2C sequence number into the offload header
        // (dword 1 bits [16:31]); the fw echoes it in the C2H ack.
        let seq = self.h2c_seq.fetch_add(1, Ordering::Relaxed);
        txdesc_set(&mut buf, TX_DESC_SIZE + 0x04, 16, 16, seq as u32);
        if buf.len().is_multiple_of(512) {
            buf.push(0);
        }
        // Instrument: with NDN_RADIO_LOG_WRITES set, dump the H2C payload bytes
        // (after the TX desc) so they can be mapped against the decoded kernel
        // golden H2C sequence.
        {
            use std::sync::OnceLock;
            static LOG: OnceLock<bool> = OnceLock::new();
            if *LOG.get_or_init(|| std::env::var("NDN_RADIO_LOG_WRITES").is_ok()) {
                let hex: Vec<String> = h2c.iter().map(|b| format!("{b:02x}")).collect();
                eprintln!("H2C\t{}", hex.join(" "));
            }
        }
        let n = self
            .handle
            .write_bulk(self.bulk_out, &buf, Duration::from_secs(1))
            .map_err(usb_err)?;
        if n != buf.len() {
            return Err(init_err(format!(
                "rtl88xx h2c: short write {n}/{}",
                buf.len()
            )));
        }
        Ok(())
    }

    /// Send an arbitrary H2C packet (diagnostic): replay firmware commands
    /// captured from the working kernel driver to test whether a missing
    /// init-H2C / firmware TX-state is the on-air gate. Pads to 32 bytes.
    pub fn send_h2c_raw(&self, payload: &[u8]) -> Result<(), FaceError> {
        let mut h2c = [0u8; 32];
        let n = payload.len().min(32);
        h2c[..n].copy_from_slice(&payload[..n]);
        self.send_h2c(&h2c)
    }

    /// `wlan_cpu_en_88xx`: gate the WLAN CPU (`REG_SYS_FUNC_EN+1[2]`) and its
    /// IO interface (`REG_RSV_CTRL+1[0]`) — IO first on disable, last on enable.
    fn wlan_cpu_en(&self, enable: bool) -> Result<(), FaceError> {
        if enable {
            self.set8(REG_RSV_CTRL + 1, 1 << 0)?;
            self.set8(REG_SYS_FUNC_EN + 1, 1 << 2)?;
        } else {
            self.clr8(REG_SYS_FUNC_EN + 1, 1 << 2)?;
            self.clr8(REG_RSV_CTRL + 1, 1 << 0)?;
        }
        Ok(())
    }

    /// `ltecoex_reg_read_88xx` — indirect LTE-coex register read.
    fn ltecoex_read(&self, offset: u16) -> Result<u32, FaceError> {
        self.ltecoex_wait_ready()?;
        self.write32(REG_LTECOEX_ACCESS_CTRL, 0x800F0000 | offset as u32)?;
        self.read32(REG_LTECOEX_ACCESS_CTRL + 8)
    }

    /// `ltecoex_reg_write_88xx` — indirect LTE-coex register write.
    fn ltecoex_write(&self, offset: u16, value: u32) -> Result<(), FaceError> {
        self.ltecoex_wait_ready()?;
        self.write32(REG_LTECOEX_ACCESS_CTRL + 4, value)?;
        self.write32(REG_LTECOEX_ACCESS_CTRL, 0xC00F0000 | offset as u32)
    }

    fn ltecoex_wait_ready(&self) -> Result<(), FaceError> {
        for _ in 0..1000 {
            if self.read8(REG_LTECOEX_ACCESS_CTRL + 3)? & (1 << 5) != 0 {
                return Ok(());
            }
        }
        Err(init_err("rtl88xx: ltecoex ready poll timeout".into()))
    }

    // ── MAC init (halmac init_mac_cfg_88xx → *_8822e, TRX_MODE_NORMAL, USB ──
    //   3-bulkout). Brings up the TX DMA queue mapping, TX-buffer page layout +
    //   auto-LLT, H2C queue, protocol/EDCA/WMAC defaults. After this REG_CR
    //   reads 0xFF (all MAC engines on; golden adds BIT9 MAC_SEC_EN from the
    //   kernel's security init, which monitor mode doesn't need).

    /// TX-buffer page accounting (`set_trx_fifo_info_8822e`, 128-byte pages):
    /// 256 KB TX FIFO = 2048 pages, minus the reserved tail (drv 8 +
    /// h2c-extra 24 + h2c-static 8 + h2cq 8 + fw-txbuf 4 + csibuf 50 = 102).
    /// The driver reserves 8 (not halmac's default 16) drv pages
    /// (`HALMAC_RSVD_PG_NUM8` via `_cfg_drv_rsvd_pg_num`) — boundary 1946
    /// matches the golden register dump (0x79A in 0x204/0x424/…).
    const TX_FIFO_PG_NUM: u16 = 2048;
    const RSVD_BOUNDARY: u16 = Self::TX_FIFO_PG_NUM - 102; // 1946, also the ACQ page count
    const RSVD_H2CQ_ADDR: u16 = Self::TX_FIFO_PG_NUM - 50 - 4 - 8; // 1986
    const RSVD_CSIBUF_ADDR: u16 = Self::TX_FIFO_PG_NUM - 50; // 1998

    /// Full MAC config: `init_trx_cfg` → `init_protocol_cfg` → `init_edca_cfg`
    /// → `init_wmac_cfg` (each the 8822E flavour, 20 MHz / normal mode).
    /// Requires [`power_on`](Self::power_on); run after
    /// [`download_firmware`](Self::download_firmware) like the kernel does.
    pub fn mac_init(&self) -> Result<(), FaceError> {
        self.init_trx_cfg()?;
        self.init_protocol_cfg()?;
        self.init_edca_cfg()?;
        self.init_wmac_cfg()
    }

    /// `init_trx_cfg_8822e` (NORMAL mode): queue→DMA mapping, MAC engine
    /// enable, FIFO page layout, auto-LLT, transfer mode, H2C queue.
    fn init_trx_cfg(&self) -> Result<(), FaceError> {
        const REG_WMAC_FWPKT_CR: u16 = 0x0601;
        const REG_FWFF_CTRL: u16 = 0x029c;
        const REG_FWFF_PKT_INFO: u16 = 0x02a0;
        // HALMAC_RQPN_3BULKOUT_8822E[NORMAL]: VO/VI→normal(2), BE/BK→low(1),
        // MG/HI→high(3), packed into REG_TXDMA_PQ_MAP bits[15:4].
        const PQ_MAP: u16 = (3 << 14) | (3 << 12) | (1 << 10) | (1 << 8) | (2 << 6) | (2 << 4);
        const MAC_TRX_ENABLE: u8 = 0xff; // HCI TX/RX DMA, TX/RX DMA, protocol, schedule, MAC TX/RX

        self.write16(REG_TXDMA_PQ_MAP, PQ_MAP)?;

        // If the fw packet engine is on, quiesce it before resetting REG_CR.
        let en_fwff = self.read8(REG_WMAC_FWPKT_CR)? & (1 << 7) != 0;
        if en_fwff {
            self.clr8(REG_WMAC_FWPKT_CR, 1 << 7)?;
            let mut empty = false;
            for _ in 0..1000 {
                if self.read16(REG_FWFF_CTRL)? == self.read16(REG_FWFF_PKT_INFO)? {
                    empty = true;
                    break;
                }
            }
            if !empty {
                return Err(init_err("rtl88xx mac init: fwff not empty".into()));
            }
        }
        self.write8(REG_CR, 0)?;
        let fwff = self.read16(REG_FWFF_PKT_INFO)?;
        self.write16(REG_FWFF_CTRL, fwff)?;
        self.write8(REG_CR, MAC_TRX_ENABLE)?;
        // Enable the MAC security engine (REG_CR bit 9, ENSEC / BIT_MAC_SEC_EN).
        // halmac's config_security_88xx sets this and the working OPi golden has
        // it on (REG_CR=0x6ff). Even with no encryption, the MAC TX datapath
        // routes every frame through the SEC stage; with the engine disabled the
        // scheduler hands a frame to SEC and it never reaches the BB (TX-PHY-OK
        // stays 0, TX FIFO pages fill but never recycle).
        self.set8(REG_CR + 1, 1 << 1)?; // bit 9 = high-byte bit 1
        if en_fwff {
            self.set8(REG_WMAC_FWPKT_CR, 1 << 7)?;
        }
        self.write32(REG_H2CQ_CSR, 1 << 31)?;

        self.priority_queue_cfg()?;
        self.init_h2c()
    }

    /// `priority_queue_cfg_8822e` + `set_trx_fifo_info_8822e` (3-bulkout
    /// NORMAL page split: high 64 / normal 64 / low 64 / extra 0 / gap 1,
    /// public = remainder) and the auto-LLT link-list init.
    fn priority_queue_cfg(&self) -> Result<(), FaceError> {
        const REG_FIFOPAGE_INFO_2: u16 = 0x0234;
        const REG_FIFOPAGE_INFO_3: u16 = 0x0238;
        const REG_FIFOPAGE_INFO_4: u16 = 0x023c;
        const REG_FIFOPAGE_INFO_5: u16 = 0x0240;
        const REG_BCNQ_BDNY_V1: u16 = 0x0424;
        const REG_BCNQ1_BDNY_V1: u16 = 0x0456;
        const REG_RXFF_BNDY: u16 = 0x011c;
        const REG_AUTO_LLT_V1: u16 = 0x0208;
        const REG_TXDMA_OFFSET_CHK: u16 = 0x020c;
        const REG_WMAC_CSIDMA_CFG: u16 = 0x169c;
        const RX_FIFO_SIZE: u32 = 24576;
        const C2H_PKT_BUF: u32 = 256;
        const BLK_DESC_NUM: u8 = 3;
        const PG_HQ: u16 = 64;
        const PG_NQ: u16 = 64;
        const PG_LQ: u16 = 64;
        const PG_EXQ: u16 = 0;
        const PG_GAP: u16 = 1;
        let pg_pub: u16 = Self::RSVD_BOUNDARY - PG_HQ - PG_NQ - PG_LQ - PG_EXQ - PG_GAP;

        self.write16(REG_FIFOPAGE_INFO_1, PG_HQ)?;
        self.write16(REG_FIFOPAGE_INFO_2, PG_LQ)?;
        self.write16(REG_FIFOPAGE_INFO_3, PG_NQ)?;
        self.write16(REG_FIFOPAGE_INFO_4, PG_EXQ)?;
        self.write16(REG_FIFOPAGE_INFO_5, pg_pub)?;
        let rqpn2 = self.read32(REG_RQPN_CTRL_2)?;
        self.write32(REG_RQPN_CTRL_2, rqpn2 | (1 << 31))?;

        self.write16(REG_FIFOPAGE_CTRL_2, Self::RSVD_BOUNDARY)?;
        self.write16(REG_WMAC_CSIDMA_CFG, Self::RSVD_CSIBUF_ADDR)?;
        self.set8(REG_FWHW_TXQ_CTRL + 2, 1 << 4)?;
        self.write16(REG_BCNQ_BDNY_V1, Self::RSVD_BOUNDARY)?;
        self.write16(REG_FIFOPAGE_CTRL_2 + 2, Self::RSVD_BOUNDARY)?;
        self.write16(REG_BCNQ1_BDNY_V1, Self::RSVD_BOUNDARY)?;

        self.write32(REG_RXFF_BNDY, RX_FIFO_SIZE - C2H_PKT_BUF - 1)?;

        // USB: bulk-descriptor count, TXDMA offset check, then auto-LLT.
        let v = self.read8(REG_AUTO_LLT_V1)?;
        self.write8(REG_AUTO_LLT_V1, (v & !(0x0f << 4)) | (BLK_DESC_NUM << 4))?;
        self.write8(REG_AUTO_LLT_V1 + 3, BLK_DESC_NUM)?;
        self.set8(REG_TXDMA_OFFSET_CHK + 1, 1 << 1)?;

        self.set8(REG_AUTO_LLT_V1, 1 << 0)?; // BIT_AUTO_INIT_LLT_V1
        let mut llt_done = false;
        for _ in 0..1000 {
            if self.read8(REG_AUTO_LLT_V1)? & (1 << 0) == 0 {
                llt_done = true;
                break;
            }
        }
        if !llt_done {
            return Err(init_err("rtl88xx mac init: auto-LLT timeout".into()));
        }

        self.write8(REG_CR + 3, 0) // HALMAC_TRNSFER_NORMAL
    }

    /// `init_h2c_8822e`: point the H2C ring at its reserved pages and verify
    /// the hardware reports the whole buffer free.
    fn init_h2c(&self) -> Result<(), FaceError> {
        const REG_H2C_HEAD: u16 = 0x0244;
        const REG_H2C_TAIL: u16 = 0x0248;
        const REG_H2C_READ_ADDR: u16 = 0x024c;
        const REG_H2C_INFO: u16 = 0x0254;
        const REG_H2C_PKT_READADDR: u16 = 0x10d0;
        const REG_H2C_PKT_WRITEADDR: u16 = 0x10d4;
        const REG_TXDMA_OFFSET_CHK: u16 = 0x020c;
        const RSVD_PG_H2CQ_NUM: u32 = 8;

        let h2cq_addr = (Self::RSVD_H2CQ_ADDR as u32) << 7;
        let h2cq_size = RSVD_PG_H2CQ_NUM << 7;

        let head = self.read32(REG_H2C_HEAD)?;
        self.write32(REG_H2C_HEAD, (head & 0xfffc0000) | h2cq_addr)?;
        let read = self.read32(REG_H2C_READ_ADDR)?;
        self.write32(REG_H2C_READ_ADDR, (read & 0xfffc0000) | h2cq_addr)?;
        let tail = self.read32(REG_H2C_TAIL)?;
        self.write32(REG_H2C_TAIL, (tail & 0xfffc0000) | (h2cq_addr + h2cq_size))?;

        let v = self.read8(REG_H2C_INFO)?;
        self.write8(REG_H2C_INFO, (v & 0xfc) | 0x01)?;
        let v = self.read8(REG_H2C_INFO)?;
        self.write8(REG_H2C_INFO, (v & 0xfb) | 0x04)?;
        let v = self.read8(REG_TXDMA_OFFSET_CHK + 1)?;
        self.write8(REG_TXDMA_OFFSET_CHK + 1, (v & 0x7f) | 0x80)?;

        // get_h2c_buf_free_space_88xx: free space must equal the buffer size.
        let wptr = self.read32(REG_H2C_PKT_WRITEADDR)? & 0x3ffff;
        let rptr = self.read32(REG_H2C_PKT_READADDR)? & 0x3ffff;
        let free = if wptr >= rptr {
            h2cq_size - (wptr - rptr)
        } else {
            rptr - wptr
        };
        if free != h2cq_size {
            return Err(init_err(format!(
                "rtl88xx mac init: h2c free space {free} != {h2cq_size}"
            )));
        }
        Ok(())
    }

    /// `init_protocol_cfg_8822e`: TX queue/report control, SIFS timing, rate
    /// fallback tables, AMPDU/protection limits, fast-EDCA thresholds, BF
    /// timer workarounds, RRSR RSC fix.
    fn init_protocol_cfg(&self) -> Result<(), FaceError> {
        const REG_AMPDU_MAX_TIME_V1: u16 = 0x0455;
        const REG_TX_HANG_CTRL: u16 = 0x045e;
        const REG_PRECNT_CTRL: u16 = 0x04e5;
        const REG_PROT_MODE_CTRL: u16 = 0x04c8;
        const REG_BAR_MODE_CTRL: u16 = 0x04cc;
        const REG_FAST_EDCA_VOVI_SETTING: u16 = 0x1448;
        const REG_FAST_EDCA_BEBK_SETTING: u16 = 0x144c;
        const REG_LIFETIME_EN: u16 = 0x0426;
        const REG_BF0_TIME_SETTING: u16 = 0x1428;
        const REG_BF1_TIME_SETTING: u16 = 0x142c;
        const REG_BF_TIMEOUT_EN: u16 = 0x1430;
        const REG_RRSR: u16 = 0x0440;
        const REG_INIRTS_RATE_SEL: u16 = 0x0480;

        // init_txq_ctrl_8822e
        self.set8(REG_FWHW_TXQ_CTRL, 1 << 7)?;
        self.write8(REG_FWHW_TXQ_CTRL + 1, 0x1f)?; // WLAN_TXQ_RPT_EN

        // init_sifs_ctrl_8822e (20 MHz values)
        const REG_RESP_SIFS_OFDM: u16 = 0x063e;
        const REG_RESP_SIFS_CCK: u16 = 0x063c;
        const REG_SPEC_SIFS: u16 = 0x0428;
        const REG_SIFS: u16 = 0x0514;
        self.write16(REG_RESP_SIFS_OFDM, 0x0e | (0x0e << 8))?;
        self.write16(REG_SPEC_SIFS, 0x0a | (0x10 << 8))?; // WLAN_SIFS_DUR_TUNE
        self.write32(REG_SIFS, 0x0a | (0x0e << 8) | (0x0a << 16) | (0x10 << 24))?;
        self.write16(REG_RESP_SIFS_CCK, 0x0a | (0x0a << 8))?;

        // init_rate_fallback_ctrl_8822e
        for (reg, val) in [
            (0x0430u16, 0x0100_0000u32), // REG_DARFRC  WLAN_DATA_RATE_FB_CNT_1_4
            (0x0434, 0x0807_0504),       // REG_DARFRCH WLAN_DATA_RATE_FB_CNT_5_8
            (0x043c, 0x0807_0504),       // REG_RARFRCH WLAN_RTS_RATE_FB_CNT_5_8
            (0x0444, 0xfe01_f010),       // REG_ARFR0
            (0x0448, 0x4000_0000),       // REG_ARFRH0
            (0x044c, 0x003f_f010),       // REG_ARFR1_V1
            (0x0450, 0x4000_0000),       // REG_ARFRH1_V1
            (0x049c, 0x0600_f010),       // REG_ARFR4
            (0x04a0, 0x4000_03e0),       // REG_ARFRH4
            (0x04a4, 0x0600_f015),       // REG_ARFR5
            (0x04a8, 0x0000_00e0),       // REG_ARFRH5
        ] {
            self.write32(reg, val)?;
        }

        self.write8(REG_AMPDU_MAX_TIME_V1, 0x70)?;
        self.set8(REG_TX_HANG_CTRL, 1 << 2)?; // BIT_EN_EOF_V1

        let pre_txcnt: u16 = 0x1e4 | (1 << 11); // WLAN_PRE_TXCNT_TIME_TH | BIT_EN_PRECNT
        self.write8(REG_PRECNT_CTRL, (pre_txcnt & 0xff) as u8)?;
        self.write8(REG_PRECNT_CTRL + 1, (pre_txcnt >> 8) as u8)?;

        // RTS len/time thresholds + aggregation limits
        self.write32(
            REG_PROT_MODE_CTRL,
            0xff | (0x08 << 8) | (0x3f << 16) | (0x20 << 24),
        )?;
        self.write16(REG_BAR_MODE_CTRL + 2, 0x01 | (0x08 << 8))?;

        self.write8(REG_FAST_EDCA_VOVI_SETTING, 0x06)?;
        self.write8(REG_FAST_EDCA_VOVI_SETTING + 2, 0x06)?;
        self.write8(REG_FAST_EDCA_BEBK_SETTING, 0x06)?;
        self.write8(REG_FAST_EDCA_BEBK_SETTING + 2, 0x06)?;

        self.clr8(REG_LIFETIME_EN, 1 << 5)?; // close BA parser

        // Bypass TXBF error protection (sounding-failure workaround)
        let bf0 = self.read32(REG_BF0_TIME_SETTING)? & !(1 << 29);
        self.write32(REG_BF0_TIME_SETTING, bf0 | (1 << 28))?;
        let bf1 = self.read32(REG_BF1_TIME_SETTING)? & !(1 << 29);
        self.write32(REG_BF1_TIME_SETTING, bf1 | (1 << 28))?;
        let bft = self.read32(REG_BF_TIMEOUT_EN)? & !(1 << 0) & !(1 << 1);
        self.write32(REG_BF_TIMEOUT_EN, bft)?;

        // Fix incorrect HW default of RRSR RSC (bits [22:21] on 8822E)
        let rrsr = self.read32(REG_RRSR)? & !(0x3 << 21);
        self.write32(REG_RRSR, rrsr)?;

        self.set8(REG_INIRTS_RATE_SEL, 1 << 5)
    }

    /// `init_edca_cfg_8822e` (20 MHz): slot/PIFS/TBTT timing, per-AC EDCA
    /// parameters, MAC clock, TX un-pause, NAV/TSF setup, beacon function.
    fn init_edca_cfg(&self) -> Result<(), FaceError> {
        const REG_SLOT: u16 = 0x051b;
        const REG_PIFS: u16 = 0x0512;
        const REG_TBTT_PROHIBIT: u16 = 0x0540;
        const REG_EDCA_VO_PARAM: u16 = 0x0500;
        const REG_EDCA_VI_PARAM: u16 = 0x0504;
        const REG_EDCA_BE_PARAM: u16 = 0x0508;
        const REG_EDCA_BK_PARAM: u16 = 0x050c;
        const REG_TX_PTCL_CTRL: u16 = 0x0520;
        const REG_RD_CTRL: u16 = 0x0524;
        const REG_AFE_CTRL1: u16 = 0x0024;
        const REG_USTIME_TSF: u16 = 0x055c;
        const REG_USTIME_EDCA: u16 = 0x0638;
        const REG_MISC_CTRL: u16 = 0x0577;
        const REG_TIMER0_SRC_SEL: u16 = 0x05b4;
        const REG_TXPAUSE: u16 = 0x0522;
        const REG_RD_NAV_NXT: u16 = 0x0544;
        const REG_RXTSF_OFFSET_CCK: u16 = 0x055e;
        const REG_DRVERLYINT: u16 = 0x0558;
        const REG_BCN_CTRL_CLINT0: u16 = 0x0551;
        const REG_BCNDMATIM: u16 = 0x0559;
        const REG_BCN_MAX_ERR: u16 = 0x055d;
        const REG_BAR_TX_CTRL: u16 = 0x0530;
        const MAC_CLK_SPEED: u8 = 80;

        self.write8(REG_SLOT, 0x09)?;
        self.write8(REG_PIFS, 0x1c)?;
        self.write32(REG_TBTT_PROHIBIT, 0x04 | (0x064 << 8))?; // WLAN_TBTT_TIME
        self.write32(REG_EDCA_VO_PARAM, 0x002f_a226)?;
        self.write32(REG_EDCA_VI_PARAM, 0x005e_a328)?;
        self.write32(REG_EDCA_BE_PARAM, 0x005e_a42b)?;
        self.write32(REG_EDCA_BK_PARAM, 0x0000_a44f)?;

        self.clr8(REG_TX_PTCL_CTRL + 1, 1 << 4)?;
        self.set8(REG_RD_CTRL + 1, 0x07)?;

        // cfg_mac_clk_88xx: 80 MHz MAC clock (sel = 0 in bits [21:20])
        let afe = self.read32(REG_AFE_CTRL1)? & !((1 << 20) | (1 << 21));
        self.write32(REG_AFE_CTRL1, afe)?;
        self.write8(REG_USTIME_TSF, MAC_CLK_SPEED)?;
        self.write8(REG_USTIME_EDCA, MAC_CLK_SPEED)?;

        self.set8(REG_MISC_CTRL, (1 << 3) | (1 << 1) | (1 << 0))?;
        self.clr8(REG_TIMER0_SRC_SEL, (1 << 4) | (1 << 5) | (1 << 6))?;
        self.write16(REG_TXPAUSE, 0x0000)?;
        self.write32(REG_RD_NAV_NXT, 0x05 | (0x1b << 16))?; // WLAN_NAV_CFG
        self.write16(REG_RXTSF_OFFSET_CCK, 0x30 | (0x30 << 8))?;

        self.set8(REG_BCN_CTRL, 1 << 3)?; // BIT_EN_BCN_FUNCTION (TSF runs)
        self.write8(REG_DRVERLYINT, 0x04)?;
        self.write8(REG_BCN_CTRL_CLINT0, 0x10)?;
        self.write8(REG_BCNDMATIM, 0x02)?;
        self.write8(REG_BCN_MAX_ERR, 0xff)?;

        self.set8(REG_BAR_TX_CTRL, 1 << 0)
    }

    /// `init_wmac_cfg_8822e` (20 MHz) + `init_low_pwr_8822e`: ACK/EIFS timing,
    /// multicast accept-all, response rates, RX filters + RCR, RX packet
    /// limit, TX/WMAC option functions, RX parser-stop-filter config.
    fn init_wmac_cfg(&self) -> Result<(), FaceError> {
        const REG_ACKTO: u16 = 0x0640;
        const REG_EIFS: u16 = 0x0642;
        const REG_MAR: u16 = 0x0620;
        const REG_BBPSF_CTRL: u16 = 0x06dc;
        const REG_ACKTO_CCK: u16 = 0x0639;
        const REG_NAV_CTRL: u16 = 0x0650;
        const REG_WMAC_TRXPTCL_CTL_H: u16 = 0x066c;
        const REG_RXFLTMAP0: u16 = 0x06a0;
        const REG_RXFLTMAP2: u16 = 0x06a4;
        const REG_RXPSF_CTRL: u16 = 0x1610;
        const REG_RXPSF_TYPE_CTRL: u16 = 0x1614;
        const REG_RX_PKT_LIMIT: u16 = 0x060c;
        const REG_TCR: u16 = 0x0604;
        const REG_GENERAL_OPTION: u16 = 0x1664;
        const REG_SND_PTCL_CTRL: u16 = 0x0718;
        const REG_WMAC_OPTION_FUNCTION_1: u16 = 0x07d4;
        const REG_WMAC_OPTION_FUNCTION_2: u16 = 0x07d8;
        const WLAN_RCR_CFG: u32 = 0xe410220e;

        self.write8(REG_ACKTO, 0x21)?;
        self.write16(REG_EIFS, 0x40)?; // WLAN_EIFS_DUR_TUNE

        self.write32(REG_MAR, 0xffff_ffff)?;
        self.write32(REG_MAR + 4, 0xffff_ffff)?;

        self.write8(REG_BBPSF_CTRL + 2, 0x84)?; // WLAN_RESP_TXRATE
        self.write8(REG_ACKTO_CCK, 0x6a)?;
        self.write8(REG_NAV_CTRL + 2, 0xc8)?; // WLAN_NAV_MAX

        self.set8(REG_WMAC_TRXPTCL_CTL_H, 1 << 1)?; // BIT_EN_TXCTS_IN_RXNAV_V1
        self.write8(REG_WMAC_TRXPTCL_CTL_H + 2, 0x05)?; // WLAN_BAR_ACK_TYPE

        self.write32(REG_RXFLTMAP0, 0xffff_ffff)?;
        self.write16(REG_RXFLTMAP2, 0xffff)?;

        self.write32(REG_RCR, WLAN_RCR_CFG)?;
        self.set8(REG_RXPSF_CTRL + 2, 0x0e)?;

        self.write8(REG_RX_PKT_LIMIT, (12288u32 >> 9) as u8)?;

        self.write8(REG_TCR + 2, 0x30)?; // WLAN_TX_FUNC_CFG2
        self.write8(REG_TCR + 1, 0x30)?; // WLAN_TX_FUNC_CFG1

        let opt = self.read16(REG_GENERAL_OPTION)?;
        self.write16(REG_GENERAL_OPTION, opt | (1 << 9) | (1 << 8))?;

        self.set8(REG_SND_PTCL_CTRL, 1 << 6)?; // disable VHT SIG-B CRC check

        self.write32(REG_WMAC_OPTION_FUNCTION_2, 0xb181_0041)?;
        self.write8(REG_WMAC_OPTION_FUNCTION_1, 0x98)?; // normal (non-loopback)

        // init_low_pwr_8822e: RXGCK FIFO thresholds + invalid-packet filter
        let v = self.read16(REG_RXPSF_CTRL + 2)? & 0xf00f;
        self.write16(
            REG_RXPSF_CTRL + 2,
            v | (1 << 10) | (1 << 8) | (1 << 6) | (1 << 4),
        )?;
        let psf: u16 = (1 << 13) // RXPSF_PKTLENTHR = 1
            | (1 << 12) // CTRLEN
            | (1 << 11) // VHTCHKEN
            | (1 << 10) // HTCHKEN
            | (1 << 9) // OFDMCHKEN
            | (1 << 8) // CCKCHKEN
            | (1 << 7); // OFDMRST
        self.write16(REG_RXPSF_CTRL, psf)?;
        self.write32(REG_RXPSF_TYPE_CTRL, 0xffff_ffff)
    }

    /// Configure monitor-mode reception the way the kernel driver's monitor
    /// interface does (golden `REG_RCR = 0x90000001`): accept-all-physical
    /// (AAP), append the PHY-status RX descriptor info (per-frame RSSI/rate),
    /// and append the FCS — and program the EFUSE MAC into `REG_MACID`.
    pub fn monitor_cfg(&self) -> Result<(), FaceError> {
        const RCR_MONITOR: u32 = (1 << 31) | (1 << 28) | (1 << 0);
        self.write32(REG_RCR, RCR_MONITOR)?;
        let mac = self.efuse_mac()?;
        for (i, b) in mac.iter().enumerate() {
            self.write8(REG_MACID + i as u16, *b)?;
        }
        Ok(())
    }

    // ── BB/RF init (phydm: halhwimg8822e_bb/_rf tables + phydm_hal_api8822e) ──
    //
    // The kernel flow after MAC init: enable the BB/RF blocks, load the
    // PHY_REG + AGC_TAB baseband tables and the RadioA/B RF tables (condition-
    // encoded u32 pair streams), set the crystal cap from EFUSE, then switch
    // channel/bandwidth. RF registers on the 8822E are memory-mapped through a
    // BB window (path A `0x3C00 + reg*4`, path B `0x4C00 + reg*4`, 20-bit).

    /// phydm table blobs (extracted verbatim from `halhwimg8822e_bb.c` /
    /// `halhwimg8822e_rf.c` `array_mp_8822e_*` arrays, LE u32 words).
    fn table_phy_reg() -> &'static [u8] {
        include_bytes!("../fw/rtl8822e_phy_reg.bin")
    }
    fn table_agc_tab() -> &'static [u8] {
        include_bytes!("../fw/rtl8822e_agc_tab.bin")
    }
    fn table_radioa() -> &'static [u8] {
        include_bytes!("../fw/rtl8822e_radioa.bin")
    }
    fn table_radiob() -> &'static [u8] {
        include_bytes!("../fw/rtl8822e_radiob.bin")
    }

    /// Full PHY bring-up: BB/RF block enable, PHY_REG + AGC_TAB + RadioA/B
    /// table loads, crystal cap from EFUSE. Follow with
    /// [`set_channel_bw20`](Self::set_channel_bw20).
    pub fn phy_init(&self) -> Result<(), FaceError> {
        self.enable_bb_rf(true)?;

        let info = self.chip_info()?;
        let sel = HeadlineSel {
            cut: info.cut as u32,
            rfe: RFE_TYPE,
        };

        self.load_table(Self::table_phy_reg(), sel, &mut |s, a, d| {
            s.bb_cfg_write(a, d)
        })?;
        self.load_table(Self::table_agc_tab(), sel, &mut |s, a, d| {
            s.bb_cfg_write(a, d)
        })?;

        // Crystal cap from logical EFUSE 0x110 → 0x1040[23:10] = cap‖cap.
        let physical = self.efuse_dump_physical()?;
        let logical = Self::efuse_decode_logical(&physical)?;
        let cap = (logical[0x110] & 0x7f) as u32;
        self.bb_write(0x1040, 0x00ff_fc00, cap | (cap << 7))?;

        // RF init (kernel `_init_rf_reg`): cal-init table, then the RF tables.
        self.rf_cal_init()?;
        self.load_table(Self::table_radioa(), sel, &mut |s, a, d| {
            s.rf_cfg_write(RfPath::A, a, d)
        })?;
        self.load_table(Self::table_radiob(), sel, &mut |s, a, d| {
            s.rf_cfg_write(RfPath::B, a, d)
        })?;

        // RF calibration (kernel `halrf_init`): DACK is the first cal and is
        // channel-independent. The heavier cals (IQK/LCK/DPK/TSSI) are not yet
        // ported — see the module header.
        self.dack()
    }

    /// Bring up the BB transmit datapath. This is the on-air gate that the
    /// phydm/halrf init configures and our static phy_reg/agc tables do NOT —
    /// without it the MAC accepts and queues frames but the BB never modulates
    /// them onto air (proven end-to-end: a peer RTL8812EU in monitor mode
    /// decodes nothing until these registers are set, then decodes every frame).
    ///
    /// These 65 registers (BB pages `0x1800-0x1fff`: TXAGC, TX/RX filter, OFDM/
    /// CCK datapath, DIG) are the distinct final values the working kernel
    /// driver leaves after its full init, captured via usbmon and reduced from
    /// ~2000 calibration-churn writes to this minimal set (see
    /// `golden/opi-usbmon-2026-06-13/`). Order is the driver's first-touch order.
    ///
    /// Must run AFTER calibration (IQK/DPK), as the last BB step before TX. A
    /// few values (e.g. `0x18a0/0x18e8` TXAGC refs, `0x1b98`/`0x1d94`) are the
    /// reference device's calibration results; they radiate fine on other units
    /// but a per-device cal pass is the proper long-term fix (TODO).
    pub fn bb_tx_datapath_init(&self) -> Result<(), FaceError> {
        for &(addr, val) in BB_TX_DATAPATH_INIT {
            self.write32(addr, val)?;
        }
        Ok(())
    }

    /// Configure the receive path (path-B BB datapath + RF LNA / RX gain /
    /// mixer). The static radio tables leave it unset, so without this the chip
    /// demodulates nothing and delivers no frames on bulk-IN (verified: raw RX
    /// reads stay 0 until these 34 registers are written, then the chip receives
    /// ~94% of reads non-empty). Captured from the working kernel driver via
    /// usbmon; see [`RX_PATH_INIT`]. Run before the final `set_channel_bw20`,
    /// which re-tunes RF `0x18`.
    pub fn rx_path_init(&self) -> Result<(), FaceError> {
        for &(addr, val) in RX_PATH_INIT {
            self.write32(addr, val)?;
        }
        Ok(())
    }

    /// Diagnostic: force both RF paths to TX mode at the lowest gain index
    /// (= max power), the gain `single_tone` uses. Frame TX normally derives the
    /// RF gain from the TXAGC mapping; this probes whether that mapping is the
    /// ~12 dB TX-power deficit (if frames get stronger, the RF gain was the lever).
    pub fn force_max_tx_gain(&self) -> Result<(), FaceError> {
        for path in [RfPath::A, RfPath::B] {
            self.rf_write(path, 0x00, 0xf0000, 0x2)?; // TX mode
            self.rf_write(path, 0x00, 0x1f, 0x0)?; // lowest gain idx = max power
        }
        Ok(())
    }

    // ── BB/RF register primitives ────────────────────────────────────────────

    /// `odm_set_bb_reg`: masked 32-bit BB register write (plain write when the
    /// mask is full-width).
    fn bb_write(&self, addr: u16, mask: u32, data: u32) -> Result<(), FaceError> {
        if mask == 0xffff_ffff {
            return self.write32(addr, data);
        }
        let shift = mask.trailing_zeros();
        let v = self.read32(addr)?;
        self.write32(addr, (v & !mask) | ((data << shift) & mask))
    }

    /// `odm_get_bb_reg`: masked BB register read.
    fn bb_read(&self, addr: u16, mask: u32) -> Result<u32, FaceError> {
        let v = self.read32(addr)?;
        Ok((v & mask) >> mask.trailing_zeros())
    }

    /// `odm_config_bb_phy_8822e` (non-offload): delay markers 0xf9–0xfe,
    /// otherwise a full-width BB write.
    fn bb_cfg_write(&self, addr: u32, data: u32) -> Result<(), FaceError> {
        match addr {
            0xfe => std::thread::sleep(Duration::from_millis(50)),
            0xfd => std::thread::sleep(Duration::from_millis(5)),
            0xfc => std::thread::sleep(Duration::from_millis(1)),
            0xfb => std::thread::sleep(Duration::from_micros(50)),
            0xfa => std::thread::sleep(Duration::from_micros(5)),
            0xf9 => std::thread::sleep(Duration::from_micros(1)),
            _ => self.bb_write(addr as u16, 0xffff_ffff, data)?,
        }
        Ok(())
    }

    /// `config_phydm_write_rf_reg_8822e`: direct memory-mapped RF write
    /// through the BB window, except RF reg 0 (indirect via 0x1808/0x4108
    /// with addr[27:20] | data[19:0]). 20-bit registers; 1 µs settle.
    fn rf_write(&self, path: RfPath, reg: u32, mask: u32, data: u32) -> Result<(), FaceError> {
        const RFREG_MASK: u32 = 0xfffff;
        let mask = mask & RFREG_MASK;
        let reg = reg & 0xff;
        if reg != 0 {
            let direct = path.window() + ((reg as u16) << 2);
            self.bb_write(direct, mask, data)?;
            std::thread::sleep(Duration::from_micros(1));
            return Ok(());
        }
        let data = if mask != RFREG_MASK {
            let orig = self.rf_read(path, 0, RFREG_MASK)?;
            (orig & !mask) | ((data << mask.trailing_zeros()) & mask)
        } else {
            data
        };
        let indirect: u16 = match path {
            RfPath::A => 0x1808,
            RfPath::B => 0x4108,
        };
        self.write32(indirect, (data & RFREG_MASK) & 0x0fff_ffff)?; // reg 0 → addr field 0
        Ok(())
    }

    /// `config_phydm_read_rf_reg_8822e`: masked RF read via the BB window.
    pub fn rf_read(&self, path: RfPath, reg: u32, mask: u32) -> Result<u32, FaceError> {
        let direct = path.window() + (((reg & 0xff) as u16) << 2);
        self.bb_read(direct, mask & 0xfffff)
    }

    /// Diagnostic: public masked RF register write (see `rf_write`).
    pub fn rf_write_reg(
        &self,
        path: RfPath,
        reg: u32,
        mask: u32,
        data: u32,
    ) -> Result<(), FaceError> {
        self.rf_write(path, reg, mask, data)
    }

    /// `odm_config_rf_reg_8822e` (non-offload): table-stream RF write with the
    /// RF delay markers.
    fn rf_cfg_write(&self, path: RfPath, addr: u32, data: u32) -> Result<(), FaceError> {
        match addr {
            0xffe => std::thread::sleep(Duration::from_millis(50)),
            0xfe => std::thread::sleep(Duration::from_micros(100)),
            0xffff => std::thread::sleep(Duration::from_micros(1)),
            _ => self.rf_write(path, addr, 0xfffff, data)?,
        }
        Ok(())
    }

    /// Walk a phydm condition-encoded table (`halbb_sel_headline` + the
    /// IF/ELSE_IF/ELSE/END/CHK body loop), applying matched (addr, data)
    /// pairs through `write`.
    fn load_table(
        &self,
        blob: &[u8],
        sel: HeadlineSel,
        write: &mut dyn FnMut(&Self, u32, u32) -> Result<(), FaceError>,
    ) -> Result<(), FaceError> {
        const PARA_IF: u32 = 0x8;
        const PARA_ELSE_IF: u32 = 0x9;
        const PARA_ELSE: u32 = 0xa;
        const PARA_END: u32 = 0xb;
        const PARA_CHK: u32 = 0x4;

        let words: Vec<u32> = blob
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
            .collect();

        let (h_size, h_idx) = sel
            .select(&words)
            .ok_or_else(|| init_err("rtl88xx phy: no matching table headline".into()))?;
        let cfg_target = if h_size != 0 {
            words[h_idx << 1] & 0x0fff_ffff
        } else {
            0
        };

        let mut i = h_size;
        let mut cfg_para = 0u32;
        let mut is_matched = true;
        let mut find_target = false;
        while i + 1 < words.len() {
            let (v1, v2) = (words[i], words[i + 1]);
            i += 2;
            match v1 >> 28 {
                PARA_IF | PARA_ELSE_IF => cfg_para = v1 & 0x0fff_ffff,
                PARA_ELSE => {
                    is_matched = false;
                    if !find_target {
                        return Err(init_err("rtl88xx phy: table condition parse fail".into()));
                    }
                }
                PARA_END => {
                    is_matched = true;
                    find_target = false;
                }
                PARA_CHK => {
                    if find_target {
                        is_matched = false;
                    } else if cfg_para == cfg_target {
                        is_matched = true;
                        find_target = true;
                    } else {
                        is_matched = false;
                        find_target = false;
                    }
                }
                _ => {
                    if is_matched {
                        write(self, v1, v2)?;
                    }
                }
            }
        }
        Ok(())
    }

    // ── Channel / bandwidth (config_phydm_switch_channel_bw_8822e) ──────────

    /// Switch to 5 GHz channel `central_ch` at 20 MHz bandwidth — the port of
    /// `config_phydm_switch_channel_8822e` + `config_phydm_switch_bandwidth_
    /// 8822e` for the named-radio operating point (5 GHz-only injection on
    /// this dongle; ch161 = the testbed channel).
    pub fn set_channel_bw20(&self, central_ch: u8) -> Result<(), FaceError> {
        if central_ch <= 14 {
            return Err(init_err(
                "rtl88xx phy: 2.4 GHz path not ported (5 GHz only)".into(),
            ));
        }

        // ---- switch_channel ----
        let mut rf18 = self.rf_read(RfPath::A, 0x18, 0xfffff)?;
        rf18 &= !0x703ff;
        rf18 |= central_ch as u32; // channel
        rf18 |= (1 << 16) | (1 << 8); // 5 GHz
        if central_ch > 144 {
            rf18 |= 1 << 18; // 5G high sub-band (f > 5720)
        } else if central_ch >= 80 {
            rf18 |= 1 << 17;
        }
        self.rf_write(RfPath::A, 0x18, 0xfffff, rf18)?;
        self.rf_write(RfPath::B, 0x18, 0xfffff, rf18)?;
        self.rf_write(RfPath::A, 0xdf, 1 << 18, 0)?; // RxA enhance-Q: 5G

        // AGC table selection (5G low/mid/high bands; high for ch ≥ 149)
        let agc_tab: u32 = if central_ch < 80 {
            1 // OFDM_5G_LOW_BAND_8822E
        } else if central_ch <= 144 {
            2 // OFDM_5G_MID_BAND
        } else {
            3 // OFDM_5G_HIGH_BAND
        };
        self.ofdm_agc_tab_sel(agc_tab)?;

        // Clock-offset tracking fc (ch 120–172 → 0x412 band setting)
        let sco: u32 = match central_ch {
            16..=51 => 0x494,
            52..=55 => 0x493,
            56..=111 => 0x453,
            112..=119 => 0x452,
            120..=172 => 0x412,
            _ => 0x411,
        };
        self.bb_write(0xc30, 0xfff, sco)?;

        // TX DFIR (5 GHz)
        self.bb_write(0x808, 0x70, 0x3)?;

        // 5 GHz-only BB settings
        self.bb_write(0x1a80, 1 << 18, 1)?; // enable BB CCK check
        self.bb_write(0x454, 1 << 7, 1)?; // enable MAC CCK check
        // phydm_cck_rxiq_8822e(REVERT)
        self.bb_write(0x1a9c, 1 << 20, 0)?;
        self.bb_write(0x1a14, 0x300, 0x3)?;
        self.bb_write(0x1c80, 0x3f00_0000, 0x22)?; // CCA mask
        self.bb_write(0x818, 0x7c0_0000, 0xc)?; // Tx backoff OFDM
        self.bb_write(0x81c, 0x1f_c000, 0x4)?; // Tx scaling

        // 2-stream OFDM TX path (`phydm_config_ofdm_tx_path_8822e`, 2T2R): enable
        // 2SS across both paths (0x820[7:0]=0x31 = 2SS-AB | 1ss-A), 0x1e2c[15:0]=
        // 0x0400. Without this the BB only forms a single spatial stream, so HT
        // MCS8-15 / VHT-2SS frames are never modulated. The 1SS path nibble
        // (0x820[1:0]) is A-only by default, or **AB** when CSD is enabled
        // (`tx_csd`) — Cyclic Shift Diversity sends the single stream from both
        // antennas (the kernel's `tx_npath`: 1ss `txpath` = `BB_PATH_AB`).
        let ofdm_path = if self.tx_csd.load(Ordering::Relaxed) {
            0x33 // 1SS=AB (CSD) | 2SS=AB
        } else {
            0x31 // 1SS=A | 2SS=AB
        };
        self.bb_write(0x820, 0xff, ofdm_path)?;
        self.bb_write(0x1e2c, 0xffff, 0x0400)?;
        // RFE control (rfe_type 21, 5 GHz): path from BB TX/RX status regs.
        let tx = self.bb_read(0x820, 0xf)? | self.bb_read(0x820, 0xf0)?;
        let rx = self.bb_read(0x824, 0xf_0000)?;
        self.rfe_ctrl(tx as u8, rx as u8)?;

        self.tx_triangular_shaping_5g()?;
        self.spur_eliminate_bw20(central_ch)?;
        self.bb_reset()?;
        self.igi_toggle()?;

        // ---- switch_bandwidth (20 MHz) ----
        let mut rf18 = self.rf_read(RfPath::A, 0x18, 0xfffff)?;
        let mut rf1a = self.rf_read(RfPath::A, 0x1a, 0xfffff)?;
        rf18 &= !((1 << 13) | (1 << 12));
        rf1a &= !0x7c00;

        self.bb_write(0x810, 0x3ff0, 0x19b)?; // RX DFIR
        self.bb_write(0x9b0, 0xffc0, 0x0)?; // small BW off, pri ch 0
        self.bb_write(0x9b4, 0x700, 0x6)?; // DAC clock 480M
        self.bb_write(0x9b4, 0x70_0000, 0x6)?; // ADC clock 160M
        self.tx_triangular_shaping_5g()?;
        self.bb_write(0x9b0, 0xf, 0x0)?; // TX/RX RF BW 20M

        rf18 |= (1 << 13) | (1 << 12); // RF bandwidth 20M
        rf1a |= (1 << 11) | (1 << 10); // RF TXBB/RXBB

        self.bb_write(0xcbc, 1 << 21, 0)?; // pilot smoothing on
        self.bb_write(0x1abc, 1 << 30, 0)?; // CCK source 4
        self.bb_write(0x1ae8, 1 << 31, 1)?; // dynamic CCK PD th
        self.bb_write(0x1aec, 0xf, 0x6)?;
        self.bb_write(0x88c, 0xf000, 0x1)?; // subtune

        self.rf_write(RfPath::A, 0x18, 0xfffff, rf18)?;
        self.rf_write(RfPath::B, 0x18, 0xfffff, rf18)?;
        self.rf_write(RfPath::A, 0x1a, 0xfffff, rf1a)?;
        self.rf_write(RfPath::B, 0x1a, 0xfffff, rf1a)?;
        // TX_CCK_IND workaround (non-40 MHz)
        self.rf_write(RfPath::A, 0x1a, 1 << 0, 0)?;
        self.rf_write(RfPath::B, 0x1a, 1 << 0, 0)?;

        self.bb_reset()?;
        self.igi_toggle()?;
        // halrf_ex_dac_fifo_rst_8822e is compiled out (#if 0) upstream.
        self.cur_bw.store(ChannelBw::Bw20 as u8, Ordering::Relaxed);
        Ok(())
    }

    /// Tune to `primary_ch` at bandwidth `bw` — generalises
    /// [`set_channel_bw20`](Self::set_channel_bw20) to 40/80 MHz and the 5/10 MHz
    /// narrowband modes (`config_phydm_switch_channel_bw_8822e`). For a bonded
    /// channel the RF tunes to the block *centre* while the primary 20 MHz keeps
    /// its position; the TX descriptor's DATA_BW then follows. Call after
    /// [`bring_up`](Self::bring_up); both ends of the link must use the same
    /// width (and, for the narrowband modes, the same down-clock).
    pub fn set_channel(&self, primary_ch: u8, bw: ChannelBw) -> Result<(), FaceError> {
        let (center, pri_idx) = channel_geometry(primary_ch, bw);
        // Tune to the centre at the 20 MHz baseline (proven path), then switch
        // the bandwidth registers to the requested width.
        self.set_channel_bw20(center)?;
        if bw != ChannelBw::Bw20 {
            self.switch_bandwidth(pri_idx, bw)?;
        }
        self.cur_channel.store(primary_ch, Ordering::Relaxed);
        self.cur_bw.store(bw as u8, Ordering::Relaxed);
        Ok(())
    }

    /// Fast **same-bandwidth (20 MHz) channel retune** for frequency agility —
    /// rewrites only what actually changes per channel (the RF synthesizer
    /// `RF 0x18` on both paths, the 5 GHz AGC sub-band table *only when the band
    /// group changes*, the sample-clock-offset `0xc30`, and per-channel spur
    /// elimination), skipping the full datapath rebuild [`set_channel_bw20`] does
    /// (CCK/OFDM-path/RFE/Tx-shaping/`bb_reset` are channel-independent). A few
    /// register writes instead of dozens, so hops and CLM scans are much quicker.
    /// Requires a prior full [`set_channel`]/bring-up at 20 MHz to have laid down
    /// the datapath; no calibration is run. (DFS channels still require a
    /// regulatory CAC before *transmitting* — that dwell is law, not retune cost.)
    ///
    /// [`set_channel_bw20`]: Self::set_channel_bw20
    /// [`set_channel`]: Self::set_channel
    pub fn set_channel_fast(&self, central_ch: u8) -> Result<(), FaceError> {
        if central_ch <= 14 {
            return Err(init_err("rtl88xx phy: 2.4 GHz not ported (5 GHz only)".into()));
        }
        let band = |ch: u8| -> u8 {
            if ch < 80 {
                1
            } else if ch <= 144 {
                2
            } else {
                3
            }
        };
        let prev = self.cur_channel.load(Ordering::Relaxed);
        // RF synthesizer retune (both paths) — the actual channel change.
        let mut rf18 = self.rf_read(RfPath::A, 0x18, 0xfffff)?;
        rf18 &= !0x703ff;
        rf18 |= central_ch as u32;
        rf18 |= (1 << 16) | (1 << 8); // 5 GHz
        if central_ch > 144 {
            rf18 |= 1 << 18;
        } else if central_ch >= 80 {
            rf18 |= 1 << 17;
        }
        self.rf_write(RfPath::A, 0x18, 0xfffff, rf18)?;
        self.rf_write(RfPath::B, 0x18, 0xfffff, rf18)?;
        // AGC sub-band table only if the 5 GHz band group changed (the costly bit).
        if prev == 0 || band(central_ch) != band(prev) {
            self.ofdm_agc_tab_sel(band(central_ch) as u32)?;
        }
        // Sample-clock-offset tracking band + per-channel spur.
        let sco: u32 = match central_ch {
            16..=51 => 0x494,
            52..=55 => 0x493,
            56..=111 => 0x453,
            112..=119 => 0x452,
            120..=172 => 0x412,
            _ => 0x411,
        };
        self.bb_write(0xc30, 0xfff, sco)?;
        self.spur_eliminate_bw20(central_ch)?;
        self.cur_channel.store(central_ch, Ordering::Relaxed);
        Ok(())
    }

    /// `config_phydm_switch_bandwidth_8822e`: program the BB/RF bandwidth
    /// registers for `bw` with the primary-20 index `pri_ch` (1-based within the
    /// bonded block). Covers 20/40/80 MHz and the 5/10 MHz down-clocked
    /// narrowband modes; the RF analog path stays 20 MHz for narrowband (it is a
    /// BB down-clock). Run after the channel is tuned (it touches RF 0x18/0x1a).
    fn switch_bandwidth(&self, pri_ch: u32, bw: ChannelBw) -> Result<(), FaceError> {
        let mut rf18 = self.rf_read(RfPath::A, 0x18, 0xfffff)?;
        let mut rf1a = self.rf_read(RfPath::A, 0x1a, 0xfffff)?;
        rf18 &= !((1 << 13) | (1 << 12));
        rf1a &= !0x7c00;

        match bw {
            ChannelBw::Bw20 | ChannelBw::Nb10 | ChannelBw::Nb5 => {
                match bw {
                    ChannelBw::Nb5 | ChannelBw::Nb10 => {
                        // Down-clocked narrowband: 20 MHz-format frame at a 1/2
                        // (10 MHz) or 1/4 (5 MHz) symbol clock.
                        self.bb_write(0x810, 0x3ff0, 0x2ab)?; // narrowband RX DFIR
                        if bw == ChannelBw::Nb5 {
                            self.bb_write(0x9b0, 0xffc0, 0x1)?; // small BW = 5
                            // DAC clock: 0x4 (240M), NOT the 0x2 (120M) the 8822e
                            // phydm table specifies — the 120M setting leaves a
                            // strong DAC reconstruction image (mirror) that swamps
                            // the 5 MHz OFDM (SDR: ~30% out-of-band, demod can't
                            // lock). Running the DAC faster pushes the image away.
                            // Fix ported from the 8812cu/8822c driver (libc0607
                            // rtl88x2eu 5mhz_bw branch, 67dbbff1).
                            self.bb_write(0x9b4, 0x0000_0700, 0x4)?; // DAC 240M (was 120M)
                            self.bb_write(0x9b4, 0x0070_0000, 0x4)?; // ADC 40M
                        } else {
                            self.bb_write(0x9b0, 0xffc0, 0x2)?; // small BW = 10
                            self.bb_write(0x9b4, 0x0000_0700, 0x4)?; // DAC 240M
                            self.bb_write(0x9b4, 0x0070_0000, 0x5)?; // ADC 80M
                        }
                        // CFR para — the narrowband channel-frequency-response
                        // filter. Omitting 0x15/0x13 left 5 MHz undecodable.
                        self.bb_write(0xa74, 1 << 31, 0x0)?;
                        self.bb_write(0xa74, 0x3ff, 0x15)?;
                        self.bb_write(0xa74, 0xffc00, 0x13)?;
                        self.bb_write(0x808, 0x70, 0x1)?;
                        self.bb_write(0x80c, 0xf, 0x5)?;
                        // Narrowband TX triangular-shaping para (the BW20 path
                        // uses phydm_tx_triangular_shap_cfg instead).
                        self.bb_write(0x81c, 0xff, 0x0)?;
                        self.bb_write(0x81c, 0xf00_0000, 0x0)?;
                        self.bb_write(0x8a0, 0xf000_0000, 0x0)?;
                    }
                    _ => {
                        self.bb_write(0x810, 0x3ff0, 0x19b)?; // 20 MHz RX DFIR
                        self.bb_write(0x9b0, 0xffc0, 0x0)?;
                        self.bb_write(0x9b4, 0x0000_0700, 0x6)?; // DAC = 480M
                        self.bb_write(0x9b4, 0x0070_0000, 0x6)?; // ADC = 160M
                        self.tx_triangular_shaping_5g()?;
                    }
                }
                self.bb_write(0x9b0, 0xf, 0x0)?; // RF BW 20 (analog) for all three
                rf18 |= (1 << 13) | (1 << 12);
                rf1a |= (1 << 11) | (1 << 10);
                self.bb_write(0xcbc, 1 << 21, 0)?; // pilot smoothing on
                self.bb_write(0x1abc, 1 << 30, 0)?;
                self.bb_write(0x1ae8, 1 << 31, 1)?;
                self.bb_write(0x1aec, 0xf, 0x6)?;
                self.bb_write(0x88c, 0xf000, 0x1)?;
            }
            ChannelBw::Bw40 => {
                self.bb_write(0x9b0, 0xf, 0x5)?; // TX/RX RF BW 40
                self.bb_write(0x9b0, 0xc0, 0x0)?; // small BW off
                self.bb_write(0x9b0, 0xff00, pri_ch | (pri_ch << 4))?; // TX/RX pri ch
                rf18 |= 1 << 13;
                rf1a |= (1 << 12) | (1 << 11);
                self.bb_write(0xcbc, 1 << 21, 1)?; // pilot smoothing off
                self.bb_write(0x1abc, 1 << 30, 1)?;
                self.bb_write(0x1ae8, 1 << 31, 0)?;
                self.bb_write(0x1aec, 0xf, 0x8)?;
                self.bb_write(0x88c, 0xf000, 0x1)?;
                self.tx_triangular_shaping_5g()?;
            }
            ChannelBw::Bw80 => {
                self.bb_write(0x9b0, 0xf, 0xa)?; // TX/RX RF BW 80
                self.bb_write(0x9b0, 0xc0, 0x0)?;
                self.bb_write(0x9b0, 0xff00, pri_ch | (pri_ch << 4))?;
                rf18 |= 1 << 12;
                rf1a |= (1 << 13) | (1 << 10);
                self.bb_write(0xcbc, 1 << 21, 1)?;
                self.bb_write(0x88c, 0xf000, 0x6)?;
                self.tx_triangular_shaping_5g()?;
            }
        }

        self.rf_write(RfPath::A, 0x18, 0xfffff, rf18)?;
        self.rf_write(RfPath::B, 0x18, 0xfffff, rf18)?;
        self.rf_write(RfPath::A, 0x1a, 0xfffff, rf1a)?;
        self.rf_write(RfPath::B, 0x1a, 0xfffff, rf1a)?;
        if bw != ChannelBw::Bw40 {
            self.rf_write(RfPath::A, 0x1a, 1 << 0, 0)?; // TX_CCK_IND workaround
            self.rf_write(RfPath::B, 0x1a, 1 << 0, 0)?;
        }
        self.bb_reset()?;
        self.igi_toggle()
    }

    /// `phydm_ofdm_agc_tab_sel_8822e` (lower bound from the table default —
    /// the AGC load's 0x1d90 lower-bound capture is not tracked here).
    fn ofdm_agc_tab_sel(&self, table: u32) -> Result<(), FaceError> {
        const L_BND_DEFAULT: u32 = 0xd;
        self.bb_write(0x18ac, 0x1f0, table)?;
        self.bb_write(0x41ac, 0x1f0, table)?;
        self.bb_write(0x828, 0xf8, L_BND_DEFAULT)
    }

    /// `phydm_rfe_8822e` for rfe_type 21/22 on 5 GHz: select the RFE pin
    /// configuration by active TX/RX path.
    fn rfe_ctrl(&self, tx: u8, rx: u8) -> Result<(), FaceError> {
        let (r1840, r1844, r4140, r4144): (u32, u32, u32, u32) = if tx == 0x1 && rx == 0x1 {
            (0x0000_2000, 0x0000_3000, 0x7070_0000, 0x0000_0070) // path A
        } else if tx == 0x2 && rx == 0x2 {
            (0x0000_7000, 0x0000_7007, 0x0020_0000, 0x0000_0030) // path B
        } else {
            (0x0000_2000, 0x0000_3000, 0x0020_0000, 0x0000_0030) // path AB
        };
        self.bb_write(0x1840, 0xffff_ffff, r1840)?;
        self.bb_write(0x1844, 0xffff_ffff, r1844)?;
        self.bb_write(0x4140, 0xffff_ffff, r4140)?;
        self.bb_write(0x4144, 0xffff_ffff, r4144)
    }

    /// `_efem_pinmux_config` (`rtl8822e_halinit.c`): for an external-FEM board
    /// (RFE type 21–24, our BL-M8812EU2) route the FEM control signals
    /// `RFE_CTRL_{3,5,7,8,9,11}` (PA-enable / LNA-enable / TX-RX switch) onto
    /// GPIO pins 28–33 through the pinmux registers `REG_LED_CFG` (0x4c) and
    /// `REG_PAD_CTRL1` (0x64). The kernel does this via
    /// `rtw_halmac_rfe_ctrl_cfg(28..33)`; the generic MAC init alone leaves
    /// these pins on their default function so the FEM control floats and the
    /// FEM never switches to TX — the modulated output then only leaks through
    /// the FEM's RX path (~−86 dBm, ~30 dB switch isolation + no PA gain)
    /// instead of the PA (~−25 dBm), or never keys. The masked bits below are
    /// the exact delta from our post-MAC-init state to the kernel's golden
    /// values (`REG_LED_CFG 0x0062e282→0x0122e282`,
    /// `REG_PAD_CTRL1 0x3e241000→0x3c201000`; usbmon 2026-06-14).
    fn efem_pinmux_config(&self) -> Result<(), FaceError> {
        // REG_GPIO_MUXCFG (0x40): route the GPIO pin FUNCTIONS for the RFE/FEM
        // control signals. The kernel writes the full dword 0x1403020c here (usbmon
        // golden); our post-MAC-init state is 0x00000004, so the FEM-control GPIO
        // functions are never selected — LED_CFG/PAD_CTRL1 alone (below) enable the
        // pads but GPIO_MUXCFG decides what drives them. Missing this leaves the FEM
        // PA-enable/TX-RX-switch on their default function → the PA never keys for TX
        // while RX (no PA needed) still works — the RX-healthy/TX-dead signature.
        self.write32(0x0040, 0x1403_020c)?;
        // REG_LED_CFG: enable the RFE-control pin function (bit24), clear bit22.
        let led = (self.read32(0x004c)? & !(1 << 22)) | (1 << 24);
        self.write32(0x004c, led)?;
        // REG_PAD_CTRL1: restore the RFE-control pad ENABLE (bit28|bit29 —
        // asserted in pre_init_system_cfg but knocked out by a later BB step)
        // and clear bit25|bit18 → kernel golden 0x3c201000. Without bit29 the
        // FEM control pad is hi-Z, so PAPE/LNAON never reach the FEM → the FEM
        // sits in bypass/off (TX dead + RX ~18 dB down).
        let pad = (self.read32(0x0064)? & !((1 << 25) | (1 << 18))) | (1 << 28) | (1 << 29);
        self.write32(0x0064, pad)
    }

    /// `phydm_tx_triangular_shap_cfg_8822e` (5 GHz flavour).
    fn tx_triangular_shaping_5g(&self) -> Result<(), FaceError> {
        self.bb_write(0xa74, 1 << 31, 0x1)?;
        self.bb_write(0x808, 0x70, 0x3)?;
        self.bb_write(0xa74, 0x3ff, 0x3f)?;
        self.bb_write(0xa74, 0xf_fc00, 0x3f)?;
        self.bb_write(0x80c, 0xf, 0x8)?;
        self.bb_write(0x81c, 0xff, 0x55)?;
        self.bb_write(0x81c, 0xf00_0000, 0x7)?;
        self.bb_write(0x8a0, 0xf000_0000, 0x0)
    }

    /// `phydm_spur_eliminate_8822e` (20 MHz): channels 153/161/169 have a
    /// 5760/5800 MHz spur — notch it with a manual NBI + CSI mask.
    fn spur_eliminate_bw20(&self, central_ch: u8) -> Result<(), FaceError> {
        // set_auto_nbi(false)
        self.bb_write(0x818, 1 << 3, 0)?;
        self.bb_write(0x1d3c, 0x7800_0000, 0)?;
        // csi_mask_enable(true)
        self.bb_write(0xc0c, 1 << 3, 1)?;

        if !matches!(central_ch, 153 | 161 | 169) {
            // No spur on this channel: disable manual NBI + clear the mask.
            self.clean_csi_mask()?;
            self.bb_write(0x1944, 0x1f_f000, 0)?;
            self.bb_write(0x4044, 0x1f_f000, 0)?;
            self.bb_write(0x1940, 1 << 31, 0)?;
            self.bb_write(0x4040, 1 << 31, 0)?;
            self.bb_write(0x818, 1 << 11, 0)?;
            self.bb_write(0x1d3c, 0x7800_0000, 0)?;
            return Ok(());
        }

        self.clean_csi_mask()?;
        // manual NBI at tone 112 (the spur)
        self.bb_write(0x1944, 0x1f_f000, 112)?;
        self.bb_write(0x4044, 0x1f_f000, 112)?;
        self.bb_write(0x1940, 1 << 31, 1)?;
        self.bb_write(0x4040, 1 << 31, 1)?;
        self.bb_write(0x818, 1 << 11, 1)?;
        self.bb_write(0x1d3c, 0x7800_0000, 0xf)?;
        // nbi_wa_para(true, BW20)
        self.bb_write(0x810, 0xf, 0x7)?;
        self.bb_write(0x810, 0xf_0000, 0x7)?;
        self.bb_write(0x88c, 0x3_0000, 0x3)?;
        self.bb_write(0x1944, 0x300, 0x3)?;
        self.bb_write(0x4044, 0x300, 0x3)?;
        // CSI mask: tone 112 weight 0xa (ch153 also masks 111/113)
        if central_ch == 153 {
            self.set_csi_mask(111, 0xa)?;
        }
        self.set_csi_mask(112, 0xa)?;
        if central_ch == 153 {
            self.set_csi_mask(113, 0xa)?;
        }
        // packet-detection threshold tweak
        self.bb_write(0xc24, 0xffff, 0x60e0)
    }

    /// `phydm_clean_specific_csi_mask_8822e`.
    fn clean_csi_mask(&self) -> Result<(), FaceError> {
        self.bb_write(0x1ee8, 0x3, 0x3)?;
        self.bb_write(0x1d94, (1 << 31) | (1 << 30), 0x1)?;
        for tone in [7u32, 8, 16, 55, 56, 103, 104, 112] {
            self.bb_write(0x1d94, 0xff_0000, tone)?;
            self.bb_write(0x1d94, 0xff, 0x0)?;
        }
        self.bb_write(0x1ee8, 0x3, 0x0)
    }

    /// `phydm_set_csi_mask_8822e`.
    fn set_csi_mask(&self, tone_idx: u32, weight: u32) -> Result<(), FaceError> {
        self.bb_write(0x1ee8, 0x3, 0x3)?;
        self.bb_write(0x1d94, (1 << 31) | (1 << 30), 0x1)?;
        self.bb_write(0x1d94, 0xff_0000, (tone_idx >> 1) & 0xff)?;
        if tone_idx & 1 != 0 {
            self.bb_write(0x1d94, 0xf0, weight)?;
        } else {
            self.bb_write(0x1d94, 0xf, weight)?;
        }
        self.bb_write(0x1ee8, 0x3, 0x0)
    }

    /// `phydm_bb_reset_8822e`: pulse `FEN_BBRSTB` (MAC reg 0x00 bit 16).
    fn bb_reset(&self) -> Result<(), FaceError> {
        self.set8(REG_SYS_FUNC_EN, 1 << 0)?;
        self.clr8(REG_SYS_FUNC_EN, 1 << 0)?;
        self.set8(REG_SYS_FUNC_EN, 1 << 0)
    }

    /// `phydm_igi_toggle_8822e`: nudge the IGI so the BB resends the 3-wire
    /// command and the RF enters RX mode after path/channel/BW changes.
    fn igi_toggle(&self) -> Result<(), FaceError> {
        let v = self.read32(0x1d70)?;
        self.write32(0x1d70, v.wrapping_sub(0x202))?;
        self.write32(0x1d70, v)
    }

    // ── RF calibration (halrf_8822e) — partial: cal-init table + DACK ───────
    //
    // The kernel's RF init (`_init_rf_reg` → `rtw_phydm_init`/`halrf_init`)
    // loads a calibration-setup table then runs a chain of analog calibrations
    // (DACK, RCK, RX-DCK, IQK, LCK, DPK, TSSI, TXGAPK). Without them the analog
    // TX chain does not radiate even with every digital register matching
    // golden. This ports the deterministic cal-init table and **DACK** (DAC/ADC
    // DC-offset calibration) — the first calibration in the chain. The heavier
    // cals (IQK/LCK/DPK/TSSI) are not yet ported; see the module header.

    /// The `array_mp_8822e_cal_init` calibration-setup table — straight
    /// `(addr, data)` BB pairs (not condition-encoded), preceded by the four
    /// IQK PHY-setting writes from `odm_read_and_config_mp_8822e_cal_init`.
    fn table_cal_init() -> &'static [u8] {
        include_bytes!("../fw/rtl8822e_cal_init.bin")
    }

    /// Load the cal-init table (part of the kernel's `_init_rf_reg`, before the
    /// RadioA/B tables). Deterministic register writes that arm the cal blocks.
    fn rf_cal_init(&self) -> Result<(), FaceError> {
        // 00_8822E_IQK_Phy_setting
        self.bb_write(0x1cd0, 0xf000_0000, 0x7)?;
        self.bb_write(0x1e24, 0x0002_0000, 0x1)?;
        self.bb_write(0x180c, 0x8000_0000, 0x1)?;
        self.bb_write(0x410c, 0x8000_0000, 0x1)?;
        let tbl = Self::table_cal_init();
        for pair in tbl.chunks_exact(8) {
            let addr = u32::from_le_bytes(pair[0..4].try_into().unwrap());
            let data = u32::from_le_bytes(pair[4..8].try_into().unwrap());
            self.bb_cfg_write(addr, data)?;
        }
        Ok(())
    }

    /// **DACK** — DAC/ADC DC-offset calibration (`halrf_dac_cal_8822e`): run
    /// ADDCK (ADC DC) then the DAC MSB/offset calibration for both spatial
    /// paths, retrying up to 10× on `dack_checkfail`, then latch the result.
    /// Corrects the converter DC offsets; runs after the RF tables, before the
    /// channel switch (it is channel-independent).
    pub fn dack(&self) -> Result<(), FaceError> {
        let mut dack = DackState::default();
        self.addck_s0(&mut dack)?;
        self.addck_s1(&mut dack)?;
        self.dack_reset()?;
        self.dack_val(false)?;
        self.dack_run(&mut dack)?;
        for _ in 0..10 {
            if !self.dack_checkfail()? {
                break;
            }
            self.dack_reset()?;
            self.dack_val(false)?;
            self.dack_run(&mut dack)?;
        }
        self.dack_val(true)
    }

    /// `halrf_wdack_8822e`: a BB write issued twice (the AFE digital block
    /// requires even-count writes to latch).
    fn wdack(&self, addr: u16, mask: u32, data: u32) -> Result<(), FaceError> {
        self.bb_write(addr, mask, data)?;
        self.bb_write(addr, mask, data)
    }

    /// `halrf_check_addc_8822e`: average-sample the SAR ADC and read back the
    /// I/Q DC codes into `addc[path]`.
    fn check_addc(&self, dack: &mut DackState, path: usize) -> Result<(), FaceError> {
        let off = if path == 0 { 0u16 } else { 0x100 };
        self.wdack(0x381c + off, 0x60000, 0x3)?;
        self.wdack(0x381c + off, 1 << 16, 0x0)?;
        self.wdack(0x381c + off, 1 << 16, 0x1)?;
        self.wdack(0x381c + off, 1 << 16, 0x1)?;
        for _ in 0..300 {
            if self.bb_read(0x3878 + off, 1 << 12)? != 0
                && self.bb_read(0x38a8 + off, 1 << 12)? != 0
            {
                break;
            }
        }
        dack.addc[path][0] = self.bb_read(0x3878 + off, 0xfff)? as u16;
        dack.addc[path][1] = self.bb_read(0x38a8 + off, 0xfff)? as u16;
        Ok(())
    }

    /// `halrf_addck_s0_8822e` / `_s1`: ADC DC-offset calibration for a path.
    fn addck(&self, dack: &mut DackState, path: usize) -> Result<(), FaceError> {
        let (r30, r60, r10, r68) = if path == 0 {
            (0x1830u16, 0x1860u16, 0x1810u16, 0x1868u16)
        } else {
            (0x4130, 0x4160, 0x4110, 0x4168)
        };
        self.bb_write(r30, 1 << 30, 0)?;
        self.bb_write(r60, 0xf000_0000, 0xf)?;
        self.bb_write(r60, 1 << 26, 0)?;
        self.bb_write(r60, 1 << 12, 0)?; // ADC input short
        self.bb_write(r10, 1 << 19, 1)?;
        self.check_addc(dack, path)?;
        let ic = 0x800u32.wrapping_sub(dack.addc[path][0] as u32);
        let qc = 0x800u32.wrapping_sub(dack.addc[path][1] as u32);
        self.write32(r68, (ic & 0x3ff) | ((qc & 0x3ff) << 10))?;
        self.bb_write(r10, 1 << 19, 0)?;
        self.bb_write(r60, 1 << 12, 1)?;
        self.bb_write(r30, 1 << 30, 1)
    }

    fn addck_s0(&self, dack: &mut DackState) -> Result<(), FaceError> {
        self.addck(dack, 0)
    }
    fn addck_s1(&self, dack: &mut DackState) -> Result<(), FaceError> {
        self.addck(dack, 1)
    }

    /// `halrf_dack_reset_8822e`: pulse the DACK reset on both paths.
    fn dack_reset(&self) -> Result<(), FaceError> {
        for r in [0x1818u16, 0x4118] {
            self.bb_write(r, 1 << 25, 0)?;
            self.bb_write(r, 1 << 25, 1)?;
            std::thread::sleep(Duration::from_millis(1));
        }
        Ok(())
    }

    /// `halrf_dack_val_8822e`: select DACK result source (1 = from registers).
    fn dack_val(&self, from_reg: bool) -> Result<(), FaceError> {
        let v = from_reg as u32;
        for r in [0x38d0u16, 0x38e4, 0x39d0, 0x39e4] {
            self.wdack(r, 1 << 0, v)?;
        }
        Ok(())
    }

    /// `halrf_dac_fifo_reset_8822e`: toggle the DAC FIFO reset bits (needs the
    /// DAC clock running).
    fn dac_fifo_reset(&self) -> Result<(), FaceError> {
        for r in [0x3800u16, 0x382c, 0x3900, 0x392c] {
            self.bb_write(r, 1 << 21, 0)?;
            self.bb_write(r, 1 << 21, 1)?;
        }
        Ok(())
    }

    /// `halrf_dack_8822e` (both paths). Per path: 160 MHz cal clock, enable
    /// DAC + comparator, MSB-bias seed, FIFO reset, run auto MSB calibration
    /// then DC-offset calibration (poll done bits), back up the MSBK codes,
    /// reload them, restore the normal clock.
    fn dack_run(&self, dack: &mut DackState) -> Result<(), FaceError> {
        self.dack_path(dack, 0)?;
        self.dack_path(dack, 1)
    }

    fn dack_path(&self, dack: &mut DackState, path: usize) -> Result<(), FaceError> {
        // Per-path register bases (S0 vs S1).
        let (r30, r60, r10, r18) = if path == 0 {
            (0x1830u16, 0x1860u16, 0x1810u16, 0x1818u16)
        } else {
            (0x4130, 0x4160, 0x4110, 0x4118)
        };
        // AFE-digital bases for this path's I/Q comparators.
        let b = if path == 0 { 0x3800u16 } else { 0x3900 };
        let bq = b + 0x2c; // I block + 0x2c = Q block

        let saved_9b4 = self.read32(0x09b4)?;
        self.bb_write(0x09b4, 0x1ff00, 0xdb)?; // 160 MHz cal clock
        self.bb_write(r30, 1 << 30, 0)?;
        self.bb_write(r60, 1 << 30, 1)?;
        self.bb_write(r60, 1 << 27, 0)?;
        self.bb_write(r10, 1 << 15, 1)?; // enable comparator
        self.bb_write(r18, 0x0c00_0000, 0x3)?; // DAC gain (cal mode)
        self.wdack(b + 0x04, 0x3ff0_0000, 0x58)?; // MSB bias seed (I)
        self.wdack(bq + 0x04, 0x3ff0_0000, 0x58)?; // MSB bias seed (Q)
        self.dac_fifo_reset()?;
        self.wdack(b + 0x0c, 1 << 1, 0)?; // hold DC-offset cal
        self.wdack(b + 0x04, 1 << 0, 1)?; // auto mode

        // Wait MSB calibration done (I ready @ b+0x5c[1], Q @ bq+0x5c[1]).
        for _ in 0..300 {
            if self.bb_read(b + 0x5c, 1 << 1)? != 0 && self.bb_read(bq + 0x5c, 1 << 1)? != 0 {
                break;
            }
        }
        self.bb_write(r18, 0x0c00_0000, 0x0)?; // DAC gain (normal)
        self.wdack(b + 0x0c, 1 << 1, 1)?; // enable DC-offset cal
        // Wait DC-offset cal done (I @ b+0x70[2], Q @ bq+0x70[2]).
        for _ in 0..300 {
            if self.bb_read(b + 0x70, 1 << 2)? != 0 && self.bb_read(bq + 0x70, 1 << 2)? != 0 {
                break;
            }
        }
        self.wdack(b + 0x04, 1 << 0, 0)?; // disable auto mode
        self.bb_write(r10, 1 << 15, 0)?; // disable comparator

        self.dack_backup(dack, path)?;
        self.dack_reload(dack, path)?;

        self.write32(0x09b4, saved_9b4)?; // restore normal clock
        self.dac_fifo_reset()?;
        self.bb_write(r30, 1 << 30, 1)?;
        Ok(())
    }

    /// `halrf_dack_backup_s0/s1_8822e`: read the 16 calibrated MSBK codes (I
    /// and Q), the bias-K, and the DA DC-offset for this path.
    fn dack_backup(&self, dack: &mut DackState, path: usize) -> Result<(), FaceError> {
        let b = if path == 0 { 0x3800u16 } else { 0x3900 };
        let bq = b + 0x2c;
        for i in 0..16u32 {
            self.wdack(b, 0x1e, i)?;
            dack.msbk[path][0][i as usize] = (self.bb_read(b + 0x70, 0xff00_0000)?) as u8;
            self.wdack(bq, 0x1e, i)?;
            dack.msbk[path][1][i as usize] = (self.bb_read(bq + 0x70, 0xff00_0000)?) as u8;
        }
        dack.biask[path] = self.bb_read(b + 0x78, 0xffc0_0000)? as u16;
        dack.dadck[path][0] = self.bb_read(b + 0x74, 0xff00_0000)? as u8;
        dack.dadck[path][1] = self.bb_read(bq + 0x74, 0xff00_0000)? as u8;
        Ok(())
    }

    /// `halrf_dack_reload_8822e` → `_by_path` for both index banks: write the
    /// backed-up MSBK/bias/DC codes into the normal-mode result registers.
    fn dack_reload(&self, dack: &mut DackState, path: usize) -> Result<(), FaceError> {
        for index in 0..2usize {
            let path_off = if path == 0 { 0u16 } else { 0x100 };
            let idx_off = if index == 0 { 0u16 } else { 0x14 };
            let base = 0x38c0 + idx_off + path_off;
            // MSBK groups 15..12, 11..8, 7..4, 3..0 packed 4 codes/dword.
            for (k, reg) in [base, base + 4, base + 8, base + 0xc].iter().enumerate() {
                let start = 12 - k * 4;
                let mut temp = 0u32;
                for i in 0..4 {
                    temp |= (dack.msbk[path][index][start + i] as u32) << (i * 8);
                }
                self.wdack(*reg, 0xffff_ffff, temp)?;
            }
            let temp = ((dack.biask[path] as u32) << 16) | ((dack.dadck[path][index] as u32) << 8);
            self.wdack(base + 0x10, 0xffff_ffff, temp)?;
        }
        Ok(())
    }

    /// `halrf_dack_checkfail_8822e`: the DACK-OK status bits (0x3800/0x3900[17]).
    fn dack_checkfail(&self) -> Result<bool, FaceError> {
        Ok(self.bb_read(0x3800, 1 << 17)? == 0 || self.bb_read(0x3900, 1 << 17)? == 0)
    }

    // ── Firmware RF calibration (IQK / DPK via H2C) ─────────────────────────
    //
    // The 8822E firmware runs IQK and DPK internally — the driver just sends a
    // one-byte H2C and polls a done flag. This is the offload path the OPi
    // kernel driver uses by default (`rtw_iqk_fw_offload = 1`), and it sidesteps
    // porting the ~2K-line driver-side calibration loops. Channel-dependent, so
    // run after [`set_channel_bw20`](Self::set_channel_bw20).

    /// Trigger **firmware IQK** (`halmac_start_iqk` → `_check_fwiqk_done_8822e`):
    /// send the IQK H2C (sub-cmd 0x0E; `clear`/`segment` flags) and poll BB
    /// `0x2D9C` until the firmware writes `0xAA`, then the post-IQK cleanup.
    pub fn fw_iqk(&self, clear: bool, segment: bool) -> Result<(), FaceError> {
        const SUB_IQK: u16 = 0x0e;
        // Send the IQK H2C and poll the firmware's done flag (BB 0x2D9C == 0xAA,
        // `_check_fwiqk_done_8822e`). Some fw builds report completion only via
        // the C2H IQK_ACK packet and never raise this register flag, so a
        // timeout is logged, not a hard error — but retry once first, since a
        // genuinely-dropped IQK leaves the TX mixer uncalibrated.
        let send_and_poll = |attempt: u32| -> Result<bool, FaceError> {
            let mut h2c = [0u8; 32];
            h2c_hdr(&mut h2c, SUB_IQK, 1, 1);
            txdesc_set(&mut h2c, 0x08, 0, 1, clear as u32);
            txdesc_set(&mut h2c, 0x08, 1, 1, segment as u32);
            self.send_h2c(&h2c)?;
            for _ in 0..300 {
                if self.read8(0x2d9c)? == 0xaa {
                    return Ok(true);
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            tracing::debug!(attempt, "FW IQK done flag (0x2d9c) not raised within 300ms");
            Ok(false)
        };
        let mut done = send_and_poll(0)?;
        if !done {
            done = send_and_poll(1)?;
        }
        if done {
            tracing::debug!("FW IQK completed (0x2d9c=0xaa)");
        } else {
            tracing::warn!(
                "FW IQK did not raise its register done-flag after a retry; the \
                 firmware may report only via C2H, or the TX mixer is uncalibrated"
            );
        }
        // Post-IQK cleanup (the firmware leaves the NCTL page selected).
        self.bb_write(0x1b00, 0x0000_0006, 0x1)?;
        self.write8(0x1b10, 0x0)?;
        self.bb_write(0x1b00, 0x0000_0006, 0x0)?;
        self.write8(0x1b10, 0x0)?;
        Ok(())
    }

    /// Trigger **firmware DPK** (`start_dpk_88xx`): send the DPK H2C (sub-cmd
    /// 0xB7) and wait for it to settle. PA digital pre-distortion; requires the
    /// fw H2C version ≥ 15 (the v1.27 NIC firmware qualifies).
    pub fn fw_dpk(&self) -> Result<(), FaceError> {
        const SUB_DPK: u16 = 0xb7;
        let mut h2c = [0u8; 32];
        h2c_hdr(&mut h2c, SUB_DPK, 1, 1);
        self.send_h2c(&h2c)?;
        // DPK has no simple BB done-flag like IQK; the firmware takes ~tens of
        // ms. Give it a settle window (the kernel waits on a C2H ack event).
        std::thread::sleep(Duration::from_millis(100));
        Ok(())
    }

    /// **LCK** (`phy_lc_calibrate_8822e`) — the 8822E LO calibration the kernel
    /// runs (`HAL_RF_LCK`): an AAC and an RT calibration, each a trigger-then-
    /// poll on path A. Calibrates the LO; we previously skipped it.
    pub fn lck(&self) -> Result<(), FaceError> {
        // AACK: toggle RF 0xca[0], poll RF 0xc9[5] until it clears.
        self.rf_write(RfPath::A, 0xca, 1 << 0, 0x0)?;
        self.rf_write(RfPath::A, 0xca, 1 << 0, 0x1)?;
        for _ in 0..100 {
            std::thread::sleep(Duration::from_millis(1));
            if self.rf_read(RfPath::A, 0xc9, 1 << 5)? != 0x1 {
                break;
            }
        }
        // RTK: toggle RF 0xcc[18], poll RF 0xce[11] until it clears, then clear.
        self.rf_write(RfPath::A, 0xcc, 1 << 18, 0x0)?;
        self.rf_write(RfPath::A, 0xcc, 1 << 18, 0x1)?;
        for _ in 0..100 {
            std::thread::sleep(Duration::from_millis(1));
            if self.rf_read(RfPath::A, 0xce, 1 << 11)? != 0x1 {
                break;
            }
        }
        self.rf_write(RfPath::A, 0xcc, 1 << 18, 0x0)
    }

    /// `_dpk_force_bypass_8822e`: put both paths' DPK into bypass mode. This is
    /// exactly what the kernel `do_dpk_8822e` does for RFE type 21/22 (our
    /// dongles) — it skips the full DPK calibration and force-bypasses it, so a
    /// faithful bring-up sets the same known DPK state rather than leaving it
    /// at the table default.
    pub fn dpk_force_bypass(&self) -> Result<(), FaceError> {
        self.bb_write(0x1b00, 0x0000_0006, 0x2)?; // subpage 2
        self.bb_write(0x1b08, (1 << 15) | (1 << 14), 0x3)?; // S0 bypass
        self.bb_write(0x1b04, 0x0000_00ff, 0x5b)?;
        self.bb_write(0x1b60, (1 << 15) | (1 << 14), 0x3)?; // S1 bypass
        self.bb_write(0x1b5c, 0x0000_00ff, 0x5b)?;
        self.bb_write(0x1b00, 0x0000_0006, 0x0) // subpage 0
    }

    /// **kfree** — apply the factory power/thermal/PA-bias trim from EFUSE
    /// (`phydm_do_new_kfree` → the three `*_8822e` helpers). These are the
    /// per-device TX calibration offsets the kernel programs in `halrf_init`
    /// that the userspace port skipped: thermal-K reference (RF 0x43), the
    /// per-gain-index power trim (RF gain table, BIT19 page), and the PA bias
    /// (RF 0x60). Reads the raw physical EFUSE `PPG_*` cells (0x5xx); unburned
    /// cells (`0xff`) are skipped exactly as the driver does. Run before
    /// [`txgapk`](Self::txgapk) so the gain-K correction sits on the trimmed base.
    pub fn kfree(&self) -> Result<(), FaceError> {
        let p = self.efuse_dump_physical()?;
        let at = |a: usize| p.get(a).copied().unwrap_or(0xff);

        // ── Thermal trim (RF 0x43[19:16]), gated on the path-A cell. ──
        let therm_a = at(0x5df);
        if therm_a != 0xff {
            let pack = |t: u8| -> u32 {
                let t = (t & 0x1f) as u32;
                ((t & 0x1) << 3) | ((t >> 1) & 0x7)
            };
            self.rf_write(RfPath::A, 0x43, 0x000f_0000, pack(therm_a))?;
            self.rf_write(RfPath::B, 0x43, 0x000f_0000, pack(at(0x5a0)))?;
        }

        // ── Power trim → per-gain-index RF gain table (BIT19 page). ──
        // gated if any of the 2G/5G-L1 cells are burned.
        let gate = [0x5c4, 0x5de, 0x5c2, 0x5dc, 0x5db]
            .iter()
            .any(|&a| at(a) != 0xff);
        if gate {
            // Unburned (0xff) cells read as 0, matching the driver.
            let m5 = |a: usize| -> u32 {
                let v = at(a);
                let v = if v == 0xff { 0 } else { v };
                (v & 0x1f) as u32
            };
            // bb_gain[idx][path]; 2G entries 0..2 all read PPG_2GM (0x5de).
            let g2 = if at(0x5de) == 0xff {
                0u32
            } else {
                at(0x5de) as u32
            };
            let bb_gain: [[u32; 2]; 8] = [
                [g2 & 0xf, (g2 & 0xf0) >> 4],
                [g2 & 0xf, (g2 & 0xf0) >> 4],
                [g2 & 0xf, (g2 & 0xf0) >> 4],
                [m5(0x5dc), m5(0x5db)], // 5G L1
                [m5(0x5d8), m5(0x5d7)], // 5G L2
                [m5(0x5d4), m5(0x5d3)], // 5G M1
                [m5(0x5d0), m5(0x5cf)], // 5G M2
                [m5(0x5cc), m5(0x5cb)], // 5G H1
            ];
            // RF 0x33 index -> bb_gain row, matching the driver's write order.
            let idx_map: [usize; 15] = [0, 1, 2, 2, 3, 4, 5, 6, 7, 3, 4, 5, 6, 7, 7];
            for path_idx in 0..2usize {
                let path = RF_PATHS[path_idx];
                self.rf_write(path, 0xee, 1 << 19, 1)?;
                for (idx, &row) in idx_map.iter().enumerate() {
                    self.rf_write(path, 0x33, 0xfffff, idx as u32)?;
                    self.rf_write(path, 0x3f, 0xfffff, bb_gain[row][path_idx])?;
                }
                self.rf_write(path, 0xee, 1 << 19, 0)?;
            }
        }

        // ── PA bias (RF 0x60), gated on the 2G-A cell. ──
        if at(0x5c6) != 0xff {
            self.rf_write(RfPath::A, 0x60, 0x0000_f000, (at(0x5c6) & 0xf) as u32)?; // 2G s0
            self.rf_write(RfPath::B, 0x60, 0x0000_f000, (at(0x5c5) & 0xf) as u32)?; // 2G s1
            self.rf_write(RfPath::A, 0x60, 0x000f_0000, (at(0x5c8) & 0xf) as u32)?; // 5G s0
            self.rf_write(RfPath::B, 0x60, 0x000f_0000, (at(0x5c7) & 0xf) as u32)?; // 5G s1
        }
        Ok(())
    }

    /// Set the TX-AGC reference power index (`config_phydm_write_txagc_ref_
    /// 8822e` for OFDM + CCK, both paths). **First clears `0x1c90` bit 15** —
    /// the "bbrstb TX-AGC report" bit that write-protects the TXAGC table; with
    /// it set, writes to the power-reference registers (`0x18e8`/`0x41e8` OFDM,
    /// `0x18a0`/`0x41a0` CCK) are ignored by the BB. `idx` is a 0–0x3f power
    /// index (higher = more TX power). Per-rate diffs in the `0x3a00` table are
    /// left at 0, so every rate transmits at this reference power.
    pub fn set_tx_power(&self, idx: u32) -> Result<(), FaceError> {
        if self.bb_read(0x1c90, 1 << 15)? != 0 {
            self.bb_write(0x1c90, 1 << 15, 0)?; // enable TXAGC table writes
        }
        self.bb_write(0x18e8, 0x0001_fc00, idx)?; // OFDM ref, path A
        self.bb_write(0x41e8, 0x0001_fc00, idx)?; // OFDM ref, path B
        self.bb_write(0x18a0, 0x007f_0000, idx)?; // CCK ref, path A
        self.bb_write(0x41a0, 0x007f_0000, idx)?; // CCK ref, path B
        Ok(())
    }

    /// **Per-device TX-power calibration** — a port of the halrf power-by-rate
    /// → per-rate TXAGC flow (`config_phydm_write_txagc_ref/diff_8822e`), using
    /// *this dongle's own* EFUSE rather than the reference unit's captured BB
    /// values that `bb_tx_datapath_init` bakes in.
    ///
    /// 1. Read the 5 GHz base power index for the channel's sub-band, per path,
    ///    from the logical EFUSE (`0x22`/`0x4c`, one byte per band group).
    /// 2. Clear the `0x1c90[15]` TXAGC write-protect, then write the OFDM
    ///    (`0x18e8`/`0x41e8`, mask `0x1fc00`) and CCK (`0x18a0`/`0x41a0`, mask
    ///    `0x7f0000`) power *references* from the per-path base.
    /// 3. Write the per-rate *diff* table (`0x3a00 + hw_rate`) — the small
    ///    OFDM/HT/2SS corrections the working driver applies (OFDM `+2`, HT 1SS
    ///    `0`, 2SS `-4`); `hw_rate` indexes the byte: `0x3a00+(rate&0xfc)`,
    ///    byte `rate&3`.
    ///
    /// Note on rate headroom: the EFUSE per-rate diffs are small (±4), so they
    /// do **not** back the higher-order rates off for PA linearity — the working
    /// driver relies on DPK to linearise the PA, and our DPK port is partial.
    /// In practice this link delivers MCS0–2 at full power and MCS3–4 only with
    /// manual backoff (`RADIO_TXPWR`); MCS6+ is EVM/SNR-limited at short range.
    /// For a broadcast face the robust low rates are the correct operating point.
    /// Returns `(base_path_a, base_path_b)` for logging.
    pub fn calibrate_tx_power(&self, channel: u8) -> Result<(u8, u8), FaceError> {
        self.write_txagc(channel)
    }

    /// **Per-rate TX power** — a faithful port of the 8822E
    /// `config_phydm_set_txagc_to_hw` flow. The kernel computes a TX power index
    /// per rate from the factory **power-by-rate** table (`phy_reg_pg`) anchored
    /// to the channel's EFUSE base, then programs the BB as a per-path OFDM/CCK
    /// **reference** (`0x18e8`/`0x18a0`) plus per-rate **diffs** from that
    /// reference (`0x3a00`). This replaces the earlier hand-tuned 0x3a00 backoff
    /// with the chip's designed power-by-rate curve — the solid foundation for
    /// rate adaptation. (Requires [`btc_grant_wl`](Self::btc_grant_wl) for the
    /// power to actually reach air.) Returns `(base_a, base_b)` for logging.
    pub fn write_txagc(&self, channel: u8) -> Result<(u8, u8), FaceError> {
        // 8822E 5 GHz power-by-rate (`array_mp_8822e_phy_reg_pg`, both paths
        // equal) as TX power indices, for *every* rate section. Each byte is
        // `(power-by-rate index, rate-section, ntx)`; sections OFDM=1 HT=2 VHT=3,
        // ntx 1T=0 2T=1. The factory curve tapers high-order rates down for PA
        // linearity. Mapped onto the per-rate TXAGC table at 0x3a00 + (ODM rate
        // & 0xfc): HT MCS0-15 = 0x0c..0x1b, VHT 1SS = 0x2c.., 2SS = 0x36.. (the
        // 0x3a1c..0x3a28 gap is the unused 3SS/4SS HT slots).
        type Rate = (i32, u8, u8);
        const PG_RATES: &[(u16, [Rate; 4])] = &[
            (0x3a04, [(88, 1, 0), (88, 1, 0), (88, 1, 0), (84, 1, 0)]), // OFDM 6-18
            (0x3a08, [(80, 1, 0), (76, 1, 0), (72, 1, 0), (68, 1, 0)]), // OFDM 24-54
            (0x3a0c, [(88, 2, 0), (88, 2, 0), (84, 2, 0), (80, 2, 0)]), // HT MCS0-3
            (0x3a10, [(76, 2, 0), (72, 2, 0), (68, 2, 0), (64, 2, 0)]), // HT MCS4-7
            (0x3a14, [(88, 2, 1), (88, 2, 1), (84, 2, 1), (80, 2, 1)]), // HT MCS8-11 2SS
            (0x3a18, [(76, 2, 1), (72, 2, 1), (68, 2, 1), (64, 2, 1)]), // HT MCS12-15 2SS
            (0x3a2c, [(88, 3, 0), (88, 3, 0), (84, 3, 0), (80, 3, 0)]), // VHT 1SS 0-3
            (0x3a30, [(76, 3, 0), (72, 3, 0), (68, 3, 0), (64, 3, 0)]), // VHT 1SS 4-7
            (0x3a34, [(60, 3, 0), (56, 3, 0), (88, 3, 1), (88, 3, 1)]), // VHT1SS8-9/2SS0-1
            (0x3a38, [(84, 3, 1), (80, 3, 1), (76, 3, 1), (72, 3, 1)]), // VHT 2SS 2-5
            (0x3a3c, [(68, 3, 1), (64, 3, 1), (60, 3, 1), (56, 3, 1)]), // VHT 2SS 6-9
        ];

        let region = self.reg_region.load(Ordering::Relaxed);
        // The regulatory limit caps the power-by-rate; missing channels (not in
        // the table) fall back to the max index = no extra cap.
        let lim = |rs: u8, ntx: u8| Self::txpwr_limit(region, channel, rs, ntx).unwrap_or(0x3f);
        // Final per-rate index = min(power-by-rate, regulatory limit), clamped.
        let idx = |(pg, rs, ntx): Rate| pg.min(lim(rs, ntx)).clamp(0, 0x3f);
        // OFDM/HT reference = the lowest OFDM-family rate (HT MCS7, 1 stream).
        let ref_idx = idx((64, 2, 0));

        if self.bb_read(0x1c90, 1 << 15)? != 0 {
            self.bb_write(0x1c90, 1 << 15, 0)?; // unlock TXAGC table writes
        }
        // References: OFDM (0x18e8/0x41e8, [16:10]) + CCK (0x18a0/0x41a0,
        // [22:16]); both paths share the curve (per-device offset is in kfree).
        self.bb_write(0x18e8, 0x0001_fc00, ref_idx as u32)?;
        self.bb_write(0x41e8, 0x0001_fc00, ref_idx as u32)?;
        self.bb_write(0x18a0, 0x007f_0000, ref_idx as u32)?;
        self.bb_write(0x41a0, 0x007f_0000, ref_idx as u32)?;

        // Per-rate diffs from the reference (7-bit signed), packed 4 rates/word.
        for &(addr, grp) in PG_RATES {
            let d = |r: Rate| ((idx(r) - ref_idx) as u32) & 0x7f;
            self.write32(
                addr,
                d(grp[0]) | (d(grp[1]) << 8) | (d(grp[2]) << 16) | (d(grp[3]) << 24),
            )?;
        }
        // Record the un-thermal-compensated reference + channel for thermal_track.
        self.tx_ref_base.store(ref_idx as u8, Ordering::Relaxed);
        self.cur_channel.store(channel, Ordering::Relaxed);
        Ok((ref_idx as u8, lim(2, 0) as u8))
    }

    /// Read the RF thermal meter for `path` (`halrf_get_thermal_8822e`): pulse
    /// RF `0x42[19]` to latch a fresh sample, then read the 6-bit value at
    /// `0x42[6:1]`. Higher = hotter; the PA's gain falls as it heats.
    pub fn read_thermal(&self, path: RfPath) -> Result<u8, FaceError> {
        self.rf_write(path, 0x42, 1 << 19, 1)?;
        self.rf_write(path, 0x42, 1 << 19, 0)?;
        self.rf_write(path, 0x42, 1 << 19, 1)?;
        std::thread::sleep(Duration::from_micros(15));
        Ok((self.rf_read(path, 0x42, 0x7e)? & 0x3f) as u8)
    }

    /// **Thermal TX-power tracking** — the runtime DM the periodic phydm
    /// watchdog does (`odm_txpowertracking` + the 8822E thermal delta tables).
    /// Over a long TX session the PA heats and its gain drops, so on-air power
    /// sags; this reads the thermal meter, compares to the bring-up reference,
    /// and offsets the TXAGC reference by the 8822E `delta_swingidx_..._5ga_{p,n}`
    /// index (which shifts every rate together, since the per-rate 0x3a00 diffs
    /// are relative to the reference). Call periodically (~2 s) for a stable
    /// link; a no-op until [`write_txagc`](Self::write_txagc) has run. Returns
    /// the applied offset (TXAGC index units).
    pub fn thermal_track(&self) -> Result<i32, FaceError> {
        // 8822E 5 GHz path-A delta-swing tables (`delta_swingidx_mp_5ga_{p,n}_
        // txpwrtrk_8822e`), per channel-group row (low/mid/high), indexed by
        // |thermal − reference| (0..29). Value = TXAGC index delta.
        const UP: [[u8; 30]; 3] = [
            [
                0, 1, 1, 2, 2, 3, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 8, 9, 9, 10, 10, 11, 11, 12,
                12, 13, 13, 13,
            ],
            [
                0, 1, 2, 2, 3, 4, 4, 5, 6, 7, 7, 8, 9, 9, 10, 11, 12, 12, 13, 14, 14, 15, 16, 17,
                17, 18, 19, 19, 20, 21,
            ],
            [
                0, 1, 2, 3, 3, 4, 5, 6, 6, 7, 8, 9, 9, 10, 11, 12, 12, 13, 14, 15, 15, 16, 17, 18,
                18, 19, 20, 21, 22, 22,
            ],
        ];
        const DN: [[u8; 30]; 3] = [
            [
                0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1,
            ],
            [
                0, 1, 1, 2, 2, 2, 3, 3, 4, 4, 5, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 9, 10, 10, 11, 11,
                12, 12, 12, 13,
            ],
            [
                0, 1, 1, 1, 2, 2, 2, 3, 3, 4, 4, 4, 5, 5, 5, 6, 6, 6, 7, 7, 8, 8, 8, 9, 9, 9, 10,
                10, 10, 11,
            ],
        ];
        let base = self.tx_ref_base.load(Ordering::Relaxed);
        if base == 0 {
            return Ok(0); // write_txagc hasn't run yet
        }
        let cal = self.cal_thermal.load(Ordering::Relaxed);
        let row = match self.cur_channel.load(Ordering::Relaxed) {
            0..=64 => 0,   // 5G low
            65..=144 => 1, // 5G mid
            _ => 2,        // 5G high
        };
        let cur = self.read_thermal(RfPath::A)?;
        let offset = if cur >= cal {
            UP[row][(cur - cal).min(29) as usize] as i32
        } else {
            -(DN[row][(cal - cur).min(29) as usize] as i32)
        };
        let new_ref = ((base as i32) + offset).clamp(0, 0x3f) as u32;
        if self.bb_read(0x1c90, 1 << 15)? != 0 {
            self.bb_write(0x1c90, 1 << 15, 0)?;
        }
        self.bb_write(0x18e8, 0x0001_fc00, new_ref)?;
        self.bb_write(0x41e8, 0x0001_fc00, new_ref)?;
        self.bb_write(0x18a0, 0x007f_0000, new_ref)?;
        self.bb_write(0x41a0, 0x007f_0000, new_ref)?;
        Ok(offset)
    }

    /// **DIG (Dynamic Initial Gain)** — the runtime RX-sensitivity DM
    /// (`phydm_dig`, jaguar3 path). Reads the OFDM false-alarm (FA) count for
    /// the interval, then walks the per-path initial-gain index (`R_0x1d70`
    /// IGI, paths A/B) to balance sensitivity against false alarms: a quiet
    /// channel lowers IGI (hear weaker peers), a noisy one raises it. Call
    /// periodically (~2 s); returns the new IGI. Without it the RX gain floor is
    /// frozen at its init value and sensitivity never adapts.
    pub fn dig_tick(&self) -> Result<u8, FaceError> {
        const IGI_MIN: u32 = 0x1c;
        const IGI_MAX: u32 = 0x3e;
        // OFDM false-alarm count (`phydm_fa_cnt_statistics_jgr3`): parity +
        // rate-illegal + crc8 + fast-fsync + sb-search + mcs fails (5 GHz, no CCK).
        let v04 = self.read32(0x2d04)?;
        let v08 = self.read32(0x2d08)?;
        let v10 = self.read32(0x2d10)?;
        let v20 = self.read32(0x2d20)?;
        let fa = (v04 >> 16)
            + (v08 & 0xffff)
            + (v08 >> 16)
            + (v10 & 0xffff)
            + (v20 & 0xffff)
            + (v20 >> 16);
        // Reset the FA counters so the next interval reads a fresh delta.
        self.bb_write(0x2a44, 1 << 21, 0)?;
        self.bb_write(0x2a44, 1 << 21, 1)?;

        // FA-driven IGI walk (`phydm_get_new_igi`): thresholds 250/500/750.
        let cur = self.bb_read(0x1d70, 0x7f)?;
        let new = if fa > 750 {
            cur + 2
        } else if fa > 500 {
            cur + 1
        } else if fa < 250 {
            cur.saturating_sub(2)
        } else {
            cur
        }
        .clamp(IGI_MIN, IGI_MAX);
        if new != cur {
            self.bb_write(0x1d70, 0x0000_007f, new)?; // IGI path A
            self.bb_write(0x1d70, 0x0000_7f00, new)?; // IGI path B
        }
        Ok(new as u8)
    }

    /// Run one **dynamic-mechanism watchdog** pass: thermal TX-power tracking
    /// ([`thermal_track`](Self::thermal_track)) + RX [`dig_tick`](Self::dig_tick).
    /// The periodic runtime maintenance the kernel's phydm watchdog does; call
    /// it every ~2 s, or let [`spawn_watchdog`](Self::spawn_watchdog) drive it.
    pub fn watchdog_tick(&self) -> Result<(), FaceError> {
        let _ = self.thermal_track();
        let _ = self.dig_tick();
        Ok(())
    }

    /// Regulatory TX-power index limit (`array_mp_8822e_txpwr_lmt`) for `region`
    /// (`PW_LMT_REGU_*`), `channel`, rate-section `rs` (0=CCK 1=OFDM 2=HT 3=VHT)
    /// and `ntx` (0=1T 1=2T), at 5 GHz / 20 MHz. Exact channel match; `None` if
    /// the channel is absent from the table for that region.
    fn txpwr_limit(region: u8, channel: u8, rs: u8, ntx: u8) -> Option<i32> {
        const TXPWR_LMT: &str = include_str!("../fw/rtl8822e_txpwr_lmt.txt");
        for line in TXPWR_LMT.lines() {
            if line.starts_with('#') {
                continue;
            }
            let v: Vec<i32> = line
                .split_whitespace()
                .filter_map(|x| x.parse().ok())
                .collect();
            // fields: reg band bw rs ntx ch val
            if v.len() == 7
                && v[0] == region as i32
                && v[1] == 1 // 5 GHz
                && v[2] == 0 // 20 MHz
                && v[3] == rs as i32
                && v[4] == ntx as i32
                && v[5] == channel as i32
            {
                return Some(v[6]);
            }
        }
        None
    }

    /// Set the regulatory region (`PW_LMT_REGU_*`: 0=FCC, 1=ETSI, 2=MKK, …) that
    /// caps per-rate TX power. Takes effect on the next [`write_txagc`](Self::write_txagc).
    pub fn set_reg_region(&self, region: u8) {
        self.reg_region.store(region, Ordering::Relaxed);
    }

    // ── TX Gain-K calibration (`halrf_txgapk_8822e`) ───────────────────────
    //
    // One of the RF calibrations the 8822E kernel driver runs for TX power
    // (`HAL_RF_TXGAPK`) that the userspace port previously skipped — and the
    // reason our modulated TX gain sat far below the kernel's. It reads the
    // factory TX gain table (RF 0x5f per gain index), then for each path
    // measures the real per-gain-index error through the chip's internal IQK
    // loop (0x1bfc) and rewrites the RF gain table (RF 0x33 index / 0x3f value,
    // paged via RF 0xee) so the delivered gain tracks the target curve.
    // Faithful port of `halrf_txgapk_8822e.c`; 5 GHz path is what we tune.

    /// Run the full TX Gain-K calibration on `channel`. Backs up and restores
    /// the BB/KIP scratch registers around the per-path IQK gain sweep.
    pub fn txgapk(&self, channel: u8) -> Result<(), FaceError> {
        let (rf3f_bp, rf3f_same) = self.txgapk_save_gain_table()?;

        // Backup BB (TX pause 0x520, 0x1e70, NCTL 0x1b00) + KIP (0x1b38, 0x1b20).
        let bb_reg = [0x0520u16, 0x1e70, 0x1b00];
        let mut bb_bak = [0u32; 3];
        for (i, &r) in bb_reg.iter().enumerate() {
            bb_bak[i] = self.read32(r)?;
        }
        let kip_reg = [0x1b38u16, 0x1b20];
        let mut kip_bak = [[0u32; 2]; 2];
        for (i, &r) in kip_reg.iter().enumerate() {
            for (j, slot) in kip_bak[i].iter_mut().enumerate() {
                self.bb_write(0x1b00, 0x0000_0006, j as u32)?;
                *slot = self.read32(r)?;
            }
        }

        self.txgapk_tx_pause()?;

        let mut offset = [[0i8; 2]; 12];
        for path_idx in 0..2usize {
            self.txgapk_bb_iqk(path_idx)?;
            self.txgapk_afe_iqk(path_idx)?;
            self.txgapk_calc_offset(path_idx, channel, &mut offset)?;
            self.txgapk_rf_restore(path_idx)?;
            self.txgapk_afe_iqk_restore(path_idx)?;
            self.txgapk_bb_iqk_restore(path_idx)?;
        }

        self.txgapk_write_tx_gain(channel, &rf3f_bp, &rf3f_same, &offset)?;

        // Reload KIP then BB scratch registers.
        for (i, &r) in kip_reg.iter().enumerate() {
            for (j, &v) in kip_bak[i].iter().enumerate() {
                self.bb_write(0x1b00, 0x0000_0006, j as u32)?;
                self.write32(r, v)?;
            }
        }
        for (i, &r) in bb_reg.iter().enumerate() {
            self.write32(r, bb_bak[i])?;
        }
        Ok(())
    }

    /// `halrf_txgapk_save_all_tx_gain_table_8822e`: read the factory TX gain
    /// table (RF 0x5f at gain indices 1,4,…,31) across the 5 bands and both
    /// paths, and flag adjacent entries sharing bits [11:5].
    #[allow(clippy::type_complexity)]
    fn txgapk_save_gain_table(
        &self,
    ) -> Result<([[[u32; 2]; 12]; 5], [[[bool; 2]; 12]; 5]), FaceError> {
        let three_wire = [0x180cu16, 0x410c];
        let ch_num = [1u32, 1, 36, 100, 149];
        let ch_setting = [0u32, 0, 1, 1, 1];
        let band_num = [0u32, 0, 1, 3, 5];
        let cck = [1u32, 0, 0, 0, 0];

        let mut bp = [[[0u32; 2]; 12]; 5];
        let mut same = [[[false; 2]; 12]; 5];

        for band in 0..5 {
            for path_idx in 0..2usize {
                let path = RF_PATHS[path_idx];
                let rf18 = self.rf_read(path, 0x18, 0xfffff)?;
                self.bb_write(three_wire[path_idx], 0x0000_0003, 0x0)?;
                self.rf_write(path, 0x18, 0x000ff, ch_num[band])?;
                self.rf_write(path, 0x18, 0x70000, band_num[band])?;
                self.rf_write(path, 0x18, 0x00100, ch_setting[band])?;
                self.rf_write(path, 0x1a, 0x00001, cck[band])?;
                self.rf_write(path, 0x1a, 0x10000, cck[band])?;

                let mut gain_idx = 0usize;
                let mut rf0 = 1u32;
                while rf0 < 32 {
                    self.rf_write(path, 0x0, 0x000ff, rf0)?;
                    bp[band][gain_idx][path_idx] = self.rf_read(path, 0x5f, 0xfffff)?;
                    gain_idx += 1;
                    rf0 += 3;
                }

                self.rf_write(path, 0x18, 0xfffff, rf18)?;
                self.bb_write(three_wire[path_idx], 0x0000_0003, 0x3)?;
            }
        }

        for band in 0..5 {
            for path_idx in 0..2usize {
                for gain in 0..11usize {
                    same[band][gain][path_idx] = (bp[band][gain][path_idx] & 0xfe0)
                        == (bp[band][gain + 1][path_idx] & 0xfe0);
                }
            }
        }
        Ok((bp, same))
    }

    /// `_halrf_txgapk_tx_pause_8822e`: stop the TX scheduler and wait for both
    /// RF paths to leave TX mode before keying the calibration.
    fn txgapk_tx_pause(&self) -> Result<(), FaceError> {
        self.write8(0x0522, 0xff)?;
        self.bb_write(0x1e70, 0x0000_000f, 0x2)?;
        let mut count = 0;
        loop {
            let a = self.rf_read(RfPath::A, 0x00, 0xf0000)?;
            let b = self.rf_read(RfPath::B, 0x00, 0xf0000)?;
            if (a != 2 && b != 2) || count >= 2500 {
                break;
            }
            std::thread::sleep(Duration::from_micros(2));
            count += 1;
        }
        Ok(())
    }

    /// `_halrf_txgapk_bb_iqk_8822e`: route the BB into IQK mode for `path`.
    fn txgapk_bb_iqk(&self, path_idx: usize) -> Result<(), FaceError> {
        self.bb_write(0x1e24, 0x0002_0000, 0x1)?;
        self.bb_write(0x1cd0, 0x1000_0000, 0x1)?;
        self.bb_write(0x1cd0, 0x2000_0000, 0x1)?;
        self.bb_write(0x1cd0, 0x4000_0000, 0x1)?;
        self.bb_write(0x1cd0, 0x8000_0000, 0x0)?;
        if path_idx == 0 {
            self.bb_write(0x1864, 0x8000_0000, 0x1)?;
            self.bb_write(0x180c, 0x0800_0000, 0x1)?;
            self.bb_write(0x186c, 0x0000_0080, 0x1)?;
            self.bb_write(0x180c, 0x0000_0003, 0x0)?;
        } else {
            self.bb_write(0x4164, 0x8000_0000, 0x1)?;
            self.bb_write(0x410c, 0x0800_0000, 0x1)?;
            self.bb_write(0x416c, 0x0000_0080, 0x1)?;
            self.bb_write(0x410c, 0x0000_0003, 0x0)?;
        }
        self.bb_write(0x1a00, 0x0000_0003, 0x2)?;
        self.write32(0x1b08, 0x0000_0080)
    }

    /// `_halrf_txgapk_afe_iqk_8822e`: program the AFE gain ladder for IQK.
    fn txgapk_afe_iqk(&self, path_idx: usize) -> Result<(), FaceError> {
        let reg = if path_idx == 0 { 0x1830u16 } else { 0x4130 };
        self.write32(0x1c38, 0xffff_ffff)?;
        // 0x700f0001 then 0x70_<hi>f_0001 for hi = 0..=0xf, with the first and
        // last value repeated (matches the driver's 18-write ladder).
        self.write32(reg, 0x700f_0001)?;
        for hi in 0x0u32..=0xf {
            self.write32(reg, 0x700f_0001 | (hi << 20))?;
        }
        self.write32(reg, 0x70ff_0001)?;
        Ok(())
    }

    /// `_halrf_txgapk_afe_iqk_restore_8822e`: restore the AFE gain ladder.
    fn txgapk_afe_iqk_restore(&self, path_idx: usize) -> Result<(), FaceError> {
        let reg = if path_idx == 0 { 0x1830u16 } else { 0x4130 };
        self.write32(0x1c38, 0xffa1_005e)?;
        for &v in &[
            0x700b_8041u32,
            0x7014_4041,
            0x7024_4041,
            0x7034_4041,
            0x7044_4041,
            0x705b_8041,
            0x7064_4041,
            0x707b_8041,
            0x708b_8041,
            0x709b_8041,
            0x70ab_8041,
            0x70bb_8041,
            0x70cb_8041,
            0x70db_8041,
            0x70eb_8041,
            0x70fb_8041,
        ] {
            self.write32(reg, v)?;
        }
        Ok(())
    }

    /// `_halrf_txgapk_bb_iqk_restore_8822e`: take the BB back out of IQK mode.
    fn txgapk_bb_iqk_restore(&self, path_idx: usize) -> Result<(), FaceError> {
        let path = RF_PATHS[path_idx];
        self.rf_write(path, 0xde, 0x10000, 0x0)?;
        self.bb_write(0x1b00, 0x0000_0006, 0x0)?;
        self.write32(0x1b08, 0x0000_0000)?;
        self.bb_write(0x1d0c, 0x0001_0000, 0x1)?;
        self.bb_write(0x1d0c, 0x0001_0000, 0x0)?;
        self.bb_write(0x1d0c, 0x0001_0000, 0x1)?;
        if path_idx == 0 {
            self.bb_write(0x1864, 0x8000_0000, 0x0)?;
            self.bb_write(0x180c, 0x0800_0000, 0x0)?;
            self.bb_write(0x186c, 0x0000_0080, 0x0)?;
            self.bb_write(0x180c, 0x0000_0003, 0x3)?;
        } else {
            self.bb_write(0x4164, 0x8000_0000, 0x0)?;
            self.bb_write(0x410c, 0x0800_0000, 0x0)?;
            self.bb_write(0x416c, 0x0000_0080, 0x0)?;
            self.bb_write(0x410c, 0x0000_0003, 0x3)?;
        }
        self.bb_write(0x1a00, 0x0000_0003, 0x0)
    }

    /// `_halrf_txgapk_rf_restore_8822e`: return the RF to normal mode.
    fn txgapk_rf_restore(&self, path_idx: usize) -> Result<(), FaceError> {
        let path = RF_PATHS[path_idx];
        self.rf_write(path, 0x0, 0xf0000, 0x3)?;
        self.rf_write(path, 0xde, 0x10000, 0x0)?;
        self.rf_write(path, 0xdf, 0x30000, 0x0)
    }

    /// `_halrf_txgapk_calculate_offset_8822e`: key the IQK gain sweep and read
    /// back the 10 per-gain-index gain errors at `0x1bfc` into `offset`.
    fn txgapk_calc_offset(
        &self,
        path_idx: usize,
        channel: u8,
        offset: &mut [[i8; 2]; 12],
    ) -> Result<(), FaceError> {
        let path = RF_PATHS[path_idx];
        let set_pi = [0x001cu16, 0x00ec];
        let set_1b00_cfg1 = [0x0000_0d19u32, 0x0000_0d29];

        self.bb_write(0x1b00, 0x0000_0006, path_idx as u32)?;
        self.rf_write(path, 0xde, 0x10000, 0x1)?;
        self.rf_write(path, 0x00, 0xf0000, 0x5)?;
        if channel <= 14 {
            // 2.4 GHz. BT-coex grant (`btc_set_gnt_wl_bt`) omitted — we never
            // tune to 2.4 GHz on this face.
            self.rf_write(path, 0x88, 0x00070, 0x1)?;
            self.rf_write(path, 0x88, 0x0000f, 0x1)?;
            self.rf_write(path, 0xdf, 0x10000, 0x1)?;
            self.rf_write(path, 0x87, 0xc0000, 0x3)?;
            self.rf_write(path, 0x00, 0x003e0, 0x0f)?;
            self.bb_write(0x1b98, 0x0000_7000, 0x0)?;
        } else {
            self.rf_write(path, 0x8b, 0x00700, 0x0)?;
            self.rf_write(path, 0xdf, 0x20000, 0x1)?;
            self.rf_write(path, 0x89, 0x00003, 0x3)?;
            self.rf_write(path, 0x00, 0x003e0, 0x0f)?;
            let sub = match channel {
                16..=96 => 0x2,
                100..=144 => 0x3,
                _ => 0x4, // 149..=253
            };
            self.bb_write(0x1b98, 0x0000_7000, sub)?;
        }

        let backup_pi = self.bb_read(set_pi[path_idx], 0xc000_0000)?;
        self.bb_write(set_pi[path_idx], 0xc000_0000, 0x0)?;
        self.bb_write(0x1b00, 0x0000_0006, path_idx as u32)?;
        self.bb_write(0x1bcc, 0x0000_003f, 0x12)?;
        self.bb_write(0x1b2c, 0x0000_0fff, 0x038)?;
        self.write32(0x1b00, set_1b00_cfg1[path_idx])?;
        std::thread::sleep(Duration::from_millis(10));

        for _ in 0..30 {
            std::thread::sleep(Duration::from_micros(100));
            if self.bb_read(0x2d9c, 0x0000_00ff)? == 0x55 {
                break;
            }
        }
        for _ in 0..30 {
            std::thread::sleep(Duration::from_micros(100));
            if self.bb_read(0x1bfc, 0x0000_ffff)? == 0x8000 {
                break;
            }
        }

        self.bb_write(0x1b10, 0x0000_00ff, 0x00)?;
        std::thread::sleep(Duration::from_micros(100));
        self.bb_write(set_pi[path_idx], 0xc000_0000, backup_pi)?;

        self.bb_write(0x1b00, 0x0000_0006, path_idx as u32)?;
        self.bb_write(0x1bd4, 0x0020_0000, 0x1)?;
        self.bb_write(0x1bd4, 0x001f_0000, 0x12)?;

        self.bb_write(0x1b9c, 0x0000_0f00, 0x3)?;
        let tmp = self.read32(0x1bfc)?;
        for (i, o) in offset.iter_mut().enumerate().take(8) {
            o[path_idx] = ((tmp >> (i * 4)) & 0xf) as i8;
        }
        self.bb_write(0x1b9c, 0x0000_0f00, 0x4)?;
        let tmp = self.bb_read(0x1bfc, 0x0000_00ff)?;
        offset[8][path_idx] = (tmp & 0xf) as i8;
        offset[9][path_idx] = ((tmp & 0xf0) >> 4) as i8;
        // Sign-extend the 4-bit gain errors.
        for o in offset.iter_mut().take(10) {
            if o[path_idx] & 0x8 != 0 {
                o[path_idx] |= 0xf0u8 as i8;
            }
        }
        Ok(())
    }

    /// `_halrf_txgapk_write_tx_gain_8822e`: fold the measured offsets into the
    /// saved gain table and write the corrected RF gain curve for `channel`.
    fn txgapk_write_tx_gain(
        &self,
        channel: u8,
        rf3f_bp: &[[[u32; 2]; 12]; 5],
        rf3f_same: &[[[bool; 2]; 12]; 5],
        offset: &[[i8; 2]; 12],
    ) -> Result<(), FaceError> {
        let (base, band) = match channel {
            1..=14 => (0x20u32, 1usize), // 2G OFDM
            16..=96 => (0x200, 2),       // 5G low
            100..=144 => (0x280, 3),     // 5G mid
            _ => (0x300, 4),             // 5G high
        };

        for path_idx in 0..2usize {
            let path = RF_PATHS[path_idx];
            // Cumulative offset per gain index (skip indices flagged "same").
            let mut offset_tmp = [0i8; 12];
            for (i, slot) in offset_tmp.iter_mut().enumerate().take(10) {
                let mut acc = 0i32;
                for j in i..10usize {
                    if rf3f_same[band][j][path_idx] {
                        continue;
                    }
                    acc += offset[j][path_idx] as i32;
                }
                *slot = acc as i8;
            }

            self.rf_write(path, 0xee, 0xfffff, 0x10000)?;
            for j in 0..=10usize {
                self.rf_write(path, 0x33, 0xfffff, base + j as u32)?;
                let tmp_3f =
                    Self::txgapk_calc_gain(rf3f_bp[band][j][path_idx], offset_tmp[j]) & 0x0_1fff;
                self.rf_write(path, 0x3f, 0x7ffff, tmp_3f << 6)?;
            }
            self.rf_write(path, 0xee, 0xfffff, 0x0)?;
        }
        Ok(())
    }

    /// `_halrf_txgapk_calculat_tx_gain_8822e`: apply a signed half-step gain
    /// offset to a packed RF 0x3f gain word (carry into bits [12] on odd steps).
    fn txgapk_calc_gain(original: u32, offset: i8) -> u32 {
        let off = offset as i32;
        let mut v = original as i32;
        if off % 2 == 0 {
            v += off / 2;
        } else if off < 0 {
            v += 0x1000 + (off / 2) - 1;
        } else {
            v += 0x1000 + (off / 2);
        }
        v as u32
    }

    /// **Single-tone TX** (`phydm_mp_set_single_tone_jgr3`, 8822E branch) — a
    /// diagnostic that keys the PA to emit a continuous carrier at the current
    /// channel, bypassing the MAC entirely. Per path: put the RF in TX mode
    /// (`RF 0x00[19:16] = 2`), set the lowest gain index (`RF 0x00[4:0] = 0` =
    /// max power), and enable the RF LO (`RF 0x58[1] = 1`); plus disable OFDM
    /// CCA. If an SDR sees a tone, the RF/PA path works and any frame-TX gap is
    /// in the MAC; if not, the analog TX path itself is dead.
    pub fn single_tone(&self, enable: bool) -> Result<(), FaceError> {
        if enable {
            self.bb_write(0x1d58, 0xff8, 0x1ff)?; // disable OFDM CCA
            for path in [RfPath::A, RfPath::B] {
                self.rf_write(path, 0x00, 0xf0000, 0x2)?; // TX mode
                self.rf_write(path, 0x00, 0x1f, 0x0)?; // lowest gain idx = max pwr
                self.rf_write(path, 0x58, 1 << 1, 0x1)?; // RF LO enable
            }
        } else {
            self.bb_write(0x1d58, 0xff8, 0x0)?; // enable OFDM CCA
            for path in [RfPath::A, RfPath::B] {
                self.rf_write(path, 0x58, 1 << 1, 0x0)?; // RF LO disable
            }
        }
        Ok(())
    }

    /// **Single-carrier TX** (`phydm_mp_set_single_carrier_jgr3`, 8822E) — a
    /// diagnostic that drives the **BB OFDM modulator → DAC**, unlike
    /// [`single_tone`](Self::single_tone) (a pure RF carrier). Run it together
    /// with `single_tone(true)` (which puts the RF in TX mode): if an SDR sees a
    /// modulated subcarrier offset from the LO, the BB→DAC→RF datapath works and
    /// the frame-TX gap is purely in the MAC; if only the bare LO tone, the
    /// BB→DAC datapath itself is the gate.
    pub fn single_carrier(&self, enable: bool) -> Result<(), FaceError> {
        const OFDM_SINGLE_CARRIER: u32 = 2;
        const OFDM_OFF: u32 = 0;
        if enable {
            // OFDM block on (else nothing modulates).
            if self.bb_read(0x1c3c, 1)? == 0 {
                self.bb_write(0x1c3c, 1, 1)?;
            }
            self.bb_write(0x1a00, 0x3, 0)?; // CCK normal mode
            self.bb_write(0x1a00, 1 << 3, 1)?; // scramble on
            self.bb_write(0x1ca4, 0x7, OFDM_SINGLE_CARRIER)?;
        } else {
            self.bb_write(0x1ca4, 0x7, OFDM_OFF)?;
            std::thread::sleep(Duration::from_millis(10));
            self.bb_write(0x1d0c, 1 << 16, 0)?; // BB reset
            self.bb_write(0x1d0c, 1 << 16, 1)?;
        }
        Ok(())
    }

    /// Read the MAC address the chip auto-loaded from EFUSE into `REG_MACID`
    /// (0x0610). This is the dongle's burned-in source address; the named-radio
    /// face never uses a host MAC on the air, but TX descriptors need a valid
    /// `addr2`, and reading it back is a clean check that EFUSE autoload worked.
    pub fn read_mac(&self) -> Result<[u8; 6], FaceError> {
        let mut mac = [0u8; 6];
        for (i, b) in mac.iter_mut().enumerate() {
            *b = self.read8(REG_MACID + i as u16)?;
        }
        Ok(mac)
    }

    /// Identify the silicon the way halmac's `get_chip_info` does: the hardware
    /// chip id from `REG_SYS_CFG2[7:0]` (`0x17` = 8822E) and the cut from
    /// `REG_SYS_CFG1` byte 1 bits[7:4] (0 = A-cut, 1 = B-cut, …).
    pub fn chip_info(&self) -> Result<ChipInfo, FaceError> {
        Ok(ChipInfo {
            sys_cfg: self.read32(REG_SYS_CFG)?,
            chip_id: self.read8(REG_SYS_CFG2)?,
            cut: self.read8(REG_SYS_CFG + 1)? >> 4,
        })
    }
}

// ── Firmware constants + TX descriptor helpers ──────────────────────────────

/// `TX_DESC_SIZE_88XX` — the TX descriptor prepended to every bulk-OUT packet.
const TX_DESC_SIZE: usize = 48;
/// `OCPBASE_TXBUF_88XX` — the TX buffer's address on the CPU's OCP bus.
const OCPBASE_TXBUF: u32 = 0x1878_0000;
/// `OCPBASE_DMEM_88XX` — DMEM OCP base; addresses below it use the IMEM bits.
const OCPBASE_DMEM: u32 = 0x0020_0000;
/// `HALMAC_DMA_MAPPING_HIGH`.
const DMA_MAPPING_HIGH: u8 = 3;
/// `WLAN_FW_HDR_SIZE`.
const WLAN_FW_HDR_SIZE: usize = 64;
/// `DESC_RATEMCS0` — the TX/RX rate code for 802.11n MCS0 (index adds on).
const DESC_RATE_MCS0: u8 = 0x0c;
/// `DESC_RATEVHTSS1MCS0` — the TX rate code for 802.11ac VHT 1-stream MCS0.
const DESC_RATE_VHT1SS_MCS0: u8 = 0x2c;
/// `DESC_RATEVHTSS2MCS0` — the TX rate code for 802.11ac VHT 2-stream MCS0.
const DESC_RATE_VHT2SS_MCS0: u8 = 0x36;
/// `HALMAC_TXDESC_QSEL_MGT` — management queue → HIGH DMA → first bulk OUT.
const QSEL_MGT: u8 = 0x12;

/// Firmware version fields from the blob header (`update_fw_info_88xx`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FwVersion {
    /// Major version (header offset 4, LE u16).
    pub version: u16,
    /// Sub version (offset 6).
    pub sub_version: u8,
    /// Sub index (offset 7).
    pub sub_index: u8,
}

impl std::fmt::Display for FwVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "v{}.{} (sub-index {})",
            self.version, self.sub_version, self.sub_index
        )
    }
}

/// Parsed firmware blob header (`WLAN_FW_HDR_*` layout, `chk_fw_size_88xx`
/// validation). Section sizes include their 8-byte checksum tails; section
/// addresses have the OCP bit 31 stripped.
struct FwHeader {
    version: FwVersion,
    dmem_addr: u32,
    dmem_size: usize,
    imem_addr: u32,
    imem_size: usize,
    emem_addr: u32,
    emem_size: usize,
}

impl FwHeader {
    fn parse(fw: &[u8]) -> Result<Self, FaceError> {
        const WLAN_FW_HDR_CHKSUM_SIZE: usize = 8;
        let le32 = |off: usize| u32::from_le_bytes(fw[off..off + 4].try_into().unwrap());
        if fw.len() < WLAN_FW_HDR_SIZE {
            return Err(init_err("rtl88xx fw: blob smaller than header".into()));
        }
        let mem_usage = fw[24];
        let dmem_size = le32(36) as usize + WLAN_FW_HDR_CHKSUM_SIZE;
        let imem_size = le32(48) as usize + WLAN_FW_HDR_CHKSUM_SIZE;
        let emem_size = if mem_usage & (1 << 4) != 0 {
            le32(52) as usize + WLAN_FW_HDR_CHKSUM_SIZE
        } else {
            0
        };
        if fw.len() != WLAN_FW_HDR_SIZE + dmem_size + imem_size + emem_size {
            return Err(init_err(format!(
                "rtl88xx fw: size {} != header sections {}",
                fw.len(),
                WLAN_FW_HDR_SIZE + dmem_size + imem_size + emem_size
            )));
        }
        Ok(Self {
            version: FwVersion {
                version: u16::from_le_bytes(fw[4..6].try_into().unwrap()),
                sub_version: fw[6],
                sub_index: fw[7],
            },
            dmem_addr: le32(32) & !(1 << 31),
            dmem_size,
            imem_addr: le32(60) & !(1 << 31),
            imem_size,
            emem_addr: le32(56) & !(1 << 31),
            emem_size,
        })
    }
}

/// Fill the 8-byte FW-offload H2C header (`set_h2c_pkt_hdr_88xx`): category 1,
/// cmd-id 0xFF, the sub-command id, total length (8 + content), ack bit. The
/// sequence number is left 0 (single-shot at init; the FW doesn't require a
/// monotonic seq for un-acked info commands).
fn h2c_hdr(pkt: &mut [u8], sub_cmd_id: u16, content_size: u16, ack: u32) {
    txdesc_set(pkt, 0x00, 0, 7, 0x01); // CATEGORY
    txdesc_set(pkt, 0x00, 7, 1, ack); // ACK
    txdesc_set(pkt, 0x00, 8, 8, 0xff); // CMD_ID
    txdesc_set(pkt, 0x00, 16, 16, sub_cmd_id as u32); // SUB_CMD_ID
    txdesc_set(pkt, 0x04, 0, 16, (8 + content_size) as u32); // TOTAL_LEN
}

/// `SET_BITS_TO_LE_4BYTE`: set a `len`-bit field at `bit` within the LE dword
/// at `dword_off` of a TX descriptor.
fn txdesc_set(desc: &mut [u8], dword_off: usize, bit: u32, len: u32, value: u32) {
    let mut dw = u32::from_le_bytes(desc[dword_off..dword_off + 4].try_into().unwrap());
    let mask = if len == 32 {
        u32::MAX
    } else {
        (1u32 << len) - 1
    };
    dw = (dw & !(mask << bit)) | ((value & mask) << bit);
    desc[dword_off..dword_off + 4].copy_from_slice(&dw.to_le_bytes());
}

/// `fill_txdesc_check_sum_8822e`: XOR of the descriptor's 16-bit LE words
/// (covering the descriptor plus any packet-offset padding), stored in the
/// checksum field at +0x1C bits[15:0]. The field is zeroed before summing.
fn txdesc_checksum(desc: &mut [u8]) {
    let pkt_offset = (u32::from_le_bytes(desc[4..8].try_into().unwrap()) >> 24) & 0x1f;
    txdesc_set(desc, 0x1c, 0, 16, 0);
    let words = (pkt_offset as usize + TX_DESC_SIZE / 8) * 4;
    let mut chksum = 0u16;
    for i in 0..words {
        chksum ^= u16::from_le_bytes(desc[i * 2..i * 2 + 2].try_into().unwrap());
    }
    txdesc_set(desc, 0x1c, 0, 16, chksum as u32);
}

/// Scratch state for DACK (`dm_dack_info`): the per-path ADC DC codes, the 16
/// calibrated DAC MSBK codes (I/Q), the bias-K, and the DA DC offsets.
#[derive(Default)]
struct DackState {
    addc: [[u16; 2]; 2],
    msbk: [[[u8; 16]; 2]; 2],
    biask: [u16; 2],
    dadck: [[u8; 2]; 2],
}

/// RFE (RF front-end) type from logical EFUSE 0xCA (`EEPROM_RFE_OPTION_8822E`)
/// — 0x15 (21) on both testbed dongles; selects table variants + RFE pin cfg.
const RFE_TYPE: u32 = 0x15;

/// The two RF paths, indexable by `path_idx` (0 = A, 1 = B) — matches the
/// driver's `for (path = 0; path < MAX_PATH_NUM_8822E; path++)` loops.
const RF_PATHS: [RfPath; 2] = [RfPath::A, RfPath::B];

/// Channel bandwidth (`config_phydm_switch_bandwidth_8822e`). 20/40/80 MHz are
/// standard 802.11n/ac widths; 5/10 MHz are the chip's narrowband down-clocked
/// modes (`CHANNEL_WIDTH_5/10`) for long-range / low-rate links — both ends must
/// agree, and they carry 20 MHz-format frames at 1/4 or 1/2 the symbol rate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelBw {
    /// 20 MHz.
    Bw20 = 0,
    /// 40 MHz (two bonded 20 MHz channels).
    Bw40 = 1,
    /// 80 MHz (four bonded 20 MHz channels).
    Bw80 = 2,
    /// 10 MHz narrowband (half-clocked).
    Nb10 = 3,
    /// 5 MHz narrowband (quarter-clocked).
    Nb5 = 4,
}

impl ChannelBw {
    /// The TX-descriptor DATA_BW code (0 = 20, 1 = 40, 2 = 80). The narrowband
    /// modes carry 20 MHz-format frames, so they use code 0.
    fn data_bw(self) -> u32 {
        match self {
            ChannelBw::Bw40 => 1,
            ChannelBw::Bw80 => 2,
            _ => 0,
        }
    }
}

/// Map a primary 5 GHz channel + bandwidth to the RF block **centre** channel
/// and the **1-based primary-20 index** within the block (what
/// `config_phydm_switch_bandwidth_8822e` wants). 40 MHz bonds pairs and 80 MHz
/// bonds quads on the 5 GHz grid; U-NII-3 (≥149) bonds on its own offset grid.
fn channel_geometry(primary: u8, bw: ChannelBw) -> (u8, u32) {
    let base: u8 = if primary >= 149 { 149 } else { 36 };
    let off = primary.saturating_sub(base);
    match bw {
        ChannelBw::Bw20 | ChannelBw::Nb10 | ChannelBw::Nb5 => (primary, 1),
        ChannelBw::Bw40 => {
            let block = base + (off / 8) * 8;
            let pri = if primary == block { 1 } else { 2 };
            (block + 2, pri)
        }
        ChannelBw::Bw80 => {
            let block = base + (off / 16) * 16;
            let pri = ((primary - block) / 4 + 1) as u32;
            (block + 6, pri)
        }
    }
}

/// RF path (the 8822E is 2T2R).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RfPath {
    /// Path A — BB window 0x3C00.
    A,
    /// Path B — BB window 0x4C00.
    B,
}

impl RfPath {
    /// The memory-mapped RF register window base in BB address space.
    fn window(&self) -> u16 {
        match self {
            RfPath::A => 0x3c00,
            RfPath::B => 0x4c00,
        }
    }
}

/// phydm table headline selection (`halbb_sel_headline`): the table starts
/// with (0xF-prefixed) variant descriptors {cut[27:24], rfe[7:0]}; pick by
/// exact match → cut-don't-care → rfe-match/max-cut → rfe-don't-care/max-cut.
#[derive(Clone, Copy)]
struct HeadlineSel {
    cut: u32,
    rfe: u32,
}

impl HeadlineSel {
    /// Returns `(headline_word_count, selected_variant_index)`.
    fn select(&self, words: &[u32]) -> Option<(usize, usize)> {
        const CUT_DONT_CARE: u32 = 0xf;
        const RFE_DONT_CARE: u32 = 0xff;
        let mut h_size = 0;
        while h_size + 1 < words.len() && words[h_size] >> 28 == 0xf {
            h_size += 2;
        }
        if h_size == 0 {
            return Some((0, 0));
        }

        for target in [
            ((self.cut & 0xf) << 24) | (self.rfe & 0xff),
            (CUT_DONT_CARE << 24) | (self.rfe & 0xff),
        ] {
            for i in (0..h_size).step_by(2) {
                if words[i] & 0x0f0000ff == target {
                    return Some((h_size, i >> 1));
                }
            }
        }

        for rfe_want in [self.rfe & 0xff, RFE_DONT_CARE] {
            let mut best: Option<(u32, usize)> = None;
            for i in (0..h_size).step_by(2) {
                let rfe = words[i] & 0xff;
                let cut = (words[i] & 0x0f00_0000) >> 24;
                if rfe == rfe_want && best.is_none_or(|(c, _)| cut >= c) {
                    best = Some((cut, i >> 1));
                }
            }
            if let Some((_, idx)) = best {
                return Some((h_size, idx));
            }
        }
        None
    }
}

/// Silicon identity (halmac `get_chip_info`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChipInfo {
    /// Raw `REG_SYS_CFG1` value (vendor/strap details).
    pub sys_cfg: u32,
    /// Hardware chip id from `REG_SYS_CFG2` ([`CHIP_ID_8822E`] expected).
    pub chip_id: u8,
    /// Cut/revision (0 = A-cut, 1 = B-cut, …).
    pub cut: u8,
}

impl ChipInfo {
    /// The power-sequence cut mask: A-cut = BIT1, B-cut = BIT2, …
    fn cut_msk(&self) -> u8 {
        1u8 << (1 + self.cut.min(6))
    }
}

// ── 8822E power sequences (halmac_pwr_seq_8822e.c) ──────────────────────────
//
// Each entry is one `halmac_wlan_pwr_cfg`: a register op gated by cut and
// interface masks. SDIO/PCIE-only entries are kept (and skipped by the USB
// interface mask) so the tables diff 1:1 against the reference driver.

const PWR_CMD_WRITE: u8 = 0x01;
const PWR_CMD_POLLING: u8 = 0x02;
const PWR_CMD_DELAY: u8 = 0x03;
const PWR_CMD_END: u8 = 0x04;

const CUT_ALL: u8 = 0xff;
const INTF_SDIO: u8 = 1 << 0;
const INTF_USB: u8 = 1 << 1;
const INTF_PCI: u8 = 1 << 2;
const INTF_ALL: u8 = 0x0f;

struct PwrCfg {
    offset: u16,
    cut_msk: u8,
    intf_msk: u8,
    cmd: u8,
    msk: u8,
    value: u8,
}

const fn pw(offset: u16, intf_msk: u8, cmd: u8, msk: u8, value: u8) -> PwrCfg {
    PwrCfg {
        offset,
        cut_msk: CUT_ALL,
        intf_msk,
        cmd,
        msk,
        value,
    }
}

/// `TRANS_CARDDIS_TO_CARDEMU_8822E` (SDIO-local entries omitted — USB build).
const TRANS_CARDDIS_TO_CARDEMU: &[PwrCfg] = &[
    pw(0x002e, INTF_ALL, PWR_CMD_WRITE, 1 << 2, 1 << 2),
    pw(0x002d, INTF_ALL, PWR_CMD_WRITE, 1 << 0, 0),
    pw(0x007f, INTF_ALL, PWR_CMD_WRITE, 1 << 7, 0),
    pw(0x004a, INTF_USB, PWR_CMD_WRITE, 1 << 0, 0),
    pw(0x0005, INTF_ALL, PWR_CMD_WRITE, (1 << 3) | (1 << 4), 0),
    pw(0xffff, INTF_ALL, PWR_CMD_END, 0, 0),
];

/// `TRANS_CARDEMU_TO_ACT_8822E` — the step that brings the MAC power domain to
/// ACT and (via the `0x1018`/`0x1045`/`0x0010`/`0x1064` analog enables) starts
/// the clocks the EFUSE controller needs.
const TRANS_CARDEMU_TO_ACT: &[PwrCfg] = &[
    pw(0x0000, INTF_USB | INTF_SDIO, PWR_CMD_WRITE, 1 << 5, 0),
    pw(
        0x0005,
        INTF_ALL,
        PWR_CMD_WRITE,
        (1 << 4) | (1 << 3) | (1 << 2),
        0,
    ),
    pw(0x0075, INTF_PCI, PWR_CMD_WRITE, 1 << 0, 1 << 0),
    pw(0x0006, INTF_ALL, PWR_CMD_POLLING, 1 << 1, 1 << 1),
    pw(0x0075, INTF_PCI, PWR_CMD_WRITE, 1 << 0, 0),
    pw(0xff1a, INTF_USB, PWR_CMD_WRITE, 0xff, 0),
    pw(0x002e, INTF_ALL, PWR_CMD_WRITE, 1 << 3, 0),
    pw(0x0006, INTF_ALL, PWR_CMD_WRITE, 1 << 0, 1 << 0),
    pw(0x0005, INTF_ALL, PWR_CMD_WRITE, (1 << 4) | (1 << 3), 0),
    pw(0x1018, INTF_ALL, PWR_CMD_WRITE, 1 << 2, 1 << 2),
    pw(0x0005, INTF_ALL, PWR_CMD_WRITE, 1 << 0, 1 << 0), // APFM_ONMAC
    pw(0x0005, INTF_ALL, PWR_CMD_POLLING, 1 << 0, 0),    // wait power-on done
    pw(0x0074, INTF_PCI, PWR_CMD_WRITE, 1 << 5, 1 << 5),
    pw(0x0071, INTF_PCI, PWR_CMD_WRITE, 1 << 4, 0),
    pw(
        0x0062,
        INTF_PCI,
        PWR_CMD_WRITE,
        (1 << 7) | (1 << 6) | (1 << 5),
        (1 << 7) | (1 << 6) | (1 << 5),
    ),
    pw(
        0x0061,
        INTF_PCI,
        PWR_CMD_WRITE,
        (1 << 7) | (1 << 6) | (1 << 5),
        0,
    ),
    pw(0x001f, INTF_ALL, PWR_CMD_WRITE, (1 << 7) | (1 << 6), 1 << 7),
    pw(0x00ef, INTF_ALL, PWR_CMD_WRITE, (1 << 7) | (1 << 6), 1 << 7),
    pw(0x1045, INTF_ALL, PWR_CMD_WRITE, 1 << 4, 1 << 4),
    pw(0x0010, INTF_ALL, PWR_CMD_WRITE, 1 << 2, 1 << 2),
    pw(0x1064, INTF_ALL, PWR_CMD_WRITE, 1 << 1, 1 << 1),
    pw(0xffff, INTF_ALL, PWR_CMD_END, 0, 0),
];

/// `TRANS_ACT_TO_CARDEMU_8822E`.
const TRANS_ACT_TO_CARDEMU: &[PwrCfg] = &[
    pw(0x0093, INTF_ALL, PWR_CMD_WRITE, 1 << 3, 0),
    pw(0x001f, INTF_ALL, PWR_CMD_WRITE, 0xff, 0),
    pw(0x00ef, INTF_ALL, PWR_CMD_WRITE, 0xff, 0),
    pw(0x1045, INTF_ALL, PWR_CMD_WRITE, 1 << 4, 0),
    pw(0xff1a, INTF_USB, PWR_CMD_WRITE, 0xff, 0x30),
    pw(0x0049, INTF_ALL, PWR_CMD_WRITE, 1 << 1, 0),
    pw(0x0006, INTF_ALL, PWR_CMD_WRITE, 1 << 0, 1 << 0),
    pw(0x0002, INTF_ALL, PWR_CMD_WRITE, 1 << 1, 0),
    pw(0x0005, INTF_ALL, PWR_CMD_WRITE, 1 << 1, 1 << 1),
    pw(0x0005, INTF_ALL, PWR_CMD_POLLING, 1 << 1, 0),
    pw(0x0000, INTF_USB | INTF_SDIO, PWR_CMD_WRITE, 1 << 5, 1 << 5),
    pw(0xffff, INTF_ALL, PWR_CMD_END, 0, 0),
];

/// `TRANS_CARDEMU_TO_CARDDIS_8822E` (SDIO-local entries omitted — USB build).
const TRANS_CARDEMU_TO_CARDDIS: &[PwrCfg] = &[
    pw(0x0007, INTF_USB | INTF_SDIO, PWR_CMD_WRITE, 0xff, 0x00),
    pw(0x0067, INTF_ALL, PWR_CMD_WRITE, 1 << 5, 0),
    pw(0x004a, INTF_USB, PWR_CMD_WRITE, 1 << 0, 0),
    pw(0x0081, INTF_ALL, PWR_CMD_WRITE, (1 << 7) | (1 << 6), 0),
    pw(0x0090, INTF_ALL, PWR_CMD_WRITE, 1 << 1, 0),
    pw(0x0092, INTF_PCI, PWR_CMD_WRITE, 0xff, 0x20),
    pw(0x0093, INTF_PCI, PWR_CMD_WRITE, 0xff, 0x04),
    pw(
        0x0005,
        INTF_USB | INTF_SDIO,
        PWR_CMD_WRITE,
        (1 << 3) | (1 << 4),
        1 << 3,
    ),
    pw(0x0005, INTF_PCI, PWR_CMD_WRITE, 1 << 2, 1 << 2),
    pw(0xffff, INTF_ALL, PWR_CMD_END, 0, 0),
];

/// `card_en_flow_8822e`: CARDDIS→CARDEMU, then CARDEMU→ACT.
const CARD_ENABLE_FLOW_8822E: &[&[PwrCfg]] = &[TRANS_CARDDIS_TO_CARDEMU, TRANS_CARDEMU_TO_ACT];

/// `card_dis_flow_8822e`: ACT→CARDEMU, then CARDEMU→CARDDIS.
const CARD_DISABLE_FLOW_8822E: &[&[PwrCfg]] = &[TRANS_ACT_TO_CARDEMU, TRANS_CARDEMU_TO_CARDDIS];

impl LibUsbRtl88xxBackend {
    // ── TX/RX descriptors (rtl8822e_ops fill_default_txdesc + rxdesc2attrib) ──

    /// Build `[48-byte TX descriptor][802.11 frame]` for `frame`. The frame is
    /// a non-QoS data frame (or the format's frame) carrying the NDN payload;
    /// the descriptor fixes the rate from `frame.mcs` (USE_RATE + DISDATAFB,
    /// no rate fallback) and routes the packet to the MGT/high queue.
    /// Build one TX unit (descriptor + 802.11 body). `agg = Some((agg_num,
    /// is_first))` marks it as part of an **A-MPDU**: the descriptor's AGG_EN +
    /// MAX_AGG_NUM + AMPDU_DENSITY tell the chip's TX engine to aggregate
    /// consecutive same-RA MPDUs under one PHY preamble (the chip inserts the
    /// MPDU delimiters/CRC/padding); the first unit also carries DMA_TXAGG_NUM =
    /// the count of USB-packed units. Aggregate units are returned unpadded (the
    /// caller 8-byte-aligns each within the USB burst); a lone frame is padded
    /// off the 512-byte bulk boundary as before.
    fn build_tx(&self, frame: &InjectFrame, agg: Option<(u8, bool)>) -> Result<Vec<u8>, FaceError> {
        // A-MPDU path: the descriptor's AGG_EN is set (along with DMA_TXAGG_NUM).
        self.build_tx_body(frame, agg.map(|(n, first)| (n, first, true)), None)
    }

    /// As [`build_tx`](Self::build_tx) but with an optional pre-built MPDU `body`
    /// (the 802.11 frame after the descriptor) — used by A-MSDU, which builds a
    /// QoS-data aggregate body itself. `frame` still supplies the rate (`mcs`) and
    /// addressing (`dst` for the BMC bit). When `body` is `None` the normal
    /// single-MSDU 802.11 frame is built from `frame.payload`.
    /// `agg = Some((dma_txagg_num, is_first, ampdu_en))`: `is_first` carries the
    /// USB-aggregation count `DMA_TXAGG_NUM` (how many descriptor+frame units share
    /// this bulk-OUT — host→chip aggregation); `ampdu_en` additionally sets AGG_EN
    /// for *on-air* A-MPDU. A-MSDU USB-aggregation uses `ampdu_en = false` (each
    /// unit is its own A-MSDU MPDU on air; only the USB transfer is shared).
    fn build_tx_body(
        &self,
        frame: &InjectFrame,
        agg: Option<(u8, bool, bool)>,
        body: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, FaceError> {
        let body = match body {
            Some(b) => b,
            None => self.build_80211(frame)?,
        };
        let mut buf = vec![0u8; TX_DESC_SIZE + body.len()];

        // ---- TX descriptor ----
        txdesc_set(&mut buf, 0x00, 0, 16, body.len() as u32); // TXPKTSIZE
        txdesc_set(&mut buf, 0x00, 16, 8, TX_DESC_SIZE as u32); // OFFSET (no pkt-offset)
        // MACID + RATE_ID: the kernel's monitor-inject path uses the default
        // management MACID (1) and the 2SS rate-id group; MACID 0 is not a valid
        // TX entry, so the MAC discards frames that use it.
        txdesc_set(&mut buf, 0x04, 0, 7, 1); // MACID = RTW_DEFAULT_MGMT_MACID
        txdesc_set(&mut buf, 0x04, 16, 5, 9); // RATE_ID = RATEID_IDX_VHT_2SS
        txdesc_set(
            &mut buf,
            0x04,
            8,
            5,
            self.tx_qsel.load(Ordering::Relaxed) as u32,
        ); // QSEL
        // LS (Last Segment, 0x00[26]): THE on-air gate. Without it the TX DMA
        // treats the frame as an incomplete multi-segment packet and waits for
        // more data forever — the frame sits in the FIFO (pages drain but never
        // recycle, TX-PHY-OK stays 0) and is never keyed onto air. The working
        // kernel driver sets it for every single-buffer frame; captured from a
        // live monitor-inject TX descriptor over usbmon (2026-06-13).
        txdesc_set(&mut buf, 0x00, 26, 1, 1); // LS
        // G_ID = 63: the no-group / broadcast default the kernel uses (0x08[24:6]).
        txdesc_set(&mut buf, 0x08, 24, 6, 63); // G_ID
        txdesc_set(&mut buf, 0x0c, 8, 1, 1); // USE_RATE (driver-fixed rate)
        txdesc_set(&mut buf, 0x0c, 9, 1, 1); // DISRTSFB (no RTS rate fallback)
        txdesc_set(&mut buf, 0x0c, 10, 1, 1); // DISDATAFB (no data rate fallback)
        // Rate code: 802.11n HT (`DESC_RATEMCS0` 0x0c + index; 8–15 = 2 streams),
        // 802.11ac VHT 1-stream (`DESC_RATEVHTSS1MCS0` 0x2c + index), or VHT
        // 2-stream (`DESC_RATEVHTSS2MCS0` 0x36 + index). The chip builds the
        // HT-SIG / VHT-SIG PHY header from this code; 2-stream also needs the
        // 2SS TX path (`0x820=0x31`, set in `set_channel_bw20`).
        let rate_code = if frame.mcs.vht {
            if frame.mcs.nss >= 2 {
                DESC_RATE_VHT2SS_MCS0 + frame.mcs.index
            } else {
                DESC_RATE_VHT1SS_MCS0 + frame.mcs.index
            }
        } else {
            DESC_RATE_MCS0 + frame.mcs.index
        };
        // NDN_RADIO_TX_RATE=<dec> overrides the DESC_RATE code for A/B testing the
        // modulation. The kernel's monitor-inject golden descriptor uses 0x04 =
        // 6 Mbps OFDM legacy (DESC codes: 0x00-0x03 CCK, 0x04-0x0b OFDM legacy,
        // 0x0c+ HT MCS, 0x2c+ VHT). Our default is HT — this lets us test whether
        // a legacy rate is decodable at the OPi RX when HT isn't.
        let rate_code = std::env::var("NDN_RADIO_TX_RATE")
            .ok()
            .and_then(|s| s.parse::<u8>().ok())
            .unwrap_or(rate_code);
        txdesc_set(&mut buf, 0x10, 0, 7, rate_code as u32);
        txdesc_set(&mut buf, 0x10, 17, 1, 1); // RTY_LMT_EN (use the limit below)
        txdesc_set(&mut buf, 0x10, 18, 6, 6); // RTS_DATA_RTY_LMT = 6 (kernel default)
        if frame.mcs.short_gi {
            txdesc_set(&mut buf, 0x14, 4, 1, 1); // DATA_SHORT (SGI)
        }
        // DATA_BW (0x14[6:5]) = the channel bandwidth (20/40/80). The frame is
        // sent at the full channel width, so DATA_SC stays DONT_CARE (0). The
        // 5/10 MHz narrowband modes use code 0 (20 MHz format, BB down-clocked).
        let bw = match self.cur_bw.load(Ordering::Relaxed) {
            1 => ChannelBw::Bw40,
            2 => ChannelBw::Bw80,
            3 => ChannelBw::Nb10,
            4 => ChannelBw::Nb5,
            _ => ChannelBw::Bw20,
        };
        if bw.data_bw() != 0 {
            txdesc_set(&mut buf, 0x14, 5, 2, bw.data_bw());
        }
        // DATA_LDPC (0x14[7]): use the LDPC FEC encoder instead of the mandatory
        // BCC — stronger coding gain on the un-ACKed broadcast channel. The chip
        // advertises it in the HT-SIG/VHT-SIG; a non-LDPC receiver ignores the
        // frame, an LDPC-capable one (the kernel rtl8812eu) decodes it.
        // `NDN_RADIO_LDPC=1` forces it on for on-air A/B regardless of the rate.
        let ldpc = frame.mcs.ldpc || std::env::var("NDN_RADIO_LDPC").is_ok();
        if ldpc {
            txdesc_set(&mut buf, 0x14, 7, 1, 1);
        }
        // DATA_STBC (0x14[8:2]): Alamouti-encode ONE spatial stream across both
        // TX antennas (A+B, enabled via `0x820=0x31`) — pure TX diversity for the
        // feedback-free broadcast case. Value 1 = one STBC stream. Only valid for
        // a 1-stream rate (HT MCS0–7, or VHT `nss == 1`): there is no 802.11 STBC
        // mode for 2 spatial streams, so suppress the bit for 2-stream rates
        // rather than emit an illegal HT-SIG/VHT-SIG. `NDN_RADIO_STBC=1` forces it.
        let one_stream = if frame.mcs.vht {
            frame.mcs.nss < 2
        } else {
            frame.mcs.index < 8
        };
        let stbc = (frame.mcs.stbc || std::env::var("NDN_RADIO_STBC").is_ok()) && one_stream;
        if stbc {
            txdesc_set(&mut buf, 0x14, 8, 2, 1);
        }
        if frame.dst == crate::frame::BROADCAST {
            txdesc_set(&mut buf, 0x00, 24, 1, 1); // BMC (broadcast/multicast)
        }
        // The kernel monitor-inject descriptor leaves DISQSELSEQ and EN_HWSEQ
        // clear (the 802.11 sequence number is carried in the frame body), so we
        // do too — setting EN_HWSEQ here previously was a wrong guess.
        // DMA_TXAGG_NUM (first unit) = how many descriptor+frame units share this
        // bulk-OUT (USB TX aggregation — fewer USB transfers). `ampdu_en` also sets
        // AGG_EN/MAX_AGG_NUM/AMPDU_DENSITY for on-air A-MPDU (BA-gated; broadcast
        // ignores it). A-MSDU USB-agg leaves AGG_EN clear: each unit is its own
        // A-MSDU MPDU on air, only the USB transfer is shared.
        if let Some((agg_num, is_first, ampdu_en)) = agg {
            if ampdu_en {
                txdesc_set(&mut buf, 0x08, 12, 1, 1); // AGG_EN
                txdesc_set(&mut buf, 0x0c, 17, 5, 0x1f); // MAX_AGG_NUM
                txdesc_set(&mut buf, 0x08, 20, 3, 0); // AMPDU_DENSITY
            }
            if is_first {
                txdesc_set(&mut buf, 0x1c, 24, 8, agg_num as u32); // DMA_TXAGG_NUM
            }
        }
        txdesc_checksum(&mut buf);

        buf[TX_DESC_SIZE..].copy_from_slice(&body);

        if agg.is_none() {
            // USB: a total length that is an exact multiple of the bulk max-packet
            // confuses the pipe; the kernel pads such frames. Mirror that.
            if buf.len().is_multiple_of(512) {
                buf.push(0);
            }
        }
        Ok(buf)
    }

    /// Inject several MPDUs in one USB bulk-OUT, each marked AGG_EN
    /// (`DMA_TXAGG_NUM` USB TX aggregation). **Finding (2026-06-15, validated):**
    /// the chip does **not** form an on-air A-MPDU from these for *broadcast* —
    /// hardware MPDU aggregation requires an established **Block-Ack** session
    /// (ADDBA to a specific RA/TID), and broadcast/multicast is never ACK'd, so
    /// the TX engine emits the frames as individual MPDUs regardless of AGG_EN
    /// (confirmed: identical fps vs single-MPDU, and the peer radiotap shows no
    /// A-MPDU status, normal per-MPDU 11n). So this is the correct building block
    /// for the *unicast + BA* case, but does not raise broadcast throughput. The
    /// broadcast-compatible aggregation is **A-MSDU** (one large MPDU, no BA),
    /// which is the throughput + larger-MTU path — see the backlog. Kept as the
    /// faithful AGG_EN/USB-agg foundation. Fire-and-forget, unacknowledged.
    pub async fn inject_ampdu(&self, frames: Vec<InjectFrame>) -> Result<(), FaceError> {
        if frames.is_empty() {
            return Ok(());
        }
        let n = frames.len().min(0xff) as u8;
        let mut buf = Vec::new();
        for (i, f) in frames.iter().enumerate() {
            let unit = self.build_tx(f, Some((n, i == 0)))?;
            buf.extend_from_slice(&unit);
            while buf.len() % 8 != 0 {
                buf.push(0); // 8-byte-align the next unit's descriptor
            }
        }
        if buf.len().is_multiple_of(512) {
            buf.push(0);
        }
        let handle = self.handle.clone();
        let ep = self.bulk_out;
        tokio::task::spawn_blocking(move || {
            handle
                .write_bulk(ep, &buf, Duration::from_secs(1))
                .map_err(usb_err)
                .and_then(|w| {
                    (w == buf.len()).then_some(()).ok_or_else(|| {
                        init_err(format!("rtl88xx inject_ampdu: short write {w}/{}", buf.len()))
                    })
                })
        })
        .await
        .map_err(|e| init_err(format!("rtl88xx inject_ampdu: join {e}")))?
    }

    /// Inject several payloads as one **A-MSDU** — a single large MPDU carrying
    /// multiple MSDU subframes under one PHY preamble and one FCS. Unlike A-MPDU
    /// this needs **no Block-Ack**, so it works for broadcast: it's an ordinary
    /// (QoS-data) frame as far as the MAC is concerned. The throughput + larger-
    /// MTU lever for the named-data radio — and the right place to **bundle**
    /// distinct NDN packets at the link layer (each MSDU is an independent packet
    /// the receiver de-aggregates back into separate NDN Interests/Data, so NDN's
    /// per-packet PIT/FIB semantics are preserved — only the airtime is shared).
    /// All `payloads` go to `dst`/`src`; `mcs` sets the rate. Fire-and-forget.
    pub async fn inject_amsdu(
        &self,
        payloads: &[Bytes],
        mcs: McsDescriptor,
        dst: [u8; 6],
        src: [u8; 6],
    ) -> Result<(), FaceError> {
        if payloads.is_empty() {
            return Ok(());
        }
        let body = self.build_amsdu_body(payloads, dst, src)?;
        let frame = InjectFrame {
            payload: Bytes::new(),
            mcs,
            dst,
            src,
        };
        let buf = self.build_tx_body(&frame, None, Some(body))?;
        let handle = self.handle.clone();
        let ep = self.bulk_out;
        tokio::task::spawn_blocking(move || {
            handle
                .write_bulk(ep, &buf, Duration::from_secs(1))
                .map_err(usb_err)
                .and_then(|w| {
                    (w == buf.len()).then_some(()).ok_or_else(|| {
                        init_err(format!("rtl88xx inject_amsdu: short write {w}/{}", buf.len()))
                    })
                })
        })
        .await
        .map_err(|e| init_err(format!("rtl88xx inject_amsdu: join {e}")))?
    }

    /// Inject several A-MSDU MPDUs in **one USB bulk-OUT** (USB TX aggregation via
    /// `DMA_TXAGG_NUM`) — fewer USB transfers per byte, to fully saturate a USB 2.0
    /// bus (the throughput ceiling once the on-air rate exceeds the bus). Each
    /// `mpdus[i]` is the MSDU list for one A-MSDU MPDU; on air they are K *separate*
    /// A-MSDUs (no A-MPDU/Block-Ack). All share `mcs`/`dst`/`src`. Fire-and-forget.
    pub async fn inject_amsdu_usbagg(
        &self,
        mpdus: &[Vec<Bytes>],
        mcs: McsDescriptor,
        dst: [u8; 6],
        src: [u8; 6],
    ) -> Result<(), FaceError> {
        if mpdus.is_empty() {
            return Ok(());
        }
        let k = mpdus.len().min(0xff) as u8;
        let frame = InjectFrame {
            payload: Bytes::new(),
            mcs,
            dst,
            src,
        };
        let mut buf = Vec::new();
        for (i, msdus) in mpdus.iter().enumerate() {
            let body = self.build_amsdu_body(msdus, dst, src)?;
            // First unit carries DMA_TXAGG_NUM = K; ampdu_en = false (A-MSDU, not A-MPDU).
            let unit = self.build_tx_body(&frame, Some((k, i == 0, false)), Some(body))?;
            buf.extend_from_slice(&unit);
            while buf.len() % 8 != 0 {
                buf.push(0); // 8-byte-align the next unit's descriptor
            }
        }
        if buf.len().is_multiple_of(512) {
            buf.push(0);
        }
        let handle = self.handle.clone();
        let ep = self.bulk_out;
        tokio::task::spawn_blocking(move || {
            handle
                .write_bulk(ep, &buf, Duration::from_secs(1))
                .map_err(usb_err)
                .and_then(|w| {
                    (w == buf.len()).then_some(()).ok_or_else(|| {
                        init_err(format!(
                            "rtl88xx inject_amsdu_usbagg: short write {w}/{}",
                            buf.len()
                        ))
                    })
                })
        })
        .await
        .map_err(|e| init_err(format!("rtl88xx inject_amsdu_usbagg: join {e}")))?
    }

    /// Build the A-MSDU MPDU body: a QoS-data frame (subtype 8) with the A-MSDU
    /// Present bit set in the QoS Control field, followed by the MSDU subframes
    /// `[DA(6) SA(6) Length(2, big-endian) | LLC/SNAP(8) + payload]`, each padded
    /// to a 4-byte boundary except the last (802.11 §A-MSDU). No delimiter CRC
    /// (that's A-MPDU); the single MPDU's FCS covers the lot.
    fn build_amsdu_body(
        &self,
        payloads: &[Bytes],
        dst: [u8; 6],
        src: [u8; 6],
    ) -> Result<Vec<u8>, FaceError> {
        let ethertype = match self.format {
            FrameFormat::RawNdn { ethertype } => ethertype,
            other => {
                return Err(init_err(format!(
                    "rtl88xx A-MSDU: frame format {other:?} not supported"
                )));
            }
        };
        let seq = self.seq.fetch_add(1, Ordering::Relaxed) & 0x0fff;
        let mut out = Vec::new();
        // QoS-data MPDU header (26 bytes): FC subtype 8, ToDS=0/FromDS=0.
        out.extend_from_slice(&[0x88, 0x00]); // FC: type Data, subtype QoS Data
        out.extend_from_slice(&[0x00, 0x00]); // Duration
        out.extend_from_slice(&dst); // addr1 (RA)
        out.extend_from_slice(&src); // addr2 (TA)
        out.extend_from_slice(&dst); // addr3 (BSSID)
        out.extend_from_slice(&(seq << 4).to_le_bytes()); // SeqCtrl
        out.extend_from_slice(&[0x80, 0x00]); // QoS Ctrl: A-MSDU Present (bit7), TID 0
        let last = payloads.len() - 1;
        for (i, p) in payloads.iter().enumerate() {
            let msdu_len = 8 + p.len(); // LLC/SNAP + payload
            out.extend_from_slice(&dst); // subframe DA
            out.extend_from_slice(&src); // subframe SA
            out.extend_from_slice(&(msdu_len as u16).to_be_bytes()); // Length (big-endian)
            out.extend_from_slice(&[0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00]); // LLC/SNAP
            out.extend_from_slice(&ethertype.to_be_bytes());
            out.extend_from_slice(p);
            if i != last {
                let sub_len = 14 + msdu_len; // DA+SA+Len + MSDU
                let pad = (4 - (sub_len % 4)) % 4;
                out.extend(std::iter::repeat_n(0u8, pad));
            }
        }
        Ok(out)
    }

    /// Build the bare 802.11 frame (no radiotap — the hardware TX descriptor
    /// carries the rate). Mirrors `frame::build` minus the radiotap prefix.
    fn build_80211(&self, frame: &InjectFrame) -> Result<Vec<u8>, FaceError> {
        let ethertype = match self.format {
            FrameFormat::RawNdn { ethertype } => ethertype,
            // ESP-NOW (and any other non-`RawNdn` format) reuses the canonical
            // platform-neutral 802.11 builder so the on-air bytes match exactly
            // what a stock `esp-wifi` peer keys on — and what `AfPacketBackend`
            // injects. The chip's TX descriptor (built by `build_tx_body`)
            // carries the rate, so we want the frame *without* radiotap: that is
            // `frame::build_dot11`, not `frame::build`. ESP-NOW must be injected
            // at a basic rate the C5 will decode — 1 Mbps on 2.4 GHz, or 6 Mbps
            // OFDM on 5 GHz (DESC_RATE 0x04, via `NDN_RADIO_TX_RATE=4`).
            other => return crate::frame::build_dot11(other, frame),
        };
        let seq = self.seq.fetch_add(1, Ordering::Relaxed) & 0x0fff;
        let mut out = Vec::with_capacity(24 + 8 + frame.payload.len());
        out.extend_from_slice(&[0x08, 0x00]); // FC: type=Data, subtype=0
        out.extend_from_slice(&[0x00, 0x00]); // Duration
        out.extend_from_slice(&frame.dst); // addr1 (RA/DA)
        out.extend_from_slice(&frame.src); // addr2 (TA/SA)
        out.extend_from_slice(&frame.dst); // addr3 (BSSID)
        out.extend_from_slice(&(seq << 4).to_le_bytes()); // SeqCtrl (frag 0)
        out.extend_from_slice(&LLC_SNAP_PREFIX);
        out.extend_from_slice(&ethertype.to_be_bytes());
        out.extend_from_slice(&frame.payload);
        Ok(out)
    }

    /// Parse one bulk-IN buffer: strip the 24-byte RX descriptor, driver-info,
    /// and shift padding, recover the 802.11 frame, and pull the NDN payload
    /// from behind the LLC/SNAP header. Returns `None` when the buffer is not a
    /// decodable data frame for our format (C2H report, CRC error, wrong type).
    /// Parse one RX unit at byte offset `at`. Returns `(decoded, advance)`:
    /// `decoded` is the frame if it is a usable data frame for our format
    /// (else `None` — a C2H report, CRC error, or non-NDN frame), and `advance`
    /// is the 8-byte-aligned span to the next aggregated unit (the chip packs
    /// several units per USB transfer). Returns `None` only when the descriptor
    /// itself is unusable (can't advance) so the caller stops draining.
    fn parse_rx_at(&self, buf: &[u8], at: usize) -> Option<(Vec<CapturedFrame>, usize)> {
        const RX_DESC_SIZE: usize = 24;
        if at + RX_DESC_SIZE > buf.len() {
            return None;
        }
        let dw = |off: usize| u32::from_le_bytes(buf[at + off..at + off + 4].try_into().unwrap());
        let w0 = dw(0x00);
        let pkt_len = (w0 & 0x3fff) as usize;
        if pkt_len == 0 {
            return None;
        }
        let crc_err = (w0 >> 14) & 1 != 0;
        let drvinfo_sz = ((w0 >> 16) & 0xf) as usize * 8;
        let shift = ((w0 >> 24) & 0x3) as usize;
        let is_c2h = (dw(0x08) >> 28) & 1 != 0;
        // `pkt_offset = _RND8(RXDESC_SIZE + drvinfo + shift + pkt_len)` per the
        // 8822EU de-aggregation loop.
        let advance = (RX_DESC_SIZE + drvinfo_sz + shift + pkt_len + 7) & !7;
        let data_rate = (dw(0x0c) & 0x7f) as u8;

        // Per-frame RSSI from the PHY-status report in the drvinfo region (right
        // after the 24-byte RX descriptor). The 8822E (jaguar3) OFDM report
        // (page_num != 0) carries path-A power `pwdb_a` at byte 1; the jaguar
        // conversion is dBm ≈ pwdb - 110. CCK (page_num 0, 2.4 GHz only) uses a
        // different layout — skipped. This is the first cross-layer signal the
        // userspace driver surfaces (feeds adaptive MCS + measured strategy).
        let rssi_dbm = if drvinfo_sz >= 2 && at + RX_DESC_SIZE + 2 <= buf.len() {
            let page_num = buf[at + RX_DESC_SIZE] & 0x0f;
            (page_num != 0).then(|| {
                let pwdb_a = buf[at + RX_DESC_SIZE + 1] as i16;
                (pwdb_a - 110).clamp(-128, 0) as i8
            })
        } else {
            None
        };

        // DESC_RATEMCS0..=MCS31 → 11n MCS index for the upward hint.
        let mcs_index = (DESC_RATE_MCS0..=DESC_RATE_MCS0 + 31)
            .contains(&data_rate)
            .then(|| data_rate - DESC_RATE_MCS0);
        // Decode the 802.11 data frame into one CapturedFrame, or — for a QoS
        // A-MSDU — several (the link-layer bundle de-aggregated back into the
        // independent NDN packets it carried; see `build_amsdu_body`).
        let decoded = (|| -> Vec<CapturedFrame> {
            if crc_err || is_c2h {
                return vec![];
            }
            let start = at + RX_DESC_SIZE + drvinfo_sz + shift;
            let frame = match buf.get(start..start + pkt_len) {
                Some(f) => f,
                None => return vec![],
            };
            // Non-`RawNdn` formats (the ESP-NOW vendor-action frame, …) share the
            // platform-neutral de-framer: it keys on the format's own header — a
            // Mgmt/Action frame for ESP-NOW, not a Data frame, so the Data-type
            // gate below would drop it — and returns the payload + transmitter
            // address. RSSI/rate come from the RX descriptor we already parsed.
            let ethertype = match self.format {
                FrameFormat::RawNdn { ethertype } => ethertype,
                other => {
                    return crate::frame::parse_dot11(other, frame, rssi_dbm, mcs_index)
                        .into_iter()
                        .collect();
                }
            };
            // Type must be Data (FC byte0 bits[3:2]); the QoS subtype (bit 7) adds
            // a 2-byte QoS Control field, so the MAC header is 26 not 24 bytes.
            if frame.len() < 24 || frame[0] & 0x0c != 0x08 {
                return vec![];
            }
            let qos = frame[0] & 0x80 != 0;
            let hdr = if qos { 26 } else { 24 };
            if frame.len() < hdr {
                return vec![];
            }
            let mut addr1 = [0u8; 6]; // RA/DA @4
            let mut addr2 = [0u8; 6]; // TA/SA @10
            addr1.copy_from_slice(&frame[4..10]);
            addr2.copy_from_slice(&frame[10..16]);

            // A-MSDU: QoS data with A-MSDU-Present (QoS Ctrl byte 0 bit 7) →
            // de-aggregate `[DA(6) SA(6) Len(2 BE) | LLC/SNAP+payload]` subframes,
            // each 4-byte-padded; each becomes its own CapturedFrame.
            if qos && frame[24] & 0x80 != 0 {
                let mut out = Vec::new();
                let mut p = hdr;
                while p + 14 <= frame.len() {
                    let len = u16::from_be_bytes([frame[p + 12], frame[p + 13]]) as usize;
                    let ms = p + 14;
                    let msdu = match frame.get(ms..ms + len) {
                        Some(m) => m,
                        None => break,
                    };
                    if msdu.len() >= 8
                        && msdu[..6] == LLC_SNAP_PREFIX
                        && msdu[6..8] == ethertype.to_be_bytes()
                    {
                        let mut da = [0u8; 6];
                        let mut sa = [0u8; 6];
                        da.copy_from_slice(&frame[p..p + 6]);
                        sa.copy_from_slice(&frame[p + 6..p + 12]);
                        out.push(CapturedFrame {
                            payload: bytes::Bytes::copy_from_slice(&msdu[8..]),
                            addr: Some(sa),
                            group: Some(da),
                            rssi_dbm,
                            mcs_index,
                        });
                    }
                    p += (14 + len + 3) & !3; // next subframe (4-byte aligned)
                }
                return out;
            }

            // Single MSDU: LLC/SNAP follows the (QoS-aware) header.
            if frame.len() < hdr + 8 {
                return vec![];
            }
            let llc = &frame[hdr..hdr + 8];
            if llc[..6] != LLC_SNAP_PREFIX || llc[6..8] != ethertype.to_be_bytes() {
                return vec![];
            }
            vec![CapturedFrame {
                payload: bytes::Bytes::copy_from_slice(&frame[hdr + 8..]),
                addr: Some(addr2),
                group: Some(addr1),
                rssi_dbm,
                mcs_index,
            }]
        })();
        Some((decoded, advance))
    }
}

#[async_trait]
impl FrameIo for LibUsbRtl88xxBackend {
    async fn inject(&self, frame: InjectFrame) -> Result<(), FaceError> {
        let buf = self.build_tx(&frame, None)?;
        let handle = self.handle.clone();
        let ep = self.bulk_out;
        tokio::task::spawn_blocking(move || {
            handle
                .write_bulk(ep, &buf, Duration::from_secs(1))
                .map_err(usb_err)
                .and_then(|n| {
                    (n == buf.len()).then_some(()).ok_or_else(|| {
                        init_err(format!("rtl88xx inject: short write {n}/{}", buf.len()))
                    })
                })
        })
        .await
        .map_err(|e| init_err(format!("rtl88xx inject: join {e}")))?
    }

    async fn inject_batch(&self, frames: Vec<InjectFrame>) -> Result<(), FaceError> {
        // Bundle maximal runs that share dst/src/mcs into one A-MSDU, bounded by
        // the 7935-byte A-MSDU max. Bigger A-MSDUs amortize the per-MPDU overhead
        // (descriptor/preamble) — the lever that took us 177→265 Mb/s toward the
        // USB 2.0 ceiling (USB-agg and write-pipelining gave nothing beyond it).
        const MPDU_BUDGET: usize = 7935;
        let mut i = 0;
        while i < frames.len() {
            let f0 = &frames[i];
            let mut j = i + 1;
            let mut bytes = f0.payload.len();
            while j < frames.len()
                && frames[j].dst == f0.dst
                && frames[j].src == f0.src
                && frames[j].mcs == f0.mcs
                && bytes + frames[j].payload.len() <= MPDU_BUDGET
            {
                bytes += frames[j].payload.len();
                j += 1;
            }
            if j - i == 1 {
                self.inject(frames[i].clone()).await?;
            } else {
                let payloads: Vec<Bytes> =
                    frames[i..j].iter().map(|f| f.payload.clone()).collect();
                self.inject_amsdu(&payloads, f0.mcs, f0.dst, f0.src).await?;
            }
            i = j;
        }
        Ok(())
    }

    // NOTE: `inject` builds the descriptor + frame correctly and the chip
    // accepts every write, but radiated TX additionally needs RF calibration
    // (IQK/LCK/DPK/TSSI — the unported `halrf_8822e` subsystem); see the module
    // header. `recv_frame` is fully functional once a peer is transmitting.
    async fn recv_frame(&self) -> Result<CapturedFrame, FaceError> {
        // Pumped mode: background reader threads keep several bulk-IN transfers in
        // flight and fill `rx_pending`; just drain it (waking on the notify).
        if self.rx_pumped.load(Ordering::Relaxed) {
            loop {
                let notified = self.rx_notify.notified();
                if let Some(f) = self.rx_pending.lock().unwrap().pop_front() {
                    return Ok(f);
                }
                // Re-poll on a timeout in case a notify was missed.
                let _ = tokio::time::timeout(Duration::from_millis(200), notified).await;
            }
        }
        loop {
            // Drain frames already de-aggregated from the previous transfer.
            if let Some(f) = self.rx_pending.lock().unwrap().pop_front() {
                return Ok(f);
            }
            let handle = self.handle.clone();
            let ep = self.bulk_in;
            let buf = tokio::task::spawn_blocking(move || {
                let mut buf = vec![0u8; 16384];
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
            .map_err(|e| init_err(format!("rtl88xx recv: join {e}")))??;

            // Walk every aggregated RX unit in the transfer, queueing the
            // decodable data frames (the OPi's Data may sit behind ambient
            // beacons in the same buffer).
            if let Some(buf) = buf {
                let mut off = 0;
                let mut q = self.rx_pending.lock().unwrap();
                while let Some((decoded, advance)) = self.parse_rx_at(&buf, off) {
                    for f in decoded {
                        q.push_back(f);
                    }
                    off += advance;
                    if off + 24 > buf.len() {
                        break;
                    }
                }
            }
        }
    }
}
