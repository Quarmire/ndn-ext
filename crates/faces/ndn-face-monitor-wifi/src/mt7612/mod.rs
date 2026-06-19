//! Userspace libusb backend for the **MT7612U** (`0e8d:7612`) — a 2×2 dual-band
//! 802.11ac dongle on the MediaTek `mt76x2u` driver. This is the **TX-capable**
//! radio for the NDN named-radio face: unlike the firmware-gated RTL8821c (which
//! is [RX-only][crate::Rtl8821cuBackend] — host injection keys the FIFO but
//! never radiates), MT76 offloads TX calibration to firmware and host-injected
//! frames radiate directly.
//!
//! Reference driver: **github.com/morrownr/mt76** (and the mainline mt76 tree).
//! Every register/flow is verified against the golden usbmon trace in
//! `golden/mt7612-usbmon-2026-06-17/golden_init.pcap`.
//!
//! ## USB register model (much simpler than Realtek's)
//! All MMIO is a USB vendor control transfer (no per-section quirk):
//! - **write32**: `bmRequestType=0x40`, `bRequest=0x06` (MULTI_WRITE),
//!   `wValue=addr>>16`, `wIndex=addr&0xffff`, 4-byte LE data.
//! - **read32**: `bmRequestType=0xc0`, `bRequest=0x07` (MULTI_READ), same split.
//! - CFG read/write `0x47`/`0x46`, FCE write `0x42` (value in `wValue`),
//!   EEPROM read `0x09`, dev-mode/power `0x01`.
//!
//! ## Status
//! Bring-up scaffold: USB open + register access + **firmware download**
//! (ROM patch + ILM/DLM via the FCE DMA path) are implemented and structured to
//! validate against the golden trace. EEPROM/cal, MAC init, monitor RX, and the
//! `FrameIo` TX/RX impl are the next stages.
#![allow(dead_code)]

use std::io;
use std::sync::Arc;
use std::time::Duration;

use rusb::{Context, Device, DeviceHandle, Direction, TransferType, UsbContext};

use async_trait::async_trait;
use bytes::Bytes;
use ndn_transport::FaceError;
use crate::{CapturedFrame, FrameFormat, FrameIo, InjectFrame, McsDescriptor};

/// Async USB TX ring (libusb URBs) — the TX-pipelining path. Linux-only.
#[cfg(target_os = "linux")]
mod tx_async;
#[cfg(target_os = "linux")]
pub use tx_async::TxRing;

/// mt76 USB RX descriptor length before the 802.11 frame: MT_RX_INFO_LEN (4) +
/// the RXWI (32) = 36. Verified against captured RX bursts (a beacon's FC +
/// broadcast addr1 land exactly at offset 36). A 4-byte FCE-info trailer follows
/// the frame. RXWI RSSI[0] sits at offset 18.
const MT76_RXD_LEN: usize = 36;

mod init_table;

// ── Identity ────────────────────────────────────────────────────────────────
pub const MEDIATEK_VID: u16 = 0x0e8d;
/// MT7612U in WiFi mode. (The CD-ROM "driver installer" PID, if present, would
/// need usb_modeswitch — handled the same way as the Realtek path.)
pub const MT7612U_PIDS: &[u16] = &[0x7612, 0x7632, 0x7662];

// ── USB vendor requests (mt76 usb.h `enum mt76_vendor_req`) ─────────────────
const REQ_OUT: u8 = 0x40; // host→device | vendor | device
const REQ_IN: u8 = 0xc0; // device→host | vendor | device
const MT_VEND_DEV_MODE: u8 = 0x01;
const MT_VEND_POWER_ON: u8 = 0x04;
const MT_VEND_MULTI_WRITE: u8 = 0x06;
const MT_VEND_MULTI_READ: u8 = 0x07;
const MT_VEND_READ_EEPROM: u8 = 0x09;
const MT_VEND_WRITE_FCE: u8 = 0x42;
const MT_VEND_WRITE_CFG: u8 = 0x46;
const MT_VEND_READ_CFG: u8 = 0x47;

const CTRL_TIMEOUT: Duration = Duration::from_millis(500);
const BULK_TIMEOUT: Duration = Duration::from_millis(1000);

// ── MCU / FCE registers (verified against golden_init.pcap) ─────────────────
// FCE config written just before the firmware download.
const MT_FCE_PSE_CTRL: u32 = 0x0800; // value 1
const MT_FCE_PDMA_GLOBAL_CONF: u32 = 0x09c4; // value 0x44 (golden)
const MT_FCE_SKIP_FS: u32 = 0x0a6c; // value 0x3 (golden)
const MT_FCE_PSE_CTRL_GO: u32 = 0x09a8; // value 1 after each chunk (golden)
const MT_TX_CPU_FROM_FCE_BASE_PTR: u32 = 0x0090; // -> 0x400230 region; cfg
const MT_USB_U3DMA_CFG: u16 = 0x9018; // CFG-space USB DMA config

// FCE DMA descriptor — written as 16-bit halves via WRITE_FCE (value in wValue).
const MT_FCE_DMA_ADDR: u16 = 0x0230; // +0x0232 = high half
const MT_FCE_DMA_LEN: u16 = 0x0234; // +0x0236 = high half

/// MCU↔host scratch register polled for firmware readiness after load-IVB.
const MT_MCU_COM_REG0: u32 = 0x0730;

// MCU download target offsets (mt76x2u_mcu_load_*).
const MCU_ROM_PATCH_OFFSET: u32 = 0x9_0000;
const MCU_ILM_OFFSET: u32 = 0x8_0000;
// DLM base is 0x110000 on early silicon but 0x110800 on rev ≥ E3 (the kernel's
// MT_MCU_DLM_ADDR_E3). This adapter is ASIC rev 76120044 (E3): the golden trace
// loads DLM at 0x110800. Using 0x110000 lands the data segment 0x800 too low —
// the firmware boots and answers bootrom + a couple commands but then goes silent
// on the calibration commands (and COM_REG0 reads 0x1138f9 instead of 0x1140f9,
// off by exactly 0x800). 0x110800 is correct for this part.
const MCU_DLM_OFFSET: u32 = 0x11_0800;
const FW_CHUNK_MAX: usize = 0x3900; // max ILM/DLM payload per send (mt76x2u)
const PATCH_CHUNK_MAX: usize = 2048;

// MCU inband info header (FCE TX): little-endian `len | flags`. The golden
// firmware chunks use flag byte 0x50 in the top byte (info = 0x50<<24 | len).
const MCU_TXD_FLAG: u32 = 0x5000_0000;

// Vendored firmware (linux-firmware; see fw/mt7612/).
const ROM_PATCH: &[u8] = include_bytes!("../../fw/mt7612/mt7662_rom_patch.bin");
const RAM_FIRMWARE: &[u8] = include_bytes!("../../fw/mt7612/mt7662.bin");

/// Full golden init op-stream (see scripts/gen_mt7612_replay.py) replayed by
/// [`Mt7612uBackend::bring_up`].
const INIT_REPLAY: &[u8] = include_bytes!("init_replay.bin");

/// Monitor-mode + channel-6 (2.4GHz) RF/BB tune op-stream, captured from the
/// kernel `iw set monitor; set channel 6` (see scripts/gen_mt7612_chanset.py).
/// Replayed by [`Mt7612uBackend::set_channel`] AFTER `bring_up` to tune the RF
/// so ambient frames arrive (init alone leaves the RF untuned → 0 RX).
const CHANSET_REPLAY: &[u8] = include_bytes!("chanset_replay.bin");

/// Monitor-mode + **5GHz channel 36 @ 80MHz (VHT80, center 5210 MHz)** RF/BB tune,
/// captured from the kernel `iw dev wlan0 set channel 36 80MHz` (see
/// scripts/gen_mt7612_chanset_5g.py). Replayed by [`Mt7612uBackend::set_channel_5g80`].
/// The throughput path: a clean 5GHz channel (vs congested 2.4GHz ch6, which adds
/// ~200µs of CSMA per frame) at 80MHz bandwidth (4× the per-byte rate of HT20).
const CHANSET_REPLAY_5G80: &[u8] = include_bytes!("chanset_replay_5g80.bin");

/// One captured kernel probe-request TX bulk (ep 0x07): `[info u32][TXWI 20B]
/// [802.11 frame][tail]`. Replayed verbatim by `tx_raw` for the radiation test,
/// and the source of the TXWI template used by `transmit`.
const TX_PROBE: &[u8] = include_bytes!("tx_probe.bin");

/// TXWI template for a DATA frame, from a captured kernel data-frame TX
/// (`golden/.../tx_data.pcap`): flags=0, rate=0 (filled per-frame), ack_ctl=0
/// (broadcast → no ACK), **wcid=0xff** (broadcast/no-station), len_ctl=0 (filled),
/// iv/eiv=0, byte17=0x13 (the kernel's ctl2). The wcid is the key difference from
/// the mgmt template (0xfd) — the firmware drops data frames sent with a mgmt
/// wcid/endpoint.
const TXWI_DATA: [u8; 20] = [
    0, 0, 0, 0, 0, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x13, 0, 0,
];

/// `struct mt76x02_patch_header` — 30-byte header skipped before the patch body.
const PATCH_HEADER_LEN: usize = 30;
/// `struct mt76x02_fw_header` — 32-byte header before ILM/DLM.
const FW_HEADER_LEN: usize = 32;

fn usb_err(e: rusb::Error) -> FaceError {
    FaceError::Io(io::Error::other(format!("mt7612u usb: {e}")))
}
/// Encode an [`McsDescriptor`] into the mt76x02 TXWI rate word (the `__le16` at
/// TXWI offset 2). Field layout (mt76x02_mac.h `MT_RXWI_RATE_*`):
/// index[5:0] | LDPC[6] | BW[8:7] | SGI[9] | STBC[11:10] | PHY[15:13].
/// PHY type: OFDM=1, HT=2, VHT=4. HT carries NSS in the index (MCS8-15 = 2SS);
/// VHT splits index[3:0]=MCS, index[5:4]=NSS-1. BW left 0 (20 MHz) for now.
fn mt76_rate_val(m: &McsDescriptor) -> u16 {
    let (phy, idx): (u16, u16) = if m.vht {
        (4, (m.index as u16 & 0x0f) | (((m.nss.max(1) - 1) as u16 & 0x03) << 4))
    } else {
        (2, m.index as u16 & 0x3f)
    };
    let mut v = idx | (phy << 13);
    if m.ldpc {
        v |= 1 << 6;
    }
    if m.short_gi {
        v |= 1 << 9;
    }
    if m.stbc {
        v |= 1 << 10; // STBC field [11:10] = 1
    }
    v
}

fn init_err(what: String) -> FaceError {
    FaceError::Io(io::Error::other(what))
}

pub struct Mt7612uBackend {
    handle: Arc<DeviceHandle<Context>>,
    /// Bulk-OUT endpoint for MCU/firmware inband commands (ep 0x08 on this dongle).
    ep_cmd: u8,
    /// Bulk-OUT endpoint for WLAN data TX.
    ep_data: u8,
    /// Bulk-IN endpoint for RX (data frames).
    ep_in: u8,
    /// All bulk-IN endpoints in descriptor order (last is the MCU cmd-response).
    ep_ins: Vec<u8>,
    /// MCU command sequence (1..=15, never 0).
    mcu_seq: std::sync::atomic::AtomicU8,
    /// When true the background RX-drain thread stops reading ep 0x84 (so a
    /// foreground `read_rx`/FrameIo consumer gets every frame instead of racing
    /// the drain). Toggled by [`pause_drain`](Self::pause_drain).
    drain_pause: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Wire frame format for `FrameIo` (NDN ethertype by default).
    format: FrameFormat,
    /// 802.11 sequence-number counter (12-bit) for TX frames.
    seq: std::sync::atomic::AtomicU16,
    /// RX-pump queue: background reader threads de-aggregate bulk-IN bursts into
    /// `CapturedFrame`s here; `recv_frame` drains it. Full-rate capture without a
    /// blocking read per call. Empty unless [`spawn_rx_pump`](Self::spawn_rx_pump).
    rx_pending: std::sync::Mutex<std::collections::VecDeque<CapturedFrame>>,
    /// True once `spawn_rx_pump` is running, so `recv_frame` drains the queue.
    rx_pumped: std::sync::atomic::AtomicBool,
    /// Wakes `recv_frame` when a pump thread enqueues a frame.
    rx_notify: tokio::sync::Notify,
    /// TX pump: `inject` hands pre-built USB bulks to a dedicated thread that does
    /// `write_bulk` in a tight loop — no per-frame `spawn_blocking` task dispatch
    /// (that capped TX at ~2000 frames/s). Set by [`spawn_tx_pump`](Self::spawn_tx_pump).
    tx_sender: std::sync::Mutex<Option<std::sync::mpsc::Sender<Vec<u8>>>>,
    /// Bytes and frames the TX-pump thread has actually written (throughput
    /// measurement / queue-drain waits).
    tx_bytes: std::sync::atomic::AtomicU64,
    tx_count: std::sync::atomic::AtomicU64,
    /// Current TX channel bandwidth code for the TXWI rate word BW field [8:7]:
    /// 0=20MHz, 1=40MHz, 2=80MHz. Set by the `set_channel_*` methods to match the
    /// RF tune (an 80MHz rate word on a 20MHz-tuned BB would be malformed). Read by
    /// `build_data_bulk` so VHT80 frames carry the right bandwidth. Default 20MHz.
    tx_bw: std::sync::atomic::AtomicU8,
}

impl Mt7612uBackend {
    /// Find, reset, and open the first MT7612U, claiming its interface.
    pub fn open() -> Result<Self, FaceError> {
        // Pass 1 — reset any matching dongle to a clean power-on state so a
        // half-loaded firmware from a previous run doesn't wedge the MCU. A USB
        // reset does NOT reset the on-chip MCU though, so on a warm device the
        // firmware_running() guard (not the reset) is what prevents a re-download.
        // `NDN_RADIO_NO_RESET=1` skips it (the reset itself can wedge the FCE).
        if std::env::var("NDN_RADIO_NO_RESET").is_err() {
            let ctx = Context::new().map_err(usb_err)?;
            for dev in ctx.devices().map_err(usb_err)?.iter() {
                if let Ok(d) = dev.device_descriptor()
                    && d.vendor_id() == MEDIATEK_VID
                    && MT7612U_PIDS.contains(&d.product_id())
                    && let Ok(h) = dev.open()
                {
                    let _ = h.reset();
                }
            }
            std::thread::sleep(Duration::from_millis(1200));
        }

        let ctx = Context::new().map_err(usb_err)?;
        for dev in ctx.devices().map_err(usb_err)?.iter() {
            if let Ok(d) = dev.device_descriptor()
                && d.vendor_id() == MEDIATEK_VID
                && MT7612U_PIDS.contains(&d.product_id())
            {
                return Self::claim(dev);
            }
        }
        Err(FaceError::Io(io::Error::new(
            io::ErrorKind::NotFound,
            "no MT7612U found (MediaTek 0e8d:7612)",
        )))
    }

    fn claim(device: Device<Context>) -> Result<Self, FaceError> {
        let handle = device.open().map_err(usb_err)?;
        let config = device.active_config_descriptor().map_err(usb_err)?;

        // Collect bulk endpoints on the (single) vendor-specific interface.
        let (mut iface_n, mut outs, mut ins) = (None, Vec::<u8>::new(), Vec::<u8>::new());
        for iface in config.interfaces() {
            for d in iface.descriptors() {
                let mut has_bulk = false;
                for ep in d.endpoint_descriptors() {
                    if ep.transfer_type() != TransferType::Bulk {
                        continue;
                    }
                    has_bulk = true;
                    match ep.direction() {
                        Direction::Out => outs.push(ep.address()),
                        Direction::In => ins.push(ep.address()),
                    }
                }
                if has_bulk {
                    iface_n = Some(iface.number());
                }
            }
        }
        let ep_in = ins.first().copied();
        let iface = iface_n.ok_or_else(|| {
            init_err("MT7612U: no interface with bulk endpoints".into())
        })?;
        if outs.is_empty() || ep_in.is_none() {
            return Err(init_err("MT7612U: missing bulk OUT/IN endpoints".into()));
        }
        // The mt76 inband-command endpoint is ep 0x08 on this dongle (verified in
        // the golden trace); data rides the lower OUT pipes. Fall back to the
        // highest/lowest OUT address if 0x08 isn't present.
        let ep_cmd = outs.iter().copied().find(|&e| e == 0x08).unwrap_or_else(|| {
            *outs.iter().max().unwrap()
        });
        let ep_data = *outs.iter().min().unwrap();

        let _ = handle.set_auto_detach_kernel_driver(true);
        handle.claim_interface(iface).map_err(usb_err)?;
        // NOTE: do NOT clear_halt here by default — on macOS it resets the
        // endpoint data toggle, which desyncs the FCE's first firmware transfer
        // on a *cold* device (the download then times out). Only useful to
        // recover a genuinely stalled endpoint: `NDN_RADIO_CLEAR_HALT=1`.
        if std::env::var("NDN_RADIO_CLEAR_HALT").is_ok() {
            let _ = handle.clear_halt(ep_cmd);
            let _ = handle.clear_halt(ep_data);
            if let Some(i) = ep_in {
                let _ = handle.clear_halt(i);
            }
        }
        if std::env::var("NDN_RADIO_EP_DEBUG").is_ok() {
            eprintln!(
                "mt7612u eps: OUT {:?} cmd={ep_cmd:#04x} data={ep_data:#04x} IN {:?}",
                outs.iter().map(|e| format!("{e:#04x}")).collect::<Vec<_>>(),
                ins.iter().map(|e| format!("{e:#04x}")).collect::<Vec<_>>(),
            );
        }
        Ok(Self {
            handle: Arc::new(handle),
            ep_cmd,
            ep_data,
            ep_in: ep_in.unwrap(),
            ep_ins: ins,
            mcu_seq: std::sync::atomic::AtomicU8::new(0),
            drain_pause: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            format: FrameFormat::default(),
            seq: std::sync::atomic::AtomicU16::new(0),
            rx_pending: std::sync::Mutex::new(std::collections::VecDeque::new()),
            rx_pumped: std::sync::atomic::AtomicBool::new(false),
            rx_notify: tokio::sync::Notify::new(),
            tx_sender: std::sync::Mutex::new(None),
            tx_bytes: std::sync::atomic::AtomicU64::new(0),
            tx_count: std::sync::atomic::AtomicU64::new(0),
            tx_bw: std::sync::atomic::AtomicU8::new(0),
        })
    }

    // ── Register access ─────────────────────────────────────────────────────
    /// Read a 32-bit MMIO register (`MT_VEND_MULTI_READ`).
    pub fn rr(&self, addr: u32) -> Result<u32, FaceError> {
        let mut b = [0u8; 4];
        let n = self
            .handle
            .read_control(
                REQ_IN,
                MT_VEND_MULTI_READ,
                (addr >> 16) as u16,
                (addr & 0xffff) as u16,
                &mut b,
                CTRL_TIMEOUT,
            )
            .map_err(usb_err)?;
        if n != 4 {
            return Err(init_err(format!("mt7612u rr({addr:#x}) short {n}")));
        }
        Ok(u32::from_le_bytes(b))
    }

    /// Write a 32-bit MMIO register (`MT_VEND_MULTI_WRITE`).
    pub fn wr(&self, addr: u32, val: u32) -> Result<(), FaceError> {
        let n = self
            .handle
            .write_control(
                REQ_OUT,
                MT_VEND_MULTI_WRITE,
                (addr >> 16) as u16,
                (addr & 0xffff) as u16,
                &val.to_le_bytes(),
                CTRL_TIMEOUT,
            )
            .map_err(usb_err)?;
        if n != 4 {
            return Err(init_err(format!("mt7612u wr({addr:#x}) short {n}")));
        }
        Ok(())
    }

    /// Write a 16-bit value to an FCE register (`MT_VEND_WRITE_FCE`): the value
    /// rides in `wValue`, the register index in `wIndex`, no data stage.
    fn wr_fce(&self, reg: u16, val: u16) -> Result<(), FaceError> {
        self.handle
            .write_control(REQ_OUT, MT_VEND_WRITE_FCE, val, reg, &[], CTRL_TIMEOUT)
            .map_err(usb_err)?;
        Ok(())
    }

    /// CFG-space read/write (`MT_VEND_READ_CFG` / `MT_VEND_WRITE_CFG`).
    fn rr_cfg(&self, addr: u16) -> Result<u32, FaceError> {
        let mut b = [0u8; 4];
        self.handle
            .read_control(REQ_IN, MT_VEND_READ_CFG, 0, addr, &mut b, CTRL_TIMEOUT)
            .map_err(usb_err)?;
        Ok(u32::from_le_bytes(b))
    }
    fn wr_cfg(&self, addr: u16, val: u32) -> Result<(), FaceError> {
        self.handle
            .write_control(REQ_OUT, MT_VEND_WRITE_CFG, 0, addr, &val.to_le_bytes(), CTRL_TIMEOUT)
            .map_err(usb_err)?;
        Ok(())
    }

    /// Read 4 bytes from the efuse-shadowed EEPROM at `offset`
    /// (`MT_VEND_READ_EEPROM`): `wValue=0`, `wIndex=offset`.
    pub fn read_efuse(&self, offset: u16) -> Result<u32, FaceError> {
        let mut b = [0u8; 4];
        self.handle
            .read_control(REQ_IN, MT_VEND_READ_EEPROM, 0, offset, &mut b, CTRL_TIMEOUT)
            .map_err(usb_err)?;
        Ok(u32::from_le_bytes(b))
    }

    /// Chip ID from EEPROM offset 0 (expect 0x7612 for the MT7612U).
    pub fn chip_id(&self) -> Result<u16, FaceError> {
        Ok((self.read_efuse(0x0000)? & 0xffff) as u16)
    }

    /// Factory MAC address (EEPROM offset 0x04).
    pub fn mac_address(&self) -> Result<[u8; 6], FaceError> {
        let lo = self.read_efuse(0x0004)?.to_le_bytes();
        let hi = self.read_efuse(0x0008)?.to_le_bytes();
        Ok([lo[0], lo[1], lo[2], lo[3], hi[0], hi[1]])
    }

    fn poll<F: Fn(u32) -> bool>(&self, addr: u32, pred: F, tries: u32) -> Result<u32, FaceError> {
        for _ in 0..tries {
            let v = self.rr(addr)?;
            if pred(v) {
                return Ok(v);
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        Err(init_err(format!("mt7612u poll({addr:#x}) timed out")))
    }

    // ── Firmware download ───────────────────────────────────────────────────
    /// Send one firmware region (`data`) to MCU `offset` in `FW_CHUNK_MAX`-sized
    /// chunks. Each chunk: program the FCE DMA descriptor (target addr + len as
    /// 16-bit halves), then bulk-OUT `[4-byte info header][data][4-byte 0 pad]`
    /// to the inband-command endpoint, then kick the FCE.
    fn mcu_fw_send_data(&self, data: &[u8], offset: u32, max: usize) -> Result<(), FaceError> {
        let chunk = max - 8; // 8 bytes overhead (4 info + 4 trailer)
        let dbg = std::env::var("NDN_RADIO_EP_DEBUG").is_ok();
        let nchunks = data.len().div_ceil(chunk);
        if dbg {
            eprintln!("    send_data off={offset:#x} len={} chunks={nchunks}", data.len());
        }
        let mut pos = 0usize;
        let mut idx = 0usize;
        while pos < data.len() {
            if dbg && (idx == 0 || idx % 32 == 0 || idx + 1 == nchunks) {
                eprintln!("    chunk {idx}/{nchunks}");
            }
            let cur = (data.len() - pos).min(chunk);
            let dst = offset + pos as u32;
            // FCE DMA descriptor (written as 16-bit halves via WRITE_FCE):
            //   MT_FCE_DMA_ADDR = dst,  MT_FCE_DMA_LEN = len << 16.
            self.wr_fce(MT_FCE_DMA_ADDR, (dst & 0xffff) as u16)?;
            self.wr_fce(MT_FCE_DMA_ADDR + 2, (dst >> 16) as u16)?;
            self.wr_fce(MT_FCE_DMA_LEN, 0)?; // low half of (len<<16)
            self.wr_fce(MT_FCE_DMA_LEN + 2, cur as u16)?; // high half = len

            // Inband packet: info header (flag | len) + data + 4-byte zero
            // trailer, padded to a 4-byte boundary.
            let mut buf = Vec::with_capacity(4 + cur + 8);
            buf.extend_from_slice(&(MCU_TXD_FLAG | cur as u32).to_le_bytes());
            buf.extend_from_slice(&data[pos..pos + cur]);
            buf.extend_from_slice(&[0u8; 4]); // trailer
            while buf.len() % 4 != 0 {
                buf.push(0);
            }
            self.handle
                .write_bulk(self.ep_cmd, &buf, BULK_TIMEOUT)
                .map_err(|e| init_err(format!("mt7612u fw chunk {idx} (dst {dst:#x}) bulk: {e}")))?;
            // Inter-chunk handshake (from golden_init): wait for the FCE to drain
            // (MT_FCE_PSE_CTRL_GO reads 0), then write 1 to advance it to the next
            // chunk. The advance-write is essential — without it the next chunk's
            // bulk times out. A short settle is also essential on fast USB stacks
            // (Linux): reading 0x09a8 immediately after the bulk can catch the FCE
            // still-idle (DMA not started) and advance prematurely → next chunk
            // NAKs/times out. macOS's slower control path hid this. Wait for the
            // FCE to go busy first (best-effort), then drain.
            std::thread::sleep(Duration::from_millis(1));
            for _ in 0..50 {
                if self.rr(MT_FCE_PSE_CTRL_GO).map(|v| v & 1 != 0).unwrap_or(false) {
                    break; // FCE picked up the chunk
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            for _ in 0..200 {
                if self.rr(MT_FCE_PSE_CTRL_GO).map(|v| v & 1 == 0).unwrap_or(false) {
                    break; // drained
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            self.wr(MT_FCE_PSE_CTRL_GO, 1)?; // advance FCE to next chunk
            pos += cur;
            idx += 1;
        }
        Ok(())
    }

    /// FCE/USB-DMA setup before a firmware download stage — the exact sequence
    /// the kernel emits right before the first firmware chunk (golden_init):
    /// USB U3DMA bulk-enable, MCU dev-mode, FCE base-ptr + max-count + conf.
    fn fce_setup(&self) -> Result<(), FaceError> {
        let d = std::env::var("NDN_RADIO_EP_DEBUG").is_ok();
        if d { eprintln!("    fce: u3dma"); }
        self.wr_cfg(MT_USB_U3DMA_CFG, 0x00c0_0020)?; // bulk TX/RX DMA enable
        // DEV_MODE (bReq 0x01) wValue=1: MCU run/dev mode.
        if d { eprintln!("    fce: devmode"); }
        self.handle
            .write_control(REQ_OUT, MT_VEND_DEV_MODE, 0x0001, 0, &[], CTRL_TIMEOUT)
            .map_err(usb_err)?;
        // DEV_MODE wValue=1 switches the MCU into download mode; the device needs
        // ~9ms to settle before it accepts the next register write. The golden
        // trace shows an 8.67ms gap here vs 0.14ms between all other transfers —
        // firing the next write immediately times out and wedges the device.
        std::thread::sleep(Duration::from_millis(12));
        if d { eprintln!("    fce: pse_ctrl"); }
        self.wr(MT_FCE_PSE_CTRL, 0x1)?; // 0x0800
        if d { eprintln!("    fce: base_ptr"); }
        self.wr(0x09a0, 0x0040_0230)?; // MT_TX_CPU_FROM_FCE_BASE_PTR
        if d { eprintln!("    fce: max_count"); }
        self.wr(0x09a4, 0x1)?; // MT_TX_CPU_FROM_FCE_MAX_COUNT
        if d { eprintln!("    fce: global_conf"); }
        self.wr(MT_FCE_PDMA_GLOBAL_CONF, 0x44)?; // 0x09c4
        if d { eprintln!("    fce: skip_fs"); }
        self.wr(MT_FCE_SKIP_FS, 0x3)?; // 0x0a6c
        if d { eprintln!("    fce: done"); }
        Ok(())
    }

    /// Download the ROM patch (`mt76x2u_mcu_load_rom_patch`): skip the 30-byte
    /// patch header, stream the body to `MCU_ROM_PATCH_OFFSET`.
    fn load_rom_patch(&self) -> Result<(), FaceError> {
        if ROM_PATCH.len() <= PATCH_HEADER_LEN {
            return Err(init_err("mt7612u rom patch too small".into()));
        }
        let d = std::env::var("NDN_RADIO_EP_DEBUG").is_ok();
        self.fce_setup()?;
        self.mcu_fw_send_data(&ROM_PATCH[PATCH_HEADER_LEN..], MCU_ROM_PATCH_OFFSET, PATCH_CHUNK_MAX)?;
        if d { eprintln!("  rom: data sent, WMT enable ..."); }
        // Activate the patch (mt76x2u_mcu_enable_patch + reset_wmt). WMT class
        // requests (bmRequestType=0x20, bRequest=0x01, wValue=0x12) carrying the
        // MediaTek WMT command bytes. WITHOUT THIS the patched firmware never runs
        // and the MCU never consumes ep-0x08 commands — the root cause of the
        // ~1.1s command-write timeouts. Bytes decoded from golden_init.
        const WMT_REQ: u8 = 0x20; // host->device | class | device
        let enable_patch = [0x6fu8, 0xfc, 0x08, 0x01, 0x20, 0x04, 0x00, 0x00, 0x00, 0x09, 0x00];
        let reset_wmt = [0x6fu8, 0xfc, 0x05, 0x01, 0x07, 0x01, 0x00, 0x04];
        self.handle
            .write_control(WMT_REQ, 0x01, 0x0012, 0x0000, &enable_patch, CTRL_TIMEOUT)
            .map_err(usb_err)?;
        std::thread::sleep(Duration::from_millis(20));
        self.handle
            .write_control(WMT_REQ, 0x01, 0x0012, 0x0000, &reset_wmt, CTRL_TIMEOUT)
            .map_err(usb_err)?;
        std::thread::sleep(Duration::from_millis(20));
        Ok(())
    }

    /// Download the main firmware (`mt76x2u_mcu_load_firmware`): parse the
    /// 32-byte header for `ilm_len`/`dlm_len`, stream ILM to `MCU_ILM_OFFSET` and
    /// DLM to `MCU_DLM_OFFSET`.
    fn load_ram_firmware(&self) -> Result<(), FaceError> {
        if RAM_FIRMWARE.len() <= FW_HEADER_LEN {
            return Err(init_err("mt7612u firmware too small".into()));
        }
        let ilm_len = u32::from_le_bytes(RAM_FIRMWARE[0..4].try_into().unwrap()) as usize;
        let dlm_len = u32::from_le_bytes(RAM_FIRMWARE[4..8].try_into().unwrap()) as usize;
        let ilm_start = FW_HEADER_LEN;
        let dlm_start = ilm_start + ilm_len;
        if dlm_start + dlm_len > RAM_FIRMWARE.len() {
            return Err(init_err(format!(
                "mt7612u fw header ilm={ilm_len} dlm={dlm_len} exceeds {} bytes",
                RAM_FIRMWARE.len()
            )));
        }
        self.fce_setup()?;
        // Experimental ILM patch: NDN_FW_ILM_PATCH="hexoff:hexval[;...]" rewrites a
        // u32 at the given ILM offset. For probing hardcoded code constants (e.g. the
        // 0x1800=6144 max-MPDU-buffer constant at ilm+0x4556) suspected to enforce
        // the ~5888B single-MPDU cap.
        let ilm_slice = &RAM_FIRMWARE[ilm_start..dlm_start];
        let ilm_patched: Option<Vec<u8>> = std::env::var("NDN_FW_ILM_PATCH").ok().map(|spec| {
            let mut v = ilm_slice.to_vec();
            for pair in spec.split(';').filter(|s| !s.is_empty()) {
                let mut it = pair.split(':');
                let off = usize::from_str_radix(it.next().unwrap().trim_start_matches("0x"), 16).unwrap_or(0);
                let val = u32::from_str_radix(it.next().unwrap().trim_start_matches("0x"), 16).unwrap_or(0);
                if off + 4 <= v.len() {
                    v[off..off + 4].copy_from_slice(&val.to_le_bytes());
                    eprintln!("  [fw ILM patched: 0x{off:05x} -> 0x{val:08x}]");
                }
            }
            v
        });
        self.mcu_fw_send_data(ilm_patched.as_deref().unwrap_or(ilm_slice), MCU_ILM_OFFSET, FW_CHUNK_MAX)?;
        let dlm_slice = &RAM_FIRMWARE[dlm_start..dlm_start + dlm_len];
        // Experimental DLM patch: the firmware's per-bandwidth TX page-count table
        // (marker 0x3f1f1f10 then two max-page u32s = 22/23 pages = the ~5888B
        // single-MPDU cap) lives at these DLM offsets. NDN_FW_PGCNT=<n> rewrites all
        // eight fields so the firmware allows larger MPDUs (the cap is enforced in
        // firmware, not a host register — see the register hunt). Off by default.
        const DLM_PGCNT_OFFS: [usize; 8] =
            [0x33c8, 0x33cc, 0x33fc, 0x3400, 0x3430, 0x3434, 0x3464, 0x3468];
        let patched: Option<Vec<u8>> = std::env::var("NDN_FW_PGCNT")
            .ok()
            .and_then(|s| s.parse::<u32>().ok())
            .map(|pg| {
                let mut v = dlm_slice.to_vec();
                for off in DLM_PGCNT_OFFS {
                    if off + 4 <= v.len() {
                        v[off..off + 4].copy_from_slice(&pg.to_le_bytes());
                    }
                }
                eprintln!("  [fw DLM patched: 8 TX page-count fields -> {pg}]");
                v
            });
        self.mcu_fw_send_data(
            patched.as_deref().unwrap_or(dlm_slice),
            MCU_DLM_OFFSET,
            FW_CHUNK_MAX,
        )?;
        Ok(())
    }

    /// True if the MCU firmware is already running (COM_REG0 ready signature).
    /// A USB reset doesn't reset the on-chip MCU, so a re-run after a prior
    /// successful load finds firmware already up — re-downloading then would hang.
    pub fn firmware_running(&self) -> bool {
        matches!(self.rr(MT_MCU_COM_REG0), Ok(v) if v & 1 != 0 && (v >> 16) == 0x0011)
    }

    /// Full firmware bring-up: ROM patch then RAM firmware (each preceded by the
    /// FCE/USB-DMA setup). Skipped if firmware is already running.
    pub fn load_firmware(&self) -> Result<(), FaceError> {
        let d = std::env::var("NDN_RADIO_EP_DEBUG").is_ok();
        if self.firmware_running() && std::env::var("NDN_RADIO_FORCE_FW").is_err() {
            if d { eprintln!("  load_firmware: already running, skip"); }
            return Ok(());
        }
        if d { eprintln!("  load_firmware: rom patch ..."); }
        self.load_rom_patch()?;
        if d { eprintln!("  load_firmware: ram firmware ..."); }
        self.load_ram_firmware()?;
        if d { eprintln!("  load_firmware: done"); }
        Ok(())
    }

    /// Start the MCU after the firmware download (`mt76x2u_mcu_load_ivb`): ack the
    /// last FCE completion, issue the IVB/run command (DEV_MODE wValue=0x12), then
    /// poll `MT_MCU_COM_REG0` for the firmware-ready bit. Returns the final
    /// COM_REG0 value and whether bit0 (ready) is set.
    pub fn start_mcu(&self) -> Result<(u32, bool), FaceError> {
        let d = std::env::var("NDN_RADIO_EP_DEBUG").is_ok();
        if d { eprintln!("  start_mcu: running={}", self.firmware_running()); }
        if !self.firmware_running() {
            let _ = self.wr(MT_FCE_PSE_CTRL_GO, 0x14); // ack last FCE completion
            self.handle
                .write_control(REQ_OUT, MT_VEND_DEV_MODE, 0x0012, 0, &[], CTRL_TIMEOUT)
                .map_err(usb_err)?;
            // load-IVB (DEV_MODE wValue=0x12) hands control to the freshly loaded
            // firmware; the golden trace waits ~20ms before reading COM_REG0.
            std::thread::sleep(Duration::from_millis(20));
            if d { eprintln!("  start_mcu: ivb sent, polling COM_REG0 ..."); }
            for _ in 0..200 {
                if self.rr(MT_MCU_COM_REG0)? & 1 != 0 {
                    break;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            if d { eprintln!("  start_mcu: COM_REG0={:#x}", self.rr(MT_MCU_COM_REG0).unwrap_or(0)); }
        }
        // Firmware-ready handshake: write COM_REG0 back (golden writes 0x1140fb
        // after polling) to signal the MCU into runtime command mode. Without it
        // the MCU never consumes ep-0x08 commands (every write times out ~1.1s).
        self.wr(MT_MCU_COM_REG0, 0x0011_40fb)?;
        // Switch the USB DMA / FCE out of firmware-download mode into runtime
        // mode. REQUIRED before any MCU command or RX: without it, command writes
        // to ep 0x08 are never consumed (every one times out ~1.1s) and no RX
        // streams. From golden_init right after load-IVB.
        self.wr(MT_FCE_PSE_CTRL, 0x1)?; // 0x0800
        self.wr_cfg(MT_USB_U3DMA_CFG, 0x00c4_0020)?; // 0x9018 runtime (RX+TX bulk)
        let v = self.rr(MT_MCU_COM_REG0)?;
        Ok((v, v & 1 != 0))
    }

    /// Send an MCU command (`mt76x02u_mcu_send_msg`). Info word layout decoded
    /// from the golden trace: `LEN[15:0] | SEQ[19:16] | CMD[26:20] | PORT(2)[29:27]
    /// | TYPE_CMD(bit30)`. Frame = `[info LE][payload][4-byte trailer]`, padded to
    /// 4, to the inband-command endpoint. If `wait_resp`, read the matching ACK on
    /// the cmd-response IN endpoint (rxfce: seq must match, evt == CMD_DONE).
    pub fn mcu_cmd(&self, cmd: u8, payload: &[u8], wait_resp: bool) -> Result<(), FaceError> {
        use std::sync::atomic::Ordering;
        let mut seq = self.mcu_seq.fetch_add(1, Ordering::Relaxed).wrapping_add(1) & 0xf;
        if seq == 0 {
            seq = self.mcu_seq.fetch_add(1, Ordering::Relaxed).wrapping_add(1) & 0xf;
            if seq == 0 {
                seq = 1;
            }
        }
        let info = (payload.len() as u32 & 0xffff)
            | ((seq as u32) << 16)
            | ((cmd as u32 & 0x7f) << 20)
            | (2u32 << 27) // CPU_TX_PORT
            | (1u32 << 30); // MT_MCU_MSG_TYPE_CMD
        let mut buf = Vec::with_capacity(4 + payload.len() + 8);
        buf.extend_from_slice(&info.to_le_bytes());
        buf.extend_from_slice(payload);
        buf.extend_from_slice(&[0u8; 4]); // trailer
        while buf.len() % 4 != 0 {
            buf.push(0);
        }
        let dbg = std::env::var("NDN_RADIO_MCU_DEBUG").is_ok();
        let tw = std::time::Instant::now();
        let wres = self.handle.write_bulk(self.ep_cmd, &buf, BULK_TIMEOUT);
        let wms = tw.elapsed().as_millis();
        wres.map_err(|e| init_err(format!("mt7612u mcu_cmd 0x{cmd:02x} write({wms}ms): {e}")))?;
        if dbg && wms > 5 {
            eprintln!("  mcu 0x{cmd:02x} len{} write={wms}ms", payload.len());
        }

        if wait_resp {
            // Wait for the command ACK on the cmd-response IN endpoint
            // (MT_EP_IN_CMD_RESP = 0x85). This is REQUIRED for throughput: the MCU
            // holds its response and won't accept the next command until we read
            // it, so missing the ACK makes each subsequent command's bulk-write
            // block ~1s. read_bulk returns as soon as the response arrives, so
            // ACKing commands cost ~ms; we accept any response (seq-exact match is
            // unnecessary for serialized replay) with a bounded timeout.
            let _ = seq;
            let ep_resp = *self.ep_ins.last().unwrap_or(&self.ep_in);
            let mut rx = [0u8; 512];
            // Short drain: with the ROM patch enabled the MCU consumes commands
            // without needing us to read each ACK for flow control, so a brief
            // read just clears any response without stalling (returns immediately
            // when data is present). NDN_RADIO_MCU_RESP_MS overrides the timeout.
            let ms = std::env::var("NDN_RADIO_MCU_RESP_MS").ok().and_then(|s| s.parse().ok()).unwrap_or(200);
            let tr = std::time::Instant::now();
            let r = self.handle.read_bulk(ep_resp, &mut rx, Duration::from_millis(ms));
            if dbg {
                match &r {
                    Ok(n) => eprintln!("  mcu 0x{cmd:02x} resp {n}B in {}ms", tr.elapsed().as_millis()),
                    Err(rusb::Error::Timeout) => eprintln!("  mcu 0x{cmd:02x} resp TIMEOUT {}ms", tr.elapsed().as_millis()),
                    Err(_) => {}
                }
            }
            match r {
                Ok(_) | Err(rusb::Error::Timeout) => {}
                Err(e) => return Err(usb_err(e)),
            }
        }
        Ok(())
    }

    /// Replay an MCU command verbatim from its captured txd info word, preserving
    /// the exact seq. mt76 uses `seq==0` for fire-and-forget commands that post NO
    /// response; only `seq!=0` commands ACK on the cmd-response IN endpoint.
    /// Forcing a non-zero seq onto a seq-0 command makes the running firmware not
    /// drain it (the ep-0x08 FIFO fills after ~90 commands and every further write
    /// blocks ~1s), and waiting for an ACK that never comes wastes ~200ms each.
    /// So: send the info word as-is, and only read a response when seq is nonzero.
    pub fn mcu_cmd_raw(&self, info: u32, payload: &[u8]) -> Result<(), FaceError> {
        let mut buf = Vec::with_capacity(4 + payload.len() + 8);
        buf.extend_from_slice(&info.to_le_bytes());
        buf.extend_from_slice(payload);
        buf.extend_from_slice(&[0u8; 4]); // trailer
        while buf.len() % 4 != 0 {
            buf.push(0);
        }
        let dbg = std::env::var("NDN_RADIO_MCU_DEBUG").is_ok();
        let cmd = (info >> 20) & 0x7f;
        let seq = (info >> 16) & 0xf;
        let tw = std::time::Instant::now();
        let wres = self.handle.write_bulk(self.ep_cmd, &buf, BULK_TIMEOUT);
        let wms = tw.elapsed().as_millis();
        wres.map_err(|e| init_err(format!("mt7612u mcu_cmd 0x{cmd:02x} write({wms}ms): {e}")))?;
        if seq == 0 {
            if dbg && wms > 5 {
                eprintln!("  mcu 0x{cmd:02x} seq0 write={wms}ms (no-resp)");
            }
            return Ok(());
        }
        let ep_resp = *self.ep_ins.last().unwrap_or(&self.ep_in);
        let mut rx = [0u8; 512];
        let ms = std::env::var("NDN_RADIO_MCU_RESP_MS").ok().and_then(|s| s.parse().ok()).unwrap_or(200);
        let tr = std::time::Instant::now();
        let r = self.handle.read_bulk(ep_resp, &mut rx, Duration::from_millis(ms));
        if dbg {
            match &r {
                Ok(n) => eprintln!("  mcu 0x{cmd:02x} seq{seq} resp {n}B in {}ms", tr.elapsed().as_millis()),
                Err(rusb::Error::Timeout) => {
                    eprintln!("  mcu 0x{cmd:02x} seq{seq} resp TIMEOUT {}ms", tr.elapsed().as_millis())
                }
                Err(_) => {}
            }
        }
        match r {
            Ok(_) | Err(rusb::Error::Timeout) => {}
            Err(e) => return Err(usb_err(e)),
        }
        Ok(())
    }

    /// Replay the MAC/BB MMIO init sequence captured from the kernel
    /// (`init_table::INIT_WRITES`) after firmware is up. Register-only — the
    /// RF/channel come from MCU commands (see [`bring_up`](Self::bring_up)).
    pub fn apply_init(&self) -> Result<(), FaceError> {
        for &(addr, val) in init_table::INIT_WRITES {
            self.wr(addr, val)?;
        }
        Ok(())
    }

    /// Full init: replay the golden op-stream (`init_replay.bin`) — MMIO writes,
    /// CFG writes, DEV_MODE, the firmware-load marker, and the 473 MCU commands
    /// (RF/BB programming + calibration) — in exact captured order. This is what
    /// tunes the RF for RX/TX. MCU commands are best-effort (an un-ACKed command
    /// is logged but doesn't abort the bring-up).
    pub fn bring_up(&self) -> Result<(), FaceError> {
        let dbg = std::env::var("NDN_RADIO_EP_DEBUG").is_ok();
        let force = std::env::var("NDN_RADIO_FORCE_FW").is_ok();

        let drain_pause = self.spawn_rx_drain();
        std::thread::sleep(Duration::from_millis(30));

        // WARM re-open (reliability): if the firmware is already running — from a
        // previous run of this driver or the kernel — DO NOT replay the cold
        // bring-up. Re-downloading firmware over a running MCU collides with the
        // FCE and times out a chunk, wedging the device (the recurring "warm run
        // wedges" failure). The MAC/BB init persists while firmware runs, so just
        // re-assert runtime mode via start_mcu(). `NDN_RADIO_FORCE_FW=1` overrides
        // to force the full cold replay. Poll a few times — the first register
        // read right after claim() can be racy.
        if !force {
            let warm = (0..5).any(|_| {
                let v = self.rr(MT_MCU_COM_REG0);
                if dbg {
                    eprintln!("  warm-check: COM_REG0 = {v:?}");
                }
                if matches!(v, Ok(x) if x & 1 != 0 && (x >> 16) == 0x0011) {
                    true
                } else {
                    std::thread::sleep(Duration::from_millis(20));
                    false
                }
            });
            if warm {
                eprintln!(
                    "mt7612u bring_up: firmware already running — warm re-open (skipping cold replay)"
                );
                self.start_mcu()?;
                return Ok(());
            }
        }

        // COLD path — FAITHFUL in-order replay. The post-load diff vs golden_init
        // showed our command sequence diverges: we skipped the pre-firmware
        // bootloader handshake (writes + ~51 MCU commands) the kernel runs BEFORE
        // the firmware download, so the firmware came up accepting-but-not-
        // processing commands. Replay everything in captured order; load firmware
        // at the marker. RX-drain runs throughout so command writes are accepted.

        let b: &[u8] = INIT_REPLAY;
        let mut i = 0usize;
        let (mut nw, mut nm, mut ne) = (0u32, 0u32, 0u32);
        let mut loaded_fw = false;
        while i < b.len() {
            if dbg && (nw + nm) % 500 == 0 && (nw + nm) > 0 {
                eprintln!("  ... {nw} writes + {nm} mcu, {ne} errs (op @ {i}/{})", b.len());
            }
            let tag = b[i];
            i += 1;
            macro_rules! exec {
                ($e:expr) => {
                    if let Err(e) = $e {
                        ne += 1;
                        if dbg && ne <= 30 {
                            eprintln!("  op err @{i} tag {tag:#04x}: {e}");
                        }
                    }
                };
            }
            match tag {
                0x06 => {
                    let addr = u32::from_le_bytes(b[i..i + 4].try_into().unwrap());
                    let val = u32::from_le_bytes(b[i + 4..i + 8].try_into().unwrap());
                    i += 8;
                    exec!(self.wr(addr, val));
                    nw += 1;
                }
                0x46 => {
                    let addr = u16::from_le_bytes(b[i..i + 2].try_into().unwrap());
                    let val = u32::from_le_bytes(b[i + 2..i + 6].try_into().unwrap());
                    i += 6;
                    exec!(self.wr_cfg(addr, val));
                }
                0x01 => {
                    let wv = u16::from_le_bytes(b[i..i + 2].try_into().unwrap());
                    i += 2;
                    // After the firmware marker, start_mcu() has already performed
                    // the runtime handoff (load-IVB + COM_REG0 + USB-DMA into runtime
                    // mode). The replay's remaining DEV_MODE writes are the captured
                    // download-mode / load-IVB switches; re-running them flips the
                    // device back out of runtime mode, so register writes still land
                    // but every MCU command write times out. Suppress them post-load.
                    if !loaded_fw {
                        exec!(self
                            .handle
                            .write_control(REQ_OUT, MT_VEND_DEV_MODE, wv, 0, &[], CTRL_TIMEOUT)
                            .map_err(usb_err)
                            .map(|_| ()));
                    }
                }
                0x4d => {
                    let info = u32::from_le_bytes(b[i..i + 4].try_into().unwrap());
                    let len = u16::from_le_bytes(b[i + 4..i + 6].try_into().unwrap()) as usize;
                    i += 6;
                    let payload = &b[i..i + len];
                    i += len;
                    exec!(self.mcu_cmd_raw(info, payload));
                    nm += 1;
                }
                0xff => {
                    // Firmware download + load-IVB + runtime reconfig, in order.
                    // Pause the RX-drain: the FCE bulk download (ep 0x08) collides
                    // with concurrent ep-0x84 reads and the download times out.
                    // (Pre-fw commands still got drained; resume for post-fw cmds.)
                    use std::sync::atomic::Ordering;
                    drain_pause.store(true, Ordering::Relaxed);
                    std::thread::sleep(Duration::from_millis(60)); // let in-flight read finish
                    let r = (|| -> Result<(), FaceError> {
                        self.load_firmware()?;
                        self.start_mcu()?;
                        Ok(())
                    })();
                    drain_pause.store(false, Ordering::Relaxed);
                    r?;
                    loaded_fw = true;
                    if dbg {
                        eprintln!("  [firmware loaded @ op {i}]");
                    }
                }
                other => {
                    return Err(init_err(format!("mt7612u replay bad tag {other:#04x} @ {i}")));
                }
            }
        }
        let _ = loaded_fw;
        eprintln!("mt7612u bring_up: {nw} writes + {nm} mcu cmds, {ne} op errors");
        Ok(())
    }

    /// Put the MAC into promiscuous monitor RX: accept-all RX filter + enable the
    /// TX/RX MAC engines. `MT_RX_FILTR_CFG` (0x1400) = 0 accepts every frame;
    /// `MT_MAC_SYS_CTRL` (0x1004) bit2|bit3 = ENABLE_TX|ENABLE_RX.
    pub fn setup_monitor_rx(&self) -> Result<(), FaceError> {
        // USB RX bulk DMA enable. The replay excludes 0x9018 (an FCE reg), but the
        // kernel sets it to 0xc40020 post-firmware — the 0x40000 bit over the
        // firmware-load value (0xc00020) enables RX streaming. Without it the
        // device never delivers frames to bulk-IN.
        self.wr_cfg(MT_USB_U3DMA_CFG, 0x00c4_0020)?;
        self.wr(0x1400, 0x0000_0000)?; // MT_RX_FILTR_CFG: promiscuous
        self.wr(0x1004, 0x0000_000c)?; // MT_MAC_SYS_CTRL: ENABLE_TX|ENABLE_RX
        Ok(())
    }

    /// Tune the RF/BB to the monitor channel by replaying [`CHANSET_REPLAY`] (the
    /// kernel's `set monitor; set channel 6` op-stream: 194 RF/BB register writes
    /// + 32 calibration MCU commands). `bring_up` only does init (firmware + MAC/
    /// BB), which leaves the RF untuned — without this the receiver delivers 0
    /// frames. Call after `bring_up`, before listening. Channel 6 (2.4GHz).
    pub fn set_channel_ch6(&self) -> Result<(), FaceError> {
        self.tx_bw.store(0, std::sync::atomic::Ordering::Relaxed); // 20MHz
        self.replay_chanset(CHANSET_REPLAY, "ch6/20MHz")
    }

    /// Tune the RF/BB to **5GHz channel 36 @ 80MHz (VHT80)** by replaying
    /// [`CHANSET_REPLAY_5G80`]. This is the throughput channel: 5GHz is far less
    /// congested than 2.4GHz ch6 (removing ~200µs of per-frame CSMA from the 337µs
    /// fixed TX overhead), and 80MHz bandwidth carries 4× the bits/symbol of HT20.
    /// Pair with a VHT TXWI ([`McsDescriptor::vht`]) and the 80MHz bandwidth bit
    /// (`build_data_bulk` honours `McsDescriptor::bw`). Call after `bring_up`.
    pub fn set_channel_5g80(&self) -> Result<(), FaceError> {
        self.tx_bw.store(2, std::sync::atomic::Ordering::Relaxed); // 80MHz
        self.replay_chanset(CHANSET_REPLAY_5G80, "ch36/80MHz")
    }

    /// Shared op-stream replayer for the captured channel-set blobs (see
    /// `gen_mt7612_chanset*.py`): 0x06 reg write, 0x46 cfg write, 0x01 DEV_MODE,
    /// 0x4D MCU command (verbatim info+payload). Errors are counted, not fatal —
    /// a few RF writes racing the MCU is normal and the tune still takes.
    fn replay_chanset(&self, b: &[u8], what: &str) -> Result<(), FaceError> {
        let mut i = 0usize;
        let (mut nw, mut nm, mut ne) = (0u32, 0u32, 0u32);
        while i < b.len() {
            let tag = b[i];
            i += 1;
            macro_rules! exec {
                ($e:expr) => {
                    if $e.is_err() {
                        ne += 1;
                    }
                };
            }
            match tag {
                0x06 => {
                    let addr = u32::from_le_bytes(b[i..i + 4].try_into().unwrap());
                    let val = u32::from_le_bytes(b[i + 4..i + 8].try_into().unwrap());
                    i += 8;
                    exec!(self.wr(addr, val));
                    nw += 1;
                }
                0x46 => {
                    let addr = u16::from_le_bytes(b[i..i + 2].try_into().unwrap());
                    let val = u32::from_le_bytes(b[i + 2..i + 6].try_into().unwrap());
                    i += 6;
                    exec!(self.wr_cfg(addr, val));
                }
                0x01 => {
                    let wv = u16::from_le_bytes(b[i..i + 2].try_into().unwrap());
                    i += 2;
                    exec!(self
                        .handle
                        .write_control(REQ_OUT, MT_VEND_DEV_MODE, wv, 0, &[], CTRL_TIMEOUT)
                        .map_err(usb_err)
                        .map(|_| ()));
                }
                0x4d => {
                    let info = u32::from_le_bytes(b[i..i + 4].try_into().unwrap());
                    let len = u16::from_le_bytes(b[i + 4..i + 6].try_into().unwrap()) as usize;
                    i += 6;
                    let payload = &b[i..i + len];
                    i += len;
                    exec!(self.mcu_cmd_raw(info, payload));
                    nm += 1;
                }
                other => {
                    return Err(init_err(format!("mt7612u chanset bad tag {other:#04x} @ {i}")));
                }
            }
        }
        eprintln!("mt7612u set_channel {what}: {nw} writes + {nm} mcu cmds, {ne} op errors");
        Ok(())
    }

    /// Continuously drain the data bulk-IN endpoint (ep 0x84) in a background
    /// thread. mt76 USB keeps RX URBs submitted; if the host stops reading, the
    /// device's USB DMA stalls and can block the MCU command path (commands get
    /// accepted into the FIFO but never processed). Call before `bring_up`.
    pub fn spawn_rx_drain(&self) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
        use std::sync::atomic::Ordering;
        let pause = self.drain_pause.clone();
        let h = self.handle.clone();
        let ep = self.ep_in;
        let p = pause.clone();
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 8192];
            loop {
                if p.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                }
                let _ = h.read_bulk(ep, &mut buf, Duration::from_millis(50));
            }
        });
        pause
    }

    /// WLAN data-TX bulk-OUT endpoint. The kernel sends mgmt/probe frames on
    /// ep 0x07 (the AC_VO queue) on this dongle; we use the same.
    const TX_EP: u8 = 0x07;

    /// Write a pre-built USB TX bulk verbatim (`[info][TXWI][802.11][tail]`) to the
    /// WLAN data endpoint. Used to replay a captured frame for the radiation test.
    pub fn tx_raw(&self, bulk: &[u8]) -> Result<(), FaceError> {
        self.handle
            .write_bulk(Self::TX_EP, bulk, BULK_TIMEOUT)
            .map_err(usb_err)?;
        Ok(())
    }

    /// Replay the embedded captured probe-request bulk verbatim (known-good
    /// bytes) — the most reliable first radiation test.
    pub fn tx_raw_probe(&self) -> Result<(), FaceError> {
        self.tx_raw(TX_PROBE)
    }

    /// Transmit an 802.11 frame: wrap it in the mt76x02u USB TX framing
    /// (`[info u32][TXWI 20B][frame][4B tail]`, padded to 4) and write it to the
    /// WLAN data endpoint. The TXWI is templated from a captured kernel TX (basic
    /// rate, no-station wcid 0xfd) with the MPDU-length field set to this frame.
    /// info = round_up(TXWI+frame,4) | 80211(bit19) | WIV(bit24) | QSEL=2(bit26),
    /// matching the captured `0x050800f0`.
    pub fn transmit(&self, frame: &[u8]) -> Result<(), FaceError> {
        let buf = self.build_tx_bulk(frame, None);
        self.handle
            .write_bulk(Self::TX_EP, &buf, BULK_TIMEOUT)
            .map_err(usb_err)?;
        Ok(())
    }

    /// Transmit a bare 802.11 frame at a specific [`McsDescriptor`] rate (builds
    /// the TXWI rate field via [`mt76_rate_val`]). For TX rate/format diagnostics.
    pub fn transmit_mcs(&self, frame: &[u8], mcs: &McsDescriptor) -> Result<(), FaceError> {
        let buf = self.build_tx_bulk(frame, Some(mcs));
        self.handle
            .write_bulk(Self::TX_EP, &buf, BULK_TIMEOUT)
            .map_err(usb_err)?;
        Ok(())
    }

    /// Wrap a 20-byte TXWI + bare 802.11 frame in the mt76x02u USB TX framing:
    /// `[info u32][TXWI][frame][4B tail]`, padded to 4.
    /// info = round_up(TXWI+frame,4) | 80211(b19) | WIV(b24) | QSEL=2(b26).
    fn wrap_tx(&self, txwi: &[u8; 20], frame: &[u8]) -> Vec<u8> {
        let payload_len = txwi.len() + frame.len();
        let info = (((payload_len + 3) & !3) as u32) | (1 << 19) | (1 << 24) | (2 << 25);
        let mut buf = Vec::with_capacity(4 + payload_len + 8);
        buf.extend_from_slice(&info.to_le_bytes());
        buf.extend_from_slice(txwi);
        buf.extend_from_slice(frame);
        buf.extend_from_slice(&[0u8; 4]); // tail
        while buf.len() % 4 != 0 {
            buf.push(0);
        }
        buf
    }

    /// Build a TX bulk for a MANAGEMENT frame (TXWI templated from the captured
    /// probe: ack_ctl=2, wcid=0xfd). `mcs` overrides the rate field. Sent on the
    /// mgmt endpoint (ep 0x07). Used by the TX diagnostics.
    fn build_tx_bulk(&self, frame: &[u8], mcs: Option<&McsDescriptor>) -> Vec<u8> {
        let mut txwi = [0u8; 20];
        txwi.copy_from_slice(&TX_PROBE[4..24]);
        if let Some(m) = mcs {
            txwi[2..4].copy_from_slice(&mt76_rate_val(m).to_le_bytes());
        }
        txwi[6..8].copy_from_slice(&(frame.len() as u16).to_le_bytes()); // len_ctl
        self.wrap_tx(&txwi, frame)
    }

    /// Diagnostic: transmit a DATA frame on the data endpoint (0x04) with the data
    /// TXWI but an explicit raw TXWI rate word (e.g. 0x0000 CCK-1M, 0x2000 OFDM-6M,
    /// 0x4001 HT-MCS1). Isolates whether data-frame radiation depends on the rate.
    pub fn tx_data_at(&self, frame: &[u8], rate: u16) -> Result<(), FaceError> {
        let mut txwi = TXWI_DATA;
        txwi[2..4].copy_from_slice(&rate.to_le_bytes());
        txwi[6..8].copy_from_slice(&(frame.len() as u16).to_le_bytes());
        let buf = self.wrap_tx(&txwi, frame);
        self.handle
            .write_bulk(self.ep_data, &buf, BULK_TIMEOUT)
            .map_err(usb_err)?;
        Ok(())
    }

    /// USB-aggregation: pack several plain-data MPDUs into ONE bulk transfer
    /// (each `[info][TXWI][802.11][tail]` unit padded to 4). Amortizes the fixed
    /// ~0.4ms/transfer over many MPDUs — the RTL's `inject_amsdu_usbagg` lever,
    /// but with plain-data units (which radiate, unlike A-MSDU here). Returns the
    /// bytes written. The device's USB-DMA must chain units by each info.len.
    pub fn tx_data_agg(&self, frames: &[&[u8]], rate: u16) -> Result<usize, FaceError> {
        let mut buf = Vec::new();
        for f in frames {
            let mut txwi = TXWI_DATA;
            txwi[2..4].copy_from_slice(&rate.to_le_bytes());
            txwi[6..8].copy_from_slice(&(f.len() as u16).to_le_bytes());
            buf.extend_from_slice(&self.wrap_tx(&txwi, f));
        }
        self.handle
            .write_bulk(self.ep_data, &buf, BULK_TIMEOUT)
            .map_err(usb_err)
    }

    /// Enable the 2nd TX chain for VHT 2-stream / STBC. Writes the mt76x2 TX-chain
    /// mask `0x0820`: `0x31` = both chains active, `0x11` = single chain (the post-
    /// init default for monitor mode). A VHT-2SS rate word with only one chain
    /// enabled transmits as 1SS (or not at all), so call this before a 2SS sweep.
    pub fn set_tx_chains(&self, two: bool) -> Result<(), FaceError> {
        self.wr(0x0820, if two { 0x31 } else { 0x11 })
    }

    /// Minimize EDCA channel-access overhead for all ACs: AIFSN=1, CWmin=CWmax=0
    /// (no random backoff). The per-MPDU air cycle is preamble + AIFS + backoff +
    /// frame; the default backoff (CWmin exponent → up to ~67µs avg) and AIFS
    /// (~34µs) dominate the ~280µs/transfer fixed overhead on a clean channel. This
    /// strips them — a broadcast NDN bearer has no contention to defer to. Registers
    /// `MT_WMM_AIFSN`(0x0214), `MT_WMM_CWMIN`(0x0218), `MT_WMM_CWMAX`(0x021c); each
    /// holds a 4-bit field per AC [AC0=3:0 .. AC3=15:12]. Diagnostic + throughput.
    pub fn set_edca_aggressive(&self) -> Result<(), FaceError> {
        self.wr(0x0214, 0x0000_1111)?; // AIFSN = 1 for all four ACs
        self.wr(0x0218, 0x0000_0000)?; // CWmin exponent 0 → CW=0 (no backoff)
        self.wr(0x021c, 0x0000_0000)?; // CWmax exponent 0
        Ok(())
    }

    /// Build a TX bulk for a DATA frame. Per the captured kernel data-frame TX,
    /// data frames use a different TXWI than mgmt — **wcid 0xff** (broadcast /
    /// no-station) and **ack_ctl 0** (broadcast → no ACK) — and go on the data AC
    /// endpoint (ep 0x04), NOT the mgmt ep 0x07. Sending a data frame with the
    /// mgmt TXWI on ep 0x07 is silently dropped by the firmware (it never
    /// radiates). `rate` sets the TXWI rate field from the frame's MCS.
    pub fn build_data_bulk(&self, frame: &[u8], mcs: &McsDescriptor) -> Vec<u8> {
        let mut txwi = TXWI_DATA;
        // Rate word + the channel bandwidth (BW[8:7]) the RF is tuned to. A VHT80
        // rate on a 20MHz BB (or vice-versa) is malformed, so the bandwidth comes
        // from `tx_bw` (set by `set_channel_5g80` = 2 = 80MHz), not the descriptor.
        let bw = (self.tx_bw.load(std::sync::atomic::Ordering::Relaxed) as u16 & 0x3) << 7;
        txwi[2..4].copy_from_slice(&(mt76_rate_val(mcs) | bw).to_le_bytes());
        txwi[6..8].copy_from_slice(&(frame.len() as u16).to_le_bytes()); // len_ctl
        self.wrap_tx(&txwi, frame)
    }

    /// Sync-send one DATA frame (build_data_bulk + write to ep_data). For the
    /// MPDU-size cap test: sweep frame sizes past the advertised ~3.8KB max MPDU
    /// and witness on a second MT7612 to see whether oversized MPDUs radiate intact
    /// or truncate at the 12-bit TXWI len_ctl (4095) / VHT max-MPDU (3895).
    pub fn tx_data_sync(&self, frame: &[u8], mcs: &McsDescriptor) -> Result<(), FaceError> {
        let buf = self.build_data_bulk(frame, mcs);
        self.handle
            .write_bulk(self.ep_data, &buf, BULK_TIMEOUT)
            .map_err(usb_err)?;
        Ok(())
    }

    /// Pause (or resume) the background RX-drain. Call `pause_drain(true)` before
    /// consuming frames with `read_rx` so the drain stops stealing them; the drain
    /// is only needed during init for MCU command flow-control.
    pub fn pause_drain(&self, paused: bool) {
        self.drain_pause
            .store(paused, std::sync::atomic::Ordering::Relaxed);
    }

    /// Read one raw bulk-IN transfer (an mt76 RX burst: RXD descriptor + 802.11).
    /// Returns the byte count (0 on timeout). For the first RX-alive check.
    pub fn read_rx(&self, buf: &mut [u8]) -> Result<usize, FaceError> {
        match self.handle.read_bulk(self.ep_in, buf, Duration::from_millis(200)) {
            Ok(n) => Ok(n),
            Err(rusb::Error::Timeout) => Ok(0),
            Err(e) => Err(usb_err(e)),
        }
    }

    /// Firmware build versions parsed from the vendored headers (sanity check the
    /// blobs loaded correctly, no hardware needed).
    pub fn fw_versions(&self) -> (u16, u16) {
        let build = u16::from_le_bytes([RAM_FIRMWARE[8], RAM_FIRMWARE[9]]);
        let ver = u16::from_le_bytes([RAM_FIRMWARE[10], RAM_FIRMWARE[11]]);
        (build, ver)
    }

    /// Set the wire frame format for `FrameIo` (defaults to NDN ethertype).
    pub fn with_format(mut self, format: FrameFormat) -> Self {
        self.format = format;
        self
    }

    /// Decode one raw mt76 RX burst into a [`CapturedFrame`] if it is a frame in
    /// our [`FrameFormat`]. Strips the 36-byte RXD prefix + 4-byte FCE trailer,
    /// lifts RSSI from RXWI byte 18, and reuses the shared `frame::parse_dot11`.
    fn decode_rx(&self, burst: &[u8]) -> Option<CapturedFrame> {
        if burst.len() < MT76_RXD_LEN + 4 + 24 {
            return None;
        }
        let rssi = burst.get(18).map(|&b| b as i8);
        let dot11 = &burst[MT76_RXD_LEN..burst.len() - 4];
        crate::frame::parse_dot11(self.format, dot11, rssi, None)
    }

    /// Build an A-MSDU MPDU body: one QoS-data frame (FC subtype 8, A-MSDU-Present
    /// bit in the QoS control) carrying many `[DA|SA|len|LLC/SNAP|payload]`
    /// subframes (4-byte padded). Standard 802.11 A-MSDU — chip-independent, same
    /// as the RTL backend. This is the broadcast throughput lever (A-MPDU needs a
    /// Block-Ack that broadcast never gets; A-MSDU amortizes per-MPDU overhead).
    fn build_amsdu_body(&self, payloads: &[Bytes], dst: [u8; 6], src: [u8; 6]) -> Result<Vec<u8>, FaceError> {
        use std::sync::atomic::Ordering;
        let ethertype = match self.format {
            FrameFormat::RawNdn { ethertype } => ethertype,
            other => return Err(init_err(format!("mt7612u A-MSDU: format {other:?} unsupported"))),
        };
        let seq = self.seq.fetch_add(1, Ordering::Relaxed) & 0x0fff;
        let mut out = Vec::new();
        out.extend_from_slice(&[0x88, 0x00]); // FC: Data, subtype QoS Data
        out.extend_from_slice(&[0x00, 0x00]); // Duration
        out.extend_from_slice(&dst); // addr1 (RA)
        out.extend_from_slice(&src); // addr2 (TA)
        out.extend_from_slice(&dst); // addr3 (BSSID)
        out.extend_from_slice(&(seq << 4).to_le_bytes()); // SeqCtrl
        out.extend_from_slice(&[0x80, 0x00]); // QoS Ctrl: A-MSDU Present (bit7), TID 0
        let last = payloads.len() - 1;
        for (i, p) in payloads.iter().enumerate() {
            let msdu_len = 8 + p.len(); // LLC/SNAP + payload
            out.extend_from_slice(&dst);
            out.extend_from_slice(&src);
            out.extend_from_slice(&(msdu_len as u16).to_be_bytes()); // Length (big-endian)
            out.extend_from_slice(&[0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00]); // LLC/SNAP
            out.extend_from_slice(&ethertype.to_be_bytes());
            out.extend_from_slice(p);
            if i != last {
                let sub_len = 14 + msdu_len;
                out.extend(std::iter::repeat_n(0u8, (4 - (sub_len % 4)) % 4));
            }
        }
        Ok(out)
    }

    /// Transmit several payloads as one A-MSDU (QoS-data) frame on the data
    /// endpoint. The throughput path for `inject_batch`.
    pub async fn inject_amsdu(
        &self,
        payloads: &[Bytes],
        mcs: McsDescriptor,
        dst: [u8; 6],
        src: [u8; 6],
    ) -> Result<(), FaceError> {
        let body = self.build_amsdu_body(payloads, dst, src)?;
        let buf = self.build_data_bulk(&body, &mcs);
        self.send_bulk(buf).await
    }

    /// Spawn `depth` dedicated TX-pump threads. `inject`/`inject_amsdu` build a USB
    /// bulk + enqueue (no per-frame `spawn_blocking`); each thread locks only for a
    /// fast `try_recv`, then does the slow `write_bulk` OUTSIDE the lock — so up to
    /// `depth` bulk transfers are in flight at once and the host controller
    /// pipelines them, hiding the ~0.37ms per-transfer round-trip that bounds a
    /// single writer. Call after `bring_up`. (Frame order across threads is not
    /// preserved — fine for connectionless NDN broadcast.)
    pub fn spawn_tx_pump(self: &std::sync::Arc<Self>, depth: usize) -> Vec<std::thread::JoinHandle<()>> {
        use std::sync::atomic::Ordering;
        let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
        *self.tx_sender.lock().unwrap() = Some(tx);
        let rx = std::sync::Arc::new(std::sync::Mutex::new(rx));
        (0..depth.max(1))
            .map(|_| {
                let me = self.clone();
                let rx = rx.clone();
                std::thread::spawn(move || loop {
                    let got = rx.lock().unwrap().try_recv();
                    match got {
                        Ok(buf) => {
                            if let Ok(n) =
                                me.handle.write_bulk(me.ep_data, &buf, Duration::from_secs(1))
                            {
                                me.tx_bytes.fetch_add(n as u64, Ordering::Relaxed);
                                me.tx_count.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        Err(std::sync::mpsc::TryRecvError::Empty) => {
                            std::thread::sleep(Duration::from_micros(50));
                        }
                        Err(std::sync::mpsc::TryRecvError::Disconnected) => break,
                    }
                })
            })
            .collect()
    }

    /// Bytes / frames the TX pump has written so far (throughput / drain measurement).
    pub fn tx_bytes_written(&self) -> u64 {
        self.tx_bytes.load(std::sync::atomic::Ordering::Relaxed)
    }
    pub fn tx_count_written(&self) -> u64 {
        self.tx_count.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Create an async USB TX ring on the data endpoint (`max_outstanding` URBs in
    /// flight). The pipelined-transfer path that breaks the ~0.7ms/transfer
    /// synchronous ceiling. Pause the RX drain before saturating TX — the ring's
    /// event thread owns all libusb completions on this context.
    #[cfg(target_os = "linux")]
    pub fn new_tx_ring(&self, max_outstanding: usize) -> std::sync::Arc<TxRing> {
        std::sync::Arc::new(TxRing::new(self.handle.clone(), self.ep_data, max_outstanding))
    }

    /// Send a pre-built USB TX bulk: fast path hands it to the TX pump thread
    /// (no per-frame `spawn_blocking`); otherwise a one-off `spawn_blocking`
    /// `write_bulk`. Used by `inject` and `inject_amsdu`.
    async fn send_bulk(&self, buf: Vec<u8>) -> Result<(), FaceError> {
        let sender = self.tx_sender.lock().unwrap().clone();
        if let Some(s) = sender {
            return s
                .send(buf)
                .map_err(|_| init_err("mt7612u: TX pump closed".into()));
        }
        let ep = self.ep_data;
        let handle = self.handle.clone();
        tokio::task::spawn_blocking(move || {
            handle
                .write_bulk(ep, &buf, Duration::from_secs(1))
                .map_err(usb_err)
                .and_then(|n| {
                    (n == buf.len())
                        .then_some(())
                        .ok_or_else(|| init_err(format!("mt7612u TX: short write {n}/{}", buf.len())))
                })
        })
        .await
        .map_err(|e| init_err(format!("mt7612u TX: join {e}")))?
    }

    /// Spawn `depth` background threads that continuously read the data bulk-IN
    /// endpoint and enqueue decoded frames into `rx_pending` (keeping RX buffers
    /// outstanding so the RX FIFO never stalls — full-rate capture). `recv_frame`
    /// then drains the queue instead of doing its own blocking read. The mt76 USB
    /// continuous-URB analogue; pause the init RX-drain first.
    pub fn spawn_rx_pump(self: &std::sync::Arc<Self>, depth: usize) -> Vec<std::thread::JoinHandle<()>> {
        use std::sync::atomic::Ordering;
        self.pause_drain(true);
        self.rx_pumped.store(true, Ordering::Relaxed);
        (0..depth.max(1))
            .map(|_| {
                let me = self.clone();
                std::thread::spawn(move || {
                    let mut buf = vec![0u8; 16384];
                    loop {
                        match me.handle.read_bulk(me.ep_in, &mut buf, Duration::from_millis(200)) {
                            Ok(n) if n > 0 => {
                                if let Some(cap) = me.decode_rx(&buf[..n]) {
                                    me.rx_pending.lock().unwrap().push_back(cap);
                                    me.rx_notify.notify_one();
                                }
                            }
                            _ => {}
                        }
                    }
                })
            })
            .collect()
    }

    /// On-air-verified maximum single-MPDU 802.11 payload for this chip: plain DATA
    /// frames radiate intact to ~5700 B (6000 B+ are dropped by firmware — see the
    /// size-cap investigation; the margin keeps clear of the cliff). This is the
    /// recommended `MonitorWifiFace::with_mtu` value — bigger frames amortise the
    /// ~300 µs/MPDU fixed overhead (≈142 Mb/s at VHT80 2×2 SGI vs ≈37 at 1500 B).
    /// The A-MSDU/A-MPDU aggregation that would push past this is firmware-gated
    /// (broadcast) / unicast-only on the MT7612 — see docs/AMPDU_PORT_SCOPE.md.
    pub const MAX_MPDU_PAYLOAD: usize = 5650;

    /// One-call bring-up for the high-throughput NDN path: firmware → 5 GHz ch36
    /// VHT80 → both TX chains (2 spatial streams) → background TX pump (pipelined,
    /// RX-compatible — unlike the libusb async ring) → RX pump (continuous capture).
    /// Afterwards the [`FrameIo`] surface injects at full rate and `recv_frame`
    /// drains captured frames. Build the face with `with_mtu(Self::MAX_MPDU_PAYLOAD)`
    /// and inject at a VHT MCS9 2SS short-GI [`McsDescriptor`] for the ~142 Mb/s
    /// ceiling. (Needs a cold device; warm re-open wedges — physical replug.)
    pub fn start_high_throughput(self: &std::sync::Arc<Self>) -> Result<(), FaceError> {
        self.bring_up()?;
        // The 5 GHz blob is a ch6→ch36/80 delta; establish the 2.4 GHz baseline
        // first (a cold device has no prior channel state for the delta to build on).
        self.set_channel_ch6()?;
        self.set_channel_5g80()?;
        self.setup_monitor_rx()?;
        self.set_tx_chains(true)?; // 2 spatial streams (VHT 2SS)
        self.spawn_tx_pump(32); // pipelined TX
        self.spawn_rx_pump(2); // continuous bulk-IN capture
        Ok(())
    }
}

#[async_trait]
impl FrameIo for Mt7612uBackend {
    async fn inject(&self, frame: InjectFrame) -> Result<(), FaceError> {
        let dot11 = crate::frame::build_dot11(self.format, &frame)?;
        // NDN frames are 802.11 DATA frames → data TXWI (wcid 0xff, no-ACK) on the
        // data AC endpoint (0x04). Mgmt TXWI/ep 0x07 would be dropped (see
        // build_data_bulk / docs/RADIO_SUBSYSTEM.md).
        let buf = self.build_data_bulk(&dot11, &frame.mcs);
        self.send_bulk(buf).await
    }

    /// Inject a batch. **Unlike the RTL8812EU, the MT7612 does NOT A-MSDU-bundle
    /// here** — host-built A-MSDU (QoS-data with A-MSDU-present) is firmware-gated
    /// on monitor injection and never radiates (verified 0/200 on air; see
    /// `inject_amsdu` / docs). So each NDN packet goes as its own plain DATA MPDU.
    /// The broadcast throughput levers on this chip are instead:
    ///   1. the background **TX pump** ([`spawn_tx_pump`](Self::spawn_tx_pump)),
    ///      which pipelines these per-frame injects (RX-compatible, unlike the
    ///      libusb async ring), and
    ///   2. a **large send MTU** — plain frames radiate intact to ~5700 B
    ///      ([`MAX_MPDU_PAYLOAD`](Self::MAX_MPDU_PAYLOAD)), so the link service
    ///      packs more NDN bytes per frame and amortises the ~300 µs/MPDU fixed
    ///      overhead → ~142 Mb/s at VHT80 2×2 SGI (vs ~37 Mb/s at a 1500 B MTU).
    async fn inject_batch(&self, frames: Vec<InjectFrame>) -> Result<(), FaceError> {
        for f in frames {
            self.inject(f).await?;
        }
        Ok(())
    }

    async fn recv_frame(&self) -> Result<CapturedFrame, FaceError> {
        use std::sync::atomic::Ordering;
        // Pumped mode: background threads (spawn_rx_pump) fill rx_pending; just
        // drain it, waking on the notify. Full-rate, no per-call blocking read.
        if self.rx_pumped.load(Ordering::Relaxed) {
            loop {
                if let Some(cap) = self.rx_pending.lock().unwrap().pop_front() {
                    return Ok(cap);
                }
                let notified = self.rx_notify.notified();
                if let Some(cap) = self.rx_pending.lock().unwrap().pop_front() {
                    return Ok(cap);
                }
                let _ = tokio::time::timeout(Duration::from_millis(200), notified).await;
            }
        }
        loop {
            let handle = self.handle.clone();
            let ep = self.ep_in;
            let burst = tokio::task::spawn_blocking(move || {
                let mut b = vec![0u8; 8192];
                match handle.read_bulk(ep, &mut b, Duration::from_millis(200)) {
                    Ok(n) => {
                        b.truncate(n);
                        Ok(Some(b))
                    }
                    Err(rusb::Error::Timeout) => Ok(None),
                    Err(e) => Err(usb_err(e)),
                }
            })
            .await
            .map_err(|e| init_err(format!("mt7612u recv_frame: join {e}")))??;
            let Some(burst) = burst else { continue };
            if let Some(cap) = self.decode_rx(&burst) {
                return Ok(cap);
            }
            // else: timeout, or not a frame in our format (beacon/other) — keep reading
        }
    }
}
