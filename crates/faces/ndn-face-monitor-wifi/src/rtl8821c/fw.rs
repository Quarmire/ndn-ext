//! RTL8821CU firmware download — the **DDMA path** for the 3081 WCPU (not the
//! legacy 8051 FIFO path). Firmware bytes ride a reserved-page TX packet on the
//! beacon-queue bulk-OUT endpoint; an on-chip DDMA engine then copies them from
//! TXBUF into DMEM/IMEM/EMEM with a hardware checksum. Ported from rtw88
//! `mac.c` (`__rtw_download_firmware` and friends) — see reference §2 and the
//! exhaustive constant table that accompanied this port. Diff the emitted writes
//! against `golden_8821cu_init.pcap` (`NDN_RADIO_LOG_WRITES=1`).
//!
//! Needed for the firmware-offloaded IQK and for TX; monitor RX does not require it.

use std::time::Duration;

use ndn_transport::FaceError;

use super::{Rtl8821cuBackend, init_err, txdesc_checksum, txdesc_set};

/// Vendored from linux-firmware `rtw88/rtw8821c_fw.bin` (header signature 0x8821).
const FIRMWARE: &[u8] = include_bytes!("../../fw/8821c/rtw8821c_fw.bin");

const FW_HDR_SIZE: usize = 64;
const FW_HDR_CHKSUM_SIZE: usize = 8;

// Registers / bits (resolved from rtw88 reg.h / mac.h).
const REG_SYS_FUNC_EN_1: u16 = 0x0003;
const BIT_FEN_CPUEN: u8 = 0x04;
const REG_RSV_CTRL_1: u16 = 0x001d;
const BIT_WLMCU_IOIF: u8 = 0x01;
const REG_SYS_CLK_CTRL_1: u16 = 0x0009;
const BIT_CPU_CLK_EN_HI: u8 = 0x40; // BIT(14) >> 8
const REG_CPU_DMEM_CON_2: u16 = 0x1082;
const BIT_WL_PLATFORM_RST_HI: u8 = 0x01; // BIT(16) >> 16
const REG_TXDMA_PQ_MAP_1: u16 = 0x010d;
const REG_CR: u16 = 0x0100;
const REG_CR_1: u16 = 0x0101;
const BIT_ENSWBCN_HI: u8 = 0x01; // BIT(8) >> 8
const MAC_TX_RX_DMA_EN: u8 = 0x05; // BIT_HCI_TXDMA_EN | BIT_TXDMA_EN
const REG_H2CQ_CSR: u16 = 0x1330;
const BIT_H2CQ_FULL: u32 = 0x8000_0000;
const REG_FIFOPAGE_INFO_1: u16 = 0x0230;
const REG_RQPN_CTRL_2: u16 = 0x022c;
const BIT_LD_RQPN: u32 = 0x8000_0000;
const REG_BCN_CTRL: u16 = 0x0550;
const BIT_EN_BCN_FUNCTION: u8 = 0x08;
const BIT_DIS_TSF_UDT: u8 = 0x10;
const REG_FIFOPAGE_CTRL_2: u16 = 0x0204;
const BIT_BCN_VALID_V1: u16 = 0x8000;
const REG_MCUFW_CTRL: u16 = 0x0080;
const BIT_MCUFWDL_EN: u16 = 0x0001;
const BIT_FW_DW_RDY: u16 = 0x4000;
const BIT_CHECK_SUM_OK: u16 = 0x0050;
const FW_READY: u16 = 0xc078;
const FW_READY_MASK: u16 = 0xcfff;
const REG_TXDMA_STATUS: u16 = 0x0210;
const BTI_PAGE_OVF: u32 = 0x04;
const REG_FW_DBG7: u16 = 0x10fc;
const FW_KEY_MASK: u32 = 0xffff_ff00;
const ILLEGAL_KEY_GROUP: u32 = 0xfaaa_aa00;
const REG_DDMA_CH0SA: u16 = 0x1200;
const REG_DDMA_CH0DA: u16 = 0x1204;
const REG_DDMA_CH0CTRL: u16 = 0x1208;
const BIT_DDMACH0_OWN: u32 = 0x8000_0000;
const BIT_DDMACH0_CHKSUM_EN: u32 = 0x2000_0000;
const BIT_DDMACH0_CHKSUM_STS: u32 = 0x0800_0000;
const BIT_DDMACH0_RESET_CHKSUM_STS: u32 = 0x0200_0000;
const BIT_DDMACH0_CHKSUM_CONT: u32 = 0x0100_0000;
const DDMACH0_DLEN_MASK: u32 = 0x3_ffff;

const OCPBASE_TXBUF: u32 = 0x1878_0000;
const TX_DESC_SIZE: usize = 48;
const CHUNK: usize = 0x1000;
/// DDMA source is constant: TXBUF base + the 48-byte rsvd-page descriptor.
const DDMA_SRC: u32 = OCPBASE_TXBUF + TX_DESC_SIZE as u32;

struct FwHdr {
    emem_present: bool,
    dmem_addr: u32,
    dmem_size: u32,
    imem_size: u32,
    imem_addr: u32,
    emem_size: u32,
    emem_addr: u32,
}

fn rd32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn parse_hdr(fw: &[u8]) -> FwHdr {
    FwHdr {
        emem_present: fw[0x18] & 0x10 != 0, // mem_usage BIT(4)
        dmem_addr: rd32(fw, 0x20),
        dmem_size: rd32(fw, 0x24),
        imem_size: rd32(fw, 0x30),
        emem_size: rd32(fw, 0x34),
        emem_addr: rd32(fw, 0x38),
        imem_addr: rd32(fw, 0x3c),
    }
}

impl Rtl8821cuBackend {
    /// Download the vendored firmware and wait for the FW-ready handshake.
    pub fn download_firmware(&self) -> Result<(), FaceError> {
        let fw = FIRMWARE;
        if fw.len() < FW_HDR_SIZE {
            return Err(init_err("8821cu fw too small".into()));
        }
        let hdr = parse_hdr(fw);

        // Validate the file image is hdr + per-region (size + 8B checksum).
        let dmem = hdr.dmem_size as usize + FW_HDR_CHKSUM_SIZE;
        let imem = hdr.imem_size as usize + FW_HDR_CHKSUM_SIZE;
        let emem = if hdr.emem_present {
            hdr.emem_size as usize + FW_HDR_CHKSUM_SIZE
        } else {
            0
        };
        if FW_HDR_SIZE + dmem + imem + emem != fw.len() {
            return Err(init_err(format!(
                "8821cu fw size mismatch: hdr+{dmem}+{imem}+{emem} != {}",
                fw.len()
            )));
        }

        self.wlan_cpu_enable(false)?;
        let bckp = self.dlfw_reg_backup()?;
        self.dlfw_reset_platform()?;

        // start_download_firmware: enable FWDL (preserve CPU_CLK_SEL bits).
        let v = (self.read16(REG_MCUFW_CTRL)? & 0x3800) | BIT_MCUFWDL_EN;
        self.write16(REG_MCUFW_CTRL, v)?;

        // DMEM, IMEM, then EMEM — each region's source steps past hdr + prior
        // regions (sizes include the 8B trailing checksum the HW verifies).
        let mut cur = FW_HDR_SIZE;
        self.download_region(&fw[cur..cur + dmem], hdr.dmem_addr & !(1 << 31))?;
        cur += dmem;
        self.download_region(&fw[cur..cur + imem], hdr.imem_addr & !(1 << 31))?;
        cur += imem;
        if hdr.emem_present {
            self.download_region(&fw[cur..cur + emem], hdr.emem_addr & !(1 << 31))?;
        }

        self.dlfw_reg_restore(&bckp)?;
        self.dlfw_end_flow()?;
        self.wlan_cpu_enable(true)?;
        self.dlfw_validate()
    }

    fn wlan_cpu_enable(&self, enable: bool) -> Result<(), FaceError> {
        if enable {
            self.set8(REG_RSV_CTRL_1, BIT_WLMCU_IOIF)?;
            self.set8(REG_SYS_FUNC_EN_1, BIT_FEN_CPUEN)
        } else {
            self.clr8(REG_SYS_FUNC_EN_1, BIT_FEN_CPUEN)?;
            self.clr8(REG_RSV_CTRL_1, BIT_WLMCU_IOIF)
        }
    }

    /// Back up the 6 registers the download path clobbers, and arm them.
    fn dlfw_reg_backup(&self) -> Result<[(u16, u32, u8); 6], FaceError> {
        // (addr, saved_value, width) — width 1 or 4.
        let pqmap = self.read8(REG_TXDMA_PQ_MAP_1)?;
        self.write8(REG_TXDMA_PQ_MAP_1, 0xc0)?; // HIQ → high priority

        let cr = self.read8(REG_CR)?;
        let h2cq = self.read32(REG_H2CQ_CSR)?;
        self.write8(REG_CR, MAC_TX_RX_DMA_EN)?;
        self.write32(REG_H2CQ_CSR, BIT_H2CQ_FULL)?;

        let info1 = self.read16(REG_FIFOPAGE_INFO_1)? as u32;
        let rqpn = self.read32(REG_RQPN_CTRL_2)?;
        self.write16(REG_FIFOPAGE_INFO_1, 0x200)?;
        self.write32(REG_RQPN_CTRL_2, rqpn | BIT_LD_RQPN)?;

        let bcn = self.read8(REG_BCN_CTRL)?;
        self.write8(REG_BCN_CTRL, (bcn & !BIT_EN_BCN_FUNCTION) | BIT_DIS_TSF_UDT)?;

        Ok([
            (REG_TXDMA_PQ_MAP_1, pqmap as u32, 1),
            (REG_CR, cr as u32, 1),
            (REG_H2CQ_CSR, h2cq, 4),
            (REG_FIFOPAGE_INFO_1, info1, 2),
            (REG_RQPN_CTRL_2, rqpn, 4),
            (REG_BCN_CTRL, bcn as u32, 1),
        ])
    }

    fn dlfw_reg_restore(&self, bckp: &[(u16, u32, u8); 6]) -> Result<(), FaceError> {
        for &(addr, val, width) in bckp {
            match width {
                1 => self.write8(addr, val as u8)?,
                2 => self.write16(addr, val as u16)?,
                _ => self.write32(addr, val)?,
            }
        }
        Ok(())
    }

    fn dlfw_reset_platform(&self) -> Result<(), FaceError> {
        self.clr8(REG_CPU_DMEM_CON_2, BIT_WL_PLATFORM_RST_HI)?;
        self.clr8(REG_SYS_CLK_CTRL_1, BIT_CPU_CLK_EN_HI)?;
        self.set8(REG_CPU_DMEM_CON_2, BIT_WL_PLATFORM_RST_HI)?;
        self.set8(REG_SYS_CLK_CTRL_1, BIT_CPU_CLK_EN_HI)
    }

    /// Download one memory region: chunk it (≤4 KB), pushing each chunk to the
    /// reserved page then triggering the DDMA copy with a running checksum.
    fn download_region(&self, data: &[u8], dst: u32) -> Result<(), FaceError> {
        // reset checksum status for this region
        self.set32(REG_DDMA_CH0CTRL, BIT_DDMACH0_RESET_CHKSUM_STS)?;
        let mut off = 0usize;
        let mut first = true;
        while off < data.len() {
            let len = CHUNK.min(data.len() - off);
            self.send_firmware_pkt(&data[off..off + len])?;
            self.iddma(DDMA_SRC, dst + off as u32, len as u32, first)?;
            first = false;
            off += len;
        }
        self.check_fw_checksum(dst)
    }

    /// Push a firmware chunk to the reserved page: prepend a 48-byte beacon-queue
    /// TX descriptor, run the beacon-valid handshake, and bulk it out.
    fn send_firmware_pkt(&self, chunk: &[u8]) -> Result<(), FaceError> {
        let mut size = chunk.len();
        // USB +1 pad when (size + desc) is an exact multiple of 512.
        let pad = if (size + TX_DESC_SIZE) % 512 == 0 { 1 } else { 0 };

        let mut pkt = vec![0u8; TX_DESC_SIZE + size + pad];
        size += pad;
        txdesc_set(&mut pkt, 0, 0, 16, size as u32); // TXPKTSIZE
        txdesc_set(&mut pkt, 0, 16, 8, TX_DESC_SIZE as u32); // OFFSET
        txdesc_set(&mut pkt, 0, 26, 1, 1); // LS
        txdesc_set(&mut pkt, 1, 8, 5, 16); // QSEL = BEACON
        txdesc_checksum(&mut pkt);
        pkt[TX_DESC_SIZE..TX_DESC_SIZE + chunk.len()].copy_from_slice(chunk);

        // rtw_fw_write_data_rsvd_page: arm page 0, do the write, poll BCN_VALID.
        let bcn = self.read8(REG_BCN_CTRL)?;
        self.write16(REG_FIFOPAGE_CTRL_2, BIT_BCN_VALID_V1)?; // head 0 + clear valid
        self.set8(REG_CR_1, BIT_ENSWBCN_HI)?;
        self.write8(REG_BCN_CTRL, (bcn & !BIT_EN_BCN_FUNCTION) | BIT_DIS_TSF_UDT)?;

        self.bulk_write(&pkt)?;

        // poll BCN_VALID set
        let mut ok = false;
        for _ in 0..200 {
            if self.read16(REG_FIFOPAGE_CTRL_2)? & BIT_BCN_VALID_V1 != 0 {
                ok = true;
                break;
            }
            std::thread::sleep(Duration::from_micros(100));
        }
        // restore
        self.write16(REG_FIFOPAGE_CTRL_2, BIT_BCN_VALID_V1)?;
        self.write8(REG_BCN_CTRL, bcn)?;
        self.clr8(REG_CR_1, BIT_ENSWBCN_HI)?;
        if !ok {
            return Err(init_err("8821cu fw rsvd-page: BCN_VALID never set".into()));
        }
        Ok(())
    }

    /// Trigger a DDMA CH0 copy and wait for it to release ownership.
    fn iddma(&self, src: u32, dst: u32, len: u32, first: bool) -> Result<(), FaceError> {
        // wait ready
        self.poll32(REG_DDMA_CH0CTRL, BIT_DDMACH0_OWN, 0, 1000, Duration::from_micros(10))?;
        let mut ctrl = BIT_DDMACH0_CHKSUM_EN | BIT_DDMACH0_OWN | (len & DDMACH0_DLEN_MASK);
        if !first {
            ctrl |= BIT_DDMACH0_CHKSUM_CONT;
        }
        self.write32(REG_DDMA_CH0SA, src)?;
        self.write32(REG_DDMA_CH0DA, dst)?;
        self.write32(REG_DDMA_CH0CTRL, ctrl)?;
        self.poll32(REG_DDMA_CH0CTRL, BIT_DDMACH0_OWN, 0, 1000, Duration::from_micros(10))
    }

    /// Verify the region's hardware checksum and latch the DW/CHKSUM-OK bits.
    fn check_fw_checksum(&self, dst: u32) -> Result<(), FaceError> {
        let mut mcu = self.read8(REG_MCUFW_CTRL)?;
        let is_imem = dst < 0x0020_0000; // OCPBASE_DMEM threshold
        let (dw_ok, chk_ok) = if is_imem { (0x08u8, 0x10u8) } else { (0x20u8, 0x40u8) };
        if self.read32(REG_DDMA_CH0CTRL)? & BIT_DDMACH0_CHKSUM_STS != 0 {
            // checksum failed: set DW_OK, clear CHKSUM_OK
            mcu = (mcu | dw_ok) & !chk_ok;
            self.write8(REG_MCUFW_CTRL, mcu)?;
            return Err(init_err(format!("8821cu fw checksum fail (dst={dst:#x})")));
        }
        mcu |= dw_ok | chk_ok;
        self.write8(REG_MCUFW_CTRL, mcu)
    }

    fn dlfw_end_flow(&self) -> Result<(), FaceError> {
        self.write32(REG_TXDMA_STATUS, BTI_PAGE_OVF)?;
        let fw_ctrl = self.read16(REG_MCUFW_CTRL)?;
        if (fw_ctrl & BIT_CHECK_SUM_OK) == BIT_CHECK_SUM_OK {
            let v = (fw_ctrl | BIT_FW_DW_RDY) & !BIT_MCUFWDL_EN;
            self.write16(REG_MCUFW_CTRL, v)?;
        }
        Ok(())
    }

    fn dlfw_validate(&self) -> Result<(), FaceError> {
        for _ in 0..1000 {
            if (self.read16(REG_MCUFW_CTRL)? & FW_READY_MASK) == FW_READY {
                return Ok(());
            }
            std::thread::sleep(Duration::from_micros(50));
        }
        let dbg = self.read32(REG_FW_DBG7)? & FW_KEY_MASK;
        if dbg == ILLEGAL_KEY_GROUP {
            return Err(init_err("8821cu fw not ready: invalid fw key (wrong firmware)".into()));
        }
        Err(init_err("8821cu fw not ready (download_firmware_validate timeout)".into()))
    }
}
