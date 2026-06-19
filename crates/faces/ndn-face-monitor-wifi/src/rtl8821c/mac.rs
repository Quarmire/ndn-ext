//! RTL8821CU post-firmware MAC initialization — ported from rtw88 `rtw_mac_init`
//! (`mac.c`) + `rtw8821c_mac_init` (`rtw8821c.c`), with every `WLAN_*`/`FAST_EDCA_*`
//! macro resolved to its literal value. See reference §4.
//!
//! Single-endpoint note: this dongle exposes one bulk-OUT endpoint, but mainline
//! rtw88 only maps USB `bulkout_num ∈ {2,3,4}`. We therefore use the **index-[1]**
//! (PCIe/default) `rqpn`/`page_table` profile and route every queue to the one
//! endpoint — the page math still balances (pubq = 397, rsvd_boundary = 460).

use std::time::Duration;

use ndn_transport::FaceError;

use super::Rtl8821cuBackend;

impl Rtl8821cuBackend {
    /// Full MAC init: TRX FIFO/queue config → chip MAC register group → H2C ring
    /// → driver-info config. Run after firmware download, before the PHY tables.
    pub fn mac_init(&self) -> Result<(), FaceError> {
        self.init_trx_cfg()?;
        self.mac_init_regs()?;
        self.drv_info_cfg()
        // NOTE: hci_usb_cfg (RX burst+agg) runs LAST in bring_up, matching the
        // kernel's rtw_hci_start ordering — done before the PHY tables it would
        // be clobbered by the BB table load / channel set.
    }

    /// USB-specific HCI config: `rtw_usb_init_burst_pkt_len` (the RXDMA burst
    /// mode — without this the chip does not DMA received frames to bulk-IN) and
    /// `rtw_usb_dynamic_rx_agg_v1(enable)`. Burst size is for HIGH-speed (USB 2.0,
    /// what these dongles are). Called last in bring_up. See rtw88 usb.c:876/902.
    pub(super) fn hci_usb_cfg(&self) -> Result<(), FaceError> {
        // A/B isolation: `NDN_RADIO_NO_RXCFG=1` skips this step entirely.
        if std::env::var("NDN_RADIO_NO_RXCFG").is_ok() {
            return Ok(());
        }
        // rxdma = BIT_DMA_BURST_CNT(0x0C) | BIT_DMA_MODE(0x02) | burst_512(1<<4)
        self.write8(0x0290, 0x1e)?; // REG_RXDMA_MODE
        let v = self.read16(0x020c)?;
        self.write16(0x020c, v | 0x0200)?; // TXDMA_OFFSET_CHK |= BIT_DROP_DATA_EN
        // dynamic_rx_agg_v1(enable=true)
        self.set8(0x010c, 1 << 2)?; // TXDMA_PQ_MAP |= BIT_RXDMA_AGG_EN
        self.clr8(0x0283, 1 << 7)?; // RXDMA_AGG_PG_TH+3 clr BIT(7)
        // Match the golden monitor trace: agg minimal (size=0, timeout=1 → frames
        // delivered immediately) rather than the size=5 batching default.
        self.write16(0x0280, 0x0100)?;
        Ok(())
    }

    /// `rtw_init_trx_cfg`: queue→DMA mapping + priority-queue page allocation +
    /// H2C ring, for the index-[1] profile (vo/vi=NORMAL, be/bk=LOW, mg=EXTRA,
    /// hi=HIGH; pages hq16/lq16/nq16/exq14/pubq397).
    fn init_trx_cfg(&self) -> Result<(), FaceError> {
        // txdma_queue_mapping: REG_TXDMA_PQ_MAP = 0xC5A0 (rqpn[1]).
        self.write16(0x010c, 0xc5a0)?;
        self.write8(0x0100, 0x00)?; // REG_CR = 0
        // REG_CR = MAC_TRX_ENABLE(0xff) | MAC_SEC_EN(bit9) | 32K_CAL_TMR_EN(bit10),
        // matching the golden monitor trace's 16-bit 0x06ff.
        self.write16(0x0100, 0x06ff)?;
        self.write32(0x1330, 0x8000_0000)?; // REG_H2CQ_CSR = BIT_H2CQ_FULL (3081)
        let pqmap = self.read16(0x010c)?;
        self.write16(0x010c, pqmap | 0x0001)?; // |= BIT_RXDMA_ARBBW_EN

        // __priority_queue_cfg (page_table[1]).
        self.write16(0x0230, 16)?; // FIFOPAGE_INFO_1 hq_num
        self.write16(0x0234, 16)?; // FIFOPAGE_INFO_2 lq_num
        self.write16(0x0238, 16)?; // FIFOPAGE_INFO_3 nq_num
        self.write16(0x023c, 14)?; // FIFOPAGE_INFO_4 exq_num
        self.write16(0x0240, 397)?; // FIFOPAGE_INFO_5 pubq_num
        self.set32(0x022c, 0x8000_0000)?; // RQPN_CTRL_2 |= BIT_LD_RQPN
        self.write16(0x0204, 460)?; // FIFOPAGE_CTRL_2 = rsvd_boundary
        self.set8(0x0422, 1 << 4)?; // FWHW_TXQ_CTRL+2 |= EN_WR_FREE_TAIL>>16
        self.write16(0x0424, 460)?; // BCNQ_BDNY_V1
        self.write16(0x0206, 460)?; // FIFOPAGE_CTRL_2+2
        self.write16(0x0456, 460)?; // BCNQ1_BDNY_V1
        self.write32(0x011c, 16127)?; // RXFF_BNDY = rxff_size - C2H_PKT_BUF - 1
        // USB-specific:
        self.write8_mask(0x0208, 0xf0, 3 << 4)?; // AUTO_LLT_V1 BLK_DESC_NUM = 3
        self.write8(0x020b, 3)?; // AUTO_LLT_V1+3 = usb_tx_agg_desc_num
        self.set8(0x020d, 1 << 1)?; // TXDMA_OFFSET_CHK+1 |= BIT(1)
        // LLT auto-init + wait for completion.
        self.set8(0x0208, 1 << 0)?; // AUTO_LLT_V1 |= BIT_AUTO_INIT_LLT_V1
        self.poll32(0x0208, 1, 0, 1000, Duration::from_micros(10))?;
        self.write8(0x0103, 0x00)?; // REG_CR+3 = 0

        self.init_h2c()
    }

    /// `init_h2c`: point the H2C ring at the reserved h2cq page (500<<7 = 0xFA00,
    /// size 8<<7 = 0x400 → tail 0xFE00).
    fn init_h2c(&self) -> Result<(), FaceError> {
        let head = self.read32(0x0244)?;
        self.write32(0x0244, (head & 0xfffc_0000) | 0xfa00)?; // REG_H2C_HEAD
        let read_addr = self.read32(0x024c)?;
        self.write32(0x024c, (read_addr & 0xfffc_0000) | 0xfa00)?; // REG_H2C_READ_ADDR
        let tail = self.read32(0x0248)?;
        self.write32(0x0248, (tail & 0xfffc_0000) | 0xfe00)?; // REG_H2C_TAIL
        let info = self.read8(0x0254)?;
        self.write8(0x0254, (info & 0xfc) | 0x01)?; // REG_H2C_INFO
        let info = self.read8(0x0254)?;
        self.write8(0x0254, (info & 0xfb) | 0x04)?;
        let chk = self.read8(0x020d)?;
        self.write8(0x020d, (chk & 0x7f) | 0x80)?; // REG_TXDMA_OFFSET_CHK+1
        Ok(())
    }

    /// `rtw8821c_mac_init`: the chip-specific protocol/EDCA/beacon/WMAC register
    /// group, all `WLAN_*` values resolved.
    fn mac_init_regs(&self) -> Result<(), FaceError> {
        // protocol
        self.write8(0x0455, 0x70)?; // AMPDU_MAX_TIME_V1
        self.set8(0x045e, 1 << 2)?; // TX_HANG_CTRL |= EN_EOF_V1
        self.write8(0x04e5, 0xe4)?; // PRECNT_CTRL lo (pre_txcnt 0x09E4)
        self.write8(0x04e6, 0x09)?; // PRECNT_CTRL hi
        self.write32(0x04c8, 0x2020_08ff)?; // PROT_MODE_CTRL
        self.write16(0x04ce, 0x0801)?; // BAR_MODE_CTRL+2
        self.write8(0x1448, 0x06)?; // FAST_EDCA_VOVI VO_TH
        self.write8(0x144a, 0x06)?; // FAST_EDCA_VOVI VI_TH
        self.write8(0x144c, 0x06)?; // FAST_EDCA_BEBK BE_TH
        self.write8(0x144e, 0x06)?; // FAST_EDCA_BEBK BK_TH
        self.set8(0x0480, 1 << 5)?; // INIRTS_RATE_SEL |= BIT(5)
        // EDCA
        self.clr8(0x05b4, (1 << 4) | (1 << 5) | (1 << 6))?; // TIMER0_SRC_SEL clr TSFT_SEL
        self.write16(0x0522, 0x0000)?; // TXPAUSE
        self.write8(0x051b, 0x09)?; // SLOT
        self.write8(0x0512, 0x19)?; // PIFS
        self.write32(0x0514, 0x100e_0e0a)?; // SIFS
        self.write16(0x0502, 0x0186)?; // EDCA_VO_PARAM+2 (VO TXOP)
        self.write16(0x0506, 0x03bc)?; // EDCA_VI_PARAM+2 (VI TXOP)
        self.write32(0x0544, 0x001b_0005)?; // RD_NAV_NXT
        self.write16(0x055e, 0x3030)?; // RXTSF_OFFSET_CCK
        // beacon
        self.set8(0x0550, 1 << 3)?; // BCN_CTRL |= EN_BCN_FUNCTION
        self.write32(0x0540, 0x0000_6404)?; // TBTT_PROHIBIT
        self.write8(0x0558, 0x04)?; // DRVERLYINT
        self.write8(0x0559, 0x02)?; // BCNDMATIM
        self.clr8(0x0521, 1 << 4)?; // TX_PTCL_CTRL+1 clr SIFS_BK_EN>>8
        // WMAC
        self.write16(0x06a0, 0xffff)?; // RXFLTMAP0
        self.write16(0x06a2, 0x0fff)?; // RXFLTMAP1
        self.write16(0x06a4, 0xffff)?; // RXFLTMAP2
        self.write32(0x0608, 0xe400_220e)?; // RCR = WLAN_RCR_CFG
        self.write8(0x060c, 0x18)?; // RX_PKT_LIMIT (24)
        self.write8(0x0606, 0x30)?; // TCR+2
        self.write8(0x0605, 0x30)?; // TCR+1
        self.write8(0x0639, 0x40)?; // ACKTO_CCK
        self.set8(0x066c, 1 << 1)?; // WMAC_TRXPTCL_CTL_H |= BIT(1)
        self.set8(0x0718, 1 << 6)?; // SND_PTCL_CTRL |= DIS_CHK_VHTSIGB_CRC
        self.write32(0x07d8, 0xb081_0041)?; // WMAC_OPTION_FUNCTION+8
        self.write8(0x07d4, 0x98)?; // WMAC_OPTION_FUNCTION+4
        Ok(())
    }

    /// `rtw_drv_info_cfg`: PHY-status drv-info size + append-physts.
    fn drv_info_cfg(&self) -> Result<(), FaceError> {
        self.write8(0x060f, 0x04)?; // RX_DRVINFO_SZ = PHY_STATUS_SIZE
        self.write8_mask(0x0115, 0x0f, 0x0f)?; // TRXFF_BNDY+1 low nibble = 0xF
        self.set32(0x0608, 1 << 28)?; // RCR |= APP_PHYSTS
        self.clr32(0x07d4, (1 << 8) | (1 << 9))?; // WMAC_OPTION_FUNCTION+4 clr [9:8]
        Ok(())
    }
}
