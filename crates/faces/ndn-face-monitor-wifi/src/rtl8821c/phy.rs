//! RTL8821CU per-channel PHY programming, TX-power-index write, and the
//! firmware-offloaded IQK — ported from rtw88 `rtw8821c.c` / `phy.c` / `fw.c`.
//! See reference §7/§8/§9. Path A only (1×1 chip); 20 MHz monitor.
//!
//! TX power: the full rtw88 power-by-rate/limit pipeline is not yet ported.
//! Instead we write a uniform per-rate index (default mid-range, overridable
//! with `NDN_RADIO_TXPWR`) into the `0x1d00` TXAGC block — the 8812EU work
//! identified the *absence* of any TXAGC write as the radiate gate, so writing a
//! sane index is what matters for first on-air TX. Regulatory power-by-rate is a
//! follow-up (the `bb_pg`/`txpwr_lmt` tables are already generated).

use std::time::Duration;

use ndn_transport::FaceError;

use super::{
    RF_CFGCH, RF_LUTDBG, RF_XTALX2, RFREG_MASK, Rtl8821cuBackend, TX_DESC_SIZE, init_err,
    txdesc_checksum, txdesc_set,
};

/// RF front-end switch target (`rtw8821c_switch_rf_set`).
enum RfSet {
    Wla, // 5 GHz
    Wlg, // 2.4 GHz, WL-only antenna path
    Btg, // 2.4 GHz, BT-shared (BTG) antenna/LNA path
}

/// Mask helper: clear `mask`, OR `val` shifted to the mask's first set bit.
fn ins(cur: u32, mask: u32, val: u32) -> u32 {
    (cur & !mask) | ((val << mask.trailing_zeros()) & mask)
}

impl Rtl8821cuBackend {
    /// `rtw8821c_set_channel_rf` (rtw8821c.c:313): route the RF front-end
    /// (`switch_rf_set` — the step whose absence left the receiver deaf), program
    /// `RF 0x18` band/channel/RFSI/BW20, and reload the PLL.
    pub(super) fn set_channel_rf(&self, channel: u8) -> Result<(), FaceError> {
        const RF18_BAND_MASK: u32 = (1 << 16) | (1 << 9) | (1 << 8);
        const RF18_BAND_5G: u32 = (1 << 16) | (1 << 8);
        const RF18_CHANNEL_MASK: u32 = 0xff;
        const RF18_RFSI_MASK: u32 = (1 << 18) | (1 << 17);
        const RF18_BW_MASK: u32 = (1 << 11) | (1 << 10);
        const RF18_BW_20M: u32 = (1 << 11) | (1 << 10);

        let is_5g = channel > 14;
        let mut cfgch = self.read_rf(RF_CFGCH, RFREG_MASK)?;
        cfgch &= !(RF18_BAND_MASK | RF18_CHANNEL_MASK | RF18_RFSI_MASK | RF18_BW_MASK);
        cfgch |= if is_5g { RF18_BAND_5G } else { 0 };
        cfgch |= (channel as u32) & RF18_CHANNEL_MASK;
        if (100..=140).contains(&channel) {
            cfgch |= 1 << 17; // RFSI_GE
        } else if channel > 140 {
            cfgch |= 1 << 18; // RFSI_GT
        }
        cfgch |= RF18_BW_20M;

        // Front-end routing (rtw8821c_set_channel_rf): 5 GHz → WLA; 2.4 GHz → BTG
        // if the efuse rfe_option says the antenna is BT-shared, else WLG.
        // `NDN_RADIO_BTG=1`/`NDN_RADIO_WLG=1` override for bench testing.
        if is_5g {
            self.switch_rf_set(RfSet::Wla)?;
            self.write_rf(RF_LUTDBG, 1 << 6, 0)?;
        } else {
            let btg = if std::env::var("NDN_RADIO_WLG").is_ok() {
                false
            } else if std::env::var("NDN_RADIO_BTG").is_ok() {
                true
            } else {
                self.rfe_btg.load(std::sync::atomic::Ordering::Relaxed)
            };
            self.switch_rf_set(if btg { RfSet::Btg } else { RfSet::Wlg })?;
            self.write_rf(RF_LUTDBG, 1 << 6, 1)?;
            self.write_rf(0x64, 0xf, 0xf)?;
        }
        self.write_rf(RF_CFGCH, RFREG_MASK, cfgch)?;
        // PLL reload: RF_XTALX2 BIT19 0→1.
        self.write_rf(RF_XTALX2, 1 << 19, 0)?;
        self.write_rf(RF_XTALX2, 1 << 19, 1)
    }

    /// `rtw8821c_switch_rf_set` (rtw8821c.c:279): steer the RF front-end switch
    /// (REG_RFECTL) + CCA/LNA to the WL antenna path for the band. Without this
    /// the 5 GHz LNA/switch is not selected and nothing is received.
    fn switch_rf_set(&self, set: RfSet) -> Result<(), FaceError> {
        const REG_SYS_CTRL: u16 = 0x0000;
        const BIT_FEN_EN: u32 = 1 << 26;
        const REG_DMEM_CTRL: u16 = 0x1080;
        const BIT_WL_RST: u32 = 1 << 16;
        const REG_RFECTL: u16 = 0x0cb8;
        const REG_ENRXCCA: u16 = 0x0a84;
        const REG_ENTXCCK: u16 = 0x0a80;
        const B_BTG_SWITCH: u32 = 1 << 16;
        const B_CTRL_SWITCH: u32 = 1 << 18;
        const B_WL_SWITCH: u32 = (1 << 20) | (1 << 22);
        const B_WLG_SWITCH: u32 = 1 << 21;
        const B_WLA_SWITCH: u32 = 1 << 23;

        self.set32(REG_DMEM_CTRL, BIT_WL_RST)?;
        self.set32(REG_SYS_CTRL, BIT_FEN_EN)?;
        let mut reg = self.read32(REG_RFECTL)?;
        match set {
            RfSet::Btg => {
                reg |= B_BTG_SWITCH;
                reg &= !(B_CTRL_SWITCH | B_WL_SWITCH | B_WLG_SWITCH | B_WLA_SWITCH);
                self.write32(REG_ENRXCCA, ins(self.read32(REG_ENRXCCA)?, 0x00ff_0000, 0x0e))?; // BTG_CCA
                self.write32(REG_ENTXCCK, ins(self.read32(REG_ENTXCCK)?, 0x0000_ffff, 0xfc84))?; // BTG_LNA
            }
            RfSet::Wla => {
                reg |= B_WL_SWITCH | B_WLA_SWITCH;
                reg &= !(B_BTG_SWITCH | B_CTRL_SWITCH | B_WLG_SWITCH);
            }
            RfSet::Wlg => {
                reg |= B_WL_SWITCH | B_WLG_SWITCH;
                reg &= !(B_BTG_SWITCH | B_CTRL_SWITCH | B_WLA_SWITCH);
                self.write32(REG_ENRXCCA, ins(self.read32(REG_ENRXCCA)?, 0x00ff_0000, 0x12))?; // WLG_CCA
                self.write32(REG_ENTXCCK, ins(self.read32(REG_ENTXCCK)?, 0x0000_ffff, 0x7532))?; // WLG_LNA
            }
        }
        self.write32(REG_RFECTL, reg)
    }

    /// `rtw8821c_set_channel_bb` (rtw8821c.c:446) — band registers + BW20.
    pub(super) fn set_channel_bb(&self, channel: u8) -> Result<(), FaceError> {
        if channel <= 14 {
            // 2.4 GHz
            self.write32(0x0808, ins(self.read32(0x0808)?, 1 << 28, 1))?; // RXPSEL
            self.write32(0x0454, ins(self.read32(0x0454)?, 1 << 7, 0))?; // CCK_CHECK
            self.write32(0x0a80, ins(self.read32(0x0a80)?, 1 << 18, 0))?; // ENTXCCK on
            self.write32(0x0814, ins(self.read32(0x0814)?, 0x0000_fc00, 15))?; // RXCCAMSK
            self.write32(0x0c1c, ins(self.read32(0x0c1c)?, 0xf00, 0))?; // TXSCALE subband
            self.write32(0x0860, ins(self.read32(0x0860)?, 0x1ffe_0000, 0x96a))?; // CLKTRK
            // CCK TX filter
            if channel == 14 {
                self.write32(0x0a24, 0x0000_b81c)?;
                self.write32(0x0a28, ins(self.read32(0x0a28)?, 0x0000_ffff, 0))?;
                self.write32(0x0aac, 0x0000_3667)?;
            } else {
                let p = *self.ch_param.lock().unwrap();
                self.write32(0x0a24, p[0])?;
                self.write32(0x0a28, ins(self.read32(0x0a28)?, 0x0000_ffff, p[1] & 0xffff))?;
                self.write32(0x0aac, p[2])?;
            }
        } else {
            // 5 GHz
            self.write32(0x0a80, ins(self.read32(0x0a80)?, 1 << 18, 1))?; // ENTXCCK off
            self.write32(0x0454, ins(self.read32(0x0454)?, 1 << 7, 1))?; // CCK_CHECK
            self.write32(0x0808, ins(self.read32(0x0808)?, 1 << 28, 0))?; // RXPSEL
            self.write32(0x0814, ins(self.read32(0x0814)?, 0x0000_fc00, 15))?; // RXCCAMSK
            let (scale, clktrk) = match channel {
                36..=48 => (1, 0x494),
                52..=64 => (1, 0x453),
                100..=116 => (2, 0x452),
                118..=144 => (2, 0x412),
                _ => (3, 0x412), // >=149
            };
            self.write32(0x0c1c, ins(self.read32(0x0c1c)?, 0xf00, scale))?;
            self.write32(0x0860, ins(self.read32(0x0860)?, 0x1ffe_0000, clktrk))?;
        }
        // Bandwidth = 20 MHz (monitor).
        self.write32(0x08ac, (self.read32(0x08ac)? & 0xffcf_fc00) | 0x1001_0000)?;
        self.write32(0x08c4, ins(self.read32(0x08c4)?, 1 << 30, 1))?; // ADC160
        Ok(())
    }

    /// `rtw8821c_set_channel_bb_swing` (rtw8821c.c:571): TXSCALE_A[31:21] from the
    /// efuse BB-swing setting (defaults to 0 → 0x200).
    pub(super) fn set_channel_bb_swing(&self, _channel: u8) -> Result<(), FaceError> {
        const SWING: [u32; 4] = [0x200, 0x16a, 0x101, 0x0b6];
        // TODO(hw): index by efuse tx_bb_swing_setting_{2g,5g}/3; default 0.
        self.write32(0x0c1c, ins(self.read32(0x0c1c)?, 0xffe0_0000, SWING[0]))
    }

    /// `rtw8821c_set_channel_rxdfir` (rtw8821c.c:364) for BW20.
    pub(super) fn set_channel_rxdfir(&self) -> Result<(), FaceError> {
        // BW20/10/5 case: ACBB0[29:28]=2, ACBBRXFIR[29:28]=2, TXDFIR BIT31=1, CHFIR BIT31=0.
        self.write32(0x0948, ins(self.read32(0x0948)?, (1 << 29) | (1 << 28), 2))?;
        self.write32(0x094c, ins(self.read32(0x094c)?, (1 << 29) | (1 << 28), 2))?;
        self.write32(0x0c20, ins(self.read32(0x0c20)?, 1 << 31, 1))?;
        self.write32(0x08f0, ins(self.read32(0x08f0)?, 1 << 31, 0))
    }

    /// Write the per-rate TX-power index into the `0x1d00` TXAGC block (path A),
    /// for CCK / OFDM / HT-1SS / VHT-1SS. Uniform index for now (see module doc);
    /// `NDN_RADIO_TXPWR=<0..63>` overrides. This is the radiate gate.
    pub(super) fn set_tx_power(&self, _channel: u8) -> Result<(), FaceError> {
        let idx = std::env::var("NDN_RADIO_TXPWR")
            .ok()
            .and_then(|s| s.parse::<u8>().ok())
            .unwrap_or(0x2d)
            .min(0x3f) as u32;
        let packed = idx | (idx << 8) | (idx << 16) | (idx << 24);
        // 0x1d00 + (rate & 0xfc) for each 4-rate group.
        for off in [
            0x00, // CCK  1/2/5.5/11
            0x04, 0x08, // OFDM 6..54
            0x0c, 0x10, // HT MCS0..7
            0x2c, 0x30, 0x34, // VHT-1SS MCS0..9
        ] {
            self.write32(0x1d00 + off, packed)?;
        }
        Ok(())
    }

    /// Firmware-offloaded IQK (`rtw8821c_do_iqk` → `rtw_fw_do_iqk`): send the IQK
    /// H2C packet, then poll `RF 0x08` for the `0xabcde` done sentinel.
    pub(super) fn do_iqk(&self) -> Result<(), FaceError> {
        self.send_iqk_h2c()?;
        // poll RF_DTXLOK (0x08) for 0xabcde, up to ~6s (300 × 20ms).
        for _ in 0..300 {
            if self.read_rf(0x08, RFREG_MASK)? == 0xabcde {
                self.write_rf(0x08, RFREG_MASK, 0)?; // clear
                let fail = self.read32(0x1bf0)? & 0xff; // REG_IQKFAILMSK
                if fail != 0 {
                    tracing::warn!("8821cu IQK fail mask = {fail:#04x}");
                }
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        Err(init_err("8821cu IQK timeout (firmware not running?)".into()))
    }

    fn send_iqk_h2c(&self) -> Result<(), FaceError> {
        // IQK (sub-id 0x0E): content[0] bit0=clear, bit1=segment_iqk — both 0
        // for an un-associated bring-up.
        self.send_h2c_packet(0x0e, &[0x00])
    }

    /// Firmware config H2C sent once after init (rtw_power_on tail): general_info
    /// then phydm_info. **phydm_info is what lets the firmware run the dynamic RX
    /// gain (DIG)** — without it the receiver's gain stays unset and demods
    /// nothing. See reference Part B.
    pub(super) fn send_fw_info(&self) -> Result<(), FaceError> {
        // general_info (sub-id 0x0D): content word bits[23:16] = FW_TX_BOUNDARY
        // = rsvd_fw_txbuf_addr(508) - rsvd_boundary(460) = 48 (content byte 2).
        self.send_h2c_packet(0x0d, &[0x00, 0x00, 48, 0x00])?;
        // phydm_info (sub-id 0x11): ref_type=rfe(0), rf_type=FW_RF_1T1R(4),
        // cut_version, ant bits = rx(bit24)|tx(bit28) = 0x11.
        let cut = self.cond.lock().unwrap().cut;
        self.send_h2c_packet(0x11, &[0x00, 0x04, cut, 0x11, 0, 0, 0, 0])
    }

    /// Build + bulk-out a 32-byte H2C packet (category 0x01, cmd 0xFF, the given
    /// `sub_id`) on the H2C queue (qsel 19), prefixed by a 48-byte TX descriptor.
    /// `content` is placed after the 8-byte header; total_len = 8 + content.len().
    fn send_h2c_packet(&self, sub_id: u16, content: &[u8]) -> Result<(), FaceError> {
        use std::sync::atomic::Ordering;
        const H2C_PKT_SIZE: usize = 32;
        let seq = self.h2c_seq.fetch_add(1, Ordering::Relaxed);

        let mut h2c = [0u8; H2C_PKT_SIZE];
        // word0: category 0x01 | cmd 0xFF<<8 | sub_id<<16
        let w0 = 0x01u32 | (0xffu32 << 8) | ((sub_id as u32) << 16);
        h2c[0..4].copy_from_slice(&w0.to_le_bytes());
        // word1: total_len(bits15:0) | seq<<16
        let total_len = (8 + content.len()) as u32;
        h2c[4..8].copy_from_slice(&(total_len | ((seq as u32) << 16)).to_le_bytes());
        h2c[8..8 + content.len()].copy_from_slice(content);

        let mut pkt = vec![0u8; TX_DESC_SIZE + H2C_PKT_SIZE];
        txdesc_set(&mut pkt, 0, 0, 16, H2C_PKT_SIZE as u32); // TXPKTSIZE
        txdesc_set(&mut pkt, 0, 16, 8, TX_DESC_SIZE as u32); // OFFSET
        txdesc_set(&mut pkt, 0, 26, 1, 1); // LS
        txdesc_set(&mut pkt, 1, 8, 5, 19); // QSEL = H2C
        txdesc_checksum(&mut pkt);
        pkt[TX_DESC_SIZE..].copy_from_slice(&h2c);
        self.bulk_write(&pkt)
    }
}
