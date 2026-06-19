//! efuse read → the **RFE (RF front-end) profile**. Realtek dongles wire the
//! front-end differently per vendor; the chip's efuse carries an `rfe_option`
//! the driver uses to pick the AGC table, antenna-switch routing (WLG vs BTG),
//! the `RFE_CTRL8` (0xcb4) value, and power tables. Hardcoding one board's
//! profile (e.g. the c820's rfe_option=4) onto another mis-tunes the receiver.
//! Ported from rtw88 `efuse.c` (physical read + logical-map decode) and
//! `rtw8821c_read_efuse`.

use std::time::Duration;

use ndn_transport::FaceError;

use super::{Rtl8821cuBackend, init_err};

/// The board's RFE profile + antenna flags, read from efuse logical offset 0xCA.
#[derive(Clone, Copy, Debug)]
pub(super) struct ChipInfo {
    /// `rfe_option & 0x1f` — selects AGC-btg/power tables + antenna.
    pub rfe_option: u8,
    /// Full `rfe_option` byte; phy_cond `rfe = rfe_option_full >> 3`.
    pub rfe_option_full: u8,
    /// `(rfe_option & BIT(5)) ? 1 : 0` — phy_cond package type.
    pub pkg_type: u8,
    /// RX/TX antenna routes through the BT-grant (BTG) front-end.
    pub rfe_btg: bool,
}

impl Rtl8821cuBackend {
    /// Read the RFE profile from efuse. Requires the chip powered on.
    pub(super) fn read_chip_info(&self) -> Result<ChipInfo, FaceError> {
        let mut phys = [0u8; 512];
        self.read_phys_efuse(&mut phys)?;
        let log = decode_logical(&phys);
        let full = log[0xca]; // rfe_option (struct rtw8821c_efuse)
        let rfe = full & 0x1f;
        Ok(ChipInfo {
            rfe_option: rfe,
            rfe_option_full: full,
            pkg_type: if full & (1 << 5) != 0 { 1 } else { 0 },
            // rfe_btg set for rfe ∈ {2,4,7,a,c,f} (rtw8821c_read_efuse).
            rfe_btg: matches!(rfe, 2 | 4 | 7 | 0xa | 0xc | 0xf),
        })
    }

    /// Read the raw physical efuse map (rtw_dump_physical_efuse_map): grant
    /// access, select the WiFi bank, disable the 2.5 V LDO, then per-byte
    /// address-trigger + poll EF_FLAG (bit31).
    fn read_phys_efuse(&self, map: &mut [u8]) -> Result<(), FaceError> {
        self.write8(0x00cf, 0x69)?; // REG_EFUSE_ACCESS = EFUSE_ACCESS_ON (grant)
        let bank = self.read32(0x0034)?; // REG_LDO_EFUSE_CTRL: bank sel = WIFI(0)
        self.write32(0x0034, bank & !((1 << 8) | (1 << 9)))?;
        let ldo = self.read8(0x0037)?; // REG_LDO_EFUSE_CTRL+3: clear LDO25_EN(bit7)
        self.write8(0x0037, ldo & !(1 << 7))?;

        let mut result = Ok(());
        let mut ctl = self.read32(0x0030)?; // REG_EFUSE_CTRL
        for (addr, slot) in map.iter_mut().enumerate() {
            ctl &= !(0xff | (0x3ff << 8)); // clear data + addr fields
            ctl |= ((addr as u32) & 0x3ff) << 8;
            self.write32(0x0030, ctl & !(1u32 << 31))?; // EF_FLAG clear → trigger
            let mut done = false;
            for _ in 0..100 {
                ctl = self.read32(0x0030)?;
                if ctl & (1u32 << 31) != 0 {
                    done = true;
                    break;
                }
                std::thread::sleep(Duration::from_micros(2));
            }
            if !done {
                result = Err(init_err(format!("8821cu efuse read timeout @{addr:#x}")));
                break;
            }
            *slot = (ctl & 0xff) as u8;
        }
        self.write8(0x00cf, 0x00)?; // grant off
        result
    }
}

/// Decode the physical efuse map into the 512-byte logical map
/// (rtw_dump_logical_efuse_map): each section has a 1- or 2-byte header giving a
/// block index + 4-bit word-enable; enabled words copy 2 bytes to
/// `logical[blk*8 + word*2]`.
fn decode_logical(phys: &[u8]) -> [u8; 512] {
    let mut log = [0xffu8; 512];
    let mut i = 0usize;
    while i < phys.len() {
        let hdr1 = phys[i];
        if hdr1 == 0xff {
            break;
        }
        let (blk, word_en);
        if (hdr1 & 0x1f) == 0x0f {
            // 2-byte header
            if i + 1 >= phys.len() {
                break;
            }
            let hdr2 = phys[i + 1];
            if hdr2 == 0xff {
                break;
            }
            blk = (((hdr2 & 0xf0) >> 1) | ((hdr1 >> 5) & 0x07)) as usize;
            word_en = hdr2 & 0x0f;
            i += 2;
        } else {
            blk = ((hdr1 & 0xf0) >> 4) as usize;
            word_en = hdr1 & 0x0f;
            i += 1;
        }
        for w in 0..4usize {
            if word_en & (1 << w) != 0 {
                continue; // word disabled
            }
            let logi = (blk << 3) + (w << 1);
            if i + 1 >= phys.len() || logi + 1 >= log.len() {
                return log;
            }
            log[logi] = phys[i];
            log[logi + 1] = phys[i + 1];
            i += 2;
        }
    }
    log
}
