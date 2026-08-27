# Golden RTL8812EU chip state (kernel driver, OPi-0, 2026-06-12)

Ground-truth reference for the userspace RTL8812EU driver port in
`src/libusb_rtl88xx.rs`. Captured from the **working** out-of-tree `rtl88x2eu`
kernel driver (v5.15.0.1-249, halmac V1_06_07_12) driving the same dongle model
(`0bda:a81a`) on the Orange Pi 5 Pro testbed node `mds-o5p-0`, via the driver's
procfs debug nodes (`/proc/net/rtl88x2eu/wlu1u1/*`), with the interface up in
monitor mode on channel 161 (5.805 GHz).

The userspace port verifies each init stage by diffing chip state against these
dumps instead of porting blind. Note the OPi dongle and the dev (Mac) dongle
are different physical units of the same model: per-device EFUSE content (MAC
at logical 0x157, RF/TX-power calibration around 0x020/0x110) legitimately
differs; structure, layout, and the non-calibration bytes match.

Key anchors:

- `mac_addr.txt` — OPi unit's MAC `78:22:88:d9:93:e6` (= logical EFUSE 0x157,
  `EEPROM_MAC_ADDR_8822EU`).
- `efuse_map.txt` — full **logical** EFUSE map as the kernel decodes it; the
  target output for `efuse_decode_logical`.
- `mac_reg_dump.txt` / `bb_reg_dump.txt` / `rf_reg_dump.txt` — register state
  after full kernel init (power-on + fw download + MAC/BB/RF init). Includes
  `REG_SYS_CFG1(0xF0) = 0x0c491d37`, `REG_SYS_CFG2(0xFC) = 0xc0000017` (chip id
  byte `0x17` = `CHIP_ID_HW_DEF_8822E`, B-cut), `REG_CR(0x100) = 0x6ff`.
- `fw_info.txt` / `halmac_info.txt` / `ver_info.txt` — firmware + driver
  versions for the fw-download stage.
- `hal_spec.txt` / `phy_cap.txt` / `monitor.txt` / `chan_info.txt` — capability
  and channel state for the MAC-init/monitor stage.
- `dmesg_driver.txt`, `drv_cfg.txt`, `ip_link.txt`, `lsusb.txt` — environment
  context.

The live post-init values of the power/clock-domain registers (read via the
`read_reg` debugfs node, used to find the EFUSE `ISO_EB2CORE` isolation gate):

```
0x0000 0xdc1f0f98   0x0004 0x00070082   0x0008 0x20207c21   0x0010 0x00000004
0x001c 0x87f7f100   0x0028 0x070f0803   0x0030 0x25c700f0   0x0034 0x00000000
0x0040 0x1403020c   0x004c 0x0122e282   0x0064 0x3c201000   0x00ec 0x87000000
0x00f0 0x0c491d37   0x00f4 0x100014c9   0x00fc 0xc0000017   0x0100 0x000006ff
0x1018 0x2c282150   0x1044 0x7cff7a08   0x1064 0x0021b2f3   0x1080 0x00010100
0x1100 0x0c000000
```
