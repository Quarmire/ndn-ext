# Realtek RTL8822E firmware

`rtl8822e_fw_nic.bin` is Realtek's WLAN-CPU firmware for the RTL8822E family
(which includes the RTL8812EU dongle this crate's `libusb-backend` drives),
extracted byte-for-byte from the `array_mp_8822e_fw_nic` C array in the vendor
reference driver `svpcom/rtl8812eu` (`hal/rtl8822e/hal8822e_fw.c`, also shipped
as `OpenHD/rtl88x2eu`). Header: signature 0x2288, version 1.27, built
2024-09-04; sections DMEM 14,400 B + IMEM 56,568 B + EMEM 128,808 B (each with
an 8-byte checksum tail) behind a 64-byte header — 199,864 bytes total.

This is proprietary Realtek firmware (data executed by the on-chip CPU, not
host code), redistributed in binary form the same way the kernel driver and
linux-firmware do. The matching golden runtime state from this exact version is
in `../golden/opi0-2026-06-12/` ("FW VER -1.27").

## phydm BB/RF tables

`rtl8822e_phy_reg.bin`, `rtl8822e_agc_tab.bin`, `rtl8822e_radioa.bin`,
`rtl8822e_radiob.bin` are the baseband and RF register tables, extracted
verbatim (LE u32 words) from the phydm `array_mp_8822e_*` arrays in
`hal/phydm/rtl8822e/halhwimg8822e_bb.c` and
`hal/phydm/halrf/rtl8822e/halhwimg8822e_rf.c`. Each is a condition-encoded
stream: a leading headline of `{cut, rfe_type}` variant descriptors followed
by an IF/ELSE/END/CHK body of `(addr, data)` pairs (see `load_table` /
`HeadlineSel` in `libusb_rtl88xx.rs`). The driver loads these to bring up the
PHY; our port replays the same bytes. Verified: after loading them and
switching to channel 161, 509/512 BB registers and the RF channel/bandwidth
registers match the golden kernel state.

## RF calibration setup table

`rtl8822e_cal_init.bin` is the `array_mp_8822e_cal_init` table from
`hal/phydm/halrf/rtl8822e/halrf_rfk_init_8822e.h` — straight `(addr, data)` BB
register pairs (not condition-encoded) that arm the calibration blocks before
the iterative RF calibrations run. Loaded by `rf_cal_init()` as part of the
kernel's `_init_rf_reg` flow, after the BB/AGC tables and before the RadioA/B
tables. Deterministic; the calibration loops themselves (DACK and the heavier
unported IQK/LCK/DPK/TSSI) are code, not tables.

The reference driver also ships variants we don't currently embed: `fw_10M`
(5/10 MHz narrowband PHY), `fw_wowlan` (wake-on-WLAN pattern matching), and
`fw_ap`/`fw_spic` — see the named-radio knobs note for why the first two are
interesting.
