# Kernel init H2C sequence — clean decode (2026-06-14, session 15)

Decoded `golden_init.pcap` (fc:23, kernel rtl88x2eu, radiates −25 dBm) with
`/tmp/h2c2.py` — locate the FW-offload header (`01ff`/`81ff`) in each bulk-OUT and
decode sub-cmd + content. **This is the full packet-H2C set the kernel sends at
bring-up:**

```
0.182s  BCN/rsvd-page len=1888  (TX desc 30 07 30 00 00 10 … = rsvd-page DMA, qsel beacon)
0.267s  H2C GENERAL_INFO (0x0d)  content 00 00 30 00
0.267s  H2C PHYDM_INFO   (0x11)  content 00 04 01 11 00 00 00 00
0.270s  H2C DUMP_EFUSE   (0x03)  ack=1, no content
        + 49 firmware-download bulk chunks (len≥2000)
        + 2 HMEBOX H2C via registers 0x1d0/0x1d4 (not bulk; see prior notes)
```

## ★★ FINDING A — the kernel sends NO cfg_parameter / datapack H2C
There are **zero** `CFG_PARAM` (0x08), `UPDATE_DATAPACK` (0x09), or `RUN_DATAPACK`
(0x0a) H2C packets in the entire bring-up. **The cfg_parameter-offload theory
(session 14 "THE fix") is dead at ground truth — the kernel never uses it here.**
The firmware self-configures the PHY/analog after `general_info` + `phydm_info`
(consistent with DECODE_FINDINGS "only 21 BB + 2 RF direct host writes"; the PHY
tables live in the firmware image and are applied internally, parameterized by the
phydm_info topology). `cfg_parameter_phy` in the driver should stay demoted/off.

## ★★ FINDING B — phydm_info topology: we declare the WRONG radio (byte-exact)
Layout confirmed from `halmac_fw_offload_h2c_nic.h` (content at h2c+0x08):
`REF_TYPE[0:8] RF_TYPE[8:8] CUT_VER[16:8] RX_ANT[24:4] TX_ANT[28:4]`, `EXT_PA` at +0xC.

| field    | kernel (works) | our driver | 
|----------|----------------|------------|
| rfe_type | **0**          | 0x15 (21)  |
| rf_type  | **4 = 1T1R**   | 2 = 2T2R   |
| cut_ver  | 1              | 1 ✓        |
| rx_ant   | **1**          | 3          |
| tx_ant   | **1**          | 3          |
| ext_pa   | **0**          | (unset)    |

The prior `H2C_MAPPING.md` decode (1T1R) was **CORRECT**; the later memory
"CORRECTION" that retracted it (claiming a mis-decoded bit layout + EFUSE 0xCA=0x15)
was the actual error — the layout above is byte-exact from source and the wire bytes
are unambiguous. (If EFUSE 0xCA really reads 0x15, then either it's the wrong offset
for RFE_OPTION on this board, or `rtw_RFE_type`/driver logic overrides it to 0 — but
the *wire truth* the working fw receives is rfe=0/1T1R/ant1-1/extPA0.)

### Why this plausibly matters (coherent with the symptoms)
1. We tell the fw a **2-path / external-PA / rfe-21** topology the working kernel
   does NOT. The fw sets up TX for the wrong front-end → weak/no key (−86 vs −25).
2. Our cal chain runs **both paths A and B** (TXGAPK/IQK/DPK ×2). If the chip is
   effectively 1T1R here, path-B cal operates on a phantom chain → corruption →
   the **non-deterministic dead TX**.
3. Our **rfe-21 FEM pinmux** (`efem_pinmux_config`) drives FEM control the kernel
   (rfe=0) does not — possibly mis-keying the FEM.

### CAVEAT — partially tested before, inconclusively
S14 added `NDN_RADIO_KERNEL_PHYDM` (sends the exact `00 04 01 11`) and "ruled it out"
in the SDR bisection — BUT that was during a dead-TX window (everything read flat),
and it changed ONLY the H2C content, NOT the 2-path cal or the rfe-21 FEM pinmux. So
the *topology as a whole* (phydm_info + single-path cal + rfe handling) has NOT been
tested coherently against a live-TX window.

## Recommended experiment (when a live-TX window exists)
Make the driver declare the kernel's topology END-TO-END, not just the H2C byte:
- phydm_info = `00 04 01 11 00 00 00 00` (rfe0/1T1R/ant1-1/extPA0) — i.e. default
  `NDN_RADIO_KERNEL_PHYDM` on.
- Run cal on **path A only** (skip path-B IQK/TXGAPK/DPK) when 1T1R.
- A/B the rfe-21 FEM pinmux (`NDN_RADIO_NO_EFEM`) under the 1T1R config.
Ground truth = OPi radiotap RSSI / SDR, repeated default bring-ups, variance check.
Do NOT re-open cfg_parameter (Finding A).
