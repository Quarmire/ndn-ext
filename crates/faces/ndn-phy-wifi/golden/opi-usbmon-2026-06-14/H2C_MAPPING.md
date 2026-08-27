# H2C mapping — our bring_up vs kernel golden (2026-06-14)

Our H2C captured with NDN_RADIO_LOG_WRITES=1 (logs the 32-byte payload in
`send_h2c`). Kernel from golden_init.pcap (3 packet-H2C QSEL 0x13 + 2 HMEBOX).
Header format (both): `[CATEGORY 0x01 | ACK<<7][CMD_ID 0xff][SUB_CMD:16][TOTAL_LEN=8+content:16][seq:16]`.

## Packet-path H2C (QSEL 0x13)

| sub-cmd | kernel (probe) | ours | verdict |
|---|---|---|---|
| 0x0d GENERAL_INFO | `01ff 0d00 0c00 …00 30 00` | `01ff 0d00 0c00 …00 30 00` | **exact match** |
| 0x11 PHYDM_INFO   | `01ff 1100 1000` content `00 04 01 11` | `81ff 1100 1000` content `15 02 01 33` | **WRONG (see below)** |
| 0x03 DUMP_PHYSICAL_EFUSE | `81ff 0300 0800` (no content) | — | we don't send (we read EFUSE directly; likely benign) |
| 0x0e IQK | (kernel does at ch-set, not probe) | `81ff 0e00 0900` ×2 | timing diff |
| 0xb7 DPK | (kernel does at ch-set) | `81ff b700 0900` | timing diff |

## ★ The real bug: PHYDM_INFO content is hardcoded & wrong for this dongle

phydm_info tells the firmware's phydm the RF topology. Reference field order
(`proc_send_phydm_info_88xx`): rfe_type, rf_type, cut_ver, rx_ant, tx_ant.
HALMAC_RF_2T2R=2, **HALMAC_RF_1T1R=4**.

| field | kernel (EFUSE-derived, fc:23) | ours (hardcoded) |
|---|---|---|
| rfe_type | **0** | `RFE_TYPE=0x15` (21) |
| rf_type  | **1T1R (4)** | `RF_2T2R=2` |
| cut      | 1 | 1 ✓ |
| rx_ant / tx_ant | **1 / 1** | `ANT_AB=3 / 3` |

We hardcode 2T2R / RFE-21 / dual-antenna; the kernel reads fc:23's EFUSE and
reports **1T1R / RFE-0 / single-antenna**. Consequences (plausible cause of the
weak + flaky TX):
- The firmware sets up TX for a 2-antenna/2-path topology the dongle doesn't
  have → power split / wrong path → the −86-vs-−25 dBm gap and possibly no key.
- Our own cal chain runs TWO paths (TXGAPK/IQK/DPK on path A *and* B). On a
  1T1R dongle path B doesn't exist → cal operates on a phantom chain →
  corruption → the non-deterministic dead TX.
- Also: ACK bit differs (ours 0x81 vs kernel 0x01) — minor.

### Fix
Read rf_type / rfe_type / antenna from EFUSE per-dongle (as the kernel does) and
drive both the phydm_info H2C content and the cal path-count from it, instead of
the hardcoded `RFE_TYPE=0x15` / `RF_2T2R=2` / `ANT_AB=3`. Verify fc:23 (and
78:22) EFUSE rf_type before committing — they may differ per unit.

## HMEBOX H2C (register 0x1d0/0x1f0) — not yet decoded
`0x1d0=0x0100004c` ext `0x1f0=0x11`; `0x1d4=0x000001c3` ext `0x1f4=0`. We send
none. Decode next (non-offload H2C: media-status / RA / rsvd-page candidates).
