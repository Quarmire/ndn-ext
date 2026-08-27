# Decode findings — kernel rtl88x2eu golden vs our userspace driver (2026-06-14)

Decoded with `../decode_usbmon.py`. Source: `golden_init.pcap` (full bring-up),
`golden_tx.pcap` (monitor TX inject). Both on fc:23, kernel driver, which TXes
at **−25 dBm** here — the reference our userspace path fails to match.

## Artifacts
- `init_regseq.txt` — 916 ordered register writes (full bring-up).
- `init_config_clean.txt` — 146 distinct config registers (poll/EFUSE/fw-dl
  handshake loops removed: 0x04e0 ×250, 0x0204/0x0422/0x0101 ×~100,
  0x1200-08 ×~50, the page-transfer/EFUSE handshakes).
- `tx_regseq.txt` — register writes during the TX inject (runtime DM).

## Finding 1 — the TX descriptor is NOT the bug (confirmed)
The kernel's 48-byte monitor-inject TX descriptor:
`88 00 30 05  01 12 09 00  00 00 00 3f  00 07 00 00  04 00 02 00 … b6 2f`
matches our `build_tx` field-for-field:
- PKT_SIZE / OFFSET=0x30(48) / **BMC** / **LS** (0x00) ✓
- MACID=1 / **QSEL=0x12** / RATE_ID=9 (0x04) ✓
- G_ID=63 (0x08) ✓ ; USE_RATE+DISRTSFB+DISDATAFB=0x7 (0x0c) ✓
- rate field + RTY_LMT_EN (0x10) ✓ ; checksum at 0x1c[15:0] ✓
- Only diff: DATA_RTY_LMT mine=6 vs golden=0 (benign for broadcast; no ACK).
⇒ The per-frame TX path is correct. The deficit is in **bring-up**.

## Finding 2 — the kernel OFFLOADS BB/RF/cal to firmware (structural)
The 146-register clean config breaks down as: 26 sys/power, 28 MAC, 66
fw/EFUSE/TXDMA/sec, **21 BB, 2 RF**. A full 8822E PHY config is *hundreds* of
BB/RF writes — which our driver ports directly (phydm tables + TXGAPK/kfree/LCK/
DPK/DACK). The kernel does almost none of that by hand: it downloads the ~195 KB
firmware (47 × 4144 B bulk-OUT) and lets the **firmware** write the BB/RF tables
and run cal internally (consistent with rtw_*_fw_offload). This is why our
userspace path is hard and per-device-fragile: we own PHY/cal; the kernel doesn't.
Implication: rather than perfecting a large direct BB/RF/cal port, the higher-
leverage path may be to drive the firmware's PHY/cal offload the way the kernel
does (H2C triggers) and write only this 146-register host set.

## Finding 3 — concrete lead: BT-coex grant value differs
Kernel init writes the BTC grant register (indirect port 0x1700/0x1704):
- read  `0x1700 = 0x800f0038`  (read 0x38)
- write `0x1704 = 0x0000dd03`, `0x1700 = 0xc00f0038`  ⇒ **BTC 0x38 = 0xdd03**

Our `btc_grant_wl` writes `0x38[15:8] = 0x77` (→ 0x7703). So **[15:8]: kernel
0xdd vs ours 0x77**, and the kernel also sets `[7:0]=0x03` explicitly. This is the
register prior sessions pinned as the ~50 dB TX-power gate. **Test on Mac:** write
0x38 = 0xdd03 exactly and re-measure — candidate for the −86 dBm/dead-TX deficit.

## Finding 4 — runtime DM writes during TX (tx_regseq.txt)
The kernel continuously writes 0x1e40–0x1e60, 0x3d08/0x4d08 (path A/B), 0x1d70
(DIG IGI) during TX — power-tracking + DIG. Our watchdog ports DIG+thermal but
should be checked against these exact addresses/cadence.

## Next (needs a dongle on the Mac)
1. Try BTC 0x38 = 0xdd03 (Finding 3) — cheapest, highest-probability test.
2. Instrument `bring_up` to log its register writes; diff the address set vs
   `init_config_clean.txt` — find host-side writes we miss or get wrong.
3. Reconcile the fw-offload boundary (Finding 2): are we fighting the firmware
   by also writing PHY/cal directly?
