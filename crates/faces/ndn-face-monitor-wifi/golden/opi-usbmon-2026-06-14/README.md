# Golden usbmon capture — kernel rtl88x2eu keying fc:23 TX (2026-06-14)

Why: the userspace libusb driver fails to key TX correctly per-device — under it
`fc:23` radiates nothing and `78:22` radiates weakly (−86 dBm), while **both**
dongles transmit at −25/−26 dBm effortlessly on the kernel `rtl88x2eu` driver
(verified point-blank on the OPi, both directions). So the PA hardware is fine;
the deficit is in our bring-up/TX path. These traces are the kernel's ground
truth to diff against.

Captured on the OPi (`minidronesys@10.10.10.127`), dongle `fc:23:cd:68:8f:8c` =
`wlu1u2` on **USB bus 1** (`usb1`, device id `1-1.2`), captured on `usbmon1`
(`sudo tcpdump -i usbmon1 -s 0 -w …`). Country US set
(`rtw_country_code` + `iw reg set US`) so ch149 is TX-legal.

## Files

- `golden_init.pcap` — 6540 pkts, 887 KB. **Full bring-up**, captured across a
  forced kernel re-probe (`echo 1-1.2 > /sys/bus/usb/drivers/usb/{unbind,bind}`).
  Contains 1502 CONTROL transfers (MMIO register R/W: bRequestType 0x40/0xC0,
  bRequest 0x05, wValue=reg addr) + 1764 BULK-OUT (firmware download chunks +
  H2C). This is the complete fw-download + cal + datapath sequence.
- `golden_tx.pcap` — 1402 pkts, 242 KB. **TX inject** (100 frames via a raw
  AF_PACKET injector on the monitor iface, ch149). 966 BULK to ep `1:6:4` (48-byte
  TX descriptor + 802.11 frame) + 436 CONTROL (per-frame/periodic reg writes).

## Decode notes

- Realtek USB register access = USB **control** transfer: `bRequest=0x05`,
  `wValue` = register address, `wIndex` = page/0, data payload = the 1/2/4-byte
  value. Host→device (0x40) = write, device→host (0xC0) = read.
- Firmware + frame TX + H2C = **bulk-OUT**. The first 48 bytes of a TX bulk-OUT
  are the TX descriptor; H2C ride a different QSEL.
- To extract the ordered register sequence like `../opi-usbmon-2026-06-13/
  init_regseq.txt`, parse the control-SUBMIT setup packets (tshark:
  `usb.bRequest == 5`, fields `usb.setup.wValue`, `usb.data_fragment`).

## Use

Diff this against what `LibUsbRtl88xxBackend::bring_up` / `inject` emit to find
the missing or wrong TX-keying step (suspects from prior sessions: firmware cal
completion, TSSI/power-tracking never ported, per-device IQK/DPK). The kernel
TXes at −25 dBm here; our userspace path does not — the delta lives in this trace.
