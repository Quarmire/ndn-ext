# OPi working-driver ground truth (usbmon capture, 2026-06-13)

Captured from the working RTL8812EU kernel driver (`8812eu`/`rtl88x2eu`) on
OPi mds-o5p-0 by recording bus 2 with `tcpdump -i usbmon2` during a full USB
re-enumerate (power-on → firmware download → BB/RF init → monitor inject).
The dongle TRANSMITS monitor frames there; this is the reference for the Mac
userspace port (`libusb_rtl88xx.rs`), which does NOT yet transmit.

## init_regseq.txt
The complete ordered register-write sequence: `addr width hexvalue`, 9147
vendor-write (bReq 0x05) control transfers. Includes firmware download, the
full phydm BB/RF tables, real IQK/DPK calibration loops, and MAC init.

## Working TX descriptor (monitor inject, 64-byte broadcast 802.11 frame)
48-byte HW TX descriptor captured on bulk-OUT ep 0x05 (HIGH queue):

    dw0=0x05300040  TXPKTSIZE=64 OFFSET=48 BMC=1 LS=1(!) DISQSELSEQ=0
    dw1=0x00091201  MACID=1 QSEL=0x12 RATE_ID=9
    dw2=0x3f000000  G_ID=63
    dw3=0x00000700  USE_RATE=1 DISRTSFB=1 DISDATAFB=1
    dw4=0x001a0000  DATARATE=0 RTY_LMT_EN=1 RTS_DATA_RTY_LMT=6
    dw5..6=0  dw7=checksum  dw8..11=0  (EN_HWSEQ=0)

KEY: LS (Last Segment, 0x00[26]) — my driver was missing it. Now fixed in
build_tx, but setting it (plus G_ID/DISRTSFB and dropping EN_HWSEQ) did NOT
make the Mac dongle transmit.

## Firmware / H2C stream (QSEL histogram of init bulk-OUT)
- QSEL 0x10 x124  firmware-download chunks
- QSEL 0x12 x35   MGT/reserved-page downloads
- QSEL 0x13 x29   H2C commands (content `81 ff 08 00 0c 00 <seq> 00 ...`)
Plus HMEBOX (register 0x1d0/0x1f0) H2C: cmd_ids 0x4c, 0x6d.

## Status / next
Register state is now comprehensively matched to this reference (MAC protocol
via --forcemac, REG_CR/ENSEC, BB 509/512, descriptor). TX STILL does not key
(SDR: no RF; TX-PHY-OK=0; TX-FIFO pages drain 64->0 but never recycle). The
gate is therefore NOT a register value or descriptor field — prime remaining
suspect is firmware TX-state (the init H2C + reserved-page sequence above) or
a BB-MAC TX handshake. Mine the H2C/rsvd-page sequence next.
