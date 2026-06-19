#!/usr/bin/env python3
"""Generate src/mt7612/chanset_replay.bin: the kernel's monitor-mode + channel-set
op stream (RF/BB register writes + MCU calibration commands), captured from
mt76x2u doing `iw set type monitor; ip link up; iw set channel 6`. Replayed by
set_channel() AFTER the init bring_up to tune the RF so ambient frames arrive.
No firmware download here (init already loaded it), so no FW marker / FCE
collapsing — just emit every write + MCU command in captured order. Reads skipped.

Op encoding matches gen_mt7612_replay.py:
  0x06 W  : addr(u32) val(u32)
  0x46 C  : addr(u16) val(u32)
  0x01 D  : wValue(u16)
  0x4D M  : info(u32) len(u16) payload[len]   (raw txd info, exact seq)
"""
import struct, os
HERE = os.path.dirname(__file__)
PCAP = os.path.join(HERE, "../golden/mt7612-usbmon-2026-06-17/chanset_ch6.pcap")
OUT = os.path.join(HERE, "../src/mt7612/chanset_replay.bin")

def read_pcap(path):
    d = open(path, 'rb').read()
    off, pk = 24, []
    while off + 16 <= len(d):
        ts, tu, ic, ol = struct.unpack('<IIII', d[off:off+16]); off += 16
        pk.append(d[off:off+ic]); off += ic
    return pk

out = bytearray(); nW = nM = nC = nD = 0
for pkt in read_pcap(PCAP):
    if len(pkt) < 64 or chr(pkt[8]) != 'S':
        continue
    xfer = pkt[9]; ep = pkt[10]
    lc, = struct.unpack('<I', pkt[36:40]); data = pkt[64:64+lc]
    if xfer == 3 and not (ep & 0x80):
        if ep == 0x08 and lc < 2048 and len(data) >= 4:        # MCU command
            info = struct.unpack('<I', data[:4])[0]; ln = info & 0xffff
            payload = data[4:4+ln]
            out.append(0x4D); out += struct.pack('<I', info)
            out += struct.pack('<H', len(payload)); out += payload
            nM += 1
        continue
    if xfer != 2:
        continue
    bm, br, wv, wi, wl = struct.unpack('<BBHHH', pkt[40:48])
    if bm & 0x80:                                              # read — skip
        continue
    addr = (wv << 16) | wi
    v = int.from_bytes(data[:4], 'little') if data else 0
    if br == 0x06:
        out.append(0x06); out += struct.pack('<II', addr, v); nW += 1
    elif br == 0x46:
        out.append(0x46); out += struct.pack('<HI', addr & 0xffff, v); nC += 1
    elif br == 0x01:
        out.append(0x01); out += struct.pack('<H', wv); nD += 1

open(OUT, 'wb').write(out)
print(f"wrote {OUT}: {len(out)} bytes  ({nW} writes, {nM} mcu, {nC} cfg, {nD} dev)")
