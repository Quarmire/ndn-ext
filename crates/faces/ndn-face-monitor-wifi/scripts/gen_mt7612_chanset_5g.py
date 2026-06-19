#!/usr/bin/env python3
"""Generate src/mt7612/chanset_replay_5g80.bin: the kernel's 5GHz VHT80 RF/BB tune
(`iw dev wlan0 set channel 36 80MHz`, center 5210 MHz), captured under usbmon6 on a
firmware-loaded device. Replayed by set_channel_5g80() after bring_up to put the RF
on a clean 5GHz 80MHz channel — the per-byte-rate + low-contention path to RTL-class
throughput (vs the congested-2.4GHz ch6 chanset_replay.bin). Same op encoding as
gen_mt7612_chanset.py. No firmware in this capture (init already loaded it).
"""
import struct, os
HERE = os.path.dirname(__file__)
PCAP = os.path.join(HERE, "../golden/mt7612-usbmon-2026-06-18/chanset_ch36_80.pcap")
OUT = os.path.join(HERE, "../src/mt7612/chanset_replay_5g80.bin")

d = open(PCAP, 'rb').read()
off = 24
out = bytearray(); nW = nM = nC = nD = 0
while off + 16 <= len(d):
    ts, tu, ic, ol = struct.unpack('<IIII', d[off:off+16]); off += 16
    pkt = d[off:off+ic]; off += ic
    if len(pkt) < 64 or chr(pkt[8]) != 'S':
        continue
    xfer = pkt[9]; ep = pkt[10]
    lc, = struct.unpack('<I', pkt[36:40]); data = pkt[64:64+lc]
    if xfer == 3 and not (ep & 0x80):
        if ep == 0x08 and lc < 2048 and len(data) >= 4:       # MCU calibration command
            info = struct.unpack('<I', data[:4])[0]; ln = info & 0xffff
            payload = data[4:4+ln]
            out.append(0x4D); out += struct.pack('<I', info)
            out += struct.pack('<H', len(payload)); out += payload
            nM += 1
        continue
    if xfer != 2:
        continue
    bm, br, wv, wi, wl = struct.unpack('<BBHHH', pkt[40:48])
    if bm & 0x80:                                             # read — skip
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
