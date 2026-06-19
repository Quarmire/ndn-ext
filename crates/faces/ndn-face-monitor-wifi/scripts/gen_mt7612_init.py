#!/usr/bin/env python3
"""Generate src/mt7612/init_table.rs from the golden mt76x2u init usbmon trace:
the ordered MAC/BB MMIO writes (bReq 0x06), excluding FCE/firmware registers
handled directly in mod.rs. Usage: python3 scripts/gen_mt7612_init.py"""
import struct, sys, os
HERE=os.path.dirname(__file__)
PCAP=os.path.join(HERE,"../golden/mt7612-usbmon-2026-06-17/golden_init.pcap")
OUT=os.path.join(HERE,"../src/mt7612/init_table.rs")
FCE={0x0230,0x0232,0x0234,0x0236,0x09a0,0x09a4,0x09c4,0x0a6c,0x0800,0x09a8,0x0730,0x9018}
def read_pcap(path):
    d=open(path,'rb').read(); end='<' if d[:4]==b'\xd4\xc3\xb2\xa1' else '>'
    off,pk=24,[]
    while off+16<=len(d):
        ts,tu,ic,ol=struct.unpack(end+'IIII',d[off:off+16]); off+=16
        pk.append(d[off:off+ic]); off+=ic
    return pk
ws=[]
for pkt in read_pcap(PCAP):
    if len(pkt)<64: continue
    if chr(pkt[8])!='S' or pkt[9]!=2: continue
    bm,br,wv,wi,wl=struct.unpack('<BBHHH',pkt[40:48])
    if (bm&0x80) or br!=0x06: continue
    addr=(wv<<16)|wi
    if addr in FCE: continue
    lc,=struct.unpack('<I',pkt[36:40]); data=pkt[64:64+lc]
    ws.append((addr,int.from_bytes(data[:4],'little') if data else 0))
with open(OUT,'w') as f:
    f.write("//! Generated from golden/mt7612-usbmon-2026-06-17/golden_init.pcap by\n")
    f.write("//! scripts/gen_mt7612_init.py — MT7612U MAC/BB MMIO init writes in order.\n")
    f.write("//! FCE/firmware registers are handled in mod.rs (excluded here).\n\n")
    f.write("/// (addr, value) MMIO writes (bReq 0x06) replayed after firmware load.\n")
    f.write("pub const INIT_WRITES: &[(u32, u32)] = &[\n")
    for a,v in ws: f.write(f"    (0x{a:04x}, 0x{v:08x}),\n")
    f.write("];\n")
print(f"wrote {OUT}: {len(ws)} writes")
