#!/usr/bin/env python3
"""Generate src/mt7612/init_replay.bin: the full mt76x2u init as an ordered op
stream (register writes + MCU commands), with the firmware download collapsed to
a single marker (handled by load_firmware() in mod.rs). Reads are skipped.

Op encoding (little-endian):
  0x06 W   : addr(u32) val(u32)              -- MMIO write (MT_VEND_MULTI_WRITE)
  0x46 C   : addr(u16) val(u32)              -- CFG write
  0x01 D   : wValue(u16)                     -- DEV_MODE
  0x4D M   : info(u32) len(u16) payload[len] -- MCU command (raw txd info word,
             replayed verbatim to preserve the exact seq; seq==0 => no response)
  0xFF FW  :                                 -- load firmware + start MCU here
"""
import struct, os
HERE=os.path.dirname(__file__)
PCAP=os.path.join(HERE,"../golden/mt7612-usbmon-2026-06-17/golden_init.pcap")
OUT=os.path.join(HERE,"../src/mt7612/init_replay.bin")
# FCE/firmware-specific regs handled by load_firmware() (collapse to FW marker)
FCE={0x0230,0x0232,0x0234,0x0236,0x09a0,0x09a4,0x09c4,0x0a6c,0x0800,0x09a8,0x0730,0x9018}
def read_pcap(path):
    d=open(path,'rb').read(); end='<' if d[:4]==b'\xd4\xc3\xb2\xa1' else '>'
    off,pk=24,[]
    while off+16<=len(d):
        ts,tu,ic,ol=struct.unpack(end+'IIII',d[off:off+16]); off+=16
        pk.append(d[off:off+ic]); off+=ic
    return pk
ops=[]
for pkt in read_pcap(PCAP):
    if len(pkt)<64: continue
    if chr(pkt[8])!='S': continue
    xfer=pkt[9]; ep=pkt[10]; lc,=struct.unpack('<I',pkt[36:40]); data=pkt[64:64+lc]
    if xfer==3 and not (ep&0x80):
        ops.append(('B',ep,lc,data))
    elif xfer==2:
        bm,br,wv,wi,wl=struct.unpack('<BBHHH',pkt[40:48])
        ops.append(('R' if bm&0x80 else 'W',br,(wv<<16)|wi,data,wv,wi))
out=bytearray(); fw_emitted=False; fce_pending=False; nW=nM=nC=nD=nFC=0
# A firmware-download bulk on ep0x08 is ALWAYS preceded by FCE DMA descriptor
# writes (WRITE_FCE bReq=0x42 to 0x0230..0x0236). MCU commands are not. Length
# is NOT a reliable discriminator: the partial last chunk of each region (ROM
# patch / ILM / DLM) is < 2048 and would otherwise be mis-tagged as an MCU
# command and replayed as raw firmware bytes into the running firmware.
for o in ops:
    if o[0]=='R': continue
    if o[0]=='B':
        ep,lc,data=o[1],o[2],o[3]
        if ep==0x08:
            if fce_pending:                        # firmware chunk
                if not fw_emitted: out.append(0xFF); fw_emitted=True
                fce_pending=False; nFC+=1
            elif data and len(data)>=4:            # genuine MCU command
                info=struct.unpack('<I',data[:4])[0]; ln=info&0xffff
                payload=data[4:4+ln]
                out.append(0x4D); out+=struct.pack('<I',info); out+=struct.pack('<H',len(payload)); out+=payload
                nM+=1
        continue  # skip ep0x07 data bulks for now
    tag,br,addr,data=o[0],o[1],o[2],o[3]
    if br==0x42:                                    # WRITE_FCE: DMA descriptor
        wi=o[5]
        if wi in (0x230,0x232,0x234,0x236):
            fce_pending=True
            if not fw_emitted: out.append(0xFF); fw_emitted=True
        continue
    if br==0x06:
        if addr in FCE:
            if not fw_emitted: out.append(0xFF); fw_emitted=True
            continue
        v=int.from_bytes(data[:4],'little') if data else 0
        out.append(0x06); out+=struct.pack('<II',addr,v); nW+=1
    elif br==0x46:
        if (addr&0xffff) in FCE:
            if not fw_emitted: out.append(0xFF); fw_emitted=True
            continue
        v=int.from_bytes(data[:4],'little') if data else 0
        out.append(0x46); out+=struct.pack('<HI',addr&0xffff,v); nC+=1
    elif br==0x01:
        out.append(0x01); out+=struct.pack('<H',(addr>>16)&0xffff); nD+=1
open(OUT,'wb').write(out)
print(f"wrote {OUT}: {len(out)} bytes  ({nW} writes, {nM} mcu, {nC} cfg, {nD} dev, {nFC} fw-chunks-collapsed, fw_marker={fw_emitted})")
