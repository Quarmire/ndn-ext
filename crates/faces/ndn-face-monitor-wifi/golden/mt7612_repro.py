#!/usr/bin/env python3
"""Reproduce the macOS MT7612U bring-up (firmware load + MCU commands) on Linux
via pyusb, so usbmon can capture OUR traffic to diff against golden_init.pcap.
Ports the logic in src/mt7612/mod.rs exactly. Run under usbmon capture:

  sudo .../python3 mt7612_repro.py   (kernel mt76x2u must be unbound first)
"""
import sys, time, struct
import usb.core, usb.util

VID, PID = 0x0e8d, 0x7612
REQ_OUT, REQ_IN = 0x40, 0xc0
CTRL_TO = 500
ROM = open(sys.argv[1], 'rb').read()
RAM = open(sys.argv[2], 'rb').read()

dev = usb.core.find(idVendor=VID, idProduct=PID)
if dev is None: sys.exit("no MT7612U")
try:
    if dev.is_kernel_driver_active(0): dev.detach_kernel_driver(0)
except Exception as e: print("detach:", e)
ok=False
for attempt in range(8):
    try:
        dev.set_configuration(1); ok=True; break
    except Exception as e:
        print(f"set_config try {attempt}: {e}"); time.sleep(0.5)
        dev = usb.core.find(idVendor=VID, idProduct=PID)
        if dev is None: time.sleep(0.5); dev = usb.core.find(idVendor=VID, idProduct=PID)
print("configured:", ok)

EP_CMD=0x08; EP_RESP=0x85

def wr(addr, val):
    dev.ctrl_transfer(REQ_OUT, 0x06, addr>>16, addr & 0xffff, struct.pack('<I', val), CTRL_TO)
def rr(addr):
    d = dev.ctrl_transfer(REQ_IN, 0x07, addr>>16, addr & 0xffff, 4, CTRL_TO)
    return struct.unpack('<I', bytes(d))[0]
def wr_fce(reg, val):
    dev.ctrl_transfer(REQ_OUT, 0x42, val, reg, None, CTRL_TO)
def wr_cfg(addr, val):
    dev.ctrl_transfer(REQ_OUT, 0x46, 0, addr, struct.pack('<I', val), CTRL_TO)

def prelude():
    # Early USB/PSE DMA config the golden does FIRST, before any FCE/firmware.
    for a, v in [(0x2934,0x492),(0x23f4,0xff64a4e2),(0x231c,0x08081010),
                 (0x232c,0x404),(0x2308,0x7070),(0x1340,0x04101b3f),
                 (0x2610,0x02000006),(0x2934,0x592),(0x110c,0x15f),(0x1004,0xc)]:
        try: wr(a, v)
        except Exception as e: print(f"  prelude wr {a:#06x}: {e}")

def fce_setup():
    wr_cfg(0x9018, 0x00c00020)
    dev.ctrl_transfer(REQ_OUT, 0x01, 0x0001, 0, None, CTRL_TO)  # DEV_MODE 1
    wr(0x0800, 1); wr(0x09a0, 0x00400230); wr(0x09a4, 1)
    wr(0x09c4, 0x44); wr(0x0a6c, 0x3)

def fw_send(data, offset, mx):
    chunk = mx - 8; pos = 0
    while pos < len(data):
        cur = min(chunk, len(data)-pos); dst = offset+pos
        wr_fce(0x0230, dst & 0xffff); wr_fce(0x0232, dst>>16)
        wr_fce(0x0234, 0); wr_fce(0x0236, cur)
        buf = struct.pack('<I', 0x50000000 | cur) + data[pos:pos+cur] + b'\0\0\0\0'
        while len(buf) % 4: buf += b'\0'
        dev.write(EP_CMD, buf, 1000)
        for _ in range(100):
            if rr(0x09a8) & 1 == 0: break
            time.sleep(0.001)
        wr(0x09a8, 1)
        pos += cur

def load_rom_patch():
    fce_setup()
    fw_send(ROM[30:], 0x90000, 2048)
    # enable_patch + reset_wmt (WMT class requests)
    dev.ctrl_transfer(0x20, 0x01, 0x0012, 0x0000, bytes([0x6f,0xfc,0x08,0x01,0x20,0x04,0,0,0,0x09,0]), CTRL_TO)
    time.sleep(0.02)
    dev.ctrl_transfer(0x20, 0x01, 0x0012, 0x0000, bytes([0x6f,0xfc,0x05,0x01,0x07,0x01,0,0x04]), CTRL_TO)
    time.sleep(0.02)

def load_ram():
    ilm = struct.unpack('<I', RAM[0:4])[0]; dlm = struct.unpack('<I', RAM[4:8])[0]
    fce_setup()
    fw_send(RAM[32:32+ilm], 0x80000, 0x3900)
    fw_send(RAM[32+ilm:32+ilm+dlm], 0x110000, 0x3900)

def start_mcu():
    wr(0x09a8, 0x14)
    dev.ctrl_transfer(REQ_OUT, 0x01, 0x0012, 0, None, CTRL_TO)  # load IVB
    for _ in range(200):
        if rr(0x0730) & 1: break
        time.sleep(0.001)
    wr(0x0730, 0x001140fb)
    wr(0x0800, 1); wr_cfg(0x9018, 0x00c40020)
    return rr(0x0730)

seq = [0]
def mcu_cmd(cmd, payload):
    seq[0] = (seq[0] + 1) & 0xf or 1
    info = (len(payload)&0xffff) | (seq[0]<<16) | ((cmd&0x7f)<<20) | (2<<27) | (1<<30)
    buf = struct.pack('<I', info) + payload + b'\0\0\0\0'
    while len(buf) % 4: buf += b'\0'
    t = time.time()
    try:
        dev.write(EP_CMD, buf, 1000)
        wms = int((time.time()-t)*1000)
    except Exception as e:
        return f"WRITE-FAIL {int((time.time()-t)*1000)}ms: {e}"
    try:
        r = dev.read(EP_RESP, 64, 300)
        return f"write={wms}ms resp={len(r)}B [{bytes(r[:8]).hex(' ')}]"
    except Exception as e:
        return f"write={wms}ms resp-TIMEOUT"

print("=== prelude (USB/PSE config) ===")
prelude()
print("=== load firmware ===")
load_rom_patch(); load_ram()
print("start_mcu COM_REG0 =", hex(start_mcu()))
print("=== send MCU commands ===")
# golden's first command: cmd 0x1f, payload 03 00 00 00 70 00 00 00
for i in range(5):
    print(f"  cmd #{i}:", mcu_cmd(0x1f, bytes([0x03,0,0,0,0x70,0,0,0])))
