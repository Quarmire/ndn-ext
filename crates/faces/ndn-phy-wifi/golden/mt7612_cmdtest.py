#!/usr/bin/env python3
"""Isolation test: with the kernel mt76x2u having already loaded firmware + inited
the MCU (command-consuming), unbind the driver and send OUR MCU command framing.
If it's consumed/answered, our framing is correct and the macOS bug is in our
firmware-load; if it NAK/timeouts, our command framing itself is wrong."""
import sys, time, struct
import usb.core
dev = usb.core.find(idVendor=0x0e8d, idProduct=0x7612)
if dev is None: sys.exit("no device")
try:
    if dev.is_kernel_driver_active(0): dev.detach_kernel_driver(0)
    print("kernel driver detached")
except Exception as e: print("detach:", e)
# device is already configured by the kernel; set_configuration() is idempotent
# and just populates pyusb's internal handle state (no re-init of the device).
try: dev.set_configuration()
except Exception as e: print("set_config:", e)
EP_CMD, EP_RESP = 0x08, 0x85
seq=[0]
def mcu_cmd(cmd, payload):
    seq[0] = (seq[0]+1)&0xf or 1
    info = (len(payload)&0xffff)|(seq[0]<<16)|((cmd&0x7f)<<20)|(2<<27)|(1<<30)
    buf = struct.pack('<I', info)+payload+b'\0\0\0\0'
    while len(buf)%4: buf+=b'\0'
    t=time.time()
    try: dev.write(EP_CMD, buf, 1000); wms=int((time.time()-t)*1000)
    except Exception as e: return f"WRITE-FAIL {int((time.time()-t)*1000)}ms: {e}"
    try:
        r=dev.read(EP_RESP, 64, 300); return f"write={wms}ms resp={len(r)}B [{bytes(r[:12]).hex(' ')}]"
    except Exception as e: return f"write={wms}ms resp-TIMEOUT"
print("our framing for golden's first cmd (info should be 0x..f30008):")
print("  info =", hex((8)|(3<<16)|(0x1f<<20)|(2<<27)|(1<<30)))
for i in range(5):
    print(f"  cmd #{i}:", mcu_cmd(0x1f, bytes([0x03,0,0,0,0x70,0,0,0])))
