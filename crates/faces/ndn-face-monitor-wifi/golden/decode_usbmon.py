#!/usr/bin/env python3
"""Decode a Linux usbmon (LINKTYPE_USB_LINUX_MMAPPED=220) pcap from the kernel
rtl88x2eu driver into an ordered list of Realtek register writes / reads and
bulk-OUT transfers (firmware download, H2C, TX descriptors).

Realtek USB MMIO = USB control transfer: bRequest=0x05, wValue=reg addr,
wLength=size; host->device (bmRequestType 0x40)=write (value in SUBMIT data),
device->host (0xC0)=read (value in COMPLETE data). Frame TX / firmware / H2C =
bulk-OUT; first 48 bytes of a TX bulk-OUT are the TX descriptor.

Usage: decode_usbmon.py <file.pcap> [--regseq | --bulk | --txdesc]
"""
import struct, sys

def read_pcap(path):
    data = open(path, 'rb').read()
    magic = data[:4]
    if magic == b'\xd4\xc3\xb2\xa1':
        end = '<'
    elif magic == b'\xa1\xb2\xc3\xd4':
        end = '>'
    else:
        raise SystemExit('not a classic pcap: %r' % magic)
    net, = struct.unpack(end + 'I', data[20:24])
    off, pkts = 24, []
    while off + 16 <= len(data):
        ts, tu, incl, orig = struct.unpack(end + 'IIII', data[off:off+16])
        off += 16
        pkts.append((ts + tu/1e6, data[off:off+incl]))
        off += incl
    return net, pkts, end

def parse(pkt, end):
    if len(pkt) < 64:
        return None
    typ = chr(pkt[8]); xfer = pkt[9]; ep = pkt[10]; dev = pkt[11]
    length, = struct.unpack(end + 'I', pkt[32:36])
    len_cap, = struct.unpack(end + 'I', pkt[36:40])
    setup = pkt[40:48]
    payload = pkt[64:64+len_cap]
    return dict(type=typ, xfer=xfer, ep=ep, dev=dev, length=length,
                len_cap=len_cap, setup=setup, data=payload)

XFER = {0: 'ISO', 1: 'INT', 2: 'CTRL', 3: 'BULK'}

def main():
    path = sys.argv[1]
    mode = sys.argv[2] if len(sys.argv) > 2 else '--regseq'
    net, pkts, end = read_pcap(path)
    if net != 220:
        print(f'# warning: linktype {net} (expected 220)', file=sys.stderr)

    writes = []   # (addr, size, value)
    reads = []    # (addr, size, value)
    bulks = []    # (ep, len, first_bytes)
    pending_read = {}  # addr -> size, awaiting COMPLETE

    for ts, pkt in pkts:
        p = parse(pkt, end)
        if not p:
            continue
        if p['xfer'] == 2:  # control
            bmreq, breq, wval, widx, wlen = struct.unpack('<BBHHH', p['setup'])
            if breq != 0x05:
                continue  # not a Realtek MMIO access
            is_read = bool(bmreq & 0x80)
            if p['type'] == 'S' and not is_read:
                val = int.from_bytes(p['data'], 'little') if p['data'] else None
                writes.append((wval, wlen, val))
            elif p['type'] == 'S' and is_read:
                pending_read[(p['ep'], wval)] = wlen
            elif p['type'] == 'C' and is_read:
                val = int.from_bytes(p['data'], 'little') if p['data'] else None
                reads.append((wval, p['len_cap'], val))
        elif p['xfer'] == 3 and p['type'] == 'S' and not (p['ep'] & 0x80):
            bulks.append((p['ep'], p['len_cap'], p['data']))

    if mode == '--regseq':
        print(f'# {path}: {len(writes)} reg writes, {len(reads)} reg reads, {len(bulks)} bulk-OUT')
        for addr, size, val in writes:
            vs = f'0x{val:0{size*2}x}' if val is not None else '??'
            print(f'W{size}\t0x{addr:04x}\t{vs}')
    elif mode == '--reads':
        print(f'# {path}: {len(reads)} reg reads')
        for addr, size, val in reads:
            vs = f'0x{val:0{size*2}x}' if val is not None else '??'
            print(f'R{size}\t0x{addr:04x}\t{vs}')
    elif mode == '--bulk':
        print(f'# {path}: {len(bulks)} bulk-OUT transfers')
        from collections import Counter
        c = Counter(l for _, l, _ in bulks)
        for ln, n in sorted(c.items()):
            print(f'  len={ln:5d}  x{n}')
    elif mode == '--txdesc':
        # show the distinct bulk-OUT payloads that look like a TX desc+frame
        seen = 0
        for ep, ln, data in bulks:
            if ln < 32:
                continue
            print(f'# bulk-OUT ep{ep:#04x} len={ln}')
            print('  ' + data[:48].hex(' '))
            print('  frame[48:88]: ' + data[48:88].hex(' '))
            seen += 1
            if seen >= 4:
                break

if __name__ == '__main__':
    main()
