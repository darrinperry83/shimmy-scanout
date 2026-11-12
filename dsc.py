#!/usr/bin/env python3
"""dyld shared cache reader + ARM64 disassembler for macOS 26 arm64e.
Read-only. Maps unslid VM addresses -> subcache file offsets and disassembles.
"""
import struct, os, sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN

BASE = '/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/'
MAIN = BASE + 'dyld_shared_cache_arm64e'

class DSC:
    def __init__(self):
        self.md = Cs(CS_ARCH_ARM64, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
        self.md.detail = True
        main = open(MAIN, 'rb').read()
        self.shared_start = struct.unpack_from('<Q', main, 224)[0]
        self.shared_size = struct.unpack_from('<Q', main, 232)[0]
        subOff = struct.unpack_from('<I', main, 392)[0]
        subCount = struct.unpack_from('<I', main, 396)[0]
        self._fh = {}  # path -> file object (lazy, kept open)
        self.mappings = []  # (addr, end, path, fileoff)
        # main cache's own mappings
        self._add_mappings(MAIN, main)
        for i in range(subCount):
            o = subOff + i * 56
            vmoff = struct.unpack_from('<Q', main, o + 16)[0]
            suffix = main[o+24:o+56].split(b'\x00')[0].decode()
            fn = 'dyld_shared_cache_arm64e' + suffix
            path = BASE + fn
            if not os.path.exists(path):
                continue
            dd = open(path, 'rb').read()
            self._add_mappings(path, dd)
        self.mappings.sort(key=lambda m: m[0])

    def _add_mappings(self, path, dd):
        mo = struct.unpack_from('<I', dd, 16)[0]
        mc = struct.unpack_from('<I', dd, 20)[0]
        for i in range(mc):
            o = mo + i * 32
            addr = struct.unpack_from('<Q', dd, o)[0]
            size = struct.unpack_from('<Q', dd, o + 8)[0]
            fo = struct.unpack_from('<Q', dd, o + 16)[0]
            self.mappings.append((addr, addr + size, path, fo))

    def fileobj(self, path):
        if path not in self._fh:
            self._fh[path] = open(path, 'rb')
        return self._fh[path]

    def resolve(self, va):
        for (a, b, path, fo) in self.mappings:
            if a <= va < b:
                return path, fo + (va - a)
        return None, None

    def read(self, va, n):
        path, off = self.resolve(va)
        if path is None:
            return None
        fh = self.fileobj(path)
        fh.seek(off)
        return fh.read(n)

    def read_u32(self, va):
        b = self.read(va, 4)
        return struct.unpack('<I', b)[0] if b else None

    def read_u64(self, va):
        b = self.read(va, 8)
        return struct.unpack('<Q', b)[0] if b else None

    def disasm(self, va, n, count=None):
        """Yield (addr, mnemonic, op_str, bytes_hex)."""
        # read a generous window; n = number of instructions if count else bytes
        if count is None:
            data = self.read(va, n)
        else:
            data = self.read(va, n * 4 + 4)
        if not data:
            return
        out = []
        for ins in self.md.disasm(data, va):
            out.append((ins.address, ins.mnemonic, ins.op_str, ins.bytes.hex()))
            if count is not None and len(out) >= count:
                break
        return out

    def ins(self, va):
        """Single instruction."""
        r = self.disasm(va, 4)
        return r[0] if r else None

    def read_cstring(self, va):
        path, off = self.resolve(va)
        if path is None:
            return None
        fh = self.fileobj(path)
        fh.seek(off)
        s = b''
        while len(s) < 512:
            c = fh.read(1)
            if not c or c == b'\x00':
                break
            s += c
        return s.decode('utf-8', 'replace')

    def load_images(self):
        """Parse the .map file for image __TEXT ranges -> (path, start, end)."""
        imgs = []
        mappath = BASE + 'dyld_shared_cache_arm64e.map'
        cur = None
        for line in open(mappath, 'r', errors='replace'):
            line = line.rstrip('\n')
            if line.startswith('/'):
                cur = line
            elif line.strip().startswith('__TEXT'):
                parts = line.split()
                # __TEXT 0x... -> 0x...
                s = int(parts[1], 16); e = int(parts[3], 16)
                imgs.append((cur, s, e))
        imgs.sort(key=lambda x: x[1])
        self.images = imgs
        return imgs

    def image_at(self, va):
        for (p, s, e) in getattr(self, 'images', []):
            if s <= va < e:
                return p, va - s
        return None, 0

# shared singleton
_dsc = None
def dsc():
    global _dsc
    if _dsc is None:
        _dsc = DSC()
    return _dsc

if __name__ == '__main__':
    d = dsc()
    print('shared region', hex(d.shared_start), hex(d.shared_start + d.shared_size))
    print('mappings', len(d.mappings))
    d.load_images()
    for va in [0x1870E9890, 0x1870EAF1C]:
        p, o = d.resolve(va)
        img, off = d.image_at(va)
        print(f'0x{va:x}: file={p} off=0x{o:x}  img={img}+0x{off:x}')
