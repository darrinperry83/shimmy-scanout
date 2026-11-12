#!/usr/bin/env python3
"""Annotated disassembly dump for dyld shared cache (arm64e)."""
import sys
from dsc import dsc

def resolve_adrp_page(ins_bytes_va):
    return None

def adrp_target(a, imm_hex, next_add_off=0):
    # capstone already computes the pc-relative target for adrp in op_str? Usually not.
    return None

def dump(va, ninstr, base_off=None, label=''):
    d = dsc()
    if not getattr(d, 'images', None):
        d.load_images()
    insns = d.disasm(va, ninstr * 4 + 8, count=ninstr)
    if not insns:
        print('(no instructions)')
        return
    # build adrp map: for each adrp, compute target page
    lines = []
    for a, m, op, b in insns:
        note = ''
        if m == 'adrp':
            # op_str like "x8, #0x1e590a000"
            imm = int(op.split(',')[1].strip()[1:], 16)
            # adrp target = (PC & ~0xfff) + imm
            page = (a & ~0xfff) + imm
            img, off = d.image_at(page)
            if img:
                note = f'  ; adrp-> {img.split("/")[-1]}+0x{off:x}'
            else:
                note = f'  ; adrp-> 0x{page:x}'
        elif m in ('bl', 'b'):
            tgt = int(op[1:], 16)
            img, off = d.image_at(tgt)
            if img:
                note = f'  ; -> {img.split("/")[-1]}+0x{off:x}'
            else:
                note = f'  ; -> 0x{tgt:x}'
        lines.append((a, m, op, note, b))
    for a, m, op, note, b in lines:
        off = a - base_off if base_off is not None else a
        print(f'{off:07x}  {a:x}: {m:8s} {op:40s}{note}')

if __name__ == '__main__':
    va = int(sys.argv[1], 16)
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 80
    base_off = int(sys.argv[3], 16) if len(sys.argv) > 3 else None
    dump(va, n, base_off)
