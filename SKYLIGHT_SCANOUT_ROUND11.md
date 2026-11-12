# SkyLight CA external-update present — round 11 (correct swap-id field + server7)

Read-only disassembly (dyld shared cache via `dyld_info -disassemble`). macOS 26.5.1 /
25F80 arm64e. Offsets below are image-relative (== dladdr `dli_fbase`-relative, ==
`__TEXT` unslid-addr-relative); live `dli_fbase` this boot is SkyLight 0x1886f1000,
QuartzCore 0x18bff4000 (unslid __TEXT 0x186CD9000 / 0x18A5DC000).

## 1. server6 bug (confirmed)

server6 settled on `[iomfb_display + 0x6714]`. That field is only a *cached* copy of the
swap id, written in `IOMFBDisplay::finish_update_` under a mode-specific branch:

```
finish_update_ (+0x3559f0)  x22 = this + 0x63bc
  0x18A931A70  cbz w0, ...          ; vtable slot +0x8d0 (declkey 0xc43f) gate
  0x18A931A74  ldr w8, [x22,#0x358] ; [this+0x6714]
  0x18A931A78  cbnz w8, ...
  0x18A931A7C  ldr w8, [x21,#0x18]  ; page->[0x18] (the real swap id)
  0x18A931A80  str w8, [x22,#0x358] ; [this+0x6714] = page->[0x18]
```

When that vtable call returns 0 the cache is never filled → server6 saw `pend_swap=0`
and skipped the settle every frame.

## 2. Where finish_update actually writes the swap id

`IOMFBDisplay::finish_update` (QuartzCore `+0x35b300`, live 0x18c31300) — prologue sets
`x20 = this` and `x19 = this + 0x6398`:

```
SwapCancel (early):                                    SwapBegin (0x18A937A44):
  0x18A937578  ldr w8,[x19,#0x28c]   ; [this+0x6624]    0x18A937A1C  ldr w9,[x19,#0x28c] ; [this+0x6624]
  0x18A93757C  add x8,x8,x8,lsl#1    ; *3                0x18A937A20  umaddl x8,w9,w8,x20 ; page*0x30+this
  0x18A937580  lsl x19,x8,#4         ; *0x30             0x18A937A28  add x22,x8,#0x6678 ; page struct
  0x18A937588  add x23,x20,#0x6690   ; swap-id array     0x18A937A30  ldr w8,[x9,#0x18]! ; &page[0x18]
  0x18A93758C  ldr w1,[x23,x19]      ; swap id           0x18A937A3C  ldr x0,[x20,#0x6470]; conn
  0x18A937598  bl SwapCancel                             0x18A937A44  bl IOMobileFramebufferSwapBegin(conn,&page[0x18])
  0x18A93759C  str wzr,[x23,x19]     ; clear
```

`0x28c + 0x6398 == 0x6624`, so the **page index field is `[iomfb_display + 0x6624]`**
(not 0x28c — 0x28c on the object is unrelated). The page struct array base is 0x6678,
stride 0x30, and the swap id is at `page[+0x18]`:

```
swap_id = [iomfb_display + 0x6690 + [iomfb_display+0x6624]*0x30]      (0x6690 = 0x6678+0x18)
```

`can_update_` (`+0x34e0ec`, live 0x18c320ec) reads that exact slot as `page->[0x18]`
(`ldr w22,[x25,#0x18]` @0x18A92A2F0) and calls `IOMFBDisplay::swap_wait(this, id, tmo, b)`
which tail-calls `IOMobileFramebuffer::swap_wait(this+0x6458, id, tmo)`.

The same id is ALSO copied into the last `FrameInfo` of the swap queue — a
`std::vector<unique_ptr<FrameInfo>>` inline at `[0x6720..0x6728]` with `FrameInfo[0]`
= swap id (`str w8,[x23]` @0x18A938FB4, then `push_back` @0x18A939374).

`finish_update_` then advances the page index:
```
0x18A931A84  ldr w8,[x22,#0x268]  ; [this+0x6624]
0x18A931A88  str w8,[x22,#0x26c]  ; [this+0x6628] = old  (the just-presented page)
0x18A931A9C  str w8,[x22,#0x268]  ; [this+0x6624] = (old+1) % [this+0x662c]
```
So AFTER present the just-written page is `[0x6628]` and its slot is
`[iomfb_display + 0x6690 + [iomfb_display+0x6628]*0x30]`.

## 3. swap_wait callable + timeout (verified)

`CA::IOMobileFramebuffer::swap_wait(unsigned swap_id, unsigned timeout)` at
`OFF_qc_swap_wait = 0x2f876c` (live 0x18c2ec76c — matches server6). `this` is the
embedded framebuffer at `[iomfb_display+0x6458]`; it calls
`IOMobileFramebufferSwapWait(*this, swap_id, timeout)`. **Id first, timeout second.** ✓

Timeout units: `can_update_` itself passes `mov w2,#-0x7fffffff` = `0x80000001` ns
≈ 2.1 s (the value server6 already used). ✓

## 4. Payload (server7)

`payload_scanout_server7.m` → `/tmp/rdgpu-scanout-server7-payload`. Changes from server6:
- settle now reads the swap id **AFTER** present from the FrameInfo queue tail
  (`[[iomfb_display+0x6728]-8][0]`, authoritative FIFO) with the page slot
  `[iomfb_display+0x6690+[iomfb_display+0x6628]*0x30]` as fallback/cross-check.
- per-frame `RDGPU_SCANOUT_IOMFB` now logs `pg_next`(0x6624), `pg_prev`(0x6628),
  `pg_swap`(page slot) and `fiq_tail_swap`(queue tail) so ONE run confirms the id is
  nonzero after present and changes per frame.
- 0 objc_msgSend (verified `nm -u`).

Build:
```
cd .../integration/rdmetal
clang -arch arm64e -O2 -bundle payload_scanout_server7.m \
    -o /tmp/rdgpu-scanout-server7-payload \
    -framework Foundation -framework IOSurface -framework CoreFoundation
```

## 5. Dock validation (uid 501, no root) — PASS (clean no-op)

```
== dock_inject == payload: /tmp/rdgpu-scanout-server7-payload
dlopen result: 0x5f00006c6f88b0 (SUCCESS — handle returned; constructor ran)
```
```
RDGPU_SCANOUT_LOAD pid=33587 mode=server7 want_id=0x1e sync=1 settle=1
RDGPU_SCANOUT_QC base=0x18bff4000 swap_wait=0x2d5080018c2ec76c
RDGPU_SCANOUT_BASE skyBase=0x1886f1000
RDGPU_SCANOUT_SKYCHEIN ref=0x0 ... (all NULL)
RDGPU_SCANOUT_DONE result=no-display
```

## 6. Root command (unchanged flow)

```
cd /Users/dperry/Documents/Codex/2026-11-07/task/linux-shim-integration-next/repo/integration/rdmetal
sudo ./ws_inject_manual_d --register /tmp/rdgpu-scanout-server7-payload
sudo grep -E 'RDGPU_SCANOUT' /tmp/rdgpu-scanout.log | tail -60
```

Expect per frame: `RDGPU_SCANOUT_IOMFB ... pg_swap=<n> fiq_tail_swap=<n>` with `<n>` nonzero
and increasing, `RDGPU_SCANOUT_PRESENT ... ret=1`, `RDGPU_SCANOUT_SETTLE swap_id=<n> ...
ret=0`, repeated indefinitely (no PRESENT_FAILED).
