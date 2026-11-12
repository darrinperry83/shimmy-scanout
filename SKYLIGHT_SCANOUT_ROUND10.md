# SkyLight CA external-update present cadence — round 10 (root cause + server6)

Read-only disassembly + corrected payload. macOS 26.5.1 / 25F80 arm64e.
SkyLight dli_fbase = 0x1886f1000, QuartzCore dli_fbase = 0x18bff4000 this boot.

## 1. Exact cause of the 3rd-frame ret=0

`present_iosurface` external-update path returns 0 on a clean `mov w21,#0` at
+0x1124 (0x188b03380), reached from the check at +0x380 (0x188b03098):

```
+372  mov w2,#0               ; flags=0
+376  bl  objc_msgSend$canUpdateWithFlags:
+380  tbz w0,#0x0, +1124      ; canUpdateWithFlags==false -> mov w21,#0; return 0
```

`canUpdateWithFlags:` is NOT a "render-update still open" check — it is the IOMFB
**swap-queue depth** gate. Full chain (QuartzCore; vptr discriminator 0x27e3 =
siphash("_ZTVN2CA12WindowServer7DisplayE")):

```
-[CAWindowServerDisplay canUpdateWithFlags:]        +0x2c79cc
  locks [self+8], calls [[self+8]+0x40] ->vtable[0x8] (declkey 0x77b5)
CA::WindowServer::Server::can_update(unsigned)       +0x2c5d0c
  = ([server+0x58] ->vtable[0x168](flags,0.0,0.0)) == 0
CA::WindowServer::IOMFBDisplay::can_update(u,d,d)    +0x295534  (wrapper)
CA::WindowServer::IOMFBDisplay::can_update_(u,d,d)   +0x2860ec  (the real check)
```

`can_update` returns 0 (="accept update") only when `can_update_` returns true, i.e.
when an IOMFB swap slot is free. Each `present_iosurface` enqueues ONE swap via
`finish_update`; the swap is freed only at the display's next vblank. Presenting
without a settle fills the finite in-flight queue (depth 2), so the 3rd consecutive
update gets `can_update != 0` (one of 0xff/0xe9/0xfe/0xfd/0xfc/0xfb/0xfa — most
likely 0xfa, which increments the miss counter [iomfb+0x63c0]).

`sync=true` does NOT drain the queue: its `MetalContext::Flush(true,0,0,0)` only
flushes the GPU + signals a shared event (no IOMFB swap wait). That is why
sync=true-vs-false only moves the failure between the 2nd and 3rd frame.

## 2. Working per-frame cadence (server6)

```
1. re-assert flags[+0x76c] |= 0x4
2. present_iosurface(hw, io, sync=TRUE)              # EVERY frame
3. settle: IOMobileFramebuffer::swap_wait(pending_swap_id, ~2.1s) on the
   embedded CA::IOMobileFramebuffer at [iomfb_display + 0x6458]
```

The settle reads the pending swap id [iomfb_display + 0x6714] (set by the just-run
`finish_update`) and blocks in `IOMobileFramebufferSwapWait` until that swap is
consumed at vblank, so the in-flight queue never exceeds depth 1 → one present per
refresh, `canUpdateWithFlags` stays true forever. Gated on a non-zero swap id and
bounded (~2.1 s) so a stale id cannot hang the server thread.

Object walk (raw derefs, no objc_msgSend):
`ca=[hw+0x1d8] -> lock_holder=[ca+0x8] -> server=[lock_holder+0x40] ->
iomfb_display=[server+0x58]`.

## 3. Payload

`payload_scanout_server6.m` -> `/tmp/rdgpu-scanout-server6-payload`. Builds on
server5 (heap-copy vtable hook + `--register` service) and adds: sync=true every
frame (default; `/tmp/rdgpu-scanout-sync=0` forces async), the swap_wait settle
(default; `/tmp/rdgpu-scanout-settle=0` disables), and per-frame IOMFB state logging
(`RDGPU_SCANOUT_IOMFB` line: state[0..5], p290, b72f6, b389, miss counter, pend_swap)
so a live run pinpoints the exact error code if it ever returns.

Build (verified: 0 objc_msgSend, swap_wait resolves to 0x18c2ec76c):

```
cd .../integration/rdmetal
clang -arch arm64e -O2 -bundle payload_scanout_server6.m \
    -o /tmp/rdgpu-scanout-server6-payload \
    -framework Foundation -framework IOSurface -framework CoreFoundation
```

## 4. Dock validation (uid 501, no root) — PASS (clean no-op)

```
== dock_inject == payload: /tmp/rdgpu-scanout-server6-payload
dlopen result: 0x280006c6f8430 (SUCCESS — handle returned; constructor ran)
```
```
RDGPU_SCANOUT_LOAD pid=33587 mode=server6 want_id=0x1e sync=1 settle=1
RDGPU_SCANOUT_QC base=0x18bff4000 swap_wait=0x2d5080018c2ec76c
RDGPU_SCANOUT_BASE skyBase=0x1886f1000
RDGPU_SCANOUT_SKYCHEIN ref=0x0 ... (all NULL)
RDGPU_SCANOUT_DONE result=no-display
```

## 5. Root command

```
cd /Users/dperry/Documents/Codex/2026-11-07/task/linux-shim-integration-next/repo/integration/rdmetal
sudo ./ws_inject_manual_d --register /tmp/rdgpu-scanout-server6-payload
sudo grep -E 'RDGPU_SCANOUT' /tmp/rdgpu-scanout.log | tail -60
```

Expect in WindowServer: `IOMFB_RESOLVE iomfb_display=<non-null>` →
`VTABLE_PATCH_RESULT rc=0 patched=1` → per frame
`RDGPU_SCANOUT_IOMFB ...` + `RDGPU_SCANOUT_PRESENT ... sync=1 ret=1` +
`RDGPU_SCANOUT_SETTLE swap_id=<n> ret=0`, repeated indefinitely (no PRESENT_FAILED).
