# SkyLight scanout present-loop — round 15 (H1/H2 disproven; vsync-paced present via drain-before-present)

Read-only disassembly (`dyld_info -all_dyld_cache -disassemble`) of
`IOMobileFramebuffer.framework` + `QuartzCore`. macOS 26.5.1 / 25F80 arm64e.
Shared-cache slide this boot = **0x1A18000**. IOMobileFramebuffer dli_fbase
(unslid) **0x18F246000** (live 0x190c5e000); QuartzCore dli_fbase (unslid)
0x18A5DC000 (live 0x18bff4000).

## 1. Verdict on the three hypotheses

| H | Claim | Verdict | Evidence |
|---|---|---|---|
| H1 | the swap id we read is NOT the true IOMFB swap id | **FALSE** | `_kern_SwapBegin` writes the kernel's id straight into `page[0x18]` (and `conn->[0xb0]`) and returns 0, not the id. `can_update_` passes that same `page[0x18]` value (via `[0x6714]`) straight to `swap_wait`. |
| H2 | `SwapWaitWithTimeout` has a different real signature | **FALSE** | `_kern_SwapWaitWithTimeout(conn, u32 swapID, u32 waitOptions, double seconds)` emits selector 6 with scalars `[swapID, waitOptions, fcvtzu(seconds*1000.0)]`; scale double == 1000.0. The payload's typedef matches. |
| H3 | drain is tied to vsync pacing; present once per vsync | **TRUE (chosen)** | The plain `swap_wait` hard-codes timeout=0 (non-blocking poll → Busy), and `SwapWaitWithTimeout` still returns Busy because can_update_'s `waitOptions=0x80000001` is a non-blocking flag — the one blocking waiter (`IOMobileFramebufferWaitSurface`) uses `0x1`. |

## 2. Disassembly evidence

### IOMobileFramebuffer dispatchers (each is `cbz x0; ldr xN,[x0,#slot]; cbz; braaz`)

```
_IOMobileFramebufferSwapBegin            0x18F265BB4   conn->[0x9a8]   (x1 = &swap_id out)
_IOMobileFramebufferSwapEnd              0x18F265BD0   conn->[0x9b0]
_IOMobileFramebufferSwapWait             0x18F265C48   conn->[0x9e0]   (x1=id, x2=options)
_IOMobileFramebufferSwapWaitWithTimeout  0x18F265C64   conn->[0x9e8]   (x1=id, x2=options, d0=seconds)
_IOMobileFramebufferWaitSurface          0x18F265CF0   conn->[0x9e0]   waitOptions=0x1, id=conn->[0xb0]
```

### `_kern_SwapBegin` (conn->[0x9a8], 0x18F269BBC)

```
selector = 4; 0 input scalars; 1 output scalar
ldr w0,[x0,#0x14] ; add x4,sp,#0x8 ; add x5,sp,#0x4 ; mov w1,#0x4
bl _IOConnectCallScalarMethod
cbz w0, ok ; else return 0xE00002BC
ok:  ldr w8,[sp,#0x8]          ; kernel swap id (output scalar[0])
     str w8,[x19,#0xb0]        ; conn->[0xb0] = id
     str w8,[x20]              ; *out = page[0x18] = id      <- the true id
     mov w0,#0 ; ret            ; RETURN VALUE is 0, NOT the id
```

=> `page[0x18]` **is** the kernel swap id. H1 false. (finish_update calls it as
`SwapBegin([this+0x6470], &page[0x18])` @0x18A937A44; can_update_ reads that slot
and `swap_wait`s on it, so the native path uses the identical value.)

### `_kern_SwapWait` (conn->[0x9e0], 0x18F269EA0)

```
selector = 6; scalars = [swapID(w1), waitOptions(w2), timeout=0]  (str xzr,[sp,#0x10])
```
timeout **hard-coded 0** → non-blocking poll → kIOReturnBusy (0xE00002D5) while in flight.

### `_kern_SwapWaitWithTimeout` (conn->[0x9e8], 0x18F269F14)

```
fmul d0,d0,d1      ; d1 = 1000.0 (scale const @ +0x31cd0 from dli_fbase)
fcvtzu x8,d0       ; x8 = (u64)(seconds*1000)  = timeout in milliseconds
selector = 6; scalars = [swapID(w1), waitOptions(w2), timeout_ticks(x8)]
```
Signature is exactly `(conn, u32 swapID, u32 waitOptions, double seconds)`. H2 false.
(server9/10 passed `settle_ms/1000.0` = 0.05 s → 50 ms, a valid blocking timeout, yet
the kernel still returned Busy — because of waitOptions, below.)

### `CA::IOMobileFramebuffer::swap_wait` (QuartzCore 0x18A8D476C, live 0x18C2EC76C)

```
swap_wait(this, u32 swapID, u32 waitOptions):
    ldr x0,[x21]              ; x0 = this[0] = *(u64*)(iomfb_display+0x6458) = the conn
    mov x1,x20 ; mov x2,x19
    bl _IOMobileFramebufferSwapWait   ; (the PLAIN, timeout=0 variant)
```
`can_update_` calls it as `swap_wait(this+0x6458, [0x6714], 0x80000001)`
(@0x18A92A184..0x18A92A190). So the payload's `conn = *(u64*)(iomfb_display+0x6458)`
is exactly the connection the native drain uses. ✓

### Why the blocking settle returned Busy — waitOptions

- `can_update_` → `swap_wait(..., 0x80000001)` (poll semantics; round-14 "poll-and-clear").
- `IOMobileFramebufferWaitSurface` → `SwapWait(conn, conn->[0xb0], 0x1)` — the **only**
  waiter using `0x1`. `0x80000001` = `0x80000000|0x1`; the `0x80000000` bit is the
  non-blocking/poll flag, so `SwapWaitWithTimeout(..., 0x80000001, timeout)` returns
  Busy regardless of timeout. (Kernel-side; not directly disassembled here, but the
  two distinct waitOptions values + the observed Busy are consistent.)

## 3. Chosen fix — server11 (vsync-paced present = H3)

`payload_scanout_server11.m` → `/tmp/rdgpu-scanout-server11-payload`.

Replace the broken **present-then-settle** with **drain-before-present**:

```
present K    -> read swap id S_K  (FrameInfo tail [[0x6728]-8][0], page slot fallback)
drain        -> poll swap_wait(fb, S_K, 0x80000001) every 500us until ret==0
                (that swap consumed at vblank -> a page slot freed) or 50ms budget
present K+1  -> ...
```

This is robust because it reuses the **verified** non-blocking poll that `can_update_`
itself relies on (returns 0 once the swap is consumed), instead of the un-blocking
`SwapWaitWithTimeout`. Queue depth stays ≤ 1 → `present_iosurface` returns 1 forever.

Secondary: the optional settle (`/tmp/rdgpu-scanout-settle=1`) now passes
`waitOptions=0x1` (the WaitSurface value) to `SwapWaitWithTimeout` instead of
`0x80000001`. Default OFF — drain-before-present supersedes it.

Build (0 `objc_msgSend`, verified):
```
cd .../integration/rdmetal
clang -arch arm64e -O2 -bundle payload_scanout_server11.m \
    -o /tmp/rdgpu-scanout-server11-payload \
    -framework Foundation -framework IOSurface -framework CoreFoundation
```

Dock validation (uid 501, no root) — PASS (clean no-op):
```
== dock_inject == payload: /tmp/rdgpu-scanout-server11-payload
dlopen result: 0x6b00006c6fb210 (SUCCESS — handle returned; constructor ran)
```
```
RDGPU_SCANOUT_LOAD pid=63068 mode=server11 want_id=0x1e sync=1 settle=0 settle_ms=50 throttle_us=0 replay=1 drain=1 drain_ms=50
RDGPU_SCANOUT_QC base=0x18bff4000 swap_wait=0x2d5080018c2ec76c
RDGPU_SCANOUT_SWAP_WAIT_TIMEOUT sym=0xfe40800190c7dc64
RDGPU_SCANOUT_BASE skyBase=0x1886f1000
RDGPU_SCANOUT_DONE result=no-display
```
(`replay=1` is a stale `/tmp/rdgpu-scanout-replay` knob from round 14; the Dock has no
display so `rd_apply_replay()` returns early. The root command below sets it 0.)

## 4. Root command + recommended knobs

```
cd /Users/dperry/Documents/Codex/2026-11-07/task/linux-shim-integration-next/repo/integration/rdmetal

# recommended: drain-before-present ON, everything else OFF
sudo sh -c 'echo 1 > /tmp/rdgpu-scanout-drain; echo 50 > /tmp/rdgpu-scanout-drain-ms; \
             echo 0 > /tmp/rdgpu-scanout-settle; echo 0 > /tmp/rdgpu-scanout-throttle-us; \
             echo 0 > /tmp/rdgpu-scanout-replay; echo 1 > /tmp/rdgpu-scanout-sync'
sudo ./ws_inject_manual_d --register /tmp/rdgpu-scanout-server11-payload
sudo grep -E 'RDGPU_SCANOUT' /tmp/rdgpu-scanout.log | tail -80

# fallback A: also enable the waitOptions=0x1 blocking settle (experimental)
#   sudo sh -c 'echo 1 > /tmp/rdgpu-scanout-settle'
# fallback B: time-based throttle at 60 Hz instead of drain
#   sudo sh -c 'echo 0 > /tmp/rdgpu-scanout-drain; echo 16667 > /tmp/rdgpu-scanout-throttle-us'
```

Expected per frame: `RDGPU_SCANOUT_DRAIN swap_id=<n> ret=0 polls=<1..34> elapsed_us=<~16667>`
then `RDGPU_SCANOUT_PRESENT ... ret=1` — repeated indefinitely (no `PRESENT_FAILED`).
