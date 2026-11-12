# SkyLight scanout present-loop drain — round 13 (the +0x8d0 gate, a blocking settle, throttle)

Read-only disassembly + corrected payload. macOS 26.5.1 / 25F80 arm64e.
Shared-cache slide this boot = **0x1A18000** (python-verified): SkyLight live base
0x1886f1000 (unslid __TEXT 0x186CD9000), QuartzCore live base 0x18bff4000 (unslid
__TEXT 0x18A5DC000). All QuartzCore disassembly below is live; image-relative offset
= live − 0x1A18000.

## 1. WHAT the +0x8d0 gate is (task 1) — `replay_active() const`

`IOMFBDisplay::finish_update_` (QuartzCore +0x3559f0, live 0x18C3499F0) starts:

```
0x18c349a48  ldr   x16,[x19]          ; vptr
0x18c349a50  movk  x17,#0x27e3,lsl#48 ; vptr discriminator (_ZTVN2CA12WindowServer7DisplayE)
0x18c349a54  autda x16,x17
0x18c349a58  mov   x17,#0x8d0
0x18c349a5c  add   x16,x16,x17        ; vtable[+0x8d0]
0x18c349a60  ldr   x8,[x16]
0x18c349a68  movk  x16,#0xc43f,lsl#48 ; declkey 0xc43f
0x18c349a6c  blraa x8,x16             ; vtable[0x8d0](this)
0x18c349a70  cbz   w0, 0x18c349a84    ; ==0 -> skip the cache write
0x18c349a7c  ldr   w8,[x21,#0x18]     ; page[0x18] (real swap id)
0x18c349a80  str   w8,[x22,#0x358]    ; [this+0x6714] = page[0x18]
```

The declkey is resolved by siphash (same code as the payload):

```
0xc43f == siphash("_ZNK2CA12WindowServer7Display13replay_activeEv")
```

and the two functions are:

```
CA::WindowServer::Display::replay_active() const          ->  mov w0,#0; ret     (false)
CA::WindowServer::IOMFBDisplay::replay_active() const     ->  ldrb w0,[x0,#0x72f7]; ret
```

So **vtable slot +0x8d0 = IOMFBDisplay::replay_active() const = the byte
`[iomfb_display+0x72f7]`** — the "Replay" (display-capture streaming) feature flag.
When it is 0 (our flow), `finish_update_` never copies the swap id into `[0x6714]`.

## 2. The critical refinement: [0x6714] is gated in BOTH directions

`IOMFBDisplay::can_update_` (QuartzCore +0x34e0ec, live 0x18C3420EC) reads the SAME
field under the SAME gate — its very first block is:

```
0x18c342150  ldr   x16,[x19]; autda (0x27e3)
0x18c342160  mov   x17,#0x8d0; add x16,x16,x17
0x18c342170  movk  x16,#0xc43f; blraa x8,x16      ; replay_active()
0x18c342178  cbz   w0, 0x18c342200                ; ==0 -> SKIP the [0x6714] read
0x18c34217c  ldr   w1,[x27,#0x2d8]                ; [this+0x6714]   (x27=this+0x643c)
0x18c342180  cbz   w1, 0x18c342200
0x18c342190  bl    0x18c2ec76c                    ; CA::IOMobileFramebuffer::swap_wait([0x6714],0x80000001)
```

Consequence: **writing `[0x6714] = page_swap` (task 1 option b) is a NO-OP while
`replay_active()==0`** — can_update_ never looks at it. The only way to light the
`[0x6714]` path is to set `[0x72f7]=1` ("replay active"), which is an invasive
feature-flag change with replay-path side effects, so it was NOT chosen. server9
still writes `[0x6714] = page_swap` (harmless; mirrors `finish_update_`; keeps the
field correct if replay ever engages mid-run), but the real drain is §3 + §4.

(Why the parent's live run showed present ret=1 for ~4 frames then ret=0: the page
array is deeper than 2 — `pg_next` reached 2 — and each present enqueues one swap
consumed at vblank; presenting faster than vblank fills the in-flight queue and
`can_update` returns false.)

## 3. Why server8's settle always returned kIOReturnBusy, and the blocking fix

`CA::IOMobileFramebuffer::swap_wait` (QuartzCore +0x2f876c, live 0x18c2ec76c) is a
3-arg wrapper that tail-calls the PLAIN `IOMobileFramebufferSwapWait(conn, swapID,
waitOptions)`. That plain entry (0x190c7dc48, `conn->[0x9e0]`) emits selector 6
(swapWait) with a HARD-CODED timeout of 0 → non-blocking poll → `kIOReturnBusy`
(0xE00002D5 = −536870187) immediately, which is exactly what the live log showed:

```
RDGPU_SCANOUT_SETTLE swap_id=23031712 ... ret=-536870187   (= kIOReturnBusy)
```

The BLOCKING variant is `IOMobileFramebufferSwapWaitWithTimeout(conn, swapID,
waitOptions, double seconds)` (0x190c7dc64, `conn->[0x9e8]` impl 0x190c81f14). That
impl does `fcvtzu(seconds * scale)` and emits the same selector 6 but with a real
timeout scalar `[swapID, waitOptions, timeout_ticks]`. It blocks until the swap is
consumed at vblank (or the timeout elapses). `conn` is the raw
`IOMobileFramebufferConnection*` at `*(uint64_t*)(iomfb_display+0x6458)`, and the
symbol is dlsym-able (verified: resolves to 0x190c7dc64).

## 4. server9 payload

`payload_scanout_server9.m` → `/tmp/rdgpu-scanout-server9-payload`. Changes from
server8:

1. **Chosen drain (task 1)**: after each successful present, read the page-slot swap
   id + FrameInfo queue tail, then
   - write `[iomfb_display+0x6714] = page_swap` (option b, harmless no-op, mirrors
     finish_update_); and
   - settle with the **BLOCKING** `IOMobileFramebufferSwapWaitWithTimeout(conn, id,
     0x80000001, settle_timeout_s)` (resolved via dlsym), falling back to the
     non-blocking `swap_wait` if the symbol is unavailable. Default settle timeout
     `RDGPU_SCANOUT_SETTLE_MS=50`.
2. **Throttle knob (task 2)**: `RDGPU_SCANOUT_THROTTLE_US` (default 0 = off); if > 0,
   `usleep()` between presents so the queue drains at the display refresh naturally,
   independent of the settle.
3. Logs `replay_active` (`[0x72f7]`) per frame and `RDGPU_SCANOUT_SWAP_WAIT_TIMEOUT
   sym=...` at load.

Build (0 objc_msgSend, verified):

```
cd .../integration/rdmetal
clang -arch arm64e -O2 -bundle payload_scanout_server9.m \
    -o /tmp/rdgpu-scanout-server9-payload \
    -framework Foundation -framework IOSurface -framework CoreFoundation
```

## 5. Dock validation (uid 501, no root) — PASS (clean no-op)

```
== dock_inject == payload: /tmp/rdgpu-scanout-server9-payload
Dock pid: 55822  task_for_pid -> kr=0
dlopen result: 0x4080006c6fb210 (SUCCESS — handle returned; constructor ran)
```
```
RDGPU_SCANOUT_LOAD pid=55822 mode=server9 want_id=0x1e sync=1 settle=1 settle_ms=50 throttle_us=0
RDGPU_SCANOUT_QC base=0x18bff4000 swap_wait=0x2d5080018c2ec76c
RDGPU_SCANOUT_SWAP_WAIT_TIMEOUT sym=0xfe40800190c7dc64
RDGPU_SCANOUT_BASE skyBase=0x1886f1000
RDGPU_SCANOUT_SKYCHEIN ref=0x0 ... (all NULL)
RDGPU_SCANOUT_DONE result=no-display
```

## 6. Root command (unchanged --register flow)

```
cd /Users/dperry/Documents/Codex/2026-11-07/task/linux-shim-integration-next/repo/integration/rdmetal
sudo ./ws_inject_manual_d --register /tmp/rdgpu-scanout-server9-payload
sudo grep -E 'RDGPU_SCANOUT' /tmp/rdgpu-scanout.log | tail -80
```

Expect: `SWAP_WAIT_TIMEOUT sym=0x…190c7dc64` → per frame `IOMFB … replay_active=0
pg_swap=<n> fiq_tail_swap=<n>` + `PRESENT … ret=1` + `SETTLE swap_id=<n> … ret=0`
(blocking settle returns 0 once the swap is consumed), repeated indefinitely. To
exercise the throttle instead, set `RDGPU_SCANOUT_THROTTLE_US=16667` (60 Hz) on the
injector's environment.
