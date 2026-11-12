# SkyLight scanout present-loop drain — round 14 (the `replay_active` flag write)

Read-only disassembly (full QuartzCore __TEXT from `dyld_info -all_dyld_cache
-disassemble`, preferred-base addresses 0x18A5DC000; live = +0x1A18000) + a
corrected payload. macOS 26.5.1 / 25F80 arm64e. QuartzCore live base 0x18bff4000
(unslid __TEXT 0x18A5DC000, slide 0x1A18000 — re-verified via dladdr this boot).

## 1. What `replay_active` (the `[0x72f7]` byte) actually gates

The byte is read by **one** accessor and written by **one** function.

```c
// reader (the only direct access to 0x72f7 in the whole image):
CA::WindowServer::IOMFBDisplay::replay_active() const
    0x18A6B00D8  mov  w8, #0x72f7
    0x18A6B00DC  ldrb w0, [x0, x8]
    0x18A6B00E0  ret
// base class:
CA::WindowServer::Display::replay_active() const  ->  mov w0,#0; ret
```

Every other reader calls this via **vtable slot +0x8d0 / declkey 0xc43f**
(`siphash("_ZNK2CA12WindowServer7Display13replay_activeEv")`). The complete
call-site inventory across QuartzCore (grep `0xc43f`), mapped to their enclosing
symbols:

| site (live) | function | effect when `replay_active()==1` |
|---|---|---|
| 0x18C342178 | `IOMFBDisplay::can_update_` +0x74 | **the drain gate** — reads `[0x6714]`; if nonzero calls `swap_wait(fb, [0x6714], 0x80000001)` then clears `[0x6714]`/`[0xebb]`; if `[0x6990]` (capture frame, cbz-guarded) decrements it |
| 0x18C3426D4 | `IOMFBDisplay::can_update_` +0x5d0 | `sub w24, w23, replay_active` — frame-count minus 1 during replay (page accounting) |
| 0x18C342948 | `IOMFBDisplay::can_update_` +0x844 | stores replay result into the returned flag (timing path) |
| 0x18C342A54 | `IOMFBDisplay::can_update_` +0x950 | `tbnz w0,#0` skips a vsync re-timing recompute (`[0x72c8]`) |
| 0x18C349A70 | `IOMFBDisplay::finish_update_` +0x68 | **the `[0x6714] = page[0x18]` write gate** (with an extra `[0x6714]==0` guard) |
| 0x18A92E710 | `IOMFBDisplay::set_cursor_surface` +0x1824 | calls `SecureIndicator::set_cursor_update()` (privacy-indicator flag) |
| 0x18A8BFD18 | `Server::set_display_state` +0x920 | sets `[display+0x388] |= 0x10000|0x2000` and `Server::invalidate(shape)` (recomposite) |
| 0x18A936F9C | `IOMFBDisplay::activate_replay` +0xc8 | re-entry guard (skip re-setup) |
| 0x18A937268 | `IOMFBDisplay::activate_replay_` +0x1b0 | clear guard (skip the clear path) |

Writer (the **only** place 0x72f7 is stored — via `this+0x6714 + 0xbe3`):

```c
CA::WindowServer::IOMFBDisplay::activate_replay_()   // 0x18A9370A0
    x24 = this + 0x6714
    ...
    0x18A9371BC  strb wzr, [x24, #0xbe3]   // [0x72f7] = 0  (no-idle-buffer / fail path)
    ... (on success: IOMobileFramebufferSetIdleBufferEvent / SetIdleBuffer) ...
    0x18A9372E0  strb w8, [x24, #0xbe3]    // [0x72f7] = 1  (w8=1, success)
    0x18A9372E4  str  wzr, [x24]           // [0x6714] = 0
```

### Side-effect assessment

`[0x72f7]` is the "Replay" (display-capture streaming) feature flag. `activate_replay_`
is what actually ENGAGES capture — it calls `IOMobileFramebufferSetIdleBufferEvent`
/ `SetIdleBuffer` and installs a CASharedEvent idle-buffer event, and only then
sets the flag. **Writing the byte to 1 alone does NOT run any of that**: no idle
buffer is installed, no capture surface is created, nothing is streamed. It only
flips the present/update bookkeeping paths into their "replay" variant.

Those variant paths are, in our synthetic external-update flow:
- **Desired**: `finish_update_` records the swap id into `[0x6714]`, and
  `can_update_` `swap_wait`s on it and clears it — the native drain we want.
- **Benign**: page-count `-1` + two timing/vsync branches in `can_update_`; a
  secure-indicator cursor flag in `set_cursor_surface`; a display invalidation in
  `set_display_state`. None of these dereference capture-specific pointers
  (`[0x6990]` is `cbz`-guarded). No crash/hang path introduced.
- **Re-entrancy**: `activate_replay`/`activate_replay_` are guarded so they won't
  re-run while the flag is set; but a real screen-recording session starting
  mid-run would call `activate_replay_` and could clear/re-set the flag. We capture
  the original byte and restore it on exit regardless.

Conclusion: a bounded, restore-on-exit write of `[0x72f7]=1` is safe — it toggles
only the drain path plus benign replay bookkeeping, and does not engage capture.

## 2. `can_update_` and `finish_update_` branch shape (task 1, confirmed)

Symbol table (preferred / live / size):
- `IOMFBDisplay::can_update_` (inner)  0x18A92A0EC / 0x18C3420EC / 0xAE8
- `IOMFBDisplay::can_update` (wrapper) 0x18A93A534 / 0x18C352534 / 0x100
- `IOMFBDisplay::finish_update_` (inner) 0x18A9319F0 / 0x18C3499F0 / 0x190
- `IOMFBDisplay::finish_update` (outer)  0x18A937300 / 0x18C34F300 / 0x292C

NOTE on naming: the task's "finish_update_ (OFF 0x35b300)" is a slight collision —
**0x35b300 is the OUTER `finish_update`** (the one that walks pages and calls
SwapBegin/SwapEnd). The inner `finish_update_` that carries the `[0x6714]=page[0x18]`
write is at **0x3559f0**. The outer function tail-calls the inner one
(`bl __ZN...14finish_update_...` at 0x18A9392A4).

`can_update_` replay gate (first block, live):

```
0x18C342150 ldr x16,[x19]; autda(0x27e3); vtable[0x8d0]; blraa(0xc43f) ; replay_active()
0x18C342178 cbz  w0, 0x18C342200               ; ==0 -> skip drain
0x18C34217C ldr  w1, [x27, #0x2d8]             ; [this+0x6714]
0x18C342180 cbz  w1, 0x18C342200               ; ==0 -> skip
0x18C342190 bl   0x18C2EC76C                   ; swap_wait(fb, [0x6714], 0x80000001)
0x18C3421A8 cbnz w21, 0x18C342200              ; busy -> keep [0x6714]
0x18C3421CC str  wzr, [x27, #0x2d8]            ; [0x6714] = 0 (drained)
```

`finish_update_` replay gate (live; x22 = this+0x63bc, so [x22,#0x358]==[this+0x6714]):

```
0x18C349A48 ldr x16,[x19]; autda(0x27e3); vtable[0x8d0]; blraa(0xc43f) ; replay_active()
0x18C349A70 cbz  w0, 0x18C349A84               ; ==0 -> skip write
0x18C349A74 ldr  w8, [x22, #0x358]             ; [this+0x6714]
0x18C349A78 cbnz w8, 0x18C349A84               ; (round-13 omitted this) only-if-zero
0x18C349A7C ldr  w8, [x21, #0x18]              ; page[0x18]  (x21 = Page*)
0x18C349A80 str  w8, [x22, #0x358]             ; [this+0x6714] = page[0x18]
```

The drain is a poll-and-clear (can_update_'s `swap_wait` is the NON-blocking
wrapper, timeout 0). So the native path keeps `[0x6714]` set across frames until
`swap_wait` observes the swap consumed; it does not itself block. The blocking
`SwapWaitWithTimeout` settle (server9) remains the fallback.

## 3. server10 payload

`payload_scanout_server10.m` → `/tmp/rdgpu-scanout-server10-payload`. Changes from
server9:

1. Knob `RDGPU_SCANOUT_REPLAY` / `/tmp/rdgpu-scanout-replay` (default 0).
2. `rd_apply_replay()` — BEFORE the present loop (right after `iomfb_display` is
   resolved): reads `[iomfb_display+0x72f7]`, writes 1, re-reads, logs
   `RDGPU_SCANOUT_REPLAY_SET ... before=0x.. after=0x.. applied=1`, stores the
   original byte.
3. `rd_restore_replay()` — writes the original byte back; wired into
   `rd_restore_all()` (present-failure path, recv-failure/stop path, thread-fail
   path). Logs `RDGPU_SCANOUT_RESTORE_REPLAY`.
4. Settle + throttle knobs unchanged (server9).

Build (0 objc_msgSend, verified — only `objc_autoreleasePool{Push,Pop}`):

```
cd .../integration/rdmetal
clang -arch arm64e -O2 -bundle payload_scanout_server10.m \
    -o /tmp/rdgpu-scanout-server10-payload \
    -framework Foundation -framework IOSurface -framework CoreFoundation
```

## 4. Dock validation (uid 501, no root) — PASS (clean no-op)

```
== dock_inject == payload: /tmp/rdgpu-scanout-server10-payload
dlopen result: 0x2880006c6f8430 (SUCCESS — handle returned; constructor ran)
```
```
RDGPU_SCANOUT_LOAD pid=55822 mode=server10 ... sync=1 settle=0 settle_ms=50 throttle_us=20000 replay=0
RDGPU_SCANOUT_QC base=0x18bff4000 swap_wait=0x...18c2ec76c
RDGPU_SCANOUT_SWAP_WAIT_TIMEOUT sym=0x...190c7dc64
RDGPU_SCANOUT_BASE skyBase=0x1886f1000
RDGPU_SCANOUT_SKYCHEIN ... (all NULL)
RDGPU_SCANOUT_DONE result=no-display
```

No `RDGPU_SCANOUT_REPLAY_SET` line — correct: the Dock has no `iomfb_display`, so
`rd_apply_replay()` returns early (guarded). (`settle=0`/`throttle_us=20000` are
stale knob files in /tmp from a prior run; see §5.)

## 5. Root command + recommended knobs (for the parent)

```
cd /Users/dperry/Documents/Codex/2026-11-07/task/linux-shim-integration-next/repo/integration/rdmetal

# (a) PURE native-drain test — replay on, settle off, throttle off
sudo sh -c 'echo 1 > /tmp/rdgpu-scanout-replay; echo 0 > /tmp/rdgpu-scanout-settle; echo 0 > /tmp/rdgpu-scanout-throttle-us'
sudo ./ws_inject_manual_d --register /tmp/rdgpu-scanout-server10-payload
sudo grep -E 'RDGPU_SCANOUT' /tmp/rdgpu-scanout.log | tail -80

# (b) variation: native drain + blocking settle (if (a) still drops after ~2 frames)
sudo sh -c 'echo 1 > /tmp/rdgpu-scanout-replay; echo 1 > /tmp/rdgpu-scanout-settle; echo 0 > /tmp/rdgpu-scanout-throttle-us'

# (c) variation: native drain + vblank throttle (60 Hz)
sudo sh -c 'echo 1 > /tmp/rdgpu-scanout-replay; echo 0 > /tmp/rdgpu-scanout-settle; echo 16667 > /tmp/rdgpu-scanout-throttle-us'

# (d) control: replay off (server9 behaviour — blocking settle)
sudo sh -c 'echo 0 > /tmp/rdgpu-scanout-replay; echo 1 > /tmp/rdgpu-scanout-settle; echo 0 > /tmp/rdgpu-scanout-throttle-us'
```

Expect in (a): `RDGPU_SCANOUT_REPLAY_SET ... before=0x0 after=0x1 applied=1` then
per-frame `replay_active=1`, `finish_update_` starts populating `pend_swap`, and
`PRESENT ... ret=1` repeats without the 3rd-frame `ret=0`. If `ret=0` persists,
the native drain's non-blocking poll is insufficient and (b)/(c) are the fallback.
On any failure/stop the payload logs `RDGPU_SCANOUT_RESTORE_REPLAY ... -> 0x0`.
