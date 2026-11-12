# SkyLight SERVER-side single bounded scanout FLIP — payload_flip.m

The actual present. One display, one IOSurface, one `present_iosurface` call, then
stop. Follows `SKYLIGHT_SCANOUT_ROUND4.md` (enumeration + SLCADisplay mapping are
unchanged). macOS 26.5.1 / 25F80, arm64e. SkyLight dli_fbase = 0x1886f1000 this
boot; all offsets relative to it.

## Deliverable

- Source: `payload_flip.m`
- Binary: `/tmp/rdgpu-scanout-flip-payload`
- Build:
  ```
  clang -arch arm64e -bundle payload_flip.m -o /tmp/rdgpu-scanout-flip-payload \
      -framework Foundation -framework IOSurface
  ```

## The exact present call

```
int WS::Displays::SLCADisplay::present_iosurface(__IOSurface* io, bool sync)
    SkyLight + 0x00411F1C   (hidden 0x000e0000; symtab: _ZN2WS8Displays11SLCADisplay17present_iosurfaceEP11__IOSurfaceb)
```

AAPCS64 arg order: **x0 = self (SLCADisplay\*)**, **x1 = io (__IOSurface\* /
IOSurfaceRef)**, **x2 = sync (bool)**. Returns int in x0: **1 = success, 0 =
failure**.

PAC-sign-call by offset, diversity 0 (same pattern as the readonly payloads):

```c
typedef int (*fn_present_iosurface)(void*, IOSurfaceRef, bool);
fn_present_iosurface present = (fn_present_iosurface)rd_sign_fn(skyBase + 0x00411F1C);
int result = present((void*)hw_display, io, /*sync*/ true);
```

## What the bool means (from the disassembly of +0x00411F1C)

`sync` is the **synchronous / vsync-on** flag. Two uses, both on the *external-update*
path only:

1. `+0x824  eor w5, w22, #0x1` — `vsyncOff = !sync`, passed as the `vsyncOff:`
   argument to `objc_msgSend$currentSurfaceWithOptions:needsClear:readOnly:vsyncOff:sharedEventRef:signalValue:`.
   `sync==true` ⇒ vsync ON; `sync==false` ⇒ vsync OFF.
2. `+0x1472 cbz w22, ...` — `sync==true` additionally issues
   `MetalContext::Flush(true, 0, 0, 0)` (synchronous flush); `sync==false` skips it.

So `true` = "synchronous / wait for vsync", `false` = "async / no vsync wait".

### Note: for the desktop displays the bool is ignored

`present_iosurface` branches on `[SLCADisplay+0x76c]` bit 2:

- bit 2 **clear** ⇒ SIMPLE path — `objc_msgSend presentSurface:withOptions:(io,nil)`
  + `set_swapped_iosurface(io)`. The bool is never read.
- bit 2 **set** ⇒ EXTERNAL-UPDATE path — full CA render-update / Metal copy; this is
  where the bool matters (and where the size assert `surface_bounds.size ==
  IOSurfaceGetWidth/Height(io)` lives).

Round-4 flags: builtin `0x800030e1`, external `0x80000020` — bit 2 (0x4) is clear in
both, so both take the SIMPLE path. We still pass `true` (the canonical value).

## Preconditions / flags (from the same disassembly)

- `[+0x76c]` bit 1 (0x2): if set, `present_iosurface` try-locks `std::mutex` at
  `[+0x9b0]` and returns 0 if the lock is held. **Clear for both displays** (no mutex).
- `[+0x76c]` bit 2 (0x4): path selector above. Clear for both displays.
- SIMPLE path requires the CA display `[+0x1d8]` to be non-NULL and
  `[ca enabled]`/`[ca uniqueId]` to be non-zero; otherwise returns 0.
- No `pthread_main_np` anywhere in `present_iosurface`. The only synchronisation is
  the global `hmd_swap_lock` recursive_mutex (via `get_hmd_swap_lock()`) plus the
  optional per-display mutex above. There is **no main-thread requirement at the
  present_iosurface level**; the injector runs the payload constructor on a fresh
  pthread (`pthread_create_from_mach_thread`), which is fine. (The `objc_msgSend
  presentSurface:withOptions:` implementation inside the CA backend is the only part
  not audited here.)

## SIMPLE-path call sequence (what actually runs for id 0x1e / 0x27)

```
1. flags[+0x76c] bit1 check          (skipped — bit clear)
2. ca = [self+0x1d8]; [ca enabled]; [ca uniqueId]
3. vtable[0x6f8]()                   (internal prepare)
4. objc_msgSend presentSurface:withOptions:(io, nil) on `ca`   <-- the real flip
5. get_hmd_swap_lock() + recursive_mutex::lock()
6. release old front surface [+0x2c8]/[+0x2d0]; clear aux [+0x2d8..0x308]
7. set_swapped_iosurface(io)         -> IOSurfaceGetID -> surfacepool -> store
                                        CASurface* @ +0x2c8, ctrl @ +0x2d0
8. unlock; return 1
```

## Payload behaviour

Enumerates the PKGDisplay chain, maps the chosen display to its `SLCADisplay*`
via `get_displayref_for_pkgdisplay_by_uuid(void*, PKGDisplay const*)`
(`+0x002B9194`), reads id/cadisplay/scanout WxH, builds a magenta
(`0xFFFF00FF` BGRA8888) IOSurface sized to the **scanout** WxH, and PAC-sign-calls
`present_iosurface(hw, io, true)` once. Logs before/after + new `swapped_surface`.
No loop, no second present. The IOSurface is intentionally not released (the display
now references it as its front surface).

Display selection (default = external 0x1e):
- `RDGPU_FLIP_DISPLAY=<hex>` env (WindowServer env is fixed, so normally unused), or
- `/tmp/rdgpu-flip-display` — a plain hex-id file the parent can write as root
  (`echo 0x27 > /tmp/rdgpu-flip-display`), or
- `RDGPU_FLIP_MAIN=1` env to flip whichever display has is_main set.

## Dock validation (uid 501, no root) — PASS (no-op)

```
RDGPU_FLIP_LOAD pid=54061 mode=flip want_id=0x1e want_main=0
RDGPU_FLIP_DLOPEN SkyLight=0x7e80035d4637d0
RDGPU_FLIP_BASE skyBase=0x1886f1000
RDGPU_FLIP_SKYCHEIN ref=0x0 p1=0x0 p2=0x0 sess=0x0 dset=0x0 begin=0x0 end=0x0
RDGPU_FLIP_DONE result=no-display
```

`__sessionControlRef` is NULL in the Dock, so the chain is all-NULL and the present
is never reached. Dock (pid 54061) stayed alive; constructor returned cleanly.

## Root command for the parent (WindowServer run — the actual flip)

```
cd /Users/dperry/Documents/Codex/2026-11-07/task/linux-shim-integration-next/repo/integration/rdmetal
sudo ./ws_inject_manual_d /tmp/rdgpu-scanout-flip-payload
sudo grep -E 'RDGPU_FLIP|\[flip\]' /tmp/rdgpu-scanout.log | tail -40
```

Optional: to flip the builtin instead, `sudo sh -c 'echo 0x27 > /tmp/rdgpu-flip-display'`
before the injection. Expected in WindowServer: `scan ... chosen=1` for id 0x1e,
`CALL present_iosurface(hw=... io=... sync=true)`, `RESULT ... result=1`, and a
`swap_after` that differs from the previous `swap_before` (new magenta front surface).

⚠️ This is the real scanout: it momentarily replaces the display's front surface.
Single bounded call only — the payload flips once and stops; do not loop it.
