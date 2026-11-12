# SkyLight SERVER-side scanout FLIP — round 6 (flip3): the REAL full present

Read-only research + corrected payload. macOS 26.5.1 / 25F80, arm64e.
SkyLight dli_fbase = 0x1886f1000 this boot; offsets relative to it.

## 1. PresentationDisplay::Present() is NOT the scanout present

`PresentationDisplay::Present()` @ +0x000B0148, size 0x1160. Mangled
`_ZN19PresentationDisplay7PresentEv` ⇒ **`void Present()`** — implicit `this` only,
NO arguments, returns void. It asserts `pthread_main_np()`.

Its body is the **selective-sharing / presentation-mode capture** present, not a
scanout: it walks CGXWindows, builds a window-id list, calls
`WS::Capture::WSCreateIOSurfaceForWindowList(WindowCaptureConfiguration&)`
(a capture IOSurface), then `WSDisplayStreamDisplayDidUpdate`. It takes no
IOSurface/DisplaySurface and never reaches IOAccel. (It is not a candidate for the
desktop scanout present.)

`display_present_swap(int,unsigned,CGXSessionWindowFrameData*,unsigned)` @ +0x404418
is likewise confirmed to be a block trampoline that records frame data
(`clear_old_frame_data`, `WSCAPresent` vectors) — not the scanout either.

## 2. The real per-display present and its two paths

`WS::Displays::SLCADisplay::present_iosurface(__IOSurface*, bool)` @ +0x00411F1C
(virtual, vtable slot 0x5e0). x0=this, x1=IOSurface*, x2=bool sync, returns int.

It branches on `flags[+0x76c]` bit 2 (0x4):

* **bit 2 CLEAR (desktop default: builtin 0x800030e1, external 0x80000020) —
  SIMPLE path.** `[ca enabled]`; `[ca uniqueId]`; `vtable[0x6f8](this)` which is
  `SLCADisplay::create_edr_request_state()` (+0x40e408) — a prepare, not a
  present; `[ca presentSurface:io withOptions:nil]`; `set_swapped_iosurface(io)`;
  return 1. This is the "lightweight CA handoff" the round-5 flip observed. It
  only takes effect when the surface already IS the display's replaceable
  scanout surface; a plain `IOSurfaceCreate` surface is silently dropped (the
  `swapped_surface` bookkeeping still changes, so result=1 but nothing flips).

* **bit 2 SET — EXTERNAL-UPDATE path (the REAL full present).**
  `[ca canUpdateWithFlags:0]`; `vtable[0x6f8](this)`; transform math;
  `CARenderUpdateAllocateSeed` / `CARenderUpdateBegin2` / `CARenderUpdateSetRegion`
  / `CARenderUpdateAddFlags(0x200)`; `[ca beginExternalUpdate:usingSoftwareRenderer:0]`;
  `[ca currentSurfaceWithOptions:needsClear:readOnly:vsyncOff:sharedEventRef:signalValue:]`
  (returns the TRUE scanout IOSurface); `collect_surfaces`; surface-pool lookup +
  `allocate_shared<CASurface>`; `CASurface::metal_texture(id<MTLDevice>)`;
  `CompositorMetal::CopyTextureToTextureWithRegion(src=magenta → dst=scanout)`;
  if sync: `MetalContext::Flush(true,0,0,0)`;
  `finish_external_update(update,0,0x200000,0)` + `CARenderUpdateFinish` (commit →
  IOMFB/IOAccel scanout); store CASurface @ +0x2c8/+0x2d0.

So the missing step is **(a) a CA commit/transaction** — the CA render update
(`CARenderUpdateBegin2` → … → `CARenderUpdateFinish`) + Metal copy + flush that
the SIMPLE path omits. (Not `IOSurfaceFlush`, not `PresentationDisplay::Present`,
not `display_present_swap`.)

### Where the CA handoff lands (QuartzCore)

`[ca presentSurface:io withOptions:nil]` (ca = `[self+0x1d8]` = `CAWindowServerDisplay`)
→ `-[CAWindowServerDisplay presentSurface:withOptions:]` (QuartzCore): locks
`[self+0x8]` and calls `[[self+8]+0x40]->vtable[0x50](io)` — the
`CA::WindowServer::Display` present into IOMFB/IOAccel. `options` is ignored.

## 3. Corrected payload

`payload_flip3.m` → `/tmp/rdgpu-scanout-flip3-payload`. Same chain/enumeration and
magenta-surface build as flip2, plus ONE functional change: **set
`flags[+0x76c] |= 0x4` before the present, call `present_iosurface(io, true)`,
restore flags after.** This forces the EXTERNAL-UPDATE (full) path so the magenta
surface is Metal-copied into the real scanout surface and committed to IOAccel.
`RD_TRY` now also traps SIGABRT (so a path assert logs instead of crashing
WindowServer).

Build:
```
cd /Users/dperry/Documents/Codex/2026-11-07/task/linux-shim-integration-next/repo/integration/rdmetal
clang -arch arm64e -bundle payload_flip3.m -o /tmp/rdgpu-scanout-flip3-payload \
    -framework Foundation -framework IOSurface -framework CoreFoundation
```

## 4. Dock validation (uid 501, no root) — PASS (clean no-op)

```
== dock_inject == payload: /tmp/rdgpu-scanout-flip3-payload
Dock pid: 81550
task_for_pid -> kr=0
dlopen result: 0x4a80006c6f8430 (SUCCESS — handle returned; constructor ran)
```
```
RDGPU_FLIP_LOAD pid=81550 mode=flip want_id=0x1e want_main=0
RDGPU_FLIP_DLOPEN SkyLight=0x6700035d4637d0
RDGPU_FLIP_BASE skyBase=0x1886f1000
RDGPU_FLIP_SKYCHEIN ref=0x0 p1=0x0 p2=0x0 sess=0x0 dset=0x0 begin=0x0 end=0x0
RDGPU_FLIP_DONE result=no-display
```
`__sessionControlRef` is NULL in the Dock → all-NULL chain → present never
reached; Dock (pid 81550) alive.

## 5. Root command for the parent (WindowServer run — the actual flip)

```
cd /Users/dperry/Documents/Codex/2026-11-07/task/linux-shim-integration-next/repo/integration/rdmetal
sudo ./ws_inject_manual_d /tmp/rdgpu-scanout-flip3-payload
sudo grep -E 'RDGPU_FLIP|\[flip\]' /tmp/rdgpu-scanout.log | tail -40
```
Expected: `flags=0x80000020 -> set bit2 -> 0x80000024`, `CALL present_iosurface … (external-update path)`,
`RESULT … result=1`, `flags_restored 0x… -> 0x80000020`, and a visible magenta
scanout on the external display (id 0x1e). Single bounded call; do not loop.
