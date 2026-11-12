# SkyLight present-to-display ("scanout") investigation — 2026-11-10

Read-only investigation + probe. No display was flipped. No sudo. `/Users/dperry/linux-shim` untouched.

## Verdict

**No — there is no SkyLight present-to-display primitive that the Dock's
`com.apple.private.SkyLight.displaycontrol` entitlement reaches.** Desktop-display
scanout remains Apple-gated behind the CoreDisplay mach service
`com.apple.CoreDisplay.master` (`com.apple.CoreDisplay.master` entitlement). The
one genuine SkyLight "present a client IOSurface to a display" family
(`SLSHMD*`) is XR/headset-only and unreachable on this Mac. The `displaycontrol`
entitlement gates only display *control* (brightness/contrast/white-point/EDR,
clamshell, idle/sleep, power state) and virtual-display creation — none of which
has a present/scanout/IOSurface method.

## 1. Symbol surface (SkyLight arm64e, dyld shared cache)

Full export dump via `dyld_info -exports` (2379 C symbols + Swift + ObjC classes).
No symbol matches present/scanout/framebuffer/display-surface for desktop displays.

Promising families, with purpose:

| Family | Symbols | Purpose | Presents IOSurface? |
|---|---|---|---|
| `SLSHMD*` (XR/headset) | `SLSHMDAcquire`, `SLSHMDConfigureDisplayQueue`, `SLSHMDGetDrawable`, `SLSHMDDrawableGetIOSurface`, `SLSHMDDrawablePresentWithTime`, `SLSHMDCopyMetalDevice`, `SLSCopyAvailableHMDList` | Present a drawable (IOSurface-backed) to a **head-mounted display** via WindowServer MIG | YES — but XR/headset only |
| Surface (window) | `SLSAddSurface`, `SLSBindSurface`, `SLSFlushSurface(WithOptions)`, `SLSGetSurfaceBinding`, `SLSSetSurface*`, `SLSTransaction*Surface*` | Bind a client surface to a **window** (CA layer / IOAccel), then flush — normal compositor | NO — window, not display |
| Display stream (capture) | `SLSDisplayStreamCreateCustom/Proxied`, `SLSDisplayStreamUpdateCreate` | Capture display frames (read), not present | NO |
| Display control | `SLSGetDisplayBrightness`, `SLSSetDisplayBrightness`, `SLSDisplayManagerRequestDisplaysIdle`, `SLSDisplayControlClient`, `SLSDisplayPowerControlClient`, `SLSBrightnessControlClient` | brightness/EDR/power/clamshell/idle | NO |
| Virtual display | `SLVirtualDisplay` (`initWithConfiguration:`, `applySettings:`, `destroy`, `displayID`) | create a virtual display target | NO (only creates a display ID) |
| Display wall | `SLSDisplayWall/Configuration/Group` | tile displays into a wall | NO |
| Metal device | `SLSDisplayCopyCurrentMetalDevice` / `SLDirectDisplayCopyCurrentMetalDevice` | map displayID → MTLDevice | NO (read-only helper) |

## 2. Disassembly findings (lldb on shared-cache images)

- `SLSHMDDrawablePresentWithTime(drawable, double time)` → MIG `"HMDPresent"` to the
  HMD session port; log tag `[ Display:XR ]`. `SLSHMDGetDrawable` → MIG
  `"HMDNextDrawable"`; `SLSHMDDrawableGetIOSurface` returns `[drawable + 0x10]`
  (the IOSurface). `SLSHMDAcquire` → `_CGSHMDAcquire`/`_CGSTBAcquire`, then
  `hmd_rebuild_drawable_queue`. All XR, all gated by WindowServer connection +
  HMD hardware.
- `SLSAddSurface(connID, windowID, &surfaceID)` → MIG `"AddSurface"` msgh_id
  0x304003 to the CGS/WindowServer port. `SLSBindSurface(connID, windowID,
  surfaceID, type, w, h)` ultimately builds a CA layer named
  `kCGSAcceleratedSurfaceType_metalLayer` / `kCGSWindowSurfaceType_host`,
  attaches it as a sublayer and `CATransaction commit`s — the window compositor,
  not a display scanout.
- `CoreDisplay_GetDisplayIDList(max, ids, &count)` → constructs
  `CoreDisplay::Mach::Port("com.apple.CoreDisplay.master", PortLookup)`; on port
  lookup failure it throws→catches and returns 0 without writing `count`. This
  is the master gate, confirmed at the instruction level.

## 3. Probe results (arm64e, read-only)

`probe.m` (dlsym + guarded calls; never flips a display):

```
SLSMainDisplayID()                       -> 1
SLSDisplayCopyCurrentMetalDevice(1)      -> 0x...  class=AGXG14CDevice   (works, no entitlement)
SLSCopyAvailableHMDList()                -> CFArray, count=0              (no XR headset)
CoreDisplay_GetDisplayIDList(16)         -> rc=0, count unchanged (0xdeadbeef)  (master gate)
```

- `SLSDisplayCopyCurrentMetalDevice` works unentitled because it goes through
  WindowServer (`SLSAcceleratorForDisplayNumber`), not CoreDisplay master — but it
  only *names* the device; it does not present.
- `SLSCopyAvailableHMDList` returns empty → the only SkyLight present path (HMD)
  has no hardware target on this machine.

## 4. Entitlement reach — hard blockers

1. **Dock does not carry `com.apple.private.windowserver.access`** (verified via
   `codesign -d --entitlements`). So even the window-surface path is out of reach
   for arbitrary surface creation, and it is a window compositor path anyway.
2. **`com.apple.private.SkyLight.displaycontrol` cannot be attached to a
   third-party binary.** A minimal `hello` ad-hoc signed with that entitlement is
   SIGKILLed by AMFI at exec (exit 137, no `main` output); the same binary
   unsigned runs fine. `SecTaskCopyValueForEntitlement` reports the entitlement
   absent in a normal process. The entitlement only exists on Apple platform
   binaries (like Dock), so the only way to exercise it is inside the Dock.
3. Inside the Dock (already established by the parent), `CoreDisplay_GetDisplayIDList`
   yields count=0 — same as my standalone probe — because scanout is gated by the
   *separate* `com.apple.CoreDisplay.master` mach service, which the Dock does not
   hold and `displaycontrol` does not substitute for.

## Concrete symbols + signatures (most useful)

```
uint32_t   SLSMainDisplayID(void);
void*      SLSDisplayCopyCurrentMetalDevice(uint32_t displayID);      // -> MTLDevice
CFArrayRef SLSCopyAvailableHMDList(void);                             // empty on this Mac
bool       SLSHMDAcquire(CFTypeRef hmd, CFDictionaryRef queueConfig);
CFTypeRef  SLSHMDGetDrawable(CFTypeRef hmd, ...);                     // MIG "HMDNextDrawable"
IOSurfaceRef SLSHMDDrawableGetIOSurface(CFTypeRef drawable);          // [drawable+0x10]
int        SLSHMDDrawablePresentWithTime(CFTypeRef drawable, double); // MIG "HMDPresent"
CGError    SLSAddSurface(connID, windowID, CGSSurfaceID *outID);
CGError    SLSBindSurface(connID, windowID, surfaceID, int type, int w, int h); // CA layer
int        CoreDisplay_GetDisplayIDList(uint32_t max, uint64_t *ids, uint32_t *count);
void*      CoreDisplay_Display_GetCurrentSurface(uint32_t displayID);
void*      CoreDisplay_Display_PresentIOSurface(IOSurfaceRef, int PresentSyncType);
IOSurfaceRef CoreDisplay_DisplaySurface_GetIOSurface(void *surface);
```

Probe/disassembly artifacts: `/tmp/skyprobe/` (probe.m, dis_full.txt, dis2.txt).
