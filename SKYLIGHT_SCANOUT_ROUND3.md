# SkyLight SERVER-side present/scanout — reverse-engineering findings (round 3)

Read-only research (lldb on dyld-shared-cache images, no display flipped). Follows
`SKYLIGHT_SCANOUT_INVESTIGATION.md`. macOS 26.5.1 / 25F80, arm64e.
SkyLight dli_fbase (dladdr) = 0x1886f1000 this boot; all offsets below are
relative to it and are slide-independent. Boot slide = 0x1A27000
(file/preferred base = 0x186cd9000, NOT the 0x186cda000 in the earlier doc).

## The server present primitive

The desktop scanout present is NOT `CoreDisplay_Display_PresentIOSurface` (that is
client-side and dead in the server) and NOT the base `present_ioaccel_surface`.
The real one is:

```
WS::Displays::SLCADisplay::present_iosurface(__IOSurface*, bool)
    SkyLight + 0x00411F1C   (load 0x188B02F1C)
```

Call sequence recovered from disassembly:

1. flag check `[SLCADisplay + 0x76c]`; on bit 1 try-lock `std::mutex` at `[+0x9b0]`.
2. `[SLCADisplay + 0x1d8]` is the CA display object (verified via
   `objc_msgSend$enabled` / `objc_msgSend$uniqueId`).
3. `objc_msgSend$presentSurface:withOptions:` on that CA display with the
   IOSurface (x21) — this is the actual flip into CoreAnimation.
4. `get_hmd_swap_lock()` + `recursive_mutex::lock()`.
5. Release old front surface `[+0x2c8]/[+0x2d0]`, clear the 3-entry aux array
   `[+0x2d8 .. 0x308]`, zero `[+0x308]`.
6. `WS::Displays::SLCADisplay::set_swapped_iosurface(__IOSurface*)`
   (+0x00412824): `IOSurfaceGetID` → surface-pool lookup/insert
   (`surfacepool_surface_by_id` +0x413978 / `surfacepool_insert`) → store
   `CASurface*` at `[+0x2c8]`, control block at `[+0x2d0]`.
7. return 1.

## Surface type & storage

- Present takes an **IOSurface** (`__IOSurface*`), not a raw IOAccel surface.
- The current front/scanout surface is a `std::shared_ptr<WS::Displays::CASurface>`
  stored at:
    `[SLCADisplay + 0x2c8]` == CASurface*   (IOSurface-backed CA surface)
    `[SLCADisplay + 0x2d0]` == shared_ptr control block
  Read-only accessor: `WS::Displays::SLCADisplay::swapped_surface()`
  (+0x00419190) — copies {+0x2c8,+0x2d0} and retains the control block.
- `WS::Displays::CASurface` is constructed by
  `allocate_shared<CASurface>(alloc, SLCADisplay*, __IOSurface*&)` — i.e. it wraps
  {SLCADisplay*, IOSurface*} (best-effort: [CASurface+0x00]=display, [+0x08]=IOSurface).

## Key SLCADisplay field offsets (hardware display object)

| field | offset | evidence |
|---|---|---|
| display id (u32) | +0xd8 | PKGDisplay ctor reads [hw+0xd8] |
| CA display object | +0x1d8 | present_iosurface objc target |
| swapped surface (CASurface*) | +0x2c8 | set_swapped_iosurface `str` |
| swapped ctrl block | +0x2d0 | set_swapped_iosurface `str` |
| stream surface | +0x320/+0x328 | display_stream_surface() |
| scanout pixels wide (u32) | +0x634 | mode_scanout_pixels_wide() |
| scanout pixels high (u32) | +0x638 | mode_scanout_pixels_high() |
| present flags | +0x76c | present_iosurface |
| present mutex | +0x9b0 | present_iosurface |

## Hidden functions (all need PAC-sign-call by offset; none are dlsym-able)

symtab flags 0x000e0000 = hidden (0x000f0000 = exported). Only `SLSMainDisplayID`
etc. are exported. Signatures + offsets (from dli_fbase):

```
void   PresentationDisplay::Present()                              +0x000B0148   (huge compositor present; calls pthread_main_np, CGXWindow ops)
void   WS::Displays::SLCADisplay::present_iosurface(__IOSurface*,bool) +0x00411F1C
void   WS::Displays::SLCADisplay::set_swapped_iosurface(__IOSurface*)  +0x00412824
<shared_ptr<CASurface>> WS::Displays::SLCADisplay::swapped_surface()   +0x00419190  (sret in x8)
void   WS::Displays::SLCADisplay::collect_surfaces(bool,unsigned,unsigned long long) +0x0040A7C8
int    WS::Displays::Display::present_ioaccel_surface(IOAccelConnectStruct*,unsigned,IOAccelSurfaceInformation*,unsigned,bool) +0x001D5764  (8-byte base stub: `mov w0,#1; ret`)
void*  WS::Displays::CAManager()                                  +0x0041BDB0  (CAWSManager singleton; DOCK-UNSAFE: constructs 1568-byte CA manager)
void*  managed_display_for_pkg_display(PKGDisplay const*)         +0x0013CCBC  (PKGDisplay -> hardware display bridge)
```

NOTE on the parent's "display_present_swap(int,int,CGXSessionWindowFrameData*) @ +0x00404418":
that address is actually `invocation function for block in display_present_swap(int,
unsigned int, CGXSessionWindowFrameData*, unsigned int)` — a block trampoline that
appends a 0x30-byte record into a hash/vector, NOT the scanout. The real present
is `SLCADisplay::present_iosurface` above.

## PKGDisplay vs SLCADisplay (why the enum alone is not enough)

`PKGDisplay` (PKGDisplay.mm, Spaces layer) is a separate object that only COPIES
metadata out of the hardware display. Its ctor
`PKGDisplay::PKGDisplay(WSDisplayWrapper const&)` reads `[wrapper+0x00]` == the
`WS::Displays::Display*`, then copies bounds (+0x08), display id (+0x28),
CFUUIDBytes (+0x2c/+0x34), sarlacc rect, and computes is_main (+0xa8) by comparing
`display_id()` (vtable[0x28]) against the CA Manager's main display. It does NOT
retain a live hardware-display pointer.

Bridge: `managed_display_for_pkg_display(PKGDisplay const*)` (+0x0013CCBC) does
`pkg->vtable[0x18]()` then returns `[result + 0xf0]`. The round-3 payload reads the
result's SLCADisplay fields AND also `[result + 0xf0]` (belt-and-suspenders) so the
correct indirection resolves either way.

## Round-3 payload

`payload_readonly3.m` → built `/tmp/rdgpu-scanout-readonly3-payload`
(`clang -arch arm64e -bundle payload_readonly3.m -o ... -framework Foundation -framework IOSurface`).

It (a) re-walks the round-2 PKGDisplay chain, (b) for each PKGDisplay PAC-calls
`managed_display_for_pkg_display` and reads the SLCADisplay surface fields (+0xd8,
+0x1d8, +0x2c8, +0x2d0, +0x634, +0x638) plus `[hw+0xf0]` fallback — READ ONLY, no
flip. It does NOT call CAManager() (that kills the Dock — see below).

### Dock validation (uid 501, no root) — PASS

```
RDGPU_SCANOUT_LOAD pid=54061 mode=readonly3
RDGPU_SCANOUT_BASE skyBase=0x1886f1000
RDGPU_SCANOUT_SKYCHEIN ref=0x0 p1=0x0 p2=0x0 sess=0x0 dset=0x0 begin=0x0 end=0x0
RDGPU_SCANOUT_READONLY3_DONE
```

All-NULL / no-op in the Dock, clean completion, Dock alive. Expected: the Dock is
not the WindowServer session, so `current_session_display_data()` is NULL and
PATH 2 is skipped.

Note: an earlier build also called `WS::Displays::CAManager()` and that **killed the
Dock** (lazy `CAWSManager::CAWSManager()` construction is WindowServer-only) —
removed; do not call CAManager() from the Dock.

## Root command for the parent (WindowServer run)

```
cd /Users/dperry/Documents/Codex/2026-11-07/task/linux-shim-integration-next/repo/integration/rdmetal
sudo ./ws_inject_manual_d /tmp/rdgpu-scanout-readonly3-payload
sudo grep -E 'RDGPU_SCANOUT|scanout' /tmp/rdgpu-scanout.log | tail -50
```

Expected in WindowServer: 2 PKGDisplays, each with `hwdisplay=...` and
`swapped_surface=...` / `scanout=WxH` populated from the real SLCADisplay.
