# Shim-side scanout handoff diff: Alpine (working) vs Arch (black, 1280x720)

Read-only investigation of the shim. The currently-live WindowServer payload
(server17) is the WORKING one and is independent of the guest — the regression is in
the shim's per-frame scanout handoff. No server change is needed.

## Verdict

The Arch (rdmetal/stock-Hyprland) present path hands off the **wrong surface kind**:
its CPU staging texture has `src.iosurface == nil`, so `present_source()` silently
falls back to `drawable.texture.iosurface` — the CAMetalLayer's display-optimized
allocation, whose bytes read back BLACK (and at the guest preview size 1280x720).
The Alpine path hands off a plain **'BGRA' IOSurface containing the composed frame**.

Role/display mapping is NOT the problem (both use `RDGPU_SCANOUT_ROLE_PRIMARY` → slot
0 → display 0x1e). Size is a secondary, separate issue (guest output config).

## 1. The shared scanout tail (window.m)

`shim-metal-clear/src/window.m` `present_source()` line 1824:

```objc
IOSurfaceRef scanSurface = src.iosurface ? src.iosurface : drawable.texture.iosurface;
```

The comment above it (lines 1810-1821) already states the correct contract: the
surface the server expects is `src.iosurface` (the composed BGRA IOSurface); the
`drawable.texture.iosurface` fallback is "display-optimized … reads back black".

## 2. Alpine path — `src.iosurface` is the composed BGRA frame (WORKING)

`metal-wayland-next/angle_iosurface_host_metal_scene.m`:

- `rd_surface_create(width,height)` (line 17) creates a **plain 'BGRA' IOSurface**
  (kIOSurfacePixelFormat = `'BGRA'`, bytesPerElement 4).
- `rd_surface_present(ptr,w,h)` (line 635) wraps it
  `[dev newTextureWithDescriptor:td(BGRA8Unorm,Shared) iosurface:surface plane:0]`
  and calls `gpuwin_present_texture(texture,…)`.
- `gpuwin_present_texture` (window.m:2010) → `present_source(tex,…)`, where
  `tex.iosurface` == that BGRA IOSurface.

Result: `scanSurface = src.iosurface` = composed frame, full display size, non-black.

## 3. Arch path — `src.iosurface` is nil → black drawable fallback (REGRESSION)

`shim-metal-clear/src/wlsrv.c` `recomposite()` (line 1120) assembles the frame on the
CPU, then (line 1366) calls `x11rnd_present_bgra(fb, W, H)`.

`/Users/dperry/linux-shim/src/x11srv_render.m` line 26:

```objc
void x11rnd_present_bgra(const uint8_t* bgra, uint32_t w, uint32_t h) {
  (void)gpuwin_present_fmt(bgra, (uint64_t)w, (uint64_t)h, /*bgra=*/1);
}
```

`window.m` `gpuwin_present_fmt()` (line 1942) → `ensure_stage()` (line 1919):

```objc
td.usage = MTLTextureUsageShaderRead; td.storageMode = MTLStorageModeShared;
gStage[i] = [dev newTextureWithDescriptor:td];      // <-- NO IOSurface
```

then uploads with `[stage replaceRegion:… withBytes:rgba bytesPerRow:w*4]` and calls
`present_source(stage,…)` (line 1991). `stage` was created with
`newTextureWithDescriptor:` (NOT `…iosurface:plane:`), so `stage.iosurface == nil`.

In `present_source` that means `scanSurface = drawable.texture.iosurface` → the
display-optimized CAMetalLayer drawable → black on readback, 1280x720 (the guest
output is `monitor WAYLAND-1 1280x720@60 scale 2.00`, ARCH_MIGRATION.md Step 11).

## 4. Role/display mapping — identical (NOT the issue)

Both shims call `rdgpu_scanout_present(scanSurface, RDGPU_SCANOUT_ROLE_PRIMARY)`
(window.m:1846). `RDGPU_SCANOUT_ROLE_PRIMARY` = 0 → server slot 0 → display 0x1e
(rdgpu_protocol.h / payload_scanout_server17.m). Same on Alpine and Arch.

## 5. The fix (shim-side only, no server recode)

Make the CPU staging texture IOSurface-backed, exactly like the Alpine
`rd_surface_present` wrapper. Then `stage.iosurface` IS the composed BGRA frame and
`present_source`'s existing line hands off the right surface.

In `window.m`, add a BGRA-IOSurface helper (mirrors `rd_surface_create`):

```objc
static IOSurfaceRef rd_stage_iosurface(uint32_t w, uint32_t h) {
  if (!w || !h) return NULL;
  const int64_t numvals[4] = { (int64_t)w, (int64_t)h, (int64_t)'BGRA', (int64_t)4 };
  const void* keys[4] = { kIOSurfaceWidth, kIOSurfaceHeight,
                          kIOSurfacePixelFormat, kIOSurfaceBytesPerElement };
  CFNumberRef nums[4]; const void* vals[4];
  for (int i = 0; i < 4; i++) {
    nums[i] = CFNumberCreate(NULL, kCFNumberSInt64Type, &numvals[i]); vals[i] = nums[i];
  }
  CFDictionaryRef props = CFDictionaryCreate(NULL, keys, vals, 4,
      &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
  IOSurfaceRef io = IOSurfaceCreate(props);
  for (int i = 0; i < 4; i++) if (nums[i]) CFRelease(nums[i]);
  if (props) CFRelease(props);
  return io;
}
```

Add `static IOSurfaceRef gStageIO[GPUWIN_STAGE_SLOTS];` beside `gStage`, and change
`ensure_stage`'s allocation loop:

```objc
for (int i = 0; i < GPUWIN_STAGE_SLOTS; i++) {
  // Frames still in flight keep the old textures alive through their command buffers.
  IOSurfaceRef io = (fmt == MTLPixelFormatBGRA8Unorm)
                        ? rd_stage_iosurface((uint32_t)w, (uint32_t)h) : NULL;
  id<MTLTexture> tex = io ? [dev newTextureWithDescriptor:td iosurface:io plane:0]
                          : [dev newTextureWithDescriptor:td];
  if (!tex) { if (io) CFRelease(io); gStageW = gStageH = 0; return -12; }
  if (gStageIO[i]) CFRelease(gStageIO[i]);
  gStageIO[i] = io;                 // held for the texture's lifetime
  gStage[i] = tex;
}
```

The `replaceRegion` upload and the `present_source` blit are unchanged; only the
backing changes. (`replaceRegion`'s `bytesPerRow` is the SOURCE stride `w*4`, so it
is correct regardless of the IOSurface's internal stride.)

Rebuild `shim_gui`, then verify with the selfcheck that already exists:

```
RDGPU_SCANOUT=1 RDGPU_SCANOUT_SELFCHECK=1 ./shim-metal-clear/shim_gui rootfs-arch \
  /usr/bin/Hyprland --config "$PWD/hypr-arch-min.lua" --i-am-really-stupid
```

Expected: `[rdgpu-scanout-selfcheck] … verdict=NONBLACK` (was `ALL_BLACK`), and the
WindowServer log's handoff frame size/content flips non-black.

## 6. Secondary issue — surface size

Even after the surface-kind fix, Arch hands off 1280x720 (its `WAYLAND-1 1280x720@60
scale 2.00` output) while Alpine handed off the full display size. That is a guest
output-mode/config difference, separate from the black-frame bug. If the flip lands
small/letterboxed, set the Arch Hyprland output to the display's native size (or the
same value Alpine used) rather than 1280x720.
