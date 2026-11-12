# SkyLight SERVER-side scanout FLIP — round 5 (flip2): root-caused + corrected

The flip crash is **NOT in `present_iosurface`**. It is in the payload's own
surface creation (`rd_make_surface`), specifically the Objective-C `@(...)` boxed
literals. `present_iosurface`'s simple path was already correct. macOS 26.5.1 /
25F80, arm64e. SkyLight dli_fbase = 0x1886f1000 this boot.

## 1. The exact wrong objc_msgSend

WindowServer crash (WindowServer-2026-11-11-070023.ips, faulting thread 30 = the
injected payload pthread):

```
exceptionReason: "+[%s %s]: unrecognized selector sent to class %p"
arguments:      ["NSNumber", "(dynamic selector)", "0x1ee0b9ed0"]
composed:       +[NSNumber (dynamic selector)]: unrecognized selector sent to class 0x1ee0b9ed0
```

- **Receiver (x0)** = `[NSNumber class]` = `0x1ee0b9ed0`. `@(w)` lowers to the
  *class* method `[NSNumber numberWithUnsignedInt:w]`, so the receiver is the
  NSNumber CLASS, not an instance.
- **Selector (x1)** = `numberWithUnsignedInt:` (also `numberWithUnsignedLong:` and
  `dictionaryWithObjects:forKeys:count:` for the other boxed args / `@{}`). It is a
  **non-canonical** selector: the payload is injected by `ws_inject_manual`, which
  applies chained fixups by hand and **never runs dyld's ObjC image registration /
  selector uniquing**. So the `__objc_selrefs` point at the bundle's *local*
  `__objc_methname` string copy instead of the runtime's uniqued SEL; `objc_msgSend`'s
  pointer-keyed method lookup misses and it throws.

Confirmed by direct reproduction (normal process, raw non-uniqued string):

```
NSForwarding: warning: selector (0x1005c0020) for message 'numberWithUnsignedInt:'
  does not match selector known to Objective C runtime (0x1fcb6dc76)-- abort
EXCEPTION: NSInvalidArgumentException : +[NSNumber numberWithUnsignedInt:]:
  unrecognized selector sent to class 0x1ee0b9ed0
```

The 5 ObjC sends live in `rd_make_surface` (verified with `objdump` on the built
payload): `_objc_msgSend$numberWithUnsignedInt:` (w/h/pixelFormat),
`_objc_msgSend$numberWithUnsignedLong:` (bytesPerRow/allocSize), and
`_objc_msgSend$dictionaryWithObjects:forKeys:count:`. The first executed —
`+[NSNumber numberWithUnsignedInt:3440]` (external width) — is the one that aborts.

The WindowServer log corroborates the location: it stops right after
`[flip] display=0x1e … scanout=3440x1440 …` and before `[flip] io=…`, i.e. inside
`rd_make_surface`, before `present_iosurface` is ever reached.

## 2. `present_iosurface` was correct — re-disassembled

`SLCADisplay::present_iosurface(__IOSurface*, bool)` @ SkyLight +0x00411F1C
(load 0x188b02f1c). Prologue confirms the payload's AAPCS64 layout was right:

```
+40  mov x22, x2    ; bool  (sync)
+44  mov x21, x1    ; __IOSurface*  (io)
+48  mov x19, x0    ; this  (SLCADisplay*)
```

Simple path (taken by both displays: builtin flags 0x800030e1, external 0x80000020,
bit 2 = 0x4 clear):

```
+156  bl  objc_msgSend$enabled                (x0 = [self+0x1d8] = ca)
+172  bl  objc_msgSend$uniqueId               (x0 = ca)
+188  .. vtable[0x6f8](this)                  (C++ virtual, blraa — internal prepare)
+228  ldr x0,[x19,#0x1d8]; mov x2,x21; mov x3,#0
+240  bl  objc_msgSend$presentSurface:withOptions:   ; [ca presentSurface:io withOptions:nil]
+244  bl  get_hmd_swap_lock()
+252  bl  recursive_mutex::lock()
+260..  release old front [+0x2c8]/[+0x2d0], clear aux [+0x2d8..0x308]
+336  bl  set_swapped_iosurface(io)           ; +0x00412824 (IOSurfaceGetID -> surfacepool)
+348  mov w21,#1 ; ret                        ; return 1
```

**Every** objc_msgSend in `present_iosurface` targets `ca = [self+0x1d8]` (the CA
display instance) — none targets NSNumber. No `sel_registerName`/`objc_getClass` in
the function. `objc_msgSend$presentSurface:withOptions:` (stub 0x188ca20e0) loads
the registered selector `presentSurface:withOptions:` from the shared-cache selref
and `braa`s to `objc_msgSend` — SkyLight's own, correctly-uniqued selector.
`set_swapped_iosurface` (+0x00412824) is pure C++ (IOSurfaceGetID →
surfacepool_surface_by_id → allocate_shared<CASurface> → surfacepool_insert →
`str` at +0x2c8/+0x2d0); no ObjC.

So the payload's call `present(hw, io, /*sync*/true)` is the correct, minimal flip
call. Nothing about `present_iosurface` needed changing.

## 3. The fix

`payload_flip2.m` = `payload_flip.m` with `rd_make_surface` rewritten to build the
IOSurface properties with **CoreFoundation C functions only** (no `@()`/`@{}`):

```c
CFNumberRef nums[5]; CFNumberCreate(NULL, kCFNumberSInt64Type, &v[i]); …
CFDictionaryRef props = CFDictionaryCreate(NULL, keys, vals, 5,
    &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
IOSurfaceRef io = IOSurfaceCreate(props);
```

`CFNumberCreate`/`CFDictionaryCreate`/`CFRelease` resolve through the same
`__auth_got` auth-bind mechanism as `IOSurfaceCreate` etc. (already proven working),
so the payload performs **zero** objc_msgSend. `objdump` confirms the flip2 bundle
has no `objc_msgSend`/`numberWith*`/`dictionaryWith*` references.

Build:

```
cd /Users/dperry/Documents/Codex/2026-11-07/task/linux-shim-integration-next/repo/integration/rdmetal
clang -arch arm64e -bundle payload_flip2.m -o /tmp/rdgpu-scanout-flip2-payload \
    -framework Foundation -framework IOSurface -framework CoreFoundation
```

Standalone surface check (same CF code path): 3440x1440 BGRA8888 magenta surface,
pixel[0]=0xFFFF00FF MATCH.

## 4. Dock validation (uid 501, no root) — PASS (clean no-op)

```
== dock_inject ==  payload: /tmp/rdgpu-scanout-flip2-payload
Dock pid: 78043
task_for_pid -> kr=0
dlopen result: 0x3580006c6fb2a0 (SUCCESS — handle returned; constructor ran)
```

```
RDGPU_FLIP_LOAD pid=78043 mode=flip want_id=0x1e want_main=0
RDGPU_FLIP_DLOPEN SkyLight=0x4d80035d4637d0
RDGPU_FLIP_BASE skyBase=0x1886f1000
RDGPU_FLIP_SKYCHEIN ref=0x0 p1=0x0 p2=0x0 sess=0x0 dset=0x0 begin=0x0 end=0x0
RDGPU_FLIP_DONE result=no-display
```

`__sessionControlRef` is NULL in the Dock, so the chain is all-NULL and the present
is never reached (no display, no surface, no flip). Dock (pid 78043) stayed alive.

## 5. Root command for the parent (WindowServer run — the actual flip)

```
cd /Users/dperry/Documents/Codex/2026-11-07/task/linux-shim-integration-next/repo/integration/rdmetal
sudo ./ws_inject_manual_d /tmp/rdgpu-scanout-flip2-payload
sudo grep -E 'RDGPU_FLIP|\[flip\]' /tmp/rdgpu-scanout.log | tail -40
```

Optional: flip the builtin instead — `sudo sh -c 'echo 0x27 > /tmp/rdgpu-flip-display'`
before injecting. Expected: `[flip] io=… id=… size=3440x1440 pixelFormat=0x42475241`,
`[flip] CALL present_iosurface(hw=… io=… sync=true)`, `RESULT … result=1`, and a
`swap_after` that differs from `swap_before` (new magenta front surface). One
bounded call; do not loop.
