# Presenting the Hyprland frame on the CA's own render thread (macOS 26.5.1 / 25F80 arm64e)

Scope: research + disassembly + a read-only userland probe. **No WindowServer injection was
performed and no payload was produced.** All addresses are *unslid* shared-cache addresses
(SkyLight `__TEXT` base = `0x186CD9000`; runtime base from the parent = `0x1886F1000`, slide
`0x1A18000`). Everything was disassembled straight out of
`/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e(.01)`.

---

## 1. Conclusion (chosen mechanism)

**Hook the `present_iosurface` vtable slot (`+0x6a0`) so the CoreAnimation render loop's own
per-vblank call presents *our* IOSurface.** The call then originates on the CA render thread,
where the `CompositorMetal` context is valid, eliminating the
`src_texture != nil && dst_texture != nil` / `scanout_iosurface != nullptr` race that SIGABRTs
WindowServer today.

The two alternatives are **refuted**:

* **(a) set `swapped_surface` (+0x2c8)** — `+0x2c8` is an *output* of `present_iosurface`
  (set by the external-update path, zeroed by the simple path), and `present_empty_update`
  never reads it. Just writing it does nothing.
* **(b) register a vsync callback via IOMobileFramebuffer selector 9** — empirically
  `kIOReturnUnsupported` on this system (probe below), and even if it worked it would fire on
  IOKit's notification dispatch, *not* the CA render thread.

---

## 2. Disassembly evidence

### 2.1 `present_iosurface` — SkyLight+`0x411F1C` (virtual, vtable slot `0x6a0`)

Signature `(this=x0, __IOSurface* io=x1, bool external=x2)`. The mode is selected by
`flags[+0x76c]`:

```
ldrb w8, [x0, #0x76c]        ; flags byte
tbz  w8, #1, ...             ; bit1 = guard (if set, run a pre-check via +0x9b0)
...
ldrb w8, [x19, #0x76c]
tbnz w8, #2, +0x412088       ; bit2 (0x4) set -> EXTERNAL-UPDATE path
; ---- SIMPLE path (bit2 clear) ----
blraa vtable[0x6f8](this)                    ; +0x411fd8
ldr  x0, [x19, #0x1d8]                       ; cadisplay
mov  x2, x21                                 ; io
mov  x3, #0                                  ; options = nil
bl   SkyLight+0x5b10e0                        ; objc_msgSend stub -> "presentSurface:withOptions:"
bl   SkyLight+0x412784                        ; get global
... zero swapped_surface {+0x2c8,+0x2d0} and 3-slot ring {+0x2d8,+0x2e8,+0x2f8}, +0x308 ...
bl   SkyLight+0x412824                        ; "set_swapped_iosurface" (also does a Metal copy)
mov  w21, #1 ; return 1
; ---- EXTERNAL-UPDATE path (bit2 set) ----
cbz  x21, ret                                 ; io == nil -> early out
ldr  x0, [x19, #0x1d8]; mov w2,#0
bl   SkyLight+0x5aaf20                        ; "beginExternalUpdate:usingSoftwareRenderer:" (NO)
...
bl   SkyLight+0x5aab40                        ; "currentSurfaceWithOptions:needsClear:...:vsyncOff:..."
... (build transform/color matrices from +0x330..+0x3b0, width/height check of io) ...
bl   SkyLight+0x4c56c0 / 0x4c56d0             ; Metal command-buffer / context acquire
...
bl   SkyLight+0x5abc80                        ; "finishExternalUpdate:withFlags:debugInfo:"
bl   SkyLight+0x412978 / 0x412a2c / 0x412b1c / 0x412c9c  ; the Metal texture copy cluster
...
str  x25, [x19, #0x2c8]                       ; swapped_surface = finish result (+0x412594)
```

The `objc_msgSend` stubs (`SkyLight+0x5b10e0` etc.) are `adrp/ldr` of a `__objc_selref` +
`braa` to `objc_msgSend`. The selector strings, read from `__objc_methname` in `__TEXT`:

| stub (SkyLight+) | selector |
|---|---|
| `0x5b10e0` | `presentSurface:withOptions:` |
| `0x5aaf20` | `beginExternalUpdate:usingSoftwareRenderer:` |
| `0x5aab40` | `currentSurfaceWithOptions:needsClear:readOnly:vsyncOff:sharedEventRef:signalValue:` |
| `0x5abc80` | `finishExternalUpdate:withFlags:debugInfo:` |

### 2.2 The exact assert site — the `CompositorMetal` scanout copy

Strings in `CompositorMetal.mm` (SkyLight `__TEXT`):

```
0x18720aac5  "scanout_iosurface != nullptr"
0x18720aae2  "scanout_iosurface_id != IOSurfaceGetID(source_iosurface) && ...same..."
0x18720ab57  "dst_texture != nil"
0x18720ab61  "src_texture != nil && dst_texture != nil"
0x18720ac6f  "scanout_texture"
```

The assert handlers live at **SkyLight+`0x412620`…`0x4126a0`**, each loading a filename/function
string, calling the `os_log`/assert routine (`SkyLight+0x4c8de0`), then executing **`brk #1`
at `+0x4126a0`** — this is the `RDGPU_SCANOUT_GUARD FAULT` → SIGABRT. The same
`+0x4126xx` block is referenced by the present_iosurface Metal-copy cluster
(`0x412978`, `0x412a2c`, `0x412b1c`, `0x412c9c`) and by `set_swapped_iosurface` (`0x412824`).
**So both the simple and external paths funnel into the same `CompositorMetal` scanout copy,
and both require the CA render thread's Metal context.**

### 2.3 `present_empty_update` — SkyLight+`0x410830` (non-virtual; parent's `+0x410890` is mid-function)

```
0x410830 pacibsp; sub sp,#0x60 ...
0x41085c ldr  x16,[x0]        ; vtable
0x41086c mov  x17,#0x6a0
0x410870 add  x16,x16,x17
0x410874 ldr  x8,[x16]
0x41087c blraa x8,x16         ; virtual call vtable[0x6a0] = present_iosurface(this, ...)
0x410880 mov  w21,#1 ; mov w20,#1
0x410888 tbnz w0,#0, +0x4108a8 ; present_iosurface returned bit0 -> skip
0x41088c ldrb w8,[x19,#0x4b1] ; tbnz w8,#0, skip
0x410894 ldrb w8,[x19,#0x4b8] ; tbnz w8,#0, skip
0x41089c bl  SkyLight+0x4109b0 ; helper (reads +0x480/+0x488/+0x490), w20 = !result
0x4108a8 ldr x0,[x19,#0x1d8]  ; cadisplay
0x4108ac mov x2,w20
0x4108b0 bl  SkyLight+0x5b2ce0 ; objc_msgSend stub #1 on cadisplay
0x4108b4 ldr x0,[x19,#0x1d8]
0x4108b8 ldrb w8,[x19,#0x4b2]; bic w2,w21,w8
0x4108c0 bl  SkyLight+0x5b2cc0 ; objc_msgSend stub #2 on cadisplay
... bookkeeping (byte +0x4ba, a log/notification struct on the stack) ...
```

Key point: `present_empty_update` reads `+0x4b1/+0x4b2/+0x4b8/+0x4ba` and `cadisplay` `+0x1d8`;
**it never reads `+0x2c8`.** Its virtual call at `vtable[0x6a0]` is `present_iosurface`.

Callers of `present_empty_update` (all on the CA render thread):
`SkyLight+0x413c80` ("refresh display state; if changed, tail-call present_empty_update"),
which itself is called from many display-reconfiguration sites. The vsync source is the CA
(QuartzCore) render loop driving `cadisplay` — not an IOF selector-9 callback (see §3).

### 2.4 The SLCADisplay vtable (arm64e auth pointers)

Vtable entries are `dyld_chained_ptr_arm64e_auth_rebase`: `{target:32, diversity:16, addrDiv:1,
key:2, next:11, bind:0, auth:1}`, where `address = 0x180000000 + target`. Decoding SkyLight
`__AUTH_CONST`:

* `present_iosurface` is stored at **`0x1EE402720`** and **`0x1EE402FC0`**
  (two vtables `0x8a0` apart — the class + a subclass; both put `present_iosurface` at
  byte offset **`0x6a0`**, slot index `0xd4`). Entry value
  `0x80156890070eaf1c` = `{target=0x70eaf1c, diversity=0x6890, key=2, auth=1}`.
* Therefore the SLCADisplay **vtable base (unslid) = `0x1EE402080`**, and
  `vtable[0x6a0]` = `present_iosurface` (consistent with `present_empty_update` calling
  `vtable[0x6a0]` and with `present_iosurface`'s own `vtable[0x530]`/`vtable[0x6f8]` calls
  decoding to real methods `SkyLight+0x41b210` / `+0x433a50`).

---

## 3. Userland probe (IOMobileFramebuffer `setVSyncNotifications`)

Built and ran `vsync_probe.c` (arm64e, links IOKit) from a normal user account. It opens the
`IOMobileFramebuffer` user client and probes the documented MIG methods
([The Apple Wiki — Dev:IOMobileFramebuffer](https://theapplewiki.com/wiki/Dev:IOMobileFramebuffer)):

```
IOServiceOpen                    -> 0x0  (success)
selector 7  getId                -> 0x0, id = 0x1
selector 8  getDisplaySize       -> 0x0, 3072 x 3152
selector 4  swapBegin            -> 0x0, swapID = 0x7
selector 3  getDefaultSurface    -> 0xe00002c2 (kIOReturnBadArgument, needs a layer arg)
IOConnectSetNotificationPort     -> 0x0
selector 9  setVSyncNotifications (fn, userData)  -> 0xe00002c7 (kIOReturnUnsupported)
selector 9  setVSyncNotifications (0 inputs)      -> 0xe00002c2 (kIOReturnBadArgument)
```

Interpretation:
* `setVSyncNotifications` **is** selector 9 with input `{size_t functionAddress, size_t
  userData}` (wiki-confirmed; 0-input → `BadArgument`, 2-input → `Unsupported`).
* On macOS 26 Apple Silicon it returns **`kIOReturnUnsupported`** — the classic vsync
  notification was moved to the Display Coprocessor (DCP). So candidate (b) cannot be used,
  and (per the wiki) its callback is dispatched through `IODispatchCalloutFromCFMessage` on an
  async-notification port — i.e. *not* the CA render thread anyway.

This also confirms the *swap* path the shim already relies on: `swapBegin` (selector 4),
`swapEnd` (5), `swapWait` (6), `getId` (7).

---

## 4. Design (step by step)

**Goal:** every vblank, the CA render thread presents the shim's Hyprland IOSurface through
the display's own `present_iosurface`, so `CompositorMetal` never sees a foreign thread.

1. **Find the display object + vtable at runtime.**
   * `SLCADisplay` object is the `hw` object the parent already has.
   * Authenticate `[hw]` with `autda` (context = object ptr) to get the vtable base;
     compute unslid base `0x1EE402080` → runtime `0x1EE402080 + slide`.
   * The slot to patch is `vtable + 0x6a0` (both copies at `+0x6a0` and `+0x6a0+0x8a0` if
     the display uses the subclass vtable — patch whichever the object actually points to,
     or both).

2. **Install the thunk (arm64e-correct).**
   * Write a trampoline `our_present_iosurface(this, io, ext)` into executable memory.
   * Patch `vtable[0x6a0]` with a *signed* pointer to the trampoline: same `key=2`,
     diversity `0x6890` (or compute a fresh `pacda`/`paciza` with the right context) — this
     is the same mechanism the parent already used to stub `present_iosurface`.

3. **Surface handoff (lock-free SPSC).**
   * The shim renders Hyprland into its Metal drawable IOSurface and publishes
     `{IOSurface*, generation}` into one fixed slot (a field the shim controls, or a known
     global). `std::atomic<uintptr_t>`-style; one writer, one reader.
   * The reader (thunk) loads the latest published surface each vblank.

4. **The thunk body (runs on the CA render thread):**
   ```
   our_present_iosurface(this, ca_io, ext):
       our = load_handoff()              # shim's latest frame, or NULL
       target = our ? our : ca_io        # substitute only when we have a frame
       return real_present_iosurface(this, target, ext)   # forward, keep return code
   ```
   * Keep the display's `flags[+0x76c]` bit2 set (external-update) — the path the parent
     already validated for ~11 frames.
   * The return value must match `present_iosurface`'s contract (1 success / 0 failure) so
     `present_empty_update`'s `tbnz w0,#0` and the `+0x4b4` counter stay correct.

5. **Eliminating the race (why this fixes it).**
   * The shim **never** calls `present_iosurface` from its injected thread again. The only
     caller is the CA render loop, on the CA render thread, where the `CompositorMetal`
     device/queue are valid. The assert
     `src_texture != nil && dst_texture != nil` / `scanout_iosurface != nullptr` at
     `SkyLight+0x4126xx` can no longer fire from a foreign thread.
   * The shim's only per-frame work is: render → publish. Presentation/scanout/swapWait stay
     on the CA render thread (the parent's existing drain-before-present `swap_wait` on
     selector 6 can move into, or simply be coordinated with, the thunk).

6. **Keeping the CA loop alive (the "stub halted it" concern).**
   * The thunk must be non-blocking, must always forward to the real `present_iosurface`,
     and must return the real code. Do **not** replace the present with a `ret`; do not
     block on the shim; do not hold a lock the CA loop needs.
   * When idle (`our == NULL`), forward `ca_io` unchanged so the normal empty-update path
     keeps the display refreshed and `present_empty_update` keeps running.

7. **Pacing.**
   * Publish one frame per vblank (or let the thunk always take the latest and drop stale
     frames). The display's own vsync (DCP-driven, through the CA loop) is the clock; do not
     try to drive timing from the shim's thread.

### Offsets / functions (unslid, SkyLight base 0x186CD9000)

| item | value |
|---|---|
| `present_iosurface` | `SkyLight+0x411F1C` (virtual, `vtable[0x6a0]`) |
| `present_empty_update` | `SkyLight+0x410830` (entry) |
| SLCADisplay vtable base | `0x1EE402080` (`__AUTH_CONST`) |
| `present_iosurface` vtable entries | `0x1EE402720`, `0x1EE402FC0` (signed: `0x80156890070eaf1c`) |
| flags (external-update bit2 = 0x4) | `+0x76c` |
| cadisplay | `+0x1d8` |
| swapped_surface | `+0x2c8` (output only) |
| CompositorMetal scanout assert / `brk #1` | `SkyLight+0x412620`…`0x4126a0` |
| CA selectors | `presentSurface:withOptions:` · `beginExternalUpdate:usingSoftwareRenderer:` · `currentSurfaceWithOptions:needsClear:readOnly:vsyncOff:sharedEventRef:signalValue:` · `finishExternalUpdate:withFlags:debugInfo:` |
| IOF setVSyncNotifications | selector 9, `{functionAddress, userData}` → `kIOReturnUnsupported` on 26.5.1 |
| IOF swap | selector 4 swapBegin · 5 swapEnd · 6 swapWait · 7 getId |
