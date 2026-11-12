# SkyLight SERVER-side present/scanout — round 4 (corrected PKGDisplay → SLCADisplay)

Read-only research (lldb on dyld-shared-cache images, no display flipped).
Follows `SKYLIGHT_SCANOUT_ROUND3.md`. macOS 26.5.1 / 25F80, arm64e.
SkyLight dli_fbase = 0x1886f1000 this boot; offsets below are relative to it.

## Root cause of the round-3 wrong pointer

Round 3 used `managed_display_for_pkg_display(PKGDisplay const*)` (+0x0013CCBC)
and treated its return as the hardware `WS::Displays::Display*`/`SLCADisplay*`.
That is wrong. Its exact disassembly:

```
+12: cbz  x0, +52                        ; pkg==NULL -> session-chain fallback
+16: ldr  x16, [x0]                      ; pkg->vptr (PAC-signed)
+28: autda x16, x17                      ; authenticate vptr
+32: ldr  x8, [x16, #0x18]!              ; vtable[0x18]
+40: blraa x8, x16                       ; call vtable[0x18](pkg)
+44: ldr  x0, [x0, #0xf0]                ; return [result + 0xf0]
```

So it returns `[ pkg->vtable[0x18](pkg) + 0xf0 ]`.

The concrete `PKGDisplay` subclass is `(anonymous namespace)::MirrorDisplay`
(vtable `_ZTVN12_GLOBAL__N_113MirrorDisplayE`, loaded 0x1efe1d500; vptr =
_ZTV+0x10). Its `vtable[0x18]` is:

```
(anonymous namespace)::MirrorDisplay::get_master() const:
    ldr x0, [x0, #0xc8]    ; return [this + 0xc8]   (the master MirrorDisplay*)
    ret
```

Therefore `managed_display_for_pkg_display(pkg)` == `[[pkg+0xc8] + 0xf0]`, and
that value is a **PKGDisplaySpaceData*** (the Spaces "managed display" runtime
state) — NOT the SLCADisplay. Proof: `PKGDisplayCopyManagedSpaces` (+0x13CD38)
reads `[managed_display_for_pkg_display(pkg) + 0x48]` as an `x_list_struct*` of
spaces, which is exactly PKGDisplaySpaceData's spaces list. Its +0xd8/+0x1d8 are
Spaces fields, hence the round-3 all-zero read and the garbage `[+0xf0]`.

(The base `_ZTV10PKGDisplay` vtable confirms the class is abstract: slots 0x20–0x40
are `__cxa_pure_virtual`; the concrete `MirrorDisplay` overrides them.)

## The corrected bridge

Hidden in-process helper (also `_ZL` local, plain `bl`-called → rd_sign_fn(addr,0)
works, same as round 2/3):

```
void get_displayref_for_pkgdisplay_by_uuid(void *out /*x0*/, PKGDisplay const* pkg /*x1*/)
    SkyLight +0x002B9194
```

It reads `pkg->uuid` (+0x2c/+0x34, the CFUUIDBytes round 2 already logs), then
tail-calls:

```
WS::Displays::Manager::display_by_uuid(CFUUIDBytes) const   SkyLight +0x0033E0C0
```

which iterates the CA manager's display list, compares each display's uuid
(vtable[0x50]), and on match writes a 16-byte `std::shared_ptr<WS::Displays::Display>`
= `{ Display*, ctrl }` to `*out` (with a strong retain). `out[0]` is the hardware
display — an `SLCADisplay` for a physical desktop display. This is the same uuid
the PKGDisplay ctor copied from the source Display, so it is an exact match.

## PKGDisplay ctor (task 2) — no retained hardware pointer

`PKGDisplay::PKGDisplay(WSDisplayWrapper const&)` (+0x454EC8) reads
`[wrapper+0x00]` = `Display*` and COPIES metadata only:

| copied | source | dest (PKGDisplay) |
|---|---|---|
| bounds CGRect | `Display::bounds()` vtable[0xa8] | +0x08 |
| display id u32 | `[Display* + 0xd8]` | +0x28 |
| CFUUIDBytes | `Display::uuid()` vtable[0x50] | +0x2c / +0x34 |
| sarlacc rect | `sarlacc_rect()` | +0x40..0x58 |
| has-sarlacc u8 | `current_mode_has_sarlacc()` | +0x60 |
| is_main u8 | compare vs CA manager main | +0xa8 |

It does NOT store the `Display*`/`shared_ptr<Display>` anywhere in the object, and
the concrete `MirrorDisplay` only adds `+0xc8` (master MirrorDisplay*) and `+0xf0`
(PKGDisplaySpaceData*) — neither is the hardware display. So there is no live
hardware-Display field to read off the PKGDisplay object; the uuid→CA-manager
bridge above is the correct (and only) in-process mapping.

## SLCADisplay field offsets (unchanged from round 3)

id u32 @ +0xd8 · CA display @ +0x1d8 · swapped surface @ +0x2c8 · ctrl @ +0x2d0 ·
scanout wide/high @ +0x634/+0x638 · present flags @ +0x76c.

## Round-4 payload

`payload_readonly4.m` → `/tmp/rdgpu-scanout-readonly4-payload`
(`clang -arch arm64e -bundle payload_readonly4.m -o /tmp/rdgpu-scanout-readonly4-payload
-framework Foundation -framework IOSurface`).

For each PKGDisplay it (a) logs the round-3 wrong chain (`master=[pkg+0xc8]`,
`managed=[master+0xf0]`) for the record, then (b) calls
`get_displayref_for_pkgdisplay_by_uuid(&ref, pkg)` and reads the SLCADisplay
fields off `ref[0]`, logging id / cadisplay / swapped_surface / ctrl / scanout WxH
/ flags and an id `MATCH` check against the PKGDisplay id. READ-ONLY, no flip, no
CAManager() call in the Dock path.

### Dock validation (uid 501, no root) — PASS

```
RDGPU_SCANOUT_LOAD pid=54061 mode=readonly4
RDGPU_SCANOUT_DLOPEN SkyLight=0x7e80035d4637d0
RDGPU_SCANOUT_BASE skyBase=0x1886f1000
RDGPU_SCANOUT_SKYCHEIN ref=0x0 p1=0x0 p2=0x0 sess=0x0 dset=0x0 begin=0x0 end=0x0
RDGPU_SCANOUT_READONLY4_DONE
```

All-NULL / no-op, clean completion, Dock alive (pid 54061). Expected: the Dock is
not the WindowServer session, so `__sessionControlRef` is NULL and PATH 2 (which
would call `get_displayref…` → `CAManager()`) is never reached.

## Root command for the parent (WindowServer run)

```
cd /Users/dperry/Documents/Codex/2026-11-07/task/linux-shim-integration-next/repo/integration/rdmetal
sudo ./ws_inject_manual_d /tmp/rdgpu-scanout-readonly4-payload
sudo grep -E 'RDGPU_SCANOUT|scanout' /tmp/rdgpu-scanout.log | tail -60
```

Expected in WindowServer: 2 PKGDisplays; for each, `displayref ptr=<SLCADisplay*>`
with `hw id=0x27`/`0x1e` MATCH, non-null `cadisplay`, and `scanout=1800x1169` /
`3440x1440` plus a non-null `swapped_surface`.
