# SkyLight vtable hook — round 9 (heap-copy + vptr rewrite, CORRECTED)

Read-only research + corrected payload. macOS 26.5.1 / 25F80 arm64e.
SkyLight dli_fbase = 0x1886f1000 this boot. Fixes the round-4/8 in-place patch
(`mach_vm_protect` on the shared-cache vtable → `KERN_PROTECTION_FAILURE kr=2`).

## 1. The DA-key vptr discriminator formula (definitive)

The object vptr (`hw+0`) is DA-key (`ptrauth_key_process_independent_data`) signed
with a discriminator blended from the OBJECT address + a 16-bit class constant:

```
vptr = ptrauth_sign_unauthenticated(vtable_addr_point, DA,
           ptrauth_blend_discriminator(hw, 0xc333))
     = ptrauth_sign_unauthenticated(vtable_addr_point, DA,
           (hw & 0x0000FFFFFFFFFFFF) | (0xc333 << 48))
```

`0xc333 = getPointerAuthStableSipHash("_ZTVN2WS8Displays7DisplayE")` — the type
discriminator is derived from the PRIMARY BASE class (`Display`), not SLCADisplay.
This is why BOTH the base-`Display` vptr and the `SLCADisplay` vptr use 0xc333.

Disassembly evidence (live, this boot):

```
; SLCADisplay::SLCADisplay ctor @ sky+0x438c24 — the SIGN site:
0x188b29c5c  adrp  x16, ...              ; vtable for WS::Displays::Display
0x188b29c60  add   x16, x16, #0xae8
0x188b29c64  add   x16, x16, #0x10       ; address point (vptr value)
0x188b29c68  mov   x17, x0               ; this
0x188b29c6c  movk  x17, #0xc333, lsl#48  ; <== discriminator
0x188b29c70  pacda x16, x17              ; sign vptr (DA key)
0x188b29c74  str   x16, [x0]
... (same pattern at +0x260..+0x280 for the SLCADisplay vtable, also 0xc333)

; SLCADisplay::present_empty_update @ sky+0x413890 — an AUTH site:
0x188b048d0  mov   x22, x19              ; this
0x188b048d4  movk  x22, #0xc333, lsl#48
0x188b048e0  autda x16, x17              ; (x17 = this | 0xc333<<48)
0x188b0492c  autda x16, x22              ; re-auth with the blended discriminator
```

## 2. The vtable-ENTRY discriminator (why a plain memcpy breaks)

A vtable entry at slot S is IA-key (`ptrauth_key_function_pointer`) signed with
ADDRESS DIVERSITY:

```
entry = ptrauth_sign_unauthenticated(fn, IA,
            ptrauth_blend_discriminator(&vtable[S], declkey))
```

where `declkey = getPointerAuthStableSipHash(mangled_name_of_ORIGINAL_method)`.
The "original method" is the BASE-class method that first declared the virtual
(`ItaniumCXXABI::findOriginalMethod`). The call site re-derives it:

```
ldr x8,[x16] ; movk x16,#declkey,lsl#48 ; blraa x8,x16
```

Crucially the low 48 bits of the discriminator are the ABSOLUTE slot address, so
copying the vtable to a NEW heap address invalidates every other entry's PAC.
A naive memcpy + vptr-rewrite would crash WindowServer on the next virtual call.
We must RE-SIGN all 264 entries for their heap addresses.

`getPointerAuthStableSipHash(s) = (SipHash-2-4_64(s, K) % 0xFFFF) + 1`, key
`K = {b5 d4 c9 eb 79 10 4a 79 6f ec 8b 1b 42 87 81 d4}` (little-endian; LLVM
`llvm/lib/Support/SipHash.cpp`). Reproduced and verified against the live values:

```
present_iosurface slot 0x5d0 declkey 0x5a24 == siphash("_ZN2WS8Displays7Display17present_iosurfaceEP11__IOSurfaceb")
swapped_surface   slot 0x560 declkey 0x4cdc == siphash("_ZN2WS8Displays7Display15swapped_surfaceEv")
vptr discriminator 0xc333 == siphash("_ZTVN2WS8Displays7DisplayE")
```

(round-8's "declkey != string_discriminator(mangled)=0x456c" mystery is resolved:
0x456c is the hash of the OVERRIDE's name `_ZN2WS8Displays11SLCADisplay...`; the
declkey uses the ORIGINAL `...7Display...` name, which hashes to 0x5a24.)

## 3. Per-entry declkey recovery (empirical, this boot's vtable)

For each entry we brute-force the 16-bit declkey (values that reproduce the live
signature) and disambiguate with the SipHash:

- 222 entries: `declkey = siphash(name with "11SLCADisplay"→"7Display")` (Display overrides)
-  41 entries: `declkey = siphash(name)` (methods introduced by SLCADisplay)
-   1 entry : `copy_to_display_surface` — outlier; brute-force-first-candidate = 0x5195,
              read off its call sites (`add xN,xM,#0x4a8 … movk #0x5195`).

The brute force is ~17M `pac` ops ≈ 11 ms (measured), negligible for a one-shot
injection.

## 4. Corrected payload (`server5`)

`payload_scanout_server5.m` → `/tmp/rdgpu-scanout-server5-payload`.

`rd_patch_vtable_present()` now:
1. reads + strips the vptr (DA) → address point `ap` (= `_ZTV+0x10`);
2. `mach_vm_allocate`s a 0x850-byte heap copy, `memcpy`s the whole vtable from
   `_ZTV` (= `ap-0x10`, incl. the offset-to-top/RTTI header);
3. re-signs every entry: strip IA → recover declkey (brute-force + SipHash
   disambiguation) → `sign(raw, IA, blend(heap_slot, declkey))`;
4. writes a `mov w0,#1 ; ret` stub into slot 0x5d0 of the HEAP copy, IA-signed
   with `blend(heap+0x10+0x5d0, 0x5a24)`;
5. DA-signs `heap+0x10` with `blend(hw, 0xc333)` and writes it to `hw+0`.

Restore: write the original DA-signed vptr back to `hw+0`, `mach_vm_deallocate`
the heap copy + stub page. The shared-cache vtable is never written.

Build (verified: 0 `objc_msgSend`, `movk #0x5a24` + `movk #0xc333` baked in, the
SipHash key baked in as pre-XORed init constants):

```
cd .../integration/rdmetal
clang -arch arm64e -O2 -bundle payload_scanout_server5.m \
    -o /tmp/rdgpu-scanout-server5-payload \
    -framework Foundation -framework IOSurface -framework CoreFoundation
```

## 5. Dock validation (uid 501, no root) — PASS (clean no-op)

```
== dock_inject == payload: /tmp/rdgpu-scanout-server5-payload
Dock pid: 28469  task_for_pid -> kr=0  dlopen result: 0x7480006c6fb200 (SUCCESS)
```
```
RDGPU_SCANOUT_LOAD pid=28469 mode=server5 want_id=0x1e
RDGPU_SCANOUT_BASE skyBase=0x1886f1000
RDGPU_SCANOUT_SKYCHEIN ref=0x0 p1=0x0 ... (all NULL)
RDGPU_SCANOUT_DONE result=no-display
```
`__sessionControlRef` is NULL in the Dock → no display → the vtable hook is never
reached; the Dock stayed alive. (Log went to `/tmp/rdgpu-scanout.uid501.log`
because `/tmp/rdgpu-scanout.log` is owned by `_windowserver`.)

## 6. Root command (unchanged --register flow)

```
cd /Users/dperry/Documents/Codex/2026-11-07/task/linux-shim-integration-next/repo/integration/rdmetal
sudo ./ws_inject_manual_d --register /tmp/rdgpu-scanout-server5-payload
sudo grep -E 'RDGPU_SCANOUT' /tmp/rdgpu-scanout.log | tail -40
```

Expect in WindowServer: `RDGPU_SCANOUT_VTABLE_READ … ap=0x1efe1a150` →
`RDGPU_SCANOUT_VTABLE_RESIGN re=264` → `RDGPU_SCANOUT_VTABLE_PATCHED heap=… new_vptr=…
orig_vptr=…` → `VTABLE_PATCH_RESULT rc=0 patched=1` (the kr=2 failure is gone).
