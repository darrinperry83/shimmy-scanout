# SkyLight vtable slot + declkey for present_iosurface — round 8 (CORRECTED)

Read-only research (live dyld-shared-cache reads + lldb disassembly, no root, no flip).
macOS 26.5.1 / 25F80 arm64e. SkyLight dli_fbase = 0x1886f1000 this boot.

## Verdict (corrects the round-7 patch)

The prior patch's vtable suppression used **slot 0x5e0** AND **declkey 0x456c**.
BOTH were wrong:

| | prior | CORRECT |
|---|---|---|
| byte offset from stripped vptr (`_ZTV+0x10`) | 0x5e0 | **0x5d0** |
| declkey (16-bit address diversity) | 0x456c | **0x5a24** |

The declkey is **NOT** `ptrauth_string_discriminator(mangled)` (that is 0x456c).
Apple's build uses a different 16-bit discriminator; 0x5a24 was recovered
empirically (see §3) and read directly off the call site's `movk`.

## 1. Vtable layout (empirical)

`_ZTVN2WS8Displays11SLCADisplayE` load @ **0x1efe1a140** (size 0x850, dyld-shared-
cache __DATA — fixed across boots; this boot's stripped vptr = `_ZTV+0x10` =
0x1efe1a150, matching the round-4/5 WindowServer log `hw` vptr).

Dumping the vtable (PAC-strip low 36 bits of each entry):

```
slot 0x5d0 (_ZTV+0x5e0) = 0x188b02f1c  <== present_iosurface  (SkyLight +0x411F1C)
slot 0x5e0 (_ZTV+0x5f0) = 0x188b02e3c  <== the WRONG slot the prior patch used
slot 0x560 (_ZTV+0x570) = 0x188b0a190  <== swapped_surface      (SkyLight +0x419190)
```

## 2. Call-site disassembly (definitive)

`WS::Displays::SLCADisplay::present_empty_update` (SkyLight +0x410890), the virtual
call to present_iosurface:

```
0x188b049b0  ldr   x16,[x19]          ; vptr (DA-signed)
0x188b049b4  autda x16,x22            ; authenticate vptr
0x188b049b8  mov   x17,#0x5d0         ; <== SLOT = 0x5d0
0x188b049bc  add   x16,x16,x17
0x188b049c0  ldr   x8,[x16]           ; x8 = vtable[0x5d0] (signed fn ptr)
0x188b049c4  mov   x0,x19             ; this
0x188b049c8  mov   w2,#0x1            ; bool sync = true  (=> present_iosurface)
0x188b049cc  movk  x16,#0x5a24,lsl#48 ; <== DECLKEY = 0x5a24
0x188b049d0  blraa x8,x16
```

`mov w2,#1` is the `bool sync` third argument — this is unambiguously
`present_iosurface(__IOSurface*, bool)`.

## 3. PAC reproduction (confirms declkey + formula)

For slot `S`, the discriminator is
`ptrauth_blend_discriminator(&vtable[S], declkey)` and the entry is IA-key
(`ptrauth_key_function_pointer`) signed. Reproducing the LIVE entry from the raw
address:

```
present_iosurface: sign(0x188b02f1c, IA, blend(0x1efe1a720, 0x5a24)) == 0xd16b000188b02f1c  MATCH
swapped_surface:   sign(0x188b0a190, IA, blend(0x1efe1a6b0, 0x4cdc)) == 0x9b79000188b0a190  MATCH
```

Second virtual (`swapped_surface`, slot 0x560, declkey 0x4cdc) confirms the exact
same formula — read off its call site `mov x17,#0x560` + `movk x16,#0x4cdc,lsl#48`
(0x188b04968/0x188b0497c) and reproduced. So the payload's sign recipe is correct;
only the two constants were wrong.

## 4. Updated payload

`payload_scanout_server3.m` — `rd_patch_vtable_present()` now uses
`CH_vtable_present_slot = 0x5d0` and `DECLKEY_PRESENT_IOSURFACE = 0x5a24`.
Rebuilt (verified constants baked in: `add x8,x8,#0x5d0`, `movk x8,#0x5a24`):

```
cd .../integration/rdmetal
clang -arch arm64e -bundle payload_scanout_server3.m \
    -o /tmp/rdgpu-scanout-server4-payload \
    -framework Foundation -framework IOSurface -framework CoreFoundation
```

## 5. Dock validation (uid 501, no root) — PASS (clean no-op)

```
== dock_inject == payload: /tmp/rdgpu-scanout-server4-payload
Dock pid: 15009  task_for_pid -> kr=0  dlopen result: 0x2700006c6f6850 (SUCCESS)
```
```
RDGPU_SCANOUT_LOAD pid=15009 mode=server want_id=0x1e
RDGPU_SCANOUT_BASE skyBase=0x1886f1000
RDGPU_SCANOUT_SKYCHEIN ref=0x0 p1=0x0 ... (all NULL)
RDGPU_SCANOUT_DONE result=no-display
```
`__sessionControlRef` is NULL in the Dock → no display mapped → the vtable patch is
never reached; Dock stayed alive.

## 6. Root command (unchanged --register flow)

```
cd /Users/dperry/Documents/Codex/2026-11-07/task/linux-shim-integration-next/repo/integration/rdmetal
sudo ./ws_inject_manual_d --register /tmp/rdgpu-scanout-server4-payload
sudo grep -E 'RDGPU_SCANOUT' /tmp/rdgpu-scanout.log | tail -40
```

Expect in WindowServer: `RDGPU_SCANOUT_VTABLE_PATCHED slot=0x1efe1a720 vtable=0x1efe1a150
orig=0xd16b000188b02f1c ... declkey=0x5a24` (the ABI_MISMATCH is gone).
