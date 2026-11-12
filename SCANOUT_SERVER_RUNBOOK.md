# Scanout server — build + runbook (round: persistent `present_iosurface` server)

macOS 26.5.1 / 25F80 arm64e. SkyLight base via dladdr = `0x1886f1000` this boot.
This builds directly on the PROVEN flip3 (`payload_flip3.m`): same offsets, same chain
walk, same PAC-sign discipline — plus a persistent Mach server.

## 1. What was built

`payload_scanout_server.m` → `/tmp/rdgpu-scanout-server-payload` (arm64e bundle, zero
`objc_msgSend`, verified with `nm -u`). On load (single bounded constructor):

1. walks `PKGDisplay` chain → `get_displayref_for_pkgdisplay_by_uuid` (+0x002B9194) →
   `SLCADisplay*` for the external display `0x1e` (override: write hex id to
   `/tmp/rdgpu-scanout-display`).
2. sets `flags[+0x76c] |= 0x4` (kept set — forces the EXTERNAL-UPDATE / real scanout
   present path), storing the original flags for restore.
3. receives on the `com.rdgpu.scanout` service port that the ROOT injector registered
   in `gui/501` (`ws_inject_manual_d --register` allocates the receive right in
   WindowServer, extracts a send right for launchd, `bootstrap_register`s it, and
   passes the receive-right NAME to the payload via the loader ctx). The payload no
   longer registers: WindowServer (uid 88) can look up `gui/501` (kr=0) but
   `bootstrap_register` there returns BOOTSTRAP_NOT_PRIVILEGED (1100) — only root or
   uid 501 may register.
4. detaches a pthread receive loop; each `rdgpu_present_msg_t` IOSurface →
   `present_iosurface(hw, io, /*sync*/true)` (PAC-signed, +0x411F1C).

Safety: `flags|=0x4` is only set AFTER the display is mapped AND the service is
registered. Any hard fault in the present loop restores the flags and stops.

## 2. Mach service + protocol (proven, no root needed)

`e2e_mach_test.c` → `/tmp/e2e_mach_test` proves the full round-trip in the console
user's own domain: `bootstrap_look_up_per_user(NULL,501)` → `bootstrap_register` →
client sends an IOSurface via `IOSurfaceCreateMachPort` → server
`IOSurfaceLookupFromMachPort` → one-word reply. **Result: `PROTOCOL MATCH OK`.**

The shared wire layout is `rdgpu_protocol.h` (the payload `#include`s it by absolute
path, so the server and `rdgpu_scanout_client.m` can never drift):
`rdgpu_present_msg_t` = 48 bytes, `rdgpu_reply_t` = 28 bytes (verified).

### Three latent Mach bugs found + fixed (the reply path had never round-tripped)

1. **Client send** — `msgh_bits` local field was `0` with a live reply port →
   `MACH_SEND_INVALID_HEADER` (0x10000010). Fixed to `MACH_MSG_TYPE_MAKE_SEND_ONCE`.
2. **Client reply receive** — `rcv_size = sizeof(reply)` (28) is too small for the
   kernel trailer → `MACH_RCV_TOO_LARGE`. Fixed to a 128-byte union buffer.
3. **Server reply** — replied to the send-once reply right with `COPY_SEND` →
   `MACH_SEND_INVALID_DEST`. Fixed to `MACH_MSG_TYPE_MOVE_SEND_ONCE`.

These are fixed in:
- `metal-wayland-next/shim-metal-clear/src/rdgpu_scanout_client.m` (shim client), and
- `payload_scanout_server.m` (server reply).

`shim_gui` has been **rebuilt** (`./build.sh gui`, 07:51) with the fixed client.
(The Dock OSAX `rdgpu-scanout-osax/payload.m` has the same reply bug #3, but it is out
of scope here — left untouched.)

## 3. Shim wiring

- env: `RDGPU_SCANOUT=1` (the shim's `present_source` already calls
  `rdgpu_scanout_present(drawable.texture.iosurface, CGMainDisplayID())` when set).
  `run_metal_clear_preview.py` inherits the env via `os.environ.copy()`, so just prefix
  the run with `RDGPU_SCANOUT=1`.
- The shim sends `display_index = CGMainDisplayID()` (builtin 0x27) but the server
  ignores it and presents to the external `0x1e` (single-display mode).

## 4. Root command (the single injection — needs sudo, I cannot run it here)

```
cd /Users/dperry/Documents/Codex/2026-11-07/task/linux-shim-integration-next/repo/integration/rdmetal
sudo ./ws_inject_manual_d --register /tmp/rdgpu-scanout-server-payload
sudo grep -E 'RDGPU_SCANOUT' /tmp/rdgpu-scanout.log | tail -40
launchctl print gui/501 | grep rdgpu.scanout     # expect "com.rdgpu.scanout" A (active)
```

The `--register` flag makes the (root) injector register `com.rdgpu.scanout` into
`gui/501` BEFORE mapping the payload, then hand the receive-right NAME to the payload.
The injector prints (on its stdout):

```
register: self bootstrap_port=0x… kr=0 uid=0 euid=0
register: bootstrap_look_up_per_user(NULL,501) kr=0 gui=0x…
register: mach_port_allocate(target, RECEIVE) kr=0 name=0x…
register: mach_port_extract_right(target, 0x…, MAKE_SEND) kr=0 send=0x…
register: bootstrap_register(gui, com.rdgpu.scanout) kr=0 (Success)
register: service com.rdgpu.scanout registered in gui/501; receive-right name=0x… in target
```

Expected payload log (`/tmp/rdgpu-scanout.log`), in order:
`LOAD mode=server want_id=0x1e` → `DLOPEN` → `BASE skyBase=0x1886f1000` →
`SKYCHEIN` → `DISPLAY display=0x1e hw=… cadisplay=… scanout=3440x1440 flags=0x…` →
`RECV port=… (injected by root injector)` → `FLAGS … -> 0x…4` →
`SERVING name=com.rdgpu.scanout port=… display=0x1e` → `DONE result=serving`.

**The one thing to watch** is the injector's `bootstrap_register(…) kr=` line:
- `kr=0 (Success)` → registered in `gui/501`, the shim will reach it. Proceed.
- `kr=1100` (or nonzero) → the root injector was NOT authorized to register into
  `gui/501` (should not happen as root); the payload will log `RECV port=…` but the
  shim will not resolve the service. Stop and report it.

## 5. Then run the shim

```
RDGPU_SCANOUT=1 python3 /Users/dperry/Documents/Codex/2026-11-07/task/hyprland-stage/metal-wayland-next/run_metal_clear_preview.py <same args as the kiosk/preview run>
```

Each frame: `present_source` blits the guest frame → `rdgpu_scanout_present` →
`com.rdgpu.scanout` → server `present_iosurface(hw, io, true)`. The external display
should show the Hyprland desktop (not magenta). Server log shows
`RDGPU_SCANOUT_PRESENT display=0x1e … ret=1` per frame.

## 6. Flashing (task 3)

The server presents on every message (the shim already paces to one frame per refresh,
and `sync=true` blocks on `MetalContext::Flush`, so presents land at vsync cadence).
But WindowServer's own compositor still presents the desktop to the external display,
so the honest prediction is that the frame will FLICKER at vsync (Hyprland ↔ desktop)
unless WindowServer's own `present_iosurface` for 0x1e is suppressed.

If it flashes, the minimal suppression is to patch the external `SLCADisplay`'s
vtable slot **0x5e0** (`present_iosurface`) to a stub that returns 1, so WindowServer's
compositor present becomes a no-op while our direct (raw-address) call keeps doing the
real scanout. vtable = `*(SLCADisplay*)` (vptr at +0x0), slot at `vtable + 0x5e0`,
PAC-signed with the vtable's diversity (needs `ptrauth_sign` with the vtable address
as context — the same auth dance round-4 documented for vptr authentication). I did
NOT ship this patch yet because it can only be validated with the live injection and
it must be reverted on failure; it is the exact next step if the flicker is confirmed.

Do NOT leave the display stuck magenta: if a present hard-faults, the payload restores
`flags[+0x76c]` and stops, and WindowServer resumes compositing.
