# RMatrixOS-scanout

The WindowServer injection for RMatrixOS: presents the shim's IOSurface directly to the
display's scanout (bypassing WindowServer's compositing). This is the only component pinned
to an exact macOS version (SkyLight offsets change per release).

## Layout
- `ws_inject_manual_d2` + `ws_inject_manual.m` + `inject_stub_manual.s` — the root injector
  (registers `com.rdgpu.scanout` in the WindowServer bootstrap namespace).
- `payload_scanout_server*.m` — the injected payloads. `server18` is the current direct-present
  flip (bit-2 EXTERNAL-UPDATE + pre-flight assert gate + drain). `payload_flip3.m` is the
  one-shot magenta proof.
- `SKYLIGHT_SCANOUT_*.md` — the reverse-engineering notes (offsets, vtable slots, asserts).

## Versioning
Tag each release with the macOS version it targets, e.g. `macos-26.5.1`.
