#!/bin/bash
# inject.sh — build + run the direct Mach injector, then verify the payload landed.
#
# Usage:
#   ./inject.sh [path/to/payload]
#
# Defaults to the rdgpu-scanout.osax payload built under metal-wayland-next.

set -uo pipefail

cd "$(dirname "$0")"

PAYLOAD="${1:-/Users/dperry/Documents/Codex/2026-11-07/task/hyprland-stage/metal-wayland-next/rdgpu-scanout-osax/rdgpu-scanout.osax/Contents/MacOS/payload}"
UID_NOW="$(id -u)"
LOG="${RDGPU_SCANOUT_LOG:-/tmp/rdgpu-scanout.log}"

echo "== inject.sh =="
echo "payload : $PAYLOAD"
echo "log     : $LOG"
echo "uid     : $UID_NOW"

# ---- build ----
echo
echo "== build dock_inject (arm64e) =="
clang -arch arm64e dock_inject.m inject_stub.s -o dock_inject -framework AppKit \
  || { echo "BUILD FAILED"; exit 1; }
echo "build OK"

# ---- codesign with the debugger entitlement (required for task_for_pid on the Dock) ----
codesign -f -s - --entitlements dock_inject.entitlements dock_inject \
  || { echo "CODESIGN FAILED"; exit 1; }
echo "codesign OK (com.apple.security.cs.debugger)"
file dock_inject

# ---- snapshot log size so we only show what this run produced ----
PRE_SIZE=0
[ -f "$LOG" ] && PRE_SIZE=$(wc -c < "$LOG" | tr -d ' ')

# ---- inject ----
echo
echo "== inject =="
./dock_inject "$PAYLOAD"
RC=$?
echo "inject exit code: $RC"

# ---- payload log (only new lines) ----
echo
echo "== $LOG (new since this run) =="
if [ -f "$LOG" ]; then
    tail -c +$((PRE_SIZE + 1)) "$LOG" 2>/dev/null | grep -E 'RDGPU_SCANOUT_(LOAD|SYM|DISPLAYLIST|CGXDEV|COREDISPLAY|BOOTSTRAP|SERVING|READY|PRESENT)' || echo "(no new RDGPU_SCANOUT_* lines)"
else
    echo "(no log file)"
fi

# ---- service registration in the Dock's gui/<uid> bootstrap domain ----
echo
echo "== launchctl print gui/$UID_NOW | grep rdgpu.scanout =="
launchctl print "gui/$UID_NOW" 2>/dev/null | grep -i "rdgpu.scanout" || echo "(not found in gui/$UID_NOW)"

echo
echo "== done =="
