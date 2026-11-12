#!/bin/bash
# ws_inject.sh — build + (optionally) run the WindowServer Mach injector.
#
# WindowServer runs as _windowserver (uid 88), so task_for_pid from a normal
# user (uid 501) returns KERN_FAILURE (5): the taskgated uid gate requires root.
# This script must therefore be run AS ROOT for the injection to succeed.
#
# Usage (as root):
#   sudo ./ws_inject.sh probe             # task_for_pid only — SAFE, no injection
#   sudo ./ws_inject.sh [payload_path]    # full injection into WindowServer
#
# Defaults to the rdgpu-scanout.osax payload built under metal-wayland-next.

set -uo pipefail
cd "$(dirname "$0")"

PAYLOAD="${1:-/Users/dperry/Documents/Codex/2026-11-07/task/hyprland-stage/metal-wayland-next/rdgpu-scanout-osax/rdgpu-scanout.osax/Contents/MacOS/payload}"
LOG="${RDGPU_SCANOUT_LOG:-/tmp/rdgpu-scanout.log}"

if [ "$(id -u)" -ne 0 ]; then
    echo "FATAL: ws_inject must run as root (WindowServer is uid 88)."
    echo "Run: sudo $0 $*"
    exit 1
fi

echo "== ws_inject.sh =="
echo "payload : $PAYLOAD"
echo "log     : $LOG"
echo "uid     : $(id -u) ($(id -un))"

echo
echo "== build ws_inject (arm64e) =="
clang -arch arm64e ws_inject.m inject_stub.s -o ws_inject || { echo "BUILD FAILED"; exit 1; }
codesign -f -s - --entitlements dock_inject.entitlements ws_inject || { echo "CODESIGN FAILED"; exit 1; }
echo "build + codesign OK (com.apple.security.cs.debugger)"

PRE_SIZE=0
[ -f "$LOG" ] && PRE_SIZE=$(wc -c < "$LOG" | tr -d ' ')

echo
echo "== run =="
if [ "${1:-}" = "probe" ]; then
    ./ws_inject --probe
    RC=$?
else
    ./ws_inject "$PAYLOAD"
    RC=$?
fi
echo "inject exit code: $RC"

echo
echo "== $LOG (new since this run) =="
if [ -f "$LOG" ]; then
    tail -c +$((PRE_SIZE + 1)) "$LOG" 2>/dev/null || echo "(no new lines)"
else
    echo "(no log file)"
fi

echo
echo "== done =="
