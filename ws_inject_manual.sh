#!/bin/bash
# ws_inject_manual.sh — build + (optionally) run the manual Mach-O loader injector.
#
# Unlike ws_inject.sh (dlopen path), this injector manually maps the payload
# bundle and applies its arm64e chained fixups, bypassing WindowServer's
# hardened-runtime library-validation flag (0x2000) that makes dlopen return NULL.
#
# The WindowServer test REQUIRES ROOT (WindowServer is uid 88). The Dock and any
# same-uid target can be injected without root.
#
# Usage:
#   ./ws_inject_manual.sh probe                          # task_for_pid only (SAFE)
#   ./ws_inject_manual.sh [payload] [pid]                # manual-map injection
#   sudo ./ws_inject_manual.sh [payload]                 # into WindowServer (default)

set -uo pipefail
cd "$(dirname "$0")"

PAYLOAD="${1:-/tmp/rdgpu-scanout-payload}"
LOG="${RDGPU_SCANOUT_LOG:-/tmp/rdgpu-scanout.log}"

echo "== ws_inject_manual.sh =="
echo "payload : $PAYLOAD"
echo "log     : $LOG"
echo "uid     : $(id -u) ($(id -un))"

echo
echo "== build ws_inject_manual (arm64e) =="
clang -arch arm64e ws_inject_manual.m inject_stub_manual.s -o ws_inject_manual || { echo "BUILD FAILED"; exit 1; }
codesign -f -s - --entitlements dock_inject.entitlements ws_inject_manual || { echo "CODESIGN FAILED"; exit 1; }
echo "build + codesign OK"

PRE_SIZE=0
[ -f "$LOG" ] && PRE_SIZE=$(wc -c < "$LOG" | tr -d ' ')

echo
echo "== run =="
if [ "${1:-}" = "probe" ]; then
    ./ws_inject_manual "$PAYLOAD" 99999
    RC=$?
else
    if [ -n "${2:-}" ]; then
        ./ws_inject_manual "$PAYLOAD" "$2"
    else
        ./ws_inject_manual "$PAYLOAD"
    fi
    RC=$?
fi
echo "inject exit code: $RC"

echo
echo "== $LOG (new since this run) =="
if [ -f "$LOG" ]; then
    tail -c +$((PRE_SIZE + 1)) "$LOG" 2>/dev/null | grep -E 'RDGPU_SCANOUT_(LOAD|SYM|DISPLAYLIST|CGXDEV|COREDISPLAY|BOOTSTRAP|SERVING|READY|PRESENT|FALLBACK)' || echo "(no new RDGPU_SCANOUT_* lines)"
else
    echo "(no log file)"
fi

echo
echo "== done =="
