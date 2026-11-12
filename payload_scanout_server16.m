// payload_scanout_server16.m — server14's CA-render-thread present TRAMPOLINE,
// extended to BOTH displays (two handoff slots, two patched SLCADisplays).
//
// server14 proved the trampoline+handoff shape on ONE display: the mach receive
// loop only updates a handoff slot and the CA render loop's present_iosurface
// vtable slot (0x5d0 from vptr, declkey 0x5a24, vptr discriminator 0xc333) is
// patched with a trampoline that substitutes the handoff surface. server16 keeps
// that exact, proven shape and turns every single-display global into a per-role
// array so the SECOND display is addressed instead of collapsed into one target:
//
//   * role 0 (primary / WAYLAND-1 / external) -> want_id0 = /tmp/rdgpu-scanout-display
//     (default 0x1e), handoff slot 0, patched SLCADisplay 0.
//   * role 1 (secondary / WAYLAND-2 / builtin) -> want_id1 = /tmp/rdgpu-scanout-display2
//     (default 0x27), handoff slot 1, patched SLCADisplay 1.
//
// The receive loop routes each rdgpu_present_msg_t by its display_index (0/1) to the
// matching handoff slot. The trampoline selects the slot by comparing `this` (the
// SLCADisplay object pointer) against the two pinned hw pointers:
//
//         int rd_tramp_present(void* this, __IOSurface* ca_io, bool ext) {
//             int idx = ((uint64_t)this == g_disp[1].hw) ? 1 : 0;
//             __IOSurface* h = g_disp[idx].handoff;          // latest frame (or NULL)
//             return g_real_present(this, h ? h : ca_io, ext);
//         }
//
// The trampoline is deliberately MINIMAL: two plain 64-bit loads + one compare, no
// locks, no atomics with barriers, no file I/O, no NSLog, no CFRetain/CFRelease. The
// handoff slots each own one CFRetain'd reference (the loop CFRetains on store and
// CFReleases the previous, at vblank cadence). When a slot is empty the trampoline
// forwards ca_io unchanged, so the CA's own empty-update present runs as-if unpatched.
//
// Both displays' flags[+0x76c] bit2 (0x4) are forced set (external-update path); both
// vtables, both handoff slots and both flag words are restored on exit. A display whose
// want_id is not present in the PKGDisplay chain is simply skipped (logged), never
// substituted with the other display, so a role-1 frame is dropped rather than misrouted.
//
// Build:
//   cd .../integration/rdmetal
//   clang -arch arm64e -O2 -bundle payload_scanout_server16.m \
//       -o /tmp/rdgpu-scanout-server16-payload \
//       -framework Foundation -framework IOSurface -framework CoreFoundation
//
// Root command (parent, one-line handoff). ws_inject_manual_d2 is the current injector
// build (has --register + idempotent zombie-reclaim, needed after a WindowServer relaunch
// leaves a dead com.rdgpu.scanout):
//   sudo ./ws_inject_manual_d2 --register /tmp/rdgpu-scanout-server16-payload
//
// Knobs: sync is inherent (the CA loop passes ext=true); drain/settle/throttle/replay
// are removed (the CA loop paces itself).

#import <Foundation/Foundation.h>
#import <IOSurface/IOSurface.h>
#import <CoreFoundation/CoreFoundation.h>

#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/message.h>
#include <dlfcn.h>
#include <pthread.h>
#include <signal.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <stdint.h>
#include <ptrauth.h>

#include "/Users/dperry/Documents/Codex/2026-11-07/task/hyprland-stage/metal-wayland-next/rdgpu-scanout-osax/rdgpu_protocol.h"

// ---------------------------------------------------------------------------
// Offsets from the SkyLight unslid image base == dladdr dli_fbase (skyBase).
#define OFF_sessionControlRef        (0x6305A580LL)  // __sessionControlRef data global
#define OFF_get_displayref_for_pkg   (0x002B9194LL)  // get_displayref_for_pkgdisplay_by_uuid
#define OFF_present_iosurface        (0x00411F1CLL)  // SLCADisplay::present_iosurface(__IOSurface*, bool)

// chain / PKGDisplay object layout (round-2/4 verified)
#define CH_sessionControlRef_to_p1   (0x20LL)
#define CH_p1_to_p2                  (0xd8LL)
#define CH_p2_to_sessionData         (0x298LL)
#define CH_sessionData_to_DisplaySet (0x00LL)
#define CH_DisplaySet_begin          (0x00LL)
#define CH_DisplaySet_end            (0x08LL)
#define CH_PKGDisplay_displayID      (0x28LL)
#define CH_PKGDisplay_uuid_lo        (0x2cLL)
#define CH_PKGDisplay_uuid_hi        (0x34LL)
#define CH_PKGDisplay_is_main        (0xa8LL)

// SLCADisplay (hardware display) object layout (round-3/4 verified)
#define CH_hw_displayID              (0xd8LL)
#define CH_hw_ca_display             (0x1d8LL)
#define CH_hw_swapped_surface        (0x2c8LL)
#define CH_hw_swapped_ctrl           (0x2d0LL)
#define CH_hw_scanout_wide           (0x634LL)
#define CH_hw_scanout_high           (0x638LL)
#define CH_hw_present_flags          (0x76cLL)

// ---------------------------------------------------------------------------
// VTABLE hook constants (round-8 live-verified; see server14 header for the full
// provenance — 0x5d0 from the ADDRESS POINT, not 0x5e0 from _ZTV).
#define CH_vtable_present_slot       (0x5d0LL)   // present_iosurface slot (byte offset from vptr)
#define DECLKEY_PRESENT_IOSURFACE    (0x5a24)    // siphash("_ZN...7Display17present_iosurfaceEP11__IOSurfaceb")
#define VPTR_DISCRIMINATOR           (0xc333)    // siphash("_ZTVN2WS8Displays7DisplayE")
#define VTABLE_TOTAL_SIZE            (0x850LL)   // _ZTVN...SLCADisplayE size (from _ZTV metadata)
#define VTABLE_HEADER                (0x10LL)    // offset-to-top + RTTI before the address point
#define RD_PAGE_SIZE                 (0x4000LL)  // 16 KiB
#define VTABLE_SIBLING_DELTA         (0x8a0LL)   // 2nd SLCADisplay vtable offset (subclass), if present

#define RD_MAX_DISPLAYS              (2)

// ---------------------------------------------------------------------------
// Logging (file + NSLog), thread-safe. NOT used by the trampoline (the trampoline
// runs on the CA render thread and must never take this lock or do file I/O).
static pthread_mutex_t g_logLock = PTHREAD_MUTEX_INITIALIZER;
static char g_logPath[1024] = "/tmp/rdgpu-scanout.log";

static void rlog(const char *fmt, ...) {
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    buf[sizeof buf - 1] = '\0';

    pthread_mutex_lock(&g_logLock);
    FILE *f = fopen(g_logPath, "a");
    if (!f) {
        char alt[1080];
        snprintf(alt, sizeof alt, "/tmp/rdgpu-scanout.uid%d.log", (int)getuid());
        f = fopen(alt, "a");
    }
    if (f) {
        time_t now = time(NULL);
        struct tm tm;
        localtime_r(&now, &tm);
        fprintf(f, "%04d-%02d-%02dT%02d:%02d:%02d [pid %d] %s\n",
                tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                tm.tm_hour, tm.tm_min, tm.tm_sec, (int)getpid(), buf);
        fflush(f);
        fclose(f);
    }
    pthread_mutex_unlock(&g_logLock);

    NSLog(@"[rdgpu-scanout] %s", buf);
}

// ---------------------------------------------------------------------------
// Fault guard for raw data derefs AND guarded function calls.
static sigjmp_buf            g_jmp;
static volatile sig_atomic_t g_guarded = 0;

static void rd_guard_handler(int sig, siginfo_t *si, void *ctx) {
    (void)sig; (void)si; (void)ctx;
    if (g_guarded) siglongjmp(g_jmp, 1);
    signal(sig, SIG_DFL);
    raise(sig);
}

#define RD_TRY(label, stmts) do {                                              \
    struct sigaction _o_segv, _o_bus, _o_ill, _o_abrt, _sa;                    \
    memset(&_sa, 0, sizeof _sa);                                               \
    _sa.sa_sigaction = rd_guard_handler;                                       \
    _sa.sa_flags = SA_SIGINFO;                                                 \
    sigaction(SIGSEGV, &_sa, &_o_segv);                                        \
    sigaction(SIGBUS,  &_sa, &_o_bus);                                         \
    sigaction(SIGILL,  &_sa, &_o_ill);                                         \
    sigaction(SIGABRT, &_sa, &_o_abrt);                                        \
    if (sigsetjmp(g_jmp, 1) == 0) {                                            \
        g_guarded = 1;                                                         \
        stmts;                                                                 \
        g_guarded = 0;                                                         \
    } else {                                                                   \
        g_guarded = 0;                                                         \
        rlog("RDGPU_SCANOUT_GUARD FAULT at %s", (label));                      \
    }                                                                          \
    sigaction(SIGSEGV, &_o_segv, NULL);                                        \
    sigaction(SIGBUS,  &_o_bus,  NULL);                                        \
    sigaction(SIGILL,  &_o_ill,  NULL);                                        \
    sigaction(SIGABRT, &_o_abrt, NULL);                                        \
} while (0)

// ---------------------------------------------------------------------------
// PAC primitives (always-inline so the 264-entry brute force stays fast).
static __attribute__((always_inline)) uint64_t rd_blend(uint64_t addr, uint64_t disc) {
    return (uint64_t)ptrauth_blend_discriminator((void*)addr, disc);
}
static __attribute__((always_inline)) uint64_t rd_sign_ia(uint64_t addr, uint64_t disc) {
    return (uint64_t)ptrauth_sign_unauthenticated((void*)addr, ptrauth_key_function_pointer, disc);
}
static __attribute__((always_inline)) uint64_t rd_sign_da(uint64_t addr, uint64_t disc) {
    return (uint64_t)ptrauth_sign_unauthenticated((void*)addr, ptrauth_key_process_independent_data, disc);
}
static __attribute__((always_inline)) uint64_t rd_strip_ia(uint64_t v) {
    return (uint64_t)ptrauth_strip((void*)v, ptrauth_key_function_pointer);
}
static __attribute__((always_inline)) uint64_t rd_strip_da(uint64_t v) {
    return (uint64_t)ptrauth_strip((void*)v, ptrauth_key_process_independent_data);
}
// PAC-sign a raw address as a plain (diversity-0) function pointer (plain bl-callable).
static __attribute__((always_inline)) void* rd_sign_fn(uint64_t addr) {
    return ptrauth_sign_unauthenticated((void*)addr, ptrauth_key_function_pointer, 0);
}

// present_iosurface(__IOSurface* io, bool ext) -> int (1 success / 0 failure)
typedef int (*fn_present_iosurface)(void*, IOSurfaceRef, bool);

// ---------------------------------------------------------------------------
// getPointerAuthStableSipHash (SipHash-2-4, 64-bit, key per LLVM SipHash.cpp),
// then (raw % 0xFFFF) + 1. Verified against the live declkeys 0x5a24/0x4cdc and
// vptr discriminator 0xc333.
static uint64_t rd_rotl64(uint64_t x, int b) { return (x << b) | (x >> (64 - b)); }

static void rd_sipround(uint64_t *v0, uint64_t *v1, uint64_t *v2, uint64_t *v3) {
    *v0 += *v1; *v1 = rd_rotl64(*v1, 13); *v1 ^= *v0; *v0 = rd_rotl64(*v0, 32);
    *v2 += *v3; *v3 = rd_rotl64(*v3, 16); *v3 ^= *v2; *v0 += *v3;
    *v3 = rd_rotl64(*v3, 21); *v3 ^= *v0; *v2 += *v1;
    *v1 = rd_rotl64(*v1, 17); *v1 ^= *v2; *v2 = rd_rotl64(*v2, 32);
}

static uint64_t rd_rdle64(const uint8_t *p) {
    uint64_t r = 0;
    for (int i = 0; i < 8; i++) r |= ((uint64_t)p[i]) << (8 * i);
    return r;
}

static uint64_t rd_siphash24(const uint8_t *in, size_t n, uint64_t k0, uint64_t k1) {
    uint64_t v0 = 0x736f6d6570736575ULL, v1 = 0x646f72616e646f6dULL;
    uint64_t v2 = 0x6c7967656e657261ULL, v3 = 0x7465646279746573ULL;
    v3 ^= k1; v2 ^= k0; v1 ^= k1; v0 ^= k0;
    size_t end = n - (n % 8);
    for (size_t i = 0; i < end; i += 8) {
        uint64_t m = rd_rdle64(in + i);
        v3 ^= m;
        for (int r = 0; r < 2; r++) rd_sipround(&v0, &v1, &v2, &v3);
        v0 ^= m;
    }
    uint64_t b = ((uint64_t)n) << 56;
    int left = (int)(n & 7);
    for (int j = 0; j < left; j++) b |= ((uint64_t)in[end + j]) << (8 * j);
    v3 ^= b;
    for (int r = 0; r < 2; r++) rd_sipround(&v0, &v1, &v2, &v3);
    v0 ^= b;
    v2 ^= 0xff;
    for (int r = 0; r < 4; r++) rd_sipround(&v0, &v1, &v2, &v3);
    return v0 ^ v1 ^ v2 ^ v3;
}

static uint16_t rd_siphash_disc(const char *s) {
    static const uint8_t K[16] = {0xb5,0xd4,0xc9,0xeb,0x79,0x10,0x4a,0x79,
                                  0x6f,0xec,0x8b,0x1b,0x42,0x87,0x81,0xd4};
    uint64_t k0 = rd_rdle64(K), k1 = rd_rdle64(K + 8);
    uint64_t raw = rd_siphash24((const uint8_t*)s, strlen(s), k0, k1);
    return (uint16_t)((raw % 0xFFFF) + 1);
}

// Replace the first "11SLCADisplay" in a mangled name with "7Display".
static int rd_subst_display(const char *name, char *out, size_t outsz) {
    static const char needle[] = "11SLCADisplay";
    const char *p = strstr(name, needle);
    if (!p) return 0;
    size_t pre = (size_t)(p - name);
    int n = snprintf(out, outsz, "%.*s7Display%s", (int)pre, name, p + sizeof(needle) - 1);
    if (n < 0 || (size_t)n >= outsz) return 0;
    return 1;
}

// ---------------------------------------------------------------------------
// Per-display server state. Each role owns one SLCADisplay (hw), one handoff slot,
// one vtable heap-copy patch and one flag-word save/restore. g_real_present is
// shared (it is the single SLCADisplay::present_iosurface at SkyLight+0x411F1C).
typedef struct {
    uint64_t            hw;
    uint64_t            ca_display;
    uint32_t            display_id;
    uint32_t            scanout_w;
    uint32_t            scanout_h;
    uint32_t            flags_orig;
    volatile int        flags_set;

    // vtable heap-copy patch state (restore = write orig_vptr back + free the copies).
    uint64_t            orig_vptr;
    uint64_t            heap_vtable;
    uint64_t            sibling_vtable;   // inert; kept for restore
    uint64_t            orig_slot;
    uint64_t            orig_signed_entry;
    volatile int        vtable_patched;

    // Handoff slot: the latest IOSurface for this display, published by the receive
    // loop. The slot owns one CFRetain'd reference; the trampoline borrows it and
    // never retains/releases (keeps the CA render thread lock-free and log-free).
    IOSurfaceRef volatile handoff;
    volatile uint64_t   frame;
} rd_display_t;

static rd_display_t g_disp[RD_MAX_DISPLAYS];
static volatile int g_disp_count = 0;

// The ORIGINAL SLCADisplay::present_iosurface (SkyLight+0x411F1C), diversity-0
// signed. Called ONLY by the trampoline, on the CA render thread.
static fn_present_iosurface g_real_present = NULL;

static int               g_sync_mode = 1;    // informational: CA loop always passes ext=true
static char g_service_name[128] = RDGPU_SERVICE_NAME;

// ---------------------------------------------------------------------------
// Restore flags[+0x76c] for one display.
static void rd_restore_display_flags(rd_display_t *d) {
    if (!d->hw || !d->flags_set) return;
    RD_TRY("restore_flags", {
        *(uint32_t*)(d->hw + CH_hw_present_flags) = d->flags_orig;
    });
    d->flags_set = 0;
    rlog("RDGPU_SCANOUT_RESTORE slot=%ld display=0x%x flags_restored -> 0x%x",
         (long)(d - g_disp), (unsigned)d->display_id, (unsigned)d->flags_orig);
}

// ---------------------------------------------------------------------------
// Restore one handoff slot: drop the retained reference, clear the pointer.
static void rd_restore_display_handoff(rd_display_t *d) {
    IOSurfaceRef h = d->handoff;
    d->handoff = NULL;
    if (h) {
        CFRelease(h);
        rlog("RDGPU_SCANOUT_RESTORE_HANDOFF slot=%ld display=0x%x released id=%u",
             (long)(d - g_disp), (unsigned)d->display_id, (unsigned)IOSurfaceGetID(h));
    }
}

// ---------------------------------------------------------------------------
// Recover the true 16-bit declkey for one vtable entry.
static uint64_t rd_recover_declkey(uint64_t raw, uint64_t old_slot, uint64_t entry) {
    uint16_t cands[8];
    int nc = 0;
    for (uint64_t d = 0; d <= 0xffff; d++) {
        if (rd_sign_ia(raw, rd_blend(old_slot, d)) == entry) {
            if (nc < 8) cands[nc] = (uint16_t)d;
            nc++;
        }
    }
    if (nc == 0) return 0;
    if (nc == 1) return cands[0];

    uint16_t h_self = 0, h_disp = 0;
    Dl_info di;
    memset(&di, 0, sizeof di);
    if (dladdr((void*)raw, &di) && di.dli_sname) {
        h_self = rd_siphash_disc(di.dli_sname);
        char sub[1024];
        if (rd_subst_display(di.dli_sname, sub, sizeof sub))
            h_disp = rd_siphash_disc(sub);
    }
    for (int i = 0; i < nc; i++) if (cands[i] == h_disp) return h_disp;
    for (int i = 0; i < nc; i++) if (cands[i] == h_self) return h_self;

    if (di.dli_sname)
        rlog("RDGPU_SCANOUT_VTABLE_AMBIG name=%s cands=%d first=0x%x (using first)",
             di.dli_sname, nc, cands[0]);
    return cands[0];
}

// ---------------------------------------------------------------------------
// THE TRAMPOLINE. Runs on the CA render thread (the CA render loop calls it via
// `blraa vtable[0x5d0](this, ca_io, ext)` every vblank). This must be:
//   * non-blocking (no locks, no file I/O, no NSLog, no swap_wait), and
//   * a pure forward: substitute the handoff surface for THIS display when we have
//     one, else forward ca_io unchanged so the CA's own empty-update present runs
//     as-if unpatched.
// It never retains/releases; the handoff slot's owned reference keeps the surface
// alive. `this` picks the slot: two plain loads + one compare.
__attribute__((noinline))
int rd_tramp_present(void* this, IOSurfaceRef ca_io, bool ext) {
    uint64_t t = (uint64_t)(uintptr_t)this;
    int idx = (t == g_disp[1].hw) ? 1 : 0;     // pinned before the vtable patch; never mutated
    IOSurfaceRef h = g_disp[idx].handoff;       // single aligned 64-bit load = atomic
    return g_real_present(this, h ? h : ca_io, ext);
}

// ---------------------------------------------------------------------------
// Probe whether `ztv` looks like a valid vtable (first code entry + the present slot
// entry are non-zero and strip to plausible code addresses). Used for the +0x8a0
// sibling detection only, so we never blindly memcpy/re-sign garbage.
static int rd_probe_vtable(uint64_t ztv) {
    uint64_t e0 = 0, ep = 0;
    RD_TRY("probe_vtable", {
        e0 = *(uint64_t*)(ztv + VTABLE_HEADER);
        ep = *(uint64_t*)(ztv + VTABLE_HEADER + CH_vtable_present_slot);
    });
    if (!e0 || !ep) return 0;
    uint64_t r0 = rd_strip_ia(e0);
    uint64_t rp = rd_strip_ia(ep);
    // live shared-cache code lives well above 0x100000000; reject zero/stack/garbage.
    if (r0 < 0x100000000ULL || r0 > 0x200000000ULL) return 0;
    if (rp < 0x100000000ULL || rp > 0x200000000ULL) return 0;
    return 1;
}

// ---------------------------------------------------------------------------
// Heap-copy `ztv`, re-sign every entry for its new heap address, then overwrite the
// present_iosurface slot with the trampoline (IA-signed with blend(heap_slot, declkey)).
// Returns the heap base (caller deallocates) or 0 on failure. Fills the slot bookkeeping
// for logging + audit (restore only needs to deallocate + rewrite the original vptr,
// because the shared-cache vtable is never written).
static uint64_t rd_heap_copy_vtable(uint64_t ztv, uint64_t tramp_raw,
                                    uint64_t *slot_out, uint64_t *orig_slot_out,
                                    uint64_t *orig_entry_out) {
    mach_vm_address_t heap = 0;
    kern_return_t kr = mach_vm_allocate(mach_task_self(), &heap, VTABLE_TOTAL_SIZE, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) { rlog("RDGPU_SCANOUT_VTABLE_ALLOC_FAIL ztv=0x%llx kr=%d", (unsigned long long)ztv, kr); return 0; }

    RD_TRY("copy_vtable", {
        memcpy((void*)heap, (void*)ztv, VTABLE_TOTAL_SIZE);
    });

    int nre = 0, nfail = 0;
    for (uint64_t off = VTABLE_HEADER; off < VTABLE_TOTAL_SIZE; off += 8) {
        uint64_t old_slot = ztv + off;
        uint64_t new_slot = heap + off;
        uint64_t entry = *(uint64_t*)(heap + off);
        if (entry == 0) continue;
        uint64_t raw = rd_strip_ia(entry);
        uint64_t declkey = rd_recover_declkey(raw, old_slot, entry);
        if (declkey == 0) { nfail++; rlog("RDGPU_SCANOUT_VTABLE_RESIGN_FAIL off=0x%llx", (unsigned long long)off); continue; }
        *(uint64_t*)(heap + off) = rd_sign_ia(raw, rd_blend(new_slot, declkey));
        nre++;
    }
    if (nfail) {
        mach_vm_deallocate(mach_task_self(), heap, VTABLE_TOTAL_SIZE);
        rlog("RDGPU_SCANOUT_VTABLE_RESIGN_ABORT fail=%d", nfail);
        return 0;
    }

    uint64_t slot = heap + VTABLE_HEADER + CH_vtable_present_slot;
    uint64_t orig_slot = ztv + VTABLE_HEADER + CH_vtable_present_slot;
    uint64_t orig_entry = *(uint64_t*)(ztv + VTABLE_HEADER + CH_vtable_present_slot);
    uint64_t signed_tramp = rd_sign_ia(tramp_raw, rd_blend(slot, DECLKEY_PRESENT_IOSURFACE));
    *(uint64_t*)(heap + VTABLE_HEADER + CH_vtable_present_slot) = signed_tramp;

    if (slot_out)       *slot_out       = slot;
    if (orig_slot_out)  *orig_slot_out  = orig_slot;
    if (orig_entry_out) *orig_entry_out = orig_entry;
    rlog("RDGPU_SCANOUT_VTABLE_RESIGN ztv=0x%llx heap=0x%llx re=%d "
         "present_slot=0x%llx orig_slot=0x%llx orig_entry=0x%llx "
         "tramp_raw=0x%llx signed_tramp=0x%llx declkey=0x%x",
         (unsigned long long)ztv, (unsigned long long)heap, nre,
         (unsigned long long)slot, (unsigned long long)orig_slot,
         (unsigned long long)orig_entry, (unsigned long long)tramp_raw,
         (unsigned long long)signed_tramp, DECLKEY_PRESENT_IOSURFACE);
    return heap;
}

// ---------------------------------------------------------------------------
// Patch the present_iosurface vtable slot for ONE display with the trampoline.
// Heap-copy + re-sign (round-9 machinery) the object's OWN vtable and rewrite the
// object's vptr, then (defensively) heap-copy + patch the sibling vtable at +0x8a0
// if one exists.
static int rd_patch_vtable_present(rd_display_t *d, uint64_t skyBase) {
    (void)skyBase;
    uint64_t hw = d->hw;

    uint64_t vptr = 0;
    RD_TRY("read_vptr", { vptr = *(uint64_t*)hw; });
    if (!vptr) { rlog("RDGPU_SCANOUT_VTABLE_NOVPTR slot=%ld hw=%p", (long)(d - g_disp), (void*)hw); return -1; }
    uint64_t ap = rd_strip_da(vptr);
    uint64_t ztv = ap - VTABLE_HEADER;
    rlog("RDGPU_SCANOUT_VTABLE_READ slot=%ld hw=%p vptr=0x%llx ap=0x%llx ztv=0x%llx",
         (long)(d - g_disp), (void*)hw, (unsigned long long)vptr,
         (unsigned long long)ap, (unsigned long long)ztv);

    uint64_t tramp_raw = rd_strip_ia((uint64_t)(uintptr_t)&rd_tramp_present);

    // (1) operative patch: the vtable THIS object points to.
    uint64_t slot = 0, orig_slot = 0, orig_entry = 0;
    uint64_t heap = rd_heap_copy_vtable(ztv, tramp_raw, &slot, &orig_slot, &orig_entry);
    if (!heap) { rlog("RDGPU_SCANOUT_VTABLE_PATCH_FAIL slot=%ld hw=%p", (long)(d - g_disp), (void*)hw); return -2; }

    uint64_t new_ap = heap + VTABLE_HEADER;
    uint64_t new_vptr = rd_sign_da(new_ap, rd_blend(hw, VPTR_DISCRIMINATOR));
    RD_TRY("write_vptr", {
        *(uint64_t*)hw = new_vptr;
    });

    d->orig_vptr          = vptr;
    d->heap_vtable        = heap;
    d->orig_slot          = orig_slot;
    d->orig_signed_entry  = orig_entry;
    d->vtable_patched     = 1;
    rlog("RDGPU_SCANOUT_VTABLE_PATCHED slot=%ld display=0x%x heap=0x%llx new_ap=0x%llx "
         "new_vptr=0x%llx orig_vptr=0x%llx orig_slot=0x%llx orig_entry=0x%llx "
         "tramp_raw=0x%llx declkey=0x%x vptr_disc=0x%x",
         (long)(d - g_disp), (unsigned)d->display_id, (unsigned long long)heap,
         (unsigned long long)new_ap, (unsigned long long)new_vptr,
         (unsigned long long)vptr, (unsigned long long)orig_slot,
         (unsigned long long)orig_entry, (unsigned long long)tramp_raw,
         DECLKEY_PRESENT_IOSURFACE, VPTR_DISCRIMINATOR);

    // (2) sibling vtable at +0x8a0, if present. Inert (no object vptr is rewritten to
    // it here), but it covers the case where the object actually pointed at the sibling
    // instead; detection is logged.
    uint64_t sibling_ztv = ztv + VTABLE_SIBLING_DELTA;
    if (rd_probe_vtable(sibling_ztv)) {
        uint64_t s_slot = 0, s_orig_slot = 0, s_orig_entry = 0;
        uint64_t s_heap = rd_heap_copy_vtable(sibling_ztv, tramp_raw, &s_slot, &s_orig_slot, &s_orig_entry);
        if (s_heap) {
            d->sibling_vtable = s_heap;
            rlog("RDGPU_SCANOUT_VTABLE_SIBLING_PATCHED slot=%ld ztv=0x%llx heap=0x%llx "
                 "slot=0x%llx orig_slot=0x%llx orig_entry=0x%llx (inert: kept for restore)",
                 (long)(d - g_disp), (unsigned long long)sibling_ztv, (unsigned long long)s_heap,
                 (unsigned long long)s_slot, (unsigned long long)s_orig_slot,
                 (unsigned long long)s_orig_entry);
        }
    } else {
        rlog("RDGPU_SCANOUT_VTABLE_SIBLING_ABSENT slot=%ld ztv=0x%llx (no vtable at +0x8a0)",
             (long)(d - g_disp), (unsigned long long)sibling_ztv);
    }
    return 0;
}

// Restore the original DA-signed vptr and free the heap copies for one display. The
// shared-cache vtable was never written, so restoring the vptr is all that is needed.
static void rd_restore_display_vtable(rd_display_t *d) {
    if (d->vtable_patched && d->hw && d->orig_vptr) {
        RD_TRY("restore_vptr", {
            *(uint64_t*)d->hw = d->orig_vptr;
        });
    }
    if (d->heap_vtable)    mach_vm_deallocate(mach_task_self(), d->heap_vtable, VTABLE_TOTAL_SIZE);
    if (d->sibling_vtable) mach_vm_deallocate(mach_task_self(), d->sibling_vtable, VTABLE_TOTAL_SIZE);
    d->heap_vtable    = 0;
    d->sibling_vtable = 0;
    d->vtable_patched = 0;
    rlog("RDGPU_SCANOUT_VTABLE_RESTORED slot=%ld vptr=0x%llx",
         (long)(d - g_disp), (unsigned long long)d->orig_vptr);
}

static void rd_restore_all(void) {
    for (int i = 0; i < RD_MAX_DISPLAYS; i++) {
        rd_restore_display_flags(&g_disp[i]);
        rd_restore_display_vtable(&g_disp[i]);
        rd_restore_display_handoff(&g_disp[i]);
    }
}

// ---------------------------------------------------------------------------
// Handle one received present request: JUST update the matching handoff slot and reply
// immediately. No present_iosurface, no drain, no settle, no throttle — the CA render
// loop presents the handoff surface at its own vblank cadence. Routes by display_index
// (0 = primary, 1 = secondary); a frame for an unmapped role is dropped, never misrouted.
static void rd_handle_present(const rdgpu_present_msg_t* msg) {
    IOSurfaceRef io = NULL;

    if (msg->body.msgh_descriptor_count >= 1 &&
        msg->surface_port.type == MACH_MSG_PORT_DESCRIPTOR) {
        mach_port_name_t sp = msg->surface_port.name;
        io = IOSurfaceLookupFromMachPort(sp);
        if (sp != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), sp);
    } else if (msg->surface_id != 0) {
        io = IOSurfaceLookup(msg->surface_id);
    }

    int slot = (msg->display_index == RDGPU_SCANOUT_ROLE_SECONDARY) ? 1 : 0;
    if (slot >= RD_MAX_DISPLAYS) slot = 0;

    int rc = 0;   // 0 == handed off
    if (!io) {
        rlog("RDGPU_SCANOUT_HANDOFF_SKIP slot=%d reason=no_surface", slot);
        rc = -1;
    } else if (!g_disp[slot].hw || !g_real_present) {
        rlog("RDGPU_SCANOUT_HANDOFF_SKIP slot=%d reason=%s (role not mapped — dropped, not misrouted)",
             slot, g_disp[slot].hw ? "no_present_sym" : "no_display");
        CFRelease(io);
        rc = -1;
    } else {
        rd_display_t *d = &g_disp[slot];

        // keep flags[+0x76c] bit2 (0x4) set — external-update path (idempotent).
        RD_TRY("reassert_flags", {
            *(uint32_t*)(d->hw + CH_hw_present_flags) = d->flags_orig | 0x4u;
        });

        uint32_t sid = (uint32_t)IOSurfaceGetID(io);

        // Publish: CFRetain(new) for the slot, store, CFRelease(previous).
        IOSurfaceRef old = d->handoff;
        CFRetain(io);
        d->handoff = io;
        if (old) CFRelease(old);

        // release our lookup reference — the slot now owns its +1.
        CFRelease(io);

        d->frame++;
        rlog("RDGPU_SCANOUT_HANDOFF slot=%d display=0x%x frame=%llu id=%u (%zux%zu) -> CA render loop",
             slot, (unsigned)d->display_id, (unsigned long long)d->frame, (unsigned)sid,
             IOSurfaceGetWidth((IOSurfaceRef)d->handoff),
             IOSurfaceGetHeight((IOSurfaceRef)d->handoff));
    }

    if (msg->header.msgh_remote_port != MACH_PORT_NULL) {
        rdgpu_reply_t reply;
        memset(&reply, 0, sizeof reply);
        reply.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
        reply.header.msgh_remote_port = msg->header.msgh_remote_port;
        reply.header.msgh_local_port = MACH_PORT_NULL;
        reply.header.msgh_id = msg->header.msgh_id + 1;
        reply.result = (rc == 0) ? 0 : rc;   // 0 == handed off; -1 == no surface / unmapped role
        mach_msg(&reply.header, MACH_SEND_MSG, sizeof reply, 0,
                 MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    }
}

// ---------------------------------------------------------------------------
// Receive loop (detached thread).
static void* rd_server_thread(void* arg) {
    mach_port_t recv = (mach_port_t)(intptr_t)arg;
    rlog("RDGPU_SCANOUT_SERVER_START port=%u displays=%d", recv, (int)g_disp_count);
    for (;;) {
        union {
            rdgpu_present_msg_t msg;
            uint64_t            align;
            uint8_t             raw[4096];
        } u;
        memset(&u, 0, sizeof u);
        kern_return_t kr = mach_msg(&u.msg.header, MACH_RCV_MSG, 0, sizeof u.raw,
                                    recv, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
        if (kr != KERN_SUCCESS) {
            rlog("RDGPU_SCANOUT_RECV_FAIL kr=%d", kr);
            if (kr == MACH_RCV_INVALID_NAME || kr == MACH_RCV_PORT_DIED) {
                rd_restore_all();
                break;
            }
            continue;
        }
        rd_handle_present(&u.msg);
        int any_flags = 0;
        for (int i = 0; i < RD_MAX_DISPLAYS; i++) if (g_disp[i].flags_set) any_flags = 1;
        if (!any_flags) { rlog("RDGPU_SCANOUT_SERVER_STOP (flags restored)"); break; }
    }
    rd_restore_all();
    rlog("RDGPU_SCANOUT_SERVER_STOP");
    return NULL;
}

// ---------------------------------------------------------------------------
// Read one want_id (role 0 -> /tmp/rdgpu-scanout-display, role 1 -> /tmp/rdgpu-scanout-display2).
static uint32_t rd_read_want_id(int role, uint32_t def) {
    const char *envname = (role == 0) ? "RDGPU_SCANOUT_DISPLAY" : "RDGPU_SCANOUT_DISPLAY2";
    const char *path    = (role == 0) ? "/tmp/rdgpu-scanout-display" : "/tmp/rdgpu-scanout-display2";
    const char *e = getenv(envname);
    if (e && e[0]) return (uint32_t)strtoul(e, NULL, 0);
    FILE *f = fopen(path, "r");
    if (f) {
        char line[64] = {0};
        if (fgets(line, sizeof line, f) && line[0]) {
            uint32_t v = (uint32_t)strtoul(line, NULL, 0);
            fclose(f);
            return v;
        }
        fclose(f);
    }
    return def;
}

// ---------------------------------------------------------------------------
__attribute__((constructor))
static void rdgpu_scanout_constructor(uint64_t injected_recv_port) {
    @autoreleasepool {
        const char *env = getenv("RDGPU_SCANOUT_LOG");
        if (env && env[0]) strlcpy(g_logPath, env, sizeof g_logPath);

        // informational sync knob (the CA loop always passes ext=true; this is inert).
        {
            FILE *fs = fopen("/tmp/rdgpu-scanout-sync", "r");
            if (fs) {
                char line[64] = {0};
                if (fgets(line, sizeof line, fs) && line[0])
                    g_sync_mode = (strtol(line, NULL, 0) != 0) ? 1 : 0;
                fclose(fs);
            }
        }

        uint32_t want_id[RD_MAX_DISPLAYS];
        want_id[0] = rd_read_want_id(0, 0x1e);   // primary   = external WAYLAND-1
        want_id[1] = rd_read_want_id(1, 0x27);   // secondary = builtin  WAYLAND-2

        {
            FILE *fn = fopen("/tmp/rdgpu-scanout.name", "r");
            if (fn) {
                char line[128] = {0};
                if (fgets(line, sizeof line, fn) && line[0]) {
                    line[strcspn(line, "\n")] = 0;
                    strlcpy(g_service_name, line, sizeof g_service_name);
                }
                fclose(fn);
            }
        }

        rlog("RDGPU_SCANOUT_LOAD pid=%d mode=server16 want_id0=0x%x want_id1=0x%x sync=%d "
             "(dual-display trampoline+handoff; drain/settle/throttle/replay removed)",
             (int)getpid(), (unsigned)want_id[0], (unsigned)want_id[1], g_sync_mode);

        void *gSkyLight = dlopen("/System/Library/PrivateFrameworks/SkyLight.framework/SkyLight",
                                 RTLD_LAZY | RTLD_LOCAL);
        rlog("RDGPU_SCANOUT_DLOPEN SkyLight=%p", gSkyLight);

        void *sym_sls_main = dlsym(RTLD_DEFAULT, "SLSMainDisplayID");
        uint64_t skyBase = 0;
        {
            Dl_info info;
            if (sym_sls_main && dladdr(sym_sls_main, &info)) skyBase = (uint64_t)info.dli_fbase;
        }
        rlog("RDGPU_SCANOUT_BASE skyBase=%p", (void*)skyBase);
        if (!skyBase) {
            rlog("RDGPU_SCANOUT_NOSKYBASE");
            rlog("RDGPU_SCANOUT_DONE result=no-skybase");
            return;
        }

        typedef void (*fn_get_displayref)(void*, void*);
        fn_get_displayref getref = (fn_get_displayref)rd_sign_fn(skyBase + OFF_get_displayref_for_pkg);
        g_real_present = (fn_present_iosurface)rd_sign_fn(skyBase + OFF_present_iosurface);

        uint64_t a_ref = skyBase + OFF_sessionControlRef;
        uint64_t ref = 0, p1 = 0, p2 = 0, sess = 0, dset = 0, begin = 0, end = 0;
        RD_TRY("walk_skylight_chain", {
            ref   = *(uint64_t*)a_ref;
            if (ref) p1 = *(uint64_t*)(ref + CH_sessionControlRef_to_p1);
            if (p1)  p2 = *(uint64_t*)(p1 + CH_p1_to_p2);
            if (p2)  sess = *(uint64_t*)(p2 + CH_p2_to_sessionData);
            if (sess) dset = *(uint64_t*)(sess + CH_sessionData_to_DisplaySet);
            if (dset) { begin = *(uint64_t*)(dset + CH_DisplaySet_begin);
                        end   = *(uint64_t*)(dset + CH_DisplaySet_end); }
        });
        rlog("RDGPU_SCANOUT_SKYCHEIN ref=%p p1=%p p2=%p sess=%p dset=%p begin=%p end=%p",
             (void*)ref, (void*)p1, (void*)p2, (void*)sess, (void*)dset, (void*)begin, (void*)end);

        int mapped = 0;
        if (dset && begin && end && end > begin && (end - begin) < 0x100000) {
            for (uint64_t p = begin; p < end; p += 8) {
                uint64_t pkg = 0;
                uint32_t dispID = 0;
                RD_TRY("walk_pkg_display", {
                    pkg = *(uint64_t*)p;
                    if (pkg) dispID = *(uint32_t*)(pkg + CH_PKGDisplay_displayID);
                });
                if (!pkg) break;

                int slot = -1;
                if (dispID == want_id[0]) slot = 0;
                else if (dispID == want_id[1]) slot = 1;
                if (slot < 0) continue;
                if (g_disp[slot].hw) continue;   // already mapped (dedupe / want_id0==want_id1)

                uint64_t refbuf[2] = {0, 0};
                RD_TRY("call_get_displayref", {
                    if (getref) getref(refbuf, (void*)pkg);
                });
                uint64_t hw = refbuf[0];
                if (!hw) { rlog("RDGPU_SCANOUT_DISPLAY slot=%d display 0x%x: displayref NULL", slot, (unsigned)dispID); continue; }

                uint32_t hid = 0, sw = 0, sh = 0, fl = 0;
                uint64_t ca = 0;
                RD_TRY("read_hw_fields", {
                    hid = *(uint32_t*)(hw + CH_hw_displayID);
                    ca  = *(uint64_t*)(hw + CH_hw_ca_display);
                    sw  = *(uint32_t*)(hw + CH_hw_scanout_wide);
                    sh  = *(uint32_t*)(hw + CH_hw_scanout_high);
                    fl  = *(uint32_t*)(hw + CH_hw_present_flags);
                });
                rlog("RDGPU_SCANOUT_DISPLAY slot=%d display=0x%x hw=%p cadisplay=%p scanout=%ux%u flags=0x%x",
                     slot, (unsigned)hid, (void*)hw, (void*)ca, (unsigned)sw, (unsigned)sh, (unsigned)fl);

                if (!ca) { rlog("RDGPU_SCANOUT_DISPLAY slot=%d 0x%x: cadisplay NULL (skipping)", slot, (unsigned)hid); continue; }

                rd_display_t *d = &g_disp[slot];
                d->hw = hw; d->ca_display = ca; d->display_id = hid;
                d->scanout_w = sw; d->scanout_h = sh; d->flags_orig = fl;
                g_disp_count++;
                mapped++;
            }
        }

        if (!mapped) {
            rlog("RDGPU_SCANOUT_DONE result=no-display want_id0=0x%x want_id1=0x%x",
                 (unsigned)want_id[0], (unsigned)want_id[1]);
            return;
        }

        mach_port_t recv = (mach_port_t)injected_recv_port;
        if (recv == MACH_PORT_NULL) {
            rlog("RDGPU_SCANOUT_DONE result=no-port (injector did not register/hand a receive right)");
            rd_restore_all();
            return;
        }
        rlog("RDGPU_SCANOUT_RECV port=%u (injected by root injector)", recv);

        // Publish g_real_present + the pinned g_disp[].hw pointers to the CA render
        // thread BEFORE the vtable patches make the trampoline reachable (release
        // barrier pairs with the CA loop's vptr read -> trampoline -> g_disp[].hw /
        // g_real_present loads; a vblank is ~16.7ms so this is belt-and-braces, but the
        // stores must not be reordered past the vptr writes below).
        __sync_synchronize();

        // Patch the present_iosurface vtable slot on BOTH mapped displays, then set the
        // external-update flag on both, before serving.
        for (int i = 0; i < RD_MAX_DISPLAYS; i++) {
            if (!g_disp[i].hw) continue;
            int vpatch = rd_patch_vtable_present(&g_disp[i], skyBase);
            rlog("RDGPU_SCANOUT_VTABLE_PATCH_RESULT slot=%d display=0x%x rc=%d patched=%d",
                 i, (unsigned)g_disp[i].display_id, vpatch, (int)g_disp[i].vtable_patched);
        }
        for (int i = 0; i < RD_MAX_DISPLAYS; i++) {
            if (!g_disp[i].hw) continue;
            RD_TRY("set_external_update_flag", {
                *(uint32_t*)(g_disp[i].hw + CH_hw_present_flags) = g_disp[i].flags_orig | 0x4u;
            });
            g_disp[i].flags_set = 1;
            rlog("RDGPU_SCANOUT_FLAGS slot=%d display=0x%x 0x%x -> 0x%x (external-update path)",
                 i, (unsigned)g_disp[i].display_id, (unsigned)g_disp[i].flags_orig,
                 (unsigned)(g_disp[i].flags_orig | 0x4u));
        }

        pthread_t t;
        if (pthread_create(&t, NULL, rd_server_thread, (void*)(intptr_t)recv) == 0) {
            pthread_detach(t);
            rlog("RDGPU_SCANOUT_SERVING name=%s port=%u displays=%d slots=%d/%d tramp=0x%llx",
                 g_service_name, recv, (int)g_disp_count,
                 g_disp[0].hw ? 1 : 0, g_disp[1].hw ? 1 : 0,
                 (unsigned long long)rd_strip_ia((uint64_t)(uintptr_t)&rd_tramp_present));
        } else {
            rlog("RDGPU_SCANOUT_THREAD_FAIL (restoring flags + vtable + handoff)");
            rd_restore_all();
        }

        rlog("RDGPU_SCANOUT_DONE result=serving");
    }
}
