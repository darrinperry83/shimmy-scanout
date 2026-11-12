// payload_scanout_server15.m — server14 + LOCK-FREE TRAMPOLINE INSTRUMENTATION.
// server14 is the CA-render-thread present TRAMPOLINE (no more injected-thread
// present_iosurface). server13 (and every earlier server) called
// present_iosurface directly from OUR injected server thread; that trips the
// CompositorMetal `scanout_iosurface != nullptr` / `src_texture != nil && dst_texture
// != nil` asserts because that Metal context is only valid on the CA render thread.
//
// server15 ADDS crash-safe diagnostics to answer: (a) is the trampoline called at
// all by the external display's CA render loop, and (b) what does the real
// present_iosurface return on that thread? The trampoline now bumps three volatile
// counters (g_tramp_calls / g_tramp_ret1 / g_tramp_ret0) and records the last
// ext/ca_io/handoff/flags values, using ONLY plain 64-bit loads/stores (no lock,
// no atomics with barriers, no printf, no CF). The mach receive loop (our own
// thread, safe to rlog) logs them as `RDGPU_SCANOUT_TRAMP ...` once per handoff.
//
// server14 stops calling present_iosurface from the injected thread entirely. Instead:
//
//   * The mach receive loop only UPDATES A HANDOFF SLOT (one IOSurface pointer) and
//     replies immediately. It never presents, never drains, never settles, never
//     throttles — the CA render loop is the only caller of present_iosurface, at its
//     own vblank cadence.
//
//   * The present_iosurface vtable slot (0x5d0 from the address point / 0x5e0 from
//     _ZTV — see round-8, live-verified) is patched with a TRAMPOLINE:
//
//         int rd_tramp_present(void* this, __IOSurface* ca_io, bool ext) {
//             __IOSurface* h = g_handoff;                 // latest Hyprland frame (or NULL)
//             return g_real_present(this, h ? h : ca_io, ext);   // forward + substitute
//         }
//
//     where g_real_present is the ORIGINAL SLCADisplay::present_iosurface
//     (SkyLight+0x411F1C, PAC-signed by raw address = diversity 0). The CA render loop
//     (present_empty_update, SkyLight+0x410830) does `blraa vtable[0x5d0](this)` every
//     vblank; it now lands in our trampoline on the CA render thread, where the
//     CompositorMetal context is valid, and the trampoline forwards to the real
//     present_iosurface with our Hyprland surface substituted for the CA's own surface.
//
//   * When the handoff slot is empty, the trampoline forwards ca_io unchanged, so the
//     CA's normal empty-update present keeps running exactly as if unpatched (this is
//     the round-9 "stub halted it" concern resolved: no `ret` stub, always forward).
//
// The trampoline is deliberately MINIMAL: no logging (no locks/file I/O/NSLog on the
// CA render thread), no CFRetain/CFRelease, no swap_wait. The handoff slot owns one
// CFRetain'd reference (the loop CFRetains the new surface and CFReleases the previous),
// which keeps the current surface alive across the vblank present. The CA loop paces
// itself, so the injected thread's drain/settle/throttle machinery is REMOVED.
//
// flags[+0x76c] bit2 (0x4) is still forced set (external-update path) and restored on
// exit; the vtable + handoff are also restored on exit.
//
// Build:
//   cd .../integration/rdmetal
//   clang -arch arm64e -O2 -bundle payload_scanout_server15.m \
//       -o /tmp/rdgpu-scanout-server15-payload \
//       -framework Foundation -framework IOSurface -framework CoreFoundation
//
// Root command (parent, one-line handoff). ws_inject_manual_d2 is the current
// injector build (has --register + idempotent zombie-reclaim, needed after a
// WindowServer relaunch leaves a dead com.rdgpu.scanout):
//   sudo ./ws_inject_manual_d2 --register /tmp/rdgpu-scanout-server15-payload
//   sudo grep -E 'RDGPU_SCANOUT_(TRAMP|DISPLAY|FLAGS|VTABLE_PATCH_RESULT)' \
//       /tmp/rdgpu-scanout.log | tail -120
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
// VTABLE hook constants. The present_iosurface slot is byte offset 0x5d0 from the
// ADDRESS POINT (the stripped vptr = _ZTV+0x10), i.e. 0x5e0 from _ZTV — round-8
// read this live off present_empty_update's call site:
//     mov x17,#0x5d0; add x16,x16,x17; ldr x8,[x16]; movk x16,#0x5a24,lsl#48; blraa x8,x16
// and reproduced the live entry sign(0x188b02f1c, IA, blend(0x1efe1a720, 0x5a24)).
// (The "0x6a0 from _ZTV" figure in the task/DESIGN.md is an unslid __AUTH_CONST decode
// that does not match the live object's vptr; 0x5d0-from-vptr is the live-verified slot.)
#define CH_vtable_present_slot       (0x5d0LL)   // present_iosurface slot (byte offset from vptr)
#define DECLKEY_PRESENT_IOSURFACE    (0x5a24)    // siphash("_ZN...7Display17present_iosurfaceEP11__IOSurfaceb")
#define VPTR_DISCRIMINATOR           (0xc333)    // siphash("_ZTVN2WS8Displays7DisplayE")
#define VTABLE_TOTAL_SIZE            (0x850LL)   // _ZTVN...SLCADisplayE size (from _ZTV metadata)
#define VTABLE_HEADER                (0x10LL)    // offset-to-top + RTTI before the address point
#define RD_PAGE_SIZE                 (0x4000LL)  // 16 KiB
#define VTABLE_SIBLING_DELTA         (0x8a0LL)   // 2nd SLCADisplay vtable offset (subclass), if present

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
// Server state.
static uint64_t       g_hw         = 0;
static uint64_t       g_ca_display = 0;
static uint32_t       g_display_id = 0;
static uint32_t       g_scanout_w  = 0;
static uint32_t       g_scanout_h  = 0;
static uint32_t       g_flags_orig = 0;
static volatile int   g_flags_set  = 0;

// The ORIGINAL SLCADisplay::present_iosurface (SkyLight+0x411F1C), diversity-0
// signed. Called ONLY by the trampoline, on the CA render thread.
static fn_present_iosurface g_real_present = NULL;

// Handoff slot: the latest Hyprland IOSurface published by the mach receive loop.
// The slot owns one CFRetain'd reference (the loop CFRetains the new surface on
// store and CFReleases the previous). The trampoline borrows it; it never retains
// or releases (keeps the CA render thread lock-free and log-free).
static IOSurfaceRef volatile g_handoff = NULL;

static volatile uint64_t g_frame = 0;
static int               g_sync_mode = 1;    // informational: CA loop always passes ext=true

// ---------------------------------------------------------------------------
// Trampoline instrumentation (server15). Written ONLY by the CA render thread
// (the trampoline) with PLAIN 64-bit loads/stores — no locks, no atomics, no
// printf, no CF — so the render loop is undisturbed. Read by the mach receive
// loop (our own thread) for logging. Single writer => no lost counts; a reader
// may observe a value one increment behind, which is fine for diagnosis.
static volatile uint64_t g_tramp_calls        = 0;   // trampoline entries
static volatile uint64_t g_tramp_ret1         = 0;   // real present_iosurface returned nonzero
static volatile uint64_t g_tramp_ret0         = 0;   // real present_iosurface returned 0
static volatile int32_t  g_tramp_last_ret     = -1;  // last return value
static volatile uint64_t g_tramp_last_ca_io   = 0;   // last ca_io arg (raw pointer)
static volatile uint64_t g_tramp_last_handoff = 0;   // last handoff value (0 == empty)
static volatile uint32_t g_tramp_last_ext     = 0;   // last ext flag (0/1)
static volatile uint32_t g_tramp_last_flags   = 0;   // flags[+0x76c] read at present time

// vtable heap-copy patch state. Restore = write g_orig_vptr back + free the copies.
// The shared-cache vtable itself is NEVER modified (heap-copy + vptr rewrite only).
static uint64_t       g_orig_vptr        = 0;
static uint64_t       g_heap_vtable      = 0;
static uint64_t       g_sibling_vtable   = 0;   // 2nd SLCADisplay vtable (+0x8a0), inert
static uint64_t       g_orig_slot        = 0;
static uint64_t       g_orig_signed_entry= 0;
static volatile int   g_vtable_patched   = 0;

static char g_service_name[128] = RDGPU_SERVICE_NAME;

// ---------------------------------------------------------------------------
// Restore flags[+0x76c].
static void rd_restore_flags(void) {
    if (!g_hw || !g_flags_set) return;
    RD_TRY("restore_flags", {
        *(uint32_t*)(g_hw + CH_hw_present_flags) = g_flags_orig;
    });
    g_flags_set = 0;
    rlog("RDGPU_SCANOUT_RESTORE display=0x%x flags_restored -> 0x%x",
         (unsigned)g_display_id, (unsigned)g_flags_orig);
}

// ---------------------------------------------------------------------------
// Restore the handoff slot: drop the retained reference, clear the pointer.
static void rd_restore_handoff(void) {
    IOSurfaceRef h = g_handoff;
    g_handoff = NULL;
    if (h) {
        CFRelease(h);
        rlog("RDGPU_SCANOUT_RESTORE_HANDOFF released id=%u", (unsigned)IOSurfaceGetID(h));
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
//   * a pure forward: substitute the handoff surface when we have one, else forward
//     ca_io unchanged so the CA's own empty-update present runs as-if unpatched.
// It never retains/releases; the handoff slot's owned reference keeps the surface
// alive (the loop CFRetains on store / CFReleases the previous, at vblank cadence).
__attribute__((noinline))
int rd_tramp_present(void* this, IOSurfaceRef ca_io, bool ext) {
    IOSurfaceRef h = g_handoff;                 // single aligned 64-bit load = atomic
    IOSurfaceRef out = h ? h : ca_io;

    // server15 instrumentation — PLAIN 64-bit loads/stores only (no lock/printf/CF).
    // Single writer = this CA render thread; the mach loop only reads these later.
    g_tramp_calls++;                                   // load / add / store, no barrier
    g_tramp_last_ca_io   = (uint64_t)(uintptr_t)ca_io;
    g_tramp_last_handoff = (uint64_t)(uintptr_t)h;
    g_tramp_last_ext     = ext ? 1u : 0u;
    g_tramp_last_flags   = *(volatile uint32_t*)((uint64_t)this + CH_hw_present_flags);

    int r = g_real_present(this, out, ext);

    if (r) g_tramp_ret1++; else g_tramp_ret0++;
    g_tramp_last_ret = r;
    return r;
}

// ---------------------------------------------------------------------------
// Log the trampoline's counters + last-call capture. Called from the mach receive
// loop (our thread) only — never from the trampoline. `tag` marks the point.
static void rd_log_tramp_state(const char *tag) {
    rlog("RDGPU_SCANOUT_TRAMP %s display=0x%x scanout=%ux%u calls=%llu ret1=%llu "
         "ret0=%llu last_ret=%d last_ext=%u last_ca_io=0x%llx last_handoff=0x%llx "
         "last_flags=0x%x (bit2=%u)",
         tag, (unsigned)g_display_id, (unsigned)g_scanout_w, (unsigned)g_scanout_h,
         (unsigned long long)g_tramp_calls,
         (unsigned long long)g_tramp_ret1,
         (unsigned long long)g_tramp_ret0,
         (int)g_tramp_last_ret,
         (unsigned)g_tramp_last_ext,
         (unsigned long long)g_tramp_last_ca_io,
         (unsigned long long)g_tramp_last_handoff,
         (unsigned)g_tramp_last_flags,
         (unsigned)((g_tramp_last_flags >> 2) & 1u));
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
// Patch the present_iosurface vtable slot with the trampoline. Heap-copy + re-sign
// (round-9 machinery) the object's OWN vtable and rewrite the object's vptr, then
// (defensively) heap-copy + patch the sibling vtable at +0x8a0 if one exists.
static int rd_patch_vtable_present(uint64_t hw, uint64_t skyBase) {
    (void)skyBase;

    uint64_t vptr = 0;
    RD_TRY("read_vptr", { vptr = *(uint64_t*)hw; });
    if (!vptr) { rlog("RDGPU_SCANOUT_VTABLE_NOVPTR hw=%p", (void*)hw); return -1; }
    uint64_t ap = rd_strip_da(vptr);
    uint64_t ztv = ap - VTABLE_HEADER;
    rlog("RDGPU_SCANOUT_VTABLE_READ hw=%p vptr=0x%llx ap=0x%llx ztv=0x%llx",
         (void*)hw, (unsigned long long)vptr,
         (unsigned long long)ap, (unsigned long long)ztv);

    uint64_t tramp_raw = rd_strip_ia((uint64_t)(uintptr_t)&rd_tramp_present);

    // (1) operative patch: the vtable THIS object points to.
    uint64_t slot = 0, orig_slot = 0, orig_entry = 0;
    uint64_t heap = rd_heap_copy_vtable(ztv, tramp_raw, &slot, &orig_slot, &orig_entry);
    if (!heap) { rlog("RDGPU_SCANOUT_VTABLE_PATCH_FAIL hw=%p", (void*)hw); return -2; }

    uint64_t new_ap = heap + VTABLE_HEADER;
    uint64_t new_vptr = rd_sign_da(new_ap, rd_blend(hw, VPTR_DISCRIMINATOR));
    RD_TRY("write_vptr", {
        *(uint64_t*)hw = new_vptr;
    });

    g_orig_vptr          = vptr;
    g_heap_vtable        = heap;
    g_orig_slot          = orig_slot;
    g_orig_signed_entry  = orig_entry;
    g_vtable_patched     = 1;
    rlog("RDGPU_SCANOUT_VTABLE_PATCHED heap=0x%llx new_ap=0x%llx new_vptr=0x%llx "
         "orig_vptr=0x%llx orig_slot=0x%llx orig_entry=0x%llx tramp_raw=0x%llx "
         "declkey=0x%x vptr_disc=0x%x",
         (unsigned long long)heap, (unsigned long long)new_ap, (unsigned long long)new_vptr,
         (unsigned long long)vptr, (unsigned long long)orig_slot,
         (unsigned long long)orig_entry, (unsigned long long)tramp_raw,
         DECLKEY_PRESENT_IOSURFACE, VPTR_DISCRIMINATOR);

    // (2) sibling vtable at +0x8a0, if present. Inert (no object vptr is rewritten to
    // it here — we only process the one external display), but it covers the case
    // where the object actually pointed at the sibling instead; detection is logged.
    uint64_t sibling_ztv = ztv + VTABLE_SIBLING_DELTA;
    if (rd_probe_vtable(sibling_ztv)) {
        uint64_t s_slot = 0, s_orig_slot = 0, s_orig_entry = 0;
        uint64_t s_heap = rd_heap_copy_vtable(sibling_ztv, tramp_raw, &s_slot, &s_orig_slot, &s_orig_entry);
        if (s_heap) {
            g_sibling_vtable = s_heap;
            rlog("RDGPU_SCANOUT_VTABLE_SIBLING_PATCHED ztv=0x%llx heap=0x%llx "
                 "slot=0x%llx orig_slot=0x%llx orig_entry=0x%llx (inert: kept for restore)",
                 (unsigned long long)sibling_ztv, (unsigned long long)s_heap,
                 (unsigned long long)s_slot, (unsigned long long)s_orig_slot,
                 (unsigned long long)s_orig_entry);
        }
    } else {
        rlog("RDGPU_SCANOUT_VTABLE_SIBLING_ABSENT ztv=0x%llx (no vtable at +0x8a0)",
             (unsigned long long)sibling_ztv);
    }
    return 0;
}

// Restore the original DA-signed vptr and free the heap copies. The shared-cache
// vtable was never written, so restoring the vptr is all that is needed to undo it.
static void rd_restore_vtable(void) {
    if (g_vtable_patched && g_hw && g_orig_vptr) {
        RD_TRY("restore_vptr", {
            *(uint64_t*)g_hw = g_orig_vptr;
        });
    }
    if (g_heap_vtable)    mach_vm_deallocate(mach_task_self(), g_heap_vtable, VTABLE_TOTAL_SIZE);
    if (g_sibling_vtable) mach_vm_deallocate(mach_task_self(), g_sibling_vtable, VTABLE_TOTAL_SIZE);
    g_heap_vtable    = 0;
    g_sibling_vtable = 0;
    g_vtable_patched = 0;
    rlog("RDGPU_SCANOUT_VTABLE_RESTORED vptr=0x%llx", (unsigned long long)g_orig_vptr);
}

static void rd_restore_all(void) {
    rd_restore_flags();
    rd_restore_vtable();
    rd_restore_handoff();
}

// ---------------------------------------------------------------------------
// Handle one received present request: JUST update the handoff slot and reply
// immediately. No present_iosurface, no drain, no settle, no throttle — the CA
// render loop presents the handoff surface at its own vblank cadence.
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

    int rc = 0;   // 0 == handed off
    if (!io) {
        rlog("RDGPU_SCANOUT_HANDOFF_SKIP reason=no_surface");
        rc = -1;
    } else if (!g_hw || !g_real_present) {
        rlog("RDGPU_SCANOUT_HANDOFF_SKIP reason=%s", g_hw ? "no_present_sym" : "no_display");
        CFRelease(io);
        rc = -1;
    } else {
        // keep flags[+0x76c] bit2 (0x4) set — external-update path (idempotent).
        RD_TRY("reassert_flags", {
            *(uint32_t*)(g_hw + CH_hw_present_flags) = g_flags_orig | 0x4u;
        });

        uint32_t sid = (uint32_t)IOSurfaceGetID(io);

        // Publish: CFRetain(new) for the slot, store, CFRelease(previous).
        IOSurfaceRef old = g_handoff;
        CFRetain(io);
        g_handoff = io;
        if (old) CFRelease(old);

        // release our lookup reference — the slot now owns its +1.
        CFRelease(io);

        g_frame++;
        rlog("RDGPU_SCANOUT_HANDOFF frame=%llu id=%u (%zux%zu) -> CA render loop",
             (unsigned long long)g_frame, (unsigned)sid,
             IOSurfaceGetWidth((IOSurfaceRef)g_handoff),
             IOSurfaceGetHeight((IOSurfaceRef)g_handoff));
    }

    if (msg->header.msgh_remote_port != MACH_PORT_NULL) {
        rdgpu_reply_t reply;
        memset(&reply, 0, sizeof reply);
        reply.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
        reply.header.msgh_remote_port = msg->header.msgh_remote_port;
        reply.header.msgh_local_port = MACH_PORT_NULL;
        reply.header.msgh_id = msg->header.msgh_id + 1;
        reply.result = (rc == 0) ? 0 : rc;   // 0 == handed off; -1 == no surface
        mach_msg(&reply.header, MACH_SEND_MSG, sizeof reply, 0,
                 MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    }
}

// ---------------------------------------------------------------------------
// Receive loop (detached thread).
static void* rd_server_thread(void* arg) {
    mach_port_t recv = (mach_port_t)(intptr_t)arg;
    rlog("RDGPU_SCANOUT_SERVER_START port=%u", recv);
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
        rd_log_tramp_state("after_handoff");
        if (!g_flags_set) { rlog("RDGPU_SCANOUT_SERVER_STOP (flags restored)"); break; }
    }
    rd_log_tramp_state("stop");
    rd_restore_all();
    rlog("RDGPU_SCANOUT_SERVER_STOP");
    return NULL;
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

        uint32_t want_id = 0x1e;
        const char *e_disp = getenv("RDGPU_SCANOUT_DISPLAY");
        if (e_disp && e_disp[0]) {
            want_id = (uint32_t)strtoul(e_disp, NULL, 0);
        } else {
            FILE *fsel = fopen("/tmp/rdgpu-scanout-display", "r");
            if (fsel) {
                char line[64] = {0};
                if (fgets(line, sizeof line, fsel) && line[0])
                    want_id = (uint32_t)strtoul(line, NULL, 0);
                fclose(fsel);
            }
        }

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

        rlog("RDGPU_SCANOUT_LOAD pid=%d mode=server15 want_id=0x%x sync=%d (trampoline+handoff+instrumentation; drain/settle/throttle/replay removed)",
             (int)getpid(), (unsigned)want_id, g_sync_mode);

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
            for (uint64_t p = begin; p < end && !mapped; p += 8) {
                uint64_t pkg = 0;
                uint32_t dispID = 0;
                RD_TRY("walk_pkg_display", {
                    pkg = *(uint64_t*)p;
                    if (pkg) dispID = *(uint32_t*)(pkg + CH_PKGDisplay_displayID);
                });
                if (!pkg) break;
                if (dispID != want_id) continue;

                uint64_t refbuf[2] = {0, 0};
                RD_TRY("call_get_displayref", {
                    if (getref) getref(refbuf, (void*)pkg);
                });
                uint64_t hw = refbuf[0];
                if (!hw) { rlog("RDGPU_SCANOUT_DISPLAY display 0x%x: displayref NULL", (unsigned)dispID); continue; }

                uint32_t hid = 0, sw = 0, sh = 0, fl = 0;
                uint64_t ca = 0;
                RD_TRY("read_hw_fields", {
                    hid = *(uint32_t*)(hw + CH_hw_displayID);
                    ca  = *(uint64_t*)(hw + CH_hw_ca_display);
                    sw  = *(uint32_t*)(hw + CH_hw_scanout_wide);
                    sh  = *(uint32_t*)(hw + CH_hw_scanout_high);
                    fl  = *(uint32_t*)(hw + CH_hw_present_flags);
                });
                rlog("RDGPU_SCANOUT_DISPLAY display=0x%x hw=%p cadisplay=%p scanout=%ux%u flags=0x%x",
                     (unsigned)hid, (void*)hw, (void*)ca, (unsigned)sw, (unsigned)sh, (unsigned)fl);

                if (!ca) { rlog("RDGPU_SCANOUT_DISPLAY 0x%x: cadisplay NULL", (unsigned)hid); break; }

                g_hw = hw; g_ca_display = ca; g_display_id = hid;
                g_scanout_w = sw; g_scanout_h = sh; g_flags_orig = fl;
                mapped = 1;
            }
        }

        if (!mapped) {
            rlog("RDGPU_SCANOUT_DONE result=no-display");
            return;
        }

        mach_port_t recv = (mach_port_t)injected_recv_port;
        if (recv == MACH_PORT_NULL) {
            rlog("RDGPU_SCANOUT_DONE result=no-port (injector did not register/hand a receive right)");
            return;
        }
        rlog("RDGPU_SCANOUT_RECV port=%u (injected by root injector)", recv);

        // Publish g_real_present to the CA render thread BEFORE the vtable patch
        // makes the trampoline reachable (release barrier pairs with the CA loop's
        // vptr read -> trampoline -> g_real_present load; a vblank is ~16.7ms so this
        // is belt-and-braces, but the store must not be reordered past the vptr write).
        __sync_synchronize();

        // Patch the present_iosurface vtable slot with the trampoline (CA render
        // thread caller), BEFORE enabling the external-update flag and serving.
        int vpatch = rd_patch_vtable_present(g_hw, skyBase);
        rlog("RDGPU_SCANOUT_VTABLE_PATCH_RESULT rc=%d patched=%d",
             vpatch, (int)g_vtable_patched);

        RD_TRY("set_external_update_flag", {
            *(uint32_t*)(g_hw + CH_hw_present_flags) = g_flags_orig | 0x4u;
        });
        g_flags_set = 1;
        rlog("RDGPU_SCANOUT_FLAGS display=0x%x 0x%x -> 0x%x (external-update path)",
             (unsigned)g_display_id, (unsigned)g_flags_orig, (unsigned)(g_flags_orig | 0x4u));

        pthread_t t;
        if (pthread_create(&t, NULL, rd_server_thread, (void*)(intptr_t)recv) == 0) {
            pthread_detach(t);
            rlog("RDGPU_SCANOUT_SERVING name=%s port=%u display=0x%x vtable_patched=%d tramp=0x%llx",
                 g_service_name, recv, (unsigned)g_display_id, (int)g_vtable_patched,
                 (unsigned long long)rd_strip_ia((uint64_t)(uintptr_t)&rd_tramp_present));
        } else {
            rlog("RDGPU_SCANOUT_THREAD_FAIL (restoring flags + vtable + handoff)");
            rd_restore_all();
        }

        rlog("RDGPU_SCANOUT_DONE result=serving");
    }
}
