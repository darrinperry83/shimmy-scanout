// payload_scanout_server8.m — server7 + the CORRECTED swap_wait invocation.
//
// ROUND-12 disasm of CA::IOMobileFramebuffer::swap_wait (QuartzCore +0x2f876c):
//   swap_wait is a 3-arg wrapper
//       int swap_wait(this, uint32_t swapID, uint32_t waitOptions)
//   that tail-calls the PLAIN IOMobileFramebufferSwapWait(this[0], swapID, waitOptions)
//   (live 0x190c7dc48; NOT SwapWaitWithTimeout 0x190c7dc64). The plain variant emits
//   selector 6 (swapWait) with scalars [swapID, waitOptions, timeout_millis=0] -- the
//   timeout is HARD-CODED to 0. So the wrapper's 3rd arg is waitOptions, NOT a
//   timeout. Round-11's "0x80000001 ns ~ 2.1 s timeout" was wrong.
//
// can_update_ (+0x34e0ec) calls it as
//       swap_wait(iomfb_display+0x6458, [iomfb_display+0x6714], 0x80000001)
//   i.e. swapID = the cached pending swap id, waitOptions = 0x80000001. server8
//   reproduces those exact arg count/order/values (keeping the page-slot/queue-tail
//   swap-id read, which is the live-correct source).
//
// =============================================================================
// ROOT CAUSE of the 3rd-frame ret=0 (round 10, disasm of present_iosurface AND
// the CA backend):
//
//   present_iosurface (external-update path, flags[+0x76c] bit2 set) does:
//     [ca canUpdateWithFlags:0]  ->  if false -> mov w21,#0 -> return 0.
//   The call chain (all in QuartzCore, vptr discriminator 0x27e3 =
//   siphash("_ZTVN2CA12WindowServer7DisplayE")):
//     -[CAWindowServerDisplay canUpdateWithFlags:]           (IMP +0x2c79cc)
//        locks [self+8], calls [[self+8]+0x40] ->vtable[0x8] (declkey 0x77b5)
//     CA::WindowServer::IOMFBDisplay::can_update(u, d, d)    (+0x35e534) wrapper
//        state-machine checks, then calls can_update_ (+0x34e0ec)
//     CA::WindowServer::IOMFBDisplay::can_update_(u, d, d)   (+0x34e0ec)
//        iterates pages, reads page->[0x18] (= pending swap id) and calls
//        IOMobileFramebuffer::swap_wait on it; false -> miss counter
//        [iomfb_display+0x63c0]++ -> present returns 0.
//
//   can_update returns 0 (=="yes, update") only when the IOMFB swap queue has a
//   free slot. Each present_iosurface enqueues ONE swap via finish_update ->
//   IOMFB; the swap is consumed only at the display's next vblank. Presenting
//   faster than vblank (or with no settle) fills the finite in-flight queue
//   (depth 2), so the 3rd consecutive external update gets can_update != 0 and
//   present_iosurface returns 0. The exact error is one of {0xff,0xe9,0xfe,0xfd,
//   0xfc,0xfb,0xfa}; the most likely is 0xfa (can_update_ false, which increments
//   the miss counter at [iomfb_display+0x63c0]).
//
//   sync=true only issues MetalContext::Flush (GPU-only; signals a shared event,
//   does NOT wait for the IOMFB swap). So sync=true alone does NOT drain the
//   IOMFB swap queue — a post-present settle is required.
//
// ROUND-11 FIX — the swap id field (server6 bug):
//   server6 settled on [iomfb_display+0x6714] but that field stayed 0 in the live
//   run, so the settle always SKIPPED and the 3rd frame still failed.  Disasm of
//   IOMFBDisplay::finish_update (+0x35b300) shows the real field:
//       page = iomfb_display + 0x6678 + [iomfb_display+0x6624]*0x30
//       IOMobileFramebufferSwapBegin(conn, &page[0x18])  -> writes the swap id
//       IOMobileFramebufferSwapEnd(conn)                 -> commits
//   so the swap id lives at
//       [iomfb_display + 0x6690 + [iomfb_display+0x6624]*0x30]   (0x6690 = 0x6678+0x18)
//   and is ALSO copied into the last FrameInfo of the swap queue
//   (std::vector at [0x6720..0x6728]; FrameInfo[0] = swap id).  can_update_ reads
//   that same page->[0x18] slot and passes it to swap_wait.  (0x6714 is only a
//   cached copy set under a mode-specific branch of finish_update_, hence 0.)
//
// CADENCE (server8):
//   1. re-assert flags[+0x76c] |= 0x4 (idempotent);
//   2. present_iosurface(hw, io, /*sync*/TRUE) EVERY frame;
//   3. settle (AFTER present): read the page swap-id slot above, then
//      IOMobileFramebuffer::swap_wait(swap_id, 0x80000001 /*waitOptions*/) on the
//      embedded CA::IOMobileFramebuffer at [iomfb_display+0x6458]. The wrapper emits
//      selector 6 with timeout_millis=0, so it waits on the kernel's own swapWait
//      timeout semantics for the just-enqueued swap id, keeping the in-flight queue
//      at depth <= 1 → one present per refresh, can_update stays true forever.
//
//   The settle is gated on a non-zero swap id and a resolved iomfb display.
//   Disable with `echo 0 > /tmp/rdgpu-scanout-settle` or force async with
//   `echo 0 > /tmp/rdgpu-scanout-sync`.
//
// INSTRUMENTATION: every frame logs the raw swap-id slot and the FrameInfo queue
// tail, so ONE run confirms the id is nonzero after present and changes per frame:
//   state = [iomfb_display+0x300] -> bytes [0],[1],[3],[5]
//   [iomfb_display+0x290] (0xfe), [+0x72f6] (0xfd), [+0x389] (0x3: 0xfb),
//   miss counter [+0x63c0] (0xfa), page indices [+0x6624]/[+0x6628],
//   swap id [+0x6690+page*0x30], FrameInfo queue [0x6720..0x6728] tail swap id.
//
// Build:
//   cd .../integration/rdmetal
//   clang -arch arm64e -O2 -bundle payload_scanout_server8.m \
//       -o /tmp/rdgpu-scanout-server8-payload \
//       -framework Foundation -framework IOSurface -framework CoreFoundation
//   sudo ./ws_inject_manual_d --register /tmp/rdgpu-scanout-server8-payload

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

// VTABLE hook constants (round-8 corrected slot/declkey + round-9 vptr disc).
#define CH_vtable_present_slot       (0x5d0LL)   // present_iosurface slot (byte offset from vptr)
#define DECLKEY_PRESENT_IOSURFACE    (0x5a24)    // siphash("_ZN...7Display17present_iosurfaceEP11__IOSurfaceb")
#define VPTR_DISCRIMINATOR           (0xc333)    // siphash("_ZTVN2WS8Displays7DisplayE")
#define VTABLE_TOTAL_SIZE            (0x850LL)   // _ZTVN...SLCADisplayE size (from _ZTV metadata)
#define VTABLE_HEADER                (0x10LL)    // offset-to-top + RTTI before the address point
#define RD_PAGE_SIZE                 (0x4000LL)  // 16 KiB

// ---------------------------------------------------------------------------
// CA backend object walk (round-10 disasm, QuartzCore). Offsets are absolute
// byte offsets into the named object.
//   ca           = [SLCADisplay + 0x1d8]         (CAWindowServerDisplay ObjC obj)
//   lock_holder  = [ca + 0x8]                    (mutex@0 + Server*@0x40)
//   server       = [lock_holder + 0x40]          (CA::WindowServer::Server*)
//   iomfb_display= [server + 0x58]               (CA::WindowServer::IOMFBDisplay*)
#define CH_ca_lock_holder            (0x8LL)
#define CH_lh_server                 (0x40LL)
#define CH_server_display            (0x58LL)

// CA::WindowServer::IOMFBDisplay object layout (round-10/round-11 disasm).
#define CH_iomfb_state               (0x300LL)   // -> state struct (bytes 0,1,3,5)
#define CH_iomfb_290                 (0x290LL)   // ptr   (can_update 0xfe branch)
#define CH_iomfb_72f6                (0x72f6LL)  // byte  (can_update 0xfd branch)
#define CH_iomfb_389                 (0x389LL)   // byte  (can_update 0xfb branch, bit3)
#define CH_iomfb_miss_counter        (0x63c0LL)  // u32   (can_update 0xfa branch increments)
#define CH_iomfb_obj                 (0x6458LL)  // embedded CA::IOMobileFramebuffer (swap_wait `this`)
#define CH_iomfb_pending_swap        (0x6714LL)  // u32   can_update_'s swap_wait id source (cached copy; 0 when +0x8d0 gate off)

// --- correct pending-swap-id field (round-11 disasm) ---
// finish_update() (QuartzCore +0x35b300) computes the page struct as
//     page = iomfb_display + 0x6678 + [iomfb_display+0x6624]*0x30
// and IOMobileFramebufferSwapBegin writes the new swap id to  page[+0x18], i.e.
//     [iomfb_display + 0x6690 + [iomfb_display+0x6624]*0x30].      (0x6690 = 0x6678+0x18)
// finish_update_() then advances the page index: [0x6628] = old [0x6624];
// [0x6624] = (old+1) % 2.  The same swap id is ALSO copied into the last FrameInfo
// of the swap queue (std::vector<unique_ptr<FrameInfo>> at [0x6720..0x6728], with
// FrameInfo[0] = swap id).  can_update_() reads page->[0x18] and passes it to
// swap_wait.  (0x6714 is only a *cached* copy set under a mode-specific branch of
// finish_update_, which is why server6 read 0 and skipped the settle.)
#define CH_iomfb_page_idx_next       (0x6624LL)  // u32   page index finish_update_ advances
#define CH_iomfb_page_idx_prev       (0x6628LL)  // u32   page index just presented (old [0x6624])
#define CH_iomfb_page_array          (0x6678LL)  // page struct array base
#define CH_iomfb_page_stride         (0x30LL)    // sizeof(page struct)
#define CH_iomfb_page_swap_id        (0x18LL)    // offset of swap id within page struct
#define CH_iomfb_swap_id_array       (0x6690LL)  // = 0x6678 + 0x18  (swap-id slot array)
// FrameInfo swap queue (std::vector<unique_ptr<FrameInfo>>) — authoritative settle source.
#define CH_iomfb_fiq_begin           (0x6720LL)  // vector __begin_
#define CH_iomfb_fiq_end             (0x6728LL)  // vector __end_

// QuartzCore offsets (relative to QuartzCore dli_fbase; boot-independent).
#define OFF_qc_swap_wait             (0x2f876cLL) // CA::IOMobileFramebuffer::swap_wait(unsigned,unsigned)

// swap_wait waitOptions: the EXACT value can_update_ passes as the 3rd argument.
// Round-12 disasm of CA::IOMobileFramebuffer::swap_wait shows the wrapper is
//   int swap_wait(this, uint32_t swapID, uint32_t waitOptions)
// which calls IOMobileFramebufferSwapWait(this[0], swapID, waitOptions) (the PLAIN
// variant, NOT SwapWaitWithTimeout). That plain variant emits selector 6 (swapWait)
// with scalars [swapID, waitOptions, timeout_millis=0] -- the timeout is HARD-CODED
// to 0 by the wrapper. So the 3rd arg is waitOptions, NOT a timeout (round-11's
// "0x80000001 ns ~ 2.1 s timeout" was wrong). can_update_ passes waitOptions =
// 0x80000001, so we reproduce exactly that.
#define SWAP_WAIT_OPTIONS           (0x80000001u)

// ---------------------------------------------------------------------------
// Logging (file + NSLog), thread-safe.
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

// present_iosurface(__IOSurface* io, bool sync) -> int (1 success / 0 failure)
typedef int (*fn_present_iosurface)(void*, IOSurfaceRef, bool);
// CA::IOMobileFramebuffer::swap_wait(unsigned swap_id, unsigned wait_options) -> int
//   Round-12 disasm: swap_wait is a 3-arg wrapper (this, swapID, waitOptions) that
//   tail-calls IOMobileFramebufferSwapWait(this[0], swapID, waitOptions) -- the
//   PLAIN variant, NOT SwapWaitWithTimeout. That plain variant emits selector 6
//   (swapWait) with scalars [swapID, waitOptions, timeout_millis=0]; the timeout is
//   HARD-CODED to 0. So the 3rd arg is waitOptions (0x80000001, exactly what
//   can_update_ passes), NOT a timeout.
typedef int (*fn_swap_wait)(void*, uint32_t swapID, uint32_t waitOptions);

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
static fn_present_iosurface g_present = NULL;

static pthread_mutex_t g_presentLock = PTHREAD_MUTEX_INITIALIZER;
static IOSurfaceRef    g_lastPresented = NULL;
static volatile uint64_t g_frame = 0;
static int               g_sync_mode = 1;    // default: sync=true EVERY frame
static int               g_settle_on = 1;    // default: swap_wait settle after present

static uint64_t       g_qc_base      = 0;    // QuartzCore dli_fbase
static fn_swap_wait   g_swap_wait    = NULL; // CA::IOMobileFramebuffer::swap_wait
static uint64_t       g_iomfb_display= 0;    // CA::WindowServer::IOMFBDisplay*

// vtable heap-copy patch state. Restore = write g_orig_vptr back + free the copy.
static uint64_t       g_orig_vptr     = 0;
static uint64_t       g_heap_vtable   = 0;
static uint64_t       g_orig_slot     = 0;
static uint64_t       g_orig_signed_entry = 0;
static uint64_t       g_stub_page     = 0;
static volatile int   g_vtable_patched = 0;

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
// Heap-copy vtable hook (unchanged from server5).
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

    mach_vm_address_t heap = 0;
    kern_return_t kr = mach_vm_allocate(mach_task_self(), &heap, VTABLE_TOTAL_SIZE, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) { rlog("RDGPU_SCANOUT_VTABLE_ALLOC_FAIL kr=%d", kr); return -2; }

    RD_TRY("copy_vtable", {
        memcpy((void*)heap, (void*)ztv, VTABLE_TOTAL_SIZE);
    });

    int nre = 0, namb = 0, nfail = 0;
    (void)namb;
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
        return -3;
    }
    rlog("RDGPU_SCANOUT_VTABLE_RESIGN re=%d entries", nre);

    static const uint8_t stub_code[8] = { 0x20,0x00,0x80,0x52, 0xc0,0x03,0x5f,0xd6 };
    mach_vm_address_t stub = 0;
    kr = mach_vm_allocate(mach_task_self(), &stub, RD_PAGE_SIZE, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) { mach_vm_deallocate(mach_task_self(), heap, VTABLE_TOTAL_SIZE); rlog("RDGPU_SCANOUT_VTABLE_STUB_ALLOC_FAIL kr=%d", kr); return -4; }
    kr = mach_vm_write(mach_task_self(), stub, (vm_offset_t)stub_code, sizeof stub_code);
    if (kr != KERN_SUCCESS) { mach_vm_deallocate(mach_task_self(), stub, RD_PAGE_SIZE); mach_vm_deallocate(mach_task_self(), heap, VTABLE_TOTAL_SIZE); return -5; }
    kr = mach_vm_protect(mach_task_self(), stub, RD_PAGE_SIZE, 0, VM_PROT_READ | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) { mach_vm_deallocate(mach_task_self(), stub, RD_PAGE_SIZE); mach_vm_deallocate(mach_task_self(), heap, VTABLE_TOTAL_SIZE); return -6; }

    uint64_t new_slot = heap + VTABLE_HEADER + CH_vtable_present_slot;
    uint64_t signed_stub = rd_sign_ia(stub, rd_blend(new_slot, DECLKEY_PRESENT_IOSURFACE));
    *(uint64_t*)(heap + VTABLE_HEADER + CH_vtable_present_slot) = signed_stub;

    uint64_t new_ap = heap + VTABLE_HEADER;
    uint64_t new_vptr = rd_sign_da(new_ap, rd_blend(hw, VPTR_DISCRIMINATOR));
    RD_TRY("write_vptr", {
        *(uint64_t*)hw = new_vptr;
    });

    g_orig_vptr          = vptr;
    g_heap_vtable        = heap;
    g_orig_slot          = ztv + VTABLE_HEADER + CH_vtable_present_slot;
    g_orig_signed_entry  = *(uint64_t*)(ztv + VTABLE_HEADER + CH_vtable_present_slot);
    g_stub_page          = stub;
    g_vtable_patched     = 1;
    rlog("RDGPU_SCANOUT_VTABLE_PATCHED heap=0x%llx new_ap=0x%llx new_vptr=0x%llx "
         "orig_vptr=0x%llx orig_slot=0x%llx orig_entry=0x%llx stub=0x%llx signed_stub=0x%llx "
         "declkey=0x%x vptr_disc=0x%x",
         (unsigned long long)heap, (unsigned long long)new_ap, (unsigned long long)new_vptr,
         (unsigned long long)vptr, (unsigned long long)g_orig_slot,
         (unsigned long long)g_orig_signed_entry, (unsigned long long)stub,
         (unsigned long long)signed_stub, DECLKEY_PRESENT_IOSURFACE, VPTR_DISCRIMINATOR);
    return 0;
}

// Restore the original DA-signed vptr and free the heap copy + stub page.
static void rd_restore_vtable(void) {
    if (!g_vtable_patched || !g_hw || !g_orig_vptr) return;
    RD_TRY("restore_vptr", {
        *(uint64_t*)g_hw = g_orig_vptr;
    });
    if (g_heap_vtable) mach_vm_deallocate(mach_task_self(), g_heap_vtable, VTABLE_TOTAL_SIZE);
    if (g_stub_page)   mach_vm_deallocate(mach_task_self(), g_stub_page, RD_PAGE_SIZE);
    g_heap_vtable = 0;
    g_stub_page   = 0;
    g_vtable_patched = 0;
    rlog("RDGPU_SCANOUT_VTABLE_RESTORED vptr=0x%llx", (unsigned long long)g_orig_vptr);
}

static void rd_restore_all(void) {
    rd_restore_flags();
    rd_restore_vtable();
}

// ---------------------------------------------------------------------------
// Resolve the CA::WindowServer::IOMFBDisplay* from the SLCADisplay, walking
// ca -> lock_holder -> Server -> display. Raw data derefs only (no objc_msgSend).
static uint64_t rd_resolve_iomfb(uint64_t hw) {
    uint64_t ca = 0, lh = 0, server = 0, disp = 0;
    RD_TRY("resolve_iomfb", {
        ca     = *(uint64_t*)(hw + CH_hw_ca_display);
        if (ca) lh = *(uint64_t*)(ca + CH_ca_lock_holder);
        if (lh) server = *(uint64_t*)(lh + CH_lh_server);
        if (server) disp = *(uint64_t*)(server + CH_server_display);
    });
    if (!disp) return 0;
    return disp;
}

// Authoritative settle source: the last FrameInfo in the swap queue. finish_update()
// copies the swap id into FrameInfo[0] and push_back's the FrameInfo at the very end,
// so the queue tail is the most-recent enqueued swap and is independent of the page
// index flip.  FrameInfo[0] = swap id (verified: `str w8,[x23]` after SwapBegin).
static uint32_t rd_read_fiq_tail_swap_id(uint64_t *qbegin_out, uint64_t *qend_out) {
    uint64_t qb = 0, qe = 0;
    uint32_t swap_id = 0;
    RD_TRY("read_fiq", {
        qb = *(uint64_t*)(g_iomfb_display + CH_iomfb_fiq_begin);
        qe = *(uint64_t*)(g_iomfb_display + CH_iomfb_fiq_end);
        if (qe > qb) {
            uint64_t tail = *(uint64_t*)(qe - 8);   // FrameInfo* (unique_ptr)
            if (tail) swap_id = *(uint32_t*)tail;   // FrameInfo[0]
        }
    });
    if (qbegin_out) *qbegin_out = qb;
    if (qend_out)   *qend_out   = qe;
    return swap_id;
}

// Secondary cross-check: the page slot finish_update() writes via SwapBegin.
//   page = iomfb_display + 0x6678 + [iomfb_display+0x6624]*0x30   (at SwapBegin time)
//   swap id = page[+0x18] = [iomfb_display + 0x6690 + page*0x30]
// finish_update_() then sets [0x6628] = old [0x6624] and [0x6624] = next page, so
// AFTER present the just-written slot is [0x6628]; we read both slots for logging.
static uint32_t rd_read_page_swap_id(uint32_t *idx_next_out, uint32_t *idx_prev_out) {
    uint32_t idx_next = 0, idx_prev = 0, swap_id = 0;
    RD_TRY("read_page_swap_id", {
        idx_next = *(uint32_t*)(g_iomfb_display + CH_iomfb_page_idx_next);
        idx_prev = *(uint32_t*)(g_iomfb_display + CH_iomfb_page_idx_prev);
        swap_id  = *(uint32_t*)(g_iomfb_display + CH_iomfb_swap_id_array
                                + (uint64_t)idx_prev * CH_iomfb_page_stride);
    });
    if (idx_next_out) *idx_next_out = idx_next;
    if (idx_prev_out) *idx_prev_out = idx_prev;
    return swap_id;
}

// Log the IOMFB state fields the can_update wrapper branches on, so a live run
// pinpoints the exact non-zero error code (0xff/0xe9/0xfe/0xfd/0xfc/0xfb/0xfa),
// plus the corrected swap-id sources (page slot + FrameInfo queue tail).
static void rd_log_iomfb_state(void) {
    if (!g_iomfb_display) return;
    uint64_t st = 0, p290 = 0;
    uint8_t b0 = 0, b1 = 0, b3 = 0, b5 = 0, b72f6 = 0, b389 = 0;
    uint32_t miss = 0, pend = 0;
    uint32_t idx_next = 0, idx_prev = 0, page_swap = 0;
    uint64_t qb = 0, qe = 0;
    uint32_t qtail = 0;
    RD_TRY("read_iomfb_state", {
        st = *(uint64_t*)(g_iomfb_display + CH_iomfb_state);
        p290 = *(uint64_t*)(g_iomfb_display + CH_iomfb_290);
        b72f6 = *(uint8_t*)(g_iomfb_display + CH_iomfb_72f6);
        b389  = *(uint8_t*)(g_iomfb_display + CH_iomfb_389);
        miss  = *(uint32_t*)(g_iomfb_display + CH_iomfb_miss_counter);
        pend  = *(uint32_t*)(g_iomfb_display + CH_iomfb_pending_swap);
        if (st) { b0 = *(uint8_t*)(st + 0); b1 = *(uint8_t*)(st + 1);
                  b3 = *(uint8_t*)(st + 3); b5 = *(uint8_t*)(st + 5); }
    });
    page_swap = rd_read_page_swap_id(&idx_next, &idx_prev);
    qtail     = rd_read_fiq_tail_swap_id(&qb, &qe);
    rlog("RDGPU_SCANOUT_IOMFB disp=%p st=%p state[0]=%u [1]=%u [3]=%u [5]=%u "
         "p290=%p b72f6=0x%x b389=0x%x miss=%u pend_swap=%u pg_next=%u pg_prev=%u "
         "pg_swap=%u fiq=[%p,%p) fiq_tail_swap=%u",
         (void*)g_iomfb_display, (void*)st, (unsigned)b0, (unsigned)b1,
         (unsigned)b3, (unsigned)b5, (void*)p290, (unsigned)b72f6,
         (unsigned)b389, (unsigned)miss, (unsigned)pend, (unsigned)idx_next,
         (unsigned)idx_prev, (unsigned)page_swap, (void*)qb, (void*)qe,
         (unsigned)qtail);
}

// ---------------------------------------------------------------------------
// Handle one received present request.
static void rd_handle_present(const rdgpu_present_msg_t* msg) {
    IOSurfaceRef io = NULL;

    if (msg->body.msgh_descriptor_count >= 1 &&
        msg->surface_port.type == MACH_MSG_PORT_DESCRIPTOR) {
        mach_port_name_t sp = msg->surface_port.name;
        io = IOSurfaceLookupFromMachPort(sp);
        rlog("RDGPU_SCANOUT_MSG port=%u id=%u iosurface=%p disp_index=%u",
             sp, (unsigned)(io ? IOSurfaceGetID(io) : 0), (void*)io, msg->display_index);
        if (sp != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), sp);
    } else if (msg->surface_id != 0) {
        io = IOSurfaceLookup(msg->surface_id);
        rlog("RDGPU_SCANOUT_MSG id=%u iosurface=%p", msg->surface_id, (void*)io);
    }

    int rc = 0;
    if (!io) {
        rlog("RDGPU_SCANOUT_PRESENT_SKIP reason=no_surface");
        rc = 0;
    } else if (!g_hw || !g_present) {
        rlog("RDGPU_SCANOUT_PRESENT_SKIP reason=%s", g_hw ? "no_present_sym" : "no_display");
        rc = 0;
    } else {
        uint32_t fl = g_flags_orig | 0x4u;
        RD_TRY("reassert_flags", {
            *(uint32_t*)(g_hw + CH_hw_present_flags) = fl;
            fl = *(uint32_t*)(g_hw + CH_hw_present_flags);
        });
        rlog("RDGPU_SCANOUT_PRESENT_PRE frame=%llu flags=0x%x orig=0x%x",
             (unsigned long long)g_frame, (unsigned)fl, (unsigned)g_flags_orig);
        rd_log_iomfb_state();

        int sync = g_sync_mode ? 1 : 0;

        int r = -1;
        pthread_mutex_lock(&g_presentLock);
        RD_TRY("present_iosurface", {
            r = g_present((void*)g_hw, io, sync ? true : false);
        });
        pthread_mutex_unlock(&g_presentLock);
        rc = r;
        g_frame++;
        rlog("RDGPU_SCANOUT_PRESENT display=0x%x hw=%p iosurface=%u (%zux%zu) sync=%d ret=%d",
             (unsigned)g_display_id, (void*)g_hw,
             (unsigned)IOSurfaceGetID(io), IOSurfaceGetWidth(io), IOSurfaceGetHeight(io),
             sync, r);

        if (r <= 0) {
            rlog("RDGPU_SCANOUT_PRESENT_FAILED restoring flags + vtable and stopping");
            CFRelease(io);
            rd_restore_all();
            return;
        }

        // ---- settle: wait for the just-enqueued IOMFB swap to be consumed at
        //      vblank, so the in-flight swap queue never exceeds depth 1. ----
        //      Read AFTER present.  Authoritative source is the FrameInfo queue
        //      tail (finish_update push_back's FrameInfo[0]=swap id last); the
        //      page slot [iomfb_display+0x6690+[iomfb_display+0x6628]*0x30] is a
        //      cross-check.  A nonzero id is required before we block.
        if (g_settle_on && g_swap_wait && g_iomfb_display) {
            uint32_t idx_next = 0, idx_prev = 0;
            uint32_t page_swap = rd_read_page_swap_id(&idx_next, &idx_prev);
            uint64_t qb = 0, qe = 0;
            uint32_t fiq_tail = rd_read_fiq_tail_swap_id(&qb, &qe);
            uint32_t pend = fiq_tail ? fiq_tail : page_swap;  // queue tail authoritative
            if (pend) {
                int sw = -1;
                RD_TRY("swap_wait", {
                    sw = g_swap_wait((void*)(g_iomfb_display + CH_iomfb_obj),
                                     pend, SWAP_WAIT_OPTIONS);
                });
                rlog("RDGPU_SCANOUT_SETTLE swap_id=%u pg_next=%u pg_prev=%u "
                     "pg_swap=%u fiq_tail=%u fiq=[%p,%p) ret=%d",
                     (unsigned)pend, (unsigned)idx_next, (unsigned)idx_prev,
                     (unsigned)page_swap, (unsigned)fiq_tail, (void*)qb, (void*)qe, sw);
            } else {
                rlog("RDGPU_SCANOUT_SETTLE skip (swap_id=0 pg_next=%u pg_prev=%u "
                     "pg_swap=%u fiq_tail=%u fiq=[%p,%p))",
                     (unsigned)idx_next, (unsigned)idx_prev, (unsigned)page_swap,
                     (unsigned)fiq_tail, (void*)qb, (void*)qe);
            }
        }

        CFRetain(io);
        if (g_lastPresented) CFRelease(g_lastPresented);
        g_lastPresented = io;
        CFRelease(io);
    }

    if (msg->header.msgh_remote_port != MACH_PORT_NULL) {
        rdgpu_reply_t reply;
        memset(&reply, 0, sizeof reply);
        reply.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
        reply.header.msgh_remote_port = msg->header.msgh_remote_port;
        reply.header.msgh_local_port = MACH_PORT_NULL;
        reply.header.msgh_id = msg->header.msgh_id + 1;
        reply.result = (rc >= 1) ? 0 : (rc < 0 ? rc : -1);
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
        if (!g_flags_set) { rlog("RDGPU_SCANOUT_SERVER_STOP (flags restored)"); break; }
    }
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

        // ---- cadence knobs (config files the root parent can write). ----
        {
            FILE *fs = fopen("/tmp/rdgpu-scanout-sync", "r");
            if (fs) {
                char line[64] = {0};
                if (fgets(line, sizeof line, fs) && line[0])
                    g_sync_mode = (strtol(line, NULL, 0) != 0) ? 1 : 0;
                fclose(fs);
            }
        }
        {
            FILE *fs = fopen("/tmp/rdgpu-scanout-settle", "r");
            if (fs) {
                char line[64] = {0};
                if (fgets(line, sizeof line, fs) && line[0])
                    g_settle_on = (strtol(line, NULL, 0) != 0) ? 1 : 0;
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

        rlog("RDGPU_SCANOUT_LOAD pid=%d mode=server8 want_id=0x%x sync=%d settle=%d",
             (int)getpid(), (unsigned)want_id, g_sync_mode, g_settle_on);

        void *gSkyLight = dlopen("/System/Library/PrivateFrameworks/SkyLight.framework/SkyLight",
                                 RTLD_LAZY | RTLD_LOCAL);
        rlog("RDGPU_SCANOUT_DLOPEN SkyLight=%p", gSkyLight);

        // ---- QuartzCore base + swap_wait symbol ----
        dlopen("/System/Library/Frameworks/QuartzCore.framework/QuartzCore",
               RTLD_LAZY | RTLD_LOCAL);
        void *sym_ca_time = dlsym(RTLD_DEFAULT, "CACurrentMediaTime");
        {
            Dl_info info;
            if (sym_ca_time && dladdr(sym_ca_time, &info))
                g_qc_base = (uint64_t)info.dli_fbase;
        }
        if (g_qc_base) g_swap_wait = (fn_swap_wait)rd_sign_fn(g_qc_base + OFF_qc_swap_wait);
        rlog("RDGPU_SCANOUT_QC base=%p swap_wait=%p",
             (void*)g_qc_base, (void*)(uintptr_t)g_swap_wait);

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
        g_present = (fn_present_iosurface)rd_sign_fn(skyBase + OFF_present_iosurface);

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

        // Resolve the CA IOMFB display for state logging + swap_wait settle.
        g_iomfb_display = rd_resolve_iomfb(g_hw);
        rlog("RDGPU_SCANOUT_IOMFB_RESOLVE iomfb_display=%p", (void*)g_iomfb_display);

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
            rlog("RDGPU_SCANOUT_SERVING name=%s port=%u display=0x%x vtable_patched=%d",
                 g_service_name, recv, (unsigned)g_display_id, (int)g_vtable_patched);
        } else {
            rlog("RDGPU_SCANOUT_THREAD_FAIL (restoring flags + vtable)");
            rd_restore_all();
        }

        rlog("RDGPU_SCANOUT_DONE result=serving");
    }
}
