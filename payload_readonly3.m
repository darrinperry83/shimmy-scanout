// payload_readonly3.m — READ-ONLY SERVER-side present/scanout surface probe (round 3).
//
// Builds on payload_readonly2.m (display enumeration via the SkyLight hidden
// chain). Round 2 already enumerates the real server displays:
//
//     __sessionControlRef (SkyLight +0x6305A580)
//         -> [+0x20] -> [+0xd8] -> [+0x298] == PKGSessionDisplayData*
//     PKGSessionDisplayData* -> [+0x00] == DisplaySet (std::vector<PKGDisplay*>)
//     PKGDisplay*            -> [+0x08] CGRect bounds, [+0x2c/+0x34] CFUUIDBytes,
//                               [+0x28] u32 display id, [+0xa8] u8 is_main
//
// This round answers "what is the display's CURRENT scanout surface, and how
// does the server present it" — WITHOUT flipping. Round-3 findings (from
// disassembling SkyLight arm64e, dyld shared cache, macOS 26.5.1 / 25F80):
//
//   * PKGDisplay is the Spaces-layer display. Its constructor
//     PKGDisplay::PKGDisplay(WSDisplayWrapper const&) COPIES metadata (bounds,
//     uuid, id, sarlacc rect) out of the wrapped WS::Displays::Display — it does
//     NOT keep a live pointer to it. So PKGDisplay itself has no surface.
//
//   * The hardware display is WS::Displays::SLCADisplay (subclass of
//     WS::Displays::Display). Its current/front scanout surface is a
//     std::shared_ptr<WS::Displays::CASurface> stored at:
//         [SLCADisplay + 0x2c8] == CASurface*        (the IOSurface-backed CA surface)
//         [SLCADisplay + 0x2d0] == shared_ptr control block
//     and the CA display object it presents into is at [SLCADisplay + 0x1d8].
//     mode_scanout_pixels_wide/high live at [SLCADisplay + 0x634] / [+0x638].
//
//   * The PKGDisplay -> hardware-display bridge is the hidden in-process function
//         WS::Displays::Display*  managed_display_for_pkg_display(PKGDisplay const*)
//     (SkyLight +0x0013CCBC). It does `pkg->vtable[0x18]()` to get the managed
//     display (PKGDisplaySpaceData*) then reads [+0xf0] -> the hardware display.
//     It is a plain `bl`-called global, so rd_sign_fn(addr, 0) works, exactly like
//     current_session_display_data() in round 2.
//
//   * The actual server-side present (NOT called here) is:
//         WS::Displays::SLCADisplay::present_iosurface(__IOSurface*, bool)
//     SkyLight +0x00411F1C. It does objc_msgSend$presentSurface:withOptions: on
//     the CA display ([SLCADisplay+0x1d8]) then set_swapped_iosurface() (which
//     writes +0x2c8/+0x2d0). The low-level primitive
//     WS::Displays::Display::present_ioaccel_surface(IOAccelConnectStruct*,
//         unsigned, IOAccelSurfaceInformation*, unsigned, bool) at +0x001D5764 is
//     an 8-byte base-class stub (returns 1).
//
// THIS PAYLOAD ONLY READS. It never calls present/flip.
//
// Recovered symbol offsets (relative to dladdr dli_fbase == "skyBase";
// slide-independent). All verified against lldb symtab + disassembly:
//   PresentationDisplay::Present()                                +0x000B0148
//   display_present_swap block-invoke helper                      +0x00404418
//   WS::Displays::Display::present_ioaccel_surface(...)           +0x001D5764 (stub)
//   managed_display_for_pkg_display(PKGDisplay const*)           +0x0013CCBC
//   WS::Displays::SLCADisplay::present_iosurface(__IOSurface*,bool)+0x00411F1C
//   WS::Displays::SLCADisplay::set_swapped_iosurface(__IOSurface*)+0x00412824
//   WS::Displays::SLCADisplay::swapped_surface()                 +0x00419190
//   WS::Displays::CAManager()                                    +0x0041BDB0

#import <Foundation/Foundation.h>
#import <IOSurface/IOSurface.h>

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <setjmp.h>
#include <unistd.h>
#include <time.h>
#include <ptrauth.h>

// ---------------------------------------------------------------------------
// Offsets from the SkyLight unslid image base == dladdr dli_fbase (skyBase).
#define OFF_sessionControlRef        (0x6305A580LL)  // __sessionControlRef data global
#define OFF_current_session_data     (0x00457020LL)  // hidden: current_session_display_data()
#define OFF_PKGDisplayGetMain        (0x00456FDCLL)  // hidden: PKGDisplayGetMain()
#define OFF_managed_display_for_pkg  (0x0013CCBCLL)  // hidden: managed_display_for_pkg_display(PKGDisplay const*)
#define OFF_CAManager                (0x0041BDB0LL)  // hidden: WS::Displays::CAManager()

// chain / PKGDisplay object layout (round-2 verified)
#define CH_sessionControlRef_to_p1   (0x20LL)
#define CH_p1_to_p2                  (0xd8LL)
#define CH_p2_to_sessionData         (0x298LL)
#define CH_sessionData_to_DisplaySet (0x00LL)
#define CH_DisplaySet_begin          (0x00LL)
#define CH_DisplaySet_end            (0x08LL)
#define CH_PKGDisplay_bounds         (0x08LL)   // CGRect: 4 doubles
#define CH_PKGDisplay_displayID      (0x28LL)   // u32 (copy of hw display id)
#define CH_PKGDisplay_uuid_lo        (0x2cLL)
#define CH_PKGDisplay_uuid_hi        (0x34LL)
#define CH_PKGDisplay_is_main        (0xa8LL)   // u8

// SLCADisplay (hardware display) object layout — recovered by disassembly.
#define CH_hw_displayID              (0xd8LL)   // u32  (PKGDisplay ctor reads [hw+0xd8])
#define CH_hw_ca_display             (0x1d8LL)  // ptr  (CA display object, presentSurface target)
#define CH_hw_swapped_surface        (0x2c8LL)  // ptr  (CASurface*, the current scanout surface)
#define CH_hw_swapped_ctrl           (0x2d0LL)  // ptr  (shared_ptr control block)
#define CH_hw_swapped_aux_flags      (0x308LL)  // u8
#define CH_hw_scanout_wide           (0x634LL)  // u32  (mode_scanout_pixels_wide)
#define CH_hw_scanout_high           (0x638LL)  // u32  (mode_scanout_pixels_high)

// ---------------------------------------------------------------------------
// Logging (file + NSLog), same style as the original payload.
static char g_logPath[1024] = "/tmp/rdgpu-scanout.log";

static void rlog(const char *fmt, ...) {
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    buf[sizeof buf - 1] = '\0';

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
    NSLog(@"[rdgpu-scanout] %s", buf);
}

// ---------------------------------------------------------------------------
// Fault guard for raw data derefs AND for guarded function calls.
static sigjmp_buf            g_jmp;
static volatile sig_atomic_t g_guarded = 0;

static void rd_guard_handler(int sig, siginfo_t *si, void *ctx) {
    (void)sig; (void)si; (void)ctx;
    if (g_guarded) siglongjmp(g_jmp, 1);
    signal(sig, SIG_DFL);
    raise(sig);
}

#define RD_TRY(label, stmts) do {                                              \
    struct sigaction _o_segv, _o_bus, _o_ill, _sa;                             \
    memset(&_sa, 0, sizeof _sa);                                               \
    _sa.sa_sigaction = rd_guard_handler;                                       \
    _sa.sa_flags = SA_SIGINFO;                                                 \
    sigaction(SIGSEGV, &_sa, &_o_segv);                                        \
    sigaction(SIGBUS,  &_sa, &_o_bus);                                         \
    sigaction(SIGILL,  &_sa, &_o_ill);                                         \
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
} while (0)

// PAC-sign a raw address as a plain (diversity-0) function pointer.
static __attribute__((always_inline)) void* rd_sign_fn(uint64_t addr) {
    return ptrauth_sign_unauthenticated((void*)addr, ptrauth_key_function_pointer, 0);
}

// ---------------------------------------------------------------------------
__attribute__((constructor))
static void rdgpu_readonly3_constructor(void) {
    @autoreleasepool {
        const char *env = getenv("RDGPU_SCANOUT_LOG");
        if (env && env[0]) strlcpy(g_logPath, env, sizeof g_logPath);

        rlog("RDGPU_SCANOUT_LOAD pid=%d mode=readonly3", (int)getpid());

        // ---- dlopen SkyLight ----
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
            rlog("RDGPU_SCANOUT_NOSKYBASE SLSMainDisplayID dladdr failed");
            rlog("RDGPU_SCANOUT_READONLY3_DONE");
            return;
        }

        // ===================================================================
        // PATH 1: enumerate PKGDisplay (round-2 chain) — read-only data walk
        // ===================================================================
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

        // resolve the PKGDisplay -> hardware-display bridge once
        typedef void* (*fn_mdfpd)(void*);
        fn_mdfpd mdfpd = (fn_mdfpd)rd_sign_fn(skyBase + OFF_managed_display_for_pkg);

        if (dset && begin && end && end > begin && (end - begin) < 0x100000) {
            int found = 0;
            for (uint64_t p = begin; p < end && found < 16; p += 8) {
                uint64_t pkg = 0;
                double x = 0, y = 0, w = 0, h = 0;
                uint32_t dispID = 0;
                uint8_t is_main = 0;
                uint64_t uuid_lo = 0, uuid_hi = 0;
                RD_TRY("walk_pkg_display", {
                    pkg = *(uint64_t*)p;
                    if (pkg) {
                        x = *(double*)(pkg + CH_PKGDisplay_bounds + 0x00);
                        y = *(double*)(pkg + CH_PKGDisplay_bounds + 0x08);
                        w = *(double*)(pkg + CH_PKGDisplay_bounds + 0x10);
                        h = *(double*)(pkg + CH_PKGDisplay_bounds + 0x18);
                        dispID  = *(uint32_t*)(pkg + CH_PKGDisplay_displayID);
                        uuid_lo = *(uint64_t*)(pkg + CH_PKGDisplay_uuid_lo);
                        uuid_hi = *(uint64_t*)(pkg + CH_PKGDisplay_uuid_hi);
                        is_main = *(uint8_t*)(pkg + CH_PKGDisplay_is_main);
                    }
                });
                if (!pkg) break;
                rlog("[scanout] pkgdisplay=%p bounds=(%.0f,%.0f %.0fx%.0f) id=0x%x main=%u uuid=%016llx%016llx",
                     (void*)pkg, x, y, w, h, (unsigned)dispID, (unsigned)is_main,
                     (unsigned long long)uuid_lo, (unsigned long long)uuid_hi);

                // ===========================================================
                // PATH 2: map PKGDisplay -> hardware display (SLCADisplay),
                // then READ its current scanout surface. NO flip.
                // ===========================================================
                void *hw = NULL;
                RD_TRY("call_managed_display_for_pkg", {
                    if (mdfpd) hw = mdfpd((void*)pkg);
                });
                rlog("[scanout]   hwdisplay=%p", hw);

                if (hw) {
                    uint64_t H = (uint64_t)hw;
                    uint32_t hid = 0;
                    uint64_t ca_display = 0, surf = 0, ctrl = 0;
                    uint32_t sw = 0, sh = 0;
                    RD_TRY("read_hw_surface", {
                        hid        = *(uint32_t*)(H + CH_hw_displayID);
                        ca_display = *(uint64_t*)(H + CH_hw_ca_display);
                        surf       = *(uint64_t*)(H + CH_hw_swapped_surface);
                        ctrl       = *(uint64_t*)(H + CH_hw_swapped_ctrl);
                        sw         = *(uint32_t*)(H + CH_hw_scanout_wide);
                        sh         = *(uint32_t*)(H + CH_hw_scanout_high);
                    });
                    rlog("[scanout]   hw id=0x%x cadisplay=%p scanout=%ux%u swapped_surface=%p ctrl=%p",
                         (unsigned)hid, (void*)ca_display, (unsigned)sw, (unsigned)sh,
                         (void*)surf, (void*)ctrl);

                    // If the swapped surface looks like a CASurface, try to
                    // read the IOSurface it wraps (CASurface layout:
                    // [surf+0x00]=SLCADisplay*, [surf+0x08]=IOSurface* — best-effort).
                    if (surf) {
                        uint64_t s0 = 0, s8 = 0;
                        RD_TRY("read_casurface", {
                            s0 = *(uint64_t*)(surf + 0x00);
                            s8 = *(uint64_t*)(surf + 0x08);
                        });
                        rlog("[scanout]   casurface[0]=%p casurface[8]=%p (best-effort IOSurface*)",
                             (void*)s0, (void*)s8);
                    }
                }

                // Fallback: if managed_display_for_pkg_display returned a
                // managed-display wrapper (PKGDisplaySpaceData) rather than the
                // hardware display, the hardware display sits at [hw+0xf0].
                // Read that too (guarded) so either interpretation resolves.
                if (hw) {
                    uint64_t hw2 = 0;
                    RD_TRY("read_hw_nested", { hw2 = *(uint64_t*)((uint64_t)hw + 0xf0); });
                    if (hw2 && hw2 != (uint64_t)hw) {
                        uint32_t h2id = 0; uint64_t h2surf = 0, h2ctrl = 0;
                        uint32_t h2w = 0, h2h = 0;
                        RD_TRY("read_hw2_surface", {
                            h2id   = *(uint32_t*)(hw2 + CH_hw_displayID);
                            h2surf = *(uint64_t*)(hw2 + CH_hw_swapped_surface);
                            h2ctrl = *(uint64_t*)(hw2 + CH_hw_swapped_ctrl);
                            h2w    = *(uint32_t*)(hw2 + CH_hw_scanout_wide);
                            h2h    = *(uint32_t*)(hw2 + CH_hw_scanout_high);
                        });
                        rlog("[scanout]   hw[0xf0]=%p id=0x%x scanout=%ux%u swapped_surface=%p ctrl=%p",
                             (void*)hw2, (unsigned)h2id, (unsigned)h2w, (unsigned)h2h,
                             (void*)h2surf, (void*)h2ctrl);
                    }
                }
                found++;
            }
            rlog("RDGPU_SCANOUT_SKY_DONE count=%d", found);
        }

        // NOTE: WS::Displays::CAManager() (SkyLight +0x41BDB0) is intentionally
        // NOT called here — its lazy singleton constructor CAWSManager::CAWSManager
        // (1568-byte CA/IOAccel setup) is WindowServer-only and kills the Dock.
        // In WindowServer it is already constructed; the SLCADisplay surface read
        // above does not need it.

        rlog("RDGPU_SCANOUT_READONLY3_DONE");
    }
}
