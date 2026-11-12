// payload_readonly2.m — READ-ONLY SERVER-side display enumeration probe (round 2).
//
// Purpose: the round-1 probe proved the CoreDisplay CLIENT-side globals
//   (gWSDeviceList / gDeviceCount / gDisplayMap, derived from the exported
//   `gWSCallbacks` anchor) are all empty inside WindowServer. This probe
//   targets the ACTUAL SERVER-side display storage:
//
//   1. CoreDisplay's SERVER-side hardware display list, reached through the
//      exported (dlsym-able) entry points:
//          CGXDisplayDevice*  CGXMainDisplayDevice(void);
//          CGXDisplayDevice*  CGXNextHardwareDisplayDevice(CGXDisplayDevice*);
//      These are the functions SkyLight itself imports from CoreDisplay to
//      walk the server's CGXDisplayDevice list (gWSDeviceList + gWSCallbacks
//      dispatch). For each device we log displayID + CoreDisplayRef (via the
//      exported in-process `CoreDisplay_GetDisplayForCGXDisplayDevice`).
//
//   2. SkyLight's REAL server display objects (the C++ `WS::Displays` /
//      `PKGDisplay` world), reached READ-ONLY through the global chain that
//      the (hidden) accessor `current_session_display_data()` uses:
//          __sessionControlRef (SkyLight data global)
//              -> [+0x20] -> [+0xd8] -> [+0x298] == PKGSessionDisplayData*
//          PKGSessionDisplayData* -> [+0x00] == DisplaySet*
//          DisplaySet*            -> [+0x00]=begin, [+0x08]=end  (vector<PKGDisplay*>)
//          PKGDisplay*            -> [+0x08]=CGRect bounds, [+0x2c/+0x34]=CFUUIDBytes id
//      This is a pure data walk (no function calls) so it is safe even if the
//      structures shift.
//
//   3. A guarded call to the hidden accessor `current_session_display_data()`
//      (PAC-signed in-process) as independent confirmation of path 2.
//
// It does NOT flip/present anything. Still read-only, no client dispatch.
//
// Recovered symbols + offsets (macOS 26.5.1 build 25F80, arm64e, dyld shared
// cache; SkyLight unslid image base 0x186cda000):
//
//   SkyLight exported anchor (for base resolution):
//     uint32_t SLSMainDisplayID(void)                       off 0x001B903C  (client-only: asserts in server — DO NOT CALL)
//   SkyLight hidden data global (server display registry root):
//     void* __sessionControlRef                             off 0x6305A580
//     chain: [ref] -> +0x20 -> +0xd8 -> +0x298 = PKGSessionDisplayData*
//     PKGSessionDisplayData* -> +0x00 = DisplaySet*
//     DisplaySet* -> +0x00 = begin, +0x08 = end (std::vector<PKGDisplay*>)
//     PKGDisplay*  -> +0x08 = CGRect(x,y,w,h) [4 doubles], +0x2c/+0x34 = CFUUIDBytes
//   SkyLight hidden functions (present path is a follow-up):
//     PKGSessionDisplayData* current_session_display_data(void) off 0x00457020
//     PKGDisplay* PKGDisplayGetMain(void)                     off 0x00456FDC
//     PKGDisplay* PKGDisplayWithIdentifier(CFStringRef)       off 0x0045707C
//     void PKGDisplayCreateList(int)                          off 0x00457468
//     int WS::Displays::Display::present_ioaccel_surface(...) off 0x001D5764  (stub: returns 1)
//
//   CoreDisplay exported (dlsym-able) server entry points:
//     CGXDisplayDevice* CGXNextHardwareDisplayDevice(CGXDisplayDevice*) (file 0x182ffa544)
//         -- SAFE: pure data walk, no gWSCallbacks dispatch. NULL -> gWSDeviceList.
//     CoreDisplayRef    CoreDisplay_GetDisplayForCGXDisplayDevice(CGXDisplayDevice*) (file 0x182f69c58)
//     NOTE: CGXMainDisplayDevice() is NOT used here — it does `blraaz`
//           gWSCallbacks->slot_0x1c0 (a PAC-signed-null in the Dock), which
//           raises an UNCATCHABLE PAC exception (SIGKILL). Dock crash proved it.
//   CGXDisplayDevice node layout (confirmed by disassembly):
//     [node+0x00]=next, [node+0x10]=info, [info+0x00]=displayID(u32),
//     [info+0x128]=online(u8), [info+0x129]=enabled(u8)

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
// Reconstructed private CoreDisplay prototypes (opaque).
typedef struct __CoreDisplay        *CoreDisplayRef;
typedef struct __CGXDisplayDevice   *CGXDisplayDevice;

typedef CGXDisplayDevice (*fn_CGXNextHardwareDisplayDevice)(CGXDisplayDevice);
typedef CoreDisplayRef   (*fn_GetDisplayForCGXDisplayDevice)(CGXDisplayDevice);
typedef int              (*fn_PresentIOSurface)(CoreDisplayRef, IOSurfaceRef);

// ---------------------------------------------------------------------------
// Offsets from the SkyLight unslid image base (macOS 26.5.1 / 25F80).
#define OFF_SLSMainDisplayID        (0x001B903CLL)  // exported, used only as a base anchor
#define OFF_sessionControlRef       (0x6305A580LL)  // __sessionControlRef data global
#define OFF_current_session_data    (0x00457020LL)  // hidden: current_session_display_data()
#define OFF_PKGDisplayGetMain       (0x00456FDCLL)  // hidden: PKGDisplayGetMain()

// chain / object layout
#define CH_sessionControlRef_to_p1  (0x20LL)
#define CH_p1_to_p2                 (0xd8LL)
#define CH_p2_to_sessionData        (0x298LL)
#define CH_sessionData_to_DisplaySet (0x00LL)
#define CH_DisplaySet_begin         (0x00LL)
#define CH_DisplaySet_end           (0x08LL)
#define CH_PKGDisplay_bounds        (0x08LL)        // CGRect: 4 doubles (x,y,w,h)
#define CH_PKGDisplay_uuid_lo       (0x2cLL)
#define CH_PKGDisplay_uuid_hi       (0x34LL)

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
        // fallback: per-uid path (e.g. the default is owned by _windowserver)
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
static void rdgpu_readonly2_constructor(void) {
    @autoreleasepool {
        const char *env = getenv("RDGPU_SCANOUT_LOG");
        if (env && env[0]) strlcpy(g_logPath, env, sizeof g_logPath);

        rlog("RDGPU_SCANOUT_LOAD pid=%d mode=readonly2", (int)getpid());

        // ---- dlopen CoreDisplay + SkyLight ----
        void *gCoreDisplay = dlopen("/System/Library/Frameworks/CoreDisplay.framework/CoreDisplay",
                                    RTLD_LAZY | RTLD_LOCAL);
        if (!gCoreDisplay)
            gCoreDisplay = dlopen("CoreDisplay", RTLD_LAZY | RTLD_LOCAL);
        void *gSkyLight = dlopen("/System/Library/PrivateFrameworks/SkyLight.framework/SkyLight",
                                 RTLD_LAZY | RTLD_LOCAL);
        rlog("RDGPU_SCANOUT_DLOPEN CoreDisplay=%p SkyLight=%p", gCoreDisplay, gSkyLight);

        // ---- resolve exported symbols (dlsym returns PAC-signed fn ptrs) ----
        void *sym_cb = dlsym(RTLD_DEFAULT, "gWSCallbacks");
        void *sym_sls_main = dlsym(RTLD_DEFAULT, "SLSMainDisplayID");
        fn_CGXNextHardwareDisplayDevice nextDev =
            (fn_CGXNextHardwareDisplayDevice)dlsym(RTLD_DEFAULT, "CGXNextHardwareDisplayDevice");
        fn_GetDisplayForCGXDisplayDevice getRef =
            (fn_GetDisplayForCGXDisplayDevice)dlsym(RTLD_DEFAULT, "CoreDisplay_GetDisplayForCGXDisplayDevice");
        fn_PresentIOSurface presentIO =
            (fn_PresentIOSurface)dlsym(RTLD_DEFAULT, "CoreDisplay_Display_PresentIOSurface");

        rlog("RDGPU_SCANOUT_SYM gWSCallbacks=%p SLSMainDisplayID=%p nextDev=%p getRef=%p presentIO=%p",
             sym_cb, sym_sls_main, (void*)nextDev, (void*)getRef, (void*)presentIO);

        // ---- resolve image bases via dladdr (robust vs ASLR slide) ----
        uint64_t skyBase = 0, cdBase = 0;
        {
            Dl_info info;
            if (sym_sls_main && dladdr(sym_sls_main, &info)) skyBase = (uint64_t)info.dli_fbase;
            if (sym_cb && dladdr(sym_cb, &info)) cdBase = (uint64_t)info.dli_fbase;
        }
        rlog("RDGPU_SCANOUT_BASE skyBase=%p cdBase=%p", (void*)skyBase, (void*)cdBase);

        // ===================================================================
        // PATH 0: dump gWSCallbacks fields to see which dispatch slots are set
        // ===================================================================
        if (sym_cb) {
            uint64_t cb = (uint64_t)sym_cb;
            uint64_t f[6];
            RD_TRY("read_gWSCallbacks", {
                f[0] = *(uint64_t*)(cb + 0x00);
                f[1] = *(uint64_t*)(cb + 0x08);
                f[2] = *(uint64_t*)(cb + 0x10);
                f[3] = *(uint64_t*)(cb + 0x18);
                f[4] = *(uint64_t*)(cb + 0x1c0);
                f[5] = *(uint64_t*)(cb + 0x3e0);
            });
            rlog("RDGPU_SCANOUT_WSCB f0=%p f8=%p f10=%p f18=%p f1c0=%p f3e0=%p",
                 (void*)f[0], (void*)f[1], (void*)f[2], (void*)f[3], (void*)f[4], (void*)f[5]);
        }

        // ===================================================================
        // PATH 1: CoreDisplay SERVER-side hardware display list (dlsym-able)
        //   CGXNextHardwareDisplayDevice(NULL) -> gWSDeviceList (safe, no PAC)
        // ===================================================================
        if (nextDev) {
            int found = 0;
            CGXDisplayDevice cur = NULL;
            RD_TRY("CGXNextHardwareDisplayDevice_first", { cur = nextDev(NULL); });
            rlog("RDGPU_SCANOUT_CGXHEAD CGXNextHardwareDisplayDevice(NULL)=%p", (void*)cur);

            for (int i = 0; i < 16 && cur != NULL; i++) {
                uint64_t next = 0, info = 0;
                uint32_t displayID = 0;
                uint8_t online = 0, enabled = 0;
                RD_TRY("walk_cgx_node", {
                    next      = *(uint64_t*)((uint64_t)cur + 0x00);
                    info      = *(uint64_t*)((uint64_t)cur + 0x10);
                    displayID = *(uint32_t*)(info + 0x00);
                    online    = *(uint8_t*)(info + 0x128);
                    enabled   = *(uint8_t*)(info + 0x129);
                });
                if (info == 0) { rlog("RDGPU_SCANOUT_CGXBADNODE node=%p", (void*)cur); break; }

                CoreDisplayRef ref = NULL;
                RD_TRY("get_display_for_device", {
                    if (getRef) ref = getRef(cur);
                });
                rlog("[scanout] display=0x%x online=%u enabled=%u node=%p ref=%p",
                     displayID, (unsigned)online, (unsigned)enabled, (void*)cur, (void*)ref);
                found++;
                cur = (CGXDisplayDevice)next;
            }
            rlog("RDGPU_SCANOUT_CGX_DONE count=%d", found);
        } else {
            rlog("RDGPU_SCANOUT_NOCGXSYM nextDev=%p", (void*)nextDev);
        }

        // ===================================================================
        // PATH 2: SkyLight server display registry — READ-ONLY data walk
        // ===================================================================
        if (skyBase) {
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

            if (dset && begin && end && end > begin && (end - begin) < 0x100000) {
                int found = 0;
                for (uint64_t p = begin; p < end && found < 16; p += 8) {
                    uint64_t pkg = 0;
                    double x = 0, y = 0, w = 0, h = 0;
                    uint64_t uuid_lo = 0, uuid_hi = 0;
                    RD_TRY("walk_pkg_display", {
                        pkg = *(uint64_t*)p;
                        if (pkg) {
                            x = *(double*)(pkg + CH_PKGDisplay_bounds + 0x00);
                            y = *(double*)(pkg + CH_PKGDisplay_bounds + 0x08);
                            w = *(double*)(pkg + CH_PKGDisplay_bounds + 0x10);
                            h = *(double*)(pkg + CH_PKGDisplay_bounds + 0x18);
                            uuid_lo = *(uint64_t*)(pkg + CH_PKGDisplay_uuid_lo);
                            uuid_hi = *(uint64_t*)(pkg + CH_PKGDisplay_uuid_hi);
                        }
                    });
                    if (!pkg) break;
                    rlog("[scanout] pkgdisplay=%p bounds=(%.0f,%.0f %.0fx%.0f) uuid=%016llx%016llx",
                         (void*)pkg, x, y, w, h,
                         (unsigned long long)uuid_lo, (unsigned long long)uuid_hi);
                    found++;
                }
                rlog("RDGPU_SCANOUT_SKY_DONE count=%d", found);
            }
        } else {
            rlog("RDGPU_SCANOUT_NOSKYBASE skyBase=0 (SLSMainDisplayID dladdr failed)");
        }

        // ===================================================================
        // PATH 3: guarded call to hidden accessor current_session_display_data()
        // ===================================================================
        if (skyBase) {
            void *sess2 = NULL;
            RD_TRY("call_current_session_display_data", {
                typedef void* (*fn_session)(void);
                fn_session f = (fn_session)rd_sign_fn(skyBase + OFF_current_session_data);
                sess2 = f();
            });
            rlog("RDGPU_SCANOUT_SKYCALL current_session_display_data()=%p", (void*)sess2);

            void *main2 = NULL;
            RD_TRY("call_PKGDisplayGetMain", {
                typedef void* (*fn_main)(void);
                fn_main f = (fn_main)rd_sign_fn(skyBase + OFF_PKGDisplayGetMain);
                main2 = f();
            });
            rlog("RDGPU_SCANOUT_SKYMAIN PKGDisplayGetMain()=%p", (void*)main2);
        }

        rlog("RDGPU_SCANOUT_READONLY2_DONE");
    }
}
