// payload_readonly.m — READ-ONLY WindowServer-internal display enumeration probe.
//
// This is the SERVER-side replacement for the (failing) client CoreDisplay chain.
// It runs INSIDE WindowServer via ws_inject_manual (manual Mach-O map + chained
// fixups; dlopen is refused by WindowServer's hardened-runtime library-validation).
//
// It does NOT flip/present anything. It only:
//   1. dlsym's the exported data anchor `gWSCallbacks` (in the CoreDisplay data
//      segment), then derives the addresses of the in-process display globals
//      by fixed offsets (stable per macOS build — see disassembly notes below).
//   2. Walks `gWSDeviceList` (the WindowServer-side CGXDisplayDevice linked list)
//      WITHOUT going through any client-mode dispatch (the client path
//      `CoreDisplay_GetDisplayIDList` -> `CGXDisplayDeviceForDisplayID` branches
//      through a NULL gWSCallbacks function pointer and PAC-crashes WindowServer).
//   3. For each device, maps CGXDisplayDevice -> CoreDisplayRef via the exported
//      in-process hash lookup, then gets its current surface + IOSurface, and logs
//      `[scanout] display=… surface=…`.
//
// Symbols + signatures (recovered by disassembly of CoreDisplay.framework,
// macOS 26.5.1 build 25F80, arm64e; file addresses, image base 0x182f30000):
//   CGXDisplayDevice node:  [n+0x00]=next, [n+0x10]=info, [info+0x00]=displayID(u32),
//                           [info+0x128]=online(u8), [info+0x129]=enabled(u8)
//   CoreDisplayRef CoreDisplay_GetDisplayForCGXDisplayDevice(CGXDisplayDevice*)  0x182f69c58  (in-process unordered_map lookup, gDisplayMapLock-guarded)
//   DisplaySurfaceRef CoreDisplay_Display_GetCurrentSurface(CoreDisplayRef)      0x182f3ca80  (in-process)
//   IOSurfaceRef CoreDisplay_DisplaySurface_GetIOSurface(DisplaySurfaceRef)      0x182f67b6c  (ret [surf])
//   int CoreDisplay_Display_PresentIOSurface(CoreDisplayRef, IOSurfaceRef)       0x182f71960  (in-process; -> Display::Present(IOSurface*,PresentSyncType) 0x182f7196c)
//
// Data globals (load addresses this boot; offsets from gWSCallbacks are fixed):
//   gWSCallbacks   0x1eb697220 (exported, dlsym-able anchor)
//   gWSDeviceList  0x1eb696d90  = gWSCallbacks - 0x490
//   gDeviceCount   0x1eb696d98  = gWSCallbacks - 0x488
//   gCGXDisplayROInfo 0x1eb696db8 = gWSCallbacks - 0x468
//   gDisplayState  0x1eb696de8  = gWSCallbacks - 0x438
//   gDisplayMap    0x1ee0c6c48  = gWSCallbacks + 0x2a2fa28  (unordered_map<CGXDisplayDevice*,unique_ptr<Display>>)

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

// ---------------------------------------------------------------------------
// Reconstructed private CoreDisplay prototypes (opaque).
typedef struct __CoreDisplay        *CoreDisplayRef;
typedef struct __CoreDisplaySurface *CoreDisplaySurfaceRef;
typedef struct __CGXDisplayDevice   *CGXDisplayDevice;

typedef CoreDisplayRef       (*fn_GetDisplayForCGXDisplayDevice)(CGXDisplayDevice);
typedef CoreDisplaySurfaceRef(*fn_GetCurrentSurface)(CoreDisplayRef);
typedef IOSurfaceRef         (*fn_SurfaceGetIOSurface)(CoreDisplaySurfaceRef);
typedef int                  (*fn_PresentIOSurface)(CoreDisplayRef, IOSurfaceRef);

// ---------------------------------------------------------------------------
// Offsets from the gWSCallbacks data anchor (macOS 26.5.1 / 25F80).
#define OFF_gWSDeviceList       (-0x490)
#define OFF_gDeviceCount        (-0x488)
#define OFF_gCGXDisplayROInfo   (-0x468)
#define OFF_gDisplayState       (-0x438)
#define OFF_gDisplayMap         (+0x2a2fa28L)

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
// Fault guard for raw data derefs only. (NOT used to call any client-mode
// dispatch function; those branch through NULL gWSCallbacks slots and PAC-crash.)
static sigjmp_buf            g_jmp;
static volatile sig_atomic_t g_guarded = 0;

static void rd_guard_handler(int sig, siginfo_t *si, void *ctx) {
    (void)sig; (void)si; (void)ctx;
    if (g_guarded) siglongjmp(g_jmp, 1);
    signal(sig, SIG_DFL);
    raise(sig);
}

#define RD_TRY(label, stmts) do {                                              \
    struct sigaction _o_segv, _o_bus, _sa;                                     \
    memset(&_sa, 0, sizeof _sa);                                               \
    _sa.sa_sigaction = rd_guard_handler;                                       \
    _sa.sa_flags = SA_SIGINFO;                                                 \
    sigaction(SIGSEGV, &_sa, &_o_segv);                                        \
    sigaction(SIGBUS,  &_sa, &_o_bus);                                         \
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
} while (0)

// ---------------------------------------------------------------------------
__attribute__((constructor))
static void rdgpu_readonly_constructor(void) {
    @autoreleasepool {
        const char *env = getenv("RDGPU_SCANOUT_LOG");
        if (env && env[0]) strlcpy(g_logPath, env, sizeof g_logPath);

        rlog("RDGPU_SCANOUT_LOAD pid=%d mode=readonly", (int)getpid());

        void *gCoreDisplay = dlopen("/System/Library/Frameworks/CoreDisplay.framework/CoreDisplay",
                                    RTLD_LAZY | RTLD_LOCAL);
        if (!gCoreDisplay)
            gCoreDisplay = dlopen("CoreDisplay", RTLD_LAZY | RTLD_LOCAL);
        rlog("RDGPU_SCANOUT_DLOPEN CoreDisplay=%p", gCoreDisplay);

        // ---- resolve exported symbols (dlsym returns PAC-signed fn ptrs) ----
        void *sym_cb = dlsym(RTLD_DEFAULT, "gWSCallbacks");
        fn_GetDisplayForCGXDisplayDevice getRef =
            (fn_GetDisplayForCGXDisplayDevice)dlsym(RTLD_DEFAULT, "CoreDisplay_GetDisplayForCGXDisplayDevice");
        fn_GetCurrentSurface getSurf =
            (fn_GetCurrentSurface)dlsym(RTLD_DEFAULT, "CoreDisplay_Display_GetCurrentSurface");
        fn_SurfaceGetIOSurface surfIO =
            (fn_SurfaceGetIOSurface)dlsym(RTLD_DEFAULT, "CoreDisplay_DisplaySurface_GetIOSurface");
        fn_PresentIOSurface presentIO =
            (fn_PresentIOSurface)dlsym(RTLD_DEFAULT, "CoreDisplay_Display_PresentIOSurface");

        rlog("RDGPU_SCANOUT_SYM gWSCallbacks=%p getRef=%p getSurf=%p surfIO=%p presentIO=%p",
             sym_cb, (void*)getRef, (void*)getSurf, (void*)surfIO, (void*)presentIO);

        if (!sym_cb) {
            rlog("RDGPU_SCANOUT_MISSING_ANCHOR gWSCallbacks");
            return;
        }

        // ---- derive in-process globals from the data anchor ----
        uint64_t cb = (uint64_t)sym_cb;
        uint64_t a_devlist  = cb + OFF_gWSDeviceList;
        uint64_t a_devcount = cb + OFF_gDeviceCount;
        uint64_t a_roinfo   = cb + OFF_gCGXDisplayROInfo;
        uint64_t a_dispstate= cb + OFF_gDisplayState;
        uint64_t a_displaymap = cb + OFF_gDisplayMap;

        uint64_t devlist  = 0, roinfo = 0, dispstate = 0, maphead = 0, mapsize = 0;
        int32_t  devcount = -1;
        RD_TRY("read_globals", {
            devlist   = *(uint64_t*)a_devlist;
            devcount  = *(int32_t*)a_devcount;
            roinfo    = *(uint64_t*)a_roinfo;
            dispstate = *(uint64_t*)a_dispstate;
            maphead   = *(uint64_t*)a_displaymap;
            mapsize   = *(uint64_t*)(a_displaymap + 0x18);
        });

        rlog("RDGPU_SCANOUT_GLOBAL gWSDeviceList=%p gDeviceCount=%d gCGXDisplayROInfo=%p gDisplayState=%p gDisplayMap.head=%p gDisplayMap.size=%llu",
             (void*)devlist, devcount, (void*)roinfo, (void*)dispstate,
             (void*)maphead, (unsigned long long)mapsize);

        if (devlist == 0) {
            rlog("RDGPU_SCANOUT_NODEVICELIST gWSDeviceList is NULL (server list not populated here)");
            rlog("RDGPU_SCANOUT_READONLY_DONE count=0");
            return;
        }

        // ---- walk gWSDeviceList (bounded; raw data derefs guarded) ----
        int found = 0;
        uint64_t node = devlist;
        for (int i = 0; i < 16 && node != 0; i++) {
            uint64_t next = 0, info = 0;
            uint32_t displayID = 0;
            uint8_t  online = 0, enabled = 0;
            RD_TRY("walk_node", {
                next      = *(uint64_t*)(node + 0x00);
                info      = *(uint64_t*)(node + 0x10);
                displayID = *(uint32_t*)(info + 0x00);
                online    = *(uint8_t*)(info + 0x128);
                enabled   = *(uint8_t*)(info + 0x129);
            });
            if (info == 0) { rlog("RDGPU_SCANOUT_BADNODE node=%p", (void*)node); break; }

            rlog("RDGPU_SCANOUT_DEVICE node=%p display=0x%x online=%u enabled=%u",
                 (void*)node, displayID, (unsigned)online, (unsigned)enabled);

            // ---- in-process map: CGXDisplayDevice -> CoreDisplayRef ----
            CoreDisplayRef ref = NULL;
            RD_TRY("get_display_for_device", {
                if (getRef) ref = getRef((CGXDisplayDevice)node);
            });
            rlog("RDGPU_SCANOUT_DISPLAY_REF display=0x%x ref=%p", displayID, (void*)ref);

            // ---- in-process current surface + IOSurface ----
            CoreDisplaySurfaceRef surf = NULL;
            IOSurfaceRef io = NULL;
            RD_TRY("get_surface", {
                if (ref && getSurf) surf = getSurf(ref);
                if (surf && surfIO) io = surfIO(surf);
            });

            if (io) {
                uint32_t id = 0; size_t w = 0, h = 0;
                RD_TRY("iosurface_info", {
                    id = IOSurfaceGetID(io);
                    w  = IOSurfaceGetWidth(io);
                    h  = IOSurfaceGetHeight(io);
                });
                rlog("[scanout] display=0x%x surface=%u (%zux%zu) ref=%p surf=%p io=%p",
                     displayID, id, w, h, (void*)ref, (void*)surf, (void*)io);
                found++;
            } else {
                rlog("[scanout] display=0x%x surface=(none) ref=%p surf=%p",
                     displayID, (void*)ref, (void*)surf);
                found++;
            }

            node = next;
        }

        rlog("RDGPU_SCANOUT_READONLY_DONE count=%d", found);
    }
}
