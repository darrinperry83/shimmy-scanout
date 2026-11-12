// payload_flip2.m — SERVER-side single bounded scanout FLIP (the actual present),
// CORRECTED surface creation.
//
// Same as payload_flip.m, with ONE fix: rd_make_surface no longer uses Objective-C
// boxing (NSNumber `@(...)` / NSDictionary `@{...}`). Those compile to
// objc_msgSend$numberWithUnsignedInt:/numberWithUnsignedLong:/dictionaryWithObjects:…
// selector stubs whose __objc_selrefs are NOT uniqued by the manual (non-dyld)
// injector, so objc_msgSend receives a non-canonical selector and throws:
//     +[NSNumber (dynamic selector)]: unrecognized selector sent to class …
// The surface properties are now built with CFNumberCreate + CFDictionaryCreate
// (plain CoreFoundation C functions, fixed up exactly like the other C imports).
//
// It enumerates the PKGDisplay hidden chain, maps one chosen PKGDisplay ->
// SLCADisplay via get_displayref_for_pkgdisplay_by_uuid, then builds a solid-color
// (magenta 0xFF00FF, BGRA8888) IOSurface sized to the display's scanout WxH and
// PAC-sign-calls:
//
//     WS::Displays::SLCADisplay::present_iosurface(__IOSurface*, bool)
//         SkyLight + 0x00411F1C    (hidden; rd_sign_fn(addr, 0))
//
// ONE display, ONE present. No loop. It momentarily takes over the display's
// front surface (the real scanout) and then stops.
//
// Choosing the display:
//   * default: external display id 0x1e.
//   * RDGPU_FLIP_DISPLAY=<hex id>   e.g. 0x27 for the builtin main display.
//   * RDGPU_FLIP_MAIN=1             flip the display whose is_main flag is set.
//
// The bool argument is "synchronous / vsync-on" (see SKYLIGHT_SCANOUT_ROUND4.md
// and the disassembly of +0x00411F1C):
//   * true  -> vsyncOff=0 in currentSurfaceWithOptions:... (vsync on) and a
//              MetalContext::Flush is issued (external-update path only).
//   * false -> vsync off and no flush.
// For the desktop displays here (flags bit 2 clear: builtin 0x800030e1, external
// 0x80000020) present_iosurface takes the SIMPLE path, which ignores the bool and
// only does objc_msgSend presentSurface:withOptions:(io,nil) + set_swapped_iosurface.
// We pass true anyway (the canonical "sync/wait" value).

#import <Foundation/Foundation.h>
#import <IOSurface/IOSurface.h>
#import <CoreFoundation/CoreFoundation.h>

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
#define OFF_get_displayref_for_pkg   (0x002B9194LL)  // get_displayref_for_pkgdisplay_by_uuid(void* out, PKGDisplay const*)
#define OFF_present_iosurface        (0x00411F1CLL)  // WS::Displays::SLCADisplay::present_iosurface(__IOSurface*, bool)

// chain / PKGDisplay object layout (round-2/4 verified)
#define CH_sessionControlRef_to_p1   (0x20LL)
#define CH_p1_to_p2                  (0xd8LL)
#define CH_p2_to_sessionData         (0x298LL)
#define CH_sessionData_to_DisplaySet (0x00LL)
#define CH_DisplaySet_begin          (0x00LL)
#define CH_DisplaySet_end            (0x08LL)
#define CH_PKGDisplay_bounds         (0x08LL)   // CGRect: 4 doubles
#define CH_PKGDisplay_displayID      (0x28LL)   // u32
#define CH_PKGDisplay_uuid_lo        (0x2cLL)
#define CH_PKGDisplay_uuid_hi        (0x34LL)
#define CH_PKGDisplay_is_main        (0xa8LL)   // u8

// SLCADisplay (hardware display) object layout (round-3/4 verified)
#define CH_hw_displayID              (0xd8LL)   // u32
#define CH_hw_ca_display             (0x1d8LL)  // ptr (CA display, presentSurface target)
#define CH_hw_swapped_surface        (0x2c8LL)  // ptr (CASurface*, current scanout surface)
#define CH_hw_swapped_ctrl           (0x2d0LL)  // ptr (shared_ptr control block)
#define CH_hw_scanout_wide           (0x634LL)  // u32
#define CH_hw_scanout_high           (0x638LL)  // u32
#define CH_hw_present_flags          (0x76cLL)  // u32

// BGRA8888 (kCVPixelFormatType_32BGRA == 'BGRA' == 0x42475241)
#define RD_PIXFMT_BGRA               (0x42475241u)
// magenta 0xFF00FF in BGRA byte order (A<<24|R<<16|G<<8|B)
#define RD_MAGENTA_BGRA              (0xFFFF00FFu)

// ---------------------------------------------------------------------------
// Logging (file + NSLog), same style as the readonly payloads.
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
        rlog("RDGPU_FLIP_GUARD FAULT at %s", (label));                         \
    }                                                                          \
    sigaction(SIGSEGV, &_o_segv, NULL);                                        \
    sigaction(SIGBUS,  &_o_bus,  NULL);                                        \
    sigaction(SIGILL,  &_o_ill,  NULL);                                        \
} while (0)

// PAC-sign a raw address as a plain (diversity-0) function pointer.
static __attribute__((always_inline)) void* rd_sign_fn(uint64_t addr) {
    return ptrauth_sign_unauthenticated((void*)addr, ptrauth_key_function_pointer, 0);
}

// present_iosurface(__IOSurface* io, bool sync) -> int (1 success / 0 failure)
typedef int (*fn_present_iosurface)(void* /*SLCADisplay*/, IOSurfaceRef /*__IOSurface*/, bool);

// Create a solid-color BGRA8888 IOSurface sized w x h, filled with `color`.
// Uses ONLY CoreFoundation C functions (no Objective-C `@()`/`@{}`), so the
// manually-injected payload never performs an objc_msgSend with a non-canonical
// selector (that is what crashed payload_flip.m as +[NSNumber ...]).
static IOSurfaceRef rd_make_surface(uint32_t w, uint32_t h, uint32_t color) {
    if (w == 0 || h == 0) return NULL;
    size_t bpr = (size_t)w * 4;
    size_t alloc = bpr * h;

    const void *keys[5] = {
        kIOSurfaceWidth,
        kIOSurfaceHeight,
        kIOSurfaceBytesPerRow,
        kIOSurfacePixelFormat,
        kIOSurfaceAllocSize,
    };
    int64_t numvals[5] = {
        (int64_t)w,
        (int64_t)h,
        (int64_t)bpr,
        (int64_t)RD_PIXFMT_BGRA,
        (int64_t)alloc,
    };
    CFNumberRef nums[5];
    const void *vals[5];
    for (int i = 0; i < 5; i++) {
        nums[i] = CFNumberCreate(NULL, kCFNumberSInt64Type, &numvals[i]);
        vals[i] = nums[i];
    }

    CFDictionaryRef props = CFDictionaryCreate(NULL, keys, vals, 5,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    IOSurfaceRef io = IOSurfaceCreate(props);

    for (int i = 0; i < 5; i++) { if (nums[i]) CFRelease(nums[i]); }
    if (props) CFRelease(props);
    if (!io) return NULL;

    IOSurfaceLock(io, 0, NULL);
    uint8_t *base = (uint8_t *)IOSurfaceGetBaseAddress(io);
    size_t rowBytes = IOSurfaceGetBytesPerRow(io);
    if (base && rowBytes >= bpr) {
        for (uint32_t y = 0; y < h; y++) {
            uint32_t *pix = (uint32_t *)(base + (size_t)y * rowBytes);
            for (uint32_t x = 0; x < w; x++) pix[x] = color;
        }
    }
    IOSurfaceUnlock(io, 0, NULL);
    return io;
}

// ---------------------------------------------------------------------------
__attribute__((constructor))
static void rdgpu_flip_constructor(void) {
    @autoreleasepool {
        const char *env = getenv("RDGPU_SCANOUT_LOG");
        if (env && env[0]) strlcpy(g_logPath, env, sizeof g_logPath);

        // ---- choose the display to flip ----
        uint32_t want_id = 0x1e;              // default: external display
        int want_main = 0;
        const char *e_disp = getenv("RDGPU_FLIP_DISPLAY");
        if (e_disp && e_disp[0]) {
            want_id = (uint32_t)strtoul(e_disp, NULL, 0);
        } else {
            // Fallback: WindowServer's environment is fixed, so allow the parent
            // to select the display via a plain-text hex file in /tmp instead of
            // rebuilding (e.g. `echo 0x27 > /tmp/rdgpu-flip-display` as root).
            FILE *fsel = fopen("/tmp/rdgpu-flip-display", "r");
            if (fsel) {
                char line[64] = {0};
                if (fgets(line, sizeof line, fsel) && line[0])
                    want_id = (uint32_t)strtoul(line, NULL, 0);
                fclose(fsel);
            }
        }
        const char *e_main = getenv("RDGPU_FLIP_MAIN");
        if (e_main && e_main[0]) want_main = (e_main[0] == '1');

        rlog("RDGPU_FLIP_LOAD pid=%d mode=flip want_id=0x%x want_main=%d",
             (int)getpid(), (unsigned)want_id, want_main);

        // ---- dlopen SkyLight ----
        void *gSkyLight = dlopen("/System/Library/PrivateFrameworks/SkyLight.framework/SkyLight",
                                 RTLD_LAZY | RTLD_LOCAL);
        rlog("RDGPU_FLIP_DLOPEN SkyLight=%p", gSkyLight);

        void *sym_sls_main = dlsym(RTLD_DEFAULT, "SLSMainDisplayID");
        uint64_t skyBase = 0;
        {
            Dl_info info;
            if (sym_sls_main && dladdr(sym_sls_main, &info)) skyBase = (uint64_t)info.dli_fbase;
        }
        rlog("RDGPU_FLIP_BASE skyBase=%p", (void*)skyBase);

        if (!skyBase) {
            rlog("RDGPU_FLIP_NOSKYBASE SLSMainDisplayID dladdr failed");
            rlog("RDGPU_FLIP_DONE result=no-skybase");
            return;
        }

        // resolve the bridges once
        typedef void (*fn_get_displayref)(void*, void*);
        fn_get_displayref getref = (fn_get_displayref)rd_sign_fn(skyBase + OFF_get_displayref_for_pkg);
        fn_present_iosurface present = (fn_present_iosurface)rd_sign_fn(skyBase + OFF_present_iosurface);

        // ---- enumerate the PKGDisplay chain ----
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
        rlog("RDGPU_FLIP_SKYCHEIN ref=%p p1=%p p2=%p sess=%p dset=%p begin=%p end=%p",
             (void*)ref, (void*)p1, (void*)p2, (void*)sess, (void*)dset, (void*)begin, (void*)end);

        int flipped = 0;
        if (dset && begin && end && end > begin && (end - begin) < 0x100000) {
            for (uint64_t p = begin; p < end && !flipped; p += 8) {
                uint64_t pkg = 0;
                uint32_t dispID = 0;
                uint8_t is_main = 0;
                RD_TRY("walk_pkg_display", {
                    pkg = *(uint64_t*)p;
                    if (pkg) {
                        dispID  = *(uint32_t*)(pkg + CH_PKGDisplay_displayID);
                        is_main = *(uint8_t*)(pkg + CH_PKGDisplay_is_main);
                    }
                });
                if (!pkg) break;

                // selection
                int chosen = want_main ? (is_main != 0) : (dispID == want_id);
                rlog("[flip] scan pkgdisplay=%p id=0x%x main=%u chosen=%d",
                     (void*)pkg, (unsigned)dispID, (unsigned)is_main, chosen);
                if (!chosen) continue;

                // map PKGDisplay -> hardware SLCADisplay
                uint64_t refbuf[2] = {0, 0};
                RD_TRY("call_get_displayref", {
                    if (getref) getref(refbuf, (void*)pkg);
                });
                uint64_t hw = refbuf[0];
                if (!hw) {
                    rlog("[flip] display 0x%x: displayref NULL (no hardware display mapped)", (unsigned)dispID);
                    continue;
                }

                uint32_t hid = 0, sw = 0, sh = 0, fl = 0;
                uint64_t ca_display = 0, swap_before = 0;
                RD_TRY("read_hw_fields", {
                    hid        = *(uint32_t*)(hw + CH_hw_displayID);
                    ca_display = *(uint64_t*)(hw + CH_hw_ca_display);
                    swap_before = *(uint64_t*)(hw + CH_hw_swapped_surface);
                    sw         = *(uint32_t*)(hw + CH_hw_scanout_wide);
                    sh         = *(uint32_t*)(hw + CH_hw_scanout_high);
                    fl         = *(uint32_t*)(hw + CH_hw_present_flags);
                });
                rlog("[flip] display=0x%x hw=%p cadisplay=%p scanout=%ux%u flags=0x%x swap_before=%p",
                     (unsigned)hid, (void*)hw, (void*)ca_display,
                     (unsigned)sw, (unsigned)sh, (unsigned)fl, (void*)swap_before);

                if (!ca_display) {
                    rlog("[flip] display 0x%x: cadisplay NULL — SKIP (present would return 0)", (unsigned)hid);
                    break;
                }

                // ---- build the magenta IOSurface sized to the scanout ----
                IOSurfaceRef io = rd_make_surface(sw, sh, RD_MAGENTA_BGRA);
                if (!io) {
                    rlog("[flip] display 0x%x: IOSurfaceCreate FAILED", (unsigned)hid);
                    break;
                }
                rlog("[flip] io=0x%llx id=%u size=%ux%u pixelFormat=0x%x (magenta BGRA)",
                     (unsigned long long)io, (unsigned)IOSurfaceGetID(io),
                     (unsigned)sw, (unsigned)sh, RD_PIXFMT_BGRA);

                // ---- the single bounded flip ----
                int result = -1;
                rlog("[flip] CALL present_iosurface(hw=%p io=%p sync=true) @+0x411F1C",
                     (void*)hw, (void*)io);
                RD_TRY("call_present_iosurface", {
                    if (present) result = present((void*)hw, io, true);
                });

                uint64_t swap_after = 0;
                RD_TRY("read_swap_after", {
                    swap_after = *(uint64_t*)(hw + CH_hw_swapped_surface);
                });
                rlog("[flip] RESULT display=0x%x io=0x%llx result=%d swap_after=%p",
                     (unsigned)hid, (unsigned long long)io, result, (void*)swap_after);

                // NOTE: the IOSurface is intentionally NOT released — the display
                // now holds a reference to it as its front/scanout surface and we
                // must keep it alive for the lifetime of this scanout. One leaked
                // surface in WindowServer is harmless for a bounded single flip.
                flipped = 1;
            }
        }

        rlog("RDGPU_FLIP_DONE result=%s", flipped ? "flipped" : "no-display");
    }
}
