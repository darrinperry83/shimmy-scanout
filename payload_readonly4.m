// payload_readonly4.m — READ-ONLY SERVER-side present/scanout surface probe (round 4).
//
// Round 3 mapped PKGDisplay -> hardware display via the hidden bridge
//     managed_display_for_pkg_display(PKGDisplay const*)   (SkyLight +0x0013CCBC)
// which was *believed* to return the WS::Displays::Display* (SLCADisplay*).
// The read-only3 log proved that wrong:
//     hwdisplay=0xc07277480 -> id=0x0 cadisplay=0x0 scanout=0x0 (all-zero)
//     hw[0xf0]=0xc0986d500   -> garbage
//
// Round-4 disassembly of managed_display_for_pkg_display shows it does:
//     r = pkg->vtable[0x18]()      ; vtable[0x18] == (anonymous)::MirrorDisplay::get_master()
//                                  ;   == `return [this + 0xc8]`  (the master MirrorDisplay*)
//     return [r + 0xf0]            ; [master + 0xf0] == PKGDisplaySpaceData*  (the "managed display")
// So the bridge returns a **PKGDisplaySpaceData** (Spaces managed-display state),
// NOT the hardware SLCADisplay. That object's +0xd8/+0x1d8 are Spaces fields, not
// the hardware display id / CA-display, hence the all-zero read.
//
// The CORRECT bridge (round 4) is the hidden in-process helper that maps a
// PKGDisplay to the hardware Display by its CFUUIDBytes via the CA manager:
//     get_displayref_for_pkgdisplay_by_uuid(void* out, PKGDisplay const* pkg)
//         SkyLight +0x002B9194
// It reads pkg->uuid (+0x2c/+0x34), then calls
//     WS::Displays::CAManager().display_by_uuid(CFUUIDBytes)
// which returns a std::shared_ptr<WS::Displays::Display> = { Display*, ctrl } (16
// bytes) written to *out (with a strong retain). Display* is the hardware display
// (an SLCADisplay for a physical desktop display), whose fields are the round-3
// offsets: id u32 @ +0xd8, CA display @ +0x1d8, swapped surface @ +0x2c8, ctrl
// @ +0x2d0, scanout wide/high @ +0x634/+0x638, present flags @ +0x76c.
//
// THIS PAYLOAD ONLY READS. It never calls present/flip.
//
// Recovered symbol offsets (relative to dladdr dli_fbase == "skyBase";
// slide-independent). Verified against lldb symtab + disassembly:
//   managed_display_for_pkg_display(PKGDisplay const*)          +0x0013CCBC (WRONG: -> PKGDisplaySpaceData)
//   get_displayref_for_pkgdisplay_by_uuid(void*, PKGDisplay const*) +0x002B9194 (CORRECT: -> shared_ptr<Display>)
//   WS::Displays::Manager::display_by_uuid(CFUUIDBytes) const   +0x0033E0C0
//   WS::Displays::CAManager()                                   +0x0041BDB0
//   WS::Displays::SLCADisplay::present_iosurface(__IOSurface*,bool) +0x00411F1C (NOT called here)
//   WS::Displays::SLCADisplay::swapped_surface()                +0x00419190

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
#define OFF_get_displayref_for_pkg   (0x002B9194LL)  // hidden: get_displayref_for_pkgdisplay_by_uuid(void* out, PKGDisplay const*)

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
#define CH_PKGDisplay_master         (0xc8LL)   // MirrorDisplay::get_master() -> [this+0xc8]

// SLCADisplay (hardware display) object layout — recovered by round-3 disassembly.
#define CH_hw_displayID              (0xd8LL)   // u32  (PKGDisplay ctor reads [hw+0xd8])
#define CH_hw_ca_display             (0x1d8LL)  // ptr  (CA display object, presentSurface target)
#define CH_hw_swapped_surface        (0x2c8LL)  // ptr  (CASurface*, the current scanout surface)
#define CH_hw_swapped_ctrl           (0x2d0LL)  // ptr  (shared_ptr control block)
#define CH_hw_scanout_wide           (0x634LL)  // u32  (mode_scanout_pixels_wide)
#define CH_hw_scanout_high           (0x638LL)  // u32  (mode_scanout_pixels_high)
#define CH_hw_present_flags          (0x76cLL)  // u32  (present_iosurface flag word)

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
static void rdgpu_readonly4_constructor(void) {
    @autoreleasepool {
        const char *env = getenv("RDGPU_SCANOUT_LOG");
        if (env && env[0]) strlcpy(g_logPath, env, sizeof g_logPath);

        rlog("RDGPU_SCANOUT_LOAD pid=%d mode=readonly4", (int)getpid());

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
            rlog("RDGPU_SCANOUT_READONLY4_DONE");
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

        // resolve the corrected PKGDisplay -> hardware Display bridge once.
        // void get_displayref_for_pkgdisplay_by_uuid(void* out, PKGDisplay const*);
        typedef void (*fn_get_displayref)(void*, void*);
        fn_get_displayref getref = (fn_get_displayref)rd_sign_fn(skyBase + OFF_get_displayref_for_pkg);

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
                // Diagnostic: the round-3 (WRONG) chain, so the log documents it.
                //   get_master() = [pkg+0xc8]; managed display = [[pkg+0xc8]+0xf0]
                // ===========================================================
                uint64_t master = 0, managed = 0;
                RD_TRY("read_wrong_chain", {
                    master = *(uint64_t*)(pkg + CH_PKGDisplay_master);
                    if (master) managed = *(uint64_t*)(master + 0xf0);
                });
                rlog("[scanout]   wrongchain master(pkg+0xc8)=%p managed(master+0xf0)=%p",
                     (void*)master, (void*)managed);

                // ===========================================================
                // PATH 2 (CORRECT): map PKGDisplay -> hardware Display via the
                // CA manager's UUID->Display map, then READ its current scanout
                // surface. NO flip.
                // ===========================================================
                uint64_t refbuf[2] = {0, 0};   // { Display*, control_block* } (16 bytes)
                RD_TRY("call_get_displayref", {
                    if (getref) getref(refbuf, (void*)pkg);
                });
                uint64_t hw = refbuf[0];
                uint64_t hwctrl = refbuf[1];
                rlog("[scanout]   displayref ptr=%p ctrl=%p", (void*)hw, (void*)hwctrl);

                if (hw) {
                    uint64_t H = hw;
                    uint32_t hid = 0;
                    uint64_t ca_display = 0, surf = 0, ctrl = 0;
                    uint32_t sw = 0, sh = 0, fl = 0;
                    RD_TRY("read_hw_surface", {
                        hid        = *(uint32_t*)(H + CH_hw_displayID);
                        ca_display = *(uint64_t*)(H + CH_hw_ca_display);
                        surf       = *(uint64_t*)(H + CH_hw_swapped_surface);
                        ctrl       = *(uint64_t*)(H + CH_hw_swapped_ctrl);
                        sw         = *(uint32_t*)(H + CH_hw_scanout_wide);
                        sh         = *(uint32_t*)(H + CH_hw_scanout_high);
                        fl         = *(uint32_t*)(H + CH_hw_present_flags);
                    });
                    rlog("[scanout]   hw id=0x%x cadisplay=%p scanout=%ux%u swapped_surface=%p ctrl=%p flags=0x%x",
                         (unsigned)hid, (void*)ca_display, (unsigned)sw, (unsigned)sh,
                         (void*)surf, (void*)ctrl, (unsigned)fl);
                    rlog("[scanout]   MATCH id hw=0x%x pkg=0x%x %s",
                         (unsigned)hid, (unsigned)dispID, (hid == dispID) ? "OK" : "MISMATCH");

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
                } else {
                    rlog("[scanout]   displayref NULL (no hardware display mapped)");
                }

                found++;
            }
            rlog("RDGPU_SCANOUT_SKY_DONE count=%d", found);
        }

        rlog("RDGPU_SCANOUT_READONLY4_DONE");
    }
}
