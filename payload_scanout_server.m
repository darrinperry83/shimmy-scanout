// payload_scanout_server.m — PERSISTENT server inside WindowServer that streams the
// shim's Hyprland compositor IOSurface straight into the display via the PROVEN
// SLCADisplay::present_iosurface external-update scanout path (flip3), so the shim
// OWNS the screen (no WindowServer re-present).
//
// Builds directly on payload_flip3.m (same offsets, same chain walk, same PAC
// call discipline) plus the Mach service skeleton from rdgpu-scanout-osax/payload.m.
//
// What it does on load (single bounded constructor, arg = injected receive-right NAME):
//   (a) walk PKGDisplay chain -> get_displayref_for_pkgdisplay_by_uuid -> SLCADisplay
//       (target: external 0x1e, overridable via /tmp/rdgpu-scanout-display hex file),
//   (b) set flags[+0x76c] |= 0x4 (keep set: forces the EXTERNAL-UPDATE / real scanout
//       present path), storing the original flags for restore,
//   (c) receive on the service port the ROOT injector already registered in gui/501
//       (ws_inject_manual --register hands the receive-right NAME in via x0); the
//       payload does NOT bootstrap_register (WindowServer euid 88 gets NOT_PRIVILEGED),
//   (d) detach a pthread that serves one present request at a time: on each received
//       rdgpu_present_msg_t IOSurface, PAC-sign-call present_iosurface(hw, io, true).
//
// SAFETY (WindowServer = single injection, restore on failure):
//   * flags[+0x76c] |= 0x4 is only set AFTER the display is mapped AND a receive port
//     is in hand; on any hard fault in the present loop the flags are restored and the
//     server stops, leaving WindowServer compositing normally.
//   * zero objc_msgSend: every surface/property is built with CoreFoundation C calls
//     and raw data derefs, because ws_inject_manual's loader never runs dyld's ObjC
//     selector uniquing (the payload_flip.m +[NSNumber ...] crash).
//
// Build:
//   cd .../integration/rdmetal
//   clang -arch arm64e -bundle payload_scanout_server.m \
//       -o /tmp/rdgpu-scanout-server-payload \
//       -framework Foundation -framework IOSurface -framework CoreFoundation
//   sudo ./ws_inject_manual_d --register /tmp/rdgpu-scanout-server-payload

#import <Foundation/Foundation.h>
#import <IOSurface/IOSurface.h>
#import <CoreFoundation/CoreFoundation.h>

#include <mach/mach.h>
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

// The SAME wire protocol the shim client compiles (rdgpu_scanout_client.m includes
// rdgpu_protocol.h from rdgpu-scanout-osax). Single source of truth: include it by
// absolute path so the two sides can never drift.
#include "/Users/dperry/Documents/Codex/2026-11-07/task/hyprland-stage/metal-wayland-next/rdgpu-scanout-osax/rdgpu_protocol.h"

// ---------------------------------------------------------------------------
// Offsets from the SkyLight unslid image base == dladdr dli_fbase (skyBase).
// Identical to payload_flip3.m (proven this boot, macOS 26.5.1 / 25F80).
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
#define CH_PKGDisplay_displayID      (0x28LL)   // u32
#define CH_PKGDisplay_uuid_lo        (0x2cLL)
#define CH_PKGDisplay_uuid_hi        (0x34LL)
#define CH_PKGDisplay_is_main        (0xa8LL)   // u8

// SLCADisplay (hardware display) object layout (round-3/4 verified)
#define CH_hw_displayID              (0xd8LL)   // u32
#define CH_hw_ca_display             (0x1d8LL)  // ptr
#define CH_hw_swapped_surface        (0x2c8LL)  // ptr
#define CH_hw_swapped_ctrl           (0x2d0LL)  // ptr
#define CH_hw_scanout_wide           (0x634LL)  // u32
#define CH_hw_scanout_high           (0x638LL)  // u32
#define CH_hw_present_flags          (0x76cLL)  // u32

// ---------------------------------------------------------------------------
// Logging (file + NSLog), thread-safe. Same style as payload_flip3.m / payload.m.
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

// PAC-sign a raw address as a plain (diversity-0) function pointer.
static __attribute__((always_inline)) void* rd_sign_fn(uint64_t addr) {
    return ptrauth_sign_unauthenticated((void*)addr, ptrauth_key_function_pointer, 0);
}

// present_iosurface(__IOSurface* io, bool sync) -> int (1 success / 0 failure)
typedef int (*fn_present_iosurface)(void* /*SLCADisplay*/, IOSurfaceRef /*__IOSurface*/, bool);

// ---------------------------------------------------------------------------
// Server state (globals: the constructor returns and its stack is torn down; the
// detached server thread reads these forever).
static uint64_t       g_hw         = 0;     // SLCADisplay*
static uint64_t       g_ca_display = 0;     // CA display (log only)
static uint32_t       g_display_id = 0;     // 0x1e
static uint32_t       g_scanout_w  = 0;
static uint32_t       g_scanout_h  = 0;
static uint32_t       g_flags_orig = 0;
static volatile int   g_flags_set  = 0;     // 1 once flags|=0x4 is applied
static fn_present_iosurface g_present = NULL;

static pthread_mutex_t g_presentLock = PTHREAD_MUTEX_INITIALIZER;
static IOSurfaceRef    g_lastPresented = NULL;   // keep last surface alive across the flip

// ---------------------------------------------------------------------------
// Service registration is now performed by the ROOT injector (ws_inject_manual
// --register), which registers "com.rdgpu.scanout" into gui/501 and hands this
// payload the receive-right NAME as the constructor argument. The payload no
// longer registers anything: WindowServer (euid 88) can look up gui/501 (kr=0)
// but bootstrap_register there fails with BOOTSTRAP_NOT_PRIVILEGED (1100).

// ---------------------------------------------------------------------------
// Restore flags[+0x76c] and hand the display back to WindowServer.
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
// Handle one received present request. Never throws; the present is guarded.
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
        // present_iosurface(io, /*sync*/true): EXTERNAL-UPDATE path (flags bit2 set)
        // copies `io` into the true scanout surface and commits to IOAccel.
        int r = -1;
        pthread_mutex_lock(&g_presentLock);
        RD_TRY("present_iosurface", {
            r = g_present((void*)g_hw, io, true);
        });
        pthread_mutex_unlock(&g_presentLock);
        rc = r;
        rlog("RDGPU_SCANOUT_PRESENT display=0x%x hw=%p iosurface=%u (%zux%zu) ret=%d",
             (unsigned)g_display_id, (void*)g_hw,
             (unsigned)IOSurfaceGetID(io), IOSurfaceGetWidth(io), IOSurfaceGetHeight(io), r);

        if (r <= 0) {
            // present_iosurface returns 0 on failure / the guard caught a hard fault.
            // Restore flags and stop serving rather than risk WindowServer.
            rlog("RDGPU_SCANOUT_PRESENT_FAILED restoring flags and stopping");
            CFRelease(io);
            rd_restore_flags();
            // (thread exits after this handler returns; see rd_server_thread)
            return;
        }

        // Keep the surface alive across the asynchronous scanout; drop the previous.
        CFRetain(io);
        if (g_lastPresented) CFRelease(g_lastPresented);
        g_lastPresented = io;
        CFRelease(io);   // release our local reference from lookup
    }

    // Optional reply so the shim learns the present result (0 == accepted).
    // The client sent msgh_local_port with MACH_MSG_TYPE_MAKE_SEND_ONCE, so the
    // reply port we see here is a SEND-ONCE right: move it, do NOT copy it.
    if (msg->header.msgh_remote_port != MACH_PORT_NULL) {
        rdgpu_reply_t reply;
        memset(&reply, 0, sizeof reply);
        reply.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
        reply.header.msgh_remote_port = msg->header.msgh_remote_port;
        reply.header.msgh_local_port = MACH_PORT_NULL;
        reply.header.msgh_id = msg->header.msgh_id + 1;
        // translate: present_iosurface 1 == success -> 0 == "accepted" (shim convention)
        reply.result = (rc >= 1) ? 0 : (rc < 0 ? rc : -1);
        mach_msg(&reply.header, MACH_SEND_MSG, sizeof reply, 0,
                 MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    }
}

// ---------------------------------------------------------------------------
// Receive loop (detached thread): serve the service port one message at a time.
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
            if (kr == MACH_RCV_INVALID_NAME || kr == MACH_RCV_PORT_DIED) break;
            continue;
        }
        rd_handle_present(&u.msg);
        if (!g_flags_set) { rlog("RDGPU_SCANOUT_SERVER_STOP (flags restored)"); break; }
    }
    rlog("RDGPU_SCANOUT_SERVER_STOP");
    return NULL;
}

// ---------------------------------------------------------------------------
__attribute__((constructor))
static void rdgpu_scanout_constructor(uint64_t injected_recv_port) {
    @autoreleasepool {
        const char *env = getenv("RDGPU_SCANOUT_LOG");
        if (env && env[0]) strlcpy(g_logPath, env, sizeof g_logPath);

        // ---- choose the display ----
        uint32_t want_id = 0x1e;              // default: external display
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

        rlog("RDGPU_SCANOUT_LOAD pid=%d mode=server want_id=0x%x", (int)getpid(), (unsigned)want_id);

        // ---- dlopen SkyLight, resolve base ----
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
        g_present = (fn_present_iosurface)rd_sign_fn(skyBase + OFF_present_iosurface);

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
            return;   // flags untouched — WindowServer fully unaffected
        }

        // ---- (c) receive on the injector-registered service port. The ROOT
        //         injector (ws_inject_manual --register) already registered
        //         "com.rdgpu.scanout" in gui/501 and handed us the receive-right
        //         NAME via this constructor's argument (ctx->recv_port in x0).
        //         Only take over scanout if we actually have a port to serve.
        mach_port_t recv = (mach_port_t)injected_recv_port;
        if (recv == MACH_PORT_NULL) {
            rlog("RDGPU_SCANOUT_DONE result=no-port (injector did not register/hand a receive right)");
            return;
        }
        rlog("RDGPU_SCANOUT_RECV port=%u (injected by root injector)", recv);

        // ---- (b) take over the display: flags[+0x76c] |= 0x4 (keep set). ----
        RD_TRY("set_external_update_flag", {
            *(uint32_t*)(g_hw + CH_hw_present_flags) = g_flags_orig | 0x4u;
        });
        g_flags_set = 1;
        rlog("RDGPU_SCANOUT_FLAGS display=0x%x 0x%x -> 0x%x (external-update path)",
             (unsigned)g_display_id, (unsigned)g_flags_orig, (unsigned)(g_flags_orig | 0x4u));

        // ---- (d) detach the receive loop. ----
        pthread_t t;
        if (pthread_create(&t, NULL, rd_server_thread, (void*)(intptr_t)recv) == 0) {
            pthread_detach(t);
            rlog("RDGPU_SCANOUT_SERVING name=%s port=%u display=0x%x",
                 RDGPU_SERVICE_NAME, recv, (unsigned)g_display_id);
        } else {
            rlog("RDGPU_SCANOUT_THREAD_FAIL (restoring flags)");
            rd_restore_flags();
        }

        rlog("RDGPU_SCANOUT_DONE result=serving");
    }
}
