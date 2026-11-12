// payload_scanout_server5.m — server3's persistent scanout server + a HEAP-COPY
// vtable hook (task: fix the round-4/8 shared-cache patch that failed with
// mach_vm_protect kr=2). Instead of writing the read-only shared-cache vtable,
// we COPY the SLCADisplay vtable into a heap buffer, re-sign every entry for its
// NEW address, overwrite slot 0x5d0 (present_iosurface) with a `mov w0,#1; ret`
// stub, DA-sign the copy's address point for the object and rewrite hw+0's vptr.
//
// The vptr at hw+0 is a HEAP object field, so it IS writable. The shared-cache
// vtable is never touched; restore = write the original DA-signed vptr back and
// free the heap copy.
//
// ---------------------------------------------------------------------------
// PAC / ABI FACTS (recovered + reproduced live, macOS 26.5.1 / 25F80 arm64e):
//
//  (1) VPTR (object+0) is DA-key signed:
//        vptr = ptrauth_sign_unauthenticated(vtable_addr_point, DA,
//                    ptrauth_blend_discriminator(hw, VPTR_DISCRIMINATOR))
//      where VPTR_DISCRIMINATOR = 0xc333 = getPointerAuthStableSipHash(
//      "_ZTVN2WS8Displays7DisplayE"). Disassembly evidence (this boot):
//        SLCADisplay::SLCADisplay ctor:
//          adrp x16,#... ; add x16,x16,#... ; add x16,x16,#0x10  (vtable address point)
//          mov x17,x0 ; movk x17,#0xc333,lsl#48 ; pacda x16,x17 ; str x16,[x0]
//        SLCADisplay::present_empty_update / update_cursor_visibility:
//          ldr x16,[x19] ; mov x17,x19 ; movk x17,#0xc333,lsl#48 ; autda x16,x17
//
//  (2) A vtable entry at slot S is IA-key signed with ADDRESS DIVERSITY:
//        entry = ptrauth_sign_unauthenticated(fn, IA,
//                    ptrauth_blend_discriminator(&vtable[S], declkey))
//      where declkey is the 16-bit "declaration discriminator" =
//        getPointerAuthStableSipHash( mangled name of the ORIGINAL method )
//      (the base-class method that first declared the virtual, via
//      ItaniumCXXABI::findOriginalMethod). The call site re-derives it:
//        ldr x8,[x16] ; movk x16,#declkey,lsl#48 ; blraa x8,x16
//      Verified: present_iosurface slot 0x5d0 declkey 0x5a24 == siphash(
//      "_ZN2WS8Displays7Display17present_iosurfaceEP11__IOSurfaceb"); swapped_surface
//      0x4cdc == siphash("_ZN2WS8Displays7Display15swapped_surfaceEv").
//
//  (3) getPointerAuthStableSipHash(s) = (SipHash-2-4_64(s, K) % 0xFFFF) + 1, with
//      key K = {b5 d4 c9 eb 79 10 4a 79 6f ec 8b 1b 42 87 81 d4} (little-endian).
//
//  (4) CONSEQUENCE the round-4 patch missed: the entry signature depends on the
//      ABSOLUTE slot address (the low 48 bits of the discriminator). A plain
//      memcpy of the vtable to a NEW heap address would leave every OTHER entry
//      signed for the shared-cache address => every other virtual call on the
//      display would autda/blraa-fail and crash WindowServer. So we must RE-SIGN
//      all 264 entries for their heap addresses. Declkeys are recovered per entry
//      by brute force (16-bit) + disambiguated with the SipHash above: for
//      overrides the declaring class is Display, so declkey = siphash(name with
//      "11SLCADisplay"->"7Display"); for methods introduced by SLCADisplay it is
//      siphash(name) unchanged. Empirically (this boot): 222 Display overrides,
//      41 SLCADisplay-declared, 1 outlier (copy_to_display_surface, declkey 0x5195
//      read off its call sites) that the brute-force-first-candidate fallback covers.
//
// ---------------------------------------------------------------------------
// The stub makes WindowServer's OWN compositor present a return-1 no-op, while our
// direct present loop keeps calling the ORIGINAL present_iosurface via g_present
// (raw skyBase+0x411F1C, IA-signed diversity-0 — a plain bl-callable symbol).
//
// Build:
//   cd .../integration/rdmetal
//   clang -arch arm64e -O2 -bundle payload_scanout_server5.m \
//       -o /tmp/rdgpu-scanout-server5-payload \
//       -framework Foundation -framework IOSurface -framework CoreFoundation
//   sudo ./ws_inject_manual_d --register /tmp/rdgpu-scanout-server5-payload

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

// VTABLE hook constants (round-8 corrected slot/declkey + this round's vptr disc).
#define CH_vtable_present_slot       (0x5d0LL)   // present_iosurface slot (byte offset from vptr)
#define DECLKEY_PRESENT_IOSURFACE    (0x5a24)    // siphash("_ZN...7Display17present_iosurfaceEP11__IOSurfaceb")
#define VPTR_DISCRIMINATOR           (0xc333)    // siphash("_ZTVN2WS8Displays7DisplayE")
#define VTABLE_TOTAL_SIZE            (0x850LL)   // _ZTVN...SLCADisplayE size (from _ZTV metadata)
#define VTABLE_HEADER                (0x10LL)    // offset-to-top + RTTI before the address point
#define RD_PAGE_SIZE                 (0x4000LL)  // 16 KiB

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
// PAC primitives (always-inline so the 264-entry brute force stays fast even
// without heavy optimisation).
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

// Replace the first "11SLCADisplay" in a mangled name with "7Display" (the
// declaring base class). Returns 1 on success.
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
static int               g_sync_mode = -1;

// vtable heap-copy patch state. Restore = write g_orig_vptr back + free the copy.
static uint64_t       g_orig_vptr     = 0;   // original DA-signed vptr read from hw+0
static uint64_t       g_heap_vtable   = 0;   // heap copy base (= _ZTV equivalent, incl. 0x10 header)
static uint64_t       g_orig_slot     = 0;   // original present_iosurface slot address (log)
static uint64_t       g_orig_signed_entry = 0; // original present_iosurface entry (log)
static uint64_t       g_stub_page     = 0;   // executable stub page (16 KiB)
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
//   raw      = stripped (raw) function address of the entry
//   old_slot = the ORIGINAL shared-cache slot address
//   entry    = the ORIGINAL signed entry value
// Returns 0 on failure (no candidate), else the declkey.
static uint64_t rd_recover_declkey(uint64_t raw, uint64_t old_slot, uint64_t entry) {
    // 16-bit brute force over the declkey; collect every value that reproduces
    // the live signature (usually exactly 1, occasionally 2-5).
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

    // Disambiguate with the ABI hash: declkey = siphash(mangled original method).
    uint16_t h_self = 0, h_disp = 0;
    Dl_info di;
    memset(&di, 0, sizeof di);
    if (dladdr((void*)raw, &di) && di.dli_sname) {
        h_self = rd_siphash_disc(di.dli_sname);
        char sub[1024];
        if (rd_subst_display(di.dli_sname, sub, sizeof sub))
            h_disp = rd_siphash_disc(sub);
    }
    for (int i = 0; i < nc; i++) if (cands[i] == h_disp) return h_disp;   // Display override
    for (int i = 0; i < nc; i++) if (cands[i] == h_self) return h_self;   // SLCADisplay-declared

    // Outlier (e.g. copy_to_display_surface whose declaring base differs): the
    // first candidate is the smallest declkey and matches its call sites (0x5195).
    if (di.dli_sname)
        rlog("RDGPU_SCANOUT_VTABLE_AMBIG name=%s cands=%d first=0x%x (using first)",
             di.dli_sname, nc, cands[0]);
    return cands[0];
}

// ---------------------------------------------------------------------------
// Heap-copy vtable hook: copy SLCADisplay's vtable into the heap, re-sign every
// entry for the new addresses, overwrite slot 0x5d0 with the stub, and rewrite
// hw+0's vptr (DA-signed for the heap copy).
static int rd_patch_vtable_present(uint64_t hw, uint64_t skyBase) {
    (void)skyBase;

    // 1. read + strip the object's vptr (DA-key signed).
    uint64_t vptr = 0;
    RD_TRY("read_vptr", { vptr = *(uint64_t*)hw; });
    if (!vptr) { rlog("RDGPU_SCANOUT_VTABLE_NOVPTR hw=%p", (void*)hw); return -1; }
    uint64_t ap = rd_strip_da(vptr);              // address point (first fn entry)
    uint64_t ztv = ap - VTABLE_HEADER;            // _ZTV (offset-to-top + RTTI header)
    rlog("RDGPU_SCANOUT_VTABLE_READ hw=%p vptr=0x%llx ap=0x%llx ztv=0x%llx",
         (void*)hw, (unsigned long long)vptr,
         (unsigned long long)ap, (unsigned long long)ztv);

    // 2. allocate the heap copy.
    mach_vm_address_t heap = 0;
    kern_return_t kr = mach_vm_allocate(mach_task_self(), &heap, VTABLE_TOTAL_SIZE, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) { rlog("RDGPU_SCANOUT_VTABLE_ALLOC_FAIL kr=%d", kr); return -2; }

    // 3. copy the whole vtable (header + 264 entries).
    RD_TRY("copy_vtable", {
        memcpy((void*)heap, (void*)ztv, VTABLE_TOTAL_SIZE);
    });

    // 4. re-sign every entry for its heap address.
    int nre = 0, namb = 0, nfail = 0;
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

    // 5. executable stub page:  mov w0,#1 (0x52800020) ; ret (0xd65f03c0).
    static const uint8_t stub_code[8] = { 0x20,0x00,0x80,0x52, 0xc0,0x03,0x5f,0xd6 };
    mach_vm_address_t stub = 0;
    kr = mach_vm_allocate(mach_task_self(), &stub, RD_PAGE_SIZE, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) { mach_vm_deallocate(mach_task_self(), heap, VTABLE_TOTAL_SIZE); rlog("RDGPU_SCANOUT_VTABLE_STUB_ALLOC_FAIL kr=%d", kr); return -4; }
    kr = mach_vm_write(mach_task_self(), stub, (vm_offset_t)stub_code, sizeof stub_code);
    if (kr != KERN_SUCCESS) { mach_vm_deallocate(mach_task_self(), stub, RD_PAGE_SIZE); mach_vm_deallocate(mach_task_self(), heap, VTABLE_TOTAL_SIZE); return -5; }
    kr = mach_vm_protect(mach_task_self(), stub, RD_PAGE_SIZE, 0, VM_PROT_READ | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) { mach_vm_deallocate(mach_task_self(), stub, RD_PAGE_SIZE); mach_vm_deallocate(mach_task_self(), heap, VTABLE_TOTAL_SIZE); return -6; }

    // Write the stub into slot 0x5d0 of the HEAP copy, signed with the heap slot
    // address blended with the present_iosurface declkey.
    uint64_t new_slot = heap + VTABLE_HEADER + CH_vtable_present_slot;
    uint64_t signed_stub = rd_sign_ia(stub, rd_blend(new_slot, DECLKEY_PRESENT_IOSURFACE));
    *(uint64_t*)(heap + VTABLE_HEADER + CH_vtable_present_slot) = signed_stub;

    // 6. DA-sign the heap address point for THIS object and rewrite the vptr.
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

        int sync;
        if (g_sync_mode >= 0) {
            sync = g_sync_mode;
        } else {
            sync = (g_frame == 0) ? 1 : 0;
        }

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

        const char *e_sync = getenv("RDGPU_SCANOUT_SYNC");
        if (e_sync && e_sync[0]) g_sync_mode = (strtol(e_sync, NULL, 0) != 0) ? 1 : 0;

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

        rlog("RDGPU_SCANOUT_LOAD pid=%d mode=server5 want_id=0x%x", (int)getpid(), (unsigned)want_id);

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
