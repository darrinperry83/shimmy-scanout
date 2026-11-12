// inject_stub.s — position-independent arm64e shellcode injected into the Dock.
//
// The entry point is a bare Mach thread. A bare Mach thread has no pthread/TLS, so
// calling straight into libc (dlopen) would fault. We therefore promote ourselves to a
// real pthread via pthread_create_from_mach_thread(), and the *pthread* then dlopen()s
// the payload bundle so its __attribute__((constructor)) runs in the Dock's context.
//
// PAC notes (arm64e): the entry thread signs the pthread entry function with `paciza`
// (IA key, zero context); pthread invokes it with `blraa` (IA key, zero context), so the
// signature matches. The pthread entry uses the standard arm64e convention (pacibsp
// prologue / retab epilogue). The two function addresses (pthread_create_from_mach_thread
// and dlopen) are stored STRIPPED of PAC (see dock_inject.m) and are branched to with a
// plain `blr`.

    .text
    .align 4

    .globl _inject_stub_start
    .globl _inject_stub_end
    .globl _inject_stub_pcfmt_ptr
    .globl _inject_stub_dlopen_ptr
    .globl _inject_stub_result_ptr
    .globl _inject_stub_path

_inject_stub_start:
    // ---- Mach-thread entry. Never returns; spins with the 0x79616265 sentinel in x0. ----
    sub     sp, sp, #0x30
    stp     x29, x30, [sp, #0x20]
    add     x29, sp, #0x20
    str     xzr, [sp, #0x8]                 // pthread_t thread = 0
    add     x0, sp, #0x8                    // x0 = &thread
    mov     x1, xzr                         // pthread_attr_t *attr = NULL
    adr     x2, _inject_stub_thread         // x2 = thread function (raw address)
    paciza  x2                              // sign IA, zero context (matches blraa)
    mov     x3, xzr                         // thread arg = NULL
    adr     x9, _inject_stub_pcfmt_ptr
    ldr     x9, [x9]                        // x9 = pthread_create_from_mach_thread
    blr     x9
    movz    x0, #0x6265
    movk    x0, #0x7961, lsl #16            // x0 = 0x79616265  (success sentinel)
_inject_stub_spin:
    b       _inject_stub_spin

    .align 8
_inject_stub_thread:
    // ---- Real pthread. Runs dlopen(payload_path, RTLD_NOW), stores result, returns. ----
    pacibsp                                 // arm64e pthread entry convention
    sub     sp, sp, #0x30
    stp     x29, x30, [sp, #0x20]
    add     x29, sp, #0x20
    mov     x1, #2                          // RTLD_NOW
    adr     x0, _inject_stub_path           // x0 = payload path
    adr     x9, _inject_stub_dlopen_ptr
    ldr     x9, [x9]                        // x9 = dlopen
    blr     x9                              // handle = dlopen(path, RTLD_NOW)
    adr     x9, _inject_stub_result_ptr
    ldr     x9, [x9]                        // x9 = &remote result slot
    str     x0, [x9]                        // *result_slot = handle
    mov     x0, xzr                         // pthread returns NULL
    ldp     x29, x30, [sp, #0x20]
    add     sp, sp, #0x30
    retab

    .align 8
_inject_stub_pcfmt_ptr:
    .quad   0                               // patched: pthread_create_from_mach_thread (stripped)
_inject_stub_dlopen_ptr:
    .quad   0                               // patched: dlopen (stripped)
_inject_stub_result_ptr:
    .quad   0                               // patched: remote address of the result slot
_inject_stub_path:
    .space  1024, 0                         // patched: absolute payload path (NUL-terminated)

_inject_stub_end:
