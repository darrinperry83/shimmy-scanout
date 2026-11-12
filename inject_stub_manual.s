// inject_stub_manual.s — position-independent arm64e shellcode that manually
// loads the rdgpu-scanout payload into a target process WITHOUT dlopen.
//
// Why: WindowServer's hardened runtime has library-validation (flags=0x2000),
// which makes dlopen(ad-hoc payload) return NULL. This stub instead applies the
// payload's arm64e chained fixups by hand and then runs its __init_offsets
// constructor, so the code never goes through dyld's image loader / code-sign
// gate.
//
// Two-stage, exactly like inject_stub.s:
//   * Mach-thread entry: promote to a real pthread via
//     pthread_create_from_mach_thread(), then spin on the 0x79616265 sentinel.
//   * The pthread (worker) reads a loader context (base, fixup program, count,
//     ctor offset, result slot) that the HOST injector already wrote, applies
//     every fixup, calls the constructor, and writes 1 to the result slot.
//
// The host pre-resolves every imported symbol address (shared-cache: same slide
// in the target) and pre-flattens the chained-fixup list into an array of
// 32-byte records. The only work left in the target is PAC-signing (the PAC keys
// are per-process) and the writes.
//
// loader context (40 bytes, written by host):
//    +0x00  uint64_t base       — image base (where __TEXT vmaddr 0 was mapped)
//    +0x08  uint64_t fixups     — pointer to fixup record array
//    +0x10  uint32_t count      — number of records
//    +0x14  uint32_t ctor_off   — __init_offsets value (offset of the constructor)
//    +0x18  uint64_t result     — pointer to result slot (worker writes 1 on success)
//    +0x20  uint64_t recv_port  — receive-right NAME in this task (0 = none); passed
//                                 to the constructor as x0 (the payload receives on it)
//
// fixup record (32 bytes, written by host):
//    +0x00  uint32_t slot       — offset from base of the pointer location
//    +0x04  uint32_t type       — 0 = bind, 1 = auth-bind, 2 = rebase
//    +0x08  uint32_t key        — PAC key (0=IA,1=IB,2=DA,3=DB) for auth-bind
//    +0x0c  uint32_t diversity  — 16-bit PAC diversity for auth-bind
//    +0x10  uint64_t target     — bind: symbol address; rebase: image offset
//    +0x18  uint64_t addend     — bind addend (0 for our payload)

    .text
    .align 4

    .globl _inject_stub_start
    .globl _inject_stub_end
    .globl _inject_stub_pcfmt_ptr
    .globl _inject_stub_ctx_ptr

_inject_stub_start:
    // ---- Mach-thread entry. Never returns; spins with 0x79616265 in x0. ----
    sub     sp, sp, #0x30
    stp     x29, x30, [sp, #0x20]
    add     x29, sp, #0x20
    str     xzr, [sp, #0x8]                 // pthread_t thread = 0
    add     x0, sp, #0x8                    // x0 = &thread
    mov     x1, xzr                         // pthread_attr_t *attr = NULL
    adr     x2, _worker                     // x2 = worker (raw address)
    paciza  x2                              // sign IA, zero context (pthread blraaz's it)
    adr     x9, _inject_stub_ctx_ptr
    ldr     x3, [x9]                        // x3 = loader context pointer
    adr     x9, _inject_stub_pcfmt_ptr
    ldr     x9, [x9]                        // x9 = pthread_create_from_mach_thread
    blr     x9
    movz    x0, #0x6265
    movk    x0, #0x7961, lsl #16            // x0 = 0x79616265  (success sentinel)
_inject_stub_spin:
    b       _inject_stub_spin

    .align 8
_worker:
    // ---- Real pthread: apply fixups, run constructor, report result. ----
    pacibsp                                 // arm64e pthread entry convention
    stp     x29, x30, [sp, #-0x10]!
    mov     x29, sp
    stp     x20, x19, [sp, #-0x10]!
    stp     x22, x21, [sp, #-0x10]!
    stp     x24, x23, [sp, #-0x10]!
    stp     x26, x25, [sp, #-0x10]!
    stp     x28, x27, [sp, #-0x10]!

    // Load loader context (arg = x0).
    ldr     x20, [x0, #0x00]                // x20 = base
    ldr     x21, [x0, #0x08]                // x21 = fixups
    ldr     w22, [x0, #0x10]                // x22 = count
    ldr     w23, [x0, #0x14]                // x23 = ctor_off
    ldr     x24, [x0, #0x18]                // x24 = result slot

    mov     x25, #0                         // i = 0
    cbz     x22, _loop_done

_loop:
    mov     x9, x25
    lsl     x9, x9, #5                      // i * 32
    add     x9, x21, x9                     // x9 = &fixups[i]
    ldr     w10, [x9, #0x00]                // slot offset
    add     x8, x20, x10                    // x8 = base + slot (fixup location)
    ldr     w10, [x9, #0x04]                // type
    ldr     x11, [x9, #0x10]                // target
    cmp     w10, #2
    b.eq    _do_rebase
    cmp     w10, #1
    b.eq    _do_auth_bind

    // plain bind: *loc = target + addend
    ldr     x12, [x9, #0x18]                // addend
    add     x11, x11, x12
    str     x11, [x8]
    b       _next

_do_rebase:
    // *loc = base + target
    add     x11, x20, x11
    str     x11, [x8]
    b       _next

_do_auth_bind:
    // *loc = sign(target, key, blend(loc, diversity))
    ldr     w12, [x9, #0x08]                // key
    ldr     w13, [x9, #0x0c]                // diversity
    mov     x14, x8                         // modifier = loc (addrDiv=1 base)
    cbz     w13, _skip_blend                // diversity==0 -> modifier is just loc
    bfi     x14, x13, #48, #16              // blend: insert diversity into bits 48..63
_skip_blend:
    mov     x15, x11                        // x15 = target to sign
    cmp     w12, #0
    b.eq    _sign_ia
    cmp     w12, #1
    b.eq    _sign_ib
    cmp     w12, #2
    b.eq    _sign_da
    pacdb   x15, x14                        // key = 3 (DB)
    b       _store_auth
_sign_ia:
    pacia   x15, x14
    b       _store_auth
_sign_ib:
    pacib   x15, x14
    b       _store_auth
_sign_da:
    pacda   x15, x14
    b       _store_auth
_store_auth:
    str     x15, [x8]

_next:
    add     x25, x25, #1
    cmp     x25, x22
    b.lo    _loop

_loop_done:
    // Run the constructor with x0 = recv_port (the receive-right NAME the host
    // injector registered + handed us; 0 when not in --register mode).
    ldr     x0, [x0, #0x20]                  // x0 = ctx->recv_port
    add     x16, x20, x23
    paciza  x16
    blraaz  x16
    // Report success.
    mov     x1, #1
    str     x1, [x24]
    mov     x0, xzr                         // pthread returns NULL

    ldp     x28, x27, [sp], #0x10
    ldp     x26, x25, [sp], #0x10
    ldp     x24, x23, [sp], #0x10
    ldp     x22, x21, [sp], #0x10
    ldp     x20, x19, [sp], #0x10
    ldp     x29, x30, [sp], #0x10
    retab

    .align 8
_inject_stub_pcfmt_ptr:
    .quad   0                               // patched: pthread_create_from_mach_thread (stripped)
_inject_stub_ctx_ptr:
    .quad   0                               // patched: remote address of loader context

_inject_stub_end:
