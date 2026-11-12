// dock_inject.m — inject the rdgpu-scanout.osax payload INTO the Dock process.
//
// The Dock's OSAX scripting-addition loader does not map the payload bundle on
// macOS 26.5.1. This tool bypasses that loader entirely and performs a direct
// Mach remote-thread injection (the yabai / newosxbook technique) so that
// dlopen(payload, RTLD_NOW) runs inside the Dock, executing the payload's
// __attribute__((constructor)) — which registers com.rdgpu.scanout and starts
// serving IOSurface presents.
//
// Build:
//   clang -arch arm64e dock_inject.m inject_stub.s -o dock_inject -framework AppKit
//
// The injection path for arm64e is based on yabai's src/osax/loader.m, which in
// turn credits Jeremy Legendre (https://github.com/jslegendre).

#import <AppKit/AppKit.h>
#import <mach/mach.h>
#import <mach/mach_vm.h>
#import <mach/task.h>
#import <mach/thread_act.h>
#import <mach/arm/thread_status.h>
#import <dlfcn.h>
#import <ptrauth.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#define STACK_SIZE  (16 * 1024)
#define RESULT_REGION_SIZE 4096
#define PATH_MAXLEN 1024

// Local thread_convert_thread_state (libsystem_kernel's userspace converter, NOT the MIG RPC).
typedef kern_return_t (*thread_convert_thread_state_fn)(
    thread_act_t thread,
    int direction,
    thread_state_flavor_t flavor,
    thread_state_t in_state,
    mach_msg_type_number_t in_stateCnt,
    thread_state_t out_state,
    mach_msg_type_number_t *out_stateCnt);

// Exported by inject_stub.s (asm label `_inject_stub_*` == C identifier `inject_stub_*`).
extern uint8_t  inject_stub_start[];
extern uint8_t  inject_stub_end[];
extern uint64_t inject_stub_pcfmt_ptr;
extern uint64_t inject_stub_dlopen_ptr;
extern uint64_t inject_stub_result_ptr;
extern char     inject_stub_path[];

static const char *DEFAULT_PAYLOAD =
    "/Users/dperry/Documents/Codex/2026-11-07/task/hyprland-stage/metal-wayland-next/"
    "rdgpu-scanout-osax/rdgpu-scanout.osax/Contents/MacOS/payload";

#define RESULT_SENTINEL 0x5EAF00D5EAF00D5ULL

static void kr_note(kern_return_t kr)
{
    // Map the two task_for_pid gate codes the task calls out, plus a few neighbours.
    switch (kr) {
        case KERN_SUCCESS:          printf("  (KERN_SUCCESS)\n"); break;
        case KERN_INVALID_ARGUMENT: printf("  (KERN_INVALID_ARGUMENT=4)\n"); break;
        case KERN_FAILURE:          printf("  (KERN_FAILURE=5)\n"); break;
        case KERN_NO_ACCESS:        printf("  (KERN_NO_ACCESS=8)\n"); break;
        case KERN_PROTECTION_FAILURE: printf("  (KERN_PROTECTION_FAILURE=2)\n"); break;
        case KERN_INVALID_ADDRESS:  printf("  (KERN_INVALID_ADDRESS=1)\n"); break;
        default:                    printf("\n"); break;
    }
}

static pid_t dock_pid_from_running_apps(void)
{
    NSArray<NSRunningApplication *> *apps =
        [NSRunningApplication runningApplicationsWithBundleIdentifier:@"com.apple.dock"];
    for (NSRunningApplication *app in apps) {
        if (app.isFinishedLaunching && app.processIdentifier > 0) {
            return app.processIdentifier;
        }
    }
    return 0;
}

static pid_t dock_pid_from_pgrep(void)
{
    FILE *fp = popen("pgrep -x Dock", "r");
    if (!fp) return 0;
    char buf[64] = {0};
    pid_t pid = 0;
    if (fgets(buf, sizeof buf, fp)) pid = (pid_t)atoi(buf);
    pclose(fp);
    return pid;
}

int main(int argc, const char **argv)
{
    @autoreleasepool {
        const char *payload_path = (argc > 1) ? argv[1] : DEFAULT_PAYLOAD;

        printf("== dock_inject ==\n");
        printf("payload: %s\n", payload_path);

        if (access(payload_path, R_OK) != 0) {
            printf("FATAL: payload not readable: %s (%s)\n", payload_path, strerror(errno));
            return 1;
        }
        size_t path_len = strlen(payload_path);
        if (path_len + 1 > PATH_MAXLEN) {
            printf("FATAL: payload path too long (%zu > %d)\n", path_len, PATH_MAXLEN);
            return 1;
        }

        // ---- (a) find the Dock pid (or use an explicit pid for testing) ----
        pid_t dock_pid = 0;
        if (argc > 2) {
            dock_pid = (pid_t)atoi(argv[2]);
        }
        if (dock_pid <= 0) dock_pid = dock_pid_from_running_apps();
        if (dock_pid <= 0) dock_pid = dock_pid_from_pgrep();
        if (dock_pid <= 0) {
            printf("FATAL: could not locate Dock pid\n");
            return 1;
        }
        printf("Dock pid: %d\n", dock_pid);

        // ---- (b) task_for_pid ----
        task_t task = MACH_PORT_NULL;
        kern_return_t kr = task_for_pid(mach_task_self(), dock_pid, &task);
        printf("task_for_pid(mach_task_self(), %d, &task) -> kr=%d (%s)",
               dock_pid, kr, mach_error_string(kr));
        kr_note(kr);
        if (kr != KERN_SUCCESS || task == MACH_PORT_NULL) {
            if (kr == KERN_FAILURE) {
                printf("\n"
                       "task_for_pid returned KERN_FAILURE (5): the AMFI/taskgated gate.\n"
                       "Required: CSR_ALLOW_TASK_FOR_PID (csrutil: 'Debugging Restrictions' disabled)\n"
                       "          and/or amfi_get_out_of_my_way=1 boot-arg, and root if the target\n"
                       "          is a different uid. The injector itself does not need an entitlement\n"
                       "          (com.apple.security.get-task-allow is for being *debugged*, not debugging).\n");
            }
            return 2;
        }
        printf("task port: 0x%x\n", task);

        // ---- (c) resolve the two function addresses (shared-cache: same slide in Dock) ----
        void *pcfmt_signed  = dlsym(RTLD_DEFAULT, "pthread_create_from_mach_thread");
        void *dlopen_signed = dlsym(RTLD_DEFAULT, "dlopen");
        if (!pcfmt_signed || !dlopen_signed) {
            printf("FATAL: dlsym failed: pcfmt=%p dlopen=%p\n", pcfmt_signed, dlopen_signed);
            return 1;
        }
        uint64_t pcfmt_raw  = (uint64_t)ptrauth_strip(pcfmt_signed, ptrauth_key_function_pointer);
        uint64_t dlopen_raw = (uint64_t)ptrauth_strip(dlopen_signed, ptrauth_key_function_pointer);
        printf("pthread_create_from_mach_thread: signed=%p stripped=0x%llx\n",
               pcfmt_signed, (unsigned long long)pcfmt_raw);
        printf("dlopen:                           signed=%p stripped=0x%llx\n",
               dlopen_signed, (unsigned long long)dlopen_raw);

        // ---- (d) build a patched copy of the stub ----
        uintptr_t stub_start = (uintptr_t)inject_stub_start;
        uintptr_t stub_end   = (uintptr_t)inject_stub_end;
        size_t stub_size = stub_end - stub_start;
        size_t off_pcfmt  = (uintptr_t)&inject_stub_pcfmt_ptr  - stub_start;
        size_t off_dlopen = (uintptr_t)&inject_stub_dlopen_ptr - stub_start;
        size_t off_result = (uintptr_t)&inject_stub_result_ptr - stub_start;
        size_t off_path   = (uintptr_t)inject_stub_path        - stub_start;
        printf("stub: %zu bytes  (pcfmt@%zu dlopen@%zu result@%zu path@%zu)\n",
               stub_size, off_pcfmt, off_dlopen, off_result, off_path);

        uint8_t *stub = (uint8_t *)malloc(stub_size);
        if (!stub) { printf("FATAL: malloc\n"); return 1; }
        memcpy(stub, (const void *)stub_start, stub_size);
        memcpy(stub + off_pcfmt,  &pcfmt_raw,  8);
        memcpy(stub + off_dlopen, &dlopen_raw, 8);
        snprintf((char *)(stub + off_path), PATH_MAXLEN, "%s", payload_path);

        // ---- (e) remote allocations ----
        mach_vm_address_t remote_stack  = 0;
        mach_vm_address_t remote_result = 0;
        mach_vm_address_t remote_code   = 0;

        kr = mach_vm_allocate(task, &remote_stack, STACK_SIZE, VM_FLAGS_ANYWHERE);
        if (kr != KERN_SUCCESS) {
            printf("FATAL: mach_vm_allocate(stack) kr=%d (%s)\n", kr, mach_error_string(kr));
            return 1;
        }
        kr = mach_vm_allocate(task, &remote_result, RESULT_REGION_SIZE, VM_FLAGS_ANYWHERE);
        if (kr != KERN_SUCCESS) {
            printf("FATAL: mach_vm_allocate(result) kr=%d (%s)\n", kr, mach_error_string(kr));
            return 1;
        }
        kr = mach_vm_allocate(task, &remote_code, stub_size, VM_FLAGS_ANYWHERE);
        if (kr != KERN_SUCCESS) {
            printf("FATAL: mach_vm_allocate(code) kr=%d (%s)\n", kr, mach_error_string(kr));
            return 1;
        }
        printf("remote: stack=0x%llx result=0x%llx code=0x%llx\n",
               (unsigned long long)remote_stack,
               (unsigned long long)remote_result,
               (unsigned long long)remote_code);

        // Patch the result-slot address into the stub now that we know it.
        memcpy(stub + off_result, &remote_result, 8);

        // Initialise the result slot to a sentinel so we can detect "never returned".
        uint64_t result_sentinel = RESULT_SENTINEL;
        kr = mach_vm_write(task, remote_result, (vm_offset_t)&result_sentinel, 8);
        if (kr != KERN_SUCCESS) {
            printf("FATAL: mach_vm_write(result) kr=%d (%s)\n", kr, mach_error_string(kr));
            return 1;
        }

        // Protect stack (RW) and result (RW).
        kr = mach_vm_protect(task, remote_stack, STACK_SIZE, 0, VM_PROT_READ | VM_PROT_WRITE);
        if (kr != KERN_SUCCESS) {
            printf("FATAL: mach_vm_protect(stack) kr=%d (%s)\n", kr, mach_error_string(kr));
            return 1;
        }
        kr = mach_vm_protect(task, remote_result, RESULT_REGION_SIZE, 0, VM_PROT_READ | VM_PROT_WRITE);
        if (kr != KERN_SUCCESS) {
            printf("FATAL: mach_vm_protect(result) kr=%d (%s)\n", kr, mach_error_string(kr));
            return 1;
        }

        // Write the patched stub and mark it R-X.
        kr = mach_vm_write(task, remote_code, (vm_offset_t)stub, (mach_msg_type_number_t)stub_size);
        if (kr != KERN_SUCCESS) {
            printf("FATAL: mach_vm_write(code) kr=%d (%s)\n", kr, mach_error_string(kr));
            return 1;
        }
        kr = mach_vm_protect(task, remote_code, stub_size, 0, VM_PROT_READ | VM_PROT_EXECUTE);
        if (kr != KERN_SUCCESS) {
            printf("FATAL: mach_vm_protect(code) kr=%d (%s)\n", kr, mach_error_string(kr));
            return 1;
        }

        // ---- (f) thread_convert_thread_state (libsystem_kernel local converter) ----
        void *kernel = dlopen("/usr/lib/system/libsystem_kernel.dylib", RTLD_GLOBAL | RTLD_LAZY);
        if (!kernel) {
            printf("FATAL: dlopen libsystem_kernel: %s\n", dlerror());
            return 1;
        }
        thread_convert_thread_state_fn thread_convert =
            (thread_convert_thread_state_fn)dlsym(kernel, "thread_convert_thread_state");
        if (!thread_convert) {
            printf("FATAL: dlsym thread_convert_thread_state: %s\n", dlerror());
            return 1;
        }

        // ---- (g) build thread state, create the running remote thread (macOS >= 14.4 path) ----
        arm_thread_state64_t ts = {};
        arm_thread_state64_t machine_ts = {};
        mach_msg_type_number_t ts_cnt = ARM_THREAD_STATE64_COUNT;
        mach_msg_type_number_t machine_cnt = ARM_THREAD_STATE64_COUNT;
        thread_act_t thread = MACH_PORT_NULL;

        __darwin_arm_thread_state64_set_pc_fptr(
            ts, ptrauth_sign_unauthenticated((void *)remote_code, ptrauth_key_asia, 0));
        __darwin_arm_thread_state64_set_sp(ts, (void *)(uintptr_t)(remote_stack + (STACK_SIZE / 2)));

        kr = thread_create(task, &thread);
        if (kr != KERN_SUCCESS) {
            printf("FATAL: thread_create kr=%d (%s)\n", kr, mach_error_string(kr));
            return 1;
        }

        kr = thread_convert(thread, 2 /* THREAD_CONVERT_THREAD_STATE_FROM_SELF */,
                            ARM_THREAD_STATE64, (thread_state_t)&ts, ts_cnt,
                            (thread_state_t)&machine_ts, &machine_cnt);
        if (kr != KERN_SUCCESS) {
            printf("FATAL: thread_convert_thread_state kr=%d (%s)\n", kr, mach_error_string(kr));
            return 1;
        }

        thread_terminate(thread);
        kr = thread_create_running(task, ARM_THREAD_STATE64,
                                   (thread_state_t)&machine_ts, machine_cnt, &thread);
        if (kr != KERN_SUCCESS) {
            printf("FATAL: thread_create_running kr=%d (%s)\n", kr, mach_error_string(kr));
            return 1;
        }
        printf("remote thread created: port=0x%x\n", thread);

        // ---- (h) wait for the mach thread to reach its sentinel (pthread_create returned) ----
        bool sentinel = false;
        for (int i = 0; i < 100; ++i) {
            arm_thread_state64_t s = {};
            mach_msg_type_number_t cnt = ARM_THREAD_STATE64_COUNT;
            if (thread_get_state(thread, ARM_THREAD_STATE64, (thread_state_t)&s, &cnt) == KERN_SUCCESS) {
                if (s.__x[0] == 0x79616265) { sentinel = true; break; }
            }
            usleep(20000);
        }
        printf("mach-thread sentinel (pthread_create_from_mach_thread returned): %s\n",
               sentinel ? "YES" : "NO");

        // ---- (i) wait for dlopen() to return (constructor runs inside dlopen) ----
        uint64_t dlopen_result = RESULT_SENTINEL;
        for (int i = 0; i < 60; ++i) {           // up to ~6s
            mach_vm_size_t out = 8;
            uint64_t v = RESULT_SENTINEL;
            if (mach_vm_read_overwrite(task, remote_result, 8, (mach_vm_address_t)&v, &out) == KERN_SUCCESS) {
                if (v != RESULT_SENTINEL) { dlopen_result = v; break; }
            }
            usleep(100000);
        }

        printf("dlopen result: ");
        if (dlopen_result == RESULT_SENTINEL) {
            printf("(still sentinel — dlopen never returned; check Dock crash log)\n");
        } else if (dlopen_result == 0) {
            printf("NULL (dlopen FAILED)\n");
        } else {
            printf("0x%llx (SUCCESS — handle returned; constructor ran)\n",
                   (unsigned long long)dlopen_result);
        }

        // ---- (j) cleanup ----
        thread_terminate(thread);
        mach_vm_deallocate(task, remote_code, stub_size);
        mach_vm_deallocate(task, remote_result, RESULT_REGION_SIZE);
        mach_vm_deallocate(task, remote_stack, STACK_SIZE);
        mach_port_deallocate(mach_task_self(), task);

        printf("== done ==\n");
        return 0;
    }
}
