// pu_probe.c — test whether bootstrap_look_up_per_user(bp, NULL, uid, &port)
// returns the per-user gui/<uid> NAMESPACE port (the key to registering a
// service into the console user's domain from a root/system process).
//
// Build: clang pu_probe.c -o /tmp/pu_probe
#include <stdio.h>
#include <string.h>
#include <servers/bootstrap.h>
#include <mach/mach.h>
#include <mach/task_special_ports.h>
#include <dlfcn.h>
#include <unistd.h>

typedef kern_return_t (*fn_pu)(mach_port_t bp, const char *name, uid_t uid, mach_port_t *out);

static void fp(mach_port_t p, const char *label) {
    if (p == MACH_PORT_NULL) { printf("[%s] port NULL\n", label); return; }
    mach_port_t sp;
    kern_return_t k1 = bootstrap_look_up(p, "com.apple.dock.server", &sp);
    printf("[%s] port=0x%x look_up(dock.server)=%d", label, p, k1);
    if (sp) mach_port_deallocate(mach_task_self(), sp);
    mach_port_t sp2 = MACH_PORT_NULL;
    kern_return_t k2 = bootstrap_look_up(p, "com.apple.WindowServer", &sp2);
    printf(" look_up(WindowServer)=%d\n", k2);
    if (sp2) mach_port_deallocate(mach_task_self(), sp2);
}

int main(void) {
    setbuf(stdout, NULL);
    fn_pu pu = (fn_pu)dlsym(RTLD_DEFAULT, "bootstrap_look_up_per_user");
    if (!pu) { printf("dlsym pu failed\n"); return 1; }

    mach_port_t bp;
    task_get_bootstrap_port(mach_task_self(), &bp);
    printf("self bp=0x%x\n", bp);

    mach_port_t p501 = MACH_PORT_NULL;
    kern_return_t k = pu(bp, NULL, (uid_t)501, &p501);
    printf("look_up_per_user(NULL,501) kr=%d port=0x%x\n", k, p501);
    fp(p501, "uid501-null");

    mach_port_t p0 = MACH_PORT_NULL;
    k = pu(bp, NULL, (uid_t)0, &p0);
    printf("look_up_per_user(NULL,0) kr=%d port=0x%x\n", k, p0);
    fp(p0, "uid0-null");

    mach_port_t p88 = MACH_PORT_NULL;
    k = pu(bp, NULL, (uid_t)88, &p88);
    printf("look_up_per_user(NULL,88) kr=%d port=0x%x\n", k, p88);
    fp(p88, "uid88-null");

    return 0;
}
