// reg_test.c — prove the FULL registration flow the payload will use:
//   gui = bootstrap_look_up_per_user(bp, NULL, uid, &gui)
//   recv = mach_port_allocate(receive) + insert send
//   bootstrap_register(gui, "com.rdgpu.scanouttest", send)
// then verify with bootstrap_look_up + launchctl. SAFE (own uid domain).
//
// Build: clang reg_test.c -o /tmp/reg_test
#include <stdio.h>
#include <string.h>
#include <servers/bootstrap.h>
#include <mach/mach.h>
#include <mach/task_special_ports.h>
#include <dlfcn.h>
#include <unistd.h>
#include <stdlib.h>

typedef kern_return_t (*fn_pu)(mach_port_t bp, const char *name, uid_t uid, mach_port_t *out);

int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    const char *svc = (argc > 1) ? argv[1] : "com.rdgpu.scanout";
    uid_t uid = (uid_t)((argc > 2) ? atoi(argv[2]) : getuid());

    fn_pu pu = (fn_pu)dlsym(RTLD_DEFAULT, "bootstrap_look_up_per_user");
    mach_port_t bp;
    task_get_bootstrap_port(mach_task_self(), &bp);
    printf("self bp=0x%x uid=%d target_svc=%s\n", bp, (int)uid, svc);

    mach_port_t gui = MACH_PORT_NULL;
    kern_return_t k = pu(bp, NULL, uid, &gui);
    printf("look_up_per_user(NULL,%d) kr=%d gui=0x%x\n", (int)uid, k, gui);
    if (k != 0 || gui == MACH_PORT_NULL) { printf("FAIL: no gui port\n"); return 1; }

    // allocate receive + make send
    mach_port_t recv = MACH_PORT_NULL;
    k = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &recv);
    printf("mach_port_allocate kr=%d recv=0x%x\n", k, recv);
    k = mach_port_insert_right(mach_task_self(), recv, recv, MACH_MSG_TYPE_MAKE_SEND);
    printf("insert send kr=%d\n", k);

    name_t nm; memset(nm, 0, sizeof nm); strlcpy(nm, svc, sizeof nm);
    k = bootstrap_register(gui, nm, recv);
    printf("bootstrap_register(gui,%s) kr=%d (%s)\n", svc, k, bootstrap_strerror(k));

    // verify via look_up on gui namespace
    mach_port_t sp = MACH_PORT_NULL;
    k = bootstrap_look_up(gui, svc, &sp);
    printf("bootstrap_look_up(gui,%s) kr=%d port=0x%x\n", svc, k, sp);

    printf("DONE\n");
    // keep the port alive a moment so launchctl can see it (sleep in caller)
    sleep(3);
    return 0;
}
