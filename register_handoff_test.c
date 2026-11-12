// register_handoff_test.c — SAFE uid-501 proof of the exact root-injector register
// + receive-right handoff that ws_inject_manual --register will perform.
//
// Parent (uid 501, own gui/501 domain — permitted):
//   1. task_for_pid(child)  (same-uid child, no root needed)
//   2. bootstrap_look_up_per_user(bp, NULL, getuid(), &gui)  -> gui/501 namespace
//   3. mach_port_allocate(RECEIVE) + insert SEND + bootstrap_register(gui, svc, recv)
//   4. verify bootstrap_look_up(gui, svc) works AND launchctl print gui/501 shows svc
//   5. mach_port_insert_right(child_task, PORT_NAME, recv, MACH_MSG_TYPE_MOVE_RECEIVE)
//   6. send PORT_NAME to the child over a pipe; child mach_msg-receives on that name
//   7. parent sends a test message through the looked-up service send-right
//   8. child receives it, checks the magic, replies OK via the reply port
//
// This proves every primitive the root injector relies on (except task_for_pid on
// uid-88 WindowServer, which requires root).
//
// Build: clang register_handoff_test.c -o /tmp/register_handoff_test
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <servers/bootstrap.h>
#include <mach/mach.h>
#include <mach/message.h>
#include <mach/task_special_ports.h>
#include <dlfcn.h>

#define TEST_SVC     "com.rdgpu.scanout.handofftest"
#define PORT_NAME    ((mach_port_name_t)0x3ee5)   // arbitrary free-ish name in child
#define MAGIC        ((uint32_t)0x5EAF00D5)

typedef kern_return_t (*fn_pu)(mach_port_t bp, const char *name, uid_t uid, mach_port_t *out);

// ---- child: wait for the port name, then receive on it, echo result, exit ----
static int child_main(int fd) {
    mach_port_name_t name = MACH_PORT_NULL;
    ssize_t n = read(fd, &name, sizeof name);
    if (n != (ssize_t)sizeof name) { printf("[child] read pipe fail\n"); return 1; }
    printf("[child] got port name=0x%x\n", name);

    union {
        struct { mach_msg_header_t h; uint32_t magic; } m;
        uint8_t raw[256];
    } u;
    memset(&u, 0, sizeof u);
    kern_return_t kr = mach_msg(&u.m.h, MACH_RCV_MSG, 0, sizeof u.raw,
                                name, 5000, MACH_PORT_NULL);
    printf("[child] mach_msg RCV kr=%d (%s) magic=0x%x remote=0x%x\n",
           kr, mach_error_string(kr), u.m.magic, u.m.h.msgh_remote_port);

    // reply if a reply port came along
    if (kr == KERN_SUCCESS && u.m.h.msgh_remote_port != MACH_PORT_NULL) {
        struct { mach_msg_header_t h; uint32_t magic; } r;
        memset(&r, 0, sizeof r);
        r.h.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
        r.h.msgh_size = sizeof r;
        r.h.msgh_remote_port = u.m.h.msgh_remote_port;
        r.h.msgh_local_port = MACH_PORT_NULL;
        r.h.msgh_id = 0x9999;
        r.magic = MAGIC;
        kr = mach_msg(&r.h, MACH_SEND_MSG, sizeof r, 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
        printf("[child] reply kr=%d (%s)\n", kr, mach_error_string(kr));
    }
    return (kr == KERN_SUCCESS && u.m.magic == MAGIC) ? 0 : 1;
}

int main(void) {
    setbuf(stdout, NULL);

    int pipefd[2];
    if (pipe(pipefd) != 0) { perror("pipe"); return 1; }

    pid_t pid = fork();
    if (pid == 0) { close(pipefd[1]); _exit(child_main(pipefd[0])); }
    close(pipefd[0]);

    // ---- parent ----
    printf("[parent] child pid=%d\n", pid);

    task_t task = MACH_PORT_NULL;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
    printf("[parent] task_for_pid(child) kr=%d (%s) task=0x%x\n", kr, mach_error_string(kr), task);
    if (kr != KERN_SUCCESS || task == MACH_PORT_NULL) { printf("[parent] FAIL task_for_pid\n"); kill(pid, SIGKILL); waitpid(pid, NULL, 0); return 1; }

    fn_pu pu = (fn_pu)dlsym(RTLD_DEFAULT, "bootstrap_look_up_per_user");
    if (!pu) { printf("[parent] FAIL dlsym bootstrap_look_up_per_user\n"); return 1; }

    mach_port_t bp = MACH_PORT_NULL;
    task_get_bootstrap_port(mach_task_self(), &bp);
    printf("[parent] self bp=0x%x uid=%d\n", bp, (int)getuid());

    mach_port_t gui = MACH_PORT_NULL;
    kr = pu(bp, NULL, getuid(), &gui);
    printf("[parent] look_up_per_user(NULL,%d) kr=%d gui=0x%x\n", (int)getuid(), kr, gui);
    if (kr != 0 || gui == MACH_PORT_NULL) { printf("[parent] FAIL gui namespace\n"); return 1; }

    // ---- allocate the receive right DIRECTLY in the child (target) task ----
    mach_port_name_t recv_name = MACH_PORT_NULL;
    kr = mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &recv_name);
    printf("[parent] mach_port_allocate(child, RECEIVE) kr=%d recv_name=0x%x\n", kr, recv_name);
    if (kr != KERN_SUCCESS) { printf("[parent] FAIL alloc in child\n"); kill(pid, SIGKILL); waitpid(pid, NULL, 0); return 1; }

    // ---- extract a send right (into OUR space) for bootstrap_register ----
    mach_port_t send_poly = MACH_PORT_NULL;
    mach_msg_type_name_t send_type = 0;
    kr = mach_port_extract_right(task, recv_name, MACH_MSG_TYPE_MAKE_SEND, &send_poly, &send_type);
    printf("[parent] mach_port_extract_right(child,0x%x,MAKE_SEND) kr=%d send=0x%x type=%d\n",
           recv_name, kr, send_poly, send_type);
    if (kr != KERN_SUCCESS) { printf("[parent] FAIL extract send\n"); kill(pid, SIGKILL); waitpid(pid, NULL, 0); return 1; }

    name_t nm; memset(nm, 0, sizeof nm); strlcpy(nm, TEST_SVC, sizeof nm);
    kr = bootstrap_register(gui, nm, send_poly);
    printf("[parent] bootstrap_register(gui,%s) kr=%d (%s)\n", TEST_SVC, kr, bootstrap_strerror(kr));
    if (kr != BOOTSTRAP_SUCCESS) { printf("[parent] FAIL register\n"); return 1; }
    mach_port_deallocate(mach_task_self(), send_poly);

    // verify lookup on the gui namespace
    mach_port_t sp = MACH_PORT_NULL;
    kr = bootstrap_look_up(gui, TEST_SVC, &sp);
    printf("[parent] bootstrap_look_up(gui,%s) kr=%d port=0x%x\n", TEST_SVC, kr, sp);
    if (sp != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), sp);

    // launchctl check (best-effort)
    {
        char cmd[256];
        snprintf(cmd, sizeof cmd, "launchctl print gui/%d 2>/dev/null | grep -i %s", (int)getuid(), TEST_SVC);
        FILE *f = popen(cmd, "r");
        char line[512]; int found = 0;
        while (f && fgets(line, sizeof line, f)) { printf("[launchctl] %s", line); found = 1; }
        if (f) pclose(f);
        printf("[parent] launchctl found=%d\n", found);
    }

    // ---- the receive right is ALREADY in the child (allocated there); just
    //      hand the NAME to the child over the pipe ----
    mach_port_name_t name = recv_name;
    write(pipefd[1], &name, sizeof name);

    // ---- send a message through the service ----
    sleep(1);   // let child enter mach_msg RCV
    mach_port_t service = MACH_PORT_NULL;
    kr = bootstrap_look_up(gui, TEST_SVC, &service);
    printf("[parent] look_up service kr=%d port=0x%x\n", kr, service);

    mach_port_t reply_port = MACH_PORT_NULL;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &reply_port);

    struct { mach_msg_header_t h; uint32_t magic; } m;
    memset(&m, 0, sizeof m);
    m.h.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    m.h.msgh_size = sizeof m;
    m.h.msgh_remote_port = service;
    m.h.msgh_local_port = reply_port;
    m.h.msgh_id = 0x7777;
    m.magic = MAGIC;
    kr = mach_msg(&m.h, MACH_SEND_MSG, sizeof m, 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    printf("[parent] send kr=%d (%s)\n", kr, mach_error_string(kr));
    mach_port_deallocate(mach_task_self(), service);

    // receive the reply
    union { struct { mach_msg_header_t h; uint32_t magic; } r; uint8_t raw[256]; } rb;
    memset(&rb, 0, sizeof rb);
    kr = mach_msg(&rb.r.h, MACH_RCV_MSG, 0, sizeof rb.raw, reply_port, 5000, MACH_PORT_NULL);
    printf("[parent] reply kr=%d (%s) magic=0x%x\n", kr, mach_error_string(kr), rb.r.magic);

    int st = 0; waitpid(pid, &st, 0);
    printf("[parent] child exit=%d\n", WEXITSTATUS(st));
    int ok = (kr == KERN_SUCCESS && rb.r.magic == MAGIC && WIFEXITED(st) && WEXITSTATUS(st) == 0);
    printf("[parent] %s\n", ok ? "HANDOFF MATCH OK" : "FAIL");
    return ok ? 0 : 1;
}
