// e2e_mach_test.c — END-TO-END proof of the com.rdgpu.scanout Mach service +
// rdgpu_present_msg_t protocol, using the exact payload-side registration path
// (bootstrap_look_up_per_user(NULL,uid) -> gui/<uid> -> bootstrap_register) and
// the exact shim-client send path (IOSurfaceCreateMachPort + mach_msg + reply).
//
// The only difference from production: the server "present" is a no-op that logs
// the received IOSurface id/size instead of SLCADisplay::present_iosurface (which
// needs WindowServer). This runs entirely as the console user — safe, no root.
//
// Build: clang e2e_mach_test.c -o /tmp/e2e_mach_test -framework IOSurface -framework CoreFoundation
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <servers/bootstrap.h>
#include <mach/mach.h>
#include <mach/message.h>
#include <mach/task_special_ports.h>
#include <IOSurface/IOSurface.h>
#include <dlfcn.h>
#include <sys/wait.h>

#include "/Users/dperry/Documents/Codex/2026-11-07/task/hyprland-stage/metal-wayland-next/rdgpu-scanout-osax/rdgpu_protocol.h"

typedef kern_return_t (*fn_pu)(mach_port_t bp, const char *name, uid_t uid, mach_port_t *out);

static int server_main(const char *svc) {
    kern_return_t kr;
    mach_port_t recv = MACH_PORT_NULL;
    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &recv);
    mach_port_insert_right(mach_task_self(), recv, recv, MACH_MSG_TYPE_MAKE_SEND);

    mach_port_t bp;
    task_get_bootstrap_port(mach_task_self(), &bp);
    fn_pu pu = (fn_pu)dlsym(RTLD_DEFAULT, "bootstrap_look_up_per_user");
    mach_port_t gui = MACH_PORT_NULL;
    uid_t uid = getuid();
    kr = pu(bp, NULL, uid, &gui);
    printf("[server] look_up_per_user(NULL,%d) kr=%d gui=0x%x\n", (int)uid, kr, gui);
    if (kr != 0 || gui == MACH_PORT_NULL) { printf("[server] FAIL no gui port\n"); return 1; }

    name_t nm; memset(nm, 0, sizeof nm); strlcpy(nm, svc, sizeof nm);
    kr = bootstrap_register(gui, nm, recv);
    printf("[server] bootstrap_register(gui,%s) kr=%d\n", svc, kr);
    if (kr != 0) return 1;

    // receive one message
    union { rdgpu_present_msg_t msg; uint8_t raw[4096]; } u;
    memset(&u, 0, sizeof u);
    kr = mach_msg(&u.msg.header, MACH_RCV_MSG, 0, sizeof u.raw, recv, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    printf("[server] mach_msg rcv kr=%d id=0x%x desc_count=%u\n", kr, u.msg.header.msgh_id, u.msg.body.msgh_descriptor_count);

    IOSurfaceRef io = NULL;
    if (u.msg.body.msgh_descriptor_count >= 1 && u.msg.surface_port.type == MACH_MSG_PORT_DESCRIPTOR) {
        mach_port_name_t sp = u.msg.surface_port.name;
        io = IOSurfaceLookupFromMachPort(sp);
        printf("[server] surface_port=%u -> IOSurface %p id=%u %zux%zu disp_index=%u\n",
               sp, (void*)io, (unsigned)IOSurfaceGetID(io), IOSurfaceGetWidth(io), IOSurfaceGetHeight(io), u.msg.display_index);
        mach_port_deallocate(mach_task_self(), sp);
    }

    // reply
    if (u.msg.header.msgh_remote_port != MACH_PORT_NULL) {
        rdgpu_reply_t reply;
        memset(&reply, 0, sizeof reply);
        reply.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
        reply.header.msgh_remote_port = u.msg.header.msgh_remote_port;
        reply.header.msgh_local_port = MACH_PORT_NULL;
        reply.header.msgh_id = u.msg.header.msgh_id + 1;
        reply.result = (io != NULL) ? 0 : -1;   // 0 == accepted
        kr = mach_msg(&reply.header, MACH_SEND_MSG, sizeof reply, 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
        printf("[server] reply sent kr=%d (%s) result=%d reply_port=0x%x\n",
               kr, mach_error_string(kr), reply.result, u.msg.header.msgh_remote_port);
    }
    if (io) CFRelease(io);
    return 0;
}

static int client_main(const char *svc) {
    // create a small magenta IOSurface (like flip3's)
    uint32_t w = 64, h = 64, pixfmt = 0x42475241;
    const void *keys[4] = { kIOSurfaceWidth, kIOSurfaceHeight, kIOSurfacePixelFormat, kIOSurfaceAllocSize };
    int64_t vals[4] = { w, h, pixfmt, (int64_t)w*h*4 };
    CFNumberRef nums[4]; const void *v[4];
    for (int i = 0; i < 4; i++) { nums[i] = CFNumberCreate(NULL, kCFNumberSInt64Type, &vals[i]); v[i] = nums[i]; }
    CFDictionaryRef props = CFDictionaryCreate(NULL, keys, v, 4, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    IOSurfaceRef io = IOSurfaceCreate(props);
    for (int i = 0; i < 4; i++) CFRelease(nums[i]);
    CFRelease(props);

    mach_port_t surface_port = IOSurfaceCreateMachPort(io);
    printf("[client] IOSurface id=%u surface_port=0x%x\n", (unsigned)IOSurfaceGetID(io), surface_port);

    mach_port_t bp; task_get_bootstrap_port(mach_task_self(), &bp);
    mach_port_t service = MACH_PORT_NULL;
    kern_return_t kr = bootstrap_look_up(bp, svc, &service);
    if (kr != 0) { fn_pu pu = (fn_pu)dlsym(RTLD_DEFAULT, "bootstrap_look_up_per_user"); kr = pu(bp, svc, getuid(), &service); }
    printf("[client] look_up(%s) kr=%d service=0x%x\n", svc, kr, service);

    mach_port_t reply_port = MACH_PORT_NULL;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &reply_port);

    rdgpu_present_msg_t msg;
    memset(&msg, 0, sizeof msg);
    msg.header.msgh_bits = MACH_MSGH_BITS_COMPLEX | MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    msg.header.msgh_size = sizeof msg;   // REQUIRED: memset leaves it 0 -> MACH_SEND_INVALID_HEADER
    msg.header.msgh_remote_port = service;
    msg.header.msgh_local_port = reply_port;
    msg.header.msgh_id = RDGPU_MSG_ID_PRESENT;
    msg.body.msgh_descriptor_count = 1;
    msg.surface_port.name = surface_port;
    msg.surface_port.disposition = MACH_MSG_TYPE_COPY_SEND;
    msg.surface_port.type = MACH_MSG_PORT_DESCRIPTOR;
    msg.surface_id = (uint32_t)IOSurfaceGetID(io);
    msg.display_index = 0x1e;

    kr = mach_msg(&msg.header, MACH_SEND_MSG, sizeof msg, 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    printf("[client] send kr=%d\n", kr);
    mach_port_deallocate(mach_task_self(), surface_port);
    mach_port_deallocate(mach_task_self(), service);

    rdgpu_reply_t reply;
    memset(&reply, 0, sizeof reply);
    union { rdgpu_reply_t r; uint8_t raw[256]; } rbuf;
    memset(&rbuf, 0, sizeof rbuf);
    kr = mach_msg((mach_msg_header_t*)&rbuf, MACH_RCV_MSG, 0, sizeof rbuf, reply_port, 3000, MACH_PORT_NULL);
    reply = rbuf.r;
    printf("[client] reply kr=%d (%s) result=%d\n", kr, mach_error_string(kr), reply.result);
    return (kr == 0 && reply.result == 0) ? 0 : 1;
}

int main(void) {
    setbuf(stdout, NULL);
    const char *svc = "com.rdgpu.scanout.e2etest";
    pid_t p = fork();
    if (p == 0) return server_main(svc);
    sleep(1);
    int rc = client_main(svc);
    kill(p, SIGKILL);            // server blocks forever in mach_msg RCV; don't wait on it
    int st = 0; waitpid(p, &st, 0);
    printf("server exited; client rc=%d => %s\n", rc, rc == 0 ? "PROTOCOL MATCH OK" : "FAIL");
    return rc;
}
