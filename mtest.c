// mtest.c — isolate the mach_msg send issue.
#include <stdio.h>
#include <string.h>
#include <mach/mach.h>
#include <mach/message.h>
#include <mach/task_special_ports.h>

int main(void) {
    setbuf(stdout, NULL);
    mach_port_t recv;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &recv);
    mach_port_insert_right(mach_task_self(), recv, recv, MACH_MSG_TYPE_MAKE_SEND);
    printf("recv=0x%x\n", recv);

    // simple message
    struct { mach_msg_header_t h; uint32_t x; } smsg;
    memset(&smsg, 0, sizeof smsg);
    smsg.h.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    smsg.h.msgh_size = sizeof smsg;
    smsg.h.msgh_remote_port = recv;
    smsg.h.msgh_local_port = MACH_PORT_NULL;
    smsg.h.msgh_id = 0x1111;
    smsg.x = 42;
    kern_return_t kr = mach_msg(&smsg.h, MACH_SEND_MSG, sizeof smsg, 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    printf("simple send kr=%d (%s)\n", kr, mach_error_string(kr));

    // receive it
    struct { mach_msg_header_t h; uint32_t x; } rmsg;
    memset(&rmsg, 0, sizeof rmsg);
    kr = mach_msg(&rmsg.h, MACH_RCV_MSG, 0, sizeof rmsg, recv, 1000, MACH_PORT_NULL);
    printf("simple recv kr=%d (%s) id=0x%x x=%u\n", kr, mach_error_string(kr), rmsg.h.msgh_id, rmsg.x);

    // complex message (port descriptor)
    union {
        struct { mach_msg_header_t h; mach_msg_body_t body; mach_msg_port_descriptor_t pd; uint32_t x; } m;
        uint8_t raw[256];
    } cmsg;
    memset(&cmsg, 0, sizeof cmsg);
    cmsg.m.h.msgh_bits = MACH_MSGH_BITS_COMPLEX | MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    cmsg.m.h.msgh_size = sizeof cmsg.m;
    cmsg.m.h.msgh_remote_port = recv;
    cmsg.m.h.msgh_local_port = MACH_PORT_NULL;
    cmsg.m.h.msgh_id = 0x2222;
    cmsg.m.body.msgh_descriptor_count = 1;
    cmsg.m.pd.name = recv;                       // send a copy of our own recv send-right
    cmsg.m.pd.disposition = MACH_MSG_TYPE_COPY_SEND;
    cmsg.m.pd.type = MACH_MSG_PORT_DESCRIPTOR;
    cmsg.m.x = 77;
    kr = mach_msg(&cmsg.m.h, MACH_SEND_MSG, sizeof cmsg.m, 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    printf("complex send kr=%d (%s) sizeof=%zu\n", kr, mach_error_string(kr), sizeof cmsg.m);

    return 0;
}
