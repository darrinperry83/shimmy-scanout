// mtest2.c — isolate whether sending an IOSurfaceCreateMachPort right in a complex
// message works (the exact operation the shim client + scanout server rely on).
#include <stdio.h>
#include <string.h>
#include <mach/mach.h>
#include <mach/message.h>
#include <mach/task_special_ports.h>
#include <IOSurface/IOSurface.h>

int main(void) {
    setbuf(stdout, NULL);
    mach_port_t recv;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &recv);
    mach_port_insert_right(mach_task_self(), recv, recv, MACH_MSG_TYPE_MAKE_SEND);

    // IOSurface + its mach port
    uint32_t w = 64, h = 64, pf = 0x42475241;
    const void *keys[4] = { kIOSurfaceWidth, kIOSurfaceHeight, kIOSurfacePixelFormat, kIOSurfaceAllocSize };
    int64_t vals[4] = { w, h, pf, (int64_t)w*h*4 };
    CFNumberRef nums[4]; const void *v[4];
    for (int i = 0; i < 4; i++) { nums[i] = CFNumberCreate(NULL, kCFNumberSInt64Type, &vals[i]); v[i] = nums[i]; }
    CFDictionaryRef props = CFDictionaryCreate(NULL, keys, v, 4, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    IOSurfaceRef io = IOSurfaceCreate(props);
    for (int i = 0; i < 4; i++) CFRelease(nums[i]);
    CFRelease(props);
    mach_port_t sp = IOSurfaceCreateMachPort(io);
    printf("io=%p id=%u mach_port=0x%x\n", (void*)io, (unsigned)IOSurfaceGetID(io), sp);

    // reply port (matching rdgpu_scanout_client.m's round-trip)
    mach_port_t reply_port = MACH_PORT_NULL;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &reply_port);

    // complex message carrying that port
    union {
        struct { mach_msg_header_t h; mach_msg_body_t body; mach_msg_port_descriptor_t pd; uint32_t surface_id; uint32_t display_index; } m;
        uint8_t raw[256];
    } c;
    memset(&c, 0, sizeof c);
    c.m.h.msgh_bits = MACH_MSGH_BITS_COMPLEX | MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    c.m.h.msgh_size = sizeof c.m;
    c.m.h.msgh_remote_port = recv;
    c.m.h.msgh_local_port = reply_port;
    c.m.h.msgh_id = 0x52445001;
    c.m.body.msgh_descriptor_count = 1;
    c.m.pd.name = sp;
    c.m.pd.disposition = MACH_MSG_TYPE_COPY_SEND;
    c.m.pd.type = MACH_MSG_PORT_DESCRIPTOR;
    c.m.surface_id = IOSurfaceGetID(io);
    c.m.display_index = 0x1e;
    kern_return_t kr = mach_msg(&c.m.h, MACH_SEND_MSG, sizeof c.m, 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    printf("complex(IOSurface) send kr=%d (%s) sizeof=%zu\n", kr, mach_error_string(kr), sizeof c.m);

    // receive it and look up the surface back
    union {
        struct { mach_msg_header_t h; mach_msg_body_t body; mach_msg_port_descriptor_t pd; uint32_t surface_id; uint32_t display_index; } m;
        uint8_t raw[256];
    } r;
    memset(&r, 0, sizeof r);
    kr = mach_msg(&r.m.h, MACH_RCV_MSG, 0, sizeof r.raw, recv, 2000, MACH_PORT_NULL);
    printf("complex recv kr=%d (%s) desc=%u name=0x%x sid=%u disp=%u\n",
           kr, mach_error_string(kr), r.m.body.msgh_descriptor_count, r.m.pd.name, r.m.surface_id, r.m.pd.disposition);
    if (kr == 0 && r.m.body.msgh_descriptor_count >= 1) {
        IOSurfaceRef back = IOSurfaceLookupFromMachPort(r.m.pd.name);
        printf("lookup back id=%u (%s)\n", back ? (unsigned)IOSurfaceGetID(back) : 0, back ? "MATCH" : "FAIL");
        mach_port_deallocate(mach_task_self(), r.m.pd.name);
        if (back) CFRelease(back);
    }
    return 0;
}
