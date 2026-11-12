#pragma once
#include <stdint.h>
#include <mach/mach.h>

#define RD_DMABUF_WIRE_CREATE 0x52444231u
#define RD_DMABUF_WIRE_DESTROY 0x52444232u
#define RD_DMABUF_WIRE_VERSION 1u
#define RD_DMABUF_ARGB8888 0x34325241u
/* Emitted only after the complete Wayland request and attached FD were
 * forwarded. st_dev/st_ino refer to the received host SCM_RIGHTS FD, not a
 * guest integer. A broker must additionally pin that issuer FD and compare
 * its signed lease/generation before authorizing an IOSurface import. */
struct rd_dmabuf_wire_event {
    uint32_t magic,version;
    uint64_t connection,generation;
    uint32_t params_id,buffer_id;
    uint32_t width,height,stride,format;
    uint64_t fd_dev,fd_ino;
    int32_t peer_pid;
    uint32_t reserved;
    audit_token_t audit;
};
_Static_assert(sizeof(struct rd_dmabuf_wire_event)==104,"dma-buf witness ABI");
