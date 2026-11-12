#ifndef RD_OWNED_WIRE_H
#define RD_OWNED_WIRE_H
#include <stdint.h>
#include <mach/mach.h>

#define RD_OWNED_WIRE_CREATE 0x52444f31u
#define RD_OWNED_WIRE_DESTROY 0x52444f32u
#define RD_OWNED_WIRE_VERSION 1u

/* Host-only fixed record. It must arrive over the authenticated witness
 * socket, never as a guest-supplied call argument. */
struct rd_owned_wire_event {
    uint32_t magic,version;
    uint64_t connection;
    uint32_t manager_id,buffer_id;
    uint64_t generation,sequence;
    uint32_t width,height,stride,format;
    uint8_t token[16];
    int32_t peer_pid;
    uint32_t reserved;
    audit_token_t audit;
};
_Static_assert(sizeof(struct rd_owned_wire_event)==112,
               "owned wire record ABI must stay fixed");

#endif
