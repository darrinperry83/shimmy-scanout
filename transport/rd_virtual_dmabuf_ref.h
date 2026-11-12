#pragma once
#ifndef RD_VIRTUAL_DMABUF_REF_ABI_H
#define RD_VIRTUAL_DMABUF_REF_ABI_H
#include <stdint.h>

/* Guest-visible import result contains only an opaque scene capability.
 * The host verifies the SCM_RIGHTS FD, exact wl_buffer ID and producer lease
 * against its own relay/broker state before returning this tuple. */
typedef struct {
    uint64_t relayConnection,objectGeneration;
    uint32_t objectID,reserved;
    uint64_t capabilityOpaque,capabilityGeneration;
} RDVirtualDMABufRef;
typedef struct {
    int32_t fd;
    uint32_t bufferID,width,height,stride,offset,format;
    uint64_t modifier;
} RDVirtualDMABufRequest;
#ifdef __cplusplus
static_assert(sizeof(RDVirtualDMABufRequest)==40);
extern "C" {
#endif
/* Missing callbacks deny virtual import. Numeric guest FD is a lookup hint;
 * authority comes from the host's signed carrier ledger and relay witness. */
bool rd_virtual_dmabuf_import_v1(const RDVirtualDMABufRequest*,
    RDVirtualDMABufRef*);
bool rd_virtual_dmabuf_ready_v1(void);
#ifdef __cplusplus
}
#endif
#endif
