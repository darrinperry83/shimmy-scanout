#pragma once
#include "rddmabuf_wire.h"
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

typedef struct RDDMABufWitness RDDMABufWitness;
typedef bool (*RDDMABufAuthenticate)(void *context,int fd,pid_t *relayPID,
                                     audit_token_t *relayAudit);
typedef struct {
    int fd;
    pid_t relayPID,producerPID;
    audit_token_t relayAudit,producerAudit;
    /* Public NSXPCConnection exposes these fields, not the full audit token.
     * In production set useProducerSubsetIdentity and pin them at accept. */
    uid_t producerUID;
    uint64_t producerAuditSession;
    bool useProducerSubsetIdentity;
    uint64_t connection;
    RDDMABufAuthenticate authenticate;
    void *context;
} RDDMABufWitnessConfig;

RDDMABufWitness *rddmabuf_witness_create(const RDDMABufWitnessConfig *config);
/* Read one fixed authenticated record: CREATE=1, DESTROY=2, need bytes=0,
 * rejected/EOF=-1. No guest-provided pointer or PID grants authority. */
int rddmabuf_witness_receive(RDDMABufWitness *channel,
    struct rd_dmabuf_wire_event *event);
/* One-use exact host claim, after the compositor has separately verified
 * the actual wl_client/wl_buffer construction. */
bool rddmabuf_witness_claim(RDDMABufWitness *channel,
    const struct rd_dmabuf_wire_event *expected);
void rddmabuf_witness_disconnect(RDDMABufWitness *channel);
void rddmabuf_witness_destroy(RDDMABufWitness *channel);
