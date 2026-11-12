#include "rddmabuf_witness.h"
#include <errno.h>
#include <bsm/libbsm.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#define RD_DMABUF_WITNESS_SLOTS 8u
typedef struct {
    struct rd_dmabuf_wire_event created;
    bool active,claimed;
} Slot;
struct RDDMABufWitness {
    RDDMABufWitnessConfig config;
    Slot slots[RD_DMABUF_WITNESS_SLOTS];
    unsigned char pending[sizeof(struct rd_dmabuf_wire_event)];
    size_t bytes;
    bool disconnected;
};
static bool same_audit(const audit_token_t *a,const audit_token_t *b){
    return memcmp(a,b,sizeof *a)==0;
}
RDDMABufWitness *rddmabuf_witness_create(const RDDMABufWitnessConfig *cfg){
    if(!cfg||cfg->fd<0||cfg->relayPID<=0||cfg->producerPID<=0||
       (cfg->useProducerSubsetIdentity&&!cfg->producerAuditSession)||
       !cfg->connection||!cfg->authenticate)return NULL;
    pid_t actualPID=0;audit_token_t actualAudit={0};
    if(!cfg->authenticate(cfg->context,cfg->fd,&actualPID,&actualAudit)||
       actualPID!=cfg->relayPID||
       !same_audit(&actualAudit,&cfg->relayAudit))return NULL;
    RDDMABufWitness *channel=calloc(1,sizeof *channel);
    if(channel)channel->config=*cfg;
    return channel;
}
static bool base_valid(const RDDMABufWitness *c,
    const struct rd_dmabuf_wire_event *e){
    bool producerIdentity=c->config.useProducerSubsetIdentity?
        (audit_token_to_pid(e->audit)==c->config.producerPID&&
         audit_token_to_euid(e->audit)==c->config.producerUID&&
         (uint64_t)audit_token_to_asid(e->audit)==
             c->config.producerAuditSession):
        same_audit(&e->audit,&c->config.producerAudit);
    return e->version==RD_DMABUF_WIRE_VERSION&&!e->reserved&&
        e->connection==c->config.connection&&
        e->peer_pid==c->config.producerPID&&
        producerIdentity&&
        e->params_id&&e->buffer_id&&e->generation&&
        e->fd_dev&&e->fd_ino&&e->format==RD_DMABUF_ARGB8888;
}
static int record(RDDMABufWitness *c,
    const struct rd_dmabuf_wire_event *e){
    if(!base_valid(c,e))return -1;
    if(e->magic==RD_DMABUF_WIRE_CREATE){
        if(!e->width||!e->height||e->width>2048||e->height>1536||
           e->stride<e->width*4u||e->stride>e->width*4u+4096u||
           e->stride>16384u||(e->stride&3u))return -1;
        Slot *available=NULL;
        for(unsigned i=0;i<RD_DMABUF_WITNESS_SLOTS;i++){
            Slot *slot=&c->slots[i];
            if(slot->active&&slot->created.buffer_id==e->buffer_id)return -1;
            if(!slot->active&&!available)available=slot;
        }
        if(!available)return -1;
        *available=(Slot){.created=*e,.active=true};return 1;
    }
    if(e->magic==RD_DMABUF_WIRE_DESTROY){
        if(e->width||e->height)return -1;
        for(unsigned i=0;i<RD_DMABUF_WITNESS_SLOTS;i++){
            Slot *slot=&c->slots[i];
            const struct rd_dmabuf_wire_event *old=&slot->created;
            if(slot->active&&old->connection==e->connection&&
               old->buffer_id==e->buffer_id&&old->generation==e->generation){
                if(old->params_id!=e->params_id||old->stride!=e->stride||
                   old->fd_dev!=e->fd_dev||old->fd_ino!=e->fd_ino)return -1;
                memset(slot,0,sizeof *slot);return 2;
            }
        }
    }
    return -1;
}
int rddmabuf_witness_receive(RDDMABufWitness *c,
    struct rd_dmabuf_wire_event *event){
    if(!c||!event||c->disconnected)return -1;
    ssize_t count=recv(c->config.fd,c->pending+c->bytes,
        sizeof c->pending-c->bytes,MSG_DONTWAIT);
    if(count<0&&(errno==EINTR||errno==EAGAIN||errno==EWOULDBLOCK))return 0;
    if(count<=0){rddmabuf_witness_disconnect(c);return -1;}
    c->bytes+=(size_t)count;
    if(c->bytes<sizeof c->pending)return 0;
    memcpy(event,c->pending,sizeof *event);c->bytes=0;
    int result=record(c,event);
    if(result<0)rddmabuf_witness_disconnect(c);
    return result;
}
bool rddmabuf_witness_claim(RDDMABufWitness *c,
    const struct rd_dmabuf_wire_event *expected){
    if(!c||!expected||c->disconnected||expected->magic!=RD_DMABUF_WIRE_CREATE)
        return false;
    for(unsigned i=0;i<RD_DMABUF_WITNESS_SLOTS;i++){
        Slot *slot=&c->slots[i];const struct rd_dmabuf_wire_event *actual=&slot->created;
        if(!slot->active||slot->claimed||actual->buffer_id!=expected->buffer_id||
           actual->generation!=expected->generation)continue;
        if(actual->connection!=expected->connection||
           actual->params_id!=expected->params_id||
           actual->width!=expected->width||actual->height!=expected->height||
           actual->stride!=expected->stride||actual->format!=expected->format||
           actual->fd_dev!=expected->fd_dev||actual->fd_ino!=expected->fd_ino||
           actual->peer_pid!=expected->peer_pid||
           !same_audit(&actual->audit,&expected->audit))return false;
        slot->claimed=true;return true;
    }
    return false;
}
void rddmabuf_witness_disconnect(RDDMABufWitness *c){
    if(!c)return;c->disconnected=true;memset(c->slots,0,sizeof c->slots);
}
void rddmabuf_witness_destroy(RDDMABufWitness *c){
    if(!c)return;rddmabuf_witness_disconnect(c);free(c);
}
