#include "rd_virtual_dmabuf_ref.h"

extern "C" long syscall(long,...);
extern "C" bool rd_virtual_dmabuf_ready_v1(void){
    return syscall(0x2002,(uint64_t)13,(uint64_t)0,(uint64_t)0,(uint64_t)0,
        (uint64_t)0,(uint64_t)0)==1;
}
extern "C" bool rd_virtual_dmabuf_import_v1(const RDVirtualDMABufRequest *request,
    RDVirtualDMABufRef *out){
    if(!request||!out)return false;
    *out=RDVirtualDMABufRef{};
    RDVirtualDMABufRef candidate{};
    long result=syscall(0x2002,(uint64_t)12,(uint64_t)request,(uint64_t)sizeof *request,
        (uint64_t)&candidate,(uint64_t)sizeof candidate,0);
    if(result!=1||!candidate.relayConnection||!candidate.objectGeneration||
       candidate.objectID!=request->bufferID||candidate.reserved||
       !candidate.capabilityOpaque||!candidate.capabilityGeneration)return false;
    *out=candidate;return true;
}
