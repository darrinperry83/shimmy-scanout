#include "rd_virtual_dmabuf_ref.h"
#include <cassert>
#include <cstdarg>
#include <cstdio>

static bool allow;
extern "C" long syscall(long number,...){
    va_list ap;va_start(ap,number);
    auto op=va_arg(ap,uint64_t);
    if(op==13){
        for(int i=0;i<5;i++)assert(va_arg(ap,uint64_t)==0);
        va_end(ap);return allow?1:-1;
    }
    auto request=(const RDVirtualDMABufRequest*)va_arg(ap,uint64_t);
    auto requestSize=va_arg(ap,uint64_t);
    auto output=(RDVirtualDMABufRef*)va_arg(ap,uint64_t);
    auto outputSize=va_arg(ap,uint64_t);
    auto last=va_arg(ap,uint64_t);va_end(ap);
    assert(number==0x2002&&op==12&&request&&requestSize==40&&
           output&&outputSize==40&&!last);
    if(!allow)return -1;
    *output=RDVirtualDMABufRef{.relayConnection=42,.objectGeneration=3,
        .objectID=request->bufferID,.capabilityOpaque=0x9911,
        .capabilityGeneration=2};return 1;
}
int main(){
    RDVirtualDMABufRequest request{.fd=3,.bufferID=19,.width=16,
        .height=16,.stride=64,.format=0x34325241u};
    RDVirtualDMABufRef ref{};
    assert(!rd_virtual_dmabuf_ready_v1());
    assert(!rd_virtual_dmabuf_import_v1(&request,&ref));
    assert(!ref.capabilityOpaque);
    allow=true;
    assert(rd_virtual_dmabuf_ready_v1());
    assert(rd_virtual_dmabuf_import_v1(&request,&ref));
    assert(ref.objectID==19&&ref.capabilityOpaque==0x9911);
    puts("VIRTUAL_DMABUF_GUEST_TRANSPORT_PASS exact_op12 opaque_ref deny_default");
}
