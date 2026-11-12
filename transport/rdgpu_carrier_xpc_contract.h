#pragma once
#include <stdint.h>

/* Host-only redemption of a standard Wayland dma-buf FD carrier. This is
 * distinct from the Wayland protocol; the client still sends the FD using
 * zwp_linux_buffer_params_v1.add. The signed compositor shim verifies the
 * relay CREATE against the actual wl_buffer before making this RPC. */
#define RDGPU_CARRIER_REDEEM_MAGIC 0x52444352u
#define RDGPU_CARRIER_REDEEM_VERSION 1u
typedef struct {
    uint32_t magic;
    uint16_t version,bytes;
    uint32_t flags,reserved;
    uint64_t relayConnection,objectGeneration;
    uint32_t paramsID,bufferID;
    uint32_t width,height,stride,fourcc;
    uint64_t modifier,fdDevice,fdInode;
} RDGPUCarrierRedeemRequest;
_Static_assert(sizeof(RDGPUCarrierRedeemRequest)==80,"carrier redeem ABI");

/* Returned only to the host compositor. Never serialized to Linux guest. */
typedef struct {
    uint8_t lease[16];
    uint64_t generation,producerFence;
    uint32_t width,height,stride,fourcc;
    uint64_t modifier;
} RDGPUCarrierPrivateIdentity;
_Static_assert(sizeof(RDGPUCarrierPrivateIdentity)==56,"carrier private ABI");

#ifdef __OBJC__
#import <Foundation/Foundation.h>
#import <IOSurface/IOSurfaceObjC.h>
NS_ASSUME_NONNULL_BEGIN
@protocol RDGPUCarrierCompositorRedeem
- (void)redeemCarrier:(NSFileHandle *)receivedFD
              witness:(NSData *)request
                reply:(void (^)(IOSurface * _Nullable surface,
                                 NSData * _Nullable privateIdentity,
                                 int32_t status))reply;
/* Release is host-only and must follow a verified consumer GPU fence and
 * actual Wayland buffer retirement. It never accepts a guest release claim. */
- (void)releaseCarrier:(NSData *)request
                reply:(void (^)(int32_t status))reply;
/* Post-redeem failure may be ambiguous about GPU submission. Quarantine the
 * exact lease until producer teardown; never return it for immediate reuse. */
- (void)abortCarrier:(NSData *)request
              reply:(void (^)(int32_t status))reply;
@end
static inline NSXPCInterface *rdgpuCarrierRedeemXPCInterface(void){
    NSXPCInterface *interface=[NSXPCInterface interfaceWithProtocol:
        @protocol(RDGPUCarrierCompositorRedeem)];
    [interface setClasses:[NSSet setWithObject:[NSFileHandle class]]
           forSelector:@selector(redeemCarrier:witness:reply:)
         argumentIndex:0 ofReply:NO];
    [interface setClasses:[NSSet setWithObject:[NSData class]]
           forSelector:@selector(redeemCarrier:witness:reply:)
         argumentIndex:1 ofReply:NO];
    [interface setClasses:[NSSet setWithObject:[IOSurface class]]
           forSelector:@selector(redeemCarrier:witness:reply:)
         argumentIndex:0 ofReply:YES];
    [interface setClasses:[NSSet setWithObject:[NSData class]]
           forSelector:@selector(redeemCarrier:witness:reply:)
         argumentIndex:1 ofReply:YES];
    [interface setClasses:[NSSet setWithObject:[NSData class]]
           forSelector:@selector(releaseCarrier:reply:)
         argumentIndex:0 ofReply:NO];
    [interface setClasses:[NSSet setWithObject:[NSData class]]
           forSelector:@selector(abortCarrier:reply:)
         argumentIndex:0 ofReply:NO];
    return interface;
}
NS_ASSUME_NONNULL_END
#endif
