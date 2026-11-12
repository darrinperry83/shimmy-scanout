// vsync_probe.c  — probe IOMobileFramebuffer user-client selectors from userland.
// Read-only: opens the framebuffer client, probes a few documented MIG methods,
// and attempts setVSyncNotifications (selector 9). Never presents/modifies a surface.
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <IOKit/IOKitLib.h>

int main(void)
{
    io_service_t service = IOServiceGetMatchingService(kIOMainPortDefault,
                                                       IOServiceMatching("IOMobileFramebuffer"));
    if (service == IO_OBJECT_NULL) { printf("no IOMobileFramebuffer service\n"); return 1; }
    io_connect_t c = IO_OBJECT_NULL;
    kern_return_t kr = IOServiceOpen(service, mach_task_self(), 0, &c);
    IOObjectRelease(service);
    printf("IOServiceOpen -> 0x%x (connect=%u)\n", kr, c);
    if (kr != KERN_SUCCESS) return 1;

    // selector 7 = getId -> output framebufferID
    { uint64_t out=0; uint32_t n=1;
      kr = IOConnectCallMethod(c, 7, NULL,0,NULL,0, &out,&n,NULL,NULL);
      printf("selector 7 getId -> 0x%x out=0x%llx\n", kr, (unsigned long long)out); }

    // selector 8 = getDisplaySize -> output {width,height}
    { uint64_t out[2]={0,0}; uint32_t n=2;
      kr = IOConnectCallMethod(c, 8, NULL,0,NULL,0, out,&n,NULL,NULL);
      printf("selector 8 getDisplaySize -> 0x%x w=%llu h=%llu\n", kr,
             (unsigned long long)out[0], (unsigned long long)out[1]); }

    // selector 3 = getDefaultSurface -> output surfaceID
    { uint64_t out=0; uint32_t n=1;
      kr = IOConnectCallMethod(c, 3, NULL,0,NULL,0, &out,&n,NULL,NULL);
      printf("selector 3 getDefaultSurface -> 0x%x surfID=0x%llx\n", kr,(unsigned long long)out); }

    // selector 9 = setVSyncNotifications : input { functionAddress, userData }
    {
      mach_port_t np = MACH_PORT_NULL;
      mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &np);
      kr = IOConnectSetNotificationPort(c, 0, np, 0);
      printf("IOConnectSetNotificationPort -> 0x%x\n", kr);
      uint64_t in[2] = { (uint64_t)(uintptr_t)0x41414141ULL /*dummy fn*/, 0x1234 };
      kr = IOConnectCallMethod(c, 9, in, 2, NULL,0,NULL,NULL,NULL,NULL);
      printf("selector 9 setVSyncNotifications -> 0x%x\n", kr);
      // also try with 0 inputs (disable form)
      kr = IOConnectCallMethod(c, 9, NULL,0,NULL,0,NULL,NULL,NULL,NULL);
      printf("selector 9 (0 inputs) -> 0x%x\n", kr);
      mach_port_deallocate(mach_task_self(), np);
    }

    // selector 4 = swapBegin -> output swapID (read-only begin, no end)
    { uint64_t out=0; uint32_t n=1;
      kr = IOConnectCallMethod(c, 4, NULL,0,NULL,0,&out,&n,NULL,NULL);
      printf("selector 4 swapBegin -> 0x%x swapID=0x%llx\n", kr,(unsigned long long)out); }

    IOServiceClose(c);
    printf("done.\n");
    return 0;
}
