/* rd_verify_peer_audit.c — verify the AF_UNIX peer of `fd` has the EXACT code
 * identity of the signed executable at `expected_path`.
 *
 * This is the real peer verifier that relay.c and the op-12 virtual-dma-buf
 * auth path declare as `extern int rd_verify_peer_audit(int fd, const char*)`.
 * The test suites substitute a permissive `return 1` stub; this file is the
 * production implementation.
 *
 * It pins the CDHash (not the path string): a guest could otherwise point
 * `expected_path` at its own binary and pass a naive path-string check.
 *
 * Returns 1 on an exact match, 0 on any failure.
 */
#include <sys/socket.h>
#include <sys/un.h>
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

int rd_verify_peer_audit(int fd, const char *expected_path) {
    if (fd < 0 || !expected_path || !*expected_path) return 0;

    /* 1. Peer PID from the kernel on the connected socket (never guest data). */
    pid_t peer = -1;
    socklen_t len = sizeof(peer);
    if (getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &peer, &len) != 0 || peer <= 0)
        return 0;

    /* 2. Expected identity: static code of the signed executable. */
    CFURLRef url = CFURLCreateFromFileSystemRepresentation(
        kCFAllocatorDefault, (const UInt8 *)expected_path,
        (CFIndex)strlen(expected_path), false);
    if (!url) return 0;
    SecStaticCodeRef expected = NULL;
    if (SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &expected) != errSecSuccess) {
        CFRelease(url);
        return 0;
    }
    CFRelease(url);

    /* 3. Live peer identity: the running code for that PID. */
    CFNumberRef pidnum = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &peer);
    if (!pidnum) { CFRelease(expected); return 0; }
    const void *keys[1] = { kSecGuestAttributePid };
    const void *vals[1] = { pidnum };
    CFDictionaryRef attrs = CFDictionaryCreate(kCFAllocatorDefault, keys, vals, 1,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFRelease(pidnum);
    if (!attrs) { CFRelease(expected); return 0; }
    SecCodeRef live = NULL;
    OSStatus st = SecCodeCopyGuestWithAttributes(NULL, attrs, kSecCSDefaultFlags, &live);
    CFRelease(attrs);
    if (st != errSecSuccess || !live) { CFRelease(expected); return 0; }

    /* 4. Compare the unique code identifier (the strong, stable pin). */
    int ok = 0;
    CFDictionaryRef exp_info = NULL, live_info = NULL;
    if (SecCodeCopySigningInformation(expected, kSecCSSigningInformation, &exp_info) == errSecSuccess &&
        SecCodeCopySigningInformation(live, kSecCSSigningInformation, &live_info) == errSecSuccess) {
        CFDataRef exp_id = CFDictionaryGetValue(exp_info, kSecCodeInfoUnique);
        CFDataRef live_id = CFDictionaryGetValue(live_info, kSecCodeInfoUnique);
        ok = (exp_id && live_id && CFEqual(exp_id, live_id)) ? 1 : 0;
    }
    if (live_info) CFRelease(live_info);
    if (exp_info) CFRelease(exp_info);
    CFRelease(live);
    CFRelease(expected);
    return ok;
}
