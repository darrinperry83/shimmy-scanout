// bootstrap_topology.c — SAFE standalone probe (run as the console user, no root).
// Walks the current process's bootstrap namespace tree and reports the gui/<uid>
// child namespace of the system bootstrap, so the WindowServer payload can find
// the port it must bootstrap_register() into.
//
// Build:  clang bootstrap_topology.c -o /tmp/bootstrap_topology
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <servers/bootstrap.h>
#include <mach/mach.h>
#include <mach/task_special_ports.h>
#include <dlfcn.h>
#include <unistd.h>

// private launchd entry points (re-exported via libSystem)
typedef kern_return_t (*fn_get_root)(mach_port_t bp, mach_port_t *root);
typedef kern_return_t (*fn_children)(mach_port_t bp, void *children, int *count);

static const char *bs_err(kern_return_t r) {
    switch (r) {
        case 0: return "SUCCESS";
        case 1100: return "NOT_PRIVILEGED";
        case 1101: return "NAME_IN_USE";
        case 1102: return "UNKNOWN_SERVICE";
        case 1103: return "SERVICE_ACTIVE";
        case 1104: return "BAD_COUNT";
        case 1105: return "NO_MEMORY";
        case 1106: return "NO_CHILDREN";
        default: return "?";
    }
}

// Look up a well-known service to fingerprint which namespace `bp` is.
static void fingerprint(mach_port_t bp, const char *label) {
    struct { const char *name; } probes[] = {
        { "com.apple.WindowServer" },   // system domain
        { "com.apple.dock.server" },    // gui/<uid> domain
    };
    for (int i = 0; i < 2; i++) {
        mach_port_t sp = MACH_PORT_NULL;
        kern_return_t kr = bootstrap_look_up(bp, probes[i].name, &sp);
        printf("  [%s] look_up(%s) -> kr=%d (%s) port=0x%x\n",
               label, probes[i].name, kr, bs_err(kr), sp);
        if (sp != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), sp);
    }
}

int main(void) {
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    printf("step 0: start\n");
    mach_port_t bp = MACH_PORT_NULL;
    kern_return_t kr = task_get_bootstrap_port(mach_task_self(), &bp);
    printf("self bootstrap_port=0x%x kr=%d\n", bp, kr);
    fingerprint(bp, "self");

    printf("step 1: dlsym get_root\n");
    fn_get_root get_root = (fn_get_root)dlsym(RTLD_DEFAULT, "bootstrap_get_root");
    if (get_root) {
        mach_port_t root = MACH_PORT_NULL;
        kr = get_root(bp, &root);
        printf("bootstrap_get_root(self) -> kr=%d root=0x%x\n", kr, root);
        fingerprint(root, "root");
    } else {
        printf("bootstrap_get_root: dlsym FAILED\n");
    }

    printf("step 2: parent chain\n");
    // parent chain
    mach_port_t cur = bp;
    for (int depth = 0; depth < 4; depth++) {
        mach_port_t parent = MACH_PORT_NULL;
        kr = bootstrap_parent(cur, &parent);
        printf("bootstrap_parent(depth %d, bp=0x%x) -> kr=%d parent=0x%x\n",
               depth, cur, kr, parent);
        if (kr != BOOTSTRAP_SUCCESS || parent == MACH_PORT_NULL) break;
        if (parent == cur) { printf("  (self-parent, stop)\n"); break; }
        cur = parent;
    }

    // enumerate children of the (likely) system root: use `cur` which is now the
    // topmost parent reached, OR the root from bootstrap_get_root.
    mach_port_t root = cur;   // whatever the top of the parent chain was
    // prefer get_root result if available
    if (get_root) {
        mach_port_t r = MACH_PORT_NULL;
        if (get_root(bp, &r) == 0 && r != MACH_PORT_NULL) root = r;
    }
    printf("step 3: using root=0x%x for children enumeration\n", root);
    fingerprint(root, "root2");

    fn_children children = (fn_children)dlsym(RTLD_DEFAULT, "bootstrap_lookup_children");
    if (!children) {
        printf("bootstrap_lookup_children: dlsym FAILED\n");
        return 0;
    }
    printf("step 4: got children fn\n");

    // Reverse-engineer the element layout by dumping raw bytes. Try a struct of
    // { name_t name; mach_port_t port; } first (size 136), and also a simple
    // status-array interpretation.
    char buf[64 * 1024];
    memset(buf, 0, sizeof buf);
    int count = 0;
    kr = children(root, buf, &count);
    printf("bootstrap_lookup_children(root) -> kr=%d (%s) count=%d\n", kr, bs_err(kr), count);

    if (count > 0 && count < 256) {
        // assume 136-byte entries { name_t name[128]; uint32_t port; uint32_t status }
        // dump first 40 bytes of each entry to see the pattern
        for (int i = 0; i < count && i < 16; i++) {
            char *e = buf + (size_t)i * 136;
            printf("  child[%d] name=%.128s\n", i, e);
            uint32_t port = *(uint32_t *)(e + 128);
            uint32_t status = *(uint32_t *)(e + 132);
            printf("            raw+128=0x%08x +132=0x%08x\n", port, status);
        }
    }

    return 0;
}
