// bootstrap_children_probe.c — determine the exact signature of the private
// bootstrap_lookup_children by forking isolated attempts. SAFE (own process).
//
// Build: clang bootstrap_children_probe.c -o /tmp/bsc_probe
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <servers/bootstrap.h>
#include <mach/mach.h>
#include <mach/task_special_ports.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>

static const char *errname(kern_return_t r) {
    switch (r) {
        case 0: return "SUCCESS";
        case 1100: return "NOT_PRIVILEGED";
        case 1102: return "UNKNOWN_SERVICE";
        case 1104: return "BAD_COUNT";
        case 1105: return "NO_MEMORY";
        case 1106: return "NO_CHILDREN";
        default: return "?";
    }
}

// candidate signatures
typedef kern_return_t (*sig_outptr)(mach_port_t, void **, int *);          // A: out-ptr
typedef kern_return_t (*sig_buf)(mach_port_t, void *, int *);              // B: caller buffer

static int attempt(const char *which) {
    pid_t p = fork();
    if (p == 0) {
        // child
        mach_port_t bp;
        task_get_bootstrap_port(mach_task_self(), &bp);
        // get root (my own tree root)
        mach_port_t root = bp;
        typedef kern_return_t (*fn_root)(mach_port_t, mach_port_t *);
        fn_root gr = (fn_root)dlsym(RTLD_DEFAULT, "bootstrap_get_root");
        if (gr) gr(bp, &root);

        void *fc = dlsym(RTLD_DEFAULT, "bootstrap_lookup_children");
        if (!fc) { printf("  [%s] dlsym NULL\n", which); _exit(42); }

        kern_return_t kr;
        int count = -1;

        if (strcmp(which, "outptr") == 0) {
            void *arr = NULL;
            kr = ((sig_outptr)fc)(root, &arr, &count);
            printf("  [outptr] root=0x%x kr=%d (%s) count=%d arr=%p\n", root, kr, errname(kr), count, arr);
            if (arr && count > 0 && count < 256) {
                // dump names: assume entries { name_t[128]; ... }
                for (int i = 0; i < count; i++) {
                    printf("     child[%d] = %.128s\n", i, (char*)arr + (size_t)i * 136);
                }
            }
        } else if (strcmp(which, "buf") == 0) {
            static char buf[65536];
            memset(buf, 0, sizeof buf);
            kr = ((sig_buf)fc)(root, buf, &count);
            printf("  [buf] root=0x%x kr=%d (%s) count=%d\n", root, kr, errname(kr), count);
            if (count > 0 && count < 256) {
                for (int i = 0; i < count; i++) {
                    printf("     child[%d] = %.128s\n", i, buf + (size_t)i * 136);
                }
            }
        }
        _exit(0);
    }
    int st = 0;
    waitpid(p, &st, 0);
    if (WIFSIGNALED(st)) printf("[%s] child killed by signal %d\n", which, WTERMSIG(st));
    else printf("[%s] child exit=%d\n", which, WEXITSTATUS(st));
    return 0;
}

int main(void) {
    setbuf(stdout, NULL);
    attempt("outptr");
    attempt("buf");
    return 0;
}
