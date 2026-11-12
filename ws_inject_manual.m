// ws_inject_manual.m — inject the rdgpu-scanout payload into a target process
// (WindowServer / Dock) by MANUALLY mapping the Mach-O bundle and applying its
// arm64e chained fixups, WITHOUT dlopen. dlopen is refused by WindowServer's
// hardened-runtime library-validation flag (0x2000).
//
// Split of labour:
//   HOST (this program):  parse the bundle, flatten the chained-fixup chain into
//     32-byte records, resolve every imported symbol (shared-cache: same slide in
//     the target), write the segments + records + loader context into the target,
//     and run a tiny assembly worker (inject_stub_manual.s).
//   TARGET (inject_stub_manual.s):  apply each fixup — PAC-signing the auth-bind
//     entries with the *target's* per-process PAC keys — then run the bundle's
//     __init_offsets constructor.
//
// Build (same as ws_inject.m):
//   clang -arch arm64e ws_inject_manual.m inject_stub_manual.s -o ws_inject_manual

#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/mach_port.h>
#include <mach/task.h>
#include <mach/thread_act.h>
#include <mach/arm/thread_status.h>
#include <servers/bootstrap.h>
#include <mach_debug/ipc_info.h>
#include <mach-o/loader.h>
#include <mach-o/fixup-chains.h>
#include <dlfcn.h>
#include <ptrauth.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

// shared wire protocol (rdgpu_present_msg_t / rdgpu_reply_t / RDGPU_SERVICE_NAME).
#include "/Users/dperry/Documents/Codex/2026-11-07/task/hyprland-stage/metal-wayland-next/rdgpu-scanout-osax/rdgpu_protocol.h"

#define STACK_SIZE  (16 * 1024)
#define RD_PAGE_SIZE 0x4000

// The mach-o headers declare C structs without typedefs; add the aliases.
typedef struct mach_header_64            mach_header_64;
typedef struct load_command              load_command;
typedef struct segment_command_64        segment_command_64;
typedef struct section_64                section_64;
typedef struct linkedit_data_command     linkedit_data_command;
typedef struct dyld_chained_fixups_header    dyld_chained_fixups_header;
typedef struct dyld_chained_starts_in_image  dyld_chained_starts_in_image;
typedef struct dyld_chained_starts_in_segment dyld_chained_starts_in_segment;

// ---- on-disk / cross-process fixup record (must match inject_stub_manual.s) ----
typedef struct {
    uint32_t slot;       // +0x00 offset from image base of the pointer location
    uint32_t type;       // +0x04 0=bind, 1=auth-bind, 2=rebase
    uint32_t key;        // +0x08 PAC key (0=IA,1=IB,2=DA,3=DB)
    uint32_t diversity;  // +0x0c 16-bit PAC diversity
    uint64_t target;     // +0x10 bind: symbol addr; rebase: image offset
    uint64_t addend;     // +0x18 bind addend
} fixup_rec_t;

// ---- loader context (must match inject_stub_manual.s) ----
typedef struct {
    uint64_t base;       // +0x00 image base
    uint64_t fixups;     // +0x08 pointer to fixup_rec_t array
    uint32_t count;      // +0x10 number of records
    uint32_t ctor_off;   // +0x14 __init_offsets value
    uint64_t result;     // +0x18 result slot (worker writes 1)
    uint64_t recv_port;  // +0x20 receive-right NAME in the target (0 = none); passed
                         //        to the constructor as x0 so the payload can receive
                         //        on the injector-registered service port.
} loader_ctx_t;

// Exported by inject_stub_manual.s.
extern uint8_t  inject_stub_start[];
extern uint8_t  inject_stub_end[];
extern uint64_t inject_stub_pcfmt_ptr;
extern uint64_t inject_stub_ctx_ptr;

typedef kern_return_t (*thread_convert_thread_state_fn)(
    thread_act_t thread, int direction, thread_state_flavor_t flavor,
    thread_state_t in_state, mach_msg_type_number_t in_stateCnt,
    thread_state_t out_state, mach_msg_type_number_t *out_stateCnt);

#define RESULT_SENTINEL 0x5EAF00D5EAF00D5ULL

static const char *DEFAULT_PAYLOAD =
    "/Users/dperry/Documents/Codex/2026-11-07/task/hyprland-stage/metal-wayland-next/"
    "rdgpu-scanout-osax/rdgpu-scanout.osax/Contents/MacOS/payload";

// ---------------------------------------------------------------------------
// Mach-O parsing
// ---------------------------------------------------------------------------

typedef struct {
    uint64_t vmaddr, vmsize, fileoff, filesize;
    vm_prot_t initprot, maxprot;
    char segname[17];
} seg_info_t;

typedef struct {
    uint8_t *data;
    size_t   size;
    seg_info_t segs[16];
    int      nsegs;
    uint32_t fixups_off, fixups_size;   // LC_DYLD_CHAINED_FIXUPS
    uint32_t ctor_off;                  // __init_offsets value
    bool     has_ctor;
} macho_t;

static int parse_macho(macho_t *m, const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) { printf("FATAL: open %s: %s\n", path, strerror(errno)); return -1; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    m->size = (size_t)sz;
    m->data = malloc(m->size);
    if (!m->data || fread(m->data, 1, m->size, f) != m->size) {
        printf("FATAL: read %s\n", path); fclose(f); return -1;
    }
    fclose(f);

    mach_header_64 *hdr = (mach_header_64 *)m->data;
    if (hdr->magic != MH_MAGIC_64) { printf("FATAL: not a 64-bit Mach-O\n"); return -1; }

    m->nsegs = 0;
    m->fixups_off = m->fixups_size = 0;
    m->has_ctor = false; m->ctor_off = 0;

    uint8_t *p = m->data + sizeof(mach_header_64);
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        load_command *lc = (load_command *)p;
        if (lc->cmd == LC_SEGMENT_64) {
            segment_command_64 *seg = (segment_command_64 *)lc;
            seg_info_t *s = &m->segs[m->nsegs++];
            s->vmaddr = seg->vmaddr; s->vmsize = seg->vmsize;
            s->fileoff = seg->fileoff; s->filesize = seg->filesize;
            s->initprot = seg->initprot; s->maxprot = seg->maxprot;
            memcpy(s->segname, seg->segname, 16); s->segname[16] = 0;

            // scan sections for __init_offsets (constructor list)
            section_64 *sect = (section_64 *)(p + sizeof(segment_command_64));
            for (uint32_t k = 0; k < seg->nsects; k++, sect++) {
                if (strcmp(sect->sectname, "__init_offsets") == 0) {
                    uint32_t v = *(uint32_t *)(m->data + sect->offset);
                    m->ctor_off = v;
                    m->has_ctor = true;
                    printf("  __init_offsets: value=0x%x (constructor at base+0x%x)\n", v, v);
                }
            }
        } else if (lc->cmd == LC_DYLD_CHAINED_FIXUPS) {
            linkedit_data_command *fix = (linkedit_data_command *)lc;
            m->fixups_off = fix->dataoff;
            m->fixups_size = fix->datasize;
        }
        p += lc->cmdsize;
    }

    printf("segments (%d):\n", m->nsegs);
    for (int i = 0; i < m->nsegs; i++) {
        seg_info_t *s = &m->segs[i];
        printf("  %-16s vmaddr=0x%llx vmsize=0x%llx fileoff=0x%llx filesize=0x%llx prot=%d/%d\n",
               s->segname, (unsigned long long)s->vmaddr, (unsigned long long)s->vmsize,
               (unsigned long long)s->fileoff, (unsigned long long)s->filesize,
               s->initprot, s->maxprot);
    }
    printf("  LC_DYLD_CHAINED_FIXUPS: off=0x%x size=0x%x\n", m->fixups_off, m->fixups_size);
    return 0;
}

// resolve a mach-o import symbol name -> raw (PAC-stripped) address in the host
static int resolve_import(const char *macho_name, uint64_t *out)
{
    // strip leading underscore (dlsym wants the C name)
    const char *cname = (macho_name[0] == '_') ? macho_name + 1 : macho_name;
    void *p = dlsym(RTLD_DEFAULT, cname);
    if (!p) {
        printf("FATAL: dlsym(RTLD_DEFAULT, \"%s\") failed: %s\n", cname, dlerror());
        return -1;
    }
    *out = (uint64_t)ptrauth_strip(p, ptrauth_key_function_pointer);
    return 0;
}

// walk the arm64e USERLAND24 chained fixups, building fixup_rec_t records
static int build_fixups(macho_t *m, fixup_rec_t **recs_out, size_t *nrecs_out)
{
    uint8_t *fb = m->data + m->fixups_off;
    dyld_chained_fixups_header *hdr = (dyld_chained_fixups_header *)fb;
    if (hdr->fixups_version != 0) { printf("FATAL: unsupported fixups_version %d\n", hdr->fixups_version); return -1; }
    if (hdr->imports_format != DYLD_CHAINED_IMPORT) { printf("FATAL: imports_format %d != 1\n", hdr->imports_format); return -1; }

    uint8_t *starts  = fb + hdr->starts_offset;
    uint8_t *imports = fb + hdr->imports_offset;
    uint8_t *symbols = fb + hdr->symbols_offset;

    // resolve every import up front
    int nimp = hdr->imports_count;
    uint64_t *imp_addr = calloc(nimp, sizeof(uint64_t));
    for (int i = 0; i < nimp; i++) {
        uint32_t raw = *(uint32_t *)(imports + i * 4);
        uint32_t name_off = raw >> 9;
        const char *name = (const char *)(symbols + name_off);
        if (resolve_import(name, &imp_addr[i]) != 0) { free(imp_addr); return -1; }
    }
    printf("resolved %d imports\n", nimp);

    // first pass: count fixups
    size_t cap = 128, n = 0;
    fixup_rec_t *recs = malloc(cap * sizeof(fixup_rec_t));

    dyld_chained_starts_in_image *si = (dyld_chained_starts_in_image *)starts;
    for (uint32_t si_seg = 0; si_seg < si->seg_count; si_seg++) {
        if (si->seg_info_offset[si_seg] == 0) continue;
        dyld_chained_starts_in_segment *ss =
            (dyld_chained_starts_in_segment *)(starts + si->seg_info_offset[si_seg]);
        if (ss->pointer_format != DYLD_CHAINED_PTR_ARM64E_USERLAND24) {
            printf("FATAL: pointer_format %d != 12\n", ss->pointer_format); return -1;
        }
        // find the segment so we can translate vmaddr -> file offset
        seg_info_t *seg = NULL;
        for (int k = 0; k < m->nsegs; k++)
            if (m->segs[k].vmaddr == ss->segment_offset) { seg = &m->segs[k]; break; }
        if (!seg) { printf("FATAL: segment for offset 0x%llx not found\n",
                            (unsigned long long)ss->segment_offset); return -1; }

        for (uint32_t pg = 0; pg < ss->page_count; pg++) {
            uint16_t off_in_page = ss->page_start[pg];
            if (off_in_page == DYLD_CHAINED_PTR_START_NONE) continue;
            uint64_t vm = ss->segment_offset + (uint64_t)pg * ss->page_size + off_in_page;
            while (1) {
                // file offset = seg->fileoff + (vm - seg->vmaddr)
                uint64_t fo = seg->fileoff + (vm - seg->vmaddr);
                uint64_t raw = *(uint64_t *)(m->data + fo);
                uint64_t bind = (raw >> 62) & 1;
                uint64_t auth = (raw >> 63) & 1;
                uint64_t next = (raw >> 51) & 0x7FF;

                if (n >= cap) { cap *= 2; recs = realloc(recs, cap * sizeof(fixup_rec_t)); }
                fixup_rec_t *r = &recs[n++];
                memset(r, 0, sizeof(*r));
                r->slot = (uint32_t)vm;

                if (auth && bind) {
                    uint32_t ord = raw & 0xFFFFFF;
                    uint16_t diversity = (raw >> 32) & 0xFFFF;
                    uint8_t  addrDiv   = (raw >> 48) & 1;
                    uint8_t  key       = (raw >> 49) & 3;
                    r->type = 1; r->key = key; r->diversity = diversity;
                    r->target = imp_addr[ord];
                    if (!addrDiv) printf("WARN: auth-bind without addrDiv (slot 0x%x)\n", r->slot);
                } else if (bind) {
                    uint32_t ord = raw & 0xFFFFFF;
                    uint32_t addend = (raw >> 32) & 0x7FFFF;
                    if (addend & 0x40000) addend -= 0x80000;   // sign-extend 19-bit
                    r->type = 0; r->target = imp_addr[ord]; r->addend = (int64_t)(int32_t)addend;
                } else if (auth) {
                    printf("FATAL: auth-rebase encountered (unhandled); slot 0x%x\n", r->slot);
                    return -1;
                } else {
                    uint64_t target = raw & 0x7FFFFFFFFFFULL;
                    uint64_t high8  = (raw >> 43) & 0xFF;
                    r->type = 2; r->target = (high8 << 56) | target;
                }

                if (next == 0) break;
                vm += next * 8;
            }
        }
    }

    printf("fixups: %zu records\n", n);
    for (size_t i = 0; i < n; i++) {
        fixup_rec_t *r = &recs[i];
        printf("  [%2zu] slot=0x%05x type=%d key=%d div=0x%04x target=0x%llx addend=%lld\n",
               i, r->slot, r->type, r->key, r->diversity,
               (unsigned long long)r->target, (long long)r->addend);
    }

    free(imp_addr);
    *recs_out = recs; *nrecs_out = n;
    return 0;
}

// ---------------------------------------------------------------------------
// injection
// ---------------------------------------------------------------------------

static pid_t pgrep_pid(const char *name)
{
    char cmd[128]; snprintf(cmd, sizeof cmd, "pgrep -x %s", name);
    FILE *fp = popen(cmd, "r");
    if (!fp) return 0;
    char buf[64] = {0}; pid_t pid = 0;
    if (fgets(buf, sizeof buf, fp)) pid = (pid_t)atoi(buf);
    pclose(fp);
    return pid;
}

static int target_uid_of(pid_t pid)
{
    char cmd[128]; snprintf(cmd, sizeof cmd, "ps -p %d -o uid=", pid);
    FILE *fp = popen(cmd, "r");
    if (!fp) return -1;
    int uid = -1; fscanf(fp, "%d", &uid); pclose(fp);
    return uid;
}

// ---------------------------------------------------------------------------
// --register: register "com.rdgpu.scanout" in the console user's gui/501
// bootstrap domain (only root/uid-501 may register there; the WindowServer
// payload runs as euid 88 and gets BOOTSTRAP_NOT_PRIVILEGED), then hand the
// receive right to the target task. The receive right is allocated DIRECTLY in
// the target's IPC space (so no cross-task MOVE_RECEIVE is needed); a send right
// for launchd is extracted back into our space via mach_port_extract_right.
//
// IDEMPOTENT reclaim: if the name already exists (a stale zombie from a prior
// injection whose server loop stopped), we probe it. A live server -> skip
// injection (already done). A dead server -> locate the zombie receive right in
// the target task by matching its kernel port-object id and mach_port_destruct
// it; launchd then drops the name and we re-register the SAME name (shim client
// unchanged). Only if that reclaim fails do we fall back to a fresh
// "com.rdgpu.scanout.<pid>.<ts>" name, written to /tmp/rdgpu-scanout.name.
//
// Returns: 1 = registered (sets *recv_out to the receive-right NAME in target),
//          0 = already-live (skip injection), -1 = fatal error.
// ---------------------------------------------------------------------------
#define RDGPU_TARGET_UID    501
#define RDGPU_PORT_FILE    "/tmp/rdgpu-scanout-port"   // last receive-right NAME in target
#define RDGPU_NAME_FILE    "/tmp/rdgpu-scanout.name"   // effective service name (shim/payload)

// kernel port-object id for `name` in `space` (0 on failure).
static unsigned port_object_id(mach_port_t space, mach_port_name_t name)
{
    ipc_info_space_t si;
    ipc_info_name_array_t tbl = NULL;
    mach_msg_type_number_t cnt = 0;
    ipc_info_tree_name_array_t tr = NULL;
    mach_msg_type_number_t tcnt = 0;
    if (mach_port_space_info(space, &si, &tbl, &cnt, &tr, &tcnt) != KERN_SUCCESS)
        return 0;
    unsigned obj = 0;
    for (mach_msg_type_number_t i = 0; i < cnt; i++)
        if (tbl[i].iin_name == name) { obj = (unsigned)tbl[i].iin_object; break; }
    if (tbl) vm_deallocate(mach_task_self(), (vm_address_t)tbl, cnt * sizeof(*tbl));
    if (tr)  vm_deallocate(mach_task_self(), (vm_address_t)tr,  tcnt * sizeof(*tr));
    return obj;
}

// first RECEIVE right in `task` whose kernel port-object id == `obj`.
static mach_port_name_t find_receive_by_object(task_t task, unsigned obj)
{
    ipc_info_space_t si;
    ipc_info_name_array_t tbl = NULL;
    mach_msg_type_number_t cnt = 0;
    ipc_info_tree_name_array_t tr = NULL;
    mach_msg_type_number_t tcnt = 0;
    if (mach_port_space_info(task, &si, &tbl, &cnt, &tr, &tcnt) != KERN_SUCCESS)
        return MACH_PORT_NULL;
    mach_port_name_t found = MACH_PORT_NULL;
    for (mach_msg_type_number_t i = 0; i < cnt; i++)
        if ((tbl[i].iin_type & MACH_PORT_TYPE_RECEIVE) &&
            (unsigned)tbl[i].iin_object == obj) { found = tbl[i].iin_name; break; }
    if (tbl) vm_deallocate(mach_task_self(), (vm_address_t)tbl, cnt * sizeof(*tbl));
    if (tr)  vm_deallocate(mach_task_self(), (vm_address_t)tr,  tcnt * sizeof(*tr));
    return found;
}

// Is the server behind `service` actually answering? Send a minimal (no-surface)
// rdgpu_present_msg_t with a reply port; the payload replies even with no surface.
static int probe_service(mach_port_t service)
{
    mach_port_t reply = MACH_PORT_NULL;
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &reply) != KERN_SUCCESS)
        return 0;

    rdgpu_present_msg_t msg;
    memset(&msg, 0, sizeof msg);
    msg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    msg.header.msgh_size = sizeof msg;
    msg.header.msgh_remote_port = service;
    msg.header.msgh_local_port = reply;
    msg.header.msgh_id = RDGPU_MSG_ID_PRESENT;
    msg.body.msgh_descriptor_count = 0;   // no surface -> server replies result=-1
    msg.surface_id = 0;
    msg.display_index = 0;

    kern_return_t kr = mach_msg(&msg.header, MACH_SEND_MSG, sizeof msg, 0,
                                MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) {          // e.g. MACH_SEND_INVALID_DEST: port already dead
        mach_port_deallocate(mach_task_self(), reply);
        return 0;
    }

    union { rdgpu_reply_t r; uint8_t raw[256]; } rbuf;
    memset(&rbuf, 0, sizeof rbuf);
    kr = mach_msg((mach_msg_header_t*)&rbuf, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
                  sizeof rbuf, reply, 500, MACH_PORT_NULL);
    mach_port_deallocate(mach_task_self(), reply);
    return (kr == KERN_SUCCESS) ? 1 : 0;
}

// Destroy the zombie receive right backing `zombie_send` inside `task`.
static int reclaim_zombie(task_t task, mach_port_t zombie_send)
{
    unsigned obj = port_object_id(mach_task_self(), zombie_send);
    if (obj == 0) {
        printf("register: reclaim: cannot read zombie port-object id\n");
        return 0;
    }
    mach_port_name_t zname = find_receive_by_object(task, obj);
    if (zname == MACH_PORT_NULL) {
        printf("register: reclaim: zombie receive right not found (obj=0x%x)\n", obj);
        return 0;
    }
    kern_return_t kr = mach_port_destruct(task, zname, 0, 0);
    printf("register: reclaim: mach_port_destruct(target, 0x%x) kr=%d\n", zname, kr);
    return (kr == KERN_SUCCESS) ? 1 : 0;
}

static int register_scanout_service(task_t task, mach_port_name_t *recv_out, int force_reclaim)
{
    kern_return_t kr;
    mach_port_t bp = MACH_PORT_NULL;
    kr = task_get_bootstrap_port(mach_task_self(), &bp);
    printf("register: self bootstrap_port=0x%x kr=%d uid=%d euid=%d\n",
           bp, kr, (int)getuid(), (int)geteuid());
    if (kr != KERN_SUCCESS || bp == MACH_PORT_NULL) {
        printf("FATAL: register: no bootstrap port\n");
        return -1;
    }

    // private launchd cross-user namespace fetch (re-exported by libSystem).
    typedef kern_return_t (*fn_pu)(mach_port_t, const char*, uid_t, mach_port_t*);
    fn_pu pu = (fn_pu)dlsym(RTLD_DEFAULT, "bootstrap_look_up_per_user");
    if (!pu) {
        printf("FATAL: register: bootstrap_look_up_per_user dlsym failed\n");
        return -1;
    }

    mach_port_t gui = MACH_PORT_NULL;
    kr = pu(bp, NULL, RDGPU_TARGET_UID, &gui);
    printf("register: bootstrap_look_up_per_user(NULL,%d) kr=%d gui=0x%x\n",
           RDGPU_TARGET_UID, kr, gui);
    if (kr != KERN_SUCCESS || gui == MACH_PORT_NULL) {
        printf("FATAL: register: no gui/%d namespace (kr=%d)\n", RDGPU_TARGET_UID, kr);
        return -1;
    }

    name_t nm;
    memset(nm, 0, sizeof nm);
    strlcpy(nm, RDGPU_SERVICE_NAME, sizeof nm);

    // ---- reclaim a pre-existing (possibly zombie) registration ----
    mach_port_t existing = MACH_PORT_NULL;
    kr = bootstrap_look_up(gui, nm, &existing);
    if (kr == BOOTSTRAP_SUCCESS && existing != MACH_PORT_NULL) {
        if (!force_reclaim && probe_service(existing)) {
            printf("register: %s is already LIVE; skipping injection (idempotent)\n", nm);
            mach_port_deallocate(mach_task_self(), existing);
            mach_port_deallocate(mach_task_self(), gui);
            return 0;    // already live
        }
        printf("register: %s exists but is DEAD (zombie) — reclaiming\n", nm);
        reclaim_zombie(task, existing);
        mach_port_deallocate(mach_task_self(), existing);

        // wait for launchd's port-death handler to drop the name, then verify.
        int free = 0;
        for (int i = 0; i < 20 && !free; i++) {
            usleep(50000);
            mach_port_t recheck = MACH_PORT_NULL;
            if (bootstrap_look_up(gui, nm, &recheck) != BOOTSTRAP_SUCCESS) free = 1;
            else if (recheck != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), recheck);
        }
        if (!free) {
            snprintf(nm, sizeof nm, "com.rdgpu.scanout.%d.%lld",
                     (int)getpid(), (long long)time(NULL));
            printf("register: reclaim failed; falling back to fresh name %s\n", nm);
        } else {
            printf("register: reclaimed; %s is free again\n", RDGPU_SERVICE_NAME);
        }
    } else if (kr != BOOTSTRAP_UNKNOWN_SERVICE) {
        printf("register: bootstrap_look_up(%s) kr=%d (%s)\n", nm, kr, bootstrap_strerror(kr));
    }

    // ---- allocate the receive right DIRECTLY in the target (WindowServer) task ----
    mach_port_name_t recv_name = MACH_PORT_NULL;
    kr = mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &recv_name);
    printf("register: mach_port_allocate(target, RECEIVE) kr=%d name=0x%x\n", kr, recv_name);
    if (kr != KERN_SUCCESS) {
        mach_port_deallocate(mach_task_self(), gui);
        return -1;
    }

    // extract a send right (into OUR space) to hand to launchd.
    mach_port_t send_poly = MACH_PORT_NULL;
    mach_msg_type_name_t send_type = 0;
    kr = mach_port_extract_right(task, recv_name, MACH_MSG_TYPE_MAKE_SEND, &send_poly, &send_type);
    printf("register: mach_port_extract_right(target, 0x%x, MAKE_SEND) kr=%d send=0x%x\n",
           recv_name, kr, send_poly);
    if (kr != KERN_SUCCESS) {
        mach_port_deallocate(task, recv_name);
        mach_port_deallocate(mach_task_self(), gui);
        return -1;
    }

    kr = bootstrap_register(gui, nm, send_poly);
    printf("register: bootstrap_register(gui, %s) kr=%d (%s)\n",
           nm, kr, bootstrap_strerror(kr));
    mach_port_deallocate(mach_task_self(), send_poly);
    mach_port_deallocate(mach_task_self(), gui);

    if (kr != BOOTSTRAP_SUCCESS) {
        printf("FATAL: register: bootstrap_register failed (kr=%d %s)\n", kr, bootstrap_strerror(kr));
        mach_port_deallocate(task, recv_name);
        return -1;
    }

    // persist the receive-right NAME (for next run's reclaim) and the effective
    // service name (for the shim/payload fallback path).
    FILE *f = fopen(RDGPU_PORT_FILE, "w");
    if (f) { fprintf(f, "0x%x\n", recv_name); fclose(f); }
    f = fopen(RDGPU_NAME_FILE, "w");
    if (f) { fprintf(f, "%s\n", nm); fclose(f); }

    printf("register: service %s registered in gui/%d; receive-right name=0x%x in target\n",
           nm, RDGPU_TARGET_UID, recv_name);
    *recv_out = recv_name;
    return 1;
}

int main(int argc, const char **argv)
{
    const char *payload_path = DEFAULT_PAYLOAD;
    pid_t pid_override = 0;
    int register_mode = 0;
    int force_reclaim = 0;
    int npos = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--register") == 0) { register_mode = 1; continue; }
        if (strcmp(argv[i], "--force") == 0) { force_reclaim = 1; continue; }
        if (argv[i][0] == '-') { printf("unknown option: %s\n", argv[i]); return 2; }
        if (npos == 0) payload_path = argv[i];
        else if (npos == 1) pid_override = (pid_t)atoi(argv[i]);
        npos++;
    }

    printf("== ws_inject_manual ==\n");
    printf("payload: %s\n", payload_path);
    printf("register mode: %s\n", register_mode ? "YES (register com.rdgpu.scanout in gui/501)" : "no");

    // ---- parse the bundle ----
    macho_t m;
    if (parse_macho(&m, payload_path) != 0) return 1;
    if (!m.has_ctor) { printf("FATAL: no __init_offsets found\n"); return 1; }

    // ---- dlopen the frameworks in the HOST so dlsym(RTLD_DEFAULT) resolves ----
    const char *fw[] = {
        "/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation",
        "/System/Library/Frameworks/IOSurface.framework/Versions/A/IOSurface",
        "/System/Library/Frameworks/CoreGraphics.framework/Versions/A/CoreGraphics",
        "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation",
        "/usr/lib/libobjc.A.dylib",
        "/usr/lib/libSystem.B.dylib",
    };
    for (int i = 0; i < 6; i++)
        if (!dlopen(fw[i], RTLD_GLOBAL | RTLD_NOW))
            printf("WARN: dlopen %s: %s\n", fw[i], dlerror());

    fixup_rec_t *recs = NULL; size_t nrecs = 0;
    if (build_fixups(&m, &recs, &nrecs) != 0) return 1;

    // ---- find target pid ----
    pid_t pid = (pid_override > 0) ? pid_override : pgrep_pid("WindowServer");
    if (pid <= 0) { printf("FATAL: no target pid\n"); return 1; }
    int uid = target_uid_of(pid);
    printf("target pid: %d (uid=%d)\n", pid, uid);

    task_t task = MACH_PORT_NULL;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
    printf("task_for_pid -> kr=%d (%s)\n", kr, mach_error_string(kr));
    if (kr != KERN_SUCCESS || task == MACH_PORT_NULL) return 2;
    printf("task port: 0x%x\n", task);

    // ---- register the mach service + hand the receive right to the target ----
    mach_port_name_t recv_name = MACH_PORT_NULL;
    if (register_mode) {
        int rr = register_scanout_service(task, &recv_name, force_reclaim);
        if (rr < 0) {
            printf("FATAL: --register: service registration failed (not injecting)\n");
            mach_port_deallocate(mach_task_self(), task);
            return 2;
        }
        if (rr == 0) {
            printf("--register: service already live; nothing to inject\n");
            mach_port_deallocate(mach_task_self(), task);
            return 0;
        }
    }

    // ---- resolve pthread_create_from_mach_thread ----
    void *pcfmt_signed = dlsym(RTLD_DEFAULT, "pthread_create_from_mach_thread");
    if (!pcfmt_signed) { printf("FATAL: dlsym pcfmt: %s\n", dlerror()); return 1; }
    uint64_t pcfmt_raw = (uint64_t)ptrauth_strip(pcfmt_signed, ptrauth_key_function_pointer);
    printf("pthread_create_from_mach_thread: stripped=0x%llx\n", (unsigned long long)pcfmt_raw);

    // ---- build patched stub ----
    uintptr_t stub_start = (uintptr_t)inject_stub_start;
    uintptr_t stub_end   = (uintptr_t)inject_stub_end;
    size_t stub_size = stub_end - stub_start;
    size_t off_pcfmt = (uintptr_t)&inject_stub_pcfmt_ptr - stub_start;
    size_t off_ctx   = (uintptr_t)&inject_stub_ctx_ptr   - stub_start;
    printf("stub: %zu bytes (pcfmt@%zu ctx@%zu)\n", stub_size, off_pcfmt, off_ctx);

    uint8_t *stub = malloc(stub_size);
    memcpy(stub, (const void *)stub_start, stub_size);
    memcpy(stub + off_pcfmt, &pcfmt_raw, 8);

    // ---- compute image total size ----
    uint64_t img_end = 0;
    for (int i = 0; i < m.nsegs; i++) {
        uint64_t e = m.segs[i].vmaddr + m.segs[i].vmsize;
        if (e > img_end) img_end = e;
    }
    img_end = (img_end + RD_PAGE_SIZE - 1) & ~(uint64_t)(RD_PAGE_SIZE - 1);

    // ---- remote allocations ----
    mach_vm_address_t image_base = 0, recs_addr = 0, ctx_addr = 0, result_addr = 0, stack = 0, code = 0;

    kr = mach_vm_allocate(task, &image_base, (mach_vm_size_t)img_end, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) { printf("FATAL: alloc image kr=%d\n", kr); return 1; }
    kr = mach_vm_allocate(task, &recs_addr, RD_PAGE_SIZE, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) { printf("FATAL: alloc recs kr=%d\n", kr); return 1; }
    kr = mach_vm_allocate(task, &ctx_addr, RD_PAGE_SIZE, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) { printf("FATAL: alloc ctx kr=%d\n", kr); return 1; }
    kr = mach_vm_allocate(task, &result_addr, RD_PAGE_SIZE, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) { printf("FATAL: alloc result kr=%d\n", kr); return 1; }
    kr = mach_vm_allocate(task, &stack, STACK_SIZE, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) { printf("FATAL: alloc stack kr=%d\n", kr); return 1; }
    kr = mach_vm_allocate(task, &code, stub_size, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) { printf("FATAL: alloc code kr=%d\n", kr); return 1; }

    printf("remote: image=0x%llx recs=0x%llx ctx=0x%llx result=0x%llx stack=0x%llx code=0x%llx\n",
           (unsigned long long)image_base, (unsigned long long)recs_addr,
           (unsigned long long)ctx_addr, (unsigned long long)result_addr,
           (unsigned long long)stack, (unsigned long long)code);

    // ---- write segments (file content) ----
    for (int i = 0; i < m.nsegs; i++) {
        seg_info_t *s = &m.segs[i];
        if (s->filesize == 0) continue;
        kr = mach_vm_write(task, image_base + s->vmaddr,
                           (vm_offset_t)(m.data + s->fileoff),
                           (mach_msg_type_number_t)s->filesize);
        if (kr != KERN_SUCCESS) { printf("FATAL: write %s kr=%d\n", s->segname, kr); return 1; }
    }

    // ---- protect: __TEXT RX, data RW, __LINKEDIT R ----
    for (int i = 0; i < m.nsegs; i++) {
        seg_info_t *s = &m.segs[i];
        vm_prot_t prot = VM_PROT_READ;
        if (s->maxprot & VM_PROT_EXECUTE) prot |= VM_PROT_EXECUTE;
        if (strcmp(s->segname, "__LINKEDIT") == 0) prot = VM_PROT_READ;
        else if (s->initprot & VM_PROT_WRITE) prot |= VM_PROT_WRITE;  // keep DATA RW for fixups
        // note: __DATA_CONST is nominally read-only but must stay RW until fixups run
        kr = mach_vm_protect(task, image_base + s->vmaddr, (mach_vm_size_t)s->vmsize, 0, prot);
        if (kr != KERN_SUCCESS) { printf("FATAL: protect %s kr=%d\n", s->segname, kr); return 1; }
    }

    // ---- write fixup records + context + result sentinel ----
    kr = mach_vm_write(task, recs_addr, (vm_offset_t)recs,
                       (mach_msg_type_number_t)(nrecs * sizeof(fixup_rec_t)));
    if (kr != KERN_SUCCESS) { printf("FATAL: write recs kr=%d\n", kr); return 1; }

    loader_ctx_t ctx;
    memset(&ctx, 0, sizeof ctx);
    ctx.base      = image_base;
    ctx.fixups    = recs_addr;
    ctx.count     = (uint32_t)nrecs;
    ctx.ctor_off  = m.ctor_off;
    ctx.result    = result_addr;
    ctx.recv_port = recv_name;   // 0 when not in --register mode
    kr = mach_vm_write(task, ctx_addr, (vm_offset_t)&ctx, sizeof(ctx));
    if (kr != KERN_SUCCESS) { printf("FATAL: write ctx kr=%d\n", kr); return 1; }

    uint64_t sentinel = RESULT_SENTINEL;
    kr = mach_vm_write(task, result_addr, (vm_offset_t)&sentinel, 8);
    if (kr != KERN_SUCCESS) { printf("FATAL: write result kr=%d\n", kr); return 1; }

    // patch stub ctx pointer + write stub + protect RX
    memcpy(stub + off_ctx, &ctx_addr, 8);
    kr = mach_vm_write(task, code, (vm_offset_t)stub, (mach_msg_type_number_t)stub_size);
    if (kr != KERN_SUCCESS) { printf("FATAL: write code kr=%d\n", kr); return 1; }
    kr = mach_vm_protect(task, code, stub_size, 0, VM_PROT_READ | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) { printf("FATAL: protect code kr=%d\n", kr); return 1; }

    // ---- thread_convert_thread_state ----
    void *kernel = dlopen("/usr/lib/system/libsystem_kernel.dylib", RTLD_GLOBAL | RTLD_LAZY);
    thread_convert_thread_state_fn thread_convert =
        (thread_convert_thread_state_fn)dlsym(kernel, "thread_convert_thread_state");
    if (!thread_convert) { printf("FATAL: thread_convert dlsym\n"); return 1; }

    // ---- create remote thread ----
    arm_thread_state64_t ts = {};
    arm_thread_state64_t machine_ts = {};
    mach_msg_type_number_t ts_cnt = ARM_THREAD_STATE64_COUNT;
    mach_msg_type_number_t machine_cnt = ARM_THREAD_STATE64_COUNT;
    thread_act_t thread = MACH_PORT_NULL;

    __darwin_arm_thread_state64_set_pc_fptr(
        ts, ptrauth_sign_unauthenticated((void *)code, ptrauth_key_asia, 0));
    __darwin_arm_thread_state64_set_sp(ts, (void *)(uintptr_t)(stack + (STACK_SIZE / 2)));

    kr = thread_create(task, &thread);
    if (kr != KERN_SUCCESS) { printf("FATAL: thread_create kr=%d\n", kr); return 1; }
    kr = thread_convert(thread, 2, ARM_THREAD_STATE64, (thread_state_t)&ts, ts_cnt,
                        (thread_state_t)&machine_ts, &machine_cnt);
    if (kr != KERN_SUCCESS) { printf("FATAL: thread_convert kr=%d\n", kr); return 1; }
    thread_terminate(thread);
    kr = thread_create_running(task, ARM_THREAD_STATE64, (thread_state_t)&machine_ts, machine_cnt, &thread);
    if (kr != KERN_SUCCESS) { printf("FATAL: thread_create_running kr=%d\n", kr); return 1; }
    printf("remote thread: port=0x%x\n", thread);

    // ---- wait for mach-thread sentinel (pthread_create_from_mach_thread returned) ----
    bool mach_ok = false;
    for (int i = 0; i < 100; ++i) {
        arm_thread_state64_t s = {};
        mach_msg_type_number_t cnt = ARM_THREAD_STATE64_COUNT;
        if (thread_get_state(thread, ARM_THREAD_STATE64, (thread_state_t)&s, &cnt) == KERN_SUCCESS) {
            if (s.__x[0] == 0x79616265) { mach_ok = true; break; }
        }
        usleep(20000);
    }
    printf("mach-thread sentinel: %s\n", mach_ok ? "YES" : "NO");

    // ---- wait for the worker to write result = 1 ----
    uint64_t result = RESULT_SENTINEL;
    for (int i = 0; i < 100; ++i) {   // up to ~10s
        mach_vm_size_t out = 8;
        uint64_t v = RESULT_SENTINEL;
        if (mach_vm_read_overwrite(task, result_addr, 8, (mach_vm_address_t)&v, &out) == KERN_SUCCESS) {
            if (v != RESULT_SENTINEL) { result = v; break; }
        }
        usleep(100000);
    }
    if (result == RESULT_SENTINEL)
        printf("result: STILL SENTINEL (constructor never finished; target may have crashed)\n");
    else if (result == 1)
        printf("result: 1 (SUCCESS — fixups applied, constructor ran and returned)\n");
    else
        printf("result: 0x%llx (unexpected)\n", (unsigned long long)result);

    // ---- cleanup ----
    thread_terminate(thread);
    mach_vm_deallocate(task, code, stub_size);
    mach_vm_deallocate(task, stack, STACK_SIZE);
    mach_vm_deallocate(task, result_addr, RD_PAGE_SIZE);
    mach_vm_deallocate(task, ctx_addr, RD_PAGE_SIZE);
    mach_vm_deallocate(task, recs_addr, RD_PAGE_SIZE);
    // NOTE: the image is deliberately left mapped when the load succeeded, so a
    // persistent payload (bootstrap service + server thread) keeps running —
    // exactly like a dlopen'd image. Only reclaim it on failure.
    if (result != 1)
        mach_vm_deallocate(task, image_base, (mach_vm_size_t)img_end);
    mach_port_deallocate(mach_task_self(), task);

    printf("== done ==\n");
    return 0;
}
