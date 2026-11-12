/* Bounded one-client Wayland transport proof; not a general secure proxy. */

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/poll.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <mach/mach.h>
#include "rdowned_wire.h"
#include "rddmabuf_wire.h"
static volatile sig_atomic_t stop;
extern int rd_verify_peer_audit(int fd,const char *expected_path);
static void term(int s){(void)s;stop=1;}
static uint32_t word(const unsigned char *p){uint32_t x;memcpy(&x,p,4);return x;}
static int wire_string(const unsigned char *b,size_t sz,size_t off,int nullable){
    if(off+4>sz)return 0;
    uint32_t len=word(b+off);
    if(!len)return nullable&&off+4==sz;
    if(len>4096||off+4u+((len+3u)&~3u)!=sz)return 0;
    return b[off+4u+len-1u]==0;
}
static size_t wire_string_next(const unsigned char *b,size_t sz,size_t off){
    if(off+4>sz)return 0;
    uint32_t len=word(b+off);
    if(!len||len>4096||off+4u+((len+3u)&~3u)>sz||b[off+4u+len-1u])return 0;
    return off+4u+((len+3u)&~3u);
}
struct top_life {uint32_t xdg,wl;uint64_t generation;
                 unsigned created,configured,dead,revoked;};
struct advertised_global {uint32_t registry,name,version;char iface[64];};
enum rd_obj_type { RD_NONE, RD_DISPLAY, RD_REGISTRY, RD_COMPOSITOR, RD_WL_SURFACE, RD_REGION,
    RD_WM_BASE, RD_XDG_SURFACE, RD_TOPLEVEL, RD_UNTRACKED,
    RD_OUTPUT, RD_SUBCOMPOSITOR, RD_SUBSURFACE, RD_VIEWPORTER, RD_VIEWPORT,
    RD_FRACTIONAL_MANAGER, RD_FRACTIONAL_SCALE,
    RD_IDLE_MANAGER,
    RD_IDLE_INHIBITOR, RD_ACTIVATION, RD_ACTIVATION_TOKEN,
    RD_GESTURES, RD_GESTURE_SWIPE, RD_GESTURE_PINCH, RD_GESTURE_HOLD,
    RD_PRESENTATION, RD_PRESENTATION_FEEDBACK, RD_KDE_DECORATION_MANAGER,
    RD_KDE_DECORATION, RD_PRIMARY_MANAGER, RD_PRIMARY_SOURCE,
    RD_PRIMARY_DEVICE, RD_PRIMARY_OFFER, RD_XDG_OUTPUT_MANAGER, RD_XDG_OUTPUT,
    RD_SHORTCUTS_MANAGER, RD_SHORTCUTS_INHIBITOR,
    RD_TABLET_MANAGER, RD_TABLET_SEAT, RD_TABLET, RD_TABLET_TOOL,
    RD_TABLET_PAD, RD_TABLET_GROUP, RD_TABLET_RING, RD_TABLET_STRIP, RD_TABLET_DIAL,
    RD_OWNED_MANAGER, RD_OWNED_BUFFER,
    RD_DMABUF_MANAGER, RD_DMABUF_PARAMS, RD_DMABUF_BUFFER };
#define RD_OBJECT_CAP 4096u
#define RD_PROBE_CAP 128u
enum { RD_EMPTY, RD_LIVE, RD_WAIT_DELETE, RD_TOMBSTONE };
struct rd_object {uint32_t id;uint32_t parent,layer_parent;uint64_t generation;
 struct top_life top; enum rd_obj_type type;
 unsigned char state,owner;
 unsigned char dead,pending_delete,shm,pool,buffer,seat,keyboard,pointer,touch;
 unsigned char data_manager,data_device,data_source,data_offer,layer_shell,layer_surface,version;
 unsigned char server_offer,server_offer_dead,server_offer_version;
 uint64_t dmabuf_dev,dmabuf_ino;uint32_t dmabuf_stride;
 unsigned char dmabuf_plane,dmabuf_created;
};
struct rd_objects {struct rd_object slot[RD_OBJECT_CAP];uint64_t next_generation,salt;};
struct parse {unsigned char b[131072];size_t n;struct rd_objects objects;
              struct rd_object missing;
              unsigned toplevels,denied,strict_capability;uint32_t host_connection;
              pid_t peer_pid;

              unsigned fd_required,server_fd_required;

              struct advertised_global globals[256];
              unsigned char server_b[131072];size_t server_n;int supervisor_fd,event_fd;
              audit_token_t audit;int owned_event_fd;unsigned emit_owned;
              int dmabuf_event_fd;unsigned emit_dmabuf;
              uint64_t fd_dev[16],fd_ino[16];unsigned fd_base,fd_count;};
static int occupied(struct parse *s,uint32_t id);
static int surface_has_role(struct parse *s,uint32_t surface){
    for(unsigned j=0;j<RD_OBJECT_CAP;j++){
        struct rd_object *o=&s->objects.slot[j];
        if(o->state!=RD_LIVE||o->dead)continue;
        if((o->type==RD_XDG_SURFACE||o->type==RD_SUBSURFACE)&&o->parent==surface)
            return 1;
        if(o->layer_surface&&o->layer_parent==surface)return 1;
    }
    return 0;
}
static enum rd_obj_type extension_type(const unsigned char *name,uint32_t len){
    if(len==sizeof("zwp_linux_dmabuf_v1")&&
       !memcmp(name,"zwp_linux_dmabuf_v1",len))return RD_DMABUF_MANAGER;
    if(len==sizeof("rd_owned_buffer_v1")&&
       !memcmp(name,"rd_owned_buffer_v1",len))return RD_OWNED_MANAGER;
    if(len==10&&!memcmp(name,"wl_output",10))return RD_OUTPUT;
    if(len==17&&!memcmp(name,"wl_subcompositor",17))return RD_SUBCOMPOSITOR;
    if(len==14&&!memcmp(name,"wp_viewporter",14))return RD_VIEWPORTER;
    if(len==31&&!memcmp(name,"wp_fractional_scale_manager_v1",31))return RD_FRACTIONAL_MANAGER;
    if(len==sizeof("zxdg_output_manager_v1")&&
       !memcmp(name,"zxdg_output_manager_v1",len))return RD_XDG_OUTPUT_MANAGER;
    if(len==sizeof("zwp_keyboard_shortcuts_inhibit_manager_v1")&&
       !memcmp(name,"zwp_keyboard_shortcuts_inhibit_manager_v1",len))return RD_SHORTCUTS_MANAGER;
    if(len==22&&!memcmp(name,"zwp_tablet_manager_v2",22))return RD_TABLET_MANAGER;
    return RD_NONE;
}
static unsigned extension_max_version(enum rd_obj_type type){
    if(type==RD_DMABUF_MANAGER)return 3;
    if(type==RD_OWNED_MANAGER)return 1;
    return type==RD_OUTPUT?4u:(type==RD_XDG_OUTPUT_MANAGER?3u:
           (type==RD_TABLET_MANAGER?2u:(type==RD_NONE?0u:1u)));
}
static unsigned rd_hash(const struct rd_objects *s,uint32_t id){
    uint64_t x=(uint64_t)id^s->salt;
    x^=x>>30;x*=0xbf58476d1ce4e5b9ULL;
    x^=x>>27;x*=0x94d049bb133111ebULL;
    x^=x>>31;return (unsigned)x&(RD_OBJECT_CAP-1);
}
static struct rd_object *rd_find(struct parse *s,uint32_t id){
    if(!id)return NULL;
    for(unsigned n=0,h=rd_hash(&s->objects,id);n<RD_PROBE_CAP;n++){
        unsigned at=(h+n)&(RD_OBJECT_CAP-1);
        struct rd_object *o=&s->objects.slot[at];
        if(o->state==RD_EMPTY)return NULL;
        if((o->state==RD_LIVE||o->state==RD_WAIT_DELETE)&&o->id==id)return o;
    }
    return NULL;
}
static struct rd_object *rd_obj(struct parse *s,uint32_t id){
    struct rd_object *o=rd_find(s,id);
    if(o)return o;
    if(getenv("RD_UNIFIED_TRACE")&&!s->strict_capability)
        fprintf(stderr,"UNIFIED_MISSING_OBJECT %u\n",id);
    s->denied++;memset(&s->missing,0,sizeof(s->missing));return &s->missing;
}
static struct rd_object *rd_view(struct parse *s,uint32_t id){
    struct rd_object *o=rd_find(s,id);
    if(o)return o;
    memset(&s->missing,0,sizeof(s->missing));return &s->missing;
}
static struct rd_object *rd_new(struct parse *s,uint32_t id){
    if(!id||rd_find(s,id)){s->denied++;return &s->missing;}
    struct rd_object *reuse=NULL;
    for(unsigned n=0,h=rd_hash(&s->objects,id);n<RD_PROBE_CAP;n++){
        unsigned at=(h+n)&(RD_OBJECT_CAP-1);
        struct rd_object *o=&s->objects.slot[at];
        if(o->state==RD_TOMBSTONE&&!reuse)reuse=o;
        if(o->state==RD_EMPTY){if(!reuse)reuse=o;break;}
    }
    if(reuse){*reuse=(struct rd_object){.id=id,.state=RD_LIVE,
        .owner=(id>=0xff000000u),.generation=++s->objects.next_generation};return reuse;}
    s->denied++;return &s->missing;
}
static struct rd_object *rd_alloc(struct parse *s,uint32_t id){
    if(occupied(s,id)){s->denied++;return &s->missing;}
    return rd_new(s,id);
}
static void rd_obj_init(struct parse *s){
    memset(&s->objects,0,sizeof(s->objects));
    arc4random_buf(&s->objects.salt,sizeof(s->objects.salt));
    s->objects.slot[rd_hash(&s->objects,1)]=(struct rd_object){.id=1,.type=RD_DISPLAY,
        .state=RD_LIVE,.generation=1};
    s->objects.next_generation=1;
}
static int rd_add(struct parse *s,uint32_t id,enum rd_obj_type type,uint32_t parent){
    if(!id||id>=0xff000000u||occupied(s,id))return 0;
    struct rd_object *o=rd_alloc(s,id);
    if(s->denied)return 0;
    o->type=type;o->parent=parent;
    return 1;
}
static int rd_lineage_request(struct parse *s,const unsigned char *p,size_t n){
    if(n<8)return 0;
    uint32_t id=word(p),h=word(p+4),op=h&65535;
    if((h>>16)!=n||id>=0xff000000u)return 0;
    enum rd_obj_type type=rd_obj(s,id)->type;
    if(type==RD_DISPLAY&&op==1&&n==12)return rd_add(s,word(p+8),RD_REGISTRY,id);
    if(type==RD_REGISTRY&&op==0&&n>=24){
        uint32_t len=word(p+12),pad=(len+3)&~3u;
        if(!len||len>64||16u+pad+8u!=n||p[16+len-1]!=0)return 0;
        enum rd_obj_type t=RD_NONE;
        if(len==14&&!memcmp(p+16,"wl_compositor",14))t=RD_COMPOSITOR;
        if(len==12&&!memcmp(p+16,"xdg_wm_base",12))t=RD_WM_BASE;
        return t!=RD_NONE&&rd_add(s,word(p+20+pad),t,id);
    }
    if(type==RD_COMPOSITOR&&op==0&&n==12)return rd_add(s,word(p+8),RD_WL_SURFACE,id);
    if(type==RD_WM_BASE&&op==2&&n==16){
        uint32_t surf=word(p+12);
        if(rd_obj(s,surf)->type!=RD_WL_SURFACE||surface_has_role(s,surf))return 0;
        return rd_add(s,word(p+8),RD_XDG_SURFACE,surf);
    }
    if(type==RD_XDG_SURFACE&&op==1&&n==12)return rd_add(s,word(p+8),RD_TOPLEVEL,id);
    return 0;
}
static int occupied(struct parse *s,uint32_t id){
    if(!id||id>=0xff000000u)return 1;
    return rd_find(s,id)!=NULL;
}
static int server_offer_slot(struct parse *s,uint32_t id){
    for(unsigned n=0,h=rd_hash(&s->objects,id);n<RD_PROBE_CAP;n++){
        unsigned at=(h+n)&(RD_OBJECT_CAP-1);
        struct rd_object *o=&s->objects.slot[at];
        if(o->state==RD_EMPTY)return -1;
        if((o->state==RD_LIVE||o->state==RD_WAIT_DELETE)&&o->id==id)
            return o->server_offer?(int)at:-1;
    }
    return -1;
}
struct rd_host_lineage_event {uint32_t magic,version;uint64_t surface_id;
    int32_t peer_pid;uint32_t reserved;uint64_t generation;audit_token_t audit;};
/* Written only after the relay has forwarded and validated the exact wire
 * request. IDs are scoped to this relay connection and its audit token;
 * guest wl_resource pointers are never an authority. */
static int write_exact(int fd,const void *data,size_t size){
    const unsigned char *p=data;
    while(size){ssize_t n=write(fd,p,size);if(n<=0){if(n<0&&errno==EINTR)continue;return 0;}
        p+=n;size-=(size_t)n;}
    return 1;
}
static int coordinator_dead(int fd){
    struct pollfd p={fd,POLLIN|POLLHUP|POLLERR,0};
    int n=poll(&p,1,0);
    return n<0 ? errno!=EINTR : n>0 && (p.revents&(POLLIN|POLLHUP|POLLERR|POLLNVAL));
}
static int emit_event(struct parse *s,uint32_t magic,unsigned obj){
    struct rd_host_lineage_event e={magic,1,
        ((uint64_t)s->host_connection<<32)|obj,s->peer_pid,0,
        rd_obj(s,obj)->top.generation,s->audit};
    return (s->supervisor_fd<0||write_exact(s->supervisor_fd,&e,sizeof(e)))&&
           (s->event_fd<0||write_exact(s->event_fd,&e,sizeof(e)));
}
static int emit_owned_create(struct parse *s,uint32_t manager,uint32_t id,
                             const unsigned char token[16],uint64_t sequence,
                             uint32_t width,uint32_t height,uint32_t stride,
                             uint32_t format){
    if(!s->emit_owned)return 1;
    if(s->owned_event_fd<0)return 0;
    struct rd_owned_wire_event e={0};
    e.magic=RD_OWNED_WIRE_CREATE;e.version=RD_OWNED_WIRE_VERSION;
    e.connection=s->host_connection;
    e.manager_id=manager;e.buffer_id=id;e.generation=rd_obj(s,id)->generation;
    e.sequence=sequence;e.width=width;e.height=height;
    e.stride=stride;e.format=format;memcpy(e.token,token,16);
    e.peer_pid=s->peer_pid;e.audit=s->audit;
    return write_exact(s->owned_event_fd,&e,sizeof(e));
}
static int emit_owned_destroy(struct parse *s,uint32_t id,uint64_t generation){
    if(!s->emit_owned)return 1;
    if(s->owned_event_fd<0)return 0;
    struct rd_owned_wire_event e={0};
    e.magic=RD_OWNED_WIRE_DESTROY;e.version=RD_OWNED_WIRE_VERSION;
    e.connection=s->host_connection;
    e.buffer_id=id;e.generation=generation;
    e.peer_pid=s->peer_pid;e.audit=s->audit;
    return write_exact(s->owned_event_fd,&e,sizeof(e));
}
static int emit_dmabuf(struct parse *s,uint32_t magic,uint32_t params,
                       uint32_t id,uint32_t width,uint32_t height,
                       uint32_t stride,uint64_t dev,uint64_t ino){
    if(!s->emit_dmabuf)return 1;
    if(s->dmabuf_event_fd<3||!dev||!ino)return 0;
    struct rd_dmabuf_wire_event e={0};
    e.magic=magic;e.version=RD_DMABUF_WIRE_VERSION;
    e.connection=s->host_connection;e.generation=rd_obj(s,id)->generation;
    e.params_id=params;e.buffer_id=id;e.width=width;e.height=height;
    e.stride=stride;e.format=RD_DMABUF_ARGB8888;
    e.fd_dev=dev;e.fd_ino=ino;e.peer_pid=s->peer_pid;e.audit=s->audit;
    return write_exact(s->dmabuf_event_fd,&e,sizeof e);
}
static void revoke_for(struct parse *s,uint32_t obj){
    if(obj<0xff000000u)rd_obj(s,obj)->dead=1;
    for(unsigned i=0;i<RD_OBJECT_CAP;i++)if(s->objects.slot[i].type==RD_TOPLEVEL){
        struct rd_object *o=&s->objects.slot[i];
        uint32_t xdg=o->parent,wl=xdg?rd_obj(s,xdg)->parent:0;
        if(obj==o->id||obj==xdg||obj==wl){o->top.dead=1;o->dead=1;}
    }
}
static int tablet_type(enum rd_obj_type t){return t>=RD_TABLET_MANAGER&&t<=RD_TABLET_DIAL;}
static int tablet_string_tail(const unsigned char *b,size_t n,size_t off){
    return wire_string(b,n,off,0);
}
static int tablet_array_tail(const unsigned char *b,size_t n,size_t off){
    if(off+4>n)return 0;
    uint32_t len=word(b+off);
    return len<=4096 && off+4u+((len+3u)&~3u)==n;
}
static int tablet_server_shape(enum rd_obj_type t,unsigned op,const unsigned char *b,size_t n,unsigned ver){
    switch(t){
    case RD_TABLET_SEAT:return op<=2&&n==12;
    case RD_TABLET:return (op==0||op==2)?tablet_string_tail(b,n,8):
        (op==1&&n==16)||(op==3&&n==8)||(op==4&&n==8)||
        (op==5&&ver>=2&&n==12);
    case RD_TABLET_TOOL:{static const unsigned short z[]={12,16,16,12,8,8,20,8,12,8,16,12,12,16,12,12,16,20,12};
        return op<sizeof(z)/sizeof(z[0])&&n==z[op];}
    case RD_TABLET_PAD:return (op==0&&n==12)||(op==1&&tablet_string_tail(b,n,8))||
        (op==2&&n==12)||(op==3&&n==8)||(op==4&&n==20)||
        (op==5&&n==20)||(op==6&&n==16)||(op==7&&n==8);
    case RD_TABLET_GROUP:return (op==0&&tablet_array_tail(b,n,8))||
        ((op==1||op==2||op==6)&&n==12&&(op!=6||ver>=2))||
        (op==3&&n==12)||(op==4&&n==8)||(op==5&&n==20);
    case RD_TABLET_RING:case RD_TABLET_STRIP:return (op==0||op==1||op==3)?n==12:op==2&&n==8;
    case RD_TABLET_DIAL:return (op==0||op==1)&&n==12;
    default:return 0;
    }
}
static enum rd_obj_type tablet_event_child(enum rd_obj_type t,unsigned op){
    if(t==RD_TABLET_SEAT)return op==0?RD_TABLET:op==1?RD_TABLET_TOOL:op==2?RD_TABLET_PAD:RD_NONE;
    if(t==RD_TABLET_PAD&&op==0)return RD_TABLET_GROUP;
    if(t==RD_TABLET_GROUP)return op==1?RD_TABLET_RING:op==2?RD_TABLET_STRIP:op==6?RD_TABLET_DIAL:RD_NONE;
    return RD_NONE;
}
static int tablet_ref(struct parse *s,uint32_t id,enum rd_obj_type t){
    struct rd_object *o=rd_find(s,id);return o&&o->type==t&&!o->dead;
}
static void inspect_server(struct parse *s,const unsigned char *p,size_t n){
    if(n>sizeof(s->server_b)-s->server_n){s->denied++;s->server_n=0;return;}
    memcpy(s->server_b+s->server_n,p,n);s->server_n+=n;
    while(s->server_n>=8){uint32_t h=word(s->server_b+4);size_t sz=h>>16;
        if(sz<8||sz>65535||(sz&3)){s->denied++;s->server_n=0;return;}
        if(s->server_n<sz)break;
        uint32_t obj=word(s->server_b),op=h&65535;
        if(rd_view(s,obj)->dead&&rd_view(s,obj)->type>=RD_OUTPUT)s->denied++;
        if(obj<0xff000000u&&rd_view(s,obj)->type==RD_REGISTRY){
            if(op==0){
                if(sz<24){s->denied++;}
                else {uint32_t name=word(s->server_b+8),len=word(s->server_b+12);
                    uint32_t padded=(len+3u)&~3u;
                    if(!len||len>64||16u+padded+4u!=sz||s->server_b[16+len-1]!=0)
                        s->denied++;
                    else {unsigned slot=256;
                        for(unsigned i=0;i<256;i++)if(s->globals[i].registry==obj&&
                            s->globals[i].name==name){s->denied++;break;}
                        if(!s->denied){for(unsigned i=0;i<256;i++)if(!s->globals[i].registry){slot=i;break;}
                            if(slot==256)s->denied++;
                            else {s->globals[slot]=(struct advertised_global){.registry=obj,.name=name,
                                .version=word(s->server_b+16+padded)};
                                memcpy(s->globals[slot].iface,s->server_b+16,len);}}
                    }
                }
            }else if(op==1&&sz==12){uint32_t name=word(s->server_b+8);
                for(unsigned i=0;i<256;i++)if(s->globals[i].registry==obj&&
                    s->globals[i].name==name)s->globals[i].registry=0;
            }else s->denied++;
        }
        /* wl_display.delete_id is the server's final object-lifetime event. */
        if(obj==1&&op==1&&sz==12){
            uint32_t deleted=word(s->server_b+8);
            if(deleted>=0xff000000u&&tablet_type(rd_view(s,deleted)->type)){
                struct rd_object *old=rd_find(s,deleted);
                if(old)old->state=RD_TOMBSTONE;
            }
            int slot=server_offer_slot(s,deleted);
            if(slot>=0){s->objects.slot[slot].server_offer=0;
                s->objects.slot[slot].server_offer_version=0;
                s->objects.slot[slot].server_offer_dead=0;
                s->objects.slot[slot].state=RD_TOMBSTONE;}
            if(deleted<0xff000000u&&(rd_view(s,deleted)->shm||rd_view(s,deleted)->pool||rd_view(s,deleted)->buffer||
                             rd_view(s,deleted)->seat||rd_view(s,deleted)->keyboard||rd_view(s,deleted)->pointer||rd_view(s,deleted)->touch||
                             rd_view(s,deleted)->layer_shell||rd_view(s,deleted)->layer_surface||
                             rd_view(s,deleted)->data_manager||rd_view(s,deleted)->data_device||
                             rd_view(s,deleted)->data_source||rd_view(s,deleted)->data_offer)){
                rd_view(s,deleted)->shm=rd_view(s,deleted)->pool=rd_view(s,deleted)->buffer=0;
                rd_view(s,deleted)->seat=rd_view(s,deleted)->keyboard=rd_view(s,deleted)->pointer=rd_view(s,deleted)->touch=0;
                rd_view(s,deleted)->layer_shell=rd_view(s,deleted)->layer_surface=0;rd_view(s,deleted)->layer_parent=0;
                rd_view(s,deleted)->data_manager=rd_view(s,deleted)->data_device=0;
                rd_view(s,deleted)->data_source=rd_view(s,deleted)->data_offer=0;
                rd_view(s,deleted)->version=0;
                /* A wl_shm_pool or wl_buffer ID is reusable only after the
                 * server's delete_id, just like a tracked xdg object. */
                rd_view(s,deleted)->dead=0;
            }
            if(deleted<0xff000000u&&rd_view(s,deleted)->type!=RD_NONE){
                if(rd_view(s,deleted)->pending_delete)s->denied++;
                else {revoke_for(s,deleted);rd_view(s,deleted)->pending_delete=1;}
            }else if(deleted<0xff000000u){struct rd_object *old=rd_find(s,deleted);
                if(old)old->state=RD_TOMBSTONE;}
        }
        if(obj<0xff000000u&&rd_view(s,obj)->keyboard){
            if(op==0&&sz==16)s->server_fd_required++;
            else if(op>5||sz<8)s->denied++;
        }
        if(obj<0xff000000u&&rd_view(s,obj)->type==RD_OUTPUT){
            uint8_t v=rd_view(s,obj)->version;
            if(op==0){
                size_t after_make=sz>=28?wire_string_next(s->server_b,sz,28):0;
                size_t after_model=after_make?wire_string_next(s->server_b,sz,after_make):0;
                if(!after_model||after_model+4!=sz)s->denied++;
            }else if((op==1&&sz!=24)||(op==2&&(v<2||sz!=8))||
                     (op==3&&(v<2||sz!=12))||
                     ((op==4||op==5)&&(v<4||!wire_string(s->server_b,sz,8,0)))||op>5)
                s->denied++;
        }
        if(obj<0xff000000u&&rd_view(s,obj)->type==RD_FRACTIONAL_SCALE&&
           (op!=0||sz!=12))s->denied++;
        enum rd_obj_type server_ext=rd_view(s,obj)->type;
        if(server_ext==RD_SUBCOMPOSITOR||server_ext==RD_SUBSURFACE||
           server_ext==RD_VIEWPORTER||server_ext==RD_VIEWPORT||
           server_ext==RD_FRACTIONAL_MANAGER)s->denied++;
        if(obj<0xff000000u&&rd_view(s,obj)->data_device){
            static const unsigned short sizes[]={12,28,8,20,8,12};
            if(op>=6||sz!=sizes[op])s->denied++;
            else if(op==0){uint32_t id=word(s->server_b+8);
                if(id<0xff000000u||server_offer_slot(s,id)>=0)s->denied++;
                else {struct rd_object *offer=rd_find(s,id);
                    if(!offer)offer=rd_new(s,id);
                    if(!s->denied){offer->server_offer=1;offer->server_offer_dead=0;
                          offer->server_offer_version=rd_view(s,obj)->version;}}
            }
        }
        if(obj<0xff000000u&&rd_view(s,obj)->data_source){
            if(op==1){if(!wire_string(s->server_b,sz,8,0))s->denied++;
                else s->server_fd_required++;}
            else if((op==0&&!wire_string(s->server_b,sz,8,1))||
                    (op>=2&&op<=4&&sz!=8)||(op==5&&sz!=12)||op>5)s->denied++;
        }
        enum rd_obj_type kind=rd_view(s,obj)->type;
        if(kind==RD_OWNED_MANAGER)s->denied++; /* no server events */
        if(kind==RD_OWNED_BUFFER&&(op!=0||sz!=8))s->denied++;
        if(kind==RD_DMABUF_MANAGER&&
           !((op==0&&sz==12)||(op==1&&sz==20&&rd_view(s,obj)->version>=3)))
            s->denied++;
        if(kind==RD_DMABUF_PARAMS)s->denied++; /* create_immed has no events */
        if(kind==RD_DMABUF_BUFFER&&(op!=0||sz!=8))s->denied++;
        /* wl_region has no server events. */
        if(kind==RD_REGION)s->denied++;
        if(kind==RD_XDG_OUTPUT_MANAGER||kind==RD_SHORTCUTS_MANAGER)
            s->denied++; /* managers have no server events */
        if(kind==RD_XDG_OUTPUT){
            unsigned v=rd_view(s,obj)->version;
            if((op==0||op==1)&&sz==16){}
            else if(op==2&&sz==8){}
            else if((op==3||op==4)&&v>=2&&wire_string(s->server_b,sz,8,0)){}
            else s->denied++;
        }
        if(kind==RD_SHORTCUTS_INHIBITOR&&
           !((op==0||op==1)&&sz==8))s->denied++;
        if(tablet_type(kind)){
            struct rd_object *current=rd_view(s,obj);
            if(!tablet_server_shape(kind,op,s->server_b,sz,current->version))s->denied++;
            else {
                enum rd_obj_type child=tablet_event_child(kind,op);
                if(child){uint32_t id=word(s->server_b+8);
                    if(id<0xff000000u||rd_find(s,id))s->denied++;
                    else {struct rd_object *created=rd_new(s,id);created->type=child;
                        created->parent=obj;created->version=current->version;}}
                if(kind==RD_TABLET_TOOL&&op==6&&
                    (!tablet_ref(s,word(s->server_b+12),RD_TABLET)||
                     !tablet_ref(s,word(s->server_b+16),RD_WL_SURFACE)))s->denied++;
                if(kind==RD_TABLET_PAD&&op==5&&
                    (!tablet_ref(s,word(s->server_b+12),RD_TABLET)||
                     !tablet_ref(s,word(s->server_b+16),RD_WL_SURFACE)))s->denied++;
                if(kind==RD_TABLET_PAD&&op==6&&
                    !tablet_ref(s,word(s->server_b+12),RD_WL_SURFACE))s->denied++;
            }
        }
        if(kind==RD_PRESENTATION&&!(op==0&&sz==12))s->denied++;
        if(kind==RD_PRESENTATION_FEEDBACK){
            if((op==0&&sz!=12)||(op==1&&sz!=36)||(op==2&&sz!=8)||op>2)
                s->denied++;
            if(op==1||op==2)rd_view(s,obj)->dead=1;
        }
        if(kind==RD_KDE_DECORATION_MANAGER&&!(op==0&&sz==12))s->denied++;
        if(kind==RD_KDE_DECORATION&&!(op==0&&sz==12))s->denied++;
        if(kind==RD_PRIMARY_DEVICE){
            if((op==0&&sz!=12)||(op==1&&sz!=12)||op>1)s->denied++;
            if(op==0&&sz==12){uint32_t id=word(s->server_b+8);
                if(id<0xff000000u||rd_find(s,id))s->denied++;
                else {struct rd_object *offer=rd_new(s,id);
                    offer->type=RD_PRIMARY_OFFER;offer->server_offer=1;
                    offer->parent=obj;offer->version=1;}}
            if(op==1&&sz==12){uint32_t id=word(s->server_b+8);
                if(id&&rd_view(s,id)->type!=RD_PRIMARY_OFFER)s->denied++;}
        }
        if(kind==RD_PRIMARY_SOURCE){
            if(op==0){if(!wire_string(s->server_b,sz,8,0))s->denied++;
                else s->server_fd_required++;}
            else if(op==1&&sz==8)rd_view(s,obj)->dead=1;
            else s->denied++;
        }
        if(kind==RD_PRIMARY_OFFER&&!(op==0&&wire_string(s->server_b,sz,8,0)))
            s->denied++;
        int high_offer=server_offer_slot(s,obj);
        if((obj<0xff000000u&&rd_view(s,obj)->data_offer)||high_offer>=0){
            if(op==0){if(!wire_string(s->server_b,sz,8,0))s->denied++;}
            else if((op==1&&sz!=12)||(op==2&&sz!=12)||op>2)s->denied++;
        }
        /* Only the compositor can issue xdg_surface.configure. This is the
         * earliest confirmation that the claimed role chain was accepted. */
        if(obj<0xff000000u&&rd_view(s,obj)->type==RD_XDG_SURFACE&&op==0){
            if(sz!=12)s->denied++;
            else for(unsigned i=0;i<RD_OBJECT_CAP;i++)if(s->objects.slot[i].type==RD_TOPLEVEL&&
                s->objects.slot[i].parent==obj&&!s->objects.slot[i].top.dead)
                    s->objects.slot[i].top.configured=1;
        }
        if(obj<0xff000000u&&rd_view(s,obj)->type==RD_ACTIVATION_TOKEN&&
           (op!=0||!wire_string(s->server_b,sz,8,0)))s->denied++;
        enum rd_obj_type gt=rd_view(s,obj)->type;
        if(gt==RD_GESTURE_SWIPE||gt==RD_GESTURE_PINCH||gt==RD_GESTURE_HOLD){
            unsigned expected=(gt==RD_GESTURE_HOLD?
                (op==0?24u:op==1?20u:0u):
                (op==0?24u:op==1?(gt==RD_GESTURE_SWIPE?20u:28u):op==2?20u:0u));
            if(!expected||sz!=expected)s->denied++;
            else if(op==0){uint32_t surf=word(s->server_b+16);
                if(rd_view(s,surf)->type!=RD_WL_SURFACE||rd_view(s,surf)->dead)s->denied++;}
        }
        memmove(s->server_b,s->server_b+sz,s->server_n-sz);s->server_n-=sz;
    }
}
static int fd_arity(struct parse *s,uint32_t obj,unsigned op,size_t sz){
    if(obj>=0xff000000u&&!tablet_type(rd_view(s,obj)->type)){int slot=server_offer_slot(s,obj);
        if(slot<0)return -1;
        if(s->objects.slot[slot].server_offer_dead)return -1;
        if(s->objects.slot[slot].type==RD_PRIMARY_OFFER)
            return op==0&&wire_string(s->b,sz,8,0)?1:
                op==1&&sz==8?0:-1;
        if(op==0)return wire_string(s->b,sz,12,1)?0:-1;
        if(op==1)return wire_string(s->b,sz,8,0)?1:-1;
        return (op==2&&sz==8)||(op==3&&sz==8&&s->objects.slot[slot].server_offer_version>=3)||
               (op==4&&sz==16&&s->objects.slot[slot].server_offer_version>=3)?0:-1;
    }
    if(obj>1&&obj<0xff000000u&&!rd_find(s,obj)){
        if(s->strict_capability)return -1;
        /* An unaudited extension may create a child object. It cannot carry
         * FDs or participate in native lineage; the backend validates it. */
        rd_new(s,obj)->type=RD_UNTRACKED;
        return s->denied?-1:0;
    }
    if(rd_obj(s,obj)->shm)return op==0&&sz==16?1:op==1&&sz==8&&rd_obj(s,obj)->version>=2?0:-1;
    if(rd_obj(s,obj)->pool)return op==0&&sz==32?0:op==1&&sz==8?0:op==2&&sz==12?0:-1;
    if(rd_obj(s,obj)->buffer)return op==0&&sz==8?0:-1;
    if(rd_obj(s,obj)->seat)return op<=2&&sz==12?0:
        op==3&&sz==8&&rd_obj(s,obj)->version>=5?0:-1;
    if(rd_obj(s,obj)->keyboard)return op==0&&sz==8&&rd_obj(s,obj)->version>=3?0:-1;
    if(rd_obj(s,obj)->pointer)return op==0&&sz==24?0:op==1&&sz==8&&rd_obj(s,obj)->version>=3?0:-1;
    if(rd_obj(s,obj)->touch)return op==0&&sz==8&&rd_obj(s,obj)->version>=3?0:-1;
    if(rd_obj(s,obj)->data_manager)return (op==0&&sz==12)||(op==1&&sz==16)?0:-1;
    if(rd_obj(s,obj)->data_device)return (op==0&&sz==24)||(op==1&&sz==16)||
        (op==2&&sz==8&&rd_obj(s,obj)->version>=2)?0:-1;
    if(rd_obj(s,obj)->data_source)return (op==0&&wire_string(s->b,sz,8,0))||
        (op==1&&sz==8)||(op==2&&sz==12&&rd_obj(s,obj)->version>=3)?0:-1;
    if(rd_obj(s,obj)->data_offer){
        if(op==0)return wire_string(s->b,sz,12,1)?0:-1;
        if(op==1)return wire_string(s->b,sz,8,0)?1:-1;
        return (op==2&&sz==8)||(op==3&&sz==8&&rd_obj(s,obj)->version>=3)||
               (op==4&&sz==16&&rd_obj(s,obj)->version>=3)?0:-1;
    }
    if(rd_obj(s,obj)->layer_shell){
        if(op==1)return sz==8&&rd_obj(s,obj)->version>=3?0:-1;
        if(op!=0||sz<28)return -1;
        uint32_t len=word(s->b+24);
        return len&&len<=4096&&28u+((len+3)&~3u)==sz?0:-1;
    }
    if(rd_obj(s,obj)->layer_surface){
        static const unsigned short sizes[]={16,12,12,24,12,12,12,8,12,12};
        if(op>=10||sz!=sizes[op]||(op==8&&rd_obj(s,obj)->version<2)||
           (op==9&&rd_obj(s,obj)->version<5))return -1;
        return 0;
    }
    switch(rd_obj(s,obj)->type){
    case RD_DMABUF_MANAGER:
        return (op==0&&sz==8)||(op==1&&sz==12)?0:-1;
    case RD_DMABUF_PARAMS:
        if(op==0)return sz==8?0:-1;
        if(op==1)return sz==28&&word(s->b+8)==0&&word(s->b+12)==0&&
            word(s->b+16)>0&&word(s->b+20)==0&&word(s->b+24)==0?1:-1;
        if(op==2)return -1; /* async create needs server-created ID tracking */
        if(op==3)return sz==28&&word(s->b+20)==RD_DMABUF_ARGB8888&&
            word(s->b+24)==0?0:-1;
        return -1;
    case RD_DMABUF_BUFFER:return op==0&&sz==8?0:-1;
    case RD_OWNED_MANAGER:
        if(op==1)return sz==8?0:-1;
        if(op!=0||sz!=56||word(s->b+12)!=16)return -1;
        return 0;
    case RD_OWNED_BUFFER:return op==0&&sz==8?0:-1;
    case RD_XDG_OUTPUT_MANAGER: return (op==0&&sz==8)||(op==1&&sz==16)?0:-1;
    case RD_XDG_OUTPUT: return op==0&&sz==8?0:-1;
    case RD_SHORTCUTS_MANAGER: return (op==0&&sz==8)||(op==1&&sz==20)?0:-1;
    case RD_SHORTCUTS_INHIBITOR: return op==0&&sz==8?0:-1;
    case RD_OUTPUT: return op==0&&sz==8&&rd_obj(s,obj)->version>=3?0:-1;
    case RD_SUBCOMPOSITOR: return (op==0&&sz==8)||(op==1&&sz==20)?0:-1;
    case RD_SUBSURFACE: return (op==0&&sz==8)||(op==1&&sz==16)||
        ((op==2||op==3)&&sz==12)||((op==4||op==5)&&sz==8)?0:-1;
    case RD_VIEWPORTER: return (op==0&&sz==8)||(op==1&&sz==16)?0:-1;
    case RD_VIEWPORT: return (op==0&&sz==8)||(op==1&&sz==24)||
        (op==2&&sz==16)?0:-1;
    case RD_FRACTIONAL_MANAGER: return (op==0&&sz==8)||(op==1&&sz==16)?0:-1;
    case RD_FRACTIONAL_SCALE: return op==0&&sz==8?0:-1;
    case RD_DISPLAY: return (op<=1&&sz==12)?0:-1;
    case RD_REGISTRY: return op==0&&sz>=24?0:-1;
    case RD_COMPOSITOR: return op<=1&&sz==12?0:-1;
    case RD_REGION: return (op==0&&sz==8)||((op==1||op==2)&&sz==24)?0:-1;
    case RD_WL_SURFACE: {
        static const unsigned short sizes[]={8,20,24,12,12,12,8,12,12,24,16};
        if(op>=sizeof(sizes)/sizeof(sizes[0])||sz!=sizes[op])return -1;
        if(rd_obj(s,obj)->version&&((op==7&&rd_obj(s,obj)->version<2)||
            (op==8&&rd_obj(s,obj)->version<3)||(op==9&&rd_obj(s,obj)->version<4)||
            (op==10&&rd_obj(s,obj)->version<5)))return -1;
        return 0;}
    case RD_WM_BASE: {
        static const unsigned short sizes[]={8,12,16,12};
        return op<sizeof(sizes)/sizeof(sizes[0])&&sz==sizes[op]?0:-1;}
    case RD_XDG_SURFACE: {
        static const unsigned short sizes[]={8,12,20,24,12};
        return op<sizeof(sizes)/sizeof(sizes[0])&&sz==sizes[op]?0:-1;}
    case RD_TOPLEVEL: {
        static const unsigned short sizes[]={8,12,0,0,24,16,20,16,16,8,8,12,8,8};
        if(op>=sizeof(sizes)/sizeof(sizes[0]))return -1;
        if(op==2||op==3)return sz>=12&&!(sz&3)?0:-1;
        return sz==sizes[op]?0:-1;}
    case RD_IDLE_MANAGER: return (op==0&&sz==8)||(op==1&&sz==16)?0:-1;
    case RD_IDLE_INHIBITOR: return op==0&&sz==8?0:-1;
    case RD_ACTIVATION:
        if(op==0)return sz==8?0:-1;
        if(op==1)return sz==12?0:-1;
        if(op==2){
            if(sz<20)return -1;
            uint32_t len=word(s->b+8),pad=(len+3u)&~3u;
            return len&&len<=4096&&12u+pad+4u==sz&&
                s->b[12u+len-1u]==0?0:-1;
        }
        return -1;
    case RD_ACTIVATION_TOKEN:
        if(op==0||op==2)return sz==16?0:-1;
        if(op==1)return wire_string(s->b,sz,8,0)?0:-1;
        return (op==3||op==4)&&sz==8?0:-1;
    case RD_GESTURES:
        if(op==2)return sz==8&&rd_obj(s,obj)->version>=2?0:-1;
        return (op==0||op==1||(op==3&&rd_obj(s,obj)->version>=3))&&sz==16?0:-1;
    case RD_GESTURE_SWIPE:
    case RD_GESTURE_PINCH:
    case RD_GESTURE_HOLD: return op==0&&sz==8?0:-1;
    case RD_PRESENTATION: return (op==0&&sz==8)||(op==1&&sz==16)?0:-1;
    case RD_PRESENTATION_FEEDBACK: return -1; /* server events only */
    case RD_KDE_DECORATION_MANAGER: return op==0&&sz==16?0:-1;
    case RD_KDE_DECORATION: return (op==0&&sz==8)||(op==1&&sz==12)?0:-1;
    case RD_PRIMARY_MANAGER: return (op==0&&sz==12)||(op==1&&sz==16)||
        (op==2&&sz==8)?0:-1;
    case RD_PRIMARY_SOURCE: return (op==0&&wire_string(s->b,sz,8,0))||
        (op==1&&sz==8)?0:-1;
    case RD_PRIMARY_DEVICE: return (op==0&&sz==16)||(op==1&&sz==8)?0:-1;
    case RD_PRIMARY_OFFER: return op==0&&wire_string(s->b,sz,8,0)?1:
        op==1&&sz==8?0:-1;
    case RD_TABLET_MANAGER:return (op==0&&sz==16)||(op==1&&sz==8)?0:-1;
    case RD_TABLET_SEAT:case RD_TABLET:case RD_TABLET_GROUP:
        return op==0&&sz==8?0:-1;
    case RD_TABLET_PAD:
        if(op==1)return sz==8?0:-1;
        if(op==0&&sz>=20){size_t after=wire_string_next(s->b,sz,12);
            return after&&after+4==sz?0:-1;}
        return -1;
    case RD_TABLET_TOOL:return (op==0&&sz==24)||(op==1&&sz==8)?0:-1;
    case RD_TABLET_RING:case RD_TABLET_STRIP:case RD_TABLET_DIAL:
        return op==0&&sz>=16&&wire_string(s->b,sz-4,8,0)?0:
            op==1&&sz==8?0:-1;
    case RD_UNTRACKED: return s->strict_capability?-1:0;
    default: return -1;
    }
}
static void inspect(struct parse *s,const unsigned char *p,size_t n){
    if(n>sizeof(s->b)-s->n){s->denied++;s->n=0;return;}
    memcpy(s->b+s->n,p,n);s->n+=n;
    while(s->n>=8){uint32_t h=word(s->b+4);size_t sz=h>>16;
        if(sz<8||sz>65535||(sz&3)){s->denied++;s->n=0;return;}
        if(s->n<sz)break;
        uint32_t obj=word(s->b);unsigned op=h&65535;
        unsigned denied_before=s->denied;
        enum rd_obj_type type_before=rd_obj(s,obj)->type;
        int arity=fd_arity(s,obj,op,sz);
        if(arity<0)s->denied++;else s->fd_required+=(unsigned)arity;
        if(rd_obj(s,obj)->dead)s->denied++;
        if(obj<0xff000000u&&sz==8&&((rd_obj(s,obj)->shm&&op==1)||
           (rd_obj(s,obj)->pool&&op==1)||(rd_obj(s,obj)->buffer&&op==0)))rd_obj(s,obj)->dead=1;
        if(type_before==RD_OWNED_MANAGER&&op==1&&sz==8)rd_obj(s,obj)->dead=1;
        if((type_before==RD_DMABUF_MANAGER||type_before==RD_DMABUF_PARAMS)&&
           op==0&&sz==8)rd_obj(s,obj)->dead=1;
        if(obj<0xff000000u&&op==0&&sz==8&&
           (rd_obj(s,obj)->type==RD_TOPLEVEL||rd_obj(s,obj)->type==RD_XDG_SURFACE||
            rd_obj(s,obj)->type==RD_WL_SURFACE))revoke_for(s,obj);
        /* This control tracks creation lineage. Other legal Wayland requests
         * pass through, but cannot grant a host surface capability. */
        int known_registry=0;
        if(obj<0xff000000u&&rd_obj(s,obj)->type==RD_REGISTRY&&op==0&&sz>=24){
            uint32_t len=word(s->b+12);
            if(len<=64&&16u+((len+3)&~3u)+8u==sz){
                uint32_t name=word(s->b+8),requested=word(s->b+16+((len+3)&~3u));
                int advertised=0;
                for(unsigned i=0;i<256;i++)if(s->globals[i].registry==obj&&
                    s->globals[i].name==name&&s->globals[i].version>=requested&&requested&&
                    strlen(s->globals[i].iface)+1==len&&
                    !memcmp(s->globals[i].iface,s->b+16,len)){advertised=1;break;}
                if(!advertised)s->denied++;
                known_registry=(len==14&&!memcmp(s->b+16,"wl_compositor",14))||
                               (len==12&&!memcmp(s->b+16,"xdg_wm_base",12));
                int is_layer=len==19&&!memcmp(s->b+16,"zwlr_layer_shell_v1",19);
                int is_data=len==23&&!memcmp(s->b+16,"wl_data_device_manager",23);
                enum rd_obj_type ext=extension_type(s->b+16,len);
                unsigned ext_max=extension_max_version(ext);
                int is_idle=len==28&&!memcmp(s->b+16,"zwp_idle_inhibit_manager_v1",28);
                int is_activation=len==18&&!memcmp(s->b+16,"xdg_activation_v1",18);
                int is_gestures=len==24&&!memcmp(s->b+16,"zwp_pointer_gestures_v1",24);
                if(ext==RD_NONE&&len==sizeof("wp_presentation")&&
                   !memcmp(s->b+16,"wp_presentation",len))
                    ext=RD_PRESENTATION,ext_max=2;
                else if(ext==RD_NONE&&len==sizeof("org_kde_kwin_server_decoration_manager")&&
                        !memcmp(s->b+16,"org_kde_kwin_server_decoration_manager",len))
                    ext=RD_KDE_DECORATION_MANAGER,ext_max=1;
                else if(ext==RD_NONE&&len==sizeof("zwp_primary_selection_device_manager_v1")&&
                        !memcmp(s->b+16,"zwp_primary_selection_device_manager_v1",len))
                    ext=RD_PRIMARY_MANAGER,ext_max=1;
                uint32_t id=word(s->b+20+((len+3)&~3u));
                int is_shm=len==7&&!memcmp(s->b+16,"wl_shm",7);
                int is_seat=len==8&&!memcmp(s->b+16,"wl_seat",8);
                if((known_registry||is_shm||is_seat||is_layer||is_data||is_idle||is_activation||is_gestures)&&
                   (!requested||requested>(known_registry?
                      (len==14?6u:7u):(is_shm?2u:is_layer?5u:is_data?3u:is_idle||is_activation?1u:is_gestures?3u:9u))))s->denied++;
                if(ext!=RD_NONE&&requested>ext_max)s->denied++;
                if(is_shm||is_seat||is_layer||is_data||is_idle||is_activation||is_gestures){
                    if(occupied(s,id))
                        s->denied++;
                    else {struct rd_object *created=rd_alloc(s,id);
                          if(is_shm)created->shm=1;else if(is_seat)created->seat=1;
                          else if(is_layer)created->layer_shell=1;
                          else if(is_data)created->data_manager=1;
                          else created->type=is_idle?RD_IDLE_MANAGER:is_activation?RD_ACTIVATION:RD_GESTURES;
                          rd_obj(s,id)->version=(unsigned char)requested;}
                }else if(ext!=RD_NONE&&advertised){
                    if(requested>ext_max||occupied(s,id))s->denied++;
                    else {struct rd_object *created=rd_alloc(s,id);
                        created->type=ext;created->version=(unsigned char)requested;}
                }else if(!known_registry&&advertised){
                    if(s->strict_capability&&getenv("RD_UNIFIED_TRACE"))
                        fprintf(stderr,"STRICT_UNMODELED_BIND iface=%.*s id=%u\n",(int)len-1,s->b+16,id);
                    if(s->strict_capability||occupied(s,id))s->denied++;
                    else {struct rd_object *created=rd_alloc(s,id);
                        created->type=RD_UNTRACKED;created->version=(unsigned char)requested;}
                }
            }
        }
        if(tablet_type(rd_obj(s,obj)->type)&&arity==0){
            enum rd_obj_type tt=rd_obj(s,obj)->type;
            if(tt==RD_TABLET_MANAGER&&op==0){uint32_t id=word(s->b+8),seat=word(s->b+12);
                if(occupied(s,id)||!rd_obj(s,seat)->seat||rd_obj(s,seat)->dead)s->denied++;
                else {struct rd_object *child=rd_alloc(s,id);child->type=RD_TABLET_SEAT;
                    child->parent=seat;child->version=rd_obj(s,obj)->version;}}
            if(tt==RD_TABLET_TOOL&&op==0){uint32_t surf=word(s->b+12);
                if(surf&&!tablet_ref(s,surf,RD_WL_SURFACE))s->denied++;}
            if(sz==8&&((tt==RD_TABLET_MANAGER&&op==1)||
                (tt==RD_TABLET_SEAT&&op==0)||(tt==RD_TABLET&&op==0)||
                (tt==RD_TABLET_GROUP&&op==0)||(tt==RD_TABLET_PAD&&op==1)||
                (tt==RD_TABLET_TOOL&&op==1)||
                ((tt==RD_TABLET_RING||tt==RD_TABLET_STRIP||tt==RD_TABLET_DIAL)&&op==1)))
                rd_obj(s,obj)->dead=1;
        }
        if(obj<0xff000000u&&rd_obj(s,obj)->type==RD_IDLE_MANAGER&&op==1&&arity==0){
            uint32_t id=word(s->b+8),surface=word(s->b+12);
            if(occupied(s,id)||rd_obj(s,surface)->type!=RD_WL_SURFACE||rd_obj(s,surface)->dead)
                s->denied++;
            else {struct rd_object *child=rd_alloc(s,id);
                child->type=RD_IDLE_INHIBITOR;child->parent=surface;child->version=1;}
        }
        if(obj<0xff000000u&&rd_obj(s,obj)->type==RD_ACTIVATION&&op==1&&arity==0){
            uint32_t id=word(s->b+8);
            if(occupied(s,id))s->denied++;
            else {struct rd_object *child=rd_alloc(s,id);
                child->type=RD_ACTIVATION_TOKEN;child->parent=obj;child->version=1;}
        }
        if(obj<0xff000000u&&rd_obj(s,obj)->type==RD_ACTIVATION&&op==2&&arity==0){
            uint32_t len=word(s->b+8),surface=word(s->b+12u+((len+3u)&~3u));
            if(rd_obj(s,surface)->type!=RD_WL_SURFACE||rd_obj(s,surface)->dead)s->denied++;
        }
        if(obj<0xff000000u&&rd_obj(s,obj)->type==RD_ACTIVATION_TOKEN&&arity==0){
            if(op==0){uint32_t seat=word(s->b+12);
                if(!rd_obj(s,seat)->seat||rd_obj(s,seat)->dead)s->denied++;}
            if(op==2){uint32_t surface=word(s->b+8);
                if(rd_obj(s,surface)->type!=RD_WL_SURFACE||rd_obj(s,surface)->dead)s->denied++;}
        }
        if(obj<0xff000000u&&rd_obj(s,obj)->type==RD_GESTURES&&arity==0&&
           (op==0||op==1||op==3)){
            uint32_t id=word(s->b+8),pointer=word(s->b+12);
            if(occupied(s,id)||!rd_obj(s,pointer)->pointer||rd_obj(s,pointer)->dead)s->denied++;
            else {struct rd_object *child=rd_alloc(s,id);
                child->type=op==0?RD_GESTURE_SWIPE:op==1?RD_GESTURE_PINCH:RD_GESTURE_HOLD;
                child->parent=pointer;child->version=rd_obj(s,obj)->version;}
        }
        if(obj<0xff000000u&&sz==8&&
            ((rd_obj(s,obj)->type==RD_IDLE_MANAGER&&op==0)||
             (rd_obj(s,obj)->type==RD_IDLE_INHIBITOR&&op==0)||
             (rd_obj(s,obj)->type==RD_ACTIVATION&&op==0)||
             (rd_obj(s,obj)->type==RD_ACTIVATION_TOKEN&&op==4)||
             (rd_obj(s,obj)->type==RD_GESTURES&&op==2)||
             (rd_obj(s,obj)->type>=RD_GESTURE_SWIPE&&rd_obj(s,obj)->type<=RD_GESTURE_HOLD&&op==0)))
            rd_obj(s,obj)->dead=1;
        if(obj<0xff000000u&&rd_obj(s,obj)->data_manager&&arity==0&&op<=1){
            uint32_t id=word(s->b+8),seat=op==1?word(s->b+12):0;
            if(occupied(s,id)||
               (op==1&&(seat>=0xff000000u||!rd_obj(s,seat)->seat||rd_obj(s,seat)->dead)))s->denied++;
            else {struct rd_object *created=rd_alloc(s,id);
                  if(op==0)created->data_source=1;else created->data_device=1;
                  rd_obj(s,id)->version=rd_obj(s,obj)->version;}
        }
        enum rd_obj_type kind=obj<0xff000000u?rd_obj(s,obj)->type:RD_NONE;
        if(kind==RD_XDG_OUTPUT_MANAGER&&op==1&&arity==0){
            uint32_t id=word(s->b+8),output=word(s->b+12);
            if(occupied(s,id)||rd_view(s,output)->type!=RD_OUTPUT||rd_view(s,output)->dead)
                s->denied++;
            else {struct rd_object *o=rd_alloc(s,id);o->type=RD_XDG_OUTPUT;
                o->parent=output;o->version=rd_obj(s,obj)->version;}
        }
        if(kind==RD_SHORTCUTS_MANAGER&&op==1&&arity==0){
            uint32_t id=word(s->b+8),surface=word(s->b+12),seat=word(s->b+16);
            int duplicate=0;
            for(unsigned j=0;j<RD_OBJECT_CAP;j++){
                struct rd_object *other=&s->objects.slot[j];
                if(other->state==RD_LIVE&&!other->dead&&
                   other->type==RD_SHORTCUTS_INHIBITOR&&other->parent==surface&&
                   other->layer_parent==seat)duplicate=1;
            }
            if(occupied(s,id)||rd_view(s,surface)->type!=RD_WL_SURFACE||
               rd_view(s,surface)->dead||!rd_view(s,seat)->seat||rd_view(s,seat)->dead||duplicate)
                s->denied++;
            else {struct rd_object *o=rd_alloc(s,id);o->type=RD_SHORTCUTS_INHIBITOR;
                o->parent=surface;o->layer_parent=seat;o->version=1;}
        }
        if(kind==RD_PRESENTATION&&op==1&&arity==0){
            uint32_t surface=word(s->b+8),id=word(s->b+12);
            if(occupied(s,id)||rd_view(s,surface)->type!=RD_WL_SURFACE||
               rd_view(s,surface)->dead)s->denied++;
            else {struct rd_object *o=rd_alloc(s,id);o->type=RD_PRESENTATION_FEEDBACK;
                o->parent=surface;o->version=rd_obj(s,obj)->version;}
        }
        if(kind==RD_KDE_DECORATION_MANAGER&&op==0&&arity==0){
            uint32_t id=word(s->b+8),surface=word(s->b+12);
            if(occupied(s,id)||rd_view(s,surface)->type!=RD_WL_SURFACE||
               rd_view(s,surface)->dead)s->denied++;
            else {struct rd_object *o=rd_alloc(s,id);o->type=RD_KDE_DECORATION;
                o->parent=surface;o->version=1;}
        }
        if(kind==RD_PRIMARY_MANAGER&&op<=1&&arity==0){
            uint32_t id=word(s->b+8),seat=op==1?word(s->b+12):0;
            if(occupied(s,id)||(op==1&&(!rd_view(s,seat)->seat||rd_view(s,seat)->dead)))
                s->denied++;
            else {struct rd_object *o=rd_alloc(s,id);
                o->type=op==0?RD_PRIMARY_SOURCE:RD_PRIMARY_DEVICE;
                o->parent=op==1?seat:obj;o->version=1;}
        }
        if(kind==RD_PRIMARY_DEVICE&&op==0&&arity==0){
            uint32_t source=word(s->b+8);
            if(source&&(rd_view(s,source)->type!=RD_PRIMARY_SOURCE||
                        rd_view(s,source)->dead))s->denied++;
        }
        if((kind==RD_PRIMARY_MANAGER&&op==2)||
           (kind==RD_PRIMARY_SOURCE&&op==1)||
           (kind==RD_PRIMARY_DEVICE&&op==1)||
           (kind==RD_PRIMARY_OFFER&&op==1)||
           (kind==RD_KDE_DECORATION&&op==0)||
           (kind==RD_PRESENTATION&&op==0)||
           (kind==RD_XDG_OUTPUT_MANAGER&&op==0)||
           (kind==RD_XDG_OUTPUT&&op==0)||
           (kind==RD_SHORTCUTS_MANAGER&&op==0)||
           (kind==RD_SHORTCUTS_INHIBITOR&&op==0))rd_obj(s,obj)->dead=1;
        if(obj<0xff000000u&&rd_obj(s,obj)->data_source&&op==1&&sz==8)rd_obj(s,obj)->dead=1;
        if(obj<0xff000000u&&rd_obj(s,obj)->data_device&&op==2&&sz==8)rd_obj(s,obj)->dead=1;
        if(obj<0xff000000u&&rd_obj(s,obj)->data_offer&&op==2&&sz==8)rd_obj(s,obj)->dead=1;
        if(obj>=0xff000000u&&sz==8){int slot=server_offer_slot(s,obj);
            if(slot>=0&&((s->objects.slot[slot].type==RD_PRIMARY_OFFER&&op==1)||
                         (s->objects.slot[slot].type!=RD_PRIMARY_OFFER&&op==2)))
                s->objects.slot[slot].server_offer_dead=1;}
        if(obj<0xff000000u&&rd_obj(s,obj)->shm&&op==0&&sz==16){
            uint32_t id=word(s->b+8);
            if(occupied(s,id))
                s->denied++;
            else {rd_alloc(s,id)->pool=1;rd_obj(s,id)->version=rd_obj(s,obj)->version;}
        }
        if(obj<0xff000000u&&rd_obj(s,obj)->pool&&op==0&&sz==32){
            uint32_t id=word(s->b+8);
            if(occupied(s,id))
                s->denied++;
            else {rd_alloc(s,id)->buffer=1;rd_obj(s,id)->version=1;}
        }
        if(!s->denied&&type_before==RD_OWNED_MANAGER&&op==0&&arity==0&&sz==56){
            uint32_t id=word(s->b+8),hi=word(s->b+32),lo=word(s->b+36);
            uint64_t sequence=((uint64_t)hi<<32)|lo;
            uint32_t width=word(s->b+40),height=word(s->b+44);
            uint32_t stride=word(s->b+48),format=word(s->b+52);
            unsigned live=0;
            for(unsigned i=0;i<RD_OBJECT_CAP;i++)
                if(s->objects.slot[i].state==RD_LIVE&&
                   s->objects.slot[i].type==RD_OWNED_BUFFER&&
                   !s->objects.slot[i].dead)live++;
            if(occupied(s,id)||!sequence||!width||!height||width>2048||
               height>1536||stride!=width*4u||format!=0||live>=3)s->denied++;
            else {struct rd_object *created=rd_alloc(s,id);
                created->type=RD_OWNED_BUFFER;created->buffer=1;
                created->parent=obj;created->version=1;
                if(!emit_owned_create(s,obj,id,s->b+16,sequence,width,height,
                                      stride,format))s->denied++;
            }
        }
        if(!s->denied&&type_before==RD_DMABUF_MANAGER&&op==1){
            uint32_t id=word(s->b+8);
            if(occupied(s,id))s->denied++;
            else {struct rd_object *created=rd_alloc(s,id);
                  created->type=RD_DMABUF_PARAMS;created->parent=obj;
                  created->version=rd_obj(s,obj)->version;}
        }
        if(!s->denied&&type_before==RD_DMABUF_PARAMS&&op==1){
            struct rd_object *params=rd_obj(s,obj);
            unsigned index=s->fd_required-1u-s->fd_base;
            if(params->dmabuf_plane||index>=s->fd_count||
               !s->fd_dev[index]||!s->fd_ino[index])s->denied++;
            else {params->dmabuf_plane=1;
                  params->dmabuf_stride=word(s->b+16);
                  params->dmabuf_dev=s->fd_dev[index];
                  params->dmabuf_ino=s->fd_ino[index];}
        }
        if(!s->denied&&type_before==RD_DMABUF_PARAMS&&op==3){
            struct rd_object *params=rd_obj(s,obj);
            uint32_t id=word(s->b+8),w=word(s->b+12),h=word(s->b+16);
            if(!params->dmabuf_plane||params->dmabuf_created||occupied(s,id)||
               !w||!h||w>2048||h>1536||
               params->dmabuf_stride<w*4u||
               params->dmabuf_stride>w*4u+4096u||
               params->dmabuf_stride>16384u||
               (params->dmabuf_stride&3u))
                s->denied++;
            else {struct rd_object *created=rd_alloc(s,id);
                  created->type=RD_DMABUF_BUFFER;created->buffer=1;
                  created->parent=obj;created->version=1;
                  created->dmabuf_stride=params->dmabuf_stride;
                  created->dmabuf_dev=params->dmabuf_dev;
                  created->dmabuf_ino=params->dmabuf_ino;
                  params->dmabuf_created=1;
                  if(!emit_dmabuf(s,RD_DMABUF_WIRE_CREATE,obj,id,w,h,
                       params->dmabuf_stride,params->dmabuf_dev,params->dmabuf_ino))
                      s->denied++;}
        }
        if(obj<0xff000000u&&rd_obj(s,obj)->seat&&op<=2&&sz==12){
            uint32_t id=word(s->b+8);
            if(occupied(s,id))s->denied++;
            else {struct rd_object *created=rd_alloc(s,id);
                  if(op==0)created->pointer=1;else if(op==1)created->keyboard=1;else created->touch=1;
                  rd_obj(s,id)->version=rd_obj(s,obj)->version;}
        }
        if(obj<0xff000000u&&rd_obj(s,obj)->type==RD_COMPOSITOR&&op==1&&sz==12){
            uint32_t id=word(s->b+8);
            if(occupied(s,id))s->denied++;
            else {struct rd_object *region=rd_alloc(s,id);
                region->type=RD_REGION;region->parent=obj;region->version=1;}
        }
        if(obj<0xff000000u&&rd_obj(s,obj)->type==RD_REGION&&op==0&&sz==8)
            rd_obj(s,obj)->dead=1;
        if(obj<0xff000000u&&rd_obj(s,obj)->type==RD_WL_SURFACE&&
           (op==4||op==5)&&sz==12){
            uint32_t region=word(s->b+8);
            if(region&&(rd_view(s,region)->type!=RD_REGION||rd_view(s,region)->dead))
                s->denied++;
        }
        if(obj<0xff000000u&&sz==8&&op==1&&rd_obj(s,obj)->pointer)rd_obj(s,obj)->dead=1;
        if(obj<0xff000000u&&sz==8&&op==0&&rd_obj(s,obj)->touch)rd_obj(s,obj)->dead=1;
        if(obj<0xff000000u&&rd_obj(s,obj)->layer_shell&&op==0&&arity==0){
            uint32_t id=word(s->b+8),surface=word(s->b+12);
            int duplicate_role=0;
            for(unsigned j=0;j<RD_OBJECT_CAP;j++)if(s->objects.slot[j].layer_surface&&
                !s->objects.slot[j].dead&&s->objects.slot[j].layer_parent==surface)duplicate_role=1;
            if(occupied(s,id)||surface>=0xff000000u||rd_obj(s,surface)->type!=RD_WL_SURFACE||
               rd_obj(s,surface)->dead||duplicate_role||surface_has_role(s,surface))s->denied++;
            else {rd_alloc(s,id)->layer_surface=1;rd_obj(s,id)->layer_parent=surface;
                  rd_obj(s,id)->version=rd_obj(s,obj)->version;}
        }
        if(obj<0xff000000u&&rd_obj(s,obj)->layer_surface&&op==7&&sz==8)rd_obj(s,obj)->dead=1;
        if(obj<0xff000000u&&rd_obj(s,obj)->layer_shell&&op==1&&sz==8)rd_obj(s,obj)->dead=1;
        enum rd_obj_type ext_type=rd_view(s,obj)->type;
        if((ext_type==RD_SUBCOMPOSITOR&&op==1&&sz==20)||
           ((ext_type==RD_VIEWPORTER||ext_type==RD_FRACTIONAL_MANAGER)&&op==1&&sz==16)){
            uint32_t id=word(s->b+8),surface=word(s->b+12);
            uint32_t parent=ext_type==RD_SUBCOMPOSITOR?word(s->b+16):0;
            enum rd_obj_type child=ext_type==RD_SUBCOMPOSITOR?RD_SUBSURFACE:
                ext_type==RD_VIEWPORTER?RD_VIEWPORT:RD_FRACTIONAL_SCALE;
            int duplicate=0;
            for(unsigned j=0;j<RD_OBJECT_CAP;j++){
                struct rd_object *other=&s->objects.slot[j];
                if(other->state==RD_LIVE&&!other->dead&&other->type==child&&
                   other->parent==surface)duplicate=1;
            }
            if(occupied(s,id)||surface==parent||rd_view(s,surface)->type!=RD_WL_SURFACE||
               rd_view(s,surface)->dead||
               (ext_type==RD_SUBCOMPOSITOR&&(rd_view(s,parent)->type!=RD_WL_SURFACE||
                rd_view(s,parent)->dead||surface_has_role(s,surface)))||duplicate)s->denied++;
            else {struct rd_object *created=rd_alloc(s,id);
                created->type=child;created->parent=surface;created->layer_parent=parent;
                created->version=rd_obj(s,obj)->version;}
        }
        if(ext_type==RD_SUBSURFACE&&(op==2||op==3)&&sz==12){
            uint32_t sibling=word(s->b+8);
            if(rd_view(s,sibling)->type!=RD_WL_SURFACE||rd_view(s,sibling)->dead)s->denied++;
        }
        if((ext_type==RD_OUTPUT||ext_type==RD_SUBCOMPOSITOR||ext_type==RD_SUBSURFACE||
            ext_type==RD_VIEWPORTER||ext_type==RD_VIEWPORT||
            ext_type==RD_FRACTIONAL_MANAGER||ext_type==RD_FRACTIONAL_SCALE)&&
            op==0&&sz==8)rd_obj(s,obj)->dead=1;
        if((obj==1&&op==1)||known_registry||
           (obj<0xff000000u&&rd_obj(s,obj)->type==RD_COMPOSITOR&&op==0)||
           (obj<0xff000000u&&rd_obj(s,obj)->type==RD_WM_BASE&&op==2)||
           (obj<0xff000000u&&rd_obj(s,obj)->type==RD_XDG_SURFACE&&op==1)){
            uint32_t id=0;
            if(known_registry){uint32_t len=word(s->b+12);
                id=word(s->b+20+((len+3)&~3u));}
            else if(sz>=12)id=word(s->b+8);
            if(occupied(s,id))s->denied++;
            if(!s->denied&&rd_lineage_request(s,s->b,sz)){
                if(id<0xff000000u){
                    if(known_registry){uint32_t len=word(s->b+12);
                        rd_obj(s,id)->version=(unsigned char)word(s->b+16+((len+3)&~3u));}
                    else if(obj==1)rd_obj(s,id)->version=1;
                    else rd_obj(s,id)->version=rd_obj(s,obj)->version;
                }
                unsigned count=0;
                for(unsigned i=0;i<RD_OBJECT_CAP;i++)if(s->objects.slot[i].type==RD_TOPLEVEL)count++;
                s->toplevels=count;
            }else s->denied++;
        }
        if(!s->denied&&type_before==RD_OWNED_BUFFER&&op==0&&sz==8&&
           !emit_owned_destroy(s,obj,rd_obj(s,obj)->generation))s->denied++;
        if(!s->denied&&type_before==RD_DMABUF_BUFFER&&op==0&&sz==8){
            struct rd_object *buffer=rd_obj(s,obj);
            if(!emit_dmabuf(s,RD_DMABUF_WIRE_DESTROY,rd_obj(s,obj)->parent,
                 obj,0,0,buffer->dmabuf_stride,buffer->dmabuf_dev,
                 buffer->dmabuf_ino))s->denied++;
        }
        if(s->denied>denied_before&&getenv("RD_UNIFIED_TRACE"))
            fprintf(stderr,"UNIFIED_CLIENT_MESSAGE_DENIED obj=%u type=%u op=%u size=%zu\n",
                    obj,(unsigned)type_before,op,sz);
        memmove(s->b,s->b+sz,s->n-sz);s->n-=sz;
    }
}
static void close_received_rights(struct msghdr *m){
    for(struct cmsghdr *c=CMSG_FIRSTHDR(m);c;c=CMSG_NXTHDR(m,c)){
        if(c->cmsg_level!=SOL_SOCKET||c->cmsg_type!=SCM_RIGHTS||c->cmsg_len<CMSG_LEN(0))continue;
        size_t count=(c->cmsg_len-CMSG_LEN(0))/sizeof(int);
        int *rights=(int*)CMSG_DATA(c);for(size_t i=0;i<count;i++)close(rights[i]);
    }
}
static int publish_parse(struct parse *parse,const unsigned char *b,size_t n,int server_direction){
    if(!parse)return 0;
    if(server_direction)inspect_server(parse,b,n);
    else {parse->emit_owned=1;inspect(parse,b,n);parse->emit_owned=0;}
    if(parse->denied)return -1;
    for(unsigned at=0;at<RD_OBJECT_CAP;at++)if(parse->objects.slot[at].type==RD_TOPLEVEL){
        struct rd_object *o=&parse->objects.slot[at];uint32_t obj=o->id;
        struct top_life *t=&o->top;
        if(!t->generation){
            t->generation=o->generation;t->xdg=o->parent;
            t->wl=t->xdg<0xff000000u?rd_obj(parse,t->xdg)->parent:0;
        }
        if(t->generation!=o->generation)return -1;
        if(!t->created&&!t->dead&&t->configured){
            if(!emit_event(parse,0x52444c31,obj))return -1;
            fprintf(stdout,"HOST_LINEAGE surface_id=%llu peer_pid=%d generation=%llu\n",
                (unsigned long long)(((uint64_t)parse->host_connection<<32)|obj),parse->peer_pid,
                (unsigned long long)t->generation);fflush(stdout);t->created=1;
        }
        if(t->created&&t->dead&&!t->revoked){
            if(!emit_event(parse,0x52445231,obj))return -1;
            fprintf(stdout,"HOST_REVOKE surface_id=%llu generation=%llu\n",
                (unsigned long long)(((uint64_t)parse->host_connection<<32)|obj),
                (unsigned long long)t->generation);fflush(stdout);t->revoked=1;
        }
    }
    for(unsigned at=0;at<RD_OBJECT_CAP;at++)if(parse->objects.slot[at].pending_delete){
        struct rd_object *o=&parse->objects.slot[at];
        if(o->type==RD_TOPLEVEL&&o->top.created&&!o->top.revoked)return -1;
        o->type=RD_NONE;o->parent=0;o->dead=0;o->pending_delete=0;o->version=0;
        memset(&o->top,0,sizeof(o->top));o->state=RD_TOMBSTONE;
    }
    return 0;
}
static void disconnect_revoke(struct parse *p){
    for(unsigned at=0;at<RD_OBJECT_CAP;at++)if(p->objects.slot[at].top.created&&
        !p->objects.slot[at].top.revoked){
        struct rd_object *o=&p->objects.slot[at];uint32_t obj=o->id;
        int delivered=emit_event(p,0x52445231,obj);
        fprintf(stdout,"HOST_REVOKE surface_id=%llu generation=%llu reason=disconnect delivered=%d\n",
            (unsigned long long)(((uint64_t)p->host_connection<<32)|obj),
            (unsigned long long)o->top.generation,delivered);fflush(stdout);
        o->top.revoked=1;
    }
}
struct relay_session {int client,server,active;pid_t peer;
    struct parse p;size_t up,down,upfds,downfds;
    struct queued_message {unsigned char data[65536];size_t len,offset;
        int rights[16],nr,awaiting_frame;
        uint64_t fd_dev[16],fd_ino[16];unsigned fd_count;} to_server,to_client;};
static int connect_backend(const char *path){
    int fd=socket(AF_UNIX,SOCK_STREAM,0);if(fd<0)return -1;
    struct sockaddr_un a={.sun_family=AF_UNIX};strcpy(a.sun_path,path);
    if(connect(fd,(void*)&a,sizeof(a))){close(fd);return -1;}
    return fd;
}
static int bound_socket(int fd){
    int buffer=131072;struct timeval timeout={0,250000};
    return !setsockopt(fd,SOL_SOCKET,SO_SNDBUF,&buffer,sizeof(buffer))&&
           !setsockopt(fd,SOL_SOCKET,SO_RCVBUF,&buffer,sizeof(buffer))&&
           !setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
}
static int nonblocking(int fd){int flags=fcntl(fd,F_GETFL,0);
    return flags>=0&&!fcntl(fd,F_SETFL,flags|O_NONBLOCK);}
static int exact_signed_peer(int fd,pid_t expected_pid,const char *binary){
    pid_t peer=0;socklen_t len=sizeof(peer);
    return expected_pid>0&&binary&&*binary&&
        !getsockopt(fd,SOL_LOCAL,LOCAL_PEERPID,&peer,&len)&&
        len==sizeof(peer)&&peer==expected_pid&&
        rd_verify_peer_audit(fd,binary);
}
static pid_t required_pid(const char *s){
    if(!s||!*s)return 0;
    char *end=NULL;errno=0;long value=strtol(s,&end,10);
    return errno||!end||*end||value<=0||value>INT32_MAX?0:(pid_t)value;
}
static void discard_queue(struct queued_message *q){
    for(int i=0;i<q->nr;i++)close(q->rights[i]);q->nr=0;q->len=q->offset=0;
    q->awaiting_frame=0;
}
/* At most one 64 KiB message and 16 descriptors wait in each direction. */
static int enqueue(int src,struct queued_message *q){
    if(q->len&&!q->awaiting_frame)return 0;
    if(q->len==sizeof(q->data))return -1;
    /* Darwin can install one truncated SCM_RIGHTS descriptor that is not
     * represented by the shortened control message. Receive the platform's
     * maximum practical descriptor payload, then enforce our 16-FD policy. */
    unsigned char ctrl[CMSG_SPACE(sizeof(int)*256)];
    struct iovec io={q->data+q->len,sizeof(q->data)-q->len};
    struct msghdr m={0};m.msg_iov=&io;m.msg_iovlen=1;
    m.msg_control=ctrl;m.msg_controllen=sizeof(ctrl);
    ssize_t n=recvmsg(src,&m,0);
    if(n<0&&(errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR))return 0;
    if(n<=0)return -1;
    if(m.msg_flags&(MSG_CTRUNC|MSG_TRUNC)){close_received_rights(&m);discard_queue(q);return -1;}
    for(struct cmsghdr *c=CMSG_FIRSTHDR(&m);c;c=CMSG_NXTHDR(&m,c)){
        if(c->cmsg_level!=SOL_SOCKET||c->cmsg_type!=SCM_RIGHTS||c->cmsg_len<CMSG_LEN(0)){
            close_received_rights(&m);discard_queue(q);return -1;}
        size_t count=(c->cmsg_len-CMSG_LEN(0))/sizeof(int);
        if(count>16-(size_t)q->nr){close_received_rights(&m);discard_queue(q);return -1;}
        int *received=(int*)CMSG_DATA(c);
        for(size_t i=0;i<count;i++){
            int flags=fcntl(received[i],F_GETFD);
            if(flags<0||fcntl(received[i],F_SETFD,flags|FD_CLOEXEC)<0){
                close_received_rights(&m);discard_queue(q);return -1;
            }
        }
        memcpy(q->rights+q->nr,CMSG_DATA(c),count*sizeof(int));q->nr+=(int)count;
    }
    q->len+=(size_t)n;q->awaiting_frame=0;return 1;
}
/* Hold a bounded client byte stream until all framed requests are complete.
 * Inspect a copy so no lineage/capability is committed until the backend
 * send completes. */
/* -1 denied, 0 awaiting more bytes, 1 complete and authorized. */
static int prevalidate_client(struct queued_message *q,const struct parse *p){
    if(!p||p->denied||p->n)return -1;
    struct parse shadow=*p;
    if(q->nr<0||q->nr>16)return -1;
    q->fd_count=(unsigned)q->nr;
    shadow.fd_base=p->fd_required;shadow.fd_count=q->fd_count;
    for(int i=0;i<q->nr;i++){
        struct stat st;
        if(fstat(q->rights[i],&st)||!st.st_dev||!st.st_ino)return -1;
        q->fd_dev[i]=shadow.fd_dev[i]=(uint64_t)st.st_dev;
        q->fd_ino[i]=shadow.fd_ino[i]=(uint64_t)st.st_ino;
    }
    inspect(&shadow,q->data,q->len);
    if(shadow.denied){
        if(getenv("RD_UNIFIED_TRACE")&&q->len>=8){
            fprintf(stderr,"UNIFIED_CLIENT_DENIED obj=%u op=%u len=%zu\n",
                    word(q->data),word(q->data+4)&65535,q->len);
        }
        return -1;
    }
    if(shadow.n)return 0;
    if(shadow.fd_required-p->fd_required!=(unsigned)q->nr)return -1;
    /* Wayland assigns SCM_RIGHTS in protocol order across a stream batch.
     * GTK4 legitimately sends many requests with a single later shm FD in
     * one write. The shadow parser counts exact FD arity per known opcode;
     * matching the ordered queue total is the transport's association rule. */
    return 1;
}
static int prevalidate_server(const struct queued_message *q,const struct parse *p){
    if(!p||p->denied)return -1;
    struct parse shadow=*p;
    inspect_server(&shadow,q->data,q->len);
    if(shadow.denied){
        if(getenv("RD_UNIFIED_TRACE")&&q->len>=8){
            fprintf(stderr,"UNIFIED_SERVER_DENIED obj=%u op=%u len=%zu\n",
                    word(q->data),word(q->data+4)&65535,q->len);
        }
        return -1;
    }
    if(shadow.server_n)return 0;
    return shadow.server_fd_required-p->server_fd_required==(unsigned)q->nr?1:-1;
}
static int flush_queue(int dst,struct queued_message *q,struct parse *p,
                       int server_direction,size_t *bytes,size_t *fds){
    if(!q->len)return 0;
    if(p&&q->offset==0){
        int valid=server_direction?prevalidate_server(q,p):prevalidate_client(q,p);
        if(valid<0)return -1;
        if(valid==0){q->awaiting_frame=1;return 0;}
    }
    unsigned char ctrl[CMSG_SPACE(sizeof(int)*16)];
    struct iovec io={q->data+q->offset,q->len-q->offset};
    struct msghdr m={0};m.msg_iov=&io;m.msg_iovlen=1;
    if(q->nr){m.msg_control=ctrl;m.msg_controllen=CMSG_SPACE((size_t)q->nr*sizeof(int));
        struct cmsghdr *c=CMSG_FIRSTHDR(&m);c->cmsg_level=SOL_SOCKET;c->cmsg_type=SCM_RIGHTS;
        c->cmsg_len=CMSG_LEN((size_t)q->nr*sizeof(int));
        memcpy(CMSG_DATA(c),q->rights,(size_t)q->nr*sizeof(int));}
    ssize_t n=sendmsg(dst,&m,0);
    if(n<0&&(errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR))return 0;
    if(n<=0)return -1;
    q->offset+=(size_t)n;*bytes+=(size_t)n;
    *fds+=(size_t)q->nr;
    for(int i=0;i<q->nr;i++)close(q->rights[i]);q->nr=0;
    if(q->offset==q->len){
        if(p&&!server_direction){
            p->fd_base=p->fd_required;p->fd_count=q->fd_count;
            memcpy(p->fd_dev,q->fd_dev,sizeof q->fd_dev);
            memcpy(p->fd_ino,q->fd_ino,sizeof q->fd_ino);
            p->emit_dmabuf=1;
        }
        int rc=publish_parse(p,q->data,q->len,server_direction);
        if(p){p->fd_count=0;p->emit_dmabuf=0;}
        q->len=q->offset=0;q->awaiting_frame=0;return rc? -1:1;
    }
    return 0;
}
static int run_two(int argc,char **argv){
    int owned_mode=!strcmp(argv[1],"--one-owned")||!strcmp(argv[1],"--two-owned");
    int dmabuf_mode=!strcmp(argv[1],"--one-dmabuf")||!strcmp(argv[1],"--two-dmabuf");
    int witness_mode=owned_mode||dmabuf_mode;
    int count=(!strcmp(argv[1],"--one")||!strcmp(argv[1],"--one-owned")||
               !strcmp(argv[1],"--one-dmabuf"))?1:2;
    if((strcmp(argv[1],"--one")&&strcmp(argv[1],"--two")&&!witness_mode)||
       argc!=(count==1?7:8)+(witness_mode?5:0)){
        fprintf(stderr,"usage: relay --one/--two/--one-owned/--two-owned/--one-dmabuf/--two-dmabuf listen backend pid1 [pid2] signed_client coordinator_socket [coordinator_pid signed_coordinator witness_socket witness_pid signed_witness]\n");
        return 2;
    }
    int signed_arg=count==1?5:6,coordinator_arg=count==1?6:7;
    int coordinator_pid_arg=coordinator_arg+1,witness_socket_arg=coordinator_arg+3;
    if(strlen(argv[2])>=sizeof(((struct sockaddr_un*)0)->sun_path)||
       strlen(argv[3])>=sizeof(((struct sockaddr_un*)0)->sun_path)||
       strlen(argv[coordinator_arg])>=sizeof(((struct sockaddr_un*)0)->sun_path)||
       (witness_mode&&strlen(argv[witness_socket_arg])>=
           sizeof(((struct sockaddr_un*)0)->sun_path)))return 2;
    pid_t expected[2]={(pid_t)atoi(argv[4]),count==2?(pid_t)atoi(argv[5]):0};
    pid_t coordinator_pid=witness_mode?required_pid(argv[coordinator_pid_arg]):0;
    pid_t witness_pid=witness_mode?required_pid(argv[witness_socket_arg+1]):0;
    if(expected[0]<=0||(count==2&&(expected[1]<=0||expected[0]==expected[1])))return 2;
    if(witness_mode&&(!coordinator_pid||!witness_pid||coordinator_pid==witness_pid||
       coordinator_pid==expected[0]||witness_pid==expected[0]||
       (count==2&&(coordinator_pid==expected[1]||witness_pid==expected[1]))))return 2;
    int listener=socket(AF_UNIX,SOCK_STREAM,0);if(listener<0)return 3;
    struct sockaddr_un a={.sun_family=AF_UNIX};strcpy(a.sun_path,argv[2]);
    if(bind(listener,(void*)&a,sizeof(a))||listen(listener,2))return 4;
    struct relay_session s[2]={0};int event_fd=-1,witness_fd=-1;pid_t seen=0;
    for(int i=0;i<2;i++){s[i].client=-1;s[i].server=-1;}
    for(int i=0;i<count;i++){
        int fd=accept(listener,NULL,NULL);if(fd<0)return 5;
        pid_t peer=0;socklen_t len=sizeof(peer);
        if(getsockopt(fd,SOL_LOCAL,LOCAL_PEERPID,&peer,&len)||
           (peer!=expected[0]&&(count==1||peer!=expected[1]))||
           (i==1&&peer==seen)||!rd_verify_peer_audit(fd,argv[signed_arg])){
            close(fd);return 6;}
        audit_token_t audit={0};len=sizeof(audit);
        if(getsockopt(fd,SOL_LOCAL,LOCAL_PEERTOKEN,&audit,&len)||len!=sizeof(audit)){
            close(fd);return 6;}
        int idx=peer==expected[0]?0:1;
        seen=peer;
        if(!bound_socket(fd)||!nonblocking(fd)){close(fd);return 7;}
        s[idx].client=fd;s[idx].peer=peer;s[idx].p.peer_pid=peer;
        s[idx].p.audit=audit;s[idx].p.supervisor_fd=-1;
        s[idx].p.owned_event_fd=-1; /* launcher must supply an authenticated channel */
        s[idx].p.dmabuf_event_fd=-1;
        rd_obj_init(&s[idx].p);
        s[idx].p.strict_capability=1;
        arc4random_buf(&s[idx].p.host_connection,sizeof(uint32_t));
        if(!s[idx].p.host_connection)s[idx].p.host_connection=1;
    }
    if(s[0].p.host_connection==s[1].p.host_connection)s[1].p.host_connection++;
    event_fd=socket(AF_UNIX,SOCK_STREAM,0);if(event_fd<0)return 9;
    strcpy(a.sun_path,argv[coordinator_arg]);if(connect(event_fd,(void*)&a,sizeof(a))||
        (witness_mode&&!exact_signed_peer(event_fd,coordinator_pid,
                                       argv[coordinator_pid_arg+1]))||
        !bound_socket(event_fd))return 9;
    if(witness_mode){
        witness_fd=socket(AF_UNIX,SOCK_STREAM,0);if(witness_fd<0)return 9;
        strcpy(a.sun_path,argv[witness_socket_arg]);
        if(connect(witness_fd,(void*)&a,sizeof(a))||
           !exact_signed_peer(witness_fd,witness_pid,argv[witness_socket_arg+2])||
           !bound_socket(witness_fd))return 9;
    }
    for(int i=0;i<count;i++){
        s[i].p.event_fd=event_fd;
        s[i].p.owned_event_fd=owned_mode?witness_fd:-1;
        s[i].p.dmabuf_event_fd=dmabuf_mode?witness_fd:-1;
        s[i].server=connect_backend(argv[3]);
        if(s[i].server<0||!bound_socket(s[i].server)||!nonblocking(s[i].server))return 8;
        s[i].active=1;
    }
    while(!stop&&(s[0].active||s[1].active)){
        if(coordinator_dead(event_fd)||
           (witness_mode&&coordinator_dead(witness_fd))){
            fprintf(stderr,"COORDINATOR_OR_WITNESS_LOST\n");break;}
        struct pollfd f[6];nfds_t nf=0;int map[6],direction[6];
        f[nf]=(struct pollfd){event_fd,POLLIN|POLLHUP|POLLERR,0};map[nf]=-1;direction[nf++]=-1;
        if(witness_mode){
            f[nf]=(struct pollfd){witness_fd,POLLIN|POLLHUP|POLLERR,0};
            map[nf]=-1;direction[nf++]=-1;
        }
        for(int i=0;i<2;i++)if(s[i].active){
            short client_events=(!s[i].to_server.len||s[i].to_server.awaiting_frame?POLLIN:0)|
                                (s[i].to_client.len&&!s[i].to_client.awaiting_frame?POLLOUT:0);
            short server_events=(!s[i].to_client.len||s[i].to_client.awaiting_frame?POLLIN:0)|
                                (s[i].to_server.len&&!s[i].to_server.awaiting_frame?POLLOUT:0);
            f[nf]=(struct pollfd){s[i].client,client_events,0};map[nf]=i;direction[nf++]=0;
            f[nf]=(struct pollfd){s[i].server,server_events,0};map[nf]=i;direction[nf++]=1;
        }
        int rc=poll(f,nf,1000);if(rc<0){if(errno==EINTR)continue;break;}
        if(rc==0)continue;
        if(f[0].revents||(witness_mode&&f[1].revents)){
            fprintf(stderr,"COORDINATOR_OR_WITNESS_LOST\n");break;}
        /* Coordinator and witness sentinel slots have map == -1. */
        for(nfds_t j=witness_mode?2u:1u;j<nf;j++){
            int i=map[j];if(!s[i].active)continue;
            int failed=0;
            if(f[j].revents&POLLIN){
                if(direction[j])failed=enqueue(s[i].server,&s[i].to_client)<0;
                else failed=enqueue(s[i].client,&s[i].to_server)<0;
            }
            if(!failed&&(f[j].revents&POLLOUT)){
                if(direction[j])failed=flush_queue(s[i].server,&s[i].to_server,&s[i].p,0,
                                                  &s[i].up,&s[i].upfds)<0;
                else failed=flush_queue(s[i].client,&s[i].to_client,&s[i].p,1,
                                        &s[i].down,&s[i].downfds)<0;
            }
            if(failed||(f[j].revents&(POLLHUP|POLLERR|POLLNVAL))){
                discard_queue(&s[i].to_server);discard_queue(&s[i].to_client);
                disconnect_revoke(&s[i].p);close(s[i].client);close(s[i].server);
                s[i].active=0;
            }
        }
    }
    for(int i=0;i<count;i++){
        if(s[i].active){discard_queue(&s[i].to_server);discard_queue(&s[i].to_client);
            disconnect_revoke(&s[i].p);close(s[i].client);close(s[i].server);}
        fprintf(stdout,"RELAY_CLIENT peer=%d up=%zu down=%zu fds=%zu/%zu lineage=%u host_surface_id=%llu denials=%u\n",
            s[i].peer,s[i].up,s[i].down,s[i].upfds,s[i].downfds,s[i].p.toplevels,
            (unsigned long long)((uint64_t)s[i].p.host_connection<<32),s[i].p.denied);
    }
    fflush(stdout);if(witness_fd>=0)close(witness_fd);
    close(event_fd);close(listener);unlink(argv[2]);return 0;
}
int main(int argc,char **argv){
    signal(SIGTERM,term);signal(SIGINT,term);signal(SIGPIPE,SIG_IGN);
    if(argc>1&&(!strcmp(argv[1],"--two")||!strcmp(argv[1],"--one")||
       !strcmp(argv[1],"--one-owned")||!strcmp(argv[1],"--two-owned")||
       !strcmp(argv[1],"--one-dmabuf")||!strcmp(argv[1],"--two-dmabuf")))
        return run_two(argc,argv);
    /* Legacy single-client transport forwards before validation. Disable it
     * in this candidate; only the framed prevalidated path may run. */
    fprintf(stderr,"single-client legacy transport disabled; use --one or --two\n");
    return 2;
}
